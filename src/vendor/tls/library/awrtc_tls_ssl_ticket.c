/*
 *  TLS server tickets callbacks implementation
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_SSL_TICKET_C)

#include "../include/mbedtls/platform.h"

#include "ssl_misc.h"
#include "../include/mbedtls/ssl_ticket.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/platform_util.h"

#include <string.h>

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
/* Define a local translating function to save code size by not using too many
 * arguments in each translating place. */
static int local_err_translation(awrtc_psa_status_t status)
{
    return awrtc_psa_status_to_mbedtls(status, awrtc_psa_to_ssl_errors,
                                 ARRAY_LENGTH(awrtc_psa_to_ssl_errors),
                                 awrtc_psa_generic_status_to_mbedtls);
}
#define AWRTC_PSA_TO_MBEDTLS_ERR(status) local_err_translation(status)
#endif

/*
 * Initialize context
 */
void awrtc_mbedtls_ssl_ticket_init(awrtc_mbedtls_ssl_ticket_context *ctx)
{
    memset(ctx, 0, sizeof(awrtc_mbedtls_ssl_ticket_context));

#if defined(AWRTC_MBEDTLS_THREADING_C)
    awrtc_mbedtls_mutex_init(&ctx->mutex);
#endif
}

#define MAX_KEY_BYTES           AWRTC_MBEDTLS_SSL_TICKET_MAX_KEY_BYTES

#define TICKET_KEY_NAME_BYTES   AWRTC_MBEDTLS_SSL_TICKET_KEY_NAME_BYTES
#define TICKET_IV_BYTES         12
#define TICKET_CRYPT_LEN_BYTES   2
#define TICKET_AUTH_TAG_BYTES   16

#define TICKET_MIN_LEN (TICKET_KEY_NAME_BYTES  +        \
                        TICKET_IV_BYTES        +        \
                        TICKET_CRYPT_LEN_BYTES +        \
                        TICKET_AUTH_TAG_BYTES)
#define TICKET_ADD_DATA_LEN (TICKET_KEY_NAME_BYTES  +        \
                             TICKET_IV_BYTES        +        \
                             TICKET_CRYPT_LEN_BYTES)

/*
 * Generate/update a key
 */
AWRTC_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_ticket_gen_key(awrtc_mbedtls_ssl_ticket_context *ctx,
                              unsigned char index)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char buf[MAX_KEY_BYTES] = { 0 };
    awrtc_mbedtls_ssl_ticket_key *key = ctx->keys + index;

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
#endif

#if defined(AWRTC_MBEDTLS_HAVE_TIME)
    key->generation_time = awrtc_mbedtls_time(NULL);
#endif
    /* The lifetime of a key is the configured lifetime of the tickets when
     * the key is created.
     */
    key->lifetime = ctx->ticket_lifetime;

    if ((ret = ctx->f_rng(ctx->p_rng, key->name, sizeof(key->name))) != 0) {
        return ret;
    }

    if ((ret = ctx->f_rng(ctx->p_rng, buf, sizeof(buf))) != 0) {
        return ret;
    }

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_set_key_usage_flags(&attributes,
                            AWRTC_PSA_KEY_USAGE_ENCRYPT | AWRTC_PSA_KEY_USAGE_DECRYPT);
    awrtc_psa_set_key_algorithm(&attributes, key->alg);
    awrtc_psa_set_key_type(&attributes, key->key_type);
    awrtc_psa_set_key_bits(&attributes, key->key_bits);

    ret = AWRTC_PSA_TO_MBEDTLS_ERR(
        awrtc_psa_import_key(&attributes, buf,
                       AWRTC_PSA_BITS_TO_BYTES(key->key_bits),
                       &key->key));
#else
    /* With GCM and CCM, same context can encrypt & decrypt */
    ret = awrtc_mbedtls_cipher_setkey(&key->ctx, buf,
                                awrtc_mbedtls_cipher_get_key_bitlen(&key->ctx),
                                AWRTC_MBEDTLS_ENCRYPT);
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    awrtc_mbedtls_platform_zeroize(buf, sizeof(buf));

    return ret;
}

/*
 * Rotate/generate keys if necessary
 */
AWRTC_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_ticket_update_keys(awrtc_mbedtls_ssl_ticket_context *ctx)
{
#if !defined(AWRTC_MBEDTLS_HAVE_TIME)
    ((void) ctx);
#else
    awrtc_mbedtls_ssl_ticket_key * const key = ctx->keys + ctx->active;
    if (key->lifetime != 0) {
        awrtc_mbedtls_time_t current_time = awrtc_mbedtls_time(NULL);
        awrtc_mbedtls_time_t key_time = key->generation_time;

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
        awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
#endif

        if (current_time >= key_time &&
            (uint64_t) (current_time - key_time) < key->lifetime) {
            return 0;
        }

        ctx->active = 1 - ctx->active;

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
        if ((status = awrtc_psa_destroy_key(ctx->keys[ctx->active].key)) != AWRTC_PSA_SUCCESS) {
            return AWRTC_PSA_TO_MBEDTLS_ERR(status);
        }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

        return ssl_ticket_gen_key(ctx, ctx->active);
    } else
#endif /* AWRTC_MBEDTLS_HAVE_TIME */
    return 0;
}

/*
 * Rotate active session ticket encryption key
 */
int awrtc_mbedtls_ssl_ticket_rotate(awrtc_mbedtls_ssl_ticket_context *ctx,
                              const unsigned char *name, size_t nlength,
                              const unsigned char *k, size_t klength,
                              uint32_t lifetime)
{
    const unsigned char idx = 1 - ctx->active;
    awrtc_mbedtls_ssl_ticket_key * const key = ctx->keys + idx;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    const size_t bitlen = key->key_bits;
#else
    const int bitlen = awrtc_mbedtls_cipher_get_key_bitlen(&key->ctx);
#endif

    if (nlength < TICKET_KEY_NAME_BYTES || klength * 8 < (size_t) bitlen) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    if ((status = awrtc_psa_destroy_key(key->key)) != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
        return ret;
    }

    awrtc_psa_set_key_usage_flags(&attributes,
                            AWRTC_PSA_KEY_USAGE_ENCRYPT | AWRTC_PSA_KEY_USAGE_DECRYPT);
    awrtc_psa_set_key_algorithm(&attributes, key->alg);
    awrtc_psa_set_key_type(&attributes, key->key_type);
    awrtc_psa_set_key_bits(&attributes, key->key_bits);

    if ((status = awrtc_psa_import_key(&attributes, k,
                                 AWRTC_PSA_BITS_TO_BYTES(key->key_bits),
                                 &key->key)) != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
        return ret;
    }
#else
    ret = awrtc_mbedtls_cipher_setkey(&key->ctx, k, bitlen, AWRTC_MBEDTLS_ENCRYPT);
    if (ret != 0) {
        return ret;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    ctx->active = idx;
    ctx->ticket_lifetime = lifetime;
    memcpy(key->name, name, TICKET_KEY_NAME_BYTES);
#if defined(AWRTC_MBEDTLS_HAVE_TIME)
    key->generation_time = awrtc_mbedtls_time(NULL);
#endif
    key->lifetime = lifetime;

    return 0;
}

/*
 * Setup context for actual use
 */
int awrtc_mbedtls_ssl_ticket_setup(awrtc_mbedtls_ssl_ticket_context *ctx,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                             awrtc_mbedtls_cipher_type_t cipher,
                             uint32_t lifetime)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t key_bits;

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_algorithm_t alg;
    awrtc_psa_key_type_t key_type;
#else
    const awrtc_mbedtls_cipher_info_t *cipher_info;
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    if (awrtc_mbedtls_ssl_cipher_to_psa(cipher, TICKET_AUTH_TAG_BYTES,
                                  &alg, &key_type, &key_bits) != AWRTC_PSA_SUCCESS) {
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (AWRTC_PSA_ALG_IS_AEAD(alg) == 0) {
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#else
    cipher_info = awrtc_mbedtls_cipher_info_from_type(cipher);

    if (awrtc_mbedtls_cipher_info_get_mode(cipher_info) != AWRTC_MBEDTLS_MODE_GCM &&
        awrtc_mbedtls_cipher_info_get_mode(cipher_info) != AWRTC_MBEDTLS_MODE_CCM &&
        awrtc_mbedtls_cipher_info_get_mode(cipher_info) != AWRTC_MBEDTLS_MODE_CHACHAPOLY) {
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    key_bits = awrtc_mbedtls_cipher_info_get_key_bitlen(cipher_info);
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    if (key_bits > 8 * MAX_KEY_BYTES) {
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ctx->f_rng = f_rng;
    ctx->p_rng = p_rng;

    ctx->ticket_lifetime = lifetime;

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    ctx->keys[0].alg = alg;
    ctx->keys[0].key_type = key_type;
    ctx->keys[0].key_bits = key_bits;

    ctx->keys[1].alg = alg;
    ctx->keys[1].key_type = key_type;
    ctx->keys[1].key_bits = key_bits;
#else
    if ((ret = awrtc_mbedtls_cipher_setup(&ctx->keys[0].ctx, cipher_info)) != 0) {
        return ret;
    }

    if ((ret = awrtc_mbedtls_cipher_setup(&ctx->keys[1].ctx, cipher_info)) != 0) {
        return ret;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    if ((ret = ssl_ticket_gen_key(ctx, 0)) != 0 ||
        (ret = ssl_ticket_gen_key(ctx, 1)) != 0) {
        return ret;
    }

    return 0;
}

/*
 * Create session ticket, with the following structure:
 *
 *    struct {
 *        opaque key_name[4];
 *        opaque iv[12];
 *        opaque encrypted_state<0..2^16-1>;
 *        opaque tag[16];
 *    } ticket;
 *
 * The key_name, iv, and length of encrypted_state are the additional
 * authenticated data.
 */

int awrtc_mbedtls_ssl_ticket_write(void *p_ticket,
                             const awrtc_mbedtls_ssl_session *session,
                             unsigned char *start,
                             const unsigned char *end,
                             size_t *tlen,
                             uint32_t *ticket_lifetime)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ssl_ticket_context *ctx = p_ticket;
    awrtc_mbedtls_ssl_ticket_key *key;
    unsigned char *key_name = start;
    unsigned char *iv = start + TICKET_KEY_NAME_BYTES;
    unsigned char *state_len_bytes = iv + TICKET_IV_BYTES;
    unsigned char *state = state_len_bytes + TICKET_CRYPT_LEN_BYTES;
    size_t clear_len, ciph_len;

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
#endif

    *tlen = 0;

    if (ctx == NULL || ctx->f_rng == NULL) {
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    /* We need at least 4 bytes for key_name, 12 for IV, 2 for len 16 for tag,
     * in addition to session itself, that will be checked when writing it. */
    AWRTC_MBEDTLS_SSL_CHK_BUF_PTR(start, end, TICKET_MIN_LEN);

#if defined(AWRTC_MBEDTLS_THREADING_C)
    if ((ret = awrtc_mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return ret;
    }
#endif

    if ((ret = ssl_ticket_update_keys(ctx)) != 0) {
        goto cleanup;
    }

    key = &ctx->keys[ctx->active];

    *ticket_lifetime = key->lifetime;

    memcpy(key_name, key->name, TICKET_KEY_NAME_BYTES);

    if ((ret = ctx->f_rng(ctx->p_rng, iv, TICKET_IV_BYTES)) != 0) {
        goto cleanup;
    }

    /* Dump session state */
    if ((ret = awrtc_mbedtls_ssl_session_save(session,
                                        state, (size_t) (end - state),
                                        &clear_len)) != 0 ||
        (unsigned long) clear_len > 65535) {
        goto cleanup;
    }
    AWRTC_MBEDTLS_PUT_UINT16_BE(clear_len, state_len_bytes, 0);

    /* Encrypt and authenticate */
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    if ((status = awrtc_psa_aead_encrypt(key->key, key->alg, iv, TICKET_IV_BYTES,
                                   key_name, TICKET_ADD_DATA_LEN,
                                   state, clear_len,
                                   state, end - state,
                                   &ciph_len)) != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }
#else
    if ((ret = awrtc_mbedtls_cipher_auth_encrypt_ext(&key->ctx,
                                               iv, TICKET_IV_BYTES,
                                               /* Additional data: key name, IV and length */
                                               key_name, TICKET_ADD_DATA_LEN,
                                               state, clear_len,
                                               state, (size_t) (end - state), &ciph_len,
                                               TICKET_AUTH_TAG_BYTES)) != 0) {
        goto cleanup;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    if (ciph_len != clear_len + TICKET_AUTH_TAG_BYTES) {
        ret = AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto cleanup;
    }

    *tlen = TICKET_MIN_LEN + ciph_len - TICKET_AUTH_TAG_BYTES;

cleanup:
#if defined(AWRTC_MBEDTLS_THREADING_C)
    if (awrtc_mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return AWRTC_MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif

    return ret;
}

/*
 * Select key based on name
 */
static awrtc_mbedtls_ssl_ticket_key *ssl_ticket_select_key(
    awrtc_mbedtls_ssl_ticket_context *ctx,
    const unsigned char name[4])
{
    unsigned char i;

    for (i = 0; i < sizeof(ctx->keys) / sizeof(*ctx->keys); i++) {
        if (memcmp(name, ctx->keys[i].name, 4) == 0) {
            return &ctx->keys[i];
        }
    }

    return NULL;
}

/*
 * Load session ticket (see awrtc_mbedtls_ssl_ticket_write for structure)
 */
int awrtc_mbedtls_ssl_ticket_parse(void *p_ticket,
                             awrtc_mbedtls_ssl_session *session,
                             unsigned char *buf,
                             size_t len)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ssl_ticket_context *ctx = p_ticket;
    awrtc_mbedtls_ssl_ticket_key *key;
    unsigned char *key_name = buf;
    unsigned char *iv = buf + TICKET_KEY_NAME_BYTES;
    unsigned char *enc_len_p = iv + TICKET_IV_BYTES;
    unsigned char *ticket = enc_len_p + TICKET_CRYPT_LEN_BYTES;
    size_t enc_len, clear_len;

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
#endif

    if (ctx == NULL || ctx->f_rng == NULL) {
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (len < TICKET_MIN_LEN) {
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_THREADING_C)
    if ((ret = awrtc_mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return ret;
    }
#endif

    if ((ret = ssl_ticket_update_keys(ctx)) != 0) {
        goto cleanup;
    }

    enc_len = AWRTC_MBEDTLS_GET_UINT16_BE(enc_len_p, 0);

    if (len != TICKET_MIN_LEN + enc_len) {
        ret = AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        goto cleanup;
    }

    /* Select key */
    if ((key = ssl_ticket_select_key(ctx, key_name)) == NULL) {
        /* We can't know for sure but this is a likely option unless we're
         * under attack - this is only informative anyway */
        ret = AWRTC_MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
        goto cleanup;
    }

    /* Decrypt and authenticate */
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    if ((status = awrtc_psa_aead_decrypt(key->key, key->alg, iv, TICKET_IV_BYTES,
                                   key_name, TICKET_ADD_DATA_LEN,
                                   ticket, enc_len + TICKET_AUTH_TAG_BYTES,
                                   ticket, enc_len, &clear_len)) != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }
#else
    if ((ret = awrtc_mbedtls_cipher_auth_decrypt_ext(&key->ctx,
                                               iv, TICKET_IV_BYTES,
                                               /* Additional data: key name, IV and length */
                                               key_name, TICKET_ADD_DATA_LEN,
                                               ticket, enc_len + TICKET_AUTH_TAG_BYTES,
                                               ticket, enc_len, &clear_len,
                                               TICKET_AUTH_TAG_BYTES)) != 0) {
        if (ret == AWRTC_MBEDTLS_ERR_CIPHER_AUTH_FAILED) {
            ret = AWRTC_MBEDTLS_ERR_SSL_INVALID_MAC;
        }

        goto cleanup;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    if (clear_len != enc_len) {
        ret = AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto cleanup;
    }

    /* Actually load session */
    if ((ret = awrtc_mbedtls_ssl_session_load(session, ticket, clear_len)) != 0) {
        goto cleanup;
    }

#if defined(AWRTC_MBEDTLS_HAVE_TIME)
    awrtc_mbedtls_ms_time_t ticket_creation_time, ticket_age;
    awrtc_mbedtls_ms_time_t ticket_lifetime =
        (awrtc_mbedtls_ms_time_t) key->lifetime * 1000;

    ret = awrtc_mbedtls_ssl_session_get_ticket_creation_time(session,
                                                       &ticket_creation_time);
    if (ret != 0) {
        goto cleanup;
    }

    ticket_age = awrtc_mbedtls_ms_time() - ticket_creation_time;
    if (ticket_age < 0 || ticket_age > ticket_lifetime) {
        ret = AWRTC_MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
        goto cleanup;
    }
#endif

cleanup:
#if defined(AWRTC_MBEDTLS_THREADING_C)
    if (awrtc_mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return AWRTC_MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif

    return ret;
}

/*
 * Free context
 */
void awrtc_mbedtls_ssl_ticket_free(awrtc_mbedtls_ssl_ticket_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_destroy_key(ctx->keys[0].key);
    awrtc_psa_destroy_key(ctx->keys[1].key);
#else
    awrtc_mbedtls_cipher_free(&ctx->keys[0].ctx);
    awrtc_mbedtls_cipher_free(&ctx->keys[1].ctx);
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#if defined(AWRTC_MBEDTLS_THREADING_C)
    awrtc_mbedtls_mutex_free(&ctx->mutex);
#endif

    awrtc_mbedtls_platform_zeroize(ctx, sizeof(awrtc_mbedtls_ssl_ticket_context));
}

#endif /* AWRTC_MBEDTLS_SSL_TICKET_C */
