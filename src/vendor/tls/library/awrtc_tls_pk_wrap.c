/*
 *  Public Key abstraction layer: wrapper functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#include "../include/mbedtls/platform_util.h"

#if defined(AWRTC_MBEDTLS_PK_C)
#include "pk_wrap.h"
#include "pk_internal.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/psa_util.h"

/* Even if RSA not activated, for the sake of RSA-alt */
#include "../include/mbedtls/rsa.h"

#if defined(AWRTC_MBEDTLS_ECP_C)
#include "../include/mbedtls/ecp.h"
#endif

#if defined(AWRTC_MBEDTLS_ECDSA_C)
#include "../include/mbedtls/ecdsa.h"
#endif

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
#include "psa_util_internal.h"
#include "../include/psa/crypto.h"
#include "../include/mbedtls/psa_util.h"

#if defined(AWRTC_MBEDTLS_RSA_C)
#include "pkwrite.h"
#include "rsa_internal.h"
#endif

#if defined(AWRTC_MBEDTLS_PK_CAN_ECDSA_SOME)
#include "../include/mbedtls/asn1write.h"
#include "../include/mbedtls/asn1.h"
#endif
#endif  /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#include "../include/mbedtls/platform.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

#if defined(AWRTC_MBEDTLS_RSA_C)
static int rsa_can_do(awrtc_mbedtls_pk_type_t type)
{
    return type == AWRTC_MBEDTLS_PK_RSA ||
           type == AWRTC_MBEDTLS_PK_RSASSA_PSS;
}

static size_t rsa_get_bitlen(awrtc_mbedtls_pk_context *pk)
{
    const awrtc_mbedtls_rsa_context *rsa = (const awrtc_mbedtls_rsa_context *) pk->pk_ctx;
    return awrtc_mbedtls_rsa_get_bitlen(rsa);
}

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
static int rsa_verify_wrap(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len)
{
    awrtc_mbedtls_rsa_context *rsa = (awrtc_mbedtls_rsa_context *) pk->pk_ctx;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_mbedtls_svc_key_id_t key_id = AWRTC_MBEDTLS_SVC_KEY_ID_INIT;
    awrtc_psa_status_t status;
    int key_len;
    unsigned char buf[AWRTC_PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(AWRTC_PSA_VENDOR_RSA_MAX_KEY_BITS)];
    unsigned char *p = buf + sizeof(buf);
    awrtc_psa_algorithm_t awrtc_psa_alg_md;
    size_t rsa_len = awrtc_mbedtls_rsa_get_len(rsa);

#if SIZE_MAX > UINT_MAX
    if (md_alg == AWRTC_MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    if (awrtc_mbedtls_rsa_get_padding_mode(rsa) == AWRTC_MBEDTLS_RSA_PKCS_V21) {
        awrtc_psa_alg_md = AWRTC_PSA_ALG_RSA_PSS(awrtc_mbedtls_md_psa_alg_from_type(md_alg));
    } else {
        awrtc_psa_alg_md = AWRTC_PSA_ALG_RSA_PKCS1V15_SIGN(awrtc_mbedtls_md_psa_alg_from_type(md_alg));
    }

    if (sig_len < rsa_len) {
        return AWRTC_MBEDTLS_ERR_RSA_VERIFY_FAILED;
    }

    key_len = awrtc_mbedtls_rsa_write_pubkey(rsa, buf, &p);
    if (key_len <= 0) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    awrtc_psa_set_key_usage_flags(&attributes, AWRTC_PSA_KEY_USAGE_VERIFY_HASH);
    awrtc_psa_set_key_algorithm(&attributes, awrtc_psa_alg_md);
    awrtc_psa_set_key_type(&attributes, AWRTC_PSA_KEY_TYPE_RSA_PUBLIC_KEY);

    status = awrtc_psa_import_key(&attributes,
                            buf + sizeof(buf) - key_len, key_len,
                            &key_id);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = awrtc_psa_verify_hash(key_id, awrtc_psa_alg_md, hash, hash_len,
                             sig, sig_len);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }
    ret = 0;

cleanup:
    status = awrtc_psa_destroy_key(key_id);
    if (ret == 0 && status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#else /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
static int rsa_verify_wrap(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_rsa_context *rsa = (awrtc_mbedtls_rsa_context *) pk->pk_ctx;
    size_t rsa_len = awrtc_mbedtls_rsa_get_len(rsa);

#if SIZE_MAX > UINT_MAX
    if (md_alg == AWRTC_MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    if (sig_len < rsa_len) {
        return AWRTC_MBEDTLS_ERR_RSA_VERIFY_FAILED;
    }

    if ((ret = awrtc_mbedtls_rsa_pkcs1_verify(rsa, md_alg,
                                        (unsigned int) hash_len,
                                        hash, sig)) != 0) {
        return ret;
    }

    /* The buffer contains a valid signature followed by extra data.
     * We have a special error code for that so that so that callers can
     * use awrtc_mbedtls_pk_verify() to check "Does the buffer start with a
     * valid signature?" and not just "Does the buffer contain a valid
     * signature?". */
    if (sig_len > rsa_len) {
        return AWRTC_MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return 0;
}
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
int  awrtc_mbedtls_pk_psa_rsa_sign_ext(awrtc_psa_algorithm_t alg,
                                 awrtc_mbedtls_rsa_context *rsa_ctx,
                                 const unsigned char *hash, size_t hash_len,
                                 unsigned char *sig, size_t sig_size,
                                 size_t *sig_len)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_mbedtls_svc_key_id_t key_id = AWRTC_MBEDTLS_SVC_KEY_ID_INIT;
    awrtc_psa_status_t status;
    int key_len;
    unsigned char *buf = NULL;
    unsigned char *p;

    buf = awrtc_mbedtls_calloc(1, AWRTC_MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES);
    if (buf == NULL) {
        return AWRTC_MBEDTLS_ERR_PK_ALLOC_FAILED;
    }
    p = buf + AWRTC_MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES;

    *sig_len = awrtc_mbedtls_rsa_get_len(rsa_ctx);
    if (sig_size < *sig_len) {
        awrtc_mbedtls_free(buf);
        return AWRTC_MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    key_len = awrtc_mbedtls_rsa_write_key(rsa_ctx, buf, &p);
    if (key_len <= 0) {
        awrtc_mbedtls_free(buf);
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    awrtc_psa_set_key_usage_flags(&attributes, AWRTC_PSA_KEY_USAGE_SIGN_HASH);
    awrtc_psa_set_key_algorithm(&attributes, alg);
    awrtc_psa_set_key_type(&attributes, AWRTC_PSA_KEY_TYPE_RSA_KEY_PAIR);

    status = awrtc_psa_import_key(&attributes,
                            buf + AWRTC_MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES - key_len, key_len,
                            &key_id);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }
    status = awrtc_psa_sign_hash(key_id, alg, hash, hash_len,
                           sig, sig_size, sig_len);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    awrtc_mbedtls_free(buf);
    status = awrtc_psa_destroy_key(key_id);
    if (ret == 0 && status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
    }
    return ret;
}
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
static int rsa_sign_wrap(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t sig_size, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    ((void) f_rng);
    ((void) p_rng);

    awrtc_psa_algorithm_t awrtc_psa_md_alg;
    awrtc_psa_md_alg = awrtc_mbedtls_md_psa_alg_from_type(md_alg);
    if (awrtc_psa_md_alg == 0) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    awrtc_psa_algorithm_t awrtc_psa_alg;
    if (awrtc_mbedtls_rsa_get_padding_mode(awrtc_mbedtls_pk_rsa(*pk)) == AWRTC_MBEDTLS_RSA_PKCS_V21) {
        awrtc_psa_alg = AWRTC_PSA_ALG_RSA_PSS(awrtc_psa_md_alg);
    } else {
        awrtc_psa_alg = AWRTC_PSA_ALG_RSA_PKCS1V15_SIGN(awrtc_psa_md_alg);
    }

    return awrtc_mbedtls_pk_psa_rsa_sign_ext(awrtc_psa_alg, pk->pk_ctx, hash, hash_len,
                                       sig, sig_size, sig_len);
}
#else /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
static int rsa_sign_wrap(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t sig_size, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    awrtc_mbedtls_rsa_context *rsa = (awrtc_mbedtls_rsa_context *) pk->pk_ctx;

#if SIZE_MAX > UINT_MAX
    if (md_alg == AWRTC_MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    *sig_len = awrtc_mbedtls_rsa_get_len(rsa);
    if (sig_size < *sig_len) {
        return AWRTC_MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    return awrtc_mbedtls_rsa_pkcs1_sign(rsa, f_rng, p_rng,
                                  md_alg, (unsigned int) hash_len,
                                  hash, sig);
}
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
static int rsa_decrypt_wrap(awrtc_mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    awrtc_mbedtls_rsa_context *rsa = (awrtc_mbedtls_rsa_context *) pk->pk_ctx;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_mbedtls_svc_key_id_t key_id = AWRTC_MBEDTLS_SVC_KEY_ID_INIT;
    awrtc_psa_algorithm_t awrtc_psa_md_alg, decrypt_alg;
    awrtc_psa_status_t status;
    int key_len;
    ((void) f_rng);
    ((void) p_rng);

    if (ilen != awrtc_mbedtls_rsa_get_len(rsa)) {
        return AWRTC_MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    const size_t key_bits = awrtc_mbedtls_pk_get_bitlen(pk);
    /* awrtc_mbedtls_rsa_write_key() uses the same format as PSA export, which
     * actually calls it under the hood, so we can use the PSA size macro. */
    const size_t buf_size = AWRTC_PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(key_bits);
    unsigned char *buf = awrtc_mbedtls_calloc(1, buf_size);

    unsigned char *p = buf + buf_size;
    key_len = awrtc_mbedtls_rsa_write_key(rsa, buf, &p);
    if (key_len <= 0) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    awrtc_psa_set_key_type(&attributes, AWRTC_PSA_KEY_TYPE_RSA_KEY_PAIR);
    awrtc_psa_set_key_usage_flags(&attributes, AWRTC_PSA_KEY_USAGE_DECRYPT);
    if (awrtc_mbedtls_rsa_get_padding_mode(rsa) == AWRTC_MBEDTLS_RSA_PKCS_V21) {
        awrtc_psa_md_alg = awrtc_mbedtls_md_psa_alg_from_type((awrtc_mbedtls_md_type_t) awrtc_mbedtls_rsa_get_md_alg(rsa));
        decrypt_alg = AWRTC_PSA_ALG_RSA_OAEP(awrtc_psa_md_alg);
    } else {
        decrypt_alg = AWRTC_PSA_ALG_RSA_PKCS1V15_CRYPT;
    }
    awrtc_psa_set_key_algorithm(&attributes, decrypt_alg);

    status = awrtc_psa_import_key(&attributes,
                            buf + buf_size - key_len, key_len,
                            &key_id);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = awrtc_psa_asymmetric_decrypt(key_id, decrypt_alg,
                                    input, ilen,
                                    NULL, 0,
                                    output, osize, olen);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    awrtc_mbedtls_zeroize_and_free(buf, buf_size);
    status = awrtc_psa_destroy_key(key_id);
    if (ret == 0 && status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#else /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
static int rsa_decrypt_wrap(awrtc_mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    awrtc_mbedtls_rsa_context *rsa = (awrtc_mbedtls_rsa_context *) pk->pk_ctx;

    if (ilen != awrtc_mbedtls_rsa_get_len(rsa)) {
        return AWRTC_MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    return awrtc_mbedtls_rsa_pkcs1_decrypt(rsa, f_rng, p_rng,
                                     olen, input, output, osize);
}
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
static int rsa_encrypt_wrap(awrtc_mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    awrtc_mbedtls_rsa_context *rsa = (awrtc_mbedtls_rsa_context *) pk->pk_ctx;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_mbedtls_svc_key_id_t key_id = AWRTC_MBEDTLS_SVC_KEY_ID_INIT;
    awrtc_psa_algorithm_t awrtc_psa_md_alg, awrtc_psa_encrypt_alg;
    awrtc_psa_status_t status;
    int key_len;
    unsigned char buf[AWRTC_PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(AWRTC_PSA_VENDOR_RSA_MAX_KEY_BITS)];
    unsigned char *p = buf + sizeof(buf);

    ((void) f_rng);
    ((void) p_rng);

    if (awrtc_mbedtls_rsa_get_len(rsa) > osize) {
        return AWRTC_MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
    }

    key_len = awrtc_mbedtls_rsa_write_pubkey(rsa, buf, &p);
    if (key_len <= 0) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    awrtc_psa_set_key_usage_flags(&attributes, AWRTC_PSA_KEY_USAGE_ENCRYPT);
    if (awrtc_mbedtls_rsa_get_padding_mode(rsa) == AWRTC_MBEDTLS_RSA_PKCS_V21) {
        awrtc_psa_md_alg = awrtc_mbedtls_md_psa_alg_from_type((awrtc_mbedtls_md_type_t) awrtc_mbedtls_rsa_get_md_alg(rsa));
        awrtc_psa_encrypt_alg = AWRTC_PSA_ALG_RSA_OAEP(awrtc_psa_md_alg);
    } else {
        awrtc_psa_encrypt_alg = AWRTC_PSA_ALG_RSA_PKCS1V15_CRYPT;
    }
    awrtc_psa_set_key_algorithm(&attributes, awrtc_psa_encrypt_alg);
    awrtc_psa_set_key_type(&attributes, AWRTC_PSA_KEY_TYPE_RSA_PUBLIC_KEY);

    status = awrtc_psa_import_key(&attributes,
                            buf + sizeof(buf) - key_len, key_len,
                            &key_id);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = awrtc_psa_asymmetric_encrypt(key_id, awrtc_psa_encrypt_alg,
                                    input, ilen,
                                    NULL, 0,
                                    output, osize, olen);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    status = awrtc_psa_destroy_key(key_id);
    if (ret == 0 && status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#else /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
static int rsa_encrypt_wrap(awrtc_mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    awrtc_mbedtls_rsa_context *rsa = (awrtc_mbedtls_rsa_context *) pk->pk_ctx;
    *olen = awrtc_mbedtls_rsa_get_len(rsa);

    if (*olen > osize) {
        return AWRTC_MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
    }

    return awrtc_mbedtls_rsa_pkcs1_encrypt(rsa, f_rng, p_rng,
                                     ilen, input, output);
}
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

static int rsa_check_pair_wrap(awrtc_mbedtls_pk_context *pub, awrtc_mbedtls_pk_context *prv,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng)
{
    (void) f_rng;
    (void) p_rng;
    return awrtc_mbedtls_rsa_check_pub_priv((const awrtc_mbedtls_rsa_context *) pub->pk_ctx,
                                      (const awrtc_mbedtls_rsa_context *) prv->pk_ctx);
}

static void *rsa_alloc_wrap(void)
{
    void *ctx = awrtc_mbedtls_calloc(1, sizeof(awrtc_mbedtls_rsa_context));

    if (ctx != NULL) {
        awrtc_mbedtls_rsa_init((awrtc_mbedtls_rsa_context *) ctx);
    }

    return ctx;
}

static void rsa_free_wrap(void *ctx)
{
    awrtc_mbedtls_rsa_free((awrtc_mbedtls_rsa_context *) ctx);
    awrtc_mbedtls_free(ctx);
}

static void rsa_debug(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_pk_debug_item *items)
{
#if defined(AWRTC_MBEDTLS_RSA_ALT)
    /* Not supported */
    (void) pk;
    (void) items;
#else
    awrtc_mbedtls_rsa_context *rsa = (awrtc_mbedtls_rsa_context *) pk->pk_ctx;

    items->type = AWRTC_MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.N";
    items->value = &(rsa->N);

    items++;

    items->type = AWRTC_MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.E";
    items->value = &(rsa->E);
#endif
}

const awrtc_mbedtls_pk_info_t awrtc_mbedtls_rsa_info = {
    .type = AWRTC_MBEDTLS_PK_RSA,
    .name = "RSA",
    .get_bitlen = rsa_get_bitlen,
    .can_do = rsa_can_do,
    .verify_func = rsa_verify_wrap,
    .sign_func = rsa_sign_wrap,
#if defined(AWRTC_MBEDTLS_ECDSA_C) && defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = rsa_decrypt_wrap,
    .encrypt_func = rsa_encrypt_wrap,
    .check_pair_func = rsa_check_pair_wrap,
    .ctx_alloc_func = rsa_alloc_wrap,
    .ctx_free_func = rsa_free_wrap,
    .debug_func = rsa_debug,
};
#endif /* AWRTC_MBEDTLS_RSA_C */

#if defined(AWRTC_MBEDTLS_PK_HAVE_ECC_KEYS)
/*
 * Generic EC key
 */
static int eckey_can_do(awrtc_mbedtls_pk_type_t type)
{
    return type == AWRTC_MBEDTLS_PK_ECKEY ||
           type == AWRTC_MBEDTLS_PK_ECKEY_DH ||
           type == AWRTC_MBEDTLS_PK_ECDSA;
}

static size_t eckey_get_bitlen(awrtc_mbedtls_pk_context *pk)
{
#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
    return pk->ec_bits;
#else /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
    awrtc_mbedtls_ecp_keypair *ecp = (awrtc_mbedtls_ecp_keypair *) pk->pk_ctx;
    return ecp->grp.pbits;
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
}

#if defined(AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY)
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
/* Common helper for ECDSA verify using PSA functions. */
static int ecdsa_verify_psa(unsigned char *key, size_t key_len,
                            awrtc_psa_ecc_family_t curve, size_t curve_bits,
                            const unsigned char *hash, size_t hash_len,
                            const unsigned char *sig, size_t sig_len)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_mbedtls_svc_key_id_t key_id = AWRTC_MBEDTLS_SVC_KEY_ID_INIT;
    awrtc_psa_algorithm_t awrtc_psa_sig_md = AWRTC_PSA_ALG_ECDSA_ANY;
    size_t signature_len = AWRTC_PSA_ECDSA_SIGNATURE_SIZE(curve_bits);
    size_t converted_sig_len;
    unsigned char extracted_sig[AWRTC_PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE];
    unsigned char *p;
    awrtc_psa_status_t status;

    if (curve == 0) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    awrtc_psa_set_key_type(&attributes, AWRTC_PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve));
    awrtc_psa_set_key_usage_flags(&attributes, AWRTC_PSA_KEY_USAGE_VERIFY_HASH);
    awrtc_psa_set_key_algorithm(&attributes, awrtc_psa_sig_md);

    status = awrtc_psa_import_key(&attributes, key, key_len, &key_id);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    if (signature_len > sizeof(extracted_sig)) {
        ret = AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        goto cleanup;
    }

    p = (unsigned char *) sig;
    ret = awrtc_mbedtls_ecdsa_der_to_raw(curve_bits, p, sig_len, extracted_sig,
                                   sizeof(extracted_sig), &converted_sig_len);
    if (ret != 0) {
        goto cleanup;
    }

    if (converted_sig_len != signature_len) {
        ret = AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        goto cleanup;
    }

    status = awrtc_psa_verify_hash(key_id, awrtc_psa_sig_md, hash, hash_len,
                             extracted_sig, signature_len);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    status = awrtc_psa_destroy_key(key_id);
    if (ret == 0 && status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}

static int ecdsa_opaque_verify_wrap(awrtc_mbedtls_pk_context *pk,
                                    awrtc_mbedtls_md_type_t md_alg,
                                    const unsigned char *hash, size_t hash_len,
                                    const unsigned char *sig, size_t sig_len)
{
    (void) md_alg;
    unsigned char key[AWRTC_MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN];
    size_t key_len;
    awrtc_psa_key_attributes_t key_attr = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_psa_ecc_family_t curve;
    size_t curve_bits;
    awrtc_psa_status_t status;

    status = awrtc_psa_get_key_attributes(pk->priv_id, &key_attr);
    if (status != AWRTC_PSA_SUCCESS) {
        return AWRTC_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }
    curve = AWRTC_PSA_KEY_TYPE_ECC_GET_FAMILY(awrtc_psa_get_key_type(&key_attr));
    curve_bits = awrtc_psa_get_key_bits(&key_attr);
    awrtc_psa_reset_key_attributes(&key_attr);

    status = awrtc_psa_export_public_key(pk->priv_id, key, sizeof(key), &key_len);
    if (status != AWRTC_PSA_SUCCESS) {
        return AWRTC_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }

    return ecdsa_verify_psa(key, key_len, curve, curve_bits,
                            hash, hash_len, sig, sig_len);
}

#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
static int ecdsa_verify_wrap(awrtc_mbedtls_pk_context *pk,
                             awrtc_mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len)
{
    (void) md_alg;
    awrtc_psa_ecc_family_t curve = pk->ec_family;
    size_t curve_bits = pk->ec_bits;

    return ecdsa_verify_psa(pk->pub_raw, pk->pub_raw_len, curve, curve_bits,
                            hash, hash_len, sig, sig_len);
}
#else /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
static int ecdsa_verify_wrap(awrtc_mbedtls_pk_context *pk,
                             awrtc_mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len)
{
    (void) md_alg;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ecp_keypair *ctx = pk->pk_ctx;
    unsigned char key[AWRTC_MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t key_len;
    size_t curve_bits;
    awrtc_psa_ecc_family_t curve = awrtc_mbedtls_ecc_group_to_psa(ctx->grp.id, &curve_bits);

    ret = awrtc_mbedtls_ecp_point_write_binary(&ctx->grp, &ctx->Q,
                                         AWRTC_MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &key_len, key, sizeof(key));
    if (ret != 0) {
        return ret;
    }

    return ecdsa_verify_psa(key, key_len, curve, curve_bits,
                            hash, hash_len, sig, sig_len);
}
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
#else /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
static int ecdsa_verify_wrap(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) md_alg);

    ret = awrtc_mbedtls_ecdsa_read_signature((awrtc_mbedtls_ecdsa_context *) pk->pk_ctx,
                                       hash, hash_len, sig, sig_len);

    if (ret == AWRTC_MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH) {
        return AWRTC_MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return ret;
}
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
#endif /* AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY */

#if defined(AWRTC_MBEDTLS_PK_CAN_ECDSA_SIGN)
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
/* Common helper for ECDSA sign using PSA functions.
 * Instead of extracting key's properties in order to check which kind of ECDSA
 * signature it supports, we try both deterministic and non-deterministic.
 */
static int ecdsa_sign_psa(awrtc_mbedtls_svc_key_id_t key_id, awrtc_mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          unsigned char *sig, size_t sig_size, size_t *sig_len)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_status_t status;
    awrtc_psa_key_attributes_t key_attr = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    size_t key_bits = 0;

    status = awrtc_psa_get_key_attributes(key_id, &key_attr);
    if (status != AWRTC_PSA_SUCCESS) {
        return AWRTC_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }
    key_bits = awrtc_psa_get_key_bits(&key_attr);
    awrtc_psa_reset_key_attributes(&key_attr);

    status = awrtc_psa_sign_hash(key_id,
                           AWRTC_PSA_ALG_DETERMINISTIC_ECDSA(awrtc_mbedtls_md_psa_alg_from_type(md_alg)),
                           hash, hash_len, sig, sig_size, sig_len);
    if (status == AWRTC_PSA_SUCCESS) {
        goto done;
    } else if (status != AWRTC_PSA_ERROR_NOT_PERMITTED) {
        return AWRTC_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }

    status = awrtc_psa_sign_hash(key_id,
                           AWRTC_PSA_ALG_ECDSA(awrtc_mbedtls_md_psa_alg_from_type(md_alg)),
                           hash, hash_len, sig, sig_size, sig_len);
    if (status != AWRTC_PSA_SUCCESS) {
        return AWRTC_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }

done:
    ret = awrtc_mbedtls_ecdsa_raw_to_der(key_bits, sig, *sig_len, sig, sig_size, sig_len);

    return ret;
}

static int ecdsa_opaque_sign_wrap(awrtc_mbedtls_pk_context *pk,
                                  awrtc_mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hash_len,
                                  unsigned char *sig, size_t sig_size,
                                  size_t *sig_len,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    ((void) f_rng);
    ((void) p_rng);

    return ecdsa_sign_psa(pk->priv_id, md_alg, hash, hash_len, sig, sig_size,
                          sig_len);
}

#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
/* When PK_USE_PSA_EC_DATA is defined opaque and non-opaque keys end up
 * using the same function. */
#define ecdsa_sign_wrap     ecdsa_opaque_sign_wrap
#else /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
static int ecdsa_sign_wrap(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           unsigned char *sig, size_t sig_size, size_t *sig_len,
                           int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_svc_key_id_t key_id = AWRTC_MBEDTLS_SVC_KEY_ID_INIT;
    awrtc_psa_status_t status;
    awrtc_mbedtls_ecp_keypair *ctx = pk->pk_ctx;
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    unsigned char buf[AWRTC_MBEDTLS_PSA_MAX_EC_KEY_PAIR_LENGTH];
    size_t curve_bits;
    awrtc_psa_ecc_family_t curve =
        awrtc_mbedtls_ecc_group_to_psa(ctx->grp.id, &curve_bits);
    size_t key_len = AWRTC_PSA_BITS_TO_BYTES(curve_bits);
    awrtc_psa_algorithm_t awrtc_psa_hash = awrtc_mbedtls_md_psa_alg_from_type(md_alg);
    awrtc_psa_algorithm_t awrtc_psa_sig_md = AWRTC_MBEDTLS_PK_PSA_ALG_ECDSA_MAYBE_DET(awrtc_psa_hash);
    ((void) f_rng);
    ((void) p_rng);

    if (curve == 0) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (key_len > sizeof(buf)) {
        return AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    ret = awrtc_mbedtls_mpi_write_binary(&ctx->d, buf, key_len);
    if (ret != 0) {
        goto cleanup;
    }

    awrtc_psa_set_key_type(&attributes, AWRTC_PSA_KEY_TYPE_ECC_KEY_PAIR(curve));
    awrtc_psa_set_key_usage_flags(&attributes, AWRTC_PSA_KEY_USAGE_SIGN_HASH);
    awrtc_psa_set_key_algorithm(&attributes, awrtc_psa_sig_md);

    status = awrtc_psa_import_key(&attributes, buf, key_len, &key_id);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = ecdsa_sign_psa(key_id, md_alg, hash, hash_len, sig, sig_size, sig_len);

cleanup:
    awrtc_mbedtls_platform_zeroize(buf, sizeof(buf));
    status = awrtc_psa_destroy_key(key_id);
    if (ret == 0 && status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
#else /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
static int ecdsa_sign_wrap(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           unsigned char *sig, size_t sig_size, size_t *sig_len,
                           int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return awrtc_mbedtls_ecdsa_write_signature((awrtc_mbedtls_ecdsa_context *) pk->pk_ctx,
                                         md_alg, hash, hash_len,
                                         sig, sig_size, sig_len,
                                         f_rng, p_rng);
}
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
#endif /* AWRTC_MBEDTLS_PK_CAN_ECDSA_SIGN */

#if defined(AWRTC_MBEDTLS_ECDSA_C) && defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
/* Forward declarations */
static int ecdsa_verify_rs_wrap(awrtc_mbedtls_pk_context *ctx, awrtc_mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx);

static int ecdsa_sign_rs_wrap(awrtc_mbedtls_pk_context *ctx, awrtc_mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx);

/*
 * Restart context for ECDSA operations with ECKEY context
 *
 * We need to store an actual ECDSA context, as we need to pass the same to
 * the underlying ecdsa function, so we can't create it on the fly every time.
 */
typedef struct {
    awrtc_mbedtls_ecdsa_restart_ctx ecdsa_rs;
    awrtc_mbedtls_ecdsa_context ecdsa_ctx;
} eckey_restart_ctx;

static void *eckey_rs_alloc(void)
{
    eckey_restart_ctx *rs_ctx;

    void *ctx = awrtc_mbedtls_calloc(1, sizeof(eckey_restart_ctx));

    if (ctx != NULL) {
        rs_ctx = ctx;
        awrtc_mbedtls_ecdsa_restart_init(&rs_ctx->ecdsa_rs);
        awrtc_mbedtls_ecdsa_init(&rs_ctx->ecdsa_ctx);
    }

    return ctx;
}

static void eckey_rs_free(void *ctx)
{
    eckey_restart_ctx *rs_ctx;

    if (ctx == NULL) {
        return;
    }

    rs_ctx = ctx;
    awrtc_mbedtls_ecdsa_restart_free(&rs_ctx->ecdsa_rs);
    awrtc_mbedtls_ecdsa_free(&rs_ctx->ecdsa_ctx);

    awrtc_mbedtls_free(ctx);
}

static int eckey_verify_rs_wrap(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    eckey_restart_ctx *rs = rs_ctx;

    /* Should never happen */
    if (rs == NULL) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /* set up our own sub-context if needed (that is, on first run) */
    if (rs->ecdsa_ctx.grp.pbits == 0) {
        AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_ecdsa_from_keypair(&rs->ecdsa_ctx, pk->pk_ctx));
    }

    AWRTC_MBEDTLS_MPI_CHK(ecdsa_verify_rs_wrap(pk,
                                         md_alg, hash, hash_len,
                                         sig, sig_len, &rs->ecdsa_rs));

cleanup:
    return ret;
}

static int eckey_sign_rs_wrap(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    eckey_restart_ctx *rs = rs_ctx;

    /* Should never happen */
    if (rs == NULL) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /* set up our own sub-context if needed (that is, on first run) */
    if (rs->ecdsa_ctx.grp.pbits == 0) {
        AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_ecdsa_from_keypair(&rs->ecdsa_ctx, pk->pk_ctx));
    }

    AWRTC_MBEDTLS_MPI_CHK(ecdsa_sign_rs_wrap(pk, md_alg,
                                       hash, hash_len, sig, sig_size, sig_len,
                                       f_rng, p_rng, &rs->ecdsa_rs));

cleanup:
    return ret;
}
#endif /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
static int eckey_check_pair_psa(awrtc_mbedtls_pk_context *pub, awrtc_mbedtls_pk_context *prv)
{
    awrtc_psa_status_t status;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint8_t prv_key_buf[AWRTC_MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t prv_key_len;
    awrtc_mbedtls_svc_key_id_t key_id = prv->priv_id;

    status = awrtc_psa_export_public_key(key_id, prv_key_buf, sizeof(prv_key_buf),
                                   &prv_key_len);
    ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
    if (ret != 0) {
        return ret;
    }

    if (memcmp(prv_key_buf, pub->pub_raw, pub->pub_raw_len) != 0) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    return 0;
}
#else /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
static int eckey_check_pair_psa(awrtc_mbedtls_pk_context *pub, awrtc_mbedtls_pk_context *prv)
{
    awrtc_psa_status_t status;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint8_t prv_key_buf[AWRTC_MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t prv_key_len;
    awrtc_psa_status_t destruction_status;
    awrtc_mbedtls_svc_key_id_t key_id = AWRTC_MBEDTLS_SVC_KEY_ID_INIT;
    awrtc_psa_key_attributes_t key_attr = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    uint8_t pub_key_buf[AWRTC_MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t pub_key_len;
    size_t curve_bits;
    const awrtc_psa_ecc_family_t curve =
        awrtc_mbedtls_ecc_group_to_psa(awrtc_mbedtls_pk_ec_ro(*prv)->grp.id, &curve_bits);
    const size_t curve_bytes = AWRTC_PSA_BITS_TO_BYTES(curve_bits);

    if (curve == 0) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    awrtc_psa_set_key_type(&key_attr, AWRTC_PSA_KEY_TYPE_ECC_KEY_PAIR(curve));
    awrtc_psa_set_key_usage_flags(&key_attr, AWRTC_PSA_KEY_USAGE_EXPORT);

    ret = awrtc_mbedtls_mpi_write_binary(&awrtc_mbedtls_pk_ec_ro(*prv)->d,
                                   prv_key_buf, curve_bytes);
    if (ret != 0) {
        awrtc_mbedtls_platform_zeroize(prv_key_buf, sizeof(prv_key_buf));
        return ret;
    }

    status = awrtc_psa_import_key(&key_attr, prv_key_buf, curve_bytes, &key_id);
    awrtc_mbedtls_platform_zeroize(prv_key_buf, sizeof(prv_key_buf));
    ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
    if (ret != 0) {
        return ret;
    }

    // From now on prv_key_buf is used to store the public key of prv.
    status = awrtc_psa_export_public_key(key_id, prv_key_buf, sizeof(prv_key_buf),
                                   &prv_key_len);
    ret = AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
    destruction_status = awrtc_psa_destroy_key(key_id);
    if (ret != 0) {
        return ret;
    } else if (destruction_status != AWRTC_PSA_SUCCESS) {
        return AWRTC_PSA_PK_TO_MBEDTLS_ERR(destruction_status);
    }

    ret = awrtc_mbedtls_ecp_point_write_binary(&awrtc_mbedtls_pk_ec_rw(*pub)->grp,
                                         &awrtc_mbedtls_pk_ec_rw(*pub)->Q,
                                         AWRTC_MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &pub_key_len, pub_key_buf,
                                         sizeof(pub_key_buf));
    if (ret != 0) {
        return ret;
    }

    if (memcmp(prv_key_buf, pub_key_buf, curve_bytes) != 0) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    return 0;
}
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */

static int eckey_check_pair_wrap(awrtc_mbedtls_pk_context *pub, awrtc_mbedtls_pk_context *prv,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng)
{
    (void) f_rng;
    (void) p_rng;
    return eckey_check_pair_psa(pub, prv);
}
#else /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
static int eckey_check_pair_wrap(awrtc_mbedtls_pk_context *pub, awrtc_mbedtls_pk_context *prv,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng)
{
    return awrtc_mbedtls_ecp_check_pub_priv((const awrtc_mbedtls_ecp_keypair *) pub->pk_ctx,
                                      (const awrtc_mbedtls_ecp_keypair *) prv->pk_ctx,
                                      f_rng, p_rng);
}
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
/* When PK_USE_PSA_EC_DATA is defined opaque and non-opaque keys end up
 * using the same function. */
#define ecdsa_opaque_check_pair_wrap    eckey_check_pair_wrap
#else /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
static int ecdsa_opaque_check_pair_wrap(awrtc_mbedtls_pk_context *pub,
                                        awrtc_mbedtls_pk_context *prv,
                                        int (*f_rng)(void *, unsigned char *, size_t),
                                        void *p_rng)
{
    awrtc_psa_status_t status;
    uint8_t exp_pub_key[AWRTC_MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN];
    size_t exp_pub_key_len = 0;
    uint8_t pub_key[AWRTC_MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN];
    size_t pub_key_len = 0;
    int ret;
    (void) f_rng;
    (void) p_rng;

    status = awrtc_psa_export_public_key(prv->priv_id, exp_pub_key, sizeof(exp_pub_key),
                                   &exp_pub_key_len);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = awrtc_psa_pk_status_to_mbedtls(status);
        return ret;
    }
    ret = awrtc_mbedtls_ecp_point_write_binary(&(awrtc_mbedtls_pk_ec_ro(*pub)->grp),
                                         &(awrtc_mbedtls_pk_ec_ro(*pub)->Q),
                                         AWRTC_MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &pub_key_len, pub_key, sizeof(pub_key));
    if (ret != 0) {
        return ret;
    }
    if ((exp_pub_key_len != pub_key_len) ||
        memcmp(exp_pub_key, pub_key, exp_pub_key_len)) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    return 0;
}
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#if !defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
static void *eckey_alloc_wrap(void)
{
    void *ctx = awrtc_mbedtls_calloc(1, sizeof(awrtc_mbedtls_ecp_keypair));

    if (ctx != NULL) {
        awrtc_mbedtls_ecp_keypair_init(ctx);
    }

    return ctx;
}

static void eckey_free_wrap(void *ctx)
{
    awrtc_mbedtls_ecp_keypair_free((awrtc_mbedtls_ecp_keypair *) ctx);
    awrtc_mbedtls_free(ctx);
}
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */

static void eckey_debug(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_pk_debug_item *items)
{
#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
    items->type = AWRTC_MBEDTLS_PK_DEBUG_PSA_EC;
    items->name = "eckey.Q";
    items->value = pk;
#else /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
    awrtc_mbedtls_ecp_keypair *ecp = (awrtc_mbedtls_ecp_keypair *) pk->pk_ctx;
    items->type = AWRTC_MBEDTLS_PK_DEBUG_ECP;
    items->name = "eckey.Q";
    items->value = &(ecp->Q);
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
}

const awrtc_mbedtls_pk_info_t awrtc_mbedtls_eckey_info = {
    .type = AWRTC_MBEDTLS_PK_ECKEY,
    .name = "EC",
    .get_bitlen = eckey_get_bitlen,
    .can_do = eckey_can_do,
#if defined(AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY)
    .verify_func = ecdsa_verify_wrap,   /* Compatible key structures */
#else /* AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(AWRTC_MBEDTLS_PK_CAN_ECDSA_SIGN)
    .sign_func = ecdsa_sign_wrap,   /* Compatible key structures */
#else /* AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .sign_func = NULL,
#endif /* AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(AWRTC_MBEDTLS_ECDSA_C) && defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = eckey_verify_rs_wrap,
    .sign_rs_func = eckey_sign_rs_wrap,
    .rs_alloc_func = eckey_rs_alloc,
    .rs_free_func = eckey_rs_free,
#endif /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = eckey_check_pair_wrap,
#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
    .ctx_alloc_func = eckey_alloc_wrap,
    .ctx_free_func = eckey_free_wrap,
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
    .debug_func = eckey_debug,
};

/*
 * EC key restricted to ECDH
 */
static int eckeydh_can_do(awrtc_mbedtls_pk_type_t type)
{
    return type == AWRTC_MBEDTLS_PK_ECKEY ||
           type == AWRTC_MBEDTLS_PK_ECKEY_DH;
}

const awrtc_mbedtls_pk_info_t awrtc_mbedtls_eckeydh_info = {
    .type = AWRTC_MBEDTLS_PK_ECKEY_DH,
    .name = "EC_DH",
    .get_bitlen = eckey_get_bitlen,         /* Same underlying key structure */
    .can_do = eckeydh_can_do,
    .verify_func = NULL,
    .sign_func = NULL,
#if defined(AWRTC_MBEDTLS_ECDSA_C) && defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
#endif /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = eckey_check_pair_wrap,
#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
    .ctx_alloc_func = eckey_alloc_wrap,   /* Same underlying key structure */
    .ctx_free_func = eckey_free_wrap,    /* Same underlying key structure */
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
    .debug_func = eckey_debug,            /* Same underlying key structure */
};

#if defined(AWRTC_MBEDTLS_PK_CAN_ECDSA_SOME)
static int ecdsa_can_do(awrtc_mbedtls_pk_type_t type)
{
    return type == AWRTC_MBEDTLS_PK_ECDSA;
}

#if defined(AWRTC_MBEDTLS_ECDSA_C) && defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
static int ecdsa_verify_rs_wrap(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) md_alg);

    ret = awrtc_mbedtls_ecdsa_read_signature_restartable(
        (awrtc_mbedtls_ecdsa_context *) pk->pk_ctx,
        hash, hash_len, sig, sig_len,
        (awrtc_mbedtls_ecdsa_restart_ctx *) rs_ctx);

    if (ret == AWRTC_MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH) {
        return AWRTC_MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return ret;
}

static int ecdsa_sign_rs_wrap(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx)
{
    return awrtc_mbedtls_ecdsa_write_signature_restartable(
        (awrtc_mbedtls_ecdsa_context *) pk->pk_ctx,
        md_alg, hash, hash_len, sig, sig_size, sig_len, f_rng, p_rng,
        (awrtc_mbedtls_ecdsa_restart_ctx *) rs_ctx);

}

static void *ecdsa_rs_alloc(void)
{
    void *ctx = awrtc_mbedtls_calloc(1, sizeof(awrtc_mbedtls_ecdsa_restart_ctx));

    if (ctx != NULL) {
        awrtc_mbedtls_ecdsa_restart_init(ctx);
    }

    return ctx;
}

static void ecdsa_rs_free(void *ctx)
{
    awrtc_mbedtls_ecdsa_restart_free(ctx);
    awrtc_mbedtls_free(ctx);
}
#endif /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */

const awrtc_mbedtls_pk_info_t awrtc_mbedtls_ecdsa_info = {
    .type = AWRTC_MBEDTLS_PK_ECDSA,
    .name = "ECDSA",
    .get_bitlen = eckey_get_bitlen,     /* Compatible key structures */
    .can_do = ecdsa_can_do,
#if defined(AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY)
    .verify_func = ecdsa_verify_wrap,   /* Compatible key structures */
#else /* AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(AWRTC_MBEDTLS_PK_CAN_ECDSA_SIGN)
    .sign_func = ecdsa_sign_wrap,   /* Compatible key structures */
#else /* AWRTC_MBEDTLS_PK_CAN_ECDSA_SIGN */
    .sign_func = NULL,
#endif /* AWRTC_MBEDTLS_PK_CAN_ECDSA_SIGN */
#if defined(AWRTC_MBEDTLS_ECDSA_C) && defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = ecdsa_verify_rs_wrap,
    .sign_rs_func = ecdsa_sign_rs_wrap,
    .rs_alloc_func = ecdsa_rs_alloc,
    .rs_free_func = ecdsa_rs_free,
#endif /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = eckey_check_pair_wrap,   /* Compatible key structures */
#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
    .ctx_alloc_func = eckey_alloc_wrap,   /* Compatible key structures */
    .ctx_free_func = eckey_free_wrap,   /* Compatible key structures */
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
    .debug_func = eckey_debug,        /* Compatible key structures */
};
#endif /* AWRTC_MBEDTLS_PK_CAN_ECDSA_SOME */
#endif /* AWRTC_MBEDTLS_PK_HAVE_ECC_KEYS */

#if defined(AWRTC_MBEDTLS_PK_RSA_ALT_SUPPORT)
/*
 * Support for alternative RSA-private implementations
 */

static int rsa_alt_can_do(awrtc_mbedtls_pk_type_t type)
{
    return type == AWRTC_MBEDTLS_PK_RSA;
}

static size_t rsa_alt_get_bitlen(awrtc_mbedtls_pk_context *pk)
{
    const awrtc_mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

    return 8 * rsa_alt->key_len_func(rsa_alt->key);
}

static int rsa_alt_sign_wrap(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             unsigned char *sig, size_t sig_size, size_t *sig_len,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    awrtc_mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

#if SIZE_MAX > UINT_MAX
    if (UINT_MAX < hash_len) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    *sig_len = rsa_alt->key_len_func(rsa_alt->key);
    if (*sig_len > AWRTC_MBEDTLS_PK_SIGNATURE_MAX_SIZE) {
        return AWRTC_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    if (*sig_len > sig_size) {
        return AWRTC_MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    return rsa_alt->sign_func(rsa_alt->key, f_rng, p_rng,
                              md_alg, (unsigned int) hash_len, hash, sig);
}

static int rsa_alt_decrypt_wrap(awrtc_mbedtls_pk_context *pk,
                                const unsigned char *input, size_t ilen,
                                unsigned char *output, size_t *olen, size_t osize,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    awrtc_mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

    ((void) f_rng);
    ((void) p_rng);

    if (ilen != rsa_alt->key_len_func(rsa_alt->key)) {
        return AWRTC_MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    return rsa_alt->decrypt_func(rsa_alt->key,
                                 olen, input, output, osize);
}

#if defined(AWRTC_MBEDTLS_RSA_C)
static int rsa_alt_check_pair(awrtc_mbedtls_pk_context *pub, awrtc_mbedtls_pk_context *prv,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    unsigned char hash[32];
    size_t sig_len = 0;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (rsa_alt_get_bitlen(prv) != rsa_get_bitlen(pub)) {
        return AWRTC_MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

    size_t sig_size = (rsa_get_bitlen(pub) + 7) / 8;
    unsigned char *sig = awrtc_mbedtls_calloc(1, sig_size);
    if (sig == NULL) {
        return AWRTC_MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    memset(hash, 0x2a, sizeof(hash));

    if ((ret = rsa_alt_sign_wrap(prv, AWRTC_MBEDTLS_MD_NONE,
                                 hash, sizeof(hash),
                                 sig, sig_size, &sig_len,
                                 f_rng, p_rng)) != 0) {
        goto cleanup;
    }

    if (rsa_verify_wrap(pub, AWRTC_MBEDTLS_MD_NONE,
                        hash, sizeof(hash), sig, sig_len) != 0) {
        ret = AWRTC_MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

cleanup:
    awrtc_mbedtls_zeroize_and_free(sig, sig_size);
    return ret;
}
#endif /* AWRTC_MBEDTLS_RSA_C */

static void *rsa_alt_alloc_wrap(void)
{
    void *ctx = awrtc_mbedtls_calloc(1, sizeof(awrtc_mbedtls_rsa_alt_context));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(awrtc_mbedtls_rsa_alt_context));
    }

    return ctx;
}

static void rsa_alt_free_wrap(void *ctx)
{
    awrtc_mbedtls_zeroize_and_free(ctx, sizeof(awrtc_mbedtls_rsa_alt_context));
}

const awrtc_mbedtls_pk_info_t awrtc_mbedtls_rsa_alt_info = {
    .type = AWRTC_MBEDTLS_PK_RSA_ALT,
    .name = "RSA-alt",
    .get_bitlen = rsa_alt_get_bitlen,
    .can_do = rsa_alt_can_do,
    .verify_func = NULL,
    .sign_func = rsa_alt_sign_wrap,
#if defined(AWRTC_MBEDTLS_ECDSA_C) && defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = rsa_alt_decrypt_wrap,
    .encrypt_func = NULL,
#if defined(AWRTC_MBEDTLS_RSA_C)
    .check_pair_func = rsa_alt_check_pair,
#else
    .check_pair_func = NULL,
#endif
    .ctx_alloc_func = rsa_alt_alloc_wrap,
    .ctx_free_func = rsa_alt_free_wrap,
    .debug_func = NULL,
};
#endif /* AWRTC_MBEDTLS_PK_RSA_ALT_SUPPORT */

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
static size_t opaque_get_bitlen(awrtc_mbedtls_pk_context *pk)
{
    size_t bits;
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;

    if (AWRTC_PSA_SUCCESS != awrtc_psa_get_key_attributes(pk->priv_id, &attributes)) {
        return 0;
    }

    bits = awrtc_psa_get_key_bits(&attributes);
    awrtc_psa_reset_key_attributes(&attributes);
    return bits;
}

#if defined(AWRTC_MBEDTLS_PK_HAVE_ECC_KEYS)
static int ecdsa_opaque_can_do(awrtc_mbedtls_pk_type_t type)
{
    return type == AWRTC_MBEDTLS_PK_ECKEY ||
           type == AWRTC_MBEDTLS_PK_ECDSA;
}

const awrtc_mbedtls_pk_info_t awrtc_mbedtls_ecdsa_opaque_info = {
    .type = AWRTC_MBEDTLS_PK_OPAQUE,
    .name = "Opaque",
    .get_bitlen = opaque_get_bitlen,
    .can_do = ecdsa_opaque_can_do,
#if defined(AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY)
    .verify_func = ecdsa_opaque_verify_wrap,
#else /* AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(AWRTC_MBEDTLS_PK_CAN_ECDSA_SIGN)
    .sign_func = ecdsa_opaque_sign_wrap,
#else /* AWRTC_MBEDTLS_PK_CAN_ECDSA_SIGN */
    .sign_func = NULL,
#endif /* AWRTC_MBEDTLS_PK_CAN_ECDSA_SIGN */
#if defined(AWRTC_MBEDTLS_ECDSA_C) && defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = ecdsa_opaque_check_pair_wrap,
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
    .debug_func = NULL,
};
#endif /* AWRTC_MBEDTLS_PK_HAVE_ECC_KEYS */

static int rsa_opaque_can_do(awrtc_mbedtls_pk_type_t type)
{
    return type == AWRTC_MBEDTLS_PK_RSA ||
           type == AWRTC_MBEDTLS_PK_RSASSA_PSS;
}

#if defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
static int rsa_opaque_decrypt(awrtc_mbedtls_pk_context *pk,
                              const unsigned char *input, size_t ilen,
                              unsigned char *output, size_t *olen, size_t osize,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_psa_algorithm_t alg;
    awrtc_psa_key_type_t type;
    awrtc_psa_status_t status;

    /* PSA has its own RNG */
    (void) f_rng;
    (void) p_rng;

    status = awrtc_psa_get_key_attributes(pk->priv_id, &attributes);
    if (status != AWRTC_PSA_SUCCESS) {
        return AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
    }

    type = awrtc_psa_get_key_type(&attributes);
    alg = awrtc_psa_get_key_algorithm(&attributes);
    awrtc_psa_reset_key_attributes(&attributes);

    if (!AWRTC_PSA_KEY_TYPE_IS_RSA(type)) {
        return AWRTC_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }

    status = awrtc_psa_asymmetric_decrypt(pk->priv_id, alg, input, ilen, NULL, 0, output, osize, olen);
    if (status != AWRTC_PSA_SUCCESS) {
        return AWRTC_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
    }

    return 0;
}
#endif /* AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */

static int rsa_opaque_sign_wrap(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
#if defined(AWRTC_MBEDTLS_RSA_C)
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_psa_algorithm_t alg;
    awrtc_psa_key_type_t type;
    awrtc_psa_status_t status;

    /* PSA has its own RNG */
    (void) f_rng;
    (void) p_rng;

    status = awrtc_psa_get_key_attributes(pk->priv_id, &attributes);
    if (status != AWRTC_PSA_SUCCESS) {
        return AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
    }

    type = awrtc_psa_get_key_type(&attributes);
    alg = awrtc_psa_get_key_algorithm(&attributes);
    awrtc_psa_reset_key_attributes(&attributes);

    if (AWRTC_PSA_KEY_TYPE_IS_RSA(type)) {
        alg = (alg & ~AWRTC_PSA_ALG_HASH_MASK) | awrtc_mbedtls_md_psa_alg_from_type(md_alg);
    } else {
        return AWRTC_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }

    status = awrtc_psa_sign_hash(pk->priv_id, alg, hash, hash_len, sig, sig_size, sig_len);
    if (status != AWRTC_PSA_SUCCESS) {
        if (AWRTC_PSA_KEY_TYPE_IS_RSA(type)) {
            return AWRTC_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        } else {
            return AWRTC_PSA_PK_TO_MBEDTLS_ERR(status);
        }
    }

    return 0;
#else /* !AWRTC_MBEDTLS_RSA_C */
    ((void) pk);
    ((void) md_alg);
    ((void) hash);
    ((void) hash_len);
    ((void) sig);
    ((void) sig_size);
    ((void) sig_len);
    ((void) f_rng);
    ((void) p_rng);
    return AWRTC_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#endif /* !AWRTC_MBEDTLS_RSA_C */
}

const awrtc_mbedtls_pk_info_t awrtc_mbedtls_rsa_opaque_info = {
    .type = AWRTC_MBEDTLS_PK_OPAQUE,
    .name = "Opaque",
    .get_bitlen = opaque_get_bitlen,
    .can_do = rsa_opaque_can_do,
    .verify_func = NULL,
    .sign_func = rsa_opaque_sign_wrap,
#if defined(AWRTC_MBEDTLS_ECDSA_C) && defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */
#if defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
    .decrypt_func = rsa_opaque_decrypt,
#else /* AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */
    .decrypt_func = NULL,
#endif /* AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */
    .encrypt_func = NULL,
    .check_pair_func = NULL,
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
    .debug_func = NULL,
};

#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#endif /* AWRTC_MBEDTLS_PK_C */
