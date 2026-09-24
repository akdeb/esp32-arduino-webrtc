/*
 *  DTLS cookie callbacks implementation
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 * These session callbacks use a simple chained list
 * to store and retrieve the session information.
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_SSL_COOKIE_C)

#include "../include/mbedtls/platform.h"

#include "../include/mbedtls/ssl_cookie.h"
#include "ssl_misc.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/constant_time.h"

#include <string.h>

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
#include "../include/mbedtls/psa_util.h"
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
 * If DTLS is in use, then at least one of SHA-256 or SHA-384 is
 * available. Try SHA-256 first as 384 wastes resources
 */
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA256)
#define COOKIE_MD           AWRTC_MBEDTLS_MD_SHA256
#define COOKIE_MD_OUTLEN    32
#define COOKIE_HMAC_LEN     28
#elif defined(AWRTC_MBEDTLS_MD_CAN_SHA384)
#define COOKIE_MD           AWRTC_MBEDTLS_MD_SHA384
#define COOKIE_MD_OUTLEN    48
#define COOKIE_HMAC_LEN     28
#else
#error "DTLS hello verify needs SHA-256 or SHA-384"
#endif

/*
 * Cookies are formed of a 4-bytes timestamp (or serial number) and
 * an HMAC of timestamp and client ID.
 */
#define COOKIE_LEN      (4 + COOKIE_HMAC_LEN)

void awrtc_mbedtls_ssl_cookie_init(awrtc_mbedtls_ssl_cookie_ctx *ctx)
{
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    ctx->awrtc_psa_hmac_key = AWRTC_MBEDTLS_SVC_KEY_ID_INIT;
#else
    awrtc_mbedtls_md_init(&ctx->hmac_ctx);
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
#if !defined(AWRTC_MBEDTLS_HAVE_TIME)
    ctx->serial = 0;
#endif
    ctx->timeout = AWRTC_MBEDTLS_SSL_COOKIE_TIMEOUT;

#if !defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
#if defined(AWRTC_MBEDTLS_THREADING_C)
    awrtc_mbedtls_mutex_init(&ctx->mutex);
#endif
#endif /* !AWRTC_MBEDTLS_USE_PSA_CRYPTO */
}

void awrtc_mbedtls_ssl_cookie_set_timeout(awrtc_mbedtls_ssl_cookie_ctx *ctx, unsigned long delay)
{
    ctx->timeout = delay;
}

void awrtc_mbedtls_ssl_cookie_free(awrtc_mbedtls_ssl_cookie_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_destroy_key(ctx->awrtc_psa_hmac_key);
#else
    awrtc_mbedtls_md_free(&ctx->hmac_ctx);

#if defined(AWRTC_MBEDTLS_THREADING_C)
    awrtc_mbedtls_mutex_free(&ctx->mutex);
#endif
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    awrtc_mbedtls_platform_zeroize(ctx, sizeof(awrtc_mbedtls_ssl_cookie_ctx));
}

int awrtc_mbedtls_ssl_cookie_setup(awrtc_mbedtls_ssl_cookie_ctx *ctx,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_algorithm_t alg;

    (void) f_rng;
    (void) p_rng;

    alg = awrtc_mbedtls_md_psa_alg_from_type(COOKIE_MD);
    if (alg == 0) {
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ctx->awrtc_psa_hmac_alg = AWRTC_PSA_ALG_TRUNCATED_MAC(AWRTC_PSA_ALG_HMAC(alg),
                                              COOKIE_HMAC_LEN);

    awrtc_psa_set_key_usage_flags(&attributes, AWRTC_PSA_KEY_USAGE_VERIFY_MESSAGE |
                            AWRTC_PSA_KEY_USAGE_SIGN_MESSAGE);
    awrtc_psa_set_key_algorithm(&attributes, ctx->awrtc_psa_hmac_alg);
    awrtc_psa_set_key_type(&attributes, AWRTC_PSA_KEY_TYPE_HMAC);
    awrtc_psa_set_key_bits(&attributes, AWRTC_PSA_BYTES_TO_BITS(COOKIE_MD_OUTLEN));

    if ((status = awrtc_psa_generate_key(&attributes,
                                   &ctx->awrtc_psa_hmac_key)) != AWRTC_PSA_SUCCESS) {
        return AWRTC_PSA_TO_MBEDTLS_ERR(status);
    }
#else
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char key[COOKIE_MD_OUTLEN];

    if ((ret = f_rng(p_rng, key, sizeof(key))) != 0) {
        return ret;
    }

    ret = awrtc_mbedtls_md_setup(&ctx->hmac_ctx, awrtc_mbedtls_md_info_from_type(COOKIE_MD), 1);
    if (ret != 0) {
        return ret;
    }

    ret = awrtc_mbedtls_md_hmac_starts(&ctx->hmac_ctx, key, sizeof(key));
    if (ret != 0) {
        return ret;
    }

    awrtc_mbedtls_platform_zeroize(key, sizeof(key));
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    return 0;
}

#if !defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
/*
 * Generate the HMAC part of a cookie
 */
AWRTC_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_cookie_hmac(awrtc_mbedtls_md_context_t *hmac_ctx,
                           const unsigned char time[4],
                           unsigned char **p, unsigned char *end,
                           const unsigned char *cli_id, size_t cli_id_len)
{
    unsigned char hmac_out[COOKIE_MD_OUTLEN];

    AWRTC_MBEDTLS_SSL_CHK_BUF_PTR(*p, end, COOKIE_HMAC_LEN);

    if (awrtc_mbedtls_md_hmac_reset(hmac_ctx) != 0 ||
        awrtc_mbedtls_md_hmac_update(hmac_ctx, time, 4) != 0 ||
        awrtc_mbedtls_md_hmac_update(hmac_ctx, cli_id, cli_id_len) != 0 ||
        awrtc_mbedtls_md_hmac_finish(hmac_ctx, hmac_out) != 0) {
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    memcpy(*p, hmac_out, COOKIE_HMAC_LEN);
    *p += COOKIE_HMAC_LEN;

    return 0;
}
#endif /* !AWRTC_MBEDTLS_USE_PSA_CRYPTO */

/*
 * Generate cookie for DTLS ClientHello verification
 */
int awrtc_mbedtls_ssl_cookie_write(void *p_ctx,
                             unsigned char **p, unsigned char *end,
                             const unsigned char *cli_id, size_t cli_id_len)
{
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_mac_operation_t operation = AWRTC_PSA_MAC_OPERATION_INIT;
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    size_t sign_mac_length = 0;
#endif
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ssl_cookie_ctx *ctx = (awrtc_mbedtls_ssl_cookie_ctx *) p_ctx;
    unsigned long t;

    if (ctx == NULL || cli_id == NULL) {
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    AWRTC_MBEDTLS_SSL_CHK_BUF_PTR(*p, end, COOKIE_LEN);

#if defined(AWRTC_MBEDTLS_HAVE_TIME)
    t = (unsigned long) awrtc_mbedtls_time(NULL);
#else
    t = ctx->serial++;
#endif

    AWRTC_MBEDTLS_PUT_UINT32_BE(t, *p, 0);
    *p += 4;

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    status = awrtc_psa_mac_sign_setup(&operation, ctx->awrtc_psa_hmac_key,
                                ctx->awrtc_psa_hmac_alg);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
        goto exit;
    }

    status = awrtc_psa_mac_update(&operation, *p - 4, 4);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
        goto exit;
    }

    status = awrtc_psa_mac_update(&operation, cli_id, cli_id_len);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
        goto exit;
    }

    status = awrtc_psa_mac_sign_finish(&operation, *p, COOKIE_MD_OUTLEN,
                                 &sign_mac_length);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
        goto exit;
    }

    *p += COOKIE_HMAC_LEN;

    ret = 0;
#else
#if defined(AWRTC_MBEDTLS_THREADING_C)
    if ((ret = awrtc_mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return AWRTC_MBEDTLS_ERROR_ADD(AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR, ret);
    }
#endif

    ret = ssl_cookie_hmac(&ctx->hmac_ctx, *p - 4,
                          p, end, cli_id, cli_id_len);

#if defined(AWRTC_MBEDTLS_THREADING_C)
    if (awrtc_mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return AWRTC_MBEDTLS_ERROR_ADD(AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR,
                                 AWRTC_MBEDTLS_ERR_THREADING_MUTEX_ERROR);
    }
#endif
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
exit:
    status = awrtc_psa_mac_abort(&operation);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
    return ret;
}

/*
 * Check a cookie
 */
int awrtc_mbedtls_ssl_cookie_check(void *p_ctx,
                             const unsigned char *cookie, size_t cookie_len,
                             const unsigned char *cli_id, size_t cli_id_len)
{
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_mac_operation_t operation = AWRTC_PSA_MAC_OPERATION_INIT;
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
#else
    unsigned char ref_hmac[COOKIE_HMAC_LEN];
    unsigned char *p = ref_hmac;
#endif
    int ret = 0;
    awrtc_mbedtls_ssl_cookie_ctx *ctx = (awrtc_mbedtls_ssl_cookie_ctx *) p_ctx;
    unsigned long cur_time, cookie_time;

    if (ctx == NULL || cli_id == NULL) {
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (cookie_len != COOKIE_LEN) {
        return -1;
    }

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    status = awrtc_psa_mac_verify_setup(&operation, ctx->awrtc_psa_hmac_key,
                                  ctx->awrtc_psa_hmac_alg);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
        goto exit;
    }

    status = awrtc_psa_mac_update(&operation, cookie, 4);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
        goto exit;
    }

    status = awrtc_psa_mac_update(&operation, cli_id,
                            cli_id_len);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
        goto exit;
    }

    status = awrtc_psa_mac_verify_finish(&operation, cookie + 4,
                                   COOKIE_HMAC_LEN);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
        goto exit;
    }

    ret = 0;
#else
#if defined(AWRTC_MBEDTLS_THREADING_C)
    if ((ret = awrtc_mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return AWRTC_MBEDTLS_ERROR_ADD(AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR, ret);
    }
#endif

    if (ssl_cookie_hmac(&ctx->hmac_ctx, cookie,
                        &p, p + sizeof(ref_hmac),
                        cli_id, cli_id_len) != 0) {
        ret = -1;
    }

#if defined(AWRTC_MBEDTLS_THREADING_C)
    if (awrtc_mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        ret = AWRTC_MBEDTLS_ERROR_ADD(AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR,
                                AWRTC_MBEDTLS_ERR_THREADING_MUTEX_ERROR);
    }
#endif

    if (ret != 0) {
        goto exit;
    }

    if (awrtc_mbedtls_ct_memcmp(cookie + 4, ref_hmac, sizeof(ref_hmac)) != 0) {
        ret = -1;
        goto exit;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#if defined(AWRTC_MBEDTLS_HAVE_TIME)
    cur_time = (unsigned long) awrtc_mbedtls_time(NULL);
#else
    cur_time = ctx->serial;
#endif

    cookie_time = (unsigned long) AWRTC_MBEDTLS_GET_UINT32_BE(cookie, 0);

    if (ctx->timeout != 0 && cur_time - cookie_time > ctx->timeout) {
        ret = -1;
        goto exit;
    }

exit:
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    status = awrtc_psa_mac_abort(&operation);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
    }
#else
    awrtc_mbedtls_platform_zeroize(ref_hmac, sizeof(ref_hmac));
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
    return ret;
}
#endif /* AWRTC_MBEDTLS_SSL_COOKIE_C */
