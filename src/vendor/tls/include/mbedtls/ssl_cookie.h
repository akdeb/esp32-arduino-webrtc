/**
 * \file ssl_cookie.h
 *
 * \brief DTLS cookie callbacks implementation
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef AWRTC_MBEDTLS_SSL_COOKIE_H
#define AWRTC_MBEDTLS_SSL_COOKIE_H
#include "private_access.h"

#include "build_info.h"

#include "ssl.h"

#if !defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
#if defined(AWRTC_MBEDTLS_THREADING_C)
#include "threading.h"
#endif
#endif /* !AWRTC_MBEDTLS_USE_PSA_CRYPTO */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in awrtc_mbedtls_config.h or define them on the compiler command line.
 * \{
 */
#ifndef AWRTC_MBEDTLS_SSL_COOKIE_TIMEOUT
#define AWRTC_MBEDTLS_SSL_COOKIE_TIMEOUT     60 /**< Default expiration delay of DTLS cookies, in seconds if HAVE_TIME, or in number of cookies issued */
#endif

/** \} name SECTION: Module settings */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Context for the default cookie functions.
 */
typedef struct awrtc_mbedtls_ssl_cookie_ctx {
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_mbedtls_svc_key_id_t    AWRTC_MBEDTLS_PRIVATE(awrtc_psa_hmac_key);  /*!< key id for the HMAC portion   */
    awrtc_psa_algorithm_t         AWRTC_MBEDTLS_PRIVATE(awrtc_psa_hmac_alg);  /*!< key algorithm for the HMAC portion   */
#else
    awrtc_mbedtls_md_context_t    AWRTC_MBEDTLS_PRIVATE(hmac_ctx);   /*!< context for the HMAC portion   */
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
#if !defined(AWRTC_MBEDTLS_HAVE_TIME)
    unsigned long   AWRTC_MBEDTLS_PRIVATE(serial);     /*!< serial number for expiration   */
#endif
    unsigned long   AWRTC_MBEDTLS_PRIVATE(timeout);    /*!< timeout delay, in seconds if HAVE_TIME,
                                                    or in number of tickets issued */

#if !defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
#if defined(AWRTC_MBEDTLS_THREADING_C)
    awrtc_mbedtls_threading_mutex_t AWRTC_MBEDTLS_PRIVATE(mutex);
#endif
#endif /* !AWRTC_MBEDTLS_USE_PSA_CRYPTO */
} awrtc_mbedtls_ssl_cookie_ctx;

/**
 * \brief          Initialize cookie context
 */
void awrtc_mbedtls_ssl_cookie_init(awrtc_mbedtls_ssl_cookie_ctx *ctx);

/**
 * \brief          Setup cookie context (generate keys)
 */
int awrtc_mbedtls_ssl_cookie_setup(awrtc_mbedtls_ssl_cookie_ctx *ctx,
                             awrtc_mbedtls_f_rng_t *f_rng,
                             void *p_rng);

/**
 * \brief          Set expiration delay for cookies
 *                 (Default AWRTC_MBEDTLS_SSL_COOKIE_TIMEOUT)
 *
 * \param ctx      Cookie context
 * \param delay    Delay, in seconds if HAVE_TIME, or in number of cookies
 *                 issued in the meantime.
 *                 0 to disable expiration (NOT recommended)
 */
void awrtc_mbedtls_ssl_cookie_set_timeout(awrtc_mbedtls_ssl_cookie_ctx *ctx, unsigned long delay);

/**
 * \brief          Free cookie context
 */
void awrtc_mbedtls_ssl_cookie_free(awrtc_mbedtls_ssl_cookie_ctx *ctx);

/**
 * \brief          Generate cookie, see \c awrtc_mbedtls_ssl_cookie_write_t
 */
awrtc_mbedtls_ssl_cookie_write_t awrtc_mbedtls_ssl_cookie_write;

/**
 * \brief          Verify cookie, see \c awrtc_mbedtls_ssl_cookie_write_t
 */
awrtc_mbedtls_ssl_cookie_check_t awrtc_mbedtls_ssl_cookie_check;

#ifdef __cplusplus
}
#endif

#endif /* ssl_cookie.h */
