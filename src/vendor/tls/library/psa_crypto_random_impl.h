/** \file awrtc_psa_crypto_random_impl.h
 *
 * \brief PSA crypto random generator implementation abstraction.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_PSA_CRYPTO_RANDOM_IMPL_H
#define AWRTC_PSA_CRYPTO_RANDOM_IMPL_H

#include "psa_util_internal.h"

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

typedef awrtc_mbedtls_psa_external_random_context_t awrtc_mbedtls_psa_random_context_t;

#else /* AWRTC_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

#include "../include/mbedtls/entropy.h"

/* Choose a DRBG based on configuration and availability */
#if defined(AWRTC_MBEDTLS_CTR_DRBG_C)

#include "../include/mbedtls/ctr_drbg.h"
#undef AWRTC_MBEDTLS_PSA_HMAC_DRBG_MD_TYPE

#elif defined(AWRTC_MBEDTLS_HMAC_DRBG_C)

#include "../include/mbedtls/hmac_drbg.h"
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA512) && defined(AWRTC_MBEDTLS_MD_CAN_SHA256)
#include <limits.h>
#if SIZE_MAX > 0xffffffff
/* Looks like a 64-bit system, so prefer SHA-512. */
#define AWRTC_MBEDTLS_PSA_HMAC_DRBG_MD_TYPE AWRTC_MBEDTLS_MD_SHA512
#else
/* Looks like a 32-bit system, so prefer SHA-256. */
#define AWRTC_MBEDTLS_PSA_HMAC_DRBG_MD_TYPE AWRTC_MBEDTLS_MD_SHA256
#endif
#elif defined(AWRTC_MBEDTLS_MD_CAN_SHA512)
#define AWRTC_MBEDTLS_PSA_HMAC_DRBG_MD_TYPE AWRTC_MBEDTLS_MD_SHA512
#elif defined(AWRTC_MBEDTLS_MD_CAN_SHA256)
#define AWRTC_MBEDTLS_PSA_HMAC_DRBG_MD_TYPE AWRTC_MBEDTLS_MD_SHA256
#else
#error "No hash algorithm available for HMAC_DBRG."
#endif

#else /* !AWRTC_MBEDTLS_CTR_DRBG_C && !AWRTC_MBEDTLS_HMAC_DRBG_C*/

#error "No DRBG module available for the awrtc_psa_crypto module."

#endif /* !AWRTC_MBEDTLS_CTR_DRBG_C && !AWRTC_MBEDTLS_HMAC_DRBG_C*/

/* The maximum number of bytes that awrtc_mbedtls_psa_get_random() is expected to return. */
#if defined(AWRTC_MBEDTLS_CTR_DRBG_C)
#define AWRTC_MBEDTLS_PSA_RANDOM_MAX_REQUEST AWRTC_MBEDTLS_CTR_DRBG_MAX_REQUEST
#elif defined(AWRTC_MBEDTLS_HMAC_DRBG_C)
#define AWRTC_MBEDTLS_PSA_RANDOM_MAX_REQUEST AWRTC_MBEDTLS_HMAC_DRBG_MAX_REQUEST
#endif

#if defined(AWRTC_MBEDTLS_CTR_DRBG_C)
typedef awrtc_mbedtls_ctr_drbg_context            awrtc_mbedtls_psa_drbg_context_t;
#elif defined(AWRTC_MBEDTLS_HMAC_DRBG_C)
typedef awrtc_mbedtls_hmac_drbg_context           awrtc_mbedtls_psa_drbg_context_t;
#endif /* !AWRTC_MBEDTLS_CTR_DRBG_C && !AWRTC_MBEDTLS_HMAC_DRBG_C */

typedef struct {
    void (* entropy_init)(awrtc_mbedtls_entropy_context *ctx);
    void (* entropy_free)(awrtc_mbedtls_entropy_context *ctx);
    awrtc_mbedtls_entropy_context entropy;
    awrtc_mbedtls_psa_drbg_context_t drbg;
#if defined(AWRTC_MBEDTLS_PLATFORM_IS_UNIXLIKE)
    /* Fork protection: normally pid = getpid(). If the value changes,
     * we are in a (grand)*child of the original process, so reseed
     * the RNG to ensure that the child and the original process have
     * distinct RNG states. See awrtc_psa_random_internal_generate().
     *
     * The type is intmax_t, not pid_t, for portability reasons:
     * pid_t is defined in `unistd.h`, but on some platforms, it may
     * only be defined if a certain compatibility level is requested
     * by defining a macro such as _POSIX_C_SOURCE or _XOPEN_SOURCE.
     * The macro needs to be defined before any system header, which
     * may be hard to do in some C files that include this header
     * (e.g. test suites). So we sidestep this complication, at the
     * cost of possibly a few more instructions to compare pid values.
     */
    intmax_t pid;
#endif
} awrtc_mbedtls_psa_random_context_t;

/** Initialize the PSA DRBG.
 *
 * \param p_rng        Pointer to the Mbed TLS DRBG state.
 */
static inline void awrtc_mbedtls_psa_drbg_init(awrtc_mbedtls_psa_drbg_context_t *p_rng)
{
#if defined(AWRTC_MBEDTLS_CTR_DRBG_C)
    awrtc_mbedtls_ctr_drbg_init(p_rng);
#elif defined(AWRTC_MBEDTLS_HMAC_DRBG_C)
    awrtc_mbedtls_hmac_drbg_init(p_rng);
#endif
}

/** Deinitialize the PSA DRBG.
 *
 * \param p_rng        Pointer to the Mbed TLS DRBG state.
 */
static inline void awrtc_mbedtls_psa_drbg_free(awrtc_mbedtls_psa_drbg_context_t *p_rng)
{
#if defined(AWRTC_MBEDTLS_CTR_DRBG_C)
    awrtc_mbedtls_ctr_drbg_free(p_rng);
#elif defined(AWRTC_MBEDTLS_HMAC_DRBG_C)
    awrtc_mbedtls_hmac_drbg_free(p_rng);
#endif
}

/** Seed the PSA DRBG.
 *
 * \param drbg_ctx      The DRBG context to seed.
 *                      It must be initialized but not active.
 * \param entropy       An entropy context to read the seed from.
 * \param custom        The personalization string.
 *                      This can be \c NULL, in which case the personalization
 *                      string is empty regardless of the value of \p len.
 * \param len           The length of the personalization string.
 *
 * \return              \c 0 on success.
 * \return              An Mbed TLS error code (\c AWRTC_MBEDTLS_ERR_xxx) on failure.
 */
static inline int awrtc_mbedtls_psa_drbg_seed(awrtc_mbedtls_psa_drbg_context_t *drbg_ctx,
                                        awrtc_mbedtls_entropy_context *entropy,
                                        const unsigned char *custom, size_t len)
{
#if defined(AWRTC_MBEDTLS_CTR_DRBG_C)
    return awrtc_mbedtls_ctr_drbg_seed(drbg_ctx, awrtc_mbedtls_entropy_func, entropy, custom, len);
#elif defined(AWRTC_MBEDTLS_HMAC_DRBG_C)
    const awrtc_mbedtls_md_info_t *md_info = awrtc_mbedtls_md_info_from_type(AWRTC_MBEDTLS_PSA_HMAC_DRBG_MD_TYPE);
    return awrtc_mbedtls_hmac_drbg_seed(drbg_ctx, md_info, awrtc_mbedtls_entropy_func, entropy, custom, len);
#endif
}

/** Reseed the PSA DRBG.
 *
 * \param drbg_ctx      The DRBG context to reseed.
 *                      It must be active.
 * \param additional    Additional data to inject.
 * \param len           The length of \p additional in bytes.
 *                      This can be 0 to simply reseed from the entropy source.
 *
 * \return              \c 0 on success.
 * \return              An Mbed TLS error code (\c AWRTC_MBEDTLS_ERR_xxx) on failure.
 */
static inline int awrtc_mbedtls_psa_drbg_reseed(awrtc_mbedtls_psa_drbg_context_t *drbg_ctx,
                                          const unsigned char *additional,
                                          size_t len)
{
#if defined(AWRTC_MBEDTLS_CTR_DRBG_C)
    return awrtc_mbedtls_ctr_drbg_reseed(drbg_ctx, additional, len);
#elif defined(AWRTC_MBEDTLS_HMAC_DRBG_C)
    return awrtc_mbedtls_hmac_drbg_reseed(drbg_ctx, additional, len);
#endif
}

/** Deplete the PSA DRBG, i.e. cause it to reseed the next time it is used.
 *
 * \note This function is not thread-safe.
 *
 * \param drbg_ctx      The DRBG context to deplete.
 *                      It must be active.
 */
static inline void awrtc_mbedtls_psa_drbg_deplete(awrtc_mbedtls_psa_drbg_context_t *drbg_ctx)
{
    drbg_ctx->reseed_counter = drbg_ctx->reseed_interval;
}

#if AWRTC_MBEDTLS_ENTROPY_TRUE_SOURCES > 0
/** Set prediction resistance in the PSA DRBG.
 *
 * \note This function is not thread-safe.
 *
 * \param drbg_ctx      The DRBG context to reconfigure.
 *                      It must be active.
 * \param enabled       \c 1 to enable, or \c 0 to disable.
 */
static inline void awrtc_mbedtls_psa_drbg_set_prediction_resistance(
    awrtc_mbedtls_psa_drbg_context_t *drbg_ctx,
    unsigned enabled)
{
#if defined(AWRTC_MBEDTLS_CTR_DRBG_C)
    awrtc_mbedtls_ctr_drbg_set_prediction_resistance(drbg_ctx, enabled);
#elif defined(AWRTC_MBEDTLS_HMAC_DRBG_C)
    awrtc_mbedtls_hmac_drbg_set_prediction_resistance(drbg_ctx, enabled);
#endif
}
#endif /* AWRTC_MBEDTLS_ENTROPY_TRUE_SOURCES > 0 */

#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

#endif /* AWRTC_PSA_CRYPTO_RANDOM_IMPL_H */
