/*
 *  PSA crypto random generator internal functions.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_PSA_CRYPTO_RANDOM_H
#define AWRTC_PSA_CRYPTO_RANDOM_H

#include "common.h"

#if !defined(AWRTC_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

#include "../include/psa/crypto.h"
#include "psa_crypto_random_impl.h"

/** Initialize the PSA random generator.
 *
 * \param[out] rng      The random generator context to initialize.
 */
void awrtc_psa_random_internal_init(awrtc_mbedtls_psa_random_context_t *rng);

/** Deinitialize the PSA random generator.
 *
 * \param[in,out] rng   The random generator context to deinitialize.
 */
void awrtc_psa_random_internal_free(awrtc_mbedtls_psa_random_context_t *rng);

/** Seed the PSA random generator.
 *
 * \note This function is not thread-safe.
 *
 * \param[in,out] rng   The random generator context to seed.
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 * \retval #AWRTC_PSA_ERROR_INSUFFICIENT_ENTROPY
 *         The entropy source failed.
 */
awrtc_psa_status_t awrtc_psa_random_internal_seed(awrtc_mbedtls_psa_random_context_t *rng);

/**
 * \brief Generate random bytes. Like awrtc_psa_generate_random(), but for use
 *        inside the library.
 *
 * This function is thread-safe.
 *
 * \warning This function **can** fail! Callers MUST check the return status
 *          and MUST NOT use the content of the output buffer if the return
 *          status is not #AWRTC_PSA_SUCCESS.
 *
 * \param[in,out] rng       The random generator context to seed.
 * \param[out] output       Output buffer for the generated data.
 * \param output_size       Number of bytes to generate and output.
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 * \retval #AWRTC_PSA_ERROR_INSUFFICIENT_ENTROPY
 *         The random generator needed to reseed, and the entropy
 *         source failed.
 * \retval #AWRTC_PSA_ERROR_HARDWARE_FAILURE
 *         A hardware accelerator failed.
 */
awrtc_psa_status_t awrtc_psa_random_internal_generate(
    awrtc_mbedtls_psa_random_context_t *rng,
    uint8_t *output, size_t output_size);

#endif /* !defined(AWRTC_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) */

#endif /* AWRTC_PSA_CRYPTO_RANDOM_H */
