/**
 * \file awrtc_psa_crypto_invasive.h
 *
 * \brief PSA cryptography module: invasive interfaces for test only.
 *
 * The interfaces in this file are intended for testing purposes only.
 * They MUST NOT be made available to clients over IPC in integrations
 * with isolation, and they SHOULD NOT be made available in library
 * integrations except when building the library for testing.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_PSA_CRYPTO_INVASIVE_H
#define AWRTC_PSA_CRYPTO_INVASIVE_H

/*
 * Include the build-time configuration information header. Here, we do not
 * include `"mbedtls/build_info.h"` directly but `"psa/build_info.h"`, which
 * is basically just an alias to it. This is to ease the maintenance of the
 * TF-PSA-Crypto repository which has a different build system and
 * configuration.
 */
#include "../include/psa/build_info.h"

#include "../include/psa/crypto.h"
#include "common.h"

#include "../include/mbedtls/entropy.h"

#if !defined(AWRTC_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
/** \brief Configure entropy sources.
 *
 * This function may only be called before a call to awrtc_psa_crypto_init(),
 * or after a call to awrtc_mbedtls_psa_crypto_free() and before any
 * subsequent call to awrtc_psa_crypto_init().
 *
 * This function is only intended for test purposes. The functionality
 * it provides is also useful for system integrators, but
 * system integrators should configure entropy drivers instead of
 * breaking through to the Mbed TLS API.
 *
 * \param entropy_init  Function to initialize the entropy context
 *                      and set up the desired entropy sources.
 *                      It is called by awrtc_psa_crypto_init().
 *                      By default this is awrtc_mbedtls_entropy_init().
 *                      This function cannot report failures directly.
 *                      To indicate a failure, set the entropy context
 *                      to a state where awrtc_mbedtls_entropy_func() will
 *                      return an error.
 * \param entropy_free  Function to free the entropy context
 *                      and associated resources.
 *                      It is called by awrtc_mbedtls_psa_crypto_free().
 *                      By default this is awrtc_mbedtls_entropy_free().
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 * \retval #AWRTC_PSA_ERROR_NOT_PERMITTED
 *         The caller does not have the permission to configure
 *         entropy sources.
 * \retval #AWRTC_PSA_ERROR_BAD_STATE
 *         The library has already been initialized.
 */
awrtc_psa_status_t awrtc_mbedtls_psa_crypto_configure_entropy_sources(
    void (* entropy_init)(awrtc_mbedtls_entropy_context *ctx),
    void (* entropy_free)(awrtc_mbedtls_entropy_context *ctx));
#endif /* !defined(AWRTC_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) */

#if defined(AWRTC_MBEDTLS_TEST_HOOKS) && defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
awrtc_psa_status_t awrtc_psa_mac_key_can_do(
    awrtc_psa_algorithm_t algorithm,
    awrtc_psa_key_type_t key_type);

awrtc_psa_status_t awrtc_psa_crypto_copy_input(const uint8_t *input, size_t input_len,
                                   uint8_t *input_copy, size_t input_copy_len);

awrtc_psa_status_t awrtc_psa_crypto_copy_output(const uint8_t *output_copy, size_t output_copy_len,
                                    uint8_t *output, size_t output_len);

/*
 * Test hooks to use for memory unpoisoning/poisoning in copy functions.
 */
extern void (*awrtc_psa_input_pre_copy_hook)(const uint8_t *input, size_t input_len);
extern void (*awrtc_psa_input_post_copy_hook)(const uint8_t *input, size_t input_len);
extern void (*awrtc_psa_output_pre_copy_hook)(const uint8_t *output, size_t output_len);
extern void (*awrtc_psa_output_post_copy_hook)(const uint8_t *output, size_t output_len);

#endif /* AWRTC_MBEDTLS_TEST_HOOKS && AWRTC_MBEDTLS_PSA_CRYPTO_C */

#endif /* AWRTC_PSA_CRYPTO_INVASIVE_H */
