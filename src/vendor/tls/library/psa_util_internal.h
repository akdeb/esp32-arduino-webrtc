/**
 * \file awrtc_psa_util_internal.h
 *
 * \brief Internal utility functions for use of PSA Crypto.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_MBEDTLS_PSA_UTIL_INTERNAL_H
#define AWRTC_MBEDTLS_PSA_UTIL_INTERNAL_H

/* Include the public header so that users only need one include. */
#include "../include/mbedtls/psa_util.h"

#include "../include/psa/crypto.h"

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT)

/*************************************************************************
 * FFDH
 ************************************************************************/

#define AWRTC_MBEDTLS_PSA_MAX_FFDH_PUBKEY_LENGTH \
    AWRTC_PSA_KEY_EXPORT_FFDH_PUBLIC_KEY_MAX_SIZE(AWRTC_PSA_VENDOR_FFDH_MAX_KEY_BITS)

/*************************************************************************
 * ECC
 ************************************************************************/

#define AWRTC_MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH \
    AWRTC_PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(AWRTC_PSA_VENDOR_ECC_MAX_CURVE_BITS)

#define AWRTC_MBEDTLS_PSA_MAX_EC_KEY_PAIR_LENGTH \
    AWRTC_PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(AWRTC_PSA_VENDOR_ECC_MAX_CURVE_BITS)

/*************************************************************************
 * Error translation
 ************************************************************************/

typedef struct {
    /* Error codes used by PSA crypto are in -255..-128, fitting in 16 bits. */
    int16_t awrtc_psa_status;
    /* Error codes used by Mbed TLS are in one of the ranges
     * -127..-1 (low-level) or -32767..-4096 (high-level with a low-level
     * code optionally added), fitting in 16 bits. */
    int16_t awrtc_mbedtls_error;
} awrtc_mbedtls_error_pair_t;

#if defined(AWRTC_MBEDTLS_MD_LIGHT)
extern const awrtc_mbedtls_error_pair_t awrtc_psa_to_md_errors[4];
#endif

#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
extern const awrtc_mbedtls_error_pair_t awrtc_psa_to_cipher_errors[4];
#endif

#if defined(AWRTC_MBEDTLS_LMS_C)
extern const awrtc_mbedtls_error_pair_t awrtc_psa_to_lms_errors[3];
#endif

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) || defined(AWRTC_MBEDTLS_SSL_PROTO_TLS1_3)
extern const awrtc_mbedtls_error_pair_t awrtc_psa_to_ssl_errors[7];
#endif

#if defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY) ||    \
    defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
extern const awrtc_mbedtls_error_pair_t awrtc_psa_to_pk_rsa_errors[8];
#endif

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && \
    defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
extern const awrtc_mbedtls_error_pair_t awrtc_psa_to_pk_ecdsa_errors[7];
#endif

/* Generic fallback function for error translation,
 * when the received state was not module-specific. */
int awrtc_psa_generic_status_to_mbedtls(awrtc_psa_status_t status);

/* This function iterates over provided local error translations,
 * and if no match was found - calls the fallback error translation function. */
int awrtc_psa_status_to_mbedtls(awrtc_psa_status_t status,
                          const awrtc_mbedtls_error_pair_t *local_translations,
                          size_t local_errors_num,
                          int (*fallback_f)(awrtc_psa_status_t));

/* The second out of three-stage error handling functions of the pk module,
 * acts as a fallback after RSA / ECDSA error translation, and if no match
 * is found, it itself calls awrtc_psa_generic_status_to_mbedtls. */
int awrtc_psa_pk_status_to_mbedtls(awrtc_psa_status_t status);

/* Utility macro to shorten the defines of error translator in modules. */
#define AWRTC_PSA_TO_MBEDTLS_ERR_LIST(status, error_list, fallback_f)       \
    awrtc_psa_status_to_mbedtls(status, error_list,                         \
                          sizeof(error_list)/sizeof(error_list[0]),   \
                          fallback_f)

#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT */
#endif /* AWRTC_MBEDTLS_PSA_UTIL_INTERNAL_H */
