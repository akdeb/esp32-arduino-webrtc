/**
 * \file psa/crypto_adjust_config_synonyms.h
 * \brief Adjust PSA configuration: enable quasi-synonyms
 *
 * This is an internal header. Do not include it directly.
 *
 * When two features require almost the same code, we automatically enable
 * both when either one is requested, to reduce the combinatorics of
 * possible configurations.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_PSA_CRYPTO_ADJUST_CONFIG_SYNONYMS_H
#define AWRTC_PSA_CRYPTO_ADJUST_CONFIG_SYNONYMS_H

#if !defined(AWRTC_MBEDTLS_CONFIG_FILES_READ)
#error "Do not include psa/crypto_adjust_*.h manually! This can lead to problems, " \
    "up to and including runtime errors such as buffer overflows. " \
    "If you're trying to fix a complaint from check_config.h, just remove " \
    "it from your configuration file: since Mbed TLS 3.0, it is included " \
    "automatically at the right point."
#endif /* */

/****************************************************************/
/* De facto synonyms */
/****************************************************************/

#if defined(AWRTC_PSA_WANT_ALG_ECDSA_ANY) && !defined(AWRTC_PSA_WANT_ALG_ECDSA)
#define AWRTC_PSA_WANT_ALG_ECDSA AWRTC_PSA_WANT_ALG_ECDSA_ANY
#elif !defined(AWRTC_PSA_WANT_ALG_ECDSA_ANY) && defined(AWRTC_PSA_WANT_ALG_ECDSA)
#define AWRTC_PSA_WANT_ALG_ECDSA_ANY AWRTC_PSA_WANT_ALG_ECDSA
#endif

#if defined(AWRTC_PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW) && !defined(AWRTC_PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
#define AWRTC_PSA_WANT_ALG_RSA_PKCS1V15_SIGN AWRTC_PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW
#elif !defined(AWRTC_PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW) && defined(AWRTC_PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
#define AWRTC_PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW AWRTC_PSA_WANT_ALG_RSA_PKCS1V15_SIGN
#endif

#if defined(AWRTC_PSA_WANT_ALG_RSA_PSS_ANY_SALT) && !defined(AWRTC_PSA_WANT_ALG_RSA_PSS)
#define AWRTC_PSA_WANT_ALG_RSA_PSS AWRTC_PSA_WANT_ALG_RSA_PSS_ANY_SALT
#elif !defined(AWRTC_PSA_WANT_ALG_RSA_PSS_ANY_SALT) && defined(AWRTC_PSA_WANT_ALG_RSA_PSS)
#define AWRTC_PSA_WANT_ALG_RSA_PSS_ANY_SALT AWRTC_PSA_WANT_ALG_RSA_PSS
#endif

#endif /* AWRTC_PSA_CRYPTO_ADJUST_CONFIG_SYNONYMS_H */
