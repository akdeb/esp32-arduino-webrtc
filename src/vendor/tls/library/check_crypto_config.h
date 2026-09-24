/**
 * \file check_crypto_config.h
 *
 * \brief Consistency checks for PSA configuration options
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * It is recommended to include this file from your crypto_config.h
 * in order to catch dependency issues early.
 */

#ifndef AWRTC_MBEDTLS_CHECK_CRYPTO_CONFIG_H
#define AWRTC_MBEDTLS_CHECK_CRYPTO_CONFIG_H

#if defined(AWRTC_PSA_WANT_ALG_CCM) && \
    !(defined(AWRTC_PSA_WANT_KEY_TYPE_AES) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_CAMELLIA))
#error "AWRTC_PSA_WANT_ALG_CCM defined, but not all prerequisites"
#endif

#if defined(AWRTC_PSA_WANT_ALG_CMAC) && \
    !(defined(AWRTC_PSA_WANT_KEY_TYPE_AES) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_CAMELLIA) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_DES))
#error "AWRTC_PSA_WANT_ALG_CMAC defined, but not all prerequisites"
#endif

#if defined(AWRTC_PSA_WANT_ALG_DETERMINISTIC_ECDSA) && \
    !(defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY))
#error "AWRTC_PSA_WANT_ALG_DETERMINISTIC_ECDSA defined, but not all prerequisites"
#endif

#if defined(AWRTC_PSA_WANT_ALG_ECDSA) && \
    !(defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY))
#error "AWRTC_PSA_WANT_ALG_ECDSA defined, but not all prerequisites"
#endif

#if defined(AWRTC_PSA_WANT_ALG_GCM) && \
    !(defined(AWRTC_PSA_WANT_KEY_TYPE_AES) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_CAMELLIA))
#error "AWRTC_PSA_WANT_ALG_GCM defined, but not all prerequisites"
#endif

#if defined(AWRTC_PSA_WANT_ALG_RSA_PKCS1V15_CRYPT) && \
    !(defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY))
#error "AWRTC_PSA_WANT_ALG_RSA_PKCS1V15_CRYPT defined, but not all prerequisites"
#endif

#if defined(AWRTC_PSA_WANT_ALG_RSA_PKCS1V15_SIGN) && \
    !(defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY))
#error "AWRTC_PSA_WANT_ALG_RSA_PKCS1V15_SIGN defined, but not all prerequisites"
#endif

#if defined(AWRTC_PSA_WANT_ALG_RSA_OAEP) && \
    !(defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY))
#error "AWRTC_PSA_WANT_ALG_RSA_OAEP defined, but not all prerequisites"
#endif

#if defined(AWRTC_PSA_WANT_ALG_RSA_PSS) && \
    !(defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY))
#error "AWRTC_PSA_WANT_ALG_RSA_PSS defined, but not all prerequisites"
#endif

#if (defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE)) && \
    !defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
#error "AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_xxx defined, but not all prerequisites"
#endif

#if (defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE)) && \
    !defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY)
#error "AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_xxx defined, but not all prerequisites"
#endif

#if (defined(AWRTC_PSA_WANT_KEY_TYPE_DH_KEY_PAIR_BASIC) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_DH_KEY_PAIR_IMPORT) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_DH_KEY_PAIR_EXPORT) || \
    defined(AWRTC_PSA_WANT_KEY_TYPE_DH_KEY_PAIR_GENERATE)) && \
    !defined(AWRTC_PSA_WANT_KEY_TYPE_DH_PUBLIC_KEY)
#error "AWRTC_PSA_WANT_KEY_TYPE_DH_KEY_PAIR_xxx defined, but not all prerequisites"
#endif

#if defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR)
#if defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
#error "AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR is deprecated and will be removed in a \
    future version of Mbed TLS. Please switch to new AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_xxx \
    symbols, where xxx can be: USE, IMPORT, EXPORT, GENERATE, DERIVE"
#elif defined(AWRTC_MBEDTLS_DEPRECATED_WARNING)
#warning "AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR is deprecated and will be removed in a \
    future version of Mbed TLS. Please switch to new AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_xxx \
    symbols, where xxx can be: USE, IMPORT, EXPORT, GENERATE, DERIVE"
#endif /* AWRTC_MBEDTLS_DEPRECATED_WARNING */
#endif /* AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR */

#if defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR)
#if defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
#error "AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR is deprecated and will be removed in a \
    future version of Mbed TLS. Please switch to new AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_xxx \
    symbols, where xxx can be: USE, IMPORT, EXPORT, GENERATE, DERIVE"
#elif defined(AWRTC_MBEDTLS_DEPRECATED_WARNING)
#warning "AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR is deprecated and will be removed in a \
    future version of Mbed TLS. Please switch to new AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_xxx \
    symbols, where xxx can be: USE, IMPORT, EXPORT, GENERATE, DERIVE"
#endif /* AWRTC_MBEDTLS_DEPRECATED_WARNING */
#endif /* AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR */

#if defined(AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_DERIVE)
#error "AWRTC_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_DERIVE defined, but feature is not supported"
#endif

#if defined(AWRTC_PSA_WANT_KEY_TYPE_DH_KEY_PAIR_DERIVE)
#error "AWRTC_PSA_WANT_KEY_TYPE_DH_KEY_PAIR_DERIVE defined, but feature is not supported"
#endif

#if defined(AWRTC_PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS) && \
    !defined(AWRTC_PSA_WANT_ALG_SHA_256)
#error "AWRTC_PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS defined, but not all prerequisites"
#endif

#endif /* AWRTC_MBEDTLS_CHECK_CRYPTO_CONFIG_H */
