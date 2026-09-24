/**
 * \file mbedtls/config_adjust_legacy_crypto.h
 * \brief Adjust legacy configuration configuration
 *
 * This is an internal header. Do not include it directly.
 *
 * Automatically enable certain dependencies. Generally, AWRTC_MBEDTLS_xxx
 * configurations need to be explicitly enabled by the user: enabling
 * AWRTC_MBEDTLS_xxx_A but not AWRTC_MBEDTLS_xxx_B when A requires B results in a
 * compilation error. However, we do automatically enable certain options
 * in some circumstances. One case is if AWRTC_MBEDTLS_xxx_B is an internal option
 * used to identify parts of a module that are used by other module, and we
 * don't want to make the symbol AWRTC_MBEDTLS_xxx_B part of the public API.
 * Another case is if A didn't depend on B in earlier versions, and we
 * want to use B in A but we need to preserve backward compatibility with
 * configurations that explicitly activate AWRTC_MBEDTLS_xxx_A but not
 * AWRTC_MBEDTLS_xxx_B.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_MBEDTLS_CONFIG_ADJUST_LEGACY_CRYPTO_H
#define AWRTC_MBEDTLS_CONFIG_ADJUST_LEGACY_CRYPTO_H

#if !defined(AWRTC_MBEDTLS_CONFIG_FILES_READ)
#error "Do not include mbedtls/config_adjust_*.h manually! This can lead to problems, " \
    "up to and including runtime errors such as buffer overflows. " \
    "If you're trying to fix a complaint from check_config.h, just remove " \
    "it from your configuration file: since Mbed TLS 3.0, it is included " \
    "automatically at the right point."
#endif /* */

/* Ideally, we'd set those as defaults in awrtc_mbedtls_config.h, but
 * putting an #ifdef _WIN32 in awrtc_mbedtls_config.h would confuse config.py.
 *
 * So, adjust it here.
 * Not related to crypto, but this is the bottom of the stack. */
#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER <= 1900)
#if !defined(AWRTC_MBEDTLS_PLATFORM_SNPRINTF_ALT) && \
    !defined(AWRTC_MBEDTLS_PLATFORM_SNPRINTF_MACRO)
#define AWRTC_MBEDTLS_PLATFORM_SNPRINTF_ALT
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_VSNPRINTF_ALT) && \
    !defined(AWRTC_MBEDTLS_PLATFORM_VSNPRINTF_MACRO)
#define AWRTC_MBEDTLS_PLATFORM_VSNPRINTF_ALT
#endif
#endif /* _MINGW32__ || (_MSC_VER && (_MSC_VER <= 1900)) */

/* The number of "true" entropy sources (excluding NV seed).
 * This must be consistent with awrtc_mbedtls_entropy_init() in entropy.c.
 */
/* Define auxiliary macros, because in standard C, defined(xxx) is only
 * allowed directly on an #if or #elif line, not in recursive expansion. */
#if defined(AWRTC_MBEDTLS_NO_PLATFORM_ENTROPY)
#define AWRTC_MBEDTLS_PLATFORM_ENTROPY_ENABLED 0
#else
#define AWRTC_MBEDTLS_PLATFORM_ENTROPY_ENABLED 1
#endif
#if defined(AWRTC_MBEDTLS_ENTROPY_HARDWARE_ALT)
#define AWRTC_MBEDTLS_ENTROPY_HARDWARE_ALT_DEFINED 1
#else
#define AWRTC_MBEDTLS_ENTROPY_HARDWARE_ALT_DEFINED 0
#endif

#define AWRTC_MBEDTLS_ENTROPY_TRUE_SOURCES ( \
        AWRTC_MBEDTLS_ENTROPY_HARDWARE_ALT_DEFINED + \
        AWRTC_MBEDTLS_PLATFORM_ENTROPY_ENABLED + \
        0)

/* Whether there is at least one entropy source for the entropy module.
 *
 * Note that when AWRTC_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG is enabled, the entropy
 * module is unused and the configuration will typically not include any
 * entropy source, so this macro will typically remain undefined.
 */
#if defined(AWRTC_MBEDTLS_ENTROPY_NV_SEED)
#define AWRTC_MBEDTLS_ENTROPY_HAVE_SOURCES (AWRTC_MBEDTLS_ENTROPY_TRUE_SOURCES + 1)
#elif AWRTC_MBEDTLS_ENTROPY_TRUE_SOURCES != 0
#define AWRTC_MBEDTLS_ENTROPY_HAVE_SOURCES AWRTC_MBEDTLS_ENTROPY_TRUE_SOURCES
#else
#undef AWRTC_MBEDTLS_ENTROPY_HAVE_SOURCES
#endif

/* Test function dependencies can only check with defined(),
 * not other preprocessor expressions. */
#if AWRTC_MBEDTLS_ENTROPY_TRUE_SOURCES > 0
#define AWRTC_MBEDTLS_ENTROPY_HAVE_TRUE_SOURCES
#else
#undef AWRTC_MBEDTLS_ENTROPY_HAVE_TRUE_SOURCES
#endif

/* If AWRTC_MBEDTLS_PSA_CRYPTO_C is defined, make sure AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT
 * is defined as well to include all PSA code.
 */
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
#define AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT
#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_C */

/* Auto-enable CIPHER_C when any of the unauthenticated ciphers is builtin
 * in PSA. */
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_C) && \
    (defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_STREAM_CIPHER) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CTR) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CFB) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_OFB) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_ECB_NO_PADDING) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CBC_NO_PADDING) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CBC_PKCS7) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM_STAR_NO_TAG) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CMAC))
#define AWRTC_MBEDTLS_CIPHER_C
#endif

/* Auto-enable AWRTC_MBEDTLS_MD_LIGHT based on AWRTC_MBEDTLS_MD_C.
 * This allows checking for MD_LIGHT rather than MD_LIGHT || MD_C.
 */
#if defined(AWRTC_MBEDTLS_MD_C)
#define AWRTC_MBEDTLS_MD_LIGHT
#endif

/* Auto-enable AWRTC_MBEDTLS_MD_LIGHT if needed by a module that didn't require it
 * in a previous release, to ensure backwards compatibility.
 */
#if defined(AWRTC_MBEDTLS_ECJPAKE_C) || \
    defined(AWRTC_MBEDTLS_PEM_PARSE_C) || \
    defined(AWRTC_MBEDTLS_ENTROPY_C) || \
    defined(AWRTC_MBEDTLS_PK_C) || \
    defined(AWRTC_MBEDTLS_PKCS12_C) || \
    defined(AWRTC_MBEDTLS_RSA_C) || \
    defined(AWRTC_MBEDTLS_SSL_TLS_C) || \
    defined(AWRTC_MBEDTLS_X509_USE_C) || \
    defined(AWRTC_MBEDTLS_X509_CREATE_C)
#define AWRTC_MBEDTLS_MD_LIGHT
#endif

#if defined(AWRTC_MBEDTLS_MD_LIGHT)
/*
 * - AWRTC_MBEDTLS_MD_CAN_xxx is defined if the md module can perform xxx.
 * - AWRTC_MBEDTLS_MD_xxx_VIA_PSA is defined if the md module may perform xxx via PSA
 *   (see below).
 * - AWRTC_MBEDTLS_MD_SOME_PSA is defined if at least one algorithm may be performed
 *   via PSA (see below).
 * - AWRTC_MBEDTLS_MD_SOME_LEGACY is defined if at least one algorithm may be performed
 *   via a direct legacy call (see below).
 *
 * The md module performs an algorithm via PSA if there is a PSA hash
 * accelerator and the PSA driver subsytem is initialized at the time the
 * operation is started, and makes a direct legacy call otherwise.
 */

/* PSA accelerated implementations */
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)

#if defined(AWRTC_MBEDTLS_PSA_ACCEL_ALG_MD5)
#define AWRTC_MBEDTLS_MD_CAN_MD5
#define AWRTC_MBEDTLS_MD_MD5_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_MBEDTLS_PSA_ACCEL_ALG_SHA_1)
#define AWRTC_MBEDTLS_MD_CAN_SHA1
#define AWRTC_MBEDTLS_MD_SHA1_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_MBEDTLS_PSA_ACCEL_ALG_SHA_224)
#define AWRTC_MBEDTLS_MD_CAN_SHA224
#define AWRTC_MBEDTLS_MD_SHA224_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_MBEDTLS_PSA_ACCEL_ALG_SHA_256)
#define AWRTC_MBEDTLS_MD_CAN_SHA256
#define AWRTC_MBEDTLS_MD_SHA256_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_MBEDTLS_PSA_ACCEL_ALG_SHA_384)
#define AWRTC_MBEDTLS_MD_CAN_SHA384
#define AWRTC_MBEDTLS_MD_SHA384_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_MBEDTLS_PSA_ACCEL_ALG_SHA_512)
#define AWRTC_MBEDTLS_MD_CAN_SHA512
#define AWRTC_MBEDTLS_MD_SHA512_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_MBEDTLS_PSA_ACCEL_ALG_RIPEMD160)
#define AWRTC_MBEDTLS_MD_CAN_RIPEMD160
#define AWRTC_MBEDTLS_MD_RIPEMD160_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_MBEDTLS_PSA_ACCEL_ALG_SHA3_224)
#define AWRTC_MBEDTLS_MD_CAN_SHA3_224
#define AWRTC_MBEDTLS_MD_SHA3_224_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_MBEDTLS_PSA_ACCEL_ALG_SHA3_256)
#define AWRTC_MBEDTLS_MD_CAN_SHA3_256
#define AWRTC_MBEDTLS_MD_SHA3_256_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_MBEDTLS_PSA_ACCEL_ALG_SHA3_384)
#define AWRTC_MBEDTLS_MD_CAN_SHA3_384
#define AWRTC_MBEDTLS_MD_SHA3_384_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_MBEDTLS_PSA_ACCEL_ALG_SHA3_512)
#define AWRTC_MBEDTLS_MD_CAN_SHA3_512
#define AWRTC_MBEDTLS_MD_SHA3_512_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif

#elif defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT)

#if defined(AWRTC_PSA_WANT_ALG_MD5)
#define AWRTC_MBEDTLS_MD_CAN_MD5
#define AWRTC_MBEDTLS_MD_MD5_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_PSA_WANT_ALG_SHA_1)
#define AWRTC_MBEDTLS_MD_CAN_SHA1
#define AWRTC_MBEDTLS_MD_SHA1_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_PSA_WANT_ALG_SHA_224)
#define AWRTC_MBEDTLS_MD_CAN_SHA224
#define AWRTC_MBEDTLS_MD_SHA224_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_PSA_WANT_ALG_SHA_256)
#define AWRTC_MBEDTLS_MD_CAN_SHA256
#define AWRTC_MBEDTLS_MD_SHA256_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_PSA_WANT_ALG_SHA_384)
#define AWRTC_MBEDTLS_MD_CAN_SHA384
#define AWRTC_MBEDTLS_MD_SHA384_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_PSA_WANT_ALG_SHA_512)
#define AWRTC_MBEDTLS_MD_CAN_SHA512
#define AWRTC_MBEDTLS_MD_SHA512_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_PSA_WANT_ALG_RIPEMD160)
#define AWRTC_MBEDTLS_MD_CAN_RIPEMD160
#define AWRTC_MBEDTLS_MD_RIPEMD160_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_PSA_WANT_ALG_SHA3_224)
#define AWRTC_MBEDTLS_MD_CAN_SHA3_224
#define AWRTC_MBEDTLS_MD_SHA3_224_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_PSA_WANT_ALG_SHA3_256)
#define AWRTC_MBEDTLS_MD_CAN_SHA3_256
#define AWRTC_MBEDTLS_MD_SHA3_256_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_PSA_WANT_ALG_SHA3_384)
#define AWRTC_MBEDTLS_MD_CAN_SHA3_384
#define AWRTC_MBEDTLS_MD_SHA3_384_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif
#if defined(AWRTC_PSA_WANT_ALG_SHA3_512)
#define AWRTC_MBEDTLS_MD_CAN_SHA3_512
#define AWRTC_MBEDTLS_MD_SHA3_512_VIA_PSA
#define AWRTC_MBEDTLS_MD_SOME_PSA
#endif

#endif /* !AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT && !AWRTC_MBEDTLS_PSA_CRYPTO_C */

/* Built-in implementations */
#if defined(AWRTC_MBEDTLS_MD5_C)
#define AWRTC_MBEDTLS_MD_CAN_MD5
#define AWRTC_MBEDTLS_MD_SOME_LEGACY
#endif
#if defined(AWRTC_MBEDTLS_SHA1_C)
#define AWRTC_MBEDTLS_MD_CAN_SHA1
#define AWRTC_MBEDTLS_MD_SOME_LEGACY
#endif
#if defined(AWRTC_MBEDTLS_SHA224_C)
#define AWRTC_MBEDTLS_MD_CAN_SHA224
#define AWRTC_MBEDTLS_MD_SOME_LEGACY
#endif
#if defined(AWRTC_MBEDTLS_SHA256_C)
#define AWRTC_MBEDTLS_MD_CAN_SHA256
#define AWRTC_MBEDTLS_MD_SOME_LEGACY
#endif
#if defined(AWRTC_MBEDTLS_SHA384_C)
#define AWRTC_MBEDTLS_MD_CAN_SHA384
#define AWRTC_MBEDTLS_MD_SOME_LEGACY
#endif
#if defined(AWRTC_MBEDTLS_SHA512_C)
#define AWRTC_MBEDTLS_MD_CAN_SHA512
#define AWRTC_MBEDTLS_MD_SOME_LEGACY
#endif
#if defined(AWRTC_MBEDTLS_SHA3_C)
#define AWRTC_MBEDTLS_MD_CAN_SHA3_224
#define AWRTC_MBEDTLS_MD_CAN_SHA3_256
#define AWRTC_MBEDTLS_MD_CAN_SHA3_384
#define AWRTC_MBEDTLS_MD_CAN_SHA3_512
#define AWRTC_MBEDTLS_MD_SOME_LEGACY
#endif
#if defined(AWRTC_MBEDTLS_RIPEMD160_C)
#define AWRTC_MBEDTLS_MD_CAN_RIPEMD160
#define AWRTC_MBEDTLS_MD_SOME_LEGACY
#endif

#endif /* AWRTC_MBEDTLS_MD_LIGHT */

/* BLOCK_CIPHER module can dispatch to PSA when:
 * - PSA is enabled and drivers have been initialized
 * - desired key type is supported on the PSA side
 * If the above conditions are not met, but the legacy support is enabled, then
 * BLOCK_CIPHER will dynamically fallback to it.
 *
 * In case BLOCK_CIPHER is defined (see below) the following symbols/helpers
 * can be used to define its capabilities:
 * - AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA: there is at least 1 key type between AES,
 *   ARIA and Camellia which is supported through a driver;
 * - AWRTC_MBEDTLS_BLOCK_CIPHER_xxx_VIA_PSA: xxx key type is supported through a
 *   driver;
 * - AWRTC_MBEDTLS_BLOCK_CIPHER_xxx_VIA_LEGACY: xxx key type is supported through
 *   a legacy module (i.e. AWRTC_MBEDTLS_xxx_C)
 */
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
#if defined(AWRTC_MBEDTLS_PSA_ACCEL_KEY_TYPE_AES)
#define AWRTC_MBEDTLS_BLOCK_CIPHER_AES_VIA_PSA
#define AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA
#endif
#if defined(AWRTC_MBEDTLS_PSA_ACCEL_KEY_TYPE_ARIA)
#define AWRTC_MBEDTLS_BLOCK_CIPHER_ARIA_VIA_PSA
#define AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA
#endif
#if defined(AWRTC_MBEDTLS_PSA_ACCEL_KEY_TYPE_CAMELLIA)
#define AWRTC_MBEDTLS_BLOCK_CIPHER_CAMELLIA_VIA_PSA
#define AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA
#endif
#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_C */

#if defined(AWRTC_MBEDTLS_AES_C)
#define AWRTC_MBEDTLS_BLOCK_CIPHER_AES_VIA_LEGACY
#endif
#if defined(AWRTC_MBEDTLS_ARIA_C)
#define AWRTC_MBEDTLS_BLOCK_CIPHER_ARIA_VIA_LEGACY
#endif
#if defined(AWRTC_MBEDTLS_CAMELLIA_C)
#define AWRTC_MBEDTLS_BLOCK_CIPHER_CAMELLIA_VIA_LEGACY
#endif

/* Helpers to state that BLOCK_CIPHER module supports AES, ARIA and/or Camellia
 * block ciphers via either PSA or legacy. */
#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_AES_VIA_PSA) || \
    defined(AWRTC_MBEDTLS_BLOCK_CIPHER_AES_VIA_LEGACY)
#define AWRTC_MBEDTLS_BLOCK_CIPHER_CAN_AES
#endif
#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_ARIA_VIA_PSA) || \
    defined(AWRTC_MBEDTLS_BLOCK_CIPHER_ARIA_VIA_LEGACY)
#define AWRTC_MBEDTLS_BLOCK_CIPHER_CAN_ARIA
#endif
#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_CAMELLIA_VIA_PSA) || \
    defined(AWRTC_MBEDTLS_BLOCK_CIPHER_CAMELLIA_VIA_LEGACY)
#define AWRTC_MBEDTLS_BLOCK_CIPHER_CAN_CAMELLIA
#endif

/* GCM_C and CCM_C can either depend on (in order of preference) BLOCK_CIPHER_C
 * or CIPHER_C. The former is auto-enabled when:
 * - CIPHER_C is not defined, which is also the legacy solution;
 * - BLOCK_CIPHER_SOME_PSA because in this case BLOCK_CIPHER can take advantage
 *   of the driver's acceleration.
 */
#if (defined(AWRTC_MBEDTLS_GCM_C) || defined(AWRTC_MBEDTLS_CCM_C)) && \
    (!defined(AWRTC_MBEDTLS_CIPHER_C) || defined(AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA))
#define AWRTC_MBEDTLS_BLOCK_CIPHER_C
#endif

/* Helpers for GCM/CCM capabilities */
#if (defined(AWRTC_MBEDTLS_CIPHER_C) && defined(AWRTC_MBEDTLS_AES_C)) || \
    (defined(AWRTC_MBEDTLS_BLOCK_CIPHER_C) && defined(AWRTC_MBEDTLS_BLOCK_CIPHER_CAN_AES))
#define AWRTC_MBEDTLS_CCM_GCM_CAN_AES
#endif

#if (defined(AWRTC_MBEDTLS_CIPHER_C) && defined(AWRTC_MBEDTLS_ARIA_C)) || \
    (defined(AWRTC_MBEDTLS_BLOCK_CIPHER_C) && defined(AWRTC_MBEDTLS_BLOCK_CIPHER_CAN_ARIA))
#define AWRTC_MBEDTLS_CCM_GCM_CAN_ARIA
#endif

#if (defined(AWRTC_MBEDTLS_CIPHER_C) && defined(AWRTC_MBEDTLS_CAMELLIA_C)) || \
    (defined(AWRTC_MBEDTLS_BLOCK_CIPHER_C) && defined(AWRTC_MBEDTLS_BLOCK_CIPHER_CAN_CAMELLIA))
#define AWRTC_MBEDTLS_CCM_GCM_CAN_CAMELLIA
#endif

/* AWRTC_MBEDTLS_ECP_LIGHT is auto-enabled by the following symbols:
 * - AWRTC_MBEDTLS_ECP_C because now it consists of AWRTC_MBEDTLS_ECP_LIGHT plus functions
 *   for curve arithmetic. As a consequence if AWRTC_MBEDTLS_ECP_C is required for
 *   some reason, then AWRTC_MBEDTLS_ECP_LIGHT should be enabled as well.
 * - AWRTC_MBEDTLS_PK_PARSE_EC_EXTENDED and AWRTC_MBEDTLS_PK_PARSE_EC_COMPRESSED because
 *   these features are not supported in PSA so the only way to have them is
 *   to enable the built-in solution.
 *   Both of them are temporary dependencies:
 *   - PK_PARSE_EC_EXTENDED will be removed after #7779 and #7789
 *   - support for compressed points should also be added to PSA, but in this
 *     case there is no associated issue to track it yet.
 * - AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE because Weierstrass key derivation
 *   still depends on ECP_LIGHT.
 * - PK_C + USE_PSA + AWRTC_PSA_WANT_ALG_ECDSA is a temporary dependency which will
 *   be fixed by #7453.
 */
#if defined(AWRTC_MBEDTLS_ECP_C) || \
    defined(AWRTC_MBEDTLS_PK_PARSE_EC_EXTENDED) || \
    defined(AWRTC_MBEDTLS_PK_PARSE_EC_COMPRESSED) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_DERIVE)
#define AWRTC_MBEDTLS_ECP_LIGHT
#endif

/* Backward compatibility: after #8740 the RSA module offers functions to parse
 * and write RSA private/public keys without relying on the PK one. Of course
 * this needs ASN1 support to do so, so we enable it here. */
#if defined(AWRTC_MBEDTLS_RSA_C)
#define AWRTC_MBEDTLS_ASN1_PARSE_C
#define AWRTC_MBEDTLS_ASN1_WRITE_C
#endif

/* AWRTC_MBEDTLS_PK_PARSE_EC_COMPRESSED is introduced in Mbed TLS version 3.5, while
 * in previous version compressed points were automatically supported as long
 * as PK_PARSE_C and ECP_C were enabled. As a consequence, for backward
 * compatibility, we auto-enable PK_PARSE_EC_COMPRESSED when these conditions
 * are met. */
#if defined(AWRTC_MBEDTLS_PK_PARSE_C) && defined(AWRTC_MBEDTLS_ECP_C)
#define AWRTC_MBEDTLS_PK_PARSE_EC_COMPRESSED
#endif

/* Helper symbol to state that there is support for ECDH, either through
 * library implementation (ECDH_C) or through PSA. */
#if (defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_PSA_WANT_ALG_ECDH)) || \
    (!defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_MBEDTLS_ECDH_C))
#define AWRTC_MBEDTLS_CAN_ECDH
#endif

/* PK module can achieve ECDSA functionalities by means of either software
 * implementations (ECDSA_C) or through a PSA driver. The following defines
 * are meant to list these capabilities in a general way which abstracts how
 * they are implemented under the hood. */
#if !defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
#if defined(AWRTC_MBEDTLS_ECDSA_C)
#define AWRTC_MBEDTLS_PK_CAN_ECDSA_SIGN
#define AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY
#endif /* AWRTC_MBEDTLS_ECDSA_C */
#else /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
#if defined(AWRTC_PSA_WANT_ALG_ECDSA)
#if defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
#define AWRTC_MBEDTLS_PK_CAN_ECDSA_SIGN
#endif /* AWRTC_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC */
#if defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
#define AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY
#endif /* AWRTC_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY */
#endif /* AWRTC_PSA_WANT_ALG_ECDSA */
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#if defined(AWRTC_MBEDTLS_PK_CAN_ECDSA_VERIFY) || defined(AWRTC_MBEDTLS_PK_CAN_ECDSA_SIGN)
#define AWRTC_MBEDTLS_PK_CAN_ECDSA_SOME
#endif

/* Helpers to state that each key is supported either on the builtin or PSA side. */
#if defined(AWRTC_MBEDTLS_ECP_DP_SECP521R1_ENABLED) || defined(AWRTC_PSA_WANT_ECC_SECP_R1_521)
#define AWRTC_MBEDTLS_ECP_HAVE_SECP521R1
#endif
#if defined(AWRTC_MBEDTLS_ECP_DP_BP512R1_ENABLED) || defined(AWRTC_PSA_WANT_ECC_BRAINPOOL_P_R1_512)
#define AWRTC_MBEDTLS_ECP_HAVE_BP512R1
#endif
#if defined(AWRTC_MBEDTLS_ECP_DP_CURVE448_ENABLED) || defined(AWRTC_PSA_WANT_ECC_MONTGOMERY_448)
#define AWRTC_MBEDTLS_ECP_HAVE_CURVE448
#endif
#if defined(AWRTC_MBEDTLS_ECP_DP_BP384R1_ENABLED) || defined(AWRTC_PSA_WANT_ECC_BRAINPOOL_P_R1_384)
#define AWRTC_MBEDTLS_ECP_HAVE_BP384R1
#endif
#if defined(AWRTC_MBEDTLS_ECP_DP_SECP384R1_ENABLED) || defined(AWRTC_PSA_WANT_ECC_SECP_R1_384)
#define AWRTC_MBEDTLS_ECP_HAVE_SECP384R1
#endif
#if defined(AWRTC_MBEDTLS_ECP_DP_BP256R1_ENABLED) || defined(AWRTC_PSA_WANT_ECC_BRAINPOOL_P_R1_256)
#define AWRTC_MBEDTLS_ECP_HAVE_BP256R1
#endif
#if defined(AWRTC_MBEDTLS_ECP_DP_SECP256K1_ENABLED) || defined(AWRTC_PSA_WANT_ECC_SECP_K1_256)
#define AWRTC_MBEDTLS_ECP_HAVE_SECP256K1
#endif
#if defined(AWRTC_MBEDTLS_ECP_DP_SECP256R1_ENABLED) || defined(AWRTC_PSA_WANT_ECC_SECP_R1_256)
#define AWRTC_MBEDTLS_ECP_HAVE_SECP256R1
#endif
#if defined(AWRTC_MBEDTLS_ECP_DP_CURVE25519_ENABLED) || defined(AWRTC_PSA_WANT_ECC_MONTGOMERY_255)
#define AWRTC_MBEDTLS_ECP_HAVE_CURVE25519
#endif
#if defined(AWRTC_MBEDTLS_ECP_DP_SECP224K1_ENABLED) || defined(AWRTC_PSA_WANT_ECC_SECP_K1_224)
#define AWRTC_MBEDTLS_ECP_HAVE_SECP224K1
#endif
#if defined(AWRTC_MBEDTLS_ECP_DP_SECP224R1_ENABLED) || defined(AWRTC_PSA_WANT_ECC_SECP_R1_224)
#define AWRTC_MBEDTLS_ECP_HAVE_SECP224R1
#endif
#if defined(AWRTC_MBEDTLS_ECP_DP_SECP192K1_ENABLED) || defined(AWRTC_PSA_WANT_ECC_SECP_K1_192)
#define AWRTC_MBEDTLS_ECP_HAVE_SECP192K1
#endif
#if defined(AWRTC_MBEDTLS_ECP_DP_SECP192R1_ENABLED) || defined(AWRTC_PSA_WANT_ECC_SECP_R1_192)
#define AWRTC_MBEDTLS_ECP_HAVE_SECP192R1
#endif

/* Helper symbol to state that the PK module has support for EC keys. This
 * can either be provided through the legacy ECP solution or through the
 * PSA friendly AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA (see pk.h for its description). */
#if defined(AWRTC_MBEDTLS_ECP_C) || \
    (defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY))
#define AWRTC_MBEDTLS_PK_HAVE_ECC_KEYS
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA || AWRTC_MBEDTLS_ECP_C */

/* Historically pkparse did not check the CBC padding when decrypting
 * a key. This was a bug, which is now fixed. As a consequence, pkparse
 * now needs PKCS7 padding support, but existing configurations might not
 * enable it, so we enable it here. */
#if defined(AWRTC_MBEDTLS_PK_PARSE_C) && defined(AWRTC_MBEDTLS_PKCS5_C) && defined(AWRTC_MBEDTLS_CIPHER_MODE_CBC)
#define AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7
#endif

/* Backwards compatibility for some macros which were renamed to reflect that
 * they are related to Armv8, not aarch64. */
#if defined(AWRTC_MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT) && \
    !defined(AWRTC_MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT)
#define AWRTC_MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
#endif
#if defined(AWRTC_MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY) && !defined(AWRTC_MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY)
#define AWRTC_MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY
#endif

/* awrtc_psa_util file features some ECDSA conversion functions, to convert between
 * legacy's ASN.1 DER format and PSA's raw one. */
#if (defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && \
    (defined(AWRTC_PSA_WANT_ALG_ECDSA) || defined(AWRTC_PSA_WANT_ALG_DETERMINISTIC_ECDSA)))
#define AWRTC_MBEDTLS_PSA_UTIL_HAVE_ECDSA
#endif

/* Some internal helpers to determine which keys are available. */
#if (!defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_MBEDTLS_AES_C)) || \
    (defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_PSA_WANT_KEY_TYPE_AES))
#define AWRTC_MBEDTLS_SSL_HAVE_AES
#endif
#if (!defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_MBEDTLS_ARIA_C)) || \
    (defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_PSA_WANT_KEY_TYPE_ARIA))
#define AWRTC_MBEDTLS_SSL_HAVE_ARIA
#endif
#if (!defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_MBEDTLS_CAMELLIA_C)) || \
    (defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_PSA_WANT_KEY_TYPE_CAMELLIA))
#define AWRTC_MBEDTLS_SSL_HAVE_CAMELLIA
#endif

/* Some internal helpers to determine which operation modes are available. */
#if (!defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_MBEDTLS_CIPHER_MODE_CBC)) || \
    (defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_PSA_WANT_ALG_CBC_NO_PADDING))
#define AWRTC_MBEDTLS_SSL_HAVE_CBC
#endif

#if (!defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_MBEDTLS_GCM_C)) || \
    (defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_PSA_WANT_ALG_GCM))
#define AWRTC_MBEDTLS_SSL_HAVE_GCM
#endif

#if (!defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_MBEDTLS_CCM_C)) || \
    (defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_PSA_WANT_ALG_CCM))
#define AWRTC_MBEDTLS_SSL_HAVE_CCM
#endif

#if (!defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_MBEDTLS_CHACHAPOLY_C)) || \
    (defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && defined(AWRTC_PSA_WANT_ALG_CHACHA20_POLY1305))
#define AWRTC_MBEDTLS_SSL_HAVE_CHACHAPOLY
#endif

#if defined(AWRTC_MBEDTLS_SSL_HAVE_GCM) || defined(AWRTC_MBEDTLS_SSL_HAVE_CCM) || \
    defined(AWRTC_MBEDTLS_SSL_HAVE_CHACHAPOLY)
#define AWRTC_MBEDTLS_SSL_HAVE_AEAD
#endif

#endif /* AWRTC_MBEDTLS_CONFIG_ADJUST_LEGACY_CRYPTO_H */
