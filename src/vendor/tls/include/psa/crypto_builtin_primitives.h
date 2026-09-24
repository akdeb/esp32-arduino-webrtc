/*
 *  Context structure declaration of the Mbed TLS software-based PSA drivers
 *  called through the PSA Crypto driver dispatch layer.
 *  This file contains the context structures of those algorithms which do not
 *  rely on other algorithms, i.e. are 'primitive' algorithms.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * \note This header and its content are not part of the Mbed TLS API and
 * applications must not depend on it. Its main purpose is to define the
 * multi-part state objects of the Mbed TLS software-based PSA drivers. The
 * definitions of these objects are then used by crypto_struct.h to define the
 * implementation-defined types of PSA multi-part state objects.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_PSA_CRYPTO_BUILTIN_PRIMITIVES_H
#define AWRTC_PSA_CRYPTO_BUILTIN_PRIMITIVES_H
#include "../mbedtls/private_access.h"

#include "crypto_driver_common.h"

/*
 * Hash multi-part operation definitions.
 */

#include "../mbedtls/md5.h"
#include "../mbedtls/ripemd160.h"
#include "../mbedtls/sha1.h"
#include "../mbedtls/sha256.h"
#include "../mbedtls/sha512.h"
#include "../mbedtls/sha3.h"

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_MD5) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA_1) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA_224) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA_256) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA_384) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA_512) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA3_224) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA3_256) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA3_384) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA3_512)
#define AWRTC_MBEDTLS_PSA_BUILTIN_HASH
#endif

typedef struct {
    awrtc_psa_algorithm_t AWRTC_MBEDTLS_PRIVATE(alg);
    union {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_MD5)
        awrtc_mbedtls_md5_context md5;
#endif
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160)
        awrtc_mbedtls_ripemd160_context ripemd160;
#endif
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA_1)
        awrtc_mbedtls_sha1_context sha1;
#endif
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA_256) || \
        defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA_224)
        awrtc_mbedtls_sha256_context sha256;
#endif
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA_512) || \
        defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA_384)
        awrtc_mbedtls_sha512_context sha512;
#endif
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA3_224) || \
        defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA3_256) || \
        defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA3_384) || \
        defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_SHA3_512)
        awrtc_mbedtls_sha3_context sha3;
#endif
    } AWRTC_MBEDTLS_PRIVATE(ctx);
} awrtc_mbedtls_psa_hash_operation_t;

#define AWRTC_MBEDTLS_PSA_HASH_OPERATION_INIT { 0, { 0 } }

/*
 * Cipher multi-part operation definitions.
 */

#include "../mbedtls/cipher.h"

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_STREAM_CIPHER) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CTR) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CFB) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_OFB) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_ECB_NO_PADDING) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CBC_NO_PADDING) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CBC_PKCS7) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM_STAR_NO_TAG)
#define AWRTC_MBEDTLS_PSA_BUILTIN_CIPHER  1
#endif

typedef struct {
    /* Context structure for the Mbed TLS cipher implementation. */
    awrtc_psa_algorithm_t AWRTC_MBEDTLS_PRIVATE(alg);
    uint8_t AWRTC_MBEDTLS_PRIVATE(iv_length);
    uint8_t AWRTC_MBEDTLS_PRIVATE(block_length);
    union {
        unsigned int AWRTC_MBEDTLS_PRIVATE(dummy);
        awrtc_mbedtls_cipher_context_t AWRTC_MBEDTLS_PRIVATE(cipher);
    } AWRTC_MBEDTLS_PRIVATE(ctx);
} awrtc_mbedtls_psa_cipher_operation_t;

#define AWRTC_MBEDTLS_PSA_CIPHER_OPERATION_INIT { 0, 0, 0, { 0 } }

#endif /* AWRTC_PSA_CRYPTO_BUILTIN_PRIMITIVES_H */
