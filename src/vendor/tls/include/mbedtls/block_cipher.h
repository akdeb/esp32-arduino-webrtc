/**
 * \file block_cipher.h
 *
 * \brief Internal abstraction layer.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef AWRTC_MBEDTLS_BLOCK_CIPHER_H
#define AWRTC_MBEDTLS_BLOCK_CIPHER_H

#include "private_access.h"

#include "build_info.h"

#if defined(AWRTC_MBEDTLS_AES_C)
#include "aes.h"
#endif
#if defined(AWRTC_MBEDTLS_ARIA_C)
#include "aria.h"
#endif
#if defined(AWRTC_MBEDTLS_CAMELLIA_C)
#include "camellia.h"
#endif

#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
#include "../psa/crypto_types.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AWRTC_MBEDTLS_BLOCK_CIPHER_ID_NONE = 0,  /**< Unset. */
    AWRTC_MBEDTLS_BLOCK_CIPHER_ID_AES,       /**< The AES cipher. */
    AWRTC_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA,  /**< The Camellia cipher. */
    AWRTC_MBEDTLS_BLOCK_CIPHER_ID_ARIA,      /**< The Aria cipher. */
} awrtc_mbedtls_block_cipher_id_t;

/**
 * Used internally to indicate whether a context uses legacy or PSA.
 *
 * Internal use only.
 */
typedef enum {
    AWRTC_MBEDTLS_BLOCK_CIPHER_ENGINE_LEGACY = 0,
    AWRTC_MBEDTLS_BLOCK_CIPHER_ENGINE_PSA,
} awrtc_mbedtls_block_cipher_engine_t;

typedef struct {
    awrtc_mbedtls_block_cipher_id_t AWRTC_MBEDTLS_PRIVATE(id);
#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
    awrtc_mbedtls_block_cipher_engine_t AWRTC_MBEDTLS_PRIVATE(engine);
    awrtc_mbedtls_svc_key_id_t AWRTC_MBEDTLS_PRIVATE(awrtc_psa_key_id);
#endif
    union {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if defined(AWRTC_MBEDTLS_AES_C)
        awrtc_mbedtls_aes_context AWRTC_MBEDTLS_PRIVATE(aes);
#endif
#if defined(AWRTC_MBEDTLS_ARIA_C)
        awrtc_mbedtls_aria_context AWRTC_MBEDTLS_PRIVATE(aria);
#endif
#if defined(AWRTC_MBEDTLS_CAMELLIA_C)
        awrtc_mbedtls_camellia_context AWRTC_MBEDTLS_PRIVATE(camellia);
#endif
    } AWRTC_MBEDTLS_PRIVATE(ctx);
} awrtc_mbedtls_block_cipher_context_t;

#ifdef __cplusplus
}
#endif

#endif /* AWRTC_MBEDTLS_BLOCK_CIPHER_H */
