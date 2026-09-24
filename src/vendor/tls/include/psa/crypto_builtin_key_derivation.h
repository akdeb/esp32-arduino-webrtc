/*
 *  Context structure declaration of the Mbed TLS software-based PSA drivers
 *  called through the PSA Crypto driver dispatch layer.
 *  This file contains the context structures of key derivation algorithms
 *  which need to rely on other algorithms.
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

#ifndef AWRTC_PSA_CRYPTO_BUILTIN_KEY_DERIVATION_H
#define AWRTC_PSA_CRYPTO_BUILTIN_KEY_DERIVATION_H
#include "../mbedtls/private_access.h"

#include "crypto_driver_common.h"

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_HKDF) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
typedef struct {
    uint8_t *AWRTC_MBEDTLS_PRIVATE(info);
    size_t AWRTC_MBEDTLS_PRIVATE(info_length);
#if AWRTC_PSA_HASH_MAX_SIZE > 0xff
#error "AWRTC_PSA_HASH_MAX_SIZE does not fit in uint8_t"
#endif
    uint8_t AWRTC_MBEDTLS_PRIVATE(offset_in_block);
    uint8_t AWRTC_MBEDTLS_PRIVATE(block_number);
    unsigned int AWRTC_MBEDTLS_PRIVATE(state) : 2;
    unsigned int AWRTC_MBEDTLS_PRIVATE(info_set) : 1;
    uint8_t AWRTC_MBEDTLS_PRIVATE(output_block)[AWRTC_PSA_HASH_MAX_SIZE];
    uint8_t AWRTC_MBEDTLS_PRIVATE(prk)[AWRTC_PSA_HASH_MAX_SIZE];
    struct awrtc_psa_mac_operation_s AWRTC_MBEDTLS_PRIVATE(hmac);
} awrtc_psa_hkdf_key_derivation_t;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_HKDF ||
          AWRTC_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT ||
          AWRTC_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
typedef struct {
    uint8_t AWRTC_MBEDTLS_PRIVATE(data)[AWRTC_PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE];
} awrtc_psa_tls12_ecjpake_to_pms_t;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS */

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
typedef enum {
    AWRTC_PSA_TLS12_PRF_STATE_INIT,             /* no input provided */
    AWRTC_PSA_TLS12_PRF_STATE_SEED_SET,         /* seed has been set */
    AWRTC_PSA_TLS12_PRF_STATE_OTHER_KEY_SET,    /* other key has been set - optional */
    AWRTC_PSA_TLS12_PRF_STATE_KEY_SET,          /* key has been set */
    AWRTC_PSA_TLS12_PRF_STATE_LABEL_SET,        /* label has been set */
    AWRTC_PSA_TLS12_PRF_STATE_OUTPUT            /* output has been started */
} awrtc_psa_tls12_prf_key_derivation_state_t;

typedef struct awrtc_psa_tls12_prf_key_derivation_s {
#if AWRTC_PSA_HASH_MAX_SIZE > 0xff
#error "AWRTC_PSA_HASH_MAX_SIZE does not fit in uint8_t"
#endif

    /* Indicates how many bytes in the current HMAC block have
     * not yet been read by the user. */
    uint8_t AWRTC_MBEDTLS_PRIVATE(left_in_block);

    /* The 1-based number of the block. */
    uint8_t AWRTC_MBEDTLS_PRIVATE(block_number);

    awrtc_psa_tls12_prf_key_derivation_state_t AWRTC_MBEDTLS_PRIVATE(state);

    uint8_t *AWRTC_MBEDTLS_PRIVATE(secret);
    size_t AWRTC_MBEDTLS_PRIVATE(secret_length);
    uint8_t *AWRTC_MBEDTLS_PRIVATE(seed);
    size_t AWRTC_MBEDTLS_PRIVATE(seed_length);
    uint8_t *AWRTC_MBEDTLS_PRIVATE(label);
    size_t AWRTC_MBEDTLS_PRIVATE(label_length);
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
    uint8_t *AWRTC_MBEDTLS_PRIVATE(other_secret);
    size_t AWRTC_MBEDTLS_PRIVATE(other_secret_length);
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS */

    uint8_t AWRTC_MBEDTLS_PRIVATE(Ai)[AWRTC_PSA_HASH_MAX_SIZE];

    /* `HMAC_hash( prk, A( i ) + seed )` in the notation of RFC 5246, Sect. 5. */
    uint8_t AWRTC_MBEDTLS_PRIVATE(output_block)[AWRTC_PSA_HASH_MAX_SIZE];
} awrtc_psa_tls12_prf_key_derivation_t;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) ||
        * AWRTC_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS */
#if defined(AWRTC_PSA_HAVE_SOFT_PBKDF2)
typedef enum {
    AWRTC_PSA_PBKDF2_STATE_INIT,             /* no input provided */
    AWRTC_PSA_PBKDF2_STATE_INPUT_COST_SET,   /* input cost has been set */
    AWRTC_PSA_PBKDF2_STATE_SALT_SET,         /* salt has been set */
    AWRTC_PSA_PBKDF2_STATE_PASSWORD_SET,     /* password has been set */
    AWRTC_PSA_PBKDF2_STATE_OUTPUT            /* output has been started */
} awrtc_psa_pbkdf2_key_derivation_state_t;

typedef struct {
    awrtc_psa_pbkdf2_key_derivation_state_t AWRTC_MBEDTLS_PRIVATE(state);
    uint64_t AWRTC_MBEDTLS_PRIVATE(input_cost);
    uint8_t *AWRTC_MBEDTLS_PRIVATE(salt);
    size_t AWRTC_MBEDTLS_PRIVATE(salt_length);
    uint8_t AWRTC_MBEDTLS_PRIVATE(password)[AWRTC_PSA_HMAC_MAX_HASH_BLOCK_SIZE];
    size_t AWRTC_MBEDTLS_PRIVATE(password_length);
    uint8_t AWRTC_MBEDTLS_PRIVATE(output_block)[AWRTC_PSA_HASH_MAX_SIZE];
    uint8_t AWRTC_MBEDTLS_PRIVATE(bytes_used);
    uint32_t AWRTC_MBEDTLS_PRIVATE(block_number);
} awrtc_psa_pbkdf2_key_derivation_t;
#endif /* AWRTC_PSA_HAVE_SOFT_PBKDF2 */

#endif /* AWRTC_PSA_CRYPTO_BUILTIN_KEY_DERIVATION_H */
