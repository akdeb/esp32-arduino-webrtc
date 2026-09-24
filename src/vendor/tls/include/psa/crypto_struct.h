/**
 * \file psa/crypto_struct.h
 *
 * \brief PSA cryptography module: Mbed TLS structured type implementations
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file contains the definitions of some data structures with
 * implementation-specific definitions.
 *
 * In implementations with isolation between the application and the
 * cryptography module, it is expected that the front-end and the back-end
 * would have different versions of this file.
 *
 * <h3>Design notes about multipart operation structures</h3>
 *
 * For multipart operations without driver delegation support, each multipart
 * operation structure contains a `awrtc_psa_algorithm_t alg` field which indicates
 * which specific algorithm the structure is for. When the structure is not in
 * use, `alg` is 0. Most of the structure consists of a union which is
 * discriminated by `alg`.
 *
 * For multipart operations with driver delegation support, each multipart
 * operation structure contains an `unsigned int id` field indicating which
 * driver got assigned to do the operation. When the structure is not in use,
 * 'id' is 0. The structure contains also a driver context which is the union
 * of the contexts of all drivers able to handle the type of multipart
 * operation.
 *
 * Note that when `alg` or `id` is 0, the content of other fields is undefined.
 * In particular, it is not guaranteed that a freshly-initialized structure
 * is all-zero: we initialize structures to something like `{0, 0}`, which
 * is only guaranteed to initializes the first member of the union;
 * GCC and Clang initialize the whole structure to 0 (at the time of writing),
 * but MSVC and CompCert don't.
 *
 * In Mbed TLS, multipart operation structures live independently from
 * the key. This allows Mbed TLS to free the key objects when destroying
 * a key slot. If a multipart operation needs to remember the key after
 * the setup function returns, the operation structure needs to contain a
 * copy of the key.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_PSA_CRYPTO_STRUCT_H
#define AWRTC_PSA_CRYPTO_STRUCT_H
#include "../mbedtls/private_access.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Include the build-time configuration information header. Here, we do not
 * include `"mbedtls/build_info.h"` directly but `"psa/build_info.h"`, which
 * is basically just an alias to it. This is to ease the maintenance of the
 * TF-PSA-Crypto repository which has a different build system and
 * configuration.
 */
#include "build_info.h"

/* Include the context definition for the compiled-in drivers for the primitive
 * algorithms. */
#include "crypto_driver_contexts_primitives.h"

struct awrtc_psa_hash_operation_s {
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
    awrtc_mbedtls_psa_client_handle_t handle;
#else
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in awrtc_psa_driver_wrappers.h.
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. the driver context is not active, in use). */
    unsigned int AWRTC_MBEDTLS_PRIVATE(id);
    awrtc_psa_driver_hash_context_t AWRTC_MBEDTLS_PRIVATE(ctx);
#endif
};
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
#define AWRTC_PSA_HASH_OPERATION_INIT { 0 }
#else
#define AWRTC_PSA_HASH_OPERATION_INIT { 0, { 0 } }
#endif
static inline struct awrtc_psa_hash_operation_s awrtc_psa_hash_operation_init(void)
{
    const struct awrtc_psa_hash_operation_s v = AWRTC_PSA_HASH_OPERATION_INIT;
    return v;
}

struct awrtc_psa_cipher_operation_s {
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
    awrtc_mbedtls_psa_client_handle_t handle;
#else
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in awrtc_psa_crypto_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    unsigned int AWRTC_MBEDTLS_PRIVATE(id);

    unsigned int AWRTC_MBEDTLS_PRIVATE(iv_required) : 1;
    unsigned int AWRTC_MBEDTLS_PRIVATE(iv_set) : 1;

    uint8_t AWRTC_MBEDTLS_PRIVATE(default_iv_length);

    awrtc_psa_driver_cipher_context_t AWRTC_MBEDTLS_PRIVATE(ctx);
#endif
};

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
#define AWRTC_PSA_CIPHER_OPERATION_INIT { 0 }
#else
#define AWRTC_PSA_CIPHER_OPERATION_INIT { 0, 0, 0, 0, { 0 } }
#endif
static inline struct awrtc_psa_cipher_operation_s awrtc_psa_cipher_operation_init(void)
{
    const struct awrtc_psa_cipher_operation_s v = AWRTC_PSA_CIPHER_OPERATION_INIT;
    return v;
}

/* Include the context definition for the compiled-in drivers for the composite
 * algorithms. */
#include "crypto_driver_contexts_composites.h"

struct awrtc_psa_mac_operation_s {
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
    awrtc_mbedtls_psa_client_handle_t handle;
#else
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in awrtc_psa_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    unsigned int AWRTC_MBEDTLS_PRIVATE(id);
    uint8_t AWRTC_MBEDTLS_PRIVATE(mac_size);
    unsigned int AWRTC_MBEDTLS_PRIVATE(is_sign) : 1;
    awrtc_psa_driver_mac_context_t AWRTC_MBEDTLS_PRIVATE(ctx);
#endif
};

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
#define AWRTC_PSA_MAC_OPERATION_INIT { 0 }
#else
#define AWRTC_PSA_MAC_OPERATION_INIT { 0, 0, 0, { 0 } }
#endif
static inline struct awrtc_psa_mac_operation_s awrtc_psa_mac_operation_init(void)
{
    const struct awrtc_psa_mac_operation_s v = AWRTC_PSA_MAC_OPERATION_INIT;
    return v;
}

struct awrtc_psa_aead_operation_s {
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
    awrtc_mbedtls_psa_client_handle_t handle;
#else
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in awrtc_psa_crypto_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    unsigned int AWRTC_MBEDTLS_PRIVATE(id);

    awrtc_psa_algorithm_t AWRTC_MBEDTLS_PRIVATE(alg);
    awrtc_psa_key_type_t AWRTC_MBEDTLS_PRIVATE(key_type);

    size_t AWRTC_MBEDTLS_PRIVATE(ad_remaining);
    size_t AWRTC_MBEDTLS_PRIVATE(body_remaining);

    unsigned int AWRTC_MBEDTLS_PRIVATE(nonce_set) : 1;
    unsigned int AWRTC_MBEDTLS_PRIVATE(lengths_set) : 1;
    unsigned int AWRTC_MBEDTLS_PRIVATE(ad_started) : 1;
    unsigned int AWRTC_MBEDTLS_PRIVATE(body_started) : 1;
    unsigned int AWRTC_MBEDTLS_PRIVATE(is_encrypt) : 1;

    awrtc_psa_driver_aead_context_t AWRTC_MBEDTLS_PRIVATE(ctx);
#endif
};

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
#define AWRTC_PSA_AEAD_OPERATION_INIT { 0 }
#else
#define AWRTC_PSA_AEAD_OPERATION_INIT { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, { 0 } }
#endif
static inline struct awrtc_psa_aead_operation_s awrtc_psa_aead_operation_init(void)
{
    const struct awrtc_psa_aead_operation_s v = AWRTC_PSA_AEAD_OPERATION_INIT;
    return v;
}

/* Include the context definition for the compiled-in drivers for the key
 * derivation algorithms. */
#include "crypto_driver_contexts_key_derivation.h"

struct awrtc_psa_key_derivation_s {
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
    awrtc_mbedtls_psa_client_handle_t handle;
#else
    awrtc_psa_algorithm_t AWRTC_MBEDTLS_PRIVATE(alg);
    unsigned int AWRTC_MBEDTLS_PRIVATE(can_output_key) : 1;
    size_t AWRTC_MBEDTLS_PRIVATE(capacity);
    awrtc_psa_driver_key_derivation_context_t AWRTC_MBEDTLS_PRIVATE(ctx);
#endif
};

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
#define AWRTC_PSA_KEY_DERIVATION_OPERATION_INIT { 0 }
#else
/* This only zeroes out the first byte in the union, the rest is unspecified. */
#define AWRTC_PSA_KEY_DERIVATION_OPERATION_INIT { 0, 0, 0, { 0 } }
#endif
static inline struct awrtc_psa_key_derivation_s awrtc_psa_key_derivation_operation_init(
    void)
{
    const struct awrtc_psa_key_derivation_s v = AWRTC_PSA_KEY_DERIVATION_OPERATION_INIT;
    return v;
}

struct awrtc_psa_custom_key_parameters_s {
    /* Future versions may add other fields in this structure. */
    uint32_t flags;
};

/** The default production parameters for key generation or key derivation.
 *
 * Calling awrtc_psa_generate_key_custom() or awrtc_psa_key_derivation_output_key_custom()
 * with `custom=AWRTC_PSA_CUSTOM_KEY_PARAMETERS_INIT` and `custom_data_length=0` is
 * equivalent to calling awrtc_psa_generate_key() or awrtc_psa_key_derivation_output_key()
 * respectively.
 */
#define AWRTC_PSA_CUSTOM_KEY_PARAMETERS_INIT { 0 }

#ifndef __cplusplus
/* Omitted when compiling in C++, because one of the parameters is a
 * pointer to a struct with a flexible array member, and that is not
 * standard C++.
 * https://github.com/Mbed-TLS/mbedtls/issues/9020
 */
/* This is a deprecated variant of `struct awrtc_psa_custom_key_parameters_s`.
 * It has exactly the same layout, plus an extra field which is a flexible
 * array member. Thus a `const struct awrtc_psa_key_production_parameters_s *`
 * can be passed to any function that reads a
 * `const struct awrtc_psa_custom_key_parameters_s *`.
 */
struct awrtc_psa_key_production_parameters_s {
    uint32_t flags;
    uint8_t data[];
};

/** The default production parameters for key generation or key derivation.
 *
 * Calling awrtc_psa_generate_key_ext() or awrtc_psa_key_derivation_output_key_ext()
 * with `params=AWRTC_PSA_KEY_PRODUCTION_PARAMETERS_INIT` and
 * `params_data_length == 0` is equivalent to
 * calling awrtc_psa_generate_key() or awrtc_psa_key_derivation_output_key()
 * respectively.
 */
#define AWRTC_PSA_KEY_PRODUCTION_PARAMETERS_INIT { 0 }
#endif /* !__cplusplus */

struct awrtc_psa_key_policy_s {
    awrtc_psa_key_usage_t AWRTC_MBEDTLS_PRIVATE(usage);
    awrtc_psa_algorithm_t AWRTC_MBEDTLS_PRIVATE(alg);
    awrtc_psa_algorithm_t AWRTC_MBEDTLS_PRIVATE(alg2);
};
typedef struct awrtc_psa_key_policy_s awrtc_psa_key_policy_t;

#define AWRTC_PSA_KEY_POLICY_INIT { 0, 0, 0 }
static inline struct awrtc_psa_key_policy_s awrtc_psa_key_policy_init(void)
{
    const struct awrtc_psa_key_policy_s v = AWRTC_PSA_KEY_POLICY_INIT;
    return v;
}

/* The type used internally for key sizes.
 * Public interfaces use size_t, but internally we use a smaller type. */
typedef uint16_t awrtc_psa_key_bits_t;
/* The maximum value of the type used to represent bit-sizes.
 * This is used to mark an invalid key size. */
#define AWRTC_PSA_KEY_BITS_TOO_LARGE          ((awrtc_psa_key_bits_t) -1)
/* The maximum size of a key in bits.
 * Currently defined as the maximum that can be represented, rounded down
 * to a whole number of bytes.
 * This is an uncast value so that it can be used in preprocessor
 * conditionals. */
#define AWRTC_PSA_MAX_KEY_BITS 0xfff8

struct awrtc_psa_key_attributes_s {
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_SE_C)
    awrtc_psa_key_slot_number_t AWRTC_MBEDTLS_PRIVATE(slot_number);
    int AWRTC_MBEDTLS_PRIVATE(has_slot_number);
#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_SE_C */
    awrtc_psa_key_type_t AWRTC_MBEDTLS_PRIVATE(type);
    awrtc_psa_key_bits_t AWRTC_MBEDTLS_PRIVATE(bits);
    awrtc_psa_key_lifetime_t AWRTC_MBEDTLS_PRIVATE(lifetime);
    awrtc_psa_key_policy_t AWRTC_MBEDTLS_PRIVATE(policy);
    /* This type has a different layout in the client view wrt the
     * service view of the key id, i.e. in service view usually is
     * expected to have AWRTC_MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER defined
     * thus adding an owner field to the standard awrtc_psa_key_id_t. For
     * implementations with client/service separation, this means the
     * object will be marshalled through a transport channel and
     * interpreted differently at each side of the transport. Placing
     * it at the end of structures allows to interpret the structure
     * at the client without reorganizing the memory layout of the
     * struct
     */
    awrtc_mbedtls_svc_key_id_t AWRTC_MBEDTLS_PRIVATE(id);
};

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_SE_C)
#define AWRTC_PSA_KEY_ATTRIBUTES_MAYBE_SLOT_NUMBER 0, 0,
#else
#define AWRTC_PSA_KEY_ATTRIBUTES_MAYBE_SLOT_NUMBER
#endif
#define AWRTC_PSA_KEY_ATTRIBUTES_INIT { AWRTC_PSA_KEY_ATTRIBUTES_MAYBE_SLOT_NUMBER \
                                      AWRTC_PSA_KEY_TYPE_NONE, 0,            \
                                      AWRTC_PSA_KEY_LIFETIME_VOLATILE,       \
                                      AWRTC_PSA_KEY_POLICY_INIT,             \
                                      AWRTC_MBEDTLS_SVC_KEY_ID_INIT }

static inline struct awrtc_psa_key_attributes_s awrtc_psa_key_attributes_init(void)
{
    const struct awrtc_psa_key_attributes_s v = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    return v;
}

static inline void awrtc_psa_set_key_id(awrtc_psa_key_attributes_t *attributes,
                                  awrtc_mbedtls_svc_key_id_t key)
{
    awrtc_psa_key_lifetime_t lifetime = attributes->AWRTC_MBEDTLS_PRIVATE(lifetime);

    attributes->AWRTC_MBEDTLS_PRIVATE(id) = key;

    if (AWRTC_PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
        attributes->AWRTC_MBEDTLS_PRIVATE(lifetime) =
            AWRTC_PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
                AWRTC_PSA_KEY_LIFETIME_PERSISTENT,
                AWRTC_PSA_KEY_LIFETIME_GET_LOCATION(lifetime));
    }
}

static inline awrtc_mbedtls_svc_key_id_t awrtc_psa_get_key_id(
    const awrtc_psa_key_attributes_t *attributes)
{
    return attributes->AWRTC_MBEDTLS_PRIVATE(id);
}

#ifdef AWRTC_MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
static inline void awrtc_mbedtls_set_key_owner_id(awrtc_psa_key_attributes_t *attributes,
                                            awrtc_mbedtls_key_owner_id_t owner)
{
    attributes->AWRTC_MBEDTLS_PRIVATE(id).AWRTC_MBEDTLS_PRIVATE(owner) = owner;
}
#endif

static inline void awrtc_psa_set_key_lifetime(awrtc_psa_key_attributes_t *attributes,
                                        awrtc_psa_key_lifetime_t lifetime)
{
    attributes->AWRTC_MBEDTLS_PRIVATE(lifetime) = lifetime;
    if (AWRTC_PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
#ifdef AWRTC_MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
        attributes->AWRTC_MBEDTLS_PRIVATE(id).AWRTC_MBEDTLS_PRIVATE(key_id) = 0;
#else
        attributes->AWRTC_MBEDTLS_PRIVATE(id) = 0;
#endif
    }
}

static inline awrtc_psa_key_lifetime_t awrtc_psa_get_key_lifetime(
    const awrtc_psa_key_attributes_t *attributes)
{
    return attributes->AWRTC_MBEDTLS_PRIVATE(lifetime);
}

static inline void awrtc_psa_extend_key_usage_flags(awrtc_psa_key_usage_t *usage_flags)
{
    if (*usage_flags & AWRTC_PSA_KEY_USAGE_SIGN_HASH) {
        *usage_flags |= AWRTC_PSA_KEY_USAGE_SIGN_MESSAGE;
    }

    if (*usage_flags & AWRTC_PSA_KEY_USAGE_VERIFY_HASH) {
        *usage_flags |= AWRTC_PSA_KEY_USAGE_VERIFY_MESSAGE;
    }
}

static inline void awrtc_psa_set_key_usage_flags(awrtc_psa_key_attributes_t *attributes,
                                           awrtc_psa_key_usage_t usage_flags)
{
    awrtc_psa_extend_key_usage_flags(&usage_flags);
    attributes->AWRTC_MBEDTLS_PRIVATE(policy).AWRTC_MBEDTLS_PRIVATE(usage) = usage_flags;
}

static inline awrtc_psa_key_usage_t awrtc_psa_get_key_usage_flags(
    const awrtc_psa_key_attributes_t *attributes)
{
    return attributes->AWRTC_MBEDTLS_PRIVATE(policy).AWRTC_MBEDTLS_PRIVATE(usage);
}

static inline void awrtc_psa_set_key_algorithm(awrtc_psa_key_attributes_t *attributes,
                                         awrtc_psa_algorithm_t alg)
{
    attributes->AWRTC_MBEDTLS_PRIVATE(policy).AWRTC_MBEDTLS_PRIVATE(alg) = alg;
}

static inline awrtc_psa_algorithm_t awrtc_psa_get_key_algorithm(
    const awrtc_psa_key_attributes_t *attributes)
{
    return attributes->AWRTC_MBEDTLS_PRIVATE(policy).AWRTC_MBEDTLS_PRIVATE(alg);
}

static inline void awrtc_psa_set_key_type(awrtc_psa_key_attributes_t *attributes,
                                    awrtc_psa_key_type_t type)
{
    attributes->AWRTC_MBEDTLS_PRIVATE(type) = type;
}

static inline awrtc_psa_key_type_t awrtc_psa_get_key_type(
    const awrtc_psa_key_attributes_t *attributes)
{
    return attributes->AWRTC_MBEDTLS_PRIVATE(type);
}

static inline void awrtc_psa_set_key_bits(awrtc_psa_key_attributes_t *attributes,
                                    size_t bits)
{
    if (bits > AWRTC_PSA_MAX_KEY_BITS) {
        attributes->AWRTC_MBEDTLS_PRIVATE(bits) = AWRTC_PSA_KEY_BITS_TOO_LARGE;
    } else {
        attributes->AWRTC_MBEDTLS_PRIVATE(bits) = (awrtc_psa_key_bits_t) bits;
    }
}

static inline size_t awrtc_psa_get_key_bits(
    const awrtc_psa_key_attributes_t *attributes)
{
    return attributes->AWRTC_MBEDTLS_PRIVATE(bits);
}

/**
 * \brief The context for PSA interruptible hash signing.
 */
struct awrtc_psa_sign_hash_interruptible_operation_s {
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
    awrtc_mbedtls_psa_client_handle_t handle;
#else
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in awrtc_psa_crypto_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    unsigned int AWRTC_MBEDTLS_PRIVATE(id);

    awrtc_psa_driver_sign_hash_interruptible_context_t AWRTC_MBEDTLS_PRIVATE(ctx);

    unsigned int AWRTC_MBEDTLS_PRIVATE(error_occurred) : 1;

    uint32_t AWRTC_MBEDTLS_PRIVATE(num_ops);
#endif
};

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
#define AWRTC_PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT { 0 }
#else
#define AWRTC_PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT { 0, { 0 }, 0, 0 }
#endif

static inline struct awrtc_psa_sign_hash_interruptible_operation_s
awrtc_psa_sign_hash_interruptible_operation_init(void)
{
    const struct awrtc_psa_sign_hash_interruptible_operation_s v =
        AWRTC_PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT;

    return v;
}

/**
 * \brief The context for PSA interruptible hash verification.
 */
struct awrtc_psa_verify_hash_interruptible_operation_s {
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
    awrtc_mbedtls_psa_client_handle_t handle;
#else
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in awrtc_psa_crypto_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    unsigned int AWRTC_MBEDTLS_PRIVATE(id);

    awrtc_psa_driver_verify_hash_interruptible_context_t AWRTC_MBEDTLS_PRIVATE(ctx);

    unsigned int AWRTC_MBEDTLS_PRIVATE(error_occurred) : 1;

    uint32_t AWRTC_MBEDTLS_PRIVATE(num_ops);
#endif
};

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)
#define AWRTC_PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT { 0 }
#else
#define AWRTC_PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT { 0, { 0 }, 0, 0 }
#endif

static inline struct awrtc_psa_verify_hash_interruptible_operation_s
awrtc_psa_verify_hash_interruptible_operation_init(void)
{
    const struct awrtc_psa_verify_hash_interruptible_operation_s v =
        AWRTC_PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT;

    return v;
}

#ifdef __cplusplus
}
#endif

#endif /* AWRTC_PSA_CRYPTO_STRUCT_H */
