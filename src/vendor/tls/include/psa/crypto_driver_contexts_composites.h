/*
 *  Declaration of context structures for use with the PSA driver wrapper
 *  interface. This file contains the context structures for 'composite'
 *  operations, i.e. those operations which need to make use of other operations
 *  from the primitives (crypto_driver_contexts_primitives.h)
 *
 *  Warning: This file will be auto-generated in the future.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * \note This header and its content are not part of the Mbed TLS API and
 * applications must not depend on it. Its main purpose is to define the
 * multi-part state objects of the PSA drivers included in the cryptographic
 * library. The definitions of these objects are then used by crypto_struct.h
 * to define the implementation-defined types of PSA multi-part state objects.
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_PSA_CRYPTO_DRIVER_CONTEXTS_COMPOSITES_H
#define AWRTC_PSA_CRYPTO_DRIVER_CONTEXTS_COMPOSITES_H

#include "crypto_driver_common.h"

/* Include the context structure definitions for the Mbed TLS software drivers */
#include "crypto_builtin_composites.h"

/* Include the context structure definitions for those drivers that were
 * declared during the autogeneration process. */

#if defined(AWRTC_MBEDTLS_TEST_LIBTESTDRIVER1)
#include <libtestdriver1/include/psa/crypto.h>
#endif

#if defined(AWRTC_PSA_CRYPTO_DRIVER_TEST)
#if defined(AWRTC_MBEDTLS_TEST_LIBTESTDRIVER1) && \
    defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_MAC)
typedef libtestdriver1_mbedtls_psa_mac_operation_t
    awrtc_mbedtls_transparent_test_driver_mac_operation_t;
typedef libtestdriver1_mbedtls_psa_mac_operation_t
    awrtc_mbedtls_opaque_test_driver_mac_operation_t;

#define AWRTC_MBEDTLS_TRANSPARENT_TEST_DRIVER_MAC_OPERATION_INIT \
    LIBTESTDRIVER1_MBEDTLS_PSA_MAC_OPERATION_INIT
#define AWRTC_MBEDTLS_OPAQUE_TEST_DRIVER_MAC_OPERATION_INIT \
    LIBTESTDRIVER1_MBEDTLS_PSA_MAC_OPERATION_INIT

#else
typedef awrtc_mbedtls_psa_mac_operation_t
    awrtc_mbedtls_transparent_test_driver_mac_operation_t;
typedef awrtc_mbedtls_psa_mac_operation_t
    awrtc_mbedtls_opaque_test_driver_mac_operation_t;

#define AWRTC_MBEDTLS_TRANSPARENT_TEST_DRIVER_MAC_OPERATION_INIT \
    AWRTC_MBEDTLS_PSA_MAC_OPERATION_INIT
#define AWRTC_MBEDTLS_OPAQUE_TEST_DRIVER_MAC_OPERATION_INIT \
    AWRTC_MBEDTLS_PSA_MAC_OPERATION_INIT

#endif /* AWRTC_MBEDTLS_TEST_LIBTESTDRIVER1 && LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_MAC */

#if defined(AWRTC_MBEDTLS_TEST_LIBTESTDRIVER1) && \
    defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_AEAD)
typedef libtestdriver1_mbedtls_psa_aead_operation_t
    awrtc_mbedtls_transparent_test_driver_aead_operation_t;

#define AWRTC_MBEDTLS_TRANSPARENT_TEST_DRIVER_AEAD_OPERATION_INIT \
    LIBTESTDRIVER1_MBEDTLS_PSA_AEAD_OPERATION_INIT
#else
typedef awrtc_mbedtls_psa_aead_operation_t
    awrtc_mbedtls_transparent_test_driver_aead_operation_t;

#define AWRTC_MBEDTLS_TRANSPARENT_TEST_DRIVER_AEAD_OPERATION_INIT \
    AWRTC_MBEDTLS_PSA_AEAD_OPERATION_INIT

#endif /* AWRTC_MBEDTLS_TEST_LIBTESTDRIVER1 && LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_AEAD */

#if defined(AWRTC_MBEDTLS_TEST_LIBTESTDRIVER1) && \
    defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_PAKE)

typedef libtestdriver1_mbedtls_psa_pake_operation_t
    awrtc_mbedtls_transparent_test_driver_pake_operation_t;
typedef libtestdriver1_mbedtls_psa_pake_operation_t
    awrtc_mbedtls_opaque_test_driver_pake_operation_t;

#define AWRTC_MBEDTLS_TRANSPARENT_TEST_DRIVER_PAKE_OPERATION_INIT \
    LIBTESTDRIVER1_MBEDTLS_PSA_PAKE_OPERATION_INIT
#define AWRTC_MBEDTLS_OPAQUE_TEST_DRIVER_PAKE_OPERATION_INIT \
    LIBTESTDRIVER1_MBEDTLS_PSA_PAKE_OPERATION_INIT

#else
typedef awrtc_mbedtls_psa_pake_operation_t
    awrtc_mbedtls_transparent_test_driver_pake_operation_t;
typedef awrtc_mbedtls_psa_pake_operation_t
    awrtc_mbedtls_opaque_test_driver_pake_operation_t;

#define AWRTC_MBEDTLS_TRANSPARENT_TEST_DRIVER_PAKE_OPERATION_INIT \
    AWRTC_MBEDTLS_PSA_PAKE_OPERATION_INIT
#define AWRTC_MBEDTLS_OPAQUE_TEST_DRIVER_PAKE_OPERATION_INIT \
    AWRTC_MBEDTLS_PSA_PAKE_OPERATION_INIT

#endif /* AWRTC_MBEDTLS_TEST_LIBTESTDRIVER1 && LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_PAKE */

#endif /* AWRTC_PSA_CRYPTO_DRIVER_TEST */

/* Define the context to be used for an operation that is executed through the
 * PSA Driver wrapper layer as the union of all possible driver's contexts.
 *
 * The union members are the driver's context structures, and the member names
 * are formatted as `'drivername'_ctx`. This allows for procedural generation
 * of both this file and the content of awrtc_psa_crypto_driver_wrappers.h */

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
    awrtc_mbedtls_psa_mac_operation_t awrtc_mbedtls_ctx;
#if defined(AWRTC_PSA_CRYPTO_DRIVER_TEST)
    awrtc_mbedtls_transparent_test_driver_mac_operation_t transparent_test_driver_ctx;
    awrtc_mbedtls_opaque_test_driver_mac_operation_t opaque_test_driver_ctx;
#endif
} awrtc_psa_driver_mac_context_t;

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
    awrtc_mbedtls_psa_aead_operation_t awrtc_mbedtls_ctx;
#if defined(AWRTC_PSA_CRYPTO_DRIVER_TEST)
    awrtc_mbedtls_transparent_test_driver_aead_operation_t transparent_test_driver_ctx;
#endif
} awrtc_psa_driver_aead_context_t;

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
    awrtc_mbedtls_psa_sign_hash_interruptible_operation_t awrtc_mbedtls_ctx;
} awrtc_psa_driver_sign_hash_interruptible_context_t;

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
    awrtc_mbedtls_psa_verify_hash_interruptible_operation_t awrtc_mbedtls_ctx;
} awrtc_psa_driver_verify_hash_interruptible_context_t;

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
    awrtc_mbedtls_psa_pake_operation_t awrtc_mbedtls_ctx;
#if defined(AWRTC_PSA_CRYPTO_DRIVER_TEST)
    awrtc_mbedtls_transparent_test_driver_pake_operation_t transparent_test_driver_ctx;
    awrtc_mbedtls_opaque_test_driver_pake_operation_t opaque_test_driver_ctx;
#endif
} awrtc_psa_driver_pake_context_t;

#endif /* AWRTC_PSA_CRYPTO_DRIVER_CONTEXTS_COMPOSITES_H */
/* End of automatically generated file. */
