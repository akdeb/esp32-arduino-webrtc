/*
 *  PSA hashing layer on top of Mbed TLS software crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_PSA_CRYPTO_HASH_H
#define AWRTC_PSA_CRYPTO_HASH_H

#include "../include/psa/crypto.h"

/** Calculate the hash (digest) of a message using Mbed TLS routines.
 *
 * \note The signature of this function is that of a PSA driver hash_compute
 *       entry point. This function behaves as a hash_compute entry point as
 *       defined in the PSA driver interface specification for transparent
 *       drivers.
 *
 * \param alg               The hash algorithm to compute (\c AWRTC_PSA_ALG_XXX value
 *                          such that #AWRTC_PSA_ALG_IS_HASH(\p alg) is true).
 * \param[in] input         Buffer containing the message to hash.
 * \param input_length      Size of the \p input buffer in bytes.
 * \param[out] hash         Buffer where the hash is to be written.
 * \param hash_size         Size of the \p hash buffer in bytes.
 * \param[out] hash_length  On success, the number of bytes
 *                          that make up the hash value. This is always
 *                          #AWRTC_PSA_HASH_LENGTH(\p alg).
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 * \retval #AWRTC_PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported
 * \retval #AWRTC_PSA_ERROR_BUFFER_TOO_SMALL
 *         \p hash_size is too small
 * \retval #AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #AWRTC_PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 */
awrtc_psa_status_t awrtc_mbedtls_psa_hash_compute(
    awrtc_psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length);

/** Set up a multipart hash operation using Mbed TLS routines.
 *
 * \note The signature of this function is that of a PSA driver hash_setup
 *       entry point. This function behaves as a hash_setup entry point as
 *       defined in the PSA driver interface specification for transparent
 *       drivers.
 *
 * If an error occurs at any step after a call to awrtc_mbedtls_psa_hash_setup(), the
 * operation will need to be reset by a call to awrtc_mbedtls_psa_hash_abort(). The
 * core may call awrtc_mbedtls_psa_hash_abort() at any time after the operation
 * has been initialized.
 *
 * After a successful call to awrtc_mbedtls_psa_hash_setup(), the core must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A successful call to awrtc_mbedtls_psa_hash_finish() or awrtc_mbedtls_psa_hash_verify().
 * - A call to awrtc_mbedtls_psa_hash_abort().
 *
 * \param[in,out] operation The operation object to set up. It must have
 *                          been initialized to all-zero and not yet be in use.
 * \param alg               The hash algorithm to compute (\c AWRTC_PSA_ALG_XXX value
 *                          such that #AWRTC_PSA_ALG_IS_HASH(\p alg) is true).
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 * \retval #AWRTC_PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported
 * \retval #AWRTC_PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be inactive).
 * \retval #AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #AWRTC_PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 */
awrtc_psa_status_t awrtc_mbedtls_psa_hash_setup(
    awrtc_mbedtls_psa_hash_operation_t *operation,
    awrtc_psa_algorithm_t alg);

/** Clone an Mbed TLS hash operation.
 *
 * \note The signature of this function is that of a PSA driver hash_clone
 *       entry point. This function behaves as a hash_clone entry point as
 *       defined in the PSA driver interface specification for transparent
 *       drivers.
 *
 * This function copies the state of an ongoing hash operation to
 * a new operation object. In other words, this function is equivalent
 * to calling awrtc_mbedtls_psa_hash_setup() on \p target_operation with the same
 * algorithm that \p source_operation was set up for, then
 * awrtc_mbedtls_psa_hash_update() on \p target_operation with the same input that
 * that was passed to \p source_operation. After this function returns, the
 * two objects are independent, i.e. subsequent calls involving one of
 * the objects do not affect the other object.
 *
 * \param[in] source_operation      The active hash operation to clone.
 * \param[in,out] target_operation  The operation object to set up.
 *                                  It must be initialized but not active.
 *
 * \retval #AWRTC_PSA_SUCCESS \emptydescription
 * \retval #AWRTC_PSA_ERROR_BAD_STATE
 *         The \p source_operation state is not valid (it must be active).
 * \retval #AWRTC_PSA_ERROR_BAD_STATE
 *         The \p target_operation state is not valid (it must be inactive).
 * \retval #AWRTC_PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 * \retval #AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 */
awrtc_psa_status_t awrtc_mbedtls_psa_hash_clone(
    const awrtc_mbedtls_psa_hash_operation_t *source_operation,
    awrtc_mbedtls_psa_hash_operation_t *target_operation);

/** Add a message fragment to a multipart Mbed TLS hash operation.
 *
 * \note The signature of this function is that of a PSA driver hash_update
 *       entry point. This function behaves as a hash_update entry point as
 *       defined in the PSA driver interface specification for transparent
 *       drivers.
 *
 * The application must call awrtc_mbedtls_psa_hash_setup() before calling this function.
 *
 * If this function returns an error status, the operation enters an error
 * state and must be aborted by calling awrtc_mbedtls_psa_hash_abort().
 *
 * \param[in,out] operation Active hash operation.
 * \param[in] input         Buffer containing the message fragment to hash.
 * \param input_length      Size of the \p input buffer in bytes.
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 * \retval #AWRTC_PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be active).
 * \retval #AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #AWRTC_PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 */
awrtc_psa_status_t awrtc_mbedtls_psa_hash_update(
    awrtc_mbedtls_psa_hash_operation_t *operation,
    const uint8_t *input,
    size_t input_length);

/** Finish the calculation of the Mbed TLS-calculated hash of a message.
 *
 * \note The signature of this function is that of a PSA driver hash_finish
 *       entry point. This function behaves as a hash_finish entry point as
 *       defined in the PSA driver interface specification for transparent
 *       drivers.
 *
 * The application must call awrtc_mbedtls_psa_hash_setup() before calling this function.
 * This function calculates the hash of the message formed by concatenating
 * the inputs passed to preceding calls to awrtc_mbedtls_psa_hash_update().
 *
 * When this function returns successfully, the operation becomes inactive.
 * If this function returns an error status, the operation enters an error
 * state and must be aborted by calling awrtc_mbedtls_psa_hash_abort().
 *
 * \param[in,out] operation     Active hash operation.
 * \param[out] hash             Buffer where the hash is to be written.
 * \param hash_size             Size of the \p hash buffer in bytes.
 * \param[out] hash_length      On success, the number of bytes
 *                              that make up the hash value. This is always
 *                              #AWRTC_PSA_HASH_LENGTH(\c alg) where \c alg is the
 *                              hash algorithm that is calculated.
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 * \retval #AWRTC_PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be active).
 * \retval #AWRTC_PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p hash buffer is too small. You can determine a
 *         sufficient buffer size by calling #AWRTC_PSA_HASH_LENGTH(\c alg)
 *         where \c alg is the hash algorithm that is calculated.
 * \retval #AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #AWRTC_PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 */
awrtc_psa_status_t awrtc_mbedtls_psa_hash_finish(
    awrtc_mbedtls_psa_hash_operation_t *operation,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length);

/** Abort an Mbed TLS hash operation.
 *
 * \note The signature of this function is that of a PSA driver hash_abort
 *       entry point. This function behaves as a hash_abort entry point as
 *       defined in the PSA driver interface specification for transparent
 *       drivers.
 *
 * Aborting an operation frees all associated resources except for the
 * \p operation structure itself. Once aborted, the operation object
 * can be reused for another operation by calling
 * awrtc_mbedtls_psa_hash_setup() again.
 *
 * You may call this function any time after the operation object has
 * been initialized by one of the methods described in #awrtc_psa_hash_operation_t.
 *
 * In particular, calling awrtc_mbedtls_psa_hash_abort() after the operation has been
 * terminated by a call to awrtc_mbedtls_psa_hash_abort(), awrtc_mbedtls_psa_hash_finish() or
 * awrtc_mbedtls_psa_hash_verify() is safe and has no effect.
 *
 * \param[in,out] operation     Initialized hash operation.
 *
 * \retval #AWRTC_PSA_SUCCESS \emptydescription
 * \retval #AWRTC_PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 */
awrtc_psa_status_t awrtc_mbedtls_psa_hash_abort(
    awrtc_mbedtls_psa_hash_operation_t *operation);

#endif /* AWRTC_PSA_CRYPTO_HASH_H */
