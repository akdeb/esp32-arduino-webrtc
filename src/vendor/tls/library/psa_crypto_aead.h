/*
 *  PSA AEAD driver entry points
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_PSA_CRYPTO_AEAD_H
#define AWRTC_PSA_CRYPTO_AEAD_H

#include "../include/psa/crypto.h"

/**
 * \brief Process an authenticated encryption operation.
 *
 * \note The signature of this function is that of a PSA driver
 *       aead_encrypt entry point. This function behaves as an aead_encrypt
 *       entry point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * \param[in]  attributes         The attributes of the key to use for the
 *                                operation.
 * \param[in]  key_buffer         The buffer containing the key context.
 * \param      key_buffer_size    Size of the \p key_buffer buffer in bytes.
 * \param      alg                The AEAD algorithm to compute.
 * \param[in]  nonce              Nonce or IV to use.
 * \param      nonce_length       Size of the nonce buffer in bytes. This must
 *                                be appropriate for the selected algorithm.
 *                                The default nonce size is
 *                                AWRTC_PSA_AEAD_NONCE_LENGTH(key_type, alg) where
 *                                key_type is the type of key.
 * \param[in]  additional_data    Additional data that will be authenticated
 *                                but not encrypted.
 * \param      additional_data_length  Size of additional_data in bytes.
 * \param[in]  plaintext          Data that will be authenticated and encrypted.
 * \param      plaintext_length   Size of plaintext in bytes.
 * \param[out] ciphertext         Output buffer for the authenticated and
 *                                encrypted data. The additional data is not
 *                                part of this output. For algorithms where the
 *                                encrypted data and the authentication tag are
 *                                defined as separate outputs, the
 *                                authentication tag is appended to the
 *                                encrypted data.
 * \param      ciphertext_size    Size of the ciphertext buffer in bytes. This
 *                                must be appropriate for the selected algorithm
 *                                and key:
 *                                - A sufficient output size is
 *                                  AWRTC_PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, alg,
 *                                  plaintext_length) where key_type is the type
 *                                  of key.
 *                                - AWRTC_PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(
 *                                  plaintext_length) evaluates to the maximum
 *                                  ciphertext size of any supported AEAD
 *                                  encryption.
 * \param[out] ciphertext_length  On success, the size of the output in the
 *                                ciphertext buffer.
 *
 * \retval #AWRTC_PSA_SUCCESS Success.
 * \retval #AWRTC_PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported.
 * \retval #AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #AWRTC_PSA_ERROR_BUFFER_TOO_SMALL
 *         ciphertext_size is too small.
 * \retval #AWRTC_PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_encrypt(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    awrtc_psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length);

/**
 * \brief Process an authenticated decryption operation.
 *
 * \note The signature of this function is that of a PSA driver
 *       aead_decrypt entry point. This function behaves as an aead_decrypt
 *       entry point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * \param[in]  attributes         The attributes of the key to use for the
 *                                operation.
 * \param[in]  key_buffer         The buffer containing the key context.
 * \param      key_buffer_size    Size of the \p key_buffer buffer in bytes.
 * \param      alg                The AEAD algorithm to compute.
 * \param[in]  nonce              Nonce or IV to use.
 * \param      nonce_length       Size of the nonce buffer in bytes. This must
 *                                be appropriate for the selected algorithm.
 *                                The default nonce size is
 *                                AWRTC_PSA_AEAD_NONCE_LENGTH(key_type, alg) where
 *                                key_type is the type of key.
 * \param[in]  additional_data    Additional data that has been authenticated
 *                                but not encrypted.
 * \param      additional_data_length  Size of additional_data in bytes.
 * \param[in]  ciphertext         Data that has been authenticated and
 *                                encrypted. For algorithms where the encrypted
 *                                data and the authentication tag are defined
 *                                as separate inputs, the buffer contains
 *                                encrypted data followed by the authentication
 *                                tag.
 * \param      ciphertext_length  Size of ciphertext in bytes.
 * \param[out] plaintext          Output buffer for the decrypted data.
 * \param      plaintext_size     Size of the plaintext buffer in bytes. This
 *                                must be appropriate for the selected algorithm
 *                                and key:
 *                                - A sufficient output size is
 *                                  AWRTC_PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, alg,
 *                                  ciphertext_length) where key_type is the
 *                                  type of key.
 *                                - AWRTC_PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE(
 *                                  ciphertext_length) evaluates to the maximum
 *                                  plaintext size of any supported AEAD
 *                                  decryption.
 * \param[out] plaintext_length   On success, the size of the output in the
 *                                plaintext buffer.
 *
 * \retval #AWRTC_PSA_SUCCESS Success.
 * \retval #AWRTC_PSA_ERROR_INVALID_SIGNATURE
 *         The cipher is not authentic.
 * \retval #AWRTC_PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported.
 * \retval #AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #AWRTC_PSA_ERROR_BUFFER_TOO_SMALL
 *         plaintext_size is too small.
 * \retval #AWRTC_PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_decrypt(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    awrtc_psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length);

/** Set the key for a multipart authenticated encryption operation.
 *
 *  \note The signature of this function is that of a PSA driver
 *       aead_encrypt_setup entry point. This function behaves as an
 *       aead_encrypt_setup entry point as defined in the PSA driver interface
 *       specification for transparent drivers.
 *
 * If an error occurs at any step after a call to
 * awrtc_mbedtls_psa_aead_encrypt_setup(), the operation is reset by the PSA core by a
 * call to awrtc_mbedtls_psa_aead_abort(). The PSA core may call
 * awrtc_mbedtls_psa_aead_abort() at any time after the operation has been
 * initialized, and is required to when the operation is no longer needed.
 *
 * \param[in,out] operation     The operation object to set up. It must have
 *                              been initialized as per the documentation for
 *                              #awrtc_mbedtls_psa_aead_operation_t and not yet in
 *                              use.
 * \param[in]  attributes       The attributes of the key to use for the
 *                              operation.
 * \param[in]  key_buffer       The buffer containing the key context.
 * \param      key_buffer_size  Size of the \p key_buffer buffer in bytes.
                                It must be consistent with the size in bits
                                recorded in \p attributes.
 * \param alg                   The AEAD algorithm to compute
 *                              (\c AWRTC_PSA_ALG_XXX value such that
 *                              #AWRTC_PSA_ALG_IS_AEAD(\p alg) is true).
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 * \retval #AWRTC_PSA_ERROR_INVALID_ARGUMENT
 *         An invalid block length was supplied.
 * \retval #AWRTC_PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported.
 * \retval #AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY
 *         Failed to allocate memory for key material
 */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_encrypt_setup(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    awrtc_psa_algorithm_t alg);

/** Set the key for a multipart authenticated decryption operation.
 *
 * \note The signature of this function is that of a PSA driver
 *       aead_decrypt_setup entry point. This function behaves as an
 *       aead_decrypt_setup entry point as defined in the PSA driver interface
 *       specification for transparent drivers.
 *
 * If an error occurs at any step after a call to
 * awrtc_mbedtls_psa_aead_decrypt_setup(), the PSA core resets the operation by a
 * call to awrtc_mbedtls_psa_aead_abort(). The PSA core may call
 * awrtc_mbedtls_psa_aead_abort() at any time after the operation has been
 * initialized, and is required to when the operation is no longer needed.
 *
 * \param[in,out] operation     The operation object to set up. It must have
 *                              been initialized as per the documentation for
 *                              #awrtc_mbedtls_psa_aead_operation_t and not yet in
 *                              use.
 * \param[in]  attributes       The attributes of the key to use for the
 *                              operation.
 * \param[in]  key_buffer       The buffer containing the key context.
 * \param      key_buffer_size  Size of the \p key_buffer buffer in bytes.
                                It must be consistent with the size in bits
                                recorded in \p attributes.
 * \param alg                   The AEAD algorithm to compute
 *                              (\c AWRTC_PSA_ALG_XXX value such that
 *                              #AWRTC_PSA_ALG_IS_AEAD(\p alg) is true).
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 * \retval #AWRTC_PSA_ERROR_INVALID_ARGUMENT
 *         An invalid block length was supplied.
 * \retval #AWRTC_PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported.
 * \retval #AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY
 *         Failed to allocate memory for key material
 */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_decrypt_setup(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    awrtc_psa_algorithm_t alg);

/** Set the nonce for an authenticated encryption or decryption operation.
 *
 * \note The signature of this function is that of a PSA driver aead_set_nonce
 *       entry point. This function behaves as an aead_set_nonce entry point as
 *       defined in the PSA driver interface specification for transparent
 *       drivers.
 *
 * This function sets the nonce for the authenticated
 * encryption or decryption operation.
 *
 * The PSA core calls awrtc_mbedtls_psa_aead_encrypt_setup() or
 * awrtc_mbedtls_psa_aead_decrypt_setup() before calling this function.
 *
 * If this function returns an error status, the PSA core will call
 * awrtc_mbedtls_psa_aead_abort().
 *
 * \param[in,out] operation     Active AEAD operation.
 * \param[in] nonce             Buffer containing the nonce to use.
 * \param nonce_length          Size of the nonce in bytes.
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 * \retval #AWRTC_PSA_ERROR_INVALID_ARGUMENT
 *         The size of \p nonce is not acceptable for the chosen algorithm.
 * \retval #AWRTC_PSA_ERROR_NOT_SUPPORTED
 *         Algorithm previously set is not supported in this configuration of
 *         the library.
 */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_set_nonce(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    const uint8_t *nonce,
    size_t nonce_length);

/** Declare the lengths of the message and additional data for AEAD.
 *
 * \note The signature of this function is that of a PSA driver aead_set_lengths
 *       entry point. This function behaves as an aead_set_lengths entry point
 *       as defined in the PSA driver interface specification for transparent
 *       drivers.
 *
 * The PSA core calls this function before calling awrtc_mbedtls_psa_aead_update_ad()
 * or awrtc_mbedtls_psa_aead_update() if the algorithm for the operation requires it.
 * If the algorithm does not require it, calling this function is optional, but
 * if this function is called then the implementation must enforce the lengths.
 *
 * The PSA core may call this function before or after setting the nonce with
 * awrtc_mbedtls_psa_aead_set_nonce().
 *
 * - For #AWRTC_PSA_ALG_CCM, calling this function is required.
 * - For the other AEAD algorithms defined in this specification, calling
 *   this function is not required.
 *
 * If this function returns an error status, the PSA core calls
 * awrtc_mbedtls_psa_aead_abort().
 *
 * \param[in,out] operation     Active AEAD operation.
 * \param ad_length             Size of the non-encrypted additional
 *                              authenticated data in bytes.
 * \param plaintext_length      Size of the plaintext to encrypt in bytes.
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 * \retval #AWRTC_PSA_ERROR_INVALID_ARGUMENT
 *         At least one of the lengths is not acceptable for the chosen
 *         algorithm.
 * \retval #AWRTC_PSA_ERROR_NOT_SUPPORTED
 *         Algorithm previously set is not supported in this configuration of
 *         the library.
 */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_set_lengths(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    size_t ad_length,
    size_t plaintext_length);

/** Pass additional data to an active AEAD operation.
 *
 *  \note The signature of this function is that of a PSA driver
 *       aead_update_ad entry point. This function behaves as an aead_update_ad
 *       entry point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * Additional data is authenticated, but not encrypted.
 *
 * The PSA core can call this function multiple times to pass successive
 * fragments of the additional data. It will not call this function after
 * passing data to encrypt or decrypt with awrtc_mbedtls_psa_aead_update().
 *
 * Before calling this function, the PSA core will:
 *    1. Call either awrtc_mbedtls_psa_aead_encrypt_setup() or
 *       awrtc_mbedtls_psa_aead_decrypt_setup().
 *    2. Set the nonce with awrtc_mbedtls_psa_aead_set_nonce().
 *
 * If this function returns an error status, the PSA core will call
 * awrtc_mbedtls_psa_aead_abort().
 *
 * \param[in,out] operation     Active AEAD operation.
 * \param[in] input             Buffer containing the fragment of
 *                              additional data.
 * \param input_length          Size of the \p input buffer in bytes.
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 * \retval #AWRTC_PSA_ERROR_NOT_SUPPORTED
 *         Algorithm previously set is not supported in this configuration of
 *         the library.
 */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_update_ad(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length);

/** Encrypt or decrypt a message fragment in an active AEAD operation.
 *
 *  \note The signature of this function is that of a PSA driver
 *       aead_update entry point. This function behaves as an aead_update entry
 *       point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * Before calling this function, the PSA core will:
 *    1. Call either awrtc_mbedtls_psa_aead_encrypt_setup() or
 *       awrtc_mbedtls_psa_aead_decrypt_setup(). The choice of setup function
 *       determines whether this function encrypts or decrypts its input.
 *    2. Set the nonce with awrtc_mbedtls_psa_aead_set_nonce().
 *    3. Call awrtc_mbedtls_psa_aead_update_ad() to pass all the additional data.
 *
 * If this function returns an error status, the PSA core will call
 * awrtc_mbedtls_psa_aead_abort().
 *
 * This function does not require the input to be aligned to any
 * particular block boundary. If the implementation can only process
 * a whole block at a time, it must consume all the input provided, but
 * it may delay the end of the corresponding output until a subsequent
 * call to awrtc_mbedtls_psa_aead_update(), awrtc_mbedtls_psa_aead_finish() provides
 * sufficient input. The amount of data that can be delayed in this way is
 * bounded by #AWRTC_PSA_AEAD_UPDATE_OUTPUT_SIZE.
 *
 * \param[in,out] operation     Active AEAD operation.
 * \param[in] input             Buffer containing the message fragment to
 *                              encrypt or decrypt.
 * \param input_length          Size of the \p input buffer in bytes.
 * \param[out] output           Buffer where the output is to be written.
 * \param output_size           Size of the \p output buffer in bytes.
 *                              This must be appropriate for the selected
 *                                algorithm and key:
 *                                - A sufficient output size is
 *                                  #AWRTC_PSA_AEAD_UPDATE_OUTPUT_SIZE(\c key_type,
 *                                  \c alg, \p input_length) where
 *                                  \c key_type is the type of key and \c alg is
 *                                  the algorithm that were used to set up the
 *                                  operation.
 *                                - #AWRTC_PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(\p
 *                                  input_length) evaluates to the maximum
 *                                  output size of any supported AEAD
 *                                  algorithm.
 * \param[out] output_length    On success, the number of bytes
 *                              that make up the returned output.
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 *
 * \retval #AWRTC_PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p output buffer is too small.
 *         #AWRTC_PSA_AEAD_UPDATE_OUTPUT_SIZE(\c key_type, \c alg, \p input_length) or
 *         #AWRTC_PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(\p input_length) can be used to
 *         determine the required buffer size.
 */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_update(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

/** Finish encrypting a message in an AEAD operation.
 *
 *  \note The signature of this function is that of a PSA driver
 *       aead_finish entry point. This function behaves as an aead_finish entry
 *       point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * The operation must have been set up by the PSA core with
 * awrtc_mbedtls_psa_aead_encrypt_setup().
 *
 * This function finishes the authentication of the additional data
 * formed by concatenating the inputs passed to preceding calls to
 * awrtc_mbedtls_psa_aead_update_ad() with the plaintext formed by concatenating the
 * inputs passed to preceding calls to awrtc_mbedtls_psa_aead_update().
 *
 * This function has two output buffers:
 * - \p ciphertext contains trailing ciphertext that was buffered from
 *   preceding calls to awrtc_mbedtls_psa_aead_update().
 * - \p tag contains the authentication tag.
 *
 * Whether or not this function returns successfully, the PSA core subsequently
 * calls awrtc_mbedtls_psa_aead_abort() to deactivate the operation.
 *
 * \param[in,out] operation     Active AEAD operation.
 * \param[out] ciphertext       Buffer where the last part of the ciphertext
 *                              is to be written.
 * \param ciphertext_size       Size of the \p ciphertext buffer in bytes.
 *                              This must be appropriate for the selected
 *                              algorithm and key:
 *                              - A sufficient output size is
 *                                #AWRTC_PSA_AEAD_FINISH_OUTPUT_SIZE(\c key_type,
 *                                \c alg) where \c key_type is the type of key
 *                                and \c alg is the algorithm that were used to
 *                                set up the operation.
 *                              - #AWRTC_PSA_AEAD_FINISH_OUTPUT_MAX_SIZE evaluates to
 *                                the maximum output size of any supported AEAD
 *                                algorithm.
 * \param[out] ciphertext_length On success, the number of bytes of
 *                              returned ciphertext.
 * \param[out] tag              Buffer where the authentication tag is
 *                              to be written.
 * \param tag_size              Size of the \p tag buffer in bytes.
 *                              This must be appropriate for the selected
 *                              algorithm and key:
 *                              - The exact tag size is #AWRTC_PSA_AEAD_TAG_LENGTH(\c
 *                                key_type, \c key_bits, \c alg) where
 *                                \c key_type and \c key_bits are the type and
 *                                bit-size of the key, and \c alg are the
 *                                algorithm that were used in the call to
 *                                awrtc_mbedtls_psa_aead_encrypt_setup().
 *                              - #AWRTC_PSA_AEAD_TAG_MAX_SIZE evaluates to the
 *                                maximum tag size of any supported AEAD
 *                                algorithm.
 * \param[out] tag_length       On success, the number of bytes
 *                              that make up the returned tag.
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 * \retval #AWRTC_PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p tag buffer is too small.
 *         #AWRTC_PSA_AEAD_TAG_LENGTH(\c key_type, key_bits, \c alg) or
 *         #AWRTC_PSA_AEAD_TAG_MAX_SIZE can be used to determine the required \p tag
 *         buffer size.
 */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_finish(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length,
    uint8_t *tag,
    size_t tag_size,
    size_t *tag_length);

/** Abort an AEAD operation.
 *
 *  \note The signature of this function is that of a PSA driver
 *       aead_abort entry point. This function behaves as an aead_abort entry
 *       point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * Aborting an operation frees all associated resources except for the
 * \p operation structure itself. Once aborted, the operation object
 * can be reused for another operation by the PSA core by it calling
 * awrtc_mbedtls_psa_aead_encrypt_setup() or awrtc_mbedtls_psa_aead_decrypt_setup() again.
 *
 * The PSA core may call this function any time after the operation object has
 * been initialized as described in #awrtc_mbedtls_psa_aead_operation_t.
 *
 * In particular, calling awrtc_mbedtls_psa_aead_abort() after the operation has been
 * terminated by a call to awrtc_mbedtls_psa_aead_abort() or
 * awrtc_mbedtls_psa_aead_finish() is safe and has no effect.
 *
 * \param[in,out] operation     Initialized AEAD operation.
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         Success.
 */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_abort(
    awrtc_mbedtls_psa_aead_operation_t *operation);

#endif /* AWRTC_PSA_CRYPTO_AEAD_H */
