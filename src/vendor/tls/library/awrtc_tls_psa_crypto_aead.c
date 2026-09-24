/*
 *  PSA AEAD entry points
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)

#include "psa_crypto_aead.h"
#include "psa_crypto_core.h"
#include "psa_crypto_cipher.h"

#include <string.h>
#include "../include/mbedtls/platform.h"

#include "../include/mbedtls/ccm.h"
#include "../include/mbedtls/chachapoly.h"
#include "../include/mbedtls/cipher.h"
#include "../include/mbedtls/gcm.h"
#include "../include/mbedtls/error.h"

static awrtc_psa_status_t awrtc_psa_aead_setup(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    awrtc_psa_algorithm_t alg)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_cipher_id_t cipher_id;
    awrtc_mbedtls_cipher_mode_t mode;
    size_t key_bits = attributes->bits;
    (void) key_buffer_size;

    status = awrtc_mbedtls_cipher_values_from_psa(alg, attributes->type,
                                            &key_bits, &mode, &cipher_id);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    switch (AWRTC_PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, 0)) {
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM)
        case AWRTC_PSA_ALG_AEAD_WITH_SHORTENED_TAG(AWRTC_PSA_ALG_CCM, 0):
            operation->alg = AWRTC_PSA_ALG_CCM;
            /* CCM allows the following tag lengths: 4, 6, 8, 10, 12, 14, 16.
             * The call to awrtc_mbedtls_ccm_encrypt_and_tag or
             * awrtc_mbedtls_ccm_auth_decrypt will validate the tag length. */
            if (AWRTC_PSA_BLOCK_CIPHER_BLOCK_LENGTH(attributes->type) != 16) {
                return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
            }

            awrtc_mbedtls_ccm_init(&operation->ctx.ccm);
            status = awrtc_mbedtls_to_psa_error(
                awrtc_mbedtls_ccm_setkey(&operation->ctx.ccm, cipher_id,
                                   key_buffer, (unsigned int) key_bits));
            if (status != AWRTC_PSA_SUCCESS) {
                return status;
            }
            break;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM */

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM)
        case AWRTC_PSA_ALG_AEAD_WITH_SHORTENED_TAG(AWRTC_PSA_ALG_GCM, 0):
            operation->alg = AWRTC_PSA_ALG_GCM;
            /* GCM allows the following tag lengths: 4, 8, 12, 13, 14, 15, 16.
             * The call to awrtc_mbedtls_gcm_crypt_and_tag or
             * awrtc_mbedtls_gcm_auth_decrypt will validate the tag length. */
            if (AWRTC_PSA_BLOCK_CIPHER_BLOCK_LENGTH(attributes->type) != 16) {
                return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
            }

            awrtc_mbedtls_gcm_init(&operation->ctx.gcm);
            status = awrtc_mbedtls_to_psa_error(
                awrtc_mbedtls_gcm_setkey(&operation->ctx.gcm, cipher_id,
                                   key_buffer, (unsigned int) key_bits));
            if (status != AWRTC_PSA_SUCCESS) {
                return status;
            }
            break;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM */

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
        case AWRTC_PSA_ALG_AEAD_WITH_SHORTENED_TAG(AWRTC_PSA_ALG_CHACHA20_POLY1305, 0):
            operation->alg = AWRTC_PSA_ALG_CHACHA20_POLY1305;
            /* We only support the default tag length. */
            if (alg != AWRTC_PSA_ALG_CHACHA20_POLY1305) {
                return AWRTC_PSA_ERROR_NOT_SUPPORTED;
            }

            awrtc_mbedtls_chachapoly_init(&operation->ctx.chachapoly);
            status = awrtc_mbedtls_to_psa_error(
                awrtc_mbedtls_chachapoly_setkey(&operation->ctx.chachapoly,
                                          key_buffer));
            if (status != AWRTC_PSA_SUCCESS) {
                return status;
            }
            break;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */

        default:
            (void) status;
            (void) key_buffer;
            return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    operation->key_type = awrtc_psa_get_key_type(attributes);

    operation->tag_length = AWRTC_PSA_ALG_AEAD_GET_TAG_LENGTH(alg);

    return AWRTC_PSA_SUCCESS;
}

awrtc_psa_status_t awrtc_mbedtls_psa_aead_encrypt(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    awrtc_psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_psa_aead_operation_t operation = AWRTC_MBEDTLS_PSA_AEAD_OPERATION_INIT;
    uint8_t *tag;

    status = awrtc_psa_aead_setup(&operation, attributes, key_buffer,
                            key_buffer_size, alg);

    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    /* For all currently supported modes, the tag is at the end of the
     * ciphertext. */
    if (ciphertext_size < (plaintext_length + operation.tag_length)) {
        status = AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }
    tag = ciphertext + plaintext_length;

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if (operation.alg == AWRTC_PSA_ALG_CCM) {
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_ccm_encrypt_and_tag(&operation.ctx.ccm,
                                        plaintext_length,
                                        nonce, nonce_length,
                                        additional_data,
                                        additional_data_length,
                                        plaintext, ciphertext,
                                        tag, operation.tag_length));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if (operation.alg == AWRTC_PSA_ALG_GCM) {
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_gcm_crypt_and_tag(&operation.ctx.gcm,
                                      AWRTC_MBEDTLS_GCM_ENCRYPT,
                                      plaintext_length,
                                      nonce, nonce_length,
                                      additional_data, additional_data_length,
                                      plaintext, ciphertext,
                                      operation.tag_length, tag));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if (operation.alg == AWRTC_PSA_ALG_CHACHA20_POLY1305) {
        if (operation.tag_length != 16) {
            status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_chachapoly_encrypt_and_tag(&operation.ctx.chachapoly,
                                               plaintext_length,
                                               nonce,
                                               additional_data,
                                               additional_data_length,
                                               plaintext,
                                               ciphertext,
                                               tag));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        (void) tag;
        (void) nonce;
        (void) nonce_length;
        (void) additional_data;
        (void) additional_data_length;
        (void) plaintext;
        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    if (status == AWRTC_PSA_SUCCESS) {
        *ciphertext_length = plaintext_length + operation.tag_length;
    }

exit:
    awrtc_mbedtls_psa_aead_abort(&operation);

    return status;
}

/* Locate the tag in a ciphertext buffer containing the encrypted data
 * followed by the tag. Return the length of the part preceding the tag in
 * *plaintext_length. This is the size of the plaintext in modes where
 * the encrypted data has the same size as the plaintext, such as
 * CCM and GCM. */
static awrtc_psa_status_t awrtc_psa_aead_unpadded_locate_tag(size_t tag_length,
                                                 const uint8_t *ciphertext,
                                                 size_t ciphertext_length,
                                                 size_t plaintext_size,
                                                 const uint8_t **p_tag)
{
    size_t payload_length;
    if (tag_length > ciphertext_length) {
        return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
    }
    payload_length = ciphertext_length - tag_length;
    if (payload_length > plaintext_size) {
        return AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
    }
    *p_tag = ciphertext + payload_length;
    return AWRTC_PSA_SUCCESS;
}

awrtc_psa_status_t awrtc_mbedtls_psa_aead_decrypt(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    awrtc_psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_psa_aead_operation_t operation = AWRTC_MBEDTLS_PSA_AEAD_OPERATION_INIT;
    const uint8_t *tag = NULL;

    status = awrtc_psa_aead_setup(&operation, attributes, key_buffer,
                            key_buffer_size, alg);

    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    status = awrtc_psa_aead_unpadded_locate_tag(operation.tag_length,
                                          ciphertext, ciphertext_length,
                                          plaintext_size, &tag);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if (operation.alg == AWRTC_PSA_ALG_CCM) {
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_ccm_auth_decrypt(&operation.ctx.ccm,
                                     ciphertext_length - operation.tag_length,
                                     nonce, nonce_length,
                                     additional_data,
                                     additional_data_length,
                                     ciphertext, plaintext,
                                     tag, operation.tag_length));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if (operation.alg == AWRTC_PSA_ALG_GCM) {
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_gcm_auth_decrypt(&operation.ctx.gcm,
                                     ciphertext_length - operation.tag_length,
                                     nonce, nonce_length,
                                     additional_data,
                                     additional_data_length,
                                     tag, operation.tag_length,
                                     ciphertext, plaintext));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if (operation.alg == AWRTC_PSA_ALG_CHACHA20_POLY1305) {
        if (operation.tag_length != 16) {
            status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_chachapoly_auth_decrypt(&operation.ctx.chachapoly,
                                            ciphertext_length - operation.tag_length,
                                            nonce,
                                            additional_data,
                                            additional_data_length,
                                            tag,
                                            ciphertext,
                                            plaintext));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        (void) nonce;
        (void) nonce_length;
        (void) additional_data;
        (void) additional_data_length;
        (void) plaintext;
        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    if (status == AWRTC_PSA_SUCCESS) {
        *plaintext_length = ciphertext_length - operation.tag_length;
    }

exit:
    awrtc_mbedtls_psa_aead_abort(&operation);

    return status;
}

/* Set the key and algorithm for a multipart authenticated encryption
 * operation. */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_encrypt_setup(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    awrtc_psa_algorithm_t alg)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;

    status = awrtc_psa_aead_setup(operation, attributes, key_buffer,
                            key_buffer_size, alg);

    if (status == AWRTC_PSA_SUCCESS) {
        operation->is_encrypt = 1;
    }

    return status;
}

/* Set the key and algorithm for a multipart authenticated decryption
 * operation. */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_decrypt_setup(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    awrtc_psa_algorithm_t alg)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;

    status = awrtc_psa_aead_setup(operation, attributes, key_buffer,
                            key_buffer_size, alg);

    if (status == AWRTC_PSA_SUCCESS) {
        operation->is_encrypt = 0;
    }

    return status;
}

/* Set a nonce for the multipart AEAD operation*/
awrtc_psa_status_t awrtc_mbedtls_psa_aead_set_nonce(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    const uint8_t *nonce,
    size_t nonce_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if (operation->alg == AWRTC_PSA_ALG_GCM) {
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_gcm_starts(&operation->ctx.gcm,
                               operation->is_encrypt ?
                               AWRTC_MBEDTLS_GCM_ENCRYPT : AWRTC_MBEDTLS_GCM_DECRYPT,
                               nonce,
                               nonce_length));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if (operation->alg == AWRTC_PSA_ALG_CCM) {
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_ccm_starts(&operation->ctx.ccm,
                               operation->is_encrypt ?
                               AWRTC_MBEDTLS_CCM_ENCRYPT : AWRTC_MBEDTLS_CCM_DECRYPT,
                               nonce,
                               nonce_length));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if (operation->alg == AWRTC_PSA_ALG_CHACHA20_POLY1305) {
        /* Note - ChaChaPoly allows an 8 byte nonce, but we would have to
         * allocate a buffer in the operation, copy the nonce to it and pad
         * it, so for now check the nonce is 12 bytes, as
         * awrtc_mbedtls_chachapoly_starts() assumes it can read 12 bytes from the
         * passed in buffer. */
        if (nonce_length != 12) {
            return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
        }

        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_chachapoly_starts(&operation->ctx.chachapoly,
                                      nonce,
                                      operation->is_encrypt ?
                                      AWRTC_MBEDTLS_CHACHAPOLY_ENCRYPT :
                                      AWRTC_MBEDTLS_CHACHAPOLY_DECRYPT));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        (void) operation;
        (void) nonce;
        (void) nonce_length;

        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}

/* Declare the lengths of the message and additional data for AEAD. */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_set_lengths(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    size_t ad_length,
    size_t plaintext_length)
{
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if (operation->alg == AWRTC_PSA_ALG_CCM) {
        return awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_ccm_set_lengths(&operation->ctx.ccm,
                                    ad_length,
                                    plaintext_length,
                                    operation->tag_length));

    }
#else /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM */
    (void) operation;
    (void) ad_length;
    (void) plaintext_length;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM */

    return AWRTC_PSA_SUCCESS;
}

/* Pass additional data to an active multipart AEAD operation. */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_update_ad(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if (operation->alg == AWRTC_PSA_ALG_GCM) {
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_gcm_update_ad(&operation->ctx.gcm, input, input_length));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if (operation->alg == AWRTC_PSA_ALG_CCM) {
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_ccm_update_ad(&operation->ctx.ccm, input, input_length));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if (operation->alg == AWRTC_PSA_ALG_CHACHA20_POLY1305) {
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_chachapoly_update_aad(&operation->ctx.chachapoly,
                                          input,
                                          input_length));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        (void) operation;
        (void) input;
        (void) input_length;

        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}

/* Encrypt or decrypt a message fragment in an active multipart AEAD
 * operation.*/
awrtc_psa_status_t awrtc_mbedtls_psa_aead_update(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    size_t update_output_length;
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;

    update_output_length = input_length;

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if (operation->alg == AWRTC_PSA_ALG_GCM) {
        status =  awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_gcm_update(&operation->ctx.gcm,
                               input, input_length,
                               output, output_size,
                               &update_output_length));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if (operation->alg == AWRTC_PSA_ALG_CCM) {
        if (output_size < input_length) {
            return AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
        }

        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_ccm_update(&operation->ctx.ccm,
                               input, input_length,
                               output, output_size,
                               &update_output_length));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if (operation->alg == AWRTC_PSA_ALG_CHACHA20_POLY1305) {
        if (output_size < input_length) {
            return AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
        }

        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_chachapoly_update(&operation->ctx.chachapoly,
                                      input_length,
                                      input,
                                      output));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        (void) operation;
        (void) input;
        (void) output;
        (void) output_size;

        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    if (status == AWRTC_PSA_SUCCESS) {
        *output_length = update_output_length;
    }

    return status;
}

/* Finish encrypting a message in a multipart AEAD operation. */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_finish(
    awrtc_mbedtls_psa_aead_operation_t *operation,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length,
    uint8_t *tag,
    size_t tag_size,
    size_t *tag_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    size_t finish_output_size = 0;

    if (tag_size < operation->tag_length) {
        return AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
    }

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if (operation->alg == AWRTC_PSA_ALG_GCM) {
        status =  awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_gcm_finish(&operation->ctx.gcm,
                               ciphertext, ciphertext_size, ciphertext_length,
                               tag, operation->tag_length));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if (operation->alg == AWRTC_PSA_ALG_CCM) {
        /* tag must be big enough to store a tag of size passed into set
         * lengths. */
        if (tag_size < operation->tag_length) {
            return AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
        }

        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_ccm_finish(&operation->ctx.ccm,
                               tag, operation->tag_length));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if (operation->alg == AWRTC_PSA_ALG_CHACHA20_POLY1305) {
        /* Belt and braces. Although the above tag_size check should have
         * already done this, if we later start supporting smaller tag sizes
         * for chachapoly, then passing a tag buffer smaller than 16 into here
         * could cause a buffer overflow, so better safe than sorry. */
        if (tag_size < 16) {
            return AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
        }

        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_chachapoly_finish(&operation->ctx.chachapoly,
                                      tag));
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        (void) ciphertext;
        (void) ciphertext_size;
        (void) ciphertext_length;
        (void) tag;
        (void) tag_size;
        (void) tag_length;

        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    if (status == AWRTC_PSA_SUCCESS) {
        /* This will be zero for all supported algorithms currently, but left
         * here for future support. */
        *ciphertext_length = finish_output_size;
        *tag_length = operation->tag_length;
    }

    return status;
}

/* Abort an AEAD operation */
awrtc_psa_status_t awrtc_mbedtls_psa_aead_abort(
    awrtc_mbedtls_psa_aead_operation_t *operation)
{
    switch (operation->alg) {
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM)
        case AWRTC_PSA_ALG_CCM:
            awrtc_mbedtls_ccm_free(&operation->ctx.ccm);
            break;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM)
        case AWRTC_PSA_ALG_GCM:
            awrtc_mbedtls_gcm_free(&operation->ctx.gcm);
            break;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
        case AWRTC_PSA_ALG_CHACHA20_POLY1305:
            awrtc_mbedtls_chachapoly_free(&operation->ctx.chachapoly);
            break;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    }

    operation->is_encrypt = 0;

    return AWRTC_PSA_SUCCESS;
}

#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_C */
