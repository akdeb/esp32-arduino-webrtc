/*
 *  PSA PAKE layer on top of Mbed TLS software crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)

#include "../include/psa/crypto.h"
#include "psa_crypto_core.h"
#include "psa_crypto_pake.h"
#include "psa_crypto_slot_management.h"

#include "../include/mbedtls/ecjpake.h"
#include "psa_util_internal.h"

#include "../include/mbedtls/platform.h"
#include "../include/mbedtls/error.h"
#include <string.h>

/*
 * State sequence:
 *
 *   awrtc_psa_pake_setup()
 *   |
 *   |-- In any order:
 *   |   | awrtc_psa_pake_set_password_key()
 *   |   | awrtc_psa_pake_set_user()
 *   |   | awrtc_psa_pake_set_peer()
 *   |   | awrtc_psa_pake_set_role()
 *   |
 *   |--- In any order: (First round input before or after first round output)
 *   |   |
 *   |   |------ In Order
 *   |   |       | awrtc_psa_pake_output(AWRTC_PSA_PAKE_STEP_KEY_SHARE)
 *   |   |       | awrtc_psa_pake_output(AWRTC_PSA_PAKE_STEP_ZK_PUBLIC)
 *   |   |       | awrtc_psa_pake_output(AWRTC_PSA_PAKE_STEP_ZK_PROOF)
 *   |   |       | awrtc_psa_pake_output(AWRTC_PSA_PAKE_STEP_KEY_SHARE)
 *   |   |       | awrtc_psa_pake_output(AWRTC_PSA_PAKE_STEP_ZK_PUBLIC)
 *   |   |       | awrtc_psa_pake_output(AWRTC_PSA_PAKE_STEP_ZK_PROOF)
 *   |   |
 *   |   |------ In Order:
 *   |           | awrtc_psa_pake_input(AWRTC_PSA_PAKE_STEP_KEY_SHARE)
 *   |           | awrtc_psa_pake_input(AWRTC_PSA_PAKE_STEP_ZK_PUBLIC)
 *   |           | awrtc_psa_pake_input(AWRTC_PSA_PAKE_STEP_ZK_PROOF)
 *   |           | awrtc_psa_pake_input(AWRTC_PSA_PAKE_STEP_KEY_SHARE)
 *   |           | awrtc_psa_pake_input(AWRTC_PSA_PAKE_STEP_ZK_PUBLIC)
 *   |           | awrtc_psa_pake_input(AWRTC_PSA_PAKE_STEP_ZK_PROOF)
 *   |
 *   |--- In any order: (Second round input before or after second round output)
 *   |   |
 *   |   |------ In Order
 *   |   |       | awrtc_psa_pake_output(AWRTC_PSA_PAKE_STEP_KEY_SHARE)
 *   |   |       | awrtc_psa_pake_output(AWRTC_PSA_PAKE_STEP_ZK_PUBLIC)
 *   |   |       | awrtc_psa_pake_output(AWRTC_PSA_PAKE_STEP_ZK_PROOF)
 *   |   |
 *   |   |------ In Order:
 *   |           | awrtc_psa_pake_input(AWRTC_PSA_PAKE_STEP_KEY_SHARE)
 *   |           | awrtc_psa_pake_input(AWRTC_PSA_PAKE_STEP_ZK_PUBLIC)
 *   |           | awrtc_psa_pake_input(AWRTC_PSA_PAKE_STEP_ZK_PROOF)
 *   |
 *   awrtc_psa_pake_get_implicit_key()
 *   awrtc_psa_pake_abort()
 */

/*
 * Possible sequence of calls to implementation:
 *
 * |--- In any order:
 * |   |
 * |   |------ In Order
 * |   |       | awrtc_mbedtls_psa_pake_output(AWRTC_PSA_JPAKE_X1_STEP_KEY_SHARE)
 * |   |       | awrtc_mbedtls_psa_pake_output(AWRTC_PSA_JPAKE_X1_STEP_ZK_PUBLIC)
 * |   |       | awrtc_mbedtls_psa_pake_output(AWRTC_PSA_JPAKE_X1_STEP_ZK_PROOF)
 * |   |       | awrtc_mbedtls_psa_pake_output(AWRTC_PSA_JPAKE_X2_STEP_KEY_SHARE)
 * |   |       | awrtc_mbedtls_psa_pake_output(AWRTC_PSA_JPAKE_X2_STEP_ZK_PUBLIC)
 * |   |       | awrtc_mbedtls_psa_pake_output(AWRTC_PSA_JPAKE_X2_STEP_ZK_PROOF)
 * |   |
 * |   |------ In Order:
 * |           | awrtc_mbedtls_psa_pake_input(AWRTC_PSA_JPAKE_X1_STEP_KEY_SHARE)
 * |           | awrtc_mbedtls_psa_pake_input(AWRTC_PSA_JPAKE_X1_STEP_ZK_PUBLIC)
 * |           | awrtc_mbedtls_psa_pake_input(AWRTC_PSA_JPAKE_X1_STEP_ZK_PROOF)
 * |           | awrtc_mbedtls_psa_pake_input(AWRTC_PSA_JPAKE_X2_STEP_KEY_SHARE)
 * |           | awrtc_mbedtls_psa_pake_input(AWRTC_PSA_JPAKE_X2_STEP_ZK_PUBLIC)
 * |           | awrtc_mbedtls_psa_pake_input(AWRTC_PSA_JPAKE_X2_STEP_ZK_PROOF)
 * |
 * |--- In any order:
 * |   |
 * |   |------ In Order
 * |   |       | awrtc_mbedtls_psa_pake_output(AWRTC_PSA_JPAKE_X2S_STEP_KEY_SHARE)
 * |   |       | awrtc_mbedtls_psa_pake_output(AWRTC_PSA_JPAKE_X2S_STEP_ZK_PUBLIC)
 * |   |       | awrtc_mbedtls_psa_pake_output(AWRTC_PSA_JPAKE_X2S_STEP_ZK_PROOF)
 * |   |
 * |   |------ In Order:
 * |           | awrtc_mbedtls_psa_pake_input(AWRTC_PSA_JPAKE_X4S_STEP_KEY_SHARE)
 * |           | awrtc_mbedtls_psa_pake_input(AWRTC_PSA_JPAKE_X4S_STEP_ZK_PUBLIC)
 * |           | awrtc_mbedtls_psa_pake_input(AWRTC_PSA_JPAKE_X4S_STEP_ZK_PROOF)
 */

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
static awrtc_psa_status_t awrtc_mbedtls_ecjpake_to_psa_error(int ret)
{
    switch (ret) {
        case AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA:
        case AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA:
        case AWRTC_MBEDTLS_ERR_ECP_INVALID_KEY:
        case AWRTC_MBEDTLS_ERR_ECP_VERIFY_FAILED:
            return AWRTC_PSA_ERROR_DATA_INVALID;
        case AWRTC_MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL:
        case AWRTC_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL:
            return AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
        case AWRTC_MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE:
            return AWRTC_PSA_ERROR_NOT_SUPPORTED;
        case AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED:
            return AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
        default:
            return AWRTC_PSA_ERROR_GENERIC_ERROR;
    }
}
#endif

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_PAKE)
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
static awrtc_psa_status_t awrtc_psa_pake_ecjpake_setup(awrtc_mbedtls_psa_pake_operation_t *operation)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    awrtc_mbedtls_ecjpake_init(&operation->ctx.jpake);

    ret = awrtc_mbedtls_ecjpake_setup(&operation->ctx.jpake,
                                operation->role,
                                AWRTC_MBEDTLS_MD_SHA256,
                                AWRTC_MBEDTLS_ECP_DP_SECP256R1,
                                operation->password,
                                operation->password_len);

    awrtc_mbedtls_platform_zeroize(operation->password, operation->password_len);

    if (ret != 0) {
        return awrtc_mbedtls_ecjpake_to_psa_error(ret);
    }

    return AWRTC_PSA_SUCCESS;
}
#endif

/* The only two JPAKE user/peer identifiers supported in built-in implementation. */
static const uint8_t jpake_server_id[] = { 's', 'e', 'r', 'v', 'e', 'r' };
static const uint8_t jpake_client_id[] = { 'c', 'l', 'i', 'e', 'n', 't' };

awrtc_psa_status_t awrtc_mbedtls_psa_pake_setup(awrtc_mbedtls_psa_pake_operation_t *operation,
                                    const awrtc_psa_crypto_driver_pake_inputs_t *inputs)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    size_t user_len = 0, peer_len = 0, password_len = 0;
    uint8_t *peer = NULL, *user = NULL;
    size_t actual_user_len = 0, actual_peer_len = 0, actual_password_len = 0;
    awrtc_psa_pake_cipher_suite_t cipher_suite = awrtc_psa_pake_cipher_suite_init();

    status = awrtc_psa_crypto_driver_pake_get_password_len(inputs, &password_len);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    status = awrtc_psa_crypto_driver_pake_get_user_len(inputs, &user_len);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    status = awrtc_psa_crypto_driver_pake_get_peer_len(inputs, &peer_len);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    status = awrtc_psa_crypto_driver_pake_get_cipher_suite(inputs, &cipher_suite);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    operation->password = awrtc_mbedtls_calloc(1, password_len);
    if (operation->password == NULL) {
        status = AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;
        goto error;
    }

    user = awrtc_mbedtls_calloc(1, user_len);
    if (user == NULL) {
        status = AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;
        goto error;
    }

    peer = awrtc_mbedtls_calloc(1, peer_len);
    if (peer == NULL) {
        status = AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;
        goto error;
    }

    status = awrtc_psa_crypto_driver_pake_get_password(inputs, operation->password,
                                                 password_len, &actual_password_len);
    if (status != AWRTC_PSA_SUCCESS) {
        goto error;
    }

    status = awrtc_psa_crypto_driver_pake_get_user(inputs, user,
                                             user_len, &actual_user_len);
    if (status != AWRTC_PSA_SUCCESS) {
        goto error;
    }

    status = awrtc_psa_crypto_driver_pake_get_peer(inputs, peer,
                                             peer_len, &actual_peer_len);
    if (status != AWRTC_PSA_SUCCESS) {
        goto error;
    }

    operation->password_len = actual_password_len;
    operation->alg = cipher_suite.algorithm;

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
    if (cipher_suite.algorithm == AWRTC_PSA_ALG_JPAKE) {
        if (cipher_suite.type != AWRTC_PSA_PAKE_PRIMITIVE_TYPE_ECC ||
            cipher_suite.family != AWRTC_PSA_ECC_FAMILY_SECP_R1 ||
            cipher_suite.bits != 256 ||
            cipher_suite.hash != AWRTC_PSA_ALG_SHA_256) {
            status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
            goto error;
        }

        const size_t user_peer_len = sizeof(jpake_client_id); // client and server have the same length
        if (actual_user_len != user_peer_len ||
            actual_peer_len != user_peer_len) {
            status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
            goto error;
        }

        if (memcmp(user, jpake_client_id, actual_user_len) == 0 &&
            memcmp(peer, jpake_server_id, actual_peer_len) == 0) {
            operation->role = AWRTC_MBEDTLS_ECJPAKE_CLIENT;
        } else
        if (memcmp(user, jpake_server_id, actual_user_len) == 0 &&
            memcmp(peer, jpake_client_id, actual_peer_len) == 0) {
            operation->role = AWRTC_MBEDTLS_ECJPAKE_SERVER;
        } else {
            status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
            goto error;
        }

        operation->buffer_length = 0;
        operation->buffer_offset = 0;

        status = awrtc_psa_pake_ecjpake_setup(operation);
        if (status != AWRTC_PSA_SUCCESS) {
            goto error;
        }

        /* Role has been set, release user/peer buffers. */
        awrtc_mbedtls_free(user); awrtc_mbedtls_free(peer);

        return AWRTC_PSA_SUCCESS;
    } else
#else
    (void) operation;
    (void) inputs;
#endif
    { status = AWRTC_PSA_ERROR_NOT_SUPPORTED; }

error:
    awrtc_mbedtls_free(user); awrtc_mbedtls_free(peer);
    /* In case of failure of the setup of a multipart operation, the PSA driver interface
     * specifies that the core does not call any other driver entry point thus does not
     * call awrtc_mbedtls_psa_pake_abort(). Therefore call it here to do the needed clean
     * up like freeing the memory that may have been allocated to store the password.
     */
    awrtc_mbedtls_psa_pake_abort(operation);
    return status;
}

static awrtc_psa_status_t awrtc_mbedtls_psa_pake_output_internal(
    awrtc_mbedtls_psa_pake_operation_t *operation,
    awrtc_psa_crypto_driver_pake_step_t step,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t length;
    (void) step; // Unused parameter

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
    /*
     * The PSA CRYPTO PAKE and Mbed TLS JPAKE API have a different
     * handling of output sequencing.
     *
     * The Mbed TLS JPAKE API outputs the whole X1+X2 and X2S steps data
     * at once, on the other side the PSA CRYPTO PAKE api requires
     * the KEY_SHARE/ZP_PUBLIC/ZK_PROOF parts of X1, X2 & X2S to be
     * retrieved in sequence.
     *
     * In order to achieve API compatibility, the whole X1+X2 or X2S steps
     * data is stored in an intermediate buffer at first step output call,
     * and data is sliced down by parsing the ECPoint records in order
     * to return the right parts on each step.
     */
    if (operation->alg == AWRTC_PSA_ALG_JPAKE) {
        /* Initialize & write round on KEY_SHARE sequences */
        if (step == AWRTC_PSA_JPAKE_X1_STEP_KEY_SHARE) {
            ret = awrtc_mbedtls_ecjpake_write_round_one(&operation->ctx.jpake,
                                                  operation->buffer,
                                                  sizeof(operation->buffer),
                                                  &operation->buffer_length,
                                                  awrtc_mbedtls_psa_get_random,
                                                  AWRTC_MBEDTLS_PSA_RANDOM_STATE);
            if (ret != 0) {
                return awrtc_mbedtls_ecjpake_to_psa_error(ret);
            }

            operation->buffer_offset = 0;
        } else if (step == AWRTC_PSA_JPAKE_X2S_STEP_KEY_SHARE) {
            ret = awrtc_mbedtls_ecjpake_write_round_two(&operation->ctx.jpake,
                                                  operation->buffer,
                                                  sizeof(operation->buffer),
                                                  &operation->buffer_length,
                                                  awrtc_mbedtls_psa_get_random,
                                                  AWRTC_MBEDTLS_PSA_RANDOM_STATE);
            if (ret != 0) {
                return awrtc_mbedtls_ecjpake_to_psa_error(ret);
            }

            operation->buffer_offset = 0;
        }

        /*
         * awrtc_mbedtls_ecjpake_write_round_xxx() outputs thing in the format
         * defined by draft-cragie-tls-ecjpake-01 section 7. The summary is
         * that the data for each step is prepended with a length byte, and
         * then they're concatenated. Additionally, the server's second round
         * output is prepended with a 3-bytes ECParameters structure.
         *
         * In PSA, we output each step separately, and don't prepend the
         * output with a length byte, even less a curve identifier, as that
         * information is already available.
         */
        if (step == AWRTC_PSA_JPAKE_X2S_STEP_KEY_SHARE &&
            operation->role == AWRTC_MBEDTLS_ECJPAKE_SERVER) {
            /* Skip ECParameters, with is 3 bytes (RFC 8422) */
            operation->buffer_offset += 3;
        }

        /* Read the length byte then move past it to the data */
        length = operation->buffer[operation->buffer_offset];
        operation->buffer_offset += 1;

        if (operation->buffer_offset + length > operation->buffer_length) {
            return AWRTC_PSA_ERROR_DATA_CORRUPT;
        }

        if (output_size < length) {
            return AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
        }

        memcpy(output,
               operation->buffer + operation->buffer_offset,
               length);
        *output_length = length;

        operation->buffer_offset += length;

        /* Reset buffer after ZK_PROOF sequence */
        if ((step == AWRTC_PSA_JPAKE_X2_STEP_ZK_PROOF) ||
            (step == AWRTC_PSA_JPAKE_X2S_STEP_ZK_PROOF)) {
            awrtc_mbedtls_platform_zeroize(operation->buffer, sizeof(operation->buffer));
            operation->buffer_length = 0;
            operation->buffer_offset = 0;
        }

        return AWRTC_PSA_SUCCESS;
    } else
#else
    (void) step;
    (void) output;
    (void) output_size;
    (void) output_length;
#endif
    { return AWRTC_PSA_ERROR_NOT_SUPPORTED; }
}

awrtc_psa_status_t awrtc_mbedtls_psa_pake_output(awrtc_mbedtls_psa_pake_operation_t *operation,
                                     awrtc_psa_crypto_driver_pake_step_t step,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_length)
{
    awrtc_psa_status_t status = awrtc_mbedtls_psa_pake_output_internal(
        operation, step, output, output_size, output_length);

    return status;
}

static awrtc_psa_status_t awrtc_mbedtls_psa_pake_input_internal(
    awrtc_mbedtls_psa_pake_operation_t *operation,
    awrtc_psa_crypto_driver_pake_step_t step,
    const uint8_t *input,
    size_t input_length)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    (void) step; // Unused parameter

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
    /*
     * The PSA CRYPTO PAKE and Mbed TLS JPAKE API have a different
     * handling of input sequencing.
     *
     * The Mbed TLS JPAKE API takes the whole X1+X2 or X4S steps data
     * at once as input, on the other side the PSA CRYPTO PAKE api requires
     * the KEY_SHARE/ZP_PUBLIC/ZK_PROOF parts of X1, X2 & X4S to be
     * given in sequence.
     *
     * In order to achieve API compatibility, each X1+X2 or X4S step data
     * is stored sequentially in an intermediate buffer and given to the
     * Mbed TLS JPAKE API on the last step.
     *
     * This causes any input error to be only detected on the last step.
     */
    if (operation->alg == AWRTC_PSA_ALG_JPAKE) {
        /*
         * Copy input to local buffer and format it as the Mbed TLS API
         * expects, i.e. as defined by draft-cragie-tls-ecjpake-01 section 7.
         * The summary is that the data for each step is prepended with a
         * length byte, and then they're concatenated. Additionally, the
         * server's second round output is prepended with a 3-bytes
         * ECParameters structure - which means we have to prepend that when
         * we're a client.
         */
        if (step == AWRTC_PSA_JPAKE_X4S_STEP_KEY_SHARE &&
            operation->role == AWRTC_MBEDTLS_ECJPAKE_CLIENT) {
            /* We only support secp256r1. */
            /* This is the ECParameters structure defined by RFC 8422. */
            unsigned char ecparameters[3] = {
                3, /* named_curve */
                0, 23 /* secp256r1 */
            };

            if (operation->buffer_length + sizeof(ecparameters) >
                sizeof(operation->buffer)) {
                return AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
            }

            memcpy(operation->buffer + operation->buffer_length,
                   ecparameters, sizeof(ecparameters));
            operation->buffer_length += sizeof(ecparameters);
        }

        /*
         * The core checks that input_length is smaller than
         * AWRTC_PSA_PAKE_INPUT_MAX_SIZE.
         * Thus no risk of integer overflow here.
         */
        if (operation->buffer_length + input_length + 1 > sizeof(operation->buffer)) {
            return AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
        }

        /* Write the length byte */
        operation->buffer[operation->buffer_length] = (uint8_t) input_length;
        operation->buffer_length += 1;

        /* Finally copy the data */
        memcpy(operation->buffer + operation->buffer_length,
               input, input_length);
        operation->buffer_length += input_length;

        /* Load buffer at each last round ZK_PROOF */
        if (step == AWRTC_PSA_JPAKE_X2_STEP_ZK_PROOF) {
            ret = awrtc_mbedtls_ecjpake_read_round_one(&operation->ctx.jpake,
                                                 operation->buffer,
                                                 operation->buffer_length);

            awrtc_mbedtls_platform_zeroize(operation->buffer, sizeof(operation->buffer));
            operation->buffer_length = 0;

            if (ret != 0) {
                return awrtc_mbedtls_ecjpake_to_psa_error(ret);
            }
        } else if (step == AWRTC_PSA_JPAKE_X4S_STEP_ZK_PROOF) {
            ret = awrtc_mbedtls_ecjpake_read_round_two(&operation->ctx.jpake,
                                                 operation->buffer,
                                                 operation->buffer_length);

            awrtc_mbedtls_platform_zeroize(operation->buffer, sizeof(operation->buffer));
            operation->buffer_length = 0;

            if (ret != 0) {
                return awrtc_mbedtls_ecjpake_to_psa_error(ret);
            }
        }

        return AWRTC_PSA_SUCCESS;
    } else
#else
    (void) step;
    (void) input;
    (void) input_length;
#endif
    { return AWRTC_PSA_ERROR_NOT_SUPPORTED; }
}

awrtc_psa_status_t awrtc_mbedtls_psa_pake_input(awrtc_mbedtls_psa_pake_operation_t *operation,
                                    awrtc_psa_crypto_driver_pake_step_t step,
                                    const uint8_t *input,
                                    size_t input_length)
{
    awrtc_psa_status_t status = awrtc_mbedtls_psa_pake_input_internal(
        operation, step, input, input_length);

    return status;
}

awrtc_psa_status_t awrtc_mbedtls_psa_pake_get_implicit_key(
    awrtc_mbedtls_psa_pake_operation_t *operation,
    uint8_t *output, size_t output_size,
    size_t *output_length)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
    if (operation->alg == AWRTC_PSA_ALG_JPAKE) {
        ret = awrtc_mbedtls_ecjpake_write_shared_key(&operation->ctx.jpake,
                                               output,
                                               output_size,
                                               output_length,
                                               awrtc_mbedtls_psa_get_random,
                                               AWRTC_MBEDTLS_PSA_RANDOM_STATE);
        if (ret != 0) {
            return awrtc_mbedtls_ecjpake_to_psa_error(ret);
        }

        return AWRTC_PSA_SUCCESS;
    } else
#else
    (void) output;
#endif
    { return AWRTC_PSA_ERROR_NOT_SUPPORTED; }
}

awrtc_psa_status_t awrtc_mbedtls_psa_pake_abort(awrtc_mbedtls_psa_pake_operation_t *operation)
{
    awrtc_mbedtls_zeroize_and_free(operation->password, operation->password_len);
    operation->password = NULL;
    operation->password_len = 0;

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
    if (operation->alg == AWRTC_PSA_ALG_JPAKE) {
        operation->role = AWRTC_MBEDTLS_ECJPAKE_NONE;
        awrtc_mbedtls_platform_zeroize(operation->buffer, sizeof(operation->buffer));
        operation->buffer_length = 0;
        operation->buffer_offset = 0;
        awrtc_mbedtls_ecjpake_free(&operation->ctx.jpake);
    }
#endif

    operation->alg = AWRTC_PSA_ALG_NONE;

    return AWRTC_PSA_SUCCESS;
}

#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_PAKE */

#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_C */
