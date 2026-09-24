/*
 *  PSA ECP layer on top of Mbed TLS crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)

#include "../include/psa/crypto.h"
#include "psa_crypto_core.h"
#include "psa_crypto_ecp.h"
#include "psa_crypto_random_impl.h"
#include "../include/mbedtls/psa_util.h"

#include <stdlib.h>
#include <string.h>
#include "../include/mbedtls/platform.h"

#include "../include/mbedtls/ecdsa.h"
#include "../include/mbedtls/ecdh.h"
#include "../include/mbedtls/ecp.h"
#include "../include/mbedtls/error.h"

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_BASIC) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_IMPORT) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_EXPORT) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_ECDH)
/* Helper function to verify if the provided EC's family and key bit size are valid.
 *
 * Note: "bits" parameter is used both as input and output and it might be updated
 *       in case provided input value is not multiple of 8 ("sloppy" bits).
 */
static int check_ecc_parameters(awrtc_psa_ecc_family_t family, size_t *bits)
{
    switch (family) {
        case AWRTC_PSA_ECC_FAMILY_SECP_R1:
            switch (*bits) {
                case 192:
                case 224:
                case 256:
                case 384:
                case 521:
                    return AWRTC_PSA_SUCCESS;
                case 528:
                    *bits = 521;
                    return AWRTC_PSA_SUCCESS;
            }
            break;

        case AWRTC_PSA_ECC_FAMILY_BRAINPOOL_P_R1:
            switch (*bits) {
                case 256:
                case 384:
                case 512:
                    return AWRTC_PSA_SUCCESS;
            }
            break;

        case AWRTC_PSA_ECC_FAMILY_MONTGOMERY:
            switch (*bits) {
                case 448:
                case 255:
                    return AWRTC_PSA_SUCCESS;
                case 256:
                    *bits = 255;
                    return AWRTC_PSA_SUCCESS;
            }
            break;

        case AWRTC_PSA_ECC_FAMILY_SECP_K1:
            switch (*bits) {
                case 192:
                /* secp224k1 is not and will not be supported in PSA (#3541). */
                case 256:
                    return AWRTC_PSA_SUCCESS;
            }
            break;
    }

    return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
}

awrtc_psa_status_t awrtc_mbedtls_psa_ecp_load_representation(
    awrtc_psa_key_type_t type, size_t curve_bits,
    const uint8_t *data, size_t data_length,
    awrtc_mbedtls_ecp_keypair **p_ecp)
{
    awrtc_mbedtls_ecp_group_id grp_id = AWRTC_MBEDTLS_ECP_DP_NONE;
    awrtc_psa_status_t status;
    awrtc_mbedtls_ecp_keypair *ecp = NULL;
    size_t curve_bytes = data_length;
    int explicit_bits = (curve_bits != 0);

    if (AWRTC_PSA_KEY_TYPE_IS_PUBLIC_KEY(type) &&
        AWRTC_PSA_KEY_TYPE_ECC_GET_FAMILY(type) != AWRTC_PSA_ECC_FAMILY_MONTGOMERY) {
        /* A Weierstrass public key is represented as:
         * - The byte 0x04;
         * - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
         * - `y_P` as a `ceiling(m/8)`-byte string, big-endian.
         * So its data length is 2m+1 where m is the curve size in bits.
         */
        if ((data_length & 1) == 0) {
            return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
        }
        curve_bytes = data_length / 2;

        /* Montgomery public keys are represented in compressed format, meaning
         * their curve_bytes is equal to the amount of input. */

        /* Private keys are represented in uncompressed private random integer
         * format, meaning their curve_bytes is equal to the amount of input. */
    }

    if (explicit_bits) {
        /* With an explicit bit-size, the data must have the matching length. */
        if (curve_bytes != AWRTC_PSA_BITS_TO_BYTES(curve_bits)) {
            return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
        }
    } else {
        /* We need to infer the bit-size from the data. Since the only
         * information we have is the length in bytes, the value of curve_bits
         * at this stage is rounded up to the nearest multiple of 8. */
        curve_bits = AWRTC_PSA_BYTES_TO_BITS(curve_bytes);
    }

    /* Allocate and initialize a key representation. */
    ecp = awrtc_mbedtls_calloc(1, sizeof(awrtc_mbedtls_ecp_keypair));
    if (ecp == NULL) {
        return AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    awrtc_mbedtls_ecp_keypair_init(ecp);

    status = check_ecc_parameters(AWRTC_PSA_KEY_TYPE_ECC_GET_FAMILY(type), &curve_bits);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    /* Load the group. */
    grp_id = awrtc_mbedtls_ecc_group_from_psa(AWRTC_PSA_KEY_TYPE_ECC_GET_FAMILY(type),
                                        curve_bits);
    if (grp_id == AWRTC_MBEDTLS_ECP_DP_NONE) {
        status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }

    status = awrtc_mbedtls_to_psa_error(
        awrtc_mbedtls_ecp_group_load(&ecp->grp, grp_id));
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    /* Load the key material. */
    if (AWRTC_PSA_KEY_TYPE_IS_PUBLIC_KEY(type)) {
        /* Load the public value. */
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_ecp_point_read_binary(&ecp->grp, &ecp->Q,
                                          data,
                                          data_length));
        if (status != AWRTC_PSA_SUCCESS) {
            goto exit;
        }

        /* Check that the point is on the curve. */
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_ecp_check_pubkey(&ecp->grp, &ecp->Q));
        if (status != AWRTC_PSA_SUCCESS) {
            goto exit;
        }
    } else {
        /* Load and validate the secret value. */
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_ecp_read_key(ecp->grp.id,
                                 ecp,
                                 data,
                                 data_length));
        if (status != AWRTC_PSA_SUCCESS) {
            goto exit;
        }
    }

    *p_ecp = ecp;
exit:
    if (status != AWRTC_PSA_SUCCESS) {
        awrtc_mbedtls_ecp_keypair_free(ecp);
        awrtc_mbedtls_free(ecp);
    }

    return status;
}
#endif /* defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_BASIC) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_IMPORT) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_EXPORT) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_ECDH) */

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_IMPORT) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_EXPORT) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY)

awrtc_psa_status_t awrtc_mbedtls_psa_ecp_import_key(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits)
{
    awrtc_psa_status_t status;
    awrtc_mbedtls_ecp_keypair *ecp = NULL;

    /* Parse input */
    status = awrtc_mbedtls_psa_ecp_load_representation(attributes->type,
                                                 attributes->bits,
                                                 data,
                                                 data_length,
                                                 &ecp);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    if (AWRTC_PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->type) ==
        AWRTC_PSA_ECC_FAMILY_MONTGOMERY) {
        *bits = ecp->grp.nbits + 1;
    } else {
        *bits = ecp->grp.nbits;
    }

    /* Re-export the data to PSA export format. There is currently no support
     * for other input formats then the export format, so this is a 1-1
     * copy operation. */
    status = awrtc_mbedtls_psa_ecp_export_key(attributes->type,
                                        ecp,
                                        key_buffer,
                                        key_buffer_size,
                                        key_buffer_length);
exit:
    /* Always free the PK object (will also free contained ECP context) */
    awrtc_mbedtls_ecp_keypair_free(ecp);
    awrtc_mbedtls_free(ecp);

    return status;
}

awrtc_psa_status_t awrtc_mbedtls_psa_ecp_export_key(awrtc_psa_key_type_t type,
                                        awrtc_mbedtls_ecp_keypair *ecp,
                                        uint8_t *data,
                                        size_t data_size,
                                        size_t *data_length)
{
    awrtc_psa_status_t status;

    if (AWRTC_PSA_KEY_TYPE_IS_PUBLIC_KEY(type)) {
        /* Check whether the public part is loaded */
        if (awrtc_mbedtls_ecp_is_zero(&ecp->Q)) {
            /* Calculate the public key */
            status = awrtc_mbedtls_to_psa_error(
                awrtc_mbedtls_ecp_mul(&ecp->grp, &ecp->Q, &ecp->d, &ecp->grp.G,
                                awrtc_mbedtls_psa_get_random,
                                AWRTC_MBEDTLS_PSA_RANDOM_STATE));
            if (status != AWRTC_PSA_SUCCESS) {
                return status;
            }
        }

        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_ecp_point_write_binary(&ecp->grp, &ecp->Q,
                                           AWRTC_MBEDTLS_ECP_PF_UNCOMPRESSED,
                                           data_length,
                                           data,
                                           data_size));
        if (status != AWRTC_PSA_SUCCESS) {
            memset(data, 0, data_size);
        }

        return status;
    } else {
        status = awrtc_mbedtls_to_psa_error(
            awrtc_mbedtls_ecp_write_key_ext(ecp, data_length, data, data_size));
        return status;
    }
}

awrtc_psa_status_t awrtc_mbedtls_psa_ecp_export_public_key(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ecp_keypair *ecp = NULL;

    status = awrtc_mbedtls_psa_ecp_load_representation(
        attributes->type, attributes->bits,
        key_buffer, key_buffer_size, &ecp);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    status = awrtc_mbedtls_psa_ecp_export_key(
        AWRTC_PSA_KEY_TYPE_ECC_PUBLIC_KEY(
            AWRTC_PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->type)),
        ecp, data, data_size, data_length);

    awrtc_mbedtls_ecp_keypair_free(ecp);
    awrtc_mbedtls_free(ecp);

    return status;
}
#endif /* defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_IMPORT) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_EXPORT) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) */

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
awrtc_psa_status_t awrtc_mbedtls_psa_ecp_generate_key(
    const awrtc_psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    awrtc_psa_ecc_family_t curve = AWRTC_PSA_KEY_TYPE_ECC_GET_FAMILY(
        attributes->type);
    awrtc_mbedtls_ecp_group_id grp_id =
        awrtc_mbedtls_ecc_group_from_psa(curve, attributes->bits);
    if (grp_id == AWRTC_MBEDTLS_ECP_DP_NONE) {
        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    awrtc_mbedtls_ecp_keypair ecp;
    awrtc_mbedtls_ecp_keypair_init(&ecp);
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = awrtc_mbedtls_ecp_group_load(&ecp.grp, grp_id);
    if (ret != 0) {
        goto exit;
    }

    ret = awrtc_mbedtls_ecp_gen_privkey(&ecp.grp, &ecp.d,
                                  awrtc_mbedtls_psa_get_random,
                                  AWRTC_MBEDTLS_PSA_RANDOM_STATE);
    if (ret != 0) {
        goto exit;
    }

    ret = awrtc_mbedtls_ecp_write_key_ext(&ecp, key_buffer_length,
                                    key_buffer, key_buffer_size);

exit:
    awrtc_mbedtls_ecp_keypair_free(&ecp);
    return awrtc_mbedtls_to_psa_error(ret);
}
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_GENERATE */

/****************************************************************/
/* ECDSA sign/verify */
/****************************************************************/

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
awrtc_psa_status_t awrtc_mbedtls_psa_ecdsa_sign_hash(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    awrtc_psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ecp_keypair *ecp = NULL;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t curve_bytes;
    awrtc_mbedtls_mpi r, s;

    status = awrtc_mbedtls_psa_ecp_load_representation(attributes->type,
                                                 attributes->bits,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 &ecp);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    curve_bytes = AWRTC_PSA_BITS_TO_BYTES(ecp->grp.pbits);
    awrtc_mbedtls_mpi_init(&r);
    awrtc_mbedtls_mpi_init(&s);

    if (signature_size < 2 * curve_bytes) {
        ret = AWRTC_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    if (AWRTC_PSA_ALG_ECDSA_IS_DETERMINISTIC(alg)) {
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
        awrtc_psa_algorithm_t hash_alg = AWRTC_PSA_ALG_SIGN_GET_HASH(alg);
        awrtc_mbedtls_md_type_t md_alg = awrtc_mbedtls_md_type_from_psa_alg(hash_alg);
        AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_ecdsa_sign_det_ext(
                            &ecp->grp, &r, &s,
                            &ecp->d, hash,
                            hash_length, md_alg,
                            awrtc_mbedtls_psa_get_random,
                            AWRTC_MBEDTLS_PSA_RANDOM_STATE));
#else
        ret = AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        goto cleanup;
#endif /* defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) */
    } else {
        (void) alg;
        AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_ecdsa_sign(&ecp->grp, &r, &s, &ecp->d,
                                           hash, hash_length,
                                           awrtc_mbedtls_psa_get_random,
                                           AWRTC_MBEDTLS_PSA_RANDOM_STATE));
    }

    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_write_binary(&r,
                                             signature,
                                             curve_bytes));
    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_write_binary(&s,
                                             signature + curve_bytes,
                                             curve_bytes));
cleanup:
    awrtc_mbedtls_mpi_free(&r);
    awrtc_mbedtls_mpi_free(&s);
    if (ret == 0) {
        *signature_length = 2 * curve_bytes;
    }

    awrtc_mbedtls_ecp_keypair_free(ecp);
    awrtc_mbedtls_free(ecp);

    return awrtc_mbedtls_to_psa_error(ret);
}

awrtc_psa_status_t awrtc_mbedtls_psa_ecp_load_public_part(awrtc_mbedtls_ecp_keypair *ecp)
{
    int ret = 0;

    /* Check whether the public part is loaded. If not, load it. */
    if (awrtc_mbedtls_ecp_is_zero(&ecp->Q)) {
        ret = awrtc_mbedtls_ecp_mul(&ecp->grp, &ecp->Q,
                              &ecp->d, &ecp->grp.G,
                              awrtc_mbedtls_psa_get_random,
                              AWRTC_MBEDTLS_PSA_RANDOM_STATE);
    }

    return awrtc_mbedtls_to_psa_error(ret);
}

awrtc_psa_status_t awrtc_mbedtls_psa_ecdsa_verify_hash(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    awrtc_psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ecp_keypair *ecp = NULL;
    size_t curve_bytes;
    awrtc_mbedtls_mpi r, s;

    (void) alg;

    status = awrtc_mbedtls_psa_ecp_load_representation(attributes->type,
                                                 attributes->bits,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 &ecp);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    curve_bytes = AWRTC_PSA_BITS_TO_BYTES(ecp->grp.pbits);
    awrtc_mbedtls_mpi_init(&r);
    awrtc_mbedtls_mpi_init(&s);

    if (signature_length != 2 * curve_bytes) {
        status = AWRTC_PSA_ERROR_INVALID_SIGNATURE;
        goto cleanup;
    }

    status = awrtc_mbedtls_to_psa_error(awrtc_mbedtls_mpi_read_binary(&r,
                                                          signature,
                                                          curve_bytes));
    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

    status = awrtc_mbedtls_to_psa_error(awrtc_mbedtls_mpi_read_binary(&s,
                                                          signature + curve_bytes,
                                                          curve_bytes));
    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

    status = awrtc_mbedtls_psa_ecp_load_public_part(ecp);
    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

    status = awrtc_mbedtls_to_psa_error(awrtc_mbedtls_ecdsa_verify(&ecp->grp, hash,
                                                       hash_length, &ecp->Q,
                                                       &r, &s));
cleanup:
    awrtc_mbedtls_mpi_free(&r);
    awrtc_mbedtls_mpi_free(&s);
    awrtc_mbedtls_ecp_keypair_free(ecp);
    awrtc_mbedtls_free(ecp);

    return status;
}

#endif /* defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) */

/****************************************************************/
/* ECDH Key Agreement */
/****************************************************************/

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_ECDH)
awrtc_psa_status_t awrtc_mbedtls_psa_key_agreement_ecdh(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    awrtc_psa_algorithm_t alg, const uint8_t *peer_key, size_t peer_key_length,
    uint8_t *shared_secret, size_t shared_secret_size,
    size_t *shared_secret_length)
{
    awrtc_psa_status_t status;
    if (!AWRTC_PSA_KEY_TYPE_IS_ECC_KEY_PAIR(attributes->type) ||
        !AWRTC_PSA_ALG_IS_ECDH(alg)) {
        return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
    }
    awrtc_mbedtls_ecp_keypair *ecp = NULL;
    status = awrtc_mbedtls_psa_ecp_load_representation(
        attributes->type,
        attributes->bits,
        key_buffer,
        key_buffer_size,
        &ecp);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }
    awrtc_mbedtls_ecp_keypair *their_key = NULL;
    awrtc_mbedtls_ecdh_context ecdh;
    size_t bits = 0;
    awrtc_psa_ecc_family_t curve = awrtc_mbedtls_ecc_group_to_psa(ecp->grp.id, &bits);
    awrtc_mbedtls_ecdh_init(&ecdh);

    status = awrtc_mbedtls_psa_ecp_load_representation(
        AWRTC_PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve),
        bits,
        peer_key,
        peer_key_length,
        &their_key);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    status = awrtc_mbedtls_to_psa_error(
        awrtc_mbedtls_ecdh_get_params(&ecdh, their_key, AWRTC_MBEDTLS_ECDH_THEIRS));
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }
    status = awrtc_mbedtls_to_psa_error(
        awrtc_mbedtls_ecdh_get_params(&ecdh, ecp, AWRTC_MBEDTLS_ECDH_OURS));
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    status = awrtc_mbedtls_to_psa_error(
        awrtc_mbedtls_ecdh_calc_secret(&ecdh,
                                 shared_secret_length,
                                 shared_secret, shared_secret_size,
                                 awrtc_mbedtls_psa_get_random,
                                 AWRTC_MBEDTLS_PSA_RANDOM_STATE));
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }
    if (AWRTC_PSA_BITS_TO_BYTES(bits) != *shared_secret_length) {
        status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    }
exit:
    if (status != AWRTC_PSA_SUCCESS) {
        awrtc_mbedtls_platform_zeroize(shared_secret, shared_secret_size);
    }
    awrtc_mbedtls_ecdh_free(&ecdh);
    awrtc_mbedtls_ecp_keypair_free(their_key);
    awrtc_mbedtls_free(their_key);
    awrtc_mbedtls_ecp_keypair_free(ecp);
    awrtc_mbedtls_free(ecp);
    return status;
}
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_ECDH */


#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_C */
