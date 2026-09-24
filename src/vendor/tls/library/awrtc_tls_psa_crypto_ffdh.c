/*
 *  PSA FFDH layer on top of Mbed TLS crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)

/* This header is only needed because it defines
 * AWRTC_MBEDTLS_DHM_RFC7919_FFDHEXXXX_[P|G]_BIN symbols that are used in
 * awrtc_mbedtls_psa_ffdh_set_prime_generator(). Apart from that, this module
 * only uses bignum functions for arithmetic. */
#include "../include/mbedtls/dhm.h"

#include "../include/psa/crypto.h"
#include "psa_crypto_core.h"
#include "psa_crypto_ffdh.h"
#include "psa_crypto_random_impl.h"
#include "../include/mbedtls/platform.h"
#include "../include/mbedtls/error.h"

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_EXPORT) ||   \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_GENERATE) ||   \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_FFDH)
static awrtc_psa_status_t awrtc_mbedtls_psa_ffdh_set_prime_generator(size_t key_size,
                                                         awrtc_mbedtls_mpi *P,
                                                         awrtc_mbedtls_mpi *G)
{
    const unsigned char *dhm_P = NULL;
    const unsigned char *dhm_G = NULL;
    size_t dhm_size_P = 0;
    size_t dhm_size_G = 0;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (P == NULL && G == NULL) {
        return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
    }

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_2048)
    static const unsigned char dhm_P_2048[] =
        AWRTC_MBEDTLS_DHM_RFC7919_FFDHE2048_P_BIN;
    static const unsigned char dhm_G_2048[] =
        AWRTC_MBEDTLS_DHM_RFC7919_FFDHE2048_G_BIN;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_2048 */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_3072)
    static const unsigned char dhm_P_3072[] =
        AWRTC_MBEDTLS_DHM_RFC7919_FFDHE3072_P_BIN;
    static const unsigned char dhm_G_3072[] =
        AWRTC_MBEDTLS_DHM_RFC7919_FFDHE3072_G_BIN;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_3072 */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_4096)
    static const unsigned char dhm_P_4096[] =
        AWRTC_MBEDTLS_DHM_RFC7919_FFDHE4096_P_BIN;
    static const unsigned char dhm_G_4096[] =
        AWRTC_MBEDTLS_DHM_RFC7919_FFDHE4096_G_BIN;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_4096 */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_6144)
    static const unsigned char dhm_P_6144[] =
        AWRTC_MBEDTLS_DHM_RFC7919_FFDHE6144_P_BIN;
    static const unsigned char dhm_G_6144[] =
        AWRTC_MBEDTLS_DHM_RFC7919_FFDHE6144_G_BIN;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_6144 */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_8192)
    static const unsigned char dhm_P_8192[] =
        AWRTC_MBEDTLS_DHM_RFC7919_FFDHE8192_P_BIN;
    static const unsigned char dhm_G_8192[] =
        AWRTC_MBEDTLS_DHM_RFC7919_FFDHE8192_G_BIN;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_8192 */

    switch (key_size) {
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_2048)
        case sizeof(dhm_P_2048):
            dhm_P = dhm_P_2048;
            dhm_G = dhm_G_2048;
            dhm_size_P = sizeof(dhm_P_2048);
            dhm_size_G = sizeof(dhm_G_2048);
            break;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_2048 */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_3072)
        case sizeof(dhm_P_3072):
            dhm_P = dhm_P_3072;
            dhm_G = dhm_G_3072;
            dhm_size_P = sizeof(dhm_P_3072);
            dhm_size_G = sizeof(dhm_G_3072);
            break;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_3072 */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_4096)
        case sizeof(dhm_P_4096):
            dhm_P = dhm_P_4096;
            dhm_G = dhm_G_4096;
            dhm_size_P = sizeof(dhm_P_4096);
            dhm_size_G = sizeof(dhm_G_4096);
            break;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_4096 */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_6144)
        case sizeof(dhm_P_6144):
            dhm_P = dhm_P_6144;
            dhm_G = dhm_G_6144;
            dhm_size_P = sizeof(dhm_P_6144);
            dhm_size_G = sizeof(dhm_G_6144);
            break;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_6144 */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_8192)
        case sizeof(dhm_P_8192):
            dhm_P = dhm_P_8192;
            dhm_G = dhm_G_8192;
            dhm_size_P = sizeof(dhm_P_8192);
            dhm_size_G = sizeof(dhm_G_8192);
            break;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_DH_RFC7919_8192 */
        default:
            return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
    }

    if (P != NULL) {
        AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_read_binary(P, dhm_P,
                                                dhm_size_P));
    }
    if (G != NULL) {
        AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_read_binary(G, dhm_G,
                                                dhm_size_G));
    }

cleanup:
    if (ret != 0) {
        return awrtc_mbedtls_to_psa_error(ret);
    }

    return AWRTC_PSA_SUCCESS;
}
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_EXPORT ||
          AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_GENERATE ||
          AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY ||
          AWRTC_MBEDTLS_PSA_BUILTIN_ALG_FFDH */

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_EXPORT) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY)
awrtc_psa_status_t awrtc_mbedtls_psa_ffdh_export_public_key(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_mpi GX, G, X, P;
    awrtc_psa_key_type_t type = attributes->type;

    if (AWRTC_PSA_KEY_TYPE_IS_PUBLIC_KEY(type)) {
        if (key_buffer_size > data_size) {
            return AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
        }
        memcpy(data, key_buffer, key_buffer_size);
        memset(data + key_buffer_size, 0,
               data_size - key_buffer_size);
        *data_length = key_buffer_size;
        return AWRTC_PSA_SUCCESS;
    }

    awrtc_mbedtls_mpi_init(&GX); awrtc_mbedtls_mpi_init(&G);
    awrtc_mbedtls_mpi_init(&X); awrtc_mbedtls_mpi_init(&P);

    size_t key_len = AWRTC_PSA_BITS_TO_BYTES(attributes->bits);
    if (key_len > data_size) {
        status = AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    status = awrtc_mbedtls_psa_ffdh_set_prime_generator(key_len, &P, &G);

    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_read_binary(&X, key_buffer,
                                            key_buffer_size));

    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_exp_mod(&GX, &G, &X, &P, NULL));
    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_write_binary(&GX, data, key_len));

    *data_length = key_len;

    ret = 0;
cleanup:
    awrtc_mbedtls_mpi_free(&P); awrtc_mbedtls_mpi_free(&G);
    awrtc_mbedtls_mpi_free(&X); awrtc_mbedtls_mpi_free(&GX);

    if (status == AWRTC_PSA_SUCCESS && ret != 0) {
        status = awrtc_mbedtls_to_psa_error(ret);
    }

    return status;
}
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_EXPORT ||
          AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY */

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_GENERATE)
awrtc_psa_status_t awrtc_mbedtls_psa_ffdh_generate_key(
    const awrtc_psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    awrtc_mbedtls_mpi X, P;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_mpi_init(&P); awrtc_mbedtls_mpi_init(&X);
    (void) attributes;

    status = awrtc_mbedtls_psa_ffdh_set_prime_generator(key_buffer_size, &P, NULL);

    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

    /* RFC7919: Traditional finite field Diffie-Hellman has each peer choose their
        secret exponent from the range [2, P-2].
        Select random value in range [3, P-1] and decrease it by 1. */
    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_random(&X, 3, &P, awrtc_mbedtls_psa_get_random,
                                       AWRTC_MBEDTLS_PSA_RANDOM_STATE));
    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_sub_int(&X, &X, 1));
    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_write_binary(&X, key_buffer, key_buffer_size));
    *key_buffer_length = key_buffer_size;

cleanup:
    awrtc_mbedtls_mpi_free(&P); awrtc_mbedtls_mpi_free(&X);
    if (status == AWRTC_PSA_SUCCESS && ret != 0) {
        return awrtc_mbedtls_to_psa_error(ret);
    }

    return status;
}
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_GENERATE */

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_IMPORT)
awrtc_psa_status_t awrtc_mbedtls_psa_ffdh_import_key(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits)
{
    (void) attributes;

    if (key_buffer_size < data_length) {
        return AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(key_buffer, data, data_length);
    *key_buffer_length = data_length;
    *bits = AWRTC_PSA_BYTES_TO_BITS(data_length);

    return AWRTC_PSA_SUCCESS;
}
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_IMPORT */

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_FFDH)
awrtc_psa_status_t awrtc_mbedtls_psa_ffdh_key_agreement(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *peer_key,
    size_t peer_key_length,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_mpi P, X, GY, K;
    const size_t calculated_shared_secret_size = key_buffer_size;

    if (!AWRTC_PSA_KEY_TYPE_IS_DH_KEY_PAIR(awrtc_psa_get_key_type(attributes))) {
        return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
    }

    if (peer_key_length != key_buffer_size) {
        return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
    }

    /* This has been checked by the core, but keep a local check too. */
    if (calculated_shared_secret_size > shared_secret_size) {
        return AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
    }

    awrtc_mbedtls_mpi_init(&P);
    awrtc_mbedtls_mpi_init(&X); awrtc_mbedtls_mpi_init(&GY);
    awrtc_mbedtls_mpi_init(&K);

    status = awrtc_mbedtls_psa_ffdh_set_prime_generator(
        AWRTC_PSA_BITS_TO_BYTES(attributes->bits), &P, NULL);

    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_read_binary(&GY, peer_key,
                                            peer_key_length));

    /* RFC 7919 5.1: validate the peer's public key: 1 < GY < P-1
     *
     * This check is sufficient to ensure GY is not of low order, because we're
     * using a safe prime (that is, q = (p-1) / 2 is also prime), so the only
     * group elements of low order are 1 and p-1. (Obviously we also want to
     * exclude 0 that is not a group element, and values >= p as they are not
     * residues mod p.)
     *
     * Note: we know we're using a safe prime because the only FFDH groups
     * defined by the PSA spec are from RFC 7919 (since version 1.0) and RFC
     * 3525 (since v1.4, not yet supported in tf-psa-crypto as of writing this
     * comment), which both use safe primes.
     *
     * Note: NIST SP 800-56Ar3 5.7.1.1 (2) has the check on the shared secret,
     * but checking before is equivalent (unless our secret key is exactly
     * (p-1)/2, which has negligible probability and can't be influenced by the
     * adversary). Checking before is cleaner in terms of side channel analysis,
     * as we haven't loaded our secret yet, so no worries about branches.
     *
     * Use X as a temporary, since we haven't loaded it yet.
     */
    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_sub_int(&X, &P, 1)); // x = p - 1
    if (awrtc_mbedtls_mpi_cmp_mpi(&GY, &X) >= 0) {
        status = AWRTC_PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }
    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_lset(&X, 1)); // x = 1
    if (awrtc_mbedtls_mpi_cmp_mpi(&GY, &X) <= 0) {
        status = AWRTC_PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_read_binary(&X, key_buffer,
                                            key_buffer_size));

    /* Calculate shared secret public key: K = G^(XY) mod P = GY^X mod P */
    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_exp_mod(&K, &GY, &X, &P, NULL));

    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_write_binary(&K, shared_secret,
                                             calculated_shared_secret_size));

    *shared_secret_length = calculated_shared_secret_size;

    ret = 0;

cleanup:
    awrtc_mbedtls_mpi_free(&P);
    awrtc_mbedtls_mpi_free(&X); awrtc_mbedtls_mpi_free(&GY);
    awrtc_mbedtls_mpi_free(&K);

    if (status == AWRTC_PSA_SUCCESS && ret != 0) {
        status = awrtc_mbedtls_to_psa_error(ret);
    }

    return status;
}
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_FFDH */

#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_C */
