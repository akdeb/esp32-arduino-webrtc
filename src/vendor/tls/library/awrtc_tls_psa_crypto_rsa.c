/*
 *  PSA RSA layer on top of Mbed TLS crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)

#include "../include/psa/crypto.h"
#include "../include/psa/crypto_values.h"
#include "psa_crypto_core.h"
#include "psa_crypto_random_impl.h"
#include "psa_crypto_rsa.h"
#include "psa_crypto_hash.h"
#include "../include/mbedtls/psa_util.h"

#include <stdlib.h>
#include <string.h>
#include "../include/mbedtls/platform.h"

#include "../include/mbedtls/rsa.h"
#include "../include/mbedtls/error.h"
#include "rsa_internal.h"

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_IMPORT) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_EXPORT) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY)

/* Mbed TLS doesn't support non-byte-aligned key sizes (i.e. key sizes
 * that are not a multiple of 8) well. For example, there is only
 * awrtc_mbedtls_rsa_get_len(), which returns a number of bytes, and no
 * way to return the exact bit size of a key.
 * To keep things simple, reject non-byte-aligned key sizes. */
static awrtc_psa_status_t awrtc_psa_check_rsa_key_byte_aligned(
    const awrtc_mbedtls_rsa_context *rsa)
{
    awrtc_mbedtls_mpi n;
    awrtc_psa_status_t status;
    awrtc_mbedtls_mpi_init(&n);
    status = awrtc_mbedtls_to_psa_error(
        awrtc_mbedtls_rsa_export(rsa, &n, NULL, NULL, NULL, NULL));
    if (status == AWRTC_PSA_SUCCESS) {
        if (awrtc_mbedtls_mpi_bitlen(&n) % 8 != 0) {
            status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
        }
    }
    awrtc_mbedtls_mpi_free(&n);
    return status;
}

awrtc_psa_status_t awrtc_mbedtls_psa_rsa_load_representation(
    awrtc_psa_key_type_t type, const uint8_t *data, size_t data_length,
    awrtc_mbedtls_rsa_context **p_rsa)
{
    awrtc_psa_status_t status;
    size_t bits;

    *p_rsa = awrtc_mbedtls_calloc(1, sizeof(awrtc_mbedtls_rsa_context));
    if (*p_rsa == NULL) {
        return AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    awrtc_mbedtls_rsa_init(*p_rsa);

    /* Parse the data. */
    if (AWRTC_PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
        status = awrtc_mbedtls_to_psa_error(awrtc_mbedtls_rsa_parse_key(*p_rsa, data, data_length));
    } else {
        status = awrtc_mbedtls_to_psa_error(awrtc_mbedtls_rsa_parse_pubkey(*p_rsa, data, data_length));
    }
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    /* The size of an RSA key doesn't have to be a multiple of 8. Mbed TLS
     * supports non-byte-aligned key sizes, but not well. For example,
     * awrtc_mbedtls_rsa_get_len() returns the key size in bytes, not in bits. */
    bits = AWRTC_PSA_BYTES_TO_BITS(awrtc_mbedtls_rsa_get_len(*p_rsa));
    if (bits > AWRTC_PSA_VENDOR_RSA_MAX_KEY_BITS) {
        status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
    status = awrtc_psa_check_rsa_key_byte_aligned(*p_rsa);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

exit:
    return status;
}
#endif /* defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_IMPORT) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_EXPORT) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY) */

#if (defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_IMPORT) && \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_EXPORT)) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY)
awrtc_psa_status_t awrtc_mbedtls_psa_rsa_import_key(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits)
{
    awrtc_psa_status_t status;
    awrtc_mbedtls_rsa_context *rsa = NULL;

    /* Parse input */
    status = awrtc_mbedtls_psa_rsa_load_representation(attributes->type,
                                                 data,
                                                 data_length,
                                                 &rsa);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    *bits = (awrtc_psa_key_bits_t) AWRTC_PSA_BYTES_TO_BITS(awrtc_mbedtls_rsa_get_len(rsa));

    /* Re-export the data to PSA export format, such that we can store export
     * representation in the key slot. Export representation in case of RSA is
     * the smallest representation that's allowed as input, so a straight-up
     * allocation of the same size as the input buffer will be large enough. */
    status = awrtc_mbedtls_psa_rsa_export_key(attributes->type,
                                        rsa,
                                        key_buffer,
                                        key_buffer_size,
                                        key_buffer_length);
exit:
    /* Always free the RSA object */
    awrtc_mbedtls_rsa_free(rsa);
    awrtc_mbedtls_free(rsa);

    return status;
}
#endif /* (defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_IMPORT) &&
        *  defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_EXPORT)) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY) */

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_EXPORT) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY)
awrtc_psa_status_t awrtc_mbedtls_psa_rsa_export_key(awrtc_psa_key_type_t type,
                                        awrtc_mbedtls_rsa_context *rsa,
                                        uint8_t *data,
                                        size_t data_size,
                                        size_t *data_length)
{
    int ret;
    uint8_t *end = data + data_size;

    /* PSA Crypto API defines the format of an RSA key as a DER-encoded
     * representation of the non-encrypted PKCS#1 RSAPrivateKey for a
     * private key and of the RFC3279 RSAPublicKey for a public key. */
    if (AWRTC_PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
        ret = awrtc_mbedtls_rsa_write_key(rsa, data, &end);
    } else {
        ret = awrtc_mbedtls_rsa_write_pubkey(rsa, data, &end);
    }

    if (ret < 0) {
        /* Clean up in case pk_write failed halfway through. */
        memset(data, 0, data_size);
        return awrtc_mbedtls_to_psa_error(ret);
    }

    /* The awrtc_mbedtls_pk_xxx functions write to the end of the buffer.
     * Move the data to the beginning and erase remaining data
     * at the original location. */
    if (2 * (size_t) ret <= data_size) {
        memcpy(data, data + data_size - ret, ret);
        memset(data + data_size - ret, 0, ret);
    } else if ((size_t) ret < data_size) {
        memmove(data, data + data_size - ret, ret);
        memset(data + ret, 0, data_size - ret);
    }

    *data_length = ret;
    return AWRTC_PSA_SUCCESS;
}

awrtc_psa_status_t awrtc_mbedtls_psa_rsa_export_public_key(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_rsa_context *rsa = NULL;

    status = awrtc_mbedtls_psa_rsa_load_representation(
        attributes->type, key_buffer, key_buffer_size, &rsa);
    if (status == AWRTC_PSA_SUCCESS) {
        status = awrtc_mbedtls_psa_rsa_export_key(AWRTC_PSA_KEY_TYPE_RSA_PUBLIC_KEY,
                                            rsa,
                                            data,
                                            data_size,
                                            data_length);
    }

    awrtc_mbedtls_rsa_free(rsa);
    awrtc_mbedtls_free(rsa);

    return status;
}
#endif /* defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_EXPORT) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY) */

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_GENERATE)
static awrtc_psa_status_t awrtc_psa_rsa_read_exponent(const uint8_t *e_bytes,
                                          size_t e_length,
                                          int *exponent)
{
    size_t i;
    uint32_t acc = 0;

    /* Mbed TLS encodes the public exponent as an int. For simplicity, only
     * support values that fit in a 32-bit integer, which is larger than
     * int on just about every platform anyway. */
    if (e_length > sizeof(acc)) {
        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }
    for (i = 0; i < e_length; i++) {
        acc = (acc << 8) | e_bytes[i];
    }
    if (acc > INT_MAX) {
        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }
    *exponent = acc;
    return AWRTC_PSA_SUCCESS;
}

awrtc_psa_status_t awrtc_mbedtls_psa_rsa_generate_key(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *custom_data, size_t custom_data_length,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    awrtc_psa_status_t status;
    awrtc_mbedtls_rsa_context rsa;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int exponent = 65537;

    if (custom_data_length != 0) {
        status = awrtc_psa_rsa_read_exponent(custom_data, custom_data_length,
                                       &exponent);
        if (status != AWRTC_PSA_SUCCESS) {
            return status;
        }
    }

    awrtc_mbedtls_rsa_init(&rsa);
    ret = awrtc_mbedtls_rsa_gen_key(&rsa,
                              awrtc_mbedtls_psa_get_random,
                              AWRTC_MBEDTLS_PSA_RANDOM_STATE,
                              (unsigned int) attributes->bits,
                              exponent);
    if (ret != 0) {
        awrtc_mbedtls_rsa_free(&rsa);
        return awrtc_mbedtls_to_psa_error(ret);
    }

    status = awrtc_mbedtls_psa_rsa_export_key(attributes->type,
                                        &rsa, key_buffer, key_buffer_size,
                                        key_buffer_length);
    awrtc_mbedtls_rsa_free(&rsa);

    return status;
}
#endif /* defined(AWRTC_MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_GENERATE) */

/****************************************************************/
/* Sign/verify hashes */
/****************************************************************/

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
    defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS)

/* Decode the hash algorithm from alg and store the mbedtls encoding in
 * md_alg. Verify that the hash length is acceptable. */
static awrtc_psa_status_t awrtc_psa_rsa_decode_md_type(awrtc_psa_algorithm_t alg,
                                           size_t hash_length,
                                           awrtc_mbedtls_md_type_t *md_alg)
{
    awrtc_psa_algorithm_t hash_alg = AWRTC_PSA_ALG_SIGN_GET_HASH(alg);
    *md_alg = awrtc_mbedtls_md_type_from_psa_alg(hash_alg);

    /* The Mbed TLS RSA module uses an unsigned int for hash length
     * parameters. Validate that it fits so that we don't risk an
     * overflow later. */
#if SIZE_MAX > UINT_MAX
    if (hash_length > UINT_MAX) {
        return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
    }
#endif

    /* For signatures using a hash, the hash length must be correct. */
    if (alg != AWRTC_PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
        if (*md_alg == AWRTC_MBEDTLS_MD_NONE) {
            return AWRTC_PSA_ERROR_NOT_SUPPORTED;
        }
        if (awrtc_mbedtls_md_get_size_from_type(*md_alg) != hash_length) {
            return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    return AWRTC_PSA_SUCCESS;
}

awrtc_psa_status_t awrtc_mbedtls_psa_rsa_sign_hash(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    awrtc_psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_rsa_context *rsa = NULL;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_md_type_t md_alg;

    status = awrtc_mbedtls_psa_rsa_load_representation(attributes->type,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 &rsa);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    status = awrtc_psa_rsa_decode_md_type(alg, hash_length, &md_alg);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    if (signature_size < awrtc_mbedtls_rsa_get_len(rsa)) {
        status = AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN)
    if (AWRTC_PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
        ret = awrtc_mbedtls_rsa_set_padding(rsa, AWRTC_MBEDTLS_RSA_PKCS_V15,
                                      AWRTC_MBEDTLS_MD_NONE);
        if (ret == 0) {
            ret = awrtc_mbedtls_rsa_pkcs1_sign(rsa,
                                         awrtc_mbedtls_psa_get_random,
                                         AWRTC_MBEDTLS_PSA_RANDOM_STATE,
                                         md_alg,
                                         (unsigned int) hash_length,
                                         hash,
                                         signature);
        }
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS)
    if (AWRTC_PSA_ALG_IS_RSA_PSS(alg)) {
        ret = awrtc_mbedtls_rsa_set_padding(rsa, AWRTC_MBEDTLS_RSA_PKCS_V21, md_alg);

        if (ret == 0) {
            ret = awrtc_mbedtls_rsa_rsassa_pss_sign(rsa,
                                              awrtc_mbedtls_psa_get_random,
                                              AWRTC_MBEDTLS_PSA_RANDOM_STATE,
                                              AWRTC_MBEDTLS_MD_NONE,
                                              (unsigned int) hash_length,
                                              hash,
                                              signature);
        }
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS */
    {
        status = AWRTC_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if (ret == 0) {
        *signature_length = awrtc_mbedtls_rsa_get_len(rsa);
    }
    status = awrtc_mbedtls_to_psa_error(ret);

exit:
    awrtc_mbedtls_rsa_free(rsa);
    awrtc_mbedtls_free(rsa);

    return status;
}

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS)
static int rsa_pss_expected_salt_len(awrtc_psa_algorithm_t alg,
                                     const awrtc_mbedtls_rsa_context *rsa,
                                     size_t hash_length)
{
    if (AWRTC_PSA_ALG_IS_RSA_PSS_ANY_SALT(alg)) {
        return AWRTC_MBEDTLS_RSA_SALT_LEN_ANY;
    }
    /* Otherwise: standard salt length, i.e. largest possible salt length
     * up to the hash length. */
    int klen = (int) awrtc_mbedtls_rsa_get_len(rsa);   // known to fit
    int hlen = (int) hash_length; // known to fit
    int room = klen - 2 - hlen;
    if (room < 0) {
        return 0;  // there is no valid signature in this case anyway
    } else if (room > hlen) {
        return hlen;
    } else {
        return room;
    }
}
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS */

awrtc_psa_status_t awrtc_mbedtls_psa_rsa_verify_hash(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    awrtc_psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_rsa_context *rsa = NULL;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_md_type_t md_alg;

    status = awrtc_mbedtls_psa_rsa_load_representation(attributes->type,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 &rsa);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    status = awrtc_psa_rsa_decode_md_type(alg, hash_length, &md_alg);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    if (signature_length != awrtc_mbedtls_rsa_get_len(rsa)) {
        status = AWRTC_PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN)
    if (AWRTC_PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
        ret = awrtc_mbedtls_rsa_set_padding(rsa, AWRTC_MBEDTLS_RSA_PKCS_V15,
                                      AWRTC_MBEDTLS_MD_NONE);
        if (ret == 0) {
            ret = awrtc_mbedtls_rsa_pkcs1_verify(rsa,
                                           md_alg,
                                           (unsigned int) hash_length,
                                           hash,
                                           signature);
        }
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN */
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS)
    if (AWRTC_PSA_ALG_IS_RSA_PSS(alg)) {
        ret = awrtc_mbedtls_rsa_set_padding(rsa, AWRTC_MBEDTLS_RSA_PKCS_V21, md_alg);
        if (ret == 0) {
            int slen = rsa_pss_expected_salt_len(alg, rsa, hash_length);
            ret = awrtc_mbedtls_rsa_rsassa_pss_verify_ext(rsa,
                                                    md_alg,
                                                    (unsigned) hash_length,
                                                    hash,
                                                    md_alg,
                                                    slen,
                                                    signature);
        }
    } else
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS */
    {
        status = AWRTC_PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    /* Mbed TLS distinguishes "invalid padding" from "valid padding but
     * the rest of the signature is invalid". This has little use in
     * practice and PSA doesn't report this distinction. */
    status = (ret == AWRTC_MBEDTLS_ERR_RSA_INVALID_PADDING) ?
             AWRTC_PSA_ERROR_INVALID_SIGNATURE :
             awrtc_mbedtls_to_psa_error(ret);

exit:
    awrtc_mbedtls_rsa_free(rsa);
    awrtc_mbedtls_free(rsa);

    return status;
}

#endif /* defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS) */

/****************************************************************/
/* Asymmetric cryptography */
/****************************************************************/

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP)
static int awrtc_psa_rsa_oaep_set_padding_mode(awrtc_psa_algorithm_t alg,
                                         awrtc_mbedtls_rsa_context *rsa)
{
    awrtc_psa_algorithm_t hash_alg = AWRTC_PSA_ALG_RSA_OAEP_GET_HASH(alg);
    awrtc_mbedtls_md_type_t md_alg = awrtc_mbedtls_md_type_from_psa_alg(hash_alg);

    /* Just to get the error status right, as rsa_set_padding() doesn't
     * distinguish between "bad RSA algorithm" and "unknown hash". */
    if (awrtc_mbedtls_md_info_from_type(md_alg) == NULL) {
        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    return awrtc_mbedtls_rsa_set_padding(rsa, AWRTC_MBEDTLS_RSA_PKCS_V21, md_alg);
}
#endif /* defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP) */

awrtc_psa_status_t awrtc_mbedtls_psa_asymmetric_encrypt(const awrtc_psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            awrtc_psa_algorithm_t alg,
                                            const uint8_t *input,
                                            size_t input_length,
                                            const uint8_t *salt,
                                            size_t salt_length,
                                            uint8_t *output,
                                            size_t output_size,
                                            size_t *output_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) input;
    (void) input_length;
    (void) salt;
    (void) salt_length;
    (void) output;
    (void) output_size;
    (void) output_length;

    if (AWRTC_PSA_KEY_TYPE_IS_RSA(attributes->type)) {
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
        defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP)
        awrtc_mbedtls_rsa_context *rsa = NULL;
        status = awrtc_mbedtls_psa_rsa_load_representation(attributes->type,
                                                     key_buffer,
                                                     key_buffer_size,
                                                     &rsa);
        if (status != AWRTC_PSA_SUCCESS) {
            goto rsa_exit;
        }

        if (output_size < awrtc_mbedtls_rsa_get_len(rsa)) {
            status = AWRTC_PSA_ERROR_BUFFER_TOO_SMALL;
            goto rsa_exit;
        }
#endif /* defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP) */
        if (alg == AWRTC_PSA_ALG_RSA_PKCS1V15_CRYPT) {
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT)
            status = awrtc_mbedtls_to_psa_error(
                awrtc_mbedtls_rsa_pkcs1_encrypt(rsa,
                                          awrtc_mbedtls_psa_get_random,
                                          AWRTC_MBEDTLS_PSA_RANDOM_STATE,
                                          input_length,
                                          input,
                                          output));
#else
            status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT */
        } else
        if (AWRTC_PSA_ALG_IS_RSA_OAEP(alg)) {
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP)
            status = awrtc_mbedtls_to_psa_error(
                awrtc_psa_rsa_oaep_set_padding_mode(alg, rsa));
            if (status != AWRTC_PSA_SUCCESS) {
                goto rsa_exit;
            }

            status = awrtc_mbedtls_to_psa_error(
                awrtc_mbedtls_rsa_rsaes_oaep_encrypt(rsa,
                                               awrtc_mbedtls_psa_get_random,
                                               AWRTC_MBEDTLS_PSA_RANDOM_STATE,
                                               salt, salt_length,
                                               input_length,
                                               input,
                                               output));
#else
            status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP */
        } else {
            status = AWRTC_PSA_ERROR_INVALID_ARGUMENT;
        }
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
        defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP)
rsa_exit:
        if (status == AWRTC_PSA_SUCCESS) {
            *output_length = awrtc_mbedtls_rsa_get_len(rsa);
        }

        awrtc_mbedtls_rsa_free(rsa);
        awrtc_mbedtls_free(rsa);
#endif /* defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP) */
    } else {
        status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}

awrtc_psa_status_t awrtc_mbedtls_psa_asymmetric_decrypt(const awrtc_psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            awrtc_psa_algorithm_t alg,
                                            const uint8_t *input,
                                            size_t input_length,
                                            const uint8_t *salt,
                                            size_t salt_length,
                                            uint8_t *output,
                                            size_t output_size,
                                            size_t *output_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) input;
    (void) input_length;
    (void) salt;
    (void) salt_length;
    (void) output;
    (void) output_size;
    (void) output_length;

    *output_length = 0;

    if (attributes->type == AWRTC_PSA_KEY_TYPE_RSA_KEY_PAIR) {
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
        defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP)
        awrtc_mbedtls_rsa_context *rsa = NULL;
        status = awrtc_mbedtls_psa_rsa_load_representation(attributes->type,
                                                     key_buffer,
                                                     key_buffer_size,
                                                     &rsa);
        if (status != AWRTC_PSA_SUCCESS) {
            goto rsa_exit;
        }

        if (input_length != awrtc_mbedtls_rsa_get_len(rsa)) {
            status = AWRTC_PSA_ERROR_INVALID_ARGUMENT;
            goto rsa_exit;
        }
#endif /* defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP) */

        if (alg == AWRTC_PSA_ALG_RSA_PKCS1V15_CRYPT) {
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT)
            status = awrtc_mbedtls_to_psa_error(
                awrtc_mbedtls_rsa_pkcs1_decrypt(rsa,
                                          awrtc_mbedtls_psa_get_random,
                                          AWRTC_MBEDTLS_PSA_RANDOM_STATE,
                                          output_length,
                                          input,
                                          output,
                                          output_size));
#else
            status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT */
        } else
        if (AWRTC_PSA_ALG_IS_RSA_OAEP(alg)) {
#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP)
            status = awrtc_mbedtls_to_psa_error(
                awrtc_psa_rsa_oaep_set_padding_mode(alg, rsa));
            if (status != AWRTC_PSA_SUCCESS) {
                goto rsa_exit;
            }

            status = awrtc_mbedtls_to_psa_error(
                awrtc_mbedtls_rsa_rsaes_oaep_decrypt(rsa,
                                               awrtc_mbedtls_psa_get_random,
                                               AWRTC_MBEDTLS_PSA_RANDOM_STATE,
                                               salt, salt_length,
                                               output_length,
                                               input,
                                               output,
                                               output_size));
#else
            status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
#endif /* AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP */
        } else {
            status = AWRTC_PSA_ERROR_INVALID_ARGUMENT;
        }

#if defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
        defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP)
rsa_exit:
        awrtc_mbedtls_rsa_free(rsa);
        awrtc_mbedtls_free(rsa);
#endif /* defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(AWRTC_MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP) */
    } else {
        status = AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}

#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_C */
