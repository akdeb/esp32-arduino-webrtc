/*
 *  PSA persistent key storage
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C)

#include <stdlib.h>
#include <string.h>

#include "../include/psa/crypto.h"
#include "psa_crypto_storage.h"
#include "../include/mbedtls/platform_util.h"

#if defined(AWRTC_MBEDTLS_PSA_ITS_FILE_C)
#include "psa_crypto_its.h"
#else /* Native ITS implementation */
#include "psa/error.h"
#include "psa/internal_trusted_storage.h"
#endif

#include "../include/mbedtls/platform.h"



/****************************************************************/
/* Key storage */
/****************************************************************/

/* Determine a file name (ITS file identifier) for the given key identifier.
 * The file name must be distinct from any file that is used for a purpose
 * other than storing a key. Currently, the only such file is the random seed
 * file whose name is AWRTC_PSA_CRYPTO_ITS_RANDOM_SEED_UID and whose value is
 * 0xFFFFFF52. */
static awrtc_psa_storage_uid_t awrtc_psa_its_identifier_of_slot(awrtc_mbedtls_svc_key_id_t key)
{
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
    /* Encode the owner in the upper 32 bits. This means that if
     * owner values are nonzero (as they are on a PSA platform),
     * no key file will ever have a value less than 0x100000000, so
     * the whole range 0..0xffffffff is available for non-key files. */
    uint32_t unsigned_owner_id = AWRTC_MBEDTLS_SVC_KEY_ID_GET_OWNER_ID(key);
    return ((uint64_t) unsigned_owner_id << 32) |
           AWRTC_MBEDTLS_SVC_KEY_ID_GET_KEY_ID(key);
#else
    /* Use the key id directly as a file name.
     * awrtc_psa_is_key_id_valid() in awrtc_psa_crypto_slot_management.c
     * is responsible for ensuring that key identifiers do not have a
     * value that is reserved for non-key files. */
    return key;
#endif
}

/**
 * \brief Load persistent data for the given key slot number.
 *
 * This function reads data from a storage backend and returns the data in a
 * buffer.
 *
 * \param key               Persistent identifier of the key to be loaded. This
 *                          should be an occupied storage location.
 * \param[out] data         Buffer where the data is to be written.
 * \param data_size         Size of the \c data buffer in bytes.
 *
 * \retval #AWRTC_PSA_SUCCESS \emptydescription
 * \retval #AWRTC_PSA_ERROR_DATA_INVALID \emptydescription
 * \retval #AWRTC_PSA_ERROR_DATA_CORRUPT \emptydescription
 * \retval #AWRTC_PSA_ERROR_STORAGE_FAILURE \emptydescription
 * \retval #AWRTC_PSA_ERROR_DOES_NOT_EXIST \emptydescription
 */
static awrtc_psa_status_t awrtc_psa_crypto_storage_load(
    const awrtc_mbedtls_svc_key_id_t key, uint8_t *data, size_t data_size)
{
    awrtc_psa_status_t status;
    awrtc_psa_storage_uid_t data_identifier = awrtc_psa_its_identifier_of_slot(key);
    struct awrtc_psa_storage_info_t data_identifier_info;
    size_t data_length = 0;

    status = awrtc_psa_its_get_info(data_identifier, &data_identifier_info);
    if (status  != AWRTC_PSA_SUCCESS) {
        return status;
    }

    status = awrtc_psa_its_get(data_identifier, 0, (uint32_t) data_size, data, &data_length);
    if (data_size  != data_length) {
        return AWRTC_PSA_ERROR_DATA_INVALID;
    }

    return status;
}

int awrtc_psa_is_key_present_in_storage(const awrtc_mbedtls_svc_key_id_t key)
{
    awrtc_psa_status_t ret;
    awrtc_psa_storage_uid_t data_identifier = awrtc_psa_its_identifier_of_slot(key);
    struct awrtc_psa_storage_info_t data_identifier_info;

    ret = awrtc_psa_its_get_info(data_identifier, &data_identifier_info);

    if (ret == AWRTC_PSA_ERROR_DOES_NOT_EXIST) {
        return 0;
    }
    return 1;
}

/**
 * \brief Store persistent data for the given key slot number.
 *
 * This function stores the given data buffer to a persistent storage.
 *
 * \param key           Persistent identifier of the key to be stored. This
 *                      should be an unoccupied storage location.
 * \param[in] data      Buffer containing the data to be stored.
 * \param data_length   The number of bytes
 *                      that make up the data.
 *
 * \retval #AWRTC_PSA_SUCCESS \emptydescription
 * \retval #AWRTC_PSA_ERROR_INSUFFICIENT_STORAGE \emptydescription
 * \retval #AWRTC_PSA_ERROR_ALREADY_EXISTS \emptydescription
 * \retval #AWRTC_PSA_ERROR_STORAGE_FAILURE \emptydescription
 * \retval #AWRTC_PSA_ERROR_DATA_INVALID \emptydescription
 */
static awrtc_psa_status_t awrtc_psa_crypto_storage_store(const awrtc_mbedtls_svc_key_id_t key,
                                             const uint8_t *data,
                                             size_t data_length)
{
    awrtc_psa_status_t status;
    awrtc_psa_storage_uid_t data_identifier = awrtc_psa_its_identifier_of_slot(key);
    struct awrtc_psa_storage_info_t data_identifier_info;

    if (awrtc_psa_is_key_present_in_storage(key) == 1) {
        return AWRTC_PSA_ERROR_ALREADY_EXISTS;
    }

    status = awrtc_psa_its_set(data_identifier, (uint32_t) data_length, data, 0);
    if (status != AWRTC_PSA_SUCCESS) {
        return AWRTC_PSA_ERROR_DATA_INVALID;
    }

    status = awrtc_psa_its_get_info(data_identifier, &data_identifier_info);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    if (data_identifier_info.size != data_length) {
        status = AWRTC_PSA_ERROR_DATA_INVALID;
        goto exit;
    }

exit:
    if (status != AWRTC_PSA_SUCCESS) {
        /* Remove the file in case we managed to create it but something
         * went wrong. It's ok if the file doesn't exist. If the file exists
         * but the removal fails, we're already reporting an error so there's
         * nothing else we can do. */
        (void) awrtc_psa_its_remove(data_identifier);
    }
    return status;
}

awrtc_psa_status_t awrtc_psa_destroy_persistent_key(const awrtc_mbedtls_svc_key_id_t key)
{
    awrtc_psa_status_t ret;
    awrtc_psa_storage_uid_t data_identifier = awrtc_psa_its_identifier_of_slot(key);
    struct awrtc_psa_storage_info_t data_identifier_info;

    ret = awrtc_psa_its_get_info(data_identifier, &data_identifier_info);
    if (ret == AWRTC_PSA_ERROR_DOES_NOT_EXIST) {
        return AWRTC_PSA_SUCCESS;
    }

    if (awrtc_psa_its_remove(data_identifier) != AWRTC_PSA_SUCCESS) {
        return AWRTC_PSA_ERROR_DATA_INVALID;
    }

    ret = awrtc_psa_its_get_info(data_identifier, &data_identifier_info);
    if (ret != AWRTC_PSA_ERROR_DOES_NOT_EXIST) {
        return AWRTC_PSA_ERROR_DATA_INVALID;
    }

    return AWRTC_PSA_SUCCESS;
}

/**
 * \brief Get data length for given key slot number.
 *
 * \param key               Persistent identifier whose stored data length
 *                          is to be obtained.
 * \param[out] data_length  The number of bytes that make up the data.
 *
 * \retval #AWRTC_PSA_SUCCESS \emptydescription
 * \retval #AWRTC_PSA_ERROR_STORAGE_FAILURE \emptydescription
 * \retval #AWRTC_PSA_ERROR_DOES_NOT_EXIST \emptydescription
 * \retval #AWRTC_PSA_ERROR_DATA_CORRUPT \emptydescription
 */
static awrtc_psa_status_t awrtc_psa_crypto_storage_get_data_length(
    const awrtc_mbedtls_svc_key_id_t key,
    size_t *data_length)
{
    awrtc_psa_status_t status;
    awrtc_psa_storage_uid_t data_identifier = awrtc_psa_its_identifier_of_slot(key);
    struct awrtc_psa_storage_info_t data_identifier_info;

    status = awrtc_psa_its_get_info(data_identifier, &data_identifier_info);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    *data_length = (size_t) data_identifier_info.size;

    return AWRTC_PSA_SUCCESS;
}

/**
 * Persistent key storage magic header.
 */
#define AWRTC_PSA_KEY_STORAGE_MAGIC_HEADER "PSA\0KEY"
#define AWRTC_PSA_KEY_STORAGE_MAGIC_HEADER_LENGTH (sizeof(AWRTC_PSA_KEY_STORAGE_MAGIC_HEADER))

typedef struct {
    uint8_t magic[AWRTC_PSA_KEY_STORAGE_MAGIC_HEADER_LENGTH];
    uint8_t version[4];
    uint8_t lifetime[sizeof(awrtc_psa_key_lifetime_t)];
    uint8_t type[2];
    uint8_t bits[2];
    uint8_t policy[sizeof(awrtc_psa_key_policy_t)];
    uint8_t data_len[4];
    uint8_t key_data[];
} awrtc_psa_persistent_key_storage_format;

void awrtc_psa_format_key_data_for_storage(const uint8_t *data,
                                     const size_t data_length,
                                     const awrtc_psa_key_attributes_t *attr,
                                     uint8_t *storage_data)
{
    awrtc_psa_persistent_key_storage_format *storage_format =
        (awrtc_psa_persistent_key_storage_format *) storage_data;

    memcpy(storage_format->magic, AWRTC_PSA_KEY_STORAGE_MAGIC_HEADER,
           AWRTC_PSA_KEY_STORAGE_MAGIC_HEADER_LENGTH);
    AWRTC_MBEDTLS_PUT_UINT32_LE(0, storage_format->version, 0);
    AWRTC_MBEDTLS_PUT_UINT32_LE(attr->lifetime, storage_format->lifetime, 0);
    AWRTC_MBEDTLS_PUT_UINT16_LE((uint16_t) attr->type, storage_format->type, 0);
    AWRTC_MBEDTLS_PUT_UINT16_LE((uint16_t) attr->bits, storage_format->bits, 0);
    AWRTC_MBEDTLS_PUT_UINT32_LE(attr->policy.usage, storage_format->policy, 0);
    AWRTC_MBEDTLS_PUT_UINT32_LE(attr->policy.alg, storage_format->policy, sizeof(uint32_t));
    AWRTC_MBEDTLS_PUT_UINT32_LE(attr->policy.alg2, storage_format->policy, 2 * sizeof(uint32_t));
    AWRTC_MBEDTLS_PUT_UINT32_LE(data_length, storage_format->data_len, 0);
    memcpy(storage_format->key_data, data, data_length);
}

static awrtc_psa_status_t check_magic_header(const uint8_t *data)
{
    if (memcmp(data, AWRTC_PSA_KEY_STORAGE_MAGIC_HEADER,
               AWRTC_PSA_KEY_STORAGE_MAGIC_HEADER_LENGTH) != 0) {
        return AWRTC_PSA_ERROR_DATA_INVALID;
    }
    return AWRTC_PSA_SUCCESS;
}

awrtc_psa_status_t awrtc_psa_parse_key_data_from_storage(const uint8_t *storage_data,
                                             size_t storage_data_length,
                                             uint8_t **key_data,
                                             size_t *key_data_length,
                                             awrtc_psa_key_attributes_t *attr)
{
    awrtc_psa_status_t status;
    const awrtc_psa_persistent_key_storage_format *storage_format =
        (const awrtc_psa_persistent_key_storage_format *) storage_data;
    uint32_t version;

    if (storage_data_length < sizeof(*storage_format)) {
        return AWRTC_PSA_ERROR_DATA_INVALID;
    }

    status = check_magic_header(storage_data);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    version = AWRTC_MBEDTLS_GET_UINT32_LE(storage_format->version, 0);
    if (version != 0) {
        return AWRTC_PSA_ERROR_DATA_INVALID;
    }

    *key_data_length = AWRTC_MBEDTLS_GET_UINT32_LE(storage_format->data_len, 0);
    if (*key_data_length > (storage_data_length - sizeof(*storage_format)) ||
        *key_data_length > AWRTC_PSA_CRYPTO_MAX_STORAGE_SIZE) {
        return AWRTC_PSA_ERROR_DATA_INVALID;
    }

    if (*key_data_length == 0) {
        *key_data = NULL;
    } else {
        *key_data = awrtc_mbedtls_calloc(1, *key_data_length);
        if (*key_data == NULL) {
            return AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        memcpy(*key_data, storage_format->key_data, *key_data_length);
    }

    attr->lifetime = AWRTC_MBEDTLS_GET_UINT32_LE(storage_format->lifetime, 0);
    attr->type = AWRTC_MBEDTLS_GET_UINT16_LE(storage_format->type, 0);
    attr->bits = AWRTC_MBEDTLS_GET_UINT16_LE(storage_format->bits, 0);
    attr->policy.usage = AWRTC_MBEDTLS_GET_UINT32_LE(storage_format->policy, 0);
    attr->policy.alg = AWRTC_MBEDTLS_GET_UINT32_LE(storage_format->policy, sizeof(uint32_t));
    attr->policy.alg2 = AWRTC_MBEDTLS_GET_UINT32_LE(storage_format->policy, 2 * sizeof(uint32_t));

    return AWRTC_PSA_SUCCESS;
}

awrtc_psa_status_t awrtc_psa_save_persistent_key(const awrtc_psa_key_attributes_t *attr,
                                     const uint8_t *data,
                                     const size_t data_length)
{
    size_t storage_data_length;
    uint8_t *storage_data;
    awrtc_psa_status_t status;

    /* All keys saved to persistent storage always have a key context */
    if (data == NULL || data_length == 0) {
        return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
    }

    if (data_length > AWRTC_PSA_CRYPTO_MAX_STORAGE_SIZE) {
        return AWRTC_PSA_ERROR_INSUFFICIENT_STORAGE;
    }
    storage_data_length = data_length + sizeof(awrtc_psa_persistent_key_storage_format);

    storage_data = awrtc_mbedtls_calloc(1, storage_data_length);
    if (storage_data == NULL) {
        return AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    awrtc_psa_format_key_data_for_storage(data, data_length, attr, storage_data);

    status = awrtc_psa_crypto_storage_store(attr->id,
                                      storage_data, storage_data_length);

    awrtc_mbedtls_zeroize_and_free(storage_data, storage_data_length);

    return status;
}

void awrtc_psa_free_persistent_key_data(uint8_t *key_data, size_t key_data_length)
{
    awrtc_mbedtls_zeroize_and_free(key_data, key_data_length);
}

awrtc_psa_status_t awrtc_psa_load_persistent_key(awrtc_psa_key_attributes_t *attr,
                                     uint8_t **data,
                                     size_t *data_length)
{
    awrtc_psa_status_t status = AWRTC_PSA_SUCCESS;
    uint8_t *loaded_data;
    size_t storage_data_length = 0;
    awrtc_mbedtls_svc_key_id_t key = attr->id;

    status = awrtc_psa_crypto_storage_get_data_length(key, &storage_data_length);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    loaded_data = awrtc_mbedtls_calloc(1, storage_data_length);

    if (loaded_data == NULL) {
        return AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    status = awrtc_psa_crypto_storage_load(key, loaded_data, storage_data_length);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    status = awrtc_psa_parse_key_data_from_storage(loaded_data, storage_data_length,
                                             data, data_length, attr);

    /* All keys saved to persistent storage always have a key context */
    if (status == AWRTC_PSA_SUCCESS &&
        (*data == NULL || *data_length == 0)) {
        status = AWRTC_PSA_ERROR_STORAGE_FAILURE;
    }

exit:
    awrtc_mbedtls_zeroize_and_free(loaded_data, storage_data_length);
    return status;
}



/****************************************************************/
/* Transactions */
/****************************************************************/

#if defined(AWRTC_PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS)

awrtc_psa_crypto_transaction_t awrtc_psa_crypto_transaction;

awrtc_psa_status_t awrtc_psa_crypto_save_transaction(void)
{
    struct awrtc_psa_storage_info_t p_info;
    awrtc_psa_status_t status;
    status = awrtc_psa_its_get_info(AWRTC_PSA_CRYPTO_ITS_TRANSACTION_UID, &p_info);
    if (status == AWRTC_PSA_SUCCESS) {
        /* This shouldn't happen: we're trying to start a transaction while
         * there is still a transaction that hasn't been replayed. */
        return AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    } else if (status != AWRTC_PSA_ERROR_DOES_NOT_EXIST) {
        return status;
    }
    return awrtc_psa_its_set(AWRTC_PSA_CRYPTO_ITS_TRANSACTION_UID,
                       sizeof(awrtc_psa_crypto_transaction),
                       &awrtc_psa_crypto_transaction,
                       0);
}

awrtc_psa_status_t awrtc_psa_crypto_load_transaction(void)
{
    awrtc_psa_status_t status;
    size_t length;
    status = awrtc_psa_its_get(AWRTC_PSA_CRYPTO_ITS_TRANSACTION_UID, 0,
                         sizeof(awrtc_psa_crypto_transaction),
                         &awrtc_psa_crypto_transaction, &length);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }
    if (length != sizeof(awrtc_psa_crypto_transaction)) {
        return AWRTC_PSA_ERROR_DATA_INVALID;
    }
    return AWRTC_PSA_SUCCESS;
}

awrtc_psa_status_t awrtc_psa_crypto_stop_transaction(void)
{
    awrtc_psa_status_t status = awrtc_psa_its_remove(AWRTC_PSA_CRYPTO_ITS_TRANSACTION_UID);
    /* Whether or not updating the storage succeeded, the transaction is
     * finished now. It's too late to go back, so zero out the in-memory
     * data. */
    memset(&awrtc_psa_crypto_transaction, 0, sizeof(awrtc_psa_crypto_transaction));
    return status;
}

#endif /* AWRTC_PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS */



/****************************************************************/
/* Random generator state */
/****************************************************************/

#if defined(AWRTC_MBEDTLS_PSA_INJECT_ENTROPY)
awrtc_psa_status_t awrtc_mbedtls_psa_storage_inject_entropy(const unsigned char *seed,
                                                size_t seed_size)
{
    awrtc_psa_status_t status;
    struct awrtc_psa_storage_info_t p_info;

    status = awrtc_psa_its_get_info(AWRTC_PSA_CRYPTO_ITS_RANDOM_SEED_UID, &p_info);

    if (AWRTC_PSA_ERROR_DOES_NOT_EXIST == status) { /* No seed exists */
        status = awrtc_psa_its_set(AWRTC_PSA_CRYPTO_ITS_RANDOM_SEED_UID, seed_size, seed, 0);
    } else if (AWRTC_PSA_SUCCESS == status) {
        /* You should not be here. Seed needs to be injected only once */
        status = AWRTC_PSA_ERROR_NOT_PERMITTED;
    }
    return status;
}
#endif /* AWRTC_MBEDTLS_PSA_INJECT_ENTROPY */



/****************************************************************/
/* The end */
/****************************************************************/

#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C */
