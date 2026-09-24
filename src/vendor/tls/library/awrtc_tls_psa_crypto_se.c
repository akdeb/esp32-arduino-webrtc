/*
 *  PSA crypto support for secure element drivers
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_SE_C)

#include <stdint.h>
#include <string.h>

#include "../include/psa/crypto_se_driver.h"

#include "psa_crypto_se.h"

#if defined(AWRTC_MBEDTLS_PSA_ITS_FILE_C)
#include "psa_crypto_its.h"
#else /* Native ITS implementation */
#include "psa/error.h"
#include "psa/internal_trusted_storage.h"
#endif

#include "../include/mbedtls/platform.h"



/****************************************************************/
/* Driver lookup */
/****************************************************************/

/* This structure is identical to awrtc_psa_drv_se_context_t declared in
 * `crypto_se_driver.h`, except that some parts are writable here
 * (non-const, or pointer to non-const). */
typedef struct {
    void *persistent_data;
    size_t persistent_data_size;
    uintptr_t transient_data;
} awrtc_psa_drv_se_internal_context_t;

struct awrtc_psa_se_drv_table_entry_s {
    awrtc_psa_key_location_t location;
    const awrtc_psa_drv_se_t *methods;
    union {
        awrtc_psa_drv_se_internal_context_t internal;
        awrtc_psa_drv_se_context_t context;
    } u;
};

static awrtc_psa_se_drv_table_entry_t driver_table[AWRTC_PSA_MAX_SE_DRIVERS];

awrtc_psa_se_drv_table_entry_t *awrtc_psa_get_se_driver_entry(
    awrtc_psa_key_lifetime_t lifetime)
{
    size_t i;
    awrtc_psa_key_location_t location = AWRTC_PSA_KEY_LIFETIME_GET_LOCATION(lifetime);
    /* In the driver table, location=0 means an entry that isn't used.
     * No driver has a location of 0 because it's a reserved value
     * (which designates transparent keys). Make sure we never return
     * a driver entry for location 0. */
    if (location == 0) {
        return NULL;
    }
    for (i = 0; i < AWRTC_PSA_MAX_SE_DRIVERS; i++) {
        if (driver_table[i].location == location) {
            return &driver_table[i];
        }
    }
    return NULL;
}

const awrtc_psa_drv_se_t *awrtc_psa_get_se_driver_methods(
    const awrtc_psa_se_drv_table_entry_t *driver)
{
    return driver->methods;
}

awrtc_psa_drv_se_context_t *awrtc_psa_get_se_driver_context(
    awrtc_psa_se_drv_table_entry_t *driver)
{
    return &driver->u.context;
}

int awrtc_psa_get_se_driver(awrtc_psa_key_lifetime_t lifetime,
                      const awrtc_psa_drv_se_t **p_methods,
                      awrtc_psa_drv_se_context_t **p_drv_context)
{
    awrtc_psa_se_drv_table_entry_t *driver = awrtc_psa_get_se_driver_entry(lifetime);
    if (p_methods != NULL) {
        *p_methods = (driver ? driver->methods : NULL);
    }
    if (p_drv_context != NULL) {
        *p_drv_context = (driver ? &driver->u.context : NULL);
    }
    return driver != NULL;
}



/****************************************************************/
/* Persistent data management */
/****************************************************************/

static awrtc_psa_status_t awrtc_psa_get_se_driver_its_file_uid(
    const awrtc_psa_se_drv_table_entry_t *driver,
    awrtc_psa_storage_uid_t *uid)
{
    if (driver->location > AWRTC_PSA_MAX_SE_LOCATION) {
        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    /* ITS file sizes are limited to 32 bits. */
    if (driver->u.internal.persistent_data_size > UINT32_MAX) {
        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    /* See the documentation of AWRTC_PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE. */
    *uid = AWRTC_PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE + driver->location;
    return AWRTC_PSA_SUCCESS;
}

awrtc_psa_status_t awrtc_psa_load_se_persistent_data(
    const awrtc_psa_se_drv_table_entry_t *driver)
{
    awrtc_psa_status_t status;
    awrtc_psa_storage_uid_t uid;
    size_t length;

    status = awrtc_psa_get_se_driver_its_file_uid(driver, &uid);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    /* Read the amount of persistent data that the driver requests.
     * If the data in storage is larger, it is truncated. If the data
     * in storage is smaller, silently keep what is already at the end
     * of the output buffer. */
    /* awrtc_psa_get_se_driver_its_file_uid ensures that the size_t
     * persistent_data_size is in range, but compilers don't know that,
     * so cast to reassure them. */
    return awrtc_psa_its_get(uid, 0,
                       (uint32_t) driver->u.internal.persistent_data_size,
                       driver->u.internal.persistent_data,
                       &length);
}

awrtc_psa_status_t awrtc_psa_save_se_persistent_data(
    const awrtc_psa_se_drv_table_entry_t *driver)
{
    awrtc_psa_status_t status;
    awrtc_psa_storage_uid_t uid;

    status = awrtc_psa_get_se_driver_its_file_uid(driver, &uid);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    /* awrtc_psa_get_se_driver_its_file_uid ensures that the size_t
     * persistent_data_size is in range, but compilers don't know that,
     * so cast to reassure them. */
    return awrtc_psa_its_set(uid,
                       (uint32_t) driver->u.internal.persistent_data_size,
                       driver->u.internal.persistent_data,
                       0);
}

awrtc_psa_status_t awrtc_psa_destroy_se_persistent_data(awrtc_psa_key_location_t location)
{
    awrtc_psa_storage_uid_t uid;
    if (location > AWRTC_PSA_MAX_SE_LOCATION) {
        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }
    uid = AWRTC_PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE + location;
    return awrtc_psa_its_remove(uid);
}

awrtc_psa_status_t awrtc_psa_find_se_slot_for_key(
    const awrtc_psa_key_attributes_t *attributes,
    awrtc_psa_key_creation_method_t method,
    awrtc_psa_se_drv_table_entry_t *driver,
    awrtc_psa_key_slot_number_t *slot_number)
{
    awrtc_psa_status_t status;
    awrtc_psa_key_location_t key_location =
        AWRTC_PSA_KEY_LIFETIME_GET_LOCATION(awrtc_psa_get_key_lifetime(attributes));

    /* If the location is wrong, it's a bug in the library. */
    if (driver->location != key_location) {
        return AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    }

    /* If the driver doesn't support key creation in any way, give up now. */
    if (driver->methods->key_management == NULL) {
        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    if (awrtc_psa_get_key_slot_number(attributes, slot_number) == AWRTC_PSA_SUCCESS) {
        /* The application wants to use a specific slot. Allow it if
         * the driver supports it. On a system with isolation,
         * the crypto service must check that the application is
         * permitted to request this slot. */
        awrtc_psa_drv_se_validate_slot_number_t p_validate_slot_number =
            driver->methods->key_management->p_validate_slot_number;
        if (p_validate_slot_number == NULL) {
            return AWRTC_PSA_ERROR_NOT_SUPPORTED;
        }
        status = p_validate_slot_number(&driver->u.context,
                                        driver->u.internal.persistent_data,
                                        attributes, method,
                                        *slot_number);
    } else if (method == AWRTC_PSA_KEY_CREATION_REGISTER) {
        /* The application didn't specify a slot number. This doesn't
         * make sense when registering a slot. */
        return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
    } else {
        /* The application didn't tell us which slot to use. Let the driver
         * choose. This is the normal case. */
        awrtc_psa_drv_se_allocate_key_t p_allocate =
            driver->methods->key_management->p_allocate;
        if (p_allocate == NULL) {
            return AWRTC_PSA_ERROR_NOT_SUPPORTED;
        }
        status = p_allocate(&driver->u.context,
                            driver->u.internal.persistent_data,
                            attributes, method,
                            slot_number);
    }
    return status;
}

awrtc_psa_status_t awrtc_psa_destroy_se_key(awrtc_psa_se_drv_table_entry_t *driver,
                                awrtc_psa_key_slot_number_t slot_number)
{
    awrtc_psa_status_t status;
    awrtc_psa_status_t storage_status;
    /* Normally a missing method would mean that the action is not
     * supported. But awrtc_psa_destroy_key() is not supposed to return
     * AWRTC_PSA_ERROR_NOT_SUPPORTED: if you can create a key, you should
     * be able to destroy it. The only use case for a driver that
     * does not have a way to destroy keys at all is if the keys are
     * locked in a read-only state: we can use the keys but not
     * destroy them. Hence, if the driver doesn't support destroying
     * keys, it's really a lack of permission. */
    if (driver->methods->key_management == NULL ||
        driver->methods->key_management->p_destroy == NULL) {
        return AWRTC_PSA_ERROR_NOT_PERMITTED;
    }
    status = driver->methods->key_management->p_destroy(
        &driver->u.context,
        driver->u.internal.persistent_data,
        slot_number);
    storage_status = awrtc_psa_save_se_persistent_data(driver);
    return status == AWRTC_PSA_SUCCESS ? storage_status : status;
}

awrtc_psa_status_t awrtc_psa_init_all_se_drivers(void)
{
    size_t i;
    for (i = 0; i < AWRTC_PSA_MAX_SE_DRIVERS; i++) {
        awrtc_psa_se_drv_table_entry_t *driver = &driver_table[i];
        if (driver->location == 0) {
            continue; /* skipping unused entry */
        }
        const awrtc_psa_drv_se_t *methods = awrtc_psa_get_se_driver_methods(driver);
        if (methods->p_init != NULL) {
            awrtc_psa_status_t status = methods->p_init(
                &driver->u.context,
                driver->u.internal.persistent_data,
                driver->location);
            if (status != AWRTC_PSA_SUCCESS) {
                return status;
            }
            status = awrtc_psa_save_se_persistent_data(driver);
            if (status != AWRTC_PSA_SUCCESS) {
                return status;
            }
        }
    }
    return AWRTC_PSA_SUCCESS;
}



/****************************************************************/
/* Driver registration */
/****************************************************************/

awrtc_psa_status_t awrtc_psa_register_se_driver(
    awrtc_psa_key_location_t location,
    const awrtc_psa_drv_se_t *methods)
{
    size_t i;
    awrtc_psa_status_t status;

    if (methods->hal_version != AWRTC_PSA_DRV_SE_HAL_VERSION) {
        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }
    /* Driver table entries are 0-initialized. 0 is not a valid driver
     * location because it means a transparent key. */
    AWRTC_MBEDTLS_STATIC_ASSERT(AWRTC_PSA_KEY_LOCATION_LOCAL_STORAGE == 0,
                          "Secure element support requires 0 to mean a local key");

    if (location == AWRTC_PSA_KEY_LOCATION_LOCAL_STORAGE) {
        return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
    }
    if (location > AWRTC_PSA_MAX_SE_LOCATION) {
        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
    }

    for (i = 0; i < AWRTC_PSA_MAX_SE_DRIVERS; i++) {
        if (driver_table[i].location == 0) {
            break;
        }
        /* Check that location isn't already in use up to the first free
         * entry. Since entries are created in order and never deleted,
         * there can't be a used entry after the first free entry. */
        if (driver_table[i].location == location) {
            return AWRTC_PSA_ERROR_ALREADY_EXISTS;
        }
    }
    if (i == AWRTC_PSA_MAX_SE_DRIVERS) {
        return AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    driver_table[i].location = location;
    driver_table[i].methods = methods;
    driver_table[i].u.internal.persistent_data_size =
        methods->persistent_data_size;

    if (methods->persistent_data_size != 0) {
        driver_table[i].u.internal.persistent_data =
            awrtc_mbedtls_calloc(1, methods->persistent_data_size);
        if (driver_table[i].u.internal.persistent_data == NULL) {
            status = AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;
            goto error;
        }
        /* Load the driver's persistent data. On first use, the persistent
         * data does not exist in storage, and is initialized to
         * all-bits-zero by the calloc call just above. */
        status = awrtc_psa_load_se_persistent_data(&driver_table[i]);
        if (status != AWRTC_PSA_SUCCESS && status != AWRTC_PSA_ERROR_DOES_NOT_EXIST) {
            goto error;
        }
    }

    return AWRTC_PSA_SUCCESS;

error:
    memset(&driver_table[i], 0, sizeof(driver_table[i]));
    return status;
}

void awrtc_psa_unregister_all_se_drivers(void)
{
    size_t i;
    for (i = 0; i < AWRTC_PSA_MAX_SE_DRIVERS; i++) {
        if (driver_table[i].u.internal.persistent_data != NULL) {
            awrtc_mbedtls_free(driver_table[i].u.internal.persistent_data);
        }
    }
    memset(driver_table, 0, sizeof(driver_table));
}



/****************************************************************/
/* The end */
/****************************************************************/

#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_SE_C */
