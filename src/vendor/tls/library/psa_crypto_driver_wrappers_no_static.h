/*
 *  Function signatures for functionality that can be provided by
 *  cryptographic accelerators.
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_PSA_CRYPTO_DRIVER_WRAPPERS_NO_STATIC_H
#define AWRTC_PSA_CRYPTO_DRIVER_WRAPPERS_NO_STATIC_H

#include "../include/psa/crypto.h"
#include "../include/psa/crypto_driver_common.h"

awrtc_psa_status_t awrtc_psa_driver_wrapper_export_public_key(
    const awrtc_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length);

awrtc_psa_status_t awrtc_psa_driver_wrapper_get_key_buffer_size(
    const awrtc_psa_key_attributes_t *attributes,
    size_t *key_buffer_size);

awrtc_psa_status_t awrtc_psa_driver_wrapper_get_builtin_key(
    awrtc_psa_drv_slot_number_t slot_number,
    awrtc_psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length);

#endif /* AWRTC_PSA_CRYPTO_DRIVER_WRAPPERS_NO_STATIC_H */

/* End of automatically generated file. */
