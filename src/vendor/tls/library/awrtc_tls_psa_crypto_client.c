/*
 *  PSA crypto client code
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"
#include "../include/psa/crypto.h"

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT)

#include <string.h>
#include "../include/mbedtls/platform.h"

void awrtc_psa_reset_key_attributes(awrtc_psa_key_attributes_t *attributes)
{
    memset(attributes, 0, sizeof(*attributes));
}

#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT */
