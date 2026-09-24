/*
 *  Version information
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_VERSION_C)

#include "../include/mbedtls/version.h"
#include <string.h>

unsigned int awrtc_mbedtls_version_get_number(void)
{
    return AWRTC_MBEDTLS_VERSION_NUMBER;
}

void awrtc_mbedtls_version_get_string(char *string)
{
    memcpy(string, AWRTC_MBEDTLS_VERSION_STRING,
           sizeof(AWRTC_MBEDTLS_VERSION_STRING));
}

void awrtc_mbedtls_version_get_string_full(char *string)
{
    memcpy(string, AWRTC_MBEDTLS_VERSION_STRING_FULL,
           sizeof(AWRTC_MBEDTLS_VERSION_STRING_FULL));
}

#endif /* AWRTC_MBEDTLS_VERSION_C */
