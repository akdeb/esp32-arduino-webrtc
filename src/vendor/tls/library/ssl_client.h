/**
 *  TLS 1.2 and 1.3 client-side functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_MBEDTLS_SSL_CLIENT_H
#define AWRTC_MBEDTLS_SSL_CLIENT_H

#include "common.h"

#if defined(AWRTC_MBEDTLS_SSL_TLS_C)
#include "ssl_misc.h"
#endif

#include <stddef.h>

AWRTC_MBEDTLS_CHECK_RETURN_CRITICAL
int awrtc_mbedtls_ssl_write_client_hello(awrtc_mbedtls_ssl_context *ssl);

#endif /* AWRTC_MBEDTLS_SSL_CLIENT_H */
