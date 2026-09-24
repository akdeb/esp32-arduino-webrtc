/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_MBEDTLS_SSL_TLS13_INVASIVE_H
#define AWRTC_MBEDTLS_SSL_TLS13_INVASIVE_H

#include "common.h"

#if defined(AWRTC_MBEDTLS_SSL_PROTO_TLS1_3)

#include "../include/psa/crypto.h"

#if defined(AWRTC_MBEDTLS_TEST_HOOKS)
int awrtc_mbedtls_ssl_tls13_parse_certificate(awrtc_mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        const unsigned char *end);
#endif /* AWRTC_MBEDTLS_TEST_HOOKS */

#endif /* AWRTC_MBEDTLS_SSL_PROTO_TLS1_3 */

#endif /* AWRTC_MBEDTLS_SSL_TLS13_INVASIVE_H */
