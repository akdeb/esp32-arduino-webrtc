/**
 * \file ssl_debug_helpers.h
 *
 * \brief Automatically generated helper functions for debugging
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_MBEDTLS_SSL_DEBUG_HELPERS_H
#define AWRTC_MBEDTLS_SSL_DEBUG_HELPERS_H

#include "common.h"

#if defined(AWRTC_MBEDTLS_DEBUG_C)

#include "../include/mbedtls/ssl.h"
#include "ssl_misc.h"


const char *awrtc_mbedtls_ssl_states_str(awrtc_mbedtls_ssl_states in);

#if defined(AWRTC_MBEDTLS_SSL_EARLY_DATA) && defined(AWRTC_MBEDTLS_SSL_CLI_C)
const char *awrtc_mbedtls_ssl_early_data_status_str(awrtc_mbedtls_ssl_early_data_status in);
const char *awrtc_mbedtls_ssl_early_data_state_str(awrtc_mbedtls_ssl_early_data_state in);
#endif

const char *awrtc_mbedtls_ssl_protocol_version_str(awrtc_mbedtls_ssl_protocol_version in);

const char *awrtc_mbedtls_tls_prf_types_str(awrtc_mbedtls_tls_prf_types in);

const char *awrtc_mbedtls_ssl_key_export_type_str(awrtc_mbedtls_ssl_key_export_type in);

const char *awrtc_mbedtls_ssl_sig_alg_to_str(uint16_t in);

const char *awrtc_mbedtls_ssl_named_group_to_str(uint16_t in);

const char *awrtc_mbedtls_ssl_get_extension_name(unsigned int extension_type);

const char *awrtc_mbedtls_ssl_get_hs_msg_name(int hs_msg_type);

void awrtc_mbedtls_ssl_print_extensions(const awrtc_mbedtls_ssl_context *ssl,
                                  int level, const char *file, int line,
                                  int hs_msg_type, uint32_t extensions_mask,
                                  const char *extra);

void awrtc_mbedtls_ssl_print_extension(const awrtc_mbedtls_ssl_context *ssl,
                                 int level, const char *file, int line,
                                 int hs_msg_type, unsigned int extension_type,
                                 const char *extra_msg0, const char *extra_msg1);

#if defined(AWRTC_MBEDTLS_SSL_PROTO_TLS1_3) && defined(AWRTC_MBEDTLS_SSL_SESSION_TICKETS)
void awrtc_mbedtls_ssl_print_ticket_flags(const awrtc_mbedtls_ssl_context *ssl,
                                    int level, const char *file, int line,
                                    unsigned int flags);
#endif /* AWRTC_MBEDTLS_SSL_PROTO_TLS1_3 && AWRTC_MBEDTLS_SSL_SESSION_TICKETS */

#define AWRTC_MBEDTLS_SSL_PRINT_EXTS(level, hs_msg_type, extensions_mask)            \
    awrtc_mbedtls_ssl_print_extensions(ssl, level, __FILE__, __LINE__,       \
                                 hs_msg_type, extensions_mask, NULL)

#define AWRTC_MBEDTLS_SSL_PRINT_EXT(level, hs_msg_type, extension_type, extra)      \
    awrtc_mbedtls_ssl_print_extension(ssl, level, __FILE__, __LINE__,        \
                                hs_msg_type, extension_type,           \
                                extra, NULL)

#if defined(AWRTC_MBEDTLS_SSL_PROTO_TLS1_3) && defined(AWRTC_MBEDTLS_SSL_SESSION_TICKETS)
#define AWRTC_MBEDTLS_SSL_PRINT_TICKET_FLAGS(level, flags)             \
    awrtc_mbedtls_ssl_print_ticket_flags(ssl, level, __FILE__, __LINE__, flags)
#endif

#else

#define AWRTC_MBEDTLS_SSL_PRINT_EXTS(level, hs_msg_type, extension_mask)

#define AWRTC_MBEDTLS_SSL_PRINT_EXT(level, hs_msg_type, extension_type, extra)

#if defined(AWRTC_MBEDTLS_SSL_PROTO_TLS1_3) && defined(AWRTC_MBEDTLS_SSL_SESSION_TICKETS)
#define AWRTC_MBEDTLS_SSL_PRINT_TICKET_FLAGS(level, flags)
#endif

#endif /* AWRTC_MBEDTLS_DEBUG_C */

#endif /* AWRTC_MBEDTLS_SSL_DEBUG_HELPERS_H */
