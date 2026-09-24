/**
 * \file ssl_ciphersuites_internal.h
 *
 * \brief Internal part of the public "ssl_ciphersuites.h".
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef AWRTC_MBEDTLS_SSL_CIPHERSUITES_INTERNAL_H
#define AWRTC_MBEDTLS_SSL_CIPHERSUITES_INTERNAL_H

#include "../include/mbedtls/pk.h"

#if defined(AWRTC_MBEDTLS_PK_C)
awrtc_mbedtls_pk_type_t awrtc_mbedtls_ssl_get_ciphersuite_sig_pk_alg(const awrtc_mbedtls_ssl_ciphersuite_t *info);
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
awrtc_psa_algorithm_t awrtc_mbedtls_ssl_get_ciphersuite_sig_pk_psa_alg(const awrtc_mbedtls_ssl_ciphersuite_t *info);
awrtc_psa_key_usage_t awrtc_mbedtls_ssl_get_ciphersuite_sig_pk_psa_usage(const awrtc_mbedtls_ssl_ciphersuite_t *info);
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
awrtc_mbedtls_pk_type_t awrtc_mbedtls_ssl_get_ciphersuite_sig_alg(const awrtc_mbedtls_ssl_ciphersuite_t *info);
#endif /* AWRTC_MBEDTLS_PK_C */

int awrtc_mbedtls_ssl_ciphersuite_uses_ec(const awrtc_mbedtls_ssl_ciphersuite_t *info);
int awrtc_mbedtls_ssl_ciphersuite_uses_psk(const awrtc_mbedtls_ssl_ciphersuite_t *info);

#if defined(AWRTC_MBEDTLS_KEY_EXCHANGE_SOME_PFS_ENABLED)
static inline int awrtc_mbedtls_ssl_ciphersuite_has_pfs(const awrtc_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->AWRTC_MBEDTLS_PRIVATE(key_exchange)) {
        case AWRTC_MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_DHE_PSK:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECJPAKE:
            return 1;

        default:
            return 0;
    }
}
#endif /* AWRTC_MBEDTLS_KEY_EXCHANGE_SOME_PFS_ENABLED */

#if defined(AWRTC_MBEDTLS_KEY_EXCHANGE_SOME_NON_PFS_ENABLED)
static inline int awrtc_mbedtls_ssl_ciphersuite_no_pfs(const awrtc_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->AWRTC_MBEDTLS_PRIVATE(key_exchange)) {
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_PSK:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_RSA_PSK:
            return 1;

        default:
            return 0;
    }
}
#endif /* AWRTC_MBEDTLS_KEY_EXCHANGE_SOME_NON_PFS_ENABLED */

#if defined(AWRTC_MBEDTLS_KEY_EXCHANGE_SOME_ECDH_ENABLED)
static inline int awrtc_mbedtls_ssl_ciphersuite_uses_ecdh(const awrtc_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->AWRTC_MBEDTLS_PRIVATE(key_exchange)) {
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
            return 1;

        default:
            return 0;
    }
}
#endif /* AWRTC_MBEDTLS_KEY_EXCHANGE_SOME_ECDH_ENABLED */

static inline int awrtc_mbedtls_ssl_ciphersuite_cert_req_allowed(const awrtc_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->AWRTC_MBEDTLS_PRIVATE(key_exchange)) {
        case AWRTC_MBEDTLS_KEY_EXCHANGE_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
            return 1;

        default:
            return 0;
    }
}

static inline int awrtc_mbedtls_ssl_ciphersuite_uses_srv_cert(const awrtc_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->AWRTC_MBEDTLS_PRIVATE(key_exchange)) {
        case AWRTC_MBEDTLS_KEY_EXCHANGE_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_RSA_PSK:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
            return 1;

        default:
            return 0;
    }
}

#if defined(AWRTC_MBEDTLS_KEY_EXCHANGE_SOME_DHE_ENABLED)
static inline int awrtc_mbedtls_ssl_ciphersuite_uses_dhe(const awrtc_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->AWRTC_MBEDTLS_PRIVATE(key_exchange)) {
        case AWRTC_MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_DHE_PSK:
            return 1;

        default:
            return 0;
    }
}
#endif /* AWRTC_MBEDTLS_KEY_EXCHANGE_SOME_DHE_ENABLED) */

#if defined(AWRTC_MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED)
static inline int awrtc_mbedtls_ssl_ciphersuite_uses_ecdhe(const awrtc_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->AWRTC_MBEDTLS_PRIVATE(key_exchange)) {
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
            return 1;

        default:
            return 0;
    }
}
#endif /* AWRTC_MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED) */

#if defined(AWRTC_MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED)
static inline int awrtc_mbedtls_ssl_ciphersuite_uses_server_signature(
    const awrtc_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->AWRTC_MBEDTLS_PRIVATE(key_exchange)) {
        case AWRTC_MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case AWRTC_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
            return 1;

        default:
            return 0;
    }
}
#endif /* AWRTC_MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED */

#endif /* AWRTC_MBEDTLS_SSL_CIPHERSUITES_INTERNAL_H */
