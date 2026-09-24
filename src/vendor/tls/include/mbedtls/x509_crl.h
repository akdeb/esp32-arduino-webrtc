/**
 * \file x509_crl.h
 *
 * \brief X.509 certificate revocation list parsing
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef AWRTC_MBEDTLS_X509_CRL_H
#define AWRTC_MBEDTLS_X509_CRL_H
#include "private_access.h"

#include "build_info.h"

#include "x509.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup x509_module
 * \{ */

/**
 * \name Structures and functions for parsing CRLs
 * \{
 */

/**
 * Certificate revocation list entry.
 * Contains the CA-specific serial numbers and revocation dates.
 *
 * Some fields of this structure are publicly readable. Do not modify
 * them except via Mbed TLS library functions: the effect of modifying
 * those fields or the data that those fields points to is unspecified.
 */
typedef struct awrtc_mbedtls_x509_crl_entry {
    /** Direct access to the whole entry inside the containing buffer. */
    awrtc_mbedtls_x509_buf raw;
    /** The serial number of the revoked certificate. */
    awrtc_mbedtls_x509_buf serial;
    /** The revocation date of this entry. */
    awrtc_mbedtls_x509_time revocation_date;
    /** Direct access to the list of CRL entry extensions
     * (an ASN.1 constructed sequence).
     *
     * If there are no extensions, `entry_ext.len == 0` and
     * `entry_ext.p == NULL`. */
    awrtc_mbedtls_x509_buf entry_ext;

    /** Next element in the linked list of entries.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct awrtc_mbedtls_x509_crl_entry *next;
}
awrtc_mbedtls_x509_crl_entry;

/**
 * Certificate revocation list structure.
 * Every CRL may have multiple entries.
 */
typedef struct awrtc_mbedtls_x509_crl {
    awrtc_mbedtls_x509_buf raw;           /**< The raw certificate data (DER). */
    awrtc_mbedtls_x509_buf tbs;           /**< The raw certificate body (DER). The part that is To Be Signed. */

    int version;            /**< CRL version (1=v1, 2=v2) */
    awrtc_mbedtls_x509_buf sig_oid;       /**< CRL signature type identifier */

    awrtc_mbedtls_x509_buf issuer_raw;    /**< The raw issuer data (DER). */

    awrtc_mbedtls_x509_name issuer;       /**< The parsed issuer data (named information object). */

    awrtc_mbedtls_x509_time this_update;
    awrtc_mbedtls_x509_time next_update;

    awrtc_mbedtls_x509_crl_entry entry;   /**< The CRL entries containing the certificate revocation times for this CA. */

    awrtc_mbedtls_x509_buf crl_ext;

    awrtc_mbedtls_x509_buf AWRTC_MBEDTLS_PRIVATE(sig_oid2);
    awrtc_mbedtls_x509_buf AWRTC_MBEDTLS_PRIVATE(sig);
    awrtc_mbedtls_md_type_t AWRTC_MBEDTLS_PRIVATE(sig_md);           /**< Internal representation of the MD algorithm of the signature algorithm, e.g. AWRTC_MBEDTLS_MD_SHA256 */
    awrtc_mbedtls_pk_type_t AWRTC_MBEDTLS_PRIVATE(sig_pk);           /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. AWRTC_MBEDTLS_PK_RSA */
    void *AWRTC_MBEDTLS_PRIVATE(sig_opts);             /**< Signature options to be passed to awrtc_mbedtls_pk_verify_ext(), e.g. for RSASSA-PSS */

    /** Next element in the linked list of CRL.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct awrtc_mbedtls_x509_crl *next;
}
awrtc_mbedtls_x509_crl;

/**
 * \brief          Parse a DER-encoded CRL and append it to the chained list
 *
 * \note           If #AWRTC_MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 awrtc_psa_crypto_init() before calling this function.
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the CRL data in DER format
 * \param buflen   size of the buffer
 *                 (including the terminating null byte for PEM data)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int awrtc_mbedtls_x509_crl_parse_der(awrtc_mbedtls_x509_crl *chain,
                               const unsigned char *buf, size_t buflen);
/**
 * \brief          Parse one or more CRLs and append them to the chained list
 *
 * \note           Multiple CRLs are accepted only if using PEM format
 *
 * \note           If #AWRTC_MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 awrtc_psa_crypto_init() before calling this function.
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the CRL data in PEM or DER format
 * \param buflen   size of the buffer
 *                 (including the terminating null byte for PEM data)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int awrtc_mbedtls_x509_crl_parse(awrtc_mbedtls_x509_crl *chain, const unsigned char *buf, size_t buflen);

#if defined(AWRTC_MBEDTLS_FS_IO)
/**
 * \brief          Load one or more CRLs and append them to the chained list
 *
 * \note           Multiple CRLs are accepted only if using PEM format
 *
 * \note           If #AWRTC_MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 awrtc_psa_crypto_init() before calling this function.
 *
 * \param chain    points to the start of the chain
 * \param path     filename to read the CRLs from (in PEM or DER encoding)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int awrtc_mbedtls_x509_crl_parse_file(awrtc_mbedtls_x509_crl *chain, const char *path);
#endif /* AWRTC_MBEDTLS_FS_IO */

#if !defined(AWRTC_MBEDTLS_X509_REMOVE_INFO)
/**
 * \brief          Returns an informational string about the CRL.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param prefix   A line prefix
 * \param crl      The X509 CRL to represent
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int awrtc_mbedtls_x509_crl_info(char *buf, size_t size, const char *prefix,
                          const awrtc_mbedtls_x509_crl *crl);
#endif /* !AWRTC_MBEDTLS_X509_REMOVE_INFO */

/**
 * \brief          Initialize a CRL (chain)
 *
 * \param crl      CRL chain to initialize
 */
void awrtc_mbedtls_x509_crl_init(awrtc_mbedtls_x509_crl *crl);

/**
 * \brief          Unallocate all CRL data
 *
 * \param crl      CRL chain to free
 */
void awrtc_mbedtls_x509_crl_free(awrtc_mbedtls_x509_crl *crl);

/** \} name Structures and functions for parsing CRLs */
/** \} addtogroup x509_module */

#ifdef __cplusplus
}
#endif

#endif /* awrtc_mbedtls_x509_crl.h */
