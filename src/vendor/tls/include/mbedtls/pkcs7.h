/**
 * \file pkcs7.h
 *
 * \brief PKCS #7 generic defines and structures
 *  https://tools.ietf.org/html/rfc2315
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/**
 * Note: For the time being, this implementation of the PKCS #7 cryptographic
 * message syntax is a partial implementation of RFC 2315.
 * Differences include:
 *  - The RFC specifies 6 different content types. The only type currently
 *    supported in Mbed TLS is the signed-data content type.
 *  - The only supported PKCS #7 Signed Data syntax version is version 1
 *  - The RFC specifies support for BER. This implementation is limited to
 *    DER only.
 *  - The RFC specifies that multiple digest algorithms can be specified
 *    in the Signed Data type. Only one digest algorithm is supported in Mbed TLS.
 *  - The RFC specifies the Signed Data type can contain multiple X.509 or PKCS #6 extended
 *    certificates. In Mbed TLS, this list can only contain 0 or 1 certificates
 *    and they must be in X.509 format.
 *  - The RFC specifies the Signed Data type can contain
 *    certificate-revocation lists (CRLs). This implementation has no support
 *    for CRLs so it is assumed to be an empty list.
 *  - The RFC allows for SignerInfo structure to optionally contain
 *    unauthenticatedAttributes and authenticatedAttributes. In Mbed TLS it is
 *    assumed these fields are empty.
 *  - The RFC allows for the signed Data type to contain contentInfo. This
 *    implementation assumes the type is DATA and the content is empty.
 */

#ifndef AWRTC_MBEDTLS_PKCS7_H
#define AWRTC_MBEDTLS_PKCS7_H

#include "private_access.h"

#include "build_info.h"

#include "asn1.h"
#include "x509_crt.h"

/**
 * \name PKCS #7 Module Error codes
 * \{
 */
#define AWRTC_MBEDTLS_ERR_PKCS7_INVALID_FORMAT                   -0x5300  /**< The format is invalid, e.g. different type expected. */
#define AWRTC_MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE              -0x5380  /**< Unavailable feature, e.g. anything other than signed data. */
#define AWRTC_MBEDTLS_ERR_PKCS7_INVALID_VERSION                  -0x5400  /**< The PKCS #7 version element is invalid or cannot be parsed. */
#define AWRTC_MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO             -0x5480  /**< The PKCS #7 content info is invalid or cannot be parsed. */
#define AWRTC_MBEDTLS_ERR_PKCS7_INVALID_ALG                      -0x5500  /**< The algorithm tag or value is invalid or cannot be parsed. */
#define AWRTC_MBEDTLS_ERR_PKCS7_INVALID_CERT                     -0x5580  /**< The certificate tag or value is invalid or cannot be parsed. */
#define AWRTC_MBEDTLS_ERR_PKCS7_INVALID_SIGNATURE                -0x5600  /**< Error parsing the signature */
#define AWRTC_MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO              -0x5680  /**< Error parsing the signer's info */
#define AWRTC_MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA                   -0x5700  /**< Input invalid. */
#define AWRTC_MBEDTLS_ERR_PKCS7_ALLOC_FAILED                     -0x5780  /**< Allocation of memory failed. */
#define AWRTC_MBEDTLS_ERR_PKCS7_VERIFY_FAIL                      -0x5800  /**< Verification Failed */
#define AWRTC_MBEDTLS_ERR_PKCS7_CERT_DATE_INVALID                -0x5880  /**< The PKCS #7 date issued/expired dates are invalid */
/* \} name */

/**
 * \name PKCS #7 Supported Version
 * \{
 */
#define AWRTC_MBEDTLS_PKCS7_SUPPORTED_VERSION                           0x01
/* \} name */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Type-length-value structure that allows for ASN.1 using DER.
 */
typedef awrtc_mbedtls_asn1_buf awrtc_mbedtls_pkcs7_buf;

/**
 * Container for ASN.1 named information objects.
 * It allows for Relative Distinguished Names (e.g. cn=localhost,ou=code,etc.).
 */
typedef awrtc_mbedtls_asn1_named_data awrtc_mbedtls_pkcs7_name;

/**
 * Container for a sequence of ASN.1 items
 */
typedef awrtc_mbedtls_asn1_sequence awrtc_mbedtls_pkcs7_sequence;

/**
 * PKCS #7 types
 */
typedef enum {
    AWRTC_MBEDTLS_PKCS7_NONE=0,
    AWRTC_MBEDTLS_PKCS7_DATA,
    AWRTC_MBEDTLS_PKCS7_SIGNED_DATA,
    AWRTC_MBEDTLS_PKCS7_ENVELOPED_DATA,
    AWRTC_MBEDTLS_PKCS7_SIGNED_AND_ENVELOPED_DATA,
    AWRTC_MBEDTLS_PKCS7_DIGESTED_DATA,
    AWRTC_MBEDTLS_PKCS7_ENCRYPTED_DATA,
}
awrtc_mbedtls_pkcs7_type;

/**
 * Structure holding PKCS #7 signer info
 */
typedef struct awrtc_mbedtls_pkcs7_signer_info {
    int AWRTC_MBEDTLS_PRIVATE(version);
    awrtc_mbedtls_x509_buf AWRTC_MBEDTLS_PRIVATE(serial);
    awrtc_mbedtls_x509_name AWRTC_MBEDTLS_PRIVATE(issuer);
    awrtc_mbedtls_x509_buf AWRTC_MBEDTLS_PRIVATE(issuer_raw);
    awrtc_mbedtls_x509_buf AWRTC_MBEDTLS_PRIVATE(alg_identifier);
    awrtc_mbedtls_x509_buf AWRTC_MBEDTLS_PRIVATE(sig_alg_identifier);
    awrtc_mbedtls_x509_buf AWRTC_MBEDTLS_PRIVATE(sig);
    struct awrtc_mbedtls_pkcs7_signer_info *AWRTC_MBEDTLS_PRIVATE(next);
}
awrtc_mbedtls_pkcs7_signer_info;

/**
 * Structure holding the signed data section
 */
typedef struct awrtc_mbedtls_pkcs7_signed_data {
    int AWRTC_MBEDTLS_PRIVATE(version);
    awrtc_mbedtls_pkcs7_buf AWRTC_MBEDTLS_PRIVATE(digest_alg_identifiers);
    int AWRTC_MBEDTLS_PRIVATE(no_of_certs);
    awrtc_mbedtls_x509_crt AWRTC_MBEDTLS_PRIVATE(certs);
    int AWRTC_MBEDTLS_PRIVATE(no_of_crls);
    awrtc_mbedtls_x509_crl AWRTC_MBEDTLS_PRIVATE(crl);
    int AWRTC_MBEDTLS_PRIVATE(no_of_signers);
    awrtc_mbedtls_pkcs7_signer_info AWRTC_MBEDTLS_PRIVATE(signers);
}
awrtc_mbedtls_pkcs7_signed_data;

/**
 * Structure holding PKCS #7 structure, only signed data for now
 */
typedef struct awrtc_mbedtls_pkcs7 {
    awrtc_mbedtls_pkcs7_buf AWRTC_MBEDTLS_PRIVATE(raw);
    awrtc_mbedtls_pkcs7_signed_data AWRTC_MBEDTLS_PRIVATE(signed_data);
}
awrtc_mbedtls_pkcs7;

/**
 * \brief          Initialize awrtc_mbedtls_pkcs7 structure.
 *
 * \param pkcs7    awrtc_mbedtls_pkcs7 structure.
 */
void awrtc_mbedtls_pkcs7_init(awrtc_mbedtls_pkcs7 *pkcs7);

/**
 * \brief          Parse a single DER formatted PKCS #7 detached signature.
 *
 * \param pkcs7    The awrtc_mbedtls_pkcs7 structure to be filled by the parser.
 * \param buf      The buffer holding only the DER encoded PKCS #7 content.
 * \param buflen   The size in bytes of \p buf. The size must be exactly the
 *                 length of the DER encoded PKCS #7 content.
 *
 * \note           This function makes an internal copy of the PKCS #7 buffer
 *                 \p buf. In particular, \p buf may be destroyed or reused
 *                 after this call returns.
 * \note           Signatures with internal data are not supported.
 *
 * \return         The \c awrtc_mbedtls_pkcs7_type of \p buf, if successful.
 * \return         A negative error code on failure.
 */
int awrtc_mbedtls_pkcs7_parse_der(awrtc_mbedtls_pkcs7 *pkcs7, const unsigned char *buf,
                            const size_t buflen);

/**
 * \brief          Verification of PKCS #7 signature against a caller-supplied
 *                 certificate.
 *
 *                 For each signer in the PKCS structure, this function computes
 *                 a signature over the supplied data, using the supplied
 *                 certificate and the same digest algorithm as specified by the
 *                 signer. It then compares this signature against the
 *                 signer's signature; verification succeeds if any comparison
 *                 matches.
 *
 *                 This function does not use the certificates held within the
 *                 PKCS #7 structure itself, and does not check that the
 *                 certificate is signed by a trusted certification authority.
 *
 * \param pkcs7    awrtc_mbedtls_pkcs7 structure containing signature.
 * \param cert     Certificate containing key to verify signature.
 * \param data     Plain data on which signature has to be verified.
 * \param datalen  Length of the data.
 *
 * \note           This function internally calculates the hash on the supplied
 *                 plain data for signature verification.
 *
 * \return         0 if the signature verifies, or a negative error code on failure.
 */
int awrtc_mbedtls_pkcs7_signed_data_verify(awrtc_mbedtls_pkcs7 *pkcs7,
                                     const awrtc_mbedtls_x509_crt *cert,
                                     const unsigned char *data,
                                     size_t datalen);

/**
 * \brief          Verification of PKCS #7 signature against a caller-supplied
 *                 certificate.
 *
 *                 For each signer in the PKCS structure, this function
 *                 validates a signature over the supplied hash, using the
 *                 supplied certificate and the same digest algorithm as
 *                 specified by the signer. Verification succeeds if any
 *                 signature is good.
 *
 *                 This function does not use the certificates held within the
 *                 PKCS #7 structure itself, and does not check that the
 *                 certificate is signed by a trusted certification authority.
 *
 * \param pkcs7    PKCS #7 structure containing signature.
 * \param cert     Certificate containing key to verify signature.
 * \param hash     Hash of the plain data on which signature has to be verified.
 * \param hashlen  Length of the hash.
 *
 * \note           This function is different from awrtc_mbedtls_pkcs7_signed_data_verify()
 *                 in that it is directly passed the hash of the data.
 *
 * \return         0 if the signature verifies, or a negative error code on failure.
 */
int awrtc_mbedtls_pkcs7_signed_hash_verify(awrtc_mbedtls_pkcs7 *pkcs7,
                                     const awrtc_mbedtls_x509_crt *cert,
                                     const unsigned char *hash, size_t hashlen);

/**
 * \brief          Unallocate all PKCS #7 data and zeroize the memory.
 *                 It doesn't free \p pkcs7 itself. This should be done by the caller.
 *
 * \param pkcs7    awrtc_mbedtls_pkcs7 structure to free.
 */
void awrtc_mbedtls_pkcs7_free(awrtc_mbedtls_pkcs7 *pkcs7);

#ifdef __cplusplus
}
#endif

#endif /* pkcs7.h */
