/**
 * \file x509_crt.h
 *
 * \brief X.509 certificate parsing and writing
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef AWRTC_MBEDTLS_X509_CRT_H
#define AWRTC_MBEDTLS_X509_CRT_H
#include "private_access.h"

#include "build_info.h"

#include "x509.h"
#include "x509_crl.h"
#include "bignum.h"

/**
 * \addtogroup x509_module
 * \{
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \name Structures and functions for parsing and writing X.509 certificates
 * \{
 */

/**
 * Container for an X.509 certificate. The certificate may be chained.
 *
 * Some fields of this structure are publicly readable. Do not modify
 * them except via Mbed TLS library functions: the effect of modifying
 * those fields or the data that those fields points to is unspecified.
 */
typedef struct awrtc_mbedtls_x509_crt {
    int AWRTC_MBEDTLS_PRIVATE(own_buffer);                     /**< Indicates if \c raw is owned
                                                          *   by the structure or not.        */
    awrtc_mbedtls_x509_buf raw;               /**< The raw certificate data (DER). */
    awrtc_mbedtls_x509_buf tbs;               /**< The raw certificate body (DER). The part that is To Be Signed. */

    int version;                /**< The X.509 version. (1=v1, 2=v2, 3=v3) */
    awrtc_mbedtls_x509_buf serial;            /**< Unique id for certificate issued by a specific CA. */
    awrtc_mbedtls_x509_buf sig_oid;           /**< Signature algorithm, e.g. sha1RSA */

    awrtc_mbedtls_x509_buf issuer_raw;        /**< The raw issuer data (DER). Used for quick comparison. */
    awrtc_mbedtls_x509_buf subject_raw;       /**< The raw subject data (DER). Used for quick comparison. */

    awrtc_mbedtls_x509_name issuer;           /**< The parsed issuer data (named information object). */
    awrtc_mbedtls_x509_name subject;          /**< The parsed subject data (named information object). */

    awrtc_mbedtls_x509_time valid_from;       /**< Start time of certificate validity. */
    awrtc_mbedtls_x509_time valid_to;         /**< End time of certificate validity. */

    awrtc_mbedtls_x509_buf pk_raw;
    awrtc_mbedtls_pk_context pk;              /**< Container for the public key context. */

    awrtc_mbedtls_x509_buf issuer_id;         /**< Optional X.509 v2/v3 issuer unique identifier. */
    awrtc_mbedtls_x509_buf subject_id;        /**< Optional X.509 v2/v3 subject unique identifier. */
    awrtc_mbedtls_x509_buf v3_ext;            /**< Optional X.509 v3 extensions.  */
    awrtc_mbedtls_x509_sequence subject_alt_names; /**< Optional list of raw entries of Subject Alternative Names extension. These can be later parsed by awrtc_mbedtls_x509_parse_subject_alt_name. */
    awrtc_mbedtls_x509_buf subject_key_id;    /**< Optional X.509 v3 extension subject key identifier. */
    awrtc_mbedtls_x509_authority authority_key_id;    /**< Optional X.509 v3 extension authority key identifier. */

    awrtc_mbedtls_x509_sequence certificate_policies; /**< Optional list of certificate policies (Only anyPolicy is printed and enforced, however the rest of the policies are still listed). */

    int AWRTC_MBEDTLS_PRIVATE(ext_types);              /**< Bit string containing detected and parsed extensions */
    int AWRTC_MBEDTLS_PRIVATE(ca_istrue);              /**< Optional Basic Constraint extension value: 1 if this certificate belongs to a CA, 0 otherwise. */
    int AWRTC_MBEDTLS_PRIVATE(max_pathlen);            /**< Optional Basic Constraint extension value: The maximum path length to the root certificate. Path length is 1 higher than RFC 5280 'meaning', so 1+ */

    unsigned int AWRTC_MBEDTLS_PRIVATE(key_usage);     /**< Optional key usage extension value: See the values in x509.h */

    awrtc_mbedtls_x509_sequence ext_key_usage; /**< Optional list of extended key usage OIDs. */

    unsigned char AWRTC_MBEDTLS_PRIVATE(ns_cert_type); /**< Optional Netscape certificate type extension value: See the values in x509.h */

    awrtc_mbedtls_x509_buf AWRTC_MBEDTLS_PRIVATE(sig);               /**< Signature: hash of the tbs part signed with the private key. */
    awrtc_mbedtls_md_type_t AWRTC_MBEDTLS_PRIVATE(sig_md);           /**< Internal representation of the MD algorithm of the signature algorithm, e.g. AWRTC_MBEDTLS_MD_SHA256 */
    awrtc_mbedtls_pk_type_t AWRTC_MBEDTLS_PRIVATE(sig_pk);           /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. AWRTC_MBEDTLS_PK_RSA */
    void *AWRTC_MBEDTLS_PRIVATE(sig_opts);             /**< Signature options to be passed to awrtc_mbedtls_pk_verify_ext(), e.g. for RSASSA-PSS */

    /** Next certificate in the linked list that constitutes the CA chain.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct awrtc_mbedtls_x509_crt *next;
}
awrtc_mbedtls_x509_crt;

/**
 * Build flag from an algorithm/curve identifier (pk, md, ecp)
 * Since 0 is always XXX_NONE, ignore it.
 */
#define AWRTC_MBEDTLS_X509_ID_FLAG(id)   (1 << ((id) - 1))

/**
 * Security profile for certificate verification.
 *
 * All lists are bitfields, built by ORing flags from AWRTC_MBEDTLS_X509_ID_FLAG().
 *
 * The fields of this structure are part of the public API and can be
 * manipulated directly by applications. Future versions of the library may
 * add extra fields or reorder existing fields.
 *
 * You can create custom profiles by starting from a copy of
 * an existing profile, such as awrtc_mbedtls_x509_crt_profile_default or
 * awrtc_mbedtls_x509_ctr_profile_none and then tune it to your needs.
 *
 * For example to allow SHA-224 in addition to the default:
 *
 *  awrtc_mbedtls_x509_crt_profile my_profile = awrtc_mbedtls_x509_crt_profile_default;
 *  my_profile.allowed_mds |= AWRTC_MBEDTLS_X509_ID_FLAG( AWRTC_MBEDTLS_MD_SHA224 );
 *
 * Or to allow only RSA-3072+ with SHA-256:
 *
 *  awrtc_mbedtls_x509_crt_profile my_profile = awrtc_mbedtls_x509_crt_profile_none;
 *  my_profile.allowed_mds = AWRTC_MBEDTLS_X509_ID_FLAG( AWRTC_MBEDTLS_MD_SHA256 );
 *  my_profile.allowed_pks = AWRTC_MBEDTLS_X509_ID_FLAG( AWRTC_MBEDTLS_PK_RSA );
 *  my_profile.rsa_min_bitlen = 3072;
 */
typedef struct awrtc_mbedtls_x509_crt_profile {
    uint32_t allowed_mds;       /**< MDs for signatures         */
    uint32_t allowed_pks;       /**< PK algs for public keys;
                                 *   this applies to all certificates
                                 *   in the provided chain.     */
    uint32_t allowed_curves;    /**< Elliptic curves for ECDSA  */
    uint32_t rsa_min_bitlen;    /**< Minimum size for RSA keys  */
}
awrtc_mbedtls_x509_crt_profile;

#define AWRTC_MBEDTLS_X509_CRT_VERSION_1              0
#define AWRTC_MBEDTLS_X509_CRT_VERSION_2              1
#define AWRTC_MBEDTLS_X509_CRT_VERSION_3              2

#define AWRTC_MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN 20
#define AWRTC_MBEDTLS_X509_RFC5280_UTC_TIME_LEN   15

#if !defined(AWRTC_MBEDTLS_X509_MAX_FILE_PATH_LEN)
#define AWRTC_MBEDTLS_X509_MAX_FILE_PATH_LEN 512
#endif

/* This macro unfolds to the concatenation of macro invocations
 * X509_CRT_ERROR_INFO( error code,
 *                             error code as string,
 *                             human readable description )
 * where X509_CRT_ERROR_INFO is defined by the user.
 * See x509_crt.c for an example of how to use this. */
#define AWRTC_MBEDTLS_X509_CRT_ERROR_INFO_LIST                                  \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_EXPIRED,            \
                        "AWRTC_MBEDTLS_X509_BADCERT_EXPIRED",          \
                        "The certificate validity has expired") \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_REVOKED,            \
                        "AWRTC_MBEDTLS_X509_BADCERT_REVOKED",          \
                        "The certificate has been revoked (is on a CRL)") \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_CN_MISMATCH,                  \
                        "AWRTC_MBEDTLS_X509_BADCERT_CN_MISMATCH",                \
                        "The certificate Common Name (CN) does not match with the expected CN") \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_NOT_TRUSTED,                             \
                        "AWRTC_MBEDTLS_X509_BADCERT_NOT_TRUSTED",                           \
                        "The certificate is not correctly signed by the trusted CA") \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCRL_NOT_TRUSTED,                      \
                        "AWRTC_MBEDTLS_X509_BADCRL_NOT_TRUSTED",                    \
                        "The CRL is not correctly signed by the trusted CA") \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCRL_EXPIRED,    \
                        "AWRTC_MBEDTLS_X509_BADCRL_EXPIRED",  \
                        "The CRL is expired")          \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_MISSING,   \
                        "AWRTC_MBEDTLS_X509_BADCERT_MISSING", \
                        "Certificate was missing")     \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_SKIP_VERIFY,         \
                        "AWRTC_MBEDTLS_X509_BADCERT_SKIP_VERIFY",       \
                        "Certificate verification was skipped")  \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_OTHER,                          \
                        "AWRTC_MBEDTLS_X509_BADCERT_OTHER",                        \
                        "Other reason (can be used by verify callback)")    \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_FUTURE,                         \
                        "AWRTC_MBEDTLS_X509_BADCERT_FUTURE",                       \
                        "The certificate validity starts in the future")    \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCRL_FUTURE,     \
                        "AWRTC_MBEDTLS_X509_BADCRL_FUTURE",   \
                        "The CRL is from the future")  \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_KEY_USAGE,                      \
                        "AWRTC_MBEDTLS_X509_BADCERT_KEY_USAGE",                    \
                        "Usage does not match the keyUsage extension")      \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_EXT_KEY_USAGE,                       \
                        "AWRTC_MBEDTLS_X509_BADCERT_EXT_KEY_USAGE",                     \
                        "Usage does not match the extendedKeyUsage extension")   \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_NS_CERT_TYPE,                        \
                        "AWRTC_MBEDTLS_X509_BADCERT_NS_CERT_TYPE",                      \
                        "Usage does not match the nsCertType extension")         \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_BAD_MD,                              \
                        "AWRTC_MBEDTLS_X509_BADCERT_BAD_MD",                            \
                        "The certificate is signed with an unacceptable hash.")  \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_BAD_PK,                                                  \
                        "AWRTC_MBEDTLS_X509_BADCERT_BAD_PK",                                                \
                        "The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA).")  \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCERT_BAD_KEY,                                                            \
                        "AWRTC_MBEDTLS_X509_BADCERT_BAD_KEY",                                                          \
                        "The certificate is signed with an unacceptable key (eg bad curve, RSA too short).")    \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCRL_BAD_MD,                          \
                        "AWRTC_MBEDTLS_X509_BADCRL_BAD_MD",                        \
                        "The CRL is signed with an unacceptable hash.")     \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCRL_BAD_PK,                                            \
                        "AWRTC_MBEDTLS_X509_BADCRL_BAD_PK",                                          \
                        "The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA).")   \
    X509_CRT_ERROR_INFO(AWRTC_MBEDTLS_X509_BADCRL_BAD_KEY,                                                    \
                        "AWRTC_MBEDTLS_X509_BADCRL_BAD_KEY",                                                  \
                        "The CRL is signed with an unacceptable key (eg bad curve, RSA too short).")

/**
 * Container for writing a certificate (CRT)
 */
typedef struct awrtc_mbedtls_x509write_cert {
    int AWRTC_MBEDTLS_PRIVATE(version);
    unsigned char AWRTC_MBEDTLS_PRIVATE(serial)[AWRTC_MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN];
    size_t AWRTC_MBEDTLS_PRIVATE(serial_len);
    awrtc_mbedtls_pk_context *AWRTC_MBEDTLS_PRIVATE(subject_key);
    awrtc_mbedtls_pk_context *AWRTC_MBEDTLS_PRIVATE(issuer_key);
    awrtc_mbedtls_asn1_named_data *AWRTC_MBEDTLS_PRIVATE(subject);
    awrtc_mbedtls_asn1_named_data *AWRTC_MBEDTLS_PRIVATE(issuer);
    awrtc_mbedtls_md_type_t AWRTC_MBEDTLS_PRIVATE(md_alg);
    char AWRTC_MBEDTLS_PRIVATE(not_before)[AWRTC_MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    char AWRTC_MBEDTLS_PRIVATE(not_after)[AWRTC_MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    awrtc_mbedtls_asn1_named_data *AWRTC_MBEDTLS_PRIVATE(extensions);
}
awrtc_mbedtls_x509write_cert;

/**
 * \brief           Set Subject Alternative Name
 *
 * \param ctx       Certificate context to use
 * \param san_list  List of SAN values
 *
 * \return          0 if successful, or AWRTC_MBEDTLS_ERR_X509_ALLOC_FAILED
 *
 * \note            "dnsName", "uniformResourceIdentifier", "IP address",
 *                  "otherName", and "DirectoryName", as defined in RFC 5280,
 *                  are supported.
 */
int awrtc_mbedtls_x509write_crt_set_subject_alternative_name(awrtc_mbedtls_x509write_cert *ctx,
                                                       const awrtc_mbedtls_x509_san_list *san_list);

/**
 * Item in a verification chain: cert and flags for it
 */
typedef struct {
    awrtc_mbedtls_x509_crt *AWRTC_MBEDTLS_PRIVATE(crt);
    uint32_t AWRTC_MBEDTLS_PRIVATE(flags);
} awrtc_mbedtls_x509_crt_verify_chain_item;

/**
 * Max size of verification chain: end-entity + intermediates + trusted root
 */
#define AWRTC_MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE  (AWRTC_MBEDTLS_X509_MAX_INTERMEDIATE_CA + 2)

/**
 * Verification chain as built by \c awrtc_mbedtls_crt_verify_chain()
 */
typedef struct {
    awrtc_mbedtls_x509_crt_verify_chain_item AWRTC_MBEDTLS_PRIVATE(items)[AWRTC_MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE];
    unsigned AWRTC_MBEDTLS_PRIVATE(len);

#if defined(AWRTC_MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    /* This stores the list of potential trusted signers obtained from
     * the CA callback used for the CRT verification, if configured.
     * We must track it somewhere because the callback passes its
     * ownership to the caller. */
    awrtc_mbedtls_x509_crt *AWRTC_MBEDTLS_PRIVATE(trust_ca_cb_result);
#endif /* AWRTC_MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */
} awrtc_mbedtls_x509_crt_verify_chain;

#if defined(AWRTC_MBEDTLS_ECDSA_C) && defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)

/**
 * \brief       Context for resuming X.509 verify operations
 */
typedef struct {
    /* for check_signature() */
    awrtc_mbedtls_pk_restart_ctx AWRTC_MBEDTLS_PRIVATE(pk);

    /* for find_parent_in() */
    awrtc_mbedtls_x509_crt *AWRTC_MBEDTLS_PRIVATE(parent); /* non-null iff parent_in in progress */
    awrtc_mbedtls_x509_crt *AWRTC_MBEDTLS_PRIVATE(fallback_parent);
    int AWRTC_MBEDTLS_PRIVATE(fallback_signature_is_good);

    /* for find_parent() */
    int AWRTC_MBEDTLS_PRIVATE(parent_is_trusted); /* -1 if find_parent is not in progress */

    /* for verify_chain() */
    enum {
        x509_crt_rs_none,
        x509_crt_rs_find_parent,
    } AWRTC_MBEDTLS_PRIVATE(in_progress);  /* none if no operation is in progress */
    int AWRTC_MBEDTLS_PRIVATE(self_cnt);
    awrtc_mbedtls_x509_crt_verify_chain AWRTC_MBEDTLS_PRIVATE(ver_chain);

} awrtc_mbedtls_x509_crt_restart_ctx;

#else /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */

/* Now we can declare functions that take a pointer to that */
typedef void awrtc_mbedtls_x509_crt_restart_ctx;

#endif /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */

#if defined(AWRTC_MBEDTLS_X509_CRT_PARSE_C)
/**
 * Default security profile. Should provide a good balance between security
 * and compatibility with current deployments.
 *
 * This profile permits:
 * - SHA2 hashes with at least 256 bits: SHA-256, SHA-384, SHA-512.
 * - Elliptic curves with 255 bits and above except secp256k1.
 * - RSA with 2048 bits and above.
 *
 * New minor versions of Mbed TLS may extend this profile, for example if
 * new algorithms are added to the library. New minor versions of Mbed TLS will
 * not reduce this profile unless serious security concerns require it.
 */
extern const awrtc_mbedtls_x509_crt_profile awrtc_mbedtls_x509_crt_profile_default;

/**
 * Expected next default profile. Recommended for new deployments.
 * Currently targets a 128-bit security level, except for allowing RSA-2048.
 * This profile may change at any time.
 */
extern const awrtc_mbedtls_x509_crt_profile awrtc_mbedtls_x509_crt_profile_next;

/**
 * NSA Suite B profile.
 */
extern const awrtc_mbedtls_x509_crt_profile awrtc_mbedtls_x509_crt_profile_suiteb;

/**
 * Empty profile that allows nothing. Useful as a basis for constructing
 * custom profiles.
 */
extern const awrtc_mbedtls_x509_crt_profile awrtc_mbedtls_x509_crt_profile_none;

/**
 * \brief          Parse a single DER formatted certificate and add it
 *                 to the end of the provided chained list.
 *
 * \note           If #AWRTC_MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 awrtc_psa_crypto_init() before calling this function.
 *
 * \param chain    The pointer to the start of the CRT chain to attach to.
 *                 When parsing the first CRT in a chain, this should point
 *                 to an instance of ::awrtc_mbedtls_x509_crt initialized through
 *                 awrtc_mbedtls_x509_crt_init().
 * \param buf      The buffer holding the DER encoded certificate.
 * \param buflen   The size in Bytes of \p buf.
 *
 * \note           This function makes an internal copy of the CRT buffer
 *                 \p buf. In particular, \p buf may be destroyed or reused
 *                 after this call returns. To avoid duplicating the CRT
 *                 buffer (at the cost of stricter lifetime constraints),
 *                 use awrtc_mbedtls_x509_crt_parse_der_nocopy() instead.
 *
 * \return         \c 0 if successful.
 * \return         A negative error code on failure.
 */
int awrtc_mbedtls_x509_crt_parse_der(awrtc_mbedtls_x509_crt *chain,
                               const unsigned char *buf,
                               size_t buflen);

/**
 * \brief          The type of certificate extension callbacks.
 *
 *                 Callbacks of this type are passed to and used by the
 *                 awrtc_mbedtls_x509_crt_parse_der_with_ext_cb() routine when
 *                 it encounters either an unsupported extension or a
 *                 "certificate policies" extension containing any
 *                 unsupported certificate policies.
 *                 Future versions of the library may invoke the callback
 *                 in other cases, if and when the need arises.
 *
 * \param p_ctx    An opaque context passed to the callback.
 * \param crt      The certificate being parsed.
 * \param oid      The OID of the extension.
 * \param critical Whether the extension is critical.
 * \param p        Pointer to the start of the extension value
 *                 (the content of the OCTET STRING).
 * \param end      End of extension value.
 *
 * \note           The callback must fail and return a negative error code
 *                 if it can not parse or does not support the extension.
 *                 When the callback fails to parse a critical extension
 *                 awrtc_mbedtls_x509_crt_parse_der_with_ext_cb() also fails.
 *                 When the callback fails to parse a non critical extension
 *                 awrtc_mbedtls_x509_crt_parse_der_with_ext_cb() simply skips
 *                 the extension and continues parsing.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
typedef int (*awrtc_mbedtls_x509_crt_ext_cb_t)(void *p_ctx,
                                         awrtc_mbedtls_x509_crt const *crt,
                                         awrtc_mbedtls_x509_buf const *oid,
                                         int critical,
                                         const unsigned char *p,
                                         const unsigned char *end);

/**
 * \brief            Parse a single DER formatted certificate and add it
 *                   to the end of the provided chained list.
 *
 * \note             If #AWRTC_MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                   subsystem must have been initialized by calling
 *                   awrtc_psa_crypto_init() before calling this function.
 *
 * \param chain      The pointer to the start of the CRT chain to attach to.
 *                   When parsing the first CRT in a chain, this should point
 *                   to an instance of ::awrtc_mbedtls_x509_crt initialized through
 *                   awrtc_mbedtls_x509_crt_init().
 * \param buf        The buffer holding the DER encoded certificate.
 * \param buflen     The size in Bytes of \p buf.
 * \param make_copy  When not zero this function makes an internal copy of the
 *                   CRT buffer \p buf. In particular, \p buf may be destroyed
 *                   or reused after this call returns.
 *                   When zero this function avoids duplicating the CRT buffer
 *                   by taking temporary ownership thereof until the CRT
 *                   is destroyed (like awrtc_mbedtls_x509_crt_parse_der_nocopy())
 * \param cb         A callback invoked for every unsupported certificate
 *                   extension.
 * \param p_ctx      An opaque context passed to the callback.
 *
 * \note             This call is functionally equivalent to
 *                   awrtc_mbedtls_x509_crt_parse_der(), and/or
 *                   awrtc_mbedtls_x509_crt_parse_der_nocopy()
 *                   but it calls the callback with every unsupported
 *                   certificate extension and additionally the
 *                   "certificate policies" extension if it contains any
 *                   unsupported certificate policies.
 *                   The callback must return a negative error code if it
 *                   does not know how to handle such an extension.
 *                   When the callback fails to parse a critical extension
 *                   awrtc_mbedtls_x509_crt_parse_der_with_ext_cb() also fails.
 *                   When the callback fails to parse a non critical extension
 *                   awrtc_mbedtls_x509_crt_parse_der_with_ext_cb() simply skips
 *                   the extension and continues parsing.
 *                   Future versions of the library may invoke the callback
 *                   in other cases, if and when the need arises.
 *
 * \return           \c 0 if successful.
 * \return           A negative error code on failure.
 */
int awrtc_mbedtls_x509_crt_parse_der_with_ext_cb(awrtc_mbedtls_x509_crt *chain,
                                           const unsigned char *buf,
                                           size_t buflen,
                                           int make_copy,
                                           awrtc_mbedtls_x509_crt_ext_cb_t cb,
                                           void *p_ctx);

/**
 * \brief          Parse a single DER formatted certificate and add it
 *                 to the end of the provided chained list. This is a
 *                 variant of awrtc_mbedtls_x509_crt_parse_der() which takes
 *                 temporary ownership of the CRT buffer until the CRT
 *                 is destroyed.
 *
 * \note           If #AWRTC_MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 awrtc_psa_crypto_init() before calling this function.
 *
 * \param chain    The pointer to the start of the CRT chain to attach to.
 *                 When parsing the first CRT in a chain, this should point
 *                 to an instance of ::awrtc_mbedtls_x509_crt initialized through
 *                 awrtc_mbedtls_x509_crt_init().
 * \param buf      The address of the readable buffer holding the DER encoded
 *                 certificate to use. On success, this buffer must be
 *                 retained and not be changed for the lifetime of the
 *                 CRT chain \p chain, that is, until \p chain is destroyed
 *                 through a call to awrtc_mbedtls_x509_crt_free().
 * \param buflen   The size in Bytes of \p buf.
 *
 * \note           This call is functionally equivalent to
 *                 awrtc_mbedtls_x509_crt_parse_der(), but it avoids creating a
 *                 copy of the input buffer at the cost of stronger lifetime
 *                 constraints. This is useful in constrained environments
 *                 where duplication of the CRT cannot be tolerated.
 *
 * \return         \c 0 if successful.
 * \return         A negative error code on failure.
 */
int awrtc_mbedtls_x509_crt_parse_der_nocopy(awrtc_mbedtls_x509_crt *chain,
                                      const unsigned char *buf,
                                      size_t buflen);

/**
 * \brief          Parse one DER-encoded or one or more concatenated PEM-encoded
 *                 certificates and add them to the chained list.
 *
 *                 For CRTs in PEM encoding, the function parses permissively:
 *                 if at least one certificate can be parsed, the function
 *                 returns the number of certificates for which parsing failed
 *                 (hence \c 0 if all certificates were parsed successfully).
 *                 If no certificate could be parsed, the function returns
 *                 the first (negative) error encountered during parsing.
 *
 *                 PEM encoded certificates may be interleaved by other data
 *                 such as human readable descriptions of their content, as
 *                 long as the certificates are enclosed in the PEM specific
 *                 '-----{BEGIN/END} CERTIFICATE-----' delimiters.
 *
 * \note           If #AWRTC_MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 awrtc_psa_crypto_init() before calling this function.
 *
 * \param chain    The chain to which to add the parsed certificates.
 * \param buf      The buffer holding the certificate data in PEM or DER format.
 *                 For certificates in PEM encoding, this may be a concatenation
 *                 of multiple certificates; for DER encoding, the buffer must
 *                 comprise exactly one certificate.
 * \param buflen   The size of \p buf, including the terminating \c NULL byte
 *                 in case of PEM encoded data.
 *
 * \return         \c 0 if all certificates were parsed successfully.
 * \return         The (positive) number of certificates that couldn't
 *                 be parsed if parsing was partly successful (see above).
 * \return         A negative X509 or PEM error code otherwise.
 *
 */
int awrtc_mbedtls_x509_crt_parse(awrtc_mbedtls_x509_crt *chain, const unsigned char *buf, size_t buflen);

#if defined(AWRTC_MBEDTLS_FS_IO)
/**
 * \brief          Load one or more certificates and add them
 *                 to the chained list. Parses permissively. If some
 *                 certificates can be parsed, the result is the number
 *                 of failed certificates it encountered. If none complete
 *                 correctly, the first error is returned.
 *
 * \note           If #AWRTC_MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 awrtc_psa_crypto_init() before calling this function.
 *
 * \param chain    points to the start of the chain
 * \param path     filename to read the certificates from
 *
 * \return         0 if all certificates parsed successfully, a positive number
 *                 if partly successful or a specific X509 or PEM error code
 */
int awrtc_mbedtls_x509_crt_parse_file(awrtc_mbedtls_x509_crt *chain, const char *path);

/**
 * \brief          Load one or more certificate files from a path and add them
 *                 to the chained list. Parses permissively. If some
 *                 certificates can be parsed, the result is the number
 *                 of failed certificates it encountered. If none complete
 *                 correctly, the first error is returned.
 *
 * \param chain    points to the start of the chain
 * \param path     directory / folder to read the certificate files from
 *
 * \return         0 if all certificates parsed successfully, a positive number
 *                 if partly successful or a specific X509 or PEM error code
 */
int awrtc_mbedtls_x509_crt_parse_path(awrtc_mbedtls_x509_crt *chain, const char *path);

#endif /* AWRTC_MBEDTLS_FS_IO */

#if !defined(AWRTC_MBEDTLS_X509_REMOVE_INFO)
/**
 * \brief          Returns an informational string about the
 *                 certificate.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param prefix   A line prefix
 * \param crt      The X509 certificate to represent
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int awrtc_mbedtls_x509_crt_info(char *buf, size_t size, const char *prefix,
                          const awrtc_mbedtls_x509_crt *crt);

/**
 * \brief          Returns an informational string about the
 *                 verification status of a certificate.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param prefix   A line prefix
 * \param flags    Verification flags created by awrtc_mbedtls_x509_crt_verify()
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int awrtc_mbedtls_x509_crt_verify_info(char *buf, size_t size, const char *prefix,
                                 uint32_t flags);
#endif /* !AWRTC_MBEDTLS_X509_REMOVE_INFO */

/**
 * \brief          Verify a chain of certificates.
 *
 *                 The verify callback is a user-supplied callback that
 *                 can clear / modify / add flags for a certificate. If set,
 *                 the verification callback is called for each
 *                 certificate in the chain (from the trust-ca down to the
 *                 presented crt). The parameters for the callback are:
 *                 (void *parameter, awrtc_mbedtls_x509_crt *crt, int certificate_depth,
 *                 int *flags). With the flags representing current flags for
 *                 that specific certificate and the certificate depth from
 *                 the bottom (Peer cert depth = 0).
 *
 *                 All flags left after returning from the callback
 *                 are also returned to the application. The function should
 *                 return 0 for anything (including invalid certificates)
 *                 other than fatal error, as a non-zero return code
 *                 immediately aborts the verification process. For fatal
 *                 errors, a specific error code should be used (different
 *                 from AWRTC_MBEDTLS_ERR_X509_CERT_VERIFY_FAILED which should not
 *                 be returned at this point), or AWRTC_MBEDTLS_ERR_X509_FATAL_ERROR
 *                 can be used if no better code is available.
 *
 * \note           In case verification failed, the results can be displayed
 *                 using \c awrtc_mbedtls_x509_crt_verify_info()
 *
 * \note           Same as \c awrtc_mbedtls_x509_crt_verify_with_profile() with the
 *                 default security profile.
 *
 * \note           It is your responsibility to provide up-to-date CRLs for
 *                 all trusted CAs. If no CRL is provided for the CA that was
 *                 used to sign the certificate, CRL verification is skipped
 *                 silently, that is *without* setting any flag.
 *
 * \note           The \c trust_ca list can contain two types of certificates:
 *                 (1) those of trusted root CAs, so that certificates
 *                 chaining up to those CAs will be trusted, and (2)
 *                 self-signed end-entity certificates to be trusted (for
 *                 specific peers you know) - in that case, the self-signed
 *                 certificate doesn't need to have the CA bit set.
 *
 * \param crt      The certificate chain to be verified.
 * \param trust_ca The list of trusted CAs.
 * \param ca_crl   The list of CRLs for trusted CAs.
 * \param cn       The expected Common Name. This will be checked to be
 *                 present in the certificate's subjectAltNames extension or,
 *                 if this extension is absent, as a CN component in its
 *                 Subject name. DNS names and IP addresses are fully
 *                 supported, while the URI subtype is partially supported:
 *                 only exact matching, without any normalization procedures
 *                 described in 7.4 of RFC5280, will result in a positive
 *                 URI verification.
 *                 This may be \c NULL if the CN need not be verified.
 * \param flags    The address at which to store the result of the verification.
 *                 If the verification couldn't be completed, the flag value is
 *                 set to (uint32_t) -1.
 * \param f_vrfy   The verification callback to use. See the documentation
 *                 of awrtc_mbedtls_x509_crt_verify() for more information.
 * \param p_vrfy   The context to be passed to \p f_vrfy.
 *
 * \return         \c 0 if the chain is valid with respect to the
 *                 passed CN, CAs, CRLs and security profile.
 * \return         #AWRTC_MBEDTLS_ERR_X509_CERT_VERIFY_FAILED in case the
 *                 certificate chain verification failed. In this case,
 *                 \c *flags will have one or more
 *                 \c AWRTC_MBEDTLS_X509_BADCERT_XXX or \c AWRTC_MBEDTLS_X509_BADCRL_XXX
 *                 flags set.
 * \return         Another negative error code in case of a fatal error
 *                 encountered during the verification process.
 */
int awrtc_mbedtls_x509_crt_verify(awrtc_mbedtls_x509_crt *crt,
                            awrtc_mbedtls_x509_crt *trust_ca,
                            awrtc_mbedtls_x509_crl *ca_crl,
                            const char *cn, uint32_t *flags,
                            int (*f_vrfy)(void *, awrtc_mbedtls_x509_crt *, int, uint32_t *),
                            void *p_vrfy);

/**
 * \brief          Verify a chain of certificates with respect to
 *                 a configurable security profile.
 *
 * \note           Same as \c awrtc_mbedtls_x509_crt_verify(), but with explicit
 *                 security profile.
 *
 * \note           The restrictions on keys (RSA minimum size, allowed curves
 *                 for ECDSA) apply to all certificates: trusted root,
 *                 intermediate CAs if any, and end entity certificate.
 *
 * \param crt      The certificate chain to be verified.
 * \param trust_ca The list of trusted CAs.
 * \param ca_crl   The list of CRLs for trusted CAs.
 * \param profile  The security profile to use for the verification.
 * \param cn       The expected Common Name. This may be \c NULL if the
 *                 CN need not be verified.
 * \param flags    The address at which to store the result of the verification.
 *                 If the verification couldn't be completed, the flag value is
 *                 set to (uint32_t) -1.
 * \param f_vrfy   The verification callback to use. See the documentation
 *                 of awrtc_mbedtls_x509_crt_verify() for more information.
 * \param p_vrfy   The context to be passed to \p f_vrfy.
 *
 * \return         \c 0 if the chain is valid with respect to the
 *                 passed CN, CAs, CRLs and security profile.
 * \return         #AWRTC_MBEDTLS_ERR_X509_CERT_VERIFY_FAILED in case the
 *                 certificate chain verification failed. In this case,
 *                 \c *flags will have one or more
 *                 \c AWRTC_MBEDTLS_X509_BADCERT_XXX or \c AWRTC_MBEDTLS_X509_BADCRL_XXX
 *                 flags set.
 * \return         Another negative error code in case of a fatal error
 *                 encountered during the verification process.
 */
int awrtc_mbedtls_x509_crt_verify_with_profile(awrtc_mbedtls_x509_crt *crt,
                                         awrtc_mbedtls_x509_crt *trust_ca,
                                         awrtc_mbedtls_x509_crl *ca_crl,
                                         const awrtc_mbedtls_x509_crt_profile *profile,
                                         const char *cn, uint32_t *flags,
                                         int (*f_vrfy)(void *, awrtc_mbedtls_x509_crt *, int, uint32_t *),
                                         void *p_vrfy);

/**
 * \brief          Restartable version of \c awrtc_mbedtls_crt_verify_with_profile()
 *
 * \note           Performs the same job as \c awrtc_mbedtls_crt_verify_with_profile()
 *                 but can return early and restart according to the limit
 *                 set with \c awrtc_mbedtls_ecp_set_max_ops() to reduce blocking.
 *
 * \param crt      The certificate chain to be verified.
 * \param trust_ca The list of trusted CAs.
 * \param ca_crl   The list of CRLs for trusted CAs.
 * \param profile  The security profile to use for the verification.
 * \param cn       The expected Common Name. This may be \c NULL if the
 *                 CN need not be verified.
 * \param flags    The address at which to store the result of the verification.
 *                 If the verification couldn't be completed, the flag value is
 *                 set to (uint32_t) -1.
 * \param f_vrfy   The verification callback to use. See the documentation
 *                 of awrtc_mbedtls_x509_crt_verify() for more information.
 * \param p_vrfy   The context to be passed to \p f_vrfy.
 * \param rs_ctx   The restart context to use. This may be set to \c NULL
 *                 to disable restartable ECC.
 *
 * \return         See \c awrtc_mbedtls_crt_verify_with_profile(), or
 * \return         #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                 operations was reached: see \c awrtc_mbedtls_ecp_set_max_ops().
 */
int awrtc_mbedtls_x509_crt_verify_restartable(awrtc_mbedtls_x509_crt *crt,
                                        awrtc_mbedtls_x509_crt *trust_ca,
                                        awrtc_mbedtls_x509_crl *ca_crl,
                                        const awrtc_mbedtls_x509_crt_profile *profile,
                                        const char *cn, uint32_t *flags,
                                        int (*f_vrfy)(void *, awrtc_mbedtls_x509_crt *, int, uint32_t *),
                                        void *p_vrfy,
                                        awrtc_mbedtls_x509_crt_restart_ctx *rs_ctx);

/**
 * \brief               The type of trusted certificate callbacks.
 *
 *                      Callbacks of this type are passed to and used by the CRT
 *                      verification routine awrtc_mbedtls_x509_crt_verify_with_ca_cb()
 *                      when looking for trusted signers of a given certificate.
 *
 *                      On success, the callback returns a list of trusted
 *                      certificates to be considered as potential signers
 *                      for the input certificate.
 *
 * \param p_ctx         An opaque context passed to the callback.
 * \param child         The certificate for which to search a potential signer.
 *                      This will point to a readable certificate.
 * \param candidate_cas The address at which to store the address of the first
 *                      entry in the generated linked list of candidate signers.
 *                      This will not be \c NULL.
 *
 * \note                The callback must only return a non-zero value on a
 *                      fatal error. If, in contrast, the search for a potential
 *                      signer completes without a single candidate, the
 *                      callback must return \c 0 and set \c *candidate_cas
 *                      to \c NULL.
 *
 * \return              \c 0 on success. In this case, \c *candidate_cas points
 *                      to a heap-allocated linked list of instances of
 *                      ::awrtc_mbedtls_x509_crt, and ownership of this list is passed
 *                      to the caller.
 * \return              A negative error code on failure.
 */
typedef int (*awrtc_mbedtls_x509_crt_ca_cb_t)(void *p_ctx,
                                        awrtc_mbedtls_x509_crt const *child,
                                        awrtc_mbedtls_x509_crt **candidate_cas);

#if defined(AWRTC_MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
/**
 * \brief          Version of \c awrtc_mbedtls_x509_crt_verify_with_profile() which
 *                 uses a callback to acquire the list of trusted CA
 *                 certificates.
 *
 * \param crt      The certificate chain to be verified.
 * \param f_ca_cb  The callback to be used to query for potential signers
 *                 of a given child certificate. See the documentation of
 *                 ::awrtc_mbedtls_x509_crt_ca_cb_t for more information.
 * \param p_ca_cb  The opaque context to be passed to \p f_ca_cb.
 * \param profile  The security profile for the verification.
 * \param cn       The expected Common Name. This may be \c NULL if the
 *                 CN need not be verified.
 * \param flags    The address at which to store the result of the verification.
 *                 If the verification couldn't be completed, the flag value is
 *                 set to (uint32_t) -1.
 * \param f_vrfy   The verification callback to use. See the documentation
 *                 of awrtc_mbedtls_x509_crt_verify() for more information.
 * \param p_vrfy   The context to be passed to \p f_vrfy.
 *
 * \return         See \c awrtc_mbedtls_crt_verify_with_profile().
 */
int awrtc_mbedtls_x509_crt_verify_with_ca_cb(awrtc_mbedtls_x509_crt *crt,
                                       awrtc_mbedtls_x509_crt_ca_cb_t f_ca_cb,
                                       void *p_ca_cb,
                                       const awrtc_mbedtls_x509_crt_profile *profile,
                                       const char *cn, uint32_t *flags,
                                       int (*f_vrfy)(void *, awrtc_mbedtls_x509_crt *, int, uint32_t *),
                                       void *p_vrfy);

#endif /* AWRTC_MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */

/**
 * \brief          Check usage of certificate against keyUsage extension.
 *
 * \param crt      Leaf certificate used.
 * \param usage    Intended usage(s) (eg AWRTC_MBEDTLS_X509_KU_KEY_ENCIPHERMENT
 *                 before using the certificate to perform an RSA key
 *                 exchange).
 *
 * \note           Except for decipherOnly and encipherOnly, a bit set in the
 *                 usage argument means this bit MUST be set in the
 *                 certificate. For decipherOnly and encipherOnly, it means
 *                 that bit MAY be set.
 *
 * \return         0 is these uses of the certificate are allowed,
 *                 AWRTC_MBEDTLS_ERR_X509_BAD_INPUT_DATA if the keyUsage extension
 *                 is present but does not match the usage argument.
 *
 * \note           You should only call this function on leaf certificates, on
 *                 (intermediate) CAs the keyUsage extension is automatically
 *                 checked by \c awrtc_mbedtls_x509_crt_verify().
 */
int awrtc_mbedtls_x509_crt_check_key_usage(const awrtc_mbedtls_x509_crt *crt,
                                     unsigned int usage);

/**
 * \brief           Check usage of certificate against extendedKeyUsage.
 *
 * \param crt       Leaf certificate used.
 * \param usage_oid Intended usage (eg AWRTC_MBEDTLS_OID_SERVER_AUTH or
 *                  AWRTC_MBEDTLS_OID_CLIENT_AUTH).
 * \param usage_len Length of usage_oid (eg given by AWRTC_MBEDTLS_OID_SIZE()).
 *
 * \return          0 if this use of the certificate is allowed,
 *                  AWRTC_MBEDTLS_ERR_X509_BAD_INPUT_DATA if not.
 *
 * \note            Usually only makes sense on leaf certificates.
 */
int awrtc_mbedtls_x509_crt_check_extended_key_usage(const awrtc_mbedtls_x509_crt *crt,
                                              const char *usage_oid,
                                              size_t usage_len);

#if defined(AWRTC_MBEDTLS_X509_CRL_PARSE_C)
/**
 * \brief          Verify the certificate revocation status
 *
 * \param crt      a certificate to be verified
 * \param crl      the CRL to verify against
 *
 * \return         1 if the certificate is revoked, 0 otherwise
 *
 */
int awrtc_mbedtls_x509_crt_is_revoked(const awrtc_mbedtls_x509_crt *crt, const awrtc_mbedtls_x509_crl *crl);
#endif /* AWRTC_MBEDTLS_X509_CRL_PARSE_C */

/**
 * \brief          Initialize a certificate (chain)
 *
 * \param crt      Certificate chain to initialize
 */
void awrtc_mbedtls_x509_crt_init(awrtc_mbedtls_x509_crt *crt);

/**
 * \brief          Unallocate all certificate data
 *
 * \param crt      Certificate chain to free
 */
void awrtc_mbedtls_x509_crt_free(awrtc_mbedtls_x509_crt *crt);

#if defined(AWRTC_MBEDTLS_ECDSA_C) && defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
/**
 * \brief           Initialize a restart context
 */
void awrtc_mbedtls_x509_crt_restart_init(awrtc_mbedtls_x509_crt_restart_ctx *ctx);

/**
 * \brief           Free the components of a restart context
 */
void awrtc_mbedtls_x509_crt_restart_free(awrtc_mbedtls_x509_crt_restart_ctx *ctx);
#endif /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */
#endif /* AWRTC_MBEDTLS_X509_CRT_PARSE_C */

/**
 * \brief               Query certificate for given extension type
 *
 * \param[in] ctx       Certificate context to be queried, must not be \c NULL
 * \param ext_type      Extension type being queried for, must be a valid
 *                      extension type. Must be one of the AWRTC_MBEDTLS_X509_EXT_XXX
 *                      values
 *
 * \return              0 if the given extension type is not present,
 *                      non-zero otherwise
 */
static inline int awrtc_mbedtls_x509_crt_has_ext_type(const awrtc_mbedtls_x509_crt *ctx,
                                                int ext_type)
{
    return ctx->AWRTC_MBEDTLS_PRIVATE(ext_types) & ext_type;
}

/**
 * \brief               Access the ca_istrue field
 *
 * \param[in] crt       Certificate to be queried, must not be \c NULL
 *
 * \return              \c 1 if this a CA certificate \c 0 otherwise.
 * \return              AWRTC_MBEDTLS_ERR_X509_INVALID_EXTENSIONS if the certificate does not contain
 *                      the Optional Basic Constraint extension.
 *
 */
int awrtc_mbedtls_x509_crt_get_ca_istrue(const awrtc_mbedtls_x509_crt *crt);

/** \} name Structures and functions for parsing and writing X.509 certificates */

#if defined(AWRTC_MBEDTLS_X509_CRT_WRITE_C)
/**
 * \brief           Initialize a CRT writing context
 *
 * \param ctx       CRT context to initialize
 */
void awrtc_mbedtls_x509write_crt_init(awrtc_mbedtls_x509write_cert *ctx);

/**
 * \brief           Set the version for a Certificate
 *                  Default: AWRTC_MBEDTLS_X509_CRT_VERSION_3
 *
 * \param ctx       CRT context to use
 * \param version   version to set (AWRTC_MBEDTLS_X509_CRT_VERSION_1, AWRTC_MBEDTLS_X509_CRT_VERSION_2 or
 *                                  AWRTC_MBEDTLS_X509_CRT_VERSION_3)
 */
void awrtc_mbedtls_x509write_crt_set_version(awrtc_mbedtls_x509write_cert *ctx, int version);

#if defined(AWRTC_MBEDTLS_BIGNUM_C) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
/**
 * \brief           Set the serial number for a Certificate.
 *
 * \deprecated      This function is deprecated and will be removed in a
 *                  future version of the library. Please use
 *                  awrtc_mbedtls_x509write_crt_set_serial_raw() instead.
 *
 * \note            Even though the AWRTC_MBEDTLS_BIGNUM_C guard looks redundant since
 *                  X509 depends on PK and PK depends on BIGNUM, this emphasizes
 *                  a direct dependency between X509 and BIGNUM which is going
 *                  to be deprecated in the future.
 *
 * \param ctx       CRT context to use
 * \param serial    serial number to set
 *
 * \return          0 if successful
 */
int AWRTC_MBEDTLS_DEPRECATED awrtc_mbedtls_x509write_crt_set_serial(
    awrtc_mbedtls_x509write_cert *ctx, const awrtc_mbedtls_mpi *serial);
#endif // AWRTC_MBEDTLS_BIGNUM_C && !AWRTC_MBEDTLS_DEPRECATED_REMOVED

/**
 * \brief           Set the serial number for a Certificate.
 *
 * \param ctx          CRT context to use
 * \param serial       A raw array of bytes containing the serial number in big
 *                     endian format
 * \param serial_len   Length of valid bytes (expressed in bytes) in \p serial
 *                     input buffer
 *
 * \return          0 if successful, or
 *                  AWRTC_MBEDTLS_ERR_X509_BAD_INPUT_DATA if the provided input buffer
 *                  is too big (longer than AWRTC_MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN)
 */
int awrtc_mbedtls_x509write_crt_set_serial_raw(awrtc_mbedtls_x509write_cert *ctx,
                                         unsigned char *serial, size_t serial_len);

/**
 * \brief           Set the validity period for a Certificate
 *                  Timestamps should be in string format for UTC timezone
 *                  i.e. "YYYYMMDDhhmmss"
 *                  e.g. "20131231235959" for December 31st 2013
 *                       at 23:59:59
 *
 * \param ctx       CRT context to use
 * \param not_before    not_before timestamp
 * \param not_after     not_after timestamp
 *
 * \return          0 if timestamp was parsed successfully, or
 *                  a specific error code
 */
int awrtc_mbedtls_x509write_crt_set_validity(awrtc_mbedtls_x509write_cert *ctx, const char *not_before,
                                       const char *not_after);

/**
 * \brief           Set the issuer name for a Certificate
 *                  Issuer names should contain a comma-separated list
 *                  of OID types and values:
 *                  e.g. "C=UK,O=ARM,CN=Mbed TLS CA"
 *
 * \param ctx           CRT context to use
 * \param issuer_name   issuer name to set
 *
 * \return          0 if issuer name was parsed successfully, or
 *                  a specific error code
 */
int awrtc_mbedtls_x509write_crt_set_issuer_name(awrtc_mbedtls_x509write_cert *ctx,
                                          const char *issuer_name);

/**
 * \brief           Set the subject name for a Certificate
 *                  Subject names should contain a comma-separated list
 *                  of OID types and values:
 *                  e.g. "C=UK,O=ARM,CN=Mbed TLS Server 1"
 *
 * \param ctx           CRT context to use
 * \param subject_name  subject name to set
 *
 * \return          0 if subject name was parsed successfully, or
 *                  a specific error code
 */
int awrtc_mbedtls_x509write_crt_set_subject_name(awrtc_mbedtls_x509write_cert *ctx,
                                           const char *subject_name);

/**
 * \brief           Set the subject public key for the certificate
 *
 * \param ctx       CRT context to use
 * \param key       public key to include
 */
void awrtc_mbedtls_x509write_crt_set_subject_key(awrtc_mbedtls_x509write_cert *ctx, awrtc_mbedtls_pk_context *key);

/**
 * \brief           Set the issuer key used for signing the certificate
 *
 * \param ctx       CRT context to use
 * \param key       private key to sign with
 */
void awrtc_mbedtls_x509write_crt_set_issuer_key(awrtc_mbedtls_x509write_cert *ctx, awrtc_mbedtls_pk_context *key);

/**
 * \brief           Set the MD algorithm to use for the signature
 *                  (e.g. AWRTC_MBEDTLS_MD_SHA1)
 *
 * \param ctx       CRT context to use
 * \param md_alg    MD algorithm to use
 */
void awrtc_mbedtls_x509write_crt_set_md_alg(awrtc_mbedtls_x509write_cert *ctx, awrtc_mbedtls_md_type_t md_alg);

/**
 * \brief           Generic function to add to or replace an extension in the
 *                  CRT
 *
 * \param ctx       CRT context to use
 * \param oid       OID of the extension
 * \param oid_len   length of the OID
 * \param critical  if the extension is critical (per the RFC's definition)
 * \param val       value of the extension OCTET STRING
 * \param val_len   length of the value data
 *
 * \return          0 if successful, or a AWRTC_MBEDTLS_ERR_X509_ALLOC_FAILED
 */
int awrtc_mbedtls_x509write_crt_set_extension(awrtc_mbedtls_x509write_cert *ctx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        const unsigned char *val, size_t val_len);

/**
 * \brief           Set the basicConstraints extension for a CRT
 *
 * \param ctx       CRT context to use
 * \param is_ca     is this a CA certificate
 * \param max_pathlen   maximum length of certificate chains below this
 *                      certificate (only for CA certificates, -1 is
 *                      unlimited)
 *
 * \return          0 if successful, or a AWRTC_MBEDTLS_ERR_X509_ALLOC_FAILED
 */
int awrtc_mbedtls_x509write_crt_set_basic_constraints(awrtc_mbedtls_x509write_cert *ctx,
                                                int is_ca, int max_pathlen);

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA1)
/**
 * \brief           Set the subjectKeyIdentifier extension for a CRT
 *                  Requires that awrtc_mbedtls_x509write_crt_set_subject_key() has been
 *                  called before
 *
 * \param ctx       CRT context to use
 *
 * \return          0 if successful, or a AWRTC_MBEDTLS_ERR_X509_ALLOC_FAILED
 */
int awrtc_mbedtls_x509write_crt_set_subject_key_identifier(awrtc_mbedtls_x509write_cert *ctx);

/**
 * \brief           Set the authorityKeyIdentifier extension for a CRT
 *                  Requires that awrtc_mbedtls_x509write_crt_set_issuer_key() has been
 *                  called before
 *
 * \param ctx       CRT context to use
 *
 * \return          0 if successful, or a AWRTC_MBEDTLS_ERR_X509_ALLOC_FAILED
 */
int awrtc_mbedtls_x509write_crt_set_authority_key_identifier(awrtc_mbedtls_x509write_cert *ctx);
#endif /* AWRTC_MBEDTLS_MD_CAN_SHA1 */

/**
 * \brief           Set the Key Usage Extension flags
 *                  (e.g. AWRTC_MBEDTLS_X509_KU_DIGITAL_SIGNATURE | AWRTC_MBEDTLS_X509_KU_KEY_CERT_SIGN)
 *
 * \param ctx       CRT context to use
 * \param key_usage key usage flags to set
 *
 * \return          0 if successful, or AWRTC_MBEDTLS_ERR_X509_ALLOC_FAILED
 */
int awrtc_mbedtls_x509write_crt_set_key_usage(awrtc_mbedtls_x509write_cert *ctx,
                                        unsigned int key_usage);

/**
 * \brief           Set the Extended Key Usage Extension
 *                  (e.g. AWRTC_MBEDTLS_OID_SERVER_AUTH)
 *
 * \param ctx       CRT context to use
 * \param exts      extended key usage extensions to set, a sequence of
 *                  AWRTC_MBEDTLS_ASN1_OID objects
 *
 * \return          0 if successful, or AWRTC_MBEDTLS_ERR_X509_ALLOC_FAILED
 */
int awrtc_mbedtls_x509write_crt_set_ext_key_usage(awrtc_mbedtls_x509write_cert *ctx,
                                            const awrtc_mbedtls_asn1_sequence *exts);

/**
 * \brief           Set the Netscape Cert Type flags
 *                  (e.g. AWRTC_MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT | AWRTC_MBEDTLS_X509_NS_CERT_TYPE_EMAIL)
 *
 * \param ctx           CRT context to use
 * \param ns_cert_type  Netscape Cert Type flags to set
 *
 * \return          0 if successful, or AWRTC_MBEDTLS_ERR_X509_ALLOC_FAILED
 */
int awrtc_mbedtls_x509write_crt_set_ns_cert_type(awrtc_mbedtls_x509write_cert *ctx,
                                           unsigned char ns_cert_type);

/**
 * \brief           Free the contents of a CRT write context
 *
 * \param ctx       CRT context to free
 */
void awrtc_mbedtls_x509write_crt_free(awrtc_mbedtls_x509write_cert *ctx);

/**
 * \brief           Write a built up certificate to a X509 DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       certificate to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 * \param f_rng     RNG function. This must not be \c NULL.
 * \param p_rng     RNG parameter
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 *
 * \note            \p f_rng is used for the signature operation.
 */
int awrtc_mbedtls_x509write_crt_der(awrtc_mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                              awrtc_mbedtls_f_rng_t *f_rng,
                              void *p_rng);

#if defined(AWRTC_MBEDTLS_PEM_WRITE_C)
/**
 * \brief           Write a built up certificate to a X509 PEM string
 *
 * \param ctx       certificate to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 * \param f_rng     RNG function. This must not be \c NULL.
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful, or a specific error code
 *
 * \note            \p f_rng is used for the signature operation.
 */
int awrtc_mbedtls_x509write_crt_pem(awrtc_mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                              awrtc_mbedtls_f_rng_t *f_rng,
                              void *p_rng);
#endif /* AWRTC_MBEDTLS_PEM_WRITE_C */
#endif /* AWRTC_MBEDTLS_X509_CRT_WRITE_C */

/** \} addtogroup x509_module */

#ifdef __cplusplus
}
#endif

#endif /* awrtc_mbedtls_x509_crt.h */
