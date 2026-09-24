/*
 *  X.509 certificate writing
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 * References:
 * - certificates: RFC 5280, updated by RFC 6818
 * - CSRs: PKCS#10 v1.7 aka RFC 2986
 * - attributes: PKCS#9 v2.0 aka RFC 2985
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_X509_CRT_WRITE_C)

#include "../include/mbedtls/x509_crt.h"
#include "x509_internal.h"
#include "../include/mbedtls/asn1write.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/oid.h"
#include "../include/mbedtls/platform.h"
#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/md.h"

#include <string.h>
#include <stdint.h>

#if defined(AWRTC_MBEDTLS_PEM_WRITE_C)
#include "../include/mbedtls/pem.h"
#endif /* AWRTC_MBEDTLS_PEM_WRITE_C */

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
#include "../include/psa/crypto.h"
#include "psa_util_internal.h"
#include "../include/mbedtls/psa_util.h"
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

void awrtc_mbedtls_x509write_crt_init(awrtc_mbedtls_x509write_cert *ctx)
{
    memset(ctx, 0, sizeof(awrtc_mbedtls_x509write_cert));

    ctx->version = AWRTC_MBEDTLS_X509_CRT_VERSION_3;
}

void awrtc_mbedtls_x509write_crt_free(awrtc_mbedtls_x509write_cert *ctx)
{
    if (ctx == NULL) {
        return;
    }

    awrtc_mbedtls_asn1_free_named_data_list(&ctx->subject);
    awrtc_mbedtls_asn1_free_named_data_list(&ctx->issuer);
    awrtc_mbedtls_asn1_free_named_data_list(&ctx->extensions);

    awrtc_mbedtls_platform_zeroize(ctx, sizeof(awrtc_mbedtls_x509write_cert));
}

void awrtc_mbedtls_x509write_crt_set_version(awrtc_mbedtls_x509write_cert *ctx,
                                       int version)
{
    ctx->version = version;
}

void awrtc_mbedtls_x509write_crt_set_md_alg(awrtc_mbedtls_x509write_cert *ctx,
                                      awrtc_mbedtls_md_type_t md_alg)
{
    ctx->md_alg = md_alg;
}

void awrtc_mbedtls_x509write_crt_set_subject_key(awrtc_mbedtls_x509write_cert *ctx,
                                           awrtc_mbedtls_pk_context *key)
{
    ctx->subject_key = key;
}

void awrtc_mbedtls_x509write_crt_set_issuer_key(awrtc_mbedtls_x509write_cert *ctx,
                                          awrtc_mbedtls_pk_context *key)
{
    ctx->issuer_key = key;
}

int awrtc_mbedtls_x509write_crt_set_subject_name(awrtc_mbedtls_x509write_cert *ctx,
                                           const char *subject_name)
{
    awrtc_mbedtls_asn1_free_named_data_list(&ctx->subject);
    return awrtc_mbedtls_x509_string_to_names(&ctx->subject, subject_name);
}

int awrtc_mbedtls_x509write_crt_set_issuer_name(awrtc_mbedtls_x509write_cert *ctx,
                                          const char *issuer_name)
{
    awrtc_mbedtls_asn1_free_named_data_list(&ctx->issuer);
    return awrtc_mbedtls_x509_string_to_names(&ctx->issuer, issuer_name);
}

#if defined(AWRTC_MBEDTLS_BIGNUM_C) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
int awrtc_mbedtls_x509write_crt_set_serial(awrtc_mbedtls_x509write_cert *ctx,
                                     const awrtc_mbedtls_mpi *serial)
{
    int ret;
    size_t tmp_len;

    /* Ensure that the MPI value fits into the buffer */
    tmp_len = awrtc_mbedtls_mpi_size(serial);
    if (tmp_len > AWRTC_MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN) {
        return AWRTC_MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    ctx->serial_len = tmp_len;

    ret = awrtc_mbedtls_mpi_write_binary(serial, ctx->serial, tmp_len);
    if (ret < 0) {
        return ret;
    }

    return 0;
}
#endif // AWRTC_MBEDTLS_BIGNUM_C && !AWRTC_MBEDTLS_DEPRECATED_REMOVED

int awrtc_mbedtls_x509write_crt_set_serial_raw(awrtc_mbedtls_x509write_cert *ctx,
                                         unsigned char *serial, size_t serial_len)
{
    if (serial_len > AWRTC_MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN) {
        return AWRTC_MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    ctx->serial_len = serial_len;
    memcpy(ctx->serial, serial, serial_len);

    return 0;
}

int awrtc_mbedtls_x509write_crt_set_validity(awrtc_mbedtls_x509write_cert *ctx,
                                       const char *not_before,
                                       const char *not_after)
{
    if (strlen(not_before) != AWRTC_MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1 ||
        strlen(not_after)  != AWRTC_MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1) {
        return AWRTC_MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    strncpy(ctx->not_before, not_before, AWRTC_MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    strncpy(ctx->not_after, not_after, AWRTC_MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    ctx->not_before[AWRTC_MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';
    ctx->not_after[AWRTC_MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';

    return 0;
}

int awrtc_mbedtls_x509write_crt_set_subject_alternative_name(awrtc_mbedtls_x509write_cert *ctx,
                                                       const awrtc_mbedtls_x509_san_list *san_list)
{
    return awrtc_mbedtls_x509_write_set_san_common(&ctx->extensions, san_list);
}


int awrtc_mbedtls_x509write_crt_set_extension(awrtc_mbedtls_x509write_cert *ctx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        const unsigned char *val, size_t val_len)
{
    return awrtc_mbedtls_x509_set_extension(&ctx->extensions, oid, oid_len,
                                      critical, val, val_len);
}

int awrtc_mbedtls_x509write_crt_set_basic_constraints(awrtc_mbedtls_x509write_cert *ctx,
                                                int is_ca, int max_pathlen)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char buf[9];
    unsigned char *c = buf + sizeof(buf);
    size_t len = 0;

    memset(buf, 0, sizeof(buf));

    if (is_ca && max_pathlen > 127) {
        return AWRTC_MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    if (is_ca) {
        if (max_pathlen >= 0) {
            AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_int(&c, buf,
                                                             max_pathlen));
        }
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_bool(&c, buf, 1));
    }

    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(&c, buf, len));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(&c, buf,
                                                     AWRTC_MBEDTLS_ASN1_CONSTRUCTED |
                                                     AWRTC_MBEDTLS_ASN1_SEQUENCE));

    return
        awrtc_mbedtls_x509write_crt_set_extension(ctx, AWRTC_MBEDTLS_OID_BASIC_CONSTRAINTS,
                                            AWRTC_MBEDTLS_OID_SIZE(AWRTC_MBEDTLS_OID_BASIC_CONSTRAINTS),
                                            is_ca, buf + sizeof(buf) - len, len);
}

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA1)
static int awrtc_mbedtls_x509write_crt_set_key_identifier(awrtc_mbedtls_x509write_cert *ctx,
                                                    int is_ca,
                                                    unsigned char tag)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char buf[AWRTC_MBEDTLS_MPI_MAX_SIZE * 2 + 20]; /* tag, length + 2xMPI */
    unsigned char *c = buf + sizeof(buf);
    size_t len = 0;
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    size_t hash_length;
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    memset(buf, 0, sizeof(buf));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len,
                         awrtc_mbedtls_pk_write_pubkey(&c,
                                                 buf,
                                                 is_ca ?
                                                 ctx->issuer_key :
                                                 ctx->subject_key));


#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    status = awrtc_psa_hash_compute(AWRTC_PSA_ALG_SHA_1,
                              buf + sizeof(buf) - len,
                              len,
                              buf + sizeof(buf) - 20,
                              20,
                              &hash_length);
    if (status != AWRTC_PSA_SUCCESS) {
        return AWRTC_MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
#else
    ret = awrtc_mbedtls_md(awrtc_mbedtls_md_info_from_type(AWRTC_MBEDTLS_MD_SHA1),
                     buf + sizeof(buf) - len, len,
                     buf + sizeof(buf) - 20);
    if (ret != 0) {
        return ret;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    c = buf + sizeof(buf) - 20;
    len = 20;

    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(&c, buf, len));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(&c, buf, tag));

    if (is_ca) { // writes AuthorityKeyIdentifier sequence
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(&c, buf, len));
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len,
                             awrtc_mbedtls_asn1_write_tag(&c,
                                                    buf,
                                                    AWRTC_MBEDTLS_ASN1_CONSTRUCTED |
                                                    AWRTC_MBEDTLS_ASN1_SEQUENCE));
    }

    if (is_ca) {
        return awrtc_mbedtls_x509write_crt_set_extension(ctx,
                                                   AWRTC_MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER,
                                                   AWRTC_MBEDTLS_OID_SIZE(
                                                       AWRTC_MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER),
                                                   0, buf + sizeof(buf) - len, len);
    } else {
        return awrtc_mbedtls_x509write_crt_set_extension(ctx,
                                                   AWRTC_MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER,
                                                   AWRTC_MBEDTLS_OID_SIZE(
                                                       AWRTC_MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER),
                                                   0, buf + sizeof(buf) - len, len);
    }
}

int awrtc_mbedtls_x509write_crt_set_subject_key_identifier(awrtc_mbedtls_x509write_cert *ctx)
{
    return awrtc_mbedtls_x509write_crt_set_key_identifier(ctx,
                                                    0,
                                                    AWRTC_MBEDTLS_ASN1_OCTET_STRING);
}

int awrtc_mbedtls_x509write_crt_set_authority_key_identifier(awrtc_mbedtls_x509write_cert *ctx)
{
    return awrtc_mbedtls_x509write_crt_set_key_identifier(ctx,
                                                    1,
                                                    (AWRTC_MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0));
}
#endif /* AWRTC_MBEDTLS_MD_CAN_SHA1 */

int awrtc_mbedtls_x509write_crt_set_key_usage(awrtc_mbedtls_x509write_cert *ctx,
                                        unsigned int key_usage)
{
    unsigned char buf[5] = { 0 }, ku[2] = { 0 };
    unsigned char *c;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned int allowed_bits = AWRTC_MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
                                      AWRTC_MBEDTLS_X509_KU_NON_REPUDIATION   |
                                      AWRTC_MBEDTLS_X509_KU_KEY_ENCIPHERMENT  |
                                      AWRTC_MBEDTLS_X509_KU_DATA_ENCIPHERMENT |
                                      AWRTC_MBEDTLS_X509_KU_KEY_AGREEMENT     |
                                      AWRTC_MBEDTLS_X509_KU_KEY_CERT_SIGN     |
                                      AWRTC_MBEDTLS_X509_KU_CRL_SIGN          |
                                      AWRTC_MBEDTLS_X509_KU_ENCIPHER_ONLY     |
                                      AWRTC_MBEDTLS_X509_KU_DECIPHER_ONLY;

    /* Check that nothing other than the allowed flags is set */
    if ((key_usage & ~allowed_bits) != 0) {
        return AWRTC_MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
    }

    c = buf + 5;
    AWRTC_MBEDTLS_PUT_UINT16_LE(key_usage, ku, 0);
    ret = awrtc_mbedtls_asn1_write_named_bitstring(&c, buf, ku, 9);

    if (ret < 0) {
        return ret;
    } else if (ret < 3 || ret > 5) {
        return AWRTC_MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    ret = awrtc_mbedtls_x509write_crt_set_extension(ctx, AWRTC_MBEDTLS_OID_KEY_USAGE,
                                              AWRTC_MBEDTLS_OID_SIZE(AWRTC_MBEDTLS_OID_KEY_USAGE),
                                              1, c, (size_t) ret);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int awrtc_mbedtls_x509write_crt_set_ext_key_usage(awrtc_mbedtls_x509write_cert *ctx,
                                            const awrtc_mbedtls_asn1_sequence *exts)
{
    unsigned char buf[256];
    unsigned char *c = buf + sizeof(buf);
    int ret;
    size_t len = 0;
    const awrtc_mbedtls_asn1_sequence *last_ext = NULL;
    const awrtc_mbedtls_asn1_sequence *ext;

    memset(buf, 0, sizeof(buf));

    /* We need at least one extension: SEQUENCE SIZE (1..MAX) OF KeyPurposeId */
    if (exts == NULL) {
        return AWRTC_MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    /* Iterate over exts backwards, so we write them out in the requested order */
    while (last_ext != exts) {
        for (ext = exts; ext->next != last_ext; ext = ext->next) {
        }
        if (ext->buf.tag != AWRTC_MBEDTLS_ASN1_OID) {
            return AWRTC_MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        }
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_raw_buffer(&c, buf, ext->buf.p, ext->buf.len));
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(&c, buf, ext->buf.len));
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(&c, buf, AWRTC_MBEDTLS_ASN1_OID));
        last_ext = ext;
    }

    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(&c, buf, len));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len,
                         awrtc_mbedtls_asn1_write_tag(&c, buf,
                                                AWRTC_MBEDTLS_ASN1_CONSTRUCTED | AWRTC_MBEDTLS_ASN1_SEQUENCE));

    return awrtc_mbedtls_x509write_crt_set_extension(ctx,
                                               AWRTC_MBEDTLS_OID_EXTENDED_KEY_USAGE,
                                               AWRTC_MBEDTLS_OID_SIZE(AWRTC_MBEDTLS_OID_EXTENDED_KEY_USAGE),
                                               1, c, len);
}

int awrtc_mbedtls_x509write_crt_set_ns_cert_type(awrtc_mbedtls_x509write_cert *ctx,
                                           unsigned char ns_cert_type)
{
    unsigned char buf[4] = { 0 };
    unsigned char *c;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    c = buf + 4;

    ret = awrtc_mbedtls_asn1_write_named_bitstring(&c, buf, &ns_cert_type, 8);
    if (ret < 3 || ret > 4) {
        return ret;
    }

    ret = awrtc_mbedtls_x509write_crt_set_extension(ctx, AWRTC_MBEDTLS_OID_NS_CERT_TYPE,
                                              AWRTC_MBEDTLS_OID_SIZE(AWRTC_MBEDTLS_OID_NS_CERT_TYPE),
                                              0, c, (size_t) ret);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

static int x509_write_time(unsigned char **p, unsigned char *start,
                           const char *t, size_t size)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    /*
     * write AWRTC_MBEDTLS_ASN1_UTC_TIME if year < 2050 (2 bytes shorter)
     */
    if (t[0] < '2' || (t[0] == '2' && t[1] == '0' && t[2] < '5')) {
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_raw_buffer(p, start,
                                                                (const unsigned char *) t + 2,
                                                                size - 2));
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(p, start, len));
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(p, start,
                                                         AWRTC_MBEDTLS_ASN1_UTC_TIME));
    } else {
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_raw_buffer(p, start,
                                                                (const unsigned char *) t,
                                                                size));
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(p, start, len));
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(p, start,
                                                         AWRTC_MBEDTLS_ASN1_GENERALIZED_TIME));
    }

    return (int) len;
}

int awrtc_mbedtls_x509write_crt_der(awrtc_mbedtls_x509write_cert *ctx,
                              unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *c, *c2;
    unsigned char sig[AWRTC_MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t hash_length = 0;
    unsigned char hash[AWRTC_MBEDTLS_MD_MAX_SIZE];
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_algorithm_t awrtc_psa_algorithm;
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    size_t sub_len = 0, pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    awrtc_mbedtls_pk_type_t pk_alg;
    int write_sig_null_par;

    /*
     * Prepare data to be signed at the end of the target buffer
     */
    c = buf + size;

    /* Signature algorithm needed in TBS, and later for actual signature */

    /* There's no direct way of extracting a signature algorithm
     * (represented as an element of awrtc_mbedtls_pk_type_t) from a PK instance. */
    if (awrtc_mbedtls_pk_can_do(ctx->issuer_key, AWRTC_MBEDTLS_PK_RSA)) {
        pk_alg = AWRTC_MBEDTLS_PK_RSA;
    } else if (awrtc_mbedtls_pk_can_do(ctx->issuer_key, AWRTC_MBEDTLS_PK_ECDSA)) {
        pk_alg = AWRTC_MBEDTLS_PK_ECDSA;
    } else {
        return AWRTC_MBEDTLS_ERR_X509_INVALID_ALG;
    }

    if ((ret = awrtc_mbedtls_oid_get_oid_by_sig_alg(pk_alg, ctx->md_alg,
                                              &sig_oid, &sig_oid_len)) != 0) {
        return ret;
    }

    /*
     *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */

    /* Only for v3 */
    if (ctx->version == AWRTC_MBEDTLS_X509_CRT_VERSION_3) {
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len,
                             awrtc_mbedtls_x509_write_extensions(&c,
                                                           buf, ctx->extensions));
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(&c, buf, len));
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len,
                             awrtc_mbedtls_asn1_write_tag(&c, buf,
                                                    AWRTC_MBEDTLS_ASN1_CONSTRUCTED |
                                                    AWRTC_MBEDTLS_ASN1_SEQUENCE));
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(&c, buf, len));
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len,
                             awrtc_mbedtls_asn1_write_tag(&c, buf,
                                                    AWRTC_MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    AWRTC_MBEDTLS_ASN1_CONSTRUCTED | 3));
    }

    /*
     *  SubjectPublicKeyInfo
     */
    AWRTC_MBEDTLS_ASN1_CHK_ADD(pub_len,
                         awrtc_mbedtls_pk_write_pubkey_der(ctx->subject_key,
                                                     buf, (size_t) (c - buf)));
    c -= pub_len;
    len += pub_len;

    /*
     *  Subject  ::=  Name
     */
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len,
                         awrtc_mbedtls_x509_write_names(&c, buf,
                                                  ctx->subject));

    /*
     *  Validity ::= SEQUENCE {
     *       notBefore      Time,
     *       notAfter       Time }
     */
    sub_len = 0;

    AWRTC_MBEDTLS_ASN1_CHK_ADD(sub_len,
                         x509_write_time(&c, buf, ctx->not_after,
                                         AWRTC_MBEDTLS_X509_RFC5280_UTC_TIME_LEN));

    AWRTC_MBEDTLS_ASN1_CHK_ADD(sub_len,
                         x509_write_time(&c, buf, ctx->not_before,
                                         AWRTC_MBEDTLS_X509_RFC5280_UTC_TIME_LEN));

    len += sub_len;
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(&c, buf, sub_len));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len,
                         awrtc_mbedtls_asn1_write_tag(&c, buf,
                                                AWRTC_MBEDTLS_ASN1_CONSTRUCTED |
                                                AWRTC_MBEDTLS_ASN1_SEQUENCE));

    /*
     *  Issuer  ::=  Name
     */
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_x509_write_names(&c, buf,
                                                       ctx->issuer));

    /*
     *  Signature   ::=  AlgorithmIdentifier
     */
    if (pk_alg == AWRTC_MBEDTLS_PK_ECDSA) {
        /*
         * The AlgorithmIdentifier's parameters field must be absent for DSA/ECDSA signature
         * algorithms, see https://www.rfc-editor.org/rfc/rfc5480#page-17 and
         * https://www.rfc-editor.org/rfc/rfc5758#section-3.
         */
        write_sig_null_par = 0;
    } else {
        write_sig_null_par = 1;
    }
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len,
                         awrtc_mbedtls_asn1_write_algorithm_identifier_ext(&c, buf,
                                                                     sig_oid, strlen(sig_oid),
                                                                     0, write_sig_null_par));

    /*
     *  Serial   ::=  INTEGER
     *
     * Written data is:
     * - "ctx->serial_len" bytes for the raw serial buffer
     *   - if MSb of "serial" is 1, then prepend an extra 0x00 byte
     * - 1 byte for the length
     * - 1 byte for the TAG
     */
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_raw_buffer(&c, buf,
                                                            ctx->serial, ctx->serial_len));
    if (*c & 0x80) {
        if (c - buf < 1) {
            return AWRTC_MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        }
        *(--c) = 0x0;
        len++;
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(&c, buf,
                                                         ctx->serial_len + 1));
    } else {
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(&c, buf,
                                                         ctx->serial_len));
    }
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(&c, buf,
                                                     AWRTC_MBEDTLS_ASN1_INTEGER));

    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */

    /* Can be omitted for v1 */
    if (ctx->version != AWRTC_MBEDTLS_X509_CRT_VERSION_1) {
        sub_len = 0;
        AWRTC_MBEDTLS_ASN1_CHK_ADD(sub_len,
                             awrtc_mbedtls_asn1_write_int(&c, buf, ctx->version));
        len += sub_len;
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len,
                             awrtc_mbedtls_asn1_write_len(&c, buf, sub_len));
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len,
                             awrtc_mbedtls_asn1_write_tag(&c, buf,
                                                    AWRTC_MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    AWRTC_MBEDTLS_ASN1_CONSTRUCTED | 0));
    }

    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(&c, buf, len));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len,
                         awrtc_mbedtls_asn1_write_tag(&c, buf, AWRTC_MBEDTLS_ASN1_CONSTRUCTED |
                                                AWRTC_MBEDTLS_ASN1_SEQUENCE));

    /*
     * Make signature
     */

    /* Compute hash of CRT. */
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_algorithm = awrtc_mbedtls_md_psa_alg_from_type(ctx->md_alg);

    status = awrtc_psa_hash_compute(awrtc_psa_algorithm,
                              c,
                              len,
                              hash,
                              sizeof(hash),
                              &hash_length);
    if (status != AWRTC_PSA_SUCCESS) {
        return AWRTC_MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
#else
    if ((ret = awrtc_mbedtls_md(awrtc_mbedtls_md_info_from_type(ctx->md_alg), c,
                          len, hash)) != 0) {
        return ret;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */


    if ((ret = awrtc_mbedtls_pk_sign(ctx->issuer_key, ctx->md_alg,
                               hash, hash_length, sig, sizeof(sig), &sig_len,
                               f_rng, p_rng)) != 0) {
        return ret;
    }

    /* Move CRT to the front of the buffer to have space
     * for the signature. */
    memmove(buf, c, len);
    c = buf + len;

    /* Add signature at the end of the buffer,
     * making sure that it doesn't underflow
     * into the CRT buffer. */
    c2 = buf + size;
    AWRTC_MBEDTLS_ASN1_CHK_ADD(sig_and_oid_len, awrtc_mbedtls_x509_write_sig(&c2, c,
                                                                 sig_oid, sig_oid_len,
                                                                 sig, sig_len, pk_alg));

    /*
     * Memory layout after this step:
     *
     * buf       c=buf+len                c2            buf+size
     * [CRT0,...,CRTn, UNUSED, ..., UNUSED, SIG0, ..., SIGm]
     */

    /* Move raw CRT to just before the signature. */
    c = c2 - len;
    memmove(c, buf, len);

    len += sig_and_oid_len;
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(&c, buf, len));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(&c, buf,
                                                     AWRTC_MBEDTLS_ASN1_CONSTRUCTED |
                                                     AWRTC_MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"

#if defined(AWRTC_MBEDTLS_PEM_WRITE_C)
int awrtc_mbedtls_x509write_crt_pem(awrtc_mbedtls_x509write_cert *crt,
                              unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen;

    if ((ret = awrtc_mbedtls_x509write_crt_der(crt, buf, size,
                                         f_rng, p_rng)) < 0) {
        return ret;
    }

    if ((ret = awrtc_mbedtls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT,
                                        buf + size - ret, ret,
                                        buf, size, &olen)) != 0) {
        return ret;
    }

    return 0;
}
#endif /* AWRTC_MBEDTLS_PEM_WRITE_C */

#endif /* AWRTC_MBEDTLS_X509_CRT_WRITE_C */
