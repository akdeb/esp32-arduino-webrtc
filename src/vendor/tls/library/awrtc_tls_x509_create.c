/*
 *  X.509 base functions for creating certificates / CSRs
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_X509_CREATE_C)

#include "x509_internal.h"
#include "../include/mbedtls/asn1write.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/oid.h"

#include <string.h>

#include "../include/mbedtls/platform.h"

#include "../include/mbedtls/asn1.h"

/* Structure linking OIDs for X.509 DN AttributeTypes to their
 * string representations and default string encodings used by Mbed TLS. */
typedef struct {
    const char *name; /* String representation of AttributeType, e.g.
                       * "CN" or "emailAddress". */
    size_t name_len; /* Length of 'name', without trailing 0 byte. */
    const char *oid; /* String representation of OID of AttributeType,
                      * as per RFC 5280, Appendix A.1. encoded as per
                      * X.690 */
    int default_tag; /* The default character encoding used for the
                      * given attribute type, e.g.
                      * AWRTC_MBEDTLS_ASN1_UTF8_STRING for UTF-8. */
} x509_attr_descriptor_t;

#define ADD_STRLEN(s)     s, sizeof(s) - 1

/* X.509 DN attributes from RFC 5280, Appendix A.1. */
static const x509_attr_descriptor_t x509_attrs[] =
{
    { ADD_STRLEN("CN"),
      AWRTC_MBEDTLS_OID_AT_CN, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("commonName"),
      AWRTC_MBEDTLS_OID_AT_CN, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("C"),
      AWRTC_MBEDTLS_OID_AT_COUNTRY, AWRTC_MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("countryName"),
      AWRTC_MBEDTLS_OID_AT_COUNTRY, AWRTC_MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("O"),
      AWRTC_MBEDTLS_OID_AT_ORGANIZATION, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("organizationName"),
      AWRTC_MBEDTLS_OID_AT_ORGANIZATION, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("L"),
      AWRTC_MBEDTLS_OID_AT_LOCALITY, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("locality"),
      AWRTC_MBEDTLS_OID_AT_LOCALITY, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("R"),
      AWRTC_MBEDTLS_OID_PKCS9_EMAIL, AWRTC_MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN("OU"),
      AWRTC_MBEDTLS_OID_AT_ORG_UNIT, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("organizationalUnitName"),
      AWRTC_MBEDTLS_OID_AT_ORG_UNIT, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("ST"),
      AWRTC_MBEDTLS_OID_AT_STATE, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("stateOrProvinceName"),
      AWRTC_MBEDTLS_OID_AT_STATE, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("emailAddress"),
      AWRTC_MBEDTLS_OID_PKCS9_EMAIL, AWRTC_MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN("serialNumber"),
      AWRTC_MBEDTLS_OID_AT_SERIAL_NUMBER, AWRTC_MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("postalAddress"),
      AWRTC_MBEDTLS_OID_AT_POSTAL_ADDRESS, AWRTC_MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("postalCode"),
      AWRTC_MBEDTLS_OID_AT_POSTAL_CODE, AWRTC_MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("dnQualifier"),
      AWRTC_MBEDTLS_OID_AT_DN_QUALIFIER, AWRTC_MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("title"),
      AWRTC_MBEDTLS_OID_AT_TITLE, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("surName"),
      AWRTC_MBEDTLS_OID_AT_SUR_NAME, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("SN"),
      AWRTC_MBEDTLS_OID_AT_SUR_NAME, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("givenName"),
      AWRTC_MBEDTLS_OID_AT_GIVEN_NAME, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("GN"),
      AWRTC_MBEDTLS_OID_AT_GIVEN_NAME, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("initials"),
      AWRTC_MBEDTLS_OID_AT_INITIALS, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("pseudonym"),
      AWRTC_MBEDTLS_OID_AT_PSEUDONYM, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("generationQualifier"),
      AWRTC_MBEDTLS_OID_AT_GENERATION_QUALIFIER, AWRTC_MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("domainComponent"),
      AWRTC_MBEDTLS_OID_DOMAIN_COMPONENT, AWRTC_MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN("DC"),
      AWRTC_MBEDTLS_OID_DOMAIN_COMPONENT,   AWRTC_MBEDTLS_ASN1_IA5_STRING },
    { NULL, 0, NULL, AWRTC_MBEDTLS_ASN1_NULL }
};

static const x509_attr_descriptor_t *x509_attr_descr_from_name(const char *name, size_t name_len)
{
    const x509_attr_descriptor_t *cur;

    for (cur = x509_attrs; cur->name != NULL; cur++) {
        if (cur->name_len == name_len &&
            strncmp(cur->name, name, name_len) == 0) {
            break;
        }
    }

    if (cur->name == NULL) {
        return NULL;
    }

    return cur;
}

static int hex_to_int(char c)
{
    return ('0' <= c && c <= '9') ? (c - '0') :
           ('a' <= c && c <= 'f') ? (c - 'a' + 10) :
           ('A' <= c && c <= 'F') ? (c - 'A' + 10) : -1;
}

static int hexpair_to_int(const char *hexpair)
{
    int n1 = hex_to_int(*hexpair);
    int n2 = hex_to_int(*(hexpair + 1));

    if (n1 != -1 && n2 != -1) {
        return (n1 << 4) | n2;
    } else {
        return -1;
    }
}

static int parse_attribute_value_string(const char *s,
                                        int len,
                                        unsigned char *data,
                                        size_t *data_len)
{
    const char *c;
    const char *end = s + len;
    unsigned char *d = data;
    int n;

    for (c = s; c < end; c++) {
        if (*c == '\\') {
            c++;

            /* Check for valid escaped characters as per RFC 4514 Section 3 */
            if (c + 1 < end && (n = hexpair_to_int(c)) != -1) {
                if (n == 0) {
                    return AWRTC_MBEDTLS_ERR_X509_INVALID_NAME;
                }
                *(d++) = n;
                c++;
            } else if (c < end && strchr(" ,=+<>#;\"\\", *c)) {
                *(d++) = *c;
            } else {
                return AWRTC_MBEDTLS_ERR_X509_INVALID_NAME;
            }
        } else {
            *(d++) = *c;
        }

        if (d - data == AWRTC_MBEDTLS_X509_MAX_DN_NAME_SIZE) {
            return AWRTC_MBEDTLS_ERR_X509_INVALID_NAME;
        }
    }
    *data_len = (size_t) (d - data);
    return 0;
}

/** Parse a hexstring containing a DER-encoded string.
 *
 * \param s         A string of \p len bytes hexadecimal digits.
 * \param len       Number of bytes to read from \p s.
 * \param data      Output buffer of size \p data_size.
 *                  On success, it contains the payload that's DER-encoded
 *                  in the input (content without the tag and length).
 *                  If the DER tag is a string tag, the payload is guaranteed
 *                  not to contain null bytes.
 * \param data_size Length of the \p data buffer.
 * \param data_len  On success, the length of the parsed string.
 *                  It is guaranteed to be less than
 *                  #AWRTC_MBEDTLS_X509_MAX_DN_NAME_SIZE.
 * \param tag       The ASN.1 tag that the payload in \p data is encoded in.
 *
 * \retval          0 on success.
 * \retval          #AWRTC_MBEDTLS_ERR_X509_INVALID_NAME if \p s does not contain
 *                  a valid hexstring,
 *                  or if the decoded hexstring is not valid DER,
 *                  or if the payload does not fit in \p data,
 *                  or if the payload is more than
 *                  #AWRTC_MBEDTLS_X509_MAX_DN_NAME_SIZE bytes,
 *                  of if \p *tag is an ASN.1 string tag and the payload
 *                  contains a null byte.
 * \retval          #AWRTC_MBEDTLS_ERR_X509_ALLOC_FAILED on low memory.
 */
static int parse_attribute_value_hex_der_encoded(const char *s,
                                                 size_t len,
                                                 unsigned char *data,
                                                 size_t data_size,
                                                 size_t *data_len,
                                                 int *tag)
{
    /* Step 1: preliminary length checks. */
    /* Each byte is encoded by exactly two hexadecimal digits. */
    if (len % 2 != 0) {
        /* Odd number of hex digits */
        return AWRTC_MBEDTLS_ERR_X509_INVALID_NAME;
    }
    size_t const der_length = len / 2;
    if (der_length > AWRTC_MBEDTLS_X509_MAX_DN_NAME_SIZE + 4) {
        /* The payload would be more than AWRTC_MBEDTLS_X509_MAX_DN_NAME_SIZE
         * (after subtracting the ASN.1 tag and length). Reject this early
         * to avoid allocating a large intermediate buffer. */
        return AWRTC_MBEDTLS_ERR_X509_INVALID_NAME;
    }
    if (der_length < 1) {
        /* Avoid empty-buffer shenanigans. A valid DER encoding is never
         * empty. */
        return AWRTC_MBEDTLS_ERR_X509_INVALID_NAME;
    }

    /* Step 2: Decode the hex string into an intermediate buffer. */
    unsigned char *der = awrtc_mbedtls_calloc(1, der_length);
    if (der == NULL) {
        return AWRTC_MBEDTLS_ERR_X509_ALLOC_FAILED;
    }
    /* Beyond this point, der needs to be freed on exit. */
    for (size_t i = 0; i < der_length; i++) {
        int c = hexpair_to_int(s + 2 * i);
        if (c < 0) {
            goto error;
        }
        der[i] = c;
    }

    /* Step 3: decode the DER. */
    /* We've checked that der_length >= 1 above. */
    *tag = der[0];
    {
        unsigned char *p = der + 1;
        if (awrtc_mbedtls_asn1_get_len(&p, der + der_length, data_len) != 0) {
            goto error;
        }
        /* Now p points to the first byte of the payload inside der,
         * and *data_len is the length of the payload. */

        /* Step 4: payload validation */
        if (*data_len > AWRTC_MBEDTLS_X509_MAX_DN_NAME_SIZE) {
            goto error;
        }
        /* Strings must not contain null bytes. */
        if (AWRTC_MBEDTLS_ASN1_IS_STRING_TAG(*tag)) {
            for (size_t i = 0; i < *data_len; i++) {
                if (p[i] == 0) {
                    goto error;
                }
            }
        }

        /* Step 5: output the payload. */
        if (*data_len > data_size) {
            goto error;
        }
        memcpy(data, p, *data_len);
    }
    awrtc_mbedtls_free(der);

    return 0;

error:
    awrtc_mbedtls_free(der);
    return AWRTC_MBEDTLS_ERR_X509_INVALID_NAME;
}

int awrtc_mbedtls_x509_string_to_names(awrtc_mbedtls_asn1_named_data **head, const char *name)
{
    int ret = AWRTC_MBEDTLS_ERR_X509_INVALID_NAME;
    int parse_ret = 0;
    const char *s = name, *c = s;
    const char *end = s + strlen(s);
    awrtc_mbedtls_asn1_buf oid = { .p = NULL, .len = 0, .tag = AWRTC_MBEDTLS_ASN1_NULL };
    const x509_attr_descriptor_t *attr_descr = NULL;
    int in_attr_type = 1;
    int tag;
    int numericoid = 0;
    unsigned char data[AWRTC_MBEDTLS_X509_MAX_DN_NAME_SIZE];
    size_t data_len = 0;

    /* Ensure the output parameter is not already populated.
     * (If it were, overwriting it would likely cause a memory leak.)
     */
    if (*head != NULL) {
        return AWRTC_MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    while (c <= end) {
        if (in_attr_type && *c == '=') {
            if ((attr_descr = x509_attr_descr_from_name(s, (size_t) (c - s))) == NULL) {
                if ((awrtc_mbedtls_oid_from_numeric_string(&oid, s, (size_t) (c - s))) != 0) {
                    return AWRTC_MBEDTLS_ERR_X509_INVALID_NAME;
                } else {
                    numericoid = 1;
                }
            } else {
                oid.len = strlen(attr_descr->oid);
                oid.p = awrtc_mbedtls_calloc(1, oid.len);
                if (oid.p == NULL) {
                    return AWRTC_MBEDTLS_ERR_X509_ALLOC_FAILED;
                }
                memcpy(oid.p, attr_descr->oid, oid.len);
                numericoid = 0;
            }

            s = c + 1;
            in_attr_type = 0;
        }

        if (!in_attr_type && ((*c == ',' && *(c-1) != '\\') || c == end)) {
            if (s == c) {
                awrtc_mbedtls_free(oid.p);
                return AWRTC_MBEDTLS_ERR_X509_INVALID_NAME;
            } else if (*s == '#') {
                /* We know that c >= s (loop invariant) and c != s (in this
                 * else branch), hence c - s - 1 >= 0. */
                parse_ret = parse_attribute_value_hex_der_encoded(
                    s + 1, (size_t) (c - s) - 1,
                    data, sizeof(data), &data_len, &tag);
                if (parse_ret != 0) {
                    awrtc_mbedtls_free(oid.p);
                    return parse_ret;
                }
            } else {
                if (numericoid) {
                    awrtc_mbedtls_free(oid.p);
                    return AWRTC_MBEDTLS_ERR_X509_INVALID_NAME;
                } else {
                    if ((parse_ret =
                             parse_attribute_value_string(s, (int) (c - s), data,
                                                          &data_len)) != 0) {
                        awrtc_mbedtls_free(oid.p);
                        return parse_ret;
                    }
                    tag = attr_descr->default_tag;
                }
            }

            awrtc_mbedtls_asn1_named_data *cur =
                awrtc_mbedtls_asn1_store_named_data(head, (char *) oid.p, oid.len,
                                              (unsigned char *) data,
                                              data_len);
            awrtc_mbedtls_free(oid.p);
            oid.p = NULL;
            if (cur == NULL) {
                return AWRTC_MBEDTLS_ERR_X509_ALLOC_FAILED;
            }

            // set tagType
            cur->val.tag = tag;

            while (c < end && *(c + 1) == ' ') {
                c++;
            }

            s = c + 1;
            in_attr_type = 1;

            /* Successfully parsed one name, update ret to success */
            ret = 0;
        }
        c++;
    }
    if (oid.p != NULL) {
        awrtc_mbedtls_free(oid.p);
    }
    return ret;
}

/* The first byte of the value in the awrtc_mbedtls_asn1_named_data structure is reserved
 * to store the critical boolean for us
 */
int awrtc_mbedtls_x509_set_extension(awrtc_mbedtls_asn1_named_data **head, const char *oid, size_t oid_len,
                               int critical, const unsigned char *val, size_t val_len)
{
    awrtc_mbedtls_asn1_named_data *cur;

    if (val_len > (SIZE_MAX  - 1)) {
        return AWRTC_MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    if ((cur = awrtc_mbedtls_asn1_store_named_data(head, oid, oid_len,
                                             NULL, val_len + 1)) == NULL) {
        return AWRTC_MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    cur->val.p[0] = critical;
    memcpy(cur->val.p + 1, val, val_len);

    return 0;
}

/*
 *  RelativeDistinguishedName ::=
 *    SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 */
static int x509_write_name(unsigned char **p,
                           unsigned char *start,
                           awrtc_mbedtls_asn1_named_data *cur_name)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    const char *oid             = (const char *) cur_name->oid.p;
    size_t oid_len              = cur_name->oid.len;
    const unsigned char *name   = cur_name->val.p;
    size_t name_len             = cur_name->val.len;

    // Write correct string tag and value
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tagged_string(p, start,
                                                               cur_name->val.tag,
                                                               (const char *) name,
                                                               name_len));
    // Write OID
    //
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_oid(p, start, oid,
                                                     oid_len));

    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(p, start, len));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(p, start,
                                                     AWRTC_MBEDTLS_ASN1_CONSTRUCTED |
                                                     AWRTC_MBEDTLS_ASN1_SEQUENCE));

    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(p, start, len));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(p, start,
                                                     AWRTC_MBEDTLS_ASN1_CONSTRUCTED |
                                                     AWRTC_MBEDTLS_ASN1_SET));

    return (int) len;
}

int awrtc_mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             awrtc_mbedtls_asn1_named_data *first)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    awrtc_mbedtls_asn1_named_data *cur = first;

    while (cur != NULL) {
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, x509_write_name(p, start, cur));
        cur = cur->next;
    }

    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(p, start, len));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(p, start, AWRTC_MBEDTLS_ASN1_CONSTRUCTED |
                                                     AWRTC_MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}

int awrtc_mbedtls_x509_write_sig(unsigned char **p, unsigned char *start,
                           const char *oid, size_t oid_len,
                           unsigned char *sig, size_t size,
                           awrtc_mbedtls_pk_type_t pk_alg)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int write_null_par;
    size_t len = 0;

    if (*p < start || (size_t) (*p - start) < size) {
        return AWRTC_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    len = size;
    (*p) -= len;
    memcpy(*p, sig, len);

    if (*p - start < 1) {
        return AWRTC_MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    *--(*p) = 0;
    len += 1;

    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(p, start, len));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(p, start, AWRTC_MBEDTLS_ASN1_BIT_STRING));

    // Write OID
    //
    if (pk_alg == AWRTC_MBEDTLS_PK_ECDSA) {
        /*
         * The AlgorithmIdentifier's parameters field must be absent for DSA/ECDSA signature
         * algorithms, see https://www.rfc-editor.org/rfc/rfc5480#page-17 and
         * https://www.rfc-editor.org/rfc/rfc5758#section-3.
         */
        write_null_par = 0;
    } else {
        write_null_par = 1;
    }
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len,
                         awrtc_mbedtls_asn1_write_algorithm_identifier_ext(p, start, oid, oid_len,
                                                                     0, write_null_par));

    return (int) len;
}

static int x509_write_extension(unsigned char **p, unsigned char *start,
                                awrtc_mbedtls_asn1_named_data *ext)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_raw_buffer(p, start, ext->val.p + 1,
                                                            ext->val.len - 1));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(p, start, ext->val.len - 1));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(p, start, AWRTC_MBEDTLS_ASN1_OCTET_STRING));

    if (ext->val.p[0] != 0) {
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_bool(p, start, 1));
    }

    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_raw_buffer(p, start, ext->oid.p,
                                                            ext->oid.len));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(p, start, ext->oid.len));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(p, start, AWRTC_MBEDTLS_ASN1_OID));

    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_len(p, start, len));
    AWRTC_MBEDTLS_ASN1_CHK_ADD(len, awrtc_mbedtls_asn1_write_tag(p, start, AWRTC_MBEDTLS_ASN1_CONSTRUCTED |
                                                     AWRTC_MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}

/*
 * Extension  ::=  SEQUENCE  {
 *     extnID      OBJECT IDENTIFIER,
 *     critical    BOOLEAN DEFAULT FALSE,
 *     extnValue   OCTET STRING
 *                 -- contains the DER encoding of an ASN.1 value
 *                 -- corresponding to the extension type identified
 *                 -- by extnID
 *     }
 */
int awrtc_mbedtls_x509_write_extensions(unsigned char **p, unsigned char *start,
                                  awrtc_mbedtls_asn1_named_data *first)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    awrtc_mbedtls_asn1_named_data *cur_ext = first;

    while (cur_ext != NULL) {
        AWRTC_MBEDTLS_ASN1_CHK_ADD(len, x509_write_extension(p, start, cur_ext));
        cur_ext = cur_ext->next;
    }

    return (int) len;
}

#endif /* AWRTC_MBEDTLS_X509_CREATE_C */
