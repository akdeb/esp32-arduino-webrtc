/*
 *  Debugging routines
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_DEBUG_C)

#include "../include/mbedtls/platform.h"

#include "debug_internal.h"
#include "../include/mbedtls/error.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* DEBUG_BUF_SIZE must be at least 2 */
#define DEBUG_BUF_SIZE      512

int awrtc_mbedtls_debug_snprintf(char *dest, size_t maxlen,
                           const char *format, ...)
{
    va_list argp;
    va_start(argp, format);
    int ret = awrtc_mbedtls_vsnprintf(dest, maxlen, format, argp);
    va_end(argp);
    return ret;
}

static int debug_threshold = 0;

void awrtc_mbedtls_debug_set_threshold(int threshold)
{
    debug_threshold = threshold;
}

/*
 * All calls to f_dbg must be made via this function
 */
static inline void debug_send_line(const awrtc_mbedtls_ssl_context *ssl, int level,
                                   const char *file, int line,
                                   const char *str)
{
    /*
     * If in a threaded environment, we need a thread identifier.
     * Since there is no portable way to get one, use the address of the ssl
     * context instead, as it shouldn't be shared between threads.
     */
#if defined(AWRTC_MBEDTLS_THREADING_C)
    char idstr[20 + DEBUG_BUF_SIZE]; /* 0x + 16 nibbles + ': ' */
    awrtc_mbedtls_snprintf(idstr, sizeof(idstr), "%p: %s", (void *) ssl, str);
    ssl->conf->f_dbg(ssl->conf->p_dbg, level, file, line, idstr);
#else
    ssl->conf->f_dbg(ssl->conf->p_dbg, level, file, line, str);
#endif
}

AWRTC_MBEDTLS_PRINTF_ATTRIBUTE(5, 6)
void awrtc_mbedtls_debug_print_msg(const awrtc_mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *format, ...)
{
    va_list argp;
    char str[DEBUG_BUF_SIZE];
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    AWRTC_MBEDTLS_STATIC_ASSERT(DEBUG_BUF_SIZE >= 2, "DEBUG_BUF_SIZE too small");

    if (NULL == ssl              ||
        NULL == ssl->conf        ||
        NULL == ssl->conf->f_dbg ||
        level > debug_threshold) {
        return;
    }

    va_start(argp, format);
    ret = awrtc_mbedtls_vsnprintf(str, DEBUG_BUF_SIZE, format, argp);
    va_end(argp);

    if (ret < 0) {
        ret = 0;
    } else {
        if (ret >= DEBUG_BUF_SIZE - 1) {
            ret = DEBUG_BUF_SIZE - 2;
        }
    }
    str[ret]     = '\n';
    str[ret + 1] = '\0';

    debug_send_line(ssl, level, file, line, str);
}

void awrtc_mbedtls_debug_print_ret(const awrtc_mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *text, int ret)
{
    char str[DEBUG_BUF_SIZE];

    if (NULL == ssl              ||
        NULL == ssl->conf        ||
        NULL == ssl->conf->f_dbg ||
        level > debug_threshold) {
        return;
    }

    /*
     * With non-blocking I/O and examples that just retry immediately,
     * the logs would be quickly flooded with WANT_READ, so ignore that.
     * Don't ignore WANT_WRITE however, since it is usually rare.
     */
    if (ret == AWRTC_MBEDTLS_ERR_SSL_WANT_READ) {
        return;
    }

    awrtc_mbedtls_snprintf(str, sizeof(str), "%s() returned %d (-0x%04x)\n",
                     text, ret, (unsigned int) -ret);

    debug_send_line(ssl, level, file, line, str);
}

void awrtc_mbedtls_debug_print_buf(const awrtc_mbedtls_ssl_context *ssl, int level,
                             const char *file, int line, const char *text,
                             const unsigned char *buf, size_t len)
{
    char str[DEBUG_BUF_SIZE];
    char txt[17];
    size_t i, idx = 0;

    if (NULL == ssl              ||
        NULL == ssl->conf        ||
        NULL == ssl->conf->f_dbg ||
        level > debug_threshold) {
        return;
    }

    awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, "dumping '%s' (%u bytes)\n",
                     text, (unsigned int) len);

    debug_send_line(ssl, level, file, line, str);

    memset(txt, 0, sizeof(txt));
    for (i = 0; i < len; i++) {
        if (i >= 4096) {
            break;
        }

        if (i % 16 == 0) {
            if (i > 0) {
                awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, "  %s\n", txt);
                debug_send_line(ssl, level, file, line, str);

                idx = 0;
                memset(txt, 0, sizeof(txt));
            }

            idx += awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, "%04x: ",
                                    (unsigned int) i);

        }

        idx += awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, " %02x",
                                (unsigned int) buf[i]);
        txt[i % 16] = (buf[i] > 31 && buf[i] < 127) ? buf[i] : '.';
    }

    if (len > 0) {
        for (/* i = i */; i % 16 != 0; i++) {
            idx += awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, "   ");
        }

        awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, "  %s\n", txt);
        debug_send_line(ssl, level, file, line, str);
    }
}

#if defined(AWRTC_MBEDTLS_ECP_LIGHT)
void awrtc_mbedtls_debug_print_ecp(const awrtc_mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *text, const awrtc_mbedtls_ecp_point *X)
{
    char str[DEBUG_BUF_SIZE];

    if (NULL == ssl              ||
        NULL == ssl->conf        ||
        NULL == ssl->conf->f_dbg ||
        level > debug_threshold) {
        return;
    }

    awrtc_mbedtls_snprintf(str, sizeof(str), "%s(X)", text);
    awrtc_mbedtls_debug_print_mpi(ssl, level, file, line, str, &X->X);

    awrtc_mbedtls_snprintf(str, sizeof(str), "%s(Y)", text);
    awrtc_mbedtls_debug_print_mpi(ssl, level, file, line, str, &X->Y);
}
#endif /* AWRTC_MBEDTLS_ECP_LIGHT */

#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
static void awrtc_mbedtls_debug_print_ec_coord(const awrtc_mbedtls_ssl_context *ssl, int level,
                                         const char *file, int line, const char *text,
                                         const unsigned char *buf, size_t len)
{
    char str[DEBUG_BUF_SIZE];
    size_t i, idx = 0;

    awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, "value of '%s' (%u bits) is:\n",
                     text, (unsigned int) len * 8);

    debug_send_line(ssl, level, file, line, str);

    for (i = 0; i < len; i++) {
        if (i >= 4096) {
            break;
        }

        if (i % 16 == 0) {
            if (i > 0) {
                awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, "\n");
                debug_send_line(ssl, level, file, line, str);

                idx = 0;
            }
        }

        idx += awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, " %02x",
                                (unsigned int) buf[i]);
    }

    if (len > 0) {
        for (/* i = i */; i % 16 != 0; i++) {
            idx += awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, "   ");
        }

        awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, "\n");
        debug_send_line(ssl, level, file, line, str);
    }
}

void awrtc_mbedtls_debug_print_psa_ec(const awrtc_mbedtls_ssl_context *ssl, int level,
                                const char *file, int line,
                                const char *text, const awrtc_mbedtls_pk_context *pk)
{
    char str[DEBUG_BUF_SIZE];
    const uint8_t *coord_start;
    size_t coord_len;

    if (NULL == ssl              ||
        NULL == ssl->conf        ||
        NULL == ssl->conf->f_dbg ||
        level > debug_threshold) {
        return;
    }

    /* For the description of pk->pk_raw content please refer to the description
     * awrtc_psa_export_public_key() function. */
    coord_len = (pk->pub_raw_len - 1)/2;

    /* X coordinate */
    coord_start = pk->pub_raw + 1;
    awrtc_mbedtls_snprintf(str, sizeof(str), "%s(X)", text);
    awrtc_mbedtls_debug_print_ec_coord(ssl, level, file, line, str, coord_start, coord_len);

    /* Y coordinate */
    coord_start = coord_start + coord_len;
    awrtc_mbedtls_snprintf(str, sizeof(str), "%s(Y)", text);
    awrtc_mbedtls_debug_print_ec_coord(ssl, level, file, line, str, coord_start, coord_len);
}
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */

#if defined(AWRTC_MBEDTLS_BIGNUM_C)
void awrtc_mbedtls_debug_print_mpi(const awrtc_mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *text, const awrtc_mbedtls_mpi *X)
{
    char str[DEBUG_BUF_SIZE];
    size_t bitlen;
    size_t idx = 0;

    if (NULL == ssl              ||
        NULL == ssl->conf        ||
        NULL == ssl->conf->f_dbg ||
        NULL == X                ||
        level > debug_threshold) {
        return;
    }

    bitlen = awrtc_mbedtls_mpi_bitlen(X);

    awrtc_mbedtls_snprintf(str, sizeof(str), "value of '%s' (%u bits) is:\n",
                     text, (unsigned) bitlen);
    debug_send_line(ssl, level, file, line, str);

    if (bitlen == 0) {
        str[0] = ' '; str[1] = '0'; str[2] = '0';
        idx = 3;
    } else {
        int n;
        for (n = (int) ((bitlen - 1) / 8); n >= 0; n--) {
            size_t limb_offset = n / sizeof(awrtc_mbedtls_mpi_uint);
            size_t offset_in_limb = n % sizeof(awrtc_mbedtls_mpi_uint);
            unsigned char octet =
                (X->p[limb_offset] >> (offset_in_limb * 8)) & 0xff;
            awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, " %02x", octet);
            idx += 3;
            /* Wrap lines after 16 octets that each take 3 columns */
            if (idx >= 3 * 16) {
                awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, "\n");
                debug_send_line(ssl, level, file, line, str);
                idx = 0;
            }
        }
    }

    if (idx != 0) {
        awrtc_mbedtls_snprintf(str + idx, sizeof(str) - idx, "\n");
        debug_send_line(ssl, level, file, line, str);
    }
}
#endif /* AWRTC_MBEDTLS_BIGNUM_C */

#if defined(AWRTC_MBEDTLS_X509_CRT_PARSE_C) && !defined(AWRTC_MBEDTLS_X509_REMOVE_INFO)
static void debug_print_pk(const awrtc_mbedtls_ssl_context *ssl, int level,
                           const char *file, int line,
                           const char *text, const awrtc_mbedtls_pk_context *pk)
{
    size_t i;
    awrtc_mbedtls_pk_debug_item items[AWRTC_MBEDTLS_PK_DEBUG_MAX_ITEMS];
    char name[16];

    memset(items, 0, sizeof(items));

    if (awrtc_mbedtls_pk_debug(pk, items) != 0) {
        debug_send_line(ssl, level, file, line,
                        "invalid PK context\n");
        return;
    }

    for (i = 0; i < AWRTC_MBEDTLS_PK_DEBUG_MAX_ITEMS; i++) {
        if (items[i].type == AWRTC_MBEDTLS_PK_DEBUG_NONE) {
            return;
        }

        awrtc_mbedtls_snprintf(name, sizeof(name), "%s%s", text, items[i].name);
        name[sizeof(name) - 1] = '\0';

#if defined(AWRTC_MBEDTLS_RSA_C)
        if (items[i].type == AWRTC_MBEDTLS_PK_DEBUG_MPI) {
            awrtc_mbedtls_debug_print_mpi(ssl, level, file, line, name, items[i].value);
        } else
#endif /* AWRTC_MBEDTLS_RSA_C */
#if defined(AWRTC_MBEDTLS_ECP_LIGHT)
        if (items[i].type == AWRTC_MBEDTLS_PK_DEBUG_ECP) {
            awrtc_mbedtls_debug_print_ecp(ssl, level, file, line, name, items[i].value);
        } else
#endif /* AWRTC_MBEDTLS_ECP_LIGHT */
#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
        if (items[i].type == AWRTC_MBEDTLS_PK_DEBUG_PSA_EC) {
            awrtc_mbedtls_debug_print_psa_ec(ssl, level, file, line, name, items[i].value);
        } else
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
        { debug_send_line(ssl, level, file, line,
                          "should not happen\n"); }
    }
}

static void debug_print_line_by_line(const awrtc_mbedtls_ssl_context *ssl, int level,
                                     const char *file, int line, const char *text)
{
    char str[DEBUG_BUF_SIZE];
    const char *start, *cur;

    start = text;
    for (cur = text; *cur != '\0'; cur++) {
        if (*cur == '\n') {
            size_t len = (size_t) (cur - start) + 1;
            if (len > DEBUG_BUF_SIZE - 1) {
                len = DEBUG_BUF_SIZE - 1;
            }

            memcpy(str, start, len);
            str[len] = '\0';

            debug_send_line(ssl, level, file, line, str);

            start = cur + 1;
        }
    }
}

void awrtc_mbedtls_debug_print_crt(const awrtc_mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *text, const awrtc_mbedtls_x509_crt *crt)
{
    char str[DEBUG_BUF_SIZE];
    int i = 0;

    if (NULL == ssl              ||
        NULL == ssl->conf        ||
        NULL == ssl->conf->f_dbg ||
        NULL == crt              ||
        level > debug_threshold) {
        return;
    }

    while (crt != NULL) {
        char buf[1024];

        awrtc_mbedtls_snprintf(str, sizeof(str), "%s #%d:\n", text, ++i);
        debug_send_line(ssl, level, file, line, str);

        awrtc_mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
        debug_print_line_by_line(ssl, level, file, line, buf);

        debug_print_pk(ssl, level, file, line, "crt->", &crt->pk);

        crt = crt->next;
    }
}
#endif /* AWRTC_MBEDTLS_X509_CRT_PARSE_C && AWRTC_MBEDTLS_X509_REMOVE_INFO */

#if defined(AWRTC_MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_ANY_ENABLED) && \
    defined(AWRTC_MBEDTLS_ECDH_C)
static void awrtc_mbedtls_debug_printf_ecdh_internal(const awrtc_mbedtls_ssl_context *ssl,
                                               int level, const char *file,
                                               int line,
                                               const awrtc_mbedtls_ecdh_context *ecdh,
                                               awrtc_mbedtls_debug_ecdh_attr attr)
{
#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    const awrtc_mbedtls_ecdh_context *ctx = ecdh;
#else
    const awrtc_mbedtls_ecdh_context_mbed *ctx = &ecdh->ctx.mbed_ecdh;
#endif

    switch (attr) {
        case AWRTC_MBEDTLS_DEBUG_ECDH_Q:
            awrtc_mbedtls_debug_print_ecp(ssl, level, file, line, "ECDH: Q",
                                    &ctx->Q);
            break;
        case AWRTC_MBEDTLS_DEBUG_ECDH_QP:
            awrtc_mbedtls_debug_print_ecp(ssl, level, file, line, "ECDH: Qp",
                                    &ctx->Qp);
            break;
        case AWRTC_MBEDTLS_DEBUG_ECDH_Z:
            awrtc_mbedtls_debug_print_mpi(ssl, level, file, line, "ECDH: z",
                                    &ctx->z);
            break;
        default:
            break;
    }
}

void awrtc_mbedtls_debug_printf_ecdh(const awrtc_mbedtls_ssl_context *ssl, int level,
                               const char *file, int line,
                               const awrtc_mbedtls_ecdh_context *ecdh,
                               awrtc_mbedtls_debug_ecdh_attr attr)
{
#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    awrtc_mbedtls_debug_printf_ecdh_internal(ssl, level, file, line, ecdh, attr);
#else
    switch (ecdh->var) {
        default:
            awrtc_mbedtls_debug_printf_ecdh_internal(ssl, level, file, line, ecdh,
                                               attr);
    }
#endif
}
#endif /* AWRTC_MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_ANY_ENABLED &&
          AWRTC_MBEDTLS_ECDH_C */

#endif /* AWRTC_MBEDTLS_DEBUG_C */
