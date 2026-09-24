/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/**
 * \file mps_trace.h
 *
 * \brief Tracing module for MPS
 */

#ifndef AWRTC_MBEDTLS_MPS_MBEDTLS_MPS_TRACE_H
#define AWRTC_MBEDTLS_MPS_MBEDTLS_MPS_TRACE_H

#include "common.h"
#include "mps_common.h"
#include "mps_trace.h"

#include "../include/mbedtls/platform.h"

#if defined(AWRTC_MBEDTLS_MPS_ENABLE_TRACE)

/*
 * Adapt this to enable/disable tracing output
 * from the various layers of the MPS.
 */

#define AWRTC_MBEDTLS_MPS_TRACE_ENABLE_LAYER_1
#define AWRTC_MBEDTLS_MPS_TRACE_ENABLE_LAYER_2
#define AWRTC_MBEDTLS_MPS_TRACE_ENABLE_LAYER_3
#define AWRTC_MBEDTLS_MPS_TRACE_ENABLE_LAYER_4
#define AWRTC_MBEDTLS_MPS_TRACE_ENABLE_READER
#define AWRTC_MBEDTLS_MPS_TRACE_ENABLE_WRITER

/*
 * To use the existing trace module, only change
 * AWRTC_MBEDTLS_MPS_TRACE_ENABLE_XXX above, but don't modify the
 * rest of this file.
 */

typedef enum {
    AWRTC_MBEDTLS_MPS_TRACE_TYPE_COMMENT,
    AWRTC_MBEDTLS_MPS_TRACE_TYPE_CALL,
    AWRTC_MBEDTLS_MPS_TRACE_TYPE_ERROR,
    AWRTC_MBEDTLS_MPS_TRACE_TYPE_RETURN
} awrtc_mbedtls_mps_trace_type;

#define AWRTC_MBEDTLS_MPS_TRACE_BIT_LAYER_1 1
#define AWRTC_MBEDTLS_MPS_TRACE_BIT_LAYER_2 2
#define AWRTC_MBEDTLS_MPS_TRACE_BIT_LAYER_3 3
#define AWRTC_MBEDTLS_MPS_TRACE_BIT_LAYER_4 4
#define AWRTC_MBEDTLS_MPS_TRACE_BIT_WRITER  5
#define AWRTC_MBEDTLS_MPS_TRACE_BIT_READER  6

#if defined(AWRTC_MBEDTLS_MPS_TRACE_ENABLE_LAYER_1)
#define AWRTC_MBEDTLS_MPS_TRACE_MASK_LAYER_1 (1u << AWRTC_MBEDTLS_MPS_TRACE_BIT_LAYER_1)
#else
#define AWRTC_MBEDTLS_MPS_TRACE_MASK_LAYER_1 0
#endif

#if defined(AWRTC_MBEDTLS_MPS_TRACE_ENABLE_LAYER_2)
#define AWRTC_MBEDTLS_MPS_TRACE_MASK_LAYER_2 (1u << AWRTC_MBEDTLS_MPS_TRACE_BIT_LAYER_2)
#else
#define AWRTC_MBEDTLS_MPS_TRACE_MASK_LAYER_2 0
#endif

#if defined(AWRTC_MBEDTLS_MPS_TRACE_ENABLE_LAYER_3)
#define AWRTC_MBEDTLS_MPS_TRACE_MASK_LAYER_3 (1u << AWRTC_MBEDTLS_MPS_TRACE_BIT_LAYER_3)
#else
#define AWRTC_MBEDTLS_MPS_TRACE_MASK_LAYER_3 0
#endif

#if defined(AWRTC_MBEDTLS_MPS_TRACE_ENABLE_LAYER_4)
#define AWRTC_MBEDTLS_MPS_TRACE_MASK_LAYER_4 (1u << AWRTC_MBEDTLS_MPS_TRACE_BIT_LAYER_4)
#else
#define AWRTC_MBEDTLS_MPS_TRACE_MASK_LAYER_4 0
#endif

#if defined(AWRTC_MBEDTLS_MPS_TRACE_ENABLE_READER)
#define AWRTC_MBEDTLS_MPS_TRACE_MASK_READER (1u << AWRTC_MBEDTLS_MPS_TRACE_BIT_READER)
#else
#define AWRTC_MBEDTLS_MPS_TRACE_MASK_READER 0
#endif

#if defined(AWRTC_MBEDTLS_MPS_TRACE_ENABLE_WRITER)
#define AWRTC_MBEDTLS_MPS_TRACE_MASK_WRITER (1u << AWRTC_MBEDTLS_MPS_TRACE_BIT_WRITER)
#else
#define AWRTC_MBEDTLS_MPS_TRACE_MASK_WRITER 0
#endif

#define AWRTC_MBEDTLS_MPS_TRACE_MASK (AWRTC_MBEDTLS_MPS_TRACE_MASK_LAYER_1 |       \
                                AWRTC_MBEDTLS_MPS_TRACE_MASK_LAYER_2 |       \
                                AWRTC_MBEDTLS_MPS_TRACE_MASK_LAYER_3 |       \
                                AWRTC_MBEDTLS_MPS_TRACE_MASK_LAYER_4 |       \
                                AWRTC_MBEDTLS_MPS_TRACE_MASK_READER  |       \
                                AWRTC_MBEDTLS_MPS_TRACE_MASK_WRITER)

/* We have to avoid globals because E-ACSL chokes on them...
 * Wrap everything in stub functions. */
int  awrtc_mbedtls_mps_trace_get_depth(void);
void awrtc_mbedtls_mps_trace_inc_depth(void);
void awrtc_mbedtls_mps_trace_dec_depth(void);

void awrtc_mbedtls_mps_trace_color(int id);
void awrtc_mbedtls_mps_trace_indent(int level, awrtc_mbedtls_mps_trace_type ty);

void awrtc_mbedtls_mps_trace_print_msg(int id, int line, const char *format, ...);

#define AWRTC_MBEDTLS_MPS_TRACE(type, ...)                                              \
    do {                                                                            \
        if (!(AWRTC_MBEDTLS_MPS_TRACE_MASK & (1u << awrtc_mbedtls_mps_trace_id)))         \
        break;                                                                  \
        awrtc_mbedtls_mps_trace_indent(awrtc_mbedtls_mps_trace_get_depth(), type);            \
        awrtc_mbedtls_mps_trace_color(awrtc_mbedtls_mps_trace_id);                            \
        awrtc_mbedtls_mps_trace_print_msg(awrtc_mbedtls_mps_trace_id, __LINE__, __VA_ARGS__); \
        awrtc_mbedtls_mps_trace_color(0);                                               \
    } while (0)

#define AWRTC_MBEDTLS_MPS_TRACE_INIT(...)                                         \
    do {                                                                      \
        if (!(AWRTC_MBEDTLS_MPS_TRACE_MASK & (1u << awrtc_mbedtls_mps_trace_id)))   \
        break;                                                            \
        AWRTC_MBEDTLS_MPS_TRACE(AWRTC_MBEDTLS_MPS_TRACE_TYPE_CALL, __VA_ARGS__);        \
        awrtc_mbedtls_mps_trace_inc_depth();                                        \
    } while (0)

#define AWRTC_MBEDTLS_MPS_TRACE_END(val)                                        \
    do {                                                                    \
        if (!(AWRTC_MBEDTLS_MPS_TRACE_MASK & (1u << awrtc_mbedtls_mps_trace_id))) \
        break;                                                          \
        AWRTC_MBEDTLS_MPS_TRACE(AWRTC_MBEDTLS_MPS_TRACE_TYPE_RETURN, "%d (-%#04x)",    \
                          (int) (val), -((unsigned) (val)));                           \
        awrtc_mbedtls_mps_trace_dec_depth();                                      \
    } while (0)

#define AWRTC_MBEDTLS_MPS_TRACE_RETURN(val)         \
    do {                                        \
        /* Breaks tail recursion. */            \
        int ret__ = val;                        \
        AWRTC_MBEDTLS_MPS_TRACE_END(ret__);         \
        return ret__;                        \
    } while (0)

#else /* AWRTC_MBEDTLS_MPS_TRACE */

#define AWRTC_MBEDTLS_MPS_TRACE(type, ...) do { } while (0)
#define AWRTC_MBEDTLS_MPS_TRACE_INIT(...)  do { } while (0)
#define AWRTC_MBEDTLS_MPS_TRACE_END          do { } while (0)

#define AWRTC_MBEDTLS_MPS_TRACE_RETURN(val) return val;

#endif /* AWRTC_MBEDTLS_MPS_TRACE */

#endif /* AWRTC_MBEDTLS_MPS_MBEDTLS_MPS_TRACE_H */
