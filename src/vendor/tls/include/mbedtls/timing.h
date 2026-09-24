/**
 * \file timing.h
 *
 * \brief Portable interface to timeouts and to the CPU cycle counter
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef AWRTC_MBEDTLS_TIMING_H
#define AWRTC_MBEDTLS_TIMING_H
#include "private_access.h"

#include "build_info.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(AWRTC_MBEDTLS_TIMING_ALT)
// Regular implementation
//

/**
 * \brief          timer structure
 */
struct awrtc_mbedtls_timing_hr_time {
    uint64_t AWRTC_MBEDTLS_PRIVATE(opaque)[4];
};

/**
 * \brief          Context for awrtc_mbedtls_timing_set/get_delay()
 */
typedef struct awrtc_mbedtls_timing_delay_context {
    struct awrtc_mbedtls_timing_hr_time   AWRTC_MBEDTLS_PRIVATE(timer);
    uint32_t                        AWRTC_MBEDTLS_PRIVATE(int_ms);
    uint32_t                        AWRTC_MBEDTLS_PRIVATE(fin_ms);
} awrtc_mbedtls_timing_delay_context;

#else  /* AWRTC_MBEDTLS_TIMING_ALT */
#include "timing_alt.h"
#endif /* AWRTC_MBEDTLS_TIMING_ALT */

/* Internal use */
unsigned long awrtc_mbedtls_timing_get_timer(struct awrtc_mbedtls_timing_hr_time *val, int reset);

/**
 * \brief          Set a pair of delays to watch
 *                 (See \c awrtc_mbedtls_timing_get_delay().)
 *
 * \param data     Pointer to timing data.
 *                 Must point to a valid \c awrtc_mbedtls_timing_delay_context struct.
 * \param int_ms   First (intermediate) delay in milliseconds.
 *                 The effect if int_ms > fin_ms is unspecified.
 * \param fin_ms   Second (final) delay in milliseconds.
 *                 Pass 0 to cancel the current delay.
 *
 * \note           To set a single delay, either use \c awrtc_mbedtls_timing_set_timer
 *                 directly or use this function with int_ms == fin_ms.
 */
void awrtc_mbedtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms);

/**
 * \brief          Get the status of delays
 *                 (Memory helper: number of delays passed.)
 *
 * \param data     Pointer to timing data
 *                 Must point to a valid \c awrtc_mbedtls_timing_delay_context struct.
 *
 * \return         -1 if cancelled (fin_ms = 0),
 *                  0 if none of the delays are passed,
 *                  1 if only the intermediate delay is passed,
 *                  2 if the final delay is passed.
 */
int awrtc_mbedtls_timing_get_delay(void *data);

/**
 * \brief          Get the final timing delay
 *
 * \param data     Pointer to timing data
 *                 Must point to a valid \c awrtc_mbedtls_timing_delay_context struct.
 *
 * \return         Final timing delay in milliseconds.
 */
uint32_t awrtc_mbedtls_timing_get_final_delay(
    const awrtc_mbedtls_timing_delay_context *data);

#ifdef __cplusplus
}
#endif

#endif /* timing.h */
