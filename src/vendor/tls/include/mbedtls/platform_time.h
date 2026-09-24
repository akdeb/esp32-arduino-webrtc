/**
 * \file platform_time.h
 *
 * \brief Mbed TLS Platform time abstraction
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef AWRTC_MBEDTLS_PLATFORM_TIME_H
#define AWRTC_MBEDTLS_PLATFORM_TIME_H

#include "build_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The time_t datatype
 */
#if defined(AWRTC_MBEDTLS_PLATFORM_TIME_TYPE_MACRO)
typedef AWRTC_MBEDTLS_PLATFORM_TIME_TYPE_MACRO awrtc_mbedtls_time_t;
#else
/* For time_t */
#include <time.h>
typedef time_t awrtc_mbedtls_time_t;
#endif /* AWRTC_MBEDTLS_PLATFORM_TIME_TYPE_MACRO */

#if defined(AWRTC_MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO)
typedef AWRTC_MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO awrtc_mbedtls_ms_time_t;
#else
#include <stdint.h>
#include <inttypes.h>
typedef int64_t awrtc_mbedtls_ms_time_t;
#endif /* AWRTC_MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO */

/**
 * \brief   Get time in milliseconds.
 *
 * \return Monotonically-increasing current time in milliseconds.
 *
 * \note Define AWRTC_MBEDTLS_PLATFORM_MS_TIME_ALT to be able to provide an
 *       alternative implementation
 *
 * \warning This function returns a monotonically-increasing time value from a
 *          start time that will differ from platform to platform, and possibly
 *          from run to run of the process.
 *
 */
awrtc_mbedtls_ms_time_t awrtc_mbedtls_ms_time(void);

/*
 * The function pointers for time
 */
#if defined(AWRTC_MBEDTLS_PLATFORM_TIME_ALT)
extern awrtc_mbedtls_time_t (*awrtc_mbedtls_time)(awrtc_mbedtls_time_t *time);

/**
 * \brief   Set your own time function pointer
 *
 * \param   time_func   the time function implementation
 *
 * \return              0
 */
int awrtc_mbedtls_platform_set_time(awrtc_mbedtls_time_t (*time_func)(awrtc_mbedtls_time_t *time));
#else
#if defined(AWRTC_MBEDTLS_PLATFORM_TIME_MACRO)
#define awrtc_mbedtls_time    AWRTC_MBEDTLS_PLATFORM_TIME_MACRO
#else
#define awrtc_mbedtls_time   time
#endif /* AWRTC_MBEDTLS_PLATFORM_TIME_MACRO */
#endif /* AWRTC_MBEDTLS_PLATFORM_TIME_ALT */

#ifdef __cplusplus
}
#endif

#endif /* platform_time.h */
