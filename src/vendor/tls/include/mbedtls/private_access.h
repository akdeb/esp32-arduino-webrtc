/**
 * \file private_access.h
 *
 * \brief Macro wrapper for struct's members.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_MBEDTLS_PRIVATE_ACCESS_H
#define AWRTC_MBEDTLS_PRIVATE_ACCESS_H

#ifndef AWRTC_MBEDTLS_ALLOW_PRIVATE_ACCESS
#define AWRTC_MBEDTLS_PRIVATE(member) private_##member
#else
#define AWRTC_MBEDTLS_PRIVATE(member) member
#endif

#endif /* AWRTC_MBEDTLS_PRIVATE_ACCESS_H */
