/**
 * \file compat-2.x.h
 *
 * \brief Compatibility definitions
 *
 * \deprecated Use the new names directly instead
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#if defined(AWRTC_MBEDTLS_DEPRECATED_WARNING)
#warning "Including compat-2.x.h is deprecated"
#endif

#ifndef AWRTC_MBEDTLS_COMPAT2X_H
#define AWRTC_MBEDTLS_COMPAT2X_H

/*
 * Macros for renamed functions
 */
#define awrtc_mbedtls_ctr_drbg_update_ret   awrtc_mbedtls_ctr_drbg_update
#define awrtc_mbedtls_hmac_drbg_update_ret  awrtc_mbedtls_hmac_drbg_update
#define awrtc_mbedtls_md5_starts_ret        awrtc_mbedtls_md5_starts
#define awrtc_mbedtls_md5_update_ret        awrtc_mbedtls_md5_update
#define awrtc_mbedtls_md5_finish_ret        awrtc_mbedtls_md5_finish
#define awrtc_mbedtls_md5_ret               awrtc_mbedtls_md5
#define awrtc_mbedtls_ripemd160_starts_ret  awrtc_mbedtls_ripemd160_starts
#define awrtc_mbedtls_ripemd160_update_ret  awrtc_mbedtls_ripemd160_update
#define awrtc_mbedtls_ripemd160_finish_ret  awrtc_mbedtls_ripemd160_finish
#define awrtc_mbedtls_ripemd160_ret         awrtc_mbedtls_ripemd160
#define awrtc_mbedtls_sha1_starts_ret       awrtc_mbedtls_sha1_starts
#define awrtc_mbedtls_sha1_update_ret       awrtc_mbedtls_sha1_update
#define awrtc_mbedtls_sha1_finish_ret       awrtc_mbedtls_sha1_finish
#define awrtc_mbedtls_sha1_ret              awrtc_mbedtls_sha1
#define awrtc_mbedtls_sha256_starts_ret     awrtc_mbedtls_sha256_starts
#define awrtc_mbedtls_sha256_update_ret     awrtc_mbedtls_sha256_update
#define awrtc_mbedtls_sha256_finish_ret     awrtc_mbedtls_sha256_finish
#define awrtc_mbedtls_sha256_ret            awrtc_mbedtls_sha256
#define awrtc_mbedtls_sha512_starts_ret     awrtc_mbedtls_sha512_starts
#define awrtc_mbedtls_sha512_update_ret     awrtc_mbedtls_sha512_update
#define awrtc_mbedtls_sha512_finish_ret     awrtc_mbedtls_sha512_finish
#define awrtc_mbedtls_sha512_ret            awrtc_mbedtls_sha512

#endif /* AWRTC_MBEDTLS_COMPAT2X_H */
