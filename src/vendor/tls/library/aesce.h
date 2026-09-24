/**
 * \file aesce.h
 *
 * \brief Support hardware AES acceleration on Armv8-A processors with
 *        the Armv8-A Cryptographic Extension.
 *
 * \warning These functions are only for internal use by other library
 *          functions; you must not call them directly.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef AWRTC_MBEDTLS_AESCE_H
#define AWRTC_MBEDTLS_AESCE_H

#include "../include/mbedtls/build_info.h"
#include "common.h"

#include "../include/mbedtls/aes.h"


#if defined(AWRTC_MBEDTLS_AESCE_C) \
    && defined(AWRTC_MBEDTLS_ARCH_IS_ARMV8_A) && defined(AWRTC_MBEDTLS_HAVE_NEON_INTRINSICS) \
    && (defined(AWRTC_MBEDTLS_COMPILER_IS_GCC) || defined(__clang__) || defined(MSC_VER))

/* AWRTC_MBEDTLS_AESCE_HAVE_CODE is defined if we have a suitable target platform, and a
 * potentially suitable compiler (compiler version & flags are not checked when defining
 * this). */
#define AWRTC_MBEDTLS_AESCE_HAVE_CODE

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__linux__) && !defined(AWRTC_MBEDTLS_AES_USE_HARDWARE_ONLY)

extern signed char awrtc_mbedtls_aesce_has_support_result;

/**
 * \brief          Internal function to detect the crypto extension in CPUs.
 *
 * \return         1 if CPU has support for the feature, 0 otherwise
 */
int awrtc_mbedtls_aesce_has_support_impl(void);

#define AWRTC_MBEDTLS_AESCE_HAS_SUPPORT() (awrtc_mbedtls_aesce_has_support_result == -1 ? \
                                     awrtc_mbedtls_aesce_has_support_impl() : \
                                     awrtc_mbedtls_aesce_has_support_result)

#else /* defined(__linux__) && !defined(AWRTC_MBEDTLS_AES_USE_HARDWARE_ONLY) */

/* If we are not on Linux, we can't detect support so assume that it's supported.
 * Similarly, assume support if AWRTC_MBEDTLS_AES_USE_HARDWARE_ONLY is set.
 */
#define AWRTC_MBEDTLS_AESCE_HAS_SUPPORT() 1

#endif /* defined(__linux__) && !defined(AWRTC_MBEDTLS_AES_USE_HARDWARE_ONLY) */

/**
 * \brief          Internal AES-ECB block encryption and decryption
 *
 * \warning        This assumes that the context specifies either 10, 12 or 14
 *                 rounds and will behave incorrectly if this is not the case.
 *
 * \param ctx      AES context
 * \param mode     AWRTC_MBEDTLS_AES_ENCRYPT or AWRTC_MBEDTLS_AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 on success (cannot fail)
 */
int awrtc_mbedtls_aesce_crypt_ecb(awrtc_mbedtls_aes_context *ctx,
                            int mode,
                            const unsigned char input[16],
                            unsigned char output[16]);

/**
 * \brief          Internal GCM multiplication: c = a * b in GF(2^128)
 *
 * \note           This function is only for internal use by other library
 *                 functions; you must not call it directly.
 *
 * \param c        Result
 * \param a        First operand
 * \param b        Second operand
 *
 * \note           Both operands and result are bit strings interpreted as
 *                 elements of GF(2^128) as per the GCM spec.
 */
void awrtc_mbedtls_aesce_gcm_mult(unsigned char c[16],
                            const unsigned char a[16],
                            const unsigned char b[16]);


#if !defined(AWRTC_MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
/**
 * \brief           Internal round key inversion. This function computes
 *                  decryption round keys from the encryption round keys.
 *
 * \param invkey    Round keys for the equivalent inverse cipher
 * \param fwdkey    Original round keys (for encryption)
 * \param nr        Number of rounds (that is, number of round keys minus one)
 */
void awrtc_mbedtls_aesce_inverse_key(unsigned char *invkey,
                               const unsigned char *fwdkey,
                               int nr);
#endif /* !AWRTC_MBEDTLS_BLOCK_CIPHER_NO_DECRYPT */

/**
 * \brief           Internal key expansion for encryption
 *
 * \param rk        Destination buffer where the round keys are written
 * \param key       Encryption key
 * \param bits      Key size in bits (must be 128, 192 or 256)
 *
 * \return          0 if successful, or AWRTC_MBEDTLS_ERR_AES_INVALID_KEY_LENGTH
 */
int awrtc_mbedtls_aesce_setkey_enc(unsigned char *rk,
                             const unsigned char *key,
                             size_t bits);

#ifdef __cplusplus
}
#endif

#else

#if defined(AWRTC_MBEDTLS_AES_USE_HARDWARE_ONLY) && defined(AWRTC_MBEDTLS_ARCH_IS_ARMV8_A)
#error "AES hardware acceleration not supported on this platform / compiler"
#endif

#endif /* AWRTC_MBEDTLS_AESCE_C && AWRTC_MBEDTLS_ARCH_IS_ARMV8_A && AWRTC_MBEDTLS_HAVE_NEON_INTRINSICS &&
          (AWRTC_MBEDTLS_COMPILER_IS_GCC || __clang__ || MSC_VER) */

#endif /* AWRTC_MBEDTLS_AESCE_H */
