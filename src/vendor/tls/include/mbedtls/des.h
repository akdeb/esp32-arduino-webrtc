/**
 * \file des.h
 *
 * \brief DES block cipher
 *
 * \warning   DES/3DES are considered weak ciphers and their use constitutes a
 *            security risk. We recommend considering stronger ciphers
 *            instead.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 */
#ifndef AWRTC_MBEDTLS_DES_H
#define AWRTC_MBEDTLS_DES_H
#include "private_access.h"

#include "build_info.h"
#include "platform_util.h"

#include <stddef.h>
#include <stdint.h>

#define AWRTC_MBEDTLS_DES_ENCRYPT     1
#define AWRTC_MBEDTLS_DES_DECRYPT     0

/** The data input has an invalid length. */
#define AWRTC_MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH              -0x0032

#define AWRTC_MBEDTLS_DES_KEY_SIZE    8

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(AWRTC_MBEDTLS_DES_ALT)
// Regular implementation
//

/**
 * \brief          DES context structure
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
typedef struct awrtc_mbedtls_des_context {
    uint32_t AWRTC_MBEDTLS_PRIVATE(sk)[32];            /*!<  DES subkeys       */
}
awrtc_mbedtls_des_context;

/**
 * \brief          Triple-DES context structure
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
typedef struct awrtc_mbedtls_des3_context {
    uint32_t AWRTC_MBEDTLS_PRIVATE(sk)[96];            /*!<  3DES subkeys      */
}
awrtc_mbedtls_des3_context;

#else  /* AWRTC_MBEDTLS_DES_ALT */
#include "des_alt.h"
#endif /* AWRTC_MBEDTLS_DES_ALT */

/**
 * \brief          Initialize DES context
 *
 * \param ctx      DES context to be initialized
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void awrtc_mbedtls_des_init(awrtc_mbedtls_des_context *ctx);

/**
 * \brief          Clear DES context
 *
 * \param ctx      DES context to be cleared
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void awrtc_mbedtls_des_free(awrtc_mbedtls_des_context *ctx);

/**
 * \brief          Initialize Triple-DES context
 *
 * \param ctx      DES3 context to be initialized
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void awrtc_mbedtls_des3_init(awrtc_mbedtls_des3_context *ctx);

/**
 * \brief          Clear Triple-DES context
 *
 * \param ctx      DES3 context to be cleared
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void awrtc_mbedtls_des3_free(awrtc_mbedtls_des3_context *ctx);

/**
 * \brief          Set key parity on the given key to odd.
 *
 *                 DES keys are 56 bits long, but each byte is padded with
 *                 a parity bit to allow verification.
 *
 * \param key      8-byte secret key
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void awrtc_mbedtls_des_key_set_parity(unsigned char key[AWRTC_MBEDTLS_DES_KEY_SIZE]);

/**
 * \brief          Check that key parity on the given key is odd.
 *
 *                 DES keys are 56 bits long, but each byte is padded with
 *                 a parity bit to allow verification.
 *
 * \param key      8-byte secret key
 *
 * \return         0 is parity was ok, 1 if parity was not correct.
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
AWRTC_MBEDTLS_CHECK_RETURN_TYPICAL
int awrtc_mbedtls_des_key_check_key_parity(const unsigned char key[AWRTC_MBEDTLS_DES_KEY_SIZE]);

/**
 * \brief          Check that key is not a weak or semi-weak DES key
 *
 * \param key      8-byte secret key
 *
 * \return         0 if no weak key was found, 1 if a weak key was identified.
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
AWRTC_MBEDTLS_CHECK_RETURN_TYPICAL
int awrtc_mbedtls_des_key_check_weak(const unsigned char key[AWRTC_MBEDTLS_DES_KEY_SIZE]);

/**
 * \brief          DES key schedule (56-bit, encryption)
 *
 * \param ctx      DES context to be initialized
 * \param key      8-byte secret key
 *
 * \return         0
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
AWRTC_MBEDTLS_CHECK_RETURN_TYPICAL
int awrtc_mbedtls_des_setkey_enc(awrtc_mbedtls_des_context *ctx, const unsigned char key[AWRTC_MBEDTLS_DES_KEY_SIZE]);

/**
 * \brief          DES key schedule (56-bit, decryption)
 *
 * \param ctx      DES context to be initialized
 * \param key      8-byte secret key
 *
 * \return         0
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
AWRTC_MBEDTLS_CHECK_RETURN_TYPICAL
int awrtc_mbedtls_des_setkey_dec(awrtc_mbedtls_des_context *ctx, const unsigned char key[AWRTC_MBEDTLS_DES_KEY_SIZE]);

/**
 * \brief          Triple-DES key schedule (112-bit, encryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      16-byte secret key
 *
 * \return         0
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
AWRTC_MBEDTLS_CHECK_RETURN_TYPICAL
int awrtc_mbedtls_des3_set2key_enc(awrtc_mbedtls_des3_context *ctx,
                             const unsigned char key[AWRTC_MBEDTLS_DES_KEY_SIZE * 2]);

/**
 * \brief          Triple-DES key schedule (112-bit, decryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      16-byte secret key
 *
 * \return         0
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
AWRTC_MBEDTLS_CHECK_RETURN_TYPICAL
int awrtc_mbedtls_des3_set2key_dec(awrtc_mbedtls_des3_context *ctx,
                             const unsigned char key[AWRTC_MBEDTLS_DES_KEY_SIZE * 2]);

/**
 * \brief          Triple-DES key schedule (168-bit, encryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      24-byte secret key
 *
 * \return         0
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
AWRTC_MBEDTLS_CHECK_RETURN_TYPICAL
int awrtc_mbedtls_des3_set3key_enc(awrtc_mbedtls_des3_context *ctx,
                             const unsigned char key[AWRTC_MBEDTLS_DES_KEY_SIZE * 3]);

/**
 * \brief          Triple-DES key schedule (168-bit, decryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      24-byte secret key
 *
 * \return         0
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
AWRTC_MBEDTLS_CHECK_RETURN_TYPICAL
int awrtc_mbedtls_des3_set3key_dec(awrtc_mbedtls_des3_context *ctx,
                             const unsigned char key[AWRTC_MBEDTLS_DES_KEY_SIZE * 3]);

/**
 * \brief          DES-ECB block encryption/decryption
 *
 * \param ctx      DES context
 * \param input    64-bit input block
 * \param output   64-bit output block
 *
 * \return         0 if successful
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
AWRTC_MBEDTLS_CHECK_RETURN_TYPICAL
int awrtc_mbedtls_des_crypt_ecb(awrtc_mbedtls_des_context *ctx,
                          const unsigned char input[8],
                          unsigned char output[8]);

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_CBC)
/**
 * \brief          DES-CBC buffer encryption/decryption
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      DES context
 * \param mode     AWRTC_MBEDTLS_DES_ENCRYPT or AWRTC_MBEDTLS_DES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
AWRTC_MBEDTLS_CHECK_RETURN_TYPICAL
int awrtc_mbedtls_des_crypt_cbc(awrtc_mbedtls_des_context *ctx,
                          int mode,
                          size_t length,
                          unsigned char iv[8],
                          const unsigned char *input,
                          unsigned char *output);
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_CBC */

/**
 * \brief          3DES-ECB block encryption/decryption
 *
 * \param ctx      3DES context
 * \param input    64-bit input block
 * \param output   64-bit output block
 *
 * \return         0 if successful
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
AWRTC_MBEDTLS_CHECK_RETURN_TYPICAL
int awrtc_mbedtls_des3_crypt_ecb(awrtc_mbedtls_des3_context *ctx,
                           const unsigned char input[8],
                           unsigned char output[8]);

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_CBC)
/**
 * \brief          3DES-CBC buffer encryption/decryption
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      3DES context
 * \param mode     AWRTC_MBEDTLS_DES_ENCRYPT or AWRTC_MBEDTLS_DES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or AWRTC_MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
AWRTC_MBEDTLS_CHECK_RETURN_TYPICAL
int awrtc_mbedtls_des3_crypt_cbc(awrtc_mbedtls_des3_context *ctx,
                           int mode,
                           size_t length,
                           unsigned char iv[8],
                           const unsigned char *input,
                           unsigned char *output);
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_CBC */

/**
 * \brief          Internal function for key expansion.
 *                 (Only exposed to allow overriding it,
 *                 see AWRTC_MBEDTLS_DES_SETKEY_ALT)
 *
 * \param SK       Round keys
 * \param key      Base key
 *
 * \warning        DES/3DES are considered weak ciphers and their use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void awrtc_mbedtls_des_setkey(uint32_t SK[32],
                        const unsigned char key[AWRTC_MBEDTLS_DES_KEY_SIZE]);

#if defined(AWRTC_MBEDTLS_SELF_TEST)

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
AWRTC_MBEDTLS_CHECK_RETURN_CRITICAL
int awrtc_mbedtls_des_self_test(int verbose);

#endif /* AWRTC_MBEDTLS_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* des.h */
