/**
 * \file pkcs5.h
 *
 * \brief PKCS#5 functions
 *
 * \author Mathias Olsson <mathias@kompetensum.com>
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef AWRTC_MBEDTLS_PKCS5_H
#define AWRTC_MBEDTLS_PKCS5_H

#include "build_info.h"
#include "platform_util.h"

#include "asn1.h"
#include "md.h"
#include "cipher.h"

#include <stddef.h>
#include <stdint.h>

/** Bad input parameters to function. */
#define AWRTC_MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA                  -0x2f80
/** Unexpected ASN.1 data. */
#define AWRTC_MBEDTLS_ERR_PKCS5_INVALID_FORMAT                  -0x2f00
/** Requested encryption or digest alg not available. */
#define AWRTC_MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE             -0x2e80
/** Given private key password does not allow for correct decryption. */
#define AWRTC_MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH               -0x2e00

#define AWRTC_MBEDTLS_PKCS5_DECRYPT      AWRTC_MBEDTLS_DECRYPT
#define AWRTC_MBEDTLS_PKCS5_ENCRYPT      AWRTC_MBEDTLS_ENCRYPT

#ifdef __cplusplus
extern "C" {
#endif

#if defined(AWRTC_MBEDTLS_ASN1_PARSE_C) && defined(AWRTC_MBEDTLS_CIPHER_C)

#if !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
/**
 * \brief          PKCS#5 PBES2 function
 *
 * \note           When encrypting, #AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7 must
 *                 be enabled at compile time.
 *
 * \deprecated     This function is deprecated and will be removed in a
 *                 future version of the library.
 *                 Please use awrtc_mbedtls_pkcs5_pbes2_ext() instead.
 *
 * \warning        When decrypting:
 *                 - if #AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7 is enabled at compile
 *                   time, this function validates the CBC padding and returns
 *                   #AWRTC_MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH if the padding is
 *                   invalid. Note that this can help active adversaries
 *                   attempting to brute-forcing the password. Note also that
 *                   there is no guarantee that an invalid password will be
 *                   detected (the chances of a valid padding with a random
 *                   password are about 1/255).
 *                 - if #AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7 is disabled at compile
 *                   time, this function does not validate the CBC padding.
 *
 * \param pbe_params the ASN.1 algorithm parameters
 * \param mode       either #AWRTC_MBEDTLS_PKCS5_DECRYPT or #AWRTC_MBEDTLS_PKCS5_ENCRYPT
 * \param pwd        password to use when generating key
 * \param pwdlen     length of password
 * \param data       data to process
 * \param datalen    length of data
 * \param output     Output buffer.
 *                   On success, it contains the encrypted or decrypted data,
 *                   possibly followed by the CBC padding.
 *                   On failure, the content is indeterminate.
 *                   For decryption, there must be enough room for \p datalen
 *                   bytes.
 *                   For encryption, there must be enough room for
 *                   \p datalen + 1 bytes, rounded up to the block size of
 *                   the block cipher identified by \p pbe_params.
 *
 * \returns        0 on success, or a AWRTC_MBEDTLS_ERR_XXX code if verification fails.
 */
int AWRTC_MBEDTLS_DEPRECATED awrtc_mbedtls_pkcs5_pbes2(const awrtc_mbedtls_asn1_buf *pbe_params, int mode,
                                           const unsigned char *pwd,  size_t pwdlen,
                                           const unsigned char *data, size_t datalen,
                                           unsigned char *output);
#endif /* AWRTC_MBEDTLS_DEPRECATED_REMOVED */

#if defined(AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7)

/**
 * \brief          PKCS#5 PBES2 function
 *
 * \warning        When decrypting:
 *                 - This function validates the CBC padding and returns
 *                   #AWRTC_MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH if the padding is
 *                   invalid. Note that this can help active adversaries
 *                   attempting to brute-forcing the password. Note also that
 *                   there is no guarantee that an invalid password will be
 *                   detected (the chances of a valid padding with a random
 *                   password are about 1/255).
 *
 * \param pbe_params the ASN.1 algorithm parameters
 * \param mode       either #AWRTC_MBEDTLS_PKCS5_DECRYPT or #AWRTC_MBEDTLS_PKCS5_ENCRYPT
 * \param pwd        password to use when generating key
 * \param pwdlen     length of password
 * \param data       data to process
 * \param datalen    length of data
 * \param output     Output buffer.
 *                   On success, it contains the decrypted data.
 *                   On failure, the content is indetermidate.
 *                   For decryption, there must be enough room for \p datalen
 *                   bytes.
 *                   For encryption, there must be enough room for
 *                   \p datalen + 1 bytes, rounded up to the block size of
 *                   the block cipher identified by \p pbe_params.
 * \param output_size size of output buffer.
 *                    This must be big enough to accommodate for output plus
 *                    padding data.
 * \param output_len On success, length of actual data written to the output buffer.
 *
 * \returns        0 on success, or a AWRTC_MBEDTLS_ERR_XXX code if parsing or decryption fails.
 */
int awrtc_mbedtls_pkcs5_pbes2_ext(const awrtc_mbedtls_asn1_buf *pbe_params, int mode,
                            const unsigned char *pwd,  size_t pwdlen,
                            const unsigned char *data, size_t datalen,
                            unsigned char *output, size_t output_size,
                            size_t *output_len);

#endif /* AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7 */

#endif /* AWRTC_MBEDTLS_ASN1_PARSE_C && AWRTC_MBEDTLS_CIPHER_C*/

/**
 * \brief          PKCS#5 PBKDF2 using HMAC without using the HMAC context
 *
 * \param md_type  Hash algorithm used
 * \param password Password to use when generating key
 * \param plen     Length of password
 * \param salt     Salt to use when generating key
 * \param slen     Length of salt
 * \param iteration_count       Iteration count
 * \param key_length            Length of generated key in bytes
 * \param output   Generated key. Must be at least as big as key_length
 *
 * \returns        0 on success, or a AWRTC_MBEDTLS_ERR_XXX code if verification fails.
 */
int awrtc_mbedtls_pkcs5_pbkdf2_hmac_ext(awrtc_mbedtls_md_type_t md_type,
                                  const unsigned char *password,
                                  size_t plen, const unsigned char *salt, size_t slen,
                                  unsigned int iteration_count,
                                  uint32_t key_length, unsigned char *output);

#if defined(AWRTC_MBEDTLS_MD_C)
#if !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
/**
 * \brief          PKCS#5 PBKDF2 using HMAC
 *
 * \deprecated     Superseded by awrtc_mbedtls_pkcs5_pbkdf2_hmac_ext().
 *
 * \param ctx      Generic HMAC context
 * \param password Password to use when generating key
 * \param plen     Length of password
 * \param salt     Salt to use when generating key
 * \param slen     Length of salt
 * \param iteration_count       Iteration count
 * \param key_length            Length of generated key in bytes
 * \param output   Generated key. Must be at least as big as key_length
 *
 * \returns        0 on success, or a AWRTC_MBEDTLS_ERR_XXX code if verification fails.
 */
int AWRTC_MBEDTLS_DEPRECATED awrtc_mbedtls_pkcs5_pbkdf2_hmac(awrtc_mbedtls_md_context_t *ctx,
                                                 const unsigned char *password,
                                                 size_t plen,
                                                 const unsigned char *salt,
                                                 size_t slen,
                                                 unsigned int iteration_count,
                                                 uint32_t key_length,
                                                 unsigned char *output);
#endif /* !AWRTC_MBEDTLS_DEPRECATED_REMOVED */
#endif /* AWRTC_MBEDTLS_MD_C */
#if defined(AWRTC_MBEDTLS_SELF_TEST)

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int awrtc_mbedtls_pkcs5_self_test(int verbose);

#endif /* AWRTC_MBEDTLS_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* pkcs5.h */
