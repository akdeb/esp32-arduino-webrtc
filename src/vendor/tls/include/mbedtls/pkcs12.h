/**
 * \file pkcs12.h
 *
 * \brief PKCS#12 Personal Information Exchange Syntax
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef AWRTC_MBEDTLS_PKCS12_H
#define AWRTC_MBEDTLS_PKCS12_H

#include "build_info.h"

#include "md.h"
#include "cipher.h"
#include "asn1.h"

#include <stddef.h>

/** Bad input parameters to function. */
#define AWRTC_MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA                 -0x1F80
/** Feature not available, e.g. unsupported encryption scheme. */
#define AWRTC_MBEDTLS_ERR_PKCS12_FEATURE_UNAVAILABLE            -0x1F00
/** PBE ASN.1 data not as expected. */
#define AWRTC_MBEDTLS_ERR_PKCS12_PBE_INVALID_FORMAT             -0x1E80
/** Given private key password does not allow for correct decryption. */
#define AWRTC_MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH              -0x1E00

#define AWRTC_MBEDTLS_PKCS12_DERIVE_KEY       1   /**< encryption/decryption key */
#define AWRTC_MBEDTLS_PKCS12_DERIVE_IV        2   /**< initialization vector     */
#define AWRTC_MBEDTLS_PKCS12_DERIVE_MAC_KEY   3   /**< integrity / MAC key       */

#define AWRTC_MBEDTLS_PKCS12_PBE_DECRYPT      AWRTC_MBEDTLS_DECRYPT
#define AWRTC_MBEDTLS_PKCS12_PBE_ENCRYPT      AWRTC_MBEDTLS_ENCRYPT

#ifdef __cplusplus
extern "C" {
#endif

#if defined(AWRTC_MBEDTLS_ASN1_PARSE_C) && defined(AWRTC_MBEDTLS_CIPHER_C)

#if !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
/**
 * \brief            PKCS12 Password Based function (encryption / decryption)
 *                   for cipher-based and awrtc_mbedtls_md-based PBE's
 *
 * \note             When encrypting, #AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7 must
 *                   be enabled at compile time.
 *
 * \deprecated       This function is deprecated and will be removed in a
 *                   future version of the library.
 *                   Please use awrtc_mbedtls_pkcs12_pbe_ext() instead.
 *
 * \warning          When decrypting:
 *                   - if #AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7 is enabled at compile
 *                     time, this function validates the CBC padding and returns
 *                     #AWRTC_MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH if the padding is
 *                     invalid. Note that this can help active adversaries
 *                     attempting to brute-forcing the password. Note also that
 *                     there is no guarantee that an invalid password will be
 *                     detected (the chances of a valid padding with a random
 *                     password are about 1/255).
 *                   - if #AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7 is disabled at compile
 *                     time, this function does not validate the CBC padding.
 *
 * \param pbe_params an ASN1 buffer containing the pkcs-12 PbeParams structure
 * \param mode       either #AWRTC_MBEDTLS_PKCS12_PBE_ENCRYPT or
 *                   #AWRTC_MBEDTLS_PKCS12_PBE_DECRYPT
 * \param cipher_type the cipher used
 * \param md_type    the awrtc_mbedtls_md used
 * \param pwd        Latin1-encoded password used. This may only be \c NULL when
 *                   \p pwdlen is 0. No null terminator should be used.
 * \param pwdlen     length of the password (may be 0)
 * \param data       the input data
 * \param len        data length
 * \param output     Output buffer.
 *                   On success, it contains the encrypted or decrypted data,
 *                   possibly followed by the CBC padding.
 *                   On failure, the content is indeterminate.
 *                   For decryption, there must be enough room for \p len
 *                   bytes.
 *                   For encryption, there must be enough room for
 *                   \p len + 1 bytes, rounded up to the block size of
 *                   the block cipher identified by \p pbe_params.
 *
 * \return           0 if successful, or a AWRTC_MBEDTLS_ERR_XXX code
 */
int AWRTC_MBEDTLS_DEPRECATED awrtc_mbedtls_pkcs12_pbe(awrtc_mbedtls_asn1_buf *pbe_params, int mode,
                                          awrtc_mbedtls_cipher_type_t cipher_type,
                                          awrtc_mbedtls_md_type_t md_type,
                                          const unsigned char *pwd,  size_t pwdlen,
                                          const unsigned char *data, size_t len,
                                          unsigned char *output);
#endif /* AWRTC_MBEDTLS_DEPRECATED_REMOVED */

#if defined(AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7)

/**
 * \brief            PKCS12 Password Based function (encryption / decryption)
 *                   for cipher-based and awrtc_mbedtls_md-based PBE's
 *
 *
 * \warning          When decrypting:
 *                   - This function validates the CBC padding and returns
 *                     #AWRTC_MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH if the padding is
 *                     invalid. Note that this can help active adversaries
 *                     attempting to brute-forcing the password. Note also that
 *                     there is no guarantee that an invalid password will be
 *                     detected (the chances of a valid padding with a random
 *                     password are about 1/255).
 *
 * \param pbe_params an ASN1 buffer containing the pkcs-12 PbeParams structure
 * \param mode       either #AWRTC_MBEDTLS_PKCS12_PBE_ENCRYPT or
 *                   #AWRTC_MBEDTLS_PKCS12_PBE_DECRYPT
 * \param cipher_type the cipher used
 * \param md_type    the awrtc_mbedtls_md used
 * \param pwd        Latin1-encoded password used. This may only be \c NULL when
 *                   \p pwdlen is 0. No null terminator should be used.
 * \param pwdlen     length of the password (may be 0)
 * \param data       the input data
 * \param len        data length
 * \param output     Output buffer.
 *                   On success, it contains the encrypted or decrypted data,
 *                   possibly followed by the CBC padding.
 *                   On failure, the content is indeterminate.
 *                   For decryption, there must be enough room for \p len
 *                   bytes.
 *                   For encryption, there must be enough room for
 *                   \p len + 1 bytes, rounded up to the block size of
 *                   the block cipher identified by \p pbe_params.
 * \param output_size size of output buffer.
 *                    This must be big enough to accommodate for output plus
 *                    padding data.
 * \param output_len On success, length of actual data written to the output buffer.
 *
 * \return           0 if successful, or a AWRTC_MBEDTLS_ERR_XXX code
 */
int awrtc_mbedtls_pkcs12_pbe_ext(awrtc_mbedtls_asn1_buf *pbe_params, int mode,
                           awrtc_mbedtls_cipher_type_t cipher_type, awrtc_mbedtls_md_type_t md_type,
                           const unsigned char *pwd,  size_t pwdlen,
                           const unsigned char *data, size_t len,
                           unsigned char *output, size_t output_size,
                           size_t *output_len);

#endif /* AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7 */

#endif /* AWRTC_MBEDTLS_ASN1_PARSE_C && AWRTC_MBEDTLS_CIPHER_C */

/**
 * \brief            The PKCS#12 derivation function uses a password and a salt
 *                   to produce pseudo-random bits for a particular "purpose".
 *
 *                   Depending on the given id, this function can produce an
 *                   encryption/decryption key, an initialization vector or an
 *                   integrity key.
 *
 * \param data       buffer to store the derived data in
 * \param datalen    length of buffer to fill
 * \param pwd        The password to use. For compliance with PKCS#12 §B.1, this
 *                   should be a BMPString, i.e. a Unicode string where each
 *                   character is encoded as 2 bytes in big-endian order, with
 *                   no byte order mark and with a null terminator (i.e. the
 *                   last two bytes should be 0x00 0x00).
 * \param pwdlen     length of the password (may be 0).
 * \param salt       Salt buffer to use. This may only be \c NULL when
 *                   \p saltlen is 0.
 * \param saltlen    length of the salt (may be zero)
 * \param awrtc_mbedtls_md awrtc_mbedtls_md type to use during the derivation
 * \param id         id that describes the purpose (can be
 *                   #AWRTC_MBEDTLS_PKCS12_DERIVE_KEY, #AWRTC_MBEDTLS_PKCS12_DERIVE_IV or
 *                   #AWRTC_MBEDTLS_PKCS12_DERIVE_MAC_KEY)
 * \param iterations number of iterations
 *
 * \return          0 if successful, or a MD, BIGNUM type error.
 */
int awrtc_mbedtls_pkcs12_derivation(unsigned char *data, size_t datalen,
                              const unsigned char *pwd, size_t pwdlen,
                              const unsigned char *salt, size_t saltlen,
                              awrtc_mbedtls_md_type_t awrtc_mbedtls_md, int id, int iterations);

#ifdef __cplusplus
}
#endif

#endif /* pkcs12.h */
