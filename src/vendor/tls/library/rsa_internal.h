/**
 * \file rsa_internal.h
 *
 * \brief Internal-only RSA public-key cryptosystem API.
 *
 * This file declares RSA-related functions that are to be used
 * only from within the Mbed TLS library itself.
 *
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef AWRTC_MBEDTLS_RSA_INTERNAL_H
#define AWRTC_MBEDTLS_RSA_INTERNAL_H

#include "../include/mbedtls/rsa.h"
#include "../include/mbedtls/asn1.h"

/**
 * \brief           Parse a PKCS#1 (ASN.1) encoded private RSA key.
 *
 * \param rsa       The RSA context where parsed data will be stored.
 * \param key       The buffer that contains the key.
 * \param keylen    The length of the key buffer in bytes.
 *
 * \return          0 on success.
 * \return          AWRTC_MBEDTLS_ERR_ASN1_xxx in case of ASN.1 parsing errors.
 * \return          AWRTC_MBEDTLS_ERR_RSA_xxx in case of RSA internal failures while
 *                  parsing data.
 * \return          AWRTC_MBEDTLS_ERR_RSA_KEY_CHECK_FAILED if validity checks on the
 *                  provided key fail.
 */
int awrtc_mbedtls_rsa_parse_key(awrtc_mbedtls_rsa_context *rsa, const unsigned char *key, size_t keylen);

/**
 * \brief           Parse a PKCS#1 (ASN.1) encoded public RSA key.
 *
 * \param rsa       The RSA context where parsed data will be stored.
 * \param key       The buffer that contains the key.
 * \param keylen    The length of the key buffer in bytes.
 *
 * \return          0 on success.
 * \return          AWRTC_MBEDTLS_ERR_ASN1_xxx in case of ASN.1 parsing errors.
 * \return          AWRTC_MBEDTLS_ERR_RSA_xxx in case of RSA internal failures while
 *                  parsing data.
 * \return          AWRTC_MBEDTLS_ERR_RSA_KEY_CHECK_FAILED if validity checks on the
 *                  provided key fail.
 */
int awrtc_mbedtls_rsa_parse_pubkey(awrtc_mbedtls_rsa_context *rsa, const unsigned char *key, size_t keylen);

/**
 * \brief           Write a PKCS#1 (ASN.1) encoded private RSA key.
 *
 * \param rsa       The RSA context which contains the data to be written.
 * \param start     Beginning of the buffer that will be filled with the
 *                  private key.
 * \param p         End of the buffer that will be filled with the private key.
 *                  On successful return, the referenced pointer will be
 *                  updated in order to point to the beginning of written data.
 *
 * \return          On success, the number of bytes written to the output buffer
 *                  (i.e. a value > 0).
 * \return          AWRTC_MBEDTLS_ERR_RSA_BAD_INPUT_DATA if the RSA context does not
 *                  contain a valid key pair.
 * \return          AWRTC_MBEDTLS_ERR_ASN1_xxx in case of failure while writing to the
 *                  output buffer.
 *
 * \note            The output buffer is filled backward, i.e. starting from its
 *                  end and moving toward its start.
 */
int awrtc_mbedtls_rsa_write_key(const awrtc_mbedtls_rsa_context *rsa, unsigned char *start,
                          unsigned char **p);

/**
 * \brief           Parse a PKCS#1 (ASN.1) encoded public RSA key.
 *
 * \param rsa       The RSA context which contains the data to be written.
 * \param start     Beginning of the buffer that will be filled with the
 *                  private key.
 * \param p         End of the buffer that will be filled with the private key.
 *                  On successful return, the referenced pointer will be
 *                  updated in order to point to the beginning of written data.
 *
 * \return          On success, the number of bytes written to the output buffer
 *                  (i.e. a value > 0).
 * \return          AWRTC_MBEDTLS_ERR_RSA_BAD_INPUT_DATA if the RSA context does not
 *                  contain a valid public key.
 * \return          AWRTC_MBEDTLS_ERR_ASN1_xxx in case of failure while writing to the
 *                  output buffer.
 *
 * \note            The output buffer is filled backward, i.e. starting from its
 *                  end and moving toward its start.
 */
int awrtc_mbedtls_rsa_write_pubkey(const awrtc_mbedtls_rsa_context *rsa, unsigned char *start,
                             unsigned char **p);

#if defined(AWRTC_MBEDTLS_PKCS1_V21)
/**
 * \brief This function is analogue to \c awrtc_mbedtls_rsa_rsassa_pss_sign().
 *        The only difference between them is that this function is more flexible
 *        on the parameters of \p ctx that are set with \c awrtc_mbedtls_rsa_set_padding().
 *
 * \note  Compared to its counterpart, this function:
 *        - does not check the padding setting of \p ctx.
 *        - allows the hash_id of \p ctx to be AWRTC_MBEDTLS_MD_NONE,
 *          in which case it uses \p md_alg as the hash_id.
 *
 * \note  Refer to \c awrtc_mbedtls_rsa_rsassa_pss_sign() for a description
 *        of the functioning and parameters of this function.
 */
int awrtc_mbedtls_rsa_rsassa_pss_sign_no_mode_check(awrtc_mbedtls_rsa_context *ctx,
                                              int (*f_rng)(void *, unsigned char *, size_t),
                                              void *p_rng,
                                              awrtc_mbedtls_md_type_t md_alg,
                                              unsigned int hashlen,
                                              const unsigned char *hash,
                                              unsigned char *sig);
#endif /* AWRTC_MBEDTLS_PKCS1_V21 */

#endif /* rsa_internal.h */
