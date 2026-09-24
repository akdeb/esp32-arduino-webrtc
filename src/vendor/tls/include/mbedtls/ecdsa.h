/**
 * \file ecdsa.h
 *
 * \brief This file contains ECDSA definitions and functions.
 *
 * The Elliptic Curve Digital Signature Algorithm (ECDSA) is defined in
 * <em>Standards for Efficient Cryptography Group (SECG):
 * SEC1 Elliptic Curve Cryptography</em>.
 * The use of ECDSA for TLS is defined in <em>RFC-4492: Elliptic Curve
 * Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)</em>.
 *
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_MBEDTLS_ECDSA_H
#define AWRTC_MBEDTLS_ECDSA_H
#include "private_access.h"

#include "build_info.h"

#include "ecp.h"
#include "md.h"

/**
 * \brief           Maximum ECDSA signature size for a given curve bit size
 *
 * \param bits      Curve size in bits
 * \return          Maximum signature size in bytes
 *
 * \note            This macro returns a compile-time constant if its argument
 *                  is one. It may evaluate its argument multiple times.
 */
/*
 *     Ecdsa-Sig-Value ::= SEQUENCE {
 *         r       INTEGER,
 *         s       INTEGER
 *     }
 *
 * For each of r and s, the value (V) may include an extra initial "0" bit.
 */
#define AWRTC_MBEDTLS_ECDSA_MAX_SIG_LEN(bits)                               \
    (/*T,L of SEQUENCE*/ ((bits) >= 61 * 8 ? 3 : 2) +              \
     /*T,L of r,s*/ 2 * (((bits) >= 127 * 8 ? 3 : 2) +     \
                         /*V of r,s*/ ((bits) + 8) / 8))

/** The maximal size of an ECDSA signature in Bytes. */
#define AWRTC_MBEDTLS_ECDSA_MAX_LEN  AWRTC_MBEDTLS_ECDSA_MAX_SIG_LEN(AWRTC_MBEDTLS_ECP_MAX_BITS)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           The ECDSA context structure.
 *
 * \warning         Performing multiple operations concurrently on the same
 *                  ECDSA context is not supported; objects of this type
 *                  should not be shared between multiple threads.
 *
 * \note            pk_wrap module assumes that "ecdsa_context" is identical
 *                  to "ecp_keypair" (see for example structure
 *                  "awrtc_mbedtls_eckey_info" where ECDSA sign/verify functions
 *                  are used also for EC key)
 */
typedef awrtc_mbedtls_ecp_keypair awrtc_mbedtls_ecdsa_context;

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)

/**
 * \brief           Internal restart context for ecdsa_verify()
 *
 * \note            Opaque struct, defined in ecdsa.c
 */
typedef struct awrtc_mbedtls_ecdsa_restart_ver awrtc_mbedtls_ecdsa_restart_ver_ctx;

/**
 * \brief           Internal restart context for ecdsa_sign()
 *
 * \note            Opaque struct, defined in ecdsa.c
 */
typedef struct awrtc_mbedtls_ecdsa_restart_sig awrtc_mbedtls_ecdsa_restart_sig_ctx;

#if defined(AWRTC_MBEDTLS_ECDSA_DETERMINISTIC)
/**
 * \brief           Internal restart context for ecdsa_sign_det()
 *
 * \note            Opaque struct, defined in ecdsa.c
 */
typedef struct awrtc_mbedtls_ecdsa_restart_det awrtc_mbedtls_ecdsa_restart_det_ctx;
#endif

/**
 * \brief           General context for resuming ECDSA operations
 */
typedef struct {
    awrtc_mbedtls_ecp_restart_ctx AWRTC_MBEDTLS_PRIVATE(ecp);        /*!<  base context for ECP restart and
                                                            shared administrative info    */
    awrtc_mbedtls_ecdsa_restart_ver_ctx *AWRTC_MBEDTLS_PRIVATE(ver); /*!<  ecdsa_verify() sub-context    */
    awrtc_mbedtls_ecdsa_restart_sig_ctx *AWRTC_MBEDTLS_PRIVATE(sig); /*!<  ecdsa_sign() sub-context      */
#if defined(AWRTC_MBEDTLS_ECDSA_DETERMINISTIC)
    awrtc_mbedtls_ecdsa_restart_det_ctx *AWRTC_MBEDTLS_PRIVATE(det); /*!<  ecdsa_sign_det() sub-context  */
#endif
} awrtc_mbedtls_ecdsa_restart_ctx;

#else /* AWRTC_MBEDTLS_ECP_RESTARTABLE */

/* Now we can declare functions that take a pointer to that */
typedef void awrtc_mbedtls_ecdsa_restart_ctx;

#endif /* AWRTC_MBEDTLS_ECP_RESTARTABLE */

/**
 * \brief          This function checks whether a given group can be used
 *                 for ECDSA.
 *
 * \param gid      The ECP group ID to check.
 *
 * \return         \c 1 if the group can be used, \c 0 otherwise
 */
int awrtc_mbedtls_ecdsa_can_do(awrtc_mbedtls_ecp_group_id gid);

/**
 * \brief           This function computes the ECDSA signature of a
 *                  previously-hashed message.
 *
 * \note            The deterministic version implemented in
 *                  awrtc_mbedtls_ecdsa_sign_det_ext() is usually preferred.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated
 *                  as defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.3, step 5.
 *
 * \see             ecp.h
 *
 * \param grp       The context for the elliptic curve to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param r         The MPI context in which to store the first part
 *                  the signature. This must be initialized.
 * \param s         The MPI context in which to store the second part
 *                  the signature. This must be initialized.
 * \param d         The private signing key. This must be initialized.
 * \param buf       The content to be signed. This is usually the hash of
 *                  the original data to be signed. This must be a readable
 *                  buffer of length \p blen Bytes. It may be \c NULL if
 *                  \p blen is zero.
 * \param blen      The length of \p buf in Bytes.
 * \param f_rng     The RNG function, used both to generate the ECDSA nonce
 *                  and for blinding. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL if \p f_rng doesn't need a context parameter.
 *
 * \return          \c 0 on success.
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX
 *                  or \c AWRTC_MBEDTLS_MPI_XXX error code on failure.
 */
int awrtc_mbedtls_ecdsa_sign(awrtc_mbedtls_ecp_group *grp, awrtc_mbedtls_mpi *r, awrtc_mbedtls_mpi *s,
                       const awrtc_mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       awrtc_mbedtls_f_rng_t *f_rng, void *p_rng);

#if defined(AWRTC_MBEDTLS_ECDSA_DETERMINISTIC)
/**
 * \brief           This function computes the ECDSA signature of a
 *                  previously-hashed message, deterministic version.
 *
 *                  For more information, see <em>RFC-6979: Deterministic
 *                  Usage of the Digital Signature Algorithm (DSA) and Elliptic
 *                  Curve Digital Signature Algorithm (ECDSA)</em>.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.3, step 5.
 *
 * \see             ecp.h
 *
 * \param grp           The context for the elliptic curve to use.
 *                      This must be initialized and have group parameters
 *                      set, for example through awrtc_mbedtls_ecp_group_load().
 * \param r             The MPI context in which to store the first part
 *                      the signature. This must be initialized.
 * \param s             The MPI context in which to store the second part
 *                      the signature. This must be initialized.
 * \param d             The private signing key. This must be initialized
 *                      and setup, for example through awrtc_mbedtls_ecp_gen_privkey().
 * \param buf           The hashed content to be signed. This must be a readable
 *                      buffer of length \p blen Bytes. It may be \c NULL if
 *                      \p blen is zero.
 * \param blen          The length of \p buf in Bytes.
 * \param md_alg        The hash algorithm used to hash the original data.
 * \param f_rng_blind   The RNG function used for blinding. This must not be
 *                      \c NULL.
 * \param p_rng_blind   The RNG context to be passed to \p f_rng_blind. This
 *                      may be \c NULL if \p f_rng_blind doesn't need a context
 *                      parameter.
 *
 * \return          \c 0 on success.
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX or \c AWRTC_MBEDTLS_MPI_XXX
 *                  error code on failure.
 */
int awrtc_mbedtls_ecdsa_sign_det_ext(awrtc_mbedtls_ecp_group *grp, awrtc_mbedtls_mpi *r,
                               awrtc_mbedtls_mpi *s, const awrtc_mbedtls_mpi *d,
                               const unsigned char *buf, size_t blen,
                               awrtc_mbedtls_md_type_t md_alg,
                               awrtc_mbedtls_f_rng_t *f_rng_blind,
                               void *p_rng_blind);
#endif /* AWRTC_MBEDTLS_ECDSA_DETERMINISTIC */

#if !defined(AWRTC_MBEDTLS_ECDSA_SIGN_ALT)
/**
 * \brief               This function computes the ECDSA signature of a
 *                      previously-hashed message, in a restartable way.
 *
 * \note                The deterministic version implemented in
 *                      awrtc_mbedtls_ecdsa_sign_det_restartable() is usually
 *                      preferred.
 *
 * \note                This function is like \c awrtc_mbedtls_ecdsa_sign() but
 *                      it can return early and restart according to the
 *                      limit set with \c awrtc_mbedtls_ecp_set_max_ops() to
 *                      reduce blocking.
 *
 * \note                If the bitlength of the message hash is larger
 *                      than the bitlength of the group order, then the
 *                      hash is truncated as defined in <em>Standards for
 *                      Efficient Cryptography Group (SECG): SEC1 Elliptic
 *                      Curve Cryptography</em>, section 4.1.3, step 5.
 *
 * \see                 ecp.h
 *
 * \param grp           The context for the elliptic curve to use.
 *                      This must be initialized and have group parameters
 *                      set, for example through awrtc_mbedtls_ecp_group_load().
 * \param r             The MPI context in which to store the first part
 *                      the signature. This must be initialized.
 * \param s             The MPI context in which to store the second part
 *                      the signature. This must be initialized.
 * \param d             The private signing key. This must be initialized
 *                      and setup, for example through
 *                      awrtc_mbedtls_ecp_gen_privkey().
 * \param buf           The hashed content to be signed. This must be a readable
 *                      buffer of length \p blen Bytes. It may be \c NULL if
 *                      \p blen is zero.
 * \param blen          The length of \p buf in Bytes.
 * \param f_rng         The RNG function used to generate the ECDSA nonce.
 *                      This must not be \c NULL.
 * \param p_rng         The RNG context to be passed to \p f_rng. This may be
 *                      \c NULL if \p f_rng doesn't need a context parameter.
 * \param f_rng_blind   The RNG function used for blinding. This must not be
 *                      \c NULL.
 * \param p_rng_blind   The RNG context to be passed to \p f_rng. This may be
 *                      \c NULL if \p f_rng doesn't need a context parameter.
 * \param rs_ctx        The restart context to use. This may be \c NULL
 *                      to disable restarting. If it is not \c NULL, it
 *                      must point to an initialized restart context.
 *
 * \return              \c 0 on success.
 * \return              #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                      operations was reached: see \c
 *                      awrtc_mbedtls_ecp_set_max_ops().
 * \return              Another \c AWRTC_MBEDTLS_ERR_ECP_XXX, \c
 *                      AWRTC_MBEDTLS_ERR_MPI_XXX or \c AWRTC_MBEDTLS_ERR_ASN1_XXX
 *                      error code on failure.
 */
int awrtc_mbedtls_ecdsa_sign_restartable(
    awrtc_mbedtls_ecp_group *grp,
    awrtc_mbedtls_mpi *r, awrtc_mbedtls_mpi *s,
    const awrtc_mbedtls_mpi *d,
    const unsigned char *buf, size_t blen,
    awrtc_mbedtls_f_rng_t *f_rng,
    void *p_rng,
    awrtc_mbedtls_f_rng_t *f_rng_blind,
    void *p_rng_blind,
    awrtc_mbedtls_ecdsa_restart_ctx *rs_ctx);

#endif /* !AWRTC_MBEDTLS_ECDSA_SIGN_ALT */

#if defined(AWRTC_MBEDTLS_ECDSA_DETERMINISTIC)

/**
 * \brief               This function computes the ECDSA signature of a
 *                      previously-hashed message, in a restartable way.
 *
 * \note                This function is like \c
 *                      awrtc_mbedtls_ecdsa_sign_det_ext() but it can return
 *                      early and restart according to the limit set with
 *                      \c awrtc_mbedtls_ecp_set_max_ops() to reduce blocking.
 *
 * \note                If the bitlength of the message hash is larger
 *                      than the bitlength of the group order, then the
 *                      hash is truncated as defined in <em>Standards for
 *                      Efficient Cryptography Group (SECG): SEC1 Elliptic
 *                      Curve Cryptography</em>, section 4.1.3, step 5.
 *
 * \see                 ecp.h
 *
 * \param grp           The context for the elliptic curve to use.
 *                      This must be initialized and have group parameters
 *                      set, for example through awrtc_mbedtls_ecp_group_load().
 * \param r             The MPI context in which to store the first part
 *                      the signature. This must be initialized.
 * \param s             The MPI context in which to store the second part
 *                      the signature. This must be initialized.
 * \param d             The private signing key. This must be initialized
 *                      and setup, for example through
 *                      awrtc_mbedtls_ecp_gen_privkey().
 * \param buf           The hashed content to be signed. This must be a readable
 *                      buffer of length \p blen Bytes. It may be \c NULL if
 *                      \p blen is zero.
 * \param blen          The length of \p buf in Bytes.
 * \param md_alg        The hash algorithm used to hash the original data.
 * \param f_rng_blind   The RNG function used for blinding. This must not be
 *                      \c NULL.
 * \param p_rng_blind   The RNG context to be passed to \p f_rng_blind. This may be
 *                      \c NULL if \p f_rng_blind doesn't need a context parameter.
 * \param rs_ctx        The restart context to use. This may be \c NULL
 *                      to disable restarting. If it is not \c NULL, it
 *                      must point to an initialized restart context.
 *
 * \return              \c 0 on success.
 * \return              #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                      operations was reached: see \c
 *                      awrtc_mbedtls_ecp_set_max_ops().
 * \return              Another \c AWRTC_MBEDTLS_ERR_ECP_XXX, \c
 *                      AWRTC_MBEDTLS_ERR_MPI_XXX or \c AWRTC_MBEDTLS_ERR_ASN1_XXX
 *                      error code on failure.
 */
int awrtc_mbedtls_ecdsa_sign_det_restartable(
    awrtc_mbedtls_ecp_group *grp,
    awrtc_mbedtls_mpi *r, awrtc_mbedtls_mpi *s,
    const awrtc_mbedtls_mpi *d, const unsigned char *buf, size_t blen,
    awrtc_mbedtls_md_type_t md_alg,
    awrtc_mbedtls_f_rng_t *f_rng_blind,
    void *p_rng_blind,
    awrtc_mbedtls_ecdsa_restart_ctx *rs_ctx);

#endif /* AWRTC_MBEDTLS_ECDSA_DETERMINISTIC */

/**
 * \brief           This function verifies the ECDSA signature of a
 *                  previously-hashed message.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.4, step 3.
 *
 * \see             ecp.h
 *
 * \param grp       The ECP group to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param buf       The hashed content that was signed. This must be a readable
 *                  buffer of length \p blen Bytes. It may be \c NULL if
 *                  \p blen is zero.
 * \param blen      The length of \p buf in Bytes.
 * \param Q         The public key to use for verification. This must be
 *                  initialized and setup.
 * \param r         The first integer of the signature.
 *                  This must be initialized.
 * \param s         The second integer of the signature.
 *                  This must be initialized.
 *
 * \return          \c 0 on success.
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX or \c AWRTC_MBEDTLS_MPI_XXX
 *                  error code on failure.
 */
int awrtc_mbedtls_ecdsa_verify(awrtc_mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const awrtc_mbedtls_ecp_point *Q, const awrtc_mbedtls_mpi *r,
                         const awrtc_mbedtls_mpi *s);

#if !defined(AWRTC_MBEDTLS_ECDSA_VERIFY_ALT)
/**
 * \brief           This function verifies the ECDSA signature of a
 *                  previously-hashed message, in a restartable manner
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.4, step 3.
 *
 * \see             ecp.h
 *
 * \param grp       The ECP group to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param buf       The hashed content that was signed. This must be a readable
 *                  buffer of length \p blen Bytes. It may be \c NULL if
 *                  \p blen is zero.
 * \param blen      The length of \p buf in Bytes.
 * \param Q         The public key to use for verification. This must be
 *                  initialized and setup.
 * \param r         The first integer of the signature.
 *                  This must be initialized.
 * \param s         The second integer of the signature.
 *                  This must be initialized.
 * \param rs_ctx    The restart context to use. This may be \c NULL to disable
 *                  restarting. If it is not \c NULL, it must point to an
 *                  initialized restart context.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c awrtc_mbedtls_ecp_set_max_ops().
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX or \c AWRTC_MBEDTLS_MPI_XXX
 *                  error code on failure.
 */
int awrtc_mbedtls_ecdsa_verify_restartable(awrtc_mbedtls_ecp_group *grp,
                                     const unsigned char *buf, size_t blen,
                                     const awrtc_mbedtls_ecp_point *Q,
                                     const awrtc_mbedtls_mpi *r,
                                     const awrtc_mbedtls_mpi *s,
                                     awrtc_mbedtls_ecdsa_restart_ctx *rs_ctx);

#endif /* !AWRTC_MBEDTLS_ECDSA_VERIFY_ALT */

/**
 * \brief           This function computes the ECDSA signature and writes it
 *                  to a buffer, serialized as defined in <em>RFC-4492:
 *                  Elliptic Curve Cryptography (ECC) Cipher Suites for
 *                  Transport Layer Security (TLS)</em>.
 *
 * \warning         It is not thread-safe to use the same context in
 *                  multiple threads.
 *
 * \note            The deterministic version is used if
 *                  #AWRTC_MBEDTLS_ECDSA_DETERMINISTIC is defined. For more
 *                  information, see <em>RFC-6979: Deterministic Usage
 *                  of the Digital Signature Algorithm (DSA) and Elliptic
 *                  Curve Digital Signature Algorithm (ECDSA)</em>.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.3, step 5.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDSA context to use. This must be initialized
 *                  and have a group and private key bound to it, for example
 *                  via awrtc_mbedtls_ecdsa_genkey() or awrtc_mbedtls_ecdsa_from_keypair().
 * \param md_alg    The message digest that was used to hash the message.
 * \param hash      The message hash to be signed. This must be a readable
 *                  buffer of length \p hlen Bytes.
 * \param hlen      The length of the hash \p hash in Bytes.
 * \param sig       The buffer to which to write the signature. This must be a
 *                  writable buffer of length at least twice as large as the
 *                  size of the curve used, plus 9. For example, 73 Bytes if
 *                  a 256-bit curve is used. A buffer length of
 *                  #AWRTC_MBEDTLS_ECDSA_MAX_LEN is always safe.
 * \param sig_size  The size of the \p sig buffer in bytes.
 * \param slen      The address at which to store the actual length of
 *                  the signature written. Must not be \c NULL.
 * \param f_rng     The RNG function. This is used for blinding.
 *                  If #AWRTC_MBEDTLS_ECDSA_DETERMINISTIC is unset, this is also
 *                  used to generate the ECDSA nonce.
 *                  This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL if \p f_rng is \c NULL or doesn't use a context.
 *
 * \return          \c 0 on success.
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX, \c AWRTC_MBEDTLS_ERR_MPI_XXX or
 *                  \c AWRTC_MBEDTLS_ERR_ASN1_XXX error code on failure.
 */
int awrtc_mbedtls_ecdsa_write_signature(awrtc_mbedtls_ecdsa_context *ctx,
                                  awrtc_mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hlen,
                                  unsigned char *sig, size_t sig_size, size_t *slen,
                                  awrtc_mbedtls_f_rng_t *f_rng,
                                  void *p_rng);

/**
 * \brief           This function computes the ECDSA signature and writes it
 *                  to a buffer, in a restartable way.
 *
 * \see             \c awrtc_mbedtls_ecdsa_write_signature()
 *
 * \note            This function is like \c awrtc_mbedtls_ecdsa_write_signature()
 *                  but it can return early and restart according to the limit
 *                  set with \c awrtc_mbedtls_ecp_set_max_ops() to reduce blocking.
 *
 * \param ctx       The ECDSA context to use. This must be initialized
 *                  and have a group and private key bound to it, for example
 *                  via awrtc_mbedtls_ecdsa_genkey() or awrtc_mbedtls_ecdsa_from_keypair().
 * \param md_alg    The message digest that was used to hash the message.
 * \param hash      The message hash to be signed. This must be a readable
 *                  buffer of length \p hlen Bytes.
 * \param hlen      The length of the hash \p hash in Bytes.
 * \param sig       The buffer to which to write the signature. This must be a
 *                  writable buffer of length at least twice as large as the
 *                  size of the curve used, plus 9. For example, 73 Bytes if
 *                  a 256-bit curve is used. A buffer length of
 *                  #AWRTC_MBEDTLS_ECDSA_MAX_LEN is always safe.
 * \param sig_size  The size of the \p sig buffer in bytes.
 * \param slen      The address at which to store the actual length of
 *                  the signature written. Must not be \c NULL.
 * \param f_rng     The RNG function. This is used for blinding.
 *                  If #AWRTC_MBEDTLS_ECDSA_DETERMINISTIC is unset, this is also
 *                  used to generate the ECDSA nonce.
 *                  This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL if \p f_rng is \c NULL or doesn't use a context.
 * \param rs_ctx    The restart context to use. This may be \c NULL to disable
 *                  restarting. If it is not \c NULL, it must point to an
 *                  initialized restart context.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c awrtc_mbedtls_ecp_set_max_ops().
 * \return          Another \c AWRTC_MBEDTLS_ERR_ECP_XXX, \c AWRTC_MBEDTLS_ERR_MPI_XXX or
 *                  \c AWRTC_MBEDTLS_ERR_ASN1_XXX error code on failure.
 */
int awrtc_mbedtls_ecdsa_write_signature_restartable(awrtc_mbedtls_ecdsa_context *ctx,
                                              awrtc_mbedtls_md_type_t md_alg,
                                              const unsigned char *hash, size_t hlen,
                                              unsigned char *sig, size_t sig_size, size_t *slen,
                                              awrtc_mbedtls_f_rng_t *f_rng,
                                              void *p_rng,
                                              awrtc_mbedtls_ecdsa_restart_ctx *rs_ctx);

/**
 * \brief           This function reads and verifies an ECDSA signature.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.4, step 3.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDSA context to use. This must be initialized
 *                  and have a group and public key bound to it.
 * \param hash      The message hash that was signed. This must be a readable
 *                  buffer of length \p hlen Bytes.
 * \param hlen      The size of the hash \p hash.
 * \param sig       The signature to read and verify. This must be a readable
 *                  buffer of length \p slen Bytes.
 * \param slen      The size of \p sig in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA if signature is invalid.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH if there is a valid
 *                  signature in \p sig, but its length is less than \p siglen.
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX or \c AWRTC_MBEDTLS_ERR_MPI_XXX
 *                  error code on failure for any other reason.
 */
int awrtc_mbedtls_ecdsa_read_signature(awrtc_mbedtls_ecdsa_context *ctx,
                                 const unsigned char *hash, size_t hlen,
                                 const unsigned char *sig, size_t slen);

/**
 * \brief           This function reads and verifies an ECDSA signature,
 *                  in a restartable way.
 *
 * \see             \c awrtc_mbedtls_ecdsa_read_signature()
 *
 * \note            This function is like \c awrtc_mbedtls_ecdsa_read_signature()
 *                  but it can return early and restart according to the limit
 *                  set with \c awrtc_mbedtls_ecp_set_max_ops() to reduce blocking.
 *
 * \param ctx       The ECDSA context to use. This must be initialized
 *                  and have a group and public key bound to it.
 * \param hash      The message hash that was signed. This must be a readable
 *                  buffer of length \p hlen Bytes.
 * \param hlen      The size of the hash \p hash.
 * \param sig       The signature to read and verify. This must be a readable
 *                  buffer of length \p slen Bytes.
 * \param slen      The size of \p sig in Bytes.
 * \param rs_ctx    The restart context to use. This may be \c NULL to disable
 *                  restarting. If it is not \c NULL, it must point to an
 *                  initialized restart context.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA if signature is invalid.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH if there is a valid
 *                  signature in \p sig, but its length is less than \p siglen.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c awrtc_mbedtls_ecp_set_max_ops().
 * \return          Another \c AWRTC_MBEDTLS_ERR_ECP_XXX or \c AWRTC_MBEDTLS_ERR_MPI_XXX
 *                  error code on failure for any other reason.
 */
int awrtc_mbedtls_ecdsa_read_signature_restartable(awrtc_mbedtls_ecdsa_context *ctx,
                                             const unsigned char *hash, size_t hlen,
                                             const unsigned char *sig, size_t slen,
                                             awrtc_mbedtls_ecdsa_restart_ctx *rs_ctx);

/**
 * \brief          This function generates an ECDSA keypair on the given curve.
 *
 * \see            ecp.h
 *
 * \param ctx      The ECDSA context to store the keypair in.
 *                 This must be initialized.
 * \param gid      The elliptic curve to use. One of the various
 *                 \c AWRTC_MBEDTLS_ECP_DP_XXX macros depending on configuration.
 * \param f_rng    The RNG function to use. This must not be \c NULL.
 * \param p_rng    The RNG context to be passed to \p f_rng. This may be
 *                 \c NULL if \p f_rng doesn't need a context argument.
 *
 * \return         \c 0 on success.
 * \return         An \c AWRTC_MBEDTLS_ERR_ECP_XXX code on failure.
 */
int awrtc_mbedtls_ecdsa_genkey(awrtc_mbedtls_ecdsa_context *ctx, awrtc_mbedtls_ecp_group_id gid,
                         awrtc_mbedtls_f_rng_t *f_rng, void *p_rng);

/**
 * \brief           This function sets up an ECDSA context from an EC key pair.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDSA context to setup. This must be initialized.
 * \param key       The EC key to use. This must be initialized and hold
 *                  a private-public key pair or a public key. In the former
 *                  case, the ECDSA context may be used for signature creation
 *                  and verification after this call. In the latter case, it
 *                  may be used for signature verification.
 *
 * \return          \c 0 on success.
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX code on failure.
 */
int awrtc_mbedtls_ecdsa_from_keypair(awrtc_mbedtls_ecdsa_context *ctx,
                               const awrtc_mbedtls_ecp_keypair *key);

/**
 * \brief           This function initializes an ECDSA context.
 *
 * \param ctx       The ECDSA context to initialize.
 *                  This must not be \c NULL.
 */
void awrtc_mbedtls_ecdsa_init(awrtc_mbedtls_ecdsa_context *ctx);

/**
 * \brief           This function frees an ECDSA context.
 *
 * \param ctx       The ECDSA context to free. This may be \c NULL,
 *                  in which case this function does nothing. If it
 *                  is not \c NULL, it must be initialized.
 */
void awrtc_mbedtls_ecdsa_free(awrtc_mbedtls_ecdsa_context *ctx);

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
/**
 * \brief           Initialize a restart context.
 *
 * \param ctx       The restart context to initialize.
 *                  This must not be \c NULL.
 */
void awrtc_mbedtls_ecdsa_restart_init(awrtc_mbedtls_ecdsa_restart_ctx *ctx);

/**
 * \brief           Free the components of a restart context.
 *
 * \param ctx       The restart context to free. This may be \c NULL,
 *                  in which case this function does nothing. If it
 *                  is not \c NULL, it must be initialized.
 */
void awrtc_mbedtls_ecdsa_restart_free(awrtc_mbedtls_ecdsa_restart_ctx *ctx);
#endif /* AWRTC_MBEDTLS_ECP_RESTARTABLE */

#ifdef __cplusplus
}
#endif

#endif /* ecdsa.h */
