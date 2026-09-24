/**
 * \file ecdh.h
 *
 * \brief This file contains ECDH definitions and functions.
 *
 * The Elliptic Curve Diffie-Hellman (ECDH) protocol is an anonymous
 * key agreement protocol allowing two parties to establish a shared
 * secret over an insecure channel. Each party must have an
 * elliptic-curve public private key pair.
 *
 * For more information, see <em>NIST SP 800-56A Rev. 2: Recommendation for
 * Pair-Wise Key Establishment Schemes Using Discrete Logarithm
 * Cryptography</em>.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_MBEDTLS_ECDH_H
#define AWRTC_MBEDTLS_ECDH_H
#include "private_access.h"

#include "build_info.h"

#include "ecp.h"

/*
 * Mbed TLS supports two formats for ECDH contexts (#awrtc_mbedtls_ecdh_context
 * defined in `ecdh.h`). For most applications, the choice of format makes
 * no difference, since all library functions can work with either format,
 * except that the new format is incompatible with AWRTC_MBEDTLS_ECP_RESTARTABLE.

 * The new format used when this option is disabled is smaller
 * (56 bytes on a 32-bit platform). In future versions of the library, it
 * will support alternative implementations of ECDH operations.
 * The new format is incompatible with applications that access
 * context fields directly and with restartable ECP operations.
 */

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
#define AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT
#else
#undef AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT
#endif

#if defined(AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
#undef AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT
#include "everest/everest.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Defines the source of the imported EC key.
 */
typedef enum {
    AWRTC_MBEDTLS_ECDH_OURS,   /**< Our key. */
    AWRTC_MBEDTLS_ECDH_THEIRS, /**< The key of the peer. */
} awrtc_mbedtls_ecdh_side;

#if !defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
/**
 * Defines the ECDH implementation used.
 *
 * Later versions of the library may add new variants, therefore users should
 * not make any assumptions about them.
 */
typedef enum {
    AWRTC_MBEDTLS_ECDH_VARIANT_NONE = 0,   /*!< Implementation not defined. */
    AWRTC_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0,/*!< The default Mbed TLS implementation */
#if defined(AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
    AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST     /*!< Everest implementation */
#endif
} awrtc_mbedtls_ecdh_variant;

/**
 * The context used by the default ECDH implementation.
 *
 * Later versions might change the structure of this context, therefore users
 * should not make any assumptions about the structure of
 * awrtc_mbedtls_ecdh_context_mbed.
 */
typedef struct awrtc_mbedtls_ecdh_context_mbed {
    awrtc_mbedtls_ecp_group AWRTC_MBEDTLS_PRIVATE(grp);   /*!< The elliptic curve used. */
    awrtc_mbedtls_mpi AWRTC_MBEDTLS_PRIVATE(d);           /*!< The private key. */
    awrtc_mbedtls_ecp_point AWRTC_MBEDTLS_PRIVATE(Q);     /*!< The public key. */
    awrtc_mbedtls_ecp_point AWRTC_MBEDTLS_PRIVATE(Qp);    /*!< The value of the public key of the peer. */
    awrtc_mbedtls_mpi AWRTC_MBEDTLS_PRIVATE(z);           /*!< The shared secret. */
#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    awrtc_mbedtls_ecp_restart_ctx AWRTC_MBEDTLS_PRIVATE(rs); /*!< The restart context for EC computations. */
#endif
} awrtc_mbedtls_ecdh_context_mbed;
#endif

/**
 *
 * \warning         Performing multiple operations concurrently on the same
 *                  ECDSA context is not supported; objects of this type
 *                  should not be shared between multiple threads.
 * \brief           The ECDH context structure.
 */
typedef struct awrtc_mbedtls_ecdh_context {
#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    awrtc_mbedtls_ecp_group AWRTC_MBEDTLS_PRIVATE(grp);   /*!< The elliptic curve used. */
    awrtc_mbedtls_mpi AWRTC_MBEDTLS_PRIVATE(d);           /*!< The private key. */
    awrtc_mbedtls_ecp_point AWRTC_MBEDTLS_PRIVATE(Q);     /*!< The public key. */
    awrtc_mbedtls_ecp_point AWRTC_MBEDTLS_PRIVATE(Qp);    /*!< The value of the public key of the peer. */
    awrtc_mbedtls_mpi AWRTC_MBEDTLS_PRIVATE(z);           /*!< The shared secret. */
    int AWRTC_MBEDTLS_PRIVATE(point_format);        /*!< The format of point export in TLS messages. */
    awrtc_mbedtls_ecp_point AWRTC_MBEDTLS_PRIVATE(Vi);    /*!< The blinding value. */
    awrtc_mbedtls_ecp_point AWRTC_MBEDTLS_PRIVATE(Vf);    /*!< The unblinding value. */
    awrtc_mbedtls_mpi AWRTC_MBEDTLS_PRIVATE(_d);          /*!< The previous \p d. */
#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    int AWRTC_MBEDTLS_PRIVATE(restart_enabled);        /*!< The flag for restartable mode. */
    awrtc_mbedtls_ecp_restart_ctx AWRTC_MBEDTLS_PRIVATE(rs); /*!< The restart context for EC computations. */
#endif /* AWRTC_MBEDTLS_ECP_RESTARTABLE */
#else
    uint8_t AWRTC_MBEDTLS_PRIVATE(point_format);       /*!< The format of point export in TLS messages
                                                    as defined in RFC 4492. */
    awrtc_mbedtls_ecp_group_id AWRTC_MBEDTLS_PRIVATE(grp_id);/*!< The elliptic curve used. */
    awrtc_mbedtls_ecdh_variant AWRTC_MBEDTLS_PRIVATE(var);   /*!< The ECDH implementation/structure used. */
    union {
        awrtc_mbedtls_ecdh_context_mbed   AWRTC_MBEDTLS_PRIVATE(mbed_ecdh);
#if defined(AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        awrtc_mbedtls_ecdh_context_everest AWRTC_MBEDTLS_PRIVATE(everest_ecdh);
#endif
    } AWRTC_MBEDTLS_PRIVATE(ctx);                      /*!< Implementation-specific context. The
                                                    context in use is specified by the \c var
                                                    field. */
#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    uint8_t AWRTC_MBEDTLS_PRIVATE(restart_enabled);    /*!< The flag for restartable mode. Functions of
                                                    an alternative implementation not supporting
                                                    restartable mode must return
                                                    AWRTC_MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED error
                                                    if this flag is set. */
#endif /* AWRTC_MBEDTLS_ECP_RESTARTABLE */
#endif /* AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT */
}
awrtc_mbedtls_ecdh_context;

/**
 * \brief          Return the ECP group for provided context.
 *
 * \note           To access group specific fields, users should use
 *                 `awrtc_mbedtls_ecp_curve_info_from_grp_id` or
 *                 `awrtc_mbedtls_ecp_group_load` on the extracted `group_id`.
 *
 * \param ctx      The ECDH context to parse. This must not be \c NULL.
 *
 * \return         The \c awrtc_mbedtls_ecp_group_id of the context.
 */
awrtc_mbedtls_ecp_group_id awrtc_mbedtls_ecdh_get_grp_id(awrtc_mbedtls_ecdh_context *ctx);

/**
 * \brief          Check whether a given group can be used for ECDH.
 *
 * \param gid      The ECP group ID to check.
 *
 * \return         \c 1 if the group can be used, \c 0 otherwise
 */
int awrtc_mbedtls_ecdh_can_do(awrtc_mbedtls_ecp_group_id gid);

/**
 * \brief           This function generates an ECDH keypair on an elliptic
 *                  curve.
 *
 *                  This function performs the first of two core computations
 *                  implemented during the ECDH key exchange. The second core
 *                  computation is performed by awrtc_mbedtls_ecdh_compute_shared().
 *
 * \see             ecp.h
 *
 * \param grp       The ECP group to use. This must be initialized and have
 *                  domain parameters loaded, for example through
 *                  awrtc_mbedtls_ecp_load() or awrtc_mbedtls_ecp_tls_read_group().
 * \param d         The destination MPI (private key).
 *                  This must be initialized.
 * \param Q         The destination point (public key).
 *                  This must be initialized.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL in case \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          Another \c AWRTC_MBEDTLS_ERR_ECP_XXX or
 *                  \c AWRTC_MBEDTLS_MPI_XXX error code on failure.
 */
int awrtc_mbedtls_ecdh_gen_public(awrtc_mbedtls_ecp_group *grp, awrtc_mbedtls_mpi *d, awrtc_mbedtls_ecp_point *Q,
                            awrtc_mbedtls_f_rng_t *f_rng,
                            void *p_rng);

/**
 * \brief           This function computes the shared secret.
 *
 *                  This function performs the second of two core computations
 *                  implemented during the ECDH key exchange. The first core
 *                  computation is performed by awrtc_mbedtls_ecdh_gen_public().
 *
 * \see             ecp.h
 *
 * \note            If \p f_rng is not NULL, it is used to implement
 *                  countermeasures against side-channel attacks.
 *                  For more information, see awrtc_mbedtls_ecp_mul().
 *
 * \param grp       The ECP group to use. This must be initialized and have
 *                  domain parameters loaded, for example through
 *                  awrtc_mbedtls_ecp_load() or awrtc_mbedtls_ecp_tls_read_group().
 * \param z         The destination MPI (shared secret).
 *                  This must be initialized.
 * \param Q         The public key from another party.
 *                  This must be initialized.
 * \param d         Our secret exponent (private key).
 *                  This must be initialized.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL if \p f_rng is \c NULL or doesn't need a
 *                  context argument.
 *
 * \return          \c 0 on success.
 * \return          Another \c AWRTC_MBEDTLS_ERR_ECP_XXX or
 *                  \c AWRTC_MBEDTLS_MPI_XXX error code on failure.
 */
int awrtc_mbedtls_ecdh_compute_shared(awrtc_mbedtls_ecp_group *grp, awrtc_mbedtls_mpi *z,
                                const awrtc_mbedtls_ecp_point *Q, const awrtc_mbedtls_mpi *d,
                                awrtc_mbedtls_f_rng_t *f_rng,
                                void *p_rng);

/**
 * \brief           This function initializes an ECDH context.
 *
 * \param ctx       The ECDH context to initialize. This must not be \c NULL.
 */
void awrtc_mbedtls_ecdh_init(awrtc_mbedtls_ecdh_context *ctx);

/**
 * \brief           This function sets up the ECDH context with the information
 *                  given.
 *
 *                  This function should be called after awrtc_mbedtls_ecdh_init() but
 *                  before awrtc_mbedtls_ecdh_make_params(). There is no need to call
 *                  this function before awrtc_mbedtls_ecdh_read_params().
 *
 *                  This is the first function used by a TLS server for ECDHE
 *                  ciphersuites.
 *
 * \param ctx       The ECDH context to set up. This must be initialized.
 * \param grp_id    The group id of the group to set up the context for.
 *
 * \return          \c 0 on success.
 */
int awrtc_mbedtls_ecdh_setup(awrtc_mbedtls_ecdh_context *ctx,
                       awrtc_mbedtls_ecp_group_id grp_id);

/**
 * \brief           This function frees a context.
 *
 * \param ctx       The context to free. This may be \c NULL, in which
 *                  case this function does nothing. If it is not \c NULL,
 *                  it must point to an initialized ECDH context.
 */
void awrtc_mbedtls_ecdh_free(awrtc_mbedtls_ecdh_context *ctx);

/**
 * \brief           This function generates an EC key pair and exports its
 *                  in the format used in a TLS ServerKeyExchange handshake
 *                  message.
 *
 *                  This is the second function used by a TLS server for ECDHE
 *                  ciphersuites. (It is called after awrtc_mbedtls_ecdh_setup().)
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDH context to use. This must be initialized
 *                  and bound to a group, for example via awrtc_mbedtls_ecdh_setup().
 * \param olen      The address at which to store the number of Bytes written.
 * \param buf       The destination buffer. This must be a writable buffer of
 *                  length \p blen Bytes.
 * \param blen      The length of the destination buffer \p buf in Bytes.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL in case \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c awrtc_mbedtls_ecp_set_max_ops().
 * \return          Another \c AWRTC_MBEDTLS_ERR_ECP_XXX error code on failure.
 */
int awrtc_mbedtls_ecdh_make_params(awrtc_mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             awrtc_mbedtls_f_rng_t *f_rng,
                             void *p_rng);

/**
 * \brief           This function parses the ECDHE parameters in a
 *                  TLS ServerKeyExchange handshake message.
 *
 * \note            In a TLS handshake, this is the how the client
 *                  sets up its ECDHE context from the server's public
 *                  ECDHE key material.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDHE context to use. This must be initialized.
 * \param buf       On input, \c *buf must be the start of the input buffer.
 *                  On output, \c *buf is updated to point to the end of the
 *                  data that has been read. On success, this is the first byte
 *                  past the end of the ServerKeyExchange parameters.
 *                  On error, this is the point at which an error has been
 *                  detected, which is usually not useful except to debug
 *                  failures.
 * \param end       The end of the input buffer.
 *
 * \return          \c 0 on success.
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX error code on failure.
 *
 */
int awrtc_mbedtls_ecdh_read_params(awrtc_mbedtls_ecdh_context *ctx,
                             const unsigned char **buf,
                             const unsigned char *end);

/**
 * \brief           This function sets up an ECDH context from an EC key.
 *
 *                  It is used by clients and servers in place of the
 *                  ServerKeyExchange for static ECDH, and imports ECDH
 *                  parameters from the EC key information of a certificate.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDH context to set up. This must be initialized.
 * \param key       The EC key to use. This must be initialized.
 * \param side      Defines the source of the key. Possible values are:
 *                  - #AWRTC_MBEDTLS_ECDH_OURS: The key is ours.
 *                  - #AWRTC_MBEDTLS_ECDH_THEIRS: The key is that of the peer.
 *
 * \return          \c 0 on success.
 * \return          Another \c AWRTC_MBEDTLS_ERR_ECP_XXX error code on failure.
 *
 */
int awrtc_mbedtls_ecdh_get_params(awrtc_mbedtls_ecdh_context *ctx,
                            const awrtc_mbedtls_ecp_keypair *key,
                            awrtc_mbedtls_ecdh_side side);

/**
 * \brief           This function generates a public key and exports it
 *                  as a TLS ClientKeyExchange payload.
 *
 *                  This is the second function used by a TLS client for ECDH(E)
 *                  ciphersuites.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDH context to use. This must be initialized
 *                  and bound to a group, the latter usually by
 *                  awrtc_mbedtls_ecdh_read_params().
 * \param olen      The address at which to store the number of Bytes written.
 *                  This must not be \c NULL.
 * \param buf       The destination buffer. This must be a writable buffer
 *                  of length \p blen Bytes.
 * \param blen      The size of the destination buffer \p buf in Bytes.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL in case \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c awrtc_mbedtls_ecp_set_max_ops().
 * \return          Another \c AWRTC_MBEDTLS_ERR_ECP_XXX error code on failure.
 */
int awrtc_mbedtls_ecdh_make_public(awrtc_mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             awrtc_mbedtls_f_rng_t *f_rng,
                             void *p_rng);

/**
 * \brief       This function parses and processes the ECDHE payload of a
 *              TLS ClientKeyExchange message.
 *
 *              This is the third function used by a TLS server for ECDH(E)
 *              ciphersuites. (It is called after awrtc_mbedtls_ecdh_setup() and
 *              awrtc_mbedtls_ecdh_make_params().)
 *
 * \see         ecp.h
 *
 * \param ctx   The ECDH context to use. This must be initialized
 *              and bound to a group, for example via awrtc_mbedtls_ecdh_setup().
 * \param buf   The pointer to the ClientKeyExchange payload. This must
 *              be a readable buffer of length \p blen Bytes.
 * \param blen  The length of the input buffer \p buf in Bytes.
 *
 * \return      \c 0 on success.
 * \return      An \c AWRTC_MBEDTLS_ERR_ECP_XXX error code on failure.
 */
int awrtc_mbedtls_ecdh_read_public(awrtc_mbedtls_ecdh_context *ctx,
                             const unsigned char *buf, size_t blen);

/**
 * \brief           This function derives and exports the shared secret.
 *
 *                  This is the last function used by both TLS client
 *                  and servers.
 *
 * \note            If \p f_rng is not NULL, it is used to implement
 *                  countermeasures against side-channel attacks.
 *                  For more information, see awrtc_mbedtls_ecp_mul().
 *
 * \see             ecp.h

 * \param ctx       The ECDH context to use. This must be initialized
 *                  and have its own private key generated and the peer's
 *                  public key imported.
 * \param olen      The address at which to store the total number of
 *                  Bytes written on success. This must not be \c NULL.
 * \param buf       The buffer to write the generated shared key to. This
 *                  must be a writable buffer of size \p blen Bytes.
 * \param blen      The length of the destination buffer \p buf in Bytes.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context. This may be \c NULL if \p f_rng
 *                  doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c awrtc_mbedtls_ecp_set_max_ops().
 * \return          Another \c AWRTC_MBEDTLS_ERR_ECP_XXX error code on failure.
 */
int awrtc_mbedtls_ecdh_calc_secret(awrtc_mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             awrtc_mbedtls_f_rng_t *f_rng,
                             void *p_rng);

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
/**
 * \brief           This function enables restartable EC computations for this
 *                  context.  (Default: disabled.)
 *
 * \see             \c awrtc_mbedtls_ecp_set_max_ops()
 *
 * \note            It is not possible to safely disable restartable
 *                  computations once enabled, except by free-ing the context,
 *                  which cancels possible in-progress operations.
 *
 * \param ctx       The ECDH context to use. This must be initialized.
 */
void awrtc_mbedtls_ecdh_enable_restart(awrtc_mbedtls_ecdh_context *ctx);
#endif /* AWRTC_MBEDTLS_ECP_RESTARTABLE */

#ifdef __cplusplus
}
#endif

#endif /* ecdh.h */
