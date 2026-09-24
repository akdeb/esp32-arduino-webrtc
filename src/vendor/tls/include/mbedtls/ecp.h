/**
 * \file ecp.h
 *
 * \brief This file provides an API for Elliptic Curves over GF(P) (ECP).
 *
 * The use of ECP in cryptography and TLS is defined in
 * <em>Standards for Efficient Cryptography Group (SECG): SEC1
 * Elliptic Curve Cryptography</em> and
 * <em>RFC-4492: Elliptic Curve Cryptography (ECC) Cipher Suites
 * for Transport Layer Security (TLS)</em>.
 *
 * <em>RFC-2409: The Internet Key Exchange (IKE)</em> defines ECP
 * group types.
 *
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_MBEDTLS_ECP_H
#define AWRTC_MBEDTLS_ECP_H
#include "private_access.h"

#include "build_info.h"
#include "platform_util.h"

#include "bignum.h"

/*
 * ECP error codes
 */
/** Bad input parameters to function. */
#define AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA                    -0x4F80
/** The buffer is too small to write to. */
#define AWRTC_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL                  -0x4F00
/** The requested feature is not available, for example, the requested curve is not supported. */
#define AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE               -0x4E80
/** The signature is not valid. */
#define AWRTC_MBEDTLS_ERR_ECP_VERIFY_FAILED                     -0x4E00
/** Memory allocation failed. */
#define AWRTC_MBEDTLS_ERR_ECP_ALLOC_FAILED                      -0x4D80
/** Generation of random value, such as ephemeral key, failed. */
#define AWRTC_MBEDTLS_ERR_ECP_RANDOM_FAILED                     -0x4D00
/** Invalid private or public key. */
#define AWRTC_MBEDTLS_ERR_ECP_INVALID_KEY                       -0x4C80
/** The buffer contains a valid signature followed by more data. */
#define AWRTC_MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH                  -0x4C00
/** Operation in progress, call again with the same parameters to continue. */
#define AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS                       -0x4B00

/* Flags indicating whether to include code that is specific to certain
 * types of curves. These flags are for internal library use only. */
#if defined(AWRTC_MBEDTLS_ECP_DP_SECP192R1_ENABLED) || \
    defined(AWRTC_MBEDTLS_ECP_DP_SECP224R1_ENABLED) || \
    defined(AWRTC_MBEDTLS_ECP_DP_SECP256R1_ENABLED) || \
    defined(AWRTC_MBEDTLS_ECP_DP_SECP384R1_ENABLED) || \
    defined(AWRTC_MBEDTLS_ECP_DP_SECP521R1_ENABLED) || \
    defined(AWRTC_MBEDTLS_ECP_DP_BP256R1_ENABLED) || \
    defined(AWRTC_MBEDTLS_ECP_DP_BP384R1_ENABLED) || \
    defined(AWRTC_MBEDTLS_ECP_DP_BP512R1_ENABLED) || \
    defined(AWRTC_MBEDTLS_ECP_DP_SECP192K1_ENABLED) || \
    defined(AWRTC_MBEDTLS_ECP_DP_SECP224K1_ENABLED) || \
    defined(AWRTC_MBEDTLS_ECP_DP_SECP256K1_ENABLED)
#define AWRTC_MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED
#endif
#if defined(AWRTC_MBEDTLS_ECP_DP_CURVE25519_ENABLED) || \
    defined(AWRTC_MBEDTLS_ECP_DP_CURVE448_ENABLED)
#define AWRTC_MBEDTLS_ECP_MONTGOMERY_ENABLED
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Domain-parameter identifiers: curve, subgroup, and generator.
 *
 * \note Only curves over prime fields are supported.
 *
 * \warning This library does not support validation of arbitrary domain
 * parameters. Therefore, only standardized domain parameters from trusted
 * sources should be used. See awrtc_mbedtls_ecp_group_load().
 */
/* Note: when adding a new curve:
 * - Add it at the end of this enum, otherwise you'll break the ABI by
 *   changing the numerical value for existing curves.
 * - Increment AWRTC_MBEDTLS_ECP_DP_MAX below if needed.
 * - Update the calculation of AWRTC_MBEDTLS_ECP_MAX_BITS below.
 * - Add the corresponding AWRTC_MBEDTLS_ECP_DP_xxx_ENABLED macro definition to
 *   awrtc_mbedtls_config.h.
 * - List the curve as a dependency of AWRTC_MBEDTLS_ECP_C and
 *   AWRTC_MBEDTLS_ECDSA_C if supported in check_config.h.
 * - Add the curve to the appropriate curve type macro
 *   AWRTC_MBEDTLS_ECP_yyy_ENABLED above.
 * - Add the necessary definitions to ecp_curves.c.
 * - Add the curve to the ecp_supported_curves array in ecp.c.
 * - Add the curve to applicable profiles in x509_crt.c.
 * - Add the curve to applicable presets in ssl_tls.c.
 */
typedef enum {
    AWRTC_MBEDTLS_ECP_DP_NONE = 0,       /*!< Curve not defined. */
    AWRTC_MBEDTLS_ECP_DP_SECP192R1,      /*!< Domain parameters for the 192-bit curve defined by FIPS 186-4 and SEC1. */
    AWRTC_MBEDTLS_ECP_DP_SECP224R1,      /*!< Domain parameters for the 224-bit curve defined by FIPS 186-4 and SEC1. */
    AWRTC_MBEDTLS_ECP_DP_SECP256R1,      /*!< Domain parameters for the 256-bit curve defined by FIPS 186-4 and SEC1. */
    AWRTC_MBEDTLS_ECP_DP_SECP384R1,      /*!< Domain parameters for the 384-bit curve defined by FIPS 186-4 and SEC1. */
    AWRTC_MBEDTLS_ECP_DP_SECP521R1,      /*!< Domain parameters for the 521-bit curve defined by FIPS 186-4 and SEC1. */
    AWRTC_MBEDTLS_ECP_DP_BP256R1,        /*!< Domain parameters for 256-bit Brainpool curve. */
    AWRTC_MBEDTLS_ECP_DP_BP384R1,        /*!< Domain parameters for 384-bit Brainpool curve. */
    AWRTC_MBEDTLS_ECP_DP_BP512R1,        /*!< Domain parameters for 512-bit Brainpool curve. */
    AWRTC_MBEDTLS_ECP_DP_CURVE25519,     /*!< Domain parameters for Curve25519. */
    AWRTC_MBEDTLS_ECP_DP_SECP192K1,      /*!< Domain parameters for 192-bit "Koblitz" curve. */
    AWRTC_MBEDTLS_ECP_DP_SECP224K1,      /*!< Domain parameters for 224-bit "Koblitz" curve. */
    AWRTC_MBEDTLS_ECP_DP_SECP256K1,      /*!< Domain parameters for 256-bit "Koblitz" curve. */
    AWRTC_MBEDTLS_ECP_DP_CURVE448,       /*!< Domain parameters for Curve448. */
} awrtc_mbedtls_ecp_group_id;

/**
 * The number of supported curves, plus one for #AWRTC_MBEDTLS_ECP_DP_NONE.
 */
#define AWRTC_MBEDTLS_ECP_DP_MAX     14

/*
 * Curve types
 */
typedef enum {
    AWRTC_MBEDTLS_ECP_TYPE_NONE = 0,
    AWRTC_MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS,    /* y^2 = x^3 + a x + b      */
    AWRTC_MBEDTLS_ECP_TYPE_MONTGOMERY,           /* y^2 = x^3 + a x^2 + x    */
} awrtc_mbedtls_ecp_curve_type;

/**
 * Curve information, for use by other modules.
 *
 * The fields of this structure are part of the public API and can be
 * accessed directly by applications. Future versions of the library may
 * add extra fields or reorder existing fields.
 */
typedef struct awrtc_mbedtls_ecp_curve_info {
    awrtc_mbedtls_ecp_group_id grp_id;    /*!< An internal identifier. */
    uint16_t tls_id;                /*!< The TLS NamedCurve identifier. */
    uint16_t bit_size;              /*!< The curve size in bits. */
    const char *name;               /*!< A human-friendly name. */
} awrtc_mbedtls_ecp_curve_info;

/**
 * \brief           The ECP point structure, in Jacobian coordinates.
 *
 * \note            All functions expect and return points satisfying
 *                  the following condition: <code>Z == 0</code> or
 *                  <code>Z == 1</code>. Other values of \p Z are
 *                  used only by internal functions.
 *                  The point is zero, or "at infinity", if <code>Z == 0</code>.
 *                  Otherwise, \p X and \p Y are its standard (affine)
 *                  coordinates.
 */
typedef struct awrtc_mbedtls_ecp_point {
    awrtc_mbedtls_mpi AWRTC_MBEDTLS_PRIVATE(X);          /*!< The X coordinate of the ECP point. */
    awrtc_mbedtls_mpi AWRTC_MBEDTLS_PRIVATE(Y);          /*!< The Y coordinate of the ECP point. */
    awrtc_mbedtls_mpi AWRTC_MBEDTLS_PRIVATE(Z);          /*!< The Z coordinate of the ECP point. */
}
awrtc_mbedtls_ecp_point;

#if !defined(AWRTC_MBEDTLS_ECP_ALT)
/*
 * default Mbed TLS elliptic curve arithmetic implementation
 *
 * (in case AWRTC_MBEDTLS_ECP_ALT is defined then the developer has to provide an
 * alternative implementation for the whole module and it will replace this
 * one.)
 */

/**
 * \brief           The ECP group structure.
 *
 * We consider two types of curve equations:
 * <ul><li>Short Weierstrass: <code>y^2 = x^3 + A x + B mod P</code>
 * (SEC1 + RFC-4492)</li>
 * <li>Montgomery: <code>y^2 = x^3 + A x^2 + x mod P</code> (Curve25519,
 * Curve448)</li></ul>
 * In both cases, the generator (\p G) for a prime-order subgroup is fixed.
 *
 * For Short Weierstrass, this subgroup is the whole curve, and its
 * cardinality is denoted by \p N. Our code requires that \p N is an
 * odd prime as awrtc_mbedtls_ecp_mul() requires an odd number, and
 * awrtc_mbedtls_ecdsa_sign() requires that it is prime for blinding purposes.
 *
 * The default implementation only initializes \p A without setting it to the
 * authentic value for curves with <code>A = -3</code>(SECP256R1, etc), in which
 * case you need to load \p A by yourself when using domain parameters directly,
 * for example:
 * \code
 * awrtc_mbedtls_mpi_init(&A);
 * awrtc_mbedtls_ecp_group_init(&grp);
 * CHECK_RETURN(awrtc_mbedtls_ecp_group_load(&grp, grp_id));
 * if (awrtc_mbedtls_ecp_group_a_is_minus_3(&grp)) {
 *     CHECK_RETURN(awrtc_mbedtls_mpi_sub_int(&A, &grp.P, 3));
 * } else {
 *     CHECK_RETURN(awrtc_mbedtls_mpi_copy(&A, &grp.A));
 * }
 *
 * do_something_with_a(&A);
 *
 * cleanup:
 * awrtc_mbedtls_mpi_free(&A);
 * awrtc_mbedtls_ecp_group_free(&grp);
 * \endcode
 *
 * For Montgomery curves, we do not store \p A, but <code>(A + 2) / 4</code>,
 * which is the quantity used in the formulas. Additionally, \p nbits is
 * not the size of \p N but the required size for private keys.
 *
 * If \p modp is NULL, reduction modulo \p P is done using a generic algorithm.
 * Otherwise, \p modp must point to a function that takes an \p awrtc_mbedtls_mpi in the
 * range of <code>0..2^(2*pbits)-1</code>, and transforms it in-place to an integer
 * which is congruent mod \p P to the given MPI, and is close enough to \p pbits
 * in size, so that it may be efficiently brought in the 0..P-1 range by a few
 * additions or subtractions. Therefore, it is only an approximate modular
 * reduction. It must return 0 on success and non-zero on failure.
 *
 * \note        Alternative implementations of the ECP module must obey the
 *              following constraints.
 *              * Group IDs must be distinct: if two group structures have
 *                the same ID, then they must be identical.
 *              * The fields \c id, \c P, \c A, \c B, \c G, \c N,
 *                \c pbits and \c nbits must have the same type and semantics
 *                as in the built-in implementation.
 *                They must be available for reading, but direct modification
 *                of these fields does not need to be supported.
 *                They do not need to be at the same offset in the structure.
 */
typedef struct awrtc_mbedtls_ecp_group {
    awrtc_mbedtls_ecp_group_id id;    /*!< An internal group identifier. */
    awrtc_mbedtls_mpi P;              /*!< The prime modulus of the base field. */
    awrtc_mbedtls_mpi A;              /*!< For Short Weierstrass: \p A in the equation. Note that
                                     \p A is not set to the authentic value in some cases.
                                     Refer to detailed description of ::awrtc_mbedtls_ecp_group if
                                     using domain parameters in the structure.
                                     For Montgomery curves: <code>(A + 2) / 4</code>. */
    awrtc_mbedtls_mpi B;              /*!< For Short Weierstrass: \p B in the equation.
                                     For Montgomery curves: unused. */
    awrtc_mbedtls_ecp_point G;        /*!< The generator of the subgroup used. */
    awrtc_mbedtls_mpi N;              /*!< The order of \p G. */
    size_t pbits;               /*!< The number of bits in \p P.*/
    size_t nbits;               /*!< For Short Weierstrass: The number of bits in \p P.
                                     For Montgomery curves: the number of bits in the
                                     private keys. */
    /* End of public fields */

    unsigned int AWRTC_MBEDTLS_PRIVATE(h);             /*!< \internal 1 if the constants are static. */
    int(*AWRTC_MBEDTLS_PRIVATE(modp))(awrtc_mbedtls_mpi *);  /*!< The function for fast pseudo-reduction
                                                    mod \p P (see above).*/
    int(*AWRTC_MBEDTLS_PRIVATE(t_pre))(awrtc_mbedtls_ecp_point *, void *);   /*!< Unused. */
    int(*AWRTC_MBEDTLS_PRIVATE(t_post))(awrtc_mbedtls_ecp_point *, void *);  /*!< Unused. */
    void *AWRTC_MBEDTLS_PRIVATE(t_data);               /*!< Unused. */
    awrtc_mbedtls_ecp_point *AWRTC_MBEDTLS_PRIVATE(T);       /*!< Pre-computed points for ecp_mul_comb(). */
    size_t AWRTC_MBEDTLS_PRIVATE(T_size);              /*!< The number of dynamic allocated pre-computed points. */
}
awrtc_mbedtls_ecp_group;

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in awrtc_mbedtls_config.h, or define them using the compiler command line.
 * \{
 */

#if !defined(AWRTC_MBEDTLS_ECP_WINDOW_SIZE)
/*
 * Maximum "window" size used for point multiplication.
 * Default: a point where higher memory usage yields diminishing performance
 *          returns.
 * Minimum value: 2. Maximum value: 7.
 *
 * Result is an array of at most ( 1 << ( AWRTC_MBEDTLS_ECP_WINDOW_SIZE - 1 ) )
 * points used for point multiplication. This value is directly tied to EC
 * peak memory usage, so decreasing it by one should roughly cut memory usage
 * by two (if large curves are in use).
 *
 * Reduction in size may reduce speed, but larger curves are impacted first.
 * Sample performances (in ECDHE handshakes/s, with FIXED_POINT_OPTIM = 1):
 *      w-size:     6       5       4       3       2
 *      521       145     141     135     120      97
 *      384       214     209     198     177     146
 *      256       320     320     303     262     226
 *      224       475     475     453     398     342
 *      192       640     640     633     587     476
 */
#define AWRTC_MBEDTLS_ECP_WINDOW_SIZE    4   /**< The maximum window size used. */
#endif /* AWRTC_MBEDTLS_ECP_WINDOW_SIZE */

#if !defined(AWRTC_MBEDTLS_ECP_FIXED_POINT_OPTIM)
/*
 * Trade code size for speed on fixed-point multiplication.
 *
 * This speeds up repeated multiplication of the generator (that is, the
 * multiplication in ECDSA signatures, and half of the multiplications in
 * ECDSA verification and ECDHE) by a factor roughly 3 to 4.
 *
 * For each n-bit Short Weierstrass curve that is enabled, this adds 4n bytes
 * of code size if n < 384 and 8n otherwise.
 *
 * Change this value to 0 to reduce code size.
 */
#define AWRTC_MBEDTLS_ECP_FIXED_POINT_OPTIM  1   /**< Enable fixed-point speed-up. */
#endif /* AWRTC_MBEDTLS_ECP_FIXED_POINT_OPTIM */

/** \} name SECTION: Module settings */

#else  /* AWRTC_MBEDTLS_ECP_ALT */
#include "ecp_alt.h"
#endif /* AWRTC_MBEDTLS_ECP_ALT */

/**
 * The maximum size of the groups, that is, of \c N and \c P.
 */
#if !defined(AWRTC_MBEDTLS_ECP_LIGHT)
/* Dummy definition to help code that has optional ECP support and
 * defines an AWRTC_MBEDTLS_ECP_MAX_BYTES-sized array unconditionally. */
#define AWRTC_MBEDTLS_ECP_MAX_BITS 1
/* Note: the curves must be listed in DECREASING size! */
#elif defined(AWRTC_MBEDTLS_ECP_DP_SECP521R1_ENABLED)
#define AWRTC_MBEDTLS_ECP_MAX_BITS 521
#elif defined(AWRTC_MBEDTLS_ECP_DP_BP512R1_ENABLED)
#define AWRTC_MBEDTLS_ECP_MAX_BITS 512
#elif defined(AWRTC_MBEDTLS_ECP_DP_CURVE448_ENABLED)
#define AWRTC_MBEDTLS_ECP_MAX_BITS 448
#elif defined(AWRTC_MBEDTLS_ECP_DP_BP384R1_ENABLED)
#define AWRTC_MBEDTLS_ECP_MAX_BITS 384
#elif defined(AWRTC_MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#define AWRTC_MBEDTLS_ECP_MAX_BITS 384
#elif defined(AWRTC_MBEDTLS_ECP_DP_BP256R1_ENABLED)
#define AWRTC_MBEDTLS_ECP_MAX_BITS 256
#elif defined(AWRTC_MBEDTLS_ECP_DP_SECP256K1_ENABLED)
#define AWRTC_MBEDTLS_ECP_MAX_BITS 256
#elif defined(AWRTC_MBEDTLS_ECP_DP_SECP256R1_ENABLED)
#define AWRTC_MBEDTLS_ECP_MAX_BITS 256
#elif defined(AWRTC_MBEDTLS_ECP_DP_CURVE25519_ENABLED)
#define AWRTC_MBEDTLS_ECP_MAX_BITS 255
#elif defined(AWRTC_MBEDTLS_ECP_DP_SECP224K1_ENABLED)
#define AWRTC_MBEDTLS_ECP_MAX_BITS 225 // n is slightly above 2^224
#elif defined(AWRTC_MBEDTLS_ECP_DP_SECP224R1_ENABLED)
#define AWRTC_MBEDTLS_ECP_MAX_BITS 224
#elif defined(AWRTC_MBEDTLS_ECP_DP_SECP192K1_ENABLED)
#define AWRTC_MBEDTLS_ECP_MAX_BITS 192
#elif defined(AWRTC_MBEDTLS_ECP_DP_SECP192R1_ENABLED)
#define AWRTC_MBEDTLS_ECP_MAX_BITS 192
#else /* !AWRTC_MBEDTLS_ECP_LIGHT */
#error "Missing definition of AWRTC_MBEDTLS_ECP_MAX_BITS"
#endif /* !AWRTC_MBEDTLS_ECP_LIGHT */

#define AWRTC_MBEDTLS_ECP_MAX_BYTES    ((AWRTC_MBEDTLS_ECP_MAX_BITS + 7) / 8)
#define AWRTC_MBEDTLS_ECP_MAX_PT_LEN   (2 * AWRTC_MBEDTLS_ECP_MAX_BYTES + 1)

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)

/**
 * \brief           Internal restart context for multiplication
 *
 * \note            Opaque struct
 */
typedef struct awrtc_mbedtls_ecp_restart_mul awrtc_mbedtls_ecp_restart_mul_ctx;

/**
 * \brief           Internal restart context for ecp_muladd()
 *
 * \note            Opaque struct
 */
typedef struct awrtc_mbedtls_ecp_restart_muladd awrtc_mbedtls_ecp_restart_muladd_ctx;

/**
 * \brief           General context for resuming ECC operations
 */
typedef struct {
    unsigned AWRTC_MBEDTLS_PRIVATE(ops_done);                  /*!<  current ops count             */
    unsigned AWRTC_MBEDTLS_PRIVATE(depth);                     /*!<  call depth (0 = top-level)    */
    awrtc_mbedtls_ecp_restart_mul_ctx *AWRTC_MBEDTLS_PRIVATE(rsm);   /*!<  ecp_mul_comb() sub-context    */
    awrtc_mbedtls_ecp_restart_muladd_ctx *AWRTC_MBEDTLS_PRIVATE(ma); /*!<  ecp_muladd() sub-context      */
} awrtc_mbedtls_ecp_restart_ctx;

/*
 * Operation counts for restartable functions
 */
#define AWRTC_MBEDTLS_ECP_OPS_CHK   3 /*!< basic ops count for ecp_check_pubkey()  */
#define AWRTC_MBEDTLS_ECP_OPS_DBL   8 /*!< basic ops count for ecp_double_jac()    */
#define AWRTC_MBEDTLS_ECP_OPS_ADD  11 /*!< basic ops count for see ecp_add_mixed() */
#define AWRTC_MBEDTLS_ECP_OPS_INV 120 /*!< empirical equivalent for mpi_mod_inv()  */

/**
 * \brief           Internal; for restartable functions in other modules.
 *                  Check and update basic ops budget.
 *
 * \param grp       Group structure
 * \param rs_ctx    Restart context
 * \param ops       Number of basic ops to do
 *
 * \return          \c 0 if doing \p ops basic ops is still allowed,
 * \return          #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS otherwise.
 */
int awrtc_mbedtls_ecp_check_budget(const awrtc_mbedtls_ecp_group *grp,
                             awrtc_mbedtls_ecp_restart_ctx *rs_ctx,
                             unsigned ops);

/* Utility macro for checking and updating ops budget */
#define AWRTC_MBEDTLS_ECP_BUDGET(ops)   \
    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_ecp_check_budget(grp, rs_ctx, \
                                             (unsigned) (ops)));

#else /* AWRTC_MBEDTLS_ECP_RESTARTABLE */

#define AWRTC_MBEDTLS_ECP_BUDGET(ops)     /* no-op; for compatibility */

/* We want to declare restartable versions of existing functions anyway */
typedef void awrtc_mbedtls_ecp_restart_ctx;

#endif /* AWRTC_MBEDTLS_ECP_RESTARTABLE */

/**
 * \brief    The ECP key-pair structure.
 *
 * A generic key-pair that may be used for ECDSA and fixed ECDH, for example.
 *
 * \note    Members are deliberately in the same order as in the
 *          ::awrtc_mbedtls_ecdsa_context structure.
 */
typedef struct awrtc_mbedtls_ecp_keypair {
    awrtc_mbedtls_ecp_group AWRTC_MBEDTLS_PRIVATE(grp);      /*!<  Elliptic curve and base point     */
    awrtc_mbedtls_mpi AWRTC_MBEDTLS_PRIVATE(d);              /*!<  our secret value                  */
    awrtc_mbedtls_ecp_point AWRTC_MBEDTLS_PRIVATE(Q);        /*!<  our public value                  */
}
awrtc_mbedtls_ecp_keypair;

/**
 * The uncompressed point format for Short Weierstrass curves
 * (AWRTC_MBEDTLS_ECP_DP_SECP_XXX and AWRTC_MBEDTLS_ECP_DP_BP_XXX).
 */
#define AWRTC_MBEDTLS_ECP_PF_UNCOMPRESSED    0
/**
 * The compressed point format for Short Weierstrass curves
 * (AWRTC_MBEDTLS_ECP_DP_SECP_XXX and AWRTC_MBEDTLS_ECP_DP_BP_XXX).
 *
 * \warning     While this format is supported for all concerned curves for
 *              writing, when it comes to parsing, it is not supported for all
 *              curves. Specifically, parsing compressed points on
 *              AWRTC_MBEDTLS_ECP_DP_SECP224R1 and AWRTC_MBEDTLS_ECP_DP_SECP224K1 is not
 *              supported.
 */
#define AWRTC_MBEDTLS_ECP_PF_COMPRESSED      1

/*
 * Some other constants from RFC 4492
 */
#define AWRTC_MBEDTLS_ECP_TLS_NAMED_CURVE    3   /**< The named_curve of ECCurveType. */

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
/**
 * \brief           Set the maximum number of basic operations done in a row.
 *
 *                  If more operations are needed to complete a computation,
 *                  #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS will be returned by the
 *                  function performing the computation. It is then the
 *                  caller's responsibility to either call again with the same
 *                  parameters until it returns 0 or an error code; or to free
 *                  the restart context if the operation is to be aborted.
 *
 *                  It is strictly required that all input parameters and the
 *                  restart context be the same on successive calls for the
 *                  same operation, but output parameters need not be the
 *                  same; they must not be used until the function finally
 *                  returns 0.
 *
 *                  This only applies to functions whose documentation
 *                  mentions they may return #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS (or
 *                  #AWRTC_MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS for functions in the
 *                  SSL module). For functions that accept a "restart context"
 *                  argument, passing NULL disables restart and makes the
 *                  function equivalent to the function with the same name
 *                  with \c _restartable removed. For functions in the ECDH
 *                  module, restart is disabled unless the function accepts
 *                  an "ECDH context" argument and
 *                  awrtc_mbedtls_ecdh_enable_restart() was previously called on
 *                  that context. For function in the SSL module, restart is
 *                  only enabled for specific sides and key exchanges
 *                  (currently only for clients and ECDHE-ECDSA).
 *
 * \warning         Using the PSA interruptible interfaces with keys in local
 *                  storage and no accelerator driver will also call this
 *                  function to set the values specified via those interfaces,
 *                  overwriting values previously set. Care should be taken if
 *                  mixing these two interfaces.
 *
 * \param max_ops   Maximum number of basic operations done in a row.
 *                  Default: 0 (unlimited).
 *                  Lower (non-zero) values mean ECC functions will block for
 *                  a lesser maximum amount of time.
 *
 * \note            A "basic operation" is defined as a rough equivalent of a
 *                  multiplication in GF(p) for the NIST P-256 curve.
 *                  As an indication, with default settings, a scalar
 *                  multiplication (full run of \c awrtc_mbedtls_ecp_mul()) is:
 *                  - about 3300 basic operations for P-256
 *                  - about 9400 basic operations for P-384
 *
 * \note            Very low values are not always respected: sometimes
 *                  functions need to block for a minimum number of
 *                  operations, and will do so even if max_ops is set to a
 *                  lower value.  That minimum depends on the curve size, and
 *                  can be made lower by decreasing the value of
 *                  \c AWRTC_MBEDTLS_ECP_WINDOW_SIZE.  As an indication, here is the
 *                  lowest effective value for various curves and values of
 *                  that parameter (w for short):
 *                          w=6     w=5     w=4     w=3     w=2
 *                  P-256   208     208     160     136     124
 *                  P-384   682     416     320     272     248
 *                  P-521  1364     832     640     544     496
 *
 * \note            This setting is currently ignored by Curve25519.
 */
void awrtc_mbedtls_ecp_set_max_ops(unsigned max_ops);

/**
 * \brief           Check if restart is enabled (max_ops != 0)
 *
 * \return          \c 0 if \c max_ops == 0 (restart disabled)
 * \return          \c 1 otherwise (restart enabled)
 */
int awrtc_mbedtls_ecp_restart_is_enabled(void);
#endif /* AWRTC_MBEDTLS_ECP_RESTARTABLE */

/*
 * Get the type of a curve
 */
awrtc_mbedtls_ecp_curve_type awrtc_mbedtls_ecp_get_type(const awrtc_mbedtls_ecp_group *grp);

/**
 * \brief           This function retrieves the information defined in
 *                  awrtc_mbedtls_ecp_curve_info() for all supported curves.
 *
 * \note            This function returns information about all curves
 *                  supported by the library. Some curves may not be
 *                  supported for all algorithms. Call awrtc_mbedtls_ecdh_can_do()
 *                  or awrtc_mbedtls_ecdsa_can_do() to check if a curve is
 *                  supported for ECDH or ECDSA.
 *
 * \return          A statically allocated array. The last entry is 0.
 */
const awrtc_mbedtls_ecp_curve_info *awrtc_mbedtls_ecp_curve_list(void);

/**
 * \brief           This function retrieves the list of internal group
 *                  identifiers of all supported curves in the order of
 *                  preference.
 *
 * \note            This function returns information about all curves
 *                  supported by the library. Some curves may not be
 *                  supported for all algorithms. Call awrtc_mbedtls_ecdh_can_do()
 *                  or awrtc_mbedtls_ecdsa_can_do() to check if a curve is
 *                  supported for ECDH or ECDSA.
 *
 * \return          A statically allocated array,
 *                  terminated with AWRTC_MBEDTLS_ECP_DP_NONE.
 */
const awrtc_mbedtls_ecp_group_id *awrtc_mbedtls_ecp_grp_id_list(void);

/**
 * \brief           This function retrieves curve information from an internal
 *                  group identifier.
 *
 * \param grp_id    An \c AWRTC_MBEDTLS_ECP_DP_XXX value.
 *
 * \return          The associated curve information on success.
 * \return          NULL on failure.
 */
const awrtc_mbedtls_ecp_curve_info *awrtc_mbedtls_ecp_curve_info_from_grp_id(awrtc_mbedtls_ecp_group_id grp_id);

/**
 * \brief           This function retrieves curve information from a TLS
 *                  NamedCurve value.
 *
 * \param tls_id    An \c AWRTC_MBEDTLS_ECP_DP_XXX value.
 *
 * \return          The associated curve information on success.
 * \return          NULL on failure.
 */
const awrtc_mbedtls_ecp_curve_info *awrtc_mbedtls_ecp_curve_info_from_tls_id(uint16_t tls_id);

/**
 * \brief           This function retrieves curve information from a
 *                  human-readable name.
 *
 * \param name      The human-readable name.
 *
 * \return          The associated curve information on success.
 * \return          NULL on failure.
 */
const awrtc_mbedtls_ecp_curve_info *awrtc_mbedtls_ecp_curve_info_from_name(const char *name);

/**
 * \brief           This function initializes a point as zero.
 *
 * \param pt        The point to initialize.
 */
void awrtc_mbedtls_ecp_point_init(awrtc_mbedtls_ecp_point *pt);

/**
 * \brief           This function initializes an ECP group context
 *                  without loading any domain parameters.
 *
 * \note            After this function is called, domain parameters
 *                  for various ECP groups can be loaded through the
 *                  awrtc_mbedtls_ecp_group_load() or awrtc_mbedtls_ecp_tls_read_group()
 *                  functions.
 */
void awrtc_mbedtls_ecp_group_init(awrtc_mbedtls_ecp_group *grp);

/**
 * \brief           This function initializes a key pair as an invalid one.
 *
 * \param key       The key pair to initialize.
 */
void awrtc_mbedtls_ecp_keypair_init(awrtc_mbedtls_ecp_keypair *key);

/**
 * \brief           This function frees the components of a point.
 *
 * \param pt        The point to free.
 */
void awrtc_mbedtls_ecp_point_free(awrtc_mbedtls_ecp_point *pt);

/**
 * \brief           This function frees the components of an ECP group.
 *
 * \param grp       The group to free. This may be \c NULL, in which
 *                  case this function returns immediately. If it is not
 *                  \c NULL, it must point to an initialized ECP group.
 */
void awrtc_mbedtls_ecp_group_free(awrtc_mbedtls_ecp_group *grp);

/**
 * \brief           This function frees the components of a key pair.
 *
 * \param key       The key pair to free. This may be \c NULL, in which
 *                  case this function returns immediately. If it is not
 *                  \c NULL, it must point to an initialized ECP key pair.
 */
void awrtc_mbedtls_ecp_keypair_free(awrtc_mbedtls_ecp_keypair *key);

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
/**
 * \brief           Initialize a restart context.
 *
 * \param ctx       The restart context to initialize. This must
 *                  not be \c NULL.
 */
void awrtc_mbedtls_ecp_restart_init(awrtc_mbedtls_ecp_restart_ctx *ctx);

/**
 * \brief           Free the components of a restart context.
 *
 * \param ctx       The restart context to free. This may be \c NULL, in which
 *                  case this function returns immediately. If it is not
 *                  \c NULL, it must point to an initialized restart context.
 */
void awrtc_mbedtls_ecp_restart_free(awrtc_mbedtls_ecp_restart_ctx *ctx);
#endif /* AWRTC_MBEDTLS_ECP_RESTARTABLE */

/**
 * \brief           This function copies the contents of point \p Q into
 *                  point \p P.
 *
 * \param P         The destination point. This must be initialized.
 * \param Q         The source point. This must be initialized.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return          Another negative error code for other kinds of failure.
 */
int awrtc_mbedtls_ecp_copy(awrtc_mbedtls_ecp_point *P, const awrtc_mbedtls_ecp_point *Q);

/**
 * \brief           This function copies the contents of group \p src into
 *                  group \p dst.
 *
 * \param dst       The destination group. This must be initialized.
 * \param src       The source group. This must be initialized.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_group_copy(awrtc_mbedtls_ecp_group *dst,
                           const awrtc_mbedtls_ecp_group *src);

/**
 * \brief           This function sets a point to the point at infinity.
 *
 * \param pt        The point to set. This must be initialized.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_set_zero(awrtc_mbedtls_ecp_point *pt);

/**
 * \brief           This function checks if a point is the point at infinity.
 *
 * \param pt        The point to test. This must be initialized.
 *
 * \return          \c 1 if the point is zero.
 * \return          \c 0 if the point is non-zero.
 * \return          A negative error code on failure.
 */
int awrtc_mbedtls_ecp_is_zero(awrtc_mbedtls_ecp_point *pt);

/**
 * \brief           This function compares two points.
 *
 * \note            This assumes that the points are normalized. Otherwise,
 *                  they may compare as "not equal" even if they are.
 *
 * \param P         The first point to compare. This must be initialized.
 * \param Q         The second point to compare. This must be initialized.
 *
 * \return          \c 0 if the points are equal.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA if the points are not equal.
 */
int awrtc_mbedtls_ecp_point_cmp(const awrtc_mbedtls_ecp_point *P,
                          const awrtc_mbedtls_ecp_point *Q);

/**
 * \brief           This function imports a non-zero point from two ASCII
 *                  strings.
 *
 * \param P         The destination point. This must be initialized.
 * \param radix     The numeric base of the input.
 * \param x         The first affine coordinate, as a null-terminated string.
 * \param y         The second affine coordinate, as a null-terminated string.
 *
 * \return          \c 0 on success.
 * \return          An \c AWRTC_MBEDTLS_ERR_MPI_XXX error code on failure.
 */
int awrtc_mbedtls_ecp_point_read_string(awrtc_mbedtls_ecp_point *P, int radix,
                                  const char *x, const char *y);

/**
 * \brief           This function exports a point into unsigned binary data.
 *
 * \param grp       The group to which the point should belong.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param P         The point to export. This must be initialized.
 * \param format    The point format. This must be either
 *                  #AWRTC_MBEDTLS_ECP_PF_COMPRESSED or #AWRTC_MBEDTLS_ECP_PF_UNCOMPRESSED.
 *                  (For groups without these formats, this parameter is
 *                  ignored. But it still has to be either of the above
 *                  values.)
 * \param olen      The address at which to store the length of
 *                  the output in Bytes. This must not be \c NULL.
 * \param buf       The output buffer. This must be a writable buffer
 *                  of length \p buflen Bytes.
 * \param buflen    The length of the output buffer \p buf in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL if the output buffer
 *                  is too small to hold the point.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if the point format
 *                  or the export for the given group is not implemented.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_point_write_binary(const awrtc_mbedtls_ecp_group *grp,
                                   const awrtc_mbedtls_ecp_point *P,
                                   int format, size_t *olen,
                                   unsigned char *buf, size_t buflen);

/**
 * \brief           This function imports a point from unsigned binary data.
 *
 * \note            This function does not check that the point actually
 *                  belongs to the given group, see awrtc_mbedtls_ecp_check_pubkey()
 *                  for that.
 *
 * \note            For compressed points, see #AWRTC_MBEDTLS_ECP_PF_COMPRESSED for
 *                  limitations.
 *
 * \param grp       The group to which the point should belong.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param P         The destination context to import the point to.
 *                  This must be initialized.
 * \param buf       The input buffer. This must be a readable buffer
 *                  of length \p ilen Bytes.
 * \param ilen      The length of the input buffer \p buf in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA if the input is invalid.
 * \return          #AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if the import for the
 *                  given group is not implemented.
 */
int awrtc_mbedtls_ecp_point_read_binary(const awrtc_mbedtls_ecp_group *grp,
                                  awrtc_mbedtls_ecp_point *P,
                                  const unsigned char *buf, size_t ilen);

/**
 * \brief           This function imports a point from a TLS ECPoint record.
 *
 * \note            On function return, \p *buf is updated to point immediately
 *                  after the ECPoint record.
 *
 * \param grp       The ECP group to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param pt        The destination point.
 * \param buf       The address of the pointer to the start of the input buffer.
 * \param len       The length of the buffer.
 *
 * \return          \c 0 on success.
 * \return          An \c AWRTC_MBEDTLS_ERR_MPI_XXX error code on initialization
 *                  failure.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA if input is invalid.
 */
int awrtc_mbedtls_ecp_tls_read_point(const awrtc_mbedtls_ecp_group *grp,
                               awrtc_mbedtls_ecp_point *pt,
                               const unsigned char **buf, size_t len);

/**
 * \brief           This function exports a point as a TLS ECPoint record
 *                  defined in RFC 4492, Section 5.4.
 *
 * \param grp       The ECP group to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param pt        The point to be exported. This must be initialized.
 * \param format    The point format to use. This must be either
 *                  #AWRTC_MBEDTLS_ECP_PF_COMPRESSED or #AWRTC_MBEDTLS_ECP_PF_UNCOMPRESSED.
 * \param olen      The address at which to store the length in Bytes
 *                  of the data written.
 * \param buf       The target buffer. This must be a writable buffer of
 *                  length \p blen Bytes.
 * \param blen      The length of the target buffer \p buf in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA if the input is invalid.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL if the target buffer
 *                  is too small to hold the exported point.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_tls_write_point(const awrtc_mbedtls_ecp_group *grp,
                                const awrtc_mbedtls_ecp_point *pt,
                                int format, size_t *olen,
                                unsigned char *buf, size_t blen);

/**
 * \brief           This function sets up an ECP group context
 *                  from a standardized set of domain parameters.
 *
 * \note            The index should be a value of the NamedCurve enum,
 *                  as defined in <em>RFC-4492: Elliptic Curve Cryptography
 *                  (ECC) Cipher Suites for Transport Layer Security (TLS)</em>,
 *                  usually in the form of an \c AWRTC_MBEDTLS_ECP_DP_XXX macro.
 *
 * \param grp       The group context to setup. This must be initialized.
 * \param id        The identifier of the domain parameter set to load.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if \p id doesn't
 *                  correspond to a known group.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_group_load(awrtc_mbedtls_ecp_group *grp, awrtc_mbedtls_ecp_group_id id);

/**
 * \brief           This function sets up an ECP group context from a TLS
 *                  ECParameters record as defined in RFC 4492, Section 5.4.
 *
 * \note            The read pointer \p buf is updated to point right after
 *                  the ECParameters record on exit.
 *
 * \param grp       The group context to setup. This must be initialized.
 * \param buf       The address of the pointer to the start of the input buffer.
 * \param len       The length of the input buffer \c *buf in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA if input is invalid.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if the group is not
 *                  recognized.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_tls_read_group(awrtc_mbedtls_ecp_group *grp,
                               const unsigned char **buf, size_t len);

/**
 * \brief           This function extracts an elliptic curve group ID from a
 *                  TLS ECParameters record as defined in RFC 4492, Section 5.4.
 *
 * \note            The read pointer \p buf is updated to point right after
 *                  the ECParameters record on exit.
 *
 * \param grp       The address at which to store the group id.
 *                  This must not be \c NULL.
 * \param buf       The address of the pointer to the start of the input buffer.
 * \param len       The length of the input buffer \c *buf in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA if input is invalid.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if the group is not
 *                  recognized.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_tls_read_group_id(awrtc_mbedtls_ecp_group_id *grp,
                                  const unsigned char **buf,
                                  size_t len);
/**
 * \brief           This function exports an elliptic curve as a TLS
 *                  ECParameters record as defined in RFC 4492, Section 5.4.
 *
 * \param grp       The ECP group to be exported.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param olen      The address at which to store the number of Bytes written.
 *                  This must not be \c NULL.
 * \param buf       The buffer to write to. This must be a writable buffer
 *                  of length \p blen Bytes.
 * \param blen      The length of the output buffer \p buf in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL if the output
 *                  buffer is too small to hold the exported group.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_tls_write_group(const awrtc_mbedtls_ecp_group *grp,
                                size_t *olen,
                                unsigned char *buf, size_t blen);

/**
 * \brief           This function performs a scalar multiplication of a point
 *                  by an integer: \p R = \p m * \p P.
 *
 *                  It is not thread-safe to use same group in multiple threads.
 *
 * \note            To prevent timing attacks, this function
 *                  executes the exact same sequence of base-field
 *                  operations for any valid \p m. It avoids any if-branch or
 *                  array index depending on the value of \p m. It also uses
 *                  \p f_rng to randomize some intermediate results.
 *
 * \param grp       The ECP group to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param R         The point in which to store the result of the calculation.
 *                  This must be initialized.
 * \param m         The integer by which to multiply. This must be initialized.
 * \param P         The point to multiply. This must be initialized.
 * \param f_rng     The RNG function. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be \c
 *                  NULL if \p f_rng doesn't need a context.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_INVALID_KEY if \p m is not a valid private
 *                  key, or \p P is not a valid public key.
 * \return          #AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_mul(awrtc_mbedtls_ecp_group *grp, awrtc_mbedtls_ecp_point *R,
                    const awrtc_mbedtls_mpi *m, const awrtc_mbedtls_ecp_point *P,
                    awrtc_mbedtls_f_rng_t *f_rng, void *p_rng);

/**
 * \brief           This function performs multiplication of a point by
 *                  an integer: \p R = \p m * \p P in a restartable way.
 *
 * \see             awrtc_mbedtls_ecp_mul()
 *
 * \note            This function does the same as \c awrtc_mbedtls_ecp_mul(), but
 *                  it can return early and restart according to the limit set
 *                  with \c awrtc_mbedtls_ecp_set_max_ops() to reduce blocking.
 *
 * \param grp       The ECP group to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param R         The point in which to store the result of the calculation.
 *                  This must be initialized.
 * \param m         The integer by which to multiply. This must be initialized.
 * \param P         The point to multiply. This must be initialized.
 * \param f_rng     The RNG function. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be \c
 *                  NULL if \p f_rng doesn't need a context.
 * \param rs_ctx    The restart context (NULL disables restart).
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_INVALID_KEY if \p m is not a valid private
 *                  key, or \p P is not a valid public key.
 * \return          #AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c awrtc_mbedtls_ecp_set_max_ops().
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_mul_restartable(awrtc_mbedtls_ecp_group *grp, awrtc_mbedtls_ecp_point *R,
                                const awrtc_mbedtls_mpi *m, const awrtc_mbedtls_ecp_point *P,
                                awrtc_mbedtls_f_rng_t *f_rng, void *p_rng,
                                awrtc_mbedtls_ecp_restart_ctx *rs_ctx);

#if defined(AWRTC_MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
/**
 * \brief           This function checks if domain parameter A of the curve is
 *                  \c -3.
 *
 * \note            This function is only defined for short Weierstrass curves.
 *                  It may not be included in builds without any short
 *                  Weierstrass curve.
 *
 * \param grp       The ECP group to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 *
 * \return          \c 1 if <code>A = -3</code>.
 * \return          \c 0 Otherwise.
 */
static inline int awrtc_mbedtls_ecp_group_a_is_minus_3(const awrtc_mbedtls_ecp_group *grp)
{
    return grp->A.AWRTC_MBEDTLS_PRIVATE(p) == NULL;
}

/**
 * \brief           This function performs multiplication and addition of two
 *                  points by integers: \p R = \p m * \p P + \p n * \p Q
 *
 *                  It is not thread-safe to use same group in multiple threads.
 *
 * \note            In contrast to awrtc_mbedtls_ecp_mul(), this function does not
 *                  guarantee a constant execution flow and timing.
 *
 * \note            This function is only defined for short Weierstrass curves.
 *                  It may not be included in builds without any short
 *                  Weierstrass curve.
 *
 * \param grp       The ECP group to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param R         The point in which to store the result of the calculation.
 *                  This must be initialized.
 * \param m         The integer by which to multiply \p P.
 *                  This must be initialized.
 * \param P         The point to multiply by \p m. This must be initialized.
 * \param n         The integer by which to multiply \p Q.
 *                  This must be initialized.
 * \param Q         The point to be multiplied by \p n.
 *                  This must be initialized.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_INVALID_KEY if \p m or \p n are not
 *                  valid private keys, or \p P or \p Q are not valid public
 *                  keys.
 * \return          #AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if \p grp does not
 *                  designate a short Weierstrass curve.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_muladd(awrtc_mbedtls_ecp_group *grp, awrtc_mbedtls_ecp_point *R,
                       const awrtc_mbedtls_mpi *m, const awrtc_mbedtls_ecp_point *P,
                       const awrtc_mbedtls_mpi *n, const awrtc_mbedtls_ecp_point *Q);

/**
 * \brief           This function performs multiplication and addition of two
 *                  points by integers: \p R = \p m * \p P + \p n * \p Q in a
 *                  restartable way.
 *
 * \see             \c awrtc_mbedtls_ecp_muladd()
 *
 * \note            This function works the same as \c awrtc_mbedtls_ecp_muladd(),
 *                  but it can return early and restart according to the limit
 *                  set with \c awrtc_mbedtls_ecp_set_max_ops() to reduce blocking.
 *
 * \note            This function is only defined for short Weierstrass curves.
 *                  It may not be included in builds without any short
 *                  Weierstrass curve.
 *
 * \param grp       The ECP group to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param R         The point in which to store the result of the calculation.
 *                  This must be initialized.
 * \param m         The integer by which to multiply \p P.
 *                  This must be initialized.
 * \param P         The point to multiply by \p m. This must be initialized.
 * \param n         The integer by which to multiply \p Q.
 *                  This must be initialized.
 * \param Q         The point to be multiplied by \p n.
 *                  This must be initialized.
 * \param rs_ctx    The restart context (NULL disables restart).
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_INVALID_KEY if \p m or \p n are not
 *                  valid private keys, or \p P or \p Q are not valid public
 *                  keys.
 * \return          #AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if \p grp does not
 *                  designate a short Weierstrass curve.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c awrtc_mbedtls_ecp_set_max_ops().
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_muladd_restartable(
    awrtc_mbedtls_ecp_group *grp, awrtc_mbedtls_ecp_point *R,
    const awrtc_mbedtls_mpi *m, const awrtc_mbedtls_ecp_point *P,
    const awrtc_mbedtls_mpi *n, const awrtc_mbedtls_ecp_point *Q,
    awrtc_mbedtls_ecp_restart_ctx *rs_ctx);
#endif /* AWRTC_MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

/**
 * \brief           This function checks that a point is a valid public key
 *                  on this curve.
 *
 *                  It only checks that the point is non-zero, has
 *                  valid coordinates and lies on the curve. It does not verify
 *                  that it is indeed a multiple of \c G. This additional
 *                  check is computationally more expensive, is not required
 *                  by standards, and should not be necessary if the group
 *                  used has a small cofactor. In particular, it is useless for
 *                  the NIST groups which all have a cofactor of 1.
 *
 * \note            This function uses bare components rather than an
 *                  ::awrtc_mbedtls_ecp_keypair structure, to ease use with other
 *                  structures, such as ::awrtc_mbedtls_ecdh_context or
 *                  ::awrtc_mbedtls_ecdsa_context.
 *
 * \param grp       The ECP group the point should belong to.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param pt        The point to check. This must be initialized.
 *
 * \return          \c 0 if the point is a valid public key.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_INVALID_KEY if the point is not
 *                  a valid public key for the given curve.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_check_pubkey(const awrtc_mbedtls_ecp_group *grp,
                             const awrtc_mbedtls_ecp_point *pt);

/**
 * \brief           This function checks that an \c awrtc_mbedtls_mpi is a
 *                  valid private key for this curve.
 *
 * \note            This function uses bare components rather than an
 *                  ::awrtc_mbedtls_ecp_keypair structure to ease use with other
 *                  structures, such as ::awrtc_mbedtls_ecdh_context or
 *                  ::awrtc_mbedtls_ecdsa_context.
 *
 * \param grp       The ECP group the private key should belong to.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param d         The integer to check. This must be initialized.
 *
 * \return          \c 0 if the point is a valid private key.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_INVALID_KEY if the point is not a valid
 *                  private key for the given curve.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_check_privkey(const awrtc_mbedtls_ecp_group *grp,
                              const awrtc_mbedtls_mpi *d);

/**
 * \brief           This function generates a private key.
 *
 * \param grp       The ECP group to generate a private key for.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param d         The destination MPI (secret part). This must be initialized.
 * \param f_rng     The RNG function. This must not be \c NULL.
 * \param p_rng     The RNG parameter to be passed to \p f_rng. This may be
 *                  \c NULL if \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX or \c AWRTC_MBEDTLS_MPI_XXX error code
 *                  on failure.
 */
int awrtc_mbedtls_ecp_gen_privkey(const awrtc_mbedtls_ecp_group *grp,
                            awrtc_mbedtls_mpi *d,
                            awrtc_mbedtls_f_rng_t *f_rng,
                            void *p_rng);

/**
 * \brief           This function generates a keypair with a configurable base
 *                  point.
 *
 * \note            This function uses bare components rather than an
 *                  ::awrtc_mbedtls_ecp_keypair structure to ease use with other
 *                  structures, such as ::awrtc_mbedtls_ecdh_context or
 *                  ::awrtc_mbedtls_ecdsa_context.
 *
 * \param grp       The ECP group to generate a key pair for.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param G         The base point to use. This must be initialized
 *                  and belong to \p grp. It replaces the default base
 *                  point \c grp->G used by awrtc_mbedtls_ecp_gen_keypair().
 * \param d         The destination MPI (secret part).
 *                  This must be initialized.
 * \param Q         The destination point (public part).
 *                  This must be initialized.
 * \param f_rng     The RNG function. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may
 *                  be \c NULL if \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX or \c AWRTC_MBEDTLS_MPI_XXX error code
 *                  on failure.
 */
int awrtc_mbedtls_ecp_gen_keypair_base(awrtc_mbedtls_ecp_group *grp,
                                 const awrtc_mbedtls_ecp_point *G,
                                 awrtc_mbedtls_mpi *d, awrtc_mbedtls_ecp_point *Q,
                                 awrtc_mbedtls_f_rng_t *f_rng,
                                 void *p_rng);

/**
 * \brief           This function generates an ECP keypair.
 *
 * \note            This function uses bare components rather than an
 *                  ::awrtc_mbedtls_ecp_keypair structure to ease use with other
 *                  structures, such as ::awrtc_mbedtls_ecdh_context or
 *                  ::awrtc_mbedtls_ecdsa_context.
 *
 * \param grp       The ECP group to generate a key pair for.
 *                  This must be initialized and have group parameters
 *                  set, for example through awrtc_mbedtls_ecp_group_load().
 * \param d         The destination MPI (secret part).
 *                  This must be initialized.
 * \param Q         The destination point (public part).
 *                  This must be initialized.
 * \param f_rng     The RNG function. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may
 *                  be \c NULL if \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX or \c AWRTC_MBEDTLS_MPI_XXX error code
 *                  on failure.
 */
int awrtc_mbedtls_ecp_gen_keypair(awrtc_mbedtls_ecp_group *grp, awrtc_mbedtls_mpi *d,
                            awrtc_mbedtls_ecp_point *Q,
                            awrtc_mbedtls_f_rng_t *f_rng,
                            void *p_rng);

/**
 * \brief           This function generates an ECP key.
 *
 * \param grp_id    The ECP group identifier.
 * \param key       The destination key. This must be initialized.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may
 *                  be \c NULL if \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX or \c AWRTC_MBEDTLS_MPI_XXX error code
 *                  on failure.
 */
int awrtc_mbedtls_ecp_gen_key(awrtc_mbedtls_ecp_group_id grp_id, awrtc_mbedtls_ecp_keypair *key,
                        awrtc_mbedtls_f_rng_t *f_rng,
                        void *p_rng);

/** \brief          Set the public key in a key pair object.
 *
 * \note            This function does not check that the point actually
 *                  belongs to the given group. Call awrtc_mbedtls_ecp_check_pubkey()
 *                  on \p Q before calling this function to check that.
 *
 * \note            This function does not check that the public key matches
 *                  the private key that is already in \p key, if any.
 *                  To check the consistency of the resulting key pair object,
 *                  call awrtc_mbedtls_ecp_check_pub_priv() after setting both
 *                  the public key and the private key.
 *
 * \param grp_id    The ECP group identifier.
 * \param key       The key pair object. It must be initialized.
 *                  If its group has already been set, it must match \p grp_id.
 *                  If its group has not been set, it will be set to \p grp_id.
 *                  If the public key has already been set, it is overwritten.
 * \param Q         The public key to copy. This must be a point on the
 *                  curve indicated by \p grp_id.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA if \p key does not
 *                  match \p grp_id.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if the operation for
 *                  the group is not implemented.
 * \return          #AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_set_public_key(awrtc_mbedtls_ecp_group_id grp_id,
                               awrtc_mbedtls_ecp_keypair *key,
                               const awrtc_mbedtls_ecp_point *Q);

/**
 * \brief           This function reads an elliptic curve private key.
 *
 * \note            This function does not set the public key in the
 *                  key pair object. Without a public key, the key pair object
 *                  cannot be used with operations that require the public key.
 *                  Call awrtc_mbedtls_ecp_keypair_calc_public() to set the public
 *                  key from the private key. Alternatively, you can call
 *                  awrtc_mbedtls_ecp_set_public_key() to set the public key part,
 *                  and then optionally awrtc_mbedtls_ecp_check_pub_priv() to check
 *                  that the private and public parts are consistent.
 *
 * \note            If a public key has already been set in the key pair
 *                  object, this function does not check that it is consistent
 *                  with the private key. Call awrtc_mbedtls_ecp_check_pub_priv()
 *                  after setting both the public key and the private key
 *                  to make that check.
 *
 * \param grp_id    The ECP group identifier.
 * \param key       The destination key.
 * \param buf       The buffer containing the binary representation of the
 *                  key. (Big endian integer for Weierstrass curves, byte
 *                  string for Montgomery curves.)
 * \param buflen    The length of the buffer in bytes.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_INVALID_KEY error if the key is
 *                  invalid.
 * \return          #AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if the operation for
 *                  the group is not implemented.
 * \return          Another negative error code on different kinds of failure.
 */
int awrtc_mbedtls_ecp_read_key(awrtc_mbedtls_ecp_group_id grp_id, awrtc_mbedtls_ecp_keypair *key,
                         const unsigned char *buf, size_t buflen);

#if !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
/**
 * \brief           This function exports an elliptic curve private key.
 *
 * \deprecated      Note that although this function accepts an output
 *                  buffer that is smaller or larger than the key, most key
 *                  import interfaces require the output to have exactly
 *                  key's nominal length. It is generally simplest to
 *                  pass the key's nominal length as \c buflen, after
 *                  checking that the output buffer is large enough.
 *                  See the description of the \p buflen parameter for
 *                  how to calculate the nominal length.
 *                  To avoid this difficulty, use awrtc_mbedtls_ecp_write_key_ext()
 *                  instead.
 *                  awrtc_mbedtls_ecp_write_key() is deprecated and will be
 *                  removed in a future version of the library.
 *
 * \note            If the private key was not set in \p key,
 *                  the output is unspecified. Future versions
 *                  may return an error in that case.
 *
 * \param key       The private key.
 * \param buf       The output buffer for containing the binary representation
 *                  of the key.
 *                  For Weierstrass curves, this is the big-endian
 *                  representation, padded with null bytes at the beginning
 *                  to reach \p buflen bytes.
 *                  For Montgomery curves, this is the standard byte string
 *                  representation (which is little-endian), padded with
 *                  null bytes at the end to reach \p buflen bytes.
 * \param buflen    The total length of the buffer in bytes.
 *                  The length of the output is
 *                  (`grp->nbits` + 7) / 8 bytes
 *                  where `grp->nbits` is the private key size in bits.
 *                  For Weierstrass keys, if the output buffer is smaller,
 *                  leading zeros are trimmed to fit if possible. For
 *                  Montgomery keys, the output buffer must always be large
 *                  enough for the nominal length.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL or
 *                  #AWRTC_MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if the \p key
 *                  representation is larger than the available space in \p buf.
 * \return          Another negative error code on different kinds of failure.
 */
int AWRTC_MBEDTLS_DEPRECATED awrtc_mbedtls_ecp_write_key(awrtc_mbedtls_ecp_keypair *key,
                                             unsigned char *buf, size_t buflen);
#endif /* AWRTC_MBEDTLS_DEPRECATED_REMOVED */

/**
 * \brief           This function exports an elliptic curve private key.
 *
 * \param key       The private key.
 * \param olen      On success, the length of the private key.
 *                  This is always (`grp->nbits` + 7) / 8 bytes
 *                  where `grp->nbits` is the private key size in bits.
 * \param buf       The output buffer for containing the binary representation
 *                  of the key.
 * \param buflen    The total length of the buffer in bytes.
 *                  #AWRTC_MBEDTLS_ECP_MAX_BYTES is always sufficient.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL if the \p key
 *                  representation is larger than the available space in \p buf.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA if no private key is
 *                  set in \p key.
 * \return          Another negative error code on different kinds of failure.
 */
int awrtc_mbedtls_ecp_write_key_ext(const awrtc_mbedtls_ecp_keypair *key,
                              size_t *olen, unsigned char *buf, size_t buflen);

/**
 * \brief           This function exports an elliptic curve public key.
 *
 * \note            If the public key was not set in \p key,
 *                  the output is unspecified. Future versions
 *                  may return an error in that case.
 *
 * \param key       The public key.
 * \param format    The point format. This must be either
 *                  #AWRTC_MBEDTLS_ECP_PF_COMPRESSED or #AWRTC_MBEDTLS_ECP_PF_UNCOMPRESSED.
 *                  (For groups without these formats, this parameter is
 *                  ignored. But it still has to be either of the above
 *                  values.)
 * \param olen      The address at which to store the length of
 *                  the output in Bytes. This must not be \c NULL.
 * \param buf       The output buffer. This must be a writable buffer
 *                  of length \p buflen Bytes.
 * \param buflen    The length of the output buffer \p buf in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL if the output buffer
 *                  is too small to hold the point.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if the point format
 *                  or the export for the given group is not implemented.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_write_public_key(const awrtc_mbedtls_ecp_keypair *key,
                                 int format, size_t *olen,
                                 unsigned char *buf, size_t buflen);

/**
 * \brief           This function checks that the keypair objects
 *                  \p pub and \p prv have the same group and the
 *                  same public point, and that the private key in
 *                  \p prv is consistent with the public key.
 *
 * \param pub       The keypair structure holding the public key. This
 *                  must be initialized. If it contains a private key, that
 *                  part is ignored.
 * \param prv       The keypair structure holding the full keypair.
 *                  This must be initialized.
 * \param f_rng     The RNG function. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be \c
 *                  NULL if \p f_rng doesn't need a context.
 *
 * \return          \c 0 on success, meaning that the keys are valid and match.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA if the keys are invalid or do not match.
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX or an \c AWRTC_MBEDTLS_ERR_MPI_XXX
 *                  error code on calculation failure.
 */
int awrtc_mbedtls_ecp_check_pub_priv(
    const awrtc_mbedtls_ecp_keypair *pub, const awrtc_mbedtls_ecp_keypair *prv,
    awrtc_mbedtls_f_rng_t *f_rng, void *p_rng);

/** \brief          Calculate the public key from a private key in a key pair.
 *
 * \param key       A keypair structure. It must have a private key set.
 *                  If the public key is set, it will be overwritten.
 * \param f_rng     The RNG function. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be \c
 *                  NULL if \p f_rng doesn't need a context.
 *
 * \return          \c 0 on success. The key pair object can be used for
 *                  operations that require the public key.
 * \return          An \c AWRTC_MBEDTLS_ERR_ECP_XXX or an \c AWRTC_MBEDTLS_ERR_MPI_XXX
 *                  error code on calculation failure.
 */
int awrtc_mbedtls_ecp_keypair_calc_public(
    awrtc_mbedtls_ecp_keypair *key,
    awrtc_mbedtls_f_rng_t *f_rng, void *p_rng);

/** \brief          Query the group that a key pair belongs to.
 *
 * \param key       The key pair to query.
 *
 * \return          The group ID for the group registered in the key pair
 *                  object.
 *                  This is \c AWRTC_MBEDTLS_ECP_DP_NONE if no group has been set
 *                  in the key pair object.
 */
awrtc_mbedtls_ecp_group_id awrtc_mbedtls_ecp_keypair_get_group_id(
    const awrtc_mbedtls_ecp_keypair *key);

/**
 * \brief           This function exports generic key-pair parameters.
 *
 *                  Each of the output parameters can be a null pointer
 *                  if you do not need that parameter.
 *
 * \note            If the private key or the public key was not set in \p key,
 *                  the corresponding output is unspecified. Future versions
 *                  may return an error in that case.
 *
 * \param key       The key pair to export from.
 * \param grp       Slot for exported ECP group.
 *                  It must either be null or point to an initialized ECP group.
 * \param d         Slot for the exported secret value.
 *                  It must either be null or point to an initialized mpi.
 * \param Q         Slot for the exported public value.
 *                  It must either be null or point to an initialized ECP point.
 *
 * \return          \c 0 on success,
 * \return          #AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return          #AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if key id doesn't
 *                  correspond to a known group.
 * \return          Another negative error code on other kinds of failure.
 */
int awrtc_mbedtls_ecp_export(const awrtc_mbedtls_ecp_keypair *key, awrtc_mbedtls_ecp_group *grp,
                       awrtc_mbedtls_mpi *d, awrtc_mbedtls_ecp_point *Q);

#if defined(AWRTC_MBEDTLS_SELF_TEST)

/**
 * \brief          The ECP checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */
int awrtc_mbedtls_ecp_self_test(int verbose);

#endif /* AWRTC_MBEDTLS_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* ecp.h */
