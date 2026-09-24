/*
 *  Low-level modular bignum functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_BIGNUM_C) && defined(AWRTC_MBEDTLS_ECP_WITH_MPI_UINT)

#include <string.h>

#include "../include/mbedtls/error.h"
#include "../include/mbedtls/platform_util.h"

#include "../include/mbedtls/platform.h"

#include "bignum_core.h"
#include "bignum_mod_raw.h"
#include "bignum_mod.h"
#include "constant_time_internal.h"

#include "bignum_mod_raw_invasive.h"

void awrtc_mbedtls_mpi_mod_raw_cond_assign(awrtc_mbedtls_mpi_uint *X,
                                     const awrtc_mbedtls_mpi_uint *A,
                                     const awrtc_mbedtls_mpi_mod_modulus *N,
                                     unsigned char assign)
{
    awrtc_mbedtls_mpi_core_cond_assign(X, A, N->limbs, awrtc_mbedtls_ct_bool(assign));
}

void awrtc_mbedtls_mpi_mod_raw_cond_swap(awrtc_mbedtls_mpi_uint *X,
                                   awrtc_mbedtls_mpi_uint *Y,
                                   const awrtc_mbedtls_mpi_mod_modulus *N,
                                   unsigned char swap)
{
    awrtc_mbedtls_mpi_core_cond_swap(X, Y, N->limbs, awrtc_mbedtls_ct_bool(swap));
}

int awrtc_mbedtls_mpi_mod_raw_read(awrtc_mbedtls_mpi_uint *X,
                             const awrtc_mbedtls_mpi_mod_modulus *N,
                             const unsigned char *input,
                             size_t input_length,
                             awrtc_mbedtls_mpi_mod_ext_rep ext_rep)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    switch (ext_rep) {
        case AWRTC_MBEDTLS_MPI_MOD_EXT_REP_LE:
            ret = awrtc_mbedtls_mpi_core_read_le(X, N->limbs,
                                           input, input_length);
            break;
        case AWRTC_MBEDTLS_MPI_MOD_EXT_REP_BE:
            ret = awrtc_mbedtls_mpi_core_read_be(X, N->limbs,
                                           input, input_length);
            break;
        default:
            return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    if (ret != 0) {
        goto cleanup;
    }

    if (!awrtc_mbedtls_mpi_core_lt_ct(X, N->p, N->limbs)) {
        ret = AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

cleanup:

    return ret;
}

int awrtc_mbedtls_mpi_mod_raw_write(const awrtc_mbedtls_mpi_uint *A,
                              const awrtc_mbedtls_mpi_mod_modulus *N,
                              unsigned char *output,
                              size_t output_length,
                              awrtc_mbedtls_mpi_mod_ext_rep ext_rep)
{
    switch (ext_rep) {
        case AWRTC_MBEDTLS_MPI_MOD_EXT_REP_LE:
            return awrtc_mbedtls_mpi_core_write_le(A, N->limbs,
                                             output, output_length);
        case AWRTC_MBEDTLS_MPI_MOD_EXT_REP_BE:
            return awrtc_mbedtls_mpi_core_write_be(A, N->limbs,
                                             output, output_length);
        default:
            return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
}

void awrtc_mbedtls_mpi_mod_raw_sub(awrtc_mbedtls_mpi_uint *X,
                             const awrtc_mbedtls_mpi_uint *A,
                             const awrtc_mbedtls_mpi_uint *B,
                             const awrtc_mbedtls_mpi_mod_modulus *N)
{
    awrtc_mbedtls_mpi_uint c = awrtc_mbedtls_mpi_core_sub(X, A, B, N->limbs);

    (void) awrtc_mbedtls_mpi_core_add_if(X, N->p, N->limbs, (unsigned) c);
}

AWRTC_MBEDTLS_STATIC_TESTABLE
void awrtc_mbedtls_mpi_mod_raw_fix_quasi_reduction(awrtc_mbedtls_mpi_uint *X,
                                             const awrtc_mbedtls_mpi_mod_modulus *N)
{
    awrtc_mbedtls_mpi_uint c = awrtc_mbedtls_mpi_core_sub(X, X, N->p, N->limbs);

    (void) awrtc_mbedtls_mpi_core_add_if(X, N->p, N->limbs, (unsigned) c);
}


void awrtc_mbedtls_mpi_mod_raw_mul(awrtc_mbedtls_mpi_uint *X,
                             const awrtc_mbedtls_mpi_uint *A,
                             const awrtc_mbedtls_mpi_uint *B,
                             const awrtc_mbedtls_mpi_mod_modulus *N,
                             awrtc_mbedtls_mpi_uint *T)
{
    /* Standard (A * B) multiplication stored into pre-allocated T
     * buffer of fixed limb size of (2N + 1).
     *
     * The space may not not fully filled by when
     * AWRTC_MBEDTLS_MPI_MOD_REP_OPT_RED is used. */
    const size_t T_limbs = BITS_TO_LIMBS(N->bits) * 2;
    switch (N->int_rep) {
        case AWRTC_MBEDTLS_MPI_MOD_REP_MONTGOMERY:
            awrtc_mbedtls_mpi_core_montmul(X, A, B, N->limbs, N->p, N->limbs,
                                     N->rep.mont.mm, T);
            break;
        case AWRTC_MBEDTLS_MPI_MOD_REP_OPT_RED:
            awrtc_mbedtls_mpi_core_mul(T, A, N->limbs, B, N->limbs);

            /* Optimised Reduction */
            (*N->rep.ored.modp)(T, T_limbs);

            /* Convert back to canonical representation */
            awrtc_mbedtls_mpi_mod_raw_fix_quasi_reduction(T, N);
            memcpy(X, T, N->limbs * sizeof(awrtc_mbedtls_mpi_uint));
            break;
        default:
            break;
    }

}

size_t awrtc_mbedtls_mpi_mod_raw_inv_prime_working_limbs(size_t AN_limbs)
{
    /* awrtc_mbedtls_mpi_mod_raw_inv_prime() needs a temporary for the exponent,
     * which will be the same size as the modulus and input (AN_limbs),
     * and additional space to pass to awrtc_mbedtls_mpi_core_exp_mod(). */
    return AN_limbs +
           awrtc_mbedtls_mpi_core_exp_mod_working_limbs(AN_limbs, AN_limbs);
}

void awrtc_mbedtls_mpi_mod_raw_inv_prime(awrtc_mbedtls_mpi_uint *X,
                                   const awrtc_mbedtls_mpi_uint *A,
                                   const awrtc_mbedtls_mpi_uint *N,
                                   size_t AN_limbs,
                                   const awrtc_mbedtls_mpi_uint *RR,
                                   awrtc_mbedtls_mpi_uint *T)
{
    /* Inversion by power: g^|G| = 1 => g^(-1) = g^(|G|-1), and
     *                       |G| = N - 1, so we want
     *                 g^(|G|-1) = g^(N - 2)
     */

    /* Use the first AN_limbs of T to hold N - 2 */
    awrtc_mbedtls_mpi_uint *Nminus2 = T;
    (void) awrtc_mbedtls_mpi_core_sub_int(Nminus2, N, 2, AN_limbs);

    /* Rest of T is given to exp_mod for its working space */
    awrtc_mbedtls_mpi_core_exp_mod(X,
                             A, N, AN_limbs, Nminus2, AN_limbs,
                             RR, T + AN_limbs);
}

void awrtc_mbedtls_mpi_mod_raw_add(awrtc_mbedtls_mpi_uint *X,
                             const awrtc_mbedtls_mpi_uint *A,
                             const awrtc_mbedtls_mpi_uint *B,
                             const awrtc_mbedtls_mpi_mod_modulus *N)
{
    awrtc_mbedtls_mpi_uint carry, borrow;
    carry  = awrtc_mbedtls_mpi_core_add(X, A, B, N->limbs);
    borrow = awrtc_mbedtls_mpi_core_sub(X, X, N->p, N->limbs);
    (void) awrtc_mbedtls_mpi_core_add_if(X, N->p, N->limbs, (unsigned) (carry ^ borrow));
}

int awrtc_mbedtls_mpi_mod_raw_canonical_to_modulus_rep(
    awrtc_mbedtls_mpi_uint *X,
    const awrtc_mbedtls_mpi_mod_modulus *N)
{
    switch (N->int_rep) {
        case AWRTC_MBEDTLS_MPI_MOD_REP_MONTGOMERY:
            return awrtc_mbedtls_mpi_mod_raw_to_mont_rep(X, N);
        case AWRTC_MBEDTLS_MPI_MOD_REP_OPT_RED:
            return 0;
        default:
            return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
}

int awrtc_mbedtls_mpi_mod_raw_modulus_to_canonical_rep(
    awrtc_mbedtls_mpi_uint *X,
    const awrtc_mbedtls_mpi_mod_modulus *N)
{
    switch (N->int_rep) {
        case AWRTC_MBEDTLS_MPI_MOD_REP_MONTGOMERY:
            return awrtc_mbedtls_mpi_mod_raw_from_mont_rep(X, N);
        case AWRTC_MBEDTLS_MPI_MOD_REP_OPT_RED:
            return 0;
        default:
            return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
}

int awrtc_mbedtls_mpi_mod_raw_random(awrtc_mbedtls_mpi_uint *X,
                               awrtc_mbedtls_mpi_uint min,
                               const awrtc_mbedtls_mpi_mod_modulus *N,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng)
{
    int ret = awrtc_mbedtls_mpi_core_random(X, min, N->p, N->limbs, f_rng, p_rng);
    if (ret != 0) {
        return ret;
    }
    return awrtc_mbedtls_mpi_mod_raw_canonical_to_modulus_rep(X, N);
}

int awrtc_mbedtls_mpi_mod_raw_to_mont_rep(awrtc_mbedtls_mpi_uint *X,
                                    const awrtc_mbedtls_mpi_mod_modulus *N)
{
    awrtc_mbedtls_mpi_uint *T;
    const size_t t_limbs = awrtc_mbedtls_mpi_core_montmul_working_limbs(N->limbs);

    if ((T = (awrtc_mbedtls_mpi_uint *) awrtc_mbedtls_calloc(t_limbs, ciL)) == NULL) {
        return AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    awrtc_mbedtls_mpi_core_to_mont_rep(X, X, N->p, N->limbs,
                                 N->rep.mont.mm, N->rep.mont.rr, T);

    awrtc_mbedtls_zeroize_and_free(T, t_limbs * ciL);
    return 0;
}

int awrtc_mbedtls_mpi_mod_raw_from_mont_rep(awrtc_mbedtls_mpi_uint *X,
                                      const awrtc_mbedtls_mpi_mod_modulus *N)
{
    const size_t t_limbs = awrtc_mbedtls_mpi_core_montmul_working_limbs(N->limbs);
    awrtc_mbedtls_mpi_uint *T;

    if ((T = (awrtc_mbedtls_mpi_uint *) awrtc_mbedtls_calloc(t_limbs, ciL)) == NULL) {
        return AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    awrtc_mbedtls_mpi_core_from_mont_rep(X, X, N->p, N->limbs, N->rep.mont.mm, T);

    awrtc_mbedtls_zeroize_and_free(T, t_limbs * ciL);
    return 0;
}

void awrtc_mbedtls_mpi_mod_raw_neg(awrtc_mbedtls_mpi_uint *X,
                             const awrtc_mbedtls_mpi_uint *A,
                             const awrtc_mbedtls_mpi_mod_modulus *N)
{
    awrtc_mbedtls_mpi_core_sub(X, N->p, A, N->limbs);

    /* If A=0 initially, then X=N now. Detect this by
     * subtracting N and catching the carry. */
    awrtc_mbedtls_mpi_uint borrow = awrtc_mbedtls_mpi_core_sub(X, X, N->p, N->limbs);
    (void) awrtc_mbedtls_mpi_core_add_if(X, N->p, N->limbs, (unsigned) borrow);
}

#endif /* AWRTC_MBEDTLS_BIGNUM_C && AWRTC_MBEDTLS_ECP_WITH_MPI_UINT */
