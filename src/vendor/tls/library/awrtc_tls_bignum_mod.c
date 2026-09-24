/**
 *  Modular bignum functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_BIGNUM_C) && defined(AWRTC_MBEDTLS_ECP_WITH_MPI_UINT)

#include <string.h>

#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/bignum.h"

#include "../include/mbedtls/platform.h"

#include "bignum_core.h"
#include "bignum_mod.h"
#include "bignum_mod_raw.h"
#include "constant_time_internal.h"

int awrtc_mbedtls_mpi_mod_residue_setup(awrtc_mbedtls_mpi_mod_residue *r,
                                  const awrtc_mbedtls_mpi_mod_modulus *N,
                                  awrtc_mbedtls_mpi_uint *p,
                                  size_t p_limbs)
{
    if (p_limbs != N->limbs || !awrtc_mbedtls_mpi_core_lt_ct(p, N->p, N->limbs)) {
        return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    r->limbs = N->limbs;
    r->p = p;

    return 0;
}

void awrtc_mbedtls_mpi_mod_residue_release(awrtc_mbedtls_mpi_mod_residue *r)
{
    if (r == NULL) {
        return;
    }

    r->limbs = 0;
    r->p = NULL;
}

void awrtc_mbedtls_mpi_mod_modulus_init(awrtc_mbedtls_mpi_mod_modulus *N)
{
    if (N == NULL) {
        return;
    }

    N->p = NULL;
    N->limbs = 0;
    N->bits = 0;
    N->int_rep = AWRTC_MBEDTLS_MPI_MOD_REP_INVALID;
}

void awrtc_mbedtls_mpi_mod_modulus_free(awrtc_mbedtls_mpi_mod_modulus *N)
{
    if (N == NULL) {
        return;
    }

    switch (N->int_rep) {
        case AWRTC_MBEDTLS_MPI_MOD_REP_MONTGOMERY:
            if (N->rep.mont.rr != NULL) {
                awrtc_mbedtls_zeroize_and_free((awrtc_mbedtls_mpi_uint *) N->rep.mont.rr,
                                         N->limbs * sizeof(awrtc_mbedtls_mpi_uint));
                N->rep.mont.rr = NULL;
            }
            N->rep.mont.mm = 0;
            break;
        case AWRTC_MBEDTLS_MPI_MOD_REP_OPT_RED:
            N->rep.ored.modp = NULL;
            break;
        case AWRTC_MBEDTLS_MPI_MOD_REP_INVALID:
            break;
    }

    N->p = NULL;
    N->limbs = 0;
    N->bits = 0;
    N->int_rep = AWRTC_MBEDTLS_MPI_MOD_REP_INVALID;
}

static int set_mont_const_square(const awrtc_mbedtls_mpi_uint **X,
                                 const awrtc_mbedtls_mpi_uint *A,
                                 size_t limbs)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_mpi N;
    awrtc_mbedtls_mpi RR;
    *X = NULL;

    awrtc_mbedtls_mpi_init(&N);
    awrtc_mbedtls_mpi_init(&RR);

    if (A == NULL || limbs == 0 || limbs >= (AWRTC_MBEDTLS_MPI_MAX_LIMBS / 2) - 2) {
        goto cleanup;
    }

    if (awrtc_mbedtls_mpi_grow(&N, limbs)) {
        goto cleanup;
    }

    memcpy(N.p, A, sizeof(awrtc_mbedtls_mpi_uint) * limbs);

    ret = awrtc_mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N);

    if (ret == 0) {
        *X = RR.p;
        RR.p = NULL;
    }

cleanup:
    awrtc_mbedtls_mpi_free(&N);
    awrtc_mbedtls_mpi_free(&RR);
    ret = (ret != 0) ? AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED : 0;
    return ret;
}

static inline void standard_modulus_setup(awrtc_mbedtls_mpi_mod_modulus *N,
                                          const awrtc_mbedtls_mpi_uint *p,
                                          size_t p_limbs,
                                          awrtc_mbedtls_mpi_mod_rep_selector int_rep)
{
    N->p = p;
    N->limbs = p_limbs;
    N->bits = awrtc_mbedtls_mpi_core_bitlen(p, p_limbs);
    N->int_rep = int_rep;
}

int awrtc_mbedtls_mpi_mod_modulus_setup(awrtc_mbedtls_mpi_mod_modulus *N,
                                  const awrtc_mbedtls_mpi_uint *p,
                                  size_t p_limbs)
{
    int ret = 0;
    standard_modulus_setup(N, p, p_limbs, AWRTC_MBEDTLS_MPI_MOD_REP_MONTGOMERY);
    N->rep.mont.mm = awrtc_mbedtls_mpi_core_montmul_init(N->p);
    ret = set_mont_const_square(&N->rep.mont.rr, N->p, N->limbs);

    if (ret != 0) {
        awrtc_mbedtls_mpi_mod_modulus_free(N);
    }

    return ret;
}

int awrtc_mbedtls_mpi_mod_optred_modulus_setup(awrtc_mbedtls_mpi_mod_modulus *N,
                                         const awrtc_mbedtls_mpi_uint *p,
                                         size_t p_limbs,
                                         awrtc_mbedtls_mpi_modp_fn modp)
{
    standard_modulus_setup(N, p, p_limbs, AWRTC_MBEDTLS_MPI_MOD_REP_OPT_RED);
    N->rep.ored.modp = modp;
    return 0;
}

int awrtc_mbedtls_mpi_mod_mul(awrtc_mbedtls_mpi_mod_residue *X,
                        const awrtc_mbedtls_mpi_mod_residue *A,
                        const awrtc_mbedtls_mpi_mod_residue *B,
                        const awrtc_mbedtls_mpi_mod_modulus *N)
{
    if (N->limbs == 0) {
        return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    if (X->limbs != N->limbs || A->limbs != N->limbs || B->limbs != N->limbs) {
        return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    awrtc_mbedtls_mpi_uint *T = awrtc_mbedtls_calloc(N->limbs * 2 + 1, ciL);
    if (T == NULL) {
        return AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    awrtc_mbedtls_mpi_mod_raw_mul(X->p, A->p, B->p, N, T);

    awrtc_mbedtls_free(T);

    return 0;
}

int awrtc_mbedtls_mpi_mod_sub(awrtc_mbedtls_mpi_mod_residue *X,
                        const awrtc_mbedtls_mpi_mod_residue *A,
                        const awrtc_mbedtls_mpi_mod_residue *B,
                        const awrtc_mbedtls_mpi_mod_modulus *N)
{
    if (X->limbs != N->limbs || A->limbs != N->limbs || B->limbs != N->limbs) {
        return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    awrtc_mbedtls_mpi_mod_raw_sub(X->p, A->p, B->p, N);

    return 0;
}

static int awrtc_mbedtls_mpi_mod_inv_mont(awrtc_mbedtls_mpi_mod_residue *X,
                                    const awrtc_mbedtls_mpi_mod_residue *A,
                                    const awrtc_mbedtls_mpi_mod_modulus *N,
                                    awrtc_mbedtls_mpi_uint *working_memory)
{
    /* Input already in Montgomery form, so there's little to do */
    awrtc_mbedtls_mpi_mod_raw_inv_prime(X->p, A->p,
                                  N->p, N->limbs,
                                  N->rep.mont.rr,
                                  working_memory);
    return 0;
}

static int awrtc_mbedtls_mpi_mod_inv_non_mont(awrtc_mbedtls_mpi_mod_residue *X,
                                        const awrtc_mbedtls_mpi_mod_residue *A,
                                        const awrtc_mbedtls_mpi_mod_modulus *N,
                                        awrtc_mbedtls_mpi_uint *working_memory)
{
    /* Need to convert input into Montgomery form */

    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    awrtc_mbedtls_mpi_mod_modulus Nmont;
    awrtc_mbedtls_mpi_mod_modulus_init(&Nmont);

    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_mod_modulus_setup(&Nmont, N->p, N->limbs));

    /* We'll use X->p to hold the Montgomery form of the input A->p */
    awrtc_mbedtls_mpi_core_to_mont_rep(X->p, A->p, Nmont.p, Nmont.limbs,
                                 Nmont.rep.mont.mm, Nmont.rep.mont.rr,
                                 working_memory);

    awrtc_mbedtls_mpi_mod_raw_inv_prime(X->p, X->p,
                                  Nmont.p, Nmont.limbs,
                                  Nmont.rep.mont.rr,
                                  working_memory);

    /* And convert back from Montgomery form */

    awrtc_mbedtls_mpi_core_from_mont_rep(X->p, X->p, Nmont.p, Nmont.limbs,
                                   Nmont.rep.mont.mm, working_memory);

cleanup:
    awrtc_mbedtls_mpi_mod_modulus_free(&Nmont);
    return ret;
}

int awrtc_mbedtls_mpi_mod_inv(awrtc_mbedtls_mpi_mod_residue *X,
                        const awrtc_mbedtls_mpi_mod_residue *A,
                        const awrtc_mbedtls_mpi_mod_modulus *N)
{
    if (X->limbs != N->limbs || A->limbs != N->limbs) {
        return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    /* Zero has the same value regardless of Montgomery form or not */
    if (awrtc_mbedtls_mpi_core_check_zero_ct(A->p, A->limbs) == 0) {
        return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    size_t working_limbs =
        awrtc_mbedtls_mpi_mod_raw_inv_prime_working_limbs(N->limbs);

    awrtc_mbedtls_mpi_uint *working_memory = awrtc_mbedtls_calloc(working_limbs,
                                                      sizeof(awrtc_mbedtls_mpi_uint));
    if (working_memory == NULL) {
        return AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    switch (N->int_rep) {
        case AWRTC_MBEDTLS_MPI_MOD_REP_MONTGOMERY:
            ret = awrtc_mbedtls_mpi_mod_inv_mont(X, A, N, working_memory);
            break;
        case AWRTC_MBEDTLS_MPI_MOD_REP_OPT_RED:
            ret = awrtc_mbedtls_mpi_mod_inv_non_mont(X, A, N, working_memory);
            break;
        default:
            ret = AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
            break;
    }

    awrtc_mbedtls_zeroize_and_free(working_memory,
                             working_limbs * sizeof(awrtc_mbedtls_mpi_uint));

    return ret;
}

int awrtc_mbedtls_mpi_mod_add(awrtc_mbedtls_mpi_mod_residue *X,
                        const awrtc_mbedtls_mpi_mod_residue *A,
                        const awrtc_mbedtls_mpi_mod_residue *B,
                        const awrtc_mbedtls_mpi_mod_modulus *N)
{
    if (X->limbs != N->limbs || A->limbs != N->limbs || B->limbs != N->limbs) {
        return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    awrtc_mbedtls_mpi_mod_raw_add(X->p, A->p, B->p, N);

    return 0;
}

int awrtc_mbedtls_mpi_mod_random(awrtc_mbedtls_mpi_mod_residue *X,
                           awrtc_mbedtls_mpi_uint min,
                           const awrtc_mbedtls_mpi_mod_modulus *N,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng)
{
    if (X->limbs != N->limbs) {
        return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    return awrtc_mbedtls_mpi_mod_raw_random(X->p, min, N, f_rng, p_rng);
}

int awrtc_mbedtls_mpi_mod_read(awrtc_mbedtls_mpi_mod_residue *r,
                         const awrtc_mbedtls_mpi_mod_modulus *N,
                         const unsigned char *buf,
                         size_t buflen,
                         awrtc_mbedtls_mpi_mod_ext_rep ext_rep)
{
    int ret = AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;

    /* Do our best to check if r and m have been set up */
    if (r->limbs == 0 || N->limbs == 0) {
        goto cleanup;
    }
    if (r->limbs != N->limbs) {
        goto cleanup;
    }

    ret = awrtc_mbedtls_mpi_mod_raw_read(r->p, N, buf, buflen, ext_rep);
    if (ret != 0) {
        goto cleanup;
    }

    r->limbs = N->limbs;

    ret = awrtc_mbedtls_mpi_mod_raw_canonical_to_modulus_rep(r->p, N);

cleanup:
    return ret;
}

int awrtc_mbedtls_mpi_mod_write(const awrtc_mbedtls_mpi_mod_residue *r,
                          const awrtc_mbedtls_mpi_mod_modulus *N,
                          unsigned char *buf,
                          size_t buflen,
                          awrtc_mbedtls_mpi_mod_ext_rep ext_rep)
{
    /* Do our best to check if r and m have been set up */
    if (r->limbs == 0 || N->limbs == 0) {
        return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    if (r->limbs != N->limbs) {
        return AWRTC_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_mpi_uint *working_memory = r->p;
    size_t working_memory_len = sizeof(awrtc_mbedtls_mpi_uint) * r->limbs;

    if (N->int_rep == AWRTC_MBEDTLS_MPI_MOD_REP_MONTGOMERY) {

        working_memory = awrtc_mbedtls_calloc(r->limbs, sizeof(awrtc_mbedtls_mpi_uint));

        if (working_memory == NULL) {
            ret = AWRTC_MBEDTLS_ERR_MPI_ALLOC_FAILED;
            goto cleanup;
        }

        memcpy(working_memory, r->p, working_memory_len);

        ret = awrtc_mbedtls_mpi_mod_raw_from_mont_rep(working_memory, N);
        if (ret != 0) {
            goto cleanup;
        }
    }

    ret = awrtc_mbedtls_mpi_mod_raw_write(working_memory, N, buf, buflen, ext_rep);

cleanup:

    if (N->int_rep == AWRTC_MBEDTLS_MPI_MOD_REP_MONTGOMERY &&
        working_memory != NULL) {

        awrtc_mbedtls_zeroize_and_free(working_memory, working_memory_len);
    }

    return ret;
}

#endif /* AWRTC_MBEDTLS_BIGNUM_C && AWRTC_MBEDTLS_ECP_WITH_MPI_UINT */
