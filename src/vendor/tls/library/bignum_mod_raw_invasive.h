/**
 * \file bignum_mod_raw_invasive.h
 *
 * \brief Function declarations for invasive functions of Low-level
 *        modular bignum.
 */
/**
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_MBEDTLS_BIGNUM_MOD_RAW_INVASIVE_H
#define AWRTC_MBEDTLS_BIGNUM_MOD_RAW_INVASIVE_H

#include "common.h"
#include "../include/mbedtls/bignum.h"
#include "bignum_mod.h"

#if defined(AWRTC_MBEDTLS_TEST_HOOKS)

/** Convert the result of a quasi-reduction to its canonical representative.
 *
 * \param[in,out] X     The address of the MPI to be converted. Must have the
 *                      same number of limbs as \p N. The input value must
 *                      be in range 0 <= X < 2N.
 * \param[in]     N     The address of the modulus.
 */
AWRTC_MBEDTLS_STATIC_TESTABLE
void awrtc_mbedtls_mpi_mod_raw_fix_quasi_reduction(awrtc_mbedtls_mpi_uint *X,
                                             const awrtc_mbedtls_mpi_mod_modulus *N);

#endif /* AWRTC_MBEDTLS_TEST_HOOKS */

#endif /* AWRTC_MBEDTLS_BIGNUM_MOD_RAW_INVASIVE_H */
