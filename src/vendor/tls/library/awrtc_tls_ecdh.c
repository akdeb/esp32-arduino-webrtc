/*
 *  Elliptic curve Diffie-Hellman
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * References:
 *
 * SEC1 https://www.secg.org/sec1-v2.pdf
 * RFC 4492
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_ECDH_C)

#include "../include/mbedtls/ecdh.h"
#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/error.h"

#include <string.h>

#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
typedef awrtc_mbedtls_ecdh_context awrtc_mbedtls_ecdh_context_mbed;
#endif

static awrtc_mbedtls_ecp_group_id awrtc_mbedtls_ecdh_grp_id(
    const awrtc_mbedtls_ecdh_context *ctx)
{
#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ctx->grp.id;
#else
    return ctx->grp_id;
#endif
}

int awrtc_mbedtls_ecdh_can_do(awrtc_mbedtls_ecp_group_id gid)
{
    /* At this time, all groups support ECDH. */
    (void) gid;
    return 1;
}

#if !defined(AWRTC_MBEDTLS_ECDH_GEN_PUBLIC_ALT)
/*
 * Generate public key (restartable version)
 *
 * Note: this internal function relies on its caller preserving the value of
 * the output parameter 'd' across continuation calls. This would not be
 * acceptable for a public function but is OK here as we control call sites.
 */
static int ecdh_gen_public_restartable(awrtc_mbedtls_ecp_group *grp,
                                       awrtc_mbedtls_mpi *d, awrtc_mbedtls_ecp_point *Q,
                                       int (*f_rng)(void *, unsigned char *, size_t),
                                       void *p_rng,
                                       awrtc_mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    int restarting = 0;
#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    restarting = (rs_ctx != NULL && rs_ctx->rsm != NULL);
#endif
    /* If multiplication is in progress, we already generated a privkey */
    if (!restarting) {
        AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_ecp_gen_privkey(grp, d, f_rng, p_rng));
    }

    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_ecp_mul_restartable(grp, Q, d, &grp->G,
                                                f_rng, p_rng, rs_ctx));

cleanup:
    return ret;
}

/*
 * Generate public key
 */
int awrtc_mbedtls_ecdh_gen_public(awrtc_mbedtls_ecp_group *grp, awrtc_mbedtls_mpi *d, awrtc_mbedtls_ecp_point *Q,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    return ecdh_gen_public_restartable(grp, d, Q, f_rng, p_rng, NULL);
}
#endif /* !AWRTC_MBEDTLS_ECDH_GEN_PUBLIC_ALT */

#if !defined(AWRTC_MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
/*
 * Compute shared secret (SEC1 3.3.1)
 */
static int ecdh_compute_shared_restartable(awrtc_mbedtls_ecp_group *grp,
                                           awrtc_mbedtls_mpi *z,
                                           const awrtc_mbedtls_ecp_point *Q, const awrtc_mbedtls_mpi *d,
                                           int (*f_rng)(void *, unsigned char *, size_t),
                                           void *p_rng,
                                           awrtc_mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ecp_point P;

    awrtc_mbedtls_ecp_point_init(&P);

    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_ecp_mul_restartable(grp, &P, d, Q,
                                                f_rng, p_rng, rs_ctx));

    if (awrtc_mbedtls_ecp_is_zero(&P)) {
        ret = AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    AWRTC_MBEDTLS_MPI_CHK(awrtc_mbedtls_mpi_copy(z, &P.X));

cleanup:
    awrtc_mbedtls_ecp_point_free(&P);

    return ret;
}

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int awrtc_mbedtls_ecdh_compute_shared(awrtc_mbedtls_ecp_group *grp, awrtc_mbedtls_mpi *z,
                                const awrtc_mbedtls_ecp_point *Q, const awrtc_mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
    return ecdh_compute_shared_restartable(grp, z, Q, d,
                                           f_rng, p_rng, NULL);
}
#endif /* !AWRTC_MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

static void ecdh_init_internal(awrtc_mbedtls_ecdh_context_mbed *ctx)
{
    awrtc_mbedtls_ecp_group_init(&ctx->grp);
    awrtc_mbedtls_mpi_init(&ctx->d);
    awrtc_mbedtls_ecp_point_init(&ctx->Q);
    awrtc_mbedtls_ecp_point_init(&ctx->Qp);
    awrtc_mbedtls_mpi_init(&ctx->z);

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    awrtc_mbedtls_ecp_restart_init(&ctx->rs);
#endif
}

awrtc_mbedtls_ecp_group_id awrtc_mbedtls_ecdh_get_grp_id(awrtc_mbedtls_ecdh_context *ctx)
{
#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ctx->AWRTC_MBEDTLS_PRIVATE(grp).id;
#else
    return ctx->AWRTC_MBEDTLS_PRIVATE(grp_id);
#endif
}

/*
 * Initialize context
 */
void awrtc_mbedtls_ecdh_init(awrtc_mbedtls_ecdh_context *ctx)
{
#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    ecdh_init_internal(ctx);
    awrtc_mbedtls_ecp_point_init(&ctx->Vi);
    awrtc_mbedtls_ecp_point_init(&ctx->Vf);
    awrtc_mbedtls_mpi_init(&ctx->_d);
#else
    memset(ctx, 0, sizeof(awrtc_mbedtls_ecdh_context));

    ctx->var = AWRTC_MBEDTLS_ECDH_VARIANT_NONE;
#endif
    ctx->point_format = AWRTC_MBEDTLS_ECP_PF_UNCOMPRESSED;
#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    ctx->restart_enabled = 0;
#endif
}

static int ecdh_setup_internal(awrtc_mbedtls_ecdh_context_mbed *ctx,
                               awrtc_mbedtls_ecp_group_id grp_id)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = awrtc_mbedtls_ecp_group_load(&ctx->grp, grp_id);
    if (ret != 0) {
        return AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    return 0;
}

/*
 * Setup context
 */
int awrtc_mbedtls_ecdh_setup(awrtc_mbedtls_ecdh_context *ctx, awrtc_mbedtls_ecp_group_id grp_id)
{
#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_setup_internal(ctx, grp_id);
#else
    switch (grp_id) {
#if defined(AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case AWRTC_MBEDTLS_ECP_DP_CURVE25519:
            ctx->point_format = AWRTC_MBEDTLS_ECP_PF_COMPRESSED;
            ctx->var = AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST;
            ctx->grp_id = grp_id;
            return awrtc_mbedtls_everest_setup(&ctx->ctx.everest_ecdh, grp_id);
#endif
        default:
            ctx->point_format = AWRTC_MBEDTLS_ECP_PF_UNCOMPRESSED;
            ctx->var = AWRTC_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0;
            ctx->grp_id = grp_id;
            ecdh_init_internal(&ctx->ctx.mbed_ecdh);
            return ecdh_setup_internal(&ctx->ctx.mbed_ecdh, grp_id);
    }
#endif
}

static void ecdh_free_internal(awrtc_mbedtls_ecdh_context_mbed *ctx)
{
    awrtc_mbedtls_ecp_group_free(&ctx->grp);
    awrtc_mbedtls_mpi_free(&ctx->d);
    awrtc_mbedtls_ecp_point_free(&ctx->Q);
    awrtc_mbedtls_ecp_point_free(&ctx->Qp);
    awrtc_mbedtls_mpi_free(&ctx->z);

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    awrtc_mbedtls_ecp_restart_free(&ctx->rs);
#endif
}

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
/*
 * Enable restartable operations for context
 */
void awrtc_mbedtls_ecdh_enable_restart(awrtc_mbedtls_ecdh_context *ctx)
{
    ctx->restart_enabled = 1;
}
#endif

/*
 * Free context
 */
void awrtc_mbedtls_ecdh_free(awrtc_mbedtls_ecdh_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    awrtc_mbedtls_ecp_point_free(&ctx->Vi);
    awrtc_mbedtls_ecp_point_free(&ctx->Vf);
    awrtc_mbedtls_mpi_free(&ctx->_d);
    ecdh_free_internal(ctx);
#else
    switch (ctx->var) {
#if defined(AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST:
            awrtc_mbedtls_everest_free(&ctx->ctx.everest_ecdh);
            break;
#endif
        case AWRTC_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            ecdh_free_internal(&ctx->ctx.mbed_ecdh);
            break;
        default:
            break;
    }

    ctx->point_format = AWRTC_MBEDTLS_ECP_PF_UNCOMPRESSED;
    ctx->var = AWRTC_MBEDTLS_ECDH_VARIANT_NONE;
    ctx->grp_id = AWRTC_MBEDTLS_ECP_DP_NONE;
#endif
}

static int ecdh_make_params_internal(awrtc_mbedtls_ecdh_context_mbed *ctx,
                                     size_t *olen, int point_format,
                                     unsigned char *buf, size_t blen,
                                     int (*f_rng)(void *,
                                                  unsigned char *,
                                                  size_t),
                                     void *p_rng,
                                     int restart_enabled)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t grp_len, pt_len;
#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    awrtc_mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if (ctx->grp.pbits == 0) {
        return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    if (restart_enabled) {
        rs_ctx = &ctx->rs;
    }
#else
    (void) restart_enabled;
#endif


#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    if ((ret = ecdh_gen_public_restartable(&ctx->grp, &ctx->d, &ctx->Q,
                                           f_rng, p_rng, rs_ctx)) != 0) {
        return ret;
    }
#else
    if ((ret = awrtc_mbedtls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q,
                                       f_rng, p_rng)) != 0) {
        return ret;
    }
#endif /* AWRTC_MBEDTLS_ECP_RESTARTABLE */

    if ((ret = awrtc_mbedtls_ecp_tls_write_group(&ctx->grp, &grp_len, buf,
                                           blen)) != 0) {
        return ret;
    }

    buf += grp_len;
    blen -= grp_len;

    if ((ret = awrtc_mbedtls_ecp_tls_write_point(&ctx->grp, &ctx->Q, point_format,
                                           &pt_len, buf, blen)) != 0) {
        return ret;
    }

    *olen = grp_len + pt_len;
    return 0;
}

/*
 * Setup and write the ServerKeyExchange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int awrtc_mbedtls_ecdh_make_params(awrtc_mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int restart_enabled = 0;
#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#else
    (void) restart_enabled;
#endif

#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_make_params_internal(ctx, olen, ctx->point_format, buf, blen,
                                     f_rng, p_rng, restart_enabled);
#else
    switch (ctx->var) {
#if defined(AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST:
            return awrtc_mbedtls_everest_make_params(&ctx->ctx.everest_ecdh, olen,
                                               buf, blen, f_rng, p_rng);
#endif
        case AWRTC_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_make_params_internal(&ctx->ctx.mbed_ecdh, olen,
                                             ctx->point_format, buf, blen,
                                             f_rng, p_rng,
                                             restart_enabled);
        default:
            return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_read_params_internal(awrtc_mbedtls_ecdh_context_mbed *ctx,
                                     const unsigned char **buf,
                                     const unsigned char *end)
{
    return awrtc_mbedtls_ecp_tls_read_point(&ctx->grp, &ctx->Qp, buf,
                                      (size_t) (end - *buf));
}

/*
 * Read the ServerKeyExchange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int awrtc_mbedtls_ecdh_read_params(awrtc_mbedtls_ecdh_context *ctx,
                             const unsigned char **buf,
                             const unsigned char *end)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ecp_group_id grp_id;
    if ((ret = awrtc_mbedtls_ecp_tls_read_group_id(&grp_id, buf, (size_t) (end - *buf)))
        != 0) {
        return ret;
    }

    if ((ret = awrtc_mbedtls_ecdh_setup(ctx, grp_id)) != 0) {
        return ret;
    }

#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_read_params_internal(ctx, buf, end);
#else
    switch (ctx->var) {
#if defined(AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST:
            return awrtc_mbedtls_everest_read_params(&ctx->ctx.everest_ecdh,
                                               buf, end);
#endif
        case AWRTC_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_read_params_internal(&ctx->ctx.mbed_ecdh,
                                             buf, end);
        default:
            return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_get_params_internal(awrtc_mbedtls_ecdh_context_mbed *ctx,
                                    const awrtc_mbedtls_ecp_keypair *key,
                                    awrtc_mbedtls_ecdh_side side)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* If it's not our key, just import the public part as Qp */
    if (side == AWRTC_MBEDTLS_ECDH_THEIRS) {
        return awrtc_mbedtls_ecp_copy(&ctx->Qp, &key->Q);
    }

    /* Our key: import public (as Q) and private parts */
    if (side != AWRTC_MBEDTLS_ECDH_OURS) {
        return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if ((ret = awrtc_mbedtls_ecp_copy(&ctx->Q, &key->Q)) != 0 ||
        (ret = awrtc_mbedtls_mpi_copy(&ctx->d, &key->d)) != 0) {
        return ret;
    }

    return 0;
}

/*
 * Get parameters from a keypair
 */
int awrtc_mbedtls_ecdh_get_params(awrtc_mbedtls_ecdh_context *ctx,
                            const awrtc_mbedtls_ecp_keypair *key,
                            awrtc_mbedtls_ecdh_side side)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (side != AWRTC_MBEDTLS_ECDH_OURS && side != AWRTC_MBEDTLS_ECDH_THEIRS) {
        return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (awrtc_mbedtls_ecdh_grp_id(ctx) == AWRTC_MBEDTLS_ECP_DP_NONE) {
        /* This is the first call to get_params(). Set up the context
         * for use with the group. */
        if ((ret = awrtc_mbedtls_ecdh_setup(ctx, key->grp.id)) != 0) {
            return ret;
        }
    } else {
        /* This is not the first call to get_params(). Check that the
         * current key's group is the same as the context's, which was set
         * from the first key's group. */
        if (awrtc_mbedtls_ecdh_grp_id(ctx) != key->grp.id) {
            return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
    }

#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_get_params_internal(ctx, key, side);
#else
    switch (ctx->var) {
#if defined(AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST:
        {
            awrtc_mbedtls_everest_ecdh_side s = side == AWRTC_MBEDTLS_ECDH_OURS ?
                                          AWRTC_MBEDTLS_EVEREST_ECDH_OURS :
                                          AWRTC_MBEDTLS_EVEREST_ECDH_THEIRS;
            return awrtc_mbedtls_everest_get_params(&ctx->ctx.everest_ecdh,
                                              key, s);
        }
#endif
        case AWRTC_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_get_params_internal(&ctx->ctx.mbed_ecdh,
                                            key, side);
        default:
            return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_make_public_internal(awrtc_mbedtls_ecdh_context_mbed *ctx,
                                     size_t *olen, int point_format,
                                     unsigned char *buf, size_t blen,
                                     int (*f_rng)(void *,
                                                  unsigned char *,
                                                  size_t),
                                     void *p_rng,
                                     int restart_enabled)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    awrtc_mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if (ctx->grp.pbits == 0) {
        return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    if (restart_enabled) {
        rs_ctx = &ctx->rs;
    }
#else
    (void) restart_enabled;
#endif

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    if ((ret = ecdh_gen_public_restartable(&ctx->grp, &ctx->d, &ctx->Q,
                                           f_rng, p_rng, rs_ctx)) != 0) {
        return ret;
    }
#else
    if ((ret = awrtc_mbedtls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q,
                                       f_rng, p_rng)) != 0) {
        return ret;
    }
#endif /* AWRTC_MBEDTLS_ECP_RESTARTABLE */

    return awrtc_mbedtls_ecp_tls_write_point(&ctx->grp, &ctx->Q, point_format, olen,
                                       buf, blen);
}

/*
 * Setup and export the client public value
 */
int awrtc_mbedtls_ecdh_make_public(awrtc_mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int restart_enabled = 0;
#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#endif

#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_make_public_internal(ctx, olen, ctx->point_format, buf, blen,
                                     f_rng, p_rng, restart_enabled);
#else
    switch (ctx->var) {
#if defined(AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST:
            return awrtc_mbedtls_everest_make_public(&ctx->ctx.everest_ecdh, olen,
                                               buf, blen, f_rng, p_rng);
#endif
        case AWRTC_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_make_public_internal(&ctx->ctx.mbed_ecdh, olen,
                                             ctx->point_format, buf, blen,
                                             f_rng, p_rng,
                                             restart_enabled);
        default:
            return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_read_public_internal(awrtc_mbedtls_ecdh_context_mbed *ctx,
                                     const unsigned char *buf, size_t blen)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;

    if ((ret = awrtc_mbedtls_ecp_tls_read_point(&ctx->grp, &ctx->Qp, &p,
                                          blen)) != 0) {
        return ret;
    }

    if ((size_t) (p - buf) != blen) {
        return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    return 0;
}

/*
 * Parse and import the client's public value
 */
int awrtc_mbedtls_ecdh_read_public(awrtc_mbedtls_ecdh_context *ctx,
                             const unsigned char *buf, size_t blen)
{
#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_read_public_internal(ctx, buf, blen);
#else
    switch (ctx->var) {
#if defined(AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST:
            return awrtc_mbedtls_everest_read_public(&ctx->ctx.everest_ecdh,
                                               buf, blen);
#endif
        case AWRTC_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_read_public_internal(&ctx->ctx.mbed_ecdh,
                                             buf, blen);
        default:
            return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_calc_secret_internal(awrtc_mbedtls_ecdh_context_mbed *ctx,
                                     size_t *olen, unsigned char *buf,
                                     size_t blen,
                                     int (*f_rng)(void *,
                                                  unsigned char *,
                                                  size_t),
                                     void *p_rng,
                                     int restart_enabled)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    awrtc_mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if (ctx == NULL || ctx->grp.pbits == 0) {
        return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    if (restart_enabled) {
        rs_ctx = &ctx->rs;
    }
#else
    (void) restart_enabled;
#endif

#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    if ((ret = ecdh_compute_shared_restartable(&ctx->grp, &ctx->z, &ctx->Qp,
                                               &ctx->d, f_rng, p_rng,
                                               rs_ctx)) != 0) {
        return ret;
    }
#else
    if ((ret = awrtc_mbedtls_ecdh_compute_shared(&ctx->grp, &ctx->z, &ctx->Qp,
                                           &ctx->d, f_rng, p_rng)) != 0) {
        return ret;
    }
#endif /* AWRTC_MBEDTLS_ECP_RESTARTABLE */

    if (awrtc_mbedtls_mpi_size(&ctx->z) > blen) {
        return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    *olen = ctx->grp.pbits / 8 + ((ctx->grp.pbits % 8) != 0);

    if (awrtc_mbedtls_ecp_get_type(&ctx->grp) == AWRTC_MBEDTLS_ECP_TYPE_MONTGOMERY) {
        return awrtc_mbedtls_mpi_write_binary_le(&ctx->z, buf, *olen);
    }

    return awrtc_mbedtls_mpi_write_binary(&ctx->z, buf, *olen);
}

/*
 * Derive and export the shared secret
 */
int awrtc_mbedtls_ecdh_calc_secret(awrtc_mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int restart_enabled = 0;
#if defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#endif

#if defined(AWRTC_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_calc_secret_internal(ctx, olen, buf, blen, f_rng, p_rng,
                                     restart_enabled);
#else
    switch (ctx->var) {
#if defined(AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case AWRTC_MBEDTLS_ECDH_VARIANT_EVEREST:
            return awrtc_mbedtls_everest_calc_secret(&ctx->ctx.everest_ecdh, olen,
                                               buf, blen, f_rng, p_rng);
#endif
        case AWRTC_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_calc_secret_internal(&ctx->ctx.mbed_ecdh, olen, buf,
                                             blen, f_rng, p_rng,
                                             restart_enabled);
        default:
            return AWRTC_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}
#endif /* AWRTC_MBEDTLS_ECDH_C */
