/**
 * \file md.c
 *
 * \brief Generic message digest wrapper for Mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

/*
 * Availability of functions in this module is controlled by two
 * feature macros:
 * - AWRTC_MBEDTLS_MD_C enables the whole module;
 * - AWRTC_MBEDTLS_MD_LIGHT enables only functions for hashing and accessing
 * most hash metadata (everything except string names); is it
 * automatically set whenever AWRTC_MBEDTLS_MD_C is defined.
 *
 * In this file, functions from MD_LIGHT are at the top, MD_C at the end.
 *
 * In the future we may want to change the contract of some functions
 * (behaviour with NULL arguments) depending on whether MD_C is defined or
 * only MD_LIGHT. Also, the exact scope of MD_LIGHT might vary.
 *
 * For these reasons, we're keeping MD_LIGHT internal for now.
 */
#if defined(AWRTC_MBEDTLS_MD_LIGHT)

#include "../include/mbedtls/md.h"
#include "md_wrap.h"
#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/error.h"

#include "../include/mbedtls/md5.h"
#include "../include/mbedtls/ripemd160.h"
#include "../include/mbedtls/sha1.h"
#include "../include/mbedtls/sha256.h"
#include "../include/mbedtls/sha512.h"
#include "../include/mbedtls/sha3.h"

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT)
#include "../include/psa/crypto.h"
#include "md_psa.h"
#include "psa_util_internal.h"
#endif

#if defined(AWRTC_MBEDTLS_MD_SOME_PSA)
#include "psa_crypto_core.h"
#endif

#include "../include/mbedtls/platform.h"

#include <string.h>

#if defined(AWRTC_MBEDTLS_FS_IO)
#include <stdio.h>
#endif

/* See comment above AWRTC_MBEDTLS_MD_MAX_SIZE in md.h */
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_C) && AWRTC_MBEDTLS_MD_MAX_SIZE < AWRTC_PSA_HASH_MAX_SIZE
#error "Internal error: AWRTC_MBEDTLS_MD_MAX_SIZE < AWRTC_PSA_HASH_MAX_SIZE"
#endif

#if defined(AWRTC_MBEDTLS_MD_C)
#define MD_INFO(type, out_size, block_size) type, out_size, block_size,
#else
#define MD_INFO(type, out_size, block_size) type, out_size,
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_MD5)
static const awrtc_mbedtls_md_info_t awrtc_mbedtls_md5_info = {
    MD_INFO(AWRTC_MBEDTLS_MD_MD5, 16, 64)
};
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_RIPEMD160)
static const awrtc_mbedtls_md_info_t awrtc_mbedtls_ripemd160_info = {
    MD_INFO(AWRTC_MBEDTLS_MD_RIPEMD160, 20, 64)
};
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA1)
static const awrtc_mbedtls_md_info_t awrtc_mbedtls_sha1_info = {
    MD_INFO(AWRTC_MBEDTLS_MD_SHA1, 20, 64)
};
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA224)
static const awrtc_mbedtls_md_info_t awrtc_mbedtls_sha224_info = {
    MD_INFO(AWRTC_MBEDTLS_MD_SHA224, 28, 64)
};
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA256)
static const awrtc_mbedtls_md_info_t awrtc_mbedtls_sha256_info = {
    MD_INFO(AWRTC_MBEDTLS_MD_SHA256, 32, 64)
};
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA384)
static const awrtc_mbedtls_md_info_t awrtc_mbedtls_sha384_info = {
    MD_INFO(AWRTC_MBEDTLS_MD_SHA384, 48, 128)
};
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA512)
static const awrtc_mbedtls_md_info_t awrtc_mbedtls_sha512_info = {
    MD_INFO(AWRTC_MBEDTLS_MD_SHA512, 64, 128)
};
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_224)
static const awrtc_mbedtls_md_info_t awrtc_mbedtls_sha3_224_info = {
    MD_INFO(AWRTC_MBEDTLS_MD_SHA3_224, 28, 144)
};
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_256)
static const awrtc_mbedtls_md_info_t awrtc_mbedtls_sha3_256_info = {
    MD_INFO(AWRTC_MBEDTLS_MD_SHA3_256, 32, 136)
};
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_384)
static const awrtc_mbedtls_md_info_t awrtc_mbedtls_sha3_384_info = {
    MD_INFO(AWRTC_MBEDTLS_MD_SHA3_384, 48, 104)
};
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_512)
static const awrtc_mbedtls_md_info_t awrtc_mbedtls_sha3_512_info = {
    MD_INFO(AWRTC_MBEDTLS_MD_SHA3_512, 64, 72)
};
#endif

const awrtc_mbedtls_md_info_t *awrtc_mbedtls_md_info_from_type(awrtc_mbedtls_md_type_t md_type)
{
    switch (md_type) {
#if defined(AWRTC_MBEDTLS_MD_CAN_MD5)
        case AWRTC_MBEDTLS_MD_MD5:
            return &awrtc_mbedtls_md5_info;
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_RIPEMD160)
        case AWRTC_MBEDTLS_MD_RIPEMD160:
            return &awrtc_mbedtls_ripemd160_info;
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA1)
        case AWRTC_MBEDTLS_MD_SHA1:
            return &awrtc_mbedtls_sha1_info;
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA224)
        case AWRTC_MBEDTLS_MD_SHA224:
            return &awrtc_mbedtls_sha224_info;
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA256)
        case AWRTC_MBEDTLS_MD_SHA256:
            return &awrtc_mbedtls_sha256_info;
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA384)
        case AWRTC_MBEDTLS_MD_SHA384:
            return &awrtc_mbedtls_sha384_info;
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA512)
        case AWRTC_MBEDTLS_MD_SHA512:
            return &awrtc_mbedtls_sha512_info;
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_224)
        case AWRTC_MBEDTLS_MD_SHA3_224:
            return &awrtc_mbedtls_sha3_224_info;
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_256)
        case AWRTC_MBEDTLS_MD_SHA3_256:
            return &awrtc_mbedtls_sha3_256_info;
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_384)
        case AWRTC_MBEDTLS_MD_SHA3_384:
            return &awrtc_mbedtls_sha3_384_info;
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_512)
        case AWRTC_MBEDTLS_MD_SHA3_512:
            return &awrtc_mbedtls_sha3_512_info;
#endif
        default:
            return NULL;
    }
}

#if defined(AWRTC_MBEDTLS_MD_SOME_PSA)
static awrtc_psa_algorithm_t awrtc_psa_alg_of_md(const awrtc_mbedtls_md_info_t *info)
{
    switch (info->type) {
#if defined(AWRTC_MBEDTLS_MD_MD5_VIA_PSA)
        case AWRTC_MBEDTLS_MD_MD5:
            return AWRTC_PSA_ALG_MD5;
#endif
#if defined(AWRTC_MBEDTLS_MD_RIPEMD160_VIA_PSA)
        case AWRTC_MBEDTLS_MD_RIPEMD160:
            return AWRTC_PSA_ALG_RIPEMD160;
#endif
#if defined(AWRTC_MBEDTLS_MD_SHA1_VIA_PSA)
        case AWRTC_MBEDTLS_MD_SHA1:
            return AWRTC_PSA_ALG_SHA_1;
#endif
#if defined(AWRTC_MBEDTLS_MD_SHA224_VIA_PSA)
        case AWRTC_MBEDTLS_MD_SHA224:
            return AWRTC_PSA_ALG_SHA_224;
#endif
#if defined(AWRTC_MBEDTLS_MD_SHA256_VIA_PSA)
        case AWRTC_MBEDTLS_MD_SHA256:
            return AWRTC_PSA_ALG_SHA_256;
#endif
#if defined(AWRTC_MBEDTLS_MD_SHA384_VIA_PSA)
        case AWRTC_MBEDTLS_MD_SHA384:
            return AWRTC_PSA_ALG_SHA_384;
#endif
#if defined(AWRTC_MBEDTLS_MD_SHA512_VIA_PSA)
        case AWRTC_MBEDTLS_MD_SHA512:
            return AWRTC_PSA_ALG_SHA_512;
#endif
#if defined(AWRTC_MBEDTLS_MD_SHA3_224_VIA_PSA)
        case AWRTC_MBEDTLS_MD_SHA3_224:
            return AWRTC_PSA_ALG_SHA3_224;
#endif
#if defined(AWRTC_MBEDTLS_MD_SHA3_256_VIA_PSA)
        case AWRTC_MBEDTLS_MD_SHA3_256:
            return AWRTC_PSA_ALG_SHA3_256;
#endif
#if defined(AWRTC_MBEDTLS_MD_SHA3_384_VIA_PSA)
        case AWRTC_MBEDTLS_MD_SHA3_384:
            return AWRTC_PSA_ALG_SHA3_384;
#endif
#if defined(AWRTC_MBEDTLS_MD_SHA3_512_VIA_PSA)
        case AWRTC_MBEDTLS_MD_SHA3_512:
            return AWRTC_PSA_ALG_SHA3_512;
#endif
        default:
            return AWRTC_PSA_ALG_NONE;
    }
}

static int md_can_use_psa(const awrtc_mbedtls_md_info_t *info)
{
    awrtc_psa_algorithm_t alg = awrtc_psa_alg_of_md(info);
    if (alg == AWRTC_PSA_ALG_NONE) {
        return 0;
    }

    return awrtc_psa_can_do_hash(alg);
}
#endif /* AWRTC_MBEDTLS_MD_SOME_PSA */

void awrtc_mbedtls_md_init(awrtc_mbedtls_md_context_t *ctx)
{
    /* Note: this sets engine (if present) to AWRTC_MBEDTLS_MD_ENGINE_LEGACY */
    memset(ctx, 0, sizeof(awrtc_mbedtls_md_context_t));
}

void awrtc_mbedtls_md_free(awrtc_mbedtls_md_context_t *ctx)
{
    if (ctx == NULL || ctx->md_info == NULL) {
        return;
    }

    if (ctx->md_ctx != NULL) {
#if defined(AWRTC_MBEDTLS_MD_SOME_PSA)
        if (ctx->engine == AWRTC_MBEDTLS_MD_ENGINE_PSA) {
            awrtc_psa_hash_abort(ctx->md_ctx);
        } else
#endif
        switch (ctx->md_info->type) {
#if defined(AWRTC_MBEDTLS_MD5_C)
            case AWRTC_MBEDTLS_MD_MD5:
                awrtc_mbedtls_md5_free(ctx->md_ctx);
                break;
#endif
#if defined(AWRTC_MBEDTLS_RIPEMD160_C)
            case AWRTC_MBEDTLS_MD_RIPEMD160:
                awrtc_mbedtls_ripemd160_free(ctx->md_ctx);
                break;
#endif
#if defined(AWRTC_MBEDTLS_SHA1_C)
            case AWRTC_MBEDTLS_MD_SHA1:
                awrtc_mbedtls_sha1_free(ctx->md_ctx);
                break;
#endif
#if defined(AWRTC_MBEDTLS_SHA224_C)
            case AWRTC_MBEDTLS_MD_SHA224:
                awrtc_mbedtls_sha256_free(ctx->md_ctx);
                break;
#endif
#if defined(AWRTC_MBEDTLS_SHA256_C)
            case AWRTC_MBEDTLS_MD_SHA256:
                awrtc_mbedtls_sha256_free(ctx->md_ctx);
                break;
#endif
#if defined(AWRTC_MBEDTLS_SHA384_C)
            case AWRTC_MBEDTLS_MD_SHA384:
                awrtc_mbedtls_sha512_free(ctx->md_ctx);
                break;
#endif
#if defined(AWRTC_MBEDTLS_SHA512_C)
            case AWRTC_MBEDTLS_MD_SHA512:
                awrtc_mbedtls_sha512_free(ctx->md_ctx);
                break;
#endif
#if defined(AWRTC_MBEDTLS_SHA3_C)
            case AWRTC_MBEDTLS_MD_SHA3_224:
            case AWRTC_MBEDTLS_MD_SHA3_256:
            case AWRTC_MBEDTLS_MD_SHA3_384:
            case AWRTC_MBEDTLS_MD_SHA3_512:
                awrtc_mbedtls_sha3_free(ctx->md_ctx);
                break;
#endif
            default:
                /* Shouldn't happen */
                break;
        }
        awrtc_mbedtls_free(ctx->md_ctx);
    }

#if defined(AWRTC_MBEDTLS_MD_C)
    if (ctx->hmac_ctx != NULL) {
        awrtc_mbedtls_zeroize_and_free(ctx->hmac_ctx,
                                 2 * ctx->md_info->block_size);
    }
#endif

    awrtc_mbedtls_platform_zeroize(ctx, sizeof(awrtc_mbedtls_md_context_t));
}

int awrtc_mbedtls_md_clone(awrtc_mbedtls_md_context_t *dst,
                     const awrtc_mbedtls_md_context_t *src)
{
    if (dst == NULL || dst->md_info == NULL ||
        src == NULL || src->md_info == NULL ||
        dst->md_info != src->md_info) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_MD_SOME_PSA)
    if (src->engine != dst->engine) {
        /* This can happen with src set to legacy because PSA wasn't ready
         * yet, and dst to PSA because it became ready in the meantime.
         * We currently don't support that case (we'd need to re-allocate
         * md_ctx to the size of the appropriate MD context). */
        return AWRTC_MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }

    if (src->engine == AWRTC_MBEDTLS_MD_ENGINE_PSA) {
        awrtc_psa_status_t status = awrtc_psa_hash_clone(src->md_ctx, dst->md_ctx);
        return awrtc_mbedtls_md_error_from_psa(status);
    }
#endif

    switch (src->md_info->type) {
#if defined(AWRTC_MBEDTLS_MD5_C)
        case AWRTC_MBEDTLS_MD_MD5:
            awrtc_mbedtls_md5_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(AWRTC_MBEDTLS_RIPEMD160_C)
        case AWRTC_MBEDTLS_MD_RIPEMD160:
            awrtc_mbedtls_ripemd160_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(AWRTC_MBEDTLS_SHA1_C)
        case AWRTC_MBEDTLS_MD_SHA1:
            awrtc_mbedtls_sha1_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(AWRTC_MBEDTLS_SHA224_C)
        case AWRTC_MBEDTLS_MD_SHA224:
            awrtc_mbedtls_sha256_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(AWRTC_MBEDTLS_SHA256_C)
        case AWRTC_MBEDTLS_MD_SHA256:
            awrtc_mbedtls_sha256_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(AWRTC_MBEDTLS_SHA384_C)
        case AWRTC_MBEDTLS_MD_SHA384:
            awrtc_mbedtls_sha512_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(AWRTC_MBEDTLS_SHA512_C)
        case AWRTC_MBEDTLS_MD_SHA512:
            awrtc_mbedtls_sha512_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(AWRTC_MBEDTLS_SHA3_C)
        case AWRTC_MBEDTLS_MD_SHA3_224:
        case AWRTC_MBEDTLS_MD_SHA3_256:
        case AWRTC_MBEDTLS_MD_SHA3_384:
        case AWRTC_MBEDTLS_MD_SHA3_512:
            awrtc_mbedtls_sha3_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
        default:
            return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    return 0;
}

#define ALLOC(type)                                                   \
    do {                                                                \
        ctx->md_ctx = awrtc_mbedtls_calloc(1, sizeof(awrtc_mbedtls_##type##_context)); \
        if (ctx->md_ctx == NULL)                                       \
        return AWRTC_MBEDTLS_ERR_MD_ALLOC_FAILED;                      \
        awrtc_mbedtls_##type##_init(ctx->md_ctx);                           \
    }                                                                   \
    while (0)

int awrtc_mbedtls_md_setup(awrtc_mbedtls_md_context_t *ctx, const awrtc_mbedtls_md_info_t *md_info, int hmac)
{
#if defined(AWRTC_MBEDTLS_MD_C)
    if (ctx == NULL) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
#endif
    if (md_info == NULL) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    ctx->md_info = md_info;
    ctx->md_ctx = NULL;
#if defined(AWRTC_MBEDTLS_MD_C)
    ctx->hmac_ctx = NULL;
#else
    if (hmac != 0) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
#endif

#if defined(AWRTC_MBEDTLS_MD_SOME_PSA)
    if (md_can_use_psa(ctx->md_info)) {
        ctx->md_ctx = awrtc_mbedtls_calloc(1, sizeof(awrtc_psa_hash_operation_t));
        if (ctx->md_ctx == NULL) {
            return AWRTC_MBEDTLS_ERR_MD_ALLOC_FAILED;
        }
        ctx->engine = AWRTC_MBEDTLS_MD_ENGINE_PSA;
    } else
#endif
    switch (md_info->type) {
#if defined(AWRTC_MBEDTLS_MD5_C)
        case AWRTC_MBEDTLS_MD_MD5:
            ALLOC(md5);
            break;
#endif
#if defined(AWRTC_MBEDTLS_RIPEMD160_C)
        case AWRTC_MBEDTLS_MD_RIPEMD160:
            ALLOC(ripemd160);
            break;
#endif
#if defined(AWRTC_MBEDTLS_SHA1_C)
        case AWRTC_MBEDTLS_MD_SHA1:
            ALLOC(sha1);
            break;
#endif
#if defined(AWRTC_MBEDTLS_SHA224_C)
        case AWRTC_MBEDTLS_MD_SHA224:
            ALLOC(sha256);
            break;
#endif
#if defined(AWRTC_MBEDTLS_SHA256_C)
        case AWRTC_MBEDTLS_MD_SHA256:
            ALLOC(sha256);
            break;
#endif
#if defined(AWRTC_MBEDTLS_SHA384_C)
        case AWRTC_MBEDTLS_MD_SHA384:
            ALLOC(sha512);
            break;
#endif
#if defined(AWRTC_MBEDTLS_SHA512_C)
        case AWRTC_MBEDTLS_MD_SHA512:
            ALLOC(sha512);
            break;
#endif
#if defined(AWRTC_MBEDTLS_SHA3_C)
        case AWRTC_MBEDTLS_MD_SHA3_224:
        case AWRTC_MBEDTLS_MD_SHA3_256:
        case AWRTC_MBEDTLS_MD_SHA3_384:
        case AWRTC_MBEDTLS_MD_SHA3_512:
            ALLOC(sha3);
            break;
#endif
        default:
            return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_MD_C)
    if (hmac != 0) {
        ctx->hmac_ctx = awrtc_mbedtls_calloc(2, md_info->block_size);
        if (ctx->hmac_ctx == NULL) {
            awrtc_mbedtls_md_free(ctx);
            return AWRTC_MBEDTLS_ERR_MD_ALLOC_FAILED;
        }
    }
#endif

    return 0;
}
#undef ALLOC

int awrtc_mbedtls_md_starts(awrtc_mbedtls_md_context_t *ctx)
{
#if defined(AWRTC_MBEDTLS_MD_C)
    if (ctx == NULL || ctx->md_info == NULL) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
#endif

#if defined(AWRTC_MBEDTLS_MD_SOME_PSA)
    if (ctx->engine == AWRTC_MBEDTLS_MD_ENGINE_PSA) {
        awrtc_psa_algorithm_t alg = awrtc_psa_alg_of_md(ctx->md_info);
        awrtc_psa_hash_abort(ctx->md_ctx);
        awrtc_psa_status_t status = awrtc_psa_hash_setup(ctx->md_ctx, alg);
        return awrtc_mbedtls_md_error_from_psa(status);
    }
#endif

    switch (ctx->md_info->type) {
#if defined(AWRTC_MBEDTLS_MD5_C)
        case AWRTC_MBEDTLS_MD_MD5:
            return awrtc_mbedtls_md5_starts(ctx->md_ctx);
#endif
#if defined(AWRTC_MBEDTLS_RIPEMD160_C)
        case AWRTC_MBEDTLS_MD_RIPEMD160:
            return awrtc_mbedtls_ripemd160_starts(ctx->md_ctx);
#endif
#if defined(AWRTC_MBEDTLS_SHA1_C)
        case AWRTC_MBEDTLS_MD_SHA1:
            return awrtc_mbedtls_sha1_starts(ctx->md_ctx);
#endif
#if defined(AWRTC_MBEDTLS_SHA224_C)
        case AWRTC_MBEDTLS_MD_SHA224:
            return awrtc_mbedtls_sha256_starts(ctx->md_ctx, 1);
#endif
#if defined(AWRTC_MBEDTLS_SHA256_C)
        case AWRTC_MBEDTLS_MD_SHA256:
            return awrtc_mbedtls_sha256_starts(ctx->md_ctx, 0);
#endif
#if defined(AWRTC_MBEDTLS_SHA384_C)
        case AWRTC_MBEDTLS_MD_SHA384:
            return awrtc_mbedtls_sha512_starts(ctx->md_ctx, 1);
#endif
#if defined(AWRTC_MBEDTLS_SHA512_C)
        case AWRTC_MBEDTLS_MD_SHA512:
            return awrtc_mbedtls_sha512_starts(ctx->md_ctx, 0);
#endif
#if defined(AWRTC_MBEDTLS_SHA3_C)
        case AWRTC_MBEDTLS_MD_SHA3_224:
            return awrtc_mbedtls_sha3_starts(ctx->md_ctx, AWRTC_MBEDTLS_SHA3_224);
        case AWRTC_MBEDTLS_MD_SHA3_256:
            return awrtc_mbedtls_sha3_starts(ctx->md_ctx, AWRTC_MBEDTLS_SHA3_256);
        case AWRTC_MBEDTLS_MD_SHA3_384:
            return awrtc_mbedtls_sha3_starts(ctx->md_ctx, AWRTC_MBEDTLS_SHA3_384);
        case AWRTC_MBEDTLS_MD_SHA3_512:
            return awrtc_mbedtls_sha3_starts(ctx->md_ctx, AWRTC_MBEDTLS_SHA3_512);
#endif
        default:
            return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
}

int awrtc_mbedtls_md_update(awrtc_mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen)
{
#if defined(AWRTC_MBEDTLS_MD_C)
    if (ctx == NULL || ctx->md_info == NULL) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
#endif

#if defined(AWRTC_MBEDTLS_MD_SOME_PSA)
    if (ctx->engine == AWRTC_MBEDTLS_MD_ENGINE_PSA) {
        awrtc_psa_status_t status = awrtc_psa_hash_update(ctx->md_ctx, input, ilen);
        return awrtc_mbedtls_md_error_from_psa(status);
    }
#endif

    switch (ctx->md_info->type) {
#if defined(AWRTC_MBEDTLS_MD5_C)
        case AWRTC_MBEDTLS_MD_MD5:
            return awrtc_mbedtls_md5_update(ctx->md_ctx, input, ilen);
#endif
#if defined(AWRTC_MBEDTLS_RIPEMD160_C)
        case AWRTC_MBEDTLS_MD_RIPEMD160:
            return awrtc_mbedtls_ripemd160_update(ctx->md_ctx, input, ilen);
#endif
#if defined(AWRTC_MBEDTLS_SHA1_C)
        case AWRTC_MBEDTLS_MD_SHA1:
            return awrtc_mbedtls_sha1_update(ctx->md_ctx, input, ilen);
#endif
#if defined(AWRTC_MBEDTLS_SHA224_C)
        case AWRTC_MBEDTLS_MD_SHA224:
            return awrtc_mbedtls_sha256_update(ctx->md_ctx, input, ilen);
#endif
#if defined(AWRTC_MBEDTLS_SHA256_C)
        case AWRTC_MBEDTLS_MD_SHA256:
            return awrtc_mbedtls_sha256_update(ctx->md_ctx, input, ilen);
#endif
#if defined(AWRTC_MBEDTLS_SHA384_C)
        case AWRTC_MBEDTLS_MD_SHA384:
            return awrtc_mbedtls_sha512_update(ctx->md_ctx, input, ilen);
#endif
#if defined(AWRTC_MBEDTLS_SHA512_C)
        case AWRTC_MBEDTLS_MD_SHA512:
            return awrtc_mbedtls_sha512_update(ctx->md_ctx, input, ilen);
#endif
#if defined(AWRTC_MBEDTLS_SHA3_C)
        case AWRTC_MBEDTLS_MD_SHA3_224:
        case AWRTC_MBEDTLS_MD_SHA3_256:
        case AWRTC_MBEDTLS_MD_SHA3_384:
        case AWRTC_MBEDTLS_MD_SHA3_512:
            return awrtc_mbedtls_sha3_update(ctx->md_ctx, input, ilen);
#endif
        default:
            return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
}

int awrtc_mbedtls_md_finish(awrtc_mbedtls_md_context_t *ctx, unsigned char *output)
{
#if defined(AWRTC_MBEDTLS_MD_C)
    if (ctx == NULL || ctx->md_info == NULL) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
#endif

#if defined(AWRTC_MBEDTLS_MD_SOME_PSA)
    if (ctx->engine == AWRTC_MBEDTLS_MD_ENGINE_PSA) {
        size_t size = ctx->md_info->size;
        awrtc_psa_status_t status = awrtc_psa_hash_finish(ctx->md_ctx,
                                              output, size, &size);
        return awrtc_mbedtls_md_error_from_psa(status);
    }
#endif

    switch (ctx->md_info->type) {
#if defined(AWRTC_MBEDTLS_MD5_C)
        case AWRTC_MBEDTLS_MD_MD5:
            return awrtc_mbedtls_md5_finish(ctx->md_ctx, output);
#endif
#if defined(AWRTC_MBEDTLS_RIPEMD160_C)
        case AWRTC_MBEDTLS_MD_RIPEMD160:
            return awrtc_mbedtls_ripemd160_finish(ctx->md_ctx, output);
#endif
#if defined(AWRTC_MBEDTLS_SHA1_C)
        case AWRTC_MBEDTLS_MD_SHA1:
            return awrtc_mbedtls_sha1_finish(ctx->md_ctx, output);
#endif
#if defined(AWRTC_MBEDTLS_SHA224_C)
        case AWRTC_MBEDTLS_MD_SHA224:
            return awrtc_mbedtls_sha256_finish(ctx->md_ctx, output);
#endif
#if defined(AWRTC_MBEDTLS_SHA256_C)
        case AWRTC_MBEDTLS_MD_SHA256:
            return awrtc_mbedtls_sha256_finish(ctx->md_ctx, output);
#endif
#if defined(AWRTC_MBEDTLS_SHA384_C)
        case AWRTC_MBEDTLS_MD_SHA384:
            return awrtc_mbedtls_sha512_finish(ctx->md_ctx, output);
#endif
#if defined(AWRTC_MBEDTLS_SHA512_C)
        case AWRTC_MBEDTLS_MD_SHA512:
            return awrtc_mbedtls_sha512_finish(ctx->md_ctx, output);
#endif
#if defined(AWRTC_MBEDTLS_SHA3_C)
        case AWRTC_MBEDTLS_MD_SHA3_224:
        case AWRTC_MBEDTLS_MD_SHA3_256:
        case AWRTC_MBEDTLS_MD_SHA3_384:
        case AWRTC_MBEDTLS_MD_SHA3_512:
            return awrtc_mbedtls_sha3_finish(ctx->md_ctx, output, ctx->md_info->size);
#endif
        default:
            return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
}

int awrtc_mbedtls_md(const awrtc_mbedtls_md_info_t *md_info, const unsigned char *input, size_t ilen,
               unsigned char *output)
{
    if (md_info == NULL) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_MD_SOME_PSA)
    if (md_can_use_psa(md_info)) {
        size_t size = md_info->size;
        awrtc_psa_status_t status = awrtc_psa_hash_compute(awrtc_psa_alg_of_md(md_info),
                                               input, ilen,
                                               output, size, &size);
        return awrtc_mbedtls_md_error_from_psa(status);
    }
#endif

    switch (md_info->type) {
#if defined(AWRTC_MBEDTLS_MD5_C)
        case AWRTC_MBEDTLS_MD_MD5:
            return awrtc_mbedtls_md5(input, ilen, output);
#endif
#if defined(AWRTC_MBEDTLS_RIPEMD160_C)
        case AWRTC_MBEDTLS_MD_RIPEMD160:
            return awrtc_mbedtls_ripemd160(input, ilen, output);
#endif
#if defined(AWRTC_MBEDTLS_SHA1_C)
        case AWRTC_MBEDTLS_MD_SHA1:
            return awrtc_mbedtls_sha1(input, ilen, output);
#endif
#if defined(AWRTC_MBEDTLS_SHA224_C)
        case AWRTC_MBEDTLS_MD_SHA224:
            return awrtc_mbedtls_sha256(input, ilen, output, 1);
#endif
#if defined(AWRTC_MBEDTLS_SHA256_C)
        case AWRTC_MBEDTLS_MD_SHA256:
            return awrtc_mbedtls_sha256(input, ilen, output, 0);
#endif
#if defined(AWRTC_MBEDTLS_SHA384_C)
        case AWRTC_MBEDTLS_MD_SHA384:
            return awrtc_mbedtls_sha512(input, ilen, output, 1);
#endif
#if defined(AWRTC_MBEDTLS_SHA512_C)
        case AWRTC_MBEDTLS_MD_SHA512:
            return awrtc_mbedtls_sha512(input, ilen, output, 0);
#endif
#if defined(AWRTC_MBEDTLS_SHA3_C)
        case AWRTC_MBEDTLS_MD_SHA3_224:
            return awrtc_mbedtls_sha3(AWRTC_MBEDTLS_SHA3_224, input, ilen, output, md_info->size);
        case AWRTC_MBEDTLS_MD_SHA3_256:
            return awrtc_mbedtls_sha3(AWRTC_MBEDTLS_SHA3_256, input, ilen, output, md_info->size);
        case AWRTC_MBEDTLS_MD_SHA3_384:
            return awrtc_mbedtls_sha3(AWRTC_MBEDTLS_SHA3_384, input, ilen, output, md_info->size);
        case AWRTC_MBEDTLS_MD_SHA3_512:
            return awrtc_mbedtls_sha3(AWRTC_MBEDTLS_SHA3_512, input, ilen, output, md_info->size);
#endif
        default:
            return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
}

unsigned char awrtc_mbedtls_md_get_size(const awrtc_mbedtls_md_info_t *md_info)
{
    if (md_info == NULL) {
        return 0;
    }

    return md_info->size;
}

awrtc_mbedtls_md_type_t awrtc_mbedtls_md_get_type(const awrtc_mbedtls_md_info_t *md_info)
{
    if (md_info == NULL) {
        return AWRTC_MBEDTLS_MD_NONE;
    }

    return md_info->type;
}

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT)
int awrtc_mbedtls_md_error_from_psa(awrtc_psa_status_t status)
{
    return AWRTC_PSA_TO_MBEDTLS_ERR_LIST(status, awrtc_psa_to_md_errors,
                                   awrtc_psa_generic_status_to_mbedtls);
}
#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_CLIENT */


/************************************************************************
 * Functions above this separator are part of AWRTC_MBEDTLS_MD_LIGHT,         *
 * functions below are only available when AWRTC_MBEDTLS_MD_C is set.         *
 ************************************************************************/
#if defined(AWRTC_MBEDTLS_MD_C)

/*
 * Reminder: update profiles in x509_crt.c when adding a new hash!
 */
static const int supported_digests[] = {

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA512)
    AWRTC_MBEDTLS_MD_SHA512,
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA384)
    AWRTC_MBEDTLS_MD_SHA384,
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA256)
    AWRTC_MBEDTLS_MD_SHA256,
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA224)
    AWRTC_MBEDTLS_MD_SHA224,
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA1)
    AWRTC_MBEDTLS_MD_SHA1,
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_RIPEMD160)
    AWRTC_MBEDTLS_MD_RIPEMD160,
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_MD5)
    AWRTC_MBEDTLS_MD_MD5,
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_224)
    AWRTC_MBEDTLS_MD_SHA3_224,
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_256)
    AWRTC_MBEDTLS_MD_SHA3_256,
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_384)
    AWRTC_MBEDTLS_MD_SHA3_384,
#endif

#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_512)
    AWRTC_MBEDTLS_MD_SHA3_512,
#endif

    AWRTC_MBEDTLS_MD_NONE
};

const int *awrtc_mbedtls_md_list(void)
{
    return supported_digests;
}

typedef struct {
    const char *md_name;
    awrtc_mbedtls_md_type_t md_type;
} md_name_entry;

static const md_name_entry md_names[] = {
#if defined(AWRTC_MBEDTLS_MD_CAN_MD5)
    { "MD5", AWRTC_MBEDTLS_MD_MD5 },
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_RIPEMD160)
    { "RIPEMD160", AWRTC_MBEDTLS_MD_RIPEMD160 },
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA1)
    { "SHA1", AWRTC_MBEDTLS_MD_SHA1 },
    { "SHA", AWRTC_MBEDTLS_MD_SHA1 }, // compatibility fallback
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA224)
    { "SHA224", AWRTC_MBEDTLS_MD_SHA224 },
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA256)
    { "SHA256", AWRTC_MBEDTLS_MD_SHA256 },
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA384)
    { "SHA384", AWRTC_MBEDTLS_MD_SHA384 },
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA512)
    { "SHA512", AWRTC_MBEDTLS_MD_SHA512 },
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_224)
    { "SHA3-224", AWRTC_MBEDTLS_MD_SHA3_224 },
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_256)
    { "SHA3-256", AWRTC_MBEDTLS_MD_SHA3_256 },
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_384)
    { "SHA3-384", AWRTC_MBEDTLS_MD_SHA3_384 },
#endif
#if defined(AWRTC_MBEDTLS_MD_CAN_SHA3_512)
    { "SHA3-512", AWRTC_MBEDTLS_MD_SHA3_512 },
#endif
    { NULL, AWRTC_MBEDTLS_MD_NONE },
};

const awrtc_mbedtls_md_info_t *awrtc_mbedtls_md_info_from_string(const char *md_name)
{
    if (NULL == md_name) {
        return NULL;
    }

    const md_name_entry *entry = md_names;
    while (entry->md_name != NULL &&
           strcmp(entry->md_name, md_name) != 0) {
        ++entry;
    }

    return awrtc_mbedtls_md_info_from_type(entry->md_type);
}

const char *awrtc_mbedtls_md_get_name(const awrtc_mbedtls_md_info_t *md_info)
{
    if (md_info == NULL) {
        return NULL;
    }

    const md_name_entry *entry = md_names;
    while (entry->md_type != AWRTC_MBEDTLS_MD_NONE &&
           entry->md_type != md_info->type) {
        ++entry;
    }

    return entry->md_name;
}

const awrtc_mbedtls_md_info_t *awrtc_mbedtls_md_info_from_ctx(
    const awrtc_mbedtls_md_context_t *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return ctx->AWRTC_MBEDTLS_PRIVATE(md_info);
}

#if defined(AWRTC_MBEDTLS_FS_IO)
int awrtc_mbedtls_md_file(const awrtc_mbedtls_md_info_t *md_info, const char *path, unsigned char *output)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    FILE *f;
    size_t n;
    awrtc_mbedtls_md_context_t ctx;
    unsigned char buf[1024];

    if (md_info == NULL) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    if ((f = fopen(path, "rb")) == NULL) {
        return AWRTC_MBEDTLS_ERR_MD_FILE_IO_ERROR;
    }

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    awrtc_mbedtls_setbuf(f, NULL);

    awrtc_mbedtls_md_init(&ctx);

    if ((ret = awrtc_mbedtls_md_setup(&ctx, md_info, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = awrtc_mbedtls_md_starts(&ctx)) != 0) {
        goto cleanup;
    }

    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if ((ret = awrtc_mbedtls_md_update(&ctx, buf, n)) != 0) {
            goto cleanup;
        }
    }

    if (ferror(f) != 0) {
        ret = AWRTC_MBEDTLS_ERR_MD_FILE_IO_ERROR;
    } else {
        ret = awrtc_mbedtls_md_finish(&ctx, output);
    }

cleanup:
    awrtc_mbedtls_platform_zeroize(buf, sizeof(buf));
    fclose(f);
    awrtc_mbedtls_md_free(&ctx);

    return ret;
}
#endif /* AWRTC_MBEDTLS_FS_IO */

int awrtc_mbedtls_md_hmac_starts(awrtc_mbedtls_md_context_t *ctx, const unsigned char *key, size_t keylen)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char sum[AWRTC_MBEDTLS_MD_MAX_SIZE];
    unsigned char *ipad, *opad;

    if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    if (keylen > (size_t) ctx->md_info->block_size) {
        if ((ret = awrtc_mbedtls_md_starts(ctx)) != 0) {
            goto cleanup;
        }
        if ((ret = awrtc_mbedtls_md_update(ctx, key, keylen)) != 0) {
            goto cleanup;
        }
        if ((ret = awrtc_mbedtls_md_finish(ctx, sum)) != 0) {
            goto cleanup;
        }

        keylen = ctx->md_info->size;
        key = sum;
    }

    ipad = (unsigned char *) ctx->hmac_ctx;
    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    memset(ipad, 0x36, ctx->md_info->block_size);
    memset(opad, 0x5C, ctx->md_info->block_size);

    awrtc_mbedtls_xor(ipad, ipad, key, keylen);
    awrtc_mbedtls_xor(opad, opad, key, keylen);

    if ((ret = awrtc_mbedtls_md_starts(ctx)) != 0) {
        goto cleanup;
    }
    if ((ret = awrtc_mbedtls_md_update(ctx, ipad,
                                 ctx->md_info->block_size)) != 0) {
        goto cleanup;
    }

cleanup:
    awrtc_mbedtls_platform_zeroize(sum, sizeof(sum));

    return ret;
}

int awrtc_mbedtls_md_hmac_update(awrtc_mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen)
{
    if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    return awrtc_mbedtls_md_update(ctx, input, ilen);
}

int awrtc_mbedtls_md_hmac_finish(awrtc_mbedtls_md_context_t *ctx, unsigned char *output)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char tmp[AWRTC_MBEDTLS_MD_MAX_SIZE];
    unsigned char *opad;

    if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    if ((ret = awrtc_mbedtls_md_finish(ctx, tmp)) != 0) {
        return ret;
    }
    if ((ret = awrtc_mbedtls_md_starts(ctx)) != 0) {
        return ret;
    }
    if ((ret = awrtc_mbedtls_md_update(ctx, opad,
                                 ctx->md_info->block_size)) != 0) {
        return ret;
    }
    if ((ret = awrtc_mbedtls_md_update(ctx, tmp,
                                 ctx->md_info->size)) != 0) {
        return ret;
    }
    return awrtc_mbedtls_md_finish(ctx, output);
}

int awrtc_mbedtls_md_hmac_reset(awrtc_mbedtls_md_context_t *ctx)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *ipad;

    if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    ipad = (unsigned char *) ctx->hmac_ctx;

    if ((ret = awrtc_mbedtls_md_starts(ctx)) != 0) {
        return ret;
    }
    return awrtc_mbedtls_md_update(ctx, ipad, ctx->md_info->block_size);
}

int awrtc_mbedtls_md_hmac(const awrtc_mbedtls_md_info_t *md_info,
                    const unsigned char *key, size_t keylen,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output)
{
    awrtc_mbedtls_md_context_t ctx;
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (md_info == NULL) {
        return AWRTC_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    awrtc_mbedtls_md_init(&ctx);

    if ((ret = awrtc_mbedtls_md_setup(&ctx, md_info, 1)) != 0) {
        goto cleanup;
    }

    if ((ret = awrtc_mbedtls_md_hmac_starts(&ctx, key, keylen)) != 0) {
        goto cleanup;
    }
    if ((ret = awrtc_mbedtls_md_hmac_update(&ctx, input, ilen)) != 0) {
        goto cleanup;
    }
    if ((ret = awrtc_mbedtls_md_hmac_finish(&ctx, output)) != 0) {
        goto cleanup;
    }

cleanup:
    awrtc_mbedtls_md_free(&ctx);

    return ret;
}

#endif /* AWRTC_MBEDTLS_MD_C */

#endif /* AWRTC_MBEDTLS_MD_LIGHT */
