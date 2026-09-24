/**
 * \file cipher.c
 *
 * \brief Generic cipher wrapper for Mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_CIPHER_C)

#include "../include/mbedtls/cipher.h"
#include "cipher_invasive.h"
#include "cipher_wrap.h"
#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/constant_time.h"
#include "constant_time_internal.h"

#include <stdlib.h>
#include <string.h>

#if defined(AWRTC_MBEDTLS_CHACHAPOLY_C)
#include "../include/mbedtls/chachapoly.h"
#endif

#if defined(AWRTC_MBEDTLS_GCM_C)
#include "../include/mbedtls/gcm.h"
#endif

#if defined(AWRTC_MBEDTLS_CCM_C)
#include "../include/mbedtls/ccm.h"
#endif

#if defined(AWRTC_MBEDTLS_CHACHA20_C)
#include "../include/mbedtls/chacha20.h"
#endif

#if defined(AWRTC_MBEDTLS_CMAC_C)
#include "../include/mbedtls/cmac.h"
#endif

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
#include "../include/psa/crypto.h"
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

#if defined(AWRTC_MBEDTLS_NIST_KW_C)
#include "../include/mbedtls/nist_kw.h"
#endif

#include "../include/mbedtls/platform.h"

static int supported_init = 0;

static inline const awrtc_mbedtls_cipher_base_t *awrtc_mbedtls_cipher_get_base(
    const awrtc_mbedtls_cipher_info_t *info)
{
    return awrtc_mbedtls_cipher_base_lookup_table[info->base_idx];
}

const int *awrtc_mbedtls_cipher_list(void)
{
    const awrtc_mbedtls_cipher_definition_t *def;
    int *type;

    if (!supported_init) {
        def = awrtc_mbedtls_cipher_definitions;
        type = awrtc_mbedtls_cipher_supported;

        while (def->type != 0) {
            *type++ = (*def++).type;
        }

        *type = 0;

        supported_init = 1;
    }

    return awrtc_mbedtls_cipher_supported;
}

const awrtc_mbedtls_cipher_info_t *awrtc_mbedtls_cipher_info_from_type(
    const awrtc_mbedtls_cipher_type_t cipher_type)
{
    const awrtc_mbedtls_cipher_definition_t *def;

    for (def = awrtc_mbedtls_cipher_definitions; def->info != NULL; def++) {
        if (def->type == cipher_type) {
            return def->info;
        }
    }

    return NULL;
}

const awrtc_mbedtls_cipher_info_t *awrtc_mbedtls_cipher_info_from_string(
    const char *cipher_name)
{
    const awrtc_mbedtls_cipher_definition_t *def;

    if (NULL == cipher_name) {
        return NULL;
    }

    for (def = awrtc_mbedtls_cipher_definitions; def->info != NULL; def++) {
        if (!strcmp(def->info->name, cipher_name)) {
            return def->info;
        }
    }

    return NULL;
}

const awrtc_mbedtls_cipher_info_t *awrtc_mbedtls_cipher_info_from_values(
    const awrtc_mbedtls_cipher_id_t cipher_id,
    int key_bitlen,
    const awrtc_mbedtls_cipher_mode_t mode)
{
    const awrtc_mbedtls_cipher_definition_t *def;

    for (def = awrtc_mbedtls_cipher_definitions; def->info != NULL; def++) {
        if (awrtc_mbedtls_cipher_get_base(def->info)->cipher == cipher_id &&
            awrtc_mbedtls_cipher_info_get_key_bitlen(def->info) == (unsigned) key_bitlen &&
            def->info->mode == mode) {
            return def->info;
        }
    }

    return NULL;
}

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
static inline awrtc_psa_key_type_t awrtc_mbedtls_psa_translate_cipher_type(
    awrtc_mbedtls_cipher_type_t cipher)
{
    switch (cipher) {
        case AWRTC_MBEDTLS_CIPHER_AES_128_CCM:
        case AWRTC_MBEDTLS_CIPHER_AES_192_CCM:
        case AWRTC_MBEDTLS_CIPHER_AES_256_CCM:
        case AWRTC_MBEDTLS_CIPHER_AES_128_CCM_STAR_NO_TAG:
        case AWRTC_MBEDTLS_CIPHER_AES_192_CCM_STAR_NO_TAG:
        case AWRTC_MBEDTLS_CIPHER_AES_256_CCM_STAR_NO_TAG:
        case AWRTC_MBEDTLS_CIPHER_AES_128_GCM:
        case AWRTC_MBEDTLS_CIPHER_AES_192_GCM:
        case AWRTC_MBEDTLS_CIPHER_AES_256_GCM:
        case AWRTC_MBEDTLS_CIPHER_AES_128_CBC:
        case AWRTC_MBEDTLS_CIPHER_AES_192_CBC:
        case AWRTC_MBEDTLS_CIPHER_AES_256_CBC:
        case AWRTC_MBEDTLS_CIPHER_AES_128_ECB:
        case AWRTC_MBEDTLS_CIPHER_AES_192_ECB:
        case AWRTC_MBEDTLS_CIPHER_AES_256_ECB:
            return AWRTC_PSA_KEY_TYPE_AES;

        /* ARIA not yet supported in PSA. */
        /* case AWRTC_MBEDTLS_CIPHER_ARIA_128_CCM:
           case AWRTC_MBEDTLS_CIPHER_ARIA_192_CCM:
           case AWRTC_MBEDTLS_CIPHER_ARIA_256_CCM:
           case AWRTC_MBEDTLS_CIPHER_ARIA_128_CCM_STAR_NO_TAG:
           case AWRTC_MBEDTLS_CIPHER_ARIA_192_CCM_STAR_NO_TAG:
           case AWRTC_MBEDTLS_CIPHER_ARIA_256_CCM_STAR_NO_TAG:
           case AWRTC_MBEDTLS_CIPHER_ARIA_128_GCM:
           case AWRTC_MBEDTLS_CIPHER_ARIA_192_GCM:
           case AWRTC_MBEDTLS_CIPHER_ARIA_256_GCM:
           case AWRTC_MBEDTLS_CIPHER_ARIA_128_CBC:
           case AWRTC_MBEDTLS_CIPHER_ARIA_192_CBC:
           case AWRTC_MBEDTLS_CIPHER_ARIA_256_CBC:
               return( AWRTC_PSA_KEY_TYPE_ARIA ); */

        default:
            return 0;
    }
}

static inline awrtc_psa_algorithm_t awrtc_mbedtls_psa_translate_cipher_mode(
    awrtc_mbedtls_cipher_mode_t mode, size_t taglen)
{
    switch (mode) {
        case AWRTC_MBEDTLS_MODE_ECB:
            return AWRTC_PSA_ALG_ECB_NO_PADDING;
        case AWRTC_MBEDTLS_MODE_GCM:
            return AWRTC_PSA_ALG_AEAD_WITH_SHORTENED_TAG(AWRTC_PSA_ALG_GCM, taglen);
        case AWRTC_MBEDTLS_MODE_CCM:
            return AWRTC_PSA_ALG_AEAD_WITH_SHORTENED_TAG(AWRTC_PSA_ALG_CCM, taglen);
        case AWRTC_MBEDTLS_MODE_CCM_STAR_NO_TAG:
            return AWRTC_PSA_ALG_CCM_STAR_NO_TAG;
        case AWRTC_MBEDTLS_MODE_CBC:
            if (taglen == 0) {
                return AWRTC_PSA_ALG_CBC_NO_PADDING;
            } else {
                return 0;
            }
        default:
            return 0;
    }
}
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

void awrtc_mbedtls_cipher_init(awrtc_mbedtls_cipher_context_t *ctx)
{
    memset(ctx, 0, sizeof(awrtc_mbedtls_cipher_context_t));
}

void awrtc_mbedtls_cipher_free(awrtc_mbedtls_cipher_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->awrtc_psa_enabled == 1) {
        if (ctx->cipher_ctx != NULL) {
            awrtc_mbedtls_cipher_context_psa * const cipher_psa =
                (awrtc_mbedtls_cipher_context_psa *) ctx->cipher_ctx;

            if (cipher_psa->slot_state == AWRTC_MBEDTLS_CIPHER_PSA_KEY_OWNED) {
                /* xxx_free() doesn't allow to return failures. */
                (void) awrtc_psa_destroy_key(cipher_psa->slot);
            }

            awrtc_mbedtls_zeroize_and_free(cipher_psa, sizeof(*cipher_psa));
        }

        awrtc_mbedtls_platform_zeroize(ctx, sizeof(awrtc_mbedtls_cipher_context_t));
        return;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

#if defined(AWRTC_MBEDTLS_CMAC_C)
    if (ctx->cmac_ctx) {
        awrtc_mbedtls_zeroize_and_free(ctx->cmac_ctx,
                                 sizeof(awrtc_mbedtls_cmac_context_t));
    }
#endif

    if (ctx->cipher_ctx) {
        awrtc_mbedtls_cipher_get_base(ctx->cipher_info)->ctx_free_func(ctx->cipher_ctx);
    }

    awrtc_mbedtls_platform_zeroize(ctx, sizeof(awrtc_mbedtls_cipher_context_t));
}

int awrtc_mbedtls_cipher_setup(awrtc_mbedtls_cipher_context_t *ctx,
                         const awrtc_mbedtls_cipher_info_t *cipher_info)
{
    if (cipher_info == NULL) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    memset(ctx, 0, sizeof(awrtc_mbedtls_cipher_context_t));

    if (awrtc_mbedtls_cipher_get_base(cipher_info)->ctx_alloc_func != NULL) {
        ctx->cipher_ctx = awrtc_mbedtls_cipher_get_base(cipher_info)->ctx_alloc_func();
        if (ctx->cipher_ctx == NULL) {
            return AWRTC_MBEDTLS_ERR_CIPHER_ALLOC_FAILED;
        }
    }

    ctx->cipher_info = cipher_info;

    return 0;
}

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
int awrtc_mbedtls_cipher_setup_psa(awrtc_mbedtls_cipher_context_t *ctx,
                             const awrtc_mbedtls_cipher_info_t *cipher_info,
                             size_t taglen)
{
    awrtc_psa_algorithm_t alg;
    awrtc_mbedtls_cipher_context_psa *cipher_psa;

    if (NULL == cipher_info || NULL == ctx) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    /* Check that the underlying cipher mode and cipher type are
     * supported by the underlying PSA Crypto implementation. */
    alg = awrtc_mbedtls_psa_translate_cipher_mode(((awrtc_mbedtls_cipher_mode_t) cipher_info->mode), taglen);
    if (alg == 0) {
        return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
    if (awrtc_mbedtls_psa_translate_cipher_type(((awrtc_mbedtls_cipher_type_t) cipher_info->type)) == 0) {
        return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }

    memset(ctx, 0, sizeof(awrtc_mbedtls_cipher_context_t));

    cipher_psa = awrtc_mbedtls_calloc(1, sizeof(awrtc_mbedtls_cipher_context_psa));
    if (cipher_psa == NULL) {
        return AWRTC_MBEDTLS_ERR_CIPHER_ALLOC_FAILED;
    }
    cipher_psa->alg  = alg;
    ctx->cipher_ctx  = cipher_psa;
    ctx->cipher_info = cipher_info;
    ctx->awrtc_psa_enabled = 1;
    return 0;
}
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

int awrtc_mbedtls_cipher_setkey(awrtc_mbedtls_cipher_context_t *ctx,
                          const unsigned char *key,
                          int key_bitlen,
                          const awrtc_mbedtls_operation_t operation)
{
    if (operation != AWRTC_MBEDTLS_ENCRYPT && operation != AWRTC_MBEDTLS_DECRYPT) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    if (ctx->cipher_info == NULL) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    if (AWRTC_MBEDTLS_MODE_ECB == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) &&
        AWRTC_MBEDTLS_DECRYPT == operation) {
        return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->awrtc_psa_enabled == 1) {
        awrtc_mbedtls_cipher_context_psa * const cipher_psa =
            (awrtc_mbedtls_cipher_context_psa *) ctx->cipher_ctx;

        size_t const key_bytelen = ((size_t) key_bitlen + 7) / 8;

        awrtc_psa_status_t status;
        awrtc_psa_key_type_t key_type;
        awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;

        /* PSA Crypto API only accepts byte-aligned keys. */
        if (key_bitlen % 8 != 0) {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        /* Don't allow keys to be set multiple times. */
        if (cipher_psa->slot_state != AWRTC_MBEDTLS_CIPHER_PSA_KEY_UNSET) {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        key_type = awrtc_mbedtls_psa_translate_cipher_type(
            ((awrtc_mbedtls_cipher_type_t) ctx->cipher_info->type));
        if (key_type == 0) {
            return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        }
        awrtc_psa_set_key_type(&attributes, key_type);

        /* Mbed TLS' cipher layer doesn't enforce the mode of operation
         * (encrypt vs. decrypt): it is possible to setup a key for encryption
         * and use it for AEAD decryption. Until tests relying on this
         * are changed, allow any usage in PSA. */
        awrtc_psa_set_key_usage_flags(&attributes,
                                AWRTC_PSA_KEY_USAGE_ENCRYPT | AWRTC_PSA_KEY_USAGE_DECRYPT);
        awrtc_psa_set_key_algorithm(&attributes, cipher_psa->alg);

        status = awrtc_psa_import_key(&attributes, key, key_bytelen,
                                &cipher_psa->slot);
        switch (status) {
            case AWRTC_PSA_SUCCESS:
                break;
            case AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY:
                return AWRTC_MBEDTLS_ERR_CIPHER_ALLOC_FAILED;
            case AWRTC_PSA_ERROR_NOT_SUPPORTED:
                return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
            default:
                return AWRTC_MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }
        /* Indicate that we own the key slot and need to
         * destroy it in awrtc_mbedtls_cipher_free(). */
        cipher_psa->slot_state = AWRTC_MBEDTLS_CIPHER_PSA_KEY_OWNED;

        ctx->key_bitlen = key_bitlen;
        ctx->operation = operation;
        return 0;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

    if ((ctx->cipher_info->flags & AWRTC_MBEDTLS_CIPHER_VARIABLE_KEY_LEN) == 0 &&
        (int) awrtc_mbedtls_cipher_info_get_key_bitlen(ctx->cipher_info) != key_bitlen) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    ctx->key_bitlen = key_bitlen;
    ctx->operation = operation;

#if !defined(AWRTC_MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    /*
     * For OFB, CFB and CTR mode always use the encryption key schedule
     */
    if (AWRTC_MBEDTLS_ENCRYPT == operation ||
        AWRTC_MBEDTLS_MODE_CFB == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        AWRTC_MBEDTLS_MODE_OFB == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        AWRTC_MBEDTLS_MODE_CTR == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        return awrtc_mbedtls_cipher_get_base(ctx->cipher_info)->setkey_enc_func(ctx->cipher_ctx, key,
                                                                          ctx->key_bitlen);
    }

    if (AWRTC_MBEDTLS_DECRYPT == operation) {
        return awrtc_mbedtls_cipher_get_base(ctx->cipher_info)->setkey_dec_func(ctx->cipher_ctx, key,
                                                                          ctx->key_bitlen);
    }
#else
    if (operation == AWRTC_MBEDTLS_ENCRYPT || operation == AWRTC_MBEDTLS_DECRYPT) {
        return awrtc_mbedtls_cipher_get_base(ctx->cipher_info)->setkey_enc_func(ctx->cipher_ctx, key,
                                                                          ctx->key_bitlen);
    }
#endif

    return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
}

int awrtc_mbedtls_cipher_set_iv(awrtc_mbedtls_cipher_context_t *ctx,
                          const unsigned char *iv,
                          size_t iv_len)
{
    size_t actual_iv_size;

    if (ctx->cipher_info == NULL) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->awrtc_psa_enabled == 1) {
        /* While PSA Crypto has an API for multipart
         * operations, we currently don't make it
         * accessible through the cipher layer. */
        return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

    /* avoid buffer overflow in ctx->iv */
    if (iv_len > AWRTC_MBEDTLS_MAX_IV_LENGTH) {
        return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }

    if ((ctx->cipher_info->flags & AWRTC_MBEDTLS_CIPHER_VARIABLE_IV_LEN) != 0) {
        actual_iv_size = iv_len;
    } else {
        actual_iv_size = awrtc_mbedtls_cipher_info_get_iv_size(ctx->cipher_info);

        /* avoid reading past the end of input buffer */
        if (actual_iv_size > iv_len) {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }
    }

#if defined(AWRTC_MBEDTLS_CHACHA20_C)
    if (((awrtc_mbedtls_cipher_type_t) ctx->cipher_info->type) == AWRTC_MBEDTLS_CIPHER_CHACHA20) {
        /* Even though the actual_iv_size is overwritten with a correct value
         * of 12 from the cipher info, return an error to indicate that
         * the input iv_len is wrong. */
        if (iv_len != 12) {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        if (0 != awrtc_mbedtls_chacha20_starts((awrtc_mbedtls_chacha20_context *) ctx->cipher_ctx,
                                         iv,
                                         0U)) {   /* Initial counter value */
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }
    }
#if defined(AWRTC_MBEDTLS_CHACHAPOLY_C)
    if (((awrtc_mbedtls_cipher_type_t) ctx->cipher_info->type) == AWRTC_MBEDTLS_CIPHER_CHACHA20_POLY1305 &&
        iv_len != 12) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
#endif
#endif

#if defined(AWRTC_MBEDTLS_GCM_C)
    if (AWRTC_MBEDTLS_MODE_GCM == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        return awrtc_mbedtls_gcm_starts((awrtc_mbedtls_gcm_context *) ctx->cipher_ctx,
                                  ctx->operation,
                                  iv, iv_len);
    }
#endif

#if defined(AWRTC_MBEDTLS_CCM_C)
    if (AWRTC_MBEDTLS_MODE_CCM_STAR_NO_TAG == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        int set_lengths_result;
        int ccm_star_mode;

        set_lengths_result = awrtc_mbedtls_ccm_set_lengths(
            (awrtc_mbedtls_ccm_context *) ctx->cipher_ctx,
            0, 0, 0);
        if (set_lengths_result != 0) {
            return set_lengths_result;
        }

        if (ctx->operation == AWRTC_MBEDTLS_DECRYPT) {
            ccm_star_mode = AWRTC_MBEDTLS_CCM_STAR_DECRYPT;
        } else if (ctx->operation == AWRTC_MBEDTLS_ENCRYPT) {
            ccm_star_mode = AWRTC_MBEDTLS_CCM_STAR_ENCRYPT;
        } else {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        return awrtc_mbedtls_ccm_starts((awrtc_mbedtls_ccm_context *) ctx->cipher_ctx,
                                  ccm_star_mode,
                                  iv, iv_len);
    }
#endif

    if (actual_iv_size != 0) {
        memcpy(ctx->iv, iv, actual_iv_size);
        ctx->iv_size = actual_iv_size;
    }

    return 0;
}

int awrtc_mbedtls_cipher_reset(awrtc_mbedtls_cipher_context_t *ctx)
{
    if (ctx->cipher_info == NULL) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->awrtc_psa_enabled == 1) {
        /* We don't support resetting PSA-based
         * cipher contexts, yet. */
        return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

    ctx->unprocessed_len = 0;

    return 0;
}

#if defined(AWRTC_MBEDTLS_GCM_C) || defined(AWRTC_MBEDTLS_CHACHAPOLY_C)
int awrtc_mbedtls_cipher_update_ad(awrtc_mbedtls_cipher_context_t *ctx,
                             const unsigned char *ad, size_t ad_len)
{
    if (ctx->cipher_info == NULL) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->awrtc_psa_enabled == 1) {
        /* While PSA Crypto has an API for multipart
         * operations, we currently don't make it
         * accessible through the cipher layer. */
        return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

#if defined(AWRTC_MBEDTLS_GCM_C)
    if (AWRTC_MBEDTLS_MODE_GCM == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        return awrtc_mbedtls_gcm_update_ad((awrtc_mbedtls_gcm_context *) ctx->cipher_ctx,
                                     ad, ad_len);
    }
#endif

#if defined(AWRTC_MBEDTLS_CHACHAPOLY_C)
    if (AWRTC_MBEDTLS_CIPHER_CHACHA20_POLY1305 == ((awrtc_mbedtls_cipher_type_t) ctx->cipher_info->type)) {
        int result;
        awrtc_mbedtls_chachapoly_mode_t mode;

        mode = (ctx->operation == AWRTC_MBEDTLS_ENCRYPT)
                ? AWRTC_MBEDTLS_CHACHAPOLY_ENCRYPT
                : AWRTC_MBEDTLS_CHACHAPOLY_DECRYPT;

        result = awrtc_mbedtls_chachapoly_starts((awrtc_mbedtls_chachapoly_context *) ctx->cipher_ctx,
                                           ctx->iv,
                                           mode);
        if (result != 0) {
            return result;
        }

        return awrtc_mbedtls_chachapoly_update_aad((awrtc_mbedtls_chachapoly_context *) ctx->cipher_ctx,
                                             ad, ad_len);
    }
#endif

    return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}
#endif /* AWRTC_MBEDTLS_GCM_C || AWRTC_MBEDTLS_CHACHAPOLY_C */

int awrtc_mbedtls_cipher_update(awrtc_mbedtls_cipher_context_t *ctx, const unsigned char *input,
                          size_t ilen, unsigned char *output, size_t *olen)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t block_size;

    if (ctx->cipher_info == NULL) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->awrtc_psa_enabled == 1) {
        /* While PSA Crypto has an API for multipart
         * operations, we currently don't make it
         * accessible through the cipher layer. */
        return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

    *olen = 0;
    block_size = awrtc_mbedtls_cipher_get_block_size(ctx);
    if (0 == block_size) {
        return AWRTC_MBEDTLS_ERR_CIPHER_INVALID_CONTEXT;
    }

    if (((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) == AWRTC_MBEDTLS_MODE_ECB) {
        if (ilen != block_size) {
            return AWRTC_MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED;
        }

        *olen = ilen;

        if (0 != (ret = awrtc_mbedtls_cipher_get_base(ctx->cipher_info)->ecb_func(ctx->cipher_ctx,
                                                                            ctx->operation, input,
                                                                            output))) {
            return ret;
        }

        return 0;
    }

#if defined(AWRTC_MBEDTLS_GCM_C)
    if (((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) == AWRTC_MBEDTLS_MODE_GCM) {
        return awrtc_mbedtls_gcm_update((awrtc_mbedtls_gcm_context *) ctx->cipher_ctx,
                                  input, ilen,
                                  output, ilen, olen);
    }
#endif

#if defined(AWRTC_MBEDTLS_CCM_C)
    if (((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) == AWRTC_MBEDTLS_MODE_CCM_STAR_NO_TAG) {
        return awrtc_mbedtls_ccm_update((awrtc_mbedtls_ccm_context *) ctx->cipher_ctx,
                                  input, ilen,
                                  output, ilen, olen);
    }
#endif

#if defined(AWRTC_MBEDTLS_CHACHAPOLY_C)
    if (((awrtc_mbedtls_cipher_type_t) ctx->cipher_info->type) == AWRTC_MBEDTLS_CIPHER_CHACHA20_POLY1305) {
        *olen = ilen;
        return awrtc_mbedtls_chachapoly_update((awrtc_mbedtls_chachapoly_context *) ctx->cipher_ctx,
                                         ilen, input, output);
    }
#endif

    if (input == output &&
        (ctx->unprocessed_len != 0 || ilen % block_size)) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_CBC)
    if (((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) == AWRTC_MBEDTLS_MODE_CBC) {
        size_t copy_len = 0;

        /*
         * If there is not enough data for a full block, cache it.
         */
        if ((ctx->operation == AWRTC_MBEDTLS_DECRYPT && NULL != ctx->add_padding &&
             ilen <= block_size - ctx->unprocessed_len) ||
            (ctx->operation == AWRTC_MBEDTLS_DECRYPT && NULL == ctx->add_padding &&
             ilen < block_size - ctx->unprocessed_len) ||
            (ctx->operation == AWRTC_MBEDTLS_ENCRYPT &&
             ilen < block_size - ctx->unprocessed_len)) {
            memcpy(&(ctx->unprocessed_data[ctx->unprocessed_len]), input,
                   ilen);

            ctx->unprocessed_len += ilen;
            return 0;
        }

        /*
         * Process cached data first
         */
        if (0 != ctx->unprocessed_len) {
            copy_len = block_size - ctx->unprocessed_len;

            memcpy(&(ctx->unprocessed_data[ctx->unprocessed_len]), input,
                   copy_len);

            if (0 != (ret = awrtc_mbedtls_cipher_get_base(ctx->cipher_info)->cbc_func(ctx->cipher_ctx,
                                                                                ctx->operation,
                                                                                block_size, ctx->iv,
                                                                                ctx->
                                                                                unprocessed_data,
                                                                                output))) {
                return ret;
            }

            *olen += block_size;
            output += block_size;
            ctx->unprocessed_len = 0;

            input += copy_len;
            ilen -= copy_len;
        }

        /*
         * Cache final, incomplete block
         */
        if (0 != ilen) {
            /* Encryption: only cache partial blocks
             * Decryption w/ padding: always keep at least one whole block
             * Decryption w/o padding: only cache partial blocks
             */
            copy_len = ilen % block_size;
            if (copy_len == 0 &&
                ctx->operation == AWRTC_MBEDTLS_DECRYPT &&
                NULL != ctx->add_padding) {
                copy_len = block_size;
            }

            memcpy(ctx->unprocessed_data, &(input[ilen - copy_len]),
                   copy_len);

            ctx->unprocessed_len += copy_len;
            ilen -= copy_len;
        }

        /*
         * Process remaining full blocks
         */
        if (ilen) {
            if (0 != (ret = awrtc_mbedtls_cipher_get_base(ctx->cipher_info)->cbc_func(ctx->cipher_ctx,
                                                                                ctx->operation,
                                                                                ilen, ctx->iv,
                                                                                input,
                                                                                output))) {
                return ret;
            }

            *olen += ilen;
        }

        return 0;
    }
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_CBC */

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_CFB)
    if (((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) == AWRTC_MBEDTLS_MODE_CFB) {
        if (0 != (ret = awrtc_mbedtls_cipher_get_base(ctx->cipher_info)->cfb_func(ctx->cipher_ctx,
                                                                            ctx->operation, ilen,
                                                                            &ctx->unprocessed_len,
                                                                            ctx->iv,
                                                                            input, output))) {
            return ret;
        }

        *olen = ilen;

        return 0;
    }
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_CFB */

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_OFB)
    if (((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) == AWRTC_MBEDTLS_MODE_OFB) {
        if (0 != (ret = awrtc_mbedtls_cipher_get_base(ctx->cipher_info)->ofb_func(ctx->cipher_ctx,
                                                                            ilen,
                                                                            &ctx->unprocessed_len,
                                                                            ctx->iv,
                                                                            input, output))) {
            return ret;
        }

        *olen = ilen;

        return 0;
    }
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_OFB */

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_CTR)
    if (((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) == AWRTC_MBEDTLS_MODE_CTR) {
        if (0 != (ret = awrtc_mbedtls_cipher_get_base(ctx->cipher_info)->ctr_func(ctx->cipher_ctx,
                                                                            ilen,
                                                                            &ctx->unprocessed_len,
                                                                            ctx->iv,
                                                                            ctx->unprocessed_data,
                                                                            input, output))) {
            return ret;
        }

        *olen = ilen;

        return 0;
    }
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_CTR */

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_XTS)
    if (((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) == AWRTC_MBEDTLS_MODE_XTS) {
        if (ctx->unprocessed_len > 0) {
            /* We can only process an entire data unit at a time. */
            return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        }

        ret = awrtc_mbedtls_cipher_get_base(ctx->cipher_info)->xts_func(ctx->cipher_ctx,
                                                                  ctx->operation,
                                                                  ilen,
                                                                  ctx->iv,
                                                                  input,
                                                                  output);
        if (ret != 0) {
            return ret;
        }

        *olen = ilen;

        return 0;
    }
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_XTS */

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_STREAM)
    if (((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) == AWRTC_MBEDTLS_MODE_STREAM) {
        if (0 != (ret = awrtc_mbedtls_cipher_get_base(ctx->cipher_info)->stream_func(ctx->cipher_ctx,
                                                                               ilen, input,
                                                                               output))) {
            return ret;
        }

        *olen = ilen;

        return 0;
    }
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_STREAM */

    return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_WITH_PADDING)
#if defined(AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7)
/*
 * PKCS7 (and PKCS5) padding: fill with ll bytes, with ll = padding_len
 */
static void add_pkcs_padding(unsigned char *output, size_t output_len,
                             size_t data_len)
{
    size_t padding_len = output_len - data_len;
    unsigned char i;

    for (i = 0; i < padding_len; i++) {
        output[data_len + i] = (unsigned char) padding_len;
    }
}

/*
 * Get the length of the PKCS7 padding.
 *
 * Note: input_len must be the block size of the cipher.
 */
AWRTC_MBEDTLS_STATIC_TESTABLE int awrtc_mbedtls_get_pkcs_padding(unsigned char *input,
                                                     size_t input_len,
                                                     size_t *data_len,
                                                     size_t *invalid_padding)
{
    size_t i, pad_idx;
    unsigned char padding_len;

    if (NULL == input || NULL == data_len) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    padding_len = input[input_len - 1];

    awrtc_mbedtls_ct_condition_t bad = awrtc_mbedtls_ct_uint_gt(padding_len, input_len);
    bad = awrtc_mbedtls_ct_bool_or(bad, awrtc_mbedtls_ct_uint_eq(padding_len, 0));

    /* The number of bytes checked must be independent of padding_len,
     * so pick input_len, which is usually 8 or 16 (one block) */
    pad_idx = input_len - padding_len;
    for (i = 0; i < input_len; i++) {
        awrtc_mbedtls_ct_condition_t in_padding = awrtc_mbedtls_ct_uint_ge(i, pad_idx);
        awrtc_mbedtls_ct_condition_t different  = awrtc_mbedtls_ct_uint_ne(input[i], padding_len);
        bad = awrtc_mbedtls_ct_bool_or(bad, awrtc_mbedtls_ct_bool_and(in_padding, different));
    }

    /* If the padding is invalid, set the output length to 0 */
    *data_len = awrtc_mbedtls_ct_if(bad, 0, input_len - padding_len);

    *invalid_padding = awrtc_mbedtls_ct_size_if_else_0(bad, SIZE_MAX);
    return 0;
}
#endif /* AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7 */

#if defined(AWRTC_MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS)
/*
 * One and zeros padding: fill with 80 00 ... 00
 */
static void add_one_and_zeros_padding(unsigned char *output,
                                      size_t output_len, size_t data_len)
{
    size_t padding_len = output_len - data_len;
    unsigned char i = 0;

    output[data_len] = 0x80;
    for (i = 1; i < padding_len; i++) {
        output[data_len + i] = 0x00;
    }
}

static int get_one_and_zeros_padding(unsigned char *input, size_t input_len,
                                     size_t *data_len, size_t *invalid_padding)
{
    if (NULL == input || NULL == data_len) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    awrtc_mbedtls_ct_condition_t in_padding = AWRTC_MBEDTLS_CT_TRUE;
    awrtc_mbedtls_ct_condition_t bad = AWRTC_MBEDTLS_CT_TRUE;

    *data_len = 0;

    for (ptrdiff_t i = (ptrdiff_t) (input_len) - 1; i >= 0; i--) {
        awrtc_mbedtls_ct_condition_t is_nonzero = awrtc_mbedtls_ct_bool(input[i]);

        awrtc_mbedtls_ct_condition_t hit_first_nonzero = awrtc_mbedtls_ct_bool_and(is_nonzero, in_padding);

        *data_len = awrtc_mbedtls_ct_size_if(hit_first_nonzero, i, *data_len);

        bad = awrtc_mbedtls_ct_bool_if(hit_first_nonzero, awrtc_mbedtls_ct_uint_ne(input[i], 0x80), bad);

        in_padding = awrtc_mbedtls_ct_bool_and(in_padding, awrtc_mbedtls_ct_bool_not(is_nonzero));
    }

    *invalid_padding = awrtc_mbedtls_ct_size_if_else_0(bad, SIZE_MAX);
    return 0;
}
#endif /* AWRTC_MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS */

#if defined(AWRTC_MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN)
/*
 * Zeros and len padding: fill with 00 ... 00 ll, where ll is padding length
 */
static void add_zeros_and_len_padding(unsigned char *output,
                                      size_t output_len, size_t data_len)
{
    size_t padding_len = output_len - data_len;
    unsigned char i = 0;

    for (i = 1; i < padding_len; i++) {
        output[data_len + i - 1] = 0x00;
    }
    output[output_len - 1] = (unsigned char) padding_len;
}

static int get_zeros_and_len_padding(unsigned char *input, size_t input_len,
                                     size_t *data_len, size_t *invalid_padding)
{
    size_t i, pad_idx;
    unsigned char padding_len;
    awrtc_mbedtls_ct_condition_t bad;

    if (NULL == input || NULL == data_len) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    padding_len = input[input_len - 1];
    *data_len = input_len - padding_len;

    /* Avoid logical || since it results in a branch */
    bad = awrtc_mbedtls_ct_uint_gt(padding_len, input_len);
    bad = awrtc_mbedtls_ct_bool_or(bad, awrtc_mbedtls_ct_uint_eq(padding_len, 0));

    /* The number of bytes checked must be independent of padding_len */
    pad_idx = input_len - padding_len;
    for (i = 0; i < input_len - 1; i++) {
        awrtc_mbedtls_ct_condition_t is_padding = awrtc_mbedtls_ct_uint_ge(i, pad_idx);
        awrtc_mbedtls_ct_condition_t nonzero_pad_byte;
        nonzero_pad_byte = awrtc_mbedtls_ct_bool_if_else_0(is_padding, awrtc_mbedtls_ct_bool(input[i]));
        bad = awrtc_mbedtls_ct_bool_or(bad, nonzero_pad_byte);
    }

    *invalid_padding = awrtc_mbedtls_ct_size_if_else_0(bad, SIZE_MAX);
    return 0;
}
#endif /* AWRTC_MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN */

#if defined(AWRTC_MBEDTLS_CIPHER_PADDING_ZEROS)
/*
 * Zero padding: fill with 00 ... 00
 */
static void add_zeros_padding(unsigned char *output,
                              size_t output_len, size_t data_len)
{
    memset(output + data_len, 0, output_len - data_len);
}

static int get_zeros_padding(unsigned char *input, size_t input_len,
                             size_t *data_len, size_t *invalid_padding)
{
    size_t i;
    awrtc_mbedtls_ct_condition_t done = AWRTC_MBEDTLS_CT_FALSE, prev_done;

    if (NULL == input || NULL == data_len) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    *data_len = 0;
    for (i = input_len; i > 0; i--) {
        prev_done = done;
        done = awrtc_mbedtls_ct_bool_or(done, awrtc_mbedtls_ct_uint_ne(input[i-1], 0));
        *data_len = awrtc_mbedtls_ct_size_if(awrtc_mbedtls_ct_bool_ne(done, prev_done), i, *data_len);
    }

    *invalid_padding = 0;
    return 0;
}
#endif /* AWRTC_MBEDTLS_CIPHER_PADDING_ZEROS */

/*
 * No padding: don't pad :)
 *
 * There is no add_padding function (check for NULL in awrtc_mbedtls_cipher_finish)
 * but a trivial get_padding function
 */
static int get_no_padding(unsigned char *input, size_t input_len,
                          size_t *data_len, size_t *invalid_padding)
{
    if (NULL == input || NULL == data_len) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    *data_len = input_len;
    *invalid_padding = 0;
    return 0;
}
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_WITH_PADDING */

int awrtc_mbedtls_cipher_finish_padded(awrtc_mbedtls_cipher_context_t *ctx,
                                 unsigned char *output, size_t *olen,
                                 size_t *invalid_padding)
{
    if (ctx->cipher_info == NULL) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->awrtc_psa_enabled == 1) {
        /* While PSA Crypto has an API for multipart
         * operations, we currently don't make it
         * accessible through the cipher layer. */
        return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

    *olen = 0;
    *invalid_padding = 0;

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_WITH_PADDING)
    /* CBC mode requires padding so we make sure a call to
     * awrtc_mbedtls_cipher_set_padding_mode has been done successfully. */
    if (AWRTC_MBEDTLS_MODE_CBC == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        if (ctx->get_padding == NULL) {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }
    }
#endif

    if (AWRTC_MBEDTLS_MODE_CFB == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        AWRTC_MBEDTLS_MODE_OFB == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        AWRTC_MBEDTLS_MODE_CTR == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        AWRTC_MBEDTLS_MODE_GCM == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        AWRTC_MBEDTLS_MODE_CCM_STAR_NO_TAG == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        AWRTC_MBEDTLS_MODE_XTS == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        AWRTC_MBEDTLS_MODE_STREAM == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        return 0;
    }

    if ((AWRTC_MBEDTLS_CIPHER_CHACHA20          == ((awrtc_mbedtls_cipher_type_t) ctx->cipher_info->type)) ||
        (AWRTC_MBEDTLS_CIPHER_CHACHA20_POLY1305 == ((awrtc_mbedtls_cipher_type_t) ctx->cipher_info->type))) {
        return 0;
    }

    if (AWRTC_MBEDTLS_MODE_ECB == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        if (ctx->unprocessed_len != 0) {
            return AWRTC_MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED;
        }

        return 0;
    }

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_CBC)
    if (AWRTC_MBEDTLS_MODE_CBC == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        int ret = 0;

        if (AWRTC_MBEDTLS_ENCRYPT == ctx->operation) {
            /* check for 'no padding' mode */
            if (NULL == ctx->add_padding) {
                if (0 != ctx->unprocessed_len) {
                    return AWRTC_MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED;
                }

                return 0;
            }

            ctx->add_padding(ctx->unprocessed_data, awrtc_mbedtls_cipher_get_iv_size(ctx),
                             ctx->unprocessed_len);
        } else if (awrtc_mbedtls_cipher_get_block_size(ctx) != ctx->unprocessed_len) {
            /*
             * For decrypt operations, expect a full block,
             * or an empty block if no padding
             */
            if (NULL == ctx->add_padding && 0 == ctx->unprocessed_len) {
                return 0;
            }

            return AWRTC_MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED;
        }

        /* cipher block */
        if (0 != (ret = awrtc_mbedtls_cipher_get_base(ctx->cipher_info)->cbc_func(ctx->cipher_ctx,
                                                                            ctx->operation,
                                                                            awrtc_mbedtls_cipher_get_block_size(
                                                                                ctx),
                                                                            ctx->iv,
                                                                            ctx->unprocessed_data,
                                                                            output))) {
            return ret;
        }

        /* Set output size for decryption */
        if (AWRTC_MBEDTLS_DECRYPT == ctx->operation) {
            return ctx->get_padding(output, awrtc_mbedtls_cipher_get_block_size(ctx),
                                    olen, invalid_padding);
        }

        /* Set output size for encryption */
        *olen = awrtc_mbedtls_cipher_get_block_size(ctx);
        return 0;
    }
#else
    ((void) output);
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_CBC */

    return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

int awrtc_mbedtls_cipher_finish(awrtc_mbedtls_cipher_context_t *ctx,
                          unsigned char *output, size_t *olen)
{
    size_t invalid_padding = 0;
    int ret = awrtc_mbedtls_cipher_finish_padded(ctx, output, olen,
                                           &invalid_padding);
    if (ret == 0) {
        ret = awrtc_mbedtls_ct_error_if_else_0(invalid_padding,
                                         AWRTC_MBEDTLS_ERR_CIPHER_INVALID_PADDING);
    }
    return ret;
}

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_WITH_PADDING)
int awrtc_mbedtls_cipher_set_padding_mode(awrtc_mbedtls_cipher_context_t *ctx,
                                    awrtc_mbedtls_cipher_padding_t mode)
{
    if (NULL == ctx->cipher_info ||
        AWRTC_MBEDTLS_MODE_CBC != ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->awrtc_psa_enabled == 1) {
        /* While PSA Crypto knows about CBC padding
         * schemes, we currently don't make them
         * accessible through the cipher layer. */
        if (mode != AWRTC_MBEDTLS_PADDING_NONE) {
            return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        }

        return 0;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

    switch (mode) {
#if defined(AWRTC_MBEDTLS_CIPHER_PADDING_PKCS7)
        case AWRTC_MBEDTLS_PADDING_PKCS7:
            ctx->add_padding = add_pkcs_padding;
            ctx->get_padding = awrtc_mbedtls_get_pkcs_padding;
            break;
#endif
#if defined(AWRTC_MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS)
        case AWRTC_MBEDTLS_PADDING_ONE_AND_ZEROS:
            ctx->add_padding = add_one_and_zeros_padding;
            ctx->get_padding = get_one_and_zeros_padding;
            break;
#endif
#if defined(AWRTC_MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN)
        case AWRTC_MBEDTLS_PADDING_ZEROS_AND_LEN:
            ctx->add_padding = add_zeros_and_len_padding;
            ctx->get_padding = get_zeros_and_len_padding;
            break;
#endif
#if defined(AWRTC_MBEDTLS_CIPHER_PADDING_ZEROS)
        case AWRTC_MBEDTLS_PADDING_ZEROS:
            ctx->add_padding = add_zeros_padding;
            ctx->get_padding = get_zeros_padding;
            break;
#endif
        case AWRTC_MBEDTLS_PADDING_NONE:
            ctx->add_padding = NULL;
            ctx->get_padding = get_no_padding;
            break;

        default:
            return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }

    return 0;
}
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_WITH_PADDING */

#if defined(AWRTC_MBEDTLS_GCM_C) || defined(AWRTC_MBEDTLS_CHACHAPOLY_C)
int awrtc_mbedtls_cipher_write_tag(awrtc_mbedtls_cipher_context_t *ctx,
                             unsigned char *tag, size_t tag_len)
{
    if (ctx->cipher_info == NULL) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    if (AWRTC_MBEDTLS_ENCRYPT != ctx->operation) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->awrtc_psa_enabled == 1) {
        /* While PSA Crypto has an API for multipart
         * operations, we currently don't make it
         * accessible through the cipher layer. */
        return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

#if defined(AWRTC_MBEDTLS_GCM_C)
    if (AWRTC_MBEDTLS_MODE_GCM == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        size_t output_length;
        /* The code here doesn't yet support alternative implementations
         * that can delay up to a block of output. */
        return awrtc_mbedtls_gcm_finish((awrtc_mbedtls_gcm_context *) ctx->cipher_ctx,
                                  NULL, 0, &output_length,
                                  tag, tag_len);
    }
#endif

#if defined(AWRTC_MBEDTLS_CHACHAPOLY_C)
    if (AWRTC_MBEDTLS_CIPHER_CHACHA20_POLY1305 == ((awrtc_mbedtls_cipher_type_t) ctx->cipher_info->type)) {
        /* Don't allow truncated MAC for Poly1305 */
        if (tag_len != 16U) {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        return awrtc_mbedtls_chachapoly_finish(
            (awrtc_mbedtls_chachapoly_context *) ctx->cipher_ctx, tag);
    }
#endif

    return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

int awrtc_mbedtls_cipher_check_tag(awrtc_mbedtls_cipher_context_t *ctx,
                             const unsigned char *tag, size_t tag_len)
{
    unsigned char check_tag[16];
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (ctx->cipher_info == NULL) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    if (AWRTC_MBEDTLS_DECRYPT != ctx->operation) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->awrtc_psa_enabled == 1) {
        /* While PSA Crypto has an API for multipart
         * operations, we currently don't make it
         * accessible through the cipher layer. */
        return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

    /* Status to return on a non-authenticated algorithm. */
    ret = AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;

#if defined(AWRTC_MBEDTLS_GCM_C)
    if (AWRTC_MBEDTLS_MODE_GCM == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        size_t output_length;
        /* The code here doesn't yet support alternative implementations
         * that can delay up to a block of output. */

        if (tag_len > sizeof(check_tag)) {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        if (0 != (ret = awrtc_mbedtls_gcm_finish(
                      (awrtc_mbedtls_gcm_context *) ctx->cipher_ctx,
                      NULL, 0, &output_length,
                      check_tag, tag_len))) {
            return ret;
        }

        /* Check the tag in "constant-time" */
        if (awrtc_mbedtls_ct_memcmp(tag, check_tag, tag_len) != 0) {
            ret = AWRTC_MBEDTLS_ERR_CIPHER_AUTH_FAILED;
            goto exit;
        }
    }
#endif /* AWRTC_MBEDTLS_GCM_C */

#if defined(AWRTC_MBEDTLS_CHACHAPOLY_C)
    if (AWRTC_MBEDTLS_CIPHER_CHACHA20_POLY1305 == ((awrtc_mbedtls_cipher_type_t) ctx->cipher_info->type)) {
        /* Don't allow truncated MAC for Poly1305 */
        if (tag_len != sizeof(check_tag)) {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        ret = awrtc_mbedtls_chachapoly_finish(
            (awrtc_mbedtls_chachapoly_context *) ctx->cipher_ctx, check_tag);
        if (ret != 0) {
            return ret;
        }

        /* Check the tag in "constant-time" */
        if (awrtc_mbedtls_ct_memcmp(tag, check_tag, tag_len) != 0) {
            ret = AWRTC_MBEDTLS_ERR_CIPHER_AUTH_FAILED;
            goto exit;
        }
    }
#endif /* AWRTC_MBEDTLS_CHACHAPOLY_C */

exit:
    awrtc_mbedtls_platform_zeroize(check_tag, tag_len);
    return ret;
}
#endif /* AWRTC_MBEDTLS_GCM_C || AWRTC_MBEDTLS_CHACHAPOLY_C */

/*
 * Packet-oriented wrapper for non-AEAD modes
 */
int awrtc_mbedtls_cipher_crypt(awrtc_mbedtls_cipher_context_t *ctx,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t finish_olen;

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->awrtc_psa_enabled == 1) {
        /* As in the non-PSA case, we don't check that
         * a key has been set. If not, the key slot will
         * still be in its default state of 0, which is
         * guaranteed to be invalid, hence the PSA-call
         * below will gracefully fail. */
        awrtc_mbedtls_cipher_context_psa * const cipher_psa =
            (awrtc_mbedtls_cipher_context_psa *) ctx->cipher_ctx;

        awrtc_psa_status_t status;
        awrtc_psa_cipher_operation_t cipher_op = AWRTC_PSA_CIPHER_OPERATION_INIT;
        size_t part_len;

        if (ctx->operation == AWRTC_MBEDTLS_DECRYPT) {
            status = awrtc_psa_cipher_decrypt_setup(&cipher_op,
                                              cipher_psa->slot,
                                              cipher_psa->alg);
        } else if (ctx->operation == AWRTC_MBEDTLS_ENCRYPT) {
            status = awrtc_psa_cipher_encrypt_setup(&cipher_op,
                                              cipher_psa->slot,
                                              cipher_psa->alg);
        } else {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        /* In the following, we can immediately return on an error,
         * because the PSA Crypto API guarantees that cipher operations
         * are terminated by unsuccessful calls to awrtc_psa_cipher_update(),
         * and by any call to awrtc_psa_cipher_finish(). */
        if (status != AWRTC_PSA_SUCCESS) {
            return AWRTC_MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        if (((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) != AWRTC_MBEDTLS_MODE_ECB) {
            status = awrtc_psa_cipher_set_iv(&cipher_op, iv, iv_len);
            if (status != AWRTC_PSA_SUCCESS) {
                return AWRTC_MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
            }
        }

        status = awrtc_psa_cipher_update(&cipher_op,
                                   input, ilen,
                                   output, ilen, olen);
        if (status != AWRTC_PSA_SUCCESS) {
            return AWRTC_MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        status = awrtc_psa_cipher_finish(&cipher_op,
                                   output + *olen, ilen - *olen,
                                   &part_len);
        if (status != AWRTC_PSA_SUCCESS) {
            return AWRTC_MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        *olen += part_len;
        return 0;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

    if ((ret = awrtc_mbedtls_cipher_set_iv(ctx, iv, iv_len)) != 0) {
        return ret;
    }

    if ((ret = awrtc_mbedtls_cipher_reset(ctx)) != 0) {
        return ret;
    }

    if ((ret = awrtc_mbedtls_cipher_update(ctx, input, ilen,
                                     output, olen)) != 0) {
        return ret;
    }

    size_t invalid_padding = 0;
    if ((ret = awrtc_mbedtls_cipher_finish_padded(ctx, output + *olen,
                                            &finish_olen,
                                            &invalid_padding)) != 0) {
        return ret;
    }
    *olen += finish_olen;

    ret = awrtc_mbedtls_ct_error_if_else_0(invalid_padding,
                                     AWRTC_MBEDTLS_ERR_CIPHER_INVALID_PADDING);
    return ret;
}

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_AEAD)
/*
 * Packet-oriented encryption for AEAD modes: internal function used by
 * awrtc_mbedtls_cipher_auth_encrypt_ext().
 */
static int awrtc_mbedtls_cipher_aead_encrypt(awrtc_mbedtls_cipher_context_t *ctx,
                                       const unsigned char *iv, size_t iv_len,
                                       const unsigned char *ad, size_t ad_len,
                                       const unsigned char *input, size_t ilen,
                                       unsigned char *output, size_t *olen,
                                       unsigned char *tag, size_t tag_len)
{
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->awrtc_psa_enabled == 1) {
        /* As in the non-PSA case, we don't check that
         * a key has been set. If not, the key slot will
         * still be in its default state of 0, which is
         * guaranteed to be invalid, hence the PSA-call
         * below will gracefully fail. */
        awrtc_mbedtls_cipher_context_psa * const cipher_psa =
            (awrtc_mbedtls_cipher_context_psa *) ctx->cipher_ctx;

        awrtc_psa_status_t status;

        /* PSA Crypto API always writes the authentication tag
         * at the end of the encrypted message. */
        if (output == NULL || tag != output + ilen) {
            return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        }

        status = awrtc_psa_aead_encrypt(cipher_psa->slot,
                                  cipher_psa->alg,
                                  iv, iv_len,
                                  ad, ad_len,
                                  input, ilen,
                                  output, ilen + tag_len, olen);
        if (status != AWRTC_PSA_SUCCESS) {
            return AWRTC_MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        *olen -= tag_len;
        return 0;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

#if defined(AWRTC_MBEDTLS_GCM_C)
    if (AWRTC_MBEDTLS_MODE_GCM == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        *olen = ilen;
        return awrtc_mbedtls_gcm_crypt_and_tag(ctx->cipher_ctx, AWRTC_MBEDTLS_GCM_ENCRYPT,
                                         ilen, iv, iv_len, ad, ad_len,
                                         input, output, tag_len, tag);
    }
#endif /* AWRTC_MBEDTLS_GCM_C */
#if defined(AWRTC_MBEDTLS_CCM_C)
    if (AWRTC_MBEDTLS_MODE_CCM == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        *olen = ilen;
        return awrtc_mbedtls_ccm_encrypt_and_tag(ctx->cipher_ctx, ilen,
                                           iv, iv_len, ad, ad_len, input, output,
                                           tag, tag_len);
    }
#endif /* AWRTC_MBEDTLS_CCM_C */
#if defined(AWRTC_MBEDTLS_CHACHAPOLY_C)
    if (AWRTC_MBEDTLS_CIPHER_CHACHA20_POLY1305 == ((awrtc_mbedtls_cipher_type_t) ctx->cipher_info->type)) {
        /* ChachaPoly has fixed length nonce and MAC (tag) */
        if ((iv_len != awrtc_mbedtls_cipher_info_get_iv_size(ctx->cipher_info)) ||
            (tag_len != 16U)) {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        *olen = ilen;
        return awrtc_mbedtls_chachapoly_encrypt_and_tag(ctx->cipher_ctx,
                                                  ilen, iv, ad, ad_len, input, output, tag);
    }
#endif /* AWRTC_MBEDTLS_CHACHAPOLY_C */

    return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

/*
 * Packet-oriented encryption for AEAD modes: internal function used by
 * awrtc_mbedtls_cipher_auth_encrypt_ext().
 */
static int awrtc_mbedtls_cipher_aead_decrypt(awrtc_mbedtls_cipher_context_t *ctx,
                                       const unsigned char *iv, size_t iv_len,
                                       const unsigned char *ad, size_t ad_len,
                                       const unsigned char *input, size_t ilen,
                                       unsigned char *output, size_t *olen,
                                       const unsigned char *tag, size_t tag_len)
{
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->awrtc_psa_enabled == 1) {
        /* As in the non-PSA case, we don't check that
         * a key has been set. If not, the key slot will
         * still be in its default state of 0, which is
         * guaranteed to be invalid, hence the PSA-call
         * below will gracefully fail. */
        awrtc_mbedtls_cipher_context_psa * const cipher_psa =
            (awrtc_mbedtls_cipher_context_psa *) ctx->cipher_ctx;

        awrtc_psa_status_t status;

        /* PSA Crypto API always writes the authentication tag
         * at the end of the encrypted message. */
        if (input == NULL || tag != input + ilen) {
            return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        }

        status = awrtc_psa_aead_decrypt(cipher_psa->slot,
                                  cipher_psa->alg,
                                  iv, iv_len,
                                  ad, ad_len,
                                  input, ilen + tag_len,
                                  output, ilen, olen);
        if (status == AWRTC_PSA_ERROR_INVALID_SIGNATURE) {
            return AWRTC_MBEDTLS_ERR_CIPHER_AUTH_FAILED;
        } else if (status != AWRTC_PSA_SUCCESS) {
            return AWRTC_MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        return 0;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO && !AWRTC_MBEDTLS_DEPRECATED_REMOVED */

#if defined(AWRTC_MBEDTLS_GCM_C)
    if (AWRTC_MBEDTLS_MODE_GCM == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        *olen = ilen;
        ret = awrtc_mbedtls_gcm_auth_decrypt(ctx->cipher_ctx, ilen,
                                       iv, iv_len, ad, ad_len,
                                       tag, tag_len, input, output);

        if (ret == AWRTC_MBEDTLS_ERR_GCM_AUTH_FAILED) {
            ret = AWRTC_MBEDTLS_ERR_CIPHER_AUTH_FAILED;
        }

        return ret;
    }
#endif /* AWRTC_MBEDTLS_GCM_C */
#if defined(AWRTC_MBEDTLS_CCM_C)
    if (AWRTC_MBEDTLS_MODE_CCM == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        *olen = ilen;
        ret = awrtc_mbedtls_ccm_auth_decrypt(ctx->cipher_ctx, ilen,
                                       iv, iv_len, ad, ad_len,
                                       input, output, tag, tag_len);

        if (ret == AWRTC_MBEDTLS_ERR_CCM_AUTH_FAILED) {
            ret = AWRTC_MBEDTLS_ERR_CIPHER_AUTH_FAILED;
        }

        return ret;
    }
#endif /* AWRTC_MBEDTLS_CCM_C */
#if defined(AWRTC_MBEDTLS_CHACHAPOLY_C)
    if (AWRTC_MBEDTLS_CIPHER_CHACHA20_POLY1305 == ((awrtc_mbedtls_cipher_type_t) ctx->cipher_info->type)) {
        int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        /* ChachaPoly has fixed length nonce and MAC (tag) */
        if ((iv_len != awrtc_mbedtls_cipher_info_get_iv_size(ctx->cipher_info)) ||
            (tag_len != 16U)) {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        *olen = ilen;
        ret = awrtc_mbedtls_chachapoly_auth_decrypt(ctx->cipher_ctx, ilen,
                                              iv, ad, ad_len, tag, input, output);

        if (ret == AWRTC_MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED) {
            ret = AWRTC_MBEDTLS_ERR_CIPHER_AUTH_FAILED;
        }

        return ret;
    }
#endif /* AWRTC_MBEDTLS_CHACHAPOLY_C */

    return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_AEAD */

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_AEAD) || defined(AWRTC_MBEDTLS_NIST_KW_C)
/*
 * Packet-oriented encryption for AEAD/NIST_KW: public function.
 */
int awrtc_mbedtls_cipher_auth_encrypt_ext(awrtc_mbedtls_cipher_context_t *ctx,
                                    const unsigned char *iv, size_t iv_len,
                                    const unsigned char *ad, size_t ad_len,
                                    const unsigned char *input, size_t ilen,
                                    unsigned char *output, size_t output_len,
                                    size_t *olen, size_t tag_len)
{
#if defined(AWRTC_MBEDTLS_NIST_KW_C)
    if (
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
        ctx->awrtc_psa_enabled == 0 &&
#endif
        (AWRTC_MBEDTLS_MODE_KW == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
         AWRTC_MBEDTLS_MODE_KWP == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode))) {
        awrtc_mbedtls_nist_kw_mode_t mode =
            (AWRTC_MBEDTLS_MODE_KW == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) ?
            AWRTC_MBEDTLS_KW_MODE_KW : AWRTC_MBEDTLS_KW_MODE_KWP;

        /* There is no iv, tag or ad associated with KW and KWP,
         * so these length should be 0 as documented. */
        if (iv_len != 0 || tag_len != 0 || ad_len != 0) {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        (void) iv;
        (void) ad;

        return awrtc_mbedtls_nist_kw_wrap(ctx->cipher_ctx, mode, input, ilen,
                                    output, olen, output_len);
    }
#endif /* AWRTC_MBEDTLS_NIST_KW_C */

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_AEAD)
    /* AEAD case: check length before passing on to shared function */
    if (output_len < ilen + tag_len) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    int ret = awrtc_mbedtls_cipher_aead_encrypt(ctx, iv, iv_len, ad, ad_len,
                                          input, ilen, output, olen,
                                          output + ilen, tag_len);
    *olen += tag_len;
    return ret;
#else
    return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_AEAD */
}

/*
 * Packet-oriented decryption for AEAD/NIST_KW: public function.
 */
int awrtc_mbedtls_cipher_auth_decrypt_ext(awrtc_mbedtls_cipher_context_t *ctx,
                                    const unsigned char *iv, size_t iv_len,
                                    const unsigned char *ad, size_t ad_len,
                                    const unsigned char *input, size_t ilen,
                                    unsigned char *output, size_t output_len,
                                    size_t *olen, size_t tag_len)
{
#if defined(AWRTC_MBEDTLS_NIST_KW_C)
    if (
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && !defined(AWRTC_MBEDTLS_DEPRECATED_REMOVED)
        ctx->awrtc_psa_enabled == 0 &&
#endif
        (AWRTC_MBEDTLS_MODE_KW == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
         AWRTC_MBEDTLS_MODE_KWP == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode))) {
        awrtc_mbedtls_nist_kw_mode_t mode =
            (AWRTC_MBEDTLS_MODE_KW == ((awrtc_mbedtls_cipher_mode_t) ctx->cipher_info->mode)) ?
            AWRTC_MBEDTLS_KW_MODE_KW : AWRTC_MBEDTLS_KW_MODE_KWP;

        /* There is no iv, tag or ad associated with KW and KWP,
         * so these length should be 0 as documented. */
        if (iv_len != 0 || tag_len != 0 || ad_len != 0) {
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        (void) iv;
        (void) ad;

        return awrtc_mbedtls_nist_kw_unwrap(ctx->cipher_ctx, mode, input, ilen,
                                      output, olen, output_len);
    }
#endif /* AWRTC_MBEDTLS_NIST_KW_C */

#if defined(AWRTC_MBEDTLS_CIPHER_MODE_AEAD)
    /* AEAD case: check length before passing on to shared function */
    if (ilen < tag_len || output_len < ilen - tag_len) {
        return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    return awrtc_mbedtls_cipher_aead_decrypt(ctx, iv, iv_len, ad, ad_len,
                                       input, ilen - tag_len, output, olen,
                                       input + ilen - tag_len, tag_len);
#else
    return AWRTC_MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_AEAD */
}
#endif /* AWRTC_MBEDTLS_CIPHER_MODE_AEAD || AWRTC_MBEDTLS_NIST_KW_C */

#endif /* AWRTC_MBEDTLS_CIPHER_C */
