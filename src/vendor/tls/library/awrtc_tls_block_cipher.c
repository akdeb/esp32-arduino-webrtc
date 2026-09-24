/**
 * \file block_cipher.c
 *
 * \brief Lightweight abstraction layer for block ciphers with 128 bit blocks,
 * for use by the GCM and CCM modules.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
#include "../include/psa/crypto.h"
#include "psa_crypto_core.h"
#include "psa_util_internal.h"
#endif

#include "block_cipher_internal.h"

#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_C)

#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
static awrtc_psa_key_type_t awrtc_psa_key_type_from_block_cipher_id(awrtc_mbedtls_block_cipher_id_t cipher_id)
{
    switch (cipher_id) {
#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_AES_VIA_PSA)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_AES:
            return AWRTC_PSA_KEY_TYPE_AES;
#endif
#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_ARIA_VIA_PSA)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_ARIA:
            return AWRTC_PSA_KEY_TYPE_ARIA;
#endif
#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_CAMELLIA_VIA_PSA)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA:
            return AWRTC_PSA_KEY_TYPE_CAMELLIA;
#endif
        default:
            return AWRTC_PSA_KEY_TYPE_NONE;
    }
}

static int awrtc_mbedtls_cipher_error_from_psa(awrtc_psa_status_t status)
{
    return AWRTC_PSA_TO_MBEDTLS_ERR_LIST(status, awrtc_psa_to_cipher_errors,
                                   awrtc_psa_generic_status_to_mbedtls);
}
#endif /* AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA */

void awrtc_mbedtls_block_cipher_free(awrtc_mbedtls_block_cipher_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
    if (ctx->engine == AWRTC_MBEDTLS_BLOCK_CIPHER_ENGINE_PSA) {
        awrtc_psa_destroy_key(ctx->awrtc_psa_key_id);
        return;
    }
#endif
    switch (ctx->id) {
#if defined(AWRTC_MBEDTLS_AES_C)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_AES:
            awrtc_mbedtls_aes_free(&ctx->ctx.aes);
            break;
#endif
#if defined(AWRTC_MBEDTLS_ARIA_C)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_ARIA:
            awrtc_mbedtls_aria_free(&ctx->ctx.aria);
            break;
#endif
#if defined(AWRTC_MBEDTLS_CAMELLIA_C)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA:
            awrtc_mbedtls_camellia_free(&ctx->ctx.camellia);
            break;
#endif
        default:
            break;
    }
    ctx->id = AWRTC_MBEDTLS_BLOCK_CIPHER_ID_NONE;
}

int awrtc_mbedtls_block_cipher_setup(awrtc_mbedtls_block_cipher_context_t *ctx,
                               awrtc_mbedtls_cipher_id_t cipher_id)
{
    ctx->id = (cipher_id == AWRTC_MBEDTLS_CIPHER_ID_AES) ? AWRTC_MBEDTLS_BLOCK_CIPHER_ID_AES :
              (cipher_id == AWRTC_MBEDTLS_CIPHER_ID_ARIA) ? AWRTC_MBEDTLS_BLOCK_CIPHER_ID_ARIA :
              (cipher_id == AWRTC_MBEDTLS_CIPHER_ID_CAMELLIA) ? AWRTC_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA :
              AWRTC_MBEDTLS_BLOCK_CIPHER_ID_NONE;

#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
    awrtc_psa_key_type_t awrtc_psa_key_type = awrtc_psa_key_type_from_block_cipher_id(ctx->id);
    if (awrtc_psa_key_type != AWRTC_PSA_KEY_TYPE_NONE &&
        awrtc_psa_can_do_cipher(awrtc_psa_key_type, AWRTC_PSA_ALG_ECB_NO_PADDING)) {
        ctx->engine = AWRTC_MBEDTLS_BLOCK_CIPHER_ENGINE_PSA;
        return 0;
    }
    ctx->engine = AWRTC_MBEDTLS_BLOCK_CIPHER_ENGINE_LEGACY;
#endif

    switch (ctx->id) {
#if defined(AWRTC_MBEDTLS_AES_C)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_AES:
            awrtc_mbedtls_aes_init(&ctx->ctx.aes);
            return 0;
#endif
#if defined(AWRTC_MBEDTLS_ARIA_C)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_ARIA:
            awrtc_mbedtls_aria_init(&ctx->ctx.aria);
            return 0;
#endif
#if defined(AWRTC_MBEDTLS_CAMELLIA_C)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA:
            awrtc_mbedtls_camellia_init(&ctx->ctx.camellia);
            return 0;
#endif
        default:
            ctx->id = AWRTC_MBEDTLS_BLOCK_CIPHER_ID_NONE;
            return AWRTC_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
}

int awrtc_mbedtls_block_cipher_setkey(awrtc_mbedtls_block_cipher_context_t *ctx,
                                const unsigned char *key,
                                unsigned key_bitlen)
{
#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
    if (ctx->engine == AWRTC_MBEDTLS_BLOCK_CIPHER_ENGINE_PSA) {
        awrtc_psa_key_attributes_t key_attr = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
        awrtc_psa_status_t status;

        awrtc_psa_set_key_type(&key_attr, awrtc_psa_key_type_from_block_cipher_id(ctx->id));
        awrtc_psa_set_key_bits(&key_attr, key_bitlen);
        awrtc_psa_set_key_algorithm(&key_attr, AWRTC_PSA_ALG_ECB_NO_PADDING);
        awrtc_psa_set_key_usage_flags(&key_attr, AWRTC_PSA_KEY_USAGE_ENCRYPT);

        status = awrtc_psa_import_key(&key_attr, key, AWRTC_PSA_BITS_TO_BYTES(key_bitlen), &ctx->awrtc_psa_key_id);
        if (status != AWRTC_PSA_SUCCESS) {
            return awrtc_mbedtls_cipher_error_from_psa(status);
        }
        awrtc_psa_reset_key_attributes(&key_attr);

        return 0;
    }
#endif /* AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA */

    switch (ctx->id) {
#if defined(AWRTC_MBEDTLS_AES_C)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_AES:
            return awrtc_mbedtls_aes_setkey_enc(&ctx->ctx.aes, key, key_bitlen);
#endif
#if defined(AWRTC_MBEDTLS_ARIA_C)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_ARIA:
            return awrtc_mbedtls_aria_setkey_enc(&ctx->ctx.aria, key, key_bitlen);
#endif
#if defined(AWRTC_MBEDTLS_CAMELLIA_C)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA:
            return awrtc_mbedtls_camellia_setkey_enc(&ctx->ctx.camellia, key, key_bitlen);
#endif
        default:
            return AWRTC_MBEDTLS_ERR_CIPHER_INVALID_CONTEXT;
    }
}

int awrtc_mbedtls_block_cipher_encrypt(awrtc_mbedtls_block_cipher_context_t *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16])
{
#if defined(AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
    if (ctx->engine == AWRTC_MBEDTLS_BLOCK_CIPHER_ENGINE_PSA) {
        awrtc_psa_status_t status;
        size_t olen;

        status = awrtc_psa_cipher_encrypt(ctx->awrtc_psa_key_id, AWRTC_PSA_ALG_ECB_NO_PADDING,
                                    input, 16, output, 16, &olen);
        if (status != AWRTC_PSA_SUCCESS) {
            return awrtc_mbedtls_cipher_error_from_psa(status);
        }
        return 0;
    }
#endif /* AWRTC_MBEDTLS_BLOCK_CIPHER_SOME_PSA */

    switch (ctx->id) {
#if defined(AWRTC_MBEDTLS_AES_C)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_AES:
            return awrtc_mbedtls_aes_crypt_ecb(&ctx->ctx.aes, AWRTC_MBEDTLS_AES_ENCRYPT,
                                         input, output);
#endif
#if defined(AWRTC_MBEDTLS_ARIA_C)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_ARIA:
            return awrtc_mbedtls_aria_crypt_ecb(&ctx->ctx.aria, input, output);
#endif
#if defined(AWRTC_MBEDTLS_CAMELLIA_C)
        case AWRTC_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA:
            return awrtc_mbedtls_camellia_crypt_ecb(&ctx->ctx.camellia,
                                              AWRTC_MBEDTLS_CAMELLIA_ENCRYPT,
                                              input, output);
#endif
        default:
            return AWRTC_MBEDTLS_ERR_CIPHER_INVALID_CONTEXT;
    }
}

#endif /* AWRTC_MBEDTLS_BLOCK_CIPHER_C */
