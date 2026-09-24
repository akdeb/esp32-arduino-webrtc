/*
 *  TLS 1.3 key schedule
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_SSL_PROTO_TLS1_3)

#include <stdint.h>
#include <string.h>

#include "../include/mbedtls/hkdf.h"
#include "debug_internal.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/platform.h"

#include "ssl_misc.h"
#include "ssl_tls13_keys.h"
#include "ssl_tls13_invasive.h"

#include "../include/psa/crypto.h"
#include "../include/mbedtls/psa_util.h"

/* Define a local translating function to save code size by not using too many
 * arguments in each translating place. */
static int local_err_translation(awrtc_psa_status_t status)
{
    return awrtc_psa_status_to_mbedtls(status, awrtc_psa_to_ssl_errors,
                                 ARRAY_LENGTH(awrtc_psa_to_ssl_errors),
                                 awrtc_psa_generic_status_to_mbedtls);
}
#define AWRTC_PSA_TO_MBEDTLS_ERR(status) local_err_translation(status)

#define AWRTC_MBEDTLS_SSL_TLS1_3_LABEL(name, string)       \
    .name = string,

struct awrtc_mbedtls_ssl_tls13_labels_struct const awrtc_mbedtls_ssl_tls13_labels =
{
    /* This seems to work in C, despite the string literal being one
     * character too long due to the 0-termination. */
    AWRTC_MBEDTLS_SSL_TLS1_3_LABEL_LIST
};

#undef AWRTC_MBEDTLS_SSL_TLS1_3_LABEL

/*
 * This function creates a HkdfLabel structure used in the TLS 1.3 key schedule.
 *
 * The HkdfLabel is specified in RFC 8446 as follows:
 *
 * struct HkdfLabel {
 *   uint16 length;            // Length of expanded key material
 *   opaque label<7..255>;     // Always prefixed by "tls13 "
 *   opaque context<0..255>;   // Usually a communication transcript hash
 * };
 *
 * Parameters:
 * - desired_length: Length of expanded key material.
 *                   The length field can hold numbers up to 2**16, but HKDF
 *                   can only generate outputs of up to 255 * HASH_LEN bytes.
 *                   It is the caller's responsibility to ensure that this
 *                   limit is not exceeded. In TLS 1.3, SHA256 is the hash
 *                   function with the smallest block size, so a length
 *                   <= 255 * 32 = 8160 is always safe.
 * - (label, label_len): label + label length, without "tls13 " prefix
 *                       The label length MUST be less than or equal to
 *                       AWRTC_MBEDTLS_SSL_TLS1_3_HKDF_LABEL_MAX_LABEL_LEN.
 *                       It is the caller's responsibility to ensure this.
 *                       All (label, label length) pairs used in TLS 1.3
 *                       can be obtained via AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN().
 * - (ctx, ctx_len): context + context length
 *                   The context length MUST be less than or equal to
 *                   AWRTC_MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN
 *                   It is the caller's responsibility to ensure this.
 * - dst: Target buffer for HkdfLabel structure,
 *        This MUST be a writable buffer of size
 *        at least SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN Bytes.
 * - dst_len: Pointer at which to store the actual length of
 *            the HkdfLabel structure on success.
 */

/* We need to tell the compiler that we meant to leave out the null character. */
static const char tls13_label_prefix[6] AWRTC_MBEDTLS_ATTRIBUTE_UNTERMINATED_STRING = "tls13 ";

#define SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN(label_len, context_len) \
    (2                     /* expansion length           */ \
     + 1                   /* label length               */ \
     + label_len                                           \
     + 1                   /* context length             */ \
     + context_len)

#define SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN                      \
    SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN(                             \
        sizeof(tls13_label_prefix) +                       \
        AWRTC_MBEDTLS_SSL_TLS1_3_HKDF_LABEL_MAX_LABEL_LEN,       \
        AWRTC_MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN)

static void ssl_tls13_hkdf_encode_label(
    size_t desired_length,
    const unsigned char *label, size_t label_len,
    const unsigned char *ctx, size_t ctx_len,
    unsigned char *dst, size_t *dst_len)
{
    size_t total_label_len =
        sizeof(tls13_label_prefix) + label_len;
    size_t total_hkdf_lbl_len =
        SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN(total_label_len, ctx_len);

    unsigned char *p = dst;

    /* Add the size of the expanded key material. */
#if AWRTC_MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN > UINT16_MAX
#error "The desired key length must fit into an uint16 but \
    AWRTC_MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN is greater than UINT16_MAX"
#endif

    *p++ = AWRTC_MBEDTLS_BYTE_1(desired_length);
    *p++ = AWRTC_MBEDTLS_BYTE_0(desired_length);

    /* Add label incl. prefix */
    *p++ = AWRTC_MBEDTLS_BYTE_0(total_label_len);
    memcpy(p, tls13_label_prefix, sizeof(tls13_label_prefix));
    p += sizeof(tls13_label_prefix);
    memcpy(p, label, label_len);
    p += label_len;

    /* Add context value */
    *p++ = AWRTC_MBEDTLS_BYTE_0(ctx_len);
    if (ctx_len != 0) {
        memcpy(p, ctx, ctx_len);
    }

    /* Return total length to the caller.  */
    *dst_len = total_hkdf_lbl_len;
}

int awrtc_mbedtls_ssl_tls13_hkdf_expand_label(
    awrtc_psa_algorithm_t hash_alg,
    const unsigned char *secret, size_t secret_len,
    const unsigned char *label, size_t label_len,
    const unsigned char *ctx, size_t ctx_len,
    unsigned char *buf, size_t buf_len)
{
    unsigned char hkdf_label[SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN];
    size_t hkdf_label_len = 0;
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_status_t abort_status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_key_derivation_operation_t operation =
        AWRTC_PSA_KEY_DERIVATION_OPERATION_INIT;

    if (label_len > AWRTC_MBEDTLS_SSL_TLS1_3_HKDF_LABEL_MAX_LABEL_LEN) {
        /* Should never happen since this is an internal
         * function, and we know statically which labels
         * are allowed. */
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    if (ctx_len > AWRTC_MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN) {
        /* Should not happen, as above. */
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    if (buf_len > AWRTC_MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN) {
        /* Should not happen, as above. */
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    if (!AWRTC_PSA_ALG_IS_HASH(hash_alg)) {
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ssl_tls13_hkdf_encode_label(buf_len,
                                label, label_len,
                                ctx, ctx_len,
                                hkdf_label,
                                &hkdf_label_len);

    status = awrtc_psa_key_derivation_setup(&operation, AWRTC_PSA_ALG_HKDF_EXPAND(hash_alg));

    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

    status = awrtc_psa_key_derivation_input_bytes(&operation,
                                            AWRTC_PSA_KEY_DERIVATION_INPUT_SECRET,
                                            secret,
                                            secret_len);

    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

    status = awrtc_psa_key_derivation_input_bytes(&operation,
                                            AWRTC_PSA_KEY_DERIVATION_INPUT_INFO,
                                            hkdf_label,
                                            hkdf_label_len);

    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

    status = awrtc_psa_key_derivation_output_bytes(&operation,
                                             buf,
                                             buf_len);

    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

cleanup:
    abort_status = awrtc_psa_key_derivation_abort(&operation);
    status = (status == AWRTC_PSA_SUCCESS ? abort_status : status);
    awrtc_mbedtls_platform_zeroize(hkdf_label, hkdf_label_len);
    return AWRTC_PSA_TO_MBEDTLS_ERR(status);
}

AWRTC_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_make_traffic_key(
    awrtc_psa_algorithm_t hash_alg,
    const unsigned char *secret, size_t secret_len,
    unsigned char *key, size_t key_len,
    unsigned char *iv, size_t iv_len)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = awrtc_mbedtls_ssl_tls13_hkdf_expand_label(
        hash_alg,
        secret, secret_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(key),
        NULL, 0,
        key, key_len);
    if (ret != 0) {
        return ret;
    }

    ret = awrtc_mbedtls_ssl_tls13_hkdf_expand_label(
        hash_alg,
        secret, secret_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(iv),
        NULL, 0,
        iv, iv_len);
    return ret;
}

/*
 * The traffic keying material is generated from the following inputs:
 *
 *  - One secret value per sender.
 *  - A purpose value indicating the specific value being generated
 *  - The desired lengths of key and IV.
 *
 * The expansion itself is based on HKDF:
 *
 *   [sender]_write_key = HKDF-Expand-Label( Secret, "key", "", key_length )
 *   [sender]_write_iv  = HKDF-Expand-Label( Secret, "iv" , "", iv_length )
 *
 * [sender] denotes the sending side and the Secret value is provided
 * by the function caller. Note that we generate server and client side
 * keys in a single function call.
 */
int awrtc_mbedtls_ssl_tls13_make_traffic_keys(
    awrtc_psa_algorithm_t hash_alg,
    const unsigned char *client_secret,
    const unsigned char *server_secret, size_t secret_len,
    size_t key_len, size_t iv_len,
    awrtc_mbedtls_ssl_key_set *keys)
{
    int ret = 0;

    ret = ssl_tls13_make_traffic_key(
        hash_alg, client_secret, secret_len,
        keys->client_write_key, key_len,
        keys->client_write_iv, iv_len);
    if (ret != 0) {
        return ret;
    }

    ret = ssl_tls13_make_traffic_key(
        hash_alg, server_secret, secret_len,
        keys->server_write_key, key_len,
        keys->server_write_iv, iv_len);
    if (ret != 0) {
        return ret;
    }

    keys->key_len = key_len;
    keys->iv_len = iv_len;

    return 0;
}

int awrtc_mbedtls_ssl_tls13_derive_secret(
    awrtc_psa_algorithm_t hash_alg,
    const unsigned char *secret, size_t secret_len,
    const unsigned char *label, size_t label_len,
    const unsigned char *ctx, size_t ctx_len,
    int ctx_hashed,
    unsigned char *dstbuf, size_t dstbuf_len)
{
    int ret;
    unsigned char hashed_context[AWRTC_PSA_HASH_MAX_SIZE];
    if (ctx_hashed == AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED) {
        awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;

        status = awrtc_psa_hash_compute(hash_alg, ctx, ctx_len, hashed_context,
                                  AWRTC_PSA_HASH_LENGTH(hash_alg), &ctx_len);
        if (status != AWRTC_PSA_SUCCESS) {
            ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
            return ret;
        }
    } else {
        if (ctx_len > sizeof(hashed_context)) {
            /* This should never happen since this function is internal
             * and the code sets `ctx_hashed` correctly.
             * Let's double-check nonetheless to not run at the risk
             * of getting a stack overflow. */
            return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }

        memcpy(hashed_context, ctx, ctx_len);
    }

    return awrtc_mbedtls_ssl_tls13_hkdf_expand_label(hash_alg,
                                               secret, secret_len,
                                               label, label_len,
                                               hashed_context, ctx_len,
                                               dstbuf, dstbuf_len);

}

int awrtc_mbedtls_ssl_tls13_evolve_secret(
    awrtc_psa_algorithm_t hash_alg,
    const unsigned char *secret_old,
    const unsigned char *input, size_t input_len,
    unsigned char *secret_new)
{
    int ret = AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_status_t abort_status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    size_t hlen;
    unsigned char tmp_secret[AWRTC_PSA_MAC_MAX_SIZE] = { 0 };
    const unsigned char all_zeroes_input[AWRTC_MBEDTLS_TLS1_3_MD_MAX_SIZE] = { 0 };
    const unsigned char *l_input = NULL;
    size_t l_input_len;

    awrtc_psa_key_derivation_operation_t operation =
        AWRTC_PSA_KEY_DERIVATION_OPERATION_INIT;

    if (!AWRTC_PSA_ALG_IS_HASH(hash_alg)) {
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    hlen = AWRTC_PSA_HASH_LENGTH(hash_alg);

    /* For non-initial runs, call Derive-Secret( ., "derived", "")
     * on the old secret. */
    if (secret_old != NULL) {
        ret = awrtc_mbedtls_ssl_tls13_derive_secret(
            hash_alg,
            secret_old, hlen,
            AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(derived),
            NULL, 0,        /* context */
            AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
            tmp_secret, hlen);
        if (ret != 0) {
            goto cleanup;
        }
    }

    ret = 0;

    if (input != NULL && input_len != 0) {
        l_input = input;
        l_input_len = input_len;
    } else {
        l_input = all_zeroes_input;
        l_input_len = hlen;
    }

    status = awrtc_psa_key_derivation_setup(&operation,
                                      AWRTC_PSA_ALG_HKDF_EXTRACT(hash_alg));

    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

    status = awrtc_psa_key_derivation_input_bytes(&operation,
                                            AWRTC_PSA_KEY_DERIVATION_INPUT_SALT,
                                            tmp_secret,
                                            hlen);

    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

    status = awrtc_psa_key_derivation_input_bytes(&operation,
                                            AWRTC_PSA_KEY_DERIVATION_INPUT_SECRET,
                                            l_input, l_input_len);

    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

    status = awrtc_psa_key_derivation_output_bytes(&operation,
                                             secret_new,
                                             AWRTC_PSA_HASH_LENGTH(hash_alg));

    if (status != AWRTC_PSA_SUCCESS) {
        goto cleanup;
    }

cleanup:
    abort_status = awrtc_psa_key_derivation_abort(&operation);
    status = (status == AWRTC_PSA_SUCCESS ? abort_status : status);
    ret = (ret == 0 ? AWRTC_PSA_TO_MBEDTLS_ERR(status) : ret);
    awrtc_mbedtls_platform_zeroize(tmp_secret, sizeof(tmp_secret));
    return ret;
}

int awrtc_mbedtls_ssl_tls13_derive_early_secrets(
    awrtc_psa_algorithm_t hash_alg,
    unsigned char const *early_secret,
    unsigned char const *transcript, size_t transcript_len,
    awrtc_mbedtls_ssl_tls13_early_secrets *derived)
{
    int ret;
    size_t const hash_len = AWRTC_PSA_HASH_LENGTH(hash_alg);

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if (!AWRTC_PSA_ALG_IS_HASH(hash_alg)) {
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /*
     *            0
     *            |
     *            v
     *  PSK ->  HKDF-Extract = Early Secret
     *            |
     *            +-----> Derive-Secret(., "c e traffic", ClientHello)
     *            |                     = client_early_traffic_secret
     *            |
     *            +-----> Derive-Secret(., "e exp master", ClientHello)
     *            |                     = early_exporter_master_secret
     *            v
     */

    /* Create client_early_traffic_secret */
    ret = awrtc_mbedtls_ssl_tls13_derive_secret(
        hash_alg,
        early_secret, hash_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(c_e_traffic),
        transcript, transcript_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
        derived->client_early_traffic_secret,
        hash_len);
    if (ret != 0) {
        return ret;
    }

    /* Create early exporter */
    ret = awrtc_mbedtls_ssl_tls13_derive_secret(
        hash_alg,
        early_secret, hash_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(e_exp_master),
        transcript, transcript_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
        derived->early_exporter_master_secret,
        hash_len);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int awrtc_mbedtls_ssl_tls13_derive_handshake_secrets(
    awrtc_psa_algorithm_t hash_alg,
    unsigned char const *handshake_secret,
    unsigned char const *transcript, size_t transcript_len,
    awrtc_mbedtls_ssl_tls13_handshake_secrets *derived)
{
    int ret;
    size_t const hash_len = AWRTC_PSA_HASH_LENGTH(hash_alg);

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if (!AWRTC_PSA_ALG_IS_HASH(hash_alg)) {
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /*
     *
     * Handshake Secret
     * |
     * +-----> Derive-Secret( ., "c hs traffic",
     * |                     ClientHello...ServerHello )
     * |                     = client_handshake_traffic_secret
     * |
     * +-----> Derive-Secret( ., "s hs traffic",
     * |                     ClientHello...ServerHello )
     * |                     = server_handshake_traffic_secret
     *
     */

    /*
     * Compute client_handshake_traffic_secret with
     * Derive-Secret( ., "c hs traffic", ClientHello...ServerHello )
     */

    ret = awrtc_mbedtls_ssl_tls13_derive_secret(
        hash_alg,
        handshake_secret, hash_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(c_hs_traffic),
        transcript, transcript_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
        derived->client_handshake_traffic_secret,
        hash_len);
    if (ret != 0) {
        return ret;
    }

    /*
     * Compute server_handshake_traffic_secret with
     * Derive-Secret( ., "s hs traffic", ClientHello...ServerHello )
     */

    ret = awrtc_mbedtls_ssl_tls13_derive_secret(
        hash_alg,
        handshake_secret, hash_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(s_hs_traffic),
        transcript, transcript_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
        derived->server_handshake_traffic_secret,
        hash_len);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int awrtc_mbedtls_ssl_tls13_derive_application_secrets(
    awrtc_psa_algorithm_t hash_alg,
    unsigned char const *application_secret,
    unsigned char const *transcript, size_t transcript_len,
    awrtc_mbedtls_ssl_tls13_application_secrets *derived)
{
    int ret;
    size_t const hash_len = AWRTC_PSA_HASH_LENGTH(hash_alg);

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if (!AWRTC_PSA_ALG_IS_HASH(hash_alg)) {
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /* Generate {client,server}_application_traffic_secret_0
     *
     * Master Secret
     * |
     * +-----> Derive-Secret( ., "c ap traffic",
     * |                      ClientHello...server Finished )
     * |                      = client_application_traffic_secret_0
     * |
     * +-----> Derive-Secret( ., "s ap traffic",
     * |                      ClientHello...Server Finished )
     * |                      = server_application_traffic_secret_0
     * |
     * +-----> Derive-Secret( ., "exp master",
     * |                      ClientHello...server Finished)
     * |                      = exporter_master_secret
     *
     */

    ret = awrtc_mbedtls_ssl_tls13_derive_secret(
        hash_alg,
        application_secret, hash_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(c_ap_traffic),
        transcript, transcript_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
        derived->client_application_traffic_secret_N,
        hash_len);
    if (ret != 0) {
        return ret;
    }

    ret = awrtc_mbedtls_ssl_tls13_derive_secret(
        hash_alg,
        application_secret, hash_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(s_ap_traffic),
        transcript, transcript_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
        derived->server_application_traffic_secret_N,
        hash_len);
    if (ret != 0) {
        return ret;
    }

    ret = awrtc_mbedtls_ssl_tls13_derive_secret(
        hash_alg,
        application_secret, hash_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(exp_master),
        transcript, transcript_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
        derived->exporter_master_secret,
        hash_len);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

/* Generate resumption_master_secret for use with the ticket exchange.
 *
 * This is not integrated with awrtc_mbedtls_ssl_tls13_derive_application_secrets()
 * because it uses the transcript hash up to and including ClientFinished. */
int awrtc_mbedtls_ssl_tls13_derive_resumption_master_secret(
    awrtc_psa_algorithm_t hash_alg,
    unsigned char const *application_secret,
    unsigned char const *transcript, size_t transcript_len,
    awrtc_mbedtls_ssl_tls13_application_secrets *derived)
{
    int ret;
    size_t const hash_len = AWRTC_PSA_HASH_LENGTH(hash_alg);

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if (!AWRTC_PSA_ALG_IS_HASH(hash_alg)) {
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    ret = awrtc_mbedtls_ssl_tls13_derive_secret(
        hash_alg,
        application_secret, hash_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(res_master),
        transcript, transcript_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
        derived->resumption_master_secret,
        hash_len);

    if (ret != 0) {
        return ret;
    }

    return 0;
}

/**
 * \brief Transition into application stage of TLS 1.3 key schedule.
 *
 *        The TLS 1.3 key schedule can be viewed as a simple state machine
 *        with states Initial -> Early -> Handshake -> Application, and
 *        this function represents the Handshake -> Application transition.
 *
 *        In the handshake stage, ssl_tls13_generate_application_keys()
 *        can be used to derive the handshake traffic keys.
 *
 * \param ssl  The SSL context to operate on. This must be in key schedule
 *             stage \c Handshake.
 *
 * \returns    \c 0 on success.
 * \returns    A negative error code on failure.
 */
AWRTC_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_key_schedule_stage_application(awrtc_mbedtls_ssl_context *ssl)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    awrtc_psa_algorithm_t const hash_alg = awrtc_mbedtls_md_psa_alg_from_type(
        (awrtc_mbedtls_md_type_t) handshake->ciphersuite_info->mac);

    /*
     * Compute MasterSecret
     */
    ret = awrtc_mbedtls_ssl_tls13_evolve_secret(
        hash_alg,
        handshake->tls13_master_secrets.handshake,
        NULL, 0,
        handshake->tls13_master_secrets.app);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_tls13_evolve_secret", ret);
        return ret;
    }

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(
        4, "Master secret",
        handshake->tls13_master_secrets.app, AWRTC_PSA_HASH_LENGTH(hash_alg));

    return 0;
}

AWRTC_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_calc_finished_core(awrtc_psa_algorithm_t hash_alg,
                                        unsigned char const *base_key,
                                        unsigned char const *transcript,
                                        unsigned char *dst,
                                        size_t *dst_len)
{
    awrtc_mbedtls_svc_key_id_t key = AWRTC_MBEDTLS_SVC_KEY_ID_INIT;
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    size_t hash_len = AWRTC_PSA_HASH_LENGTH(hash_alg);
    unsigned char finished_key[AWRTC_PSA_MAC_MAX_SIZE];
    int ret;
    awrtc_psa_algorithm_t alg;

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if (!AWRTC_PSA_ALG_IS_HASH(hash_alg)) {
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /* TLS 1.3 Finished message
     *
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     *
     * verify_data =
     *     HMAC( finished_key,
     *            Hash( Handshake Context +
     *                  Certificate*      +
     *                  CertificateVerify* )
     *    )
     *
     * finished_key =
     *    HKDF-Expand-Label( BaseKey, "finished", "", Hash.length )
     */

    ret = awrtc_mbedtls_ssl_tls13_hkdf_expand_label(
        hash_alg, base_key, hash_len,
        AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(finished),
        NULL, 0,
        finished_key, hash_len);
    if (ret != 0) {
        goto exit;
    }

    alg = AWRTC_PSA_ALG_HMAC(hash_alg);
    awrtc_psa_set_key_usage_flags(&attributes, AWRTC_PSA_KEY_USAGE_SIGN_MESSAGE);
    awrtc_psa_set_key_algorithm(&attributes, alg);
    awrtc_psa_set_key_type(&attributes, AWRTC_PSA_KEY_TYPE_HMAC);

    status = awrtc_psa_import_key(&attributes, finished_key, hash_len, &key);
    if (status != AWRTC_PSA_SUCCESS) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
        goto exit;
    }

    status = awrtc_psa_mac_compute(key, alg, transcript, hash_len,
                             dst, hash_len, dst_len);
    ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);

exit:

    status = awrtc_psa_destroy_key(key);
    if (ret == 0) {
        ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
    }

    awrtc_mbedtls_platform_zeroize(finished_key, sizeof(finished_key));

    return ret;
}

int awrtc_mbedtls_ssl_tls13_calculate_verify_data(awrtc_mbedtls_ssl_context *ssl,
                                            unsigned char *dst,
                                            size_t dst_len,
                                            size_t *actual_len,
                                            int from)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    unsigned char transcript[AWRTC_MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_len;

    unsigned char *base_key = NULL;
    size_t base_key_len = 0;
    awrtc_mbedtls_ssl_tls13_handshake_secrets *tls13_hs_secrets =
        &ssl->handshake->tls13_hs_secrets;

    awrtc_mbedtls_md_type_t const md_type = (awrtc_mbedtls_md_type_t) ssl->handshake->ciphersuite_info->mac;

    awrtc_psa_algorithm_t hash_alg = awrtc_mbedtls_md_psa_alg_from_type(
        (awrtc_mbedtls_md_type_t) ssl->handshake->ciphersuite_info->mac);
    size_t const hash_len = AWRTC_PSA_HASH_LENGTH(hash_alg);

    AWRTC_MBEDTLS_SSL_DEBUG_MSG(2, ("=> awrtc_mbedtls_ssl_tls13_calculate_verify_data"));

    if (from == AWRTC_MBEDTLS_SSL_IS_CLIENT) {
        base_key = tls13_hs_secrets->client_handshake_traffic_secret;
        base_key_len = sizeof(tls13_hs_secrets->client_handshake_traffic_secret);
    } else {
        base_key = tls13_hs_secrets->server_handshake_traffic_secret;
        base_key_len = sizeof(tls13_hs_secrets->server_handshake_traffic_secret);
    }

    if (dst_len < hash_len) {
        ret = AWRTC_MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
        goto exit;
    }

    ret = awrtc_mbedtls_ssl_get_handshake_transcript(ssl, md_type,
                                               transcript, sizeof(transcript),
                                               &transcript_len);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_get_handshake_transcript", ret);
        goto exit;
    }
    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "handshake hash", transcript, transcript_len);

    ret = ssl_tls13_calc_finished_core(hash_alg, base_key,
                                       transcript, dst, actual_len);
    if (ret != 0) {
        goto exit;
    }

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(3, "verify_data for finished message", dst, hash_len);
    AWRTC_MBEDTLS_SSL_DEBUG_MSG(2, ("<= awrtc_mbedtls_ssl_tls13_calculate_verify_data"));

exit:
    /* Erase handshake secrets */
    awrtc_mbedtls_platform_zeroize(base_key, base_key_len);
    awrtc_mbedtls_platform_zeroize(transcript, sizeof(transcript));
    return ret;
}

int awrtc_mbedtls_ssl_tls13_create_psk_binder(awrtc_mbedtls_ssl_context *ssl,
                                        const awrtc_psa_algorithm_t hash_alg,
                                        unsigned char const *psk, size_t psk_len,
                                        int psk_type,
                                        unsigned char const *transcript,
                                        unsigned char *result)
{
    int ret = 0;
    unsigned char binder_key[AWRTC_PSA_MAC_MAX_SIZE];
    unsigned char early_secret[AWRTC_PSA_MAC_MAX_SIZE];
    size_t const hash_len = AWRTC_PSA_HASH_LENGTH(hash_alg);
    size_t actual_len;

#if !defined(AWRTC_MBEDTLS_DEBUG_C)
    ssl = NULL; /* make sure we don't use it except for debug */
    ((void) ssl);
#endif

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if (!AWRTC_PSA_ALG_IS_HASH(hash_alg)) {
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /*
     *            0
     *            |
     *            v
     *  PSK ->  HKDF-Extract = Early Secret
     *            |
     *            +-----> Derive-Secret(., "ext binder" | "res binder", "")
     *            |                     = binder_key
     *            v
     */

    ret = awrtc_mbedtls_ssl_tls13_evolve_secret(hash_alg,
                                          NULL,           /* Old secret */
                                          psk, psk_len,   /* Input      */
                                          early_secret);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_tls13_evolve_secret", ret);
        goto exit;
    }

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "awrtc_mbedtls_ssl_tls13_create_psk_binder",
                          early_secret, hash_len);

    if (psk_type == AWRTC_MBEDTLS_SSL_TLS1_3_PSK_RESUMPTION) {
        ret = awrtc_mbedtls_ssl_tls13_derive_secret(
            hash_alg,
            early_secret, hash_len,
            AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(res_binder),
            NULL, 0, AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
            binder_key, hash_len);
        AWRTC_MBEDTLS_SSL_DEBUG_MSG(4, ("Derive Early Secret with 'res binder'"));
    } else {
        ret = awrtc_mbedtls_ssl_tls13_derive_secret(
            hash_alg,
            early_secret, hash_len,
            AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(ext_binder),
            NULL, 0, AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
            binder_key, hash_len);
        AWRTC_MBEDTLS_SSL_DEBUG_MSG(4, ("Derive Early Secret with 'ext binder'"));
    }

    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_tls13_derive_secret", ret);
        goto exit;
    }

    /*
     * The binding_value is computed in the same way as the Finished message
     * but with the BaseKey being the binder_key.
     */

    ret = ssl_tls13_calc_finished_core(hash_alg, binder_key, transcript,
                                       result, &actual_len);
    if (ret != 0) {
        goto exit;
    }

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(3, "psk binder", result, actual_len);

exit:

    awrtc_mbedtls_platform_zeroize(early_secret, sizeof(early_secret));
    awrtc_mbedtls_platform_zeroize(binder_key,   sizeof(binder_key));
    return ret;
}

int awrtc_mbedtls_ssl_tls13_populate_transform(
    awrtc_mbedtls_ssl_transform *transform,
    int endpoint, int ciphersuite,
    awrtc_mbedtls_ssl_key_set const *traffic_keys,
    awrtc_mbedtls_ssl_context *ssl /* DEBUG ONLY */)
{
#if !defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    int ret;
    awrtc_mbedtls_cipher_info_t const *cipher_info;
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
    const awrtc_mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    unsigned char const *key_enc;
    unsigned char const *iv_enc;
    unsigned char const *key_dec;
    unsigned char const *iv_dec;

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_key_type_t key_type;
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_psa_algorithm_t alg;
    size_t key_bits;
    awrtc_psa_status_t status = AWRTC_PSA_SUCCESS;
#endif

#if !defined(AWRTC_MBEDTLS_DEBUG_C)
    ssl = NULL; /* make sure we don't use it except for those cases */
    (void) ssl;
#endif

    ciphersuite_info = awrtc_mbedtls_ssl_ciphersuite_from_id(ciphersuite);
    if (ciphersuite_info == NULL) {
        AWRTC_MBEDTLS_SSL_DEBUG_MSG(1, ("ciphersuite info for %d not found",
                                  ciphersuite));
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

#if !defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    cipher_info = awrtc_mbedtls_cipher_info_from_type(ciphersuite_info->cipher);
    if (cipher_info == NULL) {
        AWRTC_MBEDTLS_SSL_DEBUG_MSG(1, ("cipher info for %u not found",
                                  ciphersuite_info->cipher));
        return AWRTC_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    /*
     * Setup cipher contexts in target transform
     */
    if ((ret = awrtc_mbedtls_cipher_setup(&transform->cipher_ctx_enc,
                                    cipher_info)) != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_cipher_setup", ret);
        return ret;
    }

    if ((ret = awrtc_mbedtls_cipher_setup(&transform->cipher_ctx_dec,
                                    cipher_info)) != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_cipher_setup", ret);
        return ret;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#if defined(AWRTC_MBEDTLS_SSL_SRV_C)
    if (endpoint == AWRTC_MBEDTLS_SSL_IS_SERVER) {
        key_enc = traffic_keys->server_write_key;
        key_dec = traffic_keys->client_write_key;
        iv_enc = traffic_keys->server_write_iv;
        iv_dec = traffic_keys->client_write_iv;
    } else
#endif /* AWRTC_MBEDTLS_SSL_SRV_C */
#if defined(AWRTC_MBEDTLS_SSL_CLI_C)
    if (endpoint == AWRTC_MBEDTLS_SSL_IS_CLIENT) {
        key_enc = traffic_keys->client_write_key;
        key_dec = traffic_keys->server_write_key;
        iv_enc = traffic_keys->client_write_iv;
        iv_dec = traffic_keys->server_write_iv;
    } else
#endif /* AWRTC_MBEDTLS_SSL_CLI_C */
    {
        /* should not happen */
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    memcpy(transform->iv_enc, iv_enc, traffic_keys->iv_len);
    memcpy(transform->iv_dec, iv_dec, traffic_keys->iv_len);

#if !defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    if ((ret = awrtc_mbedtls_cipher_setkey(&transform->cipher_ctx_enc,
                                     key_enc, (int) awrtc_mbedtls_cipher_info_get_key_bitlen(cipher_info),
                                     AWRTC_MBEDTLS_ENCRYPT)) != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_cipher_setkey", ret);
        return ret;
    }

    if ((ret = awrtc_mbedtls_cipher_setkey(&transform->cipher_ctx_dec,
                                     key_dec, (int) awrtc_mbedtls_cipher_info_get_key_bitlen(cipher_info),
                                     AWRTC_MBEDTLS_DECRYPT)) != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_cipher_setkey", ret);
        return ret;
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    /*
     * Setup other fields in SSL transform
     */

    if ((ciphersuite_info->flags & AWRTC_MBEDTLS_CIPHERSUITE_SHORT_TAG) != 0) {
        transform->taglen  = 8;
    } else {
        transform->taglen  = 16;
    }

    transform->ivlen       = traffic_keys->iv_len;
    transform->maclen      = 0;
    transform->fixed_ivlen = transform->ivlen;
    transform->tls_version = AWRTC_MBEDTLS_SSL_VERSION_TLS1_3;

    /* We add the true record content type (1 Byte) to the plaintext and
     * then pad to the configured granularity. The minimum length of the
     * type-extended and padded plaintext is therefore the padding
     * granularity. */
    transform->minlen =
        transform->taglen + AWRTC_MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY;

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    /*
     * Setup psa keys and alg
     */
    if ((status = awrtc_mbedtls_ssl_cipher_to_psa((awrtc_mbedtls_cipher_type_t) ciphersuite_info->cipher,
                                            transform->taglen,
                                            &alg,
                                            &key_type,
                                            &key_bits)) != AWRTC_PSA_SUCCESS) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(
            1, "awrtc_mbedtls_ssl_cipher_to_psa", AWRTC_PSA_TO_MBEDTLS_ERR(status));
        return AWRTC_PSA_TO_MBEDTLS_ERR(status);
    }

    transform->awrtc_psa_alg = alg;

    if (alg != AWRTC_MBEDTLS_SSL_NULL_CIPHER) {
        awrtc_psa_set_key_usage_flags(&attributes, AWRTC_PSA_KEY_USAGE_ENCRYPT);
        awrtc_psa_set_key_algorithm(&attributes, alg);
        awrtc_psa_set_key_type(&attributes, key_type);

        if ((status = awrtc_psa_import_key(&attributes,
                                     key_enc,
                                     AWRTC_PSA_BITS_TO_BYTES(key_bits),
                                     &transform->awrtc_psa_key_enc)) != AWRTC_PSA_SUCCESS) {
            AWRTC_MBEDTLS_SSL_DEBUG_RET(
                1, "awrtc_psa_import_key", AWRTC_PSA_TO_MBEDTLS_ERR(status));
            return AWRTC_PSA_TO_MBEDTLS_ERR(status);
        }

        awrtc_psa_set_key_usage_flags(&attributes, AWRTC_PSA_KEY_USAGE_DECRYPT);

        if ((status = awrtc_psa_import_key(&attributes,
                                     key_dec,
                                     AWRTC_PSA_BITS_TO_BYTES(key_bits),
                                     &transform->awrtc_psa_key_dec)) != AWRTC_PSA_SUCCESS) {
            AWRTC_MBEDTLS_SSL_DEBUG_RET(
                1, "awrtc_psa_import_key", AWRTC_PSA_TO_MBEDTLS_ERR(status));
            return AWRTC_PSA_TO_MBEDTLS_ERR(status);
        }
    }
#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    return 0;
}

AWRTC_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_get_cipher_key_info(
    const awrtc_mbedtls_ssl_ciphersuite_t *ciphersuite_info,
    size_t *key_len, size_t *iv_len)
{
    awrtc_psa_key_type_t key_type;
    awrtc_psa_algorithm_t alg;
    size_t taglen;
    size_t key_bits;
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;

    if (ciphersuite_info->flags & AWRTC_MBEDTLS_CIPHERSUITE_SHORT_TAG) {
        taglen = 8;
    } else {
        taglen = 16;
    }

    status = awrtc_mbedtls_ssl_cipher_to_psa((awrtc_mbedtls_cipher_type_t) ciphersuite_info->cipher, taglen,
                                       &alg, &key_type, &key_bits);
    if (status != AWRTC_PSA_SUCCESS) {
        return AWRTC_PSA_TO_MBEDTLS_ERR(status);
    }

    *key_len = AWRTC_PSA_BITS_TO_BYTES(key_bits);

    /* TLS 1.3 only have AEAD ciphers, IV length is unconditionally 12 bytes */
    *iv_len = 12;

    return 0;
}

#if defined(AWRTC_MBEDTLS_SSL_EARLY_DATA)
/*
 * ssl_tls13_generate_early_key() generates the key necessary for protecting
 * the early application data and handshake messages as described in section 7
 * of RFC 8446.
 *
 * NOTE: Only one key is generated, the key for the traffic from the client to
 *       the server. The TLS 1.3 specification does not define a secret and thus
 *       a key for server early traffic.
 */
AWRTC_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_generate_early_key(awrtc_mbedtls_ssl_context *ssl,
                                        awrtc_mbedtls_ssl_key_set *traffic_keys)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_md_type_t md_type;
    awrtc_psa_algorithm_t hash_alg;
    size_t hash_len;
    unsigned char transcript[AWRTC_MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_len;
    size_t key_len = 0;
    size_t iv_len = 0;
    awrtc_mbedtls_ssl_tls13_early_secrets tls13_early_secrets;

    awrtc_mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    const awrtc_mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        handshake->ciphersuite_info;

    AWRTC_MBEDTLS_SSL_DEBUG_MSG(2, ("=> ssl_tls13_generate_early_key"));

    ret = ssl_tls13_get_cipher_key_info(ciphersuite_info, &key_len, &iv_len);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "ssl_tls13_get_cipher_key_info", ret);
        goto cleanup;
    }

    md_type = (awrtc_mbedtls_md_type_t) ciphersuite_info->mac;

    hash_alg = awrtc_mbedtls_md_psa_alg_from_type((awrtc_mbedtls_md_type_t) ciphersuite_info->mac);
    hash_len = AWRTC_PSA_HASH_LENGTH(hash_alg);

    ret = awrtc_mbedtls_ssl_get_handshake_transcript(ssl, md_type,
                                               transcript,
                                               sizeof(transcript),
                                               &transcript_len);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1,
                              "awrtc_mbedtls_ssl_get_handshake_transcript",
                              ret);
        goto cleanup;
    }

    ret = awrtc_mbedtls_ssl_tls13_derive_early_secrets(
        hash_alg, handshake->tls13_master_secrets.early,
        transcript, transcript_len, &tls13_early_secrets);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(
            1, "awrtc_mbedtls_ssl_tls13_derive_early_secrets", ret);
        goto cleanup;
    }

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(
        4, "Client early traffic secret",
        tls13_early_secrets.client_early_traffic_secret, hash_len);

    /*
     * Export client handshake traffic secret
     */
    if (ssl->f_export_keys != NULL) {
        ssl->f_export_keys(
            ssl->p_export_keys,
            AWRTC_MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_EARLY_SECRET,
            tls13_early_secrets.client_early_traffic_secret,
            hash_len,
            handshake->randbytes,
            handshake->randbytes + AWRTC_MBEDTLS_CLIENT_HELLO_RANDOM_LEN,
            AWRTC_MBEDTLS_SSL_TLS_PRF_NONE /* TODO: FIX! */);
    }

    ret = ssl_tls13_make_traffic_key(
        hash_alg,
        tls13_early_secrets.client_early_traffic_secret,
        hash_len, traffic_keys->client_write_key, key_len,
        traffic_keys->client_write_iv, iv_len);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "ssl_tls13_make_traffic_key", ret);
        goto cleanup;
    }
    traffic_keys->key_len = key_len;
    traffic_keys->iv_len = iv_len;

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "client early write_key",
                          traffic_keys->client_write_key,
                          traffic_keys->key_len);

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "client early write_iv",
                          traffic_keys->client_write_iv,
                          traffic_keys->iv_len);

    AWRTC_MBEDTLS_SSL_DEBUG_MSG(2, ("<= ssl_tls13_generate_early_key"));

cleanup:
    /* Erase early secrets and transcript */
    awrtc_mbedtls_platform_zeroize(
        &tls13_early_secrets, sizeof(awrtc_mbedtls_ssl_tls13_early_secrets));
    awrtc_mbedtls_platform_zeroize(transcript, sizeof(transcript));
    return ret;
}

int awrtc_mbedtls_ssl_tls13_compute_early_transform(awrtc_mbedtls_ssl_context *ssl)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ssl_key_set traffic_keys;
    awrtc_mbedtls_ssl_transform *transform_earlydata = NULL;
    awrtc_mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    /* Next evolution in key schedule: Establish early_data secret and
     * key material. */
    ret = ssl_tls13_generate_early_key(ssl, &traffic_keys);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "ssl_tls13_generate_early_key",
                              ret);
        goto cleanup;
    }

    transform_earlydata = awrtc_mbedtls_calloc(1, sizeof(awrtc_mbedtls_ssl_transform));
    if (transform_earlydata == NULL) {
        ret = AWRTC_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto cleanup;
    }

    ret = awrtc_mbedtls_ssl_tls13_populate_transform(
        transform_earlydata,
        ssl->conf->endpoint,
        handshake->ciphersuite_info->id,
        &traffic_keys,
        ssl);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_tls13_populate_transform", ret);
        goto cleanup;
    }
    handshake->transform_earlydata = transform_earlydata;

cleanup:
    awrtc_mbedtls_platform_zeroize(&traffic_keys, sizeof(traffic_keys));
    if (ret != 0) {
        awrtc_mbedtls_free(transform_earlydata);
    }

    return ret;
}
#endif /* AWRTC_MBEDTLS_SSL_EARLY_DATA */

int awrtc_mbedtls_ssl_tls13_key_schedule_stage_early(awrtc_mbedtls_ssl_context *ssl)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_algorithm_t hash_alg;
    awrtc_mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    unsigned char *psk = NULL;
    size_t psk_len = 0;

    if (handshake->ciphersuite_info == NULL) {
        AWRTC_MBEDTLS_SSL_DEBUG_MSG(1, ("cipher suite info not found"));
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    hash_alg = awrtc_mbedtls_md_psa_alg_from_type((awrtc_mbedtls_md_type_t) handshake->ciphersuite_info->mac);
#if defined(AWRTC_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)
    if (awrtc_mbedtls_ssl_tls13_key_exchange_mode_with_psk(ssl)) {
        ret = awrtc_mbedtls_ssl_tls13_export_handshake_psk(ssl, &psk, &psk_len);
        if (ret != 0) {
            AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_tls13_export_handshake_psk",
                                  ret);
            return ret;
        }
    }
#endif

    ret = awrtc_mbedtls_ssl_tls13_evolve_secret(hash_alg, NULL, psk, psk_len,
                                          handshake->tls13_master_secrets.early);
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) && \
    defined(AWRTC_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)
    awrtc_mbedtls_free((void *) psk);
#endif
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_tls13_evolve_secret", ret);
        return ret;
    }

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "awrtc_mbedtls_ssl_tls13_key_schedule_stage_early",
                          handshake->tls13_master_secrets.early,
                          AWRTC_PSA_HASH_LENGTH(hash_alg));
    return 0;
}

/**
 * \brief Compute TLS 1.3 handshake traffic keys.
 *
 *        ssl_tls13_generate_handshake_keys() generates keys necessary for
 *        protecting the handshake messages, as described in Section 7 of
 *        RFC 8446.
 *
 * \param ssl  The SSL context to operate on. This must be in
 *             key schedule stage \c Handshake, see
 *             ssl_tls13_key_schedule_stage_handshake().
 * \param traffic_keys The address at which to store the handshake traffic
 *                     keys. This must be writable but may be uninitialized.
 *
 * \returns    \c 0 on success.
 * \returns    A negative error code on failure.
 */
AWRTC_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_generate_handshake_keys(awrtc_mbedtls_ssl_context *ssl,
                                             awrtc_mbedtls_ssl_key_set *traffic_keys)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_md_type_t md_type;
    awrtc_psa_algorithm_t hash_alg;
    size_t hash_len;
    unsigned char transcript[AWRTC_MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_len;
    size_t key_len = 0;
    size_t iv_len = 0;

    awrtc_mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    const awrtc_mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        handshake->ciphersuite_info;
    awrtc_mbedtls_ssl_tls13_handshake_secrets *tls13_hs_secrets =
        &handshake->tls13_hs_secrets;

    AWRTC_MBEDTLS_SSL_DEBUG_MSG(2, ("=> ssl_tls13_generate_handshake_keys"));

    ret = ssl_tls13_get_cipher_key_info(ciphersuite_info, &key_len, &iv_len);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "ssl_tls13_get_cipher_key_info", ret);
        return ret;
    }

    md_type = (awrtc_mbedtls_md_type_t) ciphersuite_info->mac;

    hash_alg = awrtc_mbedtls_md_psa_alg_from_type((awrtc_mbedtls_md_type_t) ciphersuite_info->mac);
    hash_len = AWRTC_PSA_HASH_LENGTH(hash_alg);

    ret = awrtc_mbedtls_ssl_get_handshake_transcript(ssl, md_type,
                                               transcript,
                                               sizeof(transcript),
                                               &transcript_len);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1,
                              "awrtc_mbedtls_ssl_get_handshake_transcript",
                              ret);
        return ret;
    }

    ret = awrtc_mbedtls_ssl_tls13_derive_handshake_secrets(
        hash_alg, handshake->tls13_master_secrets.handshake,
        transcript, transcript_len, tls13_hs_secrets);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_tls13_derive_handshake_secrets",
                              ret);
        return ret;
    }

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "Client handshake traffic secret",
                          tls13_hs_secrets->client_handshake_traffic_secret,
                          hash_len);
    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "Server handshake traffic secret",
                          tls13_hs_secrets->server_handshake_traffic_secret,
                          hash_len);

    /*
     * Export client handshake traffic secret
     */
    if (ssl->f_export_keys != NULL) {
        ssl->f_export_keys(
            ssl->p_export_keys,
            AWRTC_MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_HANDSHAKE_TRAFFIC_SECRET,
            tls13_hs_secrets->client_handshake_traffic_secret,
            hash_len,
            handshake->randbytes,
            handshake->randbytes + AWRTC_MBEDTLS_CLIENT_HELLO_RANDOM_LEN,
            AWRTC_MBEDTLS_SSL_TLS_PRF_NONE /* TODO: FIX! */);

        ssl->f_export_keys(
            ssl->p_export_keys,
            AWRTC_MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_HANDSHAKE_TRAFFIC_SECRET,
            tls13_hs_secrets->server_handshake_traffic_secret,
            hash_len,
            handshake->randbytes,
            handshake->randbytes + AWRTC_MBEDTLS_CLIENT_HELLO_RANDOM_LEN,
            AWRTC_MBEDTLS_SSL_TLS_PRF_NONE /* TODO: FIX! */);
    }

    ret = awrtc_mbedtls_ssl_tls13_make_traffic_keys(
        hash_alg,
        tls13_hs_secrets->client_handshake_traffic_secret,
        tls13_hs_secrets->server_handshake_traffic_secret,
        hash_len, key_len, iv_len, traffic_keys);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_tls13_make_traffic_keys", ret);
        goto exit;
    }

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "client_handshake write_key",
                          traffic_keys->client_write_key,
                          traffic_keys->key_len);

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "server_handshake write_key",
                          traffic_keys->server_write_key,
                          traffic_keys->key_len);

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "client_handshake write_iv",
                          traffic_keys->client_write_iv,
                          traffic_keys->iv_len);

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "server_handshake write_iv",
                          traffic_keys->server_write_iv,
                          traffic_keys->iv_len);

    AWRTC_MBEDTLS_SSL_DEBUG_MSG(2, ("<= ssl_tls13_generate_handshake_keys"));

exit:

    return ret;
}

/**
 * \brief Transition into handshake stage of TLS 1.3 key schedule.
 *
 *        The TLS 1.3 key schedule can be viewed as a simple state machine
 *        with states Initial -> Early -> Handshake -> Application, and
 *        this function represents the Early -> Handshake transition.
 *
 *        In the handshake stage, ssl_tls13_generate_handshake_keys()
 *        can be used to derive the handshake traffic keys.
 *
 * \param ssl  The SSL context to operate on. This must be in key schedule
 *             stage \c Early.
 *
 * \returns    \c 0 on success.
 * \returns    A negative error code on failure.
 */
AWRTC_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_key_schedule_stage_handshake(awrtc_mbedtls_ssl_context *ssl)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    awrtc_psa_algorithm_t const hash_alg = awrtc_mbedtls_md_psa_alg_from_type(
        (awrtc_mbedtls_md_type_t) handshake->ciphersuite_info->mac);
    unsigned char *shared_secret = NULL;
    size_t shared_secret_len = 0;

#if defined(AWRTC_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED)
    /*
     * Compute ECDHE secret used to compute the handshake secret from which
     * client_handshake_traffic_secret and server_handshake_traffic_secret
     * are derived in the handshake secret derivation stage.
     */
    if (awrtc_mbedtls_ssl_tls13_key_exchange_mode_with_ephemeral(ssl)) {
        if (awrtc_mbedtls_ssl_tls13_named_group_is_ecdhe(handshake->offered_group_id) ||
            awrtc_mbedtls_ssl_tls13_named_group_is_ffdh(handshake->offered_group_id)) {
#if defined(AWRTC_PSA_WANT_ALG_ECDH) || defined(AWRTC_PSA_WANT_ALG_FFDH)
            awrtc_psa_algorithm_t alg =
                awrtc_mbedtls_ssl_tls13_named_group_is_ecdhe(handshake->offered_group_id) ?
                AWRTC_PSA_ALG_ECDH : AWRTC_PSA_ALG_FFDH;

            /* Compute ECDH shared secret. */
            awrtc_psa_status_t status = AWRTC_PSA_ERROR_GENERIC_ERROR;
            awrtc_psa_key_attributes_t key_attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;

            status = awrtc_psa_get_key_attributes(handshake->xxdh_psa_privkey,
                                            &key_attributes);
            if (status != AWRTC_PSA_SUCCESS) {
                ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
            }

            shared_secret_len = AWRTC_PSA_BITS_TO_BYTES(
                awrtc_psa_get_key_bits(&key_attributes));
            shared_secret = awrtc_mbedtls_calloc(1, shared_secret_len);
            if (shared_secret == NULL) {
                return AWRTC_MBEDTLS_ERR_SSL_ALLOC_FAILED;
            }

            status = awrtc_psa_raw_key_agreement(
                alg, handshake->xxdh_psa_privkey,
                handshake->xxdh_psa_peerkey, handshake->xxdh_psa_peerkey_len,
                shared_secret, shared_secret_len, &shared_secret_len);
            if (status != AWRTC_PSA_SUCCESS) {
                ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
                AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_psa_raw_key_agreement", ret);
                goto cleanup;
            }

            status = awrtc_psa_destroy_key(handshake->xxdh_psa_privkey);
            if (status != AWRTC_PSA_SUCCESS) {
                ret = AWRTC_PSA_TO_MBEDTLS_ERR(status);
                AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_psa_destroy_key", ret);
                goto cleanup;
            }

            handshake->xxdh_psa_privkey = AWRTC_MBEDTLS_SVC_KEY_ID_INIT;
#endif /* AWRTC_PSA_WANT_ALG_ECDH || AWRTC_PSA_WANT_ALG_FFDH */
        } else {
            AWRTC_MBEDTLS_SSL_DEBUG_MSG(1, ("Group not supported."));
            return AWRTC_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        }
    }
#endif /* AWRTC_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED */

    /*
     * Compute the Handshake Secret
     */
    ret = awrtc_mbedtls_ssl_tls13_evolve_secret(
        hash_alg, handshake->tls13_master_secrets.early,
        shared_secret, shared_secret_len,
        handshake->tls13_master_secrets.handshake);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_tls13_evolve_secret", ret);
        goto cleanup;
    }

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "Handshake secret",
                          handshake->tls13_master_secrets.handshake,
                          AWRTC_PSA_HASH_LENGTH(hash_alg));

cleanup:
    if (shared_secret != NULL) {
        awrtc_mbedtls_zeroize_and_free(shared_secret, shared_secret_len);
    }

    return ret;
}

/**
 * \brief Compute TLS 1.3 application traffic keys.
 *
 *        ssl_tls13_generate_application_keys() generates application traffic
 *        keys, since any record following a 1-RTT Finished message MUST be
 *        encrypted under the application traffic key.
 *
 * \param ssl  The SSL context to operate on. This must be in
 *             key schedule stage \c Application, see
 *             ssl_tls13_key_schedule_stage_application().
 * \param traffic_keys The address at which to store the application traffic
 *                     keys. This must be writable but may be uninitialized.
 *
 * \returns    \c 0 on success.
 * \returns    A negative error code on failure.
 */
AWRTC_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_generate_application_keys(
    awrtc_mbedtls_ssl_context *ssl,
    awrtc_mbedtls_ssl_key_set *traffic_keys)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    /* Address at which to store the application secrets */
    awrtc_mbedtls_ssl_tls13_application_secrets * const app_secrets =
        &ssl->session_negotiate->app_secrets;

    /* Holding the transcript up to and including the ServerFinished */
    unsigned char transcript[AWRTC_MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_len;

    /* Variables relating to the hash for the chosen ciphersuite. */
    awrtc_mbedtls_md_type_t md_type;

    awrtc_psa_algorithm_t hash_alg;
    size_t hash_len;

    /* Variables relating to the cipher for the chosen ciphersuite. */
    size_t key_len = 0, iv_len = 0;

    AWRTC_MBEDTLS_SSL_DEBUG_MSG(2, ("=> derive application traffic keys"));

    /* Extract basic information about hash and ciphersuite */

    ret = ssl_tls13_get_cipher_key_info(handshake->ciphersuite_info,
                                        &key_len, &iv_len);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "ssl_tls13_get_cipher_key_info", ret);
        goto cleanup;
    }

    md_type = (awrtc_mbedtls_md_type_t) handshake->ciphersuite_info->mac;

    hash_alg = awrtc_mbedtls_md_psa_alg_from_type((awrtc_mbedtls_md_type_t) handshake->ciphersuite_info->mac);
    hash_len = AWRTC_PSA_HASH_LENGTH(hash_alg);

    /* Compute current handshake transcript. It's the caller's responsibility
     * to call this at the right time, that is, after the ServerFinished. */

    ret = awrtc_mbedtls_ssl_get_handshake_transcript(ssl, md_type,
                                               transcript, sizeof(transcript),
                                               &transcript_len);
    if (ret != 0) {
        goto cleanup;
    }

    /* Compute application secrets from master secret and transcript hash. */

    ret = awrtc_mbedtls_ssl_tls13_derive_application_secrets(
        hash_alg, handshake->tls13_master_secrets.app,
        transcript, transcript_len, app_secrets);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(
            1, "awrtc_mbedtls_ssl_tls13_derive_application_secrets", ret);
        goto cleanup;
    }

    /* Derive first epoch of IV + Key for application traffic. */

    ret = awrtc_mbedtls_ssl_tls13_make_traffic_keys(
        hash_alg,
        app_secrets->client_application_traffic_secret_N,
        app_secrets->server_application_traffic_secret_N,
        hash_len, key_len, iv_len, traffic_keys);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_tls13_make_traffic_keys", ret);
        goto cleanup;
    }

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "Client application traffic secret",
                          app_secrets->client_application_traffic_secret_N,
                          hash_len);

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "Server application traffic secret",
                          app_secrets->server_application_traffic_secret_N,
                          hash_len);

    /*
     * Export client/server application traffic secret 0
     */
    if (ssl->f_export_keys != NULL) {
        ssl->f_export_keys(
            ssl->p_export_keys,
            AWRTC_MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET,
            app_secrets->client_application_traffic_secret_N, hash_len,
            handshake->randbytes,
            handshake->randbytes + AWRTC_MBEDTLS_CLIENT_HELLO_RANDOM_LEN,
            AWRTC_MBEDTLS_SSL_TLS_PRF_NONE /* TODO: this should be replaced by
                                        a new constant for TLS 1.3! */);

        ssl->f_export_keys(
            ssl->p_export_keys,
            AWRTC_MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET,
            app_secrets->server_application_traffic_secret_N, hash_len,
            handshake->randbytes,
            handshake->randbytes + AWRTC_MBEDTLS_CLIENT_HELLO_RANDOM_LEN,
            AWRTC_MBEDTLS_SSL_TLS_PRF_NONE /* TODO: this should be replaced by
                                        a new constant for TLS 1.3! */);
    }

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "client application_write_key:",
                          traffic_keys->client_write_key, key_len);
    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "server application write key",
                          traffic_keys->server_write_key, key_len);
    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "client application write IV",
                          traffic_keys->client_write_iv, iv_len);
    AWRTC_MBEDTLS_SSL_DEBUG_BUF(4, "server application write IV",
                          traffic_keys->server_write_iv, iv_len);

    AWRTC_MBEDTLS_SSL_DEBUG_MSG(2, ("<= derive application traffic keys"));

cleanup:
    /* randbytes is not used again */
    awrtc_mbedtls_platform_zeroize(ssl->handshake->randbytes,
                             sizeof(ssl->handshake->randbytes));

    awrtc_mbedtls_platform_zeroize(transcript, sizeof(transcript));
    return ret;
}

int awrtc_mbedtls_ssl_tls13_compute_handshake_transform(awrtc_mbedtls_ssl_context *ssl)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ssl_key_set traffic_keys;
    awrtc_mbedtls_ssl_transform *transform_handshake = NULL;
    awrtc_mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    /* Compute handshake secret */
    ret = ssl_tls13_key_schedule_stage_handshake(ssl);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_tls13_derive_master_secret", ret);
        goto cleanup;
    }

    /* Next evolution in key schedule: Establish handshake secret and
     * key material. */
    ret = ssl_tls13_generate_handshake_keys(ssl, &traffic_keys);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "ssl_tls13_generate_handshake_keys",
                              ret);
        goto cleanup;
    }

    transform_handshake = awrtc_mbedtls_calloc(1, sizeof(awrtc_mbedtls_ssl_transform));
    if (transform_handshake == NULL) {
        ret = AWRTC_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto cleanup;
    }

    ret = awrtc_mbedtls_ssl_tls13_populate_transform(
        transform_handshake,
        ssl->conf->endpoint,
        handshake->ciphersuite_info->id,
        &traffic_keys,
        ssl);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_tls13_populate_transform", ret);
        goto cleanup;
    }
    handshake->transform_handshake = transform_handshake;

cleanup:
    awrtc_mbedtls_platform_zeroize(&traffic_keys, sizeof(traffic_keys));
    if (ret != 0) {
        awrtc_mbedtls_free(transform_handshake);
    }

    return ret;
}

int awrtc_mbedtls_ssl_tls13_compute_resumption_master_secret(awrtc_mbedtls_ssl_context *ssl)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_md_type_t md_type;
    awrtc_mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    unsigned char transcript[AWRTC_MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_len;

    AWRTC_MBEDTLS_SSL_DEBUG_MSG(
        2, ("=> awrtc_mbedtls_ssl_tls13_compute_resumption_master_secret"));

    md_type = (awrtc_mbedtls_md_type_t) handshake->ciphersuite_info->mac;

    ret = awrtc_mbedtls_ssl_get_handshake_transcript(ssl, md_type,
                                               transcript, sizeof(transcript),
                                               &transcript_len);
    if (ret != 0) {
        return ret;
    }

    ret = awrtc_mbedtls_ssl_tls13_derive_resumption_master_secret(
        awrtc_mbedtls_md_psa_alg_from_type(md_type),
        handshake->tls13_master_secrets.app,
        transcript, transcript_len,
        &ssl->session_negotiate->app_secrets);
    if (ret != 0) {
        return ret;
    }

    /* Erase master secrets */
    awrtc_mbedtls_platform_zeroize(&handshake->tls13_master_secrets,
                             sizeof(handshake->tls13_master_secrets));

    AWRTC_MBEDTLS_SSL_DEBUG_BUF(
        4, "Resumption master secret",
        ssl->session_negotiate->app_secrets.resumption_master_secret,
        AWRTC_PSA_HASH_LENGTH(awrtc_mbedtls_md_psa_alg_from_type(md_type)));

    AWRTC_MBEDTLS_SSL_DEBUG_MSG(
        2, ("<= awrtc_mbedtls_ssl_tls13_compute_resumption_master_secret"));
    return 0;
}

int awrtc_mbedtls_ssl_tls13_compute_application_transform(awrtc_mbedtls_ssl_context *ssl)
{
    int ret = AWRTC_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    awrtc_mbedtls_ssl_key_set traffic_keys;
    awrtc_mbedtls_ssl_transform *transform_application = NULL;

    ret = ssl_tls13_key_schedule_stage_application(ssl);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1,
                              "ssl_tls13_key_schedule_stage_application", ret);
        goto cleanup;
    }

    ret = ssl_tls13_generate_application_keys(ssl, &traffic_keys);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1,
                              "ssl_tls13_generate_application_keys", ret);
        goto cleanup;
    }

    transform_application =
        awrtc_mbedtls_calloc(1, sizeof(awrtc_mbedtls_ssl_transform));
    if (transform_application == NULL) {
        ret = AWRTC_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto cleanup;
    }

    ret = awrtc_mbedtls_ssl_tls13_populate_transform(
        transform_application,
        ssl->conf->endpoint,
        ssl->handshake->ciphersuite_info->id,
        &traffic_keys,
        ssl);
    if (ret != 0) {
        AWRTC_MBEDTLS_SSL_DEBUG_RET(1, "awrtc_mbedtls_ssl_tls13_populate_transform", ret);
        goto cleanup;
    }

    ssl->transform_application = transform_application;

cleanup:

    awrtc_mbedtls_platform_zeroize(&traffic_keys, sizeof(traffic_keys));
    if (ret != 0) {
        awrtc_mbedtls_free(transform_application);
    }
    return ret;
}

#if defined(AWRTC_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)
int awrtc_mbedtls_ssl_tls13_export_handshake_psk(awrtc_mbedtls_ssl_context *ssl,
                                           unsigned char **psk,
                                           size_t *psk_len)
{
#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
    awrtc_psa_key_attributes_t key_attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;

    *psk_len = 0;
    *psk = NULL;

    if (awrtc_mbedtls_svc_key_id_is_null(ssl->handshake->psk_opaque)) {
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    status = awrtc_psa_get_key_attributes(ssl->handshake->psk_opaque, &key_attributes);
    if (status != AWRTC_PSA_SUCCESS) {
        return AWRTC_PSA_TO_MBEDTLS_ERR(status);
    }

    *psk_len = AWRTC_PSA_BITS_TO_BYTES(awrtc_psa_get_key_bits(&key_attributes));
    *psk = awrtc_mbedtls_calloc(1, *psk_len);
    if (*psk == NULL) {
        return AWRTC_MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    status = awrtc_psa_export_key(ssl->handshake->psk_opaque,
                            (uint8_t *) *psk, *psk_len, psk_len);
    if (status != AWRTC_PSA_SUCCESS) {
        awrtc_mbedtls_free((void *) *psk);
        *psk = NULL;
        return AWRTC_PSA_TO_MBEDTLS_ERR(status);
    }
    return 0;
#else
    *psk = ssl->handshake->psk;
    *psk_len = ssl->handshake->psk_len;
    if (*psk == NULL) {
        return AWRTC_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    return 0;
#endif /* !AWRTC_MBEDTLS_USE_PSA_CRYPTO */
}
#endif /* AWRTC_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED */

#if defined(AWRTC_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
int awrtc_mbedtls_ssl_tls13_exporter(const awrtc_psa_algorithm_t hash_alg,
                               const unsigned char *secret, const size_t secret_len,
                               const unsigned char *label, const size_t label_len,
                               const unsigned char *context_value, const size_t context_len,
                               unsigned char *out, const size_t out_len)
{
    size_t hash_len = AWRTC_PSA_HASH_LENGTH(hash_alg);
    unsigned char hkdf_secret[AWRTC_MBEDTLS_TLS1_3_MD_MAX_SIZE];
    int ret = 0;

    ret = awrtc_mbedtls_ssl_tls13_derive_secret(hash_alg, secret, secret_len, label, label_len, NULL, 0,
                                          AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED, hkdf_secret,
                                          hash_len);
    if (ret != 0) {
        goto exit;
    }
    ret = awrtc_mbedtls_ssl_tls13_derive_secret(hash_alg,
                                          hkdf_secret,
                                          hash_len,
                                          AWRTC_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(exporter),
                                          context_value,
                                          context_len,
                                          AWRTC_MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                                          out,
                                          out_len);

exit:
    awrtc_mbedtls_platform_zeroize(hkdf_secret, sizeof(hkdf_secret));
    return ret;
}
#endif /* defined(AWRTC_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT) */

#endif /* AWRTC_MBEDTLS_SSL_PROTO_TLS1_3 */
