/*
 *  ECC setters for PK.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#include "../include/mbedtls/pk.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/ecp.h"
#include "pk_internal.h"

#if defined(AWRTC_MBEDTLS_PK_C) && defined(AWRTC_MBEDTLS_PK_HAVE_ECC_KEYS)

int awrtc_mbedtls_pk_ecc_set_group(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_ecp_group_id grp_id)
{
#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
    size_t ec_bits;
    awrtc_psa_ecc_family_t ec_family = awrtc_mbedtls_ecc_group_to_psa(grp_id, &ec_bits);

    /* group may already be initialized; if so, make sure IDs match */
    if ((pk->ec_family != 0 && pk->ec_family != ec_family) ||
        (pk->ec_bits != 0 && pk->ec_bits != ec_bits)) {
        return AWRTC_MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

    /* set group */
    pk->ec_family = ec_family;
    pk->ec_bits = ec_bits;

    return 0;
#else /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
    awrtc_mbedtls_ecp_keypair *ecp = awrtc_mbedtls_pk_ec_rw(*pk);

    /* grp may already be initialized; if so, make sure IDs match */
    if (awrtc_mbedtls_pk_ec_ro(*pk)->grp.id != AWRTC_MBEDTLS_ECP_DP_NONE &&
        awrtc_mbedtls_pk_ec_ro(*pk)->grp.id != grp_id) {
        return AWRTC_MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

    /* set group */
    return awrtc_mbedtls_ecp_group_load(&(ecp->grp), grp_id);
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
}

int awrtc_mbedtls_pk_ecc_set_key(awrtc_mbedtls_pk_context *pk, unsigned char *key, size_t key_len)
{
#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_psa_key_usage_t flags;
    awrtc_psa_status_t status;

    awrtc_psa_set_key_type(&attributes, AWRTC_PSA_KEY_TYPE_ECC_KEY_PAIR(pk->ec_family));
    if (pk->ec_family == AWRTC_PSA_ECC_FAMILY_MONTGOMERY) {
        /* Do not set algorithm here because Montgomery keys cannot do ECDSA and
         * the PK module cannot do ECDH. When the key will be used in TLS for
         * ECDH, it will be exported and then re-imported with proper flags
         * and algorithm. */
        flags = AWRTC_PSA_KEY_USAGE_EXPORT;
    } else {
        awrtc_psa_set_key_algorithm(&attributes,
                              AWRTC_MBEDTLS_PK_PSA_ALG_ECDSA_MAYBE_DET(AWRTC_PSA_ALG_ANY_HASH));
        flags = AWRTC_PSA_KEY_USAGE_SIGN_HASH | AWRTC_PSA_KEY_USAGE_SIGN_MESSAGE |
                AWRTC_PSA_KEY_USAGE_EXPORT;
    }
    awrtc_psa_set_key_usage_flags(&attributes, flags);

    status = awrtc_psa_import_key(&attributes, key, key_len, &pk->priv_id);
    return awrtc_psa_pk_status_to_mbedtls(status);

#else /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */

    awrtc_mbedtls_ecp_keypair *eck = awrtc_mbedtls_pk_ec_rw(*pk);
    int ret = awrtc_mbedtls_ecp_read_key(eck->grp.id, eck, key, key_len);
    if (ret != 0) {
        return AWRTC_MBEDTLS_ERROR_ADD(AWRTC_MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }
    return 0;
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
}

int awrtc_mbedtls_pk_ecc_set_pubkey_from_prv(awrtc_mbedtls_pk_context *pk,
                                       const unsigned char *prv, size_t prv_len,
                                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)

    (void) f_rng;
    (void) p_rng;
    (void) prv;
    (void) prv_len;
    awrtc_psa_status_t status;

    status = awrtc_psa_export_public_key(pk->priv_id, pk->pub_raw, sizeof(pk->pub_raw),
                                   &pk->pub_raw_len);
    return awrtc_psa_pk_status_to_mbedtls(status);

#elif defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO) /* && !AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */

    (void) f_rng;
    (void) p_rng;
    awrtc_psa_status_t status;

    awrtc_mbedtls_ecp_keypair *eck = (awrtc_mbedtls_ecp_keypair *) pk->pk_ctx;
    size_t curve_bits;
    awrtc_psa_ecc_family_t curve = awrtc_mbedtls_ecc_group_to_psa(eck->grp.id, &curve_bits);

    /* Import private key into PSA, from serialized input */
    awrtc_mbedtls_svc_key_id_t key_id = AWRTC_MBEDTLS_SVC_KEY_ID_INIT;
    awrtc_psa_key_attributes_t key_attr = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_psa_set_key_type(&key_attr, AWRTC_PSA_KEY_TYPE_ECC_KEY_PAIR(curve));
    awrtc_psa_set_key_usage_flags(&key_attr, AWRTC_PSA_KEY_USAGE_EXPORT);
    status = awrtc_psa_import_key(&key_attr, prv, prv_len, &key_id);
    if (status != AWRTC_PSA_SUCCESS) {
        return awrtc_psa_pk_status_to_mbedtls(status);
    }

    /* Export public key from PSA */
    unsigned char pub[AWRTC_MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t pub_len;
    status = awrtc_psa_export_public_key(key_id, pub, sizeof(pub), &pub_len);
    awrtc_psa_status_t destruction_status = awrtc_psa_destroy_key(key_id);
    if (status != AWRTC_PSA_SUCCESS) {
        return awrtc_psa_pk_status_to_mbedtls(status);
    } else if (destruction_status != AWRTC_PSA_SUCCESS) {
        return awrtc_psa_pk_status_to_mbedtls(destruction_status);
    }

    /* Load serialized public key into ecp_keypair structure */
    return awrtc_mbedtls_ecp_point_read_binary(&eck->grp, &eck->Q, pub, pub_len);

#else /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

    (void) prv;
    (void) prv_len;

    awrtc_mbedtls_ecp_keypair *eck = (awrtc_mbedtls_ecp_keypair *) pk->pk_ctx;
    return awrtc_mbedtls_ecp_mul(&eck->grp, &eck->Q, &eck->d, &eck->grp.G, f_rng, p_rng);

#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */
}

#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)
/*
 * Set the public key: fallback using ECP_LIGHT in the USE_PSA_EC_DATA case.
 *
 * Normally, when AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA is enabled, we only use PSA
 * functions to handle keys. However, currently awrtc_psa_import_key() does not
 * support compressed points. In case that support was explicitly requested,
 * this fallback uses ECP functions to get the job done. This is the reason
 * why AWRTC_MBEDTLS_PK_PARSE_EC_COMPRESSED auto-enables AWRTC_MBEDTLS_ECP_LIGHT.
 *
 * [in/out] pk: in: must have the group set, see awrtc_mbedtls_pk_ecc_set_group().
 *              out: will have the public key set.
 * [in] pub, pub_len: the public key as an ECPoint,
 *                    in any format supported by ECP.
 *
 * Return:
 * - 0 on success;
 * - AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if the format is potentially valid
 *   but not supported;
 * - another error code otherwise.
 */
static int pk_ecc_set_pubkey_psa_ecp_fallback(awrtc_mbedtls_pk_context *pk,
                                              const unsigned char *pub,
                                              size_t pub_len)
{
#if !defined(AWRTC_MBEDTLS_PK_PARSE_EC_COMPRESSED)
    (void) pk;
    (void) pub;
    (void) pub_len;
    return AWRTC_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
#else /* AWRTC_MBEDTLS_PK_PARSE_EC_COMPRESSED */
    awrtc_mbedtls_ecp_keypair ecp_key;
    awrtc_mbedtls_ecp_group_id ecp_group_id;
    int ret;

    ecp_group_id = awrtc_mbedtls_ecc_group_from_psa(pk->ec_family, pk->ec_bits);

    awrtc_mbedtls_ecp_keypair_init(&ecp_key);
    ret = awrtc_mbedtls_ecp_group_load(&(ecp_key.grp), ecp_group_id);
    if (ret != 0) {
        goto exit;
    }
    ret = awrtc_mbedtls_ecp_point_read_binary(&(ecp_key.grp), &ecp_key.Q,
                                        pub, pub_len);
    if (ret != 0) {
        goto exit;
    }
    ret = awrtc_mbedtls_ecp_point_write_binary(&(ecp_key.grp), &ecp_key.Q,
                                         AWRTC_MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &pk->pub_raw_len, pk->pub_raw,
                                         sizeof(pk->pub_raw));

exit:
    awrtc_mbedtls_ecp_keypair_free(&ecp_key);
    return ret;
#endif /* AWRTC_MBEDTLS_PK_PARSE_EC_COMPRESSED */
}
#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */

int awrtc_mbedtls_pk_ecc_set_pubkey(awrtc_mbedtls_pk_context *pk, const unsigned char *pub, size_t pub_len)
{
#if defined(AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA)

    /* Load the key */
    if (!AWRTC_PSA_ECC_FAMILY_IS_WEIERSTRASS(pk->ec_family) || *pub == 0x04) {
        /* Format directly supported by PSA:
         * - non-Weierstrass curves that only have one format;
         * - uncompressed format for Weierstrass curves. */
        if (pub_len > sizeof(pk->pub_raw)) {
            return AWRTC_MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
        }
        memcpy(pk->pub_raw, pub, pub_len);
        pk->pub_raw_len = pub_len;
    } else {
        /* Other format, try the fallback */
        int ret = pk_ecc_set_pubkey_psa_ecp_fallback(pk, pub, pub_len);
        if (ret != 0) {
            return ret;
        }
    }

    /* Validate the key by trying to import it */
    awrtc_mbedtls_svc_key_id_t key_id = AWRTC_MBEDTLS_SVC_KEY_ID_INIT;
    awrtc_psa_key_attributes_t key_attrs = AWRTC_PSA_KEY_ATTRIBUTES_INIT;

    awrtc_psa_set_key_usage_flags(&key_attrs, 0);
    awrtc_psa_set_key_type(&key_attrs, AWRTC_PSA_KEY_TYPE_ECC_PUBLIC_KEY(pk->ec_family));
    awrtc_psa_set_key_bits(&key_attrs, pk->ec_bits);

    if ((awrtc_psa_import_key(&key_attrs, pk->pub_raw, pk->pub_raw_len,
                        &key_id) != AWRTC_PSA_SUCCESS) ||
        (awrtc_psa_destroy_key(key_id) != AWRTC_PSA_SUCCESS)) {
        return AWRTC_MBEDTLS_ERR_PK_INVALID_PUBKEY;
    }

    return 0;

#else /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */

    int ret;
    awrtc_mbedtls_ecp_keypair *ec_key = (awrtc_mbedtls_ecp_keypair *) pk->pk_ctx;
    ret = awrtc_mbedtls_ecp_point_read_binary(&ec_key->grp, &ec_key->Q, pub, pub_len);
    if (ret != 0) {
        return ret;
    }
    return awrtc_mbedtls_ecp_check_pubkey(&ec_key->grp, &ec_key->Q);

#endif /* AWRTC_MBEDTLS_PK_USE_PSA_EC_DATA */
}

#endif /* AWRTC_MBEDTLS_PK_C && AWRTC_MBEDTLS_PK_HAVE_ECC_KEYS */
