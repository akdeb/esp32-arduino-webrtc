/**
 * \file pk_wrap.h
 *
 * \brief Public Key abstraction layer: wrapper functions
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_MBEDTLS_PK_WRAP_H
#define AWRTC_MBEDTLS_PK_WRAP_H

#include "../include/mbedtls/build_info.h"

#include "../include/mbedtls/pk.h"

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
#include "../include/psa/crypto.h"
#endif

struct awrtc_mbedtls_pk_info_t {
    /** Public key type */
    awrtc_mbedtls_pk_type_t type;

    /** Type name */
    const char *name;

    /** Get key size in bits */
    size_t (*get_bitlen)(awrtc_mbedtls_pk_context *pk);

    /** Tell if the context implements this type (e.g. ECKEY can do ECDSA) */
    int (*can_do)(awrtc_mbedtls_pk_type_t type);

    /** Verify signature */
    int (*verify_func)(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len);

    /** Make signature */
    int (*sign_func)(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                     const unsigned char *hash, size_t hash_len,
                     unsigned char *sig, size_t sig_size, size_t *sig_len,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng);

#if defined(AWRTC_MBEDTLS_ECDSA_C) && defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    /** Verify signature (restartable) */
    int (*verify_rs_func)(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len,
                          void *rs_ctx);

    /** Make signature (restartable) */
    int (*sign_rs_func)(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        unsigned char *sig, size_t sig_size, size_t *sig_len,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng, void *rs_ctx);
#endif /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */

    /** Decrypt message */
    int (*decrypt_func)(awrtc_mbedtls_pk_context *pk, const unsigned char *input, size_t ilen,
                        unsigned char *output, size_t *olen, size_t osize,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);

    /** Encrypt message */
    int (*encrypt_func)(awrtc_mbedtls_pk_context *pk, const unsigned char *input, size_t ilen,
                        unsigned char *output, size_t *olen, size_t osize,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);

    /** Check public-private key pair */
    int (*check_pair_func)(awrtc_mbedtls_pk_context *pub, awrtc_mbedtls_pk_context *prv,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng);

    /** Allocate a new context */
    void * (*ctx_alloc_func)(void);

    /** Free the given context */
    void (*ctx_free_func)(void *ctx);

#if defined(AWRTC_MBEDTLS_ECDSA_C) && defined(AWRTC_MBEDTLS_ECP_RESTARTABLE)
    /** Allocate the restart context */
    void *(*rs_alloc_func)(void);

    /** Free the restart context */
    void (*rs_free_func)(void *rs_ctx);
#endif /* AWRTC_MBEDTLS_ECDSA_C && AWRTC_MBEDTLS_ECP_RESTARTABLE */

    /** Interface with the debug module */
    void (*debug_func)(awrtc_mbedtls_pk_context *pk, awrtc_mbedtls_pk_debug_item *items);

};
#if defined(AWRTC_MBEDTLS_PK_RSA_ALT_SUPPORT)
/* Container for RSA-alt */
typedef struct {
    void *key;
    awrtc_mbedtls_pk_rsa_alt_decrypt_func decrypt_func;
    awrtc_mbedtls_pk_rsa_alt_sign_func sign_func;
    awrtc_mbedtls_pk_rsa_alt_key_len_func key_len_func;
} awrtc_mbedtls_rsa_alt_context;
#endif

#if defined(AWRTC_MBEDTLS_RSA_C)
extern const awrtc_mbedtls_pk_info_t awrtc_mbedtls_rsa_info;
#endif

#if defined(AWRTC_MBEDTLS_PK_HAVE_ECC_KEYS)
extern const awrtc_mbedtls_pk_info_t awrtc_mbedtls_eckey_info;
extern const awrtc_mbedtls_pk_info_t awrtc_mbedtls_eckeydh_info;
#endif

#if defined(AWRTC_MBEDTLS_PK_CAN_ECDSA_SOME)
extern const awrtc_mbedtls_pk_info_t awrtc_mbedtls_ecdsa_info;
#endif

#if defined(AWRTC_MBEDTLS_PK_RSA_ALT_SUPPORT)
extern const awrtc_mbedtls_pk_info_t awrtc_mbedtls_rsa_alt_info;
#endif

#if defined(AWRTC_MBEDTLS_USE_PSA_CRYPTO)
extern const awrtc_mbedtls_pk_info_t awrtc_mbedtls_ecdsa_opaque_info;
extern const awrtc_mbedtls_pk_info_t awrtc_mbedtls_rsa_opaque_info;

#if defined(AWRTC_MBEDTLS_RSA_C)
int awrtc_mbedtls_pk_psa_rsa_sign_ext(awrtc_psa_algorithm_t awrtc_psa_alg_md,
                                awrtc_mbedtls_rsa_context *rsa_ctx,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size,
                                size_t *sig_len);
#endif /* AWRTC_MBEDTLS_RSA_C */

#endif /* AWRTC_MBEDTLS_USE_PSA_CRYPTO */

#endif /* AWRTC_MBEDTLS_PK_WRAP_H */
