/*
 * SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO., LTD
 * SPDX-License-Identifier: LicenseRef-Espressif-Modified-MIT
 *
 * See LICENSE file for details.
 */

// #define DUMP_DTLS_KEY
#include "dtls_common.h"
#include "../tls/include/mbedtls/ecp.h"

static int dtls_srtp_selfsign_cert(dtls_srtp_t *dtls_srtp, bool export_for_cache)
{
    int ret;
    awrtc_mbedtls_x509write_cert crt;
    unsigned char *cert_buf = (unsigned char *)malloc(DTLS_CERT_PEM_BUF_SIZE);
    if (cert_buf == NULL) {
        return -1;
    }
    const char *pers = "dtls_srtp";

    awrtc_mbedtls_x509write_crt_init(&crt);
    ret = awrtc_mbedtls_ctr_drbg_seed(&dtls_srtp->ctr_drbg, dtls_srtp_entropy_func, NULL, (const unsigned char *)pers,
                                strlen(pers));
    if (ret != 0) {
        ESP_LOGE(TAG, "awrtc_mbedtls_ctr_drbg_seed failed, ret=%d", ret);
        goto _exit;
    }
    ret = awrtc_mbedtls_pk_setup(&dtls_srtp->pkey, awrtc_mbedtls_pk_info_from_type(AWRTC_MBEDTLS_PK_ECKEY));
    if (ret != 0) {
        ESP_LOGE(TAG, "awrtc_mbedtls_pk_setup(ECKEY) failed, ret=%d", ret);
        goto _exit;
    }
    ret = awrtc_mbedtls_ecp_gen_key(AWRTC_MBEDTLS_ECP_DP_SECP256R1, awrtc_mbedtls_pk_ec(dtls_srtp->pkey),
                              awrtc_mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "awrtc_mbedtls_ecp_gen_key failed, ret=%d", ret);
        goto _exit;
    }

    awrtc_mbedtls_x509write_crt_set_version(&crt, AWRTC_MBEDTLS_X509_CRT_VERSION_3);
    awrtc_mbedtls_x509write_crt_set_md_alg(&crt, AWRTC_MBEDTLS_MD_SHA256);
    awrtc_mbedtls_x509write_crt_set_subject_name(&crt, "CN=dtls_srtp");
    awrtc_mbedtls_x509write_crt_set_issuer_name(&crt, "CN=dtls_srtp");

#if AWRTC_MBEDTLS_VERSION_MAJOR == 3 && AWRTC_MBEDTLS_VERSION_MINOR >= 4 || AWRTC_MBEDTLS_VERSION_MAJOR >= 4
    unsigned char *serial = (unsigned char *)"1";
    size_t serial_len = 1;
    ret = awrtc_mbedtls_x509write_crt_set_serial_raw(&crt, serial, serial_len);
    if (ret < 0) {
        printf("awrtc_mbedtls_x509write_crt_set_serial_raw failed\n");
    }
#else
    awrtc_mbedtls_mpi serial;
    awrtc_mbedtls_mpi_init(&serial);
    awrtc_mbedtls_mpi_fill_random(&serial, 16, awrtc_mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);
    awrtc_mbedtls_x509write_crt_set_serial(&crt, &serial);
    awrtc_mbedtls_mpi_free(&serial);
#endif

    awrtc_mbedtls_x509write_crt_set_validity(&crt, "20230101000000", "20400101000000");
    awrtc_mbedtls_x509write_crt_set_subject_key(&crt, &dtls_srtp->pkey);
    awrtc_mbedtls_x509write_crt_set_issuer_key(&crt, &dtls_srtp->pkey);
    ret = awrtc_mbedtls_x509write_crt_pem(&crt, cert_buf, DTLS_CERT_PEM_BUF_SIZE, awrtc_mbedtls_ctr_drbg_random,
                                    &dtls_srtp->ctr_drbg);
    if (ret < 0) {
        ESP_LOGE(TAG, "awrtc_mbedtls_x509write_crt_pem failed");
        goto _exit;
    }
    ret = awrtc_mbedtls_x509_crt_parse(&dtls_srtp->cert, cert_buf, DTLS_CERT_PEM_BUF_SIZE);
    if (ret != 0) {
        ESP_LOGE(TAG, "awrtc_mbedtls_x509_crt_parse failed, ret=%d", ret);
        goto _exit;
    }
    if (export_for_cache) {
#ifdef DTLS_SIGN_ONCE
        ret = awrtc_mbedtls_pk_write_key_pem(&dtls_srtp->pkey, s_cached_key_pem, sizeof(s_cached_key_pem));
        if (ret != 0) {
            ESP_LOGE(TAG, "awrtc_mbedtls_pk_write_key_pem failed, ret=%d", ret);
            goto _exit;
        }
        memcpy(s_cached_cert_pem, cert_buf, sizeof(s_cached_cert_pem));
        s_cached_cert_ready = true;
#endif
    }
    ret = 0;
_exit:
    awrtc_mbedtls_x509write_crt_free(&crt);
    free(cert_buf);
    return ret;
}

static int dtls_srtp_try_gen_cert(dtls_srtp_t *dtls_srtp)
{
    int ret = 0;
    awrtc_mbedtls_x509_crt_init(&dtls_srtp->cert);
    awrtc_mbedtls_pk_init(&dtls_srtp->pkey);
    awrtc_mbedtls_ctr_drbg_init(&dtls_srtp->ctr_drbg);
    const char *pers = "dtls_srtp";
    ret = awrtc_mbedtls_ctr_drbg_seed(&dtls_srtp->ctr_drbg, dtls_srtp_entropy_func, NULL, (const unsigned char *)pers,
                                strlen(pers));
    if (ret != 0) {
        ESP_LOGE(TAG, "awrtc_mbedtls_ctr_drbg_seed failed, ret=%d", ret);
        return ret;
    }
#ifdef DTLS_SIGN_ONCE
    if (s_cached_cert_ready) {
        size_t cert_pem_len = strlen((const char *)s_cached_cert_pem) + 1;
        size_t key_pem_len = strlen((const char *)s_cached_key_pem) + 1;
        ret = awrtc_mbedtls_x509_crt_parse(&dtls_srtp->cert, s_cached_cert_pem, cert_pem_len);
        if (ret == 0) {
            ret = awrtc_mbedtls_pk_parse_key(&dtls_srtp->pkey, s_cached_key_pem, key_pem_len, NULL, 0,
                                       awrtc_mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);
        }
        if (ret == 0) {
            return 0;
        }
        ESP_LOGE(TAG, "Use cached cert/key failed, fallback to regenerate, ret=%d", ret);
    }
#endif
    ret = dtls_srtp_selfsign_cert(dtls_srtp, true);
    if (ret != 0) {
        return ret;
    }
    return 0;
}

int dtls_srtp_gen_cert(void)
{
#ifdef DTLS_SIGN_ONCE
    dtls_srtp_t *dtls_srtp = (dtls_srtp_t *) media_lib_calloc(1, sizeof(dtls_srtp_t));
    if (dtls_srtp == NULL) {
        return -1;
    }
    awrtc_mbedtls_x509_crt_init(&dtls_srtp->cert);
    awrtc_mbedtls_pk_init(&dtls_srtp->pkey);
    awrtc_mbedtls_ctr_drbg_init(&dtls_srtp->ctr_drbg);
    int ret = dtls_srtp_selfsign_cert(dtls_srtp, true);
    awrtc_mbedtls_x509_crt_free(&dtls_srtp->cert);
    awrtc_mbedtls_pk_free(&dtls_srtp->pkey);
    awrtc_mbedtls_ctr_drbg_free(&dtls_srtp->ctr_drbg);
    media_lib_free(dtls_srtp);
    return ret;
#else
    return -1;
#endif
}

dtls_srtp_t *dtls_srtp_init(dtls_srtp_cfg_t *cfg)
{
    dtls_srtp_t *dtls_srtp = (dtls_srtp_t *) media_lib_calloc(1, sizeof(dtls_srtp_t));
    if (dtls_srtp == NULL) {
        return NULL;
    }
    int ret = check_srtp(true);
    if (ret != 0) { media_lib_free(dtls_srtp); return NULL; }
    do {
        BREAK_ON_FAIL(ret);
        if (media_lib_mutex_create(&dtls_srtp->lock) != 0) { check_srtp(false); media_lib_free(dtls_srtp); return NULL; }
        dtls_srtp->role = cfg->role;
        dtls_srtp->state = DTLS_SRTP_STATE_INIT;
        dtls_srtp->ctx = cfg->ctx;
        dtls_srtp->udp_send = cfg->udp_send;
        dtls_srtp->udp_recv = cfg->udp_recv;

        awrtc_mbedtls_ssl_config_init(&dtls_srtp->conf);
        awrtc_mbedtls_ssl_init(&dtls_srtp->ssl);
        ret = dtls_srtp_try_gen_cert(dtls_srtp);
        BREAK_ON_FAIL(ret);

        if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {
            ret = awrtc_mbedtls_ssl_config_defaults(&dtls_srtp->conf, AWRTC_MBEDTLS_SSL_IS_SERVER, AWRTC_MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                              AWRTC_MBEDTLS_SSL_PRESET_DEFAULT);
            awrtc_mbedtls_ssl_cookie_init(&dtls_srtp->cookie_ctx);
            awrtc_mbedtls_ssl_cookie_setup(&dtls_srtp->cookie_ctx, awrtc_mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);
            awrtc_mbedtls_ssl_conf_dtls_cookies(&dtls_srtp->conf, awrtc_mbedtls_ssl_cookie_write, awrtc_mbedtls_ssl_cookie_check,
                                          &dtls_srtp->cookie_ctx);
        } else {
            ret = awrtc_mbedtls_ssl_config_defaults(&dtls_srtp->conf, AWRTC_MBEDTLS_SSL_IS_CLIENT, AWRTC_MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                              AWRTC_MBEDTLS_SSL_PRESET_DEFAULT);
        }
        BREAK_ON_FAIL(ret);

        dtls_srtp_conf_force_dtls12(&dtls_srtp->conf);
        awrtc_mbedtls_ssl_conf_ca_chain(&dtls_srtp->conf, &dtls_srtp->cert, NULL);
        awrtc_mbedtls_ssl_conf_authmode(&dtls_srtp->conf, AWRTC_MBEDTLS_SSL_VERIFY_OPTIONAL);
        ret = awrtc_mbedtls_ssl_conf_own_cert(&dtls_srtp->conf, &dtls_srtp->cert, &dtls_srtp->pkey);
        BREAK_ON_FAIL(ret);
        awrtc_mbedtls_ssl_conf_rng(&dtls_srtp->conf, awrtc_mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);
        if (dtls_srtp->role == DTLS_SRTP_ROLE_CLIENT) {
            awrtc_mbedtls_ssl_conf_authmode(&dtls_srtp->conf, AWRTC_MBEDTLS_SSL_VERIFY_OPTIONAL);
        }
        awrtc_mbedtls_ssl_conf_read_timeout(&dtls_srtp->conf, 1000);
        awrtc_mbedtls_ssl_conf_handshake_timeout(&dtls_srtp->conf, 1000, 6000);
        awrtc_mbedtls_ssl_conf_dtls_anti_replay(&dtls_srtp->conf, AWRTC_MBEDTLS_SSL_ANTI_REPLAY_DISABLED);

        dtls_srtp_x509_digest(&dtls_srtp->cert, dtls_srtp->local_fingerprint);
        ret = awrtc_mbedtls_ssl_conf_dtls_srtp_protection_profiles(&dtls_srtp->conf, default_profiles);
        BREAK_ON_FAIL(ret);

        awrtc_mbedtls_ssl_conf_srtp_mki_value_supported(&dtls_srtp->conf, AWRTC_MBEDTLS_SSL_DTLS_SRTP_MKI_UNSUPPORTED);
        ret = awrtc_mbedtls_ssl_setup(&dtls_srtp->ssl, &dtls_srtp->conf);
        BREAK_ON_FAIL(ret);
        awrtc_mbedtls_ssl_set_mtu(&dtls_srtp->ssl, DTLS_MTU_SIZE);
        return dtls_srtp;
    } while (0);
    dtls_srtp_deinit(dtls_srtp);
    return NULL;
}

void dtls_srtp_deinit(dtls_srtp_t *dtls_srtp)
{
    if (dtls_srtp->state == DTLS_SRTP_STATE_NONE) {
        return;
    }
    awrtc_mbedtls_ssl_free(&dtls_srtp->ssl);
    awrtc_mbedtls_ssl_config_free(&dtls_srtp->conf);

    awrtc_mbedtls_x509_crt_free(&dtls_srtp->cert);
    awrtc_mbedtls_pk_free(&dtls_srtp->pkey);
    awrtc_mbedtls_ctr_drbg_free(&dtls_srtp->ctr_drbg);

    if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {
        awrtc_mbedtls_ssl_cookie_free(&dtls_srtp->cookie_ctx);
    }
#if defined(DTLS_USE_CH_REASM_BIO)
    dtls_srtp_ch_reasm_free(dtls_srtp);
#endif
    if (dtls_srtp->srtp_in) {
        srtp_dealloc(dtls_srtp->srtp_in);
        dtls_srtp->srtp_in = NULL;
    }
    if (dtls_srtp->srtp_out) {
        srtp_dealloc(dtls_srtp->srtp_out);
        dtls_srtp->srtp_out = NULL;
    }
    if (dtls_srtp->lock) {
        media_lib_mutex_destroy(dtls_srtp->lock);
    }
    check_srtp(false);
    dtls_srtp->state = DTLS_SRTP_STATE_NONE;
    media_lib_free(dtls_srtp);
}

void dtls_srtp_reset_session(dtls_srtp_t *dtls_srtp, dtls_srtp_role_t role)
{
    if (dtls_srtp->state == DTLS_SRTP_STATE_CONNECTED) {
        srtp_dealloc(dtls_srtp->srtp_in);
        dtls_srtp->srtp_in = NULL;
        srtp_dealloc(dtls_srtp->srtp_out);
        dtls_srtp->srtp_out = NULL;
    }
    awrtc_mbedtls_ssl_session_reset(&dtls_srtp->ssl);
    awrtc_mbedtls_timing_set_delay(&dtls_srtp->timer, 0, 0);
#if defined(DTLS_USE_CH_REASM_BIO)
    dtls_srtp_ch_reasm_free(dtls_srtp);
#endif
    if (role != dtls_srtp->role) {
        if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {
            awrtc_mbedtls_ssl_cookie_free(&dtls_srtp->cookie_ctx);
        }
        if (role == DTLS_SRTP_ROLE_SERVER) {
            awrtc_mbedtls_ssl_config_defaults(&dtls_srtp->conf, AWRTC_MBEDTLS_SSL_IS_SERVER, AWRTC_MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                        AWRTC_MBEDTLS_SSL_PRESET_DEFAULT);
            dtls_srtp_conf_force_dtls12(&dtls_srtp->conf);

            awrtc_mbedtls_ssl_cookie_init(&dtls_srtp->cookie_ctx);
            awrtc_mbedtls_ssl_cookie_setup(&dtls_srtp->cookie_ctx, awrtc_mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);
            awrtc_mbedtls_ssl_conf_dtls_cookies(&dtls_srtp->conf, awrtc_mbedtls_ssl_cookie_write, awrtc_mbedtls_ssl_cookie_check,
                                          &dtls_srtp->cookie_ctx);
        } else {
            awrtc_mbedtls_ssl_config_defaults(&dtls_srtp->conf, AWRTC_MBEDTLS_SSL_IS_CLIENT, AWRTC_MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                        AWRTC_MBEDTLS_SSL_PRESET_DEFAULT);
            dtls_srtp_conf_force_dtls12(&dtls_srtp->conf);
            awrtc_mbedtls_ssl_conf_authmode(&dtls_srtp->conf, AWRTC_MBEDTLS_SSL_VERIFY_OPTIONAL);
        }
        awrtc_mbedtls_ssl_conf_ca_chain(&dtls_srtp->conf, &dtls_srtp->cert, NULL);
        awrtc_mbedtls_ssl_conf_authmode(&dtls_srtp->conf, AWRTC_MBEDTLS_SSL_VERIFY_OPTIONAL);
        awrtc_mbedtls_ssl_conf_own_cert(&dtls_srtp->conf, &dtls_srtp->cert, &dtls_srtp->pkey);
        awrtc_mbedtls_ssl_conf_rng(&dtls_srtp->conf, awrtc_mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);
        awrtc_mbedtls_ssl_conf_read_timeout(&dtls_srtp->conf, 1000);
        awrtc_mbedtls_ssl_conf_handshake_timeout(&dtls_srtp->conf, 1000, 6000);
        awrtc_mbedtls_ssl_conf_dtls_srtp_protection_profiles(&dtls_srtp->conf, default_profiles);
        awrtc_mbedtls_ssl_conf_srtp_mki_value_supported(&dtls_srtp->conf, AWRTC_MBEDTLS_SSL_DTLS_SRTP_MKI_UNSUPPORTED);
        awrtc_mbedtls_ssl_conf_dtls_anti_replay(&dtls_srtp->conf, AWRTC_MBEDTLS_SSL_ANTI_REPLAY_DISABLED);
        awrtc_mbedtls_ssl_free(&dtls_srtp->ssl);
        awrtc_mbedtls_ssl_init(&dtls_srtp->ssl);
        awrtc_mbedtls_ssl_setup(&dtls_srtp->ssl, &dtls_srtp->conf);
        awrtc_mbedtls_ssl_set_mtu(&dtls_srtp->ssl, DTLS_MTU_SIZE);
        dtls_srtp->role = role;
    }
    dtls_srtp->state = DTLS_SRTP_STATE_INIT;
}
