/**
 * \file x509.h
 *
 * \brief Internal part of the public "x509.h".
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef AWRTC_MBEDTLS_X509_INTERNAL_H
#define AWRTC_MBEDTLS_X509_INTERNAL_H
#include "../include/mbedtls/private_access.h"

#include "../include/mbedtls/build_info.h"

#include "../include/mbedtls/x509.h"
#include "../include/mbedtls/asn1.h"
#include "pk_internal.h"

#if defined(AWRTC_MBEDTLS_RSA_C)
#include "../include/mbedtls/rsa.h"
#endif

int awrtc_mbedtls_x509_get_name(unsigned char **p, const unsigned char *end,
                          awrtc_mbedtls_x509_name *cur);
int awrtc_mbedtls_x509_get_alg_null(unsigned char **p, const unsigned char *end,
                              awrtc_mbedtls_x509_buf *alg);
int awrtc_mbedtls_x509_get_alg(unsigned char **p, const unsigned char *end,
                         awrtc_mbedtls_x509_buf *alg, awrtc_mbedtls_x509_buf *params);
#if defined(AWRTC_MBEDTLS_X509_RSASSA_PSS_SUPPORT)
int awrtc_mbedtls_x509_get_rsassa_pss_params(const awrtc_mbedtls_x509_buf *params,
                                       awrtc_mbedtls_md_type_t *md_alg, awrtc_mbedtls_md_type_t *mgf_md,
                                       int *salt_len);
#endif
int awrtc_mbedtls_x509_get_sig(unsigned char **p, const unsigned char *end, awrtc_mbedtls_x509_buf *sig);
int awrtc_mbedtls_x509_get_sig_alg(const awrtc_mbedtls_x509_buf *sig_oid, const awrtc_mbedtls_x509_buf *sig_params,
                             awrtc_mbedtls_md_type_t *md_alg, awrtc_mbedtls_pk_type_t *pk_alg,
                             void **sig_opts);
int awrtc_mbedtls_x509_get_time(unsigned char **p, const unsigned char *end,
                          awrtc_mbedtls_x509_time *t);
int awrtc_mbedtls_x509_get_serial(unsigned char **p, const unsigned char *end,
                            awrtc_mbedtls_x509_buf *serial);
int awrtc_mbedtls_x509_get_ext(unsigned char **p, const unsigned char *end,
                         awrtc_mbedtls_x509_buf *ext, int tag);
#if !defined(AWRTC_MBEDTLS_X509_REMOVE_INFO)
int awrtc_mbedtls_x509_sig_alg_gets(char *buf, size_t size, const awrtc_mbedtls_x509_buf *sig_oid,
                              awrtc_mbedtls_pk_type_t pk_alg, awrtc_mbedtls_md_type_t md_alg,
                              const void *sig_opts);
#endif
int awrtc_mbedtls_x509_key_size_helper(char *buf, size_t buf_size, const char *name);
int awrtc_mbedtls_x509_set_extension(awrtc_mbedtls_asn1_named_data **head, const char *oid, size_t oid_len,
                               int critical, const unsigned char *val,
                               size_t val_len);
int awrtc_mbedtls_x509_write_extensions(unsigned char **p, unsigned char *start,
                                  awrtc_mbedtls_asn1_named_data *first);
int awrtc_mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             awrtc_mbedtls_asn1_named_data *first);
int awrtc_mbedtls_x509_write_sig(unsigned char **p, unsigned char *start,
                           const char *oid, size_t oid_len,
                           unsigned char *sig, size_t size,
                           awrtc_mbedtls_pk_type_t pk_alg);
int awrtc_mbedtls_x509_get_ns_cert_type(unsigned char **p,
                                  const unsigned char *end,
                                  unsigned char *ns_cert_type);
int awrtc_mbedtls_x509_get_key_usage(unsigned char **p,
                               const unsigned char *end,
                               unsigned int *key_usage);
int awrtc_mbedtls_x509_get_subject_alt_name(unsigned char **p,
                                      const unsigned char *end,
                                      awrtc_mbedtls_x509_sequence *subject_alt_name);
int awrtc_mbedtls_x509_get_subject_alt_name_ext(unsigned char **p,
                                          const unsigned char *end,
                                          awrtc_mbedtls_x509_sequence *subject_alt_name);
int awrtc_mbedtls_x509_info_subject_alt_name(char **buf, size_t *size,
                                       const awrtc_mbedtls_x509_sequence
                                       *subject_alt_name,
                                       const char *prefix);
int awrtc_mbedtls_x509_info_cert_type(char **buf, size_t *size,
                                unsigned char ns_cert_type);
int awrtc_mbedtls_x509_info_key_usage(char **buf, size_t *size,
                                unsigned int key_usage);

int awrtc_mbedtls_x509_write_set_san_common(awrtc_mbedtls_asn1_named_data **extensions,
                                      const awrtc_mbedtls_x509_san_list *san_list);

#endif /* AWRTC_MBEDTLS_X509_INTERNAL_H */
