// Exercise the actual private TLS configuration without an ESP32. No network.
#include "vendor/tls/include/mbedtls/ssl.h"
#include "vendor/tls/include/mbedtls/ctr_drbg.h"
#include "vendor/tls/include/mbedtls/x509_crt.h"
#include "vendor/tls/include/mbedtls/pk.h"
#include "vendor/tls/include/mbedtls/ecp.h"
#include "vendor/tls/include/mbedtls/platform_time.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define M(n) awrtc_mbedtls_##n
M(ms_time_t) M(ms_time)(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static int entropy(void* ctx, unsigned char* data, size_t n) {
    (void)ctx;
    FILE* file = fopen("/dev/urandom", "rb");
    if (!file) return -1;
    size_t count = fread(data, 1, n, file); fclose(file);
    return count == n ? 0 : -1;
}
typedef struct { unsigned char data[16][1600]; size_t size[16]; unsigned head, count; } Packets;
typedef struct { Packets *in, *out; } Link;
static int send_packet(void* ctx, const unsigned char* data, size_t n) {
    Packets* p=((Link*)ctx)->out;
    if (p->count == 16) return AWRTC_MBEDTLS_ERR_SSL_WANT_WRITE;
    assert(n <= 1600);
    unsigned at = (p->head + p->count++) % 16;
    memcpy(p->data[at], data, n); p->size[at] = n;
    return (int)n;
}
static int recv_packet(void* ctx, unsigned char* data, size_t n) {
    Packets* p=((Link*)ctx)->in;
    if (!p->count) return AWRTC_MBEDTLS_ERR_SSL_WANT_READ;
    size_t len=p->size[p->head]; assert(len <= n);
    memcpy(data,p->data[p->head],len); p->head=(p->head+1)%16; --p->count;
    return (int)len;
}
typedef struct { int64_t start; uint32_t intermediate, final; } Timer;
static void set_timer(void* ctx,uint32_t i,uint32_t f) { Timer* t=ctx;t->start=M(ms_time)();t->intermediate=i;t->final=f; }
static int get_timer(void* ctx) { Timer* t=ctx;if(!t->final)return -1;int64_t elapsed=M(ms_time)()-t->start;return elapsed>=t->final?2:(elapsed>=t->intermediate?1:0); }
int main(void) {
    M(ctr_drbg_context) rng;
    M(ctr_drbg_init)(&rng);
    assert(M(ctr_drbg_seed)(&rng, entropy, NULL, (const unsigned char*)"test", 4)==0);
    M(pk_context) key; M(pk_init)(&key);
    assert(M(pk_setup)(&key,M(pk_info_from_type)(AWRTC_MBEDTLS_PK_ECKEY))==0);
    assert(M(ecp_gen_key)(AWRTC_MBEDTLS_ECP_DP_SECP256R1,M(pk_ec)(key),M(ctr_drbg_random),&rng)==0);
    M(x509write_cert) cert; M(x509write_crt_init)(&cert);
    M(x509write_crt_set_version)(&cert,AWRTC_MBEDTLS_X509_CRT_VERSION_3);
    M(x509write_crt_set_md_alg)(&cert,AWRTC_MBEDTLS_MD_SHA256);
    assert(M(x509write_crt_set_subject_name)(&cert,"CN=loopback")==0);
    assert(M(x509write_crt_set_issuer_name)(&cert,"CN=loopback")==0);
    unsigned char serial=1;
    assert(M(x509write_crt_set_serial_raw)(&cert,&serial,1)==0);
    assert(M(x509write_crt_set_validity)(&cert,"20230101000000","20400101000000")==0);
    M(x509write_crt_set_subject_key)(&cert,&key);M(x509write_crt_set_issuer_key)(&cert,&key);
    unsigned char pem[2048];
    assert(M(x509write_crt_pem)(&cert,pem,sizeof(pem),M(ctr_drbg_random),&rng)==0);
    M(x509_crt) parsed;M(x509_crt_init)(&parsed);
    assert(M(x509_crt_parse)(&parsed,pem,strlen((char*)pem)+1)==0);
    Packets packets[2]={0}; Link links[2]={{&packets[0],&packets[1]},{&packets[1],&packets[0]}};
    M(ssl_context) ssl[2]; M(ssl_config) config[2]; Timer timers[2]={0};
    M(ssl_srtp_profile) profiles[]={AWRTC_MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80,AWRTC_MBEDTLS_TLS_SRTP_UNSET};
    for(int i=0;i<2;++i) {
        M(ssl_init)(&ssl[i]);M(ssl_config_init)(&config[i]);
        assert(M(ssl_config_defaults)(&config[i],i ? AWRTC_MBEDTLS_SSL_IS_SERVER : AWRTC_MBEDTLS_SSL_IS_CLIENT,AWRTC_MBEDTLS_SSL_TRANSPORT_DATAGRAM,AWRTC_MBEDTLS_SSL_PRESET_DEFAULT)==0);
        M(ssl_conf_rng)(&config[i],M(ctr_drbg_random),&rng);
        M(ssl_conf_authmode)(&config[i],AWRTC_MBEDTLS_SSL_VERIFY_OPTIONAL);
        assert(M(ssl_conf_own_cert)(&config[i],&parsed,&key)==0);
        M(ssl_conf_ca_chain)(&config[i],&parsed,NULL);
        M(ssl_conf_min_tls_version)(&config[i],AWRTC_MBEDTLS_SSL_VERSION_TLS1_2);
        M(ssl_conf_max_tls_version)(&config[i],AWRTC_MBEDTLS_SSL_VERSION_TLS1_2);
        assert(M(ssl_conf_dtls_srtp_protection_profiles)(&config[i],profiles)==0);
        if(i)M(ssl_conf_dtls_cookies)(&config[i],NULL,NULL,NULL);
        assert(M(ssl_setup)(&ssl[i],&config[i])==0);
        M(ssl_set_mtu)(&ssl[i],1500);
        M(ssl_set_bio)(&ssl[i],&links[i],send_packet,recv_packet,NULL);
        M(ssl_set_timer_cb)(&ssl[i],&timers[i],set_timer,get_timer);
    }
    int done[2]={0};
    for(unsigned step=0;step<1000 && !(done[0] && done[1]);++step) {
        for(int i=0;i<2;++i)if(!done[i]) {
            int rc=M(ssl_handshake)(&ssl[i]);
            if(rc==0) done[i]=1;
            else if(rc!=AWRTC_MBEDTLS_ERR_SSL_WANT_READ && rc!=AWRTC_MBEDTLS_ERR_SSL_WANT_WRITE) {
                fprintf(stderr,"handshake %d failed: -0x%x\n",i,-rc);return 1;
            }
        }
    }
    assert(done[0] && done[1]);
    for(int i=0;i<2;++i) {
        M(dtls_srtp_info) negotiated;
        M(ssl_get_dtls_srtp_negotiation_result)(&ssl[i],&negotiated);
        assert(negotiated.AWRTC_MBEDTLS_PRIVATE(chosen_dtls_srtp_profile)==AWRTC_MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80);
        const M(x509_crt)* remote=M(ssl_get_peer_cert)(&ssl[i]);
        assert(remote && remote->raw.len==parsed.raw.len && memcmp(remote->raw.p,parsed.raw.p,parsed.raw.len)==0);
    }
    const unsigned char message[]="private DTLS works";unsigned char received[64];
    assert(M(ssl_write)(&ssl[0],message,sizeof(message))==sizeof(message));
    assert(M(ssl_read)(&ssl[1],received,sizeof(received))==sizeof(message));
    assert(memcmp(message,received,sizeof(message))==0);
    for(int i=0;i<2;++i) {M(ssl_free)(&ssl[i]);M(ssl_config_free)(&config[i]);}
    M(x509_crt_free)(&parsed);M(x509write_crt_free)(&cert);M(pk_free)(&key);M(ctr_drbg_free)(&rng);
    puts("PASS: private DTLS 1.2 mutual certificates, SRTP profile negotiation, encrypted roundtrip");
}
