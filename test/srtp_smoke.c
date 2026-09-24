#include "vendor/srtp/libsrtp/include/srtp.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    unsigned char key[30]; for(unsigned i=0;i<sizeof(key);++i)key[i]=(unsigned char)i;
    assert(srtp_init()==srtp_err_status_ok);
    srtp_policy_t send={0},receive={0};
    srtp_crypto_policy_set_rtp_default(&send.rtp);
    srtp_crypto_policy_set_rtcp_default(&send.rtcp);
    send.ssrc.type=ssrc_any_outbound;send.key=key;
    receive=send;receive.ssrc.type=ssrc_any_inbound;
    srtp_t tx,rx;
    assert(srtp_create(&tx,&send)==srtp_err_status_ok);
    assert(srtp_create(&rx,&receive)==srtp_err_status_ok);
    unsigned char packet[256]={0x80,0x00,0x00,0x01,0,0,0,0,0x12,0x34,0x56,0x78};
    memset(packet+12,0xff,160);
    unsigned char plain[172];memcpy(plain,packet,sizeof(plain));
    size_t size=sizeof(packet);
    assert(srtp_protect(tx,packet,sizeof(plain),packet,&size,0)==srtp_err_status_ok);
    assert(size==182 && memcmp(packet+12,plain+12,160)!=0);
    unsigned char tampered[256],replay[256];memcpy(tampered,packet,size);memcpy(replay,packet,size);
    tampered[20]^=1;size_t bad_size=size;
    assert(srtp_unprotect(rx,tampered,size,tampered,&bad_size)==srtp_err_status_auth_fail);
    size_t replay_size=size;
    assert(srtp_unprotect(rx,packet,size,packet,&size)==srtp_err_status_ok);
    assert(size==172 && memcmp(packet,plain,sizeof(plain))==0);
    assert(srtp_unprotect(rx,replay,replay_size,replay,&replay_size)==srtp_err_status_replay_fail);
    assert(srtp_dealloc(tx)==srtp_err_status_ok);assert(srtp_dealloc(rx)==srtp_err_status_ok);
    assert(srtp_shutdown()==srtp_err_status_ok);
    puts("PASS: bundled SRTP encrypt/decrypt, tamper detection, replay rejection");
}
