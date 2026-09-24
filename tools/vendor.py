#!/usr/bin/env python3
"""Reproduce bundled dependencies from three pinned upstream checkouts.
Usage: python3 tools/vendor.py <esp-webrtc-solution> <esp-adf-libs> <mbedtls>
No network access. Preserves upstream licenses; private TLS namespace avoids
colliding with the Arduino core's differently configured mbedTLS ABI.
"""
import os, re, shutil, sys, json, subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
peer, adf, tls = map(Path, sys.argv[1:])
expected = [(peer, '3971094e2e7c2ab7cb4de59e4eae710e1902d2b4'),
            (adf, 'a1c9747e62e9f78444570ce6dfb0c4143de98393'),
            (tls, '0bebf8b8c7f07abe3571ded48a11aa907a1ffb20')]
for directory, commit in expected:
    assert subprocess.check_output(['git','-C',str(directory),'rev-parse','HEAD'], text=True).strip() == commit
assert subprocess.check_output(['git','-C',str(tls),'describe','--tags','--exact-match'], text=True).strip() in ('mbedtls-3.6.6', 'v3.6.6')
out = ROOT/'src/vendor'
if out.exists(): shutil.rmtree(out)
entries = {}
def copy(source, dest):
    # Arduino ar uses basenames: avoid aes.c.o/cipher.c.o/sha1.c.o replacing
    # each other when the whole library is merged into one static archive.
    if dest.suffix == '.c' and out in dest.parents:
        scope = dest.relative_to(out).parts[0]
        if scope in ('tls', 'srtp'):
            dest = dest.with_name('awrtc_' + scope + '_' + dest.name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)
    entries[source.resolve()] = dest
p = peer/'components/esp_peer'
for f in (p/'include').glob('*.h'): copy(f, out/'peer'/f.name)
for f in (p/'src').rglob('*'):
    if f.suffix in ('.h','.c') and f.name != 'dtls_srtp_v6.c': copy(f, out/'peer'/f.relative_to(p/'src'))
copy(p/'LICENSE', out/'peer/LICENSE')
for chip in ('esp32','esp32s3'):
    copy(p/'libs'/chip/'libpeer_default.a', ROOT/'src'/chip/'libpeer_default.a')
codec = adf/'esp_audio_codec'
for f in (codec/'include').rglob('*.h'):
    copy(f, out/'codec'/f.relative_to(codec/'include'))
copy(codec/'LICENSE', out/'codec/LICENSE')
for chip in ('esp32','esp32s3'):
    copy(codec/'lib'/chip/'libesp_audio_codec.a', ROOT/'src'/chip/'libesp_audio_codec.a')
s = adf/'esp_libsrtp'
cmake=(s/'CMakeLists.txt').read_text()
for rel in re.findall(r'libsrtp/[\w/]+\.c', cmake): copy(s/rel, out/'srtp'/Path(rel).relative_to('libsrtp'))
for base in ('libsrtp/include','libsrtp/crypto/include','libsrtp/crypto/cipher','libsrtp/crypto/hash','esp-port'):
    for f in (s/base).glob('*.h'): copy(f, out/'srtp'/f.relative_to(s))
copy(s/'LICENSE', out/'srtp/LICENSE')
for base in ('include','library'):
    for f in (tls/base).rglob('*'):
        if f.suffix in ('.h','.c'):
            copy(f, out/'tls'/f.relative_to(tls))
for name in ('LICENSE','LICENSES'):
    f=tls/name
    if f.is_file(): copy(f,out/'tls'/name)
    elif f.is_dir(): shutil.copytree(f,out/'tls'/name)
# Resolve all private includes relative to each source, so Arduino needs no
# global include path that could shadow its own mbedtls headers.
search = [codec/'include', codec/'include/encoder', codec/'include/encoder/impl',
          codec/'include/decoder', codec/'include/decoder/impl', codec/'include/simple_dec', p/'include', p/'src', s/'esp-port', s/'libsrtp/include',
          s/'libsrtp/crypto/include', s/'libsrtp/crypto/cipher', s/'libsrtp/crypto/hash', tls/'include', tls/'library']
for original, dest in entries.items():
    if dest.suffix not in ('.h','.c'): continue
    data=dest.read_text()
    def include(m):
        name=m[1]
        for base in [original.parent]+search:
            found=entries.get((base/name).resolve())
            if found:
                return '#include "'+os.path.relpath(found,dest.parent)+'"'
        return m[0]
    data=re.sub(r'#\s*include\s*[<"]([^">]+)[">]',include,data)
    if '/tls/' in str(dest) or dest.name in ('dtls_srtp.c','dtls_srtp.h','dtls_common.h'):
        data=re.sub(r'\bmbedtls_', 'awrtc_mbedtls_', data)
        data=re.sub(r'\bMBEDTLS_', 'AWRTC_MBEDTLS_', data)
        data=re.sub(r'\bpsa_', 'awrtc_psa_', data)
        data=re.sub(r'\bPSA_', 'AWRTC_PSA_', data)
    data=re.sub(r'(#include [<"])([^">]+)([">])', lambda m: m[1]+m[2].replace('awrtc_mbedtls_', 'mbedtls_').replace('awrtc_psa_', 'psa_')+m[3], data)
    if '/srtp/' in str(dest) and dest.suffix=='.c':
        data='#define HAVE_CONFIG_H 1\n'+data
    dest.write_text(data)
# Lean standalone TLS 1.2/DTLS configuration. Uses explicit hardware RNG callback
# in esp_peer, software crypto, and no IDF mbedTLS internals or alternate structs.
features='''HAVE_ASM HAVE_TIME PLATFORM_C PLATFORM_MS_TIME_ALT AES_C ASN1_PARSE_C ASN1_WRITE_C BASE64_C
BIGNUM_C CIPHER_C CTR_DRBG_C ECDH_C ECDSA_C ECP_C ECP_DP_SECP256R1_ENABLED
ECP_NIST_OPTIM ECDSA_DETERMINISTIC HMAC_DRBG_C GCM_C MD_C OID_C PEM_PARSE_C PEM_WRITE_C
PK_C PK_PARSE_C PK_WRITE_C SHA256_C SHA384_C SHA512_C
SSL_CLI_C SSL_SRV_C SSL_TLS_C SSL_PROTO_TLS1_2 SSL_PROTO_DTLS
SSL_DTLS_ANTI_REPLAY SSL_DTLS_HELLO_VERIFY SSL_DTLS_SRTP SSL_COOKIE_C
SSL_KEEP_PEER_CERTIFICATE KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
X509_USE_C X509_CRT_PARSE_C X509_CREATE_C X509_CRT_WRITE_C'''.split()
config='// Generated private DTLS configuration. See tools/vendor.py.\n#pragma once\n'
config+=''.join('#define AWRTC_MBEDTLS_'+x+'\n' for x in features)
config+='#define AWRTC_MBEDTLS_SSL_IN_CONTENT_LEN 4096\n#define AWRTC_MBEDTLS_SSL_OUT_CONTENT_LEN 4096\n'
(out/'tls/include/mbedtls/mbedtls_config.h').write_text(config)
# Only encrypted SRTP profiles; upstream also offered NULL encryption.
f=out/'peer/dtls_common.h'
f.write_text(f.read_text().replace('    AWRTC_MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80, AWRTC_MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32,\n','').replace(', AWRTC_MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32', ''))
# Authenticate the DTLS certificate against the SHA-256 fingerprint from SDP.
# Upstream's adapter allows self-signed certificates; checking only CA flags
# would not authenticate a WebRTC peer. The wrapper provides this hook.
f=out/'peer/dtls_common.h'
data=f.read_text().replace('#define TAG          "DTLS"', '#define TAG          "DTLS"\nextern int awrtc_verify_peer_digest(const unsigned char *digest);')
needle='        ESP_LOGI(TAG, "%s handshake success",'
check="""        const awrtc_mbedtls_x509_crt *remote = awrtc_mbedtls_ssl_get_peer_cert(&dtls_srtp->ssl);
        unsigned char digest[32];
        const awrtc_mbedtls_md_info_t *sha256 = awrtc_mbedtls_md_info_from_type(AWRTC_MBEDTLS_MD_SHA256);
        if (!remote || !sha256 || awrtc_mbedtls_md(sha256, remote->raw.p, remote->raw.len, digest) != 0 ||
            awrtc_verify_peer_digest(digest) != 0) {
            ESP_LOGE(TAG, "Remote DTLS certificate does not match SDP fingerprint");
            return -1;
        }
"""
assert needle in data
data=data.replace(needle,check+needle)
# Balance SRTP global initialization with deinitialization across repeated calls.
data=data.replace('            init_count++;\n', '')
# Never emit an unprotected packet if the SRTP transform fails.
data=data.replace('    srtp_protect(dtls_srtp->srtp_out, packet, *bytes, packet, &size, 0);',
    '    if (srtp_protect(dtls_srtp->srtp_out, packet, *bytes, packet, &size, 0) != srtp_err_status_ok) size = 0;')
data=data.replace('    srtp_protect_rtcp(dtls_srtp->srtp_out, packet, *bytes, packet, &size, 0);',
    '    if (srtp_protect_rtcp(dtls_srtp->srtp_out, packet, *bytes, packet, &size, 0) != srtp_err_status_ok) size = 0;')
f.write_text(data)
f=out/'peer/dtls_srtp.c'
data=f.read_text()
# Both DTLS roles must request/retain the peer certificate for the fingerprint
# check. Server defaults otherwise permit a handshake without a client cert.
ca='awrtc_mbedtls_ssl_conf_ca_chain(&dtls_srtp->conf, &dtls_srtp->cert, NULL);'
data=data.replace(ca, ca+'\n        awrtc_mbedtls_ssl_conf_authmode(&dtls_srtp->conf, AWRTC_MBEDTLS_SSL_VERIFY_OPTIONAL);')
# Certificate pre-generation does not create SRTP or a stateful session.
data=data.replace('    dtls_srtp_deinit(dtls_srtp);\n    media_lib_free(dtls_srtp);',
    '    awrtc_mbedtls_x509_crt_free(&dtls_srtp->cert);\n    awrtc_mbedtls_pk_free(&dtls_srtp->pkey);\n    awrtc_mbedtls_ctr_drbg_free(&dtls_srtp->ctr_drbg);\n    media_lib_free(dtls_srtp);')
data=data.replace('    int ret = check_srtp(true);',
    '    int ret = check_srtp(true);\n    if (ret != 0) { media_lib_free(dtls_srtp); return NULL; }')
data=data.replace('        media_lib_mutex_create(&dtls_srtp->lock);',
    '        if (media_lib_mutex_create(&dtls_srtp->lock) != 0) { check_srtp(false); media_lib_free(dtls_srtp); return NULL; }')
f.write_text(data)
# Set version-based expiry well beyond the first development release.
f=out/'peer/dtls_srtp.c'
f.write_text(f.read_text().replace('20280101000000','20400101000000'))
print('Vendored pinned esp_peer, libsrtp, and isolated mbedTLS')
