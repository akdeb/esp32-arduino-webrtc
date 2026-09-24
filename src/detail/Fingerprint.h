#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
namespace arduino_webrtc {
inline int hexDigit(char c) {
    if (c >= '0' && c <= '9') return c-'0';
    if (c >= 'A' && c <= 'F') return c-'A'+10;
    if (c >= 'a' && c <= 'f') return c-'a'+10;
    return -1;
}
// One bundled audio transport. Reject conflicting fingerprints and algorithms.
inline bool parseFingerprint(const char* sdp, size_t size, uint8_t digest[32]) {
    if (!sdp) return false;
    bool found = false;
    constexpr char prefix[] = "a=fingerprint:";
    constexpr char algorithm[] = "sha-256 ";
    for (size_t begin = 0; begin < size;) {
        size_t end = begin;
        while (end < size && sdp[end] != '\n' && sdp[end] != '\0') ++end;
        size_t len = end-begin;
        if (len && sdp[begin+len-1] == '\r') --len;
        if (len >= sizeof(prefix)-1 && !memcmp(sdp+begin,prefix,sizeof(prefix)-1)) {
            const size_t offset = sizeof(prefix)-1 + sizeof(algorithm)-1;
            if (len != offset + 95 || memcmp(sdp+begin+sizeof(prefix)-1,algorithm,sizeof(algorithm)-1)) return false;
            uint8_t parsed[32];
            for (size_t i=0;i<32;++i) {
                size_t pos=begin+offset+i*3;
                int high=hexDigit(sdp[pos]), low=hexDigit(sdp[pos+1]);
                if (high < 0 || low < 0 || (i < 31 && sdp[pos+2] != ':')) return false;
                parsed[i]=static_cast<uint8_t>(high*16+low);
            }
            if (found && memcmp(digest,parsed,32)) return false;
            memcpy(digest,parsed,32); found=true;
        }
        if (end < size && sdp[end] == '\0') {
            // esp_peer SDP callbacks may include a final NUL, never embedded NULs.
            if (end != size-1) return false;
            break;
        }
        begin=end+1;
    }
    return found;
}
}
