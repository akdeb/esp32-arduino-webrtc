#pragma once
#include <cstdint>
namespace arduino_webrtc {
inline uint8_t encodeMuLaw(int16_t value) {
    int pcm = value;
    const int mask = pcm < 0 ? 0x7f : 0xff;
    if (pcm < 0) pcm = -pcm;
    if (pcm > 32635) pcm = 32635;
    pcm += 132;
    int exponent = 7;
    for (int bit = 0x4000; exponent > 0 && !(pcm & bit); bit >>= 1) --exponent;
    return static_cast<uint8_t>(((exponent << 4) | ((pcm >> (exponent + 3)) & 15)) ^ mask);
}
inline int16_t decodeMuLaw(uint8_t value) {
    const uint8_t u = static_cast<uint8_t>(~value);
    int pcm = (((u & 15) << 3) + 132) << ((u >> 4) & 7);
    return static_cast<int16_t>((u & 128) ? 132 - pcm : pcm - 132);
}
}
