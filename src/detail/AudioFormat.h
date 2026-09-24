#pragma once
#include <cstddef>
#include <cstdint>
namespace arduino_webrtc {
enum class AudioCodecType { G711U, Opus };
struct AudioFormat {
    AudioCodecType codec = AudioCodecType::Opus;
    uint32_t sampleRate = 24000; // Local PCM/I2S rate; not the Opus RTP clock.
    uint32_t bitrate = 48000;    // Compressed bits/sec (Opus only).
    uint8_t complexity = 0;     // Opus 0..10, start at 0 on ESP32.
    bool valid() const {
        if (codec == AudioCodecType::G711U) return sampleRate == 8000;
        if (codec != AudioCodecType::Opus || (sampleRate != 16000 && sampleRate != 24000 && sampleRate != 48000)) return false;
        return complexity <= 10 && bitrate >= (sampleRate >= 24000 ? 40000u : 16000u) && bitrate <= 64000;
    }
    size_t frameSamples() const { return sampleRate / 50; } // 20 ms
    size_t maxDecodeSamples() const { return sampleRate * 120 / 1000; }
    uint32_t rtpClockRate() const { return codec == AudioCodecType::Opus ? 48000 : 8000; }
    uint8_t sdpChannels() const { return codec == AudioCodecType::Opus ? 2 : 1; }
};
// RFC 6716 TOC duration; payload validation is left to the Opus decoder.
inline size_t opusPacketSamples(const uint8_t* data, size_t size, uint32_t rate) {
    if (!data || !size) return 0;
    uint32_t samples;
    if (data[0] & 0x80) samples = (rate << ((data[0] >> 3) & 3)) / 400;
    else if ((data[0] & 0x60) == 0x60) samples = (data[0] & 8) ? rate / 50 : rate / 100;
    else { unsigned duration=(data[0] >> 3) & 3; samples=duration==3 ? rate*60/1000 : (rate << duration)/100; }
    unsigned frames;
    switch (data[0] & 3) {
        case 0: frames=1; break;
        case 1: case 2: frames=2; break;
        default: if(size<2)return 0; frames=data[1]&63; break;
    }
    size_t total=samples*frames;
    return total && total <= rate*120/1000 ? total : 0;
}
}
