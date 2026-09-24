#pragma once
#include "AudioFormat.h"
namespace arduino_webrtc {
class AudioCodec {
public:
    static constexpr size_t maxPacketBytes = 1275;
    ~AudioCodec() { end(); }
    AudioCodec() = default;
    AudioCodec(const AudioCodec&) = delete;
    AudioCodec& operator=(const AudioCodec&) = delete;
    bool begin(const AudioFormat& format);
    void end();
    // Encoder and decoder are separate instances: one task each, concurrently.
    int encode(int16_t* pcm, size_t samples, uint8_t* out, size_t capacity);
    int decode(uint8_t* packet, size_t size, int16_t* out, size_t capacity);
    void resetDecoder(); // only from the decoder task
    int lastOpenError() const { return openError_; }
private:
    AudioFormat format_{};
    void* encoder_ = nullptr;
    void* decoder_ = nullptr;
    uint8_t* encodeScratch_ = nullptr;
    size_t encodeCapacity_ = 0;
    int openError_ = 0;
    bool opened_ = false;
};
}
