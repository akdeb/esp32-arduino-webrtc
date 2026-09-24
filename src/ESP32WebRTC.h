#pragma once
#include <cstddef>
#include <cstdint>
#include "detail/AudioFormat.h"
namespace arduino_webrtc {
// Called on separate capture/playback tasks. Implementations must finish within
// timeoutMs and may return partial samples. PCM is signed 16-bit mono.
// read/write must pace streaming at Config.audio.sampleRate (blocking I2S DMA).
class AudioIO {
public:
    virtual ~AudioIO() = default;
    virtual uint32_t sampleRate() const { return 0; } // 0: custom driver must ensure a match
    virtual size_t read(int16_t* pcm, size_t samples, uint32_t timeoutMs) = 0;
    virtual size_t write(const int16_t* pcm, size_t samples, uint32_t timeoutMs) = 0;
};
class ESP32WebRTC {
public:
    enum class SignalType { SDP, Candidate };
    enum class State { Stopped, Connecting, Connected, Disconnected, Failed };
    using SignalHandler = void (*)(SignalType, const char*, size_t, void*);
    struct IceServer { const char* url = nullptr; const char* username = nullptr; const char* password = nullptr; };
    using Codec = AudioCodecType;
    struct Config {
        AudioFormat audio{}; // Opus, 24 kHz mono, 48 kbit/s by default
        bool offerer = false;
        bool relayOnly = false;
        uint16_t prefillMs = 60; // 20..120 ms, in 20 ms steps
        uint8_t serverCount = 0;
        IceServer servers[3]{}; // copied by begin()
        SignalHandler onSignal = nullptr; // dispatched only from poll()
        void* context = nullptr;
    };
    struct Stats {
        uint32_t sentFrames = 0, receivedPackets = 0, txDrops = 0;
        uint32_t missingSamples = 0, latePackets = 0, resyncs = 0;
        uint32_t captureErrors = 0, playbackErrors = 0, signalDrops = 0;
        uint32_t rxDrops = 0, encodeErrors = 0, decodeErrors = 0;
        uint32_t maxEncodeUs = 0, maxDecodeUs = 0, encodeOverruns = 0;
        uint32_t sampleRate = 0, bitrate = 0;
        int lastError = 0;
        uint32_t freeInternalHeap = 0, minimumInternalHeap = 0;
    };
    ESP32WebRTC() = default;
    ~ESP32WebRTC();
    ESP32WebRTC(const ESP32WebRTC&) = delete;
    ESP32WebRTC& operator=(const ESP32WebRTC&) = delete;
    // Call begin/end/poll/remoteSignal from the same Arduino task, not callbacks.
    // AudioIO must outlive end(). Wi-Fi and AudioIO must already be running.
    bool begin(AudioIO& audio, const Config& config);
    bool remoteSignal(SignalType type, const char* text, size_t length);
    void poll();
    // Returns false on timeout; resources remain alive for a subsequent end().
    bool end(uint32_t timeoutMs = 3000);
    void setMicrophoneEnabled(bool enabled); // silence while disabled (push-to-talk)
    State state() const;
    Stats stats() const;
private:
    struct Impl;
    Impl* impl_ = nullptr;
    int lastBeginError_ = 0;
};
}
using arduino_webrtc::ESP32WebRTC;
