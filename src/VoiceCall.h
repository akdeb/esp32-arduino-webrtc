#pragma once
#include "ESP32WebRTC.h"
#include "HttpSignaling.h"
namespace arduino_webrtc {
// An outgoing call to an HTTP-signaled WebRTC service: gathers the offer, POSTs it from
// poll() and applies the answer. Call begin/poll/end from the same task, usually loop().
class VoiceCall {
public:
    // config.offerer and config.onSignal are set by begin(); config.onData and config.context
    // are passed through. signaling.dataChannel is used when config.dataChannel is null.
    bool begin(AudioIO& audio, ESP32WebRTC::Config config, const HttpSignaling& signaling);
    void poll();  // the HTTP exchange blocks here once, for up to signaling.timeoutMs
    bool end(uint32_t timeoutMs = 3000);
    // Failed also covers a failed HTTP exchange; see error().
    ESP32WebRTC::State state() const { return failed_ ? ESP32WebRTC::State::Failed : rtc_.state(); }
    const String& error() const { return error_; }
    ESP32WebRTC& rtc() { return rtc_; } // stats(), setMicrophoneEnabled()
private:
    static void onSignal(ESP32WebRTC::SignalType type, const char* text, size_t length, void* self);
    static void onData(const uint8_t* data, size_t length, bool text, void* self);
    ESP32WebRTC rtc_;
    HttpSignaling signaling_;
    ESP32WebRTC::DataHandler userData_ = nullptr;
    void* userContext_ = nullptr;
    String offer_, error_;
    bool awaitingAnswer_ = false, failed_ = false;
};
}
using arduino_webrtc::VoiceCall;
