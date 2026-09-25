#include "VoiceCall.h"
namespace arduino_webrtc {
bool VoiceCall::begin(AudioIO& audio, ESP32WebRTC::Config config, const HttpSignaling& signaling) {
    if (!rtc_.end()) { error_ = "previous call is still stopping"; return false; }
    signaling_ = signaling;
    offer_ = ""; error_ = ""; failed_ = false;
    userData_ = config.onData; userContext_ = config.context;
    config.offerer = true;
    config.onSignal = onSignal;
    config.onData = userData_ ? onData : nullptr;
    config.context = this;
    if (!config.dataChannel) config.dataChannel = signaling_.dataChannel;
    if (!rtc_.begin(audio, config)) { error_ = "WebRTC open failed, code=" + String(rtc_.stats().lastError); return false; }
    awaitingAnswer_ = true;
    return true;
}

void VoiceCall::poll() {
    rtc_.poll();
    if (!awaitingAnswer_ || offer_.isEmpty()) return;
    awaitingAnswer_ = false;
    String answer = signaling_.exchange(offer_, &error_);
    offer_ = "";
    if (!answer.isEmpty() && rtc_.remoteSignal(ESP32WebRTC::SignalType::SDP, answer.c_str(), answer.length())) return;
    if (error_.isEmpty()) error_ = "answer SDP rejected";
    failed_ = true;
    rtc_.end();
}

bool VoiceCall::end(uint32_t timeoutMs) {
    awaitingAnswer_ = false; failed_ = false; offer_ = "";
    return rtc_.end(timeoutMs);
}

void VoiceCall::onSignal(ESP32WebRTC::SignalType type, const char* text, size_t length, void* self) {
    auto& call = *static_cast<VoiceCall*>(self);
    if (type == ESP32WebRTC::SignalType::SDP) { call.offer_ = ""; call.offer_.concat(text, length); }
}

void VoiceCall::onData(const uint8_t* data, size_t length, bool text, void* self) {
    auto& call = *static_cast<VoiceCall*>(self);
    call.userData_(data, length, text, call.userContext_);
}
}
