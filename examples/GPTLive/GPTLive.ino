// Voice call from the board straight to OpenAI GPT-Live over WebRTC. VoiceCall creates the SDP
// offer, POSTs it to OpenAI over HTTPS, and applies the answer; no computer or relay is involved.
// Serial commands: "c" starts a call, "s" hangs up. Stats print every 2 s during a call.
//
// Development example: the API key is compiled into the firmware and TLS skips certificate
// verification. For a product, fetch a short-lived client secret from your own server instead.
#include <Arduino.h>
#include <WiFi.h>
#include <VoiceCall.h>
#include <WebRTCI2S.h>
#include <algorithm>
#include <cstring>
#ifndef WEBRTC_WIFI_SSID
#define WEBRTC_WIFI_SSID "YOUR_WIFI_SSID"
#define WEBRTC_WIFI_PASSWORD "YOUR_WIFI_PASSWORD"
#endif
#ifndef OPENAI_API_KEY
#define OPENAI_API_KEY "YOUR_OPENAI_API_KEY"
#endif
#ifndef OPENAI_VOICE
#define OPENAI_VOICE "" // OpenAI's default; male: meridian, vesper, stone, ripple, cinder, tempo, beacon
#endif
#ifndef WEBRTC_VOLUME
#define WEBRTC_VOLUME 100 // speaker volume, 0..100
#endif
#ifndef OPENAI_INSTRUCTIONS
#define OPENAI_INSTRUCTIONS "You are a friendly voice assistant on a small device. Keep replies short."
#endif
WebRTCI2S audio;
VoiceCall call;
uint32_t lastStats = 0;
// Data channel events arrive on the network task: print the event type and return quickly.
void onData(const uint8_t* data, size_t length, bool, void*) {
    const char* key = "\"type\":\"";
    const char* text = reinterpret_cast<const char*>(data);
    const char* end = text + length;
    const char* found = std::search(text, end, key, key + strlen(key));
    if (found == end) { Serial.printf("event (%u bytes)\n", static_cast<unsigned>(length)); return; }
    found += strlen(key);
    const char* close = std::find(found, end, '"');
    Serial.printf("event: %.*s\n", static_cast<int>(close - found), found);
}
void startCall() {
    ESP32WebRTC::Config cfg;
    cfg.audio.codec = ESP32WebRTC::Codec::Opus;
    cfg.audio.sampleRate = 24000; // GPT-Live's native rate; 48 kHz adds RAM, not quality
    cfg.audio.bitrate = 48000;    // 64 kbit/s with complexity 5 overran the 20 ms encode budget
    cfg.audio.complexity = 0;     // under Wi-Fi load and starved the heap on a live call
    cfg.echoGateMs = 400; // no AEC: mute the mic while the assistant speaks so it cannot interrupt itself
    cfg.onData = onData;  // events from the "oai-events" channel
    // Any HTTP-signaled service works here: HttpSignaling::whip(url, token), ::json(url, token), ...
    HttpSignaling openai = HttpSignaling::openai(OPENAI_API_KEY, OPENAI_VOICE, OPENAI_INSTRUCTIONS);
    if (!call.begin(audio, cfg, openai)) { Serial.println(call.error()); return; }
    Serial.println("Gathering offer...");
}
void setup() {
    Serial.begin(115200);
    WiFi.begin(WEBRTC_WIFI_SSID, WEBRTC_WIFI_PASSWORD);
    Serial.printf("Joining Wi-Fi \"%s\"", WEBRTC_WIFI_SSID);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print('.'); }
    WiFi.setSleep(false);
    Serial.print("\nBoard address: "); Serial.println(WiFi.localIP());
    WebRTCI2S::Pins pins;
#if CONFIG_IDF_TARGET_ESP32
    pins.bclk=26; pins.ws=25; pins.din=33; pins.dout=22;
#endif
#ifdef WEBRTC_PINS
    { int v[] = {WEBRTC_PINS}; pins.bclk=v[0]; pins.ws=v[1]; pins.din=v[2]; pins.dout=v[3]; }
#endif
#ifdef WEBRTC_MIC_CLOCK_PINS
    { int v[] = {WEBRTC_MIC_CLOCK_PINS}; pins.micBclk=v[0]; pins.micWs=v[1]; }
#endif
#ifdef WEBRTC_AMP_ENABLE_PIN
    pinMode(WEBRTC_AMP_ENABLE_PIN, OUTPUT); digitalWrite(WEBRTC_AMP_ENABLE_PIN, HIGH);
#endif
    if (!audio.begin(pins, 24000)) { Serial.println("I2S initialization failed"); return; }
    audio.setVolume(WEBRTC_VOLUME);
    startCall();
}
void loop() {
    static const char* names[] = {"stopped", "connecting", "connected", "disconnected", "failed"};
    static auto last = ESP32WebRTC::State::Stopped;
    call.poll();
    auto now = call.state();
    if (now != last) {
        last = now;
        Serial.printf("Call %s\n", names[static_cast<int>(now)]);
        if (now == ESP32WebRTC::State::Failed) Serial.printf("%s\nSend \"c\" to retry\n", call.error().c_str());
    }
    if (Serial.available()) {
        char c = Serial.read();
        if (c == 'c') startCall();
        if (c == 's') Serial.println(call.end() ? "Hung up" : "Retry stop");
    }
    if (now != ESP32WebRTC::State::Stopped && millis() - lastStats > 2000) {
        lastStats = millis();
        auto s = call.rtc().stats();
        Serial.printf("[%s] sent=%lu received=%lu missing=%lu txDrops=%lu rxDrops=%lu decodeErr=%lu maxEnc=%luus heap=%lu min=%lu err=%d\n",
            names[static_cast<int>(now)], s.sentFrames, s.receivedPackets, s.missingSamples, s.txDrops, s.rxDrops,
            s.decodeErrors, s.maxEncodeUs, s.freeInternalHeap, s.minimumInternalHeap, s.lastError);
    }
    delay(2);
}
