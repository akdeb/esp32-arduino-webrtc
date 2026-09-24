// Voice call from the board straight to OpenAI Realtime over WebRTC. The board creates the SDP
// offer, POSTs it to OpenAI over HTTPS, and applies the answer; no computer or relay is involved.
// Serial commands: "c" starts a call, "s" hangs up. Stats print every 2 s during a call.
//
// Development example: the API key is compiled into the firmware and TLS skips certificate
// verification. For a product, fetch a short-lived client secret from your own server instead.
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <ESP32WebRTC.h>
#include <WebRTCI2S.h>
#include <esp_heap_caps.h>
#include <algorithm>
#include <cstring>
#ifndef WEBRTC_WIFI_SSID
#define WEBRTC_WIFI_SSID "YOUR_WIFI_SSID"
#define WEBRTC_WIFI_PASSWORD "YOUR_WIFI_PASSWORD"
#endif
#ifndef OPENAI_API_KEY
#define OPENAI_API_KEY "YOUR_OPENAI_API_KEY"
#endif
#ifndef OPENAI_MODEL
#define OPENAI_MODEL "gpt-live-1"
#endif
#ifndef OPENAI_VOICE
#define OPENAI_VOICE "marin"
#endif
#ifndef OPENAI_INSTRUCTIONS
#define OPENAI_INSTRUCTIONS "You are a friendly voice assistant on a small device. Keep replies short."
#endif
WebRTCI2S audio;
ESP32WebRTC rtc;
String localSdp;
bool awaitingAnswer = false;
uint32_t lastStats = 0;
void onSignal(ESP32WebRTC::SignalType type, const char* text, size_t length, void*) {
    if (type == ESP32WebRTC::SignalType::SDP) { localSdp = ""; localSdp.concat(text, length); }
}
uint32_t freeInternal() { return heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT); }
uint32_t largestInternal() { return heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT); }
// GPT-Live models use POST /v1/live/sessions (JSON) and need an "oai-events" data channel;
// Realtime models use POST /v1/realtime/calls (multipart form).
const bool liveApi = strncmp(OPENAI_MODEL, "gpt-live", 8) == 0;
String jsonEscape(const String& in) {
    String out; out.reserve(in.length() + in.length() / 16);
    for (char c : in) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c == '\r') out += "\\r";
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}
// Returns the unescaped string value of the first "key": "..." after `after` in json, or "".
String jsonString(const String& json, const char* key, int after = 0) {
    String needle = String("\"") + key + "\"";
    int k = json.indexOf(needle, after); if (k < 0) return "";
    int q = json.indexOf('"', json.indexOf(':', k + needle.length())); if (q < 0) return "";
    String out;
    for (int i = q + 1; i < static_cast<int>(json.length()); ++i) {
        char c = json[i];
        if (c == '"') return out;
        if (c != '\\' || i + 1 >= static_cast<int>(json.length())) { out += c; continue; }
        char e = json[++i];
        out += e == 'n' ? '\n' : e == 'r' ? '\r' : e == 't' ? '\t' : e;
    }
    return "";
}
// Undo HTTP/1.1 chunked transfer encoding.
String dechunk(const String& raw) {
    String out;
    for (int pos = 0;;) {
        int eol = raw.indexOf("\r\n", pos); if (eol < 0) break;
        long size = strtol(raw.substring(pos, eol).c_str(), nullptr, 16); if (size <= 0) break;
        out += raw.substring(eol + 2, eol + 2 + size); pos = eol + 2 + size + 2;
    }
    return out;
}
// POST the offer to OpenAI; returns the answer SDP or "".
String exchangeOffer(const String& offer) {
    static const char* boundary = "esp32webrtcboundary";
    String path, type, body;
    if (liveApi) {
        path = "/v1/live/sessions"; type = "application/json";
        body = "{\"session\":{\"model\":\"" OPENAI_MODEL "\",\"instructions\":\"" OPENAI_INSTRUCTIONS
               "\"},\"transport\":{\"type\":\"webrtc\",\"sdp\":\"" + jsonEscape(offer) + "\"}}";
    } else {
        path = "/v1/realtime/calls"; type = String("multipart/form-data; boundary=") + boundary;
        String session = "{\"type\":\"realtime\",\"model\":\"" OPENAI_MODEL "\",\"instructions\":\"" OPENAI_INSTRUCTIONS
                         "\",\"audio\":{\"output\":{\"voice\":\"" OPENAI_VOICE "\"}}}";
        body = String("--") + boundary + "\r\nContent-Disposition: form-data; name=\"sdp\"\r\n\r\n" + offer +
               "\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=\"session\"\r\n\r\n" + session +
               "\r\n--" + boundary + "--\r\n";
    }
    WiFiClientSecure tls;
    tls.setInsecure();
    Serial.printf("HTTPS POST %s: free internal=%u, largest block=%u\n", path.c_str(), freeInternal(), largestInternal());
    if (!tls.connect("api.openai.com", 443)) { Serial.println("HTTPS connect failed"); return ""; }
    tls.printf("POST %s HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer %s\r\n"
               "Content-Type: %s\r\nContent-Length: %u\r\nConnection: close\r\n\r\n",
               path.c_str(), OPENAI_API_KEY, type.c_str(), body.length());
    tls.print(body);
    body = "";
    tls.setTimeout(15000); // OpenAI can take a few seconds to answer
    String status = tls.readStringUntil('\n');
    bool chunked = false;
    while (tls.connected() || tls.available()) {
        String line = tls.readStringUntil('\n');
        line.toLowerCase();
        if (line.startsWith("transfer-encoding:") && line.indexOf("chunked") > 0) chunked = true;
        if (line == "\r" || line.isEmpty()) break;
    }
    String response;
    uint32_t deadline = millis() + 15000;
    while ((tls.connected() || tls.available()) && millis() < deadline) {
        while (tls.available()) response += static_cast<char>(tls.read());
        delay(1);
    }
    tls.stop();
    if (chunked) response = dechunk(response);
    status.trim();
    Serial.print("OpenAI: "); Serial.println(status);
    if (!status.startsWith("HTTP/1.1 20")) { Serial.println(response); return ""; }
    if (!liveApi) return response;
    String answer = jsonString(response, "sdp", response.indexOf("\"transport\""));
    if (answer.isEmpty()) Serial.println(response);
    return answer;
}
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
    if (!rtc.end()) { Serial.println("Previous call is stopping; retry"); return; }
    localSdp = "";
    ESP32WebRTC::Config cfg;
    cfg.audio.codec = ESP32WebRTC::Codec::Opus;
    cfg.audio.sampleRate = 24000; // OpenAI Realtime's native rate; 48 kHz adds RAM, not quality
    cfg.audio.bitrate = 48000;    // 64 kbit/s with complexity 5 overran the 20 ms encode budget
    cfg.audio.complexity = 0;     // under Wi-Fi load and starved the heap on a live call
    cfg.offerer = true;
    cfg.echoGateMs = 400; // no AEC: mute the mic while the assistant speaks so it cannot interrupt itself
    cfg.onSignal = onSignal;
    if (liveApi) { cfg.dataChannel = "oai-events"; cfg.onData = onData; }
    if (!rtc.begin(audio, cfg)) { Serial.printf("WebRTC open failed, code=%d\n", rtc.stats().lastError); return; }
    awaitingAnswer = true;
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
    startCall();
}
void loop() {
    rtc.poll();
    if (awaitingAnswer && !localSdp.isEmpty()) {
        awaitingAnswer = false;
        String answer = exchangeOffer(localSdp);
        if (answer.isEmpty() || !rtc.remoteSignal(ESP32WebRTC::SignalType::SDP, answer.c_str(), answer.length())) {
            Serial.println("Call setup failed; send \"c\" to retry"); rtc.end();
        } else Serial.println("Answer applied. Talk to the board.");
    }
    if (Serial.available()) {
        char c = Serial.read();
        if (c == 'c') startCall();
        if (c == 's') Serial.println(rtc.end() ? "Hung up" : "Retry stop");
    }
    if (rtc.state() != ESP32WebRTC::State::Stopped && millis() - lastStats > 2000) {
        lastStats = millis();
        auto s = rtc.stats();
        static const char* names[] = {"stopped", "connecting", "connected", "disconnected", "failed"};
        Serial.printf("[%s] sent=%lu received=%lu missing=%lu txDrops=%lu rxDrops=%lu decodeErr=%lu maxEnc=%luus heap=%lu min=%lu err=%d\n",
            names[static_cast<int>(rtc.state())], s.sentFrames, s.receivedPackets, s.missingSamples, s.txDrops, s.rxDrops,
            s.decodeErrors, s.maxEncodeUs, s.freeInternalHeap, s.minimumInternalHeap, s.lastError);
    }
    delay(2);
}
