#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <ESP32WebRTC.h>
#include <WebRTCI2S.h>
#include <esp_heap_caps.h>
#include <esp_netif.h>
#ifdef WEBRTC_WIFI_SSID
const char* WIFI_SSID = WEBRTC_WIFI_SSID;
const char* WIFI_PASSWORD = WEBRTC_WIFI_PASSWORD;
#else
const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
#endif
#ifndef WEBRTC_SAMPLE_RATE
#define WEBRTC_SAMPLE_RATE 24000
#endif
#ifndef WEBRTC_USE_G711
#define WEBRTC_USE_G711 0
#endif
// Define WEBRTC_SOFTAP=1 to have the board host its own Wi-Fi network instead of joining one.
#ifndef WEBRTC_SOFTAP
#define WEBRTC_SOFTAP 0
#endif
#ifndef WEBRTC_AP_SSID
#define WEBRTC_AP_SSID "esp32-webrtc"
#endif
#ifndef WEBRTC_AP_PASSWORD
#define WEBRTC_AP_PASSWORD "webrtc1234"
#endif
WebRTCI2S audio;
ESP32WebRTC rtc;
WebServer server(80);
String localSdp;
void onSignal(ESP32WebRTC::SignalType type, const char* text, size_t length, void*) {
    if (type == ESP32WebRTC::SignalType::SDP) { localSdp = ""; localSdp.concat(text, length); }
}
ESP32WebRTC::Config makeConfig() {
    ESP32WebRTC::Config cfg;
    cfg.audio.codec = WEBRTC_USE_G711 ? ESP32WebRTC::Codec::G711U : ESP32WebRTC::Codec::Opus;
    cfg.audio.sampleRate = WEBRTC_SAMPLE_RATE;
    cfg.audio.bitrate = 48000;
    cfg.onSignal = onSignal;
#ifdef WEBRTC_STUN_URL
    cfg.serverCount = 1; cfg.servers[0].url = WEBRTC_STUN_URL;
#endif
    return cfg;
}
void setup() {
    Serial.begin(115200);
#if WEBRTC_SOFTAP
    WiFi.softAP(WEBRTC_AP_SSID, WEBRTC_AP_PASSWORD);
    // esp_peer gathers ICE candidates from the default netif, which is not the AP by default.
    esp_netif_set_default_netif(esp_netif_get_handle_from_ifkey("WIFI_AP_DEF"));
#else
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) delay(250);
#endif
    WiFi.setSleep(false);
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
    if (!audio.begin(pins, makeConfig().audio.sampleRate)) { Serial.println("I2S initialization failed"); return; }
    // LAN development example; signaling is proxied from localhost.
    server.on("/config", HTTP_GET, [] {
        auto format = makeConfig().audio;
        String json = "{\"codec\":\"" + String(WEBRTC_USE_G711 ? "pcmu" : "opus") + "\",\"sampleRate\":" +
            String(format.sampleRate) + ",\"bitrate\":" + String(WEBRTC_USE_G711 ? 64000 : format.bitrate) + "}";
        server.send(200, "application/json", json);
    });
    server.on("/offer", HTTP_POST, [] {
        if (!rtc.end()) { server.send(503, "text/plain", "Previous call is stopping; retry"); return; }
        localSdp = "";
        auto cfg = makeConfig();
        if (!rtc.begin(audio, cfg)) {
            String error = "WebRTC allocation/open failed, code=" + String(rtc.stats().lastError) +
                ", free internal=" + String(heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)) +
                ", largest block=" + String(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
            Serial.println(error); server.send(503, "text/plain", error); return;
        }
        String offer = server.arg("plain");
        if (!rtc.remoteSignal(ESP32WebRTC::SignalType::SDP, offer.c_str(), offer.length())) {
            rtc.end(); server.send(400, "text/plain", "Invalid or oversized SDP"); return;
        }
        server.send(202, "text/plain", "Offer accepted");
    });
    server.on("/answer", HTTP_GET, [] {
        if (localSdp.isEmpty()) server.send(202, "text/plain", "Waiting for answer");
        else server.send(200, "application/sdp", localSdp);
    });
    server.on("/stop", HTTP_POST, [] {
        bool stopped = rtc.end(); localSdp = "";
        server.send(stopped ? 200 : 503, "text/plain", stopped ? "Stopped" : "Retry stop");
    });
    server.on("/mic", HTTP_POST, [] {
        rtc.setMicrophoneEnabled(server.arg("plain") != "off"); server.send(200, "text/plain", "OK");
    });
    server.on("/stats", HTTP_GET, [] {
        auto s = rtc.stats();
        String json="{\"sent\":"+String(s.sentFrames)+",\"received\":"+String(s.receivedPackets)+",\"txDrops\":"+String(s.txDrops)+
            ",\"missingSamples\":"+String(s.missingSamples)+",\"captureErrors\":"+String(s.captureErrors)+",\"playbackErrors\":"+String(s.playbackErrors)+
            ",\"freeInternalHeap\":"+String(s.freeInternalHeap)+",\"minInternalHeap\":"+String(s.minimumInternalHeap)+",\"lastError\":"+String(s.lastError)+",\"rxDrops\":"+String(s.rxDrops)+",\"encodeErrors\":"+String(s.encodeErrors)+
            ",\"decodeErrors\":"+String(s.decodeErrors)+",\"maxEncodeUs\":"+String(s.maxEncodeUs)+",\"maxDecodeUs\":"+String(s.maxDecodeUs)+
            ",\"encodeOverruns\":"+String(s.encodeOverruns)+",\"sampleRate\":"+String(s.sampleRate)+",\"bitrate\":"+String(s.bitrate)+"}";
        server.send(200,"application/json",json);
    });
    server.begin();
#if WEBRTC_SOFTAP
    Serial.printf("Join Wi-Fi \"%s\" (password \"%s\")\n", WEBRTC_AP_SSID, WEBRTC_AP_PASSWORD);
    Serial.print("Board address: http://"); Serial.println(WiFi.softAPIP());
#else
    Serial.print("Board address: http://"); Serial.println(WiFi.localIP());
#endif
}
void loop() {
    server.handleClient(); rtc.poll();
    // Serial "t": open and close a peer without a browser, to check allocation.
    if (Serial.available() && Serial.read() == 't') {
        bool ok = rtc.begin(audio, makeConfig());
        Serial.printf("begin test: %s, code=%d, free internal=%u, largest block=%u\n", ok ? "OK" : "FAILED",
            rtc.stats().lastError, heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
            heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
        rtc.end(UINT32_MAX);
    }
    delay(2);
}
