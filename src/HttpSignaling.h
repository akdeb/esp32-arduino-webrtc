#pragma once
#include <Arduino.h>
#include <functional>
namespace arduino_webrtc {
// Exchanges an SDP offer for an answer with one HTTP(S) POST: the pattern used by WHIP,
// OpenAI GPT-Live, Pipecat SmallWebRTC and most WebRTC voice AI endpoints.
struct HttpSignaling {
    String url;                              // http:// or https://host[:port]/path
    String headers;                          // extra request headers, each "Name: value\r\n"
    String contentType = "application/sdp";
    std::function<String(const String& offer)> buildBody;      // default: the offer itself
    std::function<String(const String& response)> parseAnswer; // default: the response body
    const char* dataChannel = nullptr; // opened when the service needs one (e.g. "oai-events")
    const char* caCert = nullptr;      // PEM root certificate; nullptr skips verification (development only)
    uint32_t timeoutMs = 15000;
    // Blocking. Returns the answer SDP, or "" with a reason in *error.
    String exchange(const String& offer, String* error = nullptr) const;

    // Raw SDP in, raw SDP out, optional bearer token.
    static HttpSignaling whip(const String& url, const String& token = "");
    // {"type":"offer","sdp":...} in, the "sdp" field of the JSON response out (e.g. Pipecat /api/offer).
    static HttpSignaling json(const String& url, const String& token = "");
    // OpenAI GPT-Live (/v1/live/sessions, "oai-events" channel). Accepts an API key or an ephemeral
    // client secret. Empty voice/instructions use OpenAI's defaults. Voices: meridian, vesper, stone, ...
    static HttpSignaling openai(const String& apiKey, const String& voice = "", const String& instructions = "",
                                const String& model = "gpt-live-1");

    static String jsonEscape(const String& in);
    // Unescaped string value of the first "key" at or after offset `from`, or "".
    static String jsonString(const String& json, const char* key, int from = 0);
};
}
using arduino_webrtc::HttpSignaling;
