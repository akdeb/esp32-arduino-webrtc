#include "HttpSignaling.h"
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
namespace arduino_webrtc {
namespace {
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
String bearer(const String& token) { return token.isEmpty() ? String() : String("Authorization: Bearer ") + token + "\r\n"; }
// Concrete client type so its own setTimeout and connect overloads apply.
template <class C>
bool post(C& client, const String& host, uint16_t port, const String& path, const HttpSignaling& s,
          String& body, String& status, String& response) {
    if (!client.connect(host.c_str(), port)) { status = "connect to " + host + " failed"; return false; }
    client.printf("POST %s HTTP/1.1\r\nHost: %s\r\n%sContent-Type: %s\r\nContent-Length: %u\r\nConnection: close\r\n\r\n",
                  path.c_str(), host.c_str(), s.headers.c_str(), s.contentType.c_str(), body.length());
    client.print(body);
    body = "";
    client.setTimeout(s.timeoutMs);
    status = client.readStringUntil('\n');
    bool chunked = false;
    while (client.connected() || client.available()) {
        String line = client.readStringUntil('\n');
        line.toLowerCase();
        if (line.startsWith("transfer-encoding:") && line.indexOf("chunked") > 0) chunked = true;
        if (line == "\r" || line.isEmpty()) break;
    }
    uint32_t deadline = millis() + s.timeoutMs;
    while ((client.connected() || client.available()) && millis() < deadline) {
        while (client.available()) response += static_cast<char>(client.read());
        delay(1);
    }
    client.stop();
    if (chunked) response = dechunk(response);
    status.trim();
    return true;
}
}

String HttpSignaling::exchange(const String& offer, String* error) const {
    String scratch; String& err = error ? *error : scratch;
    err = "";
    bool tls = url.startsWith("https://");
    if (!tls && !url.startsWith("http://")) { err = "URL must start with http:// or https://"; return ""; }
    int hostStart = tls ? 8 : 7, slash = url.indexOf('/', hostStart);
    String host = slash < 0 ? url.substring(hostStart) : url.substring(hostStart, slash);
    String path = slash < 0 ? String("/") : url.substring(slash);
    uint16_t port = tls ? 443 : 80;
    int colon = host.indexOf(':');
    if (colon >= 0) { port = host.substring(colon + 1).toInt(); host = host.substring(0, colon); }

    String body = buildBody ? buildBody(offer) : offer, status, response;
    log_i("POST %s%s: free heap=%u", host.c_str(), path.c_str(), ESP.getFreeHeap());
    bool sent;
    if (tls) {
        WiFiClientSecure client;
        if (caCert) client.setCACert(caCert); else client.setInsecure();
        sent = post(client, host, port, path, *this, body, status, response);
    } else {
        WiFiClient client;
        sent = post(client, host, port, path, *this, body, status, response);
    }
    if (!sent) { err = status; return ""; }
    int code = status.substring(status.indexOf(' ') + 1).toInt();
    if (code < 200 || code > 299) { err = status + "\n" + response; return ""; }
    String answer = parseAnswer ? parseAnswer(response) : response;
    if (answer.isEmpty()) err = "no SDP in response:\n" + response;
    return answer;
}

HttpSignaling HttpSignaling::whip(const String& url, const String& token) {
    HttpSignaling s;
    s.url = url;
    s.headers = bearer(token);
    return s;
}

HttpSignaling HttpSignaling::json(const String& url, const String& token) {
    HttpSignaling s = whip(url, token);
    s.contentType = "application/json";
    s.buildBody = [](const String& offer) -> String { return "{\"type\":\"offer\",\"sdp\":\"" + jsonEscape(offer) + "\"}"; };
    s.parseAnswer = [](const String& response) -> String { return jsonString(response, "sdp"); };
    return s;
}

HttpSignaling HttpSignaling::openai(const String& apiKey, const String& voice, const String& instructions, const String& model) {
    // GPT-Live: JSON body; the answer is transport.sdp and events use the "oai-events" data channel.
    HttpSignaling s;
    s.url = "https://api.openai.com/v1/live/sessions";
    s.headers = bearer(apiKey);
    s.contentType = "application/json";
    s.dataChannel = "oai-events";
    String session = String("{\"model\":\"") + jsonEscape(model) + "\"";
    if (!instructions.isEmpty()) session += String(",\"instructions\":\"") + jsonEscape(instructions) + "\"";
    if (!voice.isEmpty()) session += String(",\"audio\":{\"output\":{\"voice\":\"") + jsonEscape(voice) + "\"}}";
    session += "}";
    s.buildBody = [session](const String& offer) -> String {
        return "{\"session\":" + session + ",\"transport\":{\"type\":\"webrtc\",\"sdp\":\"" + jsonEscape(offer) + "\"}}";
    };
    s.parseAnswer = [](const String& response) -> String {
        return jsonString(response, "sdp", max(0, response.indexOf("\"transport\"")));
    };
    return s;
}

String HttpSignaling::jsonEscape(const String& in) {
    String out; out.reserve(in.length() + in.length() / 16);
    for (char c : in) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c == '\r') out += "\\r";
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

String HttpSignaling::jsonString(const String& json, const char* key, int from) {
    String needle = String("\"") + key + "\"";
    int k = json.indexOf(needle, from); if (k < 0) return "";
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
}
