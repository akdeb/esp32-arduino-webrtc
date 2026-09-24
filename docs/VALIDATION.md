# Validation record and hardware acceptance

## Automated checks performed

- PlatformIO Arduino 3.1.3 / ESP-IDF 5.3 firmware compilation and linking for ESP32-S3 DevKitC without PSRAM and standard ESP32.
- Arduino CLI compilation from an installed ZIP, using stock Espressif Arduino 3.1.3 (the Arduino IDE build system).
- Private mbedTLS DTLS 1.2 loopback handshake with mutual certificates, negotiated AES128-CM/HMAC-SHA1-80 SRTP profile, and encrypted data exchange.
- Bundled libsrtp encrypt/decrypt roundtrip, tampered packet rejection, and replay rejection.
- Rate-scaled PCM timelines at 16/24/48 kHz, frame sizing, timestamp wrap, and independent 48 kHz Opus RTP configuration.
- Opus adapter failure/size/allocation tests using a mock API backend. These do not execute Espressif’s Xtensa codec.
- Browser Opus SDP tests for clock, rate, bitrate and mono preferences.
- G.711 µ-law known vectors and exhaustive signed-16-bit encode/decode error bounds.
- Sample-buffer startup, reordered packets, duplicates, partial/variable packet sizes, missing audio, long outages, overflow recovery, and timestamp wraparound.
- AddressSanitizer and UndefinedBehaviorSanitizer on audio, DTLS, and SRTP host tests.
- SDP fingerprint parsing, malformed/missing fingerprints, embedded NUL rejection, and conflicting fingerprints.
- JavaScript syntax and Python syntax checks for the browser demo.

Build sizes are compile-time snapshots, not runtime memory measurements.

## Hardware results (ESP32-S3-WROOM, no PSRAM, INMP441-style mic and MAX98357-style amp on separate I2S buses)

- `CodecSelfTest`: PASS at 16/24/48 kHz; maximum encode time 3.0–4.3 ms and decode time 1.1–1.9 ms per 20 ms frame; about 252–261 KB internal heap free.
- Chrome → board over the board's own SoftAP: two-way audio, no audible artifacts reported.
- Board → OpenAI `gpt-realtime` and `gpt-live-1` over an iPhone hotspot: HTTPS offer exchange, ICE, DTLS client role and SRTP working; calls of about 1.5–2.5 minutes. About 1–2% of outgoing frames dropped, no decode errors, minimum internal heap 36–40 KB at 48 kbit/s / complexity 0.
- 64 kbit/s at complexity 5 exceeded the 20 ms encode budget after about 20 s under network load (max encode 21 ms, heap minimum 6 KB). It is not recommended without PSRAM.

Bugs found by these runs and fixed: a non-null ICE server list with zero entries was rejected by `esp_peer` (every STUN-less call failed); a 10 ms ICE receive timeout broke DTLS over WAN round trips; the ICE candidate limit of 4 dropped OpenAI's 6 candidates; and allocating the codec before the 40 KB capture stack fragmented the heap. The `oai-events` data channel is negotiated, but no events were observed during the GPT-Live test, so it is unconfirmed. TURN, standard ESP32, and long soak tests remain untested.

## Hardware acceptance procedure

1. Disable PSRAM, flash the example, and record free/minimum internal heap before connecting, during DTLS, and after disconnecting.
2. First run the included `CodecSelfTest` on the board; then confirm the SDP selects `opus/48000/2` for Opus or `PCMU/8000` for G.711, ICE connects, both directions are audible, and the ESP32 keeps running with the browser microphone muted.
3. Run for at least 30 minutes. Record counters every two seconds, audible dropouts, end-to-end delay, and heap trend. In a quiet LAN, capture/playback/encode/decode errors should stay at zero; Opus encode time must fit within each 20 ms frame and transmit drops should not grow continually.
4. Stop/start 100 times. After initial global allocations, heap should return to a consistent baseline; no progressively shrinking free heap, dead tasks, or failed I2S reinitializations.
5. Introduce Wi-Fi loss and delay, then restore connectivity. Check that silence/rebuffering occurs instead of unbounded delay or replaying stale speech. Explicitly end/start to establish a new call; automatic renegotiation is not implemented.
6. Leave the call up for several hours to measure clock-drift rebuffering. Current drift handling is bounded reset, not transparent adaptive resampling.
7. Run an Arduino HTTPS request alongside a call to check coexistence with the core's TLS stack. Monitor audio while doing so; application network work still consumes CPU and heap.
8. Change one SDP fingerprint byte and confirm DTLS is rejected. Restore it and verify normal setup. Test with an authenticated signaling channel before production deployment.
9. Test with the final microphone, amplifier, supply, enclosure and volume. Assess echo separately; no device-side AEC is implemented.
10. Qualify STUN and TURN on separate networks before claiming WAN support.

Do not label this library “ESP-IDF-level stable” until these tests have been measured on the intended board and network.

## Higher-rate qualification

The 0.2 profiles use 24 kHz Opus by default, with 16 and 48 kHz options. The 24 kHz profile has been measured on an ESP32-S3 without PSRAM (see Hardware results). The 16 and 48 kHz profiles have only been exercised by `CodecSelfTest`, not in calls.
