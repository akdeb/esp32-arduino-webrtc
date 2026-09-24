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

Build sizes are compile-time snapshots, not runtime memory measurements. No microphone, amplifier, ESP32, TURN service, or browser-to-device call was available for end-to-end qualification.

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

The 0.2 profiles use 24 kHz Opus by default, with 16 and 48 kHz options. Full-duplex operation without PSRAM, actual codec timings, audio quality, and Opus/browser interoperability remain unmeasured until run on a physical ESP32. The on-device self-test is supplied for that purpose and has only been compiled here.
