# Third-party provenance

| Component | Pinned source | License |
|---|---|---|
| esp_peer 1.5.3, source and ESP32/S3 `libpeer_default.a` | [esp-webrtc-solution v1.3.0](https://github.com/espressif/esp-webrtc-solution/tree/3971094e2e7c2ab7cb4de59e4eae710e1902d2b4/components/esp_peer), commit `3971094e2e7c2ab7cb4de59e4eae710e1902d2b4` | [Espressif Modified MIT](src/vendor/peer/LICENSE), Espressif products only |
| esp_libsrtp | [esp-adf-libs](https://github.com/espressif/esp-adf-libs/tree/a1c9747e62e9f78444570ce6dfb0c4143de98393/esp_libsrtp), commit `a1c9747e62e9f78444570ce6dfb0c4143de98393` | [Upstream license](src/vendor/srtp/LICENSE), plus copyright notices in source |
| esp_audio_codec 2.6.2, headers and ESP32/S3 archives | [esp-adf-libs](https://github.com/espressif/esp-adf-libs/tree/a1c9747e62e9f78444570ce6dfb0c4143de98393/esp_audio_codec), same pinned commit as above | [Espressif Modified MIT](src/vendor/codec/LICENSE), Espressif products only |
| mbedTLS 3.6.6 | [Mbed-TLS](https://github.com/Mbed-TLS/mbedtls/tree/0bebf8b8c7f07abe3571ded48a11aa907a1ffb20), tag `mbedtls-3.6.6`/`v3.6.6`, commit `0bebf8b8c7f07abe3571ded48a11aa907a1ffb20` | [Upstream license](src/vendor/tls/LICENSE) and `LICENSES/` |

The Espressif peer implementation includes precompiled proprietary implementation archives distributed under its upstream license. They are copied unchanged. This project does not claim those archive sources are available here.

`tools/vendor.py` checks the source revisions and regenerates `src/vendor` and the peer/audio-codec archives for both targets. Supply local clones as its three arguments, in the order shown above. It never fetches automatically.

Port modifications are explicit in the generator:

- Private includes use relative paths for Arduino's recursive library build. TLS/SRTP C filenames have distinct prefixes because Arduino merges objects by basename into one archive.
- Private TLS identifiers, macros, and guards receive `awrtc_` / `AWRTC_` prefixes to avoid collisions with the core's mbedTLS configuration. The private configuration enables TLS 1.2 ECDHE-ECDSA and DTLS-SRTP, with 4 KB record buffers.
- DTLS uses an ESP hardware entropy callback already provided by the upstream adapter. The wrapper supplies monotonic timers through `esp_timer`.
- Only AES128-CM/HMAC-SHA1-80 is offered, matching the adapter’s SRTP policy; null encryption and mismatched 32-bit authentication profiles are removed.
- Both DTLS roles request a peer certificate, and a handshake hook compares its digest to the SDP fingerprint.
- SRTP initialization/deinitialization reference counting is balanced across calls. Failed SRTP encryption returns an empty packet. Early initialization failures and certificate pre-generation release their allocations.
- The generated self-signed certificate expiration is extended to 2040; WebRTC identity is authenticated by SDP fingerprint, not public CA trust.
- An IDF 5.3 logging ABI adapter is provided outside the vendor directory for archives that use IDF 5.4's logging entry point.

Reference documentation: [Espressif WebRTC solution](https://docs.espressif.com/projects/esp-adf/en/latest/solution-center/esp-webrtc-solution.html), [Arduino library specification](https://docs.arduino.cc/arduino-cli/library-specification/).

Opus sample rates and resource guidance: [Espressif codec README](https://github.com/espressif/esp-adf-libs/tree/a1c9747e62e9f78444570ce6dfb0c4143de98393/esp_audio_codec), [Opus RTP clock and SDP requirements (RFC 7587)](https://www.rfc-editor.org/rfc/rfc7587.html#section-4.1). The codec archives are copied unchanged; unused codec objects are removed by the linker.
