# ESP32 Arduino WebRTC

An experimental, self-contained Arduino library for **two-way WebRTC audio on ESP32 and ESP32-S3**, with I2S microphone input and speaker output. Designed to run without PSRAM. Includes a browser calling example.

**Version 0.2 is a build-tested prototype, not a hardware-qualified stable release.** No board was connected during development. A successful compile does not establish the runtime heap budget, browser interoperability, or long-call audio stability. See [validation](docs/VALIDATION.md).

## What is included

- Espressif `esp_peer` 1.5.3 for ICE, RTP/RTCP and WebRTC transport.
- Bundled SRTP and a private, symbol-isolated mbedTLS 3.6.6 DTLS implementation. Stock Arduino cores do not need rebuilding or extra SDK flags.
- SHA-256 SDP fingerprint verification of the remote DTLS certificate.
- **Opus at 16, 24, or 48 kHz**, mono signed 16-bit PCM, with 20 ms outgoing packets. Default: **24 kHz at 48 kbit/s**, complexity 0.
- G.711 µ-law (PCMU) at 8 kHz remains available as a lower-compute profile.
- The Opus encoder/decoder is Espressif `esp_audio_codec` 2.6.2, the same component family used by its ESP-IDF media pipeline.
- Local PCM and the Opus RTP clock are configured separately: SDP always uses `opus/48000/2`, including for mono 24 kHz capture and playback.
- Separate FreeRTOS tasks for peer networking, I2S capture and I2S playback. Audio follows the DMA clock, independent of Arduino `loop()`.
- A fixed 200 ms sample timeline with 60 ms default prefill, packet reordering, fades for missing samples, rebuffering after outages, and bounded overflow recovery.
- A three-frame transmit queue that discards stale audio instead of allowing latency to grow indefinitely.
- Rate-sized internal-RAM application buffers, microphone mute, and memory/drop/error/codec-timing counters.
- Compressed receive packets are decoded on the playback task; the peer callback only copies them into a bounded queue.

This release does **not** include device-side acoustic echo cancellation, video, or a data-channel API. Opus FEC and DTX are disabled; missing playback samples fade toward silence. Use headphones, low speaker volume, or microphone mute to avoid acoustic feedback. Opus improves bandwidth/quality but uses significantly more CPU, heap, and stack than G.711.

## Arduino IDE

1. Install **esp32 by Espressif Systems 3.1.3** in Boards Manager. Arduino 2.x cores are not supported. Later 3.x versions need separate qualification.
2. Install `dist/ESP32-Arduino-WebRTC-0.2.0.zip` using **Sketch → Include Library → Add .ZIP Library**. All transport dependencies are inside the ZIP.
3. Select **ESP32S3 Dev Module** or **ESP32 Dev Module**. Disable PSRAM for the first test. Select a partition scheme with at least a 2 MB application slot; **Huge APP** works for the example.
4. Open **File → Examples → ESP32 Arduino WebRTC → BrowserAudio**.
5. Set the Wi-Fi credentials and I2S pins, compile and upload. Open Serial Monitor at 115200 baud.

No ESP-IDF project, custom Arduino core, additional Arduino libraries, or cloud service is needed for the LAN example. The included precompiled Espressif engine restricts this release to ESP32 and ESP32-S3.

## PlatformIO (Arduino framework)

This repository is also a ready-to-build example project:

```sh
pio run -e esp32s3
pio run -e esp32s3 -t upload
pio device monitor -b 115200
```

Use `-e esp32` for a standard ESP32 board. The pinned pioarduino platform supplies Arduino 3.1.3; the older official PlatformIO `espressif32` package commonly supplies Arduino 2.x and is unsuitable for this library.

For an existing project, copy the library into `lib/ESP32-Arduino-WebRTC/`, including `src`, `tools`, `library.json`, and `library.properties`. Use:

```ini
[env:esp32s3]
platform = https://github.com/pioarduino/platform-espressif32/releases/download/53.03.13/platform-espressif32.zip
board = esp32-s3-devkitc-1
framework = arduino
board_build.arduino.memory_type = qio_qspi
board_build.partitions = huge_app.csv
monitor_speed = 115200
```

The library's PlatformIO script automatically links the correct peer archive. For a local checkout, `lib_deps = ESP32-Arduino-WebRTC=symlink:///absolute/path/to/esp32-arduino-webrtc` also works.

## I2S wiring

The example uses Philips I2S with **32-bit stereo slots**, converting the selected microphone slot into 16-bit mono and duplicating playback into both speaker slots. BCLK and WS are shared between RX and TX. Suitable devices include an INMP441-style I2S microphone and a MAX98357A-style I2S amplifier. Connect their grounds together and follow the individual modules' power requirements.

| Signal | ESP32-S3 defaults | ESP32 defaults | Connection |
|---|---:|---:|---|
| BCLK | GPIO 4 | GPIO 26 | Microphone SCK and amplifier BCLK |
| WS/LRCLK | GPIO 5 | GPIO 25 | Microphone WS and amplifier LRC |
| DIN | GPIO 6 | GPIO 33 | Microphone SD → ESP32 |
| DOUT | GPIO 7 | GPIO 22 | ESP32 → amplifier DIN |

Set the microphone L/R select for the left slot, or set `pins.rightMic = true`. Check your board's schematic before using these GPIOs. PDM microphones and boards with an I2C-controlled codec need a different `AudioIO` implementation or codec initialization.

## Make a browser call

1. Flash the example and note its IP address in Serial Monitor.
2. Put the computer and ESP32 on the same LAN, with client isolation disabled.
3. From this checkout or the extracted library directory, run:

   ```sh
   python3 tools/demo_server.py --board 192.168.1.123
   ```

4. Open **http://localhost:8080**, allow microphone access, then select **Start call**.

The localhost bridge carries SDP and statistics over HTTP. **Audio travels directly between the browser and ESP32 over WebRTC**, not through Python or WebSockets. The browser reads `/config`, selects Opus or PCMU to match the firmware, and includes the requested PCM bandwidth and bitrate preferences in the Opus SDP. Browser hardware capture may use a different native sample rate; the ESP32 decoder produces the configured local rate. Python needs no third-party packages.

The demo uses an unauthenticated LAN-only HTTP signaling endpoint. It is a development example; for a deployed device, supply authenticated signaling. The library accepts SDP and ICE candidates from your existing HTTP, MQTT, or WebSocket signaling service. STUN/TURN settings are available in `Config`; cross-network behavior and UDP TURN have not been tested in this release. TURNS is not exposed by this wrapper because a TURN CA configuration API is not yet provided.

## Audio rate and quality

The earlier 8 kHz limit came from choosing G.711, not from Arduino. ESP-IDF implementations obtain higher-rate audio by using Opus and configuring capture/playback at the desired PCM rate. That is now supported here too.

| Profile | PCM samples / 20 ms | PCM bytes / 20 ms | Default encoded bitrate | RTP clock |
|---|---:|---:|---:|---:|
| G.711, 8 kHz mono | 160 | 320 | 64 kbit/s, fixed | 8 kHz |
| Opus, 16 kHz mono | 320 | 640 | 48 kbit/s, configurable | 48 kHz |
| **Opus, 24 kHz mono** | **480** | **960** | **48 kbit/s, configurable** | **48 kHz** |
| Opus, 48 kHz mono | 960 | 1920 | 48 kbit/s, configurable | 48 kHz |

At 24 kHz, PCM represents 384 kbit/s before compression. A 48 kbit/s Opus target averages about 120 encoded bytes per 20 ms; VBR packet sizes vary. The `48000` in an Opus SDP line is a transport timestamp clock, not a requirement to clock the microphone or speaker at 48 kHz. `/2` in that line is also required by the Opus RTP specification; this library encodes and renders mono.

Select a profile before starting I2S and WebRTC:

```cpp
ESP32WebRTC::Config cfg;
cfg.audio.codec = ESP32WebRTC::Codec::Opus;
cfg.audio.sampleRate = 24000;   // also supports 16000 or 48000
cfg.audio.bitrate = 48000;      // compressed bits/second
cfg.audio.complexity = 0;       // 0..10; higher needs more CPU
cfg.onSignal = sendSignal;

WebRTCI2S::Pins pins;
if (!audio.begin(pins, cfg.audio.sampleRate)) { /* handle failure */ }
if (!rtc.begin(audio, cfg)) { /* inspect rtc.stats().lastError */ }
```

The I2S and PCM codec rates must match; `begin()` rejects a mismatch for `WebRTCI2S`. Opus bitrate limits exposed by this profile are 16–64 kbit/s at 16 kHz, and 40–64 kbit/s at 24/48 kHz, within the published Espressif encoder ranges. G.711 requires `codec = G711U` and `sampleRate = 8000`.

The example defaults to Opus 24 kHz. Set `WEBRTC_SAMPLE_RATE` to 16000/24000/48000 at the top of the sketch, or use these PlatformIO environments:

```sh
pio run -e esp32s3         # Opus 24 kHz, PSRAM disabled
pio run -e esp32           # Opus 24 kHz on standard ESP32
pio run -e esp32s3_16k     # Opus 16 kHz
pio run -e esp32s3_48k     # Opus 48 kHz
pio run -e esp32s3_g711    # G.711 8 kHz
```

Version 0.2 changes the default configuration from 8 kHz G.711 to 24 kHz Opus. Custom `AudioIO` implementations must use the matching rate; their default `sampleRate()` of zero means the application takes responsibility for that match.

## Minimal API

```cpp
#include <ESP32WebRTC.h>
#include <WebRTCI2S.h>

WebRTCI2S audio;
ESP32WebRTC rtc;

void sendSignal(ESP32WebRTC::SignalType type,
                const char* data, size_t length, void* context) {
  // Copy/send exactly length bytes to your signaling service.
  // Do not call rtc methods from this callback.
}

// After Wi-Fi is connected and WiFi.setSleep(false):
// WebRTCI2S::Pins pins;
// audio.begin(pins, 24000);
// ESP32WebRTC::Config config;
// config.onSignal = sendSignal;
// config.offerer = false; // browser sends the offer
// rtc.begin(audio, config);

// In loop(): rtc.poll();
// On incoming SDP: rtc.remoteSignal(ESP32WebRTC::SignalType::SDP, data, length);
// For push-to-talk: rtc.setMicrophoneEnabled(false);
// Before destroying audio: wait until rtc.end() returns true, then audio.end().
```

`begin`, `remoteSignal`, `poll`, and `end` must be called from the same application task. `poll()` dispatches signaling callbacks; it does not drive audio. Signaling buffers are copied and capped at 8192 bytes, with four queued messages in each direction. Check every return value. Calls that cannot enqueue return `false`; statistics expose dropped messages and backend errors.

Only one active instance is supported because the underlying SRTP/certificate cache has process-global state. ICE URLs and credentials are copied by `begin()`. Keep the `AudioIO` instance and callback context alive until `end()` succeeds. `end()` never force-deletes a task that could still access memory; after a timeout, retry. The destructor waits for all tasks to finish, so custom audio drivers must honor I/O timeouts.

For custom hardware, implement `AudioIO::read` and `write`. They run concurrently on separate tasks, must pace audio at the configured sample rate, return sample counts (not bytes), and honor the supplied timeout. Partial transfers are supported. Do not allocate or block on networking in these methods.

## Memory and stability

The implementation has no mandatory PSRAM allocation, and firmware builds are checked with PSRAM disabled. This is **not a measured guarantee** that full-duplex Opus plus your application fits or meets real-time deadlines without PSRAM. The wrapper bounds its queues and audio buffers. It does **not** eliminate dynamic allocation in ICE, DTLS, SRTP, Wi-Fi, or signaling. The example's static RAM is about 62 KB on S3 and 64 KB on ESP32; these numbers exclude heap allocated after startup.

Watch `/stats` and the browser's statistics panel during calls. Check `freeInternalHeap`, `minInternalHeap`, `captureErrors`, `playbackErrors`, `txDrops`, and `missingSamples`. Zero I/O errors in a quiet LAN test is the first audio-health check. For Opus, also inspect `encodeErrors`, `decodeErrors`, `maxEncodeUs`, `maxDecodeUs`, and `encodeOverruns`; sustained encode times above 20,000 µs cannot keep up with 20 ms frames. `missingSamples` is a sample count, not a packet count. Long clock drift is bounded by occasional rebuffering; this version does not resample to correct independent device clocks.

Keep Wi-Fi power saving off, avoid flash writes during calls, and start with other services disabled. Opus uses a 40 KB capture/encoder stack, following Espressif's example, plus a 16 KB decode/playback stack and 10 KB peer stack. Codec state, Wi-Fi, DTLS, queues, I2S DMA, and PCM storage are additional allocations. The 200 ms PCM timeline uses about 10.2 KB at 24 kHz and 20.4 KB at 48 kHz. Optional PSRAM can provide heap headroom where the core permits it; task stacks and wrapper audio buffers stay internal.

Upload **Examples → ESP32 Arduino WebRTC → CodecSelfTest** to run the actual Espressif encoder and decoder at all three rates on your board. It reports timing, output validity, free internal heap, and stack watermark. This test uses a tone and needs no microphone or amplifier; it does not include Wi-Fi, DTLS, or I2S load. Run the browser soak test afterwards.

## Development

```sh
./test/run.sh                       # audio and SDP parser tests
./test/tls_smoke.sh                 # private DTLS handshake and encrypted roundtrip
./test/srtp_smoke.sh                 # SRTP encryption, tamper and replay checks
node test/sdp_test.js               # Opus SDP preferences / transport clock
pio run -e esp32s3 -e esp32         # stock Arduino firmware builds
python3 tools/package.py           # reproducible installable ZIP
```

Dependency provenance and deterministic vendoring instructions are in [THIRD_PARTY.md](THIRD_PARTY.md). The wrapper is MIT licensed; bundled Espressif components carry Espressif-only terms and mbedTLS carries its upstream license. This package has not been published to Arduino Library Manager or PlatformIO Registry.
