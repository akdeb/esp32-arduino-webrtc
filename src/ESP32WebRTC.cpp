#include "ESP32WebRTC.h"
#include "detail/PlayoutBuffer.h"
#include "detail/AudioCodec.h"
#include "detail/Fingerprint.h"
#include "vendor/peer/esp_peer_default.h"
#include <Arduino.h>
#include <esp_heap_caps.h>
#include <esp_timer.h>
#include <freertos/event_groups.h>
#include <freertos/queue.h>
#include <atomic>
#include <new>
#include <cstring>
#if !defined(CONFIG_IDF_TARGET_ESP32) && !defined(CONFIG_IDF_TARGET_ESP32S3)
#error "ESP32 WebRTC currently supports ESP32 and ESP32-S3 only"
#endif
#if ESP_IDF_VERSION_MAJOR < 5
#error "ESP32 WebRTC requires Arduino-ESP32 3.x (ESP-IDF 5.x)"
#endif
namespace arduino_webrtc {
namespace {
constexpr EventBits_t PEER_DONE = 1, CAPTURE_DONE = 2, PLAY_DONE = 4;
constexpr size_t MAX_SIGNAL = 8192;
// esp_peer's DTLS certificate cache and SRTP initialization are process-global.
std::atomic<bool> instanceActive{false};
uint8_t expectedFingerprint[32]{};
bool haveFingerprint = false;
struct Signal { ESP32WebRTC::SignalType type; size_t size; char* data; };
struct TxFrame { uint32_t pts; int64_t captured; uint16_t size; uint8_t data[AudioCodec::maxPacketBytes]; };
struct RxFrame { uint32_t pts; uint16_t size; uint8_t data[AudioCodec::maxPacketBytes]; };
bool enqueueSignal(QueueHandle_t queue, ESP32WebRTC::SignalType type, const char* data, size_t size) {
    if (!queue || !data || !size || size > MAX_SIGNAL || uxQueueSpacesAvailable(queue) == 0) return false;
    if (data[size-1] == '\0') --size;
    if (!size || memchr(data, '\0', size)) return false;
    Signal message{type, size, static_cast<char*>(heap_caps_malloc(size+1, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT))};
    if (!message.data) return false;
    memcpy(message.data, data, size); message.data[size] = 0;
    if (xQueueSend(queue, &message, 0) != pdTRUE) { free(message.data); return false; }
    return true;
}
void drainSignals(QueueHandle_t queue) {
    if (!queue) return;
    Signal signal{};
    while (xQueueReceive(queue, &signal, 0) == pdTRUE) free(signal.data);
}
}
extern "C" int awrtc_verify_peer_digest(const unsigned char* digest) {
    unsigned diff = 0;
    for (size_t i=0;i<32;++i) diff |= digest[i] ^ expectedFingerprint[i];
    return haveFingerprint && diff == 0 ? 0 : -1;
}
struct ESP32WebRTC::Impl {
    AudioIO* audio = nullptr;
    Config config{};
    esp_peer_handle_t peer = nullptr;
    esp_peer_default_cfg_t defaults{};
    esp_peer_cfg_t peerConfig{};
    esp_peer_ice_server_cfg_t servers[3]{};
    char* strings[9]{};
    QueueHandle_t incoming = nullptr, outgoing = nullptr, tx = nullptr, rx = nullptr;
    EventGroupHandle_t done = nullptr;
    EventBits_t launched = 0;
    std::atomic<bool> running{false}, microphone{true};
    std::atomic<State> state{State::Stopped};
    std::atomic<uint32_t> sent{0}, received{0}, drops{0}, captureErrors{0}, playbackErrors{0}, signalDrops{0};
    std::atomic<int> error{0};
    std::atomic<uint32_t> rxDrops{0}, encodeErrors{0}, decodeErrors{0};
    std::atomic<uint32_t> maxEncodeUs{0}, maxDecodeUs{0}, encodeOverruns{0};
    std::atomic<uint32_t> missing{0}, late{0}, resyncs{0};
    std::atomic<bool> playbackReset{false};
    AudioCodec codec;
    void* playoutMemory = nullptr;
    int16_t* capturePcm = nullptr;
    int16_t* playbackPcm = nullptr;
    int16_t* decodePcm = nullptr;
    PlayoutBuffer playout;
    bool codecAccepted = true;
    static int onState(esp_peer_state_t status, void* context) {
        auto& self = *static_cast<Impl*>(context);
        if (status == ESP_PEER_STATE_CONNECTED) self.state = self.codecAccepted ? State::Connected : State::Failed;
        if (status == ESP_PEER_STATE_DISCONNECTED || status == ESP_PEER_STATE_CLOSED || status == ESP_PEER_STATE_CONNECT_FAILED) {
            self.state = status == ESP_PEER_STATE_CONNECT_FAILED ? State::Failed : State::Disconnected;
            self.playbackReset = true;
        }
        return 0;
    }
    static int onMessage(esp_peer_msg_t* msg, void* context) {
        auto& self = *static_cast<Impl*>(context);
        if (msg->type != ESP_PEER_MSG_TYPE_SDP && msg->type != ESP_PEER_MSG_TYPE_CANDIDATE) return 0;
        auto type = msg->type == ESP_PEER_MSG_TYPE_SDP ? SignalType::SDP : SignalType::Candidate;
        if (msg->size <= 0 || !enqueueSignal(self.outgoing, type, reinterpret_cast<char*>(msg->data), msg->size)) {
            ++self.signalDrops; self.error = ESP_PEER_ERR_OVER_LIMITED;
            return ESP_PEER_ERR_OVER_LIMITED;
        }
        return 0;
    }
    static int onAudioInfo(esp_peer_audio_stream_info_t* info, void* context) {
        auto& self = *static_cast<Impl*>(context);
        const bool opus = self.config.audio.codec == AudioCodecType::Opus;
        const auto expected = opus ? ESP_PEER_AUDIO_CODEC_OPUS : ESP_PEER_AUDIO_CODEC_G711U;
        if (info->codec != expected || (info->sample_rate && info->sample_rate != self.config.audio.rtpClockRate()) ||
            info->channel > (opus ? 2 : 1)) {
            self.codecAccepted = false;
            self.error = ESP_PEER_ERR_NOT_SUPPORT; self.state = State::Failed;
            return ESP_PEER_ERR_NOT_SUPPORT;
        }
        return 0;
    }
    static int onAudio(esp_peer_audio_frame_t* frame, void* context) {
        auto& self = *static_cast<Impl*>(context);
        if (!self.codecAccepted) return ESP_PEER_ERR_NOT_SUPPORT;
        if (!frame->data || frame->size <= 0 || frame->size > static_cast<int>(AudioCodec::maxPacketBytes)) {
            ++self.rxDrops; return ESP_PEER_ERR_BAD_DATA;
        }
        RxFrame packet{}; packet.pts=frame->pts; packet.size=frame->size;
        memcpy(packet.data,frame->data,packet.size);
        if (xQueueSend(self.rx,&packet,0)!=pdTRUE) {
            RxFrame stale;
            if(xQueueReceive(self.rx,&stale,0)==pdTRUE)++self.rxDrops;
            if(xQueueSend(self.rx,&packet,0)!=pdTRUE)++self.rxDrops;
        }
        ++self.received;
        return 0;
    }
    static void peerTask(void* context) {
        auto& self = *static_cast<Impl*>(context);
        int rc = esp_peer_new_connection(self.peer);
        if (rc) { self.error = rc; self.state = State::Failed; }
        while (self.running) {
            Signal msg{};
            // Bound work per iteration so signaling cannot starve RTP.
            for (unsigned n = 0; n < 2 && xQueueReceive(self.incoming, &msg, 0) == pdTRUE; ++n) {
                if (msg.type == SignalType::SDP) {
                    haveFingerprint = parseFingerprint(msg.data, msg.size, expectedFingerprint);
                    if (!haveFingerprint) {
                        self.error = ESP_PEER_ERR_BAD_DATA; self.state = State::Failed;
                        free(msg.data); continue;
                    }
                }
                esp_peer_msg_t input{};
                input.type = msg.type == SignalType::SDP ? ESP_PEER_MSG_TYPE_SDP : ESP_PEER_MSG_TYPE_CANDIDATE;
                input.data = reinterpret_cast<uint8_t*>(msg.data); input.size = msg.size;
                rc = esp_peer_send_msg(self.peer, &input);
                free(msg.data);
                if (rc) self.error = rc;
            }
            rc = esp_peer_main_loop(self.peer);
            if (rc) self.error = rc;
            TxFrame frame{};
            for (unsigned n = 0; n < 3 && xQueueReceive(self.tx, &frame, 0) == pdTRUE; ++n) {
                if (self.state != State::Connected || esp_timer_get_time() - frame.captured > 80000) { ++self.drops; continue; }
                esp_peer_audio_frame_t packet{};
                packet.pts = frame.pts; packet.data = frame.data; packet.size = frame.size;
                rc = esp_peer_send_audio(self.peer, &packet);
                if (rc) { self.error = rc; ++self.drops; } else ++self.sent;
            }
            vTaskDelay(1);
        }
        xEventGroupSetBits(self.done, PEER_DONE);
        vTaskDelete(nullptr);
    }
    static void captureTask(void* context) {
        auto& self = *static_cast<Impl*>(context);
        int16_t* pcm=self.capturePcm; const size_t frameSamples=self.config.audio.frameSamples();
        uint32_t pts=0;
        while(self.running) {
            const int64_t start=esp_timer_get_time(); size_t used=0;
            while(self.running && used<frameSamples && esp_timer_get_time()-start<40000) {
                size_t n=self.audio->read(pcm+used,frameSamples-used,20);
                if(n>frameSamples-used){++self.captureErrors;break;}
                used+=n; if(!n)vTaskDelay(1);
            }
            if(!self.running)break;
            if(used!=frameSamples){++self.captureErrors;memset(pcm+used,0,(frameSamples-used)*sizeof(int16_t));}
            TxFrame frame{};frame.pts=pts;frame.captured=start;pts+=20;
            if(self.state!=State::Connected)continue; // Drain DMA, without spending CPU encoding before a call.
            if(!self.microphone)memset(pcm,0,frameSamples*sizeof(int16_t));
            int64_t encodeStart=esp_timer_get_time();
            int encoded=self.codec.encode(pcm,frameSamples,frame.data,sizeof(frame.data));
            uint32_t elapsed=static_cast<uint32_t>(esp_timer_get_time()-encodeStart);
            if(elapsed>self.maxEncodeUs)self.maxEncodeUs=elapsed;
            if(elapsed>20000)++self.encodeOverruns;
            if(encoded<=0){++self.encodeErrors;self.error=encoded;continue;}
            frame.size=static_cast<uint16_t>(encoded);
            if(xQueueSend(self.tx,&frame,0)!=pdTRUE) {
                TxFrame stale;
                if(xQueueReceive(self.tx,&stale,0)==pdTRUE)++self.drops;
                if(xQueueSend(self.tx,&frame,0)!=pdTRUE)++self.drops;
            }
            // DMA is the sample clock; do not add per-frame scheduling delays.
        }
        xEventGroupSetBits(self.done,CAPTURE_DONE);vTaskDelete(nullptr);
    }
    static void playbackTask(void* context) {
        auto& self = *static_cast<Impl*>(context);
        const auto& format=self.config.audio;
        const size_t frameSamples=format.frameSamples();
        int16_t* pcm=self.playbackPcm;
        bool decodedBefore=false; uint32_t nextPts=0;
        while(self.running) {
            int64_t start=esp_timer_get_time();
            if(self.playbackReset.exchange(false)) {
                self.playout.reset(self.config.prefillMs);self.codec.resetDecoder();
                xQueueReset(self.rx);decodedBefore=false;
            }
            // esp_peer orders RTP before the callback. Keep stateful Opus decode
            // in that order; callbacks only copy compressed packets into a queue.
            RxFrame packet{};
            for(unsigned i=0;i<4 && xQueueReceive(self.rx,&packet,0)==pdTRUE;++i) {
                if(decodedBefore && static_cast<int32_t>(packet.pts-nextPts)<0){++self.rxDrops;continue;}
                if(decodedBefore && static_cast<int32_t>(packet.pts-nextPts)>200)self.codec.resetDecoder();
                int64_t decodeStart=esp_timer_get_time();
                int samples=self.codec.decode(packet.data,packet.size,self.decodePcm,format.maxDecodeSamples());
                uint32_t elapsed=static_cast<uint32_t>(esp_timer_get_time()-decodeStart);
                if(elapsed>self.maxDecodeUs)self.maxDecodeUs=elapsed;
                if(samples<=0){++self.decodeErrors;self.error=samples;continue;}
                self.playout.pushPcm(packet.pts,self.decodePcm,samples);
                nextPts=packet.pts+static_cast<uint32_t>(samples)*1000/format.sampleRate;decodedBefore=true;
            }
            self.playout.pop(pcm);
            self.missing=self.playout.counters.missingSamples;
            self.late=self.playout.counters.late;self.resyncs=self.playout.counters.resync;
            size_t written=0;
            while(self.running && written<frameSamples && esp_timer_get_time()-start<40000) {
                size_t n=self.audio->write(pcm+written,frameSamples-written,20);
                if(n>frameSamples-written)break;
                written+=n;if(!n)vTaskDelay(1);
            }
            if(written!=frameSamples)++self.playbackErrors;
        }
        xEventGroupSetBits(self.done,PLAY_DONE);vTaskDelete(nullptr);
    }
    void release() {
        if (peer) esp_peer_close(peer);
        drainSignals(incoming); drainSignals(outgoing);
        if (incoming) vQueueDelete(incoming);
        if (outgoing) vQueueDelete(outgoing);
        if (tx) vQueueDelete(tx);
        if (rx) vQueueDelete(rx);
        codec.end();
        free(playoutMemory);free(capturePcm);free(playbackPcm);free(decodePcm);
        if (done) vEventGroupDelete(done);
        for (auto p : strings) free(p);
    }
};
bool ESP32WebRTC::begin(AudioIO& audio, const Config& cfg) {
    lastBeginError_ = ESP_PEER_ERR_INVALID_ARG;
    if (impl_ || !cfg.onSignal || cfg.serverCount > 3 || cfg.prefillMs < 20 || cfg.prefillMs > 120 || cfg.prefillMs % 20) return false;
    if (!cfg.audio.valid() || (audio.sampleRate() && audio.sampleRate()!=cfg.audio.sampleRate)) return false;
    if (cfg.relayOnly && !cfg.serverCount) return false;
    bool expected = false;
    if (!instanceActive.compare_exchange_strong(expected, true)) {lastBeginError_=ESP_PEER_ERR_WRONG_STATE;return false;}
    lastBeginError_=ESP_PEER_ERR_NO_MEM;
    void* memory = heap_caps_malloc(sizeof(Impl), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!memory) { instanceActive = false; return false; }
    haveFingerprint = false;
    impl_ = new(memory) Impl;
    auto& s = *impl_;
    s.audio = &audio; s.config = cfg;
    const auto caps=MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT;
    const size_t pcmBytes=cfg.audio.frameSamples()*sizeof(int16_t);
    s.playoutMemory=heap_caps_calloc(1,PlayoutBuffer::storageBytes(cfg.audio.sampleRate),caps);
    s.capturePcm=static_cast<int16_t*>(heap_caps_malloc(pcmBytes,caps));
    s.playbackPcm=static_cast<int16_t*>(heap_caps_malloc(pcmBytes,caps));
    s.decodePcm=static_cast<int16_t*>(heap_caps_malloc(cfg.audio.maxDecodeSamples()*sizeof(int16_t),caps));
    if(!s.playoutMemory || !s.capturePcm || !s.playbackPcm || !s.decodePcm ||
       !s.playout.init(cfg.audio.sampleRate,s.playoutMemory,PlayoutBuffer::storageBytes(cfg.audio.sampleRate),cfg.prefillMs)) { end(); return false; }
    if(!s.codec.begin(cfg.audio)){lastBeginError_=s.codec.lastOpenError();end();return false;}
    s.incoming = xQueueCreate(4, sizeof(Signal)); s.outgoing = xQueueCreate(4, sizeof(Signal));
    s.tx = xQueueCreate(3, sizeof(TxFrame)); s.rx=xQueueCreate(4,sizeof(RxFrame)); s.done = xEventGroupCreate();
    if (!s.incoming || !s.outgoing || !s.tx || !s.rx || !s.done) { end(); return false; }
    for (unsigned i = 0; i < cfg.serverCount; ++i) {
        if (!cfg.servers[i].url) { end(); return false; }
        const char* values[] = {cfg.servers[i].url, cfg.servers[i].username, cfg.servers[i].password};
        for (unsigned j = 0; j < 3; ++j) {
            if (values[j]) { s.strings[i*3+j] = strdup(values[j]); if (!s.strings[i*3+j]) { end(); return false; } }
        }
        s.servers[i] = {s.strings[i*3], s.strings[i*3+1], s.strings[i*3+2]};
    }
    s.defaults.agent_recv_timeout = 10;
    s.defaults.max_candidates = 4;
    s.defaults.rtp_cfg.audio_recv_jitter.cache_size = 4096;
    s.defaults.rtp_cfg.audio_recv_jitter.cache_timeout = 60;
    s.defaults.rtp_cfg.send_pool_size = 6144;
    s.defaults.rtp_cfg.send_queue_num = 24;
    s.defaults.keep_role = true;
    auto& pc = s.peerConfig;
    pc.server_lists = s.servers; pc.server_num = cfg.serverCount;
    pc.role = cfg.offerer ? ESP_PEER_ROLE_CONTROLLING : ESP_PEER_ROLE_CONTROLLED;
    pc.ice_trans_policy = cfg.relayOnly ? ESP_PEER_ICE_TRANS_POLICY_RELAY : ESP_PEER_ICE_TRANS_POLICY_ALL;
    pc.audio_info.codec = cfg.audio.codec==AudioCodecType::Opus ? ESP_PEER_AUDIO_CODEC_OPUS : ESP_PEER_AUDIO_CODEC_G711U;
    // RFC 7587: SDP is opus/48000/2 even for a 16/24 kHz mono PCM pipeline.
    // esp_peer accepts frame PTS in milliseconds and handles the RTP conversion.
    pc.audio_info.sample_rate=cfg.audio.rtpClockRate();pc.audio_info.channel=cfg.audio.sdpChannels();
    pc.audio_dir = ESP_PEER_MEDIA_DIR_SEND_RECV; pc.no_auto_reconnect = true;
    pc.extra_cfg = &s.defaults; pc.extra_size = sizeof(s.defaults); pc.ctx = &s;
    pc.on_state = Impl::onState; pc.on_msg = Impl::onMessage;
    pc.on_audio_info = Impl::onAudioInfo; pc.on_audio_data = Impl::onAudio;
    int rc = esp_peer_open(&pc, esp_peer_get_default_impl(), &s.peer);
    if (rc) { lastBeginError_ = rc; end(); return false; }
    s.running = true; s.state = State::Connecting;
    // Leave Wi-Fi on core 0 and audio on core 1 on both supported dual-core chips.
    struct Worker { TaskFunction_t fn; const char* name; uint32_t stack; UBaseType_t priority; BaseType_t core; EventBits_t bit; };
    const bool opus=cfg.audio.codec==AudioCodecType::Opus;
    Worker tasks[] = {{Impl::peerTask,"rtc_peer",10240,5,0,PEER_DONE},
                      {Impl::captureTask,"rtc_capture",opus ? 40960u : 6144u,6,1,CAPTURE_DONE},
                      {Impl::playbackTask,"rtc_play",opus ? 16384u : 6144u,7,1,PLAY_DONE}};
    for (auto& task : tasks) {
        if (xTaskCreatePinnedToCore(task.fn, task.name, task.stack, &s, task.priority, nullptr, task.core) != pdPASS) {
            end(UINT32_MAX); return false;
        }
        s.launched |= task.bit;
    }
    lastBeginError_=0;
    return true;
}
ESP32WebRTC::~ESP32WebRTC() { end(UINT32_MAX); }
bool ESP32WebRTC::end(uint32_t timeoutMs) {
    if (!impl_) return true;
    auto& s = *impl_; s.running = false;
    if (s.launched) {
        TickType_t timeout = timeoutMs == UINT32_MAX ? portMAX_DELAY : pdMS_TO_TICKS(timeoutMs);
        if ((xEventGroupWaitBits(s.done, s.launched, pdFALSE, pdTRUE, timeout) & s.launched) != s.launched) return false;
    }
    s.release(); s.~Impl(); free(impl_); impl_ = nullptr; instanceActive = false;
    return true;
}
bool ESP32WebRTC::remoteSignal(SignalType type, const char* text, size_t size) {
    if (!impl_ || !impl_->running) return false;
    bool ok = enqueueSignal(impl_->incoming, type, text, size);
    if (!ok) ++impl_->signalDrops;
    return ok;
}
void ESP32WebRTC::poll() {
    if (!impl_) return;
    Signal signal{};
    // Snapshot limits callback traffic; no library methods may be called from it.
    unsigned count = uxQueueMessagesWaiting(impl_->outgoing);
    while (count-- && xQueueReceive(impl_->outgoing, &signal, 0) == pdTRUE) {
        impl_->config.onSignal(signal.type, signal.data, signal.size, impl_->config.context);
        free(signal.data);
    }
}
void ESP32WebRTC::setMicrophoneEnabled(bool enabled) { if (impl_) impl_->microphone = enabled; }
ESP32WebRTC::State ESP32WebRTC::state() const { return impl_ ? impl_->state.load() : State::Stopped; }
ESP32WebRTC::Stats ESP32WebRTC::stats() const {
    Stats out;out.lastError=lastBeginError_;
    out.freeInternalHeap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    out.minimumInternalHeap = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!impl_) return out;
    const auto& s = *impl_;
    out.sentFrames=s.sent; out.receivedPackets=s.received; out.txDrops=s.drops;
    out.captureErrors=s.captureErrors; out.playbackErrors=s.playbackErrors; out.signalDrops=s.signalDrops; out.lastError=s.error;
    out.missingSamples=s.missing;out.latePackets=s.late;out.resyncs=s.resyncs;
    out.rxDrops=s.rxDrops;out.encodeErrors=s.encodeErrors;out.decodeErrors=s.decodeErrors;
    out.maxEncodeUs=s.maxEncodeUs;out.maxDecodeUs=s.maxDecodeUs;out.encodeOverruns=s.encodeOverruns;
    out.sampleRate=s.config.audio.sampleRate;out.bitrate=s.config.audio.codec==AudioCodecType::Opus?s.config.audio.bitrate:64000;
    return out;
}
}
