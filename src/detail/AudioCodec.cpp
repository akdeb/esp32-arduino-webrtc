#include "AudioCodec.h"
#include "G711.h"
#include <cstdlib>
#include <cstring>
#include "../vendor/codec/encoder/impl/esp_opus_enc.h"
#include "../vendor/codec/decoder/impl/esp_opus_dec.h"
namespace arduino_webrtc {
bool AudioCodec::begin(const AudioFormat& f) {
    if (opened_ || !f.valid()) return false;
    format_=f; openError_=0;
    if (f.codec == AudioCodecType::G711U) { opened_=true; return true; }
    esp_opus_enc_config_t enc{};
    enc.sample_rate=f.sampleRate; enc.channel=1; enc.bits_per_sample=16;
    enc.bitrate=f.bitrate; enc.complexity=f.complexity;
    enc.frame_duration=ESP_OPUS_ENC_FRAME_DURATION_20_MS;
    enc.application_mode=ESP_OPUS_ENC_APPLICATION_VOIP;
    enc.enable_vbr=true; enc.enable_fec=false; enc.enable_dtx=false;
    openError_=esp_opus_enc_open(&enc,sizeof(enc),&encoder_);
    if (openError_) { end(); return false; }
    int inBytes=0,outBytes=0;
    openError_=esp_opus_enc_get_frame_size(encoder_,&inBytes,&outBytes);
    if (openError_ || inBytes!=static_cast<int>(f.frameSamples()*2) || outBytes<=0 || outBytes>8192) {
        if (!openError_) openError_=ESP_AUDIO_ERR_NOT_SUPPORT;
        end(); return false;
    }
    encodeCapacity_=static_cast<size_t>(outBytes);
    encodeScratch_=static_cast<uint8_t*>(malloc(encodeCapacity_));
    if(!encodeScratch_){openError_=ESP_AUDIO_ERR_MEM_LACK;end();return false;}
    esp_opus_dec_cfg_t dec{};
    dec.sample_rate=f.sampleRate; dec.channel=1;
    dec.frame_duration=ESP_OPUS_DEC_FRAME_DURATION_INVALID;
    dec.self_delimited=false; // RTP carries raw Opus, not Ogg or length-prefixed frames.
    openError_=esp_opus_dec_open(&dec,sizeof(dec),&decoder_);
    if (openError_) { end(); return false; }
    opened_=true; return true;
}
void AudioCodec::end() {
    if(encoder_)esp_opus_enc_close(encoder_);
    if(decoder_)esp_opus_dec_close(decoder_);
    encoder_=decoder_=nullptr;free(encodeScratch_);encodeScratch_=nullptr;encodeCapacity_=0;opened_=false;
}
int AudioCodec::encode(int16_t* pcm, size_t n, uint8_t* out, size_t cap) {
    if(!opened_ || !pcm || !out || n!=format_.frameSamples())return ESP_AUDIO_ERR_INVALID_PARAMETER;
    if(format_.codec==AudioCodecType::G711U) {
        if(cap<n)return ESP_AUDIO_ERR_BUFF_NOT_ENOUGH;
        for(size_t i=0;i<n;++i)out[i]=encodeMuLaw(pcm[i]);
        return static_cast<int>(n);
    }
    esp_audio_enc_in_frame_t input{}; input.buffer=reinterpret_cast<uint8_t*>(pcm); input.len=n*2;
    esp_audio_enc_out_frame_t output{}; output.buffer=encodeScratch_; output.len=encodeCapacity_;
    int rc=esp_opus_enc_process(encoder_,&input,&output);
    if(rc)return rc;
    if(output.encoded_bytes>cap || output.encoded_bytes>encodeCapacity_)return ESP_AUDIO_ERR_BUFF_NOT_ENOUGH;
    memcpy(out,encodeScratch_,output.encoded_bytes);
    return static_cast<int>(output.encoded_bytes);
}
int AudioCodec::decode(uint8_t* packet, size_t size, int16_t* out, size_t cap) {
    if(!opened_ || !packet || !size || !out)return ESP_AUDIO_ERR_INVALID_PARAMETER;
    if(format_.codec==AudioCodecType::G711U) {
        if(size>960 || size>cap)return ESP_AUDIO_ERR_BUFF_NOT_ENOUGH;
        for(size_t i=0;i<size;++i)out[i]=decodeMuLaw(packet[i]);
        return static_cast<int>(size);
    }
    const size_t expected=opusPacketSamples(packet,size,format_.sampleRate);
    if(!expected || expected>cap)return ESP_AUDIO_ERR_INVALID_PARAMETER;
    esp_audio_dec_in_raw_t input{}; input.buffer=packet; input.len=size;
    esp_audio_dec_out_frame_t output{}; output.buffer=reinterpret_cast<uint8_t*>(out); output.len=cap*2;
    esp_audio_dec_info_t info{};
    int rc=esp_opus_dec_decode(decoder_,&input,&output,&info);
    if(rc)return rc;
    if(input.consumed!=size || output.decoded_size!=expected*2 || info.channel!=1 || info.sample_rate!=format_.sampleRate)
        return ESP_AUDIO_ERR_FAIL;
    return static_cast<int>(expected);
}
void AudioCodec::resetDecoder() { if(decoder_)esp_opus_dec_reset(decoder_); }
}
