// Fault-injected API tests for our adapter. These do NOT execute the Xtensa codec.
#include "detail/AudioCodec.h"
#include "vendor/codec/encoder/impl/esp_opus_enc.h"
#include "vendor/codec/decoder/impl/esp_opus_dec.h"
#include <cassert>
#include <cstring>
#include <cstdio>
#include <vector>
using namespace arduino_webrtc;
static uint32_t currentRate;
static unsigned encoderLive, decoderLive;
static bool rejectDecoder, corruptSize, failEncode, failDecode;
extern "C" {
esp_audio_err_t esp_opus_enc_open(void* cfg,uint32_t size,void** handle) {
    assert(size==sizeof(esp_opus_enc_config_t));auto& c=*static_cast<esp_opus_enc_config_t*>(cfg);
    assert(c.channel==1 && c.bits_per_sample==16 && c.frame_duration==ESP_OPUS_ENC_FRAME_DURATION_20_MS);
    assert(c.enable_vbr && !c.enable_fec && !c.enable_dtx);
    currentRate=c.sample_rate;*handle=&encoderLive;++encoderLive;return ESP_AUDIO_ERR_OK;
}
esp_audio_err_t esp_opus_enc_get_frame_size(void*,int* in,int* out) {
    *in=currentRate/50*2;*out=2048;return ESP_AUDIO_ERR_OK; // recommendation may exceed RTP packet cap
}
void esp_opus_enc_close(void*) {assert(encoderLive);--encoderLive;}
esp_audio_err_t esp_opus_enc_process(void*,esp_audio_enc_in_frame_t* in,esp_audio_enc_out_frame_t* out) {
    assert(in->len==currentRate/50*2 && out->len==2048);
    if(failEncode)return ESP_AUDIO_ERR_FAIL;
    out->buffer[0]=0xf8;out->buffer[1]=0xff;out->buffer[2]=0xfe;out->encoded_bytes=3;return ESP_AUDIO_ERR_OK;
}
esp_audio_err_t esp_opus_dec_open(void* cfg,uint32_t size,void** handle) {
    assert(size==sizeof(esp_opus_dec_cfg_t));auto& c=*static_cast<esp_opus_dec_cfg_t*>(cfg);
    assert(c.sample_rate==currentRate && c.channel==1 && !c.self_delimited);
    if(rejectDecoder)return ESP_AUDIO_ERR_MEM_LACK;
    *handle=&decoderLive;++decoderLive;return ESP_AUDIO_ERR_OK;
}
esp_audio_err_t esp_opus_dec_close(void*) {assert(decoderLive);--decoderLive;return ESP_AUDIO_ERR_OK;}
esp_audio_err_t esp_opus_dec_reset(void*) {return ESP_AUDIO_ERR_OK;}
esp_audio_err_t esp_opus_dec_decode(void*,esp_audio_dec_in_raw_t* input,esp_audio_dec_out_frame_t* output,esp_audio_dec_info_t* info) {
    if(failDecode)return ESP_AUDIO_ERR_FAIL;
    const auto samples=opusPacketSamples(input->buffer,input->len,currentRate);
    assert(output->len>=samples*2);memset(output->buffer,0,samples*2);
    output->decoded_size=samples*2+(corruptSize?2:0);input->consumed=input->len;
    info->sample_rate=currentRate;info->channel=1;info->bits_per_sample=16;return ESP_AUDIO_ERR_OK;
}
}
int main() {
    for(uint32_t rate : {16000u,24000u,48000u}) {
        AudioFormat format;format.sampleRate=rate;AudioCodec codec;
        assert(codec.begin(format));assert(!codec.begin(format));
        std::vector<int16_t> input(format.frameSamples(),1000),output(format.maxDecodeSamples());
        uint8_t packet[AudioCodec::maxPacketBytes];
        assert(codec.encode(input.data(),input.size()-1,packet,sizeof(packet))<0);
        assert(codec.encode(input.data(),input.size(),packet,1)<0);
        int n=codec.encode(input.data(),input.size(),packet,sizeof(packet));assert(n==3);
        assert(codec.decode(packet,n,output.data(),input.size()-1)<0);
        assert(codec.decode(packet,n,output.data(),output.size())==static_cast<int>(input.size()));
        corruptSize=true;assert(codec.decode(packet,n,output.data(),output.size())<0);corruptSize=false;
        failEncode=true;assert(codec.encode(input.data(),input.size(),packet,sizeof(packet))<0);failEncode=false;
        failDecode=true;assert(codec.decode(packet,n,output.data(),output.size())<0);failDecode=false;
        codec.end();assert(!encoderLive && !decoderLive);
        rejectDecoder=true;assert(!codec.begin(format));assert(!encoderLive && !decoderLive);rejectDecoder=false;
    }
    AudioFormat g711;g711.codec=AudioCodecType::G711U;g711.sampleRate=8000;
    AudioCodec codec;assert(codec.begin(g711));int16_t pcm[160]{};uint8_t payload[160];
    assert(codec.encode(pcm,160,payload,sizeof(payload))==160);
    assert(codec.decode(payload,160,pcm,160)==160 && pcm[0]==0);
    puts("PASS: codec adapter rate configuration, packet bounds, failure propagation and allocation cleanup (mock backend)");
}
