// Actual on-device codec/memory/timing test. No Wi-Fi or I2S hardware required.
// Upload to the target board with PSRAM disabled and inspect Serial output.
#include <Arduino.h>
#include <ESP32WebRTC.h>
#include <detail/AudioCodec.h>
#include <esp_heap_caps.h>
#include <esp_timer.h>
#include <cmath>
#include <algorithm>
using arduino_webrtc::AudioCodec;
void codecTest(void*) {
    for(uint32_t rate : {16000u,24000u,48000u}) {
        arduino_webrtc::AudioFormat format;format.sampleRate=rate;
        size_t n=format.frameSamples(),capacity=format.maxDecodeSamples();
        int16_t* input=static_cast<int16_t*>(malloc(n*2));
        int16_t* output=static_cast<int16_t*>(malloc(capacity*2));
        uint8_t packet[AudioCodec::maxPacketBytes];
        AudioCodec codec;
        if(!input || !output || !codec.begin(format)) {
            Serial.printf("%lu Hz: allocation/codec open failed (%d)\n",rate,codec.lastOpenError());
            free(input);free(output);continue;
        }
        uint32_t maxEncode=0,maxDecode=0,errors=0;size_t packetBytes=0;bool audible=false;
        for(unsigned frame=0;frame<100;++frame) {
            for(size_t i=0;i<n;++i)input[i]=static_cast<int16_t>(8000*sin(2*3.141592653589793*1000*(frame*n+i)/rate));
            int64_t start=esp_timer_get_time();int encoded=codec.encode(input,n,packet,sizeof(packet));
            maxEncode=std::max(maxEncode,static_cast<uint32_t>(esp_timer_get_time()-start));
            if(encoded<=0){++errors;continue;}
            packetBytes+=encoded;start=esp_timer_get_time();
            int decoded=codec.decode(packet,encoded,output,capacity);
            maxDecode=std::max(maxDecode,static_cast<uint32_t>(esp_timer_get_time()-start));
            if(decoded!=static_cast<int>(n))++errors;
            else for(int i=0;i<decoded;++i)if(std::abs(output[i])>100)audible=true;
            vTaskDelay(1);
        }
        Serial.printf("%lu Hz: %s, errors=%lu, max encode=%lu us, max decode=%lu us, avg packet=%u B, free internal=%u B, stack watermark=%u\n",
            rate,errors==0 && audible?"PASS":"FAIL",errors,maxEncode,maxDecode,static_cast<unsigned>(packetBytes/100),
            static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT)),
            static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)));
        codec.end();free(input);free(output);
    }
    Serial.println("Codec self-test complete. This does not measure Wi-Fi/DTLS or I2S load.");
    vTaskDelete(nullptr);
}
void setup() {
    Serial.begin(115200);delay(2000);
    if(xTaskCreatePinnedToCore(codecTest,"codec_test",48*1024,nullptr,5,nullptr,1)!=pdPASS)
        Serial.println("Cannot allocate codec test stack");
}
void loop(){delay(1000);}
