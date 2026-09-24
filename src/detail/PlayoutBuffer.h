#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "G711.h"
namespace arduino_webrtc {
// Caller-owned, rate-sized storage. Only the playback task mutates this timeline.
class PlayoutBuffer {
public:
    struct Counters { uint32_t late=0, resync=0, missingSamples=0; } counters;
    static size_t storageBytes(uint32_t rate) { size_t n=rate/5; return n*sizeof(int16_t)+(n+7)/8; }
    bool init(uint32_t rate, void* storage, size_t bytes, unsigned prefillMs=60) {
        if(!storage || (rate!=8000 && rate!=16000 && rate!=24000 && rate!=48000) || bytes<storageBytes(rate) ||
           prefillMs<20 || prefillMs>120 || prefillMs%20) return false;
        rate_=rate; capacity_=rate/5; frameSamples_=rate/50;
        samples_=static_cast<int16_t*>(storage);
        valid_=reinterpret_cast<uint8_t*>(samples_+capacity_);
        reset(prefillMs);return true;
    }
    void reset(unsigned prefillMs=60) {
        if(valid_)std::memset(valid_,0,(capacity_+7)/8);
        read_=high_=0;head_=0;primed_=started_=false;
        target_=prefillMs*(rate_/1000);last_=0;emptyFrames_=0;
    }
    bool push(uint32_t pts,const uint8_t* bytes,size_t count) {
        if(!bytes || rate_!=8000 || count>960)return false;
        return insert(pts,count,[bytes](size_t i){return decodeMuLaw(bytes[i]);});
    }
    bool pushPcm(uint32_t pts,const int16_t* pcm,size_t count) {
        if(!pcm)return false;
        return insert(pts,count,[pcm](size_t i){return pcm[i];});
    }
    bool pop(int16_t* out) {
        if(!out || !samples_)return false;
        if(!primed_ || (!started_ && static_cast<int32_t>(high_-read_)<static_cast<int32_t>(target_))) {
            std::memset(out,0,frameSamples_*sizeof(int16_t));return false;
        }
        started_=true;unsigned present=0;
        for(size_t i=0;i<frameSamples_;++i) {
            if(valid_[head_/8] & (1u<<(head_%8))) {last_=samples_[head_];++present;}
            else {
                // Same ~4 ms decay time at every sample rate.
                const int divisor=static_cast<int>(rate_/250);
                last_=static_cast<int16_t>(last_*(divisor-1)/divisor);++counters.missingSamples;
            }
            out[i]=last_;valid_[head_/8]&=static_cast<uint8_t>(~(1u<<(head_%8)));
            head_=(head_+1)%capacity_;++read_;
        }
        emptyFrames_=present?0:emptyFrames_+1;
        if(emptyFrames_>=5){reset(target_/(rate_/1000));++counters.resync;}
        return true;
    }
private:
    template<class Sample> bool insert(uint32_t pts,size_t count,Sample sample) {
        if(!samples_ || !count || count>rate_*120/1000)return false;
        const uint32_t start=pts*(rate_/1000);
        if(!primed_){read_=high_=start;primed_=true;}
        int32_t offset=static_cast<int32_t>(start-read_);
        if(offset+static_cast<int32_t>(count)<=0){++counters.late;return false;}
        if(offset>static_cast<int32_t>(capacity_) || offset+static_cast<int32_t>(count)>static_cast<int32_t>(capacity_)) {
            reset(target_/(rate_/1000));++counters.resync;read_=high_=start;primed_=true;offset=0;
        }
        for(size_t i=0;i<count;++i) {
            int32_t at=offset+static_cast<int32_t>(i);if(at<0)continue;
            size_t slot=(head_+static_cast<size_t>(at))%capacity_;
            samples_[slot]=sample(i);valid_[slot/8]|=static_cast<uint8_t>(1u<<(slot%8));
        }
        uint32_t end=start+static_cast<uint32_t>(count);
        if(static_cast<int32_t>(end-high_)>0)high_=end;
        return true;
    }
    int16_t* samples_=nullptr;uint8_t* valid_=nullptr;
    uint32_t rate_=8000,read_=0,high_=0;
    size_t capacity_=0,frameSamples_=160,head_=0,target_=480;
    unsigned emptyFrames_=0;bool primed_=false,started_=false;int16_t last_=0;
};
}
