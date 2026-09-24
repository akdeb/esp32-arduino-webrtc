#include "detail/G711.h"
#include "detail/Fingerprint.h"
#include <string>
#include <vector>
#include "detail/AudioFormat.h"
#include "detail/PlayoutBuffer.h"
#include <cassert>
#include <cstdlib>
#include <cstdio>
#include <algorithm>
using namespace arduino_webrtc;
int main() {
    assert(encodeMuLaw(0) == 0xff);
    assert(decodeMuLaw(0xff) == 0 && decodeMuLaw(0x7f) == 0);
    assert(decodeMuLaw(0x80) == 32124 && decodeMuLaw(0x00) == -32124);
    assert(encodeMuLaw(-32768) == 0 && encodeMuLaw(32767) == 0x80);
    for (int v = -32768; v <= 32767; ++v) assert(std::abs(v - decodeMuLaw(encodeMuLaw(v))) <= 644);
    for (int u = 0; u < 256; ++u) if (u != 0x7f) assert(encodeMuLaw(decodeMuLaw(u)) == u);
    PlayoutBuffer b; std::vector<uint64_t> storage((PlayoutBuffer::storageBytes(8000)+7)/8);
    assert(b.init(8000,storage.data(),storage.size()*8)); b.reset();
    uint8_t packet[960]; std::fill_n(packet,960,encodeMuLaw(1000));
    int16_t out[160];
    assert(!b.pop(out)); assert(out[0] == 0);
    assert(!b.push(0,nullptr,160)); assert(!b.push(0,packet,961));
    assert(b.push(0,packet,160)); assert(!b.pop(out));
    assert(b.push(40,packet,160)); assert(b.push(20,packet,160));
    for (int i=0;i<3;++i) { assert(b.pop(out)); assert(out[0] == decodeMuLaw(packet[0])); }
    assert(!b.push(0,packet,160)); assert(b.counters.late == 1);
    b.pop(out); assert(out[159] < 10); assert(b.counters.missingSamples == 160);
    for (int i=0;i<4;++i) b.pop(out);
    assert(!b.pop(out)); assert(b.counters.resync == 1);
    b.reset(20); b.push(0,packet,160); b.pop(out);
    b.push(10000,packet,160); assert(b.counters.resync == 2); assert(b.pop(out));
    // PTS wrap (ms) and ring wrap, including a packet spanning both.
    b.reset(20); uint32_t stamp = UINT32_MAX - 19;
    for (int i=0;i<1000;++i) { assert(b.push(stamp,packet,160)); assert(b.pop(out)); assert(out[159] == decodeMuLaw(packet[0])); stamp += 20; }
    // Variable packetization and duplicates preserve sample order.
    b.reset(20); b.push(0,packet,80); assert(!b.pop(out)); b.push(10,packet,80); b.push(10,packet,80);
    assert(b.pop(out)); assert(out[159] == decodeMuLaw(packet[0]));
    b.reset(20); b.push(0,packet,960); for(int i=0;i<6;++i) { assert(b.pop(out)); assert(out[159] == decodeMuLaw(packet[0])); }
    for(uint32_t rate : {16000u,24000u,48000u}) {
        AudioFormat fmt;fmt.sampleRate=rate;assert(fmt.valid());
        assert(fmt.frameSamples()==rate/50 && fmt.rtpClockRate()==48000 && fmt.sdpChannels()==2);
        std::vector<uint64_t> mem((PlayoutBuffer::storageBytes(rate)+7)/8);
        PlayoutBuffer rateBuffer;assert(rateBuffer.init(rate,mem.data(),mem.size()*8,20));
        std::vector<int16_t> input(rate/50,1234),output(rate/50);
        uint32_t pts=UINT32_MAX-19;
        for(int i=0;i<1000;++i) {
            assert(rateBuffer.pushPcm(pts,input.data(),input.size()));assert(rateBuffer.pop(output.data()));
            assert(output.front()==1234 && output.back()==1234);pts+=20;
        }
        assert(!rateBuffer.pushPcm(pts,input.data(),rate*121/1000));
        assert(!rateBuffer.init(rate,mem.data(),1));
        uint8_t opus20[]={0xf8,0xff,0xfe};
        assert(opusPacketSamples(opus20,sizeof(opus20),rate)==rate/50);
        uint8_t opus60[]={0x18,0};assert(opusPacketSamples(opus60,sizeof(opus60),rate)==rate*60/1000);
        uint8_t opus120[]={0x19,0};assert(opusPacketSamples(opus120,sizeof(opus120),rate)==rate*120/1000);
        uint8_t invalid[]={0xfb,63};assert(!opusPacketSamples(invalid,sizeof(invalid),rate));
        assert(!opusPacketSamples(invalid,1,rate));assert(!opusPacketSamples(nullptr,1,rate));
    }
    AudioFormat bad;bad.sampleRate=44100;assert(!bad.valid());
    bad.sampleRate=24000;bad.bitrate=20000;assert(!bad.valid());
    bad.codec=AudioCodecType::G711U;assert(!bad.valid());bad.sampleRate=8000;assert(bad.valid());
    puts("PASS: 16/24/48 kHz frame sizing, PCM timeline/wrap, RTP clock separation, Opus packet duration");
    uint8_t digest[32];
    std::string fp = "a=fingerprint:sha-256 ";
    for (int i=0;i<32;++i) { if(i) fp += ':'; fp += "AB"; }
    assert(parseFingerprint((fp+"\r\n").c_str(),fp.size()+2,digest));
    assert(digest[0]==0xab && digest[31]==0xab);
    assert(!parseFingerprint(fp.c_str(),fp.size()-1,digest));
    std::string repeated=fp+"\n"+fp+"\n";
    assert(parseFingerprint(repeated.c_str(),repeated.size(),digest));
    repeated[repeated.size()-2]='0';
    assert(!parseFingerprint(repeated.c_str(),repeated.size(),digest));
    assert(!parseFingerprint("v=0\r\n",5,digest));
    std::string embedded=fp+std::string(1,'\0')+"ignored";
    assert(!parseFingerprint(embedded.c_str(),embedded.size(),digest));
    puts("PASS: SDP fingerprint validation");
    puts("PASS: G.711 exhaustive roundtrip, bounded playout, reordering, loss, duplicates, outage, overflow, PTS wrap");
}
