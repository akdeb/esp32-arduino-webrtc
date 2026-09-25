#pragma once
#include "ESP32WebRTC.h"
#include <driver/i2s_std.h>
#include <atomic>
namespace arduino_webrtc {
// Philips I2S, 32-bit slots. Shares BCLK/WS between mic and amp unless
// micBclk/micWs are set, which puts the mic on its own I2S controller.
class WebRTCI2S : public AudioIO {
public:
    struct Pins { int bclk = 4, ws = 5, din = 6, dout = 7, micBclk = -1, micWs = -1; bool rightMic = false; };
    ~WebRTCI2S() override { end(); }
    WebRTCI2S() = default;
    WebRTCI2S(const WebRTCI2S&) = delete;
    WebRTCI2S& operator=(const WebRTCI2S&) = delete;
    bool begin(const Pins& pins, uint32_t sampleRate = 24000);
    uint32_t sampleRate() const override { return rate_; }
    void end(); // stop ESP32WebRTC first
    void setVolume(uint8_t percent); // speaker volume 0..100, default 100; safe during a call
    size_t read(int16_t*, size_t, uint32_t) override;
    size_t write(const int16_t*, size_t, uint32_t) override;
private:
    uint32_t rate_ = 0;
    i2s_chan_handle_t rx_ = nullptr, tx_ = nullptr;
    std::atomic<int32_t> gain_{65536};
    bool rxEnabled_ = false, txEnabled_ = false, right_ = false;
    int32_t rxWords_[320]{}, txWords_[320]{};
};
}
using arduino_webrtc::WebRTCI2S;
