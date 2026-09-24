#pragma once
#include "ESP32WebRTC.h"
#include <driver/i2s_std.h>
namespace arduino_webrtc {
// Philips I2S, 32-bit slots. Shares BCLK/WS between mic and amp.
class WebRTCI2S : public AudioIO {
public:
    struct Pins { int bclk = 4, ws = 5, din = 6, dout = 7; bool rightMic = false; };
    ~WebRTCI2S() override { end(); }
    WebRTCI2S() = default;
    WebRTCI2S(const WebRTCI2S&) = delete;
    WebRTCI2S& operator=(const WebRTCI2S&) = delete;
    bool begin(const Pins& pins, uint32_t sampleRate = 24000);
    uint32_t sampleRate() const override { return rate_; }
    void end(); // stop ESP32WebRTC first
    size_t read(int16_t*, size_t, uint32_t) override;
    size_t write(const int16_t*, size_t, uint32_t) override;
private:
    uint32_t rate_ = 0;
    i2s_chan_handle_t rx_ = nullptr, tx_ = nullptr;
    bool rxEnabled_ = false, txEnabled_ = false, right_ = false;
    int32_t rxWords_[320]{}, txWords_[320]{};
};
}
using arduino_webrtc::WebRTCI2S;
