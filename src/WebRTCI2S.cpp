#include "WebRTCI2S.h"
#include <algorithm>
namespace arduino_webrtc {
bool WebRTCI2S::begin(const Pins& p, uint32_t rate) {
    if (rx_ || tx_ || (rate!=8000 && rate!=16000 && rate!=24000 && rate!=48000)) return false;
    right_ = p.rightMic;
    i2s_chan_config_t chan = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_AUTO, I2S_ROLE_MASTER);
    chan.dma_desc_num = 4;
    chan.dma_frame_num = rate / 200; // Four 5 ms DMA blocks per direction, internal RAM
    chan.auto_clear = true;
    bool split = p.micBclk >= 0 && p.micWs >= 0;
    if (split ? (i2s_new_channel(&chan, &tx_, nullptr) != ESP_OK || i2s_new_channel(&chan, nullptr, &rx_) != ESP_OK)
              : i2s_new_channel(&chan, &tx_, &rx_) != ESP_OK) { end(); return false; }
    i2s_std_config_t cfg{};
    cfg.clk_cfg.sample_rate_hz = rate;
    cfg.clk_cfg.clk_src = I2S_CLK_SRC_DEFAULT;
    cfg.clk_cfg.mclk_multiple = I2S_MCLK_MULTIPLE_256;
    cfg.slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_32BIT, I2S_SLOT_MODE_STEREO);
    cfg.gpio_cfg.mclk = I2S_GPIO_UNUSED;
    cfg.gpio_cfg.bclk = static_cast<gpio_num_t>(p.bclk);
    cfg.gpio_cfg.ws = static_cast<gpio_num_t>(p.ws);
    cfg.gpio_cfg.din = split ? I2S_GPIO_UNUSED : static_cast<gpio_num_t>(p.din);
    cfg.gpio_cfg.dout = static_cast<gpio_num_t>(p.dout);
    if (i2s_channel_init_std_mode(tx_, &cfg) != ESP_OK) { end(); return false; }
    if (split) {
        cfg.gpio_cfg.bclk = static_cast<gpio_num_t>(p.micBclk);
        cfg.gpio_cfg.ws = static_cast<gpio_num_t>(p.micWs);
        cfg.gpio_cfg.din = static_cast<gpio_num_t>(p.din);
        cfg.gpio_cfg.dout = I2S_GPIO_UNUSED;
    }
    if (i2s_channel_init_std_mode(rx_, &cfg) != ESP_OK) { end(); return false; }
    if (i2s_channel_enable(tx_) != ESP_OK) { end(); return false; }
    txEnabled_ = true;
    if (i2s_channel_enable(rx_) != ESP_OK) { end(); return false; }
    rxEnabled_ = true; rate_ = rate;
    return true;
}
void WebRTCI2S::end() {
    if (rx_) { if (rxEnabled_) i2s_channel_disable(rx_); i2s_del_channel(rx_); }
    if (tx_) { if (txEnabled_) i2s_channel_disable(tx_); i2s_del_channel(tx_); }
    rate_ = 0; rx_ = tx_ = nullptr; rxEnabled_ = txEnabled_ = false;
}
size_t WebRTCI2S::read(int16_t* out, size_t n, uint32_t timeout) {
    if (!rx_ || !out) return 0;
    n = std::min(n, size_t(160));
    size_t bytes = 0;
    i2s_channel_read(rx_, rxWords_, n * 8, &bytes, timeout);
    size_t samples = bytes / 8;
    for (size_t i = 0; i < samples; ++i) out[i] = static_cast<int16_t>(rxWords_[2*i + (right_ ? 1 : 0)] >> 16);
    return samples;
}
size_t WebRTCI2S::write(const int16_t* in, size_t n, uint32_t timeout) {
    if (!tx_ || !in) return 0;
    n = std::min(n, size_t(160));
    for (size_t i = 0; i < n; ++i) txWords_[2*i] = txWords_[2*i+1] = static_cast<int32_t>(in[i]) * 65536;
    size_t bytes = 0;
    i2s_channel_write(tx_, txWords_, n * 8, &bytes, timeout);
    return bytes / 8;
}
}
