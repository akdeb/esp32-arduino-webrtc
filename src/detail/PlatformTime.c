#include "../vendor/tls/include/mbedtls/platform_time.h"
#include "esp_timer.h"
awrtc_mbedtls_ms_time_t awrtc_mbedtls_ms_time(void) { return esp_timer_get_time() / 1000; }
#include "../vendor/tls/include/mbedtls/timing.h"
unsigned long awrtc_mbedtls_timing_get_timer(struct awrtc_mbedtls_timing_hr_time* timer, int reset) {
    uint64_t now = (uint64_t)awrtc_mbedtls_ms_time();
    uint64_t elapsed = now - timer->AWRTC_MBEDTLS_PRIVATE(opaque)[0];
    if (reset) timer->AWRTC_MBEDTLS_PRIVATE(opaque)[0] = now;
    return (unsigned long)elapsed;
}
void awrtc_mbedtls_timing_set_delay(void* data, uint32_t intermediate, uint32_t final) {
    awrtc_mbedtls_timing_delay_context* ctx = data;
    ctx->AWRTC_MBEDTLS_PRIVATE(int_ms) = intermediate;
    ctx->AWRTC_MBEDTLS_PRIVATE(fin_ms) = final;
    if (final) awrtc_mbedtls_timing_get_timer(&ctx->AWRTC_MBEDTLS_PRIVATE(timer), 1);
}
int awrtc_mbedtls_timing_get_delay(void* data) {
    awrtc_mbedtls_timing_delay_context* ctx = data;
    if (!ctx->AWRTC_MBEDTLS_PRIVATE(fin_ms)) return -1;
    unsigned long elapsed = awrtc_mbedtls_timing_get_timer(&ctx->AWRTC_MBEDTLS_PRIVATE(timer), 0);
    if (elapsed >= ctx->AWRTC_MBEDTLS_PRIVATE(fin_ms)) return 2;
    return elapsed >= ctx->AWRTC_MBEDTLS_PRIVATE(int_ms) ? 1 : 0;
}
uint32_t awrtc_mbedtls_timing_get_final_delay(const awrtc_mbedtls_timing_delay_context* ctx) {
    return ctx->AWRTC_MBEDTLS_PRIVATE(fin_ms);
}
