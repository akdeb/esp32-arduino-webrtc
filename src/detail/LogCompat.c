// esp_peer 1.5.3 uses the IDF >=5.4 esp_log entry point. Match its 32-bit
// config-by-value ABI on Arduino 3.1.x (IDF 5.3). Newer cores provide it natively.
#include <esp_idf_version.h>
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5, 4, 0)
#include <esp_log.h>
#include <stdarg.h>
#include <stdint.h>
typedef struct { uint32_t data; } awrtc_log_config_t;
void esp_log(awrtc_log_config_t config, const char* tag, const char* format, ...) {
    esp_log_level_t level = (esp_log_level_t)(config.data & 7);
    if (level == ESP_LOG_NONE || level > esp_log_level_get(tag)) return;
    va_list args;
    va_start(args, format);
    esp_log_writev(level, tag, format, args);
    va_end(args);
}
#endif
