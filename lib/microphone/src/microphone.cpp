#include "microphone.h"
#include "esp_log.h"

static const char *TAG = "MIC";

Microphone::Microphone(int bck_pin, int ws_pin, int data_pin, uint32_t sample_rate) 
    : _bck_pin(bck_pin),
      _ws_pin(ws_pin),
      _data_pin(data_pin),
      _sample_rate(sample_rate),
      _port(I2S_NUM_0),
      _is_initialized(false) {
}

Microphone::~Microphone() {
    if (_is_initialized) {
        i2s_driver_uninstall(_port);
    }
}

bool Microphone::init() {
    i2s_config_t i2s_cfg = {
        .mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_RX),
        .sample_rate = _sample_rate,
        .bits_per_sample = I2S_BITS_PER_SAMPLE_32BIT,
        .channel_format = I2S_CHANNEL_FMT_ONLY_LEFT,
        .communication_format = I2S_COMM_FORMAT_STAND_I2S,
        .intr_alloc_flags = ESP_INTR_FLAG_LEVEL1,
        .dma_buf_count = 8,
        .dma_buf_len = 256,
        .use_apll = false,
        .tx_desc_auto_clear = false,
        .fixed_mclk = 0,
    };

    esp_err_t err = i2s_driver_install(_port, &i2s_cfg, 0, NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to install I2S driver: %s", esp_err_to_name(err));
        return false;
    }

    i2s_pin_config_t pin_cfg = {
        .bck_io_num = _bck_pin,
        .ws_io_num = _ws_pin,
        .data_out_num = I2S_PIN_NO_CHANGE,
        .data_in_num = _data_pin,
    };

    err = i2s_set_pin(_port, &pin_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set I2S pins: %s", esp_err_to_name(err));
        i2s_driver_uninstall(_port);
        return false;
    }

    err = i2s_zero_dma_buffer(_port);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to clear I2S DMA buffer: %s", esp_err_to_name(err));
        i2s_driver_uninstall(_port);
        return false;
    }

    _is_initialized = true;
    ESP_LOGI(TAG, "I2S Microphone initialized successfully at %d Hz", _sample_rate);
    return true;
}

size_t Microphone::read(int16_t* buffer, size_t buffer_len) {
    if (!_is_initialized || buffer == nullptr || buffer_len == 0) {
        return 0;
    }

    constexpr size_t kChunkSamples = 256;
    int32_t temp_buffer[kChunkSamples];
    size_t total_samples = 0;

    while (total_samples < buffer_len) {
        size_t remain = buffer_len - total_samples;
        size_t req_samples = remain > kChunkSamples ? kChunkSamples : remain;
        size_t bytes_read = 0;

        esp_err_t err = i2s_read(_port,
                                 temp_buffer,
                                 req_samples * sizeof(int32_t),
                                 &bytes_read,
                                 portMAX_DELAY);
        if (err != ESP_OK || bytes_read == 0) {
            break;
        }

        size_t got = bytes_read / sizeof(int32_t);
        for (size_t i = 0; i < got; ++i) {
            // INMP441 在 32-bit 槽中输出 24-bit 有效数据，右移 16bit 后得到标准 int16 PCM。
            buffer[total_samples + i] = (int16_t)(temp_buffer[i] >> 16);
        }
        total_samples += got;

        if (got < req_samples) {
            break;
        }
    }

    return total_samples;
}