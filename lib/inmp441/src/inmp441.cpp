#include "inmp441.h"
#include "esp_log.h"

static const char* TAG = "INMP441";

// ============================================================
// INMP441 — ESP32-S3 I2S PDM 模式驱动
//
// 参考：ESP32-S3 技术参考手册 §13 I2S
//       INMP441 数据手册（PDM 数字麦克风）
//
// 关键说明：
//   INMP441 在 ESP32-S3 I2S PDM RX 模式下，硬件会自动完成
//   PDM → PCM 转换（不同于经典 ESP32 需要软件解码），
//   因此我们直接读取 int16_t PCM 数据即可。
// ============================================================

INMP441::INMP441(uint8_t sck_pin, uint8_t clk_pin, uint8_t data_pin, uint32_t sample_rate)
    : _sck_pin(sck_pin),
      _clk_pin(clk_pin),
      _data_pin(data_pin),
      _sample_rate(sample_rate),
      _port(I2S_NUM_0),
      _initialized(false) {
}

INMP441::~INMP441() {
    end();
}

bool INMP441::begin() {
    // ---------- 1. I2S 配置（PDM RX 模式） ----------
    i2s_config_t i2s_cfg = {
        .mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_RX | I2S_MODE_PDM),
        .sample_rate           = _sample_rate,
        .bits_per_sample       = I2S_BITS_PER_SAMPLE_16BIT,
        .channel_format        = I2S_CHANNEL_FMT_ONLY_LEFT,   // INMP441 L/R=GND → 左声道
        .communication_format  = I2S_COMM_FORMAT_STAND_I2S,
        .intr_alloc_flags      = ESP_INTR_FLAG_LEVEL1,
        .dma_buf_count         = 8,
        .dma_buf_len           = 256,
        .use_apll              = false,
        .tx_desc_auto_clear    = false,
        .fixed_mclk            = 0,
    };

    esp_err_t err = i2s_driver_install(_port, &i2s_cfg, 0, NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "I2S driver install failed: %s", esp_err_to_name(err));
        return false;
    }

    // ---------- 2. 引脚配置 ----------
    //   ESP32-S3 I2S PDM RX 模式下：
    //     - bck_io_num   → PDM 位时钟 (INMP441 SCK)
    //     - ws_io_num    → 声道选择时钟 (INMP441 CLK)
    //     - data_in_num  → PDM 数据输入 (INMP441 DATA)
    i2s_pin_config_t pin_cfg = {
        .bck_io_num   = _sck_pin,          // SCK → I2S 位时钟
        .ws_io_num    = _clk_pin,          // CLK → I2S WS
        .data_out_num = I2S_PIN_NO_CHANGE,
        .data_in_num  = _data_pin,         // DATA → I2S 数据输入
    };

    err = i2s_set_pin(_port, &pin_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "I2S set pin failed: %s", esp_err_to_name(err));
        i2s_driver_uninstall(_port);
        return false;
    }

    // ---------- 3. 清空 DMA 缓冲区 ----------
    err = i2s_zero_dma_buffer(_port);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "I2S zero DMA buffer failed: %s", esp_err_to_name(err));
        i2s_driver_uninstall(_port);
        return false;
    }

    _initialized = true;
    ESP_LOGI(TAG, "INMP441 initialized: SCK=%d, CLK=%d, DATA=%d, %d Hz",
             _sck_pin, _clk_pin, _data_pin, _sample_rate);
    return true;
}

size_t INMP441::read(int16_t* buffer, size_t samples) {
    if (!_initialized || buffer == nullptr || samples == 0) {
        return 0;
    }

    size_t bytes_read = 0;
    size_t bytes_to_read = samples * sizeof(int16_t);

    esp_err_t err = i2s_read(_port,
                             buffer,
                             bytes_to_read,
                             &bytes_read,
                             portMAX_DELAY);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "I2S read failed: %s", esp_err_to_name(err));
        return 0;
    }

    return bytes_read / sizeof(int16_t);
}

void INMP441::end() {
    if (_initialized) {
        i2s_driver_uninstall(_port);
        _initialized = false;
        ESP_LOGI(TAG, "INMP441 driver uninstalled");
    }
}
