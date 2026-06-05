#ifndef MICROPHONE_H
#define MICROPHONE_H

#include <Arduino.h>
#include <driver/i2s.h>

/**
 * @brief I2S 硅麦驱动（标准 I2S RX 模式）
 *
 * 硬件接线：
 *   BCK (I2S 位时钟) → INMP441 SCK
 *   WS  (I2S 声道时钟) → INMP441 CLK
 *   DATA → INMP441 DATA
 *
 * 使用示例：
 * @code
 *   Microphone mic(15, 5, 4, 16000);
 *   mic.init();
 *   int16_t buf[1024];
 *   size_t n = mic.read(buf, 1024);
 * @endcode
 */
class Microphone {
public:
    /**
     * @param bck_pin    I2S 位时钟引脚 (INMP441 SCK)
     * @param ws_pin     I2S 声道时钟引脚 (INMP441 CLK)
     * @param data_pin   I2S 数据输入引脚 (INMP441 DATA)
     * @param sample_rate   采样率 (Hz)
     */
    Microphone(int bck_pin, int ws_pin, int data_pin, uint32_t sample_rate);
    ~Microphone();

    /**
     * @brief 初始化 I2S 驱动并配置引脚
     * @return true 成功 / false 失败
     */
    bool init();

    /**
     * @brief 读取 PCM 音频数据（阻塞）
     * @param buffer   存放 16-bit PCM 样本的缓冲区
     * @param buffer_len  期望读取的样本数
     * @return size_t  实际读取的样本数
     */
    size_t read(int16_t* buffer, size_t buffer_len);

private:
    int         _bck_pin;
    int         _ws_pin;
    int         _data_pin;
    uint32_t    _sample_rate;
    i2s_port_t  _port;
    bool        _is_initialized;
};

#endif // MICROPHONE_H
