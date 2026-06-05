#ifndef INMP441_H
#define INMP441_H

#include <Arduino.h>
#include <driver/i2s.h>

/**
 * @brief INMP441 PDM 硅麦驱动（ESP32-S3 I2S PDM 模式）
 *
 * 硬件接线（参考项目文档）：
 *   INMP441 DATA（SD） → GPIO 4  (I2S data_in)
 *   INMP441 SCK        → GPIO 6  (I2S bck_io_num, PDM 位时钟)
 *   INMP441 CLK（WS）  → GPIO 5  (I2S ws_io_num, 声道选择时钟)
 *   INMP441 L/R        → GND      (左声道)
 *   INMP441 VDD        → 3.3V
 *   INMP441 GND        → GND
 * 
 * 使用示例：
 * @code
 *   INMP441 mic(6, 5, 4);        // SCK=GPIO6, CLK=GPIO5, DATA=GPIO4
 *   mic.begin();
 *   int16_t buf[1024];
 *   size_t n = mic.read(buf, 1024);
 * @endcode
 */
class INMP441 {
public:
    /**
     * @param sck_pin    INMP441 SCK 所连接的 ESP32-S3 GPIO 编号（I2S 位时钟）
     * @param clk_pin    INMP441 CLK 所连接的 ESP32-S3 GPIO 编号（I2S WS）
     * @param data_pin   INMP441 DATA 所连接的 ESP32-S3 GPIO 编号（I2S 数据输入）
     * @param sample_rate   采样率 (Hz)，默认 16000
     */
    INMP441(uint8_t sck_pin, uint8_t clk_pin, uint8_t data_pin, uint32_t sample_rate = 16000);

    ~INMP441();

    /**
     * @brief 初始化 I2S 并配置为 PDM 接收模式
     * @return true 成功 / false 失败（串口会输出详细错误信息）
     */
    bool begin();

    /**
     * @brief 读取 PCM 音频数据（阻塞，直到读满或出错）
     * @param buffer   存放 16-bit PCM 样本的缓冲区
     * @param samples  期望读取的样本数
     * @return size_t  实际读取的样本数
     */
    size_t read(int16_t* buffer, size_t samples);

    /**
     * @brief 卸载 I2S 驱动，释放资源
     */
    void end();

private:
    uint8_t      _sck_pin;       // SCK 引脚号（I2S BCK）
    uint8_t      _clk_pin;       // CLK 引脚号（I2S WS）
    uint8_t      _data_pin;      // DATA 引脚号（I2S data_in）
    uint32_t     _sample_rate;   // 采样率
    i2s_port_t   _port;          // I2S 端口号
    bool         _initialized;   // 是否已初始化
};

#endif // INMP441_H
