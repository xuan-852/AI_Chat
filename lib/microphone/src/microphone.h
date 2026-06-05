#ifndef MICROPHONE_H
#define MICROPHONE_H

#include <Arduino.h>
#include <driver/i2s.h>

class Microphone {
public:
    // 构造函数：传入引脚号和采样率(默认16000)
    Microphone(int bck_pin, int ws_pin, int data_pin, uint32_t sample_rate = 16000);
    ~Microphone();

    // 初始化 I2S
    bool init();
    
    // 读取音频数据
    // buffer: 存放读取数据的缓冲区
    // buffer_len: 缓冲区可以存放的 int16_t 个数
    // 返回值: 实际读取到的 int16_t 个数
    size_t read(int16_t* buffer, size_t buffer_len);

private:
    int _bck_pin;
    int _ws_pin;
    int _data_pin;
    uint32_t _sample_rate;
    
    i2s_port_t _port;
    bool _is_initialized;
};

#endif