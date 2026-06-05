/**
 * @file main.cpp
 * @brief ESP32-S3 AI 联网对话 — INMP441 语音采集主程序
 *
 * 功能：
 *   1. 串口命令触发录音（输入 s 开始，再输 s 停止）
 *   2. 实时显示音量电平（串口进度条）
 *   3. 边录边发（流式）：WAV 头 + PCM 数据实时串口输出
 *      无需大缓冲区，只占 ~1KB 内存
 *
 * 硬件接线（参考项目文档）：
 *   INMP441 DATA（SD） → GPIO 4
 *   INMP441 SCK        → GPIO 15（避开 PSRAM 占用的 GPIO6）
 *   INMP441 CLK（WS）  → GPIO 5
 *   INMP441 L/R        → GND（左声道）
 *   INMP441 VDD        → 3.3V
 *   INMP441 GND        → GND
 *
 * 串口命令：
 *   s / S    → 开始录音 / 停止录音
 *   h / H    → 打印帮助
 */

#include <Arduino.h>
#include "microphone.h"

// ===================== 引脚定义 =====================
#define MIC_SCK_PIN      15      // INMP441 SCK（I2S 位时钟）— GPIO6 被 PSRAM 占用，改用 GPIO15
#define MIC_CLK_PIN      5       // INMP441 CLK（I2S WS）
#define MIC_DATA_PIN     4       // INMP441 DATA

// ===================== 音频参数 =====================
#define SAMPLE_RATE      16000   // 采样率 16kHz
#define MAX_RECORD_SEC   20      // 最长录音 20 秒

// ===================== 全局对象 =====================
Microphone mic(MIC_SCK_PIN, MIC_CLK_PIN, MIC_DATA_PIN, SAMPLE_RATE);

// ===================== 函数前置声明 =====================
static void     start_recording();
static void     print_help();
static void     write_wav_header(uint32_t data_bytes);
static int32_t  calc_volume_db(const int16_t* data, size_t samples);

// ============================================================
//  WAV 文件头写入（通过 Serial 输出）
// ============================================================
static void write_wav_header(uint32_t data_bytes) {
    uint32_t sample_rate = SAMPLE_RATE;
    uint16_t bits_per_sample = 16;
    uint16_t channels = 1;
    uint32_t byte_rate = sample_rate * channels * bits_per_sample / 8;
    uint16_t block_align = channels * bits_per_sample / 8;
    uint32_t chunk_size = 36 + data_bytes;

    // RIFF header
    Serial.write('R'); Serial.write('I'); Serial.write('F'); Serial.write('F');
    Serial.write((uint8_t*)&chunk_size, 4);
    Serial.write('W'); Serial.write('A'); Serial.write('V'); Serial.write('E');

    // fmt chunk
    Serial.write('f'); Serial.write('m'); Serial.write('t'); Serial.write(' ');
    uint32_t fmt_size = 16;
    Serial.write((uint8_t*)&fmt_size, 4);
    uint16_t audio_format = 1;  // PCM
    Serial.write((uint8_t*)&audio_format, 2);
    Serial.write((uint8_t*)&channels, 2);
    Serial.write((uint8_t*)&sample_rate, 4);
    Serial.write((uint8_t*)&byte_rate, 4);
    Serial.write((uint8_t*)&block_align, 2);
    Serial.write((uint8_t*)&bits_per_sample, 2);

    // data chunk
    Serial.write('d'); Serial.write('a'); Serial.write('t'); Serial.write('a');
    Serial.write((uint8_t*)&data_bytes, 4);
}

// ============================================================
//  计算音量（RMS → dBFS）
// ============================================================
static int32_t calc_volume_db(const int16_t* data, size_t samples) {
    if (samples == 0) return -9600;  // -96 dBFS（静音）

    int64_t sum_sq = 0;
    for (size_t i = 0; i < samples; i++) {
        int32_t s = data[i];
        sum_sq += (int64_t)s * s;
    }

    if (sum_sq == 0) return -9600;

    double rms = sqrt((double)sum_sq / samples);
    double db = 20.0 * log10(rms / 32768.0);

    return (int32_t)(db * 100);  // 返回 0.01dB 精度
}

// ============================================================
//  音量条显示（串口）
// ============================================================
static void print_volume_bar(int32_t db_x100) {
    double db = db_x100 / 100.0;

    // dBFS 范围 ~ -96 ~ 0，映射到 0~40 格
    int bars = constrain(map(db_x100, -9600, -600, 0, 40), 0, 40);

    Serial.print("[");
    for (int i = 0; i < 40; i++) {
        if (i < bars)
            Serial.print("▓");
        else if (i == 0)
            Serial.print("░");
        else
            Serial.print(" ");
    }
    Serial.printf("] %5.1f dBFS\r", db);
}

// ============================================================
//  setup()
// ============================================================
void setup() {
    Serial.begin(921600);
    while (!Serial) { delay(10); }
    Serial.println("\n========================================");
    Serial.println("  ESP32-S3 — INMP441 语音采集 (流式)");
    Serial.println("  输入 s 开始录音，再输 s 停止");
    Serial.println("========================================");

    // --- 初始化麦克风 ---
    if (!mic.init()) {
        Serial.println("ERROR: 麦克风初始化失败！");
        while (1) { delay(1000); }
    }

    Serial.println("\n就绪！输入 s 开始录音，再输 s 停止。");
    Serial.println("----------------------------------------\n");
}

// ============================================================
//  loop()
// ============================================================
void loop() {
    // 检查串口是否有输入
    if (Serial.available() <= 0) {
        return;
    }

    char cmd = Serial.read();

    // 处理命令
    if (cmd == 's' || cmd == 'S') {
        start_recording();
    } else if (cmd == 'h' || cmd == 'H') {
        print_help();
    }
    // 其他字符忽略
}

// ============================================================
//  打印帮助
// ============================================================
static void print_help() {
    Serial.println("\n===== 命令帮助 =====");
    Serial.println("  s / S  → 开始录音 / 停止录音");
    Serial.println("  h / H  → 打印本帮助");
    Serial.println("====================\n");
}

// ============================================================
//  开始录音（流式：只发裸 PCM，Python 端加 WAV 头）
// ============================================================
static void start_recording() {
    Serial.println("\n>>> 录音中... 再输入 s 停止录音 <<<");

    const size_t chunk = 512;           // 每次读取 512 个样本 = 1KB
    int16_t temp_buf[chunk];            // 临时缓冲区（栈上分配）
    size_t total_samples = 0;
    size_t max_samples = SAMPLE_RATE * MAX_RECORD_SEC;
    bool stopped = false;

    while (!stopped) {
        // 检查停止命令
        while (Serial.available() > 0) {
            char c = Serial.read();
            if (c == 's' || c == 'S') {
                stopped = true;
                break;
            }
        }
        if (stopped) break;

        // 超时保护
        if (total_samples >= max_samples) {
            break;
        }

        // 如果是第一帧，先发 PCM 起始标记
        if (total_samples == 0) {
            Serial.print("\n--- PCM START ---\n");
        }

        // 读取一帧音频数据
        size_t n = mic.read(temp_buf, chunk);
        if (n == 0) break;

        // ★ 立即串口发送 PCM 数据（边录边发，不带 WAV 头）
        Serial.write((uint8_t*)temp_buf, n * sizeof(int16_t));
        total_samples += n;
    }

    Serial.flush();

    // ========== 录音结束 ==========
    // 发送数据大小信息，供 Python 端构建 WAV 头
    Serial.printf("\n--- PCM:%zu ---\n", total_samples);
    Serial.println("\n就绪");
}