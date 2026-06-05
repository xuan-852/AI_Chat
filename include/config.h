#ifndef CONFIG_H
#define CONFIG_H

// ==================== WiFi ====================
#define WIFI_SSID      "Xiaomi 15 Pro"
#define WIFI_PASSWORD  "you1233211234"

// ==================== 麦克风引脚 ====================
#define MIC_SCK_PIN      15
#define MIC_CLK_PIN      5
#define MIC_DATA_PIN     4

// ==================== 音频参数 ====================
#define SAMPLE_RATE      16000
#define MAX_RECORD_SEC   10       // 最长录音（受限于 PSRAM 大小）

// ==================== 百度语音识别 ====================
#define BAIDU_APP_ID     "7825090"
#define BAIDU_API_KEY    "LVZcNhtn584JqOPB9UCsBE4H"
#define BAIDU_SECRET_KEY "QpoVPPhETyWK7yLC8L2TLRzrSBALASG3"

// ==================== DeepSeek ====================
#define DEEPSEEK_API_KEY "sk-717fd68ac7964fcabd7733cf8917f5a8"

#endif // CONFIG_H
