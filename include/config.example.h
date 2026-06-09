#ifndef CONFIG_H
#define CONFIG_H

/*
 * 配置模板
 * ========
 * 将所有密钥替换为真实值后，另存为 config.h（已 .gitignore）
 *
 * 如何获取密钥：
 *   百度语音识别: https://console.bce.baidu.com/ai/#/ai/speech/overview
 *   DeepSeek:     https://platform.deepseek.com/api_keys
 */

// ==================== WiFi ====================
#define WIFI_SSID      "your-wifi-ssid"
#define WIFI_PASSWORD  "your-wifi-password"

// ==================== 麦克风引脚 ====================
#define MIC_SCK_PIN      15
#define MIC_CLK_PIN      5
#define MIC_DATA_PIN     4

// ==================== 音频参数 ====================
#define SAMPLE_RATE      16000
#define MAX_RECORD_SEC   10

// ==================== 百度语音识别 ====================
#define BAIDU_APP_ID     "your_app_id_here"
#define BAIDU_API_KEY    "your_api_key_here"
#define BAIDU_SECRET_KEY "your_secret_key_here"

// ==================== DeepSeek ====================
#define DEEPSEEK_API_KEY "sk-your-api-key-here"

#endif // CONFIG_H
