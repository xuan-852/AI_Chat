/**
 * @file main.cpp
 * @brief ESP32-S3 AI 对话一体机
 *
 * 完整流程（全在 ESP32 上，无需 PC）：
 *   录音（INMP441 → PSRAM）→ 百度 ASR（裸 PCM POST）→ DeepSeek → 串口输出回复
 *
 * 硬件接线：
 *   INMP441 DATA → GPIO 4
 *   INMP441 SCK  → GPIO 15
 *   INMP441 CLK  → GPIO 5
 *   INMP441 L/R  → GND
 *   INMP441 VDD  → 3.3V
 *   INMP441 GND  → GND
 *
 * 串口命令：
 *   s / S  → 开始一轮对话（录音→识别→LLM→回复）
 *   w      → 重新连接 WiFi
 *   h / H  → 帮助
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "config.h"
#include "microphone.h"

// ==================== 对象 ====================
Microphone mic(MIC_SCK_PIN, MIC_CLK_PIN, MIC_DATA_PIN, SAMPLE_RATE);

// ==================== 全局状态 ====================
static char baidu_token[256] = {0};
static unsigned long token_expires = 0;

// ==================== 函数前置声明 ====================
static bool     wifi_connect();
static bool     baidu_get_token();
static String   baidu_asr(const int16_t* pcm, size_t samples);
static String   deepseek_chat(const String& text);
static void     start_ai_dialog();
static void     print_help();

// ============================================================
//  WiFi 连接
// ============================================================
static bool wifi_connect() {
    Serial.printf("🔗 连接 WiFi: %s ... ", WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    int tries = 0;
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
        if (++tries > 40) {
            Serial.println("\n❌ WiFi 连接失败");
            return false;
        }
    }
    Serial.printf("\n✅ WiFi 已连接, IP: %s\n", WiFi.localIP().toString().c_str());
    return true;
}

// ============================================================
//  百度 access_token 获取（缓存）
// ============================================================
static bool baidu_get_token() {
    if (strlen(baidu_token) > 0 && millis() / 1000 < token_expires) {
        return true;
    }

    WiFiClientSecure client;
    client.setInsecure();

    HTTPClient http;
    String url = String("https://aip.baidubce.com/oauth/2.0/token")
                 + "?grant_type=client_credentials"
                 + "&client_id=" + BAIDU_API_KEY
                 + "&client_secret=" + BAIDU_SECRET_KEY;

    http.begin(client, url);
    http.setTimeout(10000);

    int code = http.GET();
    if (code != 200) {
        Serial.printf("❌ 百度 token 获取失败: HTTP %d\n", code);
        http.end();
        return false;
    }

    String resp = http.getString();
    http.end();

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, resp);
    if (err) {
        Serial.printf("❌ 百度 token 解析失败: %s\n", err.c_str());
        return false;
    }

    const char* token = doc["access_token"];
    int expires_in = doc["expires_in"];

    if (!token) {
        Serial.println("❌ 百度 token 返回异常");
        return false;
    }

    strncpy(baidu_token, token, sizeof(baidu_token) - 1);
    token_expires = millis() / 1000 + expires_in - 86400;
    Serial.println("✅ 百度 token 已获取");
    return true;
}

// ============================================================
//  百度语音识别（裸 PCM POST）
// ============================================================
static String baidu_asr(const int16_t* pcm, size_t samples) {
    if (!baidu_get_token()) {
        return String();
    }

    size_t pcm_bytes = samples * sizeof(int16_t);
    if (pcm_bytes == 0) {
        Serial.println("❌ ASR: 音频数据为空");
        return String();
    }

    WiFiClientSecure client;
    client.setInsecure();

    HTTPClient http;
    String url = String("https://vop.baidu.com/server_api")
                 + "?cuid=ESP32_S3"
                 + "&token=" + baidu_token
                 + "&dev_pid=1537";

    http.begin(client, url);
    http.addHeader("Content-Type", "audio/pcm;rate=16000");
    http.setTimeout(30000);

    int code = http.POST((uint8_t*)pcm, pcm_bytes);
    if (code != 200) {
        Serial.printf("❌ 百度 ASR 请求失败: HTTP %d\n", code);
        http.end();
        return String();
    }

    String resp = http.getString();
    http.end();

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, resp);
    if (err) {
        Serial.printf("❌ 百度 ASR JSON 解析失败: %s\n", err.c_str());
        return String();
    }

    int err_no = doc["err_no"];
    if (err_no != 0) {
        const char* err_msg = doc["err_msg"];
        Serial.printf("❌ 百度 ASR 识别失败: %s (err_no=%d)\n", err_msg ? err_msg : "", err_no);
        return String();
    }

    JsonArray result = doc["result"].as<JsonArray>();
    if (result.size() == 0) {
        Serial.println("❌ 百度 ASR 未识别出文本");
        return String();
    }

    return result[0].as<String>();
}

// ============================================================
//  DeepSeek 对话
// ============================================================
static String deepseek_chat(const String& text) {
    WiFiClientSecure client;
    client.setInsecure();

    HTTPClient http;
    http.begin(client, "https://api.deepseek.com/chat/completions");
    http.addHeader("Content-Type", "application/json");
    http.addHeader("Authorization", String("Bearer ") + DEEPSEEK_API_KEY);
    http.useHTTP10(true);                   // 避免 chunked 编码
    http.setTimeout(30000);
    http.setConnectTimeout(10000);

    JsonDocument req_doc;
    req_doc["model"] = "deepseek-v4-flash";
    req_doc["temperature"] = 0.7;
    req_doc["stream"] = false;

    JsonArray messages = req_doc["messages"].to<JsonArray>();
    JsonObject sys_msg = messages.add<JsonObject>();
    sys_msg["role"] = "system";
    sys_msg["content"] = "你是一个有帮助的AI助手。请用简洁的中文回答用户的问题。";

    JsonObject user_msg = messages.add<JsonObject>();
    user_msg["role"] = "user";
    user_msg["content"] = text;

    String body;
    serializeJson(req_doc, body);

    Serial.printf("📤 请求体大小: %u 字节\n", body.length());

    int code = http.POST(body);
    Serial.printf("📥 HTTP %d\n", code);

    // HTTP/1.0 模式下 getString 正常读取
    String resp = http.getString();
    http.end();

    if (code != 200) {
        Serial.printf("❌ DeepSeek 请求失败: HTTP %d\n", code);
        if (resp.length() > 0) {
            Serial.printf("   返回(前300): %s\n", resp.substring(0, 300).c_str());
        }
        return String();
    }

    if (resp.length() == 0) {
        Serial.println("❌ DeepSeek 返回空响应");
        return String();
    }

    Serial.printf("📥 响应大小: %u 字节\n", resp.length());

    JsonDocument resp_doc;
    DeserializationError err = deserializeJson(resp_doc, resp);
    if (err) {
        Serial.printf("❌ DeepSeek JSON 解析失败: %s\n", err.c_str());
        Serial.printf("   原始响应(前200): %s\n", resp.substring(0, 200).c_str());
        return String();
    }

    JsonArray choices = resp_doc["choices"].as<JsonArray>();
    if (choices.size() == 0) {
        Serial.println("❌ DeepSeek 返回 choices 为空");
        Serial.printf("   响应内容: %s\n", resp.substring(0, 300).c_str());
        return String();
    }

    return choices[0]["message"]["content"].as<String>();
}

// ============================================================
//  完整 AI 对话流程
// ============================================================
static void start_ai_dialog() {
    Serial.println("\n🎤 录音中... 再说 s 停止");

    size_t max_samples = SAMPLE_RATE * MAX_RECORD_SEC;
    size_t alloc_bytes = max_samples * sizeof(int16_t);

    int16_t* pcm_buffer = (int16_t*)ps_malloc(alloc_bytes);
    if (!pcm_buffer) {
        Serial.println("⚠️ PSRAM 不可用，改用普通内存（最大约 5 秒）");
        max_samples = SAMPLE_RATE * 5;          // 降级到 5 秒
        alloc_bytes = max_samples * sizeof(int16_t);
        pcm_buffer = (int16_t*)malloc(alloc_bytes);
        if (!pcm_buffer) {
            Serial.println("❌ 内存分配全部失败！");
            return;
        }
    }

    const size_t chunk = 512;
    int16_t temp_buf[chunk];
    size_t total_samples = 0;
    bool stopped = false;

    // 录音到 PSRAM
    while (!stopped && total_samples < max_samples) {
        while (Serial.available() > 0) {
            char c = Serial.read();
            if (c == 's' || c == 'S') {
                stopped = true;
                break;
            }
        }
        if (stopped) break;

        size_t n = mic.read(temp_buf, chunk);
        if (n == 0) break;

        memcpy(pcm_buffer + total_samples, temp_buf, n * sizeof(int16_t));
        total_samples += n;
    }

    if (total_samples == 0) {
        Serial.println("❌ 未录到音频");
        free(pcm_buffer);
        return;
    }

    float real_sec = (float)total_samples / SAMPLE_RATE;
    Serial.printf("\n✅ 录音结束: %.1f 秒, %zu 样本\n", real_sec, total_samples);

    // 百度语音识别
    Serial.println("🔄 正在识别语音...");
    String recognized = baidu_asr(pcm_buffer, total_samples);
    free(pcm_buffer);

    if (recognized.length() == 0) {
        Serial.println("❌ 语音识别失败");
        return;
    }
    Serial.printf("📝 识别结果: \"%s\"\n", recognized.c_str());

    // DeepSeek 对话
    Serial.println("🤖 正在思考...");
    String reply = deepseek_chat(recognized);
    if (reply.length() == 0) {
        Serial.println("❌ DeepSeek 回复失败");
        return;
    }

    // 输出回复（按 UTF-8 字符边界切割，防止中文被截断）
    Serial.println("\n" + String(55, '-'));
    Serial.println("🤖 DeepSeek:");
    {
        const char* p = reply.c_str();
        size_t remain = reply.length();
        while (remain > 0) {
            // 找不截断 UTF-8 字符的分块位置（最多 128 字节）
            size_t n = (remain > 128) ? 128 : remain;
            // 如果边界落在多字节字符中间，回退到字符开头
            for (size_t i = n; i > 0; i--) {
                if (((unsigned char)p[i-1] & 0xC0) != 0x80) {
                    n = i;
                    break;
                }
            }
            if (n == 0) n = 1;   // 安全兜底
            Serial.write(p, n);
            p += n;
            remain -= n;
        }
        Serial.println();
    }
    Serial.println(String(55, '-') + "\n");
}

// ============================================================
//  打印帮助
// ============================================================
static void print_help() {
    Serial.println("\n===== 命令帮助 =====");
    Serial.println("  s / S  → 开始一轮 AI 对话（录音→识别→LLM→回复）");
    Serial.println("  w      → 重新连接 WiFi");
    Serial.println("  h / H  → 打印本帮助");
    Serial.println("====================\n");
}

// ============================================================
//  setup()
// ============================================================
void setup() {
    Serial.begin(115200);
    while (!Serial) { delay(10); }

    Serial.println("\n" + String(55, '='));
    Serial.println("  ESP32-S3 AI 对话一体机");
    Serial.println("  录音 → 百度 ASR → DeepSeek → 回复");
    Serial.println(String(55, '='));

    if (!mic.init()) {
        Serial.println("❌ 麦克风初始化失败！");
        while (1) { delay(1000); }
    }
    Serial.println("✅ 麦克风就绪");

    if (psramFound()) {
        Serial.printf("✅ PSRAM: %u KB\n", ESP.getPsramSize() / 1024);
    } else {
        Serial.println("⚠️ PSRAM 未启用，录音时长受限");
    }

    if (!wifi_connect()) {
        Serial.println("⚠️ WiFi 未连接，输入 w 重连");
    }

    Serial.println("\n就绪！输入 s 开始对话");
    Serial.println(String(55, '-'));
}

// ============================================================
//  loop()
// ============================================================
void loop() {
    if (Serial.available() <= 0) return;

    char cmd = Serial.read();

    switch (cmd) {
        case 's':
        case 'S':
            if (WiFi.status() != WL_CONNECTED) {
                Serial.println("⚠️ WiFi 未连接，正在重连...");
                if (!wifi_connect()) {
                    Serial.println("❌ WiFi 连接失败");
                    return;
                }
            }
            start_ai_dialog();
            break;

        case 'w':
        case 'W':
            wifi_connect();
            break;

        case 'h':
        case 'H':
            print_help();
            break;
    }
}