"""
AI 对话主程序

流程：
  录音 → 百度语音识别 (STT) → DeepSeek (LLM) → 输出回复

用法：
  python ai_chat.py                      # 自动检测串口
  python ai_chat.py --port COM3          # 指定串口
  python ai_chat.py --no-record          # 跳过录音，直接手动输入文字
"""

import argparse
import base64
import json
import os
import sys
import threading
import time
import urllib.request
import urllib.parse
import urllib.error

import serial
import serial.tools.list_ports

from config import BAIDU_APP_ID, BAIDU_API_KEY, BAIDU_SECRET_KEY, DEEPSEEK_API_KEY

# ==================== 常量 ====================
BAUDRATE = 921600
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recordings")

# 百度 ASR 接口
BAIDU_TOKEN_URL = "https://aip.baidubce.com/oauth/2.0/token"
BAIDU_ASR_URL = "https://vop.baidu.com/server_api"

# DeepSeek 接口
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"

# ==================== 串口检测 ====================
def find_esp32_port() -> str | None:
    ports = serial.tools.list_ports.comports()
    candidates = []
    for p in ports:
        desc = ((p.description or "") + (p.product or "") + (p.manufacturer or "")).lower()
        if any(kw in desc for kw in ["cp210", "ch340", "ch343", "silicon labs", "usb serial", "esp32"]):
            candidates.append(p.device)
    if len(candidates) == 1:
        return candidates[0]
    elif len(candidates) > 1:
        print("检测到多个可能的串口:")
        for i, d in enumerate(candidates):
            print(f"  [{i}] {d}")
        try:
            idx = int(input("请选择串口编号: "))
            return candidates[idx]
        except (ValueError, IndexError):
            return candidates[0]
    return None


def list_all_ports():
    ports = serial.tools.list_ports.comports()
    if not ports:
        print("未检测到任何串口")
        return
    print("可用的串口:")
    for p in ports:
        print(f"  {p.device}  -  {p.description}")


# ==================== WAV 头构建 ====================
def build_wav_header(sample_rate: int, bits_per_sample: int, channels: int, data_bytes: int) -> bytes:
    byte_rate = sample_rate * channels * bits_per_sample // 8
    block_align = channels * bits_per_sample // 8
    chunk_size = 36 + data_bytes
    header = b"RIFF"
    header += struct.pack("<I", chunk_size)
    header += b"WAVE"
    header += b"fmt "
    header += struct.pack("<I", 16)
    header += struct.pack("<H", 1)
    header += struct.pack("<H", channels)
    header += struct.pack("<I", sample_rate)
    header += struct.pack("<I", byte_rate)
    header += struct.pack("<H", block_align)
    header += struct.pack("<H", bits_per_sample)
    header += b"data"
    header += struct.pack("<I", data_bytes)
    return header


# ==================== 录音（从 ESP32 捕获） ====================
def record_audio(ser: serial.Serial) -> bytes | None:
    """录音，返回完整 WAV 文件二进制"""
    import struct
    pcm_data = bytearray()
    pcm_lock = threading.Lock()
    stop_event = threading.Event()
    marker_received = threading.Event()
    total_samples = 0

    def reader_thread():
        nonlocal total_samples
        accumulated = bytearray()
        start_marker = b"--- PCM START ---\n"
        end_marker = b"--- PCM:"
        capturing = False
        while not stop_event.is_set():
            try:
                chunk = ser.read(1024)
                if not chunk:
                    continue
            except Exception:
                break
            accumulated.extend(chunk)
            while True:
                if not capturing:
                    pos = accumulated.find(start_marker)
                    if pos == -1:
                        if len(accumulated) > len(start_marker):
                            accumulated = accumulated[-(len(start_marker)):]
                        break
                    accumulated = accumulated[pos + len(start_marker):]
                    capturing = True
                if capturing:
                    pos = accumulated.find(end_marker)
                    if pos == -1:
                        with pcm_lock:
                            pcm_data.extend(accumulated)
                        accumulated.clear()
                        break
                    with pcm_lock:
                        pcm_data.extend(accumulated[:pos])
                    tail = accumulated[pos + len(end_marker):]
                    end_pos = tail.find(b" ---")
                    if end_pos != -1:
                        try:
                            total_samples = int(tail[:end_pos])
                        except ValueError:
                            total_samples = 0
                    marker_received.set()
                    accumulated.clear()
                    break

    ser.reset_input_buffer()
    reader = threading.Thread(target=reader_thread, daemon=True)
    reader.start()
    ser.write(b"s")
    print("\n🎤 录音中... 按 Enter 停止")
    input()
    ser.write(b"s")
    print("⏳ 等待录音结束...")
    if not marker_received.wait(timeout=25):
        stop_event.set()
        print("❌ 超时：未收到结束标记")
        return None
    stop_event.set()
    reader.join(timeout=2)
    with pcm_lock:
        pcm_bytes = bytes(pcm_data)
    if total_samples == 0 or len(pcm_bytes) == 0:
        print(f"❌ 数据无效: samples={total_samples}, bytes={len(pcm_bytes)}")
        return None
    wav_header = build_wav_header(16000, 16, 1, len(pcm_bytes))
    print(f"✅ 录音完成: {total_samples} 样本, {len(pcm_bytes)} 字节")
    return wav_header + pcm_bytes


# ==================== 百度语音识别 ====================
class BaiduASR:
    def __init__(self, app_id: str, api_key: str, secret_key: str):
        self.app_id = app_id
        self.api_key = api_key
        self.secret_key = secret_key
        self._access_token = None
        self._token_expires = 0

    def _get_access_token(self) -> str:
        """获取百度 access_token（自动缓存，有效期约30天）"""
        if self._access_token and time.time() < self._token_expires:
            return self._access_token
        params = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": self.api_key,
            "client_secret": self.secret_key,
        })
        url = f"{BAIDU_TOKEN_URL}?{params}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
        self._access_token = data["access_token"]
        self._token_expires = time.time() + 86400 * 29  # 提前1天刷新
        return self._access_token

    def recognize(self, wav_bytes: bytes) -> str | None:
        """
        百度短语音识别
        限制：音频 ≤ 60秒，格式 pcm/wav，16kHz
        """
        token = self._get_access_token()
        audio_base64 = base64.b64encode(wav_bytes).decode()
        body = {
            "format": "wav",
            "rate": 16000,
            "channel": 1,
            "cuid": "ESP32_S3",
            "token": token,
            "dev_pid": 1537,    # 普通话 - 输入法模型（准确率高）
            "speech": audio_base64,
            "len": len(wav_bytes),
        }
        body_json = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            BAIDU_ASR_URL,
            data=body_json,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())
        except Exception as e:
            print(f"❌ 百度 ASR 请求失败: {e}")
            return None

        if result.get("err_no") != 0:
            print(f"❌ 百度 ASR 识别失败: {result.get('err_msg')} (err_no={result.get('err_no')})")
            return None

        # result["result"] 是 List[str]，取第一条
        texts = result.get("result", [])
        if not texts:
            print("❌ 百度 ASR 未识别出文本")
            return None
        return texts[0]


# ==================== DeepSeek API ====================
def chat_with_deepseek(api_key: str, user_text: str, system_prompt: str = None) -> str | None:
    """调用 DeepSeek API 对话"""
    if system_prompt is None:
        system_prompt = "你是一个有帮助的AI助手。请用简洁的中文回答用户的问题。"

    body = {
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_text},
        ],
        "temperature": 0.7,
        "stream": False,
    }
    body_json = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        DEEPSEEK_API_URL,
        data=body_json,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode())
    except Exception as e:
        print(f"❌ DeepSeek 请求失败: {e}")
        return None

    choices = result.get("choices", [])
    if not choices:
        print(f"❌ DeepSeek 返回异常: {result}")
        return None
    return choices[0]["message"]["content"]


# ==================== 主程序 ====================
def main():
    parser = argparse.ArgumentParser(description="AI 对话 — 语音输入 → LLM 回复")
    parser.add_argument("--port", "-p", help="串口号，如 COM3")
    parser.add_argument("--list", action="store_true", help="列出可用串口")
    parser.add_argument("--no-record", action="store_true", help="跳过录音，手动输入文字")
    args = parser.parse_args()

    if args.list:
        list_all_ports()
        return

    # ---- 初始化百度 ASR ----
    print("🔄 初始化百度语音识别...")
    asr = BaiduASR(BAIDU_APP_ID, BAIDU_API_KEY, BAIDU_SECRET_KEY)
    # 提前获取 token，避免第一次慢
    try:
        asr._get_access_token()
        print("✅ 百度 ASR 就绪")
    except Exception as e:
        print(f"❌ 百度 ASR 认证失败: {e}")
        return

    # ---- 连接串口 (仅录音模式) ----
    ser = None
    if not args.no_record:
        port = args.port
        if port is None:
            port = find_esp32_port()
            if port is None:
                print("❌ 未检测到 ESP32 串口，请用 --port 指定或用 --no-record 跳过录音")
                list_all_ports()
                sys.exit(1)
            print(f"🔗 自动检测到串口: {port}")
        ser = serial.Serial(port, BAUDRATE, timeout=0.5)
        time.sleep(0.5)
        ser.reset_input_buffer()
        print(f"✅ 已连接 {port}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("\n" + "=" * 55)
    print("  AI 对话 — 语音输入 → 百度识别 → DeepSeek 回复")
    print("=" * 55)

    while True:
        # ---------- 1. 获取音频或文字 ----------
        if args.no_record:
            user_text = input("\n💬 输入文字（输入 q 退出）: ").strip()
            if user_text.lower() in ("q", "quit", "exit"):
                break
            if not user_text:
                continue
        else:
            cmd = input("\n[对话] 按 Enter 开始录音 / q 退出: ").strip().lower()
            if cmd == "q":
                break

            # --- 录音 ---
            wav_data = record_audio(ser)
            if wav_data is None:
                print("录音失败，请重试")
                continue

            # 保存原始录音
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            raw_path = os.path.join(OUTPUT_DIR, f"voice_{timestamp}.wav")
            with open(raw_path, "wb") as f:
                f.write(wav_data)
            print(f"📁 录音已保存: {raw_path}")

            # --- 语音识别 ---
            print("🔄 正在识别语音...")
            user_text = asr.recognize(wav_data)
            if user_text is None:
                print("语音识别失败，请重试")
                continue
            print(f"📝 识别结果: \"{user_text}\"")

        # ---------- 2. DeepSeek 对话 ----------
        print("🤖 正在思考...")
        reply = chat_with_deepseek(DEEPSEEK_API_KEY, user_text)
        if reply is None:
            print("❌ DeepSeek 回复失败")
            continue

        print(f"\n{'─' * 55}")
        print(f"🤖 DeepSeek:")
        print(f"{reply}")
        print(f"{'─' * 55}")

        # 保存对话记录
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        log_path = os.path.join(OUTPUT_DIR, f"chat_{timestamp}.txt")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"用户: {user_text}\n\nAI: {reply}\n")
        print(f"📁 对话已保存: {log_path}")

    # 清理
    if ser:
        ser.close()
    print("👋 再见")


if __name__ == "__main__":
    import struct  # for WAV header
    main()
