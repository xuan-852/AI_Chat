"""
ESP32-S3 INMP441 录音捕获播放工具（流式版本）

ESP32 端只发裸 PCM 数据，录音结束发送标记：
    --- PCM:<样本数> ---

本工具：
    1. 后台线程持续读取串口，不丢数据
    2. 收到标记后解析样本数，自己拼正确的 WAV 头
    3. 保存为 .wav 文件并播放

用法：
    python recorder.py                     # 自动检测串口
    python recorder.py --port COM3         # 指定串口
"""

import argparse
import os
import struct
import sys
import threading
import time

import serial
import serial.tools.list_ports

BAUDRATE = 921600
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recordings")


# ============================================================
#  串口自动检测
# ============================================================
def find_esp32_port() -> str | None:
    """自动查找 ESP32-S3 串口（通常包含 'CP210'、'CH340'、'USB Serial' 等关键词）"""
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
            print("输入无效，使用第一个")
            return candidates[0]
    return None


def list_all_ports():
    """列出所有串口"""
    ports = serial.tools.list_ports.comports()
    if not ports:
        print("未检测到任何串口")
        return
    print("可用的串口:")
    for p in ports:
        print(f"  {p.device}  -  {p.description}")


# ============================================================
#  构建 WAV 头
# ============================================================
def build_wav_header(sample_rate: int, bits_per_sample: int, channels: int, data_bytes: int) -> bytes:
    """构建标准 WAV 文件头（PCM 格式）"""
    byte_rate = sample_rate * channels * bits_per_sample // 8
    block_align = channels * bits_per_sample // 8
    chunk_size = 36 + data_bytes

    header = b"RIFF"
    header += struct.pack("<I", chunk_size)
    header += b"WAVE"
    header += b"fmt "
    header += struct.pack("<I", 16)           # fmt chunk 大小
    header += struct.pack("<H", 1)            # PCM 格式
    header += struct.pack("<H", channels)
    header += struct.pack("<I", sample_rate)
    header += struct.pack("<I", byte_rate)
    header += struct.pack("<H", block_align)
    header += struct.pack("<H", bits_per_sample)
    header += b"data"
    header += struct.pack("<I", data_bytes)
    return header


# ============================================================
#  主录音循环
# ============================================================
def record_once(ser: serial.Serial) -> bytes | None:
    """
    完整录音流程：
      1. 发送 s 开始录音
      2. 后台线程持续读取串口 PCM 数据
      3. 发送 s 停止录音
      4. 等待解析 --- PCM:xxx --- 标记
      5. 返回完整 WAV 文件二进制
    """
    pcm_data = bytearray()
    pcm_lock = threading.Lock()
    stop_event = threading.Event()
    marker_received = threading.Event()
    started = threading.Event()
    total_samples = 0

    # ---- 后台读取线程 ----
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
                    # 还没到 PCM 数据区，找起始标记
                    pos = accumulated.find(start_marker)
                    if pos == -1:
                        # 保留可能跨包的尾部
                        if len(accumulated) > len(start_marker):
                            accumulated = accumulated[-(len(start_marker)):]
                        break
                    # 跳过起始标记，之后的数据都是 PCM
                    accumulated = accumulated[pos + len(start_marker):]
                    capturing = True
                    started.set()

                if capturing:
                    # 找结束标记
                    pos = accumulated.find(end_marker)
                    if pos == -1:
                        # 还没到结束，全部算 PCM
                        with pcm_lock:
                            pcm_data.extend(accumulated)
                        accumulated.clear()
                        break
                    # 结束标记之前的是 PCM
                    with pcm_lock:
                        pcm_data.extend(accumulated[:pos])
                    # 解析样本数
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

    # ---- 开始 ----
    ser.reset_input_buffer()
    reader = threading.Thread(target=reader_thread, daemon=True)
    reader.start()

    ser.write(b"s")
    print(">>> 录音中...")

    # ---- 等待用户停止 ----
    input("按 Enter 停止录音")

    ser.write(b"s")
    print("等待录音结束...")

    # ---- 等待标记或超时 ----
    if not marker_received.wait(timeout=25):
        stop_event.set()
        print("超时：未收到结束标记")
        return None

    stop_event.set()
    reader.join(timeout=2)

    with pcm_lock:
        pcm_bytes = bytes(pcm_data)

    if total_samples == 0 or len(pcm_bytes) == 0:
        print(f"数据无效: samples={total_samples}, bytes={len(pcm_bytes)}")
        return None

    print(f"PCM 数据: {total_samples} 样本, {len(pcm_bytes)} 字节")

    # ---- 构建 WAV ----
    wav_header = build_wav_header(
        sample_rate=16000,
        bits_per_sample=16,
        channels=1,
        data_bytes=len(pcm_bytes),
    )
    return wav_header + pcm_bytes


# ============================================================
#  主循环
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="ESP32-S3 INMP441 录音捕获播放")
    parser.add_argument("--port", "-p", help="串口号，如 COM3")
    parser.add_argument("--list", action="store_true", help="列出可用串口")
    args = parser.parse_args()

    if args.list:
        list_all_ports()
        return

    # ---- 确定串口 ----
    port = args.port
    if port is None:
        port = find_esp32_port()
        if port is None:
            print("错误: 未检测到 ESP32 串口，请用 --port 指定")
            list_all_ports()
            sys.exit(1)
        print(f"自动检测到串口: {port}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with serial.Serial(port, BAUDRATE, timeout=0.5) as ser:
        print(f"已连接 {port}")
        time.sleep(0.5)
        ser.reset_input_buffer()

        print("=" * 50)
        print("按 Enter 开始录音，再按 Enter 停止")
        print("输入 q 回车退出")
        print("=" * 50)

        while True:
            cmd = input("\n[录音] 按 Enter 开始 / q 退出: ").strip().lower()
            if cmd == "q":
                break

            wav_data = record_once(ser)
            if wav_data is None:
                print("录音失败，请重试")
                continue

            # ---- 保存 ----
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"recording_{timestamp}.wav"
            filepath = os.path.join(OUTPUT_DIR, filename)
            with open(filepath, "wb") as f:
                f.write(wav_data)
            print(f"已保存: {filepath} ({len(wav_data)} 字节)")

            # ---- 播放 ----
            try:
                import winsound
                winsound.PlaySound(filepath, winsound.SND_FILENAME | winsound.SND_ASYNC)
                print("正在播放...")
            except Exception as e:
                print(f"播放失败: {e}")
                print(f"可手动打开: {filepath}")


if __name__ == "__main__":
    main()
