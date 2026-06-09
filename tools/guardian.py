#!/usr/bin/env python3
"""
Secret Guardian - 系统托盘守护程序
====================================

后台运行，系统托盘常驻，提供：
  - 实时文件监控（检测新建/修改的文件）
  - 一键扫描指定目录
  - 扫描结果通知
  - 右键菜单快速操作

依赖：
  pip install watchdog pystray pillow

用法：
  python guardian.py                  # 启动守护程序（带托盘图标）
  python guardian.py --no-tray        # 后台模式（仅监控+日志）
  python guardian.py --watch D:\code  # 监控指定目录
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from secret_scanner import SecretScanner, format_results, format_json

# ==================== 配置 ====================
LOG_DIR = os.path.expanduser("~/.secret-guardian/logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, f"guardian_{datetime.now().strftime('%Y%m%d')}.log")

# 监控忽略目录
SKIP_DIRS = {
    ".git", "node_modules", ".pio", "__pycache__",
    ".venv", "venv", ".vscode", "build", "dist",
    "bin", "obj", "packages", "target",
}

SKIP_EXTS = {
    ".pyc", ".pyo", ".exe", ".dll", ".so", ".dylib",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".ttf", ".otf", ".woff", ".woff2",
    ".o", ".a", ".lib",
}


def setup_logging():
    """配置日志"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler() if __name__ == "__main__" else logging.NullHandler(),
        ],
    )
    return logging.getLogger("guardian")


logger = setup_logging()


# ==================== 文件监控器 ====================
class FileMonitor(threading.Thread):
    """监控文件变更，自动触发扫描"""

    def __init__(self, watch_dirs=None, scanner: SecretScanner = None):
        super().__init__(daemon=True)
        self.watch_dirs = watch_dirs or []
        self.scanner = scanner or SecretScanner()
        self._stop_event = threading.Event()
        self.on_violation = None  # 回调: on_violation(results)

    def add_watch(self, path: str):
        path = os.path.abspath(path)
        if os.path.isdir(path) and path not in self.watch_dirs:
            self.watch_dirs.append(path)
            logger.info(f"📁 添加监控: {path}")

    def stop(self):
        self._stop_event.set()

    def run(self):
        """简易轮询模式（兼容性好，无需 watchdog）"""
        known_files = {}

        # 初始索引
        for wd in self.watch_dirs:
            if os.path.isdir(wd):
                for root, dirs, files in os.walk(wd):
                    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                    for f in files:
                        fp = os.path.join(root, f)
                        try:
                            known_files[fp] = os.path.getmtime(fp)
                        except (OSError, PermissionError):
                            pass

        logger.info(f"🟢 文件监控已启动, 初始索引 {len(known_files)} 个文件")

        while not self._stop_event.is_set():
            time.sleep(3)  # 每 3 秒检查一次

            for wd in self.watch_dirs:
                if not os.path.isdir(wd):
                    continue
                try:
                    for root, dirs, files in os.walk(wd):
                        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                        for f in files:
                            fp = os.path.join(root, f)
                            ext = os.path.splitext(f)[1].lower()
                            if ext in SKIP_EXTS:
                                continue

                            try:
                                mtime = os.path.getmtime(fp)
                            except (OSError, PermissionError):
                                continue

                            old_mtime = known_files.get(fp)
                            if old_mtime is None:
                                # 新文件
                                known_files[fp] = mtime
                                logger.info(f"📄 新文件: {fp}")
                                self._scan_file(fp)
                            elif mtime > old_mtime:
                                # 文件被修改
                                known_files[fp] = mtime
                                logger.info(f"✏️  文件修改: {fp}")
                                self._scan_file(fp)
                except (OSError, PermissionError):
                    continue

    def _scan_file(self, file_path: str):
        """扫描单个文件，发现敏感信息则回调"""
        # 跳过大文件 ( > 5MB)
        try:
            if os.path.getsize(file_path) > 5 * 1024 * 1024:
                return
        except OSError:
            return

        results = self.scanner.scan_file(file_path)
        if results:
            # 只关心高危及以上的
            critical = [r for r in results
                        if r["severity"] in ("critical", "high")]
            if critical and self.on_violation:
                self.on_violation(critical)


# ==================== 系统托盘 ====================
class TrayGuardian:
    """系统托盘守护程序"""

    def __init__(self, scanner: SecretScanner, watch_dirs: list):
        self.scanner = scanner
        self.watch_dirs = watch_dirs
        self.monitor = None
        self._notification_queue = []
        self._lock = threading.Lock()

    def run(self):
        """启动托盘和监控"""
        # 先启动文件监控
        self._start_monitor()

        # 尝试启动系统托盘
        try:
            self._run_tray()
        except ImportError:
            logger.warning("⚠️ pystray 未安装，运行在无界面模式")
            logger.info("💡 安装 pystray 和 pillow 可启用系统托盘:")
            logger.info("   pip install pystray pillow")
            self._wait_forever()
        except Exception as e:
            logger.error(f"系统托盘启动失败: {e}")
            self._wait_forever()

    def _start_monitor(self):
        """启动文件监控"""
        self.monitor = FileMonitor(watch_dirs=self.watch_dirs, scanner=self.scanner)

        def violation_callback(results):
            """发现敏感信息时弹出通知"""
            file_list = "\n".join(
                f"  🔴 {r['rule']} ({os.path.relpath(r['file'])}:L{r['line']})"
                for r in results[:5]
            )
            msg = f"发现 {len(results)} 处敏感信息:\n{file_list}"
            if len(results) > 5:
                msg += f"\n  ... 还有 {len(results) - 5} 处"

            logger.warning(f"🚨 敏感信息告警:\n{msg}")

            # 发送 Windows 通知
            self._notify_windows(
                "🔴 Secret Guardian 告警",
                f"发现 {len(results)} 处敏感信息！",
            )

            # 记录到通知队列
            with self._lock:
                self._notification_queue.append({
                    "time": datetime.now().isoformat(),
                    "results": results,
                })

        self.monitor.on_violation = violation_callback
        self.monitor.start()
        logger.info(f"🟢 监控已启动: {len(self.watch_dirs)} 个目录")

    def _run_tray(self):
        """运行系统托盘（需要 pystray）"""
        import pystray
        from PIL import Image, ImageDraw

        # 创建托盘图标 (16x16)
        icon_size = 64
        image = Image.new("RGBA", (icon_size, icon_size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.ellipse([4, 4, 60, 60], fill=(231, 76, 60))  # 红色盾牌
        draw.polygon([(32, 12), (48, 24), (48, 40), (32, 52), (16, 40), (16, 24)],
                     fill=(255, 255, 255))
        draw.polygon([(32, 20), (26, 30), (32, 36), (42, 26)],
                     fill=(46, 204, 113))

        def on_scan(icon, item):
            """扫描当前监控目录"""
            threading.Thread(target=self._do_scan_all, daemon=True).start()

        def on_open_log(icon, item):
            """打开日志文件"""
            os.startfile(LOG_DIR)

        def on_scan_folder(icon, item):
            """扫描指定文件夹"""
            threading.Thread(target=self._do_scan_folder, daemon=True).start()

        def on_quit(icon, item):
            icon.stop()
            self.monitor.stop()
            os._exit(0)

        def on_show_status(icon, item):
            """显示运行状态"""
            count = len(self._notification_queue)
            status = f"🟢 监控中 | 扫描告警: {count} 次"
            self._notify_windows("Secret Guardian", status)

        # 构建菜单
        menu = pystray.Menu(
            pystray.MenuItem("📊 状态", on_show_status),
            pystray.MenuItem("🔍 扫描全部", on_scan),
            pystray.MenuItem("📁 扫描文件夹...", on_scan_folder),
            pystray.MenuItem("📋 打开日志", on_open_log),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("❌ 退出", on_quit),
        )

        icon = pystray.Icon("secret_guardian", image, "Secret Guardian", menu)
        icon.run()

    def _do_scan_all(self):
        """执行全量扫描"""
        logger.info("🔍 开始全量扫描...")
        all_files = []
        for wd in self.watch_dirs:
            if os.path.isdir(wd):
                for root, dirs, files in os.walk(wd):
                    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                    for f in files:
                        fp = os.path.join(root, f)
                        ext = os.path.splitext(f)[1].lower()
                        if ext not in SKIP_EXTS:
                            all_files.append(fp)

        results = self.scanner.scan_files(all_files)
        self._show_scan_results(results)

    def _do_scan_folder(self):
        """交互式选择文件夹扫描"""
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        folder = filedialog.askdirectory(title="选择要扫描的文件夹")
        root.destroy()

        if folder:
            logger.info(f"🔍 扫描文件夹: {folder}")
            all_files = []
            for root_dir, dirs, files in os.walk(folder):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for f in files:
                    fp = os.path.join(root_dir, f)
                    ext = os.path.splitext(f)[1].lower()
                    if ext not in SKIP_EXTS:
                        all_files.append(fp)

            results = self.scanner.scan_files(all_files)
            self._show_scan_results(results)

    def _show_scan_results(self, results):
        """显示扫描结果"""
        if not results:
            self._notify_windows("✅ Secret Guardian", "扫描完成：未发现敏感信息")
            logger.info("✅ 扫描完成：未发现敏感信息")
            return

        has_blocker = any(r["severity"] in ("critical", "high") for r in results)
        if has_blocker:
            title = "🔴 发现敏感信息！"
        else:
            title = "🟡 发现警告"

        # 按文件分组摘要
        by_rule = {}
        for r in results:
            by_rule.setdefault(r["rule"], 0)
            by_rule[r["rule"]] += 1

        summary = "\n".join(f"  {k}: {v}处" for k, v in by_rule.items())

        self._notify_windows(title, summary)
        logger.info(f"扫描完成: {len(results)} 发现问题\n{summary}")

        # 输出详细信息到日志
        logger.info(format_results(results))

    def _notify_windows(self, title: str, message: str):
        """Windows 系统通知"""
        try:
            import winrt.windows.ui.notifications as notifications
            import winrt.windows.data.xml.dom as dom

            app = notifications.ToastNotificationManager.create_toast_notifier(
                "Secret Guardian"
            )
            xml = f"""<?xml version="1.0" encoding="utf-8"?>
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>{title}</text>
            <text>{message}</text>
        </binding>
    </visual>
</toast>"""
            doc = dom.XmlDocument()
            doc.load_xml(xml)
            app.show(notifications.ToastNotification(doc))
        except ImportError:
            # fallback: 使用 PowerShell 通知
            ps_cmd = (
                f'[Windows.UI.Notifications.ToastNotificationManager, '
                f'Windows.UI.Notifications, ContentType = WindowsRuntime]::CreateToastNotifier("Secret Guardian")'
            )
            try:
                subprocess.run(
                    ["powershell", "-Command", ps_cmd],
                    capture_output=True, timeout=5
                )
            except Exception:
                pass
        except Exception:
            pass

    def _wait_forever(self):
        """无界面模式：保持运行"""
        logger.info("🟢 Secret Guardian 正在后台运行...")
        logger.info(f"📁 监控目录: {self.watch_dirs}")
        logger.info(f"📋 日志文件: {LOG_FILE}")
        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            logger.info("🛑 正在停止...")
            if self.monitor:
                self.monitor.stop()


# ==================== 主入口 ====================

def main():
    parser = argparse.ArgumentParser(
        description="Secret Guardian - 系统托盘守护程序",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--watch", "-w", nargs="*", default=[],
        help="要监控的目录（默认: 桌面 + 文档）",
    )
    parser.add_argument(
        "--no-tray", action="store_true",
        help="无界面后台模式（仅监控 + 日志）",
    )
    parser.add_argument(
        "--scan-now", nargs="*", metavar="PATH",
        help="立即扫描指定路径后退出",
    )
    parser.add_argument(
        "--log", action="store_true",
        help="打开日志目录",
    )

    args = parser.parse_args()

    scanner = SecretScanner()

    # 立即扫描模式
    if args.scan_now is not None:
        all_files = []
        for path in (args.scan_now or ["."]):
            p = os.path.abspath(path)
            if os.path.isfile(p):
                all_files.append(p)
            elif os.path.isdir(p):
                for root, dirs, files in os.walk(p):
                    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                    for f in files:
                        ext = os.path.splitext(f)[1].lower()
                        if ext not in SKIP_EXTS:
                            all_files.append(os.path.join(root, f))

        results = scanner.scan_files(all_files)
        print(format_results(results))

        if any(r["severity"] in ("critical", "high") for r in results):
            sys.exit(1)
        sys.exit(0)

    # 打开日志
    if args.log:
        os.startfile(LOG_DIR)
        sys.exit(0)

    # 确定监控目录
    watch_dirs = [os.path.abspath(w) for w in args.watch] if args.watch else []

    if not watch_dirs:
        # 默认监控桌面和文档
        desktop = os.path.expanduser("~/Desktop")
        documents = os.path.expanduser("~/Documents")
        if os.path.isdir(desktop):
            watch_dirs.append(desktop)
        if os.path.isdir(documents):
            watch_dirs.append(documents)
        # 也监控当前工作目录
        watch_dirs.append(os.getcwd())

    # 去重
    watch_dirs = list(dict.fromkeys(watch_dirs))

    print(f"🔒 Secret Guardian v1.0 - 敏感信息守护程序")
    print(f"{'=' * 50}")
    print(f"📁 监控目录: {len(watch_dirs)} 个")
    for wd in watch_dirs:
        print(f"   • {wd}")
    print(f"📋 日志: {LOG_FILE}")
    print(f"{'=' * 50}")

    guardian = TrayGuardian(scanner, watch_dirs)
    guardian.run()


if __name__ == "__main__":
    main()
