#!/usr/bin/env python3
"""
Secret Guardian - 敏感信息扫描引擎
=====================================

功能：
  扫描文件中的 API Key、密码、Token 等敏感信息
  可作为独立 CLI 工具、Git 钩子、或模块导入使用

用法：
  # 扫描指定文件
  python secret_scanner.py scan config.py main.cpp

  # 扫描 Git 暂存区 (用于 pre-commit 钩子)
  python secret_scanner.py pre-commit

  # 扫描 Git 推送内容 (用于 pre-push 钩子)
  python secret_scanner.py pre-push

  # 作为模块导入
  from secret_scanner import SecretScanner
  scanner = SecretScanner()
  results = scanner.scan_file("config.py")
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple, Optional


# ==================== 扫描规则 ====================
# 每条规则: (名称, 正则, 严重级别, 说明)
# 严重级别: critical / high / medium / low
SCAN_RULES = [
    # --- Private keys ---
    ("Private Key",
     r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
     "critical",
     "Private key content - someone can impersonate you"),

    # --- AI API Keys ---
    ("DeepSeek / OpenAI API Key",
     r"sk-[A-Za-z0-9]{20,}",
     "high",
     "AI service API key - could be used to call paid APIs"),

    ("Baidu API Credentials",
     r"(BAIDU_API_KEY|BAIDU_SECRET_KEY|BAIDU_APP_ID)\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{8,}",
     "high",
     "Baidu Cloud API credentials - could be used for paid services"),

    # --- Generic credentials ---
    ("Generic API Key",
     r"(?<!\.)(?:api[_-]?key|apikey)\s*[=:]\s*[\"']?[A-Za-z0-9_\-/+=]{16,}",
     "high",
     "API key assignment - may expose cloud service credentials"),

    ("Generic Secret Key",
     r"(?<!\.)(?:secret[_-]?key|secretkey)\s*[=:]\s*[\"']?[A-Za-z0-9_\-/+=]{8,}",
     "high",
     "Secret key assignment"),

    # --- Tokens ---
    ("GitHub Token",
     r"gh[ps]_[A-Za-z0-9]{36,}",
     "high",
     "GitHub Personal Access Token - can access your repos"),

    ("GitLab Token",
     r"glpat-[A-Za-z0-9\-_]{20,}",
     "high",
     "GitLab Personal Access Token"),

    ("Slack Token",
     r"xox[baprs]-[A-Za-z0-9]{10,}",
     "high",
     "Slack Bot/User Token"),

    ("JWT Token",
     r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
     "medium",
     "JWT token - may contain auth info"),

    ("Generic Access Token",
     r"(?<!\.)(?:access[_-]?token|auth[_-]?token)\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{20,}",
     "high",
     "Access token or auth token"),

    ("Bearer Token",
     r"(?i)(?:Authorization|Bearer)\s*[=:]\s*[\"']?Bearer\s+[A-Za-z0-9_\-\.]{20,}",
     "high",
     "HTTP Authorization Bearer token"),

    # --- Passwords ---
    ("Plain Text Password",
     r"(?<!\.)(?:password|passwd|pwd)\s*[=:]\s*[\"']?(?!\s*(?:true|false|yes|no|null|none|0|1)\s*$)[^\"';\s]{6,}",
     "high",
     "Plain text password - use environment variables instead"),

    ("WiFi Password",
     r"(?<!\.)(?:wifi[_-]?(?:password|psk|key))\s*[=:]\s*[\"']?[^\"';\s]{6,}",
     "high",
     "WiFi password - exposes home/office network"),

    ("WiFi SSID",
     r"(?<!\.)(?:wifi[_-]?ssid|ssid)\s*[=:]\s*[\"']?[A-Za-z0-9_\- ]{4,}",
     "medium",
     "WiFi SSID (network name) - may expose location info"),

    # --- Cloud services ---
    ("AWS Access Key",
     r"AKIA[0-9A-Z]{16}",
     "high",
     "AWS Access Key - may incur cloud service charges"),

    # --- Databases ---
    ("Database Connection String",
     r"(mongodb|postgresql|mysql|redis|rediss)://[A-Za-z0-9_\-%]+:[^@]{3,}@",
     "high",
     "Database connection string with username and password"),
]

# 白名单模式：匹配这些的行会被跳过（防止误报示例代码）
WHITELIST_PATTERNS = [
    r"your[_-]?api[_-]?key",
    r"your[_-]?secret[_-]?key",
    r"example[_-]?key",
    r"YOUR_API_KEY",
    r"YOUR_SECRET_KEY",
    r"<your[_-]?api[_-]?key>",
    r"sk-your-api-key",
    r"your-password",
    r"your-ssid",
    r"your-wifi-ssid",
    r"your-wifi-password",
    r"your_app_id_here",
    r"your_api_key_here",
    r"your_secret_key_here",
    r"sk-your-api-key-here",
    r"\.example\.",
    r"TODO",
    r"FIXME",
    r"示例",
    r"example",
    r"_here",
]


class SecretScanner:
    """敏感信息扫描器"""

    def __init__(self, rules: Optional[List[Tuple]] = None,
                 whitelist: Optional[List[str]] = None):
        self.rules = rules or SCAN_RULES
        self.whitelist = [re.compile(p, re.IGNORECASE) for p in (whitelist or WHITELIST_PATTERNS)]

    # ---------------------------------------------------------------
    #  扫描单个文件
    # ---------------------------------------------------------------
    def scan_file(self, file_path: str) -> List[dict]:
        """扫描单个文件，返回发现的敏感信息列表"""
        # 跳过不存在的文件
        if not os.path.isfile(file_path):
            return []

        results = []

        # 跳过二进制文件
        try:
            with open(file_path, "rb") as f:
                head = f.read(1024)
                if b"\x00" in head:
                    return []  # 二进制文件跳过
        except Exception:
            return [{
                "file": file_path,
                "line": 0,
                "rule": "文件读取错误",
                "severity": "error",
                "match": f"无法读取文件: {file_path}",
                "description": "",
            }]

        # 读取文本内容
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            return [{
                "file": file_path,
                "line": 0,
                "rule": "文件读取错误",
                "severity": "error",
                "match": str(e),
                "description": "",
            }]

        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue

            # 注释行跳过（不含等号的纯注释）
            if re.match(r"^\s*(#|//|--|;|%|/\*|\*)", stripped) and "=" not in stripped and ":" not in stripped:
                continue

            # 白名单过滤
            if any(p.search(stripped) for p in self.whitelist):
                continue

            # 逐条规则匹配
            for rule_name, pattern, severity, description in self.rules:
                try:
                    if re.search(pattern, stripped):
                        # 提取匹配的具体内容（最多显示80字符）
                        match_obj = re.search(pattern, stripped)
                        matched_text = match_obj.group(0) if match_obj else stripped
                        # 脱敏显示：只显示前6后4字符
                        masked = self._mask(matched_text)

                        results.append({
                            "file": file_path,
                            "line": line_no,
                            "rule": rule_name,
                            "severity": severity,
                            "match": masked,
                            "context": stripped[:150].strip(),
                            "description": description,
                        })
                        break  # 一行只报告一个规则（按优先级最高的）
                except re.error:
                    continue

        return results

    # ---------------------------------------------------------------
    #  扫描多个文件
    # ---------------------------------------------------------------
    def scan_files(self, file_paths: List[str]) -> List[dict]:
        """扫描多个文件"""
        all_results = []
        seen = set()  # 去重

        for fp in file_paths:
            # 规范化路径
            norm = os.path.normpath(fp)
            if norm in seen:
                continue
            seen.add(norm)

            results = self.scan_file(norm)
            all_results.extend(results)

        return all_results

    # ---------------------------------------------------------------
    #  Git 相关扫描
    # ---------------------------------------------------------------
    def scan_git_staged(self, git_dir: Optional[str] = None) -> List[dict]:
        """
        扫描 Git 暂存区中的文件 (pre-commit 钩子使用)
        git_dir: Git 工作目录，None 则自动检测
        """
        cwd = git_dir or os.getcwd()

        try:
            result = subprocess.run(
                ["git", "-C", cwd, "diff", "--cached", "--name-only",
                 "--diff-filter=ACMR"],
                capture_output=True, text=True, check=True, timeout=30
            )
            files = [f for f in result.stdout.strip().split("\n") if f.strip()]
            if not files:
                return []

            existing = [os.path.join(cwd, f) for f in files
                        if os.path.isfile(os.path.join(cwd, f))]
            return self.scan_files(existing)

        except subprocess.TimeoutExpired:
            return [{"file": "", "line": 0, "rule": "Git 超时",
                     "severity": "error", "match": "git diff 命令超时",
                     "context": "", "description": ""}]
        except subprocess.CalledProcessError:
            return [{"file": "", "line": 0, "rule": "Git 错误",
                     "severity": "error", "match": "无法获取 Git 暂存区文件",
                     "context": "", "description": ""}]
        except FileNotFoundError:
            return [{"file": "", "line": 0, "rule": "Git 未安装",
                     "severity": "error", "match": "未找到 Git 命令",
                     "context": "", "description": ""}]

    def scan_git_push(self) -> List[dict]:
        """
        扫描即将推送的提交中的文件 (pre-push 钩子使用)
        从 stdin 读取推送 refs 信息
        """
        refs = sys.stdin.read().strip()
        if not refs:
            return []

        all_results = []
        cwd = os.getcwd()

        for line in refs.split("\n"):
            parts = line.strip().split()
            if len(parts) < 4:
                continue

            local_sha = parts[1]
            remote_sha = parts[3]

            # 确定 commit 范围
            if remote_sha == "0" * 40:            # 新分支/首次推送
                try:
                    # 获取从第一个 commit 到当前的所有变化
                    result = subprocess.run(
                        ["git", "-C", cwd, "rev-list", "--max-parents=0", "HEAD"],
                        capture_output=True, text=True, check=True, timeout=15
                    )
                    first_commit = result.stdout.strip()
                    range_spec = f"{first_commit}~1..{local_sha}"
                except Exception:
                    continue
            elif local_sha == "0" * 40:           # 删除分支
                continue
            else:
                range_spec = f"{remote_sha}..{local_sha}"

            try:
                result = subprocess.run(
                    ["git", "-C", cwd, "diff", "--name-only",
                     "--diff-filter=ACMR", range_spec],
                    capture_output=True, text=True, check=True, timeout=30
                )
                files = [f for f in result.stdout.strip().split("\n") if f.strip()]
                existing = [os.path.join(cwd, f) for f in files
                            if os.path.isfile(os.path.join(cwd, f))]
                all_results.extend(self.scan_files(existing))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                continue

        return all_results

    # ---------------------------------------------------------------
    #  工具方法
    # ---------------------------------------------------------------
    @staticmethod
    def _mask(text: str) -> str:
        """脱敏显示：只显示前6后4字符"""
        text = text.strip()
        if len(text) <= 10:
            return text
        return text[:6] + "*" * (len(text) - 10) + text[-4:]

    @staticmethod
    def has_critical(results: List[dict]) -> bool:
        """检查是否有严重/高危问题"""
        return any(r["severity"] in ("critical", "high") for r in results)

    @staticmethod
    def load_rules_from_file(config_path: str) -> Tuple[List[Tuple], List[str]]:
        """从 JSON 配置文件加载规则"""
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        rules = []
        for r in cfg.get("rules", []):
            rules.append((
                r["name"],
                r["pattern"],
                r.get("severity", "high"),
                r.get("description", ""),
            ))

        whitelist = cfg.get("whitelist", [])

        return rules, whitelist


# ==================== 输出格式化 ====================

def format_results(results: List[dict], verbose: bool = False) -> str:
    """格式化扫描结果为人类可读的文本"""
    if not results:
        return "[OK] No secrets found. Safe!"

    # 按严重级别统计
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "error": 0}
    for r in results:
        counts[r.get("severity", "low")] += 1

    lines = []
    has_blocker = any(counts[s] > 0 for s in ("critical", "high"))

    if has_blocker:
        lines.append(f"[!] Found {len(results)} secrets, operation blocked!\n")
    else:
        lines.append(f"[?] Found {len(results)} warnings (non-blocking)\n")

    # 严重级别统计
    parts = []
    if counts["critical"]:
        parts.append(f"[CRIT] {counts['critical']} critical")
    if counts["high"]:
        parts.append(f"[HIGH] {counts['high']} high")
    if counts["medium"]:
        parts.append(f"[MED]  {counts['medium']} medium")
    if counts["low"]:
        parts.append(f"[LOW]  {counts['low']} low")
    if counts["error"]:
        parts.append(f"[ERR]  {counts['error']} errors")
    if parts:
        lines.append("  " + " | ".join(parts) + "\n")

    # 按文件分组
    by_file = {}
    for r in results:
        by_file.setdefault(r["file"], []).append(r)

    for file_path, items in sorted(by_file.items()):
        if not file_path:
            continue
        display_path = os.path.relpath(file_path) if os.path.exists(file_path) else file_path
        lines.append(f"\n  --- {display_path} ---")

        for item in items:
            severity_mark = {
                "critical": "[CRIT]",
                "high": "[HIGH]",
                "medium": "[MED]",
                "low": "[LOW]",
                "error": "[ERR]",
            }.get(item.get("severity", ""), "[INFO]")

            line_info = f" L{item['line']:4d}" if item.get("line", 0) > 0 else "      "
            lines.append(
                f"  {severity_mark}{line_info} | {item['rule']}"
            )
            if verbose:
                lines.append(f"          {item.get('description', '')}")
            lines.append(f"          => {item.get('match', '')}")

    lines.append("\n" + "=" * 60)
    if has_blocker:
        lines.append("[!] Operation blocked! Remove sensitive data above and retry.")
        lines.append("[*] Tip: Move secrets to environment variables or .env files.")
    else:
        lines.append("[*] Tip: Review the warnings above. Safe to proceed if acceptable.")

    return "\n".join(lines)


def format_json(results: List[dict]) -> str:
    """格式化为 JSON"""
    output = []
    for r in results:
        output.append({
            "file": os.path.relpath(r["file"]) if os.path.exists(r["file"]) else r["file"],
            "line": r.get("line", 0),
            "rule": r["rule"],
            "severity": r.get("severity", "low"),
            "match": r.get("match", ""),
            "description": r.get("description", ""),
        })
    return json.dumps(output, ensure_ascii=False, indent=2)


# ==================== 主入口 ====================

def main():
    parser = argparse.ArgumentParser(
        description="Secret Guardian - Secret Scanner v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan config.py src/main.cpp     # Scan specific files
  %(prog)s scan tools/                     # Scan directory
  %(prog)s pre-commit                       # Scan git staged area
  %(prog)s pre-push                         # Scan git push content
  %(prog)s --json scan config.py            # JSON output
  %(prog)s --verbose scan config.py         # Verbose output
        """,
    )
    parser.add_argument(
        "mode", nargs="?", default="scan",
        choices=["scan", "pre-commit", "pre-push", "install-hook"],
        help="Scan mode (default: scan)",
    )
    parser.add_argument("files", nargs="*", help="Files or dirs to scan (scan mode)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--config", help="Custom rules config file")
    parser.add_argument(
        "--hook-dir",
        default=None,
        help="Git hook install dir (install-hook mode)",
    )

    args = parser.parse_args()

    # 加载规则
    scanner: SecretScanner
    if args.config and os.path.isfile(args.config):
        rules, whitelist = SecretScanner.load_rules_from_file(args.config)
        scanner = SecretScanner(rules=rules, whitelist=whitelist)
    else:
        scanner = SecretScanner()

    # --- 扫描模式 ---
    if args.mode == "scan":
        # 收集要扫描的文件
        all_files = []
        for path in args.files:
            if os.path.isfile(path):
                all_files.append(path)
            elif os.path.isdir(path):
                for root, _, filenames in os.walk(path):
                    # 跳过常见无关目录
                    skip_dirs = {".git", "node_modules", ".pio",
                                 "__pycache__", ".venv", "venv",
                                 ".vscode", "build", "dist"}
                    # 过滤掉跳过的目录
                    if any(s in root.split(os.sep) for s in skip_dirs):
                        continue
                    for fn in filenames:
                        fp = os.path.join(root, fn)
                        all_files.append(fp)

        if not all_files:
            parser.print_help()
            sys.exit(0)

        results = scanner.scan_files(all_files)

    # --- Git pre-commit 模式 ---
    elif args.mode == "pre-commit":
        results = scanner.scan_git_staged()
        if not results:
            print("No secrets found in staged files. Safe!")
            sys.exit(0)

    # --- Git pre-push 模式 ---
    elif args.mode == "pre-push":
        results = scanner.scan_git_push()
        if not results:
            print("No secrets found in push content. Safe!")
            sys.exit(0)

    # --- 安装钩子模式 ---
    elif args.mode == "install-hook":
        return install_hooks(args.hook_dir)

    else:
        results = []

    # --- 输出 ---
    if args.json:
        print(format_json(results))
    else:
        print(format_results(results, args.verbose))

    # --- 退出码 ---
    # 0: 安全  |  1: 有高危/致命问题  |  2: 有中低危问题
    if any(r["severity"] in ("critical", "high") for r in results):
        sys.exit(1)
    elif results:
        sys.exit(2)
    else:
        sys.exit(0)


# ==================== Git 钩子安装 ====================

def install_hooks(target_dir: Optional[str] = None) -> None:
    r"""
    Install git hooks to target dir (global hooks)
    If target_dir is None, use default ~\.secret-guardian\git-hooks\
    """
    if target_dir is None:
        target_dir = os.path.expanduser("~/.secret-guardian/git-hooks")

    hook_dir = Path(target_dir)
    hook_dir.mkdir(parents=True, exist_ok=True)

    # 获取本脚本的路径
    script_path = os.path.abspath(__file__)

    # Git for Windows (MSYS2) 可以执行 shell 脚本作为钩子
    # 使用 /bin/sh shebang 确保兼容性
    hooks = {
        "pre-commit": f"""#!/bin/sh
# Secret Guardian - Pre-commit hook
echo "[Secret Guardian] Scanning staged files..."
PYTHONIOENCODING=utf-8 python "{script_path}" pre-commit
if [ $? -ne 0 ]; then
    echo ""
    echo "[!] Secret Guardian: Sensitive info detected, commit blocked!"
    echo "[*] To skip check: git commit --no-verify"
    exit 1
fi
exit 0
""",
        "pre-push": f"""#!/bin/sh
# Secret Guardian - Pre-push hook
echo "[Secret Guardian] Scanning push content..."
PYTHONIOENCODING=utf-8 python "{script_path}" pre-push
if [ $? -ne 0 ]; then
    echo ""
    echo "[!] Secret Guardian: Sensitive info detected, push blocked!"
    echo "[*] To skip check: git push --no-verify"
    exit 1
fi
exit 0
""",
        "pre-commit.bat": f"""@echo off
REM Secret Guardian - Pre-commit hook
echo [Secret Guardian] Scanning staged files...
set PYTHONIOENCODING=utf-8
python "{script_path}" pre-commit
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Secret Guardian: Sensitive info detected, commit blocked!
    echo [*] To skip check: git commit --no-verify
    exit /b 1
)
exit /b 0
""",
        "pre-push.bat": f"""@echo off
REM Secret Guardian - Pre-push hook
echo [Secret Guardian] Scanning push content...
set PYTHONIOENCODING=utf-8
python "{script_path}" pre-push
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Secret Guardian: Sensitive info detected, push blocked!
    echo [*] To skip check: git push --no-verify
    exit /b 1
)
exit /b 0
""",
    }

    for hook_name, hook_content in hooks.items():
        hook_path = hook_dir / hook_name
        with open(hook_path, "w", encoding="utf-8") as f:
            f.write(hook_content)
        print(f"  [OK] Created: {hook_path}")

    # 同时生成 PowerShell 版本（供手动使用）
    ps_hooks = {
        "pre-commit.ps1": f"""# Secret Guardian - Pre-commit hook (PowerShell)
Write-Host "[Secret Guardian] Scanning staged files..." -ForegroundColor Cyan
python "{script_path}" pre-commit
if ($LASTEXITCODE -ne 0) {{
    Write-Host ""
    Write-Host "[!] Secret Guardian: Sensitive info detected, commit blocked!" -ForegroundColor Red
    Write-Host "[*] To skip check: git commit --no-verify" -ForegroundColor Yellow
    exit 1
}}
exit 0
""",
        "pre-push.ps1": f"""# Secret Guardian - Pre-push hook (PowerShell)
Write-Host "[Secret Guardian] Scanning push content..." -ForegroundColor Cyan
python "{script_path}" pre-push
if ($LASTEXITCODE -ne 0) {{
    Write-Host ""
    Write-Host "[!] Secret Guardian: Sensitive info detected, push blocked!" -ForegroundColor Red
    Write-Host "[*] To skip check: git push --no-verify" -ForegroundColor Yellow
    exit 1
}}
exit 0
""",
    }

    for hook_name, hook_content in ps_hooks.items():
        hook_path = hook_dir / hook_name
        with open(hook_path, "w", encoding="utf-8") as f:
            f.write(hook_content)
        print(f"  [OK] Created: {hook_path}")

    print(f"\n[Hooks directory: {hook_dir}")
    print("\nNow run this command to enable global hooks:")
    print(f"  git config --global core.hooksPath \"{hook_dir}\"")
    print("")
    print("After that, ALL git repos will automatically use these hooks!")
    print("\nHooks work with Git Bash (MSYS2 shell included with Git for Windows).")
    print("If using PowerShell/cmd, Git for Windows >= 2.37+ is required.")


if __name__ == "__main__":
    main()
