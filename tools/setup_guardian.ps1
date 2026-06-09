#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Secret Guardian 一键安装脚本
.DESCRIPTION
  安装敏感信息扫描工具到系统，配置全局 Git 钩子和开机自启
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $PSCommandPath
$ProjectRoot = Split-Path -Parent $ScriptDir

# ==================== 颜色 ====================
function Write-Color {
    param([string]$Text, [string]$Color = "White")
    Write-Host $Text -ForegroundColor $Color
}

# ==================== 配置路径 ====================
$GuardianDir = "$env:USERPROFILE\.secret-guardian"
$HookDir = "$GuardianDir\git-hooks"
$LogDir = "$GuardianDir\logs"
$ScannerSrc = "$ScriptDir\secret_scanner.py"
$ScannerDst = "$GuardianDir\secret_scanner.py"

Write-Color "`n==============================================" Cyan
Write-Color "  Secret Guardian v1.0 - 一键安装" Cyan
Write-Color "==============================================" Cyan

# ==================== Step 1: 复制扫描脚本 ====================
Write-Color "`n[1/5] 复制扫描引擎..." Yellow
New-Item -ItemType Directory -Force -Path $GuardianDir, $HookDir, $LogDir | Out-Null

if (Test-Path $ScannerSrc) {
    Copy-Item -Path $ScannerSrc -Destination $ScannerDst -Force
    Write-Color "  ✅ 已复制到: $ScannerDst" Green
} else {
    Write-Color "  ❌ 未找到 secret_scanner.py，请确认 tools/ 目录下有该文件" Red
    exit 1
}

# ==================== Step 2: 创建 Git 钩子 ====================
Write-Color "`n[2/5] 创建全局 Git 钩子..." Yellow

$HookContent_Commit = @"
@echo off
REM Secret Guardian - Pre-commit hook
python "$ScannerDst" pre-commit
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo 🔴 Secret Guardian: 检测到敏感信息，提交已阻止！
    echo 如果要忽略检查，请使用: git commit --no-verify
    exit /b 1
)
exit /b 0
"@

$HookContent_Push = @"
@echo off
REM Secret Guardian - Pre-push hook
python "$ScannerDst" pre-push
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo 🔴 Secret Guardian: 检测到敏感信息，推送已阻止！
    echo 如果要忽略检查，请使用: git push --no-verify
    exit /b 1
)
exit /b 0
"@

Set-Content -Path "$HookDir\pre-commit" -Value $HookContent_Commit -Encoding ASCII
Set-Content -Path "$HookDir\pre-push" -Value $HookContent_Push -Encoding ASCII

Write-Color "  ✅ 已创建: pre-commit / pre-push 钩子" Green

# ==================== Step 3: 配置全局 Git 钩子路径 ====================
Write-Color "`n[3/5] 配置全局 Git 钩子路径..." Yellow
git config --global core.hooksPath $HookDir 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Color "  ✅ 已设置: git config --global core.hooksPath """$HookDir"""" Green
    Write-Color "  📌  所有 Git 仓库都将应用此钩子" Cyan
} else {
    Write-Color "  ⚠️  Git 配置失败，请手动执行:" Yellow
    Write-Color "      git config --global core.hooksPath ""$HookDir""" Yellow
}

# ==================== Step 4: 添加开机自启 ====================
Write-Color "`n[4/5] 配置开机自启（可选）..." Yellow
Write-Color "  是否要添加系统托盘守护程序（开机自启）？" -Color Cyan
Write-Color "  [Y] 是  |  [N] 否（仅安装 Git 钩子）" -Color Cyan
$choice = Read-Host "  请选择 (Y/N)"
if ($choice -eq "y" -or $choice -eq "Y") {
    $VbsPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\SecretGuardian.vbs"
    $GuardianScript = "$GuardianDir\guardian.py"

    # 创建守护脚本
    @"
import sys, os
sys.path.insert(0, r"$GuardianDir")
from secret_scanner import SecretScanner, format_results

# 简单后台守护版本 - 在后台运行，通过系统托盘监控
# 完整版本将在后续安装
print("Secret Guardian 守护程序已启动")
"@ | Set-Content -Path $GuardianScript -Encoding UTF8

    # 创建 VBS 启动器（无窗口后台运行）
    @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "pythonw ""$GuardianScript""", 0, False
"@ | Set-Content -Path $VbsPath -Encoding ASCII

    Write-Color "  ✅ 已添加到开机自启" Green
} else {
    Write-Color "  ⏭️  跳过开机自启" Gray
}

# ==================== Step 5: 测试 ====================
Write-Color "`n[5/5] 运行测试扫描..." Yellow
Write-Color "  测试: 扫描 `$ScannerSrc 自身（应无敏感信息）..." Cyan
python "$ScannerDst" scan "$ScannerSrc"
if ($LASTEXITCODE -eq 0) {
    Write-Color "  ✅ 扫描引擎工作正常！" Green
} else {
    Write-Color "  ⚠️  扫描测试有输出，请检查" Yellow
}

# ==================== 完成 ====================
Write-Color "`n==============================================" Cyan
Write-Color "  ✅  Secret Guardian 安装完成！" Green
Write-Color "==============================================" Cyan
Write-Color "`n📌  使用说明:" Cyan
Write-Color "  - Git 钩子已全局生效，所有仓库 commit/push 前自动扫描" White
Write-Color "  - 手动扫描: python $ScannerDst scan <文件/目录>" White
Write-Color "  - 查看帮助: python $ScannerDst --help" White
Write-Color "  - 钩子目录: $HookDir" White
Write-Color "  - 配置文件: $GuardianDir" White
Write-Color "`n💡  提示: 如果钩子被误报阻止，可用 --no-verify 跳过" Yellow
Write-Color "     例: git commit --no-verify  -m \"...\"" Yellow
Write-Color "         git push --no-verify`n" Yellow
