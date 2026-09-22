# ==========================================================
# AmuleD v0.5.1 Portable Launcher (PowerShell Version)
# ==========================================================
# Version: 1.1.0
# Author:  Soror L.'.L.'.
# Updated: 2026-09-22
#
# Patchnote v1.1.0 (By Soror L.'.L.'.):
#   [+] FULL ISOLATION: all runtime and cache data stay inside AmuleD_v2.
#       - UV_CACHE_DIR, UV_PYTHON_INSTALL_DIR, PIP_CACHE_DIR
#       - PYTHONNOUSERSITE, PYTHONUSERBASE, PYTHONPYCACHEPREFIX
#       - AMULED_ROOT, AMULED_CONFIG, AMULED_DB, AMULED_LOGS
#   [+] Added local uv.exe to PATH when present in bin\.
#   [+] Uses only AmuleD_v2\.venv\Scripts\python.exe.
#   [*] No system Python is selected, activated, repaired, or modified.
#   [*] Fully portable: can be moved to any drive or folder.
#
# Patchnote v1.0.0 (By Soror L.'.L.'.):
#   [+] Initial AmuleD_v2 launcher release.
# ==========================================================

param(
    [switch]$NoPause,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ClientArgs
)

# Set UTF-8 encoding and working directory
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "AmuleD v0.5.1 Portable Launcher by Soror L.'.L.'."
Set-Location $PSScriptRoot

# ==========================================================
# ASCII Art
# ==========================================================
Write-Host " ======================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "   ██▓        ██▓    ██▓        ██▓" -ForegroundColor Yellow
Write-Host "  ▓██▒              ▓██▒" -ForegroundColor Yellow
Write-Host "  ▒██░              ▒██░" -ForegroundColor Yellow
Write-Host "  ▒██░              ▒██░" -ForegroundColor Yellow
Write-Host "  ░██████▒ ██▓  ██▓ ░██████▒ ██▓  ██▓" -ForegroundColor Yellow
Write-Host "  ░ ▒░▓  ░ ▒▓▒  ▒▓▒ ░ ▒░▓  ░ ▒▓▒  ▒▓▒" -ForegroundColor Yellow
Write-Host "  ░ ░ ▒  ░ ░▒   ░▒  ░ ░ ▒  ░ ░▒   ░▒" -ForegroundColor Yellow
Write-Host "    ░ ░    ░    ░     ░ ░    ░    ░" -ForegroundColor Yellow
Write-Host "      ░  ░  ░    ░      ░  ░  ░    ░" -ForegroundColor Yellow
Write-Host ""
Write-Host " ======================================================" -ForegroundColor Cyan
Write-Host "   AmuleD v0.5.1 Portable ED2K/Kademlia Launcher" -ForegroundColor White
Write-Host "   by Soror L.'.L.'." -ForegroundColor Yellow
Write-Host ""

# ==========================================================
# Path configuration
# ==========================================================
$ProjectRoot = $PSScriptRoot
if (-not $ProjectRoot) { $ProjectRoot = "." }
Set-Location $ProjectRoot

$BinDir       = Join-Path $ProjectRoot "bin"
$CacheDir     = Join-Path $ProjectRoot ".cache"
$TempCacheDir = Join-Path $CacheDir "tmp"
$PycacheDir   = Join-Path $CacheDir "pycache"
$UvCacheDir   = Join-Path $CacheDir "uv"
$PipCacheDir  = Join-Path $CacheDir "pip"
$UvPythonDir  = Join-Path $BinDir "uv-python"
$PythonUserDir= Join-Path $BinDir "python-userbase"

$VenvPath     = Join-Path $ProjectRoot ".venv"
$VenvPython   = Join-Path $VenvPath "Scripts\python.exe"
$LocalUv      = Join-Path $BinDir "uv.exe"
$SrcDir       = Join-Path $ProjectRoot "src"
$ConfigDir    = Join-Path $ProjectRoot "config"
$ConfigFile   = Join-Path $ConfigDir "amuled.jsonc"
$DbDir        = Join-Path $ProjectRoot "db"
$DbFile       = Join-Path $DbDir "amuled.db"
$LogsDir      = Join-Path $ProjectRoot "logs"

# ==========================================================
# Local tool PATH
# ==========================================================
if (Test-Path $LocalUv) {
    $env:PATH = "$BinDir;$env:PATH"
    Write-Host "[RUNNER] [INFO] Local uv found in bin and added to PATH." -ForegroundColor Green
} else {
    Write-Host "[RUNNER] [WARN] Local uv not found in bin. Runtime can start, but reinstall/update flows may fail." -ForegroundColor Yellow
}

# ==========================================================
# PORTABILITY ISOLATION BLOCK
# ==========================================================
@($CacheDir, $TempCacheDir, $PycacheDir, $UvCacheDir, $PipCacheDir, $UvPythonDir, $PythonUserDir) |
    ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Force -Path $_ | Out-Null
        }
    }

$env:SCRIPT_DIR             = $ProjectRoot
$env:AMULED_ROOT            = $ProjectRoot
$env:AMULED_CONFIG          = $ConfigFile
$env:AMULED_DB              = $DbFile
$env:AMULED_LOGS            = $LogsDir
$env:AMULED_VENV_PYTHON     = $VenvPython
$env:AMULED_UV_EXE          = $LocalUv
$env:PYTHONUNBUFFERED       = "1"
$env:PYTHONNOUSERSITE       = "1"
$env:PYTHONUSERBASE         = $PythonUserDir
$env:PYTHONPYCACHEPREFIX    = $PycacheDir
$env:TEMP                   = $TempCacheDir
$env:TMP                    = $TempCacheDir
$env:XDG_CACHE_HOME         = $CacheDir
$env:UV_CACHE_DIR           = $UvCacheDir
$env:UV_PYTHON_INSTALL_DIR  = $UvPythonDir
$env:UV_MANAGED_PYTHON      = "true"
$env:UV_PROJECT_ENVIRONMENT = $VenvPath
$env:PIP_CACHE_DIR          = $PipCacheDir
Remove-Item Env:UV_NO_MANAGED_PYTHON -ErrorAction SilentlyContinue

# ==========================================================
# Pre-flight validation
# ==========================================================
if (-not (Test-Path $VenvPython)) {
    Write-Host "[RUNNER] [ERROR] Project Python not found: $VenvPython" -ForegroundColor Red
    Write-Host "[RUNNER] [ERROR] Run .\AmuleD_install.ps1 first. Never use a system Python." -ForegroundColor Red
    if (-not $NoPause) {
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    exit 1
}

if (-not (Test-Path $ConfigFile)) {
    Write-Host "[RUNNER] [ERROR] Config not found: $ConfigFile" -ForegroundColor Red
    Write-Host "[RUNNER] [ERROR] Run .\AmuleD_install.ps1 first." -ForegroundColor Red
    if (-not $NoPause) {
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    exit 1
}

$pyVersion = (& $VenvPython --version 2>$null).Trim()
if ($pyVersion -notmatch "3\.12") {
    Write-Host "[RUNNER] [ERROR] Unexpected Python version: $pyVersion" -ForegroundColor Red
    Write-Host "[RUNNER] [ERROR] Expected Python 3.12 from AmuleD_v2\.venv only." -ForegroundColor Red
    if (-not $NoPause) {
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    exit 1
}

Write-Host "[RUNNER] [INFO] Python : $pyVersion" -ForegroundColor Cyan
Write-Host "[RUNNER] [INFO] Path   : $VenvPython" -ForegroundColor Cyan
Write-Host "[RUNNER] [INFO] Root   : $ProjectRoot" -ForegroundColor Cyan

# ==========================================================
# Argument preparation
# ==========================================================
if (-not $ClientArgs -or $ClientArgs.Count -eq 0) {
    $ForwardedArgs = @("--help")
} else {
    $ForwardedArgs = $ClientArgs
}

# ==========================================================
# Environment activation and AmuleD_v2 launch
# ==========================================================
# The source tree is placed first on PYTHONPATH so the portable launcher works
# both before and after editable installation without importing another copy.
$env:PYTHONPATH = "$SrcDir"

try {
    & $VenvPython -s -W ignore::FutureWarning -m amuled_v2 @ForwardedArgs
    $exitCode = $LASTEXITCODE
} catch {
    Write-Host "[RUNNER] [ERROR] Launcher exception: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}

if ($exitCode -ne 0) {
    Write-Host "[RUNNER] [ERROR] AmuleD_v2 exited with code $exitCode" -ForegroundColor Red
}

# ==========================================================
# Pause
# ==========================================================
if (-not $NoPause) {
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
exit $exitCode

