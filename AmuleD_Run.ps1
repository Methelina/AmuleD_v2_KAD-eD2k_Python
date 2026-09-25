# ==========================================================
# AmuleD v0.6.0 Portable Runtime (PowerShell Version)
# ==========================================================
# Version: 2.1.1
# Author:  Soror L.'.L.'.
# Updated: 2026-09-25
#
# Patchnote v2.1.1 (By Soror L.'.L.'.):
#   [!] `spider` mode marked DEPRECATED: the unified kernel (`serve`) includes
#       the spider; a warning is printed before the legacy script starts.
#
# Patchnote v2.1.0 (By Soror L.'.L.'.):
#   [+] Added `serve` mode: incoming peer serve daemon (scripts\serve_daemon.py),
#       refuses a second instance unless -Force.  The daemon binds an
#       (optionally ephemeral) TCP port, writes db\serve_status.json and
#       periodically republishes KAD source entries advertising the bound
#       port (stage S).
#
# Patchnote v2.0.0 (By Soror L.'.L.'.):
#   [+] PROJECT DOCTRINE: exactly two launchers exist -- the installer
#       (AmuleD_install.ps1) and this single runtime.  Everything runs from
#       under it:
#         .\AmuleD_Run.ps1            -> interactive menu (scripts\amuled_menu.py)
#         .\AmuleD_Run.ps1 spider     -> KAD spider daemon (scripts\kad_spider.py),
#                                        refuses a second instance unless -Force
#         .\AmuleD_Run.ps1 <cli args> -> CLI passthrough (python -m amuled_v2 ...)
#   [*] AmuleD_Menu.ps1 and AmuleD_Demon_KAD-Spider.ps1 removed per doctrine.
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
    [switch]$Force,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ClientArgs
)

# Set UTF-8 encoding and working directory
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "AmuleD v0.6.0 Portable Runtime by Soror L.'.L.'."
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
Write-Host "   AmuleD v0.6.0 Portable ED2K/Kademlia Launcher" -ForegroundColor White
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
# Mode dispatch (single-runtime doctrine)
# ==========================================================
$MenuScript   = Join-Path $ProjectRoot "scripts\amuled_menu.py"
$SpiderScript = Join-Path $ProjectRoot "scripts\kad_spider.py"
$StatusFile   = Join-Path $DbDir "kad_status.json"

$Mode = "cli"
if (-not $ClientArgs -or $ClientArgs.Count -eq 0) {
    $Mode = "menu"
} elseif ($ClientArgs[0] -eq "menu") {
    $Mode = "menu"
    $ClientArgs = @($ClientArgs | Select-Object -Skip 1)
} elseif ($ClientArgs[0] -eq "spider") {
    $Mode = "spider"
    $ClientArgs = @($ClientArgs | Select-Object -Skip 1)
} elseif ($ClientArgs[0] -eq "serve") {
    $Mode = "serve"
    $ClientArgs = @($ClientArgs | Select-Object -Skip 1)
}

# The source tree is placed first on PYTHONPATH so the portable runtime works
# both before and after editable installation without importing another copy.
$env:PYTHONPATH = "$SrcDir"

if ($Mode -eq "menu") {
    if (-not (Test-Path $MenuScript)) {
        Write-Host "[RUNNER] [ERROR] Menu script not found: $MenuScript" -ForegroundColor Red
        if (-not $NoPause) {
            Write-Host "Press any key to exit..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        exit 1
    }
    Write-Host "[RUNNER] [INFO] Starting interactive menu (Ctrl+C to exit)..." -ForegroundColor Green
    try {
        & $VenvPython -s -W ignore::FutureWarning $MenuScript @ClientArgs
        $exitCode = $LASTEXITCODE
    } catch {
        Write-Host "[RUNNER] [ERROR] Menu launcher exception: $($_.Exception.Message)" -ForegroundColor Red
        $exitCode = 1
    }
    if (-not $NoPause) {
        Write-Host ""
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    exit $exitCode
}

if ($Mode -eq "spider") {
    Write-Host "[RUNNER] [WARN] DEPRECATED: the standalone spider mode is obsolete (stage U)." -ForegroundColor Yellow
    Write-Host "[RUNNER] [WARN] Use '.\AmuleD_Run.ps1 serve' — the unified kernel includes the spider." -ForegroundColor Yellow
    if (-not (Test-Path $SpiderScript)) {
        Write-Host "[RUNNER] [ERROR] Spider script not found: $SpiderScript" -ForegroundColor Red
        if (-not $NoPause) {
            Write-Host "Press any key to exit..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        exit 1
    }
    $ExistingDaemons = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '^python' -and
            $_.CommandLine -and
            $_.CommandLine -like '*kad_spider.py*'
        }
    # The venv python.exe is a shim that spawns the real uv-managed
    # interpreter: one logical daemon shows up as a parent/child pair.
    # Keep only top-level processes (parent is not itself a match).
    if ($ExistingDaemons) {
        $matchedIds = $ExistingDaemons | ForEach-Object { $_.ProcessId }
        $ExistingDaemons = $ExistingDaemons | Where-Object { $matchedIds -notcontains $_.ParentProcessId }
    }
    if ($ExistingDaemons) {
        foreach ($daemon in $ExistingDaemons) {
            Write-Host "[RUNNER] [WARN] KAD spider is already running: pid=$($daemon.ProcessId)" -ForegroundColor Yellow
        }
        if (Test-Path $StatusFile) {
            try {
                $status = Get-Content $StatusFile -Raw -Encoding UTF8 | ConvertFrom-Json
                Write-Host "[RUNNER] [INFO] Last status: cycles=$($status.cycles) pool=$($status.pool_size) alive=$($status.alive_estimate) port=$($status.bound_port) uptime_s=$($status.uptime_s)" -ForegroundColor Cyan
            } catch {
                Write-Host "[RUNNER] [WARN] Status file unreadable: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        if (-not $Force) {
            Write-Host "[RUNNER] [ERROR] Refusing to start a second spider. Stop the running one or re-run with -Force." -ForegroundColor Red
            if (-not $NoPause) {
                Write-Host "Press any key to exit..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            exit 1
        }
        Write-Host "[RUNNER] [WARN] -Force passed: starting a second spider anyway (port fallback may engage)." -ForegroundColor Yellow
    }
    if (-not $ClientArgs -or $ClientArgs.Count -eq 0) {
        $ClientArgs = @("--verbose")
    }
    Write-Host "[RUNNER] [INFO] Starting KAD spider (Ctrl+C to stop; it saves state on exit)..." -ForegroundColor Green
    try {
        & $VenvPython -s -W ignore::FutureWarning $SpiderScript @ClientArgs
        $exitCode = $LASTEXITCODE
    } catch {
        Write-Host "[RUNNER] [ERROR] Spider launcher exception: $($_.Exception.Message)" -ForegroundColor Red
        $exitCode = 1
    }
    if ($exitCode -ne 0) {
        Write-Host "[RUNNER] [ERROR] KAD spider exited with code $exitCode" -ForegroundColor Red
    } else {
        Write-Host "[RUNNER] [INFO] KAD spider stopped cleanly." -ForegroundColor Green
    }
    if (-not $NoPause) {
        Write-Host ""
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    exit $exitCode
}

if ($Mode -eq "serve") {
    $ServeScript = Join-Path $ProjectRoot "scripts\serve_daemon.py"
    $ServeStatusFile = Join-Path $DbDir "serve_status.json"
    if (-not (Test-Path $ServeScript)) {
        Write-Host "[RUNNER] [ERROR] Serve daemon script not found: $ServeScript" -ForegroundColor Red
        if (-not $NoPause) {
            Write-Host "Press any key to exit..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        exit 1
    }
    $ExistingServe = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '^python' -and
            $_.CommandLine -and
            $_.CommandLine -like '*serve_daemon.py*'
        }
    # The venv python.exe is a shim that spawns the real uv-managed
    # interpreter: one logical daemon shows up as a parent/child pair.
    if ($ExistingServe) {
        $matchedIds = $ExistingServe | ForEach-Object { $_.ProcessId }
        $ExistingServe = $ExistingServe | Where-Object { $matchedIds -notcontains $_.ParentProcessId }
    }
    if ($ExistingServe) {
        foreach ($daemon in $ExistingServe) {
            Write-Host "[RUNNER] [WARN] Serve daemon is already running: pid=$($daemon.ProcessId)" -ForegroundColor Yellow
        }
        if (Test-Path $ServeStatusFile) {
            try {
                $status = Get-Content $ServeStatusFile -Raw -Encoding UTF8 | ConvertFrom-Json
                Write-Host "[RUNNER] [INFO] Last status: port=$($status.port) active=$($status.active_connections) uptime_s=$($status.uptime_s) running=$($status.running)" -ForegroundColor Cyan
            } catch {
                Write-Host "[RUNNER] [WARN] Status file unreadable: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        if (-not $Force) {
            Write-Host "[RUNNER] [ERROR] Refusing to start a second serve daemon. Stop the running one or re-run with -Force." -ForegroundColor Red
            if (-not $NoPause) {
                Write-Host "Press any key to exit..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            exit 1
        }
        Write-Host "[RUNNER] [WARN] -Force passed: starting a second serve daemon anyway." -ForegroundColor Yellow
    }
    Write-Host "[RUNNER] [INFO] Starting serve daemon (Ctrl+C to stop)..." -ForegroundColor Green
    try {
        & $VenvPython -s -W ignore::FutureWarning $ServeScript @ClientArgs
        $exitCode = $LASTEXITCODE
    } catch {
        Write-Host "[RUNNER] [ERROR] Serve launcher exception: $($_.Exception.Message)" -ForegroundColor Red
        $exitCode = 1
    }
    if ($exitCode -ne 0) {
        Write-Host "[RUNNER] [ERROR] Serve daemon exited with code $exitCode" -ForegroundColor Red
    } else {
        Write-Host "[RUNNER] [INFO] Serve daemon stopped cleanly." -ForegroundColor Green
    }
    if (-not $NoPause) {
        Write-Host ""
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    exit $exitCode
}

# ==========================================================
# CLI passthrough
# ==========================================================
if (-not $ClientArgs -or $ClientArgs.Count -eq 0) {
    $ForwardedArgs = @("--help")
} else {
    $ForwardedArgs = $ClientArgs
}

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

