# ==========================================================
# AmuleD v0.5.1 KAD Spider Daemon Launcher (PowerShell)
# ==========================================================
# Version: 1.0.0
# Author:  Soror L.'.L.'.
# Updated: 2026-09-23
#
# Patchnote v1.0.0 (By Soror L.'.L.'.):
#   [+] Launches scripts\kad_spider.py on the project-local Python 3.12
#       runtime with full portable isolation (same env block as AmuleD_Run.ps1).
#   [+] Pre-flight guard: refuses to start a second spider while one is
#       already running (unless -Force is passed); reports the live daemon
#       PID and the last known status from db\kad_status.json.
#   [+] Live verbose mode is the default: the spider prints one status line
#       per maturation cycle so the network can be watched in the console.
#   [*] Fully portable: uses only AmuleD_v2\.venv\Scripts\python.exe.
# ==========================================================

param(
    [switch]$NoPause,
    [switch]$Force,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$DaemonArgs
)

# Set UTF-8 encoding and working directory
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "AmuleD v0.5.1 KAD Spider Daemon by Soror L.'.L.'."
Set-Location $PSScriptRoot

Write-Host " ======================================================" -ForegroundColor Cyan
Write-Host "   AmuleD v0.5.1 KAD Spider Daemon (network warmup)" -ForegroundColor White
Write-Host "   by Soror L.'.L'." -ForegroundColor Yellow
Write-Host " ======================================================" -ForegroundColor Cyan
Write-Host ""

# ==========================================================
# Path configuration (same layout as AmuleD_Run.ps1)
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
$StatusFile   = Join-Path $DbDir "kad_status.json"
$SpiderScript = Join-Path $ProjectRoot "scripts\kad_spider.py"

# ==========================================================
# Local tool PATH
# ==========================================================
if (Test-Path $LocalUv) {
    $env:PATH = "$BinDir;$env:PATH"
    Write-Host "[RUNNER] [INFO] Local uv found in bin and added to PATH." -ForegroundColor Green
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

if (-not (Test-Path $SpiderScript)) {
    Write-Host "[RUNNER] [ERROR] Spider script not found: $SpiderScript" -ForegroundColor Red
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
Write-Host "[RUNNER] [INFO] Script : $SpiderScript" -ForegroundColor Cyan
Write-Host "[RUNNER] [INFO] Root   : $ProjectRoot" -ForegroundColor Cyan

# ==========================================================
# Running-daemon guard
# ==========================================================
$ExistingDaemons = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -match '^python' -and
        $_.CommandLine -and
        $_.CommandLine -like '*kad_spider.py*'
    }

if ($ExistingDaemons) {
    foreach ($daemon in $ExistingDaemons) {
        Write-Host "[RUNNER] [WARN] KAD spider is already running: pid=$($daemon.ProcessId)" -ForegroundColor Yellow
    }
    if (Test-Path $StatusFile) {
        try {
            $status = Get-Content $StatusFile -Raw -Encoding UTF8 | ConvertFrom-Json
            Write-Host "[RUNNER] [INFO] Last status: cycles=$($status.cycles) pool=$($status.pool_size) alive=$($status.alive_estimate) port=$($status.bound_port) uptime_s=$($status.uptime_s)" -ForegroundColor Cyan
            Write-Host "[RUNNER] [INFO] Status file: $StatusFile" -ForegroundColor Cyan
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

# ==========================================================
# Argument preparation (defaults to live verbose mode)
# ==========================================================
if (-not $DaemonArgs -or $DaemonArgs.Count -eq 0) {
    $ForwardedArgs = @("--verbose")
} else {
    $ForwardedArgs = $DaemonArgs
}

# ==========================================================
# Launch the spider daemon in this console
# ==========================================================
# The source tree is placed first on PYTHONPATH so the daemon imports the
# same amuled_v2 package the CLI uses.
$env:PYTHONPATH = "$SrcDir"

Write-Host "[RUNNER] [INFO] Starting KAD spider (Ctrl+C to stop; it saves state on exit)..." -ForegroundColor Green
try {
    & $VenvPython -s -W ignore::FutureWarning $SpiderScript @ForwardedArgs
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

# ==========================================================
# Pause
# ==========================================================
if (-not $NoPause) {
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
exit $exitCode
