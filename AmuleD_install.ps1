# ==========================================
# SYNOPSIS
#     AmuleD v0.4.1 Portable Installer
#     Portable Python 3.12 + uv environment for the pure ED2K/Kademlia client.
#     Fully isolated: uv, Python interpreters, caches, packages, config, and
#     runtime state stay inside AmuleD_v2.
# ==========================================
#
# DESCRIPTION
#     This script prepares a self-contained AmuleD_v2 runtime:
#       - Downloads or refreshes a local uv.exe inside AmuleD_v2\bin.
#       - Pins uv-managed Python 3.12 inside AmuleD_v2\bin\uv-python.
#       - Pins uv cache, package cache, temp files, and Python bytecode inside
#         AmuleD_v2\.cache or AmuleD_v2\bin.
#       - Creates the portable runtime tree: config, db, logs, tmp, incoming,
#         temp, shared.
#       - Creates config\amuled.jsonc only if missing.
#       - Installs requirements.txt into .venv using only the project-local
#         Python executable.
#       - Verifies critical imports and writes logs\install.log.
#
#     The installer never selects, repairs, upgrades, or mutates any system
#     Python. The only interpreter used by the project is:
#       AmuleD_v2\.venv\Scripts\python.exe
#
# ==========================================
# VERSION
#     0.3.1
# ==========================================
# AUTHOR
#     Soror L.'.L.'.
# ==========================================
# UPDATED
#     2026-09-22
# ==========================================
#
# CHANGELOG
#
# v0.3.1 (2026-09-22 by Soror L.'.L'.)
#   [+] Added project-local baseline resources under assets\v1.
#   [*] Repointed nodes, servers, IP filters, shared metadata, and GeoIP to the
#       bundled project assets so a GitHub checkout is self-contained.
#   [*] Removed the donor cryptkey path from the default template.
#   [+] Added tagged JSONL diagnostics to the default logging configuration.

# v0.3.0 (2026-09-22 by Soror L.'.L'.)
#   [+] Full Trellis2-style portable isolation block: local uv, local managed
#       Python, local package/cache/temp paths, and project-only execution.
#   [+] Downloads uv into bin\ when a local copy is missing.
#   [+] Uses --managed-python so no system Python can be selected.
#   [+] Adds PyCryptodome MD4 runtime dependency.
#   [*] Aligns installer and runtime DB path to db\amuled.db.
#
# v0.2.1 (2026-09-22 by Soror L.'.L'.)
#   [+] Initial uv-managed Python and cache pinning inside AmuleD_v2\bin.
#
# v0.2.0 (2026-09-22 by Soror L.'.L'.)
#   [*] Restored the authored ASCII welcome/menu style.
#
# v0.1.0 (2026-09-22 by Soror L.'.L'.)
#   [+] Initial AmuleD_v2 portable installer skeleton.
#
# ==========================================
# USAGE
#     Run from AmuleD_v2:
#         .\AmuleD_install.ps1
#
# NOTES
#     - Internet is required on first run to download uv/Python/packages.
#     - Re-runs are idempotent and preserve config\amuled.jsonc.
#     - Agents and developers must use .venv\Scripts\python.exe only.
# ==========================================

# === Encoding ===
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# ==========================================
# AUTHORED WELCOME / MENU
# ==========================================
Write-Host " ===========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  ██▓        ██▓    ██▓        ██▓" -ForegroundColor Yellow
Write-Host " ▓██▒              ▓██▒" -ForegroundColor Yellow
Write-Host " ▒██░              ▒██░" -ForegroundColor Yellow
Write-Host " ▒██░              ▒██░" -ForegroundColor Yellow
Write-Host " ░██████▒ ██▓  ██▓ ░██████▒ ██▓  ██▓" -ForegroundColor Yellow
Write-Host " ░ ▒░▓  ░ ▒▓▒  ▒▓▒ ░ ▒░▓  ░ ▒▓▒  ▒▓▒" -ForegroundColor Yellow
Write-Host " ░ ░ ▒  ░ ░▒   ░▒  ░ ░ ▒  ░ ░▒   ░▒" -ForegroundColor Yellow
Write-Host "   ░ ░    ░    ░     ░ ░    ░    ░" -ForegroundColor Yellow
Write-Host "     ░  ░  ░    ░      ░  ░  ░    ░" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ===========================================" -ForegroundColor Green
Write-Host "    AmuleD_v2 by Soror L.'.L.'." -ForegroundColor Yellow
Write-Host "    AmuleD v0.4.1 Portable Installer" -ForegroundColor Green
Write-Host "    Python 3.12 Portable Runtime" -ForegroundColor Cyan
Write-Host ""

# === Execution Policy ===
Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

# === Path & Init ===
$ProjectRoot = $PSScriptRoot
if (-not $ProjectRoot) { $ProjectRoot = "." }
Set-Location $ProjectRoot

# ==========================================
# === PORTABILITY ISOLATION BLOCK ===
# ==========================================
# Set every runtime path before invoking uv or Python.

$BinDir        = Join-Path $ProjectRoot "bin"
$CacheDir      = Join-Path $ProjectRoot ".cache"
$UvCacheDir    = Join-Path $CacheDir "uv"
$UvPythonDir   = Join-Path $BinDir "uv-python"
$UvToolsDir    = Join-Path $BinDir "uv-tools"
$UvToolBinDir  = Join-Path $BinDir "uv-tool-bin"
$PipCacheDir   = Join-Path $CacheDir "pip"
$PycacheDir    = Join-Path $CacheDir "pycache"
$TempCacheDir  = Join-Path $CacheDir "tmp"
$PythonUserDir = Join-Path $BinDir "python-userbase"
$VenvPath      = Join-Path $ProjectRoot ".venv"
$VenvPython    = Join-Path $VenvPath "Scripts\python.exe"
$UvExePath     = Join-Path $BinDir "uv.exe"

$ConfigDir     = Join-Path $ProjectRoot "config"
$DbDir         = Join-Path $ProjectRoot "db"
$LogsDir       = Join-Path $ProjectRoot "logs"
$TmpDir        = Join-Path $ProjectRoot "tmp"
$IncomingDir   = Join-Path $ProjectRoot "incoming"
$TempDir       = Join-Path $ProjectRoot "temp"
$SharedDir     = Join-Path $ProjectRoot "shared"
$ReqFile       = Join-Path $ProjectRoot "requirements.txt"
$ConfigFile    = Join-Path $ConfigDir "amuled.jsonc"
$LogFile       = Join-Path $LogsDir "install.log"
$PythonVersion = "3.12"

@(
    $BinDir, $CacheDir, $UvCacheDir, $UvPythonDir, $UvToolsDir, $UvToolBinDir,
    $PipCacheDir, $PycacheDir, $TempCacheDir, $PythonUserDir,
    $ConfigDir, $DbDir, $LogsDir, $TmpDir, $IncomingDir, $TempDir, $SharedDir
) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Force -Path $_ | Out-Null
    }
}

$env:AMULED_ROOT            = $ProjectRoot
$env:AMULED_CONFIG          = $ConfigFile
$env:AMULED_DB              = Join-Path $DbDir "amuled.db"
$env:AMULED_LOGS            = $LogsDir
$env:AMULED_VENV_PYTHON     = $VenvPython
$env:AMULED_UV_EXE          = $UvExePath
$env:PYTHONUNBUFFERED       = "1"
$env:PYTHONNOUSERSITE       = "1"
$env:PYTHONUSERBASE         = $PythonUserDir
$env:PYTHONPYCACHEPREFIX    = $PycacheDir
$env:TEMP                   = $TempCacheDir
$env:TMP                    = $TempCacheDir
$env:XDG_CACHE_HOME         = $CacheDir
$env:UV_CACHE_DIR           = $UvCacheDir
$env:UV_PYTHON_INSTALL_DIR  = $UvPythonDir
$env:UV_TOOL_DIR            = $UvToolsDir
$env:UV_TOOL_BIN_DIR        = $UvToolBinDir
$env:UV_MANAGED_PYTHON      = "true"
$env:UV_PROJECT_ENVIRONMENT = $VenvPath
$env:PIP_CACHE_DIR          = $PipCacheDir
Remove-Item Env:UV_NO_MANAGED_PYTHON -ErrorAction SilentlyContinue

# === Local uv Bootstrap ===
$UvVersion  = "0.9.14"
$UvArch     = "x86_64-pc-windows-msvc"
$UvZipUrl   = "https://releases.astral.sh/github/uv/releases/download/$UvVersion/uv-$UvArch.zip"
$UvZipPath  = Join-Path $UvCacheDir "uv-$UvVersion-$UvArch.zip"

# === Runtime Directories ===
$RuntimeDirs = @(
    $BinDir, $CacheDir, $UvCacheDir, $UvPythonDir, $UvToolsDir, $UvToolBinDir,
    $PipCacheDir, $PycacheDir, $TempCacheDir, $PythonUserDir,
    $ConfigDir, $DbDir, $LogsDir, $TmpDir, $IncomingDir, $TempDir, $SharedDir
)

# === Logging ===
function Write-Status {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [INSTALL] [$Level] $Message"
    $color = switch ($Level) {
        "ERROR"   { "Red" }
        "WARN"    { "Yellow" }
        "SUCCESS" { "Green" }
        "CYAN"    { "Cyan" }
        default   { "White" }
    }
    Write-Host "[$timestamp] [INSTALL] [$Level] $Message" -ForegroundColor $color
    if (Test-Path $LogsDir) {
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    }
}

function Write-Step {
    param([string]$Message, [int]$Step, [int]$Total)
    Write-Host ""
    Write-Host ">>> Stage [$Step/$Total]: $Message" -ForegroundColor Magenta
}

function Test-Command {
    param([string]$Cmd)
    return $null -ne (Get-Command $Cmd -ErrorAction SilentlyContinue)
}

function Invoke-Uv {
    param([string[]]$ArgumentList)
    Write-Host "   > uv $($ArgumentList -join ' ')" -ForegroundColor DarkGray
    & $UvExePath @ArgumentList
    return $LASTEXITCODE
}

function Invoke-VenvPython {
    param([string[]]$ArgumentList)
    Write-Host "   > .venv python $($ArgumentList -join ' ')" -ForegroundColor DarkGray
    & $VenvPython @ArgumentList
    return $LASTEXITCODE
}

function Get-LocalUv {
    if (Test-Path $UvExePath) {
        Write-Status "Local uv found: $UvExePath" "SUCCESS"
        return
    }

    Write-Status "Local uv not found; downloading uv $UvVersion..." "INFO"
    try {
        Invoke-WebRequest -Uri $UvZipUrl -OutFile $UvZipPath -UseBasicParsing
        $extractDir = Join-Path $UvCacheDir "uv-$UvVersion-$UvArch"
        if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
        Expand-Archive -Path $UvZipPath -DestinationPath $extractDir -Force
        $downloadedUv = Join-Path $extractDir "uv.exe"
        if (-not (Test-Path $downloadedUv)) {
            throw "uv.exe not found inside $UvZipPath"
        }
        Copy-Item -Path $downloadedUv -Destination $UvExePath -Force
        Write-Status "Local uv installed: $UvExePath" "SUCCESS"
    } catch {
        Write-Status "ERROR: Failed to prepare local uv: $($_.Exception.Message)" "ERROR"
        Write-Status "Install uv manually or restore network access, then re-run." "ERROR"
        exit 1
    }
}

function Get-DefaultConfig {
    return @'
// AmuleD_v2 Configuration (JSONC)
// Version: 0.4.1
// Updated: 2026-09-22

{
  // Core daemon settings
  "daemon": {
    "pid_file": "db/amuled.pid",
    "log_level": "INFO"
  },

  // Diagnostics logging
  "logging": {
    "level": "INFO",
    "file": "logs/amuled.jsonl"
  },

  // Network configuration
  "network": {
    "ed2k_tcp_port": 8089,
    "ed2k_udp_port": 8089,
    "kad_udp_port": 8089,
    "bind_address": "0.0.0.0",
    "max_connections": 200,
    "max_sources_per_file": 500,
    "connection_timeout": 30,
    "socket_buffer_size": 65536
  },

  // Kademlia bootstrap
  "kademlia": {
    "nodes_dat": "assets/v1/nodes.dat",
    "bootstrap_nodes": [],
    "max_bucket_size": 20,
    "ping_timeout": 10,
    "publish_interval": 300
  },

  // ED2K server list
  "servers": {
    "server_met": "assets/v1/server.met",
    "static_servers": "assets/v1/staticservers.dat",
    "auto_update_server_met": false
  },

  // Sharing configuration
  "sharing": {
    "shared_dirs": [],
    "shared_files_json": "assets/v1/shared_files.json",
    "shareddir_dat": "assets/v1/shareddir.dat",
    "incoming_dir": "incoming",
    "temp_dir": "temp",
    "max_upload_slots": 3,
    "upload_queue_size": 50,
    "upload_speed_limit": 0,
    "download_speed_limit": 0
  },

  // File paths
  "paths": {
    "config_dir": "config",
    "db_dir": "db",
    "logs_dir": "logs",
    "tmp_dir": "tmp",
    "incoming_dir": "incoming",
    "temp_dir": "temp",
    "shared_dir": "shared",
    "db_file": "db/amuled.db"
  },

  // IP filter
  "ipfilter": {
    "ipfilter_dat": "assets/v1/ipfilter.dat",
    "ipfilter_static_dat": "assets/v1/ipfilter_static.dat",
    "auto_update": false
  },

  // Security
  "security": {
    "enable_obfuscation": true,
    "enable_secure_ident": false,
    "cryptkey_file": null
  },

  // Search
  "search": {
    "default_search_type": "kad",
    "max_results": 500,
    "result_ttl": 300
  },

  // Download
  "download": {
    "chunk_size": 9728000,
    "block_size": 184320,
    "disk_space_reserve_mb": 100,
    "auto_retry_failed": true,
    "max_retries": 3
  },

  // NAT / UPnP
  "nat": {
    "enable_upnp": true,
    "enable_natpmp": true,
    "external_port_override": null
  },

  // GeoIP
  "geoip": {
    "geoip_dat": "assets/v1/GeoIP.dat",
    "enabled": false
  }
}
'@
}

# === Main Install Process ===
Write-Step "Preparing portable installer" 0 6
Write-Status "Project root : $ProjectRoot" "CYAN"
Write-Status "Python target: $PythonVersion (uv-managed, project-local)" "CYAN"
Write-Status "Runtime root : $VenvPath" "CYAN"
Write-Status "Local uv     : $UvExePath" "CYAN"

# Stage 1: local uv
Write-Step "Resolving project-local uv" 1 6
Get-LocalUv
$uvVersion = (& $UvExePath --version 2>$null).Trim()
Write-Status "uv version: $uvVersion" "SUCCESS"

# Stage 2: runtime directories
Write-Step "Creating portable runtime directories" 2 6
foreach ($dir in $RuntimeDirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Status "  Created: $dir" "INFO"
    }
}
Write-Status "All runtime directories are ready" "SUCCESS"

# Stage 3: config
Write-Step "Creating default JSONC configuration" 3 6
if (-not (Test-Path $ConfigFile)) {
    $defaultConfig = Get-DefaultConfig
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($ConfigFile, $defaultConfig, $utf8NoBom)
    Write-Status "Created default config: $ConfigFile" "SUCCESS"
} else {
    Write-Status "Config already exists, leaving untouched: $ConfigFile" "INFO"
}

# Stage 4: project-local Python 3.12 venv
Write-Step "Creating project-local Python $PythonVersion environment" 4 6
if (-not (Test-Path $VenvPython)) {
    $venvArgs = @(
        "venv", $VenvPath,
        "--python", $PythonVersion,
        "--managed-python",
        "--no-config"
    )
    $venvExit = Invoke-Uv -ArgumentList $venvArgs
    if ($venvExit -ne 0) {
        Write-Status "ERROR: uv venv failed with exit code $venvExit" "ERROR"
        exit 1
    }
    Write-Status "Created .venv at $VenvPath" "SUCCESS"
} else {
    Write-Status ".venv already exists, skipping creation" "INFO"
}

$pyVersion = (& $VenvPython --version 2>$null).Trim()
Write-Status "Project Python: $pyVersion" "CYAN"
Write-Status "Python path   : $VenvPython" "CYAN"
if ($pyVersion -notmatch "3\.12") {
    Write-Status "ERROR: Project venv is not Python 3.12: $pyVersion" "ERROR"
    Write-Status "Remove $VenvPath and re-run installer." "ERROR"
    exit 1
}

# Stage 5: dependencies
Write-Step "Installing project dependencies" 5 6
if (-not (Test-Path $ReqFile)) {
    Write-Status "ERROR: requirements.txt not found: $ReqFile" "ERROR"
    exit 1
}
$pipArgs = @(
    "pip", "install",
    "--python", $VenvPython,
    "--requirements", $ReqFile,
    "--no-config"
)
$pipExit = Invoke-Uv -ArgumentList $pipArgs
if ($pipExit -ne 0) {
    Write-Status "ERROR: uv pip install failed with exit code $pipExit" "ERROR"
    exit 1
}
Write-Status "Dependencies installed successfully" "SUCCESS"

# Stage 6: verification
Write-Step "Verifying portable runtime imports" 6 6
$CriticalModules = @(
    "duckdb",
    "aiohttp",
    "cryptography",
    "Crypto.Hash.MD4",
    "prompt_toolkit",
    "rich",
    "json5"
)
$AllImportsOK = $true
foreach ($mod in $CriticalModules) {
    $checkExit = Invoke-VenvPython -ArgumentList @("-c", "import $mod")
    if ($checkExit -eq 0) {
        Write-Status "[+] $mod" "SUCCESS"
    } else {
        Write-Status "[!] $mod NOT FOUND" "ERROR"
        $AllImportsOK = $false
    }
}

# Optional convenience shim for interactive use.
$PythonShim = Join-Path $BinDir "amuled-python.cmd"
$shimText = "@echo off`r`n`"$(($VenvPython).Replace('/','\'))`" %*`r`n"
[System.IO.File]::WriteAllText($PythonShim, $shimText, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
if ($AllImportsOK) {
    Write-Status "========== Installation Complete ==========" "SUCCESS"
    Write-Status "Config : $ConfigFile" "INFO"
    Write-Status "Venv   : $VenvPath" "INFO"
    Write-Status "Python : $VenvPython" "INFO"
    Write-Status "Shim   : $PythonShim" "INFO"
    Write-Status "Log    : $LogFile" "INFO"
    Write-Status "Next   : Run .\AmuleD_Run.ps1" "INFO"
    exit 0
} else {
    Write-Status "========== Installation Completed with Warnings ==========" "WARN"
    exit 2
}
