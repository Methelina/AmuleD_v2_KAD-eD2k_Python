"""Project root and portable runtime directory discovery.

Resolves the project root from the ``AMULED_ROOT`` environment variable or,
falling back, from the package location two levels up (``src/amuled_v2`` ->
project root).  Provides canonical path constants for every portable runtime
directory and an :func:`ensure_runtime_dirs` helper that creates them on
demand.

src/amuled_v2/paths.py
Version:     0.3.1
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.3.1 (Soror L.'.L'.):
  [+] Added bundled baseline asset paths so GitHub checkouts work without any
      external donor configuration directory.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Project-root discovery via AMULED_ROOT env or package __file__.
  [+] Path constants for config/db/logs/tmp/incoming/temp/shared.
  [+] ensure_runtime_dirs() creates all portable directories.
"""

from __future__ import annotations

import os
from pathlib import Path

# ------------------------------------------------------------------
# Project root discovery
# ------------------------------------------------------------------

def _discover_project_root() -> Path:
    """Return the project root directory.

    Priority:
      1. ``AMULED_ROOT`` environment variable (resolved to absolute path).
      2. Two parents above this package file (``src/amuled_v2`` -> root).
    """
    env_root = os.environ.get("AMULED_ROOT")
    if env_root:
        return Path(env_root).resolve()
    return Path(__file__).resolve().parents[2]


PROJECT_ROOT: Path = _discover_project_root()

# ------------------------------------------------------------------
# Portable runtime directories
# ------------------------------------------------------------------

CONFIG_DIR: Path = PROJECT_ROOT / "config"
DB_DIR: Path = PROJECT_ROOT / "db"
LOGS_DIR: Path = PROJECT_ROOT / "logs"
TMP_DIR: Path = PROJECT_ROOT / "tmp"
INCOMING_DIR: Path = PROJECT_ROOT / "incoming"
TEMP_DIR: Path = PROJECT_ROOT / "temp"
SHARED_DIR: Path = PROJECT_ROOT / "shared"
ASSETS_DIR: Path = PROJECT_ROOT / "assets"
BASELINE_ASSETS_DIR: Path = ASSETS_DIR / "v1"

# ------------------------------------------------------------------
# Runtime files
# ------------------------------------------------------------------

CONFIG_FILE: Path = CONFIG_DIR / "amuled.jsonc"
DB_FILE: Path = DB_DIR / "amuled.db"
STATE_JSON: Path = DB_DIR / "state.json"
LOG_FILE: Path = LOGS_DIR / "amuled.log"
BASELINE_SERVER_MET: Path = BASELINE_ASSETS_DIR / "server.met"
BASELINE_NODES_DAT: Path = BASELINE_ASSETS_DIR / "nodes.dat"
BASELINE_STATIC_SERVERS: Path = BASELINE_ASSETS_DIR / "staticservers.dat"
BASELINE_IPFILTER: Path = BASELINE_ASSETS_DIR / "ipfilter.dat"
BASELINE_IPFILTER_STATIC: Path = BASELINE_ASSETS_DIR / "ipfilter_static.dat"
BASELINE_SHARED_FILES_JSON: Path = BASELINE_ASSETS_DIR / "shared_files.json"
BASELINE_SHAREDDIR_DAT: Path = BASELINE_ASSETS_DIR / "shareddir.dat"
BASELINE_GEOIP_DAT: Path = BASELINE_ASSETS_DIR / "GeoIP.dat"

# ------------------------------------------------------------------
# Directory helpers
# ------------------------------------------------------------------

def ensure_runtime_dirs() -> list[Path]:
    """Create every portable runtime directory that does not yet exist.

    Returns the list of directories that were created.
    """
    dirs = [
        CONFIG_DIR,
        DB_DIR,
        LOGS_DIR,
        TMP_DIR,
        INCOMING_DIR,
        TEMP_DIR,
        SHARED_DIR,
    ]
    created: list[Path] = []
    for d in dirs:
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True)
            created.append(d)
    return created
