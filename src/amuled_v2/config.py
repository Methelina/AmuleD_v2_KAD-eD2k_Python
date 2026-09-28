"""Configuration management for AmuleD_v2.

Provides a default configuration dictionary, a :func:`load_config` function
that creates ``config\\amuled.jsonc`` from defaults when missing and
normalizes null paths to portable runtime directories, and CLI helpers
:func:`config_show` and :func:`config_set` with dotted-key access and type
inference.

src/amuled_v2/config.py
Version:     0.4.4
Author:      Soror L.'.L.'.
Updated:     2026-09-28

Patch Notes v0.4.4 (Soror L.'.L.'.):
  [+] kademlia.reask_interval_s (300) - periodic KAD source re-ask and
      re-dial interval for the kernel's download queue (eMule ReAskTime
      analog, roadmap 11r P3 №9).

Patch Notes v0.4.3 (Soror L.'.L'.):
  [+] Config parity with eMuleAI preferences.ini (roadmap 11r,
      tmp/recon/emuleai-preferences-ini.recon.md): network.max_connections /
      max_half_connections / max_conn_per_5s, network.max_download_bytes_per_sec,
      network.crypt_layer_required, download.max_sources_per_file,
      download.sparse_part_files, kademlia.udp_key (persisted KAD UDP verify
      key), ipfilter.level / auto_update / update_url / update_period_days.

Patch Notes v0.4.2 (Soror L.'.L'.):
  [+] Changed the public application name to `AmuleD`.

Patch Notes v0.3.2 (Soror L.'.L'.):
  [+] Added tagged CONFIG diagnostics for load, create, merge, and save events.
  [+] Added a default JSONL diagnostics file and portable log-path resolution.

Patch Notes v0.3.1 (Soror L.'.L'.):
  [*] Added recursive defaults merge so installer-generated configs remain
      compatible with runtime-only keys added in newer versions.
  [+] Added bundled baseline resource defaults so GitHub checkouts run without
      any external donor directory.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Default config dict with network, paths, storage, logging sections.
  [+] load_config() creates config from defaults if missing, normalizes null paths.
  [+] config_show() and config_set() with dotted-key access and type inference.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from amuled_v2.jsonc import dump_json, load_jsonc_file
from amuled_v2.logging_setup import LogTags, get_tagged_logger
from amuled_v2.paths import (
    CONFIG_FILE,
    INCOMING_DIR,
    LOGS_DIR,
    PROJECT_ROOT,
    SHARED_DIR,
    TEMP_DIR,
    ensure_runtime_dirs,
)

log = get_tagged_logger(LogTags.CONFIG, "config")

# ------------------------------------------------------------------
# Defaults
# ------------------------------------------------------------------

DEFAULT_CONFIG: dict[str, Any] = {
    "app": {
        "name": "AmuleD",
    },
    "network": {
        "client_tcp_port": 8089,
        "client_udp_port": 8089,
        "enable_ed2k": True,
        "enable_kad": True,
        # Physical-NIC egress for KAD/peer UDP (VPN TUN bypass); None = 0.0.0.0.
        "bind_ip": None,
        # Connection limits (eMule MaxConnections / MaxHalfConnections /
        # MaxConnectionsPerFiveSeconds analogs).
        "max_connections": 250,
        "max_half_connections": 50,
        "max_conn_per_5s": 60,
        # Global download throttle, bytes/sec (0 = unlimited; upload throttle
        # lives in serve.throttle_bytes_per_sec).
        "max_download_bytes_per_sec": 0,
        # Refuse plain (unobfuscated) peer dials when True (eMule
        # CryptLayerRequired analog); False keeps the plain fallback.
        "crypt_layer_required": False,
    },
    "download": {
        # eMule MaxSourcesPerFile analog.
        "max_sources_per_file": 400,
        # Sparse part files: do not preallocate the full final size on disk
        # (eMule SparsePartFiles analog; the sidecar gap list is the source
        # of truth either way).
        "sparse_part_files": False,
    },
    "paths": {
        "incoming": None,
        "temp": None,
        "shared": None,
    },
    "kademlia": {
        "nodes_dat": "assets/v1/nodes.dat",
        "bootstrap_nodes": [],
        # Our KAD UDP verify key (uint32). None = generated and persisted on
        # first use (eMule preferencesKad.dat / KadUDPKey analog) so peers
        # can keep encrypting to us across restarts.
        "udp_key": None,
        # Periodic source re-ask + re-dial for queued/download entries
        # (eMule ReAskTime analog; the kernel's source-refresh loop).
        "reask_interval_s": 300,
    },
    "servers": {
        "server_met": "assets/v1/server.met",
        "static_servers": "assets/v1/staticservers.dat",
    },
    "sharing": {
        "shared_files_json": None,
        "shareddir_dat": None,
    },
    "ipfilter": {
        "ipfilter_dat": "assets/v1/ipfilter.dat",
        "ipfilter_static_dat": "assets/v1/ipfilter_static.dat",
        # Level threshold (eMule FilterLevel analog).
        "level": 127,
        # Automatic ipfilter.dat refresh (eMule AutoIPFilterUpdate analog).
        "auto_update": False,
        "update_url": None,
        "update_period_days": 7,
    },
    "geoip": {
        "geoip_dat": "assets/v1/GeoIP.dat",
        "enabled": False,
    },
    "proxy": {
        "enabled": False,
        "host": None,
        "port": None,
        "username": None,
        "password": None,
    },
    "identity": {
        "user_hash": None,
        "nick": "AmuleD",
        "tcp_port": 0,
        "client_id": 0,
    },
    "serve": {
        "bind_host": "0.0.0.0",
        "max_sessions": 64,
        "upload_slots": 4,
        "throttle_bytes_per_sec": 0,
        "republish_hours": 6.0,
        "publish_limit": 0,
    },
    "storage": {
        "backend": "duckdb",
    },
    "logging": {
        "level": "INFO",
        "file": "logs/amuled.jsonl",
    },
}


def _deep_merge(defaults: dict[str, Any], values: dict[str, Any]) -> dict[str, Any]:
    """Return defaults recursively overlaid by user values."""
    merged = copy.deepcopy(defaults)
    for key, value in values.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _normalize_paths(cfg: dict[str, Any]) -> dict[str, Any]:
    """Replace null path entries with portable runtime defaults."""
    paths = cfg.get("paths", {})
    if paths.get("incoming") is None:
        paths["incoming"] = str(INCOMING_DIR)
    if paths.get("temp") is None:
        paths["temp"] = str(TEMP_DIR)
    if paths.get("shared") is None:
        paths["shared"] = str(SHARED_DIR)
    cfg["paths"] = paths

    logging_cfg = cfg.setdefault("logging", {})
    logging_file = logging_cfg.get("file")
    if logging_file and not Path(str(logging_file)).is_absolute():
        logging_path = Path(str(logging_file))
        if logging_path.parts and logging_path.parts[0].lower() == "logs":
            logging_cfg["file"] = str(PROJECT_ROOT / logging_path)
        else:
            logging_cfg["file"] = str(LOGS_DIR / logging_path)
    return cfg


# ------------------------------------------------------------------
# Load / save
# ------------------------------------------------------------------

def load_config(save_if_missing: bool = True) -> dict[str, Any]:
    """Load configuration from ``config\\amuled.jsonc``.

    If the file does not exist, it is created from :data:`DEFAULT_CONFIG`
    (with null paths normalized) when *save_if_missing* is ``True``.
    Existing user config is never overwritten.
    """
    ensure_runtime_dirs()
    if CONFIG_FILE.exists():
        log.debug(f"Loading config: {CONFIG_FILE}")
        user_cfg = load_jsonc_file(CONFIG_FILE)
        if not isinstance(user_cfg, dict):
            log.error(f"Configuration root is not a JSON object: {CONFIG_FILE}")
            raise ValueError(f"configuration root must be a JSON object: {CONFIG_FILE}")
        cfg = _deep_merge(DEFAULT_CONFIG, user_cfg)
        _normalize_paths(cfg)
        log.debug("Config loaded and merged with defaults")
        return cfg
    # --- first run: write defaults ---
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    _normalize_paths(cfg)
    if save_if_missing:
        log.info(f"Creating default config: {CONFIG_FILE}")
        save_config(cfg)
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    """Write *cfg* to the config file as JSONC."""
    ensure_runtime_dirs()
    dump_json(cfg, CONFIG_FILE)
    log.debug(f"Config saved: {CONFIG_FILE}")


# ------------------------------------------------------------------
# Dot-notation helpers
# ------------------------------------------------------------------

def _resolve_dotted(cfg: dict[str, Any], key: str) -> Any:
    parts = key.split(".")
    cur: Any = cfg
    for p in parts:
        if not isinstance(cur, dict) or p not in cur:
            raise KeyError(key)
        cur = cur[p]
    return cur


def _set_dotted(cfg: dict[str, Any], key: str, value: Any) -> None:
    parts = key.split(".")
    cur = cfg
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


def _infer_type(raw: str) -> Any:
    """Infer a Python value from a raw string: bool, int, float, or str."""
    low = raw.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "none"):
        return None
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


# ------------------------------------------------------------------
# CLI helpers
# ------------------------------------------------------------------

def config_show(cfg: dict[str, Any] | None = None, *, json_output: bool = False) -> int:
    """Print the current configuration."""
    if cfg is None:
        cfg = load_config()
    text = dump_json(cfg)
    if json_output:
        print(text)
    else:
        print(text)
    return 0


def config_set(
    dotted_key: str,
    raw_value: str,
    *,
    json_output: bool = False,
) -> int:
    """Set a dotted config key to an inferred-typed value and persist it."""
    cfg = load_config(save_if_missing=True)
    value = _infer_type(raw_value)
    _set_dotted(cfg, dotted_key, value)
    save_config(cfg)
    if json_output:
        print(dump_json({"key": dotted_key, "value": value}))
    else:
        print(f"{dotted_key} = {value!r}")
    return 0
