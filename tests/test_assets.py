"""Self-contained baseline resource tests for portable distribution.

These tests prove that a fresh GitHub checkout contains every bundled v1
resource required by the installer and runtime, without any donor directory.

tests/test_assets.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Verified presence and minimum sizes of all bundled baseline assets.
  [+] Verified server, static-server, shared-file, and directory import counts.
  [+] Verified configured paths point only inside the project.
"""

from __future__ import annotations

import json
from pathlib import Path

from amuled_v2.config import load_config
from amuled_v2.core.ed2k import load_server_met, load_static_servers
from amuled_v2.core.sharing import load_shareddir_dat, load_shared_files_json
from amuled_v2.paths import (
    BASELINE_ASSETS_DIR,
    BASELINE_GEOIP_DAT,
    BASELINE_IPFILTER,
    BASELINE_IPFILTER_STATIC,
    BASELINE_NODES_DAT,
    BASELINE_SERVER_MET,
    BASELINE_SHAREDDIR_DAT,
    BASELINE_SHARED_FILES_JSON,
    BASELINE_STATIC_SERVERS,
    PROJECT_ROOT,
)

_REQUIRED_ASSETS = {
    "server.met": 16,
    "nodes.dat": 16,
    "GeoIP.dat": 1_000_000,
    "staticservers.dat": 8,
    "ipfilter.dat": 1,
    "ipfilter_static.dat": 8,
    "shared_files.json": 16,
    "shareddir.dat": 16,
}


def test_bundled_baseline_assets_are_present() -> None:
    paths = {
        "server.met": BASELINE_SERVER_MET,
        "nodes.dat": BASELINE_NODES_DAT,
        "GeoIP.dat": BASELINE_GEOIP_DAT,
        "staticservers.dat": BASELINE_STATIC_SERVERS,
        "ipfilter.dat": BASELINE_IPFILTER,
        "ipfilter_static.dat": BASELINE_IPFILTER_STATIC,
        "shared_files.json": BASELINE_SHARED_FILES_JSON,
        "shareddir.dat": BASELINE_SHAREDDIR_DAT,
    }
    assert set(paths) == set(_REQUIRED_ASSETS)
    for name, path in paths.items():
        assert path == BASELINE_ASSETS_DIR / name
        assert path.is_file(), f"missing bundled baseline asset: {name}"
        assert path.stat().st_size >= _REQUIRED_ASSETS[name], (
            f"bundled baseline asset is truncated: {name}"
        )


def test_bundled_server_resources_import() -> None:
    servers = load_server_met(BASELINE_SERVER_MET)
    static_servers = load_static_servers(BASELINE_STATIC_SERVERS)
    assert len(servers) == 20
    assert len(static_servers) == 1
    assert static_servers[0].host == "45.82.80.155"


def test_bundled_shared_resources_import() -> None:
    shared_files = load_shared_files_json(BASELINE_SHARED_FILES_JSON)
    shared_directories = load_shareddir_dat(BASELINE_SHAREDDIR_DAT)
    assert len(shared_files) == 494
    assert len(shared_directories) == 246


def test_configured_baseline_paths_are_project_local_and_portable() -> None:
    config = load_config(save_if_missing=False)
    configured_paths = [
        config["kademlia"]["nodes_dat"],
        config["servers"]["server_met"],
        config["servers"]["static_servers"],
        config["sharing"]["shared_files_json"],
        config["sharing"]["shareddir_dat"],
        config["ipfilter"]["ipfilter_dat"],
        config["ipfilter"]["ipfilter_static_dat"],
        config["geoip"]["geoip_dat"],
    ]
    for value in configured_paths:
        assert isinstance(value, str)
        path = Path(value)
        if path.is_absolute():
            assert PROJECT_ROOT in path.parents
        else:
            assert not path.is_absolute()
            assert path.parts[0] == "assets"
            assert path.parts[1] == "v1"


def test_bundled_metadata_is_valid_jsonc_source() -> None:
    raw = BASELINE_SHARED_FILES_JSON.read_text(encoding="utf-8-sig")
    payload = json.loads(raw)
    assert isinstance(payload, list)
    assert len(payload) == 494
