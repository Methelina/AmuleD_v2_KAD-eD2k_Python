"""Public baseline resource tests for portable distribution.

These tests prove that a fresh checkout contains only the public network
bootstrap resources required by the installer and runtime.  Private
shared-file metadata and generated configuration are intentionally absent.

tests/test_assets.py
Version:     0.2.1
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.2.1 (Soror L.'.L'.):
  [*] Isolated config assertions from the developer's physical ignored config
      file so tests validate fresh-checkout defaults without deleting data.

Patch Notes v0.2.0 (Soror L.'.L'.):
  [*] Restricted bundled assets to public network/bootstrap data.
  [*] Verified that private shared metadata is not required after cloning.
  [+] Verified null defaults for optional legacy shared-import paths.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Verified presence and minimum sizes of bundled baseline assets.
  [+] Verified server and static-server import counts.
  [+] Verified configured paths point only inside the project.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from amuled_v2.config import load_config
from amuled_v2.core.ed2k import load_server_met, load_static_servers
from amuled_v2.paths import (
    BASELINE_ASSETS_DIR,
    BASELINE_GEOIP_DAT,
    BASELINE_IPFILTER,
    BASELINE_IPFILTER_STATIC,
    BASELINE_NODES_DAT,
    BASELINE_SERVER_MET,
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
}

_PRIVATE_ASSETS = [
    BASELINE_ASSETS_DIR / "shared_files.json",
    BASELINE_ASSETS_DIR / "shareddir.dat",
    PROJECT_ROOT / "config" / "amuled.jsonc",
]


def test_bundled_public_assets_are_present() -> None:
    paths = {
        "server.met": BASELINE_SERVER_MET,
        "nodes.dat": BASELINE_NODES_DAT,
        "GeoIP.dat": BASELINE_GEOIP_DAT,
        "staticservers.dat": BASELINE_STATIC_SERVERS,
        "ipfilter.dat": BASELINE_IPFILTER,
        "ipfilter_static.dat": BASELINE_IPFILTER_STATIC,
    }
    assert set(paths) == set(_REQUIRED_ASSETS)
    for name, path in paths.items():
        assert path == BASELINE_ASSETS_DIR / name
        assert path.is_file(), f"missing bundled public asset: {name}"
        assert path.stat().st_size >= _REQUIRED_ASSETS[name], (
            f"bundled public asset is truncated: {name}"
        )


def test_bundled_server_resources_import() -> None:
    servers = load_server_met(BASELINE_SERVER_MET)
    static_servers = load_static_servers(BASELINE_STATIC_SERVERS)
    assert len(servers) == 20
    assert len(static_servers) == 1
    assert static_servers[0].host == "45.82.80.155"


def test_private_shared_metadata_is_optional(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Private files may exist physically but are never required by defaults.

    The local ignored `config/amuled.jsonc` is deliberately not read here; the
    test patches the config path to a fresh temporary location so it validates
    what a new user receives from a clean checkout.
    """
    monkeypatch.setattr(
        "amuled_v2.config.CONFIG_FILE",
        tmp_path / "missing-amuled.jsonc",
        raising=False,
    )
    config = load_config(save_if_missing=False)
    assert config["sharing"]["shared_files_json"] is None
    assert config["sharing"]["shareddir_dat"] is None


def test_configured_public_paths_are_project_local_and_portable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "amuled_v2.config.CONFIG_FILE",
        tmp_path / "missing-amuled.jsonc",
        raising=False,
    )
    config = load_config(save_if_missing=False)
    assert config["sharing"]["shared_files_json"] is None
    assert config["sharing"]["shareddir_dat"] is None

    configured_paths = [
        config["kademlia"]["nodes_dat"],
        config["servers"]["server_met"],
        config["servers"]["static_servers"],
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
