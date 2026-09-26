"""Stage X tests: IP geolocation (MMDB primary, legacy dat fallback).

Author: Soror L.'.L.'.
Updated: 2026-09-26
"""

from __future__ import annotations

from pathlib import Path

import pytest

from amuled_v2.core.geoip import load_geoip

ASSETS = Path(__file__).resolve().parents[1] / "assets" / "v1"
LEGACY_DAT = ASSETS / "GeoIP.dat"

# eMuleAI ships dbip city-lite mmdb; if present on this machine, exercise
# the MMDB path against it (read-only).
MMDB_CANDIDATES = sorted(ASSETS.glob("*.mmdb")) + [
    Path(r"K:\Software\eMuleAI_v1.6.0_x64\config\dbip-city-lite.mmdb"),
]


def test_legacy_dat_best_effort() -> None:
    if not LEGACY_DAT.exists():
        pytest.skip("assets/v1/GeoIP.dat not present")
    db = load_geoip(LEGACY_DAT)
    assert db is not None
    # Private/loopback addresses never resolve to a country.
    assert db.lookup("127.0.0.1") is None
    assert db.lookup("192.168.1.1") is None


def test_mmdb_primary_format() -> None:
    mmdb = next((p for p in MMDB_CANDIDATES if p.exists()), None)
    if mmdb is None:
        pytest.skip("no .mmdb database available on this machine")
    db = load_geoip(mmdb)
    assert db is not None
    assert db.lookup("8.8.8.8") == "US"
    assert db.lookup("127.0.0.1") is None


def test_load_geoip_missing_file() -> None:
    assert load_geoip("/nonexistent/geo.dat") is None
