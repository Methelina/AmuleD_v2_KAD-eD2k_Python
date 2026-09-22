"""Tests for shared-file import, ED2K hashing, and link generation.

Uses synthetic temporary files and the real v1 wrapper metadata when present.
No network access is required.

tests/test_sharing.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Tested shared_files.json validation, normalization, and deduplication.
  [+] Tested shareddir.dat parsing and recursive native file scanning.
  [+] Tested ED2K link generation, including compact part hashes.
  [+] Added real imported v1 metadata smoke tests.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from amuled_v2.core.hashes import ed2k_hash_data
from amuled_v2.core.sharing import (
    SharedFile,
    SharingError,
    generate_ed2k_link,
    load_shareddir_dat,
    load_shared_files_json,
    scan_shared_directories,
    scan_shared_directory,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_REAL_SHARED_JSON = _PROJECT_ROOT / "assets" / "v1" / "shared_files.json"
_REAL_SHAREDDIR = _PROJECT_ROOT / "assets" / "v1" / "shareddir.dat"


def _write_v1_json(path: Path) -> None:
    payload = [
        {
            "hash": "00112233445566778899AABBCCDDEEFF",
            "name": "model|with pipe.bin",
            "size": "1.5 kb",
            "priority": "High (auto)",
        },
        {
            "hash": "00112233445566778899aabbccddeeff",
            "name": "duplicate.bin",
            "size": 1536,
            "priority": "Low",
        },
    ]
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_shared_files_json_import_and_dedup(tmp_path: Path) -> None:
    source = tmp_path / "shared_files.json"
    _write_v1_json(source)
    files = load_shared_files_json(source)
    assert len(files) == 1
    item = files[0]
    assert item.hash_hex == "00112233445566778899AABBCCDDEEFF"
    assert item.name == "model|with pipe.bin"
    assert item.size == 1500
    assert item.priority == 2
    assert item.imported is True


@pytest.mark.parametrize("payload", [
    {"hash": "short", "name": "bad", "size": 1},
    {"hash": "00112233445566778899AABBCCDDEEFF", "name": "bad", "size": "huge"},
])
def test_shared_files_json_rejects_invalid_entries(tmp_path: Path, payload: dict) -> None:
    source = tmp_path / "bad.json"
    source.write_text(json.dumps([payload]), encoding="utf-8")
    with pytest.raises(SharingError):
        load_shared_files_json(source)


def test_shareddir_dat_import_deduplicates_paths(tmp_path: Path) -> None:
    source = tmp_path / "shareddir.dat"
    source.write_text(f"{tmp_path}\\models\n{tmp_path}\\models\n\n", encoding="utf-8")
    directories = load_shareddir_dat(source)
    assert len(directories) == 1


def test_scan_shared_directory_and_ed2k_hash(tmp_path: Path) -> None:
    root = tmp_path / "shared"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (root / "small.bin").write_bytes(b"root file")
    (nested / "part.bin").write_bytes(b"nested file")
    files = scan_shared_directory(root)
    assert len(files) == 2
    by_name = {item.name: item for item in files}
    assert by_name["small.bin"].size == 9
    assert by_name["small.bin"].file_hash == ed2k_hash_data(b"root file").file_hash
    assert by_name["part.bin"].path is not None


def test_scan_shared_directories_deduplicates_same_content(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "same.bin").write_bytes(b"same content")
    (second / "copy.bin").write_bytes(b"same content")
    files = scan_shared_directories([first, second])
    assert len(files) == 1
    assert files[0].size == len(b"same content")


def test_generate_ed2k_link_with_part_hashes() -> None:
    data = b"a" * 100
    result = ed2k_hash_data(data)
    item = SharedFile(
        file_hash=result.file_hash,
        name="tiny.bin",
        size=len(data),
        hash_result=result,
    )
    link = generate_ed2k_link(item, include_part_hashes=True)
    expected_hash = result.file_hash.hex().upper()
    assert link == f"ed2k://|file|tiny.bin|100|{expected_hash}|/"


@pytest.mark.skipif(not _REAL_SHARED_JSON.exists(), reason="bundled shared_files.json unavailable")
def test_real_shared_files_json_smoke() -> None:
    files = load_shared_files_json(_REAL_SHARED_JSON)
    assert len(files) == 494
    assert all(len(item.file_hash) == 16 for item in files)
    assert all(item.size >= 0 for item in files)


@pytest.mark.skipif(not _REAL_SHAREDDIR.exists(), reason="bundled shareddir.dat unavailable")
def test_real_shareddir_dat_smoke() -> None:
    directories = load_shareddir_dat(_REAL_SHAREDDIR)
    assert len(directories) == 246
    assert all(str(path) for path in directories)
