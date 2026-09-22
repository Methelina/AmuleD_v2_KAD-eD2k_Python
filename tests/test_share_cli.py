"""End-to-end tests for CLI shared-file management and stale-row cleanup.

Runs `python -m amuled_v2 share ...` in isolated temporary `AMULED_ROOT`
directories.  Every command writes real DuckDB state; tests then verify that
new files enter the database and deleted/moved files do not leave stale rows.

tests/test_share_cli.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Tested `share add`, `share scan`, `share list`, and DuckDB persistence.
  [+] Tested stale shared-file cleanup after a source file disappears.
  [+] Tested explicit file and directory removal commands.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SRC_DIR = _PROJECT_ROOT / "src"


def _run_cli(args: list[str], env_root: Path) -> dict:
    """Run one isolated CLI command and return its JSON stdout payload."""
    env = os.environ.copy()
    env["AMULED_ROOT"] = str(env_root)
    env["PYTHONPATH"] = str(_SRC_DIR)
    result = subprocess.run(
        [sys.executable, "-m", "amuled_v2", *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0, (
        f"CLI failed: {args}\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    return json.loads(result.stdout)


def _status_counts(env_root: Path) -> dict[str, int]:
    return _run_cli(["status", "--json"], env_root)["tables"]


@pytest.fixture()
def shared_root(tmp_path: Path) -> Path:
    """Create an isolated AMULED_ROOT containing two shared source files."""
    root = tmp_path / "amuled-root"
    media = root / "media"
    media.mkdir(parents=True)
    (media / "alpha.txt").write_text("alpha payload", encoding="utf-8")
    (media / "beta.txt").write_text("beta payload", encoding="utf-8")
    return root


def test_share_add_persists_files_in_duckdb(shared_root: Path) -> None:
    result = _run_cli(
        ["share", "add", str(shared_root / "media"), "--json"],
        shared_root,
    )
    assert result["status"] == "ok"
    assert result["saved"] is True
    assert result["files_found"] == 2
    assert result["files_saved"] == 2

    counts = _status_counts(shared_root)
    assert counts["shared_directories"] == 1
    assert counts["shared_files"] == 2

    listing = _run_cli(["share", "list", "--json"], shared_root)
    assert listing["directory_count"] == 1
    assert listing["file_count"] == 2
    assert {item["name"] for item in listing["files"]} == {
        "alpha.txt",
        "beta.txt",
    }
    assert all(len(item["hash"]) == 32 for item in listing["files"])


def test_share_scan_removes_stale_rows(shared_root: Path) -> None:
    _run_cli(
        ["share", "add", str(shared_root / "media"), "--json"],
        shared_root,
    )
    removed_source = shared_root / "media" / "beta.txt"
    removed_source.unlink()

    result = _run_cli(["share", "scan", "--json"], shared_root)
    assert result["status"] == "ok"
    assert result["files_found"] == 1
    assert result["files_saved"] == 1
    assert result["stale_files_removed"] == 1

    counts = _status_counts(shared_root)
    assert counts["shared_files"] == 1
    listing = _run_cli(["share", "list", "--files-only", "--json"], shared_root)
    assert [item["name"] for item in listing["files"]] == ["alpha.txt"]


def test_share_dry_run_does_not_change_duckdb(shared_root: Path) -> None:
    before = _status_counts(shared_root)
    result = _run_cli(
        ["share", "scan", str(shared_root / "media"), "--dry-run", "--json"],
        shared_root,
    )
    after = _status_counts(shared_root)
    assert result["saved"] is False
    assert result["files_found"] == 2
    assert after["shared_files"] == before["shared_files"]
    assert after["shared_directories"] == before["shared_directories"]


def test_share_remove_file_and_dir(shared_root: Path) -> None:
    _run_cli(
        ["share", "add", str(shared_root / "media"), "--json"],
        shared_root,
    )
    listing = _run_cli(["share", "list", "--files-only", "--json"], shared_root)
    file_hash = listing["files"][0]["hash"]

    removed_file = _run_cli(
        ["share", "remove", "file", file_hash, "--json"],
        shared_root,
    )
    assert removed_file["status"] == "ok"
    assert removed_file["removed"] is True
    assert _status_counts(shared_root)["shared_files"] == 1

    removed_dir = _run_cli(
        ["share", "remove", "dir", str(shared_root / "media"), "--json"],
        shared_root,
    )
    assert removed_dir["status"] == "ok"
    assert removed_dir["directory_removed"] is True
    assert removed_dir["removed_files"] == 1
    counts = _status_counts(shared_root)
    assert counts["shared_files"] == 0
    assert counts["shared_directories"] == 0


def test_share_remove_missing_file_returns_not_found(shared_root: Path) -> None:
    env = os.environ.copy()
    env["AMULED_ROOT"] = str(shared_root)
    env["PYTHONPATH"] = str(_SRC_DIR)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "amuled_v2",
            "share",
            "remove",
            "file",
            "00112233445566778899aabbccddeeff",
            "--json",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "not_found"
    assert payload["removed"] is False
