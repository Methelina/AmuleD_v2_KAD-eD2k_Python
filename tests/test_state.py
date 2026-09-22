"""Integration tests for DuckDB state migrations and import repositories.

Tests run against an isolated temporary database.  They never touch the real
``db/amuled.db`` runtime file.

tests/test_state.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Tested schema migration to version 2.
  [+] Tested idempotent server, static server, shared-file, and directory save.
  [+] Tested status table counts after repository operations.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import amuled_v2.state as state_module
from amuled_v2.core.ed2k import ServerRecord, StaticServer
from amuled_v2.core.sharing import SharedFile
from amuled_v2.state import StateBackend


@pytest.fixture()
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> StateBackend:
    database = tmp_path / "state.db"
    monkeypatch.setattr(state_module, "DB_FILE", database)
    backend = StateBackend()
    yield backend
    backend.close()


def _server(ip: int, port: int, name: str) -> ServerRecord:
    return ServerRecord(ip=ip, port=port, tags=[], static=False)


def test_state_migrates_and_saves_imported_resources(
    isolated_state: StateBackend,
) -> None:
    isolated_state.connect()
    status = isolated_state.get_status()
    assert status["backend"] == "duckdb"
    assert status["tables"]["schema_migrations"] >= 2

    servers = [
        _server(0x01020304, 4661, "One"),
        _server(0x05060708, 4232, "Two"),
    ]
    static = [StaticServer(host="example.invalid", port=4661, name="Static")]
    shared = [
        SharedFile(
            file_hash=bytes.fromhex("00112233445566778899aabbccddeeff"),
            name="model.bin",
            size=1536,
            priority=2,
            imported=True,
        )
    ]

    assert isolated_state.save_servers(servers) == 2
    assert isolated_state.save_servers(servers) == 2
    assert isolated_state.save_static_servers(static) == 1
    assert isolated_state.save_shared_files(shared) == 1
    assert isolated_state.save_shared_directories([r"O:\shared\models"]) == 1

    status = isolated_state.get_status()
    assert status["tables"]["servers"] == 2
    assert status["tables"]["static_servers"] == 1
    assert status["tables"]["shared_files"] == 1
    assert status["tables"]["shared_directories"] == 1


def test_state_repositories_require_duckdb_backend(
    isolated_state: StateBackend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolated_state.connect()
    isolated_state.backend = "json-fallback"
    isolated_state._con = {}
    with pytest.raises(RuntimeError):
        isolated_state.save_servers([])
