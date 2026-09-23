"""Offline tests for the persistent server blacklist.

DuckDB-only checks; no network.

tests/test_server_blacklist.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Tested failure counting, blacklist threshold, cooldown, and forgive.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

import amuled_v2.state as state_module
from amuled_v2.state import StateBackend


@pytest.fixture()
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> StateBackend:
    database = tmp_path / "state.db"
    monkeypatch.setattr(state_module, "DB_FILE", database)
    backend = StateBackend()
    backend.connect()
    yield backend
    backend.close()


def test_failures_accumulate_and_blacklist_at_threshold(
    isolated_state: StateBackend,
) -> None:
    backend = isolated_state

    assert backend.record_server_failure(
        "10.0.0.1", 4661, reason="timeout", threshold=3, cooldown_hours=1
    ) is False
    assert backend.record_server_failure(
        "10.0.0.1", 4661, reason="timeout", threshold=3, cooldown_hours=1
    ) is False
    assert backend.record_server_failure(
        "10.0.0.1", 4661, reason="timeout", threshold=3, cooldown_hours=1
    ) is True

    blacklisted = backend.list_blacklisted_servers()
    assert len(blacklisted) == 1
    assert blacklisted[0]["failures"] == 3
    assert blacklisted[0]["ip"] == "10.0.0.1"
    assert blacklisted[0]["port"] == 4661

    failures = backend.list_server_failures()
    assert len(failures) == 1
    assert failures[0]["failures"] == 3


def test_success_forgives_server(
    isolated_state: StateBackend,
) -> None:
    backend = isolated_state

    backend.record_server_failure("10.0.0.2", 4662, reason="drop", threshold=3)
    backend.record_server_failure("10.0.0.2", 4662, reason="drop", threshold=3)
    backend.record_server_failure("10.0.0.2", 4662, reason="drop", threshold=3)
    assert len(backend.list_blacklisted_servers()) == 1

    backend.record_server_success("10.0.0.2", 4662)

    assert backend.list_blacklisted_servers() == []
    assert backend.list_server_failures() == []


def test_cooldown_expiry_allows_new_count(
    isolated_state: StateBackend,
) -> None:
    backend = isolated_state

    backend.record_server_failure(
        "10.0.0.3", 4663, reason="err", threshold=3, cooldown_hours=1 / 3600
    )
    backend.record_server_failure(
        "10.0.0.3", 4663, reason="err", threshold=3, cooldown_hours=1 / 3600
    )
    backend.record_server_failure(
        "10.0.0.3", 4663, reason="err", threshold=3, cooldown_hours=1 / 3600
    )
    assert len(backend.list_blacklisted_servers()) == 1

    time.sleep(1.1)

    assert backend.list_blacklisted_servers() == []

    backend.record_server_failure(
        "10.0.0.3", 4663, reason="err", threshold=3, cooldown_hours=1 / 3600
    )

    remaining = backend.list_server_failures()
    assert len(remaining) == 1
    assert remaining[0]["failures"] == 1


def test_independent_servers_tracked_separately(
    isolated_state: StateBackend,
) -> None:
    backend = isolated_state

    backend.record_server_failure(
        "10.0.0.1", 4661, reason="timeout", threshold=3
    )
    backend.record_server_failure(
        "10.0.0.1", 4661, reason="timeout", threshold=3
    )
    backend.record_server_failure(
        "10.0.0.2", 4661, reason="timeout", threshold=3
    )

    failures = backend.list_server_failures()
    assert len(failures) == 2
    assert backend.list_blacklisted_servers() == []

    by_server: dict[tuple[str, int], int] = {
        (row["ip"], row["port"]): row["failures"] for row in failures
    }
    assert by_server[("10.0.0.1", 4661)] == 2
    assert by_server[("10.0.0.2", 4661)] == 1
