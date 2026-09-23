"""Offline tests for the persistent server blacklist gating helpers.

State-layer only: no network, no fake ED2K servers.

tests/test_server_blacklist_gate.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Tested persistent blacklist detection and failure cooldown.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import amuled_v2.state as state_module
from amuled_v2.cli import _server_is_blacklisted


@pytest.fixture()
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(state_module, "DB_FILE", tmp_path / "state.db")
    monkeypatch.setattr(state_module, "_state", None)
    backend = state_module.StateBackend()
    backend.connect()
    yield backend


def test_blacklist_detects_currently_blacklisted(isolated_state):
    isolated_state.record_server_failure(
        "10.9.8.7", 4000, reason="test", threshold=1, cooldown_hours=1.0
    )
    assert _server_is_blacklisted("10.9.8.7", 4000) is True


def test_blacklist_ignores_other_servers(isolated_state):
    isolated_state.record_server_failure(
        "10.9.8.7", 4000, reason="test", threshold=1, cooldown_hours=1.0
    )
    assert _server_is_blacklisted("10.9.8.7", 9999) is False
    assert _server_is_blacklisted("10.0.0.1", 4000) is False


def test_forgiven_server_is_not_blacklisted(isolated_state):
    isolated_state.record_server_failure(
        "10.9.8.7", 4000, reason="test", threshold=1, cooldown_hours=1.0
    )
    isolated_state.record_server_success("10.9.8.7", 4000)
    assert _server_is_blacklisted("10.9.8.7", 4000) is False
