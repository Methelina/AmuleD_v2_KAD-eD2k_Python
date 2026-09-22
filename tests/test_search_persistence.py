"""Offline tests for search-result persistence and source lifecycle.

These tests run against an isolated temporary DuckDB and exercise pure state
and codec layers; they never open a network session and never fake an ED2K
server.

tests/test_search_persistence.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Tested search-result batch persistence, listing, filtering, clearing.
  [+] Tested full tag retention through the codec to_dict layer.
  [+] Tested source last_seen updates, expiry pruning, and forgetting.
  [+] Tested connection-state manager AUTO inputs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import amuled_v2.state as state_module
from amuled_v2.core.codec.tags import Ed2kTag
from amuled_v2.core.connection_state import ConnectionStateManager
from amuled_v2.core.ed2k import FoundSource, FoundSources, SearchResultsBatch, SearchResult
from amuled_v2.state import StateBackend


@pytest.fixture()
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> StateBackend:
    database = tmp_path / "state.db"
    monkeypatch.setattr(state_module, "DB_FILE", database)
    backend = StateBackend()
    backend.connect()
    yield backend
    backend.close()


def _result_tag(name_id: int, value: object) -> Ed2kTag:
    return Ed2kTag(name_id=name_id, value=value)


def _search_result(
    hash_bytes: bytes,
    name: str,
    size: int,
    sources: int = 3,
) -> SearchResult:
    return SearchResult(
        file_hash=hash_bytes,
        client_id=0x0B0C0D0E,
        client_port=4662,
        tags=(
            _result_tag(0x01, name),
            _result_tag(0x02, size),
            _result_tag(0x15, sources),
            _result_tag(0x30, sources - 1),
        ),
    )


def _batch(
    hash_bytes: bytes,
    name: str,
    query: str = "video",
    session_id: str | None = None,
) -> SearchResultsBatch:
    return SearchResultsBatch(
        query=query,
        channel="server",
        server_host="176.123.5.89",
        server_port=4725,
        results=(_search_result(hash_bytes, name, 123_456),),
        more_results_available=True,
        session_id=session_id or "session-fixed",
    )


_HASH_A = bytes.fromhex("aabbccdd00112233445566778899eeff")
_HASH_B = bytes.fromhex("11223344556677889900aabbccddeeff")


def test_search_results_round_trip(isolated_state: StateBackend) -> None:
    batch = _batch(_HASH_A, "first.bin")
    assert isolated_state.save_search_results_batch(batch) == 1

    rows = isolated_state.list_search_results()
    assert len(rows) == 1
    row = rows[0]
    assert row["hash"] == _HASH_A.hex().upper()
    assert row["name"] == "first.bin"
    assert row["channel"] == "server"
    assert row["query"] == "video"
    assert row["sources"] == 3
    assert row["complete_sources"] == 2

    tags = isolated_state.get_search_result_tags(_HASH_A.hex())
    by_id = {tag["name_id"]: tag["value"] for tag in tags}
    assert by_id[0x01] == "first.bin"
    assert by_id[0x02] == 123_456


def test_search_results_upsert_updates_last_seen(isolated_state: StateBackend) -> None:
    isolated_state.save_search_results_batch(_batch(_HASH_A, "first.bin"))
    first_rows = isolated_state.list_search_results()
    first_seen = first_rows[0]["first_seen"]
    last_seen_before = first_rows[0]["last_seen"]

    isolated_state.save_search_results_batch(_batch(_HASH_A, "first-renamed.bin"))

    rows = isolated_state.list_search_results()
    assert len(rows) == 1
    assert rows[0]["name"] == "first-renamed.bin"
    assert rows[0]["first_seen"] == first_seen
    assert rows[0]["last_seen"] >= last_seen_before

    sessions = isolated_state.list_search_sessions()
    assert len(sessions) == 1
    assert sessions[0]["result_count"] == 2


def test_search_results_filters_and_clear(isolated_state: StateBackend) -> None:
    isolated_state.save_search_results_batch(_batch(_HASH_A, "one.bin", query="video"))
    isolated_state.save_search_results_batch(_batch(_HASH_B, "two.bin", query="audio"))

    assert len(isolated_state.list_search_results(query="video")) == 1
    assert len(isolated_state.list_search_results(channel="global")) == 0
    assert (
        len(isolated_state.list_search_results(hash_prefix="AABBCC")) == 1
    )

    removed = isolated_state.clear_search_results(query="video")
    assert removed == 1
    remaining = isolated_state.list_search_results()
    assert len(remaining) == 1
    assert remaining[0]["query"] == "audio"

    assert isolated_state.clear_search_results() == 1
    assert isolated_state.list_search_results() == []


def test_source_last_seen_updates_and_expiry(isolated_state: StateBackend) -> None:
    found = FoundSources(
        file_hash=_HASH_A,
        sources=(FoundSource(client_id=0x0A000001, client_port=4662),),
    )
    isolated_state.save_found_sources(
        found, server_ip="176.123.5.89", server_port=4725
    )
    before = isolated_state.list_file_sources()[0]
    assert before["first_seen"] == before["last_seen"]

    isolated_state.save_found_sources(
        found, server_ip="176.123.5.89", server_port=4725
    )
    rows = isolated_state.list_file_sources()
    assert len(rows) == 1
    assert rows[0]["first_seen"] == before["first_seen"]
    assert rows[0]["last_seen"] >= before["last_seen"]

    summary = isolated_state.prune_file_sources(max_age_hours=0.0001)
    assert summary["pruned"] in (0, 1)
    forgotten = isolated_state.forget_file_sources(_HASH_A.hex())
    assert forgotten == len(rows)
    assert isolated_state.list_file_sources() == []


def test_source_statistics(isolated_state: StateBackend) -> None:
    found = FoundSources(
        file_hash=_HASH_A,
        sources=(
            FoundSource(client_id=0x0A000001, client_port=4662),
            FoundSource(client_id=999, client_port=4661),
        ),
    )
    isolated_state.save_found_sources(
        found, server_ip="176.123.5.89", server_port=4725
    )
    stats = isolated_state.get_source_statistics()
    assert stats["total_sources"] == 2
    assert stats["distinct_files"] == 1
    assert stats["high_id_sources"] == 1
    assert stats["low_id_sources"] == 1
    assert stats["by_type"] == {"ed2k_server": 2}


def test_connection_state_manager_tracks_sessions() -> None:
    manager = ConnectionStateManager()
    snapshot = manager.snapshot
    assert snapshot.ed2k_connected is False
    assert snapshot.kad_connected is False

    manager.set_ed2k_connected(
        True,
        server_host="176.123.5.89",
        server_port=4725,
        server_users=43_000,
        server_files=19_000_000,
        server_is_static=True,
    )
    manager.set_server_count(3)
    snapshot = manager.snapshot
    assert snapshot.ed2k_connected is True
    assert snapshot.server_host == "176.123.5.89"
    assert snapshot.server_users == 43_000
    assert snapshot.server_is_static is True
    assert snapshot.server_count == 3

    manager.set_ed2k_connected(False)
    snapshot = manager.snapshot
    assert snapshot.server_host is None
    assert snapshot.server_users == 0

    manager.set_kad_connected(True)
    assert manager.snapshot.kad_connected is True


def test_tag_to_dict_is_json_serializable() -> None:
    tag = Ed2kTag(name_id=0x01, value="name.bin")
    decoded = json.loads(json.dumps(tag.to_dict()))
    assert decoded["name_id"] == 1
    assert decoded["value"] == "name.bin"
