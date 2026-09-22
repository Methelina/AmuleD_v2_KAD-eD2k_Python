"""Tests for ED2K server-list persistence using synthetic and real v1 data.

Covers ``server.met`` parsing, tag-driven metadata extraction, duplicate-aware
merging, and ``staticservers.dat`` import.  The real-file test is skipped when
the imported v1 file is unavailable.

tests/test_server_met.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Synthetic server.met writer and round-trip parsing tests.
  [+] Real imported v1 server.met smoke test.
  [+] Static server parser and merge tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from amuled_v2.core.codec.binary import BinaryWriter
from amuled_v2.core.codec.tags import Ed2kTag, write_new_tag
from amuled_v2.core.ed2k import (
    SERVER_MET_VERSION,
    ServerMetError,
    ServerRecord,
    load_server_met,
    load_static_servers,
    merge_server_lists,
    parse_server_met,
)

_REAL_SERVER_MET = Path(__file__).resolve().parents[1] / "assets" / "v1" / "server.met"
_REAL_STATIC_SERVERS = (
    Path(__file__).resolve().parents[1] / "assets" / "v1" / "staticservers.dat"
)


def _write_tag(writer: BinaryWriter, tag: Ed2kTag) -> None:
    write_new_tag(tag, writer)


def _build_server_met(records: list[ServerRecord]) -> bytes:
    writer = BinaryWriter()
    writer.write_u8(SERVER_MET_VERSION)
    writer.write_u32(len(records))
    for record in records:
        writer.write_u32(record.ip)
        writer.write_u16(record.port)
        writer.write_u32(len(record.tags))
        for tag in record.tags:
            _write_tag(writer, tag)
    return writer.to_bytes()


def _make_record(ip: int, port: int, name: str, users: int = 0) -> ServerRecord:
    return ServerRecord(
        ip=ip,
        port=port,
        tags=[
            Ed2kTag(name_id=0x01, type=2, value=name),
            Ed2kTag(name="users", type=3, value=users),
        ],
    )


def test_synthetic_server_met_roundtrip() -> None:
    records = [
        _make_record(0x2D52509B, 3716, "eMule Security", users=1234),
        _make_record(0x01020304, 4232, "Test Server", users=42),
    ]
    raw = _build_server_met(records)
    parsed = parse_server_met(raw)
    assert parsed == records
    assert parsed[0].address == "45.82.80.155"
    assert parsed[0].endpoint == "45.82.80.155:3716"
    assert parsed[0].name == "eMule Security"
    assert parsed[0].users == 1234
    assert parsed[1].endpoint == "1.2.3.4:4232"


def test_empty_server_met() -> None:
    assert parse_server_met(_build_server_met([])) == []


def test_rejects_unsupported_version_and_trailing_bytes() -> None:
    with pytest.raises(ServerMetError):
        parse_server_met(b"\xe1\x00\x00\x00\x00")
    records = [_make_record(0x01020304, 4661, "Extra")]
    raw = _build_server_met(records) + b"trailer"
    with pytest.raises(ServerMetError):
        parse_server_met(raw)


def test_merge_deduplicates_by_endpoint() -> None:
    primary = [_make_record(0x01020304, 4661, "Primary")]
    secondary = [
        _make_record(0x01020304, 4661, "Duplicate"),
        _make_record(0x05060708, 4661, "Added"),
    ]
    merged = merge_server_lists(primary, secondary)
    assert len(merged) == 2
    assert {record.name for record in merged} == {"Primary", "Added"}


def test_static_server_parser(tmp_path: Path) -> None:
    source = tmp_path / "staticservers.dat"
    source.write_text(
        "# comment\n"
        "1.2.3.4:4661,2,High Server\n"
        "\n"
        "bad-line\n"
        "example.invalid:4232,5,Normalized Priority\n",
        encoding="utf-8",
    )
    servers = load_static_servers(source)
    assert len(servers) == 2
    assert servers[0].host == "1.2.3.4"
    assert servers[0].port == 4661
    assert servers[0].priority == 2
    assert servers[0].static is True
    assert servers[1].priority == 0


@pytest.mark.skipif(not _REAL_SERVER_MET.exists(), reason="bundled server.met unavailable")
def test_real_imported_server_met_smoke() -> None:
    records = load_server_met(_REAL_SERVER_MET)
    assert len(records) == 20
    assert all(0 <= record.port <= 0xFFFF for record in records)
    assert any(record.name for record in records)


@pytest.mark.skipif(not _REAL_STATIC_SERVERS.exists(), reason="bundled staticservers.dat unavailable")
def test_real_imported_static_server_smoke() -> None:
    servers = load_static_servers(_REAL_STATIC_SERVERS)
    assert len(servers) == 1
    assert servers[0].host == "45.82.80.155"
    assert servers[0].port == 5687
    assert "eMule" in servers[0].name
