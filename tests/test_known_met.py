"""Stage X tests: known.met parser/writer and CLI import/export.

Author: Soror L.'.L.'.
Updated: 2026-09-26
"""

from __future__ import annotations

import argparse
import struct

from amuled_v2.core.sharing.known_met import (
    KnownMetEntry,
    parse_known_met,
    write_known_met,
)


def _write_raw_met(path, entries: bytes, *, header: int = 0x0F) -> None:
    path.write_bytes(bytes([header]) + struct.pack("<I", 1) + entries)


def test_known_met_roundtrip(tmp_path) -> None:
    target = tmp_path / "known.met"
    entry = KnownMetEntry(
        file_hash="AB" * 16,
        name="round trip file.bin",
        size=123_456,
        last_modified=1_700_000_000,
        part_hashes=["CD" * 16],
    )
    assert write_known_met(target, [entry], last_modified=entry.last_modified) == 1
    parsed = parse_known_met(target)
    assert len(parsed) == 1
    got = parsed[0]
    assert got.file_hash == entry.file_hash
    assert got.name == entry.name
    assert got.size == entry.size
    assert got.part_hashes == entry.part_hashes
    assert got.last_modified == entry.last_modified


def test_known_met_parses_emule_style_tags(tmp_path) -> None:
    """Replicates eMule's own non-compact tag layout: plain type byte,
    name = u16 length 1 + byte 0x01 (name) / 0x02 (size)."""
    entries = bytearray()
    entries += struct.pack("<I", 111)
    entries += bytes.fromhex("12" * 16)
    entries += struct.pack("<H", 0)          # no part hashes
    tags = bytearray()
    # FT_FILENAME: type 0x02, name "\x01", utf-8 value
    name = "oracle file.iso".encode("utf-8")
    tags += bytes([0x02]) + struct.pack("<H", 1) + b"\x01"
    tags += struct.pack("<H", len(name)) + name
    # FT_FILESIZE: type 0x03, name "\x02", u32 value
    tags += bytes([0x03]) + struct.pack("<H", 1) + b"\x02"
    tags += struct.pack("<I", 5_000_000)
    entries += struct.pack("<I", 2) + tags
    met = tmp_path / "emule.met"
    _write_raw_met(met, bytes(entries))

    parsed = parse_known_met(met)
    assert len(parsed) == 1
    assert parsed[0].file_hash == "12" * 16
    assert parsed[0].name == "oracle file.iso"
    assert parsed[0].size == 5_000_000
    assert parsed[0].last_modified == 111


def test_known_met_cli_import_export(tmp_path, monkeypatch) -> None:
    """Import -> state -> export round trip through the CLI handlers."""
    import amuled_v2.state as state_module

    monkeypatch.setattr(state_module, "DB_FILE", tmp_path / "state.db")
    monkeypatch.setattr(state_module, "_state", None)

    from amuled_v2.cli import _cmd_export_known_met, _cmd_import_known_met
    from amuled_v2.state import get_state

    src = tmp_path / "src.met"
    entry = KnownMetEntry(
        file_hash="EF" * 16,
        name="cli file.bin",
        size=777,
        last_modified=123,
    )
    write_known_met(src, [entry])

    args = argparse.Namespace(
        known_met=str(src), save=True, json=True, no_save=False
    )
    assert _cmd_import_known_met(args) == 0

    # Import stores path=None rows; export only emits rows with a real
    # path, so plant a path to make the record exportable.
    state = get_state()
    state.connect()
    state._require_duckdb().execute(
        "UPDATE shared_files SET path = ? WHERE lower(file_hash) = ?",
        (str(tmp_path / "cli file.bin"), "ef" * 16),
    )
    state.close()

    dst = tmp_path / "out.met"
    out_args = argparse.Namespace(
        known_met=str(dst), limit=1000, json=True
    )
    assert _cmd_export_known_met(out_args) == 0

    parsed = parse_known_met(dst)
    assert len(parsed) == 1
    assert parsed[0].file_hash == "EF" * 16
    assert parsed[0].name == "cli file.bin"
    assert parsed[0].size == 777
