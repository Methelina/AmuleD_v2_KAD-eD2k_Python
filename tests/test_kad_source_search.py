"""Tests for the Kad2 file-source search codec (no network).

Covers the pure payload builder/parser of
``src/amuled_v2/core/kad/source_search.py``: the
``KADEMLIA2_SEARCH_SOURCE_REQ`` request body and the source-entry list of a
``KADEMLIA2_SEARCH_RES`` response.  All tests are local and deterministic.

tests/test_kad_source_search.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Initial request-builder and source-entry parser coverage, including
      the eMule network-order uint32 IP tag endianness rule.
"""

from __future__ import annotations

import struct

import pytest

from amuled_v2.core.kad.packets import KadUInt128
from amuled_v2.core.kad.search import KadSearchError
from amuled_v2.core.kad.source_search import (
    build_search_source_req,
    parse_search_res_source_entries,
)

_TAGTYPE_UINT32 = 0x03
_TAGTYPE_UINT16 = 0x08
_TAGTYPE_UINT8 = 0x09
_TAGTYPE_STRING = 0x02

_TAGNAME_SOURCETYPE = b"\xFF"
_TAGNAME_SOURCEIP = b"\xFE"
_TAGNAME_SOURCEPORT = b"\xFD"
_TAGNAME_SOURCEUPORT = b"\xFC"
_TAGNAME_SERVERIP = b"\xFB"
_TAGNAME_SERVERPORT = b"\xFA"
_TAGNAME_BUDDYHASH = b"\xF8"
_TAGNAME_ENCRYPTION = b"\xF3"


def _tag(tag_type: int, name: bytes, value: bytes) -> bytes:
    return bytes((tag_type,)) + struct.pack("<H", len(name)) + name + value


def _tag_u8(name: bytes, value: int) -> bytes:
    return _tag(_TAGTYPE_UINT8, name, bytes((value,)))


def _tag_u16(name: bytes, value: int) -> bytes:
    return _tag(_TAGTYPE_UINT16, name, struct.pack("<H", value))


def _tag_u32(name: bytes, value: int) -> bytes:
    return _tag(_TAGTYPE_UINT32, name, struct.pack("<I", value))


def _tag_str(name: bytes, value: str) -> bytes:
    raw = value.encode("utf-8")
    return _tag(_TAGTYPE_STRING, name, struct.pack("<H", len(raw)) + raw)


def _tag_list(*tags: bytes) -> bytes:
    return bytes((len(tags),)) + b"".join(tags)


def _ip_wire(ip: str) -> bytes:
    """Encode a dotted quad the way eMule's network-order uint32 tag does.

    The 4 wire bytes come out in normal dotted-quad order; a little-endian
    u32 read of them yields the byte-swapped integer our parser must undo.
    """
    return bytes(int(part) for part in ip.split("."))


def _source_entry(source_id: bytes, tags: bytes) -> bytes:
    return source_id + tags


def _res_payload(source_id: bytes, tags: bytes, *, responder: bytes | None = None, target: bytes | None = None) -> bytes:
    responder = responder if responder is not None else b"\x11" * 16
    target = target if target is not None else b"\x22" * 16
    return responder + target + struct.pack("<H", 1) + _source_entry(source_id, tags)


# --- build_search_source_req -------------------------------------------------


def test_build_search_source_req_layout_roundtrip() -> None:
    file_hash = bytes(range(16))
    target = KadUInt128(file_hash)
    payload = build_search_source_req(target, 1_180_000_000)
    assert payload[:16] == file_hash
    assert payload[16:18] == b"\x00\x00"  # uStartPosition = 0
    (size,) = struct.unpack_from("<Q", payload, 18)
    assert size == 1_180_000_000
    assert len(payload) == 26


def test_build_search_source_req_zero_size_means_any() -> None:
    payload = build_search_source_req(KadUInt128(b"\xAB" * 16), 0)
    assert payload[18:26] == b"\x00" * 8


def test_build_search_source_req_rejects_negative_size() -> None:
    with pytest.raises(ValueError):
        build_search_source_req(KadUInt128(b"\xAB" * 16), -1)


# --- parse_search_res_source_entries ------------------------------------------


def test_parse_source_entries_highid() -> None:
    source_id = bytes(range(16))
    tags = _tag_list(
        _tag_u8(_TAGNAME_SOURCETYPE, 1),
        _tag_u32(_TAGNAME_SOURCEIP, struct.unpack("<I", _ip_wire("1.2.3.4"))[0]),
        _tag_u16(_TAGNAME_SOURCEPORT, 4662),
        _tag_u16(_TAGNAME_SOURCEUPORT, 4672),
        _tag_u8(_TAGNAME_ENCRYPTION, 1),
    )
    entries = parse_search_res_source_entries(_res_payload(source_id, tags))
    assert len(entries) == 1
    sid, fields = entries[0]
    assert sid == source_id
    assert fields["source_type"] == 1
    assert fields["ip"] == "1.2.3.4"
    assert fields["tcp_port"] == 4662
    assert fields["udp_port"] == 4672
    assert fields["crypt_options"] == 1
    assert fields["buddy_ip"] is None
    assert fields["buddy_port"] == 0


def test_parse_source_entries_firewalled_buddy() -> None:
    source_id = b"\xAA" * 16
    tags = _tag_list(
        _tag_u8(_TAGNAME_SOURCETYPE, 3),
        _tag_u32(_TAGNAME_SERVERIP, struct.unpack("<I", _ip_wire("5.6.7.8"))[0]),
        _tag_u16(_TAGNAME_SERVERPORT, 6555),
        _tag_str(_TAGNAME_BUDDYHASH, "DEADBEEF" * 8),
        _tag_u16(_TAGNAME_SOURCEPORT, 4662),
    )
    entries = parse_search_res_source_entries(_res_payload(source_id, tags))
    assert len(entries) == 1
    sid, fields = entries[0]
    assert sid == source_id
    assert fields["source_type"] == 3
    assert fields["buddy_ip"] == "5.6.7.8"
    assert fields["buddy_port"] == 6555
    assert fields["buddy_hash"] == "DEADBEEF" * 8
    assert fields["tcp_port"] == 4662
    assert fields["ip"] is None


def test_parse_source_entries_zero_sourceip_is_none() -> None:
    tags = _tag_list(
        _tag_u8(_TAGNAME_SOURCETYPE, 6),
        _tag_u32(_TAGNAME_SOURCEIP, 0),
        _tag_u16(_TAGNAME_SOURCEPORT, 4662),
    )
    entries = parse_search_res_source_entries(_res_payload(b"\x01" * 16, tags))
    assert entries[0][1]["ip"] is None


def test_parse_source_entries_multiple_and_extra_tags_ignored() -> None:
    filesize_tag = _tag(_TAGTYPE_UINT32, b"\x02", struct.pack("<Q", 123456)[:4])
    entry1 = _source_entry(
        b"\x01" * 16,
        _tag_list(
            _tag_u8(_TAGNAME_SOURCETYPE, 4),
            _tag_u32(_TAGNAME_SOURCEIP, struct.unpack("<I", _ip_wire("9.9.9.9"))[0]),
            _tag_u16(_TAGNAME_SOURCEPORT, 4711),
            filesize_tag,
        ),
    )
    entry2 = _source_entry(
        b"\x02" * 16,
        _tag_list(
            _tag_u8(_TAGNAME_SOURCETYPE, 1),
            _tag_u32(_TAGNAME_SOURCEIP, struct.unpack("<I", _ip_wire("10.0.0.5"))[0]),
            _tag_u16(_TAGNAME_SOURCEPORT, 4662),
        ),
    )
    payload = (
        b"\x11" * 16
        + b"\x22" * 16
        + struct.pack("<H", 2)
        + entry1
        + entry2
    )
    entries = parse_search_res_source_entries(payload)
    assert len(entries) == 2
    assert entries[0][0] == b"\x01" * 16
    assert entries[0][1]["ip"] == "9.9.9.9"
    assert entries[0][1]["tcp_port"] == 4711
    assert entries[1][0] == b"\x02" * 16
    assert entries[1][1]["ip"] == "10.0.0.5"


def test_parse_source_entries_truncated_raises() -> None:
    with pytest.raises(KadSearchError):
        parse_search_res_source_entries(b"\x00" * 10)
    # Header ok but entry hash missing.
    payload = b"\x11" * 16 + b"\x22" * 16 + struct.pack("<H", 1) + b"\x00" * 4
    with pytest.raises(KadSearchError):
        parse_search_res_source_entries(payload)
