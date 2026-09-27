"""IPv6 KAD source-tag tests (stage X, roadmap 11o addendum).

Oracle: eMuleAI Search.cpp:915-923 (write) / :1195-1209 (parse) —
TAG_IPV6 ("ip6") and TAG_SERVINGBUDDYIPV6 ("bi6") are ASCII string tags
carrying 32 lowercase hex chars of the 16-byte IPv6 (network order).
Recon: tmp/recon/emuleai-kad-ipv6-tags.recon.md.

tests/test_kad_ipv6_tags.py
Author:      Soror L.'.L.'.
Updated:     2026-09-27
"""

from __future__ import annotations

import struct

from amuled_v2.core.kad.source_search import (
    _TAGNAME_IPV6,
    _TAGNAME_SOURCETYPE,
    _TAGNAME_SOURCEPORT,
    _TAGNAME_BUDDYIPV6,
    _parse_ipv6_hex,
    parse_search_res_source_entries,
)

_TAGTYPE_STRING = 0x02
_TAGTYPE_UINT32 = 0x03


def _string_tag(name: bytes, value: str) -> bytes:
    raw = value.encode("utf-8")
    return (
        bytes((_TAGTYPE_STRING,))
        + struct.pack("<H", len(name))
        + name
        + struct.pack("<H", len(raw))
        + raw
    )


def _uint32_tag(name: bytes, value: int) -> bytes:
    return (
        bytes((_TAGTYPE_UINT32,))
        + struct.pack("<H", len(name))
        + name
        + struct.pack("<I", value)
    )


def test_parse_ipv6_hex() -> None:
    assert _parse_ipv6_hex("20010db8" + "00" * 10 + "0001") == (
        "2001:db8::1"
    )
    # Uppercase hex is still hex — canonicalized to lowercase compressed.
    assert _parse_ipv6_hex(("2A0C5704" + "00" * 12).upper()).startswith(
        "2a0c:5704::"
    )
    assert _parse_ipv6_hex("zz" * 16) is None
    assert _parse_ipv6_hex("00" * 15) is None  # wrong length
    assert _parse_ipv6_hex("") is None


def test_search_res_source_entries_ipv6_tags() -> None:
    ip6_hex = "20010db8" + "00" * 10 + "0001"
    bi6_hex = "2a0c5704" + "00" * 12
    tags = (
        _uint32_tag(b"\xFF", 1)  # SOURCETYPE 1 (direct)
        + _uint32_tag(b"\xFD", 4662)  # SOURCEPORT
        + _string_tag(b"ip6", ip6_hex)
        + _string_tag(b"bi6", bi6_hex)
    )
    payload = (
        b"\x11" * 16  # responder KadID (consumed)
        + b"\x22" * 16  # target file hash (consumed)
        + struct.pack("<H", 1)  # one entry
        + b"\x33" * 16  # entry answer KadID
        + bytes((4,))  # four tags
        + tags
    )
    entries = parse_search_res_source_entries(payload)
    assert len(entries) == 1
    source_id, fields = entries[0]
    assert source_id == b"\x33" * 16
    assert fields["ipv6"] == "2001:db8::1"
    assert fields["buddy_ipv6"] == "2a0c:5704::"
    assert fields["tcp_port"] == 4662

    # Malformed hex must degrade to None, never raise.
    bad_tags = (
        _uint32_tag(b"\xFF", 1)
        + _string_tag(b"ip6", "zz" * 16)
    )
    bad_payload = (
        b"\x11" * 16 + b"\x22" * 16 + struct.pack("<H", 1)
        + b"\x33" * 16 + bytes((1,)) + bad_tags
    )
    _sid, bad_fields = parse_search_res_source_entries(bad_payload)[0]
    assert bad_fields["ipv6"] is None
