"""Offline tests for the ED2K global UDP search layer.

Pure codec and framing checks only: no network, no fake servers, no synthetic
protocol sessions.

tests/test_udp_global.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Tested UDP search payload builders and REQ3 capability prefix.
  [+] Tested UDP framing encode/parse, including packed datagrams.
  [+] Tested endpoint validation and aggregate reporting.
"""

from __future__ import annotations

import zlib

import pytest

from amuled_v2.core.codec.constants import EDONKEY
from amuled_v2.core.ed2k import (
    GlobalSearchAggregate,
    GlobalServerEndpoint,
    GlobalUdpSearchError,
    build_udp_search_payload,
    build_udp_search_req3_prefix,
    encode_udp_packet,
    parse_udp_packet,
    SearchResult,
)


def test_build_udp_search_payload_layout() -> None:
    body = build_udp_search_payload(" ubuntu iso ")
    assert body[0] == 1
    assert body.endswith(b"ubuntu iso")


def test_build_udp_search_payload_rejects_empty() -> None:
    with pytest.raises(GlobalUdpSearchError):
        build_udp_search_payload("   ")


def test_build_udp_search_req3_prefix_layout() -> None:
    prefix = build_udp_search_req3_prefix()
    assert int.from_bytes(prefix[0:4], "little") == 1
    assert prefix[4] == 0x83  # new-tag UINT32 with numeric name id
    assert prefix[5] == 0x0E  # CT_SERVER_UDPSEARCH_FLAGS
    assert int.from_bytes(prefix[6:10], "little") == 0x01


def test_udp_framing_round_trip() -> None:
    wire = encode_udp_packet(0x98, b"\x01\x02\x03")
    assert wire[0] == EDONKEY
    assert int.from_bytes(wire[1:5], "little") == 4
    assert wire[5] == 0x98
    packet = parse_udp_packet(wire)
    assert packet.protocol == EDONKEY
    assert packet.opcode == 0x98
    assert packet.payload == b"\x01\x02\x03"


def test_udp_parse_packed_datagram_restores_edonkey() -> None:
    compressed = zlib.compress(b"payload-bytes")
    wire = bytes([0xD4]) + (len(compressed) + 1).to_bytes(4, "little") + b"\x99" + compressed
    packet = parse_udp_packet(wire)
    assert packet.protocol == EDONKEY
    assert packet.opcode == 0x99
    assert packet.payload == b"payload-bytes"


def test_udp_parse_rejects_short_datagram() -> None:
    with pytest.raises(GlobalUdpSearchError):
        parse_udp_packet(b"\xe3\x01")


def test_endpoint_validation() -> None:
    endpoint = GlobalServerEndpoint(host="176.123.5.89", port=4725)
    assert endpoint.port == 4725
    with pytest.raises(GlobalUdpSearchError):
        GlobalServerEndpoint(host="176.123.5.89", port=70_000)
    with pytest.raises(GlobalUdpSearchError):
        GlobalServerEndpoint(host="example.invalid", port=4725)


def test_aggregate_to_dict_reports_attribution() -> None:
    result = SearchResult(
        file_hash=bytes.fromhex("aabbccdd00112233445566778899eeff"),
        client_id=1,
        client_port=4662,
        tags=(),
    )
    aggregate = GlobalSearchAggregate(
        query="video",
        results=(result,),
        per_server={"176.123.5.89:4725": 1},
        dead_servers=("10.0.0.1:4661",),
    )
    decoded = aggregate.to_dict()
    assert decoded["result_count"] == 1
    assert decoded["per_server"] == {"176.123.5.89:4725": 1}
    assert decoded["dead_servers"] == ["10.0.0.1:4661"]


def test_global_search_requires_servers() -> None:
    from amuled_v2.core.ed2k import GlobalUdpSearch

    with pytest.raises(GlobalUdpSearchError):
        GlobalUdpSearch([])
