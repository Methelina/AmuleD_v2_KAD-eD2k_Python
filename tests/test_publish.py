"""Offline tests for the Kad2 publish client (core/kad/publish.py).

Author: Soror L.'.L.'.
"""

from __future__ import annotations

import struct

from amuled_v2.core.kad.packets import (
    KAD_PROTOCOL,
    KADEMLIA2_PUBLISH_KEY_REQ,
    KADEMLIA2_PUBLISH_RES_ACK,
    build_publish_res_ack,
    parse_publish_res,
)
from amuled_v2.core.kad.publish import (
    PublishReport,
    PublishTarget,
    _keyword_file_tags,
    _source_tags,
)


def _read_tag(buf: bytes, pos: int) -> tuple[int, bytes, object, int]:
    """Minimal Kad tag reader mirroring DataIO.cpp ReadTag."""
    tag_type = buf[pos]
    pos += 1
    name_len = struct.unpack_from("<H", buf, pos)[0]
    pos += 2
    name = buf[pos:pos + name_len]
    pos += name_len
    if tag_type == 0x02:  # string
        n = struct.unpack_from("<H", buf, pos)[0]
        pos += 2
        value = buf[pos:pos + n].decode("utf-8")
        pos += n
    elif tag_type == 0x03:  # uint32
        value = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
    elif tag_type == 0x08:  # uint16
        value = struct.unpack_from("<H", buf, pos)[0]
        pos += 2
    elif tag_type == 0x09:  # uint8
        value = buf[pos]
        pos += 1
    elif tag_type == 0x0B:  # uint64
        value = struct.unpack_from("<Q", buf, pos)[0]
        pos += 8
    else:
        raise AssertionError(f"unexpected tag type {tag_type:#x} in test")
    return tag_type, name, value, pos


def _parse_tag_list(raw: bytes | tuple[bytes, int], count: int) -> list[tuple[int, bytes, object]]:
    # The packets.py builders prepend the count byte; publish._build_tag_list_raw
    # does not.  Simulate the on-wire form here.  Accepts either the raw body
    # or the (body, n) pair returned by the publish tag builders.
    if isinstance(raw, tuple):
        raw, count = raw
    raw = bytes((count,)) + raw
    pos = 1
    tags = []
    for _ in range(count):
        tag_type, name, value, pos = _read_tag(raw, pos)
        tags.append((tag_type, name, value))
    assert pos == len(raw)
    return tags


def test_keyword_file_tags_layout() -> None:
    # Mirrors CSearch::StorePacket STOREKEYWORD / PreparePacketForTags:
    # TAG_FILENAME (string) + TAG_FILESIZE (uint32 for <=4GB).
    raw = _keyword_file_tags("test-file.bin", 12345)
    tags = _parse_tag_list(raw, 2)
    assert tags[0] == (0x02, b"\x01", "test-file.bin")
    assert tags[1] == (0x03, b"\x02", 12345)


def test_keyword_file_tags_size_over_4gb_bsob() -> None:
    body, count = _keyword_file_tags("big.bin", 5 * 1024**3)
    assert count == 2
    # Wire form: count byte + tags.
    wire = bytes((count,)) + body
    assert wire[0] == 2
    # Second tag: type BSOB(0x0A), name 0x02, size 8, LE uint64 value.
    pos = 1
    _t, name, value, pos = _read_tag(wire, pos)
    assert name == b"\x01"
    tag_type = wire[pos]
    assert tag_type == 0x0A
    name_len = struct.unpack_from("<H", wire, pos + 1)[0]
    name = wire[pos + 3:pos + 3 + name_len]
    assert name == b"\x02"
    bsob_size = wire[pos + 3 + name_len]
    assert bsob_size == 8
    size = struct.unpack_from("<Q", wire, pos + 4 + name_len)[0]
    assert size == 5 * 1024**3


def test_source_tags_highid_layout() -> None:
    # Mirrors CSearch::StorePacket STOREFILE HighID branch (Search.cpp:900-913):
    # SOURCETYPE(1), SOURCEPORT(uint32), SOURCEUPORT(uint16), FILESIZE(uint32).
    raw = _source_tags(
        4662, udp_port=4672, file_size=999, encryption=0, source_type=1
    )
    tags = _parse_tag_list(raw, 4)
    assert tags == [
        (0x09, b"\xFF", 1),
        (0x03, b"\xFD", 4662),
        (0x08, b"\xFC", 4672),
        (0x03, b"\x02", 999),
    ]


def test_source_tags_omits_optional() -> None:
    raw = _source_tags(4662, udp_port=None, file_size=0, encryption=0)
    tags = _parse_tag_list(raw, 2)
    assert tags == [(0x09, b"\xFF", 1), (0x03, b"\xFD", 4662)]


def test_publish_res_ack_is_null_packet() -> None:
    datagram = build_publish_res_ack()
    assert datagram == bytes((KAD_PROTOCOL, KADEMLIA2_PUBLISH_RES_ACK))


def test_parse_publish_res_with_ack_option() -> None:
    file_hash = bytes(range(16))
    payload = file_hash + bytes((7, 0x01))
    res = parse_publish_res(payload)
    assert res.file_hash.to_bytes() == file_hash
    assert res.load == 7
    assert res.ack_requested is True


def test_parse_publish_res_without_options() -> None:
    file_hash = bytes(range(16))
    payload = file_hash + bytes((3,))
    res = parse_publish_res(payload)
    assert res.load == 3
    assert res.ack_requested is False


def test_publish_report_roundtrip() -> None:
    from amuled_v2.core.kad.packets import KadUInt128

    target = KadUInt128(bytes(16))
    tgt = PublishTarget(
        kad_id=target, ip="1.2.3.4", udp_port=5678,
        tcp_port=4662, contact_version=8,
    )
    report = PublishReport(
        target=target,
        publish_op="KADEMLIA2_PUBLISH_KEY_REQ",
        targets=[tgt],
        accepts=[tgt],
        acks_sent=[("1.2.3.4", 5678)],
        avg_load=12.5,
        published=1,
        duration_s=1.25,
    )
    d = report.to_dict()
    assert d["publish_op"] == "KADEMLIA2_PUBLISH_KEY_REQ"
    assert d["accepts"][0]["ip"] == "1.2.3.4"
    assert d["accepts"][0]["contact_version"] == 8
    assert d["acks_sent"] == [{"ip": "1.2.3.4", "port": 5678}]
    assert d["avg_load"] == 12.5


def test_publish_key_req_wire_layout() -> None:
    # Regression: the tag-list count byte must appear EXACTLY once on the
    # wire (packets._build_tag_list prepends it; publish tag builders must
    # not).  Mirrors Search.cpp STOREKEYWORD packet assembly.
    from amuled_v2.core.kad.packets import KadUInt128, build_publish_key_req

    kw = KadUInt128(bytes(16))
    fh = KadUInt128(bytes(range(16)))
    tag_bytes, tag_count = _keyword_file_tags("a.bin", 5)
    payload = build_publish_key_req(kw, [(fh, tag_bytes, tag_count)])
    assert payload[0:16] == bytes(16)                    # uTarget
    assert struct.unpack_from("<H", payload, 16)[0] == 1  # uCount
    assert payload[18:34] == bytes(range(16))            # file hash
    assert payload[34] == 2                              # tag count (once!)
    assert payload[35] == 0x02                           # TAGTYPE_STRING
    assert struct.unpack_from("<H", payload, 36)[0] == 1
    assert payload[38] == 0x01                           # TAG_FILENAME
    assert struct.unpack_from("<H", payload, 39)[0] == 5
    assert payload[41:46] == b"a.bin"

