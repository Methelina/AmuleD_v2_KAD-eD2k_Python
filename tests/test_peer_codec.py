"""Offline tests for the peer (client-to-client) codec.

Round-trip and malformed-input checks only; no network, no fake peers.

tests/test_peer_codec.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Tested hello, hashset, parts, and queue-rank round trips.
  [+] Tested I64 variants, compressed parts, and malformed payloads.
"""

from __future__ import annotations

import zlib

import pytest

from amuled_v2.core.codec.binary import BinaryWriter
from amuled_v2.core.peer import (
    PeerCodecError,
    build_hello_payload,
    build_hello_answer_payload,
    build_request_filename_payload,
    build_request_parts_payload,
    build_request_parts_i64_payload,
    parse_compressed_part,
    parse_compressed_part_i64,
    parse_file_hash_payload,
    parse_filename_answer,
    parse_hashset_answer,
    parse_hello,
    parse_hello_answer,
    parse_file_status,
    parse_queue_rank,
    parse_request_parts,
    parse_request_parts_i64,
    parse_sending_part,
    parse_sending_part_i64,
)


_HASH16_A = bytes(range(16))
_HASH16_B = bytes(reversed(range(16)))


def test_hello_round_trip() -> None:
    payload = build_hello_payload(
        user_hash=_HASH16_A,
        client_id=0x11223344,
        client_port=4662,
        nickname="AmuleD",
    )
    hello = parse_hello(payload)
    assert hello.user_hash == _HASH16_A
    assert hello.client_id == 0x11223344
    assert hello.client_port == 4662
    assert hello.nickname == "AmuleD"
    assert hello.version == 0x3C
    nick_tags = [t for t in hello.tags if t.name_id == 0x01]
    assert nick_tags, "nickname tag (0x01) must be present"


def test_hello_rejects_bad_hash() -> None:
    with pytest.raises(PeerCodecError):
        build_hello_payload(
            user_hash=b"\x00" * 15,
            client_id=0,
            client_port=0,
            nickname="x",
        )


def test_hello_answer_round_trip() -> None:
    payload = build_hello_answer_payload(
        user_hash=_HASH16_B,
        client_id=0x11223344,
        client_port=4662,
        nickname="AmuleD",
        server_ip=0x7B00_0559,
        server_port=4725,
    )
    answer = parse_hello_answer(payload)
    assert answer.user_hash == _HASH16_B
    assert answer.client_id == 0x11223344
    assert answer.client_port == 4662
    assert answer.nickname == "AmuleD"
    assert answer.version == 0x3C
    assert answer.server_ip == 0x7B00_0559
    assert answer.server_port == 4725


def test_file_hash_payload_round_trip() -> None:
    payload = build_request_filename_payload(_HASH16_A)
    assert parse_file_hash_payload(payload) == _HASH16_A
    trailing = payload + b"\x00"
    with pytest.raises(PeerCodecError):
        parse_file_hash_payload(trailing)


def test_filename_answer_round_trip() -> None:
    name = "movie.mp4"
    writer = BinaryWriter()
    writer.write_hash16(_HASH16_A)
    writer.write_u16(len(name.encode("utf-8")))
    writer.write_raw_string(name, "utf-8")
    payload = writer.to_bytes()
    answer = parse_filename_answer(payload)
    assert answer.file_hash == _HASH16_A
    assert answer.name == name


def test_hashset_answer_round_trip() -> None:
    file_hash = _HASH16_A
    chunk_hashes = [bytes([i] * 16) for i in range(1, 10)]
    writer = BinaryWriter()
    writer.write_u16(len(chunk_hashes) + 1)
    writer.write_hash16(file_hash)
    for ch in chunk_hashes:
        writer.write_hash16(ch)
    payload = writer.to_bytes()
    answer = parse_hashset_answer(payload)
    assert answer.file_hash == file_hash
    assert len(answer.chunk_hashes) == 9
    assert tuple(answer.chunk_hashes) == tuple(chunk_hashes)
    truncated = payload[:-16]
    with pytest.raises(PeerCodecError):
        parse_hashset_answer(truncated)


def test_file_status_round_trip() -> None:
    chunk_count = 9
    bit_array = bytearray((chunk_count + 7) // 8)
    for bit in (0, 3, 8):
        bit_array[bit // 8] |= 1 << (bit % 8)
    writer = BinaryWriter()
    writer.write_hash16(_HASH16_A)
    writer.write_u16(chunk_count)
    writer.write_bytes(bytes(bit_array))
    payload = writer.to_bytes()
    status = parse_file_status(payload)
    assert status.file_hash == _HASH16_A
    assert status.chunk_count == 9
    assert status.present_chunks == (0, 3, 8)


def test_request_parts_round_trip() -> None:
    starts = (0, 9_728_400, 19_456_800)
    ends = (9_728_400, 19_456_800, 20_000_000)
    payload = build_request_parts_payload(_HASH16_A, starts, ends)
    parsed = parse_request_parts(payload)
    assert parsed.file_hash == _HASH16_A
    assert parsed.starts == starts
    assert parsed.ends == ends


def test_request_parts_i64_round_trip() -> None:
    starts = (0, 5_000_000_000, 6_000_000_000)
    ends = (5_000_000_000, 6_000_000_000, 7_000_000_000)
    payload = build_request_parts_i64_payload(_HASH16_A, starts, ends)
    parsed = parse_request_parts_i64(payload)
    assert parsed.file_hash == _HASH16_A
    assert parsed.starts == starts
    assert parsed.ends == ends


def test_sending_part_round_trip() -> None:
    data = b"x" * 1000
    start = 500
    end = 1500
    writer = BinaryWriter()
    writer.write_hash16(_HASH16_A)
    writer.write_u32(start)
    writer.write_u32(end)
    writer.write_bytes(data)
    payload = writer.to_bytes()
    part = parse_sending_part(payload)
    assert part.file_hash == _HASH16_A
    assert part.start == start
    assert part.end == end
    assert part.data == data
    assert part.data_size == 1000


def test_sending_part_i64_round_trip() -> None:
    data = b"x" * 1000
    start = 5_000_000_000
    end = 5_000_000_000 + 1000
    writer = BinaryWriter()
    writer.write_hash16(_HASH16_A)
    writer.write_u64(start)
    writer.write_u64(end)
    writer.write_bytes(data)
    payload = writer.to_bytes()
    part = parse_sending_part_i64(payload)
    assert part.file_hash == _HASH16_A
    assert part.start == start
    assert part.end == end
    assert part.data == data
    assert part.data_size == 1000


def test_sending_part_length_mismatch_raises() -> None:
    start = 0
    end = 100
    writer = BinaryWriter()
    writer.write_hash16(_HASH16_A)
    writer.write_u32(start)
    writer.write_u32(end)
    writer.write_bytes(b"x" * 10)
    payload = writer.to_bytes()
    with pytest.raises(PeerCodecError):
        parse_sending_part(payload)


def test_compressed_part_round_trip() -> None:
    raw = b"y" * 5000
    compressed = zlib.compress(raw)
    start = 0
    writer = BinaryWriter()
    writer.write_hash16(_HASH16_A)
    writer.write_u32(start)
    writer.write_u32(len(compressed))
    writer.write_bytes(compressed)
    payload = writer.to_bytes()
    part = parse_compressed_part(payload)
    assert part.file_hash == _HASH16_A
    assert part.start == start
    assert part.data == raw
    assert part.data_size == 5000


def test_compressed_part_i64_round_trip() -> None:
    raw = b"y" * 5000
    compressed = zlib.compress(raw)
    start = 5_000_000_000
    writer = BinaryWriter()
    writer.write_hash16(_HASH16_A)
    writer.write_u64(start)
    writer.write_u32(len(compressed))
    writer.write_bytes(compressed)
    payload = writer.to_bytes()
    part = parse_compressed_part_i64(payload)
    assert part.file_hash == _HASH16_A
    assert part.start == start
    assert part.data == raw
    assert part.data_size == 5000


def test_queue_rank_round_trip() -> None:
    writer = BinaryWriter()
    writer.write_u32(42)
    payload = writer.to_bytes()
    assert parse_queue_rank(payload) == 42
