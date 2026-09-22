"""Tests for the M3 ED2K/Kad wire codec layer.

Covers little-endian primitive IO, ED2K new-format tag encoding, packet framing,
and packed-payload behavior.  All tests are local, deterministic, and do not use
the network.

tests/test_codec.py
Version:     0.2.1
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.2.1 (Soror L.'.L'.):
  [*] Updated packet tests to the corrected wire order: protocol, length,
      opcode; packet length includes the opcode byte.
  [*] Updated tags to the corrected identifier/value semantics.
  [*] Updated packed packets to compress payload only while preserving opcode.
  [+] Added malformed-packet, zlib-boundary, STR16 boundary, and trailing-byte
      tests.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Initial binary, tag, packet, and zlib coverage.
"""

from __future__ import annotations

import os
import struct
import zlib

import pytest

from amuled_v2.core.codec import (
    BLOCKSIZE,
    BLOB,
    EDONKEY,
    EMULE,
    FLOAT32,
    HASH16,
    KAD,
    KADEMLIAPACKED,
    PACKED,
    PARTSIZE,
    STRING,
    UINT16,
    UINT32,
    UINT64,
    UINT8,
    BinaryReader,
    BinaryWriter,
    Ed2kTag,
    Packet,
    CodecError,
    PacketError,
    TagError,
    compress_payload,
    decode_packet,
    decompress_payload,
    encode_packet,
    pack_packet,
    read_new_tag,
    unpack_packet,
    write_new_tag,
)


def _roundtrip_tag(tag: Ed2kTag) -> Ed2kTag:
    writer = BinaryWriter()
    write_new_tag(tag, writer)
    return read_new_tag(BinaryReader(writer.to_bytes()))


def test_constants_match_protocol_matrix() -> None:
    assert EDONKEY == 0xE3
    assert EMULE == 0xC5
    assert PACKED == 0xD4
    assert KAD == 0xE4
    assert KADEMLIAPACKED == 0xE5
    assert PARTSIZE == 9_728_000
    assert BLOCKSIZE == 184_320


def test_binary_integer_little_endian_layout() -> None:
    writer = BinaryWriter()
    writer.write_u8(0x12)
    writer.write_u16(0x3456)
    writer.write_u32(0x789ABCDF)
    writer.write_u64(0x0102030405060708)
    raw = writer.to_bytes()
    assert raw == bytes.fromhex("125634" + "dfbc9a78" + "0807060504030201")

    reader = BinaryReader(raw)
    assert reader.read_u8() == 0x12
    assert reader.read_u16() == 0x3456
    assert reader.read_u32() == 0x789ABCDF
    assert reader.read_u64() == 0x0102030405060708
    assert reader.remaining == 0


def test_binary_string_hash_and_bounds() -> None:
    writer = BinaryWriter()
    digest = bytes.fromhex("00112233445566778899aabbccddeeff")
    writer.write_string_utf8("filename.bin")
    writer.write_hash16(digest)
    raw = writer.to_bytes()

    reader = BinaryReader(raw)
    assert reader.read_string_utf8() == "filename.bin"
    assert reader.read_hash16() == digest
    assert reader.remaining == 0
    with pytest.raises(CodecError):
        reader.read_u8()
    with pytest.raises(ValueError):
        writer.write_hash16(b"short")


def test_named_string_tag_uses_compact_value_type() -> None:
    tag = Ed2kTag(name="NAME", type=STRING, value="abc")
    writer = BinaryWriter()
    write_new_tag(tag, writer)
    raw = writer.to_bytes()

    # STRING compact value type 0x13, uint16 name length, name, raw value.
    assert raw[0] == 0x13
    assert raw[1:3] == struct.pack("<H", 4)
    assert raw[3:7] == b"NAME"
    assert raw[7:] == b"abc"

    decoded = read_new_tag(BinaryReader(raw))
    assert decoded == Ed2kTag(name="NAME", type=STRING, value="abc")


def test_named_long_string_tag_uses_length_prefix() -> None:
    value = "x" * 17
    decoded = _roundtrip_tag(Ed2kTag(name="LONG", type=STRING, value=value))
    assert decoded.name == "LONG"
    assert decoded.type == STRING
    assert decoded.value == value


def test_numeric_integer_tag_is_flagged_and_narrowed() -> None:
    tag = Ed2kTag(name_id=0x15, type=UINT32, value=300)
    writer = BinaryWriter()
    write_new_tag(tag, writer)
    raw = writer.to_bytes()

    # UINT16 wire type with numeric-name flag, numeric id, value.
    assert raw[0] == (UINT16 | 0x80)
    assert raw[1] == 0x15
    assert raw[2:4] == struct.pack("<H", 300)

    decoded = read_new_tag(BinaryReader(raw))
    assert decoded.name is None
    assert decoded.name_id == 0x15
    assert decoded.type == UINT32
    assert decoded.value == 300


def test_numeric_tags_roundtrip_all_integer_widths() -> None:
    for value, source_type in ((255, UINT32), (65_535, UINT32), (4_294_967_295, UINT32), (18_446_744_073_709_551_615, UINT64)):
        decoded = _roundtrip_tag(Ed2kTag(name="SIZE", type=source_type, value=value))
        assert decoded.value == value
        if value <= 0xFFFFFFFF:
            assert decoded.type == UINT32
        else:
            assert decoded.type == UINT64


def test_float_hash_and_blob_tags_roundtrip() -> None:
    digest = bytes(range(16))
    blob = b"\x00\x01\xffbinary payload"
    float_tag = _roundtrip_tag(Ed2kTag(name="RATIO", type=FLOAT32, value=1.5))
    hash_tag = _roundtrip_tag(Ed2kTag(name="HASH", type=HASH16, value=digest))
    blob_tag = _roundtrip_tag(Ed2kTag(name_id=0x20, type=BLOB, value=blob))
    assert float_tag.value == pytest.approx(1.5)
    assert hash_tag.value == digest
    assert blob_tag.name_id == 0x20
    assert blob_tag.value == blob


def test_tag_requires_exactly_one_identifier() -> None:
    with pytest.raises(TagError):
        Ed2kTag(type=UINT32, value=1)
    with pytest.raises(TagError):
        Ed2kTag(name="A", name_id=1, type=UINT32, value=1)
    with pytest.raises(TagError):
        Ed2kTag(name_id=256, type=UINT32, value=1)


def test_truncated_tag_raises_without_success() -> None:
    tag = Ed2kTag(name="NAME", type=STRING, value="abcdef")
    writer = BinaryWriter()
    write_new_tag(tag, writer)
    raw = writer.to_bytes()
    with pytest.raises(CodecError):
        read_new_tag(BinaryReader(raw[:-1]))


def test_packet_header_layout_and_remainder() -> None:
    packet = Packet(protocol=EDONKEY, opcode=0x01, payload=b"payload")
    raw = encode_packet(packet)
    assert raw[0] == EDONKEY
    assert raw[1:5] == struct.pack("<I", len(packet.payload) + 1)
    assert raw[5] == 0x01
    assert raw[6:] == b"payload"

    decoded, remainder = decode_packet(raw + b"next")
    assert decoded == packet
    assert remainder == b"next"


def test_decode_rejects_short_and_truncated_packets() -> None:
    with pytest.raises(PacketError):
        decode_packet(b"\xe3\x01\x00")
    packet = Packet(protocol=EDONKEY, opcode=0x01, payload=b"12345")
    raw = encode_packet(packet)
    with pytest.raises(PacketError):
        decode_packet(raw[:-1])


def test_packed_packet_compresses_payload_only() -> None:
    original = Packet(protocol=EDONKEY, opcode=0x33, payload=b"repeated" * 128)
    packed_raw = pack_packet(original, compression_level=9)
    assert packed_raw[0] == PACKED
    assert packed_raw[5] == 0x33
    payload_size = struct.unpack_from("<I", packed_raw, 1)[0] - 1
    compressed_payload = packed_raw[6 : 6 + payload_size]
    assert zlib.decompress(compressed_payload) == original.payload
    assert len(compressed_payload) < len(original.payload)

    decoded, remainder = unpack_packet(packed_raw)
    assert remainder == b""
    assert decoded.opcode == 0x33
    assert decoded.protocol == EMULE
    assert decoded.payload == original.payload


def test_packed_kad_packet_preserves_kad_family() -> None:
    original = Packet(protocol=KAD, opcode=0x30, payload=b"kad payload" * 64)
    packed_raw = pack_packet(original, compression_level=9)
    assert packed_raw[0] == KADEMLIAPACKED
    assert packed_raw[5] == 0x30
    decoded, _ = unpack_packet(packed_raw)
    assert decoded.protocol == KAD
    assert decoded.payload == original.payload


def test_pack_leaves_incompressible_payload_unpacked() -> None:
    payload = os.urandom(1024)
    original = Packet(protocol=EDONKEY, opcode=0x16, payload=payload)
    raw = pack_packet(original)
    assert raw[0] == EDONKEY
    assert raw[5] == 0x16
    decoded, _ = decode_packet(raw)
    assert decoded == original


def test_unpack_rejects_invalid_zlib_payload() -> None:
    packet = Packet(protocol=PACKED, opcode=0x16, payload=b"not zlib")
    raw = encode_packet(packet)
    with pytest.raises(PacketError):
        unpack_packet(raw)


def test_zlib_helpers_roundtrip_and_bound_output() -> None:
    source = b"bounded zlib payload" * 100
    compressed = compress_payload(source, level=9)
    assert decompress_payload(compressed) == source
    assert decompress_payload(compressed, max_size=len(source)) == source
    with pytest.raises(ValueError):
        decompress_payload(compressed, max_size=len(source) - 1)
    with pytest.raises(ValueError):
        decompress_payload(b"not zlib", max_size=100)
