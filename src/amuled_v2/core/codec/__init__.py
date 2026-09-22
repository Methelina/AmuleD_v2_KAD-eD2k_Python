"""M3 wire codec layer: binary IO, packet framing, ED2K tags, zlib (PROTOCOL_MATRIX.md section 2).

Re-exports the public codec API so callers import from ``core.codec`` directly.

src/amuled_v2/core/codec/__init__.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Package marker re-exporting constants, BinaryReader, BinaryWriter,
      Ed2kTag, write_new_tag, read_new_tag, Packet, encode_packet,
      decode_packet, pack_packet, unpack_packet, and zlib helpers.
"""

from .constants import (
    BLOCKSIZE,
    EDONKEY,
    EMULE,
    HASH16,
    KAD,
    KADEMLIAPACKED,
    PACKED,
    PARTSIZE,
    STRING,
    STR1,
    STR16,
    BLOB,
    BOOL,
    BOOLARRAY,
    FLOAT32,
    UINT8,
    UINT16,
    UINT32,
    UINT64,
    BSOB,
    TAG_COMPRESSED,
)
from .binary import BinaryReader, BinaryWriter, CodecError
from .zlib_compat import decompress_payload, compress_payload
from .tags import Ed2kTag, TagError, read_new_tag, write_new_tag
from .packet import Packet, PacketError, decode_packet, encode_packet, pack_packet, unpack_packet

__all__ = [
    "EDONKEY",
    "EMULE",
    "PACKED",
    "KAD",
    "KADEMLIAPACKED",
    "PARTSIZE",
    "STRING",
    "BLOCKSIZE",
    "HASH16",
    "STR1",
    "STR16",
    "BLOB",
    "BOOL",
    "BOOLARRAY",
    "FLOAT32",
    "UINT8",
    "UINT16",
    "UINT32",
    "UINT64",
    "BSOB",
    "TAG_COMPRESSED",
    "BinaryReader",
    "BinaryWriter",
    "CodecError",
    "TagError",
    "PacketError",
    "decompress_payload",
    "compress_payload",
    "Ed2kTag",
    "read_new_tag",
    "write_new_tag",
    "Packet",
    "encode_packet",
    "decode_packet",
    "pack_packet",
    "unpack_packet",
]
