"""ED2K new-tag system reader/writer.

Implements the wire layout described by ``docs/PROTOCOL_MATRIX.md``, section 2:
a tag type byte, a string or numeric tag identifier, and a type-specific value.
Integer values are encoded in the smallest compatible unsigned type.  UTF-8
string values from one to sixteen bytes use the STR1..STR16 compact value types.

src/amuled_v2/core/codec/tags.py
Version:     0.2.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.2.0 (Soror L.'.L'.):
  [*] Corrected tag identity semantics: STR1..STR16 encode the value length and
      coexist with either a string name or a numeric name id.
  [*] Restored the 0x80 numeric-name flag and one-byte name identifier layout.
  [*] Added bounded BLOB and BSOB decoding plus UINT8/UINT16 normalization.
  [*] Rejected malformed or truncated tags without consuming unrelated data.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Initial ED2K tag model and new-format codec.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Optional

from . import constants as C
from .binary import BinaryReader, BinaryWriter, CodecError

__all__ = ["Ed2kTag", "TagError", "write_new_tag", "read_new_tag"]


class TagError(ValueError):
    """Raised when a tag cannot be encoded or decoded."""


@dataclass(frozen=True)
class Ed2kTag:
    """One ED2K protocol tag.

    Exactly one identifier is required: either ``name`` for a normal string
    tag or ``name_id`` for the compact numeric-name form.
    """

    name: Optional[str] = None
    name_id: Optional[int] = None
    type: int = C.UINT32
    value: Any = 0

    def __post_init__(self) -> None:
        if (self.name is None) == (self.name_id is None):
            raise TagError("exactly one of name or name_id is required")
        if self.name is not None and not isinstance(self.name, str):
            raise TagError("tag name must be a string")
        if self.name_id is not None and not 0 <= self.name_id <= 0xFF:
            raise TagError(f"name_id out of range 0..255: {self.name_id}")


def _encoded_string(value: Any) -> bytes:
    if isinstance(value, str):
        try:
            return value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise TagError("string value is not valid Unicode") from exc
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise TagError("string tag value must be str or bytes")


def _narrow_int(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TagError("integer tag value must be int")
    if 0 <= value <= 0xFF:
        return C.UINT8
    if value <= 0xFFFF:
        return C.UINT16
    if value <= 0xFFFFFFFF:
        return C.UINT32
    if value <= 0xFFFFFFFFFFFFFFFF:
        return C.UINT64
    raise TagError("integer tag value exceeds UINT64")


def _string_wire_type(raw_value: bytes) -> int:
    if 1 <= len(raw_value) <= 16:
        return C.STR1 + len(raw_value) - 1
    return C.STRING


def _write_string_value(raw_value: bytes, wire_type: int, writer: BinaryWriter) -> None:
    if C.STR1 <= wire_type <= C.STR16:
        writer.write_bytes(raw_value)
        return
    writer.write_u16(len(raw_value))
    writer.write_bytes(raw_value)


def _write_value(tag: Ed2kTag, wire_type: int, writer: BinaryWriter) -> None:
    value = tag.value
    if wire_type in (C.UINT8, C.UINT16, C.UINT32, C.UINT64):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TagError("unsigned integer tag value must be int")
        if wire_type == C.UINT8:
            writer.write_u8(value)
        elif wire_type == C.UINT16:
            writer.write_u16(value)
        elif wire_type == C.UINT32:
            writer.write_u32(value)
        else:
            writer.write_u64(value)
        return

    if wire_type == C.STRING or C.STR1 <= wire_type <= C.STR16:
        _write_string_value(_encoded_string(value), wire_type, writer)
        return

    if wire_type == C.FLOAT32:
        try:
            writer.write_bytes(struct.pack("<f", float(value)))
        except (TypeError, ValueError, OverflowError) as exc:
            raise TagError("invalid FLOAT32 tag value") from exc
        return

    if wire_type == C.HASH16:
        raw = bytes(value)
        writer.write_hash16(raw)
        return

    if wire_type == C.BOOL:
        if not isinstance(value, bool):
            raise TagError("BOOL tag value must be bool")
        writer.write_u8(1 if value else 0)
        return

    if wire_type == C.BLOB:
        if not isinstance(value, (bytes, bytearray)):
            raise TagError("BLOB tag value must be bytes")
        raw = bytes(value)
        if len(raw) > 0xFFFFFFFF:
            raise TagError("BLOB tag value exceeds UINT32 size")
        writer.write_u32(len(raw))
        writer.write_bytes(raw)
        return

    if wire_type == C.BSOB:
        if not isinstance(value, (bytes, bytearray)):
            raise TagError("BSOB tag value must be bytes")
        raw = bytes(value)
        if len(raw) > 0xFF:
            raise TagError("BSOB tag value exceeds UINT8 size")
        writer.write_u8(len(raw))
        writer.write_bytes(raw)
        return

    raise TagError(f"unsupported tag type: 0x{wire_type:02X}")


def write_new_tag(tag: Ed2kTag, writer: BinaryWriter) -> None:
    """Encode one new-format ED2K tag into *writer*."""
    if tag.type == C.STRING or C.STR1 <= tag.type <= C.STR16:
        raw_value = _encoded_string(tag.value)
        wire_type = _string_wire_type(raw_value)
    elif tag.type in (C.UINT8, C.UINT16, C.UINT32, C.UINT64):
        if tag.type == C.UINT32:
            wire_type = _narrow_int(tag.value)
        else:
            wire_type = tag.type
            _narrow_int(tag.value)
    else:
        wire_type = tag.type

    if tag.name_id is not None:
        writer.write_u8(wire_type | 0x80)
        writer.write_u8(tag.name_id)
    else:
        encoded_name = tag.name.encode("utf-8")
        if len(encoded_name) > 0xFFFF:
            raise TagError("tag name exceeds UINT16 length")
        writer.write_u8(wire_type)
        writer.write_u16(len(encoded_name))
        writer.write_bytes(encoded_name)

    _write_value(tag, wire_type, writer)


def _read_identifier(reader: BinaryReader, type_byte: int) -> tuple[Optional[str], Optional[int]]:
    if type_byte & 0x80:
        return None, reader.read_u8()

    name_length = reader.read_u16()
    if name_length == 1:
        return None, reader.read_u8()
    try:
        return reader.read_bytes(name_length).decode("utf-8"), None
    except UnicodeDecodeError as exc:
        raise TagError("tag name is not valid UTF-8") from exc


def _read_string_value(reader: BinaryReader, tag_type: int) -> str:
    if C.STR1 <= tag_type <= C.STR16:
        raw = reader.read_bytes(tag_type - C.STR1 + 1)
    else:
        raw = reader.read_bytes(reader.read_u16())
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _read_value(reader: BinaryReader, tag_type: int) -> Any:
    try:
        if tag_type == C.STRING or C.STR1 <= tag_type <= C.STR16:
            return _read_string_value(reader, tag_type)
        if tag_type == C.HASH16:
            return reader.read_hash16()
        if tag_type == C.FLOAT32:
            return struct.unpack("<f", reader.read_bytes(4))[0]
        if tag_type == C.BOOL:
            return reader.read_u8() != 0
        if tag_type == C.UINT8:
            return reader.read_u8()
        if tag_type == C.UINT16:
            return reader.read_u16()
        if tag_type == C.UINT32:
            return reader.read_u32()
        if tag_type == C.UINT64:
            return reader.read_u64()
        if tag_type == C.BLOB:
            return reader.read_bytes(reader.read_u32())
        if tag_type == C.BSOB:
            return reader.read_bytes(reader.read_u8())
        if tag_type == C.BOOLARRAY:
            bool_count = reader.read_u16()
            reader.read_bytes((bool_count // 8) + 1)
            return None
    except CodecError:
        raise
    raise TagError(f"unsupported tag type: 0x{tag_type:02X}")


def read_new_tag(reader: BinaryReader) -> Ed2kTag:
    """Decode one new-format ED2K tag from *reader*."""
    type_byte = reader.read_u8()
    if type_byte & 0x80:
        tag_type = type_byte & 0x7F
    else:
        tag_type = type_byte

    name, name_id = _read_identifier(reader, type_byte)

    value = _read_value(reader, tag_type)
    if C.STR1 <= tag_type <= C.STR16 or tag_type in (C.UINT8, C.UINT16):
        normalized_type = C.STRING if C.STR1 <= tag_type <= C.STR16 else C.UINT32
    else:
        normalized_type = tag_type

    return Ed2kTag(name=name, name_id=name_id, type=normalized_type, value=value)
