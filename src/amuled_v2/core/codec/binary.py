"""Little-endian binary reader/writer over in-memory bytes (PROTOCOL_MATRIX.md section 2).

BinaryReader and BinaryWriter wrap ``bytes``/``bytearray`` buffers and provide
deterministic little-endian read/write for integers, raw bytes, MD4-style hash16
values, and length-prefixed strings.  ``to_bytes`` / ``from_bytes`` round-trips
are deterministic for a given logical state.

src/amuled_v2/core/codec/binary.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] BinaryWriter with little-endian u8/u16/u32/u64, raw bytes, hash16,
      and length-prefixed string writers (uint16 default; latin-1 + utf-8
      helpers).
  [+] BinaryReader mirroring the writer over an immutable bytes view with
      position/remaining bounds checks and deterministic from_bytes parsing.
"""

from __future__ import annotations

import struct
from typing import Union

__all__ = ["BinaryReader", "BinaryWriter", "CodecError"]

_HASH16_SIZE = 16
_UTF8 = "utf-8"
_LATIN1 = "latin-1"


class CodecError(ValueError):
    """Raised when binary decoding encounters truncated or invalid data."""


class BinaryWriter:
    """Write little-endian primitives into an internal ``bytearray``."""

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf: bytearray = bytearray()

    # -- integer writers (little-endian) ------------------------------------
    def write_u8(self, value: int) -> None:
        if not 0 <= value <= 0xFF:
            raise ValueError(f"u8 out of range: {value}")
        self._buf.append(value)

    def write_u16(self, value: int) -> None:
        if not 0 <= value <= 0xFFFF:
            raise ValueError(f"u16 out of range: {value}")
        self._buf += struct.pack("<H", value)

    def write_u32(self, value: int) -> None:
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(f"u32 out of range: {value}")
        self._buf += struct.pack("<I", value)

    def write_u64(self, value: int) -> None:
        if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(f"u64 out of range: {value}")
        self._buf += struct.pack("<Q", value)

    # -- raw bytes -----------------------------------------------------------
    def write_bytes(self, data: Union[bytes, bytearray, memoryview]) -> None:
        data = bytes(data)
        if len(data) == 1 and isinstance(data, bytes):
            self._buf += data
        else:
            self._buf += data

    # -- hash16 (16-byte raw MD4-style digest) ------------------------------
    def write_hash16(self, digest: Union[bytes, bytearray]) -> None:
        digest = bytes(digest)
        if len(digest) != _HASH16_SIZE:
            raise ValueError(f"hash16 must be {_HASH16_SIZE} bytes, got {len(digest)}")
        self._buf += digest

    # -- strings -------------------------------------------------------------
    def write_string(self, text: str, encoding: str = _UTF8) -> None:
        encoded = text.encode(encoding)
        self.write_u16(len(encoded))
        self._buf += encoded

    def write_string_latin1(self, text: str) -> None:
        self.write_string(text, _LATIN1)

    def write_string_utf8(self, text: str) -> None:
        self.write_string(text, _UTF8)

    def write_raw_string(self, text: str, encoding: str = _UTF8) -> None:
        self._buf += text.encode(encoding)

    # -- finalisation --------------------------------------------------------
    def to_bytes(self) -> bytes:
        return bytes(self._buf)

    @property
    def length(self) -> int:
        return len(self._buf)


class BinaryReader:
    """Read little-endian primitives from an immutable ``bytes`` buffer."""

    __slots__ = ("_data", "_pos")

    def __init__(self, data: Union[bytes, bytearray, memoryview]) -> None:
        self._data: bytes = bytes(data)
        self._pos: int = 0

    # -- position / bounds --------------------------------------------------
    @property
    def position(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def _require(self, n: int) -> None:
        if self._pos + n > len(self._data):
            raise CodecError(
                f"unexpected end of data: need {n} bytes at pos {self._pos}, "
                f"only {self.remaining} remaining"
            )

    # -- integer readers (little-endian) ------------------------------------
    def read_u8(self) -> int:
        self._require(1)
        v = self._data[self._pos]
        self._pos += 1
        return v

    def read_u16(self) -> int:
        self._require(2)
        v = struct.unpack_from("<H", self._data, self._pos)[0]
        self._pos += 2
        return v

    def read_u32(self) -> int:
        self._require(4)
        v = struct.unpack_from("<I", self._data, self._pos)[0]
        self._pos += 4
        return v

    def read_u64(self) -> int:
        self._require(8)
        v = struct.unpack_from("<Q", self._data, self._pos)[0]
        self._pos += 8
        return v

    # -- raw bytes -----------------------------------------------------------
    def read_bytes(self, n: int) -> bytes:
        if n < 0:
            raise ValueError(f"negative length: {n}")
        self._require(n)
        v = self._data[self._pos : self._pos + n]
        self._pos += n
        return v

    def read_bytes_remaining(self) -> bytes:
        v = self._data[self._pos :]
        self._pos = len(self._data)
        return v

    # -- hash16 --------------------------------------------------------------
    def read_hash16(self) -> bytes:
        data = self.read_bytes(_HASH16_SIZE)
        return data

    # -- strings -------------------------------------------------------------
    def read_string(self, encoding: str = _UTF8) -> str:
        length = self.read_u16()
        raw = self.read_bytes(length)
        return raw.decode(encoding)

    def read_string_latin1(self) -> str:
        return self.read_string(_LATIN1)

    def read_string_utf8(self) -> str:
        return self.read_string(_UTF8)

    def read_raw_string(self, n: int, encoding: str = _UTF8) -> str:
        return self.read_bytes(n).decode(encoding)

    # -- deterministic round-trip -------------------------------------------
    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray, memoryview]) -> "BinaryReader":
        return cls(data)
