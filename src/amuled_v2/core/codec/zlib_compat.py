"""zlib helpers for packed ED2K/Kad payloads.

Provides small wrappers over the standard-library zlib implementation.  A
packed packet compresses only its payload; packet protocol and opcode remain in
the packet header.

src/amuled_v2/core/codec/zlib_compat.py
Version:     0.2.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.2.0 (Soror L.'.L'.):
  [+] Added bounded decompression to protect packet decoding from bombs.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Initial zlib payload wrappers.
"""

from __future__ import annotations

import zlib

__all__ = ["compress_payload", "decompress_payload"]


def compress_payload(data: bytes, level: int = 9) -> bytes:
    """Compress *data* with zlib."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes-like")
    if not 0 <= level <= 9:
        raise ValueError(f"invalid zlib compression level: {level}")
    return zlib.compress(bytes(data), level)


def decompress_payload(data: bytes, max_size: int | None = None) -> bytes:
    """Decompress a zlib payload, optionally enforcing a maximum output size."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("compressed payload must be bytes-like")
    if max_size is not None and max_size < 0:
        raise ValueError("max_size must be non-negative")
    if max_size is None:
        return zlib.decompress(bytes(data))
    decompressor = zlib.decompressobj()
    try:
        output = decompressor.decompress(bytes(data), max_size + 1)
        output += decompressor.flush()
    except zlib.error as exc:
        raise ValueError(f"malformed zlib payload: {exc}") from exc
    if len(output) > max_size:
        raise ValueError(f"decompressed payload exceeds maximum size: {max_size}")
    if not decompressor.eof:
        raise ValueError("truncated or malformed zlib payload")
    return output
