"""Protocol and tag-type constants for the ED2K/Kad wire codec (PROTOCOL_MATRIX.md sections 1-2).

Constants are transcribed facts from the ED2K/Kad header files; no code logic is
derived from GPL sources. All values are wire identifiers, not behaviour.

src/amuled_v2/core/codec/constants.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Protocol family bytes: EDONKEY, EMULE, PACKED, KAD, KADEMLIAPACKED.
  [+] Tag-type identifiers: HASH16, STRING, UINT32, FLOAT32, BOOL, BOOLARRAY,
      BLOB, UINT16, UINT8, BSOB, UINT64, STR1=0x11..STR22=0x26, TAG_COMPRESSED.
  [+] Transfer constants: PARTSIZE, BLOCKSIZE.
"""

__all__ = [
    "EDONKEY",
    "EMULE",
    "PACKED",
    "KAD",
    "KADEMLIAPACKED",
    "PARTSIZE",
    "BLOCKSIZE",
    "HASH16",
    "STRING",
    "UINT32",
    "FLOAT32",
    "BOOL",
    "BOOLARRAY",
    "BLOB",
    "UINT16",
    "UINT8",
    "BSOB",
    "UINT64",
    "STR1",
    "STR22",
    "STR16",
    "TAG_COMPRESSED",
]

# ---------------------------------------------------------------------------
# Protocol family header bytes (PROTOCOL_MATRIX.md section 1, Protocols.h)
# ---------------------------------------------------------------------------
EDONKEY = 0xE3
EMULE = 0xC5
PACKED = 0xD4
KAD = 0xE4
KADEMLIAPACKED = 0xE5

# ---------------------------------------------------------------------------
# Transfer / sharing constants (PROTOCOL_MATRIX.md section 7.1, ed2k/Constants.h)
# ---------------------------------------------------------------------------
PARTSIZE = 9_728_000
BLOCKSIZE = 184_320

# ---------------------------------------------------------------------------
# Tag type identifiers (PROTOCOL_MATRIX.md section 2, TagTypes.h)
# ---------------------------------------------------------------------------
HASH16 = 0x01
STRING = 0x02
UINT32 = 0x03
FLOAT32 = 0x04
BOOL = 0x05
BOOLARRAY = 0x06
BLOB = 0x07
UINT16 = 0x08
UINT8 = 0x09
BSOB = 0x0A
UINT64 = 0x0B

# New ED2K string-tag shortcut range: STR1..STR22 encodes value lengths 1..22.
# STR16 is the compatibility boundary accepted by the studied ED2K receivers.
STR1 = 0x11
STR22 = 0x26
STR16 = 0x20

# Bit flag marking a named tag whose name is stored as a one-byte id (0x80|type).
TAG_COMPRESSED = 0x80
