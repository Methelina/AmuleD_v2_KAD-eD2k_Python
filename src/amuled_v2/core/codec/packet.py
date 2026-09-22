"""ED2K/Kad packet framing and packed-payload support.

A normal packet is a protocol byte, an opcode byte, and a four-byte
little-endian payload size, followed by exactly that many payload bytes.
Packed packets preserve the original opcode, replace the protocol byte with the
appropriate packed protocol identifier, and zlib-compress only the payload.

src/amuled_v2/core/codec/packet.py
Version:     0.2.1
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.2.1 (Soror L.'.L'.):
  [*] Corrected ED2K wire header to protocol, UInt32 packet_length, opcode;
      packet_length includes the opcode byte (`payload_size + 1`).
  [*] Decode now validates length >= 1 and derives payload from packet_length.
  [*] Corrected packed-packet semantics: compression applies to the payload
      only; the original opcode remains in the packet header.
  [+] Added KAD packed protocol selection and bounded decompression.
  [+] Added strict trailing-byte and header-size validation.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Initial packet dataclass and wire codec.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Tuple

from . import constants as C
from .binary import CodecError
from .zlib_compat import compress_payload, decompress_payload

__all__ = [
    "Packet",
    "PacketError",
    "encode_packet",
    "decode_packet",
    "pack_packet",
    "unpack_packet",
]

_HEADER_SIZE = 6
_MAX_DECOMPRESSED_SIZE = 16 * 1024 * 1024


class PacketError(ValueError):
    """Raised for malformed packets or invalid packet values."""


@dataclass(frozen=True)
class Packet:
    """One decoded ED2K/Kad protocol packet."""

    protocol: int
    opcode: int
    payload: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.protocol <= 0xFF:
            raise PacketError(f"protocol byte out of range: 0x{self.protocol:02X}")
        if not 0 <= self.opcode <= 0xFF:
            raise PacketError(f"opcode byte out of range: 0x{self.opcode:02X}")
        if not isinstance(self.payload, (bytes, bytearray, memoryview)):
            raise PacketError("payload must be bytes-like")
        object.__setattr__(self, "payload", bytes(self.payload))

    @property
    def payload_size(self) -> int:
        return len(self.payload)


def _header_bytes(protocol: int, opcode: int, payload_size: int) -> bytes:
    packet_length = payload_size + 1
    if packet_length > 0xFFFFFFFF:
        raise PacketError("packet exceeds UINT32 length")
    return bytes((protocol,)) + struct.pack("<I", packet_length) + bytes((opcode,))


def encode_packet(packet: Packet) -> bytes:
    """Encode *packet* in ED2K wire order: protocol, length, opcode, payload."""
    return _header_bytes(packet.protocol, packet.opcode, len(packet.payload)) + packet.payload


def decode_packet(data: bytes) -> Tuple[Packet, bytes]:
    """Decode one packet and return it with any unconsumed trailing bytes."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise PacketError("packet data must be bytes-like")
    raw = bytes(data)
    if len(raw) < _HEADER_SIZE:
        raise PacketError(
            f"insufficient data for header: have {len(raw)}, need {_HEADER_SIZE}"
        )
    protocol = raw[0]
    packet_length = struct.unpack_from("<I", raw, 1)[0]
    if packet_length < 1:
        raise PacketError(f"ED2K packet length cannot be less than one: {packet_length}")
    payload_size = packet_length - 1
    opcode = raw[5]
    end = _HEADER_SIZE + payload_size
    if len(raw) < end:
        raise PacketError(
            f"payload size {payload_size} exceeds available data "
            f"({len(raw) - _HEADER_SIZE} bytes after header)"
        )
    packet = Packet(
        protocol=protocol,
        opcode=opcode,
        payload=raw[_HEADER_SIZE:end],
    )
    return packet, raw[end:]


def _packed_protocol(protocol: int) -> int:
    if protocol == C.KAD:
        return C.KADEMLIAPACKED
    return C.PACKED


def _unpacked_protocol(packed_protocol: int) -> int:
    if packed_protocol == C.KADEMLIAPACKED:
        return C.KAD
    return C.EMULE


def pack_packet(packet: Packet, compression_level: int = 9) -> bytes:
    """Return a packed packet, compressing only its payload.

    The original opcode is retained in the wire header.  Kad packets use
    ``KADEMLIAPACKED``; all other packet families use ``PACKED``.
    """
    compressed = compress_payload(packet.payload, level=compression_level)
    if len(compressed) >= len(packet.payload):
        return encode_packet(packet)
    packed = Packet(
        protocol=_packed_protocol(packet.protocol),
        opcode=packet.opcode,
        payload=compressed,
    )
    return encode_packet(packed)


def unpack_packet(data: bytes) -> Tuple[Packet, bytes]:
    """Decode a normal or packed packet and return it with trailing bytes."""
    packet, remainder = decode_packet(data)
    if packet.protocol not in (C.PACKED, C.KADEMLIAPACKED):
        return packet, remainder

    if not packet.payload:
        raise PacketError("packed packet has an empty payload")
    try:
        decompressed = decompress_payload(
            packet.payload,
            max_size=_MAX_DECOMPRESSED_SIZE,
        )
    except ValueError as exc:
        raise PacketError(f"invalid packed payload: {exc}") from exc
    if not decompressed:
        raise PacketError("packed packet decompressed to an empty payload")
    return (
        Packet(
            protocol=_unpacked_protocol(packet.protocol),
            opcode=packet.opcode,
            payload=decompressed,
        ),
        remainder,
    )
