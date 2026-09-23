"""UDP packet codec for the eMule Kademlia (kad2) protocol.

Wire framing (verified in ``KademliaUDPListener.cpp`` ``ProcessPacket`` and
``ClientUDPSocket.cpp``): a Kad UDP datagram is a 3-byte prefix of
``[protocol][opcode]`` followed by the payload.  Unlike eDonkey TCP packets,
Kad UDP datagrams carry **no length field** -- the UDP payload length is
supplied by the datagram itself.  ``protocol`` is ``0xE4`` for plaintext
Kad (``OP_KADEMLIAHEADER``) or ``0xE5`` when zlib-compressed
(``OP_KADEMLIAPACKEDPROT``); the packed case is intentionally not handled
here -- the caller decompresses before invoking the payload parsers.

All 128-bit Kad node IDs are 16 bytes big-endian on the wire
(``CUInt128::ToByteArray`` / ``ReadUInt128``).

src/amuled_v2/core/kad/packets.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Initial KAD2 UDP packet codec: parse_kad_packet, KadUInt128,
      build_bootstrap_req, parse_bootstrap_res, build_hello_req,
      parse_hello_res, build_ping.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Tuple

from amuled_v2.core.kad.nodes_dat import KadNodeInfo
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.packets")

__all__ = [
    "KAD_PROTOCOL",
    "KAD_PROTOCOL_PACKED",
    "KADEMLIA2_BOOTSTRAP_REQ",
    "KADEMLIA2_BOOTSTRAP_RES",
    "KADEMLIA2_HELLO_REQ",
    "KADEMLIA2_HELLO_RES",
    "KADEMLIA2_HELLO_RES_ACK",
    "KADEMLIA2_REQ",
    "KADEMLIA2_RES",
    "KADEMLIA2_PING",
    "KADEMLIA2_PONG",
    "KADEMLIA2_SEARCH_KEY_REQ",
    "KADEMLIA2_SEARCH_SOURCE_REQ",
    "KADEMLIA2_SEARCH_RES",
    "KADEMLIA2_PUBLISH_KEY_REQ",
    "KADEMLIA2_PUBLISH_SOURCE_REQ",
    "KADEMLIA2_PUBLISH_RES",
    "KADEMLIA2_PUBLISH_RES_ACK",
    "KADEMLIA2_FIREWALLUDP",
    "KadPacketError",
    "KadUInt128",
    "KadHelloInfo",
    "parse_kad_packet",
    "build_bootstrap_req",
    "parse_bootstrap_res",
    "build_hello_req",
    "parse_hello_res",
    "build_ping",
]

# --- Protocol bytes -------------------------------------------------------

KAD_PROTOCOL = 0xE4
KAD_PROTOCOL_PACKED = 0xE5

# --- kad2 opcodes (opcodes.h "KADEMLIA (opcodes) (udp)") -------------------

KADEMLIA2_BOOTSTRAP_REQ = 0x01
KADEMLIA2_BOOTSTRAP_RES = 0x09
KADEMLIA2_HELLO_REQ = 0x11
KADEMLIA2_HELLO_RES = 0x19
KADEMLIA2_HELLO_RES_ACK = 0x22
KADEMLIA2_REQ = 0x21
KADEMLIA2_RES = 0x29
KADEMLIA2_PING = 0x60
KADEMLIA2_PONG = 0x61
KADEMLIA2_SEARCH_KEY_REQ = 0x33
KADEMLIA2_SEARCH_SOURCE_REQ = 0x34
KADEMLIA2_SEARCH_RES = 0x3B
KADEMLIA2_PUBLISH_KEY_REQ = 0x43
KADEMLIA2_PUBLISH_SOURCE_REQ = 0x44
KADEMLIA2_PUBLISH_RES = 0x4B
KADEMLIA2_PUBLISH_RES_ACK = 0x4C
KADEMLIA2_FIREWALLUDP = 0x62

# Current Kad protocol version (eMule 0.50a ``KADEMLIA_VERSION``).
KADEMLIA_VERSION = 0x09

_NODE_ID_SIZE = 16


class KadPacketError(ValueError):
    """Raised for malformed Kad UDP datagrams or payload slices."""


class KadUInt128:
    """Immutable 128-bit Kad node identifier.

    On the wire Kad IDs are 16 bytes big-endian
    (``CUInt128::ToByteArray`` / ``ReadUInt128``).  Internally the value is
    kept as a Python ``int`` so XOR and comparison are trivial; the leading
    bit index follows the ``GetBitNumber`` semantics from ``UInt128.cpp``
    where bit 0 is the most-significant bit.
    """

    __slots__ = ("_value",)

    def __init__(self, value: bytes | int) -> None:
        if isinstance(value, int):
            if not 0 <= value <= (1 << 128) - 1:
                raise KadPacketError(
                    f"KadUInt128 out of range: {value}"
                )
            self._value = value
        elif isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            if len(raw) != _NODE_ID_SIZE:
                raise KadPacketError(
                    f"KadUInt128 requires 16 bytes, got {len(raw)}"
                )
            self._value = int.from_bytes(raw, "big")
        else:
            raise KadPacketError(
                f"KadUInt128 needs bytes or int, got {type(value).__name__}"
            )

    def to_bytes(self) -> bytes:
        """Return the 16-byte big-endian wire representation."""
        return self._value.to_bytes(_NODE_ID_SIZE, "big")

    def to_int(self) -> int:
        return self._value

    def xor(self, other: KadUInt128) -> KadUInt128:
        return KadUInt128(self._value ^ other._value)

    def distance_bits(self) -> int:
        """Index of the highest differing bit (0 == MSB), i.e. the first
        bit position where the XOR result is set, counting from the most
        significant bit.  Returns 128 for the all-zero value::

            distance_bits(x) == number of leading zero bits omitted ... 128

        This is the ``GetBitNumber``-based measure used by the routing zone
        to compute the k-bucket level.  A value of ``128`` means the IDs are
        identical.
        """
        v = self._value
        if v == 0:
            return 128
        return 127 - v.bit_length() + 1

    def __eq__(self, other: object) -> bool:
        if isinstance(other, KadUInt128):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)

    def __repr__(self) -> str:
        return f"KadUInt128({self.to_bytes().hex()})"


@dataclass(frozen=True)
class KadHelloInfo:
    """Parsed ``KADEMLIA2_HELLO`` contact information (hello req/res)."""

    contact_id: KadUInt128
    tcp_port: int
    version: int
    tags_raw: bytes


# --- Datagram-level parse / build ------------------------------------------


def parse_kad_packet(datagram: bytes) -> Tuple[int, int, bytes]:
    """Split a raw Kad UDP datagram into ``(protocol, opcode, payload)``.

    Layout (per ``ProcessPacket``): ``datagram[0]`` is the protocol byte
    (``0xE4`` plaintext / ``0xE5`` packed) and ``datagram[1]`` is the opcode;
    everything from byte 2 onward is the payload.  Packed (``0xE5``)
    datagrams are **not** decompressed here -- the caller must inflate the
    payload and re-invoke the payload parsers::

        protocol, opcode, payload = parse_kad_packet(datagram)
        if protocol == KAD_PROTOCOL_PACKED:
            payload = zlib_decompress(payload)

    Raises :class:`KadPacketError` when the datagram is too short.
    """
    if not isinstance(datagram, (bytes, bytearray, memoryview)):
        raise KadPacketError("datagram must be bytes-like")
    raw = bytes(datagram)
    if len(raw) < 2:
        raise KadPacketError(
            f"Kad datagram too short: have {len(raw)}, need >= 2"
        )
    return raw[0], raw[1], raw[2:]


def _header(protocol: int, opcode: int) -> bytes:
    return bytes((protocol, opcode))


# --- KADEMLIA2_BOOTSTRAP_REQ ------------------------------------------------


def build_bootstrap_req(
    sender_id: KadUInt128,
    sender_version: int = KADEMLIA_VERSION,
) -> bytes:
    """Build a ``KADEMLIA2_BOOTSTRAP_REQ`` datagram.

    Per ``Bootstrap`` (KademliaUDPListener.cpp:94-103) the bootstrap request
    carries an **empty** payload -- ``CSafeMemFile fileIO(0)`` -- regardless
    of Kad version.  The ``sender_version`` is accepted for API symmetry and
    future-proofing but does not contribute bytes to the payload: the version
    gating in ``Bootstrap`` only selects whether an obfuscation target key is
    attached at the socket layer, not anything in the Kad payload itself.

    The returned datagram is the full ``[protocol][opcode]`` prefix; the
    payload is empty.
    """
    if sender_version < 0 or sender_version > 0xFF:
        raise KadPacketError(f"invalid sender_version: {sender_version}")
    payload = b""
    log.debug(
        "build_bootstrap_req: sender_id=%s version=%d payload_len=%d",
        sender_id,
        sender_version,
        len(payload),
    )
    return _header(KAD_PROTOCOL, KADEMLIA2_BOOTSTRAP_REQ) + payload


# --- KADEMLIA2_BOOTSTRAP_RES ------------------------------------------------


def _read_uint128(data: bytes, offset: int) -> Tuple[KadUInt128, int]:
    if offset + _NODE_ID_SIZE > len(data):
        raise KadPacketError(
            f"truncated UInt128 at offset {offset}"
        )
    return (
        KadUInt128(data[offset : offset + _NODE_ID_SIZE]),
        offset + _NODE_ID_SIZE,
    )


def _ip_to_str(ip_int: int) -> str:
    import ipaddress

    return str(ipaddress.IPv4Address(ip_int))


def parse_bootstrap_res(
    payload: bytes,
    sender_version: int = KADEMLIA_VERSION,
) -> Tuple[KadUInt128, list[KadNodeInfo]]:
    """Parse a ``KADEMLIA2_BOOTSTRAP_RES`` payload.

    Layout (per ``Process_KADEMLIA2_BOOTSTRAP_RES``,
    KademliaUDPListener.cpp:546-583)::

        UInt128 contact_id          # the sender's KadID
        UInt16    tcp_port
        UInt8     version
        UInt16    num_contacts
        repeat num_contacts:
            UInt128 contact_id
            UInt32  ip            # big-endian on the wire (ReadUInt32)
            UInt16  udp_port
            UInt16  tcp_port
            UInt8   version

    ``sender_version`` is accepted for symmetry; the bootstrap-res layout is
    the same for every Kad2 version (the contact version field is read but
    the record structure is fixed).
    """
    raw = bytes(payload)
    offset = 0
    sender_id, offset = _read_uint128(raw, offset)
    if offset + 3 > len(raw):
        raise KadPacketError(
            "truncated bootstrap_res: missing sender tcpPort/version"
        )
    tcp_port, version = struct.unpack_from("<HB", raw, offset)
    offset += 3

    if len(raw) - offset < 2:
        raise KadPacketError("truncated bootstrap_res: missing contact count")
    (num_contacts,) = struct.unpack_from("<H", raw, offset)
    offset += 2

    contacts: list[KadNodeInfo] = []
    for i in range(num_contacts):
        cid, offset = _read_uint128(raw, offset)
        if offset + 8 > len(raw):
            raise KadPacketError(
                f"truncated bootstrap_res contact {i}"
            )
        ip_int, udp_port, tcp_port = struct.unpack_from("<IHH", raw, offset)
        offset += 8
        if offset >= len(raw):
            raise KadPacketError(
                f"truncated bootstrap_res contact {i}: missing version"
            )
        (cver,) = struct.unpack_from("<B", raw, offset)
        offset += 1
        contacts.append(
            KadNodeInfo(
                kad_id=cid.to_bytes(),
                ip=_ip_to_str(ip_int),
                udp_port=udp_port,
                tcp_port=tcp_port,
                contact_version=cver,
            )
        )

    log.debug(
        "parse_bootstrap_res: sender=%s contacts=%d",
        sender_id,
        len(contacts),
    )
    return sender_id, contacts


# --- KADEMLIA2_HELLO --------------------------------------------------------


def _read_hello_contact(
    data: bytes, offset: int
) -> Tuple[KadUInt128, int, int, int, bytes, int]:
    """Read ``UInt128 id, UInt16 tcpPort, UInt8 version, UInt8 tagCount, tags``."""
    cid, offset = _read_uint128(data, offset)
    if offset + 4 > len(data):
        raise KadPacketError("truncated hello: missing tcp_port/version")
    tcp_port, version = struct.unpack_from("<HB", data, offset)
    offset += 3
    if offset >= len(data):
        raise KadPacketError("truncated hello: missing tag count")
    (tag_count,) = struct.unpack_from("<B", data, offset)
    offset += 1
    return cid, tcp_port, version, tag_count, data, offset


def _build_tag_list(tags: bytes) -> bytes:
    if not tags:
        return b"\x00"
    if len(tags) > 255:
        raise KadPacketError("tag list exceeds 255 bytes")
    return bytes((len(tags),)) + tags


def build_hello_req(
    sender_id: KadUInt128,
    tcp_port: int,
    sender_version: int = KADEMLIA_VERSION,
    tags: bytes = b"",
) -> bytes:
    """Build a ``KADEMLIA2_HELLO_REQ`` datagram.

    Layout (per ``SendMyDetails`` -> ``AddContact_KADEMLIA2`` read logic,
    KademliaUDPListener.cpp:106-143, 429-478)::

        UInt128 sender_id
        UInt16  tcp_port
        UInt8   version
        UInt8   tag_count
        [tags]

    The version field is the sender's Kad contact version (always emitted as
    a single ``UInt8``).  ``tags`` is the raw, already-encoded tag bytes;
    they are emitted verbatim with a leading count byte.  An empty tag list
    is encoded as a single ``0x00`` count byte, matching
    ``KADEMLIA2_HELLO_RES_ACK``'s ``WriteUInt8(0) // na tags``.
    """
    if sender_version < 0 or sender_version > 0xFF:
        raise KadPacketError(f"invalid sender_version: {sender_version}")
    if not 0 <= tcp_port <= 0xFFFF:
        raise KadPacketError(f"invalid tcp_port: {tcp_port}")
    payload = (
        sender_id.to_bytes()
        + struct.pack("<HB", tcp_port, sender_version)
        + _build_tag_list(tags)
    )
    log.debug(
        "build_hello_req: id=%s tcp=%d version=%d tags=%d",
        sender_id,
        tcp_port,
        sender_version,
        len(tags),
    )
    return _header(KAD_PROTOCOL, KADEMLIA2_HELLO_REQ) + payload


def parse_hello_res(
    payload: bytes,
    sender_version: int = KADEMLIA_VERSION,
) -> KadHelloInfo:
    """Parse a ``KADEMLIA2_HELLO_RES`` payload.

    The hello-res payload uses the same layout as hello-req
    (see ``SendMyDetails`` / ``Process_KADEMLIA2_HELLO_RES``):
    ``UInt128 id, UInt16 tcpPort, UInt8 version, UInt8 tagCount, tags``::

        KadHelloInfo(
            contact_id=KadUInt128(<id>),
            tcp_port=<tcpPort>,
            version=<version>,
            tags_raw=<raw tag bytes>,
        )

    Tags are **not** decoded here; only the count is consumed and the
    remainder is returned verbatim in ``tags_raw`` so a full tag codec can
    decode them later.  ``sender_version`` gates nothing in the current
    eMule 0.50a layout (the contact version byte is always present), but is
    accepted for symmetry and future-proofing.
    """
    raw = bytes(payload)
    cid, tcp_port, version, tag_count, _data, offset = _read_hello_contact(raw, 0)
    tags_raw = raw[offset:]
    expected = sum(1 for _ in range(tag_count)) if tag_count else 0
    if len(tags_raw) < expected:
        raise KadPacketError(
            f"truncated hello_res tags: count={tag_count} have={len(tags_raw)}"
        )
    log.debug(
        "parse_hello_res: id=%s tcp=%d version=%d tags=%d",
        cid,
        tcp_port,
        version,
        tag_count,
    )
    return KadHelloInfo(
        contact_id=cid,
        tcp_port=tcp_port,
        version=version,
        tags_raw=tags_raw,
    )


# --- KADEMLIA2_PING ---------------------------------------------------------


def build_ping() -> bytes:
    """Build a ``KADEMLIA2_PING`` datagram.

    Per ``SendNullPacket`` / ``Process_KADEMLIA2_PING``
    (KademliaUDPListener.cpp:190-194, 1970-1977) a ping carries an **empty**
    payload.  The full datagram is just the two-byte header.
    """
    log.debug("build_ping: empty payload")
    return _header(KAD_PROTOCOL, KADEMLIA2_PING) + b""
