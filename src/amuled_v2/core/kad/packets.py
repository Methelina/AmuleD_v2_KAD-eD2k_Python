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
    "build_publish_key_req",
    "build_publish_source_req",
    "parse_publish_res",
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
    """Immutable 128-bit Kad node identifier (eMule internal semantics).

    eMule serialises CUInt128 through ``CFileDataIO::ReadUInt128`` /
    ``WriteUInt128`` which are raw 16-byte memcpy of the internal
    ``m_uData[4]`` little-endian words.  Consequently the distance metric
    nodes use treats wire bytes as four little-endian 32-bit words, word 0
    being the most significant in ``CompareTo``.

    Internal representation here: ``w0<<96 | w1<<64 | w2<<32 | w3`` with
    ``w_i = LEint(wire[4i:4i+4])`` so Python XOR/int comparison matches the
    eMule metric exactly.
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
            self._value = self._words_to_int(
                struct.unpack_from("<4I", raw, 0)
            )
        else:
            raise KadPacketError(
                f"KadUInt128 needs bytes or int, got {type(value).__name__}"
            )

    @staticmethod
    def _words_to_int(words: tuple) -> int:
        w0, w1, w2, w3 = words
        return (w0 << 96) | (w1 << 64) | (w2 << 32) | w3

    @classmethod
    def from_be_bytes(cls, raw: bytes) -> "KadUInt128":
        """SetValueBE semantics: word_i = BEint(bytes[4i:4i+4]).

        Used for values that eMule derives via ``SetValueBE`` directly
        (e.g. the keyword target from MD4), not via file IO.
        """
        if len(raw) != _NODE_ID_SIZE:
            raise KadPacketError(
                f"KadUInt128.from_be_bytes requires 16 bytes, got {len(raw)}"
            )
        words = struct.unpack_from(">4I", raw, 0)
        return cls(cls._words_to_int(words))

    def to_bytes(self) -> bytes:
        """Return the 16-byte wire representation (LE words, word0 first)."""
        v = self._value
        w3 = v & 0xFFFFFFFF
        w2 = (v >> 32) & 0xFFFFFFFF
        w1 = (v >> 64) & 0xFFFFFFFF
        w0 = (v >> 96) & 0xFFFFFFFF
        return struct.pack("<4I", w0, w1, w2, w3)

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


def _build_tag_list(tags: bytes, count: int) -> bytes:
    """Prefix an already-encoded tag body with its tag COUNT byte.

    ``count`` is the number of tags (not bytes) and must be supplied by the
    caller, who built the tags and knows their number (mirrors
    DataIO.cpp WriteTagList which writes ``WriteUInt8(list.GetCount())``)."""
    if not tags:
        return b"\x00"
    if len(tags) > 255:
        raise KadPacketError("tag list exceeds 255 bytes")
    if not 0 <= count <= 0xFF:
        raise KadPacketError(f"tag count exceeds UInt8: {count}")
    return bytes((count,)) + tags


def build_hello_req(
    sender_id: KadUInt128,
    tcp_port: int,
    sender_version: int = KADEMLIA_VERSION,
    tags: bytes = b"",
    tag_count: int = 0,
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
        + _build_tag_list(tags, tag_count)
    )

    log.debug(
        "build_hello_req: id=%s tcp=%d version=%d tags=%d",
        sender_id,
        tcp_port,
        sender_version,
        tag_count,
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


# --- KADEMLIA2_PUBLISH_KEY_REQ -----------------------------------------------


def build_publish_key_req(
    keyword_target: KadUInt128,
    file_entries: list[Tuple[KadUInt128, bytes, int]],
) -> bytes:
    """Build a ``KADEMLIA2_PUBLISH_KEY_REQ`` (0x43) payload.

    Layout (per ``CSearch::StorePacket`` STOREKEYWORD case,
    Search.cpp:935-991)::

        UInt128  uTarget          # the keyword hash (lookup target)
        UInt16   uCount           # number of file entries (little-endian)
        repeat uCount:
            UInt128 uAnswer      # the file hash
            TagList tags         # UInt8 count + per-tag encoding
                                 #   (FILENAME string, FILESIZE uint32)

    ``file_entries`` is a list of ``(file_hash, tag_bytes, tag_count)``
    tuples where ``tag_bytes`` is the raw, already-encoded Kad tag list
    *without* the leading count byte (that is added here as ``tag_count``).
    The entry count is patched in before the keyword hash, mirroring eMule's
    ``CByteIO`` seek-and-rewrite at Search.cpp:966-970.
    """
    if len(file_entries) > 0xFFFF:
        raise KadPacketError(
            f"KADEMLIA2_PUBLISH_KEY_REQ file count exceeds UInt16: {len(file_entries)}"
        )
    out = bytearray()
    out += keyword_target.to_bytes()
    out += struct.pack("<H", len(file_entries))
    for file_hash, tag_bytes, tag_count in file_entries:
        out += file_hash.to_bytes()
        out += _build_tag_list(tag_bytes, tag_count)
    log.debug(
        "build_publish_key_req: keyword=%s files=%d",
        keyword_target,
        len(file_entries),
    )
    return bytes(out)


# --- KADEMLIA2_PUBLISH_SOURCE_REQ --------------------------------------------

_TAGNAME_FILENAME = b"\x01"
_TAGNAME_FILESIZE = b"\x02"
_TAGNAME_SOURCETYPE = b"\xFF"
_TAGNAME_SOURCEPORT = b"\xFD"
_TAGNAME_SOURCEUPORT = b"\xFC"
_TAGNAME_ENCRYPTION = b"\xF3"


def build_publish_source_req(
    file_hash: KadUInt128,
    publisher_id: KadUInt128,
    tags: bytes,
    tag_count: int,
) -> bytes:
    """Build a ``KADEMLIA2_PUBLISH_SOURCE_REQ`` (0x44) payload.

    Layout (per ``CSearch::StorePacket`` STOREFILE case,
    Search.cpp:832-934, and ``SendPublishSourcePacket`` at
    KademliaUDPListener.cpp:188-216)::

        UInt128  uTarget     # the file hash (m_uTarget)
        UInt128  uContactID  # the publisher's client/user hash
                             #   (CKademlia::GetPrefs()->GetClientHash(),
                             #    Search.cpp:854)
        TagList  tags        # UInt8 count + per-tag encoding
                             #   SOURCETYPE, SOURCEPORT, SOURCEUPORT,
                             #   FILESIZE, ENCRYPTION per Search.cpp:875-913

    The eMule reference tags differ by source type:

    - HighID (``type 1`` / ``type 4`` for >4 GB): ``TAG_SOURCETYPE`` +
      ``TAG_SOURCEPORT`` (TCP) + optional ``TAG_SOURCEUPORT`` (UDP) +
      optional ``TAG_FILESIZE``.
    - Firewalled with buddy (``type 3`` / ``type 5``): additionally
      ``TAG_SERVERIP`` (buddy IP), ``TAG_SERVERPORT`` (buddy UDP), and
      ``TAG_SERVINGBUDDYHASH``.

    ``tags`` is the raw, already-encoded tag bytes (without the leading
    count byte); ``tag_count`` is the number of tags and is written as the
    list count byte here via :func:`_build_tag_list`.
    """
    out = bytearray()
    out += file_hash.to_bytes()
    out += publisher_id.to_bytes()
    out += _build_tag_list(tags, tag_count)
    log.debug(
        "build_publish_source_req: file_hash=%s publisher_id=%s tags=%d",
        file_hash,
        publisher_id,
        tag_count,
    )
    return bytes(out)


# --- KADEMLIA2_PUBLISH_RES ---------------------------------------------------


@dataclass(frozen=True)
class PublishRes:
    """Parsed ``KADEMLIA2_PUBLISH_RES`` (0x4B) response.

    Layout (per ``Process_KADEMLIA2_PUBLISH_RES``,
    KademliaUDPListener.cpp:1430-1453)::

        UInt128  uFile    # the file hash the result refers to
        UInt8    uLoad    # publisher load (0-100, 100 = full/busy)
        [UInt8   byOptions] # optional; bit 0 = bRequestACK
                          #   (0=ACK not requested, 1=ACK requested)

    When ``ack_requested`` is true the receiver must send a
    ``KADEMLIA2_PUBLISH_RES_ACK`` (0x4C) datagram back.
    """

    file_hash: KadUInt128
    load: int
    ack_requested: bool = False
    ack_options: int = 0


def parse_publish_res(payload: bytes) -> PublishRes:
    """Parse a ``KADEMLIA2_PUBLISH_RES`` (0x4B) payload.

    Raises :class:`KadPacketError` on truncation.
    """
    raw = bytes(payload)
    if len(raw) < 16 + 1:
        raise KadPacketError(
            f"KADEMLIA2_PUBLISH_RES too short: have {len(raw)}, need >= 17"
        )
    file_hash = KadUInt128(raw[0:16])
    load = raw[16]
    ack_requested = False
    ack_options = 0
    if len(raw) > 17:
        ack_options = raw[17]
        ack_requested = bool(ack_options & 0x01)
    log.debug(
        "parse_publish_res: file_hash=%s load=%d ack_requested=%s",
        file_hash,
        load,
        ack_requested,
    )
    return PublishRes(
        file_hash=file_hash,
        load=load,
        ack_requested=ack_requested,
        ack_options=ack_options,
    )


# --- KADEMLIA2_PUBLISH_RES_ACK ------------------------------------------------


def build_publish_res_ack() -> bytes:
    """Build a ``KADEMLIA2_PUBLISH_RES_ACK`` (0x4C) datagram.

    Per ``Process_KADEMLIA2_PUBLISH_RES`` (KademliaUDPListener.cpp:1448-1450)
    the ACK is a null-packet: an empty payload, just the two-byte
    ``[protocol][opcode]`` header (sent via ``SendNullPacket``).
    """
    log.debug("build_publish_res_ack: empty payload")
    return _header(KAD_PROTOCOL, KADEMLIA2_PUBLISH_RES_ACK) + b""
