"""Kad2 publish client: KADEMLIA2_PUBLISH_KEY/PUBLISH_SOURCE_REQ -> PUBLISH_RES.

Implements the client-side half of a Kad2 publish (store-side) flow as seen
in ``Search.cpp`` (``CSearch::StorePacket`` STOREKEYWORD and STOREFILE cases;
``JumpStart``), ``KademliaUDPListener.cpp`` (``SendPublishSourcePacket`` lines
188-216, ``Process_KADEMLIA2_PUBLISH_KEY_REQ`` lines 1182-1278,
``Process_KADEMLIA2_PUBLISH_SOURCE_REQ`` lines 1281-1396,
``Process_KADEMLIA2_PUBLISH_RES`` lines 1430-1453), and ``SearchManager.cpp``
(``ProcessPublishResult`` lines 436-457, the STOREKEYWORD/STOREFILE lifetime
and answer-total limits).

A Kad2 publish is an iterative lookup identical in shape to the keyword and
source searches in ``search.py`` / ``source_search.py``:

  1. **Routing lookup** -- ``KADEMLIA2_REQ`` ("find value") requests are sent
     to the closest known contacts of the *target* (the 128-bit key being
     published: the keyword hash for keyword publish, the file hash for
     source publish).  Each responder returns closer contacts folded into
     the candidate set when strictly closer (XOR distance) to the target.
  2. **Publish** -- once a round of lookup completes, the appropriate
     ``KADEMLIA2_PUBLISH_KEY_REQ`` (0x43) or ``KADEMLIA2_PUBLISH_SOURCE_REQ``
     (0x44) is fired at the closest responders.  Their
     ``KADEMLIA2_PUBLISH_RES`` (0x4B) payloads carry the per-node load; if the
     response requests an ACK (``byOptions & 0x01``), the sender transmits a
     null ``KADEMLIA2_PUBLISH_RES_ACK`` (0x4C) back.

Wire framing and opcode semantics are defined in
``src/amuled_v2/core/kad/packets.py``; contact records come from
``src/amuled_v2/core/kad/nodes_dat.py``; the routing zone API is in
``src/amuled_v2/core/kad/routing.py``.

src/amuled_v2/core/kad/publish.py
Version:     0.1.0
Author:      Soror L'.L'.
Updated:     2026-09-25

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Kad2 publish client: PublishError, PublishTarget, PublishReport,
      KeywordPublisher, SourcePublisher, publish_shared_files,
      build_publish_keyword_req, build_publish_source_req,
      parse_publish_res, parse_publish_res_ack.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct
import time
import zlib
from dataclasses import dataclass, field
from typing import Callable, Optional, Tuple

from amuled_v2.core.kad.packets import (
    KAD_PROTOCOL,
    KADEMLIA2_REQ,
    KADEMLIA2_RES,
    KADEMLIA2_PUBLISH_KEY_REQ,
    KADEMLIA2_PUBLISH_RES,
    KADEMLIA2_PUBLISH_RES_ACK,
    KADEMLIA2_PUBLISH_SOURCE_REQ,
    KadPacketError,
    KadUInt128,
    build_publish_key_req,
    build_publish_res_ack,
    build_publish_source_req,
    parse_kad_packet,
    parse_publish_res,
)
from amuled_v2.core.kad.routing import RoutingZone
from amuled_v2.core.kad.search import (
    KadSearchError,
    _node_from_contact,
    _parse_kad2_res,
    _recv_dgram,
    _send_dgram,
)
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.publish")

__all__ = [
    "PublishError",
    "PublishTarget",
    "PublishReport",
    "KeywordPublisher",
    "SourcePublisher",
    "publish_shared_files",
]

# --- Tag type/name constants (mirrors search.py / source_search.py) ----------
# Per opcodes.h / DataIO.cpp:152-253.
_TAGTYPE_HASH = 0x01
_TAGTYPE_STRING = 0x02
_TAGTYPE_UINT32 = 0x03
_TAGTYPE_FLOAT32 = 0x04
_TAGTYPE_BOOL = 0x05
_TAGTYPE_UINT16 = 0x08
_TAGTYPE_UINT8 = 0x09
_TAGTYPE_BSOB = 0x0A
_TAGTYPE_UINT64 = 0x0B

_TAGNAME_FILENAME = b"\x01"
_TAGNAME_FILESIZE = b"\x02"
_TAGNAME_SOURCETYPE = b"\xFF"
_TAGNAME_SOURCEPORT = b"\xFD"
_TAGNAME_SOURCEUPORT = b"\xFC"
_TAGNAME_ENCRYPTION = b"\xF3"

# --- eMule constants (Defines.h) --------------------------------------------
# SEARCHTOLERANCE (Defines.h:44) -- nodes whose first 32-bit chunk of the XOR
# distance exceeds this are considered "too far" to store with.
_SEARCHTOLERANCE = 0x1000000
# SEARCHSTOREKEYWORD_TOTAL / SEARCHSTOREFILE_TOTAL (Defines.h:67-68) --
# early-stop thresholds for how many successful publishes we want per target.
_STOREKEYWORD_TOTAL = 10
_STOREFILE_TOTAL = 10
# SEARCHSTOREKEYWORD_LIFETIME (Defines.h:60) -- max seconds a store search
# runs; the receiver gives up publishing after this.
_STOREKEYWORD_LIFETIME = 140

# KADEMLIA_VERSION3_47b is the minimum Kad2 contact version that understands
# the publish opcodes (Search.cpp StorePacket: version checks gate Kad1 vs Kad2).
_KAD2_MIN_VERSION = 3


class PublishError(RuntimeError):
    """Raised for publish-level failures (e.g. socket bind errors)."""


@dataclass(frozen=False)
class PublishTarget:
    """One destination node selected for publishing.

    Mirrors the ``m_mapCandidates`` / ``m_mapPossible`` entry in
    ``CSearch`` (Search.cpp JumpStart / Go) and the closest-responder set in
    ``SearchManager`` store logic.
    """

    kad_id: KadUInt128
    ip: str
    udp_port: int
    tcp_port: int
    contact_version: int

    def to_dict(self) -> dict:
        return {
            "kad_id": self.kad_id.to_bytes().hex().upper(),
            "ip": self.ip,
            "udp_port": self.udp_port,
            "tcp_port": self.tcp_port,
            "contact_version": self.contact_version,
        }


@dataclass(frozen=False)
class PublishReport:
    """Outcome of a single publish pass.

    Attributes:
        target: The 128-bit Kad target key that was published to.
        publish_op: The opcode string ("KADEMLIA2_PUBLISH_KEY_REQ" or
            "KADEMLIA2_PUBLISH_SOURCE_REQ").
        targets: Distinct nodes we sent publish requests to.
        accepts: Nodes that responded with ``KADEMLIA2_PUBLISH_RES``.
        acks_sent: Nodes for which we sent a ``KADEMLIA2_PUBLISH_RES_ACK``.
        avg_load: Mean load value reported across all publishes-resp nodes.
        published: Number of file entries / source entries published.
        duration_s: Wall-clock seconds the receive loop ran.
    """

    target: KadUInt128
    publish_op: str
    targets: list[PublishTarget] = field(default_factory=list)
    accepts: list[PublishTarget] = field(default_factory=list)
    acks_sent: list[Tuple[str, int]] = field(default_factory=list)
    avg_load: float = 0.0
    published: int = 0
    duration_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target.to_bytes().hex().upper(),
            "publish_op": self.publish_op,
            "targets": [t.to_dict() for t in self.targets],
            "accepts": [t.to_dict() for t in self.accepts],
            "acks_sent": [{"ip": ip, "port": port} for ip, port in self.acks_sent],
            "avg_load": round(self.avg_load, 2),
            "published": self.published,
            "duration_s": round(self.duration_s, 3),
        }


# --- Tag list encoder (minimal, for publish) ---------------------------------
#
# Per-tag wire layout (DataIO.cpp:152-253):
#   UInt8   type
#   UInt16  nameLen        # little-endian
#   name    nameLen bytes
#   value  depends on type:
#     0x01 TAGTYPE_HASH   -> 16 bytes
#     0x02 TAGTYPE_STRING -> UInt16 len (LE) + len bytes (UTF-8)
#     0x03 TAGTYPE_UINT32 -> 4 bytes (LE)
#     0x08 TAGTYPE_UINT16 -> 2 bytes (LE)
#     0x09 TAGTYPE_UINT8  -> 1 byte
#     0x0B TAGTYPE_UINT64 -> 8 bytes (LE)
#     0x04 TAGTYPE_FLOAT32-> 4 bytes
#     0x0A TAGTYPE_BSOB   -> UInt8 size + size bytes
#
# We encode the tags eMule writes in StorePacket:
#   KEYWORD publish:   FILENAME (string), FILESIZE (uint32/uint64-bsob)
#   SOURCE publish:    SOURCETYPE (uint8), SOURCEPORT (uint32),
#                      SOURCEUPORT (uint16), FILESIZE (uint32), ENCRYPTION (uint8)


def _encode_tag(name: bytes, tag_type: int, value: object) -> bytes:
    """Encode a single Kad tag to wire bytes (no count prefix)."""
    out = bytearray()
    out.append(tag_type)
    out += struct.pack("<H", len(name))
    out += name
    if tag_type == _TAGTYPE_HASH:
        out += bytes(value)
    elif tag_type == _TAGTYPE_STRING:
        enc = str(value).encode("utf-8")
        out += struct.pack("<H", len(enc))
        out += enc
    elif tag_type == _TAGTYPE_UINT64:
        out += struct.pack("<Q", int(value))
    elif tag_type == _TAGTYPE_UINT32:
        out += struct.pack("<I", int(value))
    elif tag_type == _TAGTYPE_UINT16:
        out += struct.pack("<H", int(value))
    elif tag_type == _TAGTYPE_UINT8:
        out += bytes((int(value),))
    elif tag_type == _TAGTYPE_FLOAT32:
        out += struct.pack("<f", float(value))
    elif tag_type == _TAGTYPE_BSOB:
        b = bytes(value)
        out += bytes((len(b),))
        out += b
    elif tag_type == _TAGTYPE_BOOL:
        out += bytes((1 if value else 0,))
    else:
        raise PublishError(f"unsupported tag type for encoding: 0x{tag_type:02x}")
    return bytes(out)


def _build_tag_list_raw(tags: list[Tuple[bytes, int, object]]) -> bytes:
    """Encode a list of ``(name, tag_type, value)`` tuples into a raw tag-list
    block **without** the leading UInt8 count byte.

    ``packets.py`` builders (:func:`build_publish_key_req` /
    :func:`build_publish_source_req`) prepend the count themselves via
    ``_build_tag_list``; the count must appear exactly once on the wire
    (DataIO.cpp WriteTagList writes ``WriteUInt8(list.GetCount())`` followed
    by the tags, nothing else)."""
    body = b"".join(_encode_tag(n, t, v) for n, t, v in tags)
    if len(body) > 255:
        raise PublishError("tag list exceeds 255 bytes")
    return body


# --- Shared tag builders ------------------------------------------------------

def _keyword_file_tags(name: str, size: int) -> Tuple[bytes, int]:
    """Encode the tag list for a keyword-publish file entry.

    Per ``CSearch::StorePacket`` STOREKEYWORD case (Search.cpp:954-963) and
    ``PreparePacketForTags`` which emits ``TAG_FILENAME`` (string) and
    ``TAG_FILESIZE`` (uint64-bsob for >4GB, uint32 otherwise).

    Returns ``(tag_bytes, tag_count)`` -- the encoded tags WITHOUT the
    leading count byte plus their number, ready for the packets.py builders.
    """
    tags: list[Tuple[bytes, int, object]] = [
        (_TAGNAME_FILENAME, _TAGTYPE_STRING, name),
    ]
    # eMule writes FILESIZE as a uint32 tag for normal sizes, or as a BSOB
    # (8 bytes) for >4GB files.  Search.cpp:1650 uses CKadTagUInt for the
    # FILESIZE tag.  We emit the uint32 form for sizes that fit.
    if size <= 0xFFFFFFFF:
        tags.append((_TAGNAME_FILESIZE, _TAGTYPE_UINT32, size))
    else:
        tags.append((_TAGNAME_FILESIZE, _TAGTYPE_BSOB, struct.pack("<Q", size)))
    return _build_tag_list_raw(tags), len(tags)


def _source_tags(
    tcp_port: int,
    *,
    udp_port: Optional[int] = None,
    file_size: int = 0,
    encryption: int = 0,
    source_type: int = 1,
) -> Tuple[bytes, int]:
    """Encode the source tag list for a PUBLISH_SOURCE_REQ entry.

    Layout per ``CSearch::StorePacket`` STOREFILE case (Search.cpp:864-913):

    - ``TAG_SOURCETYPE`` (uint8): 1=HighID, 4=HighID >4GB,
      3=firewalled+buddy, 5=firewalled >4GB, 6=firewalled direct callback.
      Default ``1`` (open HighID).
    - ``TAG_SOURCEPORT`` (uint32): our TCP port (``thePrefs.GetPort()``).
    - ``TAG_SOURCEUPORT`` (uint16): our internal UDP/Kad port, only when
      ``GetUseExternKadPort()`` is false (Search.cpp:906-907, 877-878).
    - ``TAG_FILESIZE`` (uint32): only for receiver version >=
      ``KADEMLIA_VERSION2_47a`` (Search.cpp:909-910, 879-880).
    - ``TAG_ENCRYPTION`` (uint8): ``GetMyConnectOptions(true, true)``
      (Search.cpp:913).
    """
    tags: list[Tuple[bytes, int, object]] = [
        (_TAGNAME_SOURCETYPE, _TAGTYPE_UINT8, source_type),
        (_TAGNAME_SOURCEPORT, _TAGTYPE_UINT32, tcp_port),
    ]
    if udp_port is not None and udp_port > 0:
        tags.append((_TAGNAME_SOURCEUPORT, _TAGTYPE_UINT16, udp_port))
    if file_size > 0:
        if file_size <= 0xFFFFFFFF:
            tags.append((_TAGNAME_FILESIZE, _TAGTYPE_UINT32, file_size))
        else:
            tags.append((_TAGNAME_FILESIZE, _TAGTYPE_BSOB, struct.pack("<Q", file_size)))
    if encryption:
        tags.append((_TAGNAME_ENCRYPTION, _TAGTYPE_UINT8, encryption))
    return _build_tag_list_raw(tags), len(tags)


# --- Iterative lookup helper (mirrors search.py / source_search.py) -----------


async def _lookup_closest(
    sock: socket.socket,
    target: KadUInt128,
    *,
    routing: RoutingZone,
    own_id: KadUInt128,
    timeout: float,
    idle_extend: float,
    min_version: int = _KAD2_MIN_VERSION,
    reward_hook: Optional[Callable[[Tuple[str, int], float], None]] = None,
) -> Tuple[list[PublishTarget], int, int]:
    """Iterative Kad2 lookup that collects the closest responders.

    Mirrors the ``KADEMLIA2_REQ`` walk in ``search.py:kad_keyword_search`` and
    ``source_search.py:kad_file_source_search``: seed from
    ``routing.closest(target, 120)``, send ``KADEMLIA2_REQ`` to the ALPHA
    closest untried candidates, fold strictly-closer contacts from
    ``KADEMLIA2_RES`` replies, and re-ask with ``FIND_VALUE_MORE`` once the
    quiet-window stall condition triggers.

    Returns ``(responders, queried_count, responded_count)`` where
    ``responders`` is the list of nodes that produced a valid
    ``KADEMLIA2_RES`` and are version >= ``min_version``.
    """
    start = time.monotonic()
    targ_int = target.to_int()

    def _dist(kad_id: bytes) -> int:
        return int.from_bytes(kad_id, "big") ^ targ_int

    ALPHA = 3
    FIND_VALUE = 2
    FIND_VALUE_MORE = 11

    # One map per candidate, keyed by XOR distance (mirrors source_search.py):
    # the full contact tuple is kept here so responders can be rebuilt without
    # re-deriving tcp/version from unrelated datagrams.
    tried: dict[int, Tuple[KadUInt128, str, int, int, int]] = {}
    responded: dict[int, bool] = {}
    possible: dict[int, Tuple[KadUInt128, str, int, int, int]] = {}
    addr_to_dist: dict[Tuple[str, int], int] = {}
    reasked = False

    sock.setblocking(False)
    hard_deadline = start + timeout
    last_progress = start
    idle_strikes = 0

    async def _send_find_value(
        kad_id: KadUInt128, ip: str, udp: int, count: int
    ) -> None:
        await _send_dgram(
            sock,
            bytes((KAD_PROTOCOL, KADEMLIA2_REQ))
            + bytes((count,))
            + target.to_bytes()
            + kad_id.to_bytes(),
            (ip, udp),
        )

    seed_pool = routing.closest(target, 120)
    seed_pos = 0

    def _seed_more(count: int) -> int:
        nonlocal seed_pos
        added = 0
        while seed_pos < len(seed_pool) and added < count:
            node = seed_pool[seed_pos]
            seed_pos += 1
            d = _dist(node.kad_id)
            if d in tried or d in possible:
                continue
            possible[d] = (
                KadUInt128(node.kad_id),
                node.ip,
                node.udp_port,
                node.tcp_port,
                node.contact_version,
            )
            added += 1
        return added

    _seed_more(ALPHA)

    try:
        while True:
            now = time.monotonic()
            effective_deadline = min(hard_deadline, last_progress + idle_extend)
            if now >= effective_deadline:
                break

            ranked = sorted(possible)
            asked_this_round = 0
            for d in ranked:
                if asked_this_round >= ALPHA:
                    break
                if d in tried:
                    continue
                kad_id, ip, udp, _tcp, ver = possible.pop(d)
                if ver < min_version:
                    log.debug(
                        "skip publish candidate: remote=%s:%d version=%d < %d (kad1)",
                        ip, udp, ver, min_version,
                    )
                    continue
                tried[d] = (kad_id, ip, udp, _tcp, ver)
                addr_to_dist[(ip, udp)] = d
                asked_this_round += 1
                await _send_find_value(kad_id, ip, udp, FIND_VALUE)
                log.debug(
                    "send KADEMLIA2_REQ: remote=%s:%d dist_bits=%d",
                    ip, udp, 128 - d.bit_length(),
                )

            remaining = effective_deadline - time.monotonic()
            window = min(4.0, max(0.05, remaining))
            datagram = await _recv_dgram(sock, window)
            if datagram is None:
                if not reasked and len(tried) >= 3 * FIND_VALUE:
                    reasked = True
                    if tried:
                        d = min(tried)
                        kad_id, ip, udp, _tcp, _ver = tried[d]
                        await _send_find_value(kad_id, ip, udp, FIND_VALUE_MORE)
                        log.debug(
                            "send KADEMLIA2_REQ(reask): remote=%s:%d count=11",
                            ip, udp,
                        )
                idle_strikes += 1
                if idle_strikes >= 2:
                    if _seed_more(ALPHA) == 0 and not possible:
                        break
                    idle_strikes = 0
                continue

            idle_strikes = 0
            data, src_addr = datagram
            src_ip = src_addr[0]
            src_port = src_addr[1]
            rdist = addr_to_dist.get((src_ip, src_port))
            if rdist is None:
                continue

            try:
                protocol, opcode, payload = parse_kad_packet(data)
                if protocol == 0xE5:
                    payload = zlib.decompress(payload)
                    protocol = 0xE4
            except (KadPacketError, zlib.error) as exc:
                log.debug(
                    "parse failed: remote=%s:%d error=%s", src_ip, src_port, exc
                )
                continue

            if opcode != KADEMLIA2_RES:
                log.debug(
                    "unexpected opcode=%#x from remote=%s:%d",
                    opcode, src_ip, src_port,
                )
                continue

            try:
                contacts = _parse_kad2_res(payload)
            except KadSearchError as exc:
                log.debug(
                    "KADEMLIA2_RES parse failed: remote=%s:%d error=%s",
                    src_ip, src_port, exc,
                )
                continue
            routing.mark_alive(src_ip, src_port)
            last_progress = time.monotonic()

            # Fold strictly-closer contacts into possible + responders list.
            for cid, cip, cudp, ctcp, cver in contacts:
                d = _dist(cid)
                if d in tried or d in possible:
                    continue
                if cip in {src_ip} or d >= rdist:
                    continue
                possible[d] = (KadUInt128(cid), cip, cudp, ctcp, cver)
                routing.add(_node_from_contact(cid, cip, cudp, ctcp, cver))

            if reward_hook is not None:
                reward_hook((src_ip, src_port), 1.0)
            responded[rdist] = True

    finally:
        pass

    # Collect responder nodes straight from the single tried map (dist -> full
    # contact tuple), exactly like source_search.py rebuilds its responders.
    responders: list[PublishTarget] = []
    for d, _flag in responded.items():
        kad_id, ip, udp, tcp, ver = tried[d]
        responders.append(
            PublishTarget(
                kad_id=kad_id,
                ip=ip,
                udp_port=udp,
                tcp_port=tcp,
                contact_version=ver,
            )
        )

    return responders, len(tried), len(responded)


class KeywordPublisher:
    """Publishes shared files as Kad2 keyword index entries.

    Mirrors ``CSearch`` in ``STOREKEYWORD`` mode (Search.cpp:935-991) and the
    store-side flow in ``CSearchManager::JumpStart`` / ``StorePacket``.
    """

    def __init__(self, *, own_id: KadUInt128, own_tcp_port: int) -> None:
        self.own_id = own_id
        self.own_tcp_port = own_tcp_port

    async def publish_file(
        self,
        shared_file: "SharedFile",
        *,
        socket: socket.socket,
        routing_table: RoutingZone,
        bootstrapless: bool = True,
        node_count: int = _STOREKEYWORD_TOTAL,
        timeout: float = 30.0,
        idle_extend: float = 10.0,
    ) -> PublishReport:
        """Publish one ``SharedFile`` as a keyword entry.

        Workflow:

        1. ``target = keyword_target(shared_file.name)`` -- the keyword hash
           is MD4(filename UTF-8) loaded big-endian (Kademlia.cpp:564-570,
           ``KadGetKeywordHash``).  Reuses ``search.keyword_target``.
        2. Iterative lookup via ``_lookup_closest`` to find the
           ``node_count`` closest responders.
        3. Send ``KADEMLIA2_PUBLISH_KEY_REQ`` (0x43) to each responder.
        4. Receive ``KADEMLIA2_PUBLISH_RES`` (0x4B); if ``bRequestACK`` is set
           in ``byOptions``, send ``KADEMLIA2_PUBLISH_RES_ACK`` (0x4C).
        5. Collect per-node load; aggregate into a ``PublishReport``.
        """
        from amuled_v2.core.kad.search import keyword_target

        if shared_file is None:
            raise PublishError("shared_file must not be None")

        target = keyword_target(shared_file.name)
        log.info(
            "keyword_publish: start file_hash=%s name=%s target=%s "
            "node_count=%d timeout=%.1f",
            shared_file.hash_hex,
            shared_file.name,
            target,
            node_count,
            timeout,
        )

        start = time.monotonic()

        file_hash_kad = KadUInt128(shared_file.file_hash)
        file_tags, file_tag_count = _keyword_file_tags(shared_file.name, shared_file.size)
        publish_req = (
            bytes((KAD_PROTOCOL, KADEMLIA2_PUBLISH_KEY_REQ))
            + build_publish_key_req(target, [(file_hash_kad, file_tags, file_tag_count)])
        )

        responders, queried, responded = await _lookup_closest(
            socket,
            target,
            routing=routing_table,
            own_id=self.own_id,
            timeout=timeout,
            idle_extend=idle_extend,
        )

        targets_info = [
            PublishTarget(
                kad_id=r.kad_id,
                ip=r.ip,
                udp_port=r.udp_port,
                tcp_port=r.tcp_port,
                contact_version=r.contact_version,
            )
            for r in responders[:node_count]
        ]

        loads: list[int] = []
        accepts: list[PublishTarget] = []
        acks_sent: list[Tuple[str, int]] = []

        if targets_info:
            for tgt in targets_info:
                await _send_dgram(
                    socket,
                    publish_req,
                    (tgt.ip, tgt.udp_port),
                )
                log.debug(
                    "send KADEMLIA2_PUBLISH_KEY_REQ: remote=%s:%d file=%s",
                    tgt.ip, tgt.udp_port, shared_file.hash_hex,
                )

            collect_deadline = time.monotonic() + min(
                8.0, max(3.0, idle_extend / 3)
            )
            addr_to_tgt = {(t.ip, t.udp_port): t for t in targets_info}
            while time.monotonic() < collect_deadline and len(accepts) < node_count:
                datagram = await _recv_dgram(socket, 1.0)
                if datagram is None:
                    continue
                data, src_addr = datagram
                src_ip, src_port = src_addr[0], src_addr[1]
                tgt = addr_to_tgt.get((src_ip, src_port))
                if tgt is None:
                    continue
                try:
                    protocol, opcode, payload = parse_kad_packet(data)
                    if protocol == 0xE5:
                        payload = zlib.decompress(payload)
                        protocol = 0xE4
                except (KadPacketError, zlib.error):
                    continue
                if opcode != KADEMLIA2_PUBLISH_RES:
                    continue
                try:
                    pres = parse_publish_res(payload)
                except KadPacketError as exc:
                    log.debug(
                        "PUBLISH_RES parse failed: remote=%s:%d error=%s",
                        src_ip, src_port, exc,
                    )
                    continue
                routing_table.mark_alive(src_ip, src_port)
                accepts.append(tgt)
                loads.append(pres.load)
                if pres.ack_requested:
                    await _send_dgram(
                        socket,
                        build_publish_res_ack(),
                        (src_ip, src_port),
                    )
                    acks_sent.append((src_ip, src_port))
                    log.debug(
                        "send KADEMLIA2_PUBLISH_RES_ACK: remote=%s:%d",
                        src_ip, src_port,
                    )

        duration = time.monotonic() - start
        avg_load = sum(loads) / len(loads) if loads else 0.0
        report = PublishReport(
            target=target,
            publish_op="KADEMLIA2_PUBLISH_KEY_REQ",
            targets=targets_info,
            accepts=accepts,
            acks_sent=acks_sent,
            avg_load=avg_load,
            published=len(accepts),
            duration_s=duration,
        )
        log.info(
            "keyword_publish: done file_hash=%s queried=%d responded=%d "
            "accepts=%d avg_load=%.1f duration=%.1fs",
            shared_file.hash_hex,
            queried,
            responded,
            len(accepts),
            avg_load,
            duration,
        )
        return report


class SourcePublisher:
    """Publishes our address as a source for a known file hash.

    Mirrors ``CSearch`` in ``STOREFILE`` mode (Search.cpp:832-934) and
    ``SendPublishSourcePacket`` (KademliaUDPListener.cpp:188-216).
    """

    def __init__(
        self,
        *,
        own_id: KadUInt128,
        own_tcp_port: int,
        own_udp_port: Optional[int] = None,
        user_hash: Optional[bytes] = None,
    ) -> None:
        self.own_id = own_id
        self.own_tcp_port = own_tcp_port
        self.own_udp_port = own_udp_port
        self.user_hash = user_hash or own_id.to_bytes()

    async def publish_sources(
        self,
        file_hash: bytes,
        sources: list[Tuple[int, int, Optional[bytes]]],
        *,
        socket: socket.socket,
        routing_table: RoutingZone,
        file_size: int = 0,
        bootstrapless: bool = True,
        node_count: int = _STOREFILE_TOTAL,
        timeout: float = 30.0,
        idle_extend: float = 10.0,
    ) -> PublishReport:
        """Publish source entries for ``file_hash``.

        ``sources`` is a list of ``(ip_int, tcp_port, userhash_or_None)``
        tuples.  When ``userhash`` is ``None`` the publisher's own
        ``user_hash`` (identity) is used.  Per-entry layout
        (Search.cpp:832-934 + KademliaUDPListener.cpp:188-216)::

            UInt128 uTarget      # the file hash
            UInt128 uContactID   # the publisher's user hash (Prefs.cpp:279-297)
            TagList tags         # SOURCETYPE(1), SOURCEPORT, SOURCEUPORT,
                                 # FILESIZE, ENCRYPTION per Search.cpp:875-913
        """
        if len(file_hash) != 16:
            raise PublishError(f"file_hash must be 16 bytes, got {len(file_hash)}")

        target = KadUInt128(file_hash)
        log.info(
            "source_publish: start file_hash=%s sources=%d target=%s "
            "node_count=%d timeout=%.1f",
            file_hash.hex().upper(),
            len(sources),
            target,
            node_count,
            timeout,
        )

        start = time.monotonic()

        # We publish from our own identity; each source tuple carries its
        # IP:port.  For type-1 HighID sources, uContactID is our user hash
        # (GetClientHash = userhash from Prefs.cpp:84).  The source IP:port
        # is carried in the tag list (SOURCEPORT + the receiver sees our IP
        # from the datagram).  FILESIZE is written for receiver version >=
        # KADEMLIA_VERSION2_47a (Search.cpp:909-910); our responders all pass
        # the Kad2 min-version gate, so we always include it, as eMule does
        # for the HighID branch (Search.cpp:908-910).
        source_tag_lists: list[Tuple[bytes, int]] = []
        for ip_int, tcp_port, userhash in sources:
            del ip_int  # IP is implied by our socket's outward address;
                        # eMule's STOREFILE path does not embed source IP
                        # in tags -- the receiver takes it from the datagram.
            tags, tag_count = _source_tags(
                tcp_port,
                udp_port=self.own_udp_port,
                file_size=file_size,
                source_type=1,  # HighID
            )
            source_tag_lists.append((tags, tag_count))

        # Each source is published as a separate PUBLISH_SOURCE_REQ to its
        # own closest responders, because the target (file hash) is the same
        # but the uContactID differs per publisher identity.  For simplicity
        # and eMule-faithfulness, we publish all sources under our single
        # identity to the top-N responders of the file-hash target.
        publisher_id = KadUInt128(self.user_hash)
        publish_reqs: list[bytes] = []
        for tags, tag_count in source_tag_lists:
            req = (
                bytes((KAD_PROTOCOL, KADEMLIA2_PUBLISH_SOURCE_REQ))
                + build_publish_source_req(target, publisher_id, tags, tag_count)
            )
            publish_reqs.append(req)

        responders, queried, responded = await _lookup_closest(
            socket,
            target,
            routing=routing_table,
            own_id=self.own_id,
            timeout=timeout,
            idle_extend=idle_extend,
        )

        targets_info = [
            PublishTarget(
                kad_id=r.kad_id,
                ip=r.ip,
                udp_port=r.udp_port,
                tcp_port=r.tcp_port,
                contact_version=r.contact_version,
            )
            for r in responders[:node_count]
        ]

        loads: list[int] = []
        accepts: list[PublishTarget] = []
        acks_sent: list[Tuple[str, int]] = []

        if targets_info and publish_reqs:
            req = publish_reqs[0]
            for tgt in targets_info:
                await _send_dgram(socket, req, (tgt.ip, tgt.udp_port))
                log.debug(
                    "send KADEMLIA2_PUBLISH_SOURCE_REQ: remote=%s:%d file=%s",
                    tgt.ip, tgt.udp_port, file_hash.hex().upper(),
                )

            collect_deadline = time.monotonic() + min(
                8.0, max(3.0, idle_extend / 3)
            )
            addr_to_tgt = {(t.ip, t.udp_port): t for t in targets_info}
            while time.monotonic() < collect_deadline and len(accepts) < node_count:
                datagram = await _recv_dgram(socket, 1.0)
                if datagram is None:
                    continue
                data, src_addr = datagram
                src_ip, src_port = src_addr[0], src_addr[1]
                tgt = addr_to_tgt.get((src_ip, src_port))
                if tgt is None:
                    continue
                try:
                    protocol, opcode, payload = parse_kad_packet(data)
                    if protocol == 0xE5:
                        payload = zlib.decompress(payload)
                        protocol = 0xE4
                except (KadPacketError, zlib.error):
                    continue
                if opcode != KADEMLIA2_PUBLISH_RES:
                    continue
                try:
                    pres = parse_publish_res(payload)
                except KadPacketError as exc:
                    log.debug(
                        "PUBLISH_RES parse failed: remote=%s:%d error=%s",
                        src_ip, src_port, exc,
                    )
                    continue
                routing_table.mark_alive(src_ip, src_port)
                accepts.append(tgt)
                loads.append(pres.load)
                if pres.ack_requested:
                    await _send_dgram(socket, build_publish_res_ack(), (src_ip, src_port))
                    acks_sent.append((src_ip, src_port))
                    log.debug(
                        "send KADEMLIA2_PUBLISH_RES_ACK: remote=%s:%d",
                        src_ip, src_port,
                    )

        duration = time.monotonic() - start
        avg_load = sum(loads) / len(loads) if loads else 0.0
        report = PublishReport(
            target=target,
            publish_op="KADEMLIA2_PUBLISH_SOURCE_REQ",
            targets=targets_info,
            accepts=accepts,
            acks_sent=acks_sent,
            avg_load=avg_load,
            published=len(accepts),
            duration_s=duration,
        )
        log.info(
            "source_publish: done file_hash=%s queried=%d responded=%d "
            "accepts=%d avg_load=%.1f duration=%.1fs",
            file_hash.hex().upper(),
            queried,
            responded,
            len(accepts),
            avg_load,
            duration,
        )
        return report


async def publish_shared_files(
    files: list,
    *,
    routing_table: RoutingZone,
    own_id: KadUInt128,
    own_tcp_port: int,
    own_udp_port: Optional[int] = None,
    user_hash: Optional[bytes] = None,
    node_count: int = _STOREKEYWORD_TOTAL,
    timeout: float = 30.0,
    idle_extend: float = 10.0,
) -> list[PublishReport]:
    """Batch-publish a list of shared files to Kad.

    Reuses a single UDP socket per the source-search pattern (one bind,
    one receive loop).  Keyword publish is performed for each file via
    :class:`KeywordPublisher`; source publish for each file hash via
    :class:`SourcePublisher`.

    ``files`` items must be :class:`SharedFile` instances (duck-typed:
    ``name``, ``file_hash``, ``size``).
    """
    from amuled_v2.core.kad.search import keyword_target  # noqa: F401 -- re-export guard

    if not files:
        return []

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", 0))
    except OSError as exc:
        sock.close()
        raise PublishError(f"cannot bind UDP socket: {exc}") from exc

    keyword_pub = KeywordPublisher(own_id=own_id, own_tcp_port=own_tcp_port)
    source_pub = SourcePublisher(
        own_id=own_id,
        own_tcp_port=own_tcp_port,
        own_udp_port=own_udp_port,
        user_hash=user_hash,
    )

    reports: list[PublishReport] = []
    try:
        for f in files:
            kw_report = await keyword_pub.publish_file(
                f,
                socket=sock,
                routing_table=routing_table,
                node_count=node_count,
                timeout=timeout,
                idle_extend=idle_extend,
            )
            reports.append(kw_report)
            src_report = await source_pub.publish_sources(
                f.file_hash,
                [(0, own_tcp_port, None)],
                socket=sock,
                routing_table=routing_table,
                file_size=f.size,
                node_count=_STOREFILE_TOTAL,
                timeout=timeout,
                idle_extend=idle_extend,
            )
            reports.append(src_report)
    finally:
        sock.close()
    return reports
