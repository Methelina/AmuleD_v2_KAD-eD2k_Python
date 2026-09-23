"""Kad2 file source search client: KADEMLIA2_SEARCH_SOURCE_REQ -> SEARCH_RES.

Implements the client-side half of a Kad2 file-source (file publish) lookup as
seen in ``Search.cpp`` (``CSearch::StorePacket`` lines ~550-576, the
``KADEMLIA2_SEARCH_SOURCE_REQ`` form), ``KademliaUDPListener.cpp``
(``Process_KADEMLIA2_SEARCH_SOURCE_REQ`` lines 1155-1163,
``Process_KADEMLIA2_SEARCH_RES`` lines 1213-1254), and ``Indexed.cpp``
(``CIndexed::SendValidSourceResult`` lines 814-896).

A source search is an iterative Kad2 lookup, structurally identical to the
keyword search in ``search.py``:

  1. **Routing lookup** -- ``KADEMLIA2_REQ`` ("find value") requests are sent
     to the closest known contacts of the file's ED2K hash (treated as the
     Kad target).  Each responder returns closer contacts from its routing
     table, folded into the candidate set when strictly closer (XOR distance)
     to the target.  This mirrors the ``m_mapPossible`` /
     ``m_mapBest`` / ``m_mapTried`` bookkeeping in ``CSearch``.

  2. **Source result** -- once a round of lookup completes, the
     ``KADEMLIA2_SEARCH_SOURCE_REQ`` is fired at the closest responders.
     Their ``KADEMLIA2_SEARCH_RES`` payloads carry the source entries:
     each entry is a publisher KadID followed by a Kad tag list describing
     the publisher's IP/port/buddy/encryption attributes.

Wire framing and opcode semantics are defined in
``src/amuled_v2/core/kad/packets.py``; contact records come from
``src/amuled_v2/core/kad/nodes_dat.py``; the routing zone API is in
``src/amuled_v2/core/kad/routing.py``.

src/amuled_v2/core/kad/source_search.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Kad2 file source search: KadFileSource, KadSourceSearchReport,
      build_search_source_req, parse_search_res_source_entries,
      kad_file_source_search.
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
    KADEMLIA2_SEARCH_RES,
    KADEMLIA2_SEARCH_SOURCE_REQ,
    KadUInt128,
    KadPacketError,
    parse_kad_packet,
)
from amuled_v2.core.kad.routing import RoutingZone
from amuled_v2.core.kad.search import (
    KadSearchError,
    _TagReader,
    _read_tag_list,
    _send_dgram,
    _recv_dgram,
    _parse_kad2_res,
    _node_from_contact,
)
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.source_search")

__all__ = [
    "KadFileSource",
    "KadSourceSearchReport",
    "build_search_source_req",
    "parse_search_res_source_entries",
    "kad_file_source_search",
]

_TAGTYPE_HASH = 0x01
_TAGTYPE_STRING = 0x02
_TAGTYPE_UINT32 = 0x03
_TAGTYPE_FLOAT32 = 0x04
_TAGTYPE_BOOL = 0x05
_TAGTYPE_UINT16 = 0x08
_TAGTYPE_UINT8 = 0x09
_TAGTYPE_BSOB = 0x0A
_TAGTYPE_UINT64 = 0x0B

_TAGNAME_SOURCETYPE = b"\xFF"
_TAGNAME_SOURCEIP = b"\xFE"
_TAGNAME_SOURCEPORT = b"\xFD"
_TAGNAME_SOURCEUPORT = b"\xFC"
_TAGNAME_SERVERIP = b"\xFB"
_TAGNAME_SERVERPORT = b"\xFA"
_TAGNAME_BUDDYHASH = b"\xF8"
_TAGNAME_ENCRYPTION = b"\xF3"


@dataclass(frozen=False)
class KadFileSource:
    """One source entry from a ``KADEMLIA2_SEARCH_RES`` payload.

    Mirrors the per-answer record parsed from
    ``Process_KADEMLIA2_SEARCH_RES`` (KademliaUDPListener.cpp:1213-1254) and
    ``SendValidSourceResult`` (Indexed.cpp:814-896): each entry carries the
    publisher's KadID (``uAnswer``) followed by a tag list describing the
    source's connectivity attributes.
    """

    file_hash: bytes
    source_id: bytes
    source_type: int = 0
    ip: Optional[str] = None
    tcp_port: int = 0
    udp_port: int = 0
    buddy_ip: Optional[str] = None
    buddy_port: int = 0
    buddy_hash: Optional[str] = None
    crypt_options: int = 0

    def to_dict(self) -> dict:
        """Return a JSON-serializable dict of all fields."""
        return {
            "file_hash": self.file_hash.hex().upper(),
            "source_id": self.source_id.hex().upper(),
            "source_type": self.source_type,
            "ip": self.ip,
            "tcp_port": self.tcp_port,
            "udp_port": self.udp_port,
            "buddy_ip": self.buddy_ip,
            "buddy_port": self.buddy_port,
            "buddy_hash": self.buddy_hash,
            "crypt_options": self.crypt_options,
            "dialable": self.ip is not None and self.tcp_port > 0,
        }


def build_search_source_req(target: KadUInt128, file_size: int = 0) -> bytes:
    """Build the ``KADEMLIA2_SEARCH_SOURCE_REQ`` payload.

    Layout (per ``CSearch::StorePacket`` lines ~550-576,
    ``Process_KADEMLIA2_SEARCH_SOURCE_REQ`` at
    KademliaUDPListener.cpp:1155-1163)::

        UInt128  uTarget        # the file hash (16 raw bytes)
        UInt16   uStartPosition # 0x0000 little-endian
        UInt64   uFileSize      # little-endian; 0 means "match any size"

    The receiver filters on ``!uFileSize || size match`` (KademliaUDPListener.cpp:1161).
    """
    if file_size < 0:
        raise ValueError(f"file_size must be non-negative, got {file_size}")
    return target.to_bytes() + struct.pack("<HQ", 0, file_size)


def parse_search_res_source_entries(
    payload: bytes,
) -> list[Tuple[bytes, dict]]:
    """Parse the source entries of a ``KADEMLIA2_SEARCH_RES`` payload.

    Layout (per ``Process_KADEMLIA2_SEARCH_RES``
    KademliaUDPListener.cpp:1213-1254 and ``SendValidSourceResult``,
    Indexed.cpp:814-896)::

        UInt128 uSource   # responder KadID (consumed, not returned)
        UInt128 uTarget   # the file hash we searched (consumed, not returned)
        UInt16  uCount    # number of source entries (little-endian)
        repeat uCount:
            UInt128 uAnswer   # publisher's KadID (source entry ID)
            TagList           # UInt8 count + tags (same encoding as search.py)

    Returns a list of ``(source_id_bytes, fields)`` tuples where ``fields``
    has keys: ``source_type``, ``ip`` (str|None), ``tcp_port``, ``udp_port``,
    ``buddy_ip``, ``buddy_port``, ``buddy_hash``, ``crypt_options``.

    Tag names are single bytes (opcodes.h):

    - ``0xFF`` SOURCETYPE  -- uint8 (1=HighID, 3=firewalled+buddy,
      4=HighID >4GB, 5=firewalled >4GB, 6=firewalled direct callback)
    - ``0xFE`` SOURCEIP   -- uint32; eMule-internal byte order is NETWORK;
      the tag writer serializes the uint32 little-endian, so wire bytes come
      out in normal dotted-quad order.  Decode with
      ``ipaddress.IPv4Address(struct.pack("<I", value))``.  Value 0 -> None.
    - ``0xFD`` SOURCEPORT  -- uint (uint8/uint16/uint32); the TCP port.
    - ``0xFC`` SOURCEUPORT -- uint16; the UDP port.
    - ``0xFB`` SERVERIP    -- uint32; low-ID buddy IP (same endianness as
      SOURCEIP -> decode with ``struct.pack("<I", value)``).
    - ``0xFA`` SERVERPORT  -- uint; buddy UDP port.
    - ``0xF8`` BUDDYHASH  -- string; the buddy's KadID hash (raw string).
    - ``0xF3`` ENCRYPTION  -- uint8; encryption options bitmask.

    FILESIZE / FILENAME tags, if present, are ignored.
    """
    raw = bytes(payload)
    if len(raw) < 16 + 16 + 2:
        raise KadSearchError(
            f"SEARCH_RES source payload too short: {len(raw)} bytes, need >= 34"
        )
    offset = 0
    offset += 16  # uSource (responder KadID)
    offset += 16  # uTarget (file hash)
    (u_count,) = struct.unpack_from("<H", raw, offset)
    offset += 2

    entries: list[Tuple[bytes, dict]] = []
    for i in range(u_count):
        if offset + 16 > len(raw):
            raise KadSearchError(
                f"SEARCH_RES source entry {i} truncated: need 16-byte source "
                f"hash at offset {offset}, have {len(raw) - offset}"
            )
        source_id = raw[offset : offset + 16]
        offset += 16

        tags, offset = _read_tag_list(raw, offset)
        fields: dict = {
            "source_type": 0,
            "ip": None,
            "tcp_port": 0,
            "udp_port": 0,
            "buddy_ip": None,
            "buddy_port": 0,
            "buddy_hash": None,
            "crypt_options": 0,
        }
        for t_name, _t_type, t_value in tags:
            if t_name == _TAGNAME_SOURCETYPE and isinstance(t_value, int):
                fields["source_type"] = t_value
            elif t_name == _TAGNAME_SOURCEIP:
                if isinstance(t_value, int) and t_value != 0:
                    ip_str = str(ipaddress.IPv4Address(struct.pack("<I", t_value)))
                    # eMule IsGoodIPPort analogue: drop 0.x and 224+ (multicast
                    # / reserved / poisoned entries).
                    if ip_str.split(".")[0].isdigit():
                        first = int(ip_str.split(".")[0])
                        if 0 < first < 224:
                            fields["ip"] = ip_str
            elif t_name == _TAGNAME_SOURCEPORT and isinstance(t_value, int):
                if 0 < t_value <= 0xFFFF:
                    fields["tcp_port"] = t_value
            elif t_name == _TAGNAME_SOURCEUPORT and isinstance(t_value, int):
                if 0 < t_value <= 0xFFFF:
                    fields["udp_port"] = t_value
            elif t_name == _TAGNAME_SERVERIP:
                if isinstance(t_value, int) and t_value != 0:
                    fields["buddy_ip"] = str(
                        ipaddress.IPv4Address(struct.pack("<I", t_value))
                    )
            elif t_name == _TAGNAME_SERVERPORT and isinstance(t_value, int):
                if 0 < t_value <= 0xFFFF:
                    fields["buddy_port"] = t_value
            elif t_name == _TAGNAME_BUDDYHASH and isinstance(t_value, str):
                fields["buddy_hash"] = t_value
            elif t_name == _TAGNAME_ENCRYPTION and isinstance(t_value, int):
                fields["crypt_options"] = t_value
        entries.append((source_id, fields))
    return entries


@dataclass
class KadSourceSearchReport:
    """Outcome of a single Kad2 file-source search pass.

    Attributes:
        file_hash: The 16-byte ED2K file hash that was searched.
        queried_nodes: Number of distinct nodes we sent at least one
            ``KADEMLIA2_REQ`` or ``KADEMLIA2_SEARCH_SOURCE_REQ`` to.
        responded_nodes: Number of distinct nodes that produced a valid
            ``KADEMLIA2_RES`` or ``KADEMLIA2_SEARCH_RES`` reply.
        sources: Deduplicated source entries, ordered by first appearance.
        duration_s: Wall-clock seconds the receive loop ran.
    """

    file_hash: bytes
    queried_nodes: int = 0
    responded_nodes: int = 0
    sources: list[KadFileSource] = field(default_factory=list)
    duration_s: float = 0.0


async def kad_file_source_search(
    file_hash: bytes,
    *,
    file_size: int = 0,
    routing: RoutingZone,
    own_id: KadUInt128,
    own_tcp_port: int,
    timeout: float = 30.0,
    idle_extend: float = 10.0,
    max_sources: int = 300,
    local_port: int = 0,
    reward_hook: Optional[Callable[[Tuple[str, int], float], None]] = None,
) -> KadSourceSearchReport:
    """Run a Kad2 file-source search and return a :class:`KadSourceSearchReport`.

    The lookup mirrors ``CSearch::Go`` / ``SendFindValue`` /
    ``CSearch::ProcessResponse`` for the file-source variant (Search.cpp,
    KademliaUDPListener.cpp ``Process_KADEMLIA2_SEARCH_SOURCE_REQ``).

    1. ``target = KadUInt128(file_hash)``; seed candidates from
       ``routing.closest(target, 120)`` via a ``_seed_more(ALPHA)`` walk.
    2. Bind a single UDP socket on ``0.0.0.0:local_port`` (raises
       :class:`KadSearchError` on bind failure; ``local_port=0`` means
       ephemeral, which is required on Windows where binding 4672 is
       forbidden).
    3. Iterative rounds: each round fires ``KADEMLIA2_REQ`` "find value" to
       the top ALPHA closest untried candidates, then
       ``KADEMLIA2_SEARCH_SOURCE_REQ`` to every responder that has not yet
       been source-asked.  Closer contacts learned from ``KADEMLIA2_RES``
       replies are folded into the candidate set when their XOR distance to
       *target* is strictly smaller than the responding node's distance.
    4. A shared receive loop dispatches by opcode: ``KADEMLIA2_RES`` supplies
       closer contacts; ``KADEMLIA2_SEARCH_RES`` supplies source entries.
       ``0xE5`` datagrams are zlib-decompressed first (like ``search.py``).
    5. Sources are deduplicated by ``source_id`` (or ``(ip, tcp_port)`` when
       no source_id); the loop exits early once ``max_sources`` is collected
       or no closer candidates remain.
    6. Sliding-window deadline: ``effective_deadline =
       min(start + timeout, last_progress + idle_extend)``, recomputed every
       loop iteration.  ``last_progress`` starts at ``start`` and refreshes on
       every valid parsed response (``KADEMLIA2_RES`` or
       ``KADEMLIA2_SEARCH_RES``), so a productive lookup never starves; only
       genuine silence runs the idle clock down.  ``start + timeout`` is the
       hard cap.
    """
    target = KadUInt128(file_hash)
    start = time.monotonic()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", local_port))
    except OSError as exc:
        sock.close()
        raise KadSearchError(
            f"cannot bind UDP socket on port {local_port}: {exc}"
        ) from exc

    log.info(
        "kad_file_source_search: start file_hash=%s file_size=%d timeout=%.1f "
        "idle_extend=%.1f max_sources=%d",
        file_hash.hex().upper(),
        file_size,
        timeout,
        idle_extend,
        max_sources,
    )

    ALPHA = 3
    FIND_VALUE = 2
    FIND_VALUE_MORE = 11
    tval = target.to_int()

    def _dist(kad_id: bytes) -> int:
        return int.from_bytes(kad_id, "big") ^ tval

    tried: dict[int, Tuple[str, int]] = {}
    tried_entry: dict[int, Tuple[KadUInt128, str, int]] = {}
    responded: dict[int, bool] = {}
    possible: dict[int, Tuple[KadUInt128, str, int, int, int]] = {}
    asked_source: set[Tuple[str, int]] = set()
    addr_to_dist: dict[Tuple[str, int], int] = {}
    reasked = False
    sources: dict[Tuple[bytes], KadFileSource] = {}
    seen_sources: set[Tuple[bytes, Tuple[str, int]]] = set()
    rewards: dict[Tuple[str, int], float] = {}

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
                if ver < 3:
                    log.debug(
                        "skip KADEMLIA2_SEARCH_SOURCE_REQ candidate: remote=%s:%d "
                        "version=%d < 3 (kad1)",
                        ip,
                        udp,
                        ver,
                    )
                    continue
                tried[d] = (ip, udp)
                tried_entry[d] = (kad_id, ip, udp)
                addr_to_dist[(ip, udp)] = d
                asked_this_round += 1
                await _send_find_value(kad_id, ip, udp, FIND_VALUE)
                log.debug(
                    "send KADEMLIA2_REQ: remote=%s:%d dist_bits=%d",
                    ip,
                    udp,
                    128 - d.bit_length(),
                )

            remaining = effective_deadline - time.monotonic()
            window = min(4.0, max(0.05, remaining))
            datagram = await _recv_dgram(sock, window)
            if datagram is None:
                pending_search = [
                    (tried[d][0], tried[d][1])
                    for d, _flag in responded.items()
                    if (tried[d][0], tried[d][1]) not in asked_source
                ]
                if pending_search:
                    sreq = (
                        bytes((KAD_PROTOCOL, KADEMLIA2_SEARCH_SOURCE_REQ))
                        + build_search_source_req(target, file_size)
                    )
                    for ip, udp in pending_search[:ALPHA]:
                        await _send_dgram(sock, sreq, (ip, udp))
                        asked_source.add((ip, udp))
                        log.debug(
                            "send KADEMLIA2_SEARCH_SOURCE_REQ: remote=%s:%d",
                            ip,
                            udp,
                        )
                if not reasked and len(tried) >= 3 * FIND_VALUE:
                    reasked = True
                    if tried_entry:
                        d = min(tried_entry)
                        kad_id, ip, udp = tried_entry[d]
                        await _send_find_value(
                            kad_id, ip, udp, FIND_VALUE_MORE
                        )
                        log.debug(
                            "send KADEMLIA2_REQ(reask): remote=%s:%d count=11",
                            ip,
                            udp,
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

            if opcode == KADEMLIA2_SEARCH_RES:
                try:
                    entries = parse_search_res_source_entries(payload)
                except KadSearchError as exc:
                    log.debug(
                        "SEARCH_RES parse failed: remote=%s:%d error=%s",
                        src_ip,
                        src_port,
                        exc,
                    )
                    continue
                routing.mark_alive(src_ip, src_port)
                responded[rdist] = True
                last_progress = time.monotonic()
                rewards[(src_ip, src_port)] = rewards.get((src_ip, src_port), 0.0) + 2.0
                if reward_hook is not None:
                    reward_hook((src_ip, src_port), 2.0)
                for source_id, fields in entries:
                    if source_id:
                        dedup_key = (source_id, (fields["ip"], fields["tcp_port"]))
                    else:
                        dedup_key = (source_id, (fields["ip"], fields["tcp_port"]))
                    if dedup_key in seen_sources:
                        continue
                    seen_sources.add(dedup_key)
                    sources[source_id] = KadFileSource(
                        file_hash=file_hash,
                        source_id=source_id,
                        source_type=fields["source_type"],
                        ip=fields["ip"],
                        tcp_port=fields["tcp_port"],
                        udp_port=fields["udp_port"],
                        buddy_ip=fields["buddy_ip"],
                        buddy_port=fields["buddy_port"],
                        buddy_hash=fields["buddy_hash"],
                        crypt_options=fields["crypt_options"],
                    )
                    last_progress = time.monotonic()
                    if len(sources) >= max_sources:
                        break
                if len(sources) >= max_sources:
                    break
                continue

            if opcode != KADEMLIA2_RES:
                log.debug(
                    "unexpected opcode=%#x from remote=%s:%d",
                    opcode,
                    src_ip,
                    src_port,
                )
                continue

            try:
                contacts = _parse_kad2_res(payload)
            except KadSearchError as exc:
                log.debug(
                    "KADEMLIA2_RES parse failed: remote=%s:%d error=%s",
                    src_ip,
                    src_port,
                    exc,
                )
                continue
            routing.mark_alive(src_ip, src_port)
            last_progress = time.monotonic()
            provided_closer = False
            seen_ips: set[str] = {src_ip}
            for cid, cip, cudp, ctcp, cver in contacts:
                d = _dist(cid)
                if d < rdist:
                    provided_closer = True
                if d in tried or d in possible:
                    continue
                if cip in seen_ips:
                    continue
                seen_ips.add(cip)
                if d >= rdist:
                    continue
                possible[d] = (KadUInt128(cid), cip, cudp, ctcp, cver)
                routing.add(_node_from_contact(cid, cip, cudp, ctcp, cver))
            if reward_hook is not None:
                reward_hook(
                    (src_ip, src_port), 1.0 if provided_closer else 0.2
                )
            rewards[(src_ip, src_port)] = rewards.get((src_ip, src_port), 0.0) + (
                1.0 if provided_closer else 0.2
            )
            responded[rdist] = provided_closer

            if (src_ip, src_port) not in asked_source:
                sreq = (
                    bytes((KAD_PROTOCOL, KADEMLIA2_SEARCH_SOURCE_REQ))
                    + build_search_source_req(target, file_size)
                )
                await _send_dgram(sock, sreq, (src_ip, src_port))
                asked_source.add((src_ip, src_port))
                log.debug(
                    "send KADEMLIA2_SEARCH_SOURCE_REQ: remote=%s:%d",
                    src_ip,
                    src_port,
                )

            if len(sources) >= max_sources:
                break
            log.info(
                "kad source_search: tried=%d responded=%d possible=%d "
                "best_prefix_bits=%d source_asked=%d sources=%d",
                len(tried),
                len(responded),
                len(possible),
                128 - min(tried).bit_length() if tried else 0,
                len(asked_source),
                len(sources),
            )

        # --- delayed re-ask pass (neighbor-memory rewards) -----------------
        # Give the top-rewarded responders a settle pause (their k-buckets
        # refresh on minutes scale), then ask them once more before giving
        # the sources back.
        top = sorted(rewards, key=lambda k: -rewards[k])[:3]
        if top and len(sources) < max_sources:
            await asyncio.sleep(min(3.0, max(1.0, idle_extend / 3)))
            sreq = (
                bytes((KAD_PROTOCOL, KADEMLIA2_SEARCH_SOURCE_REQ))
                + build_search_source_req(target, file_size)
            )
            for key in top:
                await _send_dgram(sock, sreq, key)
                log.info(
                    "re-ask rewarded node: remote=%s:%d reward=%.1f",
                    key[0],
                    key[1],
                    rewards[key],
                )
            collect_deadline = time.monotonic() + 5.0
            while time.monotonic() < collect_deadline and len(sources) < max_sources:
                datagram = await _recv_dgram(sock, 1.0)
                if datagram is None:
                    continue
                data, src_addr = datagram
                if addr_to_dist.get((src_addr[0], src_addr[1])) is None:
                    continue
                try:
                    protocol, opcode, payload = parse_kad_packet(data)
                    if protocol == 0xE5:
                        payload = zlib.decompress(payload)
                        protocol = 0xE4
                except (KadPacketError, zlib.error):
                    continue
                if opcode != KADEMLIA2_SEARCH_RES:
                    continue
                try:
                    entries = parse_search_res_source_entries(payload)
                except KadSearchError:
                    continue
                routing.mark_alive(src_addr[0], src_addr[1])
                last_progress = time.monotonic()
                for source_id, fields in entries:
                    dedup_key = (source_id, (fields["ip"], fields["tcp_port"]))
                    if dedup_key in seen_sources:
                        continue
                    seen_sources.add(dedup_key)
                    sources[source_id] = KadFileSource(
                        file_hash=file_hash,
                        source_id=source_id,
                        source_type=fields["source_type"],
                        ip=fields["ip"],
                        tcp_port=fields["tcp_port"],
                        udp_port=fields["udp_port"],
                        buddy_ip=fields["buddy_ip"],
                        buddy_port=fields["buddy_port"],
                        buddy_hash=fields["buddy_hash"],
                        crypt_options=fields["crypt_options"],
                    )
                    if len(sources) >= max_sources:
                        break

    finally:
        sock.close()

    duration = time.monotonic() - start
    report = KadSourceSearchReport(
        file_hash=file_hash,
        queried_nodes=len(tried),
        responded_nodes=len(responded),
        sources=list(sources.values()),
        duration_s=duration,
    )
    log.info(
        "kad_file_source_search: done file_hash=%s queried=%d responded=%d "
        "sources=%d duration=%.1fs",
        file_hash.hex().upper(),
        len(tried),
        len(responded),
        len(sources),
        duration,
    )
    return report
