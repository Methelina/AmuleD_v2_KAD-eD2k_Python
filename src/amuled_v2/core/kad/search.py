"""Kad2 keyword search client: KADEMLIA2_SEARCH_KEY_REQ -> SEARCH_RES.

Implements the client-side half of a Kad2 keyword lookup as seen in
``Search.cpp`` (CSearch::Go / SendFindValue / ProcessResponse),
``SearchManager.cpp`` (StartSearch / ProcessResult / PrepareFindKeywords),
and ``KademliaUDPListener.cpp`` (Process_KADEMLIA2_REQ / RES /
Process_KADEMLIA2_SEARCH_RES).

A keyword search is a two-phase iterative lookup:

  1. **Routing lookup** -- ``KADEMLIA2_REQ`` ("find value") requests are sent
     to the closest known contacts of the keyword *target* (the MD4 hash of
     the keyword bytes).  Each responder returns closer contacts from its
     routing table, which are folded into the candidate set if they are
     strictly closer (by XOR distance) to the target.  This mirrors the
     ``m_mapPossible`` / ``m_mapBest`` / ``m_mapTried`` bookkeeping in
     ``CSearch`` and ``SendFindValue`` (Search.cpp:1424-1518).

  2. **Keyword result** -- once a round of lookup completes, the
     ``KADEMLIA2_SEARCH_KEY_REQ`` is fired at the closest responders.  Their
     ``KADEMLIA2_SEARCH_RES`` payloads carry the file answers (file hash +
     metadata tag list), which we parse for name/size/sources.

Wire framing and opcode semantics are defined in
``src/amuled_v2/core/kad/packets.py``; contact records come from
``src/amuled_v2/core/kad/nodes_dat.py``; the routing zone API is in
``src/amuled_v2/core/kad/routing.py``.

src/amuled_v2/core/kad/search.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Kad2 keyword search: keyword_target, kad_keyword_search,
      KadSearchResultItem, KadSearchReport, KadSearchError.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
import zlib
from dataclasses import dataclass, field
from typing import Callable, Optional, Tuple

from amuled_v2.core.hashes.md4 import md4_digest
from amuled_v2.core.kad.packets import (
    KAD_PROTOCOL,
    KADEMLIA2_REQ,
    KADEMLIA2_RES,
    KADEMLIA2_SEARCH_KEY_REQ,
    KADEMLIA2_SEARCH_RES,
    KadUInt128,
    KadPacketError,
    parse_kad_packet,
)
from amuled_v2.core.kad.routing import K, RoutingZone
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.search")

__all__ = [
    "KadSearchError",
    "KadSearchResultItem",
    "KadSearchReport",
    "keyword_target",
    "kad_keyword_search",
]


class KadSearchError(Exception):
    """Raised for search-level failures (e.g. socket bind errors)."""


@dataclass
class KadSearchResultItem:
    """One file result from a Kad2 keyword search response.

    Mirrors the answer parsed from ``KADEMLIA2_SEARCH_RES`` (see
    ``Process_KADEMLIA2_SEARCH_RES``, KademliaUDPListener.cpp:1213-1254 and
    ``SendValidKeywordResult``, Indexed.cpp:755-756): each answer carries a
    16-byte file hash followed by a Kad tag list describing the file.
    """

    file_hash: bytes
    name: str
    size: int
    sources: int = 0
    raw_tags: bytes = b""


@dataclass
class KadSearchReport:
    """Outcome of a single keyword search pass.

    Attributes:
        query: The original keyword string.
        target: The 128-bit Kad target key derived from the keyword.
        queried_nodes: Number of distinct nodes we sent at least one
            KADEMLIA2_REQ or KADEMLIA2_SEARCH_KEY_REQ to.
        responded_nodes: Number of distinct nodes that produced a valid
            KADEMLIA2_RES or KADEMLIA2_SEARCH_RES reply.
        results: Deduplicated file results, ordered by first appearance.
        duration_s: Wall-clock seconds the receive loop ran.
    """

    query: str
    target: KadUInt128
    results: list[KadSearchResultItem] = field(default_factory=list)
    queried_nodes: int = 0
    responded_nodes: int = 0
    duration_s: float = 0.0


# --- Tag type / name constants (opcodes.h) -----------------------------------

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
_TAGNAME_SOURCES = b"\x15"


# --- Keyword target ----------------------------------------------------------


def keyword_target(query: str) -> KadUInt128:
    """Port ``KadGetKeywordHash`` (Kademlia.cpp:536-552).

    A keyword search target is the big-endian 128-bit MD4 hash of the
    keyword encoded as UTF-8 (``KadGetKeywordBytes`` converts the
    wide-string keyword to UTF-8 via ``wc2utf8`` before hashing; eMule
    ``CStringA`` then holds the raw bytes).  The result is loaded into a
    ``CUInt128`` via ``SetValueBE(md4.GetHash())`` -- i.e. big-endian -- so
    the same 16 digest bytes are the on-the-wire KadUInt128.

    Reference::

        void KadGetKeywordHash(const CStringA& rstrKeywordA, CUInt128* pKadID)
        {
            CMD4 md4;
            md4.Add((byte*)(LPCSTR)rstrKeywordA, rstrKeywordA.GetLength());
            md4.Finish();
            pKadID->SetValueBE(md4.GetHash());
        }
    """
    digest = md4_digest(query.encode("utf-8"))
    return KadUInt128(digest)


# --- Payload builders (local, per Search.cpp semantics) ----------------------


def _build_search_key_req(target: KadUInt128) -> bytes:
    """Build the ``KADEMLIA2_SEARCH_KEY_REQ`` payload (Search.cpp:600-632).

    Layout (Kad2, contact version >= 3)::

        UInt128  target          # the keyword hash
        UInt16   uStartPosition  # 0x0000 = no search-term blob, not restrictive

    The eMule reference gates the start-position field width on the *contact's*
    Kad version: >= 3 writes a ``UInt16`` (with the high bit marking
    "restrictive" when search-term data follows), < 3 writes ``UInt8(0)``
    plus a ``UInt8(0)`` large-file flag.  Because we cannot know the
    contact version a priori (we learn it only from responses), we emit the
    Kad2 >= 3 form unconditionally -- a plain keyword search carries no
    search-term blob, so ``uStartPosition = 0x0000`` is correct.
    """
    return target.to_bytes() + struct.pack("<H", 0x0000)


def _build_kad2_req(target: KadUInt128, max_contacts: int, receiver_id: KadUInt128) -> bytes:
    """Build the ``KADEMLIA2_REQ`` "find value" payload (Search.cpp:1424-1453).

    Layout (KademliaUDPListener.cpp:711-726)::

        UInt8   byType      # contact count requested, & 0x1F
        UInt128 uTarget     # the node-id we are looking up (keyword target)
        UInt128 uCheck      # the RECEIVER's KadID (sanity check: the
                            # receiver compares it with its own ID and
                            # silently drops the request on mismatch)

    ``byType`` is clamped to the valid 0x01-0x1F range (Process_KADEMLIA2_REQ
    rejects 0).
    """
    by_type = max(1, min(max_contacts, 0x1F))
    return bytes((by_type,)) + target.to_bytes() + receiver_id.to_bytes()


# --- Tag list decoder (minimal) ----------------------------------------------
#
# Per-tag layout (DataIO.cpp:152-253, opcodes.h TAGTYPE_*):
#
#   UInt8   type
#   UInt16  nameLen        # little-endian
#   name    nameLen bytes
#   value  depends on type:
#     0x01 TAGTYPE_HASH    -> 16 bytes
#     0x02 TAGTYPE_STRING  -> UInt16 len (LE) + len bytes (UTF-8)
#     0x03 TAGTYPE_UINT32  -> 4 bytes (LE)
#     0x08 TAGTYPE_UINT16  -> 2 bytes (LE)
#     0x09 TAGTYPE_UINT8   -> 1 byte
#     0x0B TAGTYPE_UINT64  -> 8 bytes (LE)
#     0x04 TAGTYPE_FLOAT32 -> 4 bytes
#     0x0A TAGTYPE_BSOB    -> UInt8 size + size bytes
#
# We only decode TAG_FILENAME (TAGTYPE_STRING, name b"\x01"),
# TAG_FILESIZE (TAGTYPE_UINT32, name b"\x02"), and TAG_SOURCES
# (TAGTYPE_UINT32, name b"\x15").  Everything else is skipped by advancing
# an offset by the known value width; if a type is unknown we raise
# KadSearchError (the layout cannot be skipped reliably by length alone).


class _TagReader:
    """Minimal forward-only Kad tag decoder.

    Walks a tag-list byte block, yielding ``(name, type, value)`` tuples for
    the tags we understand and raising :class:`KadSearchError` for genuinely
    unknown tag types so the caller can attribute the failure rather than
    silently misparsing the stream.
    """

    __slots__ = ("_data", "_off", "_end")

    def __init__(self, data: bytes, offset: int = 0, end: int | None = None) -> None:
        self._data = data
        self._off = offset
        self._end = len(data) if end is None else end

    def at_end(self) -> bool:
        return self._off >= self._end

    def _read(self, n: int) -> bytes:
        if self._off + n > self._end:
            raise KadSearchError(
                f"tag stream truncated: need {n} bytes at offset {self._off}, "
                f"have {self._end - self._off}"
            )
        chunk = self._data[self._off : self._off + n]
        self._off += n
        return chunk

    def decode_tag(self) -> Tuple[bytes, int, object]:
        """Decode one tag, returning ``(name, type, value)``.

        Unknown tag *types* raise :class:`KadSearchError`.  Known types whose
        *name* we do not care about are still consumed and returned with a
        parsed ``value`` (or ``None`` for raw bytes), so the caller can
        recognise them.
        """
        (by_type,) = self._read(1)
        (name_len,) = struct.unpack_from("<H", self._read(2))
        name = self._read(name_len)

        if by_type == _TAGTYPE_HASH:
            value = self._read(16)
        elif by_type == _TAGTYPE_STRING:
            (slen,) = struct.unpack_from("<H", self._read(2))
            raw = self._read(slen)
            value = raw.decode("utf-8", errors="replace")
        elif by_type == _TAGTYPE_UINT64:
            (value,) = struct.unpack_from("<Q", self._read(8))
        elif by_type == _TAGTYPE_UINT32:
            (value,) = struct.unpack_from("<I", self._read(4))
        elif by_type == _TAGTYPE_UINT16:
            (value,) = struct.unpack_from("<H", self._read(2))
        elif by_type == _TAGTYPE_UINT8:
            (value,) = self._read(1)
        elif by_type == _TAGTYPE_FLOAT32:
            (value,) = struct.unpack_from("<f", self._read(4))
        elif by_type == _TAGTYPE_BSOB:
            (bsize,) = struct.unpack_from("<B", self._read(1))
            value = self._read(bsize)
        elif by_type == _TAGTYPE_BOOL:
            value = self._read(1)
        else:
            raise KadSearchError(
                f"unknown Kad tag type: 0x{by_type:02x} name={name!r}"
            )
        return name, by_type, value


def _read_tag_list(data: bytes, offset: int, end: int | None = None) -> Tuple[list[Tuple[bytes, int, object]], int]:
    """Read a Kad tag list starting at *offset*.

    Returns ``(tags, new_offset)`` where ``tags`` is a list of
    ``(name, type, value)`` tuples.  The leading ``UInt8`` count is consumed
    per ``ReadTagList`` (DataIO.cpp:256-263).
    """
    if end is None:
        end = len(data)
    if offset >= end:
        raise KadSearchError("truncated tag list: missing count byte")
    (count,) = struct.unpack_from("<B", data[offset : offset + 1])
    offset += 1
    reader = _TagReader(data, offset, end)
    tags: list[Tuple[bytes, int, object]] = []
    for _ in range(count):
        if reader.at_end():
            raise KadSearchError(
                "tag list count exceeds available bytes"
            )
        tags.append(reader.decode_tag())
    return tags, reader._off


def _parse_search_res_answers(payload: bytes) -> list[KadSearchResultItem]:
    """Parse the answer list of a ``KADEMLIA2_SEARCH_RES`` payload.

    Layout (KademliaUDPListener.cpp:1219-1252; Indexed.cpp:755-756)::

        UInt128  uSource          # the responder's KadID
        UInt128  uTarget          # the search target we matched
        UInt16   uCount           # number of answers (little-endian)
        repeat uCount:
            UInt128 uAnswer      # the file hash
            TagList tags         # UInt8 count + per-tag encoding

    Only ``TAG_FILENAME`` (string) and ``TAG_FILESIZE`` (uint32) are decoded
    into :class:`KadSearchResultItem`; ``TAG_SOURCES`` is decoded when present.
    All other tags are consumed by the minimal decoder (their value is parsed
    to advance the cursor) and retained raw in ``raw_tags`` for future use.
    """
    raw = bytes(payload)
    if len(raw) < 16 + 16 + 2:
        raise KadSearchError(
            f"SEARCH_RES payload too short: {len(raw)} bytes, need >= 34"
        )
    offset = 0
    offset += 16  # uSource (responder KadID) -- not needed for file results
    offset += 16  # uTarget (was our keyword hash)
    (u_count,) = struct.unpack_from("<H", raw, offset)
    offset += 2

    results: list[KadSearchResultItem] = []
    for i in range(u_count):
        if offset + 16 > len(raw):
            raise KadSearchError(
                f"SEARCH_RES answer {i} truncated: need 16-byte hash "
                f"at offset {offset}, have {len(raw) - offset}"
            )
        file_hash = raw[offset : offset + 16]
        offset += 16

        tags, offset = _read_tag_list(raw, offset)
        name = ""
        size = 0
        sources = 0
        for t_name, _t_type, t_value in tags:
            if t_name == _TAGNAME_FILENAME and isinstance(t_value, str):
                name = t_value
            elif t_name == _TAGNAME_FILESIZE and isinstance(t_value, int):
                size = t_value
            elif t_name == _TAGNAME_SOURCES and isinstance(t_value, int):
                sources = t_value

        raw_tags = b"".join(
            _encode_tag_for_raw(t_name, t_type, t_value)
            for t_name, t_type, t_value in tags
        )
        results.append(
            KadSearchResultItem(
                file_hash=file_hash,
                name=name,
                size=size,
                sources=sources,
                raw_tags=raw_tags,
            )
        )
    return results


def _encode_tag_for_raw(name: bytes, tag_type: int, value: object) -> bytes:
    """Re-serialize a decoded tag back to wire bytes for ``raw_tags``."""
    out = bytearray()
    out.append(tag_type)
    out += struct.pack("<H", len(name))
    out += name
    if tag_type == _TAGTYPE_HASH:
        out += bytes(value)  # already bytes
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
        out += bytes(value)
    return bytes(out)


# --- KADEMLIA2_RES (routing-lookup response) ---------------------------------


def _parse_kad2_res(payload: bytes) -> list[Tuple[bytes, str, int, int, int]]:
    """Parse a ``KADEMLIA2_RES`` contact list (KademliaUDPListener.cpp:767-857).

    Layout::

        UInt128  uTarget          # the lookup target we asked about
        UInt8    uNumContacts     # count
        repeat:
            UInt128  id
            UInt32   ip            # native-endian (little-endian on x86)
            UInt16   udp_port      # little-endian
            UInt16   tcp_port      # little-endian
            UInt8    version

    Returns a list of ``(kad_id, ip, udp_port, tcp_port, version)`` tuples.
    The target is consumed but not returned.
    """
    raw = bytes(payload)
    if len(raw) < 16 + 1:
        raise KadSearchError("KADEMLIA2_RES payload too short for header")
    offset = 16  # uTarget
    (u_count,) = struct.unpack_from("<B", raw, offset)
    offset += 1

    contacts: list[Tuple[bytes, str, int, int, int]] = []
    for i in range(u_count):
        if offset + 16 + 4 + 2 + 2 + 1 > len(raw):
            raise KadSearchError(
                f"KADEMLIA2_RES contact {i} truncated at offset {offset}"
            )
        kad_id = raw[offset : offset + 16]
        offset += 16
        (ip_int,) = struct.unpack_from("<I", raw, offset)
        (udp_port, tcp_port) = struct.unpack_from("<HH", raw, offset + 4)
        version = raw[offset + 8]
        offset += 9
        import ipaddress

        ip_str = str(ipaddress.IPv4Address(ip_int))
        contacts.append((kad_id, ip_str, udp_port, tcp_port, version))
    return contacts


# --- UDP helpers -------------------------------------------------------------


async def _send_dgram(
    sock: socket.socket,
    datagram: bytes,
    addr: Tuple[str, int],
) -> None:
    loop = asyncio.get_running_loop()
    await loop.sock_sendto(sock, datagram, addr)


async def _recv_dgram(
    sock: socket.socket,
    timeout: float,
) -> Tuple[bytes, Tuple[str, int]] | None:
    loop = asyncio.get_running_loop()
    sock.setblocking(False)
    try:
        datagram = await asyncio.wait_for(
            loop.sock_recvfrom(sock, 65535),
            timeout=timeout,
        )
        return datagram
    except asyncio.TimeoutError:
        return None


# --- Main search -------------------------------------------------------------


async def kad_keyword_search(
    query: str,
    *,
    routing: RoutingZone,
    own_id: KadUInt128,
    own_tcp_port: int,
    timeout: float = 8.0,
    max_results: int = 200,
    local_port: int = 4672,
    reward_hook: Optional[Callable[[Tuple[str, int], float], None]] = None,
) -> KadSearchReport:
    """Run a Kad2 keyword search and return a :class:`KadSearchReport`.

    Implementation shape (per Search.cpp / SearchManager.cpp, simplified):

      1. ``target = keyword_target(query)``; seed candidates from
         ``routing.closest(target, K)``.
      2. Bind a single UDP socket on ``0.0.0.0:local_port`` (raises
         :class:`KadSearchError` on bind failure).
      3. Iterative rounds (capped at 4): each round fires a
         ``KADEMLIA2_REQ`` "find value" to unanswered closer candidates,
         then a ``KADEMLIA2_SEARCH_KEY_REQ`` to every responder that has
         not yet been searched.  Closer contacts learned from
         ``KADEMLIA2_RES`` replies are folded into the candidate set only
         when their XOR distance to *target* is strictly smaller than the
         best-known distance.
      4. A shared receive loop dispatches by opcode: ``KADEMLIA2_RES``
         supplies closer contacts; ``KADEMLIA2_SEARCH_RES`` supplies file
         results.  ``0xE5`` datagrams are zlib-decompressed first (like
         ``bootstrap.py``).
      5. Results are deduplicated by file hash; the loop exits early once
         ``max_results`` is collected or no closer candidates remain.

    Only search (no publishing) is performed.
    """
    target = keyword_target(query)
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
        "kad_keyword_search: start query=%r target=%s timeout=%.1f max_results=%d",
        query,
        target,
        timeout,
        max_results,
    )

    # ------------------------------------------------------------------
    # eMule-faithful iterative lookup (Search.cpp ProcessResponse /
    # SendFindValue), the part the audit flagged as missing:
    #
    #   * candidates are followed ONLY when strictly closer than the
    #     responding node (`uDistance < uFromDistance`);
    #   * of those, only the top ALPHA_QUERY (=3) receive a KADEMLIA2_REQ;
    #   * responses from nodes we never asked are ignored;
    #   * tried/possible are keyed by XOR distance, not address;
    #   * keyword lookup contact count is KADEMLIA_FIND_VALUE (=2), with a
    #     single re-ask carrying KADEMLIA_FIND_VALUE_MORE (=11) once
    #     3 * KADEMLIA_FIND_VALUE nodes have been tried;
    #   * SEARCH_KEY_REQ goes to nodes that actually responded.
    # ------------------------------------------------------------------
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
    best: dict[int, None] = {}
    asked_search: set[Tuple[str, int]] = set()
    addr_to_dist: dict[Tuple[str, int], int] = {}
    reasked = False
    results: dict[bytes, KadSearchResultItem] = {}

    sock.setblocking(False)
    overall_deadline = start + timeout
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
        """Move up to *count* untried routing contacts into possible."""
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
        while time.monotonic() < overall_deadline:
            # Ask the top-ALPHA closest untried candidates.  No best-gate:
            # on a cold lookup the strictly-closer chain starves, so the
            # closest-first seed walk (plus RES-followed contacts, which are
            # strictly closer by construction) drives progress.
            ranked = sorted(possible)
            asked_this_round = 0
            for d in ranked:
                if asked_this_round >= ALPHA:
                    break
                if d in tried:
                    continue
                kad_id, ip, udp, _tcp, _ver = possible.pop(d)
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

            remaining = overall_deadline - time.monotonic()
            window = min(4.0, max(0.05, remaining))
            datagram = await _recv_dgram(sock, window)
            if datagram is None:
                # Quiet window: push SEARCH_KEY_REQ to responded nodes we
                # have not searched yet, then re-ask more once.
                pending_search = [
                    (ip, udp)
                    for d, flag in responded.items()
                    for (ip, udp) in [tried[d]]
                    if (ip, udp) not in asked_search
                ]
                if pending_search:
                    skr = (
                        bytes((KAD_PROTOCOL, KADEMLIA2_SEARCH_KEY_REQ))
                        + _build_search_key_req(target)
                    )
                    for ip, udp in pending_search[:ALPHA]:
                        await _send_dgram(sock, skr, (ip, udp))
                        asked_search.add((ip, udp))
                        log.debug(
                            "send KADEMLIA2_SEARCH_KEY_REQ: remote=%s:%d",
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
                    # Lookup exhausted so far: seed the next batch of routing
                    # contacts (eMule keeps iterating until its candidate map
                    # is empty, pulling from its full routing table).
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
                # eMule ignores responses from nodes it never asked.
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
                    answers = _parse_search_res_answers(payload)
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
                if reward_hook is not None:
                    reward_hook((src_ip, src_port), 2.0)
                for item in answers:
                    if item.file_hash not in results:
                        results[item.file_hash] = item
                        if len(results) >= max_results:
                            break
                if len(results) >= max_results:
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
                    # Strictly-closer filter (Search.cpp ProcessResponse).
                    continue
                possible[d] = (KadUInt128(cid), cip, cudp, ctcp, cver)
                routing.add(_node_from_contact(cid, cip, cudp, ctcp, cver))
            if reward_hook is not None:
                reward_hook(
                    (src_ip, src_port), 1.0 if provided_closer else 0.2
                )
            responded[rdist] = provided_closer

            # Send the keyword search to this freshly responded node.
            if (src_ip, src_port) not in asked_search:
                skr = (
                    bytes((KAD_PROTOCOL, KADEMLIA2_SEARCH_KEY_REQ))
                    + _build_search_key_req(target)
                )
                await _send_dgram(sock, skr, (src_ip, src_port))
                asked_search.add((src_ip, src_port))

            if time.monotonic() >= overall_deadline:
                break
            log.info(
                "kad search: tried=%d responded=%d possible=%d "
                "best_prefix_bits=%d searched=%d results=%d",
                len(tried),
                len(responded),
                len(possible),
                128 - min(tried).bit_length() if tried else 0,
                len(asked_search),
                len(results),
            )

    finally:
        sock.close()

    duration = time.monotonic() - start
    report = KadSearchReport(
        query=query,
        target=target,
        queried_nodes=len(tried),
        responded_nodes=len(responded),
        results=list(results.values()),
        duration_s=duration,
    )
    log.info(
        "kad_keyword_search: done query=%r queried=%d responded=%d "
        "results=%d duration=%.1fs",
        query,
        len(tried),
        len(responded),
        len(results),
        duration,
    )
    return report


def _node_from_contact(
    kad_id: bytes,
    ip: str,
    udp_port: int,
    tcp_port: int,
    version: int,
) -> "KadNodeInfo":
    """Build a :class:`KadNodeInfo` from a parsed KADEMLIA2_RES contact."""
    from amuled_v2.core.kad.nodes_dat import KadNodeInfo

    return KadNodeInfo(
        kad_id=kad_id,
        ip=ip,
        udp_port=udp_port,
        tcp_port=tcp_port,
        contact_version=version,
    )
