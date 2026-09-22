"""ED2K global UDP search over a server list.

Implements the eMule GLOBAL search channel: one text query is sent to every
known ED2K server over UDP using the OP_GLOBSEARCHREQ variants, and results are
aggregated, deduplicated, and attributed per server.  Capability detection and
the request variant ladder follow the reference implementation in
``CSearchResultsWnd::TimerGlobalSearch``:

- modern servers receive ``OP_GLOBSEARCHREQ3`` (0x90) with a leading
  ``CT_SERVER_UDPSEARCH_FLAGS`` new-tag announcing new-tag and large-file
  support;
- servers answering with extended-get-files support use ``OP_GLOBSEARCHREQ2``
  (0x92);
- all remaining servers receive the classic ``OP_GLOBSEARCHREQ`` (0x98).

Responses arrive as ``OP_GLOBSEARCHRES`` (0x99) with the same entry layout as
the TCP ``OP_SEARCHRESULT`` payload.  Servers that stay silent across the full
variant ladder are marked dead for the current session and retried on the next
search only after the dead-server retry count is reached.

src/amuled_v2/core/ed2k/udp_global.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added async UDP transport with bounded receive windows.
  [+] Added capability ladder REQ3/REQ2/REQ with per-server variant memory.
  [+] Added result aggregation, deduplication, and server attribution.
  [+] Added dead-server counting and session-scoped retry policy.
  [+] Added status probing through OP_GLOBSERVSTATREQ/RES.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass, field
from typing import Optional

from amuled_v2.core.codec.binary import BinaryReader, BinaryWriter
from amuled_v2.core.codec.constants import EDONKEY
from amuled_v2.core.codec.tags import read_new_tag
from amuled_v2.core.ed2k.constants import ProtocolError
from amuled_v2.core.ed2k.server_client import (
    SearchResult,
    parse_search_results,
)
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.SEARCH, "core.ed2k.udp_global")

__all__ = [
    "C2SUDP",
    "GlobalServerEndpoint",
    "GlobalSearchAggregate",
    "GlobalUdpSearchError",
    "build_udp_search_payload",
    "build_udp_search_req3_prefix",
    "parse_udp_packet",
    "encode_udp_packet",
    "GlobalUdpSearch",
]

PACKEDPROT = 0xD4


class C2SUDP:
    """Client-to-server UDP opcodes (eMule opcodes.h)."""

    GLOBSEARCHREQ3 = 0x90
    GLOBSEARCHREQ2 = 0x92
    GLOBSERVSTATREQ = 0x96
    GLOBSERVSTATRES = 0x97
    GLOBSEARCHREQ = 0x98
    GLOBSEARCHRES = 0x99

    # CT_SERVER_UDPSEARCH_FLAGS values.
    SRVCAP_UDP_NEWTAGS_LARGEFILES = 0x01

    # CT_SERVER_UDPSEARCH_FLAGS numeric tag id.
    SERVER_UDPSEARCH_FLAGS = 0x0E


_HEADER_SIZE = 6


class GlobalUdpSearchError(RuntimeError):
    """Raised when the global UDP search cannot be executed."""


@dataclass(frozen=True)
class GlobalServerEndpoint:
    """One ED2K server known to respond on UDP."""

    host: str
    port: int

    def __post_init__(self) -> None:
        if not 0 <= int(self.port) <= 0xFFFF:
            raise GlobalUdpSearchError(f"server port out of range: {self.port}")
        _pack_ip(self.host)


def _pack_ip(host: str) -> int:
    try:
        return int(ipaddress.IPv4Address(host))
    except ValueError as exc:
        raise GlobalUdpSearchError(f"server host is not an IPv4 address: {host!r}") from exc


@dataclass(frozen=True)
class GlobalSearchAggregate:
    """Deduplicated results collected across the whole server list."""

    query: str
    results: tuple[SearchResult, ...]
    per_server: dict[str, int]
    dead_servers: tuple[str, ...]

    @property
    def result_count(self) -> int:
        return len(self.results)

    def to_dict(self) -> dict[str, object]:
        return {
            "query": self.query,
            "result_count": self.result_count,
            "per_server": dict(self.per_server),
            "dead_servers": list(self.dead_servers),
            "results": [result.to_dict() for result in self.results],
        }


def build_udp_search_payload(query: str) -> bytes:
    """Build the classic search body shared by REQ/REQ2/REQ3."""
    if not query or not query.strip():
        raise GlobalUdpSearchError("search query cannot be empty")
    writer = BinaryWriter()
    writer.write_u8(1)
    writer.write_string_utf8(query.strip())
    return writer.to_bytes()


def build_udp_search_req3_prefix() -> bytes:
    """Build the OP_GLOBSEARCHREQ3 new-tag capability prefix."""
    writer = BinaryWriter()
    writer.write_u32(1)  # one capability tag
    writer.write_u8(0x03 | 0x80)  # new-tag UINT32 with numeric name id
    writer.write_u8(C2SUDP.SERVER_UDPSEARCH_FLAGS)
    writer.write_u32(C2SUDP.SRVCAP_UDP_NEWTAGS_LARGEFILES)
    return writer.to_bytes()


def encode_udp_packet(opcode: int, payload: bytes) -> bytes:
    """Frame one ED2K UDP packet: protocol, length (payload+1), opcode."""
    return (
        bytes([EDONKEY])
        + int(len(payload) + 1).to_bytes(4, "little")
        + bytes([opcode])
        + payload
    )


@dataclass(frozen=True)
class _UdpPacket:
    protocol: int
    opcode: int
    payload: bytes


def parse_udp_packet(datagram: bytes) -> _UdpPacket:
    """Parse one received ED2K UDP datagram, including packed packets."""
    if len(datagram) < _HEADER_SIZE:
        raise GlobalUdpSearchError(
            f"UDP datagram shorter than the ED2K header: {len(datagram)}"
        )
    protocol = datagram[0]
    packet_length = int.from_bytes(datagram[1:5], "little")
    opcode = datagram[5]
    payload = datagram[6:]
    if packet_length < 1:
        raise GlobalUdpSearchError(f"UDP packet length is below one: {packet_length}")
    if len(payload) < packet_length - 1:
        raise GlobalUdpSearchError(
            f"UDP datagram truncated: expected={packet_length - 1}, got={len(payload)}"
        )
    payload = payload[: packet_length - 1]
    if protocol == PACKEDPROT:
        import zlib

        try:
            payload = zlib.decompress(payload)
        except zlib.error as exc:
            raise GlobalUdpSearchError(f"packed UDP payload failed to inflate: {exc}") from exc
        protocol = EDONKEY
    return _UdpPacket(protocol=protocol, opcode=opcode, payload=payload)


def _parse_global_search_result(payload: bytes) -> tuple[SearchResult, ...]:
    """Parse an OP_GLOBSEARCHRES payload with a lenient trailing-byte rule."""
    try:
        response = parse_search_results(payload)
    except ProtocolError as exc:
        if "unexpected trailing bytes" not in str(exc):
            raise GlobalUdpSearchError(f"malformed OP_GLOBSEARCHRES: {exc}") from exc
        response = _parse_global_search_result_lenient(payload)
    return response.results


def _parse_global_search_result_lenient(payload: bytes) -> object:
    """Re-parse a global result tolerating unknown trailing bytes."""
    reader = BinaryReader(payload)
    results: list[SearchResult] = []
    result_count = reader.read_u32()
    for _ in range(result_count):
        file_hash = reader.read_hash16()
        client_id = reader.read_u32()
        client_port = reader.read_u16()
        tag_count = reader.read_u32()
        tags = tuple(read_new_tag(reader) for _ in range(tag_count))
        results.append(
            SearchResult(
                file_hash=file_hash,
                client_id=client_id,
                client_port=client_port,
                tags=tags,
            )
        )
    return type("Response", (), {"results": tuple(results)})()


@dataclass
class _ServerAttemptState:
    """Per-server session state: variant memory and failure counts."""

    dead_retries: int = 0
    working_variant: Optional[int] = None
    answered_this_session: bool = False

    @property
    def is_dead(self) -> bool:
        return self.dead_retries >= _DEAD_SERVER_RETRIES


_DEAD_SERVER_RETRIES = 2
_UDP_DATAGRAM_LIMIT = 65536


class GlobalUdpSearch:
    """Aggregated UDP search across a list of ED2K servers."""

    def __init__(
        self,
        servers: list[GlobalServerEndpoint],
        *,
        local_port: int = 0,
        response_window: float = 6.0,
        dead_server_retries: int = _DEAD_SERVER_RETRIES,
        progress_callback: Optional[callable] = None,
    ) -> None:
        if not servers:
            raise GlobalUdpSearchError("global search requires at least one server")
        self.servers = list(servers)
        self.local_port = local_port
        self.response_window = response_window
        self.dead_server_retries = dead_server_retries
        self.progress_callback = progress_callback
        self._state: dict[str, _ServerAttemptState] = {
            f"{server.host}:{server.port}": _ServerAttemptState()
            for server in self.servers
        }
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._pending: dict[tuple[str, int], list[_UdpPacket]] = {}

    def _variant_ladder(self, endpoint: GlobalServerEndpoint) -> list[int]:
        state = self._state[f"{endpoint.host}:{endpoint.port}"]
        ladder = [C2SUDP.GLOBSEARCHREQ3, C2SUDP.GLOBSEARCHREQ2, C2SUDP.GLOBSEARCHREQ]
        if state.working_variant is not None:
            ladder = [state.working_variant] + [
                code for code in ladder if code != state.working_variant
            ]
        return ladder

    async def _open_socket(self) -> asyncio.DatagramTransport:
        if self._transport is not None:
            return self._transport
        loop = asyncio.get_running_loop()
        ready: asyncio.Future = loop.create_future()

        class _Protocol(asyncio.DatagramProtocol):
            def connection_made(self, transport: asyncio.DatagramTransport) -> None:
                if not ready.done():
                    ready.set_result(transport)

            def datagram_received(self, data: bytes, addr: tuple) -> None:
                key = (str(addr[0]), int(addr[1]))
                try:
                    packet = parse_udp_packet(data)
                except GlobalUdpSearchError as exc:
                    log.warning(
                        "GLOBAL UDP dropped malformed datagram: endpoint=%s:%s, error=%s",
                        addr[0],
                        addr[1],
                        exc,
                    )
                    return
                self_outer = self
                bucket = self_outer._pending.setdefault(key, [])
                bucket.append(packet)

            def error_received(self, exc: Exception) -> None:
                log.warning("GLOBAL UDP socket error: error=%s", exc)

        transport, _ = await loop.create_datagram_endpoint(
            _Protocol,
            local_addr=("0.0.0.0", self.local_port),
        )
        self._transport = transport
        return transport

    async def close(self) -> None:
        if self._transport is not None:
            transport = self._transport
            self._transport = None
            self._pending.clear()
            transport.close()
            log.debug("GLOBAL UDP socket closed")

    def _drain_responses(self, endpoint: GlobalServerEndpoint) -> list[_UdpPacket]:
        key = (endpoint.host, endpoint.port)
        bucket = self._pending.pop(key, [])
        return bucket

    async def _probe_status(
        self,
        transport: asyncio.DatagramTransport,
        endpoint: GlobalServerEndpoint,
    ) -> bool:
        """Send one status probe; a reply proves the server answers on UDP."""
        transport.sendto(
            encode_udp_packet(C2SUDP.GLOBSERVSTATREQ, b""),
            (endpoint.host, endpoint.port),
        )
        deadline = time.monotonic() + self.response_window
        while time.monotonic() < deadline:
            await asyncio.sleep(0.1)
            for packet in self._drain_responses(endpoint):
                if packet.opcode == C2SUDP.GLOBSERVSTATRES:
                    return True
        return False

    async def _collect_for_server(
        self,
        transport: asyncio.DatagramTransport,
        endpoint: GlobalServerEndpoint,
        body: bytes,
        *,
        collect_window: float,
    ) -> list[SearchResult]:
        """Run the capability ladder for one server and collect its results.

        Servers with no known working variant get a capped ladder (REQ3, then
        REQ2): sweeping hundreds of silent spy servers with the full ladder
        would dominate runtime, matching the reference client's one-variant-
        per-tick behavior.
        """
        key = f"{endpoint.host}:{endpoint.port}"
        state = self._state[key]
        ladder = self._variant_ladder(endpoint)
        if state.working_variant is None:
            ladder = ladder[:2]
        for variant in ladder:
            if variant == C2SUDP.GLOBSEARCHREQ3:
                wire_body = build_udp_search_req3_prefix() + body
            else:
                wire_body = body
            transport.sendto(
                encode_udp_packet(variant, wire_body),
                (endpoint.host, endpoint.port),
            )
            log.debug(
                "GLOBAL UDP request sent: endpoint=%s:%s, opcode=0x%02X, bytes=%d",
                endpoint.host,
                endpoint.port,
                variant,
                len(wire_body),
            )
            collected: list[SearchResult] = []
            deadline = time.monotonic() + collect_window
            while time.monotonic() < deadline:
                await asyncio.sleep(0.1)
                for packet in self._drain_responses(endpoint):
                    if packet.opcode != C2SUDP.GLOBSEARCHRES:
                        continue
                    try:
                        collected.extend(_parse_global_search_result(packet.payload))
                    except GlobalUdpSearchError as exc:
                        log.warning(
                            "GLOBAL UDP malformed result: endpoint=%s:%s, error=%s",
                            endpoint.host,
                            endpoint.port,
                            exc,
                        )
                if collected:
                    state.working_variant = variant
                    state.answered_this_session = True
                    state.dead_retries = 0
                    log.info(
                        "GLOBAL UDP results received: endpoint=%s:%s, "
                        "opcode=0x%02X, results=%d",
                        endpoint.host,
                        endpoint.port,
                        variant,
                        len(collected),
                    )
                    return collected
            if state.working_variant == variant:
                # Previously working variant went silent; try the next one.
                continue
        if not state.answered_this_session:
            state.dead_retries += 1
            log.info(
                "GLOBAL UDP server marked failing: endpoint=%s:%s, "
                "dead_retries=%d",
                endpoint.host,
                endpoint.port,
                state.dead_retries,
            )
        return []

    async def search(self, query: str) -> GlobalSearchAggregate:
        """Search every live server in the list and aggregate results."""
        body = build_udp_search_payload(query)
        transport = await self._open_socket()
        results: dict[bytes, SearchResult] = {}
        per_server: dict[str, int] = {}
        dead: list[str] = []
        try:
            for endpoint in self.servers:
                key = f"{endpoint.host}:{endpoint.port}"
                state = self._state[key]
                if state.dead_retries >= self.dead_server_retries:
                    dead.append(key)
                    log.debug(
                        "GLOBAL UDP skipping dead server: endpoint=%s", key
                    )
                    continue
                found = await self._collect_for_server(
                    transport,
                    endpoint,
                    body,
                    collect_window=self.response_window,
                )
                per_server[key] = len(found)
                for result in found:
                    existing = results.get(result.file_hash)
                    if existing is None or result.sources > existing.sources:
                        results[result.file_hash] = result
                if self.progress_callback is not None:
                    try:
                        self.progress_callback(
                            len(per_server) + len(dead), len(self.servers), len(results)
                        )
                    except Exception:
                        pass
        finally:
            pass
        aggregate = GlobalSearchAggregate(
            query=query,
            results=tuple(results.values()),
            per_server=per_server,
            dead_servers=tuple(dead),
        )
        log.info(
            "GLOBAL UDP search completed: query=%r, servers=%d, results=%d, "
            "dead=%d",
            query,
            len(self.servers),
            aggregate.result_count,
            len(dead),
        )
        return aggregate
