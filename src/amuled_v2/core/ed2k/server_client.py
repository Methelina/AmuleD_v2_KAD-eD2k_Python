"""Asyncio ED2K server TCP session and server-response parsers.

Implements the M4 connection foundation described by
``docs/PROTOCOL_MATRIX.md``, section 4: bounded packet framing, login dispatch,
server identity/status/message parsing, global search, and TCP source lookup.
The client is loopback-testable and does not perform obfuscation yet.

src/amuled_v2/core/ed2k/server_client.py
Version:     0.2.2
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.2.2 (Soror L.'.L'.):
  [+] Search now accumulates result batches over an explicit time window.
  [*] Receive idle timeouts no longer close the session during search windows.
  [+] Added parser for the eMule more-results-available trailer.
  [*] Source lookup normalizes server silence to an empty response.
  [+] Added OP_SEARCHREQUEST payload builder and OP_SEARCHRESULT parser.
  [+] Added OP_GETSOURCES payload builder and OP_FOUNDSOURCES parser.
  [+] Added high-level search() and get_sources() session methods.
  [+] Added SEARCH/ED2K diagnostics for query, result, and source counts.

Patch Notes v0.1.3 (Soror L.'.L'.):
  [+] Parsed complete eMule-compatible OP_IDCHANGE payload, including optional
      server flags, primary TCP port, reported IP, and obfuscation TCP port.
  [*] Corrected bounded receive parsing to the real ED2K header order:
      protocol, UInt32 packet length, opcode; payload length is length-1.
  [*] Renamed the stored login model to avoid shadowing the async login method.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added asyncio server client with bounded receive and packet dispatch.
  [+] Added OP_LOGINREQUEST transmission and OP_IDCHANGE login completion.
  [+] Added OP_SERVERIDENT, OP_SERVERSTATUS, and OP_SERVERMESSAGE models.
  [+] Added tagged ED2K/SERVER diagnostics and explicit session state checks.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass, field
from typing import Optional

from amuled_v2.core.codec.binary import BinaryReader, BinaryWriter, CodecError
from amuled_v2.core.codec.constants import EDONKEY
from amuled_v2.core.codec.packet import Packet, PacketError, decode_packet, unpack_packet
from amuled_v2.core.codec.tags import Ed2kTag, TagError, read_new_tag
from amuled_v2.core.ed2k.constants import (
    C2STCP,
    LoginRequest,
    ProtocolError,
    build_login_payload,
)
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.ED2K, "core.ed2k.server_client")

__all__ = [
    "Ed2kServerClient",
    "FoundSource",
    "FoundSources",
    "SearchResult",
    "SearchResultResponse",
    "ServerIdentity",
    "ServerIdChange",
    "ServerStatus",
    "ServerMessage",
    "LoginResult",
    "ServerSessionError",
    "build_get_sources_payload",
    "build_global_search_payload",
    "parse_found_sources",
    "parse_search_results",
]

_HEADER_SIZE = 6
_MAX_PACKET_SIZE = 16 * 1024 * 1024
_HIGH_ID_THRESHOLD = 16_000_000


class ServerSessionError(RuntimeError):
    """Raised when an ED2K server session is used or answered incorrectly."""


@dataclass(frozen=True)
class ServerIdentity:
    """Parsed ``OP_SERVERIDENT`` response."""

    server_hash: bytes
    ip: int
    port: int
    tags: tuple[Ed2kTag, ...]

    def name(self) -> str:
        for tag in self.tags:
            if tag.name_id == 0x01 and isinstance(tag.value, str):
                return tag.value
        return ""

    def description(self) -> str:
        for tag in self.tags:
            if tag.name_id == 0x0B and isinstance(tag.value, str):
                return tag.value
        return ""


@dataclass(frozen=True)
class ServerStatus:
    """Parsed ``OP_SERVERSTATUS`` response."""

    users: int
    files: int


@dataclass(frozen=True)
class ServerMessage:
    """Parsed human-readable ``OP_SERVERMESSAGE`` response."""

    message: str


@dataclass(frozen=True)
class ServerIdChange:
    """Parsed ``OP_IDCHANGE`` response.

    eMule-compatible payload layout: client ID, server TCP flags, and primary
    TCP port are mandatory; the reported IP and obfuscation TCP port are
    optional and present only in extended responses.
    """

    client_id: int
    server_flags: int = 0
    primary_tcp_port: int = 0
    reported_ip: Optional[int] = None
    obfuscation_tcp_port: Optional[int] = None


@dataclass
class LoginResult:
    """Aggregated session state after a successful login handshake."""

    client_id: int
    low_id: bool
    identity: Optional[ServerIdentity] = None
    status: Optional[ServerStatus] = None
    id_change: Optional[ServerIdChange] = None
    messages: list[str] = field(default_factory=list)
    elapsed: float = 0.0


@dataclass(frozen=True)
class SearchResult:
    """One parsed ``OP_SEARCHRESULT`` entry."""

    file_hash: bytes
    client_id: int
    client_port: int
    tags: tuple[Ed2kTag, ...]

    def _tag_value(self, name_id: int) -> object:
        for tag in self.tags:
            if tag.name_id == name_id:
                return tag.value
        return None

    @property
    def name(self) -> str:
        value = self._tag_value(0x01)
        return value if isinstance(value, str) else ""

    @property
    def size(self) -> int:
        low = self._tag_value(0x02)
        high = self._tag_value(0x3A)
        if not isinstance(low, int):
            return 0
        if isinstance(high, int):
            return ((high & 0xFFFFFFFF) << 32) + (low & 0xFFFFFFFF)
        return low

    @property
    def sources(self) -> int:
        value = self._tag_value(0x15)
        return value if isinstance(value, int) else 0

    @property
    def complete_sources(self) -> int:
        value = self._tag_value(0x30)
        return value if isinstance(value, int) else 0

    def to_dict(self) -> dict[str, object]:
        return {
            "hash": self.file_hash.hex().upper(),
            "name": self.name,
            "size": self.size,
            "sources": self.sources,
            "complete_sources": self.complete_sources,
            "client_id": self.client_id,
            "client_port": self.client_port,
        }


@dataclass(frozen=True)
class FoundSource:
    """One source endpoint from ``OP_FOUNDSOURCES``."""

    client_id: int
    client_port: int
    crypt_options: int = 0
    user_hash: Optional[bytes] = None

    @property
    def low_id(self) -> bool:
        return self.client_id < _HIGH_ID_THRESHOLD

    @property
    def address(self) -> Optional[str]:
        if self.low_id:
            return None
        try:
            return str(ipaddress.IPv4Address(self.client_id))
        except ValueError:
            return None

    def to_dict(self) -> dict[str, object]:
        return {
            "client_id": self.client_id,
            "client_port": self.client_port,
            "low_id": self.low_id,
            "address": self.address,
            "crypt_options": self.crypt_options,
            "user_hash": self.user_hash.hex().upper() if self.user_hash else None,
        }


@dataclass(frozen=True)
class SearchResultResponse:
    """Parsed ``OP_SEARCHRESULT`` packet with the eMule more-results flag."""

    results: tuple[SearchResult, ...]
    more_results_available: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "results": [result.to_dict() for result in self.results],
            "result_count": len(self.results),
            "more_results_available": self.more_results_available,
        }


@dataclass(frozen=True)
class FoundSources:
    """Parsed source response for one ED2K file hash."""

    file_hash: bytes
    sources: tuple[FoundSource, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "hash": self.file_hash.hex().upper(),
            "source_count": len(self.sources),
            "sources": [source.to_dict() for source in self.sources],
        }


def build_global_search_payload(query: str) -> bytes:
    """Build the simple global ED2K search payload for one text term."""
    if not query or not query.strip():
        raise ProtocolError("search query cannot be empty")
    writer = BinaryWriter()
    writer.write_u8(1)  # string parameter type
    writer.write_string_utf8(query.strip())
    return writer.to_bytes()


def build_get_sources_payload(file_hash: bytes, file_size: int) -> bytes:
    """Build ``OP_GETSOURCES`` payload for one regular or large file."""
    if len(file_hash) != 16:
        raise ProtocolError("ED2K file hash must contain exactly 16 bytes")
    if file_size < 0:
        raise ProtocolError("file size cannot be negative")
    writer = BinaryWriter()
    writer.write_hash16(file_hash)
    if file_size <= 0xFFFFFFFF:
        writer.write_u32(file_size)
    else:
        writer.write_u32(0)
        writer.write_u64(file_size)
    return writer.to_bytes()


def parse_search_results(payload: bytes) -> SearchResultResponse:
    """Parse an ``OP_SEARCHRESULT`` payload and its eMule more-results flag."""
    reader = BinaryReader(payload)
    results: list[SearchResult] = []
    try:
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
        more_results = False
        if reader.remaining == 1:
            more_byte = reader.read_u8()
            # eMule accepts 0/1; unknown values are diagnostic trailing data.
            more_results = more_byte == 1
        elif reader.remaining:
            raise ProtocolError(
                f"OP_SEARCHRESULT has {reader.remaining} unexpected trailing bytes"
            )
    except (CodecError, TagError) as exc:
        raise ProtocolError(f"malformed OP_SEARCHRESULT: {exc}") from exc
    return SearchResultResponse(
        results=tuple(results),
        more_results_available=more_results,
    )


def parse_found_sources(payload: bytes, *, obfuscated: bool = False) -> FoundSources:
    """Parse ``OP_FOUNDSOURCES`` or ``OP_FOUNDSOURCES_OBFU`` payload."""
    reader = BinaryReader(payload)
    sources: list[FoundSource] = []
    try:
        file_hash = reader.read_hash16()
        source_count = reader.read_u8()
        for _ in range(source_count):
            client_id = reader.read_u32()
            client_port = reader.read_u16()
            crypt_options = 0
            user_hash = None
            if obfuscated:
                crypt_options = reader.read_u8()
                if crypt_options & 0x80:
                    user_hash = reader.read_hash16()
            sources.append(
                FoundSource(
                    client_id=client_id,
                    client_port=client_port,
                    crypt_options=crypt_options,
                    user_hash=user_hash,
                )
            )
    except (CodecError, TagError) as exc:
        raise ProtocolError(f"malformed OP_FOUNDSOURCES: {exc}") from exc
    if reader.remaining:
        raise ProtocolError(f"OP_FOUNDSOURCES has {reader.remaining} trailing bytes")
    return FoundSources(file_hash=file_hash, sources=tuple(sources))


def _parse_server_ident(payload: bytes) -> ServerIdentity:
    reader = BinaryReader(payload)
    try:
        server_hash = reader.read_hash16()
        ip = reader.read_u32()
        port = reader.read_u16()
        tag_count = reader.read_u32()
        tags = tuple(read_new_tag(reader) for _ in range(tag_count))
    except (CodecError, TagError) as exc:
        raise ProtocolError(f"malformed OP_SERVERIDENT: {exc}") from exc
    if reader.remaining:
        raise ProtocolError(f"OP_SERVERIDENT has {reader.remaining} trailing bytes")
    return ServerIdentity(server_hash=server_hash, ip=ip, port=port, tags=tags)


def _parse_server_status(payload: bytes) -> ServerStatus:
    reader = BinaryReader(payload)
    try:
        users = reader.read_u32()
        files = reader.read_u32()
    except CodecError as exc:
        raise ProtocolError(f"malformed OP_SERVERSTATUS: {exc}") from exc
    if reader.remaining:
        raise ProtocolError(f"OP_SERVERSTATUS has {reader.remaining} trailing bytes")
    return ServerStatus(users=users, files=files)


def _parse_server_message(payload: bytes) -> ServerMessage:
    reader = BinaryReader(payload)
    try:
        message = reader.read_string_utf8()
    except (CodecError, UnicodeError) as exc:
        raise ProtocolError(f"malformed OP_SERVERMESSAGE: {exc}") from exc
    if reader.remaining:
        raise ProtocolError(f"OP_SERVERMESSAGE has {reader.remaining} trailing bytes")
    return ServerMessage(message=message)


def _parse_server_id_change(payload: bytes) -> ServerIdChange:
    if len(payload) < 4:
        raise ProtocolError(f"OP_IDCHANGE payload too short: {len(payload)}")
    client_id = int.from_bytes(payload[0:4], "little")
    server_flags = int.from_bytes(payload[4:8], "little") if len(payload) >= 8 else 0
    primary_tcp_port = int.from_bytes(payload[8:12], "little") if len(payload) >= 12 else 0
    reported_ip = int.from_bytes(payload[12:16], "little") if len(payload) >= 16 else None
    obfuscation_port = int.from_bytes(payload[16:20], "little") if len(payload) >= 20 else None
    return ServerIdChange(
        client_id=client_id,
        server_flags=server_flags,
        primary_tcp_port=primary_tcp_port,
        reported_ip=reported_ip,
        obfuscation_tcp_port=obfuscation_port,
    )


class Ed2kServerClient:
    """One asyncio ED2K client-to-server TCP session."""

    def __init__(
        self,
        host: str,
        port: int,
        login_request: LoginRequest,
        *,
        connect_timeout: float = 10.0,
        response_timeout: float = 20.0,
    ) -> None:
        if not 0 <= port <= 0xFFFF:
            raise ProtocolError(f"server port out of UInt16 range: {port}")
        self.host = host
        self.port = port
        self.login_request = login_request
        self.connect_timeout = connect_timeout
        self.response_timeout = response_timeout
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self.identity: Optional[ServerIdentity] = None
        self.status: Optional[ServerStatus] = None
        self.messages: list[str] = []
        self.connected = False
        self.logged_in = False

    @property
    def is_connected(self) -> bool:
        return self.connected and self._writer is not None

    async def connect(self) -> None:
        if self.is_connected:
            return
        started = time.monotonic()
        log.debug(f"Connecting to ED2K server: host={self.host}, port={self.port}")
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.connect_timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            self.connected = False
            log.error(
                f"ED2K connect failed: host={self.host}, port={self.port}, error={exc}"
            )
            raise ServerSessionError(f"cannot connect to {self.host}:{self.port}: {exc}") from exc
        self.connected = True
        elapsed = time.monotonic() - started
        log.info(f"ED2K server connected: endpoint={self.host}:{self.port}, elapsed={elapsed:.3f}")

    async def close(self) -> None:
        if self._writer is not None:
            writer = self._writer
            self._writer = None
            self._reader = None
            self.connected = False
            self.logged_in = False
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass
            log.info(f"ED2K server disconnected: endpoint={self.host}:{self.port}")

    async def __aenter__(self) -> "Ed2kServerClient":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self.close()

    def _require_writer(self) -> asyncio.StreamWriter:
        if self._writer is None or not self.connected:
            raise ServerSessionError("ED2K server session is not connected")
        return self._writer

    async def _send_packet(self, packet: Packet) -> None:
        from amuled_v2.core.codec.packet import encode_packet

        writer = self._require_writer()
        wire = encode_packet(packet)
        writer.write(wire)
        try:
            await writer.drain()
        except (OSError, ConnectionResetError) as exc:
            await self.close()
            raise ServerSessionError(f"ED2K send failed: {exc}") from exc
        log.debug(
            f"ED2K packet sent: opcode=0x{packet.opcode:02X}, payload={len(packet.payload)}"
        )

    async def _receive_packet(
        self,
        *,
        timeout: float | None = None,
        close_on_timeout: bool = True,
    ) -> Packet | None:
        """Receive one packet.

        ``timeout=None`` keeps the session default.  With
        ``close_on_timeout=False``, an idle timeout returns ``None`` without
        destroying the session; this is required for long-lived search windows.
        """
        effective_timeout = self.response_timeout if timeout is None else timeout
        if effective_timeout is not None and effective_timeout <= 0:
            if close_on_timeout:
                await self.close()
            return None
        if self._reader is None or not self.connected:
            raise ServerSessionError("ED2K server session is not connected")
        try:
            header = await asyncio.wait_for(
                self._reader.readexactly(_HEADER_SIZE),
                timeout=effective_timeout,
            )
            packet_length = int.from_bytes(header[1:5], "little")
            if packet_length < 1:
                raise ServerSessionError(f"ED2K packet length is below one: {packet_length}")
            payload_size = packet_length - 1
            if payload_size > _MAX_PACKET_SIZE:
                raise ServerSessionError(f"ED2K packet exceeds size limit: {payload_size}")
            payload = (
                b""
                if payload_size == 0
                else await asyncio.wait_for(
                    self._reader.readexactly(payload_size),
                    timeout=effective_timeout,
                )
            )
        except asyncio.IncompleteReadError as exc:
            await self.close()
            raise ServerSessionError(
                f"ED2K server closed session: expected={exc.expected}, got={len(exc.partial)}"
            ) from exc
        except asyncio.TimeoutError as exc:
            if close_on_timeout:
                await self.close()
                raise ServerSessionError("timed out waiting for ED2K server packet") from exc
            return None
        except (OSError, ConnectionResetError) as exc:
            await self.close()
            raise ServerSessionError(f"ED2K receive failed: {exc}") from exc

        try:
            packet, _ = unpack_packet(header + payload)
        except PacketError as exc:
            await self.close()
            raise ServerSessionError(f"invalid ED2K packet received: {exc}") from exc
        log.debug(
            f"ED2K packet received: protocol=0x{packet.protocol:02X}, "
            f"opcode=0x{packet.opcode:02X}, payload={len(packet.payload)}"
        )
        return packet

    def _require_edonkey(self, packet: Packet) -> None:
        if packet.protocol != EDONKEY:
            raise ServerSessionError(
                f"unexpected ED2K protocol byte: 0x{packet.protocol:02X}"
            )

    def _require_logged_in(self) -> None:
        if not self.logged_in:
            raise ServerSessionError("ED2K server session is not logged in")

    async def _consume_auxiliary_packet(self, packet: Packet) -> bool:
        """Consume known non-response packets; return true when handled."""
        if packet.opcode == C2STCP.SERVERMESSAGE:
            message = _parse_server_message(packet.payload)
            self.messages.append(message.message)
            log.info(f"ED2K server message: text={message.message[:160]!r}")
            return True
        if packet.opcode == C2STCP.SERVERSTATUS:
            self.status = _parse_server_status(packet.payload)
            log.info(
                f"ED2K server status: users={self.status.users}, "
                f"files={self.status.files}"
            )
            return True
        return False

    async def login(self) -> LoginResult:
        """Send login and consume initial server responses until ID change."""
        if self.logged_in:
            raise ServerSessionError("ED2K session is already logged in")
        if not self.is_connected:
            await self.connect()

        started = time.monotonic()
        await self._send_packet(
            Packet(
                protocol=EDONKEY,
                opcode=C2STCP.LOGINREQUEST,
                payload=build_login_payload(self.login_request),
            )
        )
        log.info(f"ED2K login sent: endpoint={self.host}:{self.port}")

        while True:
            packet = await self._receive_packet()
            self._require_edonkey(packet)

            if packet.opcode == C2STCP.SERVERMESSAGE:
                message = _parse_server_message(packet.payload)
                self.messages.append(message.message)
                log.info(f"ED2K server message: text={message.message[:160]!r}")
                continue

            if packet.opcode == C2STCP.SERVERIDENT:
                self.identity = _parse_server_ident(packet.payload)
                log.info(
                    f"ED2K server identified: name={self.identity.name()!r}, "
                    f"port={self.identity.port}"
                )
                continue

            if packet.opcode == C2STCP.SERVERSTATUS:
                self.status = _parse_server_status(packet.payload)
                log.info(
                    f"ED2K server status: users={self.status.users}, "
                    f"files={self.status.files}"
                )
                continue

            if packet.opcode == C2STCP.IDCHANGE:
                id_change = _parse_server_id_change(packet.payload)
                self.login_request = LoginRequest(
                    user_hash=self.login_request.user_hash,
                    client_id=id_change.client_id,
                    client_port=self.login_request.client_port,
                    nickname=self.login_request.nickname,
                    edonkey_version=self.login_request.edonkey_version,
                    emule_version=self.login_request.emule_version,
                    capabilities=self.login_request.capabilities,
                )
                self.logged_in = True
                result = LoginResult(
                    client_id=id_change.client_id,
                    low_id=id_change.client_id < _HIGH_ID_THRESHOLD,
                    identity=self.identity,
                    status=self.status,
                    id_change=id_change,
                    messages=list(self.messages),
                    elapsed=time.monotonic() - started,
                )
                log.info(
                    f"ED2K login completed: client_id={id_change.client_id}, "
                    f"low_id={result.low_id}, flags=0x{id_change.server_flags:08X}, "
                    f"elapsed={result.elapsed:.3f}"
                )
                return result

            if packet.opcode == C2STCP.REJECT:
                await self.close()
                log.warning("ED2K login rejected by server")
                raise ServerSessionError("ED2K login was rejected by the server")

            log.warning(f"Unhandled ED2K packet during login: opcode=0x{packet.opcode:02X}")

    async def search(
        self,
        query: str,
        duration: float = 30.0,
    ) -> list[SearchResult]:
        """Run a global ED2K search and accumulate results over a time window.

        ED2K search is inherently asynchronous: servers deliver result batches
        over time and may legitimately return an empty batch before later data
        arrives.  Therefore this method keeps the session alive and aggregates
        all packets received within *duration* seconds.
        """
        self._require_logged_in()
        if duration <= 0:
            raise ServerSessionError("search duration must be greater than zero")
        payload = build_global_search_payload(query)
        await self._send_packet(
            Packet(
                protocol=EDONKEY,
                opcode=C2STCP.SEARCHREQUEST,
                payload=payload,
            )
        )
        log.info(
            f"ED2K server search sent: endpoint={self.host}:{self.port}, "
            f"query={query!r}, duration={duration:.1f}"
        )

        results: dict[bytes, SearchResult] = {}
        more_results = False
        packet_batches = 0
        deadline = time.monotonic() + duration
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                packet = await self._receive_packet(
                    timeout=remaining,
                    close_on_timeout=False,
                )
            except ServerSessionError as exc:
                # A server may close its end after delivering the final batch.
                # Results already accumulated remain valid.
                if not self.is_connected and "closed session" in str(exc):
                    log.warning(
                        f"ED2K search session closed by server: endpoint={self.host}:{self.port}, "
                        f"accumulated={len(results)}"
                    )
                    break
                raise

            if packet is None:
                break
            self._require_edonkey(packet)
            if await self._consume_auxiliary_packet(packet):
                continue

            if packet.opcode == C2STCP.SEARCHRESULT:
                response = parse_search_results(packet.payload)
                packet_batches += 1
                more_results = more_results or response.more_results_available
                for result in response.results:
                    results.setdefault(result.file_hash, result)
                log.info(
                    f"ED2K server search batch received: query={query!r}, "
                    f"batch={len(response.results)}, accumulated={len(results)}, "
                    f"more={response.more_results_available}"
                )
                continue
            if packet.opcode == C2STCP.REJECT:
                await self.close()
                raise ServerSessionError("ED2K search was rejected by the server")
            log.warning(
                f"Unhandled ED2K packet during search: opcode=0x{packet.opcode:02X}"
            )

        log.info(
            f"ED2K server search completed: query={query!r}, "
            f"results={len(results)}, batches={packet_batches}, "
            f"more={more_results}, endpoint={self.host}:{self.port}"
        )
        return list(results.values())

    async def get_sources(self, file_hash: bytes, file_size: int) -> FoundSources:
        """Request sources and wait one protocol response window.

        ED2K servers do not guarantee a reply when no source is known, so an
        idle timeout is normalized to an empty source response without closing
        the session.
        """
        self._require_logged_in()
        payload = build_get_sources_payload(file_hash, file_size)
        await self._send_packet(
            Packet(
                protocol=EDONKEY,
                opcode=C2STCP.GETSOURCES,
                payload=payload,
            )
        )
        log.info(
            f"ED2K sources request sent: endpoint={self.host}:{self.port}, "
            f"hash={file_hash.hex().upper()}"
        )

        while True:
            packet = await self._receive_packet(close_on_timeout=False)
            if packet is None:
                log.warning(
                    f"ED2K source lookup returned no packet: "
                    f"hash={file_hash.hex().upper()}, endpoint={self.host}:{self.port}"
                )
                return FoundSources(file_hash=file_hash, sources=())
            self._require_edonkey(packet)
            if await self._consume_auxiliary_packet(packet):
                continue
            if packet.opcode in (C2STCP.FOUNDSOURCES, C2STCP.FOUNDSOURCES_OBFU):
                sources = parse_found_sources(
                    packet.payload,
                    obfuscated=packet.opcode == C2STCP.FOUNDSOURCES_OBFU,
                )
                log.info(
                    f"ED2K sources received: hash={sources.file_hash.hex().upper()}, "
                    f"count={len(sources.sources)}, endpoint={self.host}:{self.port}"
                )
                return sources
            if packet.opcode == C2STCP.REJECT:
                await self.close()
                raise ServerSessionError(
                    "ED2K source request was rejected by the server"
                )
            log.warning(
                f"Unhandled ED2K packet during source request: "
                f"opcode=0x{packet.opcode:02X}"
            )
