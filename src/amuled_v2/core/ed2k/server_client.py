"""Asyncio ED2K server TCP session and server-response parsers.

Implements the M4 connection foundation described by
``docs/PROTOCOL_MATRIX.md``, section 4: bounded packet framing, login dispatch,
server identity/status/message parsing, and high/low-ID classification.  The
client is loopback-testable and does not perform obfuscation yet.

src/amuled_v2/core/ed2k/server_client.py
Version:     0.1.3
Author:      Soror L.'.L.'.
Updated:     2026-09-22

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
import time
from dataclasses import dataclass, field
from typing import Optional

from amuled_v2.core.codec.binary import BinaryReader, CodecError
from amuled_v2.core.codec.constants import EDONKEY
from amuled_v2.core.codec.packet import Packet, PacketError, decode_packet
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
    "ServerIdentity",
    "ServerIdChange",
    "ServerStatus",
    "ServerMessage",
    "LoginResult",
    "ServerSessionError",
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

    async def _receive_packet(self) -> Packet:
        if self._reader is None or not self.connected:
            raise ServerSessionError("ED2K server session is not connected")
        try:
            header = await asyncio.wait_for(
                self._reader.readexactly(_HEADER_SIZE),
                timeout=self.response_timeout,
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
                    timeout=self.response_timeout,
                )
            )
        except asyncio.IncompleteReadError as exc:
            await self.close()
            raise ServerSessionError(
                f"ED2K server closed session: expected={exc.expected}, got={len(exc.partial)}"
            ) from exc
        except asyncio.TimeoutError as exc:
            await self.close()
            raise ServerSessionError("timed out waiting for ED2K server packet") from exc
        except (OSError, ConnectionResetError) as exc:
            await self.close()
            raise ServerSessionError(f"ED2K receive failed: {exc}") from exc

        try:
            packet, _ = decode_packet(header + payload)
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
