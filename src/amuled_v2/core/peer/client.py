"""Asyncio peer (client-to-client) TCP session and download transfer.

Implements the eMule-compatible download flow against one remote client:

1. connect and ``OP_HELLO`` / ``OP_HELLOANSWER`` handshake;
2. ``OP_EMULEINFO`` (eMule protocol 0xC5) exchange, required before most
   peers answer file requests;
3. ``OP_REQUESTFILENAME`` + ``OP_SETREQFILEID`` + ``OP_HASHSETREQUEST``;
4. upload-queue wait: ``OP_STARTUPLOADREQ``, then ``OP_QUEUERANK`` updates
   until ``OP_ACCEPTUPLOADREQ`` grants a slot;
5. transfer loop: ``OP_REQUESTPARTS`` (three blocks of up to 184320 bytes)
   answered by ``OP_SENDINGPART`` / ``OP_COMPRESSEDPART`` (plus I64
   variants), every block handed to a caller sink until the file completes
   or the peer sends ``OP_END_OF_DOWNLOAD``.

src/amuled_v2/core/peer/client.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added asyncio peer session with bounded framing and idle timeouts.
  [+] Added hello and EMULEINFO handshake handling.
  [+] Added filename/hashset request and upload-queue wait states.
  [+] Added the block transfer loop with compressed-part support.
  [+] Added tagged PEER diagnostics and structured session reports.
"""

from __future__ import annotations

import asyncio
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from amuled_v2.core.codec.constants import EDONKEY
from amuled_v2.core.codec.tags import Ed2kTag, write_new_tag
from amuled_v2.core.peer.codec import (
    C2CTCP,
    HashSetAnswer,
    SendingPart,
    PeerCodecError,
    build_hello_payload,
    build_request_filename_payload,
    build_request_parts_i64_payload,
    build_request_parts_payload,
    parse_compressed_part,
    parse_compressed_part_i64,
    parse_file_hash_payload,
    parse_filename_answer,
    parse_hashset_answer,
    parse_hello,
    parse_queue_rank,
    parse_sending_part,
    parse_sending_part_i64,
)
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.PEER, "core.peer.client")

__all__ = [
    "EMULE_PROTOCOL",
    "C2CEMULE",
    "EMBLOCK_SIZE",
    "PeerSessionError",
    "PeerInfo",
    "DownloadOutcome",
    "PeerClient",
]

EMULE_PROTOCOL = 0xC5
EMBLOCK_SIZE = 184_320
MAX_PACKET_SIZE = 16 * 1024 * 1024
_HEADER_SIZE = 6


class C2CEMULE:
    """eMule-protocol client-to-client opcodes (protocol byte 0xC5)."""

    EMULEINFO = 0x01
    EMULEINFOANSWER = 0x02
    QUEUERANKING = 0x60
    REQUESTPARTS_A4 = 0xA4
    COMPRESSEDPART_A4 = 0xA4


class PeerSessionError(RuntimeError):
    """Raised when a peer session is used or answered incorrectly."""


@dataclass(frozen=True)
class PeerInfo:
    """Everything learned about the remote peer after the handshake."""

    user_hash: str
    client_id: int
    client_port: int
    nickname: str
    server_ip: Optional[int] = None
    server_port: Optional[int] = None
    emule_version: Optional[int] = None
    compression: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "user_hash": self.user_hash,
            "client_id": self.client_id,
            "client_port": self.client_port,
            "nickname": self.nickname,
            "server_ip": self.server_ip,
            "server_port": self.server_port,
            "emule_version": self.emule_version,
            "compression": self.compression,
        }


@dataclass
class DownloadOutcome:
    """Result of one transfer attempt against one peer."""

    file_hash: str
    bytes_received: int
    blocks_received: int
    complete: bool
    elapsed: float = 0.0
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "file_hash": self.file_hash,
            "bytes_received": self.bytes_received,
            "blocks_received": self.blocks_received,
            "complete": self.complete,
            "elapsed": self.elapsed,
            "detail": self.detail,
        }


def _pack_ip(value: int) -> str:
    return f"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}"


def build_emuleinfo_payload(emule_version: int = 0x3C) -> bytes:
    """Build a minimal OP_EMULEINFO payload (version, protocol, tags)."""
    import io

    writer_chunks: list[bytes] = []
    writer_chunks.append(bytes([emule_version, 0x01]))
    writer = struct.Struct("<I")

    tags: list[Ed2kTag] = [
        Ed2kTag(name_id=0x20, type=0x03, value=1),   # ET_COMPRESSION
        Ed2kTag(name_id=0x15, type=0x03, value=1),   # ET_SOURCEEXCHANGE
        Ed2kTag(name_id=0x0F, type=0x03, value=0),   # ET_UDPPORTS placeholder
    ]
    body = io.BytesIO()
    body.write(writer.pack(len(tags)))
    from amuled_v2.core.codec.binary import BinaryWriter

    tag_writer = BinaryWriter()
    for tag in tags:
        write_new_tag(tag, tag_writer)
    body.write(tag_writer.to_bytes())
    writer_chunks.append(body.getvalue())
    return b"".join(writer_chunks)


class PeerClient:
    """One asyncio client-to-client TCP session for downloading."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        local_client_id: int = 0,
        local_port: int = 8089,
        nickname: str = "AmuleD",
        connect_timeout: float = 10.0,
        response_timeout: float = 20.0,
        queue_wait_timeout: float = 120.0,
    ) -> None:
        self.host = host
        self.port = port
        self.local_client_id = local_client_id
        self.local_port = local_port
        self.nickname = nickname
        self.connect_timeout = connect_timeout
        self.response_timeout = response_timeout
        self.queue_wait_timeout = queue_wait_timeout
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self.connected = False
        self.peer_info: Optional[PeerInfo] = None
        import os

        self.user_hash = os.urandom(16)

    @property
    def is_connected(self) -> bool:
        return self.connected and self._writer is not None

    # -- transport -----------------------------------------------------------

    async def connect(self) -> None:
        if self.is_connected:
            return
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.connect_timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            log.error(
                "PEER connect failed: host=%s, port=%d, error=%s",
                self.host,
                self.port,
                exc,
            )
            raise PeerSessionError(
                f"cannot connect to peer {self.host}:{self.port}: {exc}"
            ) from exc
        self.connected = True
        log.info("PEER connected: host=%s, port=%d", self.host, self.port)

    async def close(self) -> None:
        if self._writer is not None:
            writer = self._writer
            self._writer = None
            self._reader = None
            self.connected = False
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass
            log.info("PEER disconnected: host=%s, port=%d", self.host, self.port)

    async def __aenter__(self) -> "PeerClient":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self.close()

    def _require_writer(self) -> asyncio.StreamWriter:
        if self._writer is None or not self.connected:
            raise PeerSessionError("peer session is not connected")
        return self._writer

    async def _send(self, protocol: int, opcode: int, payload: bytes = b"") -> None:
        writer = self._require_writer()
        wire = (
            bytes([protocol])
            + struct.pack("<I", len(payload) + 1)
            + bytes([opcode])
            + payload
        )
        writer.write(wire)
        try:
            await writer.drain()
        except (OSError, ConnectionResetError) as exc:
            await self.close()
            raise PeerSessionError(f"peer send failed: {exc}") from exc
        log.debug(
            "PEER packet sent: protocol=0x%02X, opcode=0x%02X, payload=%d",
            protocol,
            opcode,
            len(payload),
        )

    async def _receive(
        self,
        *,
        timeout: float | None = None,
        close_on_timeout: bool = True,
    ) -> Optional[tuple[int, int, bytes]]:
        """Receive one framed packet; returns (protocol, opcode, payload)."""
        effective = self.response_timeout if timeout is None else timeout
        reader = self._reader
        if reader is None or not self.connected:
            raise PeerSessionError("peer session is not connected")
        try:
            header = await asyncio.wait_for(
                reader.readexactly(_HEADER_SIZE), timeout=effective
            )
            packet_length = struct.unpack("<I", header[1:5])[0]
            if packet_length < 1:
                raise PeerSessionError(f"peer packet length below one: {packet_length}")
            payload_size = packet_length - 1
            if payload_size > MAX_PACKET_SIZE:
                raise PeerSessionError(
                    f"peer packet exceeds size limit: {payload_size}"
                )
            payload = (
                b""
                if payload_size == 0
                else await asyncio.wait_for(
                    reader.readexactly(payload_size), timeout=effective
                )
            )
        except asyncio.IncompleteReadError as exc:
            await self.close()
            raise PeerSessionError(
                f"peer closed connection: expected={exc.expected}, got={len(exc.partial)}"
            ) from exc
        except asyncio.TimeoutError as exc:
            if close_on_timeout:
                await self.close()
                raise PeerSessionError("timed out waiting for peer packet") from exc
            return None
        except (OSError, ConnectionResetError) as exc:
            await self.close()
            raise PeerSessionError(f"peer receive failed: {exc}") from exc
        return header[0], header[5], payload

    # -- handshake -----------------------------------------------------------

    async def handshake(self) -> PeerInfo:
        """Run HELLO and EMULEINFO exchange; returns learned peer info."""
        if self.peer_info is not None:
            return self.peer_info
        await self._send(
            EDONKEY,
            C2CTCP.HELLO,
            build_hello_payload(
                user_hash=self.user_hash,
                client_id=self.local_client_id,
                client_port=self.local_port,
                nickname=self.nickname,
            ),
        )
        await self._send(EMULE_PROTOCOL, C2CEMULE.EMULEINFO, build_emuleinfo_payload())

        hello_seen = False
        info_seen = False
        peer: Optional[PeerInfo] = None
        deadline = time.monotonic() + self.response_timeout * 2
        while not (hello_seen and info_seen):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PeerSessionError(
                    "peer handshake incomplete: hello=%s, info=%s"
                    % (hello_seen, info_seen)
                )
            packet = await self._receive(timeout=min(remaining, self.response_timeout))
            if packet is None:
                continue
            protocol, opcode, payload = packet
            if protocol == EDONKEY and opcode == C2CTCP.HELLOANSWER:
                parsed = parse_hello(payload)
                peer = PeerInfo(
                    user_hash=parsed.user_hash.hex().upper(),
                    client_id=parsed.client_id,
                    client_port=parsed.client_port,
                    nickname=parsed.nickname,
                    version=getattr(parsed, "version", None),
                )
                hello_seen = True
                log.info(
                    "PEER hello answer: nickname=%r, client_id=%d, port=%d",
                    parsed.nickname,
                    parsed.client_id,
                    parsed.client_port,
                )
            elif protocol == EDONKEY and opcode == C2CTCP.HELLO:
                parsed = parse_hello(payload)
                peer = PeerInfo(
                    user_hash=parsed.user_hash.hex().upper(),
                    client_id=parsed.client_id,
                    client_port=parsed.client_port,
                    nickname=parsed.nickname,
                )
                hello_seen = True
                await self._send(EDONKEY, C2CTCP.HELLOANSWER, build_hello_payload(
                    user_hash=self.user_hash,
                    client_id=self.local_client_id,
                    client_port=self.local_port,
                    nickname=self.nickname,
                ))
            elif protocol == EMULE_PROTOCOL and opcode == C2CEMULE.EMULEINFOANSWER:
                info_seen = True
                compression = len(payload) >= 3 and bool(payload[3] & 0x01)
                if peer is not None:
                    peer = PeerInfo(
                        user_hash=peer.user_hash,
                        client_id=peer.client_id,
                        client_port=peer.client_port,
                        nickname=peer.nickname,
                        server_ip=peer.server_ip,
                        server_port=peer.server_port,
                        emule_version=payload[0] if payload else None,
                        compression=compression,
                    )
                log.info("PEER emule info answer: compression=%s", compression)
            elif protocol == EMULE_PROTOCOL and opcode == C2CEMULE.EMULEINFO:
                info_seen = True
                await self._send(
                    EMULE_PROTOCOL, C2CEMULE.EMULEINFOANSWER, build_emuleinfo_payload()
                )
            else:
                log.debug(
                    "PEER ignoring packet during handshake: "
                    "protocol=0x%02X, opcode=0x%02X",
                    protocol,
                    opcode,
                )
        if peer is None:
            raise PeerSessionError("peer handshake finished without HELLOANSWER")
        self.peer_info = peer
        return peer

    # -- file request and queue ----------------------------------------------

    async def request_file(self, file_hash: bytes) -> HashSetAnswer:
        """Send filename/fileid/hashset requests; returns the answer."""
        await self._send(
            EDONKEY, C2CTCP.REQUESTFILENAME, build_request_filename_payload(file_hash)
        )
        await self._send(EDONKEY, C2CTCP.SETREQFILEID, build_request_filename_payload(file_hash))
        await self._send(EDONKEY, C2CTCP.HASHSETREQUEST, build_request_filename_payload(file_hash))
        await self._send(EDONKEY, C2CTCP.STARTUPLOADREQ, build_request_filename_payload(file_hash))
        log.info(
            "PEER file requested: host=%s:%d, hash=%s",
            self.host,
            self.port,
            file_hash.hex().upper(),
        )

        filename_answered = False
        while True:
            packet = await self._receive()
            if packet is None:
                raise PeerSessionError("peer request window timed out")
            protocol, opcode, payload = packet
            if protocol != EDONKEY:
                log.debug(
                    "PEER ignoring non-ED2K packet: protocol=0x%02X, opcode=0x%02X",
                    protocol,
                    opcode,
                )
                continue
            if opcode == C2CTCP.REQFILENAMEANSWER:
                answer = parse_filename_answer(payload)
                filename_answered = True
                log.info(
                    "PEER filename answer: hash=%s, name=%r",
                    answer.file_hash.hex().upper(),
                    answer.name,
                )
                continue
            if opcode == C2CTCP.HASHSETANSWER:
                hashset = parse_hashset_answer(payload)
                if not filename_answered:
                    log.debug("PEER hashset answer arrived before filename answer")
                return hashset
            if opcode == C2CTCP.FILEREQANSNOFIL:
                raise PeerSessionError(
                    f"peer does not have file {payload[:16].hex().upper() if len(payload) >= 16 else '?'}"
                )
            if opcode == C2CTCP.QUEUERANK:
                rank = parse_queue_rank(payload)
                log.info(
                    "PEER queue rank during request: rank=%d, host=%s:%d",
                    rank,
                    self.host,
                    self.port,
                )
                continue
            log.debug(
                "PEER ignoring packet while requesting file: opcode=0x%02X",
                opcode,
            )

    async def wait_upload_slot(
        self,
        file_hash: bytes,
        *,
        rank_callback: Optional[Callable[[int], None]] = None,
    ) -> None:
        """Wait until the peer grants an upload slot for this file."""
        deadline = time.monotonic() + self.queue_wait_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PeerSessionError(
                    f"upload slot not granted within {self.queue_wait_timeout:.0f}s: "
                    f"host={self.host}:{self.port}"
                )
            packet = await self._receive(
                timeout=min(remaining, self.response_timeout), close_on_timeout=False
            )
            if packet is None:
                await self._send(
                    EDONKEY, C2CTCP.STARTUPLOADREQ, build_request_filename_payload(file_hash)
                )
                continue
            protocol, opcode, payload = packet
            if protocol != EDONKEY:
                continue
            if opcode == C2CTCP.ACCEPTUPLOADREQ:
                log.info(
                    "PEER upload slot granted: host=%s:%d, hash=%s",
                    self.host,
                    self.port,
                    file_hash.hex().upper(),
                )
                return
            if opcode == C2CTCP.QUEUERANK:
                rank = parse_queue_rank(payload)
                log.info(
                    "PEER queue rank: rank=%d, host=%s:%d, hash=%s",
                    rank,
                    self.host,
                    self.port,
                    file_hash.hex().upper(),
                )
                if rank_callback is not None:
                    try:
                        rank_callback(rank)
                    except Exception:
                        pass
                continue
            if opcode == C2CTCP.FILEREQANSNOFIL:
                raise PeerSessionError("peer reported the file as unavailable")
            log.debug(
                "PEER ignoring packet while waiting for slot: opcode=0x%02X",
                opcode,
            )

    # -- transfer ------------------------------------------------------------

    async def transfer(
        self,
        file_hash: bytes,
        total_size: int,
        *,
        write_block: Callable[[int, bytes], None],
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
        max_blocks: int = 100_000,
    ) -> DownloadOutcome:
        """Run the request-parts / sending-part loop until completion.

        ``write_block(start, data)`` receives every verified block (already
        decompressed).  ``progress_callback(received_bytes, total_size,
        blocks)`` fires after each block.
        """
        started = time.monotonic()
        await self._send(EDONKEY, C2CTCP.ACCEPTUPLOADREQ)
        received = 0
        blocks = 0
        compressed = self.peer_info.compression if self.peer_info else False

        def _remaining_sink() -> list[tuple[int, int]]:
            try:
                remaining = total_size - received
            except Exception:
                return []
            return [(0, min(remaining, total_size))] if remaining > 0 else []

        while blocks < max_blocks:
            if received >= total_size:
                break
            starts, ends = [], []
            for offset in (received, received + EMBLOCK_SIZE, received + 2 * EMBLOCK_SIZE):
                if offset >= total_size:
                    break
                end = min(offset + EMBLOCK_SIZE, total_size)
                starts.append(offset)
                ends.append(end)
            if not starts:
                break
            while len(starts) < 3:
                starts.append(0)
                ends.append(0)
            if any(value > 0xFFFFFFFF for value in starts + ends):
                await self._send(
                    EDONKEY,
                    C2CTCP.REQUESTPARTS_I64,
                    build_request_parts_i64_payload(
                        file_hash,
                        (starts[0], starts[1], starts[2]),
                        (ends[0], ends[1], ends[2]),
                    ),
                )
            else:
                await self._send(
                    EDONKEY,
                    C2CTCP.REQUESTPARTS,
                    build_request_parts_payload(
                        file_hash,
                        (starts[0], starts[1], starts[2]),
                        (ends[0], ends[1], ends[2]),
                    ),
                )
            log.debug(
                "PEER parts requested: host=%s:%d, count=%d, from=%d",
                self.host,
                self.port,
                len([s for s in starts if s < total_size]),
                starts[0],
            )

            expected = len(starts)
            while expected > 0:
                packet = await self._receive(
                    timeout=self.response_timeout, close_on_timeout=False
                )
                if packet is None:
                    outcome = DownloadOutcome(
                        file_hash=file_hash.hex().upper(),
                        bytes_received=received,
                        blocks_received=blocks,
                        complete=received >= total_size,
                        elapsed=time.monotonic() - started,
                        detail="idle timeout while transferring",
                    )
                    log.warning(
                        "PEER transfer stalled: host=%s:%d, received=%d/%d",
                        self.host,
                        self.port,
                        received,
                        total_size,
                    )
                    return outcome
                protocol, opcode, payload = packet
                if protocol != EDONKEY:
                    continue
                part: Optional[SendingPart] = None
                if opcode == C2CTCP.SENDINGPART:
                    part = parse_sending_part(payload)
                elif opcode == C2CTCP.SENDINGPART_I64:
                    part = parse_sending_part_i64(payload)
                elif opcode == C2CTCP.COMPRESSEDPART:
                    part = parse_compressed_part(payload)
                elif opcode == C2CTCP.COMPRESSEDPART_I64:
                    part = parse_compressed_part_i64(payload)
                elif opcode == C2CTCP.END_OF_DOWNLOAD:
                    log.info(
                        "PEER end of download: host=%s:%d, received=%d/%d",
                        self.host,
                        self.port,
                        received,
                        total_size,
                    )
                    expected = 0
                    break
                elif opcode == C2CTCP.OUTOFPARTREQS:
                    outcome = DownloadOutcome(
                        file_hash=file_hash.hex().upper(),
                        bytes_received=received,
                        blocks_received=blocks,
                        complete=received >= total_size,
                        elapsed=time.monotonic() - started,
                        detail="peer has no more parts",
                    )
                    return outcome
                elif opcode == C2CTCP.QUEUERANK:
                    log.info(
                        "PEER requeued during transfer: rank=%d",
                        parse_queue_rank(payload),
                    )
                    outcome = DownloadOutcome(
                        file_hash=file_hash.hex().upper(),
                        bytes_received=received,
                        blocks_received=blocks,
                        complete=received >= total_size,
                        elapsed=time.monotonic() - started,
                        detail="moved back to queue",
                    )
                    return outcome
                else:
                    log.debug(
                        "PEER ignoring packet during transfer: opcode=0x%02X",
                        opcode,
                    )
                    continue
                if part is None:
                    continue
                write_block(part.start, part.data)
                received += len(part.data)
                blocks += 1
                if progress_callback is not None:
                    try:
                        progress_callback(received, total_size, blocks)
                    except Exception:
                        pass
                expected -= 1
            if received >= total_size:
                break

        complete = received >= total_size
        outcome = DownloadOutcome(
            file_hash=file_hash.hex().upper(),
            bytes_received=received,
            blocks_received=blocks,
            complete=complete,
            elapsed=time.monotonic() - started,
            detail="transfer finished",
        )
        log.info(
            "PEER transfer completed: host=%s:%d, received=%d/%d, complete=%s",
            self.host,
            self.port,
            received,
            total_size,
            complete,
        )
        return outcome
