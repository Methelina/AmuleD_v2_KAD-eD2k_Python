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
Version:     0.7.2
Author:      Soror L.'.L.'.
Updated:     2026-09-28

Patch Notes v0.7.2 (Soror L'.L'.):
  [+] Constructor accepts plain_dial_ok (default False) - the runner's
      obf-dial fallback (runner.py 0.9.x) retries with
      PeerClient(target_userhash=None, plain_dial_ok=True) when the peer
      ignores the BASIC handshake; without the kwarg the fallback died with
      "unexpected keyword argument" (live 2026-09-28).  Plain dial already
      happens whenever target_userhash is None; the flag is accepted for
      API parity and future gating.

Patch Notes v0.7.1 (Soror L'.L'.):
  [+] transfer(): per-packet idle window inside data rounds widened to
      response_timeout * 3 - a throttled uploader can need >20 s for the
      first SENDINGPART after the slot grant (live evidence 2026-09-28:
      eMuleAI pushed 398 KB over 20 s while the 20 s idle timeout cut the
      session at received=0).  Control-phase timeouts unchanged.

Patch Notes v0.7.0 (Soror L'.L'.):
  [+] ICS: part-status capture — OP_FILESTATUS (0x50) parsed at every
      dispatch site (handshake, request_file, wait_upload_slot, transfer);
      complete_sources set and part_status dict populated; parse errors
      caught (PeerCodecError) and logged at debug, never crash the loop.
  [+] ICS: transfer() gains block_selector / release_ranges keyword params;
      when a selector is supplied it provides inclusive (start,end) ranges
      converted to the payload's exclusive (start, end+1) convention;
      linear fallback path unchanged when selector is None.

Patch Notes v0.6.0 (Soror L'.L'.):
  [+] transfer(start_offset, end_offset): stripe scheduling — a racing
      peer downloads only its disjoint region; write offsets stay
      absolute, the queue gap list remains the completion source of
      truth.  Before: every racing peer redundantly downloaded from
      offset 0.

Patch Notes v0.5.0 (Soror L'.L'.):
  [+] Source exchange requester (stage X): request_sources() — SX2 when
      the peer advertises miso2 bit 10 (new codec helper
      miso2_source_exchange_v2, tag 0xFE) or SX1 nibble > 1, legacy
      OP_REQUESTSOURCES for SX1 == 1; OP_ANSWERSOURCES(2) collected in
      the wait/transfer receive loops (peer_tags now retained).

Patch Notes v0.4.0 (Soror L'.L'.):
  [+] AICH requester: request_aich() — OP_AICHREQUEST over the session
      with the responder's master gate, OP_AICHANSWER parsing (client
      side of stage X; recovery verification lives in hashes/aich.py).

Patch Notes v0.3.0 (Soror L'.L'.):
  [+] BASIC-obfuscation session wired into the transport (block 11e #6,
      closed live in session 11): with a known target userhash, connect()
      negotiates the obfuscation handshake on ONE persistent RC4 stream per
      direction (BasicObfuscationSession) and every frame is
      encrypted/decrypted on that stream afterwards.  No plaintext
      fallback: the plain protocol is dead on today's network (instant
      FIN).  Response leftovers are buffered in _rx_plain and consumed
      exactly once.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added asyncio peer session with bounded framing and idle timeouts.
  [+] Added hello and EMULEINFO handshake handling.
  [+] Added filename/hashset request and upload-queue wait states.
  [+] Added the block transfer loop with compressed-part support.
  [+] Added tagged PEER diagnostics and structured session reports.
"""

from __future__ import annotations

import asyncio
import os
import struct
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

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
    parse_compressed_part_chunk,
    parse_compressed_part_chunk_i64,
    parse_compressed_part_i64,
    parse_file_hash_payload,
    parse_filename_answer,
    parse_hashset_answer,
    parse_file_status,
    parse_hello,
    parse_queue_rank,
    parse_sending_part,
    parse_sending_part_i64,
    build_secident_state_payload,
    build_publickey_payload,
    build_signature_payload,
    parse_secident_state_payload,
    parse_publickey_payload,
    parse_signature_payload,
    miso1_secident_support,
    build_aich_request_payload,
    parse_aich_answer_payload,
    parse_answer_sources,
    parse_answer_sources2,
)
from amuled_v2.core.peer.obfuscation import (
    BasicObfuscationSession,
    ObfuscationError,
    negotiate_basic_client,
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
    # SecureIdent (stage X; Opcodes.h):
    PUBLICKEY = 0x85
    SIGNATURE = 0x86
    SECIDENTSTATE = 0x87
    # Source exchange (stage X; Opcodes.h):
    REQUESTSOURCES = 0x81
    ANSWERSOURCES = 0x82
    REQUESTSOURCES2 = 0x83
    ANSWERSOURCES2 = 0x84
    # AICH (stage X; Opcodes.h):
    AICHREQUEST = 0x9B
    AICHANSWER = 0x9C


# OP_OUTOFPARTREQS retry policy: the source needs a moment to read the
# file into its upload buffer after granting the slot.
_OUTOFPART_MAX_RETRIES = 5
_OUTOFPART_RETRY_DELAY = 3.0


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
    """OP_EMULEINFO: u8 версия, u8 протокол (0xC5!), u32 tagcount, 7 флаг-тегов.

    ВАЖНО (уже ломали): второй байт обязан быть 0xC5, иначе приёмник считает
    нас не-eMule, не принимает инфо-пакет и рвёт соединение по своему
    таймауту хендшейка (~10 с). Набор тегов — стандартные 7 флагов; id и
    порядок менять нельзя.

    Значения — честные (сверка стадии X): заявляем сжатие, source exchange
    v4 (responder в listener.py) и (в features) то, что реально обрабатываем.
    udp version aux-операции и комментарии мы не отвечаем — нули.
    """
    from amuled_v2.core.codec.binary import BinaryWriter

    writer = BinaryWriter()
    writer.write_u8(emule_version)
    writer.write_u8(EMULE_PROTOCOL)
    tags: list[Ed2kTag] = [
        Ed2kTag(name_id=0x20, type=0x03, value=1),   # сжатие данных (есть)
        Ed2kTag(name_id=0x22, type=0x03, value=0),   # udp version (aux — нет)
        Ed2kTag(name_id=0x21, type=0x03, value=0),   # udp port (нет)
        Ed2kTag(name_id=0x23, type=0x03, value=4),   # source exchange v4 (responder)
        Ed2kTag(name_id=0x24, type=0x03, value=0),   # comments (нет)
        Ed2kTag(name_id=0x25, type=0x03, value=0),   # extended requests (нет)
        Ed2kTag(name_id=0x27, type=0x03, value=3),   # features: full SUI + v2
    ]
    writer.write_u32(len(tags))
    for tag in tags:
        write_new_tag(tag, writer)
    payload = writer.to_bytes()
    log.debug("EMULEINFO payload built: size=%d", len(payload))
    return payload


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
        traffic_sink: Optional[Callable[[str, int], None]] = None,
        target_userhash: Optional[bytes] = None,
        local_userhash: Optional[bytes] = None,
        secure_ident: Optional[Any] = None,
        plain_dial_ok: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.local_client_id = local_client_id
        self.local_port = local_port
        self.nickname = nickname
        self.connect_timeout = connect_timeout
        self.response_timeout = response_timeout
        self.queue_wait_timeout = queue_wait_timeout
        # BASIC-obfuscation target (KAD source_id == peer userhash).  When
        # set, connect() performs the encrypted handshake and every frame
        # afterwards travels over the session's persistent RC4 streams.
        self.target_userhash = bytes(target_userhash) if target_userhash else None
        self.plain_dial_ok = bool(plain_dial_ok)
        self._obf: Optional[BasicObfuscationSession] = None
        # Already-decrypted bytes that arrived together with the handshake
        # response; consumed exactly once by _read_exact().
        self._rx_plain = bytearray()
        # Stage X SecureIdent: shared RSA provider; per-session exchange
        # state (challenge out/in, peer's claimed pubkey blob).
        self._secure_ident = secure_ident
        self._sui: dict[str, Any] = {
            "challenge_in": None,
            "challenge_out": None,
            "peer_blob": b"",
        }
        # Stage C credit accounting: called once per finished transfer with
        # (peer_user_hash_hex, downloaded_bytes); exceptions are swallowed —
        # credit bookkeeping must never break a download.
        self.traffic_sink = traffic_sink
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self.connected = False
        self.peer_info: Optional[PeerInfo] = None
        # Stage X source exchange (requester): peer hello tags and sources
        # collected from OP_ANSWERSOURCES(2) during the session.
        self.peer_tags: tuple = ()
        self.collected_sources: list = []
        # ICS (Intelligent Chunk Selection): part-status captured from
        # OP_FILESTATUS answers.  part_status maps file_hash -> present
        # chunk indices (empty frozenset means complete source, i.e. the
        # peer has every part).  complete_sources is the same set of
        # hashes but indexed for O(1) "has the whole file" checks.
        self.part_status: dict[bytes, frozenset[int]] = {}
        self.complete_sources: set[bytes] = set()
        # eMule marks every generated userhash with SO_EMULE markers
        # (Preferences.cpp::CreateUserHash: hash[5]=14, hash[14]=111);
        # GetHashType uses them to classify the client.  A plain random
        # hash classifies as SO_UNKNOWN and eMuleAI's shield PUNISHES it
        # as "Bad user hash" (verified live 2026-09-26).  The hash must
        # also be STABLE across dials from one IP: eMuleAI tracks clients
        # and bans "Userhash changed" (verified live 2026-09-26).
        raw = bytes(local_userhash) if local_userhash else os.urandom(16)
        if local_userhash is None:
            # FALLBACK (policy: every fallback is logged): a random HELLO
            # identity classifies as SO_UNKNOWN and makes peers ban
            # "Userhash changed" (see comment above; live evidence
            # 2026-09-28 eMuleAI <Ban> [Bad user hash]).
            log.warning(
                "PEER local_userhash fallback: caller supplied no identity, "
                "using random marked hash - peers will treat each dial as a "
                "different client (host=%s:%d)",
                self.host,
                self.port,
            )
        if len(raw) != 16:
            raise PeerSessionError("local_userhash must be exactly 16 bytes")
        marked = bytearray(raw)
        marked[5] = 14
        marked[14] = 111
        self.user_hash = bytes(marked)

    @property
    def is_connected(self) -> bool:
        return self.connected and self._writer is not None

    @classmethod
    def adopt_connection(
        cls,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        local_client_id: int = 0,
        local_port: int = 8089,
        nickname: str = "AmuleD",
        local_userhash: Optional[bytes] = None,
        secure_ident: Optional[Any] = None,
        response_timeout: float = 20.0,
        queue_wait_timeout: float = 120.0,
        traffic_sink: Optional[Callable[[str, int], None]] = None,
    ) -> "PeerClient":
        """Wrap an ALREADY ACCEPTED inbound TCP connection (direct-callback
        flow: the firewalled source dialed us) and run the DOWNLOADER role
        over it.  handshake() then answers the peer's HELLO/EMULEINFO
        instead of initiating them (both branches already exist)."""
        peername = writer.get_extra_info("peername") or ("?", 0)
        host = peername[0] if isinstance(peername, tuple) else str(peername)
        port = peername[1] if isinstance(peername, tuple) and len(peername) > 1 else 0
        client = cls(
            host,
            port,
            local_client_id=local_client_id,
            local_port=local_port,
            nickname=nickname,
            local_userhash=local_userhash,
            secure_ident=secure_ident,
            response_timeout=response_timeout,
            queue_wait_timeout=queue_wait_timeout,
            traffic_sink=traffic_sink,
        )
        client._reader = reader
        client._writer = writer
        client.connected = True
        return client

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
        # BASIC-obfuscation negotiation BEFORE anything else is sent: the
        # peer never sees plaintext, and no app bytes precede the response.
        if self.target_userhash is not None:
            try:
                self._obf, leftover = await negotiate_basic_client(
                    self._reader,
                    self._writer,
                    self.target_userhash,
                    timeout=self.connect_timeout,
                )
            except ObfuscationError as exc:
                await self.close()
                raise PeerSessionError(
                    f"obfuscation handshake failed with "
                    f"{self.host}:{self.port}: {exc}"
                ) from exc
            self._rx_plain = bytearray(leftover)
            log.info(
                "PEER obfuscation established: host=%s, port=%d, "
                "leftover=%d",
                self.host,
                self.port,
                len(leftover),
            )
        self.connected = True
        log.info(
            "PEER connected: host=%s, port=%d, obfuscated=%s",
            self.host,
            self.port,
            self._obf is not None,
        )

    async def close(self) -> None:
        if self._writer is not None:
            writer = self._writer
            self._writer = None
            self._reader = None
            self.connected = False
            self._obf = None
            self._rx_plain.clear()
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
        # One live RC4 stream per direction: after the handshake the session
        # continues exactly where the response padding ended (block 11e #6).
        if self._obf is not None:
            wire = self._obf.encrypt(wire)
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

    async def _read_exact(self, n: int, timeout: float) -> bytes:
        """Read exactly n WIRE bytes, decrypting at the point of
        consumption.  Already-decrypted leftovers are consumed only after
        the read succeeds, and never decrypted twice."""
        reader = self._reader
        assert reader is not None
        take = min(n, len(self._rx_plain))
        raw = b""
        if n > take:
            raw = await asyncio.wait_for(reader.readexactly(n - take), timeout)
        head = bytes(self._rx_plain[:take])
        del self._rx_plain[:take]
        if self._obf is not None:
            return head + self._obf.decrypt(raw)
        return head + raw

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
            header = await self._read_exact(_HEADER_SIZE, effective)
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
                else await self._read_exact(payload_size, effective)
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

    async def raw_peek_last_frame(self) -> Optional[bytes]:
        """Debug helper: peek the pending decrypted bytes without consuming
        them (probe diagnostics only; never used in the transfer path)."""
        if self._reader is None:
            return None
        try:
            pending = bytes(self._rx_plain)
        except Exception:
            pending = b""
        return pending or None

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
        sui_challenged = False
        sui_deadline: Optional[float] = None
        peer: Optional[PeerInfo] = None
        peer_tags: tuple = ()
        deadline = time.monotonic() + self.response_timeout * 2

        async def _maybe_challenge_sui() -> None:
            # Stage X SecureIdent (mirrors listener.py): once the EMULEINFO
            # side of the handshake is through, challenge a SUI-capable peer
            # (BaseClient.cpp InfoPacketsReceived -> SendSecIdentStatePacket).
            nonlocal sui_challenged, sui_deadline
            if sui_challenged:
                return
            provider = self._secure_ident
            if provider is None or not provider.has_keys:
                return
            if not peer_tags or not miso1_secident_support(peer_tags):
                return
            sui_challenged = True
            challenge = int.from_bytes(os.urandom(4), "little") or 1
            self._sui["challenge_out"] = challenge
            sui_deadline = time.monotonic() + 3.0
            await self._send(
                EMULE_PROTOCOL,
                C2CEMULE.SECIDENTSTATE,
                build_secident_state_payload(2, challenge),
            )
            log.debug(
                "PEER SECIDENTSTATE sent: host=%s:%d, challenge=%d",
                self.host, self.port, challenge,
            )

        # The SUI grace period: the peer's PUBLICKEY/SIGNATURE may arrive
        # after hello/info are both seen; keep draining briefly so the
        # verification is not lost (bounded by sui_deadline).
        while not (hello_seen and info_seen) or (
            sui_deadline is not None and time.monotonic() < sui_deadline
        ):
            remaining = deadline - time.monotonic()
            if sui_deadline is not None and hello_seen and info_seen:
                remaining = min(remaining, sui_deadline - time.monotonic())
            if remaining <= 0:
                if hello_seen and info_seen:
                    break  # SUI grace only; the app handshake is complete
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
                peer_tags = parsed.tags
                peer = PeerInfo(
                    user_hash=parsed.user_hash.hex().upper(),
                    client_id=parsed.client_id,
                    client_port=parsed.client_port,
                    nickname=parsed.nickname,
                    server_ip=getattr(parsed, "server_ip", None),
                    server_port=getattr(parsed, "server_port", None),
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
                peer_tags = parsed.tags
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
                await _maybe_challenge_sui()
            elif protocol == EMULE_PROTOCOL and opcode == C2CEMULE.EMULEINFO:
                info_seen = True
                await self._send(
                    EMULE_PROTOCOL, C2CEMULE.EMULEINFOANSWER, build_emuleinfo_payload()
                )
                await _maybe_challenge_sui()
            elif protocol == EMULE_PROTOCOL and opcode == C2CEMULE.SECIDENTSTATE:
                state, challenge = parse_secident_state_payload(payload)
                self._sui["challenge_in"] = challenge
                log.debug(
                    "PEER SECIDENTSTATE received: host=%s:%d, state=%d, challenge=%d",
                    self.host, self.port, state, challenge,
                )
                # Answer with PUBLICKEY + SIGNATURE over [our blob][their
                # challenge] (BaseClient.cpp SendPublicKeyPacket /
                # SendSignaturePacket; mirrors listener.py).
                if self._secure_ident is not None and self._secure_ident.has_keys:
                    await self._send(
                        EMULE_PROTOCOL,
                        C2CEMULE.PUBLICKEY,
                        build_publickey_payload(self._secure_ident.public_blob),
                    )
                    signature = self._secure_ident.create_signature(challenge)
                    await self._send(
                        EMULE_PROTOCOL,
                        C2CEMULE.SIGNATURE,
                        build_signature_payload(signature),
                    )
            elif protocol == EMULE_PROTOCOL and opcode == C2CEMULE.PUBLICKEY:
                self._sui["peer_blob"] = parse_publickey_payload(payload)
                log.debug(
                    "PEER PUBLICKEY received: host=%s:%d, len=%d",
                    self.host, self.port, len(self._sui["peer_blob"]),
                )
            elif protocol == EMULE_PROTOCOL and opcode == C2CEMULE.SIGNATURE:
                signature, _ip_kind = parse_signature_payload(payload)
                challenge_in = self._sui.get("challenge_out")
                peer_blob = self._sui.get("peer_blob", b"")
                if challenge_in is None or not peer_blob or peer is None:
                    log.debug(
                        "PEER SIGNATURE ignored (no challenge/key yet): host=%s:%d",
                        self.host, self.port,
                    )
                else:
                    from amuled_v2.core.security.secure_ident import SecureIdentProvider

                    verified = SecureIdentProvider.verify_signature(
                        peer_blob, signature, challenge_in
                    )
                    if verified and self._secure_ident is not None:
                        self._secure_ident.mark_verified(peer.user_hash.lower())
                    log.info(
                        "PEER SecureIdent %s: host=%s:%d, user_hash=%s",
                        "VERIFIED" if verified else "FAILED",
                        self.host,
                        self.port,
                        peer.user_hash,
                    )
                sui_deadline = None  # signature round over; no grace needed
            else:
                self._capture_file_status(protocol, opcode, payload)
                log.debug(
                    "PEER ignoring packet during handshake: "
                    "protocol=0x%02X, opcode=0x%02X",
                    protocol,
                    opcode,
                )
        if peer is None:
            raise PeerSessionError("peer handshake finished without HELLOANSWER")
        self.peer_info = peer
        self.peer_tags = peer_tags
        return peer

    # -- source exchange (requester; stage X) ---------------------------------

    async def request_sources(
        self, file_hash: bytes, *, sx_options: int = 0
    ) -> None:
        """Ask a source-exchange-capable peer for sources of file_hash.

        SX2 (OP_REQUESTSOURCES2) when the peer advertises the miso2 bit 10
        or an SX1 nibble > 1; legacy OP_REQUESTSOURCES for SX1 == 1.
        Answers arrive asynchronously — collected into
        ``self.collected_sources`` by the receive loops.
        """
        from amuled_v2.core.peer.codec import (
            build_request_sources2_payload,
            build_request_sources_payload,
            miso1_source_exchange,
            miso2_source_exchange_v2,
        )

        sx1 = miso1_source_exchange(self.peer_tags)
        sx2 = miso2_source_exchange_v2(self.peer_tags)
        if sx2 or sx1 > 1:
            await self._send(
                EMULE_PROTOCOL,
                C2CEMULE.REQUESTSOURCES2,
                build_request_sources2_payload(2, sx_options, file_hash),
            )
            log.info(
                "PEER source exchange requested (SX2): host=%s:%d, hash=%s",
                self.host, self.port, file_hash.hex().upper(),
            )
        elif sx1 == 1:
            await self._send(
                EMULE_PROTOCOL,
                C2CEMULE.REQUESTSOURCES,
                build_request_sources_payload(file_hash),
            )
            log.info(
                "PEER source exchange requested (SX1): host=%s:%d, hash=%s",
                self.host, self.port, file_hash.hex().upper(),
            )
        else:
            log.debug(
                "PEER source exchange skipped (peer lacks SX): host=%s:%d",
                self.host, self.port,
            )

    def _collect_answer_sources(
        self, protocol: int, opcode: int, payload: bytes
    ) -> bool:
        """Collect OP_ANSWERSOURCES(2) if this packet is one; True when
        handled.  Entries land in ``self.collected_sources``."""
        if protocol != EMULE_PROTOCOL:
            return False
        if opcode == C2CEMULE.ANSWERSOURCES2:
            _, file_hash, entries = parse_answer_sources2(payload)
        elif opcode == C2CEMULE.ANSWERSOURCES:
            _, file_hash, entries = parse_answer_sources(payload)
        else:
            return False
        self.collected_sources.extend(entries)
        log.info(
            "PEER source exchange answer: host=%s:%d, hash=%s, "
            "entries=%d (total=%d)",
            self.host, self.port, file_hash.hex().upper(),
            len(entries), len(self.collected_sources),
        )
        return True

    def _capture_file_status(self, protocol: int, opcode: int, payload: bytes) -> bool:
        """Parse OP_FILESTATUS (0x50) and store part-status for ICS.

        Returns True when the packet was a FILESTATUS that got handled.
        chunk_count == 0 signals a complete source (DownloadClient.cpp:694-724):
        the peer has every part — record it in complete_sources and leave
        part_status empty (caller checks complete_sources first).  Any
        parse error is caught and logged at debug; it must never crash
        the receive loop.
        """
        if protocol != EDONKEY or opcode != C2CTCP.FILESTATUS:
            return False
        try:
            status = parse_file_status(payload)
        except PeerCodecError as exc:
            log.debug(
                "PEER FILESTATUS parse error: host=%s:%d, error=%s",
                self.host,
                self.port,
                exc,
            )
            return True
        if status.chunk_count == 0:
            self.complete_sources.add(status.file_hash)
            self.part_status[status.file_hash] = frozenset()
            log.debug(
                "PEER FILESTATUS complete source: host=%s:%d, hash=%s",
                self.host,
                self.port,
                status.file_hash.hex().upper(),
            )
        else:
            self.part_status[status.file_hash] = frozenset(status.present_chunks)
            log.debug(
                "PEER FILESTATUS parts: host=%s:%d, hash=%s, present=%d/%d",
                self.host,
                self.port,
                status.file_hash.hex().upper(),
                len(status.present_chunks),
                status.chunk_count,
            )
        return True

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
            if self._capture_file_status(protocol, opcode, payload):
                continue
            log.debug(
                "PEER ignoring packet while requesting file: opcode=0x%02X",
                opcode,
            )

    async def request_aich(
        self,
        file_hash: bytes,
        part: int,
        known_master: bytes,
        *,
        timeout: float = 10.0,
    ) -> tuple[bytes, int, bytes, bytes]:
        """AICH requester (stage X; SHAHashSet.cpp
        CAICHRecoveryHashSet::RequestAICHRecovery): send OP_AICHREQUEST
        and wait for OP_AICHANSWER.

        Returns (file_hash, part, master, recovery_data).  The known
        master gates the responder (mismatch is silently ignored —
        anti-poison per SHAHashSet.cpp:766-771), so a client without a
        trusted master first learns it from a source that advertises
        AICH and verifies it against the completed download.
        """
        await self._send(
            EMULE_PROTOCOL,
            C2CEMULE.AICHREQUEST,
            build_aich_request_payload(file_hash, part, known_master),
        )
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PeerSessionError("timed out waiting for AICHANSWER")
            packet = await self._receive(timeout=remaining)
            if packet is None:
                raise PeerSessionError("peer request window timed out (AICH)")
            protocol, opcode, payload = packet
            if protocol == EMULE_PROTOCOL and opcode == C2CEMULE.AICHANSWER:
                answer = parse_aich_answer_payload(payload)
                log.info(
                    "PEER AICH answer: hash=%s, part=%d, master=%s, "
                    "recovery=%d",
                    answer[0].hex().upper(),
                    answer[1],
                    answer[2].hex(),
                    len(answer[3]),
                )
                return answer
            log.debug(
                "PEER ignoring packet while awaiting AICHANSWER: "
                "protocol=0x%02X, opcode=0x%02X",
                protocol,
                opcode,
            )

    async def wait_upload_slot(
        self,
        file_hash: bytes,
        *,
        rank_callback: Optional[Callable[[int], None]] = None,
    ) -> None:
        """Wait until the peer grants an upload slot for this file.

        OP_STARTUPLOADREQ is sent ONCE by ``request_file()`` immediately
        before this wait (eMule sends it once and waits; a re-send on
        every response timeout counts as aggressive behaviour - live
        evidence 2026-09-28: eMuleAI logs ``aggressive check counter``
        per request and bans ``[Aggressive behaviour]`` after a handful,
        putting the client into ``None/Banned`` state).  Wait timeouts
        simply keep waiting for the overall deadline; the peer updates
        the queue position with OP_QUEUERANK on its own schedule.
        """
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
                continue
            protocol, opcode, payload = packet
            if protocol != EDONKEY:
                self._collect_answer_sources(protocol, opcode, payload)
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
                    except Exception as exc:
                        # FALLBACK (policy: every swallowed error is logged).
                        log.warning(
                            "PEER rank_callback fallback: callback raised, "
                            "continuing without it: error=%r",
                            exc,
                        )
                continue
            if opcode == C2CTCP.FILEREQANSNOFIL:
                raise PeerSessionError("peer reported the file as unavailable")
            if self._capture_file_status(protocol, opcode, payload):
                continue
            log.debug(
                "PEER ignoring packet while waiting for slot: opcode=0x%02X",
                opcode,
            )

    # -- transfer ------------------------------------------------------------

    def _maybe_credit_downloaded(self, received: int) -> None:
        """Report received bytes to the credit ledger via traffic_sink."""
        sink = self.traffic_sink
        peer = self.peer_info
        if sink is None or peer is None or received <= 0:
            return
        try:
            sink(peer.user_hash, received)
        except Exception as exc:
            log.debug(
                "PEER traffic sink failed: peer=%s, error=%s",
                peer.user_hash,
                exc,
            )

    async def transfer(
        self,
        file_hash: bytes,
        total_size: int,
        *,
        write_block: Callable[[int, bytes], None],
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
        max_blocks: int = 100_000,
        start_offset: int = 0,
        end_offset: Optional[int] = None,
        block_selector: Optional[Callable[[int], list[tuple[int, int]]]] = None,
        release_ranges: Optional[Callable[[list[tuple[int, int]]], None]] = None,
        rank_callback: Optional[Callable[[int], None]] = None,
    ) -> DownloadOutcome:
        """Run the request-parts / sending-part loop until completion.

        ``write_block(start, data)`` receives every verified block (already
        decompressed).  ``progress_callback(received_bytes, total_size,
        blocks)`` fires after each block.  ``start_offset``/``end_offset``
        bound the region this session downloads (stripe scheduling); write
        offsets remain absolute.

        ICS: when ``block_selector`` is supplied it is called with the current
        outstanding request count and returns up to 3 *inclusive* ``(start,
        end)`` ranges chosen by the Intelligent Chunk Selector.  The selector
        output is normalised to the wire convention used by
        ``build_request_parts_payload`` — *exclusive* end (``end + 1``) —
        per DownloadClient.cpp:1241 (``aOffs[3..5] = EndOffset + 1``).  When
        ``block_selector`` is ``None`` the original linear
        ``EMBLOCK_SIZE``-stepped scheduling is used unchanged.  Every range
        actually issued on the wire is accumulated in ``issued_ranges`` and
        released via ``release_ranges`` exactly once on any exit path.
        """
        started = time.monotonic()
        # ВАЖНО (на это уже нарывались): OP_ACCEPTUPLOADREQ — серверный
        # опкод (сервер → клиент при выдаче слота). Клиент в transfer() его
        # НЕ шлёт: слот уже выдан, wait_upload_slot съел ACCEPTUPLOADREQ,
        # и движок отдачи (UploadSession) приёме ACCEPTUPLOADREQ от клиента
        # завершает сессию — живой приём обрывается после первого батча
        # блоков (WinError 10053 / "peer closed connection").
        received = 0
        blocks = 0
        compressed = self.peer_info.compression if self.peer_info else False
        # Stripe scheduling (stage X): the runner hands each racing peer a
        # disjoint region [start_offset, end_offset); ranges are requested
        # inside it and write_block receives ABSOLUTE file offsets, so the
        # queue's gap list stays the source of truth for completion.
        base_offset = start_offset
        bound = total_size if end_offset is None else end_offset

        def _remaining_sink() -> list[tuple[int, int]]:
            try:
                remaining = bound - (base_offset + received)
            except Exception:
                return []
            return (
                [(base_offset + received, base_offset + received + remaining)]
                if remaining > 0
                else []
            )

        # ICS: every range actually sent on the wire this call, for the
        # runner's block_selector bookkeeping.  Released once on exit.
        issued_ranges: list[tuple[int, int]] = []

        # COMPRESSEDPART reassembly buffer: eMule splits a compressed block
        # into sub-packets where every sub-packet repeats the BLOCK start and
        # the TOTAL compressed size (UploadDiskIOThread CreatePackedPackets).
        # Chunks are concatenated until the declared total is reached and
        # only then decompressed.
        pending_compressed: dict[tuple[int, int], dict[str, Any]] = {}
        outofpart_retries = 0

        try:
            while blocks < max_blocks:
                if base_offset + received >= bound:
                    break
                # -- range selection (ICS / linear fallback) -------------------
                # build_request_parts_payload expects EXCLUSIVE ends (the
                # encoder writes start then end-offset, eMule decodes as
                # EndOffset+1 per DownloadClient.cpp:1241).  The linear
                # fallback computes end = min(offset + EMBLOCK_SIZE, bound)
                # directly as an exclusive end.  A block_selector returns
                # INCLUSIVE (start, end) ranges, so we add +1 to each end.
                if block_selector is not None:
                    raw_ranges = block_selector(3)
                    if not raw_ranges:
                        break  # peer/source has nothing we need
                    # Clip to [base_offset, bound) and normalise to 3 slots.
                    clipped: list[tuple[int, int]] = []
                    for rstart, rend in raw_ranges[:3]:
                        rstart = max(rstart, base_offset)
                        rend = min(rend, bound - 1)
                        if rstart <= rend:
                            clipped.append((rstart, rend + 1))  # incl -> excl
                    while len(clipped) < 3:
                        clipped.append((0, 0))
                    starts = [c[0] for c in clipped]
                    ends = [c[1] for c in clipped]
                    round_ranges = [
                        (rstart, rend) for rstart, rend in raw_ranges[:3]
                    ]
                    issued_ranges.extend(round_ranges)
                else:
                    starts, ends = [], []
                    for offset in (
                        base_offset + received,
                        base_offset + received + EMBLOCK_SIZE,
                        base_offset + received + 2 * EMBLOCK_SIZE,
                    ):
                        if offset >= bound:
                            break
                        end = min(offset + EMBLOCK_SIZE, bound)
                        starts.append(offset)
                        ends.append(end)
                    if not starts:
                        break
                    while len(starts) < 3:
                        starts.append(0)
                        ends.append(0)
                    issued_ranges.extend(
                        (s, e - 1) for s, e in zip(starts, ends) if s < e
                    )
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

                # Byte-based round accounting: the server splits each requested
                # range into an arbitrary number of sub-packets (13000/10240,
                # CreateStandardPackets/CreatePackedPackets), so counting PACKETS
                # deadlocks the round.  Count PAYLOAD bytes instead: the round
                # is complete once every requested byte has arrived.
                expected_bytes = sum(
                    e - s for s, e in zip(starts, ends) if s < e
                )
                while expected_bytes > 0:
                    # Data rounds get a wider per-packet idle window than the
                    # control phase: a throttled uploader can take >20 s to
                    # push the first SENDINGPART after the slot grant (live
                    # evidence 2026-09-28: eMuleAI 1.6.0 sent 398 KB over
                    # 20 s while a 20 s idle timeout cut the session at
                    # received=0 — the kill raced the first data frame).
                    packet = await self._receive(
                        timeout=self.response_timeout * 3,
                        close_on_timeout=False,
                    )
                    if packet is None:
                        self._maybe_credit_downloaded(received)
                        outcome = DownloadOutcome(
                            file_hash=file_hash.hex().upper(),
                            bytes_received=received,
                            blocks_received=blocks,
                            complete=base_offset + received >= bound,
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
                    # TEMP DIAGNOSTIC (framing desync hunt 2026-09-28):
                    # every frame in the transfer loop is traced so a
                    # mid-stream desync (silent `protocol != EDONKEY`
                    # skips) becomes visible.
                    log.debug(
                        "PEER frame: host=%s:%d, proto=0x%02X, "
                        "opcode=0x%02X, size=%d, received=%d",
                        self.host,
                        self.port,
                        protocol,
                        opcode,
                        len(payload),
                        received,
                    )
                    if protocol not in (EDONKEY, EMULE_PROTOCOL):
                        # Unknown transport protocol byte: not data.  NOTE:
                        # data packets (SENDINGPART/COMPRESSEDPART[_I64])
                        # arrive on BOTH protocols - live evidence
                        # 2026-09-28: eMuleAI 1.6.0 pushes COMPRESSEDPART
                        # (0x40) on EMULE (0xC5); the old EDONKEY-only
                        # check silently dropped every data frame.
                        log.debug(
                            "PEER frame skipped: unknown protocol 0x%02X",
                            protocol,
                        )
                        continue
                    part: Optional[SendingPart] = None
                    if opcode == C2CTCP.SENDINGPART:
                        part = parse_sending_part(payload)
                    elif opcode == C2CTCP.SENDINGPART_I64:
                        part = parse_sending_part_i64(payload)
                    elif opcode == C2CTCP.COMPRESSEDPART:
                        h, s, total, chunk = parse_compressed_part_chunk(payload)
                        key = (s, total)
                        slot = pending_compressed.setdefault(
                            key, {"hash": h, "buf": bytearray(), "i64": False}
                        )
                        slot["buf"] += chunk
                        if len(slot["buf"]) < total:
                            continue  # more sub-packets pending
                        del pending_compressed[key]
                        try:
                            data = zlib.decompress(bytes(slot["buf"]))
                        except zlib.error as exc:
                            raise PeerSessionError(
                                f"compressed part reassembly failed: {exc}"
                            ) from exc
                        part = SendingPart(
                            file_hash=slot["hash"], start=s, end=s + len(data), data=data
                        )
                    elif opcode == C2CTCP.COMPRESSEDPART_I64:
                        h, s, total, chunk = parse_compressed_part_chunk_i64(payload)
                        key = (s, total)
                        slot = pending_compressed.setdefault(
                            key, {"hash": h, "buf": bytearray(), "i64": True}
                        )
                        slot["buf"] += chunk
                        if len(slot["buf"]) < total:
                            continue  # more sub-packets pending
                        del pending_compressed[key]
                        try:
                            data = zlib.decompress(bytes(slot["buf"]))
                        except zlib.error as exc:
                            raise PeerSessionError(
                                f"compressed part reassembly failed: {exc}"
                            ) from exc
                        part = SendingPart(
                            file_hash=slot["hash"], start=s, end=s + len(data), data=data
                        )
                    elif opcode == C2CTCP.END_OF_DOWNLOAD:
                        log.info(
                            "PEER end of download: host=%s:%d, received=%d/%d",
                            self.host,
                            self.port,
                            received,
                            total_size,
                        )
                        expected_bytes = 0
                        break
                    elif opcode == C2CTCP.OUTOFPARTREQS:
                        # The source accepted us but has no upload blocks
                        # prepared yet (it reads the file lazily after the
                        # slot grant).  Real clients re-request after a short
                        # pause instead of dropping the slot.
                        outofpart_retries += 1
                        if outofpart_retries > _OUTOFPART_MAX_RETRIES:
                            self._maybe_credit_downloaded(received)
                            outcome = DownloadOutcome(
                                file_hash=file_hash.hex().upper(),
                                bytes_received=received,
                                blocks_received=blocks,
                                complete=base_offset + received >= bound,
                                elapsed=time.monotonic() - started,
                                detail="peer has no more parts",
                            )
                            return outcome
                        log.info(
                            "PEER out of parts (retry %d/%d): host=%s:%d",
                            outofpart_retries,
                            _OUTOFPART_MAX_RETRIES,
                            self.host,
                            self.port,
                        )
                        await asyncio.sleep(_OUTOFPART_RETRY_DELAY)
                        # Escape the receive loop: the outer while re-issues
                        # REQUESTPARTS.  With an ICS selector, the re-issue
                        # path falls through to block_selector(3) again (the
                        # selector decides fresh ranges); the linear path reuses
                        # the existing base_offset + received arithmetic.
                        if block_selector is not None:
                            round_ranges = []
                        expected_bytes = 0
                        break
                    elif opcode == C2CTCP.QUEUERANK:
                        rank = parse_queue_rank(payload)
                        log.info(
                            "PEER requeued during transfer: rank=%d", rank
                        )
                        if rank_callback is not None:
                            try:
                                rank_callback(rank)
                            except Exception as exc:
                                log.warning(
                                    "PEER transfer rank_callback fallback: "
                                    "error=%r",
                                    exc,
                                )
                        self._maybe_credit_downloaded(received)
                        outcome = DownloadOutcome(
                            file_hash=file_hash.hex().upper(),
                            bytes_received=received,
                            blocks_received=blocks,
                            complete=base_offset + received >= bound,
                            elapsed=time.monotonic() - started,
                            detail="moved back to queue",
                        )
                        return outcome
                    else:
                        if self._capture_file_status(protocol, opcode, payload):
                            continue
                        if self._collect_answer_sources(protocol, opcode, payload):
                            continue
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
                        except Exception as exc:
                            # FALLBACK (policy: every swallowed error is
                            # logged).
                            log.warning(
                                "PEER progress_callback fallback: callback "
                                "raised, transfer continues: error=%r",
                                exc,
                            )
                    expected_bytes -= len(part.data)
                if base_offset + received >= bound:
                    break

            complete = base_offset + received >= bound
            self._maybe_credit_downloaded(received)
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
        finally:
            if release_ranges is not None and issued_ranges:
                try:
                    release_ranges(issued_ranges)
                except Exception as exc:
                    log.debug(
                        "PEER release_ranges failed: host=%s:%d, error=%s",
                        self.host,
                        self.port,
                        exc,
                    )
        self._maybe_credit_downloaded(received)
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
