"""Incoming peer listener for the eD2K client-to-client TCP protocol.

Accepts TCP connections from remote eD2K clients, performs the server-side
HELLO/HELLOANSWER handshake, optionally answers OP_EMULEINFO, resolves the
requested shared file against DuckDB state, enqueues the peer on the upload
queue, and hands the established session to the upload engine for block
transfer.

Protocol flow (see ``_expect_first_packet``):

    0. First wire byte selects the transport mode (EncryptedStreamSocket.cpp
       Receive ECS_UNKNOWN): 0xE3/0xC5/0xD4 -> plain framing; anything else
       -> obfuscated accept (BASIC with our userhash, DH fallback — stage X,
       ``accept_obfuscated_client``).  The first DECRYPTED packet must be
       OP_HELLO (ListenSocket.cpp:4692 ERR_NOHELLO).
    1. Client connects, first packet must be OP_HELLO (0x01, protocol 0xE3).
    2. Server parses HELLO and replies with OP_HELLOANSWER (0x4C) using
       ``build_hello_answer_payload`` from codec.py.
    3. Optional EMULEINFO (0xC5/0x01) — server replies with EMULEINFOANSWER
       (0x02) reusing ``build_emuleinfo_payload`` from client.py.
    4. OP_STARTUPLOADREQ (0x54) on protocol 0xE3 with a 16-byte file hash.
       Unknown hash → server sends OP_END_OF_DOWNLOAD (0x49) and closes
       (matching eMuleAI UploadClient.cpp behavior at ListenSocket.cpp:1069).
       Known hash → enqueue on UploadQueue; if a slot is free and the client
       is at the head, grant_slot and send OP_ACCEPTUPLOADREQ (0x55); otherwise
       send OP_QUEUERANK (0x5C).
    5. Hand off to UploadSession (engine.py) which drives REQUESTFILENAME,
       HASHSETREQUEST, REQUESTPARTS/REQUESTPARTS_I64, and END_OF_DOWNLOAD.

src/amuled_v2/core/peer/listener.py
Version:     0.3.1
Author:      Soror L.'.L.'.
Updated:     2026-09-27

Patch Notes v0.3.1 (Soror L'.L'.):
  [+] Direct-callback waiters are a FIFO queue per IP (fixes two racing
      peers sharing one reader — "readexactly() called while another
      coroutine is already waiting"); expect_connection_from must be
      started before the callback request is sent.
  [+] Serving-buddy registration: HELLO with CT_EMULE_SERVINGBUDDYID
      (0xBF) registers the client in the KAD buddy registry and holds
      the TCP channel open (_hold_buddy_session) for OP_CALLBACK relays;
      the upload engine is not started for such sessions.

Patch Notes v0.3.0 (Soror L'.L'.):
  [+] Post-transfer drain: the session keeps serving AICH requests after
      the upload completes (eMule parity — the DOWNLOADER owns the
      connection lifetime); AICH handler extracted to
      _handle_aich_request, reused by _drain_post_transfer.

Patch Notes v0.2.0 (Soror L'.L'.):
  [+] Incoming obfuscation accept (stage X): non-protocol first byte now
      starts the BASIC obfuscation accept from our own userhash with a
      server-role DH fallback (accept_obfuscated_client); StreamTransport
      decrypts at the point of consumption and honors decrypted leftovers.
      The plain 0xE3/0xC5/0xD4 path is unchanged.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added ListenerError for listener-level failures.
  [+] Added LocalIdentity dataclass for the local client's handshake identity.
  [+] Added StreamTransport implementing the UploadTransport protocol over
      asyncio streams, supporting both 0xE3 (EDONKEY) and 0xC5 (EMULE) protocol
      bytes.
  [+] Added StateSharedFileResolver that lazily opens/closes DuckDB connections.
  [+] Added IncomingPeerSession implementing the full server-side HELLO handshake,
      EMULEINFO exchange, STARTUPLOADREQ queue/accept decision, and handoff to
      UploadSession.
  [+] Added IncomingPeerServer wrapping asyncio.start_server.
"""

from __future__ import annotations

import asyncio
import os
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from amuled_v2.core.codec.constants import EDONKEY, EMULE
from amuled_v2.core.peer.codec import (
    C2CTCP,
    SXSource,
    build_answer_sources,
    build_answer_sources2,
    build_aich_answer_payload,
    parse_aich_request_payload,
    build_end_of_download_payload,
    build_hello_answer_payload,
    parse_hello,
    parse_file_hash_payload,
    parse_publickey_payload,
    parse_request_sources,
    parse_request_sources2,
    parse_secident_state_payload,
    parse_signature_payload,
    build_publickey_payload,
    build_secident_state_payload,
    build_signature_payload,
    miso1_secident_support,
    miso1_source_exchange,
)
from amuled_v2.core.peer.client import (
    C2CEMULE,
    build_emuleinfo_payload,
)
from amuled_v2.core.sharing.shared_files import SharedFile
from amuled_v2.core.upload.engine import (
    BlockSource,
    UploadEngineError,
    UploadSession,
    UploadSessionStats,
    UploadThrottle,
)
from amuled_v2.core.upload.queue import UploadQueue
from amuled_v2.logging_setup import LogTags, get_tagged_logger
from amuled_v2.state import StateBackend

log = get_tagged_logger(LogTags.PEER, "core.peer.listener")

__all__ = [
    "ListenerError",
    "LocalIdentity",
    "StreamTransport",
    "StateSharedFileResolver",
    "IncomingPeerSession",
    "IncomingPeerServer",
    "MAX_PACKET_SIZE",
]

MAX_PACKET_SIZE = 16 * 1024 * 1024
_DEFAULT_ED2K_VERSION = 0x3C


class ListenerError(RuntimeError):
    """Raised on unrecoverable listener-level protocol or transport failures."""


@dataclass(frozen=True)
class LocalIdentity:
    """Server side identity sent in OP_HELLOANSWER."""

    user_hash: bytes
    client_id: int
    tcp_port: int
    nickname: str

    def __post_init__(self) -> None:
        if len(self.user_hash) != 16:
            raise ListenerError(
                f"user_hash must be exactly 16 bytes, got {len(self.user_hash)}"
            )
        if not 0 <= self.client_id <= 0xFFFFFFFF:
            raise ListenerError(
                f"client_id out of UInt32 range: {self.client_id}"
            )
        if not 0 <= self.tcp_port <= 0xFFFF:
            raise ListenerError(
                f"tcp_port out of UInt16 range: {self.tcp_port}"
            )
        if not isinstance(self.nickname, str) or not self.nickname:
            raise ListenerError("nickname must be a non-empty string")

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_hash": self.user_hash.hex().upper(),
            "client_id": self.client_id,
            "tcp_port": self.tcp_port,
            "nickname": self.nickname,
        }


class StreamTransport:
    """asyncio-streams implementation of the UploadTransport protocol.

    Supports an optional established obfuscation session (BASIC / DH
    acceptor output, stage X): ``crypt`` provides ``encrypt()/decrypt()``
    and ``rx_plain`` carries already-decrypted handshake leftovers that
    must be consumed exactly once before touching the raw stream.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        protocol: int = EDONKEY,
        allow_emule_protocol: bool = False,
        idle_timeout: float | None = 300.0,
        crypt: Any | None = None,
        rx_plain: bytes = b"",
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._protocol = protocol
        self._allow_emule_protocol = allow_emule_protocol
        self._idle_timeout = idle_timeout
        self._crypt = crypt
        self._rx_plain = bytearray(rx_plain)
        self.last_protocol_byte: int = protocol

    async def _read_wire(self, n: int) -> bytes:
        """Read n WIRE bytes, decrypting at the point of consumption."""
        take = min(n, len(self._rx_plain))
        raw = b""
        if n > take:
            raw = await self._reader.readexactly(n - take)
        head = bytes(self._rx_plain[:take])
        del self._rx_plain[:take]
        if self._crypt is not None:
            return head + self._crypt.decrypt(raw)
        return head + raw

    async def recv(self) -> tuple[int, bytes] | None:
        """Receive one framed packet.

        Header layout (same as client._receive):
            [protocol u8][length u32 LE (payload+1)][opcode u8][payload]

        Returns ``(opcode, payload)``.  Returns ``None`` on a clean EOF.
        Stores the last protocol byte on ``self.last_protocol_byte``.
        """
        try:
            if self._idle_timeout is not None:
                header = await asyncio.wait_for(
                    self._read_wire(6), self._idle_timeout
                )
            else:
                header = await self._read_wire(6)
        except asyncio.TimeoutError as exc:
            raise ListenerError(
                f"idle timeout waiting for packet header: {self._idle_timeout}s"
            ) from exc
        except asyncio.IncompleteReadError:
            return None

        protocol_byte = header[0]
        self.last_protocol_byte = protocol_byte
        if protocol_byte != self._protocol:
            if (
                self._allow_emule_protocol
                and protocol_byte == EMULE
            ):
                pass
            else:
                raise ListenerError(
                    f"protocol byte mismatch: expected 0x{self._protocol:02X}, "
                    f"got 0x{protocol_byte:02X}"
                )

        packet_length = struct.unpack("<I", header[1:5])[0]
        if packet_length < 1:
            raise ListenerError(
                f"packet length below one: {packet_length}"
            )
        payload_size = packet_length - 1
        if payload_size > MAX_PACKET_SIZE:
            raise ListenerError(
                f"packet exceeds {MAX_PACKET_SIZE} bytes: payload_size={payload_size}"
            )

        if payload_size == 0:
            payload = b""
        else:
            try:
                if self._idle_timeout is not None:
                    payload = await asyncio.wait_for(
                        self._read_wire(payload_size),
                        self._idle_timeout,
                    )
                else:
                    payload = await self._read_wire(payload_size)
            except asyncio.TimeoutError as exc:
                raise ListenerError(
                    f"idle timeout waiting for payload: size={payload_size}"
                ) from exc
            except asyncio.IncompleteReadError as exc:
                raise ListenerError(
                    f"short read: expected {payload_size} payload bytes, "
                    f"got {len(exc.partial)}"
                ) from exc

        opcode = header[5]
        return opcode, payload

    async def send(
        self, opcode: int, payload: bytes, *, protocol: int | None = None
    ) -> None:
        """Frame and write one packet, then drain.

        ``protocol`` overrides the wire protocol byte (e.g. EMULE 0xC5 for
        OP_EMULEINFOANSWER); defaults to this transport's protocol.
        """
        if len(payload) > MAX_PACKET_SIZE - 1:
            raise ListenerError(
                f"payload exceeds max packet size: {len(payload)}"
            )
        wire = (
            bytes([self._protocol if protocol is None else protocol])
            + struct.pack("<I", len(payload) + 1)
            + bytes([opcode])
            + payload
        )
        if self._crypt is not None:
            wire = self._crypt.encrypt(wire)
        self._writer.write(wire)
        await self._writer.drain()

    def close(self) -> None:
        if self._writer is not None:
            self._writer.close()


class StateSharedFileResolver:
    """Resolves a file hash to a :class:`SharedFile` via DuckDB state.

    Opens and closes a DuckDB connection per lookup (DuckDB is single-writer,
    and incoming lookups are infrequent relative to file serving).
    """

    def __init__(
        self,
        state_factory: Callable[[], StateBackend],
    ) -> None:
        self._state_factory = state_factory

    def resolve(self, file_hash: bytes) -> SharedFile | None:
        if len(file_hash) != 16:
            return None
        try:
            state = self._state_factory()
        except Exception as exc:
            raise ListenerError(
                f"state backend creation failed: {exc}"
            ) from exc
        try:
            row = state.get_shared_file(file_hash.hex())
        except Exception as exc:
            raise ListenerError(
                f"get_shared_file failed: {exc}"
            ) from exc
        finally:
            close = getattr(state, "close", None)
            if close is not None:
                try:
                    close()
                except Exception:
                    pass

        if row is None:
            return None
        if row.get("path") is None:
            return None
        try:
            return SharedFile(
                file_hash=bytes.fromhex(row["hash"]),
                name=row["name"],
                size=row["size"],
                path=row["path"],
                priority=row["priority"],
                imported=row["imported"],
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise ListenerError(
                f"malformed shared-file row: {exc}"
            ) from exc


class _PreambleTransport:
    """Transport wrapper that replays pre-received packets before delegating.

    ``recv`` first yields every packet in ``first_packets`` (file requests
    that arrived before STARTUPLOADREQ plus the STARTUPLOADREQ itself), then
    delegates to the underlying :class:`StreamTransport` so the engine loop
    sees the full packet sequence.
    """

    def __init__(
        self,
        first_packets: list[tuple[int, bytes]],
        delegate: StreamTransport,
    ) -> None:
        self._pending = list(first_packets)
        self._delegate = delegate

    async def recv(self) -> tuple[int, bytes] | None:
        if self._pending:
            return self._pending.pop(0)
        return await self._delegate.recv()

    async def send(self, opcode: int, payload: bytes) -> None:
        await self._delegate.send(opcode, payload)

    def close(self) -> None:
        self._delegate.close()


class IncomingPeerSession:
    """Handles one incoming peer connection end-to-end.

    Steps:
      a. _expect_first_packet — plain 0xE3/0xC5/0xD4 framing or the
         obfuscation accept (BASIC/DH, stage X).
      b. Receive OP_HELLO (0x01), parse, reply with OP_HELLOANSWER (0x4C).
      c. Pre-engine loop handling OP_EMULEINFO (answer EMULEINFOANSWER) and
         OP_STARTUPLOADREQ (queue/resolve/accept decision).
      d. Hand off to UploadSession for the block transfer loop.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        identity: LocalIdentity,
        resolver: StateSharedFileResolver,
        upload_queue: UploadQueue,
        throttle: UploadThrottle | None = None,
        allow_compression: bool = True,
        idle_timeout: float | None = 300.0,
        traffic_recorder: Callable[[str, int], None] | None = None,
        queue_rank_period: float = 60.0,
        secure_ident: Any | None = None,
        source_provider: Callable[[bytes], list[SXSource]] | None = None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._identity = identity
        self._resolver = resolver
        self._upload_queue = upload_queue
        self._throttle = throttle
        self._allow_compression = allow_compression
        self._idle_timeout = idle_timeout
        # Stage C credit accounting: called after a served transfer with
        # (peer_user_hash_hex, uploaded_bytes); failures are swallowed by
        # the caller-supplied recorder, never by the session.
        self._traffic_recorder = traffic_recorder
        self._queue_rank_period = queue_rank_period
        # Stage X SecureIdent: shared RSA provider (SecureIdentProvider).
        self._secure_ident = secure_ident
        self._sui = {"challenge_in": None, "peer_blob": b""}
        # Stage X source exchange: answers OP_REQUESTSOURCES(2) from these
        # rows (None = feature disabled, requests are ignored).
        self._source_provider = source_provider
        self._peer_name = _format_peer(writer)
        self._transport: StreamTransport | None = None

    def _credit_uploaded(self, hello: Any, stats: UploadSessionStats | None) -> None:
        recorder = self._traffic_recorder
        if recorder is None or stats is None or stats.bytes_sent <= 0:
            return
        try:
            recorder(hello.user_hash.hex().lower(), stats.bytes_sent)
        except Exception as exc:
            log.debug(
                "credit accounting skipped: peer=%s, error=%s",
                self._peer_name,
                exc,
            )

    async def _expect_first_packet(self) -> tuple[StreamTransport, int, bytes]:
        """Consume the first wire byte and establish the transport mode.

        Per EncryptedStreamSocket.cpp Receive (lines 287-324): the
        acceptor inspects byte 0.  0xE3/0xC5/0xD4 mean plain eDonkey
        framing; ANY other byte starts the obfuscation accept
        (BASIC with our own userhash, falling back to server-role DH) —
        stage X, EncryptedStreamSocket.cpp ONS_BASIC_CLIENTA_*.

        Returns ``(transport, opcode, payload)`` of the first DECRYPTED
        packet for the caller to dispatch (must be OP_HELLO per
        ListenSocket.cpp:4692 ERR_NOHELLO).
        """
        reader = self._reader
        assert reader is not None
        try:
            first = await asyncio.wait_for(reader.readexactly(1), self._idle_timeout)
        except asyncio.TimeoutError as exc:
            raise ListenerError(
                f"idle timeout waiting for first byte: {self._idle_timeout}s"
            ) from exc
        except asyncio.IncompleteReadError as exc:
            raise ListenerError("peer closed before sending first byte") from exc
        first_byte = first[0]

        writer = self._writer
        if first_byte in (EDONKEY, EMULE, 0xD4):
            transport = StreamTransport(
                reader,
                writer,
                protocol=EDONKEY,
                allow_emule_protocol=True,
                idle_timeout=self._idle_timeout,
                rx_plain=first,
            )
            self._transport = transport
            log.debug("Plain protocol first byte: peer=%s, byte=0x%02X",
                      self._peer_name, first_byte)
        else:
            from amuled_v2.core.peer.obfuscation import accept_obfuscated_client

            try:
                crypt_session, leftover = await asyncio.wait_for(
                    accept_obfuscated_client(
                        reader,
                        writer,
                        self._identity.user_hash,
                        first_byte,
                        timeout=15.0,
                    ),
                    timeout=20.0,
                )
            except Exception as exc:
                raise ListenerError(
                    f"obfuscation accept failed: {exc}"
                ) from exc
            transport = StreamTransport(
                reader,
                writer,
                protocol=EDONKEY,
                allow_emule_protocol=True,
                idle_timeout=self._idle_timeout,
                crypt=crypt_session,
                rx_plain=leftover,
            )
            self._transport = transport
            log.info(
                "Obfuscated incoming connection accepted: peer=%s, mode=%s",
                self._peer_name,
                crypt_session.state,
            )

        packet = await transport.recv()
        if packet is None:
            raise ListenerError("peer closed before sending first packet")
        opcode, payload = packet
        proto = transport.last_protocol_byte
        if proto != EDONKEY:
            if proto == EMULE and transport._allow_emule_protocol:
                pass
            else:
                raise ListenerError(
                    f"unsupported protocol byte after accept: 0x{proto:02X}"
                )
        return transport, opcode, payload

    async def run(self) -> dict[str, Any]:
        started_at = time.monotonic()
        transport, opcode, payload = await self._expect_first_packet()
        if opcode != C2CTCP.HELLO:
            raise ListenerError(
                f"expected OP_HELLO (0x01) as first packet, got opcode=0x{opcode:02X}"
            )

        try:
            hello = parse_hello(payload)
        except Exception as exc:
            raise ListenerError(f"malformed OP_HELLO: {exc}") from exc

        log.info(
            "Incoming HELLO: peer=%s, user_hash=%s, client_id=%d, port=%d, name=%r",
            self._peer_name,
            hello.user_hash.hex().upper(),
            hello.client_id,
            hello.client_port,
            hello.nickname,
        )

        answer = build_hello_answer_payload(
            user_hash=self._identity.user_hash,
            client_id=self._identity.client_id,
            client_port=self._identity.tcp_port,
            nickname=self._identity.nickname,
            server_ip=0,
            server_port=0,
        )
        await transport.send(C2CTCP.HELLOANSWER, answer)
        log.info(
            "HELLOANSWER sent: peer=%s, to_user_hash=%s",
            self._peer_name,
            self._identity.user_hash.hex().upper(),
        )

        # Stage X SecureIdent: after the info packets we challenge the peer
        # (BaseClient.cpp SendSecIdentStatePacket via InfoPacketsReceived).
        if self._secure_ident is not None and self._secure_ident.has_keys:
            peer_sui = miso1_secident_support(hello.tags)
            if peer_sui:
                challenge = int.from_bytes(os.urandom(4), "little") or 1
                self._sui["challenge_out"] = challenge
                await transport.send(
                    C2CEMULE.SECIDENTSTATE,
                    build_secident_state_payload(2, challenge),
                    protocol=EMULE,
                )
                log.debug(
                    "SECIDENTSTATE sent: peer=%s, challenge=%d",
                    self._peer_name, challenge,
                )

        started_upload = False
        last_hash_hex: str | None = None
        session: UploadSession | None = None
        granted_key: tuple[str, str] | None = None

        # Stage X serving-buddy registration: a firewalled client's HELLO
        # carries CT_EMULE_SERVINGBUDDYID (0xBF) with its raw KadID
        # (BaseClient.cpp:2005-2013 — "so the buddy can store it and match
        # future OP_REASKCALLBACKUDP requests").  Such sessions do NOT run
        # the upload engine: they are held open and the KAD spider relays
        # OP_CALLBACK (0x99) packets to them via the registry.
        buddy_tag = next(
            (t for t in hello.tags if t.name_id == 0xBF), None
        )
        if buddy_tag is not None and isinstance(buddy_tag.value, (bytes, bytearray)):
            from amuled_v2.core.kad.buddy import buddy_registry

            peer_ip = self._peer_name.rsplit(":", 1)[0].strip()
            buddy_registry.register(
                bytes(buddy_tag.value), peer_ip, hello.client_port,
                transport._writer,
            )
            try:
                await self._hold_buddy_session(transport)
            finally:
                buddy_registry.unregister_transport(transport._writer)
            return self._build_report(
                hello, None, started_at, accepted=True,
                detail="buddy_session_closed",
            )

        while not started_upload:
            packet = await transport.recv()
            if packet is None:
                raise ListenerError(
                    "peer closed connection before STARTUPLOADREQ"
                )
            opcode, payload = packet

            if opcode == C2CEMULE.SECIDENTSTATE:
                state, challenge = parse_secident_state_payload(payload)
                self._sui["challenge_in"] = challenge
                log.debug(
                    "SECIDENTSTATE received: peer=%s, state=%d, challenge=%d",
                    self._peer_name, state, challenge,
                )
                # Answer with PUBLICKEY + SIGNATURE over [our blob][their
                # challenge] (BaseClient.cpp SendPublicKeyPacket /
                # SendSignaturePacket).
                await transport.send(
                    C2CEMULE.PUBLICKEY,
                    build_publickey_payload(self._secure_ident.public_blob),
                    protocol=EMULE,
                )
                signature = self._secure_ident.create_signature(challenge)
                await transport.send(
                    C2CEMULE.SIGNATURE,
                    build_signature_payload(signature),
                    protocol=EMULE,
                )
                continue

            if opcode == C2CEMULE.PUBLICKEY:
                self._sui["peer_blob"] = parse_publickey_payload(payload)
                log.debug(
                    "PUBLICKEY received: peer=%s, len=%d",
                    self._peer_name, len(self._sui["peer_blob"]),
                )
                continue

            if opcode == C2CEMULE.SIGNATURE:
                signature, _ip_kind = parse_signature_payload(payload)
                challenge_in = self._sui.get("challenge_out")
                peer_blob = self._sui.get("peer_blob", b"")
                if challenge_in is None or not peer_blob:
                    log.debug(
                        "SIGNATURE ignored (no challenge/key yet): peer=%s",
                        self._peer_name,
                    )
                    continue
                from amuled_v2.core.security.secure_ident import SecureIdentProvider

                verified = SecureIdentProvider.verify_signature(
                    peer_blob, signature, challenge_in
                )
                if verified:
                    self._secure_ident.mark_verified(hello.user_hash.hex().lower())
                log.info(
                    "SecureIdent %s: peer=%s, user_hash=%s",
                    "VERIFIED" if verified else "FAILED",
                    self._peer_name,
                    hello.user_hash.hex().upper(),
                )
                continue

            if opcode == C2CEMULE.REQUESTSOURCES2:
                # Source exchange responder (stage X; gate per
                # ListenSocket.cpp:2289 — SX2 request OR SX1 version > 1).
                if self._source_provider is None:
                    continue
                try:
                    req_version, _options, req_hash = parse_request_sources2(payload)
                except Exception as exc:
                    log.debug(
                        "REQUESTSOURCES2 ignored (malformed): peer=%s, error=%s",
                        self._peer_name, exc,
                    )
                    continue
                peer_sx1 = miso1_source_exchange(hello.tags)
                if not (req_version > 0 or peer_sx1 > 1):
                    continue
                try:
                    sources = self._source_provider(req_hash) or []
                except Exception as exc:
                    log.debug(
                        "source provider failed: peer=%s, error=%s",
                        self._peer_name, exc,
                    )
                    continue
                if not sources:
                    continue
                answer_version = max(1, min(4, req_version))
                await transport.send(
                    C2CEMULE.ANSWERSOURCES2,
                    build_answer_sources2(answer_version, req_hash, sources),
                    protocol=EMULE,
                )
                log.debug(
                    "ANSWERSOURCES2 sent: peer=%s, hash=%s, version=%d, count=%d",
                    self._peer_name, req_hash.hex().upper(),
                    answer_version, len(sources),
                )
                continue

            if opcode == C2CEMULE.REQUESTSOURCES:
                # Legacy SX1: answered only when the peer advertises an SX1
                # version above 1 (ListenSocket.cpp:2289).
                if self._source_provider is None:
                    continue
                try:
                    req_hash = parse_request_sources(payload)
                except Exception as exc:
                    log.debug(
                        "REQUESTSOURCES ignored (malformed): peer=%s, error=%s",
                        self._peer_name, exc,
                    )
                    continue
                if miso1_source_exchange(hello.tags) <= 1:
                    continue
                try:
                    sources = self._source_provider(req_hash) or []
                except Exception as exc:
                    log.debug(
                        "source provider failed: peer=%s, error=%s",
                        self._peer_name, exc,
                    )
                    continue
                if not sources:
                    continue
                await transport.send(
                    C2CEMULE.ANSWERSOURCES,
                    build_answer_sources(req_hash, sources, entry_version=peer_sx1),
                    protocol=EMULE,
                )
                log.debug(
                    "ANSWERSOURCES sent: peer=%s, hash=%s, count=%d",
                    self._peer_name, req_hash.hex().upper(), len(sources),
                )
                continue

            if opcode == C2CEMULE.AICHREQUEST:
                await self._handle_aich_request(payload, transport)
                continue

            if opcode == C2CTCP.REQUESTFILENAME:
                # eMule answers file-name requests immediately, regardless
                # of upload-queue state (UploadClient.cpp ProcessFileRequest).
                try:
                    req_hash = parse_file_hash_payload(payload)
                except Exception as exc:
                    log.debug("Ignoring malformed REQUESTFILENAME: %s", exc)
                    continue
                shared = self._resolver.resolve(req_hash)
                if shared is None:
                    log.debug(
                        "REQUESTFILENAME for unknown hash ignored: peer=%s",
                        self._peer_name,
                    )
                    continue
                from amuled_v2.core.peer.codec import (
                    build_file_name_answer_payload,
                )

                await transport.send(
                    C2CTCP.REQFILENAMEANSWER,
                    build_file_name_answer_payload(req_hash, shared.name),
                )
                continue

            if opcode == C2CTCP.HASHSETREQUEST:
                try:
                    req_hash = parse_file_hash_payload(payload)
                except Exception as exc:
                    log.debug("Ignoring malformed HASHSETREQUEST: %s", exc)
                    continue
                shared = self._resolver.resolve(req_hash)
                if shared is None:
                    continue
                source = BlockSource(shared)
                try:
                    chunks = source.chunk_hashes
                except UploadEngineError:
                    chunks = []
                finally:
                    source.close()
                if not chunks:
                    continue
                from amuled_v2.core.upload.engine import (
                    _build_hashset_answer_payload,
                )

                await transport.send(
                    C2CTCP.HASHSETANSWER,
                    _build_hashset_answer_payload(shared.file_hash, chunks),
                )
                continue

            if opcode == C2CTCP.SETREQFILEID:
                # Selection notification only; nothing to answer.
                log.debug(
                    "SETREQFILEID received: peer=%s", self._peer_name
                )
                continue

            if opcode == C2CEMULE.EMULEINFO:
                emule_answer = build_emuleinfo_payload(
                    emule_version=_DEFAULT_ED2K_VERSION
                )
                await transport.send(
                    C2CEMULE.EMULEINFOANSWER,
                    emule_answer,
                    protocol=EMULE,
                )
                log.info(
                    "EMULEINFOANSWER sent: peer=%s",
                    self._peer_name,
                )
                continue

            if opcode == C2CEMULE.EMULEINFOANSWER:
                log.debug(
                    "EMULEINFOANSWER received from peer=%s",
                    self._peer_name,
                )
                continue

            if opcode == C2CTCP.STARTUPLOADREQ:
                started_upload = True
                file_hash = parse_file_hash_payload(payload)
                last_hash_hex = file_hash.hex().upper()
                # UploadQueue normalizes hashes to lowercase; all queue keys
                # and comparisons MUST use the lowercase form.
                last_hash_key = file_hash.hex().lower()

                shared_file = self._resolver.resolve(file_hash)
                if shared_file is None:
                    log.warning(
                        "Shared file not found: peer=%s, hash=%s",
                        self._peer_name,
                        last_hash_hex,
                    )
                    end_payload = build_end_of_download_payload(file_hash)
                    await transport.send(C2CTCP.END_OF_DOWNLOAD, end_payload)
                    await self._safe_close(transport)
                    return self._build_report(
                        hello, last_hash_hex, started_at, accepted=False,
                        detail="file_not_found",
                    )

                log.info(
                    "Shared file resolved: peer=%s, hash=%s, name=%r, size=%d",
                    self._peer_name,
                    last_hash_hex,
                    shared_file.name,
                    shared_file.size,
                )

                user_hash_hex = hello.user_hash.hex().lower()
                client_id = hello.client_id

                if self._upload_queue.is_active(user_hash_hex, last_hash_key):
                    log.debug(
                        "STARTUPLOADREQ re-request from active peer: "
                        "peer=%s, user_hash=%s, hash=%s",
                        self._peer_name,
                        user_hash_hex,
                        last_hash_hex,
                    )
                    decision: tuple[str, int] = ("accept", 0)
                else:
                    rank = self._upload_queue.enqueue(
                        user_hash=user_hash_hex,
                        client_id=client_id,
                        client_port=hello.client_port,
                        nickname=hello.nickname,
                        requested_hash=last_hash_key,
                        file_priority=shared_file.priority,
                    )

                    head = self._upload_queue.next_for_slot()
                    if (
                        head is not None
                        and head.user_hash == user_hash_hex
                        and head.requested_hash == last_hash_key
                    ):
                        try:
                            self._upload_queue.grant_slot(
                                user_hash_hex, last_hash_key
                            )
                            granted_key = (user_hash_hex, last_hash_key)
                            decision = ("accept", 0)
                        except Exception as exc:
                            log.warning(
                                "grant_slot failed: peer=%s, error=%s",
                                self._peer_name,
                                exc,
                            )
                            decision = ("queue", rank)
                    else:
                        decision = ("queue", rank)

                outcome, rank_value = decision
                if outcome != "accept":
                    # Queue hold (eMule parity: the uploader keeps the
                    # queued client's connection open and pushes updated
                    # QUEUERANKs; when the head of the queue is promoted it
                    # answers with the engine hook -> ACCEPTUPLOADREQ).
                    # A clean EOF or END_OF_DOWNLOAD ends the wait.
                    while True:
                        rank_payload = struct.pack("<I", rank_value & 0xFFFFFFFF)
                        await transport.send(C2CTCP.QUEUERANK, rank_payload)
                        log.info(
                            "QUEUERANK sent: peer=%s, hash=%s, rank=%d",
                            self._peer_name,
                            last_hash_hex,
                            rank_value,
                        )
                        try:
                            packet = await asyncio.wait_for(
                                transport.recv(),
                                timeout=self._queue_rank_period,
                            )
                        except asyncio.TimeoutError:
                            head = self._upload_queue.next_for_slot()
                            if (
                                head is not None
                                and head.user_hash == user_hash_hex
                                and head.requested_hash == last_hash_key
                            ):
                                try:
                                    self._upload_queue.grant_slot(
                                        user_hash_hex, last_hash_key
                                    )
                                    granted_key = (user_hash_hex, last_hash_key)
                                    outcome = "accept"
                                    break
                                except Exception as exc:
                                    log.warning(
                                        "grant_slot failed on rank refresh: "
                                        "peer=%s, error=%s",
                                        self._peer_name,
                                        exc,
                                    )
                            fresh = self._upload_queue.rank_of(
                                user_hash_hex, last_hash_key
                            )
                            rank_value = (
                                fresh if fresh is not None else rank_value
                            )
                            continue
                        if packet is None:
                            await self._safe_close(transport)
                            return self._build_report(
                                hello, last_hash_hex, started_at,
                                accepted=False, detail="queued",
                            )
                        wait_opcode, wait_payload = packet
                        if wait_opcode == C2CTCP.STARTUPLOADREQ:
                            re_hash = parse_file_hash_payload(wait_payload)
                            re_key = re_hash.hex().lower()
                            rank_value = self._upload_queue.enqueue(
                                user_hash=user_hash_hex,
                                client_id=client_id,
                                client_port=hello.client_port,
                                nickname=hello.nickname,
                                requested_hash=re_key,
                                file_priority=shared_file.priority,
                            )
                            head = self._upload_queue.next_for_slot()
                            if (
                                head is not None
                                and head.user_hash == user_hash_hex
                                and head.requested_hash == re_key
                            ):
                                try:
                                    self._upload_queue.grant_slot(
                                        user_hash_hex, re_key
                                    )
                                    granted_key = (user_hash_hex, re_key)
                                    last_hash_hex = re_hash.hex().upper()
                                    last_hash_key = re_key
                                    outcome = "accept"
                                    break
                                except Exception as exc:
                                    log.warning(
                                        "grant_slot failed in queue wait: "
                                        "peer=%s, error=%s",
                                        self._peer_name,
                                        exc,
                                    )
                        elif wait_opcode == C2CTCP.END_OF_DOWNLOAD:
                            await self._safe_close(transport)
                            return self._build_report(
                                hello, last_hash_hex, started_at,
                                accepted=False, detail="queued",
                            )

                # Accept path: the engine's on_start_upload_request hook
                # re-examines the replayed STARTUPLOADREQ (is_active → True)
                # and sends OP_ACCEPTUPLOADREQ itself, so nothing is sent
                # here.
                preamble_transport = _PreambleTransport(
                    first_packets=[(opcode, payload)],
                    delegate=transport,
                )

                async def _on_start_upload_request(
                    req_hash: bytes,
                ) -> tuple[str, int]:
                    req_hash_hex = req_hash.hex().upper()
                    req_hash_key = req_hash.hex().lower()
                    if self._upload_queue.is_active(
                        user_hash_hex, req_hash_key
                    ):
                        return ("accept", 0)
                    r = self._upload_queue.enqueue(
                        user_hash=user_hash_hex,
                        client_id=client_id,
                        client_port=hello.client_port,
                        nickname=hello.nickname,
                        requested_hash=req_hash_key,
                        file_priority=shared_file.priority,
                    )
                    head_client = self._upload_queue.next_for_slot()
                    if (
                        head_client is not None
                        and head_client.user_hash == user_hash_hex
                        and head_client.requested_hash == req_hash_key
                    ):
                        try:
                            self._upload_queue.grant_slot(
                                user_hash_hex, req_hash_key
                            )
                            log.info(
                                "Slot granted via engine hook: "
                                "peer=%s, hash=%s",
                                self._peer_name,
                                req_hash_hex,
                            )
                            return ("accept", 0)
                        except Exception as exc:
                            log.warning(
                                "grant_slot in hook failed: peer=%s, error=%s",
                                self._peer_name,
                                exc,
                            )
                            return ("queue", r)
                    return ("queue", r)

                block_source = BlockSource(
                    shared_file,
                )
                session = UploadSession(
                    transport=preamble_transport,
                    block_source=block_source,
                    throttle=self._throttle,
                    allow_compression=self._allow_compression,
                    on_start_upload_request=_on_start_upload_request,
                )
                try:
                    await _run_upload_engine(
                        session, self._peer_name, last_hash_hex
                    )
                except ListenerError:
                    # The client may close as soon as it has every byte it
                    # asked for; the served bytes still count toward its
                    # credit ledger before the transport error propagates.
                    self._credit_uploaded(hello, session.stats)
                    raise
                if granted_key is not None:
                    self._upload_queue.release_slot(*granted_key)
                    granted_key = None
                # Post-transfer drain (eMule keeps the session open until
                # the DOWNLOADER closes it; UploadClient.cpp): serve AICH
                # requests while the peer stays connected.
                await self._drain_post_transfer(transport)
                break

            log.debug(
                "Ignoring pre-engine opcode: peer=%s, opcode=0x%02X, size=%d",
                self._peer_name,
                opcode,
                len(payload),
            )

        if session is not None:
            stats = session.stats
        else:
            stats = UploadSessionStats()
        self._credit_uploaded(hello, stats)

        await self._safe_close(transport)

        return self._build_report(
            hello, last_hash_hex, started_at, accepted=True,
            detail="transfer_complete", stats=stats,
        )

    async def _hold_buddy_session(
        self, transport: StreamTransport, idle: float = 300.0
    ) -> None:
        """Hold an open buddy-TCP channel for a served client.

        The session stays readable but deliberately idle: the KAD spider
        writes OP_CALLBACK (0x99) relays straight to the same writer via
        the registry.  The channel lives until the served client
        disconnects or the idle window lapses.  NOTE (wire TODO): the
        eMuleAI buddy ping/pong (OP_BUDDYPING 0x9F) is not answered yet —
        live clients may drop us after their ping window; implement when
        the ping payload oracle is extracted.
        """
        while True:
            try:
                packet = await transport.recv()
            except ListenerError:
                return  # idle timeout
            if packet is None:
                return  # served client disconnected
            opcode, _payload = packet
            log.debug(
                "Buddy session packet: peer=%s, opcode=0x%02X",
                self._peer_name,
                opcode,
            )

    async def _handle_aich_request(
        self, payload: bytes, transport: StreamTransport
    ) -> None:
        """AICH recovery responder (stage X; gate per SHAHashSet.cpp:
        715-723 — complete file, part in range, requested master must
        match ours)."""
        try:
            req_hash, req_part, req_master = parse_aich_request_payload(payload)
        except Exception as exc:
            log.debug(
                "AICHREQUEST ignored (malformed): peer=%s, error=%s",
                self._peer_name, exc,
            )
            return
        shared = self._resolver.resolve(req_hash)
        if shared is None or not shared.path:
            return
        try:
            from amuled_v2.core.codec.constants import PARTSIZE
            from amuled_v2.core.hashes.aich import (
                AichError,
                aich_hash_file,
                aich_part_recovery_data,
            )

            result = aich_hash_file(shared.path)
            if bytes(result.master_hash) != bytes(req_master):
                log.debug(
                    "AICHREQUEST master mismatch: peer=%s, hash=%s",
                    self._peer_name, req_hash.hex().upper(),
                )
                return
            part_count = (shared.size + PARTSIZE - 1) // PARTSIZE
            if req_part >= part_count:
                return
            recovery = aich_part_recovery_data(result, req_part)
        except AichError as exc:
            log.debug(
                "AICH recovery unavailable: peer=%s, error=%s",
                self._peer_name, exc,
            )
            return
        await transport.send(
            C2CEMULE.AICHANSWER,
            build_aich_answer_payload(req_hash, req_part, req_master, recovery),
            protocol=EMULE,
        )
        log.debug(
            "AICHANSWER sent: peer=%s, hash=%s, part=%d, recovery=%d",
            self._peer_name, req_hash.hex().upper(),
            req_part, len(recovery),
        )

    async def _drain_post_transfer(
        self, transport: StreamTransport, idle: float = 8.0
    ) -> None:
        """Serve post-transfer requests (AICH) until the peer disconnects
        or goes quiet.  eMule parity: the DOWNLOADER owns the connection
        lifetime; the source must keep answering after the last byte."""
        while True:
            try:
                packet = await transport.recv()
            except ListenerError:
                return  # idle timeout or transport error
            if packet is None:
                return  # peer closed
            opcode, payload = packet
            if opcode == C2CEMULE.AICHREQUEST:
                await self._handle_aich_request(payload, transport)
            else:
                log.debug(
                    "Ignoring post-transfer opcode: peer=%s, opcode=0x%02X",
                    self._peer_name,
                    opcode,
                )

    async def _safe_close(self, transport: StreamTransport) -> None:
        try:
            transport.close()
        except Exception:
            pass
        try:
            await self._writer.wait_closed()
        except (OSError, asyncio.CancelledError):
            pass

    @staticmethod
    def _build_report(
        hello: Any,
        file_hash_hex: str | None,
        started_at: float,
        *,
        accepted: bool,
        detail: str,
        stats: UploadSessionStats | None = None,
    ) -> dict[str, Any]:
        elapsed = time.monotonic() - started_at
        stat_dict = stats.to_dict() if stats else {}
        return {
            "peer": hello.to_dict(),
            "file_hash": file_hash_hex,
            "accepted": accepted,
            "detail": detail,
            "elapsed": elapsed,
            "stats": stat_dict,
        }


async def _run_upload_engine(
    session: UploadSession,
    peer_name: str,
    file_hash_hex: str,
) -> UploadSessionStats:
    """Run the UploadSession loop, catching transport errors.

    The transport may be plain or obfuscated (stage X); the session works
    with an established transport either way.
    """
    try:
        stats = await session.run()
        log.info(
            "Upload session complete: peer=%s, hash=%s, "
            "blocks_sent=%d, bytes_sent=%d, duration=%.3fs",
            peer_name,
            file_hash_hex,
            stats.blocks_sent,
            stats.bytes_sent,
            stats.ended_at - stats.started_at,
        )
        return stats
    except UploadEngineError as exc:
        log.error(
            "Upload engine error: peer=%s, hash=%s, error=%s",
            peer_name,
            file_hash_hex,
            exc,
        )
        raise ListenerError(
            f"upload engine failure for hash={file_hash_hex}: {exc}"
        ) from exc


def _format_peer(writer: asyncio.StreamWriter) -> str:
    try:
        peer = writer.get_extra_info("peername")
        if peer:
            return f"{peer[0]}:{peer[1]}"
    except Exception:
        pass
    return "unknown"


class IncomingPeerServer:
    """Asyncio TCP server wrapping the incoming peer listener logic.

    Port 4662 is the eD2K default, but Windows reserves/blocks several legacy
    ports in this project (4672/4673 confirmed occupied); port=0 requests an
    ephemeral bind, and the runner/KAD publish must advertise the actual bound
    port (see ``bound_port``).
    """

    def __init__(
        self,
        *,
        identity: LocalIdentity,
        resolver: StateSharedFileResolver,
        upload_queue: UploadQueue | None = None,
        host: str = "0.0.0.0",
        port: int = 0,
        throttle: UploadThrottle | None = None,
        allow_compression: bool = True,
        idle_timeout: float | None = 300.0,
        max_connections: int = 64,
        traffic_recorder: Callable[[str, int], None] | None = None,
        queue_rank_period: float = 60.0,
        secure_ident: Any | None = None,
        source_provider: Callable[[bytes], list[SXSource]] | None = None,
    ) -> None:
        self._identity = identity
        self._resolver = resolver
        self._upload_queue = upload_queue if upload_queue is not None else UploadQueue()
        self._host = host
        self._port = port
        self._throttle = throttle
        self._allow_compression = allow_compression
        self._idle_timeout = idle_timeout
        self._traffic_recorder = traffic_recorder
        self._queue_rank_period = queue_rank_period
        # Stage X SecureIdent provider shared by all sessions.
        self._secure_ident = secure_ident
        # Stage X source exchange: shared SX source rows for answers.
        self._source_provider = source_provider
        if max_connections < 1:
            raise ListenerError(f"max_connections must be >= 1, got {max_connections}")
        self._max_connections = max_connections
        self._server: asyncio.AbstractServer | None = None
        self._connections: set[IncomingPeerSession] = set()
        # Stage X direct-callback: callers (DownloadRunner) reserve inbound
        # connections from a firewalled source by IP; _on_client hands the
        # raw socket to the waiter instead of starting an upload session.
        # FIFO queue per IP: several racing peers may dial the SAME source
        # IP, and each dial-back must satisfy exactly one waiter.  Callers
        # MUST call expect_connection_from() BEFORE sending the callback
        # request (start it as a task) — dial-backs race the wait.
        self._expected: dict[str, list[asyncio.Future]] = {}

    async def expect_connection_from(
        self, ip: str, timeout: float = 15.0
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Wait for an inbound TCP connection from ``ip`` (direct-callback).

        The connection is NOT served by the upload engine: the waiting
        caller receives the raw (reader, writer) pair.  Waiters form a FIFO
        queue per IP; each dial-back satisfies exactly one waiter.
        """
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._expected.setdefault(ip, []).append(future)
        try:
            return await asyncio.wait_for(future, timeout)
        finally:
            waiters = self._expected.get(ip)
            if waiters is not None:
                try:
                    waiters.remove(future)
                except ValueError:
                    pass
                if not waiters:
                    self._expected.pop(ip, None)

    @property
    def bound_port(self) -> int:
        if self._server is not None and self._server.sockets:
            info = self._server.sockets[0].getsockname()
            if isinstance(info, tuple) and len(info) >= 2:
                return info[1]
        return self._port

    @property
    def active_connections(self) -> int:
        return len(self._connections)

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._on_client,
            self._host,
            self._port,
        )
        bound = self.bound_port
        log.info(
            "Incoming peer server listening: host=%s, port=%d",
            self._host,
            bound,
        )

    async def serve_forever(self) -> None:
        if self._server is None:
            raise ListenerError("server not started; call start() first")
        await self._server.serve_forever()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for session in list(self._connections):
            session._writer.close()
        self._connections.clear()
        log.info("Incoming peer server closed")

    async def _on_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer_name = _format_peer(writer)
        if len(self._connections) >= self._max_connections:
            log.warning(
                "Incoming C2C connection rejected: peer=%s, active=%d, max=%d",
                peer_name,
                len(self._connections),
                self._max_connections,
            )
            writer.close()
            return
        log.info("Incoming C2C connection: peer=%s", peer_name)

        # Direct-callback reservation: hand raw sockets to a waiting
        # downloader instead of the upload engine (peer IP match, FIFO).
        peer_ip = peer_name.rsplit(":", 1)[0].strip() if peer_name else ""
        waiters = self._expected.get(peer_ip)
        waiter = waiters.pop(0) if waiters else None
        if not waiters:
            self._expected.pop(peer_ip, None)
        if waiter is not None and not waiter.done():
            waiter.set_result((reader, writer))
            log.info(
                "Inbound connection reserved for direct-callback: peer=%s",
                peer_name,
            )
            return

        session = IncomingPeerSession(
            reader,
            writer,
            identity=self._identity,
            resolver=self._resolver,
            upload_queue=self._upload_queue,
            throttle=self._throttle,
            allow_compression=self._allow_compression,
            idle_timeout=self._idle_timeout,
            traffic_recorder=self._traffic_recorder,
            queue_rank_period=self._queue_rank_period,
            secure_ident=self._secure_ident,
            source_provider=self._source_provider,
        )
        self._connections.add(session)
        try:
            report = await session.run()
            log.info(
                "Session complete: peer=%s, accepted=%s, detail=%s, "
                "elapsed=%.3fs",
                peer_name,
                report.get("accepted", False),
                report.get("detail", ""),
                report.get("elapsed", 0.0),
            )
        except ListenerError as exc:
            log.error(
                "Listener error: peer=%s, error=%s",
                peer_name,
                exc,
            )
        except Exception as exc:
            log.error(
                "Unhandled session error: peer=%s, error=%s",
                peer_name,
                exc,
                exc_info=True,
            )
        finally:
            self._connections.discard(session)
            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass
