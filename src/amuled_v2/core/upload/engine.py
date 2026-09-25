"""Upload transfer engine: serves blocks of one shared file to one accepted peer.

Implements the per-session upload transfer logic transcribed from eMuleAI
``UploadClient.cpp`` and ``UploadDiskIOThread.cpp``: handling of
OP_REQUESTFILENAME, OP_HASHSETREQUEST, OP_REQUESTPARTS / OP_REQUESTPARTS_I64,
and OP_END_OF_DOWNLOAD, with optional zlib compression and a simple per-session
upload throttle.

The engine is transport-agnostic: an :class:`UploadTransport` (a
``typing.Protocol``) is injected, so the caller supplies the encrypted/obfuscated
socket wrapper externally.

src/amuled_v2/core/upload/engine.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-24

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added UploadEngineError, UploadThrottle, BlockSource, UploadTransport.
  [+] Added UploadSessionStats dataclass with to_dict serialization.
  [+] Added UploadSession.run() implementing REQUESTFILENAME, HASHSETREQUEST,
      REQUESTPARTS/REQUESTPARTS_I64, and END_OF_DOWNLOAD handling.
  [+] Added local fallback codec helpers for OP_REQFILENAMEANSWER and
      OP_HASHSETANSWER wire formats when amuled_v2.core.peer.codec is incomplete.
  [+] Added plain (non-I64) SENDINGPART/COMPRESSEDPART fallback builders.
  [+] Added OP_STARTUPLOADREQ handling via an injected accept/queue hook.
"""

from __future__ import annotations

import asyncio
import struct
import time
import zlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

from amuled_v2.core.codec.binary import BinaryWriter
from amuled_v2.core.hashes.ed2k import Ed2kHashResult, PARTSIZE, ed2k_hash_file
from amuled_v2.core.sharing.shared_files import SharedFile
from amuled_v2.logging_setup import LogTags, get_tagged_logger

try:
    from amuled_v2.core.peer.codec import (
        PeerCodecError,
        build_sending_part_i64_payload,
        build_compressed_part_i64_payload,
        build_file_name_answer_payload,
        build_end_of_download_payload,
    )
except ImportError:
    PeerCodecError = ValueError

    def build_sending_part_i64_payload(
        file_hash: bytes, start: int, end: int, data: bytes
    ) -> bytes:
        writer = BinaryWriter()
        writer.write_bytes(bytes(file_hash[:16]))
        writer.write_u64(start)
        writer.write_u64(end)
        writer.write_bytes(data)
        return writer.to_bytes()

    def build_compressed_part_i64_payload(
        file_hash: bytes, start: int, data: bytes
    ) -> bytes:
        compressed = zlib.compress(data, level=1)
        writer = BinaryWriter()
        writer.write_bytes(bytes(file_hash[:16]))
        writer.write_u64(start)
        writer.write_u32(len(compressed))
        writer.write_bytes(compressed)
        return writer.to_bytes()

    def build_file_name_answer_payload(file_hash: bytes, name: str) -> bytes:
        writer = BinaryWriter()
        writer.write_bytes(bytes(file_hash[:16]))
        encoded = name.encode("utf-8")
        writer.write_u16(len(encoded))
        writer.write_bytes(encoded)
        return writer.to_bytes()

    def build_end_of_download_payload(file_hash: bytes) -> bytes:
        return bytes(file_hash[:16])


try:
    from amuled_v2.core.peer.codec import parse_request_parts as _parse_request_parts
    from amuled_v2.core.peer.codec import parse_request_parts_i64 as _parse_request_parts_i64
except ImportError:
    _parse_request_parts = None
    _parse_request_parts_i64 = None


log = get_tagged_logger(LogTags.UPLOAD, "core.upload.engine")

__all__ = [
    "UploadEngineError",
    "UploadThrottle",
    "BlockSource",
    "UploadTransport",
    "UploadSessionStats",
    "UploadSession",
]

EMBLOCKSIZE = 184_320
MAX_REQUEST_BLOCKS = 3
# eMuleAI UploadDiskIOThread.cpp CreateStandardPackets/CreatePackedPackets:
# each sub-packet carries at most 13000 bytes; when more remains, the chunk
# size is 10240 (not 13000) to keep packets inside the socket buffer.
SPLIT_THRESHOLD = 13_000
SPLIT_CHUNK_SIZE = 10_240
DEFAULT_CHUNK_SIZE = PARTSIZE

OP_SENDINGPART = 0x46
OP_COMPRESSEDPART = 0x40
OP_SENDINGPART_I64 = 0xA2
OP_COMPRESSEDPART_I64 = 0xA1
OP_REQUESTPARTS = 0x47
OP_REQUESTPARTS_I64 = 0xA3
OP_END_OF_DOWNLOAD = 0x49
OP_HASHSETREQUEST = 0x51
OP_HASHSETANSWER = 0x52
OP_REQUESTFILENAME = 0x58
OP_REQFILENAMEANSWER = 0x59
OP_STARTUPLOADREQ = 0x54
OP_ACCEPTUPLOADREQ = 0x55
OP_QUEUERANK = 0x5C

# Decision returned by the on_start_upload_request hook:
# ("accept", 0) -> send OP_ACCEPTUPLOADREQ and continue serving blocks;
# ("queue", rank) -> send OP_QUEUERANK with the given 1-based rank.
StartUploadDecision = tuple[str, int]
StartUploadHook = Callable[[bytes], Awaitable[StartUploadDecision]]


def _build_sending_part_payload(
    file_hash: bytes, start: int, end: int, data: bytes
) -> bytes:
    """Build OP_SENDINGPART payload: hash16 + u32 start + u32 end + data.

    Fallback when codec.py does not export a plain SENDINGPART builder.
    Wire format from UploadDiskIOThread.cpp CreateStandardPackets (lines 489-497).
    """
    writer = BinaryWriter()
    writer.write_bytes(bytes(file_hash[:16]))
    writer.write_u32(start & 0xFFFFFFFF)
    writer.write_u32(end & 0xFFFFFFFF)
    writer.write_bytes(data)
    return writer.to_bytes()


def _build_compressed_part_payload(
    file_hash: bytes, start: int, compressed_size: int, compressed_data: bytes
) -> bytes:
    """Build OP_COMPRESSEDPART payload: hash16 + u32 start + u32 comp_size + data.

    Fallback when codec.py does not export a plain COMPRESSEDPART builder.
    Wire format from UploadDiskIOThread.cpp CreatePackedPackets (lines 550-557).
    """
    writer = BinaryWriter()
    writer.write_bytes(bytes(file_hash[:16]))
    writer.write_u32(start & 0xFFFFFFFF)
    writer.write_u32(compressed_size)
    writer.write_bytes(compressed_data)
    return writer.to_bytes()


def _build_compressed_part_i64_u64_payload(
    file_hash: bytes, start: int, compressed_size: int, compressed_data: bytes
) -> bytes:
    """Build OP_COMPRESSEDPART_I64 payload: hash16 + u64 start + u32 comp_size + data.

    Wire format from UploadDiskIOThread.cpp CreatePackedPackets (lines 543-549).
    """
    writer = BinaryWriter()
    writer.write_bytes(bytes(file_hash[:16]))
    writer.write_u64(start)
    writer.write_u32(compressed_size)
    writer.write_bytes(compressed_data)
    return writer.to_bytes()


def _build_hashset_answer_payload(
    file_hash: bytes, chunk_hashes: list[bytes]
) -> bytes:
    """Build OP_HASHSETANSWER payload: u16 count + count * hash16.

    First hash is the file hash; remaining entries are MD4 chunk hashes.
    Matches eMule ``WriteMD4HashsetToFile`` wire format (packets.cpp /
    CFileIdentifier) and parse_hashset_answer in codec.py.
    """
    writer = BinaryWriter()
    count = 1 + len(chunk_hashes)
    writer.write_u16(count)
    writer.write_bytes(bytes(file_hash[:16]))
    for chunk_hash in chunk_hashes:
        writer.write_bytes(bytes(chunk_hash[:16]))
    return writer.to_bytes()


def _parse_request_parts_internal(payload: bytes, is_i64: bool):
    """Parse OP_REQUESTPARTS / OP_REQUESTPARTS_I64 into (hash, starts, ends).

    eMule always sends exactly 3 (start, end) pairs; unused slots are
    (0, 0) and are dropped here.  ``start > end`` is a protocol error,
    ``start == end`` (non-zero) is tolerated as an empty request.
    """
    if is_i64 and _parse_request_parts_i64 is not None:
        try:
            result = _parse_request_parts_i64(payload)
        except PeerCodecError:
            result = None
        if result is not None:
            pairs = [
                (s, e) for s, e in zip(result.starts, result.ends)
                if not (s == 0 and e == 0)
            ]
            return result.file_hash, [p[0] for p in pairs], [p[1] for p in pairs]
    if not is_i64 and _parse_request_parts is not None:
        try:
            result = _parse_request_parts(payload)
        except PeerCodecError:
            result = None
        if result is not None:
            pairs = [
                (s, e) for s, e in zip(result.starts, result.ends)
                if not (s == 0 and e == 0)
            ]
            return result.file_hash, [p[0] for p in pairs], [p[1] for p in pairs]
    offset_width = 8 if is_i64 else 4
    fmt_char = "Q" if is_i64 else "I"
    expected = 16 + 6 * offset_width
    if len(payload) < expected:
        raise PeerCodecError(
            f"malformed request payload: need {expected} bytes, got {len(payload)}"
        )
    values = struct.unpack_from(f"<3{fmt_char}3{fmt_char}", payload[16:])
    raw_starts = values[:3]
    raw_ends = values[3:]
    starts: list[int] = []
    ends: list[int] = []
    for start, end in zip(raw_starts, raw_ends):
        if start == 0 and end == 0:
            continue
        if start > end:
            raise PeerCodecError(f"start {start} must not exceed end {end}")
        starts.append(start)
        ends.append(end)
    return payload[:16], starts, ends


class UploadEngineError(RuntimeError):
    """Raised for unrecoverable errors in the upload transfer engine."""


class UploadThrottle:
    """Simple per-session upload rate limiter.

    Mirrors the bytes-per-slot pacing model of
    ``UploadBandwidthThrottler.cpp``: the session sleeps just enough to keep
    the average send rate near ``rate_bytes_per_sec``.
    """

    def __init__(self, rate_bytes_per_sec: int | None = None) -> None:
        if rate_bytes_per_sec is not None and rate_bytes_per_sec <= 0:
            raise UploadEngineError(
                "rate_bytes_per_sec must be positive or None, got "
                f"{rate_bytes_per_sec}"
            )
        self.rate_bytes_per_sec: int | None = rate_bytes_per_sec
        self._last_send_time: float = 0.0
        self._bytes_sent: int = 0

    async def throttle(self, nbytes: int) -> None:
        if self.rate_bytes_per_sec is None or self.rate_bytes_per_sec <= 0:
            return
        if self._last_send_time == 0.0:
            self._last_send_time = time.monotonic()
        self._bytes_sent += nbytes
        now = time.monotonic()
        elapsed = now - self._last_send_time
        target_elapsed = self._bytes_sent / self.rate_bytes_per_sec
        deficit = target_elapsed - elapsed
        if deficit > 0:
            await asyncio.sleep(deficit)
            self._last_send_time = time.monotonic()
            self._bytes_sent = 0

    def reset(self) -> None:
        self._last_send_time = 0.0
        self._bytes_sent = 0


class BlockSource:
    """Provides bounds-checked block reads from one shared file on disk."""

    def __init__(
        self,
        shared_file: SharedFile,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        self.shared_file: SharedFile = shared_file
        self.chunk_size: int = chunk_size
        self._file_hash: bytes = shared_file.file_hash
        self._chunk_hashes: list[bytes] = []
        self._file_obj = None
        if shared_file.path is None:
            raise UploadEngineError(
                f"shared file has no path: hash={self._file_hash.hex().upper()}"
            )
        resolved = Path(shared_file.path)
        if not resolved.is_file():
            raise UploadEngineError(
                f"shared file does not exist: path={resolved}, "
                f"hash={self._file_hash.hex().upper()}"
            )
        self._path: Path = resolved

    @property
    def file_hash(self) -> bytes:
        return self._file_hash

    @property
    def chunk_hashes(self) -> list[bytes]:
        if not self._chunk_hashes:
            self._load_chunk_hashes()
        return self._chunk_hashes

    @property
    def file_size(self) -> int:
        return self.shared_file.size

    @property
    def chunk_count(self) -> int:
        if self.shared_file.size == 0:
            return 1
        return (self.shared_file.size + self.chunk_size - 1) // self.chunk_size

    @property
    def present_chunks(self) -> list[int]:
        return list(range(self.chunk_count))

    def _load_chunk_hashes(self) -> None:
        hash_result: Optional[Ed2kHashResult] = self.shared_file.hash_result
        if hash_result is None:
            hash_result = ed2k_hash_file(str(self._path), chunk_size=self.chunk_size)
        chunk_list = list(hash_result.chunk_hashes)
        if len(chunk_list) == self.chunk_count + 1:
            chunk_list = chunk_list[:-1]
        self._chunk_hashes = chunk_list

    def open(self) -> BlockSource:
        if self._file_obj is None:
            self._file_obj = open(self._path, "rb")
        return self

    def close(self) -> None:
        if self._file_obj is not None:
            try:
                self._file_obj.close()
            except OSError:
                pass
            self._file_obj = None

    def __enter__(self) -> BlockSource:
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def read_block(self, start: int, length: int) -> bytes:
        if self._file_obj is None:
            raise UploadEngineError("BlockSource is not open; call open() first")
        if start < 0:
            raise UploadEngineError(f"start offset is negative: start={start}")
        if length < 0:
            raise UploadEngineError(
                f"length is negative: start={start}, length={length}"
            )
        end = start + length
        if end > self.shared_file.size:
            raise UploadEngineError(
                f"block read exceeds file size: start={start}, length={length}, "
                f"end={end}, file_size={self.shared_file.size}"
            )
        self._file_obj.seek(start)
        data = self._file_obj.read(length)
        if len(data) < length:
            raise UploadEngineError(
                f"short read: requested={length}, got={len(data)}, "
                f"start={start}"
            )
        return data


@runtime_checkable
class UploadTransport(Protocol):
    """Abstract transport for an accepted upload peer.

    # WIP by external developer: encrypted transport (BASIC obfuscation / DH) is implemented externally; this session assumes an established transport.
    """

    async def recv(self) -> Optional[tuple[int, bytes]]:
        """Receive one (opcode, payload) packet, or None on EOF."""
        ...

    async def send(self, opcode: int, payload: bytes) -> None:
        """Send one (opcode, payload) packet to the peer."""
        ...


@dataclass
class UploadSessionStats:
    """Statistics for a completed upload session."""

    blocks_sent: int = 0
    bytes_sent: int = 0
    compressed_blocks: int = 0
    requests_handled: int = 0
    started_at: float = field(default_factory=time.monotonic)
    ended_at: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "blocks_sent": self.blocks_sent,
            "bytes_sent": self.bytes_sent,
            "compressed_blocks": self.compressed_blocks,
            "requests_handled": self.requests_handled,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration": self.ended_at - self.started_at,
        }


class UploadSession:
    """Serves blocks of one :class:`SharedFile` to one peer over a transport.

    # WIP by external developer: encrypted transport (BASIC obfuscation / DH) is implemented externally; this session assumes an established transport.

    The session runs a request loop: it receives OP_REQUESTFILENAME,
    OP_HASHSETREQUEST, and OP_REQUESTPARTS / OP_REQUESTPARTS_I64 requests,
    replies with the appropriate answer packets, and sends block data
    (OP_SENDINGPART* / OP_COMPRESSEDPART*) with optional zlib compression and
    per-session rate throttling.
    """

    def __init__(
        self,
        transport: UploadTransport,
        block_source: BlockSource,
        *,
        throttle: Optional[UploadThrottle] = None,
        allow_compression: bool = True,
        on_start_upload_request: Optional[StartUploadHook] = None,
    ) -> None:
        self.transport: UploadTransport = transport
        self.block_source: BlockSource = block_source
        self.throttle: Optional[UploadThrottle] = throttle
        self.allow_compression: bool = allow_compression
        # Hook deciding STARTUPLOADREQ: accept (slot granted) or queue(rank).
        # Wired to core.upload.queue.UploadQueue by the incoming listener.
        self.on_start_upload_request: Optional[StartUploadHook] = on_start_upload_request
        self.stats: UploadSessionStats = UploadSessionStats()

    async def _send(self, opcode: int, payload: bytes) -> None:
        # WIP by external developer: encrypted transport (BASIC obfuscation / DH) is implemented externally; this session assumes an established transport.
        await self.transport.send(opcode, payload)

    async def _handle_request_filename(self, payload: bytes) -> None:
        file_hash = (
            payload[:16]
            if len(payload) >= 16
            else self.block_source.file_hash
        )
        name = self.block_source.shared_file.name
        answer_payload = build_file_name_answer_payload(file_hash, name)
        await self._send(OP_REQFILENAMEANSWER, answer_payload)
        log.info(
            "REQFILENAMEANSWER sent: hash=%s, name=%r, size=%d",
            file_hash.hex().upper(),
            name,
            len(answer_payload),
        )

    async def _handle_hashset_request(self, payload: bytes) -> bool:
        """Handle OP_HASHSETREQUEST; return True if handled.

        From UploadClient.cpp SendHashsetPacket (lines 941-987): if the file
        is unknown the client calls CheckFailedFileIdReqs and throws; eMule
        does NOT send OP_END_OF_DOWNLOAD here. However, per the task spec, if
        chunk hashes are unknown (hash_result is None / chunk_hashes empty)
        we send OP_END_OF_DOWNLOAD with the requested hash to signal that no
        hashset is available.
        """
        file_hash = (
            payload[:16]
            if len(payload) >= 16
            else self.block_source.file_hash
        )
        chunk_hashes = self.block_source.chunk_hashes
        if not chunk_hashes:
            end_payload = build_end_of_download_payload(
                self.block_source.file_hash
            )
            await self._send(OP_END_OF_DOWNLOAD, end_payload)
            log.warning(
                "END_OF_DOWNLOAD sent (hashset unknown): hash=%s",
                file_hash.hex().upper(),
            )
            return True
        answer_payload = _build_hashset_answer_payload(
            self.block_source.file_hash, chunk_hashes
        )
        await self._send(OP_HASHSETANSWER, answer_payload)
        log.info(
            "HASHSETANSWER sent: hash=%s, chunk_count=%d, size=%d",
            file_hash.hex().upper(),
            len(chunk_hashes),
            len(answer_payload),
        )
        return True

    async def _handle_request_parts(
        self, payload: bytes, opcode: int
    ) -> None:
        """Handle OP_REQUESTPARTS / OP_REQUESTPARTS_I64.

        Per UploadClient.cpp IsQueuedBlockRequestValid (lines 66-77):
        start < end, end <= file_size, end - start <= EMBLOCKSIZE * 3.
        CreateStandardPackets (UploadDiskIOThread.cpp:462-505) splits each
        block into sub-packets of at most 13000 bytes; if end > UInt32 max
        it uses the I64 opcode family.

        Per-request PeerCodecError is logged and the session continues.
        """
        is_i64 = opcode == OP_REQUESTPARTS_I64
        file_size = self.block_source.file_size
        self.stats.requests_handled += 1

        try:
            req_hash, starts, ends = _parse_request_parts_internal(
                payload, is_i64
            )
        except PeerCodecError as exc:
            log.error(
                "Peer codec error parsing REQUESTPARTS: %s, opcode=0x%02X",
                exc,
                opcode,
            )
            return

        for idx, (start, end) in enumerate(zip(starts, ends)):
            if start >= end:
                log.debug(
                    "REQUESTPARTS block %d invalid: start=%d, end=%d",
                    idx,
                    start,
                    end,
                )
                continue
            if end > file_size:
                end = file_size
            if start >= end:
                continue
            block_length = end - start
            if block_length > EMBLOCKSIZE * MAX_REQUEST_BLOCKS:
                end = start + EMBLOCKSIZE * MAX_REQUEST_BLOCKS
                block_length = end - start
            if block_length <= 0:
                continue
            await self._send_block(start, end, block_length, is_i64)

    async def _send_block(
        self, start: int, end: int, length: int, is_i64: bool
    ) -> None:
        # WIP by external developer: encrypted transport (BASIC obfuscation / DH) is implemented externally; this session assumes an established transport.
        file_hash = self.block_source.file_hash
        data = self.block_source.read_block(start, length)
        if self.throttle is not None:
            await self.throttle.throttle(len(data))

        use_compression = False
        compressed_data: bytes = b""
        if self.allow_compression and len(data) > 0:
            compressed_data = zlib.compress(data, level=1)
            if len(compressed_data) < len(data):
                use_compression = True

        # eMuleAI UploadDiskIOThread.cpp: the (possibly compressed) block is
        # split into sub-packets of at most 13000 bytes (10240 when more
        # remains). SENDINGPART sub-packets carry their own (start, end)
        # window and switch to the I64 opcode family per sub-packet when
        # endpos > UINT32_MAX. COMPRESSEDPART sub-packets repeat the BLOCK
        # start offset (not the chunk offset) plus the TOTAL compressed size.
        if use_compression:
            self.stats.compressed_blocks += 1
            total_comp_size = len(compressed_data)
            togo = total_comp_size
            while togo:
                chunk_len = togo if togo <= SPLIT_THRESHOLD else SPLIT_CHUNK_SIZE
                togo -= chunk_len
                offset = total_comp_size - togo - chunk_len
                chunk = compressed_data[offset : offset + chunk_len]
                # COMPRESSEDPART* is always sent on the eMule protocol byte
                # (OP_EMULEPROT 0xC5); the opcode family still follows the
                # block end offset (CreatePackedPackets, uEndOffset check).
                compressed_is_i64 = end > 0xFFFFFFFF
                if compressed_is_i64:
                    payload = _build_compressed_part_i64_u64_payload(
                        file_hash,
                        start,
                        total_comp_size,
                        chunk,
                    )
                else:
                    payload = _build_compressed_part_payload(
                        file_hash,
                        start,
                        total_comp_size,
                        chunk,
                    )
                await self._send(
                    OP_COMPRESSEDPART_I64 if compressed_is_i64 else OP_COMPRESSEDPART,
                    payload,
                )
                self.stats.bytes_sent += len(payload)
                self.stats.blocks_sent += 1
            log.debug(
                "Compressed block sent: start=%d, end=%d, length=%d, "
                "compressed=%d",
                start,
                end,
                length,
                total_comp_size,
            )
            return

        togo = length
        while togo:
            chunk_len = togo if togo <= SPLIT_THRESHOLD else SPLIT_CHUNK_SIZE
            togo -= chunk_len
            chunk_end = end - togo
            chunk_start = chunk_end - chunk_len
            chunk = data[chunk_start - start : chunk_end - start]
            # SENDINGPART family per sub-packet: I64 only when endpos exceeds
            # UInt32 (CreateStandardPackets, endpos > _UI32_MAX check).
            chunk_is_i64 = chunk_end > 0xFFFFFFFF
            if chunk_is_i64:
                payload = build_sending_part_i64_payload(
                    file_hash,
                    chunk_start,
                    chunk_end,
                    chunk,
                )
                opcode = OP_SENDINGPART_I64
            else:
                payload = _build_sending_part_payload(
                    file_hash,
                    chunk_start,
                    chunk_end,
                    chunk,
                )
                opcode = OP_SENDINGPART
            await self._send(opcode, payload)
            self.stats.bytes_sent += len(payload)
            self.stats.blocks_sent += 1
        log.debug(
            "Block sent: start=%d, end=%d, length=%d",
            start,
            end,
            length,
        )

    async def _handle_start_upload_request(self, payload: bytes) -> None:
        """Handle OP_STARTUPLOADREQ via the injected queue-decision hook.

        eMuleAI UploadClient.cpp ProcessFileRequest: a STARTUPLOADREQ is
        answered with OP_ACCEPTUPLOADREQ when a slot is free, otherwise the
        client is queued and OP_QUEUERANK is sent.  Without a hook we cannot
        decide, so the request is ignored (listener always injects one).
        """
        if len(payload) < 16:
            log.warning("STARTUPLOADREQ too short: size=%d", len(payload))
            return
        requested_hash = payload[:16]
        if self.on_start_upload_request is None:
            log.warning(
                "STARTUPLOADREQ without decision hook, ignored: hash=%s",
                requested_hash.hex().upper(),
            )
            return
        decision, rank = await self.on_start_upload_request(requested_hash)
        if decision == "accept":
            await self._send(OP_ACCEPTUPLOADREQ, b"")
            log.info(
                "ACCEPTUPLOADREQ sent: hash=%s",
                requested_hash.hex().upper(),
            )
        elif decision == "queue":
            writer = BinaryWriter()
            writer.write_u32(rank & 0xFFFFFFFF)
            await self._send(OP_QUEUERANK, writer.to_bytes())
            log.info(
                "QUEUERANK sent: hash=%s, rank=%d",
                requested_hash.hex().upper(),
                rank,
            )
        else:
            log.warning("Unknown start-upload decision: %r", decision)

    async def run(self) -> UploadSessionStats:
        """Run the upload session request loop until EOF or END_OF_DOWNLOAD."""
        self.stats.started_at = time.monotonic()
        self.block_source.open()
        log.info(
            "Session started: file_hash=%s, file_size=%d, allow_compression=%s",
            self.block_source.file_hash.hex().upper(),
            self.block_source.file_size,
            self.allow_compression,
        )
        try:
            while True:
                # WIP by external developer: encrypted transport (BASIC obfuscation / DH) is implemented externally; this session assumes an established transport.
                packet = await self.transport.recv()
                if packet is None:
                    log.info(
                        "Session ended: EOF from peer, file_hash=%s",
                        self.block_source.file_hash.hex().upper(),
                    )
                    break
                opcode, payload = packet
                try:
                    if opcode == OP_REQUESTFILENAME:
                        await self._handle_request_filename(payload)
                    elif opcode == OP_HASHSETREQUEST:
                        await self._handle_hashset_request(payload)
                    elif opcode == OP_REQUESTPARTS:
                        await self._handle_request_parts(payload, OP_REQUESTPARTS)
                    elif opcode == OP_REQUESTPARTS_I64:
                        await self._handle_request_parts(
                            payload, OP_REQUESTPARTS_I64
                        )
                    elif opcode == OP_END_OF_DOWNLOAD:
                        log.info(
                            "Session ended: peer sent END_OF_DOWNLOAD, "
                            "hash=%s",
                            payload.hex().upper()[:32] if payload else "empty",
                        )
                        break
                    elif opcode == OP_STARTUPLOADREQ:
                        await self._handle_start_upload_request(payload)
                    else:
                        log.debug(
                            "Ignoring unsupported upload opcode: 0x%02X", opcode
                        )
                except PeerCodecError as exc:
                    log.error(
                        "Peer codec error on opcode 0x%02X: %s",
                        opcode,
                        exc,
                    )
        except OSError as exc:
            raise UploadEngineError(
                f"transport I/O error: {exc} "
                f"(file_hash={self.block_source.file_hash.hex().upper()})"
            ) from exc
        finally:
            self.stats.ended_at = time.monotonic()
            self.block_source.close()
            log.info(
                "Session ended: blocks_sent=%d, bytes_sent=%d, "
                "compressed_blocks=%d, requests_handled=%d, duration=%.3fs",
                self.stats.blocks_sent,
                self.stats.bytes_sent,
                self.stats.compressed_blocks,
                self.stats.requests_handled,
                self.stats.ended_at - self.stats.started_at,
            )
        return self.stats
