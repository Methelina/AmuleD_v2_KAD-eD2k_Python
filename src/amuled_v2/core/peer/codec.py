"""eMule client-to-client (C2C / Peer2Peer) TCP wire codec.

Implements the client-side ED2K TCP framing and the subset of eMule C2C opcodes
transcribed from ``docs/PROTOCOL_MATRIX.md`` sections 5-6 (eDonkey2000
opcodes.h / BaseClient.cpp, eMule 0.50a).  A C2C packet uses the same wire
framing as client-to-server ED2K: protocol byte 0xE3, a UInt32 LE packet length
that counts the opcode byte (payload_size + 1), the opcode byte, then the
payload.

Opcodes covered by this module:

    OP_HELLO          0x01  hello handshake (user_hash, client_id, port, tags)
    OP_HELLOANSWER    0x4C  hello answer (hello body + server_ip, server_port)
    OP_REQUESTFILENAME 0x58  request file name by hash
    OP_REQFILENAMEANSWER 0x59  answer with file name
    OP_SETREQFILEID   0x4F  set requested file id (hash16)
    OP_HASHSETREQUEST 0x51  request hash set (hash16)
    OP_HASHSETANSWER  0x52  hash set answer (count + hash16 values)
    OP_STARTUPLOADREQ 0x54  start upload request (hash16)
    OP_ACCEPTUPLOADREQ 0x55  accept upload request (empty)
    OP_QUEUERANK       0x5C  queue rank (u32)
    OP_END_OF_DOWNLOAD 0x49  end of download (hash16)
    OP_FILESTATUS     0x50  file status (hash16, chunk_count, bit array)
    OP_REQUESTPARTS    0x47  request parts (hash16, 3x start, 3x end u32)
    OP_REQUESTPARTS_I64 0xA3  request parts (hash16, 3x start, 3x end u64)
    OP_SENDINGPART    0x46  sending part (hash16, start, end, data)
    OP_SENDINGPART_I64 0xA2  sending part (hash16, start, end u64, data)
    OP_COMPRESSEDPART  0x40  compressed sending part (zlib)
    OP_COMPRESSEDPART_I64 0xA1  compressed sending part (u64 start/end)

src/amuled_v2/core/peer/codec.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added C2CTCP opcode constants for client-to-client TCP.
  [+] Added build_hello_payload / parse_hello for OP_HELLO.
  [+] Added build_hello_answer_payload / parse_hello_answer for OP_HELLOANSWER.
  [+] Added build_request_filename_payload / parse_file_hash_payload for OP_REQUESTFILENAME.
  [+] Added parse_filename_answer for OP_REQFILENAMEANSWER.
  [+] Added parse_hashset_answer for OP_HASHSETANSWER.
  [+] Added build_request_parts_payload / parse_request_parts for OP_REQUESTPARTS.
  [+] Added build_request_parts_i64_payload / parse_request_parts_i64 for OP_REQUESTPARTS_I64.
  [+] Added parse_sending_part / parse_sending_part_i64 for OP_SENDINGPART(_I64).
  [+] Added parse_compressed_part / parse_compressed_part_i64 for OP_COMPRESSEDPART(_I64).
  [+] Added parse_queue_rank / parse_file_status for OP_QUEUERANK / OP_FILESTATUS.
  [+] Added frozen dataclass models with to_dict serialization.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass
from typing import Any, Optional

from amuled_v2.core.codec.binary import BinaryReader, BinaryWriter, CodecError
from amuled_v2.core.codec.constants import EDONKEY, STRING, UINT32, UINT64
from amuled_v2.core.codec.tags import Ed2kTag, TagError, read_new_tag, write_new_tag
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.PEER, "core.peer.codec")

__all__ = [
    "C2CTCP",
    "PeerCodecError",
    "Hello",
    "HelloAnswer",
    "FileNameAnswer",
    "HashSetAnswer",
    "FileStatus",
    "RequestParts",
    "SendingPart",
    "build_hello_payload",
    "build_hello_answer_payload",
    "build_request_filename_payload",
    "parse_file_hash_payload",
    "parse_filename_answer",
    "parse_hashset_answer",
    "build_request_parts_payload",
    "parse_request_parts",
    "build_request_parts_i64_payload",
    "parse_request_parts_i64",
    "parse_sending_part",
    "parse_sending_part_i64",
    "parse_compressed_part",
    "parse_compressed_part_i64",
    "parse_queue_rank",
    "parse_file_status",
]

_HASH16_SIZE = 16
_PROTOCOL = EDONKEY
_HEADER_SIZE = 6
_COMPRESSED_MAX_OUTPUT = 184_320 + 16


class PeerCodecError(ValueError):
    """Raised when a peer codec operation encounters invalid input."""


class C2CTCP:
    """Client-to-client TCP opcode identifiers (eMule 0.50a opcodes.h)."""

    HELLO = 0x01
    HELLOANSWER = 0x4C
    REQUESTFILENAME = 0x58
    REQFILENAMEANSWER = 0x59
    SETREQFILEID = 0x4F
    HASHSETREQUEST = 0x51
    HASHSETANSWER = 0x52
    STARTUPLOADREQ = 0x54
    ACCEPTUPLOADREQ = 0x55
    QUEUERANK = 0x5C
    END_OF_DOWNLOAD = 0x49
    FILESTATUS = 0x50
    REQUESTPARTS = 0x47
    REQUESTPARTS_I64 = 0xA3
    SENDINGPART = 0x46
    SENDINGPART_I64 = 0xA2
    COMPRESSEDPART = 0x40
    COMPRESSEDPART_I64 = 0xA1


def _build_hello_tags(nickname: str, version: int = 0x3C, client_port: int = 0) -> list[Ed2kTag]:
    """HELLO tag set exactly as the protocol expects it.

    НЕ упрощать (уже сносили дважды, оба раза пиры рвали соединение через
    10 с — таймаут ожидания валидного хендшейка):
    - без EMULE-тегов приёмник считает нас старым eDonkey и не отвечает
      на файловые запросы;
    - в MISCOPTIONS2 младшие биты — версия KAD; без них пиры считают,
      что мы не умеем KAD;
    - CT_PORT в HELLO не входит (порт уже в фиксированном поле), лишние
      теги меняют tagcount — держим набор 1:1 с протоколом.
    """
    # (kad_udp_port << 16) | ed2k_udp_port; постоянного UDP-порта нет — 0.
    udports = 0
    # Флаги возможностей: AICH, Unicode, сжатие, source exchange, multipacket,
    # large files и т.п. Биты должны соответствовать тому, что мы реально
    # умеем отвечать, иначе пир пришлёт неподдерживаемый формат.
    miso1 = (
        (1 << 29)   # AICH version 1
        | (1 << 28)  # Unicode
        | (4 << 24)  # UDP version
        | (1 << 20)  # data compression
        | (0 << 16)  # SecIdent (нет)
        | (4 << 12)  # source exchange v4
        | (2 << 8)   # extended requests v2
        | (1 << 4)   # accept comment
        | (0 << 3)   # peer cache (нет)
        | (1 << 2)   # no view shared files
        | (1 << 1)   # multipacket
        | (0 << 0)   # preview (нет)
    )
    miso2 = (
        (1 << 13)   # file identifiers
        | (0 << 12)  # direct UDP callback (нет)
        | (0 << 11)  # captcha (нет)
        | (1 << 10)  # source exchange v2
        | (0 << 9) | (0 << 8) | (0 << 7)  # TCP-криптослой (не реализован)
        | (0 << 6)   # reserved (mod bit)
        | (1 << 5)   # extended multipacket
        | (1 << 4)   # large files
        | 9          # KAD version 9 (kad2)
    )
    # Версия, под которой нас видят пиры: (major << 17) | (minor << 10) |
    # (update << 7) = eMule 0.50a. Держать синхронно с build_emuleinfo_payload.
    emule_version_tag = (0 << 17) | (50 << 10) | (0 << 7)
    tags: list[Ed2kTag] = [
        Ed2kTag(name_id=0x01, type=STRING, value=nickname),           # имя
        Ed2kTag(name_id=0x11, type=UINT32, value=version),            # ed2k version
        Ed2kTag(name_id=0xF9, type=UINT32, value=udports),            # udp ports
        Ed2kTag(name_id=0xFA, type=UINT32, value=miso1),              # misc options 1
        Ed2kTag(name_id=0xFB, type=UINT32, value=emule_version_tag),  # emule version
        Ed2kTag(name_id=0xFE, type=UINT32, value=miso2),              # misc options 2
    ]
    return tags


def _write_hello_body(
    writer: BinaryWriter,
    user_hash: bytes,
    client_id: int,
    client_port: int,
    nickname: str,
    version: int = 0x3C,
) -> None:
    if len(user_hash) != _HASH16_SIZE:
        raise PeerCodecError("user hash must contain exactly 16 bytes")
    if not 0 <= client_id <= 0xFFFFFFFF:
        raise PeerCodecError(f"client_id out of UInt32 range: {client_id}")
    if not 0 <= client_port <= 0xFFFF:
        raise PeerCodecError(f"client_port out of UInt16 range: {client_port}")
    if not 0 <= version <= 0xFFFFFFFF:
        raise PeerCodecError(f"version out of UInt32 range: {version}")
    writer.write_u8(_HASH16_SIZE)
    writer.write_hash16(user_hash)
    writer.write_u32(client_id)
    writer.write_u16(client_port)
    tags = _build_hello_tags(nickname, version, client_port)
    writer.write_u32(len(tags))
    for tag in tags:
        try:
            write_new_tag(tag, writer)
        except TagError as exc:
            raise PeerCodecError(f"cannot encode HELLO tag: {exc}") from exc


def parse_hello_tags(reader: BinaryReader) -> tuple[Ed2kTag, ...]:
    tag_count = reader.read_u32()
    tags: list[Ed2kTag] = []
    try:
        for _ in range(tag_count):
            tags.append(read_new_tag(reader))
    except TagError as exc:
        raise PeerCodecError(f"malformed HELLO tag: {exc}") from exc
    return tuple(tags)


@dataclass(frozen=True)
class Hello:
    """Parsed ``OP_HELLO`` payload."""

    user_hash: bytes
    client_id: int
    client_port: int
    nickname: str
    version: int
    tags: tuple[Ed2kTag, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_hash": self.user_hash.hex().upper(),
            "client_id": self.client_id,
            "client_port": self.client_port,
            "nickname": self.nickname,
            "version": self.version,
            "tags": [tag.to_dict() for tag in self.tags],
        }


def build_hello_payload(
    user_hash: bytes,
    client_id: int,
    client_port: int,
    nickname: str,
    version: int = 0x3C,
) -> bytes:
    """Encode an ``OP_HELLO`` payload."""
    writer = BinaryWriter()
    _write_hello_body(writer, user_hash, client_id, client_port, nickname, version)
    payload = writer.to_bytes()
    log.debug(
        "HELLO payload built: user_hash=%s, client_id=%d, port=%d, name=%r, size=%d",
        user_hash.hex().upper(),
        client_id,
        client_port,
        nickname,
        len(payload),
    )
    return payload


def parse_hello(payload: bytes) -> Hello:
    """Parse an ``OP_HELLO`` payload into a :class:`Hello`."""
    reader = BinaryReader(payload)
    try:
        hash_len = reader.read_u8()
        if hash_len != _HASH16_SIZE:
            raise PeerCodecError(f"HELLO hash length must be {_HASH16_SIZE}, got {hash_len}")
        user_hash = reader.read_hash16()
        client_id = reader.read_u32()
        client_port = reader.read_u16()
        tags = parse_hello_tags(reader)
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_HELLO: {exc}") from exc
    if reader.remaining:
        raise PeerCodecError(f"OP_HELLO has {reader.remaining} trailing bytes")
    nickname = ""
    version = 0
    for tag in tags:
        if tag.name_id == 0x01 and isinstance(tag.value, str):
            nickname = tag.value
        elif tag.name_id == 0x11 and isinstance(tag.value, int):
            version = tag.value
    result = Hello(
        user_hash=user_hash,
        client_id=client_id,
        client_port=client_port,
        nickname=nickname,
        version=version,
        tags=tags,
    )
    log.debug(
        "HELLO payload parsed: user_hash=%s, client_id=%d, port=%d, name=%r, version=%d",
        user_hash.hex().upper(),
        client_id,
        client_port,
        nickname,
        version,
    )
    return result


@dataclass(frozen=True)
class HelloAnswer:
    """Parsed ``OP_HELLOANSWER`` payload."""

    user_hash: bytes
    client_id: int
    client_port: int
    nickname: str
    version: int
    server_ip: int
    server_port: int
    tags: tuple[Ed2kTag, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_hash": self.user_hash.hex().upper(),
            "client_id": self.client_id,
            "client_port": self.client_port,
            "nickname": self.nickname,
            "version": self.version,
            "server_ip": self.server_ip,
            "server_port": self.server_port,
            "tags": [tag.to_dict() for tag in self.tags],
        }


def build_hello_answer_payload(
    user_hash: bytes,
    client_id: int,
    client_port: int,
    nickname: str,
    server_ip: int,
    server_port: int,
    version: int = 0x3C,
) -> bytes:
    """Encode an ``OP_HELLOANSWER`` payload."""
    if len(user_hash) != _HASH16_SIZE:
        raise PeerCodecError("user hash must contain exactly 16 bytes")
    if not 0 <= server_ip <= 0xFFFFFFFF:
        raise PeerCodecError(f"server_ip out of UInt32 range: {server_ip}")
    if not 0 <= server_port <= 0xFFFF:
        raise PeerCodecError(f"server_port out of UInt16 range: {server_port}")
    writer = BinaryWriter()
    _write_hello_body(writer, user_hash, client_id, client_port, nickname, version)
    writer.write_u32(server_ip)
    writer.write_u16(server_port)
    payload = writer.to_bytes()
    log.debug(
        "HELLOANSWER payload built: user_hash=%s, server_ip=%d, server_port=%d, size=%d",
        user_hash.hex().upper(),
        server_ip,
        server_port,
        len(payload),
    )
    return payload


def parse_hello_answer(payload: bytes) -> HelloAnswer:
    """Parse an ``OP_HELLOANSWER`` payload into a :class:`HelloAnswer`."""
    reader = BinaryReader(payload)
    try:
        hash_len = reader.read_u8()
        if hash_len != _HASH16_SIZE:
            raise PeerCodecError(f"HELLOANSWER hash length must be {_HASH16_SIZE}, got {hash_len}")
        user_hash = reader.read_hash16()
        client_id = reader.read_u32()
        client_port = reader.read_u16()
        tags = parse_hello_tags(reader)
        server_ip = reader.read_u32()
        server_port = reader.read_u16()
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_HELLOANSWER: {exc}") from exc
    if reader.remaining:
        raise PeerCodecError(f"OP_HELLOANSWER has {reader.remaining} trailing bytes")
    nickname = ""
    version = 0
    for tag in tags:
        if tag.name_id == 0x01 and isinstance(tag.value, str):
            nickname = tag.value
        elif tag.name_id == 0x11 and isinstance(tag.value, int):
            version = tag.value
    result = HelloAnswer(
        user_hash=user_hash,
        client_id=client_id,
        client_port=client_port,
        nickname=nickname,
        version=version,
        server_ip=server_ip,
        server_port=server_port,
        tags=tags,
    )
    log.debug(
        "HELLOANSWER payload parsed: user_hash=%s, server_ip=%d, server_port=%d",
        user_hash.hex().upper(),
        server_ip,
        server_port,
    )
    return result


def build_request_filename_payload(file_hash: bytes) -> bytes:
    """Encode an ``OP_REQUESTFILENAME`` payload (hash16)."""
    if len(file_hash) != _HASH16_SIZE:
        raise PeerCodecError("file hash must contain exactly 16 bytes")
    writer = BinaryWriter()
    writer.write_hash16(file_hash)
    payload = writer.to_bytes()
    log.debug("REQUESTFILENAME payload built: hash=%s, size=%d", file_hash.hex().upper(), len(payload))
    return payload


def parse_file_hash_payload(payload: bytes) -> bytes:
    """Parse a single hash16 payload and return the raw file hash."""
    reader = BinaryReader(payload)
    try:
        file_hash = reader.read_hash16()
    except CodecError as exc:
        raise PeerCodecError(f"malformed hash payload: {exc}") from exc
    if reader.remaining:
        raise PeerCodecError(f"unexpected {reader.remaining} trailing bytes after hash16")
    log.debug("File hash payload parsed: hash=%s", file_hash.hex().upper())
    return file_hash


@dataclass(frozen=True)
class FileNameAnswer:
    """Parsed ``OP_REQFILENAMEANSWER`` payload."""

    file_hash: bytes
    name: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_hash": self.file_hash.hex().upper(),
            "name": self.name,
        }


def parse_filename_answer(payload: bytes) -> FileNameAnswer:
    """Parse an ``OP_REQFILENAMEANSWER`` payload into a :class:`FileNameAnswer`."""
    reader = BinaryReader(payload)
    try:
        file_hash = reader.read_hash16()
        name = reader.read_string_utf8()
    except (CodecError, UnicodeError) as exc:
        raise PeerCodecError(f"malformed OP_REQFILENAMEANSWER: {exc}") from exc
    if reader.remaining:
        raise PeerCodecError(f"OP_REQFILENAMEANSWER has {reader.remaining} trailing bytes")
    result = FileNameAnswer(file_hash=file_hash, name=name)
    log.debug("REQFILENAMEANSWER parsed: hash=%s, name=%r", file_hash.hex().upper(), name)
    return result


@dataclass(frozen=True)
class HashSetAnswer:
    """Parsed ``OP_HASHSETANSWER`` payload."""

    file_hash: bytes
    chunk_hashes: tuple[bytes, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_hash": self.file_hash.hex().upper(),
            "chunk_count": len(self.chunk_hashes),
            "chunk_hashes": [h.hex().upper() for h in self.chunk_hashes],
        }


def parse_hashset_answer(payload: bytes) -> HashSetAnswer:
    """Parse an ``OP_HASHSETANSWER`` payload into a :class:`HashSetAnswer`."""
    reader = BinaryReader(payload)
    try:
        count = reader.read_u16()
        hashes: list[bytes] = []
        for _ in range(count):
            hashes.append(reader.read_hash16())
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_HASHSETANSWER: {exc}") from exc
    if reader.remaining:
        raise PeerCodecError(f"OP_HASHSETANSWER has {reader.remaining} trailing bytes")
    if not hashes:
        raise PeerCodecError("OP_HASHSETANSWER has zero hashes")
    result = HashSetAnswer(file_hash=hashes[0], chunk_hashes=tuple(hashes[1:]))
    log.debug(
        "HASHSETANSWER parsed: file_hash=%s, chunk_count=%d",
        result.file_hash.hex().upper(),
        len(result.chunk_hashes),
    )
    return result


@dataclass(frozen=True)
class FileStatus:
    """Parsed ``OP_FILESTATUS`` payload."""

    file_hash: bytes
    chunk_count: int
    present_chunks: tuple[int, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_hash": self.file_hash.hex().upper(),
            "chunk_count": self.chunk_count,
            "present_chunks": list(self.present_chunks),
        }


def parse_file_status(payload: bytes) -> FileStatus:
    """Parse an ``OP_FILESTATUS`` payload into a :class:`FileStatus`."""
    reader = BinaryReader(payload)
    try:
        file_hash = reader.read_hash16()
        chunk_count = reader.read_u16()
        bit_array = reader.read_bytes((chunk_count + 7) // 8)
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_FILESTATUS: {exc}") from exc
    if reader.remaining:
        raise PeerCodecError(f"OP_FILESTATUS has {reader.remaining} trailing bytes")
    present: list[int] = []
    for i in range(chunk_count):
        byte_index = i // 8
        bit_index = i % 8
        if byte_index < len(bit_array) and (bit_array[byte_index] >> bit_index) & 1:
            present.append(i)
    result = FileStatus(
        file_hash=file_hash,
        chunk_count=chunk_count,
        present_chunks=tuple(present),
    )
    log.debug(
        "FILESTATUS parsed: hash=%s, chunk_count=%d, present=%d",
        file_hash.hex().upper(),
        chunk_count,
        len(present),
    )
    return result


@dataclass(frozen=True)
class RequestParts:
    """Parsed ``OP_REQUESTPARTS`` payload (UInt32 offsets)."""

    file_hash: bytes
    starts: tuple[int, int, int]
    ends: tuple[int, int, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_hash": self.file_hash.hex().upper(),
            "starts": list(self.starts),
            "ends": list(self.ends),
        }


def _validate_three_tuple(value: Any, name: str) -> None:
    if not isinstance(value, tuple) or len(value) != 3:
        raise PeerCodecError(f"{name} must be a 3-element tuple")
    for element in value:
        if not isinstance(element, int) or isinstance(element, bool):
            raise PeerCodecError(f"{name} elements must be int")
        if element < 0:
            raise PeerCodecError(f"{name} elements must be non-negative: {element}")


def _validate_starts_ends(starts: tuple[int, int, int], ends: tuple[int, int, int]) -> None:
    _validate_three_tuple(starts, "starts")
    _validate_three_tuple(ends, "ends")
    for start, end in zip(starts, ends):
        if start >= end:
            raise PeerCodecError(f"start {start} must be less than end {end}")


def build_request_parts_payload(
    file_hash: bytes,
    starts: tuple[int, int, int],
    ends: tuple[int, int, int],
) -> bytes:
    """Encode an ``OP_REQUESTPARTS`` payload (UInt32 offsets)."""
    if len(file_hash) != _HASH16_SIZE:
        raise PeerCodecError("file hash must contain exactly 16 bytes")
    _validate_starts_ends(starts, ends)
    writer = BinaryWriter()
    writer.write_hash16(file_hash)
    for value in starts:
        if not 0 <= value <= 0xFFFFFFFF:
            raise PeerCodecError(f"start offset out of UInt32 range: {value}")
        writer.write_u32(value)
    for value in ends:
        if not 0 <= value <= 0xFFFFFFFF:
            raise PeerCodecError(f"end offset out of UInt32 range: {value}")
        writer.write_u32(value)
    payload = writer.to_bytes()
    log.debug(
        "REQUESTPARTS payload built: hash=%s, starts=%s, ends=%s, size=%d",
        file_hash.hex().upper(),
        starts,
        ends,
        len(payload),
    )
    return payload


def parse_request_parts(payload: bytes) -> RequestParts:
    """Parse an ``OP_REQUESTPARTS`` payload into a :class:`RequestParts`."""
    reader = BinaryReader(payload)
    try:
        file_hash = reader.read_hash16()
        starts = tuple(reader.read_u32() for _ in range(3))
        ends = tuple(reader.read_u32() for _ in range(3))
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_REQUESTPARTS: {exc}") from exc
    if reader.remaining:
        raise PeerCodecError(f"OP_REQUESTPARTS has {reader.remaining} trailing bytes")
    for start, end in zip(starts, ends):
        if start >= end:
            raise PeerCodecError(f"start {start} must be less than end {end}")
    result = RequestParts(file_hash=file_hash, starts=starts, ends=ends)
    log.debug("REQUESTPARTS parsed: hash=%s, starts=%s, ends=%s", file_hash.hex().upper(), starts, ends)
    return result


def build_request_parts_i64_payload(
    file_hash: bytes,
    starts: tuple[int, int, int],
    ends: tuple[int, int, int],
) -> bytes:
    """Encode an ``OP_REQUESTPARTS_I64`` payload (UInt64 offsets)."""
    if len(file_hash) != _HASH16_SIZE:
        raise PeerCodecError("file hash must contain exactly 16 bytes")
    _validate_starts_ends(starts, ends)
    writer = BinaryWriter()
    writer.write_hash16(file_hash)
    for value in starts:
        if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            raise PeerCodecError(f"start offset out of UInt64 range: {value}")
        writer.write_u64(value)
    for value in ends:
        if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            raise PeerCodecError(f"end offset out of UInt64 range: {value}")
        writer.write_u64(value)
    payload = writer.to_bytes()
    log.debug(
        "REQUESTPARTS_I64 payload built: hash=%s, starts=%s, ends=%s, size=%d",
        file_hash.hex().upper(),
        starts,
        ends,
        len(payload),
    )
    return payload


def parse_request_parts_i64(payload: bytes) -> RequestParts:
    """Parse an ``OP_REQUESTPARTS_I64`` payload into a :class:`RequestParts`."""
    reader = BinaryReader(payload)
    try:
        file_hash = reader.read_hash16()
        starts = tuple(reader.read_u64() for _ in range(3))
        ends = tuple(reader.read_u64() for _ in range(3))
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_REQUESTPARTS_I64: {exc}") from exc
    if reader.remaining:
        raise PeerCodecError(f"OP_REQUESTPARTS_I64 has {reader.remaining} trailing bytes")
    for start, end in zip(starts, ends):
        if start >= end:
            raise PeerCodecError(f"start {start} must be less than end {end}")
    result = RequestParts(file_hash=file_hash, starts=starts, ends=ends)
    log.debug("REQUESTPARTS_I64 parsed: hash=%s, starts=%s, ends=%s", file_hash.hex().upper(), starts, ends)
    return result


@dataclass(frozen=True)
class SendingPart:
    """Parsed ``OP_SENDINGPART`` (or compressed/I64 variant) payload.

    ``data`` is always the raw, decompressed block covering ``start..end``.
    """

    file_hash: bytes
    start: int
    end: int
    data: bytes

    @property
    def data_size(self) -> int:
        return len(self.data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_hash": self.file_hash.hex().upper(),
            "start": self.start,
            "end": self.end,
            "data_size": self.data_size,
        }


def parse_sending_part(payload: bytes) -> SendingPart:
    """Parse an ``OP_SENDINGPART`` payload (UInt32 start/end)."""
    reader = BinaryReader(payload)
    try:
        file_hash = reader.read_hash16()
        start = reader.read_u32()
        end = reader.read_u32()
        data = reader.read_bytes_remaining()
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_SENDINGPART: {exc}") from exc
    if len(data) != end - start:
        raise PeerCodecError(
            f"OP_SENDINGPART data length {len(data)} != end-start {end - start}"
        )
    result = SendingPart(file_hash=file_hash, start=start, end=end, data=data)
    log.debug(
        "SENDINGPART parsed: hash=%s, start=%d, end=%d, data_size=%d",
        file_hash.hex().upper(),
        start,
        end,
        len(data),
    )
    return result


def parse_sending_part_i64(payload: bytes) -> SendingPart:
    """Parse an ``OP_SENDINGPART_I64`` payload (UInt64 start/end)."""
    reader = BinaryReader(payload)
    try:
        file_hash = reader.read_hash16()
        start = reader.read_u64()
        end = reader.read_u64()
        data = reader.read_bytes_remaining()
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_SENDINGPART_I64: {exc}") from exc
    if len(data) != end - start:
        raise PeerCodecError(
            f"OP_SENDINGPART_I64 data length {len(data)} != end-start {end - start}"
        )
    result = SendingPart(file_hash=file_hash, start=start, end=end, data=data)
    log.debug(
        "SENDINGPART_I64 parsed: hash=%s, start=%d, end=%d, data_size=%d",
        file_hash.hex().upper(),
        start,
        end,
        len(data),
    )
    return result


def parse_compressed_part(payload: bytes) -> SendingPart:
    """Parse an ``OP_COMPRESSEDPART`` payload (zlib-compressed UInt32 offsets)."""
    reader = BinaryReader(payload)
    try:
        file_hash = reader.read_hash16()
        start = reader.read_u32()
        compressed_size = reader.read_u32()
        compressed_data = reader.read_bytes(compressed_size)
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_COMPRESSEDPART: {exc}") from exc
    if reader.remaining:
        raise PeerCodecError(f"OP_COMPRESSEDPART has {reader.remaining} trailing bytes")
    try:
        decompressed = zlib.decompress(compressed_data)
    except zlib.error as exc:
        raise PeerCodecError(f"malformed OP_COMPRESSEDPART zlib payload: {exc}") from exc
    if not decompressed:
        raise PeerCodecError("OP_COMPRESSEDPART decompressed to empty data")
    end = start + len(decompressed)
    result = SendingPart(file_hash=file_hash, start=start, end=end, data=decompressed)
    log.debug(
        "COMPRESSEDPART parsed: hash=%s, start=%d, end=%d, data_size=%d",
        file_hash.hex().upper(),
        start,
        end,
        len(decompressed),
    )
    return result


def parse_compressed_part_i64(payload: bytes) -> SendingPart:
    """Parse an ``OP_COMPRESSEDPART_I64`` payload (zlib-compressed UInt64 offsets)."""
    reader = BinaryReader(payload)
    try:
        file_hash = reader.read_hash16()
        start = reader.read_u64()
        compressed_size = reader.read_u32()
        compressed_data = reader.read_bytes(compressed_size)
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_COMPRESSEDPART_I64: {exc}") from exc
    if reader.remaining:
        raise PeerCodecError(f"OP_COMPRESSEDPART_I64 has {reader.remaining} trailing bytes")
    try:
        decompressed = zlib.decompress(compressed_data)
    except zlib.error as exc:
        raise PeerCodecError(f"malformed OP_COMPRESSEDPART_I64 zlib payload: {exc}") from exc
    if not decompressed:
        raise PeerCodecError("OP_COMPRESSEDPART_I64 decompressed to empty data")
    end = start + len(decompressed)
    result = SendingPart(file_hash=file_hash, start=start, end=end, data=decompressed)
    log.debug(
        "COMPRESSEDPART_I64 parsed: hash=%s, start=%d, end=%d, data_size=%d",
        file_hash.hex().upper(),
        start,
        end,
        len(decompressed),
    )
    return result


def parse_queue_rank(payload: bytes) -> int:
    """Parse an ``OP_QUEUERANK`` payload into a queue rank integer."""
    reader = BinaryReader(payload)
    try:
        rank = reader.read_u32()
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_QUEUERANK: {exc}") from exc
    if reader.remaining:
        raise PeerCodecError(f"OP_QUEUERANK has {reader.remaining} trailing bytes")
    log.debug("QUEUERANK parsed: rank=%d", rank)
    return rank
