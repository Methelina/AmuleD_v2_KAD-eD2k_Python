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
Version:     0.2.0
Author:      Soror L.'.L'.
Updated:     2026-09-24

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

Patch Notes v0.2.0 (Soror L.'.L'.):
  [+] Added upload-answer payload builders (QUEUERANK, ACCEPTUPLOADREQ, END_OF_DOWNLOAD, SENDINGPART_I64, COMPRESSEDPART_I64, REQFILENAMEANSWER, FILESTATUS).
"""

from __future__ import annotations

import struct
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
    "build_queue_rank_payload",
    "build_accept_upload_req_payload",
    "build_end_of_download_payload",
    "build_sending_part_i64_payload",
    "build_compressed_part_i64_payload",
    "build_file_name_answer_payload",
    "build_file_status_payload",
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
    FILEREQANSNOFIL = 0x39  # OP_FILEREQANSNOFIL (opcodes.h 0.50a): no such file
    OUTOFPARTREQS = 0x57  # OP_OUTOFPARTREQS: source has no parts right now
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

    MISCOPTIONS-сверка (стадия X): заявляем ТОЛЬКО то, что реально
    обрабатываем (слушатель: REQUESTFILENAME / HASHSETREQUEST /
    SETREQFILEID / REQUESTPARTS(_I64) / END_OF_DOWNLOAD / EMULEINFO;
    клиент: COMPRESSEDPART-сборка, I64-диапазоны, kad2). AICH, source
    exchange, multipacket, extended requests, accept comment и aux-UDP
    запросы мы НЕ отвечаем — биты = 0, иначе пир пришлёт формат,
    который мы молча проглотим и он решит, что мы сломаны.
    """
    # (kad_udp_port << 16) | ed2k_udp_port; постоянного UDP-порта нет — 0.
    udports = 0
    # Возможности как код: 1 = обработчик есть, 0 = нет.
    cap_compression = 1      # шлём COMPRESSEDPART(_I64), клиент собирает чанки
    cap_unicode = 1          # теги UTF-8
    cap_large_files = 1      # REQUESTPARTS_I64 / SENDINGPART_I64
    cap_kad2 = 9             # kad2-клиент (поиск/публикация/источники)
    cap_no_view_shared = 1   # раздаемые файлы на просмотр не открываем
    cap_aich = 1             # OP_AICHREQUEST отвечаем (responder, стадия X)
    cap_udp_version = 0      # aux-UDP (OS_UDP_*) не отвечаем
    cap_source_exchange = 1  # OP_REQUESTSOURCES(2) отвечаем (responder, стадия X)
    cap_extended_requests = 0  # комментарии/файл-теги в ответах не шлём
    cap_accept_comment = 0   # комментарии о файле не принимаем
    cap_multipacket = 0      # multipacket (0xBC) не разбираем
    cap_ext_multipacket = 0  # extended multipacket не разбираем
    cap_file_identifiers = 0  # 0xA4 file identifiers не отвечаем
    # SecureIdent: 3 = full SUI + v2 capable (SUI core в
    # core/security/secure_ident.py; BaseClient.cpp:2027).
    cap_secident = 3
    miso1 = (
        (cap_aich << 29)
        | (cap_unicode << 28)
        | (cap_udp_version << 24)
        | (cap_compression << 20)
        | (cap_secident << 16)
        | (cap_source_exchange << 12)
        | (cap_extended_requests << 8)
        | (cap_accept_comment << 4)
        | (0 << 3)   # peer cache (нет)
        | (cap_no_view_shared << 2)
        | (cap_multipacket << 1)
        | (0 << 0)   # preview (нет)
    )
    # TCP-криптослой: клиентская обфускация У НАС ЕСТЬ (obfuscation.py,
    # client v0.3.0), поэтому честно заявляем Supports+Requests (биты 7/8);
    # Requires (бит 9) не ставим — plain-пиров не отвергаем на этапе битов.
    cap_crypt_supports = 1
    cap_crypt_requests = 1
    cap_crypt_requires = 0
    cap_source_exchange_v2 = 1  # SX2 (OP_REQUESTSOURCES2) отвечаем
    miso2 = (
        (cap_file_identifiers << 13)
        | (0 << 12)  # direct UDP callback (нет)
        | (0 << 11)  # captcha (нет)
        | (cap_source_exchange_v2 << 10)
        | (cap_crypt_requires << 9)
        | (cap_crypt_requests << 8)
        | (cap_crypt_supports << 7)
        | (0 << 6)   # reserved (mod bit)
        | (cap_ext_multipacket << 5)
        | (cap_large_files << 4)
        | cap_kad2   # KAD version 9 (kad2)
    )
    # Версия, под которой нас видят пиры: (major << 17) | (minor << 10) |
    # (update << 7) = eMule 0.50a. Держать синхронно с build_emuleinfo_payload.
    emule_version_tag = (0 << 17) | (50 << 10) | (0 << 7)
    # Vanilla tag order (SendHelloTypePacket, BaseClient.cpp:1853):
    # NAME, VERSION, UDPPORTS, MISCOPTIONS1, MISCOPTIONS2, EMULE_VERSION.
    # The eMuleAI Shield flags PR_WRONGTAGORDER otherwise.
    tags: list[Ed2kTag] = [
        Ed2kTag(name_id=0x01, type=STRING, value=nickname),           # имя
        Ed2kTag(name_id=0x11, type=UINT32, value=version),            # ed2k version
        Ed2kTag(name_id=0xF9, type=UINT32, value=udports),            # udp ports
        Ed2kTag(name_id=0xFA, type=UINT32, value=miso1),              # misc options 1
        Ed2kTag(name_id=0xFE, type=UINT32, value=miso2),              # misc options 2
        Ed2kTag(name_id=0xFB, type=UINT32, value=emule_version_tag),  # emule version
    ]
    return tags


def _write_hello_tag(tag: Ed2kTag, writer: BinaryWriter) -> None:
    """Write one HELLO tag in the OLD CTag::WriteTagToFile format
    (Packets.cpp:676-716), the only form real clients send in HELLO:

        [type u8][u16 namelen = 1][u8 name_id][value]

    Integers are always TAGTYPE_UINT32 (0x03) with a u32 value; strings
    are TAGTYPE_STRING (0x02) with a u16 length.  The compact 0x80|type
    short form (write_new_tag) is parser-compatible but no real client
    emits it here — the eMuleAI Shield flags PR_WRONGTAGFORMAT.
    """
    name = tag.name if tag.name is not None else tag.name_id
    if name is None:
        raise PeerCodecError("HELLO tag needs a name or name_id")
    if isinstance(tag.value, str):
        raw = tag.value.encode("utf-8")
        writer.write_u8(0x02)
        writer.write_u16(1)
        writer.write_u8(int(name))
        writer.write_u16(len(raw))
        writer.write_bytes(raw)
        return
    if isinstance(tag.value, int) and not isinstance(tag.value, bool):
        if not 0 <= tag.value <= 0xFFFFFFFF:
            raise PeerCodecError(
                f"HELLO uint tag value out of UInt32 range: {tag.value}"
            )
        writer.write_u8(0x03)
        writer.write_u16(1)
        writer.write_u8(int(name))
        writer.write_u32(tag.value)
        return
    raise PeerCodecError(
        f"unsupported HELLO tag value type: {type(tag.value).__name__}"
    )


def _write_hello_body(
    writer: BinaryWriter,
    user_hash: bytes,
    client_id: int,
    client_port: int,
    nickname: str,
    version: int = 0x3C,
    server_ip: int = 0,
    server_port: int = 0,
) -> None:
    if len(user_hash) != _HASH16_SIZE:
        raise PeerCodecError("user hash must contain exactly 16 bytes")
    if not 0 <= client_id <= 0xFFFFFFFF:
        raise PeerCodecError(f"client_id out of UInt32 range: {client_id}")
    if not 0 <= client_port <= 0xFFFF:
        raise PeerCodecError(f"client_port out of UInt16 range: {client_port}")
    if not 0 <= version <= 0xFFFFFFFF:
        raise PeerCodecError(f"version out of UInt32 range: {version}")
    if not 0 <= server_ip <= 0xFFFFFFFF:
        raise PeerCodecError(f"server_ip out of UInt32 range: {server_ip}")
    if not 0 <= server_port <= 0xFFFF:
        raise PeerCodecError(f"server_port out of UInt16 range: {server_port}")
    writer.write_u8(_HASH16_SIZE)
    writer.write_hash16(user_hash)
    writer.write_u32(client_id)
    writer.write_u16(client_port)
    tags = _build_hello_tags(nickname, version, client_port)
    writer.write_u32(len(tags))
    for tag in tags:
        _write_hello_tag(tag, writer)
    # Хвост HELLO/HELLOANSWER одинаков: server_ip u32 + server_port u16
    # (SendHelloTypePacket, BaseClient.cpp:2212-2217). Без этих 6 байт
    # приёмник читает за концом буфера и рвёт соединение мгновенно.
    writer.write_u32(server_ip)
    writer.write_u16(server_port)


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


def _parse_hello_body(payload: bytes, label: str) -> tuple[BinaryReader, bytes, int, int, tuple[Ed2kTag, ...], int, int]:
    """Parse shared HELLO/HELLOANSWER fields.

    Canonical form: [hashlen u8 = 16][hash 16][client_id u32][port u16]
    [tagcount u32][tags][server_ip u32][server_port u16].

    The eMuleAI 1.6.0 fork writes HELLOANSWER WITHOUT the leading length
    byte (verified live 2026-09-26: payload starts directly with the
    16-byte userhash, followed by client_id whose low bytes match the
    advertised client id and the real 8089 listen port).  When the first
    byte is not 16, the length-less fork form is accepted.
    """
    reader = BinaryReader(payload)
    hash_len = reader.read_u8()
    if hash_len == _HASH16_SIZE:
        user_hash = reader.read_hash16()
    else:
        # Fork form: the first byte is already part of the hash.
        reader = BinaryReader(payload)
        user_hash = reader.read_bytes(_HASH16_SIZE)
    client_id = reader.read_u32()
    client_port = reader.read_u16()
    tags = parse_hello_tags(reader)
    server_ip = reader.read_u32()
    server_port = reader.read_u16()
    if reader.remaining:
        raise PeerCodecError(f"{label} has {reader.remaining} trailing bytes")
    return reader, user_hash, client_id, client_port, tags, server_ip, server_port


def parse_hello(payload: bytes) -> Hello:
    """Parse an ``OP_HELLO`` payload into a :class:`Hello`."""
    try:
        _, user_hash, client_id, client_port, tags, _, _ = _parse_hello_body(
            payload, "OP_HELLO"
        )
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_HELLO: {exc}") from exc
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
    _write_hello_body(
        writer, user_hash, client_id, client_port, nickname, version,
        server_ip, server_port,
    )
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
    try:
        _, user_hash, client_id, client_port, tags, server_ip, server_port = (
            _parse_hello_body(payload, "OP_HELLOANSWER")
        )
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_HELLOANSWER: {exc}") from exc
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
    """Parse an ``OP_HASHSETANSWER`` payload into a :class:`HashSetAnswer`.

    Canonical form: [count u16][count x hash16] where hashes[0] is the
    file hash and the rest are part hashes.

    The eMuleAI 1.6.0 fork sends the layout INVERTED for single-part
    files: [file hash 16][count u16] (verified live 2026-09-26: an
    18-byte answer ``e4ba...a560000`` for a one-part file).  When the
    canonical parse does not fit, the inverted form is accepted and the
    trailing counter (0 or the hash count) is ignored.
    """
    def _canonical(data: bytes) -> list[bytes] | None:
        if len(data) < 2:
            return None
        (count,) = struct.unpack_from("<H", data, 0)
        if count > 0 and len(data) == 2 + _HASH16_SIZE * count:
            hashes = [data[2 + i * _HASH16_SIZE:2 + (i + 1) * _HASH16_SIZE]
                      for i in range(count)]
            return hashes
        return None

    hashes: list[bytes] | None = _canonical(payload)
    if hashes is None and len(payload) == _HASH16_SIZE + 2:
        # eMuleAI fork form: [file hash 16][count u16] (count ignored).
        hashes = [payload[:_HASH16_SIZE]]
        log.debug(
            "HASHSETANSWER: eMuleAI fork layout detected "
            "(hash first, trailing counter)"
        )
    if not hashes:
        raise PeerCodecError(
            f"malformed OP_HASHSETANSWER: length {len(payload)} fits no known layout"
        )
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
        # eMule pads unused REQUESTPARTS slots with (0, 0) and tolerates
        # start == end as an empty range (UploadDiskIOThread drops them);
        # only start > end is a protocol error.
        if start > end:
            raise PeerCodecError(f"start {start} must not exceed end {end}")


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
    # eMule pads unused slots with (0, 0); start == end is an empty range
    # and is dropped by the receiver (UploadDiskIOThread).  Only start > end
    # is a protocol error.
    for start, end in zip(starts, ends):
        if start > end:
            raise PeerCodecError(f"start {start} must not exceed end {end}")
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
    # eMule pads unused slots with (0, 0); start == end is an empty range
    # and is dropped by the receiver (UploadDiskIOThread).  Only start > end
    # is a protocol error.
    for start, end in zip(starts, ends):
        if start > end:
            raise PeerCodecError(f"start {start} must not exceed end {end}")
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


def parse_compressed_part_chunk(
    payload: bytes,
) -> tuple[bytes, int, int, bytes]:
    """Parse ONE sub-packet of a (possibly split) ``OP_COMPRESSEDPART``.

    Per UploadDiskIOThread.cpp ``CreatePackedPackets`` (507-557) a
    compressed block is split into sub-packets of at most 13000 bytes
    (10240 when more remains); EVERY sub-packet carries the BLOCK start
    offset and the TOTAL compressed size, plus only its own chunk.  The
    caller must concatenate chunks until ``len == total_size`` and only
    then zlib-decompress the whole.

    Returns ``(file_hash, start, total_compressed_size, chunk)``.
    """
    reader = BinaryReader(payload)
    try:
        file_hash = reader.read_hash16()
        start = reader.read_u32()
        total_size = reader.read_u32()
        chunk = reader.read_bytes(reader.remaining)
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_COMPRESSEDPART chunk: {exc}") from exc
    if not chunk:
        raise PeerCodecError("OP_COMPRESSEDPART chunk is empty")
    return file_hash, start, total_size, chunk


def parse_compressed_part_chunk_i64(
    payload: bytes,
) -> tuple[bytes, int, int, bytes]:
    """I64 variant of :func:`parse_compressed_part_chunk` (u64 start)."""
    reader = BinaryReader(payload)
    try:
        file_hash = reader.read_hash16()
        start = reader.read_u64()
        total_size = reader.read_u32()
        chunk = reader.read_bytes(reader.remaining)
    except CodecError as exc:
        raise PeerCodecError(f"malformed OP_COMPRESSEDPART_I64 chunk: {exc}") from exc
    if not chunk:
        raise PeerCodecError("OP_COMPRESSEDPART_I64 chunk is empty")
    return file_hash, start, total_size, chunk


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


def build_queue_rank_payload(rank: int) -> bytes:
    """Encode an ``OP_QUEUERANK`` payload (UInt32 rank)."""
    if not isinstance(rank, int) or isinstance(rank, bool):
        raise PeerCodecError(f"rank must be int: {rank}")
    if not 0 <= rank <= 0xFFFFFFFF:
        raise PeerCodecError(f"rank out of UInt32 range: {rank}")
    writer = BinaryWriter()
    writer.write_u32(rank)
    payload = writer.to_bytes()
    log.debug("QUEUERANK payload built: rank=%d, size=%d", rank, len(payload))
    return payload


def build_accept_upload_req_payload() -> bytes:
    """Encode an ``OP_ACCEPTUPLOADREQ`` payload (empty)."""
    payload = b""
    log.debug("ACCEPTUPLOADREQ payload built: size=%d", len(payload))
    return payload


def build_end_of_download_payload(file_hash: bytes) -> bytes:
    """Encode an ``OP_END_OF_DOWNLOAD`` payload (hash16)."""
    if len(file_hash) != _HASH16_SIZE:
        raise PeerCodecError("file hash must contain exactly 16 bytes")
    writer = BinaryWriter()
    writer.write_hash16(file_hash)
    payload = writer.to_bytes()
    log.debug("END_OF_DOWNLOAD payload built: hash=%s, size=%d", file_hash.hex().upper(), len(payload))
    return payload


def build_sending_part_i64_payload(
    file_hash: bytes,
    start: int,
    end: int,
    data: bytes,
) -> bytes:
    """Encode an ``OP_SENDINGPART_I64`` payload (hash16, u64 start/end, raw data)."""
    if len(file_hash) != _HASH16_SIZE:
        raise PeerCodecError("file hash must contain exactly 16 bytes")
    if not isinstance(start, int) or isinstance(start, bool):
        raise PeerCodecError(f"start must be int: {start}")
    if not isinstance(end, int) or isinstance(end, bool):
        raise PeerCodecError(f"end must be int: {end}")
    if not 0 <= start <= 0xFFFFFFFFFFFFFFFF:
        raise PeerCodecError(f"start out of UInt64 range: {start}")
    if not 0 <= end <= 0xFFFFFFFFFFFFFFFF:
        raise PeerCodecError(f"end out of UInt64 range: {end}")
    if start >= end:
        raise PeerCodecError(f"start {start} must be less than end {end}")
    if len(data) != end - start:
        raise PeerCodecError(
            f"OP_SENDINGPART_I64 data length {len(data)} != end-start {end - start}"
        )
    writer = BinaryWriter()
    writer.write_hash16(file_hash)
    writer.write_u64(start)
    writer.write_u64(end)
    writer.write_bytes(data)
    payload = writer.to_bytes()
    log.debug(
        "SENDINGPART_I64 payload built: hash=%s, start=%d, end=%d, data_size=%d, size=%d",
        file_hash.hex().upper(),
        start,
        end,
        len(data),
        len(payload),
    )
    return payload


def build_compressed_part_i64_payload(
    file_hash: bytes,
    start: int,
    data: bytes,
) -> bytes:
    """Encode an ``OP_COMPRESSEDPART_I64`` payload (zlib-compressed UInt64 start)."""
    if len(file_hash) != _HASH16_SIZE:
        raise PeerCodecError("file hash must contain exactly 16 bytes")
    if not isinstance(start, int) or isinstance(start, bool):
        raise PeerCodecError(f"start must be int: {start}")
    if not 0 <= start <= 0xFFFFFFFFFFFFFFFF:
        raise PeerCodecError(f"start out of UInt64 range: {start}")
    if not data:
        raise PeerCodecError("compressed part data must be non-empty")
    compressed_data = zlib.compress(data)
    writer = BinaryWriter()
    writer.write_hash16(file_hash)
    writer.write_u64(start)
    writer.write_u32(len(compressed_data))
    writer.write_bytes(compressed_data)
    payload = writer.to_bytes()
    log.debug(
        "COMPRESSEDPART_I64 payload built: hash=%s, start=%d, compressed=%d, data_size=%d, size=%d",
        file_hash.hex().upper(),
        start,
        len(compressed_data),
        len(data),
        len(payload),
    )
    return payload


def build_file_name_answer_payload(file_hash: bytes, name: str) -> bytes:
    """Encode an ``OP_REQFILENAMEANSWER`` payload (hash16 + UTF-8 string)."""
    if len(file_hash) != _HASH16_SIZE:
        raise PeerCodecError("file hash must contain exactly 16 bytes")
    writer = BinaryWriter()
    writer.write_hash16(file_hash)
    writer.write_string_utf8(name)
    payload = writer.to_bytes()
    log.debug("REQFILENAMEANSWER payload built: hash=%s, name=%r, size=%d", file_hash.hex().upper(), name, len(payload))
    return payload


def build_file_status_payload(
    file_hash: bytes,
    chunk_count: int,
    present_chunks: tuple[int, ...] | list[int],
) -> bytes:
    """Encode an ``OP_FILESTATUS`` payload (hash16, u16 chunk_count, bit array)."""
    if len(file_hash) != _HASH16_SIZE:
        raise PeerCodecError("file hash must contain exactly 16 bytes")
    if not isinstance(chunk_count, int) or isinstance(chunk_count, bool):
        raise PeerCodecError(f"chunk_count must be int: {chunk_count}")
    if not 0 <= chunk_count <= 0xFFFF:
        raise PeerCodecError(f"chunk_count out of UInt16 range: {chunk_count}")
    for index in present_chunks:
        if not isinstance(index, int) or isinstance(index, bool):
            raise PeerCodecError(f"present_chunks index must be int: {index}")
        if not 0 <= index < chunk_count:
            raise PeerCodecError(
                f"present_chunks index {index} out of range for chunk_count {chunk_count}"
            )
    bit_array = bytearray((chunk_count + 7) // 8)
    for index in present_chunks:
        byte_index = index // 8
        bit_index = index % 8
        bit_array[byte_index] |= 1 << bit_index
    writer = BinaryWriter()
    writer.write_hash16(file_hash)
    writer.write_u16(chunk_count)
    writer.write_bytes(bytes(bit_array))
    payload = writer.to_bytes()
    log.debug(
        "FILESTATUS payload built: hash=%s, chunk_count=%d, present=%d, size=%d",
        file_hash.hex().upper(),
        chunk_count,
        len(present_chunks),
        len(payload),
    )
    return payload


# ---------------------------------------------------------------------------
# SecureIdent payloads (stage X; Opcodes.h OP_SECIDENTSTATE/OP_PUBLICKEY/
# OP_SIGNATURE, protocol byte 0xC5)
# ---------------------------------------------------------------------------


def build_secident_state_payload(state: int, challenge: int) -> bytes:
    """OP_SECIDENTSTATE: [state u8][challenge u32 LE] (BaseClient.cpp:4907)."""
    return struct.pack("<BI", state & 0xFF, challenge & 0xFFFFFFFF)


def parse_secident_state_payload(payload: bytes) -> tuple[int, int]:
    """Parse OP_SECIDENTSTATE -> (state, challenge)."""
    if len(payload) != 5:
        raise PeerCodecError(
            f"malformed OP_SECIDENTSTATE: {len(payload)} bytes, expected 5"
        )
    state, challenge = struct.unpack("<BI", payload)
    return state, challenge


def build_publickey_payload(pubkey_blob: bytes) -> bytes:
    """OP_PUBLICKEY: [len u8][pubkey blob] (BaseClient.cpp:4732)."""
    if not 1 <= len(pubkey_blob) <= 250:
        raise PeerCodecError(
            f"public key blob length out of range: {len(pubkey_blob)}"
        )
    return bytes((len(pubkey_blob),)) + pubkey_blob


def parse_publickey_payload(payload: bytes) -> bytes:
    """Parse OP_PUBLICKEY -> pubkey blob (BaseClient.cpp:4801 sanity)."""
    if len(payload) < 10 or len(payload) > 250:
        raise PeerCodecError(f"malformed OP_PUBLICKEY: {len(payload)} bytes")
    blob_len = payload[0]
    if blob_len != len(payload) - 1:
        raise PeerCodecError(
            f"OP_PUBLICKEY length mismatch: declared={blob_len}, actual={len(payload) - 1}"
        )
    return payload[1:]


def build_signature_payload(signature: bytes, ip_kind: int = 0) -> bytes:
    """OP_SIGNATURE: v1 [len u8][sig]; v2 [len u8][sig][ipkind u8]."""
    if not 1 <= len(signature) <= 250:
        raise PeerCodecError(f"signature length out of range: {len(signature)}")
    payload = bytes((len(signature),)) + signature
    if ip_kind:
        payload += bytes((ip_kind & 0xFF,))
    return payload


def parse_signature_payload(payload: bytes) -> tuple[bytes, int]:
    """Parse OP_SIGNATURE -> (signature, ip_kind) (ip_kind 0 = v1)."""
    if len(payload) < 11 or len(payload) > 251:
        raise PeerCodecError(f"malformed OP_SIGNATURE: {len(payload)} bytes")
    sig_len = payload[0]
    if sig_len != len(payload) - 1 and sig_len != len(payload) - 2:
        raise PeerCodecError(
            f"OP_SIGNATURE length mismatch: declared={sig_len}, payload={len(payload)}"
        )
    signature = payload[1:1 + sig_len]
    ip_kind = payload[1 + sig_len] if len(payload) > 1 + sig_len else 0
    return signature, ip_kind


def miso1_secident_support(tags: tuple[Ed2kTag, ...]) -> int:
    """Extract the SUI support nibble (bits 16-19) from MISCOPTIONS1 tags.

    BaseClient.cpp:2041-2054: 0 = none, 3 = full SUI + v2 capable.
    """
    for tag in tags:
        if tag.name_id == 0xFA and isinstance(tag.value, int):
            return (int(tag.value) >> 16) & 0x0F
    return 0


# ---------------------------------------------------------------------------
# Source exchange payloads (stage X; Opcodes.h OP_REQUESTSOURCES(2)/
# OP_ANSWERSOURCES(2), protocol byte 0xC5).  Layout oracle: KnownFile.cpp
# CKnownFile::CreateSrcInfoPacket (1373-1526), PartFile.cpp:5015-5136,
# ListenSocket.cpp ProcessExtPacket (2265-2335).  CSafeMemFile writes
# native LE on x86; the SX2 v3 high-id id is the one exception — there the
# hybrid id is written WITHOUT the ntohl ("v3 high-id without htonl").
# ---------------------------------------------------------------------------

MAX_ANSWER_SOURCES = 500  # CreateSrcInfoPacket hard cap (KnownFile.cpp:1504)


@dataclass(frozen=True)
class SXSource:
    """One source entry for OP_ANSWERSOURCES(2).

    ``client_id`` is the classic ed2k high-id (a.b.c.d as a<<24|b<<16|c<<8|d,
    exactly as stored in our file_sources rows).  ``user_hash`` enables the
    obfuscated dial for v2+ entries.
    """

    client_id: int
    port: int
    server_ip: int = 0
    server_port: int = 0
    user_hash: bytes | None = None
    connect_options: int = 0


def parse_request_sources2(payload: bytes) -> tuple[int, int, bytes]:
    """OP_REQUESTSOURCES2: [ver u8][options u16 LE][hash 16] (ListenSocket.cpp:2285)."""
    if len(payload) != 19:
        raise PeerCodecError(
            f"malformed OP_REQUESTSOURCES2: {len(payload)} bytes, expected 19"
        )
    version, options = struct.unpack("<BH", payload[:3])
    return version, options, payload[3:19]


def parse_request_sources(payload: bytes) -> bytes:
    """Legacy OP_REQUESTSOURCES: [hash 16] only (ListenSocket.cpp:2298)."""
    if len(payload) != 16:
        raise PeerCodecError(
            f"malformed OP_REQUESTSOURCES: {len(payload)} bytes, expected 16"
        )
    return payload


def _sx_entry(source: SXSource, version: int) -> bytes:
    if version >= 3 and source.client_id >= 16_000_000:
        # SX2 v3+ high-id: hybrid id written without ntohl, so the wire
        # bytes are the dotted-order IP (PartFile.cpp:5099-5101).
        ident = struct.pack(">I", source.client_id & 0xFFFFFFFF)
    else:
        # v1/v2 (and any low id): id passed through htonl before the
        # native-LE WriteUInt32 -> wire bytes = LE of the ed2k client id.
        ident = struct.pack("<I", source.client_id & 0xFFFFFFFF)
    entry = ident + struct.pack("<H", source.port & 0xFFFF)
    entry += struct.pack("<IH", source.server_ip & 0xFFFFFFFF,
                         source.server_port & 0xFFFF)
    if version >= 2:
        entry += bytes(source.user_hash) if source.user_hash else b"\x00" * 16
    if version >= 4:
        entry += bytes((source.connect_options & 0xFF,))
    return entry


def build_answer_sources2(
    version: int, file_hash: bytes, sources: list[SXSource]
) -> bytes:
    """OP_ANSWERSOURCES2: [ver u8][hash 16][count u16 LE][entries]."""
    if len(file_hash) != 16:
        raise PeerCodecError("file hash must be 16 bytes")
    version = max(1, min(4, version))
    body = bytes((version,)) + file_hash
    body += struct.pack("<H", len(sources))
    for source in sources[:MAX_ANSWER_SOURCES]:
        body += _sx_entry(source, version)
    return body


def build_answer_sources(
    file_hash: bytes, sources: list[SXSource], entry_version: int = 1
) -> bytes:
    """Legacy OP_ANSWERSOURCES: [hash 16][count u16 LE][entries].

    No version byte on the wire (SX1); the entry tails still follow the
    peer's SX1 version (KnownFile.cpp: byUsedVersion =
    GetSourceExchange1Version()).
    """
    if len(file_hash) != 16:
        raise PeerCodecError("file hash must be 16 bytes")
    entry_version = max(1, min(4, entry_version))
    body = file_hash + struct.pack("<H", len(sources))
    for source in sources[:MAX_ANSWER_SOURCES]:
        body += _sx_entry(source, entry_version)
    return body


def miso1_source_exchange(tags: tuple[Ed2kTag, ...]) -> int:
    """SX1 version nibble (bits 12-15) of MISCOPTIONS1 (BaseClient.cpp)."""
    for tag in tags:
        if tag.name_id == 0xFA and isinstance(tag.value, int):
            return (int(tag.value) >> 12) & 0x0F
    return 0


def build_request_sources2_payload(
    version: int, options: int, file_hash: bytes
) -> bytes:
    """OP_REQUESTSOURCES2: [ver u8][options u16 LE][hash 16]."""
    if len(file_hash) != 16:
        raise PeerCodecError("file hash must be 16 bytes")
    return struct.pack("<BH", version & 0xFF, options & 0xFFFF) + file_hash


def build_request_sources_payload(file_hash: bytes) -> bytes:
    """Legacy OP_REQUESTSOURCES: [hash 16]."""
    if len(file_hash) != 16:
        raise PeerCodecError("file hash must be 16 bytes")
    return file_hash


def _parse_sx_entry(
    payload: bytes, offset: int, version: int
) -> tuple[SXSource, int]:
    if version >= 3:
        (client_id,) = struct.unpack(">I", payload[offset:offset + 4])
    else:
        (client_id,) = struct.unpack("<I", payload[offset:offset + 4])
    port = struct.unpack("<H", payload[offset + 4:offset + 6])[0]
    server_ip = struct.unpack("<I", payload[offset + 6:offset + 10])[0]
    server_port = struct.unpack("<H", payload[offset + 10:offset + 12])[0]
    offset += 12
    user_hash = None
    connect_options = 0
    if version >= 2:
        user_hash = payload[offset:offset + 16]
        offset += 16
    if version >= 4:
        connect_options = payload[offset]
        offset += 1
    return (
        SXSource(
            client_id=client_id,
            port=port,
            server_ip=server_ip,
            server_port=server_port,
            user_hash=user_hash,
            connect_options=connect_options,
        ),
        offset,
    )


def parse_answer_sources2(payload: bytes) -> tuple[int, bytes, list[SXSource]]:
    """OP_ANSWERSOURCES2 -> (version, file_hash, entries)."""
    if len(payload) < 19:
        raise PeerCodecError(
            f"malformed OP_ANSWERSOURCES2: {len(payload)} bytes"
        )
    version = payload[0]
    file_hash = payload[1:17]
    (count,) = struct.unpack("<H", payload[17:19])
    sources: list[SXSource] = []
    offset = 19
    for _ in range(count):
        source, offset = _parse_sx_entry(payload, offset, version)
        sources.append(source)
    return version, file_hash, sources


def parse_answer_sources(
    payload: bytes, version: int
) -> tuple[int, bytes, list[SXSource]]:
    """Legacy OP_ANSWERSOURCES -> (entry_version, file_hash, entries).

    SX1 carries no version byte; the caller supplies the entry version the
    writer used (the peer's SX1 version).
    """
    if len(payload) < 18:
        raise PeerCodecError(
            f"malformed OP_ANSWERSOURCES: {len(payload)} bytes"
        )
    file_hash = payload[:16]
    (count,) = struct.unpack("<H", payload[16:18])
    sources: list[SXSource] = []
    offset = 18
    for _ in range(count):
        source, offset = _parse_sx_entry(payload, offset, version)
        sources.append(source)
    return version, file_hash, sources


# ---------------------------------------------------------------------------
# AICH payloads (stage X; Opcodes.h OP_AICHREQUEST 0x9B / OP_AICHANSWER 0x9C,
# protocol byte 0xC5).  Request: [hash 16][part u16][master 20].  Answer:
# the same 38-byte header followed by the recovery data blob (see
# aich.aich_part_recovery_data; SHAHashSet.cpp:766-771).
# ---------------------------------------------------------------------------


def build_aich_request_payload(file_hash: bytes, part: int, master: bytes) -> bytes:
    if len(file_hash) != 16 or len(master) != 20:
        raise PeerCodecError("AICH request needs hash16 and master20")
    return file_hash + struct.pack("<H", part & 0xFFFF) + master


def parse_aich_request_payload(payload: bytes) -> tuple[bytes, int, bytes]:
    if len(payload) != 38:
        raise PeerCodecError(
            f"malformed OP_AICHREQUEST: {len(payload)} bytes, expected 38"
        )
    return payload[:16], struct.unpack("<H", payload[16:18])[0], payload[18:38]


def build_aich_answer_payload(
    file_hash: bytes, part: int, master: bytes, recovery: bytes
) -> bytes:
    return build_aich_request_payload(file_hash, part, master) + recovery


def parse_aich_answer_payload(payload: bytes) -> tuple[bytes, int, bytes, bytes]:
    """OP_AICHANSWER -> (hash, part, master, recovery data)."""
    if len(payload) < 38:
        raise PeerCodecError(
            f"malformed OP_AICHANSWER: {len(payload)} bytes, expected >= 38"
        )
    return payload[:16], struct.unpack("<H", payload[16:18])[0], payload[18:38], payload[38:]
