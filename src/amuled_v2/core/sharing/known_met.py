"""eMule known.met import/export (stage X).

Format per eMuleAI KnownFileList.cpp::Load and
CKnownFile::LoadFromFile / WriteToFile:

    [u8  header 0x0E|0x0F][u32 record count]
    record:
      [u32 last_modified]
      [16 file MD4]
      [u16 part-hash count (self hash NOT counted)][16 * count part MD4s]
      [u32 tag count][tags]

Tag encoding (validated against a real eMuleAI known.met — the value-type
byte stays RAW in the switch; a 0x80 flag on it switches to a compact u8
name-id, otherwise a u16 length + name follows):

    type u8; name = u8 0x80|name_id (compact)
    or u16 length + utf-8 name; value per type (0x01 hash16, 0x02 string
    with u16 length, 0x03 uint32, 0x04 float32, 0x08 uint16, 0x09 uint8,
    0x0A bsob, 0x0B uint64, 0x11..0x30 fixed-length string, 0x07 blob u32).
    eMule itself writes FT tags non-compact: type 0x02/0x03, name
    = u16 length 1 + the byte 0x01/0x02.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.SHARE, "core.sharing.known_met")

__all__ = ["KnownMetEntry", "KnownMetError", "parse_known_met", "write_known_met"]

FT_FILENAME = 0x01
FT_FILESIZE = 0x02
FT_LASTMODIFIED = 0x03

_TAG_STRING = 0x02
_TAG_UINT32 = 0x03


class KnownMetError(ValueError):
    """Raised when a known.met file violates the expected format."""


@dataclass
class KnownMetEntry:
    """One record of a known.met file."""

    file_hash: str
    name: str
    size: int
    last_modified: int = 0
    part_hashes: list[str] = field(default_factory=list)
    extra_tags: list[tuple[int, int, object]] = field(default_factory=list)


def _read_tags(data: bytes, pos: int, tag_count: int) -> tuple[dict[str, object], int]:
    tags: dict[str, object] = {}
    for _ in range(tag_count):
        tag_type = data[pos]
        pos += 1
        if tag_type & 0x80:
            name_id = data[pos]
            pos += 1
            name = f"#{name_id:02x}"
        else:
            (name_len,) = struct.unpack_from("<H", data, pos)
            pos += 2
            name = data[pos:pos + name_len].decode("utf-8", "replace")
            pos += name_len
        # The value-type switch uses the RAW first byte (validated layout).
        if tag_type in (0x01, 0x81):  # hash16
            value = data[pos:pos + 16]
            pos += 16
        elif tag_type in (0x02, 0x82):  # string, u16 length
            (ln,) = struct.unpack_from("<H", data, pos)
            pos += 2
            value = data[pos:pos + ln].decode("utf-8", "replace")
            pos += ln
        elif 0x11 <= (tag_type & 0x7F) <= 0x30:  # fixed-length string
            ln = (tag_type & 0x7F) - 0x10
            value = data[pos:pos + ln].decode("utf-8", "replace")
            pos += ln
        elif tag_type in (0x08, 0x88):  # uint16
            (value,) = struct.unpack_from("<H", data, pos)
            pos += 2
        elif tag_type in (0x09, 0x89):  # uint8
            value = data[pos]
            pos += 1
        elif tag_type in (0x0A, 0x8A):  # bsob
            (ln,) = struct.unpack_from("<H", data, pos)
            pos += 2
            value = data[pos:pos + ln]
            pos += ln
        elif tag_type in (0x0B, 0x8B):  # uint64
            (value,) = struct.unpack_from("<Q", data, pos)
            pos += 8
        elif tag_type in (0x03, 0x83):  # uint32
            (value,) = struct.unpack_from("<I", data, pos)
            pos += 4
        elif tag_type in (0x04, 0x84):  # float32
            (value,) = struct.unpack_from("<f", data, pos)
            pos += 4
        elif tag_type in (0x07, 0x87):  # blob
            (ln,) = struct.unpack_from("<I", data, pos)
            pos += 4
            value = data[pos:pos + ln]
            pos += ln
        else:
            raise KnownMetError(
                f"unknown tag type 0x{tag_type:02x} at offset {pos - 1}"
            )
        tags[name] = value
    return tags, pos


def parse_known_met(path: str | Path) -> list[KnownMetEntry]:
    """Parse an eMule known.met file into entries."""
    data = Path(path).read_bytes()
    if not data or data[0] not in (0x0E, 0x0F):
        raise KnownMetError(
            f"bad known.met header: 0x{data[0]:02x}" if data else "empty file"
        )
    (count,) = struct.unpack_from("<I", data, 1)
    pos = 5
    entries: list[KnownMetEntry] = []
    for _ in range(count):
        (date,) = struct.unpack_from("<I", data, pos)
        pos += 4
        # CFileIdentifier::LoadMD4HashsetFromFile: the file hash comes
        # FIRST, then the u16 count of ADDITIONAL part hashes.
        file_hash = data[pos:pos + 16]
        pos += 16
        (part_count,) = struct.unpack_from("<H", data, pos)
        pos += 2
        part_hashes = []
        for _ in range(part_count):
            part_hashes.append(data[pos:pos + 16].hex().upper())
            pos += 16
        (tag_count,) = struct.unpack_from("<I", data, pos)
        pos += 4
        tags, pos = _read_tags(data, pos, tag_count)
        name = tags.get("\x01") or tags.get("#01") or ""
        size = tags.get("\x02", tags.get("#02", -1))
        entries.append(
            KnownMetEntry(
                file_hash=file_hash.hex().upper(),
                name=str(name) if name is not None else "",
                size=int(size) if isinstance(size, int) else -1,
                last_modified=int(date),
                part_hashes=part_hashes,
            )
        )
    log.info(
        "known.met parsed: path=%s, entries=%d", path, len(entries)
    )
    return entries


def write_known_met(
    path: str | Path,
    entries: list[KnownMetEntry],
    *,
    last_modified: int | None = None,
) -> int:
    """Write a valid known.met file; returns the record count."""
    if last_modified is None:
        last_modified = int(time.time())
    out = bytearray()
    out.append(0x0F)
    out += struct.pack("<I", len(entries))
    for entry in entries:
        out += struct.pack("<I", int(entry.last_modified or last_modified))
        out += bytes.fromhex(entry.file_hash)
        out += struct.pack("<H", len(entry.part_hashes))
        for part in entry.part_hashes:
            out += bytes.fromhex(part)
        tags = bytearray()
        name_bytes = entry.name.encode("utf-8")
        # FT_FILENAME — eMule's own non-compact layout: type 0x02, name =
        # u16 length 1 + byte 0x01.
        tags.append(_TAG_STRING)
        tags += struct.pack("<H", 1)
        tags.append(FT_FILENAME)
        tags += struct.pack("<H", len(name_bytes))
        tags += name_bytes
        # FT_FILESIZE — type 0x03, name = u16 length 1 + byte 0x02.
        tags.append(_TAG_UINT32)
        tags += struct.pack("<H", 1)
        tags.append(FT_FILESIZE)
        tags += struct.pack("<I", entry.size & 0xFFFFFFFF)
        out += struct.pack("<I", 2)
        out += tags
    Path(path).write_bytes(bytes(out))
    log.info(
        "known.met written: path=%s, entries=%d", path, len(entries)
    )
    return len(entries)
