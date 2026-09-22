"""ED2K server-list models, ``server.met`` parsing, and static-server import.

This module implements the persistence layer described by
``docs/PROTOCOL_MATRIX.md``, section 10.  It accepts a version byte of ``0xE0``
followed by a UInt32 server count.  Each server record contains a UInt32 IPv4
address, UInt16 TCP port, UInt32 tag count, and new-format ED2K tags.

src/amuled_v2/core/ed2k/server_met.py
Version:     0.1.1
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.1 (Soror L.'.L'.):
  [+] Added tagged SERVER diagnostics for list loading and import counts.
  [+] Added ServerRecord, ServerMet parsing, address formatting, and tag access.
  [+] Added staticservers.dat parsing and deterministic list merge behavior.
  [+] Added bounded parsing with explicit ServerMetError diagnostics.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from amuled_v2.core.codec.binary import BinaryReader, CodecError
from amuled_v2.core.codec.tags import Ed2kTag, TagError, read_new_tag
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.SERVER, "core.ed2k.server_met")

__all__ = [
    "SERVER_MET_VERSION",
    "ServerMetError",
    "ServerRecord",
    "load_server_met",
    "parse_server_met",
    "StaticServer",
    "load_static_servers",
    "merge_server_lists",
]

SERVER_MET_VERSION = 0xE0


class ServerMetError(ValueError):
    """Raised when a server list cannot be parsed."""


def _tag_id(tag: Ed2kTag) -> Optional[int]:
    return tag.name_id


def _tag_text(tag: Ed2kTag) -> str:
    return tag.value if isinstance(tag.value, str) else ""


def _tag_int(tag: Ed2kTag) -> int:
    return tag.value if isinstance(tag.value, int) and not isinstance(tag.value, bool) else 0


@dataclass
class ServerRecord:
    """One parsed ED2K server record."""

    ip: int
    port: int
    tags: list[Ed2kTag] = field(default_factory=list)
    static: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.ip <= 0xFFFFFFFF:
            raise ServerMetError(f"server IP out of UInt32 range: {self.ip}")
        if not 0 <= self.port <= 0xFFFF:
            raise ServerMetError(f"server port out of UInt16 range: {self.port}")

    @property
    def address(self) -> str:
        return str(ipaddress.IPv4Address(self.ip))

    @property
    def endpoint(self) -> str:
        return f"{self.address}:{self.port}"

    @property
    def name(self) -> str:
        for tag in self.tags:
            if _tag_id(tag) == 0x01:
                return _tag_text(tag)
        return f"Server {self.endpoint}"

    @property
    def description(self) -> str:
        for tag in self.tags:
            if _tag_id(tag) == 0x0B:
                return _tag_text(tag)
        return ""

    @property
    def priority(self) -> int:
        for tag in self.tags:
            if _tag_id(tag) == 0x0E:
                value = _tag_int(tag)
                return value if 0 <= value <= 2 else 0
        return 0

    @property
    def version(self) -> str:
        for tag in self.tags:
            if _tag_id(tag) == 0x91:
                return _tag_text(tag)
        return ""

    @property
    def users(self) -> int:
        for tag in self.tags:
            if tag.name == "users":
                return _tag_int(tag)
        return 0

    @property
    def files(self) -> int:
        for tag in self.tags:
            if tag.name == "files":
                return _tag_int(tag)
        return 0

    @property
    def aux_ports(self) -> str:
        for tag in self.tags:
            if _tag_id(tag) == 0x93:
                return _tag_text(tag)
        return ""

    @property
    def key(self) -> tuple[int, int]:
        return self.ip, self.port


def parse_server_met(data: bytes) -> list[ServerRecord]:
    """Parse an uncompressed ``server.met`` byte image."""
    reader = BinaryReader(data)
    try:
        version = reader.read_u8()
        if version != SERVER_MET_VERSION:
            raise ServerMetError(f"unsupported server.met version: 0x{version:02X}")
        count = reader.read_u32()
        records: list[ServerRecord] = []
        for _ in range(count):
            ip = reader.read_u32()
            port = reader.read_u16()
            tag_count = reader.read_u32()
            tags: list[Ed2kTag] = []
            for _ in range(tag_count):
                tags.append(read_new_tag(reader))
            records.append(ServerRecord(ip=ip, port=port, tags=tags))
        if reader.remaining:
            raise ServerMetError(f"{reader.remaining} unexpected trailing bytes")
        return records
    except (CodecError, TagError) as exc:
        raise ServerMetError(f"malformed server.met: {exc}") from exc


def load_server_met(path: str | Path) -> list[ServerRecord]:
    """Load and parse *path* as an uncompressed ``server.met``."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        log.error(f"Cannot read server.met: {path} ({exc})")
        raise ServerMetError(f"cannot read server.met: {exc}") from exc
    records = parse_server_met(data)
    log.info(f"Loaded server.met: path={path}, servers={len(records)}")
    return records


@dataclass(frozen=True)
class StaticServer:
    """One static server imported from text format."""

    host: str
    port: int
    name: str
    priority: int = 0
    static: bool = True


def load_static_servers(path: str | Path) -> list[StaticServer]:
    """Parse ``staticservers.dat`` lines: ``host:port,priority,name``."""
    result: list[StaticServer] = []
    try:
        lines = Path(path).read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError) as exc:
        log.error(f"Cannot read static server list: {path} ({exc})")
        raise ServerMetError(f"cannot read static server list: {exc}") from exc

    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("/"):
            continue
        pieces = [piece.strip() for piece in line.split(",")]
        if len(pieces) != 3:
            continue
        endpoint, priority_raw, name = pieces
        if ":" not in endpoint:
            continue
        host, port_raw = endpoint.split(":", 1)
        try:
            port = int(port_raw)
            priority = int(priority_raw)
        except ValueError:
            continue
        if not 0 <= port <= 0xFFFF:
            continue
        if not 0 <= priority <= 2:
            priority = 0
        result.append(
            StaticServer(
                host=host,
                port=port,
                name=name or endpoint,
                priority=priority,
                static=True,
            )
        )
    log.info(f"Loaded static server list: path={path}, servers={len(result)}")
    return result


def merge_server_lists(
    primary: Iterable[ServerRecord],
    secondary: Iterable[ServerRecord],
) -> list[ServerRecord]:
    """Merge records by IP/port, preserving primary metadata on duplicates."""
    merged: dict[tuple[int, int], ServerRecord] = {}
    for record in primary:
        merged.setdefault(record.key, record)
    for record in secondary:
        merged.setdefault(record.key, record)
    return list(merged.values())
