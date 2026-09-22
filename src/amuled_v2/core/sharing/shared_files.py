"""Shared-file import, directory scanning, ED2K hashing, and link generation.

Implements the sharing persistence behavior described by
``docs/PROTOCOL_MATRIX.md``, section 7.4.  The module imports the v1 wrapper's
``shared_files.json`` metadata and ``shareddir.dat`` directory list, scans and
hashes native shared files with the ED2K hash layer, and emits compatible
``ed2k://|file|...`` links.

src/amuled_v2/core/sharing/shared_files.py
Version:     0.1.1
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.1 (Soror L.'.L'.):
  [+] Added tagged SHARE diagnostics for metadata imports, directory scans,
      per-file hashing, and final scan counts.
  [+] Added SharedFile metadata model and strict ED2K hash validation.
  [+] Added v1 shared_files.json and shareddir.dat importers.
  [+] Added deterministic directory scanning and ED2K hashing pipeline.
  [+] Added base and part-hash ED2K link generation.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from amuled_v2.core.hashes import Ed2kHashResult, ed2k_hash_file
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.SHARE, "core.sharing.shared_files")

__all__ = [
    "SharingError",
    "SharedFile",
    "load_shared_files_json",
    "load_shareddir_dat",
    "scan_shared_directory",
    "scan_shared_directories",
    "generate_ed2k_link",
]

_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
_SIZE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgtp]?i?b?)\s*$", re.I)
_SIZE_MULTIPLIERS = {
    "": 1,
    "b": 1,
    "k": 1_000,
    "kb": 1_000,
    "m": 1_000_000,
    "mb": 1_000_000,
    "g": 1_000_000_000,
    "gb": 1_000_000_000,
    "t": 1_000_000_000_000,
    "tb": 1_000_000_000_000,
    "ki": 1_024,
    "kib": 1_024,
    "mi": 1_024**2,
    "mib": 1_024**2,
    "gi": 1_024**3,
    "gib": 1_024**3,
    "ti": 1_024**4,
    "tib": 1_024**4,
}


class SharingError(ValueError):
    """Raised when shared-file metadata cannot be imported or generated."""


@dataclass
class SharedFile:
    """Metadata for one shared file."""

    file_hash: bytes
    name: str
    size: int
    path: str | None = None
    priority: int = 1
    hash_result: Ed2kHashResult | None = None
    imported: bool = False

    def __post_init__(self) -> None:
        if len(self.file_hash) != 16:
            raise SharingError("ED2K file hash must contain exactly 16 bytes")
        if self.size < 0:
            raise SharingError("shared file size cannot be negative")

    @property
    def hash_hex(self) -> str:
        return self.file_hash.hex().upper()


def _parse_priority(raw: object) -> int:
    text = str(raw or "").strip().lower()
    if text.startswith("low"):
        return 0
    if text.startswith("high"):
        return 2
    return 1


def _parse_display_size(raw: object) -> int:
    if isinstance(raw, int) and raw >= 0:
        return raw
    if isinstance(raw, float) and raw >= 0 and raw.is_integer():
        return int(raw)
    match = _SIZE_RE.match(str(raw or ""))
    if not match:
        raise SharingError(f"invalid shared-file size: {raw!r}")
    number_text, unit = match.groups()
    multiplier = _SIZE_MULTIPLIERS.get(unit.lower())
    if multiplier is None:
        raise SharingError(f"unknown shared-file size unit: {unit!r}")
    return int(float(number_text) * multiplier)


def _decode_hash(raw: object) -> bytes:
    if isinstance(raw, (bytes, bytearray)):
        value = bytes(raw)
    else:
        value = bytes.fromhex(str(raw))
    if len(value) != 16:
        raise SharingError("ED2K file hash must contain exactly 32 hexadecimal digits")
    return value


def load_shared_files_json(path: str | Path) -> list[SharedFile]:
    """Import metadata produced by the v1 web wrapper."""
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        log.error(f"Cannot read shared_files.json: {path} ({exc})")
        raise SharingError(f"cannot read shared_files.json: {exc}") from exc
    if not isinstance(payload, list):
        raise SharingError("shared_files.json must contain a JSON array")

    imported: list[SharedFile] = []
    seen: set[bytes] = set()
    for index, item in enumerate(payload, 1):
        if not isinstance(item, dict):
            continue
        try:
            file_hash = _decode_hash(item.get("hash"))
        except (ValueError, TypeError) as exc:
            raise SharingError(f"invalid shared file at index {index}: {exc}") from exc
        if file_hash in seen:
            continue
        seen.add(file_hash)
        imported.append(
            SharedFile(
                file_hash=file_hash,
                name=str(item.get("name") or f"shared-{file_hash.hex()}"),
                size=_parse_display_size(item.get("size", 0)),
                path=item.get("path"),
                priority=_parse_priority(item.get("priority")),
                imported=True,
            )
        )
    log.info(f"Loaded shared metadata: path={path}, files={len(imported)}")
    return imported


def load_shareddir_dat(path: str | Path) -> list[Path]:
    """Import one path per non-empty line from v1 ``shareddir.dat``."""
    source = Path(path)
    try:
        lines = source.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError) as exc:
        log.error(f"Cannot read shareddir.dat: {path} ({exc})")
        raise SharingError(f"cannot read shareddir.dat: {exc}") from exc
    directories: list[Path] = []
    seen: set[str] = set()
    for line in lines:
        value = line.strip()
        if not value:
            continue
        resolved = str(Path(value))
        if resolved.lower() in seen:
            continue
        seen.add(resolved.lower())
        directories.append(Path(resolved))
    log.info(f"Loaded shared directories: path={path}, directories={len(directories)}")
    return directories


def scan_shared_directory(
    directory: str | Path,
    *,
    recursive: bool = True,
) -> list[SharedFile]:
    """Scan and ED2K-hash all regular files below *directory*."""
    root = Path(directory)
    if not root.is_dir():
        raise SharingError(f"shared directory does not exist: {root}")
    iterator = root.rglob("*") if recursive else root.glob("*")
    shared: list[SharedFile] = []
    for path in sorted(iterator, key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        result = ed2k_hash_file(str(path))
        log.debug(f"Hashed shared file: path={path}, size={result.file_size}")
        shared.append(
            SharedFile(
                file_hash=result.file_hash,
                name=path.name,
                size=result.file_size,
                path=str(path.resolve()),
                hash_result=result,
            )
        )
    return shared


def scan_shared_directories(directories: Iterable[str | Path]) -> list[SharedFile]:
    """Scan multiple roots and deduplicate files by ED2K hash and size."""
    result: dict[tuple[bytes, int], SharedFile] = {}
    roots = [Path(directory) for directory in directories]
    for directory in roots:
        for item in scan_shared_directory(directory):
            result.setdefault((item.file_hash, item.size), item)
    files = list(result.values())
    log.info(f"Scan completed: roots={len(roots)}, files={len(files)}")
    return files


def generate_ed2k_link(file: SharedFile, *, include_part_hashes: bool = False) -> str:
    """Generate an ED2K file link from shared metadata."""
    encoded_name = file.name.replace("|", "%7C")
    link = f"ed2k://|file|{encoded_name}|{file.size}|{file.hash_hex}|"
    if include_part_hashes:
        if file.hash_result is None or not file.hash_result.chunk_hashes:
            raise SharingError("part hashes require an ED2K hash result")
        part_hashes = file.hash_result.chunk_hashes[:-1]
        if part_hashes:
            link += "p=" + ":".join(value.hex().upper() for value in part_hashes) + "|"
    link += "/"
    return link
