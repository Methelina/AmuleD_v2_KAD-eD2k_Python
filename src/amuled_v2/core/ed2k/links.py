"""ED2K link parsing and generation.

src/amuled_v2/core/ed2k/links.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added strict real ED2K file-link parsing and generation.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote

__all__ = ["Ed2kFileLink", "Ed2kLinkError", "parse_ed2k_file_link", "build_ed2k_file_link"]


class Ed2kLinkError(ValueError):
    """Raised when an ED2K file link is malformed."""


@dataclass(frozen=True)
class Ed2kFileLink:
    """Parsed fields from an ``ed2k://|file|...`` link."""

    name: str
    size: int
    file_hash: bytes

    @property
    def hash_hex(self) -> str:
        return self.file_hash.hex().upper()

    def to_link(self) -> str:
        return build_ed2k_file_link(self.name, self.size, self.file_hash)


def build_ed2k_file_link(name: str, size: int, file_hash: bytes) -> str:
    if not name:
        raise Ed2kLinkError("ED2K file name cannot be empty")
    if size < 0:
        raise Ed2kLinkError("ED2K file size cannot be negative")
    if len(file_hash) != 16:
        raise Ed2kLinkError("ED2K file hash must contain exactly 16 bytes")
    safe_name = name.replace("|", "%7C")
    return f"ed2k://|file|{safe_name}|{size}|{file_hash.hex().upper()}|/"


def parse_ed2k_file_link(link: str) -> Ed2kFileLink:
    """Parse a real ``ed2k://|file|name|size|hash|/`` link."""
    value = link.strip()
    if not value.lower().startswith("ed2k://|file|"):
        raise Ed2kLinkError("not an ed2k file link")
    body = value[len("ed2k://|file|") :]
    fields = body.split("|")
    if len(fields) < 3:
        raise Ed2kLinkError("ed2k file link must contain name, size, and hash fields")
    encoded_name, size_text, hash_text = fields[:3]
    if not encoded_name or not size_text or not hash_text:
        raise Ed2kLinkError("ed2k file link has an empty field")
    try:
        size = int(size_text)
    except ValueError as exc:
        raise Ed2kLinkError(f"invalid ED2K file size: {size_text}") from exc
    if size < 0:
        raise Ed2kLinkError("ED2K file size cannot be negative")
    if len(hash_text) != 32:
        raise Ed2kLinkError("ED2K file hash must contain 32 hexadecimal digits")
    try:
        file_hash = bytes.fromhex(hash_text)
    except ValueError as exc:
        raise Ed2kLinkError(f"invalid ED2K file hash: {hash_text}") from exc
    name = unquote(encoded_name)
    if not name:
        raise Ed2kLinkError("ED2K file name cannot be empty")
    return Ed2kFileLink(name=name, size=size, file_hash=file_hash)
