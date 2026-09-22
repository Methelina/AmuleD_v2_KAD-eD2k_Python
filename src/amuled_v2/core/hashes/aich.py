"""SHA1 and AICH hash-tree primitives for ED2K recovery metadata.

AICH is a binary SHA-1 Merkle tree over fixed 184,320-byte blocks.  Segment
splitting follows the wire-visible invariant: a non-leaf segment is split by
its base size, with the left branch receiving the odd block when the branch is
itself a left child.  This module provides whole-file master hashes, ordered
leaf hashes, verification, and tagged diagnostics without network access.

src/amuled_v2/core/hashes/aich.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added SHA1 helpers and streaming AICH master/leaf computation.
  [+] Added exact odd-block left/right segment splitting.
  [+] Added AichHashResult, verification, and tagged HASH diagnostics.
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from amuled_v2.core.codec.constants import BLOCKSIZE, PARTSIZE
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.HASH, "core.hashes.aich")

__all__ = [
    "AichError",
    "AichHashResult",
    "sha1_digest",
    "sha1_file",
    "aich_hash_data",
    "aich_hash_file",
    "aich_verify_data",
    "aich_verify_file",
]

_AICH_HASH_SIZE = 20


class AichError(ValueError):
    """Raised when an AICH tree cannot be computed or verified."""


@dataclass(frozen=True)
class AichHashResult:
    """Computed AICH metadata for one immutable file image."""

    file_size: int
    master_hash: bytes
    block_hashes: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if self.file_size < 0:
            raise AichError("file size cannot be negative")
        if len(self.master_hash) != _AICH_HASH_SIZE:
            raise AichError("AICH master hash must contain 20 bytes")
        for index, block_hash in enumerate(self.block_hashes):
            if len(block_hash) != _AICH_HASH_SIZE:
                raise AichError(
                    f"AICH block hash {index} must contain 20 bytes, got {len(block_hash)}"
                )


def sha1_digest(data: bytes) -> bytes:
    """Return the 20-byte SHA-1 digest of *data*."""
    return hashlib.sha1(data).digest()


def sha1_file(path: str | Path) -> bytes:
    """Return the SHA-1 digest of a file using bounded streaming reads."""
    digest = hashlib.sha1()
    try:
        with open(path, "rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        log.error(f"Cannot hash file with SHA1: path={path}, error={exc}")
        raise AichError(f"cannot hash file: {exc}") from exc
    return digest.digest()


def _read_segment(handle: BinaryIO, start: int, size: int) -> bytes:
    handle.seek(start)
    data = handle.read(size)
    if len(data) != size:
        raise AichError(
            f"unexpected end of AICH input: start={start}, expected={size}, got={len(data)}"
        )
    return data


def _hash_aich_segment(
    handle: BinaryIO,
    start: int,
    size: int,
    is_left_branch: bool,
    leaves: list[bytes] | None,
) -> bytes:
    """Compute one balanced AICH segment and optionally collect its leaves."""
    if size < 0:
        raise AichError("AICH segment size cannot be negative")
    if size == 0:
        return sha1_digest(b"")

    if size <= BLOCKSIZE:
        digest = sha1_digest(_read_segment(handle, start, size))
        if leaves is not None:
            leaves.append(digest)
        return digest

    base_size = BLOCKSIZE if size <= PARTSIZE else PARTSIZE
    block_count = (size + base_size - 1) // base_size
    left_block_count = (
        (block_count + 1) // 2 if is_left_branch else block_count // 2
    )
    left_size = left_block_count * base_size
    if left_size >= size:
        # The reference invariant keeps at least one block in each branch.
        left_size = (block_count // 2) * base_size
    right_size = size - left_size
    if left_size <= 0 or right_size <= 0:
        raise AichError(
            f"invalid AICH split: size={size}, base={base_size}, "
            f"left={left_size}, right={right_size}"
        )

    left_hash = _hash_aich_segment(handle, start, left_size, True, leaves)
    right_hash = _hash_aich_segment(
        handle,
        start + left_size,
        right_size,
        False,
        leaves,
    )
    return sha1_digest(left_hash + right_hash)


def aich_hash_data(data: bytes) -> AichHashResult:
    """Compute AICH metadata for an in-memory file image."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise AichError("AICH input must be bytes-like")
    payload = bytes(data)
    leaves: list[bytes] = []
    with io.BytesIO(payload) as handle:
        master = _hash_aich_segment(handle, 0, len(payload), True, leaves)
    result = AichHashResult(
        file_size=len(payload),
        master_hash=master,
        block_hashes=tuple(leaves),
    )
    log.debug(
        f"AICH data computed: size={result.file_size}, blocks={len(result.block_hashes)}"
    )
    return result


def aich_hash_file(path: str | Path) -> AichHashResult:
    """Compute AICH metadata for a file without loading it into memory."""
    source = Path(path)
    try:
        file_size = source.stat().st_size
    except OSError as exc:
        log.error(f"Cannot stat AICH input: path={source}, error={exc}")
        raise AichError(f"cannot stat AICH input: {exc}") from exc

    leaves: list[bytes] = []
    try:
        with open(source, "rb") as handle:
            master = _hash_aich_segment(handle, 0, file_size, True, leaves)
    except OSError as exc:
        log.error(f"Cannot hash AICH file: path={source}, error={exc}")
        raise AichError(f"cannot hash AICH file: {exc}") from exc

    result = AichHashResult(
        file_size=file_size,
        master_hash=master,
        block_hashes=tuple(leaves),
    )
    log.info(
        f"AICH file computed: path={source}, size={result.file_size}, "
        f"blocks={len(result.block_hashes)}"
    )
    return result


def aich_verify_data(data: bytes, expected_master_hash: bytes) -> bool:
    """Return whether *data* matches an expected AICH master hash."""
    if len(expected_master_hash) != _AICH_HASH_SIZE:
        raise AichError("expected AICH master hash must contain 20 bytes")
    return aich_hash_data(data).master_hash == bytes(expected_master_hash)


def aich_verify_file(path: str | Path, expected_master_hash: bytes) -> bool:
    """Return whether a file matches an expected AICH master hash."""
    if len(expected_master_hash) != _AICH_HASH_SIZE:
        raise AichError("expected AICH master hash must contain 20 bytes")
    return aich_hash_file(path).master_hash == bytes(expected_master_hash)
