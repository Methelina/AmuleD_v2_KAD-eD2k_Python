"""SHA1 and AICH hash-tree primitives for ED2K recovery metadata.

AICH is a binary SHA-1 Merkle tree over fixed 184,320-byte blocks.  Segment
splitting follows the wire-visible invariant: a non-leaf segment is split by
its base size, with the left branch receiving the odd block when the branch is
itself a left child.  This module provides whole-file master hashes, ordered
leaf hashes, verification, and tagged diagnostics without network access.

src/amuled_v2/core/hashes/aich.py
Version:     0.2.0
Author:      Soror L.'.L.'.
Updated:     2026-09-27

Patch Notes v0.2.0 (Soror L'.L'.):
  [+] AICH requester side (client): aich_parse_recovery_data +
      aich_rebuild_master_from_part — recompute the file master from one
      downloaded part plus the peer recovery blob (SHAHashSet.cpp
      ReadRecoveryData walk).

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Added SHA1 helpers and streaming AICH master/leaf computation.
  [+] Added exact odd-block left/right segment splitting.
  [+] Added AichHashResult, verification, and tagged HASH diagnostics.
"""

from __future__ import annotations

import hashlib
import io
import struct
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
    "materialize_aich_tree",
    "aich_part_recovery_data",
    "aich_parse_recovery_data",
    "aich_rebuild_master_from_part",
    "aich_part_path_ident",
    "aich_subtree_leaf_idents",
    "aich_verified_part_blocks",
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


# ---------------------------------------------------------------------------
# Recovery-data builder (stage X wire responder; SHAHashSet.cpp
# CAICHRecoveryHashSet::CreatePartRecoveryData / CAICHHashTree::WriteHash /
# WriteLowestLevelHashes).  The wire needs, for one PARTSIZE chunk: the
# sibling hashes along the path from the tree root to that chunk plus the
# chunk's own block hashes, each tagged with a MSB-first path identifier
# (1 = left branch; the identifier's highest set bit marks the root level).
# ---------------------------------------------------------------------------


class _AichNode:
    """One node of the materialized AICH tree ( wire responder)."""

    __slots__ = ("start", "size", "is_left", "hash", "left", "right")

    def __init__(
        self,
        start: int,
        size: int,
        is_left: bool,
        digest: bytes,
        left: "_AichNode | None" = None,
        right: "_AichNode | None" = None,
    ) -> None:
        self.start = start
        self.size = size
        self.is_left = is_left
        self.hash = digest
        self.left = left
        self.right = right

    @property
    def is_leaf(self) -> bool:
        return self.left is None and self.right is None


def _build_tree(leaves: list[bytes], start: int, size: int, is_left: bool) -> _AichNode:
    """Materialize the exact splitting tree of _hash_aich_segment from the
    precomputed leaf (block) hashes — no file access needed."""
    if size <= BLOCKSIZE:
        return _AichNode(start, size, is_left, leaves[0])
    base_size = BLOCKSIZE if size <= PARTSIZE else PARTSIZE
    block_count = (size + base_size - 1) // base_size
    left_block_count = (
        (block_count + 1) // 2 if is_left else block_count // 2
    )
    left_size = left_block_count * base_size
    if left_size >= size:
        left_size = (block_count // 2) * base_size
    right_size = size - left_size
    if left_size <= 0 or right_size <= 0:
        raise AichError(
            f"invalid AICH split: size={size}, base={base_size}, "
            f"left={left_size}, right={right_size}"
        )
    # Leaf counts of the subtrees at the CURRENT base granularity.
    left_leaf_count = (left_size + BLOCKSIZE - 1) // BLOCKSIZE
    left = _build_tree(leaves[:left_leaf_count], start, left_size, True)
    right = _build_tree(
        leaves[left_leaf_count:], start + left_size, right_size, False
    )
    return _AichNode(
        start, size, is_left, sha1_digest(left.hash + right.hash), left, right
    )


def materialize_aich_tree(result: AichHashResult) -> _AichNode:
    """Rebuild the full AICH tree from a computed hash result."""
    return _build_tree(
        list(result.block_hashes), 0, result.file_size, True
    )


def aich_part_recovery_data(result: AichHashResult, part_index: int) -> bytes:
    """CAICHRecoveryHashSet::CreatePartRecoveryData wire blob for one part.

    Layout (SHAHashSet.cpp:712-758, 766-771):
        small file: [count16 u16][count16 x (ident u16, hash 20)][u16 0]
        large file: [u16 0][count32 u16][count32 x (ident u32, hash 20)]
    Entries: sibling hashes along the root->part path (emitted top-down),
    then the part's block hashes left-to-right.
    """
    file_size = result.file_size
    if file_size <= BLOCKSIZE:
        raise AichError("file fits in one block; no AICH recovery data")
    part_start = part_index * PARTSIZE
    if part_start < 0 or part_start >= file_size:
        raise AichError(f"part index out of range: {part_index}")
    part_size = min(PARTSIZE, file_size - part_start)

    root = materialize_aich_tree(result)
    if root.hash != bytes(result.master_hash):
        raise AichError("materialized tree master hash mismatch")

    # Walk root -> the node covering the requested part, collecting the
    # sibling hashes (emitted top-down, before the part's own leaves).
    # ident bits accumulate MSB-first; 1 = left branch; the root's own
    # branch bit is the leading 1 (WriteHash, SHAHashSet.cpp:497-509).
    entries: list[tuple[int, bytes]] = []
    node = root
    ident = 1 if root.is_left else 0
    while not (node.start == part_start and node.size == part_size):
        if node.left is None or node.right is None:
            raise AichError("AICH tree walk hit a leaf before the part node")
        go_left = part_start < node.left.start + node.left.size
        sibling = node.right if go_left else node.left
        sib_ident = (ident << 1) | (1 if sibling.is_left else 0)
        entries.append((sib_ident, bytes(sibling.hash)))
        node = node.left if go_left else node.right
        ident = (ident << 1) | (1 if node.is_left else 0)

    # The part node's own block hashes, left-to-right
    # (WriteLowestLevelHashes, SHAHashSet.cpp:512-537).
    def _emit(leaf_node: _AichNode, leaf_ident: int) -> None:
        leaf_ident = (leaf_ident << 1) | (1 if leaf_node.is_left else 0)
        if leaf_node.is_leaf:
            entries.append((leaf_ident, bytes(leaf_node.hash)))
            return
        assert leaf_node.left is not None and leaf_node.right is not None
        _emit(leaf_node.left, leaf_ident)
        _emit(leaf_node.right, leaf_ident)

    _emit(node, ident)

    use_32bit = file_size > 0xFFFFFFFF  # IsLargeFile()
    out = bytearray()
    if use_32bit:
        out += struct.pack("<H", 0)
        out += struct.pack("<H", len(entries))
        for entry_ident, entry_hash in entries:
            out += struct.pack("<I", entry_ident) + entry_hash
    else:
        out += struct.pack("<H", len(entries))
        for entry_ident, entry_hash in entries:
            if entry_ident > 0xFFFF:
                raise AichError(f"AICH identifier exceeds 16 bits: {entry_ident:#x}")
            out += struct.pack("<H", entry_ident) + entry_hash
        out += struct.pack("<H", 0)
    return bytes(out)


def aich_part_path_ident(part_index: int, file_size: int) -> tuple[int, int, int]:
    """Walk the size-only split from the root to the part node.

    Returns ``(part_ident, part_size, part_is_left)`` — the ident encoding
    matches aich_part_recovery_data (MSB-first, leading root bit).
    """
    part_start = part_index * PARTSIZE
    if part_start < 0 or part_start >= file_size:
        raise AichError(f"part index out of range: {part_index}")
    part_size = min(PARTSIZE, file_size - part_start)

    node_start, node_size, ident = 0, file_size, 1
    while not (node_start == part_start and node_size == part_size):
        base_size = BLOCKSIZE if node_size <= PARTSIZE else PARTSIZE
        block_count = (node_size + base_size - 1) // base_size
        left_block_count = (
            (block_count + 1) // 2 if ident & 1 else block_count // 2
        )
        left_size = left_block_count * base_size
        if left_size >= node_size:
            left_size = (block_count // 2) * base_size
        go_left = part_start < node_start + left_size
        if go_left:
            ident = (ident << 1) | 1
            node_size = left_size
        else:
            ident = (ident << 1) | 0
            node_start += left_size
            node_size -= left_size
    return ident, part_size, bool(ident & 1)


def aich_subtree_leaf_idents(
    part_ident: int, part_size: int, part_is_left: bool
) -> list[int]:
    """Leaf idents of the part subtree, left-to-right.

    Mirrors the builder's _emit: entering a node shifts in the NODE's own
    is_left bit (root's children of a single-part file get 0x3/0x2 from
    ident 1, their children 0x7/0x6, etc.).
    """
    idents: list[int] = []

    def _emit(cur_ident: int, cur_count: int, cur_is_left: bool) -> None:
        cur_ident = (cur_ident << 1) | (1 if cur_is_left else 0)
        if cur_count == 1:
            idents.append(cur_ident)
            return
        left_count = (cur_count + 1) // 2 if cur_is_left else cur_count // 2
        _emit(cur_ident, left_count, True)
        _emit(cur_ident, cur_count - left_count, False)

    _emit(
        part_ident, (part_size + BLOCKSIZE - 1) // BLOCKSIZE, part_is_left
    )
    return idents


def aich_verified_part_blocks(
    recovery: bytes,
    part_index: int,
    file_size: int,
    expected_master: bytes,
) -> list[bytes]:
    """Extract and AUTHENTICATE the part's verified block hashes from a
    peer recovery blob (client-side counterpart of CreatePartRecoveryData).

    The blob's sibling hashes + the extracted part leaves must rebuild the
    ``expected_master`` (SHA1 chain) — otherwise the blob is rejected with
    AichError.  Returns the part's block hashes left-to-right.
    """
    part_ident, part_size, part_is_left = aich_part_path_ident(
        part_index, file_size
    )
    entries = aich_parse_recovery_data(recovery)

    leaf_idents = aich_subtree_leaf_idents(part_ident, part_size, part_is_left)
    part_blocks: list[bytes] = []
    for leaf_ident in leaf_idents:
        digest = entries.get(leaf_ident)
        if digest is None:
            raise AichError(
                f"recovery blob misses part leaf ident {leaf_ident:#x}"
            )
        part_blocks.append(digest)

    # Authenticate: rebuild the master from the part subtree + siblings.
    part_hash = _build_tree(
        part_blocks, part_index * PARTSIZE, part_size, part_is_left
    ).hash
    # Re-walk collecting the sibling chain (ident -> which side the
    # part-side took), bottom-up: reverse of the top-down walk.
    node_start, node_size, ident = 0, file_size, 1
    chain: list[tuple[bool, int]] = []  # (part_side_is_left, sibling_ident)
    while not (node_start == part_index * PARTSIZE and node_size == part_size):
        base_size = BLOCKSIZE if node_size <= PARTSIZE else PARTSIZE
        block_count = (node_size + base_size - 1) // base_size
        left_block_count = (
            (block_count + 1) // 2 if ident & 1 else block_count // 2
        )
        left_size = left_block_count * base_size
        if left_size >= node_size:
            left_size = (block_count // 2) * base_size
        go_left = part_index * PARTSIZE < node_start + left_size
        if go_left:
            sibling_ident = (ident << 1) | 0
            chain.append((True, sibling_ident))
            node_size = left_size
        else:
            sibling_ident = (ident << 1) | 1
            chain.append((False, sibling_ident))
            node_start += left_size
            node_size -= left_size
        ident = (ident << 1) | (1 if go_left else 0)
    combined = part_hash
    for part_side_left, sibling_ident in reversed(chain):
        sibling_hash = entries.get(sibling_ident)
        if sibling_hash is None:
            raise AichError(
                f"recovery blob misses sibling ident {sibling_ident:#x}"
            )
        combined = (
            sha1_digest(combined + sibling_hash)
            if part_side_left
            else sha1_digest(sibling_hash + combined)
        )
    if combined != expected_master:
        raise AichError(
            "recovery blob does not rebuild the trusted master"
        )
    return part_blocks


# ---------------------------------------------------------------------------
# Recovery-data consumer (client requester side; SHAHashSet.cpp
# CAICHRecoveryHashSet::SetAddress / ReadRecoveryData).  Verifies one
# downloaded part against a peer-provided recovery blob and recomputes the
# file master from the part bytes alone — the client-side mirror of
# aich_part_recovery_data.
# ---------------------------------------------------------------------------


def aich_parse_recovery_data(
    recovery: bytes,
) -> dict[int, bytes]:
    """Parse a recovery blob -> {ident: hash} entries."""
    (count16,) = struct.unpack("<H", recovery[:2])
    offset = 2
    entries: dict[int, bytes] = {}
    for _ in range(count16):
        (ident,) = struct.unpack("<H", recovery[offset : offset + 2])
        entries[ident] = bytes(recovery[offset + 2 : offset + 22])
        offset += 22
    (count32,) = struct.unpack("<H", recovery[offset : offset + 2])
    offset += 2
    for _ in range(count32):
        (ident,) = struct.unpack("<I", recovery[offset : offset + 4])
        entries[ident] = bytes(recovery[offset + 4 : offset + 24])
        offset += 24
    return entries


def aich_rebuild_master_from_part(
    part_data: bytes,
    part_index: int,
    recovery: bytes,
    file_size: int,
) -> bytes:
    """Recompute the file's AICH master hash from one downloaded part plus
    the peer's recovery blob (SHAHashSet.cpp ReadRecoveryData walk).

    Returns the recomputed master hash; compare it against the peer's
    claimed master — a match both authenticates the blob AND proves the
    part bytes are what the source tree covers.  Raises AichError when
    the recovery data cannot cover the tree.
    """
    part_start = part_index * PARTSIZE
    if part_start < 0 or part_start >= file_size:
        raise AichError(f"part index out of range: {part_index}")
    part_size = min(PARTSIZE, file_size - part_start)
    if len(part_data) != part_size:
        raise AichError(
            f"part data size mismatch: got {len(part_data)}, expected {part_size}"
        )
    entries = aich_parse_recovery_data(recovery)
    part_result = aich_hash_data(part_data)

    def resolve(start: int, size: int, is_left: bool, ident: int) -> bytes | None:
        ident = (ident << 1) | (1 if is_left else 0)
        if ident in entries and size <= BLOCKSIZE:
            return entries[ident]
        if start >= part_start and start + size <= part_start + part_size:
            rel = start - part_start
            sub_leaves = part_result.block_hashes[
                rel // BLOCKSIZE : (rel + size + BLOCKSIZE - 1) // BLOCKSIZE
            ]
            return _build_tree(list(sub_leaves), start, size, is_left).hash
        if ident in entries:
            return entries[ident]
        if size <= BLOCKSIZE:
            return None
        base = BLOCKSIZE if size <= PARTSIZE else PARTSIZE
        blocks = (size + base - 1) // base
        left_blocks = (blocks + 1) // 2 if is_left else blocks // 2
        left_size = left_blocks * base
        if left_size >= size:
            left_size = (blocks // 2) * base
        right_size = size - left_size
        left = resolve(start, left_size, True, ident)
        right = resolve(start + left_size, right_size, False, ident)
        if left is None or right is None:
            return None
        return sha1_digest(left + right)

    master = resolve(0, file_size, True, 0)
    if master is None:
        raise AichError("recovery data does not cover the whole tree")
    return master
