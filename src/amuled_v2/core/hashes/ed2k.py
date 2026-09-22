"""ED2K file-hash layer: per-chunk MD4 hashing and the outer ED2K digest.

Implements the ED2K file-hash algorithm from the aMule/eMule protocol study
(see PROTOCOL_MATRIX.md, section 3). A file is split into PARTSIZE
(9 728 000-byte) chunks. Each chunk is hashed with MD4, producing a 16-byte
chunk digest. The final ED2K hash is MD4 of the concatenated chunk digests
when more than one chunk exists; for a single chunk (including the empty
file), the ED2K hash equals that chunk's MD4 digest.

An incremental Ed2kHasher is provided for streaming byte input, plus
one-shot and file-path helpers. Each chunk hash is recorded so that the
result mirrors the ``hashset`` metadata exchanged with peers.

src/amuled_v2/core/hashes/ed2k.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-22

Patch Notes v0.2.0 (Soror L.'.L'.):
  [*] MD4 now comes from the installed PyCryptodome dependency.
  [*] Corrected exact-chunk boundary behavior: the reference protocol loop
      emits a terminating empty-chunk digest at exact PARTSIZE multiples.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Ed2kHasher incremental hasher with update() for streaming input.
  [+] Ed2kHashResult namedtuple exposing file_hash/file_size/chunk_hashes.
  [+] One-shot ed2k_hash_data and file-path ed2k_hash_file helpers.
  [+] Edge semantics: a final empty read at an exact PARTSIZE boundary still
      emits a terminating chunk digest (matching the studied C++ loop).
"""

import os
from dataclasses import dataclass, field

from .md4 import MD4, md4_digest

__all__ = ["Ed2kHashResult", "Ed2kHasher", "ed2k_hash_data", "ed2k_hash_file"]

PARTSIZE = 9_728_000
BLOCKSIZE = 184_320


@dataclass
class Ed2kHashResult:
    """Result of an ED2K computation over a data stream or file."""

    file_hash: bytes
    file_size: int
    chunk_hashes: list = field(default_factory=list)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed2kHashResult):
            return NotImplemented
        return (
            self.file_hash == other.file_hash
            and self.file_size == other.file_size
            and self.chunk_hashes == other.chunk_hashes
        )

    def __hash__(self) -> int:
        return hash((self.file_hash, self.file_size, tuple(self.chunk_hashes)))


class Ed2kHasher:
    """Incremental ED2K hasher.

    Feed data with :meth:`update` until exhausted, then call :meth:`result`.
    """

    def __init__(self, chunk_size: int = PARTSIZE) -> None:
        self._chunk_size: int = chunk_size
        self._size: int = 0
        self._md4 = MD4()
        self._chunk_hashes: list = []

    def update(self, data: bytes) -> "Ed2kHasher":
        if isinstance(data, str):
            raise TypeError("Unicode strings must be encoded before hashing")
        offset = 0
        length = len(data)
        while offset < length:
            take = min(length - offset, self._chunk_size - (self._size % self._chunk_size))
            self._md4.update(data[offset : offset + take])
            offset += take
            self._size += take
            if self._size % self._chunk_size == 0:
                self._chunk_hashes.append(self._md4.digest())
                self._md4 = MD4()
        return self

    def _finalize(self) -> None:
        remaining = self._size % self._chunk_size
        at_exact_boundary = remaining == 0 and self._size != 0
        if remaining != 0 or at_exact_boundary or not self._chunk_hashes:
            self._chunk_hashes.append(self._md4.digest())
            self._md4 = MD4()

    def result(self) -> Ed2kHashResult:
        """Compute and return the :class:`Ed2kHashResult` for all fed data."""
        self._finalize()
        if len(self._chunk_hashes) == 1:
            file_hash = self._chunk_hashes[0]
        else:
            file_hash = md4_digest(b"".join(self._chunk_hashes))
        return Ed2kHashResult(
            file_hash=file_hash,
            file_size=self._size,
            chunk_hashes=list(self._chunk_hashes),
        )


def ed2k_hash_data(data: bytes, chunk_size: int = PARTSIZE) -> Ed2kHashResult:
    """Compute the ED2K result for a bytes blob."""
    h = Ed2kHasher(chunk_size=chunk_size)
    h.update(data)
    return h.result()


def ed2k_hash_file(path: str, chunk_size: int = PARTSIZE) -> Ed2kHashResult:
    """Compute the ED2K result for a file on disk."""
    h = Ed2kHasher(chunk_size=chunk_size)
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        while True:
            block = fh.read(1 << 16)
            if not block:
                break
            h.update(block)
    return h.result()
