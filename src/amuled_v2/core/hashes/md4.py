"""MD4 hash adapter for the ED2K file-hash layer.

This module is a thin, portable adapter around PyCryptodome's established
``Crypto.Hash.MD4`` implementation.  It deliberately does not implement the
MD4 algorithm locally.  The public adapter mirrors the familiar
``update``/``digest``/``hexdigest`` interface used by the ED2K hash layer.

src/amuled_v2/core/hashes/md4.py
Version:     0.2.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.2.0 (Soror L.'.L'.):
  [*] Replaced the local MD4 implementation with the required PyCryptodome
      ``Crypto.Hash.MD4`` dependency.
  [+] Preserved an incremental MD4-compatible public API for ED2K hashing.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Initial MD4 facade for the ED2K hash layer.
"""

from __future__ import annotations

from Crypto.Hash import MD4 as _PyCryptodomeMD4

__all__ = ["MD4", "md4_digest"]


class MD4:
    """Incremental MD4 hasher backed by PyCryptodome.

    Usage::

        h = MD4()
        h.update(b"abc")
        h.digest()
    """

    name = "md4"
    block_size = 64
    digest_size = 16
    DIGEST_SIZE = 16
    BLOCK_SIZE = 64

    def __init__(self, data: bytes = b"") -> None:
        self._hash = _PyCryptodomeMD4.new()
        if data:
            self.update(data)

    def update(self, data: bytes) -> "MD4":
        if isinstance(data, str):
            raise TypeError("Unicode strings must be encoded before hashing")
        if data:
            self._hash.update(data)
        return self

    def digest(self) -> bytes:
        return self._hash.digest()

    def hexdigest(self) -> str:
        return self._hash.hexdigest()

    def copy(self) -> "MD4":
        cloned = MD4()
        cloned._hash = self._hash.copy()
        return cloned


def md4_digest(data: bytes) -> bytes:
    """Return the 16-byte MD4 digest of *data*."""
    return MD4(data).digest()
