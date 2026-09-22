"""ED2K and AICH hash layer: MD4, ED2K file hashing, SHA1, Merkle trees.

Re-exports the public hash API so callers import from ``core.hashes`` directly.

src/amuled_v2/core/hashes/__init__.py
Version:     0.2.0
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.2.0 (Soror L.'.L'.):
  [+] Added AICH SHA-1 Merkle-tree exports alongside ED2K/MD4 hashing.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Initial package exporting MD4 and ED2K hashing APIs.
"""

from .aich import (
    AichError,
    AichHashResult,
    aich_hash_data,
    aich_hash_file,
    aich_verify_data,
    aich_verify_file,
    sha1_digest,
    sha1_file,
)
from .ed2k import (
    PARTSIZE,
    Ed2kHashResult,
    Ed2kHasher,
    ed2k_hash_data,
    ed2k_hash_file,
)
from .md4 import MD4, md4_digest

__all__ = [
    "AichError",
    "AichHashResult",
    "aich_hash_data",
    "aich_hash_file",
    "aich_verify_data",
    "aich_verify_file",
    "sha1_digest",
    "sha1_file",
    "PARTSIZE",
    "MD4",
    "md4_digest",
    "Ed2kHashResult",
    "Ed2kHasher",
    "ed2k_hash_data",
    "ed2k_hash_file",
]
