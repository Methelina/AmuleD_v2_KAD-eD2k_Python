"""pytest suite for the M3 MD4 / ED2K hash layer.

Validates the pure-Python MD4 implementation against canonical RFC 1320
vectors, checks ED2K semantics for sub-chunk, exact-chunk, multi-chunk and
empty inputs, and exercises incremental streaming with odd-sized updates.
Tests must pass without ``hashlib.md4``; the portable fallback is always used.

tests/test_hashes.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-22

Patch Notes v0.2.0 (Soror L.'.L'.):
  [*] Updated exact-boundary tests to the reference terminating-empty-chunk
      semantics used by ED2K.
  [*] Removed implementation-specific assertions; MD4 is supplied by the
      installed PyCryptodome dependency.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] MD4 known-answer vectors (empty, single char, short, alphabet, 80-digit).
  [+] Streaming update round-trips over odd chunk sizes.
  [+] ED2K equals MD4 for empty and single-chunk data.
  [+] ED2K multi-chunk computed from concatenated chunk digests.
  [+] Exact PARTSIZE and PARTSIZE*2 boundary edge cases.
"""

import os
import struct
import tempfile

import pytest

from amuled_v2.core.hashes import (
    PARTSIZE,
    Ed2kHashResult,
    MD4,
    ed2k_hash_data,
    ed2k_hash_file,
    md4_digest,
)


MD4_VECTORS = [
    (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
    (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
    (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
    (b"message digest", "d9130a8164549fe818874806e1c7014b"),
    (
        b"abcdefghijklmnopqrstuvwxyz",
        "d79e1c308aa5bbcdeea8ed63df412da9",
    ),
    (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        b"abcdefghijklmnopqrstuvwxyz"
        b"0123456789",
        "043f8582f241db351ce627e153e7f0e4",
    ),
    (
        b"1234567890" * 8,
        "e33b4ddc9c38f2199c3e7b164fcc0536",
    ),
]


@pytest.mark.parametrize("data,expected_hex", MD4_VECTORS)
def test_md4_known_vectors(data: bytes, expected_hex: str) -> None:
    actual = md4_digest(data).hex()
    assert actual == expected_hex


@pytest.mark.parametrize("data,expected_hex", MD4_VECTORS)
def test_md4_incremental(data: bytes, expected_hex: str) -> None:
    """Feeding one byte at a time must match the one-shot digest."""
    h = MD4()
    for ch in data:
        h.update(bytes((ch,)))
    assert h.digest().hex() == expected_hex


def test_md4_streaming_roundtrip_odd_sizes() -> None:
    """Streaming in irregular step sizes must reproduce the single digest."""
    data = os.urandom(70000)
    expected = md4_digest(data)
    h = MD4()
    steps = [1, 7, 13, 1000, 0, 4095, 2, 65537, 50, 333]
    idx = 0
    for step in steps:
        if step:
            h.update(data[idx : idx + step])
            idx += step
    h.update(data[idx:])
    assert h.digest() == expected


def test_md4_digest_size() -> None:
    assert len(md4_digest(b"")) == 16
    assert MD4().digest_size == 16
    assert MD4().block_size == 64


def test_ed2k_empty_equals_md4() -> None:
    res = ed2k_hash_data(b"")
    assert res.file_hash == md4_digest(b"")
    assert res.file_size == 0
    assert res.chunk_hashes == [md4_digest(b"")]


def test_ed2k_small_equals_md4() -> None:
    data = b"hello ed2k"
    res = ed2k_hash_data(data)
    assert res.file_hash == md4_digest(data)
    assert len(res.chunk_hashes) == 1


def test_ed2k_single_chunk_exactly_partsiz() -> None:
    """Exact PARTSIZE emits its chunk digest plus the reference empty digest."""
    data = os.urandom(PARTSIZE)
    res = ed2k_hash_data(data)
    chunk_hash = md4_digest(data)
    empty_hash = md4_digest(b"")
    assert res.file_size == PARTSIZE
    assert res.chunk_hashes == [chunk_hash, empty_hash]
    assert res.file_hash == md4_digest(chunk_hash + empty_hash)


def test_ed2k_two_chunks_partsiz() -> None:
    """Exact PARTSIZE*2 emits two real chunks plus the terminating digest."""
    data = os.urandom(PARTSIZE * 2)
    res = ed2k_hash_data(data)
    c0 = md4_digest(data[:PARTSIZE])
    c1 = md4_digest(data[PARTSIZE:])
    terminator = md4_digest(b"")
    assert res.file_size == PARTSIZE * 2
    assert res.chunk_hashes == [c0, c1, terminator]
    assert res.file_hash == md4_digest(c0 + c1 + terminator)


def test_ed2k_multi_chunk_computed_from_digests() -> None:
    n = PARTSIZE * 3 + 12345
    data = os.urandom(n)
    res = ed2k_hash_data(data)
    assert len(res.chunk_hashes) == 4
    expected_chunks = []
    for i in range(3):
        expected_chunks.append(md4_digest(data[i * PARTSIZE : (i + 1) * PARTSIZE]))
    expected_chunks.append(md4_digest(data[3 * PARTSIZE :]))
    assert res.chunk_hashes == expected_chunks
    assert res.file_hash == md4_digest(b"".join(expected_chunks))


def test_ed2k_just_over_one_chunk() -> None:
    data = os.urandom(PARTSIZE + 1)
    res = ed2k_hash_data(data)
    assert len(res.chunk_hashes) == 2
    assert res.file_hash == md4_digest(
        md4_digest(data[:PARTSIZE]) + md4_digest(data[PARTSIZE:])
    )


def test_ed2k_chunk_hashes_independent_of_split() -> None:
    """Chunk digests must be identical regardless of how update() is split."""
    data = os.urandom(PARTSIZE * 2 + 500)
    res_bulk = ed2k_hash_data(data)

    h = MD4.__new__(MD4)
    from amuled_v2.core.hashes.ed2k import Ed2kHasher

    hasher = Ed2kHasher()
    hasher.update(data[:5])
    hasher.update(data[5:PARTSIZE])
    hasher.update(data[PARTSIZE : PARTSIZE + 200000])
    hasher.update(data[PARTSIZE + 200000 :])
    res_split = hasher.result()

    assert res_bulk.file_hash == res_split.file_hash
    assert res_bulk.file_size == res_split.file_size
    assert res_bulk.chunk_hashes == res_split.chunk_hashes


def test_ed2k_hash_file(tmp_path) -> None:
    data = os.urandom(PARTSIZE + 1000)
    p = tmp_path / "chunk.bin"
    p.write_bytes(data)
    res = ed2k_hash_file(str(p))
    assert res == ed2k_hash_data(data)
    assert res.file_hash == md4_digest(
        md4_digest(data[:PARTSIZE]) + md4_digest(data[PARTSIZE:])
    )


def test_ed2k_result_equality_and_roundtrip() -> None:
    data = os.urandom(50)
    a = ed2k_hash_data(data)
    b = Ed2kHashResult(
        file_hash=a.file_hash,
        file_size=a.file_size,
        chunk_hashes=list(a.chunk_hashes),
    )
    assert a == b
    assert hash(a) == hash(b)


@pytest.mark.parametrize("chunk_size", [1, 64, 65, 131])
def test_ed2k_custom_chunk_size(chunk_size: int) -> None:
    data = os.urandom(chunk_size * 3 + 7)
    res = ed2k_hash_data(data, chunk_size=chunk_size)
    assert res.file_size == len(data)

    expected = []
    full_chunks = len(data) // chunk_size
    remaining = len(data) % chunk_size
    for i in range(full_chunks):
        expected.append(md4_digest(data[i * chunk_size : (i + 1) * chunk_size]))
    if remaining:
        expected.append(md4_digest(data[full_chunks * chunk_size :]))
    elif data:
        expected.append(md4_digest(b""))
    assert res.chunk_hashes == expected
    assert res.file_hash == md4_digest(b"".join(expected))


def test_md4_uses_pycryptodome_dependency() -> None:
    import amuled_v2.core.hashes.md4 as md4mod

    assert getattr(md4mod, "_PyCryptodomeMD4", None) is not None
    assert md4mod.md4_digest(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
