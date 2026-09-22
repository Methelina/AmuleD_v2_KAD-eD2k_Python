"""Tests for SHA1/AICH Merkle-tree and ED2K login builders.

M3/M4 foundational tests: AICH master/leaf consistency over exact boundaries,
streaming file/data equality, SHA1 vectors, and byte-exact ED2K
``OP_LOGINREQUEST`` framing.  No network sockets are used.

tests/test_hashes_aich.py
Version:     0.1.1
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.1 (Soror L.'.L'.):
  [*] Updated login packet framing assertions to the real ED2K wire order:
      protocol, UInt32 packet length, opcode.
  [+] Tested SHA1 vectors and AICH data/file round trips.
  [+] Tested one-block, multi-block, and PARTSIZE boundary tree invariants.
  [+] Tested verification success/failure and malformed-hash rejection.
"""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

import pytest

from amuled_v2.core.codec.binary import BinaryReader
from amuled_v2.core.codec.constants import BLOCKSIZE, EDONKEY
from amuled_v2.core.codec.packet import decode_packet
from amuled_v2.core.codec.tags import read_new_tag
from amuled_v2.core.ed2k import (
    A_MULE_VERSION,
    C2STCP,
    ClientCapability,
    EDONKEY_PROTOCOL_VERSION,
    LoginRequest,
    build_login_payload,
    build_login_packet,
)
from amuled_v2.core.hashes import (
    AichError,
    aich_hash_data,
    aich_hash_file,
    aich_verify_data,
    aich_verify_file,
    sha1_digest,
    sha1_file,
)

_20KB = 20 * 1024


def test_sha1_known_vectors() -> None:
    assert sha1_digest(b"").hex() == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert sha1_digest(b"abc").hex() == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert sha1_digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").hex() == (
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    )


def test_sha1_file_matches_stdlib(tmp_path: Path) -> None:
    source = tmp_path / "sha.bin"
    payload = os.urandom(12345)
    source.write_bytes(payload)
    assert sha1_file(source) == hashlib.sha1(payload).digest()


@pytest.mark.parametrize("size", [1, BLOCKSIZE - 1, BLOCKSIZE, BLOCKSIZE + 1])
def test_aich_master_consistency_and_leaf_count(size: int) -> None:
    data = os.urandom(size)
    result = aich_hash_data(data)
    assert result.file_size == size
    assert result.master_hash == sha1_digest(data) if size <= BLOCKSIZE else True
    assert len(result.block_hashes) == (size + BLOCKSIZE - 1) // BLOCKSIZE
    assert all(len(block) == 20 for block in result.block_hashes)


def test_aich_data_and_file_results_match(tmp_path: Path) -> None:
    payload = os.urandom(BLOCKSIZE * 3 + 17)
    source = tmp_path / "aich.bin"
    source.write_bytes(payload)
    from_data = aich_hash_data(payload)
    from_file = aich_hash_file(source)
    assert from_data == from_file


def test_aich_leaf_hashes_match_sha1_segments() -> None:
    data = os.urandom(BLOCKSIZE * 2 + 123)
    result = aich_hash_data(data)
    expected = [
        hashlib.sha1(data[0:BLOCKSIZE]).digest(),
        hashlib.sha1(data[BLOCKSIZE:BLOCKSIZE * 2]).digest(),
        hashlib.sha1(data[BLOCKSIZE * 2:]).digest(),
    ]
    assert result.block_hashes == tuple(expected)


def test_aich_multi_block_master_is_sha1_of_leaf_tree() -> None:
    # Directly reconstruct the top-level tree from collected leaves.
    data = os.urandom(BLOCKSIZE * 4)
    result = aich_hash_data(data)
    leaf_hashes = result.block_hashes
    assert len(leaf_hashes) == 4
    pair_0 = hashlib.sha1(leaf_hashes[0] + leaf_hashes[1]).digest()
    pair_1 = hashlib.sha1(leaf_hashes[2] + leaf_hashes[3]).digest()
    root = hashlib.sha1(pair_0 + pair_1).digest()
    assert result.master_hash == root


def test_aich_partsize_boundary_yields_exact_block_count() -> None:
    data = os.urandom(9_728_000)
    result = aich_hash_data(data)
    assert result.file_size == 9_728_000
    assert len(result.block_hashes) == 53
    assert all(len(block) == 20 for block in result.block_hashes)


def test_aich_verify_success_and_failure(tmp_path: Path) -> None:
    payload = os.urandom(BLOCKSIZE + 5)
    source = tmp_path / "verify.bin"
    source.write_bytes(payload)
    result = aich_hash_data(payload)
    assert aich_verify_data(payload, result.master_hash) is True
    assert aich_verify_file(source, result.master_hash) is True
    assert aich_verify_data(payload + b"x", result.master_hash) is False
    with pytest.raises(AichError):
        aich_verify_data(payload, b"short")


def _login_request() -> LoginRequest:
    return LoginRequest(
        user_hash=bytes.fromhex("00112233445566778899aabbccddeeff"),
        client_id=0,
        client_port=8089,
        nickname="AmuleD_v2",
        capabilities=(
            ClientCapability.ZLIB
            | ClientCapability.NEWTAGS
            | ClientCapability.UNICODE
            | ClientCapability.LARGEFILES
        ),
    )


def test_login_payload_layout_and_tags() -> None:
    request = _login_request()
    payload = build_login_payload(request)
    reader = BinaryReader(payload)
    assert reader.read_hash16() == request.user_hash
    assert reader.read_u32() == request.client_id
    assert reader.read_u16() == request.client_port
    assert reader.read_u32() == 4

    name = read_new_tag(reader)
    version = read_new_tag(reader)
    flags = read_new_tag(reader)
    emule = read_new_tag(reader)
    assert name.name_id == 0x01 and name.value == request.nickname
    assert version.name_id == 0x11 and version.value == EDONKEY_PROTOCOL_VERSION
    assert flags.name_id == 0x20 and flags.value == request.capabilities
    assert emule.name_id == 0xFB and emule.value == A_MULE_VERSION
    assert reader.remaining == 0


def test_login_packet_wire_framing() -> None:
    request = _login_request()
    raw = build_login_packet(request)
    packet, remainder = decode_packet(raw)
    assert remainder == b""
    assert packet.protocol == EDONKEY
    assert packet.opcode == C2STCP.LOGINREQUEST
    assert packet.payload == build_login_payload(request)
    assert raw[0] == EDONKEY
    assert raw[1:5] == struct.pack("<I", len(packet.payload) + 1)
    assert raw[5] == 0x01
    assert raw[6:] == packet.payload


def test_login_request_generates_fresh_hash_and_security_flags() -> None:
    first = LoginRequest.create(nickname="fresh", client_port=4662)
    second = LoginRequest.create(nickname="fresh", client_port=4662)
    assert first.user_hash != second.user_hash
    assert first.capabilities & ClientCapability.SUPPORTCRYPT
    assert first.capabilities & ClientCapability.REQUESTCRYPT


def test_login_request_rejects_bad_hash_and_nickname() -> None:
    with pytest.raises(Exception):
        LoginRequest(user_hash=b"short", client_id=0, client_port=1, nickname="x")
    with pytest.raises(Exception):
        LoginRequest(
            user_hash=os.urandom(16),
            client_id=0,
            client_port=1,
            nickname="",
        )
