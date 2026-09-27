"""Offline tests for the AICH recovery responder (stage X).

Wire oracle: SHAHashSet.cpp CAICHRecoveryHashSet::CreatePartRecoveryData
(gates: complete file, part in range, master match; recovery blob:
[count16 u16][ident u16, hash 20]*n[u16 0] for small files, u32-idents for
large files).  The recovery data must be sufficient to recompute the file's
AICH master hash from the part bytes alone.

tests/test_aich_wire.py
Author:      Soror L.'.L.'.
Updated:     2026-09-27
"""

from __future__ import annotations

import asyncio
import struct

from amuled_v2.core.codec.constants import BLOCKSIZE, EDONKEY, EMULE, PARTSIZE
from amuled_v2.core.hashes.aich import (
    aich_hash_data,
    aich_hash_file,
    aich_part_recovery_data,
)
from amuled_v2.core.hashes.ed2k import ed2k_hash_file
from amuled_v2.core.peer.client import C2CEMULE, build_emuleinfo_payload
from amuled_v2.core.peer.codec import (
    C2CTCP,
    build_hello_payload,
    build_aich_request_payload,
    parse_aich_answer_payload,
)
from amuled_v2.core.peer.listener import IncomingPeerServer, LocalIdentity
from amuled_v2.core.sharing.shared_files import SharedFile
from amuled_v2.core.upload.queue import UploadQueue

_LOCAL_HASH = bytes.fromhex("9" * 32)
_IO_TIMEOUT = 60.0


def _rebuild_master_from_recovery(
    part_data: bytes, recovery: bytes, file_size: int
) -> bytes:
    """Client-side check of the recovery blob (SHAHashSet.cpp SetHash walk).

    Inserts every (ident, hash) into a tree map, recomputes the master from
    the part bytes, and returns the recomputed root hash.
    """
    from amuled_v2.core.hashes.aich import _build_tree  # internal, test-only

    leaves_result = aich_hash_data(part_data)
    part_tree = _build_tree(list(leaves_result.block_hashes), 0, len(part_data), True)

    (count16,) = struct.unpack("<H", recovery[:2])
    offset = 2
    entries: dict[int, bytes] = {}
    for _ in range(count16):
        (ident,) = struct.unpack("<H", recovery[offset:offset + 2])
        entries[ident] = recovery[offset + 2:offset + 22]
        offset += 22
    (count32,) = struct.unpack("<H", recovery[offset:offset + 2])
    offset += 2
    for _ in range(count32):
        (ident,) = struct.unpack("<I", recovery[offset:offset + 4])
        entries[ident] = hash_ = recovery[offset + 4:offset + 24]
        offset += 24

    def node_hash(node, ident):
        ident = (ident << 1) | (1 if node.is_left else 0)
        if node.is_leaf:
            return node.hash
        left = node_hash(node.left, ident)
        right = node_hash(node.right, (ident << 1) | 1)
        if left is None or right is None:
            return None
        from amuled_v2.core.hashes.aich import sha1_digest
        return sha1_digest(left + right)

    # Walk the whole-file tree shape; a node is known if its ident is in the
    # map, if it is covered by the part tree, or both children are known.
    total_blocks = (file_size + BLOCKSIZE - 1) // BLOCKSIZE

    def resolve(start, size, is_left, ident):
        from amuled_v2.core.hashes.aich import sha1_digest
        ident = (ident << 1) | (1 if is_left else 0)
        if ident in entries:
            return entries[ident]
        # part coverage?
        part_start = getattr(resolve, "part_start")
        part_size = getattr(resolve, "part_size")
        if start >= part_start and start + size <= part_start + part_size:
            rel = start - part_start
            sub_leaves = leaves_result.block_hashes[
                rel // BLOCKSIZE:(rel + size + BLOCKSIZE - 1) // BLOCKSIZE
            ]
            return _build_tree(list(sub_leaves), start, size, is_left).hash
        if size <= BLOCKSIZE:
            return entries.get(ident)
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

    part_start = getattr(resolve, "part_start", None)
    resolve.part_start = PARTSIZE  # part 1 in the test below
    resolve.part_size = min(PARTSIZE, file_size - PARTSIZE)
    return resolve(0, file_size, True, 0)


class _StaticResolver:
    def __init__(self, shared):
        self._shared = shared

    def resolve(self, file_hash):
        return self._shared if self._shared.file_hash == file_hash else None


def _identity() -> LocalIdentity:
    return LocalIdentity(
        user_hash=_LOCAL_HASH,
        client_id=0x10203040,
        tcp_port=0,
        nickname="AmuleD-AICH",
    )


def _run(coro) -> None:
    asyncio.run(coro)


async def _send(writer, opcode, payload, protocol=EDONKEY) -> None:
    writer.write(
        bytes([protocol]) + struct.pack("<I", len(payload) + 1)
        + bytes([opcode]) + payload
    )
    await writer.drain()


async def _recv(reader):
    header = await asyncio.wait_for(reader.readexactly(6), _IO_TIMEOUT)
    (length,) = struct.unpack("<I", header[1:5])
    payload = (
        await asyncio.wait_for(reader.readexactly(length - 1), _IO_TIMEOUT)
        if length > 1 else b""
    )
    return header[0], header[5], payload


def test_aich_answer_wire_loopback(tmp_path) -> None:
    async def scenario() -> None:
        # Two full parts + a tail: exercises the sibling path AND odd splits.
        size = PARTSIZE * 2 + 5000
        path = tmp_path / "aich_sample.bin"
        import os
        path.write_bytes(os.urandom(size))
        hashed = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hashed.file_hash,
            name=path.name,
            size=hashed.file_size,
            path=str(path),
            hash_result=hashed,
        )
        server = IncomingPeerServer(
            identity=_identity(),
            resolver=_StaticResolver(shared),
            upload_queue=UploadQueue(),
            host="127.0.0.1",
            port=0,
            idle_timeout=15.0,
        )
        await server.start()
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", server.bound_port
            )
            try:
                await _send(
                    writer, C2CTCP.HELLO,
                    build_hello_payload(user_hash=bytes.fromhex("8" * 32),
                                        client_id=0x0A0B0C0D, client_port=0,
                                        nickname="aich-peer"),
                )
                await _recv(reader)  # HELLOANSWER
                await _send(writer, C2CEMULE.EMULEINFO,
                            build_emuleinfo_payload(), protocol=EMULE)
                await _recv(reader)  # EMULEINFOANSWER

                result = aich_hash_file(str(path))
                part = 1
                await _send(
                    writer, C2CEMULE.AICHREQUEST,
                    build_aich_request_payload(
                        shared.file_hash, part, result.master_hash
                    ),
                    protocol=EMULE,
                )
                protocol, opcode, payload = await _recv(reader)
                assert protocol == EMULE
                assert opcode == C2CEMULE.AICHANSWER
                ans_hash, ans_part, ans_master, recovery = (
                    parse_aich_answer_payload(payload)
                )
                assert ans_hash == shared.file_hash
                assert ans_part == part
                assert ans_master == result.master_hash

                # The recovery data must reconstruct the master from the
                # part bytes (client-side ReadRecoveryData equivalent).
                part_data = path.read_bytes()[PARTSIZE:PARTSIZE * 2]
                rebuilt = _rebuild_master_from_recovery(
                    part_data, recovery, size
                )
                assert rebuilt == result.master_hash
            finally:
                writer.close()
        finally:
            await server.close()

    _run(scenario())


def test_aich_request_master_mismatch_silenced(tmp_path) -> None:
    async def scenario() -> None:
        import os
        path = tmp_path / "small.bin"
        path.write_bytes(os.urandom(BLOCKSIZE * 3))
        hashed = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hashed.file_hash,
            name=path.name,
            size=hashed.file_size,
            path=str(path),
            hash_result=hashed,
        )
        server = IncomingPeerServer(
            identity=_identity(),
            resolver=_StaticResolver(shared),
            upload_queue=UploadQueue(),
            host="127.0.0.1",
            port=0,
            idle_timeout=15.0,
        )
        await server.start()
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", server.bound_port
            )
            try:
                await _send(
                    writer, C2CTCP.HELLO,
                    build_hello_payload(user_hash=bytes.fromhex("8" * 32),
                                        client_id=1, client_port=0,
                                        nickname="aich-peer"),
                )
                await _recv(reader)
                await _send(writer, C2CEMULE.EMULEINFO,
                            build_emuleinfo_payload(), protocol=EMULE)
                await _recv(reader)
                wrong_master = b"\xAA" * 20
                await _send(
                    writer, C2CEMULE.AICHREQUEST,
                    build_aich_request_payload(
                        shared.file_hash, 0, wrong_master
                    ),
                    protocol=EMULE,
                )
                import pytest
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(_recv(reader), timeout=2.0)
            finally:
                writer.close()
        finally:
            await server.close()

    _run(scenario())


def test_aich_recovery_data_layout_small_file() -> None:
    """Small file: 16-bit idents, count1=n, trailing zero count2."""
    data = b"\x01" * (BLOCKSIZE * 2 + 100)
    result = aich_hash_data(data)
    recovery = aich_part_recovery_data(result, 0)
    (count1,) = struct.unpack("<H", recovery[:2])
    assert count1 == 3  # three blocks, no siblings
    assert struct.unpack("<H", recovery[-2:])[0] == 0
