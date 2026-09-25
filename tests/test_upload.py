"""Tests for the upload transfer stack.

Covers UploadQueue scheduling, BlockSource reads, UploadThrottle pacing, and
UploadSession wire semantics (REQUESTFILENAME, HASHSETREQUEST, REQUESTPARTS_I64,
COMPRESSEDPART, END_OF_DOWNLOAD) using an in-memory fake transport.  No real
network or handshake is involved; these are pure logic tests.

tests/test_upload.py
Version:     0.1.0
Author:      Soror L'.
'L'.
Updated:     2026-09-24

Patch Notes v0.1.0 (Soror L'.
'L'.):
  [+] Initial upload stack coverage: queue ordering/dedup/slots, BlockSource
      bounds, throttle pacing, and UploadSession sub-packet splitting.
"""

from __future__ import annotations

import asyncio
import os
import struct
import time
import zlib
from typing import Optional

import pytest

from amuled_v2.core.hashes.ed2k import PARTSIZE, ed2k_hash_file
from amuled_v2.core.peer.codec import (
    build_request_parts_i64_payload,
    build_request_parts_payload,
    parse_compressed_part,
    parse_filename_answer,
    parse_hashset_answer,
    parse_sending_part,
    parse_sending_part_i64,
)
from amuled_v2.core.sharing.shared_files import SharedFile
from amuled_v2.core.upload.engine import (
    OP_COMPRESSEDPART,
    OP_COMPRESSEDPART_I64,
    OP_END_OF_DOWNLOAD,
    OP_HASHSETANSWER,
    OP_HASHSETREQUEST,
    OP_REQFILENAMEANSWER,
    OP_REQUESTFILENAME,
    OP_REQUESTPARTS,
    OP_REQUESTPARTS_I64,
    OP_SENDINGPART,
    OP_SENDINGPART_I64,
    SPLIT_CHUNK_SIZE,
    SPLIT_THRESHOLD,
    BlockSource,
    UploadEngineError,
    UploadSession,
    UploadThrottle,
)
from amuled_v2.core.upload.queue import (
    UploadClient,
    UploadPriority,
    UploadQueue,
    UploadQueueError,
)

_TEST_HASH = bytes(range(16))


def _make_user_hash(seed: int = 1) -> str:
    raw = bytes((seed * 7 + i) % 256 for i in range(16))
    return raw.hex()


def _make_file_hash(seed: int = 100) -> str:
    raw = bytes((seed * 13 + i) % 256 for i in range(16))
    return raw.hex()


def _build_i64_payload(
    file_hash: bytes, ranges: list[tuple[int, int]], file_size: int
) -> bytes:
    """Build a REQUESTPARTS_I64 payload from 1-3 ranges.

    The codec validator requires start < end for all three pairs, so we pad
    with 1-byte ranges at the end of the file that do not overlap real ranges.
    """
    padded = list(ranges)
    d1 = file_size - 2
    d2 = file_size - 1
    while len(padded) < 3:
        padded.append((d1, d2))
        d1 -= 2
        d2 -= 2
    starts = tuple(r[0] for r in padded[:3])
    ends = tuple(r[1] for r in padded[:3])
    return build_request_parts_i64_payload(file_hash, starts, ends)


def _build_plain_payload(
    file_hash: bytes, ranges: list[tuple[int, int]], file_size: int
) -> bytes:
    """Build a REQUESTPARTS (non-I64) payload from 1-3 ranges."""
    padded = list(ranges)
    d1 = file_size - 2
    d2 = file_size - 1
    while len(padded) < 3:
        padded.append((d1, d2))
        d1 -= 2
        d2 -= 2
    starts = tuple(r[0] for r in padded[:3])
    ends = tuple(r[1] for r in padded[:3])
    return build_request_parts_payload(file_hash, starts, ends)


def _parse_sending_parts(
    sent: list[tuple[int, bytes]],
) -> list:
    """Parse all sent SENDINGPART*/COMPRESSEDPART* sub-packets."""
    results = []
    for opcode, payload in sent:
        if opcode == OP_SENDINGPART:
            results.append(parse_sending_part(payload))
        elif opcode == OP_SENDINGPART_I64:
            results.append(parse_sending_part_i64(payload))
        elif opcode == OP_COMPRESSEDPART:
            results.append(parse_compressed_part(payload))
        elif opcode == OP_COMPRESSEDPART_I64:
            results.append(parse_compressed_part(payload))
    return results


def _filter_range(
    parts: list, ranges: list[tuple[int, int]]
) -> list:
    """Keep only sub-packets whose start/end fall within one of ranges.

    Single-byte sub-packets (dummy padding ranges) are excluded by requiring
    end - start >= 2, since no real test range is shorter than 2 bytes.
    """
    result = []
    for part in parts:
        if part.end - part.start < 2:
            continue
        for req_start, req_end in ranges:
            if part.start >= req_start and part.end <= req_end:
                result.append(part)
                break
    return result


class FakeTransport:
    """In-memory transport that scripts recv() packets and records send() outputs."""

    def __init__(self, script: list[tuple[int, bytes]]) -> None:
        self._script = list(script)
        self._sent: list[tuple[int, bytes]] = []

    async def recv(self) -> Optional[tuple[int, bytes]]:
        if not self._script:
            return None
        return self._script.pop(0)

    async def send(self, opcode: int, payload: bytes) -> None:
        self._sent.append((opcode, payload))

    @property
    def sent(self) -> list[tuple[int, bytes]]:
        return list(self._sent)

    def sent_opcodes(self) -> list[int]:
        return [opcode for opcode, _ in self._sent]


class TestUploadQueue:
    """UploadQueue scheduling, ranking, and slot management."""

    def test_enqueue_orders_by_priority_then_fifo(self) -> None:
        queue = UploadQueue(max_slots=10, slot_ttl=600.0)
        file_hash = _make_file_hash()

        low_key = _make_user_hash(4)
        normal_a_key = _make_user_hash(2)
        high_key = _make_user_hash(1)
        normal_b_key = _make_user_hash(3)

        queue.enqueue(low_key, 1, 1, "low", file_hash, UploadPriority.LOW)
        queue.enqueue(normal_a_key, 2, 2, "na", file_hash, UploadPriority.NORMAL)
        queue.enqueue(high_key, 3, 3, "hi", file_hash, UploadPriority.HIGH)
        queue.enqueue(normal_b_key, 4, 4, "nb", file_hash, UploadPriority.NORMAL)

        waiting = queue.waiting()
        assert [c.user_hash for c in waiting] == [high_key, normal_a_key, normal_b_key, low_key]
        assert [c.rank for c in waiting] == [1, 2, 3, 4]

    def test_enqueue_rank_is_1_based(self) -> None:
        queue = UploadQueue(max_slots=10)
        file_hash = _make_file_hash()
        r = queue.enqueue(_make_user_hash(1), 1, 1, "a", file_hash, UploadPriority.NORMAL)
        assert r == 1

    def test_enqueue_returns_rank_at_enqueue_time(self) -> None:
        queue = UploadQueue(max_slots=10)
        file_hash = _make_file_hash()
        queue.enqueue(_make_user_hash(1), 1, 1, "a", file_hash, UploadPriority.NORMAL)
        r = queue.enqueue(_make_user_hash(2), 2, 2, "b", file_hash, UploadPriority.HIGH)
        assert r == 1

    def test_dedupe_waiting_returns_existing_rank(self) -> None:
        queue = UploadQueue(max_slots=10)
        file_hash = _make_file_hash()
        key = _make_user_hash(1)
        first = queue.enqueue(key, 1, 1, "a", file_hash, UploadPriority.HIGH)
        second = queue.enqueue(key, 1, 1, "a", file_hash, UploadPriority.LOW)
        assert second == first
        assert queue.enqueue(_make_user_hash(2), 2, 2, "b", file_hash, UploadPriority.HIGH) == 2
        assert queue.rank_of(key, file_hash) == 1

    def test_dedupe_does_not_create_new_rank(self) -> None:
        queue = UploadQueue(max_slots=10)
        file_hash = _make_file_hash()
        key = _make_user_hash(1)
        queue.enqueue(key, 1, 1, "a", file_hash, UploadPriority.NORMAL)
        queue.enqueue(_make_user_hash(2), 2, 2, "b", file_hash, UploadPriority.NORMAL)
        re_rank = queue.enqueue(key, 1, 1, "a", file_hash, UploadPriority.NORMAL)
        assert re_rank == 1
        assert len(queue.waiting()) == 2

    def test_grant_slot_head_only(self) -> None:
        queue = UploadQueue(max_slots=10)
        file_hash = _make_file_hash()
        high_key = _make_user_hash(1)
        low_key = _make_user_hash(2)
        queue.enqueue(low_key, 1, 1, "low", file_hash, UploadPriority.LOW)
        queue.enqueue(high_key, 2, 2, "hi", file_hash, UploadPriority.HIGH)

        with pytest.raises(UploadQueueError):
            queue.grant_slot(low_key, file_hash)

        queue.grant_slot(high_key, file_hash)
        assert queue.is_active(high_key, file_hash) is True

    def test_grant_slot_max_slots_enforcement(self) -> None:
        queue = UploadQueue(max_slots=1)
        file_hash = _make_file_hash()
        key_a = _make_user_hash(1)
        key_b = _make_user_hash(2)
        queue.enqueue(key_a, 1, 1, "a", file_hash, UploadPriority.NORMAL)
        queue.enqueue(key_b, 2, 2, "b", file_hash, UploadPriority.NORMAL)
        queue.grant_slot(key_a, file_hash)

        with pytest.raises(UploadQueueError):
            queue.grant_slot(key_b, file_hash)

    def test_release_slot_frees_capacity(self) -> None:
        queue = UploadQueue(max_slots=1)
        file_hash = _make_file_hash()
        key = _make_user_hash(1)
        queue.enqueue(key, 1, 1, "a", file_hash, UploadPriority.NORMAL)
        queue.grant_slot(key, file_hash)
        assert queue.is_active(key, file_hash) is True

        released = queue.release_slot(key, file_hash)
        assert released is True
        assert queue.is_active(key, file_hash) is False

    def test_release_slot_returns_false_when_not_held(self) -> None:
        queue = UploadQueue(max_slots=1)
        file_hash = _make_file_hash()
        queue.enqueue(_make_user_hash(1), 1, 1, "a", file_hash)
        assert queue.release_slot(_make_user_hash(2), file_hash) is False

    def test_expired_slots_with_monkeypatched_time(self, monkeypatch) -> None:
        fake_now = [1000.0]
        monkeypatch.setattr(
            "amuled_v2.core.upload.queue.time.monotonic",
            lambda: fake_now[0],
        )
        queue = UploadQueue(max_slots=4, slot_ttl=10.0)
        file_hash = _make_file_hash()
        key_a = _make_user_hash(1)
        key_b = _make_user_hash(2)
        queue.enqueue(key_a, 1, 1, "a", file_hash, UploadPriority.NORMAL)
        queue.enqueue(key_b, 2, 2, "b", file_hash, UploadPriority.NORMAL)
        queue.grant_slot(key_a, file_hash)
        queue.grant_slot(key_b, file_hash)

        assert queue.expired_slots() == []

        fake_now[0] = 1009.9
        assert queue.expired_slots() == []

        fake_now[0] = 1010.1
        expired = queue.expired_slots()
        assert len(expired) == 2
        assert (key_a, file_hash) in expired
        assert (key_b, file_hash) in expired

    def test_expired_slots_with_zero_ttl(self) -> None:
        queue = UploadQueue(max_slots=2, slot_ttl=0.0)
        file_hash = _make_file_hash()
        key = _make_user_hash(1)
        queue.enqueue(key, 1, 1, "a", file_hash, UploadPriority.NORMAL)
        queue.grant_slot(key, file_hash)
        assert len(queue.expired_slots()) == 1

    def test_cancel_removes_waiting_client(self) -> None:
        queue = UploadQueue(max_slots=10)
        file_hash = _make_file_hash()
        key_a = _make_user_hash(1)
        key_b = _make_user_hash(2)
        queue.enqueue(key_a, 1, 1, "a", file_hash, UploadPriority.NORMAL)
        queue.enqueue(key_b, 2, 2, "b", file_hash, UploadPriority.HIGH)
        assert queue.cancel(key_a, file_hash) is True
        ranks = queue.snapshot()["queue"]
        assert len(ranks) == 1
        assert ranks[0]["rank"] == 1

    def test_cancel_removes_granted_slot(self) -> None:
        queue = UploadQueue(max_slots=2, slot_ttl=600.0)
        file_hash = _make_file_hash()
        key = _make_user_hash(1)
        queue.enqueue(key, 1, 1, "a", file_hash, UploadPriority.NORMAL)
        queue.grant_slot(key, file_hash)
        assert queue.cancel(key, file_hash) is True
        assert queue.is_active(key, file_hash) is False
        assert len(queue.snapshot()["queue"]) == 0

    def test_cancel_returns_false_when_absent(self) -> None:
        queue = UploadQueue(max_slots=10)
        file_hash = _make_file_hash()
        assert queue.cancel(_make_user_hash(1), file_hash) is False

    def test_snapshot_fields(self) -> None:
        queue = UploadQueue(max_slots=3, slot_ttl=5.0)
        file_hash = _make_file_hash()
        key_a = _make_user_hash(1)
        key_b = _make_user_hash(2)
        queue.enqueue(key_a, 1, 1, "a", file_hash, UploadPriority.NORMAL)
        queue.enqueue(key_b, 2, 2, "b", file_hash, UploadPriority.HIGH)
        queue.grant_slot(key_b, file_hash)

        snap = queue.snapshot()
        assert snap["max_slots"] == 3
        assert snap["active_slots"] == 1
        assert snap["waiting"] == 1
        assert len(snap["queue"]) == 1
        client_dict = snap["queue"][0]
        assert client_dict["user_hash"] == key_a
        assert client_dict["requested_hash"] == file_hash
        assert client_dict["rank"] == 1

    def test_normalize_hash_rejects_invalid_hash(self) -> None:
        with pytest.raises(UploadQueueError):
            UploadQueue().enqueue("not-a-hash", 1, 1, "x", _make_file_hash())

    def test_duplicate_enqueue_after_grant_returns_zero(self) -> None:
        queue = UploadQueue(max_slots=2, slot_ttl=600.0)
        file_hash = _make_file_hash()
        key = _make_user_hash(1)
        queue.enqueue(key, 1, 1, "a", file_hash, UploadPriority.NORMAL)
        queue.grant_slot(key, file_hash)
        result = queue.enqueue(key, 1, 1, "a", file_hash, UploadPriority.NORMAL)
        assert result == 0

    def test_waiting_preserves_priority_then_fifo_order(self) -> None:
        queue = UploadQueue(max_slots=10)
        file_hash = _make_file_hash()
        hi = _make_user_hash(1)
        n1 = _make_user_hash(2)
        n2 = _make_user_hash(3)
        lo = _make_user_hash(4)
        queue.enqueue(lo, 1, 1, "lo", file_hash, UploadPriority.LOW)
        queue.enqueue(n1, 2, 2, "n1", file_hash, UploadPriority.NORMAL)
        queue.enqueue(hi, 3, 3, "hi", file_hash, UploadPriority.HIGH)
        queue.enqueue(n2, 4, 4, "n2", file_hash, UploadPriority.NORMAL)

        waiting = queue.waiting()
        assert [c.user_hash for c in waiting] == [hi, n1, n2, lo]
        assert [c.rank for c in waiting] == [1, 2, 3, 4]

    def test_upload_client_to_dict_fields(self) -> None:
        key = _make_user_hash(1)
        fhash = _make_file_hash()
        client = UploadClient(
            user_hash=key,
            client_id=123,
            client_port=4567,
            nickname="tester",
            requested_hash=fhash,
            file_priority=UploadPriority.HIGH,
            enqueued_at=42.0,
            rank=1,
        )
        d = client.to_dict()
        assert d["user_hash"] == key
        assert d["client_id"] == 123
        assert d["client_port"] == 4567
        assert d["nickname"] == "tester"
        assert d["requested_hash"] == fhash
        assert d["file_priority"] == UploadPriority.HIGH
        assert d["enqueued_at"] == 42.0
        assert d["rank"] == 1

    def test_upload_priority_values(self) -> None:
        assert UploadPriority.LOW == 0
        assert UploadPriority.NORMAL == 1
        assert UploadPriority.HIGH == 2
        assert UploadPriority.LOW < UploadPriority.NORMAL < UploadPriority.HIGH

    def test_next_for_slot_returns_head(self) -> None:
        queue = UploadQueue(max_slots=10)
        file_hash = _make_file_hash()
        queue.enqueue(_make_user_hash(2), 1, 1, "b", file_hash, UploadPriority.NORMAL)
        queue.enqueue(_make_user_hash(1), 2, 2, "a", file_hash, UploadPriority.HIGH)
        head = queue.next_for_slot()
        assert head is not None
        assert head.user_hash == _make_user_hash(1)

    def test_next_for_slot_none_when_full(self) -> None:
        queue = UploadQueue(max_slots=1)
        file_hash = _make_file_hash()
        queue.enqueue(_make_user_hash(1), 1, 1, "a", file_hash, UploadPriority.NORMAL)
        queue.grant_slot(_make_user_hash(1), file_hash)
        assert queue.next_for_slot() is None

    def test_next_for_slot_none_when_empty(self) -> None:
        queue = UploadQueue(max_slots=2)
        assert queue.next_for_slot() is None

    def test_rank_of_returns_none_when_absent(self) -> None:
        queue = UploadQueue(max_slots=10)
        file_hash = _make_file_hash()
        assert queue.rank_of(_make_user_hash(1), file_hash) is None

    def test_rank_of_returns_current_rank(self) -> None:
        queue = UploadQueue(max_slots=10)
        file_hash = _make_file_hash()
        key = _make_user_hash(1)
        queue.enqueue(key, 1, 1, "a", file_hash, UploadPriority.NORMAL)
        assert queue.rank_of(key, file_hash) == 1


class TestBlockSource:
    """BlockSource bounds checking and chunk metadata."""

    def test_read_block_beyond_size_raises(self, tmp_path) -> None:
        data = b"x" * 100
        path = tmp_path / "data.bin"
        path.write_bytes(data)
        shared = SharedFile(
            file_hash=_TEST_HASH,
            name="data.bin",
            size=len(data),
            path=str(path),
        )
        source = BlockSource(shared)
        source.open()
        try:
            with pytest.raises(UploadEngineError, match="exceeds file size"):
                source.read_block(50, 100)
        finally:
            source.close()

    def test_read_block_negative_start_raises(self, tmp_path) -> None:
        data = b"x" * 100
        path = tmp_path / "data.bin"
        path.write_bytes(data)
        shared = SharedFile(
            file_hash=_TEST_HASH,
            name="data.bin",
            size=len(data),
            path=str(path),
        )
        source = BlockSource(shared)
        source.open()
        try:
            with pytest.raises(UploadEngineError, match="negative"):
                source.read_block(-1, 10)
        finally:
            source.close()

    def test_read_block_negative_length_raises(self, tmp_path) -> None:
        data = b"x" * 100
        path = tmp_path / "data.bin"
        path.write_bytes(data)
        shared = SharedFile(
            file_hash=_TEST_HASH,
            name="data.bin",
            size=len(data),
            path=str(path),
        )
        source = BlockSource(shared)
        source.open()
        try:
            with pytest.raises(UploadEngineError, match="negative"):
                source.read_block(0, -1)
        finally:
            source.close()

    def test_read_block_short_read_raises(self, tmp_path) -> None:
        data = b"short file content"
        path = tmp_path / "short.bin"
        path.write_bytes(data)
        shared = SharedFile(
            file_hash=_TEST_HASH,
            name="short.bin",
            size=len(data) + 100,
            path=str(path),
        )
        source = BlockSource(shared)
        source.open()
        try:
            with pytest.raises(UploadEngineError, match="short read"):
                source.read_block(0, len(data) + 1)
        finally:
            source.close()

    def test_read_block_returns_correct_bytes(self, tmp_path) -> None:
        data = bytes(range(256)) * 4
        path = tmp_path / "data.bin"
        path.write_bytes(data)
        shared = SharedFile(
            file_hash=_TEST_HASH,
            name="data.bin",
            size=len(data),
            path=str(path),
        )
        source = BlockSource(shared)
        source.open()
        try:
            result = source.read_block(10, 20)
            assert result == data[10:30]
        finally:
            source.close()

    def test_chunk_count_for_small_file(self, tmp_path) -> None:
        data = b"x" * 300_000
        path = tmp_path / "small.bin"
        path.write_bytes(data)
        shared = SharedFile(
            file_hash=_TEST_HASH,
            name="small.bin",
            size=len(data),
            path=str(path),
        )
        source = BlockSource(shared)
        assert source.chunk_count == 1
        assert source.present_chunks == [0]

    def test_chunk_count_uses_partsize_boundary(self, tmp_path) -> None:
        data = b"x" * (PARTSIZE + 1)
        path = tmp_path / "boundary.bin"
        path.write_bytes(data)
        shared = SharedFile(
            file_hash=_TEST_HASH,
            name="boundary.bin",
            size=len(data),
            path=str(path),
        )
        source = BlockSource(shared)
        assert source.chunk_count == 2
        assert source.present_chunks == [0, 1]

    def test_chunk_count_zero_size_is_one(self, tmp_path) -> None:
        path = tmp_path / "empty.bin"
        path.write_bytes(b"")
        shared = SharedFile(
            file_hash=_TEST_HASH,
            name="empty.bin",
            size=0,
            path=str(path),
        )
        source = BlockSource(shared)
        assert source.chunk_count == 1
        assert source.present_chunks == [0]

    def test_open_without_path_raises(self) -> None:
        shared = SharedFile(file_hash=_TEST_HASH, name="nope.bin", size=10)
        with pytest.raises(UploadEngineError, match="no path"):
            BlockSource(shared)

    def test_read_block_requires_open(self, tmp_path) -> None:
        data = b"x" * 100
        path = tmp_path / "data.bin"
        path.write_bytes(data)
        shared = SharedFile(
            file_hash=_TEST_HASH,
            name="data.bin",
            size=len(data),
            path=str(path),
        )
        source = BlockSource(shared)
        with pytest.raises(UploadEngineError, match="not open"):
            source.read_block(0, 10)

    def test_context_manager_closes(self, tmp_path) -> None:
        data = b"x" * 100
        path = tmp_path / "data.bin"
        path.write_bytes(data)
        shared = SharedFile(
            file_hash=_TEST_HASH,
            name="data.bin",
            size=len(data),
            path=str(path),
        )
        with BlockSource(shared) as source:
            assert source.read_block(0, 10) == b"x" * 10
        with pytest.raises(UploadEngineError, match="not open"):
            source.read_block(0, 10)

    def test_file_hash_property(self, tmp_path) -> None:
        data = b"x" * 100
        path = tmp_path / "data.bin"
        path.write_bytes(data)
        shared = SharedFile(
            file_hash=_TEST_HASH,
            name="x.bin",
            size=len(data),
            path=str(path),
        )
        with BlockSource(shared) as source:
            assert source.file_hash == _TEST_HASH

    def test_file_size_property(self, tmp_path) -> None:
        data = b"x" * 100
        path = tmp_path / "data.bin"
        path.write_bytes(data)
        shared = SharedFile(
            file_hash=_TEST_HASH,
            name="x.bin",
            size=len(data),
            path=str(path),
        )
        with BlockSource(shared) as source:
            assert source.file_size == 100

    def test_nonexistent_path_raises(self, tmp_path) -> None:
        shared = SharedFile(
            file_hash=_TEST_HASH,
            name="ghost.bin",
            size=10,
            path=str(tmp_path / "does_not_exist.bin"),
        )
        with pytest.raises(UploadEngineError, match="does not exist"):
            BlockSource(shared)


class TestUploadThrottle:
    """UploadThrottle rate-limiting behavior."""

    @pytest.mark.asyncio
    async def test_high_rate_throttles_quickly(self) -> None:
        throttle = UploadThrottle(rate_bytes_per_sec=10**9)
        start = time.monotonic()
        await throttle.throttle(1024)
        elapsed = time.monotonic() - start
        assert elapsed < 0.05

    @pytest.mark.asyncio
    async def test_none_rate_no_delay(self) -> None:
        throttle = UploadThrottle(rate_bytes_per_sec=None)
        start = time.monotonic()
        await throttle.throttle(1024)
        elapsed = time.monotonic() - start
        assert elapsed < 0.05

    @pytest.mark.asyncio
    async def test_positive_rate_no_delay(self) -> None:
        throttle = UploadThrottle(rate_bytes_per_sec=None)
        start = time.monotonic()
        await throttle.throttle(1_000_000)
        elapsed = time.monotonic() - start
        assert elapsed < 0.05

    @pytest.mark.asyncio
    async def test_very_low_rate_waits(self) -> None:
        throttle = UploadThrottle(rate_bytes_per_sec=1)
        start = time.monotonic()
        await throttle.throttle(1)
        elapsed = time.monotonic() - start
        assert elapsed >= 0.5

    def test_zero_rate_raises(self) -> None:
        with pytest.raises(Exception):
            UploadThrottle(rate_bytes_per_sec=0)

    def test_negative_rate_raises(self) -> None:
        with pytest.raises(Exception):
            UploadThrottle(rate_bytes_per_sec=-1)

    @pytest.mark.asyncio
    async def test_reset_clears_state(self) -> None:
        throttle = UploadThrottle(rate_bytes_per_sec=10**9)
        await throttle.throttle(100)
        throttle.reset()
        assert throttle._last_send_time == 0.0
        assert throttle._bytes_sent == 0

    @pytest.mark.asyncio
    async def test_throttle_no_sleep_on_first_call(self) -> None:
        throttle = UploadThrottle(rate_bytes_per_sec=10**9)
        assert throttle._last_send_time == 0.0
        start = time.monotonic()
        await throttle.throttle(100)
        elapsed = time.monotonic() - start
        assert elapsed < 0.05

    @pytest.mark.asyncio
    async def test_throttle_resets_after_deficit(self) -> None:
        throttle = UploadThrottle(rate_bytes_per_sec=1)
        await throttle.throttle(2)
        assert throttle._bytes_sent == 0
        assert throttle._last_send_time != 0.0


class TestUploadSession:
    """UploadSession end-to-end behavior over a FakeTransport."""

    @pytest.fixture
    def shared_file(self, tmp_path) -> SharedFile:
        content = os.urandom(300_000)
        path = tmp_path / "testfile.dat"
        path.write_bytes(content)
        hash_result = ed2k_hash_file(str(path))
        return SharedFile(
            file_hash=hash_result.file_hash,
            name="testfile.dat",
            size=hash_result.file_size,
            path=str(path.resolve()),
            hash_result=hash_result,
        )

    @pytest.fixture
    def block_source(self, shared_file) -> BlockSource:
        return BlockSource(shared_file)

    @pytest.fixture
    def content(self, block_source) -> bytes:
        with open(block_source._path, "rb") as fh:
            return fh.read()

    def test_request_filename_expects_reqfilenameanswer(self, block_source) -> None:
        transport = FakeTransport(
            [(OP_REQUESTFILENAME, block_source.file_hash)]
        )
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())

        sent = transport.sent
        assert len(sent) == 1
        opcode, payload = sent[0]
        assert opcode == OP_REQFILENAMEANSWER

        answer = parse_filename_answer(payload)
        assert answer.file_hash == block_source.file_hash
        assert answer.name == "testfile.dat"

    def test_hashset_request_expects_hashsetanswer(self, block_source) -> None:
        transport = FakeTransport(
            [(OP_HASHSETREQUEST, block_source.file_hash)]
        )
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())

        sent = transport.sent
        assert len(sent) == 1
        opcode, payload = sent[0]
        assert opcode == OP_HASHSETANSWER

        answer = parse_hashset_answer(payload)
        assert answer.file_hash == block_source.file_hash
        chunk_hashes = block_source.chunk_hashes
        assert len(answer.chunk_hashes) == len(chunk_hashes)
        for sent_hash, expected in zip(answer.chunk_hashes, chunk_hashes):
            assert sent_hash == expected

    def test_request_parts_i64_three_ranges_covered(self, block_source, content) -> None:
        file_hash = block_source.file_hash
        file_size = block_source.file_size

        ranges = [(0, 100_000), (100_000, 200_000), (200_000, 201_000)]
        payload = _build_i64_payload(file_hash, ranges, file_size)

        transport = FakeTransport(
            [(OP_REQUESTPARTS_I64, payload)]
        )
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())

        sent = transport.sent
        assert len(sent) >= 1
        parts = _parse_sending_parts(sent)
        assert len(parts) >= 3

        for part in parts:
            assert part.file_hash == file_hash
            assert part.start < part.end
            if part.end - part.start > 1:
                assert part.data == content[part.start:part.end]

        for req_start, req_end in ranges:
            matching = _filter_range(parts, [(req_start, req_end)])
            assert matching, f"no sub-packets for range ({req_start}, {req_end})"
            reassembled = b"".join(
                part.data for part in sorted(matching, key=lambda p: p.start)
            )
            assert reassembled == content[req_start:req_end]

    def test_request_parts_i64_large_range_splitting(self, block_source, content) -> None:
        file_hash = block_source.file_hash
        file_size = block_source.file_size

        start, end = 0, 130_000
        payload = _build_i64_payload(file_hash, [(start, end)], file_size)
        transport = FakeTransport(
            [(OP_REQUESTPARTS_I64, payload)]
        )
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())

        sent = transport.sent
        parts = _filter_range(_parse_sending_parts(sent), [(start, end)])
        assert len(parts) >= 1

        for part in parts:
            assert part.start < part.end
            assert part.data == content[part.start:part.end]
            chunk_len = part.end - part.start
            assert chunk_len <= SPLIT_THRESHOLD

        first = parts[0]
        assert first.start == 0
        assert first.end == SPLIT_CHUNK_SIZE
        assert len(first.data) == SPLIT_CHUNK_SIZE

        last = parts[-1]
        assert last.end == 130_000
        expected_last_start = 130_000 - (130_000 % SPLIT_CHUNK_SIZE) if 130_000 % SPLIT_CHUNK_SIZE else 130_000 - SPLIT_CHUNK_SIZE
        assert last.start == expected_last_start
        assert last.data == content[last.start:last.end]

        reassembled = b"".join(
            part.data for part in sorted(parts, key=lambda p: p.start)
        )
        assert reassembled == content[0:130_000]

    def test_request_parts_i64_small_16_byte_range(self, block_source, content) -> None:
        file_hash = block_source.file_hash
        file_size = block_source.file_size

        start, end = file_size - 16, file_size
        payload = _build_i64_payload(file_hash, [(start, end)], file_size)
        transport = FakeTransport(
            [(OP_REQUESTPARTS_I64, payload)]
        )
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())

        sent = transport.sent
        parts = _filter_range(_parse_sending_parts(sent), [(start, end)])
        assert len(parts) == 1
        sp = parts[0]
        assert sp.start == start
        assert sp.end == end
        assert sp.data == content[start:end]

    def test_compressed_part_for_zero_range(self, tmp_path) -> None:
        content = b"\x00" * 65_536
        path = tmp_path / "zeros.bin"
        path.write_bytes(content)
        hash_result = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hash_result.file_hash,
            name="zeros.bin",
            size=hash_result.file_size,
            path=str(path.resolve()),
            hash_result=hash_result,
        )
        source = BlockSource(shared)

        file_hash = source.file_hash
        start, end = 0, 65_536
        payload = _build_i64_payload(file_hash, [(start, end)], source.file_size)
        transport = FakeTransport(
            [(OP_REQUESTPARTS_I64, payload)]
        )
        session = UploadSession(transport, source)
        asyncio.run(session.run())

        sent = transport.sent
        compressed_parts = _filter_range(
            _parse_sending_parts(sent), [(start, end)]
        )
        assert len(compressed_parts) == 1
        sp = compressed_parts[0]
        assert sp.start == 0
        assert sp.end == 65_536
        assert sp.data == content

    def test_end_of_download_terminates_session(self, block_source) -> None:
        transport = FakeTransport(
            [(OP_END_OF_DOWNLOAD, block_source.file_hash)]
        )
        session = UploadSession(transport, block_source)
        stats = asyncio.run(session.run())

        assert transport.sent == []
        assert stats.requests_handled == 0
        assert stats.blocks_sent == 0
        assert stats.bytes_sent == 0
        assert stats.ended_at >= stats.started_at

    def test_eof_terminates_session(self, block_source) -> None:
        transport = FakeTransport([])
        session = UploadSession(transport, block_source)
        stats = asyncio.run(session.run())
        assert stats.blocks_sent == 0
        assert stats.ended_at >= stats.started_at

    def test_session_stats_after_filename(self, block_source) -> None:
        transport = FakeTransport(
            [(OP_REQUESTFILENAME, block_source.file_hash)]
        )
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())
        assert session.stats.blocks_sent == 0
        assert session.stats.bytes_sent == 0
        assert session.stats.requests_handled == 0
        assert session.stats.compressed_blocks == 0
        assert session.stats.ended_at >= session.stats.started_at

    def test_session_multiple_packets_sequence(self, block_source, content) -> None:
        file_hash = block_source.file_hash
        file_size = block_source.file_size

        req_start, req_end = file_size - 500, file_size
        payload = _build_i64_payload(file_hash, [(req_start, req_end)], file_size)
        transport = FakeTransport(
            [
                (OP_REQUESTFILENAME, file_hash),
                (OP_HASHSETREQUEST, file_hash),
                (OP_REQUESTPARTS_I64, payload),
                (OP_END_OF_DOWNLOAD, file_hash),
            ]
        )
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())

        opcodes = transport.sent_opcodes()
        assert opcodes[0] == OP_REQFILENAMEANSWER
        assert opcodes[1] == OP_HASHSETANSWER
        assert opcodes[2] in (OP_SENDINGPART, OP_SENDINGPART_I64)
        assert len(transport.sent) == len(opcodes)

        sp_opcode, sp_payload = transport.sent[2]
        sp = parse_sending_part(sp_payload) if sp_opcode == OP_SENDINGPART else parse_sending_part_i64(sp_payload)
        assert sp.file_hash == file_hash
        assert sp.data == content[req_start:req_end]

    def test_no_compression_when_not_smaller(self, tmp_path) -> None:
        content = os.urandom(100_000)
        path = tmp_path / "random.bin"
        path.write_bytes(content)
        hash_result = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hash_result.file_hash,
            name="random.bin",
            size=hash_result.file_size,
            path=str(path.resolve()),
            hash_result=hash_result,
        )
        source = BlockSource(shared)

        file_hash = source.file_hash
        start, end = 0, len(content)
        payload = _build_i64_payload(file_hash, [(start, end)], len(content))
        transport = FakeTransport([(OP_REQUESTPARTS_I64, payload)])
        session = UploadSession(transport, source)
        asyncio.run(session.run())

        parts = _filter_range(_parse_sending_parts(transport.sent), [(start, end)])
        assert len(parts) >= 1
        assert session.stats.compressed_blocks == 0

    def test_compression_enabled_for_zeros(self, tmp_path) -> None:
        content = b"\x00" * 65_536
        path = tmp_path / "zeros.bin"
        path.write_bytes(content)
        hash_result = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hash_result.file_hash,
            name="zeros.bin",
            size=hash_result.file_size,
            path=str(path.resolve()),
            hash_result=hash_result,
        )
        source = BlockSource(shared)

        file_hash = source.file_hash
        start, end = 0, len(content)
        payload = _build_i64_payload(file_hash, [(start, end)], len(content))
        transport = FakeTransport([(OP_REQUESTPARTS_I64, payload)])
        session = UploadSession(transport, source)
        asyncio.run(session.run())

        parts = _filter_range(_parse_sending_parts(transport.sent), [(start, end)])
        assert len(parts) >= 1
        assert all(p.__class__.__name__ == "SendingPart" for p in parts)
        assert session.stats.compressed_blocks >= 1

    def test_compression_disabled_by_flag(self, tmp_path) -> None:
        content = b"\x00" * 65_536
        path = tmp_path / "zeros.bin"
        path.write_bytes(content)
        hash_result = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hash_result.file_hash,
            name="zeros.bin",
            size=hash_result.file_size,
            path=str(path.resolve()),
            hash_result=hash_result,
        )
        source = BlockSource(shared)

        file_hash = source.file_hash
        start, end = 0, len(content)
        payload = _build_i64_payload(file_hash, [(start, end)], len(content))
        transport = FakeTransport([(OP_REQUESTPARTS_I64, payload)])
        session = UploadSession(transport, source, allow_compression=False)
        asyncio.run(session.run())

        for opcode, _ in transport.sent:
            assert opcode in (OP_SENDINGPART, OP_SENDINGPART_I64)
        assert session.stats.compressed_blocks == 0

    def test_session_stats_to_dict(self, block_source) -> None:
        transport = FakeTransport([(OP_REQUESTFILENAME, block_source.file_hash)])
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())
        d = session.stats.to_dict()
        assert "blocks_sent" in d
        assert "bytes_sent" in d
        assert "compressed_blocks" in d
        assert "requests_handled" in d
        assert "started_at" in d
        assert "ended_at" in d
        assert "duration" in d

    def test_session_requests_handled_increment(self, block_source) -> None:
        file_hash = block_source.file_hash
        file_size = block_source.file_size

        req_start, req_end = file_size - 500, file_size
        payload = _build_i64_payload(file_hash, [(req_start, req_end)], file_size)
        transport = FakeTransport(
            [
                (OP_HASHSETREQUEST, file_hash),
                (OP_REQUESTPARTS_I64, payload),
                (OP_END_OF_DOWNLOAD, file_hash),
            ]
        )
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())
        assert session.stats.requests_handled == 1

    def test_session_bytes_sent_accumulates(self, block_source) -> None:
        file_hash = block_source.file_hash
        file_size = block_source.file_size

        req_start, req_end = file_size - 500, file_size
        payload = _build_i64_payload(file_hash, [(req_start, req_end)], file_size)
        transport = FakeTransport([(OP_REQUESTPARTS_I64, payload)])
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())
        assert session.stats.bytes_sent > 0
        assert session.stats.blocks_sent >= 1

    def test_session_unknown_opcode_ignored(self, block_source) -> None:
        transport = FakeTransport([
            (0xFF, b"\x00" * 16),
            (OP_END_OF_DOWNLOAD, block_source.file_hash),
        ])
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())
        assert transport.sent == []
        assert session.stats.requests_handled == 0

    def test_session_peer_codec_error_on_bad_payload(self, block_source) -> None:
        transport = FakeTransport([
            (OP_REQUESTPARTS_I64, b"\x00" * 20),
            (OP_END_OF_DOWNLOAD, block_source.file_hash),
        ])
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())
        assert transport.sent == []


class TestUploadSessionEdgeCases:
    """UploadSession parsing and wire-format edge cases."""

    @pytest.fixture
    def shared_file(self, tmp_path) -> SharedFile:
        content = os.urandom(50_000)
        path = tmp_path / "data.bin"
        path.write_bytes(content)
        hash_result = ed2k_hash_file(str(path))
        return SharedFile(
            file_hash=hash_result.file_hash,
            name="data.bin",
            size=hash_result.file_size,
            path=str(path.resolve()),
            hash_result=hash_result,
        )

    @pytest.fixture
    def block_source(self, shared_file) -> BlockSource:
        return BlockSource(shared_file)

    @pytest.fixture
    def content(self, block_source) -> bytes:
        with open(block_source._path, "rb") as fh:
            return fh.read()

    def test_requestparts_without_i64_uses_plain_sendingpart(self, block_source, content) -> None:
        file_hash = block_source.file_hash
        file_size = block_source.file_size

        payload = _build_plain_payload(file_hash, [(0, file_size)], file_size)
        transport = FakeTransport([(OP_REQUESTPARTS, payload)])
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())

        parts = _filter_range(_parse_sending_parts(transport.sent), [(0, file_size)])
        reassembled = b"".join(
            part.data for part in sorted(parts, key=lambda p: p.start)
        )
        assert reassembled == content[0:file_size]

    def test_sendingpart_subpacket_exact_13000_boundary(self, tmp_path) -> None:
        content = os.urandom(130_000)
        path = tmp_path / "data.bin"
        path.write_bytes(content)
        hash_result = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hash_result.file_hash,
            name="data.bin",
            size=hash_result.file_size,
            path=str(path.resolve()),
            hash_result=hash_result,
        )
        source = BlockSource(shared)
        file_hash = source.file_hash

        payload = _build_i64_payload(file_hash, [(0, 130_000)], len(content))
        transport = FakeTransport([(OP_REQUESTPARTS_I64, payload)])
        session = UploadSession(transport, source)
        asyncio.run(session.run())

        sent = transport.sent
        parts = _filter_range(_parse_sending_parts(sent), [(0, 130_000)])
        reassembly: dict[int, bytes] = {}
        for part in parts:
            chunk_len = part.end - part.start
            remaining = 130_000 - part.end
            if remaining > 0:
                assert chunk_len == SPLIT_CHUNK_SIZE
            else:
                assert chunk_len <= SPLIT_THRESHOLD
            reassembly[part.start] = part.data

        reassembled = b"".join(reassembly[k] for k in sorted(reassembly))
        assert reassembled == content[0:130_000]

    def test_sendingpart_subpacket_exactly_threshold(self, tmp_path) -> None:
        content = os.urandom(SPLIT_THRESHOLD)
        path = tmp_path / "data.bin"
        path.write_bytes(content)
        hash_result = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hash_result.file_hash,
            name="data.bin",
            size=hash_result.file_size,
            path=str(path.resolve()),
            hash_result=hash_result,
        )
        source = BlockSource(shared)
        file_hash = source.file_hash

        payload = _build_i64_payload(file_hash, [(0, len(content))], len(content))
        transport = FakeTransport([(OP_REQUESTPARTS_I64, payload)])
        session = UploadSession(transport, source)
        asyncio.run(session.run())

        sent = transport.sent
        parts = _filter_range(_parse_sending_parts(sent), [(0, len(content))])
        assert len(parts) == 1
        sp = parts[0]
        assert sp.end - sp.start == SPLIT_THRESHOLD
        assert sp.data == content

    def test_compressed_part_roundtrip_via_codec(self, tmp_path) -> None:
        content = b"\x00" * 65_536
        path = tmp_path / "zeros.bin"
        path.write_bytes(content)
        hash_result = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hash_result.file_hash,
            name="zeros.bin",
            size=hash_result.file_size,
            path=str(path.resolve()),
            hash_result=hash_result,
        )
        source = BlockSource(shared)
        file_hash = source.file_hash

        payload = _build_i64_payload(file_hash, [(0, len(content))], len(content))
        transport = FakeTransport([(OP_REQUESTPARTS_I64, payload)])
        session = UploadSession(transport, source)
        asyncio.run(session.run())

        sent = transport.sent
        parts = _filter_range(_parse_sending_parts(sent), [(0, len(content))])
        assert len(parts) == 1
        sp = parts[0]
        assert sp.start == 0
        assert sp.end == 65_536
        assert sp.data == content

    def test_multiple_ranges_produce_separate_subpacket_groups(self, block_source, content) -> None:
        file_hash = block_source.file_hash

        ranges = [(0, 10_000), (20_000, 30_000), (40_000, 50_000)]
        payload = _build_i64_payload(file_hash, ranges, len(content))
        transport = FakeTransport([(OP_REQUESTPARTS_I64, payload)])
        session = UploadSession(transport, block_source)
        asyncio.run(session.run())

        sent = transport.sent
        parts = _parse_sending_parts(sent)
        for part in parts:
            assert part.file_hash == file_hash

        for req_start, req_end in ranges:
            matching = _filter_range(parts, [(req_start, req_end)])
            assert matching, f"no sub-packets for range ({req_start}, {req_end})"
            reassembled = b"".join(
                part.data for part in sorted(matching, key=lambda p: p.start)
            )
            assert reassembled == content[req_start:req_end]

def test_credit_bonus_promotes_generous_client() -> None:
    """Stage X: credits -> priority.  A client with a higher credit bonus
    outranks an earlier-enqueued client despite identical file priority."""
    from amuled_v2.core.upload.queue import UploadQueue

    bonus = {("b" * 32): 5.0}
    queue = UploadQueue(
        max_slots=1, credit_bonus=lambda uh: bonus.get(uh, 1.0)
    )
    file_hash = "ab" * 16
    queue.enqueue("a" * 32, 1, 4662, "plain", file_hash)
    rank_b = queue.enqueue("b" * 32, 2, 4662, "generous", file_hash)
    assert rank_b == 1
    assert queue.rank_of("a" * 32, file_hash) == 2

    # Snapshot carries the refreshed bonus values.
    snapshot = queue.snapshot()
    entries = {c["user_hash"]: c for c in snapshot["queue"]}
    assert entries["a" * 32]["credit_bonus"] == 1.0
    assert entries["b" * 32]["credit_bonus"] == 5.0
