"""Offline tests for the download queue and part files.

Pure file-format and DuckDB tests; no network, no fake ED2K servers.

tests/test_download_queue.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Tested part-file creation, gap updates, bitmaps, and resume.
  [+] Tested queue lifecycle, block writes, cancel, and finalize.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import amuled_v2.state as state_module
from amuled_v2.core.download import (
    DownloadQueue,
    DownloadQueueError,
    DownloadStatus,
    ED2K_CHUNK_SIZE,
    PartFile,
    PartFileError,
)
from amuled_v2.core.ed2k import parse_ed2k_file_link


@pytest.fixture()
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(state_module, "DB_FILE", tmp_path / "state.db")
    backend = state_module.StateBackend()
    backend.connect()
    yield backend
    backend.close()


@pytest.fixture()
def queue(tmp_path: Path, isolated_state) -> DownloadQueue:
    DownloadQueue.__init__.__wrapped__ if hasattr(DownloadQueue.__init__, "__wrapped__") else None
    return DownloadQueue(
        state=isolated_state,
        temp_dir=tmp_path / "temp",
        incoming_dir=tmp_path / "incoming",
    )


def _parse_size(display: str) -> int:
    text = display.strip().lower()
    units = {"b": 1, "kb": 1_000, "mb": 1_000_000, "gb": 1_000_000_000, "tb": 1_000_000_000_000}
    binary = {"kib": 1024, "mib": 1024**2, "gib": 1024**3, "tib": 1024**4}
    parts = text.split()
    if len(parts) == 1:
        number, unit = "", parts[0]
    else:
        number, unit = parts[0], parts[1]
    factor = units.get(unit, binary.get(unit))
    if factor is None:
        raise ValueError(f"unrecognized size unit: {unit}")
    return int(float(number) * factor)


def _real_target() -> object:
    shared = Path(r"K:\work\AmuleD_v2\assets\v1\shared_files.json")
    if not shared.exists():
        pytest.skip("local shared_files.json unavailable")
    with open(shared, "r", encoding="utf-8") as handle:
        items = json.load(handle)
    if not items:
        pytest.skip("shared_files.json is empty")
    item = items[0]
    size = _parse_size(item["size"])
    link = f"ed2k://|file|{item['name']}|{size}|{item['hash']}|/"
    return parse_ed2k_file_link(link)


# ---------------------------------------------------------------------------
# PartFile tests
# ---------------------------------------------------------------------------

def test_part_file_creates_preallocated_file(tmp_path: Path) -> None:
    total_size = 10_000
    part_path = tmp_path / "00112233445566778899aabbccddeeff.part"
    part = PartFile(part_path, total_size, "00112233445566778899aabbccddeeff", "sample.bin")
    part.open_new()
    try:
        data_path = Path(part_path)
        assert data_path.exists()
        assert data_path.stat().st_size == total_size
        sidecar = Path(str(part_path) + ".amuled.json")
        assert sidecar.exists()
        assert len(part.gaps) == 1
        assert part.gaps[0].start == 0
        assert part.gaps[0].end == total_size
    finally:
        part.close()


def test_part_file_write_block_updates_gaps(tmp_path: Path) -> None:
    total_size = 10_000
    part_path = tmp_path / "00112233445566778899aabbccddeeff.part"
    part = PartFile(part_path, total_size, "00112233445566778899aabbccddeeff", "sample.bin")
    part.open_new()
    try:
        remaining = part.write_block(3_000, b"x" * 4_000)
        assert remaining == 6_000
        assert len(part.gaps) == 2
        assert part.gaps[0].start == 0
        assert part.gaps[0].end == 3_000
        assert part.gaps[1].start == 7_000
        assert part.gaps[1].end == 10_000
        assert part.downloaded_bytes == 4_000
    finally:
        part.close()


def test_part_file_gap_merge_on_full_fill(tmp_path: Path) -> None:
    total_size = 10_000
    part_path = tmp_path / "00112233445566778899aabbccddeeff.part"
    part = PartFile(part_path, total_size, "00112233445566778899aabbccddeeff", "sample.bin")
    part.open_new()
    try:
        block_size = 2_000
        for start in range(0, total_size, block_size):
            part.write_block(start, b"y" * block_size)
        assert part.is_complete is True
        assert part.gaps == []
        assert all(part.chunk_bitmap())
    finally:
        part.close()


def test_part_file_resume_restores_state(tmp_path: Path) -> None:
    total_size = 10_000
    part_path = tmp_path / "00112233445566778899aabbccddeeff.part"
    part = PartFile(part_path, total_size, "00112233445566778899aabbccddeeff", "sample.bin")
    part.open_new()
    try:
        part.write_block(0, b"z" * 4_000)
        part.save()
        saved_gaps = list(part.gaps)
        saved_remaining = part.remaining_bytes
    finally:
        part.close()

    resumed = PartFile.resume(part_path)
    try:
        assert resumed.remaining_bytes == saved_remaining
        assert len(resumed.gaps) == len(saved_gaps)
        for original, restored in zip(saved_gaps, resumed.gaps):
            assert restored.start == original.start
            assert restored.end == original.end
        resumed.write_block(4_000, b"w" * 6_000)
        assert resumed.is_complete is True
    finally:
        resumed.close()


def test_part_file_chunk_bitmap_two_chunks(tmp_path: Path) -> None:
    total_size = ED2K_CHUNK_SIZE + 100
    part_path = tmp_path / "00112233445566778899aabbccddeeff.part"
    part = PartFile(part_path, total_size, "00112233445566778899aabbccddeeff", "sample.bin")
    part.open_new()
    try:
        assert part.chunk_count == 2
        part.write_block(ED2K_CHUNK_SIZE, b"q" * 100)
        assert part.chunk_bitmap() == [False, True]
    finally:
        part.close()


def test_part_file_write_outside_bounds_raises(tmp_path: Path) -> None:
    total_size = 10_000
    part_path = tmp_path / "00112233445566778899aabbccddeeff.part"
    part = PartFile(part_path, total_size, "00112233445566778899aabbccddeeff", "sample.bin")
    part.open_new()
    try:
        with pytest.raises(PartFileError):
            part.write_block(total_size - 10, b"x" * 20)
    finally:
        part.close()


# ---------------------------------------------------------------------------
# DownloadQueue tests
# ---------------------------------------------------------------------------

def test_queue_add_creates_part_and_row(queue: DownloadQueue) -> None:
    target = _real_target()
    entry = queue.add(
        file_hash=target.hash_hex,
        name=target.name,
        size=target.size,
    )
    assert entry["status"] == DownloadStatus.QUEUED
    part_path = queue.temp_dir / f"{target.hash_hex.lower()}.part"
    assert part_path.exists()
    assert part_path.stat().st_size == target.size


def test_queue_add_duplicate_returns_existing(queue: DownloadQueue) -> None:
    target = _real_target()
    queue.add(file_hash=target.hash_hex, name=target.name, size=target.size)
    queue.add(file_hash=target.hash_hex, name=target.name, size=target.size)
    assert len(queue.list()) == 1


def test_queue_pause_resume_lifecycle(queue: DownloadQueue) -> None:
    target = _real_target()
    queue.add(file_hash=target.hash_hex, name=target.name, size=target.size)

    paused = queue.pause(target.hash_hex)
    assert paused["status"] == DownloadStatus.PAUSED

    resumed = queue.resume(target.hash_hex)
    assert resumed["status"] == DownloadStatus.DOWNLOADING

    queued_entry = queue.add(file_hash="abcdef0123456789abcdef0123456789", name="other.bin", size=100)
    with pytest.raises(DownloadQueueError):
        queue.resume(queued_entry["hash"])


def test_queue_record_block_completes_and_finalize_verifies(queue: DownloadQueue) -> None:
    from Crypto.Hash import MD4

    data = os.urandom(50_000)
    digest = MD4.new()
    for offset in range(0, len(data), 65_536):
        digest.update(data[offset:offset + 65_536])
    file_hash_hex = digest.hexdigest().upper()

    queue.add(file_hash=file_hash_hex, name="probe.bin", size=len(data))

    block_size = 5_000
    for start in range(0, len(data), block_size):
        chunk = data[start:start + block_size]
        result = queue.record_block(file_hash_hex, start, chunk)
    assert result["complete"] is True
    assert result["status"] == DownloadStatus.COMPLETE

    finalized = queue.finalize(file_hash_hex, verify=True)
    assert finalized["finalized"] is True
    target_path = Path(finalized["target"])
    assert target_path.exists()
    assert target_path.read_bytes() == data


def test_queue_cancel_removes_files(queue: DownloadQueue) -> None:
    target = _real_target()
    queue.add(file_hash=target.hash_hex, name=target.name, size=target.size)

    part_path = queue.temp_dir / f"{target.hash_hex.lower()}.part"
    sidecar_path = Path(str(part_path) + ".amuled.json")
    assert part_path.exists()
    assert sidecar_path.exists()

    result = queue.cancel(target.hash_hex)
    assert result["cancelled"] is True
    assert result["files_removed"] == 2
    assert queue.get(target.hash_hex) is None
    assert not part_path.exists()
    assert not sidecar_path.exists()

    entry = queue.add(file_hash=target.hash_hex, name=target.name, size=target.size)
    kept_part = Path(entry["part_path"])
    kept_sidecar = Path(str(kept_part) + ".amuled.json")
    assert kept_part.exists()
    assert kept_sidecar.exists()

    keep_result = queue.cancel(target.hash_hex, keep_files=True)
    assert keep_result["files_removed"] == 0
    assert keep_result["cancelled"] is True
    assert queue.get(target.hash_hex) is None
    assert kept_part.exists()
    assert kept_sidecar.exists()


def test_queue_unknown_hash_raises(queue: DownloadQueue) -> None:
    missing = "deadbeefdeadbeefdeadbeefdeadbeef"

    assert queue.get(missing) is None

    with pytest.raises(DownloadQueueError):
        queue.resume(missing)
    with pytest.raises(DownloadQueueError):
        queue.cancel(missing)
    with pytest.raises(DownloadQueueError):
        queue.record_block(missing, 0, b"x")
    with pytest.raises(DownloadQueueError):
        queue.finalize(missing)
