"""ICS (Intelligent Chunk Selection) tests: unit coverage of the pure
algorithm port (amuled_v2.core.download.ics, oracle eMuleAI
PartFile.cpp:7367-7521 / 2777-2851 / 2674-2741) plus a loopback e2e
multi-part download exercising the runner's ICS block-selector path.

tests/test_ics.py
Author:      Soror L.'.L.'.
Updated:     2026-09-28
"""

from __future__ import annotations

import asyncio
import os

from amuled_v2.core.download.ics import (
    CM_RELEASE_MODE,
    CM_SHARE_MODE,
    CM_SPREAD_MODE,
    EMBLOCK_SIZE,
    PART_SIZE,
    choose_part,
    ics_mode,
    is_already_requested,
    next_block_in_part,
    part_bounds,
    part_count,
    select_blocks,
    shrink_to_avoid,
)


# ---------------------------------------------------------------------------
# part_count / part_bounds
# ---------------------------------------------------------------------------


def test_part_count_matches_ed2k_semantics() -> None:
    assert part_count(0) == 1
    assert part_count(1) == 1
    assert part_count(PART_SIZE) == 1
    assert part_count(PART_SIZE + 1) == 2
    assert part_count(2 * PART_SIZE) == 2


def test_part_bounds_inclusive_last_part_short() -> None:
    size = PART_SIZE + 1000
    assert part_bounds(0, size) == (0, PART_SIZE - 1)
    assert part_bounds(1, size) == (PART_SIZE, size - 1)


# ---------------------------------------------------------------------------
# IsAlreadyRequested / ShrinkToAvoidAlreadyRequested (PartFile.cpp:2674-2741)
# ---------------------------------------------------------------------------


def test_is_already_requested_overlap() -> None:
    req = [(100, 199), (500, 599)]
    assert is_already_requested(150, 250, req)
    assert is_already_requested(599, 700, req)
    assert not is_already_requested(200, 499, req)


def test_shrink_to_avoid_trims_both_sides() -> None:
    req = [(100, 150), (250, 300)]
    # Left side covered.
    assert shrink_to_avoid(100, 200, req) == (151, 200)
    # Right side covered.
    assert shrink_to_avoid(200, 300, req) == (200, 249)
    # Fully covered.
    assert shrink_to_avoid(120, 130, req) is None
    # Gap between requests stays.
    assert shrink_to_avoid(151, 249, req) == (151, 249)


def test_shrink_to_avoid_fixpoint_multiple_ranges() -> None:
    req = [(100, 110), (105, 200)]
    assert shrink_to_avoid(100, 210, req) == (201, 210)


# ---------------------------------------------------------------------------
# GetNextEmptyBlockInPart (PartFile.cpp:2777-2851)
# ---------------------------------------------------------------------------


def test_next_block_in_part_clamps_to_emblock() -> None:
    size = 2 * PART_SIZE
    # Whole file is one gap.
    block = next_block_in_part(0, size, [(0, size - 1)], [])
    assert block == (0, EMBLOCK_SIZE - 1)


def test_next_block_in_part_clamps_to_part() -> None:
    size = 2 * PART_SIZE
    block = next_block_in_part(1, size, [(0, size - 1)], [])
    assert block is not None
    assert block[0] == PART_SIZE
    assert block[1] == PART_SIZE + EMBLOCK_SIZE - 1


def test_next_block_in_part_skips_fully_requested_gap() -> None:
    size = 2 * PART_SIZE
    first_end = EMBLOCK_SIZE - 1
    second_end = 2 * EMBLOCK_SIZE - 1
    req = [(0, first_end)]
    gaps = [(0, first_end), (first_end + 1, second_end)]
    block = next_block_in_part(0, size, gaps, req)
    assert block == (EMBLOCK_SIZE, second_end)


def test_next_block_in_part_last_part_size_bound() -> None:
    size = 300_000  # less than one PART, more than one EMBLOCK
    # First block clamped to one EMBLOCK (PartFile.cpp blockLimit arithmetic).
    block = next_block_in_part(0, size, [(0, size - 1)], [])
    assert block == (0, EMBLOCK_SIZE - 1)
    # Follow-up block covers the file tail.
    tail = next_block_in_part(
        0, size, [(0, size - 1)], [(0, EMBLOCK_SIZE - 1)]
    )
    assert tail == (EMBLOCK_SIZE, size - 1)


# ---------------------------------------------------------------------------
# ICS mode selection (PartFile.cpp:7382-7396)
# ---------------------------------------------------------------------------


def test_ics_mode_thresholds() -> None:
    gap_parts = [0, 1]
    assert ics_mode([10, 5], gap_parts) == CM_RELEASE_MODE
    assert ics_mode([11, 25], gap_parts) == CM_SPREAD_MODE
    assert ics_mode([26, 30], gap_parts) == CM_SHARE_MODE
    # Edge thresholds inclusive.
    assert ics_mode([10, 10], gap_parts) == CM_RELEASE_MODE
    assert ics_mode([25], gap_parts) == CM_SPREAD_MODE
    # Degenerate inputs default to SHARE.
    assert ics_mode([], gap_parts) == CM_SHARE_MODE
    assert ics_mode([5], []) == CM_SHARE_MODE


# ---------------------------------------------------------------------------
# choose_part (PartFile.cpp:7367-7521)
# ---------------------------------------------------------------------------


def test_choose_part_filters_unavailable_parts() -> None:
    chosen = choose_part(
        available=frozenset({1}),
        frequencies=[30, 30],
        gap_parts=[0, 1],
        gap_sizes={0: PART_SIZE, 1: PART_SIZE},
        downloading_counts={},
        last_part=None,
        total_size=2 * PART_SIZE,
    )
    assert chosen == 1


def test_choose_part_sticky_chunk_wins() -> None:
    # Part 1 is rarer-completed per prefs but last_part=0 must stick.
    chosen = choose_part(
        available=frozenset({0, 1}),
        frequencies=[30, 30],
        gap_parts=[0, 1],
        gap_sizes={0: 1_000, 1: PART_SIZE},
        downloading_counts={},
        last_part=0,
        total_size=2 * PART_SIZE,
    )
    assert chosen == 0


def test_choose_part_overassignment_penalised() -> None:
    # Part 0 has 1 downloader for a small gap (threshold ceil(184320*3/PART)=1)
    # -> penalised 0xFF000000; part 1 unpenalised must win in SHARE mode.
    small_gap = EMBLOCK_SIZE
    chosen = choose_part(
        available=frozenset({0, 1}),
        frequencies=[30, 30],
        gap_parts=[0, 1],
        gap_sizes={0: small_gap, 1: small_gap},
        downloading_counts={0: 1, 1: 0},
        last_part=None,
        total_size=2 * PART_SIZE,
    )
    assert chosen == 1


def test_choose_part_no_candidates() -> None:
    assert (
        choose_part(
            available=frozenset({5}),
            frequencies=[1],
            gap_parts=[0],
            gap_sizes={0: 100},
            downloading_counts={},
            last_part=None,
            total_size=PART_SIZE,
        )
        is None
    )


# ---------------------------------------------------------------------------
# select_blocks (PartFile.cpp:7496-7514)
# ---------------------------------------------------------------------------


def test_select_blocks_no_duplicates_and_bounds() -> None:
    size = 2 * PART_SIZE - 1000
    blocks, last = select_blocks(
        total_size=size,
        gaps=[(0, size - 1)],
        available=frozenset({0, 1}),
        frequencies=[5, 5],
        downloading_counts={},
        last_part=None,
        requested=[],
        max_blocks=3,
    )
    assert blocks, "expected at least one block"
    seen: set[tuple[int, int]] = set()
    for start, end in blocks:
        assert 0 <= start <= end < size
        assert end - start + 1 <= EMBLOCK_SIZE
        assert (start, end) not in seen
        seen.add((start, end))
    assert last is not None


def test_select_blocks_respects_requested_registry() -> None:
    size = 2 * PART_SIZE
    req = [(0, EMBLOCK_SIZE - 1)]
    blocks, _ = select_blocks(
        total_size=size,
        gaps=[(0, size - 1)],
        available=frozenset({0}),
        frequencies=[3],
        downloading_counts={},
        last_part=None,
        requested=req,
        max_blocks=2,
    )
    for start, end in blocks:
        assert not is_already_requested(start, end, req)


def test_select_blocks_exhaustion() -> None:
    size = 100_000  # single EMBLOCK
    blocks, last = select_blocks(
        total_size=size,
        gaps=[(0, size - 1)],
        available=frozenset({0}),
        frequencies=[2],
        downloading_counts={},
        last_part=None,
        requested=[],
        max_blocks=5,
    )
    assert blocks == [(0, size - 1)]
    assert last == 0


def test_select_blocks_unknown_peer_treated_full() -> None:
    # available={0} but the only gap lives in part 1 -> no candidates.
    blocks, last = select_blocks(
        total_size=2 * PART_SIZE,
        gaps=[(PART_SIZE, 2 * PART_SIZE - 1)],
        available=frozenset({0}),
        frequencies=[1, 1],
        downloading_counts={},
        last_part=None,
        requested=[],
        max_blocks=3,
    )
    assert blocks == []
    assert last is None


# ---------------------------------------------------------------------------
# e2e: multi-part loopback download through the ICS selector path
# ---------------------------------------------------------------------------

_IO_TIMEOUT = 180.0


def test_ics_multipart_download_e2e(tmp_path) -> None:
    """A 12 MB (2-part) file must go through the runner's ICS block
    selector (size > PART_SIZE) and complete MD4-verified from a single
    loopback source."""
    from test_download_stripe import (
        _FakeSource,
        _LOCAL_HASH,
        _PermissiveQueue,
        _StaticResolver,
    )

    from amuled_v2 import state as state_module
    from amuled_v2.core.download.queue import DownloadQueue
    from amuled_v2.core.download.runner import DownloadRunner
    from amuled_v2.core.hashes.ed2k import ed2k_hash_file
    from amuled_v2.core.kad.direct_callback import (
        parse_direct_callback_payload,
    )  # noqa: F401  (import parity with stripe harness)
    from amuled_v2.core.peer.listener import IncomingPeerServer
    from amuled_v2.core.sharing.shared_files import SharedFile
    from amuled_v2.core.upload.queue import UploadQueue

    async def scenario() -> None:
        state_module.DB_FILE = tmp_path / "state.db"
        backend = state_module.StateBackend()
        backend.connect()

        path = tmp_path / "ics_sample.bin"
        data = os.urandom(PART_SIZE + 2_500_000)  # 2 ED2K parts
        path.write_bytes(data)
        hashed = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=hashed.file_hash,
            name=path.name,
            size=hashed.file_size,
            path=str(path),
            hash_result=hashed,
        )
        assert hashed.file_size > PART_SIZE

        source = _FakeSource(shared)
        await source.start()

        listener = IncomingPeerServer(
            identity=_LOCAL_HASH_identity(),
            resolver=_StaticResolver(None),
            upload_queue=UploadQueue(),
            host="127.0.0.1",
            port=0,
            idle_timeout=30.0,
        )
        await listener.start()

        queue = DownloadQueue(
            state=backend,
            temp_dir=tmp_path / "temp",
            incoming_dir=tmp_path / "inc",
        )
        queue.add(
            file_hash=shared.file_hash.hex(),
            name=shared.name,
            size=shared.size,
        )

        runner = DownloadRunner(
            queue,
            local_port=listener.bound_port,
            max_peers=1,
            plain_dial_ok=False,
            connection_source=listener.expect_connection_from,
            callback_identity={
                "tcp_port": listener.bound_port,
                "user_hash": bytes.fromhex("7" * 32),
            },
        )
        runner.source_provider = lambda h, limit: [
            {
                "client_id": 0x7F000001,
                "client_port": 1,
                "user_hash": "A1" * 16,
                "source_type": "kad6",
                "kad_udp_port": source.udp_port,
            }
        ]

        try:
            result = await asyncio.wait_for(
                runner.run(shared.file_hash.hex()), _IO_TIMEOUT
            )
            assert result.get("status") == "complete", result
            assert result["finalized"]["verified"] is True, result
            assert source._served_box[0] >= shared.size
        finally:
            await listener.close()
            await source.stop()

    def _LOCAL_HASH_identity():
        from amuled_v2.core.peer.listener import LocalIdentity

        return LocalIdentity(
            user_hash=bytes.fromhex("3" * 32),
            client_id=1,
            tcp_port=0,
            nickname="AmuleD-ics",
        )

    asyncio.run(scenario())
