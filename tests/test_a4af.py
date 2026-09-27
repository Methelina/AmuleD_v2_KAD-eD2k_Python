"""Runner-level A4AF/NNS gate tests (roadmap A4AF step; oracle eMuleAI
DownloadClient.cpp:2171 SwapToAnotherFile, PartFile.cpp:3353-3370 Process
NNS pass, recons in tmp/recon/a4af-*.recon.md).

tests/test_a4af.py
Author:      Soror L.'.L.'.
Updated:     2026-09-28
"""

from __future__ import annotations

from amuled_v2.core.download.ics import PART_SIZE
from amuled_v2.core.download.runner import DownloadRunner


class _StubQueue:
    def __init__(self, gaps):
        self._gaps = gaps

    def gap_ranges(self, file_hash: str):
        return list(self._gaps)


class _StubClient:
    def __init__(self, part_status=None, complete=()):
        self.part_status = part_status or {}
        self.complete_sources = set(complete)

    async def close(self):
        pass


def _runner(gaps, source_provider=None):
    return DownloadRunner(
        queue=_StubQueue(gaps) if gaps is not None else object(),
        local_client_id=1,
        plain_dial_ok=True,
        source_provider=source_provider,
        callback_identity={
            "tcp_port": 4662,
            "user_hash": bytes.fromhex("7" * 32),
        },
    )


def test_a4af_needed_parts_matrix() -> None:
    fh_hex = "ab" * 16
    fh = bytes.fromhex(fh_hex)
    # One gap in part 0, one in part 2 of a 3-part file.
    gaps = [(0, 1000), (2 * PART_SIZE, 2 * PART_SIZE + 1000)]

    runner = _runner(gaps)

    # Complete source -> needed.
    assert (
        runner._a4af_needed_parts(fh_hex, fh, _StubClient(complete={fh}), 3 * PART_SIZE)
        is True
    )
    # Has part 0 -> needed.
    assert (
        runner._a4af_needed_parts(
            fh_hex, fh, _StubClient(part_status={fh: frozenset({0})}), 3 * PART_SIZE
        )
        is True
    )
    # Has only part 1 (we need 0 and 2) -> NNS.
    assert (
        runner._a4af_needed_parts(
            fh_hex, fh, _StubClient(part_status={fh: frozenset({1})}), 3 * PART_SIZE
        )
        is False
    )
    # Unknown part-status -> no gate.
    assert (
        runner._a4af_needed_parts(fh_hex, fh, _StubClient(), 3 * PART_SIZE) is None
    )
    # No gaps at all -> never gate.
    runner_empty = _runner([])
    assert (
        runner_empty._a4af_needed_parts(fh_hex, fh, _StubClient(), PART_SIZE)
        is True
    )


def test_a4af_resolve_sources_drops_nns() -> None:
    fh_hex = "cd" * 16

    def provider(file_hash: str, limit: int):
        return [
            {
                "client_id": 0x7F000001,
                "client_port": 1,
                "user_hash": "A1" * 16,
                "source_type": "kad3",
                "kad_udp_port": 1111,
            },
            {
                "client_id": 0x7F000001,
                "client_port": 2,
                "user_hash": "A2" * 16,
                "source_type": "kad3",
                "kad_udp_port": 2222,
            },
        ]

    runner = _runner([(0, 100)], provider)
    # Port 1 is a proven NNS source for this file.
    runner._a4af_verdicts[("127.0.0.1", 1)] = {fh_hex: "nns"}
    runner._a4af_verdicts[("127.0.0.1", 2)] = {fh_hex: "needed"}

    endpoints = runner.resolve_sources(fh_hex)
    assert [e["port"] for e in endpoints] == [2]


def test_a4af_verdict_helper() -> None:
    runner = _runner(None)
    runner._a4af_verdicts[("10.0.0.1", 5)] = {"ee" * 16: "nns"}
    assert runner._a4af_verdict("10.0.0.1", 5, "ee" * 16) == "nns"
    assert runner._a4af_verdict("10.0.0.1", 5, "ff" * 16) is None
    assert runner._a4af_verdict("10.0.0.2", 5, "ee" * 16) is None
