"""Config-parity slice tests (roadmap 11r): sparse part files, runner
source-limit/throttle/crypt-required knobs, listener connection rate limit,
ipfilter URL updater, example-config schema sync.

src/tests/test_config_parity.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-28

Patch Notes v0.1.0 (Soror L.'.L.'.):
  [+] Initial tests for the roadmap 11r config-parity slice.
"""

from __future__ import annotations

import asyncio
import io
import json
import gzip
from pathlib import Path

import pytest

from amuled_v2.config import DEFAULT_CONFIG
from amuled_v2.core.download.partfile import PartFile
from amuled_v2.core.ipfilter import update_ipfilter_from_url, load_ipfilter_file


# ---------------------------------------------------------------------------
# Example-config prototype stays in sync with DEFAULT_CONFIG.
# ---------------------------------------------------------------------------


def test_example_config_matches_default_schema() -> None:
    from amuled_v2.jsonc import load_jsonc_file

    example = load_jsonc_file(
        Path(__file__).resolve().parents[1] / "config" / "amuled.example.jsonc"
    )
    for section, keys in DEFAULT_CONFIG.items():
        assert section in example, f"missing section {section}"
        missing = set(keys) - set(example[section])
        assert not missing, f"missing keys in {section}: {sorted(missing)}"
        extra = set(example[section]) - set(keys)
        assert not extra, f"extra keys in {section}: {sorted(extra)}"


# ---------------------------------------------------------------------------
# Sparse part files.
# ---------------------------------------------------------------------------


def test_sparse_part_file_starts_empty_and_grows(tmp_path: Path) -> None:
    part = PartFile(tmp_path / "sparse.part", 10_000_000, "A" * 32, "s.bin", sparse=True)
    part.open_new()
    assert part.path.exists()
    assert part.path.stat().st_size < 10_000_000  # not preallocated
    part.write_block(9_999_000, b"\x00" * 1000)
    part.close()  # flush + close extends the sparse file
    assert part.path.stat().st_size == 10_000_000
    assert part.gaps[0].start == 0 and part.gaps[0].end == 9_999_000


def test_dense_part_file_still_preallocates(tmp_path: Path) -> None:
    part = PartFile(tmp_path / "dense.part", 5_000_000, "B" * 32, "d.bin")
    part.open_new()
    try:
        assert part.path.stat().st_size == 5_000_000
    finally:
        part.close()


def test_sparse_sidecar_resume(tmp_path: Path) -> None:
    part = PartFile(tmp_path / "s.part", 2_000_000, "C" * 32, "s.bin", sparse=True)
    part.open_new()
    part.write_block(0, b"\x01" * 1000)
    part.save()  # sidecar must reflect the new gaps before resume
    part.close()
    resumed = PartFile.resume(tmp_path / "s.part")
    assert resumed.sparse is True
    assert resumed.total_size == 2_000_000
    assert resumed.gaps[0].start == 1000


# ---------------------------------------------------------------------------
# Runner knobs.
# ---------------------------------------------------------------------------


def _make_runner(**kwargs):
    from amuled_v2.core.download.queue import DownloadQueue
    from amuled_v2.core.download.runner import DownloadRunner

    queue = kwargs.pop("queue")
    return DownloadRunner(queue, local_port=1, **kwargs)


def test_runner_knobs_default_to_config_values(tmp_path, monkeypatch) -> None:
    from amuled_v2 import state as state_module

    state_module.DB_FILE = tmp_path / "state.db"
    backend = state_module.StateBackend()
    backend.connect()
    from amuled_v2.core.download.queue import DownloadQueue
    queue = DownloadQueue(state=backend, temp_dir=tmp_path / "t", incoming_dir=tmp_path / "i")
    runner = _make_runner(queue=queue)
    assert runner.max_sources_per_file == DEFAULT_CONFIG["download"]["max_sources_per_file"]
    assert runner.download_bytes_per_sec == 0
    assert runner.crypt_layer_required is False


def test_runner_explicit_knobs_override_config(tmp_path) -> None:
    from amuled_v2 import state as state_module

    state_module.DB_FILE = tmp_path / "state.db"
    backend = state_module.StateBackend()
    backend.connect()
    from amuled_v2.core.download.queue import DownloadQueue
    queue = DownloadQueue(state=backend, temp_dir=tmp_path / "t", incoming_dir=tmp_path / "i")
    runner = _make_runner(
        queue=queue,
        max_sources_per_file=7,
        download_bytes_per_sec=1024,
        crypt_layer_required=True,
    )
    assert runner.max_sources_per_file == 7
    assert runner.download_bytes_per_sec == 1024
    assert runner.crypt_layer_required is True


def test_runner_throttle_gate_paces_writes(tmp_path) -> None:
    from amuled_v2 import state as state_module

    state_module.DB_FILE = tmp_path / "state.db"
    backend = state_module.StateBackend()
    backend.connect()
    from amuled_v2.core.download.queue import DownloadQueue
    queue = DownloadQueue(state=backend, temp_dir=tmp_path / "t", incoming_dir=tmp_path / "i")
    runner = _make_runner(queue=queue, download_bytes_per_sec=64 * 1024)

    async def scenario() -> float:
        loop = asyncio.get_running_loop()
        runner._throttle_ts = loop.time()
        start = loop.time()
        # 512 KiB at 64 KiB/s: first bucket-full is instant, the rest paces.
        for _ in range(8):
            await runner._throttle_gate(64 * 1024)
        return loop.time() - start

    elapsed = asyncio.run(scenario())
    # Pacing works: the first bucket-full is instant, the remaining 7 x 64 KiB
    # wait ~1 s each; allow scheduling slack.
    assert 3.5 <= elapsed <= 8.0


def test_runner_sources_limit_applies(tmp_path) -> None:
    from amuled_v2 import state as state_module

    state_module.DB_FILE = tmp_path / "state.db"
    backend = state_module.StateBackend()
    backend.connect()
    from amuled_v2.core.download.queue import DownloadQueue
    queue = DownloadQueue(state=backend, temp_dir=tmp_path / "t", incoming_dir=tmp_path / "i")
    queue.add(file_hash="D" * 32, name="x", size=1)
    runner = _make_runner(queue=queue, max_sources_per_file=3)
    seen: list[int] = []

    def provider(_hash: str, limit: int):
        seen.append(limit)
        return []

    runner.source_provider = provider
    runner.resolve_sources("D" * 32)
    assert seen == [3]


# ---------------------------------------------------------------------------
# Listener connection rate limit.
# ---------------------------------------------------------------------------


def test_listener_rate_limit_refuses_excess(tmp_path) -> None:
    import os as _os

    from amuled_v2.core.hashes import ed2k_hash_file
    from amuled_v2.core.peer.listener import IncomingPeerServer, LocalIdentity
    from amuled_v2.core.sharing.shared_files import SharedFile
    from amuled_v2.core.upload.queue import UploadQueue

    path = tmp_path / "sample.bin"
    path.write_bytes(_os.urandom(200_000))
    hashed = ed2k_hash_file(str(path))
    shared = SharedFile(
        file_hash=hashed.file_hash,
        name=path.name,
        size=hashed.file_size,
        path=str(path),
        hash_result=hashed,
    )

    class _Resolver:
        def resolve(self, file_hash: bytes):
            return shared if file_hash == shared.file_hash else None

    async def scenario() -> tuple[int, int]:
        server = IncomingPeerServer(
            identity=LocalIdentity(
                user_hash=bytes.fromhex("F" * 32),
                client_id=1,
                tcp_port=0,
                nickname="t",
            ),
            resolver=_Resolver(),
            upload_queue=UploadQueue(),
            host="127.0.0.1",
            port=0,
            idle_timeout=5.0,
            max_conn_per_5s=2,
        )
        await server.start()
        port = server.bound_port
        accepted = refused = 0
        for _ in range(4):
            try:
                _r, w = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port), 3.0
                )
            except (ConnectionError, OSError, asyncio.TimeoutError):
                refused += 1
                continue
            try:
                # The server closes rate-limited connections immediately;
                # a healthy session stays open waiting for the HELLO.
                data = await asyncio.wait_for(_r.read(1), 0.5)
                if data == b"":
                    refused += 1
                else:
                    accepted += 1
            except asyncio.TimeoutError:
                accepted += 1
            finally:
                w.close()
        await server.close()
        return accepted, refused

    accepted, refused = asyncio.run(scenario())
    assert (accepted, refused) == (2, 2)


# ---------------------------------------------------------------------------
# ipfilter URL updater (mocked transport).
# ---------------------------------------------------------------------------


def test_update_ipfilter_from_url_plain(tmp_path, monkeypatch) -> None:
    body = b"0.0.0.0 - 1.2.3.4 , 127 , test\n5.6.7.8 - 5.6.7.9 , 100 , x\n"

    class FakeResponse:
        def __enter__(self):
            return io.BytesIO(body)

        def __exit__(self, *a):
            return False

    import amuled_v2.core.ipfilter as ipfilter_module

    monkeypatch.setattr(
        ipfilter_module.urllib.request, "urlopen", lambda *a, **k: FakeResponse()
    )
    dest = tmp_path / "ipfilter.dat"
    stats = update_ipfilter_from_url("http://example.test/list", dest)
    assert dest.exists()
    assert stats["bytes"] == len(body)
    ip_filter = load_ipfilter_file(dest)
    assert ip_filter.statistics()["range_count"] == 2


def test_update_ipfilter_from_url_gzip(tmp_path, monkeypatch) -> None:
    body = gzip.compress(b"1.1.1.1 - 2.2.2.2 , 127 , gz\n")

    class FakeResponse:
        def __enter__(self):
            return io.BytesIO(body)

        def __exit__(self, *a):
            return False

    import amuled_v2.core.ipfilter as ipfilter_module

    monkeypatch.setattr(
        ipfilter_module.urllib.request, "urlopen", lambda *a, **k: FakeResponse()
    )
    dest = tmp_path / "ipfilter.dat"
    stats = update_ipfilter_from_url("http://example.test/list.gz", dest)
    assert dest.read_bytes().startswith(b"1.1.1.1")
    assert stats["entries_hint"] >= 1


def test_update_ipfilter_from_url_rejects_garbage(tmp_path, monkeypatch) -> None:
    class FakeResponse:
        def __enter__(self):
            return io.BytesIO(b"<html>not a filter</html>")

        def __exit__(self, *a):
            return False

    import amuled_v2.core.ipfilter as ipfilter_module

    monkeypatch.setattr(
        ipfilter_module.urllib.request, "urlopen", lambda *a, **k: FakeResponse()
    )
    dest = tmp_path / "ipfilter.dat"
    with pytest.raises(Exception):
        update_ipfilter_from_url("http://example.test/bad", dest)
    assert not dest.exists()
