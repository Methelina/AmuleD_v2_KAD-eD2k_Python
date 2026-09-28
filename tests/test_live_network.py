"""LIVE network tests — the anti-mirror-room suite.

Runs ONLY against the real eMule/KAD network and a real kernel.  Excluded
from offline runs; gated behind AMULED_LIVE=1:

    $env:AMULED_LIVE='1'; .\\.venv\\Scripts\\python.exe -m pytest -q tests\\test_live_network.py
    $env:AMULED_LIVE_LONG='1'  # + completion test (hours)

Flow (self-feeding, no hardcoded targets):
  1. live keyword search ("marvel", fallback "ubuntu")
  2. filter video files 30 MB..3 GB, prefer many sources
  3. KAD source lookup for top candidates; pick the best-connected one
     (random among the top-2 so runs exercise different peers)
  4. add + race the pick; assert real bytes arrive within the timebox
  5. [extended] full MD4-verified completion
  6. publish visibility: our shared file is findable from the network

Every test writes JSON evidence to tmp/live_reports/.

src/tests/test_live_network.py
Version:     0.2.0
Author:      Soror L.'.L.'.
Updated:     2026-09-28

Patch Notes v0.2.0 (Soror L'.L'.):
  [+] Self-feeding target selection: search -> video filter -> best-
      connected candidate (random top-2) replaces the hardcoded hash.
  [+] Corrected kad_keyword_search usage (own_tcp_port) and source
      field names (KadFileSource.source_type).
  [+] download.add via IPC before the race; selection persisted to
      tmp/live_reports/selected.json so the completion test survives
      process restarts.

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Initial live suite (search / sources / handshake / progress /
      completion / publish visibility), env-gated, JSON evidence.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
import socket
import struct
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "tmp" / "live_reports"
SELECTED = REPORTS / "selected.json"

LIVE = os.environ.get("AMULED_LIVE") == "1"
LONG = os.environ.get("AMULED_LIVE_LONG") == "1"

VIDEO_EXT = (".mkv", ".avi", ".mp4", ".mpg", ".mpeg", ".mov", ".wmv", ".vob")

pytestmark = pytest.mark.skipif(
    not LIVE, reason="live-network test: set AMULED_LIVE=1 to run"
)


# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------


def _own_userhash() -> bytes:
    """The live kernel persistent userhash - loaded from the local
    identity (config), never hardcoded (personal identifier)."""
    from amuled_v2.core.identity import load_identity

    return bytes(load_identity().user_hash)


def _report(name: str, data: dict) -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS / f"{stamp}_{name}.json"
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"\n[live report] {path}")


def _as_dict(obj) -> dict:
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, dict):
        return dict(obj)
    return {
        "hash": getattr(obj, "file_hash", b"").hex().upper()
        if isinstance(getattr(obj, "file_hash", None), (bytes, bytearray))
        else str(getattr(obj, "file_hash", "")),
        "name": getattr(obj, "name", ""),
        "size": int(getattr(obj, "size", 0)),
        "sources": int(getattr(obj, "sources", 0)),
    }


def _control(req: dict, timeout: float = 20.0) -> dict | None:
    try:
        status = json.loads(
            (ROOT / "db" / "serve_status.json").read_text(encoding="utf-8")
        )
        port = int(status["control_port"])
    except Exception:
        return None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.sendall((json.dumps(req) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        return json.loads(buf.decode())
    except Exception:
        return None


def _kernel_required() -> None:
    if _control({"command": "status"}) is None:
        pytest.skip("live kernel is not running (AmuleD_Run.ps1 serve)")


def _run_async(coro):
    return asyncio.run(coro)


async def _kad_search(query: str, timeout: int = 90) -> list[dict]:
    """Keyword search THROUGH the kernel (architecture invariant: one KAD
    process = one routing).  Falls back to the ephemeral runtime only when
    no kernel is reachable."""
    ipc = _control({"command": "kad.search", "query": query, "timeout": timeout},
                   timeout=timeout + 30)
    if ipc is not None and ipc.get("status") == "ok":
        return ipc["results"]
    from amuled_v2.core.kad.runtime import bootstrap_runtime, load_kad_runtime
    from amuled_v2.core.kad.search import kad_keyword_search

    rt = load_kad_runtime()
    await bootstrap_runtime(rt, local_port=0)
    report = await kad_keyword_search(
        query,
        routing=rt.routing,
        own_id=rt.own_id,
        own_tcp_port=4662,
        timeout=timeout,
    )
    return [_as_dict(r) for r in report.results]


async def _kad_sources(hash_hex: str, size: int, timeout: int = 60):
    """Source lookup THROUGH the kernel (persists rows itself)."""
    ipc = _control({"command": "kad.sources", "file_hash": hash_hex,
                    "size": size, "timeout": timeout}, timeout=timeout + 30)
    if ipc is not None and ipc.get("status") == "ok":
        out = []
        for s in ipc.get("sources", []):
            cid = s.get("client_id")
            if cid is None and s.get("ip"):
                cid = int.from_bytes(socket.inet_aton(s["ip"]), "big")
            out.append(
                SimpleNamespace(
                    client_id=int(cid or 0),
                    tcp_port=int(s["tcp_port"]),
                    udp_port=int(s.get("udp_port") or 0),
                    source_type=int(s.get("source_type") or 0),
                    buddy_ip=s.get("buddy_ip"),
                    buddy_port=int(s.get("buddy_port") or 0),
                )
            )
        return SimpleNamespace(sources=out)
    from amuled_v2.core.kad.runtime import bootstrap_runtime, load_kad_runtime
    from amuled_v2.core.kad.source_search import kad_file_source_search

    rt = load_kad_runtime()
    await bootstrap_runtime(rt, local_port=0)
    return await kad_file_source_search(
        bytes.fromhex(hash_hex),
        file_size=size,
        routing=rt.routing,
        own_id=rt.own_id,
        own_tcp_port=4662,
        timeout=timeout,
        max_sources=200,
        local_port=0,
    )


def _save_sources(hash_hex: str, report) -> int:
    rows = []
    for s in report.sources:
        cid = getattr(s, "client_id", None)
        if cid is None and getattr(s, "ip", None):
            cid = int.from_bytes(socket.inet_aton(s.ip), "big")
        rows.append(
            {
                "client_id": int(cid or 0),
                "client_port": s.tcp_port,
                "user_hash": None,
                "kad_type": s.source_type or None,
                "kad_udp_port": s.udp_port,
                "buddy_ip": s.buddy_ip,
                "buddy_port": s.buddy_port,
            }
        )
    resp = _control({"command": "sources.save", "file_hash": hash_hex, "sources": rows})
    return int((resp or {}).get("saved") or 0)


# ---------------------------------------------------------------------------
# 1. Live search + self-feeding target selection
# ---------------------------------------------------------------------------

_selected: dict | None = None


def _select_target() -> dict:
    """Search live KAD for videos, probe sources, pick the best-connected
    candidate (random among the top-2)."""
    import re

    videos: list[dict] = []
    report_lines = []
    for query in ("marvel", "movie", "video", "ubuntu", "linux", "pdf"):
        results = _run_async(_kad_search(query))
        vids = [
            r
            for r in results
            if str(r.get("name", "")).lower().endswith(VIDEO_EXT)
            and 9_728_000 <= int(r.get("size", 0)) <= 3_000_000_000
        ]
        report_lines.append({"query": query, "results": len(results), "videos": len(vids)})
        if len(vids) >= 1:
            videos = vids
            _report("search", {"queries": report_lines, "selected_query": query})
            break
    assert videos, f"live search returned no video candidates: {report_lines}"

    probed = []
    for cand in videos[:4]:
        hash_hex = str(cand["hash"]).upper()
        size = int(cand["size"])
        # KAD source stores warm up over repeated asks (eMule re-asks too):
        # retry the lookup before declaring the candidate sourceless.
        best_found = 0
        saved = 0
        for attempt in range(3):
            report = _run_async(_kad_sources(hash_hex, size))
            best_found = max(best_found, len(report.sources))
            saved = _save_sources(hash_hex, report)
            if saved > 0:
                break
            time.sleep(15)
        probed.append(
            {
                "hash": hash_hex,
                "size": size,
                "name": str(cand.get("name", "")),
                "kad_sources": best_found,
                "saved": saved,
            }
        )
        if saved >= 5:
            break
    assert probed and any(p["saved"] > 0 for p in probed), (
        f"no candidate had live sources: {probed}"
    )
    best = sorted(probed, key=lambda p: -p["saved"])[:2]
    pick = random.choice(best)
    pick["alternatives"] = [p["hash"] for p in best if p["hash"] != pick["hash"]]
    REPORTS.mkdir(parents=True, exist_ok=True)
    SELECTED.write_text(json.dumps(pick, indent=1, ensure_ascii=False), encoding="utf-8")
    return pick


def test_live_search_select_target() -> None:
    _kernel_required()
    global _selected
    _selected = _select_target()
    _report("selected", _selected)
    assert _selected["saved"] >= 1
    assert _selected["size"] >= 30_000_000


# ---------------------------------------------------------------------------
# 2. Real bytes from real peers (the sponsor criterion, timeboxed)
# ---------------------------------------------------------------------------


def _sidecar(fh: str) -> Path:
    return ROOT / "temp" / f"{fh.lower()}.part.amuled.json"


def _downloaded(fh: str) -> int:
    try:
        data = json.loads(_sidecar(fh).read_text(encoding="utf-8"))
        total = int(data["total_size"])
        gaps = sum(g["end"] - g["start"] for g in data["gaps"])
        return total - gaps
    except Exception:
        return 0


def test_live_download_progress() -> None:
    _kernel_required()
    global _selected
    if _selected is None:
        if not SELECTED.exists():
            pytest.skip("no selected target - run test_live_search_select_target")
        _selected = json.loads(SELECTED.read_text(encoding="utf-8"))
    fh = _selected["hash"]
    size = int(_selected["size"])
    from urllib.parse import quote

    link = (
        f"ed2k://|file|{quote(_selected.get('name') or 'live-pick')}"
        f"|{size}|{fh}|/"
    )
    add = _control({"command": "download.add", "link": link})
    assert add is not None and add.get("status") == "ok", f"download.add failed: {add}"
    run = _control({"command": "download.run", "hash": fh, "max_peers": 8,
                    "queue_wait": 240})
    assert run is not None and run.get("status") == "ok", (
        f"kernel did not accept the download race: {run}"
    )
    assert run.get("started"), f"race not started: {run}"

    start = _downloaded(fh)
    deadline = time.time() + 600
    best = start
    while time.time() < deadline:
        best = max(best, _downloaded(fh))
        if best - start >= 1_000_000:
            break
        time.sleep(10)
    _report("download_progress", {
        "hash": fh, "start_bytes": start, "end_bytes": best,
        "gained": best - start,
    })
    assert best - start >= 1_000_000, (
        f"no live download progress: gained {best - start} bytes in 10 min"
    )


# ---------------------------------------------------------------------------
# 3. Foreign-client wire acceptance (dial live kad1 peers of the target)
# ---------------------------------------------------------------------------


def test_live_foreign_handshake() -> None:
    _kernel_required()
    global _selected
    if _selected is None and SELECTED.exists():
        _selected = json.loads(SELECTED.read_text(encoding="utf-8"))
    assert _selected, "no selected target - run test_live_search_select_target"
    fh = _selected["hash"]
    from amuled_v2.core.peer.client import PeerClient

    resp = _control({"command": "sources.list", "file_hash": fh, "limit": 100})
    rows = (resp or {}).get("sources") or (resp or {}).get("rows") or []

    async def _probe(peers: list[dict], limit: int = 8):
        tried = ok = 0
        notes = []
        for row in peers:
            if tried >= limit:
                break
            ip = socket.inet_ntoa(int(row["client_id"]).to_bytes(4, "big"))
            port = int(row["client_port"])
            if port <= 0 or ip.startswith(("0.", "10.", "127.", "192.168.", "172.")):
                continue
            tried += 1
            client = PeerClient(
                ip, port,
                local_client_id=0x11223344, local_port=4662,
                target_userhash=None,
                local_userhash=_own_userhash(),
                connect_timeout=8.0, response_timeout=10.0,
                plain_dial_ok=True,
            )
            try:
                await client.connect()
                info = await client.handshake()
                ok += 1
                notes.append({"peer": f"{ip}:{port}", "ok": True, "nick": info.nickname})
            except Exception as exc:
                notes.append({"peer": f"{ip}:{port}", "ok": False, "err": str(exc)[:60]})
        return tried, ok, notes

    tried, ok, notes = _run_async(_probe(rows))
    _report("foreign_handshake", {"tried": tried, "handshake_ok": ok, "notes": notes})
    assert tried >= 3, f"too few dialable live peers in store: {tried}"
    assert ok >= 1, f"no foreign peer accepted our handshake (0/{tried})"


# ---------------------------------------------------------------------------
# 4. [extended] full MD4-verified completion (unbounded network time)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not LONG, reason="set AMULED_LIVE_LONG=1 (hours)")
def test_live_download_completion() -> None:
    assert SELECTED.exists(), "no selected target"
    fh = json.loads(SELECTED.read_text(encoding="utf-8"))["hash"]
    _kernel_required()
    deadline = time.time() + 6 * 3600
    while time.time() < deadline:
        resp = _control({"command": "download.list", "limit": 200})
        rows = (resp or {}).get("downloads") or []
        row = next(
            (r for r in rows if str(r.get("file_hash", "")).lower() == fh.lower()),
            None,
        )
        if row and row.get("status") == "complete":
            _report("download_complete", {"hash": fh, "row": row})
            return
        time.sleep(60)
    pytest.fail("live download did not complete within 6 hours")


# ---------------------------------------------------------------------------
# 5. Publish visibility: our shared file must be findable from the network
# ---------------------------------------------------------------------------


def test_live_publish_visible() -> None:
    _kernel_required()
    resp = _control({"command": "share.list", "limit": 1})
    rows = (resp or {}).get("files") or (resp or {}).get("rows") or []
    if not rows:
        pytest.skip("no shared files to publish")
    ours = rows[0]
    fh = str(ours.get("hash") or ours.get("file_hash") or "")
    name = str(ours.get("name") or "file")
    size = int(ours.get("size") or 0)
    assert fh, "shared row without hash"

    # Publish ourselves as a source right now (do not wait up to
    # republish_hours): advertise the kernel's live TCP port.
    ks = json.loads((ROOT / "db" / "kernel_status.json").read_text(encoding="utf-8"))
    tcp_port = int(ks["serve_port"])

    async def _publish():
        import socket as _socket

        from amuled_v2.core.kad.publish import SourcePublisher
        from amuled_v2.core.kad.runtime import bootstrap_runtime, load_kad_runtime

        rt = load_kad_runtime()
        await bootstrap_runtime(rt, local_port=0)
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 0))
        pub = SourcePublisher(
            own_id=rt.own_id,
            own_tcp_port=tcp_port,
            user_hash=_own_userhash(),
        )
        try:
            await pub.publish_sources(
                bytes.fromhex(fh),
                [(0, tcp_port, None)],
                socket=sock,
                routing_table=rt.routing,
                file_size=size or None,
                timeout=25,
            )
        finally:
            sock.close()

    _run_async(_publish())

    # KAD store propagation is not instant; re-search a few times.  Query
    # = the longest alphanumeric token of the file name (distinctive).
    tokens = re.findall(r"[A-Za-z0-9]{4,}", name)
    query = max(tokens, key=len) if tokens else "ubuntu"
    query = query.lower()
    hit = False
    seen = 0
    for _ in range(3):
        results = _run_async(_kad_search(query))
        seen = len(results)
        if any(str(r.get("hash", "")).lower() == fh.lower() for r in results):
            hit = True
            break
        time.sleep(20)
    _report("publish_visible", {"hash": fh, "query": query,
                                "results": seen, "visible": hit})
    assert hit, f"our shared file {fh} not visible in live KAD search ({query!r})"
