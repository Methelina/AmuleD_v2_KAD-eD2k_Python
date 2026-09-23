"""KAD network spider daemon: permanent HELLO/PING maturation with persistence.

A long-running, console-visible daemon that keeps the Kademlia network warm for
the whole project.  One permanent UDP socket, continuous HELLO/PING maturation
cycles over the cached node pool, periodic bootstrap refreshes from nodes.dat,
periodic persistence of the node cache (db/kad_nodes.json) + DuckDB
(kad_nodes table) + a machine-readable status snapshot (db/kad_status.json)
that other tools can read while the daemon runs.

KAD is only responsive when continuously warmed; this daemon is that warmth.

scripts/kad_spider.py
Version:     0.2.0
Author:      Soror L.'.L'.
Updated:     2026-09-23

Patch Notes v0.2.0 (Soror L'.L'.):
  [+] Kadabra neighbor memory: rewards from HELLO/PONG/BOOTSTRAP persisted to
      the shared db/kad_weights.json store (also fed by CLI searches).
  [+] Bandit-weight batch bias and per-cycle trend display (0-5 chevrons) with
      RTT and Vivaldi prediction.

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Added permanent-socket KAD spider daemon with HELLO/PING maturation,
      periodic bootstrap, and dual persistence (JSON + DuckDB) + status snapshot.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import socket
import sys
import time
import zlib
from pathlib import Path
from typing import Any, Dict, Tuple

from amuled_v2.logging_setup import LogTags, configure_logging, get_tagged_logger

ROOT = Path(__file__).resolve().parents[1]
configure_logging(
    level=os.environ.get("AMULED_LOG_LEVEL", "INFO"),
    log_file=ROOT / "logs" / "amuled.jsonl",
)

from amuled_v2.core.kad.bootstrap import pick_bootstrap_nodes
from amuled_v2.core.kad.nodes_dat import load_nodes_dat
from amuled_v2.core.kad.obfuscation import decode_obfuscated_kad
from amuled_v2.core.kad.packets import (
    KADEMLIA2_BOOTSTRAP_RES,
    KADEMLIA2_HELLO_RES,
    KADEMLIA2_PONG,
    KadUInt128,
    build_bootstrap_req,
    build_hello_req,
    build_ping,
    parse_bootstrap_res,
    parse_hello_res,
    parse_kad_packet,
)
from amuled_v2.core.kad.quality import NodeStats
from amuled_v2.core.kad.rtt import RttTracker
from amuled_v2.core.kad.runtime import (
    load_kadabra_state,
    save_kadabra_state,
)
from amuled_v2.core.kad.strategies import (
    KadabraState,
    active_strategy_name,
    get_strategy,
)
from amuled_v2.core.kad.vivaldi import LocalVivaldi

log = get_tagged_logger(LogTags.KAD, "kad.spider")

NODES_DAT = ROOT / "assets" / "v1" / "nodes.dat"
CACHE_FILE = ROOT / "db" / "kad_nodes.json"
STATUS_FILE = ROOT / "db" / "kad_status.json"
BATCH = 24
DEFAULT_PORT = int(os.environ.get("AMULED_KAD_SPIDER_PORT", "4672"))


def _is_routable_ipv4(ip: str) -> bool:
    """Return True only for usable IPv4 unicast addresses.

    Drops first octet 0 (unspecified/legacy) and >= 224 (multicast/reserved),
    mirroring runtime.py:_is_routable_ipv4 and kad_warmup.py candidate filtering.
    """
    try:
        first_octet = int(ip.split(".")[0])
    except (ValueError, IndexError):
        return False
    if first_octet == 0 or first_octet >= 224:
        return False
    return True


def load_cache() -> Dict[str, Any]:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("cache load failed: error=%s", exc)
    return {}


def build_pool(cache: Dict[str, Any]) -> Dict[Tuple[str, int], Dict[str, Any]]:
    """Merge cached alive nodes + nodes.dat into a candidate pool (kad_warmup.py ~92-114)."""
    nodes: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for key, rec in (cache.get("nodes") or {}).items():
        ip, _, port = key.rpartition(":")
        if not ip or not port:
            continue
        nodes[(ip, int(port))] = {
            "kad_id": rec.get("kad_id", ""),
            "tcp": int(rec.get("tcp", 4662)),
            "ver": int(rec.get("ver", 0)),
            "hellos": int(rec.get("hellos", 0)),
            "pings": int(rec.get("pings", 0)),
            "last_seen": float(rec.get("last_seen", 0)),
            "udp_key": rec.get("udp_key", ""),
        }
    if NODES_DAT.exists():
        for n in load_nodes_dat(NODES_DAT):
            if not _is_routable_ipv4(n.ip):
                continue
            nodes.setdefault(
                (n.ip, n.udp_port),
                {
                    "kad_id": n.kad_id.hex() if isinstance(n.kad_id, bytes) else n.kad_id,
                    "tcp": n.tcp_port,
                    "ver": n.contact_version,
                    "hellos": 0,
                    "pings": 0,
                    "last_seen": 0.0,
                    "udp_key": "",
                },
            )
    return nodes


def save_snapshot(
    nodes: Dict[Tuple[str, int], Dict[str, Any]],
    own: KadUInt128,
) -> None:
    """Atomically write db/kad_nodes.json + DuckDB kad_nodes upsert (kad_warmup.py ~232-316)."""
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    alive_nodes: Dict[str, Dict[str, Any]] = {}
    for k, r in nodes.items():
        if r["hellos"] > 0 or r["pings"] > 0:
            text_key = "%s:%d" % k
            alive_nodes[text_key] = {
                "kad_id": r["kad_id"],
                "tcp": r["tcp"],
                "ver": r["ver"],
                "hellos": r["hellos"],
                "pings": r["pings"],
                "udp_key": r.get("udp_key", ""),
                "last_seen": r["last_seen"],
            }
    payload = {
        "own_id": own.to_bytes().hex(),
        "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "nodes": alive_nodes,
    }
    tmp_path = CACHE_FILE.with_suffix(CACHE_FILE.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    os.replace(tmp_path, CACHE_FILE)
    log.info(
        "snapshot saved: file=%s alive_nodes=%d total_pool=%d",
        CACHE_FILE,
        len(alive_nodes),
        len(nodes),
    )
    _save_duckdb(alive_nodes)


def _save_duckdb(alive_nodes: dict) -> None:
    """Persist warmed nodes into DuckDB table kad_nodes (kad_warmup.py ~262-316)."""
    if not alive_nodes:
        return
    state = None
    try:
        from amuled_v2.state import get_state

        state = get_state()
        state.connect()
        con = state._require_duckdb()
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS kad_nodes (
                ip VARCHAR NOT NULL,
                udp_port INTEGER NOT NULL,
                kad_id VARCHAR,
                tcp_port INTEGER,
                kad_version INTEGER,
                hellos INTEGER,
                pings INTEGER,
                last_seen TIMESTAMP,
                PRIMARY KEY (ip, udp_port)
            )
            """
        )
        rows = []
        for key, rec in alive_nodes.items():
            ip, _, port = key.rpartition(":")
            rows.append(
                (
                    ip,
                    int(port),
                    rec["kad_id"],
                    rec["tcp"],
                    rec["ver"],
                    rec["hellos"],
                    rec["pings"],
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S",
                        time.localtime(rec["last_seen"] or time.time()),
                    ),
                )
            )
        con.executemany(
            """
            INSERT OR REPLACE INTO kad_nodes
                (ip, udp_port, kad_id, tcp_port, kad_version,
                 hellos, pings, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        log.info(
            "kad_nodes upserted into DuckDB: rows=%d", len(rows)
        )
    except Exception as exc:
        log.warning("duckdb save failed: error=%s", exc)
    finally:
        # DuckDB is single-writer: the CLI and other tools must be able to
        # open db/amuled.db between spider saves, so never hold it open.
        if state is not None:
            try:
                state.close()
            except Exception:
                pass


def write_status(status: Dict[str, Any]) -> None:
    """Atomically write db/kad_status.json (machine-readable status snapshot)."""
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = STATUS_FILE.with_suffix(STATUS_FILE.suffix + ".tmp")
    tmp_path.write_text(json.dumps(status, indent=2), encoding="utf-8")
    os.replace(tmp_path, STATUS_FILE)
    log.debug(
        "status written: file=%s pool=%d alive=%d",
        STATUS_FILE,
        status.get("pool_size", 0),
        status.get("alive_estimate", 0),
    )


def bind_socket(port: int) -> socket.socket:
    """Bind one UDP socket; fall back to ephemeral on OSError (WinError 10013)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError as exc:
        log.warning(
            "socket bind failed on port=%d: error=%s, falling back to ephemeral",
            port,
            exc,
        )
        sock.bind(("0.0.0.0", 0))
    actual_port = sock.getsockname()[1]
    log.info(
        "kad spider socket bound: port=%d requested=%d", actual_port, port
    )
    sock.setblocking(False)
    return sock


def _persist_own_id(
    cache_file: Path,
    own_id: KadUInt128,
    existing_nodes: dict[str, Any],
) -> None:
    """Atomically persist a newly generated own_id (runtime.py pattern)."""
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "own_id": own_id.to_bytes().hex(),
        "nodes": existing_nodes,
    }
    tmp_path = cache_file.with_suffix(cache_file.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    os.replace(tmp_path, cache_file)
    log.info("own_id persisted: own_id=%s file=%s", own_id, cache_file)


def _compute_rtt_avg(rtt_tracker: RttTracker) -> int:
    """Average of all recorded EWMA RTT values in ms (0 if none)."""
    rtt_vals = [v for v in rtt_tracker._ewma.values() if v > 0]
    if not rtt_vals:
        return 0
    return int(sum(rtt_vals) / len(rtt_vals))


def _hot_nodes_stats(
    nodes: Dict[Tuple[str, int], Dict[str, Any]],
) -> Dict[str, Any]:
    """Full statistics over successful hot connections.

    Prefers the persisted kad_nodes table in DuckDB (read-only, closed
    immediately so the CLI can always open the db); falls back to the
    in-memory pool when the db is busy.
    """
    stats: Dict[str, Any] = {
        "source": "memory",
        "rows": 0,
        "sum_hellos": 0,
        "sum_pings": 0,
        "with_udp_key": 0,
    }
    try:
        import duckdb

        con = duckdb.connect(str(ROOT / "db" / "amuled.db"), read_only=True)
        try:
            row = con.execute(
                """
                SELECT COUNT(*),
                       COALESCE(SUM(hellos), 0),
                       COALESCE(SUM(pings), 0)
                FROM kad_nodes
                """
            ).fetchone()
            with_key = con.execute(
                "SELECT COUNT(*) FROM kad_nodes WHERE kad_version >= 2"
            ).fetchone()[0]
            stats.update(
                source="duckdb",
                rows=int(row[0]),
                sum_hellos=int(row[1]),
                sum_pings=int(row[2]),
                with_udp_key=int(with_key),
            )
        finally:
            con.close()
    except Exception:
        # DuckDB busy (CLI writing) or table missing: live in-memory fallback.
        hot = [r for r in nodes.values() if r["hellos"] > 0 or r["pings"] > 0]
        stats.update(
            source="memory",
            rows=len(hot),
            sum_hellos=sum(int(r["hellos"]) for r in hot),
            sum_pings=sum(int(r["pings"]) for r in hot),
            with_udp_key=sum(1 for r in hot if r.get("udp_key")),
        )
    return stats


def _write_status(
    nodes: Dict[Tuple[str, int], Dict[str, Any]],
    own: KadUInt128,
    bound_port: int,
    strategy_name: str,
    rtt_tracker: RttTracker,
    state: Dict[str, Any],
) -> None:
    """Write db/kad_status.json with the machine-readable snapshot."""
    uptime_s = int(time.time() - state["started_at"])
    hot = state.get("hot_stats") or {}
    status = {
        "version": 1,
        "pid": os.getpid(),
        "own_id": own.to_bytes().hex(),
        "started_at": time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.localtime(state["started_at"])
        ),
        "uptime_s": uptime_s,
        "cycles": state["cycle"],
        "pool_size": len(nodes),
        "alive_estimate": state["alive"],
        "hellos_total": state["hello_res"],
        "pongs_total": state["pong"],
        "udp_keys": sum(1 for r in nodes.values() if r.get("udp_key")),
        "bound_port": bound_port,
        "strategy": strategy_name,
        "hot_nodes_stats": hot,
        "last_save": time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.localtime(state["last_save"])
        ) if state["last_save"] else None,
        "last_bootstrap": time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.localtime(state["last_bootstrap"])
        ) if state["last_bootstrap"] else None,
        "nodes_dat_contacts": sum(
            1 for r in nodes.values() if r["hellos"] == 0 and r["pings"] == 0
        ),
    }
    write_status(status)


async def main() -> int:
    parser = argparse.ArgumentParser(
        description="KAD network spider: permanent HELLO/PING maturation daemon.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=True,
        help="Per-cycle console print (default: on; --quiet disables).",
    )
    parser.add_argument(
        "--quiet",
        action="store_const",
        const=False,
        dest="verbose",
        help="Disable per-cycle console print.",
    )
    parser.add_argument(
        "--root",
        default=str(ROOT),
        help="Project root (default: script parent directory).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="UDP bind port (default: env AMULED_KAD_SPIDER_PORT or 4672).",
    )
    parser.add_argument(
        "--cycle-s",
        type=float,
        default=float(os.environ.get("AMULED_KAD_SPIDER_CYCLE_S", "25.0")),
        help="Seconds between maturation cycles (default: env or 25.0).",
    )
    parser.add_argument(
        "--save-s",
        type=float,
        default=float(os.environ.get("AMULED_KAD_SPIDER_SAVE_S", "60.0")),
        help="Seconds between persistence saves (default: 60.0).",
    )
    parser.add_argument(
        "--bootstrap-every",
        type=int,
        default=6,
        help="Bootstrap refresh interval in cycles (default: 6).",
    )
    args = parser.parse_args()

    project_root = Path(args.root)
    nodes_dat_path = project_root / "assets" / "v1" / "nodes.dat"
    cache_file = project_root / "db" / "kad_nodes.json"
    status_file = project_root / "db" / "kad_status.json"

    global NODES_DAT, CACHE_FILE, STATUS_FILE
    NODES_DAT = nodes_dat_path
    CACHE_FILE = cache_file
    STATUS_FILE = status_file

    # --- persistent own_id (kad_warmup.py ~77-83) ---------------------------
    cache = load_cache()
    own_hex = cache.get("own_id")
    own = (
        KadUInt128(bytes.fromhex(own_hex))
        if own_hex
        else KadUInt128(int.from_bytes(os.urandom(16), "big"))
    )
    if not own_hex:
        _persist_own_id(cache_file, own, cache.get("nodes", {}) or {})

    # --- candidate pool (kad_warmup.py ~92-114) ------------------------------
    nodes = build_pool(cache)

    log.info(
        "spider start: own_id=%s port=%d cycle_s=%.1f save_s=%.1f "
        "bootstrap_every=%d pool=%d",
        own,
        args.port,
        args.cycle_s,
        args.save_s,
        args.bootstrap_every,
        len(nodes),
    )

    # --- one permanent UDP socket (kad_warmup.py ~118-124) ------------------
    sock = bind_socket(args.port)
    bound_port = sock.getsockname()[1]
    loop = asyncio.get_running_loop()

    # --- mutable cycle state -----------------------------------------------
    state: Dict[str, Any] = {
        "alive": 0,
        "hello_res": 0,
        "pong": 0,
        "new_nodes": 0,
        "cycle": 0,
        "started_at": time.time(),
        "last_save": time.time(),
        "last_bootstrap": 0.0,
        "next_save": loop.time(),
    }
    rtt_tracker = RttTracker()
    vivaldi = LocalVivaldi()
    ping_sent: Dict[Tuple[str, int], float] = {}
    strategy = get_strategy(active_strategy_name())
    strategy_name = active_strategy_name()
    kadabra = load_kadabra_state(project_root)
    prev_weights: Dict[Tuple[str, int], float] = {}
    prev_ewma: Dict[Tuple[str, int], float] = {}
    log.info("seed strategy: name=%s", strategy_name)

    # --- receiver (kad_warmup.py ~130-210) ---------------------------------
    async def receiver() -> None:
        while True:
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 65535), 1.0
                )
            except (asyncio.TimeoutError, Exception):
                continue
            try:
                proto, op, payload = parse_kad_packet(data)
                if proto == 0xE5:
                    payload = zlib.decompress(payload)
            except Exception:
                continue
            if proto not in (0xE4, 0xE5):
                plain = decode_obfuscated_kad(
                    data,
                    own.to_bytes(),
                    peer_ip=addr[0],
                    peer_port=addr[1],
                )
                if plain is None:
                    continue
                pkt, recv_key, send_key = plain
                try:
                    proto, op, payload = parse_kad_packet(pkt)
                    if proto == 0xE5:
                        payload = zlib.decompress(payload)
                except Exception:
                    continue
                key = (addr[0], addr[1])
                rec = nodes.get(key)
                if rec is not None and send_key:
                    rec["udp_key"] = send_key & 0xFFFFFFFF

            key = (addr[0], addr[1])
            rec = nodes.get(key)
            if op == KADEMLIA2_HELLO_RES:
                kadabra.reward((addr[0], addr[1]), 0.5)
                try:
                    h = parse_hello_res(payload)
                except Exception:
                    continue
                state["hello_res"] += 1
                if rec is None:
                    rec = nodes[key] = {
                        "kad_id": "", "tcp": 0, "ver": 0,
                        "hellos": 0, "pings": 0, "last_seen": 0.0,
                        "udp_key": "",
                    }
                rec["kad_id"] = h.contact_id.to_bytes().hex()
                rec["tcp"] = h.tcp_port
                rec["ver"] = h.version
                rec["hellos"] = int(rec["hellos"]) + 1
                rec["last_seen"] = time.time()
                if rec["hellos"] == 1:
                    state["alive"] += 1
                log.info(
                    "HELLO_RES: remote=%s:%d ver=%d tcp=%d hellos=%d "
                    "alive=%d udp_key=%s",
                    addr[0], addr[1], h.version, h.tcp_port, rec["hellos"],
                    state["alive"], rec.get("udp_key", ""),
                )
            elif op == KADEMLIA2_PONG:
                kadabra.reward((addr[0], addr[1]), 0.2)
                state["pong"] += 1
                if rec is not None:
                    rec["pings"] = int(rec["pings"]) + 1
                    rec["last_seen"] = time.time()
                    sent_at = ping_sent.get(key)
                    if sent_at:
                        rtt = (time.time() - sent_at) * 1000.0
                        rec["rtt_ewma"] = rtt_tracker.update(key, rtt)
                        vivaldi.update(key, rtt)
            elif op == KADEMLIA2_BOOTSTRAP_RES:
                kadabra.reward((addr[0], addr[1]), 2.0)
                try:
                    sender_id, contacts = parse_bootstrap_res(payload)
                except Exception:
                    log.debug(
                        "bootstrap_res parse failed: remote=%s:%d",
                        addr[0], addr[1],
                    )
                    continue
                log.info(
                    "BOOTSTRAP_RES: remote=%s:%d contacts=%d",
                    addr[0], addr[1], len(contacts),
                )
                for c in contacts:
                    ck = (c.ip, c.udp_port)
                    if not _is_routable_ipv4(c.ip):
                        continue
                    is_new = ck not in nodes
                    nodes.setdefault(
                        ck,
                        {
                            "kad_id": c.kad_id.hex() if isinstance(c.kad_id, bytes) else c.kad_id,
                            "tcp": c.tcp_port,
                            "ver": c.contact_version,
                            "hellos": 0,
                            "pings": 0,
                            "last_seen": 0.0,
                            "udp_key": "",
                        },
                    )
                    if is_new:
                        state["new_nodes"] += 1
                    c_rec = nodes[ck]
                    if c.kad_id:
                        c_rec["kad_id"] = (
                            c.kad_id.hex() if isinstance(c.kad_id, bytes) else c.kad_id
                        )
                    c_rec["tcp"] = c.tcp_port
                    c_rec["ver"] = c.contact_version

    recv_task = asyncio.ensure_future(receiver())

    # --- socket senders (kad_warmup.py ~217-230) ---------------------------
    async def send_hello(ip: str, port: int) -> None:
        try:
            await loop.sock_sendto(
                sock, build_hello_req(own, 4662), (ip, port)
            )
        except OSError:
            pass

    async def send_ping(ip: str, port: int) -> None:
        ping_sent[(ip, port)] = time.time()
        try:
            await loop.sock_sendto(sock, build_ping(), (ip, port))
        except OSError:
            pass

    async def send_bootstrap(ip: str, port: int) -> None:
        try:
            await loop.sock_sendto(sock, build_bootstrap_req(own), (ip, port))
        except OSError:
            pass

    # --- shutdown helpers --------------------------------------------------
    running = True

    def _request_stop(signum: int, frame: Any) -> None:
        nonlocal running
        log.info("signal received: signal=%d, initiating shutdown", signum)
        running = False

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _request_stop)
        except (ValueError, OSError):
            pass

    try:
        # --- initial bootstrap from nodes.dat seeds (kad_warmup.py ~320-339) --
        if nodes_dat_path.exists():
            seeds = pick_bootstrap_nodes(str(nodes_dat_path), 12)
            sent_boot = 0
            for n in seeds:
                if not _is_routable_ipv4(n.ip):
                    continue
                await send_bootstrap(n.ip, n.udp_port)
                sent_boot += 1
            state["last_bootstrap"] = time.time()
            log.info("initial bootstrap seeds sent: count=%d", sent_boot)
            await asyncio.sleep(3.0)

        # --- main maturation loop (kad_warmup.py ~341-379) -------------------
        while running:
            cycle_start = loop.time()

            # strategy-ordered batch: core first half, tail second half
            def _stats(kv) -> NodeStats:
                r = kv[1]
                return NodeStats(
                    hellos=int(r["hellos"]),
                    pings=int(r["pings"]),
                    rtt_ewma=float(r.get("rtt_ewma", 0.0)),
                    last_seen=float(r["last_seen"]),
                )

            pool = sorted(
                nodes.items(),
                key=lambda kv: (
                    -kv[1]["hellos"],
                    -kv[1]["last_seen"],
                ),
            )
            mid = len(pool) // 2
            core = strategy(pool[:mid], _stats, rtt_tracker, vivaldi)
            core = sorted(core, key=lambda kv: -kadabra.weight(kv[0]))
            tail = pool[mid:]
            batch = core[:BATCH] + tail[-BATCH:]

            sent = 0
            for (ip, port), rec in batch:
                await send_hello(ip, port)
                sent += 1
                if sent % 3 == 0:
                    await send_ping(ip, port)
                await asyncio.sleep(0.05)

            # periodic bootstrap refresh (kad_warmup.py ~320-339 pattern)
            if state["cycle"] > 0 and state["cycle"] % args.bootstrap_every == 0:
                if nodes_dat_path.exists():
                    seeds = pick_bootstrap_nodes(str(nodes_dat_path), 12)
                    sent_boot = 0
                    for n in seeds:
                        if not _is_routable_ipv4(n.ip):
                            continue
                        await send_bootstrap(n.ip, n.udp_port)
                        sent_boot += 1
                    state["last_bootstrap"] = time.time()
                    log.info("periodic bootstrap: sent=%d", sent_boot)

            # periodic save (kad_warmup.py ~375-379)
            now = loop.time()
            if now >= state["next_save"]:
                save_snapshot(nodes, own)
                save_kadabra_state(kadabra, project_root, decay_factor=0.995)
                state["last_save"] = time.time()
                state["next_save"] = now + args.save_s

            state["cycle"] += 1

            # per-cycle hot-connections statistics (from the kad_nodes db)
            state["hot_stats"] = _hot_nodes_stats(nodes)

            # status snapshot
            _write_status(
                nodes, own, bound_port, strategy_name, rtt_tracker, state
            )

            now_weights = dict(kadabra.weights)
            if args.verbose:
                uptime_s = int(time.time() - state["started_at"])
                mm, ss = divmod(uptime_s, 60)
                rtt_avg = _compute_rtt_avg(rtt_tracker)
                hot = state.get("hot_stats") or {}
                print(
                    "[kad-spider] cycle=%d pool=%d alive=%d new=%d hellos=%d pongs=%d "
                    "rtt_avg=%d port=%d uptime=%02d:%02d"
                    % (
                        state["cycle"],
                        len(nodes),
                        state["alive"],
                        state["new_nodes"],
                        state["hello_res"],
                        state["pong"],
                        rtt_avg,
                        bound_port,
                        mm,
                        ss,
                    ),
                    flush=True,
                )
                print(
                    "[kad-spider] hot[%s] rows=%d hellos_sum=%d pings_sum=%d udp_keys=%d"
                    % (
                        hot.get("source", "?"),
                        hot.get("rows", 0),
                        hot.get("sum_hellos", 0),
                        hot.get("sum_pings", 0),
                        hot.get("with_udp_key", 0),
                    ),
                    flush=True,
                )

                top_items = [
                    (k, v)
                    for k, v in now_weights.items()
                    if v > KadabraState.BASE * 1.05
                ]
                if top_items:
                    top_items.sort(key=lambda kv: -kv[1])
                    top_entries = []
                    for key, w in top_items[:5]:
                        ip, udp_port = key
                        trend = w - prev_weights.get(key, 1.0)
                        prev_w = prev_weights.get(key, 1.0)
                        if prev_w > 0:
                            ratio = abs(trend) / max(abs(prev_w), 1e-6)
                            n = min(5, max(1, int(round(ratio * 5))))
                        else:
                            n = 1
                        if trend > 0:
                            arrow = ">"
                        elif trend < 0:
                            arrow = "<"
                        else:
                            arrow = "-"
                        chevrons = (arrow * n).ljust(5, "-")
                        now_rtt = rtt_tracker._ewma.get(key)
                        prev_rtt = prev_ewma.get(key)
                        if now_rtt is not None:
                            rtt_str = str(int(now_rtt))
                            if prev_rtt is not None:
                                if now_rtt < prev_rtt:
                                    rtt_char = "/"
                                elif now_rtt > prev_rtt:
                                    rtt_char = "\\"
                                else:
                                    rtt_char = "="
                            else:
                                rtt_char = "="
                        else:
                            rtt_str = "--"
                            rtt_char = ""
                        try:
                            v_rtt = int(vivaldi.predict(key))
                            v_str = str(v_rtt)
                        except Exception:
                            v_str = "--"
                        top_entries.append(
                            "%s:%d %s w=%.1f rtt=%sms%s v=%sms"
                            % (ip, udp_port, chevrons, w, rtt_str, rtt_char, v_str)
                        )
                    print(
                        "[kad-spider] top: " + " | ".join(top_entries),
                        flush=True,
                    )
                else:
                    print(
                        "[kad-spider] top: (no rewarded neighbors yet)",
                        flush=True,
                    )

                prev_weights = now_weights
                prev_ewma = dict(rtt_tracker._ewma)

            # reset per-cycle counters
            state["new_nodes"] = 0
            state["hello_res"] = 0
            state["pong"] = 0

            # pacing: sleep for remainder of cycle
            elapsed = loop.time() - cycle_start
            wait = max(0.5, args.cycle_s - elapsed)
            await asyncio.sleep(wait)

    except Exception as exc:
        log.error("spider error: error=%s", exc)
    finally:
        try:
            recv_task.cancel()
        except Exception:
            pass
        save_snapshot(nodes, own)
        save_kadabra_state(kadabra, project_root, decay_factor=1.0)
        _write_status(
            nodes, own, bound_port, strategy_name, rtt_tracker, state
        )
        log.info(
            "spider stopped: cycles=%d pool=%d alive=%d",
            state["cycle"],
            len(nodes),
            state["alive"],
        )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
