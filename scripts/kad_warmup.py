"""KAD network warm-up: HELLO/PING maturation cycles with node caching.

Runs for a configurable duration (default 20 minutes), continuously:
  1. bootstraps from nodes.dat + cached nodes (db/kad_nodes.json);
  2. sends KADEMLIA2_HELLO_REQ / KADEMLIA2_PING cycles over candidates;
  3. matures verified-alive contacts (hello count, last_seen, versions);
  4. saves a JSON snapshot (db/kad_nodes.json) every 60 seconds so the
     routing table persists across sessions.

scripts/kad_warmup.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added persistent KAD warm-up with HELLO/PING maturation and caching.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import time
from pathlib import Path
from typing import Any, Dict, Tuple

from amuled_v2.logging_setup import LogTags, configure_logging, get_tagged_logger

ROOT = Path(__file__).resolve().parents[1]
configure_logging(
    level=os.environ.get("AMULED_LOG_LEVEL", "INFO"),
    log_file=ROOT / "logs" / "amuled.jsonl",
)
from amuled_v2.core.kad.bootstrap import pick_bootstrap_nodes, bootstrap_nodes
from amuled_v2.core.kad.nodes_dat import load_nodes_dat
from amuled_v2.core.kad.obfuscation import decode_obfuscated_kad
from amuled_v2.core.kad.quality import NodeStats, quality_score
from amuled_v2.core.kad.rtt import RttTracker
from amuled_v2.core.kad.strategies import (
    active_strategy_name,
    get_strategy,
)
from amuled_v2.core.kad.vivaldi import LocalVivaldi
from amuled_v2.core.kad.packets import (
    KADEMLIA2_HELLO_RES,
    KADEMLIA2_PONG,
    KadUInt128,
    build_hello_req,
    build_ping,
    parse_hello_res,
    parse_kad_packet,
)

log = get_tagged_logger(LogTags.KAD, "kad.warmup")

NODES_DAT = ROOT / "assets" / "v1" / "nodes.dat"
CACHE_FILE = ROOT / "db" / "kad_nodes.json"
LOCAL_PORT = int(os.environ.get("AMULED_KAD_PORT", "0"))
DURATION_S = float(os.environ.get("AMULED_KAD_WARMUP_S", "1200"))
BATCH = 24
CYCLE_S = 25.0
SAVE_S = 60.0


def load_cache() -> Dict[str, Any]:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("cache load failed: error=%s", exc)
    return {}


async def main() -> None:
    cache = load_cache()
    own_hex = cache.get("own_id")
    own = (
        KadUInt128(bytes.fromhex(own_hex))
        if own_hex
        else KadUInt128(int.from_bytes(os.urandom(16), "big"))
    )
    log.info(
        "warmup start: own_id=%s duration_s=%.0f cache=%s",
        own,
        DURATION_S,
        CACHE_FILE,
    )

    # --- candidate pool: cached alive + nodes.dat ----------------------
    nodes: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for key, rec in (cache.get("nodes") or {}).items():
        ip, _, port = key.rpartition(":")
        nodes[(ip, int(port))] = {
            "kad_id": rec.get("kad_id", ""),
            "tcp": int(rec.get("tcp", 4662)),
            "ver": int(rec.get("ver", 0)),
            "hellos": int(rec.get("hellos", 0)),
            "pings": int(rec.get("pings", 0)),
            "last_seen": float(rec.get("last_seen", 0)),
        }
    for n in load_nodes_dat(NODES_DAT):
        nodes.setdefault(
            (n.ip, n.udp_port),
            {
                "kad_id": n.kad_id.hex() if isinstance(n.kad_id, bytes) else n.kad_id,
                "tcp": n.tcp_port,
                "ver": n.contact_version,
                "hellos": 0,
                "pings": 0,
                "last_seen": 0.0,
            },
        )
    log.info("candidate pool: %d nodes (cached alive: %d)",
             len(nodes), len(cache.get("nodes") or {}))

    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LOCAL_PORT))
    sock.setblocking(False)

    alive = 0
    hello_res = 0
    pong = 0
    t_start = loop.time()
    next_cycle = t_start
    next_save = t_start

    async def receiver() -> None:
        nonlocal alive, hello_res, pong
        while True:
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 65535), 1.0
                )
            except asyncio.TimeoutError:
                continue
            except Exception:
                return
            try:
                proto, op, payload = parse_kad_packet(data)
                if proto == 0xE5:
                    import zlib

                    payload = zlib.decompress(payload)
            except Exception:
                continue
            if proto not in (0xE4, 0xE5):
                # not a plain kad datagram: try the obfuscated decoder
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
                        import zlib

                        payload = zlib.decompress(payload)
                except Exception:
                    continue
                key = (addr[0], addr[1])
                rec = nodes.get(key)
                if rec is not None and send_key:
                    rec["udp_key"] = send_key
            key = (addr[0], addr[1])
            rec = nodes.get(key)
            if op == KADEMLIA2_HELLO_RES:
                try:
                    h = parse_hello_res(payload)
                except Exception:
                    continue
                hello_res += 1
                if rec is None:
                    rec = nodes[key] = {
                        "kad_id": "", "tcp": 0, "ver": 0,
                        "hellos": 0, "pings": 0, "last_seen": 0.0,
                    }
                rec["kad_id"] = h.contact_id.to_bytes().hex()
                rec["tcp"] = h.tcp_port
                rec["ver"] = h.version
                rec["hellos"] = int(rec["hellos"]) + 1
                rec["last_seen"] = time.time()
                if rec["hellos"] == 1:
                    alive += 1
                log.info(
                    "HELLO_RES: remote=%s:%d ver=%d tcp=%d hellos=%d "
                    "alive=%d udp_key=%s",
                    addr[0], addr[1], h.version, h.tcp_port, rec["hellos"],
                    alive, rec.get("udp_key", ""),
                )
            elif op == KADEMLIA2_PONG:
                pong += 1
                if rec is not None:
                    rec["pings"] = int(rec["pings"]) + 1
                    rec["last_seen"] = time.time()
                    sent_at = ping_sent.get(key)
                    if sent_at:
                        rtt = (time.time() - sent_at) * 1000.0
                        rec["rtt_ewma"] = rtt_tracker.update(key, rtt)
                        vivaldi.update(key, rtt)

    recv_task = asyncio.ensure_future(receiver())

    rtt_tracker = RttTracker()
    vivaldi = LocalVivaldi()
    ping_sent: Dict[Tuple[str, int], float] = {}
    strategy = get_strategy(active_strategy_name())
    log.info("seed strategy: name=%s", active_strategy_name())

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

    def save_snapshot() -> None:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "own_id": own.to_bytes().hex(),
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "nodes": {
                "%s:%d" % k: {
                    "kad_id": r["kad_id"],
                    "tcp": r["tcp"],
                    "ver": r["ver"],
                    "hellos": r["hellos"],
                    "pings": r["pings"],
                    "udp_key": r.get("udp_key", ""),
                    "last_seen": r["last_seen"],
                }
                for k, r in nodes.items()
                if r["hellos"] > 0 or r["pings"] > 0
            },
        }
        CACHE_FILE.write_text(
            json.dumps(payload, indent=1), encoding="utf-8"
        )
        log.info(
            "snapshot saved: file=%s alive_nodes=%d total_pool=%d",
            CACHE_FILE,
            len(payload["nodes"]),
            len(nodes),
        )
        _save_duckdb(payload["nodes"])

    def _save_duckdb(alive_nodes: dict) -> None:
        """Persist warmed nodes into DuckDB table kad_nodes (KAD tag)."""
        if not alive_nodes:
            return
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

    # --- bootstrap first ------------------------------------------------
    seeds = pick_bootstrap_nodes(str(NODES_DAT), 16)
    boot = await bootstrap_nodes(
        seeds, own_id=own, own_tcp_port=4662, timeout=6.0,
        local_port=LOCAL_PORT,
    )
    for n in boot.live_nodes:
        if n.kad_id:
            key = (n.ip, n.udp_port)
            rec = nodes.setdefault(
                key,
                {
                    "kad_id": n.kad_id.hex() if isinstance(n.kad_id, bytes) else n.kad_id,
                    "tcp": n.tcp_port, "ver": n.contact_version,
                    "hellos": 0, "pings": 0, "last_seen": 0.0,
                },
            )
            rec["hellos"] = int(rec.get("hellos", 0)) + 1
            rec["last_seen"] = time.time()
    log.info("bootstrap done: live=%d pool=%d", len(boot.live_nodes), len(nodes))

    # --- maturation cycles ----------------------------------------------
    while loop.time() - t_start < DURATION_S:
        # prioritize: never-helloed first, then freshest alive; the active
        # strategy (xor/quality/vivaldi) reorders the ordered core
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
        core = strategy(pool[: len(pool) // 2], _stats, rtt_tracker, vivaldi)
        tail = pool[len(pool) // 2 :]
        batch = core[:BATCH] + tail[-BATCH:]
        sent = 0
        for (ip, port), rec in batch:
            await send_hello(ip, port)
            sent += 1
            if sent % 3 == 0:
                await send_ping(ip, port)
            await asyncio.sleep(0.05)
        log.info(
            "cycle: sent=%d hellos=%d pong=%d alive=%d pool=%d elapsed=%.0fs",
            sent, hello_res, pong, alive, len(nodes), loop.time() - t_start,
        )
        if loop.time() >= next_save:
            save_snapshot()
            next_save = loop.time() + SAVE_S
        await asyncio.sleep(max(0.5, CYCLE_S - (loop.time() - next_cycle)))
        next_cycle = loop.time() + CYCLE_S

    recv_task.cancel()
    save_snapshot()
    log.info(
        "warmup done: alive=%d hellos=%d pong=%d snapshot=%s",
        alive, hello_res, pong, CACHE_FILE,
    )


if __name__ == "__main__":
    asyncio.run(main())
