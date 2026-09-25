"""KAD spider engine (stage U phase 2): the maturation cycle as a library.

Direct port of ``scripts/kad_spider.py`` (v0.2.0) into the package so the
unified kernel can run the spider **in-process**: one asyncio loop, one UDP
socket, and — through the injected ``StateBackend`` — ONE DuckDB connection
shared with the listener instead of two processes fighting over the
single-writer file lock.

Standalone mode (no injected backend) keeps the historical open/close-per-
save behavior; the kernel injects its permanent connection and never closes
it mid-run.

src/amuled_v2/core/kad/spider.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-25

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Ported the kad_spider daemon into SpiderEngine (receiver, strategy
      batch maturation cycle, bootstrap refresh, pool pruning, snapshot
      persistence) with injectable StateBackend and stop-event lifecycle.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import time
import zlib
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.spider")

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
from amuled_v2.core.kad.runtime import load_kadabra_state, save_kadabra_state
from amuled_v2.core.kad.strategies import (
    KadabraState,
    active_strategy_name,
    get_strategy,
)
from amuled_v2.core.kad.vivaldi import LocalVivaldi

BATCH = 24
DEFAULT_PORT = int(os.environ.get("AMULED_KAD_SPIDER_PORT", "4672"))
STALE_DAYS = int(os.environ.get("AMULED_KAD_SPIDER_STALE_DAYS", "7"))
MAX_POOL = int(os.environ.get("AMULED_KAD_SPIDER_MAX_POOL", "2000"))


def is_routable_ipv4(ip: str) -> bool:
    """Usable IPv4 unicast only (drops 0/8 and >=224/8)."""
    try:
        first_octet = int(ip.split(".")[0])
    except (ValueError, IndexError):
        return False
    return first_octet != 0 and first_octet < 224


def load_cache(root: Path) -> Dict[str, Any]:
    cache_file = root / "db" / "kad_nodes.json"
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("cache load failed: error=%s", exc)
    return {}


def build_pool(root: Path, cache: Dict[str, Any]) -> Dict[Tuple[str, int], Dict[str, Any]]:
    """Merge cached alive nodes + nodes.dat into a candidate pool."""
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
    nodes_dat = root / "assets" / "v1" / "nodes.dat"
    if nodes_dat.exists():
        for n in load_nodes_dat(nodes_dat):
            if not is_routable_ipv4(n.ip):
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


def prune_pool(nodes: Dict[Tuple[str, int], Dict[str, Any]]) -> int:
    """Rotate stale nodes out; returns pruned count (spider doctrine rule)."""
    now = time.time()
    stale_seconds = STALE_DAYS * 86400
    stale_keys = [
        k for k, r in nodes.items() if now - r["last_seen"] > stale_seconds
    ]
    for k in stale_keys:
        del nodes[k]
    pruned = len(stale_keys)
    overflow = len(nodes) - MAX_POOL
    if overflow > 0:
        oldest = sorted(nodes.items(), key=lambda kv: kv[1]["last_seen"])[
            :overflow
        ]
        for k, _ in oldest:
            del nodes[k]
        pruned += overflow
    return pruned


class SpiderEngine:
    """One UDP socket + maturation cycles; DuckDB via injected backend."""

    def __init__(
        self,
        root: Path,
        *,
        state_backend: Any = None,
        udp_port: int = DEFAULT_PORT,
        cycle_s: float = 25.0,
        save_s: float = 60.0,
        bootstrap_every: int = 6,
        verbose: bool = False,
    ) -> None:
        self.root = root
        self.cache_file = root / "db" / "kad_nodes.json"
        self.status_file = root / "db" / "kad_status.json"
        self.state_backend = state_backend  # kernel-owned when injected
        self.udp_port = udp_port
        self.cycle_s = cycle_s
        self.save_s = save_s
        self.bootstrap_every = bootstrap_every
        self.verbose = verbose

        cache = load_cache(root)
        own_hex = cache.get("own_id")
        self.own = (
            KadUInt128(bytes.fromhex(own_hex))
            if own_hex
            else KadUInt128(int.from_bytes(os.urandom(16), "big"))
        )
        if not own_hex:
            self._persist_own_id(self.cache_file, self.own, cache.get("nodes", {}) or {})
        self.nodes = build_pool(root, cache)

        self.sock: Optional[socket.socket] = None
        self.bound_port = 0
        self.kadabra = load_kadabra_state(root)
        self.rtt = RttTracker()
        self.vivaldi = LocalVivaldi()
        self.strategy_name = active_strategy_name()
        self.ping_sent: Dict[Tuple[str, int], float] = {}
        self.state: Dict[str, Any] = {
            "alive": 0,
            "cycle": 0,
            "last_save": 0.0,
            "last_bootstrap": 0.0,
            "hot_stats": {},
        }

    # -- persistence ------------------------------------------------------

    def _persist_own_id(
        self, cache_file: Path, own_id: KadUInt128, existing_nodes: dict[str, Any]
    ) -> None:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {"own_id": own_id.to_bytes().hex(), "nodes": existing_nodes}
        tmp = cache_file.with_suffix(cache_file.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=1), encoding="utf-8")
        os.replace(tmp, cache_file)
        log.info("own_id persisted: own_id=%s", own_id)

    def save_snapshot(self) -> None:
        """JSON cache always; DuckDB via owned backend (no open/close)."""
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        alive: Dict[str, Dict[str, Any]] = {}
        for k, r in self.nodes.items():
            if r["hellos"] > 0 or r["pings"] > 0:
                alive["%s:%d" % k] = {
                    "kad_id": r["kad_id"],
                    "tcp": r["tcp"],
                    "ver": r["ver"],
                    "hellos": r["hellos"],
                    "pings": r["pings"],
                    "udp_key": r.get("udp_key", ""),
                    "last_seen": r["last_seen"],
                }
        payload = {
            "own_id": self.own.to_bytes().hex(),
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "nodes": alive,
        }
        tmp = self.cache_file.with_suffix(self.cache_file.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=1), encoding="utf-8")
        os.replace(tmp, self.cache_file)
        log.info(
            "snapshot saved: alive_nodes=%d total_pool=%d",
            len(alive),
            len(self.nodes),
        )
        self._save_duckdb(alive)

    def _save_duckdb(self, alive_nodes: dict) -> None:
        if not alive_nodes:
            return
        try:
            if self.state_backend is not None:
                con = self.state_backend._require_duckdb()
            else:
                from amuled_v2.state import get_state

                state = get_state()
                state.connect()
                try:
                    con = state._require_duckdb()
                    self._upsert_kad_nodes(con, alive_nodes)
                finally:
                    state.close()
                return
            self._upsert_kad_nodes(con, alive_nodes)
        except Exception as exc:
            log.warning("duckdb save failed: error=%s", exc)

    def _upsert_kad_nodes(self, con: Any, alive_nodes: dict) -> None:
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
        log.info("kad_nodes upserted into DuckDB: rows=%d", len(rows))

    def status_snapshot(self) -> Dict[str, Any]:
        hot = self.state.get("hot_stats") or {}
        return {
            "pid": os.getpid(),
            "own_id": self.own.to_bytes().hex(),
            "uptime_cycles": self.state["cycle"],
            "pool_size": len(self.nodes),
            "alive_estimate": self.state["alive"],
            "udp_keys": sum(1 for r in self.nodes.values() if r.get("udp_key")),
            "bound_port": self.bound_port,
            "strategy": self.strategy_name,
            "hot_nodes_stats": hot,
        }

    def _write_status(self) -> None:
        self.status_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 2, **self.status_snapshot()}
        tmp = self.status_file.with_suffix(self.status_file.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, self.status_file)

    # -- networking --------------------------------------------------------

    def _bind_socket(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", self.udp_port))
        except OSError as exc:
            log.warning(
                "socket bind failed on port=%d: error=%s, ephemeral fallback",
                self.udp_port,
                exc,
            )
            sock.bind(("0.0.0.0", 0))
        self.bound_port = sock.getsockname()[1]
        sock.setblocking(False)
        self.sock = sock
        log.info("spider socket bound: port=%d", self.bound_port)

    def _hot_stats(self) -> Dict[str, Any]:
        stats: Dict[str, Any] = {
            "source": "memory",
            "rows": 0,
            "sum_hellos": 0,
            "sum_pings": 0,
            "with_udp_key": 0,
        }
        try:
            if self.state_backend is not None:
                con = self.state_backend._require_duckdb()
            else:
                import duckdb

                con = duckdb.connect(
                    str(self.root / "db" / "amuled.db"), read_only=True
                )
            try:
                row = con.execute(
                    """
                    SELECT COUNT(*), COALESCE(SUM(hellos), 0),
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
                if self.state_backend is None:
                    con.close()
        except Exception:
            hot = [r for r in self.nodes.values() if r["hellos"] > 0 or r["pings"] > 0]
            stats.update(
                rows=len(hot),
                sum_hellos=sum(int(r["hellos"]) for r in hot),
                sum_pings=sum(int(r["pings"]) for r in hot),
                with_udp_key=sum(1 for r in hot if r.get("udp_key")),
            )
        return stats

    # -- lifecycle ----------------------------------------------------------

    async def run(self, stop: asyncio.Event) -> None:
        """Full lifecycle until ``stop`` is set; saves on exit."""
        loop = asyncio.get_running_loop()
        self._bind_socket()
        sock = self.sock
        assert sock is not None
        nodes = self.nodes
        state = self.state
        state["last_save"] = time.time()
        kadabra = self.kadabra
        strategy = get_strategy(self.strategy_name)

        async def receiver() -> None:
            while not stop.is_set():
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
                        data, self.own.to_bytes(),
                        peer_ip=addr[0], peer_port=addr[1],
                    )
                    if plain is None:
                        continue
                    pkt, _rk, send_key = plain
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
                elif op == KADEMLIA2_PONG:
                    kadabra.reward((addr[0], addr[1]), 0.2)
                    if rec is not None:
                        rec["pings"] = int(rec["pings"]) + 1
                        rec["last_seen"] = time.time()
                        sent_at = self.ping_sent.get(key)
                        if sent_at:
                            rtt = (time.time() - sent_at) * 1000.0
                            rec["rtt_ewma"] = self.rtt.update(key, rtt)
                            self.vivaldi.update(key, rtt)
                elif op == KADEMLIA2_BOOTSTRAP_RES:
                    kadabra.reward((addr[0], addr[1]), 2.0)
                    try:
                        _sid, contacts = parse_bootstrap_res(payload)
                    except Exception:
                        continue
                    for c in contacts:
                        ck = (c.ip, c.udp_port)
                        if not is_routable_ipv4(c.ip):
                            continue
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
                        c_rec = nodes[ck]
                        if c.kad_id:
                            c_rec["kad_id"] = (
                                c.kad_id.hex() if isinstance(c.kad_id, bytes) else c.kad_id
                            )
                        c_rec["tcp"] = c.tcp_port
                        c_rec["ver"] = c.contact_version

        async def sendto(data: bytes, ip: str, port: int) -> None:
            try:
                await loop.sock_sendto(sock, data, (ip, port))
            except OSError:
                pass

        recv_task = asyncio.ensure_future(receiver())
        log.info(
            "spider engine start: own_id=%s port=%d cycle_s=%.1f save_s=%.1f pool=%d",
            self.own, self.bound_port, self.cycle_s, self.save_s, len(nodes),
        )
        try:
            nodes_dat = self.root / "assets" / "v1" / "nodes.dat"
            if nodes_dat.exists():
                seeds = pick_bootstrap_nodes(str(nodes_dat), 12)
                sent = 0
                for n in seeds:
                    if not is_routable_ipv4(n.ip):
                        continue
                    await sendto(build_bootstrap_req(self.own), n.ip, n.udp_port)
                    sent += 1
                state["last_bootstrap"] = time.time()
                log.info("initial bootstrap seeds sent: count=%d", sent)
                await asyncio.sleep(3.0)

            while not stop.is_set():
                cycle_start = loop.time()

                def _stats(kv) -> NodeStats:
                    r = kv[1]
                    return NodeStats(
                        hellos=int(r["hellos"]),
                        pings=int(r["pings"]),
                        rtt_ewma=float(r.get("rtt_ewma", 0.0)),
                        last_seen=float(r["last_seen"]),
                    )

                pool = sorted(
                    nodes.items(), key=lambda kv: (-kv[1]["hellos"], -kv[1]["last_seen"])
                )
                mid = len(pool) // 2
                core = strategy(pool[:mid], _stats, self.rtt, self.vivaldi)
                core = sorted(core, key=lambda kv: -kadabra.weight(kv[0]))
                batch = core[:BATCH] + pool[mid:][-BATCH:]

                sent = 0
                for (ip, port), _rec in batch:
                    if stop.is_set():
                        break
                    await sendto(build_hello_req(self.own, 4662), ip, port)
                    sent += 1
                    if sent % 3 == 0:
                        self.ping_sent[(ip, port)] = time.time()
                        await sendto(build_ping(), ip, port)
                    await asyncio.sleep(0.05)

                if (
                    state["cycle"] > 0
                    and state["cycle"] % self.bootstrap_every == 0
                    and nodes_dat.exists()
                ):
                    seeds = pick_bootstrap_nodes(str(nodes_dat), 12)
                    sent_boot = 0
                    for n in seeds:
                        if not is_routable_ipv4(n.ip):
                            continue
                        await sendto(build_bootstrap_req(self.own), n.ip, n.udp_port)
                        sent_boot += 1
                    state["last_bootstrap"] = time.time()
                    log.info("periodic bootstrap: sent=%d", sent_boot)

                now = loop.time()
                if now >= state["last_save"] + self.save_s:
                    pruned = prune_pool(nodes)
                    if pruned:
                        log.info("pool pruned: removed=%d pool=%d", pruned, len(nodes))
                    self.save_snapshot()
                    save_kadabra_state(kadabra, self.root, decay_factor=0.95)
                    state["last_save"] = time.time()

                state["cycle"] += 1
                state["hot_stats"] = self._hot_stats()
                self._write_status()

                if self.verbose:
                    hot = state.get("hot_stats") or {}
                    log.info(
                        "spider cycle: cycle=%d pool=%d alive=%d "
                        "hellos_sum=%d pongs_sum=%d hot_rows=%d",
                        state["cycle"], len(nodes), state["alive"],
                        hot.get("sum_hellos", 0), hot.get("sum_pings", 0),
                        hot.get("rows", 0),
                    )

                elapsed = loop.time() - cycle_start
                try:
                    await asyncio.wait_for(
                        stop.wait(), timeout=max(0.5, self.cycle_s - elapsed)
                    )
                except asyncio.TimeoutError:
                    pass
        except Exception as exc:
            log.error("spider engine error: error=%s", exc)
        finally:
            recv_task.cancel()
            self.save_snapshot()
            save_kadabra_state(kadabra, self.root, decay_factor=1.0)
            self._write_status()
            if self.sock is not None:
                self.sock.close()
            log.info(
                "spider engine stopped: cycles=%d pool=%d alive=%d",
                state["cycle"], len(nodes), state["alive"],
            )
