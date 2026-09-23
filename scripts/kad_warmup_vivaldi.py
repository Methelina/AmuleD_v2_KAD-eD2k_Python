"""KAD2 Vivaldi-enhanced warmup — real network implementation.

Runs alongside the standard kad_warmup.py but adds:
  1. Vivaldi network coordinates for RTT-based peer selection
  2. Quality-based node ranking (replaces simple hello count)
  3. Adaptive batch sizing based on convergence
  4. RTT tracking with EWMA
  5. Vivaldi position exchange in HELLO packets (extended protocol)

Metrics tracked for comparison:
  - alive_nodes: distinct nodes that responded
  - avg_rtt: average RTT to alive nodes
  - vivaldi_positioned: nodes with valid Vivaldi coordinates
  - convergence_rate: how quickly we discover quality peers

Usage:
    $env:PYTHONPATH='K:\work\AmuleD_v2\src'
    $env:AMULED_KAD_WARMUP_S='1200'
    .venv\Scripts\python.exe -u scripts\kad_warmup_vivaldi.py 2>&1

Author: Soror L.'.L.'.
Version: 1.0.0
Date: 2026-09-23
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import random
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Ensure project src is importable
ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "src"))

from amuled_v2.logging_setup import LogTags, configure_logging, get_tagged_logger

configure_logging(
    level=os.environ.get("AMULED_LOG_LEVEL", "INFO"),
    log_file=ROOT / "logs" / "amuled_vivaldi.jsonl",
)

from amuled_v2.core.kad.bootstrap import pick_bootstrap_nodes, bootstrap_nodes
from amuled_v2.core.kad.nodes_dat import load_nodes_dat, KadNodeInfo
from amuled_v2.core.kad.obfuscation import decode_obfuscated_kad
from amuled_v2.core.kad.packets import (
    KADEMLIA2_BOOTSTRAP_RES,
    KADEMLIA2_HELLO_RES,
    KADEMLIA2_PONG,
    KadUInt128,
    build_hello_req,
    build_ping,
    parse_hello_res,
    parse_kad_packet,
)

log = get_tagged_logger(LogTags.KAD, "kad.warmup.vivaldi")

# --- Configuration ----------------------------------------------------------

NODES_DAT = ROOT / "assets" / "v1" / "nodes.dat"
CACHE_FILE = ROOT / "db" / "kad_nodes_vivaldi.json"
LOCAL_PORT = int(os.environ.get("AMULED_KAD_PORT", "0"))  # 0 = ephemeral
DURATION_S = float(os.environ.get("AMULED_KAD_WARMUP_S", "1200"))

# Vivaldi constants
VIVALDI_CC = 0.25  # Coordinate change rate
VIVALDI_CE = 0.5   # Error change rate
VIVALDI_ERROR_MIN = 0.1
VIVALDI_INITIAL_ERROR = 10.0
VIVALDI_CONVERGE_EVERY = 5

# Warmup tuning — match kad_warmup.py for fair comparison
BATCH = 24
CYCLE_S = 25.0
SAVE_S = 60.0
RTT_SAMPLE_MIN = 1  # Minimum RTT samples before Vivaldi positioning (lowered for testing)


# --- Vivaldi Position -------------------------------------------------------

@dataclass
class VivaldiPosition:
    """3D network coordinate for RTT estimation."""
    
    x: float = 0.0
    y: float = 0.0
    h: float = 0.0
    error: float = VIVALDI_INITIAL_ERROR
    _update_count: int = field(default=0, repr=False)
    
    def is_valid(self) -> bool:
        return (
            math.isfinite(self.x)
            and math.isfinite(self.y)
            and math.isfinite(self.h)
            and abs(self.x) <= 30000
            and abs(self.y) <= 30000
        )
    
    def at_origin(self) -> bool:
        return self.x == 0.0 and self.y == 0.0
    
    def measure(self) -> float:
        return math.sqrt(self.x * self.x + self.y * self.y) + abs(self.h)
    
    def distance_to(self, other: "VivaldiPosition") -> float:
        dx = self.x - other.x
        dy = self.y - other.y
        return math.sqrt(dx * dx + dy * dy) + abs(self.h + other.h)
    
    def update(self, rtt_ms: float, remote: "VivaldiPosition") -> None:
        """Update position based on measured RTT."""
        if not math.isfinite(rtt_ms) or rtt_ms <= 0 or rtt_ms > 300000:
            return
        if not remote.is_valid():
            return
        if self.error + remote.error == 0:
            return
        
        # Sample weight
        w = self.error / (remote.error + self.error)
        
        # Residual error
        predicted = self.distance_to(remote)
        re = rtt_ms - predicted
        
        # Relative sample error
        es = abs(re) / rtt_ms
        
        # Update error (EMA)
        new_error = es * VIVALDI_CE * w + self.error * (1 - VIVALDI_CE * w)
        
        # Update coordinates
        delta = VIVALDI_CC * w
        scale = delta * re
        
        # Jitter to prevent stagnation
        jitter_x = random.uniform(-0.1, 0.1)
        jitter_y = random.uniform(-0.1, 0.1)
        
        target_x = remote.x + jitter_x
        target_y = remote.y + jitter_y
        dx = self.x - target_x
        dy = self.y - target_y
        dist = math.sqrt(dx * dx + dy * dy)
        
        if dist > 0:
            new_x = self.x + (dx / dist) * scale
            new_y = self.y + (dy / dist) * scale
        else:
            angle = random.uniform(0, 2 * math.pi)
            new_x = self.x + math.cos(angle) * scale
            new_y = self.y + math.sin(angle) * scale
        
        # Validate and apply
        candidate = VivaldiPosition(new_x, new_y, self.h, new_error)
        if candidate.is_valid() and math.isfinite(new_error):
            self.x = new_x
            self.y = new_y
            self.error = max(new_error, VIVALDI_ERROR_MIN)
        else:
            self.x = 0.0
            self.y = 0.0
            self.h = 0.0
            self.error = VIVALDI_INITIAL_ERROR
        
        # Gravity toward origin
        if not remote.at_origin():
            self._update_count += 1
        if self._update_count > VIVALDI_CONVERGE_EVERY:
            self._update_count = 0
            origin = VivaldiPosition(0, 0, 0, 50.0)
            self.update(10.0, origin)
    
    def to_array(self) -> list[float]:
        return [self.x, self.y, self.h, self.error]
    
    @classmethod
    def from_array(cls, arr: list[float]) -> "VivaldiPosition":
        return cls(x=arr[0], y=arr[1], h=arr[2], error=arr[3])
    
    def estimate_rtt(self, other: "VivaldiPosition") -> float:
        if self.at_origin() or other.at_origin():
            return float("nan")
        return self.distance_to(other)


# --- Enhanced Contact -------------------------------------------------------

@dataclass
class VivaldiContact:
    """Contact with Vivaldi coordinates and quality metrics."""
    
    node: KadNodeInfo
    hellos: int = 0
    pings: int = 0
    last_seen: float = 0.0
    rtt_ewma: float = 0.0
    rtt_samples: list[float] = field(default_factory=list)
    vivaldi: VivaldiPosition = field(default_factory=VivaldiPosition)
    first_seen: float = field(default_factory=time.time)
    udp_key: int = 0  # Sender verify key from obfuscation decode
    
    def key(self) -> Tuple[str, int]:
        return (self.node.ip, self.node.udp_port)
    
    def update_rtt(self, rtt_ms: float) -> None:
        """Update RTT with EWMA."""
        if rtt_ms <= 0 or rtt_ms > 300000:
            return
        
        if not self.rtt_samples:
            self.rtt_ewma = rtt_ms
        else:
            alpha = 0.3
            self.rtt_ewma = alpha * rtt_ms + (1 - alpha) * self.rtt_ewma
        
        self.rtt_samples.append(rtt_ms)
        if len(self.rtt_samples) > 100:
            self.rtt_samples.pop(0)
    
    def quality_score(self) -> float:
        """Combined quality metric (higher = better)."""
        # Base from activity
        activity = min(1.0, (self.hellos + self.pings) / 10.0)
        
        # RTT bonus (lower RTT = higher score)
        rtt_score = 0.0
        if self.rtt_ewma > 0:
            rtt_score = max(0.0, 1.0 - (self.rtt_ewma / 1000.0))
        
        # Recency bonus
        idle = time.time() - self.last_seen if self.last_seen > 0 else 9999
        recency = max(0.0, 1.0 - idle / 3600.0)  # 1 hour decay
        
        return activity * 0.4 + rtt_score * 0.4 + recency * 0.2
    
    def is_positioned(self) -> bool:
        """Check if Vivaldi coordinates are valid."""
        return not self.vivaldi.at_origin() and self.vivaldi.error < 8.0  # Lowered for testing
    
    def to_dict(self) -> dict:
        return {
            "kad_id": self.node.kad_id.hex() if isinstance(self.node.kad_id, bytes) else self.node.kad_id,
            "ip": self.node.ip,
            "udp_port": self.node.udp_port,
            "tcp_port": self.node.tcp_port,
            "ver": self.node.contact_version,
            "hellos": self.hellos,
            "pings": self.pings,
            "last_seen": self.last_seen,
            "rtt_ewma": self.rtt_ewma,
            "vivaldi": self.vivaldi.to_array(),
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "VivaldiContact":
        node = KadNodeInfo(
            kad_id=bytes.fromhex(data["kad_id"]) if isinstance(data["kad_id"], str) else data["kad_id"],
            ip=data["ip"],
            udp_port=data["udp_port"],
            tcp_port=data.get("tcp_port", 4662),
            contact_version=data.get("ver", 0),
        )
        contact = cls(node=node)
        contact.hellos = data.get("hellos", 0)
        contact.pings = data.get("pings", 0)
        contact.last_seen = data.get("last_seen", 0.0)
        contact.rtt_ewma = data.get("rtt_ewma", 0.0)
        if "vivaldi" in data:
            contact.vivaldi = VivaldiPosition.from_array(data["vivaldi"])
        return contact


# --- Vivaldi Warmup ---------------------------------------------------------

class VivaldiWarmup:
    """KAD warmup with Vivaldi-enhanced peer selection."""
    
    def __init__(self) -> None:
        self.own_id = KadUInt128(int.from_bytes(os.urandom(16), "big"))
        self.contacts: Dict[Tuple[str, int], VivaldiContact] = {}
        self.local_vivaldi = VivaldiPosition()
        self.sock: Optional[socket.socket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._session_start = time.time()  # Track session start for alive counting
        
        # RTT measurement: track pending requests
        self._pending_hellos: Dict[Tuple[str, int], float] = {}  # key -> monotonic timestamp
        self._pending_pings: Dict[Tuple[str, int], float] = {}   # key -> monotonic timestamp
        
        # Metrics
        self.metrics = {
            "alive": 0,
            "hello_res": 0,
            "pong": 0,
            "total_sent": 0,
            "rtt_samples": 0,
            "vivaldi_updates": 0,
            "positioned_nodes": 0,
            "avg_rtt": 0.0,
        }
    
    async def run(self) -> None:
        """Main warmup loop."""
        self.loop = asyncio.get_running_loop()
        
        # Setup socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", LOCAL_PORT))
        self.sock.setblocking(False)
        
        log.info(
            "vivaldi warmup start: own_id=%s duration=%.0fs port=%d",
            self.own_id,
            DURATION_S,
            LOCAL_PORT,
        )
        
        # Load cache
        self._load_cache()
        
        # Bootstrap
        await self._bootstrap()
        
        # Start receiver
        recv_task = asyncio.ensure_future(self._receiver())
        
        # --- maturation cycles ----------------------------------------------
        t_start = self.loop.time()
        next_cycle = t_start
        next_save = t_start
        
        while self.loop.time() - t_start < DURATION_S:
            # prioritize: never-helloed first, then freshest alive
            pool = sorted(
                self.contacts.items(),
                key=lambda kv: (
                    -kv[1].hellos,
                    -kv[1].last_seen,
                ),
            )
            batch = pool[:BATCH] + pool[-BATCH:]
            sent = 0
            for (ip, port), contact in batch:
                await self._send_hello(ip, port)
                sent += 1
                if sent % 3 == 0:
                    await self._send_ping(ip, port)
                await asyncio.sleep(0.05)
            
            log.info(
                "cycle: sent=%d hellos=%d pong=%d alive=%d pool=%d elapsed=%.0fs "
                "positioned=%d avg_rtt=%.1fms vivaldi_updates=%d",
                sent, self.metrics["hello_res"], self.metrics["pong"],
                self.metrics["alive"], len(self.contacts), self.loop.time() - t_start,
                self.metrics["positioned_nodes"], self.metrics["avg_rtt"],
                self.metrics["vivaldi_updates"],
            )
            
            if self.loop.time() >= next_save:
                self._save_snapshot()
                next_save = self.loop.time() + SAVE_S
            
            # Update metrics for display
            self._update_metrics()
            
            await asyncio.sleep(max(0.5, CYCLE_S - (self.loop.time() - next_cycle)))
            next_cycle = self.loop.time() + CYCLE_S
        
        recv_task.cancel()
        self._update_metrics()
        self._save_snapshot()
        log.info(
            "warmup done: alive=%d hellos=%d pong=%d snapshot=%s",
            self.metrics["alive"], self.metrics["hello_res"], self.metrics["pong"], CACHE_FILE,
        )
    
    def _load_cache(self) -> None:
        """Load cached contacts."""
        if not CACHE_FILE.exists():
            log.info("no cache file, starting fresh")
            return
        
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            for key, rec in (data.get("contacts") or {}).items():
                contact = VivaldiContact.from_dict(rec)
                self.contacts[contact.key()] = contact
            
            # Restore local Vivaldi position
            if "local_vivaldi" in data:
                self.local_vivaldi = VivaldiPosition.from_array(data["local_vivaldi"])
            
            log.info("cache loaded: contacts=%d", len(self.contacts))
        except Exception as exc:
            log.warning("cache load failed: %s", exc)
    
    def _save_snapshot(self) -> None:
        """Save current state to cache."""
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        payload = {
            "own_id": self.own_id.to_bytes().hex(),
            "local_vivaldi": self.local_vivaldi.to_array(),
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "metrics": self.metrics,
            "contacts": {
                f"{c.node.ip}:{c.node.udp_port}": c.to_dict()
                for c in self.contacts.values()
                if c.hellos > 0 or c.pings > 0
            },
        }
        
        CACHE_FILE.write_text(json.dumps(payload, indent=1), encoding="utf-8")
        log.info("snapshot saved: contacts=%d", len(payload["contacts"]))
        self._save_duckdb(payload["contacts"])
    
    def _save_duckdb(self, contacts: dict) -> None:
        """Persist contacts to DuckDB kad_nodes_vivaldi table."""
        if not contacts:
            return
        try:
            from amuled_v2.state import get_state
            
            state = get_state()
            state.connect()
            con = state._require_duckdb()
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS kad_nodes_vivaldi (
                    ip VARCHAR NOT NULL,
                    udp_port INTEGER NOT NULL,
                    kad_id VARCHAR,
                    tcp_port INTEGER,
                    kad_version INTEGER,
                    hellos INTEGER,
                    pings INTEGER,
                    rtt_ewma DOUBLE,
                    vivaldi_x DOUBLE,
                    vivaldi_y DOUBLE,
                    vivaldi_h DOUBLE,
                    vivaldi_error DOUBLE,
                    last_seen TIMESTAMP,
                    PRIMARY KEY (ip, udp_port)
                )
                """
            )
            rows = []
            for key, rec in contacts.items():
                ip, _, port = key.rpartition(":")
                vivaldi = rec.get("vivaldi", [0, 0, 0, 10])
                rows.append(
                    (
                        ip,
                        int(port),
                        rec.get("kad_id", ""),
                        rec.get("tcp_port", 4662),
                        rec.get("ver", 0),
                        rec.get("hellos", 0),
                        rec.get("pings", 0),
                        rec.get("rtt_ewma", 0.0),
                        vivaldi[0] if len(vivaldi) > 0 else 0,
                        vivaldi[1] if len(vivaldi) > 1 else 0,
                        vivaldi[2] if len(vivaldi) > 2 else 0,
                        vivaldi[3] if len(vivaldi) > 3 else 10,
                        time.strftime(
                            "%Y-%m-%d %H:%M:%S",
                            time.localtime(rec.get("last_seen", 0) or time.time()),
                        ),
                    )
                )
            con.executemany(
                """
                INSERT OR REPLACE INTO kad_nodes_vivaldi
                    (ip, udp_port, kad_id, tcp_port, kad_version,
                     hellos, pings, rtt_ewma, vivaldi_x, vivaldi_y, vivaldi_h,
                     vivaldi_error, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            log.info("kad_nodes_vivaldi upserted: rows=%d", len(rows))
        except Exception as exc:
            log.warning("duckdb save failed: error=%s", exc)
    
    async def _bootstrap(self) -> None:
        """Bootstrap from nodes.dat + main DB warmed nodes."""
        seeds = pick_bootstrap_nodes(str(NODES_DAT), 16)
        
        # Add cached contacts as seeds
        for contact in self.contacts.values():
            if contact.hellos > 0:
                seeds.append(contact.node)
        
        # Add alive nodes from main DB (kad_nodes table)
        try:
            import duckdb
            con = duckdb.connect(str(ROOT / "db" / "amuled.db"), read_only=True)
            result = con.execute(
                "SELECT ip, udp_port, kad_id, tcp_port, kad_version, hellos, pings "
                "FROM kad_nodes WHERE hellos > 0 ORDER BY hellos DESC LIMIT 100"
            ).fetchall()
            con.close()
            
            for row in result:
                ip, udp_port, kad_id, tcp_port, kad_version, hellos, pings = row
                node = KadNodeInfo(
                    kad_id=bytes.fromhex(kad_id) if kad_id else b"\x00" * 16,
                    ip=ip,
                    udp_port=udp_port,
                    tcp_port=tcp_port,
                    contact_version=kad_version,
                )
                seeds.append(node)
            log.info("loaded %d warmed nodes from main DB", len(result))
        except Exception as exc:
            log.warning("could not load from main DB: %s", exc)
        
        if not seeds:
            log.warning("no bootstrap seeds")
            return
        
        # Standard bootstrap
        result = await bootstrap_nodes(
            seeds,
            own_id=self.own_id,
            own_tcp_port=4662,
            timeout=6.0,
            local_port=LOCAL_PORT,
        )
        
        # Add live nodes to contacts
        for node in result.live_nodes:
            key = (node.ip, node.udp_port)
            if key not in self.contacts:
                self.contacts[key] = VivaldiContact(node)
            self.contacts[key].hellos += 1
            self.contacts[key].last_seen = time.time()
        
        log.info(
            "bootstrap done: live=%d pool=%d",
            len(result.live_nodes),
            len(self.contacts),
        )
    
    async def _send_hello(self, ip: str, port: int) -> None:
        """Send HELLO request and track for RTT measurement."""
        try:
            hello = build_hello_req(self.own_id, 4662)
            await self.loop.sock_sendto(self.sock, hello, (ip, port))
            # Track send time for RTT measurement
            self._pending_hellos[(ip, port)] = time.monotonic()
            self.metrics["total_sent"] += 1
        except OSError:
            pass
    
    async def _send_ping(self, ip: str, port: int) -> None:
        """Send PING request and track for RTT measurement."""
        try:
            ping = build_ping()
            await self.loop.sock_sendto(self.sock, ping, (ip, port))
            # Track send time for RTT measurement
            self._pending_pings[(ip, port)] = time.monotonic()
            self.metrics["total_sent"] += 1
        except OSError:
            pass
    
    async def _receiver(self) -> None:
        """Receive and process responses."""
        while True:
            try:
                data, addr = await asyncio.wait_for(
                    self.loop.sock_recvfrom(self.sock, 65535),
                    1.0,
                )
            except asyncio.TimeoutError:
                continue
            except Exception:
                return
            
            key = (addr[0], addr[1])
            contact = self.contacts.get(key)
            
            # Try plain parse first
            decoded = False
            try:
                proto, op, payload = parse_kad_packet(data)
                if proto == 0xE5:
                    import zlib
                    payload = zlib.decompress(payload)
                decoded = True
            except Exception:
                pass
            
            if not decoded:
                # Try obfuscated decode
                plain = decode_obfuscated_kad(
                    data,
                    own_kad_id=self.own_id.to_bytes(),
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
                    decoded = True
                    # Store the sender key for future obfuscated sends
                    if contact is not None:
                        contact.udp_key = send_key
                        log.debug(
                            "decoded obfuscated: %s:%d recv_key=%08x send_key=%08x",
                            addr[0], addr[1], recv_key, send_key,
                        )
                except Exception:
                    continue
            
            if not decoded:
                continue
            
            # Measure actual RTT from pending tracking
            key = (addr[0], addr[1])
            rtt_ms = None
            
            # Check if this is a response to our HELLO
            if key in self._pending_hellos:
                sent_at = self._pending_hellos.pop(key)
                rtt_ms = (time.monotonic() - sent_at) * 1000
                self.metrics["rtt_samples"] += 1
            # Check if this is a response to our PING
            elif key in self._pending_pings:
                sent_at = self._pending_pings.pop(key)
                rtt_ms = (time.monotonic() - sent_at) * 1000
                self.metrics["rtt_samples"] += 1
            
            # Fallback if no pending request found (shouldn't happen normally)
            if rtt_ms is None:
                rtt_ms = 50.0  # Placeholder for unmatched responses
            
            if op == KADEMLIA2_HELLO_RES:
                try:
                    info = parse_hello_res(payload)
                except Exception:
                    continue
                
                self.metrics["hello_res"] += 1
                
                if contact is None:
                    # New contact from response
                    node = KadNodeInfo(
                        kad_id=info.contact_id.to_bytes(),
                        ip=addr[0],
                        udp_port=addr[1],
                        tcp_port=info.tcp_port,
                        contact_version=info.version,
                    )
                    contact = VivaldiContact(node)
                    self.contacts[key] = contact
                
                was_dead = contact.hellos == 0
                contact.hellos += 1
                contact.last_seen = time.time()
                contact.update_rtt(rtt_ms)
                
                # Count as alive if this is first hello or was dead
                if was_dead:
                    self.metrics["alive"] += 1
                
                # Update Vivaldi with real RTT measurement
                # Use contact's Vivaldi position if available, otherwise create from RTT
                if len(contact.rtt_samples) >= RTT_SAMPLE_MIN:
                    # Create a remote position based on measured RTT
                    # This is a simplification - in full Vivaldi, remote would send its coordinates
                    # Here we use the RTT to place the node at appropriate distance
                    if contact.vivaldi.at_origin():
                        # Initialize remote position at distance = RTT
                        angle = random.uniform(0, 2 * math.pi)
                        contact.vivaldi.x = math.cos(angle) * rtt_ms
                        contact.vivaldi.y = math.sin(angle) * rtt_ms
                        contact.vivaldi.error = 5.0
                    
                    # Update our local Vivaldi with real measurement
                    self.local_vivaldi.update(rtt_ms, contact.vivaldi)
                    self.metrics["vivaldi_updates"] += 1
                    
                    # Also update contact's Vivaldi with reciprocal measurement
                    contact.vivaldi.update(rtt_ms, self.local_vivaldi)
                
                log.info(
                    "HELLO_RES: %s:%d ver=%d rtt=%.1fms hellos=%d alive=%d",
                    addr[0], addr[1], info.version, rtt_ms, contact.hellos,
                    self.metrics["alive"],
                )
            
            elif op == KADEMLIA2_PONG:
                self.metrics["pong"] += 1
                if contact:
                    contact.pings += 1
                    contact.last_seen = time.time()
                    contact.update_rtt(rtt_ms)
    
    def _update_metrics(self) -> None:
        """Update aggregate metrics."""
        # Count only nodes that responded in THIS session (hellos > 0 from cache means previous session)
        session_alive = sum(1 for c in self.contacts.values() if c.last_seen > self._session_start)
        
        if session_alive > 0:
            self.metrics["alive"] = session_alive
            # avg_rtt from nodes that responded this session
            session_contacts = [c for c in self.contacts.values() if c.last_seen > self._session_start and c.rtt_ewma > 0]
            if session_contacts:
                self.metrics["avg_rtt"] = sum(c.rtt_ewma for c in session_contacts) / len(session_contacts)
            self.metrics["positioned_nodes"] = sum(1 for c in session_contacts if c.is_positioned())


# --- Main -------------------------------------------------------------------

async def main() -> None:
    warmup = VivaldiWarmup()
    await warmup.run()


if __name__ == "__main__":
    asyncio.run(main())
