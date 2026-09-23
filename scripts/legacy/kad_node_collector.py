"""Standalone KAD node accumulator — collect, verify and cache kad2 nodes.

Runs indefinitely (or for --duration seconds), continuously:
  1. bootstraps from nodes.dat;
  2. snowballs the pool via KADEMLIA2_BOOTSTRAP_REQ (20 contacts per reply);
  3. HELLOs every candidate to collect kad_id / version / udp_key
     (decodes obfuscated replies with our NodeID key);
  4. PINGs for liveness;
  5. saves everything to db/kad_nodes_standalone.json every 60 s.

Zero dependencies beyond the Python stdlib (RC4/zlib/MD5/MD4 inline).
Run:  python kad_node_collector.py [--duration 3600] [--cache db/kad_nodes_standalone.json]

kad_node_collector.py
Version:     1.0.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import random
import socket
import struct
import sys
import time
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NODES_DAT = ROOT / "assets" / "v1" / "nodes.dat"

# --- kad2 protocol constants (eMule 0.50a opcodes.h) -------------------------
KAD_PROTOCOL = 0xE4
KAD_PROTOCOL_PACKED = 0xE5
KADEMLIA2_BOOTSTRAP_REQ = 0x04
KADEMLIA2_BOOTSTRAP_RES = 0x09
KADEMLIA2_HELLO_RES = 0x19
KADEMLIA2_PING = 0x30
KADEMLIA2_PONG = 0x31
MAGIC_UDP_SYNC_CLIENT = 0x395F2EC1

out = sys.stdout


def ts() -> str:
    return time.strftime("%H:%M:%S")


# --- minimal kad2 wire helpers -----------------------------------------------
def md4(data: bytes) -> bytes:
    h = hashlib.new("md4")
    h.update(data)
    return h.digest()


class KadUInt128:
    __slots__ = ("b",)

    def __init__(self, b: bytes):
        self.b = b

    def to_bytes(self) -> bytes:
        return self.b

    def __repr__(self):
        return self.b.hex()


def build_bootstrap_req(sender: KadUInt128) -> bytes:
    return bytes((KAD_PROTOCOL, KADEMLIA2_BOOTSTRAP_REQ)) + sender.to_bytes()


def build_hello_req(sender: KadUInt128, tcp_port: int) -> bytes:
    # kad2 hello: id(16) + tcp_port(2, LE) + version(1) + tag_count(1, 0)
    payload = (
        sender.to_bytes()
        + struct.pack("<HB", tcp_port & 0xFFFF, 6)
        + bytes((0,))
    )
    return bytes((KAD_PROTOCOL, 0x11)) + payload


def build_ping() -> bytes:
    return bytes((KAD_PROTOCOL, KADEMLIA2_PING))


def parse_packet(datagram: bytes):
    """Return (proto, opcode, payload) or None."""
    if len(datagram) < 2:
        return None
    proto = datagram[0]
    if proto not in (KAD_PROTOCOL, KAD_PROTOCOL_PACKED):
        return None
    payload = datagram[2:]
    if proto == KAD_PROTOCOL_PACKED:
        try:
            payload = zlib.decompress(payload)
        except zlib.error:
            return None
    return proto, datagram[1], payload


def parse_bootstrap_res(payload: bytes):
    """-> (sender_id, [ (id, ip, udp, tcp, ver), ... ])"""
    if len(payload) < 21:
        return None, []
    sender = payload[:16]
    (tcp_port,) = struct.unpack_from("<H", payload, 16)
    version = payload[18]
    (count,) = struct.unpack_from("<H", payload, 19)
    off = 21
    contacts = []
    for _ in range(count):
        if off + 25 > len(payload):
            break
        kad_id = payload[off : off + 16]
        ip = payload[off + 16 : off + 20]
        udp, tcp = struct.unpack_from("<HH", payload, off + 20)
        ver = payload[off + 24]
        off += 25
        contacts.append((kad_id, ip, udp, tcp, ver))
    return sender, contacts


def parse_hello_res(payload: bytes):
    """-> (id, tcp_port, version) or None (tags skipped)."""
    if len(payload) < 19:
        return None
    kad_id = payload[:16]
    (tcp,) = struct.unpack_from("<H", payload, 16)
    ver = payload[18]
    return kad_id, tcp, ver


# --- RC4 + UDP obfuscation decoder (eMule EncryptedDatagramSocket) -----------
class RC4:
    def __init__(self, key: bytes):
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xFF
            s[i], s[j] = s[j], s[i]
        self.s = s
        self.i = self.j = 0

    def crypt(self, data: bytes) -> bytes:
        s, i, j = self.s, self.i, self.j
        out = bytearray()
        for b in data:
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out.append(b ^ s[(s[i] + s[j]) & 0xFF])
        self.i, self.j = i, j
        return bytes(out)


def decode_obfuscated(data: bytes, own_id: bytes):
    """-> (plain, sender_key) or None."""
    if len(data) <= 8 or data[0] in (0xE3, 0xC5, 0xE4, 0xE5, 0xD4, 0xD5):
        return None
    for material in (own_id + data[1:3],):
        cipher = RC4(hashlib.md5(material).digest())
        if struct.unpack("<I", cipher.crypt(data[3:7]))[0] != MAGIC_UDP_SYNC_CLIENT:
            continue
        pad_len = cipher.crypt(data[7:8])[0]
        body = len(data) - 8 - pad_len
        if body <= 8:
            return None
        cipher.crypt(data[8 + pad_len : 16 + pad_len])  # verify keys (skip)
        plain = cipher.crypt(data[16 + pad_len :])
        return plain, 0
    return None


# --- main collector -----------------------------------------------------------
class Collector:
    def __init__(self, cache_path: Path, port: int = 0, verbose: bool = False):
        self.verbose = verbose
        self.cache_path = cache_path
        cache = {}
        if cache_path.exists():
            try:
                cache = json.loads(cache_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        own_hex = cache.get("own_id")
        self.own = (
            KadUInt128(bytes.fromhex(own_hex))
            if own_hex
            else KadUInt128(os.urandom(16))
        )
        self.nodes: dict = cache.get("nodes", {})
        if self.nodes:
            normalized = {}
            for key, rec in self.nodes.items():
                if isinstance(key, str):
                    ip, _, prt = key.rpartition(":")
                    key = (ip, int(prt))
                normalized[key] = rec
            self.nodes = normalized
        else:
            self.nodes = {}
        self._seed_from_nodes_dat()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", port))
        self.sock.setblocking(False)
        self.ping_sent: dict = {}
        self.stats = {
            "bootstraps": 0,
            "hello_res": 0,
            "pong": 0,
            "decoded": 0,
            "req_sent": 0,
        }

    def _seed_from_nodes_dat(self) -> None:
        """Seed the pool from assets/v1/nodes.dat (LE uint32/16 layout)."""
        if not NODES_DAT.exists():
            return
        raw = NODES_DAT.read_bytes()
        if len(raw) < 12:
            return
        first, version = struct.unpack_from("<II", raw, 0)
        if first == 0 and version in (1, 2, 3):
            (count,) = struct.unpack_from("<I", raw, 8)
            off = 12
        else:
            count = first
            version = 0
            off = 8
        import ipaddress

        added = 0
        for _ in range(count):
            if off + 25 > len(raw):
                break
            kad_id = raw[off : off + 16]
            (ip_raw,) = struct.unpack_from("<I", raw, off + 16)
            udp, tcp = struct.unpack_from("<HH", raw, off + 20)
            cver = raw[off + 24]
            off += 25
            if udp == 0:
                continue
            ip = str(ipaddress.IPv4Address(ip_raw))
            first = (ip_raw >> 24) & 0xFF
            if first >= 224 or first == 0:  # multicast/reserved/unroutable
                continue
            if self.add_contact(kad_id, ip, udp, tcp, cver):
                added += 1
        out.write(f"[{ts()}] nodes.dat seeded: +{added}\n")

    def save(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        alive = {
            "%s:%d" % k: {
                "kad_id": r["kad_id"],
                "tcp": r["tcp"],
                "ver": r["ver"],
                "hellos": r["hellos"],
                "pings": r["pings"],
                "udp_key": r["udp_key"],
                "last_seen": r["last_seen"],
            }
            for k, r in self.nodes.items()
            if r["hellos"] or r["pings"]
        }
        payload = {
            "own_id": self.own.to_bytes().hex(),
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "pool": len(self.nodes),
            "nodes": alive,
        }
        self.cache_path.write_text(
            json.dumps(payload, indent=1), encoding="utf-8"
        )
        out.write(
            f"[{ts()}] SAVE pool={len(self.nodes)} cached_alive={len(alive)}\n"
        )

    def add_contact(self, kad_id: bytes, ip: str, udp: int, tcp: int, ver: int) -> bool:
        if udp == 0:
            return False
        key = (ip, udp)
        if key in self.nodes:
            return False
        self.nodes[key] = {
            "kad_id": kad_id.hex(),
            "tcp": tcp,
            "ver": ver,
            "hellos": 0,
            "pings": 0,
            "udp_key": 0,
            "last_seen": 0.0,
        }
        return True

    async def run(self, duration: float) -> None:
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        next_cycle = 0.0
        next_save = loop.time() + 60.0
        log_every = 0

        while loop.time() - t0 < duration:
            now = loop.time()
            if now >= next_cycle:
                await self._cycle()
                next_cycle = now + 20.0
                log_every += 1
                alive = sum(1 for r in self.nodes.values() if r["hellos"])
                out.write(
                    f"[{ts()}] CYCLE pool={len(self.nodes)} alive={alive} "
                    f"boot_res={self.stats['bootstraps']} hellos={self.stats['hello_res']} "
                    f"pong={self.stats['pong']} dec={self.stats['decoded']}\n"
                )
            await self._drain_recv(1.0)
            if loop.time() >= next_save:
                self.save()
                next_save = loop.time() + 60.0
        self.save()
        out.write(f"[{ts()}] DONE pool={len(self.nodes)} stats={self.stats}\n")

    async def _cycle(self) -> None:
        """One maturation + discovery cycle."""
        loop = asyncio.get_running_loop()
        entries = list(self.nodes.items())
        fresh = [e for e in entries if not e[1]["hellos"]]
        mature = sorted(
            (e for e in entries if e[1]["hellos"]),
            key=lambda e: -e[1]["last_seen"],
        )
        batch = (
            [e for e in fresh if e not in mature[-30:]][:20]
            + mature[:16]
            + (random.sample(entries, min(12, len(entries))) if entries else [])
        )
        for (ip, port), rec in batch:
            try:
                if rec["hellos"] == 0 or rec["last_seen"] < time.time() - 600:
                    if self.verbose:
                        out.write(
                            f"[{ts()}] -> HELLO {ip}:{port} "
                            f"(hellos={rec['hellos']})\n"
                        )
                    await loop.sock_sendto(
                        self.sock, build_hello_req(self.own, 4662), (ip, port)
                    )
                else:
                    if self.verbose:
                        out.write(f"[{ts()}] -> PING {ip}:{port}\n")
                    self.ping_sent[(ip, port)] = time.time()
                    await loop.sock_sendto(self.sock, build_ping(), (ip, port))
            except OSError as exc:
                if self.verbose:
                    out.write(f"[{ts()}] !! SEND_FAIL {ip}:{port} {exc}\n")
                continue
            await asyncio.sleep(0.03)
        # discovery: bootstrap_req to random known-alive nodes
        targets = random.sample(
            [e for e in mature], min(8, len(mature))
        ) if mature else []
        for (ip, port), rec in targets:
            try:
                if self.verbose:
                    out.write(f"[{ts()}] -> BOOT {ip}:{port}\n")
                await loop.sock_sendto(
                    self.sock, build_bootstrap_req(self.own), (ip, port)
                )
                self.stats["req_sent"] += 1
            except OSError:
                continue
            await asyncio.sleep(0.03)
        # discovery: bootstrap_req to random known-alive nodes
        targets = random.sample(
            [e for e in mature], min(8, len(mature))
        ) if mature else []
        for (ip, port), rec in targets:
            try:
                await loop.sock_sendto(
                    self.sock, build_bootstrap_req(self.own), (ip, port)
                )
                self.stats["req_sent"] += 1
            except OSError:
                continue
            await asyncio.sleep(0.03)

    async def _drain_recv(self, window: float) -> None:
        loop = asyncio.get_running_loop()
        end = loop.time() + window
        while loop.time() < end:
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(self.sock, 65535),
                    max(0.05, end - loop.time()),
                )
            except asyncio.TimeoutError:
                return
            self._handle(data, addr)

    def _handle(self, data: bytes, addr) -> None:
        key = (addr[0], addr[1])
        rec = self.nodes.get(key)
        parsed = parse_packet(data)
        if parsed is None:
            plain = decode_obfuscated(data, self.own.to_bytes())
            if plain is None:
                return
            data = plain[0]
            self.stats["decoded"] += 1
            parsed = parse_packet(data)
            if parsed is None:
                return
        _, op, payload = parsed
        if op == KADEMLIA2_BOOTSTRAP_RES:
            sender, contacts = parse_bootstrap_res(payload)
            if sender is None:
                return
            self.stats["bootstraps"] += 1
            added = 0
            for kad_id, ip_b, udp, tcp, ver in contacts:
                ip = ".".join(str(b) for b in ip_b)
                if self.add_contact(kad_id, ip, udp, tcp, ver):
                    added += 1
            if rec is not None:
                rec["last_seen"] = time.time()
            if added:
                out.write(
                    f"[{ts()}] BOOT_RES {addr[0]} +{added} contacts "
                    f"(pool={len(self.nodes)})\n"
                )
        elif op == KADEMLIA2_HELLO_RES:
            info = parse_hello_res(payload)
            if info is None:
                return
            kad_id, tcp, ver = info
            self.stats["hello_res"] += 1
            if rec is None:
                rec = self.nodes.setdefault(
                    key,
                    {
                        "kad_id": "", "tcp": 0, "ver": 0,
                        "hellos": 0, "pings": 0, "udp_key": 0,
                        "last_seen": 0.0,
                    },
                )
            rec["kad_id"] = kad_id.hex()
            rec["tcp"] = tcp
            rec["ver"] = ver
            rec["hellos"] = int(rec["hellos"]) + 1
            rec["last_seen"] = time.time()
            if rec["hellos"] == 1:
                out.write(
                    f"[{ts()}] ALIVE {addr[0]}:{addr[1]} ver={ver} "
                    f"alive_total={sum(1 for r in self.nodes.values() if r['hellos'])}\n"
                )
        elif op == KADEMLIA2_PONG:
            self.stats["pong"] += 1
            if rec is not None:
                rec["pings"] = int(rec["pings"]) + 1
                rec["last_seen"] = time.time()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=float, default=3600.0)
    ap.add_argument(
        "--cache",
        default=str(ROOT / "db" / "kad_nodes_standalone.json"),
    )
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    c = Collector(Path(args.cache), args.port, verbose=args.verbose)
    out.write(
        f"[{ts()}] START own_id={c.own} pool={len(c.nodes)} "
        f"duration={args.duration:.0f}s cache={args.cache}\n"
    )
    try:
        asyncio.run(c.run(args.duration))
    except KeyboardInterrupt:
        c.save()
        out.write(f"[{ts()}] INTERRUPTED, snapshot saved\n")


if __name__ == "__main__":
    main()
