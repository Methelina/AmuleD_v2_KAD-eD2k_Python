"""KAD runtime reconstruction: offline loader for routing + own node ID.

Reconstructs a usable Kad2 runtime (routing zone + persistent own node ID)
from the local node cache (``db/kad_nodes.json``) and ``nodes.dat`` bootstrap
file, so CLI commands (kad search / kad sources) do not depend on the warmup
script running in the same process.

This module performs **no network I/O** -- it only reads the local cache and
the offline nodes.dat bootstrap file.  Online probing (HELLO/PING maturation)
is left to ``scripts/kad_warmup.py``.

src/amuled_v2/core/kad/runtime.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Added offline KadRuntime loader with cache + nodes.dat merge and IPv4
      unicast validation.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from amuled_v2.core.kad.nodes_dat import KadNodeInfo
from amuled_v2.core.kad.packets import KadUInt128
from amuled_v2.core.kad.routing import RoutingZone
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.runtime")

__all__ = ["KadRuntime", "load_kad_runtime", "bootstrap_runtime"]


@dataclass
class KadRuntime:
    """A reconstructed offline Kad runtime.

    Attributes:
        routing: The populated :class:`RoutingZone` for the local own_id.
        own_id: The 128-bit Kad node identifier (from cache or freshly
            generated).
        cache_file: Path to the ``kad_nodes.json`` cache file.
        node_count: Number of validated pool nodes added to the routing zone.
    """

    routing: RoutingZone
    own_id: KadUInt128
    cache_file: Path
    node_count: int


def _resolve_root(root: str | Path | None) -> Path:
    """Resolve the project root.

    Mirrors the AMULED_ROOT convention used by the installer/runner: if *root*
    is given, use it; otherwise fall back to the ``AMULED_ROOT`` environment
    variable, then to the current working directory.
    """
    if root is not None:
        return Path(root)
    env_root = os.environ.get("AMULED_ROOT")
    if env_root:
        return Path(env_root)
    return Path.cwd()


def _load_cache(cache_file: Path) -> dict[str, Any]:
    """Load the Kad node cache JSON, returning an empty dict on any error."""
    if not cache_file.exists():
        log.debug("cache file does not exist: path=%s", cache_file)
        return {}
    try:
        return json.loads(cache_file.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("cache load failed: path=%s error=%s", cache_file, exc)
        return {}


def _decode_own_id(own_hex: str | None) -> KadUInt128 | None:
    """Return a :class:`KadUInt128` from a 32-hex-string cache value.

    Returns ``None`` when the value is missing or not a valid 32-hex string
    (so the caller can generate a new own_id).
    """
    if not own_hex:
        return None
    try:
        raw = bytes.fromhex(own_hex)
    except ValueError:
        return None
    if len(raw) != 16:
        return None
    return KadUInt128(raw)


def _is_routable_ipv4(ip: str) -> bool:
    """Return ``True`` only for usable IPv4 unicast addresses.

    Drops 0.x (unspecified/legacy) and 224+ (multicast/reserved) first octets,
    mirroring the validation applied in kad_warmup.py candidate pools.
    """
    try:
        first_octet = int(ip.split(".")[0])
    except (ValueError, IndexError):
        return False
    if first_octet == 0 or first_octet >= 224:
        return False
    return True


def _build_node(
    kad_id_raw: str, ip: str, udp_port: int, tcp: int, ver: int
) -> KadNodeInfo | None:
    """Build a validated :class:`KadNodeInfo` from a hex kad_id and contact
    fields, or ``None`` if the record is malformed.
    """
    try:
        kad_id = bytes.fromhex(kad_id_raw)
    except (ValueError, TypeError):
        log.debug("drop node: invalid kad_id hex ip=%s", ip)
        return None
    if len(kad_id) != 16:
        log.debug(
            "drop node: kad_id length=%d expected=16 ip=%s",
            len(kad_id),
            ip,
        )
        return None
    return KadNodeInfo(
        kad_id=kad_id,
        ip=ip,
        udp_port=udp_port,
        tcp_port=tcp,
        contact_version=ver,
    )


def _persist_own_id(cache_file: Path, own_id: KadUInt128, existing_nodes: dict[str, Any]) -> None:
    """Atomically persist a newly generated own_id.

    Preserves the existing ``nodes`` map (if any) and writes to a ``.tmp``
    sibling before ``os.replace``, so a crash mid-write never corrupts the
    cache.
    """
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "own_id": own_id.to_bytes().hex(),
        "nodes": existing_nodes,
    }
    tmp_path = cache_file.with_suffix(cache_file.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    os.replace(tmp_path, cache_file)
    log.debug("persisted new own_id: path=%s", cache_file)


def load_kad_runtime(root: str | Path | None = None) -> KadRuntime:
    """Reconstruct a usable Kad runtime from local cache and nodes.dat.

    Steps:
      1. Resolve *root* (or ``AMULED_ROOT`` / cwd).
      2. Load ``db/kad_nodes.json`` (cache); treat any error as empty.
      3. Determine own_id: from a valid 32-hex cache value, or freshly
         generated and persisted atomically.
      4. Build the candidate pool from cache-warmed nodes only (nodes.dat is
         bootstrap-only: bundled contacts include dead/spy entries that
         would poison routing.closest()).
      5. Validate/filter: keep nodes whose IPv4 first octet is not 0 and not
         >= 224; drop records whose kad_id is not 16 bytes.
      6. Populate a :class:`RoutingZone` with own_id and each pool node.

    Returns a :class:`KadRuntime` with the routing zone, own_id, cache path,
    and the count of pool nodes kept.
    """
    root_path = _resolve_root(root)
    cache_file = root_path / "db" / "kad_nodes.json"

    cache = _load_cache(cache_file)

    own_id = _decode_own_id(cache.get("own_id"))
    if own_id is not None:
        log.info("own_id loaded from cache: own_id=%s source=cache", own_id)
    else:
        own_id = KadUInt128(int.from_bytes(os.urandom(16), "big"))
        _persist_own_id(cache_file, own_id, cache.get("nodes", {}) or {})
        log.info("own_id generated: own_id=%s source=new", own_id)

    # --- candidate pool: cached alive first, then nodes.dat ----------------
    # IMPORTANT: only cache-warmed nodes enter the routing zone.  nodes.dat
    # stays a bootstrap-only source (bootstrap_runtime / pick_bootstrap_nodes):
    # its bundled contacts contain many dead/spy entries, and feeding them
    # into the zone poisons routing.closest() -- the iterative lookup then
    # burns its first (and with an idle window, only) rounds on silent
    # nodes.  This mirrors the live-validated reference search snippet.
    nodes: dict[tuple[str, int], dict[str, Any]] = {}
    cached_nodes = cache.get("nodes") or {}
    for key, rec in cached_nodes.items():
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
        }

    # --- validation/filter + routing population ----------------------------
    routing = RoutingZone(own_id)
    kept = 0
    for (ip, udp_port), rec in nodes.items():
        if not _is_routable_ipv4(ip):
            log.debug("drop node: non-unicast ip=%s", ip)
            continue
        node = _build_node(rec["kad_id"], ip, udp_port, rec["tcp"], rec["ver"])
        if node is None:
            continue
        routing.add(node)
        kept += 1

    log.info(
        "kad runtime loaded: cache=%s own_id=%s pool_size=%d routing_size=%d",
        cache_file,
        own_id,
        kept,
        len(routing),
    )
    return KadRuntime(
        routing=routing,
        own_id=own_id,
        cache_file=cache_file,
        node_count=kept,
    )


async def bootstrap_runtime(
    rt: KadRuntime,
    *,
    seed_count: int = 12,
    timeout: float = 6.0,
    local_port: int = 0,
    nodes_dat: str | Path | None = None,
) -> int:
    """Live-bootstrap an offline runtime and fold live nodes into routing.

    Sends ``KADEMLIA2_BOOTSTRAP_REQ`` to *seed_count* nodes.dat seeds and adds
    every answering contact to ``rt.routing``.  A fresh process has no UDP
    presence, and the closest *cached* contacts of an arbitrary target are
    often stale -- a short live bootstrap before searching is what makes the
    iterative lookup actually get answers (same reason eMule keeps KAD
    connected between searches).

    Returns the number of live bootstrap contacts seen.
    """
    from amuled_v2.core.kad.bootstrap import bootstrap_nodes, pick_bootstrap_nodes

    seeds_path = Path(nodes_dat) if nodes_dat is not None else (
        rt.cache_file.parent.parent / "assets" / "v1" / "nodes.dat"
    )
    seeds = pick_bootstrap_nodes(str(seeds_path), seed_count)
    if not seeds:
        log.warning("kad bootstrap: no seeds available path=%s", seeds_path)
        return 0
    boot = await bootstrap_nodes(
        seeds,
        own_id=rt.own_id,
        own_tcp_port=4662,
        timeout=timeout,
        local_port=local_port,
    )
    added = 0
    for node in boot.live_nodes:
        if rt.routing.add(node):
            added += 1
    log.info(
        "kad runtime bootstrap: seeds=%d live=%d routing_added=%d",
        len(seeds),
        len(boot.live_nodes),
        added,
    )
    return len(boot.live_nodes)
