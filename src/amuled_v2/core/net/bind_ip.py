"""Network bind policy: which local IP our UDP/TCP sockets use for egress.

Problem (live 2026-09-28): with an always-on VPN TUN adapter (tun0/hys2),
an ``0.0.0.0`` bind lets OS routing choose the TUN as egress for every
KAD/peer UDP datagram. Remote peers then see the tunnel-exit address as
our source IP and their callbacks/rendezvous dials go there - where no
inbound path exists (the tunnel is outbound-only). The router-side UPnP
mapping (roadmap 8.5) opens a port on the HOME router's WAN address, but
nobody dials that address while our visible source IP is the tunnel.

Fix: bind KAD/peer UDP sockets to the physical NIC address
(``network.bind_ip`` in config, e.g. 192.168.3.111). Egress then follows
the on-link route: home NAT -> router WAN, so peers see the router's
public IP and the UPnP-forwarded port completes the callback path. This
mirrors how a stock eMule operates on the same machine.

src/amuled_v2/core/net/bind_ip.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-28

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] resolve_bind_ip(): read ``network.bind_ip`` from config; validate it
      is one of the host's local IPv4 addresses (fallback warning + None
      when absent/mismatched - callers keep their 0.0.0.0 default).
"""

from __future__ import annotations

import socket

from amuled_v2.config import load_config
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.NAT, "core.net.bind_ip")

__all__ = ["resolve_bind_ip"]


def _local_ipv4_set() -> set[str]:
    addrs: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError as exc:
        log.warning(
            "bind_ip fallback: local address enumeration failed: error=%r", exc
        )
    return addrs


def resolve_bind_ip() -> str | None:
    """Configured egress IPv4 for KAD/peer sockets, or None for 0.0.0.0.

    The value must be a local IPv4 address of this host; a configured
    address that is not local degrades to None with a tagged warning
    (policy: every fallback is logged).
    """
    try:
        cfg = load_config()
    except Exception as exc:  # noqa: BLE001 - config problems must not kill net
        log.warning("bind_ip fallback: config load failed: error=%r", exc)
        return None
    raw = (cfg.get("network") or {}).get("bind_ip")
    if not raw:
        return None
    raw = str(raw).strip()
    local = _local_ipv4_set()
    if raw == "0.0.0.0":
        return None
    if raw not in local:
        log.warning(
            "bind_ip fallback: configured network.bind_ip=%s is not a local "
            "address (local=%s) - using 0.0.0.0",
            raw,
            sorted(local),
        )
        return None
    return raw
