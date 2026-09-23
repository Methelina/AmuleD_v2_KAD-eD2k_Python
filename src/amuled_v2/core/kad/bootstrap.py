"""Kad2 UDP bootstrap client: send requests, collect live contacts.

Implements the client-side half of ``Bootstrap`` as seen in
``KademliaUDPListener.cpp``: we send ``KADEMLIA2_BOOTSTRAP_REQ`` and
``KADEMLIA2_HELLO_REQ`` to a set of known nodes, then listen for the
matching responses (``KADEMLIA2_BOOTSTRAP_RES``, ``KADEMLIA2_HELLO_RES``,
and ``KADEMLIA2_PONG``) to build a list of live routing contacts.

Wire framing and opcode semantics are defined in
``src/amuled_v2/core/kad/packets.py``; contact records come from
``src/amuled_v2/core/kad/nodes_dat.py``.

src/amuled_v2/core/kad/bootstrap.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Kad2 UDP bootstrap client: bootstrap_nodes, pick_bootstrap_nodes,
      BootstrapResult, KadBootstrapError.
"""

from __future__ import annotations

import asyncio
import socket
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Tuple

from amuled_v2.core.kad.nodes_dat import KadNodeInfo, load_nodes_dat
from amuled_v2.core.kad.packets import (
    KADEMLIA2_BOOTSTRAP_RES,
    KADEMLIA2_HELLO_RES,
    KADEMLIA2_PONG,
    KadUInt128,
    build_bootstrap_req,
    build_hello_req,
    parse_bootstrap_res,
    parse_hello_res,
    parse_kad_packet,
)
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.bootstrap")

__all__ = [
    "BootstrapResult",
    "KadBootstrapError",
    "bootstrap_nodes",
    "pick_bootstrap_nodes",
]


class KadBootstrapError(Exception):
    """Raised for bootstrap-level failures (e.g. socket bind errors)."""


@dataclass
class BootstrapResult:
    """Outcome of a single bootstrap pass.

    Attributes:
        own_id: Our Kad node ID that was sent in the requests.
        own_address: Our public IP:port as seen by responders.  Set to
            ``None`` -- see the docstring of :func:`bootstrap_nodes` for the
            rationale derived from the eMule reference.
        live_nodes: Distinct responders plus every contact learned from
            bootstrap responses, deduplicated by ``(ip, udp_port)``.
        queried: Number of nodes we sent requests to.
        failed: Number of queried nodes that never answered.
        duration_s: Wall-clock seconds the receive loop ran.
    """

    own_id: KadUInt128
    own_address: str | None
    live_nodes: list[KadNodeInfo] = field(default_factory=list)
    queried: int = 0
    failed: int = 0
    duration_s: float = 0.0


def pick_bootstrap_nodes(path: str | Path, count: int = 12) -> list[KadNodeInfo]:
    """Load a ``nodes.dat`` and return up to *count* nodes to bootstrap from.

    Selection prefers verified contacts first, then the highest
    ``contact_version``, and finally the original file order for stability.
    """
    all_nodes = load_nodes_dat(path)

    def _sort_key(n: KadNodeInfo) -> Tuple[int, int, int]:
        return (0 if n.verified else 1, -(n.contact_version), 0)

    sorted_nodes = sorted(all_nodes, key=_sort_key)
    picked = sorted_nodes[:count]

    log.debug(
        "pick_bootstrap_nodes: file=%s total=%d picked=%d",
        path,
        len(all_nodes),
        len(picked),
    )
    return picked


async def _send_request(
    sock: socket.socket,
    datagram: bytes,
    addr: Tuple[str, int],
) -> None:
    """Send a single datagram to *addr* on *sock*."""
    loop = asyncio.get_running_loop()
    await loop.sock_sendto(sock, datagram, addr)


async def _recv_packet(
    sock: socket.socket,
    timeout: float,
) -> Tuple[bytes, Tuple[str, int]] | None:
    """Receive one datagram, or ``None`` if the timeout expires."""
    loop = asyncio.get_running_loop()
    sock.setblocking(False)
    try:
        datagram = await asyncio.wait_for(
            loop.sock_recvfrom(sock, 65535),
            timeout=timeout,
        )
        return datagram
    except asyncio.TimeoutError:
        return None


async def bootstrap_nodes(
    nodes: list[KadNodeInfo],
    *,
    own_id: KadUInt128,
    own_tcp_port: int,
    timeout: float = 4.0,
    max_nodes: int = 12,
    local_port: int = 4672,
) -> BootstrapResult:
    """Bootstrap the Kad routing table by contacting *nodes*.

    Sends ``KADEMLIA2_BOOTSTRAP_REQ`` and ``KADEMLIA2_HELLO_REQ`` to the first
    ``max_nodes`` entries of *nodes*, then listens on a single UDP socket for
    ``KADEMLIA2_BOOTSTRAP_RES``, ``KADEMLIA2_HELLO_RES``, and
    ``KADEMLIA2_PONG`` until *timeout* seconds elapse.

    Response-to-request matching follows the source address: responses to our
    ``BOOTSTRAP_REQ``/``HELLO_REQ`` come from the same remote address we
    queried, so each answered remote is matched by ``(ip, udp_port)``.  Every
    distinct responder plus every contact inside a bootstrap-res payload is
    collected into :attr:`BootstrapResult.live_nodes`, deduplicated by
    ``(ip, udp_port)``.

    own_address:
        **Not implementable from these opcodes.**  The eMule reference
        (``KademliaUDPListener.cpp``) derives our public IP only from
        ``KADEMLIA_FIREWALLED_RES`` (``Process_KADEMLIA_FIREWALLED_RES``,
        line 1824: ``SetIPAddress(uFirewalledIP)``) and the optional external
        port from ``KADEMLIA2_PONG``
        (``Process_KADEMLIA2_PONG``, line 2009:
        ``SetExternKadPort(PeekUInt16(pbyPacketData), uIP)``).  The
        ``KADEMLIA2_BOOTSTRAP_RES`` and ``KADEMLIA2_HELLO_RES`` payloads carry
        only the *sender's* contact information, not ours -- our IP is always
        taken from the datagram source address (``uIP`` argument to
        ``ProcessPacket``), which the kernel already knows.  The PONG payload
        echoes our UDP port but contains no IP.  Therefore ``own_address`` is
        set to ``None`` here; a future caller that also speaks
        ``KADEMLIA2_FIREWALLUDP``/``KADEMLIA_FIREWALLED_RES`` can populate it.
    """
    targets = nodes[:max_nodes]
    queried = len(targets)
    if queried == 0:
        log.warning("bootstrap_nodes: no nodes to query")
        return BootstrapResult(
            own_id=own_id,
            own_address=None,
            live_nodes=[],
            queried=0,
            failed=0,
            duration_s=0.0,
        )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", local_port))
    except OSError as exc:
        sock.close()
        raise KadBootstrapError(
            f"cannot bind UDP socket on port {local_port}: {exc}"
        ) from exc

    log.info(
        "bootstrap_nodes: start queried=%d timeout=%.1f local_port=%d",
        queried,
        timeout,
        local_port,
    )

    loop = asyncio.get_running_loop()
    start = time.monotonic()

    # Targets we still expect answers from (keyed by (ip, udp_port)).
    pending: dict[Tuple[str, int], KadNodeInfo] = {
        (n.ip, n.udp_port): n for n in targets
    }
    # Responders that answered (keyed by (ip, udp_port)) -> KadNodeInfo.
    live_map: dict[Tuple[str, int], KadNodeInfo] = {}

    # Send bootstrap_req + hello_req to every target concurrently.
    send_tasks = []
    for node in targets:
        remote = (node.ip, node.udp_port)
        breq = build_bootstrap_req(own_id)
        hreq = build_hello_req(own_id, own_tcp_port)
        log.debug(
            "send bootstrap+hello: remote=%s:%d", node.ip, node.udp_port
        )
        send_tasks.append(_send_request(sock, breq, remote))
        send_tasks.append(_send_request(sock, hreq, remote))
    if send_tasks:
        await asyncio.gather(*send_tasks, return_exceptions=True)

    # Receive loop until timeout expires.
    deadline = timeout
    while True:
        remaining = deadline - (time.monotonic() - start)
        if remaining <= 0:
            break
        datagram = await _recv_packet(sock, remaining)
        if datagram is None:
            break

        data, src_addr = datagram
        src_ip = src_addr[0]
        src_port = src_addr[1]
        remote_key = (src_ip, src_port)

        log.debug(
            "recv: remote=%s:%d bytes=%d", src_ip, src_port, len(data)
        )

        try:
            protocol, opcode, payload = parse_kad_packet(data)
            if protocol == 0xE5:
                # OP_KADEMLIAPACKEDPROT: zlib payload, opcode stays in the
                # header, protocol restores to 0xE4 after decompression
                # (eMule 0.50a Packet::UnPackPacket).
                payload = zlib.decompress(payload)
                protocol = 0xE4
        except Exception as exc:
            log.debug(
                "parse_kad_packet failed for remote=%s:%d, error=%s: %s",
                src_ip,
                src_port,
                type(exc).__name__,
                exc,
            )
            continue

        if remote_key in pending:
            node = pending.pop(remote_key)
            if opcode == KADEMLIA2_BOOTSTRAP_RES:
                try:
                    sender_id, contacts = parse_bootstrap_res(payload)
                except Exception:
                    log.debug(
                        "bootstrap_res parse failed: remote=%s:%d",
                        src_ip,
                        src_port,
                    )
                    continue
                live_map[remote_key] = KadNodeInfo(
                    kad_id=sender_id.to_bytes(),
                    ip=src_ip,
                    udp_port=src_port,
                    tcp_port=node.tcp_port,
                    contact_version=node.contact_version,
                )
                for c in contacts:
                    ck = (c.ip, c.udp_port)
                    if ck not in live_map:
                        live_map[ck] = c
            elif opcode == KADEMLIA2_HELLO_RES:
                try:
                    info = parse_hello_res(payload)
                except Exception:
                    log.debug(
                        "hello_res parse failed: remote=%s:%d",
                        src_ip,
                        src_port,
                    )
                    continue
                live_map[remote_key] = KadNodeInfo(
                    kad_id=info.contact_id.to_bytes(),
                    ip=src_ip,
                    udp_port=src_port,
                    tcp_port=info.tcp_port,
                    contact_version=info.version,
                )
            elif opcode == KADEMLIA2_PONG:
                live_map[remote_key] = KadNodeInfo(
                    kad_id=node.kad_id,
                    ip=src_ip,
                    udp_port=src_port,
                    tcp_port=node.tcp_port,
                    contact_version=node.contact_version,
                )
            else:
                log.debug(
                    "unexpected opcode=%#x from remote=%s:%d",
                    opcode,
                    src_ip,
                    src_port,
                )
        else:
            # Response from a node we didn't query (e.g. a relayed contact).
            # We still collect it if it's a bootstrap_res/ hello_res.
            if opcode == KADEMLIA2_BOOTSTRAP_RES:
                try:
                    sender_id, contacts = parse_bootstrap_res(payload)
                except Exception:
                    continue
                live_map[remote_key] = KadNodeInfo(
                    kad_id=sender_id.to_bytes(),
                    ip=src_ip,
                    udp_port=src_port,
                    tcp_port=0,
                    contact_version=0,
                )
                for c in contacts:
                    ck = (c.ip, c.udp_port)
                    if ck not in live_map:
                        live_map[ck] = c
            elif opcode == KADEMLIA2_HELLO_RES:
                try:
                    info = parse_hello_res(payload)
                except Exception:
                    continue
                live_map[remote_key] = KadNodeInfo(
                    kad_id=info.contact_id.to_bytes(),
                    ip=src_ip,
                    udp_port=src_port,
                    tcp_port=info.tcp_port,
                    contact_version=info.version,
                )
            elif opcode == KADEMLIA2_PONG:
                live_map[remote_key] = KadNodeInfo(
                    kad_id=b"\x00" * 16,
                    ip=src_ip,
                    udp_port=src_port,
                    tcp_port=0,
                    contact_version=0,
                )

    duration = time.monotonic() - start
    failed = len(pending)
    live_nodes = list(live_map.values())

    log.info(
        "bootstrap_nodes: done live=%d queried=%d failed=%d duration=%.2fs",
        len(live_nodes),
        queried,
        failed,
        duration,
    )

    return BootstrapResult(
        own_id=own_id,
        own_address=None,
        live_nodes=live_nodes,
        queried=queried,
        failed=failed,
        duration_s=duration,
    )
