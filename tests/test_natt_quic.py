"""Offline loopback test for the aioquic NAT-T QUIC transport.

Two local UDP transports: the downloader (QUIC client) connects to the
source (QUIC server bootstrapped from the first Initial), the EAQN1 proof
is exchanged on stream 0, and app data flows both ways.

tests/test_natt_quic.py
Author:      Soror L.'.L.'.
Updated:     2026-09-27
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from amuled_v2.core.natt.quic_transport import (
    PROOF_LEN,
    quic_connect_natt,
    quic_serve_natt,
    unwrap_natt_frame,
    wrap_natt_frame,
)


class _UdpEndpoint(asyncio.DatagramProtocol):
    """Plain UDP endpoint feeding unwrapped 0xB2 frames to a callback or
    to a registered QUIC protocol (opcode 0x01)."""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.port = 0
        self.inbound: asyncio.Queue[tuple[bytes, tuple]] = asyncio.Queue()
        self.frame_handler = None  # callable(opcode, payload, addr)
        self.quic_protocol = None  # NattQuicProtocol, set at runtime

    def connection_made(self, transport) -> None:
        self.transport = transport
        self.port = transport.get_extra_info("sockname")[1]

    def datagram_received(self, data: bytes, addr) -> None:
        frame = unwrap_natt_frame(data)
        if frame is None:
            return
        opcode, payload = frame
        if opcode == 0x01 and self.quic_protocol is not None:
            self.quic_protocol.datagram_received(payload, addr)
            return
        if self.frame_handler is not None:
            self.frame_handler(opcode, payload, addr)
        else:
            self.inbound.put_nowait((payload, addr))


def test_natt_quic_stream_loopback(tmp_path: Path) -> None:
    async def scenario() -> None:
        loop = asyncio.get_running_loop()

        source_udp = _UdpEndpoint()
        s_transport, _ = await loop.create_datagram_endpoint(
            lambda: source_udp, local_addr=("127.0.0.1", 0)
        )
        dl_udp = _UdpEndpoint()
        d_transport, _ = await loop.create_datagram_endpoint(
            lambda: dl_udp, local_addr=("127.0.0.1", 0)
        )

        our_hash = bytes(range(16))
        peer_hash = bytes.fromhex("AB" * 16)
        dl_addr = d_transport.get_extra_info("sockname")

        # The source's first datagram from the downloader bootstraps the
        # QUIC server role (ngtcp2 StartServer semantics).
        first: dict = {}
        server_holder: dict = {}

        def source_frame_handler(opcode: int, payload: bytes, addr) -> None:
            # The downloader's QUIC Initial arrives as a 0xB2 frame; on the
            # first one, promote the source UDP socket to the QUIC server.
            if "proto" not in first and opcode == 0x01:
                first["proto"] = True
                asyncio.get_running_loop().create_task(
                    _serve(
                        s_transport,
                        {"user_hash": peer_hash, "peer_user_hash": our_hash},
                        (payload, dl_addr),
                        tmp_path,
                        source_udp,
                        server_holder,
                    )
                )

        source_udp.frame_handler = source_frame_handler

        client_proto = await quic_connect_natt(
            "127.0.0.1",
            source_udp.port,
            d_transport,
            {"user_hash": our_hash, "peer_user_hash": peer_hash},
        )
        dl_udp.quic_protocol = client_proto

        # Wait for both sides to complete the proof exchange.
        await asyncio.wait_for(client_proto.proof_ok.wait(), 20.0)
        for _ in range(100):
            if "server" in server_holder and server_holder["server"].proof_ok.is_set():
                break
            await asyncio.sleep(0.1)
        server_proto = server_holder.get("server")
        assert server_proto is not None and server_proto.proof_ok.is_set()

        # App data both ways over stream 0.
        payload = os.urandom(5000)
        client_proto._quic.send_stream_data(0, payload, end_stream=False)
        client_proto.transmit()

        data = bytearray()
        for _ in range(100):
            if len(data) >= len(payload):
                break
            await asyncio.sleep(0.1)
            data.extend(
                server_proto._reader._buffer[len(data):]  # noqa: SLF001
            )
        assert bytes(data[: len(payload)]) == payload

        d_transport.close()
        s_transport.close()

    asyncio.run(scenario())


async def _serve(s_transport, identity, first, tmp_path, source_udp, holder):
    proto = await quic_serve_natt(s_transport, identity, first, tmp_path)
    source_udp.quic_protocol = proto
    holder["server"] = proto
    await proto.proof_ok.wait()
