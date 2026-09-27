"""Offline test for the minimal BEP 29 uTP stream (NAT-T transport).

tests/test_natt_utp.py
Author:      Soror L.'.L.'.
Updated:     2026-09-27
"""

from __future__ import annotations

import asyncio
import os

from amuled_v2.core.natt.utp import UtpStream, _HEADER_LEN, struct


class _Endpoint:
    def __init__(self, name: str) -> None:
        self.name = name
        self.transport: asyncio.DatagramTransport | None = None
        self.port = 0
        self.stream: UtpStream | None = None
        self.accepted: asyncio.Queue[UtpStream] = asyncio.Queue()

    def connection_made(self, transport) -> None:
        self.transport = transport
        self.port = transport.get_extra_info("sockname")[1]

    def datagram_received_raw(self, data: bytes, addr) -> None:
        stream = self.stream
        if stream is not None:
            # demultiplex by connection id (single stream per test endpoint)
            (conn_id,) = struct.unpack_from(">H", data, 2)
            expected = stream.conn_id_recv
            acceptor_expected = (
                (stream.conn_id_send + 1) & 0xFFFF
            )
            if conn_id in (expected, acceptor_expected):
                stream._on_wire_packet(data)
                return
        # unknown -> may be a SYN for the acceptor side
        if len(data) >= _HEADER_LEN and (data[0] >> 4) == 4:
            asyncio.get_running_loop().create_task(self._accept(data, addr))
            return

    async def _accept(self, syn: bytes, addr) -> None:
        stream = await UtpStream.accept(
            self._send_frame, addr, syn
        )
        self.stream = stream
        self.accepted.put_nowait(stream)

    def _send_frame(self, data: bytes, addr) -> None:
        assert self.transport is not None
        self.transport.sendto(data, addr)


def test_utp_reliable_stream_loopback() -> None:
    async def scenario() -> None:
        loop = asyncio.get_running_loop()

        client_ep = _Endpoint("client")
        c_transport, _ = await loop.create_datagram_endpoint(
            lambda: client_ep, local_addr=("127.0.0.1", 0)
        )
        server_ep = _Endpoint("server")
        s_transport, _ = await loop.create_datagram_endpoint(
            lambda: server_ep, local_addr=("127.0.0.1", 0)
        )
        server_addr = s_transport.get_extra_info("sockname")

        async def client_frame(data: bytes, addr) -> None:
            server_ep.datagram_received_raw(data, ("127.0.0.1", client_ep.port))

        async def server_frame(data: bytes, addr) -> None:
            client_ep.datagram_received_raw(data, ("127.0.0.1", server_ep.port))

        client_ep._send_frame = client_frame  # type: ignore[method-assign]
        server_ep._send_frame = server_frame  # type: ignore[method-assign]

        client = UtpStream(client_frame, server_addr, initiator=True)
        client_ep.stream = client
        connect_task = asyncio.create_task(client.connect())
        server = await asyncio.wait_for(server_ep.accepted.get(), 10.0)
        await connect_task

        # client -> server: several chunks (exercises reordering/acking)
        payload = os.urandom(3000)
        for off in range(0, len(payload), 1000):
            await client.send(payload[off : off + 1000])
        received = b""
        while len(received) < len(payload):
            received += await asyncio.wait_for(server.recv(), 10.0)
        assert received == payload

        # server -> client
        back = b"ACK" * 1000
        await server.send(back)
        got = b""
        while len(got) < len(back):
            got += await asyncio.wait_for(client.recv(), 10.0)
        assert got == back

        await client.close()
        await server.close()
        c_transport.close()
        s_transport.close()

    asyncio.run(scenario())
