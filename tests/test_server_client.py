"""Loopback integration tests for the asyncio ED2K server TCP session.

A deterministic fake ED2K server exercises the complete login sequence over a
real TCP socket: server message, server identity, server status, then ID change.
No external network access is used.

tests/test_server_client.py
Version:     0.1.2
Author:      Soror L.'.L.'.
Updated:     2026-09-22

Patch Notes v0.1.2 (Soror L.'.L'.):
  [+] Added extended eMule-compatible OP_IDCHANGE payload coverage for server
      flags, primary TCP port, and reported IP.
  [*] Updated the fake server to the real ED2K header order: protocol,
      UInt32 packet length, opcode; packet length includes the opcode.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added real-loopback login handshake integration coverage.
  [+] Tested OP_SERVERMESSAGE, OP_SERVERIDENT, OP_SERVERSTATUS, and OP_IDCHANGE.
  [+] Tested high/low-ID classification and clean session teardown.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from amuled_v2.core.codec.binary import BinaryWriter
from amuled_v2.core.codec.constants import EDONKEY
from amuled_v2.core.codec.packet import Packet, encode_packet
from amuled_v2.core.codec.tags import Ed2kTag, write_new_tag
from amuled_v2.core.ed2k import (
    C2STCP,
    Ed2kServerClient,
    LoginRequest,
    ServerSessionError,
)


def _packet(opcode: int, payload: bytes) -> bytes:
    return encode_packet(Packet(protocol=EDONKEY, opcode=opcode, payload=payload))


def _message_payload(text: str) -> bytes:
    writer = BinaryWriter()
    writer.write_string_utf8(text)
    return writer.to_bytes()


def _identity_payload() -> bytes:
    writer = BinaryWriter()
    writer.write_hash16(os.urandom(16))
    writer.write_u32((127 << 24) | 1)
    writer.write_u16(4661)
    tags = [
        Ed2kTag(name_id=0x01, type=0x02, value="Fake ED2K Server"),
        Ed2kTag(name_id=0x0B, type=0x02, value="loopback"),
    ]
    writer.write_u32(len(tags))
    for tag in tags:
        write_new_tag(tag, writer)
    return writer.to_bytes()


def _status_payload(users: int = 1234, files: int = 5678) -> bytes:
    writer = BinaryWriter()
    writer.write_u32(users)
    writer.write_u32(files)
    return writer.to_bytes()


def _id_payload(client_id: int, extended: bool = False) -> bytes:
    writer = BinaryWriter()
    writer.write_u32(client_id)
    if extended:
        writer.write_u32(0x000017F9)
        writer.write_u32(4725)
        writer.write_u32((187 << 24) | 3221225)
    return writer.to_bytes()


class FakeEd2kServer:
    """Minimal ordered-response ED2K server for TCP integration."""

    def __init__(self) -> None:
        self.server: asyncio.AbstractServer | None = None
        self.port = 0
        self.received_opcode: int | None = None
        self.received_payload: bytes = b""

    async def _client_connected(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            header = await reader.readexactly(6)
            packet_length = int.from_bytes(header[1:5], "little")
            payload = await reader.readexactly(packet_length - 1)
            self.received_opcode = header[5]
            self.received_payload = payload

            writer.write(_packet(C2STCP.SERVERMESSAGE, _message_payload("Welcome")))
            writer.write(_packet(C2STCP.SERVERIDENT, _identity_payload()))
            writer.write(_packet(C2STCP.SERVERSTATUS, _status_payload()))
            writer.write(_packet(C2STCP.IDCHANGE, _id_payload(0x0A0B0C0D, extended=True)))
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._client_connected,
            host="127.0.0.1",
            port=0,
        )
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()


def _login() -> LoginRequest:
    return LoginRequest(
        user_hash=os.urandom(16),
        client_id=0,
        client_port=8089,
        nickname="AmuleD_v2",
    )


@pytest.mark.asyncio
async def test_ed2k_login_handshake_over_real_loopback() -> None:
    fake = FakeEd2kServer()
    await fake.start()
    try:
        async with Ed2kServerClient(
            "127.0.0.1",
            fake.port,
            _login(),
            connect_timeout=2.0,
            response_timeout=2.0,
        ) as client:
            assert client.is_connected is True
            result = await client.login()
            assert fake.received_opcode == C2STCP.LOGINREQUEST
            assert result.client_id == 0x0A0B0C0D
            assert result.low_id is False
            assert result.messages == ["Welcome"]
            assert result.identity is not None
            assert result.identity.name() == "Fake ED2K Server"
            assert result.identity.description() == "loopback"
            assert result.status is not None
            assert result.status.users == 1234
            assert result.status.files == 5678
            assert result.id_change is not None
            assert result.id_change.server_flags == 0x000017F9
            assert result.id_change.primary_tcp_port == 4725
            assert result.id_change.reported_ip is not None
            assert result.id_change.obfuscation_tcp_port is None
            assert client.logged_in is True
            assert result.elapsed >= 0.0
        assert client.is_connected is False
    finally:
        await fake.stop()


@pytest.mark.asyncio
async def test_ed2k_login_classifies_low_id() -> None:
    fake = FakeEd2kServer()
    await fake.start()

    async def fake_low_id_handler(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        header = await reader.readexactly(6)
        packet_length = int.from_bytes(header[1:5], "little")
        await reader.readexactly(packet_length - 1)
        writer.write(_packet(C2STCP.IDCHANGE, _id_payload(123)))
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass

    assert fake.server is not None
    fake.server.close()
    await fake.server.wait_closed()
    fake.server = await asyncio.start_server(
        fake_low_id_handler,
        host="127.0.0.1",
        port=0,
    )
    fake.port = fake.server.sockets[0].getsockname()[1]

    try:
        client = Ed2kServerClient(
            "127.0.0.1",
            fake.port,
            _login(),
            connect_timeout=2.0,
            response_timeout=2.0,
        )
        await client.connect()
        result = await client.login()
        assert result.client_id == 123
        assert result.low_id is True
        await client.close()
    finally:
        await fake.stop()


@pytest.mark.asyncio
async def test_ed2k_session_requires_connection() -> None:
    client = Ed2kServerClient("127.0.0.1", 1, _login())
    with pytest.raises(ServerSessionError):
        await client._receive_packet()


@pytest.mark.asyncio
async def test_ed2k_login_cannot_run_twice() -> None:
    fake = FakeEd2kServer()
    await fake.start()
    try:
        client = Ed2kServerClient(
            "127.0.0.1",
            fake.port,
            _login(),
            connect_timeout=2.0,
            response_timeout=2.0,
        )
        await client.connect()
        await client.login()
        with pytest.raises(ServerSessionError):
            await client.login()
        await client.close()
    finally:
        await fake.stop()
