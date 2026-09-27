"""Offline loopback tests for the SecureIdent (SUI) wire exchange (stage X).

Both sides of a real TCP loopback session hold a SecureIdentProvider with a
fresh RSA-384 key pair: the listener challenges the outgoing PeerClient and
the client challenges back.  After ``PeerClient.handshake()`` both providers
must have marked the OTHER side's userhash as verified
(BaseClient.cpp InfoPacketsReceived / SendSecIdentStatePacket / VerifyIdent).

tests/test_sui_wire.py
Author:      Soror L.'.L.'.
Updated:     2026-09-27
"""

from __future__ import annotations

import asyncio
import os

from amuled_v2.core.peer.client import PeerClient
from amuled_v2.core.peer.listener import IncomingPeerServer, LocalIdentity
from amuled_v2.core.security.secure_ident import SecureIdentProvider
from amuled_v2.core.sharing.shared_files import SharedFile
from amuled_v2.core.upload.queue import UploadQueue

_LOCAL_HASH = bytes.fromhex("B" * 32)
_LOCAL_ID = 0x55667788
_NICK = "AmuleD-SUI"
_IO_TIMEOUT = 30.0


class _EmptyResolver:
    def resolve(self, file_hash: bytes) -> SharedFile | None:
        return None


def _identity() -> LocalIdentity:
    return LocalIdentity(
        user_hash=_LOCAL_HASH,
        client_id=_LOCAL_ID,
        tcp_port=0,
        nickname=_NICK,
    )


def _provider(tmp_path, name: str) -> SecureIdentProvider:
    provider = SecureIdentProvider(key_path=tmp_path / name)
    provider.ensure_keys()
    assert provider.has_keys
    return provider


def _run(coro) -> None:
    asyncio.run(coro)


def test_sui_mutual_verification_loopback(tmp_path) -> None:
    async def scenario() -> None:
        server_keys = _provider(tmp_path, "server_cryptkey.dat")
        client_keys = _provider(tmp_path, "client_cryptkey.dat")
        server = IncomingPeerServer(
            identity=_identity(),
            resolver=_EmptyResolver(),
            upload_queue=UploadQueue(),
            host="127.0.0.1",
            port=0,
            idle_timeout=15.0,
            secure_ident=server_keys,
        )
        await server.start()
        try:
            client = PeerClient(
                "127.0.0.1",
                server.bound_port,
                local_client_id=0x99AABBCC,
                local_port=0,
                nickname="AmuleD-peer",
                response_timeout=10.0,
                local_userhash=bytes.fromhex("C" * 32),
                secure_ident=client_keys,
            )
            try:
                await asyncio.wait_for(client.connect(), _IO_TIMEOUT)
                await asyncio.wait_for(client.handshake(), _IO_TIMEOUT)
            finally:
                await client.close()

            client_view = client_keys.evaluate(_LOCAL_HASH.hex())
            assert client_view.verified, (
                "client must verify the listener userhash over the wire"
            )
            server_view = server_keys.evaluate(client.user_hash.hex())
            assert server_view.verified, (
                "listener must verify the client userhash over the wire"
            )
        finally:
            await server.close()

    _run(scenario())


def test_no_challenge_without_provider(tmp_path) -> None:
    """Without a provider the client never sends SECIDENTSTATE and the
    handshake still completes (backwards compatibility)."""

    async def scenario() -> None:
        server = IncomingPeerServer(
            identity=_identity(),
            resolver=_EmptyResolver(),
            upload_queue=UploadQueue(),
            host="127.0.0.1",
            port=0,
            idle_timeout=15.0,
        )
        await server.start()
        try:
            client = PeerClient(
                "127.0.0.1",
                server.bound_port,
                local_client_id=0x99AABBCC,
                local_port=0,
                nickname="AmuleD-peer",
                response_timeout=10.0,
                local_userhash=bytes.fromhex("D" * 32),
            )
            try:
                await asyncio.wait_for(client.connect(), _IO_TIMEOUT)
                info = await asyncio.wait_for(client.handshake(), _IO_TIMEOUT)
                assert info.user_hash == _LOCAL_HASH.hex().upper()
                assert client._sui["challenge_out"] is None
            finally:
                await client.close()
        finally:
            await server.close()

    _run(scenario())
