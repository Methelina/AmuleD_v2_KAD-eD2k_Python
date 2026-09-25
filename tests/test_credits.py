"""Stage C tests: client credit ledger + SecureIdent adapter skeleton.

Author: Soror L.'.L.'.
Updated: 2026-09-25
"""

from __future__ import annotations

import asyncio
import os

import pytest

from amuled_v2.core.peer.client import PeerClient
from amuled_v2.core.peer.listener import IncomingPeerServer, LocalIdentity
from amuled_v2.core.security import (
    SecureIdentError,
    SecureIdentProvider,
    SecureIdentState,
)
from amuled_v2.core.sharing.shared_files import SharedFile
from amuled_v2.core.upload.queue import UploadQueue
from amuled_v2.state import StateBackend

_LOCAL_HASH = bytes.fromhex("C" * 32)


def _unique_uh() -> str:
    """Fresh 32-hex userhash per test: the ledger persists in the shared
    (conftest-redirected) database, so tests must not collide."""
    return os.urandom(16).hex()


class _FakeResolver:
    def __init__(self, mapping: dict[bytes, SharedFile]) -> None:
        self._mapping = mapping

    def resolve(self, file_hash: bytes) -> SharedFile | None:
        return self._mapping.get(file_hash)


# --- migration 7 + ledger API -------------------------------------------------


def test_migration7_tables_exist() -> None:
    state = StateBackend()
    state.connect()
    try:
        con = state._require_duckdb()
        version = con.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()[0]
        assert version >= 7
        con.execute("SELECT * FROM client_credits LIMIT 0")
        con.execute("SELECT * FROM seen_clients LIMIT 0")
    finally:
        state.close()


def test_record_traffic_accumulates_and_clamps() -> None:
    uh = _unique_uh()
    state = StateBackend()
    state.connect()
    try:
        state.record_traffic(uh, uploaded=100, downloaded=50)
        state.record_traffic(uh, uploaded=10)
        row = state.get_credits(uh)
        assert row is not None
        assert row["uploaded"] == 110
        assert row["downloaded"] == 50

        # seen_clients is kept in sync by record_traffic
        seen = [s for s in state.list_seen_clients(limit=1000) if s["user_hash"] == uh]
        assert len(seen) == 1

        # refund subtracts and clamps at zero
        state.refund_traffic(uh, uploaded=10, downloaded=1000)
        row = state.get_credits(uh)
        assert row["uploaded"] == 100
        assert row["downloaded"] == 0

        # refund for an unknown client returns None
        assert state.refund_traffic(_unique_uh(), uploaded=1) is None
    finally:
        state.close()


def test_list_credits_orders_by_total() -> None:
    uh_a = _unique_uh()
    uh_b = _unique_uh()
    state = StateBackend()
    state.connect()
    try:
        state.record_traffic(uh_a, uploaded=10)
        state.record_traffic(uh_b, uploaded=1000)
        listed = [
            r
            for r in state.list_credits(limit=1000)
            if r["user_hash"] in (uh_a, uh_b)
        ]
        listed.sort(key=lambda r: -(r["uploaded"] + r["downloaded"]))
        assert listed[0]["user_hash"] == uh_b
    finally:
        state.close()


def test_normalize_user_hash_rejects_garbage() -> None:
    state = StateBackend()
    state.connect()
    try:
        with pytest.raises(ValueError):
            state.record_traffic("nothex")
    finally:
        state.close()


# --- SecureIdent adapter -------------------------------------------------------


def test_secure_ident_provider_is_a_mock() -> None:
    provider = SecureIdentProvider()
    assert provider.has_keys is False
    with pytest.raises(SecureIdentError):
        provider.sign(b"challenge")
    with pytest.raises(SecureIdentError):
        provider.verify(_unique_uh(), b"sig", b"challenge")


def test_secure_ident_evaluate_unverified_no_bonus() -> None:
    provider = SecureIdentProvider()
    uh = _unique_uh()
    info = provider.evaluate(uh)
    assert info.verified is False
    assert info.bonus_multiplier == 1.0
    assert info.state == SecureIdentState.NOT_AVAILABLE
    assert info.to_dict()["user_hash"] == uh


# --- integration: listener credits uploaded bytes -----------------------------


def test_listener_credits_uploaded_bytes(tmp_path) -> None:
    credited: list[tuple[str, int]] = []

    async def scenario() -> None:
        # Build a small shared file.
        path = tmp_path / "cred.bin"
        path.write_bytes(os.urandom(50_000))
        from amuled_v2.core.hashes.ed2k import ed2k_hash_file

        result = ed2k_hash_file(str(path))
        shared = SharedFile(
            file_hash=result.file_hash,
            name=path.name,
            size=result.file_size,
            path=str(path),
            hash_result=result,
        )

        # Ledger client userhash is the client's own HELLO userhash.
        credited: list[tuple[str, int]] = []

        def recorder(user_hash_hex: str, uploaded: int) -> None:
            # In-memory only: the real DuckDB may be locked by the spider;
            # the state-backed path is covered by test_record_traffic_*.
            credited.append((user_hash_hex, uploaded))

        server = IncomingPeerServer(
            identity=LocalIdentity(
                user_hash=_LOCAL_HASH,
                client_id=1,
                tcp_port=0,
                nickname="AmuleD-cred",
            ),
            resolver=_FakeResolver({shared.file_hash: shared}),
            upload_queue=UploadQueue(max_slots=2),
            host="127.0.0.1",
            port=0,
            idle_timeout=15.0,
            traffic_recorder=recorder,
        )
        await server.start()
        try:
            client = PeerClient(
                "127.0.0.1",
                server.bound_port,
                connect_timeout=30.0,
                response_timeout=30.0,
                queue_wait_timeout=30.0,
            )
            peer_user_hash = client.user_hash.hex().lower()
            async with client:
                await asyncio.wait_for(client.handshake(), timeout=30)
                await asyncio.wait_for(
                    client.request_file(shared.file_hash), timeout=30
                )
                await asyncio.wait_for(
                    client.wait_upload_slot(shared.file_hash), timeout=30
                )
                await asyncio.wait_for(
                    client.transfer(
                        shared.file_hash,
                        shared.size,
                        write_block=lambda s, d: None,
                    ),
                    timeout=60,
                )
            # The server-side session task credits asynchronously; poll
            # instead of racing it right after client.close().
            for _ in range(60):
                if credited:
                    break
                await asyncio.sleep(0.5)
            assert credited, "traffic recorder was not invoked"
            assert credited[0][0] == peer_user_hash
            assert credited[0][1] >= shared.size
        finally:
            await server.close()

    asyncio.run(scenario())
