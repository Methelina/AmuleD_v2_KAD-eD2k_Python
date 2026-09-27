"""Download runner wiring the queue to peer-to-peer transfers.

Coordinates sequential peer attempts for a queued file: resolves known
ED2K sources from state, opens a ``PeerClient`` against each endpoint,
and drives the handshake / hashset / upload-slot / transfer pipeline.
A single peer is tried at a time; progress is forwarded to the queue's
part file via ``record_block`` and completion is finalized only when a
peer delivers the whole file.

src/amuled_v2/core/download/runner.py
Version:     0.5.0
Author:      Soror L.'.L.'.
Updated:     2026-09-27

Patch Notes v0.5.0 (Soror L'.L'.):
  [+] Stripe scheduling: racing peers get disjoint file regions
      (region = ceil(size/peers)); peer i downloads [i*region,
      min(size, (i+1)*region)).  Queue gap list decides completion; the
      outcome "complete" is now region-complete, winner selection falls
      back to the last attempt as before.
  [+] Buddy/direct callback: expect_connection_from started as a task
      BEFORE the UDP callback request — dial-backs race the wait and
      previously fell through to normal sessions when unclaimed.

Patch Notes v0.4.0 (Soror L'.L'.):
  [+] AICH requester audit (stage X): after a complete transfer the
      runner cross-checks the AICH master with the peer (recovery walk)
      and stores the verified master in state (aich_masters, migration
      10) — seed for corrupt-part salvage; aich_audit flag.

Patch Notes v0.3.0 (Soror L'.L'.):
  [+] kad3/kad5: after the 12 s buddy-callback timeout fall through to
      the NAT-T rendezvous path (uTP stream adopted as a downloader
      PeerClient; session kept alive via a closer callback).

Patch Notes v0.2.0 (Soror L'.L'.):
  [+] Parallel peer attempts (race semantics): up to max_peers peers run
      concurrently; the first peer delivering a complete file wins and the
      losers are cancelled.  Part-file writes stay sequential on the event
      loop, so sparse block writes from several peers are safe.
  [+] Optional source_provider: sources may come from the kernel over IPC
      instead of the runner's own state connection.

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Added DownloadRunner coordinating sequential peer download attempts.
  [+] Added source resolution converting high-id client rows to endpoints.
  [+] Added single-file run() and bulk run_all() entry points.
"""

from __future__ import annotations

import asyncio
import struct
from typing import TYPE_CHECKING, Any, Callable

from amuled_v2.logging_setup import LogTags, get_tagged_logger

if TYPE_CHECKING:
    from amuled_v2.core.download.queue import DownloadQueue
    from amuled_v2.core.peer.client import DownloadOutcome

log = get_tagged_logger(LogTags.DOWNLOAD, "core.download.runner")

__all__ = [
    "DownloadRunner",
    "DownloadRunnerError",
]

_HIGH_ID_THRESHOLD = 16_000_000
# KAD source-row types and how we may dial them (eMule DownloadQueue.cpp:
# 4906-4992).  Type 6 = direct-UDP-callback, types 3/5 = serving-buddy
# callback; both end with the firewalled source connecting OUT to us.
# Legacy rows ("kad" without a digit) and server rows dial directly.
_KAD_CALLBACK_TYPES = {"kad3", "kad5", "kad6"}
_KAD_UNDIALABLE_TYPES = {"kad3", "kad5"}  # for SX answers: callback-only


def _row_is_kad_callback(row: dict) -> bool:
    return str(row.get("source_type") or "").lower() in _KAD_CALLBACK_TYPES


def _row_not_directly_dialable(row: dict) -> bool:
    """True when a row may not be used for a DIRECT (SX answer) endpoint."""
    return str(row.get("source_type") or "").lower() in _KAD_UNDIALABLE_TYPES


class DownloadRunnerError(RuntimeError):
    """Raised for download runner lifecycle errors."""


def _client_id_to_ip(client_id: int) -> str:
    packed = struct.pack(">I", client_id & 0xFFFFFFFF)
    a, b, c, d = packed
    return f"{a}.{b}.{c}.{d}"


class DownloadRunner:
    """Sequential peer-driven download runner over a ``DownloadQueue``."""

    def __init__(
        self,
        queue: "DownloadQueue",
        *,
        local_client_id: int = 0,
        local_port: int = 8089,
        nickname: str = "AmuleD",
        max_peers: int = 3,
        peer_connect_timeout: float = 8.0,
        peer_response_timeout: float = 20.0,
        queue_wait_timeout: float = 60.0,
        traffic_sink: "Callable[[str, int], None] | None" = None,
        source_provider: "Callable[[str, int], list[dict]] | None" = None,
        plain_dial_ok: bool = False,
        secure_ident: "Any | None" = None,
        connection_source: "Callable[[str, float], Any] | None" = None,
        callback_identity: "dict[str, Any] | None" = None,
        aich_audit: bool = True,
    ) -> None:
        self.queue = queue
        self.local_client_id = local_client_id
        self.local_port = local_port
        self.nickname = nickname
        self.max_peers = max_peers
        self.peer_connect_timeout = peer_connect_timeout
        self.peer_response_timeout = peer_response_timeout
        self.queue_wait_timeout = queue_wait_timeout
        # Stage C credit accounting: forwarded to every PeerClient; called
        # with (peer_user_hash_hex, downloaded_bytes) per finished transfer.
        self.traffic_sink = traffic_sink
        # Stage U: when the kernel owns the db, sources arrive over IPC via
        # this provider instead of a direct state query.
        self.source_provider = source_provider
        # Plain dial for rows WITHOUT a KAD userhash.  On the real network
        # plain is dead (instant FIN) so the default is False; loopback
        # self-tests against our own plain-only listener set it True.
        self.plain_dial_ok = plain_dial_ok
        # Stage X SecureIdent: shared RSA provider forwarded to every
        # PeerClient so outgoing handshakes can challenge/verify SUI.
        self.secure_ident = secure_ident
        # Direct-callback (KAD source type 6): ``connection_source`` awaits
        # an inbound TCP connection from a given ip (the kernel listener);
        # ``callback_identity`` = {"tcp_port": int, "user_hash": bytes}.
        self.connection_source = connection_source
        self.callback_identity = callback_identity
        # AICH requester (stage X): after a complete transfer, cross-check
        # the AICH master with the peer and store the verified master in
        # state (aich_masters, migration 10) — seed for corrupt-part
        # salvage.
        self.aich_audit = aich_audit

    def resolve_sources(
        self, file_hash: str, *, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Dialable endpoints for a hash.

        Each endpoint dict: ``host, port, user_hash (bytes|None),
        source_type (str), kad_udp_port (int|None)``.  KAD firewalled types
        3/5 are skipped (need a serving-buddy callback); type 6 is returned
        with ``source_type='kad6'`` for the direct-callback flow.
        """
        if self.source_provider is not None:
            rows = self.source_provider(file_hash, limit)
        else:
            rows = self.queue.state.list_file_sources(file_hash, limit=limit)
        seen: set[tuple[str, int]] = set()
        endpoints: list[dict[str, Any]] = []
        skipped = 0
        for row in rows:
            client_id = row["client_id"]
            if client_id < _HIGH_ID_THRESHOLD:
                skipped += 1
                continue
            raw_hash = row.get("user_hash")
            user_hash: bytes | None = None
            if raw_hash:
                try:
                    user_hash = bytes.fromhex(str(raw_hash))
                except ValueError:
                    user_hash = None
            source_type = str(row.get("source_type") or "")
            if user_hash is None:
                if not self.plain_dial_ok:
                    skipped += 1
                    continue
            endpoint = (_client_id_to_ip(client_id), row["client_port"])
            if endpoint in seen:
                continue
            seen.add(endpoint)
            endpoints.append(
                {
                    "host": endpoint[0],
                    "port": endpoint[1],
                    "user_hash": user_hash,
                    "source_type": source_type,
                    "kad_udp_port": row.get("kad_udp_port"),
                    "buddy_id": row.get("buddy_id"),
                    # DB rows keep the buddy address in server_ip/server_port
                    # (kad CLI convention); provider rows may name them
                    # buddy_ip/buddy_port directly.
                    "buddy_ip": row.get("buddy_ip") or row.get("server_ip"),
                    "buddy_port": row.get("buddy_port")
                    or row.get("server_port"),
                }
            )
        if skipped:
            log.debug(
                "DOWNLOAD skipped undialable sources: hash=%s, skipped=%d",
                file_hash,
                skipped,
            )
        return endpoints

    async def _attempt_peer(
        self,
        endpoint: dict[str, Any],
        file_hash: str,
        size: int,
        file_hash_bytes: bytes,
        progress_callback: Callable[[int, int, int], None] | None,
        start_offset: int = 0,
        end_offset: int | None = None,
    ) -> dict:
        """Drive one peer through the full download ladder; return an
        outcome dict (never raises — failures become outcome dicts)."""
        host = endpoint["host"]
        port = int(endpoint["port"])
        user_hash = endpoint.get("user_hash")
        source_type = str(endpoint.get("source_type") or "")
        outcome: "DownloadOutcome | None" = None
        client = None
        closers: list[Callable[[], Any]] = []
        try:
            from amuled_v2.core.peer.client import PeerClient

            if source_type == "kad6":
                client = await self._connect_via_direct_callback(endpoint)
                if client is None:
                    return {
                        "file_hash": file_hash,
                        "bytes_received": 0,
                        "blocks_received": 0,
                        "complete": False,
                        "elapsed": 0.0,
                        "detail": "direct-callback: no inbound connection",
                    }
            elif source_type in ("kad3", "kad5"):
                client, extra_close = await self._connect_via_buddy_callback(
                    endpoint, file_hash_bytes
                )
                if extra_close is not None:
                    closers.append(extra_close)
                if client is None:
                    return {
                        "file_hash": file_hash,
                        "bytes_received": 0,
                        "blocks_received": 0,
                        "complete": False,
                        "elapsed": 0.0,
                        "detail": "buddy-callback/rendezvous: no connection",
                    }
            else:
                client = PeerClient(
                    host,
                    port,
                    local_client_id=self.local_client_id,
                    local_port=self.local_port,
                    nickname=self.nickname,
                    connect_timeout=self.peer_connect_timeout,
                    response_timeout=self.peer_response_timeout,
                    queue_wait_timeout=self.queue_wait_timeout,
                    traffic_sink=self.traffic_sink,
                    target_userhash=user_hash,
                    secure_ident=self.secure_ident,
                )
                await client.connect()
            await client.handshake()
            await client.request_file(file_hash_bytes)
            try:
                # Stage X source exchange: ask the peer for additional
                # sources; answers are collected asynchronously and
                # persisted in the finally block below.
                await client.request_sources(file_hash_bytes)
            except Exception as exc:
                log.debug(
                    "DOWNLOAD source exchange request failed: error=%s", exc
                )
            await client.wait_upload_slot(file_hash_bytes)
            outcome = await client.transfer(
                file_hash_bytes,
                size,
                write_block=lambda start, data: self.queue.record_block(
                    file_hash, start, data
                ),
                progress_callback=progress_callback,
                start_offset=start_offset,
                end_offset=end_offset,
            )
            if outcome.complete and start_offset == 0 and self.aich_audit:
                # AICH audit (stage X): the file just completed with MD4
                # pending; verify the AICH tree against the peer and store
                # the recovery-verified master for future salvage.  Must
                # never break the download itself.
                try:
                    await self._aich_audit(
                        client, file_hash, file_hash_bytes, size
                    )
                except Exception as exc:
                    log.debug(
                        "DOWNLOAD AICH audit skipped: hash=%s, error=%s",
                        file_hash, exc,
                    )
            return outcome.to_dict()
        except Exception as exc:
            log.warning(
                "DOWNLOAD peer attempt failed: endpoint=%s:%d, error=%s",
                host, port, exc,
            )
            if outcome is not None:
                return outcome.to_dict()
            return {
                "file_hash": file_hash,
                "bytes_received": 0,
                "blocks_received": 0,
                "complete": False,
                "elapsed": 0.0,
                "detail": f"peer error: {exc}",
            }
        finally:
            if client is not None:
                try:
                    self._persist_collected_sources(client, file_hash_bytes)
                except Exception:
                    pass
                await client.close()
            for closer in closers:
                try:
                    closer()
                except Exception:
                    pass

    def _persist_collected_sources(
        self, client: Any, file_hash_bytes: bytes
    ) -> None:
        """Persist sources learned via source exchange (stage X)."""
        entries = getattr(client, "collected_sources", None)
        if not entries:
            return
        from amuled_v2.core.ed2k.server_client import (
            FoundSource,
            FoundSources,
        )

        sources = tuple(
            FoundSource(
                client_id=s.client_id,
                client_port=s.port,
                user_hash=s.user_hash,
            )
            for s in entries
        )
        record = FoundSources(file_hash=file_hash_bytes, sources=sources)
        self.queue.state.save_found_sources(
            record, server_ip="0.0.0.0", server_port=0, source_type="sx"
        )
        log.info(
            "DOWNLOAD source-exchange sources saved: hash=%s, count=%d",
            file_hash_bytes.hex().upper(),
            len(sources),
        )

    async def _aich_audit(
        self,
        client,
        file_hash: str,
        file_hash_bytes: bytes,
        size: int,
    ) -> None:
        """AICH requester audit (stage X; SHAHashSet.cpp UntrustedHashReceived
        seed): cross-check the freshly downloaded file's AICH master with
        the peer and store the recovery-verified master hash."""
        from amuled_v2.core.codec.constants import PARTSIZE
        from amuled_v2.core.hashes.aich import (
            aich_hash_file,
            aich_rebuild_master_from_part,
        )

        entry = self.queue.get(file_hash)
        if entry is None:
            return
        part_path = str(entry["part_path"])
        result = aich_hash_file(part_path)
        master = result.master_hash
        parts = (size + PARTSIZE - 1) // PARTSIZE
        if parts > 1:
            # Peer cross-check: recovery data must rebuild our master from
            # part 0's bytes (the responder's master gate requires the
            # known master, which we just computed ourselves).
            got_hash, got_part, peer_master, recovery = (
                await client.request_aich(file_hash_bytes, 0, master)
            )
            if got_hash != file_hash_bytes or peer_master != master:
                log.warning(
                    "DOWNLOAD AICH master mismatch: hash=%s, ours=%s, "
                    "peer=%s",
                    file_hash, master.hex(), peer_master.hex(),
                )
                return
            with open(part_path, "rb") as handle:
                part_data = handle.read(PARTSIZE)
            rebuilt = aich_rebuild_master_from_part(
                part_data, 0, recovery, size
            )
            if rebuilt != master:
                log.warning(
                    "DOWNLOAD AICH recovery rebuild mismatch: hash=%s",
                    file_hash,
                )
                return
        self.queue.state.save_aich_master(file_hash, master)
        log.info(
            "DOWNLOAD AICH master stored: hash=%s, master=%s, parts=%d",
            file_hash, master.hex(), parts,
        )

    async def _connect_via_buddy_callback(
        self, endpoint: dict[str, Any], file_hash_bytes: bytes
    ):
        """KAD type-3/5 firewalled source: ask its serving buddy to relay a
        callback (KADEMLIA_CALLBACK_REQ), then adopt the inbound connection
        the firewalled source makes to us.

        After the 12 s buddy-callback fallback timeout (eMule
        BaseClient.cpp:3091-3257 — the double-firewalled case cannot
        relay a TCP callback), fall through to the NAT-T rendezvous path
        over punched UDP.  Returns (PeerClient | None, closer | None)."""
        from amuled_v2.core.kad.direct_callback import send_kad_callback_req

        if self.connection_source is None or not self.callback_identity:
            log.debug("DOWNLOAD buddy-callback unavailable: no listener wiring")
            return None, None
        raw_buddy_id = endpoint.get("buddy_id")
        buddy_ip = endpoint.get("buddy_ip")
        try:
            buddy_port = int(endpoint.get("buddy_port") or 0)
            buddy_id = bytes.fromhex(str(raw_buddy_id)) if raw_buddy_id else b""
        except ValueError:
            buddy_id = b""
        if not buddy_port or len(buddy_id) != 16:
            log.debug(
                "DOWNLOAD buddy-callback skipped (no buddy address): %s",
                endpoint.get("host"),
            )
            return None, None
        ident = self.callback_identity
        # Start waiting for the inbound TCP callback BEFORE the UDP request
        # goes out — dial-backs race the wait (client dials within ms).
        waiter = asyncio.create_task(
            self.connection_source(endpoint["host"], 12.0)
        )
        try:
            await send_kad_callback_req(
                buddy_ip,
                buddy_port,
                buddy_id,
                file_hash_bytes,
                int(ident["tcp_port"]),
            )
            try:
                reader, writer = await waiter
            except (asyncio.TimeoutError, TimeoutError):
                log.info(
                    "DOWNLOAD buddy-callback timed out (12s), trying "
                    "rendezvous: %s",
                    endpoint.get("host"),
                )
                return await self._connect_via_rendezvous(
                    endpoint, file_hash_bytes, buddy_id, buddy_ip, buddy_port
                )
        except BaseException:
            waiter.cancel()
            raise
        from amuled_v2.core.peer.client import PeerClient

        return (
            PeerClient.adopt_connection(
                reader,
                writer,
                local_client_id=self.local_client_id,
                local_port=int(ident["tcp_port"]),
                nickname=self.nickname,
                local_userhash=bytes(ident["user_hash"]),
                secure_ident=self.secure_ident,
                traffic_sink=self.traffic_sink,
            ),
            None,
        )

    async def _connect_via_rendezvous(
        self,
        endpoint: dict[str, Any],
        file_hash_bytes: bytes,
        buddy_id: bytes,
        buddy_ip: str,
        buddy_port: int,
    ):
        """NAT-T rendezvous (double-firewalled): punch UDP to the source
        via its buddy, run the CAPS exchange and bring up a uTP stream,
        then adopt it as a downloader PeerClient."""
        from amuled_v2.core.natt.session import NattUdpSession, ip_to_u32

        ident = self.callback_identity
        target_hash = endpoint.get("user_hash")
        session = NattUdpSession(bytes(ident["user_hash"]))
        await session.start()
        try:
            stream = await session.rendezvous_connect(
                buddy_host=buddy_ip,
                buddy_port=buddy_port,
                buddy_id=buddy_id,
                target_user_hash=bytes(target_hash),
                file_hash=file_hash_bytes,
                our_ext_ip=int(ident.get("ext_ip") or 0),
                target_addr=(
                    endpoint["host"],
                    int(endpoint.get("kad_udp_port") or 0),
                ),
            )
        except Exception as exc:
            session.close()
            log.info(
                "DOWNLOAD rendezvous failed: peer=%s, error=%s",
                endpoint.get("host"), exc,
            )
            return None, None
        from amuled_v2.core.peer.client import PeerClient

        client = PeerClient.adopt_connection(
            stream.reader(),
            stream.writer(),
            local_client_id=self.local_client_id,
            local_port=int(ident["tcp_port"]),
            nickname=self.nickname,
            local_userhash=bytes(ident["user_hash"]),
            secure_ident=self.secure_ident,
            traffic_sink=self.traffic_sink,
        )
        return client, session.close

    async def _connect_via_direct_callback(self, endpoint: dict[str, Any]):
        """KAD type-6 firewalled source: ask it to TCP-connect back, then
        adopt the inbound connection as a downloader PeerClient."""
        from amuled_v2.core.kad.direct_callback import send_direct_callback_req

        if self.connection_source is None or not self.callback_identity:
            log.debug("DOWNLOAD direct-callback unavailable: no listener wiring")
            return None
        host = endpoint["host"]
        kad_port = int(endpoint.get("kad_udp_port") or 0)
        if not kad_port:
            log.debug(
                "DOWNLOAD direct-callback skipped (no kad udp port): %s", host
            )
            return None
        ident = self.callback_identity
        # Waiter task BEFORE the UDP request (dial-backs race the wait).
        waiter = asyncio.create_task(self.connection_source(host, 15.0))
        try:
            await send_direct_callback_req(
                host,
                kad_port,
                int(ident["tcp_port"]),
                bytes(ident["user_hash"]),
                connect_options=3,
            )
            reader, writer = await waiter
        except BaseException:
            waiter.cancel()
            raise
        from amuled_v2.core.peer.client import PeerClient

        return PeerClient.adopt_connection(
            reader,
            writer,
            local_client_id=self.local_client_id,
            local_port=int(ident["tcp_port"]),
            nickname=self.nickname,
            local_userhash=bytes(ident["user_hash"]),
            secure_ident=self.secure_ident,
            traffic_sink=self.traffic_sink,
        )

    async def run(
        self,
        file_hash: str,
        *,
        verify: bool = True,
        progress_callback: Callable[[int, int, int], None] | None = None,
    ) -> dict:
        entry = self.queue.get(file_hash)
        if entry is None:
            from amuled_v2.core.download.queue import DownloadQueueError

            raise DownloadQueueError(f"download not found: {file_hash}")
        if entry["status"] == "complete":
            return {"status": "already_complete", **entry}

        sources = self.resolve_sources(file_hash)
        if not sources:
            from amuled_v2.core.download.queue import DownloadQueueError

            raise DownloadQueueError(
                f"no known sources for hash {file_hash}; run a sources lookup first"
            )

        file_hash_bytes = bytes.fromhex(str(entry["hash"]))
        size = int(entry["size"])
        endpoints = sources[: self.max_peers]
        # Stripe scheduling (stage X): every racing peer gets a disjoint
        # region so parallel peers stop downloading identical bytes.  The
        # queue's gap list stays the completion source of truth.
        region = (size + len(endpoints) - 1) // len(endpoints)
        log.info(
            "DOWNLOAD race start: hash=%s, peers=%d, stripe=%d",
            file_hash, len(endpoints), region,
        )

        tasks = {
            asyncio.create_task(
                self._attempt_peer(
                    endpoint,
                    file_hash,
                    size,
                    file_hash_bytes,
                    progress_callback,
                    start_offset=index * region,
                    end_offset=min(size, (index + 1) * region),
                ),
                name=f"dl-peer-{endpoint['host']}:{endpoint['port']}",
            ): endpoint
            for index, endpoint in enumerate(endpoints)
        }
        attempts: list[dict] = []
        pending = set(tasks)
        try:
            while pending:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    attempts.append(task.result())
                refreshed = self.queue.get(file_hash)
                if refreshed is not None and refreshed["status"] == "complete":
                    # First winner takes the file; the losing peers are
                    # cancelled mid-transfer.
                    for task in pending:
                        task.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
                    finalized = self.queue.finalize(file_hash, verify=verify)
                    winner = next(
                        (a for a in attempts if a.get("complete")),
                        attempts[-1] if attempts else {},
                    )
                    log.info(
                        "DOWNLOAD race won: hash=%s, attempts=%d", file_hash,
                        len(attempts),
                    )
                    return {
                        "status": "complete",
                        "outcome": winner,
                        "finalized": finalized,
                    }
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        return {
            "status": "incomplete",
            "hash": file_hash,
            "outcomes": attempts,
        }

    async def run_all(
        self,
        *,
        verify: bool = True,
        progress_callback: Callable[[int, int, int], None] | None = None,
    ) -> list[dict]:
        results: list[dict] = []
        for entry in self.queue.list(limit=100):
            if entry["status"] not in ("queued", "downloading"):
                continue
            result = await self.run(
                str(entry["hash"]),
                verify=verify,
                progress_callback=progress_callback,
            )
            results.append(result)
        return results
