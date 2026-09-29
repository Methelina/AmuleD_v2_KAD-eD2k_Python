"""Download runner wiring the queue to peer-to-peer transfers.

Coordinates sequential peer attempts for a queued file: resolves known
ED2K sources from state, opens a ``PeerClient`` against each endpoint,
and drives the handshake / hashset / upload-slot / transfer pipeline.
A single peer is tried at a time; progress is forwarded to the queue's
part file via ``record_block`` and completion is finalized only when a
peer delivers the whole file.

src/amuled_v2/core/download/runner.py
Version:     0.9.6
Author:      Soror L.'.L.'.
Updated:     2026-09-29

Patch Notes v0.9.6 (Soror L.'.L'.):
  [+] rank_sink kwarg: every OP_QUEUERANK seen in transfer() is reported as
      {"host", "port", "rank", "at"} (live-test gate "dial + QUEUERANK",
      roadmap 11s); callback exceptions are logged, never propagated.

Patch Notes v0.9.5 (Soror L.'.L'.):
  [+] __init__ gains max_sources_per_file / download_bytes_per_sec /
      crypt_layer_required kwargs; resolved lazily via load_config() when None,
      with a tagged "runner fallback:" warning on config failure.
  [+] resolve_sources signature default changed to limit: int | None = None;
      falls back to self.max_sources_per_file when unset (400 default).
  [+] Download throttle: async _throttle_gate(nbytes) token-bucket gate wraps
      the single record_block write path; unlimited (<=0) is a no-op.
  [+] Crypt-layer-required gate in _attempt_peer: the obf-dial plain fallback
      is suppressed when crypt_layer_required, and a plain-dial success now
      logs "DOWNLOAD crypt layer required but peer dialed plain" warning.

Patch Notes v0.9.4 (Soror L.'.L'.):
  [+] _connect_via_rendezvous: loopback buddies start the NAT-T session on
      127.0.0.1 (0.0.0.0 would take the NIC-egress pin, and a NIC-pinned
      socket cannot send to 127.0.0.1 - WinError 1214; live 2026-09-28
      suite regression).

Patch Notes v0.9.3 (Soror L.'.L'.):
  [+] _regions_from_gaps(): terminate when gap space is exhausted - with
      peers > number of gap regions the old loop span forever on
      zero-width takes (live 2026-09-28: 1 gap x 50 peers froze the
      kernel event loop, found via faulthandler stack dump).

Patch Notes v0.9.2 (Soror L.'.L'.):
  [!] All silent `except Exception: pass` sites now log a tagged "runner
      fallback:" line (log.debug for best-effort teardown noise, log.warning
      for result-affecting degradations) per project policy.  Bare
      `except Exception:` changed to `except Exception as exc:`.

Patch Notes v0.9.1 (Soror L.'.L'.):
  [+] Stable HELLO identity: PeerClient now receives local_userhash from
      callback_identity (persistent KAD identity).  Live evidence
      2026-09-28: eMuleAI 1.6.0 bans "Userhash changed"
      (TrackedClientsList / <Ban> [Bad user hash]) when a peer presents
      os.urandom(16) per connection - repeated dials were FINned at the
      BASIC handshake.

Patch Notes v0.9.0 (Soror L.'.L'.):
  [+] Runner-level A4AF/NNS gate (stateless-session equivalent of eMule's
      SwapToAnotherFile, DownloadClient.cpp:2171 / PartFile.cpp:3353-3370).
      _attempt_peer consults _a4af_needed_parts after wait_upload_slot:
      DS_NONEEDEDPARTS skip (peer has none of our gap parts) records an
      "nns" verdict and short-circuits the transfer with a zero-byte
      outcome dict; peers with complete_sources or unknown part-status
      pass through as before.  resolve_sources drops endpoints whose
      (host, port) carries a known "nns" verdict for the file so the
      source is not re-dialed (it remains available for OTHER files).
  [+] _a4af_verdicts: per-(host,port) dict of file_hash_hex -> verdict.
  [+] _a4af_needed_parts: computes gap parts from queue.gap_ranges and
      intersects them with client.part_status / complete_sources.
  [+] _a4af_verdict: single-read helper used by both gate points.

Patch Notes v0.8.0 (Soror L.'.L'.):
  [+] ICS (Intelligent Chunk Selection): runner-level requested-ranges registry
      (_requested_ranges) as the IsAlreadyRequested equivalent (PartFile.cpp:2674-2696);
      per-peer block_selector built on amuled_v2.core.download.ics.select_blocks;
      _part_frequencies aggregates live peer part-status (ics-filestatus-client.recon.md,
      ics-endgame.recon.md section 5: UpdatePartsInfo PartFile.cpp:3644-3677).
  [+] ICS path activates only when file > PART_SIZE or >1 gap; single-part /
      single-gap files keep the linear stripe transfer.  Selector creation is
      try/except-guarded — on any failure the existing stripe transfer is used
      unchanged (no swallowing of transfer errors).
  [+] complete_sources / part_status on PeerClient (parallel client.py change)
      feed _part_frequencies; peers with no status info are treated as complete
      sources (unknown -> assume available, per ics-filestatus-client.recon.md
      Mode A: chunk_count == 0 means the peer has every part).

Patch Notes v0.7.1 (Soror L.'.L'.):
  [+] Self-record filter (roadmap 11o addendum 4): resolve_sources
      drops KAD records whose ipv6 is one of OUR local addresses (NAT
      reflection / self-publication) or whose userhash equals ours;
      self_record_filter flag for loopback tests.

Patch Notes v0.7.0 (Soror L.'.L'.):
  [+] Corrupt-part salvage (stage X; PartFile.cpp HashSinglePart
      :4399-4474 + FlushBuffer:5793-5804): after a full-file transfer,
      every PART's MD4 is verified against the peer's hashset; corrupt
      parts are punched as gaps (queue.punch_gaps -> PartFile.punch)
      and the rounds loop refetches them before finalize.

Patch Notes v0.6.0 (Soror L.'.L'.):
  [+] Stalled-stripe reassignment: run() races up to 3 rounds; later
      rounds re-stripe the CURRENT gap list (queue.gap_ranges), and
      peers that delivered zero bytes in a round are pruned from later
      rounds (their slice goes to the survivors).

Patch Notes v0.5.1 (Soror L.'.L'.):
  [+] IPv6 rendezvous: endpoint rows may carry ipv6/buddy_ipv6 (eMuleAI
      "ip6"/"bi6"); an ipv6 target starts the dual-stack NAT-T session
      (start6) and drives the direct-punch variant (endpoint hints are
      IPv4-only).
  [+] resolve_sources carries ipv6/buddy_ipv6 through to endpoints.

Patch Notes v0.5.0 (Soror L.'.L'.):
  [+] Stripe scheduling: racing peers get disjoint file regions
      (region = ceil(size/peers)); peer i downloads [i*region,
      min(size, (i+1)*region)).  Queue gap list decides completion; the
      outcome "complete" is now region-complete, winner selection falls
      back to the last attempt as before.
  [+] Buddy/direct callback: expect_connection_from started as a task
      BEFORE the UDP callback request — dial-backs race the wait and
      previously fell through to normal sessions when unclaimed.

Patch Notes v0.4.0 (Soror L.'.L'.):
  [+] AICH requester audit (stage X): after a complete transfer the
      runner cross-checks the AICH master with the peer (recovery walk)
      and stores the verified master in state (aich_masters, migration
      10) — seed for corrupt-part salvage; aich_audit flag.

Patch Notes v0.3.0 (Soror L.'.L'.):
  [+] kad3/kad5: after the 12 s buddy-callback timeout fall through to
      the NAT-T rendezvous path (uTP stream adopted as a downloader
      PeerClient; session kept alive via a closer callback).

Patch Notes v0.2.0 (Soror L.'.L'.):
  [+] Parallel peer attempts (race semantics): up to max_peers peers run
      concurrently; the first peer delivering a complete file wins and the
      losers are cancelled.  Part-file writes stay sequential on the event
      loop, so sparse block writes from several peers are safe.
  [+] Optional source_provider: sources may come from the kernel over IPC
      instead of the runner's own state connection.

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added DownloadRunner coordinating sequential peer download attempts.
  [+] Added source resolution converting high-id client rows to endpoints.
  [+] Added single-file run() and bulk run_all() entry points.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from typing import TYPE_CHECKING, Any, Callable, Sequence

from amuled_v2.core.download.ics import PART_SIZE as _ICS_PART_SIZE
from amuled_v2.logging_setup import LogTags, get_tagged_logger

if TYPE_CHECKING:
    from amuled_v2.core.download.queue import DownloadQueue
    from amuled_v2.core.peer.client import DownloadOutcome, PeerSessionError

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


def _coerce_userhash(value) -> bytes | None:
    """callback_identity user_hash arrives as bytes or a hex string."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    text = str(value)
    return bytes.fromhex(text) if text else None


def _regions_from_gaps(
    gaps: list[tuple[int, int]], peers: int
) -> list[tuple[int, int]]:
    """Split the gap space into ``peers`` contiguous [start, end) regions.

    Regions may span a filled sub-range inside a gap boundary — the
    transfer then re-requests those bytes (bounded duplication, correct
    by construction; the queue's gap list stays the source of truth).
    """
    if not gaps or peers <= 0:
        return []
    total = sum(end - start for start, end in gaps)
    per = (total + peers - 1) // peers
    regions: list[tuple[int, int]] = []
    idx = 0
    pos = gaps[0][0]
    for _ in range(peers):
        # Termination guard (live 2026-09-28: 1 gap x 50 peers spun
        # forever once the last gap was exhausted - take stayed 0 for
        # every "surplus" peer).  No gap space left -> stop; surplus
        # peers simply get no region.
        if idx >= len(gaps):
            break
        budget = per
        start = pos
        while budget > 0 and idx < len(gaps):
            gap_start, gap_end = gaps[idx]
            take = min(gap_end - pos, budget)
            if take <= 0:
                if idx + 1 < len(gaps):
                    idx += 1
                    pos = gaps[idx][0]
                    continue
                break
            pos += take
            budget -= take
            if pos >= gap_end and idx + 1 < len(gaps):
                idx += 1
                pos = gaps[idx][0]
        if pos > start:
            regions.append((start, pos))
        else:
            break
    return regions


class DownloadRunnerError(RuntimeError):
    """Raised for download runner lifecycle errors."""


def _client_id_to_ip(client_id: int) -> str:
    packed = struct.pack(">I", client_id & 0xFFFFFFFF)
    a, b, c, d = packed
    return f"{a}.{b}.{c}.{d}"


def _local_ip_set() -> set[str]:
    """All local addresses of this host (loopback included) — used to
    drop self-referential KAD records (a record can carry our own
    address after NAT reflection or self-publication)."""
    ips: set[str] = {"127.0.0.1", "::1"}
    try:
        host = socket.gethostname()
        for family in (socket.AF_INET, socket.AF_INET6):
            for info in socket.getaddrinfo(host, None, family):
                ips.add(str(info[4][0]))
    except OSError:
        pass
    return ips


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
        self_record_filter: bool = True,
        max_sources_per_file: int | None = None,
        download_bytes_per_sec: int | None = None,
        crypt_layer_required: bool | None = None,
        rank_sink: "Callable[[dict[str, Any]], None] | None" = None,
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
        # Self-record filter: drop KAD records whose ipv6 is one of OUR
        # local addresses (NAT reflection / self-publication).  Loopback
        # tests disable it — their fake source legitimately sits on ::1.
        self.self_record_filter = self_record_filter
        # Config-derived network/download knobs (roadmap 11r).  Each is
        # resolved lazily from amuled_v2.config.load_config() when the caller
        # did not pass it explicitly; on any config failure we fall back to
        # the documented defaults (project fallback-logging policy).
        cfg = None
        try:
            from amuled_v2.config import load_config

            cfg = load_config()
        except Exception as exc:
            log.warning(
                "DOWNLOAD runner fallback: config load failed, using "
                "defaults for unresolved knobs: error=%s", exc,
            )
        net = (cfg.get("network", {}) if cfg else {})
        dl = (cfg.get("download", {}) if cfg else {})
        if max_sources_per_file is None:
            max_sources_per_file = int(dl.get("max_sources_per_file", 400))
        if download_bytes_per_sec is None:
            download_bytes_per_sec = int(net.get("max_download_bytes_per_sec", 0))
        if crypt_layer_required is None:
            crypt_layer_required = bool(net.get("crypt_layer_required", False))
        # Normalize: 0/negative download_bytes_per_sec means unlimited.
        self.max_sources_per_file = int(max_sources_per_file) if max_sources_per_file else 400
        self.download_bytes_per_sec = (
            int(download_bytes_per_sec) if download_bytes_per_sec else 0
        )
        self.crypt_layer_required = bool(crypt_layer_required)
        # Live-test gate (roadmap 11s): every OP_QUEUERANK seen during
        # transfer() is reported here as {"host", "port", "rank", "at"} so
        # the kernel download box can prove "dial + QUEUERANK" happened.
        self.rank_sink = rank_sink
        # Token-bucket throttle state (download_bytes_per_sec > 0 enables;
        # <= 0 / unlimited is a no-op in _throttle_gate).  Bucket capacity
        # = max(rate, 64 KiB) so a tiny cap still absorbs a full block write.
        self._throttle_tokens: float = float(
            max(self.download_bytes_per_sec, 64 * 1024)
        )
        self._throttle_ts: float = 0.0
        # Serializes block writes through the token-bucket gate so concurrent
        # ensure_future-throttled writes drain sequentially.
        self._throttle_lock: asyncio.Lock | None = None
        # ICS requested-ranges registry (PartFile.cpp requestedblocks_list,
        # recon ics-endgame.recon.md section 6): file_hash bytes -> set of
        # inclusive (start, end) byte ranges currently in flight across all
        # peer sessions.  Prevents duplicate block requests between peers.
        self._requested_ranges: dict[bytes, set[tuple[int, int]]] = {}
        # Live ICS clients per file: used by _part_frequencies to aggregate
        # peer part-status into global per-part source counts.
        self._ics_clients: dict[bytes, list[Any]] = {}
        # A4AF/NNS verdict registry (DownloadClient.cpp:2171 SwapToAnotherFile,
        # PartFile.cpp:3353-3370 Process NNS pass).  Keyed by (host, port);
        # value maps file_hash_hex -> "nns" (peer has none of our gap parts)
        # or "needed" (peer can serve at least one gap part).  An "nns"
        # verdict in resolve_sources prevents re-dialing the endpoint for
        # this file, though the source stays available for OTHER files.
        self._a4af_verdicts: dict[tuple[str, int], dict[str, str]] = {}

    def _emit_rank(self, host: str, port: int, rank: int) -> None:
        if self.rank_sink is None:
            return
        record = {
            "host": host,
            "port": int(port),
            "rank": int(rank),
            "at": time.time(),
        }
        try:
            self.rank_sink(record)
        except Exception as exc:
            log.warning(
                "DOWNLOAD rank_sink fallback: endpoint=%s:%d, error=%r",
                host, port, exc,
            )

    def _a4af_verdict(self, host: str, port: int, file_hash_hex: str) -> str | None:
        """Return the cached A4AF verdict for (host, port) + file, or None."""
        return self._a4af_verdicts.get((host, port), {}).get(file_hash_hex)

    def _a4af_needed_parts(
        self,
        file_hash_hex: str,
        file_hash_bytes: bytes,
        client: Any,
        size: int,
    ) -> bool | None:
        """A4AF gate predicate (DS_NONEEDEDPARTS check).

        Returns True when the peer can serve at least one part we still
        need (gap part present in the peer's part_status); False when the
        peer has none of our gap parts (eMule DS_NONEEDEDPARTS — the peer
        said it has nothing we want); None when the peer's part-status is
        unknown so no gating decision can be made (proceed as before).

        Gap parts are derived from self.queue.gap_ranges (exclusive-end
        (start, end) tuples) via part-index = byte_offset // PART_SIZE
        (PartFile.cpp block-status / chunk_count semantics; recon
        a4af-downloadclient.recon.md:2171, a4af-partfile.recon.md:3353).
        """
        gaps = self.queue.gap_ranges(file_hash_hex)
        if not gaps:
            # No gaps: the file is complete (or nothing is needed) — do not
            # gate (return True so existing full-file tests proceed).
            return True
        # Peer has every part (chunk_count == 0 / complete source).
        if file_hash_bytes in getattr(client, "complete_sources", set()):
            return True
        available = getattr(client, "part_status", {}).get(file_hash_bytes)
        if available is None:
            # Unknown part-status: probe anyway.
            return None
        gap_parts: set[int] = set()
        for start, end in gaps:
            gap_parts.add(start // _ICS_PART_SIZE)
            if end > start:
                gap_parts.add((end - 1) // _ICS_PART_SIZE)
        return bool(gap_parts & available)

    def _register_ranges(self, file_hash: bytes, ranges) -> None:
        """Add inclusive (start, end) ranges to the in-flight registry."""
        bucket = self._requested_ranges.setdefault(file_hash, set())
        for start, end in ranges:
            bucket.add((start, end))

    def _release_ranges(self, file_hash: bytes, ranges) -> None:
        """Discard each range; drop the dict entry when empty."""
        bucket = self._requested_ranges.get(file_hash)
        if bucket is None:
            return
        for start, end in ranges:
            bucket.discard((start, end))
        if not bucket:
            self._requested_ranges.pop(file_hash, None)

    # ---------------------------------------------------------------------------
    # Download throttle (token bucket).  When download_bytes_per_sec <= 0 the
    # gate is a no-op — there is a single fast attribute check, no awaitable
    # overhead.  Capacity = max(rate, 64 KiB); each allowed byte consumes a
    # token, refilled at the configured rate since the last gate call.
    # (eMule DownloadThrottle / CKademilaSocket::DownloadLimit analog.)
    # ---------------------------------------------------------------------------
    async def _throttle_gate(self, nbytes: int) -> None:
        """Gate a write of ``nbytes`` through the token bucket."""
        rate = self.download_bytes_per_sec
        if rate <= 0:
            return
        if self._throttle_lock is None:
            self._throttle_lock = asyncio.Lock()
        async with self._throttle_lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._throttle_ts
            self._throttle_ts = now
            capacity = float(max(rate, 64 * 1024))
            self._throttle_tokens = min(
                capacity, self._throttle_tokens + rate * elapsed
            )
            if self._throttle_tokens < nbytes:
                deficit = nbytes - self._throttle_tokens
                self._throttle_tokens = 0.0
                await asyncio.sleep(deficit / rate)
            else:
                self._throttle_tokens -= nbytes

    def _persist_block(
        self, file_hash: str, start: int, data: bytes, _unused: bytes
    ) -> None:
        """Sync write_block callback: throttle-gate the block when a rate
        limit is configured, then persist it to the queue part file.

        client.transfer invokes write_block synchronously (no await), so the
        throttle gate is scheduled via ``asyncio.ensure_future`` when throttling
        is active.  When the limit is unlimited (<= 0) this is a straight
        delegation — no coroutine, no awaitable overhead."""
        if self.download_bytes_per_sec <= 0:
            self.queue.record_block(file_hash, start, data)
            return
        try:
            asyncio.ensure_future(self._write_block_throttled(file_hash, start, data))
        except RuntimeError:
            # No running loop is fatal — fall back to an unthrottled write
            # so the block is never lost (project fallback-logging policy).
            log.warning(
                "DOWNLOAD runner fallback: no running loop for throttle "
                "gate, writing block unthrottled: hash=%s",
                file_hash,
            )
            self.queue.record_block(file_hash, start, data)

    async def _write_block_throttled(
        self, file_hash: str, start: int, data: bytes
    ) -> None:
        """Await the throttle gate, then persist the block."""
        await self._throttle_gate(len(data))
        self.queue.record_block(file_hash, start, data)

    def _part_frequencies(
        self, file_hash: bytes, clients: Sequence, total_size: int
    ) -> list[int]:
        """Per-part source frequency m_SrcPartFrequency (recon
        ics-endgame.recon.md section 5, PartFile.cpp:3644-3677).

        For each live client with the file in client.part_status, add 1 to
        frequencies[i] for each i in part_status[hash].  Clients with the hash
        in ``complete_sources`` count as having ALL parts (range(part_count)).
        Clients with no status info at all are treated as complete sources too:
        unknown -> assume available (per ics-filestatus-client.recon.md Mode A:
        chunk_count == 0 means the peer has every part).  Length =
        part_count(total_size).
        """
        from amuled_v2.core.download.ics import part_count

        n = part_count(total_size)
        frequencies = [0] * n
        all_parts = frozenset(range(n))
        for client in clients:
            if client is None:
                continue
            complete = getattr(client, "complete_sources", None)
            if complete and file_hash in complete:
                parts = all_parts
            else:
                parts = getattr(client, "part_status", {}).get(file_hash)
                if parts is None:
                    parts = all_parts
            for i in parts:
                if 0 <= i < n:
                    frequencies[i] += 1
        return frequencies

    def resolve_sources(
        self, file_hash: str, *, limit: int | None = None
    ) -> list[dict[str, Any]]:
        """Dialable endpoints for a hash.

        Each endpoint dict: ``host, port, user_hash (bytes|None),
        source_type (str), kad_udp_port (int|None)``.  KAD firewalled types
        3/5 are skipped (need a serving-buddy callback); type 6 is returned
        with ``source_type='kad6'`` for the direct-callback flow.
        """
        if limit is None:
            limit = self.max_sources_per_file
        if self.source_provider is not None:
            rows = self.source_provider(file_hash, limit)
        else:
            rows = self.queue.state.list_file_sources(file_hash, limit=limit)
        seen: set[tuple[str, int]] = set()
        endpoints: list[dict[str, Any]] = []
        skipped = 0
        nns_dropped = 0
        own_ips = _local_ip_set()
        own_userhash: bytes | None = None
        if self.callback_identity:
            raw_own = self.callback_identity.get("user_hash")
            if raw_own:
                own_userhash = bytes(raw_own)
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
            # Self-record filter (roadmap 11o addendum 4): a record can
            # carry our own address/userhash after NAT reflection or
            # self-publication — rendezvous with ourselves never works.
            record_ipv6 = row.get("ipv6")
            if (
                self.self_record_filter
                and record_ipv6
                and record_ipv6 in own_ips
            ):
                log.debug(
                    "DOWNLOAD self-record skipped (ipv6): source=%s:%d",
                    _client_id_to_ip(client_id), row["client_port"],
                )
                skipped += 1
                continue
            if user_hash is not None and user_hash == own_userhash:
                log.debug(
                    "DOWNLOAD self-record skipped (userhash): source=%s:%d",
                    _client_id_to_ip(client_id), row["client_port"],
                )
                skipped += 1
                continue
            endpoint = (_client_id_to_ip(client_id), row["client_port"])
            if endpoint in seen:
                continue
            # A4AF / NNS filter: drop endpoints whose (host, port) carries
            # a known "nns" verdict for this file — the peer was already
            # proven useless (DS_NONEEDEDPARTS) and will not yield data, but
            # the source remains available for OTHER files.  (recon
            # a4af-downloadqueue.recon.md:1200 AddAlreadyKnownSourceAsA4AF
            # keeps the source on the other file's list.)
            if self._a4af_verdict(endpoint[0], endpoint[1], file_hash) == "nns":
                nns_dropped += 1
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
                    # Optional IPv6 endpoints (eMuleAI "ip6"/"bi6" tags);
                    # an ipv6 target drives the rendezvous direct-punch
                    # variant (endpoint hints are IPv4-only).
                    "ipv6": row.get("ipv6"),
                    "buddy_ipv6": row.get("buddy_ipv6"),
                }
            )
        if skipped:
            log.debug(
                "DOWNLOAD skipped undialable sources: hash=%s, skipped=%d",
                file_hash,
                skipped,
            )
        if nns_dropped:
            log.debug(
                "DOWNLOAD A4AF NNS endpoints dropped: hash=%s, dropped=%d",
                file_hash,
                nns_dropped,
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
        log.info(
            "DOWNLOAD peer attempt start: endpoint=%s:%d, source_type=%s, "
            "has_userhash=%s",
            host,
            port,
            source_type or "direct",
            user_hash is not None,
        )
        outcome: "DownloadOutcome | None" = None
        client = None
        closers: list[Callable[[], Any]] = []
        try:
            from amuled_v2.core.peer.client import (
                PeerClient,
                PeerSessionError,
            )

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
                    # Stable HELLO identity (live evidence 2026-09-28:
                    # eMuleAI bans "Userhash changed" via TrackedClientsList
                    # when a peer presents a different userhash per
                    # connection — os.urandom(16) per PeerClient is a ban).
                    # The runner's callback_identity carries the same
                    # persistent identity the KAD spider publishes.
                    local_userhash=(
                        _coerce_userhash(self.callback_identity.get("user_hash"))
                        if self.callback_identity
                        else None
                    ),
                )
                from amuled_v2.core.peer.client import PeerSessionError

                try:
                    await client.connect()
                except PeerSessionError as exc:
                    # Obfuscated dial fallback (eMule DownloadQueue.cpp
                    # behaviour: obfuscate only when the key is known,
                    # else dial plain - a KAD-published userhash does not
                    # always match the peer's real GetUserHash, and such
                    # peers silently ignore wrong magic; live 2026-09-28:
                    # fresh kad1 sources all timed out at the BASIC
                    # handshake while accepting TCP).
                    if (
                        user_hash is None
                        or "BASIC handshake" not in str(exc)
                        or not self.plain_dial_ok
                        or self.crypt_layer_required
                    ):
                        raise
                    log.warning(
                        "DOWNLOAD obf dial fallback: peer=%s:%d ignored the "
                        "obfuscated handshake, retrying plain (peer likely "
                        "accepts unobfuscated): error=%s",
                        host,
                        port,
                        exc,
                    )
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
                        target_userhash=None,
                        secure_ident=self.secure_ident,
                        plain_dial_ok=True,
                        local_userhash=(
                            _coerce_userhash(
                                self.callback_identity.get("user_hash")
                            )
                            if self.callback_identity
                            else None
                        ),
                    )
                    await client.connect()
                    if self.crypt_layer_required:
                        log.warning(
                            "DOWNLOAD crypt layer required but peer dialed "
                            "plain: peer=%s:%d",
                            host, port,
                        )
            await client.handshake()
            hashset = await client.request_file(file_hash_bytes)
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

            # ------------------------------------------------------------------
            # A4AF / DS_NONEEDEDPARTS gate (DownloadClient.cpp:2171
            # SwapToAnotherFile; PartFile.cpp:3353-3370 Process NNS pass).
            # After the upload-slot wait and before building the ICS selector,
            # decide whether the peer can serve any part we still need.  A peer
            # with no matching parts is skipped (recorded "nns") so its slice
            # is reassigned to others; the source stays eligible for OTHER
            # files.  Unknown part-status -> proceed unchanged.
            # ------------------------------------------------------------------
            verdict = self._a4af_needed_parts(
                file_hash, file_hash_bytes, client, size
            )
            if verdict is False:
                self._a4af_verdicts.setdefault((host, port), {})[
                    file_hash
                ] = "nns"
                log.debug(
                    "DOWNLOAD A4AF NNS skip: hash=%s, peer=%s:%d, "
                    "no gap parts available",
                    file_hash, host, port,
                )
                close_client = getattr(client, "close", None)
                if close_client is not None:
                    try:
                        await close_client()
                    except Exception as exc:
                        log.debug(
                            "runner fallback: best-effort client close "
                            "failed on A4AF NNS skip: %s", exc,
                        )
                return {
                    "file_hash": file_hash,
                    "bytes_received": 0,
                    "blocks_received": 0,
                    "complete": False,
                    "elapsed": 0.0,
                    "detail": "a4af-nns: peer has no needed parts",
                }
            elif verdict is True:
                self._a4af_verdicts.setdefault((host, port), {})[
                    file_hash
                ] = "needed"

            # ICS (Intelligent Chunk Selection): when the file is multi-part
            # (size > PART_SIZE) or has multiple gaps, delegate block selection
            # to the ICS algorithm instead of the linear stripe.  Single-part /
            # single-gap files keep the old linear behaviour.
            block_selector: Callable[[int], list[tuple[int, int]]] | None = None
            release_ranges: Callable[[list[tuple[int, int]]], None] | None = None
            ics_active = (
                size > _ICS_PART_SIZE
                or len(self.queue.gap_ranges(file_hash)) > 1
            )
            if ics_active:
                try:
                    clients = self._ics_clients.setdefault(file_hash_bytes, [])
                    clients.append(client)

                    # Per-peer sticky state (eMule m_lastPartAsked per source,
                    # PartFile.cpp:7490-7494): persists across selector calls
                    # within one peer session.
                    last_part_box: list[int | None] = [None]
                    # Ranges this closure itself issued — excluded from the
                    # "other in-flight" count so a peer does not penalise
                    # itself.
                    own_issued: set[tuple[int, int]] = set()

                    def _selector(n: int) -> list[tuple[int, int]]:
                        from amuled_v2.core.download import ics

                        # Convert exclusive-end gaps from queue.gap_ranges
                        # to inclusive (start, end-1) for the ICS module.
                        raw_gaps = self.queue.gap_ranges(file_hash)
                        gaps = [(s, e - 1) for s, e in raw_gaps if e > s]
                        frequencies = self._part_frequencies(
                            file_hash_bytes, clients, size
                        )
                        # downloading_counts: per part p, count of OTHER
                        # in-flight ranges overlapping part p, excluding the
                        # ranges this selector registered itself.
                        downloading: dict[int, int] = {}
                        for start, end in self._requested_ranges.get(
                            file_hash_bytes, set()
                        ):
                            if (start, end) in own_issued:
                                continue
                            p_lo = start // ics.PART_SIZE
                            p_hi = end // ics.PART_SIZE
                            for p in range(p_lo, p_hi + 1):
                                downloading[p] = downloading.get(p, 0) + 1

                        # available: parts the peer has (or all if unknown).
                        if file_hash_bytes in client.complete_sources:
                            available = frozenset(range(ics.part_count(size)))
                        else:
                            available = client.part_status.get(
                                file_hash_bytes
                            ) or frozenset()
                            if not available:
                                available = frozenset(range(ics.part_count(size)))

                        # gap_parts / gap_sizes (per-part remaining bytes).
                        gap_parts: list[int] = []
                        gap_sizes: dict[int, int] = {}
                        for p in range(ics.part_count(size)):
                            ps, pe = ics.part_bounds(p, size)
                            part_gap = 0
                            for g_start, g_end in gaps:
                                ov_start = max(g_start, ps)
                                ov_end = min(g_end, pe)
                                if ov_end >= ov_start:
                                    part_gap += ov_end - ov_start + 1
                            if part_gap > 0:
                                gap_parts.append(p)
                                gap_sizes[p] = part_gap

                        ranges, last_new = ics.select_blocks(
                            total_size=size,
                            gaps=gaps,
                            available=available,
                            frequencies=frequencies,
                            downloading_counts=downloading,
                            last_part=last_part_box[0],
                            requested=self._requested_ranges.get(
                                file_hash_bytes, set()
                            ),
                            max_blocks=n,
                        )
                        if ranges:
                            own_issued.update(ranges)
                            self._register_ranges(file_hash_bytes, ranges)
                            last_part_box[0] = last_new
                        return ranges

                    def _release(ranges: list[tuple[int, int]]) -> None:
                        for r in ranges:
                            own_issued.discard(r)
                        self._release_ranges(file_hash_bytes, ranges)

                    block_selector = _selector
                    release_ranges = _release

                    # ICS uses the full file range; the selector picks only
                    # from genuine gaps so start/end_offset are left at 0/None.
                    transfer_start = 0
                    transfer_end = None
                    log.debug(
                        "DOWNLOAD ICS selector armed: hash=%s, size=%d, "
                        "peers=%d",
                        file_hash, size, len(clients),
                    )
                except Exception as exc:
                    log.warning(
                        "DOWNLOAD ICS selector build failed, falling back to "
                        "stripe: hash=%s, error=%s",
                        file_hash, exc,
                    )
                    block_selector = None
                    release_ranges = None
                    transfer_start = start_offset
                    transfer_end = end_offset
            else:
                transfer_start = start_offset
                transfer_end = end_offset

            outcome = await client.transfer(
                file_hash_bytes,
                size,
                write_block=lambda start, data: self._persist_block(
                    file_hash, start, data, file_hash_bytes
                ),
                progress_callback=progress_callback,
                start_offset=transfer_start,
                end_offset=transfer_end,
                block_selector=block_selector,
                release_ranges=release_ranges,
                rank_callback=(
                    (lambda rank, _h=host, _p=port: self._emit_rank(_h, _p, rank))
                    if self.rank_sink is not None
                    else None
                ),
            )
            if (
                outcome.complete
                and hashset is not None
                and transfer_start == 0
                and (transfer_end is None or transfer_end >= size)
            ):
                # Corrupt-part salvage (stage X; PartFile.cpp
                # HashSinglePart:4399-4474, FlushBuffer:5793-5804): verify
                # each PART's MD4 against the peer's hashset; punch corrupt
                # parts as gaps so the rounds loop refetches them.  Only
                # for full-file regions (partial regions have incomplete
                # parts whose MD4 is meaningless).
                try:
                    corrupt = self._verify_parts_against_hashset(
                        file_hash, file_hash_bytes, size, hashset
                    )
                except Exception as exc:
                    corrupt = []
                    log.debug(
                        "DOWNLOAD part verification skipped: hash=%s, "
                        "error=%s",
                        file_hash, exc,
                    )
                if corrupt:
                    ranges = await self._aich_narrow_corrupt(
                        client, file_hash_bytes, size, corrupt, hashset
                    )
                    self.queue.punch_gaps(file_hash, ranges)
                    outcome.complete = False
                    outcome.detail = f"corrupt ranges punched: {ranges}"
                    log.warning(
                        "DOWNLOAD corrupt ranges punched: hash=%s, %s",
                        file_hash, ranges,
                    )
            if outcome.complete and transfer_start == 0 and self.aich_audit:
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
                except Exception as exc:
                    log.debug(
                        "runner fallback: failed to persist collected "
                        "sources for peer teardown: %s", exc,
                    )
                await client.close()
                # Unregister this peer from the ICS live-client list so
                # _part_frequencies stops counting it.
                ics_clients = self._ics_clients.get(file_hash_bytes)
                if ics_clients is not None:
                    try:
                        ics_clients.remove(client)
                    except ValueError:
                        pass
                    if not ics_clients:
                        self._ics_clients.pop(file_hash_bytes, None)
                # Ranges this peer registered are released by the transfer's
                # release_ranges callback (called in client.transfer's own
                # finally); nothing extra to clean here.
            for closer in closers:
                try:
                    closer()
                except Exception as exc:
                    log.debug(
                        "runner fallback: one-shot closer failed on "
                        "peer teardown: %s", exc,
                    )

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

    async def _aich_narrow_corrupt(
        self,
        client: Any,
        file_hash_bytes: bytes,
        size: int,
        corrupt_parts: list[tuple[int, int]],
        hashset: Any,
    ) -> list[tuple[int, int]]:
        """Narrow corrupt PART ranges down to corrupt 180 KB blocks via
        the AICH recovery data (PartFile.cpp AICHRecoveryDataAvailable
        :7108-7221).  Falls back to whole-part punches when no trusted
        master is stored or the blob does not authenticate.
        """
        from amuled_v2.core.codec.constants import (
            BLOCKSIZE,
            PARTSIZE,
        )
        from amuled_v2.core.hashes.aich import (
            AichError,
            aich_hash_data,
            aich_verified_part_blocks,
        )

        ranges: list[tuple[int, int]] = []
        entry = self.queue.get(file_hash_bytes.hex())
        if entry is None:
            return corrupt_parts
        stored = self.queue.state.get_aich_master(file_hash_bytes.hex())
        part_path = str(entry["part_path"])
        for part_start, _part_end in corrupt_parts:
            part_index = part_start // PARTSIZE
            part_size = min(PARTSIZE, size - part_start)
            narrowed = False
            if stored is not None:
                try:
                    with open(part_path, "rb") as handle:
                        handle.seek(part_start)
                        part_data = handle.read(part_size)
                    recovery = None
                    try:
                        _h, _p, _m, recovery = await client.request_aich(
                            file_hash_bytes, part_index, bytes(stored)
                        )
                    except Exception as exc:
                        log.debug(
                            "DOWNLOAD AICH request failed: part=%d, "
                            "error=%s",
                            part_index, exc,
                        )
                    if recovery:
                        verified = aich_verified_part_blocks(
                            recovery, part_index, size, bytes(stored)
                        )
                        ours = aich_hash_data(part_data).block_hashes
                        for block_index, (ours_h, verified_h) in enumerate(
                            zip(ours, verified)
                        ):
                            if ours_h != verified_h:
                                block_start = part_start + block_index * BLOCKSIZE
                                block_end = min(
                                    block_start + BLOCKSIZE,
                                    part_start + part_size,
                                )
                                ranges.append((block_start, block_end))
                        narrowed = bool(ranges)
                except AichError as exc:
                    log.debug(
                        "DOWNLOAD AICH narrowing failed: part=%d, error=%s",
                        part_index, exc,
                    )
            if not narrowed:
                ranges.append((part_start, part_start + part_size))
        return ranges

    def _verify_parts_against_hashset(
        self,
        file_hash: str,
        file_hash_bytes: bytes,
        size: int,
        hashset: Any,
    ) -> list[tuple[int, int]]:
        """Verify every PART's MD4 on disk against the peer's hashset
        (PartFile.cpp HashSinglePart:4399-4474, MD4 branch).

        chunk_hashes[0] is the file hash, the rest are part hashes.
        Returns the corrupt part ranges [start, end) — empty when all
        parts verify or the hashset does not cover the part count.
        """
        from Crypto.Hash import MD4 as _MD4

        from amuled_v2.core.codec.constants import PARTSIZE

        parts = (size + PARTSIZE - 1) // PARTSIZE
        expected = list(hashset.chunk_hashes[1:])
        if not expected and parts == 1 and hashset.chunk_hashes:
            # Single-part files: the part hash IS the file hash (eD2K
            # convention; eMuleAI sends [file hash][count] for them).
            expected = [hashset.chunk_hashes[0]]
        log.debug(
            "DOWNLOAD hashset dump: hash=%s, parts=%d, chunks=%s",
            file_hash, parts, hashset.to_dict(),
        )
        if len(expected) != parts:
            log.debug(
                "DOWNLOAD hashset part count mismatch: hash=%s, "
                "expected=%d, got=%d",
                file_hash, parts, len(expected),
            )
            return []
        entry = self.queue.get(file_hash)
        if entry is None:
            return []
        part_path = str(entry["part_path"])
        corrupt: list[tuple[int, int]] = []
        with open(part_path, "rb") as handle:
            for index in range(parts):
                handle.seek(index * PARTSIZE)
                data = handle.read(
                    min(PARTSIZE, size - index * PARTSIZE)
                )
                digest = _MD4.new(data).digest()
                if digest != expected[index]:
                    start = index * PARTSIZE
                    corrupt.append((start, start + len(data)))
        return corrupt

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
        ipv6_target = endpoint.get("ipv6")
        kad_udp_port = int(endpoint.get("kad_udp_port") or 0)
        session = NattUdpSession(bytes(ident["user_hash"]))
        # Loopback buddy (loopback tests): keep the 0.0.0.0 bind - the
        # NIC-egress pin cannot send to 127.0.0.1 (WinError 1214; live
        # 2026-09-28 suite regression).
        import ipaddress

        try:
            _loopback_buddy = ipaddress.ip_address(buddy_ip).is_loopback
        except ValueError:
            _loopback_buddy = False
        await session.start(host="127.0.0.1" if _loopback_buddy else "0.0.0.0")
        if ipv6_target:
            # IPv6 target (eMuleAI "ip6" tag): dual-stack session and the
            # direct-punch rendezvous variant — endpoint hints are
            # IPv4-only (ClientUDPSocket.cpp:1276).
            await session.start6()
        try:
            stream = await session.rendezvous_connect(
                buddy_host=buddy_ip,
                buddy_port=buddy_port,
                buddy_id=buddy_id,
                target_user_hash=bytes(target_hash),
                file_hash=file_hash_bytes,
                our_ext_ip=int(ident.get("ext_ip") or 0),
                target_addr=(
                    ipv6_target if ipv6_target else endpoint["host"],
                    kad_udp_port,
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

        attempts: list[dict] = []
        max_rounds = 3
        active = list(enumerate(endpoints))
        for round_no in range(max_rounds):
            refreshed = self.queue.get(file_hash)
            if refreshed is not None and refreshed["status"] == "complete":
                break
            if not active:
                break
            # Round 1 covers the whole file; later rounds re-stripe only
            # the CURRENT holes (stalled-peer reassignment): each round's
            # regions are rebuilt from the live gap list, so a peer that
            # died mid-region gets its bytes reassigned to the survivors.
            gaps = (
                [(0, size)]
                if round_no == 0
                else self.queue.gap_ranges(file_hash)
            )
            if not gaps:
                break
            regions = _regions_from_gaps(gaps, len(active))
            log.info(
                "DOWNLOAD race start: hash=%s, round=%d, peers=%d, "
                "gaps=%d, covered=%d",
                file_hash, round_no + 1, len(active), len(gaps),
                sum(e - s for s, e in regions),
            )

            tasks = {
                asyncio.create_task(
                    self._attempt_peer(
                        endpoint,
                        file_hash,
                        size,
                        file_hash_bytes,
                        progress_callback,
                        start_offset=start,
                        end_offset=end,
                    ),
                    name=(
                        f"dl-peer-{endpoint['host']}:{endpoint['port']}"
                        f"-r{round_no}"
                    ),
                ): index
                for (index, endpoint), (start, end) in zip(active, regions)
                if end > start
            }
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
                            await asyncio.gather(
                                *pending, return_exceptions=True
                            )
                        finalized = self.queue.finalize(
                            file_hash, verify=verify
                        )
                        winner = next(
                            (a for a in attempts if a.get("complete")),
                            attempts[-1] if attempts else {},
                        )
                        log.info(
                            "DOWNLOAD race won: hash=%s, rounds=%d",
                            file_hash, round_no + 1,
                        )
                        return {
                            "status": "complete",
                            "outcome": winner,
                            "finalized": finalized,
                        }
                # Peers that delivered nothing this round are dead for
                # this run — their slice is reassigned to the survivors.
                survivors = []
                for index, endpoint in active:
                    task = next(
                        (t for t, i in tasks.items() if i == index), None
                    )
                    res = (
                        task.result()
                        if task is not None
                        and task.done()
                        and not task.cancelled()
                        else None
                    )
                    if (
                        isinstance(res, dict)
                        and res.get("bytes_received", 0) == 0
                        and not res.get("complete")
                    ):
                        continue
                    survivors.append((index, endpoint))
                active = survivors
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
