"""Minimal BitTorrent uTP (BEP 29) over asyncio UDP — NAT-T transport.

eMuleAI NAT-T carries the eD2K session over standard uTP (libutp) wrapped
in OP_UDPRESERVEDPROT2 / OP_NATT_FRAME_UTP frames on the client UDP socket.
This module implements just enough of BEP 29 for one reliable ordered
stream per (remote endpoint, connection id):

  header (20 bytes, big-endian):
    [type<<4 | version=1][extension=0][connection_id u16]
    [timestamp_micro u32][timestamp_diff u32][window_size u32]
    [seq_nr u16][ack_nr u16]
  types: ST_DATA=0 ST_FIN=1 ST_STATE=2 ST_RESET=3 ST_SYN=4

Reliability: cumulative acks + per-packet retransmit timer (0.6 s, 40
tries), in-order reassembly with a small reorder buffer, FIN half-close,
flow control via a large static advertised window (scale is modest).

src/amuled_v2/core/natt/utp.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-27

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Minimal BEP 29 uTP stream over an asyncio datagram transport.
"""

from __future__ import annotations

import asyncio
import os
import struct
import time

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.PEER, "core.natt.utp")

__all__ = ["UtpStream", "UtpError"]

UTP_VERSION = 1
ST_DATA = 0
ST_FIN = 1
ST_STATE = 2
ST_RESET = 3
ST_SYN = 4

_HEADER = struct.Struct(">BBHIIIHH")
_HEADER_LEN = _HEADER.size  # 20
_RETRANSMIT_INTERVAL = 0.6
_MAX_RETRIES = 40
_WINDOW = 1 << 20


class UtpError(Exception):
    pass


class UtpStream:
    """One reliable ordered byte stream to a fixed remote UDP endpoint.

    ``send_frame`` is the wire callback (async, (bytes, addr) -> None) —
    the NAT-T layer supplies it so the stream never sees UDP specifics.
    ``accept`` builds the responder side from an inbound SYN.
    """

    def __init__(
        self,
        send_frame,
        remote_addr,
        *,
        conn_id_recv: int | None = None,
        conn_id_send: int | None = None,
        initiator: bool,
    ) -> None:
        self._send_frame = send_frame
        self.remote_addr = remote_addr
        if initiator:
            # BEP 29: SYN carries the initiator's SEND id; incoming = +1.
            self.conn_id_send = (conn_id_recv or 0) or (
                int.from_bytes(os.urandom(2), "big") or 1
            )
            self.conn_id_recv = (self.conn_id_send + 1) & 0xFFFF
        else:
            # acceptor: SYN carries the initiator's SEND id (BEP 29: our
            # incoming id = SYN id + 1, our outgoing id = SYN id)
            self.conn_id_recv = (conn_id_recv or 0) & 0xFFFF
            self.conn_id_send = ((conn_id_recv or 0) + 1) & 0xFFFF
        self.seq_nr = 1
        self.ack_nr = 0
        self._sent: dict[int, tuple[float, bytes]] = {}  # seq -> (sent_at, data)
        self._reorder: dict[int, bytes] = {}
        self._fin_seq: int | None = None
        self._fin_received = False
        self._closed = False
        self._connected_evt = asyncio.Event()
        self._incoming: asyncio.Queue[bytes] = asyncio.Queue()
        self._eof_evt = asyncio.Event()
        self._retransmit_task: asyncio.Task | None = None

    # -- wire ---------------------------------------------------------------

    def _header(self, ptype: int, conn_id: int, seq: int, ack: int) -> bytes:
        now_us = int(time.time() * 1_000_000) & 0xFFFFFFFF
        return _HEADER.pack(
            (ptype << 4) | UTP_VERSION,
            0,
            conn_id & 0xFFFF,
            now_us,
            0,
            _WINDOW,
            seq & 0xFFFF,
            ack & 0xFFFF,
        )

    async def _send_packet(self, ptype: int, seq: int, ack: int, payload: bytes = b"") -> None:
        conn = self.conn_id_send if ptype != ST_STATE else self.conn_id_send
        await self._send_frame(self._header(ptype, conn, seq, ack) + payload, self.remote_addr)

    async def _send_ack(self) -> None:
        await self._send_packet(ST_STATE, self.seq_nr, self.ack_nr)

    def _on_wire_packet(self, packet: bytes) -> None:
        """Feed one raw uTP packet (already demultiplexed by conn id)."""
        if len(packet) < _HEADER_LEN or self._closed:
            return
        ptype = packet[0] >> 4
        version = packet[0] & 0x0F
        if version != UTP_VERSION:
            return
        seq_nr, ack_nr = struct.unpack_from(">HH", packet, 16)
        payload = packet[_HEADER_LEN:]

        # Process their acknowledgement of our packets first.
        if ptype in (ST_STATE, ST_DATA, ST_FIN):
            for seq in [s for s in self._sent if s <= ack_nr]:
                self._sent.pop(seq, None)

        if ptype == ST_RESET:
            self._fail(UtpError("connection reset by peer"))
            return

        if ptype == ST_SYN:
            return  # duplicates of the SYN are ignored on the acceptor side

        if ptype == ST_STATE:
            if not self._connected_evt.is_set():
                self._connected_evt.set()
            return

        # ST_DATA / ST_FIN carry seq_nr data
        if seq_nr == self.ack_nr + 1:
            if payload:
                self._incoming.put_nowait(payload)
            self.ack_nr = seq_nr
            # drain reorder buffer
            while True:
                nxt = self.ack_nr + 1
                if nxt in self._reorder:
                    chunk = self._reorder.pop(nxt)
                    if chunk:
                        self._incoming.put_nowait(chunk)
                    self.ack_nr = nxt
                else:
                    break
            if ptype == ST_FIN:
                self._fin_received = True
                self._eof_evt.set()
        elif seq_nr > self.ack_nr + 1:
            self._reorder.setdefault(seq_nr, payload)
        # seq_nr <= ack_nr: duplicate, ignore

        if ptype == ST_FIN and seq_nr <= self.ack_nr:
            self._fin_received = True
            self._eof_evt.set()
        self._schedule_ack()

    def _schedule_ack(self) -> None:
        asyncio.get_running_loop().create_task(self._send_ack())

    # -- lifecycle ----------------------------------------------------------

    async def connect(self) -> None:
        """Initiator: send SYN and wait for the first ST_STATE."""
        self._retransmit_task = asyncio.get_running_loop().create_task(
            self._retransmit_loop()
        )
        await self._send_packet(ST_SYN, self.seq_nr, self.ack_nr)
        self._sent[self.seq_nr] = (time.time(), b"SYN")
        await asyncio.wait_for(self._connected_evt.wait(), 15.0)
        self.seq_nr = (self.seq_nr + 1) & 0xFFFF
        log.debug("uTP connected: endpoint=%s", self.remote_addr)

    @classmethod
    async def accept(
        cls,
        send_frame,
        remote_addr,
        syn_packet: bytes,
    ) -> "UtpStream":
        """Acceptor: derive ids from the inbound SYN and ack it."""
        if len(syn_packet) < _HEADER_LEN:
            raise UtpError("short SYN")
        (syn_conn,) = struct.unpack_from(">H", syn_packet, 2)
        stream = cls(
            send_frame,
            remote_addr,
            conn_id_recv=syn_conn,
            initiator=False,
        )
        stream.ack_nr = struct.unpack_from(">H", syn_packet, 16)[0]
        stream._retransmit_task = asyncio.get_running_loop().create_task(
            stream._retransmit_loop()
        )
        await stream._send_ack()
        stream._connected_evt.set()
        log.debug("uTP accepted: endpoint=%s", remote_addr)
        return stream

    # -- stream API ---------------------------------------------------------

    async def send(self, data: bytes) -> None:
        if self._closed:
            raise UtpError("stream closed")
        # one uTP packet per send; callers chunk (eD2K frames are small)
        await self._send_data_chunk(bytes(data))

    async def _send_data_chunk(self, chunk: bytes) -> None:
        seq = self.seq_nr
        self.seq_nr = (self.seq_nr + 1) & 0xFFFF
        await self._send_packet(ST_DATA, seq, self.ack_nr, chunk)
        self._sent[seq] = (time.time(), chunk)

    async def recv(self, n: int = 65536) -> bytes:
        if self._incoming.empty():
            if self._eof_evt.is_set():
                return b""
            eof_task = asyncio.get_running_loop().create_task(self._eof_evt.wait())
            get_task = asyncio.get_running_loop().create_task(self._incoming.get())
            try:
                done, _ = await asyncio.wait(
                    {eof_task, get_task}, return_when=asyncio.FIRST_COMPLETED
                )
                if eof_task in done and self._incoming.empty():
                    return b""
            finally:
                eof_task.cancel()
                if not get_task.done():
                    get_task.cancel()
        return await self._incoming.get()

    async def close(self) -> None:
        if self._closed:
            return
        try:
            fin_seq = self.seq_nr
            self.seq_nr = (self.seq_nr + 1) & 0xFFFF
            await self._send_packet(ST_FIN, fin_seq, self.ack_nr)
            self._sent[fin_seq] = (time.time(), b"FIN")
            await asyncio.sleep(0.2)  # give the FIN a moment
        except Exception:
            pass
        self._fail(None)

    def _fail(self, exc: Exception | None) -> None:
        self._closed = True
        self._eof_evt.set()
        if self._retransmit_task is not None:
            self._retransmit_task.cancel()

    # -- retransmission -----------------------------------------------------

    async def _retransmit_loop(self) -> None:
        try:
            while not self._closed:
                await asyncio.sleep(_RETRANSMIT_INTERVAL)
                now = time.time()
                for seq, (sent_at, data) in list(self._sent.items()):
                    if now - sent_at > _MAX_RETRIES * _RETRANSMIT_INTERVAL:
                        self._fail(UtpError(f"uTP send timeout on seq {seq}"))
                        return
                    if now - sent_at >= _RETRANSMIT_INTERVAL:
                        ptype = ST_FIN if data == b"FIN" else (
                            ST_SYN if data == b"SYN" else ST_DATA
                        )
                        await self._send_packet(
                            ptype,
                            seq,
                            self.ack_nr,
                            b"" if data in (b"FIN", b"SYN") else data,
                        )
                        self._sent[seq] = (now, data)
        except asyncio.CancelledError:
            pass

    # -- asyncio stream adapters (PeerClient bridge) -------------------------

    def reader(self) -> asyncio.StreamReader:
        reader = asyncio.StreamReader()
        feed = reader.feed_data

        async def _pump() -> None:
            while True:
                chunk = await self.recv()
                if not chunk:
                    break
                feed(chunk)
            reader.feed_eof()

        asyncio.get_running_loop().create_task(_pump())
        return reader

    def writer(self):
        stream = self

        class _UtpWriter:
            def write(self, data: bytes) -> None:
                asyncio.get_running_loop().create_task(stream.send(data))

            async def drain(self) -> None:
                await asyncio.sleep(0)

            def close(self) -> None:
                asyncio.get_running_loop().create_task(stream.close())

            async def wait_closed(self) -> None:
                await asyncio.sleep(0)

        return _UtpWriter()
