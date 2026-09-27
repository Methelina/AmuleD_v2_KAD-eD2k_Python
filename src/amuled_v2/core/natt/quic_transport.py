"""Standard IETF QUIC transport for eMuleAI-compatible NAT-T.

eMuleAI's NAT-T QUIC is real IETF QUIC (ngtcp2 + GnuTLS, TLS 1.3,
ALPN ``ed2k-ai-natt-quic-v1``, QUIC v1; NgTcp2GnuTlsBridge.cpp): the
downloader is the QUIC client, one bidirectional stream carries the eD2K
session, and the first 37 bytes of stream data in each direction are an
application proof:

    [5-byte magic "EAQN1"][16-byte sender userhash][16-byte peer userhash]

(peer userhash may be all-zero as a wildcard; eMuleAI
QuicNatSocket.cpp:619-650 / QuicNatConfig.h:12-14).

Datagrams ride on the shared client UDP socket wrapped in eMule
OP_UDPRESERVEDPROT2 / OP_NATT_FRAME_QUIC frames (ClientUDPSocket.cpp:
456-477), so aioquic's wire output is wrapped and inbound frames are
unwrapped before they reach the connection.

src/amuled_v2/core/natt/quic_transport.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-27

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] aioquic-based QUIC NAT-T stream: EAQN1 proof exchange, 0xB2/0x01
      wire wrapping, downloader-client / source-server roles.
"""

from __future__ import annotations

import asyncio
import ssl
import struct
import datetime
import time
from pathlib import Path

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    QuicEvent,
    StreamDataReceived,
)

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.PEER, "core.natt.quic")

__all__ = [
    "ALPN_NATT_QUIC",
    "PROOF_LEN",
    "NattQuicProtocol",
    "build_local_proof",
    "validate_remote_proof",
    "wrap_natt_frame",
    "unwrap_natt_frame",
]

ALPN_NATT_QUIC = "ed2k-ai-natt-quic-v1"  # QuicNatConfig.h:12
PROOF_MAGIC = b"EAQN1"  # QuicNatConfig.h:13
PROOF_LEN = 37  # QuicNatConfig.h:14 (5 + 16 + 16)

NATT_FRAME_QUIC = 0x01  # Opcodes.h:209
UDP_RESERVEDPROT2 = 0xB2  # Opcodes.h:207
UDP_PROTOCOL = 0xC5


def wrap_natt_frame(frame_opcode: int, payload: bytes) -> bytes:
    """[0xC5][len u32 LE incl. opcode][0xB2][frame_opcode][payload]."""
    body = bytes((UDP_RESERVEDPROT2, frame_opcode)) + payload
    return bytes((UDP_PROTOCOL,)) + struct.pack("<I", len(body) + 1) + body


def unwrap_natt_frame(datagram: bytes) -> tuple[int, bytes] | None:
    """Parse an inbound 0xB2 frame -> (frame_opcode, payload) or None."""
    if (
        len(datagram) < 8
        or datagram[0] != UDP_PROTOCOL
        or datagram[5] != UDP_RESERVEDPROT2
    ):
        return None
    (length,) = struct.unpack_from("<I", datagram, 1)
    body = datagram[6 : 5 + length]  # body[0] = frame opcode, body[1:] = payload
    if len(body) < 2:
        return None
    return body[0], body[1:]


def build_local_proof(our_user_hash: bytes, peer_user_hash: bytes | None) -> bytes:
    """QuicNatSocket.cpp:619-630: magic + our hash + peer hash (or zeros)."""
    peer = bytes(peer_user_hash) if peer_user_hash else b"\x00" * 16
    return PROOF_MAGIC + bytes(our_user_hash) + peer


def validate_remote_proof(
    proof: bytes, our_user_hash: bytes, peer_user_hash: bytes | None
) -> bool:
    """QuicNatSocket.cpp:632-650: magic + target-hash match (or zero)
    + sender-hash match when we know the peer (zero peer hash lenient)."""
    if len(proof) < PROOF_LEN or proof[:5] != PROOF_MAGIC:
        return False
    target = proof[21:37]
    if target != bytes(our_user_hash) and target != b"\x00" * 16:
        return False
    sender = proof[5:21]
    if peer_user_hash and sender != bytes(peer_user_hash):
        # eMuleAI tolerates a sender-hash mismatch only for trusted NAT-T
        # endpoints (HasDirectNatTraversalCaps); we mirror the lenient
        # acceptance of the all-zero wildcard only.
        if sender == b"\x00" * 16:
            return True
        log.warning(
            "QUIC proof sender-hash mismatch: expected=%s got=%s",
            bytes(peer_user_hash).hex(),
            sender.hex(),
        )
        return False
    return True


def _self_signed_cert(tmp_dir: Path) -> tuple[Path, Path]:
    """Runtime self-signed certificate for the QUIC server role (aioquic
    requires PEM paths; eMuleAI's GnuTLS cert policy is server-side)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AmuleD-NATT")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_dir / "natt_cert.pem"
    key_path = tmp_dir / "natt_key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class _WrappingTransport:
    """DatagramTransport adapter: outbound data is wrapped in
    OP_UDPRESERVEDPROT2 / OP_NATT_FRAME_QUIC before hitting the wire."""

    def __init__(self, inner: asyncio.DatagramTransport) -> None:
        self._inner = inner

    def sendto(self, data: bytes, addr=None) -> None:
        self._inner.sendto(wrap_natt_frame(NATT_FRAME_QUIC, bytes(data)), addr)

    def close(self) -> None:
        self._inner.close()


class NattQuicProtocol(QuicConnectionProtocol):
    """QuicConnectionProtocol with the EAQN1 proof exchange and a stream
    reader/writer facade for the eD2K session (single bidi stream)."""

    def __init__(self, quic: QuicConnection, proof_identity: dict) -> None:
        super().__init__(quic)
        self.proof_ok = asyncio.Event()
        self.dead = asyncio.Event()
        self._reader = asyncio.StreamReader()
        self._proof_sent = False
        self._proof_buffer = b""
        self._identity = proof_identity
        self.remote_stream_id: int | None = None

    def natt_connection_made(self, transport: asyncio.DatagramTransport) -> None:
        super().connection_made(_WrappingTransport(transport))

    def _try_send_proof(self, stream_id: int) -> None:
        if self._proof_sent:
            return
        proof = build_local_proof(
            self._identity["user_hash"], self._identity.get("peer_user_hash")
        )
        self._quic.send_stream_data(stream_id, proof, end_stream=False)
        self._proof_sent = True
        self.transmit()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            if self._quic._is_client:
                # client opens the first bidi stream (id 0 by convention)
                self._try_send_proof(0)
            return
        if isinstance(event, StreamDataReceived):
            self.remote_stream_id = event.stream_id
            if not self.proof_ok.is_set():
                self._proof_buffer += event.data
                if len(self._proof_buffer) < PROOF_LEN:
                    return
                proof = self._proof_buffer[:PROOF_LEN]
                rest = self._proof_buffer[PROOF_LEN:]
                self._proof_buffer = b""
                if not validate_remote_proof(
                    proof,
                    self._identity["user_hash"],
                    self._identity.get("peer_user_hash"),
                ):
                    log.warning("QUIC NAT-T remote proof rejected")
                    self.dead.set()
                    self.close()
                    return
                self.proof_ok.set()
                if not self._quic._is_client:
                    # server answers the proof on the peer's stream
                    answer = build_local_proof(
                        self._identity["user_hash"], proof[5:21]
                    )
                    self._quic.send_stream_data(
                        event.stream_id, answer, end_stream=False
                    )
                    self.transmit()
                if rest:
                    self._reader.feed_data(rest)
                return
            self._reader.feed_data(event.data)
            return
        if isinstance(event, ConnectionTerminated):
            self._reader.feed_eof()
            self.dead.set()

    def connection_lost(self, exc: Exception | None) -> None:
        self._reader.feed_eof()
        self.dead.set()
        super().connection_lost(exc)


async def quic_connect_natt(
    host: str,
    udp_port: int,
    transport: asyncio.DatagramTransport,
    identity: dict,
    idle_timeout: float = 30.0,
) -> NattQuicProtocol:
    """QUIC client role (the downloader): start the punch-driven connect to
    the source's punched UDP endpoint.  Returns the protocol handle
    immediately — ``await handle.proof_ok`` to wait for the proof exchange
    (the caller must route inbound 0xB2/QUIC frames to
    ``handle.datagram_received``).  ``transport`` is the shared client UDP
    datagram transport."""
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=[ALPN_NATT_QUIC],
        server_name=host,
        verify_mode=ssl.CERT_NONE,  # eMuleAI presents ad-hoc certificates
        idle_timeout=idle_timeout,
    )
    connection = QuicConnection(configuration=configuration)
    protocol = NattQuicProtocol(connection, proof_identity=identity)
    protocol.natt_connection_made(transport)
    loop = asyncio.get_running_loop()
    connection.connect((host, udp_port), now=loop.time())
    protocol.transmit()
    return protocol


async def quic_serve_natt(
    transport: asyncio.DatagramTransport,
    identity: dict,
    first_datagram: tuple[bytes, tuple],
    tmp_dir: Path,
    idle_timeout: float = 30.0,
) -> NattQuicProtocol:
    """QUIC server role (the firewalled source): bootstrap from the peer's
    first Initial datagram (ngtcp2 StartServer semantics)."""
    from aioquic.buffer import Buffer
    from aioquic.quic.packet import pull_quic_header

    cert_path, key_path = _self_signed_cert(tmp_dir)
    data, addr = first_datagram
    buf = Buffer(capacity=len(data))
    buf.push_bytes(data)
    buf.seek(0)
    header = pull_quic_header(buf, host_cid_length=8)
    loop = asyncio.get_running_loop()
    if not header.version:
        raise ValueError("first NAT-T datagram is not a QUIC Initial")
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=[ALPN_NATT_QUIC],
        idle_timeout=idle_timeout,
    )
    configuration.load_cert_chain(cert_path, key_path)
    connection = QuicConnection(
        configuration=configuration,
        original_destination_connection_id=header.destination_cid,
        retry_source_connection_id=None,
    )
    protocol = NattQuicProtocol(connection, proof_identity=identity)
    protocol.natt_connection_made(transport)
    connection.receive_datagram(data, addr, now=loop.time())
    protocol.transmit()
    # NOTE: the caller must route subsequent inbound 0xB2/QUIC frames to
    # ``protocol.datagram_received`` BEFORE awaiting protocol.proof_ok
    # (the handshake continues past the first datagram).
    return protocol
