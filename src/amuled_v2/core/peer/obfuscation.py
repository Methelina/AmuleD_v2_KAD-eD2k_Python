"""eMule TCP obfuscation handshake (DH key exchange + RC4 stream, BASIC client mode).

This module implements the client-side TCP obfuscation layer used by eMule and
compatible clients (``EncryptedStreamSocket.cpp``).  Two negotiation modes exist
on the wire; both are handled here:

1. **DH-based server obfuscation** (``ECS_PENDING_SERVER`` / ``ONS_BASIC_SERVER_*``).
   When the local client connects to an eMule server with ``CryptLayerRequested=1``
   the peer only accepts a DH-obfuscated handshake which this module builds and
   parses.  See :func:`build_dh_request`, :func:`parse_dh_response`,
   :func:`derive_keys`.

2. **BASIC client obfuscation** (``ECS_PENDING`` / ``ONS_BASIC_CLIENTB_*``).
   When the local client connects to a *remote peer* (not a server) with a known
   16-byte user-hash the receiver already holds, no DH exchange is performed.
   Instead both sides derive RC4 keys directly from ``MD5(target_userhash ||
   magic || random_key_part)`` and wrap a short ``MAGICVALUE_SYNC`` handshake.

BASIC client wire format (``ECS_PENDING`` path, ``StartNegotiation(true)``):

    Client -> Peer (BASIC request):
        plaintext bytes 0-4:
            byte  0      : semi-random non-protocol marker (see _not_protocol_marker)
            bytes 1..4   : random_key_part as uint32 LE (m_nRandomKeyPart)
        encrypted bytes 5.. (RC4 send-stream, 1024-byte keystream drop):
            bytes 5..8   : MAGICVALUE_SYNC as uint32 LE (0x835E6FC4)
            byte  9      : encryption method supported (0x00 = ENM_OBFUSCATION)
            byte 10      : encryption method preferred  (0x00)
            byte 11      : padding length n (0..15)
            bytes 12..   : n random padding bytes

    Peer -> Client (BASIC response -- fully encrypted under RC4 recv-stream):
        bytes 0..3       : MAGICVALUE_SYNC as uint32 LE  (validated; mismatch -> error)
        byte  4          : encryption method selected (must be 0x00)
        byte  5          : padding length m (0..255)
        bytes 6..6+m-1   : m random padding bytes (ignored)

The first 1024 bytes of each RC4 keystream are discarded (``RC4CreateKey`` with
the default ``bSkipDiscard=false`` calls ``RC4Crypt(NULL, NULL, 1024, key)``).

Key derivation (BASIC, per ``SetConnectionEncryption``):

    send_key = MD5(target_userhash[16] || MAGICVALUE_REQUESTER(34) || u32 random_key_part LE)
    recv_key = MD5(target_userhash[16] || MAGICVALUE_SERVER(203)   || u32 random_key_part LE)

Diffie-Hellman parameters (from ``EncryptedStreamSocket.cpp``):

    g = 2,  p = dh768_p  (768-bit MODP prime, 96 bytes)

src/amuled_v2/core/peer/obfuscation.py
Version:     0.2.0
Author:      Soror L.'.L'.
Updated:     2026-09-24

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added DH obfuscation request builder (build_dh_request).
  [+] Added DH response parser (parse_dh_response).
  [+] Added key derivation (derive_keys) with MD5 chain per CreateKeys.
  [+] Added Rc4Stream with 1024-byte key-drop.
  [+] Added semi-random padding-length helper.

Patch Notes v0.2.0 (Soror L.'.L'.):
  [+] Added BASIC client TCP obfuscation handshake (derive_basic_keys,
      build_basic_client_request, parse_basic_client_response).
  [FIX] Corrected protocol-marker constants to OP_PACKEDPROT=0xD4 and
      OP_EMULEPROT=0xC5 (opcodes.h); previous values 0xC0/0xED would cause
      the semi-random marker to collide with valid protocol bytes -- иначе пир не примет.
"""

from __future__ import annotations

import hashlib
import os
import random
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from Crypto.Cipher import ARC4

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.SECURITY, "core.peer.obfuscation")

__all__ = [
    "DIFFIE_HELLMAN_PRIME",
    "DH_GENERATOR",
    "DH_PRIVATE_KEY_BITS",
    "DH_PUBKEY_BYTES",
    "MAGICVALUE_SYNC",
    "MAGICVALUE_REQUESTER",
    "MAGICVALUE_SERVER",
    "ENM_OBFUSCATION",
    "RC4_KEY_DROP_BYTES",
    "MAX_PADDING_LENGTH",
    "PROTOCOL_MARKER_EDONKEY",
    "PROTOCOL_MARKER_PACKED",
    "PROTOCOL_MARKER_EMULE",
    "ObfuscationError",
    "NegotiationKeys",
    "build_dh_request",
    "parse_dh_response",
    "derive_keys",
    "derive_basic_keys",
    "Rc4Stream",
    "semirandom_padding_length",
    "generate_dh_private_key",
    "compute_dh_public_key",
    "build_basic_client_request",
    "parse_basic_client_response",
]


# ---------------------------------------------------------------------------
# Constants (verbatim from EncryptedStreamSocket.cpp / EncryptedStreamSocket.h)
# ---------------------------------------------------------------------------

# 768-bit Diffie-Hellman MODP prime (dh768_p), little-endian storage in C++
# source but interpreted big-endian by CryptoPP::Integer -- иначе пир не примет.
DIFFIE_HELLMAN_PRIME = int.from_bytes(
    bytes(
        [
            0xF2, 0xBF, 0x52, 0xC5, 0x5F, 0x58, 0x7A, 0xDD,
            0x53, 0x71, 0xA9, 0x36, 0xE8, 0x86, 0xEB, 0x3C,
            0x62, 0x17, 0xA3, 0x3E, 0xC3, 0x4C, 0xB4, 0x0D,
            0xC7, 0x3A, 0x41, 0xA6, 0x43, 0xAF, 0xFC, 0xE7,
            0x21, 0xFC, 0x28, 0x63, 0x66, 0x53, 0x5B, 0xDB,
            0xCE, 0x25, 0x9F, 0x22, 0x86, 0xDA, 0x4A, 0x91,
            0xB2, 0x07, 0xCB, 0xAA, 0x52, 0x55, 0xD4, 0xF6,
            0x1C, 0xCE, 0xAE, 0xD4, 0x5A, 0xD5, 0xE0, 0x74,
            0x7D, 0xF7, 0x78, 0x18, 0x28, 0x10, 0x5F, 0x34,
            0x0F, 0x76, 0x23, 0x87, 0xF8, 0x8B, 0x28, 0x91,
            0x42, 0xFB, 0x42, 0x68, 0x8F, 0x05, 0x15, 0x0F,
            0x54, 0x8B, 0x5F, 0x43, 0x6A, 0xF7, 0x0D, 0xF3,
        ]
    ),
    "big",
)

# DH generator g = 2 (CryptoPP::Integer(2) as base in a_exp_b_mod_c) -- иначе пир не примет.
DH_GENERATOR = 2

# Private key size in bits: CryptoPP::Integer::Randomize(rng, DHAGREEMENT_A_BITS).
DH_PRIVATE_KEY_BITS = 128

# Public key / shared-secret field width in bytes: PRIMESIZE_BYTES (96) -- иначе пир не примет.
DH_PUBKEY_BYTES = 96

# eMule protocol marker bytes that the semi-random marker must NOT collide with.
PROTOCOL_MARKER_EDONKEY = 0xE3   # OP_EDONKEYPROT (opcodes.h) -- иначе пир не примет.
PROTOCOL_MARKER_PACKED = 0xD4     # OP_PACKEDPROT (opcodes.h) -- иначе пир не примет.
PROTOCOL_MARKER_EMULE = 0xC5      # OP_EMULEPROT (opcodes.h)  -- иначе пир не примет.

_PROHIBITED_MARKERS = frozenset(
    {PROTOCOL_MARKER_EDONKEY, PROTOCOL_MARKER_PACKED, PROTOCOL_MARKER_EMULE}
)

# MAGICVALUE_SYNC: 0x835E6FC4 on the wire as 4 bytes little-endian.
MAGICVALUE_SYNC = 0x835E6FC4

# MAGICVALUE_REQUESTER (34): used to derive the client->server RC4 send key.
MAGICVALUE_REQUESTER = 34

# MAGICVALUE_SERVER (203): used to derive the server->client RC4 recv key.
MAGICVALUE_SERVER = 203

# Encryption method: 0 = obfuscation (ENM_OBFUSCATION).
ENM_OBFUSCATION = 0x00

# RC4 key-drop: first 1024 keystream bytes are discarded (RC4CreateKey default).
RC4_KEY_DROP_BYTES = 1024

# Maximum random padding length for the DH path: rand() % 16 → range 0..15.
MAX_PADDING_LENGTH = 16


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ObfuscationError(Exception):
    """Raised when the DH obfuscation handshake fails to build, parse, or derive keys."""


# ---------------------------------------------------------------------------
# NegotiationKeys
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NegotiationKeys:
    """Keys and RC4 keystream-drop lengths produced by the DH handshake.

    ``send_key`` encrypts data the client writes to the peer; ``recv_key``
    decrypts data the peer writes back.  Each RC4 stream must discard
    ``send_pad_len`` / ``recv_pad_len`` leading keystream bytes before use
    (always ``RC4_KEY_DROP_BYTES`` per eMule's ``RC4CreateKey``).
    """

    send_key: bytes
    recv_key: bytes
    send_pad_len: int
    recv_pad_len: int


# ---------------------------------------------------------------------------
# DH key generation
# ---------------------------------------------------------------------------


def generate_dh_private_key() -> int:
    """Generate a 128-bit DH private key ``a``.

    Mirrors ``CryptoPP::Integer::Randomize(rng, DHAGREEMENT_A_BITS)`` with
    128 bits: the result occupies exactly 128 bits with the most-significant
    bit set, placing it in ``[2^127, 2^128 - 1]``.  This keeps the encoded
    public key exactly ``DH_PUBKEY_BYTES`` (96) bytes when reduced mod p.
    """
    byte_len = DH_PRIVATE_KEY_BITS // 8
    raw = os.urandom(byte_len)
    raw = bytearray(raw)
    raw[0] |= 0x80  # CryptoPP::Integer::Randomize(bits) sets the top bit
    value = int.from_bytes(raw, "big")
    log.debug(
        "DH private key generated: bits=%d byte_len=%d msn=%#04x",
        value.bit_length(),
        byte_len,
        raw[0],
    )
    return value


def compute_dh_public_key(private_key: int) -> bytes:
    """Compute ``G^a mod p`` and encode as 96 big-endian bytes.

    CryptoPP::Integer::Encode fills a fixed-width buffer with big-endian
    bytes, zero-padding on the left when the value is shorter than the
    buffer.  Python ``int.to_bytes(96, "big")`` reproduces this exactly.
    """
    if not isinstance(private_key, int) or private_key < 0:
        raise ObfuscationError("private_key must be a non-negative integer")
    pub = pow(DH_GENERATOR, private_key, DIFFIE_HELLMAN_PRIME)
    pub_bytes = pub.to_bytes(DH_PUBKEY_BYTES, "big")
    log.debug("DH public key computed: %s", pub_bytes.hex())
    return pub_bytes


# ---------------------------------------------------------------------------
# Semi-random non-protocol marker
# ---------------------------------------------------------------------------


def _not_protocol_marker(rng: Optional[random.Random] = None) -> int:
    """Return a random byte that is not a valid ED2K protocol marker.

    Mirrors ``GetSemiRandomNotProtocolMarker``: try up to 128 times, then
    fall back to 0x01.
    """
    if rng is not None:
        gen = rng
    else:
        gen = random.Random(os.urandom(32).hex())
    for _ in range(128):
        candidate = gen.randint(0, 255)
        if candidate not in _PROHIBITED_MARKERS:
            return candidate
    log.warning(
        "semi-random marker: 128 retries exhausted, falling back to 0x01"
    )
    return 0x01


# ---------------------------------------------------------------------------
# Padding-length helper
# ---------------------------------------------------------------------------


def semirandom_padding_length(rand: Optional[random.Random] = None) -> int:
    """Return a semi-random padding length in ``[0, MAX_PADDING_LENGTH)`` (0..15).

    Mirrors eMule's DH-path padding: ``cryptRandomGen.GenerateByte() % 16``.
    Not fully random in the cryptographic sense -- the length is bounded to
    16 values so peers parse the handshake deterministically.  When *rand*
    is supplied its ``randint`` method seeds the value; otherwise
    ``os.urandom`` is used.
    """
    if rand is not None:
        value = rand.randint(0, MAX_PADDING_LENGTH - 1)
    else:
        value = os.urandom(1)[0] % MAX_PADDING_LENGTH
    log.debug("semirandom padding length: %d", value)
    return value


# ---------------------------------------------------------------------------
# Request / Response builders
# ---------------------------------------------------------------------------


def build_dh_request(
    pubkey: bytes,
    *,
    padding: Optional[bytes] = None,
) -> bytes:
    """Build the DH obfuscation request sent to the remote peer.

    Layout (per ``StartNegotiation`` -- ``ECS_PENDING_SERVER`` path)::

        byte  0      : semi-random non-protocol marker
        bytes 1..96  : G^a mod p  (96-byte big-endian)
        byte  97     : padding length n  (n = rand % 16)
        bytes 98..   : n random padding bytes

    If *padding* is given it replaces the auto-generated random padding
    (its length must match the encoded pad-length byte); otherwise the
    pad length and bytes are chosen semi-randomly per the C++.
    """
    if len(pubkey) != DH_PUBKEY_BYTES:
        raise ObfuscationError(
            f"pubkey must be {DH_PUBKEY_BYTES} bytes, got {len(pubkey)}"
        )
    marker = _not_protocol_marker()
    if padding is not None:
        pad_len = len(padding)
        if not 0 <= pad_len < MAX_PADDING_LENGTH:
            raise ObfuscationError(
                f"explicit padding length {pad_len} out of range 0..{MAX_PADDING_LENGTH - 1}"
            )
        body = bytes((pad_len,)) + bytes(padding)
    else:
        pad_len = semirandom_padding_length()
        body = bytes((pad_len,)) + os.urandom(pad_len)
    request = bytes((marker,)) + pubkey + body
    log.debug(
        "DH request built: marker=0x%02x pubkey=%d pad_len=%d total=%d",
        marker,
        len(pubkey),
        pad_len,
        len(request),
    )
    return request


def parse_dh_response(payload: bytes) -> Tuple[bytes, bytes, int]:
    """Parse the server's DH obfuscation response.

    Layout (per ``ONS_BASIC_SERVER_DHANSWER`` + ``ONS_BASIC_SERVER_MAGICVALUE``
    + ``ONS_BASIC_SERVER_METHODTAGSPADLEN``)::

        bytes 0..95  : G^B mod p  (96-byte big-endian)
        bytes 96..99 : MAGICVALUE_SYNC (uint32 LE = 0x835E6FC4)
        byte  100    : encryption methods supported
        byte  101    : encryption method preferred
        byte  102    : padding length m  (m = rand % 16)
        bytes 103..  : m random padding bytes

    Returns ``(server_pubkey, recv_pad_info, recv_padding_len)`` where
    ``recv_pad_info`` is the 4-byte ``MAGICVALUE_SYNC`` wire bytes (for
    verification by the caller) and ``recv_padding_len`` is the padding
    length the *peer* appended (the C++ simply discards the bytes).
    """
    if len(payload) < DH_PUBKEY_BYTES + 4:
        raise ObfuscationError(
            f"DH response too short: need >= {DH_PUBKEY_BYTES + 4} bytes, "
            f"got {len(payload)}"
        )
    server_pubkey = payload[:DH_PUBKEY_BYTES]
    magic_bytes = payload[DH_PUBKEY_BYTES : DH_PUBKEY_BYTES + 4]
    magic = struct.unpack_from("<I", magic_bytes, 0)[0]
    if magic != MAGICVALUE_SYNC:
        raise ObfuscationError(
            f"DH response magic mismatch: got 0x{magic:08X}, "
            f"expected 0x{MAGICVALUE_SYNC:08X}"
        )
    if len(payload) < DH_PUBKEY_BYTES + 7:
        raise ObfuscationError(
            f"DH response too short for method tags: need >= "
            f"{DH_PUBKEY_BYTES + 7} bytes, got {len(payload)}"
        )
    _supported = payload[DH_PUBKEY_BYTES + 4]
    _preferred = payload[DH_PUBKEY_BYTES + 5]
    recv_padding_len = payload[DH_PUBKEY_BYTES + 6]
    consumed = DH_PUBKEY_BYTES + 7 + recv_padding_len
    if len(payload) < consumed:
        raise ObfuscationError(
            f"DH response padding truncated: declared {recv_padding_len}, "
            f"only {len(payload) - DH_PUBKEY_BYTES - 7} bytes available"
        )
    log.debug(
        "DH response parsed: server_pubkey=%s magic=0x%08X "
        "supported=0x%02X preferred=0x%02X pad_len=%d",
        server_pubkey.hex(),
        magic,
        _supported,
        _preferred,
        recv_padding_len,
    )
    return server_pubkey, magic_bytes, recv_padding_len


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def derive_keys(
    private_key: int,
    server_pubkey: bytes,
    client_pubkey: bytes,
    recv_pad_len: int,
    send_pad_len: int,
) -> NegotiationKeys:
    """Derive send/recv RC4 keys from the DH shared secret.

    Mirrors ``ONS_BASIC_SERVER_DHANSWER`` key creation:

    1. ``shared = pow(server_pubkey_int, a, prime_int)``
    2. ``shared_buf = shared.to_bytes(96, "big")``  (CryptoPP::Integer::Encode)
    3. ``send_key = MD5(shared_buf + MAGICVALUE_REQUESTER)``
    4. ``recv_key = MD5(shared_buf + MAGICVALUE_SERVER)``

    The private key *a* is the local secret; ``server_pubkey`` (G^B) and
    ``client_pubkey`` (our G^a) are the 96-byte big-endian encoded values.
    ``client_pubkey`` is accepted for API completeness and logging; the C++
    derivation of RC4 keys does not incorporate it.  Both
    ``send_pad_len``/``recv_pad_len`` are set to ``RC4_KEY_DROP_BYTES`` (1024)
    per ``RC4CreateKey``'s ``bSkipDiscard=false`` default, which discards
    the first 1024 keystream bytes.

    CryptoPP::Integer reads/writes big-endian, so ``server_pubkey`` and the
    shared-secret encoding are interpreted big-endian -- this is the single
    most common byte-order bug in reimplementations; иначе пир не примет.
    """
    if not isinstance(private_key, int) or private_key < 0:
        raise ObfuscationError("private_key must be a non-negative integer")
    if len(server_pubkey) != DH_PUBKEY_BYTES:
        raise ObfuscationError(
            f"server_pubkey must be {DH_PUBKEY_BYTES} bytes, got {len(server_pubkey)}"
        )
    if len(client_pubkey) != DH_PUBKEY_BYTES:
        raise ObfuscationError(
            f"client_pubkey must be {DH_PUBKEY_BYTES} bytes, got {len(client_pubkey)}"
        )
    if not (0 <= send_pad_len <= 0xFFFF):
        raise ObfuscationError(f"send_pad_len out of range: {send_pad_len}")
    if not (0 <= recv_pad_len <= 0xFFFF):
        raise ObfuscationError(f"recv_pad_len out of range: {recv_pad_len}")

    # Interpret the server's 96-byte big-endian public value as an integer.
    server_int = int.from_bytes(server_pubkey, "big")

    # G^(aB) mod p  ==  (G^B)^a mod p  -- the DH shared secret.
    shared_int = pow(server_int, private_key, DIFFIE_HELLMAN_PRIME)

    # CryptoPP::Integer::Encode into a fixed 96-byte big-endian buffer;
    # zero-pads on the left when the value is shorter.
    shared_buf = shared_int.to_bytes(DH_PUBKEY_BYTES, "big")

    # Send key (client->server): MAGICVALUE_REQUESTER = 34.
    send_material = shared_buf + bytes((MAGICVALUE_REQUESTER,))
    send_key = _md5_digest(send_material)

    # Recv key (server->client): MAGICVALUE_SERVER = 203.
    recv_material = shared_buf + bytes((MAGICVALUE_SERVER,))
    recv_key = _md5_digest(recv_material)

    log.debug(
        "keys derived: send_key=%s recv_key=%s drop=%d",
        send_key.hex(),
        recv_key.hex(),
        RC4_KEY_DROP_BYTES,
    )
    return NegotiationKeys(
        send_key=send_key,
        recv_key=recv_key,
        send_pad_len=RC4_KEY_DROP_BYTES,
        recv_pad_len=RC4_KEY_DROP_BYTES,
    )


def _md5_digest(data: bytes) -> bytes:
    """Return the 16-byte raw MD5 digest of *data*."""
    return hashlib.md5(data).digest()


# ---------------------------------------------------------------------------
# BASIC client obfuscation (ECS_PENDING / ONS_BASIC_CLIENTB_*)
# ---------------------------------------------------------------------------


def derive_basic_keys(target_userhash: bytes, random_key_part: int) -> NegotiationKeys:
    """Derive BASIC-mode RC4 keys from the peer's user-hash and random key part.

    Mirrors ``SetConnectionEncryption`` (the ``ECS_PENDING`` branch, lines
    399-415 of ``EncryptedStreamSocket.cpp``): no DH exchange is performed
    because the sender already knows the receiver's 16-byte user-hash
    (``pTargetClientHash`` obtained from KAD source search).

    Key material layout (21 bytes, per the protocol comment)::

        <target_userhash 16><MAGICVALUE_REQUESTER 1><RandomKeyPart 4>  -> send_key
        <target_userhash 16><MAGICVALUE_SERVER   1><RandomKeyPart 4>  -> recv_key

    Each key is the raw 16-byte MD5 of the 21-byte material.  Both RC4
    streams discard 1024 leading keystream bytes (``RC4CreateKey`` with
    ``bSkipDiscard=false``), so ``send_pad_len``/``recv_pad_len`` are set
    to ``RC4_KEY_DROP_BYTES``.

    Args:
        target_userhash: 16-byte receiver user-hash (``pTargetClientHash``).
        random_key_part: 32-bit ``m_nRandomKeyPart`` generated by the
            sender; written to the wire as a little-endian uint32 and
            appended to the key material as ``struct.pack('<I', ...)``.

    Raises:
        ObfuscationError: if *target_userhash* is not exactly 16 bytes, or
            *random_key_part* is outside ``[0, 0xFFFFFFFF]``.
    """
    if not isinstance(target_userhash, (bytes, bytearray)) or len(target_userhash) != 16:
        raise ObfuscationError(
            f"target_userhash must be exactly 16 bytes, got {len(target_userhash)}"
        )
    if not isinstance(random_key_part, int) or not (0 <= random_key_part <= 0xFFFFFFFF):
        raise ObfuscationError(
            f"random_key_part must be in [0, 0xFFFFFFFF], got {random_key_part}"
        )

    random_key_bytes = struct.pack("<I", random_key_part)

    send_material = bytes(target_userhash) + bytes((MAGICVALUE_REQUESTER,)) + random_key_bytes
    send_key = _md5_digest(send_material)

    recv_material = bytes(target_userhash) + bytes((MAGICVALUE_SERVER,)) + random_key_bytes
    recv_key = _md5_digest(recv_material)

    log.debug(
        "basic keys derived: random_key_part=%u send_key_len=%d recv_key_len=%d drop=%d",
        random_key_part,
        len(send_key),
        len(recv_key),
        RC4_KEY_DROP_BYTES,
    )
    return NegotiationKeys(
        send_key=send_key,
        recv_key=recv_key,
        send_pad_len=RC4_KEY_DROP_BYTES,
        recv_pad_len=RC4_KEY_DROP_BYTES,
    )


def build_basic_client_request(
    target_userhash: bytes,
    *,
    random_key_part: Optional[int] = None,
    padding: Optional[bytes] = None,
) -> Tuple[bytes, NegotiationKeys, int]:
    """Build the BASIC-mode obfuscation request sent to a remote peer.

    Mirrors the ``ECS_PENDING`` / outgoing branch of ``StartNegotiation``
    (lines 446-464 of ``EncryptedStreamSocket.cpp``), which calls
    ``SendNegotiatingData(buf, len, 5)`` -- i.e. only the first 5 plaintext
    bytes are left unencrypted; everything from byte 5 onward is encrypted
    under the RC4 send-stream.

    Wire layout::

        byte  0      : semi-random non-protocol marker (see _not_protocol_marker)
        bytes 1..4   : random_key_part as uint32 LE  (m_nRandomKeyPart)
        bytes 5..8   : MAGICVALUE_SYNC as uint32 LE  (encrypted)
        byte  9      : supported method (0x00 = ENM_OBFUSCATION)  (encrypted)
        byte 10      : preferred method  (0x00)                  (encrypted)
        byte 11      : padding length n  (0..15)                 (encrypted)
        bytes 12..   : n random padding bytes                   (encrypted)

    Args:
        target_userhash: 16-byte receiver user-hash (validates to 16 bytes).
        random_key_part: optional 32-bit key part for determinism / testing.
            When ``None`` a fresh value is generated from ``os.urandom(4)``
            interpreted as a little-endian uint32 (mirrors
            ``PokeUInt32`` which writes LE).
        padding: optional fixed padding bytes (length 0..15).  When ``None``
            a semi-random length (``semirandom_padding_length``) and random
            bytes (``os.urandom``) are generated.

    Returns:
        Tuple of ``(request_bytes, keys, random_key_part)`` where
        *request_bytes* is the full plaintext-then-encrypted payload,
        *keys* holds the derived :class:`NegotiationKeys`, and
        *random_key_part* is the (possibly generated) 32-bit value.

    Raises:
        ObfuscationError: if *target_userhash* is not 16 bytes, or *padding*
            length (when given) is outside 0..15.
    """
    if not isinstance(target_userhash, (bytes, bytearray)) or len(target_userhash) != 16:
        raise ObfuscationError(
            f"target_userhash must be exactly 16 bytes, got {len(target_userhash)}"
        )

    if random_key_part is None:
        random_key_part = int.from_bytes(os.urandom(4), "little")
    elif not isinstance(random_key_part, int) or not (0 <= random_key_part <= 0xFFFFFFFF):
        raise ObfuscationError(
            f"random_key_part must be in [0, 0xFFFFFFFF], got {random_key_part}"
        )

    keys = derive_basic_keys(target_userhash, random_key_part)

    # Plaintext header (5 bytes, NOT encrypted): marker + u32 LE random_key_part.
    marker = _not_protocol_marker()
    plaintext = bytes((marker,)) + struct.pack("<I", random_key_part)

    # Encrypted body (from byte 5 onward) -- same RC4 send-stream used for
    # the rest of the session.
    if padding is not None:
        pad_len = len(padding)
        if not 0 <= pad_len < MAX_PADDING_LENGTH:
            raise ObfuscationError(
                f"explicit padding length {pad_len} out of range 0..{MAX_PADDING_LENGTH - 1}"
            )
        body_padding = bytes(padding)
    else:
        pad_len = semirandom_padding_length()
        body_padding = os.urandom(pad_len)

    encrypted_portion = (
        struct.pack("<I", MAGICVALUE_SYNC)
        + bytes((ENM_OBFUSCATION,))
        + bytes((ENM_OBFUSCATION,))
        + bytes((pad_len,))
        + body_padding
    )

    send_stream = Rc4Stream(keys.send_key, drop=keys.send_pad_len)
    encrypted_body = send_stream.crypt(encrypted_portion)

    request = plaintext + encrypted_body

    log.debug(
        "basic request built: marker=0x%02x pad_len=%d random_key_part=%u "
        "total_len=%d send_key_hex4=%s",
        marker,
        pad_len,
        random_key_part,
        len(request),
        keys.send_key[:4].hex(),
    )
    return request, keys, random_key_part


def parse_basic_client_response(payload: bytes, keys: NegotiationKeys) -> int:
    """Parse the BASIC-mode responder (peer) reply.

    Mirrors the ``ONS_BASIC_CLIENTB_*`` states in ``Negotiate`` (lines 599-627
    of ``EncryptedStreamSocket.cpp``).  The *entire* response is encrypted
    under the RC4 recv-stream, so *payload* must already contain the complete
    (post-decryption) frame.  Because a TCP stream may deliver the frame
    across multiple segments, callers are expected to buffer until at least
    ``6 + peer_pad_len`` bytes are available; the function performs that
    minimum-length validation here.

    Layout (after RC4 decryption)::

        bytes 0..3 : MAGICVALUE_SYNC as uint32 LE  (validated)
        byte  4    : encryption method selected (must == ENM_OBFUSCATION)
        byte  5    : padding length m  (0..255)
        bytes 6..  : m random padding bytes (ignored)

    Args:
        payload: the raw encrypted bytes received from the peer (may span
            one or more TCP segments; the caller must assemble them).
        keys: the :class:`NegotiationKeys` whose ``recv_key``/``recv_pad_len``
            describe the receiver-side RC4 stream.

    Returns:
        The total number of decrypted bytes consumed (6 + peer_pad_len),
        i.e. the complete frame length.

    Raises:
        ObfuscationError: if the payload is shorter than the minimum
            ``MAGICVALUE_SYNC`` (4 bytes), the magic does not match, the
            negotiated method is unsupported, or the padding is truncated
            (``"truncated"``).
    """
    if len(payload) < 4:
        raise ObfuscationError("truncated")

    recv_stream = Rc4Stream(keys.recv_key, drop=keys.recv_pad_len)
    decrypted = recv_stream.crypt(payload)

    if len(decrypted) < 4:
        raise ObfuscationError("truncated")

    magic = struct.unpack_from("<I", decrypted, 0)[0]
    if magic != MAGICVALUE_SYNC:
        raise ObfuscationError(
            f"wrong magic: got 0x{magic:08X}, expected 0x{MAGICVALUE_SYNC:08X}"
        )

    if len(decrypted) < 6:
        raise ObfuscationError("truncated")

    method = decrypted[4]
    if method != ENM_OBFUSCATION:
        raise ObfuscationError(
            f"unsupported encryption method: got 0x{method:02X}, "
            f"expected 0x{ENM_OBFUSCATION:02X}"
        )

    peer_pad_len = decrypted[5]
    total = 6 + peer_pad_len
    if len(decrypted) < total:
        raise ObfuscationError("truncated")

    log.debug(
        "basic response parsed: method=0x%02X pad_len=%d total=%d",
        method,
        peer_pad_len,
        total,
    )
    return total


# ---------------------------------------------------------------------------
# RC4 stream (with 1024-byte key-drop)
# ---------------------------------------------------------------------------


class Rc4Stream:
    """Streaming RC4 cipher with configurable keystream pre-drop.

    Wraps ``Crypto.Cipher.ARC4`` (PyCryptodome) to reproduce eMule's
    ``RC4CreateKey(..., bSkipDiscard=false)`` behaviour: ``bSkipDiscard``
    defaults to *false*, and the C++ discards 1024 keystream bytes when
    ``!bSkipDiscard``.  The default ``drop=1024`` matches this constant.

    RC4 is its own inverse, so :meth:`crypt` is used for both encryption
    and decryption on the client and server side.
    """

    __slots__ = ("_cipher",)

    def __init__(self, key: bytes, drop: int = RC4_KEY_DROP_BYTES) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise ObfuscationError("key must be bytes")
        if drop < 0:
            raise ObfuscationError(f"drop must be non-negative, got {drop}")
        self._cipher = ARC4.new(key)
        if drop:
            # Discard `drop` keystream bytes by encrypting null bytes.
            self._cipher.encrypt(b"\x00" * drop)
        log.debug("Rc4Stream initialised: key_len=%d drop=%d", len(key), drop)

    def crypt(self, data: bytes) -> bytes:
        """Encrypt or decrypt *data* (same operation for RC4)."""
        return self._cipher.encrypt(data)
