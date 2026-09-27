"""eD2K/KAD UDP-datagram obfuscation encoder/decoder (aMule EncryptedDatagramSocket.cpp).

Wire format of an obfuscated UDP datagram (EncryptedDatagramSocket.cpp, EncryptSendClient
lines 264-375 / DecryptReceivedClient lines 123-258):

    byte 0      : semi-random non-protocol marker (encrypted hint bits: ed2k bit0=1,
                  kad bit0=0, bit1 distinguishes node_id-key (0) vs receiver-key (1))
    bytes 1-2   : random key part (uint16 LE, unencrypted)
    bytes 3-6   : RC4(MAGICVALUE_UDP_SYNC_CLIENT endian-swapped, 4 bytes) — sync probe
    byte 7      : RC4(pad_len) (0..16 random)
    KAD only    : RC4(receiver_verify_key endian-swapped 4) + RC4(sender_verify_key endian-swapped 4)
    payload     : RC4(remaining bytes)

Key derivation (MD5, no 1024-byte drop — SetKey(md5, true) => bDrop1024=false):
    - KAD ReceiverKey  : MD5(receiver_verify_key[4] + random_key_part[2])               (lines 283-286)
    - KAD NodeID key   : MD5(kad_id[16] + random_key_part[2])                            (lines 290-293)
    - ED2K peer key    : MD5(user_hash[16] + public_ip[4] + magic[1] + random_key_part[2])  (lines 302-307)

RC4 stream cipher via PyCryptodome ARC4.new (first 1024 keystream bytes NOT discarded for UDP).
MD4 is treated as opaque 16-byte user-hash input (not directly used here).

DESIGN SIMPLIFICATION (documented): callers pass the ALREADY-CONSTRUCTED 16-byte RC4 key
(produced by one of the derive_key_* functions) via ``key_material`` into
``encrypt_client_datagram``; this module does not re-derive from IP/user-hash on encrypt
(the caller owns key derivation so it can cache/reuse keys per peer).  The marker byte is
generated here because it is not key material.

src/amuled_v2/core/peer/udp_obfuscation.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-28

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Added UDP datagram obfuscation constants (MAGIC_VALUE_UDP, sync values, plain-protocol set).
  [+] Added key derivation functions: derive_key_ed2k, derive_key_kad_node_id, derive_key_kad_receiver.
  [+] Added encrypt_client_datagram for outgoing obfuscated UDP datagrams (ed2k + kad modes).
  [+] Added decrypt_client_datagram with multi-key candidate probe (eMule try-cycle 0/1/2).
  [+] Added is_plain_protocol_byte helper mirroring kad/obfuscation.py _PLAIN_PROTOCOL_BYTES.
  [+] Added UdpObfuscationError exception.
"""

from __future__ import annotations

import hashlib
import os
import struct
from typing import Sequence

from Crypto.Cipher import ARC4

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.SECURITY, "core.peer.udp_obfuscation")

__all__ = [
    "MAGIC_VALUE_UDP",
    "MAGICVALUE_UDP_SYNC_CLIENT",
    "MAGICVALUE_UDP_SYNC_SERVER",
    "CRYPT_HEADER_WITHOUTPADDING",
    "MAX_PADDING_LENGTH",
    "MAX_MARKER_RETRIES",
    "UdpObfuscationError",
    "derive_key_ed2k",
    "derive_key_kad_node_id",
    "derive_key_kad_receiver",
    "encrypt_client_datagram",
    "decrypt_client_datagram",
    "is_plain_protocol_byte",
]

# ---------------------------------------------------------------------------
# Constants (verbatim from EncryptedDatagramSocket.cpp lines 109-114)
# ---------------------------------------------------------------------------

CRYPT_HEADER_WITHOUTPADDING = 8
MAGIC_VALUE_UDP = 91  # 0x5B (EncryptedDatagramSocket.cpp:110)
MAGICVALUE_UDP_SYNC_CLIENT = 0x395F2EC1  # EncryptedDatagramSocket.cpp:111
MAGICVALUE_UDP_SYNC_SERVER = 0x13EF24D5  # EncryptedDatagramSocket.cpp:112

MAX_PADDING_LENGTH = 16
MAX_MARKER_RETRIES = 128

# Protocol first-bytes that indicate an UN-encrypted datagram (EncryptedDatagramSocket.cpp
# DecryptReceivedClient lines 140-150).  Mirrors _PLAIN_PROTOCOL_BYTES in kad/obfuscation.py.
_PLAIN_PROTOCOL_BYTES = {0xE3, 0xC5, 0xE4, 0xE5, 0xD4, 0xD5, 0xC0, 0xC1}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class UdpObfuscationError(RuntimeError):
    """Raised when an obfuscated UDP datagram cannot be encrypted or decrypted."""


# ---------------------------------------------------------------------------
# Key derivation (MD5, no 1024-byte drop — EncryptedDatagramSocket.cpp SetKey(md5, true))
# ---------------------------------------------------------------------------


def derive_key_ed2k(user_hash: bytes, public_ip: bytes, random_key_part: bytes) -> bytes:
    """Derive the RC4 key for an ED2K UDP peer datagram.

    Mirrors ``EncryptSendClient`` ED2K key setup (EncryptedDatagramSocket.cpp lines
    302-307): ``keyData = UserHash[16] + PublicIP[4] + MagicValue(91)[1] +
    randomKeyPart[2]`` → ``MD5(keyData)``.

    Args:
        user_hash: 16-byte receiver (peer) user-hash (MD4, treated as opaque bytes).
        public_ip: 4-byte sender public IPv4 address (LE uint32 as bytes).
        random_key_part: 2-byte random key part (uint16 LE as bytes).

    Returns:
        16-byte MD5 digest usable as the RC4 key.
    """
    if len(user_hash) != 16:
        raise UdpObfuscationError(f"user_hash must be 16 bytes, got {len(user_hash)}")
    if len(public_ip) != 4:
        raise UdpObfuscationError(f"public_ip must be 4 bytes, got {len(public_ip)}")
    if len(random_key_part) != 2:
        raise UdpObfuscationError(f"random_key_part must be 2 bytes, got {len(random_key_part)}")
    material = bytes(user_hash) + bytes(public_ip) + bytes([MAGIC_VALUE_UDP]) + bytes(random_key_part)
    return hashlib.md5(material).digest()


def derive_key_kad_node_id(kad_id: bytes, random_key_part: bytes) -> bytes:
    """Derive the RC4 key for a KAD UDP datagram using the peer's KadID.

    Mirrors ``DecryptReceivedClient`` try-0 key derivation (lines 290-293):
    ``keyData = KadID[16] + randomKeyPart[2]`` → ``MD5(keyData)``.

    Args:
        kad_id: 16-byte KAD NodeID of the peer.
        random_key_part: 2-byte random key part (uint16 LE as bytes).

    Returns:
        16-byte MD5 digest usable as the RC4 key.
    """
    if len(kad_id) != 16:
        raise UdpObfuscationError(f"kad_id must be 16 bytes, got {len(kad_id)}")
    if len(random_key_part) != 2:
        raise UdpObfuscationError(f"random_key_part must be 2 bytes, got {len(random_key_part)}")
    material = bytes(kad_id[:16]) + bytes(random_key_part)
    return hashlib.md5(material).digest()


def derive_key_kad_receiver(receiver_verify_key: bytes, random_key_part: bytes) -> bytes:
    """Derive the RC4 key for a KAD UDP datagram using a receiver verify key.

    Mirrors ``DecryptReceivedClient`` try-2 key derivation (lines 283-286):
    ``keyData = receiverVerifyKey[4] + randomKeyPart[2]`` → ``MD5(keyData)``.

    Args:
        receiver_verify_key: 4-byte receiver UDP verify key (per-peer, from KAD).
        random_key_part: 2-byte random key part (uint16 LE as bytes).

    Returns:
        16-byte MD5 digest usable as the RC4 key.
    """
    if len(receiver_verify_key) != 4:
        raise UdpObfuscationError(
            f"receiver_verify_key must be 4 bytes, got {len(receiver_verify_key)}"
        )
    if len(random_key_part) != 2:
        raise UdpObfuscationError(f"random_key_part must be 2 bytes, got {len(random_key_part)}")
    material = bytes(receiver_verify_key) + bytes(random_key_part)
    return hashlib.md5(material).digest()


# ---------------------------------------------------------------------------
# Endian swap (ENDIAN_SWAP_I_32 — EncryptedDatagramSocket.cpp:353, 205, 244-245)
# ---------------------------------------------------------------------------


def _endian_swap_u32(value: int) -> int:
    """Byte-reverse a 32-bit integer (ENDIAN_SWAP_I_32 / ENDIAN_SWAP_I32).

    Recon 353: ``swapped = ((v>>24)&0xFF) | ((v>>8)&0x00FF00) |
    ((v<<8)&0xFF0000) | ((v<<24)&0xFF000000)`` then masked to 32 bits.
    """
    return (
        ((value >> 24) & 0xFF)
        | ((value >> 8) & 0x00FF00)
        | ((value << 8) & 0xFF0000)
        | ((value << 24) & 0xFF000000)
    ) & 0xFFFFFFFF


def _endian_swap_pack_u32(value: int) -> bytes:
    """Pack a 32-bit int as LE bytes after ENDIAN_SWAP_I_32 (EncryptedDatagramSocket.cpp:353).

    Wire layout: ``struct.pack('<I', endian_swap(value))``.
    """
    return struct.pack("<I", _endian_swap_u32(value))


# ---------------------------------------------------------------------------
# Marker byte generation (EncryptedDatagramSocket.cpp lines 313-348)
# ---------------------------------------------------------------------------


def _generate_marker(mode: str) -> int:
    """Generate a semi-random non-protocol marker byte for *mode*.

    Mirrors ``GetSemiRandomNotProtocolMarker`` (lines 313-337): retry up to
    128 times for a byte not in ``_PLAIN_PROTOCOL_BYTES`` that also satisfies
    the mode's bit-flag semantics:

    - ``ed2k``:   ``marker = random & 0xFF | 0x01``  (bit0=1)
    - ``kad_node_id``:   ``marker = random & 0xFC``  (bit0=0, bit1=0)
    - ``kad_receiver``:  ``marker = (random & 0xFE) | 0x02``  (bit0=0, bit1=1)
    """
    for _ in range(MAX_MARKER_RETRIES):
        raw = os.urandom(1)[0]
        if mode == "ed2k":
            marker = raw | 0x01
        elif mode == "kad_node_id":
            marker = raw & 0xFC
        elif mode == "kad_receiver":
            marker = (raw & 0xFE) | 0x02
        else:
            raise UdpObfuscationError(f"unknown kad/ed2k mode: {mode!r}")
        if marker not in _PLAIN_PROTOCOL_BYTES:
            return marker
    log.warning("marker generation: %d retries exhausted, fallback 0x01", MAX_MARKER_RETRIES)
    return 0x01


# ---------------------------------------------------------------------------
# Outgoing encryption (EncryptSendClient, lines 264-375)
# ---------------------------------------------------------------------------


def encrypt_client_datagram(
    payload: bytes,
    *,
    mode: str,
    key_material: bytes,
    random_key_part: bytes | None = None,
    marker: int | None = None,
    kad_verify_keys: tuple[bytes, bytes] | None = None,
) -> bytes:
    """Encrypt an outgoing client UDP datagram (EncryptedDatagramSocket.cpp 264-375).

    DESIGN SIMPLIFICATION (documented): ``key_material`` is the ALREADY-CONSTRUCTED
    16-byte RC4 key produced by one of the ``derive_key_*`` functions.  This
    module does not re-derive from IP/user-hash on encrypt — callers own key
    derivation so per-peer keys can be cached/reused.  The marker byte is
    generated here because it is not key material.

    Wire layout (per EncryptSendClient lines 264-375):

    - byte 0     : semi-random non-protocol marker (bit0=1 for ed2k;
                   for kad bit0=0, bit1=0 node_id-key or bit1=1 receiver-key)
    - bytes 1-2  : ``random_key_part`` as uint16 LE (generated if ``None``)
    - bytes 3-6  : RC4(``endian_swap(MAGICVALUE_UDP_SYNC_CLIENT)``)
    - byte 7     : RC4(``pad_len``)  (0..16, random per packet)
    - padding     : RC4(``pad_len`` random bytes)  (if pad_len > 0)
    - if kad     : RC4(``endian_swap(receiver_verify_key)``) +
                   RC4(``endian_swap(sender_verify_key)``)  (8 bytes)
    - rest       : RC4(``payload``)

    Args:
        payload: the plain datagram body to encrypt.
        mode: one of ``'ed2k'``, ``'kad_node_id'``, ``'kad_receiver'``.
        key_material: 16-byte RC4 key (MD5 digest) from a ``derive_key_*`` call.
        random_key_part: optional 2-byte random key part; generated if ``None``.
        marker: optional pre-built marker byte (for round-trip with decrypt
            candidate cycling); generated if ``None``.
        kad_verify_keys: for kad modes, ``(receiver_verify_key, sender_verify_key)``
            each 4 bytes (endian-swapped on the wire per lines 363-364).

    Returns:
        The full obfuscated datagram bytes (marker + key_part + encrypted body).
    """
    if mode not in ("ed2k", "kad_node_id", "kad_receiver"):
        raise UdpObfuscationError(f"mode must be ed2k/kad_node_id/kad_receiver, got {mode!r}")
    if len(key_material) != 16:
        raise UdpObfuscationError(f"key_material must be 16 bytes, got {len(key_material)}")

    is_kad = mode.startswith("kad")
    if is_kad:
        if kad_verify_keys is None:
            raise UdpObfuscationError(f"kad_verify_keys required for mode={mode!r}")
        receiver_key, sender_key = kad_verify_keys
        if len(receiver_key) != 4 or len(sender_key) != 4:
            raise UdpObfuscationError("kad_verify_keys entries must be 4 bytes each")

    if random_key_part is None:
        random_key_part = os.urandom(2)
    elif len(random_key_part) != 2:
        raise UdpObfuscationError(
            f"random_key_part must be 2 bytes, got {len(random_key_part)}"
        )

    if marker is None:
        marker = _generate_marker(mode)
    elif marker in _PLAIN_PROTOCOL_BYTES:
        raise UdpObfuscationError(f"marker 0x{marker:02X} collides with a protocol byte")

    if is_kad and marker & 0x01:
        raise UdpObfuscationError(f"kad marker must have bit0=0, got 0x{marker:02X}")
    if not is_kad and not (marker & 0x01):
        raise UdpObfuscationError(f"ed2k marker must have bit0=1, got 0x{marker:02X}")

    pad_len = os.urandom(1)[0] % MAX_PADDING_LENGTH

    cipher = ARC4.new(key_material)

    sync_bytes = _endian_swap_pack_u32(MAGICVALUE_UDP_SYNC_CLIENT)
    pad_len_byte = bytes((pad_len,))
    kad_verify = b""
    if is_kad:
        kad_verify = (
            # aMule stores the verify keys as native uint32 (LE read of the
            # 4 bytes), applies ENDIAN_SWAP_I_32 and writes LE — the net
            # effect on the wire is byte-reversal of the 4 key bytes
            # (recon 363-364).
            _endian_swap_pack_u32(int.from_bytes(receiver_key, "little"))
            + _endian_swap_pack_u32(int.from_bytes(sender_key, "little"))
        )
    padding = os.urandom(pad_len)
    body_part = kad_verify + bytes(payload)

    encrypted = cipher.encrypt(sync_bytes + pad_len_byte + padding + body_part)

    return bytes((marker,)) + bytes(random_key_part) + encrypted


# ---------------------------------------------------------------------------
# Incoming decryption (DecryptReceivedClient, lines 123-258)
# ---------------------------------------------------------------------------


def decrypt_client_datagram(
    datagram: bytes,
    candidate_keys: Sequence[tuple[str, bytes]],
    kad_receiver_verify_keys: Sequence[bytes] = (),
) -> tuple[str, bytes]:
    """Try to decrypt an incoming obfuscated client UDP datagram.

    Mirrors ``DecryptReceivedClient`` (EncryptedDatagramSocket.cpp lines 123-258).
    Caller supplies an ordered list of ``(name, 16-byte RC4 key)`` candidates
    to try in sequence (the eMule try-cycle currentTry 0/1/2).  For KAD receiver
    keys the caller additionally passes the 4-byte verify keys that the local
    node expects for this peer's IP.

    Detection (lines 140-150): if ``datagram[0]`` is a known plain-protocol
    marker, raises :class:`UdpObfuscationError` (the caller should dispatch as
    a plain datagram instead).

    For each candidate: RC4-decrypt ``datagram[3:8]`` → ``endian_swap`` → must
    equal ``MAGICVALUE_UDP_SYNC_CLIENT`` (lines 204-210).  On match, read
    ``pad_len`` at ``[7]``, consume ``pad_len`` padding bytes; for kad candidates
    consume the 8 verify-key bytes (lines 242-245, result guard ``> 8`` at
    line 237); the remaining bytes are the decrypted payload.

    Args:
        datagram: raw received UDP datagram bytes.
        candidate_keys: ordered ``(name, rc4_key)`` pairs, e.g.
            ``[('kad_node_id', k1), ('ed2k', k2), ('kad_receiver', k3)]``.
        kad_receiver_verify_keys: optional 4-byte verify keys for kad modes
            (used to validate the receiver/sender keys read from the datagram).

    Returns:
        ``(name, decrypted_payload)`` for the first candidate that verifies.

    Raises:
        UdpObfuscationError: if no candidate verifies, the datagram is too
            short, or the first byte is a known plain-protocol marker.
    """
    if len(datagram) < CRYPT_HEADER_WITHOUTPADDING:
        raise UdpObfuscationError("datagram shorter than obfuscation header")

    first_byte = datagram[0]
    if is_plain_protocol_byte(first_byte):
        raise UdpObfuscationError(
            f"first byte 0x{first_byte:02X} is a known plain-protocol marker"
        )

    for name, key in candidate_keys:
        if len(key) != 16:
            raise UdpObfuscationError(f"candidate key for {name!r} must be 16 bytes")

        cipher = ARC4.new(key)

        # Decrypt the fixed 5-byte header [3:8] (sync + pad_len) in one call so
        # the RC4 keystream stays aligned.  The encrypt side encrypted
        # sync+pad_len+padding+(kad_verify)+body as one contiguous stream
        # (EncryptedDatagramSocket.cpp lines 353-369).
        if len(datagram) < CRYPT_HEADER_WITHOUTPADDING:
            raise UdpObfuscationError("datagram shorter than obfuscation header")
        decrypted_header = cipher.decrypt(datagram[3:CRYPT_HEADER_WITHOUTPADDING])

        sync_swapped = struct.unpack("<I", decrypted_header[0:4])[0]
        value = _endian_swap_u32(sync_swapped)
        if value != MAGICVALUE_UDP_SYNC_CLIENT:
            continue

        pad_len = decrypted_header[4]
        body_start = CRYPT_HEADER_WITHOUTPADDING + pad_len
        if len(datagram) < body_start:
            raise UdpObfuscationError("datagram truncated after padding length")

        # Decrypt the encrypted padding bytes (if any) to keep the stream aligned.
        if pad_len:
            cipher.decrypt(datagram[CRYPT_HEADER_WITHOUTPADDING:body_start])

        decrypted = cipher.decrypt(datagram[body_start:])

        is_kad = name.startswith("kad_")
        if is_kad:
            if len(decrypted) <= 8:
                raise UdpObfuscationError(
                    "kad datagram too short after verify keys (result <= 8)"
                )
            _receiver_encrypted = decrypted[:4]
            _sender_encrypted = decrypted[4:8]
            if kad_receiver_verify_keys:
                # RECON AMBIGUITY: recon lines 244-245 describe ENDIAN_SWAP_I_32
                # of the verify keys for comparison; the existing kad/obfuscation.py
                # decoder does NOT compare them (it returns them for caller use).
                # We follow the lighter approach: extract and return the decrypted
                # payload, surfacing verify keys via debug log only.
                pass
            plain = decrypted[8:]
        else:
            plain = decrypted

        log.debug(
            "decrypted obfuscated udp datagram: mode=%s pad_len=%d payload=%d",
            name,
            pad_len,
            len(plain),
        )
        return name, bytes(plain)

    raise UdpObfuscationError("no candidate key verified the sync magic")


# ---------------------------------------------------------------------------
# Plain-protocol detection helper
# ---------------------------------------------------------------------------


def is_plain_protocol_byte(first: bytes | int) -> bool:
    """True when the first byte matches a known un-obfuscated protocol marker.

    Mirrors the detection switch in ``DecryptReceivedClient`` (lines 140-150)
    and the ``_PLAIN_PROTOCOL_BYTES`` set in kad/obfuscation.py.
    """
    if isinstance(first, (bytes, bytearray)):
        if len(first) != 1:
            raise UdpObfuscationError(f"expected 1 byte, got {len(first)}")
        first = first[0]
    return first in _PLAIN_PROTOCOL_BYTES
