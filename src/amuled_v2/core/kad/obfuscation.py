"""KAD UDP obfuscation decoder/encoder (eMule 0.50a compatible).

Wire format of an obfuscated UDP datagram (EncryptedDatagramSocket.cpp):

    byte 0      : 6 random bits + 2-bit kad/ed2k marker (never 0xE3/0xE4/...)
    bytes 1-2   : random key part sent by the remote client
    bytes 3-6   : RC4(MAGICVALUE_UDP_SYNC_CLIENT) — key probe
    byte 7      : RC4(pad_len)
    pad_len     : RC4(random padding)
    kad only    : RC4(receiver_verify_key 4) + RC4(sender_verify_key 4)
    rest        : RC4(kad datagram: 0xE4/0xE5 + opcode + payload)

Key candidates tried in eMule's order:
    try 0: MD5(peer's view of our KadID (16 bytes) || wire[1:3])
    try 2: MD5(our UDP verify key for that IP (4 bytes) || wire[1:3])

RC4 without the 1024-byte key drop (RC4CreateKey bSkipDiscard=true).

src/amuled_v2/core/kad/obfuscation.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-23

Patch Notes v0.1.0 (Soror L.'.L'.):
  [+] Added kad2 UDP obfuscation decoder with dual-key probe.
"""

from __future__ import annotations

import hashlib
import os
import struct
from typing import Callable, Optional, Tuple

from Crypto.Cipher import ARC4

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.obfuscation")

__all__ = [
    "MAGICVALUE_UDP_SYNC_CLIENT",
    "CRYPT_HEADER_WITHOUTPADDING",
    "decode_obfuscated_kad",
    "encode_obfuscated_kad",
]

MAGICVALUE_UDP_SYNC_CLIENT = 0x395F2EC1
CRYPT_HEADER_WITHOUTPADDING = 8

_PLAIN_PROTOCOL_BYTES = {0xE3, 0xC5, 0xE4, 0xE5, 0xD4, 0xD5, 0xC0, 0xC1}


def decode_obfuscated_kad(
    datagram: bytes,
    own_kad_id: bytes,
    verify_key_lookup: Optional[Callable[[str, int], int]] = None,
    peer_ip: str = "",
    peer_port: int = 0,
) -> Optional[Tuple[bytes, int, int]]:
    """Decrypt one obfuscated KAD UDP datagram.

    Returns ``(plain_datagram, receiver_verify_key, sender_verify_key)``
    where ``plain_datagram`` starts with the kad protocol byte, or ``None``
    when the datagram is not obfuscated or cannot be decoded with any known
    key candidate.
    """
    if len(datagram) <= CRYPT_HEADER_WITHOUTPADDING:
        return None
    if datagram[0] in _PLAIN_PROTOCOL_BYTES:
        return None

    key_materials = [own_kad_id[:16] + datagram[1:3]]
    if verify_key_lookup is not None:
        stored = verify_key_lookup(peer_ip, peer_port)
        if stored:
            key_materials.append(
                struct.pack("<I", stored & 0xFFFFFFFF) + datagram[1:3]
            )

    for material in key_materials:
        digest = hashlib.md5(material).digest()
        cipher = ARC4.new(digest)
        magic = cipher.decrypt(datagram[3:7])
        if struct.unpack("<I", magic)[0] != MAGICVALUE_UDP_SYNC_CLIENT:
            continue
        pad_len = cipher.decrypt(datagram[7:8])[0]
        body_len = len(datagram) - CRYPT_HEADER_WITHOUTPADDING - pad_len
        if body_len <= 8:
            log.debug(
                "obfuscated datagram too short after header: len=%d pad=%d",
                len(datagram),
                pad_len,
            )
            return None
        receiver_key = struct.unpack(
            "<I", cipher.decrypt(datagram[8 + pad_len : 12 + pad_len])
        )[0]
        sender_key = struct.unpack(
            "<I", cipher.decrypt(datagram[12 + pad_len : 16 + pad_len])
        )[0]
        plain = cipher.decrypt(datagram[16 + pad_len :])
        log.debug(
            "decoded obfuscated kad datagram: peer=%s:%d bytes=%d "
            "receiver_key=%08x sender_key=%08x",
            peer_ip,
            peer_port,
            len(plain),
            receiver_key,
            sender_key,
        )
        return plain, receiver_key, sender_key
    return None

def encode_obfuscated_kad(
    kad_datagram: bytes,
    their_kad_id: bytes,
    our_sender_key: int,
    their_receiver_key: int,
) -> bytes:
    """Encrypt one KAD UDP datagram for the peer (mirror of its decoder).

    Empirically (live-verified decoder) peers derive the try-0 key from our
    NodeID in direct wire order, so the encoder uses the peer's wire-order
    KadID directly.

    ``their_receiver_key`` is the UDP key the peer announced to us
    (sender key of its obfuscated replies); ``our_sender_key`` is the key we
    announce so the peer can encrypt back to us.
    """
    key_part = os.urandom(2)
    marker = (os.urandom(1)[0] & 0xFC) | 0x02  # kad marker bits = 2
    pad_len = 0
    digest = hashlib.md5(their_kad_id[:16] + key_part).digest()
    cipher = ARC4.new(digest)
    plain_head = (
        struct.pack("<I", MAGICVALUE_UDP_SYNC_CLIENT)
        + bytes((pad_len,))
        + struct.pack("<I", their_receiver_key & 0xFFFFFFFF)
        + struct.pack("<I", our_sender_key & 0xFFFFFFFF)
    )
    encrypted = cipher.encrypt(plain_head + kad_datagram)
    return bytes((marker,)) + key_part + encrypted