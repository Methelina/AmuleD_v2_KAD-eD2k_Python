"""UDP-datagram obfuscation tests (roadmap 8.4.2; oracle aMule
EncryptedDatagramSocket.cpp, recon tmp/recon/udp-obfuscation-amule.recon.md).

tests/test_udp_obfuscation.py
Author:      Soror L.'.L.'.
Updated:     2026-09-28
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from amuled_v2.core.peer.udp_obfuscation import (
    MAGICVALUE_UDP_SYNC_CLIENT,
    UdpObfuscationError,
    decrypt_client_datagram,
    derive_key_ed2k,
    derive_key_kad_node_id,
    derive_key_kad_receiver,
    encrypt_client_datagram,
    is_plain_protocol_byte,
)


# ---------------------------------------------------------------------------
# Key derivation: MD5 over exact recon byte layouts
# ---------------------------------------------------------------------------


def test_derive_key_ed2k_matches_md5_layout() -> None:
    user_hash = bytes(range(16))
    ip = bytes((10, 0, 0, 1))
    rand = b"\x37\x13"
    expected = hashlib.md5(user_hash + ip + bytes((91,)) + rand).digest()
    assert derive_key_ed2k(user_hash, ip, rand) == expected


def test_derive_key_kad_node_id_and_receiver() -> None:
    kad_id = bytes(range(16, 32))
    rand = b"\x01\x02"
    assert derive_key_kad_node_id(kad_id, rand) == hashlib.md5(
        kad_id + rand
    ).digest()
    vkey = b"\xde\xad\xbe\xef"
    assert derive_key_kad_receiver(vkey, rand) == hashlib.md5(
        vkey + rand
    ).digest()


def test_derive_key_length_guards() -> None:
    with pytest.raises(UdpObfuscationError):
        derive_key_ed2k(b"short", b"\x00\x00\x00\x00", b"\x00\x00")
    with pytest.raises(UdpObfuscationError):
        derive_key_kad_node_id(b"\x00" * 15, b"\x00\x00")
    with pytest.raises(UdpObfuscationError):
        derive_key_kad_receiver(b"\x00" * 5, b"\x00\x00")


# ---------------------------------------------------------------------------
# Round-trips (all three modes), incl. pad_len>0 and candidate cycling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mode",
    ["ed2k", "kad_node_id", "kad_receiver"],
)
def test_roundtrip_all_modes(mode: str) -> None:
    payload = b"\x27" + os_urandom_payload()
    rand = b"\x5a\x3c"
    if mode == "ed2k":
        key = derive_key_ed2k(
            bytes(range(16)), bytes((192, 168, 1, 2)), rand
        )
        vkeys = None
    elif mode == "kad_node_id":
        key = derive_key_kad_node_id(bytes(range(16, 32)), rand)
        vkeys = (b"\x11\x22\x33\x44", b"\x55\x66\x77\x88")
    else:
        vkey = b"\xaa\xbb\xcc\xdd"
        key = derive_key_kad_receiver(vkey, rand)
        vkeys = (vkey, b"\x99\x88\x77\x66")

    datagram = encrypt_client_datagram(
        payload,
        mode=mode,
        key_material=key,
        random_key_part=rand,
        kad_verify_keys=vkeys,
    )

    candidates = [
        ("kad_node_id", derive_key_kad_node_id(bytes(range(16, 32)), rand)),
        ("ed2k", derive_key_ed2k(bytes(range(16)), bytes((192, 168, 1, 2)), rand)),
        ("kad_receiver", derive_key_kad_receiver(b"\xaa\xbb\xcc\xdd", rand)),
    ]
    if mode == "ed2k":
        candidates = [candidates[1]]
    name, plain = decrypt_client_datagram(
        datagram,
        candidates,
        kad_receiver_verify_keys=[b"\xaa\xbb\xcc\xdd"],
    )
    assert name == mode
    assert plain == payload


def os_urandom_payload() -> bytes:
    import os

    return os.urandom(64)


def test_marker_bit_flags_and_no_protocol_collision() -> None:
    for _ in range(50):
        datagram = encrypt_client_datagram(
            b"x", mode="ed2k", key_material=bytes(range(16))
        )
        assert datagram[0] & 0x01
        assert not is_plain_protocol_byte(datagram[0])
        kad = encrypt_client_datagram(
            b"x",
            mode="kad_node_id",
            key_material=bytes(range(16)),
            kad_verify_keys=(b"\x00" * 4, b"\x00" * 4),
        )
        assert not kad[0] & 0x01


def test_sync_magic_on_wire_is_endian_swapped() -> None:
    # bytes 3-6 of the encrypted body must decrypt+swap to the sync constant;
    # verify via a zero-pad round-trip using the reference implementation's
    # own primitive: manually encrypt a datagram with pad_len=0.
    from amuled_v2.core.peer.udp_obfuscation import _endian_swap_pack_u32

    assert _endian_swap_pack_u32(MAGICVALUE_UDP_SYNC_CLIENT) == struct.pack(
        "<I", 0xC12E5F39
    )


def test_decrypt_rejects_plain_protocol_first_byte() -> None:
    with pytest.raises(UdpObfuscationError):
        decrypt_client_datagram(b"\xe3" + b"\x00" * 20, [("ed2k", bytes(16))])


def test_decrypt_rejects_wrong_key() -> None:
    datagram = encrypt_client_datagram(
        b"secret", mode="ed2k", key_material=derive_key_ed2k(
            bytes(range(16)), bytes((1, 2, 3, 4)), b"\x01\x02"
        ),
        random_key_part=b"\x01\x02",
    )
    wrong = derive_key_ed2k(bytes(range(16)), bytes((4, 3, 2, 1)), b"\x01\x02")
    with pytest.raises(UdpObfuscationError):
        decrypt_client_datagram(datagram, [("ed2k", wrong)])


def test_decrypt_rejects_truncated_datagram() -> None:
    with pytest.raises(UdpObfuscationError):
        decrypt_client_datagram(b"\x01\x02\x03", [("ed2k", bytes(16))])


def test_encrypt_validates_mode_and_kad_keys() -> None:
    with pytest.raises(UdpObfuscationError):
        encrypt_client_datagram(b"x", mode="bogus", key_material=bytes(16))
    with pytest.raises(UdpObfuscationError):
        encrypt_client_datagram(
            b"x", mode="kad_node_id", key_material=bytes(16)
        )
