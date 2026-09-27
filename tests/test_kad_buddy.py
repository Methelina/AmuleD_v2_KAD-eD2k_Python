"""Serving-buddy loopback tests (stage X, roadmap 11o).

Wire oracle: KademliaUDPListener.cpp:1681-1866 + BaseClient.cpp:2005-2013
(recon: tmp/recon/emuleai-buddy-udp.recon.md).  Covers: 0x51/0x5A/0x52 and
OP_CALLBACK payload builders (pure), TCP registration of a served client
via the CT_EMULE_SERVINGBUDDYID (0xBF) hello tag, and 0x52 relayed to the
registered client as an OP_CALLBACK (0x99) TCP packet.

tests/test_kad_buddy.py
Author:      Soror L.'.L.'.
Updated:     2026-09-27
"""

from __future__ import annotations

import asyncio
import struct

from amuled_v2.core.kad.buddy import (
    OP_CALLBACK,
    buddy_registry,
    build_find_serving_buddy_res,
    build_op_callback_payload,
    parse_callback_req,
    parse_find_serving_buddy_req,
    xor_mask,
)
from amuled_v2.core.peer.codec import (
    C2CTCP,
    build_hello_payload,
    parse_hello,
)
from amuled_v2.core.peer.listener import IncomingPeerServer, LocalIdentity
from amuled_v2.core.upload.queue import UploadQueue

_OUR_HASH = bytes.fromhex("E" * 32)
_SERVED_KAD_ID = bytes.fromhex("AB" * 16)
_BUDDY_ID_XOR = bytes(b ^ 0xFF for b in _SERVED_KAD_ID)
_IO_TIMEOUT = 30.0


class _EmptyResolver:
    def resolve(self, file_hash):
        return None


def _run(coro) -> None:
    asyncio.run(coro)


def test_buddy_payloads_roundtrip() -> None:
    served_id, userhash, tcp_port, opts = parse_find_serving_buddy_req(
        _BUDDY_ID_XOR + bytes.fromhex("1" * 32) + struct.pack("<H", 4662)
        + bytes((0x83,))
    )
    assert served_id == _BUDDY_ID_XOR
    assert userhash == bytes.fromhex("1" * 32)
    assert tcp_port == 4662
    assert opts == 0x83
    res = build_find_serving_buddy_res(
        served_id, _OUR_HASH, 4711, connect_opts=0x83
    )
    assert len(res) == 35
    assert res[:16] == _BUDDY_ID_XOR
    assert res[16:32] == _OUR_HASH
    (port,) = struct.unpack_from("<H", res, 32)
    assert port == 4711
    assert res[34] == 0x83

    ucheck, fh, req_tcp, ext_ip = parse_callback_req(
        _SERVED_KAD_ID + bytes.fromhex("2" * 32) + struct.pack("<HI", 4712, 0)
    )
    assert ucheck == _SERVED_KAD_ID
    assert req_tcp == 4712
    assert ext_ip == 0
    cb = build_op_callback_payload(
        _BUDDY_ID_XOR, bytes.fromhex("2" * 32), "80.1.2.3", 4712
    )
    assert len(cb) == 38
    a, b, c, d = (int(x) for x in "80.1.2.3".split("."))
    assert cb[32:36] == struct.pack("<I", (a << 24) | (b << 16) | (c << 8) | d)
    (cb_port,) = struct.unpack_from("<H", cb, 36)
    assert cb_port == 4712
    assert xor_mask(_SERVED_KAD_ID) == _BUDDY_ID_XOR


def test_buddy_tcp_registration_and_relay() -> None:
    async def scenario() -> None:
        buddy_registry.configure(tcp_port=0, max_served=8)
        server = IncomingPeerServer(
            identity=LocalIdentity(
                user_hash=_OUR_HASH,
                client_id=0x10203040,
                tcp_port=0,
                nickname="AmuleD-buddy",
            ),
            resolver=_EmptyResolver(),
            upload_queue=UploadQueue(),
            host="127.0.0.1",
            port=0,
            idle_timeout=60.0,
        )
        await server.start()
        buddy_registry.configure(tcp_port=server.bound_port, max_served=8)

        reader, writer = await asyncio.open_connection(
            "127.0.0.1", server.bound_port
        )
        try:
            # The firewalled client registers via its HELLO carrying
            # CT_EMULE_SERVINGBUDDYID (0xBF) = our raw KadID
            # (BaseClient.cpp:2005-2013).
            hello = build_hello_payload(
                user_hash=bytes.fromhex("1" * 32),
                client_id=1,
                client_port=4662,
                nickname="served-client",
                extra_tags=(
                    type(
                        "T",
                        (),
                        {
                            "name": None,
                            "name_id": 0xBF,
                            "type": 0x01,
                            "value": _SERVED_KAD_ID,
                        },
                    )(),
                ),
            )
            writer.write(
                bytes((0xE3,)) + struct.pack("<I", len(hello) + 1)
                + bytes((0x01,)) + hello
            )
            await writer.drain()
            header = await asyncio.wait_for(reader.readexactly(6), _IO_TIMEOUT)
            assert header[5] == C2CTCP.HELLOANSWER
            (ha_len,) = struct.unpack("<I", header[1:5])
            await asyncio.wait_for(
                reader.readexactly(ha_len - 1), _IO_TIMEOUT
            )  # consume the HELLOANSWER payload (framing)

            for _ in range(50):
                if buddy_registry.lookup(_SERVED_KAD_ID) is not None:
                    break
                await asyncio.sleep(0.1)
            entry = buddy_registry.lookup(_SERVED_KAD_ID)
            assert entry is not None, "served client not registered"
            assert buddy_registry.lookup(_BUDDY_ID_XOR) is entry

            # Relay: KADEMLIA_CALLBACK_REQ (0x52) fields -> OP_CALLBACK on
            # the registered client's TCP.
            ucheck, fh, req_tcp, ext_ip = parse_callback_req(
                _SERVED_KAD_ID + bytes.fromhex("2" * 32)
                + struct.pack("<HI", 4712, 0x7F000001)
            )
            assert buddy_registry.relay_op_callback(
                ucheck, fh, "127.0.0.1", req_tcp
            )
            header = await asyncio.wait_for(reader.readexactly(6), _IO_TIMEOUT)
            assert header[0] == 0xC5 and header[5] == OP_CALLBACK
            (length,) = struct.unpack("<I", header[1:5])
            payload = await asyncio.wait_for(
                reader.readexactly(length - 1), _IO_TIMEOUT
            )
            assert payload[:16] == _BUDDY_ID_XOR
            assert payload[16:32] == bytes.fromhex("2" * 32)
            ip_le = payload[32:36]
            # Oracle convention: host-order uint32 serialized little-endian
            # (KademliaUDPListener.cpp:1854-1858, CAddress(outIP, false)).
            assert ip_le == struct.pack("<I", 0x7F000001)
            (cb_port,) = struct.unpack_from("<H", payload, 36)
            assert cb_port == 4712
        finally:
            writer.close()
            await server.close()

    _run(scenario())
