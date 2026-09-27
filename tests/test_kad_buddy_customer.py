"""Buddy-customer loopback tests (stage X, roadmap 11o).

A fake buddy (UDP 0x51->0x5A responder + TCP acceptor) serves a
BuddyCustomer; the orchestrating 0x52 relay is simulated by writing an
OP_CALLBACK (0x99) into the registered TCP channel; the customer must
dial the requester (plain TCP) — the dial lands on a local listener.

The e2e test is heavily instrumented: every stage prints, every bounded
wait polls with progress, and an internal watchdog dumps the stack of
EVERY pending task if the scenario exceeds 20 s (so a hang shows exactly
which await is stuck, independent of the process-level faulthandler).

tests/test_kad_buddy_customer.py
Author:      Soror L.'.L.'.
Updated:     2026-09-27
"""

from __future__ import annotations

import asyncio
import struct
import time

from amuled_v2.core.kad.buddy import (
    OP_CALLBACK,
    build_find_serving_buddy_res,
    xor_mask,
)
from amuled_v2.core.kad.buddy_customer import BuddyCustomer
from amuled_v2.core.peer.codec import C2CTCP, parse_hello

_OUR_KAD_ID = bytes.fromhex("AB" * 16)
_OUR_USERHASH = bytes.fromhex("1" * 32)
_IO_TIMEOUT = 10.0
_T0 = time.monotonic()


def _stage(message: str) -> None:
    print(f"[{time.monotonic() - _T0:7.2f}s] STAGE: {message}", flush=True)


async def _dump_all_tasks(reason: str) -> None:
    print(f"=== WATCHDOG: {reason} — pending task stacks: ===", flush=True)
    me = asyncio.current_task()
    for task in asyncio.all_tasks():
        if task is me or task.done():
            continue
        stack = task.get_stack() or []
        frames = [
            f"{f.f_code.co_filename.split(chr(92))[-1]}:{f.f_code.co_name}:{f.f_lineno}"
            for f in stack
        ]
        print(f"  TASK {task.get_name()}: {frames}", flush=True)
    print("=== WATCHDOG end ===", flush=True)


def test_buddy_customer_req_and_res() -> None:
    customer = BuddyCustomer(
        own_kad_id=_OUR_KAD_ID,
        own_userhash=_OUR_USERHASH,
        own_tcp_port=4662,
        dial_back=None,
    )
    req = customer.build_find_serving_buddy_req()
    assert req[:2] == bytes((0xE4, 0x51))
    payload = req[2:]
    assert payload[0:16] == xor_mask(_OUR_KAD_ID)
    assert payload[16:32] == _OUR_USERHASH
    (port,) = struct.unpack_from("<H", payload, 32)
    assert port == 4662
    assert payload[34] == 0x83

    res = build_find_serving_buddy_res(
        xor_mask(_OUR_KAD_ID), bytes.fromhex("9" * 32), 4711,
        connect_opts=0x83,
    )
    assert customer.on_res(res, "127.0.0.1") is True
    assert customer.buddy_ip == "127.0.0.1"
    assert customer.buddy_tcp_port == 4711
    # Identity proof: a wrong echo must be rejected.
    bad = build_find_serving_buddy_res(
        xor_mask(bytes.fromhex("CD" * 16)), bytes.fromhex("9" * 32), 4711
    )
    assert customer.on_res(bad, "127.0.0.1") is False


def test_buddy_customer_tcp_registration_and_dial_back() -> None:
    async def scenario() -> None:
        # Internal watchdog: dump every pending task stack after 20 s.
        watchdog = asyncio.create_task(_watchdog())
        dialed: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        try:
            async def _accept_dial(reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> None:
                peer = writer.get_extra_info("peername")
                _stage(f"dial-target accepted from {peer}")
                await dialed.put((peer[0], peer[1], reader, writer))

            dial_target_server = await asyncio.start_server(
                _accept_dial, "127.0.0.1", 0,
            )
            dial_target_port = dial_target_server.sockets[0].getsockname()[1]
            _stage(f"dial target listening on {dial_target_port}")

            registered_kad_id: list[bytes] = []
            buddy_writer_box: list[asyncio.StreamWriter] = []

            async def handle_buddy(reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> None:
                try:
                    _stage("buddy TCP: connection accepted")
                    buddy_writer_box.append(writer)
                    header = await asyncio.wait_for(
                        reader.readexactly(6), _IO_TIMEOUT
                    )
                    _stage(
                        f"buddy TCP: HELLO header opcode={header[5]:#04x}"
                    )
                    assert header[0] == 0xE3 and header[5] == C2CTCP.HELLO
                    (length,) = struct.unpack("<I", header[1:5])
                    payload = await asyncio.wait_for(
                        reader.readexactly(length - 1), _IO_TIMEOUT
                    )
                    hello = parse_hello(payload)
                    tag = next(
                        (t for t in hello.tags if t.name_id == 0xBF), None
                    )
                    assert tag is not None, (
                        "registration HELLO lacks 0xBF tag"
                    )
                    registered_kad_id.append(bytes(tag.value))
                    ha_payload = (
                        bytes((0x10,)) + bytes.fromhex("9" * 32)
                        + struct.pack("<IH", 0, 0)
                    )
                    answer = bytes((0xE3,)) + struct.pack(
                        "<I", len(ha_payload) + 1
                    ) + bytes((C2CTCP.HELLOANSWER,)) + ha_payload
                    writer.write(answer)
                    await writer.drain()
                    _stage("buddy TCP: HELLOANSWER sent; holding channel")
                    await asyncio.sleep(3)
                    _stage("buddy TCP: hold window over")
                except Exception as exc:
                    _stage(f"buddy TCP handler error: {exc!r}")
                finally:
                    try:
                        writer.close()
                    except Exception:
                        pass

            buddy_server = await asyncio.start_server(
                handle_buddy, "127.0.0.1", 0
            )
            buddy_tcp_port = buddy_server.sockets[0].getsockname()[1]
            _stage(f"buddy server listening on {buddy_tcp_port}")

            async def _record_dial(ip: str, port: int) -> None:
                _stage(f"customer dial_back -> {ip}:{port}")
                reader, writer = await asyncio.open_connection(ip, port)
                _stage(f"customer dial_back connected to {ip}:{port}")

            customer = BuddyCustomer(
                own_kad_id=_OUR_KAD_ID,
                own_userhash=_OUR_USERHASH,
                own_tcp_port=4662,
                dial_back=_record_dial,
            )
            stop = asyncio.Event()
            assert customer.on_res(
                build_find_serving_buddy_res(
                    xor_mask(_OUR_KAD_ID), bytes.fromhex("9" * 32),
                    buddy_tcp_port,
                ),
                "127.0.0.1",
            )
            _stage("customer accepted the 0x5A")

            reg_task = asyncio.create_task(
                customer.run_registration(
                    connect=asyncio.open_connection, stop=stop,
                    idle_timeout=10.0,
                ),
                name="buddy-customer-registration",
            )
            for i in range(50):
                if buddy_writer_box:
                    break
                await asyncio.sleep(0.1)
            assert buddy_writer_box, "customer never registered"
            assert registered_kad_id == [_OUR_KAD_ID]
            _stage("registration HELLO verified (0xBF tag present)")

            relay_payload = (
                xor_mask(_OUR_KAD_ID)
                + bytes.fromhex("3" * 32)
                + struct.pack("<I", 0x7F000001)
                + struct.pack("<H", dial_target_port)
            )
            buddy_writer_box[0].write(
                bytes((0xC5,)) + struct.pack("<I", len(relay_payload) + 1)
                + bytes((OP_CALLBACK,)) + relay_payload
            )
            await buddy_writer_box[0].drain()
            _stage("OP_CALLBACK relay written into the buddy channel")

            peer_ip, peer_port, _r, _w = await asyncio.wait_for(
                dialed.get(), 15.0
            )
            assert peer_ip == "127.0.0.1", peer_ip
            # peer_port is the customer's ephemeral source port — the dial
            # itself (to dial_target_port) is the fact under test.
            _stage(f"dial verified (customer source port {peer_port})")

            stop.set()
            reg_task.cancel()
            for i in range(8):
                if reg_task.done():
                    break
                stack = reg_task.get_stack() or []
                frames = [
                    f"{f.f_code.co_name}:{f.f_lineno}" for f in stack
                ] or [("done" if reg_task.done() else "empty", 0)]
                _stage(f"reg_task cancelling: done={reg_task.done()} at={frames}")
                await asyncio.sleep(1)
            try:
                await reg_task
            except (asyncio.CancelledError, asyncio.TimeoutError, OSError):
                pass
            _stage("reg_task closed")

            # NOTE: on this CPython/Proactor build Server.wait_closed() can
            # block past handler completion (accept_coro + lingering client
            # sockets).  Server shutdown is test cleanup, not the fact under
            # test — bound it and swallow the timeout.
            dial_target_server.close()
            try:
                await asyncio.wait_for(
                    dial_target_server.wait_closed(), 5.0
                )
            except asyncio.TimeoutError:
                _stage("dial target server wait_closed timed out (ignored)")
            _stage("dial target server closed")
            buddy_server.close()
            try:
                await asyncio.wait_for(buddy_server.wait_closed(), 5.0)
            except asyncio.TimeoutError:
                _stage("buddy server wait_closed timed out (ignored)")
            _stage("buddy server closed")
        except BaseException as exc:
            _stage(f"SCENARIO EXCEPTION: {exc!r}")
            await _dump_all_tasks("scenario exception")
            raise
        finally:
            watchdog.cancel()
        _stage("SCENARIO COMPLETE")

    asyncio.run(scenario())


async def _watchdog() -> None:
    await asyncio.sleep(20.0)
    await _dump_all_tasks("20 s elapsed in scenario")
    # Keep dumping every 10 s so long hangs show evolving stacks.
    while True:
        await asyncio.sleep(10.0)
        await _dump_all_tasks("still running")
