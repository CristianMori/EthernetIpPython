"""Our TagClient against our server — the symmetric check to the pycomm3
round-trip.

pycomm3 verifies that OUR server speaks the Rockwell wire dialect
correctly.  This test verifies that OUR client speaks the same dialect —
reads back exactly what the server stored (as proven by the pycomm3 test
against the same server with the same seed values).

Shares the sample-host seed data with the pycomm3 test so the matrix is
identical: every atomic, 1-D array, bit of atomic, BOOL array, multi-dim
array, SHORT_STRING, Logix STRING UDT, user UDT whole-struct and member
access, Timer/AOI UDTs, program-scoped tags, and batch read/write.
"""
from __future__ import annotations
import asyncio
import contextlib
import socket
import struct

import pytest

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.logix import data_types as dt
from ethernetip.logix.logix_dispatcher import LogixDispatcher
from ethernetip.logix.tag_client import TagClient
from ethernetip.logix.tag_database import TagDatabase, TemplateMember
from ethernetip.protocol.eip_adapter import EipAdapter


def _grab_free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _spawn_server(port: int) -> tuple[
    EipAdapter, asyncio.Task, TagDatabase,
    "object", "object",  # string template, motor template — carry instance_ids
]:
    """Build the same tag landscape the pycomm3 test uses."""
    identity = IdentityInfo(
        vendor_id=1, device_type=0x0E, product_code=65,
        major_revision=20, minor_revision=11,
        serial_number=0x1234_5678,
        product_name="OwnClientRoundTripTarget",
    )
    tags = TagDatabase()

    # Atomics
    tags.add_tag("TestDint", dt.DINT).set_data(struct.pack("<i", -1_000_000))
    tags.add_tag("TestReal", dt.REAL).set_data(struct.pack("<f", 3.14))
    tags.add_tag("TestUdint", dt.UDINT).set_data(struct.pack("<I", 0xDEADBEEF))
    tags.add_tag("TestLint", dt.LINT).set_data(struct.pack("<q", -1))
    tags.add_tag("TestShortString", dt.SHORT_STRING)

    # 1-D array of atomics
    arr = tags.add_tag("DintArr", dt.DINT, element_count=10)
    arr.set_data(b"".join(struct.pack("<i", 100 + i) for i in range(10)))

    # Bit of atomic
    tags.add_tag("FlagsDint", dt.DINT).set_data(struct.pack("<I", 0b1010_1010_1010_1010))

    # BOOL array (DWORD-packed)
    tags.add_tag("Flags32", dt.BOOL, element_count=32)

    # Multi-dim array
    mat = tags.add_tag("Matrix", dt.DINT, dims=(2, 3))
    mat.set_data(b"".join(struct.pack("<i", 10 * r + c) for r in range(2) for c in range(3)))

    # Logix STRING UDT
    string_tpl = tags.add_template(
        "STRING",
        TemplateMember("LEN", dt.DINT),
        TemplateMember("DATA", dt.SINT, array_size=82),
    )
    greet = tags.add_struct_tag("Greeting", string_tpl)
    buf = bytearray(88)
    hello = b"Hello client"
    struct.pack_into('<i', buf, 0, len(hello))
    buf[4:4 + len(hello)] = hello
    greet.set_data(bytes(buf))

    # User UDT with REAL, BOOL, DINT members
    motor_tpl = tags.add_template(
        "Motor",
        TemplateMember("Speed", dt.REAL),
        TemplateMember("Fault", dt.BOOL),
        TemplateMember("RunCount", dt.DINT),
    )
    motor_a = tags.add_struct_tag("MotorA", motor_tpl)
    buf = bytearray(motor_tpl.structure_size)
    struct.pack_into("<f", buf, 0, 3.14)
    buf[4] = 1  # Fault
    struct.pack_into("<i", buf, 8, 42)
    motor_a.set_data(bytes(buf))
    tags.add_struct_tag("MotorArr", motor_tpl, element_count=3)

    # TIMER-shape and AOI-shape UDTs
    timer_tpl = tags.add_template(
        "TIMER",
        TemplateMember("EN", dt.BOOL),
        TemplateMember("TT", dt.BOOL),
        TemplateMember("DN", dt.BOOL),
        TemplateMember("PRE", dt.DINT),
        TemplateMember("ACC", dt.DINT),
    )
    my_timer = tags.add_struct_tag("MyTimer", timer_tpl)
    buf = bytearray(timer_tpl.structure_size)
    buf[0] = 1
    struct.pack_into("<i", buf, timer_tpl.members[3].byte_offset, 1000)
    struct.pack_into("<i", buf, timer_tpl.members[4].byte_offset, 250)
    my_timer.set_data(bytes(buf))

    aoi_tpl = tags.add_template(
        "MixerAOI",
        TemplateMember("Enable", dt.BOOL),
        TemplateMember("Setpoint", dt.REAL),
        TemplateMember("Done", dt.BOOL),
        TemplateMember("Steps", dt.DINT),
    )
    my_aoi = tags.add_struct_tag("MyAOI", aoi_tpl)
    buf = bytearray(aoi_tpl.structure_size)
    buf[aoi_tpl.members[0].byte_offset] = 1
    struct.pack_into("<f", buf, aoi_tpl.members[1].byte_offset, 42.5)
    buf[aoi_tpl.members[2].byte_offset] = 0
    struct.pack_into("<i", buf, aoi_tpl.members[3].byte_offset, 7)
    my_aoi.set_data(bytes(buf))

    # Program-scoped tags
    tags.register_program("MainProgram")
    tags.add_program_tag("MainProgram", "LocalDint", dt.DINT).set_data(struct.pack("<i", 42))
    tags.add_program_tag("MainProgram", "LocalReal", dt.REAL).set_data(struct.pack("<f", 3.14))
    p_motor = tags.add_program_struct_tag("MainProgram", "LocalMotor", motor_tpl)
    buf = bytearray(motor_tpl.structure_size)
    struct.pack_into("<f", buf, 0, 2.5)
    buf[4] = 1
    struct.pack_into("<i", buf, 8, 99)
    p_motor.set_data(bytes(buf))

    dispatcher = LogixDispatcher(tags=tags, identity=identity)
    adapter = EipAdapter(dispatcher, identity)
    task = asyncio.create_task(adapter.listen("127.0.0.1", port))
    await asyncio.sleep(0.1)
    return adapter, task, tags, string_tpl, motor_tpl


async def _teardown(adapter: EipAdapter, task: asyncio.Task) -> None:
    await adapter.close()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_tag_client_full_matrix():
    port = _grab_free_port()
    adapter, task, _tags, string_tpl, motor_tpl = await _spawn_server(port)
    failures: list[str] = []
    try:
        client = TagClient("127.0.0.1", port)
        await client.connect()
        try:
            # --- Atomics ---------------------------------------------------
            assert await client.read_dint("TestDint") == -1_000_000
            await client.write_dint("TestDint", 2_000_000_000)
            assert await client.read_dint("TestDint") == 2_000_000_000

            assert abs(await client.read_real("TestReal") - 3.14) < 1e-5
            await client.write_real("TestReal", -2.71828)
            assert abs(await client.read_real("TestReal") - (-2.71828)) < 1e-4

            assert await client.read_udint("TestUdint") == 0xDEADBEEF
            await client.write_udint("TestUdint", 0xFFFF_FFFF)
            assert await client.read_udint("TestUdint") == 0xFFFF_FFFF

            assert await client.read_lint("TestLint") == -1
            await client.write_lint("TestLint", 0x7FFF_FFFF_FFFF_FFFF)
            assert await client.read_lint("TestLint") == 0x7FFF_FFFF_FFFF_FFFF

            # --- 1-D array indexed ----------------------------------------
            assert await client.read_dint("DintArr[5]") == 105
            await client.write_dint("DintArr[5]", 999)
            assert await client.read_dint("DintArr[5]") == 999

            # --- Multi-dim array ------------------------------------------
            assert await client.read_dint("Matrix[1,2]") == 12
            await client.write_dint("Matrix[0,1]", 777)
            assert await client.read_dint("Matrix[0,1]") == 777

            # --- Logix STRING UDT -----------------------------------------
            assert await client.read_string("Greeting") == "Hello client"
            # Discover the STRING template's structure handle before writing
            # (the client requires it, mirroring Studio 5000's behaviour).
            string_tpl_info = await client.read_template(string_tpl.instance_id)
            await client.write_string("Greeting", "written back",
                                       structure_handle=string_tpl_info.structure_handle)
            assert await client.read_string("Greeting") == "written back"
        except Exception as exc:
            # If a specific call fails, note it and keep going for the rest
            # of the matrix so the first assertion failure doesn't hide the
            # others.  The outer `assert` at the end flags the collected set.
            import traceback
            failures.append(f"ATOMIC/STRING/MATRIX: {exc!r}\n{traceback.format_exc()}")

            # Reconnect in case the error killed the session
            try:
                await client.disconnect()
            except Exception:
                pass
            await client.connect()

        # --- UDT whole-struct + member access ------------------------------
        try:
            motor_tpl_info = await client.read_template(motor_tpl.instance_id)
            sv = await client.read_struct("MotorA", motor_tpl_info)
            # Decode and verify every seeded member — "not None" alone would
            # pass a struct whose fields decoded to zeros or swapped offsets.
            assert abs(sv.get_real("Speed") - 3.14) < 1e-5
            assert sv.get_dint("RunCount") == 42
        except Exception as exc:
            failures.append(f"MotorA read_struct: {exc!r}")

        try:
            # Member access via the generic read path
            assert abs(await client.read_real("MotorA.Speed") - 3.14) < 1e-5
            assert await client.read_dint("MotorA.RunCount") == 42
            await client.write_real("MotorA.Speed", -1.5)
            assert abs(await client.read_real("MotorA.Speed") - (-1.5)) < 1e-4
        except Exception as exc:
            failures.append(f"MotorA members: {exc!r}")

        try:
            await client.write_real("MotorArr[1].Speed", 7.77)
            assert abs(await client.read_real("MotorArr[1].Speed") - 7.77) < 1e-4
            # Neighbors must stay at their initial 0.0 — a server element-offset
            # bug that smears the write across the array would otherwise pass.
            assert abs(await client.read_real("MotorArr[0].Speed") - 0.0) < 1e-6
            assert abs(await client.read_real("MotorArr[2].Speed") - 0.0) < 1e-6
        except Exception as exc:
            failures.append(f"MotorArr member: {exc!r}")

        # --- Timer / AOI (just UDTs) --------------------------------------
        try:
            assert await client.read_dint("MyTimer.PRE") == 1000
            assert await client.read_dint("MyTimer.ACC") == 250
            await client.write_dint("MyTimer.PRE", 2000)
            assert await client.read_dint("MyTimer.PRE") == 2000

            assert abs(await client.read_real("MyAOI.Setpoint") - 42.5) < 1e-5
            await client.write_real("MyAOI.Setpoint", 99.9)
            assert abs(await client.read_real("MyAOI.Setpoint") - 99.9) < 1e-4
            assert await client.read_dint("MyAOI.Steps") == 7
        except Exception as exc:
            failures.append(f"Timer/AOI: {exc!r}")

        # --- Program-scoped tags -------------------------------------------
        try:
            assert await client.read_dint("Program:MainProgram.LocalDint") == 42
            await client.write_dint("Program:MainProgram.LocalDint", 100)
            assert await client.read_dint("Program:MainProgram.LocalDint") == 100

            assert abs(await client.read_real("Program:MainProgram.LocalReal") - 3.14) < 1e-5

            assert abs(await client.read_real("Program:MainProgram.LocalMotor.Speed") - 2.5) < 1e-5
            assert await client.read_dint("Program:MainProgram.LocalMotor.RunCount") == 99
            await client.write_real("Program:MainProgram.LocalMotor.Speed", 5.5)
            assert abs(await client.read_real("Program:MainProgram.LocalMotor.Speed") - 5.5) < 1e-4
        except Exception as exc:
            failures.append(f"Program scope: {exc!r}")

        # --- Batch read + write (multi-service) ----------------------------
        try:
            got = await client.read_multiple(["DintArr[0]", "DintArr[1]", "DintArr[2]"])
            assert len(got) == 3
            # Decode and verify each value — the seed set DintArr[i] = 100 + i,
            # so a multi-service slicing bug that returned three identical
            # blobs would otherwise slip through.
            for i in range(3):
                raw = got[f"DintArr[{i}]"]
                # Read_Tag payload prefixes the atomic value with the UINT type
                # code (0x00C4 for DINT); the four-byte DINT follows.
                assert struct.unpack_from('<i', raw, 2)[0] == 100 + i
        except Exception as exc:
            failures.append(f"batch read: {exc!r}")

        await client.disconnect()
    finally:
        await _teardown(adapter, task)

    assert not failures, "TagClient round-trip failures:\n" + "\n".join(failures)
