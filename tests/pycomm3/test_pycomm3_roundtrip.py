"""End-to-end round-trip against pycomm3 — the de facto Python client for
Allen-Bradley Logix controllers.

Our own in-tree tests prove the server speaks to our own TagClient; this
proves it speaks the exact wire dialect pycomm3 (and by extension Studio
5000) expects.  Covers every atomic CIP type the server exposes, including
the Logix bit-string family and SHORT_STRING.

Skipped automatically if pycomm3 is not installed.
"""
from __future__ import annotations

import asyncio
import contextlib
import socket
import struct
import threading

import pytest

pycomm3 = pytest.importorskip("pycomm3")

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.logix import data_types as dt
from ethernetip.logix.logix_dispatcher import LogixDispatcher
from ethernetip.logix.tag_database import TagDatabase, TemplateMember
from ethernetip.protocol.eip_adapter import EipAdapter


# (name, type_code, initial_value, write_value) — bit-string types take a
# list of booleans per pycomm3's write encoding; atomics take a Python
# int/float/bool.
def _bits(value: int, width: int) -> list:
    return [bool((value >> i) & 1) for i in range(width)]


TYPES = [
    ("TestBool",         dt.BOOL,         True,       False),
    ("TestSint",         dt.SINT,         -5,         127),
    ("TestInt",          dt.INT,          -1234,      32000),
    ("TestDint",         dt.DINT,         -1_000_000, 2_000_000_000),
    ("TestLint",         dt.LINT,         -1,         0x7FFF_FFFF_FFFF_FFFF),
    ("TestUsint",        dt.USINT,        42,         0xFF),
    ("TestUint",         dt.UINT,         0xBEEF,     0xFFFF),
    ("TestUdint",        dt.UDINT,        0xDEADBEEF, 0xFFFF_FFFF),
    ("TestUlint",        dt.ULINT,        1_234_567_890_123, 0xFFFF_FFFF_FFFF_FFFF),
    ("TestReal",         dt.REAL,         3.14,       -2.71828),
    ("TestLreal",        dt.LREAL,        3.141592653589793, -2.718281828459045),
    ("TestByte",         dt.BYTE,         _bits(0xAB, 8),   _bits(0xCD, 8)),
    ("TestWord",         dt.WORD,         _bits(0x1234, 16), _bits(0xABCD, 16)),
    ("TestDword",        dt.DWORD,        _bits(0xDEADBEEF, 32), _bits(0xCAFEBABE, 32)),
    ("TestLword",        dt.LWORD,        _bits(0x1234_5678_9ABC_DEF0, 64),
                                           _bits(0xFEDC_BA98_7654_3210, 64)),
]

ATOMIC_STRUCT_FMT = {
    dt.BOOL:  '<B',
    dt.SINT:  '<b', dt.USINT: '<B',
    dt.INT:   '<h', dt.UINT:  '<H',
    dt.DINT:  '<i', dt.UDINT: '<I',
    dt.LINT:  '<q', dt.ULINT: '<Q',
    dt.REAL:  '<f', dt.LREAL: '<d',
}


def _grab_free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _seed_tag(tag, ty: int, value) -> None:
    if ty in (dt.BYTE, dt.WORD, dt.DWORD, dt.LWORD) and isinstance(value, list):
        n_bytes = {dt.BYTE: 1, dt.WORD: 2, dt.DWORD: 4, dt.LWORD: 8}[ty]
        n = 0
        for i, b in enumerate(value):
            if b:
                n |= 1 << i
        tag.set_data(n.to_bytes(n_bytes, "little"))
        return
    tag.set_data(struct.pack(ATOMIC_STRUCT_FMT[ty],
                              int(value) if isinstance(value, bool) else value))


async def _spawn_server(port: int) -> tuple[EipAdapter, asyncio.Task]:
    identity = IdentityInfo(
        vendor_id=1, device_type=0x0E, product_code=65,
        major_revision=20, minor_revision=11,
        serial_number=0x1234_5678,
        product_name="PyCommRoundTripTarget",
    )
    tags = TagDatabase()
    for name, ty, initial, _ in TYPES:
        _seed_tag(tags.add_tag(name, ty), ty, initial)
    tags.add_tag("TestShortString", dt.SHORT_STRING)

    # ---- Yellow-row coverage ---------------------------------------------
    # 1-D array of atomics, bit of atomic, BOOL array, multi-dim array.
    arr = tags.add_tag("DintArr", dt.DINT, element_count=10)
    arr.set_data(b"".join(struct.pack("<i", 100 + i) for i in range(10)))
    tags.add_tag("FlagsDint", dt.DINT).set_data(struct.pack("<I", 0b1010_1010_1010_1010))
    tags.add_tag("Flags32", dt.BOOL, element_count=32)
    mat = tags.add_tag("Matrix", dt.DINT, dims=(2, 3))
    mat.set_data(b"".join(struct.pack("<i", 10 * r + c) for r in range(2) for c in range(3)))

    # Logix STRING UDT (LEN:DINT + DATA:SINT[82], 88 bytes).
    string_tpl = tags.add_template(
        "STRING",
        TemplateMember("LEN", dt.DINT),
        TemplateMember("DATA", dt.SINT, array_size=82),
    )
    greet = tags.add_struct_tag("Greeting", string_tpl)
    buf = bytearray(88)
    hello = b"Hello pycomm3"
    struct.pack_into('<i', buf, 0, len(hello))
    buf[4:4 + len(hello)] = hello
    greet.set_data(bytes(buf))
    tags.add_struct_tag("GreetingArr", string_tpl, element_count=3)

    # User UDT with atomic + BOOL + atomic.
    motor_tpl = tags.add_template(
        "Motor",
        TemplateMember("Speed", dt.REAL),
        TemplateMember("Fault", dt.BOOL),
        TemplateMember("RunCount", dt.DINT),
    )
    motor_a = tags.add_struct_tag("MotorA", motor_tpl)
    buf = bytearray(motor_tpl.structure_size)
    struct.pack_into("<f", buf, 0, 3.14)
    buf[4] = 1
    struct.pack_into("<i", buf, 8, 42)
    motor_a.set_data(bytes(buf))
    tags.add_struct_tag("MotorArr", motor_tpl, element_count=3)

    # TIMER / COUNTER / CONTROL / AOI-backing proof: all four are "just UDTs"
    # from pycomm3's perspective — same access pattern as Motor.*, same
    # Template Object plumbing.  Register a Logix-shape TIMER (EN, TT, DN,
    # PRE, ACC) and an AOI-shape UDT and seed them so the test can prove
    # MyTimer.PRE / MyTimer.EN / MyAOI.Enable all round-trip.
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
    buf[0] = 1              # EN = True
    struct.pack_into("<i", buf, timer_tpl.members[3].byte_offset, 1000)  # PRE
    struct.pack_into("<i", buf, timer_tpl.members[4].byte_offset, 250)   # ACC
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
    buf[aoi_tpl.members[0].byte_offset] = 1  # Enable = True
    struct.pack_into("<f", buf, aoi_tpl.members[1].byte_offset, 42.5)
    buf[aoi_tpl.members[2].byte_offset] = 0  # Done = False
    struct.pack_into("<i", buf, aoi_tpl.members[3].byte_offset, 7)
    my_aoi.set_data(bytes(buf))
    # ----------------------------------------------------------------------

    dispatcher = LogixDispatcher(tags=tags, identity=identity)
    adapter = EipAdapter(dispatcher, identity)
    task = asyncio.create_task(adapter.listen("127.0.0.1", port))
    await asyncio.sleep(0.1)
    return adapter, task


async def _teardown(adapter: EipAdapter, task: asyncio.Task) -> None:
    await adapter.close()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


def _values_match(ty_code: int, got, expected) -> bool:
    if ty_code == dt.BOOL:
        return bool(got) == bool(expected)
    if ty_code == dt.REAL:
        return abs(float(got) - float(expected)) < 1e-5
    if ty_code == dt.LREAL:
        return abs(float(got) - float(expected)) < 1e-12
    if ty_code == dt.DWORD:
        # pycomm3 collapses a raw DWORD read to bit 0 — see the full-32 test
        # below for the proof that the server stored the whole thing.
        exp_bit = expected[0] if isinstance(expected, (list, tuple)) else bool(expected & 1)
        return bool(got) == exp_bit
    if ty_code in (dt.BYTE, dt.WORD, dt.LWORD):
        got_list = list(got) if isinstance(got, (list, tuple)) else [got]
        exp_list = list(expected) if isinstance(expected, (list, tuple)) else [expected]
        return got_list == exp_list
    return got == expected


def _pycomm3_worker(port: int, out: dict) -> None:
    from pycomm3 import LogixDriver
    try:
        with LogixDriver(f"127.0.0.1:{port}", init_tags=True, init_program_tags=False) as plc:
            out["tag_names"] = sorted(plc.tags.keys())
            per_type = {}
            for name, ty, initial, write_val in TYPES:
                r = plc.read(name)
                if r.error:
                    per_type[name] = ("read-init-error", r.error)
                    continue
                initial_ok = _values_match(ty, r.value, initial)
                w = plc.write((name, write_val))
                if w.error:
                    per_type[name] = ("write-error", w.error)
                    continue
                r2 = plc.read(name)
                if r2.error:
                    per_type[name] = ("read-back-error", r2.error)
                    continue
                readback_ok = _values_match(ty, r2.value, write_val)
                per_type[name] = ("ok" if initial_ok and readback_ok else "mismatch",
                                   {"initial": r.value, "wrote": write_val, "back": r2.value,
                                    "initial_ok": initial_ok, "readback_ok": readback_ok})
            # DWORD full-32 proof read
            r = plc.read("TestDword{32}")
            per_type["TestDword{32}"] = ("ok" if not r.error and list(r.value) == _bits(0xCAFEBABE, 32)
                                          else "mismatch", {"val": list(r.value) if r.value else None})
            # SHORT_STRING round-trip
            r = plc.read("TestShortString")
            if r.error:
                per_type["TestShortString"] = ("read-init-error", r.error)
            else:
                w = plc.write(("TestShortString", "hello"))
                if w.error:
                    per_type["TestShortString"] = ("write-error", w.error)
                else:
                    r2 = plc.read("TestShortString")
                    per_type["TestShortString"] = ("ok" if r2.value == "hello" else "mismatch",
                                                     {"back": r2.value})

            # --- Yellow rows ---------------------------------------------------
            def check(label: str, cond: bool, detail=""):
                per_type[label] = ("ok" if cond else "mismatch", detail)

            # Row 17: 1-D array indexed read/write
            r = plc.read("DintArr[5]"); check("17 DintArr[5] read", not r.error and r.value == 105, r)
            w = plc.write(("DintArr[5]", 999)); r2 = plc.read("DintArr[5]")
            check("17 DintArr[5] round-trip", not w.error and r2.value == 999, {"w": w.error, "back": r2.value})

            # Row 18: whole array
            r = plc.read("DintArr{10}")
            check("18 DintArr{10}", not r.error and list(r.value)[0] == 100 and list(r.value)[9] == 109,
                  {"err": r.error, "vals": list(r.value) if r.value else None})

            # Row 19 + 20: fragmented read + write
            w = plc.write(("DintArr{10}", list(range(1000, 1010))))
            r = plc.read("DintArr{10}")
            check("19-20 fragmented r/w", not w.error and list(r.value) == list(range(1000, 1010)),
                  {"w": w.error, "back": list(r.value) if r.value else None})

            # Row 21: bit of atomic
            r = plc.read("FlagsDint.1"); check("21 FlagsDint.1 read", not r.error and bool(r.value) is True, r)
            w = plc.write(("FlagsDint.0", True)); r2 = plc.read("FlagsDint.0")
            check("21 FlagsDint bit write", not w.error and bool(r2.value) is True, {"w": w.error, "back": r2.value})

            # Row 22: BOOL array
            r = plc.read("Flags32[3]")
            check("22 Flags32[3] read", not r.error, {"err": r.error, "val": r.value})
            w = plc.write(("Flags32[7]", True)); r2 = plc.read("Flags32[7]")
            check("22 Flags32 bit write", not w.error and bool(r2.value) is True, {"w": w.error, "back": r2.value})

            # Row 23: multi-dim array
            r = plc.read("Matrix[1,2]")
            check("23 Matrix[1,2] read", not r.error and r.value == 12, {"err": r.error, "val": r.value})
            w = plc.write(("Matrix[0,1]", 777)); r2 = plc.read("Matrix[0,1]")
            check("23 Matrix write", not w.error and r2.value == 777, {"w": w.error, "back": r2.value})

            # Row 24: Logix STRING UDT whole-struct round-trip
            r = plc.read("Greeting")
            check("24 Greeting read", not r.error and r.value == "Hello pycomm3", {"err": r.error, "val": r.value})
            w = plc.write(("Greeting", "written back")); r2 = plc.read("Greeting")
            check("24 Greeting round-trip", not w.error and r2.value == "written back",
                  {"w": w.error, "back": r2.value})

            # Row 25: STRING array
            w = plc.write(("GreetingArr[1]", "second"))
            r = plc.read("GreetingArr[1]")
            check("25 GreetingArr[1]", not w.error and not r.error and r.value == "second",
                  {"w": w.error, "r": r.error, "val": r.value})

            # Row 26: UDT whole-struct read
            r = plc.read("MotorA")
            check("26 MotorA whole-struct",
                  not r.error and isinstance(r.value, dict) and abs(r.value["Speed"] - 3.14) < 1e-4 and r.value["Fault"] is True and r.value["RunCount"] == 42,
                  {"err": r.error, "val": r.value})

            # Row 27: UDT member access
            r = plc.read("MotorA.Speed")
            check("27 MotorA.Speed", not r.error and abs(r.value - 3.14) < 1e-5, {"err": r.error, "val": r.value})
            r = plc.read("MotorA.RunCount")
            check("27 MotorA.RunCount", not r.error and r.value == 42, {"err": r.error, "val": r.value})
            w = plc.write(("MotorA.Speed", -1.5)); r2 = plc.read("MotorA.Speed")
            check("27 MotorA.Speed write", not w.error and abs(r2.value - (-1.5)) < 1e-5, {"w": w.error, "back": r2.value})

            # Row 29: BOOL member of UDT
            r = plc.read("MotorA.Fault")
            check("29 MotorA.Fault read", not r.error and bool(r.value) is True, {"err": r.error, "val": r.value})
            w = plc.write(("MotorA.Fault", False)); r2 = plc.read("MotorA.Fault")
            check("29 MotorA.Fault write", not w.error and bool(r2.value) is False, {"w": w.error, "back": r2.value})

            # Row 31: array of UDTs with member access
            w = plc.write(("MotorArr[1].Speed", 7.77))
            r = plc.read("MotorArr[1].Speed")
            check("31 MotorArr[1].Speed", not w.error and not r.error and abs(r.value - 7.77) < 1e-4,
                  {"w": w.error, "r": r.error, "val": r.value})

            # TIMER UDT — same access pattern as a user UDT; this is just an
            # explicit witness that `MyTimer.PRE` and `MyTimer.EN` work.
            r = plc.read("MyTimer.PRE")
            check("TIMER MyTimer.PRE read", not r.error and r.value == 1000, {"err": r.error, "val": r.value})
            r = plc.read("MyTimer.EN")
            check("TIMER MyTimer.EN read", not r.error and bool(r.value) is True, {"err": r.error, "val": r.value})
            w = plc.write(("MyTimer.PRE", 2000)); r = plc.read("MyTimer.PRE")
            check("TIMER MyTimer.PRE write", not w.error and r.value == 2000, {"w": w.error, "back": r.value})
            w = plc.write(("MyTimer.EN", False)); r = plc.read("MyTimer.EN")
            check("TIMER MyTimer.EN write", not w.error and bool(r.value) is False, {"w": w.error, "back": r.value})

            # AOI-backing UDT — same mechanism, confirming AOI tags are not
            # special on the wire.
            r = plc.read("MyAOI.Enable")
            check("AOI MyAOI.Enable read", not r.error and bool(r.value) is True, {"err": r.error, "val": r.value})
            r = plc.read("MyAOI.Setpoint")
            check("AOI MyAOI.Setpoint read", not r.error and abs(r.value - 42.5) < 1e-5, {"err": r.error, "val": r.value})
            w = plc.write(("MyAOI.Setpoint", 99.9)); r = plc.read("MyAOI.Setpoint")
            check("AOI MyAOI.Setpoint write", not w.error and abs(r.value - 99.9) < 1e-5, {"w": w.error, "back": r.value})
            w = plc.write(("MyAOI.Enable", False)); r = plc.read("MyAOI.Enable")
            check("AOI MyAOI.Enable write", not w.error and bool(r.value) is False, {"w": w.error, "back": r.value})

            # Row 39-40: multi-service batch read & write
            batch = plc.read("DintArr[0]", "DintArr[1]", "DintArr[2]")
            check("39 batch read",
                  all(not t.error for t in batch) and [t.value for t in batch] == [1000, 1001, 1002],
                  [(t.tag, t.value, t.error) for t in batch])
            res = plc.write(("DintArr[0]", 5000), ("DintArr[1]", 5001), ("DintArr[2]", 5002))
            r = plc.read("DintArr[0]", "DintArr[1]", "DintArr[2]")
            check("40 batch write",
                  all(not t.error for t in res) and [t.value for t in r] == [5000, 5001, 5002],
                  {"res_errs": [t.error for t in res], "back": [t.value for t in r]})

            out["per_type"] = per_type
    except Exception as exc:
        import traceback
        out["connection_error"] = f"{exc!r}\n{traceback.format_exc()}"


@pytest.mark.asyncio
async def test_pycomm3_every_atomic_type_round_trips():
    port = _grab_free_port()
    adapter, task = await _spawn_server(port)
    try:
        out: dict = {}
        thread = threading.Thread(target=_pycomm3_worker, args=(port, out))
        thread.start()
        while thread.is_alive():
            await asyncio.sleep(0.05)
        thread.join()
    finally:
        await _teardown(adapter, task)

    assert "connection_error" not in out, out.get("connection_error")

    tag_names = out["tag_names"]
    expected_names = {t[0] for t in TYPES} | {"TestShortString"}
    missing = expected_names - set(tag_names)
    assert not missing, f"pycomm3 did not enumerate: {missing}"

    per_type = out["per_type"]
    failures = {k: v for k, v in per_type.items() if v[0] != "ok"}
    assert not failures, f"pycomm3 round-trip failures:\n{failures}"
