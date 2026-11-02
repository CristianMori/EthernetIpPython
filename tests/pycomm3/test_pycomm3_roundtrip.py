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
from ethernetip.logix.tag_database import TagDatabase
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
