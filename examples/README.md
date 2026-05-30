# EthernetIPPython Samples

Runnable examples demonstrating each major feature of the library. All samples
are self-contained — they add `../src` to `sys.path` so they work from a fresh
clone with no install.

| Sample | What it does | Hardware needed |
|--------|--------------|------------------|
| [`echo_module.py`](#echo_module) | Generic EtherNet/IP I/O adapter (echo module) | A PLC or scanner that opens a Class 1 connection |
| [`logix_host.py`](#logix_host) | Logix controller simulator with preloaded tags. pycomm3-compatible. | A pycomm3 client (or any tag-reading scanner) |
| [`cip_echo_server.py`](#cip_echo_server) | Catch-all CIP server — logs any unhandled request, optionally returns N bytes of incremental data. Handles UCMM + Class 3. | A scanner or PLC MSG instruction |
| [`connected_explicit_smoke.py`](#connected_explicit_smoke) | Scanner-side smoke: UCMM + Class 3 round-trips against an adapter that supports both | A target adapter (works with `cip_echo_server.py` or `echo_module.py`) |
| [`safety_adapter.py`](#safety_adapter) | CIP Safety adapter (target side) | A safety-capable scanner (e.g. ControlLogix with safety task) |
| [`safety_scanner_loopback.py`](#safety_scanner_loopback) | Scanner + adapter in one process | None — pure loopback |
| [`safety_scanner_1734.py`](#safety_scanner_1734) | CIP Safety scanner against a real 1734 I/O module | Allen-Bradley 1734-IB8S behind 1734-ENT |

---

## echo_module.py

Generic EtherNet/IP adapter that responds to Forward Open / Class 1 cyclic I/O.
Two assemblies (input + output) plus a config assembly, sized for a 125-DINT
Studio 5000 Generic Ethernet Module. Pre-fills the input assembly with a ramp
1..125 and echoes a per-tick counter back to the PLC.

```sh
python examples/echo_module.py                        # default 0.0.0.0:44818
python examples/echo_module.py 192.168.1.84 44818     # specific bind/port
```

Heartbeat line shows incoming Output[0] and outgoing Input[0] each tick.

---

## safety_adapter.py

CIP Safety adapter that registers a Safety Supervisor and Safety Validator,
accepts safety Forward Opens (Base or Extended format), and runs the full
producer/consumer state machine: CRC encode/decode, TCOO time coordination
with CTCV slew, ping-change detection, originator-rollover tracking.

```sh
python examples/safety_adapter.py                            # plc profile (192.168.1.84)
python examples/safety_adapter.py --profile=test2            # synthetic test profile
python examples/safety_adapter.py --bind=10.0.0.5 --vendor=12 --snn=4D90_0101_A35C --node=0x0A000005
```

CLI options (all optional; profile sets the defaults):

- `--profile=<plc|test2>` — pick a preconfigured target
- `--bind=<ip>` — local IP to bind on
- `--vendor=<n>` — vendor ID (1 = Rockwell)
- `--serial=<hex>` — device serial number (e.g. `0xC0FFEE42`)
- `--product=<text>` — Identity object product name
- `--snn=<hex_6bytes>` — Safety Network Number (12 hex chars, e.g. `4D90_0101_A35C`)
- `--node=<hex>` — safety node address (your IP packed BE as uint32)
- `--asm-data1`, `--asm-data2`, `--asm-config` — assembly instance IDs
- `--halt-threshold=<sec>` — exit if a long-running connection drops (default 60)
- `--startup-trace=<sec>` — emit per-frame trace lines during the first N seconds
- `--trace=1` — verbose per-frame logging (use only when actively debugging)

Verified against a real ControlLogix PLC — held two Extended-Format safety
connections (server + client) for 40+ minutes at 100 fps with zero drops and
zero CPCRC errors.

---

## safety_scanner_loopback.py

Spins up the Python `SafetyDevice` (adapter) and a `SafetyScannerConnection`
(scanner) in the same process. The scanner connects back to the adapter over
localhost, opens both safety connections, and exchanges 1-byte safety data for
10 seconds. Useful for validating the scanner without depending on real
hardware.

```sh
python examples/safety_scanner_loopback.py
```

Demonstrates the full round-trip: scanner produces `0xA5` to the adapter's
input assembly, adapter produces from the same assembly back to the scanner,
scanner receives `0xA5`. The test uses generous timings (50ms RPI, 32x
connection timeout multiplier) because `asyncio.sleep` on Windows has ~15ms
granularity and tighter RPIs trigger watchdog timeouts that aren't true
failures.

---

## safety_scanner_1734.py

CIP Safety scanner against a real 1734-IB8S Safety Discrete Input module
behind a 1734-ENT EtherNet/IP adapter. Spoofs a Rockwell originator identity,
sends Propose/Apply TUNID and the safety Forward Opens with CPCRC, then runs
the producer/consumer state machine for 60 seconds at the 1734's native 10ms
RPI.

```sh
python examples/safety_scanner_1734.py                       # defaults: 192.168.1.76 slot 1
python examples/safety_scanner_1734.py 192.168.1.200 3       # custom IP and slot
```

Defaults are baked in for a specific 1734-IB8S setup — change them to match
your hardware:

- Target IP: `192.168.1.76`
- Backplane slot: `1`
- Target SNN, TUNID, SCID: hard-coded constants in `main()`
- Originator vendor: `0x0001` (Rockwell), serial `0x012FE10E`

Verified against a real 1734-IB8S — sustained 6025 frames over 60 seconds
(100 fps) with zero CRC failures across multiple timestamp rollovers.

The scanner binds UDP port 2222 explicitly (separately from the EipScanner's
ephemeral port) because the 1734 sends safety frames to the originator's
2222 by spec.

---

## logix_host.py <a id="logix_host"></a>

Logix 5000-style controller simulator. Wraps `LogixDispatcher` (Symbol /
Template / Message Router / Connection Manager / Identity / Program Name)
behind an `EipAdapter`. Three preloaded tags: `rate` (DINT=534),
`temperature` (REAL=72.5), `counts` (INT[10]). Compatible with the C++ port's
`samples/logix_host/pycomm3_smoke.py` regression test — verified against
pycomm3 (browse + scalar/array reads + writes + 10-element slice, all pass).

```sh
python examples/logix_host.py                          # default 0.0.0.0:44818
python examples/logix_host.py 192.168.1.84 44818       # specific bind/port
```

---

## cip_echo_server.py <a id="cip_echo_server"></a>

Catch-all CIP echo server. Registers Identity + Connection Manager so
RegisterSession / ListIdentity / Forward Open all work; anything else
(unknown class, instance, service, attribute) lands in a `CatchAllDispatcher`
handler that prints the request and returns a fixed-size reply of
incremental bytes (0, 1, 2, …, `reply_bytes`-1).

Handles both **unconnected** (SendRRData wrapping Unconnected Send) and
**Class 3 connected** (SendUnitData after a Class 3 Forward Open) requests.
Useful for capturing exactly what a Logix MSG instruction sends, or for
testing a scanner's UCMM and Class 3 paths against a known target.

```sh
python examples/cip_echo_server.py                              # 0.0.0.0:44818, empty reply
python examples/cip_echo_server.py 0.0.0.0 44819 20             # 20-byte incremental reply
```

Verified against a live ControlLogix MSG instruction (both unconnected and
connected variants captured, reply payload routed back to a Destination Tag).

---

## connected_explicit_smoke.py <a id="connected_explicit_smoke"></a>

Scanner-side smoke test. Exercises three round-trips against any adapter
that supports both UCMM and Class 3 explicit messaging:

1. UCMM `GetAttributeSingle` on Identity attr 7 (via `EipScanner.send_explicit`)
2. Class 3 `GetAttributeSingle` on Identity attr 7 (via `ConnectedExplicit.send`)
3. Class 3 catch-all custom message — `svc=0xCD class=0xDE inst=2 attr=156`
   with a 7-DINT payload — exercises the unhandled-service path.

```sh
python examples/connected_explicit_smoke.py                     # 127.0.0.1:44818
python examples/connected_explicit_smoke.py 127.0.0.1 44819     # custom port
```

Pair this with the C++ `cip_echo_server` on the same machine and a
non-44818 port to verify the scanner-side stack without disturbing any
live I/O adapter on the standard port.
