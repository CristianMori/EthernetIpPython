# EthernetIPPython

A complete EtherNet/IP and CIP Safety protocol stack written in Python 3 (asyncio). Acts as **adapter** (target / I/O slave), **scanner** (originator / I/O master), or **Logix-compatible tag server / client** — with or without CIP Safety. Tested against real Allen-Bradley ControlLogix and CompactLogix PLCs as well as 1734 distributed safety I/O modules.

The library is organised into independent subpackages so you can use only the parts you need: import `ethernetip.cip` if you just want a CIP message router, add `ethernetip.device` for I/O assemblies, layer on `ethernetip.safety` if you need a SIL-3-style safety connection, or use `ethernetip.logix` for symbolic tag access against a real PLC.

This is a pure-Python port of [EthernetIPSharp](../EthernetIPSharp). All three ports (C#, Python, C++) share the same architecture and are wire-compatible.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Project layout](#project-layout)
- [Quick start](#quick-start)
  - [Standard adapter (Generic Ethernet Module)](#standard-adapter-generic-ethernet-module)
  - [CIP Safety adapter](#cip-safety-adapter)
  - [Standard I/O scanner](#standard-io-scanner)
  - [CIP Safety scanner](#cip-safety-scanner)
  - [Logix tag client](#logix-tag-client)
  - [Logix tag server](#logix-tag-server)
- [Samples](#samples)
- [Building and testing](#building-and-testing)
- [Library reference](#library-reference)
- [CIP services supported](#cip-services-supported)
- [CIP Safety details](#cip-safety-details)
- [Known limitations](#known-limitations)
- [License](#license)

---

## Features

**Standard EtherNet/IP**
- TCP encapsulation (port 44818) — `RegisterSession`, `SendRRData`, `SendUnitData`, `UnregisterSession`, `ListIdentity`, `ListServices`, `ListInterfaces`
- UDP I/O transport (port 2222) — Class 0 and Class 1 implicit messaging
- Forward Open / Large Forward Open / Forward Close with full parameter parsing
- Run/Idle header handling on Class 1 connections
- CIP Identity, Assembly, Connection Manager, TCP/IP Interface, and Ethernet Link objects pre-registered
- Typed encapsulation message classes (each command is a `dataclass` with named fields)

**CIP Safety (originator and target)**
- Base Format and Extended Format safety frames (short and long variants)
- Connection Parameter CRC (CPCRC) computation and validation
- Safety Network Segment parser/encoder
- Time Coordination (TCOO) message exchange and ping cycle
- Producer-rollover tracking so CRC-S5 stays valid across the 8.4 s 16-bit timestamp wrap window
- Safety Supervisor and Safety Validator CIP objects
- Configuration Identifier (SCCRC + SCTS) handling
- Interop-tested against Allen-Bradley ControlLogix as originator and 1734-IB8S as target

**Logix tag protocol**
- `Read Tag` (0x4C), `Write Tag` (0x4D), Fragmented variants (0x52/0x53), `Read Modify Write` (0x4E)
- `Multiple Service Packet` (0x0A) for batched explicit messages
- Tag browsing via `Get Instance Attribute List` (0x55) — paginated; automatically resolves controller + program scopes and pulls UDT templates
- UDT template queries and structure read/write (auto-fragmented for structs >504 B)
- Array indexer syntax in tag names: `counts[3]`, `Temp[10].AnotherArray[4]`, Studio 5000 multi-dim `arr[1,2,3]`
- ControlLogix backplane routing via a libplctag-style `path` (e.g. `"1,0"` for backplane → slot 0) — wraps each request in `Unconnected_Send` to the Connection Manager
- Opt-in Class 3 connected explicit messaging (`use_connected=True`) — opens a Forward_Open at connect time, every read/write rides `SendUnitData` instead of UCMM
- Instance-ID cache populated transparently by `browse_tags()` so subsequent reads send a 6-byte Symbol Object segment instead of the longer ANSI symbolic name
- `TagClient` for connecting to a real PLC and reading/writing tags by name
- Logix STRING handling (88-byte UDT: LEN(DINT) + DATA(SINT[82]))

**Diagnostics**
- Connection lifecycle events on `ConnectionManager.on_connection_established` / `on_connection_removed`
- Per-frame send/receive counters
- Heavy in-source comments explaining wire formats and edge cases

---

## Architecture

The codebase is split into small, focused subpackages with one-way dependencies:

```
                         ┌────────────────────────┐
                         │ ethernetip.cip         │
                         │ (pure protocol)        │
                         └───────────┬────────────┘
                                     │
            ┌────────────────────────┼────────────────────────┐
            │                        │                        │
┌───────────▼──────────┐  ┌──────────▼──────────┐  ┌──────────▼──────────┐
│ ethernetip.protocol  │  │ ethernetip.         │  │ ethernetip.logix    │
│ (asyncio TCP/UDP)    │  │ connections         │  │ (tag client/server) │
└───────────┬──────────┘  │ (Forward Open/Close)│  └─────────────────────┘
            │             └──────────┬──────────┘
            └────────────┬───────────┘
                         │
              ┌──────────▼──────────┐
              │ ethernetip.device   │
              │ (VirtualDevice,     │
              │  assemblies)        │
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │ ethernetip.safety   │
              │ (SafetyDevice,      │
              │  CRCs, TCOO,        │
              │  validators)        │
              └─────────────────────┘
```

- **`ethernetip.cip`** — Pure CIP: paths + `build_path`, services, `CipDispatcher` + `CatchAllDispatcher`, encapsulation header, CPF, identity. No sockets.
- **`ethernetip.protocol`** — Asyncio sockets only: `EipAdapter` (Class-3-clean TCP listener), `IoEipAdapter` (subclass adding Sockaddr Info for Class 0/1 I/O), `EipScanner` + `ConnectedExplicit` (TCP client + Class 3 explicit messaging), `EipUdpTransport` (UDP I/O), typed encapsulation messages.
- **`ethernetip.connections`** — Forward Open/Close parsing and connection lifecycle, used by both adapter and scanner.
- **`ethernetip.device`** — `VirtualDevice` base + `AssemblyObject`. Ties dispatcher + assemblies + I/O transport together.
- **`ethernetip.safety`** — `SafetyDevice` (extends `VirtualDevice` with safety framing), CRC routines (S1–S5), TCOO logic, Safety Supervisor/Validator objects, plus `SafetyScannerConnection` for the originator side.
- **`ethernetip.logix`** — `LogixDispatcher` (server side: serves tags), `TagClient` (client side: reads/writes tags on a real PLC), tag database with change events, UDT templates, structure value helpers.

---

## Project layout

```
src/ethernetip/
  cip/              Core CIP protocol (no I/O dependencies)
  protocol/         asyncio TCP/UDP transport (adapter + scanner)
  connections/      Forward Open/Close, connection lifecycle
  device/           Virtual device composition (VirtualDevice, AssemblyObject)
  safety/           CIP Safety: framing, CRCs, TCOO, validators
  logix/            Logix tag client & server, UDT templates

examples/
  safety_adapter.py             CIP Safety adapter — runs against a real PLC or compatible emulator
  echo_module.py                Plain EtherNet/IP adapter compatible with Studio 5000 Generic Ethernet Module
  cip_echo_server.py            Catch-all CIP server — logs any unhandled request (UCMM or Class 3)
  connected_explicit_smoke.py   UCMM + Class 3 explicit messaging smoke test
  logix_host.py                 Stand-alone Logix tag server (pycomm3-compatible)
  safety_scanner_1734.py        CIP Safety originator targeting a 1734 safety I/O module
  safety_scanner_loopback.py    Safety scanner + safety adapter loopback test

tests/
  cip/         CIP path parsing, MR codec, service registration
  protocol/    Encapsulation, scanner ↔ adapter loopback
  logix/       Tag database, read/write, edge cases
  safety/      CRC check values, frame codec round-trips, segment parser
```

---

## Quick start

### Standard adapter (Generic Ethernet Module)

```python
import asyncio
from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.device.virtual_device import VirtualDevice


async def main():
    identity = IdentityInfo(
        vendor_id=0x0001,
        device_type=0x000C,       # Communications Adapter
        product_code=1,
        major_revision=1, minor_revision=0,
        serial_number=0xC0FFEE42,
        product_name="My Simulator",
    )

    device = VirtualDevice(identity, "192.168.1.100")

    # Matches Studio 5000 "Generic Ethernet Module" with Comm Format = Data - DINT
    device.add_assembly(100, 500, "T->O Input (125 DINTs)")
    device.add_assembly(102, 496, "O->T Output (124 DINTs)")
    device.add_assembly(105,  10, "Configuration")

    await device.start()

    # Update produced data — the PLC will see this in its Input tag
    device.assemblies.get_assembly(100).write_dint(0, 42)

    # Read what the PLC sent us — its Output tag
    plc_output_dint0 = device.assemblies.get_assembly(102).read_dint(0)


asyncio.run(main())
```

### CIP Safety adapter

```python
import asyncio
from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.safety import SafetyDevice, SafetyNetworkNumber


async def main():
    identity = IdentityInfo(
        vendor_id=1, device_type=0, product_code=26,
        major_revision=1, minor_revision=1,
        serial_number=0xC0FFEE42,
        product_name="My Safety Module",
    )

    # Safety Network Number (12 hex chars displayed BE, stored LE on the wire)
    snn = SafetyNetworkNumber(bytes([0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D]))

    # Safety node address = your IP packed BE as uint32
    node_address = 0xC0A80154   # 192.168.1.84

    device = SafetyDevice(identity, "192.168.1.84", snn, node_address)

    # 1-byte safety data assemblies + a 0-byte config assembly
    device.add_assembly(  1, 1, "Safety Data In")
    device.add_assembly(199, 1, "Safety Data Out")
    # Config assembly often shares the instance with one of the data assemblies
    # in Logix safety configs — skip the add when it would collide.

    await device.start()
    device.assemblies.get_assembly(1).write_bytes(0, bytes([0x42]))


asyncio.run(main())
```

### Standard I/O scanner

```python
import asyncio
from ethernetip.protocol.eip_scanner import EipScanner
from ethernetip.protocol.eip_udp_transport import EipUdpTransport, IO_PORT


async def main():
    scanner = EipScanner()
    await scanner.connect("192.168.1.84")

    udp = EipUdpTransport(bind_port=IO_PORT)
    await udp.start()

    conn = await scanner.forward_open(
        consumed_assembly=102, produced_assembly=100, config_assembly=105,
        consumed_size=496, produced_size=500,
        rpi=10_000,                  # 10 ms
        transport_class=1,           # Class 1 cyclic
        timeout_multiplier=2,        # x16
    )

    conn.on_data_received.append(lambda data: print(f"Got {len(data)} bytes"))
    conn.write_dint(0, 1234)                     # What target reads as input
    received = conn.read_dint(0)                 # What target produced

    await conn.close()


asyncio.run(main())
```

### CIP Safety scanner

See `examples/safety_scanner_1734.py` for a worked example against a 1734-IB8S safety input module behind a 1734-ENT EtherNet/IP adapter. The originator side requires:

- Originator identity + Safety Network Number (UNID)
- Target identity (TUNID) — the SNN burned into the safety module
- Safety Configuration Identifier (SCCRC + SCTS) — proves you have the right config
- Electronic key for the target module
- Route prefix (e.g. backplane port + slot)
- Server and Client `SafetyForwardOpenConfig` — RPIs, ping interval multipliers, timeout multipliers

```python
conn = await SafetyScannerConnection.open(
    scanner, udp, server_config, client_config,
    orig_vendor=originator_vendor_id, orig_serial=originator_serial,
    route_prefix=route_prefix,
    server_app_path=server_app_path,
    client_app_path=client_app_path,
)

conn.set_output_data(bytes([0x00]))                  # safe state
conn.on_data_received.append(lambda data: ...)
```

### Logix tag client

```python
import asyncio
from ethernetip.logix.tag_client import TagClient, StructureValue


async def main():
    # CompactLogix or EN-hosted symbol service — no backplane route required.
    async with TagClient("192.168.1.96") as client:
        # Read & write simple atomic tags
        rate = await client.read_dint("rate")
        await client.write_dint("rate", 1500)

        # Array element access — Studio 5000 syntax works directly. Brackets
        # are emitted as CIP Logical Element segments after the symbolic name.
        third = await client.read_dint("counts[3]")
        nested = await client.read_dint("Temp[10].AnotherArray[4]")
        multi = await client.read_dint("matrix[1,2,3]")

        # Browse populates an internal Symbol-Object instance cache. After
        # this call every subsequent tag access uses the short 6-byte
        # instance-ID form in place of the ANSI symbolic name — no API
        # change, just less wire.
        browse = await client.browse_tags()
        tag = next(t for t in browse.tags if t.name == "MyUdt")
        value = await client.read_struct("MyUdt", tag.template)

        for name, val in value.to_dict().items():
            print(f"{name} = {val}")

        # Write a structure
        writer = StructureValue(tag.template)
        writer.set_bool("enable", True)
        writer.set_dint("setpoint", 100)
        await client.write_struct_value("MyUdt", writer)


asyncio.run(main())
```

For a **ControlLogix chassis** where the CPU is at a separate backplane slot,
pass a libplctag-style route. Tokens are decimal or `0xNN` hex; pairs are
`port,link` (port 1 = backplane, link = slot):

```python
# Walk from a 1756-EN2T at .96 to the CPU at slot 0.
async with TagClient("192.168.1.96", path="1,0") as client:
    rate = await client.read_dint("rate")
```

For hot polling loops, opt in to Class 3 connected explicit messaging. The
context manager performs a Forward_Open against the destination Message
Router at entry; every subsequent request rides `SendUnitData`. Exit closes
the connection cleanly with a Forward_Close.

```python
async with TagClient("192.168.1.96", path="1,0", use_connected=True) as c:
    for _ in range(10_000):
        await c.read_dint("rate")
```

### Logix tag server

```python
import asyncio
from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.logix.logix_dispatcher import LogixDispatcher
from ethernetip.logix.tag_database import TagDatabase
from ethernetip.logix import data_types as dt
from ethernetip.protocol.eip_adapter import EipAdapter


async def main():
    tags = TagDatabase()
    tags.add_tag("rate",        dt.DINT).write_dint(0, 1500)
    tags.add_tag("temperature", dt.REAL).write_real(0, 72.5)
    tags.add_tag("counts",      dt.INT, element_count=100)

    # React to client writes
    tags.find_by_name("rate").on_value_changed.append(
        lambda tag, change: print(f"rate = {tag.read_dint(0)}"))

    identity = IdentityInfo(product_name="PyLogix Sim")
    dispatcher = LogixDispatcher(tags, identity)
    adapter = EipAdapter(dispatcher, identity)

    await adapter.listen("0.0.0.0", 44818)
    try:
        while True:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    await adapter.close()


asyncio.run(main())
```

---

## Samples

Seven runnable scripts under `examples/`. Each one has a header docstring describing usage and CLI options. See [`examples/README.md`](examples/README.md) for end-to-end usage examples.

| Sample | Role | Safety | Brief |
|---|---|---|---|
| `safety_adapter.py` | Target | Yes | CIP Safety adapter. Two profiles (`test2`, `plc`) or fully custom via CLI |
| `echo_module.py` | Target | No | Plain EtherNet/IP adapter compatible with Studio 5000 Generic Ethernet Module |
| `cip_echo_server.py` | Target | No | Catch-all CIP server — logs any unhandled request and optionally returns N bytes of incremental data. Handles UCMM + Class 3 from Logix MSG instructions. |
| `logix_host.py` | Target | No | Stand-alone Logix tag server with preloaded tags. Compatible with pycomm3. |
| `connected_explicit_smoke.py` | Scanner | No | UCMM + Class 3 explicit round-trips against `cip_echo_server.py` or any compatible adapter |
| `safety_scanner_1734.py` | Scanner | Yes | CIP Safety originator targeting a 1734 safety I/O module |
| `safety_scanner_loopback.py` | Scanner | Yes | Self-contained safety scanner ↔ safety adapter loopback test |

Run any sample with:

```bash
python -u examples/<name>.py
python -u examples/<name>.py --key=value [...]
```

Defaults are set up so `connected_explicit_smoke.py` can talk to `cip_echo_server.py` on the same machine (loopback) without any wiring:

```bash
# Terminal 1
python -u examples/cip_echo_server.py

# Terminal 2
python -u examples/connected_explicit_smoke.py
```

---

## Building and testing

```bash
# Install for development
pip install -e ".[dev]"

# Run the full test suite
pytest tests/ -v

# Run a single subpackage's tests
pytest tests/safety -v
```

Requirements: Python 3.10+ (uses `match/case`, `X | Y` type unions). No runtime dependencies for the library itself; tests pull `pytest` and `pytest-asyncio`.

The test suite covers CIP path parsing, MR codec, encapsulation, scanner ↔ adapter loopback, tag read/write/browse, CRC check values, safety frame round-trips, and safety segment parsing.

---

## Library reference

### `ethernetip.cip`

| Type | What it is |
|---|---|
| `CipDispatcher` | Routes service requests through the class → instance → attribute tree. `on_unhandled` is a virtual catch-all hook called for every unmatched path. |
| `CatchAllDispatcher` | `CipDispatcher` subclass that routes every unmatched request through a single callback — `(CatchAllRequest) -> CatchAllReply`. Useful for echo servers / sniffers without subclassing. |
| `CipClass`, `CipInstance`, `CipAttribute` | CIP object model |
| `CipPath`, `build_path` | EPATH parser (logical + symbolic + electronic key segments) and helper for building logical EPATHs from class/instance/attribute/element fields. |
| `MrCodec` | Message Router request/response binary codec |
| `EncapsulationHeader` | 24-byte TCP framing |
| `CpfParser`, `CpfItem` | Common Packet Format |
| `IdentityInfo` | Strongly-typed device identity (vendor/serial/product/etc.) |
| `data_types`, `CipDataSerializer` | Wire-format type IDs and (de)serialization |
| `CipStatus` | All general-status codes |

### `ethernetip.protocol`

| Type | What it is |
|---|---|
| `EipAdapter` | asyncio TCP listener (port 44818). Hosts a `CipDispatcher`. Class-3-clean by default (no Sockaddr Info on Forward Open replies); has a `connection_id_lookup` hook for SendUnitData OT→TO translation. |
| `IoEipAdapter` | `EipAdapter` subclass that attaches Sockaddr Info O→T / T→O items on Class 0/1 Forward Open replies and fires `on_connection_opened`. Used by `VirtualDevice`. |
| `EipScanner` | asyncio TCP client. `register_session` + `send_explicit` (UCMM) + `open_explicit` (Class 3 connected explicit) + `forward_open` (Class 0/1 I/O) |
| `ConnectedExplicit` | Class 3 connected explicit messaging handle returned by `EipScanner.open_explicit()`. `send(svc, class, inst, attr, data)` runs over `SendUnitData`. |
| `EipUdpTransport` | UDP I/O transport (port 2222) — send + receive callbacks |
| `EncapsulationMessageManager` | Parser/dispatcher for typed encapsulation messages (`NopMessage`, `RegisterSessionMessage`, `SendRRDataMessage`, `SendUnitDataMessage`, etc.) |
| `ScannerConnection` | Active I/O connection from the scanner side |

### `ethernetip.connections`

| Type | What it is |
|---|---|
| `ConnectionManagerObject` | Implements the Connection Manager CIP class (handles Forward Open/Close) |
| `ForwardOpenRequest` | Binary parser for Forward Open / Large Forward Open |
| `IoConnection` | Per-connection state (CIDs, RPIs, safety state, timers) |
| `parse_connection_path` | Extracts assembly instances from a Forward Open path |
| `ISafetyConnectionHandler` | Interface ConnectionManager calls into for safety validation |

### `ethernetip.device`

| Type | What it is |
|---|---|
| `VirtualDevice` | Wires together adapter, UDP transport, dispatcher, and assemblies |
| `AssemblyObject` | CIP Assembly (0x04) with byte buffer + `on_data_changed` callback list |
| `AssemblyInstance` | Per-instance byte buffer with typed read/write helpers |
| Identity, TCP-IP Interface, Ethernet Link objects | Standard CIP objects pre-registered |

### `ethernetip.safety`

| Type | What it is |
|---|---|
| `SafetyDevice` | Target-side safety adapter (extends `VirtualDevice`) |
| `SafetyScannerConnection` | Originator-side safety connection pair (server + client) |
| `SafetyFrameCodec` | Safety frame encode/decode (Base + Extended, Short + Long) |
| `SafetyCrc` | All five CRCs (S1, S2, S3, S4, S5) with lookup tables |
| `SafetyCpcrc` | Connection Parameter CRC computation |
| `SafetyNetworkSegment` | Forward Open safety segment (0x50) parse/encode |
| `SafetySupervisorObject` | Safety Supervisor CIP class (0x39) |
| `SafetyValidatorObject` | Safety Validator CIP class (0x3A) |
| `ModeByte`, `SafetyNetworkNumber`, `UniqueNetworkId`, `SafetyConfigurationId` | Strongly-typed safety identifiers |
| `SafetyForwardOpenBuilder`, `SafetyForwardOpenConfig` | Originator-side Forward Open builder |

### `ethernetip.logix`

| Type | What it is |
|---|---|
| `LogixDispatcher` | Server side. Dispatches tag services + UDT template queries |
| `TagClient` | Client side. Connect to a real PLC and read/write tags. Accepts an optional libplctag-style routing `path` (e.g. `"1,0"` for backplane → slot 0) and a `use_connected` flag for Class 3 connected explicit messaging. `browse_tags()` populates a Symbol-Object instance-ID cache that shortens every later tag path. Auto-fragments large struct reads. |
| `TagDatabase`, `Tag` | In-memory tag store with `on_value_changed` callbacks |
| `data_types` | Standard Logix atomic types (DINT, REAL, INT, SINT, LINT, LREAL, BOOL) |
| `StructureValue` | Helper for reading/writing UDT structures by member name |
| `TemplateObject`, `SymbolObject` | Template Read and `Get_Instance_Attribute_List` support |
| `MultiServiceHandler` | Multiple Service Packet batching |
| `udt_code_generator` | Generate typed Python classes from UDT templates |

---

## CIP services supported

| Service | Code | Description |
|---|---|---|
| Get Attribute All | 0x01 | Read all attributes |
| Set Attribute All | 0x02 | Write all attributes |
| Get Attribute List | 0x03 | Read selected attributes |
| Reset | 0x05 | Reset CIP object |
| Multiple Service Packet | 0x0A | Batch multiple requests in one frame |
| Get Attribute Single | 0x0E | Read one CIP attribute |
| Set Attribute Single | 0x10 | Write one CIP attribute |
| Read Tag | 0x4C | Read tag data (symbolic or instance ID) |
| Write Tag | 0x4D | Write tag data with type validation |
| Forward Close | 0x4E | Close I/O connection |
| Read Modify Write | 0x4E | Bit-level OR/AND mask modification |
| Read Tag Fragmented | 0x52 | Chunked read for large tags |
| Write Tag Fragmented | 0x53 | Chunked write for large tags |
| Forward Open | 0x54 | Establish I/O connection |
| Get Instance Attribute List | 0x55 | Browse tags / instances (paginated) |
| Large Forward Open | 0x5B | Forward Open with 32-bit connection size fields |

---

## CIP Safety details

CIP Safety is a SIL-3-capable layer on top of standard EtherNet/IP. This library implements both producer (target) and consumer (originator) roles. Wire-format details (frame layouts, CRC polynomials, timing constants) follow the published CIP Safety specification — refer to the spec for protocol-level documentation.

**A "safety connection" is a pair of two underlying connections** — server and client — one in each direction for full bidirectional safety. Each carries the producer's safety data plus its own time-coordination (TCOO) exchange.

**Connection establishment:**
- Originator computes the Connection Parameter CRC over the Forward Open fields and includes it in the safety segment
- Target validates CPCRC, TUNID, electronic key, and Safety Configuration Identifier before accepting
- Production starts immediately on Forward Open; outgoing frames stay in IDLE mode until the first TCOO arrives and time coordination is established

**Timestamp rollover:**
The 16-bit producer timestamp wraps every ~8.4 s of connection uptime. The consumer side tracks a separate rollover count for the producer's stream and the consumer's own outgoing stream so CRC-S5 validation stays correct across wraps.

**Safety ownership (work in progress):**
The full safety ownership state machine (Propose_TUNID / Apply_TUNID / Configure / Run / Idle transitions in the Safety Supervisor) is not yet implemented. The current target-side check is that the originator's SNN and the safety configuration signature (SCCRC + SCTS) must match what the target was commissioned with — connections are accepted if both match. Commissioning workflows (changing a target's owner or its config from the originator side) are not yet supported.

---

## Known limitations

- 10 ms RPI runs stably for hours on Linux; on Windows the asyncio scheduler tail can occasionally exceed 50 ms, so for sub-20-ms RPIs use the C# or C++ ports.
- No persistent storage — assembly contents and tag values are in-memory only.
- Originator-side connection bridging through multiple hops is not implemented.
- Safety reset / safety configuration apply services are wired in but not extensively interop-tested.

---

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full text.

```
Copyright 2026 Cristian Mori

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
