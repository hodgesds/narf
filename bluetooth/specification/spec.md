# narf-bluetooth — Bluetooth HCI core

Clean-room implementation of the Bluetooth Host Controller Interface
(HCI) packet layer + USB transport binding.

## Sources (public only)

All code is derived from the references below. **No GPL / Linux
Bluetooth subsystem source material was consulted at any point.**

### HCI

- **Bluetooth Core Specification, version 5.3** — Bluetooth SIG.
  Free download: <https://www.bluetooth.com/specifications/specs/core-specification-5-3/>
  - **Vol 4 Part E** — HCI Functional Specification. §5.4 (packet
    types), §7 (commands & events), §3 (general operation).
  - **Vol 4 Part B** — USB Transport Layer. §2.1 (endpoint mapping),
    §2.2 (packet-type indicator bytes).

### L2CAP

- **Bluetooth Core Specification, version 5.3, Vol 3 Part A** —
  Logical Link Control and Adaptation Protocol. §2.1 (CID
  assignments), §3.1 (B-frame layout), §4 (signalling commands),
  §6.6 (segmentation / reassembly).

### ATT

- **Bluetooth Core Specification, version 5.3, Vol 3 Part F** —
  Attribute Protocol. §3.3 (PDU layout), §3.4 (opcodes), §3.4.1
  (error codes), §3.4.2 (Exchange MTU).

### GATT

- **Bluetooth Core Specification, version 5.3, Vol 3 Part G** —
  Generic Attribute Profile. §3 (Service / Characteristic /
  Descriptor model), §4.4 (discovery procedures), §3.3.1.1
  (Characteristic Properties bit definitions).
- **Bluetooth Assigned Numbers** — declaration UUIDs (0x2800
  Primary Service, 0x2803 Characteristic, 0x2902 CCC Descriptor)
  and well-known service UUIDs (0x180F Battery, 0x1812 HID, …).

### SMP

- **Bluetooth Core Specification, version 5.3, Vol 3 Part H** —
  Security Manager Protocol. §3.3 (PDU layout), §2.3.5 (LE Secure
  Connections pairing), §2.3.5.1 (pairing-method selection table 2.8),
  §2.2.5 (AES-CMAC), §2.2.6 (DHKey), §2.2.7 (f5 LTK derivation).

### AVDTP / A2DP

- **Audio/Video Distribution Transport Protocol Specification,
  Version 1.3** — Bluetooth SIG. Public adopted document.
  §8.4 (Signalling Message format), §8.5 (Signal Identifiers,
  table 8.4), §8.6 (Service Capabilities), §8.20.1 (SEP TSEP
  encoding), §8.20.6 (error codes table 8.27).
- **Advanced Audio Distribution Profile (A2DP), Version 1.4** —
  Bluetooth SIG. Public. §4.3 SBC media-codec capability layout
  (sampling-frequency / channel-mode / block-length / subbands /
  allocation-method bitmasks + 1-byte min/max bitpool).
- **Bluetooth Assigned Numbers** — AVDTP signalling PSM 0x0019,
  Audio/Video Distribution media-type and codec-type registry.

### RFCOMM

- **Bluetooth Core Specification 5.3, Vol 3 Part B (RFCOMM)** —
  Bluetooth SIG. §1 framing model, §2 multiplexer control, §5.1.1
  address byte, §5.1.2 control byte (SABM/UA/DM/DISC/UIH + P/F),
  §5.1.3 EA-coded length indicator, §5.1.4 FCS coverage, §5.4 DLCI
  ↔ server-channel mapping.
- **ETSI TS 07.10** — the underlying multiplexed-serial protocol that
  RFCOMM adapts. Public ETSI document; only the byte layout is
  consumed.

### HOGP (HID over GATT)

- **HID over GATT Profile Specification, version 1.0** — Bluetooth SIG.
  Adopted profile; defines the HID Service (0x1812) shape: HID
  Information (0x2A4A), Report Map (0x2A4B), HID Control Point
  (0x2A4C), Report (0x2A4D) + Report Reference descriptor (0x2908),
  Protocol Mode (0x2A4E), Boot Keyboard Input/Output Report (0x2A22 /
  0x2A32), Boot Mouse Input Report (0x2A33).
- **HID Service Specification, version 1.0** — Bluetooth SIG.
  §3.1 HID Information field layout, §3.4 Protocol Mode values,
  §3.6 Control Point command bytes, §3.7.1 Report Reference fields.
- **USB-IF Device Class Definition for Human Interface Devices (HID),
  v1.11** — referenced for the boot-protocol report layouts (§B.1
  keyboard, §B.2 mouse) reused on BLE.

### USB transport class

- **USB Class Definitions for Wireless Controllers, Revision 1.0** —
  USB-IF, August 2002.
  Class 0xE0 (Wireless Controller), Subclass 0x01 (RF Controller),
  Protocol 0x01 (Bluetooth Programming Interface).

## Scope

### Landed today
- **HCI** (`hci` / `opcode` / `event` / `transport` / `controller`):
  packet codec, Mandatory + LE-basics opcodes, Command Complete /
  Command Status decoders, transport trait + USB class triple, full
  bring-up state machine (Reset → Read Local Version → Read BD_ADDR
  → Read Buffer Size → Set Event Mask).
- **L2CAP** (`l2cap`): CID constants, B-frame codec, ACL fragment
  reassembler that handles the PB-flag rules from Vol 4 Part E §5.4.2,
  signalling-command codec + iterator, dynamic CID allocator.
- **ATT** (`att`): full opcode constant set + error-code constants
  + PDU codec + builders/decoders for Exchange MTU, Read, Write,
  Handle Value Notification/Indication/Confirmation, Error Response.
- **GATT** (`gatt`): Service / Characteristic / Descriptor record
  types + well-known UUIDs + discovery-request builders and
  response parsers (Read By Group Type for Primary Services, Read
  By Type for Characteristics, Find Information for Descriptors).
- **SMP** (`smp`): Pairing PDU codec, IO-Capability + AuthReq
  bitfields, pairing-method selector (table 2.8), LE Secure
  Connections **Just Works** initiator + responder state machines.
  Numeric Comparison g2 helper (§2.2.8). Crypto primitives injected
  through `SmpCrypto` trait (P-256 keygen + DH, AES-CMAC, RNG).
- **GATT server** (`gatt_server`): in-memory attribute database
  with handle assignment + permission flags, request handler that
  answers Read / Write / Read By Type / Read By Group Type / Find
  Information / Exchange MTU per ATT §3.4. Convenience builders
  `add_primary_service` / `add_characteristic` emit the canonical
  Vol 3 Part G declaration shape.
- **AVDTP / A2DP** (`avdtp`): clean-room AVDTP signalling codec.
  Header packing (transaction label, packet type, message type,
  signal id), Stream End Point encode/decode (SEID + In-Use bit +
  media type + TSEP), SBC Media Codec Capability blob (frequency /
  channel-mode / block-length / subbands / allocation-method
  bitmasks + bitpool range), and command builders for Discover /
  Get Capabilities / Set Configuration / Open / Start / Suspend /
  Close. PSM 0x0019 surfaced as a constant.
- **RFCOMM** (`rfcomm`): wire-frame codec for SABM/UA/DM/DISC/UIH
  with both 1-byte and 2-byte EA-coded length indicators, FCS-8 over
  the spec-mandated coverage (header for control frames, address+
  control only for UIH), and a single-DLC initiator state machine
  (Closed → Connecting → Open → Disconnecting). Server-channel ↔ DLCI
  mapping kept as plain const values.
- **HOGP** (`hogp`): HID-over-GATT profile builder. Composes the
  mandatory HID Service layout (HID Information, Report Map, HID
  Control Point + N Reports each with a Report Reference descriptor
  and CCCD when notify is requested), plus the optional Protocol
  Mode + Boot Keyboard / Boot Mouse Reports for hosts that fall back
  to boot protocol. Boot-report encoders for the canonical 8-byte
  keyboard and 3-byte mouse layouts.

### Out of scope (deliberate)
- GATT, SMP, SDP, RFCOMM — sit on top of L2CAP+ATT and land in
  follow-on crates.
- Specific controller quirks (vendor patches via VS_HCI commands).
- Real USB transport hookup — lands once `narf-drivers-usb` exposes
  bulk/interrupt endpoints to non-class-driver consumers.

## Cap surface

`Cap<Bluetooth, Grant>` — TCB-only mint, authorises transport
registration + admin-class HCI commands (Reset, Set Event Mask).
Per-channel data ops are gated separately once L2CAP lands.
