# narf-bluetooth — Bluetooth HCI core

Clean-room implementation of the Bluetooth Host Controller Interface
(HCI) packet layer + USB transport binding.

## Sources (public only)

- **Bluetooth Core Specification 5.3**, Volume 4 Part E (HCI Functional
  Specification) — Bluetooth SIG, freely downloadable.
- **Bluetooth Core Specification 5.3**, Volume 4 Part B (USB Transport
  Layer) — Bluetooth SIG.
- **USB Class Definitions for Wireless Controllers**, version 1.0, USB-IF
  (defines class 0xE0, subclass 0x01, protocol 0x01 — "Bluetooth
  Programming Interface").

No GPL / Linux Bluetooth subsystem source material was consulted.

## Scope

Stage-1 (this crate's first cut):
- HCI packet types: Command, ACL Data, Synchronous Data, Event.
- Opcode/event-code enums for the Mandatory commands (Reset, Read
  Local Version, Read BD_ADDR, Set Event Mask).
- Sync layer over a generic `HciTransport` trait so a USB or UART
  transport plugs in identically.
- Controller bring-up state machine: Reset → Read Local Version →
  Read BD_ADDR → Set Event Mask.

Out of scope for Stage 1:
- L2CAP, ATT, GATT, SMP, SDP — protocol layers above HCI.
- Specific controller quirks (vendor patches via VS_HCI commands).
- Real USB transport hookup — lands once `narf-drivers-usb` exposes
  bulk/interrupt endpoints to non-class-driver consumers.

## Cap surface

`Cap<Bluetooth, Grant>` — TCB-only mint, authorises transport
registration + admin-class HCI commands (Reset, Set Event Mask).
Per-channel data ops are gated separately once L2CAP lands.
