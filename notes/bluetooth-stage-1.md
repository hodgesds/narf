# Bluetooth Stage 1 — L2CAP fixed channels + ATT/GATT for BLE

## Scope

Stage 0 landed the USB transport + HCI Reset / Read_Local_Version
dance. Stage 1 adds the BLE data plane: L2CAP fragmentation /
reassembly, ATT/GATT server-side dispatch, and the Central-role HCI
command shapes the host driver needs to scan + connect.

## What landed

### `bluetooth/src/l2cap.rs`

Stage 1 additions on top of the existing B-frame codec + Reassembler:

- `wrap_bframe_into_acl` / `wrap_frame_into_acl` — outbound
  fragmentation of an encoded L2CAP frame into ACL packets sized to
  the controller's ACL MTU, with correct PB-flag progression
  (PB=0b10 for the first LE fragment, PB=0b01 for continuations).
- `Dispatcher` — per-connection inbound demux wrapping the
  `Reassembler` and exposing `classify_cid`. Routes fixed CID 0x0004
  (ATT) to the GATT server, 0x0005 to LE signalling, 0x0006 to SMP,
  dynamic CIDs to per-channel state.

### `bluetooth/src/event.rs`

New decoders: `DisconnectionComplete` (§7.7.5),
`NumberOfCompletedPackets` (§7.7.19, for ACL flow control),
`LeConnectionComplete` and `parse_le_advertising_reports` (LE Meta
subevents 0x01 / 0x02).

### `bluetooth/src/opcode.rs`

LE Central + Disconnect opcodes, each with compile-time `assert!`:

- `HCI_LE_SET_SCAN_PARAMETERS` (0x200B)
- `HCI_LE_SET_SCAN_ENABLE` (0x200C)
- `HCI_LE_CREATE_CONNECTION` (0x200D)
- `HCI_LE_CREATE_CONNECTION_CANCEL` (0x200E)
- `HCI_DISCONNECT` (0x0406)

### `bluetooth/src/gap.rs`

A `Central` state machine + builders for the Central HCI commands:

- `ScanParameters` / `ScanEnable` / `CreateConnection` —
  spec-shaped parameter blocks with `encode() -> [u8; N]`.
- `build_disconnect` + `DISCONNECT_REASON_REMOTE_USER` (0x13).
- `Central` tracks scan + connect phase, holds a `peers` table with
  RSSI refresh, applies `LeConnectionComplete` /
  `DisconnectionComplete` events.

ATT and GATT server already cover MTU, Read, Write, Notify, Read By
Type, Read By Group Type, Find Information — nothing to add at
Stage 1.

## Tests

13 new smokes under `bluetooth/l2cap`, `bluetooth/hci`,
`bluetooth/gap`: L2CAP single-packet wrap, fragmented wrap,
dispatcher routing, multi-fragment reassembly; Disconnection /
Number Of Completed Packets / LE Connection Complete / LE
Advertising Report decode; scan parameters / enable / create
connection / disconnect encoders; Central state walk.

Baseline ran 2390 / 0 / 49; with Stage 1 it is 2403 / 0 / 49.

## Out of scope (Stage 2)

Peripheral advertising role; SMP pairing invocation; specific GATT
services (HoG / Battery / DIS); LE Set Advertising Parameters /
Enable / Set Random Address.

## Sources

- Bluetooth Core Spec 5.3 Vol 3 Part A (L2CAP), Part F (ATT),
  Part G (GATT); Vol 4 Part E §7.1.6, §7.7, §7.8.10-13.
- Linux `net/bluetooth/{hci_event.c, l2cap_core.c}` — event decode
  shapes (GPL-2.0; consulted per 2026-05-20 relicense).
