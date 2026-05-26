# Bluetooth HCI Stage 0 — USB transport + command/event plumbing

## Scope

1. Recognise USB-IF interface class `0xE0 / 0x01 / 0x01`
   (Wireless / RF / Bluetooth Programming Interface).
2. Walk the configuration descriptor for the three required
   endpoints: interrupt-IN (events), bulk-IN + bulk-OUT (ACL).
   Reject any device missing one.
3. `configure_endpoints` on the xHC, then `SET_CONFIGURATION`.
4. Drive Stage-0 bring-up: `HCI_Reset` → wait Command Complete →
   `HCI_Read_Local_Version_Information` → decode HCI Version +
   Manufacturer.
5. Log `bluetooth: $vendor adapter, HCI v0x$hci, Bluetooth $bt_ver`.
6. Register an `HciTransport` against the bound slot for Stage-1+
   callers.

## Code

- `drivers/usb/src/btusb.rs` — recogniser, endpoint discovery,
  `UsbHciTransport`, async bring-up dance.
- `drivers/usb/src/attach.rs` — `AttachOutcome::Bluetooth` +
  dispatch hook after CDC-NCM.
- `bluetooth/src/lib.rs` — `register_initcalls` (Stage::Late).

## Why a per-driver async bring-up

`narf_bluetooth::controller::Controller::bring_up` is synchronous
and goes through the sync `HciTransport` trait. xHCI's transfer
methods are async. `narf_scheduler::block_on` panics from inside an
executor poll. Stage-0 issues each Mandatory command inline using
`xhci.control_out` / `xhci.poll_interrupt_in` directly, then
registers the trait-impl for Stage-1+ callers that drive it from a
kernel thread (not an executor task).

## Out of scope (Stage 1+)

ACL data plane (L2CAP, GATT, pairing); SCO / eSCO isoch streaming;
vendor firmware load (Intel, Broadcom, Realtek); LE
Advertising / Scanning / Connection; BR/EDR Inquiry / Page.

## Sources

- Bluetooth Core Spec 5.3, Vol 4 Part B (USB Transport) and
  Vol 4 Part E (HCI Functional Specification §7.3 Mandatory,
  §7.4 Informational).
- USB Class Definitions for Wireless Controllers v1.0.
- Linux `drivers/bluetooth/btusb.c` — endpoint discovery + probe
  sequence (GPL-2.0; consulted per 2026-05-20 relicense).

## Test status

- 5 new smokes under `drivers/usb/btusb` — class triple, endpoint
  discovery (positive + negative cases), empty-registry on QEMU.
- `cargo build --workspace --bins` clean.
- QEMU TCG has no USB Bluetooth controller; attach paths fire only
  on real hardware.
