# rtl8xxxu — Specification

> Status: runtime RTL8188EU power/firmware transport implemented;
> full station software and physical acceptance remain incomplete.

## 1. Purpose & scope

Owns the Realtek USB match table, register/packet helpers and retained
RTL8188EU async firmware owner. Other matched families remain detection-only.

## 2. Assumptions

The USB enumerator supplies an addressed, configured `Arc<USBDevice>`.
Authenticated firmware must already be installed in the NARF registry before
probe. The owner does not detach host devices, enumerate arbitrary hardware,
enable RF, or publish a usable station interface.

## 3. Public interface

`rtl8xxxu_probe` retains the handle and `firmware_transport::Owner<UsbControl>`.
For RTL8188EU it spawns `initialize_registered()` after releasing the device
registry lock. Duplicate registration compares the retained Arc identity,
instead of conflating equal slot numbers on different USB controllers.

`Owner::status()` reports detected, validated, powered, downloading,
firmware-ready or terminal failed state. `initialize(blob)` exercises the same
production sequence for callers owning authenticated bytes and register-model
tests. A second attempt returns `AlreadyStarted` without I/O. Dropping an
active attempt records `Cancelled`; it cannot silently replay. Deadline,
transport errors (including ambiguous xHCI errors) and cancellation poison the
one-shot owner: no cleanup read/write, retry, or other EP0 operation follows.
Recovery requires controller-proven endpoint stop/drain and a fresh USB device
lifecycle; a new software owner alone is insufficient.

Image validation requires the complete 32-byte little-endian RTL8188E header,
signature family `0x88e0`, nonempty exact `ramcodesize` and at most eight 4 KiB
pages. Validation/unsupported-family failures occur before USB. Registry bytes
are validated and copied into owned storage before awaiting USB transfers.

`ControlIo` provides async exact-count reads/writes and delay; `UsbControl`
uses vendor EP0 request `0x05`, index zero, value=register address. Firmware
pages use 196-byte control writes at `0x1000`, with the page selected through
`MCU_FW_DL+2`. Firmware bytes never use a bulk packet endpoint.

Legacy synchronous stripped-payload loading returns `UseAsyncOwner`; the old
unverified all-radio helper returns `NotImplemented` before transport access.

## 4. Invariants

- Linux's disabled→EMU→active handshake precedes firmware writes. MAC TX/RX
  stay clear until FIFO boundary setup exists (8188E hardware erratum).
- Preserve unrelated SYS/MCU/page-selector fields; reset the checksum with
  its W1C bit, disable download mode before start, reset 8051, and await both
  checksum and init-ready. RTL8188EU does not use another chip's HMTFR init.
- Short reads/writes, checksum/start failures and USB errors are terminal.
  No failure cleanup may reuse EP0: Future Drop/error does not prove that
  xHCI retired the prior TD or released its persistent control-data buffer.
- The initialization attempt is bounded to 30 seconds. Cancellation/deadline
  leaves a poisoned owner without further transport access. No IRQ-disabling
  guard crosses an await and no `block_on` executes inside a spawned worker.
- Firmware-ready does not imply RF calibration, association or packet TX.

## 5. Architecture notes

The USB protocol is common to both architecture builds. Register-model tests
drive the actual async owner; real transfer completion belongs to xHCI/USB.

## 6. Dependencies

`narf-drivers-usb` owns EP0 and transfer DMA. `narf-firmware` authenticates
registry blobs; scheduler/time provide async execution and bounded waits.

## 7. Stage assignment

RTL8188EU now reaches a software-tested firmware-ready diagnostic through
the production probe. It is not ready for full station physical acceptance.

## 8. Open questions / remaining software

| Prerequisite | State |
|---|---|
| RTL8188EU power + EP0 firmware lifecycle | Implemented; shared-path regressions |
| RTL8192EU / RTL8723BU / RTL8821CU / RTL8822BU runtime initialization | Missing |
| EFUSE identity/calibration read through retained async owner | Missing |
| Endpoint-descriptor selection, MAC FIFO/RX configuration | Missing |
| BB/RF table application and verified IQK/LC/calibration | Missing |
| Management TX/RX, passive scan and real station MLME | Missing |
| WPA2 key installation/controlled port and Ethernet transport | Missing |
| Regulatory channel/power, rates, coexistence | Missing |
| Disconnect callbacks, USB handle generations, reset/PM recovery | Missing; requires USB-owner coordination |

Linux references: `rtl8xxxu/8188e.c` power/reset functions and fops;
`rtl8xxxu/core.c` firmware parsing, `writeN`, download and start functions.
