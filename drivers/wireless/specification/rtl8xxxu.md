# rtl8xxxu — Specification

> Status: runtime RTL8188EU factory/FIFO/firmware/MAC/BB/RF + LC/IQK implemented;
> full station software and physical acceptance remain incomplete.

## 1. Purpose & scope

Owns the Realtek USB match table, register/packet helpers and retained
RTL8188EU async firmware owner. Other matched families remain detection-only.

## 2. Assumptions

The USB enumerator supplies an addressed, configured `Arc<USBDevice>`.
Authenticated firmware must already be installed in the NARF registry before
probe. Initialization powers the RF blocks for register-table setup while
MAC TX/RX stays closed. A usable station requires the remaining software below.

## 3. Public interface

`rtl8xxxu_probe` retains the handle and `firmware_transport::Owner<UsbControl>`.
For RTL8188EU it spawns `initialize_registered()` after releasing the device
registry lock. That production path now continues through factory identity,
FIFO/queue boundaries, firmware, MAC/BB/AGC/RF tables and checked post-table
MAC/LC/IQK initialization. Duplicate
registration compares the retained Arc identity, instead of conflating equal slot numbers on different USB controllers.

`Owner::status()` reports detected, validated, factory-ready, powered,
downloading, firmware-ready, initializing-tables, tables-ready, calibrating,
radio-ready or terminal failed state. Radio-ready means checked initialization
with MAC TX/RX still closed. `Owner::calibration()` exposes the selected full
TX/RX IQ coefficients only after successful completion. `Owner::factory()` returns the checked RTL8188EU factory identity
and calibration snapshot. `initialize_device(blob)` runs the production
factory/FIFO/firmware/table/calibration sequence for authenticated-byte owners/tests.
The firmware-only `initialize(blob)` remains a diagnostic entry point.
A second attempt returns `AlreadyStarted` without I/O. Dropping an
active attempt records `Cancelled`; it cannot silently replay. Deadline,
transport errors (including ambiguous xHCI errors) and cancellation poison the
one-shot owner: no cleanup read/write, retry, or other EP0 operation follows.
Recovery requires controller-proven endpoint stop/drain and a fresh USB device
lifecycle; a new software owner alone is insufficient.

Image validation requires the complete 32-byte little-endian RTL8188E header,
signature family `0x88e0`, nonempty exact `ramcodesize` and at most eight 4 KiB
pages. Validation/unsupported-family failures occur before USB. Registry bytes
are validated and copied into owned storage before awaiting USB transfers.

`ControlIo` provides configuration-descriptor reads, async exact-count
register reads/writes and delay; `UsbControl`
uses vendor EP0 request `0x05`, index zero, value=register address. Firmware
pages use 196-byte control writes at `0x1000`, with the page selected through
`MCU_FW_DL+2`. Firmware bytes never use a bulk packet endpoint.

`device_init::endpoints(config)` validates the active vendor interface's
bulk descriptors and derives 1–3 OUT queue geometry. Factory reads reject test
silicon/I cut, use the sparse logical map, validate RTL ID `0x8129` and nonzero
unicast MAC at `0xd7`, and retain CCK/HT40 power bases, crystal, thermal and
board fields. All table writes check exact transfer counts, RF addresses keep
all eight bits, and Linux RF delay markers are delays. LLT installs the
176-entry split with TX end 169 and a 170–175 ring after FIFO boundaries.
The post-table sequence programs RX/report geometry, filters, EDCA, beacon
parameters, initial factory gain indices and the hardware security gate. It
awaits CAM invalidation, performs RF HSSI reads with complete eight-bit
addresses and PI/SI readback selection, runs LC preserving prior continuous-
TX/pause state, then performs up to three full TX/RX IQK attempts with two
retries per path. It restores saved ADDA/BB/MAC registers after completed
attempts and accepts a full stable coefficient set; partial/fallback IQK is
rejected. Signed IQ matrix, thermal meter and NAV setup finish initialization.
Erased/out-of-range factory gain indices fail before gains are programmed.
MAC TX/RX remain closed: radio-ready is not regulatory, scan or packet ready.

`ccmp_runtime::Key` is the software CCMP dependency for the pending station
runtime. `Role::Pairwise` admits KeyID0; `Role::Group` admits IDs0–3 but is
receive-only. TX requires ToDS, peer RA/local TA; RX requires FromDS, peer TA,
a unicast source and local RA for PTK or multicast RA for GTK. Only Data/QoS
Data with exact native header extents is admitted; fragments/A-MSDU fail.
CCMP reserved bits, ExtIV, key ID and the 4096-byte body bound are checked
before crypto. Each key owns 16 QoS plus a separate non-QoS replay tracker;
MIC failure leaves ciphertext and all trackers unchanged. TX consumes a
non-wrapping 48-bit PN before USB ownership, and same-key `reinstall` preserves
TX/RX counters. Keys and temporary encryption storage zeroize on drop. A
fresh-key constructor must not replace an identical live/retired key; station
integration retains key slots across EAPOL retries. This dependency does not
publish a station, install RSNA keys or open the controlled port.

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
- Neither firmware-ready nor radio-ready implies association or packet TX.

## 5. Architecture notes

The USB protocol is common to both architecture builds. Register-model tests
drive the actual async owner; real transfer completion belongs to xHCI/USB.

## 6. Dependencies

`narf-drivers-usb` owns EP0 and transfer DMA. `narf-firmware` authenticates
registry blobs; scheduler/time provide async execution and bounded waits.

## 7. Stage assignment

RTL8188EU now reaches a software-tested factory/firmware/register-table
diagnostic with checked LC/IQK through the production probe. It is not ready for full station physical acceptance.

## 8. Open questions / remaining software

| Prerequisite | State |
|---|---|
| RTL8188EU power + EP0 firmware lifecycle | Implemented; shared-path regressions |
| RTL8192EU / RTL8723BU / RTL8821CU / RTL8822BU runtime initialization | Missing |
| EFUSE identity/calibration read through retained async owner | Implemented; chip/geometry/failure coverage |
| Endpoint-descriptor selection and MAC FIFO/LLT | Implemented; activation/RX filters remain open |
| MAC/BB/AGC/RF table application | Implemented with source-matched tables and checked transfers |
| Checked post-table MAC, CAM-clear, LC/full IQK and factory gain indices | Implemented; composed owner/status/error/cancellation regressions |
| Policy-admitted channel/power and RX activation | Missing; factory gain indices are not dBm policy |
| Management TX/RX, passive scan and real station MLME | Missing |
| Software AES-CCM + strict CCMP/key/TID ownership | Implemented dependency; independent ciphertext/forgery/role/PN regressions |
| WPA2 key installation/controlled port and Ethernet transport | Missing |
| Regulatory channel/power, rates, coexistence | Missing |
| USB transfer ownership / stale handles | EP0 + bulk claims, retained command DMA and generation rejection implemented; slot reuse stays gated |
| Disconnect callbacks, endpoint stop/drain, reset/PM recovery | Missing; software prerequisites |

Linux references: `rtl8xxxu/8188e.c` power/reset, IQK and fops;
`rtl8xxxu/core.c` firmware, post-table init, HSSI, LC and IQ matrix functions;
`rtl8xxxu/8188f.c` factory gain-index programming; `net/mac80211/wpa.c` CCMP
AAD/header/nonce layout. AES-CCM formatting follows RFC 3610.
