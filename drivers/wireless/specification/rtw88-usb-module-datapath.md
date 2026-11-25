# rtw88-USB loadable-module datapath — design

Status: **superseded (2026-11-24) — the driver's own source runs in the
`.ko`.** Kept as history. The Model A plan below (a hand-written C-ABI
reimplementation in `module_usb.rs`, with register programming extracted
into `narf-drivers-wireless-rtl-chip` piece by piece) reached MAC/FIFO
bring-up and stopped there: PHY/RF/IQK, the station, the netdev and the
control plane were still ahead, against an ~86k-line driver. Since then
`narf-module-rt` and kernel-free builds of `narf-crypto` / `narf-wireless`
made the ath11k approach possible, and rtw88 now follows it: the real
`rtw88/` tree (`usb_firmware::Backend`, `usb_driver`'s factory read and
provisioning, `firmware_lifecycle`, `interface::Device` and the in-driver
SME) builds into the module over `src/rtw88/platform/` and the USB KABI
(`usb_kabi.rs`, `iface_module.rs`). `module_usb.rs` is retired. The current
design is `drivers/wireless/specification/spec.md` §4.8; the KABI it added
is `modules/DATAPATH_ABI_DESIGN.md`, "USB device poller and the regulatory
domain".

Original status: proposal / for review (2026-11-20).

## Problem

`narf-drivers-wireless-rtw` already builds a loadable `.ko`, but only its PCIe
ids register; the `module` probe thunk returns `-ENOSYS`. rtw88 is multi-bus and
its USB path must run as a real datapath from the module, not merely register.

Today every Wi-Fi `.ko` probe returns `-ENOSYS` for one concrete reason: the
wireless datapath ABI is **unused scaffolding**. The C-ABI entry points exist
(`narf_wireless_open/submit/poll/cancel/close`, `narf_netif_register[_with_context]`,
`narf_netif_rx`, and the full `narf_usb_*` transport family), and the native
broker `bus/src/module_wireless.rs` is in place — but until Stage 3 landed,
**no generic family host was registered** (`register_host` has zero callers),
so `narf_wireless_open` failed for every family. The generic host now exists:
`narf-wireless` registers family `WIFI` (`0x7769_6669`), version 1 (see
"The native wireless family host" below and
`drivers/wireless/specification/spec.md` §4.1). The one pre-existing host is
the mt76 private family (`0x6d74_3736`), a copy-mode protocol that keeps
native MCU/WFDMA execution in the host — not a generic host, and not a
substitute for one. Building rtw88-USB means standing up the first consumer
on the generic host.

## What already helps us

- **USB transport is proven.** `narf_usb_{config_descriptor,configure,control,
  submit,poll,cancel,wait}` drive real devices today (ftdi, usb-storage `.ko`s),
  with an `on_event` completion callback registered at `configure`.
- **rtw88's USB bring-up is transport-generic (helps, but is not free reuse).**
  `usb_driver::Backend = usb_firmware::Backend<UsbControl, UsbIo>` — the firmware
  download, MAC, PHY, IQK calibration, parked-power and awake-station stage
  machines (B22/C21) are written against the `narf-drivers-wireless-rtl-usb`
  traits `UsbControl` (CMD-style vendor control) and `UsbIo` (bulk in/out), not
  against a concrete `USBDevice`. **Caveat (corrected):** the `module` build
  links NO kernel crates, and the Backend still depends on
  `narf_drivers_usb`/`narf_wireless`/`narf_net` beyond those two traits, so it
  CANNOT be called from the module as-is. Like e1000's `module_probe.rs`, the
  module datapath is a **self-contained C-ABI reimplementation** of the bring-up
  sequence. The transport-generic shape still helps: it documents the exact
  control/bulk sequence to re-express against `narf_usb_*`, and a later refactor
  could extract a `no_std`, kernel-crate-free `rtw88-usb-core` (generic over the
  transport AND over the stack hooks) that both the builtin driver and the
  module reimplementation share — but Stage 1 does not depend on that.
- **e1000 is the precedent.** Its `module_probe.rs` is a self-contained C-ABI
  datapath (probe brings the device up; a poller pumps RX/TX via `narf_net_*` +
  `narf_irq_*`). rtw88-USB follows the same shape with the USB + wireless ABIs.

## Architecture — Model A (fat module, thin native host)

The module owns the device and chip; the native side owns only the 802.11
control plane and the netdev. This mirrors e1000 (module runs the datapath,
native provides `netif`), and is the only split consistent with rtw88's logic
living *in* the `.ko`.

```
          rtw88.ko (module text, net protection domain)
  ┌───────────────────────────────────────────────────────────┐
  │ module_usb: impl rtl_usb::{UsbControl,UsbIo} over narf_usb_*│
  │     control()  -> narf_usb_control                          │
  │     bulk_out() -> narf_usb_submit + narf_usb_poll/wait      │
  │     bulk_in()  -> narf_usb_submit + on_event completion     │
  │ rtw88 Backend<ModuleUsbControl,ModuleUsbIo>  (UNCHANGED)    │
  │     firmware → MAC → PHY → IQK → parked → awake station     │
  │ netdev: narf_netif_register_with_context(tx_callback)       │
  │     RX frames  -> narf_netif_rx                              │
  │     TX frames  <- tx_callback (native → module)             │
  │ control plane: narf_wireless_submit/poll (module → native)  │
  └───────────────────────────────────────────────────────────┘
                     │ C-ABI (KSYMTAB only)        ▲ on_event / tx_callback
                     ▼                              │
  native: USB host (xHCI), module_wireless family host (NEW),
          module_netif, cfg80211/nl80211 control plane
```

### Boundary traffic

- **Module → native (data):** `narf_netif_rx(ifindex, frame)` for received
  802.11→802.3 frames.
- **Native → module (data):** the `tx_callback` registered at
  `narf_netif_register_with_context` delivers frames to transmit.
- **Module → native (control):** `narf_wireless_submit(session, opcode, request)`
  for control-plane results the stack must see (wiphy capabilities at bring-up,
  scan results, connect/auth outcome, BSS info, regulatory, statistics). Bounded
  by `MAX_REQUEST = 4096` / `MAX_REPLY = 65_536`.
- **Native → module (control):** cfg80211 operations (scan request, connect,
  add/del key, set channel, power save) delivered through the session's event
  callback (same mechanism as `tx_callback`; see “open questions”).

### The native wireless family host (NEW — the foundational piece)

Register one permanent `module_wireless::Host { family, version, open, submit,
poll, cancel, close }`. It is the cfg80211 glue:

- `open(owner, token, session, device, cap)`: mint the per-session wiphy shell
  bound to the module's probe device; no device I/O (the module does that).
- `submit(session, opcode, request)`: decode one versioned control-plane request
  and start the matching native cfg80211 action; return an `operation` id.
- `poll(session, operation, …, publish)`: `-EAGAIN` while pending; publish the
  terminal reply once; `-ENOBUFS` reports the required size.
- `cancel` / `close`: withdraw without freeing hardware-owned memory.

Hosts must be kernel-resident (no hook may point into unloadable text), so the
host lives in a native crate (candidate: `narf-wireless` or a new
`narf-drivers-wireless-host`), not in the `.ko`.

## Opcode protocol (family `WIFI`, version 1) — initial set

> **Superseded by version 2.** The generic host now speaks `WIFI` v2: the
> wiphy binds to the module's `wlan%d` netdev by ifindex, and the station
> control plane (`SCAN_RESULT`, `SCAN_DONE`, `CONNECT_RESULT`,
> `DISCONNECTED`; events `SCAN_REQUEST`, `CONNECT`, `DISCONNECT`,
> `SCAN_ABORT`) is implemented with in-driver SME offloads. The records
> below are the v1 history; the current wire format is in
> `modules/DATAPATH_ABI_DESIGN.md` ("Wireless copy-mode host services") and
> `drivers/wireless/specification/spec.md` §4.1.

Versioned, little-endian, bounded byte records. Starting set (extend by bumping
version, never by silently repurposing an opcode):

| opcode | dir | payload | meaning |
|-------:|-----|---------|---------|
| `0x01 REGISTER_WIPHY` | M→N | bands/channels/cipher caps | publish the wiphy; reply = assigned wiphy index |
| `0x02 SCAN_RESULT`    | M→N | BSS (bssid, ssid, freq, RSSI, IEs) | feed one scan result |
| `0x03 CONNECT_RESULT` | M→N | status, bssid, assoc resp IEs | report connect/auth outcome |
| `0x04 DISCONNECT`     | M→N | reason | report link loss |
| `0x05 SET_STATE`      | M→N | op-state (parked/awake) | mirror the chip stage machine |
| event `SCAN_REQUEST`  | N→M | channels, ssids | cfg80211 asks for a scan |
| event `CONNECT`       | N→M | bssid, ssid, auth/crypto | cfg80211 asks to associate |
| event `KEY`           | N→M | key idx, cipher, material | install/remove key |
| event `TX_FRAME`      | N→M | 802.3 frame | transmit (or reuse `tx_callback`) |

(The exact wire layout is specified per-opcode in a follow-up once the first two
stages land; keeping it minimal avoids over-committing the contract.)

`REGISTER_WIPHY` (opcode `0x01`) is fully specified — the Stage 3 follow-up
this lane is. Request, little-endian, exact length:

```text
mac[6] | modes u32 | hw_caps u8 | cipher_count u8 | band_count u8 | reserved u8
cipher_count x cipher_suite u32
per band: freq_mhz u32 | channel_count u8 | reserved u8 | channel_count x channel u8
```

Modes are the `WirelessModes` bits (STATION=1, AP=2, MONITOR=4, P2P=8);
`hw_caps` bits are HT=1, VHT=2, HE=4, EHT=8 (at most 8 ciphers, 1..=3 bands,
1..=64 channels per band, channels 1..=233). Reserved bytes must be zero;
ciphers must be known suites, bands must map to distinct wiphy bands,
channels unique within their band. Reply: assigned wiphy index (`u32`,
little-endian). One `REGISTER_WIPHY` per session; the host publishes a
`WirelessNetIface` shell under a unique `wlan{N}` name. The Stage 4
opcodes (`SCAN_RESULT`, `CONNECT_RESULT`, `DISCONNECT`, `SET_STATE`) are
defined above but report `-EOPNOTSUPP` until Stage 4 wires them; their
payload layouts are specified with Stage 4. Events are numbered in their
own namespace: `SCAN_REQUEST = 0x01`, `CONNECT = 0x02`, `KEY = 0x03`,
`TX_FRAME = 0x04`.

## MAC/PHY/RF/station via an extracted `RegIo` core

MAC/PHY/RF/IQK/station bring-up is ~2–3k lines of chip register programming.
The builtin driver already writes it against a register-I/O trait, so rather
than reimplement it in the module (a huge, QEMU-untestable transcription), the
register-programming code is **extracted into a kernel-crate-free crate both
sides share**: `narf-drivers-wireless-rtl-chip`. The builtin driver drives it
over its native transport; the `.ko` supplies a `RegIo` impl over the
`narf_usb_*` EP0 path (`module_usb::UsbRegIo`). No duplication.

Staged, each slice non-breaking (the builtin re-exports what moves):

1. **`RegIo` + `ChipError`** (done) — the register-I/O abstraction (read/write
   8/16/32 + `delay_us`; provided `update*`/`poll32`) + the module's
   `UsbRegIo`. Kernel-crate-free (`core` only), so it links in the `.ko`.
2. **MAC** — move `mac.rs` + `mac/values.rs` + the chip tables onto `RegIo`.
   Its one `narf_time` use becomes a `RegIo::poll32` attempt count; the
   `super::usb` queue/page lookups are passed in as plain `MacParams` so the
   core stays transport- and kernel-crate-free.
3. **PHY** (`phy.rs`) and **RF** (`radio.rs`) + IQK calibration.
4. **Station** bring-up, then the netdev + cfg80211 control plane (the native
   family host — see the resolved decisions above).

Only register-level helpers move onto `RegIo`; the datapath-specific transport
(bulk reserved-page firmware writes, `narf_firmware_*`, `narf_netif_*`) stays in
the `.ko`.

## Staging (each stage independently reviewable + testable)

1. **USB transport adapter + enumerate/firmware proof.** `module_usb` implements
   `UsbControl`/`UsbIo` over `narf_usb_*`; `probe_c` does `config_descriptor` →
   `configure` → reads the chip id via a vendor control transfer → runs the
   rtw88 firmware-download stage against the module transport. No wireless host
   yet; success = firmware accepted. Proves the module drives the real device.
2. **MAC/PHY/IQK/station bring-up.** Run the remaining Backend stages in the
   module to the “awake station” state. Still no stack publication.
3. **Native wireless family host + `REGISTER_WIPHY` + netdev.** Stand up the
   host, register the family, publish the wiphy/netdev
   (`narf_netif_register_with_context`), wire RX via `narf_netif_rx` and TX via
   the callback. Data plane live. — Host done: `narf-wireless` registers
   family `WIFI` v1 at boot; `REGISTER_WIPHY` publishes the wiphy shell and
   returns its index. The module-side netdev + Stage 4 control plane are
   still open (see Stage 4).
4. **cfg80211 control plane.** Implement the scan/connect/key opcodes + events
   end to end.

Stage 1 is the natural first PR. Stages 3–4 define/extend the opcode contract
and are where the host grows.

## Resolved decisions (2026-11-20 review)

- **Event direction for cfg80211 ops → (a).** Add a per-session event callback
  to `narf_wireless_open` (ABI addition) so native cfg80211 ops reach the module
  cleanly, rather than tunnelling them through the `netif` `tx_callback`. Lands
  in Stage 3/4 when the control plane is wired.
  Implemented as an **additive** export, `narf_wireless_open_with_event`
  (Stage 3): the existing `narf_wireless_open` signature is preserved — the
  mt76 `.ko` calls it, and changing it would break that module's CRC — and
  the callback travels through a new `open_with_event` broker path into the
  host session, invoked only through a bus call gate. A plain-open session
  has no event channel.
- **Host crate → `narf-wireless`.** The native family host lives in the existing
  cfg80211 core crate, not a new crate. Implemented (Stage 3):
  `wireless/src/module_host.rs`, registered from
  `narf_wireless::register_initcalls`.

## Risks / open questions (for review)
- **Async over a sync poll ABI.** rtw88's Backend is `async`; `narf_usb_poll` is
  a one-shot poll with `on_event`. The module needs a small executor that drives
  the futures off completion callbacks (ftdi does a synchronous version). Reuse
  `future_heap` + a module-local poll loop.
  Grounded (Stage 3): the host side follows the mt76 precedent — each session
  holds one operation slot with a boxed future advanced with a noop waker on
  each poll, so Stage 4 async work plugs in without reshaping the host. No
  Daniel call needed; the module-side executor is Lane B's problem.
- **Which native crate hosts the family.** `narf-wireless` (already the cfg80211
  core) vs a new `narf-drivers-wireless-host`. Leaning `narf-wireless`.
  Resolved and implemented (Stage 3): `narf-wireless`.
- **DMA/URB lifetime across unload.** `close` must retain in-flight URBs until
  terminal completion (the ABI already specifies this for both USB and
  wireless); the module executor must not free buffers a pending `poll` owns.
  Grounded (Stage 3): the host side follows the existing contract — `close`
  unpublishes the wiphy, revokes the cap, and retains started native work in
  a spawned task until its terminal completion, independently of module text.
  The URB/buffer side lives in the module (Lane B); no Daniel call needed.
  Known Stage 3 limitation (follow-up, not a blocker): the module's netdev
  is named `eth%d` by the bus while the host shell is `wlan{N}` — the
  shell↔netdev name binding needs wifi-aware netdev naming.

## Non-goals (this effort)

- cyw43439 SPI (separate Tier-2 track).
- Changing the net-domain isolation model (datapath inherits it for free).
- RF/hardware acceptance (QEMU has no rtw88 USB device; validation is dual
  builds, fixtures, gated tests + the enumerate/firmware fixture path).
