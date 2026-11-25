# rtw88-USB loadable-module datapath — design

Status: **implemented.** The rtw88 driver's own source runs in the `.ko` for
its USB parts (RTL8821CU / RTL8822BU). The module's behaviour, platform
shims, probe order, transport, netdev and control plane are specified in
`drivers/wireless/specification/spec.md` §4.8; the generic `WIFI` family
host is §4.1. The KABI the module added is `modules/DATAPATH_ABI_DESIGN.md`,
"USB device poller and the regulatory domain". This note records the two
structural decisions behind that design and the limits that remain open.

## Shape: the driver tree in the module

`narf-drivers-wireless-rtw --no-default-features --features module` builds
the real `src/rtw88/` tree into the `.ko`: `usb_firmware::Backend`,
`usb_driver`'s factory read and provisioning, `firmware_lifecycle`,
`interface::Device` and the in-driver SME. The kernel services the driver
names (`narf_time`, `narf_net`, `narf_wireless::reg`, ...) come from
`src/rtw88/platform/` over `narf-module-rt` and the KABI under the same
names, so the driver bodies are shared with the built-in build. The USB
probe and transport are `usb_kabi.rs`; the netdev is `iface_module.rs`. The
rtw88 and rtw89 PCIe ids stay registration-only in the module
(`module_probe.rs`, probe `-ENOSYS`); rtw89 does not build into the `.ko`.

An earlier plan reimplemented the bring-up as a separate C-ABI module
driver, extracting register programming piece by piece. It was dropped once
`narf-module-rt` and kernel-free builds of `narf-crypto` / `narf-wireless`
let the driver itself link into a module, as ath11k does.

## Shared chip core: `narf-drivers-wireless-rtl-chip`

Some chip register programming lives in a `no_std`, `core`-only crate
written against an async register-I/O trait, `RegIo` (read/write 8/16/32
plus a delay; `update*` and `poll32` are free async helpers), with a small
`ChipError`. Both builds link it. It holds:

- `mac` — `mac.c::rtw_mac_init` / chip MAC init and the FIFO/LLT layout
  (`mac/{values,rtl8821c,rtl8821c_values,rtl8822b}.rs`), parameterized by a
  caller-computed `MacParams` (TXDMA queue map, pages, USB burst/aggregation
  tails) so the core carries no transport or kernel-crate dependency;
- `phy`, `phy_b22` — the RTL8822C and RTL8822B PHY table programming;
- `radio` — pure-register RF primitives and sub-sequences (C21 / C22 / B22,
  DACK). The rest of the radio bring-up is interleaved with firmware
  commands and station gating, so it stays in the rtw crate;
- `band5` — 5GHz channel facts shared by the C21/C22 channel programs;
- `efuse` — the Realtek physical-EFUSE decoder, also used by rtlwifi and
  rtl8xxxu.

rtw88 bridges its firmware-owner `Io` to `RegIo` through the
`chip_bridge::IoReg` newtype, which forwards each access 1:1 (so the
byte-exact register traces in the kernel tests are unchanged) and keeps the
native error of the last failed access, which `ChipError` cannot carry.

## Open limits

- **No wiphy for a USB function.** The wireless broker and the `WIFI` host
  bind a session to a bus device context's `Cap<BusDeviceCap, Write>`, which
  a USB function lacks. `rtw88.ko` publishes a `wlan%d` netdev and drives
  its in-driver SME from `rtw.ssid=` / `rtw.psk=` / `rtw.passphrase=` /
  `rtw.scan=`; nl80211 cannot reach it. Extending the broker to USB
  functions is a capability-model decision.
- **No endpoint-halt recovery.** The KABI has no CLEAR_FEATURE(HALT), so a
  stalled bulk pipe ends the attempt. USB reset, rejoin, runtime idle,
  system PM (`usb_recovery.rs`) and WoW are built-in only.
- **Transfer lifetime across unload.** `close` and unload must retain
  in-flight transfers until their terminal completion; the module executor
  must not free a buffer a pending poll still owns. Pollers and interfaces
  are retired with the USB context before module text is unmapped
  (`modules/src/usb_wifi.rs`).
- **Hardware validation.** QEMU emulates no Realtek USB Wi-Fi device. The
  module's bring-up, firmware, RF and association are unproven until run on
  hardware; the in-tree proof is the module load test (claims, parameters,
  context refusal, clean unload).

## Non-goals

- cyw43439 SPI (separate track).
- Changing the net-domain isolation model.
