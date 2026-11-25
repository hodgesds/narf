//! Legacy Realtek Wi-Fi family — dual-build (built-in or loadable `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/{rtl8xxxu,rtlwifi}/` modules
//! into one family crate. rtl8xxxu (USB) reuses rtlwifi's (PCIe) `wmm::priority`
//! helper — a one-directional dependency that keeps the two in a single crate
//! (inner module paths `rtl8xxxu`/`rtlwifi` preserved). Both reuse already-
//! promoted crates: the shared Realtek USB transport
//! (`narf-drivers-wireless-rtl-usb`), the iwlwifi MLME builder
//! (`narf_drivers_wireless_iwlwifi::iwlwifi::mlme`) and rtw88's efuse decoder
//! (`narf_drivers_wireless_rtw::rtw88::efuse`), which forwards to the
//! kernel-free Realtek chip core (`narf_drivers_wireless_rtl_chip::efuse`) that
//! `rtlwifi::efuse` calls directly so the `.ko` can link it.
//!
//! One source builds both ways. Built in, [`rtl8xxxu`] and [`rtlwifi`] use
//! the kernel's crates. As `rtl.ko` the same drivers run over
//! `narf-module-rt` and the KABI: kernel services come from [`platform`]
//! under the same names in both builds, and only the bus bindings differ
//! (`rtlwifi::pci_kabi`, `rtlwifi::firmware_native` over the KABI,
//! `rtl8xxxu::usb_kabi`, the shared USB transport in `platform::rtl_usb`).
//!
//! - **rtlwifi (PCIe)** — every rtlwifi id: identification, firmware,
//!   native preparation and the station, published as `wlan%d` with a
//!   wiphy through the netif bridge and the `WIFI` family host
//!   (`module_netdev`).
//! - **rtl8xxxu (USB)** — every `RTL8XXXU_USB_IDS` row: the family chain
//!   unchanged; the USB station gets a netdev (no wiphy: the `WIFI` host is
//!   bound to PCI device authority) and its SME is driven by `rtl.ssid=` /
//!   `rtl.psk=` / `rtl.passphrase=`.
//!
//! See `drivers/wireless/specification/spec.md` §4.3.
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates neither a Realtek USB Wi-Fi dongle nor a Realtek PCIe Wi-Fi
//! device, so chip bring-up and association cannot run here. Validation is dual
//! builds, fixtures and the gated station/AP tests on both architectures; these
//! do not establish RF acceptance.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

/// Kernel services under one name in both builds.
pub mod platform;

/// The id tables `rtl.ko` registers (also read by its e2e load test).
pub mod module_ids;
#[cfg(feature = "kernel-test")]
mod module_ids_tests;

use narf_driver_macros::narf_driver;

// Shared, driver-agnostic helpers live in `narf-drivers-wireless-core`
// (built in) or the module platform. Re-exported at the crate root so the
// inner drivers' `crate::firmware_asset` / `crate::future_heap` /
// `crate::watchdog_work` references resolve unchanged in both builds.
pub(crate) use platform::{firmware_asset, future_heap, watchdog_work};

pub mod rtl8xxxu;

pub mod rtlwifi;

/// The module build's netdev and wiphy, which either driver's station
/// publishes through; the platform forwards the drivers' kernel calls here.
#[cfg(feature = "module")]
pub(crate) mod module_netdev;

narf_driver! {
    name: "rtl",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Legacy Realtek Wi-Fi (rtl8xxxu USB + rtlwifi PCIe)",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    rtl8xxxu::register();
    rtlwifi::register();
}

/// The USB station's parameter-driven SME (`module_netdev::autoconnect`):
/// `rtl.ssid=` / `rtl.psk=` (64 hex digits) / `rtl.passphrase=`, applied
/// from the kernel command line and the load's own arguments. Empty = not
/// given. A PCIe station is driven by nl80211 through its wiphy instead.
#[cfg(feature = "module")]
#[used]
#[link_section = ".narf_kparams"]
static KPARAMS: [u8; 23] = *b"ssid=\npsk=\npassphrase=\n";

#[cfg(feature = "module")]
fn do_register() {
    // The kernel DRBG feeds `narf-crypto` (EAPOL nonces) before any probe.
    platform::install_entropy();
    rtl8xxxu::usb_kabi::register();
    rtlwifi::pci_kabi::register_pci_driver();
}
