//! Legacy Realtek Wi-Fi family — dual-build (built-in or loadable `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/{rtl8xxxu,rtlwifi}/` modules
//! into one family crate. rtl8xxxu (USB) reuses rtlwifi's (PCIe) `wmm::priority`
//! helper — a one-directional dependency that keeps the two in a single crate
//! (inner module paths `rtl8xxxu`/`rtlwifi` preserved). Both reuse already-
//! promoted crates: the shared Realtek USB transport
//! (`narf-drivers-wireless-rtl-usb`), the iwlwifi MLME builder
//! (`narf_drivers_wireless_iwlwifi::iwlwifi::mlme`) and rtw88's efuse decoder
//! (`narf_drivers_wireless_rtw::rtw88::efuse`).
//!
//! The real drivers in [`rtl8xxxu`]/[`rtlwifi`] compile only for the built-in
//! build. The `module` build registers BOTH buses — rtl8xxxu's Realtek USB
//! VID/PIDs through `narf_register_usb_driver` and rtlwifi's Realtek PCIe ids
//! through `narf_register_pci_driver` — with a probe thunk that returns
//! `-ENOSYS` (registration-only proof), matching the net and iwlwifi `.ko`s.
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates neither a Realtek USB Wi-Fi dongle nor a Realtek PCIe Wi-Fi
//! device, so chip bring-up and association cannot run here. Validation is dual
//! builds, fixtures and the gated station/AP tests on both architectures; these
//! do not establish RF acceptance.

#![no_std]
#![allow(dead_code)]

#[cfg(feature = "builtin")]
extern crate alloc;

use narf_driver_macros::narf_driver;

// Shared, driver-agnostic helpers live in `narf-drivers-wireless-core`.
// Re-exported at the crate root so the inner drivers' `crate::firmware_asset` /
// `crate::future_heap` / `crate::watchdog_work` references resolve unchanged
// after promotion.
#[cfg(feature = "builtin")]
pub(crate) use narf_drivers_wireless_core::{firmware_asset, future_heap, watchdog_work};

#[cfg(feature = "builtin")]
pub mod rtl8xxxu;

#[cfg(feature = "builtin")]
pub mod rtlwifi;

#[cfg(feature = "module")]
mod module_probe;

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

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
