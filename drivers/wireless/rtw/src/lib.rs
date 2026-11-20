//! Realtek RTW88/RTW89 PCIe Wi-Fi family — dual-build (built-in or loadable
//! `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/{rtw88,rtw89}/` modules into
//! one family crate: rtw89 reuses rtw88's `pci_park` helper, so they share a
//! crate (inner module paths `rtw88`/`rtw89` preserved). rtw88's USB datapath
//! reuses the shared transport in `narf-drivers-wireless-rtl-usb`.
//!
//! The real drivers in [`rtw88`]/[`rtw89`] compile only for the built-in
//! build. The `module` build registers both drivers' Realtek PCI ids through
//! the `narf_register_pci_driver` KSYMTAB export; the probe thunk returns
//! `-ENOSYS` (registration-only proof), matching the net and iwlwifi `.ko`s.
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates no Realtek Wi-Fi PCIe device, so chip bring-up and
//! association cannot run here. Validation is dual builds, fixtures and the
//! gated station/AP tests on both architectures; these do not establish RF
//! acceptance.

#![no_std]
#![allow(dead_code)]

#[cfg(feature = "builtin")]
extern crate alloc;

use narf_driver_macros::narf_driver;

// Shared, driver-agnostic helpers live in `narf-drivers-wireless-core`.
// Re-exported at the crate root so the inner drivers' `crate::future_heap` and
// `crate::watchdog_work` references resolve unchanged after promotion.
#[cfg(feature = "builtin")]
pub(crate) use narf_drivers_wireless_core::{future_heap, watchdog_work};

#[cfg(feature = "builtin")]
pub mod rtw88;

#[cfg(feature = "builtin")]
pub mod rtw89;

#[cfg(feature = "module")]
mod module_probe;

// Stage 1 of the rtw88-USB loadable-module datapath (enumerate + Realtek
// control proof over `narf_usb_*`). See
// drivers/wireless/specification/rtw88-usb-module-datapath.md.
#[cfg(feature = "module")]
mod module_usb;

narf_driver! {
    name: "rtw",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Realtek RTW88/RTW89 PCIe Wi-Fi + RTL8821CU/8822BU USB",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    rtw88::register();
    rtw89::register();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
    module_usb::register();
}
