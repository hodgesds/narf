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
//! Built in, [`rtl8xxxu`] and [`rtlwifi`] are the whole drivers. The `module`
//! build (`rtl.ko`) runs the drivers' own code inside the `.ko` over
//! `narf-module-rt` and the KABI (kernel services come from [`platform`], the
//! same names in both builds), as far as it is carried today:
//!
//! - **rtlwifi (PCIe)** — every rtlwifi id. Probe runs the built-in probe's
//!   identification stage ([`rtlwifi::identity`]: BAR2 checks, ASPM off,
//!   the chip's NIC-enable power table, interrupt masking, the factory EFUSE
//!   map and MAC), then publishes `wlan%d` and its wiphy through the netif
//!   bridge and the `WIFI` family host. That is the built-in's diagnostic
//!   profile: firmware, native preparation and the station are not carried
//!   yet, so scan and connect are refused.
//! - **rtl8xxxu (USB)** — every `RTL8XXXU_USB_IDS` row. Probe classifies the
//!   dongle with the driver's own chip-family table and claims it, as the
//!   built-in probe does; the firmware/station owners are not carried yet.
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

#[cfg(feature = "builtin")]
pub mod rtl8xxxu;

/// The module build's rtl8xxxu: the chip-family table and the USB binding.
#[cfg(feature = "module")]
pub mod rtl8xxxu {
    pub mod regs;
    pub mod usb_kabi;
}

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

#[cfg(feature = "module")]
fn do_register() {
    // The kernel DRBG feeds `narf-crypto` (EAPOL nonces) before any probe.
    platform::install_entropy();
    rtl8xxxu::usb_kabi::register();
    rtlwifi::pci_kabi::register_pci_driver();
}
