//! Broadcom / Infineon FullMAC Wi-Fi family — dual-build (built-in or loadable
//! `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/{brcmfmac,cyw43439}/`
//! modules into one family crate. The two drivers are a deeply intertwined
//! Broadcom FullMAC pair: cyw43439 reuses brcmfmac's chip/event/provision/vif/
//! ap code and brcmfmac reuses cyw43439's fullmac/station/runtime, a
//! bidirectional dependency that cannot be split across crates — so they share
//! a crate (inner module paths `brcmfmac`/`cyw43439` preserved).
//!
//! The real drivers in [`brcmfmac`]/[`cyw43439`] compile only for the built-in
//! build. The `module` build registers BOTH buses — brcmfmac's Broadcom PCIe
//! ids through `narf_register_pci_driver` and the CYW43439 SDIO id through
//! `narf_register_sdio_driver` (the Tier-2 SDIO shim) — with a probe thunk that
//! returns `-ENOSYS` (registration-only proof), matching the net and iwlwifi
//! `.ko`s.
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates neither a Broadcom PCIe Wi-Fi device nor a CYW43439 SDIO
//! card, so chip bring-up and association cannot run here. Validation is dual
//! builds, fixtures and the gated station/AP tests on both architectures;
//! these do not establish RF acceptance.

#![no_std]
#![allow(dead_code)]

#[cfg(feature = "builtin")]
extern crate alloc;

use narf_driver_macros::narf_driver;

// Shared, driver-agnostic helpers live in `narf-drivers-wireless-core`.
// Re-exported at the crate root so the inner drivers' `crate::future_heap`
// references resolve unchanged after promotion.
#[cfg(feature = "builtin")]
pub(crate) use narf_drivers_wireless_core::future_heap;

#[cfg(feature = "builtin")]
pub mod brcmfmac;

#[cfg(feature = "builtin")]
pub mod cyw43439;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "brcm",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Broadcom/Infineon FullMAC Wi-Fi (brcmfmac PCIe + CYW43439 SDIO)",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    brcmfmac::register();
    cyw43439::register();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
