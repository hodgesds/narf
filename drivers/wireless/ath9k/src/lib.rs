//! Qualcomm Atheros ath9k — dual-build (built-in or loadable `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/ath9k{.rs,/}` module. The
//! shared Qualcomm/Atheros code it uses (`qualcomm_pci`/`qualcomm_regulatory`)
//! lives in `narf-drivers-wireless-ath-core`; see `drivers/wireless/ath10k/`
//! for the reference single-driver dual-build shape.
//!
//! ath9k is PCIe-only (AR5008/AR9001/AR9002/AR9003 families). The real driver
//! in [`ath9k`] binds the Atheros PCIe ids (vendor `0x168c`); the `module`
//! build registers that id table through `narf_register_pci_driver` with a
//! probe thunk that returns `-ENOSYS` (registration-only proof), matching the
//! net and iwlwifi `.ko`s.
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates no Atheros Wi-Fi PCIe device, so bring-up and association
//! cannot run here. Validation is dual builds, fixtures and the gated tests on
//! both architectures; these do not establish RF acceptance.

#![no_std]
#![allow(dead_code)]

#[cfg(feature = "builtin")]
extern crate alloc;

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
pub mod ath9k;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "ath9k",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Qualcomm Atheros ath9k (AR5008..AR9003 PCIe)",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    ath9k::register();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
