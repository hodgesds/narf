//! Qualcomm Atheros ath9k — dual-build (built-in or loadable `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/ath9k{.rs,/}` module. The
//! shared Qualcomm/Atheros code it uses (`qualcomm_pci`/`qualcomm_regulatory`)
//! lives in `narf-drivers-wireless-ath-core`; see `drivers/wireless/ath10k/`
//! for the reference single-driver dual-build shape.
//!
//! ath9k is PCIe-only (AR5008/AR9001/AR9002/AR9003 families). Built in, the
//! driver in [`ath9k`] binds every Atheros PCIe id it owns (vendor
//! `0x168c`). The `module` build is the same driver running inside the
//! `.ko`, every chip owner (AR5008, AR9280, AR9285/AR2427, AR9287 and the
//! AR9300 family): it registers the same ids through
//! `narf_register_pci_driver` and drives the chip through the KABI (BAR
//! access, the PCI Command register, PCIe state, a read-only config dword,
//! plain MSI, mapped DMA, signed board/qualification records and the host
//! regulatory domain), with its netdev and wiphy published through the
//! netif bridge and the `WIFI` family host. `narf_module_exit` runs the
//! bound owner's device removal.
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates no Atheros Wi-Fi PCIe device, so bring-up and association
//! cannot run here. Validation is dual builds, fixtures and the gated tests on
//! both architectures; these do not establish RF acceptance.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

use narf_driver_macros::narf_driver;

/// The driver. One source tree in both builds: kernel services come from
/// [`ath9k::platform`], which is the kernel's crates built in and
/// `narf-module-rt` + the KABI in the `.ko`.
pub mod ath9k;

narf_driver! {
    name: "ath9k",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Qualcomm Atheros ath9k (AR5008..AR9003 PCIe)",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write,DmaBuffer:Write,Firmware:Read",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    ath9k::register();
}

#[cfg(feature = "module")]
fn do_register() {
    ath9k::register_module();
}

/// Module exit (`rmmod`): remove the bound radio as built-in device removal
/// does, then stop the module's executor.
#[cfg(feature = "module")]
#[unsafe(no_mangle)]
pub extern "C" fn narf_module_exit() {
    ath9k::exit_module();
}
