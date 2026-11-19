//! Intel PCIe Bluetooth controller — dual-build (built-in or loadable `.ko`).
//!
//! The driver body lives in [`btintel_pcie`] and compiles only for the
//! built-in build (x86_64, where the PCIe bus is). It plugs into the
//! `narf-bluetooth` host stack through that crate's public transport,
//! controller and PM registries.
//!
//! The `module` build registers the same PCI ids through the
//! `narf_register_pci_driver` KSYMTAB export (registration-only until the
//! device datapath ABI covers Bluetooth). See `narf-drivers-net-tg3` for the
//! registration-only shape.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

/// Intel PCIe-attached Bluetooth controllers (Lunar Lake onward).
/// Needs the PCIe bus, so x86_64 only for now.
#[cfg(all(feature = "builtin", target_arch = "x86_64"))]
pub mod btintel_pcie;

#[cfg(all(feature = "kernel-test", target_arch = "x86_64"))]
mod btintel_pcie_tests;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "btintel_pcie",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Intel PCIe Bluetooth controller",
        target_domain: "net",
    },
    register: do_register,
}

#[cfg(all(feature = "builtin", target_arch = "x86_64"))]
fn do_register() {
    btintel_pcie::register_pci_driver();
}

#[cfg(all(feature = "builtin", not(target_arch = "x86_64")))]
fn do_register() {}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}

/// Stage::Subsys initcall: register the PCI match. Called by `frame`
/// alongside `narf_bluetooth::register_initcalls`.
#[cfg(feature = "builtin")]
pub fn register_initcalls() {
    #[cfg(target_arch = "x86_64")]
    narf_init::register(narf_init::Stage::Subsys, "btintel-pcie", || {
        register();
        narf_init::InitResult::Ok
    });
}

/// Stage::Late controller firmware download.
///
/// Kept out of [`register_initcalls`] on purpose: it must run after the
/// firmware scans, and Stage::Late initcalls run in registration order.
/// `frame`'s `bare_main` calls this after
/// `narf_firmware::register_rootfs_scan_initcall()`, and before it
/// registers `bluetooth-bringup`.
#[cfg(feature = "builtin")]
pub fn register_firmware_initcalls() {
    #[cfg(target_arch = "x86_64")]
    narf_init::register(narf_init::Stage::Late, "btintel-pcie-firmware", || {
        btintel_pcie::load_firmware();
        narf_init::InitResult::Ok
    });
}
