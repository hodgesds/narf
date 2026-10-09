//! USB4 native host interface and connection manager — dual-build.
//!
//! PCI discovery includes AMD Pink Sardine and Intel USB4 class controllers.
//! Firmware `_OSC` must grant USB3/DisplayPort ownership before ring zero is
//! started. One actor owns each NHI's DMA rings, config transactions, topology,
//! and tunnels. PCIe/XDomain tunneling and legacy ICM are not implemented.
//!
//! Reference: `/usr/src/linux/drivers/thunderbolt/{pci,nhi,ctl,usb4,path,tunnel}.c`.
//!
//! Single-driver crate: the whole crate is dual-build (built-in rlib or a
//! loadable `.ko`). The driver body compiles only for the built-in build; the
//! `module` build registers through the `narf_register_pci_driver` KSYMTAB
//! export (registration-only, `-ENOSYS` probe). See `narf-drivers-net-e1000`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

#[cfg(feature = "builtin")]
pub mod adapter;
#[cfg(feature = "builtin")]
pub mod cm;
#[cfg(feature = "builtin")]
mod control;
#[cfg(feature = "builtin")]
mod firmware;
#[cfg(feature = "builtin")]
pub mod nhi;
#[cfg(feature = "builtin")]
mod ring;
#[cfg(feature = "builtin")]
mod runtime;
#[cfg(feature = "builtin")]
pub mod switch;
#[cfg(feature = "builtin")]
pub mod topology;
#[cfg(feature = "builtin")]
pub mod tunnel;

#[cfg(all(feature = "builtin", target_arch = "x86_64"))]
mod tests;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "usb4-nhi",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "USB4/Thunderbolt NHI host controller",
        target_domain: "scratch",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    nhi::register_pci_driver_thunderbolt();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}

/// Discover controllers during Device init and start native CMs during Late init.
#[cfg(feature = "builtin")]
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "usb4-nhi", || {
        register();
        InitResult::Ok
    });
    narf_init::register(Stage::Late, "usb4-native-cm", runtime::start);
}
