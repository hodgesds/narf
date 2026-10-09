//! Microsemi smartpqi controller — dual-build (built-in or loadable `.ko`). See narf-drivers-net-e1000.
#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
use narf_driver_macros::narf_driver;
#[cfg(feature = "builtin")]
extern crate alloc;
#[cfg(feature = "builtin")]
pub use narf_drivers_storage_core::*;
#[cfg(feature = "module")]
mod module_probe;
#[cfg(feature = "builtin")]
pub mod smartpqi;
narf_driver! {
    name: "smartpqi",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Microsemi smartpqi controller",
        target_domain: "block",
    },
    register: do_register,
}
#[cfg(feature = "builtin")]
fn do_register() {
    smartpqi::register_pci_driver();
}
#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
