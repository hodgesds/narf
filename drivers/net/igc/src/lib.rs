//! Intel I225/I226 2.5GbE NIC — dual-build (built-in or loadable `.ko`).
//!
//! See `narf-drivers-net-e1000` for the reference pattern. The real driver in
//! [`igc`] compiles only for the built-in build; the `module` build registers
//! through the `narf_register_pci_driver` KSYMTAB export (registration-only
//! until the device datapath ABI lands).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

#[cfg(feature = "builtin")]
pub use narf_drivers_net_core::*;

#[cfg(feature = "builtin")]
pub mod igc;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "igc",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Intel I225/I226 2.5GbE NIC",
        target_domain: "net",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    igc::register_pci_driver();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
