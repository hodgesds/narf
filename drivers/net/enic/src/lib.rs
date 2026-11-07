//! Cisco VIC Ethernet NIC — dual-build (built-in or loadable `.ko`).
//!
//! Explicit refusal marker, not a driver (issue #798): the enic datapath
//! is deferred out of desktop scope, so [`enic::probe`] declines every
//! device with `ProbeError::NotForThisDriver` and the device stays
//! available to other claimants. See `narf-drivers-net-e1000` for the
//! reference dual-build pattern. The `module` build registers through
//! the `narf_register_pci_driver` KSYMTAB export; its probe thunk
//! returns `-ENOSYS` for the same reason.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

#[cfg(feature = "builtin")]
pub use narf_drivers_net_core::*;

#[cfg(feature = "builtin")]
pub mod enic;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "enic",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Cisco VIC Ethernet NIC",
        target_domain: "net",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    enic::register_pci_driver();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
