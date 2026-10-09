//! narf-drivers-nvme — NVMe host driver, dual-build.
//!
//! Single-driver crate: the whole crate is dual-build (built-in rlib or a
//! loadable `.ko`). The driver body lives in [`imp`] and compiles only for the
//! built-in build (re-exported here so `narf_drivers_nvme::…` is unchanged for
//! callers); the `module` build registers through the `narf_register_pci_driver`
//! KSYMTAB export (registration-only, `-ENOSYS` probe, until the device
//! datapath ABI lands). See `narf-drivers-net-e1000` for the pattern.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

#[cfg(feature = "builtin")]
mod imp;
#[cfg(feature = "builtin")]
pub use imp::*;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "nvme",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "NVMe host controller",
        target_domain: "block",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    imp::register_pci_driver();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}

/// Stage::Subsys initcalls for this driver crate.
#[cfg(feature = "builtin")]
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "nvme", || {
        register();
        InitResult::Ok
    });
}
