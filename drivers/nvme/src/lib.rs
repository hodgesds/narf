//! narf-drivers-nvme — NVMe host driver, dual-build.
//!
//! Single-driver crate: the whole crate is dual-build (built-in rlib or a
//! loadable `.ko`). The driver body lives in [`imp`] and compiles only for the
//! built-in build (re-exported here so `narf_drivers_nvme::…` is unchanged for
//! callers). The `module` build ([`module_probe`]) is a small polled NVMe host
//! written only against KSYMTAB exports: it drives the controller through the
//! PCI/MMIO/DMA exports and publishes namespace 1 through `narf_blk_register`.
//! See `narf-drivers-net-e1000` for the dual-build pattern.

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
        required_caps: "DmaBuffer:Write,BusDevice:Write,BlockDevice:Write",
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
    #[cfg(not(feature = "nvme-module-only"))]
    narf_init::register(Stage::Subsys, "nvme", || {
        register();
        InitResult::Ok
    });
    // AER supervisor (#928): spawn once the executor is up, so
    // namespace-change AERs are drained + rescanned without any
    // I/O having to happen first. Stage::Late runs after
    // scheduler::init; spawning earlier would panic. Idempotent —
    // the spawn itself guards against a second task.
    narf_init::register(Stage::Late, "nvme-aer-supervisor", || {
        imp::spawn_aer_supervisor();
        InitResult::Ok
    });
}
