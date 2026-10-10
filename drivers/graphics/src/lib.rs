//! Display drivers — dual-build (built-in or loadable `.ko`).
//!
//! M0 surface: bochs-display (`-device bochs-display`) on x86_64 q35.
//! Future modules: virtio-gpu (cross-arch), ramfb (paravirt minimal).
//!
//! Single-driver crate: there is nothing to split, so the whole crate is made
//! dual-build. The driver body ([`bochs`], [`generic`]) compiles only for the
//! built-in build; the `module` build registers through the
//! `narf_register_pci_driver` KSYMTAB export (registration-only, `-ENOSYS`
//! probe, until the device datapath ABI lands). See `narf-drivers-net-e1000`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

#[cfg(feature = "builtin")]
pub mod bochs;
#[cfg(feature = "builtin")]
pub mod generic;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "bochs-display",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Bochs/QEMU display controller",
        target_domain: "graphics",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    // bochs-display is an x86_64 q35 device.
    #[cfg(target_arch = "x86_64")]
    bochs::register_pci_driver();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}

/// Stage::Subsys initcalls for this driver crate.
#[cfg(feature = "builtin")]
pub fn register_initcalls() {
    #[cfg(target_arch = "x86_64")]
    {
        use narf_init::{InitResult, Stage};
        narf_init::register(Stage::Subsys, "bochs-display", || {
            register();
            InitResult::Ok
        });
    }
}
