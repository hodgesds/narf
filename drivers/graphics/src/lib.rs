//! Display drivers.
//!
//! M0 surface: bochs-display (`-device bochs-display`) on x86_64 q35.
//! Future modules: virtio-gpu (cross-arch), ramfb (paravirt minimal).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod bochs;

/// Stage::Subsys initcalls for this driver crate.
#[cfg(target_arch = "x86_64")]
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "bochs-display", || {
        bochs::register_pci_driver();
        InitResult::Ok
    });
}

/// No-op on non-x86_64 (bochs-display is x86_64-only today).
#[cfg(not(target_arch = "x86_64"))]
pub fn register_initcalls() {}
