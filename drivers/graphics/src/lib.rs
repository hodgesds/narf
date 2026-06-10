//! Display drivers.
//!
//! M0 surface: bochs-display (`-device bochs-display`) on x86_64 q35.
//! Future modules: virtio-gpu (cross-arch), ramfb (paravirt minimal).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod bochs;
pub mod generic;

/// Stage::Subsys initcalls for this driver crate.
pub fn register_initcalls() {
    #[cfg(target_arch = "x86_64")]
    use narf_init::{InitResult, Stage};
    #[cfg(target_arch = "x86_64")]
    narf_init::register(Stage::Subsys, "bochs-display", || {
        bochs::register_pci_driver();
        InitResult::Ok
    });
}
