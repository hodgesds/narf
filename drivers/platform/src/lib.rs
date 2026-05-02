//! Platform / chipset peripheral drivers.
//!
//! Clean-room implementations of standardised platform devices
//! whose specs are public (Intel ICH SMBus, TPM 2.0). Each driver
//! lives in its own module + registers via Stage::Subsys initcalls.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod smbus;
pub mod tpm;

mod tests;

/// Stage::Subsys initcalls for this driver crate.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "smbus", || {
        smbus::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "tpm", || {
        tpm::try_init_default();
        InitResult::Ok
    });
}
