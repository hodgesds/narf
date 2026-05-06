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
pub mod ec;
pub mod battery;
pub mod thermal;
pub mod fan;
pub mod lid;
pub mod buttons;
pub mod backlight;

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
    narf_init::register(Stage::Subsys, "acpi-ec", || {
        ec::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "acpi-battery", || {
        battery::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "acpi-thermal", || {
        thermal::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "acpi-fan", || {
        fan::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "acpi-lid", || {
        lid::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "acpi-buttons", || {
        buttons::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "acpi-backlight", || {
        backlight::init();
        InitResult::Ok
    });
}

