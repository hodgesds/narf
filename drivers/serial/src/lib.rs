//! Serial drivers for NARF.
//!
//! Provides the 8250/16550 UART driver for standard PC serial ports
//! (COM1-COM4 at 0x3F8/0x2F8/0x3E8/0x2E8) and ACPI PNP0501
//! enumeration for non-legacy ports.
//!
//! Linux references:
//! - `drivers/tty/serial/8250/8250_port.c` (Alan Cox, et al. — GPL-2.0)
//! - `drivers/tty/serial/8250/8250_core.c`
//!
//! ## Initialization
//!
//! On bare-metal x86_64 the COM1 UART at 0x3F8 is typically available
//! immediately after reset. `Uart8250::new(0x3F8, Some(4))` constructs
//! a handle for COM1 on IRQ 4. Call `.init()` to program FIFO + baud
//! then `.write(b)` / `.read()` for single-byte I/O.
//!
//! Early console (`earlycon`) path in the boot crate should call
//! `uart_8250::init_early_console()` which probes COM1 and programs
//! it for 115200 baud without full IRQ setup.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod intel_lpss;
pub mod probe;
pub mod registry;
pub mod uart_8250;

mod tests;

/// Stage::Subsys initcalls for the serial crate.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "serial-8250", || {
        uart_8250::register_legacy_uarts();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "serial-lpss", || {
        intel_lpss::probe_all();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "serial-acpi", || {
        probe::enumerate_acpi_uarts();
        InitResult::Ok
    });
}
