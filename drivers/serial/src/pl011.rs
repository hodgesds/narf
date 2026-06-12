//! ARM PrimeCell UART (PL011) Driver.
//!
//! Provides serial console and TTY support for the standard UART
//! block found on most ARM SoCs, including the Raspberry Pi.
//!
//! References: `linux/drivers/tty/serial/amba-pl011.c`

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;

/// Register the PL011 platform driver.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "pl011", || {
        let _ = writeln!(
            Writer,
            "  serial: ARM PrimeCell PL011 UART driver registered"
        );
        // Placeholder: parse DeviceTree for `arm,pl011` compatible strings.
        InitResult::Ok
    });
}
