//! JEDEC JC-42.4 (jc42) DIMM thermal sensor driver.
//!
//! Provides temperature readings from standard memory modules
//! via I2C/SMBus, common in server hardware monitoring.
//!
//! References: `linux/drivers/hwmon/jc42.c`

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;

/// Register the jc42 I2C driver.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "jc42", || {
        let _ = writeln!(Writer, "  hwmon: JEDEC JC-42.4 DIMM thermal sensor driver registered");
        // Placeholder: parse SMBus for I2C addresses 0x18-0x1f
        InitResult::Ok
    });
}
