//! Intel TCO Hardware Watchdog Timer.
//!
//! Exposes the TCO (Total Cost of Ownership) watchdog timer present on
//! most Intel chipsets (ICH, PCH) commonly used in servers to reset
//! the system if the OS hangs.
//!
//! References: `linux/drivers/watchdog/iTCO_wdt.c`

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;

/// Register the iTCO_wdt platform driver.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "itco_wdt", || {
        let _ = writeln!(Writer, "  platform: Intel TCO Watchdog Timer driver registered");
        // Placeholder: parse SMBus base address or LPC bridge to find TCObase.
        InitResult::Ok
    });
}
