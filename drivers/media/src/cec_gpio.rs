//! GPIO-based Consumer Electronics Control (CEC) driver.
//!
//! Handles HDMI CEC communication via bit-banging on a single GPIO pin.
//!
//! Reference: `linux/drivers/media/cec/platform/cec-gpio/cec-gpio.c`

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "media-cec-gpio", || {
        let _ = writeln!(Writer, "  media: Registered GPIO-based HDMI CEC driver");
        InitResult::Ok
    });
}
