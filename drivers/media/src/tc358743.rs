//! Toshiba TC358743 HDMI to MIPI CSI-2 bridge driver.
//!
//! Extremely common in HDMI capture adapters (e.g., for Raspberry Pi).
//!
//! Reference: `linux/drivers/media/i2c/tc358743.c`

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;

pub const TC358743_I2C_ADDR: u16 = 0x0f;

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "media-tc358743", || {
        let _ = writeln!(Writer, "  media: Registered Toshiba TC358743 HDMI capture bridge");
        InitResult::Ok
    });
}
