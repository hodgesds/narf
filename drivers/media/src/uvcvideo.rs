//! USB Video Class (UVC) driver.
//!
//! Provides support for USB webcams and video capture devices conforming
//! to the USB Video Class specification.
//!
//! References: `linux/drivers/media/usb/uvc/`

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;

/// Register the UVC driver initcalls.
pub fn register_initcalls() {
    let _ = writeln!(Writer, "  media: UVC Video driver registered");
    // Placeholder for USB Class match (Class 14 - Video)
}
