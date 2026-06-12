//! Virtual Video Test Driver (vivid).
//!
//! Provides a software-only virtual video device for testing the
//! V4L2/media pipeline without requiring physical hardware.
//!
//! References: `linux/drivers/media/test-drivers/vivid/`

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;

/// Register the vivid driver initcalls.
pub fn register_initcalls() {
    let _ = writeln!(
        Writer,
        "  media: Virtual Video Test (vivid) driver registered"
    );
    // Placeholder for software device creation
}
