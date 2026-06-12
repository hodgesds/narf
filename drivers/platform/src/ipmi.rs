//! IPMI Baseboard Management Controller Driver.
//!
//! Exposes KCS, BT, and SSIF transport interfaces for communicating
//! with the server's BMC.
//!
//! References: `linux/drivers/char/ipmi/`

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;

/// Register the IPMI driver.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "ipmi", || {
        let _ = writeln!(Writer, "  ipmi: BMC communication driver registered");
        // Placeholder: parse ACPI SPMI / SMBIOS Type 38 to find
        // KCS or BT IO ports.
        InitResult::Ok
    });
}
