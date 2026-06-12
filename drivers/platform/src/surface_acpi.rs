//! Microsoft Surface ACPI driver.
//!
//! Provides hotkeys and ACPI events for Microsoft Surface devices.
//!
//! Reference: `linux/drivers/platform/surface/surfacepro3_button.c`
//! ACPI HID: MSHW0040 (Surface Pro 3/4 buttons)

extern crate alloc;

use narf_aml::find_all_devices_by_hid;

pub const SURFACE_BUTTON_HID: &str = "MSHW0040";

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "surface-acpi", || {
        let devs = find_all_devices_by_hid(SURFACE_BUTTON_HID);
        if devs.is_empty() {
            return InitResult::NotPresent;
        }

        use core::fmt::Write;
        use narf_console::Writer;
        let _ = writeln!(Writer, "  surface-acpi: Found Surface ACPI Button device");

        InitResult::Ok
    });
}
