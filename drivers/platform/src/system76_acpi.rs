//! System76 ACPI Driver.
//!
//! Exposes System76-specific ACPI controls, like battery charge thresholds.
//!
//! ## References
//! - `linux/drivers/platform/x86/system76_acpi.c`

extern crate alloc;

use narf_aml::find_all_devices_by_hid;

pub const SYSTEM76_ACPI_HID: &str = "17761776";

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "system76-acpi", || {
        let devs = find_all_devices_by_hid(SYSTEM76_ACPI_HID);
        if devs.is_empty() {
            return InitResult::NotPresent;
        }

        use narf_console::Writer;
        use core::fmt::Write;
        
        let path = &devs[0].path;
        let _ = writeln!(Writer, "  system76-acpi: Bound to {}", path);

        // Store the device path globally if needed for future use.
        // GLED expects no arguments (or index) - actually GLED might expect no arguments, let's just log.

        InitResult::Ok
    });
}

/// Get the battery charge threshold (0 for start, 1 for end).
pub fn get_battery_threshold(which: u64) -> Result<u64, narf_aml::AmlError> {
    use narf_aml::eval::evaluate_method;
    use narf_aml::Value;
    use alloc::format;
    
    // System76 battery thresholds are typically routed to the EC's GBCT method.
    // narf_aml::ec needs to be used to find the EC path, but for a stub, we'll try evaluating
    // on a known EC path or just search for the EC device.
    let ec_devs = narf_aml::find_all_devices_by_hid("PNP0C09");
    if ec_devs.is_empty() {
        return Err(narf_aml::AmlError::MethodNotFound);
    }
    
    let gbct_path = format!("{}.GBCT", ec_devs[0].path);
    match evaluate_method(&gbct_path, &[Value::Integer(which)]) {
        Ok(val) => Ok(val.as_integer()),
        Err(e) => Err(e),
    }
}

/// Set the battery charge threshold (0 for start, 1 for end) to a percentage (0-100).
pub fn set_battery_threshold(which: u64, percent: u64) -> Result<(), narf_aml::AmlError> {
    use narf_aml::eval::evaluate_method;
    use narf_aml::Value;
    use alloc::format;
    
    let ec_devs = narf_aml::find_all_devices_by_hid("PNP0C09");
    if ec_devs.is_empty() {
        return Err(narf_aml::AmlError::MethodNotFound);
    }
    
    let sbct_path = format!("{}.SBCT", ec_devs[0].path);
    evaluate_method(&sbct_path, &[Value::Integer(which), Value::Integer(percent)])?;
    Ok(())
}

/// Set the keyboard LED color (24-bit RGB format).
pub fn set_keyboard_color(color_rgb: u32) -> Result<(), narf_aml::AmlError> {
    use narf_aml::eval::evaluate_method;
    use narf_aml::Value;
    use alloc::format;
    
    let devs = narf_aml::find_all_devices_by_hid(SYSTEM76_ACPI_HID);
    if devs.is_empty() {
        return Err(narf_aml::AmlError::MethodNotFound);
    }
    
    let sled_path = format!("{}.SLED", devs[0].path);
    evaluate_method(&sled_path, &[Value::Integer(color_rgb as u64)])?;
    Ok(())
}
