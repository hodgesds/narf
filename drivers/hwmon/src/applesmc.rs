//! Apple SMC (System Management Controller) driver.
//!
//! Provides access to Apple SMC's temperature sensors, fan control, and
//! keyboard backlighting via I/O ports 0x300 and 0x304.
//!
//! Reference: `linux/drivers/hwmon/applesmc.c`

extern crate alloc;

use core::fmt::Write;
use narf_aml::find_all_devices_by_hid;
use narf_console::Writer;

const APPLESMC_ACPI_HID: &str = "APP0001";

pub fn register_smc_driver() {
    let devs = find_all_devices_by_hid(APPLESMC_ACPI_HID);
    if devs.is_empty() {
        return;
    }

    let _ = writeln!(Writer, "  applesmc: Found Apple SMC (APP0001)");

    // Note: Full read/write handshaking via 0x300/0x304 is deferred.
}
