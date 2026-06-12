//! Alienware WMI platform driver.
//!
//! Exposes Alienware special feature controls such as lighting (AlienFX),
//! amplifier, and deep sleep controls via WMI.
//!
//! ## References
//! - `linux/drivers/platform/x86/dell/alienware-wmi-base.c`
//! - `linux/drivers/platform/x86/dell/alienware-wmi.h`
//!
//! Legacy Control GUID: A90597CE-A997-11DA-B012-B622A1EF5492
//! Legacy Power GUID:   A80593CE-A997-11DA-B012-B622A1EF5492
//! WMAX Control GUID:   A70591CE-A997-11DA-B012-B622A1EF5492

extern crate alloc;

use narf_aml::wmi;
use narf_console::Writer;
use core::fmt::Write;

pub const LEGACY_CONTROL_GUID: &str = "A90597CE-A997-11DA-B012-B622A1EF5492";
pub const LEGACY_POWER_CONTROL_GUID: &str = "A80593CE-A997-11DA-B012-B622A1EF5492";
pub const WMAX_CONTROL_GUID: &str = "A70591CE-A997-11DA-B012-B622A1EF5492";

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "alienware-wmi", || {
        let mut found = false;

        if let Some(egb) = crate::wmi_vendors::guid_str_to_bytes(WMAX_CONTROL_GUID) {
            let guids = wmi::list_guids();
            for g in &guids {
                if g.guid == egb {
                    let _ = writeln!(Writer, "  alienware-wmi: WMAX control GUID found");
                    found = true;
                }
            }
        }

        if let Some(egb) = crate::wmi_vendors::guid_str_to_bytes(LEGACY_CONTROL_GUID) {
            let guids = wmi::list_guids();
            for g in &guids {
                if g.guid == egb {
                    let _ = writeln!(Writer, "  alienware-wmi: Legacy control GUID found");
                    found = true;
                }
            }
        }

        if let Some(egb) = crate::wmi_vendors::guid_str_to_bytes(LEGACY_POWER_CONTROL_GUID) {
            let guids = wmi::list_guids();
            for g in &guids {
                if g.guid == egb {
                    let _ = writeln!(Writer, "  alienware-wmi: Legacy power control GUID found");
                    found = true;
                }
            }
        }

        if found {
            InitResult::Ok
        } else {
            InitResult::NotPresent
        }
    });
}
