//! ACPI Thermal Zone driver — clean-room.
//!
//! Spec: ACPI 6.5 §11 (Thermal Management).
//!   <https://uefi.org/specs/ACPI/>
//! Discovers ThermalZone objects in AML, registers them with `narf-power`,
//! and drives the periodic temperature poll.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use core::fmt::Write;

use narf_aml::eval::evaluate_method;
use narf_aml::{for_each_node_of_kind, NodeKind};
use narf_power::bootstrap_thermal_authority;
use narf_power::thermal::{record_temp, register_zone};

/// Converts ACPI deci-Kelvin to millidegrees Celsius.
fn decik_to_millic(dk: u64) -> i32 {
    // T_c = T_k - 273.15
    // milli_c = (deci_k * 100) - 273150
    (dk as i32 * 100) - 273150
}

pub fn init() {
    let cap = bootstrap_thermal_authority();

    for_each_node_of_kind(NodeKind::ThermalZone, |node| {
        let path = &node.path;

        // 1. Read trip points.
        // _CRT: Critical Temperature (mandatory for a zone to be useful).
        let crit_dk = evaluate_method(&format!("{}.{}", path, "_CRT"), &[])
            .map(|v| v.as_integer())
            .unwrap_or(3732); // 100C fallback

        // _PSV: Passive Temperature (throttling start).
        let psv_dk = evaluate_method(&format!("{}.{}", path, "_PSV"), &[])
            .map(|v| v.as_integer())
            .unwrap_or(crit_dk - 100); // 10C below critical fallback

        let warn_milli = decik_to_millic(psv_dk);
        let crit_milli = decik_to_millic(crit_dk);

        // 2. Register with power subsystem.
        if let Ok(id) = register_zone(&cap, path, warn_milli, crit_milli) {
            let _ = writeln!(
                narf_console::Writer,
                "  acpi-thermal: registered {} (warn={}C, crit={}C)",
                path,
                warn_milli / 1000,
                crit_milli / 1000
            );

            // 3. Start polling task for this zone.
            let path_clone = String::from(path);
            // Stackful: ACPI _TMP poll loop (AML evaluation can
            // be expensive on real silicon; preemption-capped).
            narf_scheduler::spawn_stackful(async move {
                loop {
                    // _TMP: Current Temperature.
                    if let Ok(v) = evaluate_method(&format!("{}.{}", path_clone, "_TMP"), &[]) {
                        let milli_c = decik_to_millic(v.as_integer());
                        let _ = record_temp(id, milli_c);
                    }

                    // Poll every 5 seconds (standard ACPI interval).
                    narf_time::sleep_cycles(5_000_000_000).await;
                }
            });
        }
    });
}
