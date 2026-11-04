//! Exact endpoint ACPI D-state admission for power::pci_wake.
//!
//! Linux drivers/acpi/device_pm.c::acpi_dev_pm_get_state and
//! drivers/pci/pci-acpi.c::acpi_pci_choose_state. The actual endpoint's
//! optional _SxD/_SxW are distinct from an ancestor's _PRW wake routing.
use super::*;

#[cfg(feature = "wake-test")]
#[path = "pci_wake_state_tests.rs"]
mod tests;

fn optional_state(ns: &impl Namespace, path: &str, name: &str) -> Result<Option<u8>, WakeError> {
    match object(ns, path, name)? {
        None => Ok(None),
        Some(Value::Integer(value)) if value <= 4 => Ok(Some(value as u8)),
        _ => Err(WakeError::Firmware),
    }
}

pub(super) fn admit(
    ns: &impl Namespace,
    endpoint: Option<&str>,
    sleep: SleepState,
    state: WakeState,
) -> Result<(), WakeError> {
    if state == WakeState::D3Cold {
        return Err(WakeError::Unsupported);
    }
    let Some(path) = endpoint else {
        // A missing exact endpoint companion supplies no ACPI D-state
        // constraints. Do not borrow the Root Port's power state; it stays
        // powered and is not operated through this child capability.
        return Ok(());
    };
    // Namespace presence only: evaluating _PS3 to discover it would itself
    // power the function down. This bounded owner has no ACPI PowerResource
    // reference/rail owner and cannot skip a firmware-managed sequence.
    if [
        "_PS0", "_PS1", "_PS2", "_PS3", "_PR0", "_PR1", "_PR2", "_PR3",
    ]
    .iter()
    .any(|name| ns.exists(&format!("{path}.{name}")))
    {
        return Err(WakeError::Unsupported);
    }
    let minimum = match sleep {
        SleepState::S0Idle => None,
        SleepState::S3 => optional_state(ns, path, "_S3D")?,
    };
    let minimum_number = minimum.unwrap_or(0);
    let maximum = optional_state(
        ns,
        path,
        match sleep {
            SleepState::S0Idle => "_S0W",
            SleepState::S3 => "_S3W",
        },
    )?
    // Linux/ACPI: with _SxD but no _SxW, do not choose a deeper state
    // than _SxD; with neither, the PCI owner bounds the default D3cold
    // ceiling to its actual D3hot capability and retained supply profile.
    .unwrap_or_else(|| minimum.unwrap_or(4));
    // Inconsistent firmware is refused; no maximum is invented by raising
    // an explicit _SxW below its _SxD minimum.
    let selected = state as u8;
    if minimum_number > maximum || selected < minimum_number || selected > maximum {
        Err(WakeError::Unsupported)
    } else {
        Ok(())
    }
}
