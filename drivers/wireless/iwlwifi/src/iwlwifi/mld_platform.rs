//! Native optional Intel BIOS metadata. Firmware method execution belongs
//! to the platform's delegated Power owner, not to the radio PCI grant.
use super::mld_power::{InputRead, InputStatus, Inputs};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_power::pci_firmware::{MetadataError, PciMetadata, PciMetadataKey};

fn error(error: MetadataError) -> InputStatus {
    match error {
        MetadataError::Authority => InputStatus::Authority,
        MetadataError::Unavailable => InputStatus::Unavailable,
        MetadataError::Ambiguous => InputStatus::Ambiguous,
        MetadataError::Firmware => InputStatus::Firmware,
    }
}
fn approved() -> bool {
    use narf_firmware_smbios::{SmbiosBaseboard, SmbiosSystem};
    let mut systems = [SmbiosSystem::ZERO; 2];
    let mut boards = [SmbiosBaseboard::ZERO; 2];
    if narf_firmware_smbios::copy_system(&mut systems) != 1 {
        return false;
    }
    let board = if narf_firmware_smbios::copy_baseboard(&mut boards) == 1 {
        &boards[0].manufacturer[..]
    } else {
        &[]
    };
    super::mld_power::ppag_approved(&systems[0].manufacturer, board)
}
pub(super) fn read(device: BusDevice, pci: &Cap<BusDeviceCap, Write>) -> Inputs {
    let ppag_approved = approved();
    let metadata = match PciMetadata::discover(pci, device) {
        Ok(metadata) => metadata,
        Err(reason) => {
            let mut input = Inputs::unavailable(error(reason));
            input.ppag_approved = ppag_approved;
            return input;
        }
    };
    let get = |key| -> InputRead { metadata.object(key).map_err(error) };
    // Linux's BIOS helpers accept unavailable/invalid optional records. The
    // returned status preserves that fact; it never invents an absent table
    // or a measured SAR/gain default. Only decoded supplied values are used.
    let ppag = get(PciMetadataKey::Ppag);
    let wrds = get(PciMetadataKey::Wrds);
    let has_wrds = wrds
        .as_ref()
        .ok()
        .and_then(Option::as_ref)
        .is_some_and(|value| super::mld_power::Sar::acpi(value).is_ok());
    let ewrd = if has_wrds {
        get(PciMetadataKey::Ewrd)
    } else {
        Err(InputStatus::NotRead)
    };
    let wgds = get(PciMetadataKey::Wgds);
    Inputs::decoded(wrds, ewrd, wgds, ppag, ppag_approved)
}
