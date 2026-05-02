//! virtio-scsi over modern virtio-PCI transport (VirtIO 1.2 §5.6).
//!
//! Modern transitional virtio-scsi PCI device id: `0x1040 + 8 = 0x1048`.
//!
//! Stage 1: PCI match + virtio common-cfg probe entry. Bring-up
//! beyond `register_pci_driver` lands in later stages.

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

/// Modern transitional virtio-scsi (VirtIO 1.2 §4.1.2).
pub const VIRTIO_SCSI_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_SCSI_PCI_DEVICE: u16 = 0x1048;

mod tests;

/// Probed virtio-scsi-pci controller. Stage-1 placeholder: only the
/// `ready` flag exists until queue setup lands in stage 3.
#[derive(Debug)]
pub struct VirtioScsiPci {
    pub ready: bool,
}

static CONTROLLER: IrqSafeSpinLock<Option<VirtioScsiPci>> =
    IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`.
/// Stage-1: enable MEM_SPACE + BUS_MASTER and record presence so the
/// match table claims the device. Virtqueue bring-up is stage 3.
pub fn probe(
    device: BusDevice,
    cap:    Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() { return Ok(()); }
    narf_bus::pci::set_command(
        &cap, &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    ).map_err(|_| narf_bus::ProbeError::BadDevice)?;
    *CONTROLLER.lock() = Some(VirtioScsiPci { ready: false });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-scsi-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_SCSI_PCI_VENDOR,
            device: VIRTIO_SCSI_PCI_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

pub fn with_controller<R>(f: impl FnOnce(&VirtioScsiPci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
