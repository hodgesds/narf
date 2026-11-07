//! LSI MPT Fusion SAS 3.0 (mpt3sas) driver — NOT YET IMPLEMENTED.
//!
//! Interim state (issue #935): no MPT3SAS HBA support exists in this
//! crate. `probe` declines every device with
//! `ProbeError::NotForThisDriver` without touching the hardware, so
//! the bus dispatcher (bus spec §9.3) offers the device to the next
//! claimant instead of counting it bound. In particular probe never
//! maps a BAR, never issues the doorbell reset, and never runs the
//! diagnostic-unlock write sequence — the previous probe did all of
//! that, then dropped the HBA while reporting it bound.
//!
//! The full #935 endpoint (real implementations, or clearly-labelled
//! absence, for MPT3SAS, MegaRAID and SmartPQI) is a separate lane;
//! this crate stays a labelled absence until then.
//!
//! References: `linux/drivers/scsi/mpt3sas/`

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};

/// LSI Logic PCI vendor ID.
pub const MPT3SAS_PCI_VENDOR: u16 = 0x1000; // LSI Logic
/// SAS3008 device ID (Fusion-MPT SAS 3.0).
pub const MPT3SAS_PCI_DEVICE_SAS3008: u16 = 0x0097; // SAS3008

/// Decline the device without touching it.
///
/// NOT IMPLEMENTED (issue #935): no IOC facts/queues, no SAS
/// enumeration, no block device. Declining with `NotForThisDriver`
/// returns the device to the candidate list (bus spec §9.3) so
/// another claimant can bind it; any other error would end the
/// attempts for this device. Deliberately no BAR mapping and no MMIO
/// here: the previous probe reset the HBA and then dropped it while
/// reporting it bound.
pub fn probe(
    _device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    Err(narf_bus::ProbeError::NotForThisDriver)
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "mpt3sas",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: MPT3SAS_PCI_VENDOR,
            device: MPT3SAS_PCI_DEVICE_SAS3008,
        },
        probe,
    });
}
