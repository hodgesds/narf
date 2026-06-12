//! LSI MPT Fusion SAS 3.0 (mpt3sas) driver.
//!
//! Provides support for LSI/Avago/Broadcom SAS/SATA HBAs and RAID
//! controllers. Common in enterprise storage servers.
//!
//! References: `linux/drivers/scsi/mpt3sas/`

extern crate alloc;

use alloc::sync::Arc;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

const MPT3SAS_PCI_VENDOR: u16 = 0x1000; // LSI Logic
const MPT3SAS_PCI_DEVICE_SAS3008: u16 = 0x0097; // SAS3008

#[derive(Debug)]
pub struct Mpt3Sas {
    mmio: MmioRegion,
}

impl Mpt3Sas {
    pub fn new(mmio: MmioRegion) -> Self {
        Self { mmio }
    }
}

pub fn probe(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    let mmio = match unsafe { narf_bus::map_bar(&device, 1) } { // MPT3SAS usually uses BAR1 for MMIO
        Ok(m) => m,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    
    let _hba = Arc::new(Mpt3Sas::new(mmio));
    // Register to storage subsystem
    Ok(())
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
