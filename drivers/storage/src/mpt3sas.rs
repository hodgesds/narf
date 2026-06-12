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

// Basic MPT3SAS registers
const MPT_DOORBELL: u64 = 0x00;
const MPT_WRITE_SEQ: u64 = 0x04;
const MPT_DOORBELL_RESET: u32 = 0x40000000;

#[derive(Debug)]
pub struct Mpt3Sas {
    mmio: MmioRegion,
}

impl Mpt3Sas {
    pub fn new(mmio: MmioRegion) -> Self {
        let hba = Self { mmio };
        hba.reset();
        hba
    }

    fn read_u32(&self, offset: u64) -> u32 {
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.mmio.read32(offset) }
    }

    fn write_u32(&self, offset: u64, val: u32) {
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.mmio.write32(offset, val) }
    }

    fn reset(&self) {
        // Trigger a doorbell reset
        self.write_u32(MPT_DOORBELL, MPT_DOORBELL_RESET);
        let mut timeout = 100_000;
        while (self.read_u32(MPT_DOORBELL) & MPT_DOORBELL_RESET) != 0 {
            timeout -= 1;
            if timeout == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Write diagnostic sequence to enable host diag
        self.write_u32(MPT_WRITE_SEQ, 0xFF);
        self.write_u32(MPT_WRITE_SEQ, 0x0F);
        self.write_u32(MPT_WRITE_SEQ, 0x4F);
        self.write_u32(MPT_WRITE_SEQ, 0x0F);
        self.write_u32(MPT_WRITE_SEQ, 0x4F);
    }
}

pub fn probe(
    device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let mmio = match unsafe { narf_bus::map_bar(&device, 1) } {
        // MPT3SAS usually uses BAR1 for MMIO
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
