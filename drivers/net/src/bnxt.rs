//! Broadcom NetXtreme-C/E (bnxt) Ethernet driver.
//!
//! Provides support for the Broadcom BCM573xx, BCM574xx, and BCM575xx
//! series Ethernet controllers.
//!
//! References: `linux/drivers/net/ethernet/broadcom/bnxt/`

extern crate alloc;

use alloc::sync::Arc;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

const BNXT_PCI_VENDOR: u16 = 0x14E4;
const BNXT_PCI_DEVICE_BCM57414: u16 = 0x16D7;

#[derive(Debug)]
pub struct BnxtNic {
    mmio: MmioRegion,
}

impl BnxtNic {
    pub fn new(mmio: MmioRegion) -> Self {
        Self { mmio }
    }
}

pub fn probe(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    let mmio = match unsafe { narf_bus::map_bar(&device, 0) } {
        Ok(m) => m,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    
    let _nic = Arc::new(BnxtNic::new(mmio));
    // Would normally register to net registry here
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "bnxt",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: BNXT_PCI_VENDOR,
            device: BNXT_PCI_DEVICE_BCM57414,
        },
        probe,
    });
}
