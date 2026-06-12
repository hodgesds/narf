//! Cisco VIC (enic) Ethernet driver.
//!
//! Provides support for the Cisco Virtual Interface Card (VIC) Ethernet
//! controllers, typically found in Cisco UCS environments.
//!
//! References: `linux/drivers/net/ethernet/cisco/enic/`

extern crate alloc;

use alloc::sync::Arc;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

const ENIC_PCI_VENDOR: u16 = 0x1137; // Cisco Systems
const ENIC_PCI_DEVICE_VIC: u16 = 0x0043;

#[derive(Debug)]
pub struct EnicNic {
    mmio: MmioRegion,
}

impl EnicNic {
    pub fn new(mmio: MmioRegion) -> Self {
        Self { mmio }
    }
}

pub fn probe(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    let mmio = match unsafe { narf_bus::map_bar(&device, 0) } { // Enic uses BAR0 for vNIC config
        Ok(m) => m,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    
    let _nic = Arc::new(EnicNic::new(mmio));
    // Would normally register to net registry here
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "enic",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: ENIC_PCI_VENDOR,
            device: ENIC_PCI_DEVICE_VIC,
        },
        probe,
    });
}
