//! Atheros 802.11n wireless driver (ath9k).
//!
//! Provides support for the classic Atheros AR5008, AR9001, and AR9002
//! family of 802.11n wireless chipsets.
//!
//! References: `linux/drivers/net/wireless/ath/ath9k/`

extern crate alloc;

use alloc::sync::Arc;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

const ATHEROS_PCI_VENDOR: u16 = 0x168C;
const ATHEROS_AR9285_DEVICE: u16 = 0x002B;

#[derive(Debug)]
pub struct Ath9k {
    mmio: MmioRegion,
}

impl Ath9k {
    pub fn new(mmio: MmioRegion) -> Self {
        Self { mmio }
    }
}

pub fn probe(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    let mmio = match unsafe { narf_bus::map_bar(&device, 0) } { // ath9k uses BAR0
        Ok(m) => m,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    
    let _nic = Arc::new(Ath9k::new(mmio));
    // Register to wireless subsystem
    Ok(())
}

/// Register the ath9k driver.
pub fn register() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "ath9k",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: ATHEROS_PCI_VENDOR,
            device: ATHEROS_AR9285_DEVICE,
        },
        probe,
    });
}
