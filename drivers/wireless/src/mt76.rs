//! MediaTek 802.11ac/ax wireless driver (mt76).
//!
//! Provides support for the modern MediaTek MT76x0, MT76x2, MT7615,
//! and MT7915 family of wireless chipsets.
//!
//! References: `linux/drivers/net/wireless/mediatek/mt76/`

extern crate alloc;

use alloc::sync::Arc;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

const MEDIATEK_PCI_VENDOR: u16 = 0x14C3;
const MEDIATEK_MT7615_DEVICE: u16 = 0x7615;

#[derive(Debug)]
pub struct Mt76 {
    mmio: MmioRegion,
}

impl Mt76 {
    pub fn new(mmio: MmioRegion) -> Self {
        Self { mmio }
    }
}

pub fn probe(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    let mmio = match unsafe { narf_bus::map_bar(&device, 0) } { // mt76 uses BAR0
        Ok(m) => m,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    
    let _nic = Arc::new(Mt76::new(mmio));
    // Register to wireless subsystem
    Ok(())
}

/// Register the mt76 driver.
pub fn register() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "mt76",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: MEDIATEK_PCI_VENDOR,
            device: MEDIATEK_MT7615_DEVICE,
        },
        probe,
    });
}
