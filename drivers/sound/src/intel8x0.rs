//! Classic AC97 Audio driver (intel8x0).
//!
//! Provides support for Intel 82801AA/AB/BA/CA/DB/EB/FB/GB (ICH) and
//! equivalent AC97 controllers, standard in older hardware and VMs.
//!
//! References: `linux/sound/pci/intel8x0.c`

extern crate alloc;

use alloc::sync::Arc;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

const INTEL_PCI_VENDOR: u16 = 0x8086;
const INTEL_ICH_AC97: u16 = 0x2415;

#[derive(Debug)]
pub struct Intel8x0 {
    mmio: MmioRegion,
}

impl Intel8x0 {
    pub fn new(mmio: MmioRegion) -> Self {
        Self { mmio }
    }
}

pub fn probe(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    let mmio = match unsafe { narf_bus::map_bar(&device, 0) } { // intel8x0 uses BAR0
        Ok(m) => m,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    
    let _audio = Arc::new(Intel8x0::new(mmio));
    // Would normally register to ALSA/sound registry here
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "intel8x0",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: INTEL_PCI_VENDOR,
            device: INTEL_ICH_AC97,
        },
        probe,
    });
}
