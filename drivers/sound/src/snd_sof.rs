//! Sound Open Firmware (SOF) driver.
//!
//! Provides support for modern Intel/AMD audio DSPs and ADSP subsystems,
//! bridging firmware communication over IPC.
//!
//! References: `linux/sound/soc/sof/`

extern crate alloc;

use alloc::sync::Arc;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

const INTEL_PCI_VENDOR: u16 = 0x8086;
const INTEL_CML_AUDIO_DSP: u16 = 0x02c8;

#[derive(Debug)]
pub struct SofDsp {
    mmio: MmioRegion,
}

impl SofDsp {
    pub fn new(mmio: MmioRegion) -> Self {
        Self { mmio }
    }
}

pub fn probe(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    let mmio = match unsafe { narf_bus::map_bar(&device, 4) } { // SOF usually uses BAR4
        Ok(m) => m,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    
    let _dsp = Arc::new(SofDsp::new(mmio));
    // Would normally register to ALSA/sound registry here
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "snd_sof",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: INTEL_PCI_VENDOR,
            device: INTEL_CML_AUDIO_DSP,
        },
        probe,
    });
}
