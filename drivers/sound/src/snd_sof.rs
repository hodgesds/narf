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

// Basic SOF registers
const SOF_IPC_MAILBOX: u64 = 0x1000;
const SOF_IPC_HOST_TO_DSP: u64 = 0x1004;
const SOF_IPC_DSP_TO_HOST: u64 = 0x1008;

#[derive(Debug)]
pub struct SofDsp {
    mmio: MmioRegion,
}

impl SofDsp {
    pub fn new(mmio: MmioRegion) -> Self {
        let dsp = Self { mmio };
        dsp.init();
        dsp
    }

    fn read_u32(&self, offset: u64) -> u32 {
        unsafe { self.mmio.read32(offset) }
    }

    fn write_u32(&self, offset: u64, val: u32) {
        unsafe { self.mmio.write32(offset, val) }
    }

    fn init(&self) {
        // Clear DSP to HOST doorbell
        self.write_u32(SOF_IPC_DSP_TO_HOST, 0);

        // Ring HOST to DSP doorbell
        self.write_u32(SOF_IPC_HOST_TO_DSP, 1);

        // Wait for DSP acknowledgment
        let mut timeout = 100_000;
        while (self.read_u32(SOF_IPC_HOST_TO_DSP) & 1) != 0 {
            timeout -= 1;
            if timeout == 0 {
                break;
            }
            core::hint::spin_loop();
        }
    }
}

pub fn probe(
    device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    let mmio = match unsafe { narf_bus::map_bar(&device, 4) } {
        // SOF usually uses BAR4
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
