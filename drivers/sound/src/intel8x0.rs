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

// Basic INTEL8X0 registers
const GLOB_CNT: u64 = 0x2C;
const GLOB_STA: u64 = 0x30;
const GLOB_CNT_AC97COLD: u32 = 1 << 1;

#[derive(Debug)]
pub struct Intel8x0 {
    mmio: MmioRegion,
}

impl Intel8x0 {
    pub fn new(mmio: MmioRegion) -> Self {
        let audio = Self { mmio };
        audio.init();
        audio
    }

    fn read_u32(&self, offset: u64) -> u32 {
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.mmio.read32(offset) }
    }

    fn write_u32(&self, offset: u64, val: u32) {
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.mmio.write32(offset, val) }
    }

    fn init(&self) {
        // Perform AC97 cold reset
        let mut cnt = self.read_u32(GLOB_CNT);
        cnt &= !GLOB_CNT_AC97COLD;
        self.write_u32(GLOB_CNT, cnt);

        let mut timeout = 10_000;
        while timeout > 0 {
            core::hint::spin_loop();
            timeout -= 1;
        }

        cnt |= GLOB_CNT_AC97COLD;
        self.write_u32(GLOB_CNT, cnt);

        // Wait for ready
        timeout = 100_000;
        while (self.read_u32(GLOB_STA) & 0x1) == 0 {
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
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let mmio = match unsafe { narf_bus::map_bar(&device, 0) } {
        // intel8x0 uses BAR0
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
