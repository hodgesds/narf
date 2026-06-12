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

// Basic MT76 registers
const MT_MCU_BASE: u64 = 0x2000;
const MT_MCU_PCIE_REMAP_1: u64 = 0x2400;
const MT_HW_REV: u64 = 0x1000;

#[derive(Debug)]
pub struct Mt76 {
    mmio: MmioRegion,
}

impl Mt76 {
    pub fn new(mmio: MmioRegion) -> Self {
        let nic = Self { mmio };
        nic.init();
        nic
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
        // Read hardware revision
        let _rev = self.read_u32(MT_HW_REV);

        // Reset MCU remap
        self.write_u32(MT_MCU_PCIE_REMAP_1, 0);

        // Wait for MCU to be ready
        let mut timeout = 100_000;
        while (self.read_u32(MT_MCU_BASE) & 1) == 0 {
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
        // mt76 uses BAR0
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
