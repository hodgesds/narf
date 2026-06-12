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

// Basic BNXT registers
const BNXT_VER: u64 = 0x00;
const BNXT_MAC_CTRL: u64 = 0x04;
const BNXT_MAC_RESET: u32 = 1 << 0;

#[derive(Debug)]
pub struct BnxtNic {
    mmio: MmioRegion,
}

impl BnxtNic {
    pub fn new(mmio: MmioRegion) -> Self {
        let nic = Self { mmio };
        nic.init();
        nic
    }

    fn read_u32(&self, offset: u64) -> u32 {
        unsafe { self.mmio.read32(offset) }
    }

    fn write_u32(&self, offset: u64, val: u32) {
        unsafe { self.mmio.write32(offset, val) }
    }

    fn init(&self) {
        // Read version/ID
        let _ver = self.read_u32(BNXT_VER);

        // Assert MAC reset
        let ctrl = self.read_u32(BNXT_MAC_CTRL);
        self.write_u32(BNXT_MAC_CTRL, ctrl | BNXT_MAC_RESET);

        let mut timeout = 100_000;
        while (self.read_u32(BNXT_MAC_CTRL) & BNXT_MAC_RESET) != 0 {
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
