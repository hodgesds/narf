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

// Basic ENIC registers
const ENIC_DEVCMD: u64 = 0x00;
const ENIC_DEVCMD_STAT: u64 = 0x04;
const ENIC_CMD_RESET: u32 = 0x01;

#[derive(Debug)]
pub struct EnicNic {
    mmio: MmioRegion,
}

impl EnicNic {
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
        // Issue firmware reset command
        self.write_u32(ENIC_DEVCMD, ENIC_CMD_RESET);

        let mut timeout = 100_000;
        while (self.read_u32(ENIC_DEVCMD_STAT) & 0x1) == 0 {
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
        // Enic uses BAR0 for vNIC config
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
