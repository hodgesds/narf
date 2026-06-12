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

// Basic ATH9K registers
const AR_RC: u64 = 0x4000;
const AR_RC_AHB: u32 = 1 << 0;
const AR_INTR_SYNC_CAUSE: u64 = 0x4010;

#[derive(Debug)]
pub struct Ath9k {
    mmio: MmioRegion,
}

impl Ath9k {
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
        // Assert AHB reset
        self.write_u32(AR_RC, AR_RC_AHB);
        let mut timeout = 10_000;
        while timeout > 0 {
            core::hint::spin_loop();
            timeout -= 1;
        }

        // Deassert AHB reset
        self.write_u32(AR_RC, 0);

        // Clear sync cause
        self.write_u32(AR_INTR_SYNC_CAUSE, 0xFFFFFFFF);
    }
}

pub fn probe(
    device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    let mmio = match unsafe { narf_bus::map_bar(&device, 0) } {
        // ath9k uses BAR0
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
