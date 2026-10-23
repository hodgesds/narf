// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9285 PCIe reset, EEPROM identity and inactive INI/PLL/RF preparation.
//! Linux ath9k is the reference. Modal/RF board values are applied; power/calibration,
//! PHY activation and packet DMA remain open.

use core::fmt::Write as _;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

mod identity;
mod initvals;
mod phy;
pub use identity::{BringUpError, Identity, EEPROM_4K_BYTES};
pub use phy::Prepared as BasebandPrepared;

const ATHEROS_PCI_VENDOR: u16 = 0x168c;
const ATHEROS_AR9285_DEVICE: u16 = 0x002b;

/// Retained hardware identity and calibration bytes. No netdev or packet
/// DMA is enabled until the MAC/PHY and soft-MAC runtime are implemented.
#[derive(Debug)]
pub struct Ath9k {
    _mmio: MmioRegion,
    _device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
    pub identity: Identity,
    pub baseband: BasebandPrepared,
    calibration: [u8; EEPROM_4K_BYTES],
}

impl Ath9k {
    pub fn calibration(&self) -> &[u8; EEPROM_4K_BYTES] {
        &self.calibration
    }
}

static CONTROLLER: IrqSafeSpinLock<Option<Ath9k>> = IrqSafeSpinLock::new(None);

pub fn with_controller<R>(callback: impl FnOnce(&Ath9k) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(callback)
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if device.id.vendor != ATHEROS_PCI_VENDOR || device.id.device != ATHEROS_AR9285_DEVICE {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    let owner = CONTROLLER
        .lock()
        .as_ref()
        .map(|controller| controller._device.addr);
    let occupied = owner.is_some();
    crate::qualcomm_pci::park(&device, &cap, false, owner)?;
    if occupied {
        return Err(narf_bus::ProbeError::Other(
            "ath9k singleton already owns another radio",
        ));
    }
    let mmio = crate::qualcomm_pci::map_bar_control(&device, &cap, 0)?;
    if mmio.len < phy::REQUIRED_BAR {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    let (identity, calibration) = identity::read(mmio, cap).map_err(|error| {
        let _ = writeln!(
            narf_console::Writer,
            "  ath9k: AR9285 identification failed: {:?}",
            error
        );
        narf_bus::ProbeError::BadDevice
    })?;
    let baseband = phy::program(mmio, cap, &calibration).map_err(|error| {
        let _ = writeln!(
            narf_console::Writer,
            "  ath9k: AR9285 baseband preparation failed: {:?}",
            error
        );
        narf_bus::ProbeError::BadDevice
    })?;
    let _ = writeln!(
        narf_console::Writer,
        "  ath9k: AR9285 rev {} MAC {:02x?}, EEPROM {:#x}; INI/PLL/RF registers prepared, calibration and packet runtime pending",
        identity.revision,
        identity.mac,
        identity.eeprom_version
    );
    let vendor = device.id.vendor;
    let device_id = device.id.device;
    *CONTROLLER.lock() = Some(Ath9k {
        _mmio: mmio,
        _device: device,
        _cap: cap,
        identity,
        baseband,
        calibration,
    });
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("ath9k-ar9285"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(vendor),
        pci_did: Some(device_id),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    Ok(())
}

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
