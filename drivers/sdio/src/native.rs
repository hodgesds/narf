// SPDX-License-Identifier: GPL-2.0-or-later
//! Standard PCI SDHCI ownership and SDIO function-driver dispatch.
//! Vendor-specific register interfaces and multi-slot quirks are gated.

use crate::{
    card::{Card, Config, FunctionInfo},
    pio::Registers,
};
use alloc::vec::Vec;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

pub type NativeCard = Card<Mmio>;

/// Private aperture + retained live PCI authority. Every register access
/// checks revocation; the first failure permanently closes this adapter.
pub struct Mmio {
    region: MmioRegion,
    authority: Cap<BusDeviceCap, Write>,
    gone: bool,
}
impl core::fmt::Debug for Mmio {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SdhciMmio")
            .field("gone", &self.gone)
            .finish_non_exhaustive()
    }
}
impl Mmio {
    fn check(&mut self, offset: u32, width: u32) -> bool {
        if self.gone
            || offset % width != 0
            || u64::from(offset) + u64::from(width) > self.region.len
            || self.authority.check_live().is_err()
        {
            self.gone = true;
            false
        } else {
            true
        }
    }
}
impl Registers for Mmio {
    fn read8(&mut self, o: u32) -> u8 {
        if !self.check(o, 1) {
            return u8::MAX;
        }
        // SAFETY: private owned aperture, exact width/alignment and live cap checked above.
        unsafe { self.region.read8(u64::from(o)) }
    }
    fn read16(&mut self, o: u32) -> u16 {
        if !self.check(o, 2) {
            return u16::MAX;
        }
        // SAFETY: as read8.
        unsafe { self.region.read16(u64::from(o)) }
    }
    fn read32(&mut self, o: u32) -> u32 {
        if !self.check(o, 4) {
            return u32::MAX;
        }
        // SAFETY: as read8.
        unsafe { self.region.read32(u64::from(o)) }
    }
    fn write8(&mut self, o: u32, v: u8) {
        if self.check(o, 1) {
            // SAFETY: as read8.
            unsafe { self.region.write8(u64::from(o), v) };
        }
    }
    fn write16(&mut self, o: u32, v: u16) {
        if self.check(o, 2) {
            // SAFETY: as read8.
            unsafe { self.region.write16(u64::from(o), v) };
        }
    }
    fn write32(&mut self, o: u32, v: u32) {
        if self.check(o, 4) {
            // SAFETY: as read8.
            unsafe { self.region.write32(u64::from(o), v) };
        }
    }
}

/// Whole-card ownership goes to a matching function driver (typically F1).
/// It may access related F0/F2 functions without parallel window owners.
#[derive(Clone, Copy, Debug)]
pub struct FunctionDriver {
    pub name: &'static str,
    pub vendor: u16,
    pub device: u16,
    pub function: u8,
    pub probe: fn(NativeCard),
}
static DRIVERS: IrqSafeSpinLock<Vec<FunctionDriver>> = IrqSafeSpinLock::new(Vec::new());
static CLAIMED: IrqSafeSpinLock<Vec<narf_bus::BusAddr>> = IrqSafeSpinLock::new(Vec::new());

#[derive(Clone, Copy, Eq, PartialEq)]
enum Claim {
    New,
    Existing,
    Full,
}
fn claim_once(claims: &mut Vec<narf_bus::BusAddr>, address: narf_bus::BusAddr) -> Claim {
    if claims.contains(&address) {
        return Claim::Existing;
    }
    if claims.len() == 32 {
        return Claim::Full;
    }
    claims.push(address);
    Claim::New
}

/// Disable inherited DMA and decode before enabling the owned register
/// aperture. Readback must establish each transition before the next one.
fn configure_pio(
    activate: bool,
    mut update: impl FnMut(u16, u16) -> Result<u16, ()>,
) -> Result<(), ()> {
    use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
    let mask = BUS_MASTER | MEM_SPACE | INTX_DISABLE;
    if update(BUS_MASTER | MEM_SPACE, INTX_DISABLE)? & mask != INTX_DISABLE {
        return Err(());
    }
    if activate && update(0, MEM_SPACE)? & mask != MEM_SPACE | INTX_DISABLE {
        return Err(());
    }
    Ok(())
}

pub fn register_function_driver(driver: FunctionDriver) -> bool {
    if driver.function == 0 || driver.function > 7 {
        return false;
    }
    let mut drivers = DRIVERS.lock();
    if drivers.len() == 16 || drivers.iter().any(|d| d.name == driver.name) {
        return false;
    }
    drivers.push(driver);
    true
}
fn matching_driver(card: &NativeCard) -> Option<FunctionDriver> {
    DRIVERS.lock().iter().copied().find(|driver| {
        card.function(driver.function)
            .is_some_and(|FunctionInfo { vendor, device, .. }| {
                vendor == driver.vendor && device == driver.device
            })
    })
}

/// Decode the standard PCI SLOT_INFO byte (0x40). This profile supports
/// one slot; a multi-slot function needs independent per-slot ownership.
pub fn slot_bar(slot_info: u8) -> Option<u8> {
    let slots = ((slot_info >> 4) & 7) + 1;
    let bar = slot_info & 7;
    if slots == 1 && bar < 6 {
        Some(bar)
    } else {
        None
    }
}

/// Register both standard PCI interfaces: 0=PIO, 1=DMA-capable standard
/// registers. Both use PIO; interface 2 is vendor-specific and is excluded.
pub fn register_pci_driver() {
    for (name, prog_if) in [("sdhci-pio", 0), ("sdhci-standard", 1)] {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::ClassFull {
                class: 8,
                subclass: 5,
                prog_if,
            },
            probe,
        });
    }
}

/// Bus-dispatch entry. No borrowed MMIO/DMA handle escapes. Initialization
/// and callback execute without registry locks held. An unclaimed card is
/// powered down; no network device is published by this host driver.
pub fn probe(
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    let class = device.id.class;
    if class != 0x080500 && class != 0x080501 {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    authority
        .check_live()
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    let claim = claim_once(&mut CLAIMED.lock(), device.addr);
    if claim == Claim::Existing {
        return Ok(());
    }
    configure_pio(claim == Claim::New, |clear, set| {
        if clear != 0 {
            narf_bus::pci::clear_command(&authority, &device, clear).map_err(|_| ())?;
        }
        narf_bus::pci::set_command(&authority, &device, set).map_err(|_| ())?;
        narf_bus::pci::read_command(&authority, &device).map_err(|_| ())
    })
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // Even an extra unclaimed function has inherited DMA parked. Existing
    // owners returned before any PCI/MMIO access and are never reset here.
    if claim == Claim::Full {
        return Err(narf_bus::ProbeError::Other("SDHCI host limit"));
    }
    let info = narf_bus::pci::read_config32(&authority, &device, 0x40)
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    let bar = slot_bar(info as u8).ok_or(narf_bus::ProbeError::NotForThisDriver)?;
    // SAFETY: exclusive bus dispatcher authority; BME disabled before BAR sizing.
    let region = unsafe { narf_bus::map_bar_control(&device, bar) }
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    if region.len < 0x100 {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    let card = match Card::initialize(
        Mmio {
            region,
            authority,
            gone: false,
        },
        Config::default(),
    ) {
        Ok(card) => card,
        Err(crate::card::Error::NoCard) => return Ok(()),
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: "sdhci-pio".into(),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });
    if let Some(driver) = matching_driver(&card) {
        (driver.probe)(card);
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_sdhci_pio_parking_and_duplicate_ownership() -> TestResult {
        use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
        let mut calls = Vec::new();
        let mut value = BUS_MASTER | MEM_SPACE;
        if configure_pio(true, |clear, set| {
            value = (value & !clear) | set;
            calls.push((clear, set, value));
            Ok(value)
        })
        .is_err()
            || calls
                != alloc::vec![
                    (BUS_MASTER | MEM_SPACE, INTX_DISABLE, INTX_DISABLE),
                    (0, MEM_SPACE, MEM_SPACE | INTX_DISABLE)
                ]
        {
            return TestResult::Fail("PIO decode enabled before DMA/decode parking readback");
        }
        for stale in [BUS_MASTER | INTX_DISABLE, MEM_SPACE | INTX_DISABLE, 0] {
            let mut calls = 0;
            if configure_pio(true, |_, _| {
                calls += 1;
                Ok(stale)
            })
            .is_ok()
                || calls != 1
            {
                return TestResult::Fail("bad parking readback reached enable phase");
            }
        }
        let address = narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(0, 1, 2, 0));
        let mut claims = Vec::new();
        if claim_once(&mut claims, address) != Claim::New
            || claim_once(&mut claims, address) != Claim::Existing
            || claims.len() != 1
        {
            return TestResult::Fail("repeat BDF did not retain original owner");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/sdio/native",
        smoke_sdhci_pio_parking_and_duplicate_ownership
    );

    fn smoke_sdhci_pci_slot_contract() -> TestResult {
        for (value, expected) in [
            (0, Some(0)),
            (3, Some(3)),
            (5, Some(5)),
            (6, None),
            (0x10, None),
            (0x70, None),
        ] {
            if slot_bar(value) != expected {
                return TestResult::Fail("PCI SLOT_INFO decoder drift");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/native", smoke_sdhci_pci_slot_contract);
}
