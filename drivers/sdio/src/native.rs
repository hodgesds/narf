// SPDX-License-Identifier: GPL-2.0-or-later
//! Standard PCI SDHCI ownership and SDIO function-driver dispatch.
//! Vendor-specific register interfaces and multi-slot quirks are gated.

use crate::{
    card::{Card, Config, FunctionInfo},
    pio::Registers,
};
use alloc::vec::Vec;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_lib::sync::IrqSafeSpinLock;

pub type NativeCard = Card<Mmio>;

/// Private aperture + retained live PCI authority. Every register access
/// checks revocation; the first failure permanently closes this adapter.
pub struct Mmio {
    region: MmioRegion,
    authority: Cap<BusDeviceCap, Write>,
    device: BusDevice,
    gone: bool,
    identity: crate::pio::HostIdentity,
}
impl core::fmt::Debug for Mmio {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SdhciMmio")
            .field("gone", &self.gone)
            .finish_non_exhaustive()
    }
}
fn invoke<T>(cap: &Cap<BusDeviceCap, Write>, operation: impl FnOnce() -> T) -> Result<T, CapError> {
    struct Operation<F>(F);
    impl<T, F: FnOnce() -> T> CapOp<BusDeviceCap, Write> for Operation<F> {
        type Output = T;
        fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
            Ok(self.0())
        }
    }
    cap.invoke(Operation(operation))
}
impl Mmio {
    fn access<T>(
        &mut self,
        offset: u32,
        width: u32,
        operation: impl FnOnce(&MmioRegion) -> T,
    ) -> Option<T> {
        if self.gone
            || offset % width != 0
            || u64::from(offset)
                .checked_add(u64::from(width))
                .is_none_or(|end| end > self.region.len)
        {
            self.gone = true;
            return None;
        }
        match invoke(&self.authority, || {
            use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
            let command = narf_bus::pci::read_command(&self.authority, &self.device).ok()?;
            if command == u16::MAX
                || command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != MEM_SPACE | INTX_DISABLE
            {
                return None;
            }
            Some(operation(&self.region))
        }) {
            Ok(Some(value)) => Some(value),
            _ => {
                self.gone = true;
                None
            }
        }
    }
}
impl Registers for Mmio {
    fn host_identity(&self) -> Option<crate::pio::HostIdentity> {
        Some(self.identity)
    }
    fn read8(&mut self, offset: u32) -> u8 {
        self.access(offset, 1, |region| {
            // SAFETY: complete exact-width extent and current PCI invocation.
            unsafe { region.read8(u64::from(offset)) }
        })
        .unwrap_or(u8::MAX)
    }
    fn read16(&mut self, offset: u32) -> u16 {
        self.access(offset, 2, |region| {
            // SAFETY: complete aligned extent and current PCI invocation.
            unsafe { region.read16(u64::from(offset)) }
        })
        .unwrap_or(u16::MAX)
    }
    fn read32(&mut self, offset: u32) -> u32 {
        self.access(offset, 4, |region| {
            // SAFETY: complete aligned extent and current PCI invocation.
            unsafe { region.read32(u64::from(offset)) }
        })
        .unwrap_or(u32::MAX)
    }
    fn write8(&mut self, offset: u32, value: u8) {
        let _ = self.access(offset, 1, |region| {
            // SAFETY: complete exact-width extent and current PCI invocation.
            unsafe { region.write8(u64::from(offset), value) }
        });
    }
    fn write16(&mut self, offset: u32, value: u16) {
        let _ = self.access(offset, 2, |region| {
            // SAFETY: complete aligned extent and current PCI invocation.
            unsafe { region.write16(u64::from(offset), value) }
        });
    }
    fn write32(&mut self, offset: u32, value: u32) {
        let _ = self.access(offset, 4, |region| {
            // SAFETY: complete aligned extent and current PCI invocation.
            unsafe { region.write32(u64::from(offset), value) }
        });
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

/// Drop a claim recorded by `claim_once` after a failed initialization,
/// so the host can be probed again instead of staying claimed forever.
/// Returns `true` when the address was claimed (and is now released).
fn release_claim(claims: &mut Vec<narf_bus::BusAddr>, address: narf_bus::BusAddr) -> bool {
    match claims.iter().position(|claimed| *claimed == address) {
        Some(index) => {
            claims.remove(index);
            true
        }
        None => false,
    }
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
    if activate {
        activate_pio(update)?;
    }
    Ok(())
}

/// Decode may be enabled only after sizing/mapping the owned control BAR.
fn activate_pio(mut update: impl FnMut(u16, u16) -> Result<u16, ()>) -> Result<(), ()> {
    use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
    if update(0, MEM_SPACE)? & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != MEM_SPACE | INTX_DISABLE {
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

/// Map a card-initialisation outcome onto the bus arbitration
/// contract (bus spec §9.3). The PCI device is always an SD *host
/// controller* (class 08:05); whether it belongs to this stack
/// depends on the card behind it, which only initialisation can
/// reveal — so the non-SDIO outcomes are declines, not failures:
///
/// - `NoCard`: the slot is empty. This stack has nothing to
///   drive; declining (instead of the vacuous `Ok(())` claim this
///   replaces) leaves the host to the storage SDHCI driver, which
///   owns empty and memory-card hosts.
/// - `Unsupported`: initialisation proved the inserted card is
///   not an SDIO card — CMD5 answered with zero functions or the
///   memory-present bit set, i.e. a memory card (see
///   `card::Card::start`). Decline so `probe_all` falls through
///   to the storage driver.
///
/// Anything else is a genuine initialisation failure on a host
/// this stack was prepared to own: `BadDevice`, which ends the
/// match attempts for the device.
fn init_error_to_probe_error(e: crate::card::Error) -> narf_bus::ProbeError {
    match e {
        crate::card::Error::NoCard | crate::card::Error::Unsupported => {
            narf_bus::ProbeError::NotForThisDriver
        }
        _ => narf_bus::ProbeError::BadDevice,
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
    let address = device.addr;
    let claim = claim_once(&mut CLAIMED.lock(), address);
    if claim == Claim::Existing {
        return Ok(());
    }
    let result = probe_claimed(device, authority, claim);
    if result.is_err() && claim == Claim::New {
        // Initialization failed: drop the claim so the failure is not
        // reboot-only — a later probe may retry this host.
        release_claim(&mut CLAIMED.lock(), address);
    }
    result
}

/// Probe body for a host this call claimed (`Claim::New`) or that was
/// turned away at the claim limit (`Claim::Full`, parked only). Split
/// from `probe` so every error return funnels through the caller's
/// claim-release path.
fn probe_claimed(
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
    claim: Claim,
) -> Result<(), narf_bus::ProbeError> {
    invoke(&authority, || {
        configure_pio(false, |clear, set| {
            if clear != 0 {
                narf_bus::pci::clear_command(&authority, &device, clear).map_err(|_| ())?;
            }
            narf_bus::pci::set_command(&authority, &device, set).map_err(|_| ())?;
            narf_bus::pci::read_command(&authority, &device).map_err(|_| ())
        })
    })
    .map_err(|_| narf_bus::ProbeError::BadDevice)?
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // Even an extra unclaimed function has inherited DMA parked. Existing
    // owners returned before any PCI/MMIO access and are never reset here.
    if claim == Claim::Full {
        return Err(narf_bus::ProbeError::Other("SDHCI host limit"));
    }
    let info = invoke(&authority, || {
        narf_bus::pci::read_config32(&authority, &device, 0x40)
    })
    .map_err(|_| narf_bus::ProbeError::BadDevice)?
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    let bar = slot_bar(info as u8).ok_or(narf_bus::ProbeError::NotForThisDriver)?;
    // SAFETY: exclusive bus dispatcher authority; BME disabled before BAR sizing.
    let region = invoke(&authority, || {
        // SAFETY: exclusive current PCI invocation; inherited DMA remains off.
        unsafe { narf_bus::map_bar_control(&device, bar) }
    })
    .map_err(|_| narf_bus::ProbeError::BadDevice)?
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    if region.len < 0x100 {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    invoke(&authority, || {
        activate_pio(|_, set| {
            narf_bus::pci::set_command(&authority, &device, set).map_err(|_| ())?;
            narf_bus::pci::read_command(&authority, &device).map_err(|_| ())
        })
    })
    .map_err(|_| narf_bus::ProbeError::BadDevice)?
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    let card = match Card::initialize(
        Mmio {
            region,
            authority,
            device,
            gone: false,
            identity: crate::pio::HostIdentity {
                address: device.addr,
                id: device.id,
            },
        },
        Config::default(),
    ) {
        Ok(card) => card,
        Err(e) => return Err(init_error_to_probe_error(e)),
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
    fn smoke_sdhci_native_revocation_blocks_configuration_and_mmio() -> TestResult {
        let address = narf_bus::PcieAddr::new(0xfffe, 0xfa, 0x1c, 2);
        let identity = crate::pio::HostIdentity {
            address: narf_bus::BusAddr::Pcie(address),
            id: narf_bus::DeviceId {
                vendor: 0x1abc,
                device: 0x1234,
                class: 0x080500,
                subsystem_vendor: 0x1234,
                subsystem_id: 0x5678,
            },
        };
        let device = BusDevice {
            addr: identity.address,
            id: identity.id,
            kind: narf_bus::BusKind::Pcie {
                addr: address,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        };
        let authority = Cap::<BusDeviceCap, Write>::bootstrap();
        authority.revoke();
        let region = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 256,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let mut io = Mmio {
            region,
            authority,
            device,
            gone: false,
            identity,
        };
        let mut entered = false;
        if io
            .access(0x10, 4, |_| {
                entered = true;
                0
            })
            .is_some()
            || entered
            || !io.gone
            || io.read32(0x10) != u32::MAX
        {
            return TestResult::Fail(
                "revoked SDHCI owner reached PCI configuration or invalid MMIO",
            );
        }
        io.write8(0x29, 0);
        io.write16(0x2c, 0);
        io.write32(0x38, 0);
        if io.host_identity() != Some(identity) {
            return TestResult::Fail("SDHCI immutable host identity changed with authority");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/sdio/native",
        smoke_sdhci_native_revocation_blocks_configuration_and_mmio
    );
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

    fn smoke_sdhci_failed_init_releases_host_claim() -> TestResult {
        let address = narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(0, 4, 0, 0));
        let other = narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(0, 5, 0, 0));
        let mut claims = Vec::new();
        if claim_once(&mut claims, address) != Claim::New
            || release_claim(&mut claims, other)
            || claims.len() != 1
        {
            return TestResult::Fail("releasing a foreign address dropped a live claim");
        }
        if !release_claim(&mut claims, address) || !claims.is_empty() {
            return TestResult::Fail("failed init did not release the host claim");
        }
        if claim_once(&mut claims, address) != Claim::New || claims.len() != 1 {
            return TestResult::Fail("retry after a failed init cannot re-claim the host");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/sdio/native",
        smoke_sdhci_failed_init_releases_host_claim
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

    fn smoke_sdhci_init_error_maps_to_arbitration() -> TestResult {
        // The arbitration contract (issue #824, bus spec §9.3): a
        // host whose slot is empty or whose card proved to be a
        // memory card is *declined*, so probe_all falls through to
        // the storage SDHCI driver; a genuine initialisation
        // failure on an SDIO host stays a terminal BadDevice.
        if init_error_to_probe_error(crate::card::Error::NoCard)
            != narf_bus::ProbeError::NotForThisDriver
            || init_error_to_probe_error(crate::card::Error::Unsupported)
                != narf_bus::ProbeError::NotForThisDriver
        {
            return TestResult::Fail("non-SDIO host was not declined to the storage driver");
        }
        if init_error_to_probe_error(crate::card::Error::Cis) != narf_bus::ProbeError::BadDevice
            || init_error_to_probe_error(crate::card::Error::Response)
                != narf_bus::ProbeError::BadDevice
        {
            return TestResult::Fail("genuine init failure lost its terminal BadDevice");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/sdio/native",
        smoke_sdhci_init_error_maps_to_arbitration
    );
}
