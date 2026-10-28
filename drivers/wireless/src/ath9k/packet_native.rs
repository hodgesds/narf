// SPDX-License-Identifier: GPL-2.0-or-later
//! Private PCI adapter transferred from the retained calibrated AR9285 owner.
use super::{
    identity,
    packet::{Error, Port},
};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
pub(super) struct Native {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    bar: MmioRegion,
    active: AtomicBool,
    report: super::calibration::Report,
    rf_silent: Option<(u8, bool)>,
    ht: narf_lib::sync::IrqSafeSpinLock<Option<alloc::sync::Arc<super::ht::Grant>>>,
    ht_facts: Option<super::ht::Facts>,
    ba: narf_lib::sync::IrqSafeSpinLock<Option<alloc::sync::Arc<super::rx_ba::Grant>>>,
    tx_ba: narf_lib::sync::IrqSafeSpinLock<Option<alloc::sync::Arc<super::tx_ba::Grant>>>,
    msi: narf_lib::sync::IrqSafeSpinLock<Option<Msi>>,
}
/// Single MSI vector (Linux `ath9k_use_msi` + `pci_enable_msi`). The handler
/// only raises the retained signal; the BAR is serviced by the station task.
struct Msi {
    config: narf_bus::msi::MsiConfig,
    vector: u8,
    signal: alloc::sync::Arc<super::irq::Signal>,
}
static SIGNAL: narf_lib::sync::IrqSafeSpinLock<Option<alloc::sync::Arc<super::irq::Signal>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
fn vector_irq(_cookie: u64) -> narf_interrupts::IrqStatus {
    let signal = { SIGNAL.lock().clone() };
    match signal {
        Some(signal) => {
            signal.raise();
            narf_interrupts::IrqStatus::Handled
        }
        None => narf_interrupts::IrqStatus::None,
    }
}
impl Native {
    /// # Safety
    /// Caller retains the sole AR9285 function and exact mapped BAR through
    /// calibration/MAC/packet composition. This adapter cannot be cloned.
    pub(super) unsafe fn new(
        device: BusDevice,
        cap: Cap<BusDeviceCap, Write>,
        bar: MmioRegion,
        report: super::calibration::Report,
        image: &[u8; super::EEPROM_4K_BYTES],
    ) -> Result<Self, Error> {
        // AR2427 shares this legacy owner; HT stays behind `ht::Facts`.
        if !crate::ath9k::ar9285_silicon(&device.id) || report.frequency_mhz != 2412 {
            return Err(Error::Packet);
        }
        let bytes = [image[20], image[21]];
        let rf = if image[7] & 1 != 0 {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        };
        let rf_silent = if rf & 1 != 0 {
            if rf & !31 != 0 {
                return Err(Error::Packet);
            }
            Some((((rf >> 2) & 7) as u8, rf & 2 != 0))
        } else {
            None
        };
        Ok(Self {
            device,
            cap,
            bar,
            active: AtomicBool::new(false),
            report,
            rf_silent,
            ht: narf_lib::sync::IrqSafeSpinLock::new(None),
            ht_facts: None,
            ba: narf_lib::sync::IrqSafeSpinLock::new(None),
            tx_ba: narf_lib::sync::IrqSafeSpinLock::new(None),
            msi: narf_lib::sync::IrqSafeSpinLock::new(None),
        })
    }
    /// Discover, program and install one MSI vector while delivery stays
    /// disabled. Any failure leaves the owner on scheduled polling; a vector
    /// whose source cannot be proven disabled stays quarantined.
    pub(super) fn arm_msi(&self) -> bool {
        if self.msi.lock().is_some() || SIGNAL.lock().is_some() {
            return false;
        }
        let Ok(Ok(mut config)) =
            self.invoke_cfg(|| narf_bus::msi::enable_msi(&self.cap, &self.device, 1))
        else {
            return false;
        };
        let Ok(vector) = narf_interrupts::vector::alloc() else {
            return false;
        };
        // SAFETY: this sole retained function owns its cfg space; delivery
        // is disabled again below before any chip interrupt is unmasked.
        let programmed =
            self.invoke_cfg(|| unsafe { narf_bus::msi::program_msi(&mut config, 0, vector) });
        if !matches!(programmed, Ok(Ok(_))) {
            let _ = narf_interrupts::vector::free(vector);
            return false;
        }
        let signal = super::irq::Signal::new();
        *SIGNAL.lock() = Some(signal.clone());
        narf_interrupts::install_handler_named(vector, "ath9k", 0, vector_irq);
        let msi = Msi {
            config,
            vector,
            signal,
        };
        // SAFETY: same owned cfg space; MSI Enable stays clear until start.
        if !matches!(
            self.invoke_cfg(|| unsafe { narf_bus::msi::disable(&msi.config) }),
            Ok(Ok(()))
        ) {
            quarantine(&msi);
            return false;
        }
        *self.msi.lock() = Some(msi);
        true
    }
    fn invoke_cfg<T>(&self, operation: impl FnOnce() -> T) -> Result<T, Error> {
        identity::invoke(&self.cap, operation).map_err(|_| Error::Access)
    }
}
fn quarantine(msi: &Msi) {
    narf_interrupts::disable_irq(msi.vector);
    narf_interrupts::dispatch::clear_all_wakers(msi.vector);
    narf_interrupts::synchronize_irq(msi.vector);
}
/// Disabled delivery: drain the handler and return the vector.
fn teardown(msi: Msi) {
    narf_interrupts::disable_irq(msi.vector);
    let _ = narf_interrupts::remove_handler(msi.vector, "ath9k", 0);
    narf_interrupts::dispatch::clear_all_wakers(msi.vector);
    narf_interrupts::synchronize_irq(msi.vector);
    let _ = narf_interrupts::vector::free(msi.vector);
    let mut signal = SIGNAL.lock();
    if signal
        .as_ref()
        .is_some_and(|s| alloc::sync::Arc::ptr_eq(s, &msi.signal))
    {
        *signal = None;
    }
}
impl Native {
    pub(super) fn qualify_ht(&mut self, facts: super::ht::Facts) {
        let grant = super::ht::Source::Registered.load(facts.clone()).ok();
        *self.ht.lock() = grant;
        self.ht_facts = Some(facts);
    }
    fn command(&self) -> Result<u16, Error> {
        let command =
            narf_bus::pci::read_command(&self.cap, &self.device).map_err(|_| Error::Access)?;
        if command == u16::MAX
            || command & (narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE)
                != narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE
        {
            return Err(Error::Access);
        }
        Ok(command)
    }
    fn extent(&self, reg: u64) -> Result<(), Error> {
        if reg & 3 != 0 || reg.checked_add(4).is_none_or(|end| end > self.bar.len) {
            Err(Error::Address)
        } else {
            Ok(())
        }
    }
    fn invoke<T>(&self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        identity::invoke(&self.cap, operation).map_err(|_| Error::Access)?
    }
}

#[cfg(feature = "kernel-test")]
fn smoke_ar9285_native_packet_revocation_precedes_config_dma_and_mmio(
) -> narf_kernel_test::TestResult {
    for id in [0x002b, 0x002c] {
        if let Err(error) = revoked_packet_authority(id) {
            return narf_kernel_test::TestResult::Fail(error);
        }
    }
    narf_kernel_test::TestResult::Pass
}
#[cfg(feature = "kernel-test")]
fn revoked_packet_authority(id: u16) -> Result<(), &'static str> {
    use narf_bus::{BarKind, BusAddr, BusKind, DeviceId, PcieAddr};
    let address = PcieAddr::new(0, 0, 7, 0);
    let device = BusDevice {
        addr: BusAddr::Pcie(address),
        id: DeviceId {
            vendor: 0x168c,
            device: id,
            class: 0x028000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr: address,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
    };
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    let bar = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: super::phy::REQUIRED_BAR,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let report = super::calibration::Report {
        country: *b"US",
        frequency_mhz: 2412,
        max_power_half_dbm: 34,
        pa_offset: None,
        iq_i: 0,
        iq_q: 0,
        measured_noise_dbm: -115,
        noise_dbm: -115,
    };
    cap.revoke();
    // SAFETY: invalid config/BAR addresses are deliberately unreachable with
    // the revoked real object-table capability. No physical DMA is published.
    let Ok(native) =
        (unsafe { Native::new(device, cap, bar, report, &[0; super::EEPROM_4K_BYTES]) })
    else {
        return Err("native fixture shape");
    };
    let mut entered = false;
    if native.access(false, || {
        entered = true;
        Ok(())
    }) != Err(Error::Access)
        || entered
        || native.read(0x4020) != Err(Error::Access)
        || native.write(0xc, 0x1000) != Err(Error::Access)
        || native.allocate(128).is_ok()
        || native.master(true) != Err(Error::Access)
        || native.master(false) != Err(Error::Access)
    {
        return Err("revoked packet authority reached config, DMA or BAR");
    }
    if native.ht_grant().is_some() {
        return Err("legacy AR9285-silicon owner loaded HT without measured facts");
    }
    Ok(())
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "drivers/wireless/ath9k/packet",
    smoke_ar9285_native_packet_revocation_precedes_config_dma_and_mmio
);
impl Port for Native {
    fn tx_ba_grant(&self) -> Option<alloc::sync::Arc<super::tx_ba::Grant>> {
        if let Some(g) = self.tx_ba.lock().clone() {
            return Some(g);
        }
        let grant = super::tx_ba::Source::Registered
            .load(self.ht_grant()?)
            .ok()?;
        let mut retained = self.tx_ba.lock();
        Some(retained.get_or_insert(grant).clone())
    }
    fn rx_ba_grant(&self) -> Option<alloc::sync::Arc<super::rx_ba::Grant>> {
        if let Some(grant) = self.ba.lock().clone() {
            return Some(grant);
        }
        let base = self.ht_grant()?;
        let grant = super::rx_ba::Source::Registered.load(base).ok()?;
        let mut retained = self.ba.lock();
        Some(retained.get_or_insert(grant).clone())
    }
    fn ht_grant(&self) -> Option<alloc::sync::Arc<super::ht::Grant>> {
        if let Some(grant) = self.ht.lock().clone() {
            return Some(grant);
        }
        // The report-bound request can be provisioned after legacy packet
        // preparation. Only an absent optional grant may be loaded; a revoked
        // established source is never replaced. The cache guard never spans lookup.
        let grant = super::ht::Source::Registered
            .load(self.ht_facts.clone()?)
            .ok()?;
        let mut retained = self.ht.lock();
        Some(retained.get_or_insert(grant).clone())
    }
    fn transmit_allowed(&self) -> Result<(), Error> {
        let domain = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
        let permission =
            super::calibration::Permission::from_domain(&domain).map_err(|_| Error::Access)?;
        if !permission.allows_report(self.report) {
            return Err(Error::Access);
        }
        if let Some((gpio, polarity)) = self.rf_silent {
            if (self.read(0x4048)? & (1 << (12 + gpio)) != 0) == polarity {
                return Err(Error::Access);
            }
        }
        let grant = { self.ht.lock().clone() };
        if let Some(grant) = grant {
            grant.readback(self)?;
        }
        Ok(())
    }
    fn access<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.invoke(|| {
            let command = self.command()?;
            if (command & narf_bus::pci::cmd::BUS_MASTER != 0) != active
                || self.active.load(Ordering::Acquire) != active
            {
                return Err(Error::Access);
            }
            let domain = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
            let permission =
                super::calibration::Permission::from_domain(&domain).map_err(|_| Error::Access)?;
            if !permission.allows_report(self.report) {
                return Err(Error::Access);
            }
            if let Some((gpio, polarity)) = self.rf_silent {
                self.extent(0x4048)?;
                // SAFETY: checked full input-register extent in current PCI
                // invocation, without recursively entering this access helper.
                let value = unsafe { self.bar.read32(0x4048) };
                if value == u32::MAX || (value & (1 << (12 + gpio)) != 0) == polarity {
                    return Err(Error::Access);
                }
            }
            let grant = { self.ht.lock().clone() };
            let ba = { self.ba.lock().clone() };
            let tx = { self.tx_ba.lock().clone() };
            let operation = || match (ba, grant) {
                (Some(g), _) => g.invoke(operation),
                (None, Some(g)) => g.invoke(operation),
                (None, None) => operation(),
            };
            if let Some(g) = tx {
                g.invoke(operation)
            } else {
                operation()
            }
        })
    }
    fn read(&self, reg: u64) -> Result<u32, Error> {
        self.access(self.active.load(Ordering::Acquire), || {
            self.extent(reg)?;
            // SAFETY: complete aligned BAR extent inside current invocation.
            let value = unsafe { self.bar.read32(reg) };
            if value == u32::MAX {
                self.extent(0x4020)?;
                // SAFETY: checked immutable silicon-ID dword in same BAR and invocation.
                if unsafe { self.bar.read32(0x4020) } == u32::MAX {
                    return Err(Error::Access);
                }
            }
            Ok(value)
        })
    }
    fn write(&self, reg: u64, value: u32) -> Result<(), Error> {
        self.access(self.active.load(Ordering::Acquire), || {
            self.extent(reg)?;
            // SAFETY: full aligned extent, exact exclusive retained PCI capability.
            unsafe {
                self.bar.write32(reg, value);
            }
            Ok(())
        })
    }
    fn allocate(&self, bytes: usize) -> Result<narf_io::DmaBuffer, Error> {
        self.access(false, || {
            if narf_io::iommu::mode() == narf_io::iommu::IommuMode::PerDomain {
                return Err(Error::Access);
            }
            narf_io::alloc_coherent_masked(
                bytes,
                narf_lib::id::DomainId::DRIVER_0,
                u64::from(u32::MAX),
            )
            .map_err(|_| Error::Memory)
        })
    }
    fn master(&self, enabled: bool) -> Result<(), Error> {
        self.invoke(|| {
            self.command()?;
            // Mark before the possibly ambiguous activation. Stopping remains
            // available independently, even after a failed BME readback.
            self.active.store(enabled, Ordering::Release);
            if enabled {
                narf_bus::pci::set_command(&self.cap, &self.device, narf_bus::pci::cmd::BUS_MASTER)
            } else {
                narf_bus::pci::clear_command(
                    &self.cap,
                    &self.device,
                    narf_bus::pci::cmd::BUS_MASTER,
                )
            }
            .map_err(|_| Error::Access)?;
            if (self.command()? & narf_bus::pci::cmd::BUS_MASTER != 0) != enabled {
                return Err(Error::Access);
            }
            Ok(())
        })
    }
    fn now_us(&self) -> u64 {
        narf_time::monotonic_ns() / 1000
    }
    fn ordered(&self) -> bool {
        // PCIe Device Control bit 4: Enable Relaxed Ordering.
        let Ok(read) = self.cap.derive::<narf_capabilities::Read>() else {
            return false;
        };
        matches!(
            self.invoke_cfg(|| narf_bus::pci_express::read_status(&read, &self.device)),
            Ok(Ok(status)) if status.device_control & (1 << 4) == 0
        )
    }
    fn interrupt(&self) -> Option<alloc::sync::Arc<super::irq::Signal>> {
        self.msi.lock().as_ref().map(|m| m.signal.clone())
    }
    fn deliver(&self, enabled: bool) -> Result<(), Error> {
        let mut retained = self.msi.lock();
        let Some(msi) = retained.as_ref() else {
            return Err(Error::State);
        };
        if enabled {
            narf_interrupts::enable_irq(msi.vector);
            // SAFETY: sole owner of this function's MSI capability.
            return match self.invoke_cfg(|| unsafe { narf_bus::msi::enable(&msi.config) }) {
                Ok(Ok(())) => Ok(()),
                _ => Err(Error::Access),
            };
        }
        // SAFETY: as above; a failed disable keeps the vector quarantined.
        let disabled = self.invoke_cfg(|| unsafe { narf_bus::msi::disable(&msi.config) });
        let msi = retained.take().ok_or(Error::State)?;
        drop(retained);
        if matches!(disabled, Ok(Ok(()))) {
            teardown(msi);
            Ok(())
        } else {
            quarantine(&msi);
            core::mem::forget(msi);
            Err(Error::Access)
        }
    }
}
