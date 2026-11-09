//! Retained rtlwifi PCI authority for RTL8188EE MMIO firmware writes.
use super::firmware_transport::{Error, Io};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

pub struct PciIo {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    registers: MmioRegion,
    packet_mode: AtomicBool,
    quarantined: AtomicBool,
    aspm_prepared: AtomicBool,
    msi: narf_lib::sync::IrqSafeSpinLock<Option<Msi>>,
}
/// Single MSI vector (Linux `rtl_pci_intr_mode_msi`: `pci_enable_msi` +
/// `request_irq(_rtl_pci_interrupt)`). The top half only raises the
/// retained signal; BAR2 recognition runs in the station worker.
struct Msi {
    config: narf_bus::msi::MsiConfig,
    vector: u8,
    signal: alloc::sync::Arc<super::irq::Signal>,
}
#[path = "aspm_native.rs"]
mod aspm_native;
#[path = "irq_routes.rs"]
mod irq_routes;
static SIGNALS: narf_lib::sync::IrqSafeSpinLock<irq_routes::Routes> =
    narf_lib::sync::IrqSafeSpinLock::new(irq_routes::Routes::new());
fn vector_irq(cookie: u64) -> narf_interrupts::IrqStatus {
    let signal = { SIGNALS.lock().get(cookie) };
    match signal {
        Some(signal) => {
            signal.raise();
            narf_interrupts::IrqStatus::Handled
        }
        None => narf_interrupts::IrqStatus::None,
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
    let _ = narf_interrupts::remove_handler(msi.vector, "rtlwifi", u64::from(msi.vector));
    narf_interrupts::dispatch::clear_all_wakers(msi.vector);
    narf_interrupts::synchronize_irq(msi.vector);
    // Withdraw the old route before the allocator may reuse its vector.
    // The drained handler's snapshots retain only their original Arc.
    let removed = SIGNALS.lock().remove(msi.vector, &msi.signal);
    if removed {
        let _ = narf_interrupts::vector::free(msi.vector);
    }
}
fn command_gate(command: u16, packet_mode: bool) -> Result<(), Error> {
    // An absent PCI function reports all ones. In active mode those bits
    // otherwise resemble valid MEM/BME/INTX decoding; no DMA/MMIO access is
    // authorized by that synthetic command value.
    if command == u16::MAX {
        return Err(Error::Gone);
    }
    if command & narf_bus::pci::cmd::MEM_SPACE == 0
        || (!packet_mode && command & narf_bus::pci::cmd::BUS_MASTER != 0)
        || command & narf_bus::pci::cmd::INTX_DISABLE == 0
    {
        return Err(Error::Access);
    }
    Ok(())
}
impl core::fmt::Debug for PciIo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RtlwifiPciFirmwareIo")
            .field("address", &self.device.addr)
            .finish_non_exhaustive()
    }
}
impl PciIo {
    pub(super) fn publication(&self) -> super::prepare::packet::Publication {
        super::prepare::packet::Publication::native(self.device, self.cap)
    }
    /// Caller owns the exact live BAR2 control region exclusively. No other
    /// firmware/register path may run concurrently with the retained owner.
    pub(super) unsafe fn new(
        device: BusDevice,
        cap: Cap<BusDeviceCap, Write>,
        registers: MmioRegion,
    ) -> Self {
        Self {
            device,
            cap,
            registers,
            packet_mode: AtomicBool::new(false),
            quarantined: AtomicBool::new(false),
            aspm_prepared: AtomicBool::new(false),
            msi: narf_lib::sync::IrqSafeSpinLock::new(None),
        }
    }
    /// Discover, program and install one MSI vector with delivery still
    /// disabled. Any failure leaves the owner on scheduled polling; a
    /// vector whose source cannot be proven disabled stays quarantined.
    pub(super) fn arm_msi(&self) -> bool {
        if self.msi.lock().is_some() {
            return false;
        }
        let Ok(Ok(mut config)) = crate::rtw88::pci_park::invoke(&self.cap, || {
            narf_bus::msi::enable_msi(&self.cap, &self.device, 1)
        }) else {
            return false;
        };
        let Ok(vector) = narf_interrupts::vector::alloc() else {
            return false;
        };
        if SIGNALS.lock().get(u64::from(vector)).is_some() {
            // An occupied route cannot become another function's vector.
            // Retain this inconsistent allocation rather than reuse it.
            return false;
        }
        // SAFETY: this sole retained function owns its cfg space; delivery
        // is disabled again below before any chip interrupt is unmasked.
        let programmed = crate::rtw88::pci_park::invoke(&self.cap, || unsafe {
            narf_bus::msi::program_msi(&mut config, 0, vector)
        });
        if !matches!(programmed, Ok(Ok(_))) {
            let _ = narf_interrupts::vector::free(vector);
            return false;
        }
        let signal = super::irq::Signal::new();
        if !SIGNALS.lock().insert(vector, signal.clone()) {
            // Vector allocation is exclusive. A conflicting route is a
            // terminal allocator inconsistency, never permission to reuse it.
            return false;
        }
        narf_interrupts::install_handler_named(vector, "rtlwifi", u64::from(vector), vector_irq);
        let msi = Msi {
            config,
            vector,
            signal,
        };
        // SAFETY: same owned cfg space; MSI Enable stays clear until the
        // running owner programs HIMR.
        let disabled = crate::rtw88::pci_park::invoke(&self.cap, || unsafe {
            narf_bus::msi::disable(&msi.config)
        });
        if !matches!(disabled, Ok(Ok(()))) {
            self.quarantined.store(true, Ordering::Release);
            quarantine(&msi);
            core::mem::forget(msi);
            return false;
        }
        *self.msi.lock() = Some(msi);
        true
    }
    pub(super) fn interrupt(&self) -> Option<alloc::sync::Arc<super::irq::Signal>> {
        self.msi.lock().as_ref().map(|m| m.signal.clone())
    }
    /// Enable delivery, or disable it and release the vector. A failed
    /// cfg-space disable keeps the vector quarantined rather than freed.
    pub(super) fn deliver(&self, enabled: bool) -> bool {
        let mut retained = self.msi.lock();
        let Some(msi) = retained.as_ref() else {
            return false;
        };
        if enabled {
            narf_interrupts::enable_irq(msi.vector);
            // SAFETY: sole owner of this function's MSI capability.
            let enabled = crate::rtw88::pci_park::invoke(&self.cap, || unsafe {
                narf_bus::msi::enable(&msi.config)
            });
            if matches!(enabled, Ok(Ok(()))) {
                return true;
            }
        }
        // SAFETY: as above.
        let disabled = crate::rtw88::pci_park::invoke(&self.cap, || unsafe {
            narf_bus::msi::disable(&msi.config)
        });
        let Some(msi) = retained.take() else {
            return false;
        };
        drop(retained);
        if matches!(disabled, Ok(Ok(()))) {
            teardown(msi);
        } else {
            self.quarantined.store(true, Ordering::Release);
            quarantine(&msi);
            core::mem::forget(msi);
        }
        false
    }
    /// Only the serialized replacement owner calls this after the old
    /// Prepared DMA retirement receipt and IRQ withdrawal. A failed MSI
    /// disable cannot be converted into a fresh source of register authority.
    pub(super) fn parked_control(&self) -> Result<Self, Error> {
        if self.quarantined.load(Ordering::Acquire) || self.msi.lock().is_some() {
            return Err(Error::Gate);
        }
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check(0, 1)?;
            let command =
                narf_bus::pci::read_command(&self.cap, &self.device).map_err(|_| Error::Access)?;
            command_gate(command, false)?;
            self.check_identity()?;
            // SAFETY: the old IRQ and DMA owner is retired, the caller owns
            // the device control mutex, and current config proves parked DMA.
            Ok(unsafe { Self::new(self.device, self.cap, self.registers) })
        })
        .map_err(|_| Error::Access)?
    }
    fn check_identity(&self) -> Result<(), Error> {
        self.check_function_identity()?;
        let read = |at| {
            narf_bus::pci::read_config32(&self.cap, &self.device, at).map_err(|_| Error::Access)
        };
        let low = read(0x18)?;
        if low & 1 != 0 || low == u32::MAX {
            return Err(Error::Gone);
        }
        let high = if low & 6 == 4 {
            u64::from(read(0x1c)?) << 32
        } else {
            0
        };
        if high | u64::from(low & !15) != self.registers.phys.raw() {
            return Err(Error::Gone);
        }
        Ok(())
    }
    fn check_function_identity(&self) -> Result<(), Error> {
        let read = |at| {
            narf_bus::pci::read_config32(&self.cap, &self.device, at).map_err(|_| Error::Access)
        };
        let id = u32::from(self.device.id.vendor) | (u32::from(self.device.id.device) << 16);
        let subsystem = u32::from(self.device.id.subsystem_vendor)
            | (u32::from(self.device.id.subsystem_id) << 16);
        if read(0)? != id || read(0x2c)? != subsystem {
            return Err(Error::Gone);
        }
        Ok(())
    }
    /// RTL8821AE WoWLAN PCI wake (`rtl_op_suspend`'s
    /// `device_set_wakeup_enable(true)` → PCI core `pci_prepare_to_sleep`):
    /// the endpoint PME → ACPI `_PRW` GPE route admitted for `target` from
    /// D3hot. Only this endpoint's Write authority is used; the platform
    /// Power grant is the `narf_power::pci_wake` owner's.
    pub(super) fn wake_route(
        &self,
        target: narf_power::system_pm::SystemSleepState,
    ) -> Result<narf_power::pci_wake::PciWake, Error> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(Error::Gate);
        }
        let route = narf_power::pci_wake::PciWake::discover(&self.cap, self.device)
            .map_err(|_| Error::Access)?;
        route
            .admits(target, narf_bus::pci::pme::WakeState::D3Hot)
            .map_err(|_| Error::Access)?;
        Ok(route)
    }
    /// PMCSR power-state write of this exact function (config space only).
    pub(super) fn set_pci_power(&self, state: narf_bus::pci::PciPowerState) -> Result<(), Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check_function_identity()?;
            narf_bus::pci::set_power_state(&self.cap, &self.device, state)
                .map_err(|_| Error::Access)
        })
        .map_err(|_| Error::Access)?
    }
    pub(super) fn pci_power(&self) -> Result<Option<narf_bus::pci::PciPowerState>, Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check_function_identity()?;
            narf_bus::pci::power_state(&self.cap, &self.device).map_err(|_| Error::Access)
        })
        .map_err(|_| Error::Access)?
    }
    pub(super) fn suspend_config(&self) -> Result<narf_bus::pci::SavedPciConfig, Error> {
        if self.quarantined.load(Ordering::Acquire) || self.msi.lock().is_some() {
            return Err(Error::Gate);
        }
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check_identity()?;
            let saved =
                narf_bus::pci::save_config(&self.cap, &self.device).map_err(|_| Error::Access)?;
            command_gate(saved.command, false)?;
            Ok(saved)
        })
        .map_err(|_| Error::Access)?
    }
    pub(super) fn resume_config(&self, saved: &narf_bus::pci::SavedPciConfig) -> Result<(), Error> {
        if self.quarantined.load(Ordering::Acquire) || self.msi.lock().is_some() {
            return Err(Error::Gate);
        }
        command_gate(saved.command, false)?;
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check_function_identity()?;
            // Config decoding may have been lost in S3. Disable DMA and MEM
            // before restoring BARs; the saved command restores only parked
            // MEM+INTx-disabled state. Fresh rings enable BME much later.
            narf_bus::pci::clear_command(
                &self.cap,
                &self.device,
                narf_bus::pci::cmd::BUS_MASTER | narf_bus::pci::cmd::MEM_SPACE,
            )
            .map_err(|_| Error::Access)?;
            let command =
                narf_bus::pci::read_command(&self.cap, &self.device).map_err(|_| Error::Access)?;
            if command == u16::MAX
                || command & (narf_bus::pci::cmd::BUS_MASTER | narf_bus::pci::cmd::MEM_SPACE) != 0
            {
                return Err(Error::Gate);
            }
            narf_bus::pci::restore_config(&self.cap, &self.device, saved)
                .map_err(|_| Error::Access)?;
            command_gate(
                narf_bus::pci::read_command(&self.cap, &self.device).map_err(|_| Error::Access)?,
                false,
            )?;
            self.check_identity()
        })
        .map_err(|_| Error::Access)?
    }
    /// The PCI function number of the retained device, if it is a PCIe
    /// device (`BusAddr::Pcie`). Dual-function parts (RTL8192DE: one
    /// function per MAC) select their per-function factory and radio
    /// parameters from it.
    pub(super) fn function(&self) -> Option<u8> {
        match self.device.addr {
            narf_bus::BusAddr::Pcie(address) => Some(address.function),
            _ => None,
        }
    }
    pub(super) fn verify_factory(&self, expected: &super::efuse::Factory) -> Result<(), Error> {
        self.access(0xcf, 1, || {
            self.check_identity()?;
            let function = match self.device.addr {
                narf_bus::BusAddr::Pcie(address) => address.function,
                _ => return Err(Error::Unsupported),
            };
            // SAFETY: the caller holds exclusive control after card enable,
            // current PCI identity/BAR were checked within this invocation.
            let actual = unsafe {
                super::efuse::read_factory(&self.registers, self.device.id.device, function)
            }
            .map_err(|_| Error::Gate)?;
            if actual.mac != expected.mac || actual.logical != expected.logical {
                return Err(Error::Gate);
            }
            Ok(())
        })?
    }
    pub(super) fn allocate_dma(&self, bytes: usize) -> Result<narf_io::DmaBuffer, Error> {
        if narf_io::iommu::mode() == narf_io::iommu::IommuMode::PerDomain {
            return Err(Error::Unsupported);
        }
        // Current PCI authority and parked DMA are checked in the same
        // invocation that allocates storage for this exact retained function.
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check(0, 1)?;
            narf_io::alloc_coherent_masked(
                bytes,
                narf_lib::id::DomainId::DRIVER_0,
                u64::from(u32::MAX),
            )
            .map_err(|_| Error::NoMemory)
        })
        .map_err(|_| Error::Access)?
    }
    fn access<T>(&self, reg: u16, width: usize, operation: impl FnOnce() -> T) -> Result<T, Error> {
        // The PCI command check and actual MMIO execute in the same live
        // capability operation; returning a raw register handle is forbidden.
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check(reg, width)?;
            Ok(operation())
        })
        .map_err(|_| Error::Access)?
    }
    fn check(&self, reg: u16, width: usize) -> Result<(), Error> {
        let cmd =
            narf_bus::pci::read_command(&self.cap, &self.device).map_err(|_| Error::Access)?;
        command_gate(cmd, self.packet_mode.load(Ordering::Acquire))?;
        if u64::try_from(width)
            .ok()
            .and_then(|n| u64::from(reg).checked_add(n))
            .is_none_or(|end| end > self.registers.len)
        {
            return Err(Error::Access);
        }
        Ok(())
    }
    pub(super) fn packet_authority<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, super::prepare::Error>,
    ) -> Result<Result<T, super::prepare::Error>, Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check(0, 1)?;
            let command =
                narf_bus::pci::read_command(&self.cap, &self.device).map_err(|_| Error::Access)?;
            if (command & narf_bus::pci::cmd::BUS_MASTER != 0) != active
                || (active && !self.packet_mode.load(Ordering::Acquire))
            {
                return Err(Error::Gate);
            }
            Ok(operation())
        })
        .map_err(|_| Error::Access)?
    }
    pub(super) fn packet_master(&self, enabled: bool) -> Result<(), Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check(0, 1)?;
            if enabled {
                // This private one-shot port is reachable only after the
                // retained owner validates its complete native ring/MAC state.
                // Mark before the possibly ambiguous PCI write; failure never
                // reconstructs parked firmware access or another packet owner.
                self.packet_mode
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .map_err(|_| Error::Gate)?;
                narf_bus::pci::set_command(&self.cap, &self.device, narf_bus::pci::cmd::BUS_MASTER)
                    .map_err(|_| Error::Access)?;
            } else {
                narf_bus::pci::clear_command(
                    &self.cap,
                    &self.device,
                    narf_bus::pci::cmd::BUS_MASTER,
                )
                .map_err(|_| Error::Access)?;
            }
            let command =
                narf_bus::pci::read_command(&self.cap, &self.device).map_err(|_| Error::Access)?;
            if (command & narf_bus::pci::cmd::BUS_MASTER != 0) != enabled {
                return Err(Error::Gate);
            }
            Ok(())
        })
        .map_err(|_| Error::Access)?
    }
    pub(super) fn packet_kick(&self, queue_bit: u16) -> Result<(), Error> {
        // BK0/BE1/VI2/VO3 WMM rings, BEACON4 reserved page and MGNT6.
        if !matches!(queue_bit, 1 | 2 | 4 | 8 | 16 | 64) {
            return Err(Error::Gate);
        }
        self.packet_authority(true, || {
            self.check(0x300, 2)?;
            // SAFETY: aligned complete MMIO word, inside current invocation;
            // bit mapping is Linux hw_queue BIT(n), not vector indices.
            unsafe { self.registers.write16(0x300, queue_bit) };
            // Flush the posted control write; this read is not TX completion.
            // SAFETY: the same current capability invocation and complete
            // aligned word-extent check above cover this MMIO readback.
            let value = unsafe { self.registers.read16(0x300) };
            if value & 0xff00 != 0 {
                return Err(super::prepare::Error::Readback);
            }
            Ok(())
        })?
        .map_err(|_| Error::Gate)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
fn smoke_rtl8188ee_native_pci_absence_cannot_authorize_active_dma() -> narf_kernel_test::TestResult
{
    use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
    use narf_kernel_test::TestResult;
    for active in [false, true] {
        if command_gate(u16::MAX, active) != Err(Error::Gone) {
            return TestResult::Fail("absent PCI function authorized retained DMA/MMIO");
        }
        for command in [0, MEM_SPACE, INTX_DISABLE, BUS_MASTER | INTX_DISABLE] {
            if command_gate(command, active).is_ok() {
                return TestResult::Fail("missing PCI decoding/IRQ mask authorized native MMIO");
            }
        }
    }
    if command_gate(MEM_SPACE | INTX_DISABLE, false).is_err()
        || command_gate(MEM_SPACE | INTX_DISABLE | BUS_MASTER, true).is_err()
        || command_gate(MEM_SPACE | INTX_DISABLE | BUS_MASTER, false).is_ok()
    {
        return TestResult::Fail("native parked/active PCI command policy differs");
    }
    TestResult::Pass
}
#[cfg(any(test, feature = "kernel-test"))]
narf_kernel_test::kernel_test_in!(
    "drivers/wireless/rtlwifi/packet",
    smoke_rtl8188ee_native_pci_absence_cannot_authorize_active_dma
);
#[async_trait::async_trait]
impl Io for PciIo {
    fn read8(&self, reg: u16) -> Result<u8, Error> {
        // SAFETY: access checks live authority, parked DMA and complete byte extent.
        self.access(reg, 1, || unsafe { self.registers.read8(u64::from(reg)) })
    }
    fn read32(&self, reg: u16) -> Result<u32, Error> {
        if reg & 3 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: aligned dword extent checked inside the live invocation.
        self.access(reg, 4, || unsafe { self.registers.read32(u64::from(reg)) })
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), Error> {
        // SAFETY: access checks live authority, parked DMA and complete byte extent.
        self.access(reg, 1, || unsafe {
            self.registers.write8(u64::from(reg), value)
        })
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), Error> {
        if reg & 3 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: aligned dword extent checked inside the live invocation.
        self.access(reg, 4, || unsafe {
            self.registers.write32(u64::from(reg), value)
        })
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), Error> {
        if reg & 1 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: aligned word extent checked inside the live invocation.
        self.access(reg, 2, || unsafe {
            self.registers.write16(u64::from(reg), value)
        })
    }
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), Error> {
        self.access(reg, bytes.len(), || {
            for (i, byte) in bytes.iter().enumerate() {
                // SAFETY: complete byte slice was bounded inside this CapOp.
                unsafe { self.registers.write8(u64::from(reg) + i as u64, *byte) };
            }
        })
    }
}
