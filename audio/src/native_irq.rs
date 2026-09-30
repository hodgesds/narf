//! Owned interrupt routing for native audio controllers. Firmware routing is
//! optional; the bounded service timer also handles devices without an IRQ route.
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
#[cfg(target_arch = "x86_64")]
use narf_bus::BusKind;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_interrupts::{dispatch, vector};

#[derive(Debug, Copy, Clone)]
pub(crate) enum Kind {
    Hda,
    Acp,
}
#[derive(Debug)]
pub(crate) struct State {
    pub mmio: MmioRegion,
    pub kind: Kind,
    pub pending: AtomicU32,
    pub failed: AtomicBool,
}
impl State {
    pub fn new(mmio: MmioRegion, kind: Kind) -> Arc<Self> {
        Arc::new(Self {
            mmio,
            kind,
            pending: AtomicU32::new(0),
            failed: AtomicBool::new(false),
        })
    }
    pub fn service(&self) -> bool {
        // SAFETY: owner has validated the register window and keeps it mapped
        // until IRQ removal and synchronization. All status registers are W1C.
        unsafe {
            match self.kind {
                Kind::Hda => {
                    let cause = self.mmio.read32(0x24);
                    if cause == u32::MAX {
                        self.failed.store(true, Ordering::Release);
                        return false;
                    }
                    if cause & (1 << 30) != 0 {
                        let status = self.mmio.read8(0x5d);
                        if status & 4 != 0 || self.mmio.read8(0x4d) & 1 != 0 {
                            self.failed.store(true, Ordering::Release);
                        }
                        self.mmio.write8(0x5d, status & 5);
                        self.mmio.write8(0x4d, self.mmio.read8(0x4d) & 1);
                        self.mmio.write16(0x0e, self.mmio.read16(0x0e));
                    }
                    for index in 0..30 {
                        if cause & (1 << index) != 0 && 0x84 + index * 32 <= self.mmio.len {
                            let status = self.mmio.read8(0x83 + index * 32);
                            self.mmio.write8(0x83 + index * 32, status & 0x1c);
                            if status & 0x18 != 0 {
                                self.failed.store(true, Ordering::Release);
                            }
                        }
                    }
                    self.pending.fetch_or(cause, Ordering::Release);
                    cause & 0x7fff_ffff != 0
                }
                Kind::Acp => {
                    let cause = self.mmio.read32(0x1a0c);
                    self.mmio.write32(0x1a0c, cause);
                    if cause == u32::MAX || cause & (1 << 29) != 0 {
                        self.failed.store(true, Ordering::Release);
                    }
                    self.pending.fetch_or(cause, Ordering::Release);
                    cause != 0 && cause != u32::MAX
                }
            }
        }
    }
}
fn handler(cookie: u64) -> dispatch::IrqStatus {
    // SAFETY: Route owns an Arc until removal/synchronization completes.
    if unsafe { &*(cookie as *const State) }.service() {
        dispatch::IrqStatus::Handled
    } else {
        dispatch::IrqStatus::None
    }
}

pub(crate) struct Route {
    pub vector: u8,
    owns_vector: bool,
    state: Arc<State>,
    msix: Option<MsixTable>,
    msi: Option<(narf_memory::PhysAddr, u64)>,
    #[cfg(target_arch = "x86_64")]
    gsi: Option<u32>,
}
impl core::fmt::Debug for Route {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AudioIrq")
            .field("vector", &self.vector)
            .finish()
    }
}
impl Route {
    pub fn new(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
        state: Arc<State>,
    ) -> Option<Self> {
        let v = vector::alloc().ok()?;
        dispatch::install_handler_named(v, "native-audio", Arc::as_ptr(&state) as u64, handler);
        let mut route = Self {
            vector: v,
            owns_vector: true,
            state,
            msix: None,
            msi: None,
            #[cfg(target_arch = "x86_64")]
            gsi: None,
        };
        #[cfg(target_arch = "x86_64")]
        // SAFETY: Interrupt controller initialization precedes PCI probing.
        let target = unsafe { narf_interrupts::current_cpu_target_id() };
        #[cfg(target_arch = "aarch64")]
        let target = 0;
        if target > 255 {
            return None;
        }
        if matches!(route.state.kind, Kind::Hda) {
            if let Ok(mut table) = narf_bus::enable_msix(cap, device) {
                // SAFETY: exclusively claimed capability, handler installed.
                unsafe {
                    table.disable();
                }
                if table.alloc_vector().is_some()
                    // SAFETY: Route owns the claimed device configuration and installs its handler before enabling IRQs.
                    && unsafe { table.program_vector(0, target, v) }.is_ok()
                {
                    route.msix = Some(table);
                    // SAFETY: Route owns the claimed device configuration and installs its handler before enabling IRQs.
                    if unsafe { route.msix.as_mut().unwrap().enable() }.is_ok() {
                        return Some(route);
                    }
                    // SAFETY: Route owns the claimed device configuration and installs its handler before enabling IRQs.
                    unsafe { route.msix.as_mut().unwrap().disable() };
                    route.msix = None;
                }
            }
            // The AMD analog controller normally exposes MSI, not MSI-X.
            // ARM MSI needs a device-specific ITS mapping; use MSI-X there.
            #[cfg(target_arch = "x86_64")]
            if let Ok(mut msi) = narf_bus::msi::enable_msi(cap, device, 1) {
                let BusKind::Pcie { cfg_phys, .. } = device.kind else {
                    return None;
                };
                // SAFETY: The claimed PCI function has a live ECAM mapping.
                let offset = unsafe { narf_bus::pci_cap::find_cap(device, 5) }
                    .ok()
                    .flatten()?;
                route.msi = Some((cfg_phys, offset));
                // SAFETY: owned config space, live handler and valid target.
                if unsafe { narf_bus::msi::program_msi(&mut msi, target, v) }.is_ok()
                    // SAFETY: Route owns the claimed device configuration and installs its handler before enabling IRQs.
                    && unsafe { narf_bus::msi::enable(&msi) }.is_ok()
                {
                    return Some(route);
                }
                // A failed MSI setup must not remain enabled during INTx fallback.
                // SAFETY: Route owns the claimed device configuration and installs its handler before enabling IRQs.
                unsafe {
                    let control = narf_bus::ecam::ptr_for(cfg_phys, offset + 2)?.cast::<u16>();
                    control.write_volatile(control.read_volatile() & !1);
                }
                route.msi = None;
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            let pin = narf_bus::pci::read_intx_pin(cap, device).ok()?;
            if !(1..=4).contains(&pin) {
                return None;
            }
            let path = crate::native_firmware::pci_path(device)?;
            let (parent, _) = path.rsplit_once('.')?;
            let BusKind::Pcie { addr, .. } = device.kind else {
                return None;
            };
            let irq = narf_aml::irq_routing::route_for(parent, addr.device, pin - 1)?;
            if irq.entry.source.is_some() {
                return None;
            }
            let gsi = irq.entry.source_index;
            // PCI INTx lines may already be shared with USB or another audio
            // function. Join the live vector without changing its destination.
            // SAFETY: MADT/IOAPIC initialization precedes this claimed device's IRQ setup.
            let (existing, _, flags) = unsafe { narf_acpi::ioapic::gsi_route(gsi) }?;
            if flags & narf_acpi::ioapic::MASKED == 0 {
                if flags & (0x700 | 0x800) != 0
                    || flags & (narf_acpi::ioapic::POLARITY_LOW | narf_acpi::ioapic::TRIGGER_LEVEL)
                        != (narf_acpi::ioapic::POLARITY_LOW | narf_acpi::ioapic::TRIGGER_LEVEL)
                    || existing < 32
                    || dispatch::installed_handler_names(existing).is_empty()
                {
                    return None;
                }
                dispatch::remove_handler(v, "native-audio", Arc::as_ptr(&route.state) as u64);
                dispatch::synchronize_irq(v);
                let _ = vector::free(v);
                route.vector = existing;
                route.owns_vector = false;
                dispatch::install_handler_named(
                    existing,
                    "native-audio",
                    Arc::as_ptr(&route.state) as u64,
                    handler,
                );
            } else {
                // SAFETY: masked route; fresh vector and handler are installed.
                if !unsafe {
                    narf_acpi::ioapic::route_gsi_to_vector(
                        gsi,
                        v,
                        target as u8,
                        narf_acpi::ioapic::POLARITY_LOW | narf_acpi::ioapic::TRIGGER_LEVEL,
                    )
                } {
                    return None;
                }
                route.gsi = Some(gsi);
            }
            narf_bus::pci::clear_command(cap, device, narf_bus::pci::cmd::INTX_DISABLE).ok()?;
            Some(route)
        }
        #[cfg(not(target_arch = "x86_64"))]
        None
    }
}
impl Drop for Route {
    fn drop(&mut self) {
        // Caller masks device sources before dropping the route.
        if let Some(table) = self.msix.as_mut() {
            // SAFETY: Device sources are masked; this route owns its configuration/handler.
            unsafe {
                table.disable();
            }
        }
        if let Some((cfg, offset)) = self.msi {
            // SAFETY: this route exclusively owns the device's MSI enable.
            unsafe {
                if let Some(p) = narf_bus::ecam::ptr_for(cfg, offset + 2) {
                    let p = p.cast::<u16>();
                    p.write_volatile(p.read_volatile() & !1);
                }
            }
        }
        // A shared INTx GSI is left routed; device sources are disabled by owner.
        dispatch::remove_handler(self.vector, "native-audio", Arc::as_ptr(&self.state) as u64);
        dispatch::synchronize_irq(self.vector);
        if self.owns_vector {
            // If another driver joined our INTx line, retain its route/vector.
            // It is safer to keep this boot-lifetime allocation than to recycle
            // a vector still reachable from the shared physical interrupt.
            if !dispatch::installed_handler_names(self.vector).is_empty() {
                return;
            }
            #[cfg(target_arch = "x86_64")]
            if let Some(gsi) = self.gsi {
                // SAFETY: Device sources are masked; this route owns its configuration/handler.
                unsafe {
                    narf_acpi::ioapic::route_gsi_to_vector(
                        gsi,
                        self.vector,
                        0,
                        narf_acpi::ioapic::MASKED,
                    );
                }
            }
            let _ = vector::free(self.vector);
        }
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn native_audio_shared_irq_sources() -> TestResult {
        let memory = match narf_io::alloc_coherent(8192, narf_lib::id::DomainId::DRIVER_0) {
            Ok(memory) => memory,
            Err(_) => return TestResult::Fail("fake IRQ register allocation"),
        };
        let mmio = MmioRegion {
            phys: memory.phys_addr(),
            virt: memory.cpu_mut_ptr::<u8>() as u64,
            len: memory.len() as u64,
            kind: narf_bus::bar::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let hda = State::new(mmio, Kind::Hda);
        if handler(Arc::as_ptr(&hda) as u64) != dispatch::IrqStatus::None {
            return TestResult::Fail("unrelated shared HDA IRQ");
        }
        // SAFETY: owned fake MMIO allocation includes these aligned registers.
        unsafe {
            mmio.write32(0x24, 1);
            mmio.write8(0x83, 0x18);
        }
        if handler(Arc::as_ptr(&hda) as u64) != dispatch::IrqStatus::Handled
            || !hda.failed.load(Ordering::Acquire)
        {
            return TestResult::Fail("stream DMA error must latch failure");
        }
        let acp = State::new(mmio, Kind::Acp);
        if acp.service() {
            return TestResult::Fail("unrelated shared ACP IRQ");
        }
        // SAFETY: owned fake MMIO allocation includes ACP interrupt status.
        unsafe {
            mmio.write32(0x1a0c, 1 << 16);
        }
        if !acp.service()
            || acp.failed.load(Ordering::Acquire)
            || acp.pending.load(Ordering::Acquire) != 1 << 16
        {
            return TestResult::Fail("ACP period interrupt acknowledgement");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/native-irq", native_audio_shared_irq_sources);
}
