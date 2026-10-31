//! Graphics GuC/RCS interrupt delivery for single-tile physical functions.
//! MIT Linux xe_irq.c and xe_guc.c, b90c984d615e8ce2af96f5b1411a962d83fed2ad.
//! The hard handler only masks the tile master. Identity waits and GuC work
//! run in task context; IRQ notification never proves DMA retirement.

use crate::intel_gpu_aux::MmioWindow;
use alloc::sync::Arc;
use narf_lib::sync::IrqSafeSpinLock;

const TILE: u64 = 0x190008;
const MASTER: u64 = 0x190010;
const DW: u64 = 0x190018;
const IDENTITY: u64 = 0x190060;
const SELECTOR: u64 = 0x190070;
const RENDER_ENABLE: u64 = 0x190030;
const RCS_MASK: u64 = 0x190090;
const GUC_ENABLE: u64 = 0x190038;
const GUC_MASK: u64 = 0x1900e8;
const RING_MASK: u64 = 0x20a8;
const ENABLE: u32 = 1 << 31;
const RCS: u32 = 0x11; // MI_USER_INTERRUPT and FLUSH_COMPLETE
const RCS_EVENTS: u32 = RCS << 16;
const GUC: u32 = 1 << 31; // primary GuC GUC2HOST (bit 15 in engine 1)
const OWNED: u32 = 1 | (1 << 25); // bank zero: RCS0 and primary GuC

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum IrqError {
    Unavailable,
    Conflict,
    Identity,
    Timeout,
    Route,
}

#[derive(Copy, Clone)]
struct Saved {
    master: u32,
    render: u32,
    rcs: u32,
    guc_enable: u32,
    guc_mask: u32,
    ring: u32,
}

struct State<M> {
    mmio: M,
    saved: Saved,
    active: bool,
    pending: bool,
    bits: u32,
    selected: u32,
    deadline: u64,
}

pub(crate) struct Controller<M>(IrqSafeSpinLock<State<M>>);

fn read(mmio: &impl MmioWindow, offset: u64) -> Result<u32, IrqError> {
    let value = mmio.read32(offset);
    (value != u32::MAX)
        .then_some(value)
        .ok_or(IrqError::Unavailable)
}

fn restore_bits(mmio: &impl MmioWindow, offset: u64, mask: u32, saved: u32) {
    // All-ones is a valid mask value, unlike master/identity registers.
    // Availability is checked through the master around these updates.
    let current = mmio.read32(offset);
    mmio.write32(offset, (current & !mask) | (saved & mask));
}

impl<M: MmioWindow> Controller<M> {
    pub(crate) fn new(mmio: M) -> Result<Self, IrqError> {
        // No other owner may have delivery enabled. Never commandeer firmware
        // MSI or enable a master with an unhandled display/media indication.
        let tile = read(&mmio, TILE)?;
        let master = read(&mmio, MASTER)?;
        if tile & ENABLE != 0 || tile & !(ENABLE | 1) != 0 || master & !(ENABLE | 1) != 0 {
            return Err(IrqError::Conflict);
        }
        let saved = Saved {
            master: master & ENABLE,
            render: read(&mmio, RENDER_ENABLE)?,
            rcs: mmio.read32(RCS_MASK),
            guc_enable: read(&mmio, GUC_ENABLE)?,
            guc_mask: mmio.read32(GUC_MASK),
            ring: mmio.read32(RING_MASK),
        };
        Ok(Self(IrqSafeSpinLock::new(State {
            mmio,
            saved,
            active: false,
            pending: true, // drain pre-existing owned status before enabling
            bits: 0,
            selected: 0,
            deadline: 0,
        })))
    }

    pub(crate) fn activate(&self) -> Result<(), IrqError> {
        let mut s = self.0.lock();
        read(&s.mmio, MASTER)?;
        s.active = true;
        restore_bits(&s.mmio, RENDER_ENABLE, RCS_EVENTS, RCS_EVENTS);
        restore_bits(&s.mmio, RCS_MASK, RCS_EVENTS, 0);
        restore_bits(&s.mmio, GUC_ENABLE, GUC, GUC);
        restore_bits(&s.mmio, GUC_MASK, GUC, 0);
        restore_bits(&s.mmio, RING_MASK, RCS, 0);
        for (offset, mask, expected) in [
            (RENDER_ENABLE, RCS_EVENTS, RCS_EVENTS),
            (RCS_MASK, RCS_EVENTS, 0),
            (GUC_ENABLE, GUC, GUC),
            (GUC_MASK, GUC, 0),
            (RING_MASK, RCS, 0),
        ] {
            if s.mmio.read32(offset) & mask != expected {
                return Err(IrqError::Route);
            }
        }
        // service() drains stale causes before opening the tile master.
        read(&s.mmio, MASTER).map(|_| ())
    }

    pub(crate) fn hard_irq(&self) -> narf_interrupts::dispatch::IrqStatus {
        let mut s = self.0.lock();
        if !s.active {
            return narf_interrupts::dispatch::IrqStatus::None;
        }
        s.mmio.write32(TILE, 0);
        let _ = s.mmio.read32(TILE); // posted mask before EOI
        s.pending = true;
        narf_interrupts::dispatch::IrqStatus::Handled
    }

    /// One bounded decoder step. An identity may take time to become valid;
    /// callers sleep between steps, with the tile master still masked.
    /// Ok(true) requests a short timer retry; Ok(false) is fully rearmed.
    pub(crate) fn service(&self, now: u64) -> Result<bool, IrqError> {
        let mut s = self.0.lock();
        if !s.active {
            return Ok(false);
        }
        if !s.pending {
            // The watchdog also drains a lost MSI edge. Mask before inspecting
            // the hierarchy, exactly as the hard handler would have done.
            s.mmio.write32(TILE, 0);
            let _ = read(&s.mmio, TILE)?;
            s.pending = true;
        }
        if s.selected != 0 {
            let identity = read(&s.mmio, IDENTITY)?;
            if identity & ENABLE == 0 {
                return if now >= s.deadline {
                    Err(IrqError::Timeout)
                } else {
                    Ok(true)
                };
            }
            let expected = if s.selected == 1 { RCS } else { 0x8000 };
            let class = if s.selected == 1 { 0 } else { 4 };
            if (identity >> 20) & 0x3f != 0
                || (identity >> 16) & 7 != class
                || identity & 0xffff == 0
                || identity & 0xffff & !expected != 0
            {
                return Err(IrqError::Identity);
            }
            // Identity acknowledgement must precede the bank acknowledgement.
            s.mmio.write32(IDENTITY, identity);
            s.mmio.write32(DW, s.selected);
            s.bits &= !s.selected;
            s.selected = 0;
        }
        if s.bits == 0 {
            let tile = read(&s.mmio, TILE)?;
            let master = read(&s.mmio, MASTER)?;
            if tile & !(ENABLE | 1) != 0 || master & !(ENABLE | 1) != 0 {
                return Err(IrqError::Conflict);
            }
            if tile & 1 != 0 {
                s.mmio.write32(TILE, 1);
            }
            if master & 1 != 0 {
                let bits = read(&s.mmio, DW)?;
                if bits & !OWNED != 0 {
                    return Err(IrqError::Conflict);
                }
                // GFX master is RW1C status plus its persistent enable bit.
                s.mmio.write32(MASTER, ENABLE | 1);
                s.bits = bits;
            }
        }
        if s.bits != 0 {
            s.selected = 1 << s.bits.trailing_zeros();
            s.deadline = now.checked_add(100_000).ok_or(IrqError::Timeout)?;
            s.mmio.write32(SELECTOR, s.selected);
            return Ok(true);
        }
        // Lower status is quiet; enabling the master generates a fresh edge
        // for any cause arriving between the final read and this write.
        s.mmio.write32(MASTER, ENABLE);
        s.mmio.write32(TILE, ENABLE);
        if read(&s.mmio, TILE)? & ENABLE == 0 || read(&s.mmio, MASTER)? & ENABLE == 0 {
            return Err(IrqError::Route);
        }
        s.pending = false;
        Ok(false)
    }

    pub(crate) fn quiesce(&self) -> bool {
        let mut s = self.0.lock();
        if !s.active {
            return true;
        }
        s.mmio.write32(TILE, 0);
        let quiet = read(&s.mmio, TILE).is_ok_and(|value| value & ENABLE == 0);
        s.active = false;
        // Restore only our source bits. The media GuC shares ENABLE but owns
        // its separate mask half; all unrelated masks/status stay untouched.
        for (offset, mask, saved) in [
            (RING_MASK, RCS, s.saved.ring),
            (RCS_MASK, RCS_EVENTS, s.saved.rcs),
            (RENDER_ENABLE, RCS_EVENTS, s.saved.render),
            (GUC_MASK, GUC, s.saved.guc_mask),
        ] {
            restore_bits(&s.mmio, offset, mask, saved);
        }
        // The primary/media GuCs share this enable bit. An independently
        // unmasked media GuC still needs it, even if it was clear at takeover.
        if s.mmio.read32(GUC_MASK) & (1 << 15) != 0 {
            restore_bits(&s.mmio, GUC_ENABLE, GUC, s.saved.guc_enable);
        }
        s.mmio.write32(MASTER, s.saved.master);
        let _ = s.mmio.read32(MASTER);
        quiet
    }
}

pub(crate) trait MessageRoute {
    fn program(&mut self, vector: u8) -> Result<(), IrqError>;
    fn enable(&mut self) -> Result<(), IrqError>;
    fn disable(&mut self) -> bool;
}

/// Owns handler lifetime and routing together. All failure paths mask device
/// causes, disable PCI delivery, synchronize, and only then release the cookie.
pub(crate) struct Delivery<M: MmioWindow + Send + 'static, R: MessageRoute> {
    controller: Arc<Controller<M>>,
    route: Option<R>,
    vector: u8,
}

fn handler<M: MmioWindow + Send + 'static>(cookie: u64) -> narf_interrupts::dispatch::IrqStatus {
    // SAFETY: Delivery retains the Arc until after remove + synchronize_irq.
    unsafe { &*(cookie as *const Controller<M>) }.hard_irq()
}

impl<M: MmioWindow + Send + 'static, R: MessageRoute> Delivery<M, R> {
    fn install(mmio: M, mut route: R) -> Result<Self, IrqError> {
        let controller = Arc::new(Controller::new(mmio)?);
        let vector = narf_interrupts::vector::alloc().map_err(|_| IrqError::Route)?;
        if let Err(error) = route.program(vector) {
            if route.disable() {
                let _ = narf_interrupts::vector::free(vector);
            } else {
                core::mem::forget(route); // uncertain PCI delivery keeps its vector
            }
            return Err(error);
        }
        narf_interrupts::dispatch::install_handler_named(
            vector,
            "intel-gt",
            Arc::as_ptr(&controller) as u64,
            handler::<M>,
        );
        let delivery = Self {
            controller,
            route: Some(route),
            vector,
        };
        let mut delivery = delivery;
        delivery.route.as_mut().expect("owned route").enable()?;
        delivery.controller.activate()?;
        Ok(delivery)
    }

    pub(crate) fn vector(&self) -> u8 {
        self.vector
    }

    pub(crate) fn service(&self, now: u64) -> Result<bool, IrqError> {
        self.controller.service(now)
    }
}

impl<M: MmioWindow + Send + 'static, R: MessageRoute> Drop for Delivery<M, R> {
    fn drop(&mut self) {
        let device_quiet = self.controller.quiesce();
        let route_quiet = self.route.as_mut().expect("owned route").disable();
        narf_interrupts::dispatch::disable_irq(self.vector);
        if !device_quiet || !route_quiet {
            // Revocation/removal can make it impossible to prove MSI stopped.
            // Keep the vector, cookie, BAR authority and route together. A
            // later device message must never reach another driver's vector.
            core::mem::forget(self.controller.clone());
            core::mem::forget(self.route.take());
            return;
        }
        narf_interrupts::dispatch::remove_handler(
            self.vector,
            "intel-gt",
            Arc::as_ptr(&self.controller) as u64,
        );
        narf_interrupts::dispatch::synchronize_irq(self.vector);
        let _ = narf_interrupts::vector::free(self.vector);
    }
}

pub(crate) type GtIrq = Delivery<crate::intel_gpu_gt_hw::AuthorizedWindow, PciMsi>;

pub(crate) struct PciMsi {
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    device: narf_bus::BusDevice,
    config: narf_bus::msi::MsiConfig,
    mask: Option<(u16, u32)>,
    control: (u16, u32),
    programmed: bool,
}

struct PciAction<F>(F);
impl<T, F> narf_capabilities::CapOp<narf_bus::BusDeviceCap, narf_capabilities::Write>
    for PciAction<F>
where
    F: FnOnce() -> T,
{
    type Output = T;
    fn execute(
        self,
        _: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    ) -> Result<T, narf_capabilities::CapError> {
        Ok((self.0)())
    }
}

impl PciMsi {
    fn new(
        cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        device: narf_bus::BusDevice,
    ) -> Result<Self, IrqError> {
        cap.invoke(PciAction(|| {
            if narf_bus::vmd_domain::domain_for_device(&device).is_some() {
                return Err(IrqError::Conflict); // requires the VMD shared-route owner
            }
            let mut control = None;
            for id in [narf_bus::pci_cap::id::MSI, narf_bus::pci_cap::id::MSI_X] {
                // SAFETY: exclusive live physical PCI function, inside invoke.
                if let Some(offset) = unsafe { narf_bus::pci_cap::find_cap(&device, id) }
                    .map_err(|_| IrqError::Route)?
                {
                    let word = narf_bus::pci::read_config32(&cap, &device, offset as u16)
                        .map_err(|_| IrqError::Route)?;
                    let enabled = if id == narf_bus::pci_cap::id::MSI {
                        1 << 16
                    } else {
                        1 << 31
                    };
                    if word == u32::MAX || word & enabled != 0 {
                        return Err(IrqError::Conflict);
                    }
                    if id == narf_bus::pci_cap::id::MSI {
                        control = Some((offset as u16, word));
                    }
                }
            }
            let control = control.ok_or(IrqError::Route)?;
            let config =
                narf_bus::msi::enable_msi(&cap, &device, 1).map_err(|_| IrqError::Route)?;
            let end = control.0
                + if config.is_64bit() { 16 } else { 12 }
                + if config.per_vector_mask() { 8 } else { 0 };
            if end > 0x100 {
                return Err(IrqError::Route);
            }
            let mask = if config.per_vector_mask() {
                let offset = control.0 + if config.is_64bit() { 16 } else { 12 };
                let value = narf_bus::pci::read_config32(&cap, &device, offset)
                    .map_err(|_| IrqError::Route)?;
                Some((offset, value))
            } else {
                None
            };
            Ok(Self {
                cap,
                device,
                config,
                mask,
                control,
                programmed: false,
            })
        }))
        .map_err(|_| IrqError::Unavailable)?
    }
}

impl MessageRoute for PciMsi {
    fn program(&mut self, vector: u8) -> Result<(), IrqError> {
        self.cap
            .invoke(PciAction(|| {
                self.programmed = true;
                if let Some((offset, value)) = self.mask {
                    narf_bus::pci::write_config32(&self.cap, &self.device, offset, value | 1)
                        .map_err(|_| IrqError::Route)?;
                }
                // SAFETY: Late task, APIC initialized; target this online CPU.
                #[cfg(target_arch = "x86_64")]
                let target = unsafe { narf_interrupts::x86_64::apic::apic_id() };
                #[cfg(not(target_arch = "x86_64"))]
                let target = 0;
                if target > 255 {
                    return Err(IrqError::Route); // basic MSI cannot encode x2APIC IDs >255
                }
                // SAFETY: exclusive PCI owner, disabled MSI, current authority.
                unsafe { narf_bus::msi::program_msi(&mut self.config, target, vector) }
                    .map_err(|_| IrqError::Route)?;
                Ok(())
            }))
            .map_err(|_| IrqError::Unavailable)?
    }
    fn enable(&mut self) -> Result<(), IrqError> {
        self.cap
            .invoke(PciAction(|| {
                // SAFETY: programmed vector + handler retained by Delivery.
                unsafe { narf_bus::msi::enable(&self.config) }.map_err(|_| IrqError::Route)?;
                if let Some((offset, value)) = self.mask {
                    narf_bus::pci::write_config32(&self.cap, &self.device, offset, value & !1)
                        .map_err(|_| IrqError::Route)?;
                    if narf_bus::pci::read_config32(&self.cap, &self.device, offset)
                        .map_err(|_| IrqError::Route)?
                        & 1
                        != 0
                    {
                        return Err(IrqError::Route);
                    }
                }
                let control = narf_bus::pci::read_config32(&self.cap, &self.device, self.control.0)
                    .map_err(|_| IrqError::Route)?;
                if control == u32::MAX || control & 0x00710000 != 0x00010000 {
                    return Err(IrqError::Route);
                }
                Ok(())
            }))
            .map_err(|_| IrqError::Unavailable)?
    }
    fn disable(&mut self) -> bool {
        if !self.programmed {
            return true;
        }
        self.cap
            .invoke(PciAction(|| {
                // SAFETY: device sources masked; vector and handler still retained.
                let _ = unsafe { narf_bus::msi::disable(&self.config) };
                if !narf_bus::pci::read_config32(&self.cap, &self.device, self.control.0)
                    .is_ok_and(|value| value != u32::MAX && value & (1 << 16) == 0)
                {
                    return false;
                }
                if let Some((offset, value)) = self.mask {
                    let _ = narf_bus::pci::write_config32(&self.cap, &self.device, offset, value);
                }
                let _ = narf_bus::pci::write_config32(
                    &self.cap,
                    &self.device,
                    self.control.0,
                    self.control.1,
                );
                true
            }))
            .unwrap_or(false)
    }
}

impl GtIrq {
    pub(crate) fn for_device(
        mmio: crate::intel_gpu_gt_hw::AuthorizedWindow,
        cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        device: narf_bus::BusDevice,
    ) -> Result<Self, IrqError> {
        // The GT's production DMA path currently admits coherent x86 only.
        // Do not program ARM MSI without an ITS DeviceID/event owner.
        if !cfg!(target_arch = "x86_64") {
            return Err(IrqError::Route);
        }
        Self::install(mmio, PciMsi::new(cap, device)?)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_gt_irq_tests.rs"]
mod tests;
