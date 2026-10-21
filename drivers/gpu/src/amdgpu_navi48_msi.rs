//! One retained, checked PCI MSI route for native Navi48 IH7. The PCI MSI
//! layout follows bus::msi; NBIO controls follow nbio_v7_7/nbif_v6_3_1.c.
use crate::{amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_ih7 as ih, amdgpu_psp_ring::bank};
use core::sync::atomic::{compiler_fence, Ordering};
use narf_bus::{BusDevice, BusDeviceCap, BusKind, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Revoked,
    DeviceGone,
    Readback,
    Exhausted,
    Interrupts(ih::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Programming,
    Enabled,
    Disabled,
    Failed(Error),
}
trait Io {
    fn cfg16(&mut self, at: u64) -> u16;
    fn cfg32(&mut self, at: u64) -> u32;
    fn write16(&mut self, at: u64, v: u16);
    fn write32(&mut self, at: u64, v: u32);
    fn reg_read(&mut self, at: u64) -> u32;
    fn reg_write(&mut self, at: u64, v: u32);
}
#[derive(Debug)]
struct Mmio {
    config: u64,
    regs: MmioRegion,
}
impl Io for Mmio {
    fn cfg16(&mut self, at: u64) -> u16 {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: mapped PCI function; exact MSI structure/command bounds and
        // alignment checked by construction, under live Cap::invoke.
        let v = unsafe { core::ptr::read_volatile((self.config + at) as *const u16) };
        compiler_fence(Ordering::SeqCst);
        v
    }
    fn cfg32(&mut self, at: u64) -> u32 {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same checked aligned config window and authority.
        let v = unsafe { core::ptr::read_volatile((self.config + at) as *const u32) };
        compiler_fence(Ordering::SeqCst);
        v
    }
    fn write16(&mut self, at: u64, v: u16) {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same bounds; 16-bit Command writes never touch W1C Status.
        unsafe { core::ptr::write_volatile((self.config + at) as *mut u16, v) };
        compiler_fence(Ordering::SeqCst);
    }
    fn write32(&mut self, at: u64, v: u32) {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: exact MSI address/mask fields, exclusive retained PCI owner.
        unsafe { core::ptr::write_volatile((self.config + at) as *mut u32, v) };
        compiler_fence(Ordering::SeqCst);
    }
    fn reg_read(&mut self, at: u64) -> u32 {
        // SAFETY: exact NBIO discovery bank and current capability invocation.
        unsafe { self.regs.read32(at) }
    }
    fn reg_write(&mut self, at: u64, v: u32) {
        // SAFETY: same bounded permanent mapping and exclusive ownership.
        unsafe { self.regs.write32(at, v) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    /// Config dword 0 the bound function must still read: device << 16 | vendor.
    id: u32,
    msi: u64,
    msix: Option<u64>,
    nbio: u64,
    address64: bool,
    masks: bool,
}
fn check(io: &mut impl Io, l: Layout) -> Result<(), Error> {
    if io.cfg32(0) != l.id {
        return Err(Error::DeviceGone);
    }
    if !(0x40..=0xfc).contains(&l.msi)
        || l.msi & 3 != 0
        || l.msix
            .is_some_and(|at| !(0x40..=0xfc).contains(&at) || at & 3 != 0)
    {
        return Err(Error::Invalid);
    }
    let ctrl = io.cfg16(l.msi + 2);
    if ctrl == u16::MAX {
        return Err(Error::DeviceGone);
    }
    let length = match (l.address64, l.masks) {
        (true, true) => 24,
        (true, false) => 14,
        (false, true) => 20,
        (false, false) => 10,
    };
    let next = u64::from(io.cfg16(l.msi) >> 8);
    if l.msi + length > 256
        || (next > l.msi && next < l.msi + length)
        || l.msix.is_some_and(|at| at >= l.msi && at < l.msi + length)
        || ctrl & 0x80 != if l.address64 { 0x80 } else { 0 }
        || ctrl & 0x100 != if l.masks { 0x100 } else { 0 }
        || (ctrl >> 1) & 7 > 5
        || io.cfg16(l.msi) as u8 != 5
    {
        return Err(Error::Invalid);
    }
    if ctrl & 1 != 0 || l.msix.is_some_and(|at| io.cfg16(at + 2) & 0x8000 != 0) {
        return Err(Error::Busy);
    }
    // The posted GPU already owns memory decoding and bus mastering. Do not
    // silently enable DMA on an unprepared function.
    let command = io.cfg16(4);
    if command == u16::MAX {
        return Err(Error::DeviceGone);
    }
    if command & 6 != 6 {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn write16(io: &mut impl Io, at: u64, value: u16) -> Result<(), Error> {
    io.write16(at, value);
    if io.cfg16(at) != value {
        return Err(Error::Readback);
    }
    Ok(())
}
fn write32(io: &mut impl Io, at: u64, value: u32) -> Result<(), Error> {
    io.write32(at, value);
    if io.cfg32(at) != value {
        return Err(Error::Readback);
    }
    Ok(())
}
/// The one MSI message the function posts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Message {
    address: u64,
    data: u16,
}
/// x86 LAPIC-directed message: fixed delivery, physical destination.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
fn x86_message(vector: u8, apic: u32) -> Result<Message, Error> {
    if !(48..240).contains(&vector) || apic > 255 {
        return Err(Error::Unsupported);
    }
    Ok(Message {
        address: 0xfee00000 | (u64::from(apic) << 12),
        data: u16::from(vector),
    })
}
/// GICv3 ITS message: the function writes its EventID to GITS_TRANSLATER
/// (Linux its_pci_msi_prepare / its_irq_compose_msi_msg).
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
fn its_message(doorbell: u64, event: u32) -> Result<Message, Error> {
    if doorbell == 0 || doorbell & 3 != 0 {
        return Err(Error::Unsupported);
    }
    Ok(Message {
        address: doorbell,
        data: u16::try_from(event).map_err(|_| Error::Unsupported)?,
    })
}
fn program(io: &mut impl Io, l: Layout, msg: Message) -> Result<(), Error> {
    if msg.address & 3 != 0 || (!l.address64 && msg.address >> 32 != 0) {
        return Err(Error::Unsupported);
    }
    check(io, l)?;
    let control = io.cfg16(l.msi + 2) & !0x71; // one message, initially disabled
    write16(io, l.msi + 2, control)?;
    let mask = l.msi + if l.address64 { 16 } else { 12 };
    let prior_mask = if l.masks {
        let v = io.cfg32(mask);
        write32(io, mask, v | 1)?;
        v
    } else {
        0
    };
    write32(io, l.msi + 4, msg.address as u32)?;
    if l.address64 {
        write32(io, l.msi + 8, (msg.address >> 32) as u32)?;
    }
    write16(io, l.msi + if l.address64 { 12 } else { 8 }, msg.data)?;
    let old = io.reg_read(l.nbio);
    if old == u32::MAX {
        return Err(Error::DeviceGone);
    }
    // IH buffers live in VRAM (nonsnoop). Explicitly disable dummy host reads:
    // OVERRIDE=1, EN=0 avoids inventing a host-DMA address for CNTL2.
    let value = (old & !0xb) | 9;
    io.reg_write(l.nbio, value);
    if io.reg_read(l.nbio) != value {
        return Err(Error::Readback);
    }
    let command = io.cfg16(4) | 0x400; // never fall back to an unowned INTx line
    write16(io, 4, command)?;
    if l.masks {
        write32(io, mask, prior_mask & !1)?;
    }
    write16(io, l.msi + 2, control | 1)
}
/// Where this function's MSIs go: the x2APIC ID on x86_64, the ITS
/// DeviceID of this function on aarch64 (RID mapped through IORT / DT
/// msi-map). Side-effect free, so a refusal leaves the route Prepared.
fn target(rid: (u16, u16)) -> Result<u32, Error> {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = rid;
        // SAFETY: native route enable requires initialized CPU interrupt control.
        let id = unsafe { narf_interrupts::x86_64::apic::apic_id() };
        if id <= 255 {
            Ok(id)
        } else {
            Err(Error::Unsupported)
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        use narf_interrupts::aarch64::its;
        if its::status().is_none() {
            return Err(Error::Unsupported);
        }
        its::pci_device_id(rid.0, rid.1).ok_or(Error::Unsupported)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = rid;
        Err(Error::Unsupported)
    }
}
/// Bind `vector` for `target` and build the message to program.
///
/// aarch64: a one-vector ITT for the DeviceID (MAPD), EventID 0 → the
/// vector's LPI (MAPTI + INV + SYNC). Like the handler, the mapping is
/// retained with the vector after failure or disable.
///
/// # Safety
/// `target` came from [`target`] for this exclusively owned function.
unsafe fn bind(vector: u8, target: u32) -> Result<Message, Error> {
    #[cfg(target_arch = "aarch64")]
    {
        use narf_interrupts::aarch64::its;
        // SAFETY: caller contract: this DeviceID is our function's.
        unsafe { its::create_device(target, 1) }.map_err(|_| Error::Unsupported)?;
        // SAFETY: same device; LPI of a vector we own.
        unsafe { its::map_event(target, 0, its::lpi_for_vector(vector), 0) }
            .map_err(|_| Error::Unsupported)?;
        its_message(its::doorbell_pa(), 0)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        x86_message(vector, target)
    }
}
#[derive(Debug)]
pub struct Route {
    io: Mmio,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    state: State,
    vector: Option<u8>,
    /// PCI (segment, requester ID), for the ITS DeviceID.
    rid: (u16, u16),
}
impl Route {
    /// # Safety
    /// Exclusively own this GPU and PCI config/reset/PM. Retain any published
    /// vector and route until independent device quiescence, even after failure.
    /// Preparation performs only bounded reads and allocates no IRQ vector.
    pub unsafe fn new(
        gpu: &AmdGpu,
        pci: &BusDevice,
        authority: Cap<BusDeviceCap, Write>,
    ) -> Result<Self, Error> {
        if crate::amdgpu_rdna4::Rdna4Chip::of(gpu).is_none()
            || pci.id.vendor != gpu.chip.vid
            || pci.id.device != gpu.chip.did
        {
            return Err(Error::Unsupported);
        }
        let BusKind::Pcie { cfg_phys, addr } = pci.kind else {
            return Err(Error::Unsupported);
        };
        let rid = (
            addr.segment,
            u16::from(addr.bus) << 8 | u16::from(addr.device) << 3 | u16::from(addr.function),
        );
        let config = narf_bus::ecam::va_for(cfg_phys).ok_or(Error::Unsupported)?;
        let ip = ip::find_ip(&gpu.ip_blocks, ip::HW_ID_NBIF, 0).ok_or(Error::Unsupported)?;
        let (index, reg) = if ip.major == 6 {
            (2, 0xf1)
        } else {
            (5, 0x8e11)
        };
        let nbio = bank(
            gpu,
            ip::HW_ID_NBIF,
            &[(7, 7, 0), (7, 7, 1), (6, 3, 1)],
            index,
            reg,
        )
        .map_err(|_| Error::Unsupported)?
            + u64::from(reg) * 4;
        let mut io = Mmio {
            config,
            regs: gpu.regs,
        };
        let layout = authority
            .invoke(Op(|| {
                // SAFETY: same mapped physical function under live PCI authority.
                let msi = unsafe { narf_bus::pci_cap::find_cap(pci, 5) }
                    .map_err(|_| Error::Invalid)?
                    .ok_or(Error::Unsupported)?;
                // SAFETY: same bounded capability-list walk, no device writes.
                let msix = unsafe { narf_bus::pci_cap::find_cap(pci, 0x11) }
                    .map_err(|_| Error::Invalid)?;
                let ctrl = io.cfg16(msi + 2);
                let l = Layout {
                    id: u32::from(gpu.chip.did) << 16 | u32::from(gpu.chip.vid),
                    msi,
                    msix,
                    nbio,
                    address64: ctrl & 0x80 != 0,
                    masks: ctrl & 0x100 != 0,
                };
                check(&mut io, l)?;
                Ok(l)
            }))
            .map_err(|_| Error::Revoked)??;
        Ok(Self {
            io,
            authority,
            layout,
            state: State::Prepared,
            vector: None,
            rid,
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn vector(&self) -> Option<u8> {
        (self.state == State::Enabled)
            .then_some(self.vector)
            .flatten()
    }
    /// # Safety
    /// Same GPU's live IH rings; CPU interrupt controller/executor initialized.
    /// Retain a consumer and serialize this route with all IH/reset/PM changes.
    pub unsafe fn enable(&mut self, rings: &mut ih::Rings) -> Result<u8, Error> {
        if self.state != State::Prepared || rings.state() != ih::State::Ready {
            return Err(Error::Busy);
        }
        {
            let target = target(self.rid)?;
            let vector = narf_interrupts::vector::alloc().map_err(|_| Error::Exhausted)?;
            // 0xf0 is also the architecture's fixed TLB-shootdown vector.
            // Never attach a device there even if the generic pool offers it.
            if vector == 0xf0 {
                let _ = narf_interrupts::vector::free(vector);
                return Err(Error::Exhausted);
            }
            self.vector = Some(vector);
            self.state = State::Programming;
            narf_interrupts::install_handler_named(vector, "amdgpu-navi48", 0, |_| {
                narf_interrupts::IrqStatus::Handled
            });
            let io = &mut self.io;
            let l = self.layout;
            let authority = &self.authority;
            // SAFETY: `target` names this exclusively owned function.
            let result = unsafe { bind(vector, target) }
                .and_then(|msg| {
                    authority
                        .invoke(Op(|| program(io, l, msg)))
                        .map_err(|_| Error::Revoked)
                })
                .and_then(|r| r)
                .and_then(|()| {
                    // SAFETY: the named handler is installed and PCI MSI readback
                    // succeeded; caller retains a consumer for these same rings.
                    unsafe { rings.host_interrupts(true) }.map_err(Error::Interrupts)
                });
            self.state = match result {
                Ok(()) => State::Enabled,
                Err(e) => State::Failed(e),
            };
            result.map(|()| vector)
        }
    }
    /// Disable MSI after a fatal drain error. Retain the vector/handler so an
    /// already posted interrupt cannot reach another device's recycled vector.
    pub(crate) fn disable(&mut self) -> Result<(), Error> {
        if let Some(vector) = self.vector {
            narf_interrupts::disable_irq(vector);
        }
        let io = &mut self.io;
        let l = self.layout;
        let result = self
            .authority
            .invoke(Op(|| {
                let ctrl = io.cfg16(l.msi + 2);
                if ctrl == u16::MAX {
                    return Err(Error::DeviceGone);
                }
                write16(io, l.msi + 2, ctrl & !1)
            }))
            .map_err(|_| Error::Revoked)
            .and_then(|r| r);
        self.state = match result {
            Ok(()) => State::Disabled,
            Err(e) => State::Failed(e),
        };
        result
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_msi_tests.rs"]
mod tests;
