//! DCN3.0 double-buffered page flip, scanout position and display interrupt
//! enables of one live pipe. Offsets and fields are `dcn_3_0_0_offset.h` /
//! `dcn_3_0_0_sh_mask.h` at DCN base index 2 (HUBPREQ stride 0xdc, OTG stride
//! 0x80). Linux:
//!
//! - `hubp3_program_surface_flip_and_addr`: VSYNC flip type (latched at the
//!   OTG's VUPDATE), VMID, stereo off, TMZ off, then the high address and
//!   the low address last: writing the low half arms the flip.
//! - `hubp2_is_flip_pending`: a flip is pending while SURFACE_FLIP_PENDING is
//!   set or SURFACE_EARLIEST_INUSE still names another surface. Once it names
//!   the new one, no fetch of the old surface remains outstanding.
//! - `irq_service_dcn30.c`: HUBPn pflip (DCSURF_SURFACE_FLIP_INTERRUPT
//!   SURFACE_FLIP_INT_MASK / SURFACE_FLIP_CLEAR), OTGn VUPDATE_NO_LOCK and
//!   VSTARTUP (OTG_GLOBAL_SYNC_STATUS *_INT_EN / *_EVENT_CLEAR), set and acked
//!   by `dal_irq_service_set_generic` / `dal_irq_service_ack_generic`.
//! - `optc1_get_position` / `optc1_get_vblank_counter`: OTG_STATUS_POSITION
//!   and the 24-bit OTG_STATUS_FRAME_COUNT, sampled until the frame count is
//!   stable across the position read (as amdgpu_get_vblank_counter_kms).
//!
//! The owner of this block is the pipeline that programmed the surface:
//! these registers belong to the same HUBP/OTG instance and are only ever
//! written by one task under the display owner's lock.
use crate::{amdgpu::AmdGpu, amdgpu_dcn_clk::Error, amdgpu_dcn_profile::Profile};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

// linux-ctx: hdr=dcn seg=2
// HUBPREQ instance block, stride 0xdc.
pub(crate) const VMID_SETTINGS_0: u64 = 0x0609; // linux: mmHUBPREQ0_VMID_SETTINGS_0
                                                // linux: mmHUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS
pub(crate) const PRIMARY_SURFACE_ADDRESS: u64 = 0x060a;
// linux: mmHUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH
pub(crate) const PRIMARY_SURFACE_ADDRESS_HIGH: u64 = 0x060b;
pub(crate) const SURFACE_CONTROL: u64 = 0x061a; // linux: mmHUBPREQ0_DCSURF_SURFACE_CONTROL
pub(crate) const FLIP_CONTROL: u64 = 0x061b; // linux: mmHUBPREQ0_DCSURF_FLIP_CONTROL
pub(crate) const FLIP_INTERRUPT: u64 = 0x0620; // linux: mmHUBPREQ0_DCSURF_SURFACE_FLIP_INTERRUPT
pub(crate) const EARLIEST_INUSE: u64 = 0x0625; // linux: mmHUBPREQ0_DCSURF_SURFACE_EARLIEST_INUSE
                                               // linux: mmHUBPREQ0_DCSURF_SURFACE_EARLIEST_INUSE_HIGH
pub(crate) const EARLIEST_INUSE_HIGH: u64 = 0x0626;
// linux: mmHUBPREQ1_DCSURF_PRIMARY_SURFACE_ADDRESS - mmHUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS
pub(crate) const HUBP_STRIDE: u64 = 0xdc;
// OTG instance block, stride 0x80.
pub(crate) const OTG_V_BLANK_START_END: u64 = 0x1b36; // linux: mmOTG0_OTG_V_BLANK_START_END
pub(crate) const OTG_STATUS_POSITION: u64 = 0x1b4a; // linux: mmOTG0_OTG_STATUS_POSITION
pub(crate) const OTG_STATUS_FRAME_COUNT: u64 = 0x1b4c; // linux: mmOTG0_OTG_STATUS_FRAME_COUNT
pub(crate) const OTG_GLOBAL_SYNC_STATUS: u64 = 0x1b8a; // linux: mmOTG0_OTG_GLOBAL_SYNC_STATUS
pub(crate) const OTG_STRIDE: u64 = 0x80; // linux: mmOTG1_OTG_CONTROL - mmOTG0_OTG_CONTROL
#[cfg(feature = "kernel-test")]
// linux: n/a (NARF test bound)
pub(crate) const LAST_REG: u64 = OTG_GLOBAL_SYNC_STATUS + 5 * OTG_STRIDE;
// linux-ctx: reset

const VMID_MASK: u32 = 0xf; // linux: HUBPREQ0_VMID_SETTINGS_0__VMID_MASK
                            // linux: HUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH__PRIMARY_SURFACE_ADDRESS_HIGH_MASK
const ADDRESS_HIGH_MASK: u32 = 0xffff;
/// PRIMARY_SURFACE_TMZ | PRIMARY_META_SURFACE_TMZ.
// linux: HUBPREQ0_DCSURF_SURFACE_CONTROL__PRIMARY_SURFACE_TMZ_MASK | HUBPREQ0_DCSURF_SURFACE_CONTROL__PRIMARY_META_SURFACE_TMZ_MASK
const TMZ: u32 = 0x0001_0001;
const FLIP_TYPE: u32 = 1 << 1; // linux: HUBPREQ0_DCSURF_FLIP_CONTROL__SURFACE_FLIP_TYPE_MASK
const FLIP_PENDING: u32 = 1 << 8; // linux: HUBPREQ0_DCSURF_FLIP_CONTROL__SURFACE_FLIP_PENDING_MASK
/// SURFACE_FLIP_MODE_FOR_STEREOSYNC | SURFACE_FLIP_IN_STEREOSYNC.
// linux: HUBPREQ0_DCSURF_FLIP_CONTROL__SURFACE_FLIP_MODE_FOR_STEREOSYNC_MASK | HUBPREQ0_DCSURF_FLIP_CONTROL__SURFACE_FLIP_IN_STEREOSYNC_MASK
const STEREO: u32 = 0x0000_3000 | 0x0001_0000;
// linux: HUBPREQ0_DCSURF_SURFACE_FLIP_INTERRUPT__SURFACE_FLIP_INT_MASK_MASK
const FLIP_INT_MASK: u32 = 1 << 0;
// linux: HUBPREQ0_DCSURF_SURFACE_FLIP_INTERRUPT__SURFACE_FLIP_CLEAR_MASK
const FLIP_CLEAR: u32 = 1 << 8;
const VSTARTUP_INT_EN: u32 = 1 << 0; // linux: OTG0_OTG_GLOBAL_SYNC_STATUS__VSTARTUP_INT_EN_MASK
                                     // linux: OTG0_OTG_GLOBAL_SYNC_STATUS__VSTARTUP_EVENT_CLEAR_MASK
const VSTARTUP_EVENT_CLEAR: u32 = 1 << 4;
// linux: OTG0_OTG_GLOBAL_SYNC_STATUS__VUPDATE_NO_LOCK_INT_EN_MASK
const VUPDATE_NO_LOCK_INT_EN: u32 = 1 << 12;
// linux: OTG0_OTG_GLOBAL_SYNC_STATUS__VUPDATE_NO_LOCK_EVENT_CLEAR_MASK
const VUPDATE_NO_LOCK_EVENT_CLEAR: u32 = 1 << 16;
const COUNT_MASK: u32 = 0x7fff; // linux: OTG0_OTG_STATUS_POSITION__OTG_VERT_COUNT_MASK
                                // linux: OTG0_OTG_STATUS_FRAME_COUNT__OTG_FRAME_COUNT_MASK
pub(crate) const FRAME_MASK: u32 = 0x00ff_ffff;
/// HUBP surface addresses are 48-bit and start on a 256-byte request.
const ADDRESS_BITS: u32 = 48; // linux: n/a (48-bit HUBP surface address space)
const ADDRESS_ALIGN: u64 = 256; // linux: n/a (NARF validation: 256-byte request alignment)

pub(crate) trait Io: Send {
    fn read(&mut self, reg: u64) -> u32;
    fn write(&mut self, reg: u64, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    base: u64,
}
impl Io for Mmio {
    fn read(&mut self, reg: u64) -> u32 {
        // SAFETY: the constructor bounded the DCN bank for every pipe.
        unsafe { self.regs.read32(self.base + reg * 4) }
    }
    fn write(&mut self, reg: u64, value: u32) {
        // SAFETY: same bounded bank; the pipe's owner serializes writers.
        unsafe { self.regs.write32(self.base + reg * 4, value) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}

/// One display interrupt of a pipe, as `irq_service_dcn30` names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interrupt {
    /// DC_IRQ_SOURCE_PFLIPn: the HUBP accepted a flip.
    Flip,
    /// DC_IRQ_SOURCE_VUPDATEn (VUPDATE_NO_LOCK): double-buffered latch.
    Vupdate,
    /// DC_IRQ_SOURCE_VBLANKn (VSTARTUP), amdgpu_dm's vblank on DCN.
    Vblank,
}

/// A raw scanout position read: the frame count, the beam and the vertical
/// blank the OTG is programmed with (`vblank_start` through the wrap to
/// `vblank_end`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub frame: u32,
    pub vpos: u32,
    pub hpos: u32,
    pub vblank_start: u32,
    pub vblank_end: u32,
}

#[derive(Debug)]
pub(crate) struct Engine<I: Io> {
    pub(crate) io: I,
    pub(crate) authority: Cap<BusDeviceCap, Write>,
    pub(crate) pipe: u8,
    /// The surface the last flip requested (`hubp->request_address`).
    pub(crate) requested: Option<u64>,
}
impl<I: Io> Engine<I> {
    fn hubp(&self, reg: u64) -> u64 {
        reg + u64::from(self.pipe) * HUBP_STRIDE
    }
    fn otg(&self, reg: u64) -> u64 {
        reg + u64::from(self.pipe) * OTG_STRIDE
    }
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    fn read(&mut self, reg: u64) -> Result<u32, Error> {
        let value = self.access(|io| io.read(reg))?;
        if value == u32::MAX {
            return Err(Error::DeviceGone);
        }
        Ok(value)
    }
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.read(reg)?;
        self.access(|io| io.write(reg, (old & !mask) | (value & mask)))
    }
    /// `hubp3_program_surface_flip_and_addr` for a graphics surface with no
    /// meta and no TMZ, flipped at VSYNC (VUPDATE) rather than immediately.
    pub(crate) fn program_flip(&mut self, address: u64) -> Result<(), Error> {
        if address == 0 || address >= 1 << ADDRESS_BITS || address % ADDRESS_ALIGN != 0 {
            return Err(Error::Invalid);
        }
        let flip = self.hubp(FLIP_CONTROL);
        self.update(flip, FLIP_TYPE, 0)?;
        self.update(self.hubp(VMID_SETTINGS_0), VMID_MASK, 0)?;
        self.update(flip, STEREO, 0)?;
        self.update(self.hubp(SURFACE_CONTROL), TMZ, 0)?;
        let high = self.hubp(PRIMARY_SURFACE_ADDRESS_HIGH);
        let low = self.hubp(PRIMARY_SURFACE_ADDRESS);
        self.access(|io| {
            io.write(high, (address >> 32) as u32 & ADDRESS_HIGH_MASK);
            // The low half last: it latches the high half and arms the flip.
            io.write(low, address as u32);
        })?;
        self.requested = Some(address);
        Ok(())
    }
    /// `hubp2_is_flip_pending` against the last requested surface.
    pub(crate) fn pending(&mut self) -> Result<bool, Error> {
        let requested = self.requested.ok_or(Error::Invalid)?;
        if self.read(self.hubp(FLIP_CONTROL))? & FLIP_PENDING != 0 {
            return Ok(true);
        }
        Ok(self.in_use()? != requested)
    }
    /// SURFACE_EARLIEST_INUSE: the oldest surface fetch still references.
    pub(crate) fn in_use(&mut self) -> Result<u64, Error> {
        let low = self.read(self.hubp(EARLIEST_INUSE))?;
        let high = self.read(self.hubp(EARLIEST_INUSE_HIGH))? & ADDRESS_HIGH_MASK;
        Ok(u64::from(high) << 32 | u64::from(low))
    }
    /// Adopt the surface the pipeline programmed at activation.
    pub(crate) fn adopt(&mut self, address: u64) {
        self.requested = Some(address);
    }
    fn interrupt(&self, which: Interrupt) -> (u64, u32, u32) {
        match which {
            Interrupt::Flip => (self.hubp(FLIP_INTERRUPT), FLIP_INT_MASK, FLIP_CLEAR),
            Interrupt::Vupdate => (
                self.otg(OTG_GLOBAL_SYNC_STATUS),
                VUPDATE_NO_LOCK_INT_EN,
                VUPDATE_NO_LOCK_EVENT_CLEAR,
            ),
            Interrupt::Vblank => (
                self.otg(OTG_GLOBAL_SYNC_STATUS),
                VSTARTUP_INT_EN,
                VSTARTUP_EVENT_CLEAR,
            ),
        }
    }
    /// `dal_irq_service_set_generic`: only the source's enable bit changes.
    /// The global-sync register's clear bits are written as zero so that an
    /// enable never acknowledges another source's pending event.
    pub(crate) fn set_interrupt(&mut self, which: Interrupt, enable: bool) -> Result<(), Error> {
        let (reg, en, _) = self.interrupt(which);
        let clears = if which == Interrupt::Flip {
            FLIP_CLEAR
        } else {
            VSTARTUP_EVENT_CLEAR | VUPDATE_NO_LOCK_EVENT_CLEAR
        };
        let old = self.read(reg)? & !clears;
        let value = if enable { old | en } else { old & !en };
        self.access(|io| io.write(reg, value))
    }
    /// `dal_irq_service_ack_generic`: write the source's clear bit.
    pub(crate) fn ack(&mut self, which: Interrupt) -> Result<(), Error> {
        let (reg, _, clear) = self.interrupt(which);
        let others = if which == Interrupt::Flip {
            0
        } else {
            (VSTARTUP_EVENT_CLEAR | VUPDATE_NO_LOCK_EVENT_CLEAR) & !clear
        };
        let old = self.read(reg)? & !others;
        self.access(|io| io.write(reg, old | clear))
    }
    /// One position sample whose frame count did not change across the
    /// position read (at most four tries, as a line wrap cannot repeat).
    pub(crate) fn position(&mut self) -> Result<Position, Error> {
        let blank = self.read(self.otg(OTG_V_BLANK_START_END))?;
        for _ in 0..4 {
            let before = self.read(self.otg(OTG_STATUS_FRAME_COUNT))? & FRAME_MASK;
            let position = self.read(self.otg(OTG_STATUS_POSITION))?;
            let after = self.read(self.otg(OTG_STATUS_FRAME_COUNT))? & FRAME_MASK;
            if before == after {
                return Ok(Position {
                    frame: after,
                    vpos: position & COUNT_MASK,
                    // linux-lit: 16=OTG0_OTG_STATUS_POSITION__OTG_HORZ_COUNT__SHIFT
                    hpos: position >> 16 & COUNT_MASK,
                    vblank_start: blank & COUNT_MASK,
                    // linux-lit: 16=OTG0_OTG_V_BLANK_START_END__OTG_V_BLANK_END__SHIFT
                    vblank_end: blank >> 16 & COUNT_MASK,
                });
            }
        }
        Err(Error::Busy)
    }
}

/// A flip-complete wake, normally the pipe's IH pflip/vupdate subscription.
/// The wait still checks the latch bits itself: a lost or late interrupt
/// only costs the poll interval, never the result.
pub trait Wake {
    /// Wait at most `us` microseconds for the next event.
    fn wait(&mut self, us: u64) -> impl core::future::Future<Output = ()> + Send;
}
/// Poll at the given interval when no interrupt is available.
#[derive(Debug)]
pub struct Poll;
impl Wake for Poll {
    async fn wait(&mut self, us: u64) {
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
    }
}

/// Poll period between latch reads while waiting for a flip.
pub const POLL_US: u64 = 500; // linux: n/a (NARF poll period)

impl<I: Io> Engine<I> {
    /// Wait until the requested surface is the earliest one in use, for at
    /// most `timeout_us`. A timeout leaves the flip programmed: which buffer
    /// the HUBP still fetches is then unknown, and the caller must retain
    /// both.
    pub(crate) async fn wait_flip(
        &mut self,
        timeout_us: u64,
        wake: &mut impl Wake,
    ) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_us(timeout_us);
        loop {
            if !self.pending()? {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            wake.wait(POLL_US).await;
        }
    }
}

/// The flip/position/interrupt registers of one owned DCN3.0 pipe.
#[derive(Debug)]
pub struct Flip(Engine<Mmio>);
impl Flip {
    /// # Safety
    /// The caller owns `pipe`'s HUBP and OTG (the pipeline that programmed
    /// them) and serializes every access with that owner; permanent mapping
    /// and matching PCI authority.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pipe: u8,
    ) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu)?;
        if profile != Profile::Navi22 || pipe >= profile.pipes() {
            return Err(Error::Unsupported);
        }
        let last = OTG_GLOBAL_SYNC_STATUS + u64::from(profile.pipes() - 1) * OTG_STRIDE;
        let base = profile.bank(gpu, 2, last as u32)?;
        Ok(Self(Engine {
            io: Mmio {
                regs: gpu.regs,
                base,
            },
            authority,
            pipe,
            requested: None,
        }))
    }
    pub fn pipe(&self) -> u8 {
        self.0.pipe
    }
    /// The surface the activation programmed; flips compare against it.
    pub fn adopt(&mut self, address: u64) {
        self.0.adopt(address);
    }
    /// Arm a VSYNC flip to `address`; `wait` observes it latch.
    pub fn program(&mut self, address: u64) -> Result<(), Error> {
        self.0.program_flip(address)
    }
    pub fn pending(&mut self) -> Result<bool, Error> {
        self.0.pending()
    }
    pub fn in_use(&mut self) -> Result<u64, Error> {
        self.0.in_use()
    }
    pub async fn wait(&mut self, timeout_us: u64, wake: &mut impl Wake) -> Result<(), Error> {
        self.0.wait_flip(timeout_us, wake).await
    }
    pub fn set_interrupt(&mut self, which: Interrupt, enable: bool) -> Result<(), Error> {
        self.0.set_interrupt(which, enable)
    }
    pub fn ack(&mut self, which: Interrupt) -> Result<(), Error> {
        self.0.ack(which)
    }
    pub fn position(&mut self) -> Result<Position, Error> {
        self.0.position()
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn30_flip_tests.rs"]
mod tests;
