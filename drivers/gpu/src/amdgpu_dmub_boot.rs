//! DCN 2.1 / 3.1.4 direct-load lifecycle, following Linux
//! dmub_dcn20.c/dmub_dcn31.c/dmub_srv.c.
//!
//! This is the explicitly selected direct-load method, not a PSP fallback.
//! The caller supplies a pool of known-free VRAM and a validated VBIOS image.
//! No unowned BAR space is guessed to be free. Platform boot wiring and the
//! PSP load method are separate from this lifecycle.
use super::{
    amdgpu::AmdGpu,
    amdgpu_dmub::{self, Channel, Dmub, Regs},
    amdgpu_dmub_firmware::{Layout, Placement, Prepared, Window, RING_SIZE},
    amdgpu_usbc::{claim_loader, LoaderOwnership},
    amdgpu_vram::{Pool, Reservation},
};
use alloc::vec::Vec;
use core::{
    future::Future,
    sync::atomic::{fence, Ordering},
    task::Poll,
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// Generation-independent DMCUB field values (`dcn_2_1_0_sh_mask.h` and
/// `dcn_3_1_4_sh_mask.h` agree on all of these). The register offsets
/// live in [`Regs`].
const ENABLE: u32 = 1 << 16;
const SOFT_RESET: u32 = 1 << 17;
const HUB_RESET_BIT: u32 = 1 << 8;
const STOP: u32 = (1 << 28) | (2 << 16);
const WINDOW_ENABLE: u32 = 1 << 31;
const ADDRESS_MASK: u32 = 0x1fff_ffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    StopTimeout,
    UploadFailed,
    ConfigurationFailed,
    BootTimeout,
    Transport(amdgpu_dmub::Error),
    Memory(crate::amdgpu_vram_boot::Error),
    Firmware(amdgpu_dmub::FirmwareError),
    Psp(crate::amdgpu_psp_ring::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug)]
pub struct BootOptions {
    pub dpia: bool,
    /// Preserve firmware's existing panel sequencing during initial bring-up.
    pub skip_panel_power_sequence: bool,
    pub psp_version: u32,
}
impl Default for BootOptions {
    fn default() -> Self {
        Self {
            dpia: true,
            skip_panel_power_sequence: true,
            psp_version: 0,
        }
    }
}
impl BootOptions {
    fn bits(self) -> u32 {
        // Disable unsupported Z10/BW-allocation policy; no interrupt-driven HPD
        // or power optimization is advertised by this polling-only path.
        (1 << 6)
            | (1 << 27)
            | if self.dpia { (1 << 7) | (1 << 9) } else { 0 }
            | if self.skip_panel_power_sequence {
                1 << 5
            } else {
                0
            }
    }
}

struct IoOp<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for IoOp<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
trait Io {
    fn read(&mut self, reg: u32) -> u32;
    fn write(&mut self, reg: u32, value: u32);
    fn upload(&mut self, offset: usize, bytes: &[u8]) -> bool;
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    base: u64,
    vram: MmioRegion,
}
impl Io for Mmio {
    fn read(&mut self, reg: u32) -> u32 {
        // SAFETY: constructor bounds the entire DMCUB register bank.
        unsafe { self.regs.read32(self.base + reg as u64 * 4) }
    }
    fn write(&mut self, reg: u32, value: u32) {
        // SAFETY: constructor bounds the bank and the loader owns DMCUB.
        unsafe { self.regs.write32(self.base + reg as u64 * 4, value) };
    }
    fn upload(&mut self, offset: usize, bytes: &[u8]) -> bool {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end as u64 > self.vram.len)
            || offset % 4 != 0
            || bytes.len() % 4 != 0
        {
            return false;
        }
        for (i, word) in bytes.chunks_exact(4).enumerate() {
            // SAFETY: bounds checked above; reservation is exclusively owned.
            unsafe {
                self.vram.write32(
                    (offset + i * 4) as u64,
                    u32::from_le_bytes(word.try_into().unwrap()),
                )
            };
        }
        fence(Ordering::SeqCst);
        // Read the whole uploaded range to flush posted WC writes before
        // releasing reset, as Linux's dmub_srv_flush_buffer_mem does.
        for (i, word) in bytes.chunks_exact(4).enumerate() {
            // SAFETY: same owned and bounded reservation, DMCUB is stopped.
            if unsafe { self.vram.read32((offset + i * 4) as u64) }
                != u32::from_le_bytes(word.try_into().unwrap())
            {
                return false;
            }
        }
        fence(Ordering::SeqCst);
        true
    }
}
fn update(io: &mut impl Io, reg: u32, mask: u32, bits: u32) {
    let old = io.read(reg);
    io.write(reg, (old & !mask) | bits);
}
fn reset_confirmed(regs: Regs, io: &mut impl Io) -> bool {
    let cntl = io.read(regs.cntl);
    let hub = io.read(regs.hub_reset);
    if cntl == u32::MAX || hub == u32::MAX || cntl & ENABLE != 0 || hub & HUB_RESET_BIT == 0 {
        return false;
    }
    match regs.cntl2 {
        // DCN 3.1.4: reset is requested through CNTL2 bit 0.
        Some(cntl2) => {
            let reset = io.read(cntl2);
            reset != u32::MAX && reset & 1 == 1
        }
        // DCN 2.0/2.1 has no CNTL2: reset is CNTL's own SOFT_RESET bit 17.
        None => cntl & SOFT_RESET != 0,
    }
}
fn force_reset(regs: Regs, io: &mut impl Io) -> bool {
    if io.read(regs.cntl) == u32::MAX || io.read(regs.hub_reset) == u32::MAX {
        return false;
    }
    if let Some(cntl2) = regs.cntl2 {
        if io.read(cntl2) == u32::MAX {
            return false;
        }
        update(io, cntl2, 1, 1);
    }
    update(io, regs.hub_reset, HUB_RESET_BIT, HUB_RESET_BIT);
    // DCN 3.1.4 clears ENABLE here (reset rides CNTL2); DCN 2.0/2.1
    // asserts SOFT_RESET in the same write.
    match regs.cntl2 {
        Some(_) => update(io, regs.cntl, ENABLE, 0),
        None => update(io, regs.cntl, ENABLE | SOFT_RESET, SOFT_RESET),
    }
    fence(Ordering::SeqCst);
    reset_confirmed(regs, io)
}
fn clear_mailboxes(regs: Regs, io: &mut impl Io, secure: bool) {
    for reg in [
        regs.inbox1_wptr,
        regs.inbox1_rptr,
        regs.outbox0_wptr,
        regs.outbox0_rptr,
        regs.outbox1_wptr,
        regs.outbox1_rptr,
        regs.status,
        regs.gpint,
    ] {
        io.write(reg, 0);
    }
    // Disable stale cache windows, including CW2/CW7 that this image won't use.
    // PSP owns the secure instruction and stack windows. Never clear those
    // on the PSP path, including between load completion and reset release.
    let first = if secure { regs.cw_top + 2 } else { regs.cw_top };
    for reg in first..=regs.cw_top + regs.cw_count - 1 {
        io.write(reg, 0);
    }
    io.write(regs.region5_top, 0);
    // DCN 2.0/2.1: the uncached-mailbox window, stale from a previous
    // boot in either mailbox mode.
    if let Some(region4_top) = regs.region4_top {
        io.write(region4_top, 0);
    }
}
/// A DMCUB with its firmware running: enabled and not in reset. DCN 3.1.4
/// carries reset in CNTL2 bit 0; DCN 2.0/2.1 in CNTL's own SOFT_RESET bit.
fn dmcub_active(regs: Regs, io: &mut impl Io) -> bool {
    let cntl = io.read(regs.cntl);
    if cntl & ENABLE == 0 {
        return false;
    }
    match regs.cntl2 {
        Some(cntl2) => io.read(cntl2) & 1 == 0,
        None => cntl & SOFT_RESET == 0,
    }
}
async fn tick() {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
}

#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    allocation: Reservation,
    layout: Layout,
    placement: Placement,
    fb_base: u64,
    fb_offset: u64,
    staging: Vec<u8>,
    state: State,
    secure: bool,
    /// This generation's DMCUB register map (`Regs::DCN314` or
    /// `Regs::DCN21`).
    regs: Regs,
    /// Whether the firmware's mailbox is the cached CW4 one (`Prepared`
    /// decided this from the firmware version).
    cached_inbox: bool,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(IoOp(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    async fn quiesce(&mut self, cleanup: bool) -> Result<(), Error> {
        // Teardown retains authority over previously owned hardware even after
        // revocation; it may only stop access, never publish new work.
        let regs = self.regs;
        let active = if cleanup {
            dmcub_active(regs, &mut self.io)
        } else {
            self.access(|io| dmcub_active(regs, io))?
        };
        if active {
            if cleanup {
                self.io.write(regs.gpint, STOP);
            } else {
                self.access(|io| io.write(regs.gpint, STOP))?;
            }
            let deadline = narf_time::Deadline::after_ms(100);
            loop {
                let finished = |io: &mut I| {
                    io.read(regs.gpint) == 2 << 16
                        && io.read(regs.stop_reply) == 0xdeaddead
                        && io.read(regs.cntl) & (1 << 20) != 0
                };
                if (if cleanup {
                    finished(&mut self.io)
                } else {
                    self.access(finished)?
                }) || deadline.expired()
                {
                    break;
                }
                tick().await;
            }
        }
        let deadline = narf_time::Deadline::after_ms(100);
        loop {
            let reset = if cleanup {
                force_reset(regs, &mut self.io)
            } else {
                self.access(|io| force_reset(regs, io))?
            };
            if reset {
                if cleanup {
                    clear_mailboxes(regs, &mut self.io, self.secure);
                } else {
                    let secure = self.secure;
                    self.access(|io| clear_mailboxes(regs, io, secure))?;
                }
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::StopTimeout);
            }
            tick().await;
        }
    }
    async fn boot(&mut self, options: BootOptions) -> Result<(), Error> {
        if !matches!(self.state, State::Prepared | State::Stopped) {
            return Err(Error::Busy);
        }
        // A dropped future leaves Starting, never a reusable allocation.
        self.state = State::Starting;
        self.allocation.publish();
        let result = self.boot_inner(options).await;
        self.state = if result.is_ok() {
            State::Running
        } else {
            State::Failed
        };
        result
    }
    async fn boot_inner(&mut self, options: BootOptions) -> Result<(), Error> {
        self.quiesce(false).await?;
        for (index, bytes) in self.staging.chunks(4096).enumerate() {
            let io = &mut self.io;
            if !self
                .authority
                .invoke(IoOp(|| io.upload(index * 4096, bytes)))
                .map_err(|_| Error::Revoked)?
            {
                return Err(Error::UploadFailed);
            }
            // Bound every executor poll's copy work, keeping console/IRQ tasks responsive.
            narf_scheduler::yield_now().await;
        }
        let placement = self.placement;
        let layout = self.layout;
        let fb_base = self.fb_base;
        let fb_offset = self.fb_offset;
        let secure = self.secure;
        let regs = self.regs;
        let cached_inbox = self.cached_inbox;
        self.access(|io| {
            configure(
                &regs,
                cached_inbox,
                io,
                layout,
                placement,
                fb_base,
                fb_offset,
                options,
                secure,
            )
        })??;
        self.wait_for_auto_load().await
    }
    /// `dmub_srv_wait_for_auto_load`: the DAL firmware and its mailbox ready
    /// (SCRATCH0's `dal_fw` and `mailbox_rdy`) on a running, unreset DMCUB,
    /// within 100 ms (`dm_dmub_hw_resume`'s 100000 us).
    async fn wait_for_auto_load(&mut self) -> Result<(), Error> {
        let regs = self.regs;
        let deadline = narf_time::Deadline::after_ms(100);
        loop {
            if self.access(|io| {
                let status = io.read(regs.status);
                status != u32::MAX
                    && status & 3 == 3
                    && io.read(regs.cntl) & ENABLE != 0
                    && regs.cntl2.is_none_or(|cntl2| io.read(cntl2) & 1 == 0)
            })? {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::BootTimeout);
            }
            tick().await;
        }
    }
    /// `dmub_dcn31_is_hw_init`: DMCUB enabled with the DAL firmware's boot
    /// bit (`dal_fw`, SCRATCH0 bit 0) set.
    fn is_hw_init(&mut self) -> Result<bool, Error> {
        let regs = self.regs;
        self.access(|io| {
            let status = io.read(regs.status);
            status != u32::MAX && status & 1 != 0 && io.read(regs.cntl) & ENABLE != 0
        })
    }
    async fn stop(&mut self) -> Result<(), Error> {
        if matches!(self.state, State::Prepared | State::Stopped) {
            self.state = State::Stopped;
            return Ok(());
        }
        self.state = State::Stopping;
        let result = self.quiesce(true).await;
        if result.is_ok() {
            // SAFETY: reset, hub reset and disabled DMCUB read back before reuse.
            unsafe {
                self.allocation.stopped();
            }
            self.state = State::Stopped;
        } else {
            self.state = State::Failed;
        }
        result
    }
    fn stop_on_drop(&mut self) -> bool {
        if matches!(self.state, State::Prepared | State::Stopped) {
            return true;
        }
        if !force_reset(self.regs, &mut self.io) {
            return false;
        }
        clear_mailboxes(self.regs, &mut self.io, self.secure);
        // SAFETY: synchronous forced reset verified all stop bits. No await in Drop.
        unsafe {
            self.allocation.stopped();
        }
        self.state = State::Stopped;
        true
    }
}

fn configure(
    regs: &Regs,
    cached_inbox: bool,
    io: &mut impl Io,
    layout: Layout,
    place: Placement,
    fb_base: u64,
    fb_offset: u64,
    options: BootOptions,
    secure: bool,
) -> Result<(), Error> {
    // CW0/1 use translated MC addresses; CW3..6 use GPU addresses directly.
    let translate = |w| {
        place
            .address(w)
            .checked_sub(fb_base)
            .and_then(|n| n.checked_add(fb_offset))
            .filter(|n| *n < 1 << 48)
            .ok_or(Error::Invalid)
    };
    let inst = translate(Window::Instructions)?;
    let stack = translate(Window::Stack)?;
    if secure {
        for reg in [regs.cw_top, regs.cw_top + 1] {
            let value = io.read(reg);
            if value == u32::MAX || value & WINDOW_ENABLE == 0 {
                return Err(Error::ConfigurationFailed);
            }
        }
    } else {
        update(io, regs.sec_cntl, 1 << 16, 1 << 16);
        for (window, address) in [(Window::Instructions, inst), (Window::Stack, stack)] {
            write_window(regs, io, window, address, layout.region(window).size, true)?;
        }
        update(io, regs.sec_cntl, (1 << 16) | 0x3f00, 0x2000);
    }
    for window in [Window::Vbios, Window::Mailbox, Window::Trace, Window::State] {
        // The mailbox window is REGION4, not CW4, on the uncached path.
        if window == Window::Mailbox && !cached_inbox {
            continue;
        }
        write_window(
            regs,
            io,
            window,
            place.address(window),
            layout.region(window).size,
            false,
        )?;
    }
    if !cached_inbox {
        // `dmub_dcn20_setup_windows`: the mailbox memory's GPU address in
        // REGION4's OFFSET, TOP = size - 1 with ENABLE. The firmware reads
        // the inbox at GPU 0x80000000 through this window.
        let mailbox = place.address(Window::Mailbox);
        let size = layout.region(Window::Mailbox).size;
        io.write(
            regs.region4_offset.ok_or(Error::Unsupported)?,
            mailbox as u32,
        );
        io.write(
            regs.region4_offset_high.ok_or(Error::Unsupported)?,
            (mailbox >> 32) as u32,
        );
        io.write(
            regs.region4_top.ok_or(Error::Unsupported)?,
            WINDOW_ENABLE | (size - 1),
        );
    }
    let trace = place.address(Window::Trace);
    io.write(regs.region5_offset, trace as u32);
    io.write(regs.region5_offset_high, (trace >> 32) as u32);
    io.write(
        regs.region5_top,
        WINDOW_ENABLE | (layout.region(Window::Trace).size - 1),
    );
    io.write(regs.outbox0_base, 0xa000_0010);
    io.write(regs.outbox0_size, layout.region(Window::Trace).size - 16);
    // The inbox/outbox rings: the cached CW4 window base 0x64000000, or
    // the uncached REGION4 base 0x80000000.
    let mailbox_base = if cached_inbox {
        0x6400_0000
    } else {
        0x8000_0000
    };
    for (base, address) in [
        (regs.inbox1_base, mailbox_base),
        (regs.outbox1_base, mailbox_base + RING_SIZE),
    ] {
        io.write(base, address);
        io.write(base + 1, RING_SIZE);
        if io.read(base) != address || io.read(base + 1) != RING_SIZE {
            return Err(Error::ConfigurationFailed);
        }
    }
    io.write(regs.options, options.bits());
    if (!secure && io.read(regs.sec_cntl) & ((1 << 16) | 0x3f00) != 0x2000)
        || io.read(regs.options) != options.bits()
    {
        return Err(Error::ConfigurationFailed);
    }
    update(io, regs.hub_reset, HUB_RESET_BIT, 0);
    io.write(regs.psp_version, options.psp_version & 0x0011_00ff);
    update(io, regs.cntl, ENABLE | (1 << 19), ENABLE | (1 << 19));
    fence(Ordering::SeqCst);
    if let Some(cntl2) = regs.cntl2 {
        update(io, cntl2, 1, 0);
    }
    Ok(())
}
fn write_window(
    regs: &Regs,
    io: &mut impl Io,
    window: Window,
    address: u64,
    size: u32,
    inclusive: bool,
) -> Result<(), Error> {
    let index = window as u32;
    let base = 0x6000_0000 + (index << 24);
    io.write(regs.cw_offset + index * 2, address as u32);
    io.write(regs.cw_offset_high + index * 2, (address >> 32) as u32);
    io.write(regs.cw_base + index, base);
    io.write(
        regs.cw_top + index,
        WINDOW_ENABLE | ((base + size - u32::from(inclusive)) & ADDRESS_MASK),
    );
    if io.read(regs.cw_offset + index * 2) & 0xffff_ff00 != address as u32
        || io.read(regs.cw_offset_high + index * 2) & 0xffff != (address >> 32) as u32
        || io.read(regs.cw_base + index) & ADDRESS_MASK != base & ADDRESS_MASK
        || io.read(regs.cw_top + index) & (WINDOW_ENABLE | ADDRESS_MASK)
            != WINDOW_ENABLE | ((base + size - u32::from(inclusive)) & ADDRESS_MASK)
    {
        return Err(Error::ConfigurationFailed);
    }
    Ok(())
}

/// Owns DMCUB, its reservation, and mailbox until a verified stop. System
/// suspend is refused for this object's lifetime; replay is not implemented.
#[derive(Debug)]
pub struct Loader {
    engine: Engine<Mmio>,
    fb: MmioRegion,
    transport: Option<Dmub>,
    ownership: Option<LoaderOwnership>,
    psp: Option<crate::amdgpu_psp_ring::Psp>,
    signed_instructions: Vec<u8>,
    toc: Vec<u8>,
    /// The ASD container for the PSP 12.0 load method; empty on the
    /// TOC method. A non-empty ASD is the PSP 12.0 dispatch signal in
    /// `boot`.
    asd: Vec<u8>,
    dpias: u8,
    /// Raphael's graphics set, loaded through the PSP in place of DMCUB alone.
    graphics: Option<crate::amdgpu_gfx_navi22::Firmware>,
    /// The graphics set was accepted and the RLC autoload completed.
    graphics_booted: bool,
}
impl Loader {
    /// Provision firmware storage using VBIOS reservations, current DMUB
    /// windows, the boot framebuffer and explicit existing GPU allocations.
    /// Construction only reads registers and stages ordinary RAM; `boot` is
    /// still the explicit point that replaces firmware.
    ///
    /// # Safety
    /// The contracts of `new` and `amdgpu_vram_boot::Plan::into_pool` apply.
    /// In particular, every non-firmware allocation (including other scanouts,
    /// cursors, PSP/GART storage and other pools) must appear in `other_clients`
    /// as GPU addresses. `boot_framebuffer` uses PCI/bus-physical addresses.
    /// The caller owns the unprotected VRAM for this loader's entire lifetime.
    pub unsafe fn from_boot_memory(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        firmware: &amdgpu_dmub::Firmware,
        boot_framebuffer: core::ops::Range<u64>,
        other_clients: &[core::ops::Range<u64>],
    ) -> Result<Self, Error> {
        let prepared = firmware.prepare_from_gpu(gpu).map_err(Error::Firmware)?;
        // SAFETY: inherited readable mappings, matching cap and stable ownership.
        let plan = unsafe {
            crate::amdgpu_vram_boot::Plan::read(gpu, &authority, boot_framebuffer, other_clients)
        }
        .map_err(Error::Memory)?;
        // SAFETY: caller supplies the complete inventory and owns the remainder.
        let pool = unsafe { plan.into_pool() }.map_err(Error::Memory)?;
        // SAFETY: this pool owns the free ranges; the retained VBIOS and device
        // lifetime/direct-load requirements are inherited from the caller.
        unsafe { Self::new(gpu, authority, &pool, &prepared) }
    }
    /// # Safety
    /// `authority` must control this GPU. The caller must retain its mappings
    /// and exclusive device ownership (including resets/hot-unplug) for this
    /// loader's lifetime. `pool` must be known-free VRAM on this same GPU;
    /// `prepared` must contain the authenticated DMCUB image for this GPU's
    /// DCN version and this GPU's validated VBIOS. Select this only on a
    /// platform supporting direct load.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        prepared: &Prepared<'_>,
    ) -> Result<Self, Error> {
        let ip = amdgpu_dmub::dmub_ip(gpu).map_err(|_| Error::Unsupported)?;
        if ip.num_bases < 3 {
            return Err(Error::Unsupported);
        }
        let regs = amdgpu_dmub::Regs::for_version((ip.major, ip.minor, ip.revision))
            .ok_or(Error::Unsupported)?;
        let base = ip.base_addrs[2] as u64 * 4;
        if base
            .checked_add(regs.bound as u64 * 4)
            .is_none_or(|end| end > gpu.regs.len)
        {
            return Err(Error::Invalid);
        }
        let ownership = claim_loader().ok_or(Error::Busy)?;
        let mut io = Mmio {
            regs: gpu.regs,
            base,
            vram: pool.mapping(),
        };
        let (fb_base, fb_end, fb_offset, supported) = authority
            .invoke(IoOp(|| {
                (
                    ((io.read(regs.fb_base) & 0xff_ffff) as u64) << 24,
                    (((io.read(regs.fb_top) & 0xff_ffff) as u64) + 1) << 24,
                    ((io.read(regs.fb_offset) & 0xff_ffff) as u64) << 24,
                    io.read(regs.supported),
                )
            }))
            .map_err(|_| Error::Revoked)?;
        if supported == u32::MAX || supported & ENABLE == 0 {
            return Err(Error::Unsupported);
        }
        let offset = pool.address().checked_sub(fb_base).ok_or(Error::Invalid)?;
        let map = pool.mapping();
        if fb_base >= fb_end
            || pool
                .address()
                .checked_add(map.len)
                .is_none_or(|end| end > fb_end)
            || offset
                .checked_add(map.len)
                .is_none_or(|end| end > gpu.fb_bar.len)
            || gpu.fb_bar.virt.checked_add(offset) != Some(map.virt)
            || gpu.fb_bar.phys.raw().checked_add(offset) != Some(map.phys.raw())
        {
            return Err(Error::Invalid);
        }
        let layout = prepared.layout();
        let allocation = pool
            .reserve(layout.size() as u64)
            .map_err(|_| Error::Allocation)?;
        let placement = layout
            .place(allocation.address(), fb_base..fb_end)
            .map_err(|_| Error::Invalid)?;
        // Validate translated end addresses before issuing any reset or upload.
        if allocation
            .address()
            .checked_sub(fb_base)
            .and_then(|n| n.checked_add(fb_offset))
            .and_then(|n| n.checked_add(layout.size() as u64))
            .is_none_or(|end| end > 1 << 48)
        {
            return Err(Error::Invalid);
        }
        let mut staging = Vec::new();
        staging
            .try_reserve_exact(layout.size() as usize)
            .map_err(|_| Error::Allocation)?;
        staging.resize(layout.size() as usize, 0);
        prepared.stage(&mut staging).map_err(|_| Error::Invalid)?;
        io.vram = allocation.mapping();
        Ok(Self {
            engine: Engine {
                io,
                authority,
                allocation,
                layout,
                placement,
                fb_base,
                fb_offset,
                staging,
                state: State::Prepared,
                secure: false,
                regs,
                cached_inbox: prepared.cached_inbox(),
            },
            fb: gpu.fb_bar,
            transport: None,
            ownership: Some(ownership),
            psp: None,
            dpias: amdgpu_dmub::dpia_count(ip),
            graphics: None,
            graphics_booted: false,
            signed_instructions: Vec::new(),
            toc: Vec::new(),
            asd: Vec::new(),
        })
    }
    /// Construct the PSP load method. Both firmware containers must have been
    /// authenticated by the registry. No fallback to direct load is performed.
    ///
    /// # Safety
    /// The device/mapping/pool ownership requirements of `new` apply, together
    /// with exclusive PSP, HDP and power-management ownership from `Psp::new`.
    /// Existing engines must not depend on a driver-managed TMR being replaced.
    pub unsafe fn new_psp(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        firmware: &amdgpu_dmub::Firmware,
        toc: &[u8],
    ) -> Result<Self, Error> {
        let prepared = firmware.prepare_from_gpu(gpu).map_err(Error::Firmware)?;
        crate::amdgpu_psp_ring::toc_payload(toc).map_err(Error::Psp)?;
        // SAFETY: caller owns both engines and the shared pool; construction
        // performs no resets/uploads. Loader's claim excludes other owners.
        let mut loader = unsafe { Self::new(gpu, authority, pool, &prepared) }?;
        let image = firmware.image().map_err(Error::Firmware)?;
        loader
            .signed_instructions
            .try_reserve_exact(image.signed_instructions().len())
            .map_err(|_| Error::Allocation)?;
        loader
            .signed_instructions
            .extend_from_slice(image.signed_instructions());
        loader
            .toc
            .try_reserve_exact(toc.len())
            .map_err(|_| Error::Allocation)?;
        loader.toc.extend_from_slice(toc);
        // SAFETY: inherited permanent pool, exact physical GPU and exclusive PSP.
        loader.psp = Some(
            unsafe { crate::amdgpu_psp_ring::Psp::new(gpu, authority, pool) }
                .map_err(Error::Psp)?,
        );
        loader.engine.secure = true;
        Ok(loader)
    }
    /// Construct the PSP 12.0 load method for Renoir/Cezanne. The ASD
    /// container must have been authenticated by the registry, as the TOC
    /// must for `new_psp`. No fallback to direct load is performed.
    ///
    /// # Safety
    /// The device/mapping/pool ownership requirements of `new` apply, together
    /// with exclusive PSP, HDP and power-management ownership from
    /// `Psp::new_psp12`. Existing engines must not depend on a
    /// driver-managed TMR being replaced.
    pub unsafe fn new_psp12(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        firmware: &amdgpu_dmub::Firmware,
        asd: &[u8],
    ) -> Result<Self, Error> {
        let prepared = firmware.prepare_from_gpu(gpu).map_err(Error::Firmware)?;
        crate::amdgpu_psp_ring::asd_payload(asd).map_err(Error::Psp)?;
        // SAFETY: caller owns both engines and the shared pool; construction
        // performs no resets/uploads. Loader's claim excludes other owners.
        let mut loader = unsafe { Self::new(gpu, authority, pool, &prepared) }?;
        let image = firmware.image().map_err(Error::Firmware)?;
        loader
            .signed_instructions
            .try_reserve_exact(image.signed_instructions().len())
            .map_err(|_| Error::Allocation)?;
        loader
            .signed_instructions
            .extend_from_slice(image.signed_instructions());
        loader
            .asd
            .try_reserve_exact(asd.len())
            .map_err(|_| Error::Allocation)?;
        loader.asd.extend_from_slice(asd);
        // SAFETY: inherited permanent pool, exact physical GPU and exclusive PSP.
        loader.psp = Some(
            unsafe { crate::amdgpu_psp_ring::Psp::new_psp12(gpu, authority, pool) }
                .map_err(Error::Psp)?,
        );
        loader.engine.secure = true;
        Ok(loader)
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    /// Load Raphael's whole graphics set through this loader's PSP session at
    /// `boot`, in place of DMCUB alone, as Linux's `psp_load_non_psp_fw` does
    /// for every non-PSP firmware (SDMA, CE, PFP, ME, MEC, MEC2, RLC with its
    /// autoload, VCN, DMCUB). The set's DMCUB payload must be the signed
    /// instructions this loader prepared, so the DMUB boot that follows runs
    /// exactly what the display path validated.
    pub fn set_graphics(
        &mut self,
        graphics: crate::amdgpu_gfx_navi22::Firmware,
    ) -> Result<(), Error> {
        use crate::amdgpu_gfx_firmware::Source;
        if self.psp.is_none() || self.engine.state != State::Prepared || self.graphics.is_some() {
            return Err(Error::Busy);
        }
        if graphics.profile() != &crate::amdgpu_rdna2::RAPHAEL {
            return Err(Error::Unsupported);
        }
        let images = graphics.images().map_err(|_| Error::Invalid)?;
        let dmcub = Source::ORDER
            .iter()
            .position(|s| *s == Source::Dmcub)
            .and_then(|i| images[i])
            .and_then(|image| image.payloads().next())
            .ok_or(Error::Invalid)?;
        if dmcub.bytes() != self.signed_instructions.as_slice() {
            return Err(Error::Invalid);
        }
        self.graphics = Some(graphics);
        Ok(())
    }
    /// `AMDGPU_INFO_FW_VERSION`'s view of the graphics set this loader holds:
    /// its CP, RLC, SDMA, VCN and DMCUB headers, and the TOC its PSP session
    /// took. SOS is the BIOS's, which Linux reports as 0.
    pub(crate) fn graphics_versions(&self) -> Option<crate::amdgpu_info_navi22::Firmware> {
        use crate::amdgpu_gfx_firmware::Source;
        let set = self.graphics.as_ref()?;
        let g = |source| set.source_bytes(source);
        crate::amdgpu_info_navi22::Firmware::parse(&crate::amdgpu_info_navi22::Files {
            me: g(Source::Me)?,
            pfp: g(Source::Pfp)?,
            ce: g(Source::Ce)?,
            mec: g(Source::Mec)?,
            mec2: g(Source::Mec2),
            rlc: g(Source::Rlc)?,
            sdma: g(Source::Sdma)?,
            sos: None,
            toc: (!self.toc.is_empty()).then_some(self.toc.as_slice()),
            vcn: g(Source::Vcn)?,
            dmcub: g(Source::Dmcub)?,
        })
        .ok()
    }
    /// The PSP session that loaded VCN, for its later power transitions (DPG
    /// register lists after an idle gate). Only after a graphics boot.
    pub(crate) fn media_psp(&mut self) -> Option<&mut crate::amdgpu_psp_ring::Psp> {
        if !self.graphics_booted {
            return None;
        }
        self.psp.as_mut()
    }
    /// Whether `boot` loaded the graphics set and the RLC autoload completed.
    pub fn graphics_booted(&self) -> bool {
        self.graphics_booted
    }
    /// The MES program-counter entry points (`uc_start_addr`, sched + KIQ)
    /// for a loaded Phoenix graphics set, for the Phoenix cold boot's
    /// `mes_start`. `None` until the firmware lane lands
    /// `Firmware::open_phoenix` + the Phoenix `set_graphics` arm: no Phoenix
    /// set can be loaded today, so there are no entry points to report.
    /// That lane parses them from the MES image header (see
    /// `amdgpu_phoenix_boot::parse_mes_start_addrs`) once the set exists.
    pub(crate) fn mes_start_addrs(&self) -> Option<[u64; 2]> {
        None
    }
    /// After a graphics boot, what VCN's start needs from the PSP session
    /// that loaded it: the session itself (for the DPG register lists it
    /// writes into VCN's SRAM), the VCN TMR addresses it recorded, and the
    /// VCN container's size, which sizes VCPU cache window 0.
    pub(crate) fn media(
        &mut self,
    ) -> Option<(
        &mut crate::amdgpu_psp_ring::Psp,
        crate::amdgpu_psp_ring::MediaFirmware,
        usize,
    )> {
        if !self.graphics_booted {
            return None;
        }
        let size = self.graphics.as_ref()?.vcn_size()?;
        let firmware = self.psp.as_ref()?.media_firmware();
        Some((self.psp.as_mut()?, firmware, size))
    }
    pub async fn boot(&mut self, options: BootOptions) -> Result<(), Error> {
        if self.psp.is_some() {
            if !matches!(self.engine.state, State::Prepared | State::Stopped) {
                return Err(Error::Busy);
            }
            // A dropped PSP future must not allow a second boot attempt.
            self.engine.state = State::Starting;
            self.engine.quiesce(false).await?;
            let psp = self.psp.as_mut().unwrap();
            psp.start().await.map_err(Error::Psp)?;
            if self.asd.is_empty() {
                psp.setup_tmr(&self.toc).await.map_err(Error::Psp)?;
                match self.graphics.as_ref() {
                    Some(graphics) => {
                        psp.load_gfx_rdna2(graphics).await.map_err(Error::Psp)?;
                        psp.wait_gfx_boot_rdna2().await.map_err(Error::Psp)?;
                        self.graphics_booted = true;
                    }
                    None => psp
                        .load_dmub(&self.signed_instructions)
                        .await
                        .map_err(Error::Psp)?,
                }
            } else {
                // PSP 12.0 order (`psp_hw_start`): TOC-less TMR, then the
                // DMUB load, then the ASD load.
                psp.setup_tmr_psp12().await.map_err(Error::Psp)?;
                psp.load_dmub(&self.signed_instructions)
                    .await
                    .map_err(Error::Psp)?;
                psp.load_asd(&self.asd).await.map_err(Error::Psp)?;
            }
            self.engine.state = State::Stopped;
        }
        self.engine.boot(options).await?;
        self.attach_transport()
    }
    /// `dm_dmub_hw_resume` for an s0ix resume. The PSP kept the TMR, so DMCUB
    /// alone is checked. Still initialized, it is given its auto-load wait.
    /// Otherwise it is booted again from the TMR, as `dm_dmub_hw_init`
    /// boots it: the data windows re-staged from system memory, no PSP load.
    /// Its transport is then attached again.
    pub async fn resume_dmub(&mut self, options: BootOptions) -> Result<(), Error> {
        if self.engine.state != State::Running {
            return Err(Error::Busy);
        }
        if self.engine.is_hw_init()? {
            return self.engine.wait_for_auto_load().await;
        }
        self.transport = None;
        // The hardware lost DMCUB; its owner state follows.
        self.engine.state = State::Stopped;
        self.engine.boot(options).await?;
        self.attach_transport()
    }
    fn attach_transport(&mut self) -> Result<(), Error> {
        let io = &self.engine.io;
        let regs = self.engine.regs;
        let cached_inbox = self.engine.cached_inbox;
        let transport = self
            .engine
            .authority
            .invoke(IoOp(|| {
                // SAFETY: this loader owns the verified running DMCUB and all mappings.
                unsafe {
                    Dmub::attach_regions(io.regs, self.fb, io.base, self.dpias, regs, cached_inbox)
                }
            }))
            .map_err(|_| Error::Revoked)
            .and_then(|result| result.map_err(Error::Transport));
        match transport {
            Ok(transport) => {
                self.transport = Some(transport);
                Ok(())
            }
            Err(error) => {
                self.engine.state = State::Failed;
                Err(error)
            }
        }
    }
    pub async fn stop(&mut self) -> Result<(), Error> {
        // Releasing the TMR needs every engine running from it reset. After a
        // graphics boot the RLC and CP do, and nothing here resets them, so
        // the loader stays up (and a suspend is refused) rather than pull the
        // TMR from under them.
        if self.graphics_booted {
            return Err(Error::Busy);
        }
        self.transport = None;
        self.engine.stop().await?;
        if let Some(psp) = self.psp.as_mut() {
            // SAFETY: verified DMCUB reset precedes release of its secure TMR.
            unsafe { psp.stop().await }.map_err(Error::Psp)?;
        }
        Ok(())
    }
    /// `psp_suspend` ahead of a mode 2 reset: DMUB stopped, then the TMR
    /// released and the PSP ring stopped while the RLC and CP still run from
    /// the TMR, as Linux's suspend before the reset does. A later `boot`
    /// loads the graphics set again.
    ///
    /// # Safety
    /// The caller resets every engine running from the TMR (mode 2) before
    /// anything else runs, and boots this loader again before the display or
    /// graphics are used.
    pub(crate) async unsafe fn stop_for_reset(&mut self) -> Result<(), Error> {
        self.graphics_booted = false;
        self.transport = None;
        self.engine.stop().await?;
        if let Some(psp) = self.psp.as_mut() {
            // SAFETY: DMCUB is reset above; the caller resets the rest.
            unsafe { psp.stop().await }.map_err(Error::Psp)?;
        }
        Ok(())
    }
    pub async fn enable_notifications(&mut self) -> Result<(), Error> {
        let dmub = self.transport.as_mut().ok_or(Error::Busy)?;
        authorized(&self.engine.authority, dmub.enable_notifications()).await
    }
    pub(crate) async fn command(&mut self, command: [u8; 64]) -> Result<[u8; 64], Error> {
        let dmub = self.transport.as_mut().ok_or(Error::Busy)?;
        authorized(&self.engine.authority, dmub.command(command)).await
    }
    pub(crate) async fn discover_sinks(&mut self) -> Result<Vec<crate::amdgpu_usbc::Sink>, Error> {
        let dmub = self.transport.as_mut().ok_or(Error::Busy)?;
        authorized(&self.engine.authority, crate::amdgpu_usbc::scan(dmub)).await
    }
    pub async fn hpd(&mut self, instance: u8, channel: Channel) -> Result<bool, Error> {
        let dmub = self.transport.as_mut().ok_or(Error::Busy)?;
        authorized(&self.engine.authority, dmub.hpd(instance, channel)).await
    }
    pub async fn typec_phy(&mut self, phy: u8) -> Result<(bool, bool, bool), Error> {
        let dmub = self.transport.as_mut().ok_or(Error::Busy)?;
        authorized(&self.engine.authority, dmub.typec_phy(phy)).await
    }
    pub async fn aux(
        &mut self,
        channel: Channel,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        let dmub = self.transport.as_mut().ok_or(Error::Busy)?;
        authorized(
            &self.engine.authority,
            dmub.aux(channel, instance, action, address, data),
        )
        .await
    }
}
async fn authorized<T>(
    cap: &Cap<BusDeviceCap, Write>,
    future: impl Future<Output = Result<T, amdgpu_dmub::Error>>,
) -> Result<T, Error> {
    let mut future = core::pin::pin!(future);
    core::future::poll_fn(|cx| match cap.invoke(IoOp(|| future.as_mut().poll(cx))) {
        Ok(Poll::Ready(value)) => Poll::Ready(value.map_err(Error::Transport)),
        Ok(Poll::Pending) => Poll::Pending,
        Err(_) => Poll::Ready(Err(Error::Revoked)),
    })
    .await
}
impl Drop for Loader {
    fn drop(&mut self) {
        self.transport = None;
        let stopped = self.engine.stop_on_drop();
        let psp_stopped = self.psp.as_ref().is_none_or(|psp| {
            matches!(
                psp.state(),
                crate::amdgpu_psp_ring::State::Prepared | crate::amdgpu_psp_ring::State::Stopped
            )
        });
        if !stopped || !psp_stopped {
            // Keep global mailbox/PM ownership blocked along with quarantined
            // VRAM. A new client must not race a possibly still-running DMUB.
            if let Some(owner) = self.ownership.take() {
                core::mem::forget(owner);
            }
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dmub_boot_tests.rs"]
mod tests;
