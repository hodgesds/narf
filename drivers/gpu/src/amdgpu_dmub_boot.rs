//! DCN314 direct-load lifecycle, following Linux dmub_dcn31.c/dmub_srv.c.
//!
//! This is the explicitly selected direct-load method, not a PSP fallback.
//! The caller supplies a pool of known-free VRAM and a validated VBIOS image.
//! No unowned BAR space is guessed to be free. Platform boot wiring and the
//! PSP load method are separate from this lifecycle.
use super::{
    amdgpu::AmdGpu,
    amdgpu_dmub::{self, Channel, Dmub},
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

const CNTL: u32 = 0x1f6;
const CNTL2: u32 = 0x200;
const HUB_RESET: u32 = 0x342;
const SEC_CNTL: u32 = 0x1ce;
const GPINT: u32 = 0x1f8;
const STATUS: u32 = 0x1e3;
const STOP_REPLY: u32 = 0x1ea;
const ENABLE: u32 = 1 << 16;
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
        // SAFETY: constructor bounds the entire DCN314 register bank.
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
fn reset_confirmed(io: &mut impl Io) -> bool {
    let cntl = io.read(CNTL);
    let reset = io.read(CNTL2);
    let hub = io.read(HUB_RESET);
    cntl != u32::MAX
        && reset != u32::MAX
        && hub != u32::MAX
        && cntl & ENABLE == 0
        && reset & 1 == 1
        && hub & HUB_RESET_BIT != 0
}
fn force_reset(io: &mut impl Io) -> bool {
    if io.read(CNTL) == u32::MAX || io.read(CNTL2) == u32::MAX || io.read(HUB_RESET) == u32::MAX {
        return false;
    }
    update(io, CNTL2, 1, 1);
    update(io, HUB_RESET, HUB_RESET_BIT, HUB_RESET_BIT);
    update(io, CNTL, ENABLE, 0);
    fence(Ordering::SeqCst);
    reset_confirmed(io)
}
fn clear_mailboxes(io: &mut impl Io, secure: bool) {
    for reg in [0x1d6, 0x1d7, 0x1da, 0x1db, 0x1de, 0x1df, STATUS, GPINT] {
        io.write(reg, 0);
    }
    // Disable stale cache windows, including CW2/CW7 that this image won't use.
    // PSP owns the secure instruction and stack windows. Never clear those
    // on the PSP path, including between load completion and reset release.
    for reg in (if secure { 0x1af } else { 0x1ad })..=0x1b4 {
        io.write(reg, 0);
    }
    io.write(0x1a2, 0);
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
        let active = if cleanup {
            self.io.read(CNTL) & ENABLE != 0 && self.io.read(CNTL2) & 1 == 0
        } else {
            self.access(|io| io.read(CNTL) & ENABLE != 0 && io.read(CNTL2) & 1 == 0)?
        };
        if active {
            if cleanup {
                self.io.write(GPINT, STOP);
            } else {
                self.access(|io| io.write(GPINT, STOP))?;
            }
            let deadline = narf_time::Deadline::after_ms(100);
            loop {
                let finished = |io: &mut I| {
                    io.read(GPINT) == 2 << 16
                        && io.read(STOP_REPLY) == 0xdeaddead
                        && io.read(CNTL) & (1 << 20) != 0
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
                force_reset(&mut self.io)
            } else {
                self.access(force_reset)?
            };
            if reset {
                if cleanup {
                    clear_mailboxes(&mut self.io, self.secure);
                } else {
                    let secure = self.secure;
                    self.access(|io| clear_mailboxes(io, secure))?;
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
        self.access(|io| configure(io, layout, placement, fb_base, fb_offset, options, secure))??;
        let deadline = narf_time::Deadline::after_ms(100);
        loop {
            if self.access(|io| {
                let status = io.read(STATUS);
                status != u32::MAX
                    && status & 3 == 3
                    && io.read(CNTL) & ENABLE != 0
                    && io.read(CNTL2) & 1 == 0
            })? {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::BootTimeout);
            }
            tick().await;
        }
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
        if !force_reset(&mut self.io) {
            return false;
        }
        clear_mailboxes(&mut self.io, self.secure);
        // SAFETY: synchronous forced reset verified all stop bits. No await in Drop.
        unsafe {
            self.allocation.stopped();
        }
        self.state = State::Stopped;
        true
    }
}

fn configure(
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
        for reg in [0x1ad, 0x1ae] {
            let value = io.read(reg);
            if value == u32::MAX || value & WINDOW_ENABLE == 0 {
                return Err(Error::ConfigurationFailed);
            }
        }
    } else {
        update(io, SEC_CNTL, 1 << 16, 1 << 16);
        for (window, address) in [(Window::Instructions, inst), (Window::Stack, stack)] {
            write_window(io, window, address, layout.region(window).size, true)?;
        }
        update(io, SEC_CNTL, (1 << 16) | 0x3f00, 0x2000);
    }
    for window in [Window::Vbios, Window::Mailbox, Window::Trace, Window::State] {
        write_window(
            io,
            window,
            place.address(window),
            layout.region(window).size,
            false,
        )?;
    }
    let trace = place.address(Window::Trace);
    io.write(0x198, trace as u32);
    io.write(0x199, (trace >> 32) as u32);
    io.write(
        0x1a2,
        WINDOW_ENABLE | (layout.region(Window::Trace).size - 1),
    );
    io.write(0x1d8, 0xa000_0010);
    io.write(0x1d9, layout.region(Window::Trace).size - 16);
    for (base, address) in [(0x1d4, 0x6400_0000), (0x1dc, 0x6400_0000 + RING_SIZE)] {
        io.write(base, address);
        io.write(base + 1, RING_SIZE);
        if io.read(base) != address || io.read(base + 1) != RING_SIZE {
            return Err(Error::ConfigurationFailed);
        }
    }
    io.write(0x1f1, options.bits());
    if (!secure && io.read(SEC_CNTL) & ((1 << 16) | 0x3f00) != 0x2000)
        || io.read(0x1f1) != options.bits()
    {
        return Err(Error::ConfigurationFailed);
    }
    update(io, HUB_RESET, HUB_RESET_BIT, 0);
    io.write(0x1f2, options.psp_version & 0x0011_00ff);
    update(io, CNTL, ENABLE | (1 << 19), ENABLE | (1 << 19));
    fence(Ordering::SeqCst);
    update(io, CNTL2, 1, 0);
    Ok(())
}
fn write_window(
    io: &mut impl Io,
    window: Window,
    address: u64,
    size: u32,
    inclusive: bool,
) -> Result<(), Error> {
    let index = window as u32;
    let base = 0x6000_0000 + (index << 24);
    io.write(0x1b5 + index * 2, address as u32);
    io.write(0x1b6 + index * 2, (address >> 32) as u32);
    io.write(0x1a5 + index, base);
    io.write(
        0x1ad + index,
        WINDOW_ENABLE | ((base + size - u32::from(inclusive)) & ADDRESS_MASK),
    );
    if io.read(0x1b5 + index * 2) & 0xffff_ff00 != address as u32
        || io.read(0x1b6 + index * 2) & 0xffff != (address >> 32) as u32
        || io.read(0x1a5 + index) & ADDRESS_MASK != base & ADDRESS_MASK
        || io.read(0x1ad + index) & (WINDOW_ENABLE | ADDRESS_MASK)
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
    /// `prepared` must contain the authenticated DCN314 image and this GPU's
    /// validated VBIOS. Select this only on a platform supporting direct load.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        prepared: &Prepared<'_>,
    ) -> Result<Self, Error> {
        let ip = amdgpu_dmub::dcn314_ip(gpu).map_err(|_| Error::Unsupported)?;
        if ip.num_bases < 3 {
            return Err(Error::Unsupported);
        }
        let base = ip.base_addrs[2] as u64 * 4;
        if base
            .checked_add(0x478 * 4)
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
                    ((io.read(0x475) & 0xff_ffff) as u64) << 24,
                    (((io.read(0x476) & 0xff_ffff) as u64) + 1) << 24,
                    ((io.read(0x477) & 0xff_ffff) as u64) << 24,
                    io.read(0xca),
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
            },
            fb: gpu.fb_bar,
            transport: None,
            ownership: Some(ownership),
            psp: None,
            signed_instructions: Vec::new(),
            toc: Vec::new(),
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
    pub fn state(&self) -> State {
        self.engine.state
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
            psp.setup_tmr(&self.toc).await.map_err(Error::Psp)?;
            psp.load_dmub(&self.signed_instructions)
                .await
                .map_err(Error::Psp)?;
            self.engine.state = State::Stopped;
        }
        self.engine.boot(options).await?;
        let io = &self.engine.io;
        let transport = self
            .engine
            .authority
            .invoke(IoOp(|| {
                // SAFETY: this loader owns the verified running DCN314 and all mappings.
                unsafe { Dmub::attach_regions(io.regs, self.fb, io.base) }
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
        self.transport = None;
        self.engine.stop().await?;
        if let Some(psp) = self.psp.as_mut() {
            // SAFETY: verified DMCUB reset precedes release of its secure TMR.
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
