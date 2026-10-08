//! Phoenix PSP 13.0.4 GPCOM ring. Wire layouts and MMIO sequencing follow
//! Linux psp_gfx_if.h, psp_v13_0_4.c, amdgpu_psp.c and hdp_v5_0.c.
//! All addresses on the ring are GPU addresses, not host physical addresses.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as discovery,
    amdgpu_vram::{Pool, Reservation},
};
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

const CTRL: u32 = 0x80;
const WPTR: u32 = 0x83;
const RING_LO: u32 = 0x85;
const RING_HI: u32 = 0x86;
const RING_SIZE: u32 = 0x87;
const SOS: u32 = 0x91;
const RESPONSE: u32 = 1 << 31;
const CREATE: u32 = 1 << 16;
const DESTROY: u32 = 3 << 16;
const COMMAND: u64 = 4096;
const FENCE: u64 = 8192;
const BUFFER_SIZE: u64 = 12288;
const HDP_HOLE: u64 = 0x7f000;
const MAX_IMAGE: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Allocation,
    Revoked,
    Busy,
    Timeout,
    DeviceGone,
    Rejected(u32),
    Upload,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Starting,
    Ready,
    Pending,
    Failed,
    Stopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Reply {
    address: u64,
    tmr_size: u32,
}

/// Linux leaves the size/version and RBI-only header fields zero for GPCOM.
fn command(id: u32, args: &[u32]) -> [u32; 256] {
    let mut words = [0; 256];
    words[2] = id;
    words[7..7 + args.len()].copy_from_slice(args);
    words
}
fn load_command(id: u32, address: u64, size: u32, kind: u32) -> [u32; 256] {
    command(id, &[address as u32, (address >> 32) as u32, size, kind])
}

struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
trait Io {
    fn read(&mut self, reg: u32) -> u32;
    fn write(&mut self, reg: u32, value: u32);
    fn read_mem(&mut self, offset: u64) -> u32;
    fn write_mem(&mut self, offset: u64, value: u32);
    fn setup_hdp(&mut self) -> bool;
    fn flush(&mut self);
    fn invalidate(&mut self);
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    mp0: u64,
    nbio: u64,
    invalidate_reg: Option<u64>,
    memory: MmioRegion,
}
impl Io for Mmio {
    fn read(&mut self, reg: u32) -> u32 {
        // SAFETY: constructor bounds this MP0 register bank and retains mappings.
        unsafe { self.regs.read32(self.mp0 + reg as u64 * 4) }
    }
    fn write(&mut self, reg: u32, value: u32) {
        // SAFETY: same bounds; caller owns the sole PSP ring.
        unsafe { self.regs.write32(self.mp0 + reg as u64 * 4, value) };
    }
    fn read_mem(&mut self, offset: u64) -> u32 {
        // SAFETY: all offsets below BUFFER_SIZE are internal ring constants.
        unsafe { self.memory.read32(offset) }
    }
    fn write_mem(&mut self, offset: u64, value: u32) {
        // SAFETY: same permanently owned ring allocation.
        unsafe { self.memory.write32(offset, value) };
    }
    fn setup_hdp(&mut self) -> bool {
        // SAFETY: exact supported NBIO bank and the 4 KiB remap hole are bounded.
        unsafe {
            self.regs.write32(self.nbio + 0x12d * 4, HDP_HOLE as u32);
            self.regs.read32(self.nbio + 0x12d * 4) == HDP_HOLE as u32
        }
    }
    fn flush(&mut self) {
        fence(Ordering::SeqCst);
        // SAFETY: remap was verified before publishing any device memory.
        // Linux posts this write by reading MEMSIZE, not the remapped register.
        unsafe {
            self.regs.write32(HDP_HOLE, 0);
            self.regs.read32(self.nbio + 0xc3 * 4);
        }
        fence(Ordering::SeqCst);
    }
    fn invalidate(&mut self) {
        if let Some(reg) = self.invalidate_reg {
            // SAFETY: bounded HDP5.0/5.2.0 register. HDP5.2.1 has no such step.
            unsafe {
                self.regs.write32(reg, 1);
                self.regs.read32(reg);
            }
        }
        fence(Ordering::SeqCst);
    }
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    memory: Reservation,
    state: State,
    sequence: u32,
}
async fn delay(ms: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant()).await;
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    async fn response(&mut self, cleanup: bool) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(500);
        loop {
            let value = if cleanup {
                self.io.read(CTRL)
            } else {
                self.access(|io| io.read(CTRL))?
            };
            if value == u32::MAX {
                return Err(Error::DeviceGone);
            }
            if value & RESPONSE != 0 {
                return if value & 0xffff == 0 {
                    Ok(())
                } else {
                    Err(Error::Rejected(value & 0xffff))
                };
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay(1).await;
        }
    }
    async fn start(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Prepared | State::Stopped) {
            return Err(Error::Busy);
        }
        let alive = self.access(|io| io.read(SOS))?;
        if alive == 0 || alive == u32::MAX {
            return Err(Error::DeviceGone);
        }
        self.response(false).await?;
        self.state = State::Starting;
        let address = self.memory.address();
        self.memory.publish();
        self.access(|io| {
            if !io.setup_hdp() {
                return Err(Error::Invalid);
            }
            for offset in (0..BUFFER_SIZE).step_by(4) {
                io.write_mem(offset, 0);
            }
            io.flush();
            io.write(RING_LO, address as u32);
            io.write(RING_HI, (address >> 32) as u32);
            io.write(RING_SIZE, 4096);
            io.write(CTRL, CREATE);
            Ok(())
        })??;
        // PSP13.0.4 requires the handshake delay even for a fast response.
        delay(20).await;
        let result = self.response(false).await;
        self.state = if result.is_ok() {
            State::Ready
        } else {
            State::Failed
        };
        result
    }
    async fn submit(&mut self, words: &[u32; 256]) -> Result<Reply, Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        let wptr = self.access(|io| io.read(WPTR))?;
        if wptr >= 1024 || wptr % 16 != 0 {
            return Err(Error::Invalid);
        }
        self.sequence = self.sequence.wrapping_add(1).max(1);
        let seq = self.sequence;
        let address = self.memory.address();
        self.state = State::Pending;
        self.access(|io| {
            io.write_mem(FENCE, 0);
            for (i, value) in words.iter().enumerate() {
                io.write_mem(COMMAND + i as u64 * 4, *value);
            }
            let mut frame = [0u32; 16];
            frame[0] = (address + COMMAND) as u32;
            frame[1] = ((address + COMMAND) >> 32) as u32;
            frame[3] = (address + FENCE) as u32;
            frame[4] = ((address + FENCE) >> 32) as u32;
            frame[5] = seq;
            for (i, value) in frame.iter().enumerate() {
                io.write_mem(wptr as u64 * 4 + i as u64 * 4, *value);
            }
            io.flush();
            io.write(WPTR, (wptr + 16) % 1024);
        })?;
        let deadline = narf_time::Deadline::after_ms(500);
        loop {
            let done = self.access(|io| {
                io.invalidate();
                io.read_mem(FENCE) == seq
            })?;
            if done {
                break;
            }
            if deadline.expired() {
                self.state = State::Failed;
                return Err(Error::Timeout);
            }
            delay(1).await;
        }
        let (status, reply) = self.access(|io| {
            io.invalidate();
            (
                io.read_mem(COMMAND + 864),
                Reply {
                    address: io.read_mem(COMMAND + 872) as u64
                        | (io.read_mem(COMMAND + 876) as u64) << 32,
                    tmr_size: io.read_mem(COMMAND + 880),
                },
            )
        })?;
        self.state = State::Ready;
        if status != 0 {
            return Err(Error::Rejected(status));
        }
        Ok(reply)
    }
    async fn stop(&mut self) -> Result<(), Error> {
        if matches!(self.state, State::Prepared | State::Stopped) {
            self.state = State::Stopped;
            return Ok(());
        }
        self.state = State::Failed;
        // Teardown may remove existing DMA authority after cap revocation.
        self.io.write(CTRL, DESTROY);
        delay(20).await;
        self.response(true).await?;
        // SAFETY: PSP acknowledged ring destruction, so it cannot access buffers.
        unsafe {
            self.memory.stopped();
        }
        self.state = State::Stopped;
        Ok(())
    }
}

/// Owns a single Phoenix PSP ring and any TMR installed through it. Dropping
/// without verified shutdown quarantines published memory, including payloads.
#[derive(Debug)]
pub struct Psp {
    engine: Engine<Mmio>,
    pool: Pool,
    payload: Option<Reservation>,
    tmr: Option<Reservation>,
    tmr_ready: bool,
    fb_base: u64,
    fb_offset: u64,
}
/// One IP version's register window, for a caller whose register ids are only
/// valid on some of the versions an IP reports.
///
/// Sibling revisions of the same IP agree on neither their SOC15 `_BASE_IDX`
/// nor their offsets — MMHUB 3.0.0 and 3.0.1 put `regMMVM_CONTEXT0_CNTL` at
/// the same 0x0740 on different base indices, 3.0.2 moves it to 0x06c0, and
/// DCN 3.5 shifts `regHUBPREQ0_DCSURF_SURFACE_INUSE` one dword down from
/// 3.1.4's. So a window belongs to exactly one version, and widening a
/// version list without widening its register table turns a clean
/// `Unsupported` into a write to an unrelated register.
///
/// Implement this on a row type that carries whatever offsets the caller
/// needs, put one row per supported version in a table, and resolve it with
/// [`bank_for`]. Supporting another GPU is then adding rows.
pub(crate) trait RegWindow: Copy {
    /// Discovery-blob version this window describes: (major, minor, revision).
    fn version(&self) -> (u8, u8, u8);
    /// The `_BASE_IDX` every register in this window carries.
    fn base_idx(&self) -> usize;
    /// Highest dword the caller reads or writes through this base.
    fn last(&self) -> u32;
}

/// Resolve the instance-0 bank for `id` and return it with the window row
/// matching the version discovery reports.
///
/// `Unsupported` when no row covers that version — never a fallback to another
/// generation's row.
pub(crate) fn bank_for<W: RegWindow>(
    gpu: &AmdGpu,
    id: u16,
    windows: &[W],
) -> Result<(u64, W), Error> {
    let ip = discovery::find_ip(&gpu.ip_blocks, id, 0).ok_or(Error::Unsupported)?;
    let window = windows
        .iter()
        .find(|w| w.version() == (ip.major, ip.minor, ip.revision))
        .ok_or(Error::Unsupported)?;
    let base = bank(
        gpu,
        id,
        &[window.version()],
        window.base_idx(),
        window.last(),
    )?;
    Ok((base, *window))
}

pub(crate) fn bank(
    gpu: &AmdGpu,
    id: u16,
    versions: &[(u8, u8, u8)],
    index: usize,
    last: u32,
) -> Result<u64, Error> {
    let mut blocks = gpu
        .ip_blocks
        .iter()
        .filter(|ip| ip.hw_id == id && ip.instance == 0);
    let ip = blocks.next().ok_or(Error::Unsupported)?;
    if blocks.next().is_some()
        || !versions.contains(&(ip.major, ip.minor, ip.revision))
        || ip.num_bases as usize <= index
    {
        return Err(Error::Unsupported);
    }
    let base = ip.base_addrs[index] as u64 * 4;
    if base
        .checked_add((last as u64 + 1) * 4)
        .is_none_or(|end| end > gpu.regs.len)
    {
        return Err(Error::Invalid);
    }
    Ok(base)
}
impl Psp {
    /// # Safety
    /// Caller owns this physical GPU (not an SR-IOV VF), PSP/PM/HDP exclusively,
    /// with permanent mappings and this GPU's exclusively free VRAM pool. No
    /// legacy PSP helper may run concurrently. All firmware-consuming engines
    /// must be stopped before destroying or replacing their TMR.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        let mp0 = bank(gpu, discovery::HW_ID_MP0, &[(13, 0, 4)], 1, SOS)?;
        let nbio = bank(
            gpu,
            discovery::HW_ID_NBIF,
            &[(4, 3, 0), (4, 3, 1), (7, 7, 0), (7, 7, 1)],
            2,
            0x12d,
        )?;
        let hdp = bank(
            gpu,
            discovery::HW_ID_HDP,
            &[
                (5, 0, 0),
                (5, 0, 1),
                (5, 0, 2),
                (5, 0, 3),
                (5, 0, 4),
                (5, 2, 0),
                (5, 2, 1),
            ],
            0,
            0xd1,
        )?;
        let hdp_ip = discovery::find_ip(&gpu.ip_blocks, discovery::HW_ID_HDP, 0)
            .ok_or(Error::Unsupported)?;
        if gpu.regs.len < HDP_HOLE + 4096 {
            return Err(Error::Invalid);
        }
        let dcn = bank(gpu, discovery::HW_ID_DCN, &[(3, 1, 4)], 2, 0x477)?;
        let (base, top, offset) = authority
            .invoke(Op(|| {
                // SAFETY: constructor bounds the discovered DCN bank.
                unsafe {
                    (
                        gpu.regs.read32(dcn + 0x475 * 4),
                        gpu.regs.read32(dcn + 0x476 * 4),
                        gpu.regs.read32(dcn + 0x477 * 4),
                    )
                }
            }))
            .map_err(|_| Error::Revoked)?;
        if [base, top, offset].contains(&u32::MAX) {
            return Err(Error::DeviceGone);
        }
        let fb_base = (base as u64 & 0xffffff) << 24;
        let fb_end = ((top as u64 & 0xffffff) + 1) << 24;
        let fb_offset = (offset as u64 & 0xffffff) << 24;
        let pool_offset = pool.address().checked_sub(fb_base).ok_or(Error::Invalid)?;
        let mapping = pool.mapping();
        if pool
            .address()
            .checked_add(mapping.len)
            .is_none_or(|end| end > fb_end)
            || pool_offset
                .checked_add(mapping.len)
                .is_none_or(|end| end > gpu.fb_bar.len)
            || gpu.fb_bar.virt.checked_add(pool_offset) != Some(mapping.virt)
            || gpu.fb_bar.phys.raw().checked_add(pool_offset) != Some(mapping.phys.raw())
        {
            return Err(Error::Invalid);
        }
        let memory = pool.reserve(BUFFER_SIZE).map_err(|_| Error::Allocation)?;
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: gpu.regs,
                    mp0,
                    nbio,
                    invalidate_reg: ((hdp_ip.major, hdp_ip.minor, hdp_ip.revision) != (5, 2, 1))
                        .then_some(hdp + 0xd1 * 4),
                    memory: memory.mapping(),
                },
                authority,
                memory,
                state: State::Prepared,
                sequence: 0,
            },
            pool: pool.clone(),
            payload: None,
            tmr: None,
            tmr_ready: false,
            fb_base,
            fb_offset,
        })
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    pub async fn start(&mut self) -> Result<(), Error> {
        self.engine.start().await
    }
    async fn stage(&mut self, bytes: &[u8]) -> Result<(u64, u32), Error> {
        if self.engine.state != State::Ready || self.payload.is_some() {
            return Err(Error::Busy);
        }
        if bytes.is_empty() || bytes.len() > MAX_IMAGE {
            return Err(Error::Invalid);
        }
        let allocation = self
            .pool
            .reserve(bytes.len() as u64)
            .map_err(|_| Error::Allocation)?;
        let address = allocation.address();
        let map = allocation.mapping();
        self.payload = Some(allocation);
        for (index, chunk) in bytes.chunks(4096).enumerate() {
            self.engine.access(|_| {
                for (i, word) in chunk.chunks(4).enumerate() {
                    let mut padded = [0u8; 4];
                    padded[..word.len()].copy_from_slice(word);
                    // SAFETY: exclusive payload reservation, rounded up to a page.
                    unsafe {
                        map.write32((index * 4096 + i * 4) as u64, u32::from_le_bytes(padded));
                    }
                }
            })?;
            narf_scheduler::yield_now().await;
        }
        self.engine.access(|io| io.flush())?;
        self.payload.as_mut().unwrap().publish();
        Ok((address, bytes.len() as u32))
    }
    fn release_payload(&mut self) {
        if self.engine.state == State::Ready {
            if let Some(mut payload) = self.payload.take() {
                // SAFETY: exact fence completed the only command reading this image.
                unsafe {
                    payload.stopped();
                }
            }
        }
    }
    /// TOC is the authenticated PSP firmware container, not its filename or
    /// an arbitrary buffer. Load its payload, then reserve the returned TMR size.
    pub async fn setup_tmr(&mut self, toc: &[u8]) -> Result<(), Error> {
        if self.tmr.is_some() {
            return Err(Error::Busy);
        }
        let payload = toc_payload(toc)?;
        let (address, size) = self.stage(payload).await?;
        let result = self
            .engine
            .submit(&load_command(0x20, address, size, 0))
            .await;
        self.release_payload();
        let size = result?.tmr_size as u64;
        if size == 0 || size > 64 * 1024 * 1024 || size % 4096 != 0 {
            return Err(Error::Invalid);
        }
        let mut tmr = self
            .pool
            .reserve_aligned(size, 1 << 20)
            .map_err(|_| Error::Allocation)?;
        let address = tmr.address();
        let physical = address
            .checked_sub(self.fb_base)
            .and_then(|n| n.checked_add(self.fb_offset))
            .filter(|n| n.checked_add(size).is_some_and(|end| end <= 1 << 48))
            .ok_or(Error::Invalid)?;
        tmr.publish();
        self.tmr = Some(tmr);
        self.engine
            .submit(&command(
                5,
                &[
                    address as u32,
                    (address >> 32) as u32,
                    size as u32,
                    2,
                    physical as u32,
                    (physical >> 32) as u32,
                ],
            ))
            .await?;
        self.tmr_ready = true;
        Ok(())
    }
    /// Load signed DMUB instructions through PSP (GFX_FW_TYPE_DMUB = 51).
    /// PSP installs the secure instruction/stack windows; callers must preserve
    /// those windows when configuring the remaining DMUB mailboxes.
    pub async fn load_dmub(&mut self, signed_instructions: &[u8]) -> Result<(), Error> {
        if !self.tmr_ready {
            return Err(Error::Busy);
        }
        let (address, size) = self.stage(signed_instructions).await?;
        let result = self
            .engine
            .submit(&load_command(6, address, size, 51))
            .await;
        self.release_payload();
        result.map(|_| ())
    }
    /// # Safety
    /// Every engine using this TMR (including DMUB) must have verified reset.
    /// Ring destruction alone does not stop instruction fetches from the TMR.
    pub async unsafe fn stop(&mut self) -> Result<(), Error> {
        if self.tmr.is_some() {
            if self.engine.state != State::Ready {
                return Err(Error::Busy);
            }
            self.engine.submit(&command(7, &[])).await?;
            self.tmr_ready = false;
            if let Some(mut tmr) = self.tmr.take() {
                // SAFETY: caller stopped all engines; PSP acknowledged TMR release.
                unsafe {
                    tmr.stopped();
                }
            }
        }
        self.engine.stop().await?;
        if let Some(mut payload) = self.payload.take() {
            // SAFETY: ring destruction acknowledged that PSP no longer reads it.
            unsafe {
                payload.stopped();
            }
        }
        Ok(())
    }
}
pub(crate) fn toc_payload(bytes: &[u8]) -> Result<&[u8], Error> {
    let h = crate::amdgpu_ucode_header::parse_common(bytes).map_err(|_| Error::Invalid)?;
    let end = h
        .ucode_array_offset_bytes
        .checked_add(h.ucode_size_bytes)
        .ok_or(Error::Invalid)?;
    if bytes.len() > MAX_IMAGE + 4096
        || h.size_bytes as usize != bytes.len()
        || h.header_size_bytes < 44
        || (h.header_version_major, h.header_version_minor) != (1, 0)
        || h.ucode_array_offset_bytes < h.header_size_bytes
        || h.ucode_size_bytes == 0
        || h.ucode_size_bytes as usize > MAX_IMAGE
    {
        return Err(Error::Invalid);
    }
    bytes
        .get(h.ucode_array_offset_bytes as usize..end as usize)
        .ok_or(Error::Invalid)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_psp_ring_tests.rs"]
mod tests;
