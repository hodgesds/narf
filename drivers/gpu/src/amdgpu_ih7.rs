//! Native Navi48 OSSSYS7 interrupt-vector rings. Register source: Linux
//! ih_v7_0.c, amdgpu_ih.c and osssys_7_0_0 headers. This owner initially polls;
//! host interrupt delivery stays disabled until an MSI route is installed.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip, amdgpu_gmc_navi48 as gmc,
    amdgpu_psp_ring::bank,
    amdgpu_vram::{Pool, Reservation},
};
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

const SIZES: [u32; 2] = [256 * 1024, 16 * 1024];
const OFFSETS: [u64; 2] = [0, SIZES[0] as u64];
const WRITEBACK: u64 = OFFSETS[1] + SIZES[1] as u64;
const BYTES: u64 = WRITEBACK + 4096;
const CNTL: [u64; 2] = [0x80, 0x8c];
const RPTR: [u64; 2] = [0x81, 0x8d];
const WPTR: [u64; 2] = [0x82, 0x8e];
const BASE: [u64; 2] = [0x83, 0x8f];
const DOORBELL: [u64; 2] = [0x87, 0x93];
/// IH_RB_CNTL.WPTR_OVERFLOW_CLEAR.
const OVERFLOW_CLEAR: u32 = 1 << 31;
/// Consecutive overflowed drains tolerated before the ring is declared lost.
const OVERFLOW_STREAK: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Readback,
    Overflow(u8),
    Protocol,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Programming,
    Ready,
    Failed(Error),
}
/// The native eight-dword IV layout; source payloads are deliberately retained
/// verbatim for the owning IP. SOC21's GC client is 0x0a, not legacy CP's 0x14.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub client: u8,
    pub source: u8,
    pub ring: u8,
    pub vmid: u8,
    pub vmid_source: bool,
    pub timestamp: u64,
    pub timestamp_source: bool,
    pub pasid: u16,
    pub node: u8,
    pub data: [u32; 4],
}
impl Vector {
    pub const fn decode(dw: [u32; 8]) -> Self {
        Self {
            client: dw[0] as u8,
            source: (dw[0] >> 8) as u8,
            ring: (dw[0] >> 16) as u8,
            vmid: ((dw[0] >> 24) & 15) as u8,
            vmid_source: dw[0] >> 31 != 0,
            timestamp: dw[1] as u64 | (((dw[2] & 0xffff) as u64) << 32),
            timestamp_source: dw[2] >> 31 != 0,
            pasid: dw[3] as u16,
            node: (dw[3] >> 16) as u8,
            data: [dw[4], dw[5], dw[6], dw[7]],
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub ih_ring: u8,
    pub vector: Vector,
}
/// At most sixteen vectors per ring per call: no allocation or unbounded ISR
/// work. A pending batch must be drained again after yielding to the scheduler.
/// `lost` reports a recovered ring0 overflow: vectors were overwritten, so
/// every consumer must re-check its hardware state instead of waiting.
#[derive(Debug)]
pub struct Batch {
    entries: [Option<Event>; 32],
    pub pending: bool,
    pub lost: bool,
}
impl Batch {
    pub(crate) fn from_entries(entries: [Option<Event>; 32], pending: bool) -> Self {
        Self {
            entries,
            pending,
            lost: false,
        }
    }
    pub fn events(&self) -> impl Iterator<Item = &Event> {
        self.entries.iter().flatten()
    }
    pub fn is_empty(&self) -> bool {
        self.entries[0].is_none()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub ring_addresses: [u64; 2],
    pub ring_bytes: [u32; 2],
    pub consumed: [u64; 2],
    pub host_interrupts: bool,
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    oss: u64,
    gc: u64,
    nbio: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if crate::amdgpu_rdna4::Rdna4Chip::of(gpu).is_none() || gpu.regs.len < 0x7f004 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            oss: bank(gpu, ip::HW_ID_OSSSYS, &[(7, 0, 0)], 0, 0x184)
                .map_err(|_| Error::Unsupported)?,
            gc: bank(
                gpu,
                ip::HW_ID_GC,
                crate::amdgpu_rdna4::GC_VERSIONS,
                0,
                0x1615,
            )
            .map_err(|_| Error::Unsupported)?,
            nbio: bank(
                gpu,
                ip::HW_ID_NBIF,
                &[(7, 7, 0), (7, 7, 1), (6, 3, 1)],
                2,
                0x12d,
            )
            .map_err(|_| Error::Unsupported)?,
        })
    }
    fn at(self, index: u64) -> u64 {
        self.oss + index * 4
    }
}
trait Io {
    fn read(&mut self, at: u64) -> u32;
    fn write(&mut self, at: u64, value: u32);
    fn memory_read(&mut self, map: MmioRegion, offset: u64) -> u32;
    fn memory_write(&mut self, map: MmioRegion, offset: u64, value: u32);
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: bounded exact discovery banks, exclusive owner, live invocation.
        unsafe { self.0.read32(at) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: same permanent register mapping, ownership and authority.
        unsafe { self.0.write32(at, value) };
    }
    fn memory_read(&mut self, map: MmioRegion, offset: u64) -> u32 {
        // SAFETY: drain validates pointers against the retained ring allocation.
        unsafe { map.read32(offset) }
    }
    fn memory_write(&mut self, map: MmioRegion, offset: u64, value: u32) {
        // SAFETY: initialization bounds every dword to the owned allocation.
        unsafe { map.write32(offset, value) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn read(io: &mut impl Io, at: u64) -> Result<u32, Error> {
    match io.read(at) {
        u32::MAX => Err(Error::DeviceGone),
        value => Ok(value),
    }
}
fn write(io: &mut impl Io, at: u64, value: u32) -> Result<(), Error> {
    io.write(at, value);
    if read(io, at)? != value {
        return Err(Error::Readback);
    }
    Ok(())
}
fn update(io: &mut impl Io, at: u64, mask: u32, value: u32) -> Result<(), Error> {
    let old = read(io, at)?;
    io.write(at, (old & !mask) | (value & mask));
    if read(io, at)? & mask != value & mask {
        return Err(Error::Readback);
    }
    Ok(())
}
fn flush(io: &mut impl Io, l: Layout) {
    fence(Ordering::SeqCst);
    io.write(0x7f000, 0);
    io.read(l.nbio + 0xc3 * 4);
    fence(Ordering::SeqCst);
}
fn preflight(io: &mut impl Io, l: Layout) -> Result<(), Error> {
    if read(io, l.at(CNTL[0]))? & 0x20001 != 0
        || read(io, l.at(CNTL[1]))? & 1 != 0
        || read(io, l.at(0xc2))? & 0x45 != 0x45
    {
        return Err(Error::Busy);
    }
    Ok(())
}
/// The write offset and RB_OVERFLOW. Only ring0 enables WPTR_OVERFLOW; ring1
/// drains full (RB_FULL_DRAIN), so an overflow there is a protocol failure.
fn pointer(io: &mut impl Io, l: Layout, ring: usize) -> Result<(u32, bool), Error> {
    let raw = read(io, l.at(WPTR[ring]))?;
    if raw & 1 != 0 && ring != 0 {
        return Err(Error::Overflow(ring as u8));
    }
    // RB_LEFT_NONE/RB_MAY_OVERFLOW are hints, not address bits. Reject all
    // remaining undefined bits and partial IVs instead of silently masking.
    let offset = raw & 0x3fffc;
    if raw & !0xffffd != 0 || offset >= SIZES[ring] || offset & 31 != 0 {
        return Err(Error::Protocol);
    }
    Ok((offset, raw & 1 != 0))
}
/// ih_v7_0_get_wptr's overflow recovery: resume at the oldest vector not yet
/// overwritten (WPTR + 32) and pulse WPTR_OVERFLOW_CLEAR so the next overflow
/// is detected. Returns the new ring0 read offset and write offset.
fn recover(io: &mut impl Io, l: Layout, end: u32) -> Result<(u32, u32), Error> {
    let cntl = read(io, l.at(CNTL[0]))?;
    io.write(l.at(CNTL[0]), cntl | OVERFLOW_CLEAR);
    write(io, l.at(CNTL[0]), cntl & !OVERFLOW_CLEAR)?;
    // Still overflowing right after the clear is a storm: fail closed.
    match pointer(io, l, 0)? {
        (_, true) => Err(Error::Overflow(0)),
        (now, false) => Ok(((end + 32) & (SIZES[0] - 1), now)),
    }
}
fn host_control(io: &mut impl Io, l: Layout, enabled: bool) -> Result<(), Error> {
    if enabled {
        update(io, l.at(0xaa), 1 << 18, 1 << 18)?;
        update(io, l.at(0xd5), 8, 8)?;
        update(io, l.at(0xf1), 0xfff, 3)?;
    }
    update(io, l.at(0xc1), 0x11f, if enabled { 0x108 } else { 8 })?;
    update(
        io,
        l.at(CNTL[0]),
        0x220000,
        if enabled { 0x220000 } else { 0 },
    )
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    memory: Reservation,
    state: State,
    rptr: [u32; 2],
    consumed: [u64; 2],
    host_interrupts: bool,
    overflows: u64,
    streak: u8,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> Result<T, Error>) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)?
    }
    fn initialize(&mut self) -> Result<Report, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Programming;
        let result = self.initialize_inner();
        self.state = match result {
            Ok(_) => State::Ready,
            Err(e) => State::Failed(e),
        };
        result
    }
    fn initialize_inner(&mut self) -> Result<Report, Error> {
        let l = self.layout;
        let address = self.memory.address();
        let map = self.memory.mapping();
        self.access(|io| {
            preflight(io, l)?;
            let fb = u64::from(read(io, l.gc + 0x1614 * 4)? & 0xffffff) << 24;
            let end = (u64::from(read(io, l.gc + 0x1615 * 4)? & 0xffffff) + 1) << 24;
            if address < fb
                || address
                    .checked_add(BYTES)
                    .is_none_or(|a| a > end || a >= 1 << 48)
                || read(io, l.nbio + 0x12d * 4)? != 0x7f000
            {
                return Err(Error::Invalid);
            }
            for at in (0..BYTES).step_by(4) {
                io.memory_write(map, at, 0);
            }
            flush(io, l);
            Ok(())
        })?;
        self.memory.publish();
        self.access(|io| {
            for ring in 0..2 {
                let base = address + OFFSETS[ring];
                write(io, l.at(BASE[ring]), (base >> 8) as u32)?;
                write(io, l.at(BASE[ring] + 1), (base >> 40) as u32)?;
                let size = (SIZES[ring] / 4).ilog2() << 1;
                // VMID0 GPU address space; no unprotected host physical DMA.
                // No MSI/INTx delivery, rearm or doorbell until host setup.
                let flags = 0x40100000 | size | if ring == 0 { 0x10100 } else { 0x200 };
                let mask = if ring == 0 { 0xff7fff3f } else { 0xff5dfe3f };
                update(io, l.at(CNTL[ring]), mask, flags | 0x80000000)?;
                update(io, l.at(CNTL[ring]), 0x80000000, 0)?;
                write(io, l.at(WPTR[ring]), 0)?;
                write(io, l.at(RPTR[ring]), 0)?;
                write(io, l.at(DOORBELL[ring]), 0)?;
            }
            write(io, l.at(0x85), ((address + WRITEBACK) >> 32) as u32)?;
            write(io, l.at(0x86), (address + WRITEBACK) as u32)?;
            // Native GC retry faults use ring1; preserve the indexed selector.
            let old = read(io, l.at(0x183))?;
            let result = (|| {
                update(io, l.at(0x183), 7, 0)?;
                update(io, l.at(0x184), 0x1ffff, 0x1000a)
            })();
            write(io, l.at(0x183), old)?;
            result?;
            // Disable inherited self-IV timers during polled bootstrap. Both
            // rings are drained directly, so ring1 cannot strand its vectors.
            update(io, l.at(0xc1), 0x11f, 8)?;
            update(io, l.at(CNTL[1]), 1, 1)?;
            update(io, l.at(CNTL[0]), 1, 1)?;
            Ok(())
        })?;
        Ok(self.report())
    }
    fn report(&self) -> Report {
        Report {
            ring_addresses: OFFSETS.map(|at| self.memory.address() + at),
            ring_bytes: SIZES,
            consumed: self.consumed,
            host_interrupts: self.host_interrupts,
        }
    }
    fn drain(&mut self) -> Result<Batch, Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        let l = self.layout;
        let map = self.memory.mapping();
        let mut next = self.rptr;
        let mut counts = [0u64; 2];
        let (start, streak) = (self.rptr, self.streak);
        let result = self.access(|io| {
            let mut batch = Batch {
                entries: [None; 32],
                pending: false,
                lost: false,
            };
            let (mut end0, overflow) = pointer(io, l, 0)?;
            let mut ends = [end0, pointer(io, l, 1)?.0];
            for ring in 0..2 {
                if read(io, l.at(CNTL[ring]))? & 1 == 0 || read(io, l.at(RPTR[ring]))? != next[ring]
                {
                    return Err(Error::Protocol);
                }
            }
            if overflow {
                if streak >= OVERFLOW_STREAK {
                    return Err(Error::Overflow(0));
                }
                (next[0], end0) = recover(io, l, end0)?;
                ends[0] = end0;
                batch.lost = true;
            }
            flush(io, l);
            let mut count = 0;
            for ring in 0..2 {
                for _ in 0..16 {
                    if next[ring] == ends[ring] {
                        break;
                    }
                    let at = OFFSETS[ring] + u64::from(next[ring]);
                    let mut words = [0; 8];
                    for (i, word) in words.iter_mut().enumerate() {
                        *word = io.memory_read(map, at + i as u64 * 4);
                    }
                    batch.entries[count] = Some(Event {
                        ih_ring: ring as u8,
                        vector: Vector::decode(words),
                    });
                    count += 1;
                    counts[ring] += 1;
                    next[ring] = (next[ring] + 32) & (SIZES[ring] - 1);
                }
            }
            // An overflow racing the copy invalidates the entire batch. Never
            // consume a torn/overwritten vector; ring1 entries stay unread.
            let (now, raced) = pointer(io, l, 0)?;
            if raced {
                if streak + u8::from(batch.lost) >= OVERFLOW_STREAK {
                    return Err(Error::Overflow(0));
                }
                batch.entries = [None; 32];
                counts = [0; 2];
                (next[0], _) = recover(io, l, now)?;
                next[1] = start[1];
                batch.lost = true;
                batch.pending = true;
            } else {
                batch.pending |= now != next[0];
            }
            batch.pending |= pointer(io, l, 1)?.0 != next[1];
            fence(Ordering::SeqCst);
            for ring in 0..2 {
                write(io, l.at(RPTR[ring]), next[ring])?;
            }
            Ok(batch)
        });
        match result {
            Ok(batch) => {
                self.rptr = next;
                for (total, count) in self.consumed.iter_mut().zip(counts) {
                    *total = total.saturating_add(count);
                }
                if batch.lost {
                    self.overflows = self.overflows.saturating_add(1);
                    self.streak = self.streak.saturating_add(1);
                } else {
                    self.streak = 0;
                }
                Ok(batch)
            }
            Err(e) => {
                self.state = State::Failed(e);
                self.host_interrupts = false;
                // Stop owned writers when authority is still valid. A revoked
                // cap performs no further accesses; the backing remains retained.
                let _ = self.access(|io| {
                    update(io, l.at(CNTL[0]), 0x20001, 0)?;
                    update(io, l.at(CNTL[1]), 1, 0)
                });
                Err(e)
            }
        }
    }
}
#[derive(Debug)]
pub struct Rings(Engine<Mmio>);
impl Rings {
    /// # Safety
    /// Own this physical GPU, permanent mappings, the inventory-derived free
    /// VRAM pool, all IH sources/indexing/reset/PM, and its PCI interrupt route.
    /// The retained owner must outlive any published address, including errors.
    /// Preparation reads hardware but never writes it; existing IH is refused.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        let mut io = Mmio(gpu.regs);
        authority
            .invoke(Op(|| preflight(&mut io, layout)))
            .map_err(|_| Error::Revoked)??;
        Ok(Self(Engine {
            io,
            authority,
            layout,
            memory: pool.reserve(BYTES).map_err(|_| Error::Allocation)?,
            state: State::Prepared,
            rptr: [0; 2],
            consumed: [0; 2],
            host_interrupts: false,
            overflows: 0,
            streak: 0,
        }))
    }
    /// # Safety
    /// Same GPU's authenticated firmware, trained VRAM and ready GMC/MMHUB0.
    /// Own VMID0, both IH rings and all sources; no concurrent reset or PM.
    pub unsafe fn initialize(&mut self, gmc: &gmc::Gmc) -> Result<Report, Error> {
        if !gmc.state().vmid0_ready() {
            return Err(Error::Busy);
        }
        self.0.initialize()
    }
    pub fn state(&self) -> State {
        self.0.state
    }
    /// # Safety
    /// Enabling requires an installed CPU handler/route for this same physical
    /// function and a retained consumer. Serialize PCI route and IH changes.
    pub(crate) unsafe fn host_interrupts(&mut self, enabled: bool) -> Result<(), Error> {
        if self.0.state != State::Ready {
            return Err(Error::Busy);
        }
        let l = self.0.layout;
        let result = self.0.access(|io| host_control(io, l, enabled));
        match result {
            Ok(()) => self.0.host_interrupts = enabled,
            Err(e) => self.0.state = State::Failed(e),
        }
        result
    }
    pub fn report(&self) -> Option<Report> {
        (self.0.state == State::Ready).then(|| self.0.report())
    }
    /// Drain both rings with a bounded budget; no source is treated as a fence
    /// without separate validation by its owning engine. A ring0 overflow is
    /// recovered as Linux does and reported through `Batch::lost`; repeated
    /// overflow, ring1 overflow and every other inconsistency fail closed.
    pub fn drain(&mut self) -> Result<Batch, Error> {
        self.0.drain()
    }
    /// Recovered ring0 overflows since initialization.
    pub fn overflows(&self) -> u64 {
        self.0.overflows
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_ih7_tests.rs"]
mod tests;
