//! Phoenix and Strix Point OSSSYS6 interrupt-vector rings. Register source: Linux
//! `ih_v6_0.c` and the `osssys_6_0_0` offset / shift-mask headers. This
//! owner initially polls; host interrupt delivery stays disabled until an
//! MSI route is installed. Strix Point uses the same rings (`ih_v6_0.c`
//! has no version arms and includes `osssys_6_0_0_offset.h`); only the GC
//! aperture check moves — `FB_LOCATION_BASE`/`TOP` are 0x167c/0x167d on
//! GC 11.5.0, 0x1678/0x1679 on GC 11.0.1 — so the layout carries the
//! FB dwords per die.
//!
//! The v6 ring layout differs from ih7's: ring0 is
//! CNTL 0x80 / BASE 0x81 / BASE_HI 0x82 / RPTR 0x83 / WPTR 0x84 /
//! WPTR_ADDR_HI 0x85 / WPTR_ADDR_LO 0x86 / DOORBELL_RPTR 0x87, ring1 is
//! CNTL 0x8c / BASE 0x8d / BASE_HI 0x8e / RPTR 0x8f / WPTR 0x90 /
//! WPTR_ADDR_HI 0x91 / WPTR_ADDR_LO 0x92 / DOORBELL_RPTR 0x93 — do not
//! copy ih7's CNTL/RPTR/WPTR/BASE order. The `irq_init` extras (storm
//! client, flood control, MSI storm delay, ring1 client redirect, the
//! self-interrupt timer) are the v6 ones, and the retry CAM is skipped:
//! Linux enables it only for non-APU parts, and Phoenix is an APU.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip, amdgpu_gmc_navi31 as gmc,
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
const RPTR: [u64; 2] = [0x83, 0x8f];
const WPTR: [u64; 2] = [0x84, 0x90];
const BASE: [u64; 2] = [0x81, 0x8d];
const DOORBELL: [u64; 2] = [0x87, 0x93];
/// `regIH_RB_WPTR_ADDR_HI` / `_LO`, ring0 only: the WPTR writeback address.
const WPTR_ADDR_HI: u64 = 0x85;
const WPTR_ADDR_LO: u64 = 0x86;
/// `regIH_CNTL2`: the self-interrupt timer.
const CNTL2: u64 = 0xc1;
/// `regIH_STORM_CLIENT_LIST_CNTL`, `regIH_INT_FLOOD_CNTL`,
/// `regIH_MSI_STORM_CTRL`.
const STORM_CLIENT_LIST_CNTL: u64 = 0xda;
const INT_FLOOD_CNTL: u64 = 0xd5;
const MSI_STORM_CTRL: u64 = 0xf1;
/// `regIH_RING1_CLIENT_CFG_INDEX` / `_DATA`: ring1's client redirect.
const RING1_CLIENT_CFG_INDEX: u64 = 0x185;
const RING1_CLIENT_CFG_DATA: u64 = 0x186;
/// `IH_RB_CNTL.WPTR_OVERFLOW_CLEAR`.
const OVERFLOW_CLEAR: u32 = 1 << 31;
/// Consecutive overflowed drains tolerated before the ring is declared lost.
const OVERFLOW_STREAK: u8 = 4;

/// `IH_RB_CNTL` fields (`osssys_6_0_0_sh_mask.h`).
const CNTL_RB_ENABLE: u32 = 0x1;
const CNTL_WPTR_WRITEBACK_ENABLE: u32 = 0x100;
const CNTL_RB_FULL_DRAIN_ENABLE: u32 = 0x200;
const CNTL_RB_USED_INT_THRESHOLD_MASK: u32 = 0xf000;
const CNTL_WPTR_OVERFLOW_ENABLE: u32 = 0x10000;
const CNTL_ENABLE_INTR: u32 = 0x20000;
const CNTL_MC_SNOOP: u32 = 0x100000;
/// `IH_RB_CNTL.MC_SPACE` = 4 (bus-addressable carve-out), bits[30:28].
const CNTL_MC_SPACE_BUS: u32 = 0x4000_0000;
/// `IH_CNTL2` fields.
const CNTL2_SELF_IV_TIMEOUT_MASK: u32 = 0x1f;
const CNTL2_SELF_IV_ENABLE: u32 = 0x100;
/// `IH_STORM_CLIENT_LIST_CNTL.CLIENT18_IS_STORM_CLIENT`.
const STORM_CLIENT18: u32 = 0x40000;
/// `IH_INT_FLOOD_CNTL.FLOOD_CNTL_ENABLE`.
const FLOOD_CNTL_ENABLE: u32 = 0x8;
/// `IH_MSI_STORM_CTRL.DELAY`.
const MSI_STORM_DELAY_MASK: u32 = 0xfff;
/// `IH_RING1_CLIENT_CFG_DATA`: GC client 0xa, source 0, match enabled —
/// the same redirect Linux's `ih_v6_0_irq_init` programs for ring1.
const RING1_CLIENT_CFG_VALUE: u32 = 0xa | (1 << 16);

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
    /// `GCMC_VM_FB_LOCATION_BASE` / `_TOP` dwords: 0x1678/0x1679 on
    /// Phoenix (GC 11.0.1), 0x167c/0x167d on Strix Point (GC 11.5.0).
    fb_base: u32,
    fb_top: u32,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        // DID-gated like the SMU owner: Phoenix is GC 11.0.1, Strix Point
        // is GC 11.5.0 with its FB aperture registers 0x4 higher
        // (`gc_11_5_0_offset.h`). OSSSYS is 6.0.0 for both: `ih_v6_0.c`
        // is version-agnostic, and the 6.0.0 bank is the one Linux's
        // `amdgpu_discovery.c` gives every soc21 part.
        let (gc_version, fb_base, fb_top) = match (gpu.chip.vid, gpu.chip.did) {
            (crate::amdgpu::AMD_VENDOR, crate::amdgpu::PHOENIX_HAWKPOINT1)
            | (crate::amdgpu::AMD_VENDOR, crate::amdgpu::PHOENIX1)
            | (crate::amdgpu::AMD_VENDOR, crate::amdgpu::PHOENIX2) => ((11, 0, 1), 0x1678, 0x1679),
            (crate::amdgpu::AMD_VENDOR, crate::amdgpu::STRIX_POINT) => ((11, 5, 0), 0x167c, 0x167d),
            _ => return Err(Error::Unsupported),
        };
        // Highest dword the owner touches: ring1's client-config data.
        let oss =
            bank(gpu, ip::HW_ID_OSSSYS, &[(6, 0, 0)], 0, 0x186).map_err(|_| Error::Unsupported)?;
        // The GC aperture check reads FB_LOCATION_BASE/TOP.
        let gc =
            bank(gpu, ip::HW_ID_GC, &[gc_version], 0, fb_top).map_err(|_| Error::Unsupported)?;
        Ok(Self {
            oss,
            gc,
            nbio: nbio_bank(gpu)?,
            fb_base,
            fb_top,
        })
    }
    fn at(self, index: u64) -> u64 {
        self.oss + index * 4
    }
}
/// Resolve the NBIF bank without gating on an NBIO version (see the GMC
/// owner): BASE_IDX 2, dword 0x12d, bounded by the BAR. Only the HDP
/// flush read-back goes through it.
fn nbio_bank(gpu: &AmdGpu) -> Result<u64, Error> {
    let ip = ip::find_ip(&gpu.ip_blocks, ip::HW_ID_NBIF, 0).ok_or(Error::Unsupported)?;
    if ip.num_bases < 3 {
        return Err(Error::Unsupported);
    }
    let base = ip.base_addrs[2] as u64 * 4;
    if base
        .checked_add((0x12d_u64 + 1) * 4)
        .is_none_or(|end| end > gpu.regs.len)
    {
        return Err(Error::Invalid);
    }
    Ok(base)
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
    if read(io, l.at(CNTL[0]))? & (CNTL_ENABLE_INTR | CNTL_RB_ENABLE) != 0
        || read(io, l.at(CNTL[1]))? & CNTL_RB_ENABLE != 0
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
/// `ih_v6_0_get_wptr`'s overflow recovery: resume at the oldest vector not yet
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
/// `force_update_wptr_for_self_int`: arm or disarm the self-interrupt
/// timer Linux's `ih_v6_0_irq_init` leaves enabled (threshold 0, timeout
/// 8). The timeout is left at 8 in both states so a later arm is one bit.
fn set_self_interrupt(io: &mut impl Io, l: Layout, enabled: bool) -> Result<(), Error> {
    update(
        io,
        l.at(CNTL2),
        CNTL2_SELF_IV_TIMEOUT_MASK | CNTL2_SELF_IV_ENABLE,
        if enabled { 8 | CNTL2_SELF_IV_ENABLE } else { 8 },
    )?;
    update(io, l.at(CNTL[1]), CNTL_RB_USED_INT_THRESHOLD_MASK, 0)
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
            // `GCMC_VM_FB_LOCATION_BASE/TOP`, the GFX11 aperture the GMC
            // owner programs; the ring must live inside it. The dwords
            // come from the layout (0x1678/0x1679 Phoenix, 0x167c/0x167d
            // Strix) — the hardcoded Phoenix pair would read the wrong
            // registers on Strix.
            let fb = u64::from(read(io, l.gc + u64::from(l.fb_base) * 4)? & 0xffffff) << 24;
            let end = (u64::from(read(io, l.gc + u64::from(l.fb_top) * 4)? & 0xffffff) + 1) << 24;
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
                // MC_SPACE bus + MC_SNOOP, the writeback enable, and ring0's
                // overflow enable / ring1's full drain, per
                // `ih_v6_0_enable_ring`.
                let flags = CNTL_MC_SPACE_BUS
                    | CNTL_MC_SNOOP
                    | size
                    | if ring == 0 {
                        CNTL_WPTR_WRITEBACK_ENABLE | CNTL_WPTR_OVERFLOW_ENABLE
                    } else {
                        CNTL_RB_FULL_DRAIN_ENABLE
                    };
                let mask = if ring == 0 { 0xff7fff3f } else { 0xff5dfe3f };
                update(io, l.at(CNTL[ring]), mask, flags | 0x80000000)?;
                update(io, l.at(CNTL[ring]), 0x80000000, 0)?;
                write(io, l.at(WPTR[ring]), 0)?;
                write(io, l.at(RPTR[ring]), 0)?;
                write(io, l.at(DOORBELL[ring]), 0)?;
            }
            write(io, l.at(WPTR_ADDR_HI), ((address + WRITEBACK) >> 32) as u32)?;
            write(io, l.at(WPTR_ADDR_LO), (address + WRITEBACK) as u32)?;
            // Native GC retry faults use ring1; preserve the indexed selector.
            let old = read(io, l.at(RING1_CLIENT_CFG_INDEX))?;
            let result = (|| {
                update(io, l.at(RING1_CLIENT_CFG_INDEX), 7, 0)?;
                update(
                    io,
                    l.at(RING1_CLIENT_CFG_DATA),
                    0x1ffff,
                    RING1_CLIENT_CFG_VALUE,
                )
            })();
            write(io, l.at(RING1_CLIENT_CFG_INDEX), old)?;
            result?;
            // Storm/flood/MSI setup from `ih_v6_0_irq_init`; the doorbell
            // range and retry CAM are skipped (polling; APU).
            update(
                io,
                l.at(STORM_CLIENT_LIST_CNTL),
                STORM_CLIENT18,
                STORM_CLIENT18,
            )?;
            update(
                io,
                l.at(INT_FLOOD_CNTL),
                FLOOD_CNTL_ENABLE,
                FLOOD_CNTL_ENABLE,
            )?;
            update(io, l.at(MSI_STORM_CTRL), MSI_STORM_DELAY_MASK, 3)?;
            // Disable the inherited self-IV timer during polled bootstrap.
            // Both rings are drained directly, so ring1 cannot strand its
            // vectors.
            update(io, l.at(CNTL2), 0x11f, 8)?;
            update(io, l.at(CNTL[1]), CNTL_RB_ENABLE, CNTL_RB_ENABLE)?;
            update(io, l.at(CNTL[0]), CNTL_RB_ENABLE, CNTL_RB_ENABLE)?;
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
                    update(io, l.at(CNTL[0]), CNTL_ENABLE_INTR | CNTL_RB_ENABLE, 0)?;
                    update(io, l.at(CNTL[1]), CNTL_RB_ENABLE, 0)
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
    /// `force_update_wptr_for_self_int`: arm (`true`) or disarm (`false`) the
    /// self-interrupt timer Linux's `ih_v6_0_irq_init` leaves enabled
    /// (threshold 0, timeout 8). The coordinator's InterruptTest stage arms
    /// it, drains for the self-interrupt entry, then disarms it; bootstrap
    /// leaves it disarmed so ring1 cannot strand vectors.
    pub fn set_self_interrupt(&mut self, enabled: bool) -> Result<(), Error> {
        if self.0.state != State::Ready {
            return Err(Error::Busy);
        }
        let l = self.0.layout;
        let result = self.0.access(|io| set_self_interrupt(io, l, enabled));
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                self.0.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// `ih_v6_0_toggle_ring_interrupts` off, both rings: clear RB_ENABLE so
    /// no new vector is delivered while the coordinator resets the ASIC.
    /// The state returns to Prepared, so [`Self::initialize`] can re-run it
    /// after the reset; the ring reservations are retained.
    pub fn disable(&mut self) -> Result<(), Error> {
        if self.0.state != State::Ready {
            return Err(Error::Busy);
        }
        let l = self.0.layout;
        let result = self.0.access(|io| {
            update(io, l.at(CNTL[0]), CNTL_RB_ENABLE, 0)?;
            update(io, l.at(CNTL[1]), CNTL_RB_ENABLE, 0)
        });
        match result {
            Ok(()) => {
                self.0.state = State::Prepared;
                Ok(())
            }
            Err(e) => {
                self.0.state = State::Failed(e);
                Err(e)
            }
        }
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
#[path = "amdgpu_ih_phoenix_tests.rs"]
mod tests;
