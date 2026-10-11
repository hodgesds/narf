//! Navi22 SDMA0 cold-start and translated VRAM write/copy/fence proof.
//! Register/packet sources: Linux sdma_v5_2.c, gc_10_3_0_{offset,sh_mask}.h,
//! navi10_sdma_pkt_open.h. No host DMA, user submissions, IRQs or recovery.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip, amdgpu_gmc_navi22 as gmc,
    amdgpu_psp_ring::bank,
    amdgpu_vram::{Pool, Reservation},
};
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
const BYTES: u64 = 8192;
const RPTR: u64 = 4096;
const WPTR: u64 = 4104;
const FENCE: u64 = 8188; // last dword of GMC's destination page
const SEQUENCE: u32 = 0x6750_0022;
const RESET: u32 = 0x0da8;
const RESET_SDMA0: u32 = 1 << 23;
const RB_CNTL: u32 = 0x80;
const RB_RPTR: u32 = 0x83;
const RB_WPTR: u32 = 0x85;
const PATTERN: [u32; 16] = [
    0x01234567, 0x89abcdef, 0x76543210, 0xfedcba98, 0xaaaaaaaa, 0x55555555, 0xff00ff00, 0x00ff00ff,
    0x00000001, 0x80000000, 0x01010101, 0x10101010, 0x67506750, 0x00220022, 0xdeadbeef, 0xcafebabe,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Timeout,
    DataMismatch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    ResetAsserted,
    ResetReleased,
    Programming,
    Submitted,
    Verified,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub copied_bytes: u32,
    pub fence: u32,
    pub read_pointer: u64,
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    gc: u64,
    nbio: u64,
    hdp: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR
            || gpu.chip.did != crate::amdgpu::NAVI22
            || gpu.regs.len < 0x7f004
        {
            return Err(Error::Unsupported);
        }
        let mut blocks = gpu
            .ip_blocks
            .iter()
            .filter(|b| b.hw_id == ip::HW_ID_SDMA0 && b.instance == 0);
        let sdma = blocks.next().ok_or(Error::Unsupported)?;
        if blocks.next().is_some() || (sdma.major, sdma.minor, sdma.revision) != (5, 2, 2) {
            return Err(Error::Unsupported);
        }
        let resolve = |id, versions: &[(u8, u8, u8)], index, last| {
            bank(gpu, id, versions, index, last).map_err(|_| Error::Unsupported)
        };
        Ok(Self {
            // SDMA0 is in GC bank zero, NOT the standalone discovery SDMA bank.
            gc: resolve(ip::HW_ID_GC, &[(10, 3, 2)], 0, 0x16fd)?,
            nbio: resolve(
                ip::HW_ID_NBIF,
                &[
                    (2, 3, 0),
                    (2, 3, 1),
                    (2, 3, 2),
                    (3, 3, 0),
                    (3, 3, 1),
                    (3, 3, 2),
                    (3, 3, 3),
                ],
                2,
                0x12d,
            )?,
            hdp: resolve(
                ip::HW_ID_HDP,
                &[(5, 0, 0), (5, 0, 1), (5, 0, 2), (5, 0, 3), (5, 0, 4)],
                0,
                0xd1,
            )?,
        })
    }
}
trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32;
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32);
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: Layout bounds GC/NBIO/HDP registers and the HDP remap. The
        // exclusive owner invokes every I/O batch under live PCI authority.
        unsafe { self.0.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: same validated register mapping and live authority.
        unsafe { self.0.write32(address, value) };
    }
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32 {
        // SAFETY: internal offsets are bounded by the retained ring allocation
        // or the borrowed GMC's two owned test pages, both permanently mapped.
        unsafe { map.read32(offset) }
    }
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        // SAFETY: same retained allocations and bounded dword offsets.
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
fn checked(value: u32) -> Result<u32, Error> {
    if value == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(value)
    }
}
fn update<I: Io>(io: &mut I, gc: u64, reg: u32, mask: u32, value: u32) -> Result<(), Error> {
    let address = gc + u64::from(reg) * 4;
    let old = checked(io.read(address))?;
    io.write(address, (old & !mask) | value);
    Ok(())
}
fn flush<I: Io>(io: &mut I, l: Layout) {
    fence(Ordering::SeqCst);
    io.write(0x7f000, 0);
    io.read(l.nbio + 0xc3 * 4);
    fence(Ordering::SeqCst);
}
fn invalidate<I: Io>(io: &mut I, l: Layout) {
    io.write(l.hdp + 0xd1 * 4, 1);
    io.read(l.hdp + 0xd1 * 4);
    fence(Ordering::SeqCst);
}
fn packets(aperture: gmc::Aperture) -> [u32; 32] {
    let mut words = [0; 32];
    words[..4].copy_from_slice(&[
        2,
        aperture.source as u32,
        (aperture.source >> 32) as u32,
        15,
    ]);
    words[4..20].copy_from_slice(&PATTERN);
    words[20..27].copy_from_slice(&[
        1,
        63,
        0,
        aperture.source as u32,
        (aperture.source >> 32) as u32,
        aperture.destination as u32,
        (aperture.destination >> 32) as u32,
    ]);
    let address = aperture.destination + 4092;
    words[27..31].copy_from_slice(&[0x30005, address as u32, (address >> 32) as u32, SEQUENCE]);
    // Single-dword NOP pads the submission to a sixteen-dword boundary.
    words
}
async fn delay(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    memory: Reservation,
    state: State,
    proof: Option<Proof>,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> Result<T, Error>) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)?
    }
    async fn initialize(
        &mut self,
        aperture: gmc::Aperture,
        target: MmioRegion,
    ) -> Result<Proof, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Programming;
        let result = self.initialize_inner(aperture, target).await;
        self.state = if result.is_ok() {
            State::Verified
        } else {
            State::Failed
        };
        if let Ok(proof) = result {
            self.proof = Some(proof);
        }
        result
    }
    async fn initialize_inner(
        &mut self,
        aperture: gmc::Aperture,
        target: MmioRegion,
    ) -> Result<Proof, Error> {
        let l = self.layout;
        let address = self.memory.address();
        self.access(|io| {
            let fb = u64::from(checked(io.read(l.gc + 0x16fc * 4))? & 0xffffff) << 24;
            let end = (u64::from(checked(io.read(l.gc + 0x16fd * 4))? & 0xffffff) + 1) << 24;
            if target.len != 8192
                || address < fb
                || address.checked_add(BYTES).is_none_or(|v| v > end)
                || end >= 1 << 48
                || aperture.start != end
                || aperture.size != 2 << 20
                || aperture.source != aperture.start
                || aperture.destination != aperture.start + 4096
                || checked(io.read(l.nbio + 0x12d * 4))? != 0x7f000
            {
                return Err(Error::Invalid);
            }
            // Never reset an inherited ring or a concurrently owned engine.
            for reg in [0x80, 0xd8, 0x130, 0x188] {
                if checked(io.read(l.gc + reg * 4))? & 1 != 0 {
                    return Err(Error::Busy);
                }
            }
            if checked(io.read(l.gc + 0x25 * 4))? & 1 == 0
                || checked(io.read(l.gc + u64::from(RESET) * 4))? != 0
            {
                return Err(Error::Busy);
            }
            Ok(())
        })?;
        // Publish before reset/programming so every started attempt retains
        // ring/writeback storage even if its future is cancelled mid-reset.
        self.memory.publish();
        self.state = State::ResetAsserted;
        self.access(|io| {
            update(io, l.gc, RESET, RESET_SDMA0, RESET_SDMA0)?;
            checked(io.read(l.gc + u64::from(RESET) * 4))?;
            Ok(())
        })?;
        delay(50).await;
        self.state = State::ResetReleased;
        self.access(|io| {
            update(io, l.gc, RESET, RESET_SDMA0, 0)?;
            checked(io.read(l.gc + u64::from(RESET) * 4))?;
            Ok(())
        })?;
        delay(50).await;
        self.state = State::Programming;
        let map = self.memory.mapping();
        let words = packets(aperture);
        self.access(|io| {
            for offset in (0..BYTES).step_by(4) {
                io.write_memory(map, offset, 0);
            }
            for (i, value) in words.into_iter().enumerate() {
                io.write_memory(map, i as u64 * 4, value);
            }
            for offset in (0..8192).step_by(4) {
                io.write_memory(target, offset, 0);
            }
            flush(io, l);
            // Only one privileged direct ring, VMID0. No traps, paging IRQs,
            // preemption, automatic context switches or indirect buffers.
            update(io, l.gc, 0x1c, 0x700600bf, 2)?;
            update(io, l.gc, 0x2a, 1, 1)?; // halt while programming
            io.write(l.gc + 0x21 * 4, 0);
            update(io, l.gc, RB_CNTL, 0x0f80323f, 0x00801014)?;
            update(io, l.gc, 0x8a, 0x000f0011, 0)?;
            io.write(l.gc + 0xb5 * 4, 1);
            for reg in [0x83, 0x84, 0x85, 0x86] {
                io.write(l.gc + reg * 4, 0);
            }
            for (hi, lo, value) in [(0x88, 0x89, address + RPTR), (0xb2, 0xb3, address + WPTR)] {
                io.write(l.gc + hi * 4, (value >> 32) as u32);
                io.write(l.gc + lo * 4, value as u32);
            }
            io.write(l.gc + 0x81 * 4, (address >> 8) as u32);
            io.write(l.gc + 0x82 * 4, (address >> 40) as u32);
            update(io, l.gc, 0x87, 4, 4)?;
            update(io, l.gc, 0x92, 1 << 28, 0)?; // MMIO wptr, no BAR2 doorbell
            io.write(l.gc + 0xb5 * 4, 0);
            update(io, l.gc, 0x3c, 0xe3e, (3 << 9) | (9 << 1))?;
            update(io, l.gc, 0x48, !0xff0fff, 0x0100e000)?; // NOA read, bypass write
            update(io, l.gc, 0x2a, 1, 0)?;
            update(io, l.gc, RB_CNTL, 1, 1)?;
            Ok(())
        })?;
        self.state = State::Submitted;
        self.access(|io| {
            io.write_memory(map, WPTR, 128); // pointers are bytes, not dwords
            flush(io, l);
            io.write(l.gc + u64::from(RB_WPTR) * 4, 128);
            io.write(l.gc + u64::from(RB_WPTR + 1) * 4, 0);
            Ok(())
        })?;
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            let proof = self.access(|io| {
                invalidate(io, l);
                let fence = io.read_memory(target, FENCE);
                let lo = checked(io.read(l.gc + u64::from(RB_RPTR) * 4))?;
                let hi = checked(io.read(l.gc + u64::from(RB_RPTR + 1) * 4))?;
                let read_pointer = u64::from(lo) | (u64::from(hi) << 32);
                let writeback = u64::from(io.read_memory(map, RPTR))
                    | (u64::from(io.read_memory(map, RPTR + 4)) << 32);
                if fence != SEQUENCE || read_pointer != 128 || writeback != 128 {
                    return Ok(None);
                }
                for (i, value) in PATTERN.into_iter().enumerate() {
                    for page in [0, 4096] {
                        if io.read_memory(target, page + i as u64 * 4) != value {
                            return Err(Error::DataMismatch);
                        }
                    }
                }
                Ok(Some(Proof {
                    copied_bytes: 64,
                    fence,
                    read_pointer,
                }))
            })?;
            if let Some(proof) = proof {
                return Ok(proof);
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay(1000).await;
        }
    }
}
#[derive(Debug)]
pub struct Sdma {
    engine: Engine<Mmio>,
}
impl Sdma {
    /// Reserve a VRAM ring and writeback page without I/O.
    /// # Safety
    /// Caller owns this physical Navi22 GPU, SDMA0/GC/HDP/PM/reset and the
    /// matching permanent VRAM pool exclusively. No live queues or clients.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        Ok(Self {
            engine: Engine {
                layout: Layout::resolve(gpu)?,
                io: Mmio(gpu.regs),
                authority,
                memory: pool.reserve(BYTES).map_err(|_| Error::Allocation)?,
                state: State::Prepared,
                proof: None,
            },
        })
    }
    /// Start SDMA0 and prove translated VRAM write/copy/fence execution once.
    /// # Safety
    /// PSP/RLC/SDMA firmware is ready, trained VRAM and the matching GPU's GMC
    /// translations are retained, gating is disabled, and new's ownership
    /// contract still holds. No second owner/reset after cancellation/failure.
    pub async unsafe fn initialize(&mut self, gmc: &mut gmc::Gmc) -> Result<Proof, Error> {
        let aperture = gmc.aperture().ok_or(Error::Invalid)?;
        let target = gmc.test_mapping().ok_or(Error::Invalid)?;
        self.engine.initialize(aperture, target).await
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    pub fn proof(&self) -> Option<Proof> {
        self.engine.proof
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_sdma_navi22_tests.rs"]
mod tests;
