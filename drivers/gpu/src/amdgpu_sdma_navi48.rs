//! Navi48 SDMA0 cold-start and translated VRAM write/copy/fence proof.
//! Register/packet sources: Linux sdma_v7_0.c, gc_12_0_0_{offset,sh_mask}.h,
//! sdma_v6_0_0_pkt_open.h. Retained kernel fence/TRAP interrupt proof; no host
//! DMA, user submissions or recovery.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip, amdgpu_gmc_navi48 as gmc,
    amdgpu_navi48_interrupts::{NativeObserver, Observer, Source},
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
const SEQUENCE: u32 = 0x9070_0048;
const IRQ_FENCE: u64 = 8180; // separate from GC12 and initial SDMA fences
const IRQ_SEQUENCE: u32 = 0x9070_7a48;
const RESET: u32 = 0x0da8;
const MCU_CNTL: u32 = 0x588e; // GC bank one, unlike ring registers
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
    Interrupts(crate::amdgpu_ih7::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Halted,
    Programming,
    Submitted,
    Verified,
    InterruptSubmitted,
    InterruptVerified,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub copied_bytes: u32,
    pub fence: u32,
    pub read_pointer: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterruptProof {
    pub fence: u32,
    pub read_pointer: u64,
    /// A matching IH trap also advanced the configured CPU MSI counter.
    pub msi_verified: bool,
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    gc: u64,
    nbio: u64,
    hyp: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR
            || gpu.chip.did != crate::amdgpu::NAVI48
            || gpu.regs.len < 0x7f004
        {
            return Err(Error::Unsupported);
        }
        let mut blocks = gpu
            .ip_blocks
            .iter()
            .filter(|b| b.hw_id == ip::HW_ID_SDMA0 && b.instance == 0);
        let sdma = blocks.next().ok_or(Error::Unsupported)?;
        if blocks.next().is_some()
            || !matches!((sdma.major, sdma.minor, sdma.revision), (7, 0, 0 | 1))
        {
            return Err(Error::Unsupported);
        }
        let resolve = |id, versions: &[(u8, u8, u8)], index, last| {
            bank(gpu, id, versions, index, last).map_err(|_| Error::Unsupported)
        };
        Ok(Self {
            // SDMA0 is in GC bank zero, NOT the standalone discovery SDMA bank.
            gc: resolve(ip::HW_ID_GC, &[(12, 0, 1)], 0, 0x1615)?,
            nbio: resolve(ip::HW_ID_NBIF, &[(7, 7, 0), (7, 7, 1), (6, 3, 1)], 2, 0x12d)?,
            hyp: resolve(ip::HW_ID_GC, &[(12, 0, 1)], 1, MCU_CNTL)?,
        })
    }
}
trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32;
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32);
    /// Hardware halt settling time. Models may yield deterministically so
    /// cancellation tests need not win a 1-us scheduling window under QEMU.
    async fn halt_delay(&mut self) {
        delay(1).await;
    }
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: Layout bounds GC/NBIO registers and the HDP remap. The
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
    // HDP6 has no invalidate callback; flush posted BAR writes and fence reads.
    flush(io, l);
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
fn interrupt_packets(address: u64) -> [u32; 16] {
    let mut words = [0; 16];
    // Linux sdma_v7_0_ring_emit_fence: uncached 32-bit FENCE followed by
    // TRAP with zero interrupt context. Single-dword NOPs pad to 64 bytes.
    words[..6].copy_from_slice(&[
        0x30005,
        address as u32,
        (address >> 32) as u32,
        IRQ_SEQUENCE,
        6,
        0,
    ]);
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
    interrupt_result: Option<Result<InterruptProof, Error>>,
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
            let fb = u64::from(checked(io.read(l.gc + 0x1614 * 4))? & 0xffffff) << 24;
            let end = (u64::from(checked(io.read(l.gc + 0x1615 * 4))? & 0xffffff) + 1) << 24;
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
            for reg in [0x80, 0xd8, 0x130, 0x188, 0x1e0, 0x238, 0x290, 0x2e8] {
                if checked(io.read(l.gc + reg * 4))? & 1 != 0 {
                    return Err(Error::Busy);
                }
            }
            if checked(io.read(l.gc + 0x24 * 4))? & 1 == 0
                || checked(io.read(l.gc + u64::from(RESET) * 4))? != 0
            {
                return Err(Error::Busy);
            }
            Ok(())
        })?;
        // Quarantine before publication/halting. Cold start preserves PSP's
        // loaded microcode; it never performs a GRBM reset or firmware reload.
        self.memory.publish();
        self.state = State::Halted;
        self.access(|io| {
            update(io, l.hyp, MCU_CNTL, 1, 1)?;
            if checked(io.read(l.hyp + u64::from(MCU_CNTL) * 4))? & 1 == 0 {
                return Err(Error::Invalid);
            }
            Ok(())
        })?;
        self.io.halt_delay().await;
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
            update(io, l.gc, 0x0d, 0xf0023f79, 0x40)?;
            update(io, l.gc, RB_CNTL, 0x0f803f3f, 0x00801814)?;
            update(io, l.gc, 0x89, 0x000f0111, 0)?; // direct packets only
            io.write(l.gc + 0x96 * 4, 0); // no pending preemption
            io.write(l.gc + 0x9b * 4, 1); // permit pointer rewind
            for reg in [0x83, 0x84, 0x85, 0x86] {
                io.write(l.gc + reg * 4, 0);
            }
            for (hi, lo, value) in [(0x88, 0x87, address + RPTR), (0x99, 0x98, address + WPTR)] {
                io.write(l.gc + hi * 4, (value >> 32) as u32);
                io.write(l.gc + lo * 4, value as u32);
            }
            io.write(l.gc + 0x81 * 4, (address >> 8) as u32);
            io.write(l.gc + 0x82 * 4, (address >> 40) as u32);
            update(io, l.gc, 0x8f, 1 << 28, 0)?; // MMIO pointer, no BAR2 doorbell
            io.write(l.gc + 0x9b * 4, 0);
            update(io, l.gc, 0x2b, 0xff, 1)?; // queue watchdog: 100ms
            update(io, l.gc, 0x35, 0x61f, (3 << 9) | 9)?;
            update(io, l.gc, 0x38, !0xff0fff, 0xe000)?; // default read/write policy
            update(io, l.hyp, MCU_CNTL, 3, 0)?;
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
    async fn prove_interrupts(
        &mut self,
        observer: &mut impl Observer,
        aperture: gmc::Aperture,
        target: MmioRegion,
    ) -> Result<InterruptProof, Error> {
        if self.state != State::Verified {
            return Err(Error::Busy);
        }
        // Mark before any await: cancellation must never permit replay.
        self.state = State::InterruptSubmitted;
        let result = self.interrupt_inner(observer, aperture, target).await;
        self.interrupt_result = Some(result);
        self.state = if result.is_ok() {
            State::InterruptVerified
        } else {
            State::Failed
        };
        result
    }
    async fn interrupt_inner(
        &mut self,
        observer: &mut impl Observer,
        aperture: gmc::Aperture,
        target: MmioRegion,
    ) -> Result<InterruptProof, Error> {
        let l = self.layout;
        let map = self.memory.mapping();
        if aperture.start >= (1 << 48) - (2 << 20)
            || aperture.start % (2 << 20) != 0
            || aperture.source != aperture.start
            || aperture.destination != aperture.start + 4096
            || aperture.size != 2 << 20
            || target.len != 8192
        {
            return Err(Error::Invalid);
        }
        let sample = observer
            .sample(Source::Sdma0)
            .await
            .map_err(Error::Interrupts)?;
        self.access(|io| {
            invalidate(io, l);
            let end = (u64::from(checked(io.read(l.gc + 0x1615 * 4))? & 0xffffff) + 1) << 24;
            if end != aperture.start {
                return Err(Error::Invalid);
            }
            for reg in [RB_RPTR, RB_WPTR] {
                if checked(io.read(l.gc + u64::from(reg) * 4))? != 128
                    || checked(io.read(l.gc + u64::from(reg + 1) * 4))? != 0
                {
                    return Err(Error::Busy);
                }
            }
            for offset in [RPTR, WPTR] {
                if io.read_memory(map, offset) != 128 || io.read_memory(map, offset + 4) != 0 {
                    return Err(Error::Busy);
                }
            }
            // The IH service is the sole writer of SDMA0_CNTL after startup.
            if checked(io.read(l.gc + 0x0d * 4))? & 1 == 0
                || checked(io.read(l.gc + u64::from(RB_CNTL) * 4))? & 1 == 0
            {
                return Err(Error::Busy);
            }
            io.write_memory(target, IRQ_FENCE, 0);
            for (i, word) in interrupt_packets(aperture.source + IRQ_FENCE)
                .into_iter()
                .enumerate()
            {
                io.write_memory(map, 128 + i as u64 * 4, word);
            }
            io.write_memory(map, WPTR, 192);
            flush(io, l);
            io.write(l.gc + u64::from(RB_WPTR) * 4, 192);
            io.write(l.gc + u64::from(RB_WPTR + 1) * 4, 0);
            Ok(())
        })?;
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            let memory_done = self.access(|io| {
                invalidate(io, l);
                let lo = checked(io.read(l.gc + u64::from(RB_RPTR) * 4))?;
                let hi = checked(io.read(l.gc + u64::from(RB_RPTR + 1) * 4))?;
                let rptr = u64::from(lo) | (u64::from(hi) << 32);
                let wb = u64::from(io.read_memory(map, RPTR))
                    | (u64::from(io.read_memory(map, RPTR + 4)) << 32);
                if rptr > 192 || wb > 192 {
                    return Err(Error::DataMismatch);
                }
                Ok(rptr == 192 && wb == 192 && io.read_memory(target, IRQ_FENCE) == IRQ_SEQUENCE)
            })?;
            let event_done = observer.observed(sample).await.map_err(Error::Interrupts)?;
            if memory_done && event_done {
                return Ok(InterruptProof {
                    fence: IRQ_SEQUENCE,
                    read_pointer: 192,
                    msi_verified: sample.vector.is_some(),
                });
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
    /// Validate the pool and reserve a VRAM ring/writeback page without writes.
    /// # Safety
    /// Caller owns this physical Navi48 GPU, SDMA0/GC/HDP/PM/reset and the
    /// matching permanent VRAM pool exclusively. No live queues or clients.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        crate::amdgpu_psp_ring::navi48_layout(gpu)
            .and_then(|l| l.validate_pool(gpu, &authority, pool))
            .map_err(|e| match e {
                crate::amdgpu_psp_ring::Error::Revoked => Error::Revoked,
                crate::amdgpu_psp_ring::Error::DeviceGone => Error::DeviceGone,
                _ => Error::Invalid,
            })?;
        Ok(Self {
            engine: Engine {
                layout,
                io: Mmio(gpu.regs),
                authority,
                memory: pool.reserve(BYTES).map_err(|_| Error::Allocation)?,
                state: State::Prepared,
                proof: None,
                interrupt_result: None,
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
    /// Prove one additional kernel fence and SDMA0 queue0 trap after boot.
    /// # Safety
    /// Retain the matching ready GMC and initialized independent IH service,
    /// which exclusively owns SDMA0_CNTL writes. Run from an executor task
    /// with CPU IRQs enabled for MSI. Serialize access to all test pages and
    /// this ring, excluding reset/PM and replay after failure/cancellation.
    pub async unsafe fn prove_interrupts(
        &mut self,
        gmc: &mut gmc::Gmc,
    ) -> Result<InterruptProof, Error> {
        let aperture = gmc.aperture().ok_or(Error::Invalid)?;
        let target = gmc.test_mapping().ok_or(Error::Invalid)?;
        self.engine
            .prove_interrupts(&mut NativeObserver, aperture, target)
            .await
    }
    pub fn interrupt_result(&self) -> Option<Result<InterruptProof, Error>> {
        self.engine.interrupt_result
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_sdma_navi48_tests.rs"]
mod tests;
