//! Navi48 SDMA0 cold-start and translated VRAM write/copy/fence proof.
//! Register/packet sources: Linux sdma_v7_0.c, gc_12_0_0_{offset,sh_mask}.h,
//! sdma_v6_0_0_pkt_open.h. Retained kernel fence/TRAP interrupt proof, then
//! client jobs (`Sdma::submit`): a VM flush, PASID mapping, IBs and a fence
//! per 256-dword slot, and a hung ring's reset (`Sdma::reset_ring`). No
//! host DMA.
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
/// `SDMA0_QUEUE_RESET_REQ` (GC segment 0): one bit per queue.
const QUEUE_RESET_REQ: u32 = 0x6c;
/// Client jobs' fence (in the ring allocation, past the pointers).
const JOB_FENCE: u64 = 4160;
/// The ring: 4 KiB at the allocation's start (RB_SIZE 10).
const RING_DWORDS: u64 = 1024;
/// One client job's ring slot.
const JOB_DWORDS: u64 = 256;
/// SDMA0's invalidation engine on the GFX hub: amdgpu_gmc_allocate_vm_inv_eng
/// hands engines out in ring order, the graphics ring 0, the eight compute
/// rings 1-4 and 7-10 (MES keeps 5 and 6), then SDMA0 11.
const INV_ENGINE: u32 = 11;
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
    /// OSSSYS, for the IH VMID LUT a client job maps its PASID in.
    oss: u64,
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
            oss: resolve(ip::HW_ID_OSSSYS, &[(7, 0, 0)], 0, 0x1f)?,
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
/// The ring as sdma_v7_0_gfx_resume_instance programs it, with both
/// pointers at `pointer` bytes: ring at `address`, its pointer writebacks
/// past it, MMIO write pointer, watchdog, UTCL1 policy, the engine
/// unhalted and the ring and IBs enabled.
fn program_ring<I: Io>(io: &mut I, l: Layout, address: u64, pointer: u64) -> Result<(), Error> {
    update(io, l.gc, RB_CNTL, 0x0f803f3f, 0x00801814)?;
    // IB_ENABLE, as sdma_v7_0_gfx_resume sets before enabling the ring:
    // the proofs use direct packets, client jobs IBs.
    update(io, l.gc, 0x89, 0x000f0111, 1)?;
    io.write(l.gc + 0x96 * 4, 0); // no pending preemption
    io.write(l.gc + 0x9b * 4, 1); // permit pointer rewind
    for reg in [0x83, 0x85] {
        io.write(l.gc + reg * 4, pointer as u32);
        io.write(l.gc + (reg + 1) * 4, (pointer >> 32) as u32);
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
    update(io, l.gc, RB_CNTL, 1, 1)
}
/// A slot of nothing but the fence of `seq` (the ring test after a reset,
/// amdgpu_ring_test_ring).
fn fence_words(fence: u64, seq: u32) -> Result<[u32; JOB_DWORDS as usize], Error> {
    let mut slot = Slot {
        words: [0; JOB_DWORDS as usize],
        pos: 0,
    };
    slot.push(&[0x30005, fence as u32, (fence >> 32) as u32, seq])?;
    Ok(slot.words)
}
async fn delay(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}
/// A client job's 256-dword slot, built with sdma_v7_0's ring functions as
/// amdgpu_ib_schedule orders them.
struct Slot {
    words: [u32; JOB_DWORDS as usize],
    pos: usize,
}
impl Slot {
    fn push(&mut self, words: &[u32]) -> Result<(), Error> {
        let end = self.pos + words.len();
        self.words
            .get_mut(self.pos..end)
            .ok_or(Error::Invalid)?
            .copy_from_slice(words);
        self.pos = end;
        Ok(())
    }
    /// sdma_v7_0_ring_emit_wreg: REGISTER_WRITE (the SRBM_WRITE opcode).
    fn wreg(&mut self, reg: u32, value: u32) -> Result<(), Error> {
        self.push(&[14, reg << 2, value])
    }
    /// sdma_v7_0_ring_emit_reg_wait: poll register `reg` until `(value &
    /// mask) == reference`.
    fn reg_wait(&mut self, reg: u32, reference: u32, mask: u32) -> Result<(), Error> {
        self.push(&[8 | 3 << 28, reg << 2, 0, reference, mask, 0xfff << 16 | 10])
    }
}
/// One kernel SDMA operation on VMID0 (framebuffer-aperture) addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelOp {
    /// Fill `bytes` (a multiple of 4) at dword-aligned `dst` with `value`.
    Fill { dst: u64, bytes: u64, value: u32 },
    /// Copy `bytes` from `src` to `dst`, non-overlapping.
    Copy { src: u64, dst: u64, bytes: u64 },
}
/// Bytes one SDMA7 fill or copy packet moves (`fill_max_bytes`,
/// `copy_max_bytes`).
pub const MAX_PACKET_BYTES: u64 = 1 << 30;
/// A kernel job's slot: each op as sdma_v7_0_emit_fill_buffer (CONSTANT_FILL
/// with COMPRESS, dword fill) or sdma_v7_0_emit_copy_buffer (COPY_LINEAR
/// with CPV, no DCC) in packets of at most 1 GiB, then the uncached fence.
/// Refused (`Invalid`) when an op is empty or misaligned or the packets
/// overflow the slot.
fn kernel_words(
    ops: &[KernelOp],
    fence: u64,
    seq: u32,
) -> Result<[u32; JOB_DWORDS as usize], Error> {
    let mut slot = Slot {
        words: [0; JOB_DWORDS as usize],
        pos: 0,
    };
    for &op in ops {
        match op {
            KernelOp::Fill { dst, bytes, value } => {
                if bytes == 0 || bytes % 4 != 0 || dst % 4 != 0 {
                    return Err(Error::Invalid);
                }
                let mut done = 0;
                while done < bytes {
                    let n = (bytes - done).min(MAX_PACKET_BYTES);
                    let at = dst + done;
                    slot.push(&[
                        11 | 1 << 16,
                        at as u32,
                        (at >> 32) as u32,
                        value,
                        (n - 1) as u32,
                    ])?;
                    done += n;
                }
            }
            KernelOp::Copy { src, dst, bytes } => {
                if bytes == 0 || src.max(dst) - src.min(dst) < bytes {
                    return Err(Error::Invalid);
                }
                let mut done = 0;
                while done < bytes {
                    let n = (bytes - done).min(MAX_PACKET_BYTES);
                    let (from, to) = (src + done, dst + done);
                    slot.push(&[
                        1 | 1 << 19,
                        (n - 1) as u32,
                        0,
                        from as u32,
                        (from >> 32) as u32,
                        to as u32,
                        (to >> 32) as u32,
                        0,
                    ])?;
                    done += n;
                }
            }
        }
    }
    if ops.is_empty() {
        return Err(Error::Invalid);
    }
    slot.push(&[0x30005, fence as u32, (fence >> 32) as u32, seq])?;
    Ok(slot.words)
}
/// sdma_v7_0's frame for one client job, as amdgpu_vm_flush and
/// amdgpu_ib_schedule emit it on the ring:
///
/// - when `job.flush`, the pipeline sync (sdma_v7_0_ring_emit_pipeline_sync:
///   poll the fence word until it equals `seq - 1`) and the VM flush
///   (gmc_v12_0_emit_flush_gpu_tlb on the GFX hub through engine 11:
///   context page-table base, then invalidate request and ACK wait);
/// - when `job.map_pasid`, the PASID mapping (IH_VMID_0_LUT + vmid at
///   OSSSYS dword base `oss`);
/// - when `job.mem_sync`, a GCR_REQ cache flush (sdma_v7_0_ring_emit_mem_sync);
/// - always an HDP_FLUSH POLL_REGMEM request/ack for SDMA0 before the IBs,
///   including jobs that reuse a VMID without a page-table flush;
/// - each IB as sdma_v7_0_ring_emit_ib: NOPs so the 6-dword INDIRECT packet
///   ends on an 8-dword boundary (the slot starts on one), the VMID in the
///   header, a 32-byte aligned base and no CSA;
/// - the fence (sdma_v7_0_ring_emit_fence: uncached 32-bit FENCE of `seq`
///   to `fence`), then NOPs (zero) to the slot's end.
///
/// LINUX-GAP: no TRAP after the fence; completion is read from the fence.
fn job_words(
    job: &crate::amdgpu_gfx12_queue::Job,
    gc: u32,
    oss: u32,
    nbio: u32,
    fence: u64,
    seq: u32,
) -> Result<[u32; JOB_DWORDS as usize], Error> {
    let ibs = &job.ibs[..usize::from(job.ib_count).min(job.ibs.len())];
    if !(1..16).contains(&job.vmid)
        || ibs.is_empty()
        || ibs
            .iter()
            .any(|&(at, dwords)| dwords == 0 || dwords > 0xf_ffff || at & 31 != 0)
    {
        return Err(Error::Invalid);
    }
    let mut slot = Slot {
        words: [0; JOB_DWORDS as usize],
        pos: 0,
    };
    let vmid = u32::from(job.vmid);
    if job.flush {
        slot.push(&[
            8 | 3 << 28 | 1 << 31,
            fence as u32 & !3,
            (fence >> 32) as u32,
            seq.wrapping_sub(1),
            u32::MAX,
            0xfff << 16 | 4,
        ])?;
        let hub = &crate::amdgpu_vmhub_regs::GFXHUB_V12_0;
        let eng = hub.eng_distance * INV_ENGINE;
        let ctx = hub.ctx_addr_distance * vmid;
        if hub.semaphore {
            slot.reg_wait(gc + hub.inv_eng0_sem + eng, 1, 1)?;
        }
        slot.wreg(gc + hub.ctx0_pt_base_lo + ctx, job.pd_addr as u32)?;
        slot.wreg(gc + hub.ctx0_pt_base_hi + ctx, (job.pd_addr >> 32) as u32)?;
        slot.wreg(
            gc + hub.inv_eng0_req + eng,
            crate::amdgpu_vmhub_regs::invalidate_req(job.vmid, 0),
        )?;
        slot.reg_wait(gc + hub.inv_eng0_ack + eng, 1 << vmid, 1 << vmid)?;
        if hub.semaphore {
            slot.wreg(gc + hub.inv_eng0_sem + eng, 0)?;
        }
    }
    if job.map_pasid {
        slot.wreg(oss + vmid, u32::from(job.pasid))?;
    }
    if job.mem_sync {
        // sdma_v7_0_ring_emit_mem_sync: GCR_REQ over everything, GL2
        // written back and GL2/GLM/GL1/GLV/GLK/GLI invalidated.
        const GCR: u32 = 1 << 14 | 1 << 15 | 1 << 5 | 1 << 9 | 1 << 8 | 1 << 7 | 1;
        slot.push(&[17, 0, (GCR & 0xffff) << 16, GCR >> 16, 0])?;
    }
    // sdma_v7_0_ring_emit_hdp_flush: the HDP-flush poll writes the
    // reference to REQ then polls DONE (byte register addresses). SDMA0
    // uses bit 10, with Linux's finite retry count and interval.
    slot.push(&[
        8 | 1 << 26 | 3 << 28,
        (nbio + 0x107) << 2,
        (nbio + 0x106) << 2,
        1 << 10,
        1 << 10,
        0xfff << 16 | 10,
    ])?;
    for &(at, dwords) in ibs {
        while (slot.pos + 6) % 8 != 0 {
            slot.push(&[0])?;
        }
        slot.push(&[
            4 | vmid << 16,
            at as u32 & !0x1f,
            (at >> 32) as u32,
            dwords,
            0,
            0,
        ])?;
    }
    slot.push(&[0x30005, fence as u32, (fence >> 32) as u32, seq])?;
    Ok(slot.words)
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
    /// Dwords written to the ring by client jobs so far (0: none yet).
    job_wptr: u64,
    /// The last client job sequence submitted.
    job_seq: u32,
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
            program_ring(io, l, address, 0)
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
    /// Queue one client job after both proofs, in the next 256-dword slot
    /// if the ring has room: the proofs leave 48 dwords used, so the first
    /// job pads the ring with NOPs up to its slot. Pointers are bytes and
    /// 64 bits wide. Returns the job's sequence.
    fn submit(&mut self, job: crate::amdgpu_gfx12_queue::Job) -> Result<u32, Error> {
        let l = self.layout;
        self.submit_slot(|fence, seq| {
            job_words(
                &job,
                (l.gc / 4) as u32,
                (l.oss / 4) as u32,
                (l.nbio / 4) as u32,
                fence,
                seq,
            )
        })
    }
    /// Queue one kernel job (see `kernel_words`) like a client job.
    fn submit_kernel(&mut self, ops: &[KernelOp]) -> Result<u32, Error> {
        self.submit_slot(|fence, seq| kernel_words(ops, fence, seq))
    }
    /// Write the slot `build` makes for the next sequence and its fence
    /// address into the ring, after both proofs, if the ring has room.
    fn submit_slot(
        &mut self,
        build: impl FnOnce(u64, u32) -> Result<[u32; JOB_DWORDS as usize], Error>,
    ) -> Result<u32, Error> {
        if self.state != State::InterruptVerified {
            return Err(Error::Busy);
        }
        let l = self.layout;
        let map = self.memory.mapping();
        // The interrupt proof left both pointers at 192 bytes.
        let wptr = self.job_wptr.max(192 / 4);
        let start = wptr.next_multiple_of(JOB_DWORDS);
        let next = start + JOB_DWORDS;
        let seq = self.job_seq.wrapping_add(1);
        let fence = self.memory.address() + JOB_FENCE;
        let words = build(fence, seq)?;
        self.access(|io| {
            invalidate(io, l);
            let rptr = (u64::from(io.read_memory(map, RPTR))
                | u64::from(io.read_memory(map, RPTR + 4)) << 32)
                / 4;
            if rptr > wptr || next - rptr > RING_DWORDS {
                return Err(Error::Busy);
            }
            for dword in wptr..start {
                io.write_memory(map, dword % RING_DWORDS * 4, 0);
            }
            let slot = start % RING_DWORDS * 4;
            for (i, word) in words.into_iter().enumerate() {
                io.write_memory(map, slot + i as u64 * 4, word);
            }
            let bytes = next * 4;
            io.write_memory(map, WPTR, bytes as u32);
            io.write_memory(map, WPTR + 4, (bytes >> 32) as u32);
            flush(io, l);
            io.write(l.gc + u64::from(RB_WPTR) * 4, bytes as u32);
            io.write(l.gc + u64::from(RB_WPTR + 1) * 4, (bytes >> 32) as u32);
            Ok(())
        })?;
        self.job_wptr = next;
        self.job_seq = seq;
        Ok(seq)
    }
    /// sdma_v7_0_reset_queue for the ring: the MMIO queue reset
    /// (mes_v12_0_reset_queue_mmio: SDMA0_QUEUE_RESET_REQ bit 0, which the
    /// engine clears within amdgpu's usec_timeout), then the ring
    /// programmed again as sdma_v7_0_gfx_resume_instance(restore) does,
    /// both pointers at the software write pointer, so the engine resumes
    /// past every queued slot. The read pointer writeback is set there too,
    /// as nothing writes it before the engine runs.
    async fn reset_ring(&mut self) -> Result<(), Error> {
        if self.state != State::InterruptVerified {
            return Err(Error::Busy);
        }
        let l = self.layout;
        self.access(|io| {
            io.write(l.gc + u64::from(QUEUE_RESET_REQ) * 4, 1);
            Ok(())
        })?;
        let deadline = narf_time::Deadline::after_us(100_000);
        loop {
            let pending = self.access(|io| {
                Ok(checked(io.read(l.gc + u64::from(QUEUE_RESET_REQ) * 4))? & 1 != 0)
            })?;
            if !pending {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay(50).await;
        }
        let (address, map) = (self.memory.address(), self.memory.mapping());
        let pointer = self.job_wptr.max(192 / 4) * 4;
        self.access(|io| {
            for at in [RPTR, WPTR] {
                io.write_memory(map, at, pointer as u32);
                io.write_memory(map, at + 4, (pointer >> 32) as u32);
            }
            flush(io, l);
            program_ring(io, l, address, pointer)
        })
    }
    /// Queue a fence-only slot of the next sequence: the ring test after
    /// `reset_ring`. Once it lands the engine has moved past every earlier
    /// slot.
    fn submit_fence(&mut self) -> Result<u32, Error> {
        self.submit_slot(fence_words)
    }
    /// The last client job sequence the fence reached.
    fn completed_job(&mut self) -> Result<u32, Error> {
        let l = self.layout;
        let map = self.memory.mapping();
        self.access(|io| {
            invalidate(io, l);
            Ok(io.read_memory(map, JOB_FENCE))
        })
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
                job_wptr: 0,
                job_seq: 0,
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
    /// Queue a client job (see `job_words`) after both proofs.
    /// # Safety
    /// As `amdgpu_gfx12_queue::Queues::submit`: the job's page directory,
    /// IBs and everything they reach stay mapped and alive until
    /// `completed_job` passes the returned sequence, its VMID is not moved
    /// by another ring meanwhile, and no one else writes this ring.
    pub unsafe fn submit(&mut self, job: crate::amdgpu_gfx12_queue::Job) -> Result<u32, Error> {
        self.engine.submit(job)
    }
    /// Queue a kernel job of fills and copies on VMID0 addresses, sharing
    /// the client jobs' sequence and fence.
    /// # Safety
    /// Every address the ops name is VRAM (or translated memory) the caller
    /// owns and no one else uses until `completed_job` passes the returned
    /// sequence, and no one else writes this ring.
    pub unsafe fn submit_kernel(&mut self, ops: &[KernelOp]) -> Result<u32, Error> {
        self.engine.submit_kernel(ops)
    }
    /// The last client job sequence SDMA0 completed.
    /// Reset the hung ring (see `Engine::reset_ring`).
    /// # Safety
    /// Every job on the ring keeps the memory it reaches until a later
    /// fence on it lands, and the platform serializes the ring's users.
    pub async unsafe fn reset_ring(&mut self) -> Result<(), Error> {
        self.engine.reset_ring().await
    }
    /// Queue the ring test after a reset (see `Engine::submit_fence`).
    /// # Safety
    /// As `submit`.
    pub unsafe fn submit_fence(&mut self) -> Result<u32, Error> {
        self.engine.submit_fence()
    }
    pub fn completed_job(&mut self) -> Result<u32, Error> {
        self.engine.completed_job()
    }
    /// A reader of the client-job fence that needs no access to this owner.
    pub fn fence_reader(&self) -> FenceReader {
        FenceReader {
            regs: self.engine.io.0,
            authority: self.engine.authority,
            layout: self.engine.layout,
            map: self.engine.memory.mapping(),
        }
    }
}
/// Reads SDMA0's client-job fence without its owner: its own capability,
/// an HDP flush, then the fence word.
#[derive(Clone, Copy, Debug)]
pub struct FenceReader {
    regs: MmioRegion,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    map: MmioRegion,
}
impl FenceReader {
    /// The last client job sequence SDMA0 completed.
    pub fn completed(&self) -> Result<u32, Error> {
        let mut io = Mmio(self.regs);
        let (l, map) = (self.layout, self.map);
        self.authority
            .invoke(Op(|| {
                invalidate(&mut io, l);
                io.read_memory(map, JOB_FENCE)
            }))
            .map_err(|_| Error::Revoked)
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_sdma_navi48_tests.rs"]
mod tests;
