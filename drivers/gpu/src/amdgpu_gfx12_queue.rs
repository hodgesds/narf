//! Two retained VMID0 GC12 kernel queues, with a bounded translated-memory
//! WRITE_DATA and native EOP-interrupt proofs, then client jobs on either
//! queue: each a VM flush for the client's VMID, its IBs and a fence
//! (`submit`). A hung compute queue can be reset by MMIO and restored for
//! MES to map again (`reset_compute_hqd`, `restore`). An explicit wave32 shader
//! proof runs on the same owned aperture before client submissions.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip, amdgpu_gmc_navi48 as gmc, amdgpu_mes12 as api, amdgpu_mes12_hw as mes,
    amdgpu_navi48_interrupts::{NativeObserver, Observer, Source},
    amdgpu_psp_ring::bank,
    amdgpu_vram::{Pool, Reservation},
};
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
const PIPE_BYTES: u64 = 12288;
const BYTES: u64 = PIPE_BYTES * 2;
const RPTR: u64 = 10240;
const WPTR: u64 = 10248;
const BELLS: [u32; 2] = [0x116, 6];
/// Each queue's job fence (within its pipe's area): the last completed
/// job's sequence.
const JOB_FENCE: u64 = 10496;
/// A kernel queue that runs client jobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pipe {
    Graphics = 0,
    Compute = 1,
}
impl Pipe {
    fn index(self) -> usize {
        self as usize
    }
    /// The pipe's area in the queue memory.
    fn base(self) -> u64 {
        self.index() as u64 * PIPE_BYTES
    }
    /// The ring's invalidation engine on the GFX hub, as
    /// amdgpu_gmc_allocate_vm_inv_eng hands engines out in ring order: the
    /// graphics ring 0, the first compute ring 1 (MES reserves 5 and 6; the
    /// kernel's CPU invalidations use 17).
    fn engine(self) -> u32 {
        self.index() as u32
    }
}
/// One job's ring slot: GC12's 256-dword submission alignment.
const JOB_DWORDS: u64 = 256;
/// Ring capacity in dwords (4 KiB).
const RING_DWORDS: u64 = 1024;

/// `CP_HQD_DEQUEUE_REQUEST`, `SPI_COMPUTE_QUEUE_RESET` and
/// `CP_HQD_ACTIVE` (GC segment 0).
const DEQUEUE_REQUEST: u64 = 0x1fc1;
const COMPUTE_QUEUE_RESET: u64 = 0x1f73;
const HQD_ACTIVE: u64 = 0x1fab;
/// GC segment 1: RLC safe-mode handshake and the RS64 MEC pipe control.
const RLC_CNTL: u64 = 0x4c00;
const RLC_SAFE_MODE: u64 = 0x980;
const MEC_RS64_CNTL: u64 = 0x2904;
const MEC_PIPE0_RESET: u32 = 1 << 16;
/// GRBM_GFX_CNTL selecting the compute queue: MEC1 (MEID 1, bits 3:2),
/// pipe 0, queue 0.
const COMPUTE_SELECT: u32 = 4;
/// PACKET3(NOP, 0x3fff), what amdgpu_ring_clear_ring fills a ring with.
const RING_NOP: u32 = 0xffff_1000;
const FENCES: [u32; 2] = [0x9070cafe, 0x9070beef];
const PATTERN: [u32; 16] = [
    0x01234567, 0x89abcdef, 0x76543210, 0xfedcba98, 0xaaaaaaaa, 0x55555555, 0xff00ff00, 0x00ff00ff,
    1, 0x80000000, 0x01010101, 0x10101010, 0x90709070, 0x00480048, 0xdeadbeef, 0xcafebabe,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Readback,
    Timeout,
    DataMismatch,
    Mes(mes::Error),
    Interrupts(crate::amdgpu_ih7::Error),
    Gmc(gmc::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Mapping(u8),
    Submitted(u8),
    Verified,
    InterruptSubmitted(u8),
    InterruptVerified,
    /// Code publication or shader dispatch; cancellation keeps both queues shut.
    ShaderSubmitted(u8),
    /// A dropped recovery keeps both queues quarantined.
    ResettingCompute,
    /// The HQD reset completed; MES must unmap it before `restore`.
    ComputeReset,
    Failed(Error),
}
/// A client job: IBs in VMID `vmid`'s address space, whose page directory
/// is `pd_addr` (the root's entry address with VALID, as
/// gmc_v12_0_get_vm_pde leaves it). `flush` points the VMID's context at
/// `pd_addr` and invalidates its TLB first; `map_pasid` rewrites its IH LUT
/// entry (`amdgpu_vmid::VmidManager` decides both).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Job {
    pub vmid: u8,
    /// The client's PASID, mapped to `vmid` in the IH VMID LUT so a fault
    /// names the client.
    pub pasid: u16,
    pub pd_addr: u64,
    /// The job's IBs in order, `(address, dwords)`; `ib_count` are used.
    pub ibs: [(u64, u32); MAX_JOB_IBS],
    pub ib_count: u8,
    pub flush: bool,
    pub map_pasid: bool,
    /// The ring's previous job came from another context
    /// (`AMDGPU_HAVE_CTX_SWITCH`): CONTEXT_CONTROL reloads state.
    pub ctx_switch: bool,
    /// The first IB asked for `AMDGPU_IB_FLAG_EMIT_MEM_SYNC`: invalidate
    /// and write back the GPU caches before the IBs.
    pub mem_sync: bool,
}
/// IBs one job may carry: all fit one 256-dword slot beside the flush,
/// PASID mapping and fence.
pub const MAX_JOB_IBS: usize = 8;
impl Job {
    /// A job of `ibs` (at most `MAX_JOB_IBS`).
    pub fn new(vmid: u8, pasid: u16, pd_addr: u64, ibs: &[(u64, u32)]) -> Option<Self> {
        if ibs.is_empty() || ibs.len() > MAX_JOB_IBS {
            return None;
        }
        let mut all = [(0, 0); MAX_JOB_IBS];
        all[..ibs.len()].copy_from_slice(ibs);
        Some(Self {
            vmid,
            pasid,
            pd_addr,
            ibs: all,
            ib_count: ibs.len() as u8,
            flush: true,
            map_pasid: true,
            ctx_switch: true,
            mem_sync: false,
        })
    }
    fn ibs(&self) -> &[(u64, u32)] {
        &self.ibs[..usize::from(self.ib_count).min(MAX_JOB_IBS)]
    }
}
/// gfx_v12_0's frame for one job on the graphics ring, as amdgpu_vm_flush
/// and amdgpu_ib_schedule emit it: when `job.flush`, a pipeline sync (wait
/// for the ring's fence to reach `seq - 1`) and the VM flush
/// (gmc_v12_0_emit_flush_gpu_tlb on the GFX hub through the ring's engine,
/// then PFP_SYNC_ME); when `job.map_pasid`, the PASID mapping (gmc_v12_0_emit_pasid_mapping: IH_VMID_0_LUT + vmid at OSSSYS
/// base `oss`); when `job.mem_sync`, ACQUIRE_MEM; on the graphics ring,
/// CONTEXT_CONTROL (reloading state when `job.ctx_switch`); the IBs under
/// the job's VMID, and an interrupting RELEASE_MEM
/// of `seq` to `fence`, NOP-padded to the 256-dword slot.
///
/// On the compute pipe, as gfx_v12_0's compute ring functions: register
/// writes without the PFP engine select, no PFP_SYNC_ME or CONTEXT_CONTROL,
/// the ring's own invalidation engine, and IBs marked
/// `INDIRECT_BUFFER_VALID`. Every job requests an HDP flush and waits for
/// its engine's acknowledgement before CONTEXT_CONTROL/IB execution, even
/// when its VMID is reused without a page-table flush.
fn job_packets(
    pipe: Pipe,
    job: Job,
    gc: u32,
    oss: u32,
    nbio: u32,
    fence: u64,
    seq: u32,
) -> Result<[u32; 256], Error> {
    let gfx = pipe == Pipe::Graphics;
    use crate::amdgpu_pm4::Pm4Builder;
    if !(1..16).contains(&job.vmid)
        || job.ibs().is_empty()
        || job
            .ibs()
            .iter()
            .any(|&(at, dwords)| dwords == 0 || dwords > 0xf_ffff || at & 3 != 0)
    {
        return Err(Error::Invalid);
    }
    let mut words = [0u32; 256];
    let mut b = Pm4Builder::new(&mut words);
    let built = (|| {
        if job.flush {
            // amdgpu_vm_flush's pipeline sync: the ring's previous job must
            // finish before the context moves (gfx_v12_0_ring_emit_pipeline_sync
            // waits for the last fence written, which init zeroed).
            b.wait_reg_mem(
                gfx,
                true,
                false,
                fence as u32,
                (fence >> 32) as u32,
                seq.wrapping_sub(1),
                u32::MAX,
                4,
            )?;
            b.vm_flush(
                &crate::amdgpu_vmhub_regs::GFXHUB_V12_0,
                gc,
                pipe.engine(),
                job.vmid,
                job.pd_addr,
                gfx,
            )?;
        }
        if job.map_pasid {
            b.write_reg(oss + u32::from(job.vmid), u32::from(job.pasid), gfx)?;
        }
        if job.mem_sync {
            // gfx_v12_0_emit_mem_sync: ACQUIRE_MEM over everything, GL2/GLM
            // written back and GL2/GLM/GL1/GLV/GLK/GLI invalidated.
            b.acquire_mem_gfx11(0, 0, 0x00ff_ffff_ffff_ffff, 10, 0xc3b1)?;
        }
        // gfx_v12_0_ring_emit_hdp_flush / amdgpu_gfx_get_hdp_flush_mask:
        // graphics pipe 0 uses CP0 through PFP; compute pipe 0 uses CP2
        // through ME. NBIF6.3.1/NBIO7.7 bank 2 has REQ/DONE at 0x106/107.
        let hdp = if gfx { 1 } else { 4 };
        b.reg_write_reg_wait(nbio + 0x106, nbio + 0x107, hdp, hdp, gfx)?;
        if gfx {
            // gfx_v12_0_ring_emit_cntxcntl: load_enable, plus the global,
            // per-context and SH register loads on a context switch.
            let reload = if job.ctx_switch {
                0x8001 | 0x0100_0000 | 0x1_0002
            } else {
                0
            };
            b.context_control(0x8000_0000 | reload, 0)?;
        }
        for &(at, dwords) in job.ibs() {
            if gfx {
                b.indirect_buffer(at, dwords, job.vmid)?;
            } else {
                b.indirect_buffer_valid(at, dwords, job.vmid)?;
            }
        }
        b.release_mem_fence(fence, u64::from(seq), false, true)?;
        let used = b.words().len();
        b.nop(256 - used - 1)
    })();
    built.map_err(|_| Error::Invalid)?;
    Ok(words)
}
/// A slot that only writes `seq` to `fence` (the job frame's RELEASE_MEM),
/// padded with one NOP.
fn fence_packets(fence: u64, seq: u32) -> Result<[u32; 256], Error> {
    use crate::amdgpu_pm4::Pm4Builder;
    let mut words = [0u32; 256];
    let mut b = Pm4Builder::new(&mut words);
    let built = (|| {
        b.release_mem_fence(fence, u64::from(seq), false, true)?;
        let used = b.words().len();
        b.nop(256 - used - 1)
    })();
    built.map_err(|_| Error::Invalid)?;
    Ok(words)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub graphics_fence: u32,
    pub compute_fence: u32,
    pub written_bytes: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterruptProof {
    pub fences: [u32; 2],
    /// True only when both EOPs also advanced the configured CPU MSI counter.
    pub msi_verified: bool,
}
const IRQ_FENCES: [u32; 2] = [0x90701234, 0x90705678];
fn interrupt_packets(address: u64, pipe: usize) -> [u32; 256] {
    let mut words = [0; 256];
    // Linux gfx_v12_0_ring_emit_fence: RELEASE_MEM, GL2 writeback + sequence,
    // bypass cache, CACHE_FLUSH_AND_INV_TS_EVENT/index5, confirmed 32-bit EOP.
    words[..8].copy_from_slice(&[
        0xc0064900,
        0x06600514,
        0x22000000,
        address as u32,
        (address >> 32) as u32,
        IRQ_FENCES[pipe],
        0,
        0,
    ]);
    words[8] = 0xc0f61000; // 248-dword NOP aligns the new WPTR to 512.
    words
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    gc: u64,
    /// OSSSYS 7.0 bank 0 (the IH VMID LUTs).
    oss: u64,
    hyp: u64,
    nbio: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if crate::amdgpu_rdna4::Rdna4Chip::of(gpu).is_none() || gpu.regs.len < 0x7f004 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            gc: bank(
                gpu,
                ip::HW_ID_GC,
                crate::amdgpu_rdna4::GC_VERSIONS,
                0,
                DEQUEUE_REQUEST as u32,
            )
            .map_err(|_| Error::Unsupported)?,
            hyp: bank(
                gpu,
                ip::HW_ID_GC,
                crate::amdgpu_rdna4::GC_VERSIONS,
                1,
                RLC_CNTL as u32,
            )
            .map_err(|_| Error::Unsupported)?,
            oss: bank(gpu, ip::HW_ID_OSSSYS, &[(7, 0, 0)], 0, 0x1f)
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
}
fn qmem(base: u64, pipe: usize) -> api::QueueMemory {
    let base = base + pipe as u64 * PIPE_BYTES;
    api::QueueMemory {
        descriptor: base + 4096,
        ring: base,
        ring_bytes: 4096,
        eop: base + 8192,
        read_pointer: base + RPTR,
        write_pointer: base + WPTR,
        doorbell: BELLS[pipe],
    }
}
fn descriptor(base: u64, pipe: usize) -> Result<[u32; 512], Error> {
    let m = qmem(base, pipe);
    // Shared address/alignment/disjointness validation, followed by the actual
    // gfx_v12_0_{gfx,compute}_mqd_init fields, not the MES firmware descriptor.
    let mut words = api::mqd(m).map_err(|_| Error::Invalid)?;
    if pipe == 1 {
        words[135] = 0x111; // quantum enabled, scale=1, duration=1
        words[145] = 0xd0308909; // RPTR block=9; hardware RPTR updates enabled
        words[184] = 0; // MES firmware's DB_UPDATED_MSG_EN is not a compute MQD field
    } else {
        words = [0; 512];
        for (at, value) in [
            (128, m.descriptor),
            (136, m.ring >> 8),
            (139, m.read_pointer),
            (141, m.write_pointer),
        ] {
            words[at] = value as u32;
            words[at + 1] = (value >> 32) as u32;
        }
        words[130] = 1;
        words[135] = 0xa01;
        words[143] = (m.doorbell << 2) | (1 << 30);
        words[145] = 0x00a00709;
        words[162] = 0x100;
    }
    Ok(words)
}
fn packets(address: u64, pipe: usize) -> [u32; 256] {
    // WRITE_DATA dst_sel=5 (memory), write confirmation. Pad to GC12's
    // 256-dword ring alignment with an explicitly sized, legal TYPE3 NOP.
    let mut words = [0; 256];
    words[..4].copy_from_slice(&[
        0xc0123700,
        0x00100500,
        address as u32,
        (address >> 32) as u32,
    ]);
    for (slot, value) in words[4..20].iter_mut().zip(PATTERN) {
        *slot = value ^ pipe as u32;
    }
    let at = address + 4092;
    words[20..25].copy_from_slice(&[
        0xc0033700,
        0x00100500,
        at as u32,
        (at >> 32) as u32,
        FENCES[pipe],
    ]);
    words[25] = 0xc0e51000; // 231 dwords: count=229, plus header and last body word
    words
}
trait Io {
    fn read(&mut self, at: u64) -> u32;
    fn write(&mut self, at: u64, v: u32);
    fn memory_read(&mut self, map: MmioRegion, at: u64) -> u32;
    fn memory_write(&mut self, map: MmioRegion, at: u64, v: u32);
    fn doorbell(&mut self, map: MmioRegion, offset: u32, v: u64);
    async fn delay(&mut self) {
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant()).await;
    }
}
trait Mapper {
    async fn map(&mut self, queue: api::KernelQueue) -> Result<(), mes::Error>;
}
impl Mapper for mes::Mes {
    async fn map(&mut self, queue: api::KernelQueue) -> Result<(), mes::Error> {
        // SAFETY: Engine validates ownership and publishes/retains every address
        // before calling this private adapter with either bootstrap kernel HQD.
        unsafe { self.map_bootstrap_queue(queue) }.await
    }
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: Layout bounds this register; caller invokes live authority.
        unsafe { self.0.read32(at) }
    }
    fn write(&mut self, at: u64, v: u32) {
        // SAFETY: same exclusive bounded register mapping and live authority.
        unsafe { self.0.write32(at, v) };
    }
    fn memory_read(&mut self, map: MmioRegion, at: u64) -> u32 {
        // SAFETY: offset is within a retained queue allocation or borrowed GMC page.
        unsafe { map.read32(at) }
    }
    fn memory_write(&mut self, map: MmioRegion, at: u64, v: u32) {
        // SAFETY: same bounded owned queue/test-page mapping under authority.
        unsafe { map.write32(at, v) };
    }
    fn doorbell(&mut self, map: MmioRegion, offset: u32, v: u64) {
        // SAFETY: bootstrap reserves both even offsets inside MES's mapped BAR2.
        unsafe { map.write64(u64::from(offset) * 4, v) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn checked(v: u32) -> Result<u32, Error> {
    if v == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(v)
    }
}
fn select(io: &mut impl Io, l: Layout, index: u32) -> Result<(), Error> {
    io.write(l.hyp + 0x900 * 4, index);
    if checked(io.read(l.hyp + 0x900 * 4))? != index {
        return Err(Error::Readback);
    }
    Ok(())
}
/// Run `f` with the compute queue selected, restoring the prior selection
/// even when `f` fails.
fn selected<I: Io, T>(
    io: &mut I,
    l: Layout,
    f: impl FnOnce(&mut I) -> Result<T, Error>,
) -> Result<T, Error> {
    let prior = checked(io.read(l.hyp + 0x900 * 4))?;
    let result = select(io, l, COMPUTE_SELECT).and_then(|()| f(io));
    select(io, l, prior)?;
    result
}
fn flush(io: &mut impl Io, l: Layout) -> Result<(), Error> {
    fence(Ordering::SeqCst);
    io.write(0x7f000, 0);
    checked(io.read(l.nbio + 0xc3 * 4))?;
    fence(Ordering::SeqCst);
    Ok(())
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    doorbells: MmioRegion,
    memory: Reservation,
    state: State,
    proof: Option<Proof>,
    interrupt_result: Option<Result<InterruptProof, Error>>,
    /// Dwords written to each pipe's ring so far (its WPTR).
    job_wptr: [u64; 2],
    /// The last job sequence submitted on each pipe's ring.
    job_seq: [u32; 2],
    shader_engines: u8,
    shader_result: Option<Result<crate::amdgpu_gfx12_shader::Proof, Error>>,
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
        mes: &mut impl Mapper,
        aperture: gmc::Aperture,
        target: MmioRegion,
    ) -> Result<Proof, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Mapping(0);
        let result = self.initialize_inner(mes, aperture, target).await;
        self.state = match result {
            Ok(p) => {
                self.proof = Some(p);
                State::Verified
            }
            Err(e) => State::Failed(e),
        };
        result
    }
    async fn initialize_inner(
        &mut self,
        mes: &mut impl Mapper,
        aperture: gmc::Aperture,
        target: MmioRegion,
    ) -> Result<Proof, Error> {
        let l = self.layout;
        let base = self.memory.address();
        let map = self.memory.mapping();
        let db = self.doorbells;
        self.access(|io| {
            let fb = u64::from(checked(io.read(l.gc + 0x1614 * 4))? & 0xffffff) << 24;
            let end = (u64::from(checked(io.read(l.gc + 0x1615 * 4))? & 0xffffff) + 1) << 24;
            if base < fb
                || base.checked_add(BYTES).is_none_or(|v| v > end)
                || end >= 1 << 48
                || aperture.start != end
                || aperture.size != 2 << 20
                || aperture.source != end
                || aperture.destination != end + 4096
                || target.len != 8192
                || checked(io.read(l.nbio + 0x12d * 4))? != 0x7f000
            {
                return Err(Error::Invalid);
            }
            let prior = checked(io.read(l.hyp + 0x900 * 4))?;
            let result = (|| {
                for (index, reg) in [(0, 0x1e80), (4, 0x1fab)] {
                    select(io, l, index)?;
                    if checked(io.read(l.gc + reg * 4))? & 1 != 0 {
                        return Err(Error::Busy);
                    }
                }
                Ok(())
            })();
            select(io, l, prior)?;
            result?;
            for at in (0..BYTES).step_by(4) {
                io.memory_write(map, at, 0);
            }
            for at in (0..8192).step_by(4) {
                io.memory_write(target, at, 0);
            }
            for pipe in 0..2 {
                let words = descriptor(base, pipe)?;
                for (i, v) in words.into_iter().enumerate() {
                    io.memory_write(map, pipe as u64 * PIPE_BYTES + 4096 + i as u64 * 4, v);
                }
                let words = packets(aperture.source + pipe as u64 * 4096, pipe);
                for (i, v) in words.into_iter().enumerate() {
                    io.memory_write(map, pipe as u64 * PIPE_BYTES + i as u64 * 4, v);
                }
            }
            flush(io, l)?;
            Ok(())
        })?;
        self.memory.publish();
        for pipe in 0..2 {
            self.state = State::Mapping(pipe as u8);
            let m = qmem(base, pipe);
            mes.map(api::KernelQueue {
                kind: if pipe == 0 {
                    api::QueueType::Graphics
                } else {
                    api::QueueType::Compute
                },
                pipe: 0,
                queue: 0,
                doorbell: m.doorbell,
                mqd: m.descriptor,
                write_pointer: m.write_pointer,
            })
            .await
            .map_err(Error::Mes)?;
            let off = pipe as u64 * PIPE_BYTES;
            self.access(|io| {
                io.memory_write(map, off + WPTR, 256);
                io.memory_write(map, off + WPTR + 4, 0);
                flush(io, l)?;
                io.doorbell(db, BELLS[pipe], 256);
                Ok(())
            })?;
            self.state = State::Submitted(pipe as u8);
            let deadline = narf_time::Deadline::after_us(2_100_000);
            loop {
                let done = self.access(|io| {
                    flush(io, l)?;
                    let fence = io.memory_read(target, pipe as u64 * 4096 + 4092);
                    let rptr = io.memory_read(map, off + RPTR);
                    if rptr > 256 {
                        return Err(Error::DataMismatch);
                    }
                    if fence != FENCES[pipe] || rptr != 256 {
                        return Ok(false);
                    }
                    for (i, v) in PATTERN.into_iter().enumerate() {
                        if io.memory_read(target, pipe as u64 * 4096 + i as u64 * 4)
                            != v ^ pipe as u32
                        {
                            return Err(Error::DataMismatch);
                        }
                    }
                    Ok(true)
                })?;
                if done {
                    break;
                }
                if deadline.expired() {
                    return Err(Error::Timeout);
                }
                self.io.delay().await;
            }
        }
        Ok(Proof {
            graphics_fence: FENCES[0],
            compute_fence: FENCES[1],
            written_bytes: 128,
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
        self.state = State::InterruptSubmitted(0);
        let result = self.interrupt_inner(observer, aperture, target).await;
        self.interrupt_result = Some(result);
        self.state = match result {
            Ok(_) => State::InterruptVerified,
            Err(e) => State::Failed(e),
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
        let db = self.doorbells;
        if aperture.start >= (1 << 48) - (2 << 20)
            || aperture.start % (2 << 20) != 0
            || aperture.source != aperture.start
            || aperture.destination != aperture.start + 4096
            || aperture.size != 2 << 20
            || target.len != 8192
        {
            return Err(Error::Invalid);
        }
        let mut msi_verified = true;
        for pipe in 0..2 {
            self.state = State::InterruptSubmitted(pipe as u8);
            let source = if pipe == 0 {
                Source::Graphics
            } else {
                Source::Compute
            };
            let sample = observer.sample(source).await.map_err(Error::Interrupts)?;
            msi_verified &= sample.vector.is_some();
            let off = pipe as u64 * PIPE_BYTES;
            let control = l.gc + if pipe == 0 { 0x1e0a * 4 } else { 0x1e25 * 4 };
            self.access(|io| {
                flush(io, l)?;
                if io.memory_read(map, off + RPTR) != 256
                    || io.memory_read(map, off + WPTR) != 256
                    || io.memory_read(map, off + WPTR + 4) != 0
                {
                    return Err(Error::Busy);
                }
                // The independent IH service owns all writes to CP interrupt
                // controls, including EOP enables and fault masking.
                if checked(io.read(control))? & 0x84000000 != 0x84000000 {
                    return Err(Error::Busy);
                }
                io.memory_write(target, pipe as u64 * 4096 + 4088, 0);
                let address = aperture.source + pipe as u64 * 4096 + 4088;
                for (i, word) in interrupt_packets(address, pipe).into_iter().enumerate() {
                    io.memory_write(map, off + 1024 + i as u64 * 4, word);
                }
                io.memory_write(map, off + WPTR, 512);
                flush(io, l)?;
                io.doorbell(db, BELLS[pipe], 512);
                Ok(())
            })?;
            let deadline = narf_time::Deadline::after_us(2_100_000);
            loop {
                let memory_done = self.access(|io| {
                    flush(io, l)?;
                    let rptr = io.memory_read(map, off + RPTR);
                    if rptr > 512 {
                        return Err(Error::DataMismatch);
                    }
                    Ok(rptr == 512
                        && io.memory_read(target, pipe as u64 * 4096 + 4088) == IRQ_FENCES[pipe])
                })?;
                let event_done = observer.observed(sample).await.map_err(Error::Interrupts)?;
                if memory_done && event_done {
                    break;
                }
                if deadline.expired() {
                    return Err(Error::Timeout);
                }
                self.io.delay().await;
            }
        }
        Ok(InterruptProof {
            fences: IRQ_FENCES,
            msi_verified,
        })
    }
}
impl<I: Io> Engine<I> {
    /// Queue one client job on `pipe`'s ring, after both proofs, if its
    /// 256-dword slot is free: the ring holds 1024 dwords, and only the low
    /// 32 bits of GC12's RPTR writeback are live. Returns the job's
    /// sequence on that ring; `completed_job` reports when its fence
    /// passes it.
    fn submit(&mut self, pipe: Pipe, job: Job) -> Result<u32, Error> {
        let (gc, oss) = ((self.layout.gc / 4) as u32, (self.layout.oss / 4) as u32);
        let nbio = (self.layout.nbio / 4) as u32;
        self.submit_slot(pipe, |fence, seq| {
            job_packets(pipe, job, gc, oss, nbio, fence, seq)
        })
    }
    /// Queue a slot of nothing but the next sequence's fence on `pipe`: the
    /// ring test after a reset (amdgpu_ring_test_ring). Once the fence
    /// passes it, the CP has moved past every earlier slot.
    fn submit_fence(&mut self, pipe: Pipe) -> Result<u32, Error> {
        self.submit_slot(pipe, fence_packets)
    }
    /// Write the slot `build` makes for the next sequence and its fence
    /// address onto `pipe`'s ring, after both proofs, if the slot is free.
    fn submit_slot(
        &mut self,
        pipe: Pipe,
        build: impl FnOnce(u64, u32) -> Result<[u32; 256], Error>,
    ) -> Result<u32, Error> {
        if self.state != State::InterruptVerified {
            return Err(Error::Busy);
        }
        self.publish_slot(pipe, build)
    }
    fn publish_slot(
        &mut self,
        pipe: Pipe,
        build: impl FnOnce(u64, u32) -> Result<[u32; 256], Error>,
    ) -> Result<u32, Error> {
        let l = self.layout;
        let map = self.memory.mapping();
        let db = self.doorbells;
        let (i, base) = (pipe.index(), pipe.base());
        let wptr = self.job_wptr[i];
        let seq = self.job_seq[i].wrapping_add(1);
        let fence = self.memory.address() + base + JOB_FENCE;
        let words = build(fence, seq)?;
        self.access(|io| {
            flush(io, l)?;
            let rptr = u64::from(io.memory_read(map, base + RPTR));
            // The 32-bit RPTR trails WPTR by what the CP has yet to read.
            let pending = (wptr as u32).wrapping_sub(rptr as u32) as u64;
            if pending > wptr || pending + JOB_DWORDS > RING_DWORDS {
                return Err(Error::Busy);
            }
            let slot = base + wptr % RING_DWORDS * 4;
            for (w, word) in words.into_iter().enumerate() {
                io.memory_write(map, slot + w as u64 * 4, word);
            }
            let next = wptr + JOB_DWORDS;
            io.memory_write(map, base + WPTR, next as u32);
            io.memory_write(map, base + WPTR + 4, (next >> 32) as u32);
            flush(io, l)?;
            io.doorbell(db, BELLS[i], next);
            Ok(())
        })?;
        self.job_wptr[i] = wptr + JOB_DWORDS;
        self.job_seq[i] = seq;
        Ok(seq)
    }
    async fn prove_shaders(
        &mut self,
        observer: &mut impl Observer,
        prepare: impl core::future::Future<Output = Result<(gmc::Aperture, MmioRegion), gmc::Error>>,
    ) -> Result<crate::amdgpu_gfx12_shader::Proof, Error> {
        if self.state != State::InterruptVerified
            || self.shader_result.is_some()
            || self.job_seq != [0; 2]
            || self.job_wptr != [512; 2]
        {
            return Err(Error::Busy);
        }
        let l = self.layout;
        let map = self.memory.mapping();
        // Reject outstanding/foreign ring progress before changing any PTE.
        self.access(|io| {
            flush(io, l)?;
            for pipe in 0..2 {
                if io.memory_read(map, pipe * PIPE_BYTES + RPTR) != 512 {
                    return Err(Error::Busy);
                }
            }
            Ok(())
        })?;
        self.state = State::ShaderSubmitted(0);
        let result = async {
            let (aperture, target) = prepare.await.map_err(Error::Gmc)?;
            self.shader_inner(observer, aperture, target).await
        }
        .await;
        self.shader_result = Some(result);
        self.state = match result {
            Ok(_) => State::InterruptVerified,
            Err(e) => State::Failed(e),
        };
        result
    }
    async fn shader_inner(
        &mut self,
        observer: &mut impl Observer,
        aperture: gmc::Aperture,
        target: MmioRegion,
    ) -> Result<crate::amdgpu_gfx12_shader::Proof, Error> {
        use crate::amdgpu_gfx12_shader as shader;
        if aperture.start >= (1 << 48) - (2 << 20)
            || aperture.start % (2 << 20) != 0
            || aperture.source != aperture.start
            || aperture.destination != aperture.start + 4096
            || aperture.size != 2 << 20
            || target.len != 8192
        {
            return Err(Error::Invalid);
        }
        let l = self.layout;
        let ring_map = self.memory.mapping();
        let mut proof = shader::Proof {
            lanes: shader::LANES,
            fences: [0; 2],
            msi_verified: true,
        };
        for (pipe, kind) in [Pipe::Graphics, Pipe::Compute].into_iter().enumerate() {
            self.state = State::ShaderSubmitted(pipe as u8);
            let sample = observer
                .sample(if pipe == 0 {
                    Source::Graphics
                } else {
                    Source::Compute
                })
                .await
                .map_err(Error::Interrupts)?;
            proof.msi_verified &= sample.vector.is_some();
            let ib = shader::ib(
                aperture.source,
                aperture.source + shader::OUTPUT_OFFSET,
                self.shader_engines,
                shader::SALTS[pipe],
            )?;
            self.access(|io| {
                for at in (0..8192).step_by(4) {
                    let fill = if at < shader::IB_OFFSET {
                        0xbfb0_0000
                    } else {
                        shader::POISON
                    };
                    io.memory_write(target, at, fill);
                }
                for (i, word) in shader::PROGRAM.into_iter().enumerate() {
                    io.memory_write(target, i as u64 * 4, word);
                }
                for (i, word) in ib.into_iter().enumerate() {
                    io.memory_write(target, shader::IB_OFFSET + i as u64 * 4, word);
                }
                flush(io, l)?;
                Ok(())
            })?;
            let seq = self.publish_slot(kind, |fence, seq| {
                shader::ring(aperture.source + shader::IB_OFFSET, fence, seq, pipe == 0)
            })?;
            proof.fences[pipe] = seq;
            let deadline = narf_time::Deadline::after_us(2_100_000);
            let tail = self.job_wptr[pipe];
            loop {
                let done = self.access(|io| {
                    flush(io, l)?;
                    let base = pipe as u64 * PIPE_BYTES;
                    let rptr = io.memory_read(ring_map, base + RPTR);
                    if u64::from(rptr) > tail {
                        return Err(Error::DataMismatch);
                    }
                    if u64::from(rptr) != tail || io.memory_read(ring_map, base + JOB_FENCE) != seq
                    {
                        return Ok(false);
                    }
                    for i in 0..1024u64 {
                        let at = 4096 + i * 4;
                        let expected = if (shader::OUTPUT_OFFSET
                            ..shader::OUTPUT_OFFSET + u64::from(shader::LANES) * 4)
                            .contains(&at)
                        {
                            shader::expected(((at - shader::OUTPUT_OFFSET) / 4) as u32, pipe)
                        } else {
                            shader::POISON
                        };
                        if io.memory_read(target, at) != expected {
                            return Err(Error::DataMismatch);
                        }
                    }
                    Ok(true)
                })?;
                let event = observer.observed(sample).await.map_err(Error::Interrupts)?;
                if done && event {
                    break;
                }
                if deadline.expired() {
                    return Err(Error::Timeout);
                }
                self.io.delay().await;
            }
        }
        Ok(proof)
    }
    /// mes_v12_0_reset_queue_mmio for the compute queue: with it selected,
    /// a reset dequeue (CP_HQD_DEQUEUE_REQUEST 2) and SPI's compute queue
    /// reset, then up to amdgpu's usec_timeout for the HQD to go inactive.
    /// On timeout, mes_v12_0_reset_compute_pipe_mmio's RS64 fallback clears
    /// all four HQDs while pipe 0 is held in reset. RLC safe mode covers
    /// both paths. Cancellation/failure does not permit submission or replay.
    async fn reset_compute_hqd(&mut self) -> Result<(), Error> {
        if self.state != State::InterruptVerified {
            return Err(Error::Busy);
        }
        self.state = State::ResettingCompute;
        let result = self.reset_compute_inner().await;
        self.state = match result {
            Ok(()) => State::ComputeReset,
            Err(e) => State::Failed(e),
        };
        result
    }
    async fn reset_compute_inner(&mut self) -> Result<(), Error> {
        let l = self.layout;
        // As amdgpu_gfx_rlc_enter_safe_mode: a disabled RLC has no command
        // consumer. For a running RLC, always protect against clock gating.
        let rlc = self.access(|io| Ok(checked(io.read(l.hyp + RLC_CNTL * 4))? & 1 != 0))?;
        let result = async {
            if rlc {
                self.access(|io| {
                    io.write(l.hyp + RLC_SAFE_MODE * 4, 3); // CMD + enter message
                    Ok(())
                })?;
                let deadline = narf_time::Deadline::after_us(100_000);
                loop {
                    if self.access(|io| checked(io.read(l.hyp + RLC_SAFE_MODE * 4)))? & 1 == 0 {
                        break;
                    }
                    if deadline.expired() {
                        return Err(Error::Timeout);
                    }
                    self.io.delay().await;
                }
            }
            self.dequeue_compute_hqd().await
        }
        .await;
        if rlc {
            // gfx_v12_0_unset_safe_mode, including returned-error paths.
            // A dropped future leaves safe mode and the owners quarantined.
            self.access(|io| {
                io.write(l.hyp + RLC_SAFE_MODE * 4, 1);
                Ok(())
            })?;
        }
        result
    }
    async fn dequeue_compute_hqd(&mut self) -> Result<(), Error> {
        let l = self.layout;
        self.access(|io| {
            selected(io, l, |io| {
                io.write(l.gc + DEQUEUE_REQUEST * 4, 2);
                io.write(l.gc + COMPUTE_QUEUE_RESET * 4, 1);
                Ok(())
            })
        })?;
        let deadline = narf_time::Deadline::after_us(100_000);
        loop {
            let active = self.access(|io| {
                selected(io, l, |io| {
                    Ok(checked(io.read(l.gc + HQD_ACTIVE * 4))? & 1 != 0)
                })
            })?;
            if !active {
                return Ok(());
            }
            if deadline.expired() {
                return self.reset_compute_pipe();
            }
            self.io.delay().await;
        }
    }
    fn reset_compute_pipe(&mut self) -> Result<(), Error> {
        let l = self.layout;
        self.access(|io| {
            selected(io, l, |io| {
                // This owner maps only queue 0. Do not destroy an unexpected
                // sibling's work by broadening a queue reset to the whole pipe.
                for queue in 1..4 {
                    select(io, l, COMPUTE_SELECT | (queue << 8))?;
                    if checked(io.read(l.gc + HQD_ACTIVE * 4))? & 1 != 0 {
                        return Err(Error::Busy);
                    }
                }
                select(io, l, COMPUTE_SELECT)?;
                let control = l.hyp + MEC_RS64_CNTL * 4;
                let saved = checked(io.read(control))?;
                if saved & MEC_PIPE0_RESET != 0 {
                    return Err(Error::Busy);
                }
                io.write(control, saved | MEC_PIPE0_RESET);
                if checked(io.read(control))? & MEC_PIPE0_RESET == 0 {
                    return Err(Error::Readback);
                }
                // GC12.0.1 has four HQDs per MEC pipe. No await between
                // assertion, clearing every HQD and deassertion. If any clear
                // is uncertain, retain reset rather than restart that HQD.
                for queue in 0..4 {
                    select(io, l, COMPUTE_SELECT | (queue << 8))?;
                    io.write(l.gc + HQD_ACTIVE * 4, 0);
                    io.write(l.gc + DEQUEUE_REQUEST * 4, 0);
                    if checked(io.read(l.gc + HQD_ACTIVE * 4))? & 1 != 0
                        || checked(io.read(l.gc + DEQUEUE_REQUEST * 4))? != 0
                    {
                        return Err(Error::Readback);
                    }
                }
                select(io, l, COMPUTE_SELECT)?;
                io.write(control, saved & !MEC_PIPE0_RESET);
                if checked(io.read(control))? & MEC_PIPE0_RESET != 0 {
                    return Err(Error::Readback);
                }
                // Linux treats the instruction-pointer check as diagnostic;
                // only the subsequent ring test proves the CP is running.
                Ok(())
            })
        })
    }
    /// amdgpu_gfx_mqd_reset_restore, once the reset queue is unmapped: its
    /// descriptor as first built, a ring of NOPs (amdgpu_ring_clear_ring)
    /// and its write pointer at 0, for MES to map it again. The read
    /// pointer report is cleared too, as the remapped queue starts at 0
    /// and nothing writes it while the HQD is unmapped.
    fn restore(&mut self, pipe: Pipe) -> Result<(), Error> {
        let expected = match pipe {
            Pipe::Compute => State::ComputeReset,
            Pipe::Graphics => State::InterruptVerified,
        };
        if self.state != expected {
            return Err(Error::Busy);
        }
        let l = self.layout;
        let map = self.memory.mapping();
        let off = pipe.base();
        let words = descriptor(self.memory.address(), pipe.index())?;
        self.access(|io| {
            for (i, v) in words.into_iter().enumerate() {
                io.memory_write(map, off + 4096 + i as u64 * 4, v);
            }
            for at in (0..RING_DWORDS * 4).step_by(4) {
                io.memory_write(map, off + at, RING_NOP);
            }
            for at in [RPTR, RPTR + 4, WPTR, WPTR + 4] {
                io.memory_write(map, off + at, 0);
            }
            flush(io, l)?;
            Ok(())
        })?;
        self.job_wptr[pipe.index()] = 0;
        self.state = State::InterruptVerified;
        Ok(())
    }
    /// The last job sequence `pipe`'s fence reached.
    fn completed_job(&mut self, pipe: Pipe) -> Result<u32, Error> {
        client_fence(
            &mut self.io,
            self.authority,
            self.layout,
            self.memory.mapping(),
            pipe,
        )
    }
}
// Shared by the owner and synchronous readers, so neither can translate a
// vanished BAR's fence contents into successful client retirement.
fn client_fence(
    io: &mut impl Io,
    authority: Cap<BusDeviceCap, Write>,
    l: Layout,
    map: MmioRegion,
    pipe: Pipe,
) -> Result<u32, Error> {
    let value = authority
        .invoke(Op(|| {
            flush(io, l)?;
            let value = io.memory_read(map, pipe.base() + JOB_FENCE);
            checked(io.read(l.nbio + 0xc3 * 4))?;
            Ok(value)
        }))
        .map_err(|_| Error::Revoked)??;
    authority.invoke(Op(|| ())).map_err(|_| Error::Revoked)?;
    Ok(value)
}
/// Reads the queues' job fences without the queue's owner: its own
/// capability, an HDP flush, then the fence word. Concurrent flushes
/// and reads are harmless, so syncobj fences can poll it from anywhere.
#[derive(Clone, Copy, Debug)]
pub struct FenceReader {
    regs: MmioRegion,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    map: MmioRegion,
}
impl FenceReader {
    /// The last client job sequence `pipe`'s ring completed.
    pub fn completed(&self, pipe: Pipe) -> Result<u32, Error> {
        let mut io = Mmio(self.regs);
        let (l, map) = (self.layout, self.map);
        client_fence(&mut io, self.authority, l, map, pipe)
    }
}
#[derive(Debug)]
pub struct Queues(Engine<Mmio>);
impl Queues {
    /// # Safety
    /// Own the physical GPU, both kernel HQDs (gfx/compute pipe 0 queue 0),
    /// doorbells 0x116/6, GRBM indexing, permanent mappings and inventoried pool.
    /// Keep every published allocation retained until reset, including failures.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        mes: &mes::Mes,
    ) -> Result<Self, Error> {
        Ok(Self(Engine {
            io: Mmio(gpu.regs),
            authority,
            layout: Layout::resolve(gpu)?,
            doorbells: mes.doorbells().map_err(Error::Mes)?,
            memory: pool.reserve(BYTES).map_err(|_| Error::Allocation)?,
            state: State::Prepared,
            proof: None,
            interrupt_result: None,
            // The proofs leave both rings at 512 dwords.
            job_wptr: [512; 2],
            job_seq: [0; 2],
            shader_engines: gpu
                .gc_info
                .ok_or(Error::Unsupported)?
                .num_se
                .try_into()
                .map_err(|_| Error::Invalid)?,
            shader_result: None,
        }))
    }
    /// # Safety
    /// Matching PSP/RS64/RLC setup and MES12 startup succeeded; processors are
    /// running under restricted power policy. `mes`/`gmc` belong to this GPU,
    /// and no other client uses the GMC proof pages or these HQDs/doorbells.
    pub async unsafe fn initialize(
        &mut self,
        mes: &mut mes::Mes,
        gmc: &mut gmc::Gmc,
    ) -> Result<Proof, Error> {
        let aperture = gmc.aperture().ok_or(Error::Invalid)?;
        let map = gmc.test_mapping().ok_or(Error::Invalid)?;
        self.0.initialize(mes, aperture, map).await
    }
    pub fn state(&self) -> State {
        self.0.state
    }
    /// # Safety
    /// Same retained GMC proof pages/queues and independent IH service. No other
    /// submissions may use either HQD. Masked CPU IRQs fail the MSI proof before
    /// submission.
    pub async unsafe fn prove_interrupts(
        &mut self,
        gmc: &mut gmc::Gmc,
    ) -> Result<InterruptProof, Error> {
        let aperture = gmc.aperture().ok_or(Error::Invalid)?;
        let map = gmc.test_mapping().ok_or(Error::Invalid)?;
        self.0
            .prove_interrupts(&mut NativeObserver, aperture, map)
            .await
    }
    /// Run the wave32 shader on each idle kernel queue, only before client
    /// work. A fresh EOP, drained ring, fence, all lane values and guard words
    /// must agree. This is execution evidence only, not acceleration readiness.
    /// # Safety
    /// Own both queues, SDMA and GMC test pages exclusively; CPU IRQs and the
    /// independent IH service must run. Retain owners after failure/cancellation.
    pub async unsafe fn prove_shaders(
        &mut self,
        gmc: &mut gmc::Gmc,
    ) -> Result<crate::amdgpu_gfx12_shader::Proof, Error> {
        self.0
            .prove_shaders(&mut NativeObserver, async {
                // SAFETY: caller holds every test-page/queue user and reset/PM owner.
                unsafe { gmc.prepare_shader_test().await }?;
                Ok((
                    gmc.aperture().ok_or(gmc::Error::Invalid)?,
                    gmc.test_mapping().ok_or(gmc::Error::Invalid)?,
                ))
            })
            .await
    }
    pub fn shader_result(&self) -> Option<Result<crate::amdgpu_gfx12_shader::Proof, Error>> {
        self.0.shader_result
    }
    pub fn interrupt_result(&self) -> Option<Result<InterruptProof, Error>> {
        self.0.interrupt_result
    }
    pub fn proof(&self) -> Option<Proof> {
        self.0.proof
    }
    /// Queue a client job on `pipe`'s ring (see `Job`).
    /// # Safety
    /// `job.vmid`'s context points at `job.pd_addr` only through this
    /// job's flush; that page directory, the IB and everything it reaches
    /// stay mapped and alive until `completed_job` passes the returned
    /// sequence, and no one else writes this ring.
    pub unsafe fn submit(&mut self, pipe: Pipe, job: Job) -> Result<u32, Error> {
        self.0.submit(pipe, job)
    }
    /// The last client job sequence `pipe`'s ring completed.
    /// Queue the ring test after a reset (see `Engine::submit_fence`).
    /// # Safety
    /// As `submit`.
    pub unsafe fn submit_fence(&mut self, pipe: Pipe) -> Result<u32, Error> {
        self.0.submit_fence(pipe)
    }
    /// `pipe`'s queue as MES maps (and resets) it.
    pub fn kernel_queue(&self, pipe: Pipe) -> api::KernelQueue {
        let m = qmem(self.0.memory.address(), pipe.index());
        api::KernelQueue {
            kind: match pipe {
                Pipe::Graphics => api::QueueType::Graphics,
                Pipe::Compute => api::QueueType::Compute,
            },
            pipe: 0,
            queue: 0,
            doorbell: m.doorbell,
            mqd: m.descriptor,
            write_pointer: m.write_pointer,
        }
    }
    pub fn completed_job(&mut self, pipe: Pipe) -> Result<u32, Error> {
        self.0.completed_job(pipe)
    }
    /// Reset the hung compute queue's HQD by MMIO (see
    /// `Engine::reset_compute_hqd`).
    /// # Safety
    /// MES suspended its gangs or completed hung-queue detection identifying
    /// only this owned HQD after a suspend rejection. The caller owns all four
    /// HQDs on MEC1 pipe 0 and RLC safe mode, nothing else selects GRBM queues
    /// meanwhile, and every job the queue holds keeps its memory until a
    /// later fence on it lands.
    pub async unsafe fn reset_compute_hqd(&mut self) -> Result<(), Error> {
        self.0.reset_compute_hqd().await
    }
    /// Restore `pipe`'s reset, unmapped queue for MES to map again (see
    /// `Engine::restore`).
    /// # Safety
    /// The queue's HQD is reset and MES has unmapped it.
    pub unsafe fn restore(&mut self, pipe: Pipe) -> Result<(), Error> {
        self.0.restore(pipe)
    }
    /// A reader of the job fence that needs no access to this owner.
    pub fn fence_reader(&self) -> FenceReader {
        FenceReader {
            regs: self.0.io.0,
            authority: self.0.authority,
            layout: self.0.layout,
            map: self.0.memory.mapping(),
        }
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gfx12_queue_tests.rs"]
mod tests;
