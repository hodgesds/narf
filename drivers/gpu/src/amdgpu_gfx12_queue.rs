//! Two retained VMID0 GC12 kernel queues, with a bounded translated-memory
//! WRITE_DATA and native EOP-interrupt proofs, then client jobs on the
//! graphics queue: each a VM flush for the client's VMID, its IB and a
//! fence (`submit`). No draws, shaders or reset.
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
/// The graphics queue's job fence: the last completed job's sequence.
const JOB_FENCE: u64 = 10496;
/// One job's ring slot: GC12's 256-dword submission alignment.
const JOB_DWORDS: u64 = 256;
/// Ring capacity in dwords (4 KiB).
const RING_DWORDS: u64 = 1024;
/// The graphics ring's invalidation engine on the GFX hub, as
/// amdgpu_gmc_allocate_vm_inv_eng hands the first ring engine 0 (MES
/// reserves 5 and 6; the kernel's CPU invalidations use 17).
const GFX_INV_ENGINE: u32 = 0;
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
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Mapping(u8),
    Submitted(u8),
    Verified,
    InterruptSubmitted(u8),
    InterruptVerified,
    Failed(Error),
}
/// A client job: an IB of `ib_dwords` at `ib` in VMID `vmid`'s address
/// space, whose page directory is `pd_addr` (the root's entry address with
/// VALID, as gmc_v12_0_get_vm_pde leaves it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Job {
    pub vmid: u8,
    /// The client's PASID, mapped to `vmid` in the IH VMID LUT so a fault
    /// names the client.
    pub pasid: u16,
    pub pd_addr: u64,
    pub ib: u64,
    pub ib_dwords: u32,
}
/// gfx_v12_0's frame for one job on the graphics ring, as amdgpu_vm_flush
/// and amdgpu_ib_schedule emit it: the VM flush (gmc_v12_0_emit_flush_gpu_tlb
/// on the GFX hub through the ring's engine, then PFP_SYNC_ME), the PASID
/// mapping (gmc_v12_0_emit_pasid_mapping: IH_VMID_0_LUT + vmid at OSSSYS
/// base `oss`), the IB under the job's VMID, and an interrupting RELEASE_MEM
/// of `seq` to `fence`, NOP-padded to the 256-dword slot.
fn job_packets(job: Job, gc: u32, oss: u32, fence: u64, seq: u32) -> Result<[u32; 256], Error> {
    use crate::amdgpu_pm4::Pm4Builder;
    if !(1..16).contains(&job.vmid)
        || job.ib_dwords == 0
        || job.ib_dwords > 0xf_ffff
        || job.ib & 3 != 0
    {
        return Err(Error::Invalid);
    }
    let mut words = [0u32; 256];
    let mut b = Pm4Builder::new(&mut words);
    let built = (|| {
        b.vm_flush(
            &crate::amdgpu_vmhub_regs::GFXHUB_V12_0,
            gc,
            GFX_INV_ENGINE,
            job.vmid,
            job.pd_addr,
            true,
        )?;
        b.write_reg(oss + u32::from(job.vmid), u32::from(job.pasid), true)?;
        b.indirect_buffer(job.ib, job.ib_dwords, job.vmid)?;
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
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR
            || gpu.chip.did != crate::amdgpu::NAVI48
            || gpu.regs.len < 0x7f004
        {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            gc: bank(gpu, ip::HW_ID_GC, &[(12, 0, 1)], 0, 0x1fab)
                .map_err(|_| Error::Unsupported)?,
            hyp: bank(gpu, ip::HW_ID_GC, &[(12, 0, 1)], 1, 0x900)
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
fn flush(io: &mut impl Io, l: Layout) {
    fence(Ordering::SeqCst);
    io.write(0x7f000, 0);
    io.read(l.nbio + 0xc3 * 4);
    fence(Ordering::SeqCst);
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
    /// Dwords written to the graphics ring so far (its WPTR).
    gfx_wptr: u64,
    /// The last job sequence submitted on the graphics ring.
    gfx_seq: u32,
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
            flush(io, l);
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
                flush(io, l);
                io.doorbell(db, BELLS[pipe], 256);
                Ok(())
            })?;
            self.state = State::Submitted(pipe as u8);
            let deadline = narf_time::Deadline::after_us(2_100_000);
            loop {
                let done = self.access(|io| {
                    flush(io, l);
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
                flush(io, l);
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
                flush(io, l);
                io.doorbell(db, BELLS[pipe], 512);
                Ok(())
            })?;
            let deadline = narf_time::Deadline::after_us(2_100_000);
            loop {
                let memory_done = self.access(|io| {
                    flush(io, l);
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
    /// Queue one client job on the graphics ring, after both proofs, if its
    /// 256-dword slot is free: the ring holds 1024 dwords, and only the low
    /// 32 bits of GC12's RPTR writeback are live. Returns the job's
    /// sequence; `completed_job` reports when the fence passes it.
    fn submit(&mut self, job: Job) -> Result<u32, Error> {
        if self.state != State::InterruptVerified {
            return Err(Error::Busy);
        }
        let l = self.layout;
        let map = self.memory.mapping();
        let db = self.doorbells;
        // The proofs left the graphics ring at 512 dwords.
        let wptr = self.gfx_wptr.max(512);
        let seq = self.gfx_seq.wrapping_add(1);
        let fence = self.memory.address() + JOB_FENCE;
        let words = job_packets(job, (l.gc / 4) as u32, (l.oss / 4) as u32, fence, seq)?;
        self.access(|io| {
            flush(io, l);
            let rptr = u64::from(io.memory_read(map, RPTR));
            // The 32-bit RPTR trails WPTR by what the CP has yet to read.
            let pending = (wptr as u32).wrapping_sub(rptr as u32) as u64;
            if pending > wptr || pending + JOB_DWORDS > RING_DWORDS {
                return Err(Error::Busy);
            }
            let slot = wptr % RING_DWORDS * 4;
            for (i, word) in words.into_iter().enumerate() {
                io.memory_write(map, slot + i as u64 * 4, word);
            }
            let next = wptr + JOB_DWORDS;
            io.memory_write(map, WPTR, next as u32);
            io.memory_write(map, WPTR + 4, (next >> 32) as u32);
            flush(io, l);
            io.doorbell(db, BELLS[0], next);
            Ok(())
        })?;
        self.gfx_wptr = wptr + JOB_DWORDS;
        self.gfx_seq = seq;
        Ok(seq)
    }
    /// The last job sequence the graphics ring's fence reached.
    fn completed_job(&mut self) -> Result<u32, Error> {
        let l = self.layout;
        let map = self.memory.mapping();
        self.access(|io| {
            flush(io, l);
            Ok(io.memory_read(map, JOB_FENCE))
        })
    }
}
/// Reads the graphics queue's job fence without the queue's owner: its
/// own capability, an HDP flush, then the fence word. Concurrent flushes
/// and reads are harmless, so syncobj fences can poll it from anywhere.
#[derive(Clone, Copy, Debug)]
pub struct FenceReader {
    regs: MmioRegion,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    map: MmioRegion,
}
impl FenceReader {
    /// The last client job sequence the graphics ring completed.
    pub fn completed(&self) -> Result<u32, Error> {
        let mut io = Mmio(self.regs);
        let (l, map) = (self.layout, self.map);
        self.authority
            .invoke(Op(|| {
                flush(&mut io, l);
                io.memory_read(map, JOB_FENCE)
            }))
            .map_err(|_| Error::Revoked)
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
            gfx_wptr: 0,
            gfx_seq: 0,
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
    pub fn interrupt_result(&self) -> Option<Result<InterruptProof, Error>> {
        self.0.interrupt_result
    }
    pub fn proof(&self) -> Option<Proof> {
        self.0.proof
    }
    /// Queue a client job on the graphics ring (see `Job`).
    /// # Safety
    /// `job.vmid`'s context points at `job.pd_addr` only through this
    /// job's flush; that page directory, the IB and everything it reaches
    /// stay mapped and alive until `completed_job` passes the returned
    /// sequence, and no one else writes this ring.
    pub unsafe fn submit(&mut self, job: Job) -> Result<u32, Error> {
        self.0.submit(job)
    }
    /// The last client job sequence the graphics ring completed.
    pub fn completed_job(&mut self) -> Result<u32, Error> {
        self.0.completed_job()
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
