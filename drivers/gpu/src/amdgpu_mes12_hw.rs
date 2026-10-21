//! Retained Navi48 unified MES12 firmware queues. Linux mes_v12_0.c and
//! GC12/NBIO register headers define this path. No application queues yet.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip, amdgpu_mes12 as api, amdgpu_navi48_firmware as fw,
    amdgpu_navi48_ucode::Source,
    amdgpu_psp_ring::bank,
    amdgpu_vram::{Pool, Reservation},
};
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

const PIPE_BYTES: u64 = 5 * 4096;
const BYTES: u64 = 2 * PIPE_BYTES;
const MQD: u64 = 4096;
const EOP: u64 = 8192;
const RPTR: u64 = 12288;
const WPTR: u64 = RPTR + 8;
const API_FENCE: u64 = RPTR + 16;
const DRAIN: u64 = RPTR + 24;
const CONTEXT: u64 = RPTR + 32;
const QUERY: u64 = RPTR + 40;
// The rest of the writeback page is unused; keep detection on its own line.
const HUNG: u64 = RPTR + 64;
const CLEANER: u64 = 16384; // firmware owns a complete resource_1 page
const DOORBELLS: [u32; 2] = [0x16, 0x18]; // dwords, soc24/Navi10 assignment
const AGGREGATED: [u32; 5] = [0x400, 0x402, 0x404, 0x406, 0x408];
const DOORBELL_BYTES: u64 = 8192;

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
    Protocol,
    FirmwareRejected(api::Rejection),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Starting,
    Submitting { pipe: u8, opcode: u8 },
    Ready,
    Failed(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// Live CP_MES_GP3_LO values, scheduler then KIQ (not container versions).
    pub versions: [u32; 2],
    pub completed: [u64; 2],
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    gc: u64,
    hyp: u64,
    nbio: u64,
    nbif_routing: bool,
    bases: api::Bases,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if crate::amdgpu_rdna4::Rdna4Chip::of(gpu).is_none() || gpu.regs.len < 0x7f004 {
            return Err(Error::Unsupported);
        }
        let reg = |id, versions: &[(u8, u8, u8)], index, last| {
            bank(gpu, id, versions, index, last).map_err(|_| Error::Unsupported)
        };
        let bases = |id| -> Result<[u32; 5], Error> {
            let mut found = gpu
                .ip_blocks
                .iter()
                .filter(|b| b.hw_id == id && b.instance == 0);
            let b = found.next().ok_or(Error::Unsupported)?;
            if found.next().is_some() || b.num_bases == 0 || b.num_bases > 5 {
                return Err(Error::Unsupported);
            }
            let mut out = [0; 5];
            for (dst, src) in out
                .iter_mut()
                .zip(&b.base_addrs)
                .take(usize::from(b.num_bases))
            {
                if u64::from(*src) * 4 >= gpu.regs.len {
                    return Err(Error::Invalid);
                }
                *dst = *src;
            }
            Ok(out)
        };
        // These are the exact source generations whose banks are delegated.
        reg(ip::HW_ID_MMHUB, &[(4, 1, 0)], 0, 0x610)?;
        reg(ip::HW_ID_OSSSYS, &[(7, 0, 0)], 0, 0)?;
        let nbif_routing = ip::find_ip(&gpu.ip_blocks, ip::HW_ID_NBIF, 0)
            .is_some_and(|b| (b.major, b.minor, b.revision) == (6, 3, 1));
        Ok(Self {
            gc: reg(ip::HW_ID_GC, crate::amdgpu_rdna4::GC_VERSIONS, 0, 0x1fcb)?,
            hyp: reg(ip::HW_ID_GC, crate::amdgpu_rdna4::GC_VERSIONS, 1, 0x289d)?,
            nbio: reg(
                ip::HW_ID_NBIF,
                &[(7, 7, 0), (7, 7, 1), (6, 3, 1)],
                2,
                if nbif_routing { 0x1ce } else { 0x12d },
            )?,
            nbif_routing,
            bases: api::Bases {
                gc: bases(ip::HW_ID_GC)?,
                mmhub: bases(ip::HW_ID_MMHUB)?,
                osssys: bases(ip::HW_ID_OSSSYS)?,
            },
        })
    }
}
trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn memory_write(&mut self, map: MmioRegion, offset: u64, value: u32);
    fn memory_read64(&mut self, map: MmioRegion, offset: u64) -> u64;
    fn doorbell(&mut self, map: MmioRegion, dword: u32, value: u64);
    async fn delay(&mut self, us: u64) {
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
    }
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: Layout bounds every register; Engine invokes each batch under authority.
        unsafe { self.0.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: same exclusive bounded register mapping and live authority.
        unsafe { self.0.write32(address, value) };
    }
    fn memory_write(&mut self, map: MmioRegion, offset: u64, value: u32) {
        // SAFETY: offsets are internal, bounded by the retained BYTES reservation.
        unsafe { map.write32(offset, value) };
    }
    fn memory_read64(&mut self, map: MmioRegion, offset: u64) -> u64 {
        // SAFETY: internal eight-byte-aligned pointer/fence slots in that reservation.
        unsafe { map.read64(offset) }
    }
    fn doorbell(&mut self, map: MmioRegion, dword: u32, value: u64) {
        // SAFETY: only the two owned even offsets; constructor bounds BAR2 mapping.
        unsafe { map.write64(u64::from(dword) * 4, value) };
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
fn set(io: &mut impl Io, address: u64, value: u32) -> Result<(), Error> {
    io.write(address, value);
    let got = io.read(address);
    if got != value {
        checked(got)?;
        return Err(Error::Readback);
    }
    Ok(())
}
fn update(io: &mut impl Io, address: u64, mask: u32, value: u32) -> Result<(), Error> {
    let prior = checked(io.read(address))?;
    set(io, address, (prior & !mask) | value)
}
fn indexed<T>(
    io: &mut impl Io,
    l: Layout,
    f: impl FnOnce(&mut dyn IndexIo) -> Result<T, Error>,
) -> Result<T, Error> {
    let prior = checked(io.read(l.hyp + 0x900 * 4))?;
    let result = f(io);
    set(io, l.hyp + 0x900 * 4, prior)?;
    result
}
// Keep indexed batches finite and non-async, with restoration on every error.
trait IndexIo {
    fn r(&mut self, address: u64) -> Result<u32, Error>;
    fn w(&mut self, address: u64, value: u32) -> Result<(), Error>;
}
impl<I: Io> IndexIo for I {
    fn r(&mut self, address: u64) -> Result<u32, Error> {
        checked(self.read(address))
    }
    fn w(&mut self, address: u64, value: u32) -> Result<(), Error> {
        set(self, address, value)
    }
}
fn flush(io: &mut impl Io, l: Layout) {
    fence(Ordering::SeqCst);
    io.write(0x7f000, 0);
    io.read(l.nbio + 0xc3 * 4);
    fence(Ordering::SeqCst);
}
fn queue_memory(base: u64, pipe: usize) -> api::QueueMemory {
    let a = base + pipe as u64 * PIPE_BYTES;
    api::QueueMemory {
        descriptor: a + MQD,
        ring: a,
        ring_bytes: 4096,
        eop: a + EOP,
        read_pointer: a + RPTR,
        write_pointer: a + WPTR,
        doorbell: DOORBELLS[pipe],
    }
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    doorbells: MmioRegion,
    memory: Reservation,
    starts: [u64; 2],
    state: State,
    versions: [u32; 2],
    tails: [u64; 2],
    completed: [u64; 2],
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> Result<T, Error>) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)?
    }
    async fn start(&mut self) -> Result<Report, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Starting;
        let result = self.start_inner().await;
        self.state = match result {
            Ok(_) => State::Ready,
            Err(e) => State::Failed(e),
        };
        result
    }
    async fn start_inner(&mut self) -> Result<Report, Error> {
        let l = self.layout;
        let base = self.memory.address();
        let map = self.memory.mapping();
        let mqds = [
            api::mqd(queue_memory(base, 0)),
            api::mqd(queue_memory(base, 1)),
        ];
        let [mqd0, mqd1] = mqds.map(|m| m.map_err(|_| Error::Invalid));
        let mqds = [mqd0?, mqd1?];
        self.access(|io| {
            let fb = u64::from(checked(io.read(l.gc + 0x1614 * 4))? & 0xffffff) << 24;
            let end = (u64::from(checked(io.read(l.gc + 0x1615 * 4))? & 0xffffff) + 1) << 24;
            if base < fb
                || base.checked_add(BYTES).is_none_or(|a| a > end)
                || end >= 1 << 48
                || checked(io.read(l.nbio + 0x12d * 4))? != 0x7f000
            {
                return Err(Error::Invalid);
            }
            if checked(io.read(l.hyp + 0x2807 * 4))? & 0x0c000000 != 0 {
                return Err(Error::Busy);
            }
            indexed(io, l, |io| {
                for pipe in 0..2 {
                    io.w(l.hyp + 0x900 * 4, 12 | pipe)?;
                    if io.r(l.gc + 0x1fab * 4)? & 1 != 0 {
                        return Err(Error::Busy);
                    }
                }
                Ok(())
            })?;
            for at in (0..BYTES).step_by(4) {
                io.memory_write(map, at, 0);
            }
            for (pipe, mqd) in mqds.iter().enumerate() {
                for (i, word) in mqd.iter().enumerate() {
                    io.memory_write(map, pipe as u64 * PIPE_BYTES + MQD + i as u64 * 4, *word);
                }
            }
            flush(io, l);
            Ok(())
        })?;
        // Anything below can make firmware access this allocation. Never recycle
        // it on a dropped future, failed capability check, or malformed reply.
        self.memory.publish();
        let starts = self.starts;
        self.access(|io| {
            if l.nbif_routing {
                // nbif_v6_3_1_gc_doorbell_init: NBIO7.7 has no such callback,
                // despite both backends sharing the aperture-enable bit.
                set(io, l.nbio + 0x1cb * 4, 0x30000007)?;
                set(io, l.nbio + 0x1ce * 4, 0x3000000d)?;
            }
            update(io, l.nbio + 0xc0 * 4, 1, 1)?;
            // soc24 split between graphics and compute/MES doorbells.
            for (reg, value) in [
                (0x1dfa, 0x116 << 2),
                (0x1dfb, 0x1fe << 2),
                (0x1dfc, 0),
                (0x1dfd, 0x114 << 2),
            ] {
                set(io, l.gc + reg * 4, value)?;
            }
            update(io, l.hyp + 0x98a * 4, 0xff, 0xe8)?;
            indexed(io, l, |io| {
                for (pipe, start) in starts.iter().enumerate() {
                    io.w(l.hyp + 0x900 * 4, 12 | pipe as u32)?;
                    let control = io.r(l.hyp + 0x2807 * 4)?;
                    io.w(l.hyp + 0x2807 * 4, control | (1 << (16 + pipe)))?;
                    io.w(l.hyp + 0x2800 * 4, (start >> 2) as u32)?;
                    io.w(l.hyp + 0x289d * 4, (start >> 34) as u32)?;
                    io.w(
                        l.hyp + 0x2807 * 4,
                        if pipe == 0 { 0x04000000 } else { 0x0c000000 },
                    )?;
                }
                Ok(())
            })
        })?;
        self.io.delay(500).await;
        self.access(|io| {
            indexed(io, l, |io| {
                io.w(l.hyp + 0x900 * 4, 13)?;
                let vmid = io.r(l.gc + 0x1fac * 4)?;
                io.w(l.gc + 0x1fac * 4, vmid & !15)?;
                let db = io.r(l.gc + 0x1fb8 * 4)?;
                io.w(l.gc + 0x1fb8 * 4, db & !(1 << 30))?;
                let m = &mqds[1];
                for (reg, index) in [
                    (0x1fa9, 128),
                    (0x1faa, 129),
                    (0x1fb1, 136),
                    (0x1fb2, 137),
                    (0x1fb4, 139),
                    (0x1fb5, 140),
                    (0x1fba, 145),
                    (0x1fb6, 141),
                    (0x1fb7, 142),
                    (0x1fb8, 143),
                    (0x1fad, 132),
                ] {
                    if reg == 0x1fb1 {
                        io.w(l.gc + 0x1fcb * 4, 0)?;
                    }
                    io.w(l.gc + reg * 4, m[index])?;
                }
                io.w(l.gc + 0x1fab * 4, 1)
            })
        })?;
        self.versions[1] = self.version(1).await?;
        self.resources(1).await?;
        let sched = api::KernelQueue {
            kind: api::QueueType::Scheduler,
            pipe: 0,
            queue: 0,
            doorbell: DOORBELLS[0],
            mqd: base + MQD,
            write_pointer: base + WPTR,
        };
        self.submit(1, api::map_kernel_queue(sched).map_err(|_| Error::Invalid)?)
            .await?;
        self.versions[0] = self.version(0).await?;
        self.resources(0).await?;
        self.access(|io| {
            update(io, l.hyp + 0x880 * 4, 0x1f01, 0xd01)?;
            for (i, doorbell) in AGGREGATED.iter().enumerate() {
                update(
                    io,
                    l.hyp + (0x283c + i as u64) * 4,
                    0xcffffffc,
                    (doorbell << 2) | (1 << 30),
                )?;
            }
            indexed(io, l, |io| {
                io.w(l.hyp + 0x900 * 4, 0)?;
                io.w(l.gc + 0x1e9f * 4, 1 << 15)
            })
        })?;
        self.submit(0, api::query_status()).await?;
        Ok(Report {
            versions: self.versions,
            completed: self.completed,
        })
    }
    async fn version(&mut self, pipe: usize) -> Result<u32, Error> {
        let l = self.layout;
        let deadline = narf_time::Deadline::after_us(2_100_000);
        loop {
            let v = self.access(|io| {
                indexed(io, l, |io| {
                    io.w(l.hyp + 0x900 * 4, 12 | pipe as u32)?;
                    io.r(l.hyp + 0x2849 * 4)
                })
            })?;
            if v != 0 {
                if v & 0xfff < 0x4b || (v >> 12) & 0xfff < 2 {
                    return Err(Error::Unsupported);
                }
                return Ok(v);
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            self.io.delay(50).await;
        }
    }
    async fn resources(&mut self, pipe: usize) -> Result<(), Error> {
        let base = self.memory.address() + pipe as u64 * PIPE_BYTES;
        let res = api::Resources {
            bases: self.layout.bases,
            queues: api::QueueMasks {
                aggregated_doorbells: if pipe == 0 { AGGREGATED } else { [0; 5] },
                ..Default::default()
            },
            scheduler_context: base + CONTEXT,
            query_fence: base + QUERY,
            revision: (self.versions[pipe] & 0xfff) as u16,
        };
        self.submit(pipe, api::resources(&res).map_err(|_| Error::Invalid)?)
            .await?;
        self.submit(
            pipe,
            api::resources_1(base + CLEANER).map_err(|_| Error::Invalid)?,
        )
        .await
    }
    async fn submit(&mut self, pipe: usize, mut packet: api::Packet) -> Result<(), Error> {
        self.state = State::Submitting {
            pipe: pipe as u8,
            opcode: packet.opcode(),
        };
        let seq = self.completed[pipe]
            .checked_add(1)
            .filter(|v| *v < 1 << 63)
            .ok_or(Error::Protocol)?;
        let offset = pipe as u64 * PIPE_BYTES;
        let base = self.memory.address() + offset;
        let map = self.memory.mapping();
        let l = self.layout;
        let db = self.doorbells;
        let tail = self.tails[pipe];
        let end = tail.checked_add(128).ok_or(Error::Protocol)?;
        packet
            .bind_completion(base + API_FENCE, 1)
            .map_err(|_| Error::Invalid)?;
        let mut query = api::query_status();
        query
            .bind_completion(base + DRAIN, seq)
            .map_err(|_| Error::Invalid)?;
        self.access(|io| {
            flush(io, l);
            if io.memory_read64(map, offset + RPTR) != tail {
                return Err(Error::Protocol);
            }
            for at in [API_FENCE, API_FENCE + 4] {
                io.memory_write(map, offset + at, 0);
            }
            for (i, word) in packet.words().iter().chain(query.words()).enumerate() {
                io.memory_write(map, offset + ((tail + i as u64) % 1024) * 4, *word);
            }
            io.memory_write(map, offset + WPTR, end as u32);
            io.memory_write(map, offset + WPTR + 4, (end >> 32) as u32);
            flush(io, l);
            io.doorbell(db, DOORBELLS[pipe], end);
            Ok(())
        })?;
        self.tails[pipe] = end;
        let deadline = narf_time::Deadline::after_us(2_100_000);
        loop {
            let (completion, rptr) = self.access(|io| {
                flush(io, l);
                let query = io.memory_read64(map, offset + DRAIN);
                let status = io.memory_read64(map, offset + API_FENCE);
                let rptr = io.memory_read64(map, offset + RPTR);
                Ok((
                    api::completion(status, query, seq).map_err(|_| Error::Protocol)?,
                    rptr,
                ))
            })?;
            if rptr < tail || rptr > end {
                return Err(Error::Protocol);
            }
            if rptr == end {
                match completion {
                    api::Completion::Success => {
                        self.completed[pipe] = seq;
                        return Ok(());
                    }
                    api::Completion::Rejected(e) => {
                        // The query drained this command even though its API
                        // failed. A follow-up must not reuse its drain value.
                        self.completed[pipe] = seq;
                        return Err(Error::FirmwareRejected(e));
                    }
                    api::Completion::Pending => {}
                }
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            self.io.delay(50).await;
        }
    }
}
impl<I: Io> Engine<I> {
    async fn map_bootstrap_queue(&mut self, queue: api::KernelQueue) -> Result<(), Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        let doorbell = match queue.kind {
            api::QueueType::Graphics => 0x116,
            api::QueueType::Compute => 6,
            _ => return Err(Error::Invalid),
        };
        if queue.pipe != 0 || queue.queue != 0 || queue.doorbell != doorbell {
            return Err(Error::Invalid);
        }
        let packet = api::map_kernel_queue(queue).map_err(|_| Error::Invalid)?;
        let result = self.submit(0, packet).await;
        self.state = match result {
            Ok(()) => State::Ready,
            Err(e) => State::Failed(e),
        };
        result
    }
    async fn reset_kernel_queue(&mut self, queue: api::KernelQueue, vmid: u8) -> Result<(), Error> {
        self.ready_for(queue)?;
        let packet = api::reset_kernel_queue(queue, vmid).map_err(|_| Error::Invalid)?;
        self.recovery_command(packet).await
    }
    /// REMOVE_QUEUE of a bootstrap queue already reset by MMIO, telling
    /// scheduler firmware 0x5a and later to drop its state for it.
    async fn unmap_reset_queue(&mut self, queue: api::KernelQueue) -> Result<(), Error> {
        self.ready_for(queue)?;
        let drop_state = self.versions[0] & 0xfff >= 0x5a;
        let packet =
            api::unmap_reset_kernel_queue(queue, drop_state).map_err(|_| Error::Invalid)?;
        self.recovery_command(packet).await
    }
    /// SUSPEND or RESUME of every gang on the scheduler pipe.
    async fn all_gangs(&mut self, suspend: bool) -> Result<(), Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        let packet = if suspend {
            api::suspend_all()
        } else {
            api::resume_all()
        };
        self.recovery_command(packet).await
    }
    async fn detect_hung_queues(
        &mut self,
    ) -> Result<[Option<api::HungQueue>; api::HUNG_QUEUES], Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        let map = self.memory.mapping();
        let l = self.layout;
        let packet = api::detect_hung_queues(api::QueueType::Compute, self.memory.address() + HUNG)
            .map_err(|_| Error::Invalid)?;
        self.access(|io| {
            for i in 0..api::HUNG_QUEUES * 2 {
                io.memory_write(map, HUNG + i as u64 * 4, u32::MAX);
            }
            flush(io, l);
            Ok(())
        })?;
        self.recovery_command(packet).await?;
        let result = self.access(|io| {
            flush(io, l);
            let mut words = [0; api::HUNG_QUEUES * 2];
            for (i, pair) in words.chunks_exact_mut(2).enumerate() {
                let value = io.memory_read64(map, HUNG + i as u64 * 8);
                pair[0] = value as u32;
                pair[1] = (value >> 32) as u32;
            }
            api::hung_queues(api::QueueType::Compute, words).map_err(|_| Error::Protocol)
        });
        if let Err(error) = result {
            self.state = State::Failed(error);
        }
        result
    }
    /// A fully drained suspend rejection permits Linux's detect-only path.
    /// Timeout/cancellation cannot reuse a command ring still in flight.
    async fn prepare_compute_reset(&mut self, queue: api::KernelQueue) -> Result<(), Error> {
        self.ready_for(queue)?;
        if queue.kind != api::QueueType::Compute {
            return Err(Error::Invalid);
        }
        match self.all_gangs(true).await {
            Ok(()) => Ok(()),
            Err(Error::FirmwareRejected(_)) => {
                let hung = self.detect_hung_queues().await?;
                if hung.iter().flatten().any(|h| {
                    h.doorbell != queue.doorbell || h.pipe != queue.pipe || h.queue != queue.queue
                }) {
                    // We own only this KCQ. Never reset a foreign user/KFD
                    // queue or continue with an incomplete ownership proof.
                    return Err(Error::Unsupported);
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    /// MES is ready and `queue` is one of the two bootstrap kernel queues.
    fn ready_for(&self, queue: api::KernelQueue) -> Result<(), Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        let doorbell = match queue.kind {
            api::QueueType::Graphics => 0x116,
            api::QueueType::Compute => 6,
            _ => return Err(Error::Invalid),
        };
        if queue.pipe != 0 || queue.queue != 0 || queue.doorbell != doorbell {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    /// Submit a recovery command on the scheduler pipe. A rejection leaves
    /// MES answering; a command it never completed does not.
    async fn recovery_command(&mut self, packet: api::Packet) -> Result<(), Error> {
        let result = self.submit(0, packet).await;
        self.state = match result {
            Ok(()) | Err(Error::FirmwareRejected(_)) => State::Ready,
            Err(e) => State::Failed(e),
        };
        result
    }
}
#[derive(Debug)]
pub struct Mes(Engine<Mmio>);

/// Map only the owned kernel doorbell pages. BAR sizing briefly writes and
/// restores PCI configuration; this must happen after the exclusive handoff.
/// # Safety
/// `device` and `authority` identify the same exclusively owned physical GPU.
/// No concurrent config/BAR access or previous BAR2 mappings/doorbell users.
pub(crate) unsafe fn map_doorbells(
    device: &narf_bus::BusDevice,
    authority: &Cap<BusDeviceCap, Write>,
) -> Result<MmioRegion, Error> {
    authority
        .invoke(Op(|| {
            // SAFETY: caller owns this PCI function's config window exclusively.
            let bar = unsafe { narf_bus::read_bar(device, 2) }.map_err(|_| Error::Invalid)?;
            if bar.size < DOORBELL_BYTES
                || bar.phys.raw() == 0
                || bar.phys.raw() % 4096 != 0
                || matches!(bar.kind, narf_bus::BarKind::Io)
                || bar.phys.raw().checked_add(DOORBELL_BYTES).is_none()
            {
                return Err(Error::Invalid);
            }
            // SAFETY: bounded pages of exclusively owned BAR2. Use Device even for
            // prefetchable BARs: a doorbell is a side effect, never a WC buffer.
            let mapping = unsafe {
                narf_memory::ioremap::ioremap(
                    bar.phys.raw(),
                    DOORBELL_BYTES,
                    narf_memory::ioremap::MmioAttrs::Device,
                )
            }
            .map_err(|_| Error::Allocation)?;
            // ioremap mappings persist until explicit iounmap; the GPU owns this
            // mapping until reset. Do not fall back to an unmapped physical address.
            Ok(MmioRegion {
                phys: bar.phys,
                virt: mapping.va(),
                len: DOORBELL_BYTES,
                kind: bar.kind,
            })
        }))
        .map_err(|_| Error::Revoked)?
}
impl Mes {
    /// Validate metadata and reserve memory without publishing any GPU address.
    /// # Safety
    /// Caller owns the physical Navi48, all MES/CP queues, GRBM selector, reset
    /// and PM transitions, permanent BAR mappings and the inventoried VRAM pool.
    /// `doorbells` must map this device's BAR2 as Device/uncached memory, with no
    /// other doorbell owner. Keep the device and reservations retained after
    /// cancellation/failure until independently reset. No VF or recovery attach.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        firmware: &fw::Firmware,
        doorbells: MmioRegion,
    ) -> Result<Self, Error> {
        if firmware.mes_mode() != fw::MesMode::Unified
            || fw::Target::resolve(gpu).map_err(|_| Error::Unsupported)? != firmware.target()
        {
            return Err(Error::Unsupported);
        }
        if doorbells.len < DOORBELL_BYTES
            || doorbells.virt == 0
            || doorbells.virt % 8 != 0
            || doorbells.phys.raw() == 0
            || doorbells.phys.raw() % 8 != 0
            || doorbells.virt.checked_add(DOORBELL_BYTES).is_none()
            || matches!(doorbells.kind, narf_bus::BarKind::Io)
        {
            return Err(Error::Invalid);
        }
        let layout = Layout::resolve(gpu)?;
        let images = firmware.images().map_err(|_| Error::Invalid)?;
        let mut starts = [0; 2];
        for (pipe, source) in [Source::Mes, Source::Mes1].iter().enumerate() {
            starts[pipe] = images
                .iter()
                .find(|i| i.source() == *source)
                .and_then(|i| i.entry_points())
                .map(|p| p.code)
                .ok_or(Error::Invalid)?;
            if starts[pipe] == 0 || starts[pipe] % 4 != 0 {
                return Err(Error::Invalid);
            }
        }
        Ok(Self(Engine {
            io: Mmio(gpu.regs),
            authority,
            layout,
            doorbells,
            memory: pool.reserve(BYTES).map_err(|_| Error::Allocation)?,
            starts,
            state: State::Prepared,
            versions: [0; 2],
            tails: [0; 2],
            completed: [0; 2],
        }))
    }
    /// # Safety
    /// PSP/RLC have authenticated and loaded the exact unified firmware supplied
    /// at construction. RS64 and both GMC hubs are configured and VRAM coherent;
    /// the driver's VMID0 DMA proof succeeded. Continue exclusive ownership.
    pub async unsafe fn start(&mut self) -> Result<Report, Error> {
        self.0.start().await
    }
    pub fn state(&self) -> State {
        self.0.state
    }
    pub fn report(&self) -> Option<Report> {
        (self.state() == State::Ready).then_some(Report {
            versions: self.0.versions,
            completed: self.0.completed,
        })
    }
    pub(crate) fn doorbells(&self) -> Result<MmioRegion, Error> {
        if self.state() != State::Ready {
            return Err(Error::Busy);
        }
        Ok(self.0.doorbells)
    }
    /// Map one of the two bootstrap kernel rings. MES12 maps the scheduler
    /// through KIQ, but maps ordinary kernel queues through scheduler pipe 0.
    /// # Safety
    /// Caller exclusively owns the specified inactive HQD, its doorbell and all
    /// addresses in the descriptor. Publish/retain all storage before this call,
    /// including on cancellation or firmware rejection. No user command buffers.
    pub(crate) async unsafe fn map_bootstrap_queue(
        &mut self,
        queue: api::KernelQueue,
    ) -> Result<(), Error> {
        self.0.map_bootstrap_queue(queue).await
    }
    /// Reset one of the two bootstrap kernel queues, mapped as
    /// `map_bootstrap_queue` mapped it, whose job on VMID `vmid` hung
    /// (amdgpu_mes_reset_legacy_queue). The queue stays mapped.
    /// # Safety
    /// As `map_bootstrap_queue`: the caller owns that HQD and serializes
    /// every user of it, and keeps all memory its jobs may reach until a
    /// later fence on it proves the CP has moved past them.
    pub(crate) async unsafe fn reset_kernel_queue(
        &mut self,
        queue: api::KernelQueue,
        vmid: u8,
    ) -> Result<(), Error> {
        self.0.reset_kernel_queue(queue, vmid).await
    }
    /// Unmap a bootstrap kernel queue the caller reset by MMIO
    /// (amdgpu_mes_unmap_legacy_queue with RESET_QUEUES), for
    /// `map_bootstrap_queue` to map again from its restored descriptor.
    /// # Safety
    /// As `reset_kernel_queue`, and the queue's HQD is inactive.
    pub(crate) async unsafe fn unmap_reset_queue(
        &mut self,
        queue: api::KernelQueue,
    ) -> Result<(), Error> {
        self.0.unmap_reset_queue(queue).await
    }
    /// Suspend (`true`) or resume every MES-scheduled gang
    /// (amdgpu_mes_suspend / amdgpu_mes_resume), around a kernel queue
    /// reset.
    /// # Safety
    /// The caller owns MES and resumes after every suspend.
    pub(crate) async unsafe fn all_gangs(&mut self, suspend: bool) -> Result<(), Error> {
        self.0.all_gangs(suspend).await
    }
    /// Suspend compute gangs, or identify the owned hung HQD after a drained
    /// suspend rejection. A failed/unknown command stream remains quarantined.
    /// # Safety
    /// The caller exclusively owns the compute pipe and resumes all gangs on
    /// returned paths; no user or KFD queues may be created concurrently.
    pub(crate) async unsafe fn prepare_compute_reset(
        &mut self,
        queue: api::KernelQueue,
    ) -> Result<(), Error> {
        self.0.prepare_compute_reset(queue).await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_mes12_hw_tests.rs"]
mod tests;
