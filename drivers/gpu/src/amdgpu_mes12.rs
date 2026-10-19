//! MES12's 256-byte, eight-byte-aligned command ABI. MES11 uses pack(4) and
//! cannot supply ADD/REMOVE_QUEUE layouts. Source: Linux mes_v12_api_def.h and
//! mes_v12_0.c. This module serializes commands; it does not publish queues.
pub const FRAME_DWORDS: usize = 64;
const ADDRESS_LIMIT: u64 = 1 << 48;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    MalformedCompletion,
}

fn address(value: u64, alignment: u64) -> bool {
    value != 0 && value < ADDRESS_LIMIT && value % alignment == 0
}
fn put64(words: &mut [u32], at: usize, value: u64) {
    words[at] = value as u32;
    words[at + 1] = (value >> 32) as u32;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    words: [u32; FRAME_DWORDS],
    status: usize,
}
impl Packet {
    fn new(opcode: u8, status: usize) -> Self {
        let mut words = [0; FRAME_DWORDS];
        words[0] = 1 | (u32::from(opcode) << 4) | ((FRAME_DWORDS as u32) << 12);
        Self { words, status }
    }
    pub fn words(&self) -> &[u32; FRAME_DWORDS] {
        &self.words
    }
    pub fn opcode(&self) -> u8 {
        (self.words[0] >> 4) as u8
    }
    /// Every transport binds an owned aligned completion slot immediately
    /// before publication. No packet accepts a raw caller-selected offset.
    pub fn bind_completion(&mut self, fence: u64, value: u64) -> Result<(), Error> {
        if !address(fence, 8) || value == 0 || value >= 1 << 63 {
            return Err(Error::Invalid);
        }
        put64(&mut self.words, self.status, fence);
        put64(&mut self.words, self.status + 2, value);
        Ok(())
    }
}
/// Firmware register-base arrays are dword addresses. Ownership/physical
/// discovery validation belongs to the hardware owner, not this serializer.
#[derive(Clone, Copy, Debug, Default)]
pub struct Bases {
    pub gc: [u32; 5],
    pub mmhub: [u32; 5],
    pub osssys: [u32; 5],
}
#[derive(Clone, Copy, Debug, Default)]
pub struct QueueMasks {
    pub vmids_mmhub: u16,
    pub vmids_gfxhub: u16,
    pub compute: [u32; 8],
    pub graphics: [u32; 2],
    pub sdma: [u32; 2],
    pub aggregated_doorbells: [u32; 5],
}
#[derive(Clone, Copy, Debug)]
pub struct Resources {
    pub bases: Bases,
    pub queues: QueueMasks,
    pub scheduler_context: u64,
    pub query_fence: u64,
    /// Low twelve bits of CP_MES_GP3_LO, not the container's file version.
    pub revision: u16,
}
/// SET_HW_RSRC: a KIQ owner passes zero queue/VMID masks; the scheduler grants
/// only resources it owns. VMID0 remains reserved for privileged driver work.
pub fn resources(res: &Resources) -> Result<Packet, Error> {
    if !address(res.scheduler_context, 8)
        || !address(res.query_fence, 8)
        || res.scheduler_context == res.query_fence
        || res.revision > 0xfff
        || (res.queues.vmids_mmhub | res.queues.vmids_gfxhub) & 1 != 0
        || res
            .queues
            .compute
            .iter()
            .chain(res.queues.graphics.iter())
            .any(|m| m & !0xff != 0)
        || res.queues.sdma.iter().any(|m| m & !0xff != 0)
    {
        return Err(Error::Invalid);
    }
    let mut p = Packet::new(0, 50);
    p.words[1] = u32::from(res.queues.vmids_mmhub);
    p.words[2] = u32::from(res.queues.vmids_gfxhub);
    p.words[5..13].copy_from_slice(&res.queues.compute);
    p.words[13..15].copy_from_slice(&res.queues.graphics);
    p.words[15..17].copy_from_slice(&res.queues.sdma);
    p.words[17..22].copy_from_slice(&res.queues.aggregated_doorbells);
    put64(&mut p.words, 22, res.scheduler_context);
    put64(&mut p.words, 24, res.query_fence);
    p.words[26..31].copy_from_slice(&res.bases.gc);
    p.words[34..39].copy_from_slice(&res.bases.mmhub);
    p.words[42..47].copy_from_slice(&res.bases.osssys);
    // Disable firmware reset/logging; distinct compute VMIDs, active-register
    // polling, per-level quantum checking, basic+ unmapped doorbell handling.
    p.words[54] = 0x00100447;
    p.words[55] = if res.revision < 0x8b { 0 } else { 50 };
    Ok(p)
}
/// SET_HW_RSRC_1, including the cleaner-shader fence introduced with MES12.
pub fn resources_1(cleaner_fence: u64) -> Result<Packet, Error> {
    if !address(cleaner_fence, 8) {
        return Err(Error::Invalid);
    }
    let mut p = Packet::new(19, 2);
    p.words[13] = 10; // KIQ unmap timeout, in 100-ms units.
    put64(&mut p.words, 16, cleaner_fence);
    Ok(p)
}
pub fn query_status() -> Packet {
    Packet::new(11, 2)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum QueueType {
    Graphics = 0,
    Compute = 1,
    Sdma = 2,
    Scheduler = 3,
}
#[derive(Clone, Copy, Debug)]
pub struct KernelQueue {
    pub kind: QueueType,
    pub pipe: u8,
    pub queue: u8,
    /// Doorbell offset in dwords; 64-bit doorbells require an even offset.
    pub doorbell: u32,
    pub mqd: u64,
    pub write_pointer: u64,
}
impl KernelQueue {
    fn valid(self) -> bool {
        let slot = match self.kind {
            QueueType::Graphics => self.pipe == 0 && self.queue < 8,
            QueueType::Compute => self.pipe < 2 && self.queue < 4,
            QueueType::Sdma => self.pipe < 2 && self.queue < 8,
            QueueType::Scheduler => self.pipe == 0 && self.queue == 0,
        };
        slot && self.doorbell % 2 == 0
            && self.doorbell < 1 << 26
            && address(self.mqd, 4096)
            && address(self.write_pointer, 8)
    }
}
pub fn map_kernel_queue(queue: KernelQueue) -> Result<Packet, Error> {
    if !queue.valid() {
        return Err(Error::Invalid);
    }
    let mut p = Packet::new(2, 38);
    p.words[18] = queue.doorbell;
    // MES12's dword 19 is alignment padding, unlike MES11's MQD low word.
    put64(&mut p.words, 20, queue.mqd);
    put64(&mut p.words, 22, queue.write_pointer);
    p.words[28] = queue.kind as u32;
    p.words[37] = 1 << 13; // map_legacy_kq
    p.words[50] = u32::from(queue.pipe);
    p.words[51] = u32::from(queue.queue);
    Ok(p)
}
pub fn unmap_kernel_queue(queue: KernelQueue) -> Result<Packet, Error> {
    if !queue.valid() {
        return Err(Error::Invalid);
    }
    let mut p = Packet::new(3, 6);
    p.words[1] = queue.doorbell;
    p.words[4] = 1 << 3; // unmap_legacy_queue; no reset or preempt-only claim.
    p.words[10] = u32::from(queue.pipe);
    p.words[11] = u32::from(queue.queue);
    p.words[15] = queue.kind as u32;
    Ok(p)
}
/// REMOVE_QUEUE of a kernel queue already reset by MMIO
/// (mes_v12_0_unmap_legacy_queue with RESET_QUEUES): as
/// `unmap_kernel_queue`, plus `remove_queue_after_reset` (bit 4) when
/// `drop_state` — scheduler firmware 0x5a and later — so MES drops its
/// state for the queue rather than asking the CP to unmap it again.
pub fn unmap_reset_kernel_queue(queue: KernelQueue, drop_state: bool) -> Result<Packet, Error> {
    let mut p = unmap_kernel_queue(queue)?;
    if drop_state {
        p.words[4] |= 1 << 4;
    }
    Ok(p)
}
/// SUSPEND of every gang (amdgpu_mes_suspend: `suspend_all_gangs`, no
/// suspend fence); pack(8) puts the status at 8.
pub fn suspend_all() -> Packet {
    let mut p = Packet::new(6, 8);
    p.words[1] = 1;
    p
}
/// RESUME of every gang (amdgpu_mes_resume: `resume_all_gangs`); the
/// status is at 4.
pub fn resume_all() -> Packet {
    let mut p = Packet::new(7, 4);
    p.words[1] = 1;
    p
}
/// RESET (mes_v12_0_reset_hw_queue without MMIO) of a kernel queue whose
/// job on VMID `vmid` hung: a graphics queue as a legacy HQD
/// (`reset_legacy_gfx` with its pipe, queue, VMID, MQD, doorbell and write
/// pointer), any other by its doorbell alone (`reset_queue_only`).
pub fn reset_kernel_queue(queue: KernelQueue, vmid: u8) -> Result<Packet, Error> {
    if !queue.valid() || vmid >= 16 {
        return Err(Error::Invalid);
    }
    // pack(8): flags at 1, gang context 2-3, doorbell 4, doorbell list
    // 6-7, queue type 8, the LP fields 9-17, HP 18-27, status 28.
    let mut p = Packet::new(8, 28);
    p.words[8] = queue.kind as u32;
    if queue.kind == QueueType::Graphics {
        p.words[1] = 1 << 3; // reset_legacy_gfx
        p.words[9] = u32::from(queue.pipe);
        p.words[10] = u32::from(queue.queue);
        p.words[11] = u32::from(vmid);
        put64(&mut p.words, 12, queue.mqd);
        p.words[14] = queue.doorbell;
        put64(&mut p.words, 16, queue.write_pointer);
    } else {
        p.words[1] = 1; // reset_queue_only
        p.words[4] = queue.doorbell;
    }
    Ok(p)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub code: u8,
    pub opcode: u8,
    pub misc: u8,
    pub category: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    Pending,
    Success,
    Rejected(Rejection),
}
/// The command's API fence must report one *and* the trailing query must drain
/// this exact sequence. A rejection is terminal only after the query drains.
pub fn completion(api: u64, query: u64, sequence: u64) -> Result<Completion, Error> {
    if sequence == 0 || sequence >= 1 << 63 {
        return Err(Error::Invalid);
    }
    if query < sequence {
        return Ok(Completion::Pending);
    }
    if query != sequence {
        return Err(Error::MalformedCompletion);
    }
    if api == 1 {
        return Ok(Completion::Success);
    }
    if api as u32 != 0 || api >> 63 != 1 {
        return Err(Error::MalformedCompletion);
    }
    let code = (api >> 32) as u32;
    Ok(Completion::Rejected(Rejection {
        code: code as u8,
        opcode: (code >> 8) as u8,
        misc: (code >> 16) as u8,
        category: ((code >> 24) & 0x7f) as u8,
    }))
}

/// GPU addresses of disjoint, retained VRAM allocations for a MES pipe's own
/// ring. Its v12_compute_mqd is distinct from an application's compute MQD.
#[derive(Clone, Copy, Debug)]
pub struct QueueMemory {
    pub descriptor: u64,
    pub ring: u64,
    pub ring_bytes: u32,
    pub eop: u64,
    pub read_pointer: u64,
    pub write_pointer: u64,
    pub doorbell: u32,
}
pub fn mqd(memory: QueueMemory) -> Result<[u32; 512], Error> {
    if !(1024..=1 << 20).contains(&memory.ring_bytes)
        || !memory.ring_bytes.is_power_of_two()
        || !address(memory.descriptor, 4096)
        || !address(memory.ring, 256)
        || !address(memory.eop, 256)
        || !address(memory.read_pointer, 8)
        || !address(memory.write_pointer, 8)
        || memory.doorbell % 2 != 0
        || memory.doorbell >= 1 << 26
    {
        return Err(Error::Invalid);
    }
    let ranges = [
        (memory.descriptor, 2048),
        (memory.ring, u64::from(memory.ring_bytes)),
        (memory.eop, 2048),
        (memory.read_pointer, 8),
        (memory.write_pointer, 8),
    ];
    for (i, &(base, size)) in ranges.iter().enumerate() {
        if base + size > ADDRESS_LIMIT
            || ranges[..i]
                .iter()
                .any(|&(b, s)| base < b + s && b < base + size)
        {
            return Err(Error::Invalid);
        }
    }
    let mut words = [0; 512];
    words[0] = 0xc0310800;
    words[11] = 1;
    for at in [23, 24, 26, 27] {
        words[at] = u32::MAX;
    }
    words[32] = 7;
    put64(&mut words, 128, memory.descriptor);
    words[130] = 1;
    words[132] = 0x0be05501;
    put64(&mut words, 136, memory.ring >> 8);
    put64(&mut words, 139, memory.read_pointer);
    put64(&mut words, 141, memory.write_pointer);
    words[143] = (memory.doorbell << 2) | (1 << 30);
    // Linux mes_v12_0_mqd_init uses gc_11 defaults. Its double shift of
    // RPTR_BLOCK_SIZE encodes zero; retain that firmware-tested value.
    words[145] = 0xd8308000 | ((memory.ring_bytes / 4).ilog2() - 1);
    words[149] = 0x00300000;
    words[162] = 0x100;
    put64(&mut words, 165, memory.eop >> 8);
    words[167] = 8; // 2048-byte EOP, 2^(EOP_SIZE+1) dwords.
    words[184] = 1 << 15; // MES12 CP_HQD_GFX_CONTROL.DB_UPDATED_MSG_EN.
    Ok(words)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_mes12_tests.rs"]
mod tests;
