//! AMD compute-queue submission via KIQ (Kernel Interface Queue).
//!
//! Compute queues on modern AMD GPUs are managed through the CP
//! MEC (Micro Engine for Compute). The kernel driver brings up
//! one KIQ (Kernel Interface Queue) that runs PM4 administrative
//! packets — SET_RESOURCES, MAP_QUEUES, UNMAP_QUEUES — and the
//! KIQ instructs the MEC to schedule user-mode compute queues.
//!
//! ## Reference
//!
//! - Linux `drivers/gpu/drm/amd/amdgpu/gfx_v11_0.c::gfx11_kiq_*`
//!   — KIQ packet construction for GFX11 (Phoenix / Strix).
//! - Linux `drivers/gpu/drm/amd/amdgpu/gfx_v9_0.c::gfx_v9_0_kiq_*`
//!   — same for GFX9 (Renoir, Cezanne).
//! - Linux `drivers/gpu/drm/amd/amdgpu/soc15d.h` — PACKET3
//!   opcode + field-shift values.
//! - Linux `drivers/gpu/drm/amd/amdgpu/amdgpu_ring.h` — ring +
//!   queue-mask semantics shared with the GFX ring.
//!
//! Linux is GPL-2.0-or-later (matches NARF). Structural patterns
//! adapted directly.
//!
//! ## Queue topology
//!
//! ```text
//!   MEC1
//!   ├─ pipe 0
//!   │  ├─ queue 0   ← KIQ (this driver manages)
//!   │  ├─ queue 1   ← user compute queue 0
//!   │  └─ queue 2   ← user compute queue 1
//!   └─ pipe 1
//!      ├─ queue 0   ← user compute queue 2
//!      └─ queue 1   ← user compute queue 3
//!   MEC2  (only on dGPU; APUs have one MEC)
//!   ├─ ...
//! ```
//!
//! 4 pipes × 8 queues = 32 hw queues per MEC theoretical max;
//! Linux uses 1 KIQ + 7 user queues per MEC pipe by default.

extern crate alloc;

use alloc::vec::Vec;

// ── PM4 opcodes (PACKET_TYPE3) ───────────────────────────────────
//
// Values per Linux `soc15d.h`. PACKET3 header format:
//   bits[31:30] = type (= 3)
//   bits[29:16] = predicate / reserved
//   bits[15:8]  = opcode
//   bits[7:0]   = (count - 1) in dwords
//
// `PACKET3_COMPUTE` sets bit 1 of the count field to flag a
// compute-queue packet (vs GFX queue).

/// Packet header dword for `(opcode, count)`.
pub const fn packet3(opcode: u8, count_minus_one: u8) -> u32 {
    (3u32 << 30) | ((opcode as u32) << 8) | (count_minus_one as u32)
}

/// Same as [`packet3`] but flags the packet as bound for a
/// compute queue (sets bit 1).
pub const fn packet3_compute(opcode: u8, count_minus_one: u8) -> u32 {
    packet3(opcode, count_minus_one) | (1 << 1)
}

/// PACKET3 NOP.
pub const PACKET3_NOP: u8 = 0x10;
/// PACKET3 INDIRECT_BUFFER — chain to a user-supplied IB.
pub const PACKET3_INDIRECT_BUFFER: u8 = 0x3F;
/// PACKET3 SET_RESOURCES — KIQ bring-up.
pub const PACKET3_SET_RESOURCES: u8 = 0xA0;
/// PACKET3 MAP_QUEUES — bind a compute queue to a pipe.
pub const PACKET3_MAP_QUEUES: u8 = 0xA2;
/// PACKET3 UNMAP_QUEUES — release a compute queue.
pub const PACKET3_UNMAP_QUEUES: u8 = 0xA3;
/// PACKET3 QUERY_STATUS — query KIQ status (for fence-style sync).
pub const PACKET3_QUERY_STATUS: u8 = 0xA4;

// ── PACKET3_MAP_QUEUES field shifts (per soc15d.h) ───────────────

pub const MAP_QUEUES_QUEUE_SEL_SHIFT: u32 = 4;
pub const MAP_QUEUES_VMID_SHIFT: u32 = 8;
pub const MAP_QUEUES_QUEUE_SHIFT: u32 = 13;
pub const MAP_QUEUES_PIPE_SHIFT: u32 = 16;
pub const MAP_QUEUES_ME_SHIFT: u32 = 18;
pub const MAP_QUEUES_QUEUE_TYPE_SHIFT: u32 = 21;
pub const MAP_QUEUES_ALLOC_FORMAT_SHIFT: u32 = 24;
pub const MAP_QUEUES_ENGINE_SEL_SHIFT: u32 = 26;
pub const MAP_QUEUES_NUM_QUEUES_SHIFT: u32 = 29;
pub const MAP_QUEUES_DOORBELL_OFFSET_SHIFT: u32 = 2;

// ── PACKET3_SET_RESOURCES field shifts ───────────────────────────

pub const SET_RESOURCES_VMID_MASK_SHIFT: u32 = 0;
pub const SET_RESOURCES_UNMAP_LATENCY_SHIFT: u32 = 16;
pub const SET_RESOURCES_QUEUE_TYPE_SHIFT: u32 = 29;

// ── Ring kind ────────────────────────────────────────────────────

/// Ring kind — bound for which engine selector. PACKET3_MAP_QUEUES
/// encodes this in the ENGINE_SEL field.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RingKind {
    /// Compute queue (MEC). eng_sel = 0, me = 1.
    Compute,
    /// GFX queue (CP). eng_sel = 4, me = 0.
    Gfx,
    /// MES (Micro Engine Scheduler). eng_sel = 5, me = 2.
    Mes,
}

impl RingKind {
    pub const fn engine_sel(self) -> u32 {
        match self {
            RingKind::Compute => 0,
            RingKind::Gfx => 4,
            RingKind::Mes => 5,
        }
    }
    pub const fn me_id(self) -> u32 {
        match self {
            RingKind::Compute => 1,
            RingKind::Gfx => 0,
            RingKind::Mes => 2,
        }
    }
}

// ── KIQ packets ──────────────────────────────────────────────────

/// Build a SET_RESOURCES packet — initial KIQ bring-up.
/// `queue_mask` is a bitmap of which compute queues the host wants
/// the MEC to consider for scheduling. `unmap_latency` is in
/// units of 100 µs (Linux uses 0xa ≈ 1 ms; default in spec).
pub fn build_set_resources(
    queue_mask: u64,
    unmap_latency: u8,
    queue_type: u8,
    cleaner_shader_phys: u64,
) -> Vec<u32> {
    let header = packet3(PACKET3_SET_RESOURCES, 6);
    let cfg = ((0u32) << SET_RESOURCES_VMID_MASK_SHIFT)
        | ((unmap_latency as u32) << SET_RESOURCES_UNMAP_LATENCY_SHIFT)
        | ((queue_type as u32) << SET_RESOURCES_QUEUE_TYPE_SHIFT);
    // Cleaner-shader phys is shifted right by 8 per gfx11 source.
    let cleaner = cleaner_shader_phys >> 8;
    alloc::vec![
        header,
        cfg,
        queue_mask as u32,
        (queue_mask >> 32) as u32,
        cleaner as u32,
        (cleaner >> 32) as u32,
        0, // oac mask
        0, // gds heap base / size
    ]
}

/// Build a MAP_QUEUES packet — bind a single queue to the MEC.
///
/// Arguments mirror the Linux `gfx11_kiq_map_queues` call site.
/// `mqd_phys` is the MQD (Memory Queue Descriptor) phys; the MEC
/// reads its per-queue config from there. `wptr_phys` is the
/// host-writable wptr area.
pub fn build_map_queue(
    ring_kind: RingKind,
    pipe: u8,
    queue: u8,
    doorbell_off: u32,
    mqd_phys: u64,
    wptr_phys: u64,
) -> Vec<u32> {
    let header = packet3(PACKET3_MAP_QUEUES, 5);
    let cfg = (0u32 << MAP_QUEUES_QUEUE_SEL_SHIFT)
        | (0u32 << MAP_QUEUES_VMID_SHIFT)
        | ((queue as u32) << MAP_QUEUES_QUEUE_SHIFT)
        | ((pipe as u32) << MAP_QUEUES_PIPE_SHIFT)
        | (ring_kind.me_id() << MAP_QUEUES_ME_SHIFT)
        | (0u32 << MAP_QUEUES_QUEUE_TYPE_SHIFT)
        | (0u32 << MAP_QUEUES_ALLOC_FORMAT_SHIFT)
        | (ring_kind.engine_sel() << MAP_QUEUES_ENGINE_SEL_SHIFT)
        | (1u32 << MAP_QUEUES_NUM_QUEUES_SHIFT);
    let dbell = (doorbell_off as u32) << MAP_QUEUES_DOORBELL_OFFSET_SHIFT;
    alloc::vec![
        header,
        cfg,
        dbell,
        mqd_phys as u32,
        (mqd_phys >> 32) as u32,
        wptr_phys as u32,
        (wptr_phys >> 32) as u32,
    ]
}

/// PACKET3_UNMAP_QUEUES action enum. Linux's
/// `amdgpu_unmap_queues_action`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum UnmapAction {
    /// Drain pending work, then unmap.
    Preempt = 0,
    /// Force immediate unmap (drop in-flight work).
    Reset = 1,
    /// Preempt + leave the queue mapped (used for context switch).
    PreemptNoUnmap = 2,
    /// Drain all queues.
    DisableProcessQueues = 3,
}

/// Build an UNMAP_QUEUES packet.
pub fn build_unmap_queue(ring_kind: RingKind, doorbell_off: u32, action: UnmapAction) -> Vec<u32> {
    let header = packet3(PACKET3_UNMAP_QUEUES, 4);
    let cfg = ((action as u32) << 0) // ACTION
        | (0u32 << 4)                // QUEUE_SEL
        | (ring_kind.engine_sel() << 26)
        | (1u32 << 29); // NUM_QUEUES
    let dbell = (doorbell_off as u32) << 2;
    alloc::vec![header, cfg, dbell, 0, 0, 0]
}

/// PACKET3 INDIRECT_BUFFER — chain into a user IB.
///
/// `ib_phys` is the IB's base; the low 30 bits go into IB_BASE_LO
/// (shifted left by 2). `size_dws` is in dwords; max 20-bit.
///
/// `vmid` is the per-process VMID the IB will be evaluated under.
/// `vmid = 0` is the kernel-owned VMID.
pub fn build_indirect_buffer(ib_phys: u64, size_dws: u32, vmid: u8) -> Vec<u32> {
    let header = packet3(PACKET3_INDIRECT_BUFFER, 2);
    let lo = (ib_phys & 0xFFFF_FFFF) as u32;
    let hi = (ib_phys >> 32) as u32;
    let size_field = size_dws & 0xF_FFFF;
    let attr = size_field | (1u32 << 23) | ((vmid as u32) << 24);
    alloc::vec![
        header,
        lo,
        hi | (lo & 0xC000_0000_u32.wrapping_shr(2)),
        attr
    ]
}

// ── Compute queue state ──────────────────────────────────────────

/// One compute queue the KIQ has mapped. Tracks the (me, pipe,
/// queue) coordinate + the per-queue doorbell offset + MQD.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeQueue {
    pub me: u8,
    pub pipe: u8,
    pub queue: u8,
    pub doorbell_off: u32,
    pub mqd_phys: u64,
    /// Bound VMID, if known.
    pub vmid: Option<u8>,
    pub mapped: bool,
    /// Per-queue priority — used by the round-robin scheduler.
    pub priority: ComputePriority,
    /// CWSR save area + ctl stack layout. `None` if the queue is
    /// non-preemptible (legacy compute path); `Some` after
    /// `attach_cwsr` programs the MQD.
    pub cwsr: Option<CwsrMqdFields>,
}

/// KIQ scheduler — owns the queue pool + brings up / tears down
/// compute queues on behalf of user-mode submitters.
#[derive(Clone, Debug, Default)]
pub struct KiqScheduler {
    pub queues: Vec<ComputeQueue>,
    /// Total queue mask (bitmap of which (pipe, queue) slots
    /// are owned by the KIQ vs left for the GFX ring).
    pub queue_mask: u64,
    /// `true` if SET_RESOURCES has been issued (initial KIQ
    /// bring-up complete).
    pub initialised: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ComputeError {
    NotInitialised,
    QueueExists,
    NoSuchQueue,
    PipeQueueOutOfRange,
}

impl KiqScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark the KIQ as initialised. Called after SET_RESOURCES
    /// has been written + executed.
    pub fn mark_initialised(&mut self, queue_mask: u64) {
        self.queue_mask = queue_mask;
        self.initialised = true;
    }

    /// Map a fresh compute queue. Returns the queue index in
    /// the scheduler's pool.
    ///
    /// Valid (me, pipe, queue) per MEC:
    ///   - me ∈ {1, 2}    (MEC1 / MEC2)
    ///   - pipe ∈ {0..4}  (4 pipes per MEC)
    ///   - queue ∈ {0..8} (8 queues per pipe)
    pub fn map_queue(
        &mut self,
        me: u8,
        pipe: u8,
        queue: u8,
        doorbell_off: u32,
        mqd_phys: u64,
    ) -> Result<usize, ComputeError> {
        if !self.initialised {
            return Err(ComputeError::NotInitialised);
        }
        if me == 0 || me > 2 || pipe >= 4 || queue >= 8 {
            return Err(ComputeError::PipeQueueOutOfRange);
        }
        if self
            .queues
            .iter()
            .any(|q| q.me == me && q.pipe == pipe && q.queue == queue)
        {
            return Err(ComputeError::QueueExists);
        }
        let cq = ComputeQueue {
            me,
            pipe,
            queue,
            doorbell_off,
            mqd_phys,
            vmid: None,
            mapped: true,
            priority: ComputePriority::default(),
            cwsr: None,
        };
        let idx = self.queues.len();
        self.queues.push(cq);
        Ok(idx)
    }

    /// Attach a CWSR save area to an already-mapped queue. The MQD
    /// must be updated separately (the driver-glue layer writes the
    /// `cp_hqd_ctx_save_*` fields into the MQD memory).
    pub fn attach_cwsr(&mut self, idx: usize, fields: CwsrMqdFields) -> Result<(), ComputeError> {
        let q = self.queues.get_mut(idx).ok_or(ComputeError::NoSuchQueue)?;
        q.cwsr = Some(fields);
        Ok(())
    }

    /// Set a queue's priority. Affects [`next_queue_at_priority`]
    /// + [`build_set_priority`] (which produces the MES PM4 packet
    /// to push the new priority to the hardware scheduler).
    pub fn set_priority(
        &mut self,
        idx: usize,
        priority: ComputePriority,
    ) -> Result<(), ComputeError> {
        let q = self.queues.get_mut(idx).ok_or(ComputeError::NoSuchQueue)?;
        q.priority = priority;
        Ok(())
    }

    /// Unmap a queue by scheduler index.
    pub fn unmap_queue(&mut self, idx: usize) -> Result<(), ComputeError> {
        let q = self.queues.get_mut(idx).ok_or(ComputeError::NoSuchQueue)?;
        q.mapped = false;
        Ok(())
    }

    /// Bind a VMID to a queue (per-process address space binding).
    pub fn bind_vmid(&mut self, idx: usize, vmid: u8) -> Result<(), ComputeError> {
        let q = self.queues.get_mut(idx).ok_or(ComputeError::NoSuchQueue)?;
        q.vmid = Some(vmid);
        Ok(())
    }

    /// Currently-mapped queue count.
    pub fn mapped_count(&self) -> usize {
        self.queues.iter().filter(|q| q.mapped).count()
    }

    /// Pick the next queue to schedule under a round-robin policy
    /// among queues at the given priority level. Returns `None` if
    /// no mapped queue matches the priority.
    pub fn next_queue_at_priority(&self, priority: ComputePriority, start: usize) -> Option<usize> {
        let n = self.queues.len();
        if n == 0 {
            return None;
        }
        for offset in 0..n {
            let i = (start + offset) % n;
            let q = &self.queues[i];
            if q.mapped && q.priority == priority {
                return Some(i);
            }
        }
        None
    }
}

// ── Compute Wave Save/Restore (CWSR) ───────────────────────────────
//
// CWSR is the mechanism the GPU uses to preempt a long-running
// compute kernel mid-wavefront. When the kernel-mode scheduler
// signals a preemption, a per-wave trap handler saves the wave's
// VGPRs / SGPRs / scratch ring state into a kernel-owned save area
// addressed by `CP_HQD_CTX_SAVE_BASE_ADDR_LO/HI` and
// `CP_HQD_CTX_SAVE_SIZE`.  When the queue is rescheduled the trap
// handler restores from the same area.
//
// MQD fields per Linux v10_compute_mqd / v11_compute_mqd:
//   cp_hqd_persistent_state |= QSWITCH_MODE bit
//   cp_hqd_ctx_save_base_addr_lo/hi = ctx_save area phys
//   cp_hqd_ctx_save_size            = area size in bytes
//   cp_hqd_cntl_stack_size          = ctl_stack size in bytes
//   cp_hqd_cntl_stack_offset        = ctl_stack_size (offset = size
//                                       because ctl stack is at the
//                                       *top* of the save area)
//   cp_hqd_wg_state_offset          = ctl_stack_size (same reason)
//
// References:
//   - Linux drivers/gpu/drm/amd/amdkfd/kfd_mqd_manager_v10.c:120-148
//   - Linux drivers/gpu/drm/amd/amdkfd/cwsr_trap_handler_gfx10.asm
//     (the actual on-GPU shader that does the save/restore).

/// CWSR-related fields a kernel-mode driver writes into the MQD.
/// These are the *host-side* shape — the actual MQD layout is per-
/// generation, but every modern compute MQD carries these fields.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CwsrMqdFields {
    /// `cp_hqd_ctx_save_base_addr_{lo,hi}` — phys of the save area.
    pub ctx_save_base_phys: u64,
    /// `cp_hqd_ctx_save_size` — bytes.
    pub ctx_save_size: u32,
    /// `cp_hqd_cntl_stack_size` / `_offset` — bytes.
    pub ctl_stack_size: u32,
    /// `cp_hqd_wg_state_offset` — bytes (equals `ctl_stack_size`).
    pub wg_state_offset: u32,
    /// `cp_hqd_persistent_state.QSWITCH_MODE` bit set on the MQD.
    pub persistent_state_qswitch: bool,
}

/// Errors building CWSR fields.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CwsrError {
    /// Save area phys not 4 KiB aligned.
    BadSaveAreaAlignment,
    /// Save area too small for ctl stack + working area.
    SaveAreaTooSmall,
    /// Ctl stack size larger than save area.
    CtlStackTooLarge,
}

/// Build the CWSR MQD field set. `ctl_stack_size` is the upper
/// part of the save area reserved for the trap handler's control
/// stack; the lower part holds the VGPR/SGPR/scratch state.
///
/// Mirrors the field assignment in `kfd_mqd_manager_v10.c::init_mqd`
/// (line 132-143). The trap-handler layout puts the control stack
/// at the top, so its offset equals the size.
pub fn build_cwsr_fields(
    ctx_save_base_phys: u64,
    ctx_save_size: u32,
    ctl_stack_size: u32,
) -> Result<CwsrMqdFields, CwsrError> {
    if ctx_save_base_phys & 0xFFF != 0 {
        return Err(CwsrError::BadSaveAreaAlignment);
    }
    // Minimum: at least 64 KiB of state + the ctl stack.
    const MIN_STATE_BYTES: u32 = 64 * 1024;
    if ctx_save_size < ctl_stack_size + MIN_STATE_BYTES {
        return Err(CwsrError::SaveAreaTooSmall);
    }
    if ctl_stack_size > ctx_save_size {
        return Err(CwsrError::CtlStackTooLarge);
    }
    Ok(CwsrMqdFields {
        ctx_save_base_phys,
        ctx_save_size,
        ctl_stack_size,
        wg_state_offset: ctl_stack_size,
        persistent_state_qswitch: true,
    })
}

/// Per-queue compute priority. Matches `MES_AMD_PRIORITY_LEVEL`.
/// Used by the round-robin scheduler in `KiqScheduler::next_queue_at_priority`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ComputePriority {
    Low,
    Normal,
    Medium,
    High,
    Realtime,
}

impl Default for ComputePriority {
    fn default() -> Self {
        ComputePriority::Normal
    }
}

/// Extend [`ComputeQueue`] with CWSR + priority via an associated
/// state struct. Kept separate so the existing [`ComputeQueue`]
/// surface is unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueScheduleState {
    pub priority: ComputePriority,
    /// `Some` if the queue has a CWSR save area allocated.
    pub cwsr: Option<CwsrMqdFields>,
    /// `true` while a preemption is being driven (between
    /// PREEMPT_QUEUE PM4 and the matching IH cookie).
    pub preempting: bool,
}

impl Default for QueueScheduleState {
    fn default() -> Self {
        Self {
            priority: ComputePriority::Normal,
            cwsr: None,
            preempting: false,
        }
    }
}

// ── Smoke tests ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_packet3_header_encoding() -> TestResult {
        // PACKET3 (op=NOP=0x10, count-1=0).
        let h = packet3(PACKET3_NOP, 0);
        if h >> 30 != 3 {
            return TestResult::Fail("type field wrong");
        }
        if (h >> 8) & 0xFF != PACKET3_NOP as u32 {
            return TestResult::Fail("opcode field wrong");
        }
        if h & 0xFF != 0 {
            return TestResult::Fail("count field wrong");
        }
        // PACKET3_COMPUTE sets bit 1 of count.
        let h = packet3_compute(PACKET3_INDIRECT_BUFFER, 2);
        if h & (1 << 1) == 0 {
            return TestResult::Fail("compute flag not set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_packet3_header_encoding);

    fn smoke_set_resources_packet_shape() -> TestResult {
        let q_mask = 0x0000_FF00_FF00_FF00u64;
        let p = build_set_resources(q_mask, 0xa, 0, 0x1_0000_2000);
        if p.len() != 8 {
            return TestResult::Fail("SET_RESOURCES should be 8 dwords");
        }
        // header
        if (p[0] >> 8) & 0xFF != PACKET3_SET_RESOURCES as u32 {
            return TestResult::Fail("header opcode wrong");
        }
        // queue_mask lo/hi
        if p[2] != q_mask as u32 {
            return TestResult::Fail("queue mask lo wrong");
        }
        if p[3] != (q_mask >> 32) as u32 {
            return TestResult::Fail("queue mask hi wrong");
        }
        // cleaner shader phys is >> 8 per gfx11
        let cleaner_expected = 0x1_0000_2000u64 >> 8;
        if p[4] != cleaner_expected as u32 {
            return TestResult::Fail("cleaner shader lo wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_set_resources_packet_shape);

    fn smoke_map_queue_packet_shape() -> TestResult {
        // Compute queue at (me=1, pipe=0, queue=1) with doorbell
        // offset 0x200, MQD at 0xA000_0000.
        let p = build_map_queue(RingKind::Compute, 0, 1, 0x200, 0xA000_0000, 0xB000_0000);
        if p.len() != 7 {
            return TestResult::Fail("MAP_QUEUES should be 7 dwords");
        }
        if (p[0] >> 8) & 0xFF != PACKET3_MAP_QUEUES as u32 {
            return TestResult::Fail("header opcode wrong");
        }
        // cfg field decode.
        let cfg = p[1];
        if (cfg >> MAP_QUEUES_PIPE_SHIFT) & 0x3 != 0 {
            return TestResult::Fail("pipe field wrong");
        }
        if (cfg >> MAP_QUEUES_QUEUE_SHIFT) & 0x7 != 1 {
            return TestResult::Fail("queue field wrong");
        }
        if (cfg >> MAP_QUEUES_ME_SHIFT) & 0x3 != 1 {
            return TestResult::Fail("me=1 for compute");
        }
        if (cfg >> MAP_QUEUES_ENGINE_SEL_SHIFT) & 0x7 != 0 {
            return TestResult::Fail("engine_sel=0 for compute");
        }
        // GFX queue should pick engine_sel=4, me=0.
        let p_gfx = build_map_queue(RingKind::Gfx, 0, 0, 0x300, 0xC000_0000, 0xD000_0000);
        let cfg_gfx = p_gfx[1];
        if (cfg_gfx >> MAP_QUEUES_ME_SHIFT) & 0x3 != 0 {
            return TestResult::Fail("me=0 for GFX");
        }
        if (cfg_gfx >> MAP_QUEUES_ENGINE_SEL_SHIFT) & 0x7 != 4 {
            return TestResult::Fail("engine_sel=4 for GFX");
        }
        // MES queue should pick engine_sel=5, me=2.
        let p_mes = build_map_queue(RingKind::Mes, 0, 0, 0x400, 0xE000_0000, 0xF000_0000);
        let cfg_mes = p_mes[1];
        if (cfg_mes >> MAP_QUEUES_ME_SHIFT) & 0x3 != 2 {
            return TestResult::Fail("me=2 for MES");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_map_queue_packet_shape);

    fn smoke_unmap_queue_actions() -> TestResult {
        for action in [
            UnmapAction::Preempt,
            UnmapAction::Reset,
            UnmapAction::PreemptNoUnmap,
            UnmapAction::DisableProcessQueues,
        ] {
            let p = build_unmap_queue(RingKind::Compute, 0x200, action);
            if p.len() != 6 {
                return TestResult::Fail("UNMAP_QUEUES should be 6 dwords");
            }
            // Action lives in the low 4 bits of the cfg field.
            if p[1] & 0xF != action as u32 {
                return TestResult::Fail("action encoding wrong");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_unmap_queue_actions);

    fn smoke_kiq_scheduler_lifecycle() -> TestResult {
        let mut k = KiqScheduler::new();
        // Pre-init operations fail.
        match k.map_queue(1, 0, 0, 0x100, 0x1000) {
            Err(ComputeError::NotInitialised) => {}
            _ => return TestResult::Fail("map_queue pre-init should fail"),
        }
        k.mark_initialised(0xFF);
        // Successful map.
        let idx = k.map_queue(1, 0, 1, 0x100, 0xA000).expect("map");
        if idx != 0 {
            return TestResult::Fail("first queue not idx 0");
        }
        if k.mapped_count() != 1 {
            return TestResult::Fail("mapped count wrong");
        }
        // Duplicate (me, pipe, queue) rejected.
        match k.map_queue(1, 0, 1, 0x200, 0xB000) {
            Err(ComputeError::QueueExists) => {}
            _ => return TestResult::Fail("duplicate not rejected"),
        }
        // Out-of-range coordinates rejected.
        match k.map_queue(0, 0, 0, 0x100, 0x1000) {
            Err(ComputeError::PipeQueueOutOfRange) => {}
            _ => return TestResult::Fail("me=0 should be out of range"),
        }
        match k.map_queue(1, 99, 0, 0x100, 0x1000) {
            Err(ComputeError::PipeQueueOutOfRange) => {}
            _ => return TestResult::Fail("pipe=99 should be out of range"),
        }
        // Bind VMID.
        k.bind_vmid(idx, 7).expect("bind_vmid");
        if k.queues[idx].vmid != Some(7) {
            return TestResult::Fail("vmid not recorded");
        }
        // Unmap.
        k.unmap_queue(idx).expect("unmap");
        if k.queues[idx].mapped {
            return TestResult::Fail("unmap didn't clear flag");
        }
        if k.mapped_count() != 0 {
            return TestResult::Fail("mapped count after unmap");
        }
        // Out-of-bounds unmap rejected.
        match k.unmap_queue(99) {
            Err(ComputeError::NoSuchQueue) => {}
            _ => return TestResult::Fail("unmap missing queue not rejected"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_kiq_scheduler_lifecycle);

    fn smoke_ring_kind_engine_me() -> TestResult {
        if RingKind::Compute.engine_sel() != 0 || RingKind::Compute.me_id() != 1 {
            return TestResult::Fail("compute engine_sel/me wrong");
        }
        if RingKind::Gfx.engine_sel() != 4 || RingKind::Gfx.me_id() != 0 {
            return TestResult::Fail("gfx engine_sel/me wrong");
        }
        if RingKind::Mes.engine_sel() != 5 || RingKind::Mes.me_id() != 2 {
            return TestResult::Fail("mes engine_sel/me wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_ring_kind_engine_me);

    // ── CWSR + priority ───────────────────────────────────────

    fn smoke_cwsr_fields_rejects_misalignment() -> TestResult {
        // 4KiB-misaligned save area is invalid.
        match build_cwsr_fields(0x1001, 0x80000, 0x4000) {
            Err(CwsrError::BadSaveAreaAlignment) => {}
            _ => return TestResult::Fail("misalignment not flagged"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_cwsr_fields_rejects_misalignment);

    fn smoke_cwsr_fields_rejects_undersized_save_area() -> TestResult {
        // Save area only big enough for ctl stack — no room for state.
        match build_cwsr_fields(0x1000, 0x8000, 0x8000) {
            Err(CwsrError::SaveAreaTooSmall) => {}
            _ => return TestResult::Fail("undersized save area not flagged"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_cwsr_fields_rejects_undersized_save_area
    );

    fn smoke_cwsr_fields_layout_correct() -> TestResult {
        let f = build_cwsr_fields(0x10_0000, 0x10_0000, 0x4000).expect("cwsr");
        if f.ctx_save_base_phys != 0x10_0000 {
            return TestResult::Fail("base phys wrong");
        }
        if f.ctl_stack_size != 0x4000 {
            return TestResult::Fail("ctl stack size wrong");
        }
        if f.wg_state_offset != 0x4000 {
            return TestResult::Fail("wg_state_offset must equal ctl stack size");
        }
        if !f.persistent_state_qswitch {
            return TestResult::Fail("QSWITCH bit not set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_cwsr_fields_layout_correct);

    fn smoke_attach_cwsr_to_mapped_queue() -> TestResult {
        let mut sched = KiqScheduler::new();
        sched.mark_initialised(0xFF);
        let idx = sched.map_queue(1, 0, 1, 0x100, 0xCAFE_0000).expect("map");
        let fields = build_cwsr_fields(0x10_0000, 0x10_0000, 0x4000).expect("cwsr");
        sched.attach_cwsr(idx, fields).expect("attach");
        if sched.queues[idx].cwsr.is_none() {
            return TestResult::Fail("CWSR not attached");
        }
        // Attaching to a missing queue rejects.
        match sched.attach_cwsr(99, fields) {
            Err(ComputeError::NoSuchQueue) => {}
            _ => return TestResult::Fail("bogus idx not rejected"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_attach_cwsr_to_mapped_queue);

    fn smoke_set_priority_round_robin() -> TestResult {
        let mut sched = KiqScheduler::new();
        sched.mark_initialised(0xFF);
        let q0 = sched.map_queue(1, 0, 0, 0x100, 0x1000).expect("q0");
        let q1 = sched.map_queue(1, 0, 1, 0x200, 0x2000).expect("q1");
        let q2 = sched.map_queue(1, 0, 2, 0x300, 0x3000).expect("q2");
        sched.set_priority(q0, ComputePriority::High).expect("p0");
        sched.set_priority(q1, ComputePriority::Normal).expect("p1");
        sched.set_priority(q2, ComputePriority::High).expect("p2");
        // Iterate at High priority — should pick q0 then q2.
        let pick0 = sched
            .next_queue_at_priority(ComputePriority::High, 0)
            .expect("pick0");
        if pick0 != q0 {
            return TestResult::Fail("first high-prio pick wrong");
        }
        let pick1 = sched
            .next_queue_at_priority(ComputePriority::High, pick0 + 1)
            .expect("pick1");
        if pick1 != q2 {
            return TestResult::Fail("second high-prio pick should wrap to q2");
        }
        // No realtime queues yet.
        if sched
            .next_queue_at_priority(ComputePriority::Realtime, 0)
            .is_some()
        {
            return TestResult::Fail("realtime should be empty");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_set_priority_round_robin);
}
