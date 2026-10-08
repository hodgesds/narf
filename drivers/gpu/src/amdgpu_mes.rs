//! AMD MES (Micro Engine Scheduler) v11 — Phoenix scheduler bring-up.
//!
//! On GFX11 hardware (Phoenix HawkPoint, Strix), AMD shipped a new
//! firmware scheduler — the MES — that supplants the KIQ-based
//! queue map/unmap protocol. The MES is a small RISC-V core (Aldebaran
//! onwards uses RS64) running its own scheduler firmware
//! (`mes_*.bin`), connected to a doorbell ring + the same GPU-visible
//! sysmem fabric as the user-mode queues.
//!
//! The KIQ remains alive for legacy GFX-ring management, but compute
//! queues + the user-mode gang scheduler go through MES.
//!
//! ## Protocol shape
//!
//! Each MES API command is a 64-dword aligned packet (`API_FRAME_SIZE_IN_DWORDS`)
//! ending in a `MES_API_STATUS` block. The host:
//!
//!   1. Writes the packet to a per-queue ring buffer in sysmem.
//!   2. Bumps the doorbell.
//!   3. Polls the api-status completion fence at
//!      `api_completion_fence_addr` for `api_completion_fence_value`.
//!
//! The MES firmware drains commands from the ring and bumps the fence
//! when the command has been processed.
//!
//! ## What this module ships
//!
//! - `MesApiHeader` — the 32-bit header word every packet carries:
//!   type=1 (SCHEDULER) | opcode | dwsize.
//! - `MesApiOpcode` — full SET_HW_RSRC / ADD_QUEUE / REMOVE_QUEUE
//!   opcode enumeration verbatim from `mes_v11_api_def.h`.
//! - `MesQueueType` + `MesPriority` — supporting enums.
//! - `build_set_hw_resources` — initial MES bring-up command.
//! - `build_add_queue` — the per-user-queue add command (process VM
//!   binding, doorbell, MQD, wptr).
//! - `build_remove_queue` — tear-down.
//! - `MesRing` — host-side mirror of the MES command ring head/tail.
//!
//! ## References (post 2026-05-20 GPL relicense)
//!
//! - drivers/gpu/drm/amd/include/mes_v11_api_def.h:36-350
//! - drivers/gpu/drm/amd/amdgpu/mes_v11_0.c:280-540
//! - drivers/gpu/drm/amd/amdgpu/amdgpu_mes.c:* (host wrapper / fence)

extern crate alloc;

use alloc::vec::Vec;

// ── API constants verbatim from mes_v11_api_def.h ──────────────────

/// `API_FRAME_SIZE_IN_DWORDS`. Every MES packet is padded to this
/// size, even if the payload is shorter.
pub const MES_API_FRAME_DWORDS: usize = 64;

/// `MES_API_TYPE_SCHEDULER = 1`. The other (`MES_API_TYPE_MAX`) is
/// reserved.
pub const MES_API_TYPE_SCHEDULER: u32 = 1;

// ── Opcode enumeration ────────────────────────────────────────────

/// `enum MES_SCH_API_OPCODE` verbatim.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MesApiOpcode {
    SetHwRsrc = 0,
    SetSchedulingConfig = 1,
    AddQueue = 2,
    RemoveQueue = 3,
    PerformYield = 4,
    SetGangPriorityLevel = 5,
    Suspend = 6,
    Resume = 7,
    Reset = 8,
    SetLogBuffer = 9,
    ChangeGangPriority = 10,
    QuerySchedulerStatus = 11,
    ProgramGds = 12,
    SetDebugVmid = 13,
    Misc = 14,
    UpdateRootPageTable = 15,
    AmdLog = 16,
    SetHwRsrc1 = 19,
}

// ── Queue / priority enums ────────────────────────────────────────

/// `enum MES_QUEUE_TYPE`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
#[derive(Default)]
pub enum MesQueueType {
    Gfx = 0,
    #[default]
    Compute = 1,
    Sdma = 2,
}

/// `enum MES_AMD_PRIORITY_LEVEL`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
#[derive(Default)]
pub enum MesPriority {
    Low = 0,
    #[default]
    Normal = 1,
    Medium = 2,
    High = 3,
    Realtime = 4,
}

// ── Header word ───────────────────────────────────────────────────

/// `union MES_API_HEADER`:
///   bits[3:0]   = type
///   bits[11:4]  = opcode
///   bits[19:12] = dwsize (incl. header)
///   bits[31:20] = reserved
///
/// `dwsize` is always [`MES_API_FRAME_DWORDS`] — every `mes_v11_0.c` packet
/// sets `header.dwsize = API_FRAME_SIZE_IN_DWORDS`, never a payload length.
/// The whole frame is on the wire whatever the packet carries, so a shorter
/// declared size would have MES stop reading before the fields it needs.
pub fn make_api_header(opcode: MesApiOpcode, dwsize: u32) -> u32 {
    (MES_API_TYPE_SCHEDULER & 0xF) | (((opcode as u32) & 0xFF) << 4) | ((dwsize & 0xFF) << 12)
}

/// Decode header (for testing): `(type, opcode, dwsize)`.
pub fn decode_api_header(hdr: u32) -> (u32, u32, u32) {
    (hdr & 0xF, (hdr >> 4) & 0xFF, (hdr >> 12) & 0xFF)
}

// ── Packet builders ────────────────────────────────────────────────

/// `#pragma pack(push, 4)` covers the whole of `mes_v11_api_def.h`, so every
/// packet is a flat dword array with no alignment padding: a `uint64_t` can
/// and does start on an odd dword. `doorbell_offset` at dword 18 followed
/// immediately by `mqd_addr` at 19 is the case that shows it.
///
/// The builders below therefore place each field at a named dword index taken
/// from `offsetof(…)/4`, rather than pushing fields in order and trusting the
/// count to come out right.
fn frame(opcode: MesApiOpcode) -> Vec<u32> {
    let mut dws = alloc::vec![0u32; MES_API_FRAME_DWORDS];
    dws[0] = make_api_header(opcode, MES_API_FRAME_DWORDS as u32);
    dws
}

/// Write a `uint64_t` at `dw`, low half first. Packed, so `dw` may be odd.
fn put64(dws: &mut [u32], dw: usize, value: u64) {
    dws[dw] = value as u32;
    dws[dw + 1] = (value >> 32) as u32;
}

// ── MESAPI_SET_HW_RESOURCES ───────────────────────────────────────

/// `MAX_COMPUTE_PIPES`. `compute_hqd_mask` is an array of eight per-pipe
/// dwords, not one 64-bit mask.
pub const MAX_COMPUTE_PIPES: usize = 8;
/// `MAX_GFX_PIPES` and `MAX_SDMA_PIPES`, both two — also arrays, not scalars.
pub const MAX_GFX_PIPES: usize = 2;
pub const MAX_SDMA_PIPES: usize = 2;
/// `AMD_PRIORITY_NUM_LEVELS`, matching [`MesPriority`]'s five variants.
pub const AMD_PRIORITY_NUM_LEVELS: usize = 5;
/// `MES_MAX_HWIP_SEGMENT`. `mes_v11_0_set_hw_resources` fills only the first
/// five of each base array, leaving the rest zero.
pub const MES_MAX_HWIP_SEGMENT: usize = 8;
/// How many segments Linux actually copies into `gc_base`/`mmhub_base`/
/// `osssys_base`.
pub const HWIP_SEGMENTS_USED: usize = 5;

/// Dword indices within `union MESAPI_SET_HW_RESOURCES`, from `offsetof`.
mod set_hw_rsrc {
    pub const VMID_MASK_MMHUB: usize = 1;
    pub const VMID_MASK_GFXHUB: usize = 2;
    pub const GDS_SIZE: usize = 3;
    pub const PAGING_VMID: usize = 4;
    pub const COMPUTE_HQD_MASK: usize = 5;
    pub const GFX_HQD_MASK: usize = 13;
    pub const SDMA_HQD_MASK: usize = 15;
    pub const AGGREGATED_DOORBELLS: usize = 17;
    pub const G_SCH_CTX_GPU_MC_PTR: usize = 22;
    pub const QUERY_STATUS_FENCE_GPU_MC_PTR: usize = 24;
    pub const GC_BASE: usize = 26;
    pub const MMHUB_BASE: usize = 34;
    pub const OSSSYS_BASE: usize = 42;
    pub const API_STATUS: usize = 50;
    pub const FLAGS: usize = 54;
    pub const OVERSUBSCRIPTION_TIMER: usize = 55;
}

/// The `MESAPI_SET_HW_RESOURCES` flag bits, which are not consecutive: the
/// gap between `enable_reg_active_poll` and `use_rs64mem_for_proc_gang_ctx`
/// is three fields this does not expose.
pub mod hw_rsrc_flags {
    pub const DISABLE_RESET: u32 = 1 << 0;
    pub const USE_DIFFERENT_VMID_COMPUTE: u32 = 1 << 1;
    pub const DISABLE_MES_LOG: u32 = 1 << 2;
    pub const APPLY_MMHUB_PGVM_INVALIDATE_ACK_LOSS_WA: u32 = 1 << 3;
    pub const APPLY_GRBM_REMOTE_REGISTER_DUMMY_READ_WA: u32 = 1 << 4;
    pub const SECOND_GFX_PIPE_ENABLED: u32 = 1 << 5;
    pub const ENABLE_LEVEL_PROCESS_QUANTUM_CHECK: u32 = 1 << 6;
    pub const LEGACY_SCH_MODE: u32 = 1 << 7;
    pub const DISABLE_ADD_QUEUE_WPTR_MC_ADDR: u32 = 1 << 8;
    pub const ENABLE_MES_EVENT_INT_LOGGING: u32 = 1 << 9;
    pub const ENABLE_REG_ACTIVE_POLL: u32 = 1 << 10;
    pub const USE_RS64MEM_FOR_PROC_GANG_CTX: u32 = 1 << 14;
    pub const LIMIT_SINGLE_PROCESS: u32 = 1 << 17;
    /// What `mes_v11_0_set_hw_resources` sets unconditionally.
    pub const DEFAULTS: u32 = DISABLE_RESET
        | DISABLE_MES_LOG
        | USE_DIFFERENT_VMID_COMPUTE
        | ENABLE_REG_ACTIVE_POLL
        | ENABLE_LEVEL_PROCESS_QUANTUM_CHECK;
}

/// `mes_v11_0_set_hw_resources` passes 50 to `oversubscription_timer`.
pub const DEFAULT_OVERSUBSCRIPTION_TIMER: u32 = 50;

/// What the scheduler needs to know about the hardware it is scheduling onto.
/// Field names and array widths follow `union MESAPI_SET_HW_RESOURCES`.
#[derive(Clone, Debug, Default)]
pub struct MesHwResources {
    pub vmid_mask_mmhub: u32,
    pub vmid_mask_gfxhub: u32,
    pub gds_size: u32,
    pub paging_vmid: u32,
    /// One mask per compute pipe.
    pub compute_hqd_mask: [u32; MAX_COMPUTE_PIPES],
    pub gfx_hqd_mask: [u32; MAX_GFX_PIPES],
    pub sdma_hqd_mask: [u32; MAX_SDMA_PIPES],
    pub aggregated_doorbells: [u32; AMD_PRIORITY_NUM_LEVELS],
    /// Scheduler context and query-status fence, both GPU addresses.
    pub sch_ctx_gpu_addr: u64,
    pub query_status_fence_gpu_addr: u64,
    /// `adev->reg_offset[GC_HWIP][0][0..5]` and the MMHUB/OSSSYS equivalents.
    /// MES resolves its own register writes through these, so a wrong table
    /// here misdirects every register the scheduler touches.
    pub gc_base: [u32; HWIP_SEGMENTS_USED],
    pub mmhub_base: [u32; HWIP_SEGMENTS_USED],
    pub osssys_base: [u32; HWIP_SEGMENTS_USED],
    /// Where MES writes the completion fence, and the value it writes.
    pub api_completion_fence_addr: u64,
    pub api_completion_fence_value: u64,
    pub flags: u32,
    pub oversubscription_timer: u32,
}

/// Build a `MES_SCH_API_SET_HW_RSRC` packet. Issued once per MES bring-up.
pub fn build_set_hw_resources(res: &MesHwResources) -> Vec<u32> {
    use set_hw_rsrc as f;
    let mut dws = frame(MesApiOpcode::SetHwRsrc);
    dws[f::VMID_MASK_MMHUB] = res.vmid_mask_mmhub;
    dws[f::VMID_MASK_GFXHUB] = res.vmid_mask_gfxhub;
    dws[f::GDS_SIZE] = res.gds_size;
    dws[f::PAGING_VMID] = res.paging_vmid;
    dws[f::COMPUTE_HQD_MASK..f::COMPUTE_HQD_MASK + MAX_COMPUTE_PIPES]
        .copy_from_slice(&res.compute_hqd_mask);
    dws[f::GFX_HQD_MASK..f::GFX_HQD_MASK + MAX_GFX_PIPES].copy_from_slice(&res.gfx_hqd_mask);
    dws[f::SDMA_HQD_MASK..f::SDMA_HQD_MASK + MAX_SDMA_PIPES].copy_from_slice(&res.sdma_hqd_mask);
    dws[f::AGGREGATED_DOORBELLS..f::AGGREGATED_DOORBELLS + AMD_PRIORITY_NUM_LEVELS]
        .copy_from_slice(&res.aggregated_doorbells);
    put64(&mut dws, f::G_SCH_CTX_GPU_MC_PTR, res.sch_ctx_gpu_addr);
    put64(
        &mut dws,
        f::QUERY_STATUS_FENCE_GPU_MC_PTR,
        res.query_status_fence_gpu_addr,
    );
    dws[f::GC_BASE..f::GC_BASE + HWIP_SEGMENTS_USED].copy_from_slice(&res.gc_base);
    dws[f::MMHUB_BASE..f::MMHUB_BASE + HWIP_SEGMENTS_USED].copy_from_slice(&res.mmhub_base);
    dws[f::OSSSYS_BASE..f::OSSSYS_BASE + HWIP_SEGMENTS_USED].copy_from_slice(&res.osssys_base);
    put64(&mut dws, f::API_STATUS, res.api_completion_fence_addr);
    put64(&mut dws, f::API_STATUS + 2, res.api_completion_fence_value);
    dws[f::FLAGS] = res.flags;
    dws[f::OVERSUBSCRIPTION_TIMER] = res.oversubscription_timer;
    dws
}

// ── MESAPI__ADD_QUEUE ─────────────────────────────────────────────

/// Dword indices within `union MESAPI__ADD_QUEUE`, from `offsetof`.
mod add_queue {
    pub const PROCESS_ID: usize = 1;
    pub const PAGE_TABLE_BASE_ADDR: usize = 2;
    pub const PROCESS_VA_START: usize = 4;
    pub const PROCESS_VA_END: usize = 6;
    pub const PROCESS_QUANTUM: usize = 8;
    pub const PROCESS_CONTEXT_ADDR: usize = 10;
    pub const GANG_QUANTUM: usize = 12;
    pub const GANG_CONTEXT_ADDR: usize = 14;
    pub const INPROCESS_GANG_PRIORITY: usize = 16;
    pub const GANG_GLOBAL_PRIORITY_LEVEL: usize = 17;
    pub const DOORBELL_OFFSET: usize = 18;
    pub const MQD_ADDR: usize = 19;
    pub const WPTR_ADDR: usize = 21;
    pub const H_CONTEXT: usize = 23;
    pub const H_QUEUE: usize = 25;
    pub const QUEUE_TYPE: usize = 27;
    pub const GDS_BASE: usize = 28;
    pub const GDS_SIZE: usize = 29;
    pub const GWS_BASE: usize = 30;
    pub const GWS_SIZE: usize = 31;
    pub const OA_MASK: usize = 32;
    pub const TRAP_HANDLER_ADDR: usize = 33;
    pub const VM_CONTEXT_CNTL: usize = 35;
    pub const FLAGS: usize = 36;
    pub const API_STATUS: usize = 37;
}

/// The `MESAPI__ADD_QUEUE` flag bits. `debug_vmid` is **four** bits wide and
/// sits directly after `paging`, so everything above it is three bits higher
/// than a one-bit-per-flag reading would put it.
pub mod add_queue_flags {
    pub const PAGING: u32 = 1 << 0;
    pub const DEBUG_VMID_SHIFT: u32 = 1;
    pub const DEBUG_VMID_MASK: u32 = 0xf << DEBUG_VMID_SHIFT;
    pub const PROGRAM_GDS: u32 = 1 << 5;
    pub const IS_GANG_SUSPENDED: u32 = 1 << 6;
    pub const IS_TMZ_QUEUE: u32 = 1 << 7;
    pub const MAP_KIQ_UTILITY_QUEUE: u32 = 1 << 8;
    pub const IS_KFD_PROCESS: u32 = 1 << 9;
    pub const TRAP_EN: u32 = 1 << 10;
    pub const IS_AQL_QUEUE: u32 = 1 << 11;
    pub const SKIP_PROCESS_CTX_CLEAR: u32 = 1 << 12;
    pub const MAP_LEGACY_KQ: u32 = 1 << 13;
    pub const EXCLUSIVELY_SCHEDULED: u32 = 1 << 14;
    pub const IS_LONG_RUNNING: u32 = 1 << 15;
    pub const IS_DWM_QUEUE: u32 = 1 << 16;
    pub const IS_VIDEO_BLIT_QUEUE: u32 = 1 << 17;
}

/// `MES_SCH_API_ADD_QUEUE` — bind one queue to the MES scheduler.
/// Layout from `union MESAPI__ADD_QUEUE`; sequencing from
/// `mes_v11_0_add_hw_queue`.
pub fn build_add_queue(args: &MesAddQueueArgs) -> Vec<u32> {
    use add_queue as f;
    let mut dws = frame(MesApiOpcode::AddQueue);
    dws[f::PROCESS_ID] = args.process_id;
    put64(&mut dws, f::PAGE_TABLE_BASE_ADDR, args.page_table_base_addr);
    put64(&mut dws, f::PROCESS_VA_START, args.process_va_start);
    put64(&mut dws, f::PROCESS_VA_END, args.process_va_end);
    put64(&mut dws, f::PROCESS_QUANTUM, args.process_quantum);
    put64(&mut dws, f::PROCESS_CONTEXT_ADDR, args.process_context_addr);
    put64(&mut dws, f::GANG_QUANTUM, args.gang_quantum);
    put64(&mut dws, f::GANG_CONTEXT_ADDR, args.gang_context_addr);
    dws[f::INPROCESS_GANG_PRIORITY] = args.inprocess_gang_priority;
    dws[f::GANG_GLOBAL_PRIORITY_LEVEL] = args.gang_global_priority_level as u32;
    dws[f::DOORBELL_OFFSET] = args.doorbell_offset;
    put64(&mut dws, f::MQD_ADDR, args.mqd_addr);
    put64(&mut dws, f::WPTR_ADDR, args.wptr_addr);
    put64(&mut dws, f::H_CONTEXT, args.h_context);
    put64(&mut dws, f::H_QUEUE, args.h_queue);
    dws[f::QUEUE_TYPE] = args.queue_type as u32;
    dws[f::GDS_BASE] = args.gds_base;
    dws[f::GDS_SIZE] = args.gds_size;
    dws[f::GWS_BASE] = args.gws_base;
    dws[f::GWS_SIZE] = args.gws_size;
    dws[f::OA_MASK] = args.oa_mask;
    put64(&mut dws, f::TRAP_HANDLER_ADDR, args.trap_handler_addr);
    dws[f::VM_CONTEXT_CNTL] = args.vm_context_cntl;
    dws[f::FLAGS] = args.flags
        | (args.debug_vmid << add_queue_flags::DEBUG_VMID_SHIFT) & add_queue_flags::DEBUG_VMID_MASK;
    put64(&mut dws, f::API_STATUS, args.api_completion_fence_addr);
    put64(&mut dws, f::API_STATUS + 2, args.api_completion_fence_value);
    dws
}

/// Arguments for [`build_add_queue`], one per field of
/// `union MESAPI__ADD_QUEUE`.
#[derive(Copy, Clone, Debug, Default)]
pub struct MesAddQueueArgs {
    pub process_id: u32,
    pub page_table_base_addr: u64,
    pub process_va_start: u64,
    pub process_va_end: u64,
    pub process_quantum: u64,
    pub process_context_addr: u64,
    pub gang_quantum: u64,
    pub gang_context_addr: u64,
    pub inprocess_gang_priority: u32,
    pub gang_global_priority_level: MesPriority,
    pub doorbell_offset: u32,
    pub mqd_addr: u64,
    pub wptr_addr: u64,
    /// Opaque host handles MES echoes back on completion and in its log.
    pub h_context: u64,
    pub h_queue: u64,
    pub queue_type: MesQueueType,
    pub gds_base: u32,
    pub gds_size: u32,
    pub gws_base: u32,
    pub gws_size: u32,
    pub oa_mask: u32,
    pub trap_handler_addr: u64,
    pub vm_context_cntl: u32,
    /// A bitwise-or of [`add_queue_flags`] constants, `debug_vmid` excepted.
    pub flags: u32,
    /// The four-bit `debug_vmid` field, placed by [`build_add_queue`].
    pub debug_vmid: u32,
    pub api_completion_fence_addr: u64,
    pub api_completion_fence_value: u64,
}

// ── MESAPI__REMOVE_QUEUE ──────────────────────────────────────────

/// Dword indices within `union MESAPI__REMOVE_QUEUE`, from `offsetof`.
mod remove_queue {
    pub const DOORBELL_OFFSET: usize = 1;
    pub const GANG_CONTEXT_ADDR: usize = 2;
    pub const FLAGS: usize = 4;
    pub const API_STATUS: usize = 5;
}

/// The `MESAPI__REMOVE_QUEUE` flag bits.
pub mod remove_queue_flags {
    pub const UNMAP_LEGACY_GFX_QUEUE: u32 = 1 << 0;
    pub const UNMAP_KIQ_UTILITY_QUEUE: u32 = 1 << 1;
    pub const PREEMPT_LEGACY_GFX_QUEUE: u32 = 1 << 2;
    pub const UNMAP_LEGACY_QUEUE: u32 = 1 << 3;
    pub const REMOVE_QUEUE_AFTER_RESET: u32 = 1 << 4;
}

/// `MES_SCH_API_REMOVE_QUEUE` — tear down a previously-added queue. The
/// doorbell and the gang context address are how MES finds it.
pub fn build_remove_queue(
    doorbell_offset: u32,
    gang_context_addr: u64,
    flags: u32,
    api_completion_fence_addr: u64,
    api_completion_fence_value: u64,
) -> Vec<u32> {
    use remove_queue as f;
    let mut dws = frame(MesApiOpcode::RemoveQueue);
    dws[f::DOORBELL_OFFSET] = doorbell_offset;
    put64(&mut dws, f::GANG_CONTEXT_ADDR, gang_context_addr);
    dws[f::FLAGS] = flags;
    put64(&mut dws, f::API_STATUS, api_completion_fence_addr);
    put64(&mut dws, f::API_STATUS + 2, api_completion_fence_value);
    dws
}

// ── MES ring ───────────────────────────────────────────────────────

/// Host-side mirror of the MES command ring (similar to KIQ ring,
/// but the MES firmware drains it instead of the CP). The ring
/// itself lives in GPU-visible sysmem; this struct tracks the
/// driver's write pointer.
#[derive(Clone, Debug)]
pub struct MesRing {
    pub ring_base_phys: u64,
    pub ring_size_bytes: u32,
    pub wptr_dw: u32,
    pub rptr_dw: u32,
    /// Doorbell index (PCIe BAR2 doorbell page offset). The
    /// per-queue MES uses one doorbell to bump the firmware.
    pub doorbell_index: u32,
    /// Number of MES-managed queues currently mapped — driver-side
    /// bookkeeping for diagnostics.
    pub mapped_queues: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MesError {
    BadRingAlignment,
    BadRingSize,
    RingFull,
    BadDwsize,
}

impl MesRing {
    pub fn new(
        ring_base_phys: u64,
        ring_size_bytes: u32,
        doorbell_index: u32,
    ) -> Result<Self, MesError> {
        if ring_base_phys & 0xFFF != 0 {
            return Err(MesError::BadRingAlignment);
        }
        if ring_size_bytes == 0 || !ring_size_bytes.is_power_of_two() {
            return Err(MesError::BadRingSize);
        }
        Ok(Self {
            ring_base_phys,
            ring_size_bytes,
            wptr_dw: 0,
            rptr_dw: 0,
            doorbell_index,
            mapped_queues: 0,
        })
    }

    fn ring_mask(&self) -> u32 {
        (self.ring_size_bytes / 4) - 1
    }

    /// Count of in-flight (host-committed, firmware not yet drained)
    /// dwords on the ring.
    pub fn in_flight_dw(&self) -> u32 {
        self.wptr_dw.wrapping_sub(self.rptr_dw) & self.ring_mask()
    }

    /// Push a 64-dword frame onto the ring. Caller has already
    /// padded the packet via the builders above.
    pub fn push_frame(&mut self, dws: &[u32]) -> Result<(), MesError> {
        if dws.len() != MES_API_FRAME_DWORDS {
            return Err(MesError::BadDwsize);
        }
        let free = self.ring_mask().wrapping_sub(self.in_flight_dw());
        if (dws.len() as u32) > free {
            return Err(MesError::RingFull);
        }
        self.wptr_dw = self.wptr_dw.wrapping_add(dws.len() as u32) & self.ring_mask();
        Ok(())
    }

    /// Mark `n_dw` dwords drained — caller calls after the firmware
    /// signals the fence (api_completion_fence).
    pub fn drain(&mut self, n_dw: u32) {
        self.rptr_dw = self.rptr_dw.wrapping_add(n_dw) & self.ring_mask();
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_mes_header_layout() -> TestResult {
        let h = make_api_header(MesApiOpcode::AddQueue, MES_API_FRAME_DWORDS as u32);
        let (t, op, dwsize) = decode_api_header(h);
        if t != MES_API_TYPE_SCHEDULER {
            return TestResult::Fail("type wrong");
        }
        if op != MesApiOpcode::AddQueue as u32 {
            return TestResult::Fail("opcode wrong");
        }
        // Every packet declares the whole frame, not its payload length.
        if dwsize != 64 {
            return TestResult::Fail("dwsize must be API_FRAME_SIZE_IN_DWORDS");
        }
        // Literal encoding: type 1 in bits 3:0, opcode 2 in 11:4, 64 in 19:12.
        if h != 0x0004_0021 {
            return TestResult::Fail("header field packing");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_mes_header_layout);

    /// Dword indices are literals here, not the module's constants: a wrong
    /// index must fail rather than be restated. From `offsetof` on
    /// `union MESAPI_SET_HW_RESOURCES` under `#pragma pack(push, 4)`.
    fn smoke_set_hw_resources_field_placement() -> TestResult {
        let mut res = MesHwResources {
            vmid_mask_mmhub: 0xFFFE,
            vmid_mask_gfxhub: 0xFFFD,
            gds_size: 0x400,
            paging_vmid: 0,
            sch_ctx_gpu_addr: 0x1122_3344_5566_7788,
            query_status_fence_gpu_addr: 0x8877_6655_4433_2211,
            api_completion_fence_addr: 0xAAAA_BBBB_CCCC_DDDD,
            api_completion_fence_value: 1,
            flags: hw_rsrc_flags::DEFAULTS,
            oversubscription_timer: DEFAULT_OVERSUBSCRIPTION_TIMER,
            ..MesHwResources::default()
        };
        // Per-pipe masks, distinct so a scalar-vs-array mistake shows.
        for (i, m) in res.compute_hqd_mask.iter_mut().enumerate() {
            *m = 0xC0 + i as u32;
        }
        res.gfx_hqd_mask = [0x60, 0x61];
        res.sdma_hqd_mask = [0xD0, 0xD1];
        res.aggregated_doorbells = [1, 2, 3, 4, 5];
        res.gc_base = [0x10, 0x11, 0x12, 0x13, 0x14];
        res.mmhub_base = [0x20, 0x21, 0x22, 0x23, 0x24];
        res.osssys_base = [0x30, 0x31, 0x32, 0x33, 0x34];

        let p = build_set_hw_resources(&res);
        if p.len() != 64 {
            return TestResult::Fail("frame must be 64 dwords");
        }
        if p[1] != 0xFFFE || p[2] != 0xFFFD || p[3] != 0x400 || p[4] != 0 {
            return TestResult::Fail("vmid masks / gds_size / paging_vmid at dwords 1..4");
        }
        // compute_hqd_mask[8] occupies 5..12, so gfx_hqd_mask starts at 13 —
        // not dword 7, which a single 64-bit mask would have put it at.
        if p[5] != 0xC0 || p[12] != 0xC7 {
            return TestResult::Fail("compute_hqd_mask is eight dwords at 5..12");
        }
        if p[13] != 0x60 || p[14] != 0x61 {
            return TestResult::Fail("gfx_hqd_mask is two dwords at 13");
        }
        if p[15] != 0xD0 || p[16] != 0xD1 {
            return TestResult::Fail("sdma_hqd_mask is two dwords at 15");
        }
        if p[17] != 1 || p[21] != 5 {
            return TestResult::Fail("aggregated_doorbells is five dwords at 17");
        }
        if p[22] != 0x5566_7788 || p[23] != 0x1122_3344 {
            return TestResult::Fail("g_sch_ctx_gpu_mc_ptr at dword 22, low half first");
        }
        if p[24] != 0x4433_2211 || p[25] != 0x8877_6655 {
            return TestResult::Fail("query_status_fence_gpu_mc_ptr at dword 24");
        }
        if p[26] != 0x10 || p[34] != 0x20 || p[42] != 0x30 {
            return TestResult::Fail("the three base arrays start at 26, 34, 42");
        }
        // Only five of the eight segments are filled; the rest stay zero.
        if p[31] != 0 || p[32] != 0 || p[33] != 0 {
            return TestResult::Fail("segments 5..8 of gc_base must stay zero");
        }
        // api_status is near the END of this packet, not right after the
        // header: four dwords at 50, then the flags and the timer.
        if p[50] != 0xCCCC_DDDD || p[51] != 0xAAAA_BBBB || p[52] != 1 || p[53] != 0 {
            return TestResult::Fail("api_status is four dwords at 50");
        }
        // disable_reset | use_different_vmid_compute | disable_mes_log |
        // enable_level_process_quantum_check | enable_reg_active_poll.
        if p[54] != 0x0000_0447 {
            return TestResult::Fail("flags dword is 54");
        }
        if p[55] != 50 {
            return TestResult::Fail("oversubscription_timer is dword 55");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_set_hw_resources_field_placement);

    /// Dword indices from `offsetof` on `union MESAPI__ADD_QUEUE`.
    fn smoke_add_queue_field_placement() -> TestResult {
        let args = MesAddQueueArgs {
            process_id: 0x1234,
            page_table_base_addr: 0xCAFE_0000,
            process_va_start: 0x1_0000,
            process_va_end: 0x7FFF_FFFF_F000,
            process_quantum: 10_000,
            process_context_addr: 0x2_0000,
            gang_quantum: 5_000,
            gang_context_addr: 0x3_0000,
            inprocess_gang_priority: 0,
            gang_global_priority_level: MesPriority::Normal,
            doorbell_offset: 0x100,
            mqd_addr: 0x1111_2222_3333_4444,
            wptr_addr: 0x5555_6666_7777_8888,
            h_context: 0x9999_AAAA_BBBB_CCCC,
            h_queue: 0xDDDD_EEEE_FFFF_0001,
            queue_type: MesQueueType::Compute,
            gds_base: 0xA1,
            gds_size: 0xA2,
            gws_base: 0xA3,
            gws_size: 0xA4,
            oa_mask: 0xA5,
            trap_handler_addr: 0x0102_0304_0506_0708,
            vm_context_cntl: 0xC0DE,
            flags: add_queue_flags::PAGING
                | add_queue_flags::IS_KFD_PROCESS
                | add_queue_flags::IS_AQL_QUEUE,
            debug_vmid: 0xd,
            api_completion_fence_addr: 0xFACE_0000,
            api_completion_fence_value: 7,
        };
        let p = build_add_queue(&args);
        if p.len() != 64 {
            return TestResult::Fail("frame must be 64 dwords");
        }
        if p[1] != 0x1234 || p[2] != 0xCAFE_0000 || p[3] != 0 {
            return TestResult::Fail("process_id at 1, page_table_base_addr at 2");
        }
        if p[16] != 0 || p[17] != MesPriority::Normal as u32 || p[18] != 0x100 {
            return TestResult::Fail("gang priority pair at 16/17, doorbell_offset at 18");
        }
        // The packet is packed, so mqd_addr starts on the ODD dword 19 with
        // no padding after doorbell_offset.
        if p[19] != 0x3333_4444 || p[20] != 0x1111_2222 {
            return TestResult::Fail("mqd_addr at dword 19, unpadded");
        }
        if p[21] != 0x7777_8888 || p[22] != 0x5555_6666 {
            return TestResult::Fail("wptr_addr at dword 21");
        }
        // h_context and h_queue sit between wptr_addr and queue_type; missing
        // them shifts everything after by four dwords.
        if p[23] != 0xBBBB_CCCC || p[25] != 0xFFFF_0001 {
            return TestResult::Fail("h_context at 23 and h_queue at 25");
        }
        if p[27] != MesQueueType::Compute as u32 {
            return TestResult::Fail("queue_type is dword 27, not 23");
        }
        if p[28] != 0xA1 || p[29] != 0xA2 || p[30] != 0xA3 || p[31] != 0xA4 || p[32] != 0xA5 {
            return TestResult::Fail("gds/gws/oa fields at 28..32");
        }
        if p[33] != 0x0506_0708 || p[34] != 0x0102_0304 {
            return TestResult::Fail("trap_handler_addr at dword 33");
        }
        if p[35] != 0xC0DE {
            return TestResult::Fail("vm_context_cntl is dword 35");
        }
        // paging(0) | debug_vmid 0xd at 4:1 | is_kfd_process(9) | is_aql(11).
        if p[36] != 0x0000_0A1B {
            return TestResult::Fail("flags dword is 36; debug_vmid is four bits at 4:1");
        }
        if p[37] != 0xFACE_0000 || p[39] != 7 {
            return TestResult::Fail("api_status is four dwords at 37");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_add_queue_field_placement);

    /// Dword indices from `offsetof` on `union MESAPI__REMOVE_QUEUE`.
    fn smoke_remove_queue_field_placement() -> TestResult {
        let p = build_remove_queue(
            0x100,
            0xDEAD_BEEF_0000_1000,
            remove_queue_flags::UNMAP_LEGACY_GFX_QUEUE
                | remove_queue_flags::PREEMPT_LEGACY_GFX_QUEUE,
            0xFEED_0000,
            3,
        );
        if p.len() != 64 {
            return TestResult::Fail("frame must be 64 dwords");
        }
        let (_, op, dwsize) = decode_api_header(p[0]);
        if op != MesApiOpcode::RemoveQueue as u32 || dwsize != 64 {
            return TestResult::Fail("header");
        }
        if p[1] != 0x100 {
            return TestResult::Fail("doorbell_offset is dword 1");
        }
        if p[2] != 0x0000_1000 || p[3] != 0xDEAD_BEEF {
            return TestResult::Fail("gang_context_addr at dword 2, low half first");
        }
        if p[4] != 0x05 {
            return TestResult::Fail("flags dword is 4");
        }
        if p[5] != 0xFEED_0000 || p[7] != 3 {
            return TestResult::Fail("api_status is four dwords at 5");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_remove_queue_field_placement);

    fn smoke_mes_ring_rejects_misaligned() -> TestResult {
        match MesRing::new(0x1001, 4096, 0) {
            Err(MesError::BadRingAlignment) => {}
            _ => return TestResult::Fail("misaligned base accepted"),
        }
        match MesRing::new(0x1000, 3072, 0) {
            Err(MesError::BadRingSize) => {}
            _ => return TestResult::Fail("non-power-of-2 size accepted"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_mes_ring_rejects_misaligned);

    fn smoke_mes_ring_push_advances() -> TestResult {
        let mut r = MesRing::new(0x10_0000, 8192, 0x80).expect("ring");
        let pkt = build_set_hw_resources(&MesHwResources::default());
        r.push_frame(&pkt).expect("push");
        if r.in_flight_dw() != MES_API_FRAME_DWORDS as u32 {
            return TestResult::Fail("in_flight didn't advance by 64");
        }
        r.drain(MES_API_FRAME_DWORDS as u32);
        if r.in_flight_dw() != 0 {
            return TestResult::Fail("drain didn't reset");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_mes_ring_push_advances);

    fn smoke_mes_ring_rejects_wrong_dwsize() -> TestResult {
        let mut r = MesRing::new(0x10_0000, 8192, 0x80).expect("ring");
        let mut wrong = alloc::vec![0u32; 16];
        wrong[0] = make_api_header(MesApiOpcode::AddQueue, 16);
        if r.push_frame(&wrong) != Err(MesError::BadDwsize) {
            return TestResult::Fail("short frame should reject");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_mes_ring_rejects_wrong_dwsize);

    fn smoke_mes_ring_full() -> TestResult {
        // Ring of exactly 64 dws — first push fits, second fails.
        let r = MesRing::new(0x10_0000, 64 * 4, 0x80).expect("ring");
        let pkt = build_set_hw_resources(&MesHwResources::default());
        // Wait — ring mask = 63; one push of 64 dws will wrap fully.
        // Use a ring of 128 dws + push twice.
        let mut r2 = MesRing::new(0x10_0000, 128 * 4, 0x80).expect("ring");
        r2.push_frame(&pkt).expect("push 1");
        let _ = r2.push_frame(&pkt); // may succeed (free = mask - in_flight)
                                     // 3rd must fail.
        match r2.push_frame(&pkt) {
            Err(MesError::RingFull) => {}
            Ok(_) => return TestResult::Fail("3rd push of 64 dws to 128-dw ring should fail"),
            Err(_) => return TestResult::Fail("wrong error"),
        }
        // Silence unused warning.
        let _ = r;
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_mes_ring_full);
}
