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
use narf_driver_runtime::{alloc_coherent, DmaBuffer, DomainId, MmioRegion};

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
    // Everything below sits AFTER `api_status`, which is 16 bytes / 4 dwords
    // wide. Easy to miss when reading `union MESAPI__ADD_QUEUE` top to
    // bottom and assuming the status block ends the payload: it does not, and
    // `pipe_id` / `queue_id` out here are the two fields the legacy
    // kernel-queue mapping is built from.
    pub const TMA_ADDR: usize = 41;
    pub const SCH_ID: usize = 43;
    pub const TIMESTAMP: usize = 44;
    pub const PROCESS_CONTEXT_ARRAY_INDEX: usize = 46;
    pub const GANG_CONTEXT_ARRAY_INDEX: usize = 47;
    pub const PIPE_ID: usize = 48;
    pub const QUEUE_ID: usize = 49;
    pub const ALIGNMENT_MODE_SETTING: usize = 50;
    pub const FULL_SH_MEM_CONFIG_DATA: usize = 51;
    pub const UNMAP_FLAG_ADDR: usize = 52;
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
    // Past the status block, and set by `mes_v11_0_add_hw_queue` just like
    // everything above it.
    put64(&mut dws, f::TMA_ADDR, args.tma_addr);
    dws[f::PROCESS_CONTEXT_ARRAY_INDEX] = args.process_context_array_index;
    dws[f::GANG_CONTEXT_ARRAY_INDEX] = args.gang_context_array_index;
    dws
}

/// Arguments for [`build_map_legacy_queue`].
///
/// Six fields, which is the whole packet. See that function for why.
#[derive(Copy, Clone, Debug, Default)]
pub struct MesMapLegacyQueueArgs {
    /// `ring->pipe`.
    pub pipe_id: u32,
    /// `ring->queue`.
    pub queue_id: u32,
    /// `ring->doorbell_index` — the **DWORD** index space, so twice the
    /// `AMDGPU_NAVI10_DOORBELL_*` assignment value. See
    /// `amdgpu_ring::DOORBELL_STRIDE_BYTES` for the two spaces.
    pub doorbell_offset: u32,
    pub mqd_addr: u64,
    pub wptr_addr: u64,
    pub queue_type: MesQueueType,
}

/// `MES_SCH_API_ADD_QUEUE` with `map_legacy_kq` — bind a **kernel** ring that
/// the driver programmed itself, as `mes_v11_0_map_legacy_queue` does.
///
/// This is the path a GFX11 kernel graphics ring actually takes, and it is not
/// [`build_add_queue`] with different arguments. `amdgpu_gfx_enable_kgq` splits
/// on `adev->mes.enable_legacy_queue_map`, which `mes_v11_0_late_init` sets
/// for any scheduler firmware at version 0x47 or newer, and then calls
/// `amdgpu_mes_map_legacy_queue` rather than the KIQ's `MAP_QUEUES` PM4
/// packet. The same opcode arrives carrying **six** fields and one flag:
///
/// ```text
///   pipe_id  queue_id  doorbell_offset  mqd_addr  wptr_addr  queue_type
///   map_legacy_kq = 1
/// ```
///
/// Everything [`build_add_queue`] fills — the process and gang contexts, the
/// quantums, the page-table base, the VA window, the priorities, the GDS and
/// GWS windows, `vm_context_cntl` — is left zero, because MES is not being
/// asked to schedule a process here. It is being told that a queue the driver
/// has already placed on a pipe exists, and where its descriptor and write
/// pointer live. Sending the full process form for a kernel queue would hand
/// the scheduler a process with a null page-table base.
pub fn build_map_legacy_queue(args: &MesMapLegacyQueueArgs) -> Vec<u32> {
    use add_queue as f;
    let mut dws = frame(MesApiOpcode::AddQueue);
    dws[f::PIPE_ID] = args.pipe_id;
    dws[f::QUEUE_ID] = args.queue_id;
    dws[f::DOORBELL_OFFSET] = args.doorbell_offset;
    put64(&mut dws, f::MQD_ADDR, args.mqd_addr);
    put64(&mut dws, f::WPTR_ADDR, args.wptr_addr);
    dws[f::QUEUE_TYPE] = args.queue_type as u32;
    dws[f::FLAGS] = add_queue_flags::MAP_LEGACY_KQ;
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
    /// Also the queue size. `mes_v11_0_add_hw_queue` assigns
    /// `mes_add_queue_pkt.gds_size = input->queue_size` under the comment
    /// "For KFD, gds_size is re-used for queue size (needed in MES for AQL
    /// queues)", so a caller that wants a GDS window and an AQL queue cannot
    /// have both and the firmware decides which it reads.
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
    /// Trap memory address. Past `api_status` in the packet; set by
    /// `mes_v11_0_add_hw_queue` from `input->tma_addr`.
    pub tma_addr: u64,
    pub process_context_array_index: u32,
    pub gang_context_array_index: u32,
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

// ── Status-query packet and submission pairing ─────────────────────

/// `union MESAPI__QUERY_MES_STATUS` field positions.
///
/// NOTE the `api_status` block is at dword **2**, not 1: an
/// `enum MES_API_QUERY_MES_OPCODE subopcode` sits between it and the header.
/// Every other packet in this file has `api_status` directly after its own
/// payload, so this is the one case where the obvious offset is wrong.
/// Confirmed by compiling `mes_v11_api_def.h:551-566` under
/// `#pragma pack(push, 4)`: header 0, subopcode 1, api_status 2, with
/// `api_completion_fence_value` at dword 4.
pub mod query_mes_status {
    pub const SUBOPCODE: usize = 1;
    pub const API_STATUS: usize = 2;
}

/// Build the `QUERY_SCHEDULER_STATUS` packet that follows every command.
///
/// Linux reuses `MESAPI__QUERY_MES_STATUS`'s layout with
/// `header.opcode = MES_SCH_API_QUERY_SCHEDULER_STATUS` (11) — there is no
/// separate union for that opcode — and leaves `subopcode` zeroed.
pub fn build_query_mes_status(fence_addr: u64, fence_value: u64) -> Vec<u32> {
    let mut dws = frame(MesApiOpcode::QuerySchedulerStatus);
    put64(&mut dws, query_mes_status::API_STATUS, fence_addr);
    put64(&mut dws, query_mes_status::API_STATUS + 2, fence_value);
    dws
}

/// Stamp a command's completion fence and pair it with a status query, giving
/// the two frames that go on the ring together.
///
/// This is the protocol `mes_v11_0_submit_pkt_and_poll_completion` runs, and
/// it uses TWO fences for one command:
///
///   * the command's own `api_status` points at a status slot the caller has
///     zeroed, with value **1** — MES writes it when that command completes,
///     and a zero there afterwards means the command failed rather than timed
///     out;
///   * a trailing `QUERY_SCHEDULER_STATUS` points at the ring's fence with the
///     submission's sequence number — that is what makes the wait bounded,
///     because MES answers it after draining everything before it.
///
/// Polling only the first would hang on a command MES never acknowledges;
/// polling only the second would report success for a command that failed.
pub fn pair_with_status_query(
    packet: &mut [u32],
    api_status_dw: usize,
    status_addr: u64,
    ring_fence_addr: u64,
    seq: u64,
) -> Result<Vec<u32>, MesError> {
    if packet.len() != MES_API_FRAME_DWORDS || api_status_dw + 4 > MES_API_FRAME_DWORDS {
        return Err(MesError::BadDwsize);
    }
    put64(packet, api_status_dw, status_addr);
    put64(packet, api_status_dw + 2, MES_COMMAND_COMPLETE);
    let mut out = Vec::with_capacity(2 * MES_API_FRAME_DWORDS);
    out.extend_from_slice(packet);
    out.extend_from_slice(&build_query_mes_status(ring_fence_addr, seq));
    Ok(out)
}

/// The value MES writes into a command's own status slot on completion.
/// `mes_v11_0_submit_pkt_and_poll_completion` sets
/// `api_completion_fence_value = 1` and then treats `!*status_ptr` as failure.
pub const MES_COMMAND_COMPLETE: u64 = 1;

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
    /// A DMA allocation for the ring or its writeback page failed.
    NoMemory,
    /// The scheduler drained past this command but left its status slot zero,
    /// which `mes_v11_0_submit_pkt_and_poll_completion` reports as a failure
    /// to respond rather than a timeout.
    Rejected,
    /// The ring fence never reached this submission's sequence number.
    Timeout,
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

// ── A MES command queue with its memory ────────────────────────────

/// A MES command ring with its backing, its fence page and the sequence
/// counter the status query uses.
///
/// [`MesRing`] is the pointer model and owns nothing; this owns the memory and
/// does the writes. Keeping them apart is deliberate — the pointer arithmetic
/// stays unit-testable without a device, which is where the wrap bugs live.
///
/// LINUX-GAP: before this, `MesRing::push_frame` advanced `wptr_dw` and wrote
/// no dwords anywhere, nothing rang the doorbell, and nothing waited on a
/// fence. The builders produced correct packets that had no way onto the ring.
#[derive(Debug)]
pub struct MesQueue {
    ring: MesRing,
    /// The ring itself, in GPU-visible sysmem.
    backing: DmaBuffer,
    /// Writeback page: the per-command status slot, the ring fence slot, the
    /// wptr shadow, and the two addresses `SET_HW_RSRC` names — at
    /// [`WB_STATUS_OFFSET`], [`WB_FENCE_OFFSET`], [`WB_WPTR_OFFSET`],
    /// [`WB_SCH_CTX_OFFSET`] and [`WB_QUERY_STATUS_FENCE_OFFSET`].
    ///
    /// The last two are in here rather than in buffers of their own because
    /// that is what they are in Linux: `amdgpu_mes_init` takes both from
    /// `amdgpu_wb_get`, the same allocator a ring's rptr slot comes from.
    wb: DmaBuffer,
    /// This pipe's queue descriptor, which the firmware reads and keeps queue
    /// state in.
    mqd: DmaBuffer,
    /// This pipe's end-of-pipe buffer, [`crate::amdgpu_mqd::MES_EOP_BYTES`].
    eop: DmaBuffer,
    /// `ring->doorbell_index`, kept so the descriptor and the HQD registers
    /// can be derived from the queue rather than re-supplied.
    doorbell_index: u32,
    /// Monotonic submission sequence, the value the status query waits on.
    /// `mes_v11_0_submit_pkt_and_poll_completion` uses `++ring->fence_drv
    /// .sync_seq`, so it starts at 1.
    seq: u64,
}

/// Writeback slots, at the same 32-byte spacing `amdgpu_wb_get` hands out.
pub const WB_STATUS_OFFSET: u64 = 0;
pub const WB_FENCE_OFFSET: u64 = crate::amdgpu_gfx::WB_SLOT_BYTES;
pub const WB_WPTR_OFFSET: u64 = 2 * crate::amdgpu_gfx::WB_SLOT_BYTES;
/// `mes->sch_ctx_gpu_addr[pipe]` — the scheduler context `SET_HW_RSRC` names.
/// A writeback slot, not a buffer: `amdgpu_mes_init` gets it from
/// `amdgpu_wb_get` exactly as it gets a ring's rptr slot, so it is eight bytes
/// at the same 32-byte spacing and lives in this page.
pub const WB_SCH_CTX_OFFSET: u64 = 3 * crate::amdgpu_gfx::WB_SLOT_BYTES;
/// `mes->query_status_fence_gpu_addr[pipe]`, the next `amdgpu_wb_get` after it.
pub const WB_QUERY_STATUS_FENCE_OFFSET: u64 = 4 * crate::amdgpu_gfx::WB_SLOT_BYTES;
/// Five slots: status, fence, wptr, scheduler context, query-status fence.
const WB_BYTES: usize = 5 * crate::amdgpu_gfx::WB_SLOT_BYTES as usize;

/// The MES pipe's queue descriptor, 512 dwords like any `v11_compute_mqd`.
const MES_MQD_BYTES: usize = crate::amdgpu_mqd::COMPUTE_MQD_DWORDS * 4;

/// Iteration cap on the fence poll. Linux allows 2100 ms
/// (`timeout = 2100000` µs in `mes_v11_0_submit_pkt_and_poll_completion`).
pub const MES_POLL_BUDGET: u32 = 2_100_000;

impl MesQueue {
    /// Allocate a MES command ring of `frames` 64-dword frames, plus its
    /// writeback page.
    pub fn new(frames: usize, doorbell_index: u32) -> Result<Self, MesError> {
        let dwords = frames
            .checked_mul(MES_API_FRAME_DWORDS)
            .ok_or(MesError::BadRingSize)?;
        let bytes = dwords
            .checked_mul(4)
            .filter(|b| *b > 0 && b.is_power_of_two())
            .ok_or(MesError::BadRingSize)?;
        let backing = alloc_coherent(bytes, DomainId::DRIVER_0).map_err(|_| MesError::NoMemory)?;
        let wb = alloc_coherent(WB_BYTES, DomainId::DRIVER_0).map_err(|_| MesError::NoMemory)?;
        // SAFETY: identity-mapped DMA pages this queue owns.
        unsafe {
            for offset in (0..WB_BYTES as u64).step_by(8) {
                core::ptr::write_volatile(wb.cpu_mut_ptr_at::<u64>(offset), 0);
            }
        }
        let mqd =
            alloc_coherent(MES_MQD_BYTES, DomainId::DRIVER_0).map_err(|_| MesError::NoMemory)?;
        let eop = alloc_coherent(
            crate::amdgpu_mqd::MES_EOP_BYTES as usize,
            DomainId::DRIVER_0,
        )
        .map_err(|_| MesError::NoMemory)?;
        // Both zeroed: every descriptor field `mes_mqd_init` does not set is
        // meant to read zero, and the firmware's first completion record
        // should not be whatever the page held.
        // SAFETY: identity-mapped DMA pages this queue owns.
        unsafe {
            for offset in (0..MES_MQD_BYTES as u64).step_by(8) {
                core::ptr::write_volatile(mqd.cpu_mut_ptr_at::<u64>(offset), 0);
            }
            for offset in (0..crate::amdgpu_mqd::MES_EOP_BYTES).step_by(8) {
                core::ptr::write_volatile(eop.cpu_mut_ptr_at::<u64>(offset), 0);
            }
        }
        let ring = MesRing::new(backing.dma_addr().raw(), bytes as u32, doorbell_index)?;
        Ok(Self {
            ring,
            backing,
            wb,
            mqd,
            eop,
            doorbell_index,
            seq: 0,
        })
    }

    /// GPU address of this pipe's queue descriptor.
    pub fn mqd_phys(&self) -> u64 {
        self.mqd.dma_addr().raw()
    }
    /// GPU address of this pipe's end-of-pipe buffer.
    pub fn eop_phys(&self) -> u64 {
        self.eop.dma_addr().raw()
    }
    /// GPU address of the scheduler context, for `SET_HW_RSRC`.
    pub fn sch_ctx_phys(&self) -> u64 {
        self.wb.dma_addr().raw() + WB_SCH_CTX_OFFSET
    }
    /// GPU address of the query-status fence, for `SET_HW_RSRC`.
    pub fn query_status_fence_phys(&self) -> u64 {
        self.wb.dma_addr().raw() + WB_QUERY_STATUS_FENCE_OFFSET
    }

    /// One dword of the queue descriptor, by its `v11_compute_mqd` index.
    pub fn mqd_dword(&self, index: usize) -> u32 {
        if index >= crate::amdgpu_mqd::COMPUTE_MQD_DWORDS {
            return 0;
        }
        // SAFETY: identity-mapped page this queue owns, index bounded above.
        unsafe { core::ptr::read_volatile(self.mqd.cpu_ptr_at::<u32>((index * 4) as u64)) }
    }

    /// Build this pipe's descriptor from the queue's own addresses and write it
    /// into the page the firmware reads.
    ///
    /// Derived here rather than from a passed-in [`crate::amdgpu_mqd::MqdProp`]
    /// for the same reason [`crate::amdgpu_gfx::GfxContext::write_mqd`] is: the
    /// ring base, the two writeback addresses, the descriptor's own address and
    /// the doorbell appear in both the descriptor and the HQD registers, and a
    /// caller filling them twice can fill them differently.
    pub fn write_mqd(&self) -> Result<(), MesError> {
        let prop = crate::amdgpu_mqd::MqdProp {
            mqd_gpu_addr: self.mqd_phys(),
            hqd_base_gpu_addr: self.ring_phys(),
            // The MES reports its read pointer into the status slot's page and
            // polls the wptr shadow, the same two slots the submit protocol
            // uses.
            rptr_gpu_addr: self.wb.dma_addr().raw() + WB_STATUS_OFFSET,
            wptr_gpu_addr: self.wptr_phys(),
            queue_size: u64::from(self.ring.ring_size_bytes),
            doorbell_index: self.doorbell_index,
            use_doorbell: true,
            kernel_queue: true,
            tmz_queue: false,
            priority: crate::amdgpu_mqd::QueuePriority::Normal,
            shadow_addr: 0,
            gds_bkup_addr: 0,
            csa_addr: 0,
            fence_address: 0,
        };
        let mqd = crate::amdgpu_mqd::mes_mqd_init(&prop, self.eop_phys())
            .map_err(|_| MesError::BadRingSize)?;
        // SAFETY: identity-mapped page this queue owns; `mqd` is exactly
        // COMPUTE_MQD_DWORDS dwords and the allocation is MES_MQD_BYTES.
        unsafe {
            for (i, dw) in mqd.iter().enumerate() {
                core::ptr::write_volatile(self.mqd.cpu_mut_ptr_at::<u32>((i * 4) as u64), *dw);
            }
        }
        Ok(())
    }

    /// Fill a `SET_HW_RSRC` payload: the topology-derived masks from
    /// [`crate::amdgpu_mes_hw::fill_hw_resources`], plus this queue's own two
    /// context addresses and the flags `mes_v11_0_set_hw_resources` sets.
    ///
    /// The IP bases and the GDS size stay the caller's — those come from
    /// discovery, not from the queue.
    pub fn hw_resources(&self, topo: &crate::amdgpu_mes_hw::MesTopology) -> MesHwResources {
        let mut res = MesHwResources {
            sch_ctx_gpu_addr: self.sch_ctx_phys(),
            query_status_fence_gpu_addr: self.query_status_fence_phys(),
            flags: hw_rsrc_flags::DEFAULTS,
            oversubscription_timer: DEFAULT_OVERSUBSCRIPTION_TIMER,
            ..MesHwResources::default()
        };
        crate::amdgpu_mes_hw::fill_hw_resources(&mut res, topo);
        res
    }

    /// GPU address of the ring, for `SET_HW_RESOURCES`.
    pub fn ring_phys(&self) -> u64 {
        self.backing.dma_addr().raw()
    }
    /// GPU address of the ring's fence slot.
    pub fn fence_phys(&self) -> u64 {
        self.wb.dma_addr().raw() + WB_FENCE_OFFSET
    }
    /// GPU address of the per-command status slot.
    pub fn status_phys(&self) -> u64 {
        self.wb.dma_addr().raw() + WB_STATUS_OFFSET
    }
    /// GPU address of the wptr shadow MES polls.
    pub fn wptr_phys(&self) -> u64 {
        self.wb.dma_addr().raw() + WB_WPTR_OFFSET
    }
    /// Base of the writeback page, so a test can check the slot layout.
    ///
    /// Ungated for the same reason the other accessors are: the kernel-test
    /// modules compile in the plain build too.
    pub fn wb_phys_for_test(&self) -> u64 {
        self.wb.dma_addr().raw()
    }
    pub fn mapped_queues(&self) -> u32 {
        self.ring.mapped_queues
    }

    /// Write `dws` into the ring at the current write pointer, wrapping, and
    /// advance it. Does not publish — [`MesQueue::commit`] does that.
    fn write_frames(&mut self, dws: &[u32]) -> Result<(), MesError> {
        let mask = (self.ring.ring_size_bytes / 4) - 1;
        let free = mask.wrapping_sub(self.ring.in_flight_dw());
        if dws.len() as u32 > free {
            return Err(MesError::RingFull);
        }
        for (i, word) in dws.iter().enumerate() {
            let index = (self.ring.wptr_dw.wrapping_add(i as u32)) & mask;
            // SAFETY: the index is masked into the ring's own allocation and
            // this queue is the sole writer.
            unsafe {
                core::ptr::write_volatile(
                    self.backing.cpu_mut_ptr_at::<u32>(u64::from(index) * 4),
                    *word,
                );
            }
        }
        self.ring.wptr_dw = self.ring.wptr_dw.wrapping_add(dws.len() as u32) & mask;
        Ok(())
    }

    /// Publish the write pointer to the shadow and ring the doorbell.
    ///
    /// The MES doorbell carries the dword wptr as a quadword, like GFX's
    /// (`mes_v11_0.c:87` is a plain `WDOORBELL64(ring->doorbell_index,
    /// ring->wptr)`).
    ///
    /// # Safety
    /// `bar2` must map this GPU's doorbell window and the caller owns this
    /// queue's doorbell.
    pub unsafe fn commit(&self, bar2: &MmioRegion) {
        let wptr = u64::from(self.ring.wptr_dw);
        // SAFETY: the queue's own writeback page.
        unsafe {
            core::ptr::write_volatile(self.wb.cpu_mut_ptr_at::<u64>(WB_WPTR_OFFSET), wptr);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        let off = u64::from(self.ring.doorbell_index) * crate::amdgpu_ring::DOORBELL_STRIDE_BYTES;
        // SAFETY: caller-asserted doorbell ownership; one aligned 64-bit store.
        unsafe { bar2.write64(off, wptr) };
    }

    /// Submit one command frame and wait for MES to answer it.
    ///
    /// `api_status_dw` is where that packet keeps its `MES_API_STATUS` block —
    /// `add_queue::API_STATUS` for an ADD_QUEUE, and so on. The two-fence
    /// protocol is described on [`pair_with_status_query`].
    ///
    /// # Safety
    /// `bar2` must map this GPU's doorbell window, MES must be running, and
    /// the caller owns this queue.
    pub unsafe fn submit(
        &mut self,
        packet: &mut [u32],
        api_status_dw: usize,
        bar2: &MmioRegion,
    ) -> Result<(), MesError> {
        // Zero the status slot first: a nonzero left over from a previous
        // command would read as instant success.
        // SAFETY: the queue's own writeback page.
        unsafe {
            core::ptr::write_volatile(self.wb.cpu_mut_ptr_at::<u64>(WB_STATUS_OFFSET), 0);
        }
        self.seq += 1;
        let frames = pair_with_status_query(
            packet,
            api_status_dw,
            self.status_phys(),
            self.fence_phys(),
            self.seq,
        )?;
        self.write_frames(&frames)?;
        // SAFETY: delegated to this function's contract.
        unsafe { self.commit(bar2) };

        for _ in 0..MES_POLL_BUDGET {
            // SAFETY: the queue's own writeback page; MES is the other writer.
            let fence =
                unsafe { core::ptr::read_volatile(self.wb.cpu_ptr_at::<u64>(WB_FENCE_OFFSET)) };
            if fence >= self.seq {
                // The scheduler has drained past this command. Now ask whether
                // the command itself succeeded.
                // SAFETY: same page.
                let status = unsafe {
                    core::ptr::read_volatile(self.wb.cpu_ptr_at::<u64>(WB_STATUS_OFFSET))
                };
                self.ring.drain(frames.len() as u32);
                return if status == MES_COMMAND_COMPLETE {
                    Ok(())
                } else {
                    Err(MesError::Rejected)
                };
            }
        }
        Err(MesError::Timeout)
    }

    /// Map a queue through MES. `args.api_completion_fence_addr` and `_value`
    /// are overwritten by the submit protocol.
    ///
    /// # Safety
    /// As [`MesQueue::submit`]. The MQD, context and wptr addresses in `args`
    /// must name GPU-visible memory that stays mapped while the queue is.
    pub unsafe fn add_queue(
        &mut self,
        args: &MesAddQueueArgs,
        bar2: &MmioRegion,
    ) -> Result<(), MesError> {
        let mut packet = build_add_queue(args);
        // SAFETY: delegated.
        unsafe { self.submit(&mut packet, add_queue::API_STATUS, bar2) }?;
        self.ring.mapped_queues += 1;
        Ok(())
    }

    /// The register sequence that pushes this pipe's descriptor into the live
    /// HQD registers. See [`crate::amdgpu_mes_hw::build_mes_queue_init_register`].
    ///
    /// Reads the descriptor back out of the page rather than taking an array,
    /// so the registers carry what the firmware will actually find there — a
    /// descriptor written and then not flushed, or written to the wrong page,
    /// shows up as a sequence of zeros rather than as a working-looking one.
    pub fn queue_init_sequence(
        &self,
        gc_base_idx0: u32,
        gc_base_idx1: u32,
        pipe: u32,
        live_vmid: u32,
        live_doorbell: u32,
    ) -> crate::amdgpu_gfx::Gfx11Sequence {
        let mut mqd = [0u32; crate::amdgpu_mqd::COMPUTE_MQD_DWORDS];
        for (i, slot) in mqd.iter_mut().enumerate() {
            *slot = self.mqd_dword(i);
        }
        crate::amdgpu_mes_hw::build_mes_queue_init_register(
            gc_base_idx0,
            gc_base_idx1,
            pipe,
            &mqd,
            live_vmid,
            live_doorbell,
        )
    }

    /// Bind a kernel ring the driver programmed itself. See
    /// [`build_map_legacy_queue`] — this is the GFX11 kernel graphics ring's
    /// path, not [`MesQueue::add_queue`] with fewer arguments.
    ///
    /// # Safety
    /// As [`MesQueue::submit`]. `args.mqd_addr` and `args.wptr_addr` must name
    /// GPU-visible memory that stays mapped while the queue is.
    pub unsafe fn map_legacy_queue(
        &mut self,
        args: &MesMapLegacyQueueArgs,
        bar2: &MmioRegion,
    ) -> Result<(), MesError> {
        let mut packet = build_map_legacy_queue(args);
        // SAFETY: delegated.
        unsafe { self.submit(&mut packet, add_queue::API_STATUS, bar2) }?;
        self.ring.mapped_queues += 1;
        Ok(())
    }

    /// Unmap a queue through MES.
    ///
    /// # Safety
    /// As [`MesQueue::submit`].
    pub unsafe fn remove_queue(
        &mut self,
        doorbell_offset: u32,
        gang_context_addr: u64,
        bar2: &MmioRegion,
    ) -> Result<(), MesError> {
        let mut packet = build_remove_queue(doorbell_offset, gang_context_addr, 0, 0, 0);
        // SAFETY: delegated.
        unsafe { self.submit(&mut packet, remove_queue::API_STATUS, bar2) }?;
        self.ring.mapped_queues = self.ring.mapped_queues.saturating_sub(1);
        Ok(())
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// The MES pipe describes itself: descriptor, EOP, and the two
    /// `SET_HW_RSRC` addresses all come from the queue's own allocations.
    ///
    /// Same shape as the graphics queue's consistency test, and for the same
    /// reason: the ring base, the writeback addresses, the descriptor address
    /// and the doorbell appear in both the descriptor and the HQD registers,
    /// and the failure when they disagree is a scheduler that maps and never
    /// runs.
    fn smoke_mes_pipe_describes_itself() -> TestResult {
        use crate::amdgpu_mqd as m;

        let q = match MesQueue::new(4, 0x10) {
            Ok(q) => q,
            Err(_) => return TestResult::Fail("MesQueue::new failed"),
        };
        if q.write_mqd().is_err() {
            return TestResult::Fail("the derived MES descriptor was refused");
        }

        // Five writeback slots, all distinct, at Linux's 32-byte spacing.
        let page = q.wb_phys_for_test();
        let slots = [
            page + WB_STATUS_OFFSET,
            page + WB_FENCE_OFFSET,
            page + WB_WPTR_OFFSET,
            q.sch_ctx_phys(),
            q.query_status_fence_phys(),
        ];
        for (i, a) in slots.iter().enumerate() {
            for b in slots.iter().skip(i + 1) {
                if a == b {
                    return TestResult::Fail("two writeback slots overlap");
                }
            }
        }
        if q.sch_ctx_phys() != page + 3 * crate::amdgpu_gfx::WB_SLOT_BYTES
            || q.query_status_fence_phys() != page + 4 * crate::amdgpu_gfx::WB_SLOT_BYTES
        {
            return TestResult::Fail("the two SET_HW_RSRC slots are the fourth and fifth");
        }
        // And the descriptor, the EOP and the ring are separate allocations:
        // the firmware owns the descriptor between a map and an unmap.
        for (a, b) in [
            (q.mqd_phys(), q.ring_phys()),
            (q.mqd_phys(), q.eop_phys()),
            (q.eop_phys(), q.ring_phys()),
            (q.mqd_phys(), page),
        ] {
            if a == b {
                return TestResult::Fail("the descriptor, EOP, ring and writeback must not share");
            }
        }

        // The descriptor names this queue's ring, shifted right by 8.
        let base = (u64::from(q.mqd_dword(m::C_CP_HQD_PQ_BASE_HI)) << 32)
            | u64::from(q.mqd_dword(m::C_CP_HQD_PQ_BASE_LO));
        if base << 8 != q.ring_phys() {
            return TestResult::Fail("the descriptor does not name this queue's ring");
        }
        // And this queue's EOP, also shifted right by 8 — the defect the
        // compute path had.
        let eop = (u64::from(q.mqd_dword(m::C_CP_HQD_EOP_BASE_ADDR_HI)) << 32)
            | u64::from(q.mqd_dword(m::C_CP_HQD_EOP_BASE_ADDR_LO));
        if eop << 8 != q.eop_phys() {
            return TestResult::Fail("the descriptor does not name this queue's EOP buffer");
        }
        // Active, which is what distinguishes this descriptor from a compute
        // queue's — nothing maps the scheduler.
        if q.mqd_dword(m::C_CP_HQD_ACTIVE) != 1 {
            return TestResult::Fail("the MES pipe's descriptor says active");
        }
        // The doorbell MesQueue::new was given, in the dword space.
        if (q.mqd_dword(m::C_CP_HQD_PQ_DOORBELL_CONTROL) >> 2) & 0x03FF_FFFF != 0x10 {
            return TestResult::Fail("the descriptor carries this queue's doorbell");
        }

        // The register sequence reads the descriptor back out of the page, so
        // the two cannot disagree.
        const GC0: u32 = 0x0003_0000;
        const GC1: u32 = 0x0005_0000;
        let seq = q.queue_init_sequence(GC0, GC1, crate::amdgpu_mes_hw::MES_SCHED_PIPE, 0, 0);
        use crate::amdgpu_mes_hw as hw;
        if seq.first_write_to(GC0, hw::CP_HQD_PQ_BASE) != Some(q.mqd_dword(m::C_CP_HQD_PQ_BASE_LO))
        {
            return TestResult::Fail("the sequence does not carry the descriptor's ring base");
        }
        if seq.first_write_to(GC0, hw::CP_MQD_BASE_ADDR)
            != Some(q.mqd_dword(m::C_CP_MQD_BASE_ADDR_LO))
        {
            return TestResult::Fail("the sequence does not carry the descriptor's own address");
        }
        if seq.first_write_to(GC0, hw::CP_HQD_ACTIVE) != Some(1) {
            return TestResult::Fail("the sequence activates the queue");
        }

        // `SET_HW_RSRC`: this queue's two context addresses, the five flags
        // `mes_v11_0_set_hw_resources` sets, and the topology's masks.
        let res = q.hw_resources(&hw::PHOENIX_TOPOLOGY);
        if res.sch_ctx_gpu_addr != q.sch_ctx_phys() {
            return TestResult::Fail("SET_HW_RSRC must name this queue's scheduler context");
        }
        if res.query_status_fence_gpu_addr != q.query_status_fence_phys() {
            return TestResult::Fail("SET_HW_RSRC must name this queue's query-status fence");
        }
        if res.flags != hw_rsrc_flags::DEFAULTS {
            return TestResult::Fail("the five unconditional flags must be set");
        }
        if res.oversubscription_timer != DEFAULT_OVERSUBSCRIPTION_TIMER {
            return TestResult::Fail("the oversubscription timer is 50");
        }
        if res.gfx_hqd_mask[0] != 0x2 || res.compute_hqd_mask[0] != 0xC {
            return TestResult::Fail("the topology's masks must reach the payload");
        }
        // The packet the payload becomes still round-trips.
        let pkt = build_set_hw_resources(&res);
        if pkt.len() != MES_API_FRAME_DWORDS {
            return TestResult::Fail("the SET_HW_RSRC frame is 64 dwords");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_mes_pipe_describes_itself);

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
            tma_addr: 0x0A0B_0C0D_0E0F_1011,
            process_context_array_index: 0xB1,
            gang_context_array_index: 0xB2,
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
        // The payload does NOT end at api_status. Four more dwords of status
        // and then tma_addr, which is why these sit at 41 and not 37.
        if p[41] != 0x0E0F_1011 || p[42] != 0x0A0B_0C0D {
            return TestResult::Fail("tma_addr is dword 41, past the status block");
        }
        if p[46] != 0xB1 || p[47] != 0xB2 {
            return TestResult::Fail("the context array indices are dwords 46 and 47");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_add_queue_field_placement);

    /// `mes_v11_0_map_legacy_queue` — the GFX11 kernel graphics ring's actual
    /// registration, which is the same opcode carrying six fields.
    ///
    /// The two that matter most are `pipe_id` and `queue_id`, because they sit
    /// PAST `api_status` at dwords 48 and 49. A reading of
    /// `union MESAPI__ADD_QUEUE` that stops at the status block does not know
    /// they exist, and a packet without them names pipe 0 queue 0 whatever
    /// queue the caller meant.
    fn smoke_map_legacy_queue_is_not_add_queue() -> TestResult {
        let args = MesMapLegacyQueueArgs {
            pipe_id: 3,
            queue_id: 2,
            // `AMDGPU_NAVI10_DOORBELL_GFX_RING0 << 1` — the dword space.
            doorbell_offset: 0x08B << 1,
            mqd_addr: 0x1111_2222_3333_4444,
            wptr_addr: 0x5555_6666_7777_8888,
            queue_type: MesQueueType::Gfx,
        };
        let p = build_map_legacy_queue(&args);
        if p.len() != 64 {
            return TestResult::Fail("frame must be 64 dwords");
        }
        let (ty, op, dwsize) = decode_api_header(p[0]);
        if ty != MES_API_TYPE_SCHEDULER
            || op != MesApiOpcode::AddQueue as u32
            || dwsize != MES_API_FRAME_DWORDS as u32
        {
            return TestResult::Fail("the legacy mapping is an ADD_QUEUE packet");
        }
        if p[48] != 3 || p[49] != 2 {
            return TestResult::Fail("pipe_id at 48 and queue_id at 49, past api_status");
        }
        if p[18] != 0x116 {
            return TestResult::Fail("doorbell_offset at 18, in the dword index space");
        }
        if p[19] != 0x3333_4444 || p[20] != 0x1111_2222 {
            return TestResult::Fail("mqd_addr at 19");
        }
        if p[21] != 0x7777_8888 || p[22] != 0x5555_6666 {
            return TestResult::Fail("wptr_addr at 21");
        }
        if p[27] != MesQueueType::Gfx as u32 {
            return TestResult::Fail("queue_type at 27");
        }
        if p[36] != add_queue_flags::MAP_LEGACY_KQ {
            return TestResult::Fail("map_legacy_kq is the only flag set");
        }
        // The process form's fields must all be zero: MES is not being asked
        // to schedule a process, and a null page-table base inside a real
        // process descriptor is worse than an absent one.
        for (idx, what) in [
            (1usize, "process_id"),
            (2, "page_table_base_addr"),
            (4, "process_va_start"),
            (6, "process_va_end"),
            (8, "process_quantum"),
            (10, "process_context_addr"),
            (12, "gang_quantum"),
            (14, "gang_context_addr"),
            (16, "inprocess_gang_priority"),
            (17, "gang_global_priority_level"),
            (23, "h_context"),
            (25, "h_queue"),
            (28, "gds_base"),
            (29, "gds_size"),
            (33, "trap_handler_addr"),
            (35, "vm_context_cntl"),
            (37, "api_status"),
            (41, "tma_addr"),
        ] {
            if p[idx] != 0 {
                let _ = what;
                return TestResult::Fail("a process-form field leaked into the legacy mapping");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_map_legacy_queue_is_not_add_queue);

    /// The whole `union MESAPI__ADD_QUEUE` tail, against `offsetof` run by
    /// gcc on `mes_v11_api_def.h` under its own `#pragma pack(push, 4)`.
    ///
    /// The fields past `api_status` are not all used, and the unused ones are
    /// exactly the ones a later packet shape would reach for — so they are
    /// recorded, and recorded means checked. The union is 64 dwords total, so
    /// every index here has to be inside it.
    fn smoke_add_queue_tail_offsets() -> TestResult {
        use super::add_queue as f;
        for (got, want, _name) in [
            (f::API_STATUS, 37usize, "api_status"),
            (f::TMA_ADDR, 41, "tma_addr"),
            (f::SCH_ID, 43, "sch_id"),
            (f::TIMESTAMP, 44, "timestamp"),
            (
                f::PROCESS_CONTEXT_ARRAY_INDEX,
                46,
                "process_context_array_index",
            ),
            (f::GANG_CONTEXT_ARRAY_INDEX, 47, "gang_context_array_index"),
            (f::PIPE_ID, 48, "pipe_id"),
            (f::QUEUE_ID, 49, "queue_id"),
            (f::ALIGNMENT_MODE_SETTING, 50, "alignment_mode_setting"),
            (f::FULL_SH_MEM_CONFIG_DATA, 51, "full_sh_mem_config_data"),
            (f::UNMAP_FLAG_ADDR, 52, "unmap_flag_addr"),
        ] {
            if got != want {
                return TestResult::Fail("an ADD_QUEUE tail offset disagrees with the header");
            }
            // `unmap_flag_addr` is 64-bit, so it needs its second dword too.
            if got + 1 >= MES_API_FRAME_DWORDS {
                return TestResult::Fail("a tail field does not fit inside the 64-dword frame");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_add_queue_tail_offsets);

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
    /// The status-query packet's layout and the two-fence pairing, against
    /// `mes_v11_api_def.h:551-566` compiled under `#pragma pack(push, 4)` and
    /// `mes_v11_0_submit_pkt_and_poll_completion`.
    fn smoke_mes_status_query_and_fence_pairing() -> TestResult {
        // header 0, subopcode 1, api_status 2 — api_status is NOT at dword 1,
        // which is where every other packet in this file keeps it.
        if query_mes_status::SUBOPCODE != 1 || query_mes_status::API_STATUS != 2 {
            return TestResult::Fail("MESAPI__QUERY_MES_STATUS puts api_status at dword 2");
        }
        let q = build_query_mes_status(0x1122_3344_5566_7788, 0x99);
        if q.len() != MES_API_FRAME_DWORDS {
            return TestResult::Fail("the status query is a full 64-dword frame");
        }
        // Opcode 11, type 1 (MES_API_TYPE_SCHEDULER), dwsize 64.
        if decode_api_header(q[0]) != (1, 11, MES_API_FRAME_DWORDS as u32) {
            return TestResult::Fail("status query header");
        }
        // subopcode stays zero, as Linux's memset leaves it.
        if q[query_mes_status::SUBOPCODE] != 0 {
            return TestResult::Fail("subopcode must be zero");
        }
        if q[2] != 0x5566_7788 || q[3] != 0x1122_3344 {
            return TestResult::Fail("fence address halves");
        }
        if q[4] != 0x99 || q[5] != 0 {
            return TestResult::Fail("fence value halves");
        }

        // Pairing: the command's own fence gets the status slot and value 1,
        // and the trailing query gets the ring fence and the sequence number.
        // Polling only one of the two cannot distinguish "MES never answered"
        // from "the command failed".
        let mut packet = build_add_queue(&MesAddQueueArgs::default());
        let frames = match pair_with_status_query(
            &mut packet,
            add_queue::API_STATUS,
            0xAAAA_0000,
            0xBBBB_0000,
            7,
        ) {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("pairing rejected a valid packet"),
        };
        if frames.len() != 2 * MES_API_FRAME_DWORDS {
            return TestResult::Fail("two frames go on the ring together");
        }
        let s = add_queue::API_STATUS;
        if frames[s] != 0xAAAA_0000 || frames[s + 2] != MES_COMMAND_COMPLETE as u32 {
            return TestResult::Fail("the command's fence must be the status slot, value 1");
        }
        if MES_COMMAND_COMPLETE != 1 {
            return TestResult::Fail("MES writes 1 on completion");
        }
        // The second frame is the query, pointing at the ring fence.
        let base = MES_API_FRAME_DWORDS;
        if decode_api_header(frames[base]).1 != 11 {
            return TestResult::Fail("the second frame must be the status query");
        }
        if frames[base + 2] != 0xBBBB_0000 || frames[base + 4] != 7 {
            return TestResult::Fail("the query must carry the ring fence and sequence");
        }
        // The two fences must be different addresses, or the command's own
        // completion would be indistinguishable from the drain.
        if frames[s] == frames[base + 2] {
            return TestResult::Fail("the two fences must not share a slot");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_mes_status_query_and_fence_pairing);

    /// The owning queue: real backing, distinct writeback slots, and frames
    /// that actually land in the ring.
    fn smoke_mes_queue_writes_frames_into_its_ring() -> TestResult {
        let mut q = match MesQueue::new(4, 0x10) {
            Ok(q) => q,
            Err(_) => return TestResult::Fail("MesQueue::new failed"),
        };
        // Three writeback slots, 32 bytes apart, none overlapping.
        if q.status_phys() == q.fence_phys()
            || q.fence_phys() == q.wptr_phys()
            || q.status_phys() == q.wptr_phys()
        {
            return TestResult::Fail("the status, fence and wptr slots must be distinct");
        }
        if q.fence_phys() - q.status_phys() != crate::amdgpu_gfx::WB_SLOT_BYTES {
            return TestResult::Fail("slots are one 32-byte allocation apart");
        }
        // The ring is four 64-dword frames.
        if q.ring.ring_size_bytes != (4 * MES_API_FRAME_DWORDS * 4) as u32 {
            return TestResult::Fail("ring size");
        }
        // Writing a frame advances the pointer AND puts the dwords in memory —
        // the old push_frame did only the former.
        let frames = build_query_mes_status(0xDEAD_BEEF, 1);
        if q.write_frames(&frames).is_err() {
            return TestResult::Fail("write_frames rejected one frame");
        }
        if q.ring.wptr_dw != MES_API_FRAME_DWORDS as u32 {
            return TestResult::Fail("the write pointer must advance by the frame");
        }
        // SAFETY: the queue's own identity-mapped backing.
        let first = unsafe { core::ptr::read_volatile(q.backing.cpu_ptr_at::<u32>(0)) };
        if first != frames[0] {
            return TestResult::Fail("the frame's header did not reach the ring");
        }
        // SAFETY: same, within the four-frame allocation.
        let last = unsafe {
            core::ptr::read_volatile(
                q.backing
                    .cpu_ptr_at::<u32>((MES_API_FRAME_DWORDS as u64 - 1) * 4),
            )
        };
        if last != frames[MES_API_FRAME_DWORDS - 1] {
            return TestResult::Fail("the frame's tail did not reach the ring");
        }
        // A ring too small for the frames it is handed refuses rather than
        // wrapping over what the scheduler has not read.
        let mut tiny = match MesQueue::new(1, 0) {
            Ok(q) => q,
            Err(_) => return TestResult::Fail("MesQueue::new(1) failed"),
        };
        let pair = [0u32; 2 * MES_API_FRAME_DWORDS];
        if tiny.write_frames(&pair).is_ok() {
            return TestResult::Fail("a one-frame ring cannot hold a command and its query");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_mes_queue_writes_frames_into_its_ring);
}
