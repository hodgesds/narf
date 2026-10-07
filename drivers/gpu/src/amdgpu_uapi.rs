//! AMDGPU DRM UAPI - mechanical translation from Linux kernel 7.3.0-rc4
//! This file is a mechanical mirror of include/uapi/drm/amdgpu_drm.h
//! DO NOT hand-edit; regenerate from the C header instead

#![allow(non_camel_case_types, dead_code)]

// ── Type definitions ──

/// C: drm_amdgpu_gem_create_in
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemCreateIn {
    /// the requested memory size
    pub bo_size: u64,
    /// physical start_addr alignment in bytes for some HW requirements
    pub alignment: u64,
    /// the requested memory domains
    pub domains: u64,
    /// allocation flags
    pub domain_flags: u64,
}

/// C: drm_amdgpu_gem_create_out
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemCreateOut {
    /// returned GEM object handle
    pub handle: u32,
    pub _pad: u32,
}

/// C: drm_amdgpu_gem_create (union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemCreate {
    pub in_: DrmAmdgpuGemCreateIn,
    pub out: DrmAmdgpuGemCreateOut,
}

/// C: drm_amdgpu_bo_list_in
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuBoListIn {
    /// Type of operation
    pub operation: u32,
    /// Handle of list or 0 if we want to create one
    pub list_handle: u32,
    /// Number of BOs in list
    pub bo_number: u32,
    /// Size of each element describing BO
    pub bo_info_size: u32,
    /// Pointer to array describing BOs
    pub bo_info_ptr: u64,
}

/// C: drm_amdgpu_bo_list_entry
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuBoListEntry {
    /// Handle of BO
    pub bo_handle: u32,
    /// New (if specified) BO priority to be used during migration
    pub bo_priority: u32,
}

/// C: drm_amdgpu_bo_list_out
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuBoListOut {
    /// Handle of resource list
    pub list_handle: u32,
    pub _pad: u32,
}

/// C: drm_amdgpu_bo_list (union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuBoList {
    pub in_: DrmAmdgpuBoListIn,
    pub out: DrmAmdgpuBoListOut,
}

/// C: drm_amdgpu_ctx_in
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCtxIn {
    /// AMDGPU_CTX_OP_*
    pub op: u32,
    /// Flags
    pub flags: u32,
    pub ctx_id: u32,
    /// AMDGPU_CTX_PRIORITY_*
    pub priority: i32,
}

/// C: drm_amdgpu_ctx_alloc (inner struct of union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCtxOutAlloc {
    pub ctx_id: u32,
    pub _pad: u32,
}

/// C: drm_amdgpu_ctx_state (inner struct of union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCtxOutState {
    /// For future use, no flags defined so far
    pub flags: u64,
    /// Number of resets caused by this context so far
    pub hangs: u32,
    /// Reset status since the last call of the ioctl
    pub reset_status: u32,
}

/// C: drm_amdgpu_ctx_pstate (inner struct of union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCtxOutPstate {
    pub flags: u32,
    pub _pad: u32,
}

/// C: drm_amdgpu_ctx_out (union - largest member)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCtxOut {
    pub flags: u64,
    pub hangs: u32,
    pub reset_status: u32,
}

/// C: drm_amdgpu_ctx (union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCtx {
    pub in_: DrmAmdgpuCtxIn,
    pub out: DrmAmdgpuCtxOut,
}

/// C: drm_amdgpu_userq_in
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuUserqIn {
    /// AMDGPU_USERQ_OP_*
    pub op: u32,
    /// Queue id passed for operation USERQ_OP_FREE
    pub queue_id: u32,
    /// the target GPU engine to execute workload (AMDGPU_HW_IP_*)
    pub ip_type: u32,
    /// the handle of doorbell GEM object associated with this userqueue client
    pub doorbell_handle: u32,
    /// 32-bit offset of the doorbell in the doorbell bo
    pub doorbell_offset: u32,
    /// flags used for queue parameters
    pub flags: u32,
    /// Virtual address of the GPU memory which holds the queue object
    pub queue_va: u64,
    /// Size of the queue in bytes, this needs to be 256-byte aligned
    pub queue_size: u64,
    /// Virtual address of the GPU memory which holds the ring RPTR
    pub rptr_va: u64,
    /// Virtual address of the GPU memory which holds the ring WPTR
    pub wptr_va: u64,
    /// MQD (memory queue descriptor) pointer
    pub mqd: u64,
    /// size of MQD data in bytes
    pub mqd_size: u64,
}

/// C: drm_amdgpu_userq_out
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuUserqOut {
    /// For operation AMDGPU_USERQ_OP_CREATE: unique queue ID
    pub queue_id: u32,
    pub _pad: u32,
}

/// C: drm_amdgpu_userq (union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuUserq {
    pub in_: DrmAmdgpuUserqIn,
    pub out: DrmAmdgpuUserqOut,
}

/// C: drm_amdgpu_userq_mqd_gfx11
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuUserqMqdGfx11 {
    /// Virtual address of the GPU memory to hold the shadow buffer
    pub shadow_va: u64,
    /// Virtual address of the GPU memory to hold the CSA buffer
    pub csa_va: u64,
}

/// C: drm_amdgpu_userq_mqd_sdma_gfx11
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuUserqMqdSdmaGfx11 {
    /// Virtual address of the GPU memory to hold the CSA buffer
    pub csa_va: u64,
}

/// C: drm_amdgpu_userq_mqd_compute_gfx11
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuUserqMqdComputeGfx11 {
    /// Virtual address of the GPU memory to hold the EOP buffer
    pub eop_va: u64,
}

/// C: drm_amdgpu_userq_signal
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuUserqSignal {
    /// Queue handle used by the userq fence creation function
    pub queue_id: u32,
    pub pad: u32,
    /// The list of syncobj handles submitted by the user queue job to be signaled
    pub syncobj_handles: u64,
    /// A count that represents the number of syncobj handles
    pub num_syncobj_handles: u16,
    pub pad0: u16,
    pub pad1: u32,
    /// The list of BO handles that the submitted user queue job is using for read only
    pub bo_read_handles: u64,
    /// The list of BO handles that the submitted user queue job is using for write only
    pub bo_write_handles: u64,
    /// A count that represents the number of read BO handles
    pub num_bo_read_handles: u32,
    /// A count that represents the number of write BO handles
    pub num_bo_write_handles: u32,
}

/// C: drm_amdgpu_userq_fence_info
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuUserqFenceInfo {
    /// A gpu address allocated for each queue which stores the read pointer (RPTR) value
    pub va: u64,
    /// A 64 bit value represents the write pointer (WPTR) of the queue commands
    pub value: u64,
}

/// C: drm_amdgpu_userq_wait
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuUserqWait {
    /// Queue handle used by the userq wait IOCTL
    pub waitq_id: u32,
    pub pad: u32,
    /// The list of syncobj handles submitted by the user queue job
    pub syncobj_handles: u64,
    /// The list of timeline syncobj handles submitted by the user queue job
    pub syncobj_timeline_handles: u64,
    /// The list of timeline syncobj points
    pub syncobj_timeline_points: u64,
    /// The list of read BO handles
    pub bo_read_handles: u64,
    /// The list of write BO handles
    pub bo_write_handles: u64,
    /// A count that represents the number of timeline syncobj handles
    pub num_syncobj_timeline_handles: u16,
    /// The maximum number of fences that can be returned
    pub num_fences: u16,
    /// A count that represents the number of syncobj handles
    pub num_syncobj_handles: u16,
    pub pad0: u16,
    /// A count that represents the number of read BO handles
    pub num_bo_read_handles: u32,
    /// A count that represents the number of write BO handles
    pub num_bo_write_handles: u32,
    /// The field is a return value from the ioctl containing the list of address/value pairs to wait for
    pub out_fences: u64,
}

/// C: drm_amdgpu_vm_in
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuVmIn {
    /// AMDGPU_VM_OP_*
    pub op: u32,
    pub flags: u32,
}

/// C: drm_amdgpu_vm_out
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuVmOut {
    /// For future use, no flags defined so far
    pub flags: u64,
}

/// C: drm_amdgpu_vm (union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuVm {
    pub in_: DrmAmdgpuVmIn,
    pub out: DrmAmdgpuVmOut,
}

/// C: drm_amdgpu_sched_in
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuSchedIn {
    /// AMDGPU_SCHED_OP_*
    pub op: u32,
    pub fd: u32,
    /// AMDGPU_CTX_PRIORITY_*
    pub priority: i32,
    pub ctx_id: u32,
}

/// C: drm_amdgpu_sched (union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuSched {
    pub in_: DrmAmdgpuSchedIn,
    pub _pad: [u32; 0],
}

/// C: drm_amdgpu_gem_userptr
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemUserptr {
    pub addr: u64,
    pub size: u64,
    /// AMDGPU_GEM_USERPTR_*
    pub flags: u32,
    /// Resulting GEM handle
    pub handle: u32,
}

/// C: drm_amdgpu_gem_metadata
#[repr(C)]
// `Default` is implemented by hand: the derive only covers arrays up to 32.
#[derive(Copy, Clone, Debug)]
pub struct DrmAmdgpuGemMetadata {
    /// GEM Object handle
    pub handle: u32,
    /// Do we want get or set metadata
    pub op: u32,
    /// For future use, no flags defined so far
    pub flags: u64,
    /// family specific tiling info
    pub tiling_info: u64,
    pub data_size_bytes: u32,
    pub data: [u32; 64],
}

impl Default for DrmAmdgpuGemMetadata {
    fn default() -> Self {
        Self {
            handle: 0,
            op: 0,
            flags: 0,
            tiling_info: 0,
            data_size_bytes: 0,
            data: [0; 64],
        }
    }
}

/// C: drm_amdgpu_gem_mmap_in
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemMmapIn {
    /// the GEM object handle
    pub handle: u32,
    pub _pad: u32,
}

/// C: drm_amdgpu_gem_mmap_out
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemMmapOut {
    /// mmap offset from the vma offset manager
    pub addr_ptr: u64,
}

/// C: drm_amdgpu_gem_mmap (union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemMmap {
    pub in_: DrmAmdgpuGemMmapIn,
    pub out: DrmAmdgpuGemMmapOut,
}

/// C: drm_amdgpu_gem_wait_idle_in
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemWaitIdleIn {
    /// GEM object handle
    pub handle: u32,
    /// For future use, no flags defined so far
    pub flags: u32,
    /// Absolute timeout to wait
    pub timeout: u64,
}

/// C: drm_amdgpu_gem_wait_idle_out
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemWaitIdleOut {
    /// BO status: 0 - BO is idle, 1 - BO is busy
    pub status: u32,
    /// Returned current memory domain
    pub domain: u32,
}

/// C: drm_amdgpu_gem_wait_idle (union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemWaitIdle {
    pub in_: DrmAmdgpuGemWaitIdleIn,
    pub out: DrmAmdgpuGemWaitIdleOut,
}

/// C: drm_amdgpu_wait_cs_in
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuWaitCsIn {
    /// Command submission handle (0 means none to wait for, ~0ull means wait for the latest sequence number)
    pub handle: u64,
    /// Absolute timeout to wait
    pub timeout: u64,
    pub ip_type: u32,
    pub ip_instance: u32,
    pub ring: u32,
    pub ctx_id: u32,
}

/// C: drm_amdgpu_wait_cs_out
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuWaitCsOut {
    /// CS status: 0 - CS completed, 1 - CS still busy
    pub status: u64,
}

/// C: drm_amdgpu_wait_cs (union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuWaitCs {
    pub in_: DrmAmdgpuWaitCsIn,
    pub out: DrmAmdgpuWaitCsOut,
}

/// C: drm_amdgpu_fence
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuFence {
    pub ctx_id: u32,
    pub ip_type: u32,
    pub ip_instance: u32,
    pub ring: u32,
    pub seq_no: u64,
}

/// C: drm_amdgpu_wait_fences_in
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuWaitFencesIn {
    /// This points to uint64_t * which points to fences
    pub fences: u64,
    pub fence_count: u32,
    pub wait_all: u32,
    pub timeout_ns: u64,
}

/// C: drm_amdgpu_wait_fences_out
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuWaitFencesOut {
    pub status: u32,
    pub first_signaled: u32,
}

/// C: drm_amdgpu_wait_fences (union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuWaitFences {
    pub in_: DrmAmdgpuWaitFencesIn,
    pub out: DrmAmdgpuWaitFencesOut,
}

/// C: drm_amdgpu_gem_vm_entry
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemVmEntry {
    /// Start of mapping (in bytes)
    pub addr: u64,
    /// Size of mapping (in bytes)
    pub size: u64,
    /// Mapping offset
    pub offset: u64,
    /// flags needed to recreate mapping
    pub flags: u64,
}

/// C: drm_amdgpu_gem_op
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemOp {
    /// GEM object handle
    pub handle: u32,
    /// AMDGPU_GEM_OP_*
    pub op: u32,
    /// Input or return value
    pub value: u64,
    /// For MAPPING_INFO op: number of mappings (in/out)
    pub num_entries: u32,
    pub padding: u32,
}

/// C: drm_amdgpu_gem_list_handles
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemListHandles {
    /// User pointer to array of drm_amdgpu_gem_bo_info_entry
    pub entries: u64,
    /// Size of entries buffer / Number of handles in process
    pub num_entries: u32,
    pub padding: u32,
}

/// C: drm_amdgpu_gem_list_handles_entry
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemListHandlesEntry {
    /// gem handle of buffer object
    pub gem_handle: u32,
    /// Currently just one flag: IS_IMPORT
    pub flags: u32,
    /// Size of bo
    pub size: u64,
    /// Preferred domains for GEM_CREATE
    pub preferred_domains: u64,
    /// GEM_CREATE flags for re-creation of buffer
    pub alloc_flags: u64,
    /// physical start_addr alignment in bytes for some HW requirements
    pub alignment: u64,
}

/// C: drm_amdgpu_gem_va
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuGemVa {
    /// GEM object handle
    pub handle: u32,
    pub _pad: u32,
    /// AMDGPU_VA_OP_*
    pub operation: u32,
    /// AMDGPU_VM_PAGE_*
    pub flags: u32,
    /// va address to assign
    pub va_address: u64,
    /// Specify offset inside of BO to assign
    pub offset_in_bo: u64,
    /// Specify mapping size
    pub map_size: u64,
    /// vm_timeline_point is a sequence number used to add new timeline point
    pub vm_timeline_point: u64,
    /// The vm page table update fence is installed in given vm_timeline_syncobj_out
    pub vm_timeline_syncobj_out: u32,
    /// the number of syncobj handles in input_fence_syncobj_handles
    pub num_syncobj_handles: u32,
    /// Array of sync object handle to wait for given input fences
    pub input_fence_syncobj_handles: u64,
}

/// C: drm_amdgpu_cs_in
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCsIn {
    /// Rendering context id
    pub ctx_id: u32,
    /// Handle of resource list associated with CS
    pub bo_list_handle: u32,
    pub num_chunks: u32,
    pub flags: u32,
    /// this points to __u64 * which point to cs chunks
    pub chunks: u64,
}

/// C: drm_amdgpu_cs_out
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCsOut {
    /// return values to know the value returned in out-fences
    pub handle: u64,
}

/// C: drm_amdgpu_cs (union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCs {
    pub in_: DrmAmdgpuCsIn,
    pub out: DrmAmdgpuCsOut,
}

/// C: drm_amdgpu_cs_chunk
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCsChunk {
    pub chunk_id: u32,
    pub length_dw: u32,
    pub chunk_data: u64,
}

/// C: drm_amdgpu_cs_chunk_ib
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCsChunkIb {
    pub _pad: u32,
    /// AMDGPU_IB_FLAG_*
    pub flags: u32,
    /// Virtual address to begin IB execution
    pub va_start: u64,
    /// Size of submission
    pub ib_bytes: u32,
    /// HW IP to submit to
    pub ip_type: u32,
    /// HW IP index of the same type to submit to
    pub ip_instance: u32,
    /// Ring index to submit to
    pub ring: u32,
}

/// C: drm_amdgpu_cs_chunk_fence
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCsChunkFence {
    pub handle: u32,
    pub offset: u32,
}

/// C: drm_amdgpu_cs_chunk_dep
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCsChunkDep {
    pub ip_type: u32,
    pub ip_instance: u32,
    pub ring: u32,
    pub ctx_id: u32,
    pub handle: u64,
}

/// C: drm_amdgpu_cs_chunk_sem
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCsChunkSem {
    pub handle: u32,
}

/// C: drm_amdgpu_cs_chunk_syncobj
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCsChunkSyncobj {
    pub handle: u32,
    pub flags: u32,
    pub point: u64,
}

/// C: drm_amdgpu_cs_chunk_data
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCsChunkData {
    pub ib_data: [u64; 4],
}

/// C: drm_amdgpu_cs_chunk_cp_gfx_shadow
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCsChunkCpGfxShadow {
    pub shadow_va: u64,
    pub csa_va: u64,
    pub gds_va: u64,
    pub flags: u64,
}

/// C: drm_amdgpu_fence_to_handle (union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuFenceToHandle {
    pub handle: u32,
    pub _pad: u32,
}

/// C: drm_amdgpu_cs_chunk_syncobj_in
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCsChunkSyncobjIn {
    pub handle: u32,
    pub flags: u32,
    pub point: u64,
}

/// C: drm_amdgpu_cs_chunk_syncobj_out
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuCsChunkSyncobjOut {
    pub handle: u32,
    pub flags: u32,
    pub point: u64,
}

/// C: drm_amdgpu_query_fw
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuQueryFw {
    /// AMDGPU_INFO_FW_*
    pub fw_type: u32,
    /// Index of the IP if there are more IPs of the same type
    pub ip_instance: u32,
    /// Index of the engine
    pub index: u32,
    pub _pad: u32,
}

/// C: drm_amdgpu_info
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfo {
    /// Where the return value will be stored
    pub return_pointer: u64,
    /// The size of the return value. Like `snprintf`'s "size", it limits how
    /// many bytes the kernel may write.
    pub return_size: u32,
    /// The query request id — one of the `AMDGPU_INFO_*` constants.
    pub query: u32,
    /// The anonymous union, as its largest member: 16 bytes.
    ///
    /// The union was originally mirrored by laying its members out one after
    /// another, which made this struct 56 bytes where C is 32 — every
    /// `AMDGPU_INFO` call would have read its parameters from the wrong
    /// offsets. The members it overlays, each starting at word 0:
    ///
    /// ```text
    /// mode_crtc     { u32 id; u32 _pad; }
    /// query_hw_ip   { u32 type; u32 ip_instance; }
    /// read_mmr_reg  { u32 dword_offset; u32 count; u32 instance; u32 flags; }
    /// query_fw      drm_amdgpu_query_fw (16 bytes — the largest member)
    /// vbios_info    { u32 type; u32 offset; }
    /// sensor_info   { u32 type; }
    /// video_cap     { u32 type; }
    /// ```
    pub union_payload: [u32; 4],
}

impl DrmAmdgpuInfo {
    /// `query_hw_ip { type, ip_instance }`.
    pub const fn query_hw_ip(ty: u32, ip_instance: u32) -> [u32; 4] {
        [ty, ip_instance, 0, 0]
    }
    /// `read_mmr_reg { dword_offset, count, instance, flags }`.
    pub const fn read_mmr_reg(
        dword_offset: u32,
        count: u32,
        instance: u32,
        flags: u32,
    ) -> [u32; 4] {
        [dword_offset, count, instance, flags]
    }
    /// `query_fw { fw_type, ip_instance, index, _pad }`.
    pub const fn query_fw(fw_type: u32, ip_instance: u32, index: u32) -> [u32; 4] {
        [fw_type, ip_instance, index, 0]
    }
    /// `sensor_info { type }` — also the shape of `video_cap`.
    pub const fn sensor_info(ty: u32) -> [u32; 4] {
        [ty, 0, 0, 0]
    }
}

/// C: drm_amdgpu_info_gds
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoGds {
    /// GDS GFX partition size
    pub gds_gfx_partition_size: u32,
    /// GDS compute partition size
    pub compute_partition_size: u32,
    /// total GDS memory size
    pub gds_total_size: u32,
    /// GWS size per GFX partition
    pub gws_per_gfx_partition: u32,
    /// GSW size per compute partition
    pub gws_per_compute_partition: u32,
    /// OA size per GFX partition
    pub oa_per_gfx_partition: u32,
    /// OA size per compute partition
    pub oa_per_compute_partition: u32,
    pub _pad: u32,
}

/// C: drm_amdgpu_info_vram_gtt
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoVramGtt {
    pub vram_size: u64,
    pub vram_cpu_accessible_size: u64,
    pub gtt_size: u64,
}

/// C: drm_amdgpu_heap_info
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuHeapInfo {
    /// max. physical memory
    pub total_heap_size: u64,
    /// Theoretical max. available memory in the given heap
    pub usable_heap_size: u64,
    /// Number of bytes allocated in the heap
    pub heap_usage: u64,
    /// Theoretical possible max. size of buffer which could be allocated
    pub max_allocation: u64,
}

/// C: drm_amdgpu_memory_info
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuMemoryInfo {
    pub vram: DrmAmdgpuHeapInfo,
    pub cpu_accessible_vram: DrmAmdgpuHeapInfo,
    pub gtt: DrmAmdgpuHeapInfo,
}

/// C: drm_amdgpu_info_firmware
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoFirmware {
    pub ver: u32,
    pub feature: u32,
}

/// C: drm_amdgpu_info_vbios
#[repr(C)]
// `Default` is implemented by hand: the derive only covers arrays up to 32.
#[derive(Copy, Clone, Debug)]
pub struct DrmAmdgpuInfoVbios {
    pub name: [u8; 64],
    pub vbios_pn: [u8; 64],
    pub version: u32,
    pub pad: u32,
    pub vbios_ver_str: [u8; 32],
    pub date: [u8; 32],
}

impl Default for DrmAmdgpuInfoVbios {
    fn default() -> Self {
        Self {
            name: [0; 64],
            vbios_pn: [0; 64],
            version: 0,
            pad: 0,
            vbios_ver_str: [0; 32],
            date: [0; 32],
        }
    }
}

/// C: drm_amdgpu_info_device
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoDevice {
    /// PCI Device ID
    pub device_id: u32,
    /// Internal chip revision
    pub chip_rev: u32,
    pub external_rev: u32,
    /// Revision id in PCI Config space
    pub pci_rev: u32,
    pub family: u32,
    pub num_shader_engines: u32,
    pub num_shader_arrays_per_engine: u32,
    /// in KHz
    pub gpu_counter_freq: u32,
    pub max_engine_clock: u64,
    pub max_memory_clock: u64,
    /// cu information
    pub cu_active_number: u32,
    pub cu_ao_mask: u32,
    pub cu_bitmap: [[u32; 4]; 4],
    /// Render backend pipe mask
    pub enabled_rb_pipes_mask: u32,
    pub num_rb_pipes: u32,
    pub num_hw_gfx_contexts: u32,
    /// PCIe version
    pub pcie_gen: u32,
    pub ids_flags: u64,
    /// Starting virtual address for UMDs
    pub virtual_address_offset: u64,
    /// The maximum virtual address
    pub virtual_address_max: u64,
    /// Required alignment of virtual addresses
    pub virtual_address_alignment: u32,
    /// Page table entry - fragment size
    pub pte_fragment_size: u32,
    pub gart_page_size: u32,
    /// constant engine ram size
    pub ce_ram_size: u32,
    /// video memory type info
    pub vram_type: u32,
    /// video memory bit width
    pub vram_bit_width: u32,
    /// vce harvesting instance
    pub vce_harvest_config: u32,
    /// gfx double offchip LDS buffers
    pub gc_double_offchip_lds_buf: u32,
    /// NGG Primitive Buffer
    pub prim_buf_gpu_addr: u64,
    /// NGG Position Buffer
    pub pos_buf_gpu_addr: u64,
    /// NGG Control Sideband
    pub cntl_sb_buf_gpu_addr: u64,
    /// NGG Parameter Cache
    pub param_buf_gpu_addr: u64,
    pub prim_buf_size: u32,
    pub pos_buf_size: u32,
    pub cntl_sb_buf_size: u32,
    pub param_buf_size: u32,
    /// wavefront size
    pub wave_front_size: u32,
    /// shader visible vgprs
    pub num_shader_visible_vgprs: u32,
    /// CU per shader array
    pub num_cu_per_sh: u32,
    /// number of tcc blocks
    pub num_tcc_blocks: u32,
    /// gs vgt table depth
    pub gs_vgt_table_depth: u32,
    /// gs primitive buffer depth
    pub gs_prim_buffer_depth: u32,
    /// max gs wavefront per vgt
    pub max_gs_waves_per_vgt: u32,
    /// PCIe number of lanes
    pub pcie_num_lanes: u32,
    /// always on cu bitmap
    pub cu_ao_bitmap: [[u32; 4]; 4],
    /// Starting high virtual address for UMDs
    pub high_va_offset: u64,
    /// The maximum high virtual address
    pub high_va_max: u64,
    /// gfx10 pa_sc_tile_steering_override
    pub pa_sc_tile_steering_override: u32,
    pub pad: u32,
    /// disabled TCCs
    pub tcc_disabled_mask: u64,
    pub min_engine_clock: u64,
    pub min_memory_clock: u64,
    /// The following fields are only set on gfx11+
    pub tcp_cache_size: u32,
    pub num_sqc_per_wgp: u32,
    pub sqc_data_cache_size: u32,
    pub sqc_inst_cache_size: u32,
    pub gl1c_cache_size: u32,
    pub gl2c_cache_size: u32,
    pub mall_size: u64,
    /// high 32 bits of the rb pipes mask
    pub enabled_rb_pipes_mask_hi: u32,
    /// shadow area size for gfx11
    pub shadow_size: u32,
    /// shadow area base virtual alignment for gfx11
    pub shadow_alignment: u32,
    /// context save area size for gfx11
    pub csa_size: u32,
    /// context save area base virtual alignment for gfx11
    pub csa_alignment: u32,
    /// Userq IP mask
    pub userq_ip_mask: u32,
}

/// C: drm_amdgpu_info_hw_ip
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoHwIp {
    /// Version of h/w IP
    pub hw_ip_version_major: u32,
    pub hw_ip_version_minor: u32,
    /// Capabilities
    pub capabilities_flags: u64,
    /// command buffer address start alignment
    pub ib_start_alignment: u32,
    /// command buffer size alignment
    pub ib_size_alignment: u32,
    /// Bitmask of available rings
    pub available_rings: u32,
    /// version info
    pub ip_discovery_version: u32,
    /// Userq available slots
    pub userq_num_slots: u32,
}

/// C: drm_amdgpu_info_num_handles
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoNumHandles {
    /// Max handles as supported by firmware for UVD
    pub uvd_max_handles: u32,
    /// Handles currently in use for UVD
    pub uvd_used_handles: u32,
}

/// C: drm_amdgpu_info_vce_clock_table_entry
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoVceClockTableEntry {
    /// System clock
    pub sclk: u32,
    /// Memory clock
    pub mclk: u32,
    /// VCE clock
    pub eclk: u32,
    pub pad: u32,
}

/// C: drm_amdgpu_info_vce_clock_table
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoVceClockTable {
    pub entries: [DrmAmdgpuInfoVceClockTableEntry; 6],
    pub num_valid_entries: u32,
    pub pad: u32,
}

/// C: drm_amdgpu_info_video_codec_info
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoVideoCodecInfo {
    pub valid: u32,
    pub max_width: u32,
    pub max_height: u32,
    pub max_pixels_per_frame: u32,
    pub max_level: u32,
    pub pad: u32,
}

/// C: drm_amdgpu_info_video_caps
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoVideoCaps {
    pub codec_info: [DrmAmdgpuInfoVideoCodecInfo; 8],
}

/// C: drm_amdgpu_info_gpuvm_fault
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoGpuvmFault {
    pub addr: u64,
    pub status: u32,
    pub vmhub: u32,
}

/// C: drm_amdgpu_info_uq_metadata_gfx
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoUqMetadataGfx {
    pub shadow_size: u32,
    pub shadow_alignment: u32,
    pub csa_size: u32,
    pub csa_alignment: u32,
}

/// C: drm_amdgpu_info_uq_metadata_compute
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoUqMetadataCompute {
    pub eop_size: u32,
    pub eop_alignment: u32,
}

/// C: drm_amdgpu_info_uq_metadata_sdma
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoUqMetadataSdma {
    pub csa_size: u32,
    pub csa_alignment: u32,
}

/// C: drm_amdgpu_info_uq_metadata (union)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuInfoUqMetadata {
    pub gfx_data: [u32; 4],
}

/// C: drm_amdgpu_proc_options
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmAmdgpuProcOptions {
    pub op: u32,
    /// C: the nested `struct { __u32 value; } kfd_sigbus_delay`. Flattening a
    /// NESTED struct preserves layout (unlike flattening a union); the field
    /// is named for its path so the C spelling stays greppable. The mirror
    /// originally had a single `flags` field and was 4 bytes, not 8.
    pub kfd_sigbus_delay_value: u32,
}

// ── Constants ──

/// DRM ioctl command opcodes
pub const DRM_AMDGPU_GEM_CREATE: u32 = 0x00;
pub const DRM_AMDGPU_GEM_MMAP: u32 = 0x01;
pub const DRM_AMDGPU_CTX: u32 = 0x02;
pub const DRM_AMDGPU_BO_LIST: u32 = 0x03;
pub const DRM_AMDGPU_CS: u32 = 0x04;
pub const DRM_AMDGPU_INFO: u32 = 0x05;
pub const DRM_AMDGPU_GEM_METADATA: u32 = 0x06;
pub const DRM_AMDGPU_GEM_WAIT_IDLE: u32 = 0x07;
pub const DRM_AMDGPU_GEM_VA: u32 = 0x08;
pub const DRM_AMDGPU_WAIT_CS: u32 = 0x09;
pub const DRM_AMDGPU_GEM_OP: u32 = 0x10;
pub const DRM_AMDGPU_GEM_USERPTR: u32 = 0x11;
pub const DRM_AMDGPU_WAIT_FENCES: u32 = 0x12;
pub const DRM_AMDGPU_VM: u32 = 0x13;
pub const DRM_AMDGPU_FENCE_TO_HANDLE: u32 = 0x14;
pub const DRM_AMDGPU_SCHED: u32 = 0x15;
pub const DRM_AMDGPU_USERQ: u32 = 0x16;
pub const DRM_AMDGPU_USERQ_SIGNAL: u32 = 0x17;
pub const DRM_AMDGPU_USERQ_WAIT: u32 = 0x18;
pub const DRM_AMDGPU_GEM_LIST_HANDLES: u32 = 0x19;
pub const DRM_AMDGPU_PROC_OPTIONS: u32 = 0x1A;

/// Memory domains
/// System memory that is not GPU accessible
pub const AMDGPU_GEM_DOMAIN_CPU: u32 = 0x1;
/// GPU accessible system memory
pub const AMDGPU_GEM_DOMAIN_GTT: u32 = 0x2;
/// Local video memory
pub const AMDGPU_GEM_DOMAIN_VRAM: u32 = 0x4;
/// Global on-chip data storage
pub const AMDGPU_GEM_DOMAIN_GDS: u32 = 0x8;
/// Global wave sync
pub const AMDGPU_GEM_DOMAIN_GWS: u32 = 0x10;
/// Ordered append
pub const AMDGPU_GEM_DOMAIN_OA: u32 = 0x20;
/// Doorbell MMIO region
pub const AMDGPU_GEM_DOMAIN_DOORBELL: u32 = 0x40;

/// GEM create flags
/// CPU access will be required for the case of VRAM domain
pub const AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED: u32 = 1 << 0;
/// CPU access will not work, this VRAM domain is invisible
pub const AMDGPU_GEM_CREATE_NO_CPU_ACCESS: u32 = 1 << 1;
/// USWC attributes should be used for GTT
pub const AMDGPU_GEM_CREATE_CPU_GTT_USWC: u32 = 1 << 2;
/// The memory should be in VRAM and cleared
pub const AMDGPU_GEM_CREATE_VRAM_CLEARED: u32 = 1 << 3;
/// Allocating the BO should use linear VRAM
pub const AMDGPU_GEM_CREATE_VRAM_CONTIGUOUS: u32 = 1 << 5;
/// BO is always valid in this VM
pub const AMDGPU_GEM_CREATE_VM_ALWAYS_VALID: u32 = 1 << 6;
/// BO sharing will be explicitly synchronized
pub const AMDGPU_GEM_CREATE_EXPLICIT_SYNC: u32 = 1 << 7;
/// Allocating MQD gart on GFX9
pub const AMDGPU_GEM_CREATE_CP_MQD_GFX9: u32 = 1 << 8;
/// BO may contain sensitive data that must be wiped
pub const AMDGPU_GEM_CREATE_VRAM_WIPE_ON_RELEASE: u32 = 1 << 9;
/// BO will be encrypted
pub const AMDGPU_GEM_CREATE_ENCRYPTED: u32 = 1 << 10;
/// BO will be used only in preemptible context
pub const AMDGPU_GEM_CREATE_PREEMPTIBLE: u32 = 1 << 11;
/// BO can be discarded under memory pressure
pub const AMDGPU_GEM_CREATE_DISCARDABLE: u32 = 1 << 12;
/// BO is shared coherently between multiple devices
pub const AMDGPU_GEM_CREATE_COHERENT: u32 = 1 << 13;
/// BO should not be cached by GPU
pub const AMDGPU_GEM_CREATE_UNCACHED: u32 = 1 << 14;
/// BO should be coherent across devices
pub const AMDGPU_GEM_CREATE_EXT_COHERENT: u32 = 1 << 15;
/// Set PTE.D and recompress during GTT->VRAM moves
pub const AMDGPU_GEM_CREATE_GFX12_DCC: u32 = 1 << 16;

/// BO list operations
/// Opcode to create new residency list
pub const AMDGPU_BO_LIST_OP_CREATE: u32 = 0;
/// Opcode to destroy previously created residency list
pub const AMDGPU_BO_LIST_OP_DESTROY: u32 = 1;
/// Opcode to update resource information in the list
pub const AMDGPU_BO_LIST_OP_UPDATE: u32 = 2;

/// Context operations
pub const AMDGPU_CTX_OP_ALLOC_CTX: u32 = 1;
pub const AMDGPU_CTX_OP_FREE_CTX: u32 = 2;
pub const AMDGPU_CTX_OP_QUERY_STATE: u32 = 3;
pub const AMDGPU_CTX_OP_QUERY_STATE2: u32 = 4;
pub const AMDGPU_CTX_OP_GET_STABLE_PSTATE: u32 = 5;
pub const AMDGPU_CTX_OP_SET_STABLE_PSTATE: u32 = 6;

/// GPU reset status
pub const AMDGPU_CTX_NO_RESET: u32 = 0;
pub const AMDGPU_CTX_GUILTY_RESET: u32 = 1;
pub const AMDGPU_CTX_INNOCENT_RESET: u32 = 2;
pub const AMDGPU_CTX_UNKNOWN_RESET: u32 = 3;

/// Context query flags
pub const AMDGPU_CTX_QUERY2_FLAGS_RESET: u32 = 1 << 0;
pub const AMDGPU_CTX_QUERY2_FLAGS_VRAMLOST: u32 = 1 << 1;
pub const AMDGPU_CTX_QUERY2_FLAGS_GUILTY: u32 = 1 << 2;
pub const AMDGPU_CTX_QUERY2_FLAGS_RAS_CE: u32 = 1 << 3;
pub const AMDGPU_CTX_QUERY2_FLAGS_RAS_UE: u32 = 1 << 4;
pub const AMDGPU_CTX_QUERY2_FLAGS_RESET_IN_PROGRESS: u32 = 1 << 5;

/// Context priority levels
pub const AMDGPU_CTX_PRIORITY_UNSET: i32 = -2048;
pub const AMDGPU_CTX_PRIORITY_VERY_LOW: i32 = -1023;
pub const AMDGPU_CTX_PRIORITY_LOW: i32 = -512;
pub const AMDGPU_CTX_PRIORITY_NORMAL: i32 = 0;
pub const AMDGPU_CTX_PRIORITY_HIGH: i32 = 512;
pub const AMDGPU_CTX_PRIORITY_VERY_HIGH: i32 = 1023;

/// Stable pstate modes
pub const AMDGPU_CTX_STABLE_PSTATE_FLAGS_MASK: u32 = 0xf;
pub const AMDGPU_CTX_STABLE_PSTATE_NONE: u32 = 0;
pub const AMDGPU_CTX_STABLE_PSTATE_STANDARD: u32 = 1;
pub const AMDGPU_CTX_STABLE_PSTATE_MIN_SCLK: u32 = 2;
pub const AMDGPU_CTX_STABLE_PSTATE_MIN_MCLK: u32 = 3;
pub const AMDGPU_CTX_STABLE_PSTATE_PEAK: u32 = 4;

/// User queue operations
pub const AMDGPU_USERQ_OP_CREATE: u32 = 1;
pub const AMDGPU_USERQ_OP_FREE: u32 = 2;

/// User queue priority flags
pub const AMDGPU_USERQ_CREATE_FLAGS_QUEUE_PRIORITY_MASK: u32 = 0x3;
pub const AMDGPU_USERQ_CREATE_FLAGS_QUEUE_PRIORITY_SHIFT: u32 = 0;
pub const AMDGPU_USERQ_CREATE_FLAGS_QUEUE_PRIORITY_NORMAL_LOW: u32 = 0;
pub const AMDGPU_USERQ_CREATE_FLAGS_QUEUE_PRIORITY_LOW: u32 = 1;
pub const AMDGPU_USERQ_CREATE_FLAGS_QUEUE_PRIORITY_NORMAL_HIGH: u32 = 2;
pub const AMDGPU_USERQ_CREATE_FLAGS_QUEUE_PRIORITY_HIGH: u32 = 3;
pub const AMDGPU_USERQ_CREATE_FLAGS_QUEUE_SECURE: u32 = 1 << 2;

/// VM operations
pub const AMDGPU_VM_OP_RESERVE_VMID: u32 = 1;
pub const AMDGPU_VM_OP_UNRESERVE_VMID: u32 = 2;

/// Scheduler operations
pub const AMDGPU_SCHED_OP_PROCESS_PRIORITY_OVERRIDE: u32 = 1;
pub const AMDGPU_SCHED_OP_CONTEXT_PRIORITY_OVERRIDE: u32 = 2;

/// GEM userptr flags
pub const AMDGPU_GEM_USERPTR_READONLY: u32 = 1 << 0;
pub const AMDGPU_GEM_USERPTR_ANONONLY: u32 = 1 << 1;
pub const AMDGPU_GEM_USERPTR_VALIDATE: u32 = 1 << 2;
pub const AMDGPU_GEM_USERPTR_REGISTER: u32 = 1 << 3;

/// Tiling flags - SI-CI-VI
pub const AMDGPU_TILING_ARRAY_MODE_SHIFT: u32 = 0;
pub const AMDGPU_TILING_ARRAY_MODE_MASK: u32 = 0xf;
pub const AMDGPU_TILING_PIPE_CONFIG_SHIFT: u32 = 4;
pub const AMDGPU_TILING_PIPE_CONFIG_MASK: u32 = 0x1f;
pub const AMDGPU_TILING_TILE_SPLIT_SHIFT: u32 = 9;
pub const AMDGPU_TILING_TILE_SPLIT_MASK: u32 = 0x7;
pub const AMDGPU_TILING_MICRO_TILE_MODE_SHIFT: u32 = 12;
pub const AMDGPU_TILING_MICRO_TILE_MODE_MASK: u32 = 0x7;
pub const AMDGPU_TILING_BANK_WIDTH_SHIFT: u32 = 15;
pub const AMDGPU_TILING_BANK_WIDTH_MASK: u32 = 0x3;
pub const AMDGPU_TILING_BANK_HEIGHT_SHIFT: u32 = 17;
pub const AMDGPU_TILING_BANK_HEIGHT_MASK: u32 = 0x3;
pub const AMDGPU_TILING_MACRO_TILE_ASPECT_SHIFT: u32 = 19;
pub const AMDGPU_TILING_MACRO_TILE_ASPECT_MASK: u32 = 0x3;
pub const AMDGPU_TILING_NUM_BANKS_SHIFT: u32 = 21;
pub const AMDGPU_TILING_NUM_BANKS_MASK: u32 = 0x3;

/// Tiling flags - GFX9 through GFX11
pub const AMDGPU_TILING_SWIZZLE_MODE_SHIFT: u32 = 0;
pub const AMDGPU_TILING_SWIZZLE_MODE_MASK: u32 = 0x1f;
pub const AMDGPU_TILING_DCC_OFFSET_256B_SHIFT: u32 = 5;
pub const AMDGPU_TILING_DCC_OFFSET_256B_MASK: u32 = 0xFFFFFF;
pub const AMDGPU_TILING_DCC_PITCH_MAX_SHIFT: u32 = 29;
pub const AMDGPU_TILING_DCC_PITCH_MAX_MASK: u32 = 0x3FFF;
pub const AMDGPU_TILING_DCC_INDEPENDENT_64B_SHIFT: u32 = 43;
pub const AMDGPU_TILING_DCC_INDEPENDENT_64B_MASK: u64 = 0x1;
pub const AMDGPU_TILING_DCC_INDEPENDENT_128B_SHIFT: u32 = 44;
pub const AMDGPU_TILING_DCC_INDEPENDENT_128B_MASK: u64 = 0x1;
pub const AMDGPU_TILING_SCANOUT_SHIFT: u32 = 63;
pub const AMDGPU_TILING_SCANOUT_MASK: u32 = 0x1;

/// Tiling flags - GFX12 and later
pub const AMDGPU_TILING_GFX12_SWIZZLE_MODE_SHIFT: u32 = 0;
pub const AMDGPU_TILING_GFX12_SWIZZLE_MODE_MASK: u32 = 0x7;
pub const AMDGPU_TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_SHIFT: u32 = 3;
pub const AMDGPU_TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_MASK: u32 = 0x3;
pub const AMDGPU_TILING_GFX12_DCC_NUMBER_TYPE_SHIFT: u32 = 5;
pub const AMDGPU_TILING_GFX12_DCC_NUMBER_TYPE_MASK: u32 = 0x7;
pub const AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_SHIFT: u32 = 8;
pub const AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_MASK: u32 = 0x3f;
pub const AMDGPU_TILING_GFX12_DCC_WRITE_COMPRESS_DISABLE_SHIFT: u32 = 14;
pub const AMDGPU_TILING_GFX12_DCC_WRITE_COMPRESS_DISABLE_MASK: u32 = 0x1;
pub const AMDGPU_TILING_GFX12_SCANOUT_SHIFT: u32 = 63;
pub const AMDGPU_TILING_GFX12_SCANOUT_MASK: u32 = 0x1;

/// Metadata operations
pub const AMDGPU_GEM_METADATA_OP_SET_METADATA: u32 = 1;
pub const AMDGPU_GEM_METADATA_OP_GET_METADATA: u32 = 2;

/// GEM operations
pub const AMDGPU_GEM_OP_GET_GEM_CREATE_INFO: u32 = 0;
pub const AMDGPU_GEM_OP_SET_PLACEMENT: u32 = 1;
pub const AMDGPU_GEM_OP_GET_MAPPING_INFO: u32 = 2;

/// VA operations
pub const AMDGPU_VA_OP_MAP: u32 = 1;
pub const AMDGPU_VA_OP_UNMAP: u32 = 2;
pub const AMDGPU_VA_OP_CLEAR: u32 = 3;
pub const AMDGPU_VA_OP_REPLACE: u32 = 4;

/// VM page mapping flags
pub const AMDGPU_VM_DELAY_UPDATE: u32 = 1 << 0;
pub const AMDGPU_VM_PAGE_READABLE: u32 = 1 << 1;
pub const AMDGPU_VM_PAGE_WRITEABLE: u32 = 1 << 2;
pub const AMDGPU_VM_PAGE_EXECUTABLE: u32 = 1 << 3;
pub const AMDGPU_VM_PAGE_PRT: u32 = 1 << 4;
pub const AMDGPU_VM_MTYPE_MASK: u32 = 0xf << 5;
pub const AMDGPU_VM_MTYPE_DEFAULT: u32 = 0 << 5;
pub const AMDGPU_VM_MTYPE_NC: u32 = 1 << 5;
pub const AMDGPU_VM_MTYPE_WC: u32 = 2 << 5;
pub const AMDGPU_VM_MTYPE_CC: u32 = 3 << 5;
pub const AMDGPU_VM_MTYPE_UC: u32 = 4 << 5;

/// HW IP types
pub const AMDGPU_HW_IP_GFX: u32 = 0;
pub const AMDGPU_HW_IP_COMPUTE: u32 = 1;
pub const AMDGPU_HW_IP_DMA: u32 = 2;
pub const AMDGPU_HW_IP_UVD: u32 = 3;
pub const AMDGPU_HW_IP_VCE: u32 = 4;
pub const AMDGPU_HW_IP_UVD_ENC: u32 = 5;
pub const AMDGPU_HW_IP_VCN_DEC: u32 = 6;
pub const AMDGPU_HW_IP_VCN_ENC: u32 = 7;
pub const AMDGPU_HW_IP_VCN_JPEG: u32 = 8;
pub const AMDGPU_HW_IP_VPE: u32 = 9;
pub const AMDGPU_HW_IP_NUM: u32 = 10;
pub const AMDGPU_HW_IP_INSTANCE_MAX_COUNT: u32 = 1;

/// CS chunk types
pub const AMDGPU_CHUNK_ID_IB: u32 = 0x01;
pub const AMDGPU_CHUNK_ID_FENCE: u32 = 0x02;
pub const AMDGPU_CHUNK_ID_DEPENDENCIES: u32 = 0x03;
pub const AMDGPU_CHUNK_ID_SYNCOBJ_IN: u32 = 0x04;
pub const AMDGPU_CHUNK_ID_SYNCOBJ_OUT: u32 = 0x05;
pub const AMDGPU_CHUNK_ID_BO_HANDLES: u32 = 0x06;
pub const AMDGPU_CHUNK_ID_SCHEDULED_DEPENDENCIES: u32 = 0x07;
pub const AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT: u32 = 0x08;
pub const AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_SIGNAL: u32 = 0x09;
pub const AMDGPU_CHUNK_ID_CP_GFX_SHADOW: u32 = 0x0a;

/// IB flags - Specify flags to be used for IB
/// This IB should be submitted to CE
pub const AMDGPU_IB_FLAG_CE: u32 = 1 << 0;
/// Preamble flag, which means the IB could be dropped if no context switch
pub const AMDGPU_IB_FLAG_PREAMBLE: u32 = 1 << 1;
/// Preempt flag, IB should set Pre_enb bit if PREEMPT flag detected
pub const AMDGPU_IB_FLAG_PREEMPT: u32 = 1 << 2;
/// The IB fence should do the L2 writeback but not invalidate any shader caches
pub const AMDGPU_IB_FLAG_TC_WB_NOT_INVALIDATE: u32 = 1 << 3;
/// Set GDS_COMPUTE_MAX_WAVE_ID = DEFAULT before PACKET3_INDIRECT_BUFFER
pub const AMDGPU_IB_FLAG_RESET_GDS_MAX_WAVE_ID: u32 = 1 << 4;
/// Flag the IB as secure (TMZ)
pub const AMDGPU_IB_FLAGS_SECURE: u32 = 1 << 5;
/// Tell KMD to flush and invalidate caches
pub const AMDGPU_IB_FLAG_EMIT_MEM_SYNC: u32 = 1 << 6;

/// CS chunk CP GFX shadow flags
pub const AMDGPU_CS_CHUNK_CP_GFX_SHADOW_FLAGS_INIT_SHADOW: u32 = 0x1;

/// Fence to handle operations
pub const AMDGPU_FENCE_TO_HANDLE_GET_SYNCOBJ: u32 = 0;
pub const AMDGPU_FENCE_TO_HANDLE_GET_SYNCOBJ_FD: u32 = 1;

/// IDS flags
pub const AMDGPU_IDS_FLAGS_FUSION: u32 = 0x01;
pub const AMDGPU_IDS_FLAGS_PREEMPTION: u32 = 0x02;
pub const AMDGPU_IDS_FLAGS_TMZ: u32 = 0x04;
pub const AMDGPU_IDS_FLAGS_CONFORMANT_TRUNC_COORD: u32 = 0x08;
pub const AMDGPU_IDS_FLAGS_MODE_MASK: u32 = 0x300;
pub const AMDGPU_IDS_FLAGS_MODE_SHIFT: u32 = 0x8;
pub const AMDGPU_IDS_FLAGS_MODE_PF: u32 = 0x0;
pub const AMDGPU_IDS_FLAGS_MODE_VF: u32 = 0x1;

/// INFO query IDs
/// indicate if acceleration can be working
pub const AMDGPU_INFO_ACCEL_WORKING: u32 = 0x00;
/// get the crtc_id from the mode object id
pub const AMDGPU_INFO_CRTC_FROM_ID: u32 = 0x01;
/// query hw IP info
pub const AMDGPU_INFO_HW_IP_INFO: u32 = 0x02;
/// query hw IP instance count for the specified type
pub const AMDGPU_INFO_HW_IP_COUNT: u32 = 0x03;
/// timestamp for GL_ARB_timer_query
pub const AMDGPU_INFO_TIMESTAMP: u32 = 0x05;
/// Query the firmware version
pub const AMDGPU_INFO_FW_VERSION: u32 = 0x0e;
/// number of bytes moved for TTM migration
pub const AMDGPU_INFO_NUM_BYTES_MOVED: u32 = 0x0f;
/// the used VRAM size
pub const AMDGPU_INFO_VRAM_USAGE: u32 = 0x10;
/// the used GTT size
pub const AMDGPU_INFO_GTT_USAGE: u32 = 0x11;
/// Information about GDS, etc. resource configuration
pub const AMDGPU_INFO_GDS_CONFIG: u32 = 0x13;
/// Query information about VRAM and GTT domains
pub const AMDGPU_INFO_VRAM_GTT: u32 = 0x14;
/// Query information about register in MMR address space
pub const AMDGPU_INFO_READ_MMR_REG: u32 = 0x15;
/// Query information about device: rev id, family, etc.
pub const AMDGPU_INFO_DEV_INFO: u32 = 0x16;
/// visible vram usage
pub const AMDGPU_INFO_VIS_VRAM_USAGE: u32 = 0x17;
/// number of TTM buffer evictions
pub const AMDGPU_INFO_NUM_EVICTIONS: u32 = 0x18;
/// Query memory about VRAM and GTT domains
pub const AMDGPU_INFO_MEMORY: u32 = 0x19;
/// Query vce clock table
pub const AMDGPU_INFO_VCE_CLOCK_TABLE: u32 = 0x1A;
/// Query vbios related information
pub const AMDGPU_INFO_VBIOS: u32 = 0x1B;
/// Query UVD handles
pub const AMDGPU_INFO_NUM_HANDLES: u32 = 0x1C;
/// Query sensor related information
pub const AMDGPU_INFO_SENSOR: u32 = 0x1D;
/// Number of VRAM page faults on CPU access
pub const AMDGPU_INFO_NUM_VRAM_CPU_PAGE_FAULTS: u32 = 0x1E;
pub const AMDGPU_INFO_VRAM_LOST_COUNTER: u32 = 0x1F;
/// query ras mask of enabled features
pub const AMDGPU_INFO_RAS_ENABLED_FEATURES: u32 = 0x20;
/// query video encode/decode caps
pub const AMDGPU_INFO_VIDEO_CAPS: u32 = 0x21;
/// Query the max number of IBs per gang per submission
pub const AMDGPU_INFO_MAX_IBS: u32 = 0x22;
/// query last page fault info
pub const AMDGPU_INFO_GPUVM_FAULT: u32 = 0x23;
/// query FW object size and alignment
pub const AMDGPU_INFO_UQ_FW_AREAS: u32 = 0x24;

/// AMDGPU_INFO_FW_* firmware types
pub const AMDGPU_INFO_FW_VCE: u32 = 0x1;
pub const AMDGPU_INFO_FW_UVD: u32 = 0x2;
pub const AMDGPU_INFO_FW_GMC: u32 = 0x03;
pub const AMDGPU_INFO_FW_GFX_ME: u32 = 0x04;
pub const AMDGPU_INFO_FW_GFX_PFP: u32 = 0x05;
pub const AMDGPU_INFO_FW_GFX_CE: u32 = 0x06;
pub const AMDGPU_INFO_FW_GFX_RLC: u32 = 0x07;
pub const AMDGPU_INFO_FW_GFX_MEC: u32 = 0x08;
pub const AMDGPU_INFO_FW_SMC: u32 = 0x0a;
pub const AMDGPU_INFO_FW_SDMA: u32 = 0x0b;
pub const AMDGPU_INFO_FW_SOS: u32 = 0x0c;
pub const AMDGPU_INFO_FW_ASD: u32 = 0x0d;
pub const AMDGPU_INFO_FW_VCN: u32 = 0x0e;
pub const AMDGPU_INFO_FW_GFX_RLC_RESTORE_LIST_CNTL: u32 = 0x0f;
pub const AMDGPU_INFO_FW_GFX_RLC_RESTORE_LIST_GPM_MEM: u32 = 0x10;
pub const AMDGPU_INFO_FW_GFX_RLC_RESTORE_LIST_SRM_MEM: u32 = 0x11;
pub const AMDGPU_INFO_FW_DMCU: u32 = 0x12;
pub const AMDGPU_INFO_FW_TA: u32 = 0x13;
pub const AMDGPU_INFO_FW_DMCUB: u32 = 0x14;
pub const AMDGPU_INFO_FW_TOC: u32 = 0x15;
pub const AMDGPU_INFO_FW_CAP: u32 = 0x16;
pub const AMDGPU_INFO_FW_GFX_RLCP: u32 = 0x17;
pub const AMDGPU_INFO_FW_GFX_RLCV: u32 = 0x18;
pub const AMDGPU_INFO_FW_MES_KIQ: u32 = 0x19;
pub const AMDGPU_INFO_FW_MES: u32 = 0x1a;
pub const AMDGPU_INFO_FW_IMU: u32 = 0x1b;
pub const AMDGPU_INFO_FW_VPE: u32 = 0x1c;

/// AMDGPU_INFO_VBIOS_* sub-query IDs
pub const AMDGPU_INFO_VBIOS_SIZE: u32 = 0x1;
pub const AMDGPU_INFO_VBIOS_IMAGE: u32 = 0x2;
pub const AMDGPU_INFO_VBIOS_INFO: u32 = 0x3;

/// AMDGPU_INFO_SENSOR_* sub-query IDs
pub const AMDGPU_INFO_SENSOR_GFX_SCLK: u32 = 0x1;
pub const AMDGPU_INFO_SENSOR_GFX_MCLK: u32 = 0x2;
pub const AMDGPU_INFO_SENSOR_GPU_TEMP: u32 = 0x3;
pub const AMDGPU_INFO_SENSOR_GPU_LOAD: u32 = 0x4;
pub const AMDGPU_INFO_SENSOR_GPU_AVG_POWER: u32 = 0x5;
pub const AMDGPU_INFO_SENSOR_VDDNB: u32 = 0x6;
pub const AMDGPU_INFO_SENSOR_VDDGFX: u32 = 0x7;
pub const AMDGPU_INFO_SENSOR_STABLE_PSTATE_GFX_SCLK: u32 = 0x8;
pub const AMDGPU_INFO_SENSOR_STABLE_PSTATE_GFX_MCLK: u32 = 0x9;
pub const AMDGPU_INFO_SENSOR_PEAK_PSTATE_GFX_SCLK: u32 = 0xa;
pub const AMDGPU_INFO_SENSOR_PEAK_PSTATE_GFX_MCLK: u32 = 0xb;
pub const AMDGPU_INFO_SENSOR_GPU_INPUT_POWER: u32 = 0xc;

/// AMDGPU_INFO_VIDEO_CAPS_* sub-query IDs
pub const AMDGPU_INFO_VIDEO_CAPS_DECODE: u32 = 0;
pub const AMDGPU_INFO_VIDEO_CAPS_ENCODE: u32 = 1;

/// Video codec indices
pub const AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG2: u32 = 0;
pub const AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4: u32 = 1;
pub const AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_VC1: u32 = 2;
pub const AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC: u32 = 3;
pub const AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_HEVC: u32 = 4;
pub const AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_JPEG: u32 = 5;
pub const AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_VP9: u32 = 6;
pub const AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_AV1: u32 = 7;
pub const AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_COUNT: u32 = 8;

/// INFO_MMR query sub-IDs
pub const AMDGPU_INFO_MMR_SE_INDEX_SHIFT: u32 = 0;
pub const AMDGPU_INFO_MMR_SE_INDEX_MASK: u32 = 0xff;
pub const AMDGPU_INFO_MMR_SH_INDEX_SHIFT: u32 = 8;
pub const AMDGPU_INFO_MMR_SH_INDEX_MASK: u32 = 0xff;

/// RAS enabled features
pub const AMDGPU_INFO_RAS_ENABLED_UMC: u32 = 1 << 0;
pub const AMDGPU_INFO_RAS_ENABLED_SDMA: u32 = 1 << 1;
pub const AMDGPU_INFO_RAS_ENABLED_GFX: u32 = 1 << 2;
pub const AMDGPU_INFO_RAS_ENABLED_MMHUB: u32 = 1 << 3;
pub const AMDGPU_INFO_RAS_ENABLED_ATHUB: u32 = 1 << 4;
pub const AMDGPU_INFO_RAS_ENABLED_PCIE: u32 = 1 << 5;
pub const AMDGPU_INFO_RAS_ENABLED_HDP: u32 = 1 << 6;
pub const AMDGPU_INFO_RAS_ENABLED_XGMI: u32 = 1 << 7;
pub const AMDGPU_INFO_RAS_ENABLED_DF: u32 = 1 << 8;
pub const AMDGPU_INFO_RAS_ENABLED_SMN: u32 = 1 << 9;
pub const AMDGPU_INFO_RAS_ENABLED_SEM: u32 = 1 << 10;
pub const AMDGPU_INFO_RAS_ENABLED_MP0: u32 = 1 << 11;
pub const AMDGPU_INFO_RAS_ENABLED_MP1: u32 = 1 << 12;
pub const AMDGPU_INFO_RAS_ENABLED_FUSE: u32 = 1 << 13;

/// VRAM type enumeration
pub const AMDGPU_VRAM_TYPE_UNKNOWN: u32 = 0;
pub const AMDGPU_VRAM_TYPE_GDDR1: u32 = 1;
pub const AMDGPU_VRAM_TYPE_DDR2: u32 = 2;
pub const AMDGPU_VRAM_TYPE_GDDR3: u32 = 3;
pub const AMDGPU_VRAM_TYPE_GDDR4: u32 = 4;
pub const AMDGPU_VRAM_TYPE_GDDR5: u32 = 5;
pub const AMDGPU_VRAM_TYPE_HBM: u32 = 6;
pub const AMDGPU_VRAM_TYPE_DDR3: u32 = 7;
pub const AMDGPU_VRAM_TYPE_DDR4: u32 = 8;
pub const AMDGPU_VRAM_TYPE_GDDR6: u32 = 9;
pub const AMDGPU_VRAM_TYPE_DDR5: u32 = 10;
pub const AMDGPU_VRAM_TYPE_LPDDR4: u32 = 11;
pub const AMDGPU_VRAM_TYPE_LPDDR5: u32 = 12;
pub const AMDGPU_VRAM_TYPE_HBM3E: u32 = 13;
pub const AMDGPU_VRAM_TYPE_HBM4: u32 = 14;

/// GEM list handles flags
pub const AMDGPU_GEM_LIST_HANDLES_FLAG_IS_IMPORT: u32 = 1 << 0;

/// VMHUB types
pub const AMDGPU_VMHUB_TYPE_MASK: u32 = 0xff;
pub const AMDGPU_VMHUB_TYPE_SHIFT: u32 = 0;
pub const AMDGPU_VMHUB_TYPE_GFX: u32 = 0;
pub const AMDGPU_VMHUB_TYPE_MM0: u32 = 1;
pub const AMDGPU_VMHUB_TYPE_MM1: u32 = 2;
pub const AMDGPU_VMHUB_IDX_MASK: u32 = 0xff00;
pub const AMDGPU_VMHUB_IDX_SHIFT: u32 = 8;

/// VCE clock table entries
pub const AMDGPU_VCE_CLOCK_TABLE_ENTRIES: u32 = 6;

/// Supported GPU families
pub const AMDGPU_FAMILY_UNKNOWN: u32 = 0;
pub const AMDGPU_FAMILY_SI: u32 = 110;
pub const AMDGPU_FAMILY_CI: u32 = 120;
pub const AMDGPU_FAMILY_KV: u32 = 125;
pub const AMDGPU_FAMILY_VI: u32 = 130;
pub const AMDGPU_FAMILY_CZ: u32 = 135;
pub const AMDGPU_FAMILY_AI: u32 = 141;
pub const AMDGPU_FAMILY_RV: u32 = 142;
pub const AMDGPU_FAMILY_NV: u32 = 143;
pub const AMDGPU_FAMILY_VGH: u32 = 144;
pub const AMDGPU_FAMILY_GC_11_0_0: u32 = 145;
pub const AMDGPU_FAMILY_YC: u32 = 146;
pub const AMDGPU_FAMILY_GC_11_0_1: u32 = 148;
pub const AMDGPU_FAMILY_GC_10_3_6: u32 = 149;
pub const AMDGPU_FAMILY_GC_10_3_7: u32 = 151;
pub const AMDGPU_FAMILY_GC_11_5_0: u32 = 150;
pub const AMDGPU_FAMILY_GC_11_5_4: u32 = 154;
pub const AMDGPU_FAMILY_GC_12_0_0: u32 = 152;

/// Processor options
pub const AMDGPU_PROC_OPTIONS_OP_KFD_SIGBUS_DELAY: u32 = 0;
pub const AMDGPU_PROC_OPTIONS_KFD_SIGBUS_DELAY_DISABLED: u32 = 0xFFFFFFFF;

/// IDS flags - additional
pub const AMDGPU_IDS_FLAGS_GANG_SUBMIT: u32 = 0x10;
pub const AMDGPU_IDS_FLAGS_MODE_PT: u32 = 0x2;

// ── kernel tests ──

use narf_kernel_test::{kernel_test_in, TestResult};

/// Every mirrored struct's size against the C header's own.
///
/// The expected values are NOT hand-computed. They come from compiling the
/// real `amdgpu_drm.h` on the build host and printing `sizeof` for each
/// struct, so this test compares the mirror against the compiler rather than
/// against someone's arithmetic. The first version of this test was
/// hand-computed and got `drm_amdgpu_bo_list_in` wrong (32 for a 24-byte
/// struct) — the struct was right and the check was not, which is the one
/// failure mode a size assertion exists to prevent.
///
/// 64 of the header's 64 structs are covered. A struct
/// missing here is one the mirror does not define; regenerate rather than
/// relaxing a number.
fn smoke_amdgpu_uapi_struct_sizes() -> TestResult {
    use core::mem;
    // C: drm_amdgpu_bo_list_entry
    if mem::size_of::<DrmAmdgpuBoListEntry>() != 8 {
        return TestResult::Fail("DrmAmdgpuBoListEntry");
    }
    // C: drm_amdgpu_bo_list_in
    if mem::size_of::<DrmAmdgpuBoListIn>() != 24 {
        return TestResult::Fail("DrmAmdgpuBoListIn");
    }
    // C: drm_amdgpu_bo_list_out
    if mem::size_of::<DrmAmdgpuBoListOut>() != 8 {
        return TestResult::Fail("DrmAmdgpuBoListOut");
    }
    // C: drm_amdgpu_cs_chunk
    if mem::size_of::<DrmAmdgpuCsChunk>() != 16 {
        return TestResult::Fail("DrmAmdgpuCsChunk");
    }
    // C: drm_amdgpu_cs_chunk_cp_gfx_shadow
    if mem::size_of::<DrmAmdgpuCsChunkCpGfxShadow>() != 32 {
        return TestResult::Fail("DrmAmdgpuCsChunkCpGfxShadow");
    }
    // C: drm_amdgpu_cs_chunk_data
    if mem::size_of::<DrmAmdgpuCsChunkData>() != 32 {
        return TestResult::Fail("DrmAmdgpuCsChunkData");
    }
    // C: drm_amdgpu_cs_chunk_dep
    if mem::size_of::<DrmAmdgpuCsChunkDep>() != 24 {
        return TestResult::Fail("DrmAmdgpuCsChunkDep");
    }
    // C: drm_amdgpu_cs_chunk_fence
    if mem::size_of::<DrmAmdgpuCsChunkFence>() != 8 {
        return TestResult::Fail("DrmAmdgpuCsChunkFence");
    }
    // C: drm_amdgpu_cs_chunk_ib
    if mem::size_of::<DrmAmdgpuCsChunkIb>() != 32 {
        return TestResult::Fail("DrmAmdgpuCsChunkIb");
    }
    // C: drm_amdgpu_cs_chunk_sem
    if mem::size_of::<DrmAmdgpuCsChunkSem>() != 4 {
        return TestResult::Fail("DrmAmdgpuCsChunkSem");
    }
    // C: drm_amdgpu_cs_chunk_syncobj
    if mem::size_of::<DrmAmdgpuCsChunkSyncobj>() != 16 {
        return TestResult::Fail("DrmAmdgpuCsChunkSyncobj");
    }
    // C: drm_amdgpu_cs_in
    if mem::size_of::<DrmAmdgpuCsIn>() != 24 {
        return TestResult::Fail("DrmAmdgpuCsIn");
    }
    // C: drm_amdgpu_cs_out
    if mem::size_of::<DrmAmdgpuCsOut>() != 8 {
        return TestResult::Fail("DrmAmdgpuCsOut");
    }
    // C: drm_amdgpu_ctx_in
    if mem::size_of::<DrmAmdgpuCtxIn>() != 16 {
        return TestResult::Fail("DrmAmdgpuCtxIn");
    }
    // C: drm_amdgpu_fence
    if mem::size_of::<DrmAmdgpuFence>() != 24 {
        return TestResult::Fail("DrmAmdgpuFence");
    }
    // C: drm_amdgpu_gem_create_in
    if mem::size_of::<DrmAmdgpuGemCreateIn>() != 32 {
        return TestResult::Fail("DrmAmdgpuGemCreateIn");
    }
    // C: drm_amdgpu_gem_create_out
    if mem::size_of::<DrmAmdgpuGemCreateOut>() != 8 {
        return TestResult::Fail("DrmAmdgpuGemCreateOut");
    }
    // C: drm_amdgpu_gem_list_handles
    if mem::size_of::<DrmAmdgpuGemListHandles>() != 16 {
        return TestResult::Fail("DrmAmdgpuGemListHandles");
    }
    // C: drm_amdgpu_gem_list_handles_entry
    if mem::size_of::<DrmAmdgpuGemListHandlesEntry>() != 40 {
        return TestResult::Fail("DrmAmdgpuGemListHandlesEntry");
    }
    // C: drm_amdgpu_gem_metadata
    if mem::size_of::<DrmAmdgpuGemMetadata>() != 288 {
        return TestResult::Fail("DrmAmdgpuGemMetadata");
    }
    // C: drm_amdgpu_gem_mmap_in
    if mem::size_of::<DrmAmdgpuGemMmapIn>() != 8 {
        return TestResult::Fail("DrmAmdgpuGemMmapIn");
    }
    // C: drm_amdgpu_gem_mmap_out
    if mem::size_of::<DrmAmdgpuGemMmapOut>() != 8 {
        return TestResult::Fail("DrmAmdgpuGemMmapOut");
    }
    // C: drm_amdgpu_gem_op
    if mem::size_of::<DrmAmdgpuGemOp>() != 24 {
        return TestResult::Fail("DrmAmdgpuGemOp");
    }
    // C: drm_amdgpu_gem_userptr
    if mem::size_of::<DrmAmdgpuGemUserptr>() != 24 {
        return TestResult::Fail("DrmAmdgpuGemUserptr");
    }
    // C: drm_amdgpu_gem_va
    if mem::size_of::<DrmAmdgpuGemVa>() != 64 {
        return TestResult::Fail("DrmAmdgpuGemVa");
    }
    // C: drm_amdgpu_gem_vm_entry
    if mem::size_of::<DrmAmdgpuGemVmEntry>() != 32 {
        return TestResult::Fail("DrmAmdgpuGemVmEntry");
    }
    // C: drm_amdgpu_gem_wait_idle_in
    if mem::size_of::<DrmAmdgpuGemWaitIdleIn>() != 16 {
        return TestResult::Fail("DrmAmdgpuGemWaitIdleIn");
    }
    // C: drm_amdgpu_gem_wait_idle_out
    if mem::size_of::<DrmAmdgpuGemWaitIdleOut>() != 8 {
        return TestResult::Fail("DrmAmdgpuGemWaitIdleOut");
    }
    // C: drm_amdgpu_heap_info
    if mem::size_of::<DrmAmdgpuHeapInfo>() != 32 {
        return TestResult::Fail("DrmAmdgpuHeapInfo");
    }
    // C: drm_amdgpu_info
    if mem::size_of::<DrmAmdgpuInfo>() != 32 {
        return TestResult::Fail("DrmAmdgpuInfo");
    }
    // C: drm_amdgpu_info_device
    if mem::size_of::<DrmAmdgpuInfoDevice>() != 440 {
        return TestResult::Fail("DrmAmdgpuInfoDevice");
    }
    // C: drm_amdgpu_info_firmware
    if mem::size_of::<DrmAmdgpuInfoFirmware>() != 8 {
        return TestResult::Fail("DrmAmdgpuInfoFirmware");
    }
    // C: drm_amdgpu_info_gds
    if mem::size_of::<DrmAmdgpuInfoGds>() != 32 {
        return TestResult::Fail("DrmAmdgpuInfoGds");
    }
    // C: drm_amdgpu_info_gpuvm_fault
    if mem::size_of::<DrmAmdgpuInfoGpuvmFault>() != 16 {
        return TestResult::Fail("DrmAmdgpuInfoGpuvmFault");
    }
    // C: drm_amdgpu_info_hw_ip
    if mem::size_of::<DrmAmdgpuInfoHwIp>() != 40 {
        return TestResult::Fail("DrmAmdgpuInfoHwIp");
    }
    // C: drm_amdgpu_info_num_handles
    if mem::size_of::<DrmAmdgpuInfoNumHandles>() != 8 {
        return TestResult::Fail("DrmAmdgpuInfoNumHandles");
    }
    // C: drm_amdgpu_info_uq_metadata
    if mem::size_of::<DrmAmdgpuInfoUqMetadata>() != 16 {
        return TestResult::Fail("DrmAmdgpuInfoUqMetadata");
    }
    // C: drm_amdgpu_info_uq_metadata_compute
    if mem::size_of::<DrmAmdgpuInfoUqMetadataCompute>() != 8 {
        return TestResult::Fail("DrmAmdgpuInfoUqMetadataCompute");
    }
    // C: drm_amdgpu_info_uq_metadata_gfx
    if mem::size_of::<DrmAmdgpuInfoUqMetadataGfx>() != 16 {
        return TestResult::Fail("DrmAmdgpuInfoUqMetadataGfx");
    }
    // C: drm_amdgpu_info_uq_metadata_sdma
    if mem::size_of::<DrmAmdgpuInfoUqMetadataSdma>() != 8 {
        return TestResult::Fail("DrmAmdgpuInfoUqMetadataSdma");
    }
    // C: drm_amdgpu_info_vbios
    if mem::size_of::<DrmAmdgpuInfoVbios>() != 200 {
        return TestResult::Fail("DrmAmdgpuInfoVbios");
    }
    // C: drm_amdgpu_info_vce_clock_table
    if mem::size_of::<DrmAmdgpuInfoVceClockTable>() != 104 {
        return TestResult::Fail("DrmAmdgpuInfoVceClockTable");
    }
    // C: drm_amdgpu_info_vce_clock_table_entry
    if mem::size_of::<DrmAmdgpuInfoVceClockTableEntry>() != 16 {
        return TestResult::Fail("DrmAmdgpuInfoVceClockTableEntry");
    }
    // C: drm_amdgpu_info_video_caps
    if mem::size_of::<DrmAmdgpuInfoVideoCaps>() != 192 {
        return TestResult::Fail("DrmAmdgpuInfoVideoCaps");
    }
    // C: drm_amdgpu_info_video_codec_info
    if mem::size_of::<DrmAmdgpuInfoVideoCodecInfo>() != 24 {
        return TestResult::Fail("DrmAmdgpuInfoVideoCodecInfo");
    }
    // C: drm_amdgpu_info_vram_gtt
    if mem::size_of::<DrmAmdgpuInfoVramGtt>() != 24 {
        return TestResult::Fail("DrmAmdgpuInfoVramGtt");
    }
    // C: drm_amdgpu_memory_info
    if mem::size_of::<DrmAmdgpuMemoryInfo>() != 96 {
        return TestResult::Fail("DrmAmdgpuMemoryInfo");
    }
    // C: drm_amdgpu_proc_options
    if mem::size_of::<DrmAmdgpuProcOptions>() != 8 {
        return TestResult::Fail("DrmAmdgpuProcOptions");
    }
    // C: drm_amdgpu_query_fw
    if mem::size_of::<DrmAmdgpuQueryFw>() != 16 {
        return TestResult::Fail("DrmAmdgpuQueryFw");
    }
    // C: drm_amdgpu_sched_in
    if mem::size_of::<DrmAmdgpuSchedIn>() != 16 {
        return TestResult::Fail("DrmAmdgpuSchedIn");
    }
    // C: drm_amdgpu_userq_fence_info
    if mem::size_of::<DrmAmdgpuUserqFenceInfo>() != 16 {
        return TestResult::Fail("DrmAmdgpuUserqFenceInfo");
    }
    // C: drm_amdgpu_userq_in
    if mem::size_of::<DrmAmdgpuUserqIn>() != 72 {
        return TestResult::Fail("DrmAmdgpuUserqIn");
    }
    // C: drm_amdgpu_userq_mqd_compute_gfx11
    if mem::size_of::<DrmAmdgpuUserqMqdComputeGfx11>() != 8 {
        return TestResult::Fail("DrmAmdgpuUserqMqdComputeGfx11");
    }
    // C: drm_amdgpu_userq_mqd_gfx11
    if mem::size_of::<DrmAmdgpuUserqMqdGfx11>() != 16 {
        return TestResult::Fail("DrmAmdgpuUserqMqdGfx11");
    }
    // C: drm_amdgpu_userq_mqd_sdma_gfx11
    if mem::size_of::<DrmAmdgpuUserqMqdSdmaGfx11>() != 8 {
        return TestResult::Fail("DrmAmdgpuUserqMqdSdmaGfx11");
    }
    // C: drm_amdgpu_userq_out
    if mem::size_of::<DrmAmdgpuUserqOut>() != 8 {
        return TestResult::Fail("DrmAmdgpuUserqOut");
    }
    // C: drm_amdgpu_userq_signal
    if mem::size_of::<DrmAmdgpuUserqSignal>() != 48 {
        return TestResult::Fail("DrmAmdgpuUserqSignal");
    }
    // C: drm_amdgpu_userq_wait
    if mem::size_of::<DrmAmdgpuUserqWait>() != 72 {
        return TestResult::Fail("DrmAmdgpuUserqWait");
    }
    // C: drm_amdgpu_vm_in
    if mem::size_of::<DrmAmdgpuVmIn>() != 8 {
        return TestResult::Fail("DrmAmdgpuVmIn");
    }
    // C: drm_amdgpu_vm_out
    if mem::size_of::<DrmAmdgpuVmOut>() != 8 {
        return TestResult::Fail("DrmAmdgpuVmOut");
    }
    // C: drm_amdgpu_wait_cs_in
    if mem::size_of::<DrmAmdgpuWaitCsIn>() != 32 {
        return TestResult::Fail("DrmAmdgpuWaitCsIn");
    }
    // C: drm_amdgpu_wait_cs_out
    if mem::size_of::<DrmAmdgpuWaitCsOut>() != 8 {
        return TestResult::Fail("DrmAmdgpuWaitCsOut");
    }
    // C: drm_amdgpu_wait_fences_in
    if mem::size_of::<DrmAmdgpuWaitFencesIn>() != 24 {
        return TestResult::Fail("DrmAmdgpuWaitFencesIn");
    }
    // C: drm_amdgpu_wait_fences_out
    if mem::size_of::<DrmAmdgpuWaitFencesOut>() != 8 {
        return TestResult::Fail("DrmAmdgpuWaitFencesOut");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu_uapi", smoke_amdgpu_uapi_struct_sizes);
