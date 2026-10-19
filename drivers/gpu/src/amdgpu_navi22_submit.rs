//! Client IB submission on the Navi22 kernel queues under a user VMID.
//!
//! Mirrors the emit order of Linux `amdgpu_ib_schedule` + `amdgpu_vm_flush`
//! for GC 10.3.2 (`gfx_v10_0.c`) and SDMA 5.2 (`sdma_v5_2.c`):
//!
//! 1. pipeline sync (`emit_pipeline_sync`: wait for the ring's last fence)
//!    when `amdgpu_ib_schedule` asks for one — the job flushes its VM, or
//!    its scheduler entity differs from the ring's previous job's
//!    (`amdgpu_vm_need_pipeline_sync`, `need_ctx_switch`; GC 10.3 has no
//!    `has_compute_vm_bug`, and dependencies are waited for before
//!    submission, so no explicit-sync fence reaches the ring);
//!
//!    Then the VM flush (`emit_vm_flush`: write the VMID's page-table base,
//!    then request and await a legacy invalidation on the ring's
//!    invalidation engine; PFP_SYNC_ME on the gfx ring) when the job's
//!    `amdgpu_vmid_grab` grant needs one (`amdgpu_vmid::VmidManager`), and
//!    the PASID mapping (`gmc_v10_0_emit_pasid_mapping`: the GFXHUB
//!    `IH_VMID_<vmid>_LUT` ← the client's PASID, so its faults' IVs name the
//!    client) when the grant asks for it;
//! 2. gfx: CONTEXT_CONTROL (`emit_cntxcntl`, context switch when the client
//!    context changes) and FRAME_CONTROL start;
//! 3. the IBs (`emit_ib_gfx` / `_compute` with `vmid << 24`, SDMA
//!    `OP_INDIRECT` with `VMID`);
//! 4. gfx: FRAME_CONTROL end; then the ring fence (RELEASE_MEM / SDMA FENCE +
//!    TRAP) with a fresh 32-bit sequence.
//!
//! At most `amdgpu_sched_hw_submission` (2) submissions are outstanding per
//! ring: a submission first waits for the fence two behind it, which also
//! bounds ring use to two frames. Each ring has its own GFXHUB invalidation
//! engine, allocated as `amdgpu_gmc_allocate_vm_inv_eng` does for Navi22's
//! ring order (gfx 0.0.0 → 0, comp 1.0.0 → 4, sdma0 → 13, sdma1 → 14); the
//! CPU-side `gmc_v10_0_flush_gpu_tlb` uses engine 17.
//!
//! IB contents are not parsed (Linux has no `parse_cs` for these rings);
//! the VMID's page tables are the boundary. Callers validate that every IB
//! lies in a mapping of the submitting client's VM.
use crate::{
    amdgpu_cp_navi22::{pm4, Error, Hw, Io, Kind, Layout, Queue, FENCE},
    amdgpu_fence_navi22 as fence,
    amdgpu_pm4_defs::{
        packet3, PACKET3_CONTEXT_CONTROL, PACKET3_FRAME_CONTROL, PACKET3_INDIRECT_BUFFER,
        PACKET3_PFP_SYNC_ME, PACKET3_WAIT_REG_MEM, PACKET3_WRITE_DATA,
    },
};
use alloc::vec::Vec;

/// `mmGCVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32` (GC BASE_IDX 0); HI32 is +1,
/// `ctx_addr_distance` 2.
const PTB_LO: u32 = 0x1667; // linux: mmGCVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32@gc
/// `mmGCVM_INVALIDATE_ENG0_REQ` / `_ACK`, `eng_distance` 1.
const INV_REQ: u32 = 0x161f; // linux: mmGCVM_INVALIDATE_ENG0_REQ@gc
const INV_ACK: u32 = 0x1631; // linux: mmGCVM_INVALIDATE_ENG0_ACK@gc
/// `mmIH_VMID_0_LUT` (OSSSYS BASE_IDX 0), one register per VMID: the GFXHUB
/// LUT gmc_v10_0_emit_pasid_mapping writes (`_LUT_MM` is MMHUB's).
// linux-ctx: hdr=oss seg=0
pub(crate) const IH_VMID_0_LUT: u32 = 0x0000; // linux: mmIH_VMID_0_LUT@oss
/// Last OSSSYS register a queue layout must reach: `mmIH_VMID_0_LUT_MM + 15`.
pub(crate) const IH_VMID_LUT_LAST: u32 = 0x001f; // linux: mmIH_VMID_0_LUT_MM@oss + 15
                                                 // linux-ctx: reset
/// `amdgpu_sched_hw_submission` default.
pub const HW_SUBMISSIONS: u32 = 2; // linux: n/a (amdgpu_sched_hw_submission module default)
/// Largest IB count per submission (`AMDGPU_CS_MAX_IBS_PER_SUBMIT`); 16
/// frames of at most 13 dwords stay far inside one ring half.
pub const MAX_IBS: usize = 16; // linux: n/a (NARF bound)
/// Largest single IB, in dwords (`length_dw` is 20 bits in the packet).
pub const MAX_IB_DWORDS: u32 = (1 << 20) - 1; // linux: n/a (20-bit IB length_dw)

/// The ring a submission targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ring {
    Gfx,
    Compute,
    Sdma(u8),
}
impl Ring {
    /// GFXHUB invalidation engine owned by this ring.
    pub const fn inv_engine(self) -> u32 {
        match self {
            Ring::Gfx => 0,
            Ring::Compute => 4,
            Ring::Sdma(i) => 13 + i as u32,
        }
    }
    pub const fn fence_engine(self) -> fence::Engine {
        match self {
            Ring::Gfx => fence::Engine::Gfx,
            Ring::Compute => fence::Engine::Compute,
            Ring::Sdma(0) => fence::Engine::Sdma0,
            Ring::Sdma(1) => fence::Engine::Sdma1,
            Ring::Sdma(2) => fence::Engine::Sdma2,
            Ring::Sdma(_) => fence::Engine::Sdma3,
        }
    }
}

/// One `AMDGPU_CHUNK_ID_IB`, already checked against the client's VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ib {
    pub va: u64,
    pub dwords: u32,
}

/// The VM a submission runs in, as its `amdgpu_vmid_grab` grant decided
/// (`amdgpu_job::vmid`, `vm_pd_addr`, `pasid`, `vm_needs_flush`, and
/// `amdgpu_vm_flush`'s `pasid_mapping_needed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmRef {
    pub vmid: u8,
    /// `amdgpu_gmc_pd_addr(root)`: the value programmed into
    /// `PAGE_TABLE_BASE_ADDR` for this VMID, flags included.
    pub page_table_base: u64,
    /// The client's PASID, written to the VMID's IH LUT entry.
    pub pasid: u16,
    /// Point the VMID's context at `page_table_base` and invalidate it.
    pub flush: bool,
    /// Rewrite the VMID's IH LUT entry with `pasid`.
    pub map_pasid: bool,
}

/// Per-ring scheduling memory: which client context (scheduler entity) ran
/// last (`amdgpu_ring::current_ctx`). 0 is no client context.
#[derive(Clone, Copy, Debug, Default)]
pub struct RingState {
    context: u64,
}
impl RingState {
    pub const fn new() -> Self {
        Self { context: 0 }
    }
}

#[allow(clippy::too_many_arguments, reason = "mirrors gfx_v10_0_wait_reg_mem")]
fn wait_reg_mem(
    eng_sel: u32,
    mem: u32,
    write_wait: u32,
    a0: u32,
    a1: u32,
    r: u32,
    m: u32,
    i: u32,
) -> [u32; 7] {
    [
        packet3(PACKET3_WAIT_REG_MEM, 5),
        (mem << 4) | (write_wait << 6) | 3 | (eng_sel << 8),
        a0,
        a1,
        r,
        m,
        i,
    ]
}
/// `gfx_v10_0_ring_emit_wreg` for a gfx (ENGINE_SEL 1) or compute ring.
fn cp_wreg(gfx: bool, reg: u32, value: u32) -> [u32; 5] {
    let cmd = if gfx { (1 << 30) | (1 << 20) } else { 1 << 20 };
    [packet3(PACKET3_WRITE_DATA, 3), cmd, reg, 0, value]
}
fn sdma_wreg(reg: u32, value: u32) -> [u32; 3] {
    // SDMA_OP_SRBM_WRITE, BYTE_EN 0xf.
    [14 | (0xf << 28), reg, value]
}

/// One submission's ring frame, after the flush decision.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Frame<'a> {
    pub gfx: bool,
    /// GFXHUB invalidation engine of the ring.
    pub engine: u32,
    /// Pipeline sync: (ring fence address, last emitted sequence).
    pub sync: Option<(u64, u32)>,
    pub flush: Option<VmRef>,
    /// IH LUT write: (absolute `IH_VMID_<vmid>_LUT` dword, PASID).
    pub pasid_map: Option<(u32, u16)>,
    pub vmid: u8,
    pub context_switch: bool,
    pub ibs: &'a [Ib],
    pub fence: u64,
    pub seq: u32,
    /// Ring position the frame starts at (SDMA IB alignment).
    pub wptr: u64,
}

/// Encode one CP submission (gfx or compute).
pub(crate) fn encode_cp(l: Layout, f: &Frame<'_>) -> Vec<u32> {
    let (gfx, engine, vmid) = (f.gfx, f.engine, f.vmid);
    let base = l.segment(0);
    let eng_sel = u32::from(gfx);
    let mut w = Vec::new();
    if let Some((address, value)) = f.sync {
        // gfx_v10_0_ring_emit_pipeline_sync
        w.extend(wait_reg_mem(
            eng_sel,
            1,
            0,
            address as u32,
            (address >> 32) as u32,
            value,
            u32::MAX,
            4,
        ));
    }
    if let Some(vm) = f.flush {
        let v = u32::from(vm.vmid);
        // gmc_v10_0_emit_flush_gpu_tlb: no semaphore on GFXHUB.
        w.extend(cp_wreg(
            gfx,
            base + PTB_LO + 2 * v,
            vm.page_table_base as u32,
        ));
        w.extend(cp_wreg(
            gfx,
            base + PTB_LO + 1 + 2 * v,
            (vm.page_table_base >> 32) as u32,
        ));
        // emit_reg_write_reg_wait with cp_fw_write_wait (true on GC 10.3).
        w.extend(wait_reg_mem(
            eng_sel,
            0,
            1,
            base + INV_REQ + engine,
            base + INV_ACK + engine,
            invalidate_request(vm.vmid),
            1 << v,
            0x20,
        ));
        if gfx {
            w.extend([packet3(PACKET3_PFP_SYNC_ME, 0), 0]);
        }
    }
    if let Some((lut, pasid)) = f.pasid_map {
        // gmc_v10_0_emit_pasid_mapping via gfx_v10_0_ring_emit_wreg.
        w.extend(cp_wreg(gfx, lut, u32::from(pasid)));
    }
    if gfx {
        // gfx_v10_0_ring_emit_cntxcntl: load_enable, plus the context-switch
        // loads (global config/uconfig, CS SH, per-context and gfx SH regs).
        let dw2 = 0x8000_0000
            | if f.context_switch {
                0x8001 | 0x0100_0000 | 0x1_0002
            } else {
                0
            };
        w.extend([packet3(PACKET3_CONTEXT_CONTROL, 1), dw2, 0]);
        // gfx_v10_0_ring_emit_frame_cntl(start)
        w.extend([packet3(PACKET3_FRAME_CONTROL, 0), 0]);
    }
    for ib in f.ibs {
        let control = ib.dwords | (u32::from(vmid) << 24) | if gfx { 0 } else { 1 << 23 };
        w.extend([
            packet3(PACKET3_INDIRECT_BUFFER, 2),
            ib.va as u32,
            (ib.va >> 32) as u32,
            control,
        ]);
    }
    if gfx {
        w.extend([packet3(PACKET3_FRAME_CONTROL, 0), 1 << 28]);
    }
    w.extend(pm4::release_mem(f.fence, f.seq));
    w
}

/// `gfxhub_v2_1_get_invalidate_req(vmid, 0)`.
pub(crate) const fn invalidate_request(vmid: u8) -> u32 {
    (1 << vmid) | 0xf8_0000
}

/// Encode an SDMA submission; `f.wptr` places the IB packets.
pub(crate) fn encode_sdma(l: Layout, f: &Frame<'_>) -> Vec<u32> {
    let base = l.segment(0);
    let mut w = Vec::new();
    if let Some((address, value)) = f.sync {
        // sdma_v5_2_ring_emit_pipeline_sync: POLL_REGMEM, mem, equal.
        w.extend([
            8 | (3 << 28) | (1 << 31),
            address as u32 & !3,
            (address >> 32) as u32,
            value,
            u32::MAX,
            (0xfff << 16) | 4,
        ]);
    }
    if let Some(vm) = f.flush {
        let v = u32::from(vm.vmid);
        w.extend(sdma_wreg(base + PTB_LO + 2 * v, vm.page_table_base as u32));
        w.extend(sdma_wreg(
            base + PTB_LO + 1 + 2 * v,
            (vm.page_table_base >> 32) as u32,
        ));
        // POLL_REGMEM / SUBOP_VM_INVALIDATION on this GFX engine, MM 0x1f.
        w.extend([
            8 | (4 << 8) | (f.engine << 16) | (0x1f << 24),
            invalidate_request(vm.vmid),
            u32::MAX,
            (1 << v) | (0x1f << 16),
        ]);
    }
    if let Some((lut, pasid)) = f.pasid_map {
        // gmc_v10_0_emit_pasid_mapping via sdma_v5_2_ring_emit_wreg.
        w.extend(sdma_wreg(lut, u32::from(pasid)));
    }
    for ib in f.ibs {
        // sdma_v5_2_ring_emit_ib: NOP so the 6-dword packet ends on 8.
        let at = f.wptr + w.len() as u64;
        let pad = (2u64.wrapping_sub(at) & 7) as usize;
        w.resize(w.len() + pad, pm4::SDMA_NOP);
        w.extend([
            4 | (u32::from(f.vmid & 0xf) << 16),
            ib.va as u32 & !0x1f,
            (ib.va >> 32) as u32,
            ib.dwords,
            0,
            0,
        ]);
    }
    w.extend(pm4::sdma_fence(f.fence, f.seq));
    w
}

/// Validate a submission before any ring access.
pub fn validate(ring: Ring, vm: VmRef, ibs: &[Ib]) -> Result<(), Error> {
    if matches!(ring, Ring::Sdma(i) if i >= 4) {
        return Err(Error::Invalid);
    }
    if !(1..=15).contains(&vm.vmid) || ibs.is_empty() || ibs.len() > MAX_IBS {
        return Err(Error::Invalid);
    }
    let align = if matches!(ring, Ring::Sdma(_)) { 32 } else { 4 };
    if ibs
        .iter()
        .any(|ib| ib.dwords == 0 || ib.dwords > MAX_IB_DWORDS || ib.va % align != 0)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// Submit to one kernel queue. Returns the fence sequence the ring writes
/// after the last IB. `context` identifies the client context (0 = none).
pub(crate) fn submit<I: Io>(
    hw: &mut Hw<I>,
    queue: &mut Queue,
    state: &mut RingState,
    ring: Ring,
    vm: VmRef,
    context: u64,
    ibs: &[Ib],
) -> Result<u32, Error> {
    validate(ring, vm, ibs)?;
    // HW_SUBMISSIONS outstanding jobs per ring: the caller waits (without
    // holding the device) for `throttle_seq` and retries on Busy.
    if !fence::signaled(completed(hw, queue)?, throttle_seq(queue)) {
        return Err(Error::Busy);
    }
    let fence_address = queue.address(FENCE);
    // amdgpu_ib_schedule: need_ctx_switch || amdgpu_vm_need_pipeline_sync.
    let context_switch = state.context != context;
    let sync = (vm.flush || context_switch).then_some((fence_address, queue.seq));
    let flush = vm.flush.then_some(vm);
    let seq = queue.next_seq();
    let lut = hw.layout.oss(IH_VMID_0_LUT) + u32::from(vm.vmid);
    let frame = Frame {
        gfx: ring == Ring::Gfx,
        engine: ring.inv_engine(),
        sync,
        flush,
        pasid_map: vm.map_pasid.then_some((lut, vm.pasid)),
        vmid: vm.vmid,
        context_switch,
        ibs,
        fence: fence_address,
        seq,
        wptr: queue.wptr,
    };
    let result = hw.access(|io, l| {
        let words = match queue.kind {
            Kind::Cp => encode_cp(l, &frame),
            Kind::Sdma => encode_sdma(l, &frame),
        };
        queue.emit(io, &words)?;
        queue.commit(io, l);
        Ok(())
    });
    if result.is_err() {
        // Nothing was emitted: give the sequence back so the throttle never
        // waits for a fence no ring will write.
        queue.seq = seq.wrapping_sub(1);
    }
    result?;
    state.context = context;
    Ok(seq)
}

/// The fence that must signal before another submission may be queued.
pub(crate) fn throttle_seq(queue: &Queue) -> u32 {
    queue.seq.wrapping_sub(HW_SUBMISSIONS - 1)
}

/// The ring's current fence value (after an HDP read invalidate).
pub(crate) fn completed<I: Io>(hw: &mut Hw<I>, queue: &Queue) -> Result<u32, Error> {
    hw.access(|io, l| crate::amdgpu_cp_navi22::checked(queue.read(io, l, FENCE)))
}

// ── Media rings: VCN 3.0 decode/encode and JPEG 3.0 (append-only) ──────
//
// Client IBs on instance 0's decode ring, its two encode rings and the JPEG
// ring, all on MMHUB (`ring->vm_hub = AMDGPU_MMHUB0(0)`). The frame is what
// `amdgpu_ib_schedule` emits for these rings (vcn_v3_0.c dec/enc ring funcs
// built from the vcn_v2_0.c emitters, jpeg_v3_0.c from jpeg_v2_0.c):
//
// 1. when the VM needs a flush (`amdgpu_vm_flush`): decode/JPEG
//    `insert_start`, then `emit_vm_flush` = `gmc_v10_0_emit_flush_gpu_tlb`
//    on MMHUB — acquire the engine's invalidation semaphore (MMHUB only,
//    `gmc_v10_0_use_invalidate_semaphore`), write the VMID's page-table base
//    LO/HI, write the invalidate request and wait for its ACK bit, release
//    the semaphore — followed by the ring's wait for the PTB LO write;
// 2. decode/JPEG `insert_start`, one `emit_ib` per IB with the job's VMID;
// 3. the job fence (`emit_fence`), then decode/JPEG `insert_end` or the
//    encoder's VCN_ENC_CMD_END.
//
// The flush and PASID-mapping decisions are the job's MMHUB
// `amdgpu_vmid_grab` grant (`VmRef::flush` / `map_pasid`). These rings have
// no `emit_pipeline_sync`, so `amdgpu_vm_flush` returns early unless the VM
// flushes: the `IH_VMID_<vmid>_LUT_MM` write (`gmc_v10_0_emit_pasid_mapping`
// for a non-GFXHUB ring) rides along with a flush only, right after it.
// Omitted, as on the kernel queues: the separate VM fence `amdgpu_vm_flush`
// emits after a flush (the job's own fence stands in for `last_flush`).

/// `mmUVD_GP_SCRATCH8_INTERNAL_OFFSET` (vcn_v3_0.c), the decode reg-wait mask.
pub(crate) const VCN_GP_SCRATCH8: u32 = 0x66; // linux: mmUVD_GP_SCRATCH8_INTERNAL_OFFSET@vcn
pub(crate) const VCN_DEC_WRITE_REG: u32 = 4; // linux: VCN_DEC_CMD_WRITE_REG
pub(crate) const VCN_DEC_REG_WAIT: u32 = 6; // linux: VCN_DEC_CMD_REG_READ_COND_WAIT
pub(crate) const VCN_ENC_REG_WRITE: u32 = 0xb; // linux: VCN_ENC_CMD_REG_WRITE
pub(crate) const VCN_ENC_REG_WAIT: u32 = 0xc; // linux: VCN_ENC_CMD_REG_WAIT

/// jpeg_v2_0.h internal JRBC registers (jpeg_v3_0.c uses the 2.0 emitters).
pub(crate) mod jrbc {
    pub const EXTERNAL_REG: u32 = 0x1bfff; // linux: mmUVD_JRBC_EXTERNAL_REG_INTERNAL_OFFSET
    pub const GPCOM_CMD: u32 = 0x4029; // linux: mmUVD_JPEG_GPCOM_CMD_INTERNAL_OFFSET
    pub const GPCOM_DATA0: u32 = 0x402a; // linux: mmUVD_JPEG_GPCOM_DATA0_INTERNAL_OFFSET
    pub const GPCOM_DATA1: u32 = 0x402b; // linux: mmUVD_JPEG_GPCOM_DATA1_INTERNAL_OFFSET
    /// linux: mmUVD_LMI_JRBC_RB_MEM_WR_64BIT_BAR_LOW_INTERNAL_OFFSET
    pub const RB_MEM_WR_LOW: u32 = 0x40ea;
    /// linux: mmUVD_LMI_JRBC_RB_MEM_WR_64BIT_BAR_HIGH_INTERNAL_OFFSET
    pub const RB_MEM_WR_HIGH: u32 = 0x40eb;
    pub const IB_VMID: u32 = 0x40cf; // linux: mmUVD_LMI_JRBC_IB_VMID_INTERNAL_OFFSET
    pub const JPEG_VMID: u32 = 0x40d1; // linux: mmUVD_LMI_JPEG_VMID_INTERNAL_OFFSET
    /// linux: mmUVD_LMI_JRBC_IB_64BIT_BAR_LOW_INTERNAL_OFFSET
    pub const IB_LOW: u32 = 0x40e8;
    /// linux: mmUVD_LMI_JRBC_IB_64BIT_BAR_HIGH_INTERNAL_OFFSET
    pub const IB_HIGH: u32 = 0x40e9;
    pub const IB_SIZE: u32 = 0x4082; // linux: mmUVD_JRBC_IB_SIZE_INTERNAL_OFFSET
    /// linux: mmUVD_LMI_JRBC_RB_MEM_RD_64BIT_BAR_LOW_INTERNAL_OFFSET
    pub const RB_MEM_RD_LOW: u32 = 0x40ec;
    /// linux: mmUVD_LMI_JRBC_RB_MEM_RD_64BIT_BAR_HIGH_INTERNAL_OFFSET
    pub const RB_MEM_RD_HIGH: u32 = 0x40ed;
    pub const COND_RD_TIMER: u32 = 0x4085; // linux: mmUVD_JRBC_RB_COND_RD_TIMER_INTERNAL_OFFSET
    pub const REF_DATA: u32 = 0x4084; // linux: mmUVD_JRBC_RB_REF_DATA_INTERNAL_OFFSET
    pub const STATUS: u32 = 0x4089; // linux: mmUVD_JRBC_STATUS_INTERNAL_OFFSET
    pub const IH_CTRL: u32 = 0x4149; // linux: mmUVD_JPEG_IH_CTRL_INTERNAL_OFFSET
    pub const DEC_EXTERNAL_REG_WRITE_ADDR: u32 = 0x18000; // linux: JRBC_DEC_EXTERNAL_REG_WRITE_ADDR
    pub const IH_VMID_SHIFT: u32 = 3; // linux: JPEG_IH_CTRL__IH_VMID__SHIFT
    /// `PACKETJ(reg, 0, cond, type)` (soc15d.h).
    pub const fn packet(reg: u32, cond: u32, kind: u32) -> u32 {
        (reg & 0x3ffff) | ((cond & 0xf) << 24) | ((kind & 0xf) << 28) // linux: n/a (PACKETJ, soc15d.h)
    }
}

/// `mmIH_VMID_0_LUT_MM` (OSSSYS BASE_IDX 0): MMHUB's VMID → PASID LUT.
// linux-ctx: hdr=oss seg=0
pub(crate) const IH_VMID_0_LUT_MM: u32 = 0x0010; // linux: mmIH_VMID_0_LUT_MM@oss

/// MMHUB context-0 and invalidation-engine-0 registers (mmhub_2_0_0, base
/// index 0), with `ctx_addr_distance` 2 and `eng_distance` 1.
// linux-ctx: hdr=mmhub seg=0
pub(crate) const MM_PTB_LO: u32 = 0x72b; // linux: mmMMVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32
pub(crate) const MM_PTB_HI: u32 = 0x72c; // linux: mmMMVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_HI32
pub(crate) const MM_INV_SEM: u32 = 0x6d1; // linux: mmMMVM_INVALIDATE_ENG0_SEM
pub(crate) const MM_INV_REQ: u32 = 0x6e3; // linux: mmMMVM_INVALIDATE_ENG0_REQ
pub(crate) const MM_INV_ACK: u32 = 0x6f5; // linux: mmMMVM_INVALIDATE_ENG0_ACK

// linux-ctx: reset
/// `AMDGPU_VMHUB_INV_ENG_BITMAP`: engines 2 and 3 stay with KFD/firmware.
pub(crate) const INV_ENG_BITMAP: u32 = 0x1fff3; // linux: AMDGPU_VMHUB_INV_ENG_BITMAP@amdgpu
/// Largest IB count per media job: `amdgpu_ring_max_ibs(VCN_JPEG)`, and the
/// kernel queues' bound for the other media rings.
pub const MEDIA_MAX_IBS: usize = 16; // linux: n/a (AMDGPU_RING_TYPE_VCN_JPEG -> 16 in amdgpu_ring_max_ibs)

/// A client media ring of VCN instance 0 / JPEG 3.0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaRing {
    Dec,
    /// Encode ring 0 (general purpose) or 1 (low latency).
    Enc(u8),
    Jpeg,
}
impl MediaRing {
    /// Index of the ring among the media rings (dec, enc0, enc1, jpeg).
    pub const fn index(self) -> usize {
        match self {
            MediaRing::Dec => 0,
            MediaRing::Enc(0) => 1,
            MediaRing::Enc(_) => 2,
            MediaRing::Jpeg => 3,
        }
    }
    pub const ALL: [MediaRing; 4] = [
        MediaRing::Dec,
        MediaRing::Enc(0),
        MediaRing::Enc(1),
        MediaRing::Jpeg,
    ];
    /// MMHUB invalidation engine, as `amdgpu_gmc_allocate_vm_inv_eng`
    /// hands them out in ring order on MMHUB: per unharvested VCN instance
    /// its decode ring then both encode rings (`vcn_v3_0_sw_init`), then the
    /// JPEG ring (`jpeg_v3_0_sw_init`), each the lowest free bit of
    /// `AMDGPU_VMHUB_INV_ENG_BITMAP` (no MES/UMSCH on GC 10.3.2).
    pub const fn inv_engine(self, vcn_instances: u8) -> u32 {
        self.inv_engine_for(vcn_instances, 2)
    }
    pub const fn inv_engine_for(self, vcn_instances: u8, encoders: u8) -> u32 {
        let before = match self {
            MediaRing::Dec => 0,
            MediaRing::Enc(0) => 1,
            MediaRing::Enc(_) => 2,
            MediaRing::Jpeg => (1 + encoders as u32) * (vcn_instances & 3).count_ones(),
        };
        let mut free = INV_ENG_BITMAP;
        let mut n = 0;
        while n < before {
            free &= free - 1;
            n += 1;
        }
        free.trailing_zeros()
    }
    pub const fn fence_engine(self) -> fence::Engine {
        match self {
            MediaRing::Jpeg => fence::Engine::Jpeg,
            _ => fence::Engine::Vcn0,
        }
    }
}

/// One media submission's frame, after the flush decision.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MediaFrame<'a> {
    pub ring: MediaRing,
    /// MMHUB segment-0 dword base (`adev->reg_offset[MMHUB_HWIP][0][0]`).
    pub mmhub: u32,
    pub engine: u32,
    pub flush: Option<VmRef>,
    /// IH LUT write after the flush: (absolute `IH_VMID_<vmid>_LUT_MM`
    /// dword, PASID).
    pub pasid_map: Option<(u32, u16)>,
    pub vmid: u8,
    /// IBs as the engine fetches them: client VAs for VCN, the kernel copies
    /// (VMID 0) for JPEG, whose ring has a `parse_cs`.
    pub ibs: &'a [Ib],
    pub fence: u64,
    pub seq: u32,
    /// JPEG: the ring's own MC address (`ring->gpu_addr`, RB_MEM_RD).
    pub ring_base: u64,
}

fn vcn_dec_wreg(w: &mut Vec<u32>, reg: u32, value: u32) {
    use crate::amdgpu_vcn_navi22::cmd::*;
    // vcn_v2_0_dec_ring_emit_wreg
    w.extend([
        packet0(INTERNAL_DATA0),
        reg << 2,
        packet0(INTERNAL_DATA1),
        value,
        packet0(INTERNAL_CMD),
        DEC_KMD | (VCN_DEC_WRITE_REG << 1),
    ]);
}
fn vcn_dec_reg_wait(w: &mut Vec<u32>, reg: u32, value: u32, mask: u32) {
    use crate::amdgpu_vcn_navi22::cmd::*;
    // vcn_v2_0_dec_ring_emit_reg_wait
    w.extend([
        packet0(INTERNAL_DATA0),
        reg << 2,
        packet0(INTERNAL_DATA1),
        value,
        packet0(VCN_GP_SCRATCH8),
        mask,
        packet0(INTERNAL_CMD),
        DEC_KMD | (VCN_DEC_REG_WAIT << 1),
    ]);
}
fn vcn_enc_wreg(w: &mut Vec<u32>, reg: u32, value: u32) {
    w.extend([VCN_ENC_REG_WRITE, reg << 2, value]);
}
fn vcn_enc_reg_wait(w: &mut Vec<u32>, reg: u32, value: u32, mask: u32) {
    w.extend([VCN_ENC_REG_WAIT, reg << 2, mask, value]);
}
/// `jpeg_v2_0_dec_ring_emit_wreg`/`_reg_wait`: registers in the JPEG
/// window (byte offsets 0x10000..=0x105ff) are addressed directly, every
/// other one through JRBC_DEC_EXTERNAL_REG_WRITE_ADDR.
fn jpeg_reg(w: &mut Vec<u32>, reg: u32, kind: u32) {
    use jrbc::*;
    let offset = reg << 2;
    w.push(packet(EXTERNAL_REG, 0, 0));
    if (0x10000..=0x105ff).contains(&offset) {
        w.extend([0, packet(offset >> 2, 0, kind)]);
    } else {
        w.extend([offset, packet(DEC_EXTERNAL_REG_WRITE_ADDR, 0, kind)]);
    }
}
fn jpeg_wreg(w: &mut Vec<u32>, reg: u32, value: u32) {
    jpeg_reg(w, reg, 0);
    w.push(value);
}
fn jpeg_reg_wait(w: &mut Vec<u32>, reg: u32, value: u32, mask: u32) {
    use jrbc::*;
    // linux: n/a (literal 0x01400200 in jpeg_v2_0.c:jpeg_v2_0_dec_ring_emit_reg_wait)
    w.extend([packet(COND_RD_TIMER, 0, 0), 0x0140_0200]);
    w.extend([packet(REF_DATA, 0, 0), value]);
    jpeg_reg(w, reg, 3);
    w.push(mask);
}
/// decode/JPEG `insert_start`.
fn media_start(ring: MediaRing, w: &mut Vec<u32>) {
    match ring {
        MediaRing::Dec => w.extend(crate::amdgpu_vcn_navi22::dec_start()),
        // jpeg_v2_0_dec_ring_insert_start
        // linux: n/a (literals 0x68e04, 0x80010000 in jpeg_v2_0.c:jpeg_v2_0_dec_ring_insert_start)
        MediaRing::Jpeg => w.extend([
            jrbc::packet(jrbc::EXTERNAL_REG, 0, 0),
            0x68e04,
            jrbc::packet(jrbc::DEC_EXTERNAL_REG_WRITE_ADDR, 0, 0),
            0x8001_0000,
        ]),
        MediaRing::Enc(_) => {}
    }
}

/// Encode one media submission (see the section comment for the order).
pub(crate) fn encode_media(f: &MediaFrame<'_>) -> Vec<u32> {
    let mut w = Vec::new();
    type Wreg = fn(&mut Vec<u32>, u32, u32);
    type Wait = fn(&mut Vec<u32>, u32, u32, u32);
    let (wreg, wait): (Wreg, Wait) = match f.ring {
        MediaRing::Dec => (vcn_dec_wreg, vcn_dec_reg_wait),
        MediaRing::Enc(_) => (vcn_enc_wreg, vcn_enc_reg_wait),
        MediaRing::Jpeg => (jpeg_wreg, jpeg_reg_wait),
    };
    if let Some(vm) = f.flush {
        let v = u32::from(vm.vmid);
        let reg = |offset: u32| f.mmhub + offset;
        let (lo, hi) = (vm.page_table_base as u32, (vm.page_table_base >> 32) as u32);
        media_start(f.ring, &mut w);
        // gmc_v10_0_emit_flush_gpu_tlb: semaphore acquire (reads 1).
        wait(&mut w, reg(MM_INV_SEM) + f.engine, 1, 1);
        wreg(&mut w, reg(MM_PTB_LO) + 2 * v, lo);
        wreg(&mut w, reg(MM_PTB_HI) + 2 * v, hi);
        // amdgpu_ring_emit_reg_write_reg_wait_helper
        wreg(
            &mut w,
            reg(MM_INV_REQ) + f.engine,
            invalidate_request(vm.vmid),
        );
        wait(&mut w, reg(MM_INV_ACK) + f.engine, 1 << v, 1 << v);
        // semaphore release
        wreg(&mut w, reg(MM_INV_SEM) + f.engine, 0);
        // the ring's own emit_vm_flush tail: wait for the PTB write
        wait(&mut w, reg(MM_PTB_LO) + 2 * v, lo, u32::MAX);
        if let Some((lut, pasid)) = f.pasid_map {
            // gmc_v10_0_emit_pasid_mapping through the ring's emit_wreg.
            wreg(&mut w, lut, u32::from(pasid));
        }
    }
    media_start(f.ring, &mut w);
    let vmid = u32::from(f.vmid);
    for ib in f.ibs {
        let (low, high) = (ib.va as u32, (ib.va >> 32) as u32);
        match f.ring {
            MediaRing::Dec => {
                use crate::amdgpu_vcn_navi22::cmd::*;
                // vcn_v2_0_dec_ring_emit_ib
                w.extend([
                    packet0(INTERNAL_IB_VMID),
                    vmid,
                    packet0(INTERNAL_IB_BAR_LOW),
                    low,
                    packet0(INTERNAL_IB_BAR_HIGH),
                    high,
                    packet0(INTERNAL_IB_SIZE),
                    ib.dwords,
                ]);
            }
            // vcn_v2_0_enc_ring_emit_ib
            MediaRing::Enc(_) => w.extend([
                crate::amdgpu_vcn_navi22::cmd::ENC_IB,
                vmid,
                low,
                high,
                ib.dwords,
            ]),
            MediaRing::Jpeg => {
                use jrbc::*;
                let triple = vmid | (vmid << 4) | (vmid << 8);
                // jpeg_v2_0_dec_ring_emit_ib with parse_cs: the IB itself is
                // the kernel's validated copy (IB_VMID 0); data uses the VMID.
                // linux: n/a (literals 0x01400200 / 0x2 in jpeg_v2_0.c:jpeg_v2_0_dec_ring_emit_ib)
                w.extend([
                    packet(IH_CTRL, 0, 0),
                    vmid << IH_VMID_SHIFT,
                    packet(IB_VMID, 0, 0),
                    0,
                    packet(JPEG_VMID, 0, 0),
                    triple,
                    packet(IB_LOW, 0, 0),
                    low,
                    packet(IB_HIGH, 0, 0),
                    high,
                    packet(IB_SIZE, 0, 0),
                    ib.dwords,
                    packet(RB_MEM_RD_LOW, 0, 0),
                    f.ring_base as u32,
                    packet(RB_MEM_RD_HIGH, 0, 0),
                    (f.ring_base >> 32) as u32,
                    packet(0, 0, 2),
                    0,
                    packet(COND_RD_TIMER, 0, 0),
                    0x0140_0200,
                    packet(REF_DATA, 0, 0),
                    0x2,
                    packet(STATUS, 3, 3),
                    0x2,
                ]);
            }
        }
    }
    match f.ring {
        MediaRing::Dec => {
            w.extend(crate::amdgpu_vcn_navi22::dec_fence(f.fence, f.seq));
            w.extend(crate::amdgpu_vcn_navi22::dec_end());
        }
        MediaRing::Enc(_) => {
            use crate::amdgpu_vcn_navi22::cmd::*;
            // vcn_v2_0_enc_ring_emit_fence, vcn_v2_0_enc_ring_insert_end
            w.extend([
                ENC_FENCE,
                f.fence as u32,
                (f.fence >> 32) as u32,
                f.seq,
                ENC_TRAP,
                ENC_END,
            ]);
        }
        MediaRing::Jpeg => {
            use jrbc::*;
            // jpeg_v2_0_dec_ring_emit_fence, then jpeg_v2_0_dec_ring_insert_end
            // linux: n/a (literals 0x8, 0x3fbc, 0x1, 0x68e04, 0x10000 in jpeg_v2_0.c fence/insert_end)
            w.extend([
                packet(GPCOM_DATA0, 0, 0),
                f.seq,
                packet(GPCOM_DATA1, 0, 0),
                f.seq,
                packet(RB_MEM_WR_LOW, 0, 0),
                f.fence as u32,
                packet(RB_MEM_WR_HIGH, 0, 0),
                (f.fence >> 32) as u32,
                packet(GPCOM_CMD, 0, 0),
                0x8,
                packet(GPCOM_CMD, 0, 4),
                0,
                packet(EXTERNAL_REG, 0, 0),
                0x3fbc,
                packet(DEC_EXTERNAL_REG_WRITE_ADDR, 0, 0),
                0x1,
                packet(0, 0, 7),
                0,
                packet(EXTERNAL_REG, 0, 0),
                0x68e04,
                packet(DEC_EXTERNAL_REG_WRITE_ADDR, 0, 0),
                0x0001_0000,
            ]);
        }
    }
    w
}

/// Validate a media submission before any ring access: a user VMID, 1..=16
/// IBs, each non-empty, dword-aligned and within the 20-bit size field.
pub fn validate_media(vm: VmRef, ibs: &[Ib]) -> Result<(), Error> {
    if !(1..=15).contains(&vm.vmid) || ibs.is_empty() || ibs.len() > MEDIA_MAX_IBS {
        return Err(Error::Invalid);
    }
    if ibs
        .iter()
        .any(|ib| ib.dwords == 0 || ib.dwords > MAX_IB_DWORDS || ib.va % 4 != 0)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// The grant a media ring honours: `amdgpu_vm_flush` on a ring without
/// `emit_pipeline_sync` emits (and records) the PASID mapping only together
/// with a VM flush.
pub fn media_grant(grant: crate::amdgpu_vmid::Grant) -> crate::amdgpu_vmid::Grant {
    crate::amdgpu_vmid::Grant {
        map_pasid: grant.map_pasid && grant.needs_flush,
        ..grant
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_submit_tests.rs"]
mod tests;
