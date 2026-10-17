//! Client IB submission on the Navi22 kernel queues under a user VMID.
//!
//! Mirrors the emit order of Linux `amdgpu_ib_schedule` + `amdgpu_vm_flush`
//! for GC 10.3.2 (`gfx_v10_0.c`) and SDMA 5.2 (`sdma_v5_2.c`):
//!
//! 1. pipeline sync (`emit_pipeline_sync`: wait for the ring's last fence)
//!    and VM flush (`emit_vm_flush`: write the VMID's page-table base, then
//!    request and await a legacy invalidation on the ring's invalidation
//!    engine; PFP_SYNC_ME on the gfx ring) — only the first time a VM
//!    (VMID + generation) runs on that ring, as `amdgpu_vmid_grab` sets
//!    `vm_needs_flush` only for a new or changed VMID owner;
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
const PTB_LO: u32 = 0x1667;
/// `mmGCVM_INVALIDATE_ENG0_REQ` / `_ACK`, `eng_distance` 1.
const INV_REQ: u32 = 0x161f;
const INV_ACK: u32 = 0x1631;
/// `amdgpu_sched_hw_submission` default.
pub const HW_SUBMISSIONS: u32 = 2;
/// Largest IB count per submission (`AMDGPU_CS_MAX_IBS_PER_SUBMIT` is 16;
/// two frames of the 2048-dword ring bound us to fewer).
pub const MAX_IBS: usize = 4;
/// Largest single IB, in dwords (`length_dw` is 20 bits in the packet).
pub const MAX_IB_DWORDS: u32 = (1 << 20) - 1;

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
            Ring::Sdma(0) => 13,
            Ring::Sdma(_) => 14,
        }
    }
    pub const fn fence_engine(self) -> fence::Engine {
        match self {
            Ring::Gfx => fence::Engine::Gfx,
            Ring::Compute => fence::Engine::Compute,
            Ring::Sdma(0) => fence::Engine::Sdma0,
            Ring::Sdma(_) => fence::Engine::Sdma1,
        }
    }
}

/// One `AMDGPU_CHUNK_ID_IB`, already checked against the client's VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ib {
    pub va: u64,
    pub dwords: u32,
}

/// The VM a submission runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmRef {
    pub vmid: u8,
    pub generation: u64,
    /// `amdgpu_gmc_pd_addr(root)`: the value programmed into
    /// `PAGE_TABLE_BASE_ADDR` for this VMID, flags included.
    pub page_table_base: u64,
}

/// Per-ring scheduling memory: which VM generations this ring has flushed
/// and which client context ran last.
#[derive(Clone, Copy, Debug, Default)]
pub struct RingState {
    flushed: [u64; 16],
    context: u64,
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
    let slot = usize::from(vm.vmid);
    let needs_flush = state.flushed[slot] != vm.generation;
    let fence_address = queue.address(FENCE);
    let sync = needs_flush.then_some((fence_address, queue.seq));
    let flush = needs_flush.then_some(vm);
    let context_switch = state.context != context;
    let seq = queue.next_seq();
    let frame = Frame {
        gfx: ring == Ring::Gfx,
        engine: ring.inv_engine(),
        sync,
        flush,
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
    state.flushed[slot] = vm.generation;
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

/// Forget every flush this ring performed for `vmid` (its VM was destroyed).
pub fn forget(state: &mut RingState, vmid: u8) {
    if let Some(slot) = state.flushed.get_mut(usize::from(vmid)) {
        *slot = 0;
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_submit_tests.rs"]
mod tests;
