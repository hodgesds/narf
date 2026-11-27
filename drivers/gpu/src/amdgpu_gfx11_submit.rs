//! GFX11 (RDNA3 Navi31/32/33) command submission: the
//! [`amdgpu_cs::Submitter`](crate::amdgpu_cs::Submitter) over the graphics
//! and compute rings, its fences, and its context switch.
//!
//! Mirrors the emit order of Linux `amdgpu_ib_schedule` +
//! `amdgpu_vm_flush` for GC 11.0 (`gfx_v11_0.c`, `gmc_v11_0.c`,
//! `amdgpu_ib.c`):
//!
//! 1. pipeline sync (`WAIT_REG_MEM` on the ring fence) when the job flushes
//!    its VM or its scheduler entity differs from the ring's previous job's
//!    (`amdgpu_vm_need_pipeline_sync`, `need_ctx_switch`);
//! 2. the VM flush (`gmc_v11_0_emit_flush_gpu_tlb`: write the VMID's
//!    page-table base, then request and await a legacy invalidation on the
//!    ring's invalidation engine; `PFP_SYNC_ME` on the gfx ring) when the
//!    job's `amdgpu_vmid_grab` grant needs one, and the PASID mapping
//!    (`gmc_v11_0_emit_pasid_mapping`: the GFXHUB `IH_VMID_<vmid>_LUT` ← the
//!    client's PASID) when the grant asks for it — followed by a dedicated
//!    VM fence (`RELEASE_MEM`) before the client IBs, so VMID reuse waits
//!    on that writeback while active jobs retain their own final fences;
//! 3. ring-ordered HDP flush; gfx: `CONTEXT_CONTROL` (context switch when
//!    the client context changes) and `FRAME_CONTROL` start;
//! 4. the IBs (`INDIRECT_BUFFER` with `vmid << 24`, compute adding
//!    `INDIRECT_BUFFER_VALID`);
//! 5. gfx: `FRAME_CONTROL` end; HDP read-cache invalidation; then the ring
//!    fence (`RELEASE_MEM` with a fresh 32-bit sequence); gfx:
//!    `SWITCH_BUFFER` after the fence.
//!
//! At most [`HW_SUBMISSIONS`] (2) submissions are outstanding per ring, as
//! on Navi22: a submission first waits for the fence two behind it.
//!
//! ## What is per-die, what is a parameter, what is unresolved
//!
//! The GFXHUB registers a VM flush writes differ by die: Navi31 and Navi33
//! take the `gfxhub_v3_0` table (GC 11.0.0 offsets), Navi32 the
//! `gfxhub_v3_0_3` table (GC 11.0.3 offsets, +0x10) —
//! `gmc_v11_0_set_gfxhub_funcs` selects by discovered GC version, and only
//! 11.0.3 takes the v3_0_3 table. [`GfxHubRegs`] carries the table; the
//! invalidate-request value is the same on both
//! (`gfxhub_v3_0_get_invalidate_req` / `gfxhub_v3_0_3_get_invalidate_req`
//! with `flush_type` 0).
//!
//! The HDP flush request/done registers and CP0/CP2 masks are
//! NBIO-version-dependent (`nbio_v7_0`/`v7_4`/`v7_9`/`v7_11` all differ),
//! and Navi31's NBIO version comes from the discovery binary, not from any
//! static table in the ref tree — lane 3 already concluded no NBIO version
//! is groundable from source for Navi3x. The HDP read-cache invalidate
//! register likewise depends on the discovered HDP version (0xd1 on HDP
//! 4.0/5.0; HDP 6.0 has no invalidate callback at all). Both therefore
//! arrive in [`Gfx11Layout`] from the platform lane, which reads them from
//! discovery; nothing here hardcodes Navi22's NBIO 2.3 values.
//!
//! The VM invalidation engine per ring comes from
//! `amdgpu_gmc_allocate_vm_inv_eng`'s ring order, which is bring-up
//! dependent (lowest free bit of `AMDGPU_VMHUB_INV_ENG_BITMAP`, engine 5
//! reserved once MES is enabled — and MES-KIQ *is* enabled on all three
//! RDNA3 dies, per lane 6's `uses_mes_kiq`). It is a constructor input
//! ([`SubmitterConfig::inv_engines`]), not a hardcoded table: Navi22's
//! 0/4/13/14 mapping is Navi22's ring order, not Navi31's.
//!
//! ## Scope
//!
//! Graphics and compute rings only. SDMA submissions are lane 7's surface:
//! the SDMA 6.0 frame encoder (`sdma_v6_0_ring_emit_*`) belongs to the
//! SDMA owner, so [`ring_for`](crate::amdgpu_cs::Submitter::ring_for)
//! refuses DMA entities until that lane wires its submit path — a gfx or
//! compute submission no longer reports ENODEV once this submitter is
//! registered, a DMA one still does. VCN/JPEG likewise stay with lane 10.
//!
//! The submitter performs no MMIO itself. The platform lane supplies the
//! rings through [`RingBackend`]; until the CP rings (lane 6) and PSP
//! dispatch exist, no backend exists and nothing registers — the submitter
//! is the validated, fixture-tested description of what the platform lane
//! will drive. `install_preamble` is the one place the clear-state table
//! meets a ring: it emits [`build_preamble`](crate::amdgpu_clearstate::build_preamble)
//! on the gfx ring, and the second ring's `CLEAR_STATE` when the card runs
//! two gfx rings (`GFX11_NUM_GFX_RINGS` is 2 unless RS64 or `disable_kq`).

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu_clearstate;
use crate::amdgpu_ctx::Health;
use crate::amdgpu_discovery::GcInfo;
use crate::amdgpu_fence_navi22::signaled;
use crate::amdgpu_pm4_defs as pm4;
use crate::amdgpu_uapi as uapi;
use crate::amdgpu_vm::{Geometry, VmState};
use crate::amdgpu_vmid::{GrabRequest, Grant, VmidManager};

/// Errors the encoder and the ring backend report; mapped to [`FsError`]
/// at the [`Submitter`](crate::amdgpu_cs::Submitter) boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Busy,
    NoDevice,
}
impl Error {
    fn to_fs(self) -> FsError {
        match self {
            Error::Invalid => FsError::InvalidData,
            Error::Busy => FsError::Busy,
            Error::NoDevice => FsError::NoDevice,
        }
    }
}

// ── Per-die parameters ─────────────────────────────────────────────

/// An RDNA3 die, by its discovered GC version — the corrected pairing
/// (lane 1, PR #2459): Navi31 is GC 11.0.0, Navi32 is GC 11.0.3, Navi33 is
/// GC 11.0.2. The programme record originally had Navi32/33 swapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gfx11Die {
    /// GC 11.0.0: RX 7900 XTX/XT/GRE, Radeon Pro W7900/W7800.
    Navi31,
    /// GC 11.0.3: RX 7800 XT / 7700 XT, Radeon Pro W7700/V710.
    Navi32,
    /// GC 11.0.2: RX 7600/7600 XT, Radeon Pro W7500.
    Navi33,
}
impl Gfx11Die {
    /// The die's discovered GC version.
    pub const fn gc_version(self) -> (u8, u8, u8) {
        match self {
            Gfx11Die::Navi31 => (11, 0, 0),
            Gfx11Die::Navi32 => (11, 0, 3),
            Gfx11Die::Navi33 => (11, 0, 2),
        }
    }
    /// The die for a discovered GC version, or `None` — Phoenix GC 11.0.1
    /// is explicitly not an RDNA3 die.
    pub const fn from_gc(major: u8, minor: u8, revision: u8) -> Option<Self> {
        match (major, minor, revision) {
            (11, 0, 0) => Some(Gfx11Die::Navi31),
            (11, 0, 3) => Some(Gfx11Die::Navi32),
            (11, 0, 2) => Some(Gfx11Die::Navi33),
            _ => None,
        }
    }
}

/// The GFXHUB registers a VM flush writes, as the die's gfxhub init sets
/// them (`hub->ctx0_ptb_addr_lo32`, `vm_inv_eng0_req/ack`): GC BASE_IDX 0
/// register dwords. `ctx_addr_distance` is 2 and `eng_distance` is 1 on
/// both tables, so they are not carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GfxHubRegs {
    /// `regGCVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32`.
    pub ptb_lo: u32,
    /// `regGCVM_INVALIDATE_ENG0_REQ`.
    pub inv_req: u32,
    /// `regGCVM_INVALIDATE_ENG0_ACK`.
    pub inv_ack: u32,
}

/// The die's GFXHUB register table.
///
/// `gmc_v11_0_set_gfxhub_funcs`: only GC 11.0.3 takes
/// `gfxhub_v3_0_3_funcs`; every other GFX11 die takes `gfxhub_v3_0_funcs`
/// — so Navi33 (11.0.2) shares Navi31's table, and the 11.0.3 table is
/// Navi32's alone.
pub const fn gfxhub_regs(die: Gfx11Die) -> GfxHubRegs {
    match die {
        Gfx11Die::Navi31 | Gfx11Die::Navi33 => GfxHubRegs {
            // linux: gc_11_0_0_offset.h
            ptb_lo: 0x16f3,
            inv_req: 0x16ab,
            inv_ack: 0x16bd,
        },
        Gfx11Die::Navi32 => GfxHubRegs {
            // linux: gc_11_0_3_offset.h
            ptb_lo: 0x1703,
            inv_req: 0x16bb,
            inv_ack: 0x16cd,
        },
    }
}

/// `gfxhub_v3_0_get_invalidate_req` / `gfxhub_v3_0_3_get_invalidate_req`
/// with `flush_type` 0: legacy per-VMID invalidate, L2 PTEs + PDE0/1/2 +
/// L1 PTEs. The field shifts (`gc_11_0_0_sh_mask.h`,
/// `gc_11_0_3_sh_mask.h`) agree: `PER_VMID_INVALIDATE_REQ` at 0,
/// `INVALIDATE_L2_PTES` at 0x13, PDE0 at 0x14, PDE1 at 0x15, PDE2 at 0x16,
/// `INVALIDATE_L1_PTES` at 0x17 — so the value is `(1 << vmid) |
/// 0xF80000` on both dies.
pub const fn invalidate_request(vmid: u8) -> u32 {
    (1u32 << vmid) | 0x00f8_0000
}

/// `mmIH_VMID_0_LUT` (OSSSYS BASE_IDX 0): the GFXHUB VMID → PASID LUT
/// `gmc_v11_0_emit_pasid_mapping` writes, one dword per VMID. The value is
/// 0x0000 in every OSSSYS header from 4.0 through 7.1.0, so it does not
/// depend on which OSSSYS version the discovery blob reports.
pub const IH_VMID_0_LUT: u32 = 0x0000;

/// `gfx_v11_0_constants_init` sets `adev->gfx.config
/// .pa_sc_tile_steering_override = 0`: the clear-state preamble carries a
/// zero tile-steering override on GFX11, not a per-ASIC value.
pub const TILE_STEERING_OVERRIDE: u32 = 0;

/// `regGDS_COMPUTE_MAX_WAVE_ID` (`gc_11_0_0_offset.h`, BASE_IDX 0).
pub const GDS_COMPUTE_MAX_WAVE_ID: u32 = 0x20e8;
/// `GDS_COMPUTE_MAX_WAVE_ID__MAX_WAVE_ID_MASK` (`gc_11_0_0_sh_mask.h`).
pub const GDS_MAX_WAVE_ID_MASK: u32 = 0xfff;

/// `gfx_v11_0_set_gds_init`: `total_cu * 32 - 1`, where `total_cu` is
/// `max_cu_per_sh * max_sh_per_se * max_shader_engines`. `None` when the
/// discovery geometry is absent or the limit does not fit the mask — a
/// compute submission asking to reset the wave-id limit is then refused
/// rather than programmed with a truncated value.
pub fn gds_max_wave_id(gc: Option<GcInfo>) -> Option<u32> {
    gc.and_then(|gc| {
        gc.num_se
            .checked_mul(gc.num_sa_per_se)?
            .checked_mul(gc.num_cu_per_sa)?
            .checked_mul(32)?
            .checked_sub(1)
    })
    .filter(|&id| id <= GDS_MAX_WAVE_ID_MASK)
}

// ── Layout ─────────────────────────────────────────────────────────

/// The HDP flush a ring's `emit_hdp_flush` performs
/// (`gfx_v11_0_ring_emit_hdp_flush` + `amdgpu_gfx_get_hdp_flush_mask`):
/// absolute NBIO register dwords and the ring's flush mask, all
/// NBIO-version-dependent and therefore supplied by the platform lane
/// from discovery — never Navi22's NBIO 2.3 literals. The masks are the
/// `ref_and_mask_cp0`/`cp2` values shifted by the ring's pipe; both owned
/// queues are pipe 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HdpFlush {
    /// NBIO HDP flush request register dword.
    pub req: u32,
    /// NBIO HDP flush done register dword.
    pub done: u32,
    /// GFX ring mask (`ref_and_mask_cp0 << pipe`).
    pub gfx_mask: u32,
    /// Compute ring mask (`ref_and_mask_cp2 << pipe`).
    pub compute_mask: u32,
}

/// The register windows a GFX11 frame is encoded against. GC bases are the
/// `AmdGpu::gc_base()` / `gc_base_1()` dword bases (BASE_IDX 0 / 1);
/// `oss_base` is the OSSSYS BASE_IDX 0 dword base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gfx11Layout {
    /// GC BASE_IDX 0 dword base.
    pub gc_base: u32,
    /// GC BASE_IDX 1 dword base (also the clear-state tile-steering base).
    pub gc_base_1: u32,
    /// OSSSYS BASE_IDX 0 dword base.
    pub oss_base: u32,
    /// The HDP flush for both rings.
    pub hdp_flush: HdpFlush,
    /// HDP read-cache invalidate register dword, if the discovered HDP has
    /// one (`hdp_v5_0`: HDP base + 0xd1; `hdp_v6_0` has no invalidate
    /// callback, so `None` skips the step exactly as Linux does).
    pub hdp_read_cache_invalidate: Option<u32>,
}

// ── Rings, IBs, frames ─────────────────────────────────────────────

/// A submittable ring. `GfxSecondary` is the second gfx ring, which
/// carries only the preamble's `CLEAR_STATE` copy
/// (`gfx_v11_0_cp_gfx_start`'s tail) — no fence, no submissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ring {
    Gfx,
    Compute,
    GfxSecondary,
}

/// Ring ids in ticket space: the low four bits of a ticket's ring index.
pub const RING_IDS: usize = 2;

/// `amdgpu_ctx_get_entity` for this ASIC: gfx ring 0, compute rings 0–3
/// on the one kernel compute queue (Navi22 precedent — Linux runs several
/// compute queues, NARF runs one). DMA/VCN/JPEG entities are refused here;
/// their submit paths belong to lanes 7 and 10.
pub fn ring_id(ip_type: u32, ip_instance: u32, ring: u32) -> Option<usize> {
    match (ip_type, ip_instance, ring) {
        (uapi::AMDGPU_HW_IP_GFX, 0, 0) => Some(0),
        (uapi::AMDGPU_HW_IP_COMPUTE, 0, 0..=3) => Some(1),
        _ => None,
    }
}

/// `amdgpu_sched_hw_submission` default: at most two submissions
/// outstanding per ring.
pub const HW_SUBMISSIONS: u32 = 2;
/// Largest IB count per submission: the NARF bound Navi22 uses (Linux's
/// `amdgpu_ring_max_ibs` allows 192 on GFX / 125 on compute; 16 frames
/// stay far inside one ring half).
pub const MAX_IBS: usize = 16;
/// Largest single IB, in dwords (`length_dw` is 20 bits in the packet).
pub const MAX_IB_DWORDS: u32 = (1 << 20) - 1;

/// One `AMDGPU_CHUNK_ID_IB`, already checked against the client's VM.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ib {
    pub va: u64,
    pub dwords: u32,
    pub flags: u32,
}
impl Ib {
    /// The address an IB packet carries: [`Ib::va`] (hole stripped, for VM
    /// lookups) sign-extended back, as Linux emits `ib->gpu_addr`.
    pub fn gpu_addr(&self) -> u64 {
        crate::amdgpu_vm::sign_extend(self.va)
    }
}
impl From<&crate::amdgpu_cs::Ib> for Ib {
    fn from(ib: &crate::amdgpu_cs::Ib) -> Self {
        Self {
            va: ib.va_start,
            dwords: ib.length_dw,
            flags: ib.flags,
        }
    }
}

/// The VM a submission runs in, as its `amdgpu_vmid_grab` grant decided.
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
/// last (`amdgpu_ring::current_ctx`), the GDS wave-id limit the discovery
/// geometry allows, and the last fence sequence emitted. 0 is no client
/// context.
#[derive(Clone, Copy, Debug, Default)]
pub struct RingState {
    context: u64,
    gds_max_wave_id: Option<u32>,
    seq: u32,
}
impl RingState {
    pub const fn new() -> Self {
        Self {
            context: 0,
            gds_max_wave_id: None,
            seq: 0,
        }
    }
    /// `gfx_v11_0_set_gds_init` from the discovery geometry.
    pub fn configure_gds(&mut self, gc: Option<GcInfo>) {
        self.gds_max_wave_id = gds_max_wave_id(gc);
    }
    /// The context that ran last on this ring.
    pub fn context(&self) -> u64 {
        self.context
    }
    /// The last fence sequence emitted on this ring.
    pub fn seq(&self) -> u32 {
        self.seq
    }
}

/// `gfx_v11_0_wait_reg_mem`: `WAIT_REG_MEM`, function equal, poll
/// interval `inv`. Identical field layout to Navi22's — the packet format
/// did not change between GC 10.3 and 11.0.
#[allow(clippy::too_many_arguments, reason = "mirrors gfx_v11_0_wait_reg_mem")]
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
        pm4::packet3(pm4::PACKET3_WAIT_REG_MEM, 5),
        (mem << 4) | (write_wait << 6) | 3 | (eng_sel << 8),
        a0,
        a1,
        r,
        m,
        i,
    ]
}
/// `gfx_v11_0_ring_emit_wreg` for a gfx (`ENGINE_SEL` 1) or compute ring:
/// `WRITE_DATA`, `WR_CONFIRM`, register dword, value.
fn cp_wreg(gfx: bool, reg: u32, value: u32) -> [u32; 5] {
    let cmd = if gfx { (1 << 30) | (1 << 20) } else { 1 << 20 };
    [pm4::packet3(pm4::PACKET3_WRITE_DATA, 3), cmd, reg, 0, value]
}

/// `gfx_v11_0_ring_emit_fence`, 32-bit data with an EOP interrupt request
/// (delivered only once IH enables the CP timestamp interrupt): the
/// `RELEASE_MEM` the ring writes after a job. The GCR is
/// `SEQ | GL2_WB | GLM_INV | GLM_WB | CACHE_POLICY(3) |
/// EVENT_TYPE(CACHE_FLUSH_AND_INV_TS_EVENT = 0x14) | EVENT_INDEX(5)`.
///
/// 32-bit, not 64-bit: Linux's `amdgpu_ib_schedule` passes
/// `AMDGPU_FENCE_FLAG_64BIT` to the fence emitter, but NARF's fence
/// writeback slots are 32-bit sequences, as on Navi22 and Navi48 — the
/// ledger tracks 32-bit sequences, so the packet writes 32-bit data.
/// `DATA_SEL(1) | INT_SEL(2)`.
pub fn release_mem_fence(address: u64, seq: u32) -> [u32; 8] {
    [
        pm4::packet3(pm4::PACKET3_RELEASE_MEM, 6),
        pm4::PACKET3_RELEASE_MEM_GCR_SEQ
            | pm4::PACKET3_RELEASE_MEM_GCR_GL2_WB
            | pm4::PACKET3_RELEASE_MEM_GCR_GLM_INV
            | pm4::PACKET3_RELEASE_MEM_GCR_GLM_WB
            | pm4::packet3_release_mem_cache_policy(3)
            | pm4::packet3_release_mem_event_type(0x14)
            | pm4::packet3_release_mem_event_index(5),
        pm4::packet3_release_mem_data_sel(1) | pm4::packet3_release_mem_int_sel(2),
        address as u32,
        (address >> 32) as u32,
        seq,
        0,
        0,
    ]
}

/// `gfx_v11_0_ring_emit_cntxcntl`: `load_enable`, plus the context-switch
/// loads (global config/uconfig, CS SH, per-context and gfx SH regs) when
/// the client context changes. Identical to Navi22's — the packet did not
/// change between GC 10.3 and 11.0.
pub fn context_control(context_switch: bool) -> [u32; 3] {
    let dw2 = 0x8000_0000
        | if context_switch {
            0x8001 | 0x0100_0000 | 0x1_0002
        } else {
            0
        };
    [pm4::packet3(pm4::PACKET3_CONTEXT_CONTROL, 1), dw2, 0]
}

/// `gfx_v11_0_ring_emit_frame_cntl` with `secure = false`:
/// `FRAME_CMD(start ? 0 : 1)`.
fn frame_control(start: bool) -> [u32; 2] {
    [
        pm4::packet3(pm4::PACKET3_FRAME_CONTROL, 0),
        pm4::frame_cmd(if start { 0 } else { 1 }),
    ]
}

/// `gfx_v11_0_emit_mem_sync`: whole-cache acquisition before client IBs.
/// The GCR is identical to Navi22's — every term matches
/// `gfx_v11_0_emit_mem_sync` one for one.
const CP_MEM_SYNC_GCR: u32 = {
    use crate::amdgpu_pm4_defs::*;
    packet3_acquire_mem_gcr_cntl_gl2_inv(1)
        | packet3_acquire_mem_gcr_cntl_gl2_wb(1)
        | packet3_acquire_mem_gcr_cntl_glm_inv(1)
        | packet3_acquire_mem_gcr_cntl_glm_wb(1)
        | packet3_acquire_mem_gcr_cntl_gl1_inv(1)
        | packet3_acquire_mem_gcr_cntl_glv_inv(1)
        | packet3_acquire_mem_gcr_cntl_glk_inv(1)
        | packet3_acquire_mem_gcr_cntl_gli_inv(1)
};

/// One submission's ring frame, after the flush decision.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    pub gfx: bool,
    /// GFXHUB invalidation engine of the ring.
    pub engine: u32,
    /// Pipeline sync: (ring fence address, last emitted sequence).
    pub sync: Option<(u64, u32)>,
    pub flush: Option<VmRef>,
    /// IH LUT write: (absolute `IH_VMID_<vmid>_LUT` dword, PASID).
    pub pasid_map: Option<(u32, u16)>,
    /// Dedicated writeback after the flush and LUT write, before client IBs.
    pub vm_fence: Option<(u64, u32)>,
    pub vmid: u8,
    pub context_switch: bool,
    pub gds_max_wave_id: Option<u32>,
    pub ibs: &'a [Ib],
    pub fence: u64,
    pub seq: u32,
}

/// Encode one CP submission (gfx or compute), in `amdgpu_ib_schedule`
/// order. `hub` is the die's GFXHUB table; `layout` carries the register
/// windows. A compute IB asking to reset the GDS wave-id limit without a
/// discovered limit is refused (`Error::Invalid`) rather than programmed
/// with a guessed value.
pub fn encode_cp(layout: &Gfx11Layout, hub: &GfxHubRegs, f: &Frame<'_>) -> Result<Vec<u32>, Error> {
    let (gfx, engine, vmid) = (f.gfx, f.engine, f.vmid);
    let base = layout.gc_base;
    let eng_sel = u32::from(gfx);
    let mut w = Vec::new();
    if let Some((address, value)) = f.sync {
        // gfx_v11_0_ring_emit_pipeline_sync
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
        // gmc_v11_0_emit_flush_gpu_tlb: no semaphore on GFXHUB
        // (gmc_v11_0_use_invalidate_semaphore is MMHUB-only).
        w.extend(cp_wreg(
            gfx,
            base + hub.ptb_lo + 2 * v,
            vm.page_table_base as u32,
        ));
        w.extend(cp_wreg(
            gfx,
            base + hub.ptb_lo + 1 + 2 * v,
            (vm.page_table_base >> 32) as u32,
        ));
        // emit_reg_write_reg_wait with cp_fw_write_wait (true on GC 11.0).
        w.extend(wait_reg_mem(
            eng_sel,
            0,
            1,
            base + hub.inv_req + engine,
            base + hub.inv_ack + engine,
            invalidate_request(vm.vmid),
            1 << v,
            0x20,
        ));
        if gfx {
            w.extend([pm4::packet3(pm4::PACKET3_PFP_SYNC_ME, 0), 0]);
        }
    }
    if let Some((lut, pasid)) = f.pasid_map {
        // gmc_v11_0_emit_pasid_mapping via gfx_v11_0_ring_emit_wreg.
        w.extend(cp_wreg(gfx, lut, u32::from(pasid)));
    }
    if let Some((address, sequence)) = f.vm_fence {
        w.extend(release_mem_fence(address, sequence));
    }
    // amdgpu_ib_schedule inspects the first IB for this job-wide request.
    if f.ibs
        .first()
        .is_some_and(|ib| ib.flags & uapi::AMDGPU_IB_FLAG_EMIT_MEM_SYNC != 0)
    {
        w.extend([
            pm4::packet3(pm4::PACKET3_ACQUIRE_MEM, 6),
            0,
            u32::MAX,
            0x00ff_ffff,
            0,
            0,
            10,
            CP_MEM_SYNC_GCR,
        ]);
    }
    // gfx_v11_0_ring_emit_hdp_flush: GFX pipe0 uses PFP (eng_sel 1), MEC
    // pipe0 uses ME (eng_sel 0). Both owned queues are pipe 0, so the
    // masks arrive unshifted in the layout.
    let hdp_mask = if gfx {
        layout.hdp_flush.gfx_mask
    } else {
        layout.hdp_flush.compute_mask
    };
    w.extend(wait_reg_mem(
        eng_sel,
        0,
        1,
        layout.hdp_flush.req,
        layout.hdp_flush.done,
        hdp_mask,
        hdp_mask,
        0x20,
    ));
    if gfx {
        // gfx_v11_0_ring_emit_cntxcntl + emit_frame_cntl(start).
        w.extend(context_control(f.context_switch));
        w.extend(frame_control(true));
    }
    for ib in f.ibs {
        if !gfx && ib.flags & uapi::AMDGPU_IB_FLAG_RESET_GDS_MAX_WAVE_ID != 0 {
            // gfx_v11_0_ring_emit_ib_compute: writing
            // GDS_COMPUTE_MAX_WAVE_ID resets wave ID counters in ME and
            // GDS to 0 for this ring. Validate at submission admits the
            // request only with a limit derived from this GPU's discovery
            // geometry.
            let Some(limit) = f.gds_max_wave_id else {
                return Err(Error::Invalid);
            };
            w.extend([
                pm4::packet3(pm4::PACKET3_SET_CONFIG_REG, 1),
                GDS_COMPUTE_MAX_WAVE_ID,
                limit,
            ]);
        }
        // gfx_v11_0_ring_emit_ib_gfx / _compute (no CE/preemption bits:
        // NARF's CS path submits no preemptible IBs).
        let control = ib.dwords | (u32::from(vmid) << 24) | if gfx { 0 } else { 1 << 23 };
        w.extend([
            pm4::packet3(pm4::PACKET3_INDIRECT_BUFFER, 2),
            ib.gpu_addr() as u32,
            (ib.gpu_addr() >> 32) as u32,
            control,
        ]);
    }
    if gfx {
        w.extend(frame_control(false));
    }
    // amdgpu_device_invalidate_hdp: hdp_v5_0_invalidate_hdp's emit_wreg.
    // HDP 6.0 has no invalidate step (layout carries None).
    if let Some(reg) = layout.hdp_read_cache_invalidate {
        w.extend(cp_wreg(gfx, reg, 1));
    }
    w.extend(release_mem_fence(f.fence, f.seq));
    if gfx {
        // amdgpu_ib_schedule: emit_switch_buffer after the job fence
        // (gfx_v11_0_ring_emit_sb), gfx ring only.
        w.extend([pm4::packet3(pm4::PACKET3_SWITCH_BUFFER, 0), 0]);
    }
    Ok(w)
}

/// Validate a submission before any ring access: a gfx/compute ring, a
/// user VMID, 1..=16 IBs, each non-empty, dword-aligned and within the
/// 20-bit size field.
pub fn validate(ring: Ring, vm: VmRef, ibs: &[Ib]) -> Result<(), Error> {
    if !matches!(ring, Ring::Gfx | Ring::Compute) {
        return Err(Error::Invalid);
    }
    if !(1..=15).contains(&vm.vmid) || ibs.is_empty() || ibs.len() > MAX_IBS {
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

// ── Ring backend ───────────────────────────────────────────────────

/// The rings a platform lane lends the submitter: the two kernel queues
/// lane 6 brings up, their fence writeback slots, and the doorbell that
/// makes the CP fetch. The submitter never touches MMIO; the backend
/// owns every register and every ring buffer.
///
/// A ring the backend does not provision reports no fence address, and
/// `ring_for` refuses it — so a half-built platform (gfx only, say) still
/// submits on what exists instead of failing the whole card.
pub trait RingBackend: Send + Sync {
    /// GPU address of `ring`'s fence writeback slot (the `RELEASE_MEM`
    /// target), or `None` when the ring is not provisioned.
    fn fence_address(&self, ring: Ring) -> Option<u64>;
    /// GPU address of `ring`'s VM-programming writeback slot, or `None`
    /// when the ring is not provisioned.
    fn vm_fence_address(&self, ring: Ring) -> Option<u64>;
    /// Write `words` to `ring`'s buffer and ring its doorbell. `Busy`
    /// when the ring has no room for the frame (the submitter waits for
    /// the oldest outstanding job and retries).
    fn emit(&self, ring: Ring, words: &[u32]) -> Result<(), Error>;
    /// Last fence sequence the ring's writeback reports, or `None` when
    /// the device stopped answering.
    fn completed(&self, ring: Ring) -> Option<u32>;
    /// Last VM-programming fence sequence the ring reports, or `None`
    /// when the device stopped answering.
    fn vm_completed(&self, ring: Ring) -> Option<u32>;
}

// ── Job ledger ─────────────────────────────────────────────────────

/// Signal times kept: the latest jobs' (ticket, ns). Older jobs' fences
/// fall back to the time a reader first saw them signalled.
const SIGNAL_TIMES: usize = 256; // linux: n/a (NARF bound on recorded fence timestamps)

/// API completion and physical retirement are separate on the native
/// GFX11 queues. Only observed writebacks can retire memory; reset/loss
/// errors wake clients while every unconfirmed resource remains
/// quarantined. (Navi22's `amdgpu_navi22_jobs::Jobs`, cut to this
/// submitter's two rings and no media engines.)
struct Jobs {
    epoch: u64,
    completed: [u32; RING_IDS],
    terminal: Option<FsError>,
    /// (ticket, context health, VMID the job ran in; 0 when not recorded).
    pending: Vec<(u64, Arc<Health>, u8)>,
    /// When each recently completed job was first seen complete
    /// (`dma_fence_signal_timestamp` from `amdgpu_fence_process`), oldest
    /// first, at most [`SIGNAL_TIMES`].
    signalled_at: VecDeque<(u64, u64)>,
}
/// The ticket's ring id (the low four bits of its ring index).
fn jobs_ring_id(ticket: u64) -> usize {
    ((ticket >> 32) as u32 & 15) as usize
}
impl Jobs {
    fn new(epoch: u64) -> Self {
        Self {
            epoch,
            completed: [0; RING_IDS],
            terminal: None,
            pending: Vec::new(),
            signalled_at: VecDeque::new(),
        }
    }
    fn retired(&self, ticket: u64) -> bool {
        let ring = (ticket >> 32) as u32;
        ring & !15 == ring_index(self.epoch, 0)
            && self
                .completed
                .get((ring & 15) as usize)
                .is_some_and(|&done| signaled(done, ticket as u32))
    }
    fn observe(&mut self, completed: [u32; RING_IDS]) {
        if self.terminal.is_some() {
            return;
        }
        self.completed = completed;
        let epoch = self.epoch;
        // amdgpu_fence_process: every job this sample completes signals now.
        let now = narf_time::wall::monotonic_ns().max(1);
        let signalled_at = &mut self.signalled_at;
        self.pending.retain(|(ticket, _, _)| {
            let done = job_done(epoch, completed, *ticket);
            if done {
                if signalled_at.len() == SIGNAL_TIMES {
                    signalled_at.pop_front();
                }
                signalled_at.push_back((*ticket, now));
            }
            !done
        });
    }
    /// [`Self::emitted`] for a job granted VMID `vmid`, which a soft
    /// recovery needs to name the waves it kills.
    fn emitted_on(&mut self, ticket: u64, health: &Arc<Health>, vmid: u8) {
        if self.terminal.is_some() {
            health.mark_canceled();
        }
        self.pending.push((ticket, health.clone(), vmid));
    }
    /// The oldest unfinished job on `ring` (the one a timeout blames) and
    /// its VMID. Consumed by the future hang-watchdog lane.
    #[allow(dead_code)]
    fn oldest(&self, ring: usize) -> Option<(u64, u8)> {
        self.pending
            .iter()
            .find(|(ticket, _, _)| jobs_ring_id(*ticket) == ring)
            .map(|(ticket, _, vmid)| (*ticket, *vmid))
    }
    fn finish(&mut self, error: FsError) {
        if self.terminal.is_none() || error == FsError::NoDevice {
            self.terminal = Some(error);
        }
        for (_, health, _) in &self.pending {
            health.mark_canceled();
        }
    }
    /// A job on `ring` hung: the oldest job's context is guilty, every
    /// other job is abandoned (`-ECANCELED`). A watchdog lane calls this;
    /// there is no recovery owner yet, so the terminal error stands until
    /// the platform lane registers a new submitter.
    #[allow(dead_code)]
    fn hang(&mut self, ring: usize) {
        if self.terminal.is_none() {
            if let Some((_, health, _)) = self
                .pending
                .iter()
                .find(|(t, _, _)| jobs_ring_id(*t) == ring)
            {
                health.mark_guilty();
            }
            self.finish(FsError::Canceled);
        }
    }
    /// When job `ticket` was seen complete (`Submitter::signal_time`).
    fn signal_time(&self, ticket: u64) -> Option<u64> {
        self.signalled_at
            .iter()
            .rev()
            .find(|(done, _)| *done == ticket)
            .map(|&(_, at)| at)
    }
    fn error(&self, ticket: u64) -> Option<FsError> {
        if self.retired(ticket) {
            return None;
        }
        self.terminal.map(|error| {
            if error == FsError::Canceled {
                self.pending
                    .iter()
                    .find(|(t, _, _)| *t == ticket)
                    .and_then(|(_, h, _)| h.error())
                    .unwrap_or(error)
            } else {
                error
            }
        })
    }
}

// ── Submitter ──────────────────────────────────────────────────────

/// Client VMIDs the GMC owner lends for client work: 1–7 on GFX11
/// (8–15 stay KFD's, as `gmc_v11_0_sw_init` sets `first_kfd_vmid` 8).
/// Lane 3's owner lends this range; until it merges, the platform lane
/// passes the same range explicitly.
pub const CLIENT_VMIDS: (u8, u8) = (1, 7);

/// Bound on waiting out the per-ring throttle or for an idle VMID before
/// giving up with EBUSY.
const THROTTLE_NS: u64 = 10_000_000_000; // linux: n/a (NARF policy)
/// Interval between fence-writeback samples while waiting (polling is the
/// only mandatory completion path until the IH v6 owner lands).
const POLL_NS: u64 = 1_000_000;

/// What the platform lane supplies to build a submitter.
#[derive(Clone, Copy, Debug)]
pub struct SubmitterConfig {
    /// The die this submitter runs on.
    pub die: Gfx11Die,
    /// The register windows the frames are encoded against.
    pub layout: Gfx11Layout,
    /// VM invalidation engine per ring ([gfx, compute]), from
    /// `amdgpu_gmc_allocate_vm_inv_eng`'s ring order.
    pub inv_engines: [u32; RING_IDS],
    /// Client VMID range the GMC owner lent.
    pub client_vmids: (u8, u8),
    /// Discovery GC geometry for the GDS wave-id limit, if known.
    pub gc: Option<GcInfo>,
}

/// The ticket ring index of ring `id` in recovery epoch `epoch`.
pub const fn ring_index(epoch: u64, id: usize) -> u32 {
    ((epoch as u32 & 0x07ff_ffff) << 4) | id as u32
}
/// Whether `ticket` completed, given each ring's completed sequence in
/// `epoch`. Tickets of another epoch were abandoned by a recovery.
pub fn job_done(epoch: u64, completed: [u32; RING_IDS], ticket: u64) -> bool {
    let index = (ticket >> 32) as u32;
    if index & !15 != ring_index(epoch, 0) {
        return true;
    }
    let done = completed.get((index & 15) as usize).copied().unwrap_or(0);
    signaled(done, ticket as u32)
}
/// The ring's scheduler entity for a job: Linux compares the entity's
/// fence context (`ring->current_ctx`), one per (open's VM, context) and
/// ring. Low 32 bits of the never-reused `VmState::owner` above the
/// context id; 0 is reserved for "none" and never produced (owners start
/// at 1).
pub const fn entity(owner: u64, ctx_id: u32) -> u64 {
    owner << 32 | ctx_id as u64
}
/// The submission request `amdgpu_vmid_grab` decides on, for a job of
/// `vm` at root `pd_addr` on ticket ring `ring`.
pub fn grab_request(
    vm: &VmState,
    pd_addr: u64,
    pasid: crate::amdgpu_vmid::Pasid,
    ring: u32,
) -> GrabRequest {
    GrabRequest {
        owner: vm.owner(),
        pd_addr,
        tlb_seq: vm.tlb_seq(),
        pasid,
        ring,
    }
}
/// The ring-side VM state of a job granted `grant`.
pub fn vm_ref(request: &GrabRequest, grant: Grant) -> VmRef {
    VmRef {
        vmid: grant.vmid,
        page_table_base: request.pd_addr,
        pasid: request.pasid,
        flush: grant.needs_flush,
        map_pasid: grant.map_pasid,
    }
}

/// RDNA3 has no gang scheduler: all IBs must name exactly one userspace
/// entity, even when several logical compute rings share a hardware queue.
/// Run before dependency waits and BO placement, and recheck at submission.
fn submission_ring(ibs: &[crate::amdgpu_cs::Ib]) -> Result<usize, FsError> {
    let first = ibs.first().ok_or(FsError::InvalidData)?;
    let ent = (first.ip_type, first.ip_instance, first.ring);
    let id = ring_id(ent.0, ent.1, ent.2).ok_or(FsError::InvalidData)?;
    if ibs.iter().any(|ib| {
        (ib.ip_type, ib.ip_instance, ib.ring) != ent
            || ib.flags & (uapi::AMDGPU_IB_FLAGS_SECURE | uapi::AMDGPU_IB_FLAG_CE) != 0
    }) {
        return Err(FsError::InvalidData);
    }
    Ok(id)
}

/// The Navi31/32/33 queues behind `AMDGPU_CS` on DRM card `card`.
///
/// No `Debug`: the backend is a trait object and the job ledger carries
/// fence state, neither of which has a useful debug form.
#[allow(missing_debug_implementations)]
pub struct Navi31Submitter {
    card: u32,
    die: Gfx11Die,
    layout: Gfx11Layout,
    hub: GfxHubRegs,
    backend: Arc<dyn RingBackend>,
    /// Recovery epoch. 0 until a recovery owner exists: a recovery
    /// registers a new submitter with a fresh manager, so every VMID is
    /// flushed and remapped before its next use.
    epoch: u64,
    vmids: IrqSafeSpinLock<VmidManager>,
    rings: IrqSafeSpinLock<[RingState; RING_IDS]>,
    inv_engines: [u32; RING_IDS],
    admission: [crate::amdgpu_admission::Queue; RING_IDS],
    jobs: IrqSafeSpinLock<Jobs>,
    /// The clear-state preamble has been installed on the gfx ring.
    /// Submissions before it are refused: the CP would run client IBs
    /// against whatever context state the ring held before.
    preamble: AtomicBool,
}

static CURRENT: IrqSafeSpinLock<Option<alloc::sync::Weak<Navi31Submitter>>> =
    IrqSafeSpinLock::new(None);

/// The current submitter, if one is registered and alive.
fn current() -> Option<Arc<Navi31Submitter>> {
    CURRENT.lock().as_ref().and_then(alloc::sync::Weak::upgrade)
}

/// Abandon every outstanding job with `error` (device loss / watchdog).
/// A recovery lane calls this; it finishes the ledger, it does not retire
/// memory — only observed writebacks do that.
#[allow(dead_code)]
pub(crate) fn abandon(error: FsError) {
    if let Some(submitter) = current() {
        submitter.jobs.lock().finish(error);
    }
}

/// One job's inputs to [`Navi31Submitter::encode_and_emit`]: the VMID
/// request and grant, the owning context, and the IBs.
struct Emit<'a> {
    request: &'a GrabRequest,
    grant: Grant,
    context: u64,
    ibs: &'a [Ib],
}

impl Navi31Submitter {
    /// Build the submitter over `backend`'s rings. Does not register it:
    /// [`register`](Self::register) does that, after the platform lane
    /// has installed the preamble and proven the rings.
    pub fn new(card: u32, config: SubmitterConfig, backend: Arc<dyn RingBackend>) -> Arc<Self> {
        let mut rings = [RingState::new(), RingState::new()];
        for state in &mut rings {
            state.configure_gds(config.gc);
        }
        Arc::new(Self {
            card,
            die: config.die,
            layout: config.layout,
            hub: gfxhub_regs(config.die),
            backend,
            epoch: 0,
            vmids: IrqSafeSpinLock::new(VmidManager::new(
                config.client_vmids.0,
                config.client_vmids.1,
            )),
            rings: IrqSafeSpinLock::new(rings),
            inv_engines: config.inv_engines,
            admission: [
                crate::amdgpu_admission::Queue::new(),
                crate::amdgpu_admission::Queue::new(),
            ],
            jobs: IrqSafeSpinLock::new(Jobs::new(0)),
            preamble: AtomicBool::new(false),
        })
    }

    /// Build the submitter and let DRM card `card`'s clients submit
    /// through it. Called with the platform owner held, after a bring-up
    /// whose ring tests passed and whose preamble is installed.
    pub fn register(
        card: u32,
        config: SubmitterConfig,
        backend: Arc<dyn RingBackend>,
    ) -> Arc<Self> {
        let submitter = Self::new(card, config, backend);
        *CURRENT.lock() = Some(Arc::downgrade(&submitter));
        crate::amdgpu_cs::register_submitter(card, submitter.clone());
        submitter
    }

    /// Stop accepting submissions for DRM card `card`.
    pub fn unregister(card: u32) {
        crate::amdgpu_cs::unregister_submitter(card);
        if let Some(submitter) = current().filter(|s| s.card == card) {
            submitter.jobs.lock().finish(FsError::NoDevice);
        }
    }

    /// The die this submitter runs on.
    pub fn die(&self) -> Gfx11Die {
        self.die
    }

    /// Whether the clear-state preamble has been installed.
    pub fn preamble_installed(&self) -> bool {
        self.preamble.load(Ordering::Acquire)
    }

    /// Install the clear-state preamble on the gfx ring:
    /// `gfx_v11_0_cp_gfx_start` — the 960-dword CSB
    /// ([`CSB_DWORDS`](crate::amdgpu_clearstate::CSB_DWORDS)) — and, when
    /// the card runs two gfx rings, the second ring's `CLEAR_STATE` copy.
    /// `gc_base_1` is the layout's GC BASE_IDX 1 dword base. The
    /// tile-steering override is [`TILE_STEERING_OVERRIDE`] (0 on GFX11).
    ///
    /// Fails closed (`Error::Invalid`) when the GC window-1 base puts the
    /// tile-steering register outside the context aperture, and
    /// (`Error::NoDevice`) when a ring the backend does not provision is
    /// named. Re-installing is harmless (Linux re-emits it on resume).
    pub fn install_preamble(&self, num_gfx_rings: u32) -> Result<(), Error> {
        let dws = match amdgpu_clearstate::build_preamble(
            self.layout.gc_base_1,
            TILE_STEERING_OVERRIDE,
        ) {
            Some(dws) => dws,
            None => return Err(Error::Invalid),
        };
        self.backend.emit(Ring::Gfx, &dws)?;
        if num_gfx_rings > 1 {
            self.backend.emit(
                Ring::GfxSecondary,
                &amdgpu_clearstate::build_secondary_ring_clear_state(),
            )?;
        }
        self.preamble.store(true, Ordering::Release);
        Ok(())
    }

    /// Every ring's completed sequence, retiring what completed jobs held.
    /// `None` when the device stopped answering. A dark sample finishes
    /// the ledger with `NoDevice`: the loss is terminal, so `error()`
    /// must surface it and later submissions must refuse, instead of
    /// leaving every waiter to re-discover the loss on its own poll.
    fn progress(&self) -> Option<[u32; RING_IDS]> {
        if self.jobs.lock().terminal.is_some() {
            return None;
        }
        let (completed, _) = match self.sample() {
            Some(sample) => sample,
            None => {
                self.jobs.lock().finish(FsError::NoDevice);
                return None;
            }
        };
        {
            let mut jobs = self.jobs.lock();
            if jobs.terminal.is_some() {
                return None;
            }
            jobs.observe(completed);
        }
        let epoch = self.epoch;
        crate::amdgpu_cs::retire(self.card, &|t| {
            (t >> 32) as u32 & !15 == ring_index(epoch, 0) && job_done(epoch, completed, t)
        });
        Some(completed)
    }

    /// Sample both rings' fence writebacks (job + VM-programming).
    /// `None` when a provisioned ring stopped answering.
    fn sample(&self) -> Option<([u32; RING_IDS], [u32; RING_IDS])> {
        let mut completed = [0; RING_IDS];
        let mut vm_completed = [0; RING_IDS];
        for (id, ring) in [Ring::Gfx, Ring::Compute].iter().enumerate() {
            if self.backend.fence_address(*ring).is_some() {
                completed[id] = self.backend.completed(*ring)?;
                vm_completed[id] = self.backend.vm_completed(*ring)?;
            }
        }
        Some((completed, vm_completed))
    }

    /// Every ring's VM-programming completed sequence. `None` when the
    /// device stopped answering.
    fn vm_progress(&self) -> Option<[u32; RING_IDS]> {
        self.sample().map(|(_, vm)| vm)
    }

    async fn wait_for(&self, ticket: u64, deadline_ns: u64) -> Result<bool, FsError> {
        loop {
            if let Some(error) = self.jobs.lock().error(ticket) {
                return Err(error);
            }
            if self.jobs.lock().retired(ticket) {
                return Ok(true);
            }
            let completed = self.progress().ok_or(FsError::NoDevice)?;
            if job_done(self.epoch, completed, ticket) {
                return Ok(true);
            }
            if narf_time::monotonic_ns() >= deadline_ns {
                return Ok(false);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ns(POLL_NS).as_instant()).await;
        }
    }

    /// The fence that must signal before another submission may be queued.
    fn throttle_seq(state: &RingState) -> u32 {
        state.seq.wrapping_sub(HW_SUBMISSIONS - 1)
    }

    /// Encode one job's frame and emit it on ring `id`. `completed` is
    /// the sampled fence progress the throttle checks. The ring's sequence
    /// advances only on a successful emit, so a refused frame never
    /// consumes a fence the throttle would wait for.
    fn encode_and_emit(
        &self,
        id: usize,
        state: &mut RingState,
        job: Emit<'_>,
        completed: [u32; RING_IDS],
    ) -> Result<u32, Error> {
        let ring = match id {
            0 => Ring::Gfx,
            _ => Ring::Compute,
        };
        if !signaled(completed[id], Self::throttle_seq(state)) {
            return Err(Error::Busy);
        }
        let fence = self.backend.fence_address(ring).ok_or(Error::NoDevice)?;
        let vm_fence = self.backend.vm_fence_address(ring).ok_or(Error::NoDevice)?;
        let seq = state.seq.wrapping_add(1).max(1);
        // amdgpu_ib_schedule: need_ctx_switch ||
        // amdgpu_vm_need_pipeline_sync.
        let context_switch = state.context != job.context;
        let vm = vm_ref(job.request, job.grant);
        let sync = (vm.flush || context_switch).then_some((fence, state.seq));
        let frame = Frame {
            gfx: ring == Ring::Gfx,
            engine: self.inv_engines[id],
            sync,
            flush: vm.flush.then_some(vm),
            pasid_map: vm.map_pasid.then_some((
                self.layout.oss_base + IH_VMID_0_LUT + u32::from(vm.vmid),
                vm.pasid,
            )),
            vm_fence: (vm.flush || vm.map_pasid).then_some((vm_fence, seq)),
            vmid: vm.vmid,
            context_switch,
            gds_max_wave_id: state.gds_max_wave_id,
            ibs: job.ibs,
            fence,
            seq,
        };
        let words = encode_cp(&self.layout, &self.hub, &frame)?;
        self.backend.emit(ring, &words)?;
        state.seq = seq;
        state.context = job.context;
        Ok(seq)
    }
}

impl crate::amdgpu_cs::Submitter for Navi31Submitter {
    fn validate_submission(
        &self,
        submission: &crate::amdgpu_cs::Submission,
    ) -> Result<(), FsError> {
        self.jobs.lock().terminal.map_or(Ok(()), Err)?;
        submission_ring(&submission.ibs).map(|_| ())
    }
    fn ring_for(&self, ip_type: u32, ip_instance: u32, ring: u32) -> Option<u32> {
        ring_id(ip_type, ip_instance, ring)
            .filter(|&id| {
                let r = if id == 0 { Ring::Gfx } else { Ring::Compute };
                self.backend.fence_address(r).is_some()
            })
            .map(|id| ring_index(self.epoch, id))
    }
    /// `ring` is a ticket ring index (`ring_for`); its low four bits are the
    /// ring id.
    fn max_ibs(&self, ring: u32) -> u32 {
        if (ring & 15) as usize >= RING_IDS {
            0
        } else {
            MAX_IBS as u32
        }
    }
    fn signalled(&self, ticket: u64) -> bool {
        // A vanished device makes no more progress; report done so waiters
        // cannot wedge.
        self.progress()
            .is_none_or(|completed| job_done(self.epoch, completed, ticket))
    }
    fn retired(&self, ticket: u64) -> bool {
        let _ = self.progress();
        self.jobs.lock().retired(ticket)
    }
    fn error(&self, ticket: u64) -> Option<FsError> {
        let _ = self.progress();
        self.jobs.lock().error(ticket)
    }
    fn signal_time(&self, ticket: u64) -> Option<u64> {
        self.jobs.lock().signal_time(ticket)
    }
    fn submit<'a>(
        &'a self,
        vm: &'a VmState,
        submission: &'a crate::amdgpu_cs::Submission,
        health: &'a Arc<Health>,
    ) -> Pin<Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>> {
        Box::pin(async move {
            if health.reset_epoch() != crate::amdgpu_ctx::recoveries() {
                health.mark_canceled();
                return Err(FsError::Canceled);
            }
            if let Some(error) = health.error().or(self.jobs.lock().terminal) {
                return Err(error);
            }
            let id = submission_ring(&submission.ibs)?;
            if vm.geometry() != Geometry::GMC11 {
                return Err(FsError::InvalidData);
            }
            if !self.preamble.load(Ordering::Acquire) {
                return Err(FsError::InvalidData);
            }
            let ibs: Vec<Ib> = submission.ibs.iter().map(Ib::from).collect();
            let page_table_base = vm.root_pde().ok_or(FsError::InvalidData)?;
            let pasid = vm.pasid().ok_or(FsError::NoSpace)?;
            let index = ring_index(self.epoch, id);
            let request = grab_request(vm, page_table_base, pasid, index);
            let context = entity(request.owner, submission.ctx_id);
            let deadline = narf_time::monotonic_ns().saturating_add(THROTTLE_NS);
            let mut admission = core::pin::pin!(self.admission[id].enter());
            let mut timeout = core::pin::pin!(narf_time::SleepUntil::new(
                narf_time::Deadline::after_ns(THROTTLE_NS).as_instant()
            ));
            let _permit = core::future::poll_fn(|cx| {
                if let core::task::Poll::Ready(permit) = admission.as_mut().poll(cx) {
                    return core::task::Poll::Ready(Ok(permit));
                }
                if timeout.as_mut().poll(cx).is_ready() {
                    return core::task::Poll::Ready(Err(FsError::Busy));
                }
                core::task::Poll::Pending
            })
            .await?;
            let seq = loop {
                if health.reset_epoch() != crate::amdgpu_ctx::recoveries() {
                    health.mark_canceled();
                    return Err(FsError::Canceled);
                }
                if let Some(error) = health.error().or(self.jobs.lock().terminal) {
                    return Err(error);
                }
                let completed = self.progress().ok_or(FsError::NoDevice)?;
                let vm_completed = self.vm_progress().ok_or(FsError::NoDevice)?;
                let epoch = self.epoch;
                let done = |t: u64| {
                    if t & (1 << 63) != 0 {
                        job_done(epoch, vm_completed, t & !(1 << 63))
                    } else {
                        job_done(epoch, completed, t)
                    }
                };
                let grant = self.vmids.lock().grab(request, &done);
                let Some(grant) = grant else {
                    // amdgpu_vmid_grab_idle: every client VMID still has
                    // an unfinished job; wait without holding anything.
                    if narf_time::monotonic_ns() >= deadline {
                        return Err(FsError::Busy);
                    }
                    narf_time::SleepUntil::new(narf_time::Deadline::after_ns(POLL_NS).as_instant())
                        .await;
                    continue;
                };
                let result = {
                    let mut rings = self.rings.lock();
                    self.encode_and_emit(
                        id,
                        &mut rings[id],
                        Emit {
                            request: &request,
                            grant,
                            context,
                            ibs: &ibs,
                        },
                        completed,
                    )
                };
                match result {
                    Ok(seq) => {
                        let ticket = u64::from(index) << 32 | u64::from(seq);
                        self.vmids.lock().commit_with_flush(
                            request,
                            grant,
                            ticket,
                            ticket | (1 << 63),
                        );
                        self.jobs.lock().emitted_on(ticket, health, grant.vmid);
                        break seq;
                    }
                    Err(Error::Busy) => {
                        // Two jobs in flight: wait for the older without
                        // holding anything.
                        let oldest = {
                            let state = self.rings.lock();
                            u64::from(index) << 32 | u64::from(Self::throttle_seq(&state[id]))
                        };
                        if !self.wait_for(oldest, deadline).await? {
                            return Err(FsError::Busy);
                        }
                    }
                    Err(error) => return Err(error.to_fs()),
                }
            };
            let _ = self.progress();
            Ok(u64::from(index) << 32 | u64::from(seq))
        })
    }
    fn wait(
        &self,
        ticket: u64,
        deadline_ns: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>> {
        Box::pin(async move { self.wait_for(ticket, deadline_ns).await })
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gfx11_submit_tests.rs"]
mod tests;
