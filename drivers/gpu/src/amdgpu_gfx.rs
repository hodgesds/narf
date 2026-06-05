//! AMD GFX (CP — Command Processor) ring bring-up.
//!
//! After PSP loads the GFX firmware and SMU powers up the GFX
//! block (`PPSMC_MSG_PowerUpGfx`), the host driver still has to
//! program the CP's ring registers so the GPU knows where to
//! fetch PM4 packets from. This module emits the canonical
//! GFX9 (Vega / Renoir / Cezanne) CP ring init register-write
//! sequence as a list of `(offset, value)` pairs; the driver
//! core walks the sequence and executes it against BAR5.
//!
//! Same pattern as [`crate::amdgpu_dcn::build_modeset`]: we
//! build the sequence pure, the driver writes it. Lets the
//! sequence be smoke-tested without real silicon.
//!
//! ## Sequence (GFX9)
//!
//! Per `drivers/gpu/drm/amd/amdgpu/gfx_v9_0.c::gfx_v9_0_cp_gfx_resume()`:
//!
//!   1. **Halt the CP**. `CP_ME_CNTL |= CE_HALT | PFP_HALT | ME_HALT`.
//!      The three engines stop fetching from their rings so
//!      programming the base / size registers is safe.
//!   2. **Reset wptr**. `CP_RB0_WPTR = 0; CP_RB0_WPTR_HI = 0`.
//!   3. **Program rptr writeback**. The GPU writes its read
//!      pointer back to a host buffer so the host knows how much
//!      of the ring has been consumed. `CP_RB0_RPTR_ADDR = lo;
//!      CP_RB0_RPTR_ADDR_HI = hi | 0x3` — the low two bits gate
//!      cache coherence for the writeback DMA.
//!   4. **Program ring base**. `CP_RB0_BASE = lo; CP_RB0_BASE_HI = hi`.
//!   5. **Program ring size**. `CP_RB0_CNTL` packs the log2 of
//!      the ring size in dwords (minus 1) into bits[5:0] and the
//!      block-size hint into bits[13:8].
//!   6. **Program doorbell window**. `CP_RB_DOORBELL_CONTROL`
//!      enables the doorbell + names the BAR2 offset to use;
//!      `CP_RB_DOORBELL_RANGE_LOWER` / `_UPPER` clamp the active
//!      queue range so stray doorbell writes outside the window
//!      are ignored.
//!   7. **Unhalt the CP**. `CP_ME_CNTL = 0` — fetch resumes.
//!
//! Linux references (GPL-2.0-or-later post-relicense; cite-okay):
//! - `drivers/gpu/drm/amd/amdgpu/gfx_v9_0.c::gfx_v9_0_cp_gfx_resume`
//! - `drivers/gpu/drm/amd/amdgpu/gfx_v11_0.c::gfx_v11_0_cp_gfx_resume`
//!   (GFX11 = Phoenix; same shape, different MMIO offsets).
//! - `gc/gc_9_0_offset.h` / `gc/gc_11_0_0_offset.h` — register defs.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_driver_runtime::{alloc_coherent, DmaBuffer, DomainId};

use crate::amdgpu_pm4::{Pm4Builder, Pm4Error};
use crate::amdgpu_ring::{Ring, RingError};

// ── CP register offsets (GFX9, relative to GC block base) ──────────
//
// Values from `gc/gc_9_0_offset.h` shipped in Linux's
// `drivers/gpu/drm/amd/include/asic_reg/`. These are the
// dword-indexed register IDs; the BAR5 byte offset is `id * 4`.

/// `mmCP_ME_CNTL` — halt / unhalt the three CP engines.
pub const CP_ME_CNTL_REL: u32 = 0x103D * 4;
/// `mmCP_RB0_BASE` — low 32 bits of ring phys.
pub const CP_RB0_BASE_REL: u32 = 0x107E * 4;
/// `mmCP_RB0_BASE_HI` — high 32 bits of ring phys.
pub const CP_RB0_BASE_HI_REL: u32 = 0x117C * 4;
/// `mmCP_RB0_CNTL` — ring size + block size config.
pub const CP_RB0_CNTL_REL: u32 = 0x1080 * 4;
/// `mmCP_RB0_RPTR_ADDR` — host rptr-writeback buffer lo.
pub const CP_RB0_RPTR_ADDR_REL: u32 = 0x107A * 4;
/// `mmCP_RB0_RPTR_ADDR_HI` — host rptr-writeback buffer hi.
pub const CP_RB0_RPTR_ADDR_HI_REL: u32 = 0x107B * 4;
/// `mmCP_RB0_WPTR` — host writeable wptr lo.
pub const CP_RB0_WPTR_REL: u32 = 0x1084 * 4;
/// `mmCP_RB0_WPTR_HI` — host writeable wptr hi.
pub const CP_RB0_WPTR_HI_REL: u32 = 0x1085 * 4;
/// `mmCP_RB_DOORBELL_CONTROL` — enable + offset of the doorbell.
pub const CP_RB_DOORBELL_CONTROL_REL: u32 = 0x1170 * 4;
/// `mmCP_RB_DOORBELL_RANGE_LOWER` — lower clamp on the doorbell window.
pub const CP_RB_DOORBELL_RANGE_LOWER_REL: u32 = 0x1171 * 4;
/// `mmCP_RB_DOORBELL_RANGE_UPPER` — upper clamp on the doorbell window.
pub const CP_RB_DOORBELL_RANGE_UPPER_REL: u32 = 0x1172 * 4;

// ── Field encodings ────────────────────────────────────────────────

/// `CP_ME_CNTL` — halt the PFP engine.
pub const CP_ME_CNTL_PFP_HALT: u32 = 1 << 26;
/// `CP_ME_CNTL` — halt the CE engine.
pub const CP_ME_CNTL_CE_HALT: u32 = 1 << 24;
/// `CP_ME_CNTL` — halt the ME engine.
pub const CP_ME_CNTL_ME_HALT: u32 = 1 << 28;
/// Combined: halt all three CP engines.
pub const CP_ME_CNTL_HALT_ALL: u32 = CP_ME_CNTL_PFP_HALT | CP_ME_CNTL_CE_HALT | CP_ME_CNTL_ME_HALT;

/// `CP_RB0_RPTR_ADDR_HI` — gate the writeback DMA through the
/// L2 cache (bit 0) and snoop coherent (bit 1). Linux ORs both.
pub const RPTR_WRITEBACK_COHERENT: u32 = 0x3;

/// `CP_RB_DOORBELL_CONTROL` — enable the per-queue doorbell.
pub const CP_RB_DOORBELL_EN: u32 = 1 << 30;
/// `CP_RB_DOORBELL_CONTROL` — doorbell offset shift.
pub const CP_RB_DOORBELL_OFFSET_SHIFT: u32 = 2;

// ── GRBM (Graphics Register Bus Manager) — chip-identity surface ───
//
// GRBM is the per-shader-engine register-broadcast manager. Three
// registers form the Foundations-wave read surface:
//
// - `mmGRBM_STATUS`     — busy bits for every CP/RLC/SE subengine.
//                         Read-only. Ring/scheduler bring-up reads
//                         it to confirm engines are idle before
//                         programming CP_RB0_BASE et al.
// - `mmGRBM_GFX_INDEX`  — per-SE / per-SH / per-CU broadcast mask.
//                         RW. Subsequent waves write this to select
//                         which shader-engine instance subsequent
//                         indexed register accesses apply to.
// - `mmCP_VERSION`      — CP firmware microcode version (the colloquial
//                         "GFX_VERSION"). Read-only. Foundations
//                         wave reads it as a chip presence-test
//                         corroborator (non-FF, non-0).
//
// Per-family register dword indices from gc_9_0_offset.h /
// gc_11_0_0_offset.h. Multiplied by 4 for byte offsets so the
// constants directly compose with `mm_read(gc_base + REL)`.
//
//   GFX9  mmGRBM_STATUS    dword 0x0DA0   byte 0x3680
//   GFX9  mmGRBM_GFX_INDEX dword 0x2A00   byte 0xA800
//   GFX9  mmCP_VERSION     dword 0x0867   byte 0x219C
//   GFX11 mmGRBM_STATUS    dword 0x1A40   byte 0x6900
//   GFX11 mmGRBM_GFX_INDEX dword 0x2A00   byte 0xA800
//   GFX11 mmCP_VERSION     dword 0x0C8C   byte 0x3230
//
// All offsets are relative to the GC IP block window
// (`HW_ID_GC` instance 0 from discovery).

/// GFX9 `mmGRBM_STATUS` byte offset — busy bitfield over CP/RLC/SE.
pub const GRBM_STATUS_REL_GFX9: u32 = 0x0DA0 * 4;
/// GFX11 `mmGRBM_STATUS` byte offset.
pub const GRBM_STATUS_REL_GFX11: u32 = 0x1A40 * 4;
/// `mmGRBM_GFX_INDEX` byte offset — SE/SH/CU broadcast mask.
/// Identical dword index on both GFX9 and GFX11 per the public
/// PPR tables (the register is part of the GFX hub block that
/// didn't move between generations).
pub const GRBM_GFX_INDEX_REL: u32 = 0x2A00 * 4;
/// GFX9 `mmCP_VERSION` byte offset.
pub const CP_VERSION_REL_GFX9: u32 = 0x0867 * 4;
/// GFX11 `mmCP_VERSION` byte offset.
pub const CP_VERSION_REL_GFX11: u32 = 0x0C8C * 4;

// ── GRBM_STATUS bit decode ─────────────────────────────────────────
//
// Bits chosen by the rule "if Linux uses the same #define name
// across both gen headers AND the bit position matches, it's stable
// across GFX9 + GFX11".

/// `GRBM_STATUS.GUI_ACTIVE` — any GFX engine busy.
pub const GRBM_STATUS_GUI_ACTIVE: u32 = 1 << 31;
/// `GRBM_STATUS.CP_BUSY` — CP front-end busy fetching/decoding.
pub const GRBM_STATUS_CP_BUSY: u32 = 1 << 29;
/// `GRBM_STATUS.CP_COHERENCY_BUSY` — CP cache-coherency unit busy.
pub const GRBM_STATUS_CP_COHERENCY_BUSY: u32 = 1 << 28;
/// `GRBM_STATUS.RLC_BUSY` — RLC microcontroller busy.
pub const GRBM_STATUS_RLC_BUSY: u32 = 1 << 26;
/// `GRBM_STATUS.GDS_BUSY` — Global Data Share busy.
pub const GRBM_STATUS_GDS_BUSY: u32 = 1 << 15;

/// Decoded view of `mmGRBM_STATUS`. Foundations wave uses this as
/// a presence-test corroborator; later waves drive scheduler /
/// ring bring-up off the same struct.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GrbmStatus {
    pub raw: u32,
}

impl GrbmStatus {
    /// Any GFX engine reports busy.
    pub fn any_busy(&self) -> bool {
        self.raw & GRBM_STATUS_GUI_ACTIVE != 0
    }
    /// CP front-end busy.
    pub fn cp_busy(&self) -> bool {
        self.raw & GRBM_STATUS_CP_BUSY != 0
    }
    /// RLC microcontroller busy.
    pub fn rlc_busy(&self) -> bool {
        self.raw & GRBM_STATUS_RLC_BUSY != 0
    }
    /// Every documented busy bit clear. Invariant the ring/scheduler
    /// bring-up (Wave-81+) waits on before touching CP_RB0_BASE.
    pub fn idle(&self) -> bool {
        self.raw
            & (GRBM_STATUS_GUI_ACTIVE
                | GRBM_STATUS_CP_BUSY
                | GRBM_STATUS_CP_COHERENCY_BUSY
                | GRBM_STATUS_RLC_BUSY
                | GRBM_STATUS_GDS_BUSY)
            == 0
    }
    /// Register window read 0xFFFF_FFFF. Live silicon never reports
    /// every bit set simultaneously; treat as device-gone.
    pub fn is_sentinel(&self) -> bool {
        self.raw == 0xFFFF_FFFF
    }
}

// ── GRBM_GFX_INDEX field encoding ──────────────────────────────────
//
// Per gc_9_0_offset.h / gc_11_0_0_offset.h:
//   [7:0]   INSTANCE_INDEX
//   [15:8]  SH_INDEX
//   [23:16] SE_INDEX
//   [29]    SH_BROADCAST_WRITES         1 = broadcast to all SHs
//   [30]    INSTANCE_BROADCAST_WRITES   1 = broadcast to all instances
//   [31]    SE_BROADCAST_WRITES         1 = broadcast to all SEs

/// `GRBM_GFX_INDEX` value broadcasting to every SE/SH/instance.
/// Standard "no narrowing" mask the bring-up writes for CP/RLC
/// registers that aren't shader-engine-private.
pub const fn grbm_gfx_index_broadcast() -> u32 {
    (1u32 << 31) | (1u32 << 30) | (1u32 << 29)
}

/// `GRBM_GFX_INDEX` value targeting one specific `(se, sh, instance)`
/// triple. Caller keeps indices within the chip's SE/SH/CU counts
/// (Renoir = 1 SE x 1 SH x 7 CU active; Phoenix = 1 SE x 2 SH x 6
/// CU active per AMD public docs).
pub const fn grbm_gfx_index_for(se: u8, sh: u8, instance: u8) -> u32 {
    ((se as u32) << 16) | ((sh as u32) << 8) | (instance as u32)
}

// ── CP register offsets (GFX11 — Phoenix HawkPoint1 / Strix) ───────
//
// Values from gc/gc_11_0_0_offset.h. Most ring registers keep the
// same dword IDs as GFX9; the key delta is that CP_ME_CNTL is
// replaced by CP_GFX_CNTL with reshuffled halt-bit positions.

/// `mmCP_GFX_CNTL` (GFX11) — replaces CP_ME_CNTL for halt/unhalt.
pub const CP_GFX_CNTL_REL: u32 = 0x103E * 4;

// CP_GFX_CNTL halt bits — distinct positions from CP_ME_CNTL on GFX9.

/// `CP_GFX_CNTL` — halt the FE (front-end fetch).
pub const CP_GFX_CNTL_FE_HALT: u32 = 1 << 0;
/// `CP_GFX_CNTL` — halt the PFP engine.
pub const CP_GFX_CNTL_PFP_HALT_GFX11: u32 = 1 << 4;
/// `CP_GFX_CNTL` — halt the ME engine.
pub const CP_GFX_CNTL_ME_HALT_GFX11: u32 = 1 << 8;
/// Combined: halt all GFX11 CP engines.
pub const CP_GFX_CNTL_HALT_ALL: u32 =
    CP_GFX_CNTL_FE_HALT | CP_GFX_CNTL_PFP_HALT_GFX11 | CP_GFX_CNTL_ME_HALT_GFX11;

/// Validate the ring config + emit the CP ring-init sequence for a
/// GFX11 device (Phoenix HawkPoint1 / Strix Point). Structurally
/// identical to `build_gfx9_ring_init` — same disable/wptr-reset/
/// rptr-writeback/base/size/doorbell/unhalt ordering — but the
/// halt/unhalt writes go to mmCP_GFX_CNTL with different bit
/// positions, and the ME_CNTL register doesn't exist on GFX11.
/// Per Linux drivers/gpu/drm/amd/amdgpu/gfx_v11_0.c::
/// gfx_v11_0_cp_gfx_resume + gfx_v11_0_cp_gfx_enable.
pub fn build_gfx11_ring_init(
    gc_base: u32,
    ring_phys: u64,
    ring_size_dw: u32,
    doorbell_idx: u32,
    rptr_writeback_phys: u64,
) -> Result<GfxRingInitSequence, GfxError> {
    if !ring_size_dw.is_power_of_two() || ring_size_dw < 8 || ring_size_dw > (1 << 20) {
        return Err(GfxError::BadRingSize);
    }
    if ring_phys & 0xFF != 0 {
        return Err(GfxError::UnalignedRingPhys);
    }
    if rptr_writeback_phys & 0x7 != 0 {
        return Err(GfxError::UnalignedRptrWriteback);
    }

    let mut seq = GfxRingInitSequence::default();

    // Step 1: halt the CP engines via CP_GFX_CNTL (NOT CP_ME_CNTL).
    seq.push(gc_base + CP_GFX_CNTL_REL, CP_GFX_CNTL_HALT_ALL);

    // Step 2: reset wptr.
    seq.push(gc_base + CP_RB0_WPTR_REL, 0);
    seq.push(gc_base + CP_RB0_WPTR_HI_REL, 0);

    // Step 3: rptr writeback (same coherent-bits-OR-into-hi rule).
    seq.push(gc_base + CP_RB0_RPTR_ADDR_REL, rptr_writeback_phys as u32);
    seq.push(
        gc_base + CP_RB0_RPTR_ADDR_HI_REL,
        ((rptr_writeback_phys >> 32) as u32) | RPTR_WRITEBACK_COHERENT,
    );

    // Step 4: ring base.
    seq.push(gc_base + CP_RB0_BASE_REL, ring_phys as u32);
    seq.push(gc_base + CP_RB0_BASE_HI_REL, (ring_phys >> 32) as u32);

    // Step 5: ring size.
    let log2_size = ring_size_dw.trailing_zeros();
    let blksz: u32 = 6;
    seq.push(gc_base + CP_RB0_CNTL_REL, log2_size | (blksz << 8));

    // Step 6: doorbell.
    seq.push(
        gc_base + CP_RB_DOORBELL_CONTROL_REL,
        CP_RB_DOORBELL_EN | (doorbell_idx << CP_RB_DOORBELL_OFFSET_SHIFT),
    );
    seq.push(gc_base + CP_RB_DOORBELL_RANGE_LOWER_REL, doorbell_idx);
    seq.push(gc_base + CP_RB_DOORBELL_RANGE_UPPER_REL, doorbell_idx + 1);

    // Step 7: unhalt — clear CP_GFX_CNTL (engines start fetching).
    seq.push(gc_base + CP_GFX_CNTL_REL, 0);

    Ok(seq)
}

// ── Sequence shape ─────────────────────────────────────────────────

/// Errors building the ring-init sequence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GfxError {
    /// `ring_size_dw` isn't a power of two between 8 (3 dwords)
    /// and `1 << 20`. `CP_RB0_CNTL` encodes the size as `log2(size_dw)`,
    /// so non-powers-of-two can't be expressed.
    BadRingSize,
    /// `ring_phys` isn't 256-byte aligned. `CP_RB0_BASE` requires
    /// at least 256-byte alignment per the CP IP docs.
    UnalignedRingPhys,
    /// `rptr_writeback_phys` isn't 8-byte aligned. The writeback
    /// DMA targets a 64-bit value.
    UnalignedRptrWriteback,
}

/// One MMIO write in a ring-init sequence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GfxWrite {
    /// Register-bus address (gc_base + register offset, in BAR5
    /// byte address space).
    pub addr: u32,
    /// Value to write.
    pub value: u32,
}

/// Ordered list of GFX CP register writes to perform a single
/// GFX-ring bring-up.
#[derive(Default, Debug)]
pub struct GfxRingInitSequence {
    pub writes: Vec<GfxWrite>,
}

impl GfxRingInitSequence {
    /// Convenience: number of writes.
    pub fn len(&self) -> usize {
        self.writes.len()
    }
    /// Convenience: empty sequence (defensive guard).
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }
    /// Iterator over (addr, value).
    pub fn iter(&self) -> core::slice::Iter<'_, GfxWrite> {
        self.writes.iter()
    }

    fn push(&mut self, addr: u32, value: u32) {
        self.writes.push(GfxWrite { addr, value });
    }
}

/// Validate the ring config + emit the CP ring-init sequence
/// for a GFX9 (Vega / Renoir / Cezanne) device. The caller has
/// already allocated the ring + the rptr-writeback buffer; we
/// just stitch the registers together.
pub fn build_gfx9_ring_init(
    gc_base: u32,
    ring_phys: u64,
    ring_size_dw: u32,
    doorbell_idx: u32,
    rptr_writeback_phys: u64,
) -> Result<GfxRingInitSequence, GfxError> {
    // Validate inputs.
    if !ring_size_dw.is_power_of_two() || ring_size_dw < 8 || ring_size_dw > (1 << 20) {
        return Err(GfxError::BadRingSize);
    }
    if ring_phys & 0xFF != 0 {
        return Err(GfxError::UnalignedRingPhys);
    }
    if rptr_writeback_phys & 0x7 != 0 {
        return Err(GfxError::UnalignedRptrWriteback);
    }

    let mut seq = GfxRingInitSequence::default();

    // Step 1: halt the CP engines.
    seq.push(gc_base + CP_ME_CNTL_REL, CP_ME_CNTL_HALT_ALL);

    // Step 2: reset wptr.
    seq.push(gc_base + CP_RB0_WPTR_REL, 0);
    seq.push(gc_base + CP_RB0_WPTR_HI_REL, 0);

    // Step 3: rptr writeback address (with coherent bits set on hi).
    seq.push(gc_base + CP_RB0_RPTR_ADDR_REL, rptr_writeback_phys as u32);
    seq.push(
        gc_base + CP_RB0_RPTR_ADDR_HI_REL,
        ((rptr_writeback_phys >> 32) as u32) | RPTR_WRITEBACK_COHERENT,
    );

    // Step 4: ring base.
    seq.push(gc_base + CP_RB0_BASE_REL, ring_phys as u32);
    seq.push(gc_base + CP_RB0_BASE_HI_REL, (ring_phys >> 32) as u32);

    // Step 5: ring size. log2(size_dw) in bits[5:0]; BLKSZ in [13:8].
    // 256-byte (= 64-dword) block size — Linux default.
    let log2_size = ring_size_dw.trailing_zeros();
    let blksz: u32 = 6;
    seq.push(gc_base + CP_RB0_CNTL_REL, log2_size | (blksz << 8));

    // Step 6: doorbell window.
    seq.push(
        gc_base + CP_RB_DOORBELL_CONTROL_REL,
        CP_RB_DOORBELL_EN | (doorbell_idx << CP_RB_DOORBELL_OFFSET_SHIFT),
    );
    seq.push(gc_base + CP_RB_DOORBELL_RANGE_LOWER_REL, doorbell_idx);
    seq.push(gc_base + CP_RB_DOORBELL_RANGE_UPPER_REL, doorbell_idx + 1);

    // Step 7: unhalt — fetch resumes.
    seq.push(gc_base + CP_ME_CNTL_REL, 0);

    Ok(seq)
}

// ── Indirect-buffer submission helper ──────────────────────────────
//
// Combines the three primitives (PM4 builder, Ring buffer, fence
// buffer) into a single "submit this IB and tell me when it's
// done" API that the rest of the driver uses to push GPU work.
// The actual end-to-end completion needs the GPU to write back to
// the fence buffer; on real silicon that fires within microseconds
// of the IB retiring. In the test harness, fence completion is
// staged via `set_fence_for_test`.

/// One submission to GFX. Caller passes back into
/// [`GfxContext::fence_completed`] to poll.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Fence {
    /// Monotonic sequence number from the issuing context.
    pub seq: u64,
}

/// Errors that can happen during IB submission.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SubmitError {
    /// Ring rejected the packet pair (out of contiguous tail room).
    Ring(RingError),
    /// PM4 packet construction failed (out of staging room).
    Pm4(Pm4Error),
}

impl From<RingError> for SubmitError {
    fn from(e: RingError) -> Self {
        SubmitError::Ring(e)
    }
}
impl From<Pm4Error> for SubmitError {
    fn from(e: Pm4Error) -> Self {
        SubmitError::Pm4(e)
    }
}

/// Per-queue GFX submission context. Owns its ring and a
/// host-coherent fence dword. Caller is responsible for binding
/// the ring's `phys_addr()` into the CP via
/// [`build_gfx9_ring_init`] before the first submission lands.
#[derive(Debug)]
pub struct GfxContext {
    ring: Ring,
    /// Single DMA-coherent dword the GPU writes the most-recent
    /// retired sequence number into via WRITE_DATA. Host polls it.
    fence_buf: DmaBuffer,
    /// Next sequence number to publish.
    next_seq: u64,
}

impl GfxContext {
    /// Allocate a fresh GFX context: ring + fence buffer.
    pub fn new(queue_idx: u16) -> Result<Self, RingError> {
        let ring = Ring::new(queue_idx)?;
        // 8 bytes is enough — single u64 sequence number. Hardware
        // requires 8-byte alignment for the WRITE_DATA target
        // anyway, and DMA pages are 4-KiB aligned so this is fine.
        let fence_buf = alloc_coherent(8, DomainId::DRIVER_0).map_err(|_| RingError::NoMemory)?;
        // Zero the fence buffer so reads-before-completion return 0,
        // not garbage.
        // SAFETY: identity-mapped, exclusive owner.
        unsafe {
            core::ptr::write_volatile(fence_buf.phys_addr().raw() as *mut u64, 0);
        }
        Ok(Self {
            ring,
            fence_buf,
            next_seq: 0,
        })
    }

    /// Phys address of the ring's first dword — feed this into
    /// [`build_gfx9_ring_init`].
    pub fn ring_phys(&self) -> u64 {
        self.ring.phys_addr()
    }

    /// Phys address of the fence-writeback buffer — feed this
    /// into [`build_gfx9_ring_init`] as `rptr_writeback_phys`. The
    /// CP uses the same buffer for RPTR writeback in this minimal
    /// scaffold; production splits them.
    pub fn fence_phys(&self) -> u64 {
        self.fence_buf.phys_addr().raw()
    }

    /// Doorbell offset for the BAR2 doorbell write that kicks the
    /// CP after [`submit_ib`].
    pub fn doorbell_offset(&self) -> u64 {
        self.ring.doorbell_offset()
    }

    /// Submit a pre-built IB (sitting somewhere in GPU-visible
    /// memory at `ib_phys`, `ib_size_dw` dwords long) and request
    /// the CP publish a fence when it retires.
    ///
    /// Layout pushed to the ring:
    ///
    /// ```text
    ///   PM4 INDIRECT_BUFFER(ib_phys, ib_size_dw, vmid=0)    — 4 dw
    ///   PM4 WRITE_DATA(fence_phys, next_seq as u32)         — 5 dw
    /// ```
    ///
    /// Total: 9 dwords per submission.
    ///
    /// # Safety
    /// Caller owns the ring exclusively for this call. Subsequent
    /// submissions to the same queue must not overlap. The ring
    /// must have been bound to the CP (`build_gfx9_ring_init`) and
    /// the CP unhalted; otherwise the doorbell write below has no
    /// effect (the packets sit in DRAM until bring-up).
    pub unsafe fn submit_ib(
        &mut self,
        ib_phys: u64,
        ib_size_dw: u32,
    ) -> Result<Fence, SubmitError> {
        self.next_seq += 1;
        let seq = self.next_seq;

        // Build INDIRECT_BUFFER + WRITE_DATA fence-publish packets
        // into a staging slice. 9 dwords total.
        let mut staging = [0u32; 9];
        {
            let mut b = Pm4Builder::new(&mut staging);
            b.indirect_buffer(ib_phys, ib_size_dw, 0)?;
            b.write_data(self.fence_phys(), seq as u32)?;
        }

        // SAFETY: caller-promised ring exclusivity.
        unsafe {
            self.ring.submit(&staging)?;
        }
        compiler_fence(Ordering::SeqCst);

        Ok(Fence { seq })
    }

    /// Has the CP retired through (or past) `fence`?
    ///
    /// Reads the host-coherent fence buffer; comparison is "≥" so
    /// a later submission's completion implicitly retires earlier
    /// fences on the same queue (per CP ordering).
    pub fn fence_completed(&self, fence: &Fence) -> bool {
        // SAFETY: identity-mapped DMA backing, exclusive owner.
        let observed: u32 =
            unsafe { core::ptr::read_volatile(self.fence_buf.phys_addr().raw() as *const u32) };
        (observed as u64) >= fence.seq
    }

    /// Most-recently-issued fence (for diagnostics).
    pub fn last_fence_seq(&self) -> u64 {
        self.next_seq
    }
}

impl GfxContext {
    /// Test scaffolding: simulate the CP retiring through `seq` by
    /// writing the fence dword directly. Used by smokes that verify
    /// the `fence_completed` poll without a real GPU; production
    /// callers never reach for this (the CP writes the fence dword).
    pub fn set_fence_for_test(&self, seq: u32) {
        // SAFETY: identity-mapped DMA backing, exclusive owner.
        unsafe {
            core::ptr::write_volatile(self.fence_buf.phys_addr().raw() as *mut u32, seq);
        }
    }
}
