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

/// `CP_RB_RPTR_ADDR_HI__RB_RPTR_ADDR_HI_MASK` — the writeback address's
/// high half, 16 bits of a 48-bit address.
///
/// This constant was `RPTR_WRITEBACK_COHERENT = 0x3`, documented as "gate the
/// writeback DMA through the L2 cache (bit 0) and snoop coherent (bit 1),
/// Linux ORs both". Linux does not: `gfx_v9_0_cp_gfx_resume` and
/// `gfx_v11_0_cp_gfx_resume` both MASK this register with
/// `CP_RB_RPTR_ADDR_HI__RB_RPTR_ADDR_HI_MASK`, and the register has exactly
/// one field — bits 15:0, the address. There are no cache bits to set, so
/// ORing 0x3 set address bits 32 and 33 and pointed the writeback DMA at the
/// wrong page.
pub const RPTR_ADDR_HI_MASK: u32 = 0x0000_FFFF;

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
    if !ring_size_dw.is_power_of_two() || !(8..=(1 << 20)).contains(&ring_size_dw) {
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

    // Step 3: rptr writeback address. The high half is MASKED to 16 bits —
    // `upper_32_bits(rptr_addr) & CP_RB_RPTR_ADDR_HI__RB_RPTR_ADDR_HI_MASK`.
    // It used to have 0x3 OR'd into it; see `RPTR_ADDR_HI_MASK`.
    seq.push(gc_base + CP_RB0_RPTR_ADDR_REL, rptr_writeback_phys as u32);
    seq.push(
        gc_base + CP_RB0_RPTR_ADDR_HI_REL,
        ((rptr_writeback_phys >> 32) as u32) & RPTR_ADDR_HI_MASK,
    );

    // Step 4: ring base, SHIFTED RIGHT BY 8 — `rb_addr = ring->gpu_addr >> 8`
    // in both `gfx_v9_0_cp_gfx_resume` and `gfx_v11_0_cp_gfx_resume`. The
    // register holds a 256-byte granule, which is exactly why the 256-byte
    // alignment check above exists; the check was here and the shift was not,
    // so the CP was pointed 256x too high.
    let rb_addr = ring_phys >> 8;
    seq.push(gc_base + CP_RB0_BASE_REL, rb_addr as u32);
    seq.push(gc_base + CP_RB0_BASE_HI_REL, (rb_addr >> 32) as u32);

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
    /// The engine's ring read pointer, as last reported.
    ///
    /// LINUX-GAP: nothing reports it. Linux has the command processor write
    /// `rptr` into a host page it named at queue setup
    /// (`ring->rptr_gpu_addr`), and reads it from there to decide whether a
    /// submission fits. That needs the queue descriptor the firmware consumes.
    /// Until then this stays 0, which makes the ring effectively write-once:
    /// `submit` starts refusing with `Full` after a ring's worth of dwords,
    /// which is the SAFE direction — the alternative is overwriting commands
    /// the engine may still be executing.
    ring_rptr_dw: u64,
}

impl GfxContext {
    /// Tell the context how far the engine has consumed its ring.
    ///
    /// For the firmware path to call once it can read `rptr` back, and for
    /// tests to drive the wrap. Without it the ring fills and stays full.
    pub fn set_ring_rptr(&mut self, rptr_dw: u64) {
        self.ring_rptr_dw = rptr_dw;
    }

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
            core::ptr::write_volatile(fence_buf.cpu_mut_ptr::<u64>(), 0);
        }
        Ok(Self {
            ring,
            fence_buf,
            next_seq: 0,
            ring_rptr_dw: 0,
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
        self.fence_buf.dma_addr().raw()
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
            self.ring.submit(&staging, self.ring_rptr_dw)?;
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
        let observed: u32 =
            // SAFETY: identity-mapped DMA backing, exclusive owner.
            unsafe { core::ptr::read_volatile(self.fence_buf.cpu_ptr::<u32>()) };
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
            core::ptr::write_volatile(self.fence_buf.cpu_mut_ptr::<u32>(), seq);
        }
    }
}

// ── GFX11 CP ring bring-up ──────────────────────────────────────────

// Register offsets from `gc_11_0_0_offset.h`, in DWORD address space — the
// `GfxWrite.addr` convention elsewhere in this file is a byte address, so
// each is shifted when emitted.
const GFX11_GRBM_GFX_CNTL: u32 = 0x0900;
const GFX11_CP_RB_WPTR_DELAY: u32 = 0x0f61;
const GFX11_CP_RB0_BASE: u32 = 0x1de0;
const GFX11_CP_RB0_CNTL: u32 = 0x1de1;
const GFX11_CP_RB0_RPTR_ADDR: u32 = 0x1de3;
const GFX11_CP_RB0_RPTR_ADDR_HI: u32 = 0x1de4;
const GFX11_CP_RB_VMID: u32 = 0x1df1;
const GFX11_CP_RB0_WPTR: u32 = 0x1df4;
const GFX11_CP_RB0_WPTR_HI: u32 = 0x1df5;
const GFX11_CP_RB_DOORBELL_RANGE_LOWER: u32 = 0x1dfa;
const GFX11_CP_RB_DOORBELL_RANGE_UPPER: u32 = 0x1dfb;
const GFX11_CP_RB0_BASE_HI: u32 = 0x1e51;
const GFX11_CP_RB_WPTR_POLL_ADDR_LO: u32 = 0x1e8b;
const GFX11_CP_RB_WPTR_POLL_ADDR_HI: u32 = 0x1e8c;
const GFX11_CP_RB_DOORBELL_CONTROL: u32 = 0x1e8d;
const GFX11_CP_RB_ACTIVE: u32 = 0x1f40;

/// `CP_RB_RPTR_ADDR_HI__RB_RPTR_ADDR_HI_MASK` — the writeback address is
/// 48-bit, so its high half keeps 16 bits.
const GFX11_RPTR_ADDR_HI_MASK: u32 = 0x0000_FFFF;
/// `CP_RB_DOORBELL_RANGE_UPPER__DOORBELL_RANGE_UPPER_MASK`. Linux writes the
/// whole mask, opening the range to its maximum rather than to one entry.
const GFX11_DOORBELL_RANGE_UPPER_MASK: u32 = 0x0000_0FFC;
const GFX11_DOORBELL_RANGE_LOWER_SHIFT: u32 = 2;
const GFX11_DOORBELL_OFFSET_SHIFT: u32 = 2;
const GFX11_DOORBELL_EN: u32 = 1 << 30;

/// One step of a bring-up sequence: a write, or a wait the hardware needs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GfxStep {
    /// Write `value` to the byte address `addr`.
    Write { addr: u32, value: u32 },
    /// Wait at least `us` microseconds before continuing.
    ///
    /// Modelled rather than performed, so a sequence is a value a test can
    /// inspect. `gfx_v11_0_cp_gfx_resume`'s `mdelay(1)` is here because
    /// dropping it is invisible in review and the second `CP_RB0_CNTL` write
    /// that follows exists only because of it.
    Delay { us: u32 },
}

/// An ordered GFX11 bring-up sequence.
#[derive(Default, Debug)]
pub struct Gfx11Sequence {
    pub steps: Vec<GfxStep>,
}

impl Gfx11Sequence {
    fn write(&mut self, gc_base: u32, dword_reg: u32, value: u32) {
        self.steps.push(GfxStep::Write {
            addr: gc_base + (dword_reg << 2),
            value,
        });
    }
    fn delay(&mut self, us: u32) {
        self.steps.push(GfxStep::Delay { us });
    }
    pub fn len(&self) -> usize {
        self.steps.len()
    }
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
    /// The value written to `dword_reg`, counting from the start. `None` if
    /// the sequence never writes it.
    pub fn first_write_to(&self, gc_base: u32, dword_reg: u32) -> Option<u32> {
        let want = gc_base + (dword_reg << 2);
        self.steps.iter().find_map(|s| match s {
            GfxStep::Write { addr, value } if *addr == want => Some(*value),
            _ => None,
        })
    }
    /// Every value written to `dword_reg`, in order.
    pub fn writes_to(&self, gc_base: u32, dword_reg: u32) -> Vec<u32> {
        let want = gc_base + (dword_reg << 2);
        self.steps
            .iter()
            .filter_map(|s| match s {
                GfxStep::Write { addr, value } if *addr == want => Some(*value),
                _ => None,
            })
            .collect()
    }
    /// Index of the first write to `dword_reg`.
    pub fn index_of_write(&self, gc_base: u32, dword_reg: u32) -> Option<usize> {
        let want = gc_base + (dword_reg << 2);
        self.steps.iter().position(|s| match s {
            GfxStep::Write { addr, .. } => *addr == want,
            _ => false,
        })
    }
}

/// `gfx_v11_0_cp_gfx_resume` for graphics ring 0 on pipe 0 —
/// the register sequence that points the GFX11 command processor at a ring.
///
/// This is NOT the GFX9 sequence in [`build_gfx9_ring_init`]: GFX11 reaches
/// the same registers through different offsets and in a different order, and
/// adds the write-pointer poll address and `CP_RB_ACTIVE` that GFX9 has no
/// equivalent of.
///
/// `gfx_v11_0_cp_gfx_switch_pipe` reads `GRBM_GFX_CNTL` and sets its PIPEID
/// field. Read-modify-write needs the live value, which a sequence cannot
/// carry, so `grbm_gfx_cntl` is passed in — the caller reads it once.
///
/// LINUX-GAP: ring 1 on pipe 1 is not emitted. Linux brings it up when
/// `num_gfx_rings > 1`; one ring is enough to submit, and a second doubles the
/// bring-up surface for no gain until the first works.
///
/// LINUX-GAP: `gfx_v11_0_cp_gfx_start` is not part of this. It writes a PM4
/// `CONTEXT_CONTROL` / `CLEAR_STATE` preamble INTO the ring and rings the
/// doorbell, which needs a live ring object rather than a register list.
#[allow(clippy::too_many_arguments)]
pub fn build_gfx11_ring_init(
    gc_base: u32,
    grbm_gfx_cntl: u32,
    ring_phys: u64,
    ring_size_bytes: u64,
    doorbell_idx: u32,
    use_doorbell: bool,
    rptr_writeback_phys: u64,
    wptr_poll_phys: u64,
) -> Result<Gfx11Sequence, GfxError> {
    // `order_base_2(ring_size / 8)` underflows below 8 bytes, and a
    // non-power-of-two size cannot be described by a log2 field.
    if ring_size_bytes < 8 || !ring_size_bytes.is_power_of_two() {
        return Err(GfxError::BadRingSize);
    }
    // The base register holds the address shifted right by 8.
    if ring_phys & 0xFF != 0 {
        return Err(GfxError::UnalignedRingPhys);
    }
    if rptr_writeback_phys & 0x7 != 0 {
        return Err(GfxError::UnalignedRptrWriteback);
    }

    let mut seq = Gfx11Sequence::default();

    // The write-pointer delay and the ring's VMID, both to zero.
    seq.write(gc_base, GFX11_CP_RB_WPTR_DELAY, 0);
    seq.write(gc_base, GFX11_CP_RB_VMID, 0);

    // Select pipe 0. Read-modify-write of the caller's live value: PIPEID is
    // bits 1:0, and pipe 0 means clearing them.
    let pipe0 = grbm_gfx_cntl & !0x3;
    seq.write(gc_base, GFX11_GRBM_GFX_CNTL, pipe0);

    // `rb_bufsz = order_base_2(ring_size / 8)`.
    //
    // Note this is spelled differently from the MQD's
    // `order_base_2(queue_size / 4) - 1` and means the SAME number — log2 of
    // a quarter is one more than log2 of an eighth. Transcribing one in place
    // of the other produces a ring the hardware believes is twice or half its
    // real size, which is why both are written out as Linux writes them
    // rather than factored into a shared helper.
    let rb_bufsz = (ring_size_bytes / 8).trailing_zeros();
    let cntl = rb_bufsz | (rb_bufsz.wrapping_sub(2) << 8);
    seq.write(gc_base, GFX11_CP_RB0_CNTL, cntl);

    // Write pointer to zero.
    seq.write(gc_base, GFX11_CP_RB0_WPTR, 0);
    seq.write(gc_base, GFX11_CP_RB0_WPTR_HI, 0);

    // Read-pointer writeback, high half masked to 16 bits.
    seq.write(gc_base, GFX11_CP_RB0_RPTR_ADDR, rptr_writeback_phys as u32);
    seq.write(
        gc_base,
        GFX11_CP_RB0_RPTR_ADDR_HI,
        ((rptr_writeback_phys >> 32) as u32) & GFX11_RPTR_ADDR_HI_MASK,
    );

    // Where the CP polls for the host's write pointer. GFX9 has no equivalent.
    seq.write(
        gc_base,
        GFX11_CP_RB_WPTR_POLL_ADDR_LO,
        wptr_poll_phys as u32,
    );
    seq.write(
        gc_base,
        GFX11_CP_RB_WPTR_POLL_ADDR_HI,
        (wptr_poll_phys >> 32) as u32,
    );

    // `mdelay(1)` and then CP_RB0_CNTL AGAIN, with the same value. Linux does
    // this deliberately; the second write latches the configuration after the
    // addresses are in place. Dropping it looks like removing a redundant
    // line.
    seq.delay(1000);
    seq.write(gc_base, GFX11_CP_RB0_CNTL, cntl);

    // The ring base, shifted right by 8.
    let rb_addr = ring_phys >> 8;
    seq.write(gc_base, GFX11_CP_RB0_BASE, rb_addr as u32);
    seq.write(gc_base, GFX11_CP_RB0_BASE_HI, (rb_addr >> 32) as u32);

    // The ring is live.
    seq.write(gc_base, GFX11_CP_RB_ACTIVE, 1);

    // `gfx_v11_0_cp_gfx_set_doorbell`. The control register is a
    // read-modify-write in Linux; its reset value is zero and nothing earlier
    // in this sequence touches it, so composing from zero is the same result.
    let mut doorbell = 0u32;
    if use_doorbell {
        doorbell |= doorbell_idx << GFX11_DOORBELL_OFFSET_SHIFT;
        doorbell |= GFX11_DOORBELL_EN;
    }
    seq.write(gc_base, GFX11_CP_RB_DOORBELL_CONTROL, doorbell);
    seq.write(
        gc_base,
        GFX11_CP_RB_DOORBELL_RANGE_LOWER,
        doorbell_idx << GFX11_DOORBELL_RANGE_LOWER_SHIFT,
    );
    // Linux writes the whole mask here, not `index + 1` — the range is opened
    // to its maximum. The GFX9 sequence in this file writes `index + 1`,
    // which is that era's convention and not this one's.
    seq.write(
        gc_base,
        GFX11_CP_RB_DOORBELL_RANGE_UPPER,
        GFX11_DOORBELL_RANGE_UPPER_MASK,
    );

    Ok(seq)
}
