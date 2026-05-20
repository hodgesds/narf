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
pub const CP_ME_CNTL_HALT_ALL: u32 =
    CP_ME_CNTL_PFP_HALT | CP_ME_CNTL_CE_HALT | CP_ME_CNTL_ME_HALT;

/// `CP_RB0_RPTR_ADDR_HI` — gate the writeback DMA through the
/// L2 cache (bit 0) and snoop coherent (bit 1). Linux ORs both.
pub const RPTR_WRITEBACK_COHERENT: u32 = 0x3;

/// `CP_RB_DOORBELL_CONTROL` — enable the per-queue doorbell.
pub const CP_RB_DOORBELL_EN: u32 = 1 << 30;
/// `CP_RB_DOORBELL_CONTROL` — doorbell offset shift.
pub const CP_RB_DOORBELL_OFFSET_SHIFT: u32 = 2;

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
    seq.push(
        gc_base + CP_RB0_CNTL_REL,
        log2_size | (blksz << 8),
    );

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
