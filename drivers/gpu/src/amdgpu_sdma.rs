//! AMD SDMA (System DMA) ring bring-up.
//!
//! SDMA is the asynchronous DMA copy engine. Bigger than the
//! CP for raw memcopy throughput, used by the host driver for
//! VRAM↔system memory transfers — paging GTT/VRAM, framebuffer
//! staging, GART population. Has its own command stream
//! (SDMA packets, not PM4) and its own ring registers.
//!
//! On Vega / Renoir / Cezanne (SDMA v4.0) two SDMA instances live
//! at separate IP-block bases (SDMA0 + SDMA1); Phoenix exposes
//! one SDMA v6.0 instance. The ring-init shape is the same
//! across instances and across versions — only the register
//! offsets shift.
//!
//! ## Sequence (SDMA v4.0 — Vega / Renoir)
//!
//! Per `drivers/gpu/drm/amd/amdgpu/sdma_v4_0.c::sdma_v4_0_gfx_resume_instance()`:
//!
//!   1. **Disable the ring**. `SDMA*_GFX_RB_CNTL = 0` clears
//!      RB_ENABLE so the engine won't fetch while we re-program
//!      base / size.
//!   2. **Reset r/wptr**. `SDMA*_GFX_RB_RPTR = 0;
//!      SDMA*_GFX_RB_WPTR = 0`.
//!   3. **Program ring base**. `SDMA*_GFX_RB_BASE = phys >> 8`
//!      (the low 8 bits are implicit) and
//!      `SDMA*_GFX_RB_BASE_HI = phys >> 40`.
//!   4. **Program rptr writeback**. `SDMA*_GFX_RB_RPTR_ADDR_LO`
//!      / `_HI` — host buffer the SDMA writes back to so the
//!      host knows what's drained.
//!   5. **Program ring size + rptr writeback enable**. CNTL bits:
//!      `RB_SIZE = log2(ring_size_dw)` in bits[6:1];
//!      `RPTR_WRITEBACK_ENABLE` bit 12.
//!   6. **Program doorbell**. `SDMA*_GFX_DOORBELL_OFFSET = idx<<2`
//!      and `SDMA*_GFX_DOORBELL_ENABLE` bit 28 in DOORBELL.
//!   7. **Enable**. Re-write CNTL with `RB_ENABLE` bit 0.
//!
//! Linux references (GPL-2.0-or-later post-relicense):
//! - `drivers/gpu/drm/amd/amdgpu/sdma_v4_0.c` (Vega / Renoir)
//! - `drivers/gpu/drm/amd/amdgpu/sdma_v6_0.c` (Phoenix)
//! - `sdma0/sdma0_4_0_offset.h` — register defs.

extern crate alloc;

use alloc::vec::Vec;

// ── SDMA v4.0 register offsets (dword-indexed, multiply by 4 for byte) ──
//
// Values from sdma0/sdma0_4_0_offset.h. Relative to the SDMA
// instance's IP-block base.

/// `mmSDMA0_GFX_RB_CNTL` — ring config + enable.
pub const SDMA_GFX_RB_CNTL_REL: u32 = 0x80 * 4;
/// `mmSDMA0_GFX_RB_BASE` — phys >> 8.
pub const SDMA_GFX_RB_BASE_REL: u32 = 0x81 * 4;
/// `mmSDMA0_GFX_RB_BASE_HI` — phys >> 40.
pub const SDMA_GFX_RB_BASE_HI_REL: u32 = 0x82 * 4;
/// `mmSDMA0_GFX_RB_RPTR` — engine-written rptr.
pub const SDMA_GFX_RB_RPTR_REL: u32 = 0x83 * 4;
/// `mmSDMA0_GFX_RB_RPTR_HI` — high bits of rptr (64-bit on v4).
pub const SDMA_GFX_RB_RPTR_HI_REL: u32 = 0x84 * 4;
/// `mmSDMA0_GFX_RB_WPTR` — host-written wptr.
pub const SDMA_GFX_RB_WPTR_REL: u32 = 0x85 * 4;
/// `mmSDMA0_GFX_RB_WPTR_HI` — high bits of wptr.
pub const SDMA_GFX_RB_WPTR_HI_REL: u32 = 0x86 * 4;
/// `mmSDMA0_GFX_RB_RPTR_ADDR_HI` — writeback target hi.
pub const SDMA_GFX_RB_RPTR_ADDR_HI_REL: u32 = 0x87 * 4;
/// `mmSDMA0_GFX_RB_RPTR_ADDR_LO` — writeback target lo.
pub const SDMA_GFX_RB_RPTR_ADDR_LO_REL: u32 = 0x88 * 4;
/// `mmSDMA0_GFX_DOORBELL` — per-queue doorbell enable.
pub const SDMA_GFX_DOORBELL_REL: u32 = 0x92 * 4;
/// `mmSDMA0_GFX_DOORBELL_OFFSET` — BAR2 byte offset of the doorbell.
pub const SDMA_GFX_DOORBELL_OFFSET_REL: u32 = 0xAB * 4;

// ── Field encodings ────────────────────────────────────────────────

/// `SDMA*_GFX_RB_CNTL` — enable the ring (host issues this last).
pub const SDMA_RB_ENABLE: u32 = 1 << 0;
/// `SDMA*_GFX_RB_CNTL` — bits[6:1] = log2(ring size in dwords).
pub const SDMA_RB_SIZE_SHIFT: u32 = 1;
/// `SDMA*_GFX_RB_CNTL` — gate the rptr writeback DMA.
pub const SDMA_RB_RPTR_WRITEBACK_ENABLE: u32 = 1 << 12;
/// `SDMA*_GFX_DOORBELL` — enable the per-queue doorbell.
pub const SDMA_DOORBELL_ENABLE: u32 = 1 << 28;

// ── Sequence shape ─────────────────────────────────────────────────

/// Errors building the SDMA ring-init sequence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SdmaError {
    /// `ring_size_dw` isn't a power of two between 8 and `1 << 20`.
    BadRingSize,
    /// `ring_phys` isn't 256-byte aligned. SDMA RB_BASE encodes
    /// `phys >> 8`; the low 8 bits must be zero.
    UnalignedRingPhys,
    /// `rptr_writeback_phys` isn't 4-byte aligned. The writeback
    /// target is a 32-bit dword.
    UnalignedRptrWriteback,
}

/// One MMIO write in an SDMA ring-init sequence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SdmaWrite {
    /// Register-bus address (sdma_base + register offset, in BAR5
    /// byte address space).
    pub addr: u32,
    pub value: u32,
}

/// Ordered list of SDMA register writes to bring up one ring.
#[derive(Default, Debug)]
pub struct SdmaRingInitSequence {
    pub writes: Vec<SdmaWrite>,
}

impl SdmaRingInitSequence {
    pub fn len(&self) -> usize {
        self.writes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }
    pub fn iter(&self) -> core::slice::Iter<'_, SdmaWrite> {
        self.writes.iter()
    }
    fn push(&mut self, addr: u32, value: u32) {
        self.writes.push(SdmaWrite { addr, value });
    }
}

/// Build the SDMA v4.0 ring-init sequence. `sdma_base` is the
/// IP-block base of one SDMA instance (SDMA0 or SDMA1 on Renoir;
/// just SDMA0 on Phoenix v6.0 with adjusted offsets — caller
/// picks the right base via IP discovery).
pub fn build_sdma4_ring_init(
    sdma_base: u32,
    ring_phys: u64,
    ring_size_dw: u32,
    doorbell_idx: u32,
    rptr_writeback_phys: u64,
) -> Result<SdmaRingInitSequence, SdmaError> {
    if !ring_size_dw.is_power_of_two() || ring_size_dw < 8 || ring_size_dw > (1 << 20) {
        return Err(SdmaError::BadRingSize);
    }
    if ring_phys & 0xFF != 0 {
        return Err(SdmaError::UnalignedRingPhys);
    }
    if rptr_writeback_phys & 0x3 != 0 {
        return Err(SdmaError::UnalignedRptrWriteback);
    }

    let mut seq = SdmaRingInitSequence::default();

    // Step 1: disable.
    seq.push(sdma_base + SDMA_GFX_RB_CNTL_REL, 0);

    // Step 2: reset r/wptr (both 64-bit on v4).
    seq.push(sdma_base + SDMA_GFX_RB_RPTR_REL, 0);
    seq.push(sdma_base + SDMA_GFX_RB_RPTR_HI_REL, 0);
    seq.push(sdma_base + SDMA_GFX_RB_WPTR_REL, 0);
    seq.push(sdma_base + SDMA_GFX_RB_WPTR_HI_REL, 0);

    // Step 3: ring base. SDMA encodes (phys >> 8) in BASE, then
    // bits[63:40] of phys in BASE_HI.
    seq.push(sdma_base + SDMA_GFX_RB_BASE_REL, (ring_phys >> 8) as u32);
    seq.push(
        sdma_base + SDMA_GFX_RB_BASE_HI_REL,
        (ring_phys >> 40) as u32,
    );

    // Step 4: rptr writeback target (split as LO/HI on v4).
    seq.push(
        sdma_base + SDMA_GFX_RB_RPTR_ADDR_LO_REL,
        rptr_writeback_phys as u32,
    );
    seq.push(
        sdma_base + SDMA_GFX_RB_RPTR_ADDR_HI_REL,
        (rptr_writeback_phys >> 32) as u32,
    );

    // Step 5: program size + enable writeback (but NOT RB_ENABLE
    // yet — step 7 enables the ring as the last write so the
    // engine doesn't start fetching against a half-programmed
    // doorbell window).
    let log2_size = ring_size_dw.trailing_zeros();
    let cntl_no_enable = (log2_size << SDMA_RB_SIZE_SHIFT) | SDMA_RB_RPTR_WRITEBACK_ENABLE;
    seq.push(sdma_base + SDMA_GFX_RB_CNTL_REL, cntl_no_enable);

    // Step 6: doorbell offset + enable.
    seq.push(
        sdma_base + SDMA_GFX_DOORBELL_OFFSET_REL,
        doorbell_idx << 2,
    );
    seq.push(sdma_base + SDMA_GFX_DOORBELL_REL, SDMA_DOORBELL_ENABLE);

    // Step 7: re-write CNTL with RB_ENABLE set — engine starts fetching.
    seq.push(
        sdma_base + SDMA_GFX_RB_CNTL_REL,
        cntl_no_enable | SDMA_RB_ENABLE,
    );

    Ok(seq)
}
