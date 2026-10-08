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
//!      `RB_SIZE = log2(ring_size_dw)` in bits[5:1] (mask 0x0000003E — five
//!      bits, not six); `RPTR_WRITEBACK_ENABLE` bit 12.
//!   6. **Program doorbell**. `SDMA*_GFX_DOORBELL_OFFSET = idx<<2`
//!      and `SDMA*_GFX_DOORBELL_ENABLE` bit 28 in DOORBELL.
//!   7. **Enable**. Re-write CNTL with `RB_ENABLE` bit 0.
//!
//! SDMA v6.0's sequence is longer than that, not just differently addressed —
//! see [`build_sdma6_ring_init`], which follows
//! `sdma_v6_0.c::sdma_v6_0_gfx_resume_instance` and adds the wptr shadow, the
//! `RB_PRIV` and F32-poll bits, the `MINOR_PTR_UPDATE` bracket and `IB_CNTL`.
//!
//! On v6 the SDMA registers are not their own IP block: they live in GC
//! (`gc_11_0_0_offset.h`), reached through `adev->reg_offset[GC_HWIP][0][0]`,
//! with the `HYP_DEC` range on base index 1 and instance 1 at
//! `SDMA1_REG_OFFSET` 0x600 dwords (`sdma_v6_0_get_reg_offset`).
//!
//! Linux references (GPL-2.0-or-later post-relicense):
//! - `drivers/gpu/drm/amd/amdgpu/sdma_v4_0.c` (Vega / Renoir)
//! - `drivers/gpu/drm/amd/amdgpu/sdma_v6_0.c` (Phoenix)
//! - `sdma0/sdma0_4_0_offset.h` — v4 register defs.
//! - `gc/gc_11_0_0_offset.h`, `gc/gc_11_0_0_sh_mask.h` — v6 register defs.
//! - `sdma_v6_0_0_pkt_open.h` — v6 packet layouts.

extern crate alloc;

use alloc::vec::Vec;

// ── SDMA packet opcodes (sdma_pkt_open.h) ──────────────────────────
//
// Header layout, from `sdma_v6_0_0_pkt_open.h` (and identical in every
// `*_sdma_pkt_open.h` back to iceland):
//
//   op      bits[7:0]    `..._HEADER_op_mask` 0xFF, `_op_shift` 0
//   sub_op  bits[15:8]   `..._HEADER_sub_op_mask` 0xFF, `_sub_op_shift` 8
//   bits[31:16]          per-OP flags
//
// LINUX-GAP: this file's header builder put OP at bits[31:24] and SUB_OP at
// bits[23:16] — the two fields transposed to the other end of the dword. Every
// packet it emitted therefore had op 0 (`SDMA_OP_NOP`) in the low byte with the
// intended opcode sitting among the flags, so a COPY copied nothing and a
// FENCE published nothing. The smoke tests composed their expected header the
// same wrong way (`OP=COPY << 24`), so they passed.

/// `SDMA_OP_NOP` — no-op padding packet.
pub const SDMA_OP_NOP: u32 = 0x00;
/// `SDMA_OP_COPY` — linear or tiled copy.
pub const SDMA_OP_COPY: u32 = 0x01;
/// `SDMA_OP_WRITE` — write immediate dwords to memory.
pub const SDMA_OP_WRITE: u32 = 0x02;
/// `SDMA_OP_FENCE` — write a 32-bit value to memory (fence publish).
pub const SDMA_OP_FENCE: u32 = 0x05;
/// `SDMA_OP_TRAP` — signal an interrupt.
pub const SDMA_OP_TRAP: u32 = 0x06;
/// `SDMA_OP_POLL_REGMEM` — poll register/memory until a condition.
pub const SDMA_OP_POLL_REGMEM: u32 = 0x08;

/// `SDMA_SUBOP_COPY_LINEAR` — default sub-op for `SDMA_OP_COPY`.
pub const SDMA_SUBOP_COPY_LINEAR: u32 = 0x00;
/// `SDMA_SUBOP_WRITE_LINEAR` — default sub-op for `SDMA_OP_WRITE`.
pub const SDMA_SUBOP_WRITE_LINEAR: u32 = 0x00;

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
/// `mmSDMA0_GFX_RB_RPTR_ADDR_HI` (0x0088). Was 0x87, which is
/// `mmSDMA0_GFX_RB_WPTR_POLL_CNTL` — the writeback address's high half was
/// being written into the write-pointer poll control register. The run is
/// NOT contiguous here: 0x87 sits between WPTR_HI and RPTR_ADDR_HI.
pub const SDMA_GFX_RB_RPTR_ADDR_HI_REL: u32 = 0x88 * 4;
/// `mmSDMA0_GFX_RB_RPTR_ADDR_LO` — writeback target lo.
/// `mmSDMA0_GFX_RB_RPTR_ADDR_LO` (0x0089). Was 0x88, which is the HIGH half
/// — so the two halves of the writeback address overwrote each other.
pub const SDMA_GFX_RB_RPTR_ADDR_LO_REL: u32 = 0x89 * 4;
/// `mmSDMA0_GFX_DOORBELL` — per-queue doorbell enable.
pub const SDMA_GFX_DOORBELL_REL: u32 = 0x92 * 4;
/// `mmSDMA0_GFX_DOORBELL_OFFSET` — BAR2 byte offset of the doorbell.
pub const SDMA_GFX_DOORBELL_OFFSET_REL: u32 = 0xAB * 4;

// ── Field encodings ────────────────────────────────────────────────

/// `SDMA*_GFX_RB_CNTL` — enable the ring (host issues this last).
pub const SDMA_RB_ENABLE: u32 = 1 << 0;
/// `SDMA*_GFX_RB_CNTL` — `RB_SIZE` is bits[5:1] (mask 0x0000003E), five bits,
/// holding log2(ring size in dwords). Linux:
/// `rb_bufsz = order_base_2(ring->ring_size / 4)`.
pub const SDMA_RB_SIZE_SHIFT: u32 = 1;
/// `SDMA*_QUEUE0_RB_CNTL__RB_SIZE_MASK` >> `SDMA_RB_SIZE_SHIFT`: the largest
/// log2 the field can hold.
pub const SDMA_RB_SIZE_MAX_LOG2: u32 = 0x3E >> 1;
/// `SDMA*_GFX_RB_CNTL` — gate the rptr writeback DMA.
pub const SDMA_RB_RPTR_WRITEBACK_ENABLE: u32 = 1 << 12;
/// `SDMA*_GFX_DOORBELL` — enable the per-queue doorbell.
///
/// The companion `..._DOORBELL_OFFSET` register's `OFFSET` field sits at bit 2
/// with mask 0x0FFFFFFC, and Linux writes the doorbell INDEX into it
/// (`REG_SET_FIELD(.., OFFSET, ring->doorbell_index)`), so the raw register
/// value is `index << 2` — the doorbell's byte offset, as named.
pub const SDMA_DOORBELL_ENABLE: u32 = 1 << 28;
/// `SDMA*_QUEUE0_RB_CNTL__RB_PRIV` (0x00800000). Linux sets it unconditionally
/// in `sdma_v6_0_gfx_resume_instance`.
pub const SDMA_RB_PRIV: u32 = 1 << 23;
/// `SDMA*_QUEUE0_RB_CNTL__WPTR_POLL_ENABLE` (0x00000100). Linux clears this
/// one and enables the F32 poll instead.
pub const SDMA_RB_WPTR_POLL_ENABLE: u32 = 1 << 8;
/// `SDMA*_QUEUE0_RB_CNTL__F32_WPTR_POLL_ENABLE` (0x00000800) — the engine's
/// F32 polls the host wptr shadow named by `RB_WPTR_POLL_ADDR_LO`/`_HI`.
pub const SDMA_RB_F32_WPTR_POLL_ENABLE: u32 = 1 << 11;
/// `SDMA*_QUEUE0_IB_CNTL__IB_ENABLE` (0x00000001). Without it the engine
/// fetches the ring but refuses every indirect buffer on it.
pub const SDMA_IB_ENABLE: u32 = 1 << 0;
/// `SDMA*_QUEUE0_MINOR_PTR_UPDATE__ENABLE` (0x00000001). Linux brackets the
/// wptr write with this set then cleared: "before programing wptr to a less
/// value, need set minor_ptr_update first".
pub const SDMA_MINOR_PTR_UPDATE_ENABLE: u32 = 1 << 0;

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

// ── SDMA v6.0 (Phoenix HawkPoint1) register offsets ────────────────
//
// Per Linux drivers/gpu/drm/amd/amdgpu/sdma_v6_0.c +
// sdma/sdma_6_0_0_offset.h. Phoenix renames the per-queue
// registers to "QUEUE0_" instead of "GFX_" and shifts most
// offsets. Ring-init shape is identical to v4.

/// `mmSDMA0_QUEUE0_RB_CNTL` (Phoenix).
// SDMA 6.0's register offsets are IDENTICAL to SDMA 4.0's. Only the names
// changed — `mmSDMA0_GFX_*` became `regSDMA0_QUEUE0_*`, and the block moved
// into `gc_11_0_0_offset.h` — so a reader comparing the two headers by name
// finds nothing in common and may conclude the numbers moved too. They did
// not. This table held 0x1F..0x2D, which matches neither generation.
pub const SDMA6_QUEUE0_RB_CNTL_REL: u32 = 0x80 * 4;
/// `regSDMA0_QUEUE0_RB_BASE` (0x0081).
pub const SDMA6_QUEUE0_RB_BASE_REL: u32 = 0x81 * 4;
/// `regSDMA0_QUEUE0_RB_BASE_HI` (0x0082).
pub const SDMA6_QUEUE0_RB_BASE_HI_REL: u32 = 0x82 * 4;
/// `regSDMA0_QUEUE0_RB_RPTR` (0x0083).
pub const SDMA6_QUEUE0_RB_RPTR_REL: u32 = 0x83 * 4;
/// `regSDMA0_QUEUE0_RB_RPTR_HI` (0x0084).
pub const SDMA6_QUEUE0_RB_RPTR_HI_REL: u32 = 0x84 * 4;
/// `regSDMA0_QUEUE0_RB_WPTR` (0x0085).
pub const SDMA6_QUEUE0_RB_WPTR_REL: u32 = 0x85 * 4;
/// `regSDMA0_QUEUE0_RB_WPTR_HI` (0x0086).
pub const SDMA6_QUEUE0_RB_WPTR_HI_REL: u32 = 0x86 * 4;
/// `regSDMA0_QUEUE0_RB_RPTR_ADDR_HI` (0x0088) — 0x87 is WPTR_POLL_CNTL.
pub const SDMA6_QUEUE0_RB_RPTR_ADDR_HI_REL: u32 = 0x88 * 4;
/// `regSDMA0_QUEUE0_RB_RPTR_ADDR_LO` (0x0089).
pub const SDMA6_QUEUE0_RB_RPTR_ADDR_LO_REL: u32 = 0x89 * 4;
/// `regSDMA0_QUEUE0_DOORBELL` (0x0092).
pub const SDMA6_QUEUE0_DOORBELL_REL: u32 = 0x92 * 4;
/// `regSDMA0_QUEUE0_DOORBELL_OFFSET` (0x00ab).
pub const SDMA6_QUEUE0_DOORBELL_OFFSET_REL: u32 = 0xAB * 4;
/// `regSDMA0_QUEUE0_IB_CNTL` (0x008a).
pub const SDMA6_QUEUE0_IB_CNTL_REL: u32 = 0x8A * 4;
/// `regSDMA0_QUEUE0_RB_WPTR_POLL_ADDR_HI` (0x00b2) — **below** `_LO`, like
/// `IH_RB_WPTR_ADDR_HI`. Not inferrable from the LO offset.
pub const SDMA6_QUEUE0_RB_WPTR_POLL_ADDR_HI_REL: u32 = 0xB2 * 4;
/// `regSDMA0_QUEUE0_RB_WPTR_POLL_ADDR_LO` (0x00b3).
pub const SDMA6_QUEUE0_RB_WPTR_POLL_ADDR_LO_REL: u32 = 0xB3 * 4;
/// `regSDMA0_QUEUE0_MINOR_PTR_UPDATE` (0x00b5).
pub const SDMA6_QUEUE0_MINOR_PTR_UPDATE_REL: u32 = 0xB5 * 4;

/// Build the SDMA v6.0 ring-init sequence for queue 0 of one instance.
///
/// Follows `sdma_v6_0.c::sdma_v6_0_gfx_resume_instance` step for step:
///
///   1. `RB_CNTL = 0` — stop the engine fetching while the base moves.
///   2. Zero `RB_RPTR`/`_HI` and `RB_WPTR`/`_HI`.
///   3. `RB_WPTR_POLL_ADDR_LO`/`_HI` — the host wptr shadow the engine's F32
///      polls. Note `_HI` is the LOWER register id of the pair.
///   4. `RB_RPTR_ADDR_LO`/`_HI` — the rptr writeback target. Linux masks the
///      low half with 0xFFFFFFFC, so the bottom two bits never reach it.
///   5. `RB_CNTL` with `RB_SIZE`, `RB_PRIV`, `RPTR_WRITEBACK_ENABLE` and
///      `F32_WPTR_POLL_ENABLE`, with `WPTR_POLL_ENABLE` left clear — Linux
///      enables the F32 poll and not the legacy one.
///   6. `RB_BASE = phys >> 8`, `RB_BASE_HI = phys >> 40`.
///   7. `MINOR_PTR_UPDATE = 1`, then the wptr write, then `= 0`. Linux:
///      "before programing wptr to a less value, need set minor_ptr_update
///      first".
///   8. `DOORBELL_OFFSET` and `DOORBELL` with `ENABLE`.
///   9. `RB_CNTL |= RB_ENABLE`.
///  10. `IB_CNTL = IB_ENABLE`.
///
/// Step 10 and the `RB_PRIV` / poll bits in step 5 and the step-7 bracket were
/// all missing, so the ring would have come up unprivileged, with no wptr
/// shadow, and refusing every indirect buffer submitted to it.
///
/// LINUX-GAP: three groups of writes Linux also makes are not here.
/// `SDMA0_F32_CNTL` (`HALT = 0`, `TH1_RESET = 0`) is `regSDMA0_F32_CNTL`
/// 0x589a on **BASE_IDX 1**, while every `QUEUE0_*` register above is
/// BASE_IDX 0 — `sdma_v6_0_get_reg_offset` picks the second GC segment for
/// that range — so it cannot be addressed from this function's single
/// `sdma_base`, and un-halting the engine belongs with firmware load anyway.
/// `WATCHDOG_CNTL` and `UTCL1_CNTL`/`UTCL1_PAGE` are timeout and
/// address-translation tuning left at their reset values. `RB_SWAP_ENABLE` and
/// `IB_SWAP_ENABLE` are big-endian only.
///
/// `sdma_base` is the GC IP block's BASE_IDX-0 base, in bytes
/// (`adev->reg_offset[GC_HWIP][0][0]` — SDMA 6 registers live in the GC
/// block). Instance 1 would add `SDMA1_REG_OFFSET` 0x600 dwords.
pub fn build_sdma6_ring_init(
    sdma_base: u32,
    ring_phys: u64,
    ring_size_dw: u32,
    doorbell_idx: u32,
    rptr_writeback_phys: u64,
    wptr_poll_phys: u64,
) -> Result<SdmaRingInitSequence, SdmaError> {
    if !ring_size_dw.is_power_of_two()
        || !(8..=(1 << SDMA_RB_SIZE_MAX_LOG2)).contains(&ring_size_dw)
    {
        return Err(SdmaError::BadRingSize);
    }
    if ring_phys & 0xFF != 0 {
        return Err(SdmaError::UnalignedRingPhys);
    }
    if rptr_writeback_phys & 0x3 != 0 || wptr_poll_phys & 0x3 != 0 {
        return Err(SdmaError::UnalignedRptrWriteback);
    }
    let mut seq = SdmaRingInitSequence::default();
    seq.push(sdma_base + SDMA6_QUEUE0_RB_CNTL_REL, 0);
    seq.push(sdma_base + SDMA6_QUEUE0_RB_RPTR_REL, 0);
    seq.push(sdma_base + SDMA6_QUEUE0_RB_RPTR_HI_REL, 0);
    seq.push(sdma_base + SDMA6_QUEUE0_RB_WPTR_REL, 0);
    seq.push(sdma_base + SDMA6_QUEUE0_RB_WPTR_HI_REL, 0);
    seq.push(
        sdma_base + SDMA6_QUEUE0_RB_WPTR_POLL_ADDR_LO_REL,
        wptr_poll_phys as u32,
    );
    seq.push(
        sdma_base + SDMA6_QUEUE0_RB_WPTR_POLL_ADDR_HI_REL,
        (wptr_poll_phys >> 32) as u32,
    );
    seq.push(
        sdma_base + SDMA6_QUEUE0_RB_RPTR_ADDR_LO_REL,
        rptr_writeback_phys as u32 & 0xFFFF_FFFC,
    );
    seq.push(
        sdma_base + SDMA6_QUEUE0_RB_RPTR_ADDR_HI_REL,
        (rptr_writeback_phys >> 32) as u32,
    );
    let log2_size = ring_size_dw.trailing_zeros();
    let cntl_no_enable = (log2_size << SDMA_RB_SIZE_SHIFT)
        | SDMA_RB_PRIV
        | SDMA_RB_RPTR_WRITEBACK_ENABLE
        | SDMA_RB_F32_WPTR_POLL_ENABLE;
    seq.push(sdma_base + SDMA6_QUEUE0_RB_CNTL_REL, cntl_no_enable);
    seq.push(
        sdma_base + SDMA6_QUEUE0_RB_BASE_REL,
        (ring_phys >> 8) as u32,
    );
    seq.push(
        sdma_base + SDMA6_QUEUE0_RB_BASE_HI_REL,
        (ring_phys >> 40) as u32,
    );
    seq.push(
        sdma_base + SDMA6_QUEUE0_MINOR_PTR_UPDATE_REL,
        SDMA_MINOR_PTR_UPDATE_ENABLE,
    );
    seq.push(sdma_base + SDMA6_QUEUE0_RB_WPTR_REL, 0);
    seq.push(sdma_base + SDMA6_QUEUE0_RB_WPTR_HI_REL, 0);
    seq.push(
        sdma_base + SDMA6_QUEUE0_DOORBELL_OFFSET_REL,
        doorbell_idx << 2,
    );
    seq.push(sdma_base + SDMA6_QUEUE0_DOORBELL_REL, SDMA_DOORBELL_ENABLE);
    seq.push(sdma_base + SDMA6_QUEUE0_MINOR_PTR_UPDATE_REL, 0);
    seq.push(
        sdma_base + SDMA6_QUEUE0_RB_CNTL_REL,
        cntl_no_enable | SDMA_RB_ENABLE,
    );
    seq.push(sdma_base + SDMA6_QUEUE0_IB_CNTL_REL, SDMA_IB_ENABLE);
    Ok(seq)
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
    if !ring_size_dw.is_power_of_two() || !(8..=(1 << 20)).contains(&ring_size_dw) {
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
    seq.push(sdma_base + SDMA_GFX_DOORBELL_OFFSET_REL, doorbell_idx << 2);
    seq.push(sdma_base + SDMA_GFX_DOORBELL_REL, SDMA_DOORBELL_ENABLE);

    // Step 7: re-write CNTL with RB_ENABLE set — engine starts fetching.
    seq.push(
        sdma_base + SDMA_GFX_RB_CNTL_REL,
        cntl_no_enable | SDMA_RB_ENABLE,
    );

    Ok(seq)
}

// ── SDMA packet builder ────────────────────────────────────────────
//
// Mirror of [`crate::amdgpu_pm4::Pm4Builder`] for the SDMA command
// stream. SDMA packets are pushed onto an SDMA ring (allocated +
// brought up via build_sdma4_ring_init above), and the engine
// fetches + executes them asynchronously from the CP. Useful for
// host↔VRAM memcopy without burning GFX cycles.

/// Errors from SDMA packet construction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SdmaPktError {
    /// Output buffer too small for the packet being built.
    OutOfRoom,
    /// Linear copy byte count exceeds this generation's per-packet limit —
    /// `SdmaGeneration::copy_max_bytes`.
    CopyTooLarge,
    /// Copy byte count of zero — no-op copies don't go through
    /// COPY; use NOP if padding is needed.
    EmptyCopy,
    /// A `FENCE` target that is not dword-aligned. The engine ignores the low
    /// two bits of the address, so the value would land elsewhere.
    UnalignedFence,
}

/// Which SDMA generation's packet encoding to emit. Two of the fields this
/// builder writes are generation-dependent, so a builder has to know:
///
///   * `COPY_LINEAR`'s COUNT width. `vega10_sdma_pkt_open.h` gives
///     `SDMA_PKT_COPY_LINEAR_COUNT_count_mask` 0x003FFFFF (22 bits) and
///     `sdma_v4_0.c:2612` `.copy_max_bytes = 1 << 22`;
///     `sdma_v6_0_0_pkt_open.h:152` widens the mask to 0x3FFFFFFF and
///     `sdma_v6_0.c:1861` sets `.copy_max_bytes = 1 << 30`.
///   * `FENCE`'s MTYPE. v4 has no such field at all — `vega10_sdma_pkt_open.h`
///     does not define it and `sdma_v4_0_ring_emit_fence` writes a bare
///     `SDMA_PKT_HEADER_OP(SDMA_OP_FENCE)`. From v5.0 on, every generation
///     writes `SDMA_PKT_FENCE_HEADER_MTYPE(0x3)` — uncached — so the fence the
///     host polls is not left sitting in a cache.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SdmaGeneration {
    /// SDMA v4.0 — Vega, Renoir, Cezanne.
    V4,
    /// SDMA v6.0 — Phoenix. Also correct for v5.x and v7.x on both fields.
    V6,
}

impl SdmaGeneration {
    /// Largest `byte_count` one `SDMA_OP_COPY` packet can carry. COUNT holds
    /// `byte_count - 1`, so a 22-bit field tops out at exactly `1 << 22`.
    pub const fn copy_max_bytes(self) -> u32 {
        match self {
            SdmaGeneration::V4 => 1 << 22,
            SdmaGeneration::V6 => 1 << 30,
        }
    }

    /// The `FENCE` header's MTYPE field, already shifted into place, or 0 on a
    /// generation that has no such field.
    pub const fn fence_mtype(self) -> u32 {
        match self {
            SdmaGeneration::V4 => 0,
            SdmaGeneration::V6 => FENCE_MTYPE_UC << FENCE_MTYPE_SHIFT,
        }
    }
}

/// `SDMA_PKT_FENCE_HEADER_mtype_shift` — bits[18:16], mask 0x7.
pub const FENCE_MTYPE_SHIFT: u32 = 16;
/// MTYPE 3, which Linux annotates `/* Ucached(UC) */`.
pub const FENCE_MTYPE_UC: u32 = 0x3;
/// `SDMA_PKT_TRAP_INT_CONTEXT_int_context_mask` — bits[27:0].
pub const TRAP_INT_CONTEXT_MASK: u32 = 0x0FFF_FFFF;

/// SDMA packet builder. Writes 32-bit words into `out`.
#[derive(Debug)]
pub struct SdmaBuilder<'a> {
    out: &'a mut [u32],
    pos: usize,
    generation: SdmaGeneration,
}

impl<'a> SdmaBuilder<'a> {
    pub fn new(out: &'a mut [u32], generation: SdmaGeneration) -> Self {
        Self {
            out,
            pos: 0,
            generation,
        }
    }

    pub fn bytes_written(&self) -> usize {
        self.pos * 4
    }

    fn push(&mut self, w: u32) -> Result<(), SdmaPktError> {
        if self.pos >= self.out.len() {
            return Err(SdmaPktError::OutOfRoom);
        }
        self.out[self.pos] = w;
        self.pos += 1;
        Ok(())
    }

    /// `..._HEADER_OP(op) | ..._HEADER_SUB_OP(sub_op)`: op in bits[7:0],
    /// sub_op in bits[15:8]. See the header-layout note at the top of this
    /// file for what this used to be.
    fn header(op: u32, sub_op: u32) -> u32 {
        (op & 0xFF) | ((sub_op & 0xFF) << 8)
    }

    /// `SDMA_OP_NOP` — emit one no-op header. Useful for padding
    /// the ring before a wrap.
    pub fn nop(&mut self) -> Result<(), SdmaPktError> {
        self.push(Self::header(SDMA_OP_NOP, 0))
    }

    /// `SDMA_OP_COPY` linear → linear. Copies `byte_count` bytes
    /// from `src` to `dst`. Both addresses are bus-physical and
    /// should be 4-byte aligned (SDMA serves smaller alignments
    /// but throughput tanks).
    ///
    /// Packet shape (v4): 7 dwords (header + count + reserved +
    /// src lo/hi + dst lo/hi).
    pub fn copy_linear(&mut self, src: u64, dst: u64, byte_count: u32) -> Result<(), SdmaPktError> {
        if byte_count == 0 {
            return Err(SdmaPktError::EmptyCopy);
        }
        if byte_count > self.generation.copy_max_bytes() {
            return Err(SdmaPktError::CopyTooLarge);
        }
        self.push(Self::header(SDMA_OP_COPY, SDMA_SUBOP_COPY_LINEAR))?;
        // COUNT is byte_count - 1: 22 bits on v4, 30 on v6.
        self.push(byte_count - 1)?;
        // Reserved dword — src/dst endian swap, 0 on little-endian hosts.
        self.push(0)?;
        self.push(src as u32)?;
        self.push((src >> 32) as u32)?;
        self.push(dst as u32)?;
        self.push((dst >> 32) as u32)?;
        Ok(())
    }

    /// `SDMA_OP_FENCE` — write a 32-bit value to memory. Used to
    /// publish a fence after a COPY completes; the SDMA engine
    /// drains the FENCE only after preceding packets retire.
    ///
    /// Packet shape (v4): 4 dwords (header + dst lo + dst hi + value).
    pub fn fence(&mut self, dst: u64, value: u32) -> Result<(), SdmaPktError> {
        // Linux WARN_ONs `addr & 0x3` — the engine ignores the low two bits,
        // so a misaligned target silently publishes somewhere else.
        if dst & 0x3 != 0 {
            return Err(SdmaPktError::UnalignedFence);
        }
        self.push(Self::header(SDMA_OP_FENCE, 0) | self.generation.fence_mtype())?;
        self.push(dst as u32)?;
        self.push((dst >> 32) as u32)?;
        self.push(value)?;
        Ok(())
    }

    /// `SDMA_OP_TRAP` — signal an interrupt back to host. Argument
    /// is passed through the ack register on real silicon (here we
    /// just encode it). Packet shape: 2 dwords (header + ack).
    pub fn trap(&mut self, ack: u32) -> Result<(), SdmaPktError> {
        self.push(Self::header(SDMA_OP_TRAP, 0))?;
        self.push(ack & TRAP_INT_CONTEXT_MASK)?;
        Ok(())
    }
}
