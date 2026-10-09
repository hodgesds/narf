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

use crate::amdgpu_mqd::MqdProp;
use crate::amdgpu_pm4::{Pm4Builder, Pm4Error};
use crate::amdgpu_ring::{Ring, RingError};

// ── CP register offsets (GFX9, relative to GC block base 0) ────────
//
// Every value here is the dword register id from `gc/gc_9_0_offset.h`, times
// four for the byte offset. They were ALL wrong — not off by a base, but
// naming other real registers: `CP_ME_CNTL` was 0x103D, which is
// `mmCPC_UTCL1_CNTL`, and `CP_RB0_BASE` was 0x107E, which is
// `mmGB_EDC_MODE`. The old header comment claimed they came from
// `gc_9_0_offset.h`; they match no AMD header of any generation (GFX9 has
// CP_RB0_BASE at 0x1040, GFX10 and GFX11 at 0x1de0). So `build_gfx9_ring_init`
// was writing ring configuration into the memory-error-detection and UTCL1
// cache-control registers.
//
// ## Base windows
//
// A SOC15-era register is addressed as `reg_offset[GC][0][BASE_IDX] + id`,
// and `BASE_IDX` is per register. Everything in this block is BASE_IDX 0, so
// one `gc_base` addresses them all; the two constants below that are
// BASE_IDX 1 say so, because adding them to the wrong window lands on an
// unrelated register.

/// `mmCP_ME_CNTL` (0x01b6, BASE_IDX 0) — halt / unhalt the three CP engines.
pub const CP_ME_CNTL_REL: u32 = 0x01B6 * 4;
/// `mmCP_RB0_BASE` (0x1040, BASE_IDX 0) — ring address, shifted right by 8.
pub const CP_RB0_BASE_REL: u32 = 0x1040 * 4;
/// `mmCP_RB0_BASE_HI` (0x10b1, BASE_IDX 0).
pub const CP_RB0_BASE_HI_REL: u32 = 0x10B1 * 4;
/// `mmCP_RB0_CNTL` (0x1041, BASE_IDX 0) — ring size + block size.
pub const CP_RB0_CNTL_REL: u32 = 0x1041 * 4;
/// `mmCP_RB0_RPTR_ADDR` (0x1043, BASE_IDX 0) — rptr writeback, low.
pub const CP_RB0_RPTR_ADDR_REL: u32 = 0x1043 * 4;
/// `mmCP_RB0_RPTR_ADDR_HI` (0x1044, BASE_IDX 0) — rptr writeback, high 16.
pub const CP_RB0_RPTR_ADDR_HI_REL: u32 = 0x1044 * 4;
/// `mmCP_RB0_WPTR` (0x1054, BASE_IDX 0).
pub const CP_RB0_WPTR_REL: u32 = 0x1054 * 4;
/// `mmCP_RB0_WPTR_HI` (0x1055, BASE_IDX 0).
pub const CP_RB0_WPTR_HI_REL: u32 = 0x1055 * 4;
/// `mmCP_RB_DOORBELL_CONTROL` (0x1059, BASE_IDX 0).
pub const CP_RB_DOORBELL_CONTROL_REL: u32 = 0x1059 * 4;
/// `mmCP_RB_DOORBELL_RANGE_LOWER` (0x105a, BASE_IDX 0).
pub const CP_RB_DOORBELL_RANGE_LOWER_REL: u32 = 0x105A * 4;
/// `mmCP_RB_DOORBELL_RANGE_UPPER` (0x105b, BASE_IDX 0).
pub const CP_RB_DOORBELL_RANGE_UPPER_REL: u32 = 0x105B * 4;

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

/// GFX9 `mmGRBM_STATUS` (0x0004, BASE_IDX 0) — busy bitfield over CP/RLC/SE.
///
/// Was 0x0DA0, which is not `GRBM_STATUS` on GFX9 — 0x0da4 is its GFX11
/// offset, so this looks like the GFX11 value transcribed four short and then
/// applied to the wrong generation.
pub const GRBM_STATUS_REL_GFX9: u32 = 0x0004 * 4;
/// GFX11 `regGRBM_STATUS` (0x0da4, BASE_IDX 0).
///
/// Was 0x1A40, which is `regSPI_SHADER_USER_DATA_GS_20` — a shader
/// user-data register. The chip-liveness probe that reads this was therefore
/// reading shader state and calling it a GRBM status word.
pub const GRBM_STATUS_REL_GFX11: u32 = 0x0DA4 * 4;
/// `GRBM_GFX_INDEX` (0x2200) — SE/SH/CU broadcast mask. Same id on GFX9 and
/// GFX11, as the old comment claimed; the VALUE was 0x2A00, which on GFX11 is
/// `regCP_GFX_CNTL`.
///
/// **BASE_IDX 1.** Adding this to the GC window used for every other constant
/// in this file lands somewhere else entirely; see [`GC_BASE_IDX_1`].
pub const GRBM_GFX_INDEX_REL: u32 = 0x2200 * 4;

/// Marker for the registers above that live in GC base window **1** rather
/// than 0, and so cannot be reached from the same `gc_base`.
///
/// LINUX-GAP: nothing in this file resolves window 1. A SOC15 register is
/// addressed as `reg_offset[GC][0][BASE_IDX] + id`, and IP discovery supplies
/// both windows in `IpBlock::base_addrs`, but the helpers here take a single
/// `gc_base`. The two BASE_IDX 1 registers are declared so a caller cannot
/// use one by accident believing it is reachable; wiring the second window
/// through is the fix.
pub const GC_BASE_IDX_1: &[&str] = &["GRBM_GFX_INDEX", "CP_GFX_CNTL", "GRBM_GFX_CNTL"];

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
/// `GRBM_STATUS.ANY_ACTIVE` (0x08000000).
pub const GRBM_STATUS_ANY_ACTIVE: u32 = 1 << 27;
/// `GRBM_STATUS.DB_BUSY` (0x04000000) — the depth block.
///
/// LINUX-GAP: this bit was named `GRBM_STATUS_RLC_BUSY` and read back by
/// `GrbmStatus::rlc_busy`. `GRBM_STATUS` has no `RLC_BUSY` field on either
/// generation — neither `gc_9_0_sh_mask.h` nor `gc_11_0_0_sh_mask.h` defines
/// one — and bit 26 of it is `DB_BUSY`. The RLC's busy bit lives in
/// `GRBM_STATUS2`, and even there it moves between generations; see
/// [`GfxGeneration::grbm_status2_rlc_busy`]. So the idle check that gated
/// touching `CP_RB0_BASE` was waiting on the depth block, and `rlc_busy()`
/// answered about the wrong unit entirely.
pub const GRBM_STATUS_DB_BUSY: u32 = 1 << 26;
/// `GRBM_STATUS.GDS_BUSY` — Global Data Share busy.
pub const GRBM_STATUS_GDS_BUSY: u32 = 1 << 15;

/// Which GFX generation a register window or bit position belongs to. The two
/// this driver carries tables for do not agree on either, so the ones that
/// move are selected here rather than being `_GFX9`/`_GFX11` constants a caller
/// might pick the wrong one of.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GfxGeneration {
    /// GFX9 — Vega, Renoir, Cezanne. `gc_9_0_offset.h`.
    Gfx9,
    /// GFX11 — Phoenix, Navi3x. `gc_11_0_0_offset.h`.
    Gfx11,
}

impl GfxGeneration {
    /// `GRBM_STATUS` — 0x0004 on GFX9, 0x0da4 on GFX11, BASE_IDX 0 on both.
    ///
    /// Returns the byte offset and the GC window, the same shape as
    /// [`GfxGeneration::cp_me_cntl_rel`]. The window is part of a register's
    /// address, not a property of the block, so it travels with the offset
    /// rather than being decided at the call site — which is how
    /// `GRBM_GFX_INDEX` came to be addressed from window 0.
    pub const fn grbm_status_rel(self) -> (u32, usize) {
        match self {
            GfxGeneration::Gfx9 => (0x0004 * 4, 0),
            GfxGeneration::Gfx11 => (0x0DA4 * 4, 0),
        }
    }

    /// `GRBM_GFX_INDEX` — 0x2200 on both generations, and **BASE_IDX 1** on
    /// both. See [`GC_BASE_IDX_1`].
    pub const fn grbm_gfx_index_rel(self) -> (u32, usize) {
        (GRBM_GFX_INDEX_REL, 1)
    }

    /// `GRBM_STATUS2` — 0x0002 on GFX9, 0x0da2 on GFX11, BASE_IDX 0 on both.
    /// This is where the RLC's busy bit actually is.
    pub const fn grbm_status2_rel(self) -> u32 {
        match self {
            GfxGeneration::Gfx9 => 0x0002 * 4,
            GfxGeneration::Gfx11 => 0x0DA2 * 4,
        }
    }

    /// `GRBM_STATUS2__RLC_BUSY` — 0x04000000 on GFX9 but 0x01000000 on GFX11.
    /// The field keeps its name across the two headers and changes position,
    /// which is exactly the case a shared constant cannot express.
    pub const fn grbm_status2_rlc_busy(self) -> u32 {
        match self {
            GfxGeneration::Gfx9 => 1 << 26,
            GfxGeneration::Gfx11 => 1 << 24,
        }
    }

    /// `CP_STAT` — 0x01a0 on GFX9, 0x0f40 on GFX11, BASE_IDX 0 on both.
    /// `gfx_v11_0_cp_gfx_enable` polls it to zero after un-halting the CP.
    pub const fn cp_stat_rel(self) -> u32 {
        match self {
            GfxGeneration::Gfx9 => 0x01A0 * 4,
            GfxGeneration::Gfx11 => 0x0F40 * 4,
        }
    }

    /// `CP_ME_CNTL` — 0x01b6 on BASE_IDX 0 for GFX9, 0x0803 on **BASE_IDX 1**
    /// for GFX11. Returns the offset and the base index it belongs to, because
    /// the window changes with the generation; see [`GC_BASE_IDX_1`].
    pub const fn cp_me_cntl_rel(self) -> (u32, usize) {
        match self {
            GfxGeneration::Gfx9 => (0x01B6 * 4, 0),
            GfxGeneration::Gfx11 => (0x0803 * 4, 1),
        }
    }

    /// The `CP_ME_CNTL` halt bits this generation's CP has.
    ///
    /// `gfx_v9_0_cp_gfx_enable` drives ME, PFP and CE; `gfx_v11_0_cp_gfx_enable`
    /// drives only ME and PFP — GFX10 dropped the constant engine, so setting
    /// `CE_HALT` on GFX11 halts a unit that is not there.
    pub const fn cp_me_cntl_halt_all(self) -> u32 {
        match self {
            GfxGeneration::Gfx9 => CP_ME_CNTL_ME_HALT | CP_ME_CNTL_PFP_HALT | CP_ME_CNTL_CE_HALT,
            GfxGeneration::Gfx11 => CP_ME_CNTL_ME_HALT | CP_ME_CNTL_PFP_HALT,
        }
    }
}

/// `GRBM_STATUS2`, whose only field this driver reads is the RLC's.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GrbmStatus2 {
    pub raw: u32,
}

impl GrbmStatus2 {
    /// RLC microcontroller busy, per this generation's bit position.
    pub fn rlc_busy(&self, generation: GfxGeneration) -> bool {
        self.raw & generation.grbm_status2_rlc_busy() != 0
    }
}

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
    /// Every documented busy bit in THIS register clear. Invariant the
    /// ring/scheduler bring-up waits on before touching `CP_RB0_BASE`.
    ///
    /// The RLC is not among them: its busy bit is in `GRBM_STATUS2`, so a
    /// caller that needs it reads [`GrbmStatus2`] as well.
    pub fn idle(&self) -> bool {
        self.raw
            & (GRBM_STATUS_GUI_ACTIVE
                | GRBM_STATUS_ANY_ACTIVE
                | GRBM_STATUS_CP_BUSY
                | GRBM_STATUS_CP_COHERENCY_BUSY
                | GRBM_STATUS_DB_BUSY
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
// Values from `gc/gc_11_0_0_offset.h`.
//
// The comment here used to say "most ring registers keep the same dword IDs
// as GFX9". They do not: `CP_RB0_BASE` is 0x1040 on GFX9 and 0x1de0 on GFX11,
// and `CP_ME_CNTL` moves from 0x01b6 to 0x0803. The GFX11 sequence therefore
// carries its own offset block (see `GFX11_*` further down) rather than
// reusing the GFX9 `*_REL` constants.

/// `regCP_GFX_CNTL` (0x2a00, **BASE_IDX 1**).
///
/// Was 0x103E in base window 0, which is neither this register nor that
/// window. See [`GC_BASE_IDX_1`]: reaching it needs the second GC window,
/// which nothing here resolves yet.
///
/// LINUX-GAP: this was documented as "the GFX11 CP halt register" and carried
/// `CP_GFX_CNTL_FE_HALT` 1<<0, `CP_GFX_CNTL_PFP_HALT_GFX11` 1<<4 and
/// `CP_GFX_CNTL_ME_HALT_GFX11` 1<<8. `gc_11_0_0_sh_mask.h` gives this register
/// exactly two fields — `ENGINE_SEL` bit 0 and `CONFIG` bits[2:1] — and no
/// halt bit at all. GFX11 halts the CP through `CP_ME_CNTL` with the same
/// `ME_HALT`/`PFP_HALT` bits as GFX9 (`gfx_v11_0_cp_gfx_enable` at
/// `gfx_v11_0.c:3189`), only at a different offset and base index; see
/// [`GfxGeneration::cp_me_cntl_rel`]. Linux's only use of `regCP_GFX_CNTL` is
/// setting `ENGINE_SEL` (`gfx_v11_0.c:4793`), so the fabricated `FE_HALT` bit
/// would have selected an engine rather than halting one.
pub const CP_GFX_CNTL_REL: u32 = 0x2A00 * 4;

/// `CP_GFX_CNTL__ENGINE_SEL` (0x00000001).
pub const CP_GFX_CNTL_ENGINE_SEL: u32 = 1 << 0;
/// `CP_GFX_CNTL__CONFIG` (0x00000006).
pub const CP_GFX_CNTL_CONFIG_MASK: u32 = 0x6;

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

/// Size of one host-memory writeback slot.
///
/// Linux keeps a single writeback page per device and hands slots out of it;
/// `amdgpu_wb_get` returns `offset << 3` as a DWORD offset, so consecutive
/// allocations are 32 bytes apart. That is why an 8-byte `atomic64` wptr fits
/// in what the code calls one "slot" — see `amdgpu_wb.c:95-110`.
pub const WB_SLOT_BYTES: u64 = 32;
/// Byte offset of the `rptr` slot. The CP writes a 32-bit value here on GFX11
/// (`gfx_v11_0_ring_get_rptr_gfx`: "gfx11 is 32bit rptr").
pub const WB_RPTR_OFFSET: u64 = 0;
/// Byte offset of the `wptr` shadow. The HOST writes this one, as a 64-bit
/// store, and the CP polls it (`CP_RB_WPTR_POLL_ADDR_LO`/`_HI`).
pub const WB_WPTR_OFFSET: u64 = WB_SLOT_BYTES;
/// Byte offset of the fence slot the `WRITE_DATA` packet targets.
pub const WB_FENCE_OFFSET: u64 = 2 * WB_SLOT_BYTES;
/// Three slots: rptr, wptr, fence.
pub const WB_BYTES: usize = 3 * WB_SLOT_BYTES as usize;

/// The queue descriptor's size: `struct v11_gfx_mqd` is 512 dwords.
pub const MQD_BYTES: usize = crate::amdgpu_mqd::MQD_DWORDS * 4;

/// Why [`GfxContext::write_mqd`] refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MqdError {
    /// `gfx_mqd_init` rejected the derived properties. Reachable only if the
    /// ring size stops being a power of two or the ring base stops being
    /// 256-byte aligned, both of which `Ring::new` guarantees today — so this
    /// is the arm that catches a change to either.
    BadProp,
}

/// Per-queue GFX submission context. Owns its ring and a host-memory
/// writeback page. Caller is responsible for binding the ring's
/// `phys_addr()`, `rptr_phys()` and `wptr_phys()` into the CP via
/// [`build_gfx9_ring_init`] or [`build_gfx11_ring_init`] before the first
/// submission lands.
#[derive(Debug)]
pub struct GfxContext {
    ring: Ring,
    /// The writeback page: rptr (CP writes), wptr shadow (host writes, CP
    /// polls) and the fence dword the `WRITE_DATA` packet targets, at
    /// [`WB_RPTR_OFFSET`], [`WB_WPTR_OFFSET`] and [`WB_FENCE_OFFSET`].
    ///
    /// This used to be an 8-byte buffer serving as both the fence target and
    /// the rptr writeback address — "the CP uses the same buffer for RPTR
    /// writeback in this minimal scaffold; production splits them". They
    /// cannot share: the CP overwrites rptr continuously while the fence has
    /// to survive until the host reads it.
    wb: DmaBuffer,
    /// The memory queue descriptor the CP firmware reads: 512 dwords, one per
    /// `struct v11_gfx_mqd` field. Separate from the ring and from the
    /// writeback page because the firmware owns it between a map and an unmap
    /// and keeps queue state in it across a preemption.
    mqd: DmaBuffer,
    /// Next sequence number to publish.
    next_seq: u64,
}

impl GfxContext {
    /// Tell the context how far the engine has consumed its ring.
    ///
    /// How far the CP has consumed this ring, read back from the writeback
    /// page it was given at queue setup.
    ///
    /// GFX11's rptr is 32 bits (`gfx_v11_0_ring_get_rptr_gfx`), so the slot
    /// holds a dword. Before the CP has run it reads 0, which makes the ring
    /// behave as write-once — `submit` starts refusing with `Full` after a
    /// ring's worth of dwords, which is the safe direction.
    pub fn ring_rptr(&self) -> u64 {
        // SAFETY: identity-mapped DMA-coherent page owned by this context;
        // the slot is within it and the CP only ever writes this dword.
        let rptr: u32 =
            unsafe { core::ptr::read_volatile(self.wb.cpu_ptr_at::<u32>(WB_RPTR_OFFSET)) };
        u64::from(rptr)
    }

    /// Publish the host write pointer to the shadow the CP polls, then ring
    /// the doorbell.
    ///
    /// Linux does exactly this pair in `*_ring_set_wptr`:
    /// `atomic64_set(ring->wptr_cpu_addr, wptr)` and then `WDOORBELL64`. The
    /// shadow is what the CP reads when the doorbell is not in use, and what
    /// MES reads when it is scheduling the queue.
    ///
    /// # Safety
    /// `bar2` must map the doorbell window of this GPU, and the caller owns
    /// the doorbell range for this queue.
    pub unsafe fn commit(&self, bar2: &narf_driver_runtime::MmioRegion) {
        let payload = self.ring.doorbell_payload();
        // SAFETY: identity-mapped page this context owns; one aligned 64-bit
        // store, matching Linux's atomic64.
        unsafe {
            core::ptr::write_volatile(self.wb.cpu_mut_ptr_at::<u64>(WB_WPTR_OFFSET), payload);
        }
        // The shadow has to be visible before the doorbell announces it.
        compiler_fence(Ordering::SeqCst);
        // SAFETY: caller-asserted doorbell ownership.
        unsafe { self.ring.ring_doorbell(bar2) };
    }

    /// Allocate a fresh GFX context: ring + writeback page + queue descriptor.
    pub fn new(queue_idx: u16) -> Result<Self, RingError> {
        // A GFX ring: the doorbell carries the dword wptr as a quadword.
        let ring = Ring::new(queue_idx, crate::amdgpu_ring::DoorbellKind::Gfx)?;
        let wb = alloc_coherent(WB_BYTES, DomainId::DRIVER_0).map_err(|_| RingError::NoMemory)?;
        // Zero all three slots: a read before the CP has written must give 0,
        // not whatever the page held.
        // SAFETY: identity-mapped, exclusive owner, bounded by WB_BYTES.
        unsafe {
            for offset in (0..WB_BYTES as u64).step_by(8) {
                core::ptr::write_volatile(wb.cpu_mut_ptr_at::<u64>(offset), 0);
            }
        }
        let mqd = alloc_coherent(MQD_BYTES, DomainId::DRIVER_0).map_err(|_| RingError::NoMemory)?;
        // Zero the descriptor. Every field `gfx_mqd_init` does not set is
        // meant to read zero, and what the page held before is not zero.
        // SAFETY: identity-mapped, exclusive owner, bounded by MQD_BYTES.
        unsafe {
            for offset in (0..MQD_BYTES as u64).step_by(8) {
                core::ptr::write_volatile(mqd.cpu_mut_ptr_at::<u64>(offset), 0);
            }
        }
        Ok(Self {
            ring,
            wb,
            mqd,
            next_seq: 0,
        })
    }

    /// Phys address of the queue descriptor.
    pub fn mqd_phys(&self) -> u64 {
        self.mqd.dma_addr().raw()
    }

    /// One dword of the queue descriptor, by its `v11_gfx_mqd` index.
    ///
    /// Reads back what [`GfxContext::write_mqd`] put there, so a test can
    /// check the firmware's copy rather than the array it was built from.
    ///
    /// Ungated for the same reason [`GfxContext::ring_rptr`] is: the
    /// kernel-test modules compile in the plain build too.
    pub fn mqd_dword(&self, index: usize) -> u32 {
        if index >= crate::amdgpu_mqd::MQD_DWORDS {
            return 0;
        }
        // SAFETY: identity-mapped page this context owns, index bounded above.
        unsafe { core::ptr::read_volatile(self.mqd.cpu_ptr_at::<u32>((index * 4) as u64)) }
    }

    /// Build this queue's descriptor from this context's own addresses and
    /// write it into the page the firmware reads.
    ///
    /// The point of deriving it here rather than taking an [`MqdProp`] is that
    /// the ring base, the rptr writeback, the wptr shadow, the descriptor's
    /// own address and the doorbell index all have to agree between three
    /// consumers — the descriptor, the CP's registers
    /// ([`build_gfx11_ring_init`]) and the MES mapping packet
    /// ([`GfxContext::map_legacy_args`]). A caller assembling them by hand can
    /// hand two of the three a different answer, and the failure is a queue
    /// the firmware accepts and that never runs.
    pub fn write_mqd(&self) -> Result<(), MqdError> {
        let prop = MqdProp {
            mqd_gpu_addr: self.mqd_phys(),
            hqd_base_gpu_addr: self.ring_phys(),
            rptr_gpu_addr: self.rptr_phys(),
            wptr_gpu_addr: self.wptr_phys(),
            queue_size: crate::amdgpu_ring::RING_SIZE_DW as u64 * 4,
            doorbell_index: self.ring.doorbell_index_dw(),
            use_doorbell: true,
            // A kernel ring, so privileged packets are allowed. `kernel_queue`
            // is what clears `PRIV_STATE` in the MQD's `CP_GFX_HQD_CNTL`.
            kernel_queue: true,
            // `amdgpu_ring_to_mqd_prop` memsets the whole prop and then
            // assigns the fields above; everything below is a zero it leaves
            // alone for a kernel graphics ring, written out rather than
            // defaulted so each one is a decision on the page.
            //
            // Not a TMZ queue: there is no secure-memory path.
            tmz_queue: false,
            // Ring 0 is not a high-priority graphics queue
            // (`amdgpu_gfx_is_high_priority_graphics_queue` is false for it),
            // so both priority fields stay at their normal level.
            priority: crate::amdgpu_mqd::QueuePriority::Normal,
            // The GFX11 user-queue areas. A kernel ring has no shadow, no GDS
            // backup, no CSA and no separate fence page — its fence lives in
            // the writeback slot the `WRITE_DATA` packet targets, which is not
            // this field.
            shadow_addr: 0,
            gds_bkup_addr: 0,
            csa_addr: 0,
            fence_address: 0,
        };
        let mqd = crate::amdgpu_mqd::gfx_mqd_init(&prop).map_err(|_| MqdError::BadProp)?;
        // SAFETY: identity-mapped page this context owns; `mqd` is exactly
        // MQD_DWORDS dwords and the allocation is MQD_BYTES.
        unsafe {
            for (i, dw) in mqd.iter().enumerate() {
                core::ptr::write_volatile(self.mqd.cpu_mut_ptr_at::<u32>((i * 4) as u64), *dw);
            }
        }
        Ok(())
    }

    /// The MES legacy-queue mapping for this context, on `pipe`/`queue`.
    ///
    /// Built from the same three addresses [`GfxContext::write_mqd`] put in
    /// the descriptor, for the reason given there. `doorbell_offset` is
    /// `ring->doorbell_index` — the dword space, not the assignment slot.
    pub fn map_legacy_args(
        &self,
        pipe: u32,
        queue: u32,
    ) -> crate::amdgpu_mes::MesMapLegacyQueueArgs {
        crate::amdgpu_mes::MesMapLegacyQueueArgs {
            pipe_id: pipe,
            queue_id: queue,
            doorbell_offset: self.ring.doorbell_index_dw(),
            mqd_addr: self.mqd_phys(),
            wptr_addr: self.wptr_phys(),
            queue_type: crate::amdgpu_mes::MesQueueType::Gfx,
        }
    }

    /// Phys address of the ring's first dword — feed this into
    /// [`build_gfx9_ring_init`].
    pub fn ring_phys(&self) -> u64 {
        self.ring.phys_addr()
    }

    /// Phys address of the fence slot — the `WRITE_DATA` target.
    pub fn fence_phys(&self) -> u64 {
        self.wb.dma_addr().raw() + WB_FENCE_OFFSET
    }

    /// Phys address of the rptr slot — feed this into the ring init as
    /// `rptr_writeback_phys`, so the CP has somewhere to report from.
    pub fn rptr_phys(&self) -> u64 {
        self.wb.dma_addr().raw() + WB_RPTR_OFFSET
    }

    /// Phys address of the wptr shadow — feed this into
    /// [`build_gfx11_ring_init`] as `wptr_poll_phys`.
    pub fn wptr_phys(&self) -> u64 {
        self.wb.dma_addr().raw() + WB_WPTR_OFFSET
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
            self.ring.submit(&staging, self.ring_rptr())?;
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
            unsafe { core::ptr::read_volatile(self.wb.cpu_ptr_at::<u32>(WB_FENCE_OFFSET)) };
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
            core::ptr::write_volatile(self.wb.cpu_mut_ptr_at::<u32>(WB_FENCE_OFFSET), seq);
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
/// `CP_RB_DOORBELL_RANGE_LOWER__DOORBELL_RANGE_LOWER_MASK` — **ten** bits at
/// shift 2, so a doorbell index of 0x400 or more does not fit. Linux places
/// the field with `REG_SET_FIELD`, which masks; writing the shifted index raw
/// would spill into the register's reserved bits for any index that large.
const GFX11_DOORBELL_RANGE_LOWER_MASK: u32 = 0x0000_0FFC;
const GFX11_DOORBELL_OFFSET_SHIFT: u32 = 2;
/// `CP_RB_DOORBELL_CONTROL__DOORBELL_OFFSET_MASK` — 26 bits at shift 2. Wide
/// enough that no real index overflows it, and masked anyway because that is
/// what `REG_SET_FIELD` does and the next field up is `DOORBELL_EN`.
const GFX11_DOORBELL_OFFSET_MASK: u32 = 0x0FFF_FFFC;
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
/// `GRBM_GFX_CNTL` is also the one register here in GC base window **1**
/// (BASE_IDX 1); everything else is window 0. Both windows are therefore
/// parameters, because a single `gc_base` silently puts the pipe select on
/// whatever register sits at that offset in the other window.
///
/// LINUX-GAP: ring 1 on pipe 1 is not emitted. Linux brings it up when
/// `num_gfx_rings > 1`; one ring is enough to submit, and a second doubles the
/// bring-up surface for no gain until the first works.
///
/// `gfx_v11_0_cp_gfx_start` is deliberately not part of this: it writes a PM4
/// `CONTEXT_CONTROL` / `CLEAR_STATE` preamble INTO the ring and rings the
/// doorbell, which needs a live ring object rather than a register list. That
/// preamble is [`crate::amdgpu_clearstate::build_preamble`], and a caller runs
/// it after this sequence has been applied.
#[allow(clippy::too_many_arguments)]
pub fn build_gfx11_ring_init(
    gc_base: u32,
    // `gc_base_1` is GC base window 1, where `GRBM_GFX_CNTL` lives. Every
    // other register in this sequence is BASE_IDX 0 and uses `gc_base`.
    // Passing `gc_base` for both would put the pipe select on an unrelated
    // register — a mistake this parameter exists to make visible.
    gc_base_1: u32,
    grbm_gfx_cntl: u32,
    ring_phys: u64,
    ring_size_bytes: u64,
    // `ring->doorbell_index` — the DWORD index space, twice the
    // `AMDGPU_NAVI10_DOORBELL_*` assignment value. `Ring::doorbell_index_dw`
    // returns it; `Ring::queue_idx` is the other space and would halve both
    // the control offset and the range.
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
    //
    // `GRBM_GFX_CNTL` is BASE_IDX **1**, so it is addressed from the second
    // GC window. This was emitted against `gc_base` when the sequence was
    // first written; the two windows are different base addresses and the
    // write would have landed on whatever register sits at that offset in
    // window 0.
    let pipe0 = grbm_gfx_cntl & !0x3;
    seq.write(gc_base_1, GFX11_GRBM_GFX_CNTL, pipe0);

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
        doorbell |= (doorbell_idx << GFX11_DOORBELL_OFFSET_SHIFT) & GFX11_DOORBELL_OFFSET_MASK;
        doorbell |= GFX11_DOORBELL_EN;
    }
    seq.write(gc_base, GFX11_CP_RB_DOORBELL_CONTROL, doorbell);
    seq.write(
        gc_base,
        GFX11_CP_RB_DOORBELL_RANGE_LOWER,
        (doorbell_idx << GFX11_DOORBELL_RANGE_LOWER_SHIFT) & GFX11_DOORBELL_RANGE_LOWER_MASK,
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
