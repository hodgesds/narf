//! AMD Graphics Memory Controller (GMC) — GART + VM scaffold.
//!
//! GMC is the GPU's memory translation block. It implements two
//! distinct translation paths:
//!
//! - **GART** (Graphics Aperture Remapping Table) — a flat,
//!   single-level page table the host populates so the GPU can
//!   address system memory through GPU-visible virtual
//!   addresses. Used for things like indirect-buffer storage in
//!   GTT, framebuffers backed by sysmem, scanout buffers.
//! - **VM** (per-process page tables) — multi-level page tables
//!   per VMID, used to isolate user contexts. Each PASID gets
//!   its own VM page table; the GPU walks it with the same
//!   shape as x86_64 (4-level, 9 bits per level, 4 KiB leaf).
//!   Stage-N expands this; for now we ship just the GART path
//!   since that's enough for the bring-up arc.
//!
//! ## GART PTE format
//!
//! GFX9 / Vega / Renoir GART entries are 8 bytes:
//!
//! | bits     | field |
//! |----------|-------|
//! | [0]      | V (valid) |
//! | [1]      | S (system memory, not VRAM) |
//! | [2]      | C (cacheable hint) |
//! | [3]      | W (writable) |
//! | [6:4]    | reserved |
//! | [7]      | Z (write-back snoop) |
//! | [39:12]  | physical page frame number (PFN) |
//! | [63:40]  | reserved (upper PFN bits on Phoenix / 64 GiB systems) |
//!
//! Note: the spec for GFX9 places the PFN in bits[39:12]; Phoenix
//! (GFX11) extends it through bit 47 to support >64 GiB system
//! memory. The encoding below matches GFX9; the Phoenix-extended
//! field width is a delta the per-chip code adjusts.
//!
//! Linux references (post 2026-05-20 GPL relicense):
//! - `drivers/gpu/drm/amd/amdgpu/amdgpu_gart.c`
//! - `drivers/gpu/drm/amd/amdgpu/amdgpu_gmc.c`
//! - `drivers/gpu/drm/amd/amdgpu/gmc_v9_0.c`

extern crate alloc;

// ── GART PTE flag bits ─────────────────────────────────────────────

/// V — entry is valid (GPU may translate against it).
pub const GART_PTE_VALID: u64 = 1 << 0;
/// S — entry points to system memory (not VRAM).
pub const GART_PTE_SYSTEM: u64 = 1 << 1;
/// C — cacheable in the L1 / L2 (GFX-side caches).
pub const GART_PTE_CACHEABLE: u64 = 1 << 2;
/// W — writable. Clear for read-only mappings (e.g. shader code).
pub const GART_PTE_WRITABLE: u64 = 1 << 3;
/// Z — write-back snoop. Tells the IOMMU to snoop CPU L3 on writes
/// so the CPU never reads stale data after the GPU writes the page.
pub const GART_PTE_SNOOP: u64 = 1 << 7;

/// PFN field shift in the PTE.
pub const GART_PTE_PFN_SHIFT: u64 = 12;
/// PFN field mask after the shift — 28 bits on GFX9 (covers 1 TiB
/// of system memory at 4 KiB pages, enough for the bring-up targets).
pub const GART_PTE_PFN_MASK: u64 = 0x0FFF_FFFF;

/// Composite flag set for the typical "sysmem readable + writable
/// cacheable + snoop" mapping the driver creates for GTT pages.
pub const GART_PTE_FLAGS_GTT_DEFAULT: u64 =
    GART_PTE_VALID | GART_PTE_SYSTEM | GART_PTE_CACHEABLE | GART_PTE_WRITABLE | GART_PTE_SNOOP;

// ── PTE builder ────────────────────────────────────────────────────

/// Errors building a GART PTE.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GartError {
    /// `phys_addr` isn't 4 KiB aligned.
    UnalignedPhys,
    /// PFN doesn't fit in 28 bits (PFN ≥ 1 TiB). Phoenix extends
    /// to bits[47:12] (4 PiB) — caller uses `make_pte_phoenix`.
    PfnOverflow,
}

/// Encode a GART PTE for a single 4 KiB system-memory page.
///
/// `phys_addr` must be 4 KiB aligned; the bottom 12 bits go into
/// the flag field. `flags` is OR-merged into the entry; pass
/// [`GART_PTE_FLAGS_GTT_DEFAULT`] for the typical bring-up case.
pub fn make_pte_gfx9(phys_addr: u64, flags: u64) -> Result<u64, GartError> {
    if phys_addr & 0xFFF != 0 {
        return Err(GartError::UnalignedPhys);
    }
    let pfn = phys_addr >> GART_PTE_PFN_SHIFT;
    if pfn & !GART_PTE_PFN_MASK != 0 {
        return Err(GartError::PfnOverflow);
    }
    Ok((pfn << GART_PTE_PFN_SHIFT) | (flags & 0xFFF))
}

/// Decode a GART PTE: returns (phys_addr, flag_bits[11:0]).
pub fn parse_pte(pte: u64) -> (u64, u64) {
    let pfn = (pte >> GART_PTE_PFN_SHIFT) & GART_PTE_PFN_MASK;
    let phys = pfn << GART_PTE_PFN_SHIFT;
    let flags = pte & 0xFFF;
    (phys, flags)
}

/// Is the entry valid (V bit set)?
pub fn pte_is_valid(pte: u64) -> bool {
    pte & GART_PTE_VALID != 0
}

// ── VM (process page table) shape ──────────────────────────────────
//
// The full multi-level VM page table is a follow-up; for now expose
// the constants that distinguish it from GART so future code can
// reach for the right encoding without scattering magic numbers.

/// Number of address bits per VM page-table level (matches x86_64).
pub const VM_LEVEL_BITS: u32 = 9;
/// VM PTE bits[58:57] gate page size (4K / 2M / 1G).
pub const VM_PTE_PAGE_SIZE_SHIFT: u64 = 57;
/// VM PTE bit 0 — valid.
pub const VM_PTE_VALID: u64 = 1 << 0;
/// VM PTE bit 1 — system memory (vs VRAM).
pub const VM_PTE_SYSTEM: u64 = 1 << 1;
/// VM PTE bit 2 — readable.
pub const VM_PTE_READABLE: u64 = 1 << 5;
/// VM PTE bit 6 — writable.
pub const VM_PTE_WRITABLE: u64 = 1 << 6;
/// VM PTE bit 56 — last-level (leaf). Set on PTEs; clear on PDEs.
pub const VM_PTE_FRAGMENT_SHIFT: u64 = 59;

/// Number of GART PTEs in a 4 KiB page table page (the GART itself
/// is one big contiguous array; this constant lets callers compute
/// the GART backing-store size).
pub const GART_PTES_PER_PAGE: usize = 4096 / 8;

// ── MC IP block register offsets ───────────────────────────────────
//
// The MC (Memory Controller) block holds VRAM aperture + system
// aperture geometry. On the bring-up targets (Renoir GFX9 + Phoenix
// GFX11) these registers sit in the register-bus address space at
// fixed dword offsets — old enough to predate IP discovery's MC
// base on Renoir; on Phoenix the MC block ID isn't published in
// discovery (the aperture registers move to MMHUB / GFXHUB
// contexts). The Foundations wave exposes the offsets; bring-up
// uses MM_INDEX / MM_DATA in `amdgpu::mm_read` to fetch them.
//
// Reference: AMD MC IP public docs + Linux
// `drivers/gpu/drm/amd/include/asic_reg/gc/gc_9_0_offset.h` for
// the MC_VM_* / MC_SHARED_* names.

// Aperture bases are in 16-MiB units: bits[23:0] are the field, and the
// aperture covers `[base << 24, (top + 1) << 24)`.
//
// The GFX9 values are `mm*` dword ids from `gc_9_0_offset.h`, all in the GC
// block (BASE_IDX 0) — not a separate "MC" block, which is where the old
// values' magnitude suggested they came from. `0x6B0F` appears in no AMD
// header for any `MC_VM_FB_LOCATION_BASE` variant, of any generation.
//
// Phoenix needs different registers entirely: GFX11 reads
// `regGCMC_VM_FB_LOCATION_BASE` (0x1678) and `_TOP` (0x1679) from the GC
// block (`gfxhub_v3_0.c`), where GFX9 reads `mmMC_VM_FB_LOCATION_BASE`
// (0x0980) and `_TOP` (0x0981) (`gfxhub_v1_0.c`). Both are provided; the
// caller picks by family, as it already does for GRBM_STATUS.
//
// The AGP triple is also ordered TOP, BOT, BASE ascending (0x0982, 0x0983,
// 0x0984) — not BASE, BOT, TOP. The old constants assumed the intuitive
// order and so had all three wrong relative to each other as well as
// absolutely.

/// `mmMC_VM_FB_LOCATION_BASE` (0x0980) — GFX9. Visible-VRAM aperture base
/// in 16-MiB units.
pub const MC_VM_FB_LOCATION_BASE: u32 = 0x0000_0980;
/// `mmMC_VM_FB_LOCATION_TOP` (0x0981) — GFX9.
pub const MC_VM_FB_LOCATION_TOP: u32 = 0x0000_0981;
/// `regGCMC_VM_FB_LOCATION_BASE` (0x1678) — GFX11 / Phoenix.
pub const GCMC_VM_FB_LOCATION_BASE_GFX11: u32 = 0x0000_1678;
/// `regGCMC_VM_FB_LOCATION_TOP` (0x1679) — GFX11 / Phoenix.
pub const GCMC_VM_FB_LOCATION_TOP_GFX11: u32 = 0x0000_1679;
/// `mmMC_VM_FB_OFFSET` (0x096b) — GFX9.
pub const MC_VM_FB_OFFSET: u32 = 0x0000_096B;
/// `mmMC_VM_AGP_TOP` (0x0982) — GFX9. Note TOP is the LOWEST of the three.
pub const MC_VM_AGP_TOP: u32 = 0x0000_0982;
/// `mmMC_VM_AGP_BOT` (0x0983) — GFX9.
pub const MC_VM_AGP_BOT: u32 = 0x0000_0983;
/// `mmMC_VM_AGP_BASE` (0x0984) — GFX9.
pub const MC_VM_AGP_BASE: u32 = 0x0000_0984;
/// `regGCMC_VM_SYSTEM_APERTURE_LOW_ADDR` (0x167d) — GFX11 / Phoenix, GC
/// BASE_IDX 0.
///
/// A different register from GFX9's `mmMC_VM_SYSTEM_APERTURE_LOW_ADDR`, the
/// same way `GCMC_VM_FB_LOCATION_BASE` is a different register from
/// `MC_VM_FB_LOCATION_BASE` — not one register at two offsets.
pub const GCMC_VM_SYSTEM_APERTURE_LOW_ADDR_GFX11: u32 = 0x0000_167D;
/// `regGCMC_VM_SYSTEM_APERTURE_HIGH_ADDR` (0x167e) — GFX11 / Phoenix.
pub const GCMC_VM_SYSTEM_APERTURE_HIGH_ADDR_GFX11: u32 = 0x0000_167E;

/// `mmMC_VM_SYSTEM_APERTURE_LOW_ADDR` (0x0985) — GFX9.
pub const MC_VM_SYSTEM_APERTURE_LOW_ADDR: u32 = 0x0000_0985;
/// `mmMC_VM_SYSTEM_APERTURE_HIGH_ADDR` (0x0986) — GFX9.
pub const MC_VM_SYSTEM_APERTURE_HIGH_ADDR: u32 = 0x0000_0986;
/// `mmMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_LSB` — low 32 bits of the
/// phys address the MC uses when a GPU access falls outside both
/// VRAM and system apertures. Pre-firmware this is the GART
/// scratch page; post-firmware a per-VM unmapped-fault handler.
pub const MC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_LSB: u32 = 0x0000_6B19;
/// `mmMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_MSB` — high 32 bits, same.
pub const MC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_MSB: u32 = 0x0000_6B1A;

/// `mmMC_SHARED_CHMAP` — chip-shared "channel map" describing the
/// memory controller's channel ↔ HBM/DDR-stack interleave.
/// Foundations wave reads it as part of chip-ID corroboration
/// (channel count corroborates VRAM family) and hands it to the
/// memory bring-up wave for interleave programming.
/// `mmMC_SHARED_CHMAP` (0x0801). Was 0x2004.
pub const MC_SHARED_CHMAP: u32 = 0x0000_0801;
/// `mmMC_SHARED_CHREMAP` — companion remap table for CHMAP.
/// `mmMC_SHARED_CHREMAP` (0x0802). Was 0x2005.
pub const MC_SHARED_CHREMAP: u32 = 0x0000_0802;

// ── Aperture decode ────────────────────────────────────────────────

/// Scale factor: MC_VM_FB_LOCATION_* registers are 16-MiB units.
pub const FB_LOCATION_UNIT_SHIFT: u64 = 24;
/// Scale factor: MC_VM_SYSTEM_APERTURE_* registers are 4-KiB units.
pub const SYSTEM_APERTURE_UNIT_SHIFT: u64 = 12;
/// Mask of bits[23:0] in an FB_LOCATION register field.
pub const FB_LOCATION_FIELD_MASK: u32 = 0x00FF_FFFF;

/// Decoded GPU memory aperture geometry. Holds both the VRAM
/// aperture (FB_LOCATION_BASE/TOP) and the system aperture
/// (SYSTEM_APERTURE_LOW/HIGH); both are consumed by the GMC
/// bring-up wave when populating VM hub registers.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ApertureLayout {
    /// VRAM aperture base, in bytes.
    pub vram_base: u64,
    /// VRAM aperture size, in bytes.
    pub vram_size: u64,
    /// System memory aperture low bound, in bytes. Zero on chips
    /// where the system aperture hasn't been programmed yet by
    /// firmware.
    pub system_low: u64,
    /// System memory aperture high bound, in bytes (inclusive).
    pub system_high: u64,
}

impl ApertureLayout {
    /// VRAM aperture spans non-zero bytes.
    pub fn has_vram(&self) -> bool {
        self.vram_size > 0
    }
    /// System aperture range is non-degenerate.
    pub fn has_system(&self) -> bool {
        self.system_high > self.system_low
    }
}

/// Decode VRAM aperture from raw `(MC_VM_FB_LOCATION_BASE,
/// MC_VM_FB_LOCATION_TOP)` register dwords. Pure helper.
pub fn decode_vram_aperture(base_field: u32, top_field: u32) -> (u64, u64) {
    let base = (base_field as u64 & FB_LOCATION_FIELD_MASK as u64) << FB_LOCATION_UNIT_SHIFT;
    let top = (top_field as u64 & FB_LOCATION_FIELD_MASK as u64) << FB_LOCATION_UNIT_SHIFT;
    let size = if top >= base {
        top - base + (1u64 << FB_LOCATION_UNIT_SHIFT)
    } else {
        0
    };
    (base, size)
}

/// Decode system aperture range from raw `(SYSTEM_APERTURE_LOW,
/// SYSTEM_APERTURE_HIGH)` register dwords. Pure helper.
pub fn decode_system_aperture(low_field: u32, high_field: u32) -> (u64, u64) {
    let low = (low_field as u64) << SYSTEM_APERTURE_UNIT_SHIFT;
    let high = (high_field as u64) << SYSTEM_APERTURE_UNIT_SHIFT;
    (low, high)
}
