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
