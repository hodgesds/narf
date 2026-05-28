//! GPU MMU — page-table descriptor encoders.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/subdev/mmu/base.c`**
//!   — generic `nvkm_mmu_*` entry points.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/mmu/vmmgf100.c`** —
//!   Fermi-style 64-bit page tables (PDE0/PDE1 with 64 KiB +
//!   large pages). All later families inherit this shape.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/mmu/vmmgp100.c`** —
//!   Pascal's 5-level page tables introduced PDE2/PDE3/PDE4. The
//!   PTE layout reshaped: bit 0 = VALID, bits[63:8] = phys frame,
//!   bits[5:4] = read/write/atomic, bit 32 = vol/cache.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/mmu/vmmgv100.c`** /
//!   **`vmmtu102.c`** — Volta/Turing add VID/peer/sysmem aperture
//!   bits.
//!
//! Stage 1 encodes the PTE bits only — the host driver allocates
//! page-table pages and writes the descriptors; no live MMU
//! programming yet.

#![allow(dead_code)]

// ── Page-size constants ──────────────────────────────────────────

/// 4 KiB small page — the typical PTE granularity.
pub const PAGE_SIZE_SMALL: u64 = 4 * 1024;
/// 64 KiB "big" page — covers 16 4-KiB PTEs in one PDE-level slot.
pub const PAGE_SIZE_BIG: u64 = 64 * 1024;
/// 2 MiB large page — Pascal+ uses these for VRAM-backed regions.
pub const PAGE_SIZE_LARGE: u64 = 2 * 1024 * 1024;

// ── PTE bit layout (Pascal+) ─────────────────────────────────────
//
// Cite `nvkm/subdev/mmu/vmmgp100.c::gp100_vmm_pgt_pte`. PTE format
// (little-endian):
//
//   bits  0     VALID
//   bits  1     PRIV (kernel-only when set; user when clear)
//   bits  2     RO   (read-only)
//   bits  3     ATOMIC_DISABLE
//   bits  5:4   APERTURE (00 = VRAM, 01 = sysmem coherent,
//                          10 = sysmem non-coherent, 11 = peer)
//   bits  6     VOLATILE (uncached on host)
//   bits  7     KIND_INVALID
//   bits 63:8   phys-address >> 4 (PA bits[63:12] for 4 KiB, but
//               PTE field is wider for the GPU's aperture)

/// PTE bit 0 — entry valid.
pub const PTE_VALID: u64 = 1 << 0;
/// PTE bit 1 — privileged (no user access).
pub const PTE_PRIV: u64 = 1 << 1;
/// PTE bit 2 — read-only.
pub const PTE_RO: u64 = 1 << 2;
/// PTE bit 3 — atomic ops disabled (write-only).
pub const PTE_ATOMIC_DISABLE: u64 = 1 << 3;
/// PTE bit 6 — volatile (uncached on the host bus).
pub const PTE_VOLATILE: u64 = 1 << 6;

/// PTE aperture field ([5:4]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Aperture {
    Vram,
    SysCoherent,
    SysNonCoherent,
    Peer,
}

impl Aperture {
    pub const fn pte_bits(self) -> u64 {
        match self {
            Aperture::Vram => 0b00 << 4,
            Aperture::SysCoherent => 0b01 << 4,
            Aperture::SysNonCoherent => 0b10 << 4,
            Aperture::Peer => 0b11 << 4,
        }
    }
}

/// Encode a 4 KiB PTE entry. `phys` is the physical page address
/// (must be 4 KiB-aligned).
pub const fn pte_encode_4k(phys: u64, aperture: Aperture, flags: u64) -> u64 {
    debug_assert!(phys & 0xFFF == 0);
    // PTE bits[63:8] hold `phys >> 4`. Shift left by 8 from a
    // canonical phys frame.
    let phys_field = (phys >> 4) << 8;
    phys_field | aperture.pte_bits() | flags | PTE_VALID
}

// ── PDE bit layout ───────────────────────────────────────────────
//
// PDEs at each level can either point at the next-level page table
// (PT) or hold a "big-page leaf" PDE that covers a region directly
// (Pascal+ uses this for 2 MiB ranges). The simplest encoding is
// "PT pointer with the same aperture field as a PTE".

/// Encode a PDE pointing at a 4 KiB page-table page in VRAM.
pub const fn pde_encode_pt(pt_phys: u64) -> u64 {
    // Same shift as the PTE.
    let phys_field = (pt_phys >> 4) << 8;
    phys_field | Aperture::Vram.pte_bits() | PTE_VALID
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PageSize {
    Small,
    Big,
    Large,
}

impl PageSize {
    pub const fn bytes(self) -> u64 {
        match self {
            PageSize::Small => PAGE_SIZE_SMALL,
            PageSize::Big => PAGE_SIZE_BIG,
            PageSize::Large => PAGE_SIZE_LARGE,
        }
    }
}
