//! Master Controller (PMC) — the top-level engine reset/enable +
//! interrupt routing block.
//!
//! ## References
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/subdev/mc/base.c`**
//!   — generic `nvkm_mc_*` entry points.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/mc/gp100.c`** &
//!   **`gp10b.c`** — Pascal/Volta MC functable; the
//!   `nvkm_wr32(device, 0x000200, 0xffffffff)` "everything on"
//!   sequence (cited gp10b.c:30, ga100.c:64).
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/mc/ga100.c`** —
//!   Ampere+ MC (slightly reshaped, but PMC_ENABLE @ 0x000200
//!   still works).
//! - **PMC_BOOT_0** at BAR0 offset 0x000000 — universal chip-id
//!   register. Used here as the presence + family detect.
//!
//! ## Register offsets (BAR0)
//!
//! | offset       | name                                       |
//! |--------------|--------------------------------------------|
//! | `0x000000`   | `NV_PMC_BOOT_0` — chip identifier          |
//! | `0x000100`   | `NV_PMC_INTR_0` — top-level IRQ status     |
//! | `0x000104`   | `NV_PMC_INTR_1` — secondary IRQ status     |
//! | `0x000140`   | `NV_PMC_INTR_EN_0` — IRQ mask, group 0     |
//! | `0x000144`   | `NV_PMC_INTR_EN_1` — IRQ mask, group 1     |
//! | `0x000200`   | `NV_PMC_ENABLE` — per-engine enable        |
//! | `0x000204`   | `NV_PMC_ENABLE_UNK0` — Ampere+ alt bank    |

#![allow(dead_code)]

use crate::chip::ChipFamily;

// ── Register offsets ─────────────────────────────────────────────

/// `NV_PMC_BOOT_0` — chip identifier. Read-only. Stable since Fermi.
pub const PMC_BOOT_0: u64 = 0x0000_0000;

/// `NV_PMC_INTR_0` — top-level interrupt status, host group.
pub const PMC_INTR_0: u64 = 0x0000_0100;
/// `NV_PMC_INTR_1` — secondary interrupt status.
pub const PMC_INTR_1: u64 = 0x0000_0104;
/// `NV_PMC_INTR_EN_0` — interrupt enable, host group.
pub const PMC_INTR_EN_0: u64 = 0x0000_0140;
/// `NV_PMC_INTR_EN_1` — interrupt enable, secondary group.
pub const PMC_INTR_EN_1: u64 = 0x0000_0144;

/// `NV_PMC_ENABLE` — per-engine reset/enable. Bit set = engine
/// out of reset; cleared = engine held in reset.
pub const PMC_ENABLE: u64 = 0x0000_0200;
/// `NV_PMC_ENABLE_UNK0` — alternate enable bank on some parts.
pub const PMC_ENABLE_UNK0: u64 = 0x0000_0204;

// ── PMC_ENABLE engine-bit assignments ────────────────────────────
//
// Bit layout is reasonably stable across Maxwell→Ada for the
// engines we touch in Stage 1. Cite `nvkm/subdev/mc/gp100.c`
// (gp100_mc_reset) which enumerates the canonical bit names; the
// numeric positions match `dev_pmc.ref.txt`.

/// `NV_PMC_ENABLE.PFIFO` — host FIFO engine.
pub const PMC_ENABLE_PFIFO: u32 = 1 << 8;
/// `NV_PMC_ENABLE.PGRAPH` — graphics engine.
pub const PMC_ENABLE_PGRAPH: u32 = 1 << 12;
/// `NV_PMC_ENABLE.PMSPDEC` — video decoder.
pub const PMC_ENABLE_PMSPDEC: u32 = 1 << 17;
/// `NV_PMC_ENABLE.PMSENC` — video encoder.
pub const PMC_ENABLE_PMSENC: u32 = 1 << 18;
/// `NV_PMC_ENABLE.PSEC` — security engine (SEC2).
pub const PMC_ENABLE_PSEC: u32 = 1 << 14;
/// `NV_PMC_ENABLE.PCE0` — copy engine 0.
pub const PMC_ENABLE_PCE0: u32 = 1 << 15;
/// `NV_PMC_ENABLE.PDISP` — display engine.
pub const PMC_ENABLE_PDISP: u32 = 1 << 30;

/// "Everything on" — used by Pascal+ MC bring-up. Cite
/// `nvkm/subdev/mc/gp10b.c:30`.
pub const PMC_ENABLE_ALL: u32 = 0xFFFF_FFFF;

// ── PMC_BOOT_0 field layout ──────────────────────────────────────
//
// Bits[24:20] — architecture version (Maxwell=0x04, Pascal=0x05,
// Volta=0x06, Turing=0x07, Ampere=0x08, Ada=0x09).
//
// Layout from
// `drivers/gpu/drm/nouveau/include/nvkm/core/device.h` cited
// `NVKM_DEVICE_PMC_BOOT_0` and `nvkm/subdev/mc/g84.c::g84_mc`.
// Field positions verified against `open-gpu-doc/manuals/*` PMC
// register files.

/// Mask for `PMC_BOOT_0[3:0]` — minor revision.
pub const PMC_BOOT_0_MINOR_MASK: u32 = 0x0000_000F;
/// Mask for `PMC_BOOT_0[7:4]` — major revision.
pub const PMC_BOOT_0_MAJOR_MASK: u32 = 0x0000_00F0;
/// Mask for `PMC_BOOT_0[19:8]` — implementation (chip variant).
pub const PMC_BOOT_0_IMPL_MASK: u32 = 0x000F_FF00;
/// Mask for `PMC_BOOT_0[24:20]` — architecture version (Maxwell=4,
/// Pascal=5, etc.). Bits[24:20] is what `chip::ChipFamily` decodes.
pub const PMC_BOOT_0_ARCH_MASK: u32 = 0x01F0_0000;
/// Shift to recover the architecture nibble.
pub const PMC_BOOT_0_ARCH_SHIFT: u32 = 20;

/// Decoded `PMC_BOOT_0`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Boot0 {
    pub family: ChipFamily,
    /// Implementation (chip variant). For GA102 = 0x02, GA104 =
    /// 0x04, …
    pub implementation: u16,
    pub major_rev: u8,
    pub minor_rev: u8,
}

impl Boot0 {
    /// Sanity-check that the value plausibly came from silicon
    /// rather than from a torn PCI bus / unmapped BAR.
    pub const fn looks_present(raw: u32) -> bool {
        // All-ones is the typical "BAR not mapped / device gone"
        // pattern; all-zeros is the second-typical case.
        raw != 0xFFFF_FFFF && raw != 0x0000_0000
    }

    /// Decode a raw PMC_BOOT_0 sample.
    pub const fn decode(raw: u32) -> Self {
        let minor_rev = (raw & PMC_BOOT_0_MINOR_MASK) as u8;
        let major_rev = ((raw & PMC_BOOT_0_MAJOR_MASK) >> 4) as u8;
        let implementation = ((raw & PMC_BOOT_0_IMPL_MASK) >> 8) as u16;
        let arch_field = ((raw & PMC_BOOT_0_ARCH_MASK) >> PMC_BOOT_0_ARCH_SHIFT) as u8;
        // Encode the arch nibble back to the high-byte tag the
        // ChipFamily decoder consumes ("0x40" style).
        let arch_tag = arch_field << 4;
        let family = ChipFamily::from_arch_version(arch_tag);
        Self {
            family,
            implementation,
            major_rev,
            minor_rev,
        }
    }
}

// ── Top-level interrupt mask vectors ─────────────────────────────
//
// `dev_pmc.ref.txt` top-level INTR bits (stable Maxwell→Ada).
//
// We model the canonical interrupt-source bits as a typed enum so
// the routing code can be exhaustive.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IntrSource {
    Fifo,
    Graphics,
    CopyEngine0,
    CopyEngine1,
    CopyEngine2,
    Display,
    Sec,
    Pmu,
    Gsp,
}

impl IntrSource {
    /// Bit mask in `PMC_INTR_0`. Bit positions cited from
    /// `dev_pmc.ref.txt::NV_PMC_INTR_0` (Turing manual) — these are
    /// the host-group bits.
    pub const fn intr0_bit(self) -> u32 {
        match self {
            IntrSource::Fifo => 1 << 8,
            IntrSource::Graphics => 1 << 12,
            IntrSource::CopyEngine0 => 1 << 13,
            IntrSource::CopyEngine1 => 1 << 14,
            IntrSource::CopyEngine2 => 1 << 15,
            IntrSource::Display => 1 << 26,
            IntrSource::Sec => 1 << 24,
            IntrSource::Pmu => 1 << 21,
            IntrSource::Gsp => 1 << 28,
        }
    }
}
