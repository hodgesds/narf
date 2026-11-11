//! Frame Buffer / memory controller — VRAM detect + RAM type
//! classification.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/subdev/fb/base.c`**
//!   — generic `nvkm_fb_init`. Reads `NV_PFB_CFG0` (BAR0 0x100200)
//!   for the VRAM size and `NV_PFB_FBPA_*` for memory type bits.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/fb/gm107.c`** /
//!   **`gm200.c`** / **`gp100.c`** / **`gp102.c`** / **`gv100.c`** /
//!   **`tu102.c`** / **`ga102.c`** / **`ad102.c`** — per-ASIC FB
//!   functable (`*_fb_funcs`); the `init` callback issues the
//!   VRAM-size readback.
//! - **`include/nvkm/subdev/fb.h`** — `nvkm_ram_type` enum
//!   (`NVKM_RAM_TYPE_DDR3`, `_GDDR5`, `_HBM2`, `_GDDR6`, `_GDDR6X`,
//!   etc.).

#![allow(dead_code)]

use crate::chip::ChipFamily;

// ── BAR0 register offsets in the PFB block ───────────────────────

/// `NV_PFB_CFG0` — chip-level FB configuration. The high-half
/// holds the VRAM size in MiB on Pascal+. Cited
/// `nvkm/subdev/fb/gp100.c::gp100_fb_init`.
pub const PFB_CFG0: u64 = 0x0010_0200;
/// `NV_PFB_FBPA_*` — per-partition controller registers; we only
/// scan the type field here for diagnostics.
pub const PFB_FBPA: u64 = 0x0011_0000;

// ── VRAM type classification ─────────────────────────────────────

/// Memory technology that backs the GPU's frame-buffer pool. Type
/// dictates the IMC programming sequence and the GDDR/HBM-specific
/// PLL recipe. We don't ship those sequences here — Stage 1 only
/// needs the classification to pick the right firmware bundle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RamType {
    Unknown,
    Ddr3,
    Ddr4,
    Gddr5,
    Gddr5X,
    Gddr6,
    Gddr6X,
    Hbm2,
    Hbm2e,
    Hbm3,
}

impl RamType {
    pub const fn tag(self) -> &'static str {
        match self {
            RamType::Unknown => "unknown",
            RamType::Ddr3 => "ddr3",
            RamType::Ddr4 => "ddr4",
            RamType::Gddr5 => "gddr5",
            RamType::Gddr5X => "gddr5x",
            RamType::Gddr6 => "gddr6",
            RamType::Gddr6X => "gddr6x",
            RamType::Hbm2 => "hbm2",
            RamType::Hbm2e => "hbm2e",
            RamType::Hbm3 => "hbm3",
        }
    }
}

/// Best-effort RAM-type guess from the chip family. Real silicon
/// reports the exact type via PFB_FBPA bits, but the SKU-to-RAM
/// mapping is reasonably stable per generation and serves as a
/// fallback when the per-partition bits aren't yet decoded.
pub const fn ram_type_for_family(family: ChipFamily) -> RamType {
    match family {
        // GTX 750 (GM107) shipped DDR3 / GDDR5; default to GDDR5.
        ChipFamily::Maxwell => RamType::Gddr5,
        // Pascal split GDDR5 (1060/1070), GDDR5X (1080), HBM2 (P100).
        ChipFamily::Pascal => RamType::Gddr5X,
        // Volta — V100 is HBM2.
        ChipFamily::Volta => RamType::Hbm2,
        // Turing introduced GDDR6 across the consumer line.
        ChipFamily::Turing => RamType::Gddr6,
        // Ampere — GDDR6 on 3060, GDDR6X on 3080/3090.
        ChipFamily::Ampere => RamType::Gddr6X,
        // Ada — GDDR6X across the high-end.
        ChipFamily::Ada => RamType::Gddr6X,
        _ => RamType::Unknown,
    }
}

/// Decoded FB configuration. `vram_mib` is best-effort — on a few
/// generations the size needs cross-checking against the BIOS
/// table; we expose what the register-bus says and let the caller
/// reconcile.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FbConfig {
    pub vram_mib: u32,
    pub ram_type: RamType,
}

impl FbConfig {
    /// Decode `NV_PFB_CFG0`. Pascal+: bits[31:16] hold VRAM size
    /// in MiB. (Per nvkm/subdev/fb/gp100.c the size is mirrored
    /// from the BIOS but reads back through the register.)
    pub const fn decode(pfb_cfg0_raw: u32, family: ChipFamily) -> Self {
        let vram_mib = (pfb_cfg0_raw >> 16) & 0xFFFF;
        let ram_type = ram_type_for_family(family);
        Self { vram_mib, ram_type }
    }
}
