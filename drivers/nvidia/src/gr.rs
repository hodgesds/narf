//! Graphics engine (GR).
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/engine/gr/base.c`**
//!   — generic `nvkm_gr_*` entry points.
//! - **`drivers/gpu/drm/nouveau/nvkm/engine/gr/gm200.c`** —
//!   Maxwell+ GR (SM5 shader model). Per-ASIC GR has 100+ subdev
//!   files; the canonical channel-binding + ring management lives
//!   in `gf100.c::gf100_gr_chan_*`.
//! - **`drivers/gpu/drm/nouveau/nvkm/engine/gr/ga102.c`** &
//!   **`gv100.c`** — Volta+/Ampere GR; GSP-loaded firmware for the
//!   FECS+GPCCS Falcons.
//!
//! Stage 3 — Graphics class submission via Pushbuffer (FIFO). The
//! channel-binding code goes here; per-GPU SM/TPC/ROP counts are
//! discovered from the chip's `dev_gr.ref.txt` fuse straps.

#![allow(dead_code)]

use crate::chip::ChipFamily;

// ── BAR0 offsets ─────────────────────────────────────────────────

/// `NV_PGRAPH_STATUS` — top-level GR status.
pub const PGRAPH_STATUS: u64 = 0x0040_0700;
/// `NV_PGRAPH_INTR` — GR interrupt status.
pub const PGRAPH_INTR: u64 = 0x0040_0100;
/// `NV_PGRAPH_INTR_EN` — GR interrupt mask.
pub const PGRAPH_INTR_EN: u64 = 0x0040_0140;

// ── GR class numbers ─────────────────────────────────────────────
//
// Each NVIDIA SM generation exposes its compute interface as a
// Graphics class. Cited `include/nvif/class.h::FERMI_A` etc.
//
// The user-mode client uses these as the class id when allocating
// a channel: nouveau_channel_new(... GR class ...).

pub const FERMI_A: u32 = 0x0000_9097;
pub const KEPLER_A: u32 = 0x0000_a097;
pub const KEPLER_B: u32 = 0x0000_a197;
pub const MAXWELL_A: u32 = 0x0000_b097;
pub const MAXWELL_B: u32 = 0x0000_b197;
pub const PASCAL_A: u32 = 0x0000_c097;
pub const PASCAL_B: u32 = 0x0000_c197;
pub const VOLTA_A: u32 = 0x0000_c397;
pub const TURING_A: u32 = 0x0000_c597;
pub const AMPERE_A: u32 = 0x0000_c697;
pub const AMPERE_B: u32 = 0x0000_c797;
pub const ADA_A: u32 = 0x0000_c997;

/// Map a chip family to its primary 3D class.
pub const fn graphics_class_for(family: ChipFamily) -> Option<u32> {
    match family {
        ChipFamily::Fermi => Some(FERMI_A),
        ChipFamily::Kepler => Some(KEPLER_A),
        ChipFamily::Maxwell => Some(MAXWELL_A),
        ChipFamily::Pascal => Some(PASCAL_A),
        ChipFamily::Volta => Some(VOLTA_A),
        ChipFamily::Turing => Some(TURING_A),
        ChipFamily::Ampere => Some(AMPERE_A),
        ChipFamily::Ada => Some(ADA_A),
        ChipFamily::Unknown(_) => None,
    }
}

/// Compute class (CUDA-side primary). Per
/// `include/nvif/class.h::FERMI_COMPUTE_A` etc.
pub const fn compute_class_for(family: ChipFamily) -> Option<u32> {
    match family {
        ChipFamily::Fermi => Some(0x0000_90c0),
        ChipFamily::Kepler => Some(0x0000_a0c0),
        ChipFamily::Maxwell => Some(0x0000_b0c0),
        ChipFamily::Pascal => Some(0x0000_c0c0),
        ChipFamily::Volta => Some(0x0000_c3c0),
        ChipFamily::Turing => Some(0x0000_c5c0),
        ChipFamily::Ampere => Some(0x0000_c6c0),
        ChipFamily::Ada => Some(0x0000_c9c0),
        ChipFamily::Unknown(_) => None,
    }
}

/// Decoded GPC/TPC/ROP count for a chip — discovered at runtime
/// from fuse straps in the GR block. Stage 3 will read them; we
/// expose the shape so the rest of the driver can consume it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct GrTopology {
    pub gpc_count: u8,
    pub tpc_per_gpc: u8,
    pub rop_count: u8,
}
