//! Copy Engine (CE) — async DMA.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/engine/ce/base.c`**
//!   — generic CE entry.
//! - **`drivers/gpu/drm/nouveau/nvkm/engine/ce/gm200.c`** /
//!   **`gp100.c`** / **`tu102.c`** / **`ga102.c`** — per-ASIC CE
//!   instance count + Falcon base.
//!
//! Each CE is a small DMA engine that can copy:
//! - VRAM → VRAM
//! - sysmem → VRAM (and back)
//! - peer-VRAM → VRAM (multi-GPU)
//!
//! Submission is via the host FIFO (same pushbuffer machinery as
//! GR), using the CE classes below.

#![allow(dead_code)]

use crate::chip::ChipFamily;

// ── CE class numbers ─────────────────────────────────────────────
//
// Cited `include/nvif/class.h::FERMI_DMA` family.

pub const KEPLER_DMA_COPY_A: u32 = 0x0000_a0b5;
pub const MAXWELL_DMA_COPY_A: u32 = 0x0000_b0b5;
pub const PASCAL_DMA_COPY_A: u32 = 0x0000_c0b5;
pub const PASCAL_DMA_COPY_B: u32 = 0x0000_c1b5;
pub const VOLTA_DMA_COPY_A: u32 = 0x0000_c3b5;
pub const TURING_DMA_COPY_A: u32 = 0x0000_c5b5;
pub const AMPERE_DMA_COPY_A: u32 = 0x0000_c6b5;
pub const AMPERE_DMA_COPY_B: u32 = 0x0000_c7b5;
pub const ADA_DMA_COPY_A: u32 = 0x0000_c9b5;

/// Number of CE instances per family. Pulled from Nouveau's
/// per-ASIC `*_ce.func.inst.nr`.
pub const fn ce_instance_count(family: ChipFamily) -> u8 {
    match family {
        ChipFamily::Maxwell => 3,
        ChipFamily::Pascal => 4,
        ChipFamily::Volta => 8,
        ChipFamily::Turing => 5,
        ChipFamily::Ampere => 8,
        ChipFamily::Ada => 8,
        _ => 1,
    }
}

/// Map a chip family to its primary CE class.
pub const fn ce_class_for(family: ChipFamily) -> Option<u32> {
    match family {
        ChipFamily::Maxwell => Some(MAXWELL_DMA_COPY_A),
        ChipFamily::Pascal => Some(PASCAL_DMA_COPY_A),
        ChipFamily::Volta => Some(VOLTA_DMA_COPY_A),
        ChipFamily::Turing => Some(TURING_DMA_COPY_A),
        ChipFamily::Ampere => Some(AMPERE_DMA_COPY_A),
        ChipFamily::Ada => Some(ADA_DMA_COPY_A),
        _ => None,
    }
}

// ── CE submission shape ──────────────────────────────────────────
//
// Cite `include/nvhw/class/cl90b5.h` (Maxwell CE) for the method
// space. The driver pushes:
//
//   LAUNCH_DMA (method 0x00C0): start a copy.
//   OFFSET_IN_UPPER / OFFSET_IN_LOWER (0x0400/0x0404): source 64-b
//                                                     address.
//   OFFSET_OUT_UPPER / OFFSET_OUT_LOWER (0x0408/0x040C): dest.
//   LINE_LENGTH_IN (0x0418): bytes per line.
//   LINE_COUNT (0x041C): number of lines.
//
// Stage 3 will assemble these into pushbuffer entries via
// `fifo::pb_header`. The shape lives here as a typed descriptor.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CopyDesc {
    pub src: u64,
    pub dst: u64,
    pub line_length: u32,
    pub line_count: u32,
    /// LAUNCH_DMA flags packed into the method's data word.
    pub flags: u32,
}

/// CE method addresses (cl90b5).
pub const CE_LAUNCH_DMA: u16 = 0x00C0;
pub const CE_OFFSET_IN_UPPER: u16 = 0x0400;
pub const CE_OFFSET_IN_LOWER: u16 = 0x0404;
pub const CE_OFFSET_OUT_UPPER: u16 = 0x0408;
pub const CE_OFFSET_OUT_LOWER: u16 = 0x040C;
pub const CE_LINE_LENGTH_IN: u16 = 0x0418;
pub const CE_LINE_COUNT: u16 = 0x041C;

/// LAUNCH_DMA flag bits (subset).
pub const CE_FLAGS_BLOCKING: u32 = 1 << 8;
pub const CE_FLAGS_PIPELINED: u32 = 1 << 9;
