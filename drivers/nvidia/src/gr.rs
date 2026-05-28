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

// ── GR class method ids (item 11) ────────────────────────────────
//
// Cite Nouveau's `nvhw/class/` headers; the methods below are stable
// across MAXWELL_A / PASCAL_A / VOLTA_A / TURING_A / AMPERE_A.
//
// MAXWELL_A class entry is `0xb097`. To bind a class to a subchannel
// the host pushes a `SET_OBJECT` method (id 0x0) whose data word is
// the class id; subsequent methods in that subchannel are dispatched
// to the bound class.

/// SET_OBJECT method id — bind class to subchannel.
pub const GR_SET_OBJECT: u16 = 0x0000;
/// NO_OPERATION method id (NV90C0 / NV9097) — used as ring filler.
pub const GR_NO_OPERATION: u16 = 0x0100;
/// CLEAR_REPORT_VALUE — reset perf counters (Maxwell+).
pub const GR_CLEAR_REPORT_VALUE: u16 = 0x0024;
/// CLEAR_BUFFERS — clear the bound render target. Cite
/// `nvhw/class/cl9097.h::NV9097_CLEAR_SURFACE` family. We expose
/// the umbrella method id; the data word's fields say which buffers
/// to clear.
pub const GR_CLEAR_BUFFERS: u16 = 0x0674;
/// SET_VIEWPORT_HORIZONTAL — viewport x/width.
pub const GR_SET_VIEWPORT_HORIZONTAL: u16 = 0x0a00;
/// SET_VIEWPORT_VERTICAL — viewport y/height.
pub const GR_SET_VIEWPORT_VERTICAL: u16 = 0x0a04;
/// SET_COLOR_TARGET_A_LOWER — render target address (low 32 bits).
pub const GR_SET_COLOR_TARGET_A_LOWER: u16 = 0x0800;
/// SET_COLOR_TARGET_A_UPPER — render target address (high 32 bits).
pub const GR_SET_COLOR_TARGET_A_UPPER: u16 = 0x0804;
/// SET_COLOR_TARGET_A_WIDTH — render target width in px.
pub const GR_SET_COLOR_TARGET_A_WIDTH: u16 = 0x0808;
/// SET_COLOR_TARGET_A_HEIGHT — render target height in px.
pub const GR_SET_COLOR_TARGET_A_HEIGHT: u16 = 0x080C;
/// SET_COLOR_TARGET_A_FORMAT — render target format code.
pub const GR_SET_COLOR_TARGET_A_FORMAT: u16 = 0x0810;
/// SET_CLEAR_COLOR_R — clear-color R component (float).
pub const GR_SET_CLEAR_COLOR_R: u16 = 0x0820;
/// SET_CLEAR_COLOR_G — clear-color G component.
pub const GR_SET_CLEAR_COLOR_G: u16 = 0x0824;
/// SET_CLEAR_COLOR_B — clear-color B component.
pub const GR_SET_CLEAR_COLOR_B: u16 = 0x0828;
/// SET_CLEAR_COLOR_A — clear-color A component.
pub const GR_SET_CLEAR_COLOR_A: u16 = 0x082C;

/// GR submission subchannel — by convention 0 on Maxwell+. Cite
/// `nvhw/class/cl906f.h::NV906F_DMA_METHOD_SUBCHANNEL`.
pub const GR_SUBCHANNEL: u16 = 0;

/// Color-buffer format code for BGRA8888 (the format the disp
/// engine + fb console use). Cite `nvhw/class/cl9097.h`.
pub const GR_FORMAT_A8R8G8B8: u32 = 0xCF;

/// Default CLEAR_BUFFERS payload — clear color buffer A.
/// Bits[3:0] = TARGET (0 = A), bit 4 = R, bit 5 = G, bit 6 = B,
/// bit 7 = A, bit 8 = depth, bit 9 = stencil. Cite cl9097.h
/// `NV9097_CLEAR_SURFACE_*`.
pub const GR_CLEAR_BUFFERS_COLOR_RGBA: u32 = 0xF0;

/// Stage a "bind GR class + clear-screen" pushbuffer batch into
/// `pb`. Designed for first-triangle-equivalent bring-up: program
/// the render target, set the clear colour, and run CLEAR_BUFFERS.
/// The colour values are IEEE-754 floats stored as raw u32.
///
/// Cite Nouveau's `nv50_fbcon_fillrect` family for the same shape
/// — the cleared FB then drives the disp scanout. The data words
/// mirror those used by the Mesa Nouveau gallium driver when it
/// emits a colour clear.
pub fn stage_clear_screen(
    pb: &mut crate::pb::PbBuilder<'_>,
    class_id: u32,
    fb_phys: u64,
    width: u16,
    height: u16,
    clear_color_rgba: [u32; 4],
) -> Result<(), crate::pb::PbError> {
    // Bind the class to subchannel 0.
    pb.write_inc(GR_SET_OBJECT, &[class_id])?;
    // Programme the color target (5 consecutive words starting at
    // SET_COLOR_TARGET_A_LOWER).
    pb.write_inc(
        GR_SET_COLOR_TARGET_A_LOWER,
        &[
            (fb_phys & 0xFFFF_FFFF) as u32,
            (fb_phys >> 32) as u32,
            width as u32,
            height as u32,
            GR_FORMAT_A8R8G8B8,
        ],
    )?;
    // Programme clear color (4 consecutive words starting at
    // SET_CLEAR_COLOR_R).
    pb.write_inc(GR_SET_CLEAR_COLOR_R, &clear_color_rgba)?;
    // Fire CLEAR_BUFFERS.
    pb.write_inc(GR_CLEAR_BUFFERS, &[GR_CLEAR_BUFFERS_COLOR_RGBA])?;
    Ok(())
}

/// Stage a no-op ring filler that keeps the GR channel alive
/// between submissions. Used for synchronization round-trips while
/// waiting on a fence.
pub fn stage_ring_noop(pb: &mut crate::pb::PbBuilder<'_>) -> Result<(), crate::pb::PbError> {
    pb.write_inc(GR_NO_OPERATION, &[0])
}
