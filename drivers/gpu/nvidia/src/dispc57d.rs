//! NvDisplay C57D core-channel method layer (Turing modeset).
//!
//! The existing [`crate::disp::nv50`] encoders target the old EVO
//! (NV507D) display class; Turing GSP cards drive the **NvDisplay**
//! core channel (TU102_DISP_CORE_CHANNEL_DMA = `0xc57d`), which has a
//! different method map. This module provides the C57D method ids +
//! raster/clock/output-resource field encoders + the staging that
//! builds a core-channel modeset into a pushbuffer. The host kicks it
//! at the channel's GET/PUT page ([`crate::gsp_chan::channel_user_offset`]).
//!
//! Grounded against `/usr/src/linux` `include/nvhw/class/clc57d.h` +
//! `dispnv50/{headc57d.c,corec37d.c,head.c}` (the raster derivation).
//!
//! Pure CPU work (no hardware), unit-tested.

#![allow(dead_code)]

use crate::disp::Mode;
use crate::pb::{PbBuilder, PbError};

// ── C57D method ids (byte offsets; head 0 / window 0) ────────────

/// Core UPDATE (shared NVC37D). Value `1` kicks the staged state.
pub const C57D_UPDATE: u16 = 0x0200;
pub const C57D_SET_CONTEXT_DMA_NOTIFIER: u16 = 0x0208;
/// Per-window, stride 0x80.
pub const C57D_WINDOW_SET_WINDOW_FORMAT_USAGE_BOUNDS: u16 = 0x1004;
pub const C57D_WINDOW_SET_WINDOW_USAGE_BOUNDS: u16 = 0x1010;
pub const C57D_WINDOW_STRIDE: u16 = 0x80;
/// Per-head, stride 0x400.
pub const C57D_HEAD_SET_CONTROL_OUTPUT_RESOURCE: u16 = 0x2004;
pub const C57D_HEAD_SET_PIXEL_CLOCK_FREQUENCY: u16 = 0x200c;
pub const C57D_HEAD_SET_RASTER_SIZE: u16 = 0x2064;
pub const C57D_HEAD_SET_RASTER_SYNC_END: u16 = 0x2068;
pub const C57D_HEAD_SET_RASTER_BLANK_END: u16 = 0x206c;
pub const C57D_HEAD_SET_RASTER_BLANK_START: u16 = 0x2070;
pub const C57D_HEAD_STRIDE: u16 = 0x400;

/// `HEAD_SET_CONTROL_OUTPUT_RESOURCE.PIXEL_DEPTH` value for 24bpp 444.
pub const PIXEL_DEPTH_BPP_24_444: u32 = 4;

/// Method id for `base` on head `i` (stride 0x400).
pub const fn head_method(base: u16, i: u8) -> u16 {
    base + (i as u16) * C57D_HEAD_STRIDE
}
/// Method id for `base` on window `w` (stride 0x80).
pub const fn window_method(base: u16, w: u8) -> u16 {
    base + (w as u16) * C57D_WINDOW_STRIDE
}

// ── Raster field encoders ────────────────────────────────────────
//
// Values are derived per `dispnv50/head.c::nv50_head_mode`:
//   active = total; synce = sync_end - sync_start - 1;
//   blanke = blank_end - sync_start - 1 (blank_end == total);
//   blanks = blanke + display.
// `RASTER_SIZE`/`*_SYNC_END`/`*_BLANK_*` pack h in bits[14:0], v in
// bits[30:16] (clc57d.h).

const MASK15: u32 = 0x7fff;

/// `HEAD_SET_RASTER_SIZE` — htotal | vtotal<<16.
pub fn raster_size(m: &Mode) -> u32 {
    (m.h_total as u32 & MASK15) | ((m.v_total as u32 & MASK15) << 16)
}

/// `HEAD_SET_RASTER_SYNC_END` — sync width minus one, h and v.
pub fn raster_sync_end(m: &Mode) -> u32 {
    let h = (m.h_sync_end as u32)
        .wrapping_sub(m.h_sync_start as u32)
        .wrapping_sub(1)
        & MASK15;
    let v = (m.v_sync_end as u32)
        .wrapping_sub(m.v_sync_start as u32)
        .wrapping_sub(1)
        & MASK15;
    h | (v << 16)
}

/// `HEAD_SET_RASTER_BLANK_END` — total - sync_start - 1, h and v.
pub fn raster_blank_end(m: &Mode) -> u32 {
    let h = (m.h_total as u32)
        .wrapping_sub(m.h_sync_start as u32)
        .wrapping_sub(1)
        & MASK15;
    let v = (m.v_total as u32)
        .wrapping_sub(m.v_sync_start as u32)
        .wrapping_sub(1)
        & MASK15;
    h | (v << 16)
}

/// `HEAD_SET_RASTER_BLANK_START` — blank_end + display, h and v.
pub fn raster_blank_start(m: &Mode) -> u32 {
    let he = (m.h_total as u32)
        .wrapping_sub(m.h_sync_start as u32)
        .wrapping_sub(1);
    let ve = (m.v_total as u32)
        .wrapping_sub(m.v_sync_start as u32)
        .wrapping_sub(1);
    let h = he.wrapping_add(m.h_display as u32) & MASK15;
    let v = ve.wrapping_add(m.v_display as u32) & MASK15;
    h | (v << 16)
}

/// `HEAD_SET_PIXEL_CLOCK_FREQUENCY.HERTZ` (bits[30:0]).
pub fn pixel_clock_hz(m: &Mode) -> u32 {
    m.clock_khz.wrapping_mul(1000) & 0x7fff_ffff
}

/// `HEAD_SET_CONTROL_OUTPUT_RESOURCE` with `PIXEL_DEPTH` (bits[7:4]).
pub const fn output_resource(pixel_depth: u32) -> u32 {
    (pixel_depth & 0xf) << 4
}

// ── Staging into a pushbuffer ────────────────────────────────────

/// Stage a core-channel modeset for `head`: raster timing, pixel
/// clock, and output resource. Does not UPDATE — call
/// [`stage_update`] after staging all heads/windows.
pub fn stage_head_mode(pb: &mut PbBuilder<'_>, mode: &Mode, head: u8) -> Result<(), PbError> {
    pb.write_inc(
        head_method(C57D_HEAD_SET_RASTER_SIZE, head),
        &[raster_size(mode)],
    )?;
    pb.write_inc(
        head_method(C57D_HEAD_SET_RASTER_SYNC_END, head),
        &[raster_sync_end(mode)],
    )?;
    pb.write_inc(
        head_method(C57D_HEAD_SET_RASTER_BLANK_END, head),
        &[raster_blank_end(mode)],
    )?;
    pb.write_inc(
        head_method(C57D_HEAD_SET_RASTER_BLANK_START, head),
        &[raster_blank_start(mode)],
    )?;
    pb.write_inc(
        head_method(C57D_HEAD_SET_PIXEL_CLOCK_FREQUENCY, head),
        &[pixel_clock_hz(mode)],
    )?;
    pb.write_inc(
        head_method(C57D_HEAD_SET_CONTROL_OUTPUT_RESOURCE, head),
        &[output_resource(PIXEL_DEPTH_BPP_24_444)],
    )?;
    Ok(())
}

/// Stage the core UPDATE that latches the staged state.
pub fn stage_update(pb: &mut PbBuilder<'_>) -> Result<(), PbError> {
    pb.write_inc(C57D_UPDATE, &[1])
}
