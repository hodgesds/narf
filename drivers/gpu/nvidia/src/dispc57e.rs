//! NvDisplay C57E window-channel method layer (Turing surface scanout).
//!
//! The core channel ([`crate::dispc57d`]) programs the raster timing;
//! the **window** channel (TU102_DISP_WINDOW_CHANNEL_DMA = `0xc57e`)
//! points a head at an actual framebuffer surface — its address,
//! format, and size. This module provides the C57E method ids + field
//! encoders + the staging that builds a surface present into a
//! pushbuffer, kicked at the window channel's GET/PUT page
//! ([`crate::gsp_chan::channel_user_offset`]).
//!
//! Grounded against `/usr/src/linux` `include/nvhw/class/clc57e.h` +
//! `dispnv50/{wndwc57e.c,wndwc37e.c}`.
//!
//! Pure CPU work (no hardware), unit-tested.

#![allow(dead_code)]

use crate::pb::{PbBuilder, PbError};

// ── C57E method ids (byte offsets) ───────────────────────────────

/// Window UPDATE (shared NVC37E). Value `1` latches the staged state.
pub const C57E_UPDATE: u16 = 0x0200;
/// Surface width/height (`WIDTH` 15:0, `HEIGHT` 31:16).
pub const C57E_SET_SIZE: u16 = 0x0224;
/// Memory layout (`BLOCK_HEIGHT` 3:0, `MEMORY_LAYOUT` 4:4).
pub const C57E_SET_STORAGE: u16 = 0x0228;
/// Pixel format (`FORMAT` 7:0).
pub const C57E_SET_PARAMS: u16 = 0x022c;
/// ISO (scanout) context-DMA handle, plane `b` (stride 4).
pub const C57E_SET_CONTEXT_DMA_ISO: u16 = 0x0240;
/// Surface offset within the ctx-dma, plane `b` (stride 4); value is
/// the byte offset shifted right by 8 (256-byte units).
pub const C57E_SET_OFFSET: u16 = 0x0260;
/// Input viewport size.
pub const C57E_SET_SIZE_IN: u16 = 0x0298;
/// Output (scaled) size.
pub const C57E_SET_SIZE_OUT: u16 = 0x02a4;
/// Per-plane method stride for the `(b)` methods.
pub const C57E_PLANE_STRIDE: u16 = 0x4;

/// `SET_STORAGE.MEMORY_LAYOUT` values.
pub const MEMORY_LAYOUT_BLOCKLINEAR: u32 = 0;
pub const MEMORY_LAYOUT_PITCH: u32 = 1;
/// `SET_PARAMS.FORMAT` for 32-bit ARGB (the common XRGB8888 scanout).
pub const FORMAT_A8R8G8B8: u32 = 0xcf;

/// Method id for a per-plane method (`SET_CONTEXT_DMA_ISO`/`SET_OFFSET`).
pub const fn plane_method(base: u16, b: u8) -> u16 {
    base + (b as u16) * C57E_PLANE_STRIDE
}

// ── Field encoders ───────────────────────────────────────────────

/// `SET_SIZE` / `SET_SIZE_IN` / `SET_SIZE_OUT` — width | height<<16.
pub const fn size_wh(w: u16, h: u16) -> u32 {
    (w as u32) | ((h as u32) << 16)
}

/// `SET_STORAGE` — memory layout + block height.
pub const fn storage(memory_layout: u32, block_height: u32) -> u32 {
    (block_height & 0xf) | ((memory_layout & 1) << 4)
}

/// `SET_PARAMS` — the pixel format (other fields default to 0).
pub const fn params(format: u32) -> u32 {
    format & 0xff
}

/// `SET_OFFSET` value for a byte `offset` (256-byte units).
pub const fn offset_units(offset: u64) -> u32 {
    (offset >> 8) as u32
}

// ── Staging ──────────────────────────────────────────────────────

/// Stage a full-screen pitch-linear XRGB8888 surface present on this
/// window channel: size/storage/format, the scanout ctx-dma + offset
/// (plane 0), and the input/output viewport. Does not UPDATE — call
/// [`stage_update`] after.
pub fn stage_surface(
    pb: &mut PbBuilder<'_>,
    fb_handle: u32,
    fb_offset: u64,
    width: u16,
    height: u16,
) -> Result<(), PbError> {
    pb.write_inc(C57E_SET_SIZE, &[size_wh(width, height)])?;
    pb.write_inc(C57E_SET_STORAGE, &[storage(MEMORY_LAYOUT_PITCH, 0)])?;
    pb.write_inc(C57E_SET_PARAMS, &[params(FORMAT_A8R8G8B8)])?;
    pb.write_inc(plane_method(C57E_SET_CONTEXT_DMA_ISO, 0), &[fb_handle])?;
    pb.write_inc(plane_method(C57E_SET_OFFSET, 0), &[offset_units(fb_offset)])?;
    pb.write_inc(C57E_SET_SIZE_IN, &[size_wh(width, height)])?;
    pb.write_inc(C57E_SET_SIZE_OUT, &[size_wh(width, height)])?;
    Ok(())
}

/// Stage the window UPDATE that latches the staged surface.
pub fn stage_update(pb: &mut PbBuilder<'_>) -> Result<(), PbError> {
    pb.write_inc(C57E_UPDATE, &[1])
}
