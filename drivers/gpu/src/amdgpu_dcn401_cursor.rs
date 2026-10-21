//! Native DCN401 hardware cursor on a live scanout, on every pipe of the
//! stream whose plane it overlaps. Linux: amdgpu_dm_plane_get_cursor_position
//! (the CRTC position and hotspot DC gets), program_cursor_attributes and
//! program_cursor_position (every pipe of the stream with a plane: the
//! primary's ODM segments and MPC slices and every overlay's),
//! dcn10_set_cursor_attribute (hubp32_cursor_set_attributes,
//! dpp401_set_cursor_attributes, dpp401_set_cursor_sdr_white_level),
//! dcn401_set_cursor_position (recout space, ODM and MPC slice hotspot
//! moves, resource_can_pipe_disable_cursor) with
//! hubp401_cursor_set_position and dpp401_set_cursor_position, all inside
//! dcn10_cursor_lock's mpc1_cursor_lock (CUR_VUPDATE_LOCK_SET of each ODM
//! segment's OPP, whose MPCC tree carries every plane of the segment).
//! Linux caps the DCN401 cursor at 64x64 (dcn401_resource
//! max_cursor_size), which also keeps it out of MALL; DML21 already budgets
//! a 256-wide ARGB cursor per plane. amdgpu_dm always uses the native
//! cursor on DCN 4.0.1 (`cursor_mode`).
use super::*;
use crate::amdgpu_dcn401_spl as spl;
use crate::amdgpu_dcn_color::Fixed31_32 as Fx;
use crate::amdgpu_gmc_navi48::{DisplayContext, Gmc};

pub const CURSOR_MAX: u32 = 64;
const CONTROL: u64 = 0x679; // CURSOR0_n, HUBP stride
const ADDRESS: u64 = 0x67a;
const ADDRESS_HIGH: u64 = 0x67b;
const SIZE: u64 = 0x67c;
const POSITION: u64 = 0x67d;
const HOT_SPOT: u64 = 0x67e;
const DST_OFFSET: u64 = 0x680;
const SETTINGS: u64 = 0x653; // HUBPREQ_CURSOR_SETTINGS
const ENABLE: u32 = 1;
const REQ_MODE: u32 = 4;
/// CURSOR_MODE, 2X_MAGNIFY, PITCH and LINES_PER_CHUNK.
const CONTROL_FIELDS: u32 = 0x1f03_0710;
const PRE_MULTIPLIED: u32 = 2;
const CM_CONTROL: u64 = 0xcf1; // CM_CUR0, DPP stride 0x16b
const CM_SCALE_G_Y: u64 = 0xcf4;
const CM_SCALE_RB: u64 = 0xcf5;
const CM_MATRIX: u64 = 0xcf6;
/// CUR0_ENABLE, EXPANSION_MODE, ROM_EN and MODE.
const CM_FIELDS: u32 = 0x7b;
const FP16_ONE: u32 = 0x3c00;
const LOCK_SET: u64 = 0x2c5; // MPC block, stride 5 per OPP

/// The owned cursor image and where it is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorApplied {
    pub pipe: u8,
    pub address: u64,
    pub width: u32,
    pub height: u32,
    /// Screen position of the image's top-left pixel, as DRM's crtc_x/y.
    pub x: i32,
    pub y: i32,
    /// Programmed enable: false while no pipe shows any of the image.
    pub visible: bool,
    /// The pipes whose cursor is enabled, by bit: every pipe of the stream
    /// (any plane's, ODM segment's or MPC slice's) whose recout the image
    /// overlaps and no plane above covers (dcn401_set_cursor_position per
    /// pipe).
    pub shown: u8,
}
impl CursorApplied {
    pub(in crate::amdgpu_dcn401_otg) fn shown_on(self, pipe: u8) -> bool {
        self.shown & bit(pipe) != 0
    }
}

/// amdgpu_dm's cursor mode on a CRTC (enum amdgpu_dm_cursor_mode): the
/// cursor every DCN plane carries, or a DCN plane of its own above them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorMode {
    Native,
    Overlay,
}
/// One plane under a cursor, as amdgpu_dm_crtc_get_cursor_mode reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorUnder {
    /// amdgpu_dm_plane_is_video_format: a YCbCr framebuffer.
    pub video: bool,
    /// dm_get_plane_scale (`plane_scale`).
    pub scale: (i32, i32),
    /// The plane covers the whole CRTC.
    pub covers_crtc: bool,
}
/// amdgpu_dm_crtc_get_cursor_mode for an enabled cursor of scale
/// `cursor_scale` above `planes` (from the top, as for_each_oldnew_plane_
/// in_descending_zpos visits them) on display IP `dce_ip` (major, minor,
/// revision). DCN 4.0.1 (Navi48), 4.2.0 and 4.2.1 have neither the
/// cursor-on-scaled-plane nor the cursor-on-YUV-plane restriction and
/// always take the native cursor, as does a disabled CRTC; elsewhere a
/// YCbCr plane, a plane scaled unlike the cursor in both directions, or a
/// hole in the planes under the cursor takes the overlay cursor.
pub fn cursor_mode(
    dce_ip: (u8, u8, u8),
    crtc_enabled: bool,
    cursor_scale: (i32, i32),
    planes: &[CursorUnder],
) -> CursorMode {
    if matches!(dce_ip, (4, 0, 1) | (4, 2, 0) | (4, 2, 1)) || !crtc_enabled {
        return CursorMode::Native;
    }
    for p in planes {
        if p.video {
            return CursorMode::Overlay;
        }
        if cursor_scale.0 != p.scale.0 && cursor_scale.1 != p.scale.1 {
            return CursorMode::Overlay;
        }
        if p.covers_crtc {
            return CursorMode::Native;
        }
    }
    CursorMode::Overlay
}
/// dm_get_plane_scale: CRTC size over the (rotated) source size, in
/// thousandths; zero for an empty source.
pub fn plane_scale(src: (u32, u32), crtc: (u32, u32), rotated: bool) -> (i32, i32) {
    let (w, h) = if rotated { (src.1, src.0) } else { src };
    let scale = |c: u32, s: u32| {
        if s == 0 {
            0
        } else {
            (i64::from(c) * 1000 / i64::from(s)) as i32
        }
    };
    (scale(crtc.0, w), scale(crtc.1, h))
}

/// The dc_cursor_position amdgpu_dm_plane_get_cursor_position hands DC for
/// a cursor whose top-left pixel is at (`x`, `y`) on the CRTC: a negative
/// origin moves into the hotspot (at most the cursor size less one); one
/// entirely past the left or top edge is disabled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct DmPosition {
    pub(super) enable: bool,
    pub(super) x: i32,
    pub(super) y: i32,
    pub(super) hot_x: i32,
    pub(super) hot_y: i32,
}
pub(super) fn dm_position(x: i32, y: i32) -> DmPosition {
    let max = CURSOR_MAX as i32;
    if x <= -max || y <= -max {
        return DmPosition::default();
    }
    let (x, hot_x) = if x < 0 {
        (0, (-x).min(max - 1))
    } else {
        (x, 0)
    };
    let (y, hot_y) = if y < 0 {
        (0, (-y).min(max - 1))
    } else {
        (y, 0)
    };
    DmPosition {
        enable: true,
        x,
        y,
        hot_x,
        hot_y,
    }
}

/// One pipe of a stream as dcn401_set_cursor_position reads its pipe_ctx:
/// its plane's layer, its scaler data (recout in its ODM slice's space,
/// viewport, horizontal ratio), its plane's src_rect size, the src widths
/// of the ODM slices before it and its neighbours in the MPCC tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CursorPipe {
    pub(super) pipe: u8,
    /// The plane's layer_index: the same for every slice of one plane.
    pub(super) layer: u8,
    pub(super) recout: spl::Rect,
    pub(super) viewport: spl::Rect,
    /// scl_data.ratios.horz as SPL's register value (U3.19 << 5).
    pub(super) h_ratio: u32,
    /// plane_state->src_rect's size.
    pub(super) src: (i32, i32),
    /// Its plane spans ODM slices (a previous or next ODM pipe).
    pub(super) odm: bool,
    /// The summed resource_get_odm_slice_src_rect widths of the slices
    /// before its own.
    pub(super) prev_odm_width: i32,
    /// An MPCC above it (top_pipe) and below it (bottom_pipe) in its tree.
    pub(super) top: bool,
    pub(super) bottom: bool,
}

/// What the position registers hold for one pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Placement {
    pub(super) visible: bool,
    pub(super) x: u32,
    pub(super) y: u32,
    pub(super) hot_x: u32,
    pub(super) hot_y: u32,
    pub(super) dst_x_offset: u32,
}

/// resource_can_pipe_disable_cursor: a plane of another layer above `p`
/// (`above`, nearest first) whose recout, merged with its other slice
/// among them, contains `p`'s recout hides the cursor on `p`, so it is not
/// drawn twice.
fn covered(p: &CursorPipe, above: &[CursorPipe]) -> bool {
    let r1 = p.recout;
    let (r1_right, r1_bottom) = (r1.x + r1.width, r1.y + r1.height);
    for (i, t) in above.iter().enumerate() {
        if t.layer == p.layer {
            continue;
        }
        let mut r2 = t.recout;
        let mut r2_right = r2.x + r2.width;
        let mut r2_bottom = r2.y + r2.height;
        for (j, s) in above.iter().enumerate() {
            if j == i {
                continue;
            }
            if s.layer == t.layer {
                let half = s.recout;
                r2.x = half.x.min(r2.x);
                r2.width += half.width;
                r2_right = r2.x + r2.width;
                r2_bottom = r2_bottom.min(half.y + half.height);
                break;
            }
        }
        if r1.x >= r2.x && r1.y >= r2.y && r1_right <= r2_right && r1_bottom <= r2_bottom {
            return true;
        }
    }
    false
}

/// dcn401_set_cursor_position and hubp401_cursor_set_position for pipe `p`
/// (no 2x magnification; DCN4's stream src equals its dst): the position
/// past the ODM slices before it, then in its recout's space, every part
/// left of or above either moved into the hotspot (so a cursor straddling
/// ODM or MPC slices, or a plane's edge, shows on both sides), disabled
/// when none of it lands in the recout or a plane above covers the pipe;
/// CURSOR_DST_X_OFFSET from the viewport position in DCHUB reference
/// clocks over the horizontal ratio, the X hotspot clamped to its field.
pub(super) fn pipe_position(
    pos: DmPosition,
    p: &CursorPipe,
    above: &[CursorPipe],
    (width, height): (u32, u32),
    (ref_khz, pixel_khz): (u32, u32),
) -> Placement {
    let (mut hot_x, mut hot_y) = (pos.hot_x, pos.hot_y);
    let mut enable = pos.enable;
    let r = p.recout;
    let mpc_combine_on =
        (p.top || p.bottom) && (p.src.0 != p.viewport.width || p.src.1 != p.viewport.height);
    let (mut x_pos, mut y_pos) = (pos.x, pos.y);
    if p.odm {
        x_pos -= p.prev_odm_width;
    }
    if x_pos < 0 {
        hot_x -= x_pos;
        x_pos = 0;
    }
    if y_pos < 0 {
        hot_y -= y_pos;
        y_pos = 0;
    }
    if mpc_combine_on && p.top {
        let bottom_pipe_x_pos = x_pos - r.x;
        if bottom_pipe_x_pos < 0 {
            x_pos = r.x;
            hot_x -= bottom_pipe_x_pos;
        }
    }
    if enable && covered(p, above) {
        enable = false;
    }
    let mut x_pos = x_pos.wrapping_sub(r.x);
    let mut y_pos = y_pos.wrapping_sub(r.y);
    if x_pos < 0 {
        hot_x -= x_pos;
        x_pos = 0;
    }
    if y_pos < 0 {
        hot_y -= y_pos;
        y_pos = 0;
    }
    let recout_x_pos = x_pos - hot_x;
    let recout_y_pos = y_pos - hot_y;
    if recout_x_pos >= r.width
        || recout_y_pos >= r.height
        || recout_x_pos + width as i32 <= 0
        || recout_y_pos + height as i32 <= 0
    {
        enable = false;
    }
    // hubp401_cursor_set_position: CURSOR_DST_X_OFFSET is relative to the
    // viewport start, in reference clocks, over the horizontal ratio.
    let (x_vp, hot_vp) = if r.width != 0 {
        let to_viewport =
            |v: i32| (i64::from(v) * i64::from(p.viewport.width) / i64::from(r.width)) as i32;
        (to_viewport(x_pos), to_viewport(hot_x))
    } else {
        (0, 0)
    };
    let mut dst = (x_vp - hot_vp).max(0) as u32;
    dst = dst.wrapping_mul(ref_khz) / pixel_khz.max(1);
    // dc_fixpt_from_ux_dy(h_scale_ratio >> 5, 3, 19).
    let ratio = Fx(i64::from(p.h_ratio >> 5) << 13);
    if ratio.0 != 0 {
        dst = Fx::from_int(dst as i32).div(ratio).floor() as u32;
    }
    Placement {
        visible: enable,
        x: x_pos as u32 & 0x7fff,
        y: y_pos as u32 & 0x7fff,
        hot_x: (hot_x as u32).min(0xff),
        hot_y: hot_y as u32 & 0xff,
        dst_x_offset: dst & 0x3fff,
    }
}
/// A cursor at (`x`, `y`) on one unscaled pipe whose recout is the whole
/// `active` stream: the single-pipe case of `pipe_position`.
#[cfg(feature = "kernel-test")]
pub(super) fn placement(
    x: i32,
    y: i32,
    size: (u32, u32),
    (active_w, active_h): (u32, u32),
    clocks: (u32, u32),
) -> Placement {
    let r = spl::Rect::new(0, 0, active_w as i32, active_h as i32);
    let p = CursorPipe {
        pipe: 0,
        layer: 0,
        recout: r,
        viewport: r,
        h_ratio: 1 << 19 << 5,
        src: (r.width, r.height),
        odm: false,
        prev_odm_width: 0,
        top: false,
        bottom: false,
    };
    pipe_position(dm_position(x, y), &p, &[], size, clocks)
}
/// At most 64x64 (Linux's DCN401 cap), one pixel per position.
fn validate_image(width: u32, height: u32, pixels: &[u32]) -> Result<(), Error> {
    if !(1..=CURSOR_MAX).contains(&width)
        || !(1..=CURSOR_MAX).contains(&height)
        || pixels.len() != (width * height) as usize
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
/// CURSOR_LINES_PER_CHUNK for 32 bpp (hubp2_get_lines_per_chunk).
fn lines_per_chunk(width: u32) -> u32 {
    match width {
        0..=32 => 4,
        33..=64 => 3,
        65..=128 => 2,
        _ => 1,
    }
}

/// Every pipe of the planes `primary` and `overlays` (bottom first) as
/// dcn401_set_cursor_position reads it, each with the pipes above it in
/// its segment's MPCC tree, nearest first; in tree order, segment by
/// segment.
pub(super) fn stream_cursor_pipes(
    primary: SurfaceApplied,
    overlays: &[Option<SurfaceApplied>; MAX_OVERLAYS],
) -> alloc::vec::Vec<(CursorPipe, alloc::vec::Vec<CursorPipe>)> {
    // The planes in stacking order: their layer indices.
    let planes: alloc::vec::Vec<SurfaceApplied> = overlays
        .iter()
        .flatten()
        .filter(|o| o.request.layout().underlay)
        .copied()
        .chain(core::iter::once(primary))
        .chain(
            overlays
                .iter()
                .flatten()
                .filter(|o| !o.request.layout().underlay)
                .copied(),
        )
        .collect();
    // resource_get_odm_slice_src_rect: a 4:2:0 slice after the first is one
    // pixel wider to the left.
    let edge = i32::from(primary.request.layout().ycbcr420);
    let mut slice_widths = alloc::vec::Vec::new();
    for ((_, segment, slice), (_, _, w)) in primary.request.slices().zip(primary.request.segments())
    {
        if slice == 0 {
            slice_widths.push(w as i32 + if segment > 0 { edge } else { 0 });
        }
    }
    let prev = |segment: u32| -> i32 { slice_widths.iter().take(segment as usize).sum() };
    let mut all: alloc::vec::Vec<CursorPipe> = alloc::vec::Vec::new();
    for (layer, s) in planes.iter().enumerate() {
        let src = s.request.layout().src;
        for ((p, segment, _), (_, scaler)) in s.request.slices().zip(s.request.scalers()) {
            all.push(CursorPipe {
                pipe: p,
                layer: layer as u8,
                recout: scaler.recout,
                viewport: scaler.viewport,
                h_ratio: scaler.ratios[0],
                src: (src.width, src.height),
                odm: s.request.odm.is_some(),
                prev_odm_width: prev(segment),
                top: false,
                bottom: false,
            });
        }
    }
    let scanned = overlays.map(|o| o.map(OverlayScanout::of));
    let trees = super::scanout::trees(
        (
            primary.request.pipe,
            primary.request.odm,
            primary.request.mpc,
        ),
        &scanned,
    );
    let mut out = alloc::vec::Vec::new();
    for tree in trees {
        let placed: alloc::vec::Vec<CursorPipe> = tree
            .iter()
            .enumerate()
            .filter_map(|(j, &q)| {
                let c = all.iter().find(|c| c.pipe == q)?;
                Some(CursorPipe {
                    top: j + 1 < tree.len(),
                    bottom: j > 0,
                    ..*c
                })
            })
            .collect();
        for (j, c) in placed.iter().enumerate() {
            out.push((*c, placed[j + 1..].to_vec()));
        }
    }
    out
}

impl<I: Io> Engine<I> {
    pub(super) fn cm(&self, pipe: u8, reg: u64) -> u64 {
        self.layout.base + (reg + u64::from(self.layout.inst(pipe)) * 0x16b) * 4
    }
    /// The cursor lock of the MPCC tree of pipe `opp`'s OPP.
    fn cursor_lock_at(&self, opp: u8) -> u64 {
        self.layout.mpc_base + (LOCK_SET + u64::from(self.layout.inst(opp)) * 5) * 4
    }
    /// The OPP of every ODM segment of `pipe`'s stream: each MPCC tree's.
    fn stream_opps(&self, pipe: u8) -> alloc::vec::Vec<u8> {
        let odm = self
            .status
            .surfaces
            .get(usize::from(pipe))
            .copied()
            .flatten()
            .map_or(SplitPipes::NONE, |a| a.request.odm);
        core::iter::once(pipe).chain(odm).collect()
    }
    /// Cursor registers latch together at the VUPDATE after the locks drop:
    /// each segment's OPP (the cursor lock is per MPCC tree) is locked
    /// across the writes.
    fn cursor_locked(
        &mut self,
        pipe: u8,
        writes: impl FnOnce(&mut Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let locks: alloc::vec::Vec<u64> = self
            .stream_opps(pipe)
            .into_iter()
            .map(|o| self.cursor_lock_at(o))
            .collect();
        let mut held = 0;
        let mut result = Ok(());
        for &at in &locks {
            result = self.update(at, 1, 1);
            if result.is_err() {
                break;
            }
            held += 1;
        }
        if result.is_ok() {
            result = writes(self);
        }
        // Always release: a held cursor lock would freeze cursor latching.
        for &at in locks[..held].iter().rev() {
            let released = self.update(at, 1, 0);
            result = result.and(released);
        }
        result
    }
    /// Every pipe of display `a.pipe`'s planes (as its records name them)
    /// with its placement of `a` (program_cursor_position).
    pub(super) fn cursor_segments(
        &self,
        a: CursorApplied,
    ) -> Result<alloc::vec::Vec<(u8, Placement)>, Error> {
        let deadlines = self.status.deadlines.ok_or(Error::Invalid)?;
        let primary = self
            .status
            .surfaces
            .get(usize::from(a.pipe))
            .copied()
            .flatten()
            .ok_or(Error::Invalid)?;
        let overlays = self
            .status
            .requestor
            .filter(|r| r.pipe == a.pipe)
            .map_or([None; MAX_OVERLAYS], |r| r.overlays);
        Ok(placements(
            a,
            primary,
            &overlays,
            clocks_of(&deadlines.plan),
        ))
    }
    pub(super) fn cursor_attributes(&mut self, a: CursorApplied, p: u8) -> [(u64, u32, u32); 9] {
        let l = self.layout;
        [
            (l.hubp(p, ADDRESS_HIGH), 0xffff, (a.address >> 32) as u32),
            (l.hubp(p, ADDRESS), u32::MAX, a.address as u32),
            (l.hubp(p, SIZE), 0x01ff_01ff, a.width << 16 | a.height),
            // Pitch 64 pixels (field 0), no magnification, early requests.
            (
                l.hubp(p, CONTROL),
                CONTROL_FIELDS | REQ_MODE,
                lines_per_chunk(a.width) << 24 | PRE_MULTIPLIED << 8 | REQ_MODE,
            ),
            (l.hubp(p, SETTINGS), u32::MAX, 0x300), // full write, as Linux
            (
                self.cm(p, CM_CONTROL),
                CM_FIELDS & !ENABLE,
                PRE_MULTIPLIED << 4,
            ),
            (self.cm(p, CM_SCALE_G_Y), u32::MAX, FP16_ONE),
            (self.cm(p, CM_SCALE_RB), u32::MAX, FP16_ONE),
            (self.cm(p, CM_MATRIX), 3, 0),
        ]
    }
    fn cursor_position(&mut self, pipe: u8, at: Placement) -> [(u64, u32, u32); 5] {
        let l = self.layout;
        let en = u32::from(at.visible);
        [
            (l.hubp(pipe, POSITION), 0x3fff_ffff, at.x << 15 | at.y),
            (
                l.hubp(pipe, HOT_SPOT),
                0x00ff_00ff,
                at.hot_x << 16 | at.hot_y,
            ),
            (l.hubp(pipe, DST_OFFSET), 0x3fff, at.dst_x_offset),
            (l.hubp(pipe, CONTROL), ENABLE, en),
            (self.cm(pipe, CM_CONTROL), ENABLE, en),
        ]
    }
    /// Every pipe's cursor attributes and position (dcn10_set_cursor_attribute
    /// and dcn401_set_cursor_position per pipe), without a lock of their own.
    pub(super) fn cursor_writes(
        &mut self,
        a: CursorApplied,
        segments: &[(u8, Placement)],
    ) -> alloc::vec::Vec<(u64, u32, u32)> {
        let mut writes = alloc::vec::Vec::new();
        for &(p, at) in segments {
            writes.extend(self.cursor_attributes(a, p));
            writes.extend(self.cursor_position(p, at));
        }
        writes
    }
    pub(super) fn program_cursor(
        &mut self,
        a: CursorApplied,
        segments: &[(u8, Placement)],
    ) -> Result<(), Error> {
        let writes = self.cursor_writes(a, segments);
        self.cursor_locked(a.pipe, |e| {
            for (at, mask, value) in writes {
                e.update(at, mask, value)?;
            }
            Ok(())
        })
    }
    pub(super) fn verify_cursor(
        &mut self,
        a: CursorApplied,
        segments: &[(u8, Placement)],
    ) -> Result<(), Error> {
        for &(p, place) in segments {
            let attributes = self.cursor_attributes(a, p);
            let position = self.cursor_position(p, place);
            for (at, mask, value) in attributes.into_iter().chain(position) {
                if self.read(at)? & mask != value {
                    return Err(Error::Readback(at));
                }
            }
        }
        for o in self.stream_opps(a.pipe) {
            if self.read(self.cursor_lock_at(o))? & 1 != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    /// Disable both cursor enables on every pipe of the display's planes;
    /// used before the planes stop.
    pub(super) fn hide_cursor(&mut self, pipe: u8) -> Result<(), Error> {
        let at: alloc::vec::Vec<(u64, u64)> = self
            .plane_pipes(pipe)
            .into_iter()
            .map(|p| (self.layout.hubp(p, CONTROL), self.cm(p, CM_CONTROL)))
            .collect();
        self.cursor_locked(pipe, |e| {
            for (hubp, cm) in at {
                e.update(hubp, ENABLE, 0)?;
                e.update(cm, ENABLE, 0)?;
            }
            Ok(())
        })
    }
}

/// The DCHUB reference and pixel clocks of a stream running `plan`
/// (dc_cursor_mi_param's ref_clk_khz and pixel_clk_khz).
pub(super) fn clocks_of(plan: &crate::amdgpu_dcn401_dml::Plan) -> (u32, u32) {
    (plan.soc.dchub_refclk_khz, plan.mode.timing.pixel_clock_khz)
}
/// `a` placed on every pipe of the planes `primary` and `overlays` of a
/// stream at `clocks` (`clocks_of`).
pub(super) fn placements(
    a: CursorApplied,
    primary: SurfaceApplied,
    overlays: &[Option<SurfaceApplied>; MAX_OVERLAYS],
    clocks: (u32, u32),
) -> alloc::vec::Vec<(u8, Placement)> {
    let pos = dm_position(a.x, a.y);
    stream_cursor_pipes(primary, overlays)
        .iter()
        .map(|(p, above)| {
            (
                p.pipe,
                pipe_position(pos, p, above, (a.width, a.height), clocks),
            )
        })
        .collect()
}
/// `a` with the pipes `segments` enable recorded.
pub(super) fn shown(a: CursorApplied, segments: &[(u8, Placement)]) -> CursorApplied {
    let shown = segments
        .iter()
        .filter(|(_, at)| at.visible)
        .fold(0, |m, &(p, _)| m | bit(p));
    CursorApplied {
        visible: shown != 0,
        shown,
        ..a
    }
}

impl Surfaces {
    /// Upload a premultiplied ARGB8888 image (row-major, `width` x `height`,
    /// at most 64x64) into the pipe's cursor buffer, allocated on first use,
    /// and show it at (`x`, `y`). Requires a live scanout on the pipe.
    pub(in crate::amdgpu_dcn401_otg) fn set_cursor<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pool: &Pool,
        config: DisplayContext,
        pipe: u8,
        image: (u32, u32, &[u32]),
        (x, y): (i32, i32),
    ) -> Result<CursorApplied, Error> {
        let (width, height, pixels) = image;
        validate_image(width, height, pixels)?;
        let running = e.status.scanout.ok_or(Error::Invalid)?;
        if e.status.state != State::ScanoutRunning(pipe) || running.pipe != pipe {
            return Err(Error::Busy);
        }
        let slot = usize::from(pipe);
        let surface = self
            .0
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(Error::Invalid)?;
        if surface.cursor.is_none() {
            let mut memory = pool
                .reserve(u64::from(CURSOR_MAX * CURSOR_MAX * 4))
                .map_err(|_| Error::Allocation)?;
            if memory.address() < config.fb_base
                || memory
                    .address()
                    .checked_add(memory.size() - 1)
                    .is_none_or(|last| last > config.fb_top || last >= 1 << 48)
            {
                return Err(Error::Invalid);
            }
            memory.publish();
            surface.cursor = Some(memory);
        }
        let memory = surface.cursor.as_ref().ok_or(Error::Invalid)?;
        let map = memory.mapping();
        let address = memory.address();
        // Pitch is the full 64-pixel row; padding stays transparent black.
        e.access(|_| {
            for row in 0..CURSOR_MAX {
                for col in 0..CURSOR_MAX {
                    let pixel = if row < height && col < width {
                        pixels[(row * width + col) as usize]
                    } else {
                        0
                    };
                    // SAFETY: live authority; offset within the owned 16 KiB buffer.
                    unsafe { map.write32(u64::from(row * CURSOR_MAX + col) * 4, pixel) };
                }
            }
            Ok(())
        })?;
        e.flush_surface_writes()?;
        let applied = CursorApplied {
            pipe,
            address,
            width,
            height,
            x,
            y,
            visible: false,
            shown: 0,
        };
        self.place_cursor(e, applied)
    }
    /// Move the owned cursor; hidden when entirely off screen.
    pub(in crate::amdgpu_dcn401_otg) fn move_cursor<I: Io>(
        &self,
        e: &mut Engine<I>,
        pipe: u8,
        (x, y): (i32, i32),
    ) -> Result<CursorApplied, Error> {
        let current = e.status.cursor.ok_or(Error::Invalid)?;
        if current.pipe != pipe || e.status.state != State::ScanoutRunning(pipe) {
            return Err(Error::Busy);
        }
        self.place_cursor(e, CursorApplied { x, y, ..current })
    }
    fn place_cursor<I: Io>(
        &self,
        e: &mut Engine<I>,
        a: CursorApplied,
    ) -> Result<CursorApplied, Error> {
        let segments = e.cursor_segments(a)?;
        let a = shown(a, &segments);
        e.status.state = State::Cursor(a.pipe);
        e.status.cursor = None;
        match e
            .program_cursor(a, &segments)
            .and_then(|()| e.verify_cursor(a, &segments))
        {
            Ok(()) => {
                e.status.cursor = Some(a);
                e.status.state = State::ScanoutRunning(a.pipe);
                Ok(a)
            }
            Err(err) => {
                e.status.state = State::Failed(err);
                Err(err)
            }
        }
    }
}

impl Otg {
    /// Show a premultiplied ARGB8888 cursor (at most 64x64) on a live pipe.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/HDP writers; the cursor
    /// buffer is retained by the pipe until explicit surface release.
    pub unsafe fn set_cursor(
        &mut self,
        pool: &Pool,
        gmc: &mut Gmc,
        pipe: u8,
        image: (u32, u32, &[u32]),
        position: (i32, i32),
    ) -> Result<CursorApplied, Error> {
        // Display k scans out on pipe k: address that display's records.
        self.0.select_display(pipe)?;
        let config = gmc.display_context(self.0.io.0).map_err(Error::Memory)?;
        self.1
            .set_cursor(&mut self.0, pool, config, pipe, image, position)
    }
    /// Move the live cursor.
    /// # Safety
    /// As for `set_cursor`.
    pub unsafe fn move_cursor(
        &mut self,
        pipe: u8,
        position: (i32, i32),
    ) -> Result<CursorApplied, Error> {
        // Display k scans out on pipe k: address that display's records.
        self.0.select_display(pipe)?;
        self.1.move_cursor(&mut self.0, pipe, position)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_cursor_tests.rs"]
mod tests;
