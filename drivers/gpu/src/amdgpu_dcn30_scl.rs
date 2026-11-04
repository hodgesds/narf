//! DCN 3.0 scaling geometry: `resource_build_scaling_params` (`dc_resource.c`)
//! as DC runs it on DCN3.0, where `use_spl` is off, for one pipe of a linear
//! RGB primary that amdgpu_dm placed with `amdgpu_dm_plane_fill_dc_scaling_info`
//! (SRC in whole pixels, CRTC rectangle as dst and clip, no rotation or
//! mirror), on a stream whose source and destination are the whole timing
//! (no RMX scaling, no borders, no 3D view, no visual confirm, no MPC split).
//!
//! The steps are Linux's: `calculate_recout` (the plane clipped to the
//! stream and to this pipe's ODM slice, relative to the slice),
//! `calculate_scaling_ratios` (U3.19-truncated src/dst), the tap choice of
//! `dpp3_get_optimal_number_of_taps` (first against a dummy 100x100
//! viewport, then the real one; `dscl2_calc_lb_num_partitions` for the line
//! buffer, `max_downscale_src_width` 7680, no `always_scale`), then
//! `calculate_inits_and_viewports` / `calculate_init_and_vp`, and the
//! `MIN_VIEWPORT_SIZE` clamp. RGB has no chroma plane: DC's `_c` copies
//! equal the luma values (vpc_div 1, the same ratio and taps), so only luma
//! is kept. All arithmetic is `dc_fixpt` 31.32, rounding as Linux does.
use crate::amdgpu_dcn_color::Fixed31_32 as Fx;

/// `struct rect`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}
impl Rect {
    pub const fn new(x: i32, y: i32, width: i32, height: i32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
}

/// `MIN_VIEWPORT_SIZE` (`dc_resource.c`).
pub const MIN_VIEWPORT_SIZE: i32 = 12; // linux: n/a (#define MIN_VIEWPORT_SIZE 12, dc_resource.c)
/// `dcn30_resource.c` `debug_defaults_drv.max_downscale_src_width`.
const MAX_DOWNSCALE_SRC_WIDTH: i32 = 7680; // linux: n/a (debug_defaults_drv.max_downscale_src_width, dcn30_resource.c)
/// `dscl2_calc_lb_num_partitions`' LB_MEMORY_CONFIG_0 size, in 6-pixel
/// memory words: 970 + 1290 + 484.
const LB_MEMORY_CONFIG_0_WORDS: i32 = 970 + 1290 + 484; // linux: n/a (dscl2_calc_lb_num_partitions, dcn20_dpp.c)
/// The partition cap `dscl2_calc_lb_num_partitions` applies.
const MAX_LB_PARTITIONS: i32 = 64; // linux: n/a (num_part_y cap 64, dcn20_dpp.c)

/// One pipe's scaler data (`struct scaler_data`), luma only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScalerData {
    /// `h_active` / `v_active`: the ODM slice this pipe outputs (MPC_SIZE).
    pub h_active: i32,
    pub v_active: i32,
    /// The plane's output rectangle within the slice (RECOUT_*).
    pub recout: Rect,
    /// The surface rectangle the HUBP fetches (PRI_VIEWPORT_*).
    pub viewport: Rect,
    /// U3.19-truncated source over destination.
    pub ratio_h: Fx,
    pub ratio_v: Fx,
    /// The initial filter phases, truncated to 19 fraction bits.
    pub init_h: Fx,
    pub init_v: Fx,
    pub h_taps: u32,
    pub v_taps: u32,
}

/// Why DC refuses a placement on this pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A zero-sized source or destination (`resource_build_scaling_params`'
    /// invalid input).
    Invalid,
    /// The plane shows nothing on this pipe (recout zero).
    Empty,
    /// `dpp3_get_optimal_number_of_taps` failed: the line buffer cannot hold
    /// the taps the vertical ratio needs, or the viewport is wider than
    /// `max_downscale_src_width` while downscaling.
    Taps,
}

/// `dc_fixpt_truncate`: keep `frac_bits` of the 32 fraction bits.
fn truncate(arg: Fx, frac_bits: u32) -> Fx {
    let negative = arg.0 < 0;
    let mut v = if negative {
        arg.0.wrapping_neg()
    } else {
        arg.0
    };
    v &= (!0u64 << (32 - frac_bits)) as i64;
    Fx(if negative { v.wrapping_neg() } else { v })
}
/// `ux_dy`: `integer_bits`.`fractional_bits` of a 31.32 value, truncated.
fn ux_dy(value: i64, integer_bits: u32, fractional_bits: u32) -> u32 {
    let mut result: u32 = (1u32 << integer_bits).wrapping_sub(1);
    let mut fractional = (value as u64 & 0xffff_ffff) as u32;
    result &= (value >> 32) as u32;
    result <<= fractional_bits;
    fractional >>= 32 - fractional_bits;
    result | fractional
}
/// `dc_fixpt_u3d19`.
pub fn u3d19(a: Fx) -> u32 {
    ux_dy(a.0, 3, 19)
}
/// `dc_fixpt_u0d19`.
pub fn u0d19(a: Fx) -> u32 {
    ux_dy(a.0, 0, 19)
}
/// `IDENTITY_RATIO` of `dcn30_dpp.c`: exactly 1.0 at U3.19.
pub fn identity(ratio: Fx) -> bool {
    u3d19(ratio) == 1 << 19
}

/// `intersect_rec`.
fn intersect(r0: Rect, r1: Rect) -> Rect {
    let r0_x_end = r0.x + r0.width;
    let r1_x_end = r1.x + r1.width;
    let r0_y_end = r0.y + r0.height;
    let r1_y_end = r1.y + r1.height;
    let x = r0.x.max(r1.x);
    let width = if r0_x_end > r1_x_end {
        r1_x_end - x
    } else {
        r0_x_end - x
    };
    let y = r0.y.max(r1.y);
    let height = if r0_y_end > r1_y_end {
        r1_y_end - y
    } else {
        r0_y_end - y
    };
    if width < 0 || height < 0 {
        Rect::default()
    } else {
        Rect::new(x, y, width, height)
    }
}
/// `shift_rec`.
fn shift(r: Rect, x: i32, y: i32) -> Rect {
    Rect::new(r.x + x, r.y + y, r.width, r.height)
}

/// `resource_get_odm_slice_src_rect` for slice `index` of `count` on an RGB
/// stream (no two-pixel alignment, no left-edge extra pixels): equal
/// widths, the last slice taking the remainder.
pub fn odm_slice(h_active: i32, v_active: i32, (index, count): (i32, i32)) -> Rect {
    let width = h_active / count;
    let last = index == count - 1;
    Rect::new(
        width * index,
        0,
        if last {
            h_active - width * (count - 1)
        } else {
            width
        },
        v_active,
    )
}

/// `dscl2_calc_lb_num_partitions` for LB_MEMORY_CONFIG_0 without alpha:
/// how many lines of `min(viewport, recout)` pixels the line buffer holds.
pub fn lb_partitions(viewport_width: i32, recout_width: i32) -> i32 {
    let line = viewport_width.min(recout_width).max(1);
    let words = (line + 5) / 6;
    (LB_MEMORY_CONFIG_0_WORDS / words).min(MAX_LB_PARTITIONS)
}

/// `dpp3_get_optimal_number_of_taps` with amdgpu_dm's zeroed scaling
/// quality (every tap count chosen here). DCN30 sets `use_max_lb`, so the
/// line buffer is LB_MEMORY_CONFIG_0 for RGB. False is DC's refusal; the
/// taps are left as Linux leaves them then.
fn optimal_taps(d: &mut ScalerData) -> bool {
    let ceil_h = d.ratio_h.ceil();
    let ceil_v = d.ratio_v.ceil();
    d.h_taps = if ceil_h > 1 {
        (2 * ceil_h).min(8) as u32
    } else {
        4
    };
    d.v_taps = if ceil_v > 1 {
        d.ratio_v.mul_int(2).ceil().min(8) as u32
    } else {
        4
    };
    if d.viewport.width > d.h_active && d.viewport.width > MAX_DOWNSCALE_SRC_WIDTH {
        return false;
    }
    let min_taps = ceil_v;
    let parts = lb_partitions(d.viewport.width, d.recout.width);
    let max_taps = if ceil_v > 2 {
        parts - (ceil_v - 2)
    } else {
        parts
    };
    if max_taps < min_taps {
        return false;
    }
    if d.v_taps as i32 > max_taps {
        d.v_taps = max_taps as u32;
    }
    if identity(d.ratio_h) {
        d.h_taps = 1;
    }
    if identity(d.ratio_v) {
        d.v_taps = 1;
    }
    true
}

/// `calculate_init_and_vp` scanning in the display's direction: the first
/// filter phase and the source span (offset, size) a recout of
/// `recout_size` pixels, `offset` pixels into the plane's destination,
/// reads.
fn init_and_vp(
    offset: i32,
    recout_size: i32,
    src_size: i32,
    taps: u32,
    ratio: Fx,
) -> (Fx, i32, i32) {
    let mut temp = ratio.mul_int(offset);
    let mut vp_offset = temp.floor();
    temp.0 &= 0xffff_ffff;
    let mut init = truncate(
        ratio
            .add(Fx::from_int(taps as i32 + 1))
            .div_int(2)
            .add(temp),
        19,
    );
    // Scale the viewport back so the first filter tap has its full
    // neighbourhood where the source allows.
    let mut int_part = init.floor();
    if int_part < taps as i32 {
        int_part = (taps as i32 - int_part).min(vp_offset);
        vp_offset -= int_part;
        init = init.add(Fx::from_int(int_part));
    }
    let temp = init.add(ratio.mul_int(recout_size - 1));
    let mut vp_size = temp.floor();
    if vp_size + vp_offset > src_size {
        vp_size = src_size - vp_offset;
    }
    (init, vp_offset, vp_size)
}

/// `calculate_inits_and_viewports` for an unrotated, unmirrored plane.
fn inits_and_viewport(d: &mut ScalerData, slice: Rect, src: Rect, dst: Rect) {
    let clip_in_active = shift(d.recout, slice.x, slice.y);
    let overlap = intersect(clip_in_active, dst);
    let clip_in_dst = if overlap.width > 0 && overlap.height > 0 {
        shift(overlap, -dst.x, -dst.y)
    } else {
        Rect::default()
    };
    let (init_h, x, width) = init_and_vp(
        clip_in_dst.x,
        d.recout.width,
        src.width,
        d.h_taps,
        d.ratio_h,
    );
    let (init_v, y, height) = init_and_vp(
        clip_in_dst.y,
        d.recout.height,
        src.height,
        d.v_taps,
        d.ratio_v,
    );
    d.init_h = init_h;
    d.init_v = init_v;
    d.viewport = Rect::new(x + src.x, y + src.y, width, height);
}

/// `resource_build_scaling_params` for slice `odm` (index, count) of an
/// `h_active` x `v_active` stream showing the `src` rectangle of a surface
/// in the `dst` rectangle of the CRTC (which may reach past it).
pub fn build(
    h_active: i32,
    v_active: i32,
    odm: (i32, i32),
    src: Rect,
    dst: Rect,
) -> Result<ScalerData, Error> {
    if src.width <= 0 || src.height <= 0 || dst.width <= 0 || dst.height <= 0 {
        return Err(Error::Invalid);
    }
    if odm.1 < 1 || odm.0 < 0 || odm.0 >= odm.1 || h_active <= 0 || v_active <= 0 {
        return Err(Error::Invalid);
    }
    let slice = odm_slice(h_active, v_active, odm);
    // calculate_recout: the stream maps its source 1:1 onto the timing, so
    // the plane clip in timing-active space is the CRTC rectangle; clip it
    // to the stream, then to this slice, relative to the slice.
    let stream = Rect::new(0, 0, h_active, v_active);
    let clip = intersect(dst, stream);
    let overlap = intersect(clip, slice);
    let recout = if overlap.height > 0 && overlap.width > 0 {
        shift(overlap, -slice.x, -slice.y)
    } else {
        Rect::default()
    };
    // calculate_scaling_ratios: the stream ratio is 1, so only the plane's
    // src/dst remains, truncated to U3.19.
    let ratio_h = truncate(Fx::from_fraction(src.width.into(), dst.width.into()), 19);
    let ratio_v = truncate(Fx::from_fraction(src.height.into(), dst.height.into()), 19);
    let mut d = ScalerData {
        h_active: slice.width,
        v_active: slice.height,
        recout,
        viewport: Rect::new(0, 0, 100, 100),
        ratio_h,
        ratio_v,
        init_h: Fx::ZERO,
        init_v: Fx::ZERO,
        h_taps: 0,
        v_taps: 0,
    };
    // Taps for a dummy 100x100 viewport, the viewport from them, then the
    // taps for the real viewport (a 24 bpp line buffer retry changes
    // nothing on DCN3.0: dscl2_calc_lb_num_partitions ignores the depth).
    optimal_taps(&mut d);
    let first = (d.h_taps, d.v_taps);
    inits_and_viewport(&mut d, slice, src, dst);
    let ok = optimal_taps(&mut d);
    if ok && (d.h_taps, d.v_taps) != first {
        inits_and_viewport(&mut d, slice, src, dst);
    }
    d.viewport.width = d.viewport.width.max(MIN_VIEWPORT_SIZE);
    d.viewport.height = d.viewport.height.max(MIN_VIEWPORT_SIZE);
    if !ok {
        return Err(Error::Taps);
    }
    if d.recout.width == 0 || d.recout.height == 0 {
        return Err(Error::Empty);
    }
    Ok(d)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn30_scl_tests.rs"]
mod tests;
