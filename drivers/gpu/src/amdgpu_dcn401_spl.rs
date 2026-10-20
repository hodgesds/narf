//! DCN 4.0.1 scaler parameters: a port of Linux's SPL (`dc/sspl/dc_spl.c`,
//! `dc_spl_scl_filters.c`, `dc_spl_scl_easf_filters.c` and
//! `spl_fixpt31_32`) for the planes the native display path scans out, as
//! `resource_build_scaling_params` runs it on DCN401 after
//! `translate_SPL_in_params_from_pipe_ctx`.
//!
//! The fixed inputs are DC's DCN401 configuration and amdgpu_dm's plane
//! state: `use_spl` and `prefer_easf` set, no forced EASF, sharpness off
//! (`force_sharpness` is `SHARPNESS_HW_OFF`, so iSHARP is never enabled),
//! `max_downscale_src_width` 7680, no `always_scale`, the DCN4.x linear-light
//! preference left to the format (`LLS_PREF_DONT_CARE`), no HDR
//! (`dm_helpers_is_hdr_on` is false), no 3D view, no MPC combine (one MPC
//! slice), no visual confirm, no OPP recout adjustment, cositing none and
//! zeroed scaling quality (amdgpu_dm_plane_fill_dc_scaling_info), and only
//! packed RGB formats (never subsampled, never video). The stream maps its
//! source onto the whole timing (no RMX scaling or underscan): stream src =
//! dst = output = the addressable timing.
//!
//! Everything is Linux's integer arithmetic on `Fixed31_32`; nothing here
//! touches hardware. `drivers/gpu/tests/dcn401_spl/check.sh` compares the
//! register words programmed from these values with Linux SPL compiled on
//! the host.
use crate::amdgpu_dcn401_spl_filters as filters;
use crate::amdgpu_dcn_color::Fixed31_32 as Fx;

/// `struct spl_rect`.
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

/// `enum spl_rotation_angle` (DRM's rotation, as amdgpu_dm passes it).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Rotation {
    #[default]
    R0 = 0,
    R90 = 1,
    R180 = 2,
    R270 = 3,
}

/// What `translate_SPL_in_params_from_pipe_ctx` hands SPL for one pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input {
    /// The plane's source rectangle in its surface (DRM SRC_*, integer part).
    pub src: Rect,
    /// The plane's destination in stream space (DRM CRTC_*; may lie partly
    /// off the stream).
    pub dst: Rect,
    /// amdgpu_dm's clip rectangle: the destination (DRM does not clip it).
    pub clip: Rect,
    /// The addressable timing: stream source, destination and output size.
    pub stream_width: i32,
    pub stream_height: i32,
    /// This pipe's ODM slice in timing active (`resource_get_odm_slice_src_rect`);
    /// the whole timing without ODM. Its size is the pipe's h/v active.
    pub odm_slice: Rect,
    pub rotation: Rotation,
    pub horizontal_mirror: bool,
    /// `lb_params.alpha_en`: the plane blends per-pixel alpha.
    pub alpha: bool,
}

/// `enum scl_mode`.
pub const SCL_MODE_SCALING_444_BYPASS: u32 = 0;
pub const SCL_MODE_SCALING_444_RGB_ENABLE: u32 = 1;

/// The EASF fields of `struct dscl_prog_data`, as `spl_set_easf_data` fills
/// them (zero where it leaves them alone).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Easf {
    pub matrix_mode: u32,
    pub ltonl_en: u32,
    pub matrix_c: [u32; 4],
    pub v: EasfDirection,
    pub h: EasfDirection,
}

/// One direction's EASF fields. `ringest_3tap` (dntilt_uptilt, uptilt_max,
/// dntilt_slope, uptilt1_slope, uptilt2_slope, uptilt2_offset) exists only
/// vertically.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EasfDirection {
    pub en: u32,
    pub ring: u32,
    pub sharp_factor: u32,
    pub bf1_en: u32,
    pub bf2_mode: u32,
    pub bf3_mode: u32,
    pub bf2_flat1_gain: u32,
    pub bf2_flat2_gain: u32,
    pub bf2_roc_gain: u32,
    pub ringest_3tap: [u32; 6],
    pub ringest_eventap_reduceg: [u32; 2],
    pub ringest_eventap_gain: [u32; 2],
    pub bf_max_min: [u32; 4],
    /// BF1 PWL segments 0-7 (in, base, slope); segment 7 has no slope.
    pub bf1_pwl: [[u32; 3]; 8],
    /// BF3 PWL segments 0-5 (in, base, slope); segment 5 has no slope.
    pub bf3_pwl: [[u32; 3]; 6],
}

/// `struct init` of `dscl_prog_data`: (frac, int) pairs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Init {
    pub h: (u32, u32),
    pub h_c: (u32, u32),
    pub v: (u32, u32),
    pub v_c: (u32, u32),
    pub v_bot: (u32, u32),
    pub v_bot_c: (u32, u32),
}

/// `struct dscl_prog_data` for an RGB plane (iSHARP off, UPSP bypassed),
/// and whether `spl_calculate_scaler_params` succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scaler {
    pub recout: Rect,
    pub mpc_size: (i32, i32),
    pub dscl_mode: u32,
    /// h, v, h_c, v_c scale ratios (U3.19 << 5).
    pub ratios: [u32; 4],
    pub init: Init,
    /// v, h, v_c, h_c taps less one.
    pub taps: [u32; 4],
    pub viewport: Rect,
    pub viewport_c: Rect,
    pub filter_h: Option<&'static [u16]>,
    pub filter_v: Option<&'static [u16]>,
    pub filter_h_c: Option<&'static [u16]>,
    pub filter_v_c: Option<&'static [u16]>,
    pub easf: Easf,
    /// spl_calculate_scaler_params' result: false when the line buffer
    /// cannot hold the taps the ratio needs, or the viewport is wider than
    /// `max_downscale_src_width` (resource_build_scaling_params fails).
    pub ok: bool,
}

const MIN_VIEWPORT_SIZE: i32 = 12;
const MAX_DOWNSCALE_SRC_WIDTH: i32 = 7680;

fn frac(n: i64, d: i64) -> Fx {
    Fx::from_fraction(n, d)
}
/// spl_fixpt_truncate.
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
/// spl_ux_dy.
fn ux_dy(value: i64, integer_bits: u32, fractional_bits: u32) -> u32 {
    let mut result: u32 = (1u32 << integer_bits).wrapping_sub(1);
    let mut fractional = (value as u64 & 0xffff_ffff) as u32;
    result &= (value >> 32) as u32;
    result <<= fractional_bits;
    fractional >>= 32 - fractional_bits;
    result | fractional
}
fn u3d19(a: Fx) -> u32 {
    ux_dy(a.0, 3, 19)
}
fn u0d19(a: Fx) -> u32 {
    ux_dy(a.0, 0, 19)
}
fn add_int(a: Fx, n: i32) -> Fx {
    a.add(Fx::from_int(n))
}
/// IDENTITY_RATIO: exactly 1.0 at U3.19.
fn identity(ratio: Fx) -> bool {
    u3d19(ratio) == 1 << 19
}

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
        return Rect::default();
    }
    Rect::new(x, y, width, height)
}
fn shift(r: Rect, x: i32, y: i32) -> Rect {
    Rect::new(r.x + x, r.y + y, r.width, r.height)
}

#[derive(Clone, Copy, Default)]
struct Ratios {
    horz: Fx,
    vert: Fx,
    horz_c: Fx,
    vert_c: Fx,
}
#[derive(Clone, Copy, Default)]
struct Taps {
    v: u32,
    h: u32,
    v_c: u32,
    h_c: u32,
}
#[derive(Clone, Copy, Default)]
struct Data {
    h_active: i32,
    v_active: i32,
    taps: Taps,
    viewport: Rect,
    viewport_c: Rect,
    recout: Rect,
    ratios: Ratios,
    recip: Ratios,
    inits: [Fx; 4], // h, h_c, v, v_c
}

impl Input {
    /// calculate_plane_rec_in_timing_active with stream src = dst.
    fn in_timing_active(&self, r: Rect) -> Rect {
        let (sw, sh) = (i64::from(self.stream_width), i64::from(self.stream_height));
        let x = frac(i64::from(r.x) * sw, sw).round();
        let width = frac(i64::from(r.x + r.width) * sw, sw).round() - x;
        let y = frac(i64::from(r.y) * sh, sh).round();
        let height = frac(i64::from(r.y + r.height) * sh, sh).round() - y;
        Rect::new(x, y, width, height)
    }
    fn stream_rect(&self) -> Rect {
        Rect::new(0, 0, self.stream_width, self.stream_height)
    }
    /// spl_calculate_recout with one MPC slice.
    fn recout(&self) -> Rect {
        let plane_clip = intersect(self.in_timing_active(self.clip), self.stream_rect());
        // calculate_mpc_slice_in_timing_active for a single slice.
        let mpc = plane_clip;
        let odm = self.odm_slice;
        let overlap = intersect(mpc, odm);
        if overlap.height > 0 && overlap.width > 0 {
            shift(overlap, -odm.x, -odm.y)
        } else {
            Rect::default()
        }
    }
    fn orthogonal(&self) -> bool {
        matches!(self.rotation, Rotation::R90 | Rotation::R270)
    }
    /// spl_calculate_scaling_ratios (stream scaling is unity).
    fn ratios(&self, d: &mut Data) {
        let mut surf = self.src;
        if self.orthogonal() {
            core::mem::swap(&mut surf.width, &mut surf.height);
        }
        let mut horz = frac(i64::from(surf.width), i64::from(self.dst.width));
        let mut vert = frac(i64::from(surf.height), i64::from(self.dst.height));
        let (sw, sh) = (i64::from(self.stream_width), i64::from(self.stream_height));
        vert = Fx(vert.0.wrapping_mul(sh) / sh);
        horz = Fx(horz.0.wrapping_mul(sw) / sw);
        let horz = truncate(horz, 19);
        let vert = truncate(vert, 19);
        d.ratios = Ratios {
            horz,
            vert,
            horz_c: horz,
            vert_c: vert,
        };
        d.recip = Ratios {
            horz: horz.recip(),
            vert: vert.recip(),
            horz_c: horz.recip(),
            vert_c: vert.recip(),
        };
    }
}

/// spl_calculate_viewport_size.
fn viewport_size(input: &Input, d: &mut Data) {
    d.viewport.width = d.ratios.horz.mul_int(d.recout.width).ceil();
    d.viewport.height = d.ratios.vert.mul_int(d.recout.height).ceil();
    d.viewport_c.width = d.ratios.horz_c.mul_int(d.recout.width).ceil();
    d.viewport_c.height = d.ratios.vert_c.mul_int(d.recout.height).ceil();
    if input.orthogonal() {
        core::mem::swap(&mut d.viewport.width, &mut d.viewport.height);
        core::mem::swap(&mut d.viewport_c.width, &mut d.viewport_c.height);
    }
}

/// dscl401_spl_calc_lb_num_partitions.
fn spl_lb_partitions(alpha: bool, d: &Data, lb_config: u32) -> (i32, i32) {
    let size = |w: i32| match w.min(d.recout.width) {
        0 => 1,
        line => line,
    };
    let (line, line_c) = (size(d.viewport.width), size(d.viewport_c.width));
    let (y_size, c_size, a_size) = ((line + 5) / 6, (line_c + 5) / 6, (line + 5) / 6);
    let unscaled = d.viewport.width == d.h_active
        && d.viewport.height == d.v_active
        && d.taps.h == 1
        && d.taps.v == 1;
    let (lb, lb_c, lb_a) = match lb_config {
        1 => (970, 970, 970),
        2 => (1290, 1290, 1290),
        3 if unscaled => (
            970 + 1290 + 1170 + 1170 + 1170,
            970 + 1290,
            970 + 1290 + 1170,
        ),
        3 => (970 + 1290 + 484 * 3, 970 + 1290, 970 + 1290 + 484),
        _ if unscaled => (3430, 3430, 3430),
        _ => (2744, 2744, 2744),
    };
    let mut y = lb / y_size;
    let c = (lb_c / c_size).min(64);
    let a = lb_a / a_size;
    if alpha && a < y {
        y = a;
    }
    (y.min(64), c)
}

/// spl_get_taps_non_adaptive_scaler with zero input taps (RGB: neither
/// direction subsampled).
fn taps_non_adaptive(d: &mut Data) {
    let pick = |r: Fx| {
        if r.ceil() > 1 {
            (2 * r.ceil()).min(8) as u32
        } else {
            4
        }
    };
    d.taps.h = pick(d.ratios.horz);
    d.taps.v = pick(d.ratios.vert);
    d.taps.v_c = pick(d.ratios.vert_c);
    d.taps.h_c = pick(d.ratios.horz_c);
    if identity(d.ratios.horz) {
        d.taps.h = 1;
    }
    if identity(d.ratios.vert) {
        d.taps.v = 1;
    }
    if identity(d.ratios.horz_c) {
        d.taps.h_c = 1;
    }
    if identity(d.ratios.vert_c) {
        d.taps.v_c = 1;
    }
}

/// `enum linear_light_scaling`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lls {
    DontCare,
    Yes,
}

/// spl_get_optimal_number_of_taps: (result, EASF vertical, horizontal).
/// `lls` is SPL's `spl_in->lls_pref`, which enable_easf resolves.
fn optimal_taps(input: &Input, d: &mut Data, lls: &mut Lls) -> (bool, bool, bool) {
    if d.viewport.width > d.h_active && d.viewport.width > MAX_DOWNSCALE_SRC_WIDTH {
        taps_non_adaptive(d);
        return (false, false, false);
    }
    // enable_easf: no EASF beyond 2:1 downscaling; the RGB format decides
    // linear-light scaling, which prefers EASF.
    // (With prefer_easf set the linear-light preference cannot skip it.)
    let skip_easf = d.ratios.vert.ceil() > 2 || d.ratios.horz.ceil() > 2;
    if *lls == Lls::DontCare {
        *lls = Lls::Yes;
    }
    if skip_easf {
        taps_non_adaptive(d);
    } else {
        d.taps = Taps {
            v: 6,
            h: 6,
            v_c: 6,
            h_c: 6,
        };
    }
    let min_taps_y = d.ratios.vert.ceil();
    let min_taps_c = d.ratios.vert_c.ceil();
    let (num_part_y, num_part_c) = spl_lb_partitions(input.alpha, d, 0);
    let max_taps = |ratio: Fx, parts: i32| -> u32 {
        if ratio.ceil() > 2 {
            if ratio.ceil() - 2 > parts {
                0
            } else {
                (parts - (ratio.ceil() - 2)) as u32
            }
        } else {
            parts as u32
        }
    };
    let max_taps_y = max_taps(d.ratios.vert, num_part_y);
    let max_taps_c = max_taps(d.ratios.vert_c, num_part_c);
    if max_taps_y < min_taps_y as u32 || max_taps_c < min_taps_c as u32 {
        return (false, false, false);
    }
    d.taps.v = d.taps.v.min(max_taps_y);
    d.taps.v_c = d.taps.v_c.min(max_taps_c);
    let (mut easf_v, mut easf_h) = (false, false);
    if !skip_easf {
        for t in [
            &mut d.taps.v,
            &mut d.taps.v_c,
            &mut d.taps.h,
            &mut d.taps.h_c,
        ] {
            if *t == 5 {
                *t = 4;
            }
        }
        // RGB.
        if d.taps.h <= 3 {
        } else if d.taps.v < 3 {
            easf_h = true;
        } else {
            easf_v = true;
            easf_h = true;
        }
    }
    // iSHARP is off: unity directions take one tap.
    if identity(d.ratios.horz) && identity(d.ratios.vert) {
        d.taps.h = 1;
        d.taps.v = 1;
        if identity(d.ratios.horz_c) {
            d.taps.h_c = 1;
        }
        if identity(d.ratios.vert_c) {
            d.taps.v_c = 1;
        }
        easf_v = false;
        easf_h = false;
    } else {
        if !easf_h && identity(d.ratios.horz) {
            d.taps.h = 1;
        }
        if !easf_v && identity(d.ratios.vert) {
            d.taps.v = 1;
        }
        if !easf_h && identity(d.ratios.horz_c) {
            d.taps.h_c = 1;
        }
        if !easf_v && identity(d.ratios.vert_c) {
            d.taps.v_c = 1;
        }
    }
    (true, easf_v, easf_h)
}

/// spl_calculate_init_and_vp: (init, vp_offset, vp_size).
fn init_and_vp(
    flip: bool,
    recout_offset: i32,
    recout_size: i32,
    src_size: i32,
    taps: i32,
    ratio: Fx,
    init_adj: Fx,
) -> (Fx, i32, i32) {
    let mut temp = ratio.mul_int(recout_offset);
    let mut vp_offset = temp.floor();
    temp.0 &= 0xffff_ffff;
    let mut init = add_int(ratio, taps + 1).div_int(2).add(temp);
    init = init.add(init_adj);
    init = truncate(init, 19);
    let mut int_part = init.floor();
    if int_part < taps {
        int_part = taps - int_part;
        if int_part > vp_offset {
            int_part = vp_offset;
        }
        vp_offset -= int_part;
        init = add_int(init, int_part);
    }
    let temp = init.add(ratio.mul_int(recout_size - 1));
    let mut vp_size = temp.floor();
    if vp_size + vp_offset > src_size {
        vp_size = src_size - vp_offset;
    }
    if flip {
        vp_offset = src_size - vp_offset - vp_size;
    }
    (init, vp_offset, vp_size)
}

/// spl_calculate_inits_and_viewports (RGB: no chroma subsampling or
/// cositing adjustment).
fn inits_and_viewports(input: &Input, d: &mut Data) {
    let mut src = input.src;
    let odm = input.odm_slice;
    let recout_clip = shift(d.recout, odm.x, odm.y);
    let recout_dst = input.in_timing_active(input.dst);
    let overlap = intersect(recout_clip, recout_dst);
    let in_dst = if overlap.width > 0 && overlap.height > 0 {
        shift(overlap, -recout_dst.x, -recout_dst.y)
    } else {
        Rect::default()
    };
    // spl_get_vp_scan_direction.
    let (orthogonal, mut flip_v, mut flip_h) = match input.rotation {
        Rotation::R0 => (false, false, false),
        Rotation::R90 => (true, false, true),
        Rotation::R180 => (false, true, true),
        Rotation::R270 => (true, true, false),
    };
    if input.horizontal_mirror {
        flip_h = !flip_h;
    }
    if orthogonal {
        core::mem::swap(&mut src.width, &mut src.height);
        core::mem::swap(&mut flip_v, &mut flip_h);
    }
    let zero = Fx::ZERO;
    let (h, x, w) = init_and_vp(
        flip_h,
        in_dst.x,
        d.recout.width,
        src.width,
        d.taps.h as i32,
        d.ratios.horz,
        zero,
    );
    let (h_c, x_c, w_c) = init_and_vp(
        flip_h,
        in_dst.x,
        d.recout.width,
        src.width,
        d.taps.h_c as i32,
        d.ratios.horz_c,
        zero,
    );
    let (v, y, ht) = init_and_vp(
        flip_v,
        in_dst.y,
        d.recout.height,
        src.height,
        d.taps.v as i32,
        d.ratios.vert,
        zero,
    );
    let (v_c, y_c, ht_c) = init_and_vp(
        flip_v,
        in_dst.y,
        d.recout.height,
        src.height,
        d.taps.v_c as i32,
        d.ratios.vert_c,
        zero,
    );
    d.inits = [h, h_c, v, v_c];
    d.viewport = Rect::new(x, y, w, ht);
    d.viewport_c = Rect::new(x_c, y_c, w_c, ht_c);
    if orthogonal {
        let s = |r: Rect| Rect::new(r.y, r.x, r.height, r.width);
        d.viewport = s(d.viewport);
        d.viewport_c = s(d.viewport_c);
    }
    d.viewport.x += input.src.x;
    d.viewport.y += input.src.y;
    d.viewport_c.x += input.src.x;
    d.viewport_c.y += input.src.y;
}

/// spl_dscl_get_filter_coeffs_64p.
fn filter(taps: u32, ratio: Fx) -> Option<&'static [u16]> {
    use filters::*;
    let band = |up, a, b, c| {
        if ratio.0 < Fx::ONE.0 {
            up
        } else if ratio.0 < frac(4, 3).0 {
            a
        } else if ratio.0 < frac(5, 3).0 {
            b
        } else {
            c
        }
    };
    Some(match taps {
        8 => band(
            &FILTER_8TAP_64P_UPSCALE[..],
            &FILTER_8TAP_64P_116[..],
            &FILTER_8TAP_64P_149[..],
            &FILTER_8TAP_64P_183[..],
        ),
        7 => band(
            &FILTER_7TAP_64P_UPSCALE[..],
            &FILTER_7TAP_64P_116[..],
            &FILTER_7TAP_64P_149[..],
            &FILTER_7TAP_64P_183[..],
        ),
        6 => band(
            &FILTER_6TAP_64P_UPSCALE[..],
            &FILTER_6TAP_64P_116[..],
            &FILTER_6TAP_64P_149[..],
            &FILTER_6TAP_64P_183[..],
        ),
        5 => band(
            &FILTER_5TAP_64P_UPSCALE[..],
            &FILTER_5TAP_64P_116[..],
            &FILTER_5TAP_64P_149[..],
            &FILTER_5TAP_64P_183[..],
        ),
        4 => band(
            &FILTER_4TAP_64P_UPSCALE[..],
            &FILTER_4TAP_64P_116[..],
            &FILTER_4TAP_64P_149[..],
            &FILTER_4TAP_64P_183[..],
        ),
        3 => band(
            &FILTER_3TAP_64P_UPSCALE[..],
            &FILTER_3TAP_64P_116[..],
            &FILTER_3TAP_64P_149[..],
            &FILTER_3TAP_64P_183[..],
        ),
        2 => &FILTER_2TAP_64P[..],
        _ => return None,
    })
}

/// spl_dscl_get_easf_filter_coeffs_64p: by output/input ratio in tenths.
fn easf_filter(taps: u32, ratio: Fx) -> Option<&'static [u16]> {
    use filters::*;
    let tables: [&'static [u16]; 8] = match taps {
        6 => [
            &EASF_FILTER_6TAP_64P_RATIO_0_30_S1_12,
            &EASF_FILTER_6TAP_64P_RATIO_0_40_S1_12,
            &EASF_FILTER_6TAP_64P_RATIO_0_50_S1_12,
            &EASF_FILTER_6TAP_64P_RATIO_0_60_S1_12,
            &EASF_FILTER_6TAP_64P_RATIO_0_70_S1_12,
            &EASF_FILTER_6TAP_64P_RATIO_0_80_S1_12,
            &EASF_FILTER_6TAP_64P_RATIO_0_90_S1_12,
            &EASF_FILTER_6TAP_64P_RATIO_1_00_S1_12,
        ],
        4 => [
            &EASF_FILTER_4TAP_64P_RATIO_0_30_S1_12,
            &EASF_FILTER_4TAP_64P_RATIO_0_40_S1_12,
            &EASF_FILTER_4TAP_64P_RATIO_0_50_S1_12,
            &EASF_FILTER_4TAP_64P_RATIO_0_60_S1_12,
            &EASF_FILTER_4TAP_64P_RATIO_0_70_S1_12,
            &EASF_FILTER_4TAP_64P_RATIO_0_80_S1_12,
            &EASF_FILTER_4TAP_64P_RATIO_0_90_S1_12,
            &EASF_FILTER_4TAP_64P_RATIO_1_00_S1_12,
        ],
        3 => [
            &EASF_FILTER_3TAP_64P_RATIO_0_30_S1_12,
            &EASF_FILTER_3TAP_64P_RATIO_0_40_S1_12,
            &EASF_FILTER_3TAP_64P_RATIO_0_50_S1_12,
            &EASF_FILTER_3TAP_64P_RATIO_0_60_S1_12,
            &EASF_FILTER_3TAP_64P_RATIO_0_70_S1_12,
            &EASF_FILTER_3TAP_64P_RATIO_0_80_S1_12,
            &EASF_FILTER_3TAP_64P_RATIO_0_90_S1_12,
            &EASF_FILTER_3TAP_64P_RATIO_1_00_S1_12,
        ],
        _ => return None,
    };
    let band = (3..10)
        .position(|tenths| ratio.0 < frac(tenths, 10).0)
        .unwrap_or(7);
    Some(tables[band])
}

/// `struct scale_ratio_to_reg_value_lookup` tables: the value of the first
/// entry whose ratio exceeds the input, the {-1, -1} terminator's otherwise.
type Lookup = [u32; 9];
fn lookup(ratio: Fx, table: &Lookup) -> u32 {
    const BOUNDS: [(i64, i64); 8] = [
        (3, 10),
        (4, 10),
        (5, 10),
        (6, 10),
        (7, 10),
        (8, 10),
        (9, 10),
        (1, 1),
    ];
    BOUNDS
        .iter()
        .position(|&(n, d)| ratio.0 < frac(n, d).0)
        .map_or(table[8], |i| table[i])
}
const BF3_MODE: Lookup = [0, 0, 0, 0, 0, 0, 0, 0, 2];
const REDUCER_GAIN6: Lookup = [0x4100; 9];
const REDUCER_GAIN4: Lookup = [0x4000; 9];
const GAIN_RING6_6TAP: Lookup = [
    0, 0x251F, 0x291F, 0xA51F, 0xA51F, 0xAA66, 0xA51F, 0xA640, 0xA640,
];
const GAIN_RING4_6TAP: Lookup = [
    0, 0x9600, 0xA460, 0xA8E0, 0xAC00, 0xAD20, 0xAFC0, 0xB058, 0xB058,
];
const GAIN_RING4_4TAP: Lookup = [0, 0, 0, 0x9900, 0xA100, 0xA8C0, 0xAB20, 0xAC00, 0xAC00];
const TAP3_DNTILT_UPTILT_OFFSET: Lookup = [0, 0, 0, 0, 0, 0x4100, 0x9F00, 0xA4C0, 0xA8D8];
const TAP3_UPTILT_MAXVAL: Lookup = [0, 0, 0, 0, 0, 0x4000, 0x24FE, 0x2D64, 0x3ADB];
const TAP3_DNTILT_SLOPE: Lookup = [
    0x3800, 0x3800, 0x3800, 0x3800, 0x3800, 0x3886, 0x3940, 0x3A4E, 0x3B66,
];
const TAP3_UPTILT1_SLOPE: Lookup = [
    0x3800, 0x3800, 0x3800, 0x3800, 0x3800, 0x36F4, 0x359C, 0x3360, 0x2F20,
];
const TAP3_UPTILT2_SLOPE: Lookup = [0, 0, 0, 0, 0, 0, 0x359C, 0x31F0, 0x1F00];
const TAP3_UPTILT2_OFFSET: Lookup = [0, 0, 0, 0, 0, 0, 0x9F00, 0xA400, 0x9E00];

fn by_taps(taps: u32, ratio: Fx, four: &Lookup, six: &Lookup) -> u32 {
    match taps {
        4 => lookup(ratio, four),
        6 => lookup(ratio, six),
        _ => 0,
    }
}
fn three_tap(taps: u32, ratio: Fx, table: &Lookup) -> u32 {
    if taps == 3 {
        lookup(ratio, table)
    } else {
        0
    }
}

/// The linear-light BF1/BF3 PWLs and BF2 gains spl_set_easf_data uses for
/// both directions (`lls_pref == LLS_PREF_YES`).
const BF2_GAINS_L: [u32; 3] = [4, 8, 4];
const BF1_PWL_L: [[u32; 3]; 8] = [
    [0x600, 0, 3],
    [0x7EC, 12, 326],
    [0, 63, 0],
    [16, 63, 0x7C8],
    [32, 56, 0x7D0],
    [48, 50, 0x710],
    [64, 20, 0x760],
    [80, 0, 0],
];
const BF3_PWL_L: [[u32; 3]; 6] = [
    [0x000, 63, 0x12C5],
    [0x0B37, 62, 0x13B8],
    [0x0BB7, 20, 0x1356],
    [0x0BF7, 0, 0x136B],
    [0x0C37, 0x4E, 0x1200],
    [0x0CF7, 0x41, 0],
];

/// spl_set_easf_data for an RGB plane at SDR_L (lls_pref YES, no HDR).
fn easf_data(d: &Data, easf_v: bool, easf_h: bool) -> Easf {
    let direction = |taps: u32, recip: Fx, vertical: bool| {
        let mut e = EasfDirection {
            en: 1,
            ring: 0,
            sharp_factor: 1,
            bf1_en: 1,
            bf2_mode: 0xF,
            bf3_mode: lookup(recip, &BF3_MODE),
            ringest_eventap_reduceg: [
                by_taps(taps, recip, &REDUCER_GAIN4, &REDUCER_GAIN4),
                by_taps(taps, recip, &REDUCER_GAIN6, &REDUCER_GAIN6),
            ],
            ringest_eventap_gain: [
                by_taps(taps, recip, &GAIN_RING4_4TAP, &GAIN_RING4_6TAP),
                by_taps(taps, recip, &[0; 9], &GAIN_RING6_6TAP),
            ],
            bf_max_min: [63, 63, 0, 0],
            bf1_pwl: BF1_PWL_L,
            bf3_pwl: BF3_PWL_L,
            ..EasfDirection::default()
        };
        [e.bf2_flat1_gain, e.bf2_flat2_gain, e.bf2_roc_gain] = BF2_GAINS_L;
        if vertical {
            e.ringest_3tap = [
                three_tap(taps, recip, &TAP3_DNTILT_UPTILT_OFFSET),
                three_tap(taps, recip, &TAP3_UPTILT_MAXVAL),
                three_tap(taps, recip, &TAP3_DNTILT_SLOPE),
                three_tap(taps, recip, &TAP3_UPTILT1_SLOPE),
                three_tap(taps, recip, &TAP3_UPTILT2_SLOPE),
                three_tap(taps, recip, &TAP3_UPTILT2_OFFSET),
            ];
        }
        e
    };
    Easf {
        matrix_mode: 0,
        // Linear input; SDR_L's rec709 luma coefficients.
        ltonl_en: 1,
        matrix_c: [0x4EF7, 0x55DC, 0x48BB, 0],
        v: if easf_v {
            direction(d.taps.v, d.recip.vert, true)
        } else {
            EasfDirection::default()
        },
        h: if easf_h {
            direction(d.taps.h, d.recip.horz, false)
        } else {
            EasfDirection::default()
        },
    }
}

/// spl_calculate_scaler_params.
pub fn calculate(input: &Input) -> Scaler {
    let mut d = Data {
        h_active: input.odm_slice.width,
        v_active: input.odm_slice.height,
        ..Data::default()
    };
    let mut lls = Lls::DontCare;
    // spl_calculate_number_of_taps.
    d.recout = input.recout();
    input.ratios(&mut d);
    viewport_size(input, &mut d);
    let (ok, easf_v, easf_h) = optimal_taps(input, &mut d, &mut lls);
    if ok {
        inits_and_viewports(input, &mut d);
    }
    // spl_clamp_viewport.
    d.viewport.height = d.viewport.height.max(MIN_VIEWPORT_SIZE);
    d.viewport.width = d.viewport.width.max(MIN_VIEWPORT_SIZE);
    // spl_set_dscl_prog_data.
    let one = Fx::ONE.0;
    let r = d.ratios;
    let dscl_mode = if r.horz.0 == one && r.vert.0 == one && r.horz_c.0 == one && r.vert_c.0 == one
    {
        SCL_MODE_SCALING_444_BYPASS
    } else {
        SCL_MODE_SCALING_444_RGB_ENABLE
    };
    let pair = |f: Fx| (u0d19(f) << 5, f.floor() as u32);
    let [h, h_c, v, v_c] = d.inits;
    let init = Init {
        h: pair(h),
        h_c: pair(h_c),
        v: pair(v),
        v_c: pair(v_c),
        v_bot: pair(v.add(r.vert)),
        v_bot_c: pair(v_c.add(r.vert_c)),
    };
    // spl_set_filters_data: EASF filters by output/input ratio.
    let (filter_h, filter_h_c) = if easf_h {
        (
            easf_filter(d.taps.h, d.recip.horz),
            easf_filter(d.taps.h_c, d.recip.horz_c),
        )
    } else {
        (filter(d.taps.h, r.horz), filter(d.taps.h_c, r.horz_c))
    };
    let (filter_v, filter_v_c) = if easf_v {
        (
            easf_filter(d.taps.v, d.recip.vert),
            easf_filter(d.taps.v_c, d.recip.vert_c),
        )
    } else {
        (filter(d.taps.v, r.vert), filter(d.taps.v_c, r.vert_c))
    };
    let easf = if ok {
        easf_data(&d, easf_v, easf_h)
    } else {
        Easf::default()
    };
    Scaler {
        recout: d.recout,
        mpc_size: (d.h_active, d.v_active),
        dscl_mode,
        ratios: [
            u3d19(r.horz) << 5,
            u3d19(r.vert) << 5,
            u3d19(r.horz_c) << 5,
            u3d19(r.vert_c) << 5,
        ],
        init,
        taps: [
            d.taps.v.wrapping_sub(1),
            d.taps.h.wrapping_sub(1),
            d.taps.v_c.wrapping_sub(1),
            d.taps.h_c.wrapping_sub(1),
        ],
        viewport: d.viewport,
        viewport_c: d.viewport_c,
        filter_h,
        filter_v,
        filter_h_c,
        filter_v_c,
        easf,
        ok,
    }
}

impl Scaler {
    /// What SPL computes for an unscaled full-frame plane's ODM slice
    /// `x..x + width` of `height` lines, without the 12-pixel minimum
    /// viewport clamp: the scaler bypassed with one tap, the slice's own
    /// recout and viewport.
    pub fn unity(x: i32, width: i32, height: i32) -> Self {
        let r = Rect::new(x, 0, width, height);
        let one = 1 << 19 << 5;
        Self {
            recout: Rect::new(0, 0, width, height),
            mpc_size: (width, height),
            dscl_mode: SCL_MODE_SCALING_444_BYPASS,
            ratios: [one; 4],
            init: Init::default(),
            taps: [0; 4],
            viewport: r,
            viewport_c: r,
            filter_h: None,
            filter_v: None,
            filter_h_c: None,
            filter_v_c: None,
            easf: Easf::default(),
            ok: true,
        }
    }
    /// The taps (v, h, v_c, h_c), as translate_SPL_out_params_to_pipe_ctx
    /// returns them to DC.
    pub fn dc_taps(&self) -> [u32; 4] {
        self.taps.map(|t| t.wrapping_add(1))
    }
    /// dc_fixpt_ceil of DC's vertical ratios (luma, chroma): the U3.19
    /// register ratio back in 31.32.
    fn ceil_vratios(&self) -> (i32, i32) {
        let back = |r: u32| Fx(i64::from(r >> 5) << (32 - 19)).ceil();
        (back(self.ratios[1]), back(self.ratios[3]))
    }
    /// dpp401_dscl_find_lb_memory_config (no `use_max_lb`, RGB) with
    /// dscl401_calc_lb_num_partitions on DC's scaler data.
    pub fn lb_memory_config(&self, alpha: bool) -> u32 {
        let [v_taps, _, v_taps_c, _] = self.dc_taps().map(|t| t as i32);
        let (ceil_v, ceil_v_c) = self.ceil_vratios();
        let valid = |ceil_vratio: i32, parts: i32, vtaps: i32| {
            if ceil_vratio > 2 {
                vtaps <= parts - ceil_vratio + 2
            } else {
                vtaps <= parts
            }
        };
        for config in [1, 2] {
            let (y, c) = self.lb_partitions(alpha, config);
            if valid(ceil_v, y, v_taps) && valid(ceil_v_c, c, v_taps_c) {
                return config;
            }
        }
        0
    }
    /// dscl401_calc_lb_num_partitions (DC's variant: no tap condition).
    fn lb_partitions(&self, alpha: bool, config: u32) -> (i32, i32) {
        let size = |w: i32| {
            let line = w.min(self.recout.width);
            if line == 0 {
                1
            } else {
                line
            }
        };
        let (line, line_c) = (size(self.viewport.width), size(self.viewport_c.width));
        let (y_size, c_size, a_size) = ((line + 5) / 6, (line_c + 5) / 6, (line + 5) / 6);
        let unscaled =
            self.viewport.width == self.mpc_size.0 && self.viewport.height == self.mpc_size.1;
        let (lb, lb_c, lb_a) = match config {
            1 => (970, 970, 970),
            2 => (1290, 1290, 1290),
            _ if unscaled => (3430, 3430, 3430),
            _ => (2744, 2744, 2744),
        };
        let mut y = lb / y_size;
        let c = lb_c / c_size;
        let a = lb_a / a_size;
        if alpha && a < y {
            y = a;
        }
        (y.min(64), c.min(64))
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_spl_tests.rs"]
mod tests;
