//! Display-14 (Meteor Lake) pipe scaler for panel fitting: Linux's window,
//! scaler admission and register image.
//!
//! Sources (Linux b90c984d):
//! - `intel_pfit.c::pch_panel_fitting`: the panel-fitter window for a pipe
//!   source smaller than the panel's fixed mode (`DRM_MODE_SCALE_CENTER`,
//!   `_ASPECT` (the eDP default) and `_FULLSCREEN`); display 9+ leaves the
//!   checks to the unified scaler code;
//! - `skl_scaler.c`: `skl_update_scaler` (source/destination ranges,
//!   display 14's 4096x8192 source maximum), `intel_allocate_scaler` and
//!   `intel_atomic_setup_scaler` for the crtc user (`PS_SCALER_MODE_NORMAL`
//!   on display 10+, `calculate_max_scale`: scaler 0 takes 3.0 both ways,
//!   scaler 1 no vertical downscale), `skl_scaler_calc_phase`,
//!   `skl_pfit_enable`, `skl_scaler_disable`, `skl_scaler_get_filter_select`,
//!   `glk_program_nearest_filter_coefs` and `skl_scaler_1st_prefill_lines` /
//!   `_2nd_prefill_lines`;
//! - `drm_rect.c`: `drm_calc_scale`, `drm_rect_calc_hscale`/`_vscale`;
//! - `intel_display_regs.h`: `SKL_PS_*` and `GLK_PS_COEF_*`
//!   (`intel_display_device.c`: two scalers on every display 11+ pipe).
//!   Wa_14011503117 (the DE fatal-error mask around the enable) is display
//!   13 only.
//!
//! Qualified profile: upscaling only. A downscaled source raises the pipe
//! pixel rate (`ilk_pipe_pixel_rate`) and with it CDCLK and the watermarks,
//! which the display-14 resource model does not carry; it is a typed
//! [`ScalerRefusal::Downscale`]. Plane scaling (a plane-bound scaler) and
//! YCbCr 4:2:0 output are not offered.

use crate::intel_gpu_modeset::Mode;
use crate::intel_gpu_pipes::Pipe;

/// `drm_connector_state::scaling_mode` for a panel (`DRM_MODE_SCALE_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalingMode {
    /// Unscaled, centered.
    Center,
    /// Scaled, aspect ratio kept (`intel_dp_add_properties`' eDP default).
    Aspect,
    /// Scaled to the whole panel.
    Fullscreen,
}

/// `crtc_state->hw.scaling_filter`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    /// `DRM_SCALING_FILTER_DEFAULT`: the hardware's medium filter.
    Default,
    /// `DRM_SCALING_FILTER_NEAREST_NEIGHBOR`: programmed coefficients.
    NearestNeighbor,
}

/// The panel-fitter window (`crtc_state->pch_pfit.dst`) in panel pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Why a pipe scaler cannot fit the source to the panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalerRefusal {
    /// `skl_update_scaler`'s source or destination range.
    OutOfRange,
    /// The pipe source exceeds the scaler destination maximum.
    PipeSourceTooLarge,
    /// `drm_rect_calc_hscale`/`_vscale` out of `calculate_max_scale`.
    Ratio,
    /// Downscaling: unqualified (pipe pixel rate, CDCLK, watermarks).
    Downscale,
}

/// One pipe scaler bound to the pipe (`scaler_state->scalers[id]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipeScaler {
    /// The scaler (`intel_allocate_scaler`'s first free: 0).
    pub id: u32,
    /// `pch_pfit.dst`.
    pub window: Window,
    /// Source/destination in 16.16 (`drm_rect_calc_*scale`).
    pub hscale: u32,
    pub vscale: u32,
    pub filter: Filter,
}

/// `skl_scaler_max_src_size` (display 14).
const MAX_SRC_W: u32 = 4096;
const MAX_SRC_H: u32 = 8192;
/// `skl_scaler_max_dst_size` (display 12+).
const MAX_DST: u32 = 8192;
/// `skl_scaler_min_src_size` (packed formats) / `skl_scaler_min_dst_size`.
const MIN_SIZE: u32 = 8;

/// `pch_panel_fitting` for display 9+: the window the pipe source is
/// fitted into on the panel's `native` timing, `None` for a native source.
pub fn panel_fit(native: &Mode, src_w: u32, src_h: u32, mode: ScalingMode) -> Option<Window> {
    let (hd, vd) = (u32::from(native.h_active), u32::from(native.v_active));
    if hd == src_w && vd == src_h {
        return None;
    }
    let window = match mode {
        ScalingMode::Center => Window {
            x: hd.wrapping_sub(src_w).wrapping_add(1) / 2,
            y: vd.wrapping_sub(src_h).wrapping_add(1) / 2,
            width: src_w,
            height: src_h,
        },
        ScalingMode::Aspect => {
            let scaled_width = hd * src_h;
            let scaled_height = src_w * vd;
            if scaled_width > scaled_height {
                // Pillarbox.
                let mut width = scaled_height / src_h;
                if width & 1 != 0 {
                    width += 1;
                }
                Window {
                    x: (hd - width + 1) / 2,
                    y: 0,
                    width,
                    height: vd,
                }
            } else if scaled_width < scaled_height {
                // Letterbox.
                let mut height = scaled_width / src_w;
                if height & 1 != 0 {
                    height += 1;
                }
                Window {
                    x: 0,
                    y: (vd - height + 1) / 2,
                    width: hd,
                    height,
                }
            } else {
                Window {
                    x: 0,
                    y: 0,
                    width: hd,
                    height: vd,
                }
            }
        }
        ScalingMode::Fullscreen => Window {
            x: 0,
            y: 0,
            width: hd,
            height: vd,
        },
    };
    Some(window)
}

/// `drm_calc_scale`: 16.16, rounded up above 1.0 and down below.
fn calc_scale(src: u32, dst: u32) -> u32 {
    if dst == 0 {
        return 0;
    }
    if u64::from(src) > u64::from(dst) << 16 {
        src.div_ceil(dst)
    } else {
        src / dst
    }
}

/// `drm_rect_calc_hscale`/`_vscale` with `[min, max]`.
fn checked_scale(src: u32, dst: u32, min: u32, max: u32) -> Result<u32, ScalerRefusal> {
    let scale = calc_scale(src, dst);
    if dst != 0 && (scale < min || scale > max) {
        return Err(ScalerRefusal::Ratio);
    }
    Ok(scale)
}

/// `calculate_max_scale` (display 14): 3.0 horizontally; vertically 3.0 on
/// scaler 0 and 1.0 on scaler 1. 16.16.
pub const fn max_scale(id: u32) -> (u32, u32) {
    (0x30000 - 1, if id == 0 { 0x30000 - 1 } else { 0x10000 })
}

/// `skl_update_scaler_crtc` with `intel_atomic_setup_scaler` for the
/// panel fitter: `None` for a native source, the bound scaler otherwise.
pub fn plan(
    native: &Mode,
    src_w: u32,
    src_h: u32,
    mode: ScalingMode,
    filter: Filter,
) -> Result<Option<PipeScaler>, ScalerRefusal> {
    let Some(window) = panel_fit(native, src_w, src_h, mode) else {
        return Ok(None);
    };
    // The window must lie on the panel (a centered source larger than the
    // panel would not).
    if u64::from(window.x) + u64::from(window.width) > u64::from(native.h_active)
        || u64::from(window.y) + u64::from(window.height) > u64::from(native.v_active)
    {
        return Err(ScalerRefusal::OutOfRange);
    }
    // skl_update_scaler's range checks (packed RGB source).
    if src_w < MIN_SIZE
        || src_h < MIN_SIZE
        || window.width < MIN_SIZE
        || window.height < MIN_SIZE
        || src_w > MAX_SRC_W
        || src_h > MAX_SRC_H
        || window.width > MAX_DST
        || window.height > MAX_DST
    {
        return Err(ScalerRefusal::OutOfRange);
    }
    if src_w > MAX_DST || src_h > MAX_DST {
        return Err(ScalerRefusal::PipeSourceTooLarge);
    }
    // intel_allocate_scaler: the panel fitter is the pipe's only user.
    let id = 0;
    let (max_h, max_v) = max_scale(id);
    let hscale = checked_scale(src_w << 16, window.width, 0, max_h)?;
    let vscale = checked_scale(src_h << 16, window.height, 0, max_v)?;
    if hscale > 0x10000 || vscale > 0x10000 {
        return Err(ScalerRefusal::Downscale);
    }
    Ok(Some(PipeScaler {
        id,
        window,
        hscale,
        vscale,
        filter,
    }))
}

/// `skl_scaler_calc_phase(1, scale, false)`.
pub fn calc_phase(scale: u32) -> u16 {
    let mut phase = -0x8000i32 + (scale / 2) as i32;
    let mut trip = 0u16;
    if phase < 0 {
        phase += 0x10000;
    } else {
        trip = PS_PHASE_TRIP;
    }
    (((phase >> 2) as u16) & PS_PHASE_MASK) | trip
}

/// `PS_PHASE_MASK` (u2.13) and `PS_PHASE_TRIP`.
const PS_PHASE_MASK: u16 = 0x7fff << 1;
const PS_PHASE_TRIP: u16 = 1;
/// `PS_SCALER_EN`, `PS_BINDING_PIPE`, `PS_SCALER_MODE_NORMAL`.
pub const PS_SCALER_EN: u32 = 1 << 31;
/// `PS_FILTER_PROGRAMMED` with every filter select on set 0.
pub const PS_FILTER_PROGRAMMED: u32 = 1 << 23;
/// `PS_COEF_INDEX_AUTO_INC`.
pub const PS_COEF_INDEX_AUTO_INC: u32 = 1 << 10;

/// `_MMIO_PIPE(pipe, _ID(id, 1A, 2A), _ID(id, 1B, 2B))`: 0x800 per pipe,
/// 0x100 per scaler.
const fn ps_reg(pipe: Pipe, id: u32, reg_1a: u64) -> u64 {
    reg_1a + pipe as u64 * 0x800 + id as u64 * 0x100
}
/// `SKL_PS_CTRL`.
pub const fn ps_ctrl(pipe: Pipe, id: u32) -> u64 {
    ps_reg(pipe, id, 0x6_8180)
}
/// `SKL_PS_WIN_POS`.
pub const fn ps_win_pos(pipe: Pipe, id: u32) -> u64 {
    ps_reg(pipe, id, 0x6_8170)
}
/// `SKL_PS_WIN_SZ`.
pub const fn ps_win_sz(pipe: Pipe, id: u32) -> u64 {
    ps_reg(pipe, id, 0x6_8174)
}
/// `SKL_PS_VPHASE`.
pub const fn ps_vphase(pipe: Pipe, id: u32) -> u64 {
    ps_reg(pipe, id, 0x6_8188)
}
/// `SKL_PS_HPHASE`.
pub const fn ps_hphase(pipe: Pipe, id: u32) -> u64 {
    ps_reg(pipe, id, 0x6_8194)
}
/// `GLK_PS_COEF_INDEX_SET` / `GLK_PS_COEF_DATA_SET`.
pub const fn ps_coef_index(pipe: Pipe, id: u32, set: u32) -> u64 {
    ps_reg(pipe, id, 0x6_8198) + set as u64 * 8
}
pub const fn ps_coef_data(pipe: Pipe, id: u32, set: u32) -> u64 {
    ps_reg(pipe, id, 0x6_819c) + set as u64 * 8
}

/// Scalers per display-14 pipe.
pub const SCALERS: u32 = 2;

/// `glk_program_nearest_filter_coefs`: 17 phases of 7 taps, the centre
/// tap 1.0 (0x0800) and every other tap 0 (0x3000), two per dword, with
/// the index auto-incrementing.
pub fn nearest_filter_writes(pipe: Pipe, id: u32, set: u32) -> alloc::vec::Vec<(u64, u32)> {
    let coef = |i: u32| if i % 7 == 3 { 0x0800u32 } else { 0x3000 };
    let mut w = alloc::vec::Vec::with_capacity(62);
    w.push((ps_coef_index(pipe, id, set), PS_COEF_INDEX_AUTO_INC));
    let mut i = 0;
    while i < 17 * 7 {
        w.push((ps_coef_data(pipe, id, set), coef(i) | coef(i + 1) << 16));
        i += 2;
    }
    w.push((ps_coef_index(pipe, id, set), 0));
    w
}

impl PipeScaler {
    /// `PS_CTRL`: enabled, bound to the pipe, normal mode, the filter.
    pub fn ctrl(&self) -> u32 {
        PS_SCALER_EN
            | match self.filter {
                // PS_FILTER_MEDIUM is 0.
                Filter::Default => 0,
                Filter::NearestNeighbor => PS_FILTER_PROGRAMMED,
            }
    }

    /// `skl_pfit_enable` on `pipe`, in its order: the filter
    /// coefficients (nearest neighbour), `PS_CTRL`, `PS_VPHASE`,
    /// `PS_HPHASE`, `PS_WIN_POS`, `PS_WIN_SZ`. The phases take
    /// `drm_rect_calc_*scale` without limits, as Linux recomputes them.
    pub fn enable_writes(&self, pipe: Pipe) -> alloc::vec::Vec<(u64, u32)> {
        let id = self.id;
        let mut w = alloc::vec::Vec::new();
        if self.filter == Filter::NearestNeighbor {
            w.extend(nearest_filter_writes(pipe, id, 0));
        }
        let vphase = u32::from(calc_phase(self.vscale));
        let hphase = u32::from(calc_phase(self.hscale));
        w.push((ps_ctrl(pipe, id), self.ctrl()));
        w.push((ps_vphase(pipe, id), vphase));
        w.push((ps_hphase(pipe, id), hphase));
        w.push((
            ps_win_pos(pipe, id),
            (self.window.x & 0xffff) << 16 | (self.window.y & 0xffff),
        ));
        w.push((
            ps_win_sz(pipe, id),
            (self.window.width & 0xffff) << 16 | (self.window.height & 0xffff),
        ));
        w
    }
}

/// `skl_scaler_disable`: every scaler of `pipe` detached (`PS_CTRL`,
/// `PS_WIN_POS`, `PS_WIN_SZ` zero).
pub fn disable_writes(pipe: Pipe) -> [(u64, u32); 6] {
    [
        (ps_ctrl(pipe, 0), 0),
        (ps_win_pos(pipe, 0), 0),
        (ps_win_sz(pipe, 0), 0),
        (ps_ctrl(pipe, 1), 0),
        (ps_win_pos(pipe, 1), 0),
        (ps_win_sz(pipe, 1), 0),
    ]
}

/// `skl_scaler_1st_prefill_lines` and `skl_scaler_2nd_prefill_lines`
/// (.16 lines) for `scalers` users, the panel fitter among them when
/// `pfit`. Their adjustments are 1.0 at this revision.
pub fn prefill_lines(scalers: u32, pfit: bool) -> (u64, u64) {
    let first = if scalers > 0 { 4 << 16 } else { 0 };
    let second = if scalers > 1 && pfit { 4 << 16 } else { 0 };
    (first, second)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_scaler_tests.rs"]
mod tests;
