//! The Navi22 primary as amdgpu_dm hands it to DC: a linear XRGB/ARGB8888
//! framebuffer (pitch and size) showing its SRC rectangle in a CRTC
//! rectangle. [`plan`] is what a plane update needs before any register is
//! written, in DC's order: `resource_build_scaling_params`
//! ([`crate::amdgpu_dcn30_scl::build`]) for the lit pipe, then
//! `dcn30_validate_bandwidth`'s DML30 run with that pipe's viewport, ratios,
//! taps and recout ([`crate::amdgpu_dml30::plan_stream`]) on the lit
//! stream's timing and bounding-box state.
//!
//! The lit configuration is itself a request (the owned surface, full
//! screen, unscaled), so returning to it is the same update. The
//! programming lives in `amdgpu_navi22_modeset` (`Pipeline::program_plane`)
//! and the flip in `amdgpu_navi22_scanout`.
use crate::{
    amdgpu_dcn30_scl as scl,
    amdgpu_dml::{Config, Format, Plane, Timing},
    amdgpu_dml30 as dml30,
};

/// One primary frame's placement: the framebuffer it fetches (pitch in
/// pixels, width and height) and DRM's SRC (whole pixels) and CRTC
/// rectangles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub src: (u32, u32, u32, u32),
    pub dst: (i32, i32, u32, u32),
}
impl Request {
    /// A full-screen, unscaled frame of a `pitch`-pixel framebuffer at least
    /// as large as `timing`'s active area.
    pub fn full_screen(pitch: u32, width: u32, height: u32, timing: &Timing) -> Self {
        let (w, h) = (timing.h_active, timing.v_active);
        Self {
            pitch,
            width,
            height,
            src: (0, 0, w, h),
            dst: (0, 0, w, h),
        }
    }
}

/// Everything the lit pipe is programmed with for a [`Request`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Update {
    pub request: Request,
    pub scaler: scl::ScalerData,
    pub plan: dml30::Plan,
}

/// Why a placement cannot be shown on the lit pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The framebuffer or rectangles are malformed (SRC outside the
    /// framebuffer, a pitch the HUBP cannot hold).
    Invalid,
    /// `resource_build_scaling_params` refuses it.
    Geometry(scl::Error),
    /// DML30 mode support refuses it.
    Mode(crate::amdgpu_dml::Error),
    /// It needs more DPPCLK or DISPCLK than the lit stream runs at.
    /// LINUX-GAP: dcn3_update_clocks would raise them in prepare_bandwidth;
    /// NARF's DCN30 clock owner only sets them at a modeset.
    Clock,
    /// The stream is split across two ODM pipes.
    /// LINUX-GAP: DC builds a viewport per ODM slice; this owner programs
    /// a placed plane on a single pipe only.
    Odm,
}

/// The lit stream a placement is planned on: its timing, DENTIST VCO,
/// bounding-box state and own plan, and whether it is split across ODM
/// pipes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Basis {
    pub timing: Timing,
    pub vco_khz: u32,
    pub soc: dml30::Soc,
    pub lit: dml30::Plan,
    pub odm: bool,
}
impl Basis {
    /// [`plan`] on this stream; an ODM stream refuses every placement.
    pub fn plan(&self, request: &Request) -> Result<Update, Refusal> {
        if self.odm {
            return Err(Refusal::Odm);
        }
        plan(&self.timing, self.vco_khz, &self.soc, &self.lit, request)
    }
}

/// `hubp2_program_size`'s pitch field and DCN30's 14-bit viewport fields.
const MAX_PITCH: u32 = 0x4000; // linux: n/a (HUBPREQ0_DCSURF_SURFACE_PITCH__PITCH_MASK + 1)

/// The scaler data and DML30 plan for `request` on the lit single-pipe
/// stream of `timing`, whose own plan is `lit` on bounding-box state
/// `soc`. Nothing is programmed.
pub fn plan(
    timing: &Timing,
    vco_khz: u32,
    soc: &dml30::Soc,
    lit: &dml30::Plan,
    request: &Request,
) -> Result<Update, Refusal> {
    let r = request;
    let fits = |at: u32, len: u32, max: u32| at.checked_add(len).is_some_and(|e| e <= max);
    if r.pitch == 0
        || r.pitch > MAX_PITCH
        || r.width == 0
        || r.height == 0
        || r.pitch < r.width
        || !fits(r.src.0, r.src.2, r.width)
        || !fits(r.src.1, r.src.3, r.height)
        || r.dst.2 == 0
        || r.dst.3 == 0
    {
        return Err(Refusal::Invalid);
    }
    let int = |v: u32| i32::try_from(v).map_err(|_| Refusal::Invalid);
    let src = scl::Rect::new(int(r.src.0)?, int(r.src.1)?, int(r.src.2)?, int(r.src.3)?);
    let dst = scl::Rect::new(r.dst.0, r.dst.1, int(r.dst.2)?, int(r.dst.3)?);
    let scaler = scl::build(
        int(timing.h_active)?,
        int(timing.v_active)?,
        (0, 1),
        src,
        dst,
    )
    .map_err(Refusal::Geometry)?;
    let vp = scaler.viewport;
    let ratio = |r| crate::amdgpu_dml::Fx::ratio(i64::from(scl::u3d19(r)), 1 << 19);
    let config = Config {
        timing: *timing,
        plane: Plane {
            format: Format::Rgb32,
            surface_width: r.width,
            surface_height: r.height,
            viewport_width: vp.width as u32,
            viewport_height: vp.height as u32,
            pitch: r.pitch,
            h_taps: scaler.h_taps,
            v_taps: scaler.v_taps,
        },
        dentist_vco_khz: vco_khz,
        // dcn20_populate_dml_pipes_from_context budgets the cursor.
        cursors: 1,
    };
    let stream = dml30::Stream {
        scale: Some(dml30::Scale {
            h_ratio: ratio(scaler.ratio_h),
            v_ratio: ratio(scaler.ratio_v),
            recout_width: scaler.recout.width as u32,
            recout_height: scaler.recout.height as u32,
        }),
        ..dml30::Stream::tmds(config)
    };
    let plan = dml30::plan_stream(&stream, soc).map_err(Refusal::Mode)?;
    if plan.clocks.dppclk_khz > lit.clocks.dppclk_khz
        || plan.clocks.dispclk_khz > lit.clocks.dispclk_khz
    {
        return Err(Refusal::Clock);
    }
    Ok(Update {
        request: *request,
        scaler,
        plan,
    })
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_plane_tests.rs"]
mod tests;
