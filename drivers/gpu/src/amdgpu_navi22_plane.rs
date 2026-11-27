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
//! screen, unscaled), so returning to it is the same update. [`plan_two`]
//! is the same for a primary with a slave overlay beside it: one joint
//! DML30 plan for both planes, on the one stream's timing. The
//! programming lives in `amdgpu_navi22_modeset` (`Pipeline::program_plane`,
//! `Pipeline::program_two_planes`) and the flip in `amdgpu_navi22_scanout`.
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

/// Everything a lit stream shows with a slave overlay beside its primary:
/// the primary's and the overlay's placements, each with its own scaler and
/// DML30 plan, planned jointly (`dcn30_validate_bandwidth` runs DML30 on
/// the whole context: one DISPCLK and DPPCLK step, the summed read
/// bandwidth, one watermark set, each pipe's DLG/TTU registers). The two
/// plans share the joint clocks, watermarks and DRAM-clock-change support;
/// `overlay_dppclk_khz` is the slave pipe's DPP DTO
/// (`dml30::PlanePlan::dppclk_khz`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwoPlaneUpdate {
    pub primary: Update,
    pub overlay: Update,
    pub overlay_dppclk_khz: u32,
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
    /// A slave overlay is live: place through the two-plane path
    /// ([`plan_two`]), not the single-plane one — the single plan's
    /// clocks and watermarks do not budget the overlay.
    Overlay,
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
    /// [`plan_two`] on this stream: a primary and a slave overlay placed
    /// together. An ODM stream refuses every placement. Planning is pure:
    /// it does not lease the slave pipe; the caller leases it before
    /// programming the update.
    pub fn plan_two(
        &self,
        primary: &Request,
        overlay: &Request,
    ) -> Result<TwoPlaneUpdate, Refusal> {
        if self.odm {
            return Err(Refusal::Odm);
        }
        plan_two(
            &self.timing,
            self.vco_khz,
            &self.soc,
            &self.lit,
            primary,
            overlay,
        )
    }
}

/// `hubp2_program_size`'s pitch field and DCN30's 14-bit viewport fields.
const MAX_PITCH: u32 = 0x4000; // linux: n/a (HUBPREQ0_DCSURF_SURFACE_PITCH__PITCH_MASK + 1)

/// The scaler and DML30 stream for `request` on `timing`: the
/// `resource_build_scaling_params` scaler for the lit pipe, then the
/// `dcn20_populate_dml_pipes_from_context` stream for it. `cursors` is the
/// cursor count this plane's pipe budgets (the cursor is budgeted once, on
/// the primary).
fn stream_for(
    timing: &Timing,
    vco_khz: u32,
    request: &Request,
    cursors: u32,
) -> Result<(scl::ScalerData, dml30::Stream), Refusal> {
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
        // dml30 reads only the timing and plane; `dcn` selects DCN 3.1.x math.
        dcn: crate::amdgpu_dml::Dcn::Dcn314,
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
        cursors,
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
    Ok((scaler, stream))
}

/// A [`dml30::Plan`] for one plane of a joint plan, as [`dml30::plan_stream`]
/// builds it from the joint plan's first plane.
fn plan_of(joint: &dml30::JointPlan, index: usize) -> Result<dml30::Plan, Refusal> {
    let plane = joint
        .planes
        .get(index)
        .ok_or(Refusal::Mode(crate::amdgpu_dml::Error::Invalid))?;
    let pipe = plane.pipes[0].ok_or(Refusal::Mode(crate::amdgpu_dml::Error::Invalid))?;
    Ok(dml30::Plan {
        prefetch_mode: joint.prefetch_mode,
        geometry: plane.geometry,
        clocks: joint.clocks,
        watermarks: joint.watermarks,
        prefetch: plane.prefetch,
        registers: pipe.registers,
        hubbub: joint.hubbub,
        dram_clock_change: joint.dram_clock_change,
        urgent_bandwidth_thousandths: joint.urgent_bandwidth_thousandths,
        cursor: pipe.cursor,
    })
}

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
    let (scaler, stream) = stream_for(timing, vco_khz, request, 1)?;
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

/// The scaler data and DML30 plans for `primary` and `overlay` on the lit
/// stream of `timing`, planned jointly as one two-plane configuration:
/// the two streams share `timing` (one OTG), the cursor is budgeted on the
/// primary only, and the joint clocks must fit the lit stream's — the same
/// admission [`plan`] applies to one plane. Nothing is programmed.
pub fn plan_two(
    timing: &Timing,
    vco_khz: u32,
    soc: &dml30::Soc,
    lit: &dml30::Plan,
    primary: &Request,
    overlay: &Request,
) -> Result<TwoPlaneUpdate, Refusal> {
    let (primary_scaler, primary_stream) = stream_for(timing, vco_khz, primary, 1)?;
    let (overlay_scaler, overlay_stream) = stream_for(timing, vco_khz, overlay, 0)?;
    let joint = dml30::plan_joint(&[primary_stream, overlay_stream], soc).map_err(Refusal::Mode)?;
    if joint.planes.iter().any(|p| p.odm != dml30::Odm::None) {
        // The lit stream fits on one pipe, so the same timing cannot need
        // ODM — but a joint plan that split a plane would only program its
        // first slice here. Refuse rather than drive half a plane.
        return Err(Refusal::Odm);
    }
    let primary_plan = plan_of(&joint, 0)?;
    let overlay_plan = plan_of(&joint, 1)?;
    if primary_plan.clocks.dppclk_khz > lit.clocks.dppclk_khz
        || primary_plan.clocks.dispclk_khz > lit.clocks.dispclk_khz
    {
        return Err(Refusal::Clock);
    }
    let overlay_dppclk_khz = joint
        .planes
        .get(1)
        .map(|p| p.dppclk_khz)
        .ok_or(Refusal::Mode(crate::amdgpu_dml::Error::Invalid))?;
    Ok(TwoPlaneUpdate {
        primary: Update {
            request: *primary,
            scaler: primary_scaler,
            plan: primary_plan,
        },
        overlay: Update {
            request: *overlay,
            scaler: overlay_scaler,
            plan: overlay_plan,
        },
        overlay_dppclk_khz,
    })
}

/// The refusal texts of [`admit`], in the atomic refusal trace's
/// `why="<plane/property>: <rule> (<Linux function>)"` style.
pub mod why {
    pub const FORMAT: &str =
        "primary plane FB_ID: not a linear 8888 framebuffer (LINUX-GAP: Navi22 presents XRGB8888/ARGB8888 primaries only)";
    pub const ROTATION: &str =
        "plane 'rotation': Navi22 scans out unrotated planes only (LINUX-GAP: hubp2_program_rotation)";
    pub const COVERAGE: &str =
        "primary plane 'pixel blend mode': Coverage on the bottom plane is not programmed (LINUX-GAP: dcn20_update_mpcc)";
    pub const TILED: &str =
        "plane FB_ID: framebuffer modifier is not LINEAR (DCN30 scans out linear surfaces only)";
    pub const MALFORMED: &str =
        "primary plane placement: DC refuses it on the lit stream (dc_validate_global_state): SRC outside the framebuffer or a pitch the HUBP cannot hold";
    pub const GEOMETRY: &str =
        "primary plane placement: DC refuses it on the lit stream (dc_validate_global_state): resource_build_scaling_params";
    pub const MODE: &str =
        "primary plane placement: DC refuses it on the lit stream (dc_validate_global_state): dcn30_validate_bandwidth";
    pub const CLOCK: &str =
        "primary plane placement: DC refuses it on the lit stream (dc_validate_global_state): needs more DISPCLK/DPPCLK than the stream runs at (LINUX-GAP: dcn3_update_clocks)";
    pub const ODM: &str =
        "primary plane placement: DC refuses it on the lit stream (dc_validate_global_state): the stream is split across ODM pipes (LINUX-GAP)";
    pub const OVERLAY: &str =
        "primary plane placement: a slave overlay is live, so place through the two-plane path, not the single-plane one — the single plan's clocks and watermarks do not budget the overlay (dc_validate_global_state)";
    pub const OVERLAY_COUNT: &str =
        "overlay planes: Navi22 lights at most one slave pipe per stream (dc_validate_global_state: max_slave_planes = 2, one slave per stream)";
    pub const OVERLAY_FORMAT: &str =
        "overlay plane FB_ID: not a linear 8888 framebuffer (LINUX-GAP: Navi22 presents XRGB8888/ARGB8888 overlays only)";
    pub const OVERLAY_UNDERLAY: &str =
        "overlay plane 'zpos': below the primary's, but the slave MPCC links above the primary's in the tree (LINUX-GAP: dcn20_update_mpcc would place it below)";
    pub const OVERLAY_ROTATION: &str =
        "overlay plane 'rotation': Navi22 scans out unrotated planes only (LINUX-GAP: hubp2_program_rotation)";
    pub const OVERLAY_CLIENT: &str =
        "overlay plane FB_ID: a dumb-buffer overlay has no GEM pin to scan out in place (LINUX-GAP: no staging surface exists for a dumb overlay)";
    pub const OVERLAY_DISPLAY: &str =
        "overlay plane: only display 0 lights a slave pipe (dc_validate_global_state: one lit stream)";
    pub const OVERLAY_MALFORMED: &str =
        "overlay plane placement: DC refuses it on the lit stream (dc_validate_global_state): SRC outside the framebuffer or a pitch the HUBP cannot hold";
    pub const OVERLAY_GEOMETRY: &str =
        "overlay plane placement: DC refuses it on the lit stream (dc_validate_global_state): resource_build_scaling_params";
    pub const OVERLAY_MODE: &str =
        "overlay plane placement: DC refuses it on the lit stream (dc_validate_global_state): dcn30_validate_bandwidth";
    pub const OVERLAY_CLOCK: &str =
        "overlay plane placement: DC refuses it on the lit stream (dc_validate_global_state): needs more DISPCLK/DPPCLK than the stream runs at (LINUX-GAP: dcn3_update_clocks)";
    pub const OVERLAY_ODM: &str =
        "overlay plane placement: DC refuses it on the lit stream (dc_validate_global_state): the stream is split across ODM pipes (LINUX-GAP)";
}

/// The text for a placement [`Refusal`].
pub const fn refusal_why(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::Invalid => why::MALFORMED,
        Refusal::Geometry(_) => why::GEOMETRY,
        Refusal::Mode(_) => why::MODE,
        Refusal::Clock => why::CLOCK,
        Refusal::Odm => why::ODM,
        Refusal::Overlay => why::OVERLAY,
    }
}

/// The text for an overlay placement [`Refusal`]: the same DC refusal,
/// named for the overlay plane rather than the primary.
pub const fn refusal_why_overlay(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::Invalid => why::OVERLAY_MALFORMED,
        Refusal::Geometry(_) => why::OVERLAY_GEOMETRY,
        Refusal::Mode(_) => why::OVERLAY_MODE,
        Refusal::Clock => why::OVERLAY_CLOCK,
        Refusal::Odm => why::OVERLAY_ODM,
        Refusal::Overlay => why::OVERLAY,
    }
}

/// `dc_validate_global_state` for one CRTC's planes after a DRM commit
/// (`planes`, as `drm_native_planes::check` built them) on the lit stream
/// `basis`, at `mode`, the CRTC's active size (width, height) after the
/// commit — the callers pass the request's MODE_ID's, else the committed
/// mode's: exactly what the presenter programs is admitted, so a refused
/// request never reaches it and the compositor falls back at TEST_ONLY.
///
/// The primary is a linear 8888 framebuffer, unrotated, blended as the
/// bottom plane (opaque and pre-multiplied are the same over the black
/// background; Coverage is not), and a positioned or scaled one must plan
/// on the lit pipe ([`Basis::plan`]: `resource_build_scaling_params`, then
/// `dcn30_validate_bandwidth`). With no lit stream, or a mode other than
/// the lit one (a modeset in this commit, or one committed earlier that
/// the display has not lit yet), the placement is validated by the modeset
/// that lights it.
///
/// One overlay is admitted on the same stream: DCN30's
/// `max_slave_planes = 2` is one slave per stream, and the presenter
/// leases the free pipe at present time, so a second overlay is refused
/// here rather than raced there. The overlay is a GEM framebuffer in
/// place (no staging surface exists for a dumb overlay), XRGB8888 or
/// ARGB8888, LINEAR tiling, R0 rotation, and above the primary in
/// z-order: the slave MPCC links above the primary's in the tree, so an
/// underlay cannot be programmed. Its blend is not checked: per-pixel
/// alpha, pre-multiplied and global alpha are all programmed by
/// `program_two_planes`, unlike the primary's. The joint two-plane DML30
/// plan ([`Basis::plan_two`]) must fit the lit stream's clock and
/// watermark headroom. An overlay-only commit (no primary) is admitted
/// on its static checks alone: the joint plan is against the shown
/// primary, which this check does not know — the presenter plans two
/// against it at present time.
pub fn admit(
    basis: Option<&Basis>,
    mode: Option<(u32, u32)>,
    planes: &crate::drm_native_planes::DisplayPlanes,
) -> Result<(), &'static str> {
    use crate::amdgpu_dcn401_otg::{Blend, SurfaceFormat, Tiling};
    use crate::amdgpu_dcn401_spl::Rotation;
    let format = match SurfaceFormat::from_fourcc(planes.primary_format) {
        Some(f @ (SurfaceFormat::Xrgb8888 | SurfaceFormat::Argb8888)) => f,
        _ => return Err(why::FORMAT),
    };
    // No DCN30 surface is tiled here: ADDFB2 lets none onto the linear
    // card, and one that got this far is never handed to a HUBP.
    let surfaces = planes
        .setup
        .primary
        .iter()
        .chain(planes.setup.overlays.iter().flatten().map(|o| &o.geometry));
    if surfaces
        .into_iter()
        .any(|g| g.surface.tiling != Tiling::LINEAR)
    {
        return Err(why::TILED);
    }
    // One slave overlay per stream (see the doc comment above).
    if planes.setup.overlay_count() > 1 {
        return Err(why::OVERLAY_COUNT);
    }
    let overlay = planes
        .setup
        .overlays
        .iter()
        .enumerate()
        .find_map(|(k, o)| o.as_ref().map(|o| (k, o)));
    if let Some((_, o)) = overlay {
        match o.format {
            SurfaceFormat::Xrgb8888 | SurfaceFormat::Argb8888 => (),
            _ => return Err(why::OVERLAY_FORMAT),
        }
        if o.underlay {
            return Err(why::OVERLAY_UNDERLAY);
        }
        if o.geometry.rotation != Rotation::R0 {
            return Err(why::OVERLAY_ROTATION);
        }
        if !o.geometry.client {
            return Err(why::OVERLAY_CLIENT);
        }
    }
    let Some(g) = planes.setup.primary else {
        return Ok(());
    };
    if g.rotation != Rotation::R0 {
        return Err(why::ROTATION);
    }
    // amdgpu_dm_plane_fill_blending_from_plane_state: None and
    // Pre-multiplied leave the bottom plane's pixels as they are.
    let opaque = Blend {
        per_pixel_alpha: false,
        ..Blend::default_for(format)
    };
    if g.blend != Blend::default_for(format) && g.blend != opaque {
        return Err(why::COVERAGE);
    }
    let Some(basis) = basis else {
        return Ok(());
    };
    if mode.is_some_and(|m| m != (basis.timing.h_active, basis.timing.v_active)) {
        return Ok(());
    }
    let (Ok(w), Ok(h)) = (u32::try_from(g.dst.width), u32::try_from(g.dst.height)) else {
        return Err(why::MALFORMED);
    };
    let request = Request {
        pitch: planes.pitches[0] / 4,
        width: g.fb_size.0,
        height: g.fb_size.1,
        src: (g.src_x, g.src_y, g.width, g.height),
        dst: (g.dst.x, g.dst.y, w, h),
    };
    let Some((k, o)) = overlay else {
        return basis.plan(&request).map(|_| ()).map_err(refusal_why);
    };
    let (Ok(ow), Ok(oh)) = (
        u32::try_from(o.geometry.dst.width),
        u32::try_from(o.geometry.dst.height),
    ) else {
        return Err(why::OVERLAY_MALFORMED);
    };
    let overlay_request = Request {
        pitch: planes.pitches[1 + k] / 4,
        width: o.geometry.fb_size.0,
        height: o.geometry.fb_size.1,
        src: (
            o.geometry.src_x,
            o.geometry.src_y,
            o.geometry.width,
            o.geometry.height,
        ),
        dst: (o.geometry.dst.x, o.geometry.dst.y, ow, oh),
    };
    basis
        .plan_two(&request, &overlay_request)
        .map(|_| ())
        .map_err(refusal_why_overlay)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_plane_tests.rs"]
mod tests;
