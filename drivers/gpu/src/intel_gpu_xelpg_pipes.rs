//! Display-14.00 Pipe B–D owner for the external outputs.
//!
//! The owned Pipe-A panel is adopted, never stopped or replaned; this
//! owner adds and removes Pipes B–D around it. Its caller is the MTL
//! external route ([`crate::intel_gpu_xelpg_external`] for DP,
//! [`crate::intel_gpu_xelpg_hdmi`] for HDMI), which owns the port side.
//! Sequence (MIT Linux b90c984d `intel_display.c::intel_atomic_commit_tail`,
//! `skl_commit_modeset_enables`, `hsw_crtc_enable` / `hsw_crtc_disable`,
//! `intel_update_crtc`, `intel_crtc.c::intel_pipe_update_start` / `_end`),
//! with resources from [`crate::intel_gpu_xelpg_live`]:
//!
//! 1. [`Pipes::reserve`] — the pre-plane update: DBUF/DDB/WM/MBUS/CDCLK/
//!    PM demand for the new pipe while every lit pipe stays lit (the
//!    all-off commit when none is lit), then `intel_dmc_enable_pipe`, the
//!    first step of `hsw_crtc_enable`.
//! 2. The caller: `intel_encoders_pre_enable` — port PLL, `TRANS_CLK_SEL`,
//!    `TRANS_DDI_FUNC_CTL` configured, link training (DP) or infoframes
//!    (HDMI) for this pipe's transcoder.
//! 3. [`Pipes::program_timings`] — `intel_set_pipe_src_size`,
//!    `bdw_set_pipe_misc`, `hsw_configure_cpu_transcoder`
//!    (`intel_set_transcoder_timings` with `TRANS_SET_CONTEXT_LATENCY`,
//!    `intel_vrr_set_transcoder_timings`, `TRANS_MULT`,
//!    `hsw_set_frame_start_delay`, `hsw_set_transconf`),
//!    `intel_color_modeset` (the owned RGB bypass), `hsw_set_linetime_wm`,
//!    `icl_set_pipe_chicken` and the display-14 no-DPT plane chicken
//!    (`intel_pre_update_crtc` → `intel_dpt_configure`), pipe off.
//! 4. The caller enables `TRANS_DDI_FUNC_CTL`; [`Pipes::enable`] is
//!    `intel_enable_transcoder` (`TRANSCONF` with its STATE ack).
//! 5. [`Pipes::arm_primary`] — `intel_update_crtc`: the noarm plane
//!    registers, then `PLANE_CTL` + `PLANE_SURF` inside vblank evasion with
//!    local interrupts masked ([`crate::intel_gpu_xelpg_live::evade_then`]),
//!    proved by a fresh frame and `PLANE_SURFLIVE`.
//! 6. Stop: [`Pipes::disable_primary`] (`intel_crtc_disable_planes`),
//!    [`Pipes::disable`] (`intel_disable_transcoder`), the caller's port
//!    stop and PLL off, then [`Pipes::release`]: `intel_dmc_disable_pipe`
//!    (the last step of `hsw_crtc_disable`) and the post-plane repartition
//!    without the pipe.
//!
//! Only linear XRGB8888 full-pipe primaries, unscaled, are admitted.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_dc_states::PipeDmc;
use crate::intel_gpu_modeset::Mode;
use crate::intel_gpu_pipes::{
    build_pipe, build_primary_plane, build_transcoder, DisplayTiming, Pipe, PixelFormat,
    PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE, PIPE_SRCSZ_OFFSET, PLANE_CTL_ENABLE,
    PLANE_CTL_OFFSET, PLANE_OFFSET_OFFSET, PLANE_POS_OFFSET, PLANE_PRIMARY_OFFSET,
    PLANE_SIZE_OFFSET, PLANE_STRIDE_OFFSET, PLANE_SURF_OFFSET, TRANS_HBLANK_OFFSET,
    TRANS_HSYNC_OFFSET, TRANS_HTOTAL_OFFSET, TRANS_VBLANK_OFFSET, TRANS_VSYNC_OFFSET,
    TRANS_VTOTAL_OFFSET,
};
use crate::intel_gpu_xelpg_resources::{
    self as res, checked, read, PipeRequest, PlaneRequest, ResourceError, State, PLANES,
};
use crate::intel_gpu_xelpg_wm::Tiling;
use alloc::boxed::Box;

/// `PIPE_FRMCOUNT_G4X` relative to the pipe block.
const FRMCOUNT_OFFSET: u64 = 0x40;
/// `PLANE_SURFLIVE` relative to the plane block.
const PLANE_SURFLIVE_OFFSET: u64 = 0x2c;
/// `PLANE_CHICKEN` relative to the plane block (`_PLANE_CHICKEN_1_A`).
const PLANE_CHICKEN_OFFSET: u64 = 0xec;
/// `PLANE_CHICKEN_DISABLE_DPT`.
const PLANE_CHICKEN_DISABLE_DPT: u32 = 1 << 19;
/// `PLANE_CTL` tiling field (bits 12:10): linear, X, Tile4.
const PLANE_CTL_TILED_MASK: u32 = 7 << 10;
const PLANE_CTL_TILED_X: u32 = 1 << 10;
const PLANE_CTL_TILED_4: u32 = 5 << 10;
/// `intel_wait_for_pipe_off` / the transcoder-enable budget, 100 ms.
const TRANSCONF_WAIT_MS: u64 = 100;
/// `PIPE_MISC` relative to the pipe block.
const PIPE_MISC_OFFSET: u64 = 0x30;
/// `PIPE_CHICKEN` relative to the pipe block (`_PIPEA_CHICKEN`).
const PIPE_CHICKEN_OFFSET: u64 = 0x38;
/// `icl_set_pipe_chicken` on display 14: `PER_PIXEL_ALPHA_BYPASS_EN`
/// (Display WA #1153), `PIXEL_ROUNDING_TRUNC_FB_PASSTHRU` (Display WA
/// #1605353570) and `UNDERRUN_RECOVERY_DISABLE_ADLP` (display 13..29).
pub(crate) const PIPE_CHICKEN_BITS: u32 = (1 << 30) | (1 << 15) | (1 << 7);
/// Transcoder-block offsets: `TRANS_VSYNCSHIFT`, `TRANS_MULT`,
/// `TRANS_SET_CONTEXT_LATENCY`, `TRANS_VRR_CTL` and the display-14
/// `CHICKEN_TRANS` (`_MTL_CHICKEN_TRANS_A` 0x604e0).
const TRANS_VSYNCSHIFT_OFFSET: u64 = 0x28;
const TRANS_MULT_OFFSET: u64 = 0x2c;
const TRANS_SET_CONTEXT_LATENCY_OFFSET: u64 = 0x7c;
const TRANS_VRR_CTL_OFFSET: u64 = 0x420;
const CHICKEN_TRANS_OFFSET: u64 = 0x4e0;
/// `HSW_FRAME_START_DELAY_MASK`; `framestart_delay` is 1, so the field
/// (`framestart_delay - 1`) is 0.
const FRAME_START_DELAY_MASK: u32 = 3 << 27;
/// `CHICKEN_TRANS` `DP_FEC_BS_JITTER_WA` and `DP_DSC_INSERT_SF_AT_EOL_WA`.
const DP_FEC_BS_JITTER_WA: u32 = 1 << 15;
const DP_DSC_INSERT_SF_AT_EOL_WA: u32 = 1 << 4;

/// `WM_LINETIME(pipe)`.
pub(crate) const fn wm_linetime(pipe: Pipe) -> u64 {
    0x45270 + pipe as u64 * 4
}

/// One external pipe the port owner wants lit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExternalPipe {
    /// B, C or D.
    pub(crate) pipe: Pipe,
    pub(crate) mode: Mode,
    /// GGTT address of a 4 KiB-aligned linear XRGB8888 surface.
    pub(crate) surface: u32,
    pub(crate) stride_bytes: u32,
    /// The port clock the owner runs while the pipe is lit
    /// (`crtc_state->port_clock`: the DP link rate or the HDMI TMDS clock).
    pub(crate) port_clock_khz: u32,
    /// Non-Type-C PHY index, `None` for Type-C.
    pub(crate) combo_phy: Option<u8>,
    /// The route's VDSC term when it compresses (DP DSC).
    pub(crate) dsc: Option<crate::intel_gpu_xelpg_dsc::DscTerm>,
    /// `crtc_state->pipe_bpp`: 24, or 18 for a 6 bpc DP route.
    pub(crate) pipe_bpp: u32,
}

/// Typed pipe-owner failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PipeEnableError {
    /// Pipe A, an invalid mode/surface or an unsupported configuration.
    Unsupported,
    /// The pipe has no reservation (or already has one).
    NotReserved,
    /// The pipe is already enabled, or must be disabled first.
    Busy,
    /// The primary plane was armed on a pipe that is not enabled.
    NotLit,
    /// Resource transaction refusal or failure.
    Resource(ResourceError),
    /// A TRANSCONF/plane acknowledgement did not arrive.
    Timeout,
    /// Lost current access or an all-ones read.
    NoDevice,
}

impl From<ResourceError> for PipeEnableError {
    fn from(e: ResourceError) -> Self {
        match e {
            ResourceError::NoDevice => Self::NoDevice,
            other => Self::Resource(other),
        }
    }
}

fn timing(mode: &Mode) -> DisplayTiming {
    DisplayTiming {
        hactive: mode.h_active,
        hblank_start: mode.h_active,
        hblank_end: mode.h_total,
        hsync_start: mode.h_sync_start,
        hsync_end: mode.h_sync_end,
        htotal: mode.h_total,
        vactive: mode.v_active,
        vblank_start: mode.v_active,
        vblank_end: mode.v_total,
        vsync_start: mode.v_sync_start,
        vsync_end: mode.v_sync_end,
        vtotal: mode.v_total,
    }
}

/// The watermark timing of `ext`'s mode (unscaled: pipe pixel rate).
fn res_timing(ext: &ExternalPipe) -> crate::intel_gpu_xelpg_wm::Timing {
    crate::intel_gpu_xelpg_wm::Timing {
        pixel_rate_khz: ext.mode.pixel_clock_khz,
        htotal: u32::from(ext.mode.h_total),
        vtotal: u32::from(ext.mode.v_total),
        vblank_start: u32::from(ext.mode.v_active),
    }
}

fn request(ext: &ExternalPipe) -> PipeRequest {
    let mut planes = [None; PLANES];
    planes[0] = Some(PlaneRequest {
        width: ext.mode.h_active,
        height: ext.mode.v_active,
        cpp: 4,
        tiling: Tiling::Linear,
    });
    PipeRequest {
        pixel_rate_khz: ext.mode.pixel_clock_khz,
        hdisplay: ext.mode.h_active,
        htotal: ext.mode.h_total,
        vdisplay: ext.mode.v_active,
        vtotal: ext.mode.v_total,
        planes,
        cursor_visible: false,
        port_clock_khz: ext.port_clock_khz,
        combo_phy: ext.combo_phy,
        dsc: ext.dsc,
        src_w: None,
        src_h: None,
        scaler: None,
        bigjoiner_slave: None,
    }
}

/// Bounded poll of `done` against `pipe`'s registers; `lost` on an
/// all-ones read or lost access.
fn poll(
    io: &(impl MmioWindow + ?Sized),
    ms: u64,
    mut done: impl FnMut() -> Option<bool>,
) -> Result<(), PipeEnableError> {
    let mut lost = false;
    let ok = narf_scheduler::responsive_spin_until(
        || match done() {
            None => {
                lost = true;
                true
            }
            Some(done) => done,
        },
        narf_time::Deadline::after_ms(ms),
    );
    if lost || !io.display_access_ok() {
        Err(PipeEnableError::NoDevice)
    } else if ok {
        Ok(())
    } else {
        Err(PipeEnableError::Timeout)
    }
}

fn wait_conf(io: &(impl MmioWindow + ?Sized), pipe: Pipe, on: bool) -> Result<(), PipeEnableError> {
    let conf = pipe.base() + PIPECONF_OFFSET;
    poll(io, TRANSCONF_WAIT_MS, || {
        let v = io.read32(conf);
        (v != u32::MAX && io.display_access_ok()).then_some((v & PIPECONF_STATE != 0) == on)
    })
}

/// The multi-pipe display-14 layout the Pipe B–D owner programmed, as the
/// fixed Pipe-A KMS owner proves its own share against it
/// ([`crate::intel_gpu_display_resources::Profile`]). Present only while a
/// Pipe B–D is reserved; absent means the owned single-pipe layout (or
/// nothing) is programmed. It is a description, never a proof: every
/// reader still verifies the hardware against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    /// The programmed state. Pipe A's primary watermarks are those of the
    /// tiling it scanned out when the owner last transitioned; its cursor
    /// watermarks, every DDB entry and the globals are the linear-baseline
    /// computation, as the KMS owner programs them.
    pub(crate) state: State,
    /// The GGTT scanout surface of each reserved Pipe B–D primary.
    pub(crate) surfaces: [Option<u32>; 4],
}

/// One integrated display per system, as the PSR watermark provider.
static LAYOUT: narf_lib::sync::IrqSafeSpinLock<Option<Layout>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// The layout the Pipe B–D owner last programmed (see [`Layout`]).
pub(crate) fn published_layout() -> Option<Layout> {
    *LAYOUT.lock()
}

/// Fixtures start from the single-pipe description.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn reset_published_layout() {
    *LAYOUT.lock() = None;
}

/// Publish `layout` as programmed (fixtures that program a multi-pipe
/// register image directly).
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn publish_layout_for_test(layout: Option<Layout>) {
    *LAYOUT.lock() = layout;
}

/// The owner's Pipe-A primary tiling read from `PLANE_CTL` (the KMS owner
/// may have flipped it to X or Tile4 since the last transition).
fn panel_tiling(io: &(impl MmioWindow + ?Sized)) -> Result<Tiling, PipeEnableError> {
    match read(io, Pipe::A.base() + PLANE_PRIMARY_OFFSET + PLANE_CTL_OFFSET)? & PLANE_CTL_TILED_MASK
    {
        0 => Ok(Tiling::Linear),
        PLANE_CTL_TILED_X => Ok(Tiling::X),
        PLANE_CTL_TILED_4 => Ok(Tiling::Tile4),
        _ => Err(PipeEnableError::Resource(ResourceError::Diverged)),
    }
}

/// Owner of the programmed display14 resource state across pipe adds and
/// removals. `lit` tracks the pipes this owner treats as lit.
#[derive(Clone, Debug)]
pub(crate) struct Pipes {
    // Keep route, choice and cloned-owner values small while nested planners
    // use their scratch space on the 64 KiB ARM bootstrap stack.
    state: Option<Box<State>>,
    lit: u8,
    reserved: [Option<ExternalPipe>; 4],
}

impl Pipes {
    /// Adopt an already programmed state with the `lit` pipes on. `None`
    /// means nothing is programmed that a lit pipe depends on (every pipe
    /// off): the next reservation is the all-off commit.
    pub(crate) fn adopt(state: Option<State>, lit: u8) -> Self {
        Self {
            state: state.map(Box::new),
            lit,
            reserved: [None; 4],
        }
    }

    /// Adopt the state of the owned Pipe-A modeset for `mode`, proving it
    /// is what the hardware holds. The primary's tiling is the one Pipe A
    /// scans out (the KMS owner may have flipped to X or Tile4).
    pub(crate) fn adopt_panel(
        io: &(impl MmioWindow + ?Sized),
        mode: &Mode,
    ) -> Result<Self, PipeEnableError> {
        crate::intel_gpu_display_resources::Profile::capture(io, mode)
            .map_err(|_| PipeEnableError::Resource(ResourceError::Diverged))?;
        // Only the owned single-pipe layout is adopted: one external route
        // runs at a time, so a lit Pipe B–D here is not this owner's.
        for pipe in [Pipe::B, Pipe::C, Pipe::D] {
            if read(io, pipe.base() + PIPECONF_OFFSET)? & (PIPECONF_ENABLE | PIPECONF_STATE) != 0 {
                return Err(PipeEnableError::Resource(ResourceError::Diverged));
            }
        }
        let tiling = panel_tiling(io)?;
        // A compressing panel keeps its VDSC term (read back from Pipe A).
        let dsc = crate::intel_gpu_display_resources::pipe_a_dsc(io, mode)
            .map_err(|_| PipeEnableError::Resource(ResourceError::NoDevice))?;
        let state = Self::compute(
            io,
            &crate::intel_gpu_display_resources::request_dsc(mode, tiling, 0, dsc),
        )?;
        let lit = read(io, Pipe::A.base() + PIPECONF_OFFSET)? & (PIPECONF_ENABLE | PIPECONF_STATE)
            == PIPECONF_ENABLE | PIPECONF_STATE;
        Ok(Self::adopt(Some(state), u8::from(lit)))
    }

    /// Publish what this owner holds programmed for the Pipe-A KMS proofs:
    /// the layout while any Pipe B–D is part of it, nothing otherwise.
    fn publish(&self) {
        let layout = self
            .state
            .as_deref()
            .filter(|s| s.requests[1..].iter().any(Option::is_some));
        *LAYOUT.lock() = layout.map(|state| Layout {
            state: *state,
            surfaces: core::array::from_fn(|p| self.reserved[p].map(|ext| ext.surface)),
        });
    }

    /// Pipe A belongs to the panel's KMS owner, which turns it off and on
    /// without this owner (`intel_gpu_modeset_xelpg::XeLpgModeset::panel_off`
    /// and its panel-on modeset): its lit bit follows the hardware whenever
    /// the programmed state carries the panel's request. A dark Pipe A keeps
    /// its share of the layout (its planes are off), as a reserved pipe that
    /// is not yet enabled does.
    fn sync_panel(&mut self, io: &(impl MmioWindow + ?Sized)) -> Result<(), PipeEnableError> {
        if self.state.as_ref().is_none_or(|s| s.requests[0].is_none()) {
            return Ok(());
        }
        let conf = read(io, Pipe::A.base() + PIPECONF_OFFSET)?;
        if conf & (PIPECONF_ENABLE | PIPECONF_STATE) == PIPECONF_ENABLE | PIPECONF_STATE {
            self.lit |= 1;
        } else {
            self.lit &= !1;
        }
        Ok(())
    }

    /// Before computing a transition from the programmed state: a lit Pipe
    /// A keeps the primary watermarks of whatever tiling the KMS owner
    /// flipped it to, so the programmed state is retiled to that tiling
    /// (only its primary watermarks change; see [`State::retile`]).
    fn refresh_panel(&mut self, io: &(impl MmioWindow + ?Sized)) -> Result<(), PipeEnableError> {
        let Some(state) = self.state.as_deref() else {
            return Ok(());
        };
        if self.lit & 1 == 0 || state.requests[0].is_none() {
            return Ok(());
        }
        let tiling = panel_tiling(io)?;
        let latency =
            crate::intel_gpu_xelpg_wm::Latency::read(io).map_err(|_| PipeEnableError::NoDevice)?;
        self.state = Some(Box::new((*state).retile(0, tiling, &latency)?));
        Ok(())
    }

    /// The programmed state (`None`: nothing a lit pipe depends on).
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn state(&self) -> Option<&State> {
        self.state.as_deref()
    }

    fn transition(
        &mut self,
        io: &(impl MmioWindow + ?Sized),
        new: State,
    ) -> Result<(), PipeEnableError> {
        // Allocate before programming; an uncertain transaction keeps the old
        // snapshot, and successful ownership transfer needs no later allocation.
        let new = Box::new(new);
        match (&self.state, self.lit) {
            (Some(old), lit) if lit != 0 => {
                crate::intel_gpu_xelpg_live::commit_live(io, old, &new, lit)?
            }
            _ => res::commit(io, &new)?,
        }
        self.state = Some(new);
        Ok(())
    }

    fn request_with(&self, change: impl FnOnce(&mut res::Request)) -> res::Request {
        let mut request = res::Request {
            pipes: self.state.as_deref().map_or([None; 4], |s| s.requests),
            min_cdclk_khz: 0,
        };
        change(&mut request);
        request
    }

    /// `request` computed as the KMS owner programs Pipe A: everything from
    /// the linear baseline of its primary (the owned modeset's layout),
    /// then that primary retiled to the tiling it actually scans out.
    fn compute(
        io: &(impl MmioWindow + ?Sized),
        request: &res::Request,
    ) -> Result<State, PipeEnableError> {
        let latency =
            crate::intel_gpu_xelpg_wm::Latency::read(io).map_err(|_| PipeEnableError::NoDevice)?;
        let mut baseline = *request;
        let primary = baseline.pipes[0]
            .as_mut()
            .and_then(|p| p.planes[0].as_mut());
        let tiling = primary.as_ref().map(|p| p.tiling);
        if let Some(plane) = primary {
            plane.tiling = Tiling::Linear;
        }
        let state = res::compute(&baseline, &latency)?;
        match tiling {
            Some(tiling) => Ok(state.retile(0, tiling, &latency)?),
            None => Ok(state),
        }
    }

    /// [`Self::reserve`]'s refusals and computed state, without a write.
    fn check(
        &self,
        io: &(impl MmioWindow + ?Sized),
        ext: &ExternalPipe,
    ) -> Result<State, PipeEnableError> {
        let p = ext.pipe as usize;
        if ext.pipe == Pipe::A
            || ext.surface & 0xfff != 0
            || ext.stride_bytes % 64 != 0
            || u32::from(ext.mode.h_active) * 4 > ext.stride_bytes
            || build_transcoder(&timing(&ext.mode)).is_err()
        {
            return Err(PipeEnableError::Unsupported);
        }
        if self.reserved[p].is_some()
            || self.state.as_ref().is_some_and(|s| s.requests[p].is_some())
        {
            return Err(PipeEnableError::NotReserved);
        }
        let mut fresh = self.clone();
        fresh.sync_panel(io)?;
        fresh.refresh_panel(io)?;
        if read(io, ext.pipe.base() + PIPECONF_OFFSET)? & (PIPECONF_ENABLE | PIPECONF_STATE) != 0 {
            return Err(PipeEnableError::Busy);
        }
        // The transaction's hardware precondition: the lit pipes are lit
        // and every other pipe, plane, cursor, DSB and FBC is idle.
        if fresh.lit != 0 {
            crate::intel_gpu_xelpg_live::check_pipes(io, fresh.lit)?;
        } else {
            res::require_idle(io)?;
        }
        Self::compute(io, &fresh.request_with(|r| r.pipes[p] = Some(request(ext))))
    }

    /// Step 0: admission. Every refusal [`Self::reserve`] can make from the
    /// request alone (qualified profile, an occupied pipe, WM/DDB/CDCLK/
    /// bandwidth), with reads only; the transaction's own hardware
    /// preconditions are checked again before its first write.
    pub(crate) fn admit(
        &self,
        io: &(impl MmioWindow + ?Sized),
        ext: &ExternalPipe,
    ) -> Result<(), PipeEnableError> {
        self.check(io, ext).map(|_| ())
    }

    /// Step 1: the pre-plane update for `ext` with the pipe off, then the
    /// first step of its crtc enable (`intel_dmc_enable_pipe`).
    pub(crate) fn reserve(
        &mut self,
        io: &(impl MmioWindow + ?Sized),
        ext: &ExternalPipe,
        dmc: &dyn PipeDmc,
    ) -> Result<(), PipeEnableError> {
        let new = self.check(io, ext)?;
        self.sync_panel(io)?;
        self.refresh_panel(io)?;
        self.transition(io, new)?;
        let p = ext.pipe as usize;
        self.reserved[p] = Some(*ext);
        self.publish();
        dmc.enable_pipe(p as u32);
        Ok(())
    }

    fn reserved(&self, pipe: Pipe) -> Result<ExternalPipe, PipeEnableError> {
        if pipe == Pipe::A {
            return Err(PipeEnableError::Unsupported);
        }
        self.reserved[pipe as usize].ok_or(PipeEnableError::NotReserved)
    }

    /// Step 3, pipe off, in `hsw_crtc_enable` order for display 14: pipe
    /// source size and `PIPE_MISC`; the transcoder (set-context latency 0,
    /// vsync shift 0, timings, `TRANS_VRR_CTL` 0 without VRR,
    /// `TRANS_MULT` 0, frame-start delay 0 in `CHICKEN_TRANS`, and
    /// `TRANSCONF` configured progressive and still disabled); the owned
    /// RGB bypass, the line-time watermark and the pipe chicken bits; then
    /// the no-DPT plane chicken (`intel_pre_update_crtc`).
    pub(crate) fn program_timings(
        &self,
        io: &(impl MmioWindow + ?Sized),
        pipe: Pipe,
    ) -> Result<(), PipeEnableError> {
        let ext = self.reserved(pipe)?;
        if self.lit & (1 << pipe as usize) != 0 {
            return Err(PipeEnableError::Busy);
        }
        let t = timing(&ext.mode);
        let trans = build_transcoder(&t).map_err(|_| PipeEnableError::Unsupported)?;
        let src = build_pipe(&t).map_err(|_| PipeEnableError::Unsupported)?;
        let linetime = crate::intel_gpu_xelpg_wm::linetime(res_timing(&ext))
            .map_err(|_| PipeEnableError::Unsupported)?;
        // intel_set_pipe_src_size, bdw_set_pipe_misc.
        checked(io, pipe.trans_base() + PIPE_SRCSZ_OFFSET, src.srcsz)?;
        checked(
            io,
            pipe.base() + PIPE_MISC_OFFSET,
            crate::intel_gpu_xelpg_dsc::pipe_misc(ext.pipe_bpp) | (1 << 23),
        )?;
        // hsw_configure_cpu_transcoder (the DP M/N precede it here):
        // intel_set_transcoder_timings, intel_vrr_set_transcoder_timings,
        // TRANS_MULT, hsw_set_frame_start_delay, hsw_set_transconf.
        let base = pipe.transcoder().base();
        // intel_set_transcoder_timings: the set-context-latency is
        // the VRR-TG value (1 while the TG runs on this CRTC's
        // pipe, 0 otherwise — wa_14015401596 floor), not a
        // hardcoded 0; the VRR guardband is computed against it.
        checked(
            io,
            base + TRANS_SET_CONTEXT_LATENCY_OFFSET,
            crate::intel_gpu_vrr::set_context_latency_for_crtc(pipe as u32 + 1),
        )?;
        checked(io, base + TRANS_VSYNCSHIFT_OFFSET, 0)?;
        for (off, v) in [
            (TRANS_HTOTAL_OFFSET, trans.htotal),
            (TRANS_HBLANK_OFFSET, trans.hblank),
            (TRANS_HSYNC_OFFSET, trans.hsync),
            (TRANS_VTOTAL_OFFSET, trans.vtotal),
            // Display 13+ clears VBLANK_START (intel_set_transcoder_timings).
            (TRANS_VBLANK_OFFSET, trans.vblank_display13()),
            (TRANS_VSYNC_OFFSET, trans.vsync),
        ] {
            checked(io, base + off, v)?;
        }
        checked(io, base + TRANS_VRR_CTL_OFFSET, 0)?;
        checked(io, base + TRANS_MULT_OFFSET, 0)?;
        let chicken = read(io, base + CHICKEN_TRANS_OFFSET)?;
        checked(
            io,
            base + CHICKEN_TRANS_OFFSET,
            chicken & !FRAME_START_DELAY_MASK,
        )?;
        checked(io, pipe.base() + PIPECONF_OFFSET, 0)?;
        // intel_color_modeset (the owned RGB bypass), hsw_set_linetime_wm,
        // icl_set_pipe_chicken.
        crate::intel_gpu_color::initialize_pipe_rgb_bypass(io, pipe).map_err(|e| match e {
            narf_filesystem::FsError::Busy => PipeEnableError::Busy,
            _ => PipeEnableError::NoDevice,
        })?;
        checked(io, wm_linetime(pipe), linetime)?;
        let chicken = read(io, pipe.base() + PIPE_CHICKEN_OFFSET)?;
        checked(
            io,
            pipe.base() + PIPE_CHICKEN_OFFSET,
            chicken | PIPE_CHICKEN_BITS,
        )?;
        // intel_dpt_configure (display 14) for every universal plane: this
        // driver scans out of the GGTT, never through a DPT.
        for plane in 0..PLANES as u64 {
            let r = pipe.base() + PLANE_PRIMARY_OFFSET + plane * 0x100 + PLANE_CHICKEN_OFFSET;
            let v = read(io, r)?;
            checked(io, r, v | PLANE_CHICKEN_DISABLE_DPT)?;
        }
        Ok(())
    }

    /// Step 4: `intel_enable_transcoder` (with its display-14
    /// `CHICKEN_TRANS` workaround bits). The caller has enabled its port
    /// and `TRANS_DDI_FUNC_CTL`. From the `TRANSCONF` write on, the pipe
    /// counts as lit for every later transaction.
    pub(crate) fn enable(
        &mut self,
        io: &(impl MmioWindow + ?Sized),
        pipe: Pipe,
    ) -> Result<(), PipeEnableError> {
        self.reserved(pipe)?;
        let bit = 1 << pipe as usize;
        if self.lit & bit != 0 {
            return Err(PipeEnableError::Busy);
        }
        // intel_enable_transcoder, display 14: CHICKEN_TRANS clears
        // DP_DSC_INSERT_SF_AT_EOL_WA and sets DP_FEC_BS_JITTER_WA first.
        let chicken = pipe.transcoder().base() + CHICKEN_TRANS_OFFSET;
        let v = read(io, chicken)?;
        checked(
            io,
            chicken,
            (v & !DP_DSC_INSERT_SF_AT_EOL_WA) | DP_FEC_BS_JITTER_WA,
        )?;
        let conf = pipe.base() + PIPECONF_OFFSET;
        let old = read(io, conf)?;
        io.write32(conf, (old & !PIPECONF_STATE) | PIPECONF_ENABLE);
        self.lit |= bit;
        wait_conf(io, pipe, true)
    }

    /// Step 5: `intel_update_crtc` for the primary of an enabled pipe.
    pub(crate) fn arm_primary(
        &self,
        io: &(impl MmioWindow + ?Sized),
        pipe: Pipe,
    ) -> Result<(), PipeEnableError> {
        let ext = self.reserved(pipe)?;
        if self.lit & (1 << pipe as usize) == 0 {
            return Err(PipeEnableError::NotLit);
        }
        let plane = build_primary_plane(
            ext.mode.h_active,
            ext.mode.v_active,
            ext.stride_bytes,
            ext.surface,
            PixelFormat::Argb8888,
        )
        .map_err(|_| PipeEnableError::Unsupported)?;
        let base = pipe.base() + PLANE_PRIMARY_OFFSET;
        // icl_plane_update_noarm.
        for (off, v) in [
            (PLANE_STRIDE_OFFSET, plane.plane_stride),
            (PLANE_POS_OFFSET, 0),
            (PLANE_SIZE_OFFSET, plane.plane_size),
            (PLANE_OFFSET_OFFSET, plane.plane_offset),
        ] {
            checked(io, base + off, v)?;
        }
        // icl_plane_update_arm inside intel_pipe_update_start/_end.
        let frame_reg = pipe.base() + FRMCOUNT_OFFSET;
        let frame =
            crate::intel_gpu_xelpg_live::evade_then(io, pipe as usize, &request(&ext), || {
                let frame = read(io, frame_reg)?;
                io.write32(base + PLANE_CTL_OFFSET, plane.plane_ctl);
                io.write32(base + PLANE_SURF_OFFSET, plane.plane_surf);
                Ok::<u32, ResourceError>(frame)
            })??;
        if read(io, base + PLANE_CTL_OFFSET)? != plane.plane_ctl {
            return Err(PipeEnableError::Resource(ResourceError::Readback));
        }
        poll(io, TRANSCONF_WAIT_MS, || {
            let now = io.read32(frame_reg);
            let live = io.read32(base + PLANE_SURFLIVE_OFFSET);
            (now != u32::MAX && live != u32::MAX && io.display_access_ok())
                .then_some(now != frame && live == plane.plane_surf)
        })
    }

    /// Step 6a: `intel_crtc_disable_planes` — the primary off, latched by
    /// its `PLANE_SURF` write.
    pub(crate) fn disable_primary(
        &self,
        io: &(impl MmioWindow + ?Sized),
        pipe: Pipe,
    ) -> Result<(), PipeEnableError> {
        self.reserved(pipe)?;
        let base = pipe.base() + PLANE_PRIMARY_OFFSET;
        let ctl = read(io, base + PLANE_CTL_OFFSET)?;
        checked(io, base + PLANE_CTL_OFFSET, ctl & !PLANE_CTL_ENABLE)?;
        let surf = read(io, base + PLANE_SURF_OFFSET)?;
        io.write32(base + PLANE_SURF_OFFSET, surf);
        Ok(())
    }

    /// Step 6b: `intel_disable_transcoder` with its STATE ack.
    pub(crate) fn disable(
        &mut self,
        io: &(impl MmioWindow + ?Sized),
        pipe: Pipe,
    ) -> Result<(), PipeEnableError> {
        self.reserved(pipe)?;
        let conf = pipe.base() + PIPECONF_OFFSET;
        let old = read(io, conf)?;
        io.write32(conf, old & !(PIPECONF_ENABLE | PIPECONF_STATE));
        wait_conf(io, pipe, false)?;
        self.lit &= !(1 << pipe as usize);
        Ok(())
    }

    /// Step 6c: after the caller stopped its port and PLL, the last step of
    /// the crtc disable (`intel_dmc_disable_pipe`), then the post-plane
    /// repartition without the pipe while the remaining lit pipes stay
    /// lit. Releasing the last programmed pipe forgets the state instead
    /// and, with every pipe off, runs the all-off post-plane steps
    /// ([`res::settle_all_off`]: WM/DDB cleared, DBUF to S1, CDCLK and PM
    /// demand lowered, as Linux's post-plane update does); the next
    /// reservation is the all-off commit.
    pub(crate) fn release(
        &mut self,
        io: &(impl MmioWindow + ?Sized),
        pipe: Pipe,
        dmc: &dyn PipeDmc,
    ) -> Result<(), PipeEnableError> {
        self.reserved(pipe)?;
        let p = pipe as usize;
        if self.lit & (1 << p) != 0 {
            return Err(PipeEnableError::Busy);
        }
        self.sync_panel(io)?;
        self.refresh_panel(io)?;
        dmc.disable_pipe(p as u32);
        let request = self.request_with(|r| r.pipes[p] = None);
        if request.pipes.iter().all(Option::is_none) {
            // Every pipe is off: the post-plane steps of that commit lower
            // DBUF, CDCLK and PM demand to the all-off minimum. Best effort:
            // a refusal or failure leaves them raised (never under-covered,
            // see settle_all_off) and the next reservation is the all-off
            // commit either way.
            self.state = None;
            if let Ok(latency) = crate::intel_gpu_xelpg_wm::Latency::read(io) {
                let _ = res::settle_all_off(io, &latency);
            }
        } else {
            let new = Self::compute(io, &request)?;
            self.transition(io, new)?;
        }
        self.reserved[p] = None;
        self.publish();
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_pipes_tests.rs"]
mod tests;
