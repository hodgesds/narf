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
//!    `intel_set_transcoder_timings`, `intel_color_modeset` (the owned RGB
//!    bypass) and the display-14 no-DPT plane chicken
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

/// Owner of the programmed display14 resource state across pipe adds and
/// removals. `lit` tracks the pipes this owner treats as lit.
#[derive(Clone, Debug)]
pub(crate) struct Pipes {
    state: Option<State>,
    lit: u8,
    reserved: [Option<ExternalPipe>; 4],
}

impl Pipes {
    /// Adopt an already programmed state with the `lit` pipes on. `None`
    /// means nothing is programmed that a lit pipe depends on (every pipe
    /// off): the next reservation is the all-off commit.
    pub(crate) fn adopt(state: Option<State>, lit: u8) -> Self {
        Self {
            state,
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
        let tiling = match read(io, Pipe::A.base() + PLANE_PRIMARY_OFFSET + PLANE_CTL_OFFSET)?
            & PLANE_CTL_TILED_MASK
        {
            0 => Tiling::Linear,
            PLANE_CTL_TILED_X => Tiling::X,
            PLANE_CTL_TILED_4 => Tiling::Tile4,
            _ => return Err(PipeEnableError::Resource(ResourceError::Diverged)),
        };
        let latency =
            crate::intel_gpu_xelpg_wm::Latency::read(io).map_err(|_| PipeEnableError::NoDevice)?;
        let state = res::compute(
            &crate::intel_gpu_display_resources::request(mode, tiling, 0),
            &latency,
        )?;
        let lit = read(io, Pipe::A.base() + PIPECONF_OFFSET)? & (PIPECONF_ENABLE | PIPECONF_STATE)
            == PIPECONF_ENABLE | PIPECONF_STATE;
        Ok(Self::adopt(Some(state), u8::from(lit)))
    }

    /// The programmed state (`None`: nothing a lit pipe depends on).
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn state(&self) -> Option<&State> {
        self.state.as_ref()
    }

    fn transition(
        &mut self,
        io: &(impl MmioWindow + ?Sized),
        new: State,
    ) -> Result<(), PipeEnableError> {
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
            pipes: self.state.map_or([None; 4], |s| s.requests),
            min_cdclk_khz: 0,
        };
        change(&mut request);
        request
    }

    fn compute(
        io: &(impl MmioWindow + ?Sized),
        request: &res::Request,
    ) -> Result<State, PipeEnableError> {
        let latency =
            crate::intel_gpu_xelpg_wm::Latency::read(io).map_err(|_| PipeEnableError::NoDevice)?;
        Ok(res::compute(request, &latency)?)
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
        if self.reserved[p].is_some() || self.state.is_some_and(|s| s.requests[p].is_some()) {
            return Err(PipeEnableError::NotReserved);
        }
        if read(io, ext.pipe.base() + PIPECONF_OFFSET)? & (PIPECONF_ENABLE | PIPECONF_STATE) != 0 {
            return Err(PipeEnableError::Busy);
        }
        // The transaction's hardware precondition: the lit pipes are lit
        // and every other pipe, plane, cursor, DSB and FBC is idle.
        if self.lit != 0 {
            crate::intel_gpu_xelpg_live::check_pipes(io, self.lit)?;
        } else {
            res::require_idle(io)?;
        }
        Self::compute(io, &self.request_with(|r| r.pipes[p] = Some(request(ext))))
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
        self.transition(io, new)?;
        let p = ext.pipe as usize;
        self.reserved[p] = Some(*ext);
        dmc.enable_pipe(p as u32);
        Ok(())
    }

    fn reserved(&self, pipe: Pipe) -> Result<ExternalPipe, PipeEnableError> {
        if pipe == Pipe::A {
            return Err(PipeEnableError::Unsupported);
        }
        self.reserved[pipe as usize].ok_or(PipeEnableError::NotReserved)
    }

    /// Step 3: pipe source size, transcoder timings, the owned RGB bypass
    /// and the no-DPT plane chicken, pipe off.
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
        checked(io, pipe.trans_base() + PIPE_SRCSZ_OFFSET, src.srcsz)?;
        let base = pipe.transcoder().base();
        for (off, v) in [
            (TRANS_HTOTAL_OFFSET, trans.htotal),
            (TRANS_HBLANK_OFFSET, trans.hblank),
            (TRANS_HSYNC_OFFSET, trans.hsync),
            (TRANS_VTOTAL_OFFSET, trans.vtotal),
            (TRANS_VBLANK_OFFSET, trans.vblank),
            (TRANS_VSYNC_OFFSET, trans.vsync),
        ] {
            checked(io, base + off, v)?;
        }
        crate::intel_gpu_color::initialize_pipe_rgb_bypass(io, pipe).map_err(|e| match e {
            narf_filesystem::FsError::Busy => PipeEnableError::Busy,
            _ => PipeEnableError::NoDevice,
        })?;
        // intel_dpt_configure (display 14) for every universal plane: this
        // driver scans out of the GGTT, never through a DPT.
        for plane in 0..PLANES as u64 {
            let r = pipe.base() + PLANE_PRIMARY_OFFSET + plane * 0x100 + PLANE_CHICKEN_OFFSET;
            let v = read(io, r)?;
            checked(io, r, v | PLANE_CHICKEN_DISABLE_DPT)?;
        }
        Ok(())
    }

    /// Step 4: `intel_enable_transcoder`. The caller has enabled its port
    /// and `TRANS_DDI_FUNC_CTL`. From the write on, the pipe counts as lit
    /// for every later transaction.
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
    /// lit. Releasing the last programmed pipe forgets the state instead:
    /// every pipe is off, nothing fetches, and the next reservation is the
    /// all-off commit (Linux's post-plane update would also lower CDCLK and
    /// PM demand here; this owner leaves them raised until then).
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
        dmc.disable_pipe(p as u32);
        let request = self.request_with(|r| r.pipes[p] = None);
        if request.pipes.iter().all(Option::is_none) {
            self.state = None;
        } else {
            let new = Self::compute(io, &request)?;
            self.transition(io, new)?;
        }
        self.reserved[p] = None;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_pipes_tests.rs"]
mod tests;
