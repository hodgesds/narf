//! Display-14.00 Pipe B–D enable contract for the external-output owner.
//!
//! The owned Pipe-A fixed-mode path is unchanged; this owner adds and
//! removes Pipes B–D around it. Sequence (MIT Linux b90c984d
//! `intel_display.c::hsw_crtc_enable` / `hsw_crtc_disable`,
//! `intel_set_transcoder_timings`, `intel_set_pipe_src_size`,
//! `intel_enable_transcoder` / `intel_disable_transcoder`, plane arm via
//! `PLANE_SURF`), with resources from
//! [`crate::intel_gpu_xelpg_live`]:
//!
//! 1. [`Pipes::reserve`] — DBUF/DDB/WM/CDCLK/PM demand for the new pipe
//!    while every lit pipe stays lit (all-off commit when none is lit).
//! 2. [`Pipes::program_timings`] — transcoder timings and pipe source size
//!    with the pipe off.
//! 3. The caller (port owner) programs its port clock, PHY,
//!    `TRANS_DDI_FUNC_CTL`, `DP_TP_CTL`, M/N and trains the link.
//! 4. [`Pipes::enable`] — `TRANSCONF` enable with its STATE ACK, then the
//!    primary plane armed by `PLANE_SURF` and proved by a fresh frame and
//!    `PLANE_SURFLIVE`.
//! 5. [`Pipes::disable`] — plane off, `TRANSCONF` off with its STATE ACK;
//!    the caller then stops its port, and [`Pipes::release`] repartitions
//!    the resources without the pipe.
//!
//! Only linear XRGB8888 full-pipe primaries, unscaled, are admitted.
//!
//! The external-output (port/PHY) owner is the production caller; until it
//! lands, only native fixtures exercise this entry.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_modeset::Mode;
use crate::intel_gpu_pipes::{
    build_pipe, build_primary_plane, build_transcoder, DisplayTiming, Pipe, PixelFormat,
    PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE, PIPE_SRCSZ_OFFSET, PLANE_CTL_ENABLE,
    PLANE_CTL_OFFSET, PLANE_OFFSET_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_SIZE_OFFSET,
    PLANE_STRIDE_OFFSET, PLANE_SURF_OFFSET, TRANS_HBLANK_OFFSET, TRANS_HSYNC_OFFSET,
    TRANS_HTOTAL_OFFSET, TRANS_VBLANK_OFFSET, TRANS_VSYNC_OFFSET, TRANS_VTOTAL_OFFSET,
};
use crate::intel_gpu_xelpg_resources::{
    self as res, checked, read, PipeRequest, PlaneRequest, ResourceError, State, PLANES,
};
use crate::intel_gpu_xelpg_wm::Tiling;

/// One external pipe the port owner wants lit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExternalPipe {
    /// B, C or D.
    pub(crate) pipe: Pipe,
    pub(crate) mode: Mode,
    /// GGTT address of a 4 KiB-aligned linear XRGB8888 surface.
    pub(crate) surface: u32,
    pub(crate) stride_bytes: u32,
    /// Highest port clock the owner will run while the pipe is lit.
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

fn wait_conf(io: &(impl MmioWindow + ?Sized), pipe: Pipe, on: bool) -> Result<(), PipeEnableError> {
    res::wait(
        io,
        pipe.base() + PIPECONF_OFFSET,
        PIPECONF_STATE,
        if on { PIPECONF_STATE } else { 0 },
    )
    .map_err(|e| match e {
        ResourceError::Timeout => PipeEnableError::Timeout,
        _ => PipeEnableError::NoDevice,
    })
}

/// Owner of the programmed display14 resource state across pipe adds and
/// removals. `lit` tracks the pipes this owner treats as lit.
#[derive(Debug)]
pub(crate) struct Pipes {
    state: Option<State>,
    lit: u8,
    reserved: [Option<ExternalPipe>; 4],
}

impl Pipes {
    /// Adopt an already programmed state with the `lit` pipes on. `None`
    /// means nothing is programmed yet (every pipe off).
    pub(crate) fn adopt(state: Option<State>, lit: u8) -> Self {
        Self {
            state,
            lit,
            reserved: [None; 4],
        }
    }

    /// Adopt the state of the owned Pipe-A modeset for `mode`, proving it
    /// is what the hardware holds.
    pub(crate) fn adopt_panel(
        io: &(impl MmioWindow + ?Sized),
        mode: &Mode,
    ) -> Result<Self, PipeEnableError> {
        crate::intel_gpu_display_resources::Profile::capture(io, mode)
            .map_err(|_| PipeEnableError::Resource(ResourceError::Diverged))?;
        let latency =
            crate::intel_gpu_xelpg_wm::Latency::read(io).map_err(|_| PipeEnableError::NoDevice)?;
        let state = res::compute(
            &crate::intel_gpu_display_resources::request(mode, Tiling::Linear, 0),
            &latency,
        )?;
        let lit = read(io, Pipe::A.base() + PIPECONF_OFFSET)? & (PIPECONF_ENABLE | PIPECONF_STATE)
            == PIPECONF_ENABLE | PIPECONF_STATE;
        Ok(Self::adopt(Some(state), u8::from(lit)))
    }

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

    fn compute(
        &self,
        io: &(impl MmioWindow + ?Sized),
        change: impl FnOnce(&mut res::Request),
    ) -> Result<State, PipeEnableError> {
        let mut request = res::Request {
            pipes: self.state.map_or([None; 4], |s| s.requests),
            min_cdclk_khz: 0,
        };
        change(&mut request);
        let latency =
            crate::intel_gpu_xelpg_wm::Latency::read(io).map_err(|_| PipeEnableError::NoDevice)?;
        Ok(res::compute(&request, &latency)?)
    }

    /// Step 1: reserve display resources for `ext` with the pipe off.
    pub(crate) fn reserve(
        &mut self,
        io: &(impl MmioWindow + ?Sized),
        ext: &ExternalPipe,
    ) -> Result<(), PipeEnableError> {
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
        let new = self.compute(io, |r| r.pipes[p] = Some(request(ext)))?;
        self.transition(io, new)?;
        self.reserved[p] = Some(*ext);
        Ok(())
    }

    fn reserved(&self, pipe: Pipe) -> Result<ExternalPipe, PipeEnableError> {
        if pipe == Pipe::A {
            return Err(PipeEnableError::Unsupported);
        }
        self.reserved[pipe as usize].ok_or(PipeEnableError::NotReserved)
    }

    /// Step 2: transcoder timings and pipe source size, pipe off.
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
        checked(io, pipe.trans_base() + PIPE_SRCSZ_OFFSET, src.srcsz)?;
        Ok(())
    }

    /// Step 4: enable the transcoder, then arm the primary plane. The
    /// caller has already enabled its port and trained its link.
    pub(crate) fn enable(
        &mut self,
        io: &(impl MmioWindow + ?Sized),
        pipe: Pipe,
    ) -> Result<(), PipeEnableError> {
        let ext = self.reserved(pipe)?;
        let bit = 1 << pipe as usize;
        if self.lit & bit != 0 {
            return Err(PipeEnableError::Busy);
        }
        let plane = build_primary_plane(
            ext.mode.h_active,
            ext.mode.v_active,
            ext.stride_bytes,
            ext.surface,
            PixelFormat::Argb8888,
        )
        .map_err(|_| PipeEnableError::Unsupported)?;
        let conf = pipe.base() + PIPECONF_OFFSET;
        let old = read(io, conf)?;
        io.write32(conf, (old & !PIPECONF_STATE) | PIPECONF_ENABLE);
        wait_conf(io, pipe, true)?;
        // From here the pipe counts as lit for every later transaction.
        self.lit |= bit;
        let base = pipe.base() + PLANE_PRIMARY_OFFSET;
        for (off, v) in [
            (PLANE_STRIDE_OFFSET, plane.plane_stride),
            (PLANE_SIZE_OFFSET, plane.plane_size),
            (PLANE_OFFSET_OFFSET, plane.plane_offset),
            (PLANE_CTL_OFFSET, plane.plane_ctl),
        ] {
            checked(io, base + off, v)?;
        }
        let frame = read(io, pipe.base() + 0x40)?;
        io.write32(base + PLANE_SURF_OFFSET, plane.plane_surf);
        let mut lost = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let now = io.read32(pipe.base() + 0x40);
                let live = io.read32(base + 0x2c);
                lost = now == u32::MAX || live == u32::MAX || !io.display_access_ok();
                lost || (now != frame && live == plane.plane_surf)
            },
            narf_time::Deadline::after_ms(100),
        );
        if lost {
            return Err(PipeEnableError::NoDevice);
        }
        if !done {
            return Err(PipeEnableError::Timeout);
        }
        Ok(())
    }

    /// Step 5a: plane off, then the transcoder off.
    pub(crate) fn disable(
        &mut self,
        io: &(impl MmioWindow + ?Sized),
        pipe: Pipe,
    ) -> Result<(), PipeEnableError> {
        self.reserved(pipe)?;
        let base = pipe.base() + PLANE_PRIMARY_OFFSET;
        let ctl = read(io, base + PLANE_CTL_OFFSET)?;
        checked(io, base + PLANE_CTL_OFFSET, ctl & !PLANE_CTL_ENABLE)?;
        let surf = read(io, base + PLANE_SURF_OFFSET)?;
        io.write32(base + PLANE_SURF_OFFSET, surf);
        let conf = pipe.base() + PIPECONF_OFFSET;
        let old = read(io, conf)?;
        io.write32(conf, old & !(PIPECONF_ENABLE | PIPECONF_STATE));
        wait_conf(io, pipe, false)?;
        self.lit &= !(1 << pipe as usize);
        Ok(())
    }

    /// Step 5b: after the caller stopped its port, repartition without the
    /// pipe while the remaining lit pipes stay lit.
    pub(crate) fn release(
        &mut self,
        io: &(impl MmioWindow + ?Sized),
        pipe: Pipe,
    ) -> Result<(), PipeEnableError> {
        self.reserved(pipe)?;
        let p = pipe as usize;
        if self.lit & (1 << p) != 0 {
            return Err(PipeEnableError::Busy);
        }
        // An empty configuration is refused by the computation itself.
        let new = self.compute(io, |r| r.pipes[p] = None)?;
        self.transition(io, new)?;
        self.reserved[p] = None;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_pipes_tests.rs"]
mod tests;
