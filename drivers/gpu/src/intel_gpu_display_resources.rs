//! Display14.00 Pipe-A resource ownership on top of the display-14 resource
//! transaction ([`crate::intel_gpu_xelpg_resources`]). MIT Linux b90c984d:
//! intel_bw.c::mtl_find_qgv_points (0xffff disables SAGV), intel_pmdemand.c,
//! intel_display_power.c::gen12_dbuf_slices_config, skl_watermark.c
//! (adlp_allowed_dbufs, pipe_mbus_dbox_ctl, skl_cursor_allocation,
//! skl_crtc_allocate_plane_ddb, display-14 watermarks) and intel_cdclk.c
//! (computed CDCLK, raised or lowered with every pipe off). All
//! repartitioning occurs with every pipe/fetcher verified off. The owned
//! console keeps the joined/no-SAGV policy and budgets the 64x64 cursor
//! even while it is hidden.
//!
//! Every proof of the programmed Pipe-A watermarks (profile capture,
//! primary complete/check) publishes that image's `wm_level_disabled`
//! ([`crate::intel_gpu_xelpg_wm::publish_pipe_a`]) for PSR's
//! Wa_14015648006; a transaction about to write, a pending image and a
//! failed proof publish "unknown".
//!
//! A compressing panel (eDP DSC) adds its VDSC term to Pipe A's request:
//! `intel_vdsc_min_cdclk` and `intel_vdsc_prefill_lines`. The owned
//! modeset passes the planned term; every later proof reads it back from
//! Pipe A's engines (`intel_dsc_get_config`), so the KMS owners compute the
//! same layout the modeset programmed.
//!
//! Display 20 (Xe2_LPD, [`crate::intel_gpu_xe2lpd`]) runs the same
//! single-pipe ownership with its resource state ([`res::compute_ip`]):
//! no `PLANE_CHICKEN` no-DPT bit and no 14.00 stepping workaround. Its X and
//! Tile4 primaries are fetched through the presenter's display page table
//! and take the same tiled watermark images (skl_watermark.c has no DPT
//! term); the multi-pipe layout stays display 14.
//!
//! Display 30 (Xe3_LPD, [`crate::intel_gpu_xe3lpd`]) runs the single-pipe
//! ownership too: its vblank prefill budget is the VRR timing generator's
//! guardband ([`crate::intel_gpu_xe3lpd::vrr_guardband`]), its PM demand is
//! proved in the Xe3 layout, its CDCLK against the display-30 ceiling and
//! voltage level, and the primary image adds the level-0/SAGV auto minimum
//! allocation bit and `PLANE_MIN_BUF_CFG`.
use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_modeset::Mode,
    intel_gpu_xe2lpd::DisplayIp,
    intel_gpu_xelpg_dsc::DscTerm,
    intel_gpu_xelpg_pipes::Layout,
    intel_gpu_xelpg_resources::{self as res, ResourceError},
    intel_gpu_xelpg_wm::{self as wm, Latency, PlaneWm, Tiling},
};
use alloc::boxed::Box;
use narf_filesystem::FsError;

const REQUEST0: u64 = 0x45230;
const REQUEST1: u64 = 0x45234;
const INFLIGHT: u64 = 0x46440;
const ENABLE: u32 = 1 << 31;
const DBUFS: [u64; 4] = [0x45008, 0x44fe8, 0x44300, 0x44304];
/// Highest port clock the owned MTL DP modeset may enable before training
/// settles (HBR3, the top of its link-rate ladder).
const MAX_PORT_CLOCK_KHZ: u32 = 810_000;

fn read(io: &(impl MmioWindow + ?Sized), r: u64) -> Result<u32, FsError> {
    let v = io.read32(r);
    if v == u32::MAX {
        Err(FsError::NoDevice)
    } else {
        Ok(v)
    }
}
fn checked(io: &(impl MmioWindow + ?Sized), r: u64, v: u32) -> Result<(), FsError> {
    read(io, r)?;
    io.write32(r, v);
    if read(io, r)? == v {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}
fn wait(io: &(impl MmioWindow + ?Sized), r: u64, mask: u32, want: u32) -> Result<(), FsError> {
    let mut error = None;
    let done = narf_scheduler::responsive_spin_until(
        || match read(io, r) {
            Ok(value) => value & mask == want,
            Err(failure) => {
                error = Some(failure);
                true
            }
        },
        narf_time::Deadline::after_ms(10),
    );
    if let Some(error) = error {
        Err(error)
    } else if done {
        Ok(())
    } else {
        Err(FsError::TimedOut)
    }
}
fn idle_ip(io: &(impl MmioWindow + ?Sized), ip: DisplayIp) -> Result<(), FsError> {
    // The owner cannot reset/allocate behind FBC, DSB or a foreign cursor.
    res::require_idle_ip(io, ip).map_err(|e| match e {
        ResourceError::Busy => FsError::Unsupported,
        _ => FsError::NoDevice,
    })
}
/// The display IP this owner programs: 14.00, 20.00 or 30.00 (`None` for
/// every other GMD, which keeps the inherited layout). Display 30 is only
/// reached through the opted-in Panther Lake route.
fn display_ip(io: &(impl MmioWindow + ?Sized)) -> Result<Option<DisplayIp>, FsError> {
    let gmd = read(io, 0x510a0)?;
    Ok(DisplayIp::decode_all(gmd).ok())
}
/// The owned modeset's pipe-A configuration: one full-screen XRGB8888
/// primary, the budgeted hidden cursor and the combo PHY of DDI A/B.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn request(mode: &Mode, tiling: Tiling, min_cdclk_khz: u32) -> res::Request {
    request_dsc(mode, tiling, min_cdclk_khz, None)
}
/// The owned modeset's request (`request`) for a panel compressing with
/// `dsc`.
pub(crate) fn request_dsc(
    mode: &Mode,
    tiling: Tiling,
    min_cdclk_khz: u32,
    dsc: Option<DscTerm>,
) -> res::Request {
    let mut pipes = [None; res::PIPES];
    let mut planes = [None; res::PLANES];
    planes[0] = Some(res::PlaneRequest {
        width: mode.h_active,
        height: mode.v_active,
        cpp: 4,
        tiling,
    });
    pipes[0] = Some(res::PipeRequest {
        pixel_rate_khz: mode.pixel_clock_khz,
        hdisplay: mode.h_active,
        htotal: mode.h_total,
        vdisplay: mode.v_active,
        vtotal: mode.v_total,
        planes,
        cursor_visible: false,
        port_clock_khz: MAX_PORT_CLOCK_KHZ,
        combo_phy: Some(0),
        dsc,
        src_w: None,
        src_h: None,
        scaler: None,
        bigjoiner_slave: None,
    });
    res::Request {
        pipes,
        min_cdclk_khz,
    }
}
/// Pipe A's share of a programmed display-14 layout: the owned single-pipe
/// layout of the MTL modeset, or the multi-pipe layout the Pipe B–D owner
/// programmed around the lit panel ([`crate::intel_gpu_xelpg_pipes::Layout`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile {
    pub(crate) primary: PlaneWm,
    pub(crate) cursor: PlaneWm,
    pub(crate) cursor_start: u16,
    cursor_ddb: u32,
    /// The primary's `PLANE_BUF_CFG` in this layout.
    primary_ddb: u32,
    /// `skl_wm_check_vblank`'s `wm_level_disabled` for this layout: the
    /// same prefill the transaction's vblank check used (the primary and
    /// the always-budgeted cursor; level-0 lines survive the DDB stage).
    /// It depends only on Pipe A's own planes and timing, so every layout
    /// gives the same value for the same primary tiling.
    pub(crate) wm_level_disabled: bool,
    /// The display IP this layout was proved on.
    pub(crate) ip: DisplayIp,
}
impl Profile {
    /// Pipe A's share of `state` for `mode`: its primary ends where the
    /// always-budgeted cursor starts, both keep their level-0 watermark and
    /// both images are encodable.
    fn share(
        mode: &Mode,
        latency: &Latency,
        state: &res::State,
        dsc: Option<DscTerm>,
    ) -> Result<Self, FsError> {
        let alloc = &state.dbuf.pipes[0];
        let timing = wm::Timing {
            pixel_rate_khz: mode.pixel_clock_khz,
            htotal: u32::from(mode.h_total),
            vtotal: u32::from(mode.v_total),
            vblank_start: u32::from(mode.v_active),
        };
        let wm0 = alloc.wm[0].levels[0]
            .lines
            .max(alloc.cursor_wm.levels[0].lines);
        let wm_level_disabled = match state.ip {
            // The VRR guardband is display 30's vblank prefill budget.
            DisplayIp::Xe3Lpd => wm::wm_level_disabled_dsc_ip(
                state.ip,
                wm::Timing {
                    vblank_start: u32::from(state.vblank_start[0].unwrap_or(mode.v_active)),
                    ..timing
                },
                latency,
                wm0,
                dsc.is_some(),
            ),
            DisplayIp::Xelpdp | DisplayIp::Xe2Lpd => {
                wm::wm_level_disabled_dsc(timing, latency, wm0, dsc.is_some())
            }
        }
        .map_err(|_| FsError::Unsupported)?;
        let profile = Self {
            primary: alloc.wm[0],
            cursor: alloc.cursor_wm,
            cursor_start: alloc.cursor.start,
            cursor_ddb: alloc.cursor.reg(),
            primary_ddb: alloc.planes[0].reg(),
            wm_level_disabled,
            ip: state.ip,
        };
        if state.dbuf.active_pipes & 1 == 0
            || alloc.planes[0].size() == 0
            || alloc.planes[0].start != alloc.ddb.start
            || alloc.planes[0].end != alloc.cursor.start
            || alloc.cursor.end != alloc.ddb.end
            || alloc.planes[1..].iter().any(|p| p.size() != 0)
            || !profile.primary.levels[0].enable
            || !profile.cursor.levels[0].enable
            || res::cursor_wm_image(0, &profile.cursor).is_none()
            || res::plane_wm_image(0, 0, &profile.primary).is_none()
        {
            return Err(FsError::Unsupported);
        }
        Ok(profile)
    }
    fn valid_mode(mode: &Mode) -> Result<(), FsError> {
        if mode.pixel_clock_khz == 0
            || mode.pixel_clock_khz > 1_305_600
            || mode.h_active == 0
            || mode.h_active >= mode.h_total
            || mode.v_active == 0
            || mode.v_active >= mode.v_total
        {
            return Err(FsError::Unsupported);
        }
        Ok(())
    }
    /// The full single-pipe transaction state for this mode; WM/DDB do not
    /// depend on the CDCLK floor, only the clock/PM demand parts do.
    fn compute_state(
        io: &(impl MmioWindow + ?Sized),
        ip: DisplayIp,
        mode: &Mode,
        tiling: Tiling,
        min_cdclk_khz: u32,
        dsc: Option<DscTerm>,
    ) -> Result<(Self, Box<res::State>), FsError> {
        Self::valid_mode(mode)?;
        let latency = Latency::read(io)?;
        // Display 30 always scans out through the VRR timing generator:
        // the vblank prefill budget is its guardband.
        let mut vblank_start = [None; res::PIPES];
        if ip == DisplayIp::Xe3Lpd {
            let guardband = crate::intel_gpu_xe3lpd::vrr_guardband_for(io, mode, dsc, &latency)
                .map_err(|_| FsError::Unsupported)?;
            vblank_start[0] = Some(mode.v_total - guardband);
        }
        // Proofs nest inside external modesets on the ARM bootstrap stack.
        // Keep their large snapshots out of intermediate result values.
        let state = Box::new(
            res::compute_ip_vblank(
                ip,
                &request_dsc(mode, tiling, min_cdclk_khz, dsc),
                &latency,
                vblank_start,
            )
            .map_err(|_| FsError::Unsupported)?,
        );
        let profile = Self::share(mode, &latency, &state, dsc)?;
        // The fixed owner's single-pipe layout is the joined one, with the
        // whole DBUF behind Pipe A.
        if !state.dbuf.joined
            || state.dbuf.pipes[0].absolute
                != (crate::intel_gpu_xelpg_dbuf::Entry {
                    start: 0,
                    end: 4096,
                })
        {
            return Err(FsError::Unsupported);
        }
        Ok((profile, state))
    }
    /// The published multi-pipe layout retiled to Pipe A's `tiling`, after
    /// proving its Pipe-A request is the owned panel profile of `mode`.
    fn multi_state(
        mode: &Mode,
        tiling: Tiling,
        layout: &Layout,
        latency: &Latency,
        dsc: Option<DscTerm>,
    ) -> Result<Box<res::State>, FsError> {
        Self::valid_mode(mode)?;
        let panel = request_dsc(mode, Tiling::Linear, 0, dsc).pipes[0];
        let mut held = layout.state.requests[0];
        if let Some(plane) = held.as_mut().and_then(|p| p.planes[0].as_mut()) {
            plane.tiling = Tiling::Linear;
        }
        if held != panel || layout.state.requests[1..].iter().all(Option::is_none) {
            return Err(FsError::Unsupported);
        }
        layout
            .state
            .retile(0, tiling, latency)
            .map(Box::new)
            .map_err(|_| FsError::Unsupported)
    }
    /// Pipe A's share for `tiling` in the single (`None`) or multi-pipe
    /// layout.
    fn compute_for_layout(
        io: &(impl MmioWindow + ?Sized),
        ip: DisplayIp,
        mode: &Mode,
        tiling: Tiling,
        layout: Option<&Layout>,
        dsc: Option<DscTerm>,
    ) -> Result<Self, FsError> {
        match layout {
            None => Ok(Self::compute_state(io, ip, mode, tiling, 0, dsc)?.0),
            Some(layout) => {
                let latency = Latency::read(io)?;
                let state = Self::multi_state(mode, tiling, layout, &latency, dsc)?;
                Self::share(mode, &latency, &state, dsc)
            }
        }
    }
    pub(crate) fn cursor_registers(self, enabled: bool) -> alloc::vec::Vec<(u64, u32)> {
        let wm = if enabled {
            self.cursor
        } else {
            PlaneWm::default()
        };
        let mut regs = alloc::vec::Vec::new();
        // Encodability is part of Profile admission.
        if let Some(image) = res::cursor_wm_image(0, &wm) {
            regs.extend(image);
        }
        regs.push((res::cursor_buf_cfg(0), self.cursor_ddb));
        regs
    }
    /// Runtime cursor admission requires the exact source-owned global layout,
    /// powered slices and acknowledged no-SAGV request, not a generation flag.
    pub(crate) fn capture_timing(
        io: &(impl MmioWindow + ?Sized),
        timing: crate::intel_gpu_dsb::Timing,
    ) -> Result<Self, FsError> {
        let vsync = read(io, 0x60014).unwrap_or(0);
        let (v_sync_start, v_sync_end) = if vsync != 0 && vsync != u32::MAX {
            let start = ((vsync & 0xffff) + 1) as u16;
            let end = (((vsync >> 16) & 0xffff) + 1) as u16;
            if start <= timing.vtotal && end <= timing.vtotal && start >= timing.height {
                (start, end)
            } else {
                (timing.height + 1, timing.height + 2)
            }
        } else {
            (timing.height + 1, timing.height + 2)
        };
        let hsync = read(io, 0x60008).unwrap_or(0);
        let (h_sync_start, h_sync_end) = if hsync != 0 && hsync != u32::MAX {
            let start = ((hsync & 0xffff) + 1) as u16;
            let end = (((hsync >> 16) & 0xffff) + 1) as u16;
            if start <= timing.htotal && end <= timing.htotal && start >= timing.width {
                (start, end)
            } else {
                (timing.width + 1, timing.width + 2)
            }
        } else {
            (timing.width + 1, timing.width + 2)
        };
        let mode = Mode {
            pixel_clock_khz: timing.clock,
            h_active: timing.width,
            h_sync_start,
            h_sync_end,
            h_total: timing.htotal,
            v_active: timing.height,
            v_sync_start,
            v_sync_end,
            v_total: timing.vtotal,
            ..Mode::VESA_1024X768_60
        };
        Self::capture(io, &mode)
    }
    pub(crate) fn capture(io: &(impl MmioWindow + ?Sized), mode: &Mode) -> Result<Self, FsError> {
        let dsc = pipe_a_dsc(io, mode)?;
        let profile = Self::capture_layout(io, mode, dsc)?;
        Self::check_cdclk(io, profile.ip, mode)?;
        Ok(profile)
    }
    /// The running CDCLK covers `mode` and the acknowledged PM demand covers
    /// the clock: `ip`'s ceiling (691.2 MHz on display 30) and voltage level
    /// (`xe3lpd_calc_voltage_level` is 0); both PM demand layouts keep the
    /// voltage and CDCLK fields in place.
    fn check_cdclk(
        io: &(impl MmioWindow + ?Sized),
        ip: DisplayIp,
        mode: &Mode,
    ) -> Result<(), FsError> {
        let pll = read(io, 0x46070)?;
        let ctl = read(io, 0x46000)?;
        let squash = read(io, 0x46008)?;
        if pll & 0xc0000000 != 0xc0000000
            || ctl & (3 << 22) != 0
            || (squash & (1 << 31) != 0 && squash & (15 << 24) != 15 << 24)
        {
            return Err(FsError::Unsupported);
        }
        let actual = crate::intel_gpu_modeset_xelpg::cdclk_current_khz(io);
        if !(1..=crate::intel_gpu_xelpg_cdclk::max_cdclk_khz(ip)).contains(&actual)
            || mode.pixel_clock_khz > actual * 2
        {
            return Err(FsError::Unsupported);
        }
        let voltage = crate::intel_gpu_xelpg_cdclk::voltage_level_ip(ip, actual);
        let req0 = read(io, REQUEST0)?;
        let req1 = read(io, REQUEST1)?;
        if ((req0 >> 12) & 7) < u32::from(voltage) || ((req1 >> 20) & 2047) < actual.div_ceil(1000)
        {
            return Err(FsError::Unsupported);
        }
        Ok(())
    }
    /// The globals of whichever layout holds, with Pipe A's linear/X
    /// primary image: the owned single-pipe layout, else the published
    /// multi-pipe one (`Some`). Every proof reads the hardware; the
    /// published layout only names what to expect.
    fn capture_globals(
        io: &(impl MmioWindow + ?Sized),
        mode: &Mode,
        dsc: Option<DscTerm>,
    ) -> Result<(Self, Option<Box<Layout>>, DisplayIp), FsError> {
        let ip = display_ip(io)?.ok_or(FsError::Unsupported)?;
        match Self::capture_single(io, ip, mode, dsc) {
            Ok(profile) => return Ok((profile, None, ip)),
            Err(FsError::Unsupported) => {}
            Err(error) => return Err(error),
        }
        // Only the display-14 Pipe B–D owner publishes multi-pipe layouts.
        if ip != DisplayIp::Xelpdp {
            return Err(FsError::Unsupported);
        }
        let layout =
            crate::intel_gpu_xelpg_pipes::published_layout().ok_or(FsError::Unsupported)?;
        Ok((
            Self::capture_multi(io, mode, &layout, dsc)?,
            Some(Box::new(layout)),
            ip,
        ))
    }
    /// Display 20's MBUS throttle and DBUF minimum trackers follow the
    /// MDCLK/CDCLK ratio of the clock actually running (a caller floor may
    /// have raised it past the computed minimum), so its proof takes that
    /// known rung; it must cover the computed one. Display 14 is unchanged.
    fn running_clock(
        io: &(impl MmioWindow + ?Sized),
        state: &mut res::State,
    ) -> Result<(), FsError> {
        if state.ip.xe2_plus() {
            let current = crate::intel_gpu_xelpg_cdclk::Current::read_ip(io, state.ip)
                .map_err(|_| FsError::NoDevice)?;
            let rung = current.known.ok_or(FsError::Unsupported)?;
            if rung.cdclk_khz < state.cdclk.cdclk_khz {
                return Err(FsError::Unsupported);
            }
            state.cdclk = rung;
        }
        Ok(())
    }
    /// The PM demand, MBUS/DBOX, IPC and DBUF slice proof shared by both
    /// layouts, against `state`.
    fn check_shared_globals(
        io: &(impl MmioWindow + ?Sized),
        state: &res::State,
        mbus_ok: impl Fn(u32) -> bool,
    ) -> Result<(), FsError> {
        let req0 = read(io, REQUEST0)?;
        let req1 = read(io, REQUEST1)?;
        // Every acknowledged PM demand field covers the computed state, and
        // the QGV peak bandwidth is exactly the computed SAGV decision
        // (0xffff keeps SAGV masked).
        let held = crate::intel_gpu_pmdemand::Params::decode_for(
            crate::intel_gpu_pmdemand::Layout::for_ip(state.ip),
            req0,
            req1,
        );
        let need = state.pmdemand;
        let mbus = read(io, crate::intel_gpu_xelpg_dbuf::MBUS_CTL)? & state.mbus_ctl_mask();
        if held.qclk_gv_bw != need.qclk_gv_bw
            || held.max(&need) != held
            || read(io, 0x44468)? & (1 << 27) != 0
            || read(io, REQUEST1)? & ENABLE != 0
            || read(io, INFLIGHT)? & (1 << 26) != 0
            || !mbus_ok(mbus)
            || read(io, 0x45004)? & (1 << 3) == 0
        {
            return Err(FsError::Unsupported);
        }
        for pipe in 0..res::PIPES {
            if state.dbuf.active_pipes & (1 << pipe) != 0
                && read(io, crate::intel_gpu_xelpg_dbuf::dbox_ctl(pipe))? != state.dbox(pipe)
            {
                return Err(FsError::Unsupported);
            }
        }
        let mask = state.dbuf_ctl_mask();
        for (slice, r) in DBUFS.into_iter().enumerate() {
            let want = state.dbuf_ctl(slice, 0, state.dbuf.enabled_slices);
            let want = want | ((want >> 1) & (1 << 30));
            if read(io, r)? & mask != want & mask {
                return Err(FsError::Unsupported);
            }
        }
        Ok(())
    }
    /// The owned single-pipe layout: every other pipe off, the joined
    /// allocation and one-active-pipe PM demand of Pipe A alone.
    fn capture_single(
        io: &(impl MmioWindow + ?Sized),
        ip: DisplayIp,
        mode: &Mode,
        dsc: Option<DscTerm>,
    ) -> Result<Self, FsError> {
        // An enabled blank foreign pipe still consumes global display
        // resources, even when none of its fetchers is enabled.
        for pipe in 1..4 {
            if read(io, 0x70008 + pipe * 0x1000)? & 0xc0000000 != 0 {
                return Err(FsError::Unsupported);
            }
        }
        let (profile, mut state) = Self::compute_state(io, ip, mode, Tiling::Linear, 0, dsc)?;
        Self::running_clock(io, &mut state)?;
        // mbus_ctl_join_update selects the joined pipe when it stays lit
        // without a modeset (intel_mbus_joined_pipe) and NONE otherwise: the
        // owned modeset joins with NONE, while a live repartition that
        // re-joins around a lit Pipe A selects Pipe A. Linux's MBUS readout
        // takes only MBUS_JOIN, so either select is the joined profile.
        Self::check_shared_globals(io, &state, |mbus| {
            mbus == state.mbus_ctl_select(None) || mbus == state.mbus_ctl_select(Some(0))
        })?;
        if read(io, res::plane_buf_cfg(0, 0))? != profile.primary_ddb
            || read(io, res::cursor_buf_cfg(0))? != profile.cursor_ddb
        {
            return Err(FsError::Unsupported);
        }
        Ok(profile)
    }
    /// The multi-pipe layout the Pipe B–D owner published: its Pipe-A
    /// request is the owned panel of `mode`, every pipe outside it is off,
    /// the globals cover it, and every pipe's plane and cursor DDB is
    /// exactly its entry (so no allocation, foreign or stale, overlaps
    /// Pipe A's).
    fn capture_multi(
        io: &(impl MmioWindow + ?Sized),
        mode: &Mode,
        layout: &Layout,
        dsc: Option<DscTerm>,
    ) -> Result<Self, FsError> {
        let latency = Latency::read(io)?;
        let state = Self::multi_state(mode, Tiling::Linear, layout, &latency, dsc)?;
        let profile = Self::share(mode, &latency, &state, dsc)?;
        for pipe in 1..res::PIPES {
            if state.requests[pipe].is_none()
                && read(io, 0x70008 + pipe as u64 * 0x1000)? & 0xc0000000 != 0
            {
                return Err(FsError::Unsupported);
            }
        }
        // MBUS_JOIN and the hashing mode are the layout's; the select is
        // NONE (an all-off commit) or the formerly joined pipe the live
        // unjoin kept (mbus_ctl_join_update), which must be active here.
        let base = state.dbuf.mbus_ctl() & !(7 << 26);
        Self::check_shared_globals(io, &state, |mbus| {
            let select = (mbus >> 26) & 7;
            mbus & !(7 << 26) == base
                && (select == 7 || state.dbuf.active_pipes & (1 << select) != 0)
        })?;
        for pipe in 0..res::PIPES {
            let active = state.dbuf.active_pipes & (1 << pipe) != 0;
            let alloc = &state.dbuf.pipes[pipe];
            for plane in 0..res::PLANES {
                let want = if active { alloc.planes[plane].reg() } else { 0 };
                if read(io, res::plane_buf_cfg(pipe, plane))? != want {
                    return Err(FsError::Unsupported);
                }
            }
            let want = if active { alloc.cursor.reg() } else { 0 };
            if read(io, res::cursor_buf_cfg(pipe))? != want {
                return Err(FsError::Unsupported);
            }
        }
        Ok(profile)
    }
    /// The proved layout, published as Pipe A's programmed
    /// `wm_level_disabled`; any failure publishes "unknown".
    fn capture_layout(
        io: &(impl MmioWindow + ?Sized),
        mode: &Mode,
        dsc: Option<DscTerm>,
    ) -> Result<Self, FsError> {
        let profile = Self::capture_layout_inner(io, mode, dsc);
        wm::publish_pipe_a(profile.as_ref().ok().map(|p| p.wm_level_disabled));
        profile
    }
    fn capture_layout_inner(
        io: &(impl MmioWindow + ?Sized),
        mode: &Mode,
        dsc: Option<DscTerm>,
    ) -> Result<Self, FsError> {
        let (mut profile, layout, ip) = Self::capture_globals(io, mode, dsc)?;
        // X-tiled takes the linear watermark arithmetic on display >= 10.
        // A display-20 tiled primary is fetched through the presenter's DPT
        // (no no-DPT chicken, intel_dpt_configure); its watermarks are the
        // same tiled images.
        let tiling = match read(io, 0x70180)? & (7 << 10) {
            0 => None,
            0x400 => Some(Tiling::X),
            0x1400 => Some(Tiling::Tile4),
            _ => return Err(FsError::Unsupported),
        };
        if let Some(tiling) = tiling {
            let share = Self::compute_for_layout(io, ip, mode, tiling, layout.as_deref(), dsc)?;
            profile.primary = share.primary;
            profile.wm_level_disabled = share.wm_level_disabled;
        }
        verify_primary(io, ip, profile.primary)?;
        Ok(profile)
    }
}

/// Pipe A primary's watermark image on `ip`; display 30 adds the auto
/// minimum allocation bits and `PLANE_MIN_BUF_CFG` (`skl_write_plane_wm`).
fn primary_registers(ip: DisplayIp, wm: PlaneWm) -> Result<alloc::vec::Vec<(u64, u32)>, FsError> {
    let mut image = res::plane_wm_image_ip(ip, 0, 0, &wm)
        .ok_or(FsError::Unsupported)?
        .to_vec();
    if ip == DisplayIp::Xe3Lpd {
        image.push((
            res::plane_min_buf_cfg(0, 0),
            res::min_ddb_value(&wm).ok_or(FsError::Unsupported)?,
        ));
    }
    Ok(image)
}
fn verify_primary(
    io: &(impl MmioWindow + ?Sized),
    ip: DisplayIp,
    wm: PlaneWm,
) -> Result<(), FsError> {
    for (r, value) in primary_registers(ip, wm)? {
        if read(io, r)? != value {
            return Err(FsError::Unsupported);
        }
    }
    Ok(())
}

/// Retained primary watermark ownership. Only shadowed primary WM registers
/// vary under this owner; the acknowledged PM demand, DBUF/MBUS and cursor
/// partition change only when the Pipe B–D owner repartitions around the
/// panel (an external output added or removed), never under this owner. The
/// images are therefore derived from whichever layout is proved programmed
/// at each use. A pending image survives cancellation and partial writes
/// until a verified original console latch. Neither GT reset nor command
/// retirement alone authorizes forgetting it.
#[derive(Debug)]
pub(crate) struct Primary {
    mode: Mode,
    /// `wm_level_disabled` of the linear/X and the Tile4 image. It depends
    /// only on Pipe A's planes and timing, never on the layout.
    wm_level_disabled: [bool; 2],
    current_tile4: bool,
    pending: Option<bool>,
    /// The display IP every proof must find again.
    ip: DisplayIp,
}
impl Primary {
    /// The display-14 owner ([`Self::capture_ip`] on 14.00).
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn capture(
        io: &(impl MmioWindow + ?Sized),
        timing: crate::intel_gpu_dsb::Timing,
    ) -> Result<Self, FsError> {
        Self::capture_ip(io, timing, DisplayIp::Xelpdp)
    }
    /// Retained primary watermark ownership on `ip`. Display 14 requires
    /// the owned `PLANE_CHICKEN` no-DPT bit; display 20 has none (its tiled
    /// primary is fetched through the presenter's DPT), so nothing extra is
    /// read there. The proved layout must be `ip`'s.
    pub(crate) fn capture_ip(
        io: &(impl MmioWindow + ?Sized),
        timing: crate::intel_gpu_dsb::Timing,
        ip: DisplayIp,
    ) -> Result<Self, FsError> {
        let vsync = read(io, 0x60014).unwrap_or(0);
        let (v_sync_start, v_sync_end) = if vsync != 0 && vsync != u32::MAX {
            let start = ((vsync & 0xffff) + 1) as u16;
            let end = (((vsync >> 16) & 0xffff) + 1) as u16;
            if start <= timing.vtotal && end <= timing.vtotal && start >= timing.height {
                (start, end)
            } else {
                (timing.height + 1, timing.height + 2)
            }
        } else {
            (timing.height + 1, timing.height + 2)
        };
        let hsync = read(io, 0x60008).unwrap_or(0);
        let (h_sync_start, h_sync_end) = if hsync != 0 && hsync != u32::MAX {
            let start = ((hsync & 0xffff) + 1) as u16;
            let end = (((hsync >> 16) & 0xffff) + 1) as u16;
            if start <= timing.htotal && end <= timing.htotal && start >= timing.width {
                (start, end)
            } else {
                (timing.width + 1, timing.width + 2)
            }
        } else {
            (timing.width + 1, timing.width + 2)
        };
        let mode = Mode {
            pixel_clock_khz: timing.clock,
            h_active: timing.width,
            h_sync_start,
            h_sync_end,
            h_total: timing.htotal,
            v_active: timing.height,
            v_sync_start,
            v_sync_end,
            v_total: timing.vtotal,
            ..Mode::VESA_1024X768_60
        };
        // A fresh resource journal must begin on our verified linear/X
        // baseline, never adopt an unrelated inherited Tile4 allocation.
        if !matches!(read(io, 0x70180)? & (7 << 10), 0 | 0x400) {
            return Err(FsError::Unsupported);
        }
        if ip.has_no_dpt_chicken() && read(io, 0x7026c)? & (1 << 19) == 0 {
            return Err(FsError::Unsupported);
        }
        let original = Profile::capture(io, &mode)?;
        if original.ip != ip {
            return Err(FsError::Unsupported);
        }
        let mut primary = Self {
            mode,
            wm_level_disabled: [original.wm_level_disabled; 2],
            current_tile4: false,
            pending: None,
            ip,
        };
        let [_, tile4] = primary.images(io)?;
        primary.wm_level_disabled[1] = tile4.wm_level_disabled;
        Ok(primary)
    }
    /// Pipe A's linear/X and Tile4 shares of the layout proved programmed
    /// now (globals and CDCLK included).
    fn images(&self, io: &(impl MmioWindow + ?Sized)) -> Result<[Profile; 2], FsError> {
        let dsc = pipe_a_dsc(io, &self.mode)?;
        let (linear, layout, ip) = Profile::capture_globals(io, &self.mode, dsc)?;
        Profile::check_cdclk(io, ip, &self.mode)?;
        if ip != self.ip {
            return Err(FsError::Unsupported);
        }
        if ip.has_no_dpt_chicken() && read(io, 0x7026c)? & (1 << 19) == 0 {
            return Err(FsError::Unsupported);
        }
        let tile4 =
            Profile::compute_for_layout(io, ip, &self.mode, Tiling::Tile4, layout.as_deref(), dsc)?;
        Ok([linear, tile4])
    }
    /// `wm_level_disabled` of the linear/X (`false`) or Tile4 image.
    pub(crate) fn wm_level_disabled(&self, tile4: bool) -> bool {
        self.wm_level_disabled[usize::from(tile4)]
    }
    /// The image a staged update moves to, if one is pending.
    pub(crate) fn pending_tile4(&self) -> Option<bool> {
        self.pending
    }
    /// `wm_level_disabled` of the image programmed now; `None` while an
    /// update is pending.
    pub(crate) fn current_wm_level_disabled(&self) -> Option<bool> {
        self.pending
            .is_none()
            .then(|| self.wm_level_disabled(self.current_tile4))
    }
    /// Prove the programmed image (globals always; the primary image when no
    /// update is pending) and publish its `wm_level_disabled` (unknown
    /// while pending or on failure).
    pub(crate) fn check_current(&self, io: &(impl MmioWindow + ?Sized)) -> Result<(), FsError> {
        let result = self.check_current_inner(io);
        wm::publish_pipe_a(result.ok().and_then(|()| self.current_wm_level_disabled()));
        result
    }
    fn check_current_inner(&self, io: &(impl MmioWindow + ?Sized)) -> Result<(), FsError> {
        let images = self.images(io)?;
        if self.pending.is_none() {
            let tiling = read(io, 0x70180)? & (7 << 10);
            if if self.current_tile4 {
                tiling != 0x1400
            } else {
                !matches!(tiling, 0 | 0x400)
            } {
                return Err(FsError::Unsupported);
            }
            verify_primary(io, self.ip, images[usize::from(self.current_tile4)].primary)?;
        }
        Ok(())
    }
    pub(crate) fn stage(
        &mut self,
        io: &(impl MmioWindow + ?Sized),
        tile4: bool,
    ) -> Result<alloc::vec::Vec<(u64, u32)>, FsError> {
        if self.pending.is_some() {
            return Err(FsError::Busy);
        }
        self.check_current(io)?;
        let image = primary_registers(self.ip, self.images(io)?[usize::from(tile4)].primary)?;
        self.pending = Some(tile4);
        wm::publish_pipe_a(None);
        Ok(image)
    }
    /// A staged image was never armed: the current image stays programmed.
    pub(crate) fn rollback(&mut self) {
        self.pending = None;
        wm::publish_pipe_a(self.current_wm_level_disabled());
    }
    pub(crate) fn pending(&self) -> bool {
        self.pending.is_some()
    }
    pub(crate) fn complete(&mut self, io: &(impl MmioWindow + ?Sized)) -> Result<(), FsError> {
        let images = self.images(io)?;
        let target = self.pending.ok_or(FsError::Busy)?;
        verify_primary(io, self.ip, images[usize::from(target)].primary)?;
        self.current_tile4 = target;
        self.pending = None;
        wm::publish_pipe_a(self.current_wm_level_disabled());
        Ok(())
    }
    /// Caller has independently retired all DSB streams and holds display
    /// exclusion. These are shadow writes; only the following original
    /// console SURF latch plus readback completes restoration.
    pub(crate) fn restore(&mut self, io: &(impl MmioWindow + ?Sized)) -> Result<Profile, FsError> {
        let [original, _] = self.images(io)?;
        let image = primary_registers(self.ip, original.primary)?;
        self.pending = Some(false); // retained before the first possible write
        wm::publish_pipe_a(None);
        for (r, value) in image {
            checked(io, r, value)?;
        }
        Ok(original)
    }
}
/// None is a strict, read-only refusal before writes: older boot modes may
/// continue with inherited resources, but cannot acquire the cursor profile.
/// Once the transaction starts, failure restores every touched resource
/// register it can and always leaves the pipe off; no caller may enable it
/// or publish a cursor on a failed baseline. `min_cdclk_khz` is a caller
/// CDCLK floor (Linux `force_min_cdclk`); 0 lets the computed minimum both
/// raise and lower the clock.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn initialize(
    io: &(impl MmioWindow + ?Sized),
    mode: &Mode,
    min_cdclk_khz: u32,
) -> Result<Option<Profile>, ResourceError> {
    initialize_dsc(io, mode, min_cdclk_khz, None)
}

/// `initialize` for a panel the modeset will compress with `dsc`: the
/// transaction carries its VDSC CDCLK and prefill terms. Pipe A's engines
/// are programmed later in the modeset, so the final proof takes the
/// planned term instead of reading it back.
pub(crate) fn initialize_dsc(
    io: &(impl MmioWindow + ?Sized),
    mode: &Mode,
    min_cdclk_khz: u32,
    dsc: Option<DscTerm>,
) -> Result<Option<Profile>, ResourceError> {
    let Some(ip) = display_ip(io)? else {
        return Ok(None);
    };
    match idle_ip(io, ip) {
        Ok(()) => {}
        Err(FsError::Unsupported) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let (profile, state) =
        match Profile::compute_state(io, ip, mode, Tiling::Linear, min_cdclk_khz, dsc) {
            Ok(v) => v,
            Err(FsError::Unsupported) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
    let irq_enable = read(io, 0x4446c)?;
    let irq_mask = io.read32(0x44464); // all masked is a valid value
    if irq_enable & !irq_mask & ((1 << 3) | (1 << 27)) != 0 || read(io, 0x44468)? & (1 << 27) != 0 {
        return Ok(None);
    }
    // The programmed Pipe-A watermarks are unproved until the final
    // capture below republishes them.
    wm::publish_pipe_a(None);
    wait(io, REQUEST1, ENABLE, 0)?;
    wait(io, INFLIGHT, 1 << 26, 0)?;
    // intel_dpt_common.c::intel_dpt_configure, display14 no-DPT profile.
    // Only our primary changes, with every pipe/fetcher proved off above.
    // Display 20 programs no PLANE_CHICKEN: its tiled primaries use a DPT.
    if ip == DisplayIp::Xelpdp {
        let chicken = read(io, 0x7026c)?;
        checked(io, 0x7026c, chicken | (1 << 19))?;
        // Wa_14016740474 (intel_pmdemand_init): display14.00 A0..<C0.
        // STEP_* enumerates four substeps per letter; GMD stepping is the
        // offset.
        let gmd = read(io, 0x510a0)?;
        if gmd & 63 < 8 {
            let v = read(io, 0x46438)?;
            checked(io, 0x46438, v | (1 << 19))?;
        }
    }
    // skl_watermark_ipc_update: transition watermarks require IPC. Own its
    // enable while the pipes are off instead of inheriting firmware policy.
    let arb = read(io, 0x45004)?;
    checked(io, 0x45004, arb | (1 << 3))?;
    res::commit(io, &state)?;
    for r in [0x70080, 0x70088, 0x70084] {
        checked(io, r, 0)?;
    }
    Profile::capture_layout(io, mode, dsc)?;
    Ok(Some(profile))
}

/// Pipe A's VDSC term as its engines hold it (`intel_dsc_get_config`):
/// what every proof of an owned panel layout computes with.
pub(crate) fn pipe_a_dsc(
    io: &(impl MmioWindow + ?Sized),
    mode: &Mode,
) -> Result<Option<DscTerm>, FsError> {
    crate::intel_gpu_xelpg_dsc::read_term(io, crate::intel_gpu_pipes::Pipe::A, mode)
        .map_err(|_| FsError::NoDevice)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_display_resources_tests.rs"]
mod tests;
