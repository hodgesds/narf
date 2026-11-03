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
use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_modeset::Mode,
    intel_gpu_xelpg_resources::{self as res, ResourceError},
    intel_gpu_xelpg_wm::{self as wm, Latency, PlaneWm, Tiling},
};
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
fn idle(io: &(impl MmioWindow + ?Sized)) -> Result<(), FsError> {
    // The owner cannot reset/allocate behind FBC, DSB or a foreign cursor.
    res::require_idle(io).map_err(|e| match e {
        ResourceError::Busy => FsError::Unsupported,
        _ => FsError::NoDevice,
    })
}
fn display14(io: &(impl MmioWindow + ?Sized)) -> Result<bool, FsError> {
    let gmd = read(io, 0x510a0)?;
    Ok(gmd >> 22 == 14 && (gmd >> 14) & 255 == 0)
}
/// The owned modeset's pipe-A configuration: one full-screen XRGB8888
/// primary, the budgeted hidden cursor and the combo PHY of DDI A/B.
pub(crate) fn request(mode: &Mode, tiling: Tiling, min_cdclk_khz: u32) -> res::Request {
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
    });
    res::Request {
        pipes,
        min_cdclk_khz,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile {
    pub(crate) primary: PlaneWm,
    pub(crate) cursor: PlaneWm,
    pub(crate) cursor_start: u16,
    cursor_ddb: u32,
    /// `skl_wm_check_vblank`'s `wm_level_disabled` for this layout: the
    /// same prefill the transaction's vblank check used (the primary and
    /// the always-budgeted cursor; level-0 lines survive the DDB stage).
    pub(crate) wm_level_disabled: bool,
}
impl Profile {
    fn compute_for_layout(
        io: &(impl MmioWindow + ?Sized),
        mode: &Mode,
        tiling: Tiling,
    ) -> Result<Self, FsError> {
        Ok(Self::compute_state(io, mode, tiling, 0)?.0)
    }
    /// The full transaction state for this mode; WM/DDB do not depend on
    /// the CDCLK floor, only the clock/PM demand parts do.
    fn compute_state(
        io: &(impl MmioWindow + ?Sized),
        mode: &Mode,
        tiling: Tiling,
        min_cdclk_khz: u32,
    ) -> Result<(Self, res::State), FsError> {
        if mode.pixel_clock_khz == 0
            || mode.pixel_clock_khz > 1_305_600
            || mode.h_active == 0
            || mode.h_active >= mode.h_total
            || mode.v_active == 0
            || mode.v_active >= mode.v_total
        {
            return Err(FsError::Unsupported);
        }
        let latency = Latency::read(io)?;
        let state = res::compute(&request(mode, tiling, min_cdclk_khz), &latency)
            .map_err(|_| FsError::Unsupported)?;
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
        let profile = Self {
            primary: alloc.wm[0],
            cursor: alloc.cursor_wm,
            cursor_start: alloc.cursor.start,
            cursor_ddb: alloc.cursor.reg(),
            wm_level_disabled: wm::wm_level_disabled(timing, &latency, wm0)
                .map_err(|_| FsError::Unsupported)?,
        };
        // The fixed owner admits only the joined single-pipe layout whose
        // primary and cursor both hold their level-0 watermark.
        if !state.dbuf.joined
            || alloc.absolute
                != (crate::intel_gpu_xelpg_dbuf::Entry {
                    start: 0,
                    end: 4096,
                })
            || alloc.cursor.end != 4096
            || alloc.planes[0].start != 0
            || alloc.planes[0].end != alloc.cursor.start
            || !profile.primary.levels[0].enable
            || !profile.cursor.levels[0].enable
            || res::cursor_wm_image(0, &profile.cursor).is_none()
            || res::plane_wm_image(0, 0, &profile.primary).is_none()
        {
            return Err(FsError::Unsupported);
        }
        Ok((profile, state))
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
        let mode = Mode {
            pixel_clock_khz: timing.clock,
            h_active: timing.width,
            h_total: timing.htotal,
            v_active: timing.height,
            v_total: timing.vtotal,
            ..Mode::VESA_1024X768_60
        };
        Self::capture(io, &mode)
    }
    pub(crate) fn capture(io: &(impl MmioWindow + ?Sized), mode: &Mode) -> Result<Self, FsError> {
        let profile = Self::capture_layout(io, mode)?;
        Self::check_cdclk(io, mode)?;
        Ok(profile)
    }
    fn check_cdclk(io: &(impl MmioWindow + ?Sized), mode: &Mode) -> Result<(), FsError> {
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
        if !(1..=652800).contains(&actual) || mode.pixel_clock_khz > actual * 2 {
            return Err(FsError::Unsupported);
        }
        let voltage = crate::intel_gpu_xelpg_cdclk::voltage_level(actual);
        let req0 = read(io, REQUEST0)?;
        let req1 = read(io, REQUEST1)?;
        if ((req0 >> 12) & 7) < u32::from(voltage) || ((req1 >> 20) & 2047) < actual.div_ceil(1000)
        {
            return Err(FsError::Unsupported);
        }
        Ok(())
    }
    fn capture_globals(io: &(impl MmioWindow + ?Sized), mode: &Mode) -> Result<Self, FsError> {
        if !display14(io)? {
            return Err(FsError::Unsupported);
        }
        // The joined allocation and one-active-pipe PM demand belong to
        // Pipe A alone. An enabled blank foreign pipe still consumes global
        // display resources, even when none of its fetchers is enabled.
        for pipe in 1..4 {
            if read(io, 0x70008 + pipe * 0x1000)? & 0xc0000000 != 0 {
                return Err(FsError::Unsupported);
            }
        }
        let (profile, state) = Self::compute_state(io, mode, Tiling::Linear, 0)?;
        let req0 = read(io, REQUEST0)?;
        let req1 = read(io, REQUEST1)?;
        // Every acknowledged PM demand field covers the computed state, and
        // the QGV peak bandwidth is exactly the computed SAGV decision
        // (0xffff keeps SAGV masked).
        let held = crate::intel_gpu_pmdemand::Params::decode(req0, req1);
        let need = state.pmdemand;
        if held.qclk_gv_bw != need.qclk_gv_bw
            || held.max(&need) != held
            || read(io, 0x44468)? & (1 << 27) != 0
            || read(io, REQUEST1)? & ENABLE != 0
            || read(io, INFLIGHT)? & (1 << 26) != 0
            || read(io, crate::intel_gpu_xelpg_dbuf::MBUS_CTL)?
                & crate::intel_gpu_xelpg_dbuf::MBUS_CTL_MASK
                != state.dbuf.mbus_ctl()
            || read(io, crate::intel_gpu_xelpg_dbuf::dbox_ctl(0))? != state.dbuf.dbox(0)
            || read(io, 0x45004)? & (1 << 3) == 0
            || read(io, res::plane_buf_cfg(0, 0))? != state.dbuf.pipes[0].planes[0].reg()
            || read(io, res::cursor_buf_cfg(0))? != profile.cursor_ddb
        {
            return Err(FsError::Unsupported);
        }
        for (slice, r) in DBUFS.into_iter().enumerate() {
            let want = state.dbuf.dbuf_ctl(slice, 0, state.dbuf.enabled_slices);
            let want = want | ((want >> 1) & (1 << 30));
            if read(io, r)? & 0xc0ff0000 != want & 0xc0ff0000 {
                return Err(FsError::Unsupported);
            }
        }
        Ok(profile)
    }
    /// The proved layout, published as Pipe A's programmed
    /// `wm_level_disabled`; any failure publishes "unknown".
    fn capture_layout(io: &(impl MmioWindow + ?Sized), mode: &Mode) -> Result<Self, FsError> {
        let profile = Self::capture_layout_inner(io, mode);
        wm::publish_pipe_a(profile.as_ref().ok().map(|p| p.wm_level_disabled));
        profile
    }
    fn capture_layout_inner(io: &(impl MmioWindow + ?Sized), mode: &Mode) -> Result<Self, FsError> {
        let mut profile = Self::capture_globals(io, mode)?;
        // X-tiled takes the linear watermark arithmetic on display >= 10.
        match read(io, 0x70180)? & (7 << 10) {
            0 => {}
            0x400 => {
                let layout = Self::compute_for_layout(io, mode, Tiling::X)?;
                profile.primary = layout.primary;
                profile.wm_level_disabled = layout.wm_level_disabled;
            }
            0x1400 => {
                let layout = Self::compute_for_layout(io, mode, Tiling::Tile4)?;
                profile.primary = layout.primary;
                profile.wm_level_disabled = layout.wm_level_disabled;
            }
            _ => return Err(FsError::Unsupported),
        }
        verify_primary(io, profile.primary)?;
        Ok(profile)
    }
}

fn primary_registers(wm: PlaneWm) -> Result<[(u64, u32); 9], FsError> {
    res::plane_wm_image(0, 0, &wm).ok_or(FsError::Unsupported)
}
fn verify_primary(io: &(impl MmioWindow + ?Sized), wm: PlaneWm) -> Result<(), FsError> {
    for (r, value) in primary_registers(wm)? {
        if read(io, r)? != value {
            return Err(FsError::Unsupported);
        }
    }
    Ok(())
}

/// Retained primary watermark ownership. Only shadowed primary WM registers
/// vary; the acknowledged PM demand, DBUF/MBUS and cursor partition never do.
/// A pending image survives cancellation and partial writes until a verified
/// original console latch. Neither GT reset nor command retirement alone
/// authorizes forgetting it.
#[derive(Debug)]
pub(crate) struct Primary {
    mode: Mode,
    original: Profile,
    tile4: PlaneWm,
    /// `wm_level_disabled` of the Tile4 image.
    tile4_wm_level_disabled: bool,
    current_tile4: bool,
    pending: Option<bool>,
}
impl Primary {
    pub(crate) fn capture(
        io: &(impl MmioWindow + ?Sized),
        timing: crate::intel_gpu_dsb::Timing,
    ) -> Result<Self, FsError> {
        let mode = Mode {
            pixel_clock_khz: timing.clock,
            h_active: timing.width,
            h_total: timing.htotal,
            v_active: timing.height,
            v_total: timing.vtotal,
            ..Mode::VESA_1024X768_60
        };
        // A fresh resource journal must begin on our verified linear/X
        // baseline, never adopt an unrelated inherited Tile4 allocation.
        if !matches!(read(io, 0x70180)? & (7 << 10), 0 | 0x400) {
            return Err(FsError::Unsupported);
        }
        if read(io, 0x7026c)? & (1 << 19) == 0 {
            return Err(FsError::Unsupported);
        }
        let original = Profile::capture(io, &mode)?;
        let tile4 = Profile::compute_for_layout(io, &mode, Tiling::Tile4)?;
        Ok(Self {
            mode,
            original,
            tile4: tile4.primary,
            tile4_wm_level_disabled: tile4.wm_level_disabled,
            current_tile4: false,
            pending: None,
        })
    }
    /// `wm_level_disabled` of the linear/X (`false`) or Tile4 image.
    pub(crate) fn wm_level_disabled(&self, tile4: bool) -> bool {
        if tile4 {
            self.tile4_wm_level_disabled
        } else {
            self.original.wm_level_disabled
        }
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
    pub(crate) fn check_globals(&self, io: &(impl MmioWindow + ?Sized)) -> Result<(), FsError> {
        let profile = Profile::capture_globals(io, &self.mode)?;
        Profile::check_cdclk(io, &self.mode)?;
        if profile != self.original || read(io, 0x7026c)? & (1 << 19) == 0 {
            return Err(FsError::Unsupported);
        }
        Ok(())
    }
    fn image(&self, tile4: bool) -> PlaneWm {
        if tile4 {
            self.tile4
        } else {
            self.original.primary
        }
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
        self.check_globals(io)?;
        if self.pending.is_none() {
            let tiling = read(io, 0x70180)? & (7 << 10);
            if if self.current_tile4 {
                tiling != 0x1400
            } else {
                !matches!(tiling, 0 | 0x400)
            } {
                return Err(FsError::Unsupported);
            }
            verify_primary(io, self.image(self.current_tile4))?;
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
        let image = primary_registers(self.image(tile4))?;
        self.pending = Some(tile4);
        wm::publish_pipe_a(None);
        Ok(image.to_vec())
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
        self.check_globals(io)?;
        let target = self.pending.ok_or(FsError::Busy)?;
        verify_primary(io, self.image(target))?;
        self.current_tile4 = target;
        self.pending = None;
        wm::publish_pipe_a(self.current_wm_level_disabled());
        Ok(())
    }
    /// Caller has independently retired all DSB streams and holds display
    /// exclusion. These are shadow writes; only the following original
    /// console SURF latch plus readback completes restoration.
    pub(crate) fn restore(&mut self, io: &(impl MmioWindow + ?Sized)) -> Result<Profile, FsError> {
        self.check_globals(io)?;
        let image = primary_registers(self.original.primary)?;
        self.pending = Some(false); // retained before the first possible write
        wm::publish_pipe_a(None);
        for (r, value) in image {
            checked(io, r, value)?;
        }
        Ok(self.original)
    }
}
/// None is a strict, read-only refusal before writes: older boot modes may
/// continue with inherited resources, but cannot acquire the cursor profile.
/// Once the transaction starts, failure restores every touched resource
/// register it can and always leaves the pipe off; no caller may enable it
/// or publish a cursor on a failed baseline. `min_cdclk_khz` is a caller
/// CDCLK floor (Linux `force_min_cdclk`); 0 lets the computed minimum both
/// raise and lower the clock.
pub(crate) fn initialize(
    io: &(impl MmioWindow + ?Sized),
    mode: &Mode,
    min_cdclk_khz: u32,
) -> Result<Option<Profile>, ResourceError> {
    if !display14(io)? {
        return Ok(None);
    }
    match idle(io) {
        Ok(()) => {}
        Err(FsError::Unsupported) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let (profile, state) = match Profile::compute_state(io, mode, Tiling::Linear, min_cdclk_khz) {
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
    let chicken = read(io, 0x7026c)?;
    checked(io, 0x7026c, chicken | (1 << 19))?;
    // Wa_14016740474 (intel_pmdemand_init): display14.00 A0..<C0. STEP_*
    // enumerates four substeps per letter; GMD stepping is the offset.
    let gmd = read(io, 0x510a0)?;
    if gmd & 63 < 8 {
        let v = read(io, 0x46438)?;
        checked(io, 0x46438, v | (1 << 19))?;
    }
    // skl_watermark_ipc_update: transition watermarks require IPC. Own its
    // enable while the pipes are off instead of inheriting firmware policy.
    let arb = read(io, 0x45004)?;
    checked(io, 0x45004, arb | (1 << 3))?;
    res::commit(io, &state)?;
    for r in [0x70080, 0x70088, 0x70084] {
        checked(io, r, 0)?;
    }
    Profile::capture_layout(io, mode)?;
    Ok(Some(profile))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_display_resources_tests.rs"]
mod tests;
