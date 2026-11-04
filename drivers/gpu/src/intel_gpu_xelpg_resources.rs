//! Display-14.00 (Meteor/Arrow Lake) display-resource transactions.
//!
//! Compute (pure) → check (typed refusal before any write) → commit (source
//! ordering, readback proofs, restoration of every touched register on
//! failure). The computation is the multi-pipe one: up to four pipes with
//! up to five universal planes each, DBUF slice selection and MBUS joining,
//! per-pipe and per-plane DDB, display-14 watermarks, CDCLK and PM demand.
//!
//! Source (MIT Linux b90c984d): `skl_watermark.c::skl_compute_wm` /
//! `skl_compute_ddb`, `intel_cdclk.c::intel_crtc_min_cdclk` /
//! `intel_compute_min_cdclk` / `bxt_modeset_calc_cdclk`,
//! `intel_crtc.c::intel_crtc_bw_min_cdclk`,
//! `skl_universal_plane.c::icl_plane_min_cdclk`,
//! `intel_pmdemand.c::intel_pmdemand_atomic_check` and the commit order of
//! `intel_display.c::intel_atomic_commit_tail` /
//! `skl_commit_modeset_enables`: PM demand pre-plane, CDCLK pre-plane,
//! DBUF pre-plane slices, MBUS pre-DDB join/DBOX/min-tracker, plane
//! WM/DDB (`skl_write_plane_wm`, `skl_write_cursor_wm`), DBUF post-plane,
//! PM demand post-plane.
//!
//! Commit precondition: every pipe, plane, cursor, DSB and FBC is off, the
//! state Linux reaches with `cdclk_state->disable_pipes` and full modesets of
//! every pipe. CDCLK is therefore programmed to its final value (raising or
//! lowering) before planes, with `TGL_CDCLK_CD2X_PIPE_NONE`, and PM demand
//! is lowered to the new requirement before any pipe is enabled. Live-pipe
//! repartitioning (vblank-ordered DDB updates) is not implemented and is
//! refused. SAGV is never enabled: the QGV peak bandwidth is `U16_MAX`
//! (`mtl_find_qgv_points` with a SAGV-rejecting pipe), so no DRAM QGV
//! bandwidth derating is required for admission.

use alloc::vec::Vec;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_pmdemand::{self as pmdemand, Demand, Params};
use crate::intel_gpu_xelpg_cdclk::{self as cdclk, CdclkError, Rung};
use crate::intel_gpu_xelpg_dbuf::{self as dbuf, Dbuf, DdbError, PipeInput, PlaneInput};
use crate::intel_gpu_xelpg_wm::{self as wm, Latency, PlaneWm, Surface, Tiling, WmError};
use narf_filesystem::FsError;

pub(crate) use dbuf::{PIPES, PLANES};

/// One universal plane: unscaled, full-pipe source/destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlaneRequest {
    pub(crate) width: u16,
    pub(crate) height: u16,
    pub(crate) cpp: u32,
    pub(crate) tiling: Tiling,
}

/// One pipe of the new configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PipeRequest {
    pub(crate) pixel_rate_khz: u32,
    pub(crate) hdisplay: u16,
    pub(crate) htotal: u16,
    pub(crate) vdisplay: u16,
    pub(crate) vtotal: u16,
    pub(crate) planes: [Option<PlaneRequest>; PLANES],
    /// The 64x64 ARGB8888 legacy cursor is always budgeted (DDB, level
    /// selection, vblank prefill) so it can be shown later without
    /// repartitioning; this only selects whether its WMs are programmed.
    pub(crate) cursor_visible: bool,
    /// Highest port clock this pipe may run while the state is current.
    pub(crate) port_clock_khz: u32,
    /// Non-Type-C PHY index driving the pipe, if any.
    pub(crate) combo_phy: Option<u8>,
    /// The pipe's VDSC term when it compresses (`intel_vdsc_min_cdclk`
    /// and `intel_vdsc_prefill_lines`).
    pub(crate) dsc: Option<crate::intel_gpu_xelpg_dsc::DscTerm>,
}

/// The complete new configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) pipes: [Option<PipeRequest>; PIPES],
    /// Caller CDCLK floor (`cdclk_state->force_min_cdclk`).
    pub(crate) min_cdclk_khz: u32,
}

/// Computed resource state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct State {
    pub(crate) dbuf: Dbuf,
    pub(crate) cdclk: Rung,
    pub(crate) voltage_level: u8,
    pub(crate) pmdemand: Params,
    pub(crate) cursor_visible: [bool; PIPES],
    /// The request each active pipe was computed from; a live pipe must
    /// keep exactly this configuration across a repartition. Read by the
    /// live/pipe owners.
    pub(crate) requests: [Option<PipeRequest>; PIPES],
}

/// Typed refusals and failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResourceError {
    /// Request outside the qualified bounds; nothing was written.
    Unsupported,
    /// No watermark level fits the vblank prefill budget.
    VblankTooShort,
    /// The DDB cannot hold level 0 of every plane.
    DdbExhausted,
    /// Required CDCLK exceeds the 652.8 MHz maximum.
    CdclkUnsatisfiable,
    /// SAGV is allowed but no QGV point carries the display data rate
    /// (`mtl_find_qgv_points` -EINVAL).
    BandwidthExceeded,
    /// A pipe, plane, cursor, DSB or FBC is live.
    Busy,
    /// Lost current access or an all-ones read.
    NoDevice,
    /// A hardware acknowledgement did not arrive.
    Timeout,
    /// A written value did not read back.
    Readback,
    /// CDCLK change failed.
    Clock(CdclkError),
    /// No lit pipe can take its new DDB without overlapping another
    /// pipe's current allocation.
    DdbOrdering,
    /// A lit pipe's configuration would change; that needs its modeset.
    LivePipeChanged,
    /// The transition needs every pipe off (unknown firmware CDCLK).
    RequiresPipesOff,
    /// The hardware no longer holds the programmed resource state.
    Diverged,
}

impl From<WmError> for ResourceError {
    fn from(e: WmError) -> Self {
        match e {
            WmError::Unsupported => Self::Unsupported,
            WmError::VblankTooShort => Self::VblankTooShort,
        }
    }
}
impl From<DdbError> for ResourceError {
    fn from(e: DdbError) -> Self {
        match e {
            DdbError::Unsupported | DdbError::Overlap => Self::Unsupported,
            DdbError::Exhausted => Self::DdbExhausted,
        }
    }
}
impl From<FsError> for ResourceError {
    fn from(e: FsError) -> Self {
        match e {
            FsError::TimedOut => Self::Timeout,
            FsError::Busy => Self::Busy,
            FsError::Unsupported => Self::Unsupported,
            _ => Self::NoDevice,
        }
    }
}
impl From<CdclkError> for ResourceError {
    fn from(e: CdclkError) -> Self {
        Self::Clock(e)
    }
}

/// The cursor surface this driver can show (`intel_gpu_cursor`).
const CURSOR: Surface = Surface {
    width: 64,
    cpp: 4,
    tiling: Tiling::Linear,
};

fn timing(p: &PipeRequest) -> wm::Timing {
    wm::Timing {
        pixel_rate_khz: p.pixel_rate_khz,
        htotal: u32::from(p.htotal),
        vtotal: u32::from(p.vtotal),
        vblank_start: u32::from(p.vdisplay),
    }
}

/// Compute and check the complete state. Pure: no register access.
pub(crate) fn compute(request: &Request, latency: &Latency) -> Result<State, ResourceError> {
    let active = request
        .pipes
        .iter()
        .enumerate()
        .filter(|(_, p)| p.is_some())
        .fold(0u8, |m, (i, _)| m | (1 << i));
    if active == 0 {
        return Err(ResourceError::Unsupported);
    }
    let num_active = active.count_ones();
    let mut inputs: [Option<PipeInput>; PIPES] = [None; PIPES];
    let mut min_cdclk = request.min_cdclk_khz;
    let mut min_voltage = 0u8;
    let mut max_port = 0u32;
    let mut phys = 0u16;
    let mut cursor_visible = [false; PIPES];
    for (pipe, p) in request.pipes.iter().enumerate() {
        let Some(p) = p else { continue };
        if p.hdisplay == 0
            || p.vdisplay == 0
            || p.htotal <= p.hdisplay
            || p.vtotal <= p.vdisplay
            || p.pixel_rate_khz == 0
            || p.planes[0].is_none()
            || p.combo_phy.is_some_and(|phy| phy >= 16)
        {
            return Err(ResourceError::Unsupported);
        }
        let t = timing(p);
        let mut planes = [None; PLANES];
        let mut plane_wm = [PlaneWm::default(); PLANES];
        for (i, plane) in p.planes.iter().enumerate() {
            let Some(plane) = plane else { continue };
            if plane.width == 0
                || plane.height == 0
                || plane.width > p.hdisplay
                || plane.height > p.vdisplay
            {
                return Err(ResourceError::Unsupported);
            }
            plane_wm[i] = wm::plane(
                t,
                Surface {
                    width: u32::from(plane.width),
                    cpp: plane.cpp,
                    tiling: plane.tiling,
                },
                latency,
            )?;
        }
        let mut cursor_wm = wm::plane(t, CURSOR, latency)?;
        {
            let mut all: Vec<&mut PlaneWm> = plane_wm.iter_mut().collect();
            all.push(&mut cursor_wm);
            wm::check_vblank_dsc(t, latency, &mut all, p.dsc.is_some())?;
        }
        let mut crtc_data_rate = 0u64;
        for (i, plane) in p.planes.iter().enumerate() {
            let Some(plane) = plane else { continue };
            let data_rate = u64::from(p.pixel_rate_khz) * u64::from(plane.cpp);
            if data_rate > u64::from(u32::MAX) {
                return Err(ResourceError::Unsupported);
            }
            crtc_data_rate += data_rate;
            planes[i] = Some(PlaneInput {
                wm: plane_wm[i],
                rel_data_rate: u64::from(plane.width)
                    * u64::from(plane.height)
                    * u64::from(plane.cpp),
                data_rate: data_rate as u32,
            });
            // icl_plane_min_cdclk: two pixels per clock.
            min_cdclk = min_cdclk.max(p.pixel_rate_khz.div_ceil(2));
        }
        inputs[pipe] = Some(PipeInput {
            hdisplay: p.hdisplay,
            planes,
            cursor_alloc: wm::cursor_allocation(t, latency, num_active)?,
            cursor_wm,
        });
        // intel_crtc_min_cdclk: pixel rate, "Maximum Pipe Read Bandwidth"
        // and intel_vdsc_min_cdclk.
        min_cdclk = min_cdclk.max(cdclk::pixel_rate_to_cdclk(p.pixel_rate_khz));
        if let Some(dsc) = p.dsc {
            min_cdclk = min_cdclk.max(dsc.min_cdclk_khz);
        }
        let bw = (crtc_data_rate * 10).div_ceil(512);
        min_cdclk = min_cdclk.max(bw.min(u64::from(u32::MAX)) as u32);
        min_voltage = min_voltage.max(cdclk::port_min_voltage_level(p.port_clock_khz));
        max_port = max_port.max(p.port_clock_khz);
        if let Some(phy) = p.combo_phy {
            phys |= 1 << phy;
        }
        cursor_visible[pipe] = p.cursor_visible;
    }
    let dbuf = dbuf::compute(&inputs)?;
    min_cdclk = min_cdclk.max(dbuf.bw_min_cdclk(&inputs));
    if min_cdclk > cdclk::MAX_CDCLK_KHZ {
        return Err(ResourceError::CdclkUnsatisfiable);
    }
    let rung = cdclk::calc_cdclk(min_cdclk).ok_or(ResourceError::CdclkUnsatisfiable)?;
    let qgv_peak_bw = sagv_peak_bw(request, latency, &dbuf, &inputs)?;
    let voltage_level = min_voltage.max(cdclk::voltage_level(rung.cdclk_khz));
    let pmdemand = Demand {
        qgv_peak_bw,
        enabled_slices: dbuf.enabled_slices,
        active_pipes: dbuf.active_pipes,
        voltage_level,
        cdclk_khz: rung.cdclk_khz,
        max_port_clock_khz: max_port,
        combo_phys: phys,
    }
    .params();
    let state = State {
        dbuf,
        cdclk: rung,
        voltage_level,
        pmdemand,
        cursor_visible,
        requests: request.pipes,
    };
    // Every computed level must be representable in its register.
    if state.plane_registers().is_none() {
        return Err(ResourceError::Unsupported);
    }
    Ok(state)
}

/// `intel_bw_atomic_check` for display 14: every active pipe must allow
/// SAGV (`tgl_crtc_can_enable_sagv`: each enabled plane, including a
/// visible cursor, keeps its post-DDB SAGV level-0 watermark) and SAGV must
/// be controllable; otherwise QCLK_GV_BW stays `U16_MAX`. With SAGV allowed,
/// `mtl_find_qgv_points` must find a point for the summed data rate.
fn sagv_peak_bw(
    request: &Request,
    latency: &Latency,
    dbuf: &Dbuf,
    inputs: &[Option<PipeInput>; PIPES],
) -> Result<Option<u16>, ResourceError> {
    let Some(qgv) = latency.qgv.as_ref() else {
        return Ok(None);
    };
    let mut data_rate = 0u64;
    let mut planes = 0u32;
    for (pipe, input) in inputs.iter().enumerate() {
        let Some(input) = input else { continue };
        let alloc = &dbuf.pipes[pipe];
        for (wm, plane) in alloc.wm.iter().zip(&input.planes) {
            if wm.levels[0].enable && !wm.sagv.enable {
                return Ok(None);
            }
            if let Some(plane) = plane {
                data_rate += u64::from(plane.data_rate);
                planes += 1;
            }
        }
        let cursor_visible = request.pipes[pipe].is_some_and(|p| p.cursor_visible);
        if cursor_visible && alloc.cursor_wm.levels[0].enable && !alloc.cursor_wm.sagv.enable {
            return Ok(None);
        }
    }
    let mbps = data_rate.div_ceil(1000).min(u64::from(u32::MAX)) as u32;
    crate::intel_gpu_xelpg_bw::qgv_peak_bw(qgv, mbps, planes)
        .map(Some)
        .ok_or(ResourceError::BandwidthExceeded)
}

const PLANE_BLOCKS: u32 = 0x1fff;
const CURSOR_BLOCKS: u32 = 0xfff;

/// `PLANE_WM`, `PLANE_WM_SAGV`, `PLANE_WM_SAGV_TRANS`, `PLANE_WM_TRANS`
/// for `plane` (0-based) on `pipe`.
pub(crate) fn plane_wm_image(pipe: usize, plane: usize, w: &PlaneWm) -> Option<[(u64, u32); 9]> {
    let base = 0x70240 + pipe as u64 * 0x1000 + plane as u64 * 0x100;
    let mut out = [(0, 0); 9];
    for (l, level) in w.levels.iter().enumerate() {
        out[l] = (base + l as u64 * 4, level.encode(PLANE_BLOCKS)?);
    }
    out[6] = (base + 0x18, w.sagv.encode(PLANE_BLOCKS)?);
    out[7] = (base + 0x1c, w.sagv_trans.encode(PLANE_BLOCKS)?);
    out[8] = (base + 0x28, w.trans.encode(PLANE_BLOCKS)?);
    Some(out)
}

/// `PLANE_BUF_CFG`.
pub(crate) fn plane_buf_cfg(pipe: usize, plane: usize) -> u64 {
    0x7027c + pipe as u64 * 0x1000 + plane as u64 * 0x100
}

/// `CUR_WM`, `CUR_WM_SAGV`, `CUR_WM_SAGV_TRANS`, `CUR_WM_TRANS`.
pub(crate) fn cursor_wm_image(pipe: usize, w: &PlaneWm) -> Option<[(u64, u32); 9]> {
    let base = 0x70140 + pipe as u64 * 0x1000;
    let mut out = [(0, 0); 9];
    for (l, level) in w.levels.iter().enumerate() {
        out[l] = (base + l as u64 * 4, level.encode(CURSOR_BLOCKS)?);
    }
    out[6] = (base + 0x18, w.sagv.encode(CURSOR_BLOCKS)?);
    out[7] = (base + 0x1c, w.sagv_trans.encode(CURSOR_BLOCKS)?);
    out[8] = (base + 0x28, w.trans.encode(CURSOR_BLOCKS)?);
    Some(out)
}

/// `CUR_BUF_CFG`.
pub(crate) fn cursor_buf_cfg(pipe: usize) -> u64 {
    0x7017c + pipe as u64 * 0x1000
}

impl State {
    /// The programmed state after an owner changed only `pipe`'s primary
    /// tiling, as the KMS primary owner does
    /// ([`crate::intel_gpu_display_resources::Primary::stage`]): that
    /// primary takes the watermarks `compute` gives for `tiling`, while every
    /// DDB entry, the cursor watermarks, the clock and the PM demand stay as
    /// programmed. Pure. A tiling that would move any DDB entry or change
    /// the slice/join layout is refused (`Diverged`); one universal plane
    /// per pipe keeps its whole pipe allocation, so this never happens for
    /// the owned layouts.
    pub(crate) fn retile(
        &self,
        pipe: usize,
        tiling: Tiling,
        latency: &Latency,
    ) -> Result<State, ResourceError> {
        let mut request = Request {
            pipes: self.requests,
            min_cdclk_khz: 0,
        };
        let plane = request
            .pipes
            .get_mut(pipe)
            .and_then(Option::as_mut)
            .and_then(|p| p.planes[0].as_mut())
            .ok_or(ResourceError::Unsupported)?;
        if plane.tiling == tiling {
            return Ok(*self);
        }
        plane.tiling = tiling;
        let fresh = compute(&request, latency)?;
        if fresh.dbuf.active_pipes != self.dbuf.active_pipes
            || fresh.dbuf.joined != self.dbuf.joined
            || fresh.dbuf.slices != self.dbuf.slices
            || fresh.dbuf.pipes.iter().zip(&self.dbuf.pipes).any(|(a, b)| {
                a.absolute != b.absolute || a.planes != b.planes || a.cursor != b.cursor
            })
        {
            return Err(ResourceError::Diverged);
        }
        let mut out = *self;
        out.requests = fresh.requests;
        out.dbuf.pipes[pipe].wm[0] = fresh.dbuf.pipes[pipe].wm[0];
        if out.plane_registers().is_none() {
            return Err(ResourceError::Unsupported);
        }
        Ok(out)
    }

    /// Every plane/cursor WM and DDB register of every pipe. Planes of
    /// inactive pipes and disabled planes are zero, matching Linux's zeroed
    /// state for disabled planes; a hidden cursor keeps only its DDB.
    pub(crate) fn plane_registers(&self) -> Option<Vec<(u64, u32)>> {
        let mut regs = Vec::with_capacity(PIPES * (PLANES + 1) * 10);
        for pipe in 0..PIPES {
            regs.extend(self.pipe_registers(pipe, self.cursor_visible[pipe])?);
        }
        Some(regs)
    }

    /// One pipe's plane and cursor WM/DDB image; `cursor_visible` selects
    /// whether the cursor's watermarks are programmed.
    pub(crate) fn pipe_registers(
        &self,
        pipe: usize,
        cursor_visible: bool,
    ) -> Option<Vec<(u64, u32)>> {
        let mut regs = Vec::with_capacity((PLANES + 1) * 10);
        let alloc = self.dbuf.pipes.get(pipe)?;
        let active = self.dbuf.active_pipes & (1 << pipe) != 0;
        for (plane, (wm, ddb)) in alloc.wm.iter().zip(alloc.planes).enumerate() {
            let w = if active { *wm } else { PlaneWm::default() };
            regs.extend(plane_wm_image(pipe, plane, &w)?);
            let ddb = if active { ddb.reg() } else { 0 };
            regs.push((plane_buf_cfg(pipe, plane), ddb));
        }
        let w = if active && cursor_visible {
            alloc.cursor_wm
        } else {
            PlaneWm::default()
        };
        // The cursor WM must be encodable even while hidden.
        if active {
            cursor_wm_image(pipe, &alloc.cursor_wm)?;
        }
        regs.extend(cursor_wm_image(pipe, &w)?);
        let ddb = if active { alloc.cursor.reg() } else { 0 };
        regs.push((cursor_buf_cfg(pipe), ddb));
        Some(regs)
    }
}

pub(crate) fn read(io: &(impl MmioWindow + ?Sized), r: u64) -> Result<u32, ResourceError> {
    let v = io.read32(r);
    if v == u32::MAX || !io.display_access_ok() {
        Err(ResourceError::NoDevice)
    } else {
        Ok(v)
    }
}

pub(crate) fn checked(
    io: &(impl MmioWindow + ?Sized),
    r: u64,
    v: u32,
) -> Result<(), ResourceError> {
    io.write32(r, v);
    if read(io, r)? == v {
        Ok(())
    } else {
        Err(ResourceError::Readback)
    }
}

pub(crate) fn wait(
    io: &(impl MmioWindow + ?Sized),
    r: u64,
    mask: u32,
    want: u32,
) -> Result<(), ResourceError> {
    let mut lost = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let v = io.read32(r);
            lost = v == u32::MAX || !io.display_access_ok();
            lost || v & mask == want
        },
        // gen9_dbuf_slice_set waits 10 us; keep the bounded 10 ms budget the
        // owned display paths use for power acknowledgements.
        narf_time::Deadline::after_ms(10),
    );
    if lost {
        Err(ResourceError::NoDevice)
    } else if done {
        Ok(())
    } else {
        Err(ResourceError::Timeout)
    }
}

/// Every pipe, universal plane, cursor, DSB engine and FBC instance off.
pub(crate) fn require_idle(io: &(impl MmioWindow + ?Sized)) -> Result<(), ResourceError> {
    for pipe in 0..PIPES as u64 {
        if read(io, 0x70008 + pipe * 0x1000)? & 0xc000_0000 != 0
            || read(io, 0x70080 + pipe * 0x1000)? & 0x27 != 0
        {
            return Err(ResourceError::Busy);
        }
        for plane in 0..PLANES as u64 {
            if read(io, 0x70180 + pipe * 0x1000 + plane * 0x100)? & (1 << 31) != 0 {
                return Err(ResourceError::Busy);
            }
        }
        for dsb in 0..3 {
            if read(io, 0x70b08 + pipe * 0x1000 + dsb * 0x100)? & ((1 << 31) | 1) != 0 {
                return Err(ResourceError::Busy);
            }
        }
    }
    for r in [0x43208, 0x43248] {
        if read(io, r)? & (1 << 31) != 0 {
            return Err(ResourceError::Busy);
        }
    }
    Ok(())
}

/// Everything a commit may change, captured before its first write.
#[derive(Clone, Debug)]
pub(crate) struct Snapshot {
    pub(crate) pmdemand: Params,
    pub(crate) cdclk: cdclk::Current,
    pub(crate) dbuf_ctl: [u32; dbuf::SLICES],
    pub(crate) mbus_ctl: u32,
    pub(crate) dbox: [u32; PIPES],
    pub(crate) planes: Vec<(u64, u32)>,
}

impl Snapshot {
    pub(crate) fn capture(
        io: &(impl MmioWindow + ?Sized),
        state: &State,
    ) -> Result<Self, ResourceError> {
        let pmdemand = pmdemand::current(io)?;
        let cdclk = cdclk::Current::read(io)?;
        let mut dbuf_ctl = [0; dbuf::SLICES];
        for (v, r) in dbuf_ctl.iter_mut().zip(dbuf::DBUF_CTL) {
            *v = read(io, r)?;
        }
        let mbus_ctl = read(io, dbuf::MBUS_CTL)?;
        let mut dbox = [0; PIPES];
        for (pipe, v) in dbox.iter_mut().enumerate() {
            *v = read(io, dbuf::dbox_ctl(pipe))?;
        }
        let mut planes = Vec::new();
        for (r, _) in state.plane_registers().ok_or(ResourceError::Unsupported)? {
            planes.push((r, read(io, r)?));
        }
        Ok(Self {
            pmdemand,
            cdclk,
            dbuf_ctl,
            mbus_ctl,
            dbox,
            planes,
        })
    }

    fn enabled_slices(&self) -> u8 {
        self.dbuf_ctl
            .iter()
            .enumerate()
            .filter(|(_, v)| *v & dbuf::DBUF_POWER_STATE != 0)
            .fold(0, |m, (s, _)| m | (1 << s))
    }
}

/// How far a commit progressed, for restoration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    Nothing,
    PmDemand,
    Cdclk,
    Dbuf,
    Mbus,
    Planes,
}

fn program_slices(
    io: &(impl MmioWindow + ?Sized),
    state: &State,
    old: &[u32; dbuf::SLICES],
    enabled: u8,
) -> Result<(), ResourceError> {
    for (slice, r) in dbuf::DBUF_CTL.into_iter().enumerate() {
        let value = state.dbuf.dbuf_ctl(slice, old[slice], enabled);
        io.write32(r, value);
        let want = if enabled & (1 << slice) != 0 {
            dbuf::DBUF_POWER_STATE
        } else {
            0
        };
        wait(io, r, dbuf::DBUF_POWER_STATE, want)?;
        let mask = dbuf::DBUF_POWER_REQUEST | dbuf::DBUF_TRACKER_MASK;
        if read(io, r)? & mask != value & mask {
            return Err(ResourceError::Readback);
        }
    }
    Ok(())
}

fn apply(
    io: &(impl MmioWindow + ?Sized),
    state: &State,
    snap: &Snapshot,
    stage: &mut Stage,
) -> Result<(), ResourceError> {
    // intel_pmdemand_pre_plane_update: max(old, new).
    *stage = Stage::PmDemand;
    pmdemand::program(io, &state.pmdemand, Some(&snap.pmdemand))?;
    // intel_set_cdclk_pre_plane_update, disable_pipes: the final config.
    *stage = Stage::Cdclk;
    cdclk::program(io, &snap.cdclk, state.cdclk)?;
    // intel_dbuf_pre_plane_update: old | new slices.
    *stage = Stage::Dbuf;
    let old_slices = snap.enabled_slices();
    program_slices(
        io,
        state,
        &snap.dbuf_ctl,
        old_slices | state.dbuf.enabled_slices,
    )?;
    // intel_dbuf_mbus_pre_ddb_update: join, DBOX, min tracker (above).
    *stage = Stage::Mbus;
    let mbus = (snap.mbus_ctl & !dbuf::MBUS_CTL_MASK) | state.dbuf.mbus_ctl();
    checked(io, dbuf::MBUS_CTL, mbus)?;
    for pipe in 0..PIPES {
        if state.dbuf.active_pipes & (1 << pipe) != 0 {
            checked(io, dbuf::dbox_ctl(pipe), state.dbuf.dbox(pipe))?;
        }
    }
    // skl_write_plane_wm / skl_write_cursor_wm for every plane.
    *stage = Stage::Planes;
    for (r, v) in state.plane_registers().ok_or(ResourceError::Unsupported)? {
        checked(io, r, v)?;
    }
    // intel_dbuf_post_plane_update: only the new slices.
    if old_slices | state.dbuf.enabled_slices != state.dbuf.enabled_slices {
        let mut current = [0; dbuf::SLICES];
        for (v, r) in current.iter_mut().zip(dbuf::DBUF_CTL) {
            *v = read(io, r)?;
        }
        program_slices(io, state, &current, state.dbuf.enabled_slices)?;
    }
    // intel_pmdemand_post_plane_update: new. Every pipe is still off, so
    // no older configuration depends on the raised intermediate values.
    pmdemand::program(io, &state.pmdemand, None)?;
    Ok(())
}

fn restore(
    io: &(impl MmioWindow + ?Sized),
    state: &State,
    snap: &Snapshot,
    stage: Stage,
) -> Result<(), ResourceError> {
    // Once the pre-plane superset was acknowledged, a failed post-plane
    // request may have lowered PM demand to the new state's values. Re-raise
    // max(original, new) before restoring anything it must cover (DBUF,
    // MBUS and above all a higher original CDCLK), mirroring the forward
    // pre-plane request; the original demand follows the original clock.
    if stage > Stage::PmDemand {
        pmdemand::program(io, &state.pmdemand, Some(&snap.pmdemand))?;
    }
    if stage >= Stage::Planes {
        for &(r, v) in &snap.planes {
            checked(io, r, v)?;
        }
    }
    if stage >= Stage::Mbus {
        checked(io, dbuf::MBUS_CTL, snap.mbus_ctl)?;
        for (pipe, v) in snap.dbox.iter().enumerate() {
            checked(io, dbuf::dbox_ctl(pipe), *v)?;
        }
    }
    if stage >= Stage::Dbuf {
        for (slice, r) in dbuf::DBUF_CTL.into_iter().enumerate() {
            let original = snap.dbuf_ctl[slice];
            io.write32(r, original & !dbuf::DBUF_POWER_STATE);
            wait(
                io,
                r,
                dbuf::DBUF_POWER_STATE,
                original & dbuf::DBUF_POWER_STATE,
            )?;
        }
    }
    if stage >= Stage::Cdclk {
        cdclk::restore(io, &snap.cdclk)?;
    }
    if stage >= Stage::PmDemand {
        // Only once the original clock is back may its demand be restored.
        pmdemand::program(io, &snap.pmdemand, None)?;
    }
    Ok(())
}

/// Commit `state`. On failure every register the commit may have changed
/// is restored to its captured value in reverse order; if restoration
/// itself fails, the PM demand is left at the raised superset and the
/// original error is returned (callers keep every pipe off either way).
pub(crate) fn commit(io: &(impl MmioWindow + ?Sized), state: &State) -> Result<(), ResourceError> {
    require_idle(io)?;
    let snap = Snapshot::capture(io, state)?;
    let mut stage = Stage::Nothing;
    match apply(io, state, &snap, &mut stage) {
        Ok(()) => Ok(()),
        Err(error) => {
            if io.display_access_ok() {
                let _ = restore(io, state, &snap, stage);
            }
            Err(error)
        }
    }
}

/// The PM demand of a display with every pipe off, at `cdclk`
/// (`intel_pmdemand_atomic_check` with no active pipe: S1 the only DBUF
/// slice, `intel_dbuf_enabled_slices`; the actual CDCLK and its voltage
/// level; no port clock or PHY; and the QGV point `mtl_find_qgv_points`
/// picks for no plane when SAGV is controllable, nothing rejecting it).
pub(crate) fn all_off_pmdemand(latency: &Latency, cdclk: Rung) -> Params {
    Demand {
        qgv_peak_bw: latency
            .qgv
            .as_ref()
            .and_then(|q| crate::intel_gpu_xelpg_bw::qgv_peak_bw(q, 0, 0)),
        enabled_slices: 1,
        active_pipes: 0,
        voltage_level: cdclk::voltage_level(cdclk.cdclk_khz),
        cdclk_khz: cdclk.cdclk_khz,
        max_port_clock_khz: 0,
        combo_phys: 0,
    }
    .params()
}

/// The post-plane half of the commit that turns the last pipe off
/// (`intel_atomic_commit_tail` with every pipe disabled): every plane and
/// cursor WM/DDB cleared, `intel_dbuf_post_plane_update` down to S1 (the
/// minimum trackers keep the current join state),
/// `intel_set_cdclk_post_plane_update` to `bxt_modeset_calc_cdclk`'s
/// no-active-pipe clock (`bxt_calc_cdclk(force_min_cdclk)`, the lowest rung
/// without a forced minimum), and `intel_pmdemand_post_plane_update` to
/// [`all_off_pmdemand`]. Refused (`Busy`) before any write unless every
/// pipe, plane, cursor, DSB and FBC is off. A failure after the first write
/// re-requests the original PM demand once the clock it may have left is
/// covered by it, so the demand never under-covers the hardware.
pub(crate) fn settle_all_off(
    io: &(impl MmioWindow + ?Sized),
    latency: &Latency,
) -> Result<(), ResourceError> {
    require_idle(io)?;
    let target = cdclk::calc_cdclk(0).ok_or(ResourceError::Unsupported)?;
    let new = all_off_pmdemand(latency, target);
    let old = pmdemand::current(io)?;
    let clock = cdclk::Current::read(io)?;
    let joined = read(io, dbuf::MBUS_CTL)? & (1 << 31) != 0;
    let result = (|| {
        for pipe in 0..PIPES {
            for plane in 0..PLANES {
                for (r, v) in plane_wm_image(pipe, plane, &PlaneWm::default())
                    .ok_or(ResourceError::Unsupported)?
                {
                    checked(io, r, v)?;
                }
                checked(io, plane_buf_cfg(pipe, plane), 0)?;
            }
            for (r, v) in
                cursor_wm_image(pipe, &PlaneWm::default()).ok_or(ResourceError::Unsupported)?
            {
                checked(io, r, v)?;
            }
            checked(io, cursor_buf_cfg(pipe), 0)?;
        }
        for (slice, r) in dbuf::DBUF_CTL.into_iter().enumerate() {
            let value = dbuf::dbuf_ctl_value(slice, read(io, r)?, 1, joined);
            io.write32(r, value);
            let want = if slice == 0 {
                dbuf::DBUF_POWER_STATE
            } else {
                0
            };
            wait(io, r, dbuf::DBUF_POWER_STATE, want)?;
        }
        if clock.known != Some(target) {
            cdclk::program(io, &clock, target)?;
        }
        pmdemand::program(io, &new, None)?;
        Ok(())
    })();
    if result.is_err() && io.display_access_ok() {
        let _ = pmdemand::program(io, &old, Some(&new));
    }
    result
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_resources_tests.rs"]
mod tests;
