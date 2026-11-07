//! Display-14.00 (Meteor/Arrow Lake) plane watermarks.
//!
//! MIT Linux b90c984d `display/skl_watermark.c`, resolved for
//! `DISPLAY_VER == 14` (no DG2 multiply, no 16 Gb DIMM workaround, no Xe3
//! auto-minimum allocation):
//! - latency: `mtl_read_wm_latency` (`MTL_LATENCY_LP0_LP1..LP4_LP5`,
//!   13-bit even/odd fields), `adjust_wm_latency` (`sanitize_wm_latency`,
//!   `make_wm_latency_monotonic`, WaWmMemoryReadLatency with
//!   `wm_read_latency() == 6`), `intel_sagv_block_time`
//!   (`MTL_LATENCY_SAGV.QCLK_SAGV`); six levels (`HAS_HW_SAGV_WM`);
//! - per level: `skl_compute_wm_params`, `skl_wm_method1/2`,
//!   `skl_compute_plane_wm` with `skl_wm_max_lines() == 255`;
//! - transition: `skl_compute_transition_wm` (IPC on, trans_min 4,
//!   trans_amount 10); SAGV: `tgl_compute_sagv_wm` (programmed through the
//!   dedicated `PLANE_WM_SAGV*` registers, `use_sagv_wm == false`);
//! - cursor DDB size: `skl_cursor_allocation` (ARGB8888 linear at
//!   `mode_config->cursor_width == 256`);
//! - vblank: `skl_wm_check_vblank` with `skl_prefill.c` for an unscaled,
//!   non-VRR pipe with `framestart_delay == 1` (a compressing pipe adds
//!   `intel_vdsc_prefill_lines`), including its
//!   `wm_level_disabled` (`skl_max_wm_level_for_vblank` below the top
//!   level), which `intel_psr.c::wm_optimization_wa` consumes as
//!   Wa_14015648006. The Pipe-A value of the watermarks proved programmed
//!   is published here and registered as PSR's provider.
//!
//! Display 30 (Xe3_LPD) runs the `_ip` entry points: `skl_compute_plane_wm`
//! adds no block (`blocks++` is display < 30 only), a Tile4 surface adds a
//! block per line only when panned (`interm_pbpl += (pan_x != 0)`), the
//! prefill CDCLK adjustment takes the display-30 table and the vblank
//! prefill budget is the VRR timing generator's guardband
//! (`intel_crtc_vblank_length` after `intel_vrr_compute_guardband` moved
//! `crtc_vblank_start`), which the caller passes as [`Timing::vblank_start`].
//! The level-0 and SAGV auto minimum allocation and `PLANE_MIN_BUF_CFG`
//! are register-image deltas ([`crate::intel_gpu_xe3lpd`]).
//!
//! Gen12 keeps its own transcription in [`crate::intel_gpu_wm`]; nothing
//! here changes Gen12 results.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::intel_gpu_aux::MmioWindow;
use narf_filesystem::FsError;

/// `MTL_LATENCY_LP0_LP1`, `LP2_LP3`, `LP4_LP5`.
pub(crate) const LATENCY_REGS: [u64; 3] = [0x45780, 0x45784, 0x45788];
/// `MTL_LATENCY_SAGV`.
pub(crate) const LATENCY_SAGV: u64 = 0x4578c;
const LEVEL_MASK: u32 = 0x1fff;
/// `wm_read_latency()` for display >= 14.
const READ_LATENCY_US: u16 = 6;
/// Regular levels with hardware SAGV watermarks.
pub(crate) const LEVELS: usize = 6;
/// `skl_wm_max_lines()` for display >= 13.
const MAX_LINES: u64 = 255;
const BLOCK: u64 = 512;
const FX: u64 = 1 << 16;
/// `mode_config->cursor_width` (`intel_cursor_mode_config_init`).
pub(crate) const CURSOR_ALLOC_WIDTH: u32 = 256;

/// Adjusted latencies and SAGV block time, in microseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Latency {
    pub(crate) levels: [u16; LEVELS],
    pub(crate) sagv_block_us: u16,
    /// QGV description when SAGV is controllable (`intel_has_sagv`).
    pub(crate) qgv: Option<crate::intel_gpu_xelpg_bw::Qgv>,
}

impl Latency {
    /// `adjust_wm_latency` on the raw `mtl_read_wm_latency` values.
    pub(crate) fn adjust(raw: [u16; LEVELS], sagv_block_us: u16) -> Self {
        let mut wm = raw;
        let first_zero = (1..LEVELS).find(|&l| wm[l] == 0).unwrap_or(LEVELS);
        for v in wm.iter_mut().skip(first_zero + 1) {
            *v = 0;
        }
        for l in 1..LEVELS {
            if wm[l] == 0 {
                break;
            }
            wm[l] = wm[l].max(wm[l - 1]);
        }
        if wm[0] == 0 {
            wm[0] += READ_LATENCY_US;
            for v in wm.iter_mut().skip(1) {
                if *v == 0 {
                    break;
                }
                *v += READ_LATENCY_US;
            }
        }
        Self {
            levels: wm,
            sagv_block_us,
            qgv: None,
        }
    }

    pub(crate) fn read(io: &(impl MmioWindow + ?Sized)) -> Result<Self, FsError> {
        let mut raw = [0u16; LEVELS];
        for (i, r) in LATENCY_REGS.into_iter().enumerate() {
            let v = io.read32(r);
            if v == u32::MAX || !io.display_access_ok() {
                return Err(FsError::NoDevice);
            }
            raw[i * 2] = (v & LEVEL_MASK) as u16;
            raw[i * 2 + 1] = ((v >> 16) & LEVEL_MASK) as u16;
        }
        let sagv = io.read32(LATENCY_SAGV);
        if sagv == u32::MAX || !io.display_access_ok() {
            return Err(FsError::NoDevice);
        }
        // intel_sagv_init: without SAGV control the block time is zero, so
        // no SAGV watermark is computed or programmed.
        let qgv = crate::intel_gpu_xelpg_bw::Qgv::read(io)?;
        let block = if qgv.is_some() {
            (sagv & LEVEL_MASK) as u16
        } else {
            0
        };
        Ok(Self {
            qgv,
            ..Self::adjust(raw, block)
        })
    }
}

/// Surface layouts this transcription admits. X-tiled takes the linear
/// arithmetic on display >= 10; Tile4 is the `y_tiled` branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tiling {
    Linear,
    X,
    Tile4,
}

/// One watermark level with Linux `struct skl_wm_level` semantics: a
/// disabled level may still carry blocks/lines (vblank limiting and
/// `skl_need_wm_copy_wa`), and those are what the register holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Level {
    pub(crate) enable: bool,
    pub(crate) blocks: u16,
    pub(crate) lines: u16,
    pub(crate) min_ddb_alloc: u16,
}

const REJECTED: Level = Level {
    enable: false,
    blocks: 0,
    lines: 0,
    min_ddb_alloc: u16::MAX,
};

impl Level {
    /// `skl_plane_wm_reg_val` / cursor equivalent. `None` if the value does
    /// not fit the 13-bit lines or the plane's blocks field.
    pub(crate) fn encode(self, blocks_mask: u32) -> Option<u32> {
        let blocks = u32::from(self.blocks);
        let lines = u32::from(self.lines);
        if blocks > blocks_mask || lines > 0x1fff {
            return None;
        }
        Some((u32::from(self.enable) << 31) | (lines << 14) | blocks)
    }
}

/// `struct skl_plane_wm` for one non-planar plane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PlaneWm {
    pub(crate) levels: [Level; LEVELS],
    pub(crate) trans: Level,
    pub(crate) sagv: Level,
    pub(crate) sagv_trans: Level,
}

/// Plane surface inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Surface {
    pub(crate) width: u32,
    pub(crate) cpp: u32,
    pub(crate) tiling: Tiling,
}

/// Pipe timing inputs (unscaled: plane pixel rate == pipe pixel rate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Timing {
    pub(crate) pixel_rate_khz: u32,
    pub(crate) htotal: u32,
    pub(crate) vtotal: u32,
    pub(crate) vblank_start: u32,
}

/// Watermark refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WmError {
    /// Inputs outside the bounded transcription (Linux would WARN/wrap).
    Unsupported,
    /// `skl_max_wm_level_for_vblank` found no level that fits.
    VblankTooShort,
}

struct Params {
    y_tiled: bool,
    cpp: u64,
    bytes_per_line: u64,
    blocks_per_line: u64, // 16.16
    y_tile_minimum: u64,  // 16.16
    linetime_us: u64,
}

#[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
fn params(timing: Timing, surface: Surface) -> Result<Params, WmError> {
    if !matches!(surface.cpp, 1 | 2 | 4 | 8)
        || surface.width == 0
        || surface.width > 8192
        || timing.htotal == 0
        || timing.htotal > 16384
        || !(1..=2 * crate::intel_gpu_xelpg_cdclk::MAX_CDCLK_KHZ).contains(&timing.pixel_rate_khz)
    {
        return Err(WmError::Unsupported);
    }
    params_rules(timing, surface, Rules::Display14)
}

/// The `skl_watermark.c` branches a computation follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rules {
    /// Display 14 and 20.
    Display14,
    /// Display >= 30, with `pan_x != 0` when the surface is panned.
    Display30 { panned: bool },
}

impl Rules {
    const fn for_ip(ip: crate::intel_gpu_xe2lpd::DisplayIp) -> Self {
        match ip {
            crate::intel_gpu_xe2lpd::DisplayIp::Xe3Lpd => Self::Display30 { panned: false },
            _ => Self::Display14,
        }
    }
}

/// [`params`] for `ip`: display 30 also scans out up to twice its
/// 691.2 MHz CDCLK.
fn params_ip(
    ip: crate::intel_gpu_xe2lpd::DisplayIp,
    timing: Timing,
    surface: Surface,
) -> Result<Params, WmError> {
    let max = crate::intel_gpu_xelpg_cdclk::max_cdclk_khz(ip);
    if !matches!(surface.cpp, 1 | 2 | 4 | 8)
        || surface.width == 0
        || surface.width > 8192
        || timing.htotal == 0
        || timing.htotal > 16384
        || !(1..=2 * max).contains(&timing.pixel_rate_khz)
    {
        return Err(WmError::Unsupported);
    }
    params_rules(timing, surface, Rules::for_ip(ip))
}

/// `skl_compute_wm_params` (unrotated, non-planar, 512-byte blocks) after
/// the caller's bounds.
fn params_rules(timing: Timing, surface: Surface, rules: Rules) -> Result<Params, WmError> {
    if timing.htotal == 0 || timing.pixel_rate_khz == 0 {
        return Err(WmError::Unsupported);
    }
    let y_tiled = surface.tiling == Tiling::Tile4;
    let cpp = u64::from(surface.cpp);
    let bytes_per_line = u64::from(surface.width) * cpp;
    // y_min_scanlines: 4 without 90/270 rotation. A Y-tiled surface adds a
    // block on display 10..29, and on display >= 30 only when panned.
    let y_extra = match rules {
        Rules::Display14 => 1,
        Rules::Display30 { panned } => u64::from(panned),
    };
    let blocks_per_line = if y_tiled {
        (((bytes_per_line * 4).div_ceil(BLOCK) + y_extra) * FX).div_ceil(4)
    } else {
        (bytes_per_line.div_ceil(BLOCK) + 1) * FX
    };
    Ok(Params {
        y_tiled,
        cpp,
        bytes_per_line,
        blocks_per_line,
        y_tile_minimum: 4 * blocks_per_line,
        linetime_us: (u64::from(timing.htotal) * 1000).div_ceil(u64::from(timing.pixel_rate_khz)),
    })
}

/// `skl_compute_plane_wm` (display 14).
#[allow(dead_code)]
fn level(timing: Timing, wp: &Params, latency: u32, prev: Level) -> Result<Level, WmError> {
    level_rules(timing, wp, latency, prev, Rules::Display14)
}

/// `skl_compute_plane_wm` under `rules`.
fn level_rules(
    timing: Timing,
    wp: &Params,
    latency: u32,
    prev: Level,
    rules: Rules,
) -> Result<Level, WmError> {
    if latency == 0 {
        return Ok(REJECTED);
    }
    let lat = u64::from(latency);
    let rate = u64::from(timing.pixel_rate_khz);
    // Linux keeps both intermediates in u32; refuse where it would wrap.
    let m1_raw = lat * rate * wp.cpp;
    if m1_raw > u64::from(u32::MAX) || lat * rate > u64::from(u32::MAX) {
        return Err(WmError::Unsupported);
    }
    let method1 = (m1_raw * FX).div_ceil(1000 * BLOCK) + FX;
    let method2 = (lat * rate).div_ceil(u64::from(timing.htotal) * 1000) * wp.blocks_per_line;
    let selected = if wp.y_tiled {
        method2.max(wp.y_tile_minimum)
    } else if (wp.cpp * u64::from(timing.htotal) / BLOCK < 1 && wp.bytes_per_line / BLOCK < 1)
        || u64::from(latency) >= wp.linetime_us
    {
        // Linux keeps these as two branches; display 14 selects method2 in
        // both (only display 9 takes min(method1, method2) on the second).
        method2
    } else {
        method1
    };
    if selected > u64::from(u32::MAX) {
        return Err(WmError::Unsupported);
    }
    // blocks++ only below display 30.
    let mut blocks = selected.div_ceil(FX) + u64::from(rules == Rules::Display14);
    blocks = blocks.max(wp.blocks_per_line.div_ceil(FX));
    let mut lines = selected.div_ceil(wp.blocks_per_line);
    blocks = blocks.max(u64::from(prev.blocks));
    lines = lines.max(u64::from(prev.lines));
    let min_ddb = if wp.y_tiled {
        let extra = if lines % 4 == 0 { 4 } else { 8 - lines % 4 };
        ((lines + extra) * wp.blocks_per_line).div_ceil(FX)
    } else {
        blocks + blocks.div_ceil(10)
    };
    if lines > MAX_LINES {
        return Ok(REJECTED);
    }
    let min_ddb_alloc = min_ddb.max(blocks) + 1;
    // Beyond the 4096-block DBUF any such level is disabled by
    // skl_check_wm_level; refuse values that would truncate Linux's u16.
    if min_ddb_alloc >= u64::from(u16::MAX) {
        return Ok(REJECTED);
    }
    Ok(Level {
        enable: true,
        blocks: blocks as u16,
        lines: lines as u16,
        min_ddb_alloc: min_ddb_alloc as u16,
    })
}

/// `skl_compute_transition_wm` (display >= 11, IPC enabled). A disabled
/// base yields no transition level; Linux's result for that case is
/// discarded by the DDB check because its minimum is `U16_MAX`.
fn transition(wp: &Params, wm0: Level) -> Level {
    if !wm0.enable {
        return Level::default();
    }
    let base = u64::from(wm0.blocks - 1);
    let blocks = if wp.y_tiled {
        base.max((2 * wp.y_tile_minimum).div_ceil(FX))
    } else {
        base
    } + 14
        + 1;
    if blocks + 1 >= u64::from(u16::MAX) {
        return Level::default();
    }
    Level {
        enable: true,
        blocks: blocks as u16,
        lines: 0,
        min_ddb_alloc: wm0.min_ddb_alloc.max(blocks as u16 + 1),
    }
}

/// `skl_build_plane_wm_single` for display 14: levels, transition, SAGV.
#[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
pub(crate) fn plane(
    timing: Timing,
    surface: Surface,
    latency: &Latency,
) -> Result<PlaneWm, WmError> {
    let wp = params(timing, surface)?;
    plane_with(timing, &wp, latency, Rules::Display14)
}

/// [`plane`] on `ip` (display 30: no added block, unpanned Tile4).
pub(crate) fn plane_ip(
    ip: crate::intel_gpu_xe2lpd::DisplayIp,
    timing: Timing,
    surface: Surface,
    latency: &Latency,
) -> Result<PlaneWm, WmError> {
    let wp = params_ip(ip, timing, surface)?;
    plane_with(timing, &wp, latency, Rules::for_ip(ip))
}

fn plane_with(
    timing: Timing,
    wp: &Params,
    latency: &Latency,
    rules: Rules,
) -> Result<PlaneWm, WmError> {
    let mut wm = PlaneWm::default();
    let mut prev = Level::default();
    for (slot, &lat) in wm.levels.iter_mut().zip(&latency.levels) {
        *slot = level_rules(timing, wp, u32::from(lat), prev, rules)?;
        prev = *slot;
    }
    wm.trans = transition(wp, wm.levels[0]);
    let sagv_latency = if latency.sagv_block_us == 0 {
        0
    } else {
        u32::from(latency.sagv_block_us) + u32::from(latency.levels[0])
    };
    wm.sagv = level_rules(timing, wp, sagv_latency, wm.levels[0], rules)?;
    wm.sagv_trans = transition(wp, wm.sagv);
    Ok(wm)
}

/// `skl_wm0_prefill_lines_worst` on display 30 (.16 lines): the level-0
/// lines of an `XBGR16161616F` (cpp 8) Tile4 primary of `width` pixels at
/// `pixel_rate_khz`, panned (`pan_x` 1), on the pipe's `htotal`; a rejected
/// level counts `skl_wm_max_lines()`. The caller supplies the scaled width
/// and pixel rate (`skl_scaler_max_hscale`, `skl_scaler_max_total_scale`).
/// Linux keeps the method intermediates in u32; a computation that would
/// wrap them is refused.
pub(crate) fn wm0_prefill_lines_worst_xe3(
    pixel_rate_khz: u32,
    htotal: u32,
    width: u32,
    latency: &Latency,
) -> Result<u64, WmError> {
    if width == 0 || htotal == 0 || htotal > 16384 || pixel_rate_khz == 0 {
        return Err(WmError::Unsupported);
    }
    let timing = Timing {
        pixel_rate_khz,
        htotal,
        vtotal: 0,
        vblank_start: 0,
    };
    let surface = Surface {
        width,
        cpp: 8,
        tiling: Tiling::Tile4,
    };
    let rules = Rules::Display30 { panned: true };
    let wp = params_rules(timing, surface, rules)?;
    let wm = level_rules(
        timing,
        &wp,
        u32::from(latency.levels[0]),
        Level::default(),
        rules,
    )?;
    let lines = if wm.min_ddb_alloc == u16::MAX {
        MAX_LINES
    } else {
        u64::from(wm.lines)
    };
    Ok(lines << 16)
}

/// `intel_display.c::skl_linetime_wm` for an enabled pipe on display 14:
/// the line time in 1/8 µs, `DIV_ROUND_UP(crtc_htotal * 1000 * 8,
/// pixel_rate)`, capped at 0x1ff (Display WA #1135 halves it only on
/// BXT/GLK). `hsw_crtc_supports_ips` is HSW/BDW only, so the IPS line time
/// `WM_LINETIME` also carries is 0 here.
pub(crate) fn linetime(timing: Timing) -> Result<u32, WmError> {
    if timing.pixel_rate_khz == 0 || timing.htotal == 0 {
        return Err(WmError::Unsupported);
    }
    let lines = (u64::from(timing.htotal) * 1000 * 8).div_ceil(u64::from(timing.pixel_rate_khz));
    Ok(lines.min(0x1ff) as u32)
}

/// `skl_cursor_allocation`.
#[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
pub(crate) fn cursor_allocation(
    timing: Timing,
    latency: &Latency,
    num_active: u32,
) -> Result<u16, WmError> {
    let wp = params(
        timing,
        Surface {
            width: CURSOR_ALLOC_WIDTH,
            cpp: 4,
            tiling: Tiling::Linear,
        },
    )?;
    cursor_allocation_with(timing, &wp, latency, num_active, Rules::Display14)
}

/// [`cursor_allocation`] on `ip`.
pub(crate) fn cursor_allocation_ip(
    ip: crate::intel_gpu_xe2lpd::DisplayIp,
    timing: Timing,
    latency: &Latency,
    num_active: u32,
) -> Result<u16, WmError> {
    let wp = params_ip(
        ip,
        timing,
        Surface {
            width: CURSOR_ALLOC_WIDTH,
            cpp: 4,
            tiling: Tiling::Linear,
        },
    )?;
    cursor_allocation_with(timing, &wp, latency, num_active, Rules::for_ip(ip))
}

fn cursor_allocation_with(
    timing: Timing,
    wp: &Params,
    latency: &Latency,
    num_active: u32,
    rules: Rules,
) -> Result<u16, WmError> {
    let mut wm = Level::default();
    let mut min_ddb_alloc = 0u16;
    for &lat in &latency.levels {
        // skl_compute_plane_wm(.., &wm, &wm): a rejected level only sets
        // min_ddb_alloc, keeping the prior blocks/lines.
        let next = level_rules(timing, wp, u32::from(lat), wm, rules)?;
        if next.min_ddb_alloc == u16::MAX {
            break;
        }
        wm = next;
        min_ddb_alloc = wm.min_ddb_alloc;
    }
    Ok(min_ddb_alloc.max(if num_active == 1 { 32 } else { 8 }))
}

/// `prefill_usecs_to_lines` (.16 lines).
fn usecs_to_lines(timing: Timing, us: u32) -> u64 {
    (u64::from(timing.pixel_rate_khz) * (u64::from(us) << 16))
        .div_ceil(u64::from(timing.htotal) * 1000)
}

/// `struct skl_prefill_ctx` after `skl_prefill_init` for an unscaled,
/// non-VRR pipe with `framestart_delay == 1`.
struct Prefill {
    timing: Timing,
    /// `prefill.full` (.16 lines).
    full: u64,
    /// `prefill_guardband` (.16 lines).
    guardband: u64,
}

impl Prefill {
    /// `skl_prefill_init` with `skl_wm0_prefill_lines` = `wm0_lines`, the
    /// worst level-0 lines of the pipe's planes (`skl_max_wm0_lines`), and
    /// `prefill.dsc` = `intel_vdsc_prefill_lines` when the pipe compresses.
    fn new(timing: Timing, wm0_lines: u16, dsc: bool) -> Result<Self, WmError> {
        Self::new_ip(
            crate::intel_gpu_xe2lpd::DisplayIp::Xelpdp,
            timing,
            wm0_lines,
            dsc,
        )
    }

    /// [`Prefill::new`] with `ip`'s CDCLK table (`calc_cdclk`). The
    /// guardband is `timing.vtotal - timing.vblank_start`
    /// (`intel_crtc_vblank_length` without VRR).
    fn new_ip(
        ip: crate::intel_gpu_xe2lpd::DisplayIp,
        timing: Timing,
        wm0_lines: u16,
        dsc: bool,
    ) -> Result<Self, WmError> {
        Self::new_ip_scaler(ip, timing, wm0_lines, dsc, false)
    }

    /// [`Prefill::new_ip`] with crtc scaler prefill lines factored in.
    fn new_ip_scaler(
        ip: crate::intel_gpu_xe2lpd::DisplayIp,
        timing: Timing,
        wm0_lines: u16,
        dsc: bool,
        scaler: bool,
    ) -> Result<Self, WmError> {
        if timing.vtotal <= timing.vblank_start || timing.htotal == 0 {
            return Err(WmError::Unsupported);
        }
        // prefill_init: framestart_delay 1 + 20 us of translation walks.
        let fixed = (1u64 << 16) + usecs_to_lines(timing, 20);
        // prefill_lines_nocdclk: DSC (1.5 lines when compressing),
        // scaler (4.0 lines on display 14 when crtc scaler is enabled),
        // then the worst wm0 lines.
        let dsc = if dsc {
            crate::intel_gpu_xelpg_dsc::PREFILL_LINES
        } else {
            0
        };
        let scaler = if scaler {
            let (first, _) = crate::intel_gpu_xelpg_scaler::prefill_lines(1, true);
            first
        } else {
            0
        };
        let wm0 = dsc + scaler + (u64::from(wm0_lines) << 16);
        // intel_cdclk_prefill_adjustment(_worst): calc_cdclk at the
        // pixel-rate minimum, ppc 2.
        let cdclk = crate::intel_gpu_xelpg_cdclk::calc_cdclk_ip(
            ip,
            crate::intel_gpu_xelpg_cdclk::pixel_rate_to_cdclk(timing.pixel_rate_khz),
        )
        .ok_or(WmError::Unsupported)?
        .cdclk_khz;
        let adj = ((u64::from(timing.pixel_rate_khz) << 16).div_ceil(2 * u64::from(cdclk))).min(FX);
        Ok(Self {
            timing,
            full: fixed + (wm0 * adj).div_ceil(FX),
            guardband: u64::from(timing.vtotal - timing.vblank_start) << 16,
        })
    }

    /// `skl_prefill_vblank_too_short`.
    fn too_short(&self, us: u32) -> bool {
        self.guardband < self.full + usecs_to_lines(self.timing, us)
    }

    /// `skl_max_wm_level_for_vblank`: the highest level with a non-zero
    /// latency whose prefill fits vblank (level 0 at zero latency).
    fn max_level(&self, latency: &Latency) -> Result<usize, WmError> {
        for (l, &lat) in latency.levels.iter().enumerate().rev() {
            if lat == 0 {
                continue;
            }
            let lat = if l == 0 { 0 } else { u32::from(lat) };
            if !self.too_short(lat) {
                return Ok(l);
            }
        }
        Err(WmError::VblankTooShort)
    }
}

/// `skl_wm_check_vblank`'s `crtc_state->wm_level_disabled` for display 14
/// (`display->wm.num_levels == 6`): whether the highest level that fits
/// the vblank prefill is below the top level. A zero latency level never
/// fits, so a latency table that ends early also reports true, exactly as
/// Linux does. `wm0_lines` is the worst level-0 lines over the pipe's
/// planes (`skl_max_wm0_lines`).
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn wm_level_disabled(
    timing: Timing,
    latency: &Latency,
    wm0_lines: u16,
) -> Result<bool, WmError> {
    wm_level_disabled_dsc(timing, latency, wm0_lines, false)
}

/// `skl_wm_check_vblank`'s `wm_level_disabled` (see `wm_level_disabled`)
/// for a pipe that compresses (`dsc`) or not.
pub(crate) fn wm_level_disabled_dsc(
    timing: Timing,
    latency: &Latency,
    wm0_lines: u16,
    dsc: bool,
) -> Result<bool, WmError> {
    Ok(Prefill::new(timing, wm0_lines, dsc)?.max_level(latency)? < LEVELS - 1)
}

/// [`wm_level_disabled_dsc`] on `ip`.
pub(crate) fn wm_level_disabled_dsc_ip(
    ip: crate::intel_gpu_xe2lpd::DisplayIp,
    timing: Timing,
    latency: &Latency,
    wm0_lines: u16,
    dsc: bool,
) -> Result<bool, WmError> {
    Ok(Prefill::new_ip(ip, timing, wm0_lines, dsc)?.max_level(latency)? < LEVELS - 1)
}

/// `skl_wm_check_vblank` for a pipe whose planes are `planes`. Levels that
/// cannot complete prefill inside vblank lose their enable bit (keeping
/// blocks/lines, as Linux does); SAGV levels likewise when the block time
/// does not fit. No fitting level is a typed refusal. Returns the pipe's
/// `wm_level_disabled` (Wa_14015648006's input, see [`wm_level_disabled`]).
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn check_vblank(
    timing: Timing,
    latency: &Latency,
    planes: &mut [&mut PlaneWm],
) -> Result<bool, WmError> {
    check_vblank_dsc(timing, latency, planes, false)
}

/// `skl_wm_check_vblank` (see `check_vblank`) for a pipe that compresses
/// (`dsc`) or not.
#[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
pub(crate) fn check_vblank_dsc(
    timing: Timing,
    latency: &Latency,
    planes: &mut [&mut PlaneWm],
    dsc: bool,
) -> Result<bool, WmError> {
    check_vblank_dsc_ip(
        crate::intel_gpu_xe2lpd::DisplayIp::Xelpdp,
        timing,
        latency,
        planes,
        dsc,
    )
}

/// [`check_vblank_dsc`] on `ip` with `scaler`.
pub(crate) fn check_vblank_dsc_scaler_ip(
    ip: crate::intel_gpu_xe2lpd::DisplayIp,
    timing: Timing,
    latency: &Latency,
    planes: &mut [&mut PlaneWm],
    dsc: bool,
    scaler: bool,
) -> Result<bool, WmError> {
    let wm0 = planes.iter().map(|p| p.levels[0].lines).max().unwrap_or(0);
    let prefill = Prefill::new_ip_scaler(ip, timing, wm0, dsc, scaler)?;
    let max_level = prefill.max_level(latency)?;
    for plane in planes.iter_mut() {
        for level in plane.levels.iter_mut().skip(max_level + 1) {
            level.enable = false;
        }
    }
    if latency.sagv_block_us != 0 && prefill.too_short(u32::from(latency.sagv_block_us)) {
        for plane in planes.iter_mut() {
            plane.sagv.enable = false;
            plane.sagv_trans.enable = false;
        }
    }
    Ok(max_level < LEVELS - 1)
}

/// [`check_vblank_dsc`] on `ip`.
pub(crate) fn check_vblank_dsc_ip(
    ip: crate::intel_gpu_xe2lpd::DisplayIp,
    timing: Timing,
    latency: &Latency,
    planes: &mut [&mut PlaneWm],
    dsc: bool,
) -> Result<bool, WmError> {
    check_vblank_dsc_scaler_ip(ip, timing, latency, planes, dsc, false)
}

// ── Wa_14015648006's Pipe-A input ─────────────────────────────────

const PIPE_A_UNKNOWN: u8 = 0;
const PIPE_A_CLEAR: u8 = 1;
const PIPE_A_DISABLED: u8 = 2;

/// The Pipe-A `wm_level_disabled` of the watermarks last proved programmed
/// (one integrated display per system). Lock-free: the PSR provider reads
/// it without touching registers.
static PIPE_A_WM_LEVEL_DISABLED: AtomicU8 = AtomicU8::new(PIPE_A_UNKNOWN);

/// Record the Pipe-A `wm_level_disabled` of the watermarks a resource owner
/// just proved programmed (`Some`), or that no programmed state is proved
/// (`None`: before a write, while a new image is pending, or after a
/// failed verification).
pub(crate) fn publish_pipe_a(value: Option<bool>) {
    let raw = match value {
        None => PIPE_A_UNKNOWN,
        Some(false) => PIPE_A_CLEAR,
        Some(true) => PIPE_A_DISABLED,
    };
    PIPE_A_WM_LEVEL_DISABLED.store(raw, Ordering::Release);
}

/// The [`crate::intel_gpu_psr::WmLevelProvider`]: Pipe A's published
/// `wm_level_disabled`, `None` while no programmed state is proved.
pub(crate) fn pipe_a_wm_level_disabled() -> Option<bool> {
    match PIPE_A_WM_LEVEL_DISABLED.load(Ordering::Acquire) {
        PIPE_A_CLEAR => Some(false),
        PIPE_A_DISABLED => Some(true),
        _ => None,
    }
}

/// Register [`pipe_a_wm_level_disabled`] as PSR's Wa_14015648006 input.
pub(crate) fn register_psr_provider() {
    crate::intel_gpu_psr::register_wm_level_disabled(Some(pipe_a_wm_level_disabled));
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_wm_tests.rs"]
mod tests;
