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
//!   non-DSC, non-VRR pipe with `framestart_delay == 1`.
//!
//! Gen12 keeps its own transcription in [`crate::intel_gpu_wm`]; nothing
//! here changes Gen12 results.

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
        Ok(Self::adjust(raw, (sagv & LEVEL_MASK) as u16))
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
    let y_tiled = surface.tiling == Tiling::Tile4;
    let cpp = u64::from(surface.cpp);
    let bytes_per_line = u64::from(surface.width) * cpp;
    // y_min_scanlines: 4 without 90/270 rotation.
    let blocks_per_line = if y_tiled {
        (((bytes_per_line * 4).div_ceil(BLOCK) + 1) * FX).div_ceil(4)
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
fn level(timing: Timing, wp: &Params, latency: u32, prev: Level) -> Result<Level, WmError> {
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
    } else if wp.cpp * u64::from(timing.htotal) / BLOCK < 1 && wp.bytes_per_line / BLOCK < 1 {
        method2
    } else if u64::from(latency) >= wp.linetime_us {
        method2
    } else {
        method1
    };
    if selected > u64::from(u32::MAX) {
        return Err(WmError::Unsupported);
    }
    let mut blocks = selected.div_ceil(FX) + 1;
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
pub(crate) fn plane(
    timing: Timing,
    surface: Surface,
    latency: &Latency,
) -> Result<PlaneWm, WmError> {
    let wp = params(timing, surface)?;
    let mut wm = PlaneWm::default();
    let mut prev = Level::default();
    for l in 0..LEVELS {
        wm.levels[l] = level(timing, &wp, u32::from(latency.levels[l]), prev)?;
        prev = wm.levels[l];
    }
    wm.trans = transition(&wp, wm.levels[0]);
    let sagv_latency = if latency.sagv_block_us == 0 {
        0
    } else {
        u32::from(latency.sagv_block_us) + u32::from(latency.levels[0])
    };
    wm.sagv = level(timing, &wp, sagv_latency, wm.levels[0])?;
    wm.sagv_trans = transition(&wp, wm.sagv);
    Ok(wm)
}

/// `skl_cursor_allocation`.
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
    let mut wm = Level::default();
    let mut min_ddb_alloc = 0u16;
    for l in 0..LEVELS {
        // skl_compute_plane_wm(.., &wm, &wm): a rejected level only sets
        // min_ddb_alloc, keeping the prior blocks/lines.
        let next = level(timing, &wp, u32::from(latency.levels[l]), wm)?;
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

/// `skl_wm_check_vblank` for a pipe whose planes are `planes`. Levels that
/// cannot complete prefill inside vblank lose their enable bit (keeping
/// blocks/lines, as Linux does); SAGV levels likewise when the block time
/// does not fit. No fitting level is a typed refusal.
pub(crate) fn check_vblank(
    timing: Timing,
    latency: &Latency,
    planes: &mut [&mut PlaneWm],
) -> Result<(), WmError> {
    if timing.vtotal <= timing.vblank_start || timing.htotal == 0 {
        return Err(WmError::Unsupported);
    }
    // prefill_init: framestart_delay 1 + 20 us of translation walks.
    let fixed = (1u64 << 16) + usecs_to_lines(timing, 20);
    // No DSC/scalers: nocdclk prefill is the worst wm0 lines.
    let wm0 = u64::from(planes.iter().map(|p| p.levels[0].lines).max().unwrap_or(0)) << 16;
    // intel_cdclk_prefill_adjustment(_worst): calc_cdclk at the pixel-rate
    // minimum, ppc 2.
    let cdclk = crate::intel_gpu_xelpg_cdclk::calc_cdclk(
        crate::intel_gpu_xelpg_cdclk::pixel_rate_to_cdclk(timing.pixel_rate_khz),
    )
    .ok_or(WmError::Unsupported)?
    .cdclk_khz;
    let adj = ((u64::from(timing.pixel_rate_khz) << 16).div_ceil(2 * u64::from(cdclk))).min(FX);
    let full = fixed + (wm0 * adj).div_ceil(FX);
    let guardband = u64::from(timing.vtotal - timing.vblank_start) << 16;
    let too_short = |us: u32| guardband < full + usecs_to_lines(timing, us);
    let mut max_level = None;
    for l in (0..LEVELS).rev() {
        let lat = latency.levels[l];
        if lat == 0 {
            continue;
        }
        let lat = if l == 0 { 0 } else { u32::from(lat) };
        if !too_short(lat) {
            max_level = Some(l);
            break;
        }
    }
    let max_level = max_level.ok_or(WmError::VblankTooShort)?;
    for plane in planes.iter_mut() {
        for l in max_level + 1..LEVELS {
            plane.levels[l].enable = false;
        }
    }
    if latency.sagv_block_us != 0 && too_short(u32::from(latency.sagv_block_us)) {
        for plane in planes.iter_mut() {
            plane.sagv.enable = false;
            plane.sagv_trans.enable = false;
        }
    }
    Ok(())
}
