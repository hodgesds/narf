//! Gen11 (Ice Lake / Elkhart Lake / Jasper Lake) latency-based plane
//! watermarks + DBUF allocation.
//!
//! The SKL watermark method (`display/skl_watermark.c`), transcribed
//! for DISPLAY_VER 11 and scoped to this driver's shape, following
//! the `intel_gpu_wm.rs` (Gen12) pattern:
//!
//! - **Gen11 only.** Version-gated branches in the reference that
//!   select other generations are resolved at transcription time
//!   and noted where they mattered.
//! - **Linear (untiled) surfaces only.** The driver scans out
//!   linear XRGB8888; the Y-tiled branches of the reference
//!   (plane_blocks_per_line rounding, y_tile_minimum floors) are
//!   not reachable and not transcribed.
//! - **One pipe, one universal plane.** DDB allocation is the
//!   degenerate single-consumer case of the reference's
//!   proportional allocator: the pipe's primary plane receives
//!   the whole DBUF. Slice *arbitration* between pipes is
//!   multi-pipe work; both slices are powered and the allocation
//!   spans both (see the DBUF section below).
//!
//! ## Gen11 deltas against the Gen12 module
//!
//! - **8 regular levels, not 6.** `skl_setup_wm_latency` sets
//!   `num_levels = 6` only when `HAS_HW_SAGV_WM` (DISPLAY_VER >= 13);
//!   on Gen11 it is 8. There is no SAGV watermark on Gen11 at all:
//!   `HAS_SAGV_WM` is DISPLAY_VER >= 12, so `skl_build_plane_wm_single`
//!   never computes one here — `PlaneWatermarks` has no `sagv` /
//!   `sagv_trans` fields. (`can_sagv`, the per-level SAGV-admission
//!   flag, feeds the power manager's SAGV enable decision; the
//!   Gen11 power lane annotates it with [`apply_sagv_admission`]
//!   — it is not a watermark register.)
//! - **WaWmMemoryReadLatency adds 2 µs, not 3.** `wm_read_latency`
//!   returns 2 below DISPLAY_VER 12 (3 on Gen12, 6 on Gen14+).
//! - **The 16 Gb-DIMM workaround applies on Gen11.**
//!   `need_16gb_dimm_wa` lists SKL/KBL/CFL/CML **and DISPLAY_VER 11**:
//!   with 16 Gb DIMMs fitted, every valid level gains a further
//!   1 µs. The DIMM size is a caller input (`has_16gb_dimms`);
//!   Linux reads it from the DRAM info, this driver does not model
//!   DIMMs yet.
//! - Transition watermarks are the same as Gen12: trans_min 4 +
//!   trans_amount 10 (DISPLAY_VER >= 11; Gen9 has no transition
//!   watermarks at all — `WaDisableTWM`). Linux also requires IPC
//!   enabled (`skl_watermark_ipc_enabled`); this module follows
//!   the Gen12 module in computing them unconditionally — the
//!   modeset that programs them runs with IPC on.
//! - DBUF geometry is the same as Gen12: 2048 blocks total, slices
//!   S1|S2, 512-byte blocks (`ICL_DISPLAY` in
//!   `display/intel_display_device.c`).
//!
//! ## Algorithm (per plane, per level)
//!
//! 1. Memory latencies come from the pcode mailbox
//!    ([`crate::intel_gpu_pcode`]), then `adjust_latencies`
//!    sanitises them exactly as the reference does.
//! 2. `method1` = latency × pixel_rate × cpp / (1000 ×
//!    block_size), plus 1 block (DISPLAY_VER ≥ 10 rule);
//!    `method2` = ceil(latency × pixel_rate / (htotal × 1000))
//!    × plane_blocks_per_line. Selection (non-tiled, ver ≥ 10):
//!    method2 when the mode is tiny in both dimensions, or when
//!    latency ≥ linetime; method1 otherwise. (DISPLAY_VER 9 takes
//!    min(method1, method2) in the second case — not Gen11.)
//! 3. Result blocks = ceil(selected) + 1, floored at
//!    plane_blocks_per_line; lines = ceil(selected /
//!    plane_blocks_per_line); blocks/lines are clamped
//!    monotonically non-decreasing across levels.
//!    min_ddb_alloc = blocks + ceil(blocks/10), then +1
//!    ("value >= plane ddb allocation → invalid", PRM).
//! 4. A level with latency 0, or needing more than 31 lines
//!    (`skl_wm_max_lines`: 31 below DISPLAY_VER 13), is rejected.
//!    A level whose min_ddb_alloc exceeds the plane's DDB
//!    allocation is disabled at validation time
//!    (`skl_check_wm_level`).
//! 5. Transition watermarks: wm0 blocks + 14 (trans_min 4 +
//!    trans_amount 10, DISPLAY_VER ≥ 11).
//!
//! Deliberately NOT transcribed: the DG2 ×2 latency multiply
//! (discrete part) and the cursor-allocation special case
//! (`skl_cursor_allocation`, min 32 blocks single-pipe / 8
//! multi-pipe), which belongs to the cursor lane. The SAGV
//! *control* pcode command belongs to the power manager
//! (`intel_gpu_gen11_sagv`): on display 11 it is the QGV-point
//! restriction via `ICL_PCODE_SAGV_DE_MEM_SS_CONFIG` (0xe),
//! not `GEN9_PCODE_SAGV_CONTROL` (0x21) — that is the
//! pre-ICL (display 9) mechanism. This module only computes
//! the levels; the per-level SAGV admission flag (`can_sagv`)
//! is annotated by [`apply_sagv_admission`].
//!
//! ## DBUF_CTL power sequencing
//!
//! `DBUF_CTL` per slice (`display/skl_watermark_regs.h`):
//! S1 at 0x45008, S2 at 0x44FE8 — *not* a uniform stride from
//! a base; the register file scatters them. POWER_REQUEST is
//! bit 31, POWER_STATE (grant) is bit 30. The modeset sets
//! REQUEST for both slices and polls STATE before programming
//! any watermark, so the DDB blocks the watermarks point at
//! are backed by powered SRAM. The tracker-state-service
//! fields (bits [23:16]) belong to the MDCLK/CDCLK-ratio and
//! joined-MBUS machinery (multi-pipe); this driver's request
//! write is read-modify-write and leaves them at their
//! firmware values.

use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu_aux::MmioWindow;

/// Regular watermark levels on Gen11 (no HW SAGV WM takes
/// slots 6/7 here — `skl_setup_wm_latency` sets 8).
pub const NUM_WM_LEVELS: usize = 8;

/// DBUF block size in bytes on Gen11.
pub const DBUF_BLOCK_SIZE: u32 = 512;
/// Total DBUF blocks on Gen11 (both slices).
pub const DBUF_TOTAL_BLOCKS: u16 = 2048;
/// Blocks per DBUF slice on Gen11 (2048 blocks / 2 slices).
pub const DBUF_SLICE_BLOCKS: u16 = 1024;
/// Number of DBUF slices on Gen11.
pub const DBUF_SLICES: u32 = 2;

/// PLANE_WM lines field ceiling on Gen11 (`skl_wm_max_lines`:
/// 31 below DISPLAY_VER 13).
const WM_MAX_LINES: u32 = 31;

// ── Latency adjustment (i915 adjust_wm_latency, Gen11) ─────

/// Adjust the raw pcode latency table the way the reference
/// driver does before computing watermarks. Input is the full
/// 8-level table; Gen11 uses all 8 levels.
///
/// Steps, in reference order:
/// 1. **Sanitize** — the first zero level at index ≥ 1 marks
///    the end of the valid range; every level past it is zeroed.
/// 2. **Monotonic** — each level is raised to at least the
///    previous level's value, stopping at the first zero.
/// 3. **WaWmMemoryReadLatency** — when level 0 reads back 0,
///    the punit has not accounted for read latency; add 2 µs
///    (the DISPLAY_VER < 12 value) to level 0 and every
///    subsequent nonzero level.
/// 4. **16 Gb-DIMM workaround** — when `has_16gb_dimms`, add
///    a further 1 µs to level 0 and every subsequent nonzero
///    level (`need_16gb_dimm_wa` covers DISPLAY_VER 11).
pub fn adjust_latencies(raw: &[u16; 8], has_16gb_dimms: bool) -> [u16; NUM_WM_LEVELS] {
    let mut wm = *raw;

    // 1. Sanitize.
    let mut first_zero = NUM_WM_LEVELS;
    for (level, &lat) in wm.iter().enumerate().skip(1) {
        if lat == 0 {
            first_zero = level;
            break;
        }
    }
    for slot in wm.iter_mut().skip(first_zero + 1) {
        *slot = 0;
    }

    // 2. Monotonic clamp.
    for level in 1..NUM_WM_LEVELS {
        if wm[level] == 0 {
            break;
        }
        wm[level] = wm[level].max(wm[level - 1]);
    }

    // 3 + 4. Latency increases (each stops at the first zero
    // past level 0; level 0 always gains the increase).
    let increase = |wm: &mut [u16; NUM_WM_LEVELS], inc: u16| {
        wm[0] += inc;
        for slot in wm.iter_mut().skip(1) {
            if *slot == 0 {
                break;
            }
            *slot += inc;
        }
    };
    if wm[0] == 0 {
        increase(&mut wm, 2);
    }
    if has_16gb_dimms {
        increase(&mut wm, 1);
    }
    wm
}

// ── Watermark computation ────────────────────────────────────

/// One computed watermark level. A disabled level is all-zero
/// and encodes to a zero PLANE_WM word.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WmLevel {
    pub enable: bool,
    /// Result blocks (FIFO depth the level requests).
    pub blocks: u16,
    /// Result lines.
    pub lines: u16,
    /// Minimum DDB allocation this level needs to be usable;
    /// compared against the plane's allocation at validation.
    pub min_ddb_alloc: u16,
    /// Per-level SAGV admission (`skl_compute_wm_levels`):
    /// this level tolerates the SAGV block time. Annotated by
    /// [`apply_sagv_admission`], not by the level computation
    /// itself — the block time comes from the pcode read, not
    /// the watermark inputs.
    pub can_sagv: bool,
}

/// The full watermark set for one plane on Gen11: 8 latency
/// levels and the transition watermark. No SAGV watermark:
/// `HAS_SAGV_WM` is DISPLAY_VER >= 12.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PlaneWatermarks {
    pub levels: [WmLevel; NUM_WM_LEVELS],
    pub trans: WmLevel,
}

/// Inputs the Gen11 linear-surface algorithm needs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WmParams {
    /// Pixel rate in kHz (the mode's pixel clock for a
    /// full-screen primary plane).
    pub pixel_rate_khz: u32,
    /// Horizontal total (active + blanking), in pixels.
    pub htotal: u32,
    /// Plane width in pixels.
    pub width_px: u32,
    /// Bytes per pixel (4 for XRGB8888).
    pub cpp: u32,
}

impl WmParams {
    /// Bytes in one scanline of the plane surface.
    fn plane_bytes_per_line(&self) -> u32 {
        self.width_px * self.cpp
    }

    /// `plane_blocks_per_line` for a linear surface:
    /// ceil(bytes_per_line / block_size) + 1 (the +1 applies
    /// to every non-Y-tiled surface at DISPLAY_VER ≥ 10).
    fn plane_blocks_per_line(&self) -> u32 {
        self.plane_bytes_per_line().div_ceil(DBUF_BLOCK_SIZE) + 1
    }

    /// Line time in whole microseconds, rounded up.
    fn linetime_us(&self) -> u32 {
        (self.htotal * 1000).div_ceil(self.pixel_rate_khz)
    }
}

/// Internal level with headroom; the public `WmLevel` narrows
/// after the rejection checks have run.
#[derive(Copy, Clone, Default)]
struct RawLevel {
    enable: bool,
    blocks: u32,
    lines: u32,
    min_ddb_alloc: u32,
}

/// Fixed-point 16.16 helpers (the reference computes in
/// uint_fixed_16_16_t; u64 backing removes overflow concern at
/// pixel rates up to ~2 GHz with worst-case 255 µs latencies).
const FX_ONE: u64 = 1 << 16;

fn fx_ceil(fx: u64) -> u64 {
    fx.div_ceil(FX_ONE)
}

/// `skl_compute_plane_wm`, Gen11 + linear surface. `prev` is
/// the previous level's result for the monotonic clamp (a
/// zeroed level for level 0).
fn compute_level(params: &WmParams, latency_us: u32, prev: &RawLevel) -> RawLevel {
    const REJECTED: RawLevel = RawLevel {
        enable: false,
        blocks: 0,
        lines: 0,
        min_ddb_alloc: u16::MAX as u32,
    };
    if latency_us == 0 {
        return REJECTED;
    }
    let lat = latency_us as u64;
    let pixel_rate = params.pixel_rate_khz as u64;
    let pbpl = params.plane_blocks_per_line() as u64;

    // method1: latency * pixel_rate * cpp / (1000 * block_size),
    // plus 1 (DISPLAY_VER >= 10).
    let method1 =
        (lat * pixel_rate * params.cpp as u64) * FX_ONE / (1000 * DBUF_BLOCK_SIZE as u64) + FX_ONE;
    // method2: ceil(latency * pixel_rate / (htotal * 1000)) *
    // plane_blocks_per_line.
    let method2 = (lat * pixel_rate).div_ceil(params.htotal as u64 * 1000) * pbpl * FX_ONE;

    // Selection (non-Y-tiled, DISPLAY_VER 11).
    let tiny = params.cpp * params.htotal / DBUF_BLOCK_SIZE < 1
        && params.plane_bytes_per_line() / DBUF_BLOCK_SIZE < 1;
    let selected = if tiny || latency_us >= params.linetime_us() {
        method2
    } else {
        method1
    };

    let mut blocks = fx_ceil(selected) + 1;
    // With lines in use, blocks cover at least one line.
    blocks = blocks.max(pbpl);
    let mut lines = selected.div_ceil(pbpl * FX_ONE);
    // Monotonic clamp against the previous level.
    blocks = blocks.max(prev.blocks as u64);
    lines = lines.max(prev.lines as u64);

    if lines > WM_MAX_LINES as u64 {
        return REJECTED;
    }
    // min_ddb_alloc (DISPLAY_VER >= 11, non-Y-tiled):
    // blocks + ceil(blocks / 10); the level's own requirement
    // is max(that, blocks) + 1. The u16 gate below bounds
    // blocks too (min_alloc > blocks), so the narrowing casts
    // in the result cannot truncate.
    let min_ddb = blocks + blocks.div_ceil(10);
    let min_alloc = min_ddb.max(blocks) + 1;
    if min_alloc > u16::MAX as u64 {
        return REJECTED;
    }
    RawLevel {
        enable: true,
        blocks: blocks as u32,
        lines: lines as u32,
        min_ddb_alloc: min_alloc as u32,
    }
}

/// `skl_compute_transition_wm`, Gen11: trans_min 4 +
/// trans_amount 10 on top of the base level's blocks.
fn compute_transition(wm0: &RawLevel) -> RawLevel {
    if !wm0.enable {
        return RawLevel::default();
    }
    // blocks = (wm0.blocks - 1) + (4 + 10) + 1 = wm0.blocks + 14.
    let blocks = wm0.blocks + 14;
    RawLevel {
        enable: true,
        blocks,
        lines: 0,
        min_ddb_alloc: wm0.min_ddb_alloc.max(blocks + 1),
    }
}

fn narrow(raw: RawLevel) -> WmLevel {
    if !raw.enable {
        return WmLevel::default();
    }
    WmLevel {
        enable: true,
        blocks: raw.blocks as u16,
        lines: raw.lines as u16,
        min_ddb_alloc: raw.min_ddb_alloc as u16,
        // SAGV admission is annotated separately by
        // apply_sagv_admission; a fresh level admits nothing.
        can_sagv: false,
    }
}

/// Compute the full watermark set for one plane. Unvalidated:
/// run [`validate_watermarks`] with the plane's DDB allocation
/// before programming.
pub fn compute_plane_watermarks(
    params: &WmParams,
    latencies: &[u16; NUM_WM_LEVELS],
) -> PlaneWatermarks {
    let mut raw_levels = [RawLevel::default(); NUM_WM_LEVELS];
    let mut prev = RawLevel::default();
    for (level, raw) in raw_levels.iter_mut().enumerate() {
        *raw = compute_level(params, latencies[level] as u32, &prev);
        prev = *raw;
    }
    let trans = compute_transition(&raw_levels[0]);

    PlaneWatermarks {
        levels: [
            narrow(raw_levels[0]),
            narrow(raw_levels[1]),
            narrow(raw_levels[2]),
            narrow(raw_levels[3]),
            narrow(raw_levels[4]),
            narrow(raw_levels[5]),
            narrow(raw_levels[6]),
            narrow(raw_levels[7]),
        ],
        trans: narrow(trans),
    }
}

/// `skl_check_wm_level`: a level whose minimum DDB allocation
/// exceeds the plane's allocation is disabled outright.
fn check_level(level: &mut WmLevel, ddb_size: u16) {
    if level.min_ddb_alloc > ddb_size {
        *level = WmLevel::default();
    }
}

/// Disable every watermark in the set that the plane's DDB
/// allocation cannot satisfy.
pub fn validate_watermarks(wm: &mut PlaneWatermarks, ddb_size: u16) {
    for level in wm.levels.iter_mut() {
        check_level(level, ddb_size);
    }
    check_level(&mut wm.trans, ddb_size);
}

// ── Per-level SAGV admission (Gen11 power lane) ─────────────

/// Annotate each level's SAGV admission from the adjusted
/// latency table and the pcode SAGV block time
/// (`skl_compute_wm_levels`: `if (!HAS_SAGV_WM(display) &&
/// display->sagv.block_time_us) result->can_sagv = latency >=
/// display->sagv.block_time_us`). Gen11 has no SAGV watermark
/// register (`HAS_SAGV_WM` is DISPLAY_VER >= 12), so the
/// admission flag is the whole SAGV story at the watermark
/// layer: a level admits SAGV exactly when its latency covers
/// the block time. A zero block time means the punit has no
/// SAGV (or SAGV is disabled in BIOS) and no level admits it.
/// The flag is per level and independent of whether the level
/// is enabled — Linux sets it while computing the level, before
/// validation disables levels the DDB cannot satisfy.
pub fn apply_sagv_admission(
    wm: &mut PlaneWatermarks,
    latencies: &[u16; NUM_WM_LEVELS],
    sagv_block_time_us: u32,
) {
    for (level, &latency) in wm.levels.iter_mut().zip(latencies.iter()) {
        level.can_sagv = sagv_block_time_us != 0 && (latency as u32) >= sagv_block_time_us;
    }
}

/// Whether SAGV may be enabled with this plane's watermarks
/// (`skl_crtc_can_enable_sagv`, single-plane form): every
/// enabled plane must have a common enabled watermark level
/// that tolerates latencies above the SAGV block time, i.e.
/// the plane's *highest* enabled level must admit SAGV. A
/// plane with no enabled level imposes nothing (Linux skips
/// disabled planes), so it admits SAGV.
pub fn can_enable_sagv(wm: &PlaneWatermarks) -> bool {
    match wm.levels.iter().rposition(|level| level.enable) {
        None => true,
        Some(highest) => wm.levels[highest].can_sagv,
    }
}

// ── Register encodings ───────────────────────────────────────

/// Encode a `PLANE_WM` word: enable bit 31, lines bits
/// [26:14], blocks bits [12:0] (`skl_universal_plane_regs.h`).
pub fn encode_wm_level(level: &WmLevel) -> u32 {
    if !level.enable {
        return 0;
    }
    (1 << 31) | ((level.lines as u32 & 0x1FFF) << 14) | (level.blocks as u32 & 0x1FFF)
}

/// Encode a `PLANE_BUF_CFG` word: END (last block of the
/// allocation, i.e. end − 1 for an exclusive end) at bits
/// [28:16], START at bits [12:0].
pub fn encode_plane_buf_cfg(start: u16, end_exclusive: u16) -> u32 {
    let end_field = end_exclusive.saturating_sub(1) as u32;
    (end_field << 16) | start as u32
}

/// This driver's DDB allocation for Pipe A's primary plane:
/// the whole DBUF, [0, 2048). The degenerate single-consumer
/// case of the reference's proportional allocator.
pub const PRIMARY_DDB_START: u16 = 0;
/// Exclusive end of the primary plane's DDB allocation.
pub const PRIMARY_DDB_END: u16 = DBUF_TOTAL_BLOCKS;

// ── DBUF_CTL power sequencing ────────────────────────────────

/// `DBUF_CTL` for slice S1 (i915 slice index 0).
pub const DBUF_CTL_S1: u64 = 0x0004_5008;
/// `DBUF_CTL` for slice S2 (i915 slice index 1).
pub const DBUF_CTL_S2: u64 = 0x0004_4FE8;
/// `DBUF_POWER_REQUEST` — bit 31.
pub const DBUF_POWER_REQUEST: u32 = 1 << 31;
/// `DBUF_POWER_STATE` — bit 30.
pub const DBUF_POWER_STATE: u32 = 1 << 30;

/// MMIO offset of slice `slice`'s `DBUF_CTL`. The register
/// file scatters the slices; this table is the encoding, not
/// a stride.
pub const fn dbuf_ctl_offset(slice: u32) -> u64 {
    match slice {
        0 => DBUF_CTL_S1,
        _ => DBUF_CTL_S2,
    }
}

/// DBUF power-sequencing failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DbufError {
    /// A slice never granted power inside the poll budget.
    PowerTimeout,
}

/// Request power for one DBUF slice and poll for the grant.
/// The write is read-modify-write: the tracker-state-service
/// fields stay at their firmware values.
pub fn request_dbuf_slice<M: MmioWindow + ?Sized>(mmio: &M, slice: u32) -> Result<(), DbufError> {
    let off = dbuf_ctl_offset(slice);
    let cur = mmio.read32(off);
    mmio.write32(off, cur | DBUF_POWER_REQUEST);
    compiler_fence(Ordering::SeqCst);
    // 20 ms budget — the same generous cap the pcode codec
    // uses; silicon grants in microseconds, the cap only
    // bounds a wedged power controller.
    let budget = narf_time::wall::ns_to_cycles(20_000_000);
    let start = narf_time::now_cycles();
    loop {
        // read_poll_timeout: sample expiry before the read, so the read
        // that ends a timed-out wait follows the deadline.
        let expired = narf_time::now_cycles().wrapping_sub(start) > budget;
        if mmio.read32(off) & DBUF_POWER_STATE != 0 {
            return Ok(());
        }
        if expired {
            return Err(DbufError::PowerTimeout);
        }
        core::hint::spin_loop();
    }
}

/// Request power for every Gen11 DBUF slice (S1 + S2).
pub fn request_dbuf_slices<M: MmioWindow + ?Sized>(mmio: &M) -> Result<(), DbufError> {
    for slice in 0..DBUF_SLICES {
        request_dbuf_slice(mmio, slice)?;
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// The 1080p60 worked example: 148.5 MHz pixel rate,
    /// 2200 htotal, 1920 px wide XRGB8888 (cpp 4), latencies
    /// [6, 9, 13, 18, 24, 31, 40, 52] µs.
    /// Expected values worked from the algorithm by hand:
    /// pbpl = ceil(7680/512)+1 = 16; linetime = 15 µs.
    /// L0/L1/L2 method1 (latency < linetime 15), L3..L7 method2.
    fn params_1080p() -> WmParams {
        WmParams {
            pixel_rate_khz: 148_500,
            htotal: 2200,
            width_px: 1920,
            cpp: 4,
        }
    }

    fn smoke_adjust_latencies_sanitize_and_wa() -> TestResult {
        // First zero at level 2 → levels past it are zeroed.
        let adj = adjust_latencies(&[6, 9, 0, 18, 24, 31, 40, 52], false);
        if adj != [6, 9, 0, 0, 0, 0, 0, 0] {
            return TestResult::Fail("sanitize must zero levels past the first zero");
        }
        // Monotonic clamp raises level 1 to level 0's value.
        let adj = adjust_latencies(&[9, 4, 13, 18, 24, 31, 0, 0], false);
        if adj != [9, 9, 13, 18, 24, 31, 0, 0] {
            return TestResult::Fail("monotonic clamp wrong");
        }
        // WaWmMemoryReadLatency: level 0 == 0 → +2 µs (the
        // DISPLAY_VER < 12 value, not Gen12's +3) to level 0
        // and every subsequent nonzero level.
        let adj = adjust_latencies(&[0, 5, 9, 0, 0, 0, 0, 0], false);
        if adj != [2, 7, 11, 0, 0, 0, 0, 0] {
            return TestResult::Fail("WaWmMemoryReadLatency +2us wrong");
        }
        // 16 Gb-DIMM workaround: a further +1 µs on every valid
        // level (Gen11 is in need_16gb_dimm_wa's list).
        let adj = adjust_latencies(&[6, 9, 13, 18, 24, 31, 40, 52], true);
        if adj != [7, 10, 14, 19, 25, 32, 41, 53] {
            return TestResult::Fail("16 Gb-DIMM +1us wrong");
        }
        // Both workarounds stack when level 0 reads 0 on a
        // 16 Gb-DIMM system: +2 then +1.
        let adj = adjust_latencies(&[0, 5, 9, 0, 0, 0, 0, 0], true);
        if adj != [3, 8, 12, 0, 0, 0, 0, 0] {
            return TestResult::Fail("stacked latency workarounds wrong");
        }
        // Clean table passes through untouched.
        let adj = adjust_latencies(&[6, 9, 13, 18, 24, 31, 40, 52], false);
        if adj != [6, 9, 13, 18, 24, 31, 40, 52] {
            return TestResult::Fail("clean latency table must pass through");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_wm",
        smoke_adjust_latencies_sanitize_and_wa
    );

    fn smoke_compute_plane_wm_1080p() -> TestResult {
        let lat = [6, 9, 13, 18, 24, 31, 40, 52];
        let wm = compute_plane_watermarks(&params_1080p(), &lat);
        // Hand-worked from the algorithm (see module docs):
        // L0/L1 method1, L2 method1, L3..L7 method2.
        // L6 (40 µs): ceil(40*148500/2200000)=3 * 16 = 48 ->
        // blocks 49, lines 3, min 55. L7 (52 µs):
        // ceil(52*148500/2200000)=4 * 16 = 64 -> blocks 65,
        // lines 4, min 73.
        let want_blocks = [16u16, 16, 18, 33, 33, 49, 49, 65];
        let want_lines = [1u16, 1, 2, 2, 2, 3, 3, 4];
        let want_min = [19u16, 19, 21, 38, 38, 55, 55, 73];
        for i in 0..NUM_WM_LEVELS {
            let l = &wm.levels[i];
            if !l.enable || l.blocks != want_blocks[i] || l.lines != want_lines[i] {
                return TestResult::Fail("computed level blocks/lines mismatch");
            }
            if l.min_ddb_alloc != want_min[i] {
                return TestResult::Fail("computed level min_ddb_alloc mismatch");
            }
        }
        // Register words pin the packing too.
        let want_words = [
            0x8000_4010u32,
            0x8000_4010,
            0x8000_8012,
            0x8000_8021,
            0x8000_8021,
            0x8000_C031,
            0x8000_C031,
            0x8001_0041,
        ];
        for (level, &want_word) in wm.levels.iter().zip(&want_words) {
            if encode_wm_level(level) != want_word {
                return TestResult::Fail("PLANE_WM register word mismatch");
            }
        }
        if encode_wm_level(&wm.trans) != 0x8000_001E {
            return TestResult::Fail("transition watermark must be wm0 blocks + 14");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_wm",
        smoke_compute_plane_wm_1080p
    );

    fn smoke_compute_zero_latency_and_validation() -> TestResult {
        // Level 1 latency 0 → that level is rejected and encodes
        // to zero (later levels compute from their own latencies,
        // monotonic-clamped against the rejected level's zeros).
        let lat = [6, 0, 13, 18, 24, 31, 40, 52];
        let mut wm = compute_plane_watermarks(&params_1080p(), &lat);
        if wm.levels[1].enable || encode_wm_level(&wm.levels[1]) != 0 {
            return TestResult::Fail("zero-latency level must be disabled");
        }
        // Validate against a 20-block allocation: only levels
        // whose min_ddb_alloc <= 20 survive (L0: 19). L2's 21
        // is the masking-defeating case — one block over.
        validate_watermarks(&mut wm, 20);
        if !wm.levels[0].enable {
            return TestResult::Fail("level 0 (19 blocks) must survive a 20-block DDB");
        }
        if wm.levels[2].enable || wm.levels[3].enable || wm.levels[7].enable {
            return TestResult::Fail("levels over the DDB allocation must be disabled");
        }
        if wm.trans.enable {
            return TestResult::Fail("trans over the DDB allocation must be disabled");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_wm",
        smoke_compute_zero_latency_and_validation
    );

    fn smoke_sagv_admission_per_level() -> TestResult {
        // Latencies [6, 9, 13, 18, 24, 31, 40, 52], SAGV
        // block time 20 µs: a level admits SAGV exactly when
        // its latency covers the block time.
        let lat = [6, 9, 13, 18, 24, 31, 40, 52];
        let mut wm = compute_plane_watermarks(&params_1080p(), &lat);
        // Fresh levels admit nothing before annotation.
        if wm.levels.iter().any(|l| l.can_sagv) {
            return TestResult::Fail("fresh levels must not admit SAGV");
        }
        apply_sagv_admission(&mut wm, &lat, 20);
        let want = [false, false, false, false, true, true, true, true];
        for (level, &w) in wm.levels.iter().zip(&want) {
            if level.can_sagv != w {
                return TestResult::Fail("per-level SAGV admission wrong");
            }
        }
        // The highest enabled level (L7) admits SAGV, so the
        // plane admits it.
        if !can_enable_sagv(&wm) {
            return TestResult::Fail("plane must admit SAGV when its top level does");
        }
        // A 60 µs block time admits no level at all.
        apply_sagv_admission(&mut wm, &lat, 60);
        if wm.levels.iter().any(|l| l.can_sagv) || can_enable_sagv(&wm) {
            return TestResult::Fail("no level may admit SAGV past the longest latency");
        }
        // A zero block time (no SAGV in the punit) admits
        // nothing either.
        apply_sagv_admission(&mut wm, &lat, 0);
        if wm.levels.iter().any(|l| l.can_sagv) || can_enable_sagv(&wm) {
            return TestResult::Fail("a zero block time must admit no SAGV");
        }
        // Admission is per level, not per enablement: a level
        // disabled by validation keeps its flag, but the
        // enable decision reads the highest *enabled* level.
        // Block time 26 µs admits L5..L7; validating against
        // a 20-block DDB leaves only L0/L1 enabled (19 blocks
        // each), neither of which admits SAGV at 26 µs.
        apply_sagv_admission(&mut wm, &lat, 26);
        validate_watermarks(&mut wm, 20);
        if !wm.levels[0].enable || wm.levels[5].enable {
            return TestResult::Fail("validation fixture shape wrong");
        }
        // L5's flag survives validation (it was annotated
        // before validation ran).
        if !wm.levels[5].can_sagv {
            return TestResult::Fail("validation must not clear the admission flag");
        }
        if can_enable_sagv(&wm) {
            return TestResult::Fail(
                "SAGV must be refused when the top enabled level cannot take it",
            );
        }
        // No enabled level at all imposes nothing.
        validate_watermarks(&mut wm, 0);
        if !can_enable_sagv(&wm) {
            return TestResult::Fail("a plane with no enabled level must not block SAGV");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_wm",
        smoke_sagv_admission_per_level
    );

    fn smoke_buf_cfg_encoding() -> TestResult {
        // This lane's allocation: [0, 2048) → END field 2047.
        if encode_plane_buf_cfg(PRIMARY_DDB_START, PRIMARY_DDB_END) != 0x07FF_0000 {
            return TestResult::Fail("full-DBUF BUF_CFG encoding wrong");
        }
        // Cross-check against lane 1's PRM pre-boot value:
        // [0, 160) → 0x009F_0000.
        if encode_plane_buf_cfg(0, 160) != 0x009F_0000 {
            return TestResult::Fail("BUF_CFG encoding disagrees with the pre-boot pin");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen11_wm", smoke_buf_cfg_encoding);

    /// DBUF slice model: POWER_STATE follows POWER_REQUEST
    /// (unless `grant` is off), everything else is stored.
    #[derive(Debug)]
    pub struct DbufMmio {
        pub writes: RefCell<Vec<(u64, u32)>>,
        regs: RefCell<Vec<(u64, u32)>>,
        pub grant: bool,
    }

    impl DbufMmio {
        pub fn granting() -> Self {
            Self {
                writes: RefCell::new(Vec::new()),
                regs: RefCell::new(Vec::new()),
                grant: true,
            }
        }
    }

    impl MmioWindow for DbufMmio {
        fn read32(&self, off: u64) -> u32 {
            let mut v = 0;
            for (o, val) in self.regs.borrow().iter() {
                if *o == off {
                    v = *val;
                }
            }
            if off == DBUF_CTL_S1 || off == DBUF_CTL_S2 {
                if self.grant && v & DBUF_POWER_REQUEST != 0 {
                    v |= DBUF_POWER_STATE;
                } else {
                    v &= !DBUF_POWER_STATE;
                }
            }
            v
        }
        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            self.regs.borrow_mut().push((off, val));
        }
    }

    fn smoke_dbuf_power_sequencing() -> TestResult {
        // The two slice registers are NOT a stride apart —
        // pin the scattered addresses.
        if dbuf_ctl_offset(0) != 0x4_5008 || dbuf_ctl_offset(1) != 0x4_4FE8 {
            return TestResult::Fail("DBUF_CTL slice addresses wrong");
        }
        let mmio = DbufMmio::granting();
        if request_dbuf_slices(&mmio).is_err() {
            return TestResult::Fail("granting slices must sequence cleanly");
        }
        for off in [DBUF_CTL_S1, DBUF_CTL_S2] {
            let wrote_req = mmio
                .writes
                .borrow()
                .iter()
                .any(|(o, v)| *o == off && v & DBUF_POWER_REQUEST != 0);
            if !wrote_req {
                return TestResult::Fail("POWER_REQUEST not written for a slice");
            }
        }
        // A slice that never grants must time out, not hang.
        let mut mmio = DbufMmio::granting();
        mmio.grant = false;
        match request_dbuf_slice(&mmio, 0) {
            Err(DbufError::PowerTimeout) => TestResult::Pass,
            _ => TestResult::Fail("ungranted slice must surface PowerTimeout"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_wm",
        smoke_dbuf_power_sequencing
    );
}
