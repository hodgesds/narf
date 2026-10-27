//! Gen12 latency-based plane watermarks + DBUF allocation.
//!
//! Lane 1 (#1010) programmed the PRM's pre-OS-boot basics: a
//! fixed 160-block allocation and one watermark level for any
//! mode. This module is the real algorithm from the PRM's
//! watermark chapter, transcribed from the reference
//! implementation (i915 `display/skl_watermark.c`), scoped to
//! this driver's shape:
//!
//! - **Gen12 (DISPLAY_VER 12) only.** Version-gated branches in
//!   the reference that select other generations are resolved at
//!   transcription time and noted where they mattered.
//! - **Linear (untiled) surfaces only.** The driver scans out
//!   linear XRGB8888; the Y-tiled branches of the reference
//!   (plane_blocks_per_line rounding, y_tile_minimum floors)
//!   are not reachable and not transcribed.
//! - **One pipe, one universal plane.** DDB allocation is the
//!   degenerate single-consumer case of the reference's
//!   proportional allocator: the pipe's primary plane receives
//!   the whole DBUF. Slice *arbitration* between pipes is
//!   multi-pipe work (#1017); both slices are powered and the
//!   allocation spans both (see the DBUF section below).
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
//!    latency ≥ linetime; method1 otherwise.
//! 3. Result blocks = ceil(selected) + 1, floored at
//!    plane_blocks_per_line; lines = ceil(selected /
//!    plane_blocks_per_line); blocks/lines are clamped
//!    monotonically non-decreasing across levels.
//!    min_ddb_alloc = blocks + ceil(blocks/10), then +1
//!    ("value >= plane ddb allocation → invalid", PRM).
//! 4. A level with latency 0, or needing more than 31 lines,
//!    is rejected. A level whose min_ddb_alloc exceeds the
//!    plane's DDB allocation is disabled at validation time
//!    (`skl_check_wm_level`).
//! 5. Transition watermarks: wm0 blocks + 14 (trans_min 4 +
//!    trans_amount 10, DISPLAY_VER ≥ 11). The SAGV watermark
//!    is level 0 recomputed at (SAGV block time + level-0
//!    latency) — Gen12 has dedicated SAGV watermark registers
//!    occupying the PLANE_WM slots 6/7, so there are 6 regular
//!    levels, not 8.
//!
//! Deliberately NOT transcribed: the DG2 ×2 latency multiply
//! (discrete part; this driver binds integrated Gen12), the
//! 16 Gb-DIMM +1 µs workaround (platform list in the reference
//! is SKL/KBL/CFL/CML + DISPLAY_VER 11 — Gen12 excluded), and
//! the memory-bandwidth SAGV *control* pcode command (0x21) —
//! enabling SAGV itself is the bandwidth manager's call; this
//! module only consumes the block time and programs the SAGV
//! watermark registers.
//!
//! ## DBUF_CTL power sequencing
//!
//! `DBUF_CTL` per slice (i915 `display/skl_watermark_regs.h`):
//! S1 at 0x45008, S2 at 0x44FE8 — *not* a uniform stride from
//! a base; the register file scatters them. POWER_REQUEST is
//! bit 31, POWER_STATE (grant) is bit 30. The modeset sets
//! REQUEST for both slices and polls STATE before programming
//! any watermark, so the DDB blocks the watermarks point at
//! are backed by powered SRAM. The tracker-state-service
//! fields (bits [23:16]) belong to the MDCLK/CDCLK-ratio and
//! joined-MBUS machinery (multi-pipe, #1017); this driver's
//! request write is read-modify-write and leaves them at
//! their firmware values.
//!
//! Gen12 DBUF geometry (`intel_display_device.c`, XE_D_DISPLAY
//! — the macro TGL/ADL/RPL resolve to): 2048 blocks total,
//! slice mask S1|S2, 1024 blocks per slice, 512 bytes per block.

use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu_aux::MmioWindow;

/// Regular watermark levels on Gen12 (the SAGV registers take
/// the slots that were levels 6/7 on Gen9/10).
pub const NUM_WM_LEVELS: usize = 6;

/// DBUF block size in bytes on Gen12.
pub const DBUF_BLOCK_SIZE: u32 = 512;
/// Total DBUF blocks on Gen12 (both slices).
pub const DBUF_TOTAL_BLOCKS: u16 = 2048;
/// Blocks per DBUF slice on Gen12 (2048 blocks / 2 slices).
pub const DBUF_SLICE_BLOCKS: u16 = 1024;
/// Number of DBUF slices on Gen12.
pub const DBUF_SLICES: u32 = 2;

/// PLANE_WM lines field ceiling on Gen12 (`skl_wm_max_lines`:
/// 31 below DISPLAY_VER 13).
const WM_MAX_LINES: u32 = 31;

// ── Latency adjustment (i915 adjust_wm_latency, Gen12) ─────

/// Adjust the raw pcode latency table the way the reference
/// driver does before computing watermarks. Input is the full
/// 8-level table; Gen12 uses 6 levels.
///
/// Steps, in reference order:
/// 1. **Sanitize** — the first zero level at index ≥ 1 marks
///    the end of the valid range; every level past it is zeroed.
/// 2. **Monotonic** — each level is raised to at least the
///    previous level's value, stopping at the first zero.
/// 3. **WaWmMemoryReadLatency** — when level 0 reads back 0,
///    the punit has not accounted for read latency; add 3 µs
///    (the DISPLAY_VER ≥ 12 value) to level 0 and every
///    subsequent nonzero level.
pub fn adjust_latencies(raw: &[u16; 8]) -> [u16; NUM_WM_LEVELS] {
    let mut wm = [raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]];

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

    // 3. WaWmMemoryReadLatency (Gen12: +3 µs).
    if wm[0] == 0 {
        wm[0] += 3;
        for level in 1..NUM_WM_LEVELS {
            if wm[level] == 0 {
                break;
            }
            wm[level] += 3;
        }
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
}

/// The full watermark set for one plane: 6 latency levels,
/// the SAGV level, and both transition watermarks.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PlaneWatermarks {
    pub levels: [WmLevel; NUM_WM_LEVELS],
    pub sagv: WmLevel,
    pub trans: WmLevel,
    pub sagv_trans: WmLevel,
}

/// Inputs the Gen12 linear-surface algorithm needs.
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
    (fx + FX_ONE - 1) / FX_ONE
}

/// `skl_compute_plane_wm`, Gen12 + linear surface. `prev` is
/// the previous level's result for the monotonic clamp (a
/// zeroed level for level 0 — and, per the reference, level 0
/// itself when computing the SAGV watermark).
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

    // Selection (non-Y-tiled, DISPLAY_VER 12).
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

/// `skl_compute_transition_wm`, Gen12: trans_min 4 +
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
    }
}

/// Compute the full watermark set for one plane. Unvalidated:
/// run [`validate_watermarks`] with the plane's DDB allocation
/// before programming.
pub fn compute_plane_watermarks(
    params: &WmParams,
    latencies: &[u16; NUM_WM_LEVELS],
    sagv_block_time_us: u32,
) -> PlaneWatermarks {
    let mut raw_levels = [RawLevel::default(); NUM_WM_LEVELS];
    let mut prev = RawLevel::default();
    for (level, raw) in raw_levels.iter_mut().enumerate() {
        *raw = compute_level(params, latencies[level] as u32, &prev);
        prev = *raw;
    }
    // SAGV watermark: level 0 recomputed at block-time +
    // level-0 latency, monotonic-clamped against level 0.
    // Zero block time means the punit has no SAGV — the level
    // computes with latency 0 and is rejected.
    let sagv_latency = if sagv_block_time_us == 0 {
        0
    } else {
        sagv_block_time_us + latencies[0] as u32
    };
    let sagv = compute_level(params, sagv_latency, &raw_levels[0]);
    let trans = compute_transition(&raw_levels[0]);
    let sagv_trans = compute_transition(&sagv);

    PlaneWatermarks {
        levels: [
            narrow(raw_levels[0]),
            narrow(raw_levels[1]),
            narrow(raw_levels[2]),
            narrow(raw_levels[3]),
            narrow(raw_levels[4]),
            narrow(raw_levels[5]),
        ],
        sagv: narrow(sagv),
        trans: narrow(trans),
        sagv_trans: narrow(sagv_trans),
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
    check_level(&mut wm.sagv, ddb_size);
    check_level(&mut wm.trans, ddb_size);
    check_level(&mut wm.sagv_trans, ddb_size);
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
        if mmio.read32(off) & DBUF_POWER_STATE != 0 {
            return Ok(());
        }
        if narf_time::now_cycles().wrapping_sub(start) > budget {
            return Err(DbufError::PowerTimeout);
        }
        core::hint::spin_loop();
    }
}

/// Request power for every Gen12 DBUF slice (S1 + S2).
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
    /// [6, 9, 13, 18, 24, 31] µs, SAGV block time 20 µs.
    /// Expected values worked from the algorithm by hand:
    /// pbpl = ceil(7680/512)+1 = 16; linetime = 15 µs.
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
        let adj = adjust_latencies(&[6, 9, 0, 18, 24, 31, 40, 52]);
        if adj != [6, 9, 0, 0, 0, 0] {
            return TestResult::Fail("sanitize must zero levels past the first zero");
        }
        // Monotonic clamp raises level 1 to level 0's value.
        let adj = adjust_latencies(&[9, 4, 13, 18, 24, 31, 0, 0]);
        if adj != [9, 9, 13, 18, 24, 31] {
            return TestResult::Fail("monotonic clamp wrong");
        }
        // WaWmMemoryReadLatency: level 0 == 0 → +3 µs to level 0
        // and every subsequent nonzero level.
        let adj = adjust_latencies(&[0, 5, 9, 0, 0, 0, 0, 0]);
        if adj != [3, 8, 12, 0, 0, 0] {
            return TestResult::Fail("WaWmMemoryReadLatency +3us wrong");
        }
        // Clean table passes through untouched.
        let adj = adjust_latencies(&[6, 9, 13, 18, 24, 31, 40, 52]);
        if adj != [6, 9, 13, 18, 24, 31] {
            return TestResult::Fail("clean latency table must pass through");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_wm",
        smoke_adjust_latencies_sanitize_and_wa
    );

    fn smoke_compute_plane_wm_1080p() -> TestResult {
        let lat = [6, 9, 13, 18, 24, 31];
        let wm = compute_plane_watermarks(&params_1080p(), &lat, 20);
        // Hand-worked from the algorithm (see module docs):
        // L0/L1 method1 (latency < linetime 15), L2 method1,
        // L3..L5 method2; SAGV at latency 26 → method2.
        let want_blocks = [16u16, 16, 18, 33, 33, 49];
        let want_lines = [1u16, 1, 2, 2, 2, 3];
        let want_min = [19u16, 19, 21, 38, 38, 55];
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
        ];
        for i in 0..NUM_WM_LEVELS {
            if encode_wm_level(&wm.levels[i]) != want_words[i] {
                return TestResult::Fail("PLANE_WM register word mismatch");
            }
        }
        if encode_wm_level(&wm.sagv) != 0x8000_8021 {
            return TestResult::Fail("SAGV watermark word mismatch");
        }
        if encode_wm_level(&wm.trans) != 0x8000_001E {
            return TestResult::Fail("transition watermark must be wm0 blocks + 14");
        }
        if encode_wm_level(&wm.sagv_trans) != 0x8000_002F {
            return TestResult::Fail("SAGV transition watermark mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_wm", smoke_compute_plane_wm_1080p);

    fn smoke_compute_zero_latency_and_validation() -> TestResult {
        // Level 1 latency 0 → that level (and the monotonic
        // chain past it only via their own latencies) — level 1
        // itself is rejected and encodes to zero.
        let lat = [6, 0, 13, 18, 24, 31];
        let mut wm = compute_plane_watermarks(&params_1080p(), &lat, 20);
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
        if wm.levels[2].enable || wm.levels[3].enable || wm.levels[5].enable {
            return TestResult::Fail("levels over the DDB allocation must be disabled");
        }
        if wm.trans.enable || wm.sagv.enable {
            return TestResult::Fail("trans/SAGV over the DDB allocation must be disabled");
        }
        // Zero block time → no SAGV watermark at all.
        let wm = compute_plane_watermarks(&params_1080p(), &[6, 9, 13, 18, 24, 31], 0);
        if wm.sagv.enable || wm.sagv_trans.enable {
            return TestResult::Fail("SAGV watermarks must be off when block time is 0");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_wm",
        smoke_compute_zero_latency_and_validation
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
    kernel_test_in!("drivers/gpu/intel_gpu_wm", smoke_buf_cfg_encoding);

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
    kernel_test_in!("drivers/gpu/intel_gpu_wm", smoke_dbuf_power_sequencing);
}
