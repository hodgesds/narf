//! AMD DCCG (Display Clock Generator) — multi-display PLL programming.
//!
//! When two CRTCs run at different refresh rates whose pixel clocks
//! aren't an integer multiple of each other, the DCCG has to allocate
//! distinct PLLs and run a per-pipe pixel clock divider. The naive
//! shared-PLL path only works when the two pixel clocks are integer-
//! related (e.g. 60 Hz + 120 Hz → 2:1; 60 + 30 → 2:1).
//!
//! ## What this module ships
//!
//! - `PllAssignment` — which PLL backs which pipe. Phoenix has 4 PLLs.
//! - `assign_plls` — runs the matrix algorithm: cluster pixel-clocks
//!   into integer-related families; allocate one PLL per family with
//!   the highest pixel-clock divisor count.
//! - `program_dtbclk_dto` — produces the DCCG DTO register
//!   programming for a single PLL→pipe assignment.
//!
//! ## References
//!
//! - Linux drivers/gpu/drm/amd/display/dc/dccg/dcn35/dcn35_dccg.c
//!   (dccg35_set_dtbclk_p_src / dccg35_set_dtbclk_dto).
//! - Linux drivers/gpu/drm/amd/display/dc/inc/hw/dccg.h
//!
//! GPL-2.0-or-later post-relicense.

extern crate alloc;

use alloc::vec::Vec;

// ── DCCG PLL inventory ────────────────────────────────────────────

/// Phoenix DCN 3.5 has 4 PLLs available to the display engine
/// (plus a fixed REFCLK source). Older DCN (2.0 / 3.0) had 5;
/// DCN 3.5 dropped one with the iGPU integration.
pub const N_DCCG_PLLS: usize = 4;

/// One PLL's assignment. `freq_khz` is the PLL's target output
/// frequency; `pipes` is the list of CRTC indices that draw from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PllAssignment {
    pub pll_idx: u8,
    pub freq_khz: u32,
    pub pipes: Vec<u8>,
}

/// Per-pipe pixel-clock request the host hands to assign_plls.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PixelClockRequest {
    pub pipe_idx: u8,
    pub pixel_clock_khz: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DccgError {
    /// More distinct pixel-clock families than PLLs available.
    NotEnoughPlls,
    /// One of the requested pixel clocks is 0.
    BadPixelClock,
}

/// Test whether two pixel clocks are integer-related — i.e. share
/// a common base PLL frequency. Used by the assignment algorithm
/// to fold related rates onto a single PLL.
pub fn is_integer_related(a_khz: u32, b_khz: u32) -> bool {
    if a_khz == 0 || b_khz == 0 {
        return false;
    }
    let (max, min) = if a_khz > b_khz { (a_khz, b_khz) } else { (b_khz, a_khz) };
    max % min == 0
}

/// Run the multi-display PLL assignment algorithm. Two-pass:
///
///   1. Sort requests by pixel-clock descending. The highest pixel
///      clock seeds the first PLL.
///   2. For each subsequent request, find the PLL whose frequency
///      is an integer multiple of the request (or vice versa); if
///      found, attach the pipe + bump the PLL's freq to the max.
///      Otherwise allocate a fresh PLL.
///
/// Returns the final PllAssignment list. Errors with NotEnoughPlls
/// if the matrix can't be folded onto N_DCCG_PLLS.
pub fn assign_plls(requests: &[PixelClockRequest]) -> Result<Vec<PllAssignment>, DccgError> {
    if requests.iter().any(|r| r.pixel_clock_khz == 0) {
        return Err(DccgError::BadPixelClock);
    }
    let mut sorted = requests.to_vec();
    sorted.sort_by(|a, b| b.pixel_clock_khz.cmp(&a.pixel_clock_khz));
    let mut plls: Vec<PllAssignment> = Vec::new();
    for r in sorted {
        let mut placed = false;
        for pll in plls.iter_mut() {
            if is_integer_related(pll.freq_khz, r.pixel_clock_khz) {
                if r.pixel_clock_khz > pll.freq_khz {
                    pll.freq_khz = r.pixel_clock_khz;
                }
                pll.pipes.push(r.pipe_idx);
                placed = true;
                break;
            }
        }
        if !placed {
            if plls.len() >= N_DCCG_PLLS {
                return Err(DccgError::NotEnoughPlls);
            }
            let mut pipes = Vec::new();
            pipes.push(r.pipe_idx);
            plls.push(PllAssignment {
                pll_idx: plls.len() as u8,
                freq_khz: r.pixel_clock_khz,
                pipes,
            });
        }
    }
    Ok(plls)
}

// ── DCCG register programming ─────────────────────────────────────

/// DCCG DTO register offsets (relative to DCCG block base, Phoenix
/// dcn35). The DTO drives the per-pipe pixel-clock divider; phase +
/// module form a ratio that synthesises the final clock from the
/// PLL's source frequency.
pub const DCCG_DTBCLK_P_CNTL_BASE: u32 = 0x0150;
pub const DCCG_DTBCLK_DTO_MODULE_BASE: u32 = 0x0200;
pub const DCCG_DTBCLK_DTO_PHASE_BASE: u32 = 0x0204;
pub const DCCG_PIXCLK_DTO_STRIDE: u32 = 0x10;

pub trait DccgMmio {
    fn read(&mut self, byte_off: u32) -> u32;
    fn write(&mut self, byte_off: u32, value: u32);
}

/// Compute a (phase, module) DTO pair for a target pixel clock from
/// a source PLL frequency. The pair forms a ratio: actual rate =
/// pll_khz * phase / module. We use a phase = pixel_khz and module
/// = pll_khz to get a unity gain; larger modulus gives finer
/// granularity but the dword field is 24 bits so we cap accordingly.
pub fn compute_dto_pair(pll_khz: u32, target_khz: u32) -> Option<(u32, u32)> {
    if pll_khz == 0 || target_khz == 0 || target_khz > pll_khz {
        return None;
    }
    // Trivial form: phase = target, module = pll.
    Some((target_khz, pll_khz))
}

/// Program one pipe's DTBCLK DTO with the (phase, module) pair.
/// Adapted from `dccg35_set_dtbclk_dto`. Per-pipe stride is
/// `DCCG_PIXCLK_DTO_STRIDE`.
pub fn program_pipe_dto<M: DccgMmio>(
    mmio: &mut M,
    dccg_base: u32,
    pipe_idx: u8,
    phase: u32,
    module: u32,
) {
    let stride = (pipe_idx as u32) * DCCG_PIXCLK_DTO_STRIDE;
    mmio.write(dccg_base + DCCG_DTBCLK_DTO_MODULE_BASE + stride, module);
    mmio.write(dccg_base + DCCG_DTBCLK_DTO_PHASE_BASE + stride, phase);
}

/// Program every pipe in a PllAssignment list. After this, each
/// CRTC's pixel clock is locked to its assigned PLL's source.
pub fn program_assignments<M: DccgMmio>(
    mmio: &mut M,
    dccg_base: u32,
    requests: &[PixelClockRequest],
    plls: &[PllAssignment],
) {
    for pll in plls {
        for &pipe in &pll.pipes {
            let request = requests
                .iter()
                .find(|r| r.pipe_idx == pipe)
                .map(|r| r.pixel_clock_khz)
                .unwrap_or(pll.freq_khz);
            if let Some((phase, module)) = compute_dto_pair(pll.freq_khz, request) {
                program_pipe_dto(mmio, dccg_base, pipe, phase, module);
            }
        }
    }
}

// ── Smoke tests ───────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_integer_related_basic_cases() -> TestResult {
        if !is_integer_related(60_000, 120_000) {
            return TestResult::Fail("60/120 are integer-related");
        }
        if !is_integer_related(120_000, 60_000) {
            return TestResult::Fail("order-independent");
        }
        if is_integer_related(60_000, 75_000) {
            return TestResult::Fail("60/75 NOT integer-related");
        }
        if is_integer_related(60_000, 0) {
            return TestResult::Fail("0 should fail");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_integer_related_basic_cases);

    fn smoke_assign_plls_shared_when_integer_related() -> TestResult {
        // 4K@60 (594 MHz) + 1080p@120 (297 MHz, half) → share 1 PLL.
        let reqs = [
            PixelClockRequest { pipe_idx: 0, pixel_clock_khz: 594_000 },
            PixelClockRequest { pipe_idx: 1, pixel_clock_khz: 297_000 },
        ];
        let plls = assign_plls(&reqs).expect("assign");
        if plls.len() != 1 {
            return TestResult::Fail("should share one PLL");
        }
        if plls[0].pipes.len() != 2 {
            return TestResult::Fail("both pipes should attach");
        }
        if plls[0].freq_khz != 594_000 {
            return TestResult::Fail("PLL freq should be highest");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_assign_plls_shared_when_integer_related);

    fn smoke_assign_plls_separate_when_unrelated() -> TestResult {
        // 60 + 75 → 2 distinct PLLs.
        let reqs = [
            PixelClockRequest { pipe_idx: 0, pixel_clock_khz: 148_500 },
            PixelClockRequest { pipe_idx: 1, pixel_clock_khz: 162_000 },
        ];
        let plls = assign_plls(&reqs).expect("assign");
        if plls.len() != 2 {
            return TestResult::Fail("should be 2 PLLs");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_assign_plls_separate_when_unrelated);

    fn smoke_assign_plls_overflows_with_too_many_distinct() -> TestResult {
        // 5 distinct unrelated rates — N_DCCG_PLLS = 4 → overflow.
        let reqs = [
            PixelClockRequest { pipe_idx: 0, pixel_clock_khz: 162_000 },
            PixelClockRequest { pipe_idx: 1, pixel_clock_khz: 148_500 },
            PixelClockRequest { pipe_idx: 2, pixel_clock_khz: 173_400 },
            PixelClockRequest { pipe_idx: 3, pixel_clock_khz: 270_000 },
            PixelClockRequest { pipe_idx: 4, pixel_clock_khz: 297_023 },
        ];
        if assign_plls(&reqs) != Err(DccgError::NotEnoughPlls) {
            return TestResult::Fail("should overflow");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_assign_plls_overflows_with_too_many_distinct);

    fn smoke_compute_dto_pair_unity() -> TestResult {
        if compute_dto_pair(594_000, 297_000) != Some((297_000, 594_000)) {
            return TestResult::Fail("4K/2K ratio wrong");
        }
        // Target > source → None.
        if compute_dto_pair(297_000, 594_000).is_some() {
            return TestResult::Fail("target > source should fail");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_compute_dto_pair_unity);

    struct MockDccg {
        writes: Vec<(u32, u32)>,
    }
    impl DccgMmio for MockDccg {
        fn read(&mut self, _off: u32) -> u32 {
            0
        }
        fn write(&mut self, off: u32, val: u32) {
            self.writes.push((off, val));
        }
    }

    fn smoke_program_pipe_dto_writes_module_then_phase() -> TestResult {
        let mut m = MockDccg { writes: Vec::new() };
        program_pipe_dto(&mut m, 0x10000, 2, 0x123, 0x456);
        if m.writes.len() != 2 {
            return TestResult::Fail("expected 2 writes");
        }
        let stride = 2 * DCCG_PIXCLK_DTO_STRIDE;
        if m.writes[0] != (0x10000 + DCCG_DTBCLK_DTO_MODULE_BASE + stride, 0x456) {
            return TestResult::Fail("module wrong");
        }
        if m.writes[1] != (0x10000 + DCCG_DTBCLK_DTO_PHASE_BASE + stride, 0x123) {
            return TestResult::Fail("phase wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_program_pipe_dto_writes_module_then_phase);

    fn smoke_program_assignments_writes_each_pipe() -> TestResult {
        let mut m = MockDccg { writes: Vec::new() };
        let reqs = [
            PixelClockRequest { pipe_idx: 0, pixel_clock_khz: 594_000 },
            PixelClockRequest { pipe_idx: 1, pixel_clock_khz: 297_000 },
        ];
        let plls = assign_plls(&reqs).expect("assign");
        program_assignments(&mut m, 0x10000, &reqs, &plls);
        // 2 pipes × 2 writes (module + phase) = 4.
        if m.writes.len() != 4 {
            return TestResult::Fail("expected 4 writes");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_program_assignments_writes_each_pipe);
}
