use super::*;
use crate::amdgpu_dcn401_dscl as dscl;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Shared with tests/dcn401_spl/check.sh, which answers every line with
/// Linux SPL built on the host (see harness.c for the write tokens).
const VECTORS: &str = include_str!("../tests/dcn401_spl/vectors.txt");

fn input(a: &[i32]) -> Input {
    let r = |i: usize| Rect::new(a[i], a[i + 1], a[i + 2], a[i + 3]);
    Input {
        src: r(0),
        dst: r(4),
        clip: r(4),
        stream_width: a[8],
        stream_height: a[9],
        odm_slice: Rect::new(a[10], 0, a[11], a[9]),
        rotation: [Rotation::R0, Rotation::R90, Rotation::R180, Rotation::R270][a[12] as usize],
        horizontal_mirror: a[13] != 0,
        alpha: a[14] != 0,
    }
}

/// The harness's line: the result, the DSCL writes and the viewport.
fn tokens(input: &Input) -> String {
    let s = calculate(input);
    let mut out = String::from(if s.ok { "OK" } else { "FAIL" });
    for op in dscl::program(&s, input.alpha) {
        out += &match op {
            dscl::Op::Write { reg, mask, value } => format!(" {reg:x}&{mask:x}={value:x}"),
            dscl::Op::Wait { reg, mask, value } => format!(" w{reg:x}&{mask:x}={value:x}"),
            dscl::Op::Coefficients {
                filter_type,
                taps,
                filter,
            } => {
                // FNV-1a over the TAP_DATA words' little-endian bytes.
                let mut hash: u32 = 2_166_136_261;
                let mut n = 0;
                for word in dscl::coefficient_words(taps, filter) {
                    for b in word.to_le_bytes() {
                        hash = (hash ^ u32::from(b)).wrapping_mul(16_777_619);
                    }
                    n += 1;
                }
                format!(" c{filter_type}/{taps}/{n}/{hash:08x}")
            }
            dscl::Op::SwapCoefficientRam => String::from(" t"),
        };
    }
    for (reg, mask, value) in dscl::viewport(&s) {
        out += &format!(" {reg:x}&{mask:x}={:x}", value & mask);
    }
    out
}

/// Every plane of vectors.txt programs exactly Linux's writes: recout, MPC
/// size, mode, line buffer, ratios, inits, taps, iSHARP off, the polyphase
/// or EASF coefficient loads and the EASF controls, then the viewport.
fn dcn401_spl_matches_linux_vectors() -> TestResult {
    let mut n = 0;
    for line in VECTORS
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let Some((inputs, want)) = line.split_once(" = ") else {
            return TestResult::Fail("malformed vector");
        };
        let a: Vec<i32> = inputs
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();
        if a.len() != 15 {
            return TestResult::Fail("malformed vector inputs");
        }
        if tokens(&input(&a)) != want {
            return TestResult::Fail("SPL writes differ from Linux");
        }
        n += 1;
    }
    if n < 200 {
        return TestResult::Fail("too few SPL vectors");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn401-spl", dcn401_spl_matches_linux_vectors);

/// A unity full-screen plane bypasses the scaler with one tap; 2:1 and 1.5x
/// take EASF's six taps; 3:1 falls back to the polyphase filters; past
/// 7680 source pixels of downscaling SPL fails, as Linux's
/// max_downscale_src_width does.
fn dcn401_spl_scaling_modes() -> TestResult {
    let full = |src: (i32, i32), dst: (i32, i32)| Input {
        src: Rect::new(0, 0, src.0, src.1),
        dst: Rect::new(0, 0, dst.0, dst.1),
        clip: Rect::new(0, 0, dst.0, dst.1),
        stream_width: dst.0,
        stream_height: dst.1,
        odm_slice: Rect::new(0, 0, dst.0, dst.1),
        rotation: Rotation::R0,
        horizontal_mirror: false,
        alpha: false,
    };
    let unity = calculate(&full((1920, 1080), (1920, 1080)));
    if !unity.ok
        || unity.dscl_mode != SCL_MODE_SCALING_444_BYPASS
        || unity.dc_taps() != [1; 4]
        || unity.viewport != Rect::new(0, 0, 1920, 1080)
        || unity.easf.v.en != 0
    {
        return TestResult::Fail("unity bypass");
    }
    let up = calculate(&full((1280, 720), (1920, 1080)));
    if !up.ok || up.dc_taps() != [6; 4] || up.easf.v.en != 1 || up.easf.h.en != 1 {
        return TestResult::Fail("1.5x EASF");
    }
    let down3 = calculate(&full((5760, 3240), (1920, 1080)));
    if !down3.ok || down3.easf.h.en != 0 || down3.filter_h.is_none() {
        return TestResult::Fail("3:1 polyphase");
    }
    let wide = calculate(&full((8192, 4320), (3840, 2160)));
    if wide.ok {
        return TestResult::Fail("max_downscale_src_width");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn401-spl", dcn401_spl_scaling_modes);
