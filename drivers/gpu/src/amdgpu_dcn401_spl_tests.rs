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
        mpc_slice: (0, 1),
        rotation: [Rotation::R0, Rotation::R90, Rotation::R180, Rotation::R270][a[12] as usize],
        horizontal_mirror: a[13] != 0,
        alpha: a[14] != 0,
        video: None,
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
            dscl::Op::SwapCoefficientRam { chroma } => {
                String::from(if chroma { " T" } else { " t" })
            }
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

/// 4:2:0 planes, shared with check.sh likewise: each line leads with the
/// format (8 NV12/NV21, 10 P010).
const VIDEO_VECTORS: &str = include_str!("../tests/dcn401_spl/video_vectors.txt");

/// Every NV12/P010 plane of video_vectors.txt programs exactly Linux's
/// writes: the halved chroma ratios and viewport, chroma taps and inits,
/// the 420 SCL mode, LB_MEMORY_CONFIG_3, the luma and chroma coefficient
/// loads with chroma coefficient mode, and the non-linear EASF controls.
/// Linux's SPL_ASSERT that a chroma viewport starts on a whole chroma
/// sample (an odd source origin) only warns; its "WARN" marker is not part
/// of the programming.
fn dcn401_spl_matches_linux_video_vectors() -> TestResult {
    let mut n = 0;
    for line in VIDEO_VECTORS
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
        if a.len() != 16 {
            return TestResult::Fail("malformed vector inputs");
        }
        let video = match a[0] {
            8 => Video::Nv12,
            10 => Video::P010,
            _ => return TestResult::Fail("unknown video format"),
        };
        let mut plane = input(&a[1..]);
        plane.video = Some(video);
        let want = want.replacen("OK WARN", "OK", 1);
        if tokens(&plane) != want {
            return TestResult::Fail("SPL 4:2:0 writes differ from Linux");
        }
        n += 1;
    }
    if n < 100 {
        return TestResult::Fail("too few SPL 4:2:0 vectors");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-spl",
    dcn401_spl_matches_linux_video_vectors
);

/// An unscaled NV12 frame bypasses only luma (420_LUMA_BYPASS): chroma
/// is upscaled 2x with four taps on a half-size chroma viewport, in
/// LB_MEMORY_CONFIG_3; RGB at the same size bypasses the whole scaler.
fn dcn401_spl_nv12_full_frame_scales_chroma() -> TestResult {
    let r = Rect::new(0, 0, 1920, 1080);
    let plane = Input {
        src: r,
        dst: r,
        clip: r,
        stream_width: 1920,
        stream_height: 1080,
        odm_slice: r,
        mpc_slice: (0, 1),
        rotation: Rotation::R0,
        horizontal_mirror: false,
        alpha: false,
        video: Some(Video::Nv12),
    };
    let s = calculate(&plane);
    if !s.ok
        || s.dscl_mode != SCL_MODE_SCALING_420_LUMA_BYPASS
        || s.viewport != r
        || s.viewport_c != Rect::new(0, 0, 960, 540)
        || s.ratios != [1 << 24, 1 << 24, 1 << 23, 1 << 23]
        || s.dc_taps() != [1, 1, 4, 4]
        || s.lb_memory_config(false) != 3
        || s.easf.v.en != 0
        || s.easf.h.en != 0
    {
        return TestResult::Fail("NV12 full frame");
    }
    let rgb = calculate(&Input {
        video: None,
        ..plane
    });
    if rgb.dscl_mode != SCL_MODE_SCALING_444_BYPASS || rgb.video.is_some() {
        return TestResult::Fail("RGB full frame");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-spl",
    dcn401_spl_nv12_full_frame_scales_chroma
);

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
        mpc_slice: (0, 1),
        rotation: Rotation::R0,
        horizontal_mirror: false,
        alpha: false,
        video: None,
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

/// Shared with tests/dcn401_spl/check.sh (harness.c with MPC set).
const MPC_VECTORS: &str = include_str!("../tests/dcn401_spl/mpc_vectors.txt");

/// Every MPC slice of mpc_vectors.txt programs exactly Linux's writes:
/// calculate_mpc_slice_in_timing_active's share of the plane clip (the
/// remainder to the last slices), its recout, viewport and inits.
fn dcn401_spl_matches_linux_mpc_vectors() -> TestResult {
    let mut n = 0;
    for line in MPC_VECTORS
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
        if a.len() != 17 {
            return TestResult::Fail("malformed vector inputs");
        }
        let input = Input {
            mpc_slice: (a[15], a[16]),
            ..input(&a)
        };
        if tokens(&input) != want {
            return TestResult::Fail("MPC slice SPL writes differ from Linux");
        }
        n += 1;
    }
    if n < 200 {
        return TestResult::Fail("too few MPC slice vectors");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-spl",
    dcn401_spl_matches_linux_mpc_vectors
);
