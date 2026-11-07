//! Display-14 `wm_level_disabled` (`skl_wm_check_vblank`) and the Pipe-A
//! Wa_14015648006 provider. Expected values are worked by hand from Linux
//! b90c984d skl_watermark.c / skl_prefill.c, independently of this
//! module's arithmetic.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// 100 MHz pixel rate, htotal 1000: one line is exactly 10 µs, so
/// `prefill_usecs_to_lines` is `us / 10` lines with no rounding for
/// multiples of 10. 100 lines of vblank.
fn ten_us_lines() -> Timing {
    Timing {
        pixel_rate_khz: 100_000,
        htotal: 1000,
        vtotal: 1100,
        vblank_start: 1000,
    }
}

fn latency(levels: [u16; LEVELS]) -> Latency {
    Latency {
        levels,
        sagv_block_us: 0,
        qgv: None,
    }
}

fn level(lines: u16) -> Level {
    Level {
        enable: true,
        blocks: 8,
        lines,
        min_ddb_alloc: 9,
    }
}

fn smoke_xelpg_wm_level_disabled_follows_skl_wm_check_vblank() -> TestResult {
    let t = ten_us_lines();
    // prefill.full with no wm0 lines: framestart delay (1 line) + 20 µs
    // of translation walks (2 lines) = 3 lines. Guardband 100 lines: a
    // latency of 970 µs (97 lines) fits exactly, 980 µs does not.
    assert_eq!(
        wm_level_disabled(t, &latency([6, 10, 100, 500, 900, 970]), 0),
        Ok(false)
    );
    assert_eq!(
        wm_level_disabled(t, &latency([6, 10, 100, 500, 900, 980]), 0),
        Ok(true)
    );
    // 20 wm0 lines at 100 MHz: calc_cdclk(50 MHz) is 172.8 MHz, adj =
    // ceil(100000 << 16 / 345600) = 18963, so wm0 adds 20 * 18963 / 65536
    // = 5.79 lines: 900 µs (90 lines) fits, 920 µs (92) does not.
    assert_eq!(
        wm_level_disabled(t, &latency([6, 10, 100, 500, 800, 900]), 20),
        Ok(false)
    );
    assert_eq!(
        wm_level_disabled(t, &latency([6, 10, 100, 500, 800, 920]), 20),
        Ok(true)
    );
    // A zero latency level is skipped: a table ending early reports the
    // top level as unreachable, as Linux does.
    assert_eq!(
        wm_level_disabled(t, &latency([6, 10, 100, 500, 900, 0]), 0),
        Ok(true)
    );
    assert_eq!(
        wm_level_disabled(t, &latency([6, 0, 0, 0, 0, 0]), 0),
        Ok(true)
    );
    // Level 0 is tested at zero latency; a 2-line vblank cannot hold the
    // 3-line prefill: skl_max_wm_level_for_vblank's -EINVAL.
    let short = Timing { vtotal: 1002, ..t };
    assert_eq!(
        wm_level_disabled(short, &latency([6, 10, 100, 500, 900, 970]), 0),
        Err(WmError::VblankTooShort)
    );
    let none = Timing { vtotal: 1000, ..t };
    assert_eq!(
        wm_level_disabled(none, &latency([6, 10, 100, 500, 900, 970]), 0),
        Err(WmError::Unsupported)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_wm",
    smoke_xelpg_wm_level_disabled_follows_skl_wm_check_vblank
);

fn smoke_xelpg_wm_check_vblank_returns_its_level_decision() -> TestResult {
    let t = ten_us_lines();
    let lat = latency([6, 10, 100, 500, 800, 920]);
    let mut primary = PlaneWm {
        levels: [level(20); LEVELS],
        ..Default::default()
    };
    let mut cursor = PlaneWm {
        levels: [level(5); LEVELS],
        ..Default::default()
    };
    // The worst wm0 lines (20) decide, exactly as wm_level_disabled sees
    // them; only the level above the maximum loses its enable bit and
    // keeps its blocks/lines.
    assert_eq!(
        check_vblank(t, &lat, &mut [&mut primary, &mut cursor]),
        Ok(true)
    );
    assert_eq!(wm_level_disabled(t, &lat, 20), Ok(true));
    for plane in [&primary, &cursor] {
        assert!(plane.levels[..LEVELS - 1].iter().all(|l| l.enable));
        assert!(!plane.levels[LEVELS - 1].enable);
        assert_eq!(plane.levels[LEVELS - 1].blocks, 8);
    }
    let mut primary = PlaneWm {
        levels: [level(20); LEVELS],
        ..Default::default()
    };
    let lat = latency([6, 10, 100, 500, 800, 900]);
    assert_eq!(check_vblank(t, &lat, &mut [&mut primary]), Ok(false));
    assert!(primary.levels.iter().all(|l| l.enable));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_wm",
    smoke_xelpg_wm_check_vblank_returns_its_level_decision
);

/// The owned Pipe-A profile records the value the resource transaction's
/// own vblank check computed: its primary and always-budgeted cursor
/// level-0 lines survive DDB allocation unchanged.
fn smoke_xelpg_wm_profile_value_matches_transaction_vblank_check() -> TestResult {
    let mode = crate::intel_gpu_modeset::Mode {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_total: 2200,
        v_active: 1080,
        v_total: 1125,
        ..crate::intel_gpu_modeset::Mode::VESA_1024X768_60
    };
    let t = Timing {
        pixel_rate_khz: 148_500,
        htotal: 2200,
        vtotal: 1125,
        vblank_start: 1080,
    };
    // 45 vblank lines of 14.8 µs: a 300 µs top level fits; 700 µs (47.2
    // lines) cannot; a zero top latency is unreachable.
    for (levels, want) in [
        ([6, 20, 40, 80, 150, 300], false),
        ([6, 20, 40, 80, 150, 700], true),
        ([6, 20, 40, 80, 150, 0], true),
    ] {
        let lat = latency(levels);
        for tiling in [Tiling::Linear, Tiling::Tile4] {
            let state = crate::intel_gpu_xelpg_resources::compute(
                &crate::intel_gpu_display_resources::request(&mode, tiling, 0),
                &lat,
            )
            .unwrap();
            let alloc = &state.dbuf.pipes[0];
            let wm0 = alloc.wm[0].levels[0]
                .lines
                .max(alloc.cursor_wm.levels[0].lines);
            let mut primary = plane(
                t,
                Surface {
                    width: 1920,
                    cpp: 4,
                    tiling,
                },
                &lat,
            )
            .unwrap();
            let mut cursor = plane(
                t,
                Surface {
                    width: 64,
                    cpp: 4,
                    tiling: Tiling::Linear,
                },
                &lat,
            )
            .unwrap();
            let checked = check_vblank(t, &lat, &mut [&mut primary, &mut cursor]);
            assert_eq!(checked, Ok(want));
            assert_eq!(wm_level_disabled(t, &lat, wm0), checked);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_wm",
    smoke_xelpg_wm_profile_value_matches_transaction_vblank_check
);

fn smoke_xelpg_wm_pipe_a_provider_publishes_and_registers() -> TestResult {
    let previous = crate::intel_gpu_psr::register_wm_level_disabled(None);
    publish_pipe_a(None);
    assert_eq!(pipe_a_wm_level_disabled(), None);
    publish_pipe_a(Some(true));
    assert_eq!(pipe_a_wm_level_disabled(), Some(true));
    publish_pipe_a(Some(false));
    assert_eq!(pipe_a_wm_level_disabled(), Some(false));
    // Without registration PSR has no input; registered, it reads the
    // current publication, including a later "unknown".
    assert_eq!(crate::intel_gpu_psr::wm_level_disabled(), None);
    register_psr_provider();
    assert_eq!(crate::intel_gpu_psr::wm_level_disabled(), Some(false));
    publish_pipe_a(Some(true));
    assert_eq!(crate::intel_gpu_psr::wm_level_disabled(), Some(true));
    publish_pipe_a(None);
    assert_eq!(crate::intel_gpu_psr::wm_level_disabled(), None);
    crate::intel_gpu_psr::register_wm_level_disabled(previous);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_wm",
    smoke_xelpg_wm_pipe_a_provider_publishes_and_registers
);

fn smoke_xelpg_wm_dsc_prefill_adds_one_and_a_half_lines() -> TestResult {
    // prefill_lines_nocdclk adds intel_vdsc_prefill_lines (0x18000) before
    // the CDCLK adjustment: at 100 MHz the adjustment is
    // ceil(100000 << 16 / 345600) = 18963, so DSC adds
    // ceil(0x18000 * 18963 / 65536) = 28445 (.16) lines. A 970 us level
    // (97 lines) fitted the 100-line vblank exactly without DSC and no
    // longer does; 960 us (96 lines) still fits.
    let t = ten_us_lines();
    let lat = latency([6, 10, 100, 500, 900, 970]);
    if wm_level_disabled_dsc(t, &lat, 0, false) != Ok(false)
        || wm_level_disabled_dsc(t, &lat, 0, true) != Ok(true)
        || wm_level_disabled_dsc(t, &latency([6, 10, 100, 500, 900, 960]), 0, true) != Ok(false)
    {
        return TestResult::Fail("the DSC prefill must count 1.5 adjusted lines");
    }
    // check_vblank_dsc drops the levels that no longer fit.
    let mut primary = PlaneWm::default();
    for l in primary.levels.iter_mut() {
        *l = level(4);
    }
    if check_vblank_dsc(t, &lat, &mut [&mut primary], true) != Ok(true)
        || primary.levels[5].enable
        || !primary.levels[4].enable
    {
        return TestResult::Fail("a compressing pipe loses the top level here");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_wm",
    smoke_xelpg_wm_dsc_prefill_adds_one_and_a_half_lines
);

fn smoke_xelpg_wm_scaler_prefill_adds_four_lines() -> TestResult {
    let t = ten_us_lines();
    let lat = latency([6, 10, 100, 500, 900, 960]);
    // Without scaler: latency 960 us fits into 100-line guardband (3 fixed lines + 96 lines = 99 lines <= 100).
    // With scaler: adds 4 lines * 18963 / 65536 = 1.157 lines: 3 + 1.157 + 96 = 100.157 lines > 100, so level 5 fails to fit.
    if wm_level_disabled_dsc(t, &lat, 0, false) != Ok(false) {
        return TestResult::Fail("without scaler, latency 960 us must fit");
    }
    let mut primary = PlaneWm::default();
    for l in primary.levels.iter_mut() {
        *l = level(4);
    }
    if check_vblank_dsc_scaler_ip(
        crate::intel_gpu_xe2lpd::DisplayIp::Xelpdp,
        t,
        &lat,
        &mut [&mut primary],
        false,
        true,
    ) != Ok(true)
        || primary.levels[5].enable
        || !primary.levels[4].enable
    {
        return TestResult::Fail("a scaled pipe must lose level 5 due to 4-line scaler prefill");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_wm",
    smoke_xelpg_wm_scaler_prefill_adds_four_lines
);
