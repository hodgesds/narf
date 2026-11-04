//! Display-14 panel-fitter window, scaler admission, PS_* image and
//! nearest-neighbour coefficients, worked by hand from Linux b90c984d
//! intel_pfit.c / skl_scaler.c / drm_rect.c.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn panel(h: u16, v: u16) -> Mode {
    Mode {
        h_active: h,
        h_total: h + 160,
        h_sync_start: h + 48,
        h_sync_end: h + 80,
        v_active: v,
        v_total: v + 30,
        v_sync_start: v + 3,
        v_sync_end: v + 9,
        ..Mode::VESA_1024X768_60
    }
}

fn smoke_xelpg_scaler_panel_fit_windows_follow_pch_panel_fitting() -> TestResult {
    let w = |x, y, width, height| {
        Some(Window {
            x,
            y,
            width,
            height,
        })
    };
    let oled = panel(2880, 1800);
    let fhd = panel(1920, 1080);
    let wuxga = panel(1920, 1200);
    let cases = [
        // A native source needs no fitting.
        (panel_fit(&oled, 2880, 1800, ScalingMode::Aspect), None),
        // 16:9 on 16:10: letterbox, height 2880 * 1080 / 1920 = 1620,
        // y = (1800 - 1620 + 1) / 2 = 90.
        (
            panel_fit(&oled, 1920, 1080, ScalingMode::Aspect),
            w(0, 90, 2880, 1620),
        ),
        // 4:3 on 16:9: pillarbox, width 1024 * 1080 / 768 = 1440,
        // x = (1920 - 1440 + 1) / 2 = 240.
        (
            panel_fit(&fhd, 1024, 768, ScalingMode::Aspect),
            w(240, 0, 1440, 1080),
        ),
        // 1366x768 on 1920x1200: 1920 * 768 / 1366 = 1079 is odd and
        // rounds up to 1080; y = (1200 - 1080 + 1) / 2 = 60.
        (
            panel_fit(&wuxga, 1366, 768, ScalingMode::Aspect),
            w(0, 60, 1920, 1080),
        ),
        // Equal aspect: the whole panel.
        (
            panel_fit(&oled, 1280, 800, ScalingMode::Aspect),
            w(0, 0, 2880, 1800),
        ),
        // Centered: (2880 - 1920 + 1) / 2 = 480, (1800 - 1080 + 1) / 2 = 360.
        (
            panel_fit(&oled, 1920, 1080, ScalingMode::Center),
            w(480, 360, 1920, 1080),
        ),
        (
            panel_fit(&oled, 1920, 1080, ScalingMode::Fullscreen),
            w(0, 0, 2880, 1800),
        ),
    ];
    if cases.iter().any(|(got, want)| got != want) {
        return TestResult::Fail("the window must follow pch_panel_fitting");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_scaler",
    smoke_xelpg_scaler_panel_fit_windows_follow_pch_panel_fitting
);

fn smoke_xelpg_scaler_admission_scales_and_refusals() -> TestResult {
    let oled = panel(2880, 1800);
    // 1920x1080 into 2880x1620: drm_calc_scale rounds down below 1.0,
    // 1920 << 16 / 2880 = 0xaaaa both ways; scaler 0.
    let Ok(Some(s)) = plan(&oled, 1920, 1080, ScalingMode::Aspect, Filter::Default) else {
        return TestResult::Fail("an upscale must be admitted");
    };
    if (s.id, s.hscale, s.vscale) != (0, 0xaaaa, 0xaaaa) {
        return TestResult::Fail("scaler 0 at 0xaaaa");
    }
    if plan(&oled, 2880, 1800, ScalingMode::Aspect, Filter::Default) != Ok(None) {
        return TestResult::Fail("a native source needs no scaler");
    }
    // calculate_max_scale (display 14): scaler 0 takes 3.0 both ways,
    // scaler 1 no vertical downscale.
    if max_scale(0) != (0x2ffff, 0x2ffff) || max_scale(1) != (0x2ffff, 0x10000) {
        return TestResult::Fail("display 14 scale limits");
    }
    let cases = [
        // 3840x2400 on the 2880x1800 panel: 4/3 downscale.
        (
            plan(&oled, 3840, 2400, ScalingMode::Fullscreen, Filter::Default),
            Err(ScalerRefusal::Downscale),
        ),
        // 4000x1600 into 1000x400: 4.0 exceeds 3.0 (Linux's refusal first).
        (
            plan(
                &panel(1000, 400),
                4000,
                1600,
                ScalingMode::Fullscreen,
                Filter::Default,
            ),
            Err(ScalerRefusal::Ratio),
        ),
        // skl_scaler_max_src_size on display 14: 4096 wide.
        (
            plan(
                &panel(6000, 3000),
                4100,
                2000,
                ScalingMode::Fullscreen,
                Filter::Default,
            ),
            Err(ScalerRefusal::OutOfRange),
        ),
        // Below the 8x8 minimum.
        (
            plan(&oled, 4, 1800, ScalingMode::Fullscreen, Filter::Default),
            Err(ScalerRefusal::OutOfRange),
        ),
        // A centered source larger than the panel is off the panel.
        (
            plan(&oled, 3000, 1800, ScalingMode::Center, Filter::Default),
            Err(ScalerRefusal::OutOfRange),
        ),
    ];
    if cases.iter().any(|(got, want)| got != want) {
        return TestResult::Fail("unqualified ratios and sizes must refuse typed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_scaler",
    smoke_xelpg_scaler_admission_scales_and_refusals
);

fn smoke_xelpg_scaler_pfit_registers_and_nearest_coefficients() -> TestResult {
    // skl_scaler_calc_phase(1, scale, false): -0.5 + scale / 2, wrapped to
    // u2.13 with the trip bit at or above 0.
    if calc_phase(0x10000) != 0x0001 || calc_phase(0x8000) != 0x3000 || calc_phase(0xaaaa) != 0x3554
    {
        return TestResult::Fail("the initial phase must follow skl_scaler_calc_phase");
    }
    let oled = panel(2880, 1800);
    let Ok(Some(s)) = plan(&oled, 1920, 1080, ScalingMode::Aspect, Filter::Default) else {
        return TestResult::Fail("an upscale must be admitted");
    };
    // skl_pfit_enable on Pipe B (scaler 0 at 0x68980): CTRL (enable, pipe
    // binding, normal mode, medium filter), VPHASE, HPHASE, WIN_POS,
    // WIN_SZ.
    let want = [
        (0x6_8980, 1 << 31),
        (0x6_8988, 0x3554),
        (0x6_8994, 0x3554),
        (0x6_8970, 90),
        (0x6_8974, (2880 << 16) | 1620),
    ];
    if s.enable_writes(Pipe::B) != want {
        return TestResult::Fail("skl_pfit_enable's image must match");
    }
    if s.enable_writes(Pipe::A)[0] != (0x6_8180, 1 << 31)
        || ps_ctrl(Pipe::C, 1) != 0x6_9280
        || ps_win_sz(Pipe::D, 0) != 0x6_9974
    {
        return TestResult::Fail("SKL_PS_* sit 0x800 per pipe, 0x100 per scaler");
    }
    // skl_scaler_disable: both scalers detached.
    if disable_writes(Pipe::A)
        != [
            (0x6_8180, 0),
            (0x6_8170, 0),
            (0x6_8174, 0),
            (0x6_8280, 0),
            (0x6_8270, 0),
            (0x6_8274, 0),
        ]
    {
        return TestResult::Fail("skl_scaler_disable detaches both scalers");
    }
    // Nearest neighbour: the programmed filter, then 17 x 7 taps with the
    // centre tap (index % 7 == 3) at 1.0, set 0, auto-incrementing.
    let Ok(Some(n)) = plan(
        &oled,
        1440,
        900,
        ScalingMode::Fullscreen,
        Filter::NearestNeighbor,
    ) else {
        return TestResult::Fail("an integer upscale must be admitted");
    };
    let w = n.enable_writes(Pipe::A);
    if w.len() != 62 + 5
        || w[0] != (0x6_8198, 1 << 10)
        || w[1] != (0x6_819c, 0x3000_3000)
        || w[2] != (0x6_819c, 0x0800_3000)
        || w[60] != (0x6_819c, 0x3000_3000)
        || w[61] != (0x6_8198, 0)
        || w[62] != (0x6_8180, (1 << 31) | (1 << 23))
        || w[1..61]
            .iter()
            .filter(|&&(_, v)| v & 0x0800_0800 != 0)
            .count()
            != 17
    {
        return TestResult::Fail("glk_program_nearest_filter_coefs' table must be written");
    }
    // 2x both ways: phase 0x3000, no trip.
    if (n.hscale, n.vscale) != (0x8000, 0x8000) || w[63].1 != 0x3000 || w[64].1 != 0x3000 {
        return TestResult::Fail("a 2x upscale starts at phase 0x3000");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_scaler",
    smoke_xelpg_scaler_pfit_registers_and_nearest_coefficients
);

fn smoke_xelpg_scaler_prefill_lines() -> TestResult {
    // skl_scaler_1st/2nd_prefill_lines: four lines for the first scaler
    // user, four more for a second with the panel fitter.
    if prefill_lines(0, false) != (0, 0)
        || prefill_lines(1, true) != (4 << 16, 0)
        || prefill_lines(2, false) != (4 << 16, 0)
        || prefill_lines(2, true) != (4 << 16, 4 << 16)
    {
        return TestResult::Fail("the scaler prefill must follow skl_scaler.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_scaler",
    smoke_xelpg_scaler_prefill_lines
);
