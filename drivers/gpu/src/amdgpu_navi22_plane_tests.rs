//! Placement planning on a lit Navi22 stream.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn soc() -> dml30::Soc {
    dml30::Soc {
        dcn_revision: 0,
        dcfclk_khz: 1_200_000,
        fabric_khz: 1_200_000,
        socclk_khz: 1_000_000,
        dram_speed_mts: 16_000,
        channels: 12,
        channel_width_bytes: 2,
        max_dispclk_khz: 1_330_000,
        max_dppclk_khz: 1_330_000,
        max_phyclk_khz: 810_000,
        dentist_vco_khz: 3_650_000,
        dchub_refclk_khz: 50_000,
    }
}
fn timing(pclk: u32, h: (u32, u32, u32, u32), v: (u32, u32, u32, u32)) -> Timing {
    Timing {
        pixel_clock_khz: pclk,
        h_active: h.0,
        h_total: h.1,
        h_front_porch: h.2,
        h_sync_width: h.3,
        v_active: v.0,
        v_total: v.1,
        v_front_porch: v.2,
        v_sync_width: v.3,
        h_sync_positive: true,
        v_sync_positive: true,
    }
}
/// The modeset's own plan of `t` on an `h_active`-pitch surface.
fn lit(t: &Timing) -> dml30::Plan {
    let config = Config {
        timing: *t,
        plane: Plane {
            format: Format::Rgb32,
            surface_width: t.h_active,
            surface_height: t.v_active,
            viewport_width: t.h_active,
            viewport_height: t.v_active,
            pitch: t.h_active,
            h_taps: 1,
            v_taps: 1,
        },
        dentist_vco_khz: 3_650_000,
        cursors: 1,
    };
    dml30::plan(&config, &soc()).expect("the lit mode")
}

fn navi22_plane_full_screen_request_is_the_lit_plan() -> TestResult {
    let t = timing(148_500, (1920, 2200, 88, 44), (1080, 1125, 4, 5));
    let lit = lit(&t);
    let full = Request::full_screen(1920, 1920, 1080, &t);
    let Ok(u) = plan(&t, 3_650_000, &soc(), &lit, &full) else {
        return TestResult::Fail("full-screen request refused");
    };
    // An identity Scale with the recout equal to the viewport is DML's
    // unscaled plane: the same plan the modeset programmed.
    if u.plan != lit
        || u.scaler.viewport != scl::Rect::new(0, 0, 1920, 1080)
        || (u.scaler.h_taps, u.scaler.v_taps) != (1, 1)
    {
        return TestResult::Fail("full-screen plan differs from the lit one");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-plane",
    navi22_plane_full_screen_request_is_the_lit_plan
);

fn navi22_plane_plans_positioned_and_scaled_primaries() -> TestResult {
    // KWin's 55x55 primary at (1912, 1073) on 2160p60.
    let uhd = timing(594_000, (3840, 4400, 176, 88), (2160, 2250, 8, 10));
    let lit_uhd = lit(&uhd);
    let kwin = Request {
        pitch: 64,
        width: 55,
        height: 55,
        src: (0, 0, 55, 55),
        dst: (1912, 1073, 55, 55),
    };
    let Ok(k) = plan(&uhd, 3_650_000, &soc(), &lit_uhd, &kwin) else {
        return TestResult::Fail("KWin placement refused");
    };
    if k.scaler.recout != scl::Rect::new(1912, 1073, 55, 55)
        || k.plan.geometry.swath_width != 55
        || k.plan.clocks.dppclk_khz != lit_uhd.clocks.dppclk_khz
    {
        return TestResult::Fail("KWin placement plan");
    }
    let t = timing(148_500, (1920, 2200, 88, 44), (1080, 1125, 4, 5));
    let lit = lit(&t);
    // 2x up and 2:1 down need no more DPPCLK than the lit stream.
    let up = Request {
        pitch: 960,
        width: 960,
        height: 540,
        src: (0, 0, 960, 540),
        dst: (0, 0, 1920, 1080),
    };
    let down = Request {
        pitch: 3840,
        width: 3840,
        height: 2160,
        src: (0, 0, 3840, 2160),
        dst: (0, 0, 1920, 1080),
    };
    let (Ok(u), Ok(d)) = (
        plan(&t, 3_650_000, &soc(), &lit, &up),
        plan(&t, 3_650_000, &soc(), &lit, &down),
    ) else {
        return TestResult::Fail("2x up or 2:1 down refused");
    };
    if (u.scaler.h_taps, d.scaler.h_taps) != (4, 4)
        || u.plan.geometry.v_ratio != crate::amdgpu_dml::Fx::ratio(1, 2)
        || d.plan.geometry.v_ratio != crate::amdgpu_dml::Fx::int(2)
    {
        return TestResult::Fail("scaled plans");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-plane",
    navi22_plane_plans_positioned_and_scaled_primaries
);

fn navi22_plane_refusals() -> TestResult {
    let t = timing(148_500, (1920, 2200, 88, 44), (1080, 1125, 4, 5));
    let lit = lit(&t);
    // 3:1 down needs 2.25x the pixel rate of DPPCLK.
    let three = Request {
        pitch: 5760,
        width: 5760,
        height: 3240,
        src: (0, 0, 5760, 3240),
        dst: (0, 0, 1920, 1080),
    };
    if plan(&t, 3_650_000, &soc(), &lit, &three) != Err(Refusal::Clock) {
        return TestResult::Fail("DPPCLK raise admitted");
    }
    // SRC past the framebuffer, and a pitch past the HUBP's field.
    let outside = Request {
        pitch: 1920,
        width: 1920,
        height: 1080,
        src: (100, 0, 1920, 1080),
        dst: (0, 0, 1920, 1080),
    };
    let wide = Request {
        pitch: 0x4001,
        ..outside
    };
    if plan(&t, 3_650_000, &soc(), &lit, &outside) != Err(Refusal::Invalid)
        || plan(&t, 3_650_000, &soc(), &lit, &wide) != Err(Refusal::Invalid)
    {
        return TestResult::Fail("malformed request");
    }
    // DC's tap refusal surfaces as a geometry refusal.
    let taps = Request {
        pitch: 1920,
        width: 1920,
        height: 5940,
        src: (0, 0, 1920, 5940),
        dst: (0, 0, 1920, 1080),
    };
    if plan(&t, 3_650_000, &soc(), &lit, &taps) != Err(Refusal::Geometry(scl::Error::Taps)) {
        return TestResult::Fail("tap refusal");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu/navi22-plane", navi22_plane_refusals);
