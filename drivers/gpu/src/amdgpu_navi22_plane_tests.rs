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

fn navi22_plane_plans_two_planes_jointly() -> TestResult {
    let t = timing(148_500, (1920, 2200, 88, 44), (1080, 1125, 4, 5));
    let lit = lit(&t);
    let primary = Request::full_screen(1920, 1920, 1080, &t);
    // A 480x270 video overlay upscaled 2x into the centre of the screen.
    let overlay = Request {
        pitch: 480,
        width: 480,
        height: 270,
        src: (0, 0, 480, 270),
        dst: (720, 405, 960, 540),
    };
    let Ok(two) = plan_two(&t, 3_650_000, &soc(), &lit, &primary, &overlay) else {
        return TestResult::Fail("two-plane plan refused");
    };
    // The primary keeps the lit placement; the overlay scales 2x.
    if two.primary.scaler.viewport != scl::Rect::new(0, 0, 1920, 1080)
        || two.overlay.scaler.recout != scl::Rect::new(720, 405, 960, 540)
        || (two.overlay.scaler.h_taps, two.overlay.scaler.v_taps) != (4, 4)
    {
        return TestResult::Fail("two-plane scalers wrong");
    }
    // One joint plan: the same clocks and watermarks on both planes, within
    // the lit stream's clocks; the cursor is budgeted on the primary only.
    if two.primary.plan.clocks != two.overlay.plan.clocks
        || two.primary.plan.hubbub != two.overlay.plan.hubbub
        || two.primary.plan.clocks.dppclk_khz > lit.clocks.dppclk_khz
        || two.primary.plan.clocks.dispclk_khz > lit.clocks.dispclk_khz
        || two.primary.plan.cursor.is_none()
        || two.overlay.plan.cursor.is_some()
    {
        return TestResult::Fail("two-plane joint plan wrong");
    }
    // Each plane has its own HUBP pacing registers, and the slave's DPP
    // clock comes from the joint plan.
    if two.primary.plan.registers == two.overlay.plan.registers || two.overlay_dppclk_khz == 0 {
        return TestResult::Fail("two planes share one pipe");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-plane",
    navi22_plane_plans_two_planes_jointly
);

fn navi22_plane_two_plane_refusals() -> TestResult {
    let t = timing(148_500, (1920, 2200, 88, 44), (1080, 1125, 4, 5));
    let lit = lit(&t);
    let primary = Request::full_screen(1920, 1920, 1080, &t);
    // SRC past the overlay framebuffer.
    let outside = Request {
        pitch: 480,
        width: 480,
        height: 270,
        src: (100, 0, 480, 270),
        dst: (0, 0, 480, 270),
    };
    if plan_two(&t, 3_650_000, &soc(), &lit, &primary, &outside) != Err(Refusal::Invalid) {
        return TestResult::Fail("malformed overlay admitted");
    }
    // 3:1 down needs 2.25x the pixel rate of DPPCLK.
    let three = Request {
        pitch: 5760,
        width: 5760,
        height: 3240,
        src: (0, 0, 5760, 3240),
        dst: (0, 0, 1920, 1080),
    };
    if plan_two(&t, 3_650_000, &soc(), &lit, &primary, &three) != Err(Refusal::Clock) {
        return TestResult::Fail("over-clock overlay admitted");
    }
    // An ODM stream refuses the two-plane path.
    let basis = Basis {
        timing: t,
        vco_khz: 3_650_000,
        soc: soc(),
        lit,
        odm: true,
    };
    if basis.plan_two(&primary, &primary) != Err(Refusal::Odm) {
        return TestResult::Fail("ODM two-plane plan admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-plane",
    navi22_plane_two_plane_refusals
);
