//! `resource_build_scaling_params` on DCN3.0 against values worked by hand
//! from Linux's formulas (`calculate_recout`, `calculate_scaling_ratios`,
//! `dpp3_get_optimal_number_of_taps`, `calculate_init_and_vp`).
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// The register view of a phase: (integer, U0.19 fraction).
fn phase(f: Fx) -> (i32, u32) {
    (f.floor(), u0d19(f))
}

fn dcn30_scaling_positioned_unscaled() -> TestResult {
    // KWin's 55x55 primary at (1912, 1073) on a 2160p CRTC: ratio 1, so
    // both taps collapse to 1 (IDENTITY_RATIO); the recout is the CRTC
    // rectangle and the viewport the whole source.
    let Ok(d) = build(
        3840,
        2160,
        (0, 1),
        Rect::new(0, 0, 55, 55),
        Rect::new(1912, 1073, 55, 55),
    ) else {
        return TestResult::Fail("refused");
    };
    if d.recout != Rect::new(1912, 1073, 55, 55)
        || d.viewport != Rect::new(0, 0, 55, 55)
        || (d.h_taps, d.v_taps) != (1, 1)
        || u3d19(d.ratio_h) != 1 << 19
        || u3d19(d.ratio_v) != 1 << 19
        || (d.h_active, d.v_active) != (3840, 2160)
    {
        return TestResult::Fail("positioned plane geometry");
    }
    // A source offset moves only the viewport.
    let Ok(o) = build(
        3840,
        2160,
        (0, 1),
        Rect::new(100, 40, 55, 55),
        Rect::new(1912, 1073, 55, 55),
    ) else {
        return TestResult::Fail("refused");
    };
    if o.viewport != Rect::new(100, 40, 55, 55) || o.recout != d.recout {
        return TestResult::Fail("source offset");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn30-scl", dcn30_scaling_positioned_unscaled);

fn dcn30_scaling_upscale_and_downscale() -> TestResult {
    // 2x up, 960x540 onto 1920x1080: ratio 0.5, the upscale default of 4
    // taps; init = trunc19((0.5 + 5) / 2) = 2.75; the viewport is
    // floor(2.75 + 0.5 x 1919) = 962 clipped to the 960-pixel source.
    let Ok(up) = build(
        1920,
        1080,
        (0, 1),
        Rect::new(0, 0, 960, 540),
        Rect::new(0, 0, 1920, 1080),
    ) else {
        return TestResult::Fail("2x up refused");
    };
    if up.recout != Rect::new(0, 0, 1920, 1080)
        || up.viewport != Rect::new(0, 0, 960, 540)
        || (up.h_taps, up.v_taps) != (4, 4)
        || u3d19(up.ratio_h) != 1 << 18
        || u3d19(up.ratio_v) != 1 << 18
        || phase(up.init_h) != (2, 3 << 17)
        || phase(up.init_v) != (2, 3 << 17)
    {
        return TestResult::Fail("2x upscale");
    }
    // 2:1 down, 3840x2160 onto 1920x1080: 2 x ceil(2) = 4 horizontal and
    // ceil(2 x 2) = 4 vertical taps; init = (2 + 5) / 2 = 3.5; the line
    // buffer holds 2744 / ceil(1920 / 6) = 8 lines, enough for 4 taps.
    let Ok(down) = build(
        1920,
        1080,
        (0, 1),
        Rect::new(0, 0, 3840, 2160),
        Rect::new(0, 0, 1920, 1080),
    ) else {
        return TestResult::Fail("2:1 down refused");
    };
    if down.viewport != Rect::new(0, 0, 3840, 2160)
        || (down.h_taps, down.v_taps) != (4, 4)
        || u3d19(down.ratio_h) != 2 << 19
        || phase(down.init_h) != (3, 1 << 18)
        || phase(down.init_v) != (3, 1 << 18)
        || lb_partitions(3840, 1920) != 8
    {
        return TestResult::Fail("2:1 downscale");
    }
    // A non-integer ratio, clipped at the right and bottom edges:
    // 1000x500 from (10, 20) into 600x300 at (1500, 900). Both ratios are
    // 5/3, U3.19 floor(5/3 x 2^19) = 873813: 2 x ceil = 4 taps across and
    // ceil(10/3) = 4 down. The recout stops at the screen edge (420 x
    // 180). init = trunc19((873813 + 5 x 2^19) / 2^20) = 1747626 / 2^19;
    // the viewport is floor(init + r x 419) = 701 by floor(init + r x 179)
    // = 301 source pixels.
    let Ok(odd) = build(
        1920,
        1080,
        (0, 1),
        Rect::new(10, 20, 1000, 500),
        Rect::new(1500, 900, 600, 300),
    ) else {
        return TestResult::Fail("5:3 refused");
    };
    if odd.recout != Rect::new(1500, 900, 420, 180)
        || odd.viewport != Rect::new(10, 20, 701, 301)
        || u3d19(odd.ratio_h) != 873_813
        || u3d19(odd.ratio_v) != 873_813
        || (odd.h_taps, odd.v_taps) != (4, 4)
        || phase(odd.init_h) != (3, 1_747_626 - 3 * (1 << 19))
    {
        return TestResult::Fail("5:3 clipped");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn30-scl", dcn30_scaling_upscale_and_downscale);

fn dcn30_scaling_clips_at_the_left_edge_and_odm_slices() -> TestResult {
    // The 2x upscale 100 pixels left of the screen: the recout starts at 0
    // and is 1820 wide; it is 100 destination pixels into the plane, so
    // the viewport starts floor(0.5 x 100) = 50, then backs off up to
    // taps - floor(init) = 2 pixels for the filter (init 2.75 + 2), and
    // spans floor(4.75 + 0.5 x 1819) = 914 pixels clipped to 960 - 48.
    let Ok(left) = build(
        1920,
        1080,
        (0, 1),
        Rect::new(0, 0, 960, 540),
        Rect::new(-100, 0, 1920, 1080),
    ) else {
        return TestResult::Fail("left-clipped refused");
    };
    if left.recout != Rect::new(0, 0, 1820, 1080)
        || left.viewport != Rect::new(48, 0, 912, 540)
        || phase(left.init_h) != (4, 3 << 17)
        || phase(left.init_v) != (2, 3 << 17)
    {
        return TestResult::Fail("left edge clip");
    }
    // ODM 2:1 on 3840: a 100x100 unscaled plane at x = 1900 straddles the
    // slices. The left pipe shows its first 20 columns at x 1900 of its
    // slice; the right pipe its last 80 at x 0, fetched from x 20.
    let src = Rect::new(0, 0, 100, 100);
    let dst = Rect::new(1900, 0, 100, 100);
    let (Ok(a), Ok(b)) = (
        build(3840, 2160, (0, 2), src, dst),
        build(3840, 2160, (1, 2), src, dst),
    ) else {
        return TestResult::Fail("ODM slices refused");
    };
    if (a.h_active, b.h_active) != (1920, 1920)
        || a.recout != Rect::new(1900, 0, 20, 100)
        || a.viewport != Rect::new(0, 0, 20, 100)
        || b.recout != Rect::new(0, 0, 80, 100)
        || b.viewport != Rect::new(20, 0, 80, 100)
    {
        return TestResult::Fail("ODM slices");
    }
    // A plane wholly on the left slice shows nothing on the right one.
    if build(3840, 2160, (1, 2), src, Rect::new(100, 0, 100, 100)) != Err(Error::Empty) {
        return TestResult::Fail("empty slice");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-scl",
    dcn30_scaling_clips_at_the_left_edge_and_odm_slices
);

fn dcn30_scaling_refuses_what_dc_refuses() -> TestResult {
    // 5.5:1 down: ceil(5.5) = 6 taps are needed, but a 1920-pixel line
    // leaves 8 partitions less ceil - 2 = 4.
    if build(
        1920,
        1080,
        (0, 1),
        Rect::new(0, 0, 1920, 5940),
        Rect::new(0, 0, 1920, 1080),
    ) != Err(Error::Taps)
    {
        return TestResult::Fail("line buffer taps");
    }
    // A downscaled source wider than max_downscale_src_width (7680).
    if build(
        3840,
        2160,
        (0, 1),
        Rect::new(0, 0, 8000, 2160),
        Rect::new(0, 0, 3840, 2160),
    ) != Err(Error::Taps)
    {
        return TestResult::Fail("max downscale source width");
    }
    if build(
        1920,
        1080,
        (0, 1),
        Rect::new(0, 0, 0, 10),
        Rect::new(0, 0, 10, 10),
    ) != Err(Error::Invalid)
    {
        return TestResult::Fail("zero source");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-scl",
    dcn30_scaling_refuses_what_dc_refuses
);
