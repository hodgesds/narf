use super::*;
use crate::amdgpu_dcn401_otg::tests::engine;
use narf_kernel_test::{kernel_test_in, TestResult};

fn dcn401_cursor_placement_follows_dcn401_clipping() -> TestResult {
    let at = |x, y| placement(x, y, (64, 64), (1920, 1080), (100_000, 148_500));
    let visible = |x, y, hot_x, hot_y, dst| Placement {
        visible: true,
        x,
        y,
        hot_x,
        hot_y,
        dst_x_offset: dst,
    };
    // On screen: position as given; DST_X_OFFSET in reference clocks.
    if at(100, 50) != visible(100, 50, 0, 0, 67) {
        return TestResult::Fail("on-screen placement");
    }
    // Negative origins move into the hotspot (amdgpu_dm/dcn401 rule).
    if at(-10, -5) != visible(0, 0, 10, 5, 0) || at(-63, 0) != visible(0, 0, 63, 0, 0) {
        return TestResult::Fail("negative origin");
    }
    // Last visible pixels, then fully off screen on each side.
    if !at(1919, 1079).visible {
        return TestResult::Fail("bottom-right pixel hidden");
    }
    for (x, y) in [
        (-64, 0),
        (0, -64),
        (1920, 0),
        (0, 1080),
        (i32::MIN, i32::MAX),
    ] {
        if at(x, y).visible {
            return TestResult::Fail("off-screen cursor shown");
        }
    }
    if lines_per_chunk(64) != 3 || lines_per_chunk(32) != 4 || lines_per_chunk(1) != 4 {
        return TestResult::Fail("lines per chunk");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-cursor",
    dcn401_cursor_placement_follows_dcn401_clipping
);

fn dcn401_cursor_requires_live_scanout_and_bounded_image() -> TestResult {
    let mut e = engine();
    let surfaces = Surfaces::new();
    let pixels = alloc::vec![0u32; 64 * 64];
    if surfaces.move_cursor(&mut e, 0, (0, 0)) != Err(Error::Invalid)
        || e.status.state != State::Ready
    {
        return TestResult::Fail("cursor move without cursor");
    }
    for (w, h, len) in [(0, 64, 0), (65, 1, 65), (64, 64, 64 * 64 - 1)] {
        if !matches!(validate_image(w, h, &pixels[..len]), Err(Error::Invalid)) {
            return TestResult::Fail("bad cursor image accepted");
        }
    }
    if validate_image(64, 64, &pixels).is_err() {
        return TestResult::Fail("64x64 rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-cursor",
    dcn401_cursor_requires_live_scanout_and_bounded_image
);
