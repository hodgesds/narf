use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn hd() -> Timing {
    Timing {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_total: 2200,
        h_front_porch: 88,
        h_sync_width: 44,
        v_active: 1080,
        v_total: 1125,
        v_front_porch: 4,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: true,
    }
}
fn surface(address: u64) -> Surface {
    Surface {
        address,
        fb: GenericFb::new(0xe000_0000 + address, 1920, 1080, 7680, 32),
    }
}

fn navi22_scanout_buffers_swap_only_with_a_back_buffer() -> TestResult {
    let mut b = Buffers::new(surface(0x1000));
    if b.back().is_some() || b.swap() != Err(Error::Invalid) || b.front().address != 0x1000 {
        return TestResult::Fail("flip without a back buffer");
    }
    b.surfaces[1] = Some(surface(0x9000));
    if b.swap().is_err()
        || b.front().address != 0x9000
        || b.back().map(|s| s.address) != Some(0x1000)
    {
        return TestResult::Fail("first flip roles");
    }
    if b.swap().is_err()
        || b.front().address != 0x1000
        || b.back().map(|s| s.address) != Some(0x9000)
    {
        return TestResult::Fail("second flip roles");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_scanout_buffers_swap_only_with_a_back_buffer
);

fn navi22_scanout_flip_deadline_and_vblank_phase() -> TestResult {
    // 1080p60: 16.67 ms frames -> 4 frames + 20 ms.
    let t = hd();
    if flip_timeout_us(&t) != 4 * 16_666 + 20_000 {
        return TestResult::Fail("flip deadline");
    }
    let slow = Timing {
        pixel_clock_khz: 0,
        ..t
    };
    if flip_timeout_us(&slow) != 50_000 {
        return TestResult::Fail("degenerate timing deadline");
    }
    // Inside vblank (line 1100 of a blank starting at 1084): the count
    // already includes this vblank, which began 16 lines ago.
    let p = Position {
        frame: 7,
        vpos: 1100,
        hpos: 0,
        vblank_start: 1084,
        vblank_end: 41,
    };
    let Some(phase) = vblank_phase(p, &t) else {
        return TestResult::Fail("no phase");
    };
    if phase.count != 8
        || phase.start_ns != -(16 * 2200 * 1_000_000 / 148_500)
        || phase.period_ns != 16_666_666
    {
        return TestResult::Fail("vblank phase");
    }
    if vblank_phase(Position { vpos: 2000, ..p }, &t).is_some() {
        return TestResult::Fail("impossible position accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_scanout_flip_deadline_and_vblank_phase
);

fn navi22_cursor_digest_distinguishes_images() -> TestResult {
    let a = [0xffff_ffffu32; 4];
    let mut b = a;
    b[3] = 0;
    if image_digest(2, 2, &a) == image_digest(2, 2, &b)
        || image_digest(2, 2, &a) == image_digest(4, 1, &a)
        || image_digest(2, 2, &a) != image_digest(2, 2, &a)
        || image_digest(1, 1, &[0]) == 0
    {
        return TestResult::Fail("cursor image identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_cursor_digest_distinguishes_images
);
