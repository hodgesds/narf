//! `abs_to_px` per-axis scaling smokes.
//!
//! A virtio-tablet reports an absolute position over a *square* device range
//! (QEMU: 0..0x7FFF on both axes) that covers the whole screen. The kernel
//! reconstructs relative deltas as the difference of two `abs_to_px` results.
//! Mapping both axes onto one nominal span stretches the shorter axis — on a
//! 1024x768 output a Y mapped to a 1024-px span runs 1.33x fast. These pin the
//! contract that each axis maps onto its own `span` (scanout width / height).

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::abs_to_px;
use narf_input::AxisInfo;

fn qemu_tablet_axis() -> AxisInfo {
    // QEMU virtio-tablet advertises 0..0x7FFF, res/fuzz/flat = 0.
    AxisInfo {
        min: 0,
        max: 0x7FFF,
        fuzz: 0,
        flat: 0,
        res: 0,
    }
}

/// A full min→max sweep telescopes to exactly `span` pixels on either axis,
/// so a corner-to-corner host move lands the pointer on the opposite corner.
fn smoke_abs_to_px_full_sweep_is_span() -> TestResult {
    let info = Some(qemu_tablet_axis());
    let a = qemu_tablet_axis();
    for span in [640_i64, 768, 1024, 1920] {
        let d = abs_to_px(a.max, info, span) - abs_to_px(a.min, info, span);
        if d != span as i32 {
            return TestResult::Fail("full-range sweep did not telescope to span");
        }
    }
    TestResult::Pass
}

/// The midpoint of the range maps to the middle of the axis, and the X (1024)
/// and Y (768) spans differ — the regression that motivated the fix: with a
/// shared 1024 span, Y at midrange would land at 512 (a third too low) instead
/// of 384.
fn smoke_abs_to_px_midpoint_per_axis() -> TestResult {
    let info = Some(qemu_tablet_axis());
    let mid = 0x7FFF / 2;
    let x = abs_to_px(mid, info, 1024);
    let y = abs_to_px(mid, info, 768);
    // Integer division of 0x3FFF*span/0x7FFF: X≈511, Y≈383 (one below exact
    // center from the truncation) — allow the off-by-one, reject the ~512 that
    // a shared 1024 span would produce for Y.
    if !(510..=512).contains(&x) {
        return TestResult::Fail("X midpoint not at ~512 on a 1024 span");
    }
    if !(382..=384).contains(&y) {
        return TestResult::Fail("Y midpoint not at ~384 on a 768 span (shared-span regression)");
    }
    TestResult::Pass
}

/// Monotonic: larger absolute samples never map to smaller pixel positions,
/// and a clamped out-of-range sample pins to the axis extent.
fn smoke_abs_to_px_monotonic_and_clamped() -> TestResult {
    let info = Some(qemu_tablet_axis());
    let mut prev = i32::MIN;
    for step in 0..=16 {
        let v = (0x7FFF * step) / 16;
        let px = abs_to_px(v, info, 768);
        if px < prev {
            return TestResult::Fail("abs_to_px not monotonic");
        }
        prev = px;
    }
    // Beyond max clamps to the top of the span; below min clamps to 0.
    if abs_to_px(0x7FFF + 5000, info, 768) != 768 {
        return TestResult::Fail("over-range sample not clamped to span");
    }
    if abs_to_px(-5000, info, 768) != 0 {
        return TestResult::Fail("under-range sample not clamped to 0");
    }
    TestResult::Pass
}

/// No advertised range → fixed ~1/32 shrink, independent of the requested
/// span (there's no device range to normalise against).
fn smoke_abs_to_px_no_axisinfo_fallback() -> TestResult {
    if abs_to_px(0x7FFF, None, 768) != 0x7FFF / 32 {
        return TestResult::Fail("no-axisinfo fallback is not v/32");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/virtio/input_pci", smoke_abs_to_px_full_sweep_is_span);
kernel_test_in!("drivers/virtio/input_pci", smoke_abs_to_px_midpoint_per_axis);
kernel_test_in!(
    "drivers/virtio/input_pci",
    smoke_abs_to_px_monotonic_and_clamped
);
kernel_test_in!(
    "drivers/virtio/input_pci",
    smoke_abs_to_px_no_axisinfo_fallback
);
