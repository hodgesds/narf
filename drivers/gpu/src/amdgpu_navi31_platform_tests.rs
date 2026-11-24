//! Navi31 platform skeleton: framebuffer geometry, the stage list, and the
//! prepare/run contract. The retain path (a bound Navi31 card) is exercised
//! by the boot handoff, not here: it needs a real clock preflight.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn fb(addr: u64) -> GenericFb {
    // 1920x1080x32bpp, pitch 7680: 8_294_400 bytes.
    GenericFb::new(addr, 1920, 1080, 7680, 32)
}

fn framebuffer_range_classifies_the_boot_framebuffer() -> TestResult {
    // No framebuffer: nothing affected.
    if framebuffer_range(0..(256 << 20), None) != Ok(None) {
        return TestResult::Fail("absent framebuffer reported as affected");
    }
    // Inside the aperture: affected, with the exact range.
    let inside = framebuffer_range(0..(256 << 20), Some(fb(0x1000)));
    if inside != Ok(Some(0x1000..0x1000 + 8_294_400)) {
        return TestResult::Fail("in-aperture framebuffer range is wrong");
    }
    // Entirely outside the aperture: not affected.
    if framebuffer_range(0..(256 << 20), Some(fb(1 << 30))) != Ok(None) {
        return TestResult::Fail("off-GPU framebuffer reported as affected");
    }
    // Partial overlap is an invalid handoff, not evidence of absence.
    if framebuffer_range(0..(256 << 20), Some(fb((256 << 20) - 4096))).is_ok() {
        return TestResult::Fail("partially overlapping framebuffer accepted");
    }
    // Degenerate aperture, zero-size framebuffer, and a pitch too narrow
    // for the width are all invalid.
    for (aperture, framebuffer) in [
        (0..0, Some(fb(0))),
        (0..(256 << 20), Some(GenericFb::new(0, 1920, 1080, 7680, 0))),
        (0..(256 << 20), Some(GenericFb::new(0, 1920, 1080, 100, 32))),
    ] {
        if framebuffer_range(aperture, framebuffer).is_ok() {
            return TestResult::Fail("degenerate framebuffer geometry accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31",
    framebuffer_range_classifies_the_boot_framebuffer
);

fn stage_list_covers_the_programme_lanes_in_order() -> TestResult {
    if STAGES.len() != 11
        || STAGES[0] != Stage::MemoryTraining
        || STAGES[STAGES.len() - 1] != Stage::Thermal
    {
        return TestResult::Fail("skeleton stage list does not cover the lanes");
    }
    for (i, stage) in STAGES.iter().enumerate() {
        if STAGES[..i].contains(stage) {
            return TestResult::Fail("duplicate stage in the skeleton list");
        }
    }
    // The skeleton report names the first stage as the next work and
    // completes none of them.
    let report = Report::skeleton(Rdna3Chip::Navi31);
    if report.stages_completed != 0 || report.next_stage != Some(Stage::MemoryTraining) {
        return TestResult::Fail("skeleton report does not start at MemoryTraining");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31",
    stage_list_covers_the_programme_lanes_in_order
);

fn prepare_returns_none_without_a_navi31_card() -> TestResult {
    if amdgpu::is_navi31() {
        return TestResult::Skip("a Navi31 card is bound; the boot handoff owns it");
    }
    // SAFETY: no Navi31 is bound, so prepare takes the Ok(None) path
    // before any clock preflight or ownership claim.
    let prepared = unsafe { prepare(None) };
    if prepared != Ok(None) {
        return TestResult::Fail("prepare claimed a card that is not RDNA3");
    }
    if status() != Status::Absent {
        return TestResult::Fail("skeleton status is not Absent before prepare");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31",
    prepare_returns_none_without_a_navi31_card
);

fn run_without_prepare_fails_closed() -> TestResult {
    if status() != Status::Absent {
        return TestResult::Skip("a Navi31 owner is already retained in this run");
    }
    // SAFETY: no owner was prepared, so run takes the NotPrepared path
    // before touching any hardware.
    let outcome = narf_scheduler::block_on_spin(async { unsafe { run().await } });
    if outcome != Err(Error::NotPrepared) {
        return TestResult::Fail("unprepared skeleton run did not fail closed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/navi31", run_without_prepare_fails_closed);
