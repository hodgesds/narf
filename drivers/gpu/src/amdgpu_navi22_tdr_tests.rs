use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn p(engine: Engine, emitted: u32, signaled: u32) -> Progress {
    Progress {
        engine,
        emitted,
        signaled,
    }
}

fn navi22_tdr_times_out_only_stalled_pending_work() -> TestResult {
    let mut w = Watchdog::new(TIMEOUT_MS);
    // Idle queues never time out, however long.
    if w.observe(p(Engine::Gfx, 7, 7), 0) != Verdict::Idle
        || w.observe(p(Engine::Gfx, 7, 7), 100_000) != Verdict::Idle
    {
        return TestResult::Fail("idle ring flagged");
    }
    // New work after a long idle starts a fresh timer (no stale `since`).
    if w.observe(p(Engine::Gfx, 9, 7), 100_250) != Verdict::Busy
        || w.observe(p(Engine::Gfx, 9, 7), 102_249) != Verdict::Busy
    {
        return TestResult::Fail("timer did not start at submission");
    }
    // Fence progress re-arms the timer (drm_sched re-arm on completion).
    if w.observe(p(Engine::Gfx, 9, 8), 102_000) != Verdict::Busy
        || w.observe(p(Engine::Gfx, 9, 8), 103_999) != Verdict::Busy
    {
        return TestResult::Fail("progress did not re-arm");
    }
    let hang = Hang {
        engine: Engine::Gfx,
        emitted: 9,
        signaled: 8,
        stalled_ms: 2000,
    };
    if w.observe(p(Engine::Gfx, 9, 8), 104_000) != Verdict::Hung(hang)
        || w.observe(p(Engine::Gfx, 9, 8), 110_000) != Verdict::StillHung
    {
        return TestResult::Fail("stall reported wrongly or repeatedly");
    }
    // Per-engine timers: a stalled GFX ring does not affect SDMA1.
    if w.observe(p(Engine::Sdma1, 3, 2), 110_000) != Verdict::Busy {
        return TestResult::Fail("engines share a timer");
    }
    // Recovery of the stall (late completion) clears it; a new stall is new.
    if w.observe(p(Engine::Gfx, 9, 9), 111_000) != Verdict::Idle
        || w.observe(p(Engine::Gfx, 10, 9), 111_250) != Verdict::Busy
        || !matches!(w.observe(p(Engine::Gfx, 10, 9), 113_250), Verdict::Hung(_))
    {
        return TestResult::Fail("second stall not detected");
    }
    // Sequence wrap: emitted 1 after u32::MAX signalled is pending work.
    let mut w = Watchdog::new(TIMEOUT_MS);
    if w.observe(p(Engine::Sdma0, 1, u32::MAX), 0) != Verdict::Busy
        || w.observe(p(Engine::Sdma0, 1, 1), 1) != Verdict::Idle
    {
        return TestResult::Fail("wrap-unsafe pending check");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-recovery",
    navi22_tdr_times_out_only_stalled_pending_work
);

fn navi22_tdr_records_hangs_without_enabling_recovery() -> TestResult {
    let before = status();
    if before.automatic_recovery {
        return TestResult::Fail("automatic recovery is on by default");
    }
    let mut w = Watchdog::new(TIMEOUT_MS);
    let stalled = [p(Engine::Compute, 4, 3), p(Engine::Kiq, 2, 2)];
    if !record(&mut w, &stalled, 0).is_empty() || !record(&mut w, &stalled, 1999).is_empty() {
        return TestResult::Fail("hang before the timeout");
    }
    let hangs = record(&mut w, &stalled, 2000);
    if hangs.len() != 1 || hangs[0].engine != Engine::Compute {
        return TestResult::Fail("compute stall not recorded");
    }
    let after = status();
    if after.hangs != before.hangs + 1
        || after.samples != before.samples + 3
        || after.last != Some(hangs[0])
        || after.automatic_recovery
    {
        return TestResult::Fail("status");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-recovery",
    navi22_tdr_records_hangs_without_enabling_recovery
);
