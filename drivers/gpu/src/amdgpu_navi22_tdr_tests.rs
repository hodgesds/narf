use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn p(engine: Engine, emitted: u32, signaled: u32) -> Progress {
    Progress {
        engine,
        media: None,
        emitted,
        signaled,
    }
}
fn m(ring: MediaRing, emitted: u32, signaled: u32) -> Progress {
    let engine = if ring == MediaRing::Jpeg {
        Engine::Jpeg
    } else {
        Engine::Vcn0
    };
    Progress {
        media: Some(ring),
        ..p(engine, emitted, signaled)
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
        media: None,
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

/// Detection alone never enables recovery: only the fb handoff of a booted
/// RX 6000 turns it on (no such card exists under QEMU).
fn navi22_tdr_records_hangs_without_enabling_recovery() -> TestResult {
    let before = status();
    if before.automatic_recovery {
        return TestResult::Fail("automatic recovery enabled without an RX 6000 boot");
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

/// Automatic recovery is budgeted per boot: each one quarantines VRAM.
fn navi22_tdr_automatic_recovery_budget_is_bounded() -> TestResult {
    __reset_automatic_recoveries();
    let claimed = (0..MAX_AUTOMATIC_RECOVERIES).all(|_| claim_automatic_recovery());
    let refused = !claim_automatic_recovery() && !claim_automatic_recovery();
    __reset_automatic_recoveries();
    if claimed && refused {
        TestResult::Pass
    } else {
        TestResult::Fail("automatic recovery budget")
    }
}
kernel_test_in!(
    "drivers/gpu/navi22-recovery",
    navi22_tdr_automatic_recovery_budget_is_bounded
);

struct Count(core::sync::atomic::AtomicUsize);
impl alloc::task::Wake for Count {
    fn wake(self: alloc::sync::Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// drm_sched arms the job timeout when a job starts on the hardware
/// (`drm_sched_start_timeout`) and cancels it once the ring has nothing
/// pending; nothing runs while no job is in flight. With every queue idle
/// the detector arms nothing and an emitted job wakes it at once; a job in
/// flight is sampled at its timeout, a stuck one is reported, and a reported
/// hang arms nothing more.
fn navi22_tdr_arms_nothing_without_a_job_and_times_out_a_stuck_one() -> TestResult {
    use core::{future::Future, task::Context};
    let mut w = Watchdog::new(TIMEOUT_MS);
    for engine in [
        Engine::Gfx,
        Engine::Kiq,
        Engine::Compute,
        Engine::Sdma0,
        Engine::Sdma1,
    ] {
        if w.observe(p(engine, 5, 5), 0) != Verdict::Idle {
            return TestResult::Fail("idle queue not idle");
        }
    }
    if next_sample(&w, 0).is_some() {
        return TestResult::Fail("the hang monitor wakes with no job in flight (every PERIOD_MS)");
    }
    let count = alloc::sync::Arc::new(Count(core::sync::atomic::AtomicUsize::new(0)));
    let waker = core::task::Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    let mut wait = core::pin::pin!(job_emitted_wait());
    let _ = wait.as_mut().poll(&mut cx);
    job_emitted();
    if count.0.load(Ordering::SeqCst) == 0 || wait.as_mut().poll(&mut cx).is_pending() {
        return TestResult::Fail("an emitted job did not wake the parked hang monitor");
    }
    if w.observe(p(Engine::Gfx, 6, 5), 0) != Verdict::Busy || next_sample(&w, 0) != Some(TIMEOUT_MS)
    {
        return TestResult::Fail("a job in flight is not timed from its start");
    }
    match w.observe(p(Engine::Gfx, 6, 5), TIMEOUT_MS) {
        Verdict::Hung(hang) if hang.engine == Engine::Gfx => {}
        _ => return TestResult::Fail("a stuck job did not time out"),
    }
    if next_sample(&w, TIMEOUT_MS).is_some() {
        return TestResult::Fail("a reported hang keeps the monitor sampling");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-tdr/timer",
    navi22_tdr_arms_nothing_without_a_job_and_times_out_a_stuck_one
);

/// Linux gives every VCN and JPEG ring a drm_sched with `adev->video_timeout`
/// (2 s, `amdgpu_device_get_job_timeout_settings`), so a media job that
/// never completes times out on its own ring. VCN0's decode and encode
/// rings share one fence engine but not one timer: an idle decode ring
/// does not restart a stuck encode job's timeout.
fn navi22_tdr_times_out_each_media_ring_like_linux_video_rings() -> TestResult {
    let mut w = Watchdog::new(TIMEOUT_MS);
    let mut hung = None;
    for now in [0, 1000, TIMEOUT_MS] {
        if w.observe(m(MediaRing::Dec, 5, 5), now) != Verdict::Idle {
            return TestResult::Fail("idle decode ring not idle");
        }
        match w.observe(m(MediaRing::Enc(0), 3, 2), now) {
            Verdict::Busy => {}
            Verdict::Hung(hang) => hung = Some(hang),
            _ => return TestResult::Fail("a pending encode ring reported idle"),
        }
    }
    let want = Hang {
        engine: Engine::Vcn0,
        media: Some(MediaRing::Enc(0)),
        emitted: 3,
        signaled: 2,
        stalled_ms: TIMEOUT_MS,
    };
    if hung != Some(want) {
        return TestResult::Fail("a stuck encode job never timed out beside an idle decode ring");
    }
    // The JPEG ring, the other VCN0 encode ring and a kernel queue each
    // keep their own timer.
    let stalled = [
        m(MediaRing::Jpeg, 9, 8),
        m(MediaRing::Enc(1), 4, 3),
        p(Engine::Sdma0, 2, 1),
    ];
    let mut w = Watchdog::new(TIMEOUT_MS);
    if !record(&mut w, &stalled, 0).is_empty() || next_sample(&w, 0) != Some(TIMEOUT_MS) {
        return TestResult::Fail("pending media jobs are not timed from their start");
    }
    let hangs = record(&mut w, &stalled, TIMEOUT_MS);
    let rings: alloc::vec::Vec<_> = hangs.iter().map(|h| (h.engine, h.media)).collect();
    if rings
        != [
            (Engine::Jpeg, Some(MediaRing::Jpeg)),
            (Engine::Vcn0, Some(MediaRing::Enc(1))),
            (Engine::Sdma0, None),
        ]
    {
        return TestResult::Fail("media rings share a timer with each other or a kernel queue");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-tdr/media",
    navi22_tdr_times_out_each_media_ring_like_linux_video_rings
);

/// `amdgpu_job_timedout` on a media ring, bare metal: with
/// `amdgpu_gpu_recovery` off it only sets `-ETIME` and suspends the timeout
/// (no reset of any kind); otherwise a VCN 3.0 ring has a per-queue reset
/// (`vcn.supported_reset` has `AMDGPU_RESET_TYPE_PER_QUEUE`,
/// `amdgpu_vcn_ring_reset`) and is reset first. NARF has no JPEG ring
/// reset (Linux's needs ring backup and re-emission), so a JPEG timeout
/// goes to the `-ETIME` / `amdgpu_device_gpu_recover` branch.
fn navi22_tdr_media_timeout_follows_amdgpu_job_timedout() -> TestResult {
    let vcn = [MediaRing::Dec, MediaRing::Enc(0), MediaRing::Enc(1)];
    for ring in vcn.into_iter().chain([MediaRing::Jpeg]) {
        if media_action(false, ring) != MediaAction::Suspend {
            return TestResult::Fail("a media timeout with gpu_recovery=0 does more than suspend");
        }
    }
    if vcn
        .iter()
        .any(|&ring| media_action(true, ring) != MediaAction::ResetEngine)
    {
        return TestResult::Fail("a VCN ring timeout does not reset the VCN instance first");
    }
    if media_action(true, MediaRing::Jpeg) != MediaAction::Recover {
        return TestResult::Fail("a JPEG timeout without a ring reset does not recover the GPU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-tdr/media",
    navi22_tdr_media_timeout_follows_amdgpu_job_timedout
);
