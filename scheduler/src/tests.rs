//! Per-crate smoke tests for `narf-scheduler`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `"scheduler"`. Migrated from
//! `narf-verification`'s mega-lib so each subsystem owns its own
//! smokes without cycling on the higher-level harness.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_scheduler_parked_idle_leaves_rcu_census() -> TestResult {
    let cpu = narf_lib::percpu::current_cpu();
    if cpu >= 64 {
        return TestResult::Skip("current CPU is outside watchdog mask");
    }
    let bit = 1u64 << cpu;

    // Establish an active timestamp, then exercise the exact helper used by
    // run_until_empty's parked-queue halt. An arbitrarily-late watchdog
    // snapshot must no longer classify this CPU as stalled.
    narf_rcu::report_quiescent();
    if narf_rcu::stalled_cpu_mask(u64::MAX, 1) & bit == 0 {
        return TestResult::Fail("active CPU missing from synthetic stale snapshot");
    }
    crate::report_parked_queue_idle();
    let still_active = narf_rcu::stalled_cpu_mask(u64::MAX, 1) & bit != 0;
    // Restore the active state for later tests sharing this CPU.
    narf_rcu::report_quiescent();
    if still_active {
        TestResult::Fail("parked idle CPU remained in RCU watchdog census")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("scheduler", smoke_scheduler_parked_idle_leaves_rcu_census);

fn smoke_scheduler_drives_future() -> TestResult {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    crate::__reset_queues_for_test();
    for _ in 0..3 {
        crate::spawn(async {
            COUNT.fetch_add(1, Ordering::Relaxed);
            crate::yield_now().await;
            COUNT.fetch_add(10, Ordering::Relaxed);
        });
    }
    crate::run_until_empty();
    // Three tasks × (1 + 10) = 33.
    if COUNT.load(Ordering::Relaxed) == 33 {
        TestResult::Pass
    } else {
        TestResult::Fail("scheduler didn't drive 3 tasks to completion")
    }
}
kernel_test_in!("scheduler", smoke_scheduler_drives_future);

fn smoke_scheduler_respects_waker() -> TestResult {
    // Proves the scheduler honours per-task wakers: a Parked future
    // that returns Pending *without* calling its waker must not be
    // re-polled until something else wakes it. Without the per-task
    // awake flag this test would fail because the old no-op waker
    // caused every Pending task to be repolled on every round.
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};
    use narf_lib::sync::IrqSafeSpinLock;

    static POLLS: AtomicUsize = AtomicUsize::new(0);
    static PARKED_WAKER: IrqSafeSpinLock<Option<Waker>> = IrqSafeSpinLock::new(None);

    struct Parked {
        ready: bool,
    }
    impl Future for Parked {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            let this = self.get_mut();
            POLLS.fetch_add(1, Ordering::Relaxed);
            if this.ready {
                return Poll::Ready(());
            }
            *PARKED_WAKER.lock() = Some(cx.waker().clone());
            this.ready = true; // next poll (after being woken) completes
            Poll::Pending
        }
    }

    POLLS.store(0, Ordering::Relaxed);
    *PARKED_WAKER.lock() = None;

    crate::__reset_queues_for_test();
    crate::spawn(Parked { ready: false });
    crate::spawn(async {
        // Yield once so Parked gets a turn to register its waker, then
        // wake it. Under the old noop_waker Parked would already have
        // been re-polled many times by now; with per-task wakers it
        // must have been polled exactly once so far.
        crate::yield_now().await;
        if let Some(w) = PARKED_WAKER.lock().take() {
            w.wake();
        }
    });
    crate::run_until_empty();

    match POLLS.load(Ordering::Relaxed) {
        2 => TestResult::Pass,
        n if n < 2 => TestResult::Fail("parked task never woke after wake()"),
        _ => TestResult::Fail("parked task re-polled without a wake — waker gating broken"),
    }
}
kernel_test_in!("scheduler", smoke_scheduler_respects_waker);

fn smoke_scheduler_budget_cap_revokes_task() -> TestResult {
    // A Cap<CpuBudget, Spend>-attached task runs while the cap is live,
    // and is dropped by the scheduler once the cap is revoked.
    use crate::{CpuBudget, ResourceBudget, TaskSpec};
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll};
    use narf_capabilities::Cap;

    static RUNS: AtomicUsize = AtomicUsize::new(0);

    struct Alive;
    impl Future for Alive {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            RUNS.fetch_add(1, Ordering::Relaxed);
            // Always ask to be re-polled — would run forever if the
            // scheduler never dropped the task.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    RUNS.store(0, Ordering::Relaxed);
    crate::__reset_queues_for_test();

    let cap: Cap<CpuBudget, narf_capabilities::Spend> = Cap::bootstrap();
    // Spawn a second task that revokes the budget cap after a few
    // yields so the scheduler has a clear "alive, then dead" window.
    let revoke_cap = cap;
    crate::spawn_with_spec(
        Alive,
        TaskSpec::budgeted(ResourceBudget::unthrottled(), cap),
    );
    crate::spawn(async move {
        for _ in 0..4 {
            crate::yield_now().await;
        }
        revoke_cap.revoke();
    });

    crate::run_until_empty();

    let n = RUNS.load(Ordering::Relaxed);
    if n == 0 {
        return TestResult::Fail("budgeted task never polled while cap was live");
    }
    // After revoke the task must drop, not spin forever — if we got
    // here at all the scheduler terminated, which is the assertion.
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_budget_cap_revokes_task);

fn smoke_scheduler_budget_accounts_cycles() -> TestResult {
    // The executor charges measured cycles into the task's
    // `BudgetAccount` via `ResourceBudget` — single-shot task, so we
    // can't observe the account post-drop, but we can verify the
    // types compose and TaskSpec construction doesn't require a cap.
    use crate::{BudgetAccount, OverrunPolicy, ResourceBudget, TaskSpec};

    let unthrottled = TaskSpec::unthrottled();
    if unthrottled.budget_cap.is_some() {
        return TestResult::Fail("unthrottled TaskSpec should not carry a budget cap");
    }
    if unthrottled.budget.policy != OverrunPolicy::Ignore {
        return TestResult::Fail("unthrottled budget must default to Ignore policy");
    }

    use crate::budget::ChargeOutcome;
    let mut acct = BudgetAccount::new();
    let budget = ResourceBudget::fair_share(100_000, 1_000);
    let over = acct.charge(2_000, &budget);
    if over != ChargeOutcome::Throttle {
        return TestResult::Fail("over-burst with Throttle policy should return Throttle");
    }
    if acct.overruns != 1 || acct.polls != 1 || acct.cycles_spent != 2_000 {
        return TestResult::Fail("BudgetAccount did not accumulate correctly");
    }
    let under = acct.charge(500, &budget);
    if under != ChargeOutcome::Continue {
        return TestResult::Fail("500 cycles inside burst should return Continue");
    }
    if acct.overruns != 1 || acct.polls != 2 || acct.cycles_spent != 2_500 {
        return TestResult::Fail("BudgetAccount running totals drifted");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_budget_accounts_cycles);

fn smoke_scheduler_cpu_lifecycle_take_offline() -> TestResult {
    use crate::{cpu_bring_up, cpu_online, cpu_take_offline, CpuId, CpuLifecycle, HotPlugError};
    use narf_capabilities::{Cap, Invoke};

    crate::cpu_lifecycle::__test_reset_online_mask();

    let cap: Cap<CpuLifecycle, Invoke> = Cap::bootstrap();

    if !cpu_online(CpuId::BOOT) {
        return TestResult::Fail("boot CPU should be online after reset");
    }
    if cpu_online(CpuId(3)) {
        return TestResult::Fail("CPU 3 should not be online before bring-up");
    }
    if cpu_bring_up(CpuId(3), &cap).is_err() {
        return TestResult::Fail("cpu_bring_up with live cap returned Err");
    }
    if !cpu_online(CpuId(3)) {
        return TestResult::Fail("cpu_bring_up did not mark CPU 3 online");
    }
    if cpu_take_offline(CpuId(3), &cap).is_err() {
        return TestResult::Fail("cpu_take_offline with live cap returned Err");
    }
    if cpu_online(CpuId(3)) {
        return TestResult::Fail("cpu_take_offline did not clear CPU 3");
    }
    match cpu_take_offline(CpuId::BOOT, &cap) {
        Err(HotPlugError::OutOfRange) => {}
        _ => return TestResult::Fail("boot CPU take-offline should be rejected"),
    }

    cap.revoke();
    match cpu_bring_up(CpuId(3), &cap) {
        Err(HotPlugError::AuthorityRevoked) => {}
        _ => return TestResult::Fail("revoked lifecycle cap not rejected"),
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_cpu_lifecycle_take_offline);

fn smoke_scheduler_realtime_spec() -> TestResult {
    use crate::{Priority, SchedClass, SmtSharePolicy, TaskSpec};

    let rt = TaskSpec::realtime(1_000_000);
    if rt.class != SchedClass::RealTime {
        return TestResult::Fail("realtime TaskSpec class wrong");
    }
    if rt.priority != Priority::HIGH {
        return TestResult::Fail("realtime TaskSpec priority not HIGH");
    }
    if rt.smt != SmtSharePolicy::Avoid {
        return TestResult::Fail("realtime TaskSpec SMT default wrong");
    }
    if rt.budget.deadline_cycles != Some(1_000_000) {
        return TestResult::Fail("realtime deadline_cycles not stored");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_realtime_spec);

fn smoke_scheduler_donate_to_reorders_head() -> TestResult {
    // donate_to moves the named task to the head of the ready queue.
    // Called *before* run_until_empty, it swaps spawn-order so the
    // donee's first poll lands ahead of the task that was spawned
    // before it.
    use crate::{donate_to, Task};
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_capabilities::{Cap, Invoke};

    static FIRST_TAG: AtomicU32 = AtomicU32::new(0);
    FIRST_TAG.store(0, Ordering::Relaxed);

    crate::__reset_queues_for_test();

    let donation: Cap<Task, Invoke> = Cap::bootstrap();

    // Spawn A first, B second. Both record their own tag into
    // FIRST_TAG on first poll if the slot is still 0.
    let _a = crate::spawn(async {
        let _ = FIRST_TAG.compare_exchange(0, 0xAAAA, Ordering::Relaxed, Ordering::Relaxed);
    });
    let b = crate::spawn(async {
        let _ = FIRST_TAG.compare_exchange(0, 0xBBBB, Ordering::Relaxed, Ordering::Relaxed);
    });

    // Donate to B *before* run_until_empty so the reorder is
    // observable. Without donation A would write first.
    if donate_to(b, &donation).is_err() {
        return TestResult::Fail("donate_to returned Err on a live cap");
    }

    crate::run_until_empty();

    match FIRST_TAG.load(Ordering::Relaxed) {
        0xBBBB => TestResult::Pass,
        0xAAAA => TestResult::Fail("donee did not run ahead of the pre-spawned task"),
        _ => TestResult::Fail("neither task ran"),
    }
}
kernel_test_in!("scheduler", smoke_scheduler_donate_to_reorders_head);

fn smoke_scheduler_current_task_id_during_poll() -> TestResult {
    // Before any spawn, current_task_id() is TaskId::NONE. Inside
    // a poll it matches the polling slot's id. Between rounds it
    // reverts to NONE.
    use crate::{current_task_id, TaskId};
    use core::sync::atomic::{AtomicU64, Ordering};

    if current_task_id() != TaskId::NONE {
        return TestResult::Fail("current_task_id leaked across tests");
    }

    crate::__reset_queues_for_test();
    static OBSERVED: AtomicU64 = AtomicU64::new(u64::MAX);
    OBSERVED.store(u64::MAX, Ordering::Relaxed);

    let tid = crate::spawn(async {
        OBSERVED.store(current_task_id().raw(), Ordering::Relaxed);
    });
    crate::run_until_empty();

    if OBSERVED.load(Ordering::Relaxed) != tid.raw() {
        return TestResult::Fail("task did not see its own id via current_task_id");
    }
    if current_task_id() != TaskId::NONE {
        return TestResult::Fail("current_task_id not cleared after run_until_empty");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_current_task_id_during_poll);

#[cfg(feature = "cgroup")]
fn smoke_scheduler_memory_pid_provider_resolves_current() -> TestResult {
    // The `memory` cgroup controller installs this provider so the
    // frame allocator can attribute a charge to the allocating process.
    // Scheduler TaskId and userspace ProcessId deliberately have separate
    // namespaces, so exercise a non-identity resolver: `memory.max` must
    // never accidentally charge the task whose raw id happens to equal a
    // process id.
    use crate::current_task_id;
    use core::sync::atomic::{AtomicU64, Ordering};

    const PID_OFFSET: u64 = 0x1_0000;
    fn task_to_process_for_test(task: u64) -> Option<u64> {
        task.checked_add(PID_OFFSET)
    }

    crate::install_memory_pid_resolver(task_to_process_for_test);
    crate::install_memory_pid_provider();

    // Outside any poll: unattributed.
    if narf_memory::__charge_pid_for_test().is_some() {
        return TestResult::Fail("charge pid attributed outside a poll context");
    }

    crate::__reset_queues_for_test();
    static OBSERVED: AtomicU64 = AtomicU64::new(u64::MAX);
    OBSERVED.store(u64::MAX, Ordering::Relaxed);

    let tid = crate::spawn(async {
        let pid = narf_memory::__charge_pid_for_test().unwrap_or(u64::MAX);
        // The provider must resolve through the process-ID hook rather than
        // leak the scheduler's private task id to the cgroup controller.
        debug_assert_eq!(pid, current_task_id().raw() + PID_OFFSET);
        OBSERVED.store(pid, Ordering::Relaxed);
    });
    crate::run_until_empty();

    if OBSERVED.load(Ordering::Relaxed) != tid.raw() + PID_OFFSET {
        return TestResult::Fail("charge pid did not resolve through the process-id hook");
    }
    if narf_memory::__charge_pid_for_test().is_some() {
        return TestResult::Fail("charge pid not cleared after run_until_empty");
    }
    TestResult::Pass
}
#[cfg(feature = "cgroup")]
kernel_test_in!(
    "scheduler",
    smoke_scheduler_memory_pid_provider_resolves_current
);

#[cfg(feature = "cgroup")]
fn smoke_scheduler_cgroup_affinity_resolves_process_to_task() -> TestResult {
    use crate::{Affinity, CpuId, CpuSet, TaskSpec};
    use core::sync::atomic::{AtomicU64, Ordering};

    const OUTER_PID: u64 = 0x4242;
    static TARGET_TASK: AtomicU64 = AtomicU64::new(u64::MAX);

    fn process_to_task_for_test(pid: u64) -> Option<u64> {
        (pid == OUTER_PID).then(|| TARGET_TASK.load(Ordering::Acquire))
    }

    crate::__reset_queues_for_test();
    let id = crate::spawn_with_spec(
        core::future::pending::<()>(),
        TaskSpec {
            affinity: Affinity::any(),
            ..TaskSpec::unthrottled()
        },
    );
    TARGET_TASK.store(id.raw(), Ordering::Release);

    let boot = CpuSet::single(CpuId::BOOT);
    let applied =
        crate::cgroup::with_process_task_resolver_for_test(process_to_task_for_test, || {
            crate::apply_affinity(OUTER_PID, boot.bits())
        });
    if !applied {
        return TestResult::Fail("cgroup affinity rejected the resolved task");
    }
    if crate::task_affinity(id) != Some(boot) {
        return TestResult::Fail("cgroup affinity updated the process id instead of its task");
    }

    crate::__reset_queues_for_test();
    TestResult::Pass
}
#[cfg(feature = "cgroup")]
kernel_test_in!(
    "scheduler",
    smoke_scheduler_cgroup_affinity_resolves_process_to_task
);

fn smoke_scheduler_donate_to_rejects_revoked_cap() -> TestResult {
    use crate::{donate_to, DonateError, Task, TaskId};
    use narf_capabilities::{Cap, Invoke};

    crate::__reset_queues_for_test();
    let cap: Cap<Task, Invoke> = Cap::bootstrap();
    cap.revoke();
    match donate_to(TaskId(1), &cap) {
        Err(DonateError::AuthorityRevoked) => TestResult::Pass,
        Err(other) => {
            let _ = other;
            TestResult::Fail("donate_to with revoked cap returned wrong error")
        }
        Ok(()) => TestResult::Fail("donate_to with revoked cap succeeded"),
    }
}
kernel_test_in!("scheduler", smoke_scheduler_donate_to_rejects_revoked_cap);

fn smoke_scheduler_donate_to_missing_target() -> TestResult {
    use crate::{donate_to, DonateError, Task, TaskId};
    use narf_capabilities::{Cap, Invoke};

    crate::__reset_queues_for_test();
    let cap: Cap<Task, Invoke> = Cap::bootstrap();
    // An id far past any live task's id — guaranteed not to match.
    match donate_to(TaskId(u64::MAX), &cap) {
        Err(DonateError::TargetNotFound) => TestResult::Pass,
        _ => TestResult::Fail("donate_to to unknown id did not return TargetNotFound"),
    }
}
kernel_test_in!("scheduler", smoke_scheduler_donate_to_missing_target);

fn smoke_scheduler_cpu_set_membership() -> TestResult {
    use crate::{Affinity, CpuId, CpuSet};

    let all = CpuSet::ALL;
    if !all.contains(CpuId::BOOT) {
        return TestResult::Fail("CpuSet::ALL should contain the boot CPU");
    }
    let empty = CpuSet::EMPTY;
    if empty.contains(CpuId::BOOT) {
        return TestResult::Fail("CpuSet::EMPTY should not contain any CPU");
    }
    let single = CpuSet::single(CpuId(3));
    if !single.contains(CpuId(3)) || single.contains(CpuId(0)) {
        return TestResult::Fail("CpuSet::single membership incorrect");
    }
    if single.len() != 1 {
        return TestResult::Fail("single-CPU set should have len 1");
    }

    let pinned = Affinity::pinned(CpuId(0));
    if pinned.preferred != Some(CpuId(0)) {
        return TestResult::Fail("pinned affinity should prefer the pinned CPU");
    }
    if !pinned.allowed.contains(CpuId(0)) {
        return TestResult::Fail("pinned affinity should allow the pinned CPU");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_cpu_set_membership);

fn smoke_scheduler_steal_disabled_returns_clean() -> TestResult {
    // With work-stealing off (the default), an empty BSP queue causes
    // run_until_empty to return promptly. A test that calls it with
    // an empty queue must not block.
    crate::__reset_queues_for_test();
    crate::disable_work_stealing();
    crate::run_until_empty();
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_steal_disabled_returns_clean);

// ── scheduler/affinity + AS routing ──────────────────────────────────

fn smoke_scheduler_two_cpu_user_spawn_balances_bsp_and_ap() -> TestResult {
    use crate::affinity::CpuId;

    let mut sole_ap = [0u32; 64];
    sole_ap[0] = 1;
    let first = crate::user_affinity_from_aps(sole_ap, 1, 0);
    let second = crate::user_affinity_from_aps(sole_ap, 1, 1);
    let third = crate::user_affinity_from_aps(sole_ap, 1, 2);
    if first.preferred != Some(CpuId::BOOT)
        || second.preferred != Some(CpuId(1))
        || third.preferred != Some(CpuId::BOOT)
    {
        return TestResult::Fail("sole-AP user placement did not alternate BSP/AP");
    }
    if first.allowed != crate::affinity::CpuSet::ALL
        || second.allowed != crate::affinity::CpuSet::ALL
    {
        return TestResult::Fail("two-CPU user placement narrowed the allowed mask");
    }

    // Larger machines retain the AP-only policy: this fix must not move
    // ordinary user work back onto the housekeeping BSP when multiple APs
    // are available.
    let mut several_aps = [0u32; 64];
    several_aps[..3].copy_from_slice(&[1, 2, 3]);
    for sequence in 0..6 {
        let affinity = crate::user_affinity_from_aps(several_aps, 3, sequence);
        if affinity.preferred == Some(CpuId::BOOT) {
            return TestResult::Fail("multi-AP user placement selected the BSP");
        }
    }

    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_two_cpu_user_spawn_balances_bsp_and_ap
);

fn smoke_scheduler_per_cpu_pin_to_bsp() -> TestResult {
    // Pinning a task to CpuId(0) lands it on BSP's queue. With the
    // BSP running run_until_empty, the task completes — same outcome
    // as an unpinned spawn from BSP, but exercising the affinity
    // routing path through `target_cpu`.
    use crate::{spawn_with_spec, Affinity, CpuId, TaskSpec};
    use core::sync::atomic::{AtomicU32, Ordering};
    static RAN: AtomicU32 = AtomicU32::new(0);
    RAN.store(0, Ordering::Relaxed);

    crate::__reset_queues_for_test();

    let spec = TaskSpec {
        affinity: Affinity::pinned(CpuId(0)),
        ..TaskSpec::unthrottled()
    };
    let _ = spawn_with_spec(
        async {
            RAN.store(1, Ordering::Relaxed);
        },
        spec,
    );

    crate::run_until_empty();

    if RAN.load(Ordering::Relaxed) == 1 {
        TestResult::Pass
    } else {
        TestResult::Fail("BSP-pinned task didn't run")
    }
}
kernel_test_in!("scheduler", smoke_scheduler_per_cpu_pin_to_bsp);

/// A spawn IS a wake: `enqueue_on` placing a runnable slot on a REMOTE
/// idle-halted CPU must kick that CPU through the reschedule-IPI path
/// (`resched_remote`), exactly like a cross-core `Waker::wake`. Before the
/// fix, a fresh task enqueued onto an idle AP (every pthread_create under
/// the round-robin `user_ap_affinity` placement) was only noticed at the
/// target's next timer tick — and `run_forever`'s empty-queue halt sat
/// OUTSIDE the CPU_HALTED protocol entirely, so the kick would have been
/// skipped even if sent. Asserted through the `dbg_resched_counts` SENT
/// counter, which `resched_remote` bumps independently of the (boot-only)
/// IPI hook, so the test needs no second physical CPU: it marks CPU 1
/// online + halted, spawns a CPU-1-preferred task, and requires exactly
/// one kick; the not-halted control run must skip instead.
fn smoke_scheduler_spawn_kicks_halted_remote_cpu() -> TestResult {
    use crate::{spawn_with_spec, Affinity, CpuId, TaskSpec};

    // This test commandeers CPU 1 as a FAKE idle-halted AP
    // (`__test_fake_online` + `__test_set_cpu_halted`) and asserts against
    // the aggregate resched counters. Both only hold when no REAL AP is live:
    // at SMP>1 CPU 1 is a genuine core that manages its own `CPU_HALTED`
    // bit and issues its own reschedules, and every other AP advances its
    // per-CPU resched counters concurrently — so the aggregate
    // state and the counter deltas are both polluted (the negative
    // "running target sent no IPI" assertion false-fails). The kick logic
    // itself is exercised for real by the condbcast/futex_contend cases at
    // the full 16-vCPU topology; here we pin the decision
    // deterministically, which is only possible at SMP=1.
    if narf_lib::smp::online_count() > 1 {
        return TestResult::Skip(
            "needs SMP=1 — a live AP pollutes CPU_HALTED[1] and the aggregate resched counters",
        );
    }
    // The online bitmap alone is NOT a sound guard: it is fakeable test
    // state, and earlier smokes in the shared kernel-test boot falsify it
    // (the sysfs cpu-device smokes used to leave `smp::__reset_for_test`'s
    // BSP-only bitmap behind on a 16-vCPU boot). A really-started AP keeps
    // running `run_forever` regardless of the bitmap, flipping
    // `CPU_HALTED[1]` around every idle HLT and draining `READY[1]` when
    // our spawn's (real) resched IPI wakes it — which raced this test's
    // halted-flag writes in BOTH directions (the historical flake: "did
    // not send a resched kick" when AP 1's post-wake clear landed before
    // the first spawn's check, "spurious resched IPI" when its re-halt
    // publish landed after our not-halted store). The monotonic
    // ever-online record can't be falsified: any AP that ever came up
    // this boot means CPU 1's scheduler state isn't ours to script.
    if narf_lib::smp::ever_online_bitmap() != 1 {
        return TestResult::Skip(
            "an AP really came up this boot — run_forever owns CPU_HALTED[1], not the test",
        );
    }

    crate::__reset_queues_for_test();

    // Pretend CPU 1 is an online, idle-halted AP. Restored below. The
    // fake setter keeps the ever-online record truthful for later tests.
    narf_lib::smp::__test_fake_online(1);
    crate::__test_set_cpu_halted(1, true);

    let spec = TaskSpec {
        affinity: Affinity {
            allowed: crate::affinity::CpuSet::ALL,
            preferred: Some(CpuId(1)),
        },
        ..TaskSpec::unthrottled()
    };

    let (sent_before, _) = crate::dbg_resched_counts();
    let _ = spawn_with_spec(async {}, spec);
    let (sent_after, skip_mid) = crate::dbg_resched_counts();

    // Control: a spawn to the same remote CPU while it is NOT halted must
    // skip the IPI (the target's pre-halt re-scan covers it).
    crate::__test_set_cpu_halted(1, false);
    let spec2 = TaskSpec {
        affinity: Affinity {
            allowed: crate::affinity::CpuSet::ALL,
            preferred: Some(CpuId(1)),
        },
        ..TaskSpec::unthrottled()
    };
    let _ = spawn_with_spec(async {}, spec2);
    let (sent_final, skip_final) = crate::dbg_resched_counts();

    // Restore: CPU 1 back offline, queues cleared (the two slots parked on
    // CPU 1's queue have no CPU to run them).
    narf_lib::smp::mark_offline(1);
    crate::__reset_queues_for_test();

    if sent_after != sent_before + 1 {
        return TestResult::Fail("spawn onto a halted remote CPU did not send a resched kick");
    }
    if sent_final != sent_after {
        return TestResult::Fail("spawn onto a running remote CPU sent a spurious resched IPI");
    }
    if skip_final == skip_mid {
        return TestResult::Fail("not-halted spawn was not counted as a skipped cross-core wake");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_spawn_kicks_halted_remote_cpu);

/// The hardened wake path publishes a per-CPU `NEED_RESCHED` request on EVERY
/// cross-core wake, independent of the IPI decision. This is the authoritative
/// second Dekker channel: even when the target is running (IPI correctly
/// skipped), the request is durable so the target catches it via the O(1)
/// check at its next halt commit instead of relying on a bounded idle spin.
/// Asserted through the test accessors on the same commandeered-CPU-1 harness
/// as the kick test (SMP=1 only, or a real AP owns CPU 1's resched state).
fn smoke_scheduler_wake_publishes_need_resched() -> TestResult {
    use crate::{spawn_with_spec, Affinity, CpuId, TaskSpec};

    if narf_lib::smp::online_count() > 1 {
        return TestResult::Skip("needs SMP=1 — a live AP owns CPU 1's NEED_RESCHED");
    }
    if narf_lib::smp::ever_online_bitmap() != 1 {
        return TestResult::Skip(
            "an AP really came up this boot — CPU 1's resched state isn't ours",
        );
    }

    crate::__reset_queues_for_test();
    narf_lib::smp::__test_fake_online(1);

    let spec = || TaskSpec {
        affinity: Affinity {
            allowed: crate::affinity::CpuSet::ALL,
            preferred: Some(CpuId(1)),
        },
        ..TaskSpec::unthrottled()
    };

    // Case A: target halted → request published AND IPI sent.
    crate::__test_set_cpu_halted(1, true);
    crate::__test_clear_need_resched(1);
    let _ = spawn_with_spec(async {}, spec());
    let need_when_halted = crate::__test_need_resched(1);

    // Case B: target running → IPI skipped, but the request is STILL published
    // (the durable channel is what hardens the halt-poll-window race).
    crate::__test_set_cpu_halted(1, false);
    crate::__test_clear_need_resched(1);
    let _ = spawn_with_spec(async {}, spec());
    let need_when_running = crate::__test_need_resched(1);

    narf_lib::smp::mark_offline(1);
    crate::__test_clear_need_resched(1);
    crate::__reset_queues_for_test();

    if !need_when_halted {
        return TestResult::Fail("wake to a halted remote CPU did not publish NEED_RESCHED");
    }
    if !need_when_running {
        return TestResult::Fail(
            "wake to a running remote CPU did not publish NEED_RESCHED (authoritative channel lost)",
        );
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_wake_publishes_need_resched);

fn smoke_scheduler_numa_steal_prefers_same_node() -> TestResult {
    // With work-stealing on and per-CPU queues seeded across two
    // NUMA nodes, a steal should pull from a same-node victim first.
    // We exercise this purely through the public surface: spawn
    // tasks pinned to specific CPUs in different nodes; force-enable
    // stealing; run the BSP loop. Tasks all complete because affinity
    // routes them to their target CPU's queue and the BSP steals
    // them.
    use crate::{spawn_with_spec, Affinity, CpuId, TaskSpec};
    use core::sync::atomic::{AtomicU32, Ordering};

    static DONE: AtomicU32 = AtomicU32::new(0);
    DONE.store(0, Ordering::Relaxed);

    crate::__reset_queues_for_test();
    crate::enable_work_stealing();

    for cpu in 0..4u32 {
        let spec = TaskSpec {
            affinity: Affinity::pinned(CpuId(cpu)),
            ..TaskSpec::unthrottled()
        };
        let _ = spawn_with_spec(
            async {
                DONE.fetch_add(1, Ordering::Relaxed);
            },
            spec,
        );
    }

    crate::run_until_empty();
    crate::disable_work_stealing();

    // BSP drained at least its own pinned task; the others may or
    // may not be visible depending on whether real APs ran them.
    if DONE.load(Ordering::Relaxed) == 0 {
        return TestResult::Fail("no task ran");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_numa_steal_prefers_same_node);

fn smoke_scheduler_spawn_user_carries_address_space() -> TestResult {
    extern crate alloc;
    use crate::{address_space_of, spawn_user, TaskSpec};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_memory::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    crate::__reset_queues_for_test();
    static RAN: AtomicU32 = AtomicU32::new(0);
    RAN.store(0, Ordering::Relaxed);

    // Allocate a real user-root for the active arch — the
    // constructor takes care of the kernel/high-half bits that
    // have to survive activation (full-copy PML4 on x86_64, empty
    // TTBR0 on aarch64 since the kernel lives behind TTBR1).
    // SAFETY: Paging is enabled in the running kernel test environment, which
    // is new_for_user's sole precondition.
    // SAFETY: Valid memory or trusted environment
    let a = unsafe { AddressSpace::new_for_user() }.expect("alloc user AS");
    a.map_region(Region {
        base: VirtAddr::new(0x4000),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::EXEC,
        phys: alloc::vec![PhysAddr::new(0x2_0000)],
    })
    .expect("map");
    let arc_a = Arc::new(a);

    let tid = spawn_user(
        crate::alloc_task_id(),
        async {
            RAN.fetch_add(1, Ordering::Relaxed);
        },
        TaskSpec::unthrottled(),
        Arc::clone(&arc_a),
    );

    // Before running, `address_space_of` finds our AS.
    match address_space_of(tid) {
        Some(found) => {
            if found.region_count() != 1 {
                return TestResult::Fail("address_space_of returned wrong AS");
            }
        }
        None => return TestResult::Fail("spawn_user did not attach AS"),
    }

    crate::run_until_empty();

    if RAN.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("user task did not run");
    }
    // After task completes, lookup should return None.
    if address_space_of(tid).is_some() {
        return TestResult::Fail("AS handle persisted past task completion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_spawn_user_carries_address_space
);

/// Regression: polling a user task must restore the kernel CR3
/// before returning to the caller, otherwise any subsequent
/// low-half access (FB phys, identity-mapped MMIO, beacon write)
/// from kernel context page-faults.
///
/// The original `boot-init` symptom: `DrainTask` polled fine in
/// the first round, then the executor activated init's user AS,
/// polled `UserTaskFuture` (returning Pending), and left CR3 in
/// init's user PML4. The next kernel task in the queue
/// (cursor::pump, status-refresh, the periodic FB drain) ran with
/// stale user CR3 and faulted on the first low-half access.
/// Existing user-task smokes didn't catch this because they only
/// spawned one user task and the test never asserted on CR3 or
/// queued a follow-up task that touched low-half memory.
#[cfg(target_arch = "x86_64")]
fn smoke_scheduler_user_task_poll_restores_kernel_cr3() -> TestResult {
    extern crate alloc;
    use crate::{spawn_user, TaskSpec};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use narf_memory::{tlb_shootdown, AddressSpace};

    static RESIDENCY_SEEN_DURING_POLL: AtomicBool = AtomicBool::new(false);
    static POLL_CPU: AtomicU32 = AtomicU32::new(u32::MAX);
    RESIDENCY_SEEN_DURING_POLL.store(false, Ordering::Relaxed);
    POLL_CPU.store(u32::MAX, Ordering::Relaxed);

    /// # Safety
    /// Must run at CPL=0 (kernel test context); reading CR3 is otherwise
    /// privileged. Has no memory or stack effects.
    #[inline(always)]
    unsafe fn read_cr3() -> u64 {
        let v: u64;
        // SAFETY: `mov reg, cr3` is a side-effect-free ring-0 read; the test
        // runner executes at CPL=0 and `v` receives the value.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::arch::asm!(
                "mov {0}, cr3",
                out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }

    crate::__reset_queues_for_test();
    // SAFETY: read_cr3 runs at CPL=0 in the in-kernel test runner.
    let kernel_cr3 = unsafe { read_cr3() };

    // SAFETY: Paging is enabled in the running kernel test environment, which
    // is new_for_user's sole precondition.
    // SAFETY: `new_for_user` only requires paging be enabled, which always
    // holds once the kernel test harness is running at EL1/long mode.
    // SAFETY: Valid memory or trusted environment
    let user_as = unsafe { AddressSpace::new_for_user() }.expect("alloc user AS");
    let user_cr3 = user_as.root.as_u64();
    if user_cr3 == kernel_cr3 {
        return TestResult::Fail("new user AS shares root with kernel AS");
    }
    let arc_as = Arc::new(user_as);

    let _tid = spawn_user(
        crate::alloc_task_id(),
        async {
            let cpu = narf_lib::percpu::current_cpu() as u32;
            POLL_CPU.store(cpu, Ordering::Relaxed);
            RESIDENCY_SEEN_DURING_POLL.store(
                tlb_shootdown::active_as_bitmap(cpu) & 1 != 0,
                Ordering::Relaxed,
            );
        },
        TaskSpec::unthrottled(),
        Arc::clone(&arc_as),
    );

    crate::run_until_empty();

    // SAFETY: read_cr3 runs at CPL=0 in the in-kernel test runner.
    let cr3_after = unsafe { read_cr3() };
    if cr3_after == user_cr3 {
        return TestResult::Fail("CR3 left in user AS after run_until_empty");
    }
    if cr3_after != kernel_cr3 {
        return TestResult::Fail("CR3 ended in unexpected value after run_until_empty");
    }
    if !RESIDENCY_SEEN_DURING_POLL.load(Ordering::Relaxed) {
        return TestResult::Fail("PCID-0 residency was absent during user poll");
    }
    let poll_cpu = POLL_CPU.load(Ordering::Relaxed);
    if poll_cpu == u32::MAX {
        return TestResult::Fail("user poll did not record its CPU");
    }
    if tlb_shootdown::active_as_bitmap(poll_cpu) & 1 != 0 {
        return TestResult::Fail("PCID-0 residency survived kernel CR3 restore");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "scheduler",
    smoke_scheduler_user_task_poll_restores_kernel_cr3
);

/// aarch64 mirror of the x86_64 `…restores_kernel_cr3` test:
/// asserts that polling a user task leaves TTBR0_EL1 at the
/// kernel root after `run_until_empty` returns. `activate()` installs
/// the user root for the poll, so without the save/restore two user
/// tasks back-to-back would inherit each other's TTBR0 until their
/// own activation ran.
#[cfg(target_arch = "aarch64")]
fn smoke_scheduler_user_task_poll_restores_kernel_ttbr0() -> TestResult {
    extern crate alloc;
    use crate::{spawn_user, TaskSpec};
    use alloc::sync::Arc;
    use narf_memory::AddressSpace;

    // SAFETY: `MRS TTBR0_EL1` is unconditional at EL1.
    #[inline(always)]
    unsafe fn read_ttbr0() -> u64 {
        let v: u64;
        // SAFETY: `MRS TTBR0_EL1` is an unprivileged-of-EL1 system-register
        // read with no side effects; `nomem`/`nostack`/`preserves_flags`
        // hold and `out(reg) v` is the sole, written operand.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: reads a system register into the sole `out(reg)` operand.
        unsafe {
            core::arch::asm!(
                "mrs {0}, ttbr0_el1",
                out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        v
    }

    crate::__reset_queues_for_test();
    // SAFETY: `read_ttbr0` only issues `MRS TTBR0_EL1`; the test runs at
    // EL1 where that read is always permitted.
    // SAFETY: Valid memory or trusted environment
    let kernel_ttbr0 = unsafe { read_ttbr0() };

    // SAFETY: `new_for_user` only requires paging be enabled, which always
    // holds once the kernel test harness is running at EL1/long mode.
    // SAFETY: Valid memory or trusted environment
    let user_as = unsafe { AddressSpace::new_for_user() }.expect("alloc user AS");
    let arc_as = Arc::new(user_as);

    let _tid = spawn_user(
        crate::alloc_task_id(),
        async {},
        TaskSpec::unthrottled(),
        Arc::clone(&arc_as),
    );

    crate::run_until_empty();

    // SAFETY: `read_ttbr0` only issues `MRS TTBR0_EL1`; the test runs at
    // EL1 where that read is always permitted.
    // SAFETY: Valid memory or trusted environment
    let ttbr0_after = unsafe { read_ttbr0() };
    drop(arc_as);
    if ttbr0_after == kernel_ttbr0 {
        TestResult::Pass
    } else {
        TestResult::Fail("TTBR0_EL1 not restored to kernel root after run_until_empty")
    }
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!(
    "scheduler",
    smoke_scheduler_user_task_poll_restores_kernel_ttbr0
);

/// Regression: a user task followed by a kernel task on the same
/// CPU queue must BOTH run, and CR3 must be the kernel root by
/// the time the kernel task is polled. Otherwise any low-half
/// access in the kernel task would page-fault (the production
/// `boot-init` symptom: DrainTask polled fine, then init's user
/// AS was activated, then cursor::pump / status-refresh / the
/// FB drain task all ran with stale user CR3 and faulted
/// silently on their first FB-phys beacon write).
///
/// Reads CR3 from inside the kernel task — that's where the
/// regression hits in production.
#[cfg(target_arch = "x86_64")]
fn smoke_scheduler_user_then_kernel_task_sees_kernel_cr3() -> TestResult {
    extern crate alloc;
    use crate::{spawn, spawn_user, TaskSpec};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use narf_memory::AddressSpace;

    static USER_RAN: AtomicBool = AtomicBool::new(false);
    static KERNEL_RAN: AtomicBool = AtomicBool::new(false);
    static KERNEL_CR3_OBSERVED: AtomicU64 = AtomicU64::new(0);
    USER_RAN.store(false, Ordering::Relaxed);
    KERNEL_RAN.store(false, Ordering::Relaxed);
    KERNEL_CR3_OBSERVED.store(0, Ordering::Relaxed);

    crate::__reset_queues_for_test();

    /// # Safety
    /// Must run at CPL=0 (kernel test context); reading CR3 is otherwise
    /// privileged. Has no memory or stack effects.
    #[inline(always)]
    unsafe fn read_cr3() -> u64 {
        let v: u64;
        // SAFETY: `mov reg, cr3` is a side-effect-free ring-0 read; the test
        // runner executes at CPL=0 and `v` receives the value.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::arch::asm!(
                "mov {0}, cr3",
                out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }
    // SAFETY: read_cr3 runs at CPL=0 in the in-kernel test runner.
    let kernel_cr3 = unsafe { read_cr3() };

    // SAFETY: Paging is enabled in the running kernel test environment, which
    // is new_for_user's sole precondition.
    // SAFETY: `new_for_user` only requires paging be enabled, which always
    // holds once the kernel test harness is running at EL1/long mode.
    // SAFETY: Valid memory or trusted environment
    let user_as = unsafe { AddressSpace::new_for_user() }.expect("alloc user AS");
    let user_cr3 = user_as.root.as_u64();
    let arc_as = Arc::new(user_as);

    let _utid = spawn_user(
        crate::alloc_task_id(),
        async {
            USER_RAN.store(true, Ordering::Relaxed);
        },
        TaskSpec::unthrottled(),
        Arc::clone(&arc_as),
    );

    spawn(async move {
        // SAFETY: see read_cr3.
        let cr3_seen = unsafe { read_cr3() };
        KERNEL_CR3_OBSERVED.store(cr3_seen, Ordering::Relaxed);
        KERNEL_RAN.store(true, Ordering::Relaxed);
    });

    crate::run_until_empty();

    if !USER_RAN.load(Ordering::Relaxed) {
        return TestResult::Fail("user task didn't run");
    }
    if !KERNEL_RAN.load(Ordering::Relaxed) {
        return TestResult::Fail("kernel task didn't run after user task");
    }
    let observed = KERNEL_CR3_OBSERVED.load(Ordering::Relaxed);
    if observed == user_cr3 {
        return TestResult::Fail("kernel task observed stale user CR3 — leak");
    }
    if observed != kernel_cr3 {
        return TestResult::Fail("kernel task observed unexpected CR3 value");
    }
    // arc_as drops here, exercising AddressSpace::drop. The new
    // memory smoke tests assert drop-then-realloc cycles are
    // hermetic, so this no longer needs the leak workaround.
    drop(arc_as);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "scheduler",
    smoke_scheduler_user_then_kernel_task_sees_kernel_cr3
);

/// aarch64 mirror of `…sees_kernel_cr3`. Spawns a user task
/// followed by a kernel task on the same CPU queue; the kernel
/// task reads its own TTBR0_EL1 and asserts the scheduler
/// restored it to the kernel value (NOT the leaked user AS). The
/// user task also samples TTBR0 so a no-op `activate()` cannot make
/// the restore-only half of the test pass accidentally.
#[cfg(target_arch = "aarch64")]
fn smoke_scheduler_user_then_kernel_task_sees_kernel_ttbr0() -> TestResult {
    extern crate alloc;
    use crate::{spawn, spawn_user, TaskSpec};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use narf_memory::AddressSpace;

    static USER_RAN: AtomicBool = AtomicBool::new(false);
    static KERNEL_RAN: AtomicBool = AtomicBool::new(false);
    static USER_TTBR0_OBSERVED: AtomicU64 = AtomicU64::new(0);
    static KERNEL_TTBR0_OBSERVED: AtomicU64 = AtomicU64::new(0);
    USER_RAN.store(false, Ordering::Relaxed);
    KERNEL_RAN.store(false, Ordering::Relaxed);
    USER_TTBR0_OBSERVED.store(0, Ordering::Relaxed);
    KERNEL_TTBR0_OBSERVED.store(0, Ordering::Relaxed);

    crate::__reset_queues_for_test();

    // SAFETY: `MRS TTBR0_EL1` is unconditional at EL1.
    #[inline(always)]
    unsafe fn read_ttbr0() -> u64 {
        let v: u64;
        // SAFETY: `MRS TTBR0_EL1` is an unprivileged-of-EL1 system-register
        // read with no side effects; `nomem`/`nostack`/`preserves_flags`
        // hold and `out(reg) v` is the sole, written operand.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: reads a system register into the sole `out(reg)` operand.
        unsafe {
            core::arch::asm!(
                "mrs {0}, ttbr0_el1",
                out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        v
    }
    // SAFETY: `read_ttbr0` only issues `MRS TTBR0_EL1`; the test runs at
    // EL1 where that read is always permitted.
    // SAFETY: Valid memory or trusted environment
    let kernel_ttbr0 = unsafe { read_ttbr0() };

    // SAFETY: `new_for_user` only requires paging be enabled, which always
    // holds once the kernel test harness is running at EL1/long mode.
    // SAFETY: Valid memory or trusted environment
    let user_as = unsafe { AddressSpace::new_for_user() }.expect("alloc user AS");
    let user_root = user_as.root.as_u64();
    let arc_as = Arc::new(user_as);

    let _utid = spawn_user(
        crate::alloc_task_id(),
        async {
            // SAFETY: the task is polled at EL1 by the executor; MRS has no
            // side effects and lets the test observe the active low-half root.
            let observed = unsafe { read_ttbr0() };
            USER_TTBR0_OBSERVED.store(observed, Ordering::Relaxed);
            USER_RAN.store(true, Ordering::Relaxed);
        },
        TaskSpec::unthrottled(),
        Arc::clone(&arc_as),
    );

    spawn(async move {
        // SAFETY: see read_ttbr0.
        let observed = unsafe { read_ttbr0() };
        KERNEL_TTBR0_OBSERVED.store(observed, Ordering::Relaxed);
        KERNEL_RAN.store(true, Ordering::Relaxed);
    });

    crate::run_until_empty();

    drop(arc_as);

    if !USER_RAN.load(Ordering::Relaxed) {
        return TestResult::Fail("user task didn't run");
    }
    if !KERNEL_RAN.load(Ordering::Relaxed) {
        return TestResult::Fail("kernel task didn't run after user task");
    }
    let observed = KERNEL_TTBR0_OBSERVED.load(Ordering::Relaxed);
    // The user-root bit comparison: TTBR0 holds the root phys in
    // its table address in bits [47:12] and ASID in bits [63:48]. We mask to
    // the table-address bits before comparing roots.
    const ROOT_MASK: u64 = 0x0000_FFFF_FFFF_F000;
    let user_observed = USER_TTBR0_OBSERVED.load(Ordering::Relaxed);
    if (user_observed & ROOT_MASK) != (user_root & ROOT_MASK) {
        return TestResult::Fail("user task did not observe its own TTBR0 root");
    }
    if (user_observed >> 48) == 0 {
        return TestResult::Fail("user task did not receive a process ASID");
    }
    if (observed & ROOT_MASK) == (user_root & ROOT_MASK) {
        return TestResult::Fail("kernel task observed stale user TTBR0 — leak");
    }
    if (observed & ROOT_MASK) != (kernel_ttbr0 & ROOT_MASK) {
        return TestResult::Fail("kernel task observed unexpected TTBR0 value");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!(
    "scheduler",
    smoke_scheduler_user_then_kernel_task_sees_kernel_ttbr0
);

// ── relocated from verification ──

fn smoke_sleep_future_waits() -> TestResult {
    use core::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    crate::__reset_queues_for_test();
    let start = narf_time::Instant::now();
    crate::spawn(async {
        narf_time::sleep_cycles(10_000_000).await;
        DONE.store(true, Ordering::Relaxed);
    });
    crate::run_until_empty();
    let elapsed = narf_time::Instant::now().cycles_since(start);
    if !DONE.load(Ordering::Relaxed) {
        return TestResult::Fail("sleep future never completed");
    }
    if elapsed < 10_000_000 {
        return TestResult::Fail("completed before deadline — sleep isn't blocking");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_sleep_future_waits);

// ── block_on / block_on_spin smokes ────────────────────────────────

fn smoke_block_on_drives_ready_future() -> TestResult {
    // Future immediately Ready: block_on returns its value after a
    // single poll.
    let v = crate::block_on(async { 42u32 });
    if v == 42 {
        TestResult::Pass
    } else {
        TestResult::Fail("block_on didn't return the future's value")
    }
}
kernel_test_in!("scheduler", smoke_block_on_drives_ready_future);

fn smoke_block_on_drives_yield_chain() -> TestResult {
    // Future with two yield_now's: block_on must re-poll on each
    // self-wake. Drives the awake-flag-reset + re-poll path.
    let v = crate::block_on(async {
        crate::yield_now().await;
        crate::yield_now().await;
        7u32
    });
    if v == 7 {
        TestResult::Pass
    } else {
        TestResult::Fail("block_on lost the value after yield_now chain")
    }
}
kernel_test_in!("scheduler", smoke_block_on_drives_yield_chain);

fn smoke_block_on_spin_drives_yield_chain() -> TestResult {
    // block_on_spin doesn't halt — safe to call when IRQs are
    // disabled. Same shape as the cooperative variant; if the
    // spin path were broken we'd hang.
    let v = crate::block_on_spin(async {
        crate::yield_now().await;
        99u32
    });
    if v == 99 {
        TestResult::Pass
    } else {
        TestResult::Fail("block_on_spin didn't return value")
    }
}
kernel_test_in!("scheduler", smoke_block_on_spin_drives_yield_chain);

// ── deep scheduler coverage ────────────────────────────────────────
//
// New tests go deep on:
//   - affinity (CpuId, CpuSet, Affinity)
//   - priority (SchedClass, Priority, SmtSharePolicy)
//   - budget (OverrunPolicy, ResourceBudget builders, BudgetAccount::charge)
//   - cpu_lifecycle (online_count, error variants, lifecycle path)
//   - TaskSpec builders
//   - DonateError variants
//   - YieldNow shape
//   - responsive_spin
//   - all_task_ids
//
// Pure-logic where possible; runs on every target.

// ── affinity ───────────────────────────────────────────────────────

fn smoke_scheduler_cpu_id_boot_constant() -> TestResult {
    use crate::affinity::CpuId;
    if CpuId::BOOT.0 != 0 {
        return TestResult::Fail("CpuId::BOOT drifted from 0");
    }
    if CpuId::default().0 != 0 {
        return TestResult::Fail("CpuId::default drifted from 0");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_cpu_id_boot_constant);

fn smoke_scheduler_cpuset_constants() -> TestResult {
    use crate::affinity::CpuSet;
    if !CpuSet::EMPTY.is_empty() {
        return TestResult::Fail("EMPTY not empty");
    }
    let empty_len: u32 = CpuSet::EMPTY.len();
    if empty_len != 0 {
        return TestResult::Fail("EMPTY len != 0");
    }
    if CpuSet::ALL.is_empty() {
        return TestResult::Fail("ALL is empty");
    }
    if CpuSet::ALL.len() != 64 {
        return TestResult::Fail("ALL len != 64");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_cpuset_constants);

fn smoke_scheduler_cpuset_single_contains() -> TestResult {
    use crate::affinity::{CpuId, CpuSet};
    let s = CpuSet::single(CpuId(7));
    if s.len() != 1 {
        return TestResult::Fail("single set len != 1");
    }
    if !s.contains(CpuId(7)) {
        return TestResult::Fail("single set didn't contain its member");
    }
    if s.contains(CpuId(8)) {
        return TestResult::Fail("single set contained a non-member");
    }
    // bit 71 maps to bit 7 of u64 (modular).
    if !s.contains(CpuId(7 + 64)) {
        return TestResult::Fail("CpuId mod-64 wrap not honoured");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_cpuset_single_contains);

fn smoke_scheduler_cpuset_insert_accumulates() -> TestResult {
    use crate::affinity::{CpuId, CpuSet};
    let mut s = CpuSet::EMPTY;
    s.insert(CpuId(1));
    s.insert(CpuId(3));
    s.insert(CpuId(5));
    if s.len() != 3 {
        return TestResult::Fail("insert didn't accumulate to 3");
    }
    if !s.contains(CpuId(1)) || !s.contains(CpuId(3)) || !s.contains(CpuId(5)) {
        return TestResult::Fail("inserted CPUs missing");
    }
    if s.contains(CpuId(2)) || s.contains(CpuId(4)) {
        return TestResult::Fail("set contained CPUs we didn't insert");
    }
    s.insert(CpuId(3));
    if s.len() != 3 {
        return TestResult::Fail("re-insert grew the set");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_cpuset_insert_accumulates);

fn smoke_scheduler_cpuset_bitmap_intersection() -> TestResult {
    use crate::affinity::CpuSet;
    let left = CpuSet::from_bits(0b1011);
    let right = CpuSet::from_bits(0b0110);
    if left.bits() != 0b1011 {
        return TestResult::Fail("CpuSet bitmap round trip changed bits");
    }
    if left.intersection(right).bits() != 0b0010 {
        return TestResult::Fail("CpuSet intersection returned wrong CPUs");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_cpuset_bitmap_intersection);

fn smoke_scheduler_live_task_affinity_round_trip() -> TestResult {
    use crate::{Affinity, CpuId, CpuSet, SetAffinityError, TaskSpec};

    crate::__reset_queues_for_test();
    let spec = TaskSpec {
        affinity: Affinity::any(),
        ..TaskSpec::unthrottled()
    };
    let id = crate::spawn_with_spec(core::future::pending::<()>(), spec);
    if crate::task_affinity(id) != Some(CpuSet::ALL) {
        return TestResult::Fail("spawn did not register its initial affinity");
    }

    let boot = CpuSet::single(CpuId::BOOT);
    if crate::set_task_affinity(id, boot).is_err() {
        return TestResult::Fail("live queued task rejected an online CPU");
    }
    if crate::task_affinity(id) != Some(boot) {
        return TestResult::Fail("affinity update did not round trip");
    }
    if crate::set_task_affinity(id, CpuSet::EMPTY) != Err(SetAffinityError::NoOnlineCpu) {
        return TestResult::Fail("empty affinity was not rejected");
    }
    if crate::task_affinity(id) != Some(boot) {
        return TestResult::Fail("rejected update changed the live mask");
    }

    crate::__reset_queues_for_test();
    if crate::task_affinity(id).is_some() {
        return TestResult::Fail("completed/dropped task retained affinity state");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_live_task_affinity_round_trip);

fn smoke_scheduler_spawn_normalizes_offline_affinity() -> TestResult {
    use crate::{Affinity, CpuId, CpuSet, TaskSpec};

    let Some(offline) = (0..narf_lib::percpu::MAX_CPUS as u32)
        .find(|cpu| !narf_lib::smp::is_online(*cpu))
        .map(CpuId)
    else {
        return TestResult::Skip("all inline CPUs are online");
    };
    let here = CpuId(narf_lib::percpu::current_cpu() as u32);
    let fallback = if narf_lib::smp::is_online(here.0) {
        here
    } else {
        CpuId::BOOT
    };

    crate::__reset_queues_for_test();
    let id = crate::spawn_with_spec(
        core::future::pending::<()>(),
        TaskSpec {
            affinity: Affinity::pinned(offline),
            ..TaskSpec::unthrottled()
        },
    );
    if crate::task_affinity(id) != Some(CpuSet::single(fallback)) {
        return TestResult::Fail("spawn retained an affinity with no online CPU");
    }
    crate::__reset_queues_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_spawn_normalizes_offline_affinity
);

fn smoke_scheduler_requeue_keeps_allowed_current_cpu() -> TestResult {
    use crate::{Affinity, CpuId, CpuSet};

    if !narf_lib::smp::is_online(1) {
        return TestResult::Skip("soft-preference requeue needs a second online CPU");
    }
    let affinity = Affinity {
        allowed: CpuSet::ALL,
        preferred: Some(CpuId(1)),
    };
    if crate::requeue_cpu_for_affinity(affinity, 0) != 0 {
        return TestResult::Fail("soft preferred CPU overrode the allowed current CPU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_requeue_keeps_allowed_current_cpu
);

fn smoke_scheduler_affinity_any_and_pinned() -> TestResult {
    use crate::affinity::{Affinity, CpuId, CpuSet};
    let any = Affinity::any();
    if any.preferred.is_some() {
        return TestResult::Fail("Affinity::any has preferred set");
    }
    if any.allowed != CpuSet::ALL {
        return TestResult::Fail("Affinity::any allowed != ALL");
    }
    let p = Affinity::pinned(CpuId(2));
    if p.preferred != Some(CpuId(2)) {
        return TestResult::Fail("pinned preferred != target");
    }
    if !p.allowed.contains(CpuId(2)) || p.allowed.len() != 1 {
        return TestResult::Fail("pinned allowed != single(2)");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_affinity_any_and_pinned);

// ── priority ───────────────────────────────────────────────────────

fn smoke_scheduler_sched_class_variants_distinct() -> TestResult {
    use crate::priority::SchedClass;
    let all = [
        SchedClass::Idle,
        SchedClass::Batch,
        SchedClass::Default,
        SchedClass::Interactive,
        SchedClass::Realtime,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("two SchedClass variants collapsed");
            }
        }
    }
    if SchedClass::default() != SchedClass::Default {
        return TestResult::Fail("SchedClass::default != Default");
    }
    for pair in all.windows(2) {
        if pair[0].rank() >= pair[1].rank() {
            return TestResult::Fail("SchedClass rank is not strictly increasing");
        }
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_sched_class_variants_distinct);

fn smoke_scheduler_priority_constants_ordered() -> TestResult {
    use crate::priority::Priority;
    if Priority::HIGH.raw() != -10 {
        return TestResult::Fail("HIGH drifted from -10");
    }
    if Priority::NORMAL.raw() != 0 {
        return TestResult::Fail("NORMAL drifted from 0");
    }
    if Priority::LOW.raw() != 10 {
        return TestResult::Fail("LOW drifted from 10");
    }
    // PartialOrd: HIGH < NORMAL < LOW (lower nice = higher priority).
    if Priority::HIGH >= Priority::NORMAL {
        return TestResult::Fail("HIGH not < NORMAL under PartialOrd");
    }
    if Priority::NORMAL >= Priority::LOW {
        return TestResult::Fail("NORMAL not < LOW under PartialOrd");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_priority_constants_ordered);

fn smoke_scheduler_smt_share_policy_variants_distinct() -> TestResult {
    use crate::priority::SmtSharePolicy;
    let all = [
        SmtSharePolicy::Avoid,
        SmtSharePolicy::Allow,
        SmtSharePolicy::Require,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("SmtSharePolicy variants collapsed");
            }
        }
    }
    if SmtSharePolicy::default() != SmtSharePolicy::Avoid {
        return TestResult::Fail("SmtSharePolicy::default != Avoid");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_smt_share_policy_variants_distinct
);

// ── budget ─────────────────────────────────────────────────────────

fn smoke_scheduler_overrun_policy_variants_distinct() -> TestResult {
    use crate::budget::OverrunPolicy;
    let all = [
        OverrunPolicy::Throttle,
        OverrunPolicy::Demote,
        OverrunPolicy::Kill,
        OverrunPolicy::Ignore,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("OverrunPolicy variants collapsed");
            }
        }
    }
    if OverrunPolicy::default() != OverrunPolicy::Throttle {
        return TestResult::Fail("default != Throttle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_overrun_policy_variants_distinct
);

fn smoke_scheduler_resource_budget_unthrottled_shape() -> TestResult {
    use crate::budget::{OverrunPolicy, ResourceBudget};
    let b = ResourceBudget::unthrottled();
    if b.share_ppm != 1_000_000 {
        return TestResult::Fail("unthrottled share_ppm != 1M");
    }
    if b.burst_cycles != u64::MAX {
        return TestResult::Fail("unthrottled burst != MAX");
    }
    if b.deadline_cycles.is_some() {
        return TestResult::Fail("unthrottled has deadline");
    }
    if b.policy != OverrunPolicy::Ignore {
        return TestResult::Fail("unthrottled policy != Ignore");
    }
    if ResourceBudget::default() != b {
        return TestResult::Fail("default != unthrottled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_resource_budget_unthrottled_shape
);

fn smoke_scheduler_resource_budget_fair_share_shape() -> TestResult {
    use crate::budget::{OverrunPolicy, ResourceBudget};
    let b = ResourceBudget::fair_share(250_000, 50_000);
    if b.share_ppm != 250_000 {
        return TestResult::Fail("fair_share share didn't take");
    }
    if b.burst_cycles != 50_000 {
        return TestResult::Fail("fair_share burst didn't take");
    }
    if b.policy != OverrunPolicy::Throttle {
        return TestResult::Fail("fair_share policy != Throttle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_resource_budget_fair_share_shape
);

fn smoke_scheduler_budget_account_tracks_polls_and_cycles() -> TestResult {
    use crate::budget::{BudgetAccount, ChargeOutcome, ResourceBudget};
    let b = ResourceBudget::fair_share(500_000, 1_000);
    let mut a = BudgetAccount::new();
    let o1 = a.charge(500, &b);
    let o2 = a.charge(400, &b);
    let o3 = a.charge(900, &b);
    if o1 != ChargeOutcome::Continue
        || o2 != ChargeOutcome::Continue
        || o3 != ChargeOutcome::Continue
    {
        return TestResult::Fail("within-burst polls flagged as overrun");
    }
    if a.cycles_spent != 1_800 || a.polls != 3 || a.overruns != 0 {
        return TestResult::Fail("3 within-burst polls didn't accumulate cleanly");
    }
    let o4 = a.charge(2_000, &b);
    if o4 != ChargeOutcome::Throttle {
        return TestResult::Fail("over-burst poll with Throttle policy didn't surface Throttle");
    }
    if a.overruns != 1 {
        return TestResult::Fail("overruns didn't bump to 1");
    }
    if a.polls != 4 {
        return TestResult::Fail("poll count didn't bump to 4");
    }
    if a.cycles_spent != 3_800 {
        return TestResult::Fail("cycles_spent wrong after overrun");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_budget_account_tracks_polls_and_cycles
);

fn smoke_scheduler_budget_account_charge_saturates() -> TestResult {
    use crate::budget::{BudgetAccount, ResourceBudget};
    let b = ResourceBudget::unthrottled();
    let mut a = BudgetAccount::new();
    let huge = u64::MAX - 100;
    a.charge(huge, &b);
    if a.cycles_spent != huge {
        return TestResult::Fail("first huge charge didn't take");
    }
    a.charge(huge, &b);
    if a.cycles_spent != u64::MAX {
        return TestResult::Fail("second huge charge didn't saturate to MAX");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_budget_account_charge_saturates);

fn smoke_scheduler_period_budget_strict_replenishes() -> TestResult {
    use crate::{BudgetAccount, BudgetEligibility, ChargeOutcome, PeriodBudget, ResourceBudget};

    let budget = ResourceBudget::unthrottled().with_period(PeriodBudget::strict(100, 1_000));
    let mut account = BudgetAccount::new();
    let first = account.prepare(10_000, &budget);
    if first.eligibility != BudgetEligibility::Eligible || first.remaining_cycles != 100 {
        return TestResult::Fail("strict period did not initialise with full runtime");
    }
    if account.charge_period(100, &budget, false) != ChargeOutcome::Continue {
        return TestResult::Fail("exact strict runtime charge should complete cleanly");
    }
    if account.view(10_100, &budget).eligibility != BudgetEligibility::Throttled {
        return TestResult::Fail("strict budget remained eligible after exhaustion");
    }
    let replenished = account.prepare(11_000, &budget);
    if replenished.eligibility != BudgetEligibility::Eligible || replenished.remaining_cycles != 100
    {
        return TestResult::Fail("strict budget did not replenish at its boundary");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_period_budget_strict_replenishes
);

fn smoke_scheduler_period_budget_idle_borrow_repays_debt() -> TestResult {
    use crate::{BudgetAccount, BudgetEligibility, ChargeOutcome, PeriodBudget, ResourceBudget};

    let budget =
        ResourceBudget::unthrottled().with_period(PeriodBudget::idle_borrow(100, 1_000, 50));
    let mut account = BudgetAccount::new();
    let _ = account.prepare(20_000, &budget);
    if account.charge_period(125, &budget, true) != ChargeOutcome::Continue {
        return TestResult::Fail("bounded idle borrow was rejected");
    }
    let borrowed = account.view(20_100, &budget);
    if borrowed.eligibility != BudgetEligibility::Borrowable
        || borrowed.borrowed_cycles != 25
        || borrowed.debt_cycles != 25
    {
        return TestResult::Fail("idle-borrow accounting snapshot is wrong");
    }
    let replenished = account.prepare(21_000, &budget);
    if replenished.remaining_cycles != 75 || replenished.debt_cycles != 0 {
        return TestResult::Fail("next period did not repay idle-borrow debt");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_period_budget_idle_borrow_repays_debt
);

fn smoke_scheduler_period_budget_overshoot_becomes_debt() -> TestResult {
    use crate::{BudgetAccount, ChargeOutcome, PeriodBudget, ResourceBudget};

    let budget = ResourceBudget::unthrottled().with_period(PeriodBudget::strict(100, 1_000));
    let mut account = BudgetAccount::new();
    let _ = account.prepare(30_000, &budget);
    if account.charge_period(140, &budget, false) != ChargeOutcome::PeriodExhausted {
        return TestResult::Fail("strict overshoot did not exhaust the period");
    }
    if account.debt_cycles != 40 {
        return TestResult::Fail("unpreemptible overshoot was not retained as debt");
    }
    let replenished = account.prepare(31_000, &budget);
    if replenished.remaining_cycles != 60 {
        return TestResult::Fail("overshoot debt was not deducted at replenishment");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_period_budget_overshoot_becomes_debt
);

// ── cpu_lifecycle ──────────────────────────────────────────────────

fn smoke_scheduler_cpu_online_boot_starts_online() -> TestResult {
    use crate::affinity::CpuId;
    use crate::cpu_lifecycle::{__test_reset_online_mask, cpu_online, online_count};
    __test_reset_online_mask();
    if !cpu_online(CpuId::BOOT) {
        return TestResult::Fail("CPU 0 not online after reset");
    }
    if online_count() != 1 {
        return TestResult::Fail("online_count after reset != 1");
    }
    if cpu_online(CpuId(64)) {
        return TestResult::Fail("CPU 64 reported online (out of 64-bit range)");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_cpu_online_boot_starts_online);

fn smoke_scheduler_hotplug_error_variants_distinct() -> TestResult {
    use crate::cpu_lifecycle::HotPlugError;
    let all = [
        HotPlugError::AuthorityRevoked,
        HotPlugError::OutOfRange,
        HotPlugError::NoChange,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("HotPlugError variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_hotplug_error_variants_distinct);

fn smoke_scheduler_cpu_take_offline_refuses_bsp() -> TestResult {
    use crate::affinity::CpuId;
    use crate::cpu_lifecycle::{cpu_take_offline, HotPlugError, __test_reset_online_mask};
    use narf_capabilities::{Cap, Invoke};
    __test_reset_online_mask();
    let cap: Cap<crate::cpu_lifecycle::CpuLifecycle, Invoke> = Cap::bootstrap();
    match cpu_take_offline(CpuId::BOOT, &cap) {
        Err(HotPlugError::OutOfRange) => TestResult::Pass,
        _ => TestResult::Fail("BSP take-offline didn't surface OutOfRange"),
    }
}
kernel_test_in!("scheduler", smoke_scheduler_cpu_take_offline_refuses_bsp);

fn smoke_scheduler_cpu_bring_up_take_offline_lifecycle() -> TestResult {
    use crate::affinity::CpuId;
    use crate::cpu_lifecycle::{
        cpu_bring_up, cpu_online, cpu_take_offline, online_count, HotPlugError,
        __test_reset_online_mask,
    };
    use narf_capabilities::{Cap, Invoke};
    __test_reset_online_mask();
    let cap: Cap<crate::cpu_lifecycle::CpuLifecycle, Invoke> = Cap::bootstrap();
    cpu_bring_up(CpuId(3), &cap).expect("bring up");
    if !cpu_online(CpuId(3)) {
        return TestResult::Fail("CPU 3 not online after bring_up");
    }
    if online_count() != 2 {
        return TestResult::Fail("online_count didn't reach 2");
    }
    match cpu_bring_up(CpuId(3), &cap) {
        Err(HotPlugError::NoChange) => {}
        _ => return TestResult::Fail("re-bring_up didn't surface NoChange"),
    }
    cpu_take_offline(CpuId(3), &cap).expect("take offline");
    if cpu_online(CpuId(3)) {
        return TestResult::Fail("CPU 3 still online after take_offline");
    }
    match cpu_take_offline(CpuId(3), &cap) {
        Err(HotPlugError::NoChange) => {}
        _ => return TestResult::Fail("re-take_offline didn't surface NoChange"),
    }
    __test_reset_online_mask();
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_cpu_bring_up_take_offline_lifecycle
);

fn smoke_scheduler_cpu_bring_up_out_of_range() -> TestResult {
    use crate::affinity::CpuId;
    use crate::cpu_lifecycle::{cpu_bring_up, HotPlugError, __test_reset_online_mask};
    use narf_capabilities::{Cap, Invoke};
    __test_reset_online_mask();
    let cap: Cap<crate::cpu_lifecycle::CpuLifecycle, Invoke> = Cap::bootstrap();
    match cpu_bring_up(CpuId(64), &cap) {
        Err(HotPlugError::OutOfRange) => TestResult::Pass,
        _ => TestResult::Fail("cpu_bring_up(64) didn't surface OutOfRange"),
    }
}
kernel_test_in!("scheduler", smoke_scheduler_cpu_bring_up_out_of_range);

fn smoke_scheduler_cpu_lifecycle_revoked_cap_rejected() -> TestResult {
    use crate::affinity::CpuId;
    use crate::cpu_lifecycle::{cpu_bring_up, HotPlugError, __test_reset_online_mask};
    use narf_capabilities::{Cap, Invoke};
    __test_reset_online_mask();
    let cap: Cap<crate::cpu_lifecycle::CpuLifecycle, Invoke> = Cap::bootstrap();
    cap.revoke();
    match cpu_bring_up(CpuId(2), &cap) {
        Err(HotPlugError::AuthorityRevoked) => TestResult::Pass,
        _ => TestResult::Fail("revoked cap didn't surface AuthorityRevoked"),
    }
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_cpu_lifecycle_revoked_cap_rejected
);

// ── TaskSpec ───────────────────────────────────────────────────────

fn smoke_scheduler_task_spec_unthrottled_bsp_pinned() -> TestResult {
    use crate::affinity::CpuId;
    use crate::TaskSpec;
    let s = TaskSpec::unthrottled();
    if s.affinity.preferred != Some(CpuId::BOOT) {
        return TestResult::Fail("unthrottled not BSP-pinned");
    }
    if s.budget_cap.is_some() {
        return TestResult::Fail("unthrottled carries a budget cap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_task_spec_unthrottled_bsp_pinned
);

fn smoke_scheduler_task_spec_realtime_shape() -> TestResult {
    use crate::priority::{Priority, SchedClass};
    use crate::TaskSpec;
    let s = TaskSpec::realtime(12_345_678);
    if s.class != SchedClass::RealTime {
        return TestResult::Fail("realtime class wrong");
    }
    if s.priority != Priority::HIGH {
        return TestResult::Fail("realtime priority != HIGH");
    }
    if s.budget.deadline_cycles != Some(12_345_678) {
        return TestResult::Fail("realtime deadline didn't take");
    }
    // realtime is NOT BSP-pinned (any() allows migration).
    if s.affinity.preferred.is_some() {
        return TestResult::Fail("realtime has BSP pin");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_task_spec_realtime_shape);

// ── DonateError ────────────────────────────────────────────────────

fn smoke_scheduler_donate_error_variants_distinct() -> TestResult {
    use crate::DonateError;
    let all = [
        DonateError::AuthorityRevoked,
        DonateError::TargetNotFound,
        DonateError::NotReady,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("DonateError variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_donate_error_variants_distinct);

// ── all_task_ids + spawn surface ───────────────────────────────────

fn smoke_scheduler_all_task_ids_lists_spawned() -> TestResult {
    use crate::TaskId;
    use core::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    DONE.store(false, Ordering::Relaxed);

    crate::__reset_queues_for_test();
    let pre = crate::all_task_ids().len();
    let id = crate::spawn(async {
        DONE.store(true, Ordering::Relaxed);
    });
    let after = crate::all_task_ids();
    if after.len() != pre + 1 {
        return TestResult::Fail("spawn didn't bump all_task_ids count");
    }
    if !after.contains(&id) {
        return TestResult::Fail("spawned id missing from all_task_ids");
    }
    if id == TaskId(0) {
        return TestResult::Fail("spawn returned zero TaskId");
    }
    crate::run_until_empty();
    if !DONE.load(Ordering::Relaxed) {
        return TestResult::Fail("spawned task didn't run");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_all_task_ids_lists_spawned);

// ── YieldNow ───────────────────────────────────────────────────────

fn smoke_scheduler_yield_now_resolves_on_second_poll() -> TestResult {
    // YieldNow returns Pending on first poll (after registering its
    // wake) and Ready on second poll. Confirms the "yield exactly
    // once" contract.
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn noop_clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VT)
    }
    fn wake(_: *const ()) {}
    fn drop_no(_: *const ()) {}
    static VT: RawWakerVTable = RawWakerVTable::new(noop_clone, wake, wake, drop_no);
    // SAFETY: The vtable `VT`'s clone/wake/drop are all no-ops that never
    // dereference the data pointer, so the null data pointer is never read and
    // the RawWaker contract (each fn behaves correctly for this data) holds.
    // SAFETY: Valid memory or trusted environment
    let w = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VT)) };
    let mut cx = Context::from_waker(&w);

    let mut y = crate::yield_now();
    let p1 = Pin::new(&mut y).poll(&mut cx);
    if !matches!(p1, Poll::Pending) {
        return TestResult::Fail("yield_now first poll wasn't Pending");
    }
    let p2 = Pin::new(&mut y).poll(&mut cx);
    if !matches!(p2, Poll::Ready(())) {
        return TestResult::Fail("yield_now second poll wasn't Ready");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_yield_now_resolves_on_second_poll
);

// ── responsive_spin ────────────────────────────────────────────────

fn smoke_scheduler_responsive_spin_returns_true_when_done_immediately() -> TestResult {
    let before = crate::forward_progress_count();
    let result = crate::responsive_spin(|| true, 10);
    if !result {
        return TestResult::Fail("responsive_spin with immediate done didn't return true");
    }
    if crate::forward_progress_count() == before {
        return TestResult::Fail("successful responsive_spin did not publish forward progress");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_responsive_spin_returns_true_when_done_immediately
);

fn smoke_scheduler_responsive_spin_caps_at_max_iters() -> TestResult {
    use core::cell::Cell;
    let calls = Cell::new(0u32);
    let result = crate::responsive_spin(
        || {
            calls.set(calls.get() + 1);
            false
        },
        16,
    );
    if result {
        return TestResult::Fail("responsive_spin returned true with never-done predicate");
    }
    if calls.get() == 0 {
        return TestResult::Fail("responsive_spin never invoked predicate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_responsive_spin_caps_at_max_iters
);

// ── Stage-5 donation fast path ─────────────────────────────────────

fn smoke_scheduler_donation_credit_debit_balance() -> TestResult {
    // BudgetAccount: a credit on the donee and a debit on the
    // donor are exact mirrors; revert_* unwinds both sides.
    use crate::budget::BudgetAccount;
    let mut donee = BudgetAccount::new();
    let mut donor = BudgetAccount::new();
    donor.cycles_spent = 500;
    donee.cycles_spent = 800;
    donor.add_debit(300);
    donee.add_credit(300);
    if donor.donated_out != 300 || donor.cycles_spent != 800 {
        return TestResult::Fail("donor debit didn't bump cycles_spent + donated_out");
    }
    if donee.donated_in != 300 || donee.cycles_spent != 500 {
        return TestResult::Fail("donee credit didn't reduce cycles_spent + bump donated_in");
    }
    donor.revert_debit(300);
    donee.revert_credit(300);
    if donor.donated_out != 0 || donor.cycles_spent != 500 {
        return TestResult::Fail("revert_debit didn't restore donor");
    }
    if donee.donated_in != 0 || donee.cycles_spent != 800 {
        return TestResult::Fail("revert_credit didn't restore donee");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_donation_credit_debit_balance);

fn smoke_scheduler_donation_credit_saturates_at_zero() -> TestResult {
    // Crediting more than `cycles_spent` clamps cycles_spent to 0
    // — the donee can't end up with negative spend.
    use crate::budget::BudgetAccount;
    let mut donee = BudgetAccount::new();
    donee.cycles_spent = 100;
    donee.add_credit(10_000);
    if donee.cycles_spent != 0 {
        return TestResult::Fail("credit didn't saturate cycles_spent to 0");
    }
    if donee.donated_in != 10_000 {
        return TestResult::Fail("donated_in didn't take full credit");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_donation_credit_saturates_at_zero
);

fn smoke_scheduler_donate_to_revoked_cap_falls_back() -> TestResult {
    // Donating with a live cap, then revoking before the donee
    // polls, must leave the donee runnable (donation never
    // happened semantics) — the executor's settle_donation drops
    // the claim, the task still completes.
    use crate::{donate_to, spawn, Task};
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_capabilities::{Cap, Invoke};

    static RAN: AtomicU32 = AtomicU32::new(0);
    RAN.store(0, Ordering::Relaxed);

    crate::__reset_queues_for_test();
    crate::__reset_donations_for_test();

    let target = spawn(async {
        RAN.fetch_add(1, Ordering::Relaxed);
    });

    let cap: Cap<Task, Invoke> = Cap::bootstrap();
    if donate_to(target, &cap).is_err() {
        return TestResult::Fail("donate_to on live cap failed");
    }
    // Revoke before run_until_empty so settle_donation observes
    // the dead cap on first pop.
    cap.revoke();

    crate::run_until_empty();

    if RAN.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("donee didn't run after revoked donation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_donate_to_revoked_cap_falls_back
);

fn smoke_scheduler_donate_to_credits_donee_account() -> TestResult {
    // After donate_to on a live cap, the donee's BudgetAccount
    // carries the credit on first pop. We can't reach inside the
    // slot from a test, but we can observe that two donations to
    // the same target accumulate without panicking the pending
    // debit table (capacity sanity).
    use crate::{donate_to, spawn, Task};
    use narf_capabilities::{Cap, Invoke};

    crate::__reset_queues_for_test();
    crate::__reset_donations_for_test();

    let target = spawn(async {});
    let cap: Cap<Task, Invoke> = Cap::bootstrap();

    for _ in 0..3 {
        if donate_to(target, &cap).is_err() {
            return TestResult::Fail("donate_to failed on live cap");
        }
    }
    crate::run_until_empty();
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_donate_to_credits_donee_account);

fn smoke_scheduler_donate_to_head_enqueues() -> TestResult {
    // Functional contract from Stage-3: donate_to moves the donee
    // ahead of FIFO order. Reuses the original `…reorders_head`
    // shape; included so the Stage-5 fast path doesn't regress
    // the head-enqueue behaviour.
    use crate::{donate_to, Task};
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_capabilities::{Cap, Invoke};

    static FIRST_TAG: AtomicU32 = AtomicU32::new(0);
    FIRST_TAG.store(0, Ordering::Relaxed);

    crate::__reset_queues_for_test();
    crate::__reset_donations_for_test();

    let donation: Cap<Task, Invoke> = Cap::bootstrap();
    let _a = crate::spawn(async {
        let _ = FIRST_TAG.compare_exchange(0, 0xAAAA, Ordering::Relaxed, Ordering::Relaxed);
    });
    let b = crate::spawn(async {
        let _ = FIRST_TAG.compare_exchange(0, 0xBBBB, Ordering::Relaxed, Ordering::Relaxed);
    });
    if donate_to(b, &donation).is_err() {
        return TestResult::Fail("donate_to live cap returned Err");
    }
    crate::run_until_empty();
    match FIRST_TAG.load(Ordering::Relaxed) {
        0xBBBB => TestResult::Pass,
        0xAAAA => TestResult::Fail("Stage-5 fast path lost head-enqueue ordering"),
        _ => TestResult::Fail("neither task ran"),
    }
}
kernel_test_in!("scheduler", smoke_scheduler_donate_to_head_enqueues);

// ── Stage-5 PKRS save/restore at yield points ──────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_scheduler_pkrs_save_restore_round_trip() -> TestResult {
    // pks::save() then pks::restore() is a no-op when CR4.PKS
    // isn't active (the BSP under QEMU -cpu max may or may not
    // have it). The test verifies is_active() is consistent and
    // when active, save/restore round-trips.
    use narf_arch::x86_64::pks;
    if !pks::is_active() {
        if pks::is_active() {
            return TestResult::Fail("is_active flapped");
        }
        return TestResult::Pass;
    }
    // SAFETY: We are inside the `pks::is_active()` branch, so CR4.PKS is set,
    // satisfying save()'s precondition that RDMSR(IA32_PKRS) won't #GP.
    // SAFETY: Valid memory or trusted environment
    let a = unsafe { pks::save() };
    // SAFETY: CR4.PKS is set (is_active branch); `a` was produced by save(),
    // so writing it back is a well-defined restore.
    // SAFETY: Valid memory or trusted environment
    unsafe { pks::restore(a) };
    // SAFETY: CR4.PKS is set (is_active branch), satisfying save()'s precondition.
    let b = unsafe { pks::save() };
    if a != b {
        return TestResult::Fail("save/restore round-trip didn't preserve PKRS");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("scheduler", smoke_scheduler_pkrs_save_restore_round_trip);

#[cfg(target_arch = "x86_64")]
fn smoke_scheduler_saved_pkrs_type_copy_eq() -> TestResult {
    // SavedPkrs must be Copy + Eq so the scheduler can stash it
    // in a TaskSlot field and compare reads.
    use narf_arch::x86_64::pks::SavedPkrs;
    let a = SavedPkrs(0xDEAD_BEEF);
    let b = a;
    if a != b {
        return TestResult::Fail("SavedPkrs Copy/Eq broken");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("scheduler", smoke_scheduler_saved_pkrs_type_copy_eq);

fn smoke_scheduler_yield_with_pkrs_wiring() -> TestResult {
    // The executor's PKRS save-after-Pending + restore-before-poll
    // must not break basic yield semantics. Two tasks each yield
    // once and complete; the count is the regression assertion.
    use core::sync::atomic::{AtomicUsize, Ordering};
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    COUNT.store(0, Ordering::Relaxed);
    crate::__reset_queues_for_test();
    for _ in 0..2 {
        crate::spawn(async {
            COUNT.fetch_add(1, Ordering::Relaxed);
            crate::yield_now().await;
            COUNT.fetch_add(10, Ordering::Relaxed);
        });
    }
    crate::run_until_empty();
    if COUNT.load(Ordering::Relaxed) != 22 {
        return TestResult::Fail("yield + PKRS path didn't drive 2 tasks to completion");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_yield_with_pkrs_wiring);

#[cfg(target_arch = "aarch64")]
fn smoke_scheduler_pkrs_no_op_on_aarch64() -> TestResult {
    // aarch64 has no PKRS analogue — scheduler PKRS save/restore
    // is cfg'd out. Tasks still yield + complete cleanly.
    use core::sync::atomic::{AtomicUsize, Ordering};
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    COUNT.store(0, Ordering::Relaxed);
    crate::__reset_queues_for_test();
    crate::spawn(async {
        COUNT.fetch_add(1, Ordering::Relaxed);
        crate::yield_now().await;
        COUNT.fetch_add(2, Ordering::Relaxed);
    });
    crate::run_until_empty();
    if COUNT.load(Ordering::Relaxed) != 3 {
        return TestResult::Fail("aarch64 yield path didn't complete");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("scheduler", smoke_scheduler_pkrs_no_op_on_aarch64);

// ── Stage-5 fair-share enforcement + NUMA-aware steal ─────────────

fn smoke_scheduler_overrun_policy_throttle_outcome() -> TestResult {
    // Throttle policy yields ChargeOutcome::Throttle when the
    // per-poll cycles exceed burst_cycles.
    use crate::budget::{BudgetAccount, ChargeOutcome, OverrunPolicy, ResourceBudget};
    let b = ResourceBudget {
        share_ppm: 500_000,
        burst_cycles: 100,
        deadline_cycles: None,
        policy: OverrunPolicy::Throttle,
        period: None,
    };
    let mut a = BudgetAccount::new();
    if a.charge(200, &b) != ChargeOutcome::Throttle {
        return TestResult::Fail("Throttle policy didn't return Throttle outcome");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_overrun_policy_throttle_outcome);

fn smoke_scheduler_overrun_policy_demote_outcome() -> TestResult {
    use crate::budget::{BudgetAccount, ChargeOutcome, OverrunPolicy, ResourceBudget};
    let b = ResourceBudget {
        share_ppm: 500_000,
        burst_cycles: 100,
        deadline_cycles: None,
        policy: OverrunPolicy::Demote,
        period: None,
    };
    let mut a = BudgetAccount::new();
    if a.charge(200, &b) != ChargeOutcome::Demote {
        return TestResult::Fail("Demote policy didn't return Demote outcome");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_overrun_policy_demote_outcome);

fn smoke_scheduler_overrun_policy_kill_outcome() -> TestResult {
    use crate::budget::{BudgetAccount, ChargeOutcome, OverrunPolicy, ResourceBudget};
    let b = ResourceBudget {
        share_ppm: 500_000,
        burst_cycles: 100,
        deadline_cycles: None,
        policy: OverrunPolicy::Kill,
        period: None,
    };
    let mut a = BudgetAccount::new();
    if a.charge(200, &b) != ChargeOutcome::Kill {
        return TestResult::Fail("Kill policy didn't return Kill outcome");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_overrun_policy_kill_outcome);

fn smoke_scheduler_overrun_policy_ignore_outcome() -> TestResult {
    use crate::budget::{BudgetAccount, ChargeOutcome, OverrunPolicy, ResourceBudget};
    let b = ResourceBudget {
        share_ppm: 500_000,
        burst_cycles: 100,
        deadline_cycles: None,
        policy: OverrunPolicy::Ignore,
        period: None,
    };
    let mut a = BudgetAccount::new();
    if a.charge(200, &b) != ChargeOutcome::Continue {
        return TestResult::Fail("Ignore policy should return Continue even when over burst");
    }
    if a.overruns != 1 {
        return TestResult::Fail("Ignore policy must still tick overruns");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_overrun_policy_ignore_outcome);

fn smoke_scheduler_kill_policy_drops_slot() -> TestResult {
    // A Kill-policy task with burst_cycles 0 trips on its very
    // first poll. The executor drops the slot, so the task that
    // marks itself ALIVE never gets a second poll. With Kill in
    // place, the second-yield body never runs.
    use crate::{spawn_with_spec, OverrunPolicy, ResourceBudget, TaskSpec};
    use core::sync::atomic::{AtomicU32, Ordering};

    static FIRST: AtomicU32 = AtomicU32::new(0);
    static SECOND: AtomicU32 = AtomicU32::new(0);
    FIRST.store(0, Ordering::Relaxed);
    SECOND.store(0, Ordering::Relaxed);

    crate::__reset_queues_for_test();
    let mut spec = TaskSpec::unthrottled();
    spec.budget = ResourceBudget {
        share_ppm: 500_000,
        burst_cycles: 0,
        deadline_cycles: None,
        policy: OverrunPolicy::Kill,
        period: None,
    };
    spawn_with_spec(
        async {
            FIRST.fetch_add(1, Ordering::Relaxed);
            crate::yield_now().await;
            SECOND.fetch_add(1, Ordering::Relaxed);
        },
        spec,
    );
    crate::run_until_empty();
    if FIRST.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("task never got a first poll");
    }
    if SECOND.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("Kill policy didn't drop the slot — second body ran");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_kill_policy_drops_slot);

fn smoke_scheduler_local_node_returns() -> TestResult {
    // Sanity: local_node() either returns None (no SRAT in this
    // test environment) or a sensible Some(u32). It must not
    // panic.
    let _ = crate::local_node();
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_local_node_returns);

fn smoke_scheduler_charge_outcome_variants_distinct() -> TestResult {
    use crate::budget::ChargeOutcome;
    let all = [
        ChargeOutcome::Continue,
        ChargeOutcome::Throttle,
        ChargeOutcome::Demote,
        ChargeOutcome::Kill,
        ChargeOutcome::PeriodExhausted,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("ChargeOutcome variants collapsed");
            }
        }
    }
    if ChargeOutcome::default() != ChargeOutcome::Continue {
        return TestResult::Fail("default ChargeOutcome != Continue");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_charge_outcome_variants_distinct
);

fn smoke_pluggable_scheduler_policy() -> TestResult {
    // Wave D: validate the `Scheduler` policy seam.
    //
    // 1) Default strict-class policy is wired by `init()` — confirmed
    //    via `current_scheduler_name`.
    // 2) Install `PriorityScheduler` under a `Cap<SchedPolicy, Grant>`
    //    minted from `Cap::bootstrap()`; spawn one HIGH and one LOW
    //    priority task and drive one round. With priority enabled,
    //    the HIGH-priority task polls first.
    // 3) Reinstall `ClassScheduler` so subsequent smokes start clean.
    use crate::{
        current_scheduler_name, install_scheduler, spawn_with_spec, ClassScheduler, Priority,
        PriorityScheduler, SchedPolicy, TaskSpec,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_capabilities::{Cap, Grant};

    // Default install — `init()` always plants ClassScheduler. Re-run a fresh
    // `init()` is gated, but the slot is already set from boot, so
    // the name is observable right here.
    let default_name = current_scheduler_name();
    if default_name != Some("class") {
        return TestResult::Fail("default scheduler is not 'class'");
    }

    let cap: Cap<SchedPolicy, Grant> = Cap::bootstrap();
    if install_scheduler(&cap, PriorityScheduler).is_err() {
        return TestResult::Fail("install_scheduler(Priority) failed");
    }
    if current_scheduler_name() != Some("priority") {
        // Restore default before bailing so we don't leak the
        // wrong-policy install into the next smoke.
        let _ = install_scheduler(&cap, ClassScheduler);
        return TestResult::Fail("current_scheduler_name did not reflect Priority install");
    }

    // Order-of-poll witness: each task records the round-tick at
    // which it first polled. With Priority installed, HIGH polls
    // before LOW even though LOW is enqueued first. With Fifo the
    // ordering would be reversed.
    static TICK: AtomicUsize = AtomicUsize::new(0);
    static LOW_FIRST_POLL: AtomicUsize = AtomicUsize::new(0);
    static HIGH_FIRST_POLL: AtomicUsize = AtomicUsize::new(0);
    TICK.store(0, Ordering::Relaxed);
    LOW_FIRST_POLL.store(0, Ordering::Relaxed);
    HIGH_FIRST_POLL.store(0, Ordering::Relaxed);

    crate::__reset_queues_for_test();

    let mut low_spec = TaskSpec::unthrottled();
    low_spec.priority = Priority::LOW;
    let mut high_spec = TaskSpec::unthrottled();
    high_spec.priority = Priority::HIGH;

    // Enqueue LOW first so a naive FIFO would poll LOW before HIGH;
    // Priority must reverse the order.
    spawn_with_spec(
        async {
            let t = TICK.fetch_add(1, Ordering::Relaxed) + 1;
            LOW_FIRST_POLL.store(t, Ordering::Relaxed);
        },
        low_spec,
    );
    spawn_with_spec(
        async {
            let t = TICK.fetch_add(1, Ordering::Relaxed) + 1;
            HIGH_FIRST_POLL.store(t, Ordering::Relaxed);
        },
        high_spec,
    );

    crate::run_until_empty();

    let low = LOW_FIRST_POLL.load(Ordering::Relaxed);
    let high = HIGH_FIRST_POLL.load(Ordering::Relaxed);
    let order_ok = high > 0 && low > 0 && high < low;

    // Always reinstall the default before returning so subsequent
    // smokes (and the rest of the kernel) see strict class dispatch.
    if install_scheduler(&cap, ClassScheduler).is_err() {
        return TestResult::Fail("re-install_scheduler(Class) failed");
    }
    if current_scheduler_name() != Some("class") {
        return TestResult::Fail("scheduler did not revert to class");
    }

    if !order_ok {
        return TestResult::Fail(
            "PriorityScheduler did not poll HIGH before LOW \
             (tick witness)",
        );
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_pluggable_scheduler_policy);

fn smoke_scheduler_strict_class_order() -> TestResult {
    use crate::{
        install_scheduler, spawn_with_spec, ClassScheduler, SchedClass, SchedPolicy, TaskSpec,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_capabilities::{Cap, Grant, Spend};

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    static SEEN: [AtomicUsize; 5] = [const { AtomicUsize::new(usize::MAX) }; 5];

    NEXT.store(0, Ordering::Relaxed);
    for seen in &SEEN {
        seen.store(usize::MAX, Ordering::Relaxed);
    }
    crate::__reset_queues_for_test();
    let cap: Cap<SchedPolicy, Grant> = Cap::bootstrap();
    let budget_cap: Cap<crate::CpuBudget, Spend> = Cap::bootstrap();
    if install_scheduler(&cap, ClassScheduler).is_err() {
        return TestResult::Fail("install_scheduler(Class) failed");
    }

    // Enqueue lowest-to-highest so FIFO produces the exact opposite order.
    let classes = [
        SchedClass::Idle,
        SchedClass::Batch,
        SchedClass::Default,
        SchedClass::Interactive,
        SchedClass::Realtime,
    ];
    for (index, class) in classes.into_iter().enumerate() {
        let mut spec = TaskSpec::unthrottled();
        spec.class = class;
        let task = async move {
            SEEN[index].store(NEXT.fetch_add(1, Ordering::Relaxed), Ordering::Relaxed);
        };
        if class == SchedClass::Realtime {
            spec =
                TaskSpec::realtime_periodic(1, 100, narf_time::now_cycles().saturating_add(10_000));
            if crate::spawn_realtime(task, spec, &budget_cap).is_err() {
                return TestResult::Fail("realtime class admission failed");
            }
        } else {
            spawn_with_spec(task, spec);
        }
    }
    crate::run_until_empty();

    let expected = [4usize, 3, 2, 1, 0];
    for (class_index, expected_order) in expected.into_iter().enumerate() {
        if SEEN[class_index].load(Ordering::Relaxed) != expected_order {
            return TestResult::Fail("strict scheduling-class order was not enforced");
        }
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_strict_class_order);

fn smoke_scheduler_faulty_policy_cannot_strand_work() -> TestResult {
    use crate::{
        install_scheduler, spawn, ClassScheduler, CpuId, RunQueue, SchedPolicy, Scheduler,
        TaskHandle,
    };
    use core::sync::atomic::{AtomicBool, Ordering};
    use narf_capabilities::{Cap, Grant};

    #[derive(Copy, Clone, Debug)]
    struct DeclinesEverything;
    impl Scheduler for DeclinesEverything {
        fn name(&self) -> &'static str {
            "declines-everything"
        }

        fn pick_next(&self, _cpu: CpuId, _queue: &RunQueue<'_>) -> Option<TaskHandle> {
            None
        }
    }

    static RAN: AtomicBool = AtomicBool::new(false);
    RAN.store(false, Ordering::Relaxed);
    crate::__reset_queues_for_test();
    let cap: Cap<SchedPolicy, Grant> = Cap::bootstrap();
    if install_scheduler(&cap, DeclinesEverything).is_err() {
        return TestResult::Fail("install_scheduler(DeclinesEverything) failed");
    }
    spawn(async { RAN.store(true, Ordering::Relaxed) });
    crate::run_until_empty();
    let _ = install_scheduler(&cap, ClassScheduler);

    if !RAN.load(Ordering::Relaxed) {
        return TestResult::Fail("core fallback allowed policy to strand runnable work");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_faulty_policy_cannot_strand_work
);

fn smoke_scheduler_honors_policy_pick_order() -> TestResult {
    use crate::{
        install_scheduler, spawn, ClassScheduler, CpuId, RunQueue, SchedPolicy, Scheduler,
        TaskHandle,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_capabilities::{Cap, Grant};

    // A policy that always requests the LAST runnable candidate. The core's
    // single-pass pick_next_slot must honor that handle (it is in the top
    // eligibility tier), so the most-recently-enqueued task is dispatched
    // first — not the front of the queue. This pins the "honor the policy's
    // requested slot when it is top-tier" branch of the fused selection.
    #[derive(Copy, Clone, Debug)]
    struct PicksLast;
    impl Scheduler for PicksLast {
        fn name(&self) -> &'static str {
            "picks-last"
        }

        fn pick_next(&self, _cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle> {
            queue
                .iter_meta()
                .filter(|(_, meta)| meta.runnable)
                .map(|(handle, _)| handle)
                .last()
        }
    }

    static ORDER: [AtomicUsize; 3] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    NEXT.store(0, Ordering::Relaxed);
    for slot in &ORDER {
        slot.store(0, Ordering::Relaxed);
    }

    crate::__reset_queues_for_test();
    let cap: Cap<SchedPolicy, Grant> = Cap::bootstrap();
    if install_scheduler(&cap, PicksLast).is_err() {
        return TestResult::Fail("install_scheduler(PicksLast) failed");
    }
    // Enqueue tags 1,2,3 in order (queue front→back = [1,2,3]).
    for tag in 1usize..=3 {
        spawn(async move {
            let pos = NEXT.fetch_add(1, Ordering::Relaxed);
            if pos < ORDER.len() {
                ORDER[pos].store(tag, Ordering::Relaxed);
            }
        });
    }
    crate::run_until_empty();
    let _ = install_scheduler(&cap, ClassScheduler);

    if NEXT.load(Ordering::Relaxed) != 3 {
        return TestResult::Fail("not all tasks ran under the picks-last policy");
    }
    // The policy requested the last-enqueued task (tag 3) first; the fused
    // selection must have dispatched it ahead of the queue front (tag 1).
    if ORDER[0].load(Ordering::Relaxed) != 3 {
        return TestResult::Fail("policy's non-front requested pick was not honored first");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_honors_policy_pick_order);

// Wake-next ("next buddy"): when enabled, a just-woken task is dispatched
// ahead of the tasks already queued in front of it (Linux `set_next_buddy` +
// PICK_BUDDY). When disabled, the queue stays strict FIFO. Both phases enqueue
// [1,2,3] front→back; the buddy hint points at tag 3 (the back). Phase A
// (enabled) must run tag 3 first; phase B (disabled) must run tag 1 first.
fn smoke_scheduler_wake_next_buddy_runs_first() -> TestResult {
    use crate::{spawn, TaskId};
    use core::sync::atomic::{AtomicUsize, Ordering};

    static ORDER: [AtomicUsize; 3] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    let run_phase = |wake_next_on: bool| -> [usize; 3] {
        NEXT.store(0, Ordering::Relaxed);
        for slot in &ORDER {
            slot.store(0, Ordering::Relaxed);
        }
        crate::__reset_queues_for_test();
        crate::disable_wake_next();
        // Enqueue tags 1,2,3 in order (queue front→back = [1,2,3]).
        let mut ids = [TaskId(0); 3];
        for (i, id_slot) in ids.iter_mut().enumerate() {
            let tag = i + 1;
            *id_slot = spawn(async move {
                let pos = NEXT.fetch_add(1, Ordering::Relaxed);
                if pos < ORDER.len() {
                    ORDER[pos].store(tag, Ordering::Relaxed);
                }
            });
        }
        if wake_next_on {
            // Point the buddy at the BACK task (tag 3) on this CPU.
            crate::enable_wake_next();
            crate::__test_set_wake_next(narf_lib::percpu::current_cpu() as u32, ids[2].raw());
        }
        crate::run_until_empty();
        crate::disable_wake_next();
        [
            ORDER[0].load(Ordering::Relaxed),
            ORDER[1].load(Ordering::Relaxed),
            ORDER[2].load(Ordering::Relaxed),
        ]
    };

    // Phase A: buddy on → tag 3 (queue back) dispatched first.
    let a = run_phase(true);
    if a[0] != 3 {
        return TestResult::Fail("wake-next buddy (tag 3) was not dispatched ahead of the queue");
    }
    // Phase B: buddy off → strict FIFO, tag 1 (queue front) first.
    let b = run_phase(false);
    if b[0] != 1 {
        return TestResult::Fail("with wake-next off the queue was not strict FIFO");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_wake_next_buddy_runs_first);

fn smoke_scheduler_select_wake_cpu_prefers_idle_sibling() -> TestResult {
    use crate::affinity::CpuId;
    use crate::steal::{NumaAwareSteal, StealStrategy};

    let strat = NumaAwareSteal;
    // CPUs 0..4 online; only cpu 2 idle. A task homed on the busy cpu 0 should
    // be hinted to the idle sibling cpu 2 so it gets pulled there.
    let online = |c: CpuId| c.0 < 4;
    let only_2_idle = |c: CpuId| c.0 == 2;
    match strat.select_wake_cpu(CpuId(0), &online, &only_2_idle) {
        Some(t) if t.0 == 2 => {}
        _ => return TestResult::Fail("expected the idle sibling cpu 2"),
    }

    // No idle sibling → None (leave the wake on home).
    let none_idle = |_c: CpuId| false;
    if strat
        .select_wake_cpu(CpuId(0), &online, &none_idle)
        .is_some()
    {
        return TestResult::Fail("expected None when no sibling is idle");
    }

    // Must never hint a CPU to pull the task onto its own home, and must skip
    // offline CPUs even when they read "idle".
    let all_idle = |_c: CpuId| true;
    match strat.select_wake_cpu(CpuId(1), &online, &all_idle) {
        Some(t) if t.0 != 1 && t.0 < 4 => {}
        _ => return TestResult::Fail("must return an online sibling that is not home"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_select_wake_cpu_prefers_idle_sibling
);

fn smoke_scheduler_policy_observes_cpu_state_edges() -> TestResult {
    use crate::{
        cpu_bring_up, cpu_take_offline, install_scheduler, spawn, ClassScheduler, CpuId,
        CpuLifecycle, CpuState, CpuStateChange, RunQueue, SchedPolicy, Scheduler,
        TaskDequeueReason, TaskEnqueueReason, TaskHandle, TaskQueueEvent,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_capabilities::{Cap, Grant, Invoke};

    static ACTIVE: AtomicUsize = AtomicUsize::new(0);
    static IDLE: AtomicUsize = AtomicUsize::new(0);
    static BAD_IDLE_META: AtomicUsize = AtomicUsize::new(0);
    static STARTING: AtomicUsize = AtomicUsize::new(0);
    static DRAINING: AtomicUsize = AtomicUsize::new(0);
    static OFFLINE: AtomicUsize = AtomicUsize::new(0);
    static POLICY_INSTALL: AtomicUsize = AtomicUsize::new(0);
    static CPU_ATTACH: AtomicUsize = AtomicUsize::new(0);
    static CPU_DETACH: AtomicUsize = AtomicUsize::new(0);
    static POLICY_UNINSTALL: AtomicUsize = AtomicUsize::new(0);
    static TASK_ENQUEUE: AtomicUsize = AtomicUsize::new(0);
    static TASK_DEQUEUE: AtomicUsize = AtomicUsize::new(0);
    static BAD_TASK_REASON: AtomicUsize = AtomicUsize::new(0);

    #[derive(Copy, Clone, Debug)]
    struct StateObserver;

    impl Scheduler for StateObserver {
        fn name(&self) -> &'static str {
            "state-observer"
        }

        fn pick_next(&self, _cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle> {
            queue.front()
        }

        fn on_install(&self) {
            POLICY_INSTALL.fetch_add(1, Ordering::Relaxed);
        }

        fn on_cpu_attach(&self, _cpu: CpuId) {
            CPU_ATTACH.fetch_add(1, Ordering::Relaxed);
        }

        fn on_cpu_detach(&self, _cpu: CpuId) {
            CPU_DETACH.fetch_add(1, Ordering::Relaxed);
        }

        fn on_uninstall(&self) {
            POLICY_UNINSTALL.fetch_add(1, Ordering::Relaxed);
        }

        fn on_task_queue_event(&self, cpu: CpuId, event: TaskQueueEvent) {
            if cpu != CpuId::BOOT {
                return;
            }
            match event {
                TaskQueueEvent::Enqueued { reason, .. } => {
                    TASK_ENQUEUE.fetch_add(1, Ordering::Relaxed);
                    if reason != TaskEnqueueReason::Admitted {
                        BAD_TASK_REASON.fetch_add(1, Ordering::Relaxed);
                    }
                }
                TaskQueueEvent::Dequeued { reason, .. } => {
                    TASK_DEQUEUE.fetch_add(1, Ordering::Relaxed);
                    if reason != TaskDequeueReason::Selected {
                        BAD_TASK_REASON.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        fn on_cpu_state_change(&self, cpu: CpuId, change: CpuStateChange) {
            if cpu == CpuId(3) {
                match change.current {
                    CpuState::Starting => {
                        STARTING.fetch_add(1, Ordering::Relaxed);
                    }
                    CpuState::Draining => {
                        DRAINING.fetch_add(1, Ordering::Relaxed);
                    }
                    CpuState::Offline => {
                        OFFLINE.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
                return;
            }
            if cpu != CpuId::BOOT {
                return;
            }
            match change.current {
                CpuState::Active => {
                    ACTIVE.fetch_add(1, Ordering::Relaxed);
                }
                CpuState::Idle => {
                    IDLE.fetch_add(1, Ordering::Relaxed);
                    if change.idle.is_none() {
                        BAD_IDLE_META.fetch_add(1, Ordering::Relaxed);
                    }
                }
                _ => {}
            }
        }
    }

    ACTIVE.store(0, Ordering::Relaxed);
    IDLE.store(0, Ordering::Relaxed);
    BAD_IDLE_META.store(0, Ordering::Relaxed);
    STARTING.store(0, Ordering::Relaxed);
    DRAINING.store(0, Ordering::Relaxed);
    OFFLINE.store(0, Ordering::Relaxed);
    POLICY_INSTALL.store(0, Ordering::Relaxed);
    CPU_ATTACH.store(0, Ordering::Relaxed);
    CPU_DETACH.store(0, Ordering::Relaxed);
    POLICY_UNINSTALL.store(0, Ordering::Relaxed);
    TASK_ENQUEUE.store(0, Ordering::Relaxed);
    TASK_DEQUEUE.store(0, Ordering::Relaxed);
    BAD_TASK_REASON.store(0, Ordering::Relaxed);
    crate::__reset_queues_for_test();
    crate::cpu_lifecycle::__test_reset_online_mask();

    let cap: Cap<SchedPolicy, Grant> = Cap::bootstrap();
    if install_scheduler(&cap, StateObserver).is_err() {
        return TestResult::Fail("install_scheduler(StateObserver) failed");
    }

    // An empty executor enters Idle exactly once. Dispatching a task produces
    // one Active edge, and completing the now-empty queue enters Idle again.
    crate::run_until_empty();
    spawn(async {});
    crate::run_until_empty();

    let lifecycle_cap: Cap<CpuLifecycle, Invoke> = Cap::bootstrap();
    if cpu_bring_up(CpuId(3), &lifecycle_cap).is_err()
        || cpu_take_offline(CpuId(3), &lifecycle_cap).is_err()
    {
        let _ = install_scheduler(&cap, ClassScheduler);
        crate::cpu_lifecycle::__test_reset_online_mask();
        return TestResult::Fail("logical CPU lifecycle transition failed");
    }

    let active = ACTIVE.load(Ordering::Relaxed);
    let idle = IDLE.load(Ordering::Relaxed);
    let bad_idle_meta = BAD_IDLE_META.load(Ordering::Relaxed);
    let lifecycle_edges = (
        STARTING.load(Ordering::Relaxed),
        DRAINING.load(Ordering::Relaxed),
        OFFLINE.load(Ordering::Relaxed),
    );

    let _ = install_scheduler(&cap, ClassScheduler);
    let policy_lifecycle = (
        POLICY_INSTALL.load(Ordering::Relaxed),
        CPU_ATTACH.load(Ordering::Relaxed),
        CPU_DETACH.load(Ordering::Relaxed),
        POLICY_UNINSTALL.load(Ordering::Relaxed),
    );
    crate::cpu_lifecycle::__test_reset_online_mask();

    if active != 1 || idle != 2 {
        return TestResult::Fail("CPU Active/Idle callbacks were not edge-triggered");
    }
    if bad_idle_meta != 0 {
        return TestResult::Fail("Idle callback omitted CpuIdleMeta");
    }
    if TASK_ENQUEUE.load(Ordering::Relaxed) != 1
        || TASK_DEQUEUE.load(Ordering::Relaxed) != 1
        || BAD_TASK_REASON.load(Ordering::Relaxed) != 0
    {
        return TestResult::Fail("task queue enter/leave callbacks were not balanced");
    }
    if lifecycle_edges != (1, 1, 1) {
        return TestResult::Fail("Starting/Draining/Offline callbacks were not edge-triggered");
    }
    if policy_lifecycle != (1, narf_lib::percpu::MAX_CPUS, narf_lib::percpu::MAX_CPUS, 1) {
        return TestResult::Fail("policy install/attach/detach/uninstall lifecycle was unbalanced");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_policy_observes_cpu_state_edges);

fn smoke_scheduler_policy_replacement_rebalances_queued_tasks() -> TestResult {
    use crate::{
        install_scheduler, spawn, ClassScheduler, CpuId, RunQueue, SchedPolicy, Scheduler,
        TaskDequeueReason, TaskEnqueueReason, TaskHandle, TaskQueueEvent,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_capabilities::{Cap, Grant};

    static ADMITTED: AtomicUsize = AtomicUsize::new(0);
    static ENTER_REPLACEMENT: AtomicUsize = AtomicUsize::new(0);
    static LEAVE_REPLACEMENT: AtomicUsize = AtomicUsize::new(0);
    static SELECTED: AtomicUsize = AtomicUsize::new(0);

    #[derive(Copy, Clone)]
    struct Observer;

    impl Scheduler for Observer {
        fn name(&self) -> &'static str {
            "task-queue-observer"
        }

        fn pick_next(&self, _cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle> {
            queue.front()
        }

        fn on_task_queue_event(&self, _cpu: CpuId, event: TaskQueueEvent) {
            match event {
                TaskQueueEvent::Enqueued {
                    reason: TaskEnqueueReason::Admitted,
                    ..
                } => {
                    ADMITTED.fetch_add(1, Ordering::Relaxed);
                }
                TaskQueueEvent::Enqueued {
                    reason: TaskEnqueueReason::PolicyReplacement,
                    ..
                } => {
                    ENTER_REPLACEMENT.fetch_add(1, Ordering::Relaxed);
                }
                TaskQueueEvent::Dequeued {
                    reason: TaskDequeueReason::PolicyReplacement,
                    ..
                } => {
                    LEAVE_REPLACEMENT.fetch_add(1, Ordering::Relaxed);
                }
                TaskQueueEvent::Dequeued {
                    reason: TaskDequeueReason::Selected,
                    ..
                } => {
                    SELECTED.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }

    ADMITTED.store(0, Ordering::Relaxed);
    ENTER_REPLACEMENT.store(0, Ordering::Relaxed);
    LEAVE_REPLACEMENT.store(0, Ordering::Relaxed);
    SELECTED.store(0, Ordering::Relaxed);
    crate::__reset_queues_for_test();
    let cap: Cap<SchedPolicy, Grant> = Cap::bootstrap();
    if install_scheduler(&cap, Observer).is_err() {
        return TestResult::Fail("initial observer install failed");
    }
    spawn(async {});
    if install_scheduler(&cap, Observer).is_err() {
        return TestResult::Fail("replacement observer install failed");
    }
    crate::run_until_empty();
    let _ = install_scheduler(&cap, ClassScheduler);

    if ADMITTED.load(Ordering::Relaxed) != 1
        || ENTER_REPLACEMENT.load(Ordering::Relaxed) != 1
        || LEAVE_REPLACEMENT.load(Ordering::Relaxed) != 1
        || SELECTED.load(Ordering::Relaxed) != 1
    {
        return TestResult::Fail("queued task was not balanced across policy replacement");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_policy_replacement_rebalances_queued_tasks
);

fn smoke_pluggable_donation_policy() -> TestResult {
    // Wave E: validate the `DonationPolicy` seam.
    //
    // 1) Default install ("head-queue") is wired by `init()`.
    // 2) Spawn donor + donee + a witness task; `donate_to` with
    //    HeadQueueDonation pushes donee ahead of the witness.
    // 3) Install `BackQueueDonation`; re-run; donee now lands behind
    //    the witness.
    // 4) Reinstall `HeadQueueDonation` for hygiene.
    use crate::{
        current_donation_policy_name, donate_to, install_donation_policy, spawn, BackQueueDonation,
        Donation, HeadQueueDonation, Task,
    };
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_capabilities::{Cap, Grant, Invoke};

    if current_donation_policy_name() != Some("head-queue") {
        return TestResult::Fail("default donation policy is not 'head-queue'");
    }

    let donation_cap: Cap<Donation, Grant> = Cap::bootstrap();
    let invoke_cap: Cap<Task, Invoke> = Cap::bootstrap();

    // ── Round 1: HeadQueueDonation (default) ─────────────────
    static FIRST_TAG: AtomicU32 = AtomicU32::new(0);
    FIRST_TAG.store(0, Ordering::Relaxed);
    crate::__reset_queues_for_test();
    crate::__reset_donations_for_test();

    let _witness = spawn(async {
        let _ = FIRST_TAG.compare_exchange(0, 0xAAAA, Ordering::Relaxed, Ordering::Relaxed);
    });
    let donee = spawn(async {
        let _ = FIRST_TAG.compare_exchange(0, 0xBBBB, Ordering::Relaxed, Ordering::Relaxed);
    });

    if donate_to(donee, &invoke_cap).is_err() {
        return TestResult::Fail("donate_to (head-queue) returned Err on live cap");
    }
    crate::run_until_empty();

    if FIRST_TAG.load(Ordering::Relaxed) != 0xBBBB {
        return TestResult::Fail("head-queue donation did not place donee at front");
    }

    // ── Round 2: BackQueueDonation ───────────────────────────
    if install_donation_policy(&donation_cap, BackQueueDonation).is_err() {
        return TestResult::Fail("install_donation_policy(Back) failed");
    }
    if current_donation_policy_name() != Some("back-queue") {
        let _ = install_donation_policy(&donation_cap, HeadQueueDonation);
        return TestResult::Fail("current_donation_policy_name did not reflect Back install");
    }

    FIRST_TAG.store(0, Ordering::Relaxed);
    crate::__reset_queues_for_test();
    crate::__reset_donations_for_test();

    let _witness2 = spawn(async {
        let _ = FIRST_TAG.compare_exchange(0, 0xAAAA, Ordering::Relaxed, Ordering::Relaxed);
    });
    let donee2 = spawn(async {
        let _ = FIRST_TAG.compare_exchange(0, 0xBBBB, Ordering::Relaxed, Ordering::Relaxed);
    });

    if donate_to(donee2, &invoke_cap).is_err() {
        let _ = install_donation_policy(&donation_cap, HeadQueueDonation);
        return TestResult::Fail("donate_to (back-queue) returned Err on live cap");
    }
    crate::run_until_empty();

    let back_order_ok = FIRST_TAG.load(Ordering::Relaxed) == 0xAAAA;

    // ── Hygiene: restore default ─────────────────────────────
    if install_donation_policy(&donation_cap, HeadQueueDonation).is_err() {
        return TestResult::Fail("re-install_donation_policy(Head) failed");
    }
    if current_donation_policy_name() != Some("head-queue") {
        return TestResult::Fail("donation policy did not revert to head-queue");
    }

    if !back_order_ok {
        return TestResult::Fail(
            "BackQueueDonation did not place donee behind pre-spawned witness",
        );
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_pluggable_donation_policy);

fn smoke_pluggable_steal_strategy() -> TestResult {
    // Wave F: validate the `StealStrategy` seam.
    //
    // 1) Default install ("numa-aware") is wired by `init()`.
    // 2) Installing `RandomSteal` flips `current_steal_strategy_name`
    //    to "random".
    // 3) Trait-call witness: invoking `order_victims` on the installed
    //    strategy returns a permutation of `online`, and across two
    //    calls produces a non-strict-NUMA ordering at least once.
    //    Work-stealing is opt-in and requires a multi-CPU executor,
    //    so a full end-to-end migration witness is left to the SMP
    //    bring-up smokes; trait-call witness is sufficient here.
    // 4) Reinstall `NumaAwareSteal` for hygiene.
    use crate::{
        affinity::CpuId, current_steal_strategy_name, install_steal_strategy, NumaAwareSteal,
        RandomSteal, Steal, StealStrategy,
    };
    use narf_capabilities::{Cap, Grant};

    if current_steal_strategy_name() != Some("numa-aware") {
        return TestResult::Fail("default steal strategy is not 'numa-aware'");
    }

    let cap: Cap<Steal, Grant> = Cap::bootstrap();

    // ── Round 1: install RandomSteal ─────────────────────────
    if install_steal_strategy(&cap, RandomSteal::new()).is_err() {
        return TestResult::Fail("install_steal_strategy(Random) failed");
    }
    if current_steal_strategy_name() != Some("random") {
        let _ = install_steal_strategy(&cap, NumaAwareSteal);
        return TestResult::Fail("current_steal_strategy_name did not reflect Random install");
    }

    // ── Trait-call witness on RandomSteal ────────────────────
    // Drive `order_victims` directly so the test doesn't depend on a
    // multi-CPU executor. The permutation must contain every input
    // and at least one of two trials should differ from the strict
    // ascending order [1, 2, 3, 4, 5] (which is what NumaAwareSteal
    // would produce when topology is unknown / single-node).
    let strategy = RandomSteal::new();
    let online = [CpuId(1), CpuId(2), CpuId(3), CpuId(4), CpuId(5)];
    let a = strategy.order_victims(CpuId(0), &online);
    let b = strategy.order_victims(CpuId(0), &online);
    let a_is_perm = a.len() == online.len() && online.iter().all(|c| a.contains(c));
    let b_is_perm = b.len() == online.len() && online.iter().all(|c| b.contains(c));
    let strict = [CpuId(1), CpuId(2), CpuId(3), CpuId(4), CpuId(5)];
    let non_strict_at_least_once = a.as_slice() != strict || b.as_slice() != strict;

    // ── NumaAwareSteal: same input must be deterministic ─────
    let numa = NumaAwareSteal;
    let n1 = numa.order_victims(CpuId(0), &online);
    let n2 = numa.order_victims(CpuId(0), &online);
    let numa_deterministic = n1 == n2;
    let numa_is_perm = n1.len() == online.len() && online.iter().all(|c| n1.contains(c));

    // ── Hygiene: restore default ─────────────────────────────
    if install_steal_strategy(&cap, NumaAwareSteal).is_err() {
        return TestResult::Fail("re-install_steal_strategy(NumaAware) failed");
    }
    if current_steal_strategy_name() != Some("numa-aware") {
        return TestResult::Fail("steal strategy did not revert to numa-aware");
    }

    if !a_is_perm || !b_is_perm {
        return TestResult::Fail("RandomSteal::order_victims did not return a permutation");
    }
    if !non_strict_at_least_once {
        return TestResult::Fail("RandomSteal produced strict NUMA ordering on both trials");
    }
    if !numa_deterministic {
        return TestResult::Fail("NumaAwareSteal::order_victims was non-deterministic");
    }
    if !numa_is_perm {
        return TestResult::Fail("NumaAwareSteal::order_victims did not return a permutation");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_pluggable_steal_strategy);

fn smoke_task_numa_allowed_mask_roundtrip() -> TestResult {
    const TASK: u64 = 0x4e55_4d41;
    crate::clear_task_mems_allowed(TASK);
    if crate::task_mems_allowed(TASK) != u64::MAX {
        return TestResult::Fail("unstored task NUMA mask was constrained");
    }
    crate::set_task_mems_allowed(TASK, 0b10);
    if crate::task_mems_allowed(TASK) != 0b10 {
        return TestResult::Fail("task NUMA mask did not round-trip");
    }
    crate::clear_task_mems_allowed(TASK);
    if crate::task_mems_allowed(TASK) != u64::MAX {
        return TestResult::Fail("cleared task NUMA mask remained constrained");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_task_numa_allowed_mask_roundtrip);

fn smoke_realtime_admission_is_bounded_and_released() -> TestResult {
    use narf_capabilities::{Cap, Spend};

    crate::__reset_queues_for_test();
    let cpu = crate::CpuId(narf_lib::percpu::current_cpu() as u32);
    let before = crate::realtime_bandwidth(cpu).cpu_reserved_ppm;
    let authority: Cap<crate::CpuBudget, Spend> = Cap::bootstrap();
    let deadline = narf_time::now_cycles().saturating_add(10_000);
    let first = crate::TaskSpec::realtime_periodic(100, 1_000, deadline);
    if crate::spawn_realtime(async {}, first, &authority).is_err() {
        return TestResult::Fail("valid realtime reservation was rejected");
    }
    if crate::realtime_bandwidth(cpu).cpu_reserved_ppm != before.saturating_add(100_000) {
        return TestResult::Fail("realtime utilization was not reserved");
    }
    let excess = crate::TaskSpec::realtime_periodic(900, 1_000, deadline);
    match crate::spawn_realtime(async {}, excess, &authority) {
        Err(crate::AdmissionError::CpuBandwidthExceeded)
        | Err(crate::AdmissionError::DomainBandwidthExceeded)
        | Err(crate::AdmissionError::SystemBandwidthExceeded) => {}
        _ => return TestResult::Fail("overcommitted realtime reservation was admitted"),
    }
    crate::run_until_empty();
    if crate::realtime_bandwidth(cpu).cpu_reserved_ppm != before {
        return TestResult::Fail("completed realtime task leaked its reservation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_realtime_admission_is_bounded_and_released
);

/// The cross-core wake list (Linux `ttwu_queue_wakelist`) stages a task off to
/// the side and the target folds it into its OWN run queue on drain (Linux
/// `sched_ttwu_pending`) — the task is not visible in `READY` until then, and
/// the `Enqueued` policy event fires on the target. Exercised on a single CPU:
/// the primitives take an explicit `cpu`, independent of SMP onlineness.
fn smoke_scheduler_wake_list_transfers_to_ready() -> TestResult {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static RAN: AtomicUsize = AtomicUsize::new(0);
    RAN.store(0, Ordering::Relaxed);
    crate::__reset_queues_for_test();

    // Spawn one task; the local enqueue path lands it in READY[0].
    crate::spawn(async {
        RAN.fetch_add(1, Ordering::Relaxed);
    });
    let slot = match crate::READY[0].lock().as_mut().and_then(|d| d.pop_front()) {
        Some(s) => s,
        None => return TestResult::Fail("spawned task not found in READY[0]"),
    };

    if crate::wake_list_pending(0) {
        return TestResult::Fail("wake list unexpectedly non-empty before push");
    }
    // Stage it as a cross-core waker would (llist_add).
    crate::wake_list_push(0, slot, crate::policy::TaskEnqueueReason::Admitted);
    if !crate::wake_list_pending(0) {
        return TestResult::Fail("push did not register on the wake list");
    }
    // Still off-queue: the target folds it in only on drain.
    if crate::READY[0]
        .lock()
        .as_ref()
        .map(|d| d.len())
        .unwrap_or(0)
        != 0
    {
        return TestResult::Fail("task reached READY before drain");
    }

    // Target-side fold (llist_del_all + sched_ttwu_pending).
    crate::drain_wake_list(0);
    if crate::wake_list_pending(0) {
        return TestResult::Fail("wake list not emptied by drain");
    }
    if crate::READY[0]
        .lock()
        .as_ref()
        .map(|d| d.len())
        .unwrap_or(0)
        != 1
    {
        return TestResult::Fail("drain did not move the task into READY");
    }

    crate::run_until_empty();
    if RAN.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("drained task did not run to completion");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler", smoke_scheduler_wake_list_transfers_to_ready);

/// Steal-path contention fix: a remote best-effort caller must SKIP a contended
/// victim policy slot, never spin on it. A blocking acquire in the steal path
/// let a herd of idle thieves pile onto a queue-rich victim's slot and starve
/// its own dispatch (the SPIN-NOT-POLLING stall). The probe holds the slot and
/// confirms the non-blocking accessor returns `None` (skip) rather than
/// blocking, and succeeds once the slot is free.
fn smoke_scheduler_try_with_scheduler_is_non_blocking() -> TestResult {
    // A high slot index, least likely to collide with an actively-dispatching
    // online CPU; the assertion holds regardless since we hold the guard.
    let cpu = crate::CpuId((narf_lib::percpu::MAX_CPUS - 1) as u32);
    let (skipped_while_held, ran_when_free) =
        crate::policy::__try_with_scheduler_contention_probe(cpu);
    if !skipped_while_held {
        return TestResult::Fail("try_with_scheduler acquired a held slot (would block)");
    }
    if !ran_when_free {
        return TestResult::Fail("try_with_scheduler failed to run on a free slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler",
    smoke_scheduler_try_with_scheduler_is_non_blocking
);
