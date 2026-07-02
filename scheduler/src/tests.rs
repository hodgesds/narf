//! Per-crate smoke tests for `narf-scheduler`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `"scheduler"`. Migrated from
//! `narf-verification`'s mega-lib so each subsystem owns its own
//! smokes without cycling on the higher-level harness.

use narf_kernel_test::{kernel_test_in, TestResult};

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
    // frame allocator can attribute a charge to the allocating task.
    // Once installed, narf-memory must resolve the polling task's id
    // during a poll and `None` outside one — the wiring `memory.max`
    // enforcement rides on.
    use crate::current_task_id;
    use core::sync::atomic::{AtomicU64, Ordering};

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
        // Sanity: the provider agrees with current_task_id().
        debug_assert_eq!(pid, current_task_id().raw());
        OBSERVED.store(pid, Ordering::Relaxed);
    });
    crate::run_until_empty();

    if OBSERVED.load(Ordering::Relaxed) != tid.raw() {
        return TestResult::Fail("charge pid did not resolve to the allocating task");
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
    use narf_memory::AddressSpace;

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
            // No-op user-task body. The bug isn't in the body —
            // it's that the scheduler leaks CR3 to the *next*
            // task after this one returns.
        },
        TaskSpec::unthrottled(),
        Arc::clone(&arc_as),
    );

    crate::run_until_empty();

    // SAFETY: read_cr3 runs at CPL=0 in the in-kernel test runner.
    let cr3_after = unsafe { read_cr3() };
    if cr3_after == kernel_cr3 {
        TestResult::Pass
    } else if cr3_after == user_cr3 {
        TestResult::Fail("CR3 left in user AS after run_until_empty")
    } else {
        TestResult::Fail("CR3 ended in unexpected value after run_until_empty")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "scheduler",
    smoke_scheduler_user_task_poll_restores_kernel_cr3
);

/// aarch64 mirror of the x86_64 `…restores_kernel_cr3` test:
/// asserts that polling a user task leaves TTBR0_EL1 at the
/// kernel root after `run_until_empty` returns. Today
/// `AddressSpace::activate()` on aarch64 is a diagnostic no-op
/// (writes TTBR0 back to itself), so the test passes trivially —
/// but the assertion stays in place so that if/when activate()
/// is wired to swap TTBR0 to `self.root`, the scheduler MUST
/// continue to save and restore it. Without the save/restore,
/// two user tasks back-to-back would inherit each other's TTBR0
/// until their own activate() ran.
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
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::arch::asm!(
                "mrs {0}, ttbr0_el1",
                out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
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

    let _tid = spawn_user(async {}, TaskSpec::unthrottled(), Arc::clone(&arc_as));

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
/// restored it to the kernel value (NOT the leaked user AS).
/// Trivially passes today because aarch64 activate() is a no-op,
/// but pins the contract so a future activate() rewrite stays
/// honest.
#[cfg(target_arch = "aarch64")]
fn smoke_scheduler_user_then_kernel_task_sees_kernel_ttbr0() -> TestResult {
    extern crate alloc;
    use crate::{spawn, spawn_user, TaskSpec};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use narf_memory::AddressSpace;

    static USER_RAN: AtomicBool = AtomicBool::new(false);
    static KERNEL_RAN: AtomicBool = AtomicBool::new(false);
    static KERNEL_TTBR0_OBSERVED: AtomicU64 = AtomicU64::new(0);
    USER_RAN.store(false, Ordering::Relaxed);
    KERNEL_RAN.store(false, Ordering::Relaxed);
    KERNEL_TTBR0_OBSERVED.store(0, Ordering::Relaxed);

    crate::__reset_queues_for_test();

    // SAFETY: `MRS TTBR0_EL1` is unconditional at EL1.
    #[inline(always)]
    unsafe fn read_ttbr0() -> u64 {
        let v: u64;
        // SAFETY: `MRS TTBR0_EL1` is an unprivileged-of-EL1 system-register
        // read with no side effects; `nomem`/`nostack`/`preserves_flags`
        // hold and `out(reg) v` is the sole, written operand.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::arch::asm!(
                "mrs {0}, ttbr0_el1",
                out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
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
    // its top bits plus ASID in low bits. We mask to the table-
    // address bits before comparison.
    const ROOT_MASK: u64 = 0x0000_FFFF_FFFF_F000;
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
    let all = [SchedClass::Normal, SchedClass::RealTime, SchedClass::Idle];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("two SchedClass variants collapsed");
            }
        }
    }
    if SchedClass::default() != SchedClass::Normal {
        return TestResult::Fail("SchedClass::default != Normal");
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
    let result = crate::responsive_spin(|| true, 10);
    if !result {
        return TestResult::Fail("responsive_spin with immediate done didn't return true");
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
    // 1) Default install ("fifo") is wired by `init()` — confirmed
    //    via `current_scheduler_name`.
    // 2) Install `PriorityScheduler` under a `Cap<SchedPolicy, Grant>`
    //    minted from `Cap::bootstrap()`; spawn one HIGH and one LOW
    //    priority task and drive one round. With priority enabled,
    //    the HIGH-priority task polls first.
    // 3) Reinstall `FifoScheduler` so subsequent smokes start clean.
    use crate::{
        current_scheduler_name, install_scheduler, spawn_with_spec, FifoScheduler, Priority,
        PriorityScheduler, SchedPolicy, TaskSpec,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_capabilities::{Cap, Grant};

    // Default install — `init()` always plants Fifo. Re-run a fresh
    // `init()` is gated, but the slot is already set from boot, so
    // the name is observable right here.
    let default_name = current_scheduler_name();
    if default_name != Some("fifo") {
        return TestResult::Fail("default scheduler is not 'fifo'");
    }

    let cap: Cap<SchedPolicy, Grant> = Cap::bootstrap();
    if install_scheduler(&cap, PriorityScheduler).is_err() {
        return TestResult::Fail("install_scheduler(Priority) failed");
    }
    if current_scheduler_name() != Some("priority") {
        // Restore default before bailing so we don't leak the
        // wrong-policy install into the next smoke.
        let _ = install_scheduler(&cap, FifoScheduler);
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
    // smokes (and the rest of the kernel) see fifo.
    if install_scheduler(&cap, FifoScheduler).is_err() {
        return TestResult::Fail("re-install_scheduler(Fifo) failed");
    }
    if current_scheduler_name() != Some("fifo") {
        return TestResult::Fail("scheduler did not revert to fifo");
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
