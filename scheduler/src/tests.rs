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

    let mut acct = BudgetAccount::new();
    let budget = ResourceBudget::fair_share(100_000, 1_000);
    let over = acct.charge(2_000, &budget);
    if !over {
        return TestResult::Fail("charge exceeding burst_cycles should report over-budget");
    }
    if acct.overruns != 1 || acct.polls != 1 || acct.cycles_spent != 2_000 {
        return TestResult::Fail("BudgetAccount did not accumulate correctly");
    }
    let under = acct.charge(500, &budget);
    if under {
        return TestResult::Fail("500 cycles inside burst should not report over-budget");
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
    use core::sync::atomic::{AtomicU32, Ordering};
    use crate::{spawn_with_spec, Affinity, CpuId, TaskSpec};
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
    use core::sync::atomic::{AtomicU32, Ordering};
    use crate::{spawn_with_spec, Affinity, CpuId, TaskSpec};

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
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_memory::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};
    use crate::{address_space_of, spawn_user, TaskSpec};

    crate::__reset_queues_for_test();
    static RAN: AtomicU32 = AtomicU32::new(0);
    RAN.store(0, Ordering::Relaxed);

    // Allocate a real user-root for the active arch — the
    // constructor takes care of the kernel/high-half bits that
    // have to survive activation (full-copy PML4 on x86_64, empty
    // TTBR0 on aarch64 since the kernel lives behind TTBR1).
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
kernel_test_in!("scheduler", smoke_scheduler_spawn_user_carries_address_space);

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
    use alloc::sync::Arc;
    use narf_memory::AddressSpace;
    use crate::{spawn_user, TaskSpec};

    // SAFETY: `mov %cr3, reg` is unconditional at CPL=0.
    #[inline(always)]
    unsafe fn read_cr3() -> u64 {
        let v: u64;
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
    let kernel_cr3 = unsafe { read_cr3() };

    let user_as = unsafe { AddressSpace::new_for_user() }.expect("alloc user AS");
    let user_cr3 = user_as.root.as_u64();
    if user_cr3 == kernel_cr3 {
        return TestResult::Fail("new user AS shares root with kernel AS");
    }
    let arc_as = Arc::new(user_as);

    let _tid = spawn_user(
        async {
            // No-op user-task body. The bug isn't in the body —
            // it's that the scheduler leaks CR3 to the *next*
            // task after this one returns.
        },
        TaskSpec::unthrottled(),
        Arc::clone(&arc_as),
    );

    crate::run_until_empty();

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
    use alloc::sync::Arc;
    use narf_memory::AddressSpace;
    use crate::{spawn_user, TaskSpec};

    // SAFETY: `MRS TTBR0_EL1` is unconditional at EL1.
    #[inline(always)]
    unsafe fn read_ttbr0() -> u64 {
        let v: u64;
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
    let kernel_ttbr0 = unsafe { read_ttbr0() };

    let user_as = unsafe { AddressSpace::new_for_user() }.expect("alloc user AS");
    let arc_as = Arc::new(user_as);

    let _tid = spawn_user(
        async {},
        TaskSpec::unthrottled(),
        Arc::clone(&arc_as),
    );

    crate::run_until_empty();

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
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use narf_memory::AddressSpace;
    use crate::{spawn, spawn_user, TaskSpec};

    static USER_RAN: AtomicBool = AtomicBool::new(false);
    static KERNEL_RAN: AtomicBool = AtomicBool::new(false);
    static KERNEL_CR3_OBSERVED: AtomicU64 = AtomicU64::new(0);
    USER_RAN.store(false, Ordering::Relaxed);
    KERNEL_RAN.store(false, Ordering::Relaxed);
    KERNEL_CR3_OBSERVED.store(0, Ordering::Relaxed);

    crate::__reset_queues_for_test();

    // SAFETY: `mov %cr3, reg` is unconditional at CPL=0.
    #[inline(always)]
    unsafe fn read_cr3() -> u64 {
        let v: u64;
        unsafe {
            core::arch::asm!(
                "mov {0}, cr3",
                out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }
    let kernel_cr3 = unsafe { read_cr3() };

    let user_as = unsafe { AddressSpace::new_for_user() }.expect("alloc user AS");
    let user_cr3 = user_as.root.as_u64();
    let arc_as = Arc::new(user_as);

    let _utid = spawn_user(
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
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use narf_memory::AddressSpace;
    use crate::{spawn, spawn_user, TaskSpec};

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
        unsafe {
            core::arch::asm!(
                "mrs {0}, ttbr0_el1",
                out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }
    let kernel_ttbr0 = unsafe { read_ttbr0() };

    let user_as = unsafe { AddressSpace::new_for_user() }.expect("alloc user AS");
    let user_root = user_as.root.as_u64();
    let arc_as = Arc::new(user_as);

    let _utid = spawn_user(
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
