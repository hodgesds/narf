//! Smokes for wakes staged on a CPU that does not reach a scheduling point.
//!
//! A woken task is held in one of three places: `READY[cpu]`, the parked set
//! plus `PARKED_WAKE_INBOX[cpu]` (it was asleep when woken), or
//! `WAKE_INBOX[cpu]` (another CPU enqueued it). Only the first used to be
//! reachable by an idle CPU; the other two waited for the owner's next
//! executor boundary, however far away that was.
//!
//! Two harnesses are used:
//!
//! - **A stuck CPU that never existed.** A CPU index no core ever ran on is
//!   given scheduler state (`Active`, not halted, a running task) but is not
//!   marked online, so nothing outside these tests looks at it. It owns queues
//!   and provably never drains them — the limiting case of a non-yielding
//!   section — which makes every assertion deterministic.
//! - **A real AP held in a non-yielding poll.** A plain (non-stackful, so
//!   non-preemptible) future pinned to an AP spins until released. The boot
//!   CPU then wakes, enqueues and pins tasks against it.
//!
//! They register under `scheduler/strand`, so `--subsystem scheduler/strand`
//! runs them alone and `--subsystem scheduler` still includes them.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use alloc::sync::Arc;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::percpu::MAX_CPUS;
use narf_lib::sync::IrqSafeSpinLock;

use crate::affinity::{Affinity, CpuId, CpuSet};
use crate::policy::{CpuState, TaskEnqueueReason};
use crate::{TaskId, TaskSpec, WakeCell};

const PROBES: usize = 4;
const NO_CPU: usize = usize::MAX;

static PROBE_WAKER: [IrqSafeSpinLock<Option<Waker>>; PROBES] =
    [const { IrqSafeSpinLock::new(None) }; PROBES];
static PROBE_POLLS: [AtomicUsize; PROBES] = [const { AtomicUsize::new(0) }; PROBES];
static PROBE_LAST_CPU: [AtomicUsize; PROBES] = [const { AtomicUsize::new(NO_CPU) }; PROBES];

/// Parks `parks` times, publishing its waker each time, then completes.
struct Probe {
    slot: usize,
    parks: usize,
}

impl Future for Probe {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        PROBE_LAST_CPU[this.slot].store(narf_lib::percpu::current_cpu(), Ordering::Release);
        PROBE_POLLS[this.slot].fetch_add(1, Ordering::AcqRel);
        if this.parks == 0 {
            return Poll::Ready(());
        }
        this.parks -= 1;
        *PROBE_WAKER[this.slot].lock() = Some(cx.waker().clone());
        Poll::Pending
    }
}

fn polls(slot: usize) -> usize {
    PROBE_POLLS[slot].load(Ordering::Acquire)
}

fn reset_probes() {
    crate::disable_work_stealing();
    crate::__reset_queues_for_test();
    for slot in 0..PROBES {
        *PROBE_WAKER[slot].lock() = None;
        PROBE_POLLS[slot].store(0, Ordering::Release);
        PROBE_LAST_CPU[slot].store(NO_CPU, Ordering::Release);
    }
}

fn take_waker(slot: usize) -> Option<Waker> {
    PROBE_WAKER[slot].lock().take()
}

/// Spin until `done` holds or `ns` elapse.
fn wait_for(ns: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(ns));
    loop {
        if done() {
            return true;
        }
        if narf_time::now_cycles() >= deadline {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Outlast the idle balancer's cache-hot window (`MIGRATION_COST_NS`).
fn let_cool() {
    narf_time::busy_wait_cycles(narf_time::ns_to_cycles(2 * crate::MIGRATION_COST_NS));
}

fn any_cpu_preferring(cpu: usize) -> TaskSpec {
    TaskSpec {
        affinity: Affinity {
            allowed: CpuSet::ALL,
            preferred: Some(CpuId(cpu as u32)),
        },
        ..TaskSpec::kernel_any()
    }
}

/// A CPU index no core ever ran on, dressed as a CPU that is executing a task
/// and never returns to its executor.
struct StuckCpu(usize);

impl StuckCpu {
    fn claim() -> Option<Self> {
        let ever = narf_lib::smp::ever_online_bitmap();
        let cpu = (1..MAX_CPUS)
            .rev()
            .find(|cpu| ever & (1u64 << cpu) == 0 && !narf_lib::smp::is_online(*cpu as u32))?;
        crate::policy::__test_set_cpu_state(CpuId(cpu as u32), CpuState::Active);
        crate::__test_set_cpu_halted(cpu, false);
        crate::CURRENT_TASK[cpu].store(u64::MAX, Ordering::Release);
        let stuck = Self(cpu);
        // Start every test at a scheduling-pass count no earlier test saw.
        stuck.pass_scheduling_point();
        Some(stuck)
    }

    /// The same CPU between polls: still not draining, but running no task.
    fn set_running(&self, running: bool) {
        let task = if running { u64::MAX } else { 0 };
        crate::CURRENT_TASK[self.0].store(task, Ordering::Release);
    }

    /// What a live executor does every time round its loop and after every
    /// poll. A CPU that keeps doing this is healthy however idle it is.
    fn pass_scheduling_point(&self) {
        crate::note_sched_pass(self.0);
    }

    fn release(self) {
        crate::CURRENT_TASK[self.0].store(0, Ordering::Release);
        crate::__test_clear_need_resched(self.0);
        crate::policy::__test_set_cpu_state(CpuId(self.0 as u32), CpuState::Offline);
        reset_probes();
    }
}

/// One idle-balance attempt by `thief` against `victim`.
fn pull(victim: usize, thief: usize) -> bool {
    crate::try_steal_from(victim, thief, &crate::steal::NumaAwareSteal::new())
}

fn parked_on(cpu: usize, id: TaskId) -> bool {
    crate::PARKED[cpu]
        .lock()
        .as_ref()
        .is_some_and(|parked| parked.contains_key(&id))
}

fn staged_parked_wakes(cpu: usize) -> usize {
    crate::PARKED_WAKE_INBOX[cpu].len.load(Ordering::Acquire)
}

fn staged_enqueues(cpu: usize) -> usize {
    crate::WAKE_INBOX_LEN[cpu].load(Ordering::Acquire)
}

/// Spawn a probe on this CPU, let it park, and hand its parked slot to
/// `home` — the state "CPU `home` parked the task".
fn park_probe_on(
    slot: usize,
    parks: usize,
    home: usize,
    affinity: Option<Affinity>,
) -> Option<(TaskId, Arc<WakeCell>)> {
    let me = narf_lib::percpu::current_cpu();
    let id = crate::spawn_with_spec(Probe { slot, parks }, any_cpu_preferring(me));
    crate::poll_one_round();
    if polls(slot) != 1 {
        return None;
    }
    let cell = {
        let waker = PROBE_WAKER[slot].lock();
        crate::scheduler_wake_cell(waker.as_ref()?)?
    };
    let mut entry = crate::PARKED[me].lock().as_mut()?.remove(&id)?;
    if let Some(affinity) = affinity {
        entry.slot.spec.affinity = affinity;
        entry.slot.affinity_generation = crate::register_task_affinity(id, affinity, false);
    }
    crate::enqueue_on(home, entry.slot, TaskEnqueueReason::Migrated);
    parked_on(home, id).then_some((id, cell))
}

/// A task woken while parked on a CPU that never drains must be pulled by an
/// idle CPU, and its activation node must leave with it.
fn smoke_scheduler_idle_cpu_pulls_stranded_parked_wake() -> TestResult {
    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    let Some((id, _cell)) = park_probe_on(0, 1, stuck.0, None) else {
        stuck.release();
        return TestResult::Fail("could not park the probe on the stuck CPU");
    };
    let_cool();
    let Some(waker) = take_waker(0) else {
        stuck.release();
        return TestResult::Fail("probe published no waker");
    };
    waker.wake();
    let staged = staged_parked_wakes(stuck.0);
    let pulled = pull(stuck.0, me);
    crate::poll_one_round();
    let ran = polls(0);
    let left_behind = parked_on(stuck.0, id);
    let stale_nodes = staged_parked_wakes(stuck.0);
    stuck.release();
    if staged != 1 {
        return TestResult::Fail("wake of a parked task was not staged on its home CPU");
    }
    if !pulled || left_behind {
        return TestResult::Fail(
            "idle CPU could not pull a woken task parked on a CPU that never drains",
        );
    }
    if ran != 2 {
        return TestResult::Fail("pulled task did not run on the idle CPU");
    }
    if stale_nodes != 0 {
        return TestResult::Fail("pulled task left its activation node on the stuck CPU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_idle_cpu_pulls_stranded_parked_wake
);

/// A task another CPU enqueued onto a CPU that never drains must be pulled by
/// an idle CPU out of that CPU's wake inbox.
fn smoke_scheduler_idle_cpu_pulls_stranded_wake_inbox() -> TestResult {
    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    crate::spawn_with_spec(Probe { slot: 0, parks: 0 }, any_cpu_preferring(me));
    let Some(slot) = crate::READY[me].lock().as_mut().and_then(|q| q.pop_front()) else {
        stuck.release();
        return TestResult::Fail("spawned probe not found on this CPU");
    };
    // The cross-CPU enqueue itself: a runnable slot aimed at a draining CPU
    // other than the caller is staged on that CPU's wake inbox.
    crate::enqueue_on(stuck.0, slot, TaskEnqueueReason::Requeued);
    let staged = staged_enqueues(stuck.0);
    let pulled = pull(stuck.0, me);
    crate::poll_one_round();
    let ran = polls(0);
    let remaining = staged_enqueues(stuck.0);
    stuck.release();
    if staged != 1 {
        return TestResult::Fail("cross-CPU enqueue was not staged on the wake inbox");
    }
    if !pulled || remaining != 0 {
        return TestResult::Fail(
            "idle CPU could not pull a task from the wake inbox of a CPU that never drains",
        );
    }
    if ran != 1 {
        return TestResult::Fail("pulled task did not run on the idle CPU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_idle_cpu_pulls_stranded_wake_inbox
);

/// Affinity is a hard constraint on the pull: a task allowed only on the
/// stuck CPU stays staged there, in either holding place.
fn smoke_scheduler_stranded_pinned_wake_is_not_pulled() -> TestResult {
    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    let pinned = Affinity::pinned(CpuId(stuck.0 as u32));

    let Some((parked_id, _cell)) = park_probe_on(0, 1, stuck.0, Some(pinned)) else {
        stuck.release();
        return TestResult::Fail("could not park the pinned probe on the stuck CPU");
    };
    let_cool();
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }

    let queued_id = crate::spawn_with_spec(Probe { slot: 1, parks: 0 }, any_cpu_preferring(me));
    let Some(mut slot) = crate::READY[me].lock().as_mut().and_then(|q| q.pop_front()) else {
        stuck.release();
        return TestResult::Fail("spawned probe not found on this CPU");
    };
    slot.spec.affinity = pinned;
    slot.affinity_generation = crate::register_task_affinity(queued_id, pinned, false);
    crate::enqueue_on(stuck.0, slot, TaskEnqueueReason::Requeued);

    let mut pulled = false;
    for _ in 0..4 {
        pulled |= pull(stuck.0, me);
        crate::poll_one_round();
    }
    let ran = polls(0) != 1 || polls(1) != 0;
    let parked_stays = parked_on(stuck.0, parked_id);
    let queued_stays = staged_enqueues(stuck.0) == 1;
    stuck.release();
    if pulled || ran {
        return TestResult::Fail("a task pinned to the stuck CPU was pulled off it");
    }
    if !parked_stays || !queued_stays {
        return TestResult::Fail("a pinned staged task left its home CPU's storage");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_stranded_pinned_wake_is_not_pulled
);

/// Wake-time placement (`try_migrate_wakee_to`) moves a woken parked task off
/// its home after the wake already staged an activation node there. The next
/// sleep-and-wake of that task, now on its new CPU, must not depend on the old
/// home ever draining that node.
fn smoke_scheduler_migrated_wakee_rewake_needs_no_old_home_drain() -> TestResult {
    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    let Some((id, cell)) = park_probe_on(0, 2, stuck.0, None) else {
        stuck.release();
        return TestResult::Fail("could not park the probe on the stuck CPU");
    };
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }
    let moved = crate::try_migrate_wakee_to(stuck.0 as u32, me as u32, Arc::as_ptr(&cell));
    crate::poll_one_round();
    let ran_after_move = polls(0);
    let reparked_here = parked_on(me, id);
    // Asleep again, this time on the calling CPU. Wake it once more.
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }
    for _ in 0..4 {
        crate::poll_one_round();
    }
    let ran_after_rewake = polls(0);
    stuck.release();
    if !moved || ran_after_move != 2 || !reparked_here {
        return TestResult::Fail("wake-time placement did not move and run the woken task");
    }
    if ran_after_rewake != 3 {
        return TestResult::Fail(
            "re-wake of a migrated task waited on its old home draining a stale node",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_migrated_wakee_rewake_needs_no_old_home_drain
);

static HOLD_STARTED: AtomicBool = AtomicBool::new(false);
static HOLD_RELEASE: AtomicBool = AtomicBool::new(false);
static HOLD_DONE: AtomicBool = AtomicBool::new(false);

/// Upper bound on how long the holder keeps its CPU if nobody releases it.
const HOLD_LIMIT_NS: u64 = 3_000_000_000;
/// How long a stranded task may wait for another CPU to run it.
const PULL_BOUND_NS: u64 = 250_000_000;

/// End to end on real CPUs: an AP parks T, then sits in a non-yielding poll.
/// The boot CPU wakes T (parked-woken on the AP), enqueues U onto the AP
/// (wake inbox) and V pinned to the AP. T and U must run on some other CPU
/// within a bound while the AP is still held; V must wait for the AP.
fn smoke_scheduler_stranded_wakes_run_on_another_cpu() -> TestResult {
    reset_probes();
    let me = narf_lib::percpu::current_cpu();
    let live = narf_lib::smp::ever_online_bitmap() & narf_lib::smp::online_bitmap();
    let Some(ap) = (0..MAX_CPUS).find(|cpu| *cpu != me && live & (1u64 << cpu) != 0) else {
        return TestResult::Skip("needs a second CPU that really came up");
    };
    HOLD_STARTED.store(false, Ordering::Release);
    HOLD_RELEASE.store(false, Ordering::Release);
    HOLD_DONE.store(false, Ordering::Release);

    // T: first poll on the AP, where it parks.
    crate::spawn_with_spec(Probe { slot: 0, parks: 1 }, any_cpu_preferring(ap));
    let parked = wait_for(1_000_000_000, || {
        polls(0) == 1
            && PROBE_WAKER[0]
                .lock()
                .as_ref()
                .and_then(crate::scheduler_wake_cell)
                .is_some_and(|cell| {
                    let token = cell.parked_location.load(Ordering::Acquire);
                    token != crate::NOT_PARKED && token % MAX_CPUS == ap
                })
    });
    if !parked {
        reset_probes();
        return TestResult::Fail("the AP did not run and park a task enqueued onto it");
    }

    // The AP enters a long non-yielding section: a plain future is polled on
    // the executor stack and cannot be preempted.
    crate::spawn_with_spec(
        async {
            HOLD_STARTED.store(true, Ordering::Release);
            wait_for(HOLD_LIMIT_NS, || HOLD_RELEASE.load(Ordering::Acquire));
            HOLD_DONE.store(true, Ordering::Release);
        },
        TaskSpec {
            affinity: Affinity::pinned(CpuId(ap as u32)),
            ..TaskSpec::kernel_any()
        },
    );
    if !wait_for(1_000_000_000, || HOLD_STARTED.load(Ordering::Acquire)) {
        HOLD_RELEASE.store(true, Ordering::Release);
        reset_probes();
        return TestResult::Fail("the AP did not start the non-yielding task");
    }
    let_cool();
    crate::enable_work_stealing();

    // V first, so the pull has to step over an entry it may not take.
    crate::spawn_with_spec(
        Probe { slot: 2, parks: 0 },
        TaskSpec {
            affinity: Affinity::pinned(CpuId(ap as u32)),
            ..TaskSpec::kernel_any()
        },
    );
    crate::spawn_with_spec(Probe { slot: 1, parks: 0 }, any_cpu_preferring(ap));
    let woke = take_waker(0).map(Waker::wake).is_some();

    // This CPU is idle and allowed: act as an idle CPU would, alongside
    // whichever real APs are idle.
    let rescued = wait_for(PULL_BOUND_NS, || {
        let _ = crate::try_steal_one(me);
        crate::poll_one_round();
        polls(0) >= 2 && polls(1) >= 1
    });
    let held_throughout = !HOLD_DONE.load(Ordering::Acquire);
    let woken_cpu = PROBE_LAST_CPU[0].load(Ordering::Acquire);
    let enqueued_cpu = PROBE_LAST_CPU[1].load(Ordering::Acquire);
    let pinned_ran_early = polls(2) != 0;

    HOLD_RELEASE.store(true, Ordering::Release);
    let pinned_ran = wait_for(1_000_000_000, || polls(2) == 1);
    let pinned_cpu = PROBE_LAST_CPU[2].load(Ordering::Acquire);
    let released = wait_for(1_000_000_000, || HOLD_DONE.load(Ordering::Acquire));
    crate::disable_work_stealing();
    reset_probes();

    if !woke {
        return TestResult::Fail("parked probe published no waker");
    }
    if !released {
        return TestResult::Fail("the non-yielding task never finished");
    }
    if !rescued {
        return TestResult::Fail(
            "woken tasks stayed stranded behind a CPU in a non-yielding section",
        );
    }
    if !held_throughout {
        return TestResult::Fail("the AP left its non-yielding section before the check");
    }
    if woken_cpu == ap || enqueued_cpu == ap {
        return TestResult::Fail("a stranded task was reported as run by the held CPU");
    }
    if pinned_ran_early {
        return TestResult::Fail("a task pinned to the held CPU ran somewhere else");
    }
    if !pinned_ran || pinned_cpu != ap {
        return TestResult::Fail("the pinned task did not run on its CPU once it was free");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_stranded_wakes_run_on_another_cpu
);

/// The surplus rule covers staged wakes: a healthy CPU that is running nothing
/// keeps a single staged wake (it was kicked and will take it), gives one up
/// when it holds two, and gives its only one up while it is running a task.
fn smoke_scheduler_staged_pull_leaves_idle_cpu_its_only_wake() -> TestResult {
    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    stuck.set_running(false);
    let parked = [
        park_probe_on(0, 1, stuck.0, None),
        park_probe_on(1, 1, stuck.0, None),
    ];
    if parked.iter().any(Option::is_none) {
        stuck.release();
        return TestResult::Fail("could not park the probes on the stuck CPU");
    }
    let_cool();
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }
    // Healthy: it went round its loop just now.
    stuck.pass_scheduling_point();
    let took_only_wake = pull(stuck.0, me);
    if let Some(waker) = take_waker(1) {
        waker.wake();
    }
    let took_one_of_two = pull(stuck.0, me);
    // Healthy: it has been round its loop since a thief last looked.
    stuck.pass_scheduling_point();
    let took_last = pull(stuck.0, me);
    stuck.set_running(true);
    let took_from_running = pull(stuck.0, me);
    crate::poll_one_round();
    let ran = polls(0) + polls(1);
    stuck.release();
    if took_only_wake {
        return TestResult::Fail("an idle CPU's only staged wake was pulled from under it");
    }
    if !took_one_of_two || took_last {
        return TestResult::Fail("an idle CPU with two staged wakes did not give up exactly one");
    }
    if !took_from_running || ran != 4 {
        return TestResult::Fail("a busy CPU's only staged wake was not pulled and run");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_staged_pull_leaves_idle_cpu_its_only_wake
);

/// A parked task under a direct-handoff claim is being run by another task
/// on its home CPU. The pull must not take it; once the claim is released it
/// may.
fn smoke_scheduler_staged_pull_skips_direct_claimed_task() -> TestResult {
    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    let Some((id, cell)) = park_probe_on(0, 1, stuck.0, None) else {
        stuck.release();
        return TestResult::Fail("could not park the probe on the stuck CPU");
    };
    let_cool();
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }
    cell.direct_claimed.store(true, Ordering::SeqCst);
    let took_claimed = pull(stuck.0, me);
    let still_parked = parked_on(stuck.0, id);
    cell.direct_claimed.store(false, Ordering::SeqCst);
    let took_released = pull(stuck.0, me);
    crate::poll_one_round();
    let ran = polls(0);
    stuck.release();
    if took_claimed || !still_parked {
        return TestResult::Fail("a task under a direct-handoff claim was pulled");
    }
    if !took_released || ran != 2 {
        return TestResult::Fail("the task was not pulled once its claim was released");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_staged_pull_skips_direct_claimed_task
);

/// The cache-hot window applies to staged wakes as it does to queued ones: a
/// task that ran within the migration cost stays, and may go once it cools.
/// A CPU that is not rescheduling gives the warm cache back to nobody, so
/// there a hot task goes at once.
fn smoke_scheduler_staged_pull_respects_cache_hot_window() -> TestResult {
    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    let Some((_id, cell)) = park_probe_on(0, 1, stuck.0, None) else {
        stuck.release();
        return TestResult::Fail("could not park the probe on the stuck CPU");
    };
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }
    // Ran "just now", whatever the time the steps above took, on a CPU that
    // is still rescheduling.
    cell.last_run_cycles
        .store(narf_time::now_cycles(), Ordering::Release);
    stuck.pass_scheduling_point();
    let took_hot = pull(stuck.0, me);
    let_cool();
    stuck.pass_scheduling_point();
    let took_cold = pull(stuck.0, me);
    crate::poll_one_round();

    // The same, hot, on a CPU that has passed no scheduling point for longer
    // than the not-rescheduling threshold.
    let Some((_id, cell)) = park_probe_on(1, 1, stuck.0, None) else {
        stuck.release();
        return TestResult::Fail("could not park the second probe on the stuck CPU");
    };
    if let Some(waker) = take_waker(1) {
        waker.wake();
    }
    narf_time::busy_wait_cycles(narf_time::ns_to_cycles(STALL_WAIT_NS));
    cell.last_run_cycles
        .store(narf_time::now_cycles(), Ordering::Release);
    let took_hot_from_stalled = pull(stuck.0, me);
    stuck.release();
    if took_hot {
        return TestResult::Fail("a cache-hot staged wake was pulled");
    }
    if !took_cold {
        return TestResult::Fail("a staged wake was not pulled after it cooled");
    }
    if !took_hot_from_stalled {
        return TestResult::Fail("a hot wake was left on a CPU that is not rescheduling");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_staged_pull_respects_cache_hot_window
);

/// A pulled task that sleeps again on its new CPU is woken there directly:
/// nothing of it is left on the CPU it was pulled from.
fn smoke_scheduler_pulled_task_sleeps_and_wakes_on_new_cpu() -> TestResult {
    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    let Some((id, _cell)) = park_probe_on(0, 2, stuck.0, None) else {
        stuck.release();
        return TestResult::Fail("could not park the probe on the stuck CPU");
    };
    let_cool();
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }
    let pulled = pull(stuck.0, me);
    crate::poll_one_round();
    let reparked_here = parked_on(me, id);
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }
    let staged_here = staged_parked_wakes(me);
    crate::poll_one_round();
    let ran = polls(0);
    stuck.release();
    if !pulled || !reparked_here {
        return TestResult::Fail("pulled task did not run and sleep on the idle CPU");
    }
    if staged_here != 1 || ran != 3 {
        return TestResult::Fail("re-wake of a pulled task was not staged on its new CPU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_pulled_task_sleeps_and_wakes_on_new_cpu
);

/// `set_task_affinity` moves a parked task off a CPU its new mask excludes.
/// If the task had already been woken, the activation node goes with it.
fn smoke_scheduler_affinity_move_takes_staged_wake_along() -> TestResult {
    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    let Some((id, _cell)) = park_probe_on(0, 2, stuck.0, None) else {
        stuck.release();
        return TestResult::Fail("could not park the probe on the stuck CPU");
    };
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }
    let staged = staged_parked_wakes(stuck.0);
    let moved = crate::set_task_affinity(id, CpuSet::single(CpuId(me as u32))).is_ok();
    let left = staged_parked_wakes(stuck.0);
    crate::poll_one_round();
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }
    crate::poll_one_round();
    let ran = polls(0);
    stuck.release();
    if staged != 1 || !moved {
        return TestResult::Fail("could not move a woken parked task by affinity");
    }
    if left != 0 {
        return TestResult::Fail("affinity move left the task's activation node behind");
    }
    if ran != 3 {
        return TestResult::Fail("re-wake after an affinity move waited on the old CPU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_affinity_move_takes_staged_wake_along
);

/// The tick-side kick fires only when a tick with wakes staged has seen the
/// same scheduling-pass count before, and aims at the nearest halted online
/// CPU above the caller, wrapping.
fn smoke_scheduler_idle_balance_kick_decision() -> TestResult {
    use core::sync::atomic::AtomicU64;
    let seen = AtomicU64::new(0);
    if crate::staged_wakes_stalled(&seen, 0) {
        return TestResult::Fail("first tick with staged wakes kicked immediately");
    }
    if !crate::staged_wakes_stalled(&seen, 0) || !crate::staged_wakes_stalled(&seen, 0) {
        return TestResult::Fail("a tick period without a scheduling point did not kick");
    }
    if crate::staged_wakes_stalled(&seen, 1) {
        return TestResult::Fail("a CPU that passed a scheduling point still kicked");
    }
    if !crate::staged_wakes_stalled(&seen, 1) {
        return TestResult::Fail("a second stall was not noticed");
    }

    let online = 0b1011_0111u64;
    let all = |_: usize| true;
    if crate::idle_balance_kick_target(2, online, all) != Some(4) {
        return TestResult::Fail("kick did not go to the next online CPU");
    }
    if crate::idle_balance_kick_target(7, online, all) != Some(0) {
        return TestResult::Fail("kick did not wrap past the highest CPU");
    }
    if crate::idle_balance_kick_target(2, online, |cpu| cpu == 1) != Some(1) {
        return TestResult::Fail("kick did not skip CPUs that are not halted");
    }
    if crate::idle_balance_kick_target(2, online, |cpu| cpu == 2 || cpu == 3).is_some() {
        return TestResult::Fail("kick aimed at the caller or an offline CPU");
    }
    if crate::idle_balance_kick_target(63, (1u64 << 63) | 1, all) != Some(0) {
        return TestResult::Fail("kick from the last CPU index did not wrap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_idle_balance_kick_decision
);

const STRESS_FREE: usize = 20;
const STRESS_PINNED: usize = 4;
const STRESS_TASKS: usize = STRESS_FREE + STRESS_PINNED;
const STRESS_ROUNDS: usize = 60;
const STRESS_LIMIT_NS: u64 = 20_000_000_000;

static STRESS_WAKER: [IrqSafeSpinLock<Option<Waker>>; STRESS_TASKS] =
    [const { IrqSafeSpinLock::new(None) }; STRESS_TASKS];
static STRESS_IN_POLL: [AtomicBool; STRESS_TASKS] =
    [const { AtomicBool::new(false) }; STRESS_TASKS];
static STRESS_POLLS: [AtomicUsize; STRESS_TASKS] = [const { AtomicUsize::new(0) }; STRESS_TASKS];
static STRESS_DONE: AtomicUsize = AtomicUsize::new(0);
static STRESS_OVERLAP: AtomicUsize = AtomicUsize::new(0);
static STRESS_OFF_MASK: AtomicUsize = AtomicUsize::new(0);
static STRESS_MIGRATIONS: AtomicUsize = AtomicUsize::new(0);

/// Sleeps `STRESS_ROUNDS` times. Every poll checks that no other CPU is
/// polling the same task and that the CPU is one the task may run on, and
/// every few polls it holds its CPU without yielding so the wakes aimed there
/// pile up behind it.
struct StressTask {
    index: usize,
    left: usize,
    pin: Option<usize>,
    last_cpu: usize,
}

impl Future for StressTask {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let cpu = narf_lib::percpu::current_cpu();
        if STRESS_IN_POLL[this.index].swap(true, Ordering::SeqCst) {
            STRESS_OVERLAP.fetch_add(1, Ordering::Relaxed);
        }
        if this.pin.is_some_and(|pin| pin != cpu) {
            STRESS_OFF_MASK.fetch_add(1, Ordering::Relaxed);
        }
        if this.last_cpu != NO_CPU && this.last_cpu != cpu {
            STRESS_MIGRATIONS.fetch_add(1, Ordering::Relaxed);
        }
        this.last_cpu = cpu;
        let polled = STRESS_POLLS[this.index].fetch_add(1, Ordering::Relaxed);
        if polled % 4 == this.index % 4 {
            narf_time::busy_wait_cycles(narf_time::ns_to_cycles(1_500_000));
        }
        let finished = this.left == 0;
        if !finished {
            this.left -= 1;
            *STRESS_WAKER[this.index].lock() = Some(cx.waker().clone());
        }
        STRESS_IN_POLL[this.index].store(false, Ordering::SeqCst);
        if finished {
            STRESS_DONE.fetch_add(1, Ordering::Relaxed);
            return Poll::Ready(());
        }
        Poll::Pending
    }
}

/// Real CPUs, stealing on: tasks sleep and are woken from the boot CPU while
/// the CPUs they sleep on are regularly held in non-yielding polls, so wakes
/// are staged, drained by owners, pulled by idle CPUs and re-staged
/// concurrently. No wake may be lost, no task may be polled on two CPUs at
/// once, and a pinned task may only ever run on its CPU.
fn smoke_scheduler_staged_wake_stress() -> TestResult {
    reset_probes();
    let me = narf_lib::percpu::current_cpu();
    let live = narf_lib::smp::ever_online_bitmap() & narf_lib::smp::online_bitmap();
    let mut aps = [0usize; MAX_CPUS];
    let mut ap_count = 0;
    for cpu in 0..MAX_CPUS {
        if cpu != me && live & (1u64 << cpu) != 0 {
            aps[ap_count] = cpu;
            ap_count += 1;
        }
    }
    if ap_count < 2 {
        return TestResult::Skip("needs two APs that really came up");
    }
    // Crowd the tasks onto a few CPUs so that idle ones exist to pull.
    let homes = &aps[..ap_count.min(3)];
    for index in 0..STRESS_TASKS {
        *STRESS_WAKER[index].lock() = None;
        STRESS_IN_POLL[index].store(false, Ordering::Release);
        STRESS_POLLS[index].store(0, Ordering::Release);
    }
    STRESS_DONE.store(0, Ordering::Release);
    STRESS_OVERLAP.store(0, Ordering::Release);
    STRESS_OFF_MASK.store(0, Ordering::Release);
    STRESS_MIGRATIONS.store(0, Ordering::Release);
    let pulls_before = crate::__test_staged_pulls();

    crate::enable_work_stealing();
    for index in 0..STRESS_TASKS {
        let home = homes[index % homes.len()];
        let pin = (index >= STRESS_FREE).then_some(home);
        let spec = match pin {
            Some(cpu) => TaskSpec {
                affinity: Affinity::pinned(CpuId(cpu as u32)),
                ..TaskSpec::kernel_any()
            },
            None => any_cpu_preferring(home),
        };
        crate::spawn_with_spec(
            StressTask {
                index,
                left: STRESS_ROUNDS,
                pin,
                last_cpu: NO_CPU,
            },
            spec,
        );
    }

    // The boot CPU only wakes; it runs none of the tasks.
    let finished = wait_for(STRESS_LIMIT_NS, || {
        for waker in STRESS_WAKER.iter() {
            let waker = waker.lock().take();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
        narf_time::busy_wait_cycles(narf_time::ns_to_cycles(200_000));
        STRESS_DONE.load(Ordering::Acquire) == STRESS_TASKS
    });
    crate::disable_work_stealing();
    let short = (0..STRESS_TASKS)
        .any(|index| STRESS_POLLS[index].load(Ordering::Acquire) != STRESS_ROUNDS + 1);
    let overlap = STRESS_OVERLAP.load(Ordering::Acquire);
    let off_mask = STRESS_OFF_MASK.load(Ordering::Acquire);
    let migrations = STRESS_MIGRATIONS.load(Ordering::Acquire);
    let pulls = crate::__test_staged_pulls().wrapping_sub(pulls_before);
    reset_probes();

    if !finished {
        return TestResult::Fail("a wake was lost: not every task finished its rounds");
    }
    if short {
        return TestResult::Fail("a task was polled a number of times its wakes do not explain");
    }
    if overlap != 0 {
        return TestResult::Fail("a task was polled on two CPUs at once");
    }
    if off_mask != 0 {
        return TestResult::Fail("a pinned task ran outside its affinity mask");
    }
    if migrations == 0 {
        return TestResult::Fail("no task ever moved CPU: the stress did not exercise migration");
    }
    if pulls == 0 {
        return TestResult::Fail("no staged wake was ever pulled: the stress missed the new path");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler/strand", smoke_scheduler_staged_wake_stress);

/// The owner's drain gives up a node's claim before it takes the slot. A wake
/// that lands in between claims the cell and links it on the public list
/// again, and the drain then takes the slot out from under it. The node must
/// not stay behind: once the task has moved on and sleeps on another CPU, its
/// next wake would coalesce into a claim only the old home can release.
fn smoke_scheduler_owner_drain_takes_relinked_node_along() -> TestResult {
    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    let Some((id, cell)) = park_probe_on(0, 2, stuck.0, None) else {
        stuck.release();
        return TestResult::Fail("could not park the probe on the stuck CPU");
    };
    // A wake stages the node. A local direct handoff then runs the task and
    // puts it back to sleep without the owner draining: the wake is consumed
    // (`claim_direct_handoff_slot` clears the flag) and the node stays linked
    // (`release_direct_handoff_target` leaves it).
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }
    cell.flag.store(false, Ordering::SeqCst);

    // The owner's drain, stopped between its two halves.
    let batch = crate::take_parked_wake_batch(stuck.0);
    if batch.is_null() {
        stuck.release();
        return TestResult::Fail("wake of a parked task staged no node");
    }
    // SAFETY: a detached node carries the inbox's reference, which this takes
    // over exactly as `drain_parked_wakes` does.
    let node = unsafe { Arc::from_raw(batch.cast_const()) };
    let rest = crate::release_drained_wake(stuck.0, &node);
    // Another CPU wakes the task in that window. The claim is free and the
    // token still names the stuck CPU, so the cell goes back on its list.
    crate::make_waker(cell.clone()).wake_by_ref();
    let relinked = staged_parked_wakes(stuck.0);
    crate::activate_drained_wake(stuck.0, &node);
    drop(node);
    let taken = !parked_on(stuck.0, id);
    let left_linked = staged_parked_wakes(stuck.0);
    let claim_left = cell.activation_queued.load(Ordering::SeqCst);

    // The task is now runnable on the stuck CPU. An idle CPU takes it and
    // runs it, it sleeps there, and it is woken there.
    let_cool();
    let pulled = pull(stuck.0, me);
    crate::poll_one_round();
    let reparked_here = parked_on(me, id);
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }
    crate::poll_one_round();
    let ran = polls(0);
    stuck.release();
    if !rest.is_null() || relinked != 1 || !taken {
        return TestResult::Fail("could not stage a wake between the drain's release and its take");
    }
    if left_linked != 0 || claim_left {
        return TestResult::Fail("owner's drain took the slot and left its relinked node behind");
    }
    if !pulled || !reparked_here {
        return TestResult::Fail("activated task did not run and sleep on the idle CPU");
    }
    if ran != 3 {
        return TestResult::Fail("re-wake was swallowed by a node left on the task's old home");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_owner_drain_takes_relinked_node_along
);

/// Longer than any threshold a thief uses to call a CPU stalled.
const STALL_WAIT_NS: u64 = 3_000_000;

/// A CPU can be stuck outside a task poll: in deferred destructors, the slab
/// drain, the sleep pumps or the timer wheel, all of which run with no task
/// current. It looks idle, and an idle CPU keeps its last staged wake. It must
/// not keep it once it has passed no scheduling point for the not-rescheduling
/// threshold; a CPU that has just passed one keeps it.
fn smoke_scheduler_stalled_idle_cpu_gives_up_its_only_wake() -> TestResult {
    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    stuck.set_running(false);
    if park_probe_on(0, 1, stuck.0, None).is_none() {
        stuck.release();
        return TestResult::Fail("could not park the probe on the stuck CPU");
    }
    let_cool();
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }
    // Healthy: it went round its loop just now.
    stuck.pass_scheduling_point();
    let took_at_first_sight = pull(stuck.0, me);
    stuck.pass_scheduling_point();
    let took_from_healthy = pull(stuck.0, me);
    // Stalled: the same wake, no scheduling point since, and time.
    narf_time::busy_wait_cycles(narf_time::ns_to_cycles(STALL_WAIT_NS));
    let took_from_stalled = pull(stuck.0, me);
    crate::poll_one_round();
    let ran = polls(0);
    stuck.release();
    if took_at_first_sight || took_from_healthy {
        return TestResult::Fail("a healthy idle CPU's only staged wake was pulled");
    }
    if !took_from_stalled || ran != 2 {
        return TestResult::Fail(
            "the only staged wake of a CPU stalled outside a task poll was never pulled",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_stalled_idle_cpu_gives_up_its_only_wake
);

/// A stackful continuation that gives up its CPU inside a QSBR read section,
/// or with preemption disabled, is caught at the switch. The same yield with
/// neither held is not. Under `kernel-test` an unexpected violation panics;
/// this test arms the expectation, so its two are counted instead.
#[cfg(all(
    feature = "kernel-test",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn smoke_scheduler_park_with_cpu_local_state_is_caught() -> TestResult {
    use core::sync::atomic::AtomicU64;
    static YIELDS: AtomicUsize = AtomicUsize::new(0);
    static SEEN: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
    static DONE: AtomicBool = AtomicBool::new(false);

    reset_probes();
    YIELDS.store(0, Ordering::Release);
    DONE.store(false, Ordering::Release);
    let before = crate::stackful::park_violation_count();
    crate::stackful::__test_expect_park_violation(true);
    crate::spawn_stackful(async {
        let yielded = |held: usize| {
            if crate::stackful::cooperative_yield() {
                YIELDS.fetch_add(1, Ordering::AcqRel);
            }
            SEEN[held].store(crate::stackful::park_violation_count(), Ordering::Release);
        };
        yielded(0);
        {
            let guard = narf_rcu::pin();
            yielded(1);
            drop(guard);
        }
        {
            let pin = crate::preempt_disable();
            yielded(2);
            drop(pin);
        }
        DONE.store(true, Ordering::Release);
    });
    for _ in 0..64 {
        crate::poll_one_round();
        if DONE.load(Ordering::Acquire) {
            break;
        }
    }
    crate::stackful::__test_expect_park_violation(false);
    let finished = DONE.load(Ordering::Acquire);
    let yields = YIELDS.load(Ordering::Acquire);
    let seen = [
        SEEN[0].load(Ordering::Acquire).wrapping_sub(before),
        SEEN[1].load(Ordering::Acquire).wrapping_sub(before),
        SEEN[2].load(Ordering::Acquire).wrapping_sub(before),
    ];
    reset_probes();
    if !finished || yields != 3 {
        return TestResult::Fail("the stackful task did not yield three times and finish");
    }
    if seen[0] != 0 {
        return TestResult::Fail("a yield holding no CPU-local state was reported");
    }
    if seen[1] != 1 {
        return TestResult::Fail("a yield inside a QSBR read section was not caught");
    }
    if seen[2] != 2 {
        return TestResult::Fail("a yield with preemption disabled was not caught");
    }
    TestResult::Pass
}
#[cfg(all(
    feature = "kernel-test",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_park_with_cpu_local_state_is_caught
);

/// The tick-side kick is rationed and aimed. Within a stall it sends on
/// stalled ticks 1, 2, 4, 8, … while the staged count is unchanged and starts
/// over when it changes. It is aimed only at CPUs that may run something
/// staged: a wake pinned to the stalled CPU, or a node whose task has gone
/// back to sleep, asks for nobody.
fn smoke_scheduler_idle_balance_kick_is_aimed_and_rationed() -> TestResult {
    let mut state = 0u64;
    let mut sent = [false; 9];
    for tick in sent.iter_mut().skip(1) {
        let (next, due) = crate::staged_kick_backoff(state, 3);
        state = next;
        *tick = due;
    }
    if sent != [false, true, true, false, true, false, false, false, true] {
        return TestResult::Fail("kick did not back off to stalled ticks 1, 2, 4, 8");
    }
    let (state, on_change) = crate::staged_kick_backoff(state, 4);
    let (state, second) = crate::staged_kick_backoff(state, 4);
    let (_, third) = crate::staged_kick_backoff(state, 4);
    if !on_change || !second || third {
        return TestResult::Fail("a change in what is staged did not restart the back-off");
    }

    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    let stuck_bit = 1u64 << stuck.0;
    let pinned = Affinity::pinned(CpuId(stuck.0 as u32));
    if park_probe_on(0, 1, stuck.0, Some(pinned)).is_none() {
        stuck.release();
        return TestResult::Fail("could not park the pinned probe on the stuck CPU");
    }
    if let Some(waker) = take_waker(0) {
        waker.wake();
    }
    let for_pinned = crate::staged_pull_mask(stuck.0);

    let Some((_id, cell)) = park_probe_on(1, 1, stuck.0, None) else {
        stuck.release();
        return TestResult::Fail("could not park the probe on the stuck CPU");
    };
    if let Some(waker) = take_waker(1) {
        waker.wake();
    }
    // Its node stays linked, but the wake has been consumed.
    cell.flag.store(false, Ordering::SeqCst);
    let for_stale_node = crate::staged_pull_mask(stuck.0);

    crate::spawn_with_spec(Probe { slot: 2, parks: 0 }, any_cpu_preferring(me));
    let Some(slot) = crate::READY[me].lock().as_mut().and_then(|q| q.pop_front()) else {
        stuck.release();
        return TestResult::Fail("spawned probe not found on this CPU");
    };
    crate::enqueue_on(stuck.0, slot, TaskEnqueueReason::Requeued);
    let for_free_task = crate::staged_pull_mask(stuck.0);
    stuck.release();

    if for_pinned != 0 {
        return TestResult::Fail("a wake pinned to the stalled CPU asked another CPU to come");
    }
    if for_stale_node != 0 {
        return TestResult::Fail("a node whose task went back to sleep asked for a kick");
    }
    if for_free_task & (1u64 << me) == 0 || for_free_task & stuck_bit != 0 {
        return TestResult::Fail("a task any CPU may run did not ask the other CPUs to come");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_idle_balance_kick_is_aimed_and_rationed
);

/// One more than a pull judges in one visit, plus the task behind them.
const CROWD: usize = 34;

static CROWD_WAKER: [IrqSafeSpinLock<Option<Waker>>; CROWD] =
    [const { IrqSafeSpinLock::new(None) }; CROWD];
static CROWD_POLLS: [AtomicUsize; CROWD] = [const { AtomicUsize::new(0) }; CROWD];

/// Sleeps once, then finishes.
struct CrowdTask {
    index: usize,
    slept: bool,
}

impl Future for CrowdTask {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        CROWD_POLLS[this.index].fetch_add(1, Ordering::AcqRel);
        if this.slept {
            return Poll::Ready(());
        }
        this.slept = true;
        *CROWD_WAKER[this.index].lock() = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// A pull judges a bounded window of a victim's staged entries. Entries no
/// other CPU may take must not hide the ones behind them for as long as the
/// victim is stalled: a pull that finds nothing in its window starts the next
/// one further on. Checked in both holding places with 33 tasks pinned to the
/// stalled CPU in front of one that any CPU may run.
fn smoke_scheduler_staged_pull_window_moves_past_ineligible_entries() -> TestResult {
    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    let pinned = Affinity::pinned(CpuId(stuck.0 as u32));
    for index in 0..CROWD {
        *CROWD_WAKER[index].lock() = None;
        CROWD_POLLS[index].store(0, Ordering::Release);
    }

    // The wake inbox is scanned oldest first: the pinned tasks go in first,
    // the free one last.
    static INBOX_RAN: AtomicUsize = AtomicUsize::new(0);
    INBOX_RAN.store(0, Ordering::Release);
    for index in 0..CROWD {
        let id = crate::spawn_with_spec(
            async {
                INBOX_RAN.fetch_add(1, Ordering::AcqRel);
            },
            any_cpu_preferring(me),
        );
        let Some(mut slot) = crate::READY[me].lock().as_mut().and_then(|q| q.pop_front()) else {
            stuck.release();
            return TestResult::Fail("spawned task not found on this CPU");
        };
        if index != CROWD - 1 {
            slot.spec.affinity = pinned;
            slot.affinity_generation = crate::register_task_affinity(id, pinned, false);
        }
        crate::enqueue_on(stuck.0, slot, TaskEnqueueReason::Requeued);
    }
    let inbox_first = pull(stuck.0, me);
    let inbox_second = pull(stuck.0, me);
    let inbox_left = staged_enqueues(stuck.0);
    crate::poll_one_round();
    let inbox_ran = INBOX_RAN.load(Ordering::Acquire);
    // Clear the inbox so the parked half is judged on its own.
    crate::WAKE_INBOX[stuck.0].lock().clear();
    crate::WAKE_INBOX_LEN[stuck.0].store(0, Ordering::Release);

    // The parked-wake list is scanned newest first: the free task is woken
    // first, the pinned ones after it.
    let mut ids = [TaskId::NONE; CROWD];
    for (index, id) in ids.iter_mut().enumerate() {
        *id = crate::spawn_with_spec(
            CrowdTask {
                index,
                slept: false,
            },
            any_cpu_preferring(me),
        );
    }
    crate::poll_one_round();
    for (index, id) in ids.iter().enumerate() {
        let Some(mut entry) = crate::PARKED[me]
            .lock()
            .as_mut()
            .and_then(|parked| parked.remove(id))
        else {
            stuck.release();
            return TestResult::Fail("crowd task did not park on this CPU");
        };
        if index != 0 {
            entry.slot.spec.affinity = pinned;
            entry.slot.affinity_generation = crate::register_task_affinity(*id, pinned, false);
        }
        crate::enqueue_on(stuck.0, entry.slot, TaskEnqueueReason::Migrated);
    }
    let_cool();
    for waker in CROWD_WAKER.iter() {
        let waker = waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
    let staged = staged_parked_wakes(stuck.0);
    let parked_first = pull(stuck.0, me);
    let parked_second = pull(stuck.0, me);
    let parked_left = staged_parked_wakes(stuck.0);
    crate::poll_one_round();
    let free_polls = CROWD_POLLS[0].load(Ordering::Acquire);
    let pinned_polls: usize = CROWD_POLLS[1..]
        .iter()
        .map(|polls| polls.load(Ordering::Acquire))
        .sum();
    stuck.release();

    if inbox_first || !inbox_second || inbox_left != CROWD - 1 || inbox_ran != 1 {
        return TestResult::Fail(
            "wake-inbox pull did not move past a window of entries pinned to the victim",
        );
    }
    if staged != CROWD {
        return TestResult::Fail("crowd wakes were not all staged on the stuck CPU");
    }
    if parked_first || !parked_second || parked_left != CROWD - 1 || free_polls != 2 {
        return TestResult::Fail(
            "parked-wake pull did not move past a window of nodes pinned to the victim",
        );
    }
    if pinned_polls != CROWD - 1 {
        return TestResult::Fail("a task pinned to the stuck CPU ran somewhere else");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_staged_pull_window_moves_past_ineligible_entries
);

/// The floor counts tasks, not nodes. A node whose wake has been consumed
/// (its task ran under a direct handoff and went back to sleep) is not
/// runnable work, so a healthy idle CPU holding one real staged wake and one
/// such node still keeps the wake.
fn smoke_scheduler_staged_pull_floor_ignores_stale_nodes() -> TestResult {
    reset_probes();
    let Some(stuck) = StuckCpu::claim() else {
        return TestResult::Skip("every CPU index has been online");
    };
    let me = narf_lib::percpu::current_cpu();
    stuck.set_running(false);
    let (Some((_, stale)), Some(_)) = (
        park_probe_on(0, 1, stuck.0, None),
        park_probe_on(1, 1, stuck.0, None),
    ) else {
        stuck.release();
        return TestResult::Fail("could not park the probes on the stuck CPU");
    };
    let_cool();
    for slot in 0..2 {
        if let Some(waker) = take_waker(slot) {
            waker.wake();
        }
    }
    // Probe 0's wake was consumed without the owner draining its node.
    stale.flag.store(false, Ordering::SeqCst);
    let nodes = staged_parked_wakes(stuck.0);
    stuck.pass_scheduling_point();
    let took_from_idle = pull(stuck.0, me);
    stuck.set_running(true);
    let took_from_running = pull(stuck.0, me);
    crate::poll_one_round();
    let ran = (polls(0), polls(1));
    stuck.release();
    if nodes != 2 {
        return TestResult::Fail("both wakes should have staged a node");
    }
    if took_from_idle {
        return TestResult::Fail(
            "a stale node made an idle CPU's only real wake look like surplus",
        );
    }
    if !took_from_running || ran != (1, 2) {
        return TestResult::Fail("the real staged wake was not the one pulled from a busy CPU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_staged_pull_floor_ignores_stale_nodes
);

/// One search by this CPU under `strategy`, with the stuck CPU as the only
/// victim it may look at.
fn policy_search(strategy: &dyn crate::steal::StealStrategy, stuck: &StuckCpu) -> bool {
    let me = narf_lib::percpu::current_cpu();
    let victim = stuck.0 as u32;
    crate::try_steal_among(me, strategy, 1u64 << victim, |cpu| cpu == victim)
}

/// The opt-in steal policies choose victims from advisory hints: LLC-aware
/// search skips CPUs that report `Idle` or no runnable peer, and two-choice
/// sampling skips those and CPUs whose ready queue is empty. A CPU stuck in
/// executor maintenance reports `Idle` and has an empty ready queue while its
/// staged wakes wait for it. Each policy must still find it — on its own
/// sampling pass, not only on a two-choice full-coverage round — and pull the
/// wake once the CPU has been seen stalled.
fn smoke_scheduler_steal_policies_see_staged_wakes() -> TestResult {
    let llc = crate::steal::LlcAwareSteal::new();
    let pick2 = crate::steal::Pick2Steal::new();
    let policies: [(&dyn crate::steal::StealStrategy, &str); 2] = [
        (
            &llc,
            "LLC-aware search never pulled a stalled CPU's staged wake",
        ),
        (
            &pick2,
            "two-choice search never pulled a stalled CPU's staged wake",
        ),
    ];
    for (strategy, failure) in policies {
        reset_probes();
        let Some(stuck) = StuckCpu::claim() else {
            return TestResult::Skip("every CPU index has been online");
        };
        stuck.set_running(false);
        crate::policy::__test_set_cpu_state(CpuId(stuck.0 as u32), CpuState::Idle);
        let Some((id, _cell)) = park_probe_on(0, 1, stuck.0, None) else {
            stuck.release();
            return TestResult::Fail("could not park the probe on the stuck CPU");
        };
        let_cool();
        let Some(waker) = take_waker(0) else {
            stuck.release();
            return TestResult::Fail("probe published no waker");
        };
        waker.wake();
        // The first visit records the sighting; the CPU passes no scheduling
        // point, so a visit after the stall threshold may take its last wake.
        let early = policy_search(strategy, &stuck);
        narf_time::busy_wait_cycles(narf_time::ns_to_cycles(STALL_WAIT_NS));
        let pulled = early || policy_search(strategy, &stuck);
        crate::poll_one_round();
        let ran = polls(0);
        let left_behind = parked_on(stuck.0, id);
        stuck.release();
        if !pulled || left_behind || ran != 2 {
            return TestResult::Fail(failure);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_steal_policies_see_staged_wakes
);

/// Turn tickless idle on, as production boots, and let every AP pass through
/// one more idle entry so the ones that idle stop their periodic tick. The
/// kernel-test boot leaves it off. Returns whether a tickless clockevent is in
/// use: some AP's tick stopped.
fn enter_tickless_idle(aps: u64) -> bool {
    narf_time::set_nohz_idle_enabled(true);
    // An idle AP still ticks until its next tick, when it re-enters idle with
    // tickless on. Two tick periods (100 Hz) cover that.
    wait_for(1_000_000_000, || {
        (0..MAX_CPUS).any(|cpu| aps & (1u64 << cpu) != 0 && !narf_time::periodic_tick_wanted(cpu))
    })
}

/// Undo [`enter_tickless_idle`]: tickless off, and every AP dispatches once so
/// its periodic tick is running again before the next test.
fn leave_tickless_idle(aps: u64) {
    static WOKE: AtomicUsize = AtomicUsize::new(0);
    narf_time::set_nohz_idle_enabled(false);
    WOKE.store(0, Ordering::Release);
    let mut count = 0;
    for cpu in (0..MAX_CPUS).filter(|cpu| aps & (1u64 << cpu) != 0) {
        crate::spawn_with_spec(
            async {
                WOKE.fetch_add(1, Ordering::AcqRel);
            },
            TaskSpec {
                affinity: Affinity::pinned(CpuId(cpu as u32)),
                ..TaskSpec::kernel_any()
            },
        );
        count += 1;
    }
    let _ = wait_for(1_000_000_000, || WOKE.load(Ordering::Acquire) == count);
}

/// Every AP that really came up, as a mask.
fn live_aps() -> u64 {
    let me = narf_lib::percpu::current_cpu();
    narf_lib::smp::ever_online_bitmap() & narf_lib::smp::online_bitmap() & !(1u64 << me)
}

/// Spawn probe `slot` preferring `cpu` and wait until it has run once and is
/// parked there.
fn park_probe_on_real_cpu(slot: usize, cpu: usize) -> bool {
    crate::spawn_with_spec(Probe { slot, parks: 1 }, any_cpu_preferring(cpu));
    wait_for(1_000_000_000, || {
        polls(slot) == 1
            && PROBE_WAKER[slot]
                .lock()
                .as_ref()
                .and_then(crate::scheduler_wake_cell)
                .is_some_and(|cell| {
                    let token = cell.parked_location.load(Ordering::Acquire);
                    token != crate::NOT_PARKED && token % MAX_CPUS == cpu
                })
    })
}

/// How long a wake may take to reach a task on real CPUs before it counts as
/// stranded. Far below any periodic backstop, far above an IPI round trip
/// even under an emulator.
const WAKE_BOUND_NS: u64 = 100_000_000;

/// A wake aimed at a halted CPU wakes it with one reschedule IPI: under
/// tickless idle there is no tick to wait for, so the task runs only because
/// of the IPI the wake sent. A CPU the idle governor keeps polling instead of
/// halting gets none and still runs it at once.
fn smoke_scheduler_wake_to_idle_cpu_runs_by_ipi() -> TestResult {
    reset_probes();
    let me = narf_lib::percpu::current_cpu();
    let aps = live_aps();
    let Some(ap) = (0..MAX_CPUS).find(|cpu| aps & (1u64 << cpu) != 0) else {
        return TestResult::Skip("needs a second CPU that really came up");
    };
    if !enter_tickless_idle(aps) {
        leave_tickless_idle(aps);
        return TestResult::Skip("no AP stopped its tick: no tickless clockevent");
    }
    if !park_probe_on_real_cpu(0, ap) {
        leave_tickless_idle(aps);
        reset_probes();
        return TestResult::Fail("the AP did not run and park a task enqueued onto it");
    }
    let tickless = wait_for(1_000_000_000, || {
        crate::CPU_HALTED[ap].load(Ordering::SeqCst) && !narf_time::periodic_tick_wanted(ap)
    });
    let Some(waker) = take_waker(0) else {
        leave_tickless_idle(aps);
        reset_probes();
        return TestResult::Fail("probe published no waker");
    };
    let ipis = crate::__test_resched_ipis_sent(me);
    let halted_at_wake = crate::CPU_HALTED[ap].load(Ordering::SeqCst);
    waker.wake();
    let sent = crate::__test_resched_ipis_sent(me).wrapping_sub(ipis);
    let ran = wait_for(WAKE_BOUND_NS, || polls(0) == 2);
    let ran_on = PROBE_LAST_CPU[0].load(Ordering::Acquire);
    leave_tickless_idle(aps);
    reset_probes();
    if !tickless {
        return TestResult::Skip("the AP did not go tickless-idle");
    }
    if sent > 1 {
        return TestResult::Fail("a wake to an idle CPU sent more than one IPI");
    }
    // A CPU the idle governor keeps polling is not halted and needs no IPI
    // (Linux `TIF_POLLING_NRFLAG`); one seen halted just before the wake does.
    if sent == 0 && halted_at_wake {
        return TestResult::Fail("a wake to a CPU seen halted sent no IPI");
    }
    if !ran || ran_on != ap {
        return TestResult::Fail("a task woken on a halted CPU did not run there promptly");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_wake_to_idle_cpu_runs_by_ipi
);

/// An AP holds its CPU with interrupts masked, so it takes no IPI and no tick
/// and sends neither. Every other AP is idle. A task that last ran on the held
/// AP is woken, and another is enqueued onto it: both must run on another CPU
/// within a small bound, because the waker and the enqueuer moved them or
/// IPI'd an idle CPU to pull them — the held CPU's tick cannot have, and no
/// timer is involved. Each of the two operations sends at most one IPI.
#[cfg(feature = "kernel-test")]
fn smoke_scheduler_wake_behind_masked_cpu_runs_elsewhere() -> TestResult {
    static MASKED_STARTED: AtomicBool = AtomicBool::new(false);
    static MASKED_RELEASE: AtomicBool = AtomicBool::new(false);
    static MASKED_DONE: AtomicBool = AtomicBool::new(false);
    reset_probes();
    let me = narf_lib::percpu::current_cpu();
    let live = live_aps();
    let mut aps = (0..MAX_CPUS).filter(|cpu| live & (1u64 << cpu) != 0);
    let (Some(held), Some(_)) = (aps.next(), aps.next()) else {
        return TestResult::Skip("needs two APs that really came up");
    };
    if !enter_tickless_idle(live) {
        leave_tickless_idle(live);
        return TestResult::Skip("no AP stopped its tick: no tickless clockevent");
    }
    MASKED_STARTED.store(false, Ordering::Release);
    MASKED_RELEASE.store(false, Ordering::Release);
    MASKED_DONE.store(false, Ordering::Release);
    if !park_probe_on_real_cpu(0, held) {
        leave_tickless_idle(live);
        reset_probes();
        return TestResult::Fail("the AP did not run and park a task enqueued onto it");
    }
    // A plain future cannot be preempted; with interrupts masked the CPU
    // also takes no tick and no IPI.
    crate::spawn_with_spec(
        async {
            narf_lib::sync::without_interrupts(|| {
                MASKED_STARTED.store(true, Ordering::Release);
                wait_for(HOLD_LIMIT_NS, || MASKED_RELEASE.load(Ordering::Acquire));
            });
            MASKED_DONE.store(true, Ordering::Release);
        },
        TaskSpec {
            affinity: Affinity::pinned(CpuId(held as u32)),
            ..TaskSpec::kernel_any()
        },
    );
    if !wait_for(1_000_000_000, || MASKED_STARTED.load(Ordering::Acquire)) {
        MASKED_RELEASE.store(true, Ordering::Release);
        leave_tickless_idle(live);
        reset_probes();
        return TestResult::Fail("the AP did not start the masked section");
    }
    // Every other AP is idle with its tick stopped; nothing periodic will
    // come along and look at the held CPU's queues.
    let _ = wait_for(100_000_000, || {
        (0..MAX_CPUS).all(|cpu| {
            cpu == held
                || live & (1u64 << cpu) == 0
                || (crate::CPU_HALTED[cpu].load(Ordering::SeqCst)
                    && !narf_time::periodic_tick_wanted(cpu))
        })
    });
    crate::enable_work_stealing();
    let placements = crate::__test_wake_placements();

    // The wake: issued at once, while the held CPU is running a task.
    let woke = take_waker(0).map(|waker| {
        let ipis = crate::__test_resched_ipis_sent(me);
        waker.wake();
        crate::__test_resched_ipis_sent(me).wrapping_sub(ipis)
    });

    // The enqueue: once the held CPU has passed no scheduling point for longer
    // than the not-rescheduling threshold.
    narf_time::busy_wait_cycles(narf_time::ns_to_cycles(STALL_WAIT_NS));
    crate::spawn_with_spec(Probe { slot: 1, parks: 0 }, any_cpu_preferring(me));
    let slot = crate::READY[me].lock().as_mut().and_then(|q| q.pop_front());
    let enqueued = slot.map(|slot| {
        let ipis = crate::__test_resched_ipis_sent(me);
        crate::enqueue_on(held, slot, TaskEnqueueReason::Requeued);
        crate::__test_resched_ipis_sent(me).wrapping_sub(ipis)
    });

    // This CPU does not poll: only an AP can run either task.
    let ran = wait_for(WAKE_BOUND_NS, || polls(0) == 2 && polls(1) == 1);
    let held_throughout = !MASKED_DONE.load(Ordering::Acquire);
    let after = crate::__test_wake_placements();
    let woken_cpu = PROBE_LAST_CPU[0].load(Ordering::Acquire);
    let enqueued_cpu = PROBE_LAST_CPU[1].load(Ordering::Acquire);
    MASKED_RELEASE.store(true, Ordering::Release);
    let released = wait_for(1_000_000_000, || MASKED_DONE.load(Ordering::Acquire));
    crate::disable_work_stealing();
    leave_tickless_idle(live);
    reset_probes();

    let (Some(wake_ipis), Some(enqueue_ipis)) = (woke, enqueued) else {
        return TestResult::Fail("probe published no waker, or the spawned probe was not found");
    };
    if !released {
        return TestResult::Fail("the masked section never finished");
    }
    if !ran {
        return TestResult::Fail("a task stayed stranded behind a CPU with interrupts masked");
    }
    if !held_throughout {
        return TestResult::Fail("the AP left its masked section before the check");
    }
    if woken_cpu == held || enqueued_cpu == held || woken_cpu == me || enqueued_cpu == me {
        return TestResult::Fail("a task ran on a CPU that could not have run it");
    }
    if after.0 == placements.0 && after.1 == placements.1 {
        return TestResult::Fail("neither a wake-time move nor a pull kick happened");
    }
    if wake_ipis > 1 || enqueue_ipis > 1 {
        return TestResult::Fail("a single wake or enqueue sent more than one IPI");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "scheduler/strand",
    smoke_scheduler_wake_behind_masked_cpu_runs_elsewhere
);
