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
        Some(Self(cpu))
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
