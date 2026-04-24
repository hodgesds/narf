//! narf-scheduler — cooperative async executor.
//!
//! Spec: `scheduler/specification/spec.md`. Stage-1 subset per STAGE1.md
//! #10: single-CPU cooperative executor, intrusive-esque ready queue,
//! `spawn`, `yield_now`, `block_on`, no preemption.
//!
//! Stage 2 adds real per-task wakers (see ── Waker plumbing ──): a
//! Pending task whose waker has not fired since its last poll is
//! skipped on the next round, so futures driven by external signals
//! (IRQ handlers, IPC events) no longer cost a poll per loop iteration.
//! The halt-on-no-progress backstop is kept so self-waking futures
//! (today's `SleepUntil`, `yield_now`) still idle the CPU between
//! rounds until a hardware tick resumes us.
//!
//! Stage 3 adds CPU budgets, affinity types, and the scaffolding for
//! direct context transfer. Single-CPU reality keeps the work-stealing
//! and SMP pieces structural; what the executor *does* act on:
//! - `TaskSpec { affinity, budget, budget_cap }` on every spawn.
//! - A live `Cap<CpuBudget, Spend>`, when attached, is
//!   `check_live`-gated on every poll — revoke → task dropped next
//!   round.
//! - Per-task `BudgetAccount` accumulates measured poll cycles and
//!   ticks `overruns` when a poll blows the burst allowance.
//!
//! Non-goals still (Stage 4):
//! - Direct context transfer / time-slice donation fast path.
//! - Work stealing / multi-CPU run queues.
//! - PKRS save/restore at yield points.
//! - Fair-share enforcement (today's budget accounting is diagnostic).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod affinity;
pub mod budget;

pub use affinity::{Affinity, CpuId, CpuSet};
pub use budget::{BudgetAccount, CpuBudget, OverrunPolicy, ResourceBudget};

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use narf_capabilities::{Cap, Spend};
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::Instant;

/// A pinned boxed future representing one kernel task.
type Task = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Ready queue of runnable tasks. Stage 1 uses `VecDeque` for FIFO
/// fairness; Stage 3 upgrades to the intrusive doubly-linked structure
/// in `narf_lib::IntrusiveList` so spawn is allocation-free for the
/// queue itself (tasks are still boxed).
static READY: IrqSafeSpinLock<Option<VecDeque<TaskSlot>>> = IrqSafeSpinLock::new(None);

struct TaskSlot {
    task: Task,
    // Per-task "needs-repoll" flag set by the waker. The slot owns one
    // `Arc<AtomicBool>`; each handed-out `Waker` owns another clone, so
    // the flag outlives the slot if the future has stashed its waker.
    // The scheduler swaps this to `false` before polling; if the poll
    // returns `Pending` and nothing has re-set it, the slot is skipped
    // on subsequent rounds until a waker flips it back to `true`.
    awake: Arc<AtomicBool>,
    /// Stage-3 §3.3/§3.4 per-task metadata: affinity, CPU budget, the
    /// `Cap<CpuBudget, Spend>` that gates scheduling, and the running
    /// `BudgetAccount`.
    spec:    TaskSpec,
    account: BudgetAccount,
}

impl core::fmt::Debug for TaskSlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TaskSlot")
            .field("awake",   &self.awake.load(Ordering::Relaxed))
            .field("spec",    &self.spec)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

/// Per-task scheduling metadata — spec §3.3 + §3.4.
///
/// A `TaskSpec` with `budget_cap = None` behaves like a Stage-2 task:
/// always runnable, no accounting. Attaching a live
/// `Cap<CpuBudget, Spend>` makes the executor `check_live`-gate every
/// poll; revoking the cap takes the task off the scheduler in O(1) on
/// the next round.
#[derive(Copy, Clone, Debug, Default)]
pub struct TaskSpec {
    pub affinity:   Affinity,
    pub budget:     ResourceBudget,
    pub budget_cap: Option<Cap<CpuBudget, Spend>>,
}

impl TaskSpec {
    /// Default: any CPU, unthrottled, no cap gate. Matches the
    /// Stage-2 `spawn` behaviour byte-for-byte in the executor.
    pub const fn unthrottled() -> Self {
        Self {
            affinity:   Affinity::any(),
            budget:     ResourceBudget::unthrottled(),
            budget_cap: None,
        }
    }

    /// Budgeted spec: charge every poll against `budget`, and
    /// `check_live` the cap each round.
    pub const fn budgeted(budget: ResourceBudget, cap: Cap<CpuBudget, Spend>) -> Self {
        Self {
            affinity:   Affinity::any(),
            budget,
            budget_cap: Some(cap),
        }
    }
}

/// Call once at boot before spawning anything. Stage 3 promotes this to
/// a per-CPU `Executor` struct; Stages 1–2 are single-CPU so a global
/// works.
pub fn init() {
    let mut q = READY.lock();
    *q = Some(VecDeque::new());
}

/// Queue a new task on the ready queue. Requires `init()` to have run.
pub fn spawn<F: Future<Output = ()> + Send + 'static>(f: F) {
    spawn_with_spec(f, TaskSpec::unthrottled());
}

/// Queue a new task with a Stage-3 `TaskSpec` attached. A `None`
/// `budget_cap` makes the task always-runnable; a live cap is
/// epoch-checked on every round and the task drops when the cap is
/// revoked.
pub fn spawn_with_spec<F>(f: F, spec: TaskSpec)
where
    F: Future<Output = ()> + Send + 'static,
{
    let slot = TaskSlot {
        task:    Box::pin(f),
        awake:   Arc::new(AtomicBool::new(true)),
        spec,
        account: BudgetAccount::new(),
    };
    let mut q = READY.lock();
    q.as_mut().expect("scheduler::spawn before init").push_back(slot);
}

/// Shorthand: spawn a task with a budget cap + the default everywhere-
/// affinity.
pub fn spawn_budgeted<F>(f: F, budget: ResourceBudget, cap: Cap<CpuBudget, Spend>)
where
    F: Future<Output = ()> + Send + 'static,
{
    spawn_with_spec(f, TaskSpec::budgeted(budget, cap));
}

// ── Waker plumbing ──────────────────────────────────────────────────
//
// Each task owns an `Arc<AtomicBool>` awake flag. A `Waker` is just an
// `Arc<AtomicBool>` whose `wake`/`wake_by_ref` store `true` into the
// flag. The vtable's `clone`/`drop` operate the Arc refcount, so a
// future is free to stash its waker (as IRQ-driven drivers will want
// to) and have it outlive the original `TaskSlot` view.

const TASK_VTABLE: RawWakerVTable = RawWakerVTable::new(
    clone_raw,
    wake_raw,
    wake_by_ref_raw,
    drop_raw,
);

unsafe fn clone_raw(data: *const ()) -> RawWaker {
    // Reconstitute, clone, restore the original — net +1 refcount.
    // SAFETY: `data` was produced by `Arc::into_raw` in `make_waker`
    // or a prior `clone_raw`, and the Arc is still live.
    let arc = unsafe { Arc::<AtomicBool>::from_raw(data as *const AtomicBool) };
    let cloned = arc.clone();
    let _ = Arc::into_raw(arc);
    RawWaker::new(Arc::into_raw(cloned) as *const (), &TASK_VTABLE)
}

unsafe fn wake_raw(data: *const ()) {
    // wake-by-value: consume the Arc.
    // SAFETY: same as clone_raw; we own the refcount handed to us.
    let arc = unsafe { Arc::<AtomicBool>::from_raw(data as *const AtomicBool) };
    arc.store(true, Ordering::Release);
}

unsafe fn wake_by_ref_raw(data: *const ()) {
    // SAFETY: caller still holds a live Waker (hence a live Arc), so
    // the AtomicBool behind `data` is valid for the duration of this
    // call.
    let ptr = data as *const AtomicBool;
    unsafe { (*ptr).store(true, Ordering::Release); }
}

unsafe fn drop_raw(data: *const ()) {
    // SAFETY: reconstructing consumes the refcount owned by this waker.
    unsafe { drop(Arc::<AtomicBool>::from_raw(data as *const AtomicBool)); }
}

fn make_waker(flag: Arc<AtomicBool>) -> Waker {
    let raw = Arc::into_raw(flag) as *const ();
    // SAFETY: vtable functions are matched to the `Arc<AtomicBool>`
    // representation encoded in `raw`.
    unsafe { Waker::from_raw(RawWaker::new(raw, &TASK_VTABLE)) }
}

/// Run the ready queue until it's empty.
///
/// Strategy: round through every task in the queue; each slot is polled
/// iff its awake flag is set. The flag is cleared (`swap(false)`) before
/// the poll so a waker that fires *during* the poll leaves the task
/// marked for re-poll on the next round.
///
/// After a full round where **no** task went `Ready`, halt the CPU via
/// `arch::halt_until_irq`. An external interrupt (timer or otherwise)
/// will wake us, and the next round either makes progress (a deadline
/// met, waker fired) or we halt again. The halt is kept even though
/// wakers are now per-task because today's self-waking futures
/// (`SleepUntil`, `yield_now`) would otherwise spin the CPU between
/// clock ticks — they re-set their own awake flag before returning
/// Pending, so the "any awake?" check would always pass.
pub fn run_until_empty() {
    loop {
        // Snapshot queue length. We'll visit each task at most once per
        // round; spawns during the round land at the back and get
        // visited on the NEXT round.
        let round_len = {
            let q = READY.lock();
            q.as_ref().expect("scheduler::run_until_empty before init").len()
        };
        if round_len == 0 { return; }

        let mut ready_this_round: usize = 0;

        for _ in 0..round_len {
            // Pop; if empty, break (can happen if a task was cancelled).
            let mut slot = {
                let mut q = READY.lock();
                match q.as_mut().unwrap().pop_front() {
                    Some(t) => t,
                    None    => break,
                }
            };

            // Budget cap check — a revoked Cap<CpuBudget, Spend>
            // drops the task O(1). No cap attached → skip the check.
            if let Some(ref cap) = slot.spec.budget_cap {
                if cap.check_live().is_err() {
                    // Task is off the scheduler: drop the slot.
                    continue;
                }
            }

            // Skip if no waker has fired since the last poll. The slot
            // stays in the queue, waiting for an external signal.
            if !slot.awake.swap(false, Ordering::Acquire) {
                let mut q = READY.lock();
                q.as_mut().unwrap().push_back(slot);
                continue;
            }

            let waker = make_waker(slot.awake.clone());
            let mut ctx = Context::from_waker(&waker);
            let start = Instant::now();
            let poll_result = slot.task.as_mut().poll(&mut ctx);
            let elapsed = Instant::now().cycles_since(start);
            slot.account.charge(elapsed, &slot.spec.budget);

            // Announce a QSBR quiescent state: the task has yielded
            // back to the executor and holds no RCU read-guards across
            // the poll boundary (per rcu/ §3.7, read-guards may not
            // span awaits). Every poll return is therefore a grace-
            // period tick for this CPU.
            narf_rcu::report_quiescent();

            match poll_result {
                Poll::Ready(()) => { ready_this_round += 1; /* drop slot */ }
                Poll::Pending   => {
                    let mut q = READY.lock();
                    q.as_mut().unwrap().push_back(slot);
                }
            }
        }

        if ready_this_round == 0 {
            narf_arch::halt_until_irq();
        }
    }
}

/// Tiny convenience: Future that returns Pending once, then Ready.
/// `block_on`-equivalent `yield` point for cooperative tasks that just
/// want to give the executor a chance to run peers.
#[derive(Debug)]
pub struct YieldNow { yielded: bool }

impl Future for YieldNow {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.yielded { Poll::Ready(()) }
        else {
            this.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

pub fn yield_now() -> YieldNow { YieldNow { yielded: false } }
