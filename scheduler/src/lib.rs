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
pub mod cpu_lifecycle;
pub mod priority;

pub use affinity::{Affinity, CpuId, CpuSet};
pub use budget::{BudgetAccount, CpuBudget, OverrunPolicy, ResourceBudget};
pub use cpu_lifecycle::{cpu_bring_up, cpu_online, cpu_take_offline, online_count, CpuLifecycle, HotPlugError};
pub use priority::{Priority, SchedClass, SmtSharePolicy};

// re-export the Invoke rights marker for callers who need to type a
// donation cap — saves one import line at every call site.
pub use narf_capabilities::Invoke;

// Re-export user-mode primitives so downstream crates that already
// depend on `narf-scheduler` (notably `narf-userspace`, where user
// tasks live as scheduler futures) can name them without taking a
// fresh direct dep on `narf-arch` — adding a fresh direct dep
// perturbs link-time test-registration ordering enough to expose
// latent flakes in the e2e suite. The transitive dep already
// exists (`narf-scheduler` → `narf-arch`); this just exposes it.
#[cfg(target_arch = "x86_64")]
pub use narf_arch::x86_64::{
    enter_user_mode, enter_user_mode_resume, longjmp, set_user_fs_base,
    setjmp, JmpBuf, UserState, USER_RFLAGS,
};

// `halt_forever` is the right "I should never reach here" sink for
// the user-task hook fast-paths in `narf-userspace`. Re-exported
// for the same reason the user-mode primitives are: avoids a fresh
// direct `narf-arch` dep on `narf-userspace` that re-perturbs link
// ordering.
pub use narf_arch::halt_forever;

// Re-export the time crate so `narf-userspace` (already a downstream
// of `narf-scheduler`) can read the monotonic clock without taking a
// direct `narf-time` dep — same dep-cycle / link-ordering rationale
// as the `narf-arch` re-export above.
pub use narf_time;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use core::sync::atomic::AtomicU64;

use narf_capabilities::{Cap, CapKind, CapType, Spend};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::AddressSpace;
use narf_time::Instant;

/// A pinned boxed future representing one kernel task.
type BoxedTask = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Ready queue of runnable tasks. Stage 1 uses `VecDeque` for FIFO
/// fairness; Stage 3 upgrades to the intrusive doubly-linked structure
/// in `narf_lib::IntrusiveList` so spawn is allocation-free for the
/// queue itself (tasks are still boxed).
static READY: IrqSafeSpinLock<Option<VecDeque<TaskSlot>>> = IrqSafeSpinLock::new(None);

/// Monotonic task identifier. Minted at `spawn` time. `0` is reserved
/// as "no task"; the first spawn gets `TaskId(1)`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u64);

impl TaskId {
    pub const NONE: TaskId = TaskId(0);

    #[inline]
    pub const fn raw(self) -> u64 { self.0 }
}

/// Cap-type marker for `Cap<Task, R>`. `Cap<Task, Invoke>` is the
/// `scheduler/` spec §3.3 donation-authority type: the caller proves
/// prior permission to donate its time slice to the target.
#[derive(Copy, Clone, Debug)]
pub struct Task;

impl CapType for Task {
    const KIND: CapKind = CapKind::Task;
}

static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

/// Id of the task currently being polled by the executor, or
/// `TaskId::NONE` when the executor is between polls. Syscall
/// handlers read this to identify the caller; SMP bring-up will
/// migrate to a per-CPU slot read via `gs:[offset]`.
static CURRENT_TASK: AtomicU64 = AtomicU64::new(0);

/// Read the currently-polling task's id. Returns `TaskId::NONE`
/// when called outside any `poll` context (e.g. from boot or
/// between rounds).
#[inline]
pub fn current_task_id() -> TaskId {
    TaskId(CURRENT_TASK.load(Ordering::Acquire))
}

struct TaskSlot {
    task: BoxedTask,
    // Per-task "needs-repoll" flag set by the waker. The slot owns one
    // `Arc<AtomicBool>`; each handed-out `Waker` owns another clone, so
    // the flag outlives the slot if the future has stashed its waker.
    // The scheduler swaps this to `false` before polling; if the poll
    // returns `Pending` and nothing has re-set it, the slot is skipped
    // on subsequent rounds until a waker flips it back to `true`.
    awake: Arc<AtomicBool>,
    /// Monotonic identifier stamped at spawn time so `donate_to` has
    /// a stable handle into the ready queue.
    id:      TaskId,
    /// Stage-3 §3.3/§3.4 per-task metadata: affinity, CPU budget, the
    /// `Cap<CpuBudget, Spend>` that gates scheduling, and the running
    /// `BudgetAccount`.
    spec:    TaskSpec,
    account: BudgetAccount,
    /// Optional per-process address space (Stage 4). `None` for
    /// kernel-only tasks; `Some` for a user-mode task that shares
    /// the AS with its process peers. Held as `Arc` so tasks within
    /// one process share one AS without copying.
    addr_space: Option<Arc<AddressSpace>>,
}

impl core::fmt::Debug for TaskSlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TaskSlot")
            .field("id",      &self.id)
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
    /// Scheduling class (Stage-4). Stage-3 executor ignores this;
    /// SMP dispatch consumes it once the deadline class lands.
    pub class:      SchedClass,
    /// Nice-style priority within `class`.
    pub priority:   Priority,
    /// SMT-sibling co-scheduling preference.
    pub smt:        SmtSharePolicy,
}

impl TaskSpec {
    /// Default: any CPU, unthrottled, no cap gate. Matches the
    /// Stage-2 `spawn` behaviour byte-for-byte in the executor.
    pub const fn unthrottled() -> Self {
        Self {
            affinity:   Affinity::any(),
            budget:     ResourceBudget::unthrottled(),
            budget_cap: None,
            class:      SchedClass::Normal,
            priority:   Priority::NORMAL,
            smt:        SmtSharePolicy::Avoid,
        }
    }

    /// Budgeted spec: charge every poll against `budget`, and
    /// `check_live` the cap each round.
    pub const fn budgeted(budget: ResourceBudget, cap: Cap<CpuBudget, Spend>) -> Self {
        Self {
            affinity:   Affinity::any(),
            budget,
            budget_cap: Some(cap),
            class:      SchedClass::Normal,
            priority:   Priority::NORMAL,
            smt:        SmtSharePolicy::Avoid,
        }
    }

    /// Shorthand: realtime task with an absolute cycle deadline.
    pub const fn realtime(deadline_cycles: u64) -> Self {
        Self {
            affinity:   Affinity::any(),
            budget:     ResourceBudget {
                share_ppm:       1_000_000,
                burst_cycles:    u64::MAX,
                deadline_cycles: Some(deadline_cycles),
                policy:          OverrunPolicy::Ignore,
            },
            budget_cap: None,
            class:      SchedClass::RealTime,
            priority:   Priority::HIGH,
            smt:        SmtSharePolicy::Avoid,
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
///
/// Returns the `TaskId` stamped on the newly-created task — `donate_to`
/// and future `cancel`/`join` primitives name the task by this id.
pub fn spawn<F: Future<Output = ()> + Send + 'static>(f: F) -> TaskId {
    spawn_with_spec(f, TaskSpec::unthrottled())
}

/// Queue a new task with a Stage-3 `TaskSpec` attached. A `None`
/// `budget_cap` makes the task always-runnable; a live cap is
/// epoch-checked on every round and the task drops when the cap is
/// revoked.
pub fn spawn_with_spec<F>(f: F, spec: TaskSpec) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    let id = TaskId(NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed));
    let slot = TaskSlot {
        task:    Box::pin(f),
        awake:   Arc::new(AtomicBool::new(true)),
        id,
        spec,
        addr_space: None,
        account: BudgetAccount::new(),
    };
    let mut q = READY.lock();
    q.as_mut().expect("scheduler::spawn before init").push_back(slot);
    id
}

/// Shorthand: spawn a task with a budget cap + the default everywhere-
/// affinity.
pub fn spawn_budgeted<F>(f: F, budget: ResourceBudget, cap: Cap<CpuBudget, Spend>) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    spawn_with_spec(f, TaskSpec::budgeted(budget, cap))
}

/// Spawn a user-mode task carrying its own address space. Every
/// poll of the task's future is preceded by
/// `addr_space.activate()` — the Stage-4 arch backend will make
/// this a real `MOV CR3` / `TTBR0_EL1` store. Until that lands
/// `activate()` returns `NotImplemented` and the executor logs +
/// proceeds (user code would trap, but the shape is exercised).
pub fn spawn_user<F>(f: F, spec: TaskSpec, addr_space: Arc<AddressSpace>) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    let id = TaskId(NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed));
    let slot = TaskSlot {
        task:    Box::pin(f),
        awake:   Arc::new(AtomicBool::new(true)),
        id,
        spec,
        addr_space: Some(addr_space),
        account: BudgetAccount::new(),
    };
    let mut q = READY.lock();
    q.as_mut().expect("scheduler::spawn_user before init").push_back(slot);
    id
}

/// Look up the address space attached to `id`, if any. The returned
/// `Arc` keeps the AS alive even if the task drops immediately —
/// callers holding it observe a consistent snapshot.
pub fn address_space_of(id: TaskId) -> Option<Arc<AddressSpace>> {
    let q = READY.lock();
    q.as_ref()?.iter().find(|s| s.id == id).and_then(|s| s.addr_space.clone())
}

/// Errors `donate_to` can return.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DonateError {
    /// Caller's donation authority was revoked.
    AuthorityRevoked,
    /// No task with the named id is currently on the ready queue.
    /// Target may have completed or never existed.
    TargetNotFound,
    /// Scheduler is not initialised.
    NotReady,
}

/// Direct time-slice donation: cap-gated reorder that moves `target`
/// to the head of the ready queue so the next dispatch round services
/// it ahead of its queue position. Matches the spec's §3.3 donation
/// surface for the single-CPU executor. The SMP fast-path (save caller
/// state, restore callee's domain, branch directly into the callee)
/// is Stage-4 work — this Stage-3 form is correct but not performant.
pub fn donate_to(target: TaskId, cap: &Cap<Task, Invoke>) -> Result<(), DonateError> {
    cap.check_live().map_err(|_| DonateError::AuthorityRevoked)?;
    let mut q = READY.lock();
    let ready = q.as_mut().ok_or(DonateError::NotReady)?;
    let pos = match ready.iter().position(|s| s.id == target) {
        Some(p) => p,
        None    => return Err(DonateError::TargetNotFound),
    };
    if pos != 0 {
        let slot = ready.remove(pos).unwrap();
        // Force-wake the donee so the executor doesn't skip it on the
        // next round if its waker hasn't fired — donation is by
        // definition "let me pick this task even though you wouldn't
        // normally have chosen it".
        slot.awake.store(true, Ordering::Release);
        ready.push_front(slot);
    }
    Ok(())
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

            // Stage-4: if the task owns an address space, activate it
            // before polling so user-mode accesses land in the right
            // low-half mappings. Today the arch backend isn't wired;
            // `activate()` returns `NotImplemented` and we ignore the
            // error — user tasks would trap, but kernel-only tasks
            // are unaffected.
            if let Some(ref a) = slot.addr_space {
                let _ = a.activate();
            }

            let waker = make_waker(slot.awake.clone());
            let mut ctx = Context::from_waker(&waker);
            let start = Instant::now();
            // Publish this slot's id as the currently-polling task
            // so syscall handlers + introspection can identify the
            // caller. Cleared after the poll so async code that
            // defers via `.await` doesn't leak the id across yield
            // points (the next round's task will re-publish).
            CURRENT_TASK.store(slot.id.raw(), Ordering::Release);
            let poll_result = slot.task.as_mut().poll(&mut ctx);
            CURRENT_TASK.store(0, Ordering::Release);
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
