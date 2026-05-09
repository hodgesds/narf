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
//! Stage 4 adds per-CPU run queues + opt-in work stealing. Each CPU
//! owns one slot of `READY: [_; MAX_CPUS]`; `spawn` routes by the
//! task's `affinity.preferred` (when online) or the current CPU. APs
//! enter `run_forever` after bring-up and drain their own queue;
//! `enable_work_stealing()` lets idle CPUs steal from siblings.
//! Off by default so the BSP-only test harness sees stable single-
//! CPU FIFO ordering.
//!
//! Non-goals still (later waves):
//! - Direct context transfer / time-slice donation fast path.
//! - PKRS save/restore at yield points.
//! - Fair-share enforcement (today's budget accounting is diagnostic).
//! - NUMA-aware steal targeting.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod affinity;
pub mod budget;
pub mod cpu_lifecycle;
pub mod priority;

mod tests;

pub use affinity::{Affinity, CpuId, CpuSet};
pub use budget::{BudgetAccount, CpuBudget, OverrunPolicy, ResourceBudget};
pub use cpu_lifecycle::{
    cpu_bring_up, cpu_online, cpu_take_offline, online_count, CpuLifecycle, HotPlugError,
};
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
    enter_user_mode, enter_user_mode_resume, longjmp, set_user_fs_base, setjmp, JmpBuf, UserState,
    USER_RFLAGS,
};

#[cfg(target_arch = "aarch64")]
pub use narf_arch::aarch64::{
    enter_user_mode, enter_user_mode_resume, longjmp, set_user_tls_base, setjmp, JmpBuf,
    UserState, USER_SPSR,
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

/// Per-CPU ready queues. Each CPU owns its own `VecDeque<TaskSlot>`;
/// `spawn` enqueues onto the CPU named by the task's affinity hint
/// (or the current CPU if no hint). `run_until_empty` drains the
/// caller's queue then attempts to steal one task from another CPU's
/// queue. With single-CPU configurations only index 0 is exercised,
/// matching pre-SMP behaviour byte-for-byte.
const NEW_QUEUE: IrqSafeSpinLock<Option<VecDeque<TaskSlot>>> = IrqSafeSpinLock::new(None);
static READY: [IrqSafeSpinLock<Option<VecDeque<TaskSlot>>>; narf_lib::percpu::MAX_CPUS] =
    [NEW_QUEUE; narf_lib::percpu::MAX_CPUS];

/// Monotonic task identifier. Minted at `spawn` time. `0` is reserved
/// as "no task"; the first spawn gets `TaskId(1)`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u64);

impl TaskId {
    pub const NONE: TaskId = TaskId(0);

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
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

/// Master switch for cross-CPU work stealing. Off by default so the
/// BSP-only test harness sees stable single-CPU FIFO semantics. Boot
/// code (or a runtime toggle) flips it on once the system is past
/// the sequential setup phase, after which APs in `run_forever`
/// drain their own queue first and steal from siblings only when
/// idle.
static STEAL_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable cross-CPU work stealing on this kernel. Callable from boot
/// once the BSP has finished publishing its initial spawn batch and
/// is ready to share work with online APs.
pub fn enable_work_stealing() {
    STEAL_ENABLED.store(true, Ordering::Release);
}

/// Disable work stealing. The toggle is process-wide; useful for
/// tests that need the single-CPU FIFO invariant back.
pub fn disable_work_stealing() {
    STEAL_ENABLED.store(false, Ordering::Release);
}

/// Id of the task currently being polled by the executor, or
/// `TaskId::NONE` when the executor is between polls. Syscall
/// handlers read this to identify the caller; SMP bring-up will
/// migrate to a per-CPU slot read via `gs:[offset]`.
static CURRENT_TASK: AtomicU64 = AtomicU64::new(0);

/// Address space of the currently-polling task — published before
/// `poll` so syscall handlers can resolve it without searching the
/// run-queue (the slot has been popped and isn't visible to
/// `address_space_of` during the poll body). Cleared on the way
/// out. Lock-protected because boot establishes a kernel-only
/// thread of control before any user task spawns; subsequent
/// reads are infrequent (one per syscall) and writes are once per
/// poll, so the lock cost is negligible.
static ACTIVE_USER_AS: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Read the currently-polling task's id. Returns `TaskId::NONE`
/// when called outside any `poll` context (e.g. from boot or
/// between rounds).
#[inline]
pub fn current_task_id() -> TaskId {
    TaskId(CURRENT_TASK.load(Ordering::Acquire))
}

/// Resolve the address space of the currently-polling task. This
/// is the syscall-side companion to `address_space_of` that works
/// during a poll body (when the slot has been popped from the
/// run-queue and is no longer findable by id). Returns `None`
/// when the active task is kernel-only (no AS) or the executor
/// isn't currently polling.
pub fn current_address_space() -> Option<Arc<AddressSpace>> {
    ACTIVE_USER_AS.lock().clone()
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
    id: TaskId,
    /// Stage-3 §3.3/§3.4 per-task metadata: affinity, CPU budget, the
    /// `Cap<CpuBudget, Spend>` that gates scheduling, and the running
    /// `BudgetAccount`.
    spec: TaskSpec,
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
            .field("id", &self.id)
            .field("awake", &self.awake.load(Ordering::Relaxed))
            .field("spec", &self.spec)
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
    pub affinity: Affinity,
    pub budget: ResourceBudget,
    pub budget_cap: Option<Cap<CpuBudget, Spend>>,
    /// Scheduling class (Stage-4). Stage-3 executor ignores this;
    /// SMP dispatch consumes it once the deadline class lands.
    pub class: SchedClass,
    /// Nice-style priority within `class`.
    pub priority: Priority,
    /// SMT-sibling co-scheduling preference.
    pub smt: SmtSharePolicy,
}

impl TaskSpec {
    /// Default: any CPU, unthrottled, no cap gate. Matches the
    /// Stage-2 `spawn` behaviour byte-for-byte in the executor.
    pub const fn unthrottled() -> Self {
        Self {
            affinity: Affinity::any(),
            budget: ResourceBudget::unthrottled(),
            budget_cap: None,
            class: SchedClass::Normal,
            priority: Priority::NORMAL,
            smt: SmtSharePolicy::Avoid,
        }
    }

    /// Budgeted spec: charge every poll against `budget`, and
    /// `check_live` the cap each round.
    pub const fn budgeted(budget: ResourceBudget, cap: Cap<CpuBudget, Spend>) -> Self {
        Self {
            affinity: Affinity::any(),
            budget,
            budget_cap: Some(cap),
            class: SchedClass::Normal,
            priority: Priority::NORMAL,
            smt: SmtSharePolicy::Avoid,
        }
    }

    /// Shorthand: realtime task with an absolute cycle deadline.
    pub const fn realtime(deadline_cycles: u64) -> Self {
        Self {
            affinity: Affinity::any(),
            budget: ResourceBudget {
                share_ppm: 1_000_000,
                burst_cycles: u64::MAX,
                deadline_cycles: Some(deadline_cycles),
                policy: OverrunPolicy::Ignore,
            },
            budget_cap: None,
            class: SchedClass::RealTime,
            priority: Priority::HIGH,
            smt: SmtSharePolicy::Avoid,
        }
    }
}

/// Call once at boot before spawning anything. Initialises every
/// per-CPU ready queue. Idempotent within a test run: re-init drops
/// any tasks left over from a prior round, which is what test setup
/// wants.
///
/// **Smoke tests using `spawn` + `run_until_empty` MUST call
/// `init()` first.** The boot-time queue carries long-lived
/// kernel async tasks (USB HID supervisor, FB drain, scheduler
/// step pump, etc.) that are parked indefinitely on
/// `sleep_cycles` / `wait_for_irq`. Without re-initialising the
/// queue, a smoke's `run_until_empty` would try to drive those
/// zombies too — round 1 polls them all (each returns Pending),
/// `ready_this_round = 0`, `local_empty = false` → executor
/// hits `halt_until_irq` and waits forever for an IRQ that
/// would only re-arm one of the zombies (typically a timer tick
/// that satisfies a sleep deadline far in the future).
pub fn init() {
    for q in READY.iter() {
        *q.lock() = Some(VecDeque::new());
    }
}

/// Pick the CPU index a task with `spec` should land on. Honours
/// `affinity.preferred` when the named CPU is online; otherwise spawns
/// on the current CPU. Falls back to CPU 0 if the current CPU is
/// somehow not online (shouldn't happen — current_cpu() returning a
/// CPU implies that CPU is executing).
fn target_cpu(spec: &TaskSpec) -> usize {
    if let Some(cpu) = spec.affinity.preferred {
        let id = cpu.0 as usize;
        if id < narf_lib::percpu::MAX_CPUS && narf_lib::smp::is_online(cpu.0) {
            return id;
        }
    }
    let here = narf_lib::percpu::current_cpu();
    if here < narf_lib::percpu::MAX_CPUS {
        here
    } else {
        0
    }
}

/// Push `slot` onto `cpu`'s ready queue. Panics if `init()` hasn't run.
fn enqueue_on(cpu: usize, slot: TaskSlot) {
    let mut q = READY[cpu].lock();
    q.as_mut()
        .expect("scheduler: spawn before init")
        .push_back(slot);
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
        task: Box::pin(f),
        awake: Arc::new(AtomicBool::new(true)),
        id,
        spec,
        addr_space: None,
        account: BudgetAccount::new(),
    };
    let cpu = target_cpu(&spec);
    enqueue_on(cpu, slot);
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
/// poll of the task's future is preceded by `addr_space.activate()`,
/// which on x86_64 issues a `MOV CR3` (with the right `compiler_fence`
/// discipline) and on aarch64 issues the architected
/// `MSR TTBR0_EL1 + DSB + TLBI VMALLE1 + DSB + ISB` sequence. Both
/// paths are live; the only `NotImplemented` returns now come from
/// arches outside the {x86_64, aarch64} matrix (they log + proceed).
pub fn spawn_user<F>(f: F, spec: TaskSpec, addr_space: Arc<AddressSpace>) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    let id = TaskId(NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed));
    let slot = TaskSlot {
        task: Box::pin(f),
        awake: Arc::new(AtomicBool::new(true)),
        id,
        spec,
        addr_space: Some(addr_space),
        account: BudgetAccount::new(),
    };
    let cpu = target_cpu(&spec);
    enqueue_on(cpu, slot);
    id
}

/// Look up the address space attached to `id`, if any. The returned
/// `Arc` keeps the AS alive even if the task drops immediately —
/// callers holding it observe a consistent snapshot.
///
/// Searches every per-CPU queue. The lock on each CPU's queue is held
/// for the duration of its scan; no two CPUs' queues are held at once.
pub fn address_space_of(id: TaskId) -> Option<Arc<AddressSpace>> {
    for q in READY.iter() {
        let g = q.lock();
        if let Some(ref dq) = *g {
            if let Some(slot) = dq.iter().find(|s| s.id == id) {
                return slot.addr_space.clone();
            }
        }
    }
    None
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
    cap.check_live()
        .map_err(|_| DonateError::AuthorityRevoked)?;
    let mut any_initialised = false;
    for q in READY.iter() {
        let mut g = q.lock();
        let ready = match g.as_mut() {
            Some(r) => r,
            None => continue,
        };
        any_initialised = true;
        if let Some(pos) = ready.iter().position(|s| s.id == target) {
            if pos != 0 {
                let slot = ready.remove(pos).unwrap();
                // Force-wake the donee so the executor doesn't skip
                // it on the next round if its waker hasn't fired —
                // donation is by definition "let me pick this task
                // even though you wouldn't normally have chosen it".
                slot.awake.store(true, Ordering::Release);
                ready.push_front(slot);
            }
            return Ok(());
        }
    }
    if !any_initialised {
        return Err(DonateError::NotReady);
    }
    Err(DonateError::TargetNotFound)
}

// ── Waker plumbing ──────────────────────────────────────────────────
//
// Each task owns an `Arc<AtomicBool>` awake flag. A `Waker` is just an
// `Arc<AtomicBool>` whose `wake`/`wake_by_ref` store `true` into the
// flag. The vtable's `clone`/`drop` operate the Arc refcount, so a
// future is free to stash its waker (as IRQ-driven drivers will want
// to) and have it outlive the original `TaskSlot` view.

const TASK_VTABLE: RawWakerVTable =
    RawWakerVTable::new(clone_raw, wake_raw, wake_by_ref_raw, drop_raw);

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
    unsafe {
        (*ptr).store(true, Ordering::Release);
    }
}

unsafe fn drop_raw(data: *const ()) {
    // SAFETY: reconstructing consumes the refcount owned by this waker.
    unsafe {
        drop(Arc::<AtomicBool>::from_raw(data as *const AtomicBool));
    }
}

fn make_waker(flag: Arc<AtomicBool>) -> Waker {
    let raw = Arc::into_raw(flag) as *const ();
    // SAFETY: vtable functions are matched to the `Arc<AtomicBool>`
    // representation encoded in `raw`.
    unsafe { Waker::from_raw(RawWaker::new(raw, &TASK_VTABLE)) }
}

/// Run the ready queue until it's empty.
///
/// Drives the *current CPU's* per-CPU queue. Each round visits every
/// task currently on the queue at most once; each slot is polled iff
/// its awake flag is set. The flag is cleared (`swap(false)`) before
/// the poll so a waker that fires *during* the poll leaves the task
/// marked for re-poll on the next round.
///
/// After a local round produces no `Ready` tasks, the executor tries
/// to steal one task from another CPU's queue (round-robin starting
/// at `cpu+1`). If every queue is empty *and* nothing made progress,
/// halt the CPU via `arch::halt_until_irq`. An external interrupt
/// (timer or otherwise) will wake us, and the next round either makes
/// progress (a deadline met, waker fired) or we halt again. The halt
/// is kept even though wakers are now per-task because today's self-
/// waking futures (`SleepUntil`, `yield_now`) would otherwise spin
/// the CPU between clock ticks — they re-set their own awake flag
/// before returning Pending, so the "any awake?" check would always
/// pass.
///
/// Termination: returns when both this CPU's queue and every other
/// CPU's queue are empty. Workers (APs) call this in a loop with no
/// expectation of return; tests call it from BSP and rely on it
/// returning once their spawned tasks complete.
/// Drive one round of the local CPU's run-queue, polling **only
/// kernel-side tasks** (`addr_space.is_none()`), and return.
///
/// Designed to be called from inside a syscall trap — most
/// notably the `sys_sleep` busy-wait in
/// `narf_userspace::handlers::sleep_pumps` — to keep kernel async
/// work (FB drain, USB HID supervisor, the boot-time async demo,
/// future device pumps) advancing while a user task is parked.
///
/// User-mode (AS-bearing) tasks are intentionally skipped:
/// polling one of them inside a syscall handler would call
/// `enter_user_mode` from a trap context whose `iretq` frame is
/// still on the kernel stack, re-entering user code while another
/// trap is in flight — the kernel stack would corrupt and the
/// CR3 swap would race. User tasks resume normally on the
/// outermost `run_until_empty` after the syscall returns.
///
/// Each kernel task is visited at most once. The function never
/// `halt_until_irq`s. Returns the number of tasks that completed
/// this round (`Ready` returns), purely as a diagnostic.
pub fn poll_one_round() -> usize {
    let cpu = narf_lib::percpu::current_cpu();
    let cpu = if cpu < narf_lib::percpu::MAX_CPUS {
        cpu
    } else {
        0
    };

    let round_len = {
        let q = READY[cpu].lock();
        match q.as_ref() {
            Some(d) => d.len(),
            None => return 0,
        }
    };
    let mut ready_this_round = 0usize;

    for _ in 0..round_len {
        let mut slot = {
            let mut q = READY[cpu].lock();
            match q.as_mut().and_then(|d| d.pop_front()) {
                Some(t) => t,
                None => break,
            }
        };
        // Skip user-mode tasks — see fn-level comment. Re-push so
        // the outer run loop still sees them when this returns.
        if slot.addr_space.is_some() {
            let mut q = READY[cpu].lock();
            q.as_mut().unwrap().push_back(slot);
            continue;
        }
        if let Some(ref cap) = slot.spec.budget_cap {
            if cap.check_live().is_err() {
                continue;
            }
        }
        if !slot.awake.swap(false, Ordering::Acquire) {
            let mut q = READY[cpu].lock();
            q.as_mut().unwrap().push_back(slot);
            continue;
        }
        let waker = make_waker(slot.awake.clone());
        let mut ctx = Context::from_waker(&waker);
        let start = Instant::now();
        // Save + restore identity around the inner poll. We're
        // running INSIDE another task's poll (the user-mode
        // syscall handler that called sleep_pumps); a blunt
        // clear on exit would strip the outer task's
        // CURRENT_TASK + ACTIVE_USER_AS publication and break
        // its next syscall lookup. Pumps only ever poll
        // kernel-only tasks (the user-task skip above), so the
        // ACTIVE_USER_AS clear is unconditional — kernel tasks
        // don't carry their own AS publication.
        let outer_task = CURRENT_TASK.load(Ordering::Acquire);
        let outer_as = ACTIVE_USER_AS.lock().clone();
        CURRENT_TASK.store(slot.id.raw(), Ordering::Release);
        // No `*ACTIVE_USER_AS.lock() = ...` here because kernel
        // tasks have `addr_space.is_none()` (we filtered above).
        let poll_result = slot.task.as_mut().poll(&mut ctx);
        CURRENT_TASK.store(outer_task, Ordering::Release);
        *ACTIVE_USER_AS.lock() = outer_as;
        let elapsed = Instant::now().cycles_since(start);
        slot.account.charge(elapsed, &slot.spec.budget);
        narf_rcu::report_quiescent();
        match poll_result {
            Poll::Ready(()) => ready_this_round += 1,
            Poll::Pending => {
                let mut q = READY[cpu].lock();
                q.as_mut().unwrap().push_back(slot);
            }
        }
    }
    ready_this_round
}

pub fn run_until_empty() {
    let cpu = narf_lib::percpu::current_cpu();
    let cpu = if cpu < narf_lib::percpu::MAX_CPUS {
        cpu
    } else {
        0
    };

    loop {
        // Snapshot queue length. We'll visit each task at most once per
        // round; spawns during the round land at the back and get
        // visited on the NEXT round.
        let round_len = {
            let q = READY[cpu].lock();
            q.as_ref()
                .expect("scheduler::run_until_empty before init")
                .len()
        };

        let mut ready_this_round: usize = 0;

        for _ in 0..round_len {
            // Pop; if empty, break (can happen if a task was cancelled).
            let mut slot = {
                let mut q = READY[cpu].lock();
                match q.as_mut().unwrap().pop_front() {
                    Some(t) => t,
                    None => break,
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
                let mut q = READY[cpu].lock();
                q.as_mut().unwrap().push_back(slot);
                continue;
            }

            // If the task owns an address space, activate it before
            // polling so user-mode accesses land in the right low-half
            // mappings. Live on x86_64 (CR3 swap) and aarch64 (TTBR0
            // swap). The error path remains so kernel-only tasks on
            // unsupported arches keep running unchanged.
            if let Some(ref a) = slot.addr_space {
                let _ = a.activate();
            }

            let waker = make_waker(slot.awake.clone());
            let mut ctx = Context::from_waker(&waker);
            let start = Instant::now();
            // Publish this slot's id + AS as the currently-polling
            // task so syscall handlers + introspection can identify
            // the caller and resolve its mappings. Cleared after the
            // poll so async code that defers via `.await` doesn't
            // leak identity across yield points (the next round's
            // task will re-publish). The AS publication makes
            // `current_address_space()` work during the poll body —
            // by the time we'd otherwise look the slot up via
            // `address_space_of(id)` it's already been popped from
            // the queue and thus invisible to that scan.
            CURRENT_TASK.store(slot.id.raw(), Ordering::Release);
            *ACTIVE_USER_AS.lock() = slot.addr_space.clone();
            let poll_result = slot.task.as_mut().poll(&mut ctx);
            CURRENT_TASK.store(0, Ordering::Release);
            *ACTIVE_USER_AS.lock() = None;
            let elapsed = Instant::now().cycles_since(start);
            slot.account.charge(elapsed, &slot.spec.budget);

            // Announce a QSBR quiescent state: the task has yielded
            // back to the executor and holds no RCU read-guards across
            // the poll boundary (per rcu/ §3.7, read-guards may not
            // span awaits). Every poll return is therefore a grace-
            // period tick for this CPU.
            narf_rcu::report_quiescent();

            match poll_result {
                Poll::Ready(()) => {
                    ready_this_round += 1; /* drop slot */
                }
                Poll::Pending => {
                    let mut q = READY[cpu].lock();
                    q.as_mut().unwrap().push_back(slot);
                }
            }
        }

        // Local queue done for this round. If empty, try to steal one
        // task from another CPU's queue; if that fails, we have
        // nothing to do — return so the caller decides whether to
        // park (worker APs via `run_forever`) or proceed (BSP-side
        // test callers).
        let local_empty = {
            let q = READY[cpu].lock();
            q.as_ref().map(|d| d.is_empty()).unwrap_or(true)
        };
        if local_empty {
            if !try_steal_one(cpu) {
                return;
            }
            continue;
        }

        if ready_this_round == 0 {
            // Polled some Pending tasks but nothing completed; idle
            // until an IRQ delivers a wake.
            narf_arch::halt_until_irq();
        }
    }
}

/// Try to steal one task from another CPU's queue. Returns `true` if
/// a slot was moved onto `cpu`'s queue.
///
/// Search order: same-NUMA-node victims first (when ACPI SRAT
/// provided topology), then cross-node victims, then a flat
/// round-robin fallback. The same-node pass is what makes the SRAT
/// data load-bearing — stealing a task from the same NUMA node
/// keeps cache-warm working sets local.
///
/// No-op when `STEAL_ENABLED` is false (boot default). Callers in the
/// idle path treat a `false` return as "nothing to do, return".
fn try_steal_one(cpu: usize) -> bool {
    if !STEAL_ENABLED.load(Ordering::Acquire) {
        return false;
    }
    let max = narf_lib::percpu::MAX_CPUS;
    let my_node = narf_acpi::cpu_node(cpu as u32);

    // Phase 1: same-NUMA-node victims. Skipped when topology is
    // unknown — falls through to flat round-robin.
    if my_node.is_some() {
        for i in 1..max {
            let victim = (cpu + i) % max;
            if victim == cpu {
                continue;
            }
            if narf_acpi::cpu_node(victim as u32) != my_node {
                continue;
            }
            if try_steal_from(victim, cpu) {
                return true;
            }
        }
    }

    // Phase 2: cross-node victims (or every victim if topology is
    // unknown). Round-robin starting at cpu+1.
    for i in 1..max {
        let victim = (cpu + i) % max;
        if victim == cpu {
            continue;
        }
        // Skip same-node victims — phase 1 already covered them.
        if my_node.is_some() && narf_acpi::cpu_node(victim as u32) == my_node {
            continue;
        }
        if try_steal_from(victim, cpu) {
            return true;
        }
    }
    false
}

/// Inner helper: try to move one affinity-allowed slot from
/// `victim`'s queue onto `cpu`'s queue. Returns `true` on success.
fn try_steal_from(victim: usize, cpu: usize) -> bool {
    let stolen = {
        let mut g = READY[victim].lock();
        let q = match g.as_mut() {
            Some(q) => q,
            None => return false,
        };
        // Linear scan for the first slot we're allowed to take.
        // Stealing a pinned task to the wrong CPU would defeat
        // the pin — respect `allowed`.
        let pos = q.iter().position(|s| {
            s.spec
                .affinity
                .allowed
                .contains(crate::affinity::CpuId(cpu as u32))
        });
        match pos {
            Some(p) => q.remove(p),
            None => None,
        }
    };
    if let Some(slot) = stolen {
        let mut g = READY[cpu].lock();
        g.as_mut()
            .expect("scheduler: steal before init")
            .push_back(slot);
        return true;
    }
    false
}

/// Worker-AP entry: the per-CPU run loop that an AP enters after
/// bring-up. Equivalent to `run_until_empty` but never returns —
/// when both this CPU's queue and every steal target are empty,
/// halts until an IRQ delivers a wake.
///
/// Reports a QSBR quiescent state immediately before the halt so
/// `narf_rcu::sync` can advance even when this CPU has gone idle.
/// Without this, an AP that polled one task and then halted would
/// leave its `last_quiescent` stuck below the current epoch and
/// stall every subsequent grace period kernel-wide.
pub fn run_forever() -> ! {
    loop {
        run_until_empty();
        // Idle path: declare ourselves out of RCU consideration so
        // `sync()` doesn't block on an asleep CPU. We re-adopt the
        // live epoch on our first `report_quiescent` after wake.
        // Safe at this point because `run_until_empty` only returns
        // between polls, and read guards may not span awaits per
        // rcu/ §3.7.
        narf_rcu::report_idle();
        narf_arch::halt_until_irq();
    }
}

/// Tiny convenience: Future that returns Pending once, then Ready.
/// `block_on`-equivalent `yield` point for cooperative tasks that just
/// want to give the executor a chance to run peers.
#[derive(Debug)]
pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.yielded {
            Poll::Ready(())
        } else {
            this.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
}
