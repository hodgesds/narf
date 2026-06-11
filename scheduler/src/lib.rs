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
//! Stage 5 lands the spec's post-Stage-4 features in three waves:
//! direct time-slice donation (this commit), PKRS save/restore at
//! yield points, and fair-share enforcement + NUMA-aware steal.
//!
//! Donation fast path (spec §3.3): `donate_to(target, &Cap<Task,
//! Invoke>)` deducts the donor's remaining burst quantum from its
//! `BudgetAccount`, credits it to the target, and head-enqueues
//! the target so the next dispatch services it first. Revoking
//! the donation cap before the donee polls refunds both sides
//! atomically at the donee's next pop (`settle_donation`).
//!
//! PKRS save/restore at yield points (x86_64, Intel SDM Vol 3
//! §4.6.2.4): `IA32_PKRS` (MSR `0x6E1`) is snapshotted into the
//! task slot's `saved_pkrs` after the future returns
//! `Poll::Pending`; restored before the next `Future::poll`. Two
//! tasks polled back-to-back never see each other's protection-
//! key rights view. aarch64 has no PKRS analogue; the field and
//! the save/restore are gated behind `cfg(target_arch = "x86_64")`.
//!
//! Fair-share enforcement + NUMA-aware steal (spec §3.4 / §3.2):
//! `BudgetAccount::charge` returns a `ChargeOutcome` the executor
//! acts on — `Throttle` clears the awake flag for one round,
//! `Demote` reclassifies the slot as `SchedClass::Idle`, `Kill`
//! drops the slot O(1). `try_steal_one` prefers same-NUMA-node
//! victims (`narf_acpi::cpu_node`) before crossing nodes; design
//! follows Vyukov's CPPCON work-stealing notes
//! (https://www.1024cores.net/).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod affinity;
pub mod budget;
pub mod cpu_lifecycle;
pub mod donation;
pub mod policy;
pub mod priority;
pub mod stackful;
pub mod steal;

mod tests;

pub use affinity::{Affinity, CpuId, CpuSet};
pub use budget::{BudgetAccount, CpuBudget, OverrunPolicy, ResourceBudget};
pub use cpu_lifecycle::{
    cpu_bring_up, cpu_online, cpu_take_offline, online_count, CpuLifecycle, HotPlugError,
};
pub use donation::{
    current_donation_policy_name, install_donation_policy, BackQueueDonation, Donation,
    DonationError, DonationPolicy, EnqueueDonee, HeadQueueDonation,
};
pub use policy::{
    current_scheduler_name, install_scheduler, FifoScheduler, PriorityScheduler, RunQueue,
    SchedPolicy, Scheduler, SchedulerError, TaskHandle, TaskMeta,
};
pub use priority::{Priority, SchedClass, SmtSharePolicy};
pub use steal::{
    current_steal_strategy_name, install_steal_strategy, NumaAwareSteal, RandomSteal, Steal,
    StealError, StealStrategy,
};

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
    enter_user_mode, enter_user_mode_resume, enter_user_mode_with_arg, longjmp, set_user_fs_base,
    setjmp, JmpBuf, UserState, USER_RFLAGS,
};

#[cfg(target_arch = "aarch64")]
pub use narf_arch::aarch64::{
    enter_user_mode, enter_user_mode_resume, longjmp, set_user_tls_base, setjmp, JmpBuf, UserState,
    USER_SPSR,
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

pub(crate) struct TaskSlot {
    task: BoxedTask,
    // Per-task "needs-repoll" flag set by the waker. The slot owns one
    // `Arc<AtomicBool>`; each handed-out `Waker` owns another clone, so
    // the flag outlives the slot if the future has stashed its waker.
    // The scheduler swaps this to `false` before polling; if the poll
    // returns `Pending` and nothing has re-set it, the slot is skipped
    // on subsequent rounds until a waker flips it back to `true`.
    awake: Arc<AtomicBool>,
    /// Monotonic identifier stamped at spawn time so `donate_to` has
    /// a stable handle into the ready queue. `pub(crate)` so the
    /// `policy` module's `RunQueue` projection can read it.
    pub(crate) id: TaskId,
    /// Stage-3 §3.3/§3.4 per-task metadata: affinity, CPU budget, the
    /// `Cap<CpuBudget, Spend>` that gates scheduling, and the running
    /// `BudgetAccount`. `pub(crate)` so the `policy` module's
    /// `RunQueue` projection can read its `priority`/`class`/
    /// `affinity` fields.
    pub(crate) spec: TaskSpec,
    account: BudgetAccount,
    /// Optional per-process address space (Stage 4). `None` for
    /// kernel-only tasks; `Some` for a user-mode task that shares
    /// the AS with its process peers. Held as `Arc` so tasks within
    /// one process share one AS without copying.
    addr_space: Option<Arc<AddressSpace>>,
    /// Pending time-slice donation (§3.3). Set by `donate_to` so the
    /// next pop either consumes the credit (cap live) or refunds
    /// the donor (cap revoked). `None` outside an active donation.
    donation: Option<DonationClaim>,
    /// Saved IA32_PKRS (Intel SDM Vol 3 §4.6.2.4). Snapshotted
    /// after a `Poll::Pending` so the next poll of this slot
    /// restores the task's protection-key rights view. `None`
    /// before the first yield. x86_64-only; aarch64 has no
    /// protection-key analogue.
    #[cfg(target_arch = "x86_64")]
    saved_pkrs: Option<narf_arch::x86_64::pks::SavedPkrs>,
}

/// One in-flight time-slice donation handed to a task by
/// `donate_to`. The donee carries the claim until its next
/// dispatch round; `settle_donation` then either keeps the credit
/// (cap still live) or reverts both sides (cap revoked → refund
/// donor + revert donee's credit). Stored on the donee so the
/// executor resolves revocation O(1) at pop time.
struct DonationClaim {
    donor: TaskId,
    /// Snapshot of the donor's `TaskMeta` at donation time. Passed
    /// to `DonationPolicy::on_revoke` if the donation is cancelled
    /// between donate and settle, so the policy can attribute the
    /// refund without re-walking the ready queues.
    donor_meta: crate::policy::TaskMeta,
    cycles: u64,
    cap: Cap<Task, Invoke>,
}

impl core::fmt::Debug for DonationClaim {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DonationClaim")
            .field("donor", &self.donor)
            .field("cycles", &self.cycles)
            .finish_non_exhaustive()
    }
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
    /// Default: BSP-pinned, unthrottled, no cap gate. Pinning to
    /// the boot CPU is a load-bearing safety property today —
    /// most spawn-and-forget tasks (FB drain, USB-HID supervisor,
    /// virtio-input pump, …) were written assuming single-CPU
    /// execution and reach into shared state without locks. Until
    /// each is audited for SMP safety, the default keeps them on
    /// CPU0 even when work-stealing is enabled and APs are alive.
    /// Tasks that have been verified SMP-safe can opt into
    /// migration with `Affinity::any()` via spawn_with_spec.
    pub const fn unthrottled() -> Self {
        Self {
            affinity: Affinity::pinned(crate::affinity::CpuId::BOOT),
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
            affinity: Affinity::pinned(crate::affinity::CpuId::BOOT),
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
    use core::sync::atomic::{AtomicBool, Ordering};
    static INITIALIZED: AtomicBool = AtomicBool::new(false);
    if INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // Double-init is a *bug*. Pre-fix this path
        // unconditionally re-built every per-CPU VecDeque, silently
        // dropping any task spawned in between (cursor pump + USB
        // HID supervisor were historic victims — both spawned
        // during Stage::Late initcalls and disappeared when
        // bare_main re-init'd before run_async_demo). Panic now so
        // the mistake surfaces at the call site instead of becoming
        // a silent kill weeks later. Tests that need a fresh queue
        // call `__reset_queues_for_test` explicitly.
        panic!("narf_scheduler::init() called twice — would wipe spawned tasks; use __reset_queues_for_test in tests");
    }
    for q in READY.iter() {
        *q.lock() = Some(VecDeque::new());
    }
    // Wave D: wire the default `FifoScheduler` into the policy slot
    // before any `run_until_empty` call dispatches. Idempotent — if a
    // smoke installed an alternative impl ahead of init, leave it.
    policy::install_default_if_unset();
    // Wave E: wire the default `HeadQueueDonation` so `donate_to`'s
    // policy-driven placement and cycle-ceiling lookups return the
    // pre-Wave-E hardcoded behaviour byte-for-byte. Idempotent for the
    // same reason `policy::install_default_if_unset` is.
    donation::install_default_if_unset();
    // Wave F: wire the default `NumaAwareSteal` so `try_steal_one`'s
    // policy-driven victim-ordering and per-task allow_steal checks
    // return the pre-Wave-F two-phase same-node-first behaviour
    // byte-for-byte. Idempotent for the same reason the wave D/E
    // installs are.
    steal::install_default_if_unset();
}

/// Test-only hook: clear every ready queue without re-running
/// `init()`. Hermetic isolation between verification smokes that
/// build their own task graph and need an empty queue without
/// touching the one-shot `INITIALIZED` flag in `init`.
#[doc(hidden)]
pub fn __reset_queues_for_test() {
    for q in READY.iter() {
        if let Some(d) = q.lock().as_mut() {
            d.clear();
        }
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
        donation: None,
        #[cfg(target_arch = "x86_64")]
        saved_pkrs: None,
    };
    let cpu = target_cpu(&spec);
    enqueue_on(cpu, slot);
    id
}

/// Spawn a task that runs on its own dedicated kernel stack
/// (16 KiB default). The future's `poll` is driven via
/// `kernel_switch` so the LAPIC timer ISR can preempt it on
/// slice expiry — see `scheduler/specification/preemption.md`.
///
/// Phase 2 lossy preemption is now active: a kernel async task
/// that busy-loops inside its `poll()` body gets preempted at
/// the per-task TSC slice (default 10 ms ≈ 33 M cycles on a
/// 3.3 GHz CPU) and the executor regains control. The future
/// re-polls from its current heap state on next dispatch — its
/// progress isn't lost, only the intermediate stack frames of
/// the abandoned poll.
///
/// Migrate suspect-busy-loop kernel tasks (FB cursor pump,
/// drain task, USB HID supervisor, etc.) from `spawn()` to this
/// to immunise the executor against their wedges.
///
/// Same return + queueing semantics as `spawn()` — caller gets
/// back a TaskId. For per-task preemption tuning (slice size,
/// opt-out via `no_preempt`), use `spawn_stackful_with_options`.
pub fn spawn_stackful<F>(f: F) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    spawn(stackful::StackfulAdapter::new(f))
}

/// Options for tuning a stackful task's preemption behaviour.
#[derive(Copy, Clone, Debug)]
pub struct StackfulOptions {
    /// Per-task TSC slice in cycles. Default
    /// `stackful::DEFAULT_SLICE_CYCLES` (~10 ms on 3.3 GHz Zen2).
    pub slice_cycles: u64,
    /// When true, the trap-handler hook skips preempting this
    /// task. Use for drivers that hold hardware locks across an
    /// `.await`-free region.
    pub no_preempt: bool,
    /// Per-task kernel stack size. Must be ≥ 4 KiB and 16-byte
    /// aligned. Default `stackful::DEFAULT_KERNEL_STACK_BYTES`
    /// (16 KiB).
    pub stack_bytes: usize,
}

impl Default for StackfulOptions {
    fn default() -> Self {
        Self {
            slice_cycles: stackful::DEFAULT_SLICE_CYCLES,
            no_preempt: false,
            stack_bytes: stackful::DEFAULT_KERNEL_STACK_BYTES,
        }
    }
}

/// Spawn a stackful task with explicit preemption options.
/// Wraps `spawn_stackful` but configures the per-task slice +
/// preempt opt-out + stack size before queuing.
pub fn spawn_stackful_with_options<F>(f: F, opts: StackfulOptions) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut adapter = stackful::StackfulAdapter::with_options(f, opts);
    adapter.apply_options();
    spawn(adapter)
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
        donation: None,
        #[cfg(target_arch = "x86_64")]
        saved_pkrs: None,
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

/// Snapshot of every task currently sitting on a per-CPU ready
/// queue. Used by /proc to enumerate `[pid]` subdirectories and
/// by debug surfaces (`ps`-style introspection).
///
/// Intentionally returns owned Vec rather than an iterator: the
/// per-CPU lock is dropped before any caller code runs, so the
/// snapshot can become stale immediately. Stale-but-consistent is
/// the right semantic for /proc — Linux reports the same shape.
pub fn all_task_ids() -> alloc::vec::Vec<TaskId> {
    let mut out = alloc::vec::Vec::new();
    for q in READY.iter() {
        let g = q.lock();
        if let Some(ref dq) = *g {
            for slot in dq.iter() {
                out.push(slot.id);
            }
        }
    }
    out
}

/// Replace the address space attached to `id`. Returns the
/// previous Arc so the caller can decide what to do with it
/// (e.g. drop immediately to free the old AS's frames + page-
/// table pages, or hold it briefly to continue running on the
/// old AS until the trap-return swap takes effect).
///
/// Used by `execve` to swap the current task's AS to the freshly-
/// loaded program AS without re-spawning the task — the task id,
/// its place in the ready queue, and any in-flight syscall
/// bookkeeping (fd table, brk, sigaction handlers) all stay
/// keyed to the same id.
///
/// Returns None if no slot with that id is on any ready queue.
pub fn replace_address_space(id: TaskId, new_arc: Arc<AddressSpace>) -> Option<Arc<AddressSpace>> {
    // Wave-49fu: when execve fires from inside a user task's poll
    // body (the normal case), the slot has been popped from the
    // ready queue and lives on the executor's stack — the queue
    // scan below won't find it. Two updates are needed for the
    // mismatch-free outcome:
    //
    //   1. ACTIVE_USER_AS — the trap path / sys_* handlers read
    //      this immediately for any further #PF / mmap / brk in the
    //      same poll round (e.g. demand-paging the new image's
    //      stack writes during the bytes-walk of init_sysv_stack).
    //   2. PENDING_SLOT_AS map — the slot will be pushed back to
    //      the queue on Poll::Pending; on the NEXT round the
    //      scheduler must publish the NEW AS, not the slot's stale
    //      addr_space field. The map is checked after the slot is
    //      popped; the override takes precedence over the slot's
    //      own field.
    let id_now = CURRENT_TASK.load(Ordering::Acquire);
    if id_now == id.raw() {
        {
            let mut g = ACTIVE_USER_AS.lock();
            let _ = g.take();
            *g = Some(new_arc.clone());
        }
        let mut p = PENDING_SLOT_AS.lock();
        let prev = p
            .iter()
            .find(|(k, _)| *k == id.raw())
            .map(|(_, v)| v.clone());
        p.retain(|(k, _)| *k != id.raw());
        p.push((id.raw(), new_arc));
        return prev;
    }
    for q in READY.iter() {
        let mut g = q.lock();
        if let Some(ref mut dq) = *g {
            if let Some(slot) = dq.iter_mut().find(|s| s.id == id) {
                let prev = slot.addr_space.take();
                slot.addr_space = Some(new_arc);
                return prev;
            }
        }
    }
    None
}

/// Wave-49fu: pending slot AS updates queued by `replace_address_
/// space` when the target slot is the currently-polling task. The
/// scheduler's per-poll prelude drains this on pop and applies the
/// override to the slot's `addr_space` before activate. Vec instead
/// of BTreeMap to avoid an alloc-only dependency on `alloc::collections`
/// for one-or-two-entry workloads. Wave-49+ may swap this to a
/// `BTreeMap` if the post-fork burst pattern needs it.
static PENDING_SLOT_AS: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<(u64, Arc<AddressSpace>)>> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Drain `PENDING_SLOT_AS` for the given task id, returning the
/// pending AS if any. Called by `poll_one_round` after popping a
/// slot — the caller assigns the override into `slot.addr_space`
/// so the activate + ACTIVE_USER_AS publication see the new AS.
fn take_pending_slot_as(id: TaskId) -> Option<Arc<AddressSpace>> {
    let mut p = PENDING_SLOT_AS.lock();
    let pos = p.iter().position(|(k, _)| *k == id.raw())?;
    let (_, v) = p.swap_remove(pos);
    Some(v)
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
    /// The installed donation policy returned
    /// `EnqueueDonee::Refuse`. The donor's budget has been
    /// restored; the donee is unchanged.
    PolicyRefused,
}

/// Pending donor-side debit table for donations whose donor is
/// off-queue (currently being polled). Each entry is `(donor,
/// cycles)`; the executor drains matching entries when the donor's
/// slot is re-enqueued and applies them via `add_debit`.
///
/// 16 slots covers the realistic in-flight donation graph; an
/// overflow panics so the misuse surfaces at the call site.
const MAX_PENDING_DONATIONS: usize = 16;
static PENDING_DONOR_DEBITS: IrqSafeSpinLock<[(TaskId, u64); MAX_PENDING_DONATIONS]> =
    IrqSafeSpinLock::new([(TaskId::NONE, 0); MAX_PENDING_DONATIONS]);

fn stage_donor_debit(donor: TaskId, cycles: u64) {
    let mut t = PENDING_DONOR_DEBITS.lock();
    for slot in t.iter_mut() {
        if slot.0 == TaskId::NONE {
            *slot = (donor, cycles);
            return;
        }
    }
    panic!("donate_to: pending-debit table full");
}

fn drain_donor_debit(donor: TaskId) -> u64 {
    if donor == TaskId::NONE {
        return 0;
    }
    let mut t = PENDING_DONOR_DEBITS.lock();
    let mut total = 0u64;
    for slot in t.iter_mut() {
        if slot.0 == donor {
            total = total.saturating_add(slot.1);
            *slot = (TaskId::NONE, 0);
        }
    }
    total
}

fn cancel_donor_debit(donor: TaskId, cycles: u64) {
    let mut t = PENDING_DONOR_DEBITS.lock();
    for slot in t.iter_mut() {
        if slot.0 == donor {
            let new = slot.1.saturating_sub(cycles);
            if new == 0 {
                *slot = (TaskId::NONE, 0);
            } else {
                slot.1 = new;
            }
            return;
        }
    }
}

fn refund_donor(donor: TaskId, cycles: u64) {
    if cycles == 0 || donor == TaskId::NONE {
        return;
    }
    for q in READY.iter() {
        let mut g = q.lock();
        if let Some(ref mut dq) = *g {
            if let Some(s) = dq.iter_mut().find(|s| s.id == donor) {
                s.account.revert_debit(cycles);
                return;
            }
        }
    }
    cancel_donor_debit(donor, cycles);
}

#[doc(hidden)]
pub fn __reset_donations_for_test() {
    *PENDING_DONOR_DEBITS.lock() = [(TaskId::NONE, 0); MAX_PENDING_DONATIONS];
}

/// Direct time-slice donation fast path (spec §3.3).
///
/// On success the scheduler:
/// 1. Deducts the donor's remaining burst quantum (capped at
///    `MAX_DONATION_CYCLES` so an unthrottled donor can't transfer
///    `u64::MAX`) from the donor's `BudgetAccount`. If the donor
///    is currently being polled (off-queue), the debit is staged
///    in `PENDING_DONOR_DEBITS` and applied at the donor's next
///    `push_back`.
/// 2. Credits the same cycle count to the target via
///    `BudgetAccount::add_credit`, extending its effective
///    quantum.
/// 3. Stamps a `Donation` claim on the target's slot.
/// 4. Forces the donee awake and moves the slot to the head of
///    its ready queue so the next dispatch round polls it first
///    (ahead of normal FIFO order).
///
/// Revocation: if `cap.revoke()` is called before the donee
/// consumes the donation, the executor's `settle_donation` at
/// the donee's next pop calls `account.revert_credit` on the
/// donee and `refund_donor` on the donor (refunds via
/// `revert_debit` if findable, otherwise cancels the pending
/// debit). The donee continues without the boost.
pub fn donate_to(target: TaskId, cap: &Cap<Task, Invoke>) -> Result<(), DonateError> {
    cap.check_live()
        .map_err(|_| DonateError::AuthorityRevoked)?;

    let donor_id = current_task_id();
    let mut any_initialised = false;

    for q in READY.iter() {
        let mut g = q.lock();
        let ready = match g.as_mut() {
            Some(r) => r,
            None => continue,
        };
        any_initialised = true;
        if let Some(pos) = ready.iter().position(|s| s.id == target) {
            // Build a donor-meta snapshot. If the donor is on the
            // same queue, lift its real `TaskMeta`; if not, synthesise
            // a placeholder carrying just the donor id so the policy
            // can still log/decide. Either way `donor_meta` is what
            // the policy sees for both `cycle_ceiling` and
            // `enqueue_donee`.
            let (donor_meta, donor_on_queue) = if donor_id != TaskId::NONE {
                if let Some(d) = ready.iter().find(|s| s.id == donor_id) {
                    (
                        crate::policy::TaskMeta {
                            id: d.id,
                            priority: d.spec.priority,
                            class: d.spec.class,
                            affinity: d.spec.affinity,
                        },
                        true,
                    )
                } else {
                    (
                        crate::policy::TaskMeta {
                            id: donor_id,
                            priority: crate::priority::Priority::NORMAL,
                            class: crate::priority::SchedClass::Normal,
                            affinity: crate::affinity::Affinity::any(),
                        },
                        false,
                    )
                }
            } else {
                (
                    crate::policy::TaskMeta {
                        id: TaskId::NONE,
                        priority: crate::priority::Priority::NORMAL,
                        class: crate::priority::SchedClass::Normal,
                        affinity: crate::affinity::Affinity::any(),
                    },
                    false,
                )
            };

            // Consult the donation policy for placement intent and
            // cycle ceiling. The helper acquires `DONATION`, reads,
            // and drops the lock before returning so the queue lock
            // we still hold here is never nested under it.
            let donee_handle = crate::policy::TaskHandle::from_id(target);
            let mut rq = crate::policy::RunQueue::projected(ready);
            let (placement, ceiling) =
                crate::donation::placement_and_ceiling(&mut rq, &donor_meta, donee_handle);
            // `rq` is a borrow of `ready`; drop it before mutating
            // `ready` further so the borrow checker sees the lifetime
            // ended (no `take_picked` was called — the projection is
            // read-only for this path).
            drop(rq);

            // Refuse short-circuit: no budget changes, no enqueue
            // mutation; donee stays where it is.
            if matches!(placement, crate::donation::EnqueueDonee::Refuse) {
                return Err(DonateError::PolicyRefused);
            }

            // Compute the actual cycles to transfer. When the donor
            // is on-queue we cap by its remaining burst quantum (the
            // pre-Wave-E behaviour); otherwise the ceiling is the
            // full policy budget (debit staged for next pop).
            let mut donor_remaining: u64 = 0;
            let mut donor_debited_inline = false;
            if donor_id != TaskId::NONE {
                if donor_on_queue {
                    if let Some(d) = ready.iter_mut().find(|s| s.id == donor_id) {
                        let rem = d
                            .spec
                            .budget
                            .burst_cycles
                            .saturating_sub(d.account.cycles_spent);
                        donor_remaining = rem.min(ceiling);
                        if donor_remaining > 0 {
                            d.account.add_debit(donor_remaining);
                            donor_debited_inline = true;
                        }
                    }
                } else {
                    donor_remaining = ceiling;
                }
            }

            let mut slot = ready.remove(pos).unwrap();
            if donor_remaining > 0 {
                slot.account.add_credit(donor_remaining);
                slot.donation = Some(DonationClaim {
                    donor: donor_id,
                    donor_meta,
                    cycles: donor_remaining,
                    cap: *cap,
                });
                if !donor_debited_inline {
                    stage_donor_debit(donor_id, donor_remaining);
                }
            }
            slot.awake.store(true, Ordering::Release);
            match placement {
                crate::donation::EnqueueDonee::HeadOfQueue => ready.push_front(slot),
                crate::donation::EnqueueDonee::BackOfQueue => ready.push_back(slot),
                // Refuse handled above.
                crate::donation::EnqueueDonee::Refuse => unreachable!(),
            }
            return Ok(());
        }
    }

    if !any_initialised {
        return Err(DonateError::NotReady);
    }
    Err(DonateError::TargetNotFound)
}

/// Settle the slot's pending donation claim before polling. Live
/// cap → consume the claim (credit was already applied at
/// `donate_to` time); revoked cap → refund both sides so the
/// donor and donee end up as they would have without the
/// donation.
fn settle_donation(slot: &mut TaskSlot) {
    if let Some(d) = slot.donation.take() {
        if d.cap.check_live().is_err() {
            slot.account.revert_credit(d.cycles);
            refund_donor(d.donor, d.cycles);
            // Inform the active donation policy that the donation
            // was revoked. The structural refund above is the
            // load-bearing side effect; this hook is informational
            // for policy-level accounting / telemetry. Done after
            // the structural work so an impl that re-enters
            // `current_donation_policy_name`-style observers sees
            // consistent state.
            crate::donation::notify_revoke(&d.donor_meta, d.cycles);
        }
    }
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

/// Diagnostic: total `wake` + `wake_by_ref` invocations across all
/// tasks. Lets a real-HW observer distinguish "wake_by_ref is never
/// fired" (waker plumbing broken or waker isn't reaching this
/// vtable) from "wake fires but the executor doesn't re-poll."
pub static WAKE_BY_REF_CALLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

unsafe fn wake_raw(data: *const ()) {
    WAKE_BY_REF_CALLS.fetch_add(1, Ordering::Relaxed);
    // wake-by-value: consume the Arc.
    // SAFETY: same as clone_raw; we own the refcount handed to us.
    let arc = unsafe { Arc::<AtomicBool>::from_raw(data as *const AtomicBool) };
    arc.store(true, Ordering::Release);
}

unsafe fn wake_by_ref_raw(data: *const ()) {
    WAKE_BY_REF_CALLS.fetch_add(1, Ordering::Relaxed);
    let ptr = data as *const AtomicBool;
    // SAFETY: caller still holds a live Waker (hence a live Arc), so
    // the AtomicBool behind `data` is valid for the duration of this
    // call.
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
        // Settle any pending donation claim before deciding to
        // drop. A revoked donation cap rolls back both sides; the
        // donee still polls (donation never happened semantics).
        settle_donation(&mut slot);
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
        // Stage-5 PKRS restore (Intel SDM Vol 3 §4.6.2.4):
        // re-establish the task's protection-key rights view
        // before re-entering its future. No-op when CR4.PKS is
        // off (pre-SPR Intel, AMD) or the slot has never yielded
        // before (saved_pkrs is None).
        #[cfg(target_arch = "x86_64")]
        if let Some(saved) = slot.saved_pkrs {
            if narf_arch::x86_64::pks::is_active() {
                // SAFETY: CR4.PKS is on (is_active() returned true);
                // WRMSR IA32_PKRS is well-defined.
                unsafe { narf_arch::x86_64::pks::restore(saved) };
            }
        }
        let poll_result = slot.task.as_mut().poll(&mut ctx);
        CURRENT_TASK.store(outer_task, Ordering::Release);
        *ACTIVE_USER_AS.lock() = outer_as;
        let elapsed = Instant::now().cycles_since(start);
        let outcome = slot.account.charge(elapsed, &slot.spec.budget);
        // Apply any donor-side debit that `donate_to` staged
        // while this task was off-queue (currently polling).
        let pending = drain_donor_debit(slot.id);
        if pending > 0 {
            slot.account.add_debit(pending);
        }
        // Stage-5 PKRS save: snapshot IA32_PKRS into the slot
        // so the next poll restores the same rights view.
        #[cfg(target_arch = "x86_64")]
        if narf_arch::x86_64::pks::is_active() {
            // SAFETY: see above.
            slot.saved_pkrs = Some(unsafe { narf_arch::x86_64::pks::save() });
        }
        narf_rcu::report_quiescent();
        match poll_result {
            Poll::Ready(()) => ready_this_round += 1,
            Poll::Pending => {
                // Stage-5 fair-share enforcement (§3.4).
                use crate::budget::ChargeOutcome;
                match outcome {
                    ChargeOutcome::Kill => continue,
                    ChargeOutcome::Demote => slot.spec.class = SchedClass::Idle,
                    ChargeOutcome::Throttle => {
                        slot.awake.store(false, Ordering::Release);
                    }
                    ChargeOutcome::Continue => {}
                }
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
        // Per-round drain of IRQ-deferred wakers. Must run every
        // round (not gated on ready_this_round == 0), because a
        // perpetually self-waking task (supervisor with
        // YieldTimeout) keeps ready > 0 and would otherwise
        // starve deferred wakes forever.
        let _ = narf_lib::deferred_wake::drain_and_wake();
        // Slot 21: run_until_empty round entry beacon. White → red
        // toggles each round. If this stays a single colour, the
        // executor never completes one round (wedged in first
        // task's poll). If it toggles but slot 22 (DrainTask poll
        // entry) doesn't, the task ahead of DrainTask never
        // returns Pending and the round never reaches DrainTask.
        narf_memory::beacon::paint(
            21,
            if (narf_time::now_cycles() >> 27) & 1 == 0 {
                0x00FF_FFFF
            } else {
                0x00FF_0000
            },
        );
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
            // Wave D: the pluggable `Scheduler` policy decides which
            // slot to dispatch next. Default is `FifoScheduler` — its
            // `pick_next` is pop_front, so this branch behaves
            // byte-for-byte like the pre-Wave-D inline pop. The
            // policy is consulted under the per-CPU queue lock; impls
            // must not allocate or re-enter the scheduler (see the
            // trait-level hot-path constraint comment in
            // `policy.rs`).
            let cpu_id = crate::affinity::CpuId(cpu as u32);
            let mut slot = {
                let mut q = READY[cpu].lock();
                let dq = q.as_mut().unwrap();
                match policy::pick_next_slot(cpu_id, dq) {
                    Some((_h, slot)) => slot,
                    None => break,
                }
            };

            // Wave-49fu: apply any deferred AS update that
            // `replace_address_space` queued while this slot was
            // off-queue (currently polling). Without this, an
            // execve-driven AS swap that fired during the prior
            // poll body only updated ACTIVE_USER_AS for the rest of
            // that round — the slot's own `addr_space` stayed at the
            // pre-execve value, and the next round's activate() +
            // ACTIVE_USER_AS publication would resurrect the stale
            // AS, mis-routing demand-paging into the wrong PML4 and
            // looping the user task on its first write to any
            // post-execve heap page.
            if let Some(new_as) = take_pending_slot_as(slot.id) {
                slot.addr_space = Some(new_as);
            }

            // Settle any pending donation claim before deciding to
            // drop. A revoked donation cap rolls back both sides;
            // the donee still polls (donation never happened
            // semantics).
            settle_donation(&mut slot);

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

            // Slot 17: user-task poll heartbeat — painted in
            // KERNEL AS, before `activate()` swaps CR3 to the
            // user's AS (which lacks the low-half identity map
            // that the FB phys lives in; a beacon paint after
            // activate would page-fault and the next kernel task
            // polled with stale CR3 would page-fault too).
            // Blue ↔ red toggle.
            if slot.addr_space.is_some() {
                use core::sync::atomic::{AtomicU64, Ordering as O};
                static N: AtomicU64 = AtomicU64::new(0);
                let v = N.fetch_add(1, O::Relaxed);
                let colour = if v & 1 == 0 { 0x0000_00FF } else { 0x00FF_0000 };
                narf_memory::beacon::paint(17, colour);
            }

            // Save the kernel per-AS register before activating
            // the user AS so we can swap back after `poll()`
            // returns. Without this, the next kernel task to be
            // polled runs with the stale user mapping register
            // active — any low-half access (FB phys, identity-
            // mapped MMIO, beacon paint) page-faults on x86_64.
            //
            // x86_64: the single CR3 holds both halves; leaving
            // it on the user AS is the actual bug we hit on Zen2
            // (init's user AS lacked the FB phys low-half map,
            // every subsequent kernel task faulted silently).
            //
            // aarch64: split TTBR0/TTBR1. Kernel always resolves
            // via TTBR1, so kernel tasks following a user task
            // are fine even without this restore. But two user
            // tasks back-to-back would inherit the previous one's
            // TTBR0 until their own activate() runs — same
            // save/restore shape prevents the user-vs-user leak
            // pre-emptively.
            #[cfg(target_arch = "x86_64")]
            let saved_cr3: u64 = if slot.addr_space.is_some() {
                let raw: u64;
                // SAFETY: Reading CR3 is an unprivileged-of-side-effects
                // ring-0 instruction with no memory operand; `nomem`/`nostack`
                // accurately describe it and `raw` receives the value.
                unsafe {
                    core::arch::asm!(
                        "mov {0}, cr3",
                        out(reg) raw,
                        options(nomem, nostack, preserves_flags),
                    );
                }
                raw
            } else {
                0
            };
            #[cfg(target_arch = "aarch64")]
            let saved_ttbr0: u64 = if slot.addr_space.is_some() {
                let raw: u64;
                // SAFETY: `mrs ttbr0_el1` reads the EL1 translation-table
                // base register; the scheduler runs at EL1 where this read
                // is unconditionally permitted. It has no memory operand,
                // so `nomem`/`nostack`/`preserves_flags` hold, and `raw`
                // receives the register value.
                unsafe {
                    core::arch::asm!(
                        "mrs {0}, ttbr0_el1",
                        out(reg) raw,
                        options(nomem, nostack, preserves_flags),
                    );
                }
                raw
            } else {
                0
            };

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
            // Stage-5 PKRS restore (Intel SDM Vol 3 §4.6.2.4):
            // re-establish the task's protection-key rights view
            // before re-entering its future.
            #[cfg(target_arch = "x86_64")]
            if let Some(saved) = slot.saved_pkrs {
                if narf_arch::x86_64::pks::is_active() {
                    // SAFETY: CR4.PKS is on (is_active() returned
                    // true); WRMSR IA32_PKRS is well-defined.
                    unsafe { narf_arch::x86_64::pks::restore(saved) };
                }
            }
            // Per-poll identification beacon — slot 18 cycles
            // through 8 palette colors keyed by a global counter.
            // When run_until_empty wedges inside one task's poll
            // (slot 21 stuck, slot 17 dark), this slot's color
            // tells you WHICH poll-count was the last one
            // attempted: red(0) → orange(1) → yellow(2) →
            // green(3) → blue(4) → cyan(5) → magenta(6) →
            // white(7) → wraps. Combined with knowing the rough
            // boot-order of spawn() calls (TPM init tasks
            // first, then power-monitor, then FB stuff, then
            // measured-boot, then heartbeat, then init/shell
            // last), pin the wedge.
            #[cfg(target_arch = "x86_64")]
            {
                use core::sync::atomic::{AtomicU64, Ordering as O};
                static POLL_N: AtomicU64 = AtomicU64::new(0);
                const PALETTE: [u32; 8] = [
                    0x00FF_0000, // red 0
                    0x00FF_8000, // orange 1
                    0x00FF_FF00, // yellow 2
                    0x0000_FF00, // green 3
                    0x0000_00FF, // blue 4
                    0x0000_FFFF, // cyan 5
                    0x00FF_00FF, // magenta 6
                    0x00FF_FFFF, // white 7
                ];
                let n = POLL_N.fetch_add(1, O::Relaxed);
                narf_memory::beacon::paint(18, PALETTE[(n as usize) & 7]);
            }
            let poll_result = slot.task.as_mut().poll(&mut ctx);
            CURRENT_TASK.store(0, Ordering::Release);
            *ACTIVE_USER_AS.lock() = None;
            // Restore kernel per-AS register — see save comment
            // above. Without this, every kernel task polled after
            // a user task runs with stale user-AS CR3 (x86_64)
            // and faults on any low-half access; on aarch64 two
            // back-to-back user tasks would inherit each other's
            // TTBR0 until their own activate() runs.
            #[cfg(target_arch = "x86_64")]
            if saved_cr3 != 0 {
                // SAFETY: `saved_cr3` was just read from CR3 in
                // kernel context above; writing it back is
                // identity-safe.
                unsafe {
                    core::arch::asm!(
                        "mov cr3, {0}",
                        in(reg) saved_cr3,
                        options(nomem, nostack, preserves_flags),
                    );
                }
            }
            #[cfg(target_arch = "aarch64")]
            if saved_ttbr0 != 0 {
                // SAFETY: `saved_ttbr0` was just read from
                // TTBR0_EL1 in kernel context above. The
                // architected sequence for a TTBR swap is MSR +
                // ISB; we also broadcast a TLBI VMALLE1IS to
                // clear stale Stage-1 TLB entries from the
                // intervening user-AS activation. This is the
                // same dance `aarch64::paging::write_ttbr0_el1`
                // performs internally, replicated here so we
                // don't pull a circular dep on `narf-memory`
                // from inside `narf-scheduler`'s hot path.
                unsafe {
                    core::arch::asm!(
                        "msr ttbr0_el1, {0}",
                        "isb",
                        "tlbi vmalle1is",
                        "dsb ish",
                        "isb",
                        in(reg) saved_ttbr0,
                        options(nomem, nostack, preserves_flags),
                    );
                }
            }
            let elapsed = Instant::now().cycles_since(start);
            let outcome = slot.account.charge(elapsed, &slot.spec.budget);

            // Apply any donor-side debit that `donate_to` staged
            // while this task was off-queue (currently polling).
            let pending = drain_donor_debit(slot.id);
            if pending > 0 {
                slot.account.add_debit(pending);
            }

            // Stage-5 PKRS save: snapshot IA32_PKRS into the slot
            // so the next poll restores the same rights view
            // (Intel SDM Vol 3 §4.6.2.4). Done on both Ready and
            // Pending; the Ready case drops the slot immediately
            // after so the save is redundant but keeps the
            // invariant uniform.
            #[cfg(target_arch = "x86_64")]
            if narf_arch::x86_64::pks::is_active() {
                // SAFETY: CR4.PKS is on; RDMSR(IA32_PKRS) is well-defined.
                slot.saved_pkrs = Some(unsafe { narf_arch::x86_64::pks::save() });
            }

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
                    // Stage-5 fair-share enforcement (§3.4): act on
                    // the `BudgetAccount::charge` outcome before
                    // re-enqueue.
                    use crate::budget::ChargeOutcome;
                    match outcome {
                        ChargeOutcome::Kill => {
                            // Drop the slot. `overruns` already
                            // ticked; no refund.
                            continue;
                        }
                        ChargeOutcome::Demote => {
                            // Hot cutover: mutate the slot's class
                            // to Idle so it only polls when no
                            // Normal/RealTime peer is runnable.
                            slot.spec.class = SchedClass::Idle;
                        }
                        ChargeOutcome::Throttle => {
                            // Clear awake so the next round skips
                            // this slot; only an external wake
                            // (timer, IRQ, peer-wake) revives it.
                            slot.awake.store(false, Ordering::Release);
                            let mut q = READY[cpu].lock();
                            q.as_mut().unwrap().push_back(slot);
                            continue;
                        }
                        ChargeOutcome::Continue => {}
                    }
                    // Did the poll itself self-wake? `yield_now()` and
                    // `SleepUntil`'s busy-poll fallback both call
                    // `cx.waker().wake_by_ref()` which flips awake
                    // back to true before Poll::Pending returns.
                    // Counting that as forward progress for this
                    // round is what keeps the executor alive on
                    // hosts where timer IRQs misfire (real-HW
                    // laptops where the LAPIC didn't enumerate
                    // cleanly, etc.) — without it, halt_until_irq
                    // sleeps forever and busy-polling futures stop
                    // making progress despite their self-wakes.
                    if slot.awake.load(Ordering::Acquire) {
                        ready_this_round += 1;
                    }
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
            // Drain any wakers that IRQ handlers stashed for
            // deferred execution. The IRQ paths (dispatch::on_irq's
            // vector-waker chain, timer_pump's pump_irq → wheel
            // wakers) can't call `Waker::wake()` directly — the
            // drop of the inner Arc can hit a Sleepable slab
            // dealloc, which the allocator's IRQ-context check
            // refuses. They push to the per-CPU deferred queue;
            // we drain + wake here, in non-IRQ context. This is
            // the load-bearing wake path for everything that
            // depends on IRQ delivery (xHCI completions,
            // keyboard IRQ1, HPET-driven wheel wakes).
            let n_drained = narf_lib::deferred_wake::drain_and_wake();
            if n_drained > 0 {
                // A drained wake may have flipped a slot's
                // awake flag — continue to the top of the outer
                // loop so we re-evaluate ready_this_round on the
                // updated state instead of falling into the
                // halt/spin idle path.
                continue;
            }
            // Idle path. Conservative on real hardware: trust the
            // wheel's deadline rather than `halt_until_irq` alone.
            //
            // Old behaviour: `halt_until_irq` and wait for a tick
            // IRQ to wake us. On hardware where the tick source
            // (LAPIC timer / HPET) doesn't actually deliver IRQs
            // for our allocated vectors — observed on AMD Renoir
            // 4700U: LAPIC vec 32 silently dropped, HPET via IOAPIC
            // also dropped — every Pending task with a wheel
            // deadline wedges forever.
            //
            // New behaviour: when the wheel has a pending deadline,
            // TSC-busy-poll `fire_due` up to that deadline (waking
            // the moment its waker's set), then loop. When the
            // wheel is empty, halt cleanly — no work to do, an
            // external IRQ is the only thing that can deliver new
            // work. The CPU-busy phase is bounded by the next
            // deadline (typically ms-scale).
            match narf_time::timer_wheel::next_deadline_cycles() {
                Some(deadline) => {
                    // Bound the busy phase: spin until the deadline
                    // passes OR an IRQ fires (interrupts are still
                    // enabled, so any IRQ also calls fire_due via
                    // the trap-handler fail-safe and updates the
                    // wheel).
                    let start = narf_time::now_cycles();
                    while narf_time::now_cycles() < deadline {
                        let _ = narf_time::timer_wheel::fire_due(narf_time::now_cycles());
                        // Bail out if any task became ready (an
                        // IRQ-driven wake fired during the spin).
                        if local_ready_count(cpu) > 0 {
                            break;
                        }
                        // Bound any single spin burst to ~1 ms of
                        // TSC progression so we don't get stuck if
                        // a deadline gets pushed back via
                        // refresh_waker mid-spin (cpns=2 → 2M
                        // cycles = 1 ms wall).
                        let elapsed = narf_time::now_cycles().wrapping_sub(start);
                        if elapsed > 2_000_000 {
                            break;
                        }
                        core::hint::spin_loop();
                    }
                    // Final fire_due after the spin in case the
                    // deadline passed in our last iteration.
                    let _ = narf_time::timer_wheel::fire_due(narf_time::now_cycles());
                }
                None => {
                    // Wheel empty + no ready tasks + no steal
                    // target. Nothing the executor can do — wait
                    // for an external IRQ to deliver new work.
                    narf_arch::halt_until_irq();
                }
            }
        }
    }
}

/// Number of slots whose `awake` flag is currently set on `cpu`.
/// Used by the idle path to bail out of TSC busy-poll when an IRQ
/// wakes something during the spin.
fn local_ready_count(cpu: usize) -> usize {
    let q = READY[cpu].lock();
    match q.as_ref() {
        Some(d) => d.iter().filter(|s| s.awake.load(Ordering::Acquire)).count(),
        None => 0,
    }
}

/// Snapshot per-CPU ready-queue depths. Returns one entry per
/// online CPU as `(cpu_id, len)`. Diagnostic surface — the FB
/// status panel renders this so a wedged executor is visible
/// at a glance (`sched: c0=42 c1=0 c2=0 …` means BSP is hoarding
/// while APs idle).
pub fn cpu_queue_depths() -> alloc::vec::Vec<(u32, usize)> {
    let mut out = alloc::vec::Vec::new();
    for (cpu, ready) in READY.iter().enumerate().take(narf_lib::percpu::MAX_CPUS) {
        if !narf_lib::smp::is_online(cpu as u32) {
            continue;
        }
        let len = ready.lock().as_ref().map(|d| d.len()).unwrap_or(0);
        out.push((cpu as u32, len));
    }
    out
}

/// NUMA node ID of the executing CPU, or `None` when SRAT
/// topology wasn't published. Thin wrapper over
/// `narf_acpi::cpu_node(current_cpu())` so callers in this crate
/// (and downstream introspection) name the concept once. The
/// work-stealing search uses this to prefer same-node victims —
/// see `arch/specification/smp-topology.md` for the topology API.
pub fn local_node() -> Option<u32> {
    let cpu = narf_lib::percpu::current_cpu();
    if cpu >= narf_lib::percpu::MAX_CPUS {
        return None;
    }
    narf_acpi::cpu_node(cpu as u32)
}

/// Try to steal one task from another CPU's queue. Returns `true` if
/// a slot was moved onto `cpu`'s queue.
///
/// Victim ordering and per-task eligibility are delegated to the
/// installed `steal::StealStrategy` (Wave F). The default
/// `NumaAwareSteal` reproduces the pre-Wave-F two-phase
/// same-NUMA-node-first / cross-node round-robin scan byte-for-byte;
/// alternative strategies (e.g. `RandomSteal`) can be installed under
/// a `Cap<Steal, Grant>`.
///
/// **Lock order**: snapshot the `Arc<dyn StealStrategy>` out of
/// `steal::STEAL` first, drop that lock, then walk victims. Calling
/// the strategy is allowed while the `READY[victim]` lock is held
/// (for the `allow_steal` check) because the strategy is a *cloned-
/// out* Arc — STEAL itself is not held during the queue walk, so
/// there is no STEAL → READY[victim] inversion.
///
/// No-op when `STEAL_ENABLED` is false (boot default). Callers in the
/// idle path treat a `false` return as "nothing to do, return".
fn try_steal_one(cpu: usize) -> bool {
    if !STEAL_ENABLED.load(Ordering::Acquire) {
        return false;
    }
    let strategy = match crate::steal::snapshot() {
        Some(s) => s,
        // No strategy installed (pre-`init` very early boot). The
        // idle path treats this as "no steal", same as STEAL_ENABLED
        // being false.
        None => return false,
    };

    // Build the online-minus-thief set the strategy will permute.
    let max = narf_lib::percpu::MAX_CPUS;
    let mut online: alloc::vec::Vec<crate::affinity::CpuId> = alloc::vec::Vec::with_capacity(max);
    for v in 0..max {
        if v == cpu {
            continue;
        }
        if !narf_lib::smp::is_online(v as u32) {
            continue;
        }
        online.push(crate::affinity::CpuId(v as u32));
    }

    let thief = crate::affinity::CpuId(cpu as u32);
    let victims = strategy.order_victims(thief, &online);
    for v in victims {
        if try_steal_from(v.0 as usize, cpu, strategy.as_ref()) {
            return true;
        }
    }
    false
}

/// Inner helper: try to move one strategy-permitted slot from
/// `victim`'s queue onto `cpu`'s queue. Returns `true` on success.
/// The `strategy` reference is the snapshot-out Arc from
/// `try_steal_one`; it's safe to call `allow_steal` here because the
/// STEAL slot lock is no longer held.
fn try_steal_from(victim: usize, cpu: usize, strategy: &dyn crate::steal::StealStrategy) -> bool {
    let thief = crate::affinity::CpuId(cpu as u32);
    let stolen = {
        let mut g = READY[victim].lock();
        let q = match g.as_mut() {
            Some(q) => q,
            None => return false,
        };
        // Linear scan for the first slot the strategy permits. The
        // default impl respects `affinity.allowed`; custom impls may
        // refuse on class/priority/id.
        let pos = q.iter().position(|s| {
            let meta = crate::policy::TaskMeta {
                id: s.id,
                priority: s.spec.priority,
                class: s.spec.class,
                affinity: s.spec.affinity,
            };
            strategy.allow_steal(thief, &meta)
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

/// Background-pump registry — fn-pointer hooks that scheduler-blocking
/// busy-waits should tick periodically so subsystems whose forward
/// progress depends on regular polling (FB drain, cursor renderer,
/// future audio drain) don't freeze while a sync caller spins on
/// hardware.
///
/// Shape: fixed-size lock-free static array of `usize` (transmuted
/// `fn()` pointers). Registration is boot-only + idempotent on the
/// same fn pointer (registering twice fills two slots — callers
/// register exactly once per subsystem).
///
/// Used by:
/// - `userspace::handlers::sys_sleep`'s busy-wait
/// - Driver sync spin loops (NVMe, AHCI, NIC TX poll) — added so
///   a stuck device doesn't freeze the cursor / FB / serial
pub mod sleep_pumps {
    use core::sync::atomic::{AtomicUsize, Ordering};

    const MAX_PUMPS: usize = 8;
    pub type Pump = fn();

    static SLOTS: [AtomicUsize; MAX_PUMPS] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];

    pub fn register(p: Pump) {
        let p_addr = p as usize;
        for slot in SLOTS.iter() {
            if slot
                .compare_exchange(0, p_addr, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
        panic!("sleep_pumps: registry full ({} slots)", MAX_PUMPS);
    }

    pub fn run() {
        for slot in SLOTS.iter() {
            let p = slot.load(Ordering::Acquire);
            if p == 0 {
                return;
            }
            // SAFETY: slot was populated by `register` with a
            // valid `Pump` (`fn()`), and the static lifetime is
            // the kernel's.
            let f: Pump = unsafe { core::mem::transmute(p) };
            f();
        }
    }

    #[doc(hidden)]
    pub fn __reset_for_test() {
        for slot in SLOTS.iter() {
            slot.store(0, Ordering::Release);
        }
    }
}

/// Bounded busy-poll that ticks `sleep_pumps` periodically so the
/// FB cursor / serial drain / audio pump stay alive during driver
/// reset/init busy-waits. Returns true if `done` returned true
/// before `max_iters`, false on timeout.
///
/// The right primitive for "wait for an MMIO bit to flip" loops in
/// hardware drivers: pre-fix every NIC + USB controller hand-
/// rolled the spin loop, none ticked sleep_pumps, and a slow
/// device init froze the visible system for the duration. Default
/// every-4096-iters tick is invisible at MMIO read speeds and
/// pump cost is trivial (a few atomic loads + indirect calls).
#[inline]
pub fn responsive_spin<F: FnMut() -> bool>(mut done: F, max_iters: u32) -> bool {
    for i in 0..max_iters {
        if done() {
            return true;
        }
        if i & 0xFFF == 0 {
            sleep_pumps::run();
        }
        core::hint::spin_loop();
    }
    false
}

/// Deadline-driven counterpart to `responsive_spin`. Polls
/// `done()` until it returns true or the wall-clock `deadline`
/// passes; same `sleep_pumps`-tick cadence in between. Use this
/// when the wait should be bounded by real wall time rather than
/// an arbitrary iteration count that varies with CPU clock —
/// e.g. spec-defined "controller must respond within 100 ms" or
/// "hub reset takes max 50 ms".
///
/// Returns true if `done` succeeded before the deadline, false
/// on timeout.
#[inline]
pub fn responsive_spin_until<F: FnMut() -> bool>(
    mut done: F,
    deadline: narf_time::Deadline,
) -> bool {
    let mut i: u32 = 0;
    loop {
        if done() {
            return true;
        }
        if deadline.expired() {
            return false;
        }
        if i & 0xFFF == 0 {
            sleep_pumps::run();
        }
        core::hint::spin_loop();
        i = i.wrapping_add(1);
    }
}

/// Drive a future to completion synchronously from outside the
/// async executor. Polls the future; on Pending, runs the
/// registered `sleep_pumps` (so cursor/FB/serial keep moving) and
/// **idles to `halt_until_irq`** until something delivers a wake.
/// Returns the future's output.
///
/// The right primitive for **sync→async bridges in normal kernel
/// context**: any sync subsystem (BlockDeviceSync, FsOps' sync
/// wrappers, the eventual VFS sync paths) that wants to call into
/// an already-async driver path. Drivers should expose async
/// functions (e.g. NVMe's submit_io_irq_async) and let block_on
/// bridge instead of every driver hand-rolling spin loops.
///
/// **Constraints:**
/// - Caller MUST NOT hold any `IrqSafeSpinLock`. Those locks
///   disable IRQs while held, and `halt_until_irq` waits for an
///   IRQ — would deadlock forever. Use [`block_on_spin`] for the
///   IRQ-disabled / lock-held variant.
/// - Caller MUST NOT be inside an executor poll. block_on doesn't
///   yield to the executor; nested invocation deadlocks the
///   polling loop. (No runtime check; callers are expected to
///   know which context they're in.)
/// - The awaited future must be IRQ-driven or self-waking. A
///   future that depends on another scheduler task to make
///   progress will hang because block_on doesn't run the executor.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    block_on_inner(fut, /* allow_halt = */ true)
}

/// Spin-only sync→async bridge. Same shape as [`block_on`] but
/// never calls `halt_until_irq`, so safe to call with IRQs
/// disabled (any caller holding an `IrqSafeSpinLock`, panic
/// dump path, IRQ handler, SMP startup before the BSP timer is
/// armed). Trade-off: 100% CPU during the wait. Sleep-pumps
/// still tick so cursor/FB/serial don't freeze under the spin.
///
/// Same async-task and IRQ-driven-future constraints as
/// [`block_on`].
pub fn block_on_spin<F: Future>(fut: F) -> F::Output {
    block_on_inner(fut, /* allow_halt = */ false)
}

#[inline]
fn block_on_inner<F: Future>(mut fut: F, allow_halt: bool) -> F::Output {
    use core::pin::Pin;
    use core::task::{Context, Poll};
    // Defensive: refuse to run the halting variant from inside an
    // executor poll. The executor publishes CURRENT_TASK before
    // polling and clears after; if it's non-zero we're inside
    // someone else's poll body, and recursing into block_on with
    // halt would deadlock the polling loop. The spinning variant
    // (block_on_spin) cannot deadlock the executor since it
    // busy-polls instead of calling halt_until_irq, and its
    // documented callers (panic dump, IRQ handlers, lock holders,
    // SMP startup, sleep_pump re-entry) may legitimately observe
    // CURRENT_TASK != 0.
    if allow_halt && CURRENT_TASK.load(Ordering::Acquire) != 0 {
        panic!(
            "narf_scheduler::block_on called from inside executor poll \
             (CURRENT_TASK != 0) — would deadlock the polling loop. \
             Use yield_now().await or restructure the caller as async."
        );
    }
    // Pin the future on the stack. Sound because `fut` is owned
    // by this function's stack frame and Rust prevents moving it
    // out from under our `&mut` for the function's lifetime.
    // SAFETY: `fut` is a unique mutable binding we never move
    // again until the future completes.
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    let awake = Arc::new(AtomicBool::new(true));
    let waker = make_waker(awake.clone());
    let mut ctx = Context::from_waker(&waker);
    loop {
        // Reset awake before polling so a wake landing during
        // the poll body is observable on the next iteration.
        awake.store(false, Ordering::Release);
        match fut.as_mut().poll(&mut ctx) {
            Poll::Ready(v) => return v,
            Poll::Pending => {
                // Tick the sleep pumps so cursor/FB/serial stay
                // alive while we wait for an IRQ wake or self-
                // wake from the future's busy-poll.
                sleep_pumps::run();
                if allow_halt && !awake.load(Ordering::Acquire) {
                    // Cooperative path: idle until something
                    // fires an IRQ. IRQ handler (or the future's
                    // own wake_by_ref) flips awake, then
                    // halt_until_irq returns.
                    narf_arch::halt_until_irq();
                } else {
                    // Spin path: re-poll immediately. Cheap
                    // back-off via spin_loop hint.
                    core::hint::spin_loop();
                }
            }
        }
    }
}
