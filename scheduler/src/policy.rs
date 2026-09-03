//! Pluggable scheduler-policy seam — Wave D of the modular-cores plan
//! (`docs/PLUGGABILITY.md`). See
//! [`specification/scheduling-policies.md`](../specification/scheduling-policies.md)
//! for the policy-authoring guide (core/policy split, the method contract, the
//! `vruntime` metadata, and the EEVDF-lite default with its Linux lineage).
//! Mirrors `power::GovernorPolicy` shape:
//!
//! - `pub trait Scheduler: Send + Sync + 'static` defines the policy.
//! - one generation-stamped CPU-local slot holds the active impl per CPU;
//!   dispatch takes no global policy lock.
//! - `install_scheduler(&cap, impl)` performs a lifecycle-hooked rolling swap
//!   under a `Cap<SchedPolicy, Grant>` check.
//! - Default `ClassScheduler` provides strict Linux-like class ordering.
//! - Alternative `PriorityScheduler` picks the slot with the lowest
//!   `Priority::raw()` value (numerically lower = scheduling-higher;
//!   see `Priority::HIGH`).
//!
//! The `RunQueue` / `TaskHandle` / `TaskMeta` projections expose the
//! per-CPU `VecDeque<TaskSlot>` to policy impls without leaking the
//! private `TaskSlot` body. `RunQueue` itself is constructed in
//! `lib.rs` (where `TaskSlot` is visible) and the projection methods
//! are implemented here against the `pub(crate)` field.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::any::{Any, TypeId};
use core::fmt;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::affinity::{Affinity, CpuId};
use crate::budget::{BudgetAccount, BudgetEligibility, BudgetView, ResourceBudget};
use crate::priority::{Priority, SchedClass, WorkKind};
use crate::TaskId;

/// Authority to install a scheduler policy. Cap-gated via
/// `install_scheduler`; revocation is observed lazily on the next
/// install attempt.
#[derive(Copy, Clone, Debug)]
pub struct SchedPolicy;

impl CapType for SchedPolicy {
    const KIND: CapKind = CapKind::SchedPolicy;
}

/// Errors `install_scheduler` can return.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedulerError {
    /// The install cap has been revoked.
    CapRevoked,
    /// No scheduler is installed — `init()` hasn't run yet.
    NotInstalled,
    /// A concurrently installed newer generation won the publication race.
    /// The caller's policy has already been detached from every CPU on which
    /// it was briefly visible and will receive `on_uninstall` once its last
    /// reference is released.
    Superseded,
}

impl From<CapError> for SchedulerError {
    fn from(_: CapError) -> Self {
        SchedulerError::CapRevoked
    }
}

/// Opaque handle into the per-CPU ready queue. Returned by
/// `RunQueue::iter_meta` and reported back from `Scheduler::pick_next`.
/// The body is the underlying `TaskId::raw()`
/// of the slot the handle names — stable across re-queues so a policy
/// can refer to a task it previously observed.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskHandle(pub(crate) u64);

impl TaskHandle {
    /// Construct from a raw `TaskId`. Crate-internal helper.
    #[inline]
    pub(crate) const fn from_id(id: TaskId) -> Self {
        TaskHandle(id.raw())
    }

    /// Underlying task id. Useful for policies that want to log or
    /// trace the slot they just picked.
    #[inline]
    pub const fn task_id(self) -> TaskId {
        TaskId(self.0)
    }
}

/// Read-only metadata snapshot exposed to policy impls. Mirrors the
/// scheduling-relevant slice of `TaskSpec` plus the slot's `id`.
#[derive(Copy, Clone, Debug)]
pub struct TaskMeta {
    pub id: TaskId,
    /// What kind of execution this slot represents. The core copies this from
    /// admitted task metadata; it is not an accounting identity or authority.
    pub work_kind: WorkKind,
    pub priority: Priority,
    pub class: SchedClass,
    /// Absolute monotonic-cycle deadline used only as an equal-priority
    /// realtime tie-breaker. `None` is ordered after a concrete deadline.
    pub deadline_cycles: Option<u64>,
    /// Immutable copy of the configured budget. Mutating this copy in an
    /// out-of-tree policy cannot alter the core-owned task budget.
    pub budget: ResourceBudget,
    /// Immutable snapshot of consumption at policy-dispatch time.
    pub account: BudgetAccount,
    /// Core-computed periodic eligibility. Policies can order work within an
    /// eligibility tier but cannot make throttled work dispatchable.
    pub budget_state: BudgetView,
    /// Whether the task is currently signalled runnable. Policies should not
    /// choose parked work while runnable work exists; the core validates this
    /// rule even for buggy external implementations.
    pub runnable: bool,
    pub affinity: Affinity,
    /// True when the slot carries an address space (a user /
    /// process-bearing task). Such tasks must never be stolen across
    /// CPUs: the global single-in-flight-user-task assumptions
    /// (`CURRENT`, `CURRENT_TASK`, `ACTIVE_USER_AS`) make full
    /// user-task SMP a separate effort. The default steal strategy
    /// refuses these unconditionally — a hard safety floor that holds
    /// even if a user task were mis-pinned to `Affinity::any()`.
    pub addr_space: bool,
    /// Accumulated virtual runtime in TSC cycles (EEVDF-lite; see
    /// `specification/scheduling-policies.md` §4). Frozen while parked, so a
    /// long-slept task reads a low value relative to the CPU's `VFLOOR` — the
    /// sleeper credit an eligibility policy (`EevdfScheduler`) uses to order
    /// picks and decide wake-preemption. Read-only projection of core state.
    pub vruntime: u64,
}

impl TaskMeta {
    pub(crate) fn from_slot(slot: &crate::TaskSlot) -> Self {
        Self::from_slot_at(slot, narf_time::now_cycles())
    }

    /// Like [`from_slot`](Self::from_slot) but reuses a caller-supplied
    /// timestamp instead of reading the cycle counter. `pick_next` projects
    /// EVERY queued slot on each dispatch, so calling `now_cycles()` inside the
    /// per-slot projection cost one rdtsc per queued task per pick (a top
    /// dispatch hotspot under a deep run queue). Hoisting it to one read per
    /// scan also evaluates every slot's budget eligibility at the SAME instant,
    /// which is more consistent than staggering it across the walk.
    pub(crate) fn from_slot_at(slot: &crate::TaskSlot, now: u64) -> Self {
        Self {
            id: slot.id,
            work_kind: slot.spec.work_kind,
            priority: slot.spec.priority,
            class: slot.spec.class,
            deadline_cycles: slot.spec.budget.deadline_cycles,
            budget: slot.spec.budget,
            account: slot.account,
            budget_state: slot.account.view(now, &slot.spec.budget),
            runnable: slot.awake.flag.load(Ordering::Acquire),
            affinity: slot.spec.affinity,
            addr_space: slot.addr_space.is_some(),
            vruntime: slot.vruntime,
        }
    }
}

/// Snapshot of the task currently running on a CPU, published by the core at
/// dispatch and handed to [`Scheduler::wakeup_preempt`]. The running task's
/// slot is detached from the queue during its poll, so this is how a policy
/// sees the runner. `vdeadline` is the runner's EEVDF virtual-deadline
/// protection horizon (`vruntime`-at-dispatch + base slice); an eligibility
/// policy preempts a wake only when the wakee is more eligible than this. See
/// `specification/scheduling-policies.md` §5.
#[derive(Copy, Clone, Debug)]
pub struct CurrentTask {
    pub id: TaskId,
    pub class: SchedClass,
    /// Virtual runtime at dispatch, in TSC cycles.
    pub vruntime: u64,
    /// Protected virtual deadline = `vruntime`-at-dispatch + base slice.
    pub vdeadline: u64,
}

/// Per-CPU scheduling context handed to a policy's decision hooks. Assembled by
/// the core from cached per-CPU state (the dispatch-time [`CurrentTask`] snapshot
/// plus the CPU's virtual-time floor) — a `Copy` view, never a heap allocation
/// and never rebuilt from the task slot. Bundling these means a policy reads
/// `ctx.vfloor` / `ctx.current` directly instead of calling back into the core,
/// and new per-CPU scheduling state can be added here without changing every
/// hook signature.
#[derive(Copy, Clone, Debug)]
pub struct CpuSchedContext {
    pub cpu: CpuId,
    /// This CPU's EEVDF virtual-time floor (see
    /// `specification/scheduling-policies.md` §4).
    pub vfloor: u64,
    /// Snapshot of the task currently running on `cpu`.
    pub current: CurrentTask,
    /// Cycles the running task has executed since its current dispatch. Lets a
    /// policy apply RUN_TO_PARITY slice protection (don't preempt the runner
    /// until it has consumed a base slice) — the batching guard that keeps a
    /// cooperative producer/consumer from context-switching on every wake.
    pub elapsed: u64,
}

/// Lean per-slot projection for eligibility policies (`EevdfScheduler`) — only
/// the fields a dispatch/wake decision needs, WITHOUT materialising the full
/// [`TaskMeta`] (which copies the budget, account, and view). Produced by
/// [`RunQueue::iter_sched`], which computes each slot's eligibility tier once
/// with a single shared timestamp, so an eligibility scan pays no per-slot
/// budget/account copy. `Copy`, so a scan never allocates.
#[derive(Copy, Clone, Debug)]
pub struct SchedRow {
    pub handle: TaskHandle,
    pub class: SchedClass,
    pub priority: Priority,
    /// Core-computed periodic eligibility tier at scan time.
    pub eligibility: BudgetEligibility,
    pub runnable: bool,
    /// True for user / process-bearing tasks (never stolen cross-CPU).
    pub addr_space: bool,
    /// Accumulated virtual runtime in TSC cycles (see `TaskMeta::vruntime`).
    pub vruntime: u64,
}

/// Why a task entered a policy's CPU-local queue ownership.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TaskEnqueueReason {
    Admitted,
    Requeued,
    Migrated,
    PolicyReplacement,
}

/// Why a task left a policy's CPU-local queue ownership.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TaskDequeueReason {
    Selected,
    Migrated,
    PolicyReplacement,
}

/// Balanced notification that a task entered or left one CPU policy's
/// selectable set. Metadata is copied; no queue node or execution state is
/// exposed.
#[derive(Copy, Clone, Debug)]
pub enum TaskQueueEvent {
    Enqueued {
        task: TaskMeta,
        reason: TaskEnqueueReason,
    },
    Dequeued {
        task: TaskMeta,
        reason: TaskDequeueReason,
    },
}

/// Copied scheduler-core state supplied on a CPU's transition to idle.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuIdleMeta {
    pub queued: usize,
    pub parked: usize,
    pub throttled: usize,
    pub borrowable: usize,
    pub next_budget_replenishment: Option<u64>,
}

/// Core-observed CPU scheduler state. `Starting` and `Draining` bracket
/// hot-plug transitions; `Idle`/`Active` are executor run-state transitions.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum CpuState {
    #[default]
    Offline = 0,
    Starting = 1,
    Active = 2,
    Idle = 3,
    Draining = 4,
}

impl CpuState {
    fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Starting,
            2 => Self::Active,
            3 => Self::Idle,
            4 => Self::Draining,
            _ => Self::Offline,
        }
    }
}

/// Edge-triggered state-change notification delivered without a run-queue
/// lock held. `idle` is populated only when entering `CpuState::Idle`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CpuStateChange {
    pub previous: CpuState,
    pub current: CpuState,
    pub idle: Option<CpuIdleMeta>,
}

/// Read-only borrow of one CPU's ready queue, scoped to a single
/// `pick_next` call. The interior `VecDeque<TaskSlot>` is private to
/// the scheduler crate — policies see only immutable metadata.
///
/// A policy returns an opaque [`TaskHandle`]. The executor validates that the
/// handle still names a candidate and performs the removal itself. Policy code
/// can therefore never detach, drop, duplicate, or reorder a core-owned task
/// slot.
pub struct RunQueue<'a> {
    pub(crate) inner: &'a VecDeque<crate::TaskSlot>,
}

impl<'a> fmt::Debug for RunQueue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunQueue")
            .field("len", &self.inner.len())
            .finish()
    }
}

impl<'a> RunQueue<'a> {
    /// Wrap an immutable `VecDeque<TaskSlot>` borrow into a `RunQueue`
    /// projection. Crate-internal; callers go through
    /// `pick_next_for_cpu`.
    #[inline]
    pub(crate) fn projected(q: &'a VecDeque<crate::TaskSlot>) -> Self {
        Self { inner: q }
    }

    /// Number of slots currently on the queue.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True iff the queue has no slots.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate metadata for every queued slot in queue order. Does
    /// not allocate.
    pub fn iter_meta(&self) -> impl Iterator<Item = (TaskHandle, TaskMeta)> + '_ {
        // One cycle-counter read for the whole scan, not one per slot: a policy
        // `pick_next` walks every queued slot, so this turns N rdtsc reads per
        // dispatch into one and evaluates all slots at a single instant.
        let now = narf_time::now_cycles();
        self.inner.iter().map(move |slot| {
            (
                TaskHandle::from_id(slot.id),
                TaskMeta::from_slot_at(slot, now),
            )
        })
    }

    /// Lean projection for eligibility policies (see [`SchedRow`]). Like
    /// [`iter_meta`](Self::iter_meta) but yields only the decision fields, with
    /// NO per-slot `TaskMeta` (budget/account/view) copy — an EevdfScheduler
    /// pick/preempt scan is O(n) in cheap `Copy` rows. One shared `now_cycles()`
    /// for the whole scan. Does not allocate.
    pub fn iter_sched(&self) -> impl Iterator<Item = SchedRow> + '_ {
        let now = narf_time::now_cycles();
        self.inner.iter().map(move |slot| SchedRow {
            handle: TaskHandle::from_id(slot.id),
            class: slot.spec.class,
            priority: slot.spec.priority,
            eligibility: slot.account.view(now, &slot.spec.budget).eligibility,
            runnable: slot.awake.flag.load(Ordering::Acquire),
            addr_space: slot.addr_space.is_some(),
            vruntime: slot.vruntime,
        })
    }

    /// Handle for the front-most candidate, without detaching it.
    #[inline]
    pub fn front(&self) -> Option<TaskHandle> {
        self.inner.front().map(|slot| TaskHandle::from_id(slot.id))
    }
}

/// Pluggable scheduler policy. Implementors decide which slot to poll
/// next; the executor owns slot lifecycles and IRQ-safety guarantees.
///
/// **Hot-path constraint**: `pick_next` is called once per dispatched
/// task with the per-CPU queue lock held. Impls must not allocate,
/// must not re-enter the scheduler, and must not touch any
/// `IrqSafeSpinLock` that an IRQ handler could be waiting on. The
/// detached slot is owned by the executor for the duration of the
/// poll and re-enqueued after.
pub trait Scheduler: Any + Send + Sync + 'static {
    /// Stable identifier — surfaced by `current_scheduler_name`.
    fn name(&self) -> &'static str;

    /// Choose one slot from `queue`. Returning `None`, a stale handle, or a
    /// wrong-tier task causes a core-side fallback to the first candidate in
    /// the highest available eligibility tier; policy code cannot strand
    /// core-owned work or override throttling.
    fn pick_next(&self, cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle>;

    /// Decide whether the task currently running on `cpu` (`current`) should
    /// cede at its next cooperative preemption point because a wake just made a
    /// peer in `queue` runnable. NARF's analogue of Linux
    /// `check_preempt_wakeup_fair` (`kernel/sched/fair.c`). Consulted ONCE per
    /// wake, at the waker's syscall-exit — never on a no-wake exit — so its cost
    /// is paid only when a wake actually happened.
    ///
    /// Default `false`: a policy without an eligibility model (FIFO, priority,
    /// strict-class) does not wake-preempt, preserving its batching. An
    /// EEVDF-style policy overrides this to preempt iff the wakee is more
    /// eligible than the runner's protected `vdeadline`. The core still owns the
    /// mechanism (the sticky per-CPU request, the syscall-exit yield); this only
    /// decides yes/no. See `specification/scheduling-policies.md` §5.
    fn wakeup_preempt(&self, _ctx: &CpuSchedContext, _queue: &RunQueue<'_>) -> bool {
        false
    }

    /// Called once before this policy is published to any CPU. Constructors
    /// should perform fallible setup before `install_scheduler`; lifecycle
    /// callbacks themselves are infallible and may allocate but must not
    /// re-enter scheduler policy installation.
    fn on_install(&self) {}

    /// Called before this policy becomes selectable on `cpu`.
    fn on_cpu_attach(&self, _cpu: CpuId) {}

    /// Called after `cpu` can no longer enter this policy and all of that
    /// CPU's in-flight policy callbacks have returned.
    fn on_cpu_detach(&self, _cpu: CpuId) {}

    /// Called for every transition into or out of this policy's CPU-local
    /// selectable set. Events are serialized with `pick_next` on that CPU and
    /// balanced across dispatch, migration, and policy replacement. The core
    /// remains the source of truth; implementations must not allocate, block,
    /// or re-enter the scheduler from this callback.
    fn on_task_queue_event(&self, _cpu: CpuId, _event: TaskQueueEvent) {}

    /// Called once after the policy has been detached from every CPU and its
    /// final in-flight callback/reference has completed.
    fn on_uninstall(&self) {}

    /// Notification after a CPU changes scheduler state. The core retains
    /// authority over hot-plug, stealing, deadlines, and architecture halt;
    /// this callback is observational and must not block or re-enter the
    /// scheduler.
    fn on_cpu_state_change(&self, _cpu: CpuId, _change: CpuStateChange) {}
}

/// The in-tree stateless policies inherit the default no-op queue-event hook.
/// Avoid materialising a full `TaskMeta` (including an RDTSC-backed budget
/// snapshot) merely to make that no-op virtual call on every dequeue/requeue.
/// External policies remain observable by default.
#[inline]
pub(crate) fn observes_queue_events(scheduler: &dyn Scheduler) -> bool {
    let kind = scheduler.type_id();
    kind != TypeId::of::<FifoScheduler>()
        && kind != TypeId::of::<PriorityScheduler>()
        && kind != TypeId::of::<ClassScheduler>()
        && kind != TypeId::of::<crate::eevdf::EevdfScheduler>()
}

/// First-in-first-out scheduler — today's stage-3+ behaviour.
#[derive(Copy, Clone, Debug, Default)]
pub struct FifoScheduler;

impl Scheduler for FifoScheduler {
    fn name(&self) -> &'static str {
        "fifo"
    }

    fn pick_next(&self, _cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle> {
        queue
            .iter_meta()
            .find_map(|(handle, meta)| {
                (meta.runnable && meta.budget_state.eligibility == BudgetEligibility::Eligible)
                    .then_some(handle)
            })
            .or_else(|| {
                queue.iter_meta().find_map(|(handle, meta)| {
                    (meta.runnable
                        && meta.budget_state.eligibility == BudgetEligibility::Borrowable)
                        .then_some(handle)
                })
            })
            .or_else(|| queue.front())
    }
}

/// Priority-aware scheduler: picks the slot with the lowest
/// `Priority::raw()` value (numerically lower = scheduling-higher;
/// `Priority::HIGH == Priority(-10)`). Ties resolved by queue order
/// (first wins) so FIFO semantics survive among equal-priority peers.
#[derive(Copy, Clone, Debug, Default)]
pub struct PriorityScheduler;

impl Scheduler for PriorityScheduler {
    fn name(&self) -> &'static str {
        "priority"
    }

    fn pick_next(&self, _cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle> {
        let mut best: Option<(TaskHandle, TaskMeta)> = None;
        for (h, meta) in queue.iter_meta() {
            if !meta.runnable || meta.budget_state.eligibility == BudgetEligibility::Throttled {
                continue;
            }
            match best {
                None => best = Some((h, meta)),
                Some((_, current))
                    if (meta.budget_state.eligibility == BudgetEligibility::Eligible
                        && current.budget_state.eligibility == BudgetEligibility::Borrowable)
                        || (meta.budget_state.eligibility == current.budget_state.eligibility
                            && meta.priority.raw() < current.priority.raw()) =>
                {
                    best = Some((h, meta));
                }
                _ => {}
            }
        }
        best.map(|(h, _)| h)
    }
}

/// Linux-like strict class dispatcher. Realtime outranks Interactive,
/// Default, Batch, and Idle. Within a class, numerically lower priority wins;
/// equal-priority realtime tasks use the earliest concrete deadline as a
/// tie-breaker, then preserve queue FIFO order.
#[derive(Copy, Clone, Debug, Default)]
pub struct ClassScheduler;

impl Scheduler for ClassScheduler {
    fn name(&self) -> &'static str {
        "class"
    }

    fn pick_next(&self, _cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle> {
        let mut best: Option<(TaskHandle, TaskMeta)> = None;
        for (handle, meta) in queue.iter_meta() {
            if !meta.runnable || meta.budget_state.eligibility == BudgetEligibility::Throttled {
                continue;
            }
            let replace = match best {
                None => true,
                Some((_, current)) => {
                    let eligibility_rank = |value| match value {
                        BudgetEligibility::Eligible => 2,
                        BudgetEligibility::Borrowable => 1,
                        BudgetEligibility::Throttled => 0,
                    };
                    if meta.budget_state.eligibility != current.budget_state.eligibility {
                        eligibility_rank(meta.budget_state.eligibility)
                            > eligibility_rank(current.budget_state.eligibility)
                    } else if meta.class.rank() != current.class.rank() {
                        meta.class.rank() > current.class.rank()
                    } else if meta.priority != current.priority {
                        meta.priority.raw() < current.priority.raw()
                    } else if meta.class == SchedClass::Realtime {
                        match (meta.deadline_cycles, current.deadline_cycles) {
                            (Some(candidate), Some(incumbent)) => candidate < incumbent,
                            (Some(_), None) => true,
                            _ => false,
                        }
                    } else {
                        false
                    }
                }
            };
            if replace {
                best = Some((handle, meta));
            }
        }
        best.map(|(handle, _)| handle)
    }
}

struct PolicyInstance {
    policy: Box<dyn Scheduler>,
}

impl Drop for PolicyInstance {
    fn drop(&mut self) {
        self.policy.on_uninstall();
    }
}

struct PublishedScheduler {
    generation: u64,
    instance: Arc<PolicyInstance>,
}

/// One policy publication slot per CPU. Dispatch has no global lock or shared
/// Arc-refcount write: it locks only its CPU-local slot and invokes the policy
/// through the resident reference. Installation is a rare rolling update.
static CPU_SCHEDULERS: [IrqSafeSpinLock<Option<PublishedScheduler>>; narf_lib::percpu::MAX_CPUS] =
    [const { IrqSafeSpinLock::new(None) }; narf_lib::percpu::MAX_CPUS];

/// Total order for concurrent rolling publications. This is an atomic ticket,
/// not a dispatch lock; the newest issued generation wins each CPU slot.
static NEXT_SCHEDULER_GENERATION: AtomicU64 = AtomicU64::new(1);

static CPU_STATES: [AtomicU8; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU8::new(CpuState::Offline as u8) }; narf_lib::percpu::MAX_CPUS];

/// Last scheduler state observed for `cpu`.
pub fn cpu_state(cpu: CpuId) -> CpuState {
    CPU_STATES
        .get(cpu.0 as usize)
        .map(|state| CpuState::from_raw(state.load(Ordering::Acquire)))
        .unwrap_or(CpuState::Offline)
}

/// Publish one edge-triggered CPU-state transition and notify policy after all
/// core locks relevant to the transition have been released.
pub(crate) fn notify_cpu_state(cpu: CpuId, current: CpuState, idle: Option<CpuIdleMeta>) {
    let Some(state) = CPU_STATES.get(cpu.0 as usize) else {
        return;
    };
    let previous = CpuState::from_raw(state.swap(current as u8, Ordering::AcqRel));
    if previous == current {
        return;
    }
    with_scheduler(cpu, |scheduler| {
        if let Some(scheduler) = scheduler {
            scheduler.on_cpu_state_change(
                cpu,
                CpuStateChange {
                    previous,
                    current,
                    idle,
                },
            );
        }
    });
}

/// Publish an executor-owned Active/Idle edge without racing a lifecycle
/// transition. Once a control CPU has published Draining or Offline, a late
/// poll completion must not overwrite that state and reopen dispatch.
pub(crate) fn notify_cpu_executor_state(cpu: CpuId, current: CpuState, idle: Option<CpuIdleMeta>) {
    debug_assert!(matches!(current, CpuState::Active | CpuState::Idle));
    let Some(state) = CPU_STATES.get(cpu.0 as usize) else {
        return;
    };
    loop {
        let previous = CpuState::from_raw(state.load(Ordering::Acquire));
        if previous == current
            || matches!(
                previous,
                CpuState::Offline | CpuState::Starting | CpuState::Draining
            )
        {
            return;
        }
        if state
            .compare_exchange(
                previous as u8,
                current as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            continue;
        }
        with_scheduler(cpu, |scheduler| {
            if let Some(scheduler) = scheduler {
                scheduler.on_cpu_state_change(
                    cpu,
                    CpuStateChange {
                        previous,
                        current,
                        idle,
                    },
                );
            }
        });
        return;
    }
}

#[doc(hidden)]
pub fn __reset_cpu_states_for_test() {
    for (cpu, state) in CPU_STATES.iter().enumerate() {
        let reset = if cpu == CpuId::BOOT.0 as usize || narf_lib::smp::is_online(cpu as u32) {
            CpuState::Active
        } else {
            CpuState::Offline
        };
        state.store(reset as u8, Ordering::Release);
    }
}

/// Test hook: force a CPU's published scheduler state. A fixture that fakes a
/// remote CPU online (`smp::__test_fake_online`) must also give it a realistic
/// executor state — a halted, drain-ready AP is `Idle`, not the default
/// `Offline` — or the wake path's `target_drains` gate (which mirrors Linux
/// `ttwu_queue_cond`'s `cpu_active` check) treats it as quiesced and skips the
/// cross-core kick.
#[doc(hidden)]
pub fn __test_set_cpu_state(cpu: CpuId, state: CpuState) {
    if let Some(cell) = CPU_STATES.get(cpu.0 as usize) {
        cell.store(state as u8, Ordering::Release);
    }
}

/// Install a scheduler policy. Cap-gated on `Cap<SchedPolicy, Grant>`.
/// Replaces the previous active policy; the displaced `Arc` is
/// dropped.
pub fn install_scheduler<S: Scheduler>(
    cap: &Cap<SchedPolicy, Grant>,
    s: S,
) -> Result<(), SchedulerError> {
    cap.check_live()?;
    let replacement = Arc::new(PolicyInstance {
        policy: Box::new(s),
    });
    replacement.policy.on_install();
    let generation = publish_policy(replacement, false);
    // This acquire load is the install operation's linearization point. If no
    // newer ticket exists, our completed walk necessarily published this
    // generation to every CPU. A ticket issued after the load is a later
    // install; a ticket issued before it makes this caller the explicit loser.
    if NEXT_SCHEDULER_GENERATION.load(Ordering::Acquire) == generation.wrapping_add(1) {
        Ok(())
    } else {
        Err(SchedulerError::Superseded)
    }
}

/// Snapshot this CPU's active scheduler name. During a rolling replacement,
/// another CPU may already report the newer policy.
pub fn current_scheduler_name() -> Option<&'static str> {
    let cpu = narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
    CPU_SCHEDULERS[cpu]
        .lock()
        .as_ref()
        .map(|published| published.instance.policy.name())
}

/// Install the default strict-class scheduler if no scheduler is yet
/// installed. Idempotent — re-calling after an explicit
/// `install_scheduler` is a no-op. Called from `crate::init`.
/// Which built-in policy [`install_default_if_unset`] installs at boot. Set
/// before `narf_scheduler` init via [`set_default_policy`] (e.g. from a
/// `sched_policy=` boot arg). Staged as `class` (the historical default) while
/// `eevdf` is validated via the boot arg; the Phase-5 flip changes this initial
/// value to `POLICY_EEVDF` so the robust eligibility policy is the default.
static DEFAULT_POLICY: AtomicU8 = AtomicU8::new(POLICY_CLASS);
const POLICY_EEVDF: u8 = 0;
const POLICY_CLASS: u8 = 1;
const POLICY_FIFO: u8 = 2;
const POLICY_PRIORITY: u8 = 3;

/// Choose the built-in policy installed as the boot default. Returns `false`
/// for an unknown name (the current default is left unchanged). Must be called
/// before scheduler init; after init, use [`install_scheduler`] to swap live.
pub fn set_default_policy(name: &str) -> bool {
    let v = match name {
        "eevdf" => POLICY_EEVDF,
        "class" => POLICY_CLASS,
        "fifo" => POLICY_FIFO,
        "priority" => POLICY_PRIORITY,
        _ => return false,
    };
    DEFAULT_POLICY.store(v, Ordering::Release);
    true
}

fn default_policy_boxed() -> Box<dyn Scheduler> {
    match DEFAULT_POLICY.load(Ordering::Acquire) {
        POLICY_CLASS => Box::new(ClassScheduler),
        POLICY_FIFO => Box::new(FifoScheduler),
        POLICY_PRIORITY => Box::new(PriorityScheduler),
        _ => Box::new(crate::eevdf::EevdfScheduler),
    }
}

pub(crate) fn install_default_if_unset() {
    if CPU_SCHEDULERS.iter().all(|slot| slot.lock().is_some()) {
        return;
    }
    let replacement = Arc::new(PolicyInstance {
        policy: default_policy_boxed(),
    });
    replacement.policy.on_install();
    let _ = publish_policy(replacement, true);
}

fn publish_policy(instance: Arc<PolicyInstance>, only_if_empty: bool) -> u64 {
    let generation = NEXT_SCHEDULER_GENERATION.fetch_add(1, Ordering::AcqRel);
    for (index, slot) in CPU_SCHEDULERS.iter().enumerate() {
        let eligible = {
            let current = slot.lock();
            match current.as_ref() {
                None => true,
                Some(_) if only_if_empty => false,
                Some(current) => current.generation <= generation,
            }
        };
        if !eligible {
            continue;
        }

        let cpu = CpuId(index as u32);
        instance.policy.on_cpu_attach(cpu);
        let publication = PublishedScheduler {
            generation,
            instance: instance.clone(),
        };
        let displaced = {
            let mut current = slot.lock();
            let still_eligible = match current.as_ref() {
                None => true,
                Some(_) if only_if_empty => false,
                Some(current) => current.generation <= generation,
            };
            if !still_eligible {
                None
            } else {
                // Policy-slot -> local-runqueue is the same order as dispatch
                // and enqueue. Rebalance every queued task while both are
                // stable. A task currently executing already left the old
                // policy at selection and enters whichever policy is current
                // only if it later requeues.
                let queue = crate::READY[index].lock();
                if let Some(queue) = queue.as_ref() {
                    if let Some(old) = current.as_ref() {
                        for task in queue {
                            old.instance.policy.on_task_queue_event(
                                cpu,
                                TaskQueueEvent::Dequeued {
                                    task: TaskMeta::from_slot(task),
                                    reason: TaskDequeueReason::PolicyReplacement,
                                },
                            );
                        }
                    }
                    for task in queue {
                        instance.policy.on_task_queue_event(
                            cpu,
                            TaskQueueEvent::Enqueued {
                                task: TaskMeta::from_slot(task),
                                reason: TaskEnqueueReason::PolicyReplacement,
                            },
                        );
                    }
                }
                Some(current.replace(publication))
            }
        };
        match displaced {
            Some(displaced) => {
                if let Some(displaced) = displaced {
                    displaced.instance.policy.on_cpu_detach(cpu);
                    drop(displaced);
                }
            }
            None => instance.policy.on_cpu_detach(cpu),
        }
    }
    generation
}

/// Invoke the active policy through a CPU-local slot. The closure may take this
/// CPU's run-queue lock. Replacement waits only for this CPU-local callback;
/// no global dispatch lock or per-dispatch Arc clone exists.
pub(crate) fn with_scheduler<R>(cpu: CpuId, f: impl FnOnce(Option<&dyn Scheduler>) -> R) -> R {
    let cpu = (cpu.0 as usize).min(narf_lib::percpu::MAX_CPUS - 1);
    let published = CPU_SCHEDULERS[cpu].lock();
    f(published
        .as_ref()
        .map(|entry| entry.instance.policy.as_ref()))
}

/// Non-blocking `with_scheduler`: run `f` against `cpu`'s policy slot only if
/// the slot lock is uncontended, otherwise return `None` without spinning.
///
/// This is the cross-CPU variant. `with_scheduler` blocks, which is correct for
/// a CPU acting on its own slot (dispatch) or an operation that must complete
/// (a cross-core enqueue). A remote *best-effort* caller — work-stealing — must
/// instead skip a contended victim: blocking on a remote `CPU_SCHEDULERS[victim]`
/// lets a horde of idle thieves starve the victim's own dispatch of its slot
/// (the SPIN-NOT-POLLING stall on a queue-rich victim). Skipping is always safe
/// for stealing: the slot stays for the lock holder or another thief. Mirrors
/// the non-blocking `READY[victim].try_lock()` the steal path already uses.
pub(crate) fn try_with_scheduler<R>(
    cpu: CpuId,
    f: impl FnOnce(Option<&dyn Scheduler>) -> R,
) -> Option<R> {
    let cpu = (cpu.0 as usize).min(narf_lib::percpu::MAX_CPUS - 1);
    let published = CPU_SCHEDULERS[cpu].try_lock()?;
    Some(f(published
        .as_ref()
        .map(|entry| entry.instance.policy.as_ref())))
}

/// Test hook for the steal-path contention fix: hold `cpu`'s policy slot and
/// probe `try_with_scheduler` against it, returning `(skipped_while_held,
/// ran_when_free)`. Lives here because `CPU_SCHEDULERS` is module-private. A
/// *blocking* `with_scheduler` in its place would deadlock this single thread —
/// which is exactly the cross-core starvation the non-blocking variant avoids.
#[doc(hidden)]
pub fn __try_with_scheduler_contention_probe(cpu: CpuId) -> (bool, bool) {
    let idx = (cpu.0 as usize).min(narf_lib::percpu::MAX_CPUS - 1);
    let held = CPU_SCHEDULERS[idx].lock();
    let skipped_while_held = try_with_scheduler(cpu, |_| ()).is_none();
    drop(held);
    let ran_when_free = try_with_scheduler(cpu, |_| ()).is_some();
    (skipped_while_held, ran_when_free)
}

/// Executor entry: pop the policy's pick from the per-CPU queue.
/// Returns the detached `TaskSlot` plus the handle the policy
/// reported. None when the policy declined (queue empty / no
/// candidate). Defaults to `FifoScheduler` when nothing is installed
/// (very early boot / smoke teardown).
pub(crate) fn pick_next_slot(
    scheduler: Option<&dyn Scheduler>,
    cpu: CpuId,
    q: &mut VecDeque<crate::TaskSlot>,
) -> Option<(TaskHandle, crate::TaskSlot)> {
    // Fuse the built-in class policy into the mandatory validation scan below.
    // External policies remain untrusted and still run their pick followed by
    // the core pass that enforces work conservation and budget eligibility.
    let builtin_class = scheduler.is_some_and(|s| s.type_id() == TypeId::of::<ClassScheduler>());
    let requested = if builtin_class {
        None
    } else {
        let rq = RunQueue::projected(q);
        match scheduler {
            Some(s) => s.pick_next(cpu, &rq),
            None => FifoScheduler.pick_next(cpu, &rq),
        }
    };

    // Core-side validation is load-bearing: a buggy external policy may return
    // a stale/foreign/wrong-tier handle or decline despite runnable candidates.
    // Keep the executor work-conserving without allowing policy to bypass a
    // strict throttle or run idle-borrow work ahead of regular eligibility.
    let mut now = None;
    let mut dispatch_tier = |slot: &crate::TaskSlot| {
        if !slot.awake.flag.load(core::sync::atomic::Ordering::Acquire) {
            return 0u8;
        }
        let eligibility = match slot.spec.budget.period {
            None => BudgetEligibility::Eligible,
            Some(_) => {
                let timestamp = *now.get_or_insert_with(narf_time::now_cycles);
                slot.account.view(timestamp, &slot.spec.budget).eligibility
            }
        };
        match eligibility {
            BudgetEligibility::Eligible => 2,
            BudgetEligibility::Borrowable => 1,
            BudgetEligibility::Throttled => 0,
        }
    };
    // Single pass over the queue: evaluate each slot's dispatch tier exactly
    // once while tracking the best tier seen, the earliest slot that reaches
    // it, and the policy's requested slot (if present) with its tier. This
    // fuses what were three separate O(n) scans plus per-slot re-evaluation
    // (max-tier, first-dispatchable, requested-position) into one. It matters
    // because the executor calls this once per queued task per poll round, so
    // the round was O(n^2) in queue length with a large constant (an atomic
    // load and a budget `view()` per slot per scan).
    let requested_id = requested.map(|h| h.task_id());
    // Wake-next ("next buddy"): the id of the most recently woken task on this
    // CPU, read-and-cleared here so the boost is one-shot (Linux clears
    // `cfs_rq->next` on pick). 0 when the feature is off or nothing is queued.
    let wake_next_id = crate::take_wake_next(cpu.0);
    let mut best_tier = 0u8;
    let mut best_pos: Option<usize> = None;
    let mut requested_hit: Option<(usize, u8)> = None;
    let mut wake_next_hit: Option<(usize, u8)> = None;
    let mut dispatchable_count = 0usize;
    let mut class_pick: Option<(usize, u8, SchedClass, Priority, Option<u64>)> = None;
    // Clear before scanning. A wake that races after this store raises the
    // hint and is never overwritten; a wake that completed before the store
    // has already made its slot awake and is counted by the scan below.
    crate::publish_runnable_peer(cpu.0 as usize, false);
    for (index, slot) in q.iter().enumerate() {
        let tier = dispatch_tier(slot);
        if tier != 0 {
            dispatchable_count += 1;
        }
        // `best_tier` only ever rises, so the index at which it reaches its
        // final value is the earliest top-tier slot — identical to the old
        // `position(tier == best_tier)` scan.
        if tier > best_tier {
            best_tier = tier;
            best_pos = Some(index);
        }
        if requested_id == Some(slot.id) {
            requested_hit = Some((index, tier));
        }
        if wake_next_id != 0 && wake_next_id == slot.id.raw() {
            wake_next_hit = Some((index, tier));
        }
        if builtin_class && tier != 0 {
            let candidate = (
                index,
                tier,
                slot.spec.class,
                slot.spec.priority,
                slot.spec.budget.deadline_cycles,
            );
            let replace = match class_pick {
                None => true,
                Some((_, current_tier, current_class, current_priority, current_deadline)) => {
                    if tier != current_tier {
                        tier > current_tier
                    } else if slot.spec.class.rank() != current_class.rank() {
                        slot.spec.class.rank() > current_class.rank()
                    } else if slot.spec.priority != current_priority {
                        slot.spec.priority.raw() < current_priority.raw()
                    } else if slot.spec.class == SchedClass::Realtime {
                        match (slot.spec.budget.deadline_cycles, current_deadline) {
                            (Some(candidate), Some(incumbent)) => candidate < incumbent,
                            (Some(_), None) => true,
                            _ => false,
                        }
                    } else {
                        false
                    }
                }
            };
            if replace {
                class_pick = Some(candidate);
            }
        }
    }
    if let Some((index, tier, ..)) = class_pick {
        requested_hit = Some((index, tier));
    }
    if dispatchable_count > 1 {
        crate::publish_runnable_peer(cpu.0 as usize, true);
    }
    if best_tier == 0 {
        // No dispatchable work. Detach one slot for core maintenance so cap
        // revocation and affinity cleanup remain observable even while every
        // task is parked or period-throttled; the executor rechecks
        // eligibility before polling and requeues a still-live slot.
        let slot = q.pop_front()?;
        if let Some(scheduler) = scheduler.filter(|policy| observes_queue_events(*policy)) {
            scheduler.on_task_queue_event(
                cpu,
                TaskQueueEvent::Dequeued {
                    task: TaskMeta::from_slot(&slot),
                    reason: TaskDequeueReason::Selected,
                },
            );
        }
        return Some((TaskHandle::from_id(slot.id), slot));
    }
    // Pick priority, each honored ONLY at the top eligibility tier so none can
    // bypass a strict throttle (mirrors Linux `pick_next_entity` taking
    // `cfs_rq->next` only `&& entity_eligible`):
    //   1. the wake-next buddy — a just-woken task jumps ahead of the tasks
    //      queued in front of it (latency, not fairness — the buddy is cleared
    //      above so it is a single boost),
    //   2. the policy's requested pick,
    //   3. the earliest top-tier slot (the default FIFO order).
    let pos = match wake_next_hit {
        Some((wake_pos, wake_tier)) if wake_tier == best_tier => wake_pos,
        _ => match requested_hit {
            Some((requested_pos, requested_tier)) if requested_tier == best_tier => requested_pos,
            _ => best_pos.expect("best_tier > 0 guarantees a top-tier position"),
        },
    };
    let slot = q.remove(pos)?;
    let handle = TaskHandle::from_id(slot.id);
    if let Some(scheduler) = scheduler.filter(|policy| observes_queue_events(*policy)) {
        scheduler.on_task_queue_event(
            cpu,
            TaskQueueEvent::Dequeued {
                task: TaskMeta::from_slot(&slot),
                reason: TaskDequeueReason::Selected,
            },
        );
    }
    Some((handle, slot))
}
