//! Pluggable scheduler-policy seam — Wave D of the modular-cores plan
//! (`docs/PLUGGABILITY.md`). Mirrors `power::GovernorPolicy` shape:
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
        }
    }
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
pub trait Scheduler: Send + Sync + 'static {
    /// Stable identifier — surfaced by `current_scheduler_name`.
    fn name(&self) -> &'static str;

    /// Choose one slot from `queue`. Returning `None`, a stale handle, or a
    /// wrong-tier task causes a core-side fallback to the first candidate in
    /// the highest available eligibility tier; policy code cannot strand
    /// core-owned work or override throttling.
    fn pick_next(&self, cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle>;

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
pub(crate) fn install_default_if_unset() {
    if CPU_SCHEDULERS.iter().all(|slot| slot.lock().is_some()) {
        return;
    }
    let replacement = Arc::new(PolicyInstance {
        policy: Box::new(ClassScheduler),
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
    let requested = {
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
    let now = narf_time::now_cycles();
    let dispatch_tier = |slot: &crate::TaskSlot| {
        if !slot.awake.flag.load(core::sync::atomic::Ordering::Acquire) {
            return 0u8;
        }
        match slot.account.view(now, &slot.spec.budget).eligibility {
            BudgetEligibility::Eligible => 2,
            BudgetEligibility::Borrowable => 1,
            BudgetEligibility::Throttled => 0,
        }
    };
    let best_tier = q.iter().map(dispatch_tier).max().unwrap_or(0);
    if best_tier == 0 {
        // No dispatchable work. Detach one slot for core maintenance so cap
        // revocation and affinity cleanup remain observable even while every
        // task is parked or period-throttled; the executor rechecks
        // eligibility before polling and requeues a still-live slot.
        let slot = q.pop_front()?;
        if let Some(scheduler) = scheduler {
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
    let first_dispatchable = q.iter().position(|slot| dispatch_tier(slot) == best_tier);
    let requested_pos = requested.and_then(|h| {
        q.iter()
            .position(|slot| slot.id == h.task_id())
            .and_then(|pos| (dispatch_tier(&q[pos]) == best_tier).then_some((h, pos)))
    });
    let (handle, pos) = requested_pos.or_else(|| {
        let pos = first_dispatchable?;
        q.get(pos).map(|slot| (TaskHandle::from_id(slot.id), pos))
    })?;
    let slot = q.remove(pos)?;
    if let Some(scheduler) = scheduler {
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
