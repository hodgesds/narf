//! Pluggable scheduler-policy seam — Wave D of the modular-cores plan
//! (`docs/PLUGGABILITY.md`). Mirrors `power::GovernorPolicy` shape:
//!
//! - `pub trait Scheduler: Send + Sync + 'static` defines the policy.
//! - `static SCHEDULER` slot holds one boxed impl.
//! - `install_scheduler(&cap, impl)` swaps it under a `Cap<SchedPolicy,
//!   Grant>` check.
//! - Default `FifoScheduler` matches today's `run_until_empty`
//!   pop-front behaviour byte-for-byte.
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
use core::fmt;

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::affinity::{Affinity, CpuId};
use crate::priority::{Priority, SchedClass};
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
}

impl From<CapError> for SchedulerError {
    fn from(_: CapError) -> Self {
        SchedulerError::CapRevoked
    }
}

/// Opaque handle into the per-CPU ready queue. Returned by
/// `RunQueue::iter_meta` and consumed by `RunQueue::take` /
/// `RunQueue::pop_front`. The body is the underlying `TaskId::raw()`
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
    pub priority: Priority,
    pub class: SchedClass,
    pub affinity: Affinity,
}

/// Mutable borrow of one CPU's ready queue, scoped to a single
/// `pick_next` call. The interior `VecDeque<TaskSlot>` is private to
/// the scheduler crate — policies see only the projection methods.
///
/// The executor constructs a `RunQueue` over the locked per-CPU
/// `VecDeque<TaskSlot>`, calls the policy's `pick_next`, then
/// `take_picked` to drain the picked slot for the polling code path.
pub struct RunQueue<'a> {
    pub(crate) inner: &'a mut VecDeque<crate::TaskSlot>,
    /// Slot detached from `inner` by `take` / `pop_front`. The
    /// executor calls `take_picked()` after the policy returns to
    /// claim ownership of the slot it must poll.
    pub(crate) picked: Option<crate::TaskSlot>,
}

impl<'a> fmt::Debug for RunQueue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunQueue")
            .field("len", &self.inner.len())
            .field("has_picked", &self.picked.is_some())
            .finish()
    }
}

impl<'a> RunQueue<'a> {
    /// Wrap a mutable `VecDeque<TaskSlot>` borrow into a `RunQueue`
    /// projection. Crate-internal; callers go through
    /// `pick_next_for_cpu`.
    #[inline]
    pub(crate) fn projected(q: &'a mut VecDeque<crate::TaskSlot>) -> Self {
        Self {
            inner: q,
            picked: None,
        }
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
        self.inner.iter().map(|slot| {
            (
                TaskHandle::from_id(slot.id),
                TaskMeta {
                    id: slot.id,
                    priority: slot.spec.priority,
                    class: slot.spec.class,
                    affinity: slot.spec.affinity,
                },
            )
        })
    }

    /// Detach the front-most slot from the queue and return its
    /// handle. The actual slot is stashed in `picked` for the
    /// executor to claim via `take_picked`. Returns `None` when the
    /// queue is empty.
    pub fn pop_front(&mut self) -> Option<TaskHandle> {
        let slot = self.inner.pop_front()?;
        let h = TaskHandle::from_id(slot.id);
        // A well-behaved policy calls pop_front (or take) at most
        // once per pick_next. Multiple calls would clobber the
        // previously detached slot; assert here so the misuse
        // surfaces immediately rather than silently dropping a
        // pending task.
        debug_assert!(
            self.picked.is_none(),
            "RunQueue::pop_front called twice in one pick_next — \
             previously detached slot would be dropped"
        );
        self.picked = Some(slot);
        Some(h)
    }

    /// Detach the slot named by `h` and return its handle. Returns
    /// `None` if the handle is no longer on the queue. Same one-pick
    /// contract as `pop_front`.
    pub fn take(&mut self, h: TaskHandle) -> Option<TaskHandle> {
        let id = h.task_id();
        let pos = self.inner.iter().position(|s| s.id == id)?;
        let slot = self.inner.remove(pos)?;
        let handle = TaskHandle::from_id(slot.id);
        debug_assert!(
            self.picked.is_none(),
            "RunQueue::take called after pop_front/take — \
             previously detached slot would be dropped"
        );
        self.picked = Some(slot);
        Some(handle)
    }

    /// Re-attach a previously-picked slot at the back of the queue.
    /// Used by tests and by policy impls that want to defer a slot
    /// without polling it. No-op if no slot is currently detached.
    pub fn push_back(&mut self, _h: TaskHandle) {
        if let Some(slot) = self.picked.take() {
            self.inner.push_back(slot);
        }
    }

    /// Executor-side: claim the slot the policy detached. Returns
    /// `None` if the policy returned `None` from `pick_next`.
    #[inline]
    pub(crate) fn take_picked(&mut self) -> Option<crate::TaskSlot> {
        self.picked.take()
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

    /// Pick one slot off `queue` to dispatch next. The default FIFO
    /// impl simply calls `queue.pop_front()`. Returning `None` tells
    /// the executor "no candidate this round" — the round ends and
    /// the idle path runs.
    fn pick_next(&self, cpu: CpuId, queue: &mut RunQueue) -> Option<TaskHandle>;

    /// Hook fired after a fresh task lands on `cpu`'s queue. The
    /// default impl does nothing; CFS-style policies can use this to
    /// reposition the slot. Currently unused by the executor but
    /// reserved on the trait surface for forward compatibility.
    fn on_enqueue(&self, _cpu: CpuId, _task: &TaskMeta) {}

    /// Hook fired when a task voluntarily yields via `yield_now()`.
    /// Counterpart to `on_enqueue`; same contract.
    fn on_yield(&self, _cpu: CpuId, _task: &TaskMeta) {}
}

/// First-in-first-out scheduler — today's stage-3+ behaviour.
#[derive(Copy, Clone, Debug, Default)]
pub struct FifoScheduler;

impl Scheduler for FifoScheduler {
    fn name(&self) -> &'static str {
        "fifo"
    }

    fn pick_next(&self, _cpu: CpuId, queue: &mut RunQueue) -> Option<TaskHandle> {
        queue.pop_front()
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

    fn pick_next(&self, _cpu: CpuId, queue: &mut RunQueue) -> Option<TaskHandle> {
        let mut best: Option<(TaskHandle, Priority)> = None;
        for (h, meta) in queue.iter_meta() {
            match best {
                None => best = Some((h, meta.priority)),
                Some((_, p)) if meta.priority.raw() < p.raw() => {
                    best = Some((h, meta.priority));
                }
                _ => {}
            }
        }
        let (h, _) = best?;
        queue.take(h)
    }
}

/// `Box<dyn Scheduler>` slot. Init wires a `FifoScheduler` so behaviour
/// out of the box matches the pre-Wave-D inline FIFO byte-for-byte.
pub(crate) static SCHEDULER: IrqSafeSpinLock<Option<Box<dyn Scheduler>>> =
    IrqSafeSpinLock::new(None);

/// Install a scheduler policy. Cap-gated on `Cap<SchedPolicy, Grant>`.
/// Replaces the previous active policy; the displaced `Box` is
/// dropped.
pub fn install_scheduler<S: Scheduler>(
    cap: &Cap<SchedPolicy, Grant>,
    s: S,
) -> Result<(), SchedulerError> {
    cap.check_live()?;
    let mut slot = SCHEDULER.lock();
    *slot = Some(Box::new(s));
    Ok(())
}

/// Snapshot the active scheduler's name. Returns `None` if `init()`
/// hasn't run yet.
pub fn current_scheduler_name() -> Option<&'static str> {
    let slot = SCHEDULER.lock();
    slot.as_ref().map(|s| s.name())
}

/// Install the default `FifoScheduler` if no scheduler is yet
/// installed. Idempotent — re-calling after an explicit
/// `install_scheduler` is a no-op. Called from `crate::init`.
pub(crate) fn install_default_if_unset() {
    let mut slot = SCHEDULER.lock();
    if slot.is_none() {
        *slot = Some(Box::new(FifoScheduler));
    }
}

/// Executor entry: pop the policy's pick from the per-CPU queue.
/// Returns the detached `TaskSlot` plus the handle the policy
/// reported. None when the policy declined (queue empty / no
/// candidate). Defaults to `FifoScheduler` when nothing is installed
/// (very early boot / smoke teardown).
pub(crate) fn pick_next_slot(
    cpu: CpuId,
    q: &mut VecDeque<crate::TaskSlot>,
) -> Option<(TaskHandle, crate::TaskSlot)> {
    let mut rq = RunQueue::projected(q);
    let h = {
        let slot = SCHEDULER.lock();
        match slot.as_ref() {
            Some(s) => s.pick_next(cpu, &mut rq),
            None => FifoScheduler.pick_next(cpu, &mut rq),
        }
    };
    let h = h?;
    let slot = rq.take_picked()?;
    Some((h, slot))
}
