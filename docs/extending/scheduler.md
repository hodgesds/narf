# Extending the scheduler

Crate: `narf-scheduler` (`scheduler/`).

NARF's scheduler is a **global async executor**: a task is a
`Pin<Box<dyn Future<Output = ()> + Send>>` polled per-round on a per-CPU run
queue. Three policy dimensions are pluggable via the **cap-gated global
install** pattern (pattern 1 in the [README](README.md)), each with a trait,
two in-tree impls, and an `install_*(&Cap<…, Grant>, impl)`:

1. **`Scheduler`** — which task to dispatch next.
2. **`DonationPolicy`** — how a priority-donated task is enqueued/budgeted.
3. **`StealStrategy`** — work-stealing victim order and permission.

## Task model

```rust
// scheduler/src/lib.rs:173
pub struct TaskId(pub u64);
impl TaskId { pub const NONE: TaskId = TaskId(0); pub const fn raw(self) -> u64; }

// scheduler/src/lib.rs:589
pub struct TaskSpec {
    pub affinity: Affinity,
    pub budget: ResourceBudget,
    pub budget_cap: Option<Cap<CpuBudget, Spend>>,
    pub class: SchedClass,
    pub priority: Priority,
    pub smt: SmtSharePolicy,
}
```

Spawn entry points (all take a `Future<Output = ()> + Send + 'static`):

```rust
pub fn spawn<F>(f: F) -> TaskId;                                    // :902
pub fn spawn_with_spec<F>(f: F, spec: TaskSpec) -> TaskId;          // :910
pub fn spawn_stackful<F>(f: F) -> TaskId;                           // :955
pub fn spawn_stackful_with_options<F>(f: F, opts: StackfulOptions) -> TaskId; // :991
pub fn spawn_stackful_pinned<F>(f: F, cpu: u32) -> TaskId;          // :1008
pub fn spawn_budgeted<F>(f: F, budget: ResourceBudget, cap: Cap<CpuBudget, Spend>) -> TaskId; // :1021
pub fn spawn_user<F>(id: TaskId, f: F, spec: TaskSpec, addr_space: Arc<AddressSpace>) -> TaskId; // :1071
pub fn alloc_task_id() -> TaskId;                                   // :1033
```

`spawn_user` is how a user process's task is created: you pass a pre-allocated
`TaskId`, the task future, a `TaskSpec`, and the process's `AddressSpace`.

Priority / class model (`scheduler/src/priority.rs`):

```rust
pub enum SchedClass { Normal, RealTime, Idle }            // :14
pub struct Priority(pub i8);                              // :25  (HIGH=-10, NORMAL=0, LOW=10)
pub enum SmtSharePolicy { Avoid, Allow, Require }         // :43
```

## Seam 1 — scheduler policy (`Scheduler`) ✅ pluggable

`scheduler/src/policy.rs:226`

```rust
pub trait Scheduler: Send + Sync + 'static {
    fn name(&self) -> &'static str;                                       // required
    fn pick_next(&self, cpu: CpuId, queue: &mut RunQueue) -> Option<TaskHandle>; // required
    fn on_enqueue(&self, _cpu: CpuId, _task: &TaskMeta) {}                // default no-op
    fn on_yield(&self, _cpu: CpuId, _task: &TaskMeta) {}                  // default no-op
}
```

`pick_next` is the hot-path contract: pull one slot off `queue` to run next,
or `None` to end the round (idle path runs). `on_enqueue` / `on_yield` are
reserved hooks for CFS-style repositioning (currently unused by the executor
but on the trait surface).

Install (cap-gated):

```rust
// scheduler/src/policy.rs:297
pub fn install_scheduler<S: Scheduler>(cap: &Cap<SchedPolicy, Grant>, s: S)
    -> Result<(), SchedulerError>;
```

Cap marker: `SchedPolicy` (`policy.rs:34`, `KIND = CapKind::SchedPolicy`).
In-tree impls: `FifoScheduler` (`:248`, default — `queue.pop_front()`) and
`PriorityScheduler` (`:265`, lowest `priority.raw()` wins).

Supporting types you receive in `pick_next`:

```rust
// scheduler/src/policy.rs:62
pub struct TaskHandle(/* opaque */);  impl TaskHandle { pub const fn task_id(self) -> TaskId; }

// scheduler/src/policy.rs:82
pub struct TaskMeta {
    pub id: TaskId, pub priority: Priority, pub class: SchedClass,
    pub affinity: Affinity, pub addr_space: bool,
}

// scheduler/src/policy.rs:104 — the run queue you pick from
pub struct RunQueue<'a> { /* … */ }
// methods used by the in-tree impls: pop_front(), iter_meta(), take(handle)
```

## Seam 2 — donation policy (`DonationPolicy`) ✅ pluggable

`scheduler/src/donation.rs:84`

```rust
pub trait DonationPolicy: Send + Sync + 'static {
    fn name(&self) -> &'static str;                                      // required
    fn enqueue_donee(&self, queue: &mut RunQueue, donor_meta: &TaskMeta,
                     donee: TaskHandle) -> EnqueueDonee;                 // required
    fn cycle_ceiling(&self, donor_meta: &TaskMeta) -> u64;              // required
    fn on_revoke(&self, donor_meta: &TaskMeta, refund_cycles: u64) {}   // default no-op
}

// scheduler/src/donation.rs:62
pub enum EnqueueDonee { HeadOfQueue, BackOfQueue, Refuse }
```

Priority donation: when a task donates its cap to a target, this policy
decides where the donee lands on the donor's run queue and how many cycles
the donation may transfer. Install (cap-gated):

```rust
// scheduler/src/donation.rs:186
pub fn install_donation_policy<D: DonationPolicy>(cap: &Cap<Donation, Grant>, d: D)
    -> Result<(), DonationError>;
```

Cap marker: `Donation` (`donation.rs:37`, `KIND = CapKind::DonationPolicy`).
In-tree impls: `HeadQueueDonation` (`:122`, default) and `BackQueueDonation`
(`:148`). Donation itself is triggered by:

```rust
// scheduler/src/lib.rs:1346
pub fn donate_to(target: TaskId, cap: &Cap<Task, Invoke>) -> Result<(), DonateError>;
```

## Seam 3 — work-steal strategy (`StealStrategy`) ✅ pluggable

`scheduler/src/steal.rs:68`

```rust
pub trait StealStrategy: Send + Sync + 'static {
    fn name(&self) -> &'static str;                                      // required
    fn order_victims(&self, thief: CpuId, online: &[CpuId]) -> Vec<CpuId>; // required
    fn allow_steal(&self, thief: CpuId, task: &TaskMeta) -> bool {       // default
        if task.addr_space && !crate::user_task_smp_enabled() { return false; }
        task.affinity.allowed.contains(thief)
    }
}
```

`order_victims` returns the CPUs to try stealing from, in order (empty = don't
steal this round). `allow_steal`'s **default refuses to steal an
address-space-bearing (user) task unless user-task SMP is enabled at boot** —
override with care; stealing a user task without cross-CPU TLB shootdown wired
is unsound (see the SMP memory notes). Install (cap-gated):

```rust
// scheduler/src/steal.rs:223
pub fn install_steal_strategy<S: StealStrategy>(cap: &Cap<Steal, Grant>, s: S)
    -> Result<(), StealError>;
```

Cap marker: `Steal` (`steal.rs:40`, `KIND = CapKind::StealStrategy`). In-tree
impls: `NumaAwareSteal` (`:107`, default) and `RandomSteal` (`:165`).

## Budget model (used by, not a seam)

`scheduler/src/budget.rs` is the accounting substrate the policies consume; it
is concrete, not a trait seam:

```rust
pub struct ResourceBudget {                                     // :51
    pub share_ppm: u32, pub burst_cycles: u64,
    pub deadline_cycles: Option<u64>, pub policy: OverrunPolicy,
}
pub enum OverrunPolicy { Throttle, Demote, Kill, Ignore }       // :35
pub struct CpuBudget;  // CapType, KIND = CapKind::CpuBudget     // :89
pub struct BudgetAccount { /* cycles_spent, overruns, polls, donated_in/out */ } // :104
```

You attach a budget to a task via `TaskSpec.budget` / `spawn_budgeted`; the
executor charges it. There is no "custom budget accounting" trait — the
`BudgetAccount::charge` logic (`:126`) is fixed. To influence scheduling by
budget, use the `Scheduler` seam.

## Worked example: a custom scheduler policy

An LIFO scheduler (dispatch the most recently enqueued task) installed at
boot.

```rust
#![no_std]
extern crate alloc;
use narf_scheduler::{install_scheduler, CpuId, RunQueue, Scheduler, TaskHandle};
use narf_capabilities::{Cap, Grant};
use narf_scheduler::SchedPolicy;

#[derive(Copy, Clone, Debug, Default)]
pub struct LifoScheduler;

impl Scheduler for LifoScheduler {
    fn name(&self) -> &'static str { "lifo" }
    fn pick_next(&self, _cpu: CpuId, queue: &mut RunQueue) -> Option<TaskHandle> {
        // RunQueue exposes pop-from-front; a true LIFO needs a back-pop —
        // check RunQueue's method set in scheduler/src/policy.rs. If only
        // pop_front / iter_meta / take exist, select the last handle via
        // iter_meta and take() it (as PriorityScheduler does for its scan).
        let last = queue.iter_meta().last().map(|(h, _)| h)?;
        queue.take(last)
    }
}

// At boot, with the scheduler-policy Grant cap:
pub fn install(cap: &Cap<SchedPolicy, Grant>) {
    let _ = install_scheduler(cap, LifoScheduler);
}
```

## Reflection helpers

Each seam has a name-snapshot function for diagnostics:
`current_scheduler_name()`, `current_donation_policy_name()`,
`current_steal_strategy_name()` (all re-exported from `scheduler/src/lib.rs`).

## Gotchas

- **Default policies are planted in `init()`.** If you don't install your
  own, `FifoScheduler` / `HeadQueueDonation` / `NumaAwareSteal` are installed
  idempotently at boot. Install yours *after* init (or in your own initcall)
  with the `Grant` cap; installing replaces the current backend.
- **`allow_steal` default is a safety gate, not a perf knob.** Removing the
  `addr_space && !user_task_smp_enabled()` refusal without cross-CPU TLB
  shootdown wired risks the SMP user-task fault loops documented in the
  memory notes. Keep the guard unless you know user-task SMP is on.
- **`pick_next` runs on the hot path.** It's called every round on every CPU.
  Keep it O(queue) at worst (`PriorityScheduler` is the reference for a scan).
- **`RunQueue` method surface.** The in-tree impls use `pop_front()`,
  `iter_meta()`, and `take(handle)`. Confirm the exact set in
  `scheduler/src/policy.rs` before relying on others.
- **`no_std` + `alloc`.** As everywhere.
