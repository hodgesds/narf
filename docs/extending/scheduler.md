# Extending the scheduler

Crate: `narf-scheduler` (`scheduler/`). The canonical contracts are
`scheduler/src/policy.rs`, `donation.rs`, `steal.rs`, and the
[scheduler specification](../../scheduler/specification/spec.md).

NARF's scheduler is a global async executor with CPU-local run queues. It has
three capability-gated policy seams:

1. `Scheduler` chooses and observes dispatch.
2. `DonationPolicy` chooses placement and the cycle ceiling for donated work.
3. `StealStrategy` chooses work-stealing victims and eligibility.

These are source-level Rust traits for crates linked into the kernel. They are
not a stable runtime-module ABI; separately compiled `.ko` files cannot pass
Rust trait objects across the module boundary.

## Task model and safe defaults

`TaskSpec` carries affinity, a resource budget and optional budget capability,
`WorkKind`, scheduling class/priority, and SMT sharing policy. Ordinary
`TaskSpec::unthrottled()` work is pinned to the boot CPU because many
spawn-and-forget kernel tasks have not been audited for migration. Use
`TaskSpec::kernel_any()` only for a kernel task whose shared state and device
access are known to be SMP-safe. `TaskSpec::user_task()` selects an
architecture-safe user affinity according to whether user-task SMP was enabled
at boot.

The common spawn functions are `spawn`, `spawn_with_spec`, the stackful spawn
variants, and `spawn_user`. Every spawned future must be `Send + 'static`.
An `IrqSafeSpinLockGuard` is deliberately `!Send`, so holding one across an
`.await` makes a future fail that bound.

## Scheduler policy

The current policy surface is:

```rust
pub trait Scheduler: Any + Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn quantum_unit(&self) -> QuantumUnit { QuantumUnit::Nanos }
    fn on_tick(&self, ctx: &CpuSchedContext, queue: &RunQueue<'_>) {}
    fn pick_next(&self, cpu: CpuId, queue: &RunQueue<'_>)
        -> Option<TaskHandle>;
    fn wakeup_preempt(
        &self,
        ctx: &CpuSchedContext,
        queue: &RunQueue<'_>,
    ) -> bool { false }
    fn select_task_rq(/* placement predicates */) -> Option<CpuId> { None }
    // on_install/on_cpu_attach/on_cpu_detach/on_task_queue_event/
    // on_cpu_state_change/on_uninstall have default no-op implementations.
}
```

`RunQueue` is read-only to policy code. `iter_meta()` returns opaque
`TaskHandle`s plus copied `TaskMeta`; metadata includes work kind, class,
priority, affinity, budget/accounting and core-computed eligibility, runnable
state, address-space presence, deadline, and virtual runtime. The policy
returns a handle and the executor performs the mutation. A stale handle,
wrong eligibility tier, or `None` cannot strand work: the core validates the
selection and falls back within the highest available eligibility tier.

`on_tick`, wake placement, and queue-event callbacks are hot/IRQ-adjacent
paths. Follow their allocation, blocking, and lock-order requirements in the
trait documentation. Policy code ranks work; it does not gain authority over
task bodies, domain state, stacks, clockevents, CPU hotplug, or frequency.

Install through the capability-gated entry point:

```rust
pub fn install_scheduler<S: Scheduler>(
    cap: &Cap<SchedPolicy, Grant>,
    scheduler: S,
) -> Result<(), SchedulerError>;
```

Installation is a generation-stamped rolling replacement across CPU-local
slots. Lifecycle hooks bracket publication and in-flight callbacks. A racing
older install can return `SchedulerError::Superseded`; a policy requesting
`QuantumUnit::Cycles` is refused with `CycleModeUnavailable` when the PMU work
cycle source is unavailable. `ClassScheduler` is the current default;
`FifoScheduler`, `PriorityScheduler`, and `EevdfScheduler` are also in-tree.
Use `current_scheduler_name()` and `current_scheduler_quantum_unit()` for
diagnostics.

The compile-proof example in `scheduler/policy-example/` is the best starting
point for an external linked policy because it intentionally has no private
scheduler dependency.

## Donation policy

`DonationPolicy` receives an immutable `RunQueue`, donor `TaskMeta`, and a
donee handle, and returns `HeadOfQueue`, `BackOfQueue`, or `Refuse`. It also
declares a per-donation cycle ceiling and may observe revocation. The executor
performs queue mutation and structural refunds.

```rust
pub fn install_donation_policy<D: DonationPolicy>(
    cap: &Cap<Donation, Grant>,
    policy: D,
) -> Result<(), DonationError>;
```

`HeadQueueDonation` is the default and `BackQueueDonation` is the alternative.
Use `current_donation_policy_name()` for diagnostics. These callbacks are on
the donation fast path: do not allocate, re-enter the scheduler, or acquire a
lock that an IRQ handler may be waiting on.

## Work-steal strategy

`StealStrategy::order_victims` returns an ordered list of online victim CPUs;
`allow_steal` filters a candidate `TaskMeta`. The default safety rule refuses
address-space-bearing tasks until user-task SMP is enabled and always honors
affinity. Do not weaken that as a mere performance experiment.

```rust
pub fn install_steal_strategy<S: StealStrategy>(
    cap: &Cap<Steal, Grant>,
    strategy: S,
) -> Result<(), StealError>;
```

`NumaAwareSteal` is the default and `RandomSteal` is the alternative. Use
`current_steal_strategy_name()` for diagnostics. Work stealing is colder than
dispatch, but an implementation still must not re-enter the scheduler or
create an IRQ lock-order inversion.

## Budget mechanism is not a policy seam

`ResourceBudget`, `BudgetAccount`, and `OverrunPolicy` are core-owned
accounting. A scheduler sees copied budget state and can rank work within the
eligible tier, but it cannot make throttled work dispatchable or replace the
charging mechanism through this trait. Attach a budget through `TaskSpec` or
the budgeted spawn helper.
