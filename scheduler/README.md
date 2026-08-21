# scheduler — Global Async Executor

A global executor runs async tasks, stackful kernel/user threads, and bounded
deferred interrupt work. Scheduling policy is replaceable from a separate
`no_std` crate through a read-only `RunQueue`/`TaskMeta` interface. Policy sees
class, work kind, runnable state, affinity, and immutable budget/accounting
snapshots; the executor alone owns task slots, charging, stack/domain restore,
and context switching.

The optional `on_cpu_state_change` policy callback reports
`Offline/Starting/Active/Idle/Draining` edges. Idle events include copied
parked/throttled/borrowable counts and the next budget replenishment. The hook
is observational: CPU hot-plug, halt, clockevents, and DVFS remain core or
`power/` mechanisms. Scheduling policy can express demand; it cannot program
frequency state.

Logical hot-unplug makes `Draining` a dispatch barrier: the target executor
acknowledges from between polls, remains parked through `Offline`, and resumes
only after reactivation. Queue migration never nests source and destination
locks. Physical firmware power-off/start remains an architecture integration
gate rather than a policy callback.

Separate-crate policy is not sandboxing: a callback that never returns can
still stall its CPU. The core protects queue, budget, and switch integrity from
bad return values, while policy code remains trusted for availability.

Policy replacement is first-class and has balanced `on_install`, per-CPU
`on_cpu_attach`/`on_cpu_detach`, and final `on_uninstall` hooks. Publication is
generation-ordered and rolling across CPU-local slots—there is no global lock
or shared reference-count write in dispatch. Core-owned task and budget state
survives the cutover unchanged. Concurrent older installers receive
`SchedulerError::Superseded` instead of falsely reporting that they remain the
active generation.

Task control has a matching first-class lifecycle. `on_task_queue_event`
receives copied `Enqueued`/`Dequeued` events for admission, dispatch, requeue,
migration, and policy replacement. Replacement rebalances every queued task
between the old and new policy while holding only that CPU's local locks; an
in-flight task enters the new policy only if it later requeues. Futures, domain
state, stacks, and queue mutation remain private to the executor.

The in-tree `ClassScheduler` uses strict Linux-like class order
(`Realtime > Interactive > Default > Batch > Idle`). Core-owned
`PeriodBudget` accounting supports strict replenishment and bounded idle
borrowing: if no competing work exists, an x86_64 stackful borrower resumes the
same continuation without switching through idle (the aarch64 timer path uses
the same decision), while borrowed time becomes
debt against later replenishment. Policy sees `BudgetView` but cannot alter
eligibility or accounting.

Realtime is an admitted service, not a class-label shortcut.
`spawn_realtime` requires a live `Cap<CpuBudget, Spend>`, a strict
runtime/period contract, an absolute deadline, and available per-CPU, system,
and capability-domain bandwidth. Generic spawn paths demote an unadmitted
`Realtime` request. Admitted reservations are CPU-pinned and released by the
task-slot lifetime guard.

x86_64 and aarch64 stackful kernel tasks have own-stack timer switching;
ordinary stackless futures remain cooperative. `preempt_disable()` supplies a
nestable, CPU-local, `!Send` guard for task-context critical sections. Hard-IRQ
time is accounted separately from task budgets, `SoftIrq` remains schedulable
work, and `cpu_demand()` publishes read-only observations to the separate power
governor. Full trap-entry domain neutralisation and aarch64 own-stack EL0 user
preemption remain open safety gates; see the implementation contract.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Preemption/accounting: [`specification/preemption.md`](./specification/preemption.md)
- Research: [`research/README.md`](./research/README.md)
- External-crate compile proof: [`policy-example`](./policy-example)
- Stage: 1 (single-CPU basic) → 5 (preemption/policy decoupling audit).
