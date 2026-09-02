# Authoring a scheduling policy

> Status: **draft**. Companion to [`spec.md`](spec.md) and
> [`preemption.md`](preemption.md). Covers the pluggable `Scheduler` trait in
> [`scheduler/src/policy.rs`](../src/policy.rs): what a policy owns, what the
> core owns, the method contract, and how to add a new policy without bolting
> hacks onto the core. Worked examples: `FifoScheduler` (naive) and
> `EevdfScheduler` (default, eligibility-based).

## 1. The core/policy split

The executor is deliberately factored so that **mechanism** lives in the core
(`lib.rs` / `stackful.rs`) and **policy** lives behind the `Scheduler` trait.

- **Core owns** (a policy cannot and must not reimplement these): the per-CPU
  ready `VecDeque<TaskSlot>`, admission/park/wake transitions, work-stealing and
  migration, CPU hot-plug, time-slice/tick preemption at CPL3, budget throttling
  and eligibility tiers, and the run-time *accounting* every policy needs (a
  task's accumulated virtual runtime — see §4). Accounting is core-owned because
  it is charged on the hottest path (once per dispatch) and every policy reads
  the same numbers; duplicating it per policy would add a virtual call to that
  path for no benefit.
- **Policy owns** the *decisions*: which runnable slot to run next
  (`pick_next`), and whether a wake should preempt the running task
  (`wakeup_preempt`). Policies are pure readers of core-published metadata.

**Rule of thumb (do not add hacks):** if a policy needs information or a
decision point the trait does not expose, **add a method or a `TaskMeta` field
to the trait**, with a default that preserves existing behavior — do not reach
around the seam with a global flag, a side table keyed by task id, or a
special-case in the core. The trait is the contract; grow it deliberately.

## 2. The `Scheduler` trait

```rust
pub trait Scheduler: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn pick_next(&self, cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle>;
    fn wakeup_preempt(&self, cpu: CpuId, current: &CurrentTask, queue: &RunQueue<'_>) -> bool { false }
    // lifecycle (all defaulted): on_install, on_cpu_attach, on_cpu_detach,
    //                            on_task_queue_event, on_cpu_state_change, on_uninstall
}
```

### `pick_next` — required
Choose one runnable slot from `queue`. The **core validates** the return: a
`None`, a stale handle, or a task below the highest available eligibility tier
falls back to the first candidate in that tier (`pick_next_slot`,
`policy.rs`). A policy therefore *cannot* strand core-owned or throttled work,
and need not re-check throttling itself beyond the `TaskMeta.budget_state`
eligibility it is handed. Keep it a single O(n) scan over `queue.iter_meta()`;
allocation, locking, or re-entering the scheduler from here is forbidden.

### `wakeup_preempt` — defaulted, opt-in
Returns `true` iff the running task should cede at its next cooperative
preemption point because a wake just made a peer runnable. Default `false`
(FIFO/Priority/Class do not wake-preempt). This is NARF's analogue of Linux
`check_preempt_wakeup_fair()` (`/usr/src/linux/kernel/sched/fair.c`). It is
consulted once per wake at the waker's syscall-exit (the sticky per-CPU
`WAKE_PREEMPT` request set by `note_wake_preempt`), never on a no-wake exit, so
its cost is paid only when a wake actually happened.

### Lifecycle hooks — defaulted
`on_install`/`on_uninstall`, `on_cpu_attach`/`on_cpu_detach`,
`on_task_queue_event`, `on_cpu_state_change`. Serialized with `pick_next` on
their CPU. Observational: must not allocate, block, or re-enter policy
installation. Use these for policy-internal per-CPU bookkeeping if a policy
maintains any (EEVDF-lite does not — it derives everything from core metadata).

## 3. `TaskMeta` — what a policy may read
`RunQueue::iter_meta()` yields `(TaskHandle, TaskMeta)`. `TaskMeta` projects the
private `TaskSlot` so policy code never sees its body. Fields relevant to a
policy: `runnable`, `priority` (lower `raw()` = scheduling-higher), `sched_class`,
`deadline` (RT), `budget_state.eligibility` (`Eligible`/`Borrowable`/`Throttled`),
and **`vruntime`** (§4). Add a field here (and copy it in `from_slot_at`) when a
new policy needs a new signal.

## 4. Virtual runtime (core-owned accounting)
Each `TaskSlot` carries a `vruntime` (cycles). The core charges it at the two
dispatch sites in `lib.rs` (`poll_one_round`, `run_until_empty`) with the
`elapsed` value already computed there for slice accounting — one 64-bit add, no
extra `rdtsc`. A parked task's `vruntime` is frozen (it is not charged while it
is not running), which is exactly the "sleeper credit" that lets an
eligibility policy react to a just-woken task. Per-CPU `VFLOOR[cpu]` tracks the
minimum vruntime dispatched, so a long sleeper's credit can be clamped to one
base slice (Linux `place_entity()`'s lag clamp) and cross-CPU origin skew after a
steal can be renormalized in core (policy never writes slots).

## 5. EEVDF-lite (the default policy) and its Linux lineage
`EevdfScheduler` mirrors Linux EEVDF (`kernel/sched/fair.c`) with equal weights:

- **Virtual deadline** `d = v_eff + BASE_SLICE`, where
  `v_eff = max(vruntime, VFLOOR - BASE_SLICE)` (bounded lag). Linux:
  `se->deadline = se->vruntime + calc_delta_fair(se->slice, se)`.
- **`pick_next`**: within the top eligibility tier and class rank, pick minimum
  `d` (Linux `__pick_eevdf()`; with uniform slices this reduces to min-`v_eff`).
- **`wakeup_preempt`**: preempt iff the best runnable sibling's `d` is strictly
  earlier than the runner's *protected* deadline `D_run = vruntime_at_dispatch +
  BASE_SLICE`. This is Linux's `RUN_TO_PARITY` + eligibility in one comparison: a
  just-slept task (clamped at the floor) has an early `d` and preempts
  immediately (→ fast futex wait/wake handoff); a balanced peer has
  `d >= D_run` and does **not** preempt, so the runner batches out its base
  slice (→ no de-batch of pipe/msg/redis-pipeline throughput). No wall-clock
  threshold is involved — the batching hysteresis is the base slice, a
  first-class scheduling quantum, not a tuned constant.
- **`BASE_SLICE`** is derived from `DEFAULT_SLICE_CYCLES` (not a new magic
  number) and is comparable to Linux's `sysctl_sched_base_slice` (700 µs). The
  tick/CPL3 slice preemption (`try_preempt_user`) and the `FAIR_QUANTUM_DIV`
  fair-share floor remain the backstops; EEVDF only re-orders picks and supplies
  the wake-preempt rule.

Why this is correct where a flat "minimum run time before a wake may preempt"
floor is not: the floor cannot tell a *starved sleeper that should preempt now*
from a *balanced peer that should not* — only a two-task virtual-time comparison
can. EEVDF makes that comparison; the floor guesses.

## 6. Selecting a policy
`install_scheduler(&cap, impl)` performs a cap-gated rolling swap;
`current_scheduler_name()` reflects the active policy. Boot arg
`sched_policy=<fifo|priority|class|eevdf>` and the writable debugfs
`sched/policy` knob select among the built-ins. The default (installed by
`install_default_if_unset`) is `eevdf`; `fifo` remains available as the naive,
zero-accounting reference and for A/B measurement.

## 7. Checklist for a new policy
1. `impl Scheduler`; keep `pick_next` a single allocation-free O(n) scan.
2. Read only `TaskMeta`; if you need a new signal, **add a `TaskMeta` field or a
   trait method with a default** — do not add a core special-case.
3. Unit-test the decision as a **pure free function** (see
   `syscall_exit_yield_decision`'s test in `stackful.rs`): futex-spinner →
   preempt, balanced-peer → no de-batch, woken-hog → no starvation of others.
4. Validate throughput/latency with the A/B matrix (stress-ng
   futex/pipe/sem/switch/msg + `redis-bench` + `mt-echo-bench`) — redis
   pipelining is the canonical de-batch canary (a prior wake-next buddy dispatch
   was reverted, #235, for exactly this).
5. Land behind a flag/selectable first; flip the default only after the A/B.
