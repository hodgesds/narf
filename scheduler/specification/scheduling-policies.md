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
  and eligibility tiers, the bounded synchronous-wake batch (one fixed root,
  one target at a time, at most 64 exact-root returns), and the run-time
  *accounting* every policy needs (a task's
  accumulated virtual runtime
  — see §4). Accounting is core-owned because
  it is charged on the hottest path (once per dispatch) and every policy reads
  the same numbers; duplicating it per policy would add a virtual call to that
  path for no benefit.
- **Policy owns** the *decisions*: which runnable slot to run next
  (`pick_next`), and whether a wake should preempt the running task
  (`wakeup_preempt`). Policies are pure readers of core-published metadata.
  `pick_wakeup` optionally changes selection using `TaskMeta::wake_reason`.
  `on_task_runtime` supplies charged execution for policy-private state; the
  common clock, virtual-runtime and bandwidth accounting remain core-owned.

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
    fn pick_wakeup(&self, cpu: CpuId, queue: &RunQueue<'_>) -> Option<TaskHandle> { None }
    fn on_task_runtime(&self, cpu: CpuId, runtime: TaskRuntime) { }
    fn wakeup_preempt(&self, ctx: &CpuSchedContext, queue: &RunQueue<'_>) -> bool { false }
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
The built-in class/FIFO path may select an exact, awake synchronous-handoff
buddy before this scan only when the task has no periodic budget. Such a task
is necessarily in the highest core eligibility tier; periodic-budget tasks and
external policies still take the ordinary validated path. `ClassScheduler`
also falls back when a higher-class task is awake, and the ordinary path applies
the buddy only within the class selected by strict class ordering. A per-CPU
class bitmask is a conservative guard only: admission and migration publish a
class before its slot becomes visible, and bits remain sticky so a race cannot
create a false negative. A stale higher-class bit only forces the validated
path.

Before returning through the executor, the core may directly enter that exact
wakee only for the built-in class/FIFO policies and a default-class,
normal-priority stackful task with no period, budget cap, or donation. A local
target remains resident under a home-run-queue claim. A remote target stays on
its authoritative home and runs through ordinary executor dispatch; direct
handoff never rehomes a task across run queues. Target runtime is charged back
to its own virtual runtime. External and wrapper
policies are never bypassed: their wakees return through `pick_next` so policy
observation and ordering remain complete.

For an exact synchronous wake of a sleeping direct-eligible partner on another
CPU, the core may make a non-blocking attempt to move the queued wakee to the
waker's CPU when both source and destination use the built-in class/FIFO
policies and the destination has no other runnable peer. This is the Linux
`wake_affine_idle(..., sync)` `rq->nr_running == 1` direction (NARF's running
waker is temporarily off-queue): the sleeping
slot moves, never the currently executing continuation. Failure may instead
request that the running direct-eligible waker join the wakee's authoritative
home after the waker returns to the executor. Both `WF_SYNC`-shaped placement
paths revalidate live hard affinity and CPU lifecycle state and use the same
core-owned migration enqueue as every other allowed move; the destination
still dispatches through `pick_next`. The exact wake also suppresses the
generic idle-sibling pull hint, which would let a thief split the pair that
co-location and the urgent buddy are establishing.

### `wakeup_preempt` — defaulted, opt-in

The target CPU invokes `wakeup_preemption(ctx, queue)` after activating pending
wakes at a safe user return. Its default implementation adapts the boolean hook.
A policy can instead return `WakePreemption::After(elapsed_cycles)` to retain a
check until slice protection expires. The task stores that deadline locally;
ordinary returns test it in O(1), and a new dispatch clears it. No recovery
timer is introduced. `CurrentTask` includes the dispatched priority.

The boolean hook returns `true` when a runnable peer should preempt the current
task, and defaults to `false`. Class and EEVDF implement protected wake
preemption; FIFO retains its default. The queue is inspected when activation
adds runnable work or a retained policy deadline becomes due. An activation
node belonging to the currently claimed direct-handoff task does not trigger a
queue-policy scan merely to rearm that same task.

### Lifecycle hooks — defaulted
The default ClassScheduler uses per-task blocking-I/O wake metadata with a
CPU-time credit ledger, owned by its implementation in `policy/blocking.rs`.
It spends preferred execution, retains overshoot debt and repays it with
ordinary execution, capped at one fair-share quantum. The core validates the preferred
handle and reports the charged span and whether preference was granted.
Every granted dispatch spends credit, even when already first in ordinary
queue order. The burst cap is one fair-share quantum (a quarter of a default
task slice). A delegating policy must
forward runtime and lifecycle hooks along with `pick_wakeup` to preserve ClassScheduler's credit accounting.
`pick_wakeup` preserves ordinary policy fallback, class/priority and throttle
checks. Per-task metadata retains simultaneous wakes; no single next-buddy id
can overwrite another receiver. Other policies retain their defaults.

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
maximum vruntime dispatched, so a long sleeper's credit can be clamped to one
base slice (Linux `place_entity()`'s lag clamp) and cross-CPU origin skew after a
steal can be renormalized in core (policy never writes slots).

## 5. EEVDF-lite and its Linux lineage
`EevdfScheduler` adapts Linux 7.0-rc3 `kernel/sched/fair.c` to NARF's
existing equal-weight accounting and uniform virtual requests:

- **Virtual deadline:** `d = v_eff + BASE_SLICE`, where
  `v_eff = max(vruntime, VFLOOR - BASE_SLICE)` bounds sleeper credit.
- **Pick:** within the top budget eligibility tier and class, choose the
  earliest deadline. Uniform requests make the minimum-runtime peer the
  earliest deadline candidate.
- **Wake:** follow `vruntime_eligible` and `__pick_eevdf` ordering. Include the
  runner's elapsed service when computing runnable eligibility. An ineligible
  runner loses slice protection immediately. An eligible runner retains its
  virtual request until it expires, then competes with eligible peers by
  deadline. ClassScheduler applies this rule only within its strict
  class/priority tier; equal-priority realtime FIFO/RR order remains intact.
- **Deferred check:** retain the earlier applicable boundary: protection expiry
  or the first cycle at which current becomes ineligible. Equal-weight
  eligibility compares exact sums, without rounding the average or imposing a
  fixed wall-time grace period. `After` remains a request for the core's existing
  safe-boundary recheck; it does not arm a new timer.

Both sides of the comparison use the same bounded-credit view. One
allocation-free O(n) scan accumulates the runtime sum and earliest candidate;
NARF does not yet provide Linux's weighted/group accounting, variable request
sizes, persistent per-entity deadlines or augmented runqueue tree. This change
borrows the eligibility-before-protection decision, not those data structures.
`BASE_SLICE` remains derived from `DEFAULT_SLICE_CYCLES`. Existing core budget,
class, affinity and safe context-switch checks remain authoritative.

## 6. Selecting a policy
`install_scheduler(&cap, impl)` performs a cap-gated rolling swap;
`current_scheduler_name()` reflects the active policy. Boot arg
`sched_policy=<fifo|priority|class|eevdf>` and the writable debugfs
`sched/policy` knob select among the built-ins. The default (installed by
`install_default_if_unset`) is `class`; `fifo` remains available as the naive,
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


## Live user FIFO/RR policies

The boot default is `ClassScheduler`. Linux policy setters publish core-owned
user configuration after credential checks. FIFO/RR outrank ordinary work and
retain a stable `TaskMeta::rt_order`; the core also validates this RT contract
for external policies. An equal-priority wake cannot jump an older FIFO turn.
Actual wake/yield and RR exhaustion rotate; involuntary preemption retains the
turn and RR credit. Shared per-CPU RT budget eligibility is authoritative for
all policies and cannot be replenished by queue events or callback selection.
See scheduler `spec.md` §3 for authority, inheritance and migration contracts.
