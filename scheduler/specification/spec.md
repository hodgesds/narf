# scheduler — Specification

> Status: **v1.0** (Stage 4 design lock). v0.3 specified PKRS/TCF
> save-restore on every preemption + direct-context-transfer
> boundary; v1.0 locks the priority class taxonomy, the
> heterogeneous-core policy, the wake-overhead cap, the
> realtime class shape, hot-plug PKS coherence, and ABI
> versioning.

## 1. Purpose & scope

**Owns:** The global async executor, per-CPU run queues, task wake-up
path, direct context transfer semantics, timer-driven preemption point,
work stealing (Stage 3+), **CPU topology model**, **affinity hints**,
**resource-account caps** (CPU share, time-slice budgets), **CPU
hot-plug** lifecycle.

**Does NOT own:** Trap entry (`frame/`), IRQ routing (`interrupts/`),
IPC (`ipc/`), memory quotas (`memory/`). The executor is driven by
those — it is the glue, not the signal source.

## 2. Assumptions

- Tasks are `Future`s pinned in kernel-allocated storage (`memory/`).
- Wakers are provided by IPC/interrupt sources.
- The Frame can disable interrupts around critical sections.

## 3. Public interface

### 3.1 Core executor API

```rust
pub fn spawn<F: Future<Output=()> + Send + 'static>(f: F) -> TaskId;
pub fn spawn_with_spec(
    f: impl Future<Output=()> + Send + 'static,
    spec: TaskSpec,
) -> TaskId;
pub fn spawn_stackful_with_spec(
    f: impl Future<Output=()> + Send + 'static,
    spec: TaskSpec,
    options: StackfulOptions,
) -> TaskId;
pub fn spawn_user(
    id: TaskId,
    f: impl Future<Output=()> + Send + 'static,
    spec: TaskSpec,
    address_space: Arc<AddressSpace>,
) -> TaskId;
pub fn yield_now() -> impl Future<Output=()>;
pub fn donate_to(task: TaskId, cap: &Cap<Task, Invoke>)
    -> Result<(), DonateError>;
pub fn set_task_mems_allowed(task: u64, mask: u64);
pub fn task_mems_allowed(task: u64) -> u64;
pub fn clear_task_mems_allowed(task: u64);
pub fn install_memory_pid_resolver(resolve: fn(task: u64) -> Option<u64>);
pub fn install_process_task_resolver(resolve: fn(pid: u64) -> Option<u64>);
pub fn online_cpu_set() -> CpuSet;
pub fn task_affinity(task: TaskId) -> Option<CpuSet>;
pub fn set_task_affinity(task: TaskId, requested: CpuSet)
    -> Result<(), SetAffinityError>;
/// Distinct live user address spaces, including currently-polled tasks.
pub fn all_address_spaces() -> Vec<Arc<AddressSpace>>;
pub fn set_user_perf_switch_hook(hook: fn(task: u64, running: bool));
pub fn set_user_slice_account_hook(hook: fn(elapsed_ns: u64));
pub fn set_user_kernel_preempt_hooks(pause: fn() -> bool, resume: fn());
pub fn note_forward_progress();          // bounded completion heartbeat
pub fn forward_progress_count() -> u64;  // fatal-watchdog snapshot
```

Executor internals are per-CPU queues plus global stealing. The specified
design requires every task to carry `DomainId` plus architecture-neutral
`DomainSavedState`, with the executor switching domain before polling. The
current `TaskSlot` carries an opaque architecture-neutral state and switches it
at cooperative poll boundaries. Trap-entry neutralisation and
first-instruction restore inside involuntary/direct context transfer remain
mandatory gaps. The state remains executor-private and is intentionally absent
from the policy interface.
The per-task NUMA mask is the task-identity seam for cgroup-v2
`cpuset.mems`; the page-fault policy resolver treats it as a hard
allocation boundary and removes it when the task exits or detaches.
The memory-controller charge provider resolves the executor-private `TaskId`
through `install_memory_pid_resolver` before charging: cgroup membership is
keyed by the outer userspace ProcessId, never by a numerically coincident task
id. Kernel tasks and unmapped bootstrap tasks remain unattributed.
The optional userspace PMU hook brackets every stackful continuation in
executor context after run-queue locks have been released. `running=true`
precedes the switch into the task and `running=false` follows every switch
back, including preemption and migration.
On x86_64, every own-stack switch-out folds the elapsed on-CPU slice through
the slice-account hook. A CPL0 timer preemption additionally calls `pause`
before switching and calls `resume` only when `pause` reported an open syscall
span, preventing off-CPU residency from being charged as kernel CPU time. The
callbacks run with interrupts disabled and may not sleep or take a non-IRQ-safe
lock.
Own-stack user tasks are timer-preemptible at the CPL3 scheduler tick. The
preemption path retains the task's live trap frame, FPU state, address space,
TLS base, and dedicated kernel-stack continuation across requeue, so a
syscall-free user loop cannot monopolize a CPU and strand runnable siblings.
Their CPL0 syscall continuations remain run-to-completion except at explicit
park/yield points. NARF now has a nestable CPU-local `preempt_disable()` guard,
but syscall/driver critical regions have not completed the adoption audit;
enabling arbitrary CPL0 timer preemption before that would still make an
unannotated lock-bearing continuation migratable and could strand shared state.
The progress counter advances when bounded synchronous waits complete, so a
long syscall with continuing I/O is not misclassified as a scheduler stall.
Ordinary background task polls deliberately do not advance it: scheduler churn
must not hide a foreground task that has stopped making useful progress.

#### 3.1.1 Pluggable scheduling policy

Scheduling policy may be implemented in a separate `no_std` crate using only
the public interface below:

```rust
pub trait Scheduler: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn pick_next(&self, cpu: CpuId, queue: &RunQueue<'_>)
        -> Option<TaskHandle>;
    fn on_install(&self) { }
    fn on_cpu_attach(&self, cpu: CpuId) { }
    fn on_cpu_detach(&self, cpu: CpuId) { }
    fn on_task_queue_event(&self, cpu: CpuId, event: TaskQueueEvent) { }
    fn on_uninstall(&self) { }
    fn on_cpu_state_change(&self, cpu: CpuId, change: CpuStateChange) { }
}

pub struct TaskMeta {
    pub id: TaskId,
    pub work_kind: WorkKind,
    pub class: SchedClass,
    pub priority: Priority,
    pub deadline_cycles: Option<u64>,
    pub budget: ResourceBudget,
    pub account: BudgetAccount,
    pub budget_state: BudgetView,
    pub runnable: bool,
    pub affinity: Affinity,
    pub addr_space: bool,
}

pub enum WorkKind { UserThread, KernelThread, AsyncTask, SoftIrq, Idle }
pub enum SchedClass { Idle, Batch, Default, Interactive, Realtime }
pub enum TaskEnqueueReason { Admitted, Requeued, Migrated, PolicyReplacement }
pub enum TaskDequeueReason { Selected, Migrated, PolicyReplacement }
pub enum TaskQueueEvent {
    Enqueued { task: TaskMeta, reason: TaskEnqueueReason },
    Dequeued { task: TaskMeta, reason: TaskDequeueReason },
}
pub enum CpuState { Offline, Starting, Active, Idle, Draining }
pub struct CpuStateChange {
    pub previous: CpuState,
    pub current: CpuState,
    pub idle: Option<CpuIdleMeta>,
}
pub struct CpuIdleMeta {
    pub queued: usize,
    pub parked: usize,
    pub throttled: usize,
    pub borrowable: usize,
    pub next_budget_replenishment: Option<u64>,
}
```

`RunQueue` is a read-only, callback-scoped projection. It exposes queue length,
the first opaque handle, and iteration over `(TaskHandle, TaskMeta)` snapshots;
it never exposes `TaskSlot`, futures, saved domain state, stacks, queue locks,
or context-switch entry points. A policy returns only an opaque handle. The
executor validates that the handle is still queued and in the highest available
eligibility tier, then performs removal itself. `None`, a stale handle, or an
ineligible handle falls back to the first eligible core-owned slot. When no
slot is dispatchable, the core may detach one slot only for cap/affinity
maintenance and rechecks its budget before polling. A faulty policy therefore
cannot detach, duplicate, lose, run throttled work, or strand a task.

Each CPU has a local publication slot containing a generation-stamped reference
to the active policy. Dispatch takes no global policy lock and performs no
shared `Arc` reference-count write; it touches only the CPU-local policy slot
and run queue. `pick_next` executes with both local locks held and therefore
must not allocate, sleep, re-enter the scheduler, or acquire an IRQ-contended
lock.

`on_task_queue_event` is the task-control lifecycle boundary. `Enqueued` means
the copied task is now in that CPU policy's selectable set; `Dequeued` means it
has left that set for selection or migration. The callback is serialized with
`pick_next` under the same CPU-local policy/run-queue lock order, so a policy
never observes selection before enqueue. It is a bounded hot-path callback and
must not allocate, sleep, re-enter the scheduler, or acquire an IRQ-contended
lock. Runnable/wake changes remain visible in authoritative `RunQueue`
snapshots rather than invoking arbitrary policy code from a waker or IRQ.

Policy replacement is a first-class rolling operation ordered by an atomic
generation ticket. `on_install` runs once before publication;
`on_cpu_attach(cpu)` runs before that CPU can enter the new policy. Replacement
of a CPU slot waits for its in-flight callback to return, publishes the new
complete instance, then calls the old policy's `on_cpu_detach(cpu)` outside the
slot lock. `on_uninstall` runs once when the last CPU/reference releases the old
instance. A completed, non-concurrent `install_scheduler` call has processed
every CPU slot. During the bounded rolling interval, different CPUs may use old
and new policies, but one dispatch never mixes them. Task slots, runnable state,
budget/debt, affinity, and switch/domain state stay core-owned, so policy
replacement neither migrates nor reconstructs task execution state. Stateful
policies receive `Dequeued(PolicyReplacement)` on the old instance and
`Enqueued(PolicyReplacement)` on the new instance for every task queued during
the CPU-local cutover. A task already executing left the old policy at
selection; if it returns `Pending`, its later requeue enters whichever policy
is then active. This makes task-control events balanced without stopping CPUs.
Install/CPU lifecycle callbacks may allocate, but task queue callbacks may not;
none may recursively install a policy.
Concurrent installers are ordered by generation: the newest issued generation
wins every CPU slot, and an older overlapping caller returns
`SchedulerError::Superseded` if that newer ticket existed at its completion
linearization point. Superseded instances still receive balanced detach and
uninstall callbacks; callers may retry with a newly constructed policy.

`on_cpu_state_change` is an edge-triggered observation delivered after relevant
run-queue/lifecycle locks are released. `Idle` includes copied queue and budget
state; other transitions carry `idle: None`. The callback may update bounded,
nonblocking policy telemetry, but does not grant authority over hot-plug,
stealing, clockevents, architecture halt, or power state.

A separate crate is an API and build boundary, not a protection boundary. The
core remains safe against a returned stale/invalid choice, but a policy that
loops forever can deny service on the calling CPU. Policy implementations are
therefore trusted for availability and require TCB-grade review until policy
execution is moved behind a protected-domain/RPC boundary.

Budget and accounting values in `TaskMeta` are immutable copies for policy
ranking. Budget-cap liveness checks, elapsed-time charging, donation settlement,
throttling, task removal, and accounting attribution remain executor-owned.
In particular, `WorkKind` is descriptive policy input and never substitutes for
a capability, process/cgroup identity, domain id, or IRQ-source identity.
Hard IRQ/NMI execution is not a schedulable `WorkKind`; hard-IRQ entry/exit is
charged to per-CPU counters and subtracted from task dispatch time, while
deferred interrupt work uses `SoftIrq`. The same public guard exists for NMI;
architecture NMI/FIQ entry wiring remains a gate.

### 3.2 CPU topology

```rust
pub struct CpuId(u16);
pub struct NumaNodeId(u8);
pub struct CpuSet;                        // bitset; typically ≤ 4096 CPUs

pub fn cpu_count() -> u16;
pub fn cpu_topology() -> &'static Topology;
pub struct Topology {
    pub cpus: &'static [CpuInfo],
    pub numa_nodes: &'static [NumaInfo],
}
pub struct CpuInfo { pub id: CpuId, pub node: NumaNodeId, pub smt_sibling_of: Option<CpuId>,
                     pub llc_group: u16, pub freq_hint_mhz: u16 }
```

- Topology is discovered once by `arch/` at boot (CPUID leaves on
  x86_64; `MPIDR_EL1` + ACPI/DT on aarch64) and published here
  read-only.
- NUMA awareness: each `CpuInfo` records its node; `memory/`
  coordinates so per-CPU kernel storage lands on the local node.
- SMT/HyperThread sibling tracking: the scheduler avoids scheduling
  two cache-competing tasks on SMT siblings unless explicitly opted
  in (see §3.4).

### 3.3 Affinity and placement

```rust
pub struct Affinity { pub allowed: CpuSet, pub preferred: Option<CpuId> }
pub struct TaskSpec {
    pub affinity: Affinity,
    pub budget: ResourceBudget,
    pub budget_cap: Option<Cap<CpuBudget, Spend>>,
    pub work_kind: WorkKind,
    pub class: SchedClass,
    pub priority: Priority,
    pub smt: SmtSharePolicy,
}
```

- **Hints, not guarantees.** The executor honours `Affinity.preferred`
  for initial placement when possible; a completed poll remains on its
  current CPU while that CPU is allowed. Work-stealing may move a task
  within `allowed` under load.
- Runtime affinity updates are published in a task-identity registry so
  a currently-polled slot cannot miss them. A parked slot whose queue is
  excluded is moved immediately; a running cooperative continuation is
  moved only after it yields back to the executor.
- The infallible spawn API validates that an initial mask contains an online
  CPU. A partly offline mask is retained for future hot-plug; if an internal
  caller supplies a wholly stale/offline mask, creation falls back to the
  caller's online CPU instead of admitting an unrunnable slot. Subsequent
  runtime updates reject an empty effective mask.
- **`smt_share: Require`** is opt-in (latency-sensitive driver pairs
  that benefit from sharing an LLC).
- Native domain callers that restrict another domain's tasks require
  `Cap<CpuAffinity, Pin>`; the capability-bearing control surface remains
  separate from Linux process compatibility. The Linux-compat
  `sched_setaffinity(2)` bridge authorises self/same-uid processes and calls
  the task-identity/online-mask checked scheduler path.

### 3.4 Resource accounting (CPU share)

```rust
pub struct ResourceBudget {
    pub share_ppm: u32,                  // parts-per-million of a CPU
    pub burst_cycles: u64,               // contiguous-poll burst allowance
    pub deadline_cycles: Option<u64>,    // absolute monotonic-cycle deadline
    pub policy: OverrunPolicy,
    pub period: Option<PeriodBudget>,
}
pub struct PeriodBudget {
    pub runtime_cycles: u64,
    pub period_cycles: u64,
    pub max_borrow_cycles: u64,
    pub exhaustion: ExhaustionPolicy,     // Strict | IdleBorrow
}
pub struct BudgetView {
    pub eligibility: BudgetEligibility,   // Eligible | Borrowable | Throttled
    pub remaining_cycles: u64,
    pub replenish_at_cycles: Option<u64>,
    pub borrowed_cycles: u64,
    pub debt_cycles: u64,
}
pub type CpuBudgetCap = Cap<CpuBudget, Spend>;
pub fn spawn_realtime<F>(f: F, spec: TaskSpec, authority: &CpuBudgetCap)
    -> Result<TaskId, AdmissionError>;
pub fn spawn_realtime_with_options<F>(f: F, spec: TaskSpec,
    authority: &CpuBudgetCap, options: StackfulOptions)
    -> Result<TaskId, AdmissionError>;
pub fn realtime_bandwidth(cpu: CpuId) -> RealtimeBandwidth;
```

- `burst_cycles` and `OverrunPolicy` govern an individual dispatch that runs
  too long (`Throttle`, `Demote`, `Kill`, or `Ignore`). `PeriodBudget` governs
  aggregate runtime across dispatches and is authoritative when present.
- The executor initialises a period on first dispatch, deducts actual elapsed
  cycles after every poll/switch-back, and advances an expired replenishment
  boundary without looping once per missed period. Unused runtime does not
  accumulate.
- `Strict` makes an exhausted task ineligible until replenishment, even if the
  CPU would otherwise idle. `IdleBorrow` exposes a lower `Borrowable` tier:
  bounded idle capacity may run only when no `Eligible` work exists and is
  retained as debt against later replenishment.
- Cooperative/non-preemptible overshoot is also debt. It is not silently
  forgiven at the next boundary.
- Before a stackful switch-in, the core publishes soft and hard budget
  ends and arms the clockevent. At the soft end, an idle borrower resumes the
  same continuation when no competitor exists, avoiding a switch to idle and
  back. A competitor wake makes it preemptible at the next tick; the hard end
  or period boundary always switches.
- Policy receives `BudgetView` by value. It can rank eligible tasks but cannot
  replenish runtime, modify debt, or make `Throttled` work runnable. Core-side
  validation enforces `Eligible` before `Borrowable` regardless of policy.
- Budget caps are **revocable** like any cap; revocation causes the executor
  to reap the task at the next cap check.
- Realtime admission reserves the ceiling-rounded `runtime/period` utilization
  atomically against the selected CPU, the online system, and the
  `CpuBudget` capability-object domain. A conservative hash collision may
  reject admission but can never permit overcommit. Five percent of each CPU
  remains outside RT reservations for IRQ and kernel progress.
- Admitted RT tasks are pinned to their admission CPU; affinity mutation
  returns `RealtimePinned`. Generic `spawn_with_spec` and `spawn_user` demote a
  bare `Realtime` label to `Default`, so policy metadata cannot mint service.
- Driver domains typically carry a `share_ppm` large enough that they
  never hit the cap; the mechanism is there to *limit* misbehaving
  tasks, not to micro-manage well-behaved ones.
- `share_ppm` is descriptive unless a consistent `PeriodBudget` is attached;
  `runtime_cycles/period_cycles` is the enforcement source of truth.
- Stackless futures remain bounded only at cooperative poll returns. Stackful
  kernel tasks are tick-preemptive on both architectures; x86_64 additionally
  supports own-stack CPL3 preemption. NMI/FIQ entry accounting and aarch64 EL0
  own-stack handoff remain incomplete.

### 3.5 CPU hot-plug

```rust
pub fn cpu_online(id: CpuId) -> bool;
pub fn cpu_state(id: CpuId) -> CpuState;
pub fn cpu_bring_up(id: CpuId, cap: &Cap<CpuLifecycle, Invoke>)
    -> Result<(), HotPlugError>;
pub fn cpu_take_offline(id: CpuId, cap: &Cap<CpuLifecycle, Invoke>)
    -> Result<(), HotPlugError>;
```

- The implementation publishes `Draining` and waits for a target-CPU
  between-polls acknowledgement before inspecting its queue. The target's
  run loop cannot overwrite a lifecycle state with a late Active/Idle edge and
  remains logically parked while Draining/Offline. A bounded acknowledgement
  timeout or a pinned task returns `HotPlugError::Busy`; otherwise the core
  migrates the queue without holding source and destination locks together
  before publishing `Offline`.
- Architecture startup (`INIT-SIPI-SIPI` / `PSCI CPU_ON`) and physical park are
  integration gates. Logical queue drain completion is not proof firmware has
  powered the CPU down.
- Used by `power/` (when that lands) for suspend/resume and by
  stress testing in `verification/`.

Frequency control is deliberately not part of `Scheduler`. Scheduling classes
express ordering, deadlines, and latency intent; the core publishes CPU/load
observations; a separately capability-gated `power/` governor owns DVFS and
must enforce thermal and platform constraints. An external scheduler policy
therefore cannot write P-states or architecture frequency registers.

```rust
pub fn cpu_demand(cpu: CpuId) -> CpuDemand;
pub fn interrupt_account_enter(kind: InterruptKind) -> InterruptAccountGuard;
pub fn preempt_disable() -> PreemptGuard;
pub fn preempt_count() -> u32;
```

`CpuDemand` reads only one CPU-local queue and copied/atomic counters. It
reports runnable work-kind counts, RT reservation, next deadline, state, and
cumulative hard-IRQ/NMI cycles. It is a governor input, never a frequency
control callback.

## 4. Invariants & safety properties

- A task always polls inside the domain it was spawned with.
- A user task polls with its own address-space root active. On aarch64 the
  executor saves the incoming TTBR0, installs the task's TTBR0 before polling,
  and restores the saved `(root, ASID)` before any later kernel or user task is
  polled. Lifetime-scoped ASIDs make both switches non-flushing; an ASID is not
  reused until the memory subsystem completes a system-wide tag invalidation.
- On x86_64 the executor publishes process-PCID-0 residency before a user root
  is loaded using the memory subsystem's sequentially consistent publication
  primitive, and clears it only after the plain kernel-root CR3 restore has
  invalidated PCID 0 locally. A CPU entering either scheduler halt path marks
  itself TLB-idle; after wake it clears that state and completes any deferred
  full non-global flush before another task root or domain context can load.
  The idle/debt publication handshake guarantees a racing shootdown is handled
  either by its ordinary IPI acknowledgement or by this pre-dispatch flush.
- `donate_to` does not bypass capability checks; caller must hold a
  `Cap<Task, Invoke>` (Stage 3).
- The executor never holds a lock across a poll boundary.
- Work-stealing preserves per-task FIFO ordering of wakes.
- A task is never scheduled on a CPU outside its `Affinity.allowed`
  set. Work-stealing and runtime requeue both respect this as a hard
  constraint; a mask change takes effect at the next cooperative poll
  boundary if the task is already executing.
- `cpu_take_offline` is atomic from a running-task's perspective:
  it sees either the old CPU or a new CPU; never a torn migration.
- Resource-budget accounting is never racy: a task that exceeds its
  budget cannot cause a refund to another task.
- A policy cannot override budget eligibility. Regular eligible work always
  outranks idle-borrow work, and strict-throttled work cannot be polled before
  replenishment.
- Idle borrowing is bounded and accounted as debt. It may save a context
  switch only while no competing eligible work exists.
- A task-scoped PMU event is active only between its matching switch-in and
  switch-out hook calls. The hook must stop and fold the current CPU's counter
  before the executor or another task runs.
- **Domain state is task context, with mechanism owned below policy.** On
  every cooperative poll return the executor calls
  `memory::save_domain_state()` before touching
  any executor-local state. On every resume it calls
  `memory::restore_domain_state(&task.domain_saved)` before the
  first instruction of the resumed task executes. No memory access in
  the new task's domain is allowed before the restore. Without this,
  every preemption is a TOCTOU window on domain rights. For stackful and
  involuntary paths, architecture-owned trap frames and `kernel_switch` close
  the same boundary without exposing register details to scheduler policy:
  entry neutralises before Rust/outgoing stores, and restore occurs after the
  last incoming-context load and before the resumed continuation.
- A future true direct-transfer primitive must restore the callee's domain
  state before its first instruction. Today's `donate_to` only moves budget
  credit and queue position; it does not branch directly to the donee and must
  not be described as satisfying this future invariant.
- **A task never polls across an await with a `ReadGuard` held
  (except sleepable-RCU guards).** The executor's `report_quiescent`
  hook relies on poll-boundary release; holding a non-sleepable guard
  across await is a UAF waiting to happen. Enforced by `!Send` + type
  discipline in `rcu/`; the scheduler treats the invariant as given.

## 5. Architecture notes

### x86_64
- Preemption point via LAPIC timer (TSC-deadline) raising a reschedule IPI.
- `mwait`/`umwait` for idle with exit latency small enough not to hurt
  wake responsiveness.
- Topology discovery: CPUID leaves `0x0B` / `0x1F` (x2APIC topology);
  LLC info from leaf `4`; NUMA from ACPI SRAT.
- Hot-plug: startup IPI (INIT-SIPI-SIPI) for bring-up; `HLT` with
  IPIs disabled for park.

### aarch64
- Preemption via the generic timer.
- `WFI` in idle, `SEV` to wake remote CPUs.
- Topology discovery: `MPIDR_EL1` + ACPI PPTT / devicetree
  `cpu-map` nodes.
- Hot-plug: PSCI `CPU_ON` / `CPU_OFF` where firmware supports it;
  otherwise fall back to parked-with-SGI wake.

## 6. Dependencies

- **Consumes:** `arch/` (timer, CPU pause, topology discovery, IPI,
  PSCI), `frame/` (enter_domain), `memory/` (task storage + NUMA-local
  per-CPU storage), `interrupts/` (timer IRQ, reschedule IPI),
  `capabilities/` (Stage 3 donation check; affinity and budget caps),
  `time/` (deadlines), `power/` (thermal/capacity feedback; never direct
  frequency-register access from scheduling policy).
- **Provides to:** every other subsystem (anything async); `power/`
  (CPU lifecycle and read-only demand/state observations for DVFS decisions);
  `rcu/` (`report_quiescent` hook at each poll boundary).

## 7. Stage assignment

Stage 1: single-CPU cooperative executor; no preemption; static topology (n=1).
Stage 2: SMP with topology discovery, timer-driven preemption point,
NUMA-aware per-CPU state, CPU hot-plug (bring up APs).
Stage 3: direct context transfer, capability-checked donation, work
stealing, affinity honoured, `ResourceBudget` accounting.
Stage 4: CPU take-offline path for suspend/resume (with `power/`),
SMT-aware placement, deadline-ish realtime class.

## 8. Resolved decisions

### 8.1 Wake-overhead cap (resolved)

**Decision:** **2 µs** (≈ 6000 cycles at 3 GHz) is the budget
for a wake-and-poll round trip in the executor. Above this,
hot paths bypass the executor with direct context transfer
(`donate_to`, mirroring seL4's IPC fast path) or with
Narf-Ring polling on the consumer side.

The 2 µs cap is profile-tracked; `tracing/` emits
`scheduler.wake_latency` histograms and a CI gate fails if
the p99 regresses past 2.5 µs.

### 8.2 Priority taxonomy (resolved)

**Decision:** **fixed-priority levels with budget-based
preemption**, not CFS-shaped. Five classes:

```rust
pub enum SchedClass {
    Idle,         // background; preempted by anything
    Batch,        // non-interactive bulk work
    Default,      // ordinary kernel/user tasks
    Interactive,  // boosted for low-latency response
    Realtime,     // bounded latency; see §8.4
}
```

Within a class, scheduling is per-CPU FIFO with budget caps.
Inter-class is strict priority (Realtime preempts
Interactive preempts Default …).

### 8.3 Driver-domain vs user-task fairness (resolved)

**Decision:** **per-domain budget caps**. This is the aggregation target, not
yet an implemented root-pool mechanism. Each `DomainId` will get a budget pool
(configurable at boot and manifest-overridable per driver). Tasks attribute CPU
to their domain; a spendthrift domain is throttled, not its individual tasks.

Default budgets:
- `DOMAIN_FRAME / CAPS / MEMORY_MGR` — uncapped (TCB).
- Driver domains — 100 ms / sec / CPU each (tunable).
- `DOMAIN_USERSPACE_K` — uncapped per-task; per-process caps
  set by `process/`.

### 8.4 E-core / P-core (resolved)

**Decision:** **`CpuInfo::class` enumerates {`Performance`,
`Efficient`, `Mixed`}**, populated by `bus/` from CPUID +
ACPI on x86_64 / DT `cpu-capacity` on aarch64. Tasks declare
`pref: Option<CpuClass>` in `TaskSpec`; default is `None` =
"don't care."

Scheduler policy:
- Realtime tasks → P cores when available.
- Interactive tasks → P cores preferred, E cores acceptable
  when P cores are saturated.
- Batch / Idle tasks → E cores preferred.
- Driver tasks → P core, can be relocated under thermal
  pressure (signalled by `power/`).

### 8.5 Gang scheduling (resolved)

**Decision (was open):** **no gang scheduling**. The current `donate_to`
operation transfers bounded budget credit and moves an already queued donee
to the head of its core-owned queue; it does not branch directly to the donee.
This covers the present IPC-pair priority-inheritance case without multi-CPU
coordinated dispatch. A future true direct-transfer fast path remains subject
to the first-instruction domain-restore gate in §4. Producer-consumer pairs
that benefit from cache locality express it via affinity hints, not gang.

Revisit if profiling shows specific pairs that lose >10% to
inter-CPU cache misses.

### 8.6 Realtime class shape (resolved)

**Decision:** **fixed-priority with deadline annotations and core-owned
period bandwidth**, not a claim of full Linux `SCHED_DEADLINE`. RT tasks use:

```rust
TaskSpec::realtime_periodic(runtime_cycles, period_cycles, deadline_cycles)
```

The deadline orders equal-priority realtime tasks. Runtime/period is strictly
enforced by the core. `spawn_realtime` requires a live
`Cap<CpuBudget, Spend>`, ceiling-rounds utilization, and atomically reserves it
against CPU, online-system, and capability-object-domain ceilings before the
task becomes visible. The admitted task is CPU-pinned and retains an RAII
reservation until its slot is destroyed. A label supplied through a generic
spawn path is demoted to `Default`; only successful admission establishes RT
service. This provides bounded fixed-priority periodic service, but does not
yet promise Linux `SCHED_DEADLINE`-style deadline-miss guarantees or
transactional RT migration.

### 8.7 CPU hot-plug PKS coherence (resolved)

**Decision:** **AP bring-up sequence includes a PKS-init
barrier** before the AP is marked ready. Sequence:

1. AP boot trampoline: enable PKS (`CR4.PKS=1` on x86_64;
   equivalent MTE init on aarch64).
2. Initialise per-CPU `current_domain = DomainId::FRAME`
   and write the corresponding PKRS / TCF.
3. Issue a memory fence visible to the BSP.
4. BSP polls a shared `online_count` until the AP has
   completed steps 1-3.
5. Only then is the AP accepted into the run-queue
   shuffler.

This guarantees that any task migrated to the new AP sees a
coherent domain-rights state from the first instruction.

## 9. ABI versioning

`scheduler/` exports through SDK at `@v0`:
- `spawn`, `spawn_with_spec`, `spawn_stackful_with_spec`, `spawn_user`.
- `run_until_empty`, `yield_now`.
- `Scheduler`, `RunQueue`, `TaskHandle`, `TaskMeta`, `WorkKind`, `SchedClass`,
  `TaskQueueEvent`, `TaskEnqueueReason`, `TaskDequeueReason`, `CpuState`,
  `CpuStateChange`, `CpuIdleMeta`, `cpu_state`.
- `ResourceBudget`, `PeriodBudget`, `BudgetView`, `BudgetEligibility`.
- `spawn_realtime`, `spawn_realtime_with_options`, `AdmissionError`,
  `RealtimeBandwidth`, `realtime_bandwidth`.
- `CpuDemand`, `cpu_demand`, `InterruptKind`, `interrupt_account_enter`.
- `PreemptGuard`, `preempt_disable`, `preempt_count`.
- `Cap<Task, _>`, `Cap<CpuBudget, _>`.

Task waking and IRQ integration follows
`interrupts/spec` §8 (`wait_for_irq`'s waker contract).

`SCHEDULER_ABI_MAJOR = 1`, `SCHEDULER_ABI_MINOR = 2`.

## 10. Open implementation gates

- MTE allocation-tag ownership on aarch64 (switch/vector state preservation is
  complete; enforcement is structural until the allocator is tag-aware).
- Aarch64 EL0 own-stack handoff and preemption.
- Adoption audit for arbitrary CPL0 user-continuation preempt guards.
- NMI/FIQ entry wiring and a bounded softirq execution policy.
