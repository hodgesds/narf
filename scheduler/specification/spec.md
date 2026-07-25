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
pub fn spawn<F: Future<Output=()> + Send + 'static>(f: F, domain: DomainId) -> TaskId;
pub fn spawn_with(f: impl Future<Output=()>, domain: DomainId, spec: TaskSpec) -> TaskId;
pub fn yield_now() -> impl Future<Output=()>;
pub fn donate_to(task: TaskId) -> impl Future<Output=()>; // direct context transfer
pub fn set_task_mems_allowed(task: u64, mask: u64);
pub fn task_mems_allowed(task: u64) -> u64;
pub fn clear_task_mems_allowed(task: u64);
```

Executor internals: per-CPU queues + global stealing pool; each task
carries `DomainId` so the executor switches domain before polling.
The per-task NUMA mask is the task-identity seam for cgroup-v2
`cpuset.mems`; the page-fault policy resolver treats it as a hard
allocation boundary and removes it when the task exits or detaches.

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
    pub affinity:  Affinity,
    pub budget:    Option<ResourceBudget>,    // see §3.4
    pub smt_share: SmtSharePolicy,            // None | Allow | Require
    pub priority:  Priority,                  // tentative
}
```

- **Hints, not guarantees.** The executor honours `Affinity.preferred`
  when possible; work-stealing may move a task within `allowed` under
  load.
- **`smt_share: Require`** is opt-in (latency-sensitive driver pairs
  that benefit from sharing an LLC).
- Pinning a task to a specific CPU requires a `Cap<CpuAffinity, Pin>`
  — not ambient, to prevent user tasks locking out kernel work.

### 3.4 Resource accounting (CPU share)

```rust
pub struct ResourceBudget {
    pub share_ppm: u32,               // parts-per-million of a CPU
    pub burst_ns:  u32,               // how long a task may exceed its share
    pub deadline:  Option<Deadline>,  // absolute wake deadline for realtime-ish
}
pub type CpuBudgetCap = Cap<CpuBudget, Spend>;
```

- A task holding a `CpuBudgetCap` is charged for every ns it runs.
  Running past the budget either blocks the task (default) or raises
  a `tracing/` event and continues at degraded priority
  (`OverrunPolicy::Degrade`).
- Budget caps are **revocable** like any cap; revocation causes the
  scheduler to stop picking that task until a replacement cap arrives.
- Fair-share between domains is implemented by assigning each domain
  a root budget cap from which per-task caps are derived.
- Driver domains typically carry a `share_ppm` large enough that they
  never hit the cap; the mechanism is there to *limit* misbehaving
  tasks, not to micro-manage well-behaved ones.

### 3.5 CPU hot-plug

```rust
pub fn cpu_online(id: CpuId) -> bool;
pub fn cpu_bring_up(id: CpuId, cap: &Cap<CpuLifecycle, Manage>) -> Result<(), HotPlugError>;
pub fn cpu_take_offline(id: CpuId, cap: &Cap<CpuLifecycle, Manage>) -> impl Future<Output=()>;
```

- Bring-up: `arch/` sends the startup IPI / `PSCI CPU_ON`; the new CPU
  joins the per-CPU run-queue set atomically.
- Take-offline: mark the CPU non-schedulable; migrate queued tasks
  with compatible affinity to other CPUs; drain; park the CPU via
  `HLT` / `WFI` loop. Undoes cleanly with `cpu_bring_up`.
- Used by `power/` (when that lands) for suspend/resume and by
  stress testing in `verification/`.

## 4. Invariants & safety properties

- A task always polls inside the domain it was spawned with.
- `donate_to` does not bypass capability checks; caller must hold a
  `Cap<Task, Invoke>` (Stage 3).
- The executor never holds a lock across a poll boundary.
- Work-stealing preserves per-task FIFO ordering of wakes.
- A task is never scheduled on a CPU outside its `Affinity.allowed`
  set. Work-stealing respects this as a hard constraint.
- `cpu_take_offline` is atomic from a running-task's perspective:
  it sees either the old CPU or a new CPU; never a torn migration.
- Resource-budget accounting is never racy: a task that exceeds its
  budget cannot cause a refund to another task.
- **PKRS / TCF save/restore is the scheduler's responsibility.** On
  every preemption the executor calls
  `memory::save_domain_state(&mut task.domain_saved)` before touching
  any executor-local state. On every resume it calls
  `memory::restore_domain_state(&task.domain_saved)` **before** the
  first instruction of the resumed task executes. No memory access in
  the new task's domain is allowed before the restore. Without this,
  every preemption is a TOCTOU window on domain rights.
- **Direct context transfer restores the callee's domain state before
  its first instruction.** The `donate_to` path, with interrupts
  disabled, saves the caller's `DomainSavedState`, restores the
  callee's, and only then branches into the callee. A `WRMSR
  IA32_PKRS` on x86_64 or the equivalent TCF write on aarch64 is part
  of the transfer's critical section.
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
  `time/` (deadlines), `power/` (EnergyAware governor feedback).
- **Provides to:** every other subsystem (anything async); `power/`
  (CPU hot-plug lifecycle for suspend/resume, load snapshot for DVFS);
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

**Decision:** **per-domain budget caps**. Each `DomainId`
gets a budget pool (configurable at boot, manifest-overridable
per driver). Tasks attribute CPU to their domain; a
spendthrift domain is throttled, not its individual tasks.

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

**Decision (was open):** **no gang scheduling**. Direct
context transfer (`donate_to`) handles the IPC-pair case
adequately and avoids the complexity of multi-CPU
coordinated dispatch. Producer-consumer pairs that benefit
from cache-locality express it via affinity hints, not gang.

Revisit if profiling shows specific pairs that lose >10% to
inter-CPU cache misses.

### 8.6 Realtime class shape (resolved)

**Decision:** **fixed-priority with deadline annotations**,
not full SCHED_DEADLINE. RT tasks declare:

```rust
pub struct RtSpec {
    pub priority: u8,               // 0..=63 (RT range)
    pub deadline_us: Option<u32>,   // soft hint; not enforced
    pub period_us:   Option<u32>,   // for periodic tasks
}
```

The deadline is a hint to `power/` for DVFS decisions and to
the scheduler for tie-breaking among same-priority RT tasks.
True deadline-bounded RT requires hardware support and a
carefully designed energy model that we're not attempting in
v1.

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
- `spawn`, `spawn_with_spec`, `spawn_user`.
- `run_until_empty`, `yield_now`.
- `Cap<Task, _>`, `Cap<CpuBudget, _>`.

Task waking and IRQ integration follows
`interrupts/spec` §8 (`wait_for_irq`'s waker contract).

`SCHEDULER_ABI_MAJOR = 1`, `SCHEDULER_ABI_MINOR = 0`.

## 10. Open questions

(none — all v0.3 questions resolved in §8)
