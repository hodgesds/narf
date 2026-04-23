# scheduler — Specification

> Status: **Outline v0.3** (Stage 1 → Stage 4). v0.2 added topology,
> affinity, resource accounting, and CPU hot-plug. v0.3 specifies
> PKRS / TCF save-restore at every preemption and direct-context-transfer
> boundary.

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
```

Executor internals: per-CPU queues + global stealing pool; each task
carries `DomainId` so the executor switches domain before polling.

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

## 8. Open questions

- What wake overhead is acceptable before Narf-Ring fast-paths bypass
  the executor entirely?
- Priorities — static levels, rate-monotonic, or something CFS-shaped?
- Do we need fairness guarantees for driver domains vs. user tasks?
- **E-core / P-core heterogeneity** (Alder Lake+, big.LITTLE).
  How are heterogeneous cores represented in `Topology`, and what
  scheduler policy decides which class each task runs on? Probably
  a class tag on `CpuInfo` and a task-supplied preference; defer
  concrete policy to Stage 4.
- **Gang scheduling** for cooperating driver pairs (e.g. IPC
  producer + consumer on same LLC) — worth the complexity, or lean
  on direct context transfer?
- **Realtime class.** SCHED_DEADLINE-style or simpler fixed-priority?
  Ties to `power/` decisions about DVFS-during-RT.
- **Hot-plug + PKS** — when a CPU comes online late, does it see a
  coherent domain-rights state? Spec the bring-up barrier.
