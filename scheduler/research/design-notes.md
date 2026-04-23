# scheduler — Design Notes

## Iteration 2026-04-22

---

## Load-bearing decisions

**The executor is TCB.** This is not just an organisational decision — it determines what can compromise the security model. If the executor polls a task in the wrong domain, or fails to call `enter_domain` before polling, the domain isolation guarantee collapses without any PKS fault (the right key is loaded but for the wrong task). The `scheduler/` core is therefore as security-sensitive as `capabilities/` or `frame/`, and the process spec correctly includes it in the TCB definition.

**DomainId is per-task, checked at poll time.** The invariant "a task always polls inside the domain it was spawned with" (§4) means domain switching happens in the executor's inner loop, not at task creation or IPC entry. This is load-bearing: a task that escapes its domain during a poll would see the previous domain's PKS keys, giving it read/write access to that domain's data. The mechanism must be `frame::enter_domain()` called unconditionally before each `poll`, not cached or optimised away.

**Work-stealing respects `Affinity.allowed` as a hard constraint.** The spec correctly marks this as hard, not soft. A steal that moves a task outside its allowed set could break NUMA memory locality, violate CPU-isolation budgets, or (for CPU-pinned tasks) break the assumption that `CpuAffinity::Pin` is honoured. The distinction "hints, not guarantees" for `Affinity.preferred` vs. hard constraint for `Affinity.allowed` needs to survive every optimisation of the stealer.

**Direct context transfer is a Stage 3 capability-checked operation.** `donate_to(task)` requires `Cap<Task, Invoke>`. This is the correct answer to L4's problem: L4's direct switch bypasses the scheduler entirely and has no cap gate, which makes it a covert channel if A can force-donate time to B without B's cooperation. NARF's model requires the donating task to hold an invoke capability on the target, ensuring B has explicitly published its identity to A. The l4-direct-switch research notes L4's latency gains are ~80%; NARF's extra cap check costs a cache line on the fast path but eliminates the covert-channel concern.

---

## Divergences from precedent

**vs. Embassy executor:** Embassy's executor is entirely cooperative with no domain switching — tasks run to `Poll::Pending` and the executor picks the next ready task. NARF adds domain switching to this loop, which is architecturally clean but means the per-poll overhead is no longer "a few instructions" — it includes an `WRPKRU` on x86_64 or the equivalent MTE context operation. The embassy-executor research notes the model "relies on tasks not blocking indefinitely"; NARF inherits this constraint but adds the additional discipline that domain entry/exit must not fault.

**vs. Linux CFS:** CFS uses a virtual-time fair-share model with a per-task `vruntime` and a red-black tree. NARF's `ResourceBudget` with `share_ppm` is simpler and more conservative — it is a rate limiter, not a fair-share scheduler. This divergence is intentional: NARF's primary use case in Stages 1-3 is kernel services and drivers, not competing user processes. CFS is optimised for mixed user-process workloads. NARF's model is easier to verify (no complex virtual-time calculations) but gives up some fairness guarantees. Risky if NARF ever needs to run competing user workloads fairly — the Stage 4 "deadline class" hints at this concern.

**vs. Fuchsia Zircon scheduler:** Zircon uses a fair + deadline hybrid with explicit CPU affinity and a profile-based API. NARF's approach is similar in shape but differs in one critical way: Zircon's scheduler is a separate component from the IPC subsystem; NARF's direct-context-transfer fuses scheduling and IPC on the fast path. This fusion is the L4 insight applied to an async executor — it is the right call for NARF's performance goals but creates a coupling that needs careful invariant tracking (if IPC is broken, the scheduler's fast path is also broken).

**vs. Tokio multi-thread scheduler:** Tokio uses work-stealing with per-thread local queues and a global injection queue. NARF's design mirrors this (per-CPU queues + global stealing pool), but Tokio does not have domain switching, capability checks, or CPU-hot-plug lifecycle. The Tokio work-stealing design is well-studied and battle-tested; NARF should adopt its queue structure directly rather than inventing a custom one. The open question about representing domain switches ("tagging the future? a `Domain<F>` wrapper?") has a clean answer from Tokio's `LocalSet` design: a wrapper future `DomainFuture<F>` that enters the domain before delegating to `F::poll` and exits after. This composes cleanly with the stealer's affinity check.

---

## Proposed spec changes

- §3.1 Core executor API: **Define `DomainFuture<F>` as the canonical wrapping type** for domain-aware tasks rather than leaving domain entry as an implicit executor responsibility. Why: if domain entry is the executor's job and happens outside the task's type, there is no compile-time way to ensure a raw Future is never polled without domain entry. A `DomainFuture<F>` wrapper makes the domain entry part of the Future's `poll` impl, which is verifiable by Kani (verification/§10).

- §4 Invariants: **Add: "The executor must not hold a live domain key (i.e. must be in the kernel's neutral domain) between polls."** Why: if the executor's own bookkeeping code runs in domain N's context (because the previous task was in N and the domain wasn't restored to neutral), any memory the executor touches is tagged to domain N's key — a silent privilege escalation. This invariant is implicit in the current spec but never stated.

- §3.3 Affinity and placement: **Specify the capability needed to set `Affinity.allowed`** — not just to pin. Currently, any `spawn_with` caller can set `Affinity.allowed` to restrict a task to a specific CPU, which combined with a high-priority task could starve all other tasks on that CPU. Restricting `allowed` to fewer than `cpu_count()` CPUs should require a `Cap<CpuAffinity, Restrict>`. Why: without this, an unprivileged driver domain could deny CPU time to other domains by filling a CPU's run-queue with affinity-restricted tasks.

- §3.5 CPU hot-plug: **Define the domain-rights state a newly brought-up CPU inherits.** The §8 open question "when a CPU comes online late, does it see a coherent domain-rights state?" should be answered here: a new CPU starts in the kernel neutral domain with no domain keys loaded; `enter_domain()` is called unconditionally before the first task poll. Why: without this, race conditions between PKS key registration and the first task assignment on the new CPU could grant the task wrong domain access.

- §3.4 Resource accounting: **Specify what happens to a domain's reclamation worker (rcu/) when its root budget cap is revoked.** The spec says revocation causes the scheduler to stop picking the task; but the RCU reclamation worker is the mechanism by which domain memory is freed. Stopping it starves memory reclamation. Why: this creates a denial-of-service: revoke a domain's budget cap, its reclamation worker stops, memory accumulates. Reclamation workers need budget-exempt or budget-elevated status.

- §8 Open questions: **Resolve E-core / P-core heterogeneity representation before Stage 4** — add a `cpu_class: CpuClass` field to `CpuInfo` (values: `Efficiency`, `Performance`, `Unknown`) derived from CPUID leaf `0x1A` on x86_64 and `MPIDR_EL1` affinity level on aarch64. Why: deferring to "Stage 4 probably a class tag" is fine for now but the field needs to be in the struct from Stage 2 to avoid an ABI break at Stage 4.

---

## Open invariants / cross-subsystem hazards

**scheduler §4 (domain-at-poll) ↔ rcu §3.7 (report_quiescent):** `report_quiescent` is called around each `Future::poll`. If the executor calls `report_quiescent` while in the neutral domain (between polls), but a task's `drop` fires during poll in domain N (task completed and owns an RCU-guarded object), the `Drop` impl runs in domain N but the `defer_drop` queue accounting happens under the neutral domain's lock. If the queue is domain-partitioned (as the spec requires), the executor must know which domain to charge the drop to. This means `drop` can only be called with the domain context live — which means the executor may need to re-enter the domain to process task completion drops.

**scheduler §3.5 (cpu_take_offline) ↔ rcu §3.7 (reclamation worker Future):** When a CPU is taken offline, tasks with compatible affinity are migrated. But the per-domain reclamation worker Future that drains `defer_drop` queues may be affinity-pinned to the going-offline CPU (if it was spawned with per-CPU affinity for NUMA reasons). The spec needs explicit handling: either reclamation workers are never affinity-pinned, or `cpu_take_offline` explicitly migrates them.

**scheduler §3.4 (ResourceBudget) ↔ tracing §3.2.1 (FnTime overhead):** `FnTime` with 4 HW counters adds ≤ 600 cycles per call. If a task is budget-accounted and `FnTime` is active on that task's hot functions, the probe overhead consumes the task's CPU budget without doing useful work. This inflates budget usage and may trigger false `OverrunPolicy::Degrade` events. The verification spec needs a test case: "budget accounting with FnTime active should not falsely degrade a task that is within real-work budget."

**scheduler §3.1 (spawn domain parameter) ↔ security-model §4 (TCB boundary):** `spawn<F>(f, domain)` takes a `DomainId` directly. If this API is callable from a non-TCB domain, a misbehaving driver could spawn a task into domain 0 (kernel/TCB domain). The spec says capabilities will gate this in Stage 3 (`Cap<Task, Invoke>` for donation) but does not state that spawn itself requires a capability. A `Cap<Domain, Spawn>` should be required to spawn into any domain other than the caller's own.

---

## Additional opinionated commentary

The direct-context-transfer story is compelling but the spec never resolves whether it is an optimisation (the scheduler is free to do a normal dispatch instead) or a contract (the IPC layer guarantees the donation happens immediately). If it is only an optimisation, IPC latency is unpredictable and the Narf-Ring performance claims are only amortised. If it is a contract, the executor must guarantee it, which constraints work-stealing and preemption. The l4-direct-switch research shows L4 treats it as a contract on the fast path with graceful fallback — NARF should adopt the same model explicitly.

The "gang scheduling" open question is worth addressing early: if a VirtIO producer and consumer domain should run simultaneously for maximum throughput, not scheduling them together can easily halve NIC throughput. The direct-context-transfer model handles one-way donation but not symmetric co-scheduling. This is a gap that may only surface in Stage 4 benchmarks when it's expensive to fix architecturally.

Priority inversion is mentioned in §8 but the `ResourceBudget` design makes it worse: a high-priority task waiting on `rcu::sync().await` is now blocked behind low-priority readers *and* subject to the reclamation worker's budget availability. Priority inheritance for `sync()` waiters should be designed in Stage 2, not retrofitted at Stage 4 when real RT workloads appear.
