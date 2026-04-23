# rcu — Design Notes

## Iteration 2026-04-22

---

## Load-bearing decisions

**Poll-boundary = quiescent state.** This is the foundational inversion relative to Linux. Linux RCU's quiescent state is a context switch (preemption boundary); NARF's is `Future::poll` returning. The mapping is structurally clean — a task that has returned from `poll` cannot be holding a live `Shared<'g, T>` because `ReadGuard` is `!Send` and its lifetime is tied to the poll frame. The borrow checker enforces this at compile time for safe code. This eliminates most of Linux's "did you forget to call `rcu_read_unlock`?" class of bugs.

**Four variants, explicitly ranked.** QSBR is the hot-path default; Epoch is the fallback for non-executor contexts; Hazard provides bounded-memory guarantees; Sleepable allows `await` across reads. This rank ordering (laid out in the hazard-pointers research) is load-bearing: promoting Epoch above QSBR or using Hazard indiscriminately would silently degrade performance. The variant selection table in §3.2 is exactly the right approach — per-consumer, explicit, reviewable.

**Cap-gated sleepable readers.** `SleepableCap` is required to hold a `SleepableGuard`. This is not merely a permission gate; it's what makes `sleepable_sync` bounded. Without the cap, a buggy user task could hold a sleepable reservation indefinitely, reproducing Linux SRCU's worst-case unbounded stall. The linux-rcu-variants research confirms: Linux has no equivalent gate, and `synchronize_srcu` hanging is a real production incident pattern.

**Reclamation runs in the owner's domain.** The rule "drops run inside the domain that owned the allocation" means `Drop` impls for domain-tagged data see the correct PKS/MTE rights. This is subtle but critical: if reclamation were dispatched to a global worker that ran outside domain context, `Drop` would execute without the domain key that might be needed to zero-fill sensitive memory. The per-domain reclamation worker `Future` is the right architecture.

---

## Divergences from precedent

**vs. Linux RCU (preempt-based):** Linux's quiescent state is preemption; NARF's is poll-boundary. Linux achieves quiescence "for free" because every context switch is a quiescent state. NARF achieves it "for free" differently — the executor already calls `report_quiescent()` as part of the poll loop. The costs are comparable, but NARF's approach gives compile-time enforcement that Linux's runtime hooks cannot. Risky: code paths outside the executor (early boot, interrupt handlers) get no automatic quiescent signal; §8 open question correctly flags this. The proposed answer ("forbid QSBR there; handlers send short messages to a Future") is sound but needs explicit documentation as an invariant, not just an open question.

**vs. crossbeam-epoch:** NARF's API deliberately mirrors crossbeam-epoch naming (`Owned<T>`, `Shared<'g, T>`, `Atomic<T>`) because the epoch-and-qsbr research shows this eases reasoning. The key divergence is per-domain `defer_drop` queues instead of a single global collector. This is the right call for domain isolation, but it means writers must know which domain their data belongs to at defer time — a burden crossbeam-epoch doesn't impose.

**vs. seL4 (no RCU):** seL4 has no RCU equivalent; capability revocation is synchronous and bounded by design (CDT revocation walks a tree). seL4 pays for this with a revocation cost that is O(children in cap derivation tree) plus kernel reentry. NARF trades that predictable (if expensive) revocation for a grace-period window. The tradeoff is justified for NARF's performance goals but means revoked objects remain reachable from QSBR readers for up to one grace period — an interval that needs bounding.

**vs. Fuchsia Zircon handles:** Zircon uses per-handle reference counting rather than grace periods. Ref-counting is predictable but has per-access overhead (atomic inc/dec on every handle use). NARF's QSBR for capability table reads should be measurably cheaper on lookup-heavy workloads — but the Fraser epoch research warns that stuck readers cause unbounded memory growth in epoch schemes, which ref-counting never does. NARF's answer (cap revocation of stuck sleepable readers; executor cooperation for QSBR) is adequate but leaves the "what if a QSBR reader loops forever" case to scheduler vigilance.

---

## Proposed spec changes

- §3.3 QSBR: **Bound the maximum grace-period duration** — emit a `tracing/` event and escalate to a warning if any CPU has not reported quiescence within a configurable window (e.g. 100 ms). Why: an infinite-loop Future or a CPU that never enters the poll loop will silently prevent reclamation indefinitely; the current spec has no detection mechanism.

- §3.5 Sleepable: **Specify the default scope granularity for filesystem use cases** — one scope per mount point, not per mount type or per VFS instance. Why: the open question "one scope per mount? per FS driver?" has a clear answer from SRCU practice (per-mount is correct; a driver serving 100 mounts with one scope serialises all their syncs). This should be resolved in the spec, not left open.

- §3.7 Executor integration: **Define the maximum `defer_drop` drain budget per `report_quiescent` call in CPU cycles, not "a bounded slice."** Why: "bounded slice" is unactionable for tail-latency budgeting. The `verification/` spec §8 statistical protocol can only gate against a regression if there's a number to compare against. Suggest ≤ 500 cycles for the drain slice on the hot path; remainder falls to the reclamation worker.

- §4 Invariants: **Add: "A CPU that has not reported quiescence for more than N poll cycles is treated as absent for epoch-advance purposes."** N configurable, default 1000. Why: this is the missing escape hatch for the "stuck reader blocks reclamation" problem. Without it, reclamation stalls permanently; with it, we accept bounded unsafety (the stuck CPU eventually gets killed or the memory is leaked, but the rest of the system continues).

- §3.5 Sleepable: **Specify cooperative cancellation protocol when SleepableCap is revoked mid-read.** The spec says "the task sees a cancellation signal, its Drop runs, reservation releases" but never defines *how* the cancellation signal is delivered. Is it a waker notification? A flag checked at each `.await`? The cooperative model requires a concrete mechanism. Why: without it, implementers will invent incompatible approaches.

- §8 Open questions: **Resolve "QSBR on NMI / IRQ paths" before Stage 2** — the answer "forbid" should be promoted to an invariant in §4, not left as an open question. Why: interrupt handlers that call `pin()` without being in the executor poll loop will silently corrupt the quiescence accounting. Making this a formal prohibition now prevents subtle correctness bugs.

---

## Open invariants / cross-subsystem hazards

**rcu §3.7 ↔ scheduler §4 (poll boundary):** The `report_quiescent` hook fires at every `Future::poll` boundary. But `scheduler/` §4 states "the executor never holds a lock across a poll boundary." These two invariants compose safely, but there's an implicit third: `report_quiescent` itself must never take a lock that could be held by a task currently being polled. If `report_quiescent` takes, say, the reclamation worker's domain lock while a polled task holds the same lock, deadlock results. This interaction is not documented.

**rcu §3.5 (sleepable timeout) ↔ time §3.2 (sleep_until):** `sleepable_sync` enforces a deadline via `time/`. But `time/` §4 states `sleep_until` wakes at time ≥ deadline, never earlier. If the deadline is very tight (e.g. 1 ms) and the timer wheel coalesces it, the sleepable sync fires late. Late timeout is fine. But `SyncOutcome::Timeout(delinquents)` uses `time/` monotonic instants for the deadline check — and §3.4 SMP skew in `time/` means two CPUs may disagree on whether the deadline has passed by up to the skew tolerance. A writer on CPU A may declare a reader on CPU B delinquent before B's clock shows the deadline expired.

**rcu §3.2 (variant table) ↔ capabilities §? (cap-table reclamation):** The variant table assigns QSBR to `capabilities/` cap-table lookup. But capability revocation is a write operation that must ensure no reader holds a reference to the revoked cap descriptor before the descriptor is freed. This requires `rcu::sync().await` on the QSBR domain. During that sync, the revoking task is parked. If the revoked cap was the only cap authorising some critical kernel operation (e.g. a timer or IPC endpoint), blocking revocation could cause a priority inversion: a high-priority task waits on low-priority readers. The `scheduler/` §8 open question on priority inversion in `sync` is exactly this case — it is not hypothetical.

**rcu §3.5 (SleepableCap budget) ↔ security-model §4 (TCB boundary):** SleepableCap is minted by the scope owner. The scope owner for `filesystem/` dentry-like caches will presumably be a trusted kernel component, not a user process. But the budget (max duration, max simultaneous reservations) is "configurable" — if that configuration is user-accessible via some cap, a malicious user could inflate the budget and reproduce the SRCU stall. The security model must specify that budget configuration requires a TCB-scoped cap, not just a scope-owner cap.

---

## Additional opinionated commentary

The four-variant design is the right shape, but the ordering discipline in the hazard-pointer research (QSBR > Epoch > Sleepable > Hazard) should be hardened into a lint or code review checklist. In practice, engineers reach for the most familiar API, not the most appropriate one. If Epoch is easier to use because it resembles crossbeam-epoch more closely, it will be overused and QSBR will be underused — wasting the free quiescence signal the executor provides.

The per-domain reclamation worker Future running at low priority is elegant, but "low priority" interacts with the resource budget caps in `scheduler/`. If the reclamation worker's budget is exhausted by a busy domain's rapid object churn, deferred drops queue unboundedly. The spec promises reclamation runs inside the owner domain but does not specify what happens when the reclamation worker's budget is suspended. This needs a rate-limit or budget-exempt classification for reclamation.

The `sync()` implementation — yielding in a loop until all CPUs have passed the epoch — will spin the reclamation Future and re-enter the executor repeatedly on a busy system. If many writers are simultaneously waiting on grace periods, the executor run-queue fills with parked sync Futures. The `verification/` stress suite should explicitly include a "many concurrent `rcu::sync().await` calls" scenario.
