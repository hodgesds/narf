# Epoch-based Reclamation and QSBR — reading notes

**Primary sources:** Fraser, "Practical Lock-Freedom" (PhD thesis,
2004); McKenney et al. on QSBR variants; `crossbeam-epoch` Rust
implementation; Userspace RCU (`liburcu`) QSBR flavour;
DPDK `rte_rcu_qsbr`.

> Distilled for NARF design. The two variants NARF uses by default.

## The shared premise

A reader obtains shared data, dereferences it, releases the
reservation. A concurrent writer wants to replace the data and free
the old copy. The problem: a reader still dereferencing the old copy
during free is a use-after-free.

Both epoch and QSBR solve this without per-object locks by tracking
*which generation a reader is in* rather than *which specific object
a reader holds*.

## Epoch-based reclamation (Fraser)

**Global state:** an `epoch: AtomicU64`.

**Reader:**
1. `pin()` stores the current global epoch into a per-thread slot.
2. Dereference freely.
3. `drop(guard)` publishes "no longer pinned."

**Writer / reclaimer:**
1. `defer_drop(x)` queues `x` in the current epoch's bin.
2. Periodically: advance the global epoch; scan every per-thread
   slot. If all pinned threads are at epoch ≥ N, then epoch < N−2
   bins are safe to free.
3. The "−2" is defensive: it prevents a reader that pinned at epoch
   N−1 from racing with a reclaim during the transition.

**Cost:**
- Read-side: one atomic store on pin, one on drop.
- Write-side: O(threads) scan, amortised by batching.

**Failure mode:** a stuck reader (thread that pinned and never
unpinned) prevents reclamation indefinitely. Memory bloats
unboundedly.

**Rust incarnation:** `crossbeam-epoch` — `Guard`, `Atomic<T>`,
`Shared<'g, T>`, `Owned<T>`. NARF's API mirrors this; names match
where possible to ease oral/written comprehension.

## QSBR — Quiescent-State-Based Reclamation

QSBR is a specialisation: instead of tracking "is this thread
currently pinned?", it tracks "has this thread *passed a known
quiescent point* since the last epoch advance?"

**What is a quiescent state?** A moment when the thread demonstrably
holds no references to shared data. In a kernel, it's a
context-switch. In an async executor, it's the boundary between
`Future::poll` invocations.

**Reader:**
- Nothing explicit! Just accessing the data is the read.
- At natural quiescent boundaries, a report is made: "I've passed a
  quiescent point; I'm not holding anything."

**Writer:**
- `synchronize()` waits until every thread has reported quiescence
  since the call.

**Cost:**
- Read-side: ~zero (the reporting already happens as part of the
  executor).
- Write-side: same scan as epoch, but with trivial per-thread check.

**Failure mode:** a thread that never reaches a quiescent point (an
infinite-loop Future that never returns from `poll`) blocks
reclamation. This is why NARF forbids `await` inside QSBR read
sections and why well-behaved Futures cooperate.

## Why NARF uses both

- **QSBR is the default** because the executor already produces the
  quiescence signal for free. Hot paths in `capabilities/`,
  `interrupts/`, `time/` use QSBR.
- **Epoch is the fallback** for contexts outside the executor's
  poll loop (early boot, some interrupt-derived code paths) or
  where a simpler "is someone reading?" check is preferable to
  "have we passed a quiescent point?"

## Memory-ordering notes

- Publish (writer): release store on the pointer cell.
- Read (reader): acquire load on the pointer cell.
- Epoch publish: release; reader's epoch store: relaxed is enough on
  x86_64 if combined with a later fence; aarch64 needs release
  explicitly.
- Reclaim thread scanning slots: acquire loads.

## Rust type-system leverage

The `'g` lifetime on `Shared<'g, T>` and `ReadGuard<'g>` makes the
whole invariant a compile-time check:

```rust
fn bad<'g>(atomic: &Atomic<T>) -> Shared<'g, T> {
    let g = rcu::pin();
    atomic.load(&g)    // won't compile: 'g outlives local g
}
```

This is the headline reason NARF's RCU is much smaller than Linux's:
most of the "did you forget to unlock?" concerns vanish because the
borrow checker enforces them for us.

## Practical NARF integration points

1. `scheduler/` calls `rcu::report_quiescent()` around each
   `Future::poll`. One per-CPU relaxed store.
2. `pin()` obtains a guard that lives only for the current poll
   (enforced by `!Send` + lifetime tying).
3. `defer_drop` queues per-domain; per-domain reclamation worker
   drains under a `rcu::sync().await` barrier that is itself a
   Future.
4. No kernel code ever spins on RCU — `sync()` is always `await`-ed.

## Open implementation questions

- Per-CPU vs. per-task epoch slot. Per-CPU is cheaper; per-task gives
  cleaner stats for debugging. Compromise: per-CPU with stats
  mirrored into per-task on poll entry in debug builds only.
- How aggressively to batch `defer_drop` queue draining inside
  `report_quiescent` — too much per-poll draining hurts tail
  latency; too little grows queues unboundedly.
- NUMA-aware reclamation queues — queue drops on the node that
  owns the memory, free on that node.
