# Linux RCU variants — reading notes

**Primary sources:** McKenney's RCU chapter in *Is Parallel Programming
Hard*; Linux `Documentation/RCU/`; LWN's multi-part RCU series by
Corbet and McKenney.

> Distilled for NARF design. What each Linux variant does, and why
> NARF's epoch-based approach diverges.

## Classic / Tree RCU

**Reader side:**
- `rcu_read_lock()` disables preemption. `rcu_read_unlock()` re-enables.
- Read-side critical section is a "quiescent state" when it ends
  (preemption re-enabled = CPU can context-switch away).

**Writer side:**
- `synchronize_rcu()` waits until every online CPU has passed through
  a quiescent state since the call — i.e., every CPU has been through
  at least one context switch.
- Implementation uses a tree of per-CPU "reports" aggregated up to the
  root to avoid cacheline contention at scale.

**Grace-period cost:** milliseconds on idle/mostly-idle systems;
microseconds on busy ones.

**Why NARF diverges:** classic RCU's quiescent-state marker is
"preemption boundary." NARF has no classic preemption; tasks are
Futures that yield at `await` points. The natural quiescent state is
the **end of a `Future::poll`** — a task that just returned from poll
is provably not holding any borrow. That's what NARF's QSBR uses.

## SRCU — Sleepable RCU

**Reader side:**
- `srcu_read_lock(&ssp)` returns an index into the per-scope counters;
  `srcu_read_unlock(&ssp, idx)` releases.
- Reader may *sleep* while holding the reservation — the whole point.
- Each SRCU instance is a separate scope; synchronize on one doesn't
  block readers of another.

**Writer side:**
- `synchronize_srcu(&ssp)` flips the per-scope counter pair and waits
  for the old half to drain to zero.
- Unbounded in principle (a buggy reader can wedge it); Linux has
  `synchronize_srcu_expedited` + timeout variants as mitigations.

**Why NARF diverges:**
- **Bounded sync with outcome enum.** NARF's `sleepable_sync` returns
  `SyncOutcome::Ok` or `SyncOutcome::Timeout(delinquents)` —
  wedging is never an option.
- **Cap-gated reads.** A sleepable reservation requires
  `SleepableCap`, which carries a per-cap budget; overrunning the
  budget revokes the cap. SRCU has no such gate.
- **RAII guard.** Linux SRCU has a pair of functions; forgetting one
  is a bug. NARF's `SleepableGuard` is a `#[must_use]` RAII type.

## Tasks RCU

Used by Linux for things that cannot put an `rcu_read_lock` around
themselves — canonically, BPF trampolines and scheduler code paths.

**Reader side:** no explicit lock. A task is a "reader" implicitly
from the moment it enters a trampoline-protected region.

**Writer side:** wait for every task in the system to have been
voluntarily scheduled out at least once. That's the quiescent marker.

**Why NARF cares:** `tracing/` dynamic probe arming/disarming is the
classic use case. NARF's equivalent is to treat "arming a probe" as
a deferred operation that completes at the next executor sync —
effectively the same idea expressed in async terms.

## Tasks Trace RCU

Newer Linux variant used by BPF for longer-lived readers that can
sleep but cannot use SRCU (because they're running in an atomic
context transiently).

**Why NARF doesn't need a separate variant:** NARF has no BPF VM
inside the kernel (see `tracing/` §3). Probe actions are declarative
and can choose QSBR or Sleepable based on whether they include an
async step. A separate variant is not required.

## Takeaways for NARF

1. **Async, not preemption.** NARF's quiescent marker is poll-boundary,
   not context-switch. This simplifies everything.
2. **Keep sleepable but make it safe.** SRCU is the right shape for
   long-held reads (filesystem walks, mount-tree iteration); add
   cap-gating, budgets, and timeout-bounded sync to tame it.
3. **No BPF → no Tasks Trace RCU.** One fewer variant to implement.
4. **Reclamation is per-domain.** Drops run in the domain that owned
   the allocation, preserving PKS/MTE rights invariants.
5. **RCU primitives are pay-per-use.** Subsystems that don't need
   deferred reclamation never link the machinery.
