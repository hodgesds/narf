# rcu — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 outlined QSBR
> + sleepable readers; v1.0 locks the IRQ-context policy, the
> sleepable-scope granularity, the per-domain reclamation
> fairness, and the priority-inversion handling.
>
> **Name vs. mechanism.** The folder is `rcu/` because engineers search
> for "RCU" when they want this shape. The underlying mechanism is
> **epoch-based reclamation** (with QSBR, hazard-pointer, and sleepable
> variants). This spec never relies on preemption boundaries as grace-
> period markers — NARF is async, so poll boundaries are the natural
> quiescent states.

## 1. Purpose & scope

**Owns:**

- `ReadGuard` / `Atomic<T>` / `Owned<T>` / `Shared<'g, T>` primitives.
- Grace-period / epoch machinery.
- Four reclamation variants:
  - **QSBR** — quiescent-state-based; readers are free, writers wait
    for the executor to announce quiescence at every poll boundary.
  - **Epoch** — crossbeam-style; cheap read-side (one atomic per pin).
  - **Hazard pointers** — per-reader slots announcing currently-held
    objects; bounded reclamation latency.
  - **Sleepable** — readers may `await` while holding a reservation;
    analogous to Linux SRCU but async-native.
- `defer_drop` queues, drained per domain.
- Executor integration hook (`report_quiescent`) called at every
  `Future::poll` boundary.

**Does NOT own:**

- General allocator — `memory/`.
- Lock primitives (Mutex, RwLock) — those live in `lib/` / `std` with
  `no_std` adaptations; this spec provides an *alternative* pattern,
  not a replacement for all locks.
- Specific data-structures (hash maps, tries) — consumers build them
  using the primitives here.

## 2. Assumptions

- `scheduler/` can call `rcu::report_quiescent()` at each poll
  boundary (it is free — one per-CPU `fetch_add`).
- `memory/` can allocate per-CPU and per-domain storage for epoch
  counters and `defer_drop` queues.
- `time/` provides a monotonic clock for sleepable-RCU reader-timeout
  enforcement.
- `capabilities/` exists but this subsystem deliberately needs *no*
  cap gate on reads (the guarantee is safety, not authorisation).
  Sleepable reads do need a cap — see §3.5.

## 3. Public interface

### 3.1 Core types

```rust
pub struct ReadGuard<'g>;                  // pins current epoch; !Send
pub struct Owned<T>;                       // exclusively-owned allocation
pub struct Shared<'g, T>;                  // tied to a ReadGuard's lifetime

pub struct Atomic<T>;                       // epoch-collected pointer cell
impl<T> Atomic<T> {
    pub fn load<'g>(&self, g: &'g ReadGuard) -> Shared<'g, T>;
    pub fn store(&self, owned: Owned<T>, g: &ReadGuard);
    pub fn compare_and_set<'g>(
        &self, expected: Shared<'_, T>, new: Owned<T>, g: &'g ReadGuard,
    ) -> Result<Shared<'g, T>, (Owned<T>, Shared<'g, T>)>;
}

pub fn pin() -> ReadGuard<'static>;        // QSBR / epoch variant
pub fn defer_drop<T>(owned: Owned<T>, g: &ReadGuard);
pub fn sync() -> impl Future<Output = ()>; // wait one grace period
pub fn stalled_cpu_mask(now_ns: u64, threshold_ns: u64) -> u64;
```

`'g` ties `Shared<'g, T>` to the guard; the borrow checker forbids
keeping it past `drop(g)`. UAF is a compile error for well-typed
consumers.

`stalled_cpu_mask` is an allocation-free watchdog snapshot. Bit `N` is set
when active CPU `N` has not reported a QSBR quiescent boundary within the
requested interval; inactive CPUs are omitted.

### 3.2 Variant selection

```rust
pub enum ReclamationPolicy { Qsbr, Epoch, Hazard, Sleepable }

pub struct Collector<P: Policy>;           // optional per-structure override
```

Global default per call site is chosen by the consumer; NARF picks:

| Consumer / data                                  | Variant          |
| ------------------------------------------------ | ---------------- |
| `capabilities/` cap-table lookup                 | **QSBR**         |
| `tracing/` probe-site table                      | Epoch            |
| `interrupts/` IRQ routing table / UITT           | **QSBR**         |
| `time/` clocksource current-best pointer         | **QSBR**         |
| `filesystem/` dentry-equivalent cache            | **Sleepable** (§3.5) |
| `drivers/` driver registry                       | Epoch            |
| Long-lived structures with many pointers         | Hazard           |

### 3.3 QSBR (default hot-path variant)

- Every kernel task is a Future. The executor calls
  `rcu::report_quiescent()` at every poll boundary — O(1), typically
  one per-CPU atomic store.
- `pin()` bumps a per-CPU "reader-in-flight" counter; dropping the
  guard bumps it down. **Read path is nearly free.**
- `sync()` samples the global epoch, then awaits until every CPU has
  passed a quiescent boundary beyond that epoch. Written as:

  ```rust
  let target = global_epoch.fetch_add(1, Release);
  loop {
      if all_cpus_past(target) { break; }
      yield_once().await;      // scheduler re-polls us
  }
  ```

- **Strict rule for QSBR readers: you may not `await` inside a read
  critical section.** The executor treats an `await` as a quiescent
  state; doing so while holding a `ReadGuard` would allow reclamation
  under your feet. The Rust type system enforces this by making
  `ReadGuard` `!Send` *and* making the sleepable path a different type
  (§3.5).
- **Bounded grace-period detection.** If any CPU has not reported
  quiescence within a configurable window (default 100 ms),
  `rcu/` emits a `tracing/` event at `warn` and starts incrementing
  a `stuck_quiescent_cpu` counter per CPU. At 1 s a `critical`-severity
  event fires with the offending CPU's current task ID. This catches
  infinite-loop Futures and CPUs that never enter the poll loop —
  without detection, reclamation stalls indefinitely with no visible
  symptom until memory pressure surfaces it.

### 3.4 Epoch variant

- Functionally identical to crossbeam-epoch: each reader's `pin()`
  pushes a snapshot of the global epoch into a per-thread slot;
  writers advance the global epoch and reclaim anything queued in
  epochs ≥ 2 behind every thread's snapshot.
- Read-side cost: one atomic load + one atomic store on pin, one
  atomic store on drop.
- Writer cost: proportional to number of per-thread slots.
- Used where poll-boundary QSBR doesn't apply naturally (e.g. inside
  interrupt handlers that don't go through the executor).

### 3.5 Sleepable variant (SRCU-analogue)

The feature you asked for. Readers may hold a reservation *across*
`await` points; writers wait for those reservations to release, up
to a configurable timeout.

```rust
pub struct SleepableReader;                 // cap-gated; Send + pinning a scope
pub struct SleepableGuard<'a>;              // !Send but Future-safe
pub type SleepableCap = Cap<rcu::SleepableReader, Read>;

pub fn sleepable_read(cap: &SleepableCap) -> SleepableGuard<'_>;  // cheap
pub fn sleepable_sync(scope: SleepableScope) -> impl Future<Output = SyncOutcome>;
```

Semantics:

- A **scope** is the unit of sleepable-RCU concurrency. Each call
  site that uses sleepable-RCU creates a scope (a counter + a
  per-scope reader census) at init time. Scopes are isolated: a sync
  on scope X does not wait for readers in scope Y.
- `sleepable_read(cap)` returns a guard tied to the scope. The caller
  may `await` anything while holding it. Loads through the scope's
  `Atomic<T>` pointers remain safe.
- `sleepable_sync(scope)` waits until every currently-held
  `SleepableGuard` on that scope has been dropped, *or* the
  per-scope deadline expires (default: configurable, typically 250 ms
  for filesystem-scale scopes, tighter for hot paths).
- On deadline expiry, `SyncOutcome::Timeout(set_of_delinquent_tasks)`
  is returned. The writer decides: escalate (cap-revoke the
  offenders), log-and-retry, or panic per policy.

Cap requirement:

- `SleepableCap` is minted by the scope owner. This prevents a
  misbehaving user task from holding a sleepable reservation
  indefinitely and stalling writers. Every scope has a per-cap
  **budget** (max simultaneous reservations, max duration). Budget
  violation → the cap is auto-revoked (see `capabilities/` §3).

Scope granularity (resolves an open question):

- **`filesystem/` uses one scope per mount point**, not per FS driver
  and not per VFS instance. SRCU practice in Linux has settled on
  per-mount: a driver serving 100 mounts with one scope serialises
  all their syncs, which is unacceptable. Per-mount scope is the
  default; subsystems with different scaling characteristics
  document their own scope strategy (e.g. `interrupts/` uses one
  scope per IRQ-routing-table generation).

Rust invariants:

- `SleepableGuard<'a>` is `!Send` across an async task (to keep it on
  one CPU, simplifying epoch tracking) but *is* allowed to live
  across `.await` — this is the whole point.
- Reference material borrowed from the scope uses a separate
  lifetime; the guard's drop runs scope-accounting but doesn't
  generally reclaim by itself (reclamation is batched at
  `sleepable_sync`).

Key differences vs. Linux SRCU:

- **Async-native timeout.** Linux SRCU waits unbounded; NARF returns
  a `Timeout(…)` so the writer is never wedged by a buggy reader.
- **Cap-gated.** Long-held readers need explicit authority.
- **Per-scope budgets.** A misbehaving scope can't starve the rest
  of the kernel.
- **Compile-time guard discipline.** Classic SRCU API is pair-of-
  function-calls; NARF's is RAII so forgetting to release is a
  linter error (`#[must_use]`).

### 3.6 Hazard pointers

Optional third variant where:

- Each reader has a small fixed array of slots it can publish a
  pointer into before dereferencing.
- Writers scan all hazard slots; an object is reclaimable only when
  no slot names it.
- Bounded memory footprint regardless of grace-period length; higher
  read-side cost than epoch or QSBR.
- Target use case: long-lived reads across many pointers (e.g.
  `filesystem/` dentry-like walks *when sleepable is unavailable*),
  or structures where epoch "stuck reader" blocks too much memory.

### 3.7 Executor integration

One hook in `scheduler/`:

```rust
// Called by the executor exactly once around each Future::poll
rcu::report_quiescent();
```

This single call:

- Publishes the current CPU's epoch snapshot.
- Advances any `sleepable_sync` tracker if its scope's readers have
  all released.
- Drains a bounded slice of this CPU's `defer_drop` queue (bounded
  to keep per-poll latency capped — residual work falls to the
  reclamation worker Future below).

A per-domain **reclamation worker Future** runs on a low-priority
executor slot, draining the rest of the domain's deferred-drop queue.
Reclamation runs *inside the domain that owned the allocation* so
the `Drop` impl sees the correct PKS/MTE rights.

## 4. Invariants & safety properties

- `ReadGuard` is `!Send` *and* `!Sync`. Hot-path guards cannot cross
  executor poll boundaries. (`SleepableGuard` is the carefully-
  designed exception.)
- `Shared<'g, T>` never outlives its guard — lifetime-tagged.
- An object queued for `defer_drop` is not actually dropped until
  every reader whose guard existed at the queue-time has either
  reported quiescence (QSBR / epoch) or released its reservation
  (sleepable / hazard).
- Reclamation happens in the owner's domain; cross-domain free is
  impossible by construction.
- A sleepable reader whose cap is revoked has its guard forcibly
  drained at its next `await` boundary (cooperative — the task sees
  a cancellation signal, its Drop runs, reservation releases).
- `sleepable_sync` terminates in bounded time: either all readers
  released, or deadline fired. Unbounded waits are impossible.
- No use of `rcu::` primitives is visible to code that does not
  explicitly link it — pay-for-what-you-use.

## 5. Architecture notes

Largely arch-neutral. Two points of contact:

- **Per-CPU atomic epoch counter.** On x86_64 a plain `mov` + release
  fence suffices; on aarch64 use `STLR` for release semantics on the
  epoch publish.
- **Memory ordering of `Atomic<T>::load`.** Acquire ordering both
  arches; ensures the pointed-to object's fields are visible to the
  reader.

## 6. Dependencies

- **Consumes:** `scheduler/` (per-poll `report_quiescent` hook),
  `memory/` (per-CPU + per-domain storage, domain-aware drops),
  `time/` (sleepable-sync deadline), `capabilities/` (SleepableCap
  + budget revocation), `arch/` (atomics + memory ordering).
- **Provides to:** `capabilities/` (cap-table readers), `interrupts/`
  (routing-table readers), `tracing/` (probe-site readers), `time/`
  (clocksource selection), `filesystem/` (dentry-like cache,
  mount-tree walks — sleepable), `drivers/` (driver registry — epoch).

## 7. Stage assignment

| Stage | Lands                                                              |
| ----- | ------------------------------------------------------------------ |
| 1     | API surface (types, traits, `Atomic<T>`, `pin` / `sync` stubs). Single-CPU executor calls the `report_quiescent` hook; sync is a no-op. No reclamation yet. |
| 2     | Real QSBR + Epoch variants with SMP; `defer_drop` queues; per-domain reclamation worker Future. |
| 3     | Hazard-pointer variant; **Sleepable variant** with cap-gated scopes, budgets, and timeout-bounded sync; first consumers adopt (`capabilities/`, `interrupts/`, `time/`, `filesystem/` dentry). |
| 4     | Tuning: batched reclamation, per-domain deferred-drop pacing, NUMA-aware queues, expanded consumers. |

## 8. Resolved decisions

### 8.1 IRQ-context RCU (resolved)

**Decision:** **forbidden**. RCU primitives must not be
called from interrupt handlers. Handlers produce short
messages (atomic writes, ring-pushes) and a Future processes
them. This keeps the QSBR model simple — every read is
in-Future, every quiescent state is a poll boundary.

The `narf-rcu` crate enforces via `#[narf_rcu::no_irq]` lint
(checked by CI) on functions that take RCU read-guards.
Handlers calling into a function tagged with this fail
build.

### 8.2 Sleepable-scope granularity (resolved)

**Decision:** **one scope per filesystem instance**, not per
mount and not per driver. A filesystem driver may be hosting
multiple mounts (each its own `FsInstance`); each instance
gets its own SRCU-style scope. This bounds the worst-case
"how long can a sleepable reader hold up sync" to a single
mount's IO patterns.

Driver-internal RCU usage (e.g. driver's own data structures)
uses QSBR scopes, not sleepable. SRCU scopes are reserved for
the IO-blocking path that filesystems need.

### 8.3 Sleepable budget defaults (resolved)

**Decision:** **defaults driven by per-system measurement**,
revisited every release. Initial v1.0 numbers:

- Max sleepable read duration: 5 seconds (then escalates to
  warn + force-quiesce).
- Max simultaneous sleepable readers per scope: 256.
- Max scopes system-wide: 64 (1 per FS instance).

These are tunable via `narf.rcu.*` boot params. The 5-second
ceiling is generous for normal IO; a reader exceeding it is
almost certainly buggy.

### 8.4 Reclamation per-domain fairness (resolved)

**Decision:** **round-robin across domains in the
reclamation worker**, not strict equal allocation. The worker
is a Future that polls each domain's deferred-drop queue in
turn, draining a bounded chunk per pass. A chatty domain's
queue doesn't block others — at worst its drains are spread
across N round-robin passes.

Per-domain quota on outstanding deferrals: 1000 items default.
Exhaustion blocks the producer (synchronous drop) instead of
unbounded queue growth.

### 8.5 Priority inversion in `sync` (resolved)

**Decision:** **priority boost for sleepable readers blocking
a high-priority writer**. The writer's priority is propagated
to all current readers in the same scope; readers run at
boosted priority until quiescence. Mirrors Linux's PREEMPT_RT
priority inheritance for RCU.

For QSBR (non-sleepable): readers complete in O(µs) — boost
doesn't matter and adds complexity. No boost; the writer's
sync just polls.

### 8.6 Cross-kernel-migration (resolved by punting)

**Decision:** **out of scope for v1.0**. Live kernel update
is deferred indefinitely; if it ever lands, RCU semantics
across kernels would need fresh design.

### 8.7 Tracing events (resolved)

**Decision:** v1.0 emits these `tracing/` events:

- `rcu.qsbr.scope_size` — periodic gauge of active QSBR
  scopes per CPU.
- `rcu.sync.duration` — histogram of `sync` wait times.
- `rcu.timeout.fired` — count of timeouts on
  `sync_with_timeout`.
- `rcu.reclaim.queue_depth` — per-domain reclamation queue
  depth gauge.
- `rcu.sleepable.read_duration` — histogram of sleepable
  read durations.

All fields are stable at v1.0; adding new events / fields is
a minor bump.

## 9. ABI versioning

`narf-rcu` exports through SDK at `@v0`:

- Scope guards (`ReadGuard`, `SleepableReadGuard`).
- `synchronize_rcu`, `synchronize_rcu_with_timeout`.
- `Cap<SleepableReader, _>` (drivers requesting sleepable
  semantics).

Drivers consume RCU through these stable APIs; the
implementation (epoch counters, deferred-drop machinery) is
internal.

`RCU_ABI_MAJOR = 1`, `RCU_ABI_MINOR = 0`.

## 10. Open questions

(none — all v0.1 questions resolved in §8)
