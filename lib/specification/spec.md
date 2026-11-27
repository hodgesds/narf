# lib — Specification

> Status: **v1.0** (Stage 2 design lock). v0.1 outlined the
> primitives; v1.0 locks vendored-vs-in-tree policy, the
> allocator-collections boundary, the async-Mutex policy,
> the crate layout, and ABI versioning.

## 1. Purpose & scope

**Owns:**

- **Sync primitives** beyond RCU: `SpinLock`, `IrqSafeSpinLock`,
  `TicketSpinLock`, `IrqSafeTicketSpinLock`,
  `Mutex` (async-aware), `RwLock` (async-aware), `SeqLock`,
  `Once`, `OnceLock`.
- **Intrusive collections:** linked list, doubly-linked list,
  FIFO / LIFO, priority heap, RB-tree, skiplist. All
  non-allocating, caller-owns-nodes.
- **Bitmaps / bitsets** with arch-optimised scans (BMI2 / CLZ,
  `CLZ` on aarch64).
- **Typed IDs:** `CpuId`, `DomainId`, `TaskId`, `NodeId`, … — all
  newtype-wrapped `u{8,16,32,64}` with conversion discipline.
- **Error helpers:** `NarfError` base, `thiserror`-lite derive macros,
  context chaining without allocation.
- **Assertion macros:** `debug_assert_in_domain!`, `assert_tcb!`,
  `bug_on!` — attribute failures to the active domain so
  `tracing/` can log them.
- **Small utility types:** `Zeroizing<T>` re-export policy from
  `crypto/` dependency, `BoundedString`, `ArrayVec`-equivalent.

**Does NOT own:**

- Allocation — `memory/`.
- Deferred reclamation — `rcu/`.
- Crypto primitives — `crypto/`.
- IPC rings — `ipc/`.
- Generic algorithms better left to vetted external crates
  (`hashbrown`, `arrayvec`, `smallvec`) — those are pinned via
  `build/`'s workspace.

## 2. Assumptions

- `arch/` provides atomic primitives at the widths we need.
- `build/` pins external dependencies consistently for every crate.
- `no_std`-first; anything that could require `alloc` is feature-
  gated and explicitly crossed.

## 3. Public interface (selected)

### 3.1 Sync primitives

```rust
pub trait IrqState: Sealed {}
pub struct IrqsEnabled;       // marker
pub struct IrqsDisabled;      // marker
impl IrqState for IrqsEnabled {}
impl IrqState for IrqsDisabled {}

pub struct SpinLock<T>(…);
pub struct SpinLockGuard<'a, T, I: IrqState>(…);

impl<T> SpinLock<T> {
    /// Requires `IrqsEnabled` at the call site (typestate enforced
    /// via the executor's per-CPU `IrqState` token).
    pub fn lock(&self, _: &IrqContext<IrqsEnabled>)
        -> SpinLockGuard<'_, T, IrqsEnabled>;
}

pub struct IrqSafeSpinLock<T>(…);
impl<T> IrqSafeSpinLock<T> {
    /// Disables IRQs around the critical section; safe from any context.
    pub fn lock(&self) -> SpinLockGuard<'_, T, IrqsDisabled>;
}

/// FIFO-fair ticket variants of the spinlocks above: waiters take
/// monotonically increasing tickets and are served strictly in ticket
/// order, so a waiter cannot be overtaken indefinitely by later arrivals
/// (the starvation mode of the ticket-free `SpinLock`). `try_lock` on
/// either variant never jumps the queue — it fails when a waiter already
/// holds a ticket, even if the lock itself is momentarily free. Fairness
/// only: ticket locks change acquisition order under contention, not
/// critical-section speed; no throughput gain is claimed for them. The
/// epoll instance locks (`inner` / `ready` / `waiters`) use the IRQ-safe
/// variant; the plain `IrqSafeSpinLock` remains the default elsewhere.
pub struct TicketSpinLock<T>(…);
impl<T> TicketSpinLock<T> {
    /// FIFO ticket order; requires `IrqsEnabled` at the call site.
    pub fn lock(&self, _: &IrqContext<IrqsEnabled>)
        -> TicketSpinLockGuard<'_, T, IrqsEnabled>;
}

pub struct IrqSafeTicketSpinLock<T>(…);
impl<T> IrqSafeTicketSpinLock<T> {
    /// FIFO ticket order; disables IRQs around the critical section.
    pub fn lock(&self) -> IrqSafeTicketSpinLockGuard<'_, T>;
}

/// Fatal-path diagnostic: the IrqSafeSpinLock address on which a CPU is
/// spinning, or zero when no throttled contention is active.
pub fn contended_irq_lock(cpu: usize) -> usize;

pub struct Mutex<T>(…);                    // async; await-safe, uses scheduler waker
pub struct RwLock<T>(…);                   // async; prefer RCU where applicable
pub struct SeqLock<T: Copy>(…);            // T: Copy is load-bearing — see §4
pub struct Once<T>(…);                     // single-initialise
```

`Mutex::try_lock_unqueued()` grants a guard only when the mutex is free and
its waiter queue is empty, checked together under the existing internal lock.
Failure does not enroll or select a waiter. Providers with an optional bounded
optimistic wait can use it without bypassing queued sleepers; ordinary mutex
acquisition, FIFO wake selection, and cancellation remain unchanged.

**Typestate IRQ safety.** `SpinLockGuard<'_, T, I: IrqState>` makes
mixed-IRQ-context use a compile error. Acquiring a `SpinLock` from a
context tagged `IrqsDisabled` is a type-error; use `IrqSafeSpinLock`
instead. Acquiring an `IrqSafeSpinLock` from `IrqsEnabled` is fine and
returns a `IrqsDisabled` guard. The runtime panic that the original
spec relied on becomes a compile error — which matters because the
runtime panic only fires under specific timings, and a compile-time
check covers every reachable path.

**`SeqLock<T>` requires `T: Copy`.** This is not a stylistic choice —
the reader samples `T`'s bytes without synchronisation and retries on
sequence mismatch. A `T` containing pointers, references, or owned
heap is undefined behaviour under torn-state sampling (the reader
might dereference a half-written pointer before noticing the
sequence mismatch and retrying). For non-`Copy` use cases that
genuinely need seqlock semantics, an `unsafe SeqLockUnchecked<T>`
exists with documented-by-caller preconditions.

Chosen crate baseline: start with `spin`, `parking_lot` patterns
ported to `no_std`, and custom async `Mutex` tied to `scheduler/`
wakers. Exactly which of these live in-tree vs. vendored-from-crate
is a `build/` decision.

### 3.2 Intrusive collections

```rust
pub struct IntrusiveList<T: Linked>;     // doubly-linked, O(1) unlink
pub trait Linked { fn link(&self) -> &ListLink<Self>; }

pub struct RbTree<K, T: RbNode<K>>;
pub struct BinaryHeap<T: Ord>;           // pin-stable
```

Intrusive means the caller provides storage; `lib/` never
allocates. Mirrors the shapes used by `scheduler/` run-queues,
`time/` timer wheel, `tracing/` recorder registries.

### 3.3 Bitmaps

```rust
pub struct Bitmap<const N: usize>;
pub struct DynBitmap;                    // backed by allocator; used sparsely
impl<const N: usize> Bitmap<N> {
    pub fn first_set(&self) -> Option<usize>;
    pub fn first_clear(&self) -> Option<usize>;
    pub fn iter_set(&self) -> impl Iterator<Item = usize>;
}
```

Used by `scheduler/` `CpuSet`, `capabilities/` cap-slot allocation,
`interrupts/` IRQ allocation, `bus/` BAR management.

### 3.4 Assertion / diagnostic macros

```rust
debug_assert_in_domain!(expected);             // attribute failure to current domain
assert_tcb!();                                  // must be inside the TCB
bug_on!(cond, "bug: {}", detail);              // panics; records into tracing/ before
```

Failure path: if `tracing/` is initialised, emit a USDT-style
event with file/line + domain id + a stack fingerprint; then call
`frame::panic` with a structured reason.

### 3.5 Typed IDs

```rust
macro_rules! define_typed_id {
    ($name:ident, $repr:ty) => { /* newtype + display + Hash + Eq impls */ };
}
define_typed_id!(CpuId, u16);
define_typed_id!(DomainId, u8);
/* ... etc ... */
```

Eliminates "is this a `u32` a PID or a CPU id?" bug class.

### 3.6 Execution-context tracking (`context`)

Per-CPU IRQ-depth counter that the arch IRQ dispatcher
brackets around every interrupt body. Lets allocators and
synchronization primitives ask "am I in IRQ?" without each
crate growing its own ad-hoc tracking.

```rust
pub fn enter_irq();          // bump this CPU's depth
pub fn exit_irq();           // saturating-at-0
pub fn in_irq() -> bool;     // depth > 0
```

`narf-interrupts::dispatch::on_irq` calls `enter_irq` /
`exit_irq` around every synchronous handler + waker run.
`narf-memory::context` composes this with the arch
RFLAGS.IF / DAIF.I read to expose `is_sleepable()` and the
`AllocContext { Sleepable | Atomic | IrqOff }` enum that
`slab::alloc` debug-asserts on.

Storage: `[AtomicU32; MAX_CPUS]` indexed by `current_cpu()`.
Lock-free; only the owning CPU writes its cell.

### 3.6.1 Per-CPU telemetry counters

```rust
pub struct PerCpuCounterBank<const N: usize>;
pub struct PerCpuCounterSnapshot<const N: usize>;

impl<const N: usize> PerCpuCounterBank<N> {
    pub const fn new() -> Self;
    pub fn increment(&self, counter: usize);
    pub fn add(&self, counter: usize, value: u64);
    pub fn snapshot(&self) -> PerCpuCounterSnapshot<N>;
    pub fn snapshot_cpu(&self, cpu: usize) -> PerCpuCounterSnapshot<N>;
}
impl<const N: usize> Default for PerCpuCounterBank<N> {
    fn default() -> Self;
}
impl<const N: usize> PerCpuCounterSnapshot<N> {
    pub fn get(&self, counter: usize) -> u64;
    pub fn delta_since(self, previous: Self) -> Self;
}
```

`PerCpuCounterBank` is the low-overhead telemetry primitive: the CPU that
records an event only writes its own cache-line-padded counter array with a
relaxed load/store, avoiding locked RMW and cross-CPU cache-line bouncing.
Snapshots are intentionally eventually consistent; callers measure an interval
by taking two snapshots and applying wrapping `delta_since`.

### 3.7 Durable readiness

```rust
pub struct Readiness;
impl Readiness {
    pub fn arm(&self, id: u64, interest: u32, waker: &Waker) -> Poll<u32>;
    pub fn arm_exclusive(&self, id: u64, interest: u32, waker: &Waker)
        -> Poll<u32>;
    pub fn arm_persistent(&self, id: u64, interest: u32, waker: &Waker) -> u32;
    pub fn arm_persistent_exclusive(
        &self, id: u64, interest: u32, waker: &Waker
    ) -> u32;
    pub fn set(&self, add: u32, clear: u32);
    pub fn set_event(&self, add: u32, clear: u32, event: u32);
    pub fn set_event_with_exclusive_id(
        &self, add: u32, clear: u32, event: u32
    ) -> Option<u64>;
    pub fn set_wake_all(&self, add: u32, clear: u32);
    pub fn set_event_with_continuation(
        &self, add: u32, clear: u32, event: u32, continuation: u32,
        wake: impl FnMut(u64, &Waker),
    ) -> Option<u64>;
    pub fn notify(&self, bits: u32);
    pub fn disarm(&self, id: u64);
}
```

`arm` and `arm_persistent` are non-exclusive observers; every matching event
wakes all of them. `arm_exclusive` joins a FIFO in which each matching event
wakes at most one waiter, after the non-exclusive observers. Selection removes
only the waiter's integer FIFO entry in the event path; its allocation-bearing
waker remains stored until task-context re-arm or disarm.
`arm_persistent_exclusive` is the epoll form: selection leaves the registration
armed and rotates its integer id to the FIFO tail, so successive source events
are distributed among exclusive epoll subscriptions in O(1). This matches
Linux wait-queue exclusivity without permitting a waker drop or allocation in
IRQ context. All arm variants check the current level under the same lock used
by `set`, preserving the lost-wake-free contract. `set_event` folds a same-level
provider notification into the state publication so one operation cannot
select two exclusive waiters. `set_event_with_exclusive_id` performs the same
atomic publication and additionally returns the selected exclusive waiter's id
after its waker has fired, allowing a provider to request a scheduler handoff
without coupling this primitive to the scheduler. It returns `None` when only
ordinary observers fired or the event made no waiter eligible. `set_wake_all` is
the terminal-state form: it wakes and logically dequeues all exclusive waiters
without dropping their wakers.

`set_event_with_continuation` publishes directed provider events and relays
remaining work to one exclusive waiter in the other direction. Pipes use OUT
events with IN continuation after a read, and the reverse after a write.
Continuation alone does not create a poll edge. The callback can run once per
direction under the readiness lock and must neither allocate nor drop wakers.
This prevents available data/space from stranding other exclusive blockers.

```rust
pub struct WaitQueue;
impl WaitQueue {
    pub const fn new() -> Self;
    pub fn arm(&self, id: u64, interest: u32, waker: &Waker,
               level: impl FnOnce() -> u32) -> Poll<u32>;
    pub fn arm_persistent(&self, id: u64, interest: u32, waker: &Waker,
                          level: impl FnOnce() -> u32) -> u32;
    pub fn disarm(&self, id: u64);
    pub fn wake(&self, bits: u32);
}
```

`WaitQueue` is the Linux `wait_queue_head_t` for providers whose readiness is
computed by the provider (`->poll`) rather than held as a level: a sequence
cursor (`/dev/kmsg`, mountinfo, `cgroup.events`), a line discipline (ttys,
ptys), a request queue (`/dev/fuse`). It keeps no level, so it cannot hold a
stale one. `arm` and `arm_persistent` register first and then call `level`,
outside the queue lock (`poll_wait(); mask = compute();`); `arm` removes the
registration when it reports `Ready`. A producer publishes its state change and
then calls `wake`, which wakes every waiter whose interest intersects `bits`
by reference under the queue lock (IRQ-safe, allocation-free). Either the
waiter's computation sees the change or the wake finds the waiter queued.

### 3.8 Deferred IRQ wakes

`deferred_wake::{push_pending_iter, try_push_one}` publish wakers to a bounded
CPU-local stash without allocation. `has_pending_local()` is one acquire load
of a cache-line-isolated presence flag; it never scans slots or uses another
CPU's wake count. Producers set that flag under the queue lock.
`drain_and_wake()` takes the batch and clears presence under the same lock,
then invokes wakers after unlocking, outside hard-IRQ context. A callback may
enqueue another waker; its new presence publication survives for the next pass.
The scheduler drains at executor and completed own-stack user-return boundaries.

### 3.9 Clockevent delta conversion (`clockevent_scale`)

```rust
pub struct ClockEventScale; // Copy
impl ClockEventScale {
    pub const fn from_measurement(units: u64, ticks: u64, units_err: u64,
                                  min_ticks: u64, max_ticks: u64) -> Option<Self>;
    pub const fn program(&self, delta: u64) -> Programmed;
    pub const fn ticks_to_units(&self, ticks: u64) -> u64;
    pub const fn min_delta(&self) -> u64;
    pub const fn max_delta(&self) -> u64;
}
pub struct Programmed { pub ticks: u64, pub latest: u64 }
```

Linux `clockevents_config` + `clockevents_program_event` for a one-shot device
calibrated against a reference counter (x86: LAPIC TMICT ticks against TSC
cycles). `from_measurement` keeps the calibration's uncertainty (`units_err`
reference units, one tick per end): `program` clamps the delta to
`[min_delta, max_delta]` and converts with the fastest admissible device rate,
so the device never fires before the delta; `Programmed::latest` uses the
slowest, so recording `now + latest` as the armed time never treats a still
counting device as expired. Pure 32.32 fixed point with 128-bit products;
host-tested.

### 3.10 Kernel CPU statistics (`kstat`)

Linux `kernel_stat.h` softirq counters and `rq->nr_iowait`, kept here because
their producers (time, rcu, block) sit below the scheduler.

```rust
pub const NR_SOFTIRQS: usize = 10;
pub mod vector { HI, TIMER, NET_TX, NET_RX, BLOCK, IRQ_POLL, TASKLET, SCHED, HRTIMER, RCU }
pub const SOFTIRQ_NAMES: [&str; NR_SOFTIRQS];
pub fn softirq_enter(vec: usize) -> SoftirqGuard;   // count + softirq CPU time until drop
pub fn note_softirq(vec: usize);                    // count only
pub fn softirq_count(cpu: usize, vec: usize) -> u64;
pub fn set_softirq_time_hooks(enter: fn() -> usize, exit: fn(usize)); // scheduler
pub struct IoWait;  // block() on the waiting CPU, wake()/drop on any CPU
pub struct IoWaitFuture<F>; // Pending polls are I/O wait
pub fn nr_iowait(cpu: usize) -> u64;
pub fn nr_iowait_total() -> u64;                    // /proc/stat procs_blocked
```

Vector mapping: `TIMER` = timer-wheel expiry, `HRTIMER` = soft hrtimer expiry,
`NET_RX` = a `WorkKind::SoftIrq` task poll, `SCHED` = a policy-requested
migration, `RCU` = an RCU callback batch; `HI`, `NET_TX`, `BLOCK`, `IRQ_POLL`
and `TASKLET` have no NARF equivalent and stay 0. A vector counts once per
handler execution that had work. `SoftirqGuard` is `!Send`; the hooks mask
interrupts themselves and neither allocates nor takes a lock. A task counts in
`nr_iowait` of the CPU it blocked on until its wait completes (`SyncSubmit` /
`SyncFlush` waits on a queued block request are I/O wait).

### 3.11 CPU-time arithmetic (`cputime`)

Pure, host-tested helpers behind `scheduler/` §3.4.1 and the `/proc` and
syscall reporting:

```rust
pub const USER_HZ: u64 = 100;
pub const fn ns_to_clock_t(ns: u64) -> u64;          // nsec_to_clock_t, truncating
pub const fn clock_t_to_ns(ticks: u64) -> u64;
pub const fn exclusive_span(now: u64, stamp: u64, irq_now: u64, irq_stamp: u64) -> u64;
pub fn cputime_adjust(stime: u64, utime: u64, rtime: u64,
    prev: &mut (u64, u64)) -> (u64, u64);            // Linux cputime_adjust
```

### 3.12 Uninterruptible kernel waits (`hung_task`)

```rust
pub struct WaitKind { pub name: &'static str, pub detail: &'static str }
pub static MUTEX: WaitKind;                 // async Mutex waiter; detail = waiter id
pub const MAX_BLOCKED: usize = 256;
pub fn set_hooks(current_task: fn() -> u64, now_ns: fn() -> u64);
pub struct BlockedWait;                     // held by the waiting future
impl BlockedWait {
    pub const fn new() -> Self;
    pub fn block(&mut self, kind: &'static WaitKind,
                 site: &'static core::panic::Location<'static>,
                 object: usize, detail: u64);
    pub fn wake(&mut self);                 // also on Drop
    pub const fn is_blocked(&self) -> bool;
}
pub struct BlockedInfo { pub owner: u64, pub since_ns: u64, pub kind: &'static WaitKind,
                         pub site: Option<&'static core::panic::Location<'static>>,
                         pub object: usize, pub detail: u64 }
pub fn for_each_blocked(f: impl FnMut(&BlockedInfo));
pub const fn owner_is_anonymous(owner: u64) -> bool;
pub fn overflowed() -> u64;
```

Linux's `TASK_UNINTERRUPTIBLE` for async kernel code, so the hung-task
detector sees kernel tasks. A future that waits the way Linux waits
uninterruptibly (`Mutex::lock` — `__mutex_lock_common`; the btrfs
transaction gate's join and close) records the wait on its first `Pending`
— the owner (the scheduler task being polled, or `1 << 63 | cpu` outside
any task), when it began, the kind, the waiting call's site, the lock's
address and a kind-specific detail — and releases it on `Ready` or drop.
Re-polls of the same wait keep its start. The table is fixed-size and
lock-free: a claim is one compare-exchange per slot tried, on the wait's
slow path only; a full table counts (`overflowed`) and does not track.
`for_each_blocked` never blocks a waiter and allocates nothing (the stall
watchdog scans it from a timer interrupt); a slot changing hands mid-read
is skipped. Nothing is recorded until the scheduler installs `set_hooks`.

## 4. Invariants & safety properties

- All `no_std`-clean. No hidden `alloc` dependency without a
  feature gate.
- `SpinLock` used from an IRQ-possible context is a compile error
  via a marker trait on the guard (`Send`/`!Send` discipline).
- Intrusive collection nodes are pinned; moving a linked node is
  UB, enforced at type level (`!Unpin`) where possible.
- Assertion macros compile out in release builds when marked
  `debug_`; the `bug_on!` / `assert_tcb!` forms always compile in.
- No macro in `lib/` silently allocates.

## 5. Architecture notes

- Bitmap scan implementations use `#[cfg(target_arch)]` paths:
  `tzcnt` / `lzcnt` on x86_64 with BMI1, `CLZ` / `RBIT` on aarch64.
  All paths have a portable fallback.
- `SeqLock` uses release/acquire ordering carefully — aarch64's
  weaker model demands explicit fences where x86_64 gets them free.

## 6. Dependencies

- **Consumes:** `arch/` (atomics, bit-scan instructions).
- **Provides to:** every other subsystem.

## 7. Stage assignment

| Stage | Lands                                                         |
| ----- | ------------------------------------------------------------- |
| 1     | Typed IDs, `SpinLock`, `IrqSafeSpinLock`, `Once`, `OnceLock`, `Bitmap`, `IntrusiveList`, base assertion macros. |
| 2     | `SeqLock`, `BinaryHeap`, `RbTree`, `Mutex`/`RwLock` tied to `scheduler/` wakers, `BoundedString`. |
| 3     | Domain-aware assertion macros integrated with `tracing/` and `frame/` panic path. |
| 4     | Additional intrusive structures as consumers demand; skiplist if a use case earns it. |

## 8. Resolved decisions

### 8.1 In-tree vs vendored (resolved)

**Decision:** in-tree implementations for primitives that
touch PKS/MTE state, run in trap context, define
cap-crossing types, or are read by the audit team. Vendored
+ pinned external crates are fine for non-TCB auxiliaries.

`IrqSafeSpinLock`, `SpinLock`, intrusive lists, typed IDs,
`Once`, atomic primitives → in-tree. `hashbrown` (non-domain
hash maps), `crossbeam-utils` (non-trap queues) → vendored.

### 8.2 Allocator-backed collections (resolved)

**Decision:** reuse `alloc` crate transparently. `memory/`'s
allocator implements `GlobalAlloc`; `Vec`/`BTreeMap`/`Box`
work without `lib/`-side mirroring. Domain tagging is implicit
from the calling context.

### 8.3 Async Mutex policy (resolved)

**Decision:** donation-via-scheduler for critical sections
< 100 µs (the common case); async `Mutex<T>` for genuinely
long sections. The crossover is profile-driven via
`tracing/` lock-hold-time histograms.

### 8.4 Crate layout (resolved)

**Decision:** **one `narf-lib` crate**, not per-primitive.
Foundational primitives change rarely; rebuild scope is
acceptable. Compile-time and dependency-graph clarity outweigh
workspace tidiness.

## 9. ABI versioning

`LIB_ABI_MAJOR = 1`, `LIB_ABI_MINOR = 0`. Re-exported through
SDK at `@v0`: `IrqSafeSpinLock`, `SpinLock`, `Once`,
`OnceLock`, intrusive primitives, typed-ID types.

## 10. Open questions

(none — all v0.1 questions resolved in §8)
