# lib — Specification

> Status: **v1.0** (Stage 2 design lock). v0.1 outlined the
> primitives; v1.0 locks vendored-vs-in-tree policy, the
> allocator-collections boundary, the async-Mutex policy,
> the crate layout, and ABI versioning.

## 1. Purpose & scope

**Owns:**

- **Sync primitives** beyond RCU: `SpinLock`, `IrqSafeSpinLock`,
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

/// Fatal-path diagnostic: the IrqSafeSpinLock address on which a CPU is
/// spinning, or zero when no throttled contention is active.
pub fn contended_irq_lock(cpu: usize) -> usize;

pub struct Mutex<T>(…);                    // async; await-safe, uses scheduler waker
pub struct RwLock<T>(…);                   // async; prefer RCU where applicable
pub struct SeqLock<T: Copy>(…);            // T: Copy is load-bearing — see §4
pub struct Once<T>(…);                     // single-initialise
```

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
