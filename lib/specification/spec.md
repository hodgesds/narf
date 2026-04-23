# lib — Specification

> Status: **Outline v0.1**. Grows incrementally across all stages.

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

## 8. Open questions

- **In-tree vs. vendored.** `spin`, `crossbeam-utils`, `hashbrown` —
  do we re-export with thin wrappers, or fork-and-vet? `build/`
  currently prefers pinned external crates; `lib/` should codify a
  criterion for when we bring something in-tree.
- **Allocator-backed collections home.** `Vec`-like and `BTreeMap`-like
  types from `alloc` are fine in subsystems that have an allocator;
  but do we mirror them here as a domain-aware variant? Probably not
  — reuse `alloc` when available, let `memory/` own the allocator.
- **Async Mutex vs. spin + donation.** For short critical sections
  donation via `scheduler/` beats a sleeping mutex; when does the
  mutex earn its keep? Expect benchmarks to decide.
- **Whether `lib/` becomes a namespace for crate-per-primitive or
  one big crate.** Cargo workspace tidiness argues for several
  crates; compile-time argues for one. `build/` decides.
