# Extending memory

Crate: `narf-memory` (`memory/`).

The memory subsystem exposes several **cap-gated global install** seams
(pattern 1 in the [README](README.md)): a trait, a static slot, and an
`install_*(&Cap<…, Grant>, impl Trait)` function. A custom crate implements
the trait and installs it at boot. Not every memory component is pluggable —
the table at the end says which are real seams and which would require
editing core.

## Public surface

`memory/src/lib.rs` re-exports the seams:

```rust
// memory/src/lib.rs (approx :85–:107)
pub use frame::{ install_frame_alloc, FrameAlloc, FrameAllocError, FrameStats,
                 MemAlloc, BuddyFrameAlloc, BumpFrameAlloc, /* … */ };
pub use heap_backend::{ install_heap_backend, HeapBackend, HeapAuthority, HeapError,
                        BumpBackend, SlabBackend, BUMP_BACKEND, SLAB_BACKEND };
pub use pager::{ install_pager, Pager, PagerAuthority, PagerError, SwapSlot,
                 NoopPager, ZpoolPager };
pub use mempolicy::{ set_active, alloc_frame_policied, Mempolicy, /* MPOL_* */ };
```

## Seam 1 — heap backend (`HeapBackend`) ✅ pluggable

`memory/src/heap_backend.rs:37`

```rust
pub trait HeapBackend: Send + Sync + 'static {
    fn name(&self) -> &'static str;                              // required
    unsafe fn alloc(&self, layout: Layout) -> *mut u8;          // required
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout);     // required
    fn try_alloc_atomic(&self, _layout: Layout) -> Option<NonNull<u8>> { None } // default
}
```

Install (cap-gated):

```rust
// memory/src/heap_backend.rs:176
pub fn install_heap_backend(
    cap: &Cap<HeapAuthority, Grant>,
    backend: &'static dyn HeapBackend,
) -> Result<(), HeapError>;
```

Note the backend is `&'static dyn HeapBackend` — a heap backend can't itself
be heap-allocated (chicken/egg), so it must be a `static`. In-tree impls:
`BumpBackend` (`:109`) and `SlabBackend` (`:134`), exported as statics
`BUMP_BACKEND` / `SLAB_BACKEND`.

## Seam 2 — frame allocator (`FrameAlloc`) ✅ pluggable

`memory/src/frame.rs:1049`

```rust
pub trait FrameAlloc: Send + Sync {
    fn name(&self) -> &'static str;
    fn alloc_frame_on(&self, node: usize) -> Result<PhysFrame, FrameAllocError>;
    fn alloc_frame_anywhere(&self) -> Result<PhysFrame, FrameAllocError>;
    fn free_frame(&self, frame: PhysFrame);
    fn stats(&self) -> FrameStats;
}
```

All methods required. Install (cap-gated):

```rust
// memory/src/frame.rs:1193
pub fn install_frame_alloc(
    cap: &Cap<MemAlloc, Grant>,
    alloc: &'static dyn FrameAlloc,
) -> Result<(), FrameAllocError>;
```

Cap marker: `MemAlloc` (`frame.rs:1065`, `KIND = CapKind::MemAlloc`). In-tree
impls: `BuddyFrameAlloc` (`:1075`, default) and `BumpFrameAlloc` (`:1104`).

> **Scope of the seam:** the trait dispatches single-frame ops
> (`alloc_frame_on` / `alloc_frame_anywhere` / `free_frame` / `stats`).
> Multi-frame `alloc_pages_on` / `free_pages` remain concrete buddy ops in
> `frame.rs` and are *not* routed through your installed allocator.

## Seam 3 — pager / swap backend (`Pager`) ✅ pluggable

`memory/src/pager.rs:118`

```rust
pub trait Pager: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn page_out(&self, phys: PhysAddr, flags: PageFlags) -> Result<SwapSlot, PagerError>;
    fn page_in(&self, slot: SwapSlot) -> Result<PhysAddr, PagerError>;
    fn discard(&self, slot: SwapSlot);
}
```

Install (cap-gated, takes the impl by value — it *can* be boxed):

```rust
// memory/src/pager.rs:254
pub fn install_pager<P: Pager>(cap: &Cap<PagerAuthority, Grant>, p: P)
    -> Result<(), PagerError>;
```

Cap marker: `PagerAuthority` (`pager.rs:155`, `KIND = CapKind::Pager`).
In-tree impls: `NoopPager` (`:169`, default) and `ZpoolPager` (`:214`, a
compression-backed pager — today `page_out` returns `Err(NoBacking)` pending
a later wave). The reclaim loop calls the installed pager via
`pager::page_out_via_installed()` (`reclaim.rs:645`).

This is the seam to implement a custom swap device (disk, network, remote
memory): implement `Pager`, `install_pager(cap, MyPager)`.

## Seam 4 — reclaim callbacks (`ReclaimFn`) ✅ pluggable (fn-ptr protocol)

Not a trait — a **function-pointer protocol**. The reclaim loop asks each
registered page's owner to free it:

```rust
// memory/src/reclaim.rs:153
pub type ReclaimFn = fn(phys: PhysAddr) -> ReclaimOutcome;

// memory/src/reclaim.rs:110
pub enum ReclaimOutcome { Freed, Dirty, Locked, DeferToPager }

// memory/src/reclaim.rs:368
pub fn register_page(entry: PageEntry) -> PageHandle;
```

You supply a plain `fn` pointer (`Copy`, lives in `.rodata` — no `Box`, no
capture) as part of the `PageEntry` you register. When the reclaimer targets
your page it calls your `ReclaimFn`; return `Freed`, `Dirty`, `Locked`, or
`DeferToPager`. Inspect `PageEntry`'s fields in `reclaim.rs` to see exactly
what you register.

## Seam 5 — memory policy (`Mempolicy`) ⚠️ value, not trait

`memory/src/mempolicy.rs:67`

```rust
pub struct Mempolicy { pub mode: u32, pub nodemask: u64 }
impl Mempolicy { pub const DEFAULT: Self = Self { mode: MPOL_DEFAULT, nodemask: 0 }; }

pub fn set_active(policy: Mempolicy);                                   // :94 per-CPU install
pub fn alloc_frame_with(policy: Mempolicy, local: usize) -> Result<PhysFrame, FrameAllocError>; // :146
pub fn alloc_frame_policied(local: usize) -> Result<PhysFrame, FrameAllocError>;                // :188
```

You can `set_active(policy)` at runtime (per-CPU, no cap), but the policy is a
*value* (`mode` + `nodemask`), not a trait. The interpretation of each
`MPOL_*` mode is a hardcoded `match` inside `alloc_frame_with`. **Adding a new
NUMA/allocation policy mode requires editing `mempolicy.rs`** — you cannot
plug in a custom policy *function* from your crate. Existing modes:
`MPOL_DEFAULT`, `MPOL_BIND`, `MPOL_INTERLEAVE`, `MPOL_LOCAL`, `MPOL_PREFERRED`.

## Non-seams (extension requires editing core)

### `BuddyZone` (`buddy.rs:285`) — ❌ concrete type, no trait

`BuddyZone` is a concrete struct with public methods (`new`, `donate`,
`alloc`, `alloc_below`, `free`, `free_frame_count`, `drain_into`, …). You can
*use* it, but you cannot substitute a different order-N free-list policy
underneath the frame allocator without editing `frame.rs` (which owns the
buddy zone). Custom frame-allocation policy → implement `FrameAlloc` (seam 2)
instead of touching buddy internals.

### `Zpool` / `compress` (`zpool.rs:75`, `compress.rs:80`) — ❌ concrete

`Zpool` (`store`/`load`/`free`/`stats`) and the LZ4 codec (`lz4_encode` /
`lz4_decode`) are concrete. You can instantiate a `Zpool`, but the
compression format is fixed. Two extension paths:

1. **Different swap strategy** → implement `Pager` (seam 3). ✅
2. **Different compression codec inside the pool** → requires editing
   `compress.rs`. ❌

## Worked example: a custom pager

```rust
#![no_std]
extern crate alloc;
use narf_memory::{install_pager, Pager, PagerError, SwapSlot};
use narf_memory::{PageFlags, PhysAddr}; // confirm exact re-export paths in memory/src/lib.rs

pub struct MyDiskPager { /* device handle, slot map, … */ }

impl Pager for MyDiskPager {
    fn name(&self) -> &'static str { "mydisk" }
    fn page_out(&self, phys: PhysAddr, _flags: PageFlags) -> Result<SwapSlot, PagerError> {
        // write the 4 KiB at `phys` to your backing store; return its slot id
        todo!()
    }
    fn page_in(&self, slot: SwapSlot) -> Result<PhysAddr, PagerError> {
        // read the slot back into a fresh frame; return its phys addr
        todo!()
    }
    fn discard(&self, _slot: SwapSlot) { /* free the backing-store slot */ }
}

// At boot, with the pager authority cap:
// install_pager(&pager_cap, MyDiskPager { … })?;
```

## Summary table

| Seam | Trait / type | Install | Pluggable from your crate? |
| --- | --- | --- | --- |
| Heap backend | `HeapBackend` (`heap_backend.rs:37`) | `install_heap_backend` (`:176`) | ✅ (must be `static`) |
| Frame allocator | `FrameAlloc` (`frame.rs:1049`) | `install_frame_alloc` (`:1193`) | ✅ single-frame ops only |
| Pager / swap | `Pager` (`pager.rs:118`) | `install_pager` (`:254`) | ✅ |
| Reclaim callback | `ReclaimFn` fn-ptr (`reclaim.rs:153`) | `register_page` (`:368`) | ✅ per-page |
| Memory policy | `Mempolicy` value (`mempolicy.rs:67`) | `set_active` (`:94`) | ⚠️ value only; new modes edit core |
| Buddy allocator | `BuddyZone` (`buddy.rs:285`) | — | ❌ use `FrameAlloc` instead |
| Zpool / compress | concrete (`zpool.rs:75`) | — | ❌ codec fixed; use `Pager` |

## Gotchas

- **`no_std` + `alloc`.** Same as every core crate.
- **Heap backend must be `static`.** `install_heap_backend` takes
  `&'static dyn HeapBackend` — you cannot heap-allocate the thing that
  provides the heap.
- **Install order.** These backends are installed at boot; installing the
  frame allocator or heap backend after allocations are in flight is not a
  supported "hot-swap." Plant your backend early.
- **Cap gating.** Every `install_*` calls `cap.check_live()`; a revoked
  `Grant` cap fails the install. The `Grant` caps are minted on the TCB boot
  path.
