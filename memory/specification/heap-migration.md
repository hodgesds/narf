# Heap migration — bump → buddy + slab

Plan for replacing the Stage-1 bump allocator (`memory/src/heap.rs`,
`HEAP_CAPACITY` static) with the buddy + slab pair the main spec
already calls for.

## 1. Current state

- `BumpAllocator` is the global allocator (`#[global_allocator]`).
- 128 MiB static arena in `.bss` (`HEAP` in `heap.rs`); allocations
  bump an `AtomicUsize` offset; `dealloc` is a no-op.
- Hits `alloc_error_handler` with "memory allocation of N bytes
  failed" once the arena fills.
- Frame allocator (`memory::frame`) is real: per-NUMA-node free-list
  pop, IRQ-safe spinlock around bins, NUMA topology rebalance.
- Page-table allocator (`memory::paging`) goes through
  `alloc_frame` for fresh PML4/PDPT/PD/PT pages.

## 2. Problem

Bump never reclaims. Any sustained kernel allocation (driver lifetime
churn, per-task structs created/destroyed, log buffers, networking
SKBs once we have them) will exhaust the arena. We're already at the
edge on real hardware boots.

## 3. Target architecture

Two layers, matching `memory/specification/spec.md` §3.

### 3.1 Buddy allocator (frame layer)

Replaces today's `Vec<PhysFrame>` per-NUMA bin in `memory::frame`.
Power-of-two-order free lists from order 0 (4 KiB) to order 10 (4 MiB).

```rust
pub fn alloc_pages(order: u8) -> Result<PhysFrame, FrameAllocError>;
pub fn free_pages(frame: PhysFrame, order: u8);
pub fn alloc_pages_on(node: usize, order: u8) -> Result<PhysFrame, FrameAllocError>;
```

Per-NUMA-node, per-order free lists. Splits/coalesces standard buddy.
The existing `alloc_frame` becomes `alloc_pages(0)` shorthand.

### 3.2 Slab allocator (object layer)

Replaces `BumpAllocator` as `#[global_allocator]`. Per-CPU magazines
on top of size-class central slabs, each backed by buddy-allocated
4 KiB or 8 KiB slabs.

Size classes: 16, 32, 64, 96, 128, 192, 256, 384, 512, 768, 1024,
1536, 2048, 3072, 4096, 6144, 8192. Allocations beyond 8 KiB go
directly to the buddy.

```rust
unsafe impl GlobalAlloc for SlabAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8;
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout);
}
```

Per-CPU magazine = bounded LIFO stack of free objects per size class
(default 32 entries). Hot-path alloc/free hits the magazine; only on
miss does the central slab (spinlock'd) get touched. Refill / drain
batch sizes tuned for cache friendliness.

### 3.3 Domain hook (Stage 4 prep)

Slab caches carry a `domain: DomainId` tag. Allocator returns objects
mapped under the calling domain's PKEY/PCID. Stage-1 implementation
ignores the tag (single domain); the API surface lands now so Stage-4
domain isolation work doesn't have to touch every allocation site.

## 4. Migration phases

### Phase 0 — keep bump alive, raise ceiling

Already done. `HEAP_CAPACITY = 128 << 20`. Buys time for the rest.
Acceptance: real-hardware boot completes through Stage::Late + ticks
without alloc panic.

### Phase 1 — buddy under the existing frame API

Replace `memory::frame::ALLOC.bins: [Vec<PhysFrame>; MAX_NUMA_NODES]`
with `[BuddyZone; MAX_NUMA_NODES]`. `alloc_frame_on` continues to
work; new `alloc_pages_on(node, order)` lights up.

- Add `memory/src/buddy.rs` with the per-zone splay and free-list
  arrays
- Rewrite `init_from_map` to feed regions to the buddy as initial
  large blocks, not as individual frames
- Test: existing frame allocator tests pass. New tests for higher
  orders + coalescing.

Risk: page-table allocators (`new_user_pml4_on`) still call
`alloc_frame` (= `alloc_pages(0)`). Should be transparent.

Estimated cost: 1-2 days work, ~600 lines + tests.

### Phase 2 — slab on top of buddy, alongside bump

Add `memory/src/slab.rs`. Don't make it the global allocator yet;
expose `slab_alloc` / `slab_free` as named functions. Migrate
specific high-churn sites (scheduler `TaskSlot`, capability
allocations, FB ring entries) to use the slab.

Acceptance: bump arena usage drops measurably for a full boot pass
(probably 30-50% lower).

Estimated cost: 2-3 days, ~800 lines + tests.

### Phase 3 — flip the global allocator

Swap `#[global_allocator]` from `BumpAllocator` to `SlabAllocator`.
Bump becomes the early-boot bootstrap allocator (used only between
`_start_rust` and the slab being live).

The early-boot window: between MMU init and the buddy being seeded.
Bootstrap pattern: a tiny 64 KiB bump arena for the very-early
allocations, switch over once `init_from_map` + buddy + slab are
ready.

Acceptance: Stage-1 boot completes with the slab as global
allocator. Existing `cargo xtask test` suite (1386 cases) passes.
Boot heap usage: should be ~50 MiB, not 128 MiB.

Estimated cost: 1-2 days, mostly debugging the early-boot ordering.

### Phase 4 — per-CPU magazines

Add per-CPU magazine cache on top of the central slab. Lock-free
hot path for the common case (alloc/free of a recent object).

Acceptance: alloc latency benchmark shows 5-10x improvement for the
hot path (single-object alloc/free in a loop).

Estimated cost: 2-3 days, ~400 lines + benchmarks.

### Phase 5 — domain tagging

Plumb `DomainId` through `SlabOpts`. Default-domain allocations work
exactly as before. Stage-4 work later wires the tag into PKEY /
domain isolation.

Estimated cost: 1 day surface change, deferred until Stage 4.

## 5. Acceptance criteria (overall)

1. Real-hardware boot completes through `tick 4` + halting, no alloc
   panic, with workloads that today exhaust 128 MiB.
2. `cargo xtask test` passes — same coverage, no regressions.
3. Memory accounting: `frame_stats()` and a new `slab_stats()` give
   accurate live-allocation counts.
4. Reclaim works: a 1000-iteration alloc/free loop holds steady at
   roughly the working-set size, doesn't grow unboundedly.

## 6. Out of scope

- Hot-add / hot-remove of memory regions (not until much later)
- Compaction / anti-fragmentation — deferred to a follow-up if
  fragmentation actually shows up in workloads
- KASAN-style allocator instrumentation — separate work

## 7. Open questions

- **Should slab caches per CPU pin to a NUMA node?** If yes, every
  alloc consults `current_cpu()`. Probably yes for performance, no
  for simplicity in Phase 3. Defer to Phase 4.
- **What's the fast-path lock for the central slab?** Simple
  `IrqSafeSpinLock` works; a per-class lock-free freelist would be
  faster. Deferring.
- **Pool the very-early bootstrap arena from .bss or from buddy?**
  `.bss` is simpler (no chicken-and-egg); 64 KiB is small enough.

## 8. Files this touches

- `memory/src/heap.rs` — gut bump, replace with bootstrap-bump +
  global-allocator that delegates to slab once live
- `memory/src/buddy.rs` — new
- `memory/src/slab.rs` — new (currently a placeholder magazine)
- `memory/src/frame.rs` — switch backing store from `Vec` per node
  to `BuddyZone` per node
- `memory/src/lib.rs` — public exports
- `memory/specification/spec.md` — mark §3 buddy/slab as Stage-1
  delivered (instead of "Wave 2" placeholder)
