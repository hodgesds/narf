# Heap migration — bump → buddy + slab

Plan for replacing the Stage-1 bump allocator (`memory/src/heap.rs`,
`HEAP_CAPACITY` static) with the buddy + slab pair the main spec
already calls for.

## 0. Provenance — clean-room implementation

**Mandatory invariant:** every line of code that lands as part of
this migration is clean-room. No GPL-licensed source — and in
particular no Linux kernel mm/ source — is read, referenced,
ported, paraphrased, or used as a model. Same rule that produced
`crypto/src/clean/` (SHA-256/512, ChaCha20-Poly1305, HKDF) and
the same reasoning: NARF is MPL-2.0 and must remain
distributable without GPL contamination concerns.

What's allowed:

- **Published specifications and academic literature.** Knuth Vol 1
  §2.5 "Dynamic Storage Allocation" (buddy system, original 1965
  Knowlton paper). Bonwick 1994 USENIX paper on the slab allocator.
  Bonwick & Adams 2001 USENIX paper on per-CPU magazines + vmem.
  Any peer-reviewed paper — paper text is not GPL.
- **Hardware vendor manuals.** Intel SDM Vol 3, AMD APM Vol 2 for
  paging / TLB / WC / MTRR semantics.
- **MIT/BSD/Apache/MPL-licensed reference implementations** for
  cross-checking algorithmic correctness, ONLY consulted at the
  ALGORITHM level (e.g., "buddy coalesces by XOR'ing the frame
  number with the order's size to find the buddy"), never at the
  code level.
- **Our own existing modules.** `frame.rs` API surface, capability
  patterns, `IrqSafeSpinLock` discipline.

What's forbidden:

- Reading Linux mm/ source (`mm/page_alloc.c`, `mm/slab.c`,
  `mm/slub.c`, `mm/vmalloc.c`, etc.) for any reason.
- Reading any GPLv2 / GPLv3 / LGPL allocator source: jemalloc is
  BSD-2 (allowed for algorithm xref), tcmalloc is Apache-2
  (allowed), but glibc malloc is LGPL (forbidden), the Linux SLUB
  is GPL (forbidden), the ZGC allocator from OpenJDK is GPL
  w/ Classpath (avoid).
- Using AI-assisted code generation that was trained on Linux
  kernel source without explicit clean-room provenance —
  Claude generations for this work cite only this spec, the
  algorithm-level papers/manuals above, and the existing NARF
  codebase.

Each new file (`memory/src/buddy.rs`, `slab.rs`, etc.) opens with
a comment block stating:

```
// Clean-room implementation. Algorithm refs: <papers cited>.
// No GPL source consulted.
```

Code review on PRs touching these files explicitly checks for
provenance compliance.

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

## 3. Use cases the allocator must serve

Audit of every allocation pattern the kernel actually uses. Each
target-architecture decision in §4 has to satisfy at least one
of these.

| # | Use case | Frequency | Size | Latency | Reclaim |
|---|----------|-----------|------|---------|---------|
| 1 | Per-task `TaskSlot` (scheduler) | High churn | ~256 B | < 1 µs | Yes (task exit) |
| 2 | Capability `CapSlot` | Moderate | 16 B | < 1 µs | Yes (revoke) |
| 3 | IPC message buffers | Very high | 64 B – 4 KiB | < 1 µs | Yes (consumed) |
| 4 | Page-table pages (PML4/PDPT/PD/PT) | Per-task | 4 KiB | < 10 µs | Yes (address-space drop) |
| 5 | DMA buffers (NIC RX, NVMe SQ/CQ) | Driver init | 4 KiB – 4 MiB | < 10 µs | Yes (driver unbind) |
| 6 | DMA32 buffers (legacy USB EHCI) | Driver init | 4 KiB | once | Rare |
| 7 | VM guest memory backing | Workload-driven | 2 MiB / 1 GiB | bounded | Yes (VM exit) |
| 8 | Framebuffer scanout | Boot-once | 1 – 64 MiB | once | Never (until display change) |
| 9 | Async future bodies | Very high | 64 B – 16 KiB | < 1 µs | Yes (await complete) |
| 10 | Driver work queues | Per-driver | 4 – 64 KiB | once | Yes (driver unbind) |
| 11 | VFS page cache | Workload-driven | 4 KiB pages | < 10 µs | Yes (clean-page evict) |
| 12 | Userspace page-frames | Per-page-fault | 4 KiB | < 10 µs | Yes (page swap / unmap) |
| 13 | Kernel stacks | Per-task | 16 KiB | once / task | Yes (task exit) |
| 14 | Per-CPU storage | Boot | small | once | Never |
| 15 | Trace buffers / log rings | Continuous | 64 KiB – MiB | < 1 µs | Yes (oldest-first) |
| 16 | TLB-shootdown IPI descriptors | High | 32 B | bounded | Yes (ack) |
| 17 | Boot-time arena (early-init) | Bounded | small | once | Never |
| 18 | Vmalloc-style non-contiguous | Driver/VM | 4 KiB – 16 MiB | < 100 µs | Yes |
| 19 | Pre-allocated IRQ pool | Per-driver | small fixed | < 1 µs | Never |
| 20 | Crashdump reservation | Boot | configurable | once | Never |

Coverage rationale:

- 1, 2, 3, 9, 16 → small fixed-size, very high churn → **per-CPU
  magazine + slab** (§4.3, §4.4)
- 4, 12, 13 → fixed-size 4 KiB / 16 KiB power-of-two → **buddy
  order 0..2** (§4.1)
- 5, 8, 10, 18 → variable up to a few MiB → **buddy order 0..10**
  (§4.1) + vmalloc for the non-contiguous case (§4.7)
- 6 → < 4 GiB constraint → **DMA32 zone** (§4.5)
- 7 → multi-MiB to GiB contiguous → **hugepage pool** (§4.2)
- 11, 15 → reclaimable on pressure → **shrinker registry** (§4.6.2)
- 14, 17, 20 → boot-time once → **bootstrap-bump** + carve from
  buddy at init (§4.6.6 / phase 3)
- 19 → never-fail under IRQ → **pre-allocated pool, separate
  from general allocator** (§4.6.5)

Anything missing from this table is either out-of-scope (§7) or
should be added before implementation begins.

## 4. Target architecture

Two layers, matching `memory/specification/spec.md` §3.

### 3.1 Buddy allocator (frame layer)

Replaces today's `Vec<PhysFrame>` per-NUMA bin in `memory::frame`.
Power-of-two-order free lists from order 0 (4 KiB) up to and
including order 10 (4 MiB). Cap at 4 MiB by design — see §3.1.1
for why we don't go higher.

```rust
pub fn alloc_pages(order: u8) -> Result<PhysFrame, FrameAllocError>;
pub fn free_pages(frame: PhysFrame, order: u8);
pub fn alloc_pages_on(node: usize, order: u8) -> Result<PhysFrame, FrameAllocError>;
```

Per-NUMA-node, per-order free lists. Splits/coalesces standard buddy.
The existing `alloc_frame` becomes `alloc_pages(0)` shorthand.

#### 3.1.1 Why order 10 max (and not 1 GiB / order 18)

x86_64 supports three page sizes: 4 KiB, 2 MiB (PD with PS=1),
1 GiB (PDPT with PS=1). Tempting to size the buddy to 1 GiB so
hugepage allocations route through the same code path. We
deliberately don't, for three reasons:

1. **Coalescing past ~order 12 fails in practice.** Real RAM
   gets fragmented within minutes of uptime: PCI BARs, ACPI
   reserved, SMM stolen pages, kernel-image .bss, runtime
   allocations all carve sub-MiB holes. The chance of an
   order-18 buddy block (1 GiB physically-contiguous, naturally-
   aligned) materializing dynamically is ~0. Bookkeeping for
   orders nothing ever populates is dead bytes and dead code.

2. **Linux caps buddy at order 10.** Two decades of production
   tuning landed there. Hugepages are a separate boot-reserved
   pool, not buddy-managed.

3. **Kernel direct map doesn't need to allocate 1-GiB pages.**
   boot.S already builds 0..4 GiB identity at PDPT-level with
   four 1-GiB huge pages; the page-table entries are filled
   once, no allocator involved. Same pattern for the eventual
   high-half direct map.

### 3.1.2 Hugepage pool (separate, boot-reserved)

For workloads that legitimately want 2 MiB or 1 GiB pages
(virtualization guest memory backing, large DMA buffers for GPU
passthrough, kernel direct-map extensions past 4 GiB), we keep a
separate hugepage allocator seeded at boot from
naturally-aligned contiguous regions in the memory map:

```rust
pub fn alloc_hugepage_2m() -> Result<HugeFrame, HugeAllocError>;
pub fn alloc_hugepage_1g() -> Result<HugeFrame, HugeAllocError>;
pub fn free_hugepage(frame: HugeFrame);
```

`init_from_map` walks the usable regions and, for each region
whose start is aligned to 2 MiB / 1 GiB and whose length is
≥ that size, reserves the leading aligned chunks into the
hugepage pool. Whatever's left over (head misalignment + tail)
goes to the buddy.

Hugepage allocations don't fall back to coalescing buddy
blocks — if the boot reservation didn't capture enough
hugepages, the request fails. Callers must either retry with
small pages or arrange for the workload to start before
fragmentation eats the contiguous regions. This is the
explicit Linux model (`hugepages=` boot param + dedicated
pool).

Hugepage tuning is a per-deployment decision (how many to
reserve, what sizes); for Stage-1 we reserve none by default
and the API just returns "Empty" until config plumbing lands.

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

### 3.4 Memory zones

Three zones, each with its own buddy free-list set. NUMA-aware
underneath (per-zone-per-node).

| Zone | Phys range | Use case |
|------|-----------|----------|
| `Dma32` | < 4 GiB | Legacy device DMA buffers (controllers with 32-bit DMA mask: USB EHCI, some xHCI) |
| `Normal` | ≥ 4 GiB | Everything else; default pool for kernel objects + user-page backing |
| `HugePage` | (boot-reserved) | The 2 MiB / 1 GiB pool described in §3.1.2 |

`alloc_pages` defaults to `Normal`. Devices that need 32-bit DMA
addresses request `Zone::Dma32` explicitly:

```rust
pub fn alloc_pages_zoned(zone: Zone, order: u8) -> Result<PhysFrame, FrameAllocError>;
```

DMA32 falls back to Normal for the *bookkeeping* metadata pages
(buddy free-list arrays, etc.) — only the returned data pages are
zone-constrained.

### 3.5 Allocator API surface — context, blocking, fallibility

Two orthogonal concerns shape every allocation:

1. **Can the caller sleep?** (process context vs IRQ / spinlock-held)
2. **Does the caller want a panic on OOM, or do they handle failure?**

We model context explicitly via an `AllocContext` enum the caller
passes to the allocator (Linux's GFP flags translated to a Rust
type system). Mixing them up is a class of bug we want the
compiler to catch at the call site:

```rust
pub enum AllocContext {
    /// Process context. May sleep, may invoke shrinkers, may
    /// migrate to other NUMA nodes / CPUs. The "normal" mode.
    /// Roughly equivalent to Linux GFP_KERNEL.
    Sleepable,

    /// Atomic context (IRQ handler, spinlock held, NMI handler,
    /// preempt-disabled section). MUST NOT sleep. MUST NOT trigger
    /// shrinkers. MUST NOT cross CPUs (no work-stealing across
    /// magazines). Roughly equivalent to Linux GFP_ATOMIC.
    Atomic,

    /// IRQ-disabled but non-IRQ context (kernel hot path with
    /// `IrqSafeSpinLock` held). Same constraints as Atomic plus
    /// MUST be lock-free on the hot path (we own a spinlock; any
    /// cross-CPU IPI we'd issue could deadlock against our lock).
    IrqOff,
}
```

#### 3.5.1 Fallible vs panicking

Orthogonal to context — every allocator entry point has both
flavors. `GlobalAlloc::alloc` (Rust trait) returns null on
failure → `alloc_error_handler` → panic, which is fine for
`Box::new` ergonomics in long-running paths. But kernel code that
can recover from alloc failure shouldn't panic.

```rust
// Panicking — for code paths that can't recover anyway.
// Implicit Sleepable context.
pub fn alloc_obj<T>(cache: &SlabCache<T>) -> Box<T>;
pub fn alloc_pages(order: u8) -> PhysFrame;

// Fallible — caller handles None / Err.
// Context explicit; compile-time-checked against caller's state.
pub fn try_alloc_obj<T>(cache: &SlabCache<T>, ctx: AllocContext) -> Option<Box<T>>;
pub fn try_alloc_pages(order: u8, ctx: AllocContext) -> Result<PhysFrame, FrameAllocError>;
```

Two helpers for the common atomic-context path that just want to
fail fast:

```rust
// Atomic-context shorthand: never sleeps, never invokes reclaim,
// magazine-only, fails immediately if local magazine is empty.
// O(1) hot path, ideal for IRQ handlers.
pub fn try_alloc_obj_atomic<T>(cache: &SlabCache<T>) -> Option<Box<T>>;
pub fn try_alloc_pages_atomic(order: u8) -> Option<PhysFrame>;
```

#### 3.5.2 Context inference + enforcement

Three layers of safety:

1. **Compile time.** A `SleepableScope` token is required to
   construct `AllocContext::Sleepable`. Kernel-mode code that
   runs in IRQ / spinlock-held context can't get a token, so
   the compiler refuses the wrong context.

2. **Debug-build runtime.** `cfg(debug_assertions)` checks at
   each entry point: `Sleepable` panics if `!preempt_enabled()`
   or `irqs_disabled()`; `Atomic`/`IrqOff` succeeds in either.

3. **Production check.** Lightweight: `Sleepable` asserts
   `irqs_enabled()` (one `pushfq`), to catch the case where
   someone calls a sleepable allocator with IRQs off.

#### 3.5.3 Behavior matrix

| Context | Sleeps? | Triggers shrinker? | Cross-NUMA? | Hot path |
|---------|---------|--------------------|-----------:|----------|
| `Sleepable` | Yes (yields to scheduler) | Yes | Yes | Magazine, then central, then reclaim, then OOM |
| `Atomic` | No | No | No (local node only) | Magazine; on miss return Err immediately |
| `IrqOff` | No | No | No | Magazine only, lock-free; on miss return Err |

`Sleepable` is what `GlobalAlloc::alloc` maps to (any code that
hits `Box::new` etc.). `Atomic` / `IrqOff` are what driver IRQ
handlers and the scheduler hot path use explicitly.

#### 3.5.4 Pre-allocated pools for IRQ-critical paths

Some paths can't even tolerate `Atomic` failure (network RX,
TLB-shootdown IPI descriptors, scheduler tick handler). For
those, the driver pre-allocates a fixed-size pool at init and
draws from it under IRQ:

```rust
pub struct AtomicPool<T> { /* private */ }
impl<T> AtomicPool<T> {
    pub fn new(capacity: usize, ctx: SleepableScope) -> Self; // sleepable
    pub fn try_get(&self) -> Option<Pooled<T>>;               // atomic, lock-free
    pub fn put(&self, item: Pooled<T>);                       // atomic, lock-free
}
```

Pool exhaustion is a driver bug (sized too small) — the driver
panics or drops the request, but the kernel itself stays up.

### 3.6 OOM and reclaim

Allocation failure is a real failure mode — buddy can have free
RAM but be unable to satisfy a high-order request (fragmentation),
or the system can genuinely have no free RAM left. Both need
explicit handling, and reclaim is the bridge between "alloc
failed" and "panic the kernel".

#### 3.6.1 Failure decision tree

When an allocation fails, the order of operations is:

```
try alloc on local NUMA node
  → success: return
  → fail: try other NUMA nodes (round-robin)
     → success: return
     → fail: drain per-CPU magazines back to central slabs
              (releases held-but-unallocated objects)
        → retry alloc
        → success: return
        → fail: invoke registered shrinkers (drop reclaimable caches)
           → retry alloc
           → success: return
           → fail: returned to caller as OOM
              ├ fallible caller: gets Err / None, decides what to do
              └ panicking caller: alloc_error_handler fires
```

Each step is bounded — no busy-loops between retries. Shrinker
invocation is "best effort, return promptly" — they can release
some memory but aren't required to release any specific amount.

#### 3.6.2 Reclaim mechanism

Kernel subsystems that hold reclaimable caches register a
shrinker:

```rust
pub trait Shrinker: Send + Sync {
    /// How much (bytes) the shrinker estimates it can free.
    /// Cheap to compute — called frequently.
    fn estimate_freeable(&self) -> usize;

    /// Actually free up to `target` bytes. Return the actual
    /// freed amount. May free zero. May free more than target.
    fn shrink(&self, target: usize) -> usize;
}

pub fn register_shrinker(s: Arc<dyn Shrinker>);
```

Stage-1 candidates for shrinkers (these aren't critical to the
allocator working, just useful pressure relief):

- **VFS pagecache** — drop clean cached file pages
- **Slab cache magazines** — drain to central slab without
  freeing the slabs themselves (just shrinks per-CPU footprint)
- **Empty slab pages** — central slabs that have all-free objects
  can free their backing buddy block
- **Per-task work-queue caches** — bounded ring buffers that hold
  recent completions for diagnostics

The OOM path walks the shrinker registry in priority order
(highest-`estimate_freeable` first), invokes `shrink(target)` on
each, retries the allocation after each callback.

#### 3.6.3 Last-resort OOM kill

If shrinkers can't free enough, the kernel must kill something.
Two options:

1. **Kernel panic.** Simplest. Acceptable if OOM is genuinely
   never expected. Stage-1 default.
2. **OOM killer.** Walk per-task accounting (§3.6.4), pick the
   task using the most reclaimable memory, terminate it,
   reclaim its allocations. Stage-3+ when we have proper task
   accounting.

For Stage 1: if alloc fails after shrinkers, we panic with
"OOM: N bytes requested, N free, N reclaimable". Userspace
dies with the kernel — fine for a microkernel that hasn't yet
proven it can survive userspace death anyway.

#### 3.6.4 Memory accounting (per-domain / per-task)

Every allocation through the slab carries a charge to the
calling task / domain. `frame_stats()` extends to include:

```rust
pub struct AllocStats {
    pub frames_total: usize,
    pub frames_free: usize,
    pub frames_reclaimable: usize,  // estimate from all shrinkers
    pub heap_bytes_in_use: usize,
    pub heap_bytes_reclaimable: usize,
    pub per_domain: [DomainAlloc; 16],
}

pub struct DomainAlloc {
    pub frames: usize,
    pub heap_bytes: usize,
    pub task_count: u32,
}
```

Used by:
- The OOM killer when it lands (Stage 3+)
- Diagnostics / `narf>` shell commands
- Per-domain quota enforcement (Stage 4 work)

Stage-1 just maintains the counters; doesn't act on them.

#### 3.6.5 IRQ-context constraints

The constraint enforcement is encoded in `AllocContext` (§3.5).
`Atomic` and `IrqOff` skip the §3.6.1 fallback chain past the
local magazine — no shrinker invocation, no cross-CPU migration,
return Err immediately on miss. Real-time paths use the
pre-allocated pools (§3.5.4) so they never enter the allocator
at all on the hot path.

#### 3.6.6 Reclaim cadence + watermarks

In addition to alloc-failure-driven reclaim, a background
shrinker walker fires on watermark thresholds:

```
high_watermark   ─────  reclaim disabled
                       │
                       │  (shrinker idle)
                       │
mid_watermark    ───── │  ── start gentle reclaim ──
                       │
                       │  (shrinker walks every 100 ms)
                       │
low_watermark    ───── │  ── aggressive reclaim ──
                       │
                       │  (shrinker walks every 10 ms)
                       │
                  ──── │  alloc failures spawn synchronous reclaim
oom_threshold    ───── │  (in caller's context if Sleepable)
```

Watermarks are per-NUMA-zone, sized as fractions of the zone's
total free pages. Defaults: high 75%, mid 50%, low 25%, oom 5%.

The watermark walker runs as a low-priority kernel task spawned
during boot. Doesn't touch IRQ-only allocations.

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

### Phase 6 — hugepage pool (separate from buddy)

Add `memory/src/hugepage.rs` with the 2 MiB / 1 GiB pools.
`init_from_map` walks usable regions, reserves naturally-aligned
hugepages BEFORE the buddy gets the rest. Pool size policy:

- 2 MiB: reserve up to N pages (N from cmdline `hugepages_2m=N`,
  default 0).
- 1 GiB: reserve up to N pages (cmdline `hugepages_1g=N`,
  default 0).

`alloc_hugepage_2m()` / `alloc_hugepage_1g()` return `HugeFrame`s
backed by those pre-reserved chunks. No coalescing from buddy —
explicit pool only. `free_hugepage` returns the page to the pool.

Acceptance: with `hugepages_2m=8` on cmdline, eight 2 MiB
allocations succeed and a ninth fails with `Empty`. Free four
and four more allocations succeed.

Estimated cost: 1 day, ~300 lines + tests. No Stage-1 driver
needs hugepages, so this phase can land any time after Phase 1
(buddy is what carves up the leftover non-hugepage RAM).

## 5. Acceptance criteria (overall)

1. Real-hardware boot completes through `tick 4` + halting, no alloc
   panic, with workloads that today exhaust 128 MiB.
2. `cargo xtask test` passes — same coverage, no regressions.
3. Memory accounting: `frame_stats()` and a new `slab_stats()` give
   accurate live-allocation counts; per-domain accounting populated.
4. Reclaim works: a 1000-iteration alloc/free loop holds steady at
   roughly the working-set size, doesn't grow unboundedly.
5. **Context safety**: a debug build catches every `Sleepable`
   allocation made in IRQ context (asserts in the test suite).
6. **Atomic-context perf**: `try_alloc_obj_atomic` measured at
   < 100 ns hot path on the bring-up CPU; failure path < 200 ns.
7. **Pre-allocated pools**: IRQ-critical drivers can sustain peak
   request rate without allocator pressure — verified by a stress
   test that floods the network RX path.
8. **Reclaim under load**: synthetic workload that fills 75% of
   memory with reclaimable pagecache, then allocates aggressively
   in another task, completes without OOM kill (shrinker frees
   the cached pages).
9. **OOM behavior**: with 1 MiB total free RAM, attempting to
   allocate 2 MiB returns `Err` from `try_alloc_pages` and panics
   from `alloc_pages` — both with informative diagnostic.

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
- `memory/src/buddy.rs` — new (per-zone, per-NUMA-node free lists)
- `memory/src/slab.rs` — new (per-CPU magazines + central slabs)
- `memory/src/hugepage.rs` — new (boot-reserved 2 MiB / 1 GiB pool)
- `memory/src/zone.rs` — new (Dma32 / Normal / HugePage enum + zone
  selection logic)
- `memory/src/alloc_context.rs` — new (`AllocContext` + scope tokens
  + debug enforcement)
- `memory/src/shrinker.rs` — new (`Shrinker` trait + registry +
  watermark walker task)
- `memory/src/atomic_pool.rs` — new (driver-side pre-allocated
  fixed-size pool)
- `memory/src/accounting.rs` — new (`AllocStats`, per-domain charge)
- `memory/src/frame.rs` — switch backing store from `Vec` per node
  to `BuddyZone` per node; expose zone-aware variants
- `memory/src/lib.rs` — public exports
- `memory/specification/spec.md` — mark §3 buddy/slab as Stage-1
  delivered (instead of "Wave 2" placeholder)
