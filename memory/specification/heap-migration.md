# Heap migration — bump → buddy + slab

Plan for replacing the Stage-1 bump allocator (`memory/src/heap.rs`,
`HEAP_CAPACITY` static) with the buddy + slab pair the main spec
already calls for.

## 0. Provenance — clean-room implementation (historical)

**Historical invariant (kept for the in-tree allocators that
already landed under it):** every line of code in
`memory/src/{buddy,slab,heap}.rs` and the matching tests is
clean-room. No GPL-licensed source — and in particular no Linux
kernel mm/ source — was read, referenced, ported, paraphrased,
or used as a model. Same rule that produced `crypto/src/clean/`
(SHA-256/512, ChaCha20-Poly1305, HKDF).

**Current license posture:** NARF is now GPL-2.0-or-later
(2026-05-20 relicense — see commit log). Future memory-management
work MAY consult Linux `mm/` source directly. The clean-room
rule above is no longer mandatory; it remains an explicit choice
the author may make for individual subsystems where they want
algorithmic independence from the Linux implementation. Don't
rewrite the existing clean-room files to re-derive from Linux
— the provenance comment stays accurate as a historical
statement.

What's allowed:

- **Published specifications and academic literature.**
  - Knuth, "The Art of Computer Programming" Vol 1 §2.5 "Dynamic
    Storage Allocation" — the buddy system as documented after
    Knowlton's 1965 paper.
    <https://www.informit.com/store/art-of-computer-programming-volume-1-fundamental-9780201896831>
  - Knowlton, K. C. (1965). "A fast storage allocator." Comm. ACM
    8(10): 623–625. <https://dl.acm.org/doi/10.1145/365628.365655>
  - Bonwick, J. (1994). "The Slab Allocator: An Object-Caching
    Kernel Memory Allocator." USENIX Summer 1994.
    <https://www.usenix.org/legacy/publications/library/proceedings/bos94/full_papers/bonwick.ps>
  - Bonwick, J. & Adams, J. (2001). "Magazines and Vmem: Extending
    the Slab Allocator to Many CPUs and Arbitrary Resources."
    USENIX 2001.
    <https://www.usenix.org/legacy/event/usenix01/full_papers/bonwick/bonwick.pdf>
  - Any peer-reviewed paper — paper text is not GPL.
- **Hardware vendor manuals.**
  - Intel® 64 and IA-32 Architectures Software Developer's Manual,
    Vol 3 (System Programming Guide).
    <https://www.intel.com/sdm>
  - AMD64 Architecture Programmer's Manual, Vol 2 (System
    Programming).
    <https://www.amd.com/system/files/TechDocs/24593.pdf>
- **MIT/BSD/Apache/MPL-licensed reference implementations** for
  cross-checking algorithmic correctness, ONLY consulted at the
  ALGORITHM level (e.g., "buddy coalesces by XOR'ing the frame
  number with the order's size to find the buddy"), never at the
  code level.
  - jemalloc — BSD-2.
    <https://github.com/jemalloc/jemalloc/blob/dev/COPYING>
  - tcmalloc — Apache-2.
    <https://github.com/google/tcmalloc/blob/master/LICENSE>
  - illumos kernel slab — CDDL-1.0 (allowed for algorithm xref;
    Bonwick's original implementation).
    <https://github.com/illumos/illumos-gate/blob/master/usr/src/uts/common/os/kmem.c>
- **Our own existing modules.** `frame.rs` API surface, capability
  patterns, `IrqSafeSpinLock` discipline.

What was forbidden under the historical rule (the rule no
longer binds; this list is preserved so the clean-room subset
of files stays identifiable):

- Reading Linux `mm/` source — `mm/page_alloc.c`, `mm/slab.c`,
  `mm/slub.c`, `mm/slob.c`, `mm/vmalloc.c`, `mm/page-writeback.c`,
  `mm/oom_kill.c`, `mm/shrinker.c`, `mm/compaction.c`,
  `mm/memory_hotplug.c`, or anything under
  <https://github.com/torvalds/linux/tree/master/mm>.
- Reading any GPLv2 / GPLv3 / LGPL allocator source — glibc
  malloc, musl mallocng, OpenJDK ZGC.
- Using AI-assisted code generation that was trained on Linux
  kernel source without explicit clean-room provenance.

The existing `memory/src/{buddy,slab,heap}.rs` files open with a
comment block stating:

```
// Clean-room implementation. Algorithm refs: <papers cited>.
// No GPL source consulted.
```

That comment stays accurate as a historical statement. New
allocator work added after the 2026-05-20 relicense doesn't
need the marker.

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

**Status as of 2026-05-10**: phases 0-4 + 6 are landed; phase 5
(domain tagging) is held until Stage 4. See the per-phase
notes below for the actual commits + what remains.

### Phase 0 — keep bump alive, raise ceiling

**Done.** `HEAP_CAPACITY = 128 << 20`. Bought time for the rest.
Real-hardware boot completes through Stage::Late + ticks without
alloc panic.

### Phase 1 — buddy under the existing frame API

**Done** (`f7b5ea2`). `memory::frame::ALLOC.bins` replaced with
`[BuddyZone; MAX_NUMA_NODES]`. `alloc_pages_on(node, order)` is
the public entry; `alloc_frame_on` is the order=0 case. See
`memory/src/buddy.rs`. Pre-existing frame-allocator tests still
pass; new tests cover split / coalesce / OOM
(`smoke_buddy_oom_returns_empty`).

### Phase 2 — slab on top of buddy, alongside bump

**Done** (`8a0e389`). `memory/src/slab.rs` is on top of the
buddy. Multi-page allocations route through `alloc_pages_on(0,
order)` via a `pages_to_order` helper. Heap is a hybrid
bootstrap-bump → slab (`memory/src/heap.rs`): bump until
`heap::promote_to_slab()` flips `SLAB_LIVE`, slab afterwards.
`dealloc` checks `in_bootstrap(ptr)` to route freeing to the
right path (bump-era allocations stay leaked but bounded). Per
the original phase split this is "alongside bump" *and* the
phase-3 global-allocator flip in one — once SLAB_LIVE flips,
the global allocator is effectively the slab.

### Phase 3 — bootstrap arena shrunk

**Done** (`075bd99`). `BOOTSTRAP_CAPACITY` cut from 128 MiB
to 8 MiB after two changes:

1. Buddy capacity reservation moved out of `init_from_map` and
   into `reserve_for_slab_promotion()`, called from bare_main
   between `rebalance_to_topology` and `promote_to_slab`.
   Per-zone reservation uses each zone's actual frame count
   instead of the global total in every zone.
2. Reservation skips zones with `total_frames == 0`. On a
   16-NUMA-slot setup the empty zones used to burn ~1.4 MiB
   each on speculative capacity.

Real boot pre-promotion footprint: ~750 KiB (vs 16 MiB
before). 8 MiB ceiling = 4× headroom. Drop further once we're
confident in the slab promotion path.

### Phase 4 — per-CPU magazines

**Done** in slab.rs from the start; the central path was
written with magazines from day one. The `try_alloc_atomic`
API (`7c0b34f`) exposes the magazine-only fast path directly
to IRQ-context callers; `try_dealloc_atomic` returns
`AtomicDeallocFull` instead of draining when the magazine
overflows, so IRQ-side code never takes the central lock.

### Phase 5 — domain tagging

**Deferred to Stage 4.** Surface unchanged; plumbing the
`DomainId` through `SlabOpts` is meaningless until the
domain-isolation backbone (PKEY/MTE/PCID per domain) is wired
up beyond what Stage 1 ships.

### Phase 6 — hugepage pool (separate from buddy)

**Done** (`54a1b73`). `memory/src/hugepage.rs` with 2 MiB and
1 GiB pools. `reserve_from_regions(usable, want_2m, want_1g)`
walks the memory map at boot, carves leading naturally-aligned
chunks out of each region up to the cmdline-bounded targets
(`hugepages_2m=N` / `hugepages_1g=N`), and returns the
byte-range excludes that `init_from_map` skips when donating
to the buddy. `alloc_hugepage_2m` / `alloc_hugepage_1g` return
`HugeFrame`s; pool exhaustion returns `Err(Empty)` (no
buddy-coalesce fallback). Tests:
`smoke_hugepage_2m_reserve_alloc_free` and
`smoke_hugepage_1g_reserve_picks_aligned_chunk`.

### Status (2026-05-10)

| Acceptance | Status | Notes |
|---|---|---|
| #1 HW boot, no panic | ✅ | Boots on Zen2 laptop |
| #2 cargo xtask test passes | ✅ | 1402 / 0 / 34 |
| #3 Memory accounting | 🟡 | `frame_stats` + `slab::stats` exist; per-domain accounting waits on Stage 4 |
| #4 Steady-state under churn | ✅ | `smoke_slab_steady_state_under_churn` (1000-iter × 5 classes) + `_large_alloc_` |
| #5 Sleepable assert | ✅ | `AllocContext::Sleepable.debug_assert_consistent()` panics from IRQ ctx; `slab::alloc` asserts on entry |
| #6 Atomic-context perf | ✅ | `try_alloc_atomic` / `try_dealloc_atomic` magazine-only; perf bench `smoke_slab_atomic_perf_bounded` (loose TCG bound; tighten on real HW) |
| #7 Pre-allocated pools | 🟡 | Substrate landed (`memory/src/atomic_pool.rs`, end-to-end IRQ test); driver consumers TBD |
| #8 Reclaim under load | ⏳ | Needs shrinker subsystem (Stage 3+) |
| #9 OOM behavior | ✅ | `try_alloc_pages` returns `Err(Exhausted)`; `smoke_buddy_oom_returns_empty` |

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

- **Should slab caches per CPU pin to a NUMA node?** Resolved
  by Phase 4 — magazines are per-CPU, central is global.
  NUMA-pinned magazines defer to a future perf pass.
- **What's the fast-path lock for the central slab?** Currently
  `IrqSafeSpinLock`; per-class lock-free freelist would be
  faster. Deferring.
- **Pool the very-early bootstrap arena from .bss or from
  buddy?** Resolved: `.bss`-backed bump arena
  (`BOOTSTRAP_CAPACITY = 8 << 20`).

## 8. Files this touches

Landed (status as of 2026-05-10):

- `memory/src/heap.rs` — hybrid bootstrap-bump → slab global
  allocator (Phase 2 + 3)
- `memory/src/buddy.rs` — per-zone free lists, donate / alloc /
  free / drain_into / reserve_growth_capacity (Phase 1)
- `memory/src/slab.rs` — per-CPU magazines + central slabs +
  `try_alloc_atomic` / `try_dealloc_atomic` (Phase 2 + 4)
- `memory/src/hugepage.rs` — boot-reserved 2 MiB / 1 GiB pool
  (Phase 6)
- `memory/src/atomic_pool.rs` — driver-side `AtomicPool<T>`
  fixed-capacity pool, IRQ-safe (acceptance #7 substrate)
- `memory/src/context.rs` — `AllocContext { Sleepable | Atomic
  | IrqOff }`, `is_sleepable()`, debug-asserts at slab entry
  (acceptance #5)
- `memory/src/frame.rs` — `BuddyZone` per NUMA node,
  `alloc_pages_on(node, order)`, `reserve_for_slab_promotion`
- `memory/src/lib.rs` — public exports
- `lib/src/context.rs` — per-CPU IRQ-depth tracker
  (`enter_irq` / `exit_irq` wired into `interrupts::dispatch`)

Pending (Stage 3+ / Stage 4):

- `memory/src/zone.rs` — Dma32 / Normal / HugePage zone selector
- `memory/src/shrinker.rs` — `Shrinker` trait + registry +
  watermark walker (acceptance #8)
- `memory/src/accounting.rs` — per-domain `AllocStats`
  (acceptance #3 second half)
- Domain plumbing through `SlabOpts` (Phase 5)
