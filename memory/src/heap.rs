//! Hybrid bootstrap-bump + slab global allocator.
//!
//! Two-phase global allocation:
//!
//! 1. **Bootstrap phase** (from `_start_rust` until the buddy is
//!    seeded by `init_from_map`). Allocations come from a small
//!    static bump arena in `.bss` — single-page tables, capability
//!    bookkeeping, and other very-early kernel objects fit easily
//!    in a few MiB.
//! 2. **Slab phase** (after `promote_to_slab()` is called).
//!    Allocations route to `crate::slab` (per-CPU magazines + central
//!    size-class free lists), which is in turn backed by the buddy.
//!
//! Promotion is one-way: once we're on the slab, we don't fall back.
//! `dealloc` checks the pointer's address: if it's inside the
//! bootstrap arena, it's a bump-era allocation that we can't reclaim
//! (typical bump semantics); otherwise it's a slab object and gets
//! freed properly.
//!
//! ## Wave-B pluggability
//!
//! `BumpAllocator` is still the workspace's `#[global_allocator]`
//! type — its identity is load-bearing for downstream
//! `static GLOBAL_ALLOC: BumpAllocator = BumpAllocator;` declarations
//! (notably `frame::bare_main`). Its `GlobalAlloc::alloc` /
//! `dealloc` body no longer branches on `SLAB_LIVE` directly;
//! instead it dispatches through `heap_backend::current_backend()`,
//! the seam introduced in `memory/src/heap_backend.rs`. The two
//! shipped backends (`BumpBackend`, `SlabBackend`) wrap the same
//! `HEAP` bump arena + `crate::slab` they used to inline. The
//! `bump_alloc` shim below is the canonical entry point those
//! backends call into; the `in_bootstrap` predicate is what makes
//! cross-backend `dealloc` (slab routing past a stranded bump
//! pointer) still safe.
//!
//! See `memory/specification/heap-migration.md` for the full plan.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::heap_backend::{
    self, current_backend, install_default_if_unset, HeapBackend, SLAB_BACKEND,
};

/// Bootstrap arena size. Has to cover every allocation up to the
/// point `promote_to_slab()` is called. Pre-promotion includes
/// ACPI table parse, MADT/SRAT/HMAT topology, NUMA rebalance,
/// and per-zone buddy capacity reservation. Empirically ~2 MiB
/// on a 16 GiB / 16-node system; 8 MiB worked through QEMU but
/// real-HW laptops with denser device trees (dozens of PCI nodes,
/// AML namespace nodes per platform device, multiple I2C / GPIO
/// controllers + their HID children) blow past it before the slab
/// comes up. 16 MiB gives ~8× headroom over the QEMU steady state
/// while still costing only 16 MiB of `.bss` on a kernel that's
/// already 50+ MiB.
pub const BOOTSTRAP_CAPACITY: usize = 12 << 20;

/// Byte storage for the bootstrap bump arena. Lives in `.bss`,
/// 16-byte aligned for any alignment ≤ 16 to be trivially satisfiable.
#[repr(C, align(16))]
struct HeapBacking(UnsafeCell<[u8; BOOTSTRAP_CAPACITY]>);
// SAFETY: the operation upholds its documented invariant (see surrounding context).
unsafe impl Sync for HeapBacking {}

static HEAP: HeapBacking = HeapBacking(UnsafeCell::new([0; BOOTSTRAP_CAPACITY]));
static OFFSET: AtomicUsize = AtomicUsize::new(0);

/// Promote the global allocator from bootstrap-bump to slab. Call
/// exactly once, after `init_from_map` has populated the buddy.
/// Allocations made before this point stay in the bootstrap arena
/// (and stay leaked, per bump semantics); allocations after route
/// to the slab.
///
/// Implementation: installs `&SLAB_BACKEND` into the heap-backend
/// slot, replacing whatever was there (typically `&BUMP_BACKEND`
/// planted lazily on first allocation). The bump arena's
/// `in_bootstrap` predicate ensures stranded bump pointers still
/// land on the no-op `dealloc` path even after the slab is the
/// active backend.
pub fn promote_to_slab() {
    // The cap-gated install surface (`install_heap_backend`) is the
    // public path; this internal route exists because `promote_to_slab`
    // is the canonical, kernel-internal promotion point and existed
    // before the trait seam. `install_uncapped` is crate-private to
    // ensure no external code can side-step the cap check.
    heap_backend::install_uncapped(&SLAB_BACKEND);
}

/// The hybrid global allocator. Pre-promotion: bump arena.
/// Post-promotion: slab routes to size-class central + per-CPU
/// magazines. Wave B: the routing decision moved into
/// `heap_backend::current_backend()` — this type is now the shell
/// the workspace's `#[global_allocator]` declarations bind to.
pub struct BumpAllocator;

impl core::fmt::Debug for BumpAllocator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BumpAllocator")
            .field("bootstrap_used", &OFFSET.load(Ordering::Relaxed))
            .field("bootstrap_capacity", &BOOTSTRAP_CAPACITY)
            .field(
                "backend",
                &heap_backend::current_heap_backend_name().unwrap_or("none"),
            )
            .finish()
    }
}

/// How many SPILL regions the bootstrap arena can be extended with.
/// The buddy hands out at most `1 << MAX_ORDER` frames (32 MiB) per
/// allocation, so a handful of regions covers a very large machine:
/// the pre-slab reservation costs ~16 bytes per 4 KiB frame, i.e.
/// ~0.4% of RAM, so 8 × 32 MiB of spill covers ~64 GiB.
const MAX_SPILL_REGIONS: usize = 8;

/// One buddy-donated extension of the bootstrap arena: `(base, len,
/// cursor)`. `base == 0` means the slot is unused. Written only by
/// `add_bootstrap_spill` during single-threaded early boot; read
/// concurrently thereafter.
static SPILL: [(AtomicUsize, AtomicUsize, AtomicUsize); MAX_SPILL_REGIONS] = [const {
    (
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    )
}; MAX_SPILL_REGIONS];

/// Extend the bootstrap bump arena with a region of real RAM.
///
/// The `.bss` arena is a FIXED 12 MiB, but one pre-slab consumer
/// scales with RAM: `BuddyZone::reserve_growth_capacity` reserves the
/// pessimistic per-order free-list capacity, ~16 bytes per frame. That
/// put a hard ~3 GiB ceiling on boot — an 8 GiB machine died in
/// `reserve_for_slab_promotion` with "memory allocation of 2080896
/// bytes failed" — even though the MMU maps far more. Rather than
/// grow `.bss` for every machine, the caller allocates frames from the
/// (already live) buddy and donates them here.
///
/// # Safety
/// `base` must point to `len` bytes of RAM that are mapped, writable,
/// and owned by the caller for the lifetime of the kernel — the bump
/// arena never frees, and pointers into this region must stay valid
/// after the bump→slab promotion (see [`in_bootstrap`]).
pub unsafe fn add_bootstrap_spill(base: *mut u8, len: usize) -> bool {
    if base.is_null() || len == 0 {
        return false;
    }
    for slot in SPILL.iter() {
        if slot
            .0
            .compare_exchange(0, base as usize, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            slot.1.store(len, Ordering::Release);
            slot.2.store(0, Ordering::Release);
            return true;
        }
    }
    false
}

/// Bytes still available in the `.bss` arena plus every spill region.
/// Lets a caller decide whether it needs to donate more before making
/// a large pre-slab reservation.
pub fn bootstrap_remaining() -> usize {
    let mut free = BOOTSTRAP_CAPACITY.saturating_sub(OFFSET.load(Ordering::Relaxed));
    for slot in SPILL.iter() {
        if slot.0.load(Ordering::Acquire) != 0 {
            let len = slot.1.load(Ordering::Acquire);
            free += len.saturating_sub(slot.2.load(Ordering::Relaxed));
        }
    }
    free
}

/// Returns true iff `ptr` lies inside the bootstrap arena's bytes —
/// the `.bss` array OR any spill region donated to it.
/// Used by `dealloc` to route freeing to the right path —
/// stranded bump-era pointers survive the bump→slab promotion and
/// must NOT be handed to `slab::dealloc`.
pub(crate) fn in_bootstrap(ptr: *mut u8) -> bool {
    let base = HEAP.0.get() as *mut u8 as usize;
    let end = base + BOOTSTRAP_CAPACITY;
    let p = ptr as usize;
    if p >= base && p < end {
        return true;
    }
    for slot in SPILL.iter() {
        let sbase = slot.0.load(Ordering::Acquire);
        if sbase != 0 && p >= sbase && p < sbase + slot.1.load(Ordering::Acquire) {
            return true;
        }
    }
    false
}

/// Carve `layout` out of a spill region. Same CAS discipline as the
/// `.bss` arena, per region.
fn spill_alloc(layout: Layout) -> *mut u8 {
    let align = layout.align().max(1);
    let size = layout.size();
    for slot in SPILL.iter() {
        let base = slot.0.load(Ordering::Acquire);
        if base == 0 {
            continue;
        }
        let len = slot.1.load(Ordering::Acquire);
        loop {
            let cur = slot.2.load(Ordering::Relaxed);
            // Align the ABSOLUTE address, not the offset — a
            // buddy-donated base is page-aligned, but keeping the
            // arithmetic on real addresses is what the alignment
            // contract is actually about.
            let addr = match (base + cur).checked_add(align - 1) {
                Some(a) => a & !(align - 1),
                None => break,
            };
            let end_off = match (addr - base).checked_add(size) {
                Some(e) if e <= len => e,
                _ => break, // this region can't fit it; try the next
            };
            if slot
                .2
                .compare_exchange_weak(cur, end_off, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return addr as *mut u8;
            }
        }
    }
    core::ptr::null_mut()
}

/// Bump-arena `alloc` implementation. Public to the crate so
/// `heap_backend::BumpBackend` can call into it without
/// re-implementing the CAS loop. Returns null on overflow,
/// matching `GlobalAlloc::alloc`.
pub(crate) fn bump_alloc(layout: Layout) -> *mut u8 {
    let align = layout.align().max(1);
    let size = layout.size();
    loop {
        let cur = OFFSET.load(Ordering::Relaxed);
        let aligned = (cur + align - 1) & !(align - 1);
        let end = match aligned.checked_add(size) {
            Some(e) if e <= BOOTSTRAP_CAPACITY => e,
            // `.bss` arena full (or this request is simply bigger than
            // what's left): fall through to any buddy-donated spill.
            _ => return spill_alloc(layout),
        };
        if OFFSET
            .compare_exchange_weak(cur, end, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            let base = HEAP.0.get() as *mut u8;
            // SAFETY: the CAS above succeeded, so `aligned..end` is now
            // exclusively reserved for this caller, and `end <=
            // BOOTSTRAP_CAPACITY` was checked, so `aligned <= end <=
            // BOOTSTRAP_CAPACITY`. `base` points at the start of the
            // `BOOTSTRAP_CAPACITY`-byte HEAP arena, so `base.add(aligned)`
            // stays within (or one past the end of) that same allocation.
            // SAFETY: Valid memory or trusted environment
            return unsafe { base.add(aligned) };
        }
    }
}

// SAFETY: `BumpAllocator` satisfies the `GlobalAlloc` contract. Every
// pointer it returns from `alloc` comes from the currently-installed
// backend (bump arena or slab), is suitably aligned for `layout`, and
// stays valid until the matching `dealloc`. `dealloc` is only ever
// called with a pointer/layout pair this allocator previously handed
// out: bootstrap-arena pointers are routed away from the slab (they are
// never freed), and all other pointers go back to the backend that
// produced them. Concurrent calls are serialised through the backend's
// own atomics (the bump path is a lock-free CAS loop), so the impl is
// sound under the multi-threaded use the global allocator sees.
/// Maximum background-reclaim target published by one failed
/// `GlobalAlloc::alloc`. Coalescing happens per node, so repeated failures do
/// not accumulate unbounded work.
const BACKGROUND_RECLAIM_MAX_PAGES: usize = 8;

#[inline]
const fn background_reclaim_target(size: usize) -> usize {
    let pages = size.saturating_add(4095) / 4096;
    if pages == 0 {
        1
    } else if pages > BACKGROUND_RECLAIM_MAX_PAGES {
        BACKGROUND_RECLAIM_MAX_PAGES
    } else {
        pages
    }
}

/// Attempt one backend allocation, publishing background reclaim on failure.
///
/// This helper deliberately neither retries nor invokes a shrinker: a global
/// allocation may occur while its caller holds any kernel lock, including a
/// lock that a shrinker needs. Returning null preserves `GlobalAlloc`'s failure
/// contract and lets an allocation-aware outer path decide whether it can park
/// and retry safely.
unsafe fn alloc_once_or_request(
    backend: &'static dyn HeapBackend,
    layout: Layout,
    node: usize,
) -> *mut u8 {
    // SAFETY: the caller forwards the `GlobalAlloc::alloc` layout contract.
    let ptr = unsafe { backend.alloc(layout) };
    if ptr.is_null() {
        crate::reclaim::request_reclaim(node, background_reclaim_target(layout.size()));
    }
    ptr
}

// SAFETY: the backend dispatched to (`current_backend`) upholds the
// `GlobalAlloc` contract; alloc/dealloc forward the caller's layout
// unchanged. Failure only publishes an allocation-free background-reclaim
// request and returns null; it never sleeps, runs callbacks, or retries while
// the caller may hold arbitrary locks.
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // First-allocation lazy default: if no backend is installed
        // yet, plant `&BUMP_BACKEND` so the very first allocation
        // (which fires before `init_from_map` runs) succeeds.
        // Idempotent — subsequent `promote_to_slab` overwrites it.
        install_default_if_unset();
        let backend = match current_backend() {
            Some(b) => b,
            // Defensive: `install_default_if_unset` above means
            // this branch is structurally unreachable, but a null
            // return is safer than a panic if a future caller
            // skips initialization.
            None => return core::ptr::null_mut(),
        };
        // SAFETY: caller upholds `GlobalAlloc::alloc`'s layout contract, which
        // is the same contract `HeapBackend::alloc` forwards.
        unsafe { alloc_once_or_request(backend, layout, crate::frame::current_cpu_node()) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Pointers from the bootstrap arena can't be freed (bump
        // doesn't track sizes per slot). Route them away from
        // whatever backend is currently installed — once the slab
        // takes over, handing a bump-era pointer to `slab::dealloc`
        // would corrupt the slab's free-list.
        if in_bootstrap(ptr) {
            return;
        }
        let backend = match current_backend() {
            Some(b) => b,
            // No backend + non-bump pointer is a logic bug, but a
            // silent leak is the least-bad outcome.
            None => return,
        };
        // SAFETY: caller asserts the pointer/layout pair came from
        // a prior `alloc`. The `in_bootstrap` check above
        // guarantees `ptr` is NOT a stranded bump-era pointer, so
        // it's safe to hand to the current backend.
        // SAFETY: Valid memory or trusted environment
        unsafe { backend.dealloc(ptr, layout) }
    }
}

/// Snapshot of bootstrap arena usage for diagnostics. Does NOT
/// include slab usage — see `crate::slab::stats()` for that.
pub fn used_bytes() -> usize {
    OFFSET.load(Ordering::Relaxed)
}

/// Bootstrap arena total capacity.
pub const fn capacity_bytes() -> usize {
    BOOTSTRAP_CAPACITY
}

/// Diagnostic: `(regions, total_bytes)` of buddy-donated spill added to
/// the bootstrap arena. `(0, 0)` on a small machine that never needed
/// to grow past the fixed `.bss` array.
pub fn spill_stats() -> (usize, usize) {
    let mut n = 0;
    let mut bytes = 0;
    for slot in SPILL.iter() {
        if slot.0.load(Ordering::Acquire) != 0 {
            n += 1;
            bytes += slot.1.load(Ordering::Acquire);
        }
    }
    (n, bytes)
}

/// Backwards-compat alias. The constant is now BOOTSTRAP_CAPACITY,
/// but external diagnostics may still reference HEAP_CAPACITY.
pub const HEAP_CAPACITY: usize = BOOTSTRAP_CAPACITY;

#[cfg(test)]
mod tests {
    use super::{background_reclaim_target, BACKGROUND_RECLAIM_MAX_PAGES};

    #[test]
    fn background_reclaim_target_is_nonzero_and_strictly_bounded() {
        assert_eq!(background_reclaim_target(0), 1);
        assert_eq!(background_reclaim_target(1), 1);
        assert_eq!(background_reclaim_target(4096), 1);
        assert_eq!(background_reclaim_target(4097), 2);
        assert_eq!(
            background_reclaim_target(usize::MAX),
            BACKGROUND_RECLAIM_MAX_PAGES
        );
    }
}

/// In-kernel regression coverage for the global-allocation failure path. The
/// test backend always fails; the scoped shrinker proves failure publishes work
/// without invoking reclaim inline, and the call count proves there is no
/// hidden backend retry.
mod allocation_failure_tests {
    use core::alloc::Layout;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::alloc_once_or_request;
    use crate::heap_backend::HeapBackend;
    use crate::reclaim::{
        __register_shrinker_first_for_test, __unregister_shrinker_for_test, take_reclaim_request,
        Shrinker,
    };

    const NODE: usize = crate::frame::MAX_NUMA_NODES - 1;
    const SHRINKER_NAME: &str = "heap-no-inline-reclaim-test";
    static BACKEND_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SHRINKER_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct FailingBackend;

    impl HeapBackend for FailingBackend {
        fn name(&self) -> &'static str {
            "failing-test"
        }

        unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
            BACKEND_CALLS.fetch_add(1, Ordering::Relaxed);
            core::ptr::null_mut()
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }

    static FAILING_BACKEND: FailingBackend = FailingBackend;

    fn shrinker_count() -> usize {
        1
    }

    fn shrinker_scan(_pages: usize) -> usize {
        SHRINKER_CALLS.fetch_add(1, Ordering::Relaxed);
        0
    }

    fn smoke_global_alloc_failure_has_no_inline_reclaim_or_retry() -> TestResult {
        let _ = take_reclaim_request(NODE);
        BACKEND_CALLS.store(0, Ordering::Relaxed);
        SHRINKER_CALLS.store(0, Ordering::Relaxed);
        if !__register_shrinker_first_for_test(Shrinker {
            name: SHRINKER_NAME,
            count: shrinker_count,
            scan: shrinker_scan,
        }) {
            return TestResult::Fail("test shrinker registry was full");
        }

        let layout = Layout::from_size_align(4097, 8).expect("valid test layout");
        // SAFETY: `layout` is valid and the mock backend always returns null.
        let ptr = unsafe { alloc_once_or_request(&FAILING_BACKEND, layout, NODE) };
        let backend_calls = BACKEND_CALLS.load(Ordering::Relaxed);
        let shrinker_calls = SHRINKER_CALLS.load(Ordering::Relaxed);
        let request = take_reclaim_request(NODE);
        let _ = __unregister_shrinker_for_test(SHRINKER_NAME);

        if !ptr.is_null() {
            return TestResult::Fail("failing backend unexpectedly allocated");
        }
        if backend_calls != 1 {
            return TestResult::Fail("global allocator retried its backend");
        }
        if shrinker_calls != 0 {
            return TestResult::Fail("global allocator invoked a shrinker inline");
        }
        if request != 2 {
            return TestResult::Fail("global allocator published the wrong reclaim target");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "memory/heap",
        smoke_global_alloc_failure_has_no_inline_reclaim_or_retry
    );
}
