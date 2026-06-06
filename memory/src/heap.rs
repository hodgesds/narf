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

use crate::heap_backend::{self, current_backend, install_default_if_unset, SLAB_BACKEND};

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

/// Returns true iff `ptr` lies inside the bootstrap arena's bytes.
/// Used by `dealloc` to route freeing to the right path —
/// stranded bump-era pointers survive the bump→slab promotion and
/// must NOT be handed to `slab::dealloc`.
pub(crate) fn in_bootstrap(ptr: *mut u8) -> bool {
    let base = HEAP.0.get() as *mut u8 as usize;
    let end = base + BOOTSTRAP_CAPACITY;
    let p = ptr as usize;
    p >= base && p < end
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
            _ => return core::ptr::null_mut(),
        };
        if OFFSET
            .compare_exchange_weak(cur, end, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            // SAFETY: `aligned..end` lies inside HEAP.0.
            let base = HEAP.0.get() as *mut u8;
            return unsafe { base.add(aligned) };
        }
    }
}

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
        // SAFETY: caller upholds `GlobalAlloc::alloc` contract,
        // which is the same contract `HeapBackend::alloc`
        // forwards.
        unsafe { backend.alloc(layout) }
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

/// Backwards-compat alias. The constant is now BOOTSTRAP_CAPACITY,
/// but external diagnostics may still reference HEAP_CAPACITY.
pub const HEAP_CAPACITY: usize = BOOTSTRAP_CAPACITY;
