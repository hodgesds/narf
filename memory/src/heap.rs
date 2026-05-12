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
//! See `memory/specification/heap-migration.md` for the full plan.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::slab;

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
pub const BOOTSTRAP_CAPACITY: usize = 16 << 20;

/// Byte storage for the bootstrap bump arena. Lives in `.bss`,
/// 16-byte aligned for any alignment ≤ 16 to be trivially satisfiable.
#[repr(C, align(16))]
struct HeapBacking(UnsafeCell<[u8; BOOTSTRAP_CAPACITY]>);
unsafe impl Sync for HeapBacking {}

static HEAP: HeapBacking = HeapBacking(UnsafeCell::new([0; BOOTSTRAP_CAPACITY]));
static OFFSET: AtomicUsize = AtomicUsize::new(0);

/// True once the slab is initialized and ready to serve allocations.
/// Flipped by `promote_to_slab()` after `init_from_map`.
static SLAB_LIVE: AtomicBool = AtomicBool::new(false);

/// Promote the global allocator from bootstrap-bump to slab. Call
/// exactly once, after `init_from_map` has populated the buddy.
/// Allocations made before this point stay in the bootstrap arena
/// (and stay leaked, per bump semantics); allocations after route
/// to the slab.
pub fn promote_to_slab() {
    SLAB_LIVE.store(true, Ordering::Release);
}

/// The hybrid global allocator. Pre-promotion: bump arena.
/// Post-promotion: slab routes to size-class central + per-CPU
/// magazines.
pub struct BumpAllocator;

impl core::fmt::Debug for BumpAllocator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BumpAllocator")
            .field("bootstrap_used", &OFFSET.load(Ordering::Relaxed))
            .field("bootstrap_capacity", &BOOTSTRAP_CAPACITY)
            .field("slab_live", &SLAB_LIVE.load(Ordering::Relaxed))
            .finish()
    }
}

/// Returns true iff `ptr` lies inside the bootstrap arena's bytes.
/// Used by `dealloc` to route freeing to the right path.
fn in_bootstrap(ptr: *mut u8) -> bool {
    let base = HEAP.0.get() as *mut u8 as usize;
    let end = base + BOOTSTRAP_CAPACITY;
    let p = ptr as usize;
    p >= base && p < end
}

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Slab path — only available post-promotion.
        if SLAB_LIVE.load(Ordering::Acquire) {
            match slab::alloc(layout) {
                Ok(p) => return p.as_ptr(),
                Err(_) => return core::ptr::null_mut(),
            }
        }
        // Bootstrap bump fast path.
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

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Pointers from the bootstrap arena can't be freed (bump
        // doesn't track sizes per slot). Skipping is correct —
        // those bytes stay leaked, but the arena is small + bounded.
        if in_bootstrap(ptr) {
            return;
        }
        // SAFETY: caller asserts the pointer/layout pair came from
        // a prior `alloc` call. By construction, anything not in the
        // bootstrap arena came from the slab.
        if let Some(nn) = core::ptr::NonNull::new(ptr) {
            unsafe {
                slab::dealloc(nn, layout);
            }
        }
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
