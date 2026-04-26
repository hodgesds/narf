//! Stage-1 bump allocator backing `#[global_allocator]`.
//!
//! This is explicitly NOT the Stage-2 allocator described in `memory/`
//! §3. It's a tiny linear arena over a compile-time-sized `static`
//! buffer, there purely so we can use `alloc::{boxed, vec}` in the
//! scheduler / time subsystems before the buddy allocator lands.
//!
//! Free is a no-op: bump allocators don't reclaim. Sizing is tuned so
//! Stage 1 never exhausts it — if it does, `alloc_error_handler` fires
//! and the kernel halts with a visible error.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Heap capacity. The Stage-1 bump allocator never reclaims, so the
/// total budget is the sum of every allocation made for the lifetime
/// of the kernel — including every smoke test's mounts / fd tables /
/// MemFs files in a single QEMU boot. 1 MiB was the original Stage-1
/// floor and was tight by the time Tier-3 VFS work landed
/// (185+ tests, each retaining state in the global registry +
/// per-task tables). 4 MiB gives enough headroom for the current
/// suite plus a few rounds of growth before the Wave-2 buddy+slab
/// replacement (per `memory/` spec) makes the question moot.
pub const HEAP_CAPACITY: usize = 4 << 20;

/// Byte storage for the bump arena. Lives in `.bss`; aligned to 16 so
/// any alignment ≤ 16 alloc request is trivially satisfiable.
#[repr(C, align(16))]
struct HeapBacking(UnsafeCell<[u8; HEAP_CAPACITY]>);
unsafe impl Sync for HeapBacking {}

static HEAP: HeapBacking = HeapBacking(UnsafeCell::new([0; HEAP_CAPACITY]));
static OFFSET: AtomicUsize = AtomicUsize::new(0);

/// The global-allocator adapter.
pub struct BumpAllocator;

impl core::fmt::Debug for BumpAllocator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BumpAllocator")
            .field("used", &OFFSET.load(Ordering::Relaxed))
            .field("capacity", &HEAP_CAPACITY)
            .finish()
    }
}

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(1);
        let size  = layout.size();

        // Lock-free bump: CAS on a `(offset)` atomic. Align up, add size,
        // reject if we'd overrun the arena.
        loop {
            let cur = OFFSET.load(Ordering::Relaxed);
            let aligned = (cur + align - 1) & !(align - 1);
            let end = match aligned.checked_add(size) {
                Some(e) if e <= HEAP_CAPACITY => e,
                _ => return core::ptr::null_mut(),
            };
            if OFFSET
                .compare_exchange_weak(cur, end, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // SAFETY: `aligned..end` lies entirely inside HEAP.0.
                let base = HEAP.0.get() as *mut u8;
                return unsafe { base.add(aligned) };
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump: never reclaim. Stage 2's slab owns this responsibility.
    }
}

/// Snapshot of arena usage for diagnostics.
pub fn used_bytes() -> usize { OFFSET.load(Ordering::Relaxed) }

/// Total capacity.
pub const fn capacity_bytes() -> usize { HEAP_CAPACITY }
