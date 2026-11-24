//! The module heap: `alloc` over `narf_kmalloc` / `narf_kfree`.
//!
//! The kernel heap does not record a block's layout, which is exactly the
//! contract `GlobalAlloc` already gives: `dealloc` receives the layout the
//! block was allocated with. `narf_kmalloc` serves the calling domain's
//! tagged heap where one exists, so module allocations carry the module's
//! domain the way its image does.
//!
//! The allocator is installed only for the kernel target. A module image is
//! the sole consumer on that target; linking this crate into the kernel
//! itself would be a second `#[global_allocator]`, which is a link error —
//! the loud failure that mistake deserves.

use core::alloc::{GlobalAlloc, Layout};

use crate::abi;

/// `GlobalAlloc` over the kernel heap.
#[derive(Debug)]
pub struct KernelHeap;

// SAFETY: `narf_kmalloc` returns null or a block valid for `layout`;
// `narf_kfree` is given back that block with the same layout, which is the
// kernel heap's whole contract.
unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: plain KABI call; an invalid layout returns null.
        unsafe { abi::narf_kmalloc(layout.size(), layout.align()) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `GlobalAlloc` callers pass back a block from `alloc` above
        // together with the layout it was allocated with.
        unsafe { abi::narf_kfree(ptr, layout.size(), layout.align()) }
    }
}

#[cfg(all(target_os = "none", not(test)))]
#[global_allocator]
static HEAP: KernelHeap = KernelHeap;
