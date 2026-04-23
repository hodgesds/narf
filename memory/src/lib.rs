//! narf-memory — physical/virtual addresses + allocators + MMU.
//!
//! Spec: `memory/specification/spec.md`. Wave-1 scope: just the `PhysAddr`
//! and `VirtAddr` newtypes that other crates need to talk about memory.
//! Buddy frame allocator, page tables, folios, slab magazines — Wave 2.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod addr;
pub mod frame;
pub mod heap;

#[cfg(target_arch = "x86_64")]
pub mod mmu;
#[cfg(target_arch = "x86_64")]
pub mod paging;

pub use addr::{PhysAddr, VirtAddr};
pub use frame::{
    alloc_frame, free_frame, init_from_map, stats as frame_stats,
    FrameAllocError, FrameStats, PhysFrame, UsableRegion, PAGE_SHIFT, PAGE_SIZE,
};
pub use heap::BumpAllocator;
