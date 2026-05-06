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
pub mod address_space;
pub mod asid_alloc;
pub mod frame;
pub mod heap;
pub mod per_domain_root;
pub mod slab;
pub mod tlb_shootdown;
pub mod vmalloc;

mod tests;

pub use address_space::{AddressSpace, AddressSpaceError, Region, RegionPerms};

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::{domain, ioremap, mmu, paging};

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::{ioremap, mmu, paging};

pub use addr::{PhysAddr, VirtAddr};
pub use frame::{
    alloc_frame, alloc_frame_anywhere, alloc_frame_on, free_frame, init_from_map, is_numa_aware,
    node_free, rebalance_to_topology, stats as frame_stats, FrameAllocError, FrameStats, PhysFrame,
    UsableRegion, MAX_NUMA_NODES as FRAME_MAX_NUMA_NODES, PAGE_SHIFT, PAGE_SIZE,
};
pub use heap::BumpAllocator;
