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
pub mod beacon;
pub mod atomic_pool;
pub mod buddy;
pub mod compress;
pub mod compressed_ramdisk;
pub mod asid_alloc;
pub mod context;
pub mod frame;
pub mod heap;
pub mod hugepage;
pub mod kaslr;
pub mod per_domain_root;
pub mod reclaim;
pub mod ro_after_init;
pub mod slab;
pub mod zpool;
pub mod spd5;
pub mod tlb_shootdown;
pub mod vmalloc;
pub mod wx;

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

/// Per-arch offset that maps a physical RAM address to its
/// **kernel** virtual address. The kernel uses this to access
/// page-table memory + DMA buffers + the COW memcpy path through
/// the kernel's TTBR1 / high-half mapping, so accesses stay
/// valid across user-task TTBR0 swaps.
///
/// - x86_64: `0` — the kernel runs with a low-4-GiB identity map
///   in CR3 and every per-domain PML4 clones it; phys IS the
///   kernel virt for low RAM.
/// - aarch64: `0xFFFF_FF80_0000_0000` — matches `KERNEL_VIRT_BASE`
///   from `build/linker/aarch64.ld` and the TTBR1 high-half RAM
///   mapping that `boot.S` installs at L0[511]/L1[1].
#[cfg(target_arch = "x86_64")]
pub const KERNEL_PHYS_OFFSET: u64 = 0;
#[cfg(target_arch = "aarch64")]
pub const KERNEL_PHYS_OFFSET: u64 = 0xFFFF_FF80_0000_0000;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const KERNEL_PHYS_OFFSET: u64 = 0;
pub use frame::{
    alloc_frame, alloc_frame_anywhere, alloc_frame_on, free_frame, init_from_map, is_numa_aware,
    node_free, rebalance_to_topology, release_early_ceiling, reserve_for_slab_promotion,
    stats as frame_stats, validate_no_overlap as frame_validate_no_overlap, FrameAllocError,
    FrameStats, PhysFrame, UsableRegion, MAX_NUMA_NODES as FRAME_MAX_NUMA_NODES, PAGE_SHIFT,
    PAGE_SIZE,
};
pub use heap::BumpAllocator;
