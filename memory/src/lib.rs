//! narf-memory — physical/virtual addresses + allocators + MMU.
//!
//! Spec: `memory/specification/spec.md`. Wave-1 scope: just the `PhysAddr`
//! and `VirtAddr` newtypes that other crates need to talk about memory.
//! Buddy frame allocator, page tables, folios, slab magazines — Wave 2.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
// KASAN callbacks + the slab (whose intrusive free-list/canary writes land in
// freed blocks) opt OUT of instrumentation via `#[sanitize(address = "off")]`.
#![cfg_attr(feature = "kasan", feature(sanitize))]

extern crate alloc;

pub mod addr;
pub mod address_space;
pub mod asid_alloc;
pub mod atomic_pool;
// BPF memory: the executable-text allocator, the program heap, the recoverable
// -fault table, and the per-CPU BPF stack. `bpf_text::reserve_kernel_slots` is
// boot-order critical — see `bpf/specification/spec.md` §4.1.
pub mod bpf_arena;
pub mod bpf_extable;
pub mod bpf_stack;
pub mod bpf_text;
pub mod buddy;
#[cfg(feature = "cgroup")]
pub mod cgroup_charge;
pub mod compress;
pub mod compressed_ramdisk;
pub mod context;
pub mod diag;
pub mod frame;
pub mod heap;
pub mod heap_backend;
pub mod hugepage;
#[cfg(feature = "kasan")]
pub mod kasan;
pub mod kaslr;
pub mod mempolicy;
pub mod numa_tier;
pub mod oom;
pub mod pager;
pub mod per_domain_root;
pub mod reclaim;
pub mod rmap;
pub mod ro_after_init;
// The slab writes intrusive free-list links + per-block canaries INTO freed
// blocks; under KASAN those blocks are poisoned, so the slab's own accesses
// must not self-report. Exempt the whole module (the corruptor we hunt lives
// in the scheduler, not here).
#[cfg_attr(feature = "kasan", sanitize(address = "off"))]
pub mod slab;
pub mod spd5;
pub mod swap;
pub mod text_poke;
pub mod tlb_shootdown;
pub mod vmalloc;
pub mod wx;
pub mod zpool;

mod tests;

pub use address_space::{
    install_file_fault_hook, install_shared_frame_hooks, with_shared_mapping_transaction,
    AddressSpace, AddressSpaceError, HugeRegion, NumaRegionSnapshot, Region, RegionPerms,
};

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::{domain, ioremap, mmu, paging};

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::{ioremap, mmu, paging};

#[cfg(target_arch = "x86_64")]
pub use addr::{
    direct_map_activate, direct_map_live, KERNEL_DIRECT_MAP_BASE, KERNEL_DIRECT_MAP_PML4_BASE,
    KERNEL_DIRECT_MAP_PML4_SLOTS,
};
pub use addr::{PhysAddr, VirtAddr};

#[cfg(feature = "cgroup")]
pub use cgroup_charge::{
    __charge_pid_for_test, install_cgroup_charge_hook, install_cgroup_pid_provider,
};

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
pub use frame::alloc_frame_on_strict;
pub use frame::{
    alloc_frame, alloc_frame_anywhere, alloc_frame_on, alloc_pages_on, current_frame_alloc_name,
    free_frame, free_pages, hotplug_node_for_phys, init_from_map, install_frame_alloc,
    install_memory_hotplug_hook, is_numa_aware, memory_blocks, node_for_phys, node_free,
    node_free_blocks, node_total, numa_node_stats, offline_memory_range, online_memory_range,
    online_node_count, online_node_mask, rebalance_to_topology, release_early_ceiling,
    reserve_for_slab_promotion, stats as frame_stats,
    validate_no_overlap as frame_validate_no_overlap, BuddyFrameAlloc, BumpFrameAlloc, FrameAlloc,
    FrameAllocError, FrameStats, MemAlloc, MemoryBlock, MemoryHotplugError, NumaNodeStats,
    PhysFrame, UsableRegion, BUDDY_FRAME_ALLOC, BUDDY_ORDER_COUNT,
    MAX_NUMA_NODES as FRAME_MAX_NUMA_NODES, MEMORY_BLOCK_SIZE, PAGE_SHIFT, PAGE_SIZE,
};

/// Whether the complete physical range is reachable through the kernel's
/// canonical RAM accessor.
///
/// Hotplug drivers must check this before donating frames: allocator clients
/// dereference [`PhysAddr::kernel_mut_ptr`], so accepting RAM outside the
/// active linear map would turn a later allocation into a kernel fault.
pub fn kernel_ram_range_mapped(start: PhysAddr, len: u64) -> bool {
    if len == 0 {
        return false;
    }
    let Some(last) = start.raw().checked_add(len - 1) else {
        return false;
    };

    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: CR3 is readable in ring 0 and names the active kernel root.
        let root = unsafe { x86_64::paging::read_cr3() };
        for phys in [start.raw(), last] {
            let addr = PhysAddr::new(phys);
            let virt = VirtAddr::new(addr.kernel_ptr::<u8>() as u64);
            // SAFETY: `root` is the active, valid page-table root.
            if unsafe { x86_64::paging::translate(root, virt) }.map(PhysAddr::raw) != Some(phys) {
                return false;
            }
        }
        true
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: TTBR1_EL1 is readable at EL1 and names the active kernel
        // translation tree.
        let root = unsafe { aarch64::paging::read_ttbr1_el1() };
        for phys in [start.raw(), last] {
            let addr = PhysAddr::new(phys);
            let virt = VirtAddr::new(addr.kernel_ptr::<u8>() as u64);
            // SAFETY: `root` is the active, valid kernel translation root.
            if unsafe { aarch64::paging::translate(root, virt) }.map(PhysAddr::raw) != Some(phys) {
                return false;
            }
        }
        true
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = last;
        false
    }
}
pub use heap::BumpAllocator;
pub use heap::{bootstrap_remaining, spill_stats as heap_spill_stats};
pub use heap_backend::{
    current_heap_backend_name, install_heap_backend, BumpBackend, HeapAuthority, HeapBackend,
    HeapError, SlabBackend, BUMP_BACKEND, SLAB_BACKEND,
};
pub use mempolicy::{
    active as mempolicy_active, alloc_frame_policied, clear_active as mempolicy_clear,
    interleave_auto, interleave_node_at, interleave_weight, set_active as mempolicy_set,
    set_interleave_auto, set_interleave_bandwidth, set_interleave_weight, Mempolicy, MPOL_BIND,
    MPOL_DEFAULT, MPOL_INTERLEAVE, MPOL_LOCAL, MPOL_PREFERRED, MPOL_PREFERRED_MANY,
    MPOL_WEIGHTED_INTERLEAVE,
};
pub use numa_tier::{demotion_target, node_tier, set_node_performance, tier_nodes};
pub use pager::{
    current_pager_name, install_pager, NoopPager, Pager, PagerAuthority, PagerError, SwapSlot,
    ZpoolPager,
};
pub use swap::{
    backend_name as swap_backend_name, install_backend as install_swap_backend,
    set_swap_batch_pages, swap_batch_pages, swap_discard, swap_discard_batch, swap_stats,
    SwapBackend, SwapError, SwapPte, SwapStats, ZramBackend, SWAP_BATCH_PAGES_DEFAULT,
    SWAP_BATCH_PAGES_MAX,
};
#[cfg(target_arch = "x86_64")]
pub use swap::{
    swap_in_batch, swap_in_pte, swap_out_batch, swap_out_plan, SwapBatchReport, SwapInRequest,
    SwapVictim,
};
