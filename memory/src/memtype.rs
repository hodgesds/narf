//! User-mapping memory types (Linux `pgprot_writecombine` & co.) and the
//! rule that keeps them from aliasing RAM.
//!
//! Spec: `memory/specification/spec.md` §3 ("Memory types") and §4.
//!
//! A user leaf's memory type is chosen per mapping, like Linux's
//! `vma->vm_page_prot`: a driver's mmap backing asks for a [`MemoryType`]
//! and the address space records it in the region's [`RegionPerms`]. The
//! request is honoured only where it cannot create a conflicting alias:
//!
//! * **Only special mappings may ask.** A non-write-back type is accepted
//!   only on a `SHARED | LOCK_EXEMPT` region (Linux `VM_IO`/`VM_PFNMAP`
//!   territory: externally owned frames, never COW, never swapped, never
//!   migrated) that does not declare `PINNABLE_RAM`. Anything else maps
//!   write-back, so anonymous, file, COW, swap-in and huge-page leaves are
//!   unaffected.
//! * **Never on System RAM.** Every RAM page is mapped write-back by the
//!   kernel direct map, and NARF never changes that (it has no
//!   `set_memory_wc`). A write-combining or uncached user alias of such a
//!   page is an architectural mixed-attribute alias: a cached line filled
//!   through the direct map can be written back over data the user wrote
//!   around the cache, or the user can read stale DRAM under a dirty line.
//!   Linux refuses the alias the same way: for a RAM pfn,
//!   `reserve_pfn_range` and `track_pfn_insert` (`arch/x86/mm/pat/memtype.c`)
//!   replace the requested cache bits with the page's own memtype, which is
//!   write-back unless `set_memory_*` changed the direct map. NARF does
//!   exactly that per leaf: a RAM frame in a write-combining region gets a
//!   write-back leaf, and [`ram_alias_refusals`] counts it (Linux prints
//!   "x86/PAT: ... map pfn RAM range req ..., got write-back").
//!
//! RAM is [`crate::frame::is_system_ram`], Linux's `pat_pagerange_is_ram`.
//! Every decision is per leaf and recomputed from the backing frame each
//! time a leaf is built, so a device object relocated between VRAM and
//! system memory changes leaf type with its frames.
//!
//! The default is [`MemoryType::WriteBack`], encoded as zero bits on both
//! architectures, so every mapping that does not ask is bit-identical to
//! the encoding before memory types existed.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::address_space::RegionPerms;
use crate::PhysAddr;

/// Memory type of a user mapping. Mirrors the Linux `pgprot_*` helpers a
/// driver's `mmap` applies to `vm_page_prot`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum MemoryType {
    /// Normal cacheable memory — the default `vm_page_prot`.
    /// x86_64: PAT slot 0 (WB). aarch64: `MT_NORMAL`.
    #[default]
    WriteBack = 0,
    /// `pgprot_writecombine`. x86_64: PAT slot 1 (WC). aarch64:
    /// `MT_NORMAL_NC`, with UXN|PXN forced as Linux arm64 does.
    WriteCombining = 1,
    /// `pgprot_noncached`. x86_64: UC- (PCD, PAT slot 2), which an MTRR may
    /// still make WC. aarch64: `MT_DEVICE_nGnRnE`, UXN|PXN forced.
    Uncached = 2,
    /// `pgprot_writethrough`. x86_64: PAT slot 7 (WT) — the only type that
    /// needs the PAT bit (7 in a 4 KiB PTE, 12 in a large leaf). aarch64 has
    /// no write-through user type and, like Linux's generic fallback
    /// (`#define pgprot_writethrough pgprot_noncached`), maps it as
    /// `MT_DEVICE_nGnRnE`.
    WriteThrough = 3,
}

impl MemoryType {
    pub const ALL: [MemoryType; 4] = [
        MemoryType::WriteBack,
        MemoryType::WriteCombining,
        MemoryType::Uncached,
        MemoryType::WriteThrough,
    ];

    #[inline]
    const fn from_bits(bits: u32) -> MemoryType {
        match bits {
            1 => MemoryType::WriteCombining,
            2 => MemoryType::Uncached,
            3 => MemoryType::WriteThrough,
            // 0, and the never-written values 4..=7.
            _ => MemoryType::WriteBack,
        }
    }

    /// The x86_64 PAT cache mode this type selects.
    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub const fn cache_mode(self) -> narf_arch::x86_64::pat::CacheMode {
        use narf_arch::x86_64::pat::CacheMode;
        match self {
            MemoryType::WriteBack => CacheMode::Wb,
            MemoryType::WriteCombining => CacheMode::Wc,
            MemoryType::Uncached => CacheMode::UcMinus,
            MemoryType::WriteThrough => CacheMode::Wt,
        }
    }
}

/// Bit position of the memory-type field inside [`RegionPerms`].
pub(crate) const REGION_MEMTYPE_SHIFT: u32 = 24;
/// The 3-bit memory-type field inside [`RegionPerms`] (bits 24..=26).
/// Outside `PROT_MASK`, so `mprotect`, VMA splits, `mremap` and fork carry
/// it like every other internal flag.
pub(crate) const REGION_MEMTYPE_MASK: u32 = 0b111 << REGION_MEMTYPE_SHIFT;

impl RegionPerms {
    /// The memory type this region requested (Linux `vm_page_prot` cache
    /// bits). [`MemoryType::WriteBack`] unless set with
    /// [`with_memory_type`](Self::with_memory_type).
    #[inline]
    pub const fn memory_type(self) -> MemoryType {
        MemoryType::from_bits((self.0 & REGION_MEMTYPE_MASK) >> REGION_MEMTYPE_SHIFT)
    }

    /// These permissions requesting `memory_type` for every leaf. Whether
    /// a leaf gets it is decided per frame by [`effective_memory_type`].
    #[inline]
    pub const fn with_memory_type(self, memory_type: MemoryType) -> RegionPerms {
        RegionPerms(
            (self.0 & !REGION_MEMTYPE_MASK) | ((memory_type as u32) << REGION_MEMTYPE_SHIFT),
        )
    }
}

static RAM_ALIAS_REFUSALS: AtomicU64 = AtomicU64::new(0);

/// How many leaves were built write-back although their region asked for
/// another type, because the frame was System RAM. Linux's equivalent is
/// the `x86/PAT: ... map pfn RAM range req ...` warning.
pub fn ram_alias_refusals() -> u64 {
    RAM_ALIAS_REFUSALS.load(Ordering::Relaxed)
}

/// Whether a region with these permissions may carry a non-write-back
/// memory type at all: an externally owned special mapping that is not
/// declared allocator RAM and is never copy-on-write.
#[inline]
pub const fn region_may_request(perms: RegionPerms) -> bool {
    perms.contains(RegionPerms(
        RegionPerms::SHARED.0 | RegionPerms::LOCK_EXEMPT.0,
    )) && !perms.contains(RegionPerms::COW)
        && !perms.contains(RegionPerms::PINNABLE_RAM)
}

/// The memory type the leaf mapping `phys` under `perms` must use.
///
/// Write-back unless the region asked otherwise, may ask
/// ([`region_may_request`]), and `phys` is a real frame outside System
/// RAM. A request refused because `phys` is RAM increments
/// [`ram_alias_refusals`].
#[inline]
pub fn effective_memory_type(perms: RegionPerms, phys: PhysAddr) -> MemoryType {
    let requested = perms.memory_type();
    if requested == MemoryType::WriteBack || !region_may_request(perms) || phys.raw() == 0 {
        return MemoryType::WriteBack;
    }
    if crate::frame::is_system_ram(phys) {
        RAM_ALIAS_REFUSALS.fetch_add(1, Ordering::Relaxed);
        return MemoryType::WriteBack;
    }
    requested
}

/// x86_64 4 KiB-leaf bits for `memory_type` under the programmed PAT
/// (Linux `cachemode2protval`). Zero for write-back.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn x86_leaf_bits_4k(memory_type: MemoryType) -> crate::x86_64::paging::PtFlags {
    if memory_type == MemoryType::WriteBack {
        return crate::x86_64::paging::PtFlags::EMPTY;
    }
    crate::x86_64::paging::PtFlags::from_bits(narf_arch::x86_64::pat::cachemode2pte(
        memory_type.cache_mode(),
    ))
}

/// aarch64 descriptor bits for `memory_type`: the `AttrIndx` value, plus
/// UXN|PXN for every non-Normal-cacheable type exactly as Linux arm64's
/// `pgprot_writecombine` / `pgprot_noncached` force them. Zero for
/// write-back. Never `ATTR_TAGGED`: MTE tag checks apply only to Normal
/// Tagged memory, and Linux likewise refuses `PROT_MTE` on anything but
/// RAM-backed anonymous / shmem mappings (`arch_validate_flags`).
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn aarch64_leaf_bits(memory_type: MemoryType) -> crate::aarch64::paging::PtFlags {
    use crate::aarch64::paging::PtFlags;
    match memory_type {
        MemoryType::WriteBack => PtFlags::EMPTY,
        MemoryType::WriteCombining => PtFlags::ATTR_NORMAL_NC | PtFlags::UXN | PtFlags::PXN,
        MemoryType::Uncached | MemoryType::WriteThrough => {
            PtFlags::ATTR_DEVICE_NGNRNE | PtFlags::UXN | PtFlags::PXN
        }
    }
}

/// Leaf flags for re-pointing an existing user leaf at `phys`, keeping
/// every attribute of `old` except the memory-type selection, which is
/// recomputed for the new frame. Shared-frame relocation uses this so a leaf
/// that was write-combining over a device page becomes write-back when its
/// object moves onto System RAM (and back), rather than carrying the old
/// frame's type onto the new one.
#[cfg(target_arch = "x86_64")]
pub(crate) fn rebind_leaf_flags(
    old: crate::x86_64::paging::PtFlags,
    perms: RegionPerms,
    phys: PhysAddr,
) -> crate::x86_64::paging::PtFlags {
    use crate::x86_64::paging::PtFlags;
    old.without(PtFlags::CACHE_MASK_4K) | x86_leaf_bits_4k(effective_memory_type(perms, phys))
}

/// aarch64 form of `rebind_leaf_flags`: `AttrIndx` and the execute-never
/// bits are recomputed exactly as `user_leaf_flags` derives them (XN when
/// the region is not executable or the type is not Normal cacheable).
#[cfg(target_arch = "aarch64")]
pub(crate) fn rebind_leaf_flags(
    old: crate::aarch64::paging::PtFlags,
    perms: RegionPerms,
    phys: PhysAddr,
) -> crate::aarch64::paging::PtFlags {
    use crate::aarch64::paging::PtFlags;
    let xn = PtFlags::UXN | PtFlags::PXN;
    let mut flags = old.without(PtFlags::ATTR_MASK | xn);
    if !perms.contains(RegionPerms::EXEC) {
        flags = flags | xn;
    }
    flags | aarch64_leaf_bits(effective_memory_type(perms, phys))
}
