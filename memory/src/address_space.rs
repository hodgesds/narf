//! Per-process address space.
//!
//! Spec: `memory/specification/spec.md` (Stage-4 — user-mode address
//! spaces). A kernel thread always runs in the shared high-half
//! address space; a user process needs its own page table so
//! user-mode mappings in the low half don't collide across
//! processes.
//!
//! This module pins the `AddressSpace` shape + a region table + the
//! entry points the Stage-4 ELF loader calls (`map_region`,
//! `activate`, `unmap_region`). The per-arch primitives
//! (`arch::x86_64::paging::new_pml4_from_kernel`,
//! `arch::aarch64::paging::new_ttbr0`) don't yet exist — the stubs
//! return `Err(AddressSpaceError::NotImplemented)` until they do,
//! but the shape is stable enough that Stage-4 loader code can
//! compile and test against it.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

/// Serializes creation and replacement of externally-owned shared aliases.
/// The closure must not await or enter code that can recursively map SHARED
/// memory.
static SHARED_MAPPING_TRANSACTION: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());
type SharedFrameHooks = (fn(u64), fn(u64));
static SHARED_FRAME_HOOKS: IrqSafeSpinLock<Option<SharedFrameHooks>> = IrqSafeSpinLock::new(None);

#[cfg(feature = "kernel-test")]
static PRIVATE_UNMAP_FAST_PATHS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "kernel-test")]
static SHARED_UNMAP_TRANSACTIONS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "kernel-test")]
pub(crate) fn __test_unmap_path_counts() -> (usize, usize) {
    use core::sync::atomic::Ordering;

    (
        PRIVATE_UNMAP_FAST_PATHS.load(Ordering::Relaxed),
        SHARED_UNMAP_TRANSACTIONS.load(Ordering::Relaxed),
    )
}

#[inline]
fn record_unmap_path(shared: bool) {
    #[cfg(feature = "kernel-test")]
    {
        use core::sync::atomic::Ordering;

        if shared {
            SHARED_UNMAP_TRANSACTIONS.fetch_add(1, Ordering::Relaxed);
        } else {
            PRIVATE_UNMAP_FAST_PATHS.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[cfg(not(feature = "kernel-test"))]
    let _ = shared;
}

pub fn install_shared_frame_hooks(retain: fn(u64), release: fn(u64)) {
    *SHARED_FRAME_HOOKS.lock() = Some((retain, release));
}

fn retain_shared_frames(region: &Region) {
    if let Some((retain, _)) = *SHARED_FRAME_HOOKS.lock() {
        for phys in region.phys.iter().filter(|phys| phys.raw() != 0) {
            retain(phys.raw());
        }
    }
}

fn release_shared_phys(phys: PhysAddr) {
    if phys.raw() != 0 {
        if let Some((_, release)) = *SHARED_FRAME_HOOKS.lock() {
            release(phys.raw());
        }
    }
}

pub fn with_shared_mapping_transaction<R>(f: impl FnOnce() -> R) -> R {
    let _guard = SHARED_MAPPING_TRANSACTION.lock();
    f()
}

/// Resolves a fault on an unbacked page of a `RegionPerms::FILE_DEMAND`
/// mapping to the frame the backing file wants there. Takes the faulting
/// (page-aligned) user VA, returns a page-aligned physical address.
///
/// A `fn` pointer rather than a filesystem dependency: `narf-memory` sits
/// below `narf-filesystem`, and the region table deliberately holds frames
/// and no file objects (see `userspace/src/mapped_file.rs`). This is the same
/// seam shape as [`install_shared_frame_hooks`] and `install_pager`.
type FileFaultHook = fn(u64) -> Option<u64>;
static FILE_FAULT_HOOK: IrqSafeSpinLock<Option<FileFaultHook>> = IrqSafeSpinLock::new(None);

/// Install the demand-paging callback for `RegionPerms::FILE_DEMAND` regions,
/// returning whatever it displaced.
///
/// Idempotent, and callable at any time: a `FILE_DEMAND` region cannot exist
/// before the syscall layer creates one, and the syscall layer installs this
/// on the same path. There is therefore no boot-order requirement — unlike
/// `bpf_text::reserve_kernel_slots`, whose top-level page-table entries must
/// predate the first user address space.
///
/// The displaced hook is returned so a test can chain to it rather than
/// silently blackholing a real mapping's faults for the duration.
pub fn install_file_fault_hook(hook: FileFaultHook) -> Option<FileFaultHook> {
    FILE_FAULT_HOOK.lock().replace(hook)
}

/// Ask the backing file for the frame at `vaddr`. Must be called with **no**
/// address-space lock held — the hook re-enters the filesystem, which
/// allocates, takes its own locks, and (for a BPF arena) installs a kernel
/// page-table entry.
fn file_fault_frame(vaddr: u64) -> Option<u64> {
    let hook = (*FILE_FAULT_HOOK.lock())?;
    let phys = hook(vaddr)?;
    // A zero or misaligned answer would be stored in a `phys` slot where zero
    // *means* "unbacked" and every consumer assumes page alignment, so it is
    // rejected here rather than corrupting the region table.
    (phys != 0 && phys & 0xFFF == 0).then_some(phys)
}

use crate::addr::{PhysAddr, VirtAddr};

/// Region permission flags. Mirrors ELF `PF_*` so the loader doesn't
/// need a translation step.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RegionPerms(pub u32);

impl RegionPerms {
    pub const EXEC: RegionPerms = RegionPerms(1 << 0);
    pub const WRITE: RegionPerms = RegionPerms(1 << 1);
    pub const READ: RegionPerms = RegionPerms(1 << 2);

    /// Internal flag: this region is `mlock`'d and a future swap /
    /// page-reclaim pass must leave it alone. Plain `mlock` eagerly backs
    /// every page; `mlock2(MLOCK_ONFAULT)` may leave zero entries that become
    /// resident on first access and remain pinned thereafter.
    /// Stored in `RegionPerms` rather than as a separate `Region`
    /// field so existing `Region { ... }` constructors keep
    /// compiling — the bit lives outside the POSIX prot range
    /// (READ/WRITE/EXEC = bits 0..2) so it never confuses the
    /// `materialize` flag-translation paths.
    pub const LOCKED: RegionPerms = RegionPerms(1 << 8);

    /// Internal flag: this region is a stack guard page. Carries
    /// no POSIX prot bits — `materialize` skips installing a PTE
    /// so a user-mode access faults with P=0 — but the trap path
    /// recognises the bit, allocates a fresh frame, promotes this
    /// region to R+W, and installs a *new* one-page guard region
    /// directly below. Implements POSIX-style automatic stack
    /// extension on first write to the guard page.
    /// Bit 9, separate from LOCKED (bit 8); the POSIX prot mask
    /// strips it the same way.
    pub const STACK_GUARD: RegionPerms = RegionPerms(1 << 9);

    /// Internal flag: this region's frames are *borrowed*, not owned by
    /// the address space — they belong to an external registry (e.g. the
    /// narf-shmem store backing System V `shmat`). Two regions in the
    /// same AS may legitimately alias the same borrowed frames (a second
    /// `shmat` of the same segment), so `map_region` skips its
    /// duplicate-phys guard, and neither `unmap_region_pages` nor the AS
    /// drop frees the frames (the owning registry does, on `IPC_RMID` /
    /// process-exit). Bit 10; stripped by the POSIX prot mask like the
    /// other internal flags.
    pub const SHARED: RegionPerms = RegionPerms(1 << 10);

    /// Internal flag: this region's unbacked pages are filled by the *backing
    /// file*, not by the frame allocator.
    ///
    /// A zero `phys[i]` normally means "anonymous, demand-allocate a fresh
    /// zeroed frame". In a `FILE_DEMAND` region it instead means "ask
    /// [`install_file_fault_hook`]'s callback", which is what makes a
    /// `MAP_SHARED` device mapping *track* its file rather than snapshot it:
    /// pages the file backs after `mmap` still appear. Always set together
    /// with [`SHARED`](Self::SHARED) — the frames belong to the file, so
    /// teardown must clear PTEs and free nothing. Bit 11; stripped by the
    /// POSIX prot mask like the other internal flags.
    pub const FILE_DEMAND: RegionPerms = RegionPerms(1 << 11);

    /// Internal flag: at least one resident page in this private region may
    /// still be shared with a fork sibling.  The POSIX WRITE bit remains the
    /// authoritative permission; COW only forces a hardware read-only leaf
    /// while that page's frame refcount is greater than one.  Keeping the two
    /// states separate is load-bearing: `mprotect(PROT_READ)` must not be
    /// mistaken for a recoverable COW write fault, while a later
    /// `mprotect(PROT_WRITE)` on a fork-shared page must still split first.
    /// Bit 12; stripped by the POSIX prot mask.
    pub const COW: RegionPerms = RegionPerms(1 << 12);

    /// Mask isolating the POSIX prot bits (READ | WRITE | EXEC).
    /// Used by callers that want to compare permissions without
    /// caring about the internal LOCKED bit.
    pub const PROT_MASK: RegionPerms = RegionPerms(0b111);

    #[inline]
    pub const fn contains(self, o: RegionPerms) -> bool {
        self.0 & o.0 == o.0
    }

    #[inline]
    pub const fn prot_only(self) -> RegionPerms {
        RegionPerms(self.0 & Self::PROT_MASK.0)
    }
}

impl core::ops::BitOr for RegionPerms {
    type Output = RegionPerms;
    fn bitor(self, rhs: RegionPerms) -> Self {
        RegionPerms(self.0 | rhs.0)
    }
}

/// Whether a user leaf may carry a hardware writable bit.
///
/// Normal and externally shared mappings take their authority directly from
/// the POSIX WRITE bit.  Fork-private mappings additionally remain read-only
/// while their particular backing frame has more than one COW owner.  A zero
/// backing slot is independently demand-allocated in each address space and
/// therefore needs no split.
#[inline]
fn user_page_writable(perms: RegionPerms, phys: PhysAddr) -> bool {
    let cow_count = if perms.contains(RegionPerms::COW) && phys.raw() != 0 {
        crate::frame::cow::count(phys)
    } else {
        0
    };
    user_page_writable_at_count(perms, phys, cow_count)
}

/// Batch-aware counterpart used when the caller already holds a stable COW
/// count snapshot for the region.
#[inline]
fn user_page_writable_at_count(perms: RegionPerms, phys: PhysAddr, cow_count: u32) -> bool {
    perms.contains(RegionPerms::WRITE)
        && (!perms.contains(RegionPerms::COW) || phys.raw() == 0 || cow_count <= 1)
}

/// A user-mode mapping. The virtual range is contiguous; the
/// physical backing is a per-page scatter list — `phys[i]` covers
/// the page at `base + i * 4096`. The frame allocator is a freelist
/// so consecutive `alloc_frame` calls don't return adjacent
/// physical frames in general; the earlier "single base + assume
/// contiguous" shape silently miscompiled multi-page mappings any
/// time the freelist had been touched between page allocations.
///
/// A `phys[i]` of `PhysAddr::new(0)` means "lazily allocated — the
/// frame hasn't been backed yet, allocate on first touch via the
/// page-fault demand-paging path." `mmap` may use this; `mlock`
/// walks the region and forces every zero entry to be backed.
///
/// `perms` carries the POSIX prot bits (READ/WRITE/EXEC) plus a
/// few internal flags in the high bits — see `RegionPerms::LOCKED`
/// for `mlock` state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region {
    pub base: VirtAddr,
    pub len: u64,
    pub perms: RegionPerms,
    /// Per-page phys backing. Length must equal `len / 4096`; an
    /// empty Vec is a structural error rejected by `map_region`.
    /// `PhysAddr::new(0)` slots are unbacked (demand paging).
    pub phys: Vec<PhysAddr>,
}

/// Ordered base-page VMA index.
///
/// The virtual base is stored both as the tree key and in [`Region`] because
/// `Region` is part of the public snapshot/interface shape. All structural
/// mutation goes through this wrapper so those values cannot diverge. The
/// tree replaces the previous sorted `Vec`: lookup and random `MAP_FIXED`
/// insertion are O(log VMA), while ordered iteration remains linear.
#[derive(Clone, Debug, Default)]
struct RegionTable {
    by_base: BTreeMap<u64, Region>,
    /// Page-scoped demand-fault ownership.  The thread holding a ticket may
    /// drop the region lock while it allocates/zeros anonymous backing or
    /// calls into a demand-pageable file.  Structural VMA removal cancels
    /// every ticket in the removed region before a replacement can appear.
    demand_pages: BTreeMap<u64, u64>,
    /// Page-scoped COW-copy ownership. The owner pins the source frame before
    /// dropping the region lock, so unrelated write faults can copy in
    /// parallel without letting VMA teardown recycle either source.
    cow_pages: BTreeMap<u64, u64>,
    /// Per-page swap ownership transitions, keyed by page-aligned user VA.
    /// Kept under the same lock as `Region::phys` so the two authorities can
    /// never disagree at a visible transaction boundary.
    swap_pages: BTreeMap<u64, SwapPageState>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
enum SwapPageState {
    /// Backend write is in progress; the region still owns `phys`.
    Evicting(PhysAddr),
    /// PTE owns a swap slot and the corresponding `Region::phys` entry is 0.
    Swapped,
    /// Backend read is in progress; another fault should retry.
    Loading,
}

impl RegionTable {
    const fn new() -> Self {
        Self {
            by_base: BTreeMap::new(),
            demand_pages: BTreeMap::new(),
            cow_pages: BTreeMap::new(),
            swap_pages: BTreeMap::new(),
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.by_base.len()
    }

    #[inline]
    fn iter(&self) -> alloc::collections::btree_map::Values<'_, u64, Region> {
        self.by_base.values()
    }

    #[inline]
    fn iter_mut(&mut self) -> alloc::collections::btree_map::ValuesMut<'_, u64, Region> {
        self.by_base.values_mut()
    }

    #[inline]
    fn get(&self, base: u64) -> Option<&Region> {
        self.by_base.get(&base)
    }

    #[inline]
    fn get_mut(&mut self, base: u64) -> Option<&mut Region> {
        self.by_base.get_mut(&base)
    }

    #[inline]
    fn predecessor(&self, base: u64) -> Option<&Region> {
        self.by_base
            .range(..base)
            .next_back()
            .map(|(_, region)| region)
    }

    #[inline]
    fn successor(&self, base: u64) -> Option<&Region> {
        self.by_base.range(base..).next().map(|(_, region)| region)
    }

    fn containing(&self, address: u64) -> Option<&Region> {
        self.by_base
            .range(..=address)
            .next_back()
            .map(|(_, region)| region)
            .filter(|region| address < region.base.as_u64().saturating_add(region.len))
    }

    fn containing_mut(&mut self, address: u64) -> Option<&mut Region> {
        let base = *self.by_base.range(..=address).next_back()?.0;
        let region = self.by_base.get_mut(&base)?;
        (address < region.base.as_u64().saturating_add(region.len)).then_some(region)
    }

    /// Find the first eligible resident private page at or after `start`.
    ///
    /// The old iterator pipeline visited every page in every VMA and selected
    /// the minimum qualifying address. Since VMAs and their backing vectors
    /// are already ordered, seek to the containing/successor VMA and stop at
    /// the first resident slot instead. This bounds the IRQ-disabled timer
    /// path by the forward distance from its persistent scan cursor.
    fn next_numa_hint_candidate(&self, start: u64) -> Option<VirtAddr> {
        let first_base = self
            .by_base
            .range(..=start)
            .next_back()
            .filter(|(_, region)| start < region.base.as_u64().saturating_add(region.len))
            .map_or(start, |(&base, _)| base);

        for (_, region) in self.by_base.range(first_base..) {
            if region.perms.contains(RegionPerms::SHARED)
                || region.perms.contains(RegionPerms::LOCKED)
                || region.perms.prot_only().0 == 0
            {
                continue;
            }
            let rb = region.base.as_u64();
            let first_index = if start > rb {
                ((start - rb) >> 12) as usize
            } else {
                0
            };
            let Some(tail) = region.phys.get(first_index..) else {
                continue;
            };
            let Some(relative) = tail.iter().position(|phys| phys.raw() != 0) else {
                continue;
            };
            return Some(VirtAddr::new(rb + ((first_index + relative) as u64) * 4096));
        }
        None
    }

    fn insert(&mut self, region: Region) -> Option<Region> {
        self.by_base.insert(region.base.as_u64(), region)
    }

    #[inline]
    fn remove(&mut self, base: u64) -> Option<Region> {
        let region = self.by_base.remove(&base)?;
        let end = region.base.as_u64().saturating_add(region.len);
        self.demand_pages
            .retain(|&vaddr, _| vaddr < region.base.as_u64() || vaddr >= end);
        self.cow_pages
            .retain(|&vaddr, _| vaddr < region.base.as_u64() || vaddr >= end);
        Some(region)
    }

    fn has_overlap(&self, lo: u64, hi: u64) -> bool {
        self.predecessor(lo)
            .is_some_and(|region| region.base.as_u64().saturating_add(region.len) > lo)
            || self.by_base.range(lo..hi).next().is_some()
    }

    fn overlapping_any(&self, lo: u64, hi: u64, predicate: impl Fn(&Region) -> bool) -> bool {
        if self.predecessor(lo).is_some_and(|region| {
            region.base.as_u64().saturating_add(region.len) > lo && predicate(region)
        }) {
            return true;
        }
        self.by_base
            .range(lo..hi)
            .any(|(_, region)| predicate(region))
    }

    /// Visit only VMAs intersecting `[lo, hi)`, in virtual order.
    fn for_each_overlapping(&self, lo: u64, hi: u64, mut visit: impl FnMut(&Region)) {
        if let Some(region) = self.predecessor(lo) {
            if region.base.as_u64().saturating_add(region.len) > lo {
                visit(region);
            }
        }
        for (_, region) in self.by_base.range(lo..hi) {
            visit(region);
        }
    }

    /// Mutable counterpart of [`Self::for_each_overlapping`].
    fn for_each_overlapping_mut(&mut self, lo: u64, hi: u64, mut visit: impl FnMut(&mut Region)) {
        let start = self
            .by_base
            .range(..lo)
            .next_back()
            .filter(|(_, region)| region.base.as_u64().saturating_add(region.len) > lo)
            .map_or(lo, |(&base, _)| base);
        for (_, region) in self.by_base.range_mut(start..hi) {
            visit(region);
        }
    }

    /// Remove and return every VMA intersecting `[lo, hi)`, in virtual order.
    fn drain_overlapping(&mut self, lo: u64, hi: u64) -> Vec<Region> {
        let mut keys = Vec::new();
        if let Some((&base, region)) = self.by_base.range(..lo).next_back() {
            if region.base.as_u64().saturating_add(region.len) > lo {
                keys.push(base);
            }
        }
        keys.extend(self.by_base.range(lo..hi).map(|(&base, _)| base));
        keys.into_iter()
            .filter_map(|base| self.remove(base))
            .collect()
    }

    fn covers_range(&self, lo: u64, hi: u64) -> bool {
        let mut cursor = lo;
        if let Some(region) = self
            .by_base
            .range(..=lo)
            .next_back()
            .map(|(_, region)| region)
        {
            let begin = region.base.as_u64();
            let end = begin.saturating_add(region.len);
            if begin <= cursor && end > cursor {
                cursor = end;
                if cursor >= hi {
                    return true;
                }
            }
        }
        for (_, region) in self.by_base.range(cursor..hi) {
            let begin = region.base.as_u64();
            if begin > cursor {
                return false;
            }
            cursor = cursor.max(begin.saturating_add(region.len));
            if cursor >= hi {
                return true;
            }
        }
        false
    }

    fn snapshot(&self) -> Vec<Region> {
        self.iter().cloned().collect()
    }
}

/// Result of taking page-scoped ownership of a demand fault.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DemandPageClaim {
    /// The leaf was already present or was repaired while the region lock was
    /// held; the faulting instruction can retry immediately.
    Resolved,
    /// A peer owns the slow part of this exact page fault.  Retrying cannot
    /// observe a half-published frame because publication also takes the
    /// region lock.
    InProgress,
    /// This caller owns the slow path and may leave the region lock.
    Owner { ticket: u64, file_backed: bool },
}

static NEXT_DEMAND_TICKET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
static NEXT_COW_TICKET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// An owned hardware huge-page mapping. Each backing entry is installed as
/// one architecture block/huge leaf; it is never represented as base-page
/// PTEs.
#[derive(Debug, PartialEq, Eq)]
pub struct HugeRegion {
    pub base: VirtAddr,
    pub len: u64,
    pub perms: RegionPerms,
    pub size: crate::hugepage::HugeSize,
    pub frames: Vec<crate::hugepage::HugeFrame>,
}

/// Non-owning NUMA residency summary for one registered virtual region.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NumaRegionSnapshot {
    pub base: VirtAddr,
    pub len: u64,
    pub perms: RegionPerms,
    /// Hardware leaf size in KiB (4, 2048, or 1048576).
    pub kernel_page_kb: u64,
    /// Resident base-page equivalents, excluding lazy/unbacked slots.
    pub resident_pages: u64,
    /// Resident base-page equivalents per SRAT node.
    pub node_pages: [u64; crate::frame::MAX_NUMA_NODES],
}

/// Allocation-free process memory totals used by procfs and exit accounting.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressSpaceMemoryStats {
    pub mapped_bytes: u64,
    pub resident_pages: u64,
    pub writable_nonexec_bytes: u64,
}

const MAX_NUMA_HINTS: usize = 64;

#[derive(Debug)]
struct NumaHints {
    pages: [u64; MAX_NUMA_HINTS],
    len: usize,
}

impl NumaHints {
    const fn new() -> Self {
        Self {
            pages: [0; MAX_NUMA_HINTS],
            len: 0,
        }
    }
}

fn release_failed_huge_region(
    region: HugeRegion,
    error: AddressSpaceError,
) -> Result<(), AddressSpaceError> {
    for frame in region.frames {
        crate::hugepage::free_hugepage(frame);
    }
    Err(error)
}

/// Errors from the address-space surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddressSpaceError {
    NotImplemented,
    Overlap,
    OutOfRange,
    AlignmentMismatch,
    Unmapped,
    /// The requested NUMA node is outside the allocator's node table.
    InvalidNode,
    /// The mapping borrows externally-owned backing and cannot be migrated.
    SharedMapping,
    /// No online, allowed node exists in a strictly slower memory tier.
    NoDemotionTarget,
}

/// Per-process address space. Stage-4 body: holds the region table +
/// a placeholder for the root paging structure; `activate()` is the
/// per-arch `MOV CR3, …` / `TTBR0_EL1 = …` operation that makes
/// this the live address space.
///
/// The region table lives behind an `IrqSafeSpinLock` so syscall
/// handlers holding `Arc<AddressSpace>` can mutate it without
/// exclusive ownership — the typical shape for per-task ASes
/// shared across a trap handler + the executor's poll path.
#[derive(Debug)]
pub struct AddressSpace {
    /// Root page-table physical frame. Filled in by the per-arch
    /// `new_table` primitive once it lands; `PhysAddr::new(0)`
    /// acts as "not-yet-initialised" sentinel.
    pub root: PhysAddr,
    /// Lifetime-scoped aarch64 process ASID. Tag 0 is the safe fallback and
    /// selects the flushing TTBR0 switch path.
    #[cfg(target_arch = "aarch64")]
    asid: crate::asid_alloc::DomainTag,
    regions: IrqSafeSpinLock<RegionTable>,
    huge_regions: IrqSafeSpinLock<Vec<HugeRegion>>,
    /// Per-AS mmap cursor: next free virt for a no-hint mmap.
    /// Lives here (not on a single global) so each process gets its
    /// own monotonically-increasing arena instead of a shared race.
    /// Initial value 0x4080_0000_0000 matches the prior global —
    /// well above the ELF + brk regions and below the user stack.
    mmap_cursor: core::sync::atomic::AtomicU64,
    /// Set once this AS is shared by a `CLONE_VM` clone (a thread) —
    /// from then on it can be RESIDENT ON MULTIPLE CPUS at once, so PTE
    /// mutations must broadcast cross-CPU TLB shootdowns. While false
    /// (a single-threaded process — the common case) the AS is active
    /// on at most ONE CPU: the one its task is currently running on.
    /// Every residency change reloads CR3 with a plain (flushing)
    /// `mov cr3` (`activate()` / `poll_to_yield`'s resume path), so no
    /// OTHER CPU can hold a live user-half TLB entry for it — remote
    /// shootdowns are pure waste there, and their ack-wait spins were
    /// measured to serialise the whole machine under fork/COW-heavy
    /// load (stress-ng --sigrt) whenever one vCPU was slow to ack.
    vm_shared: core::sync::atomic::AtomicBool,
    /// Resident base pages temporarily made inaccessible by automatic NUMA
    /// balancing. The next access is a NUMA hint fault, not demand paging.
    numa_hints: IrqSafeSpinLock<NumaHints>,
}

impl AddressSpace {
    /// Default base for the per-AS mmap cursor. Matches the prior
    /// global MMAP_CURSOR so existing user binaries continue to see
    /// mmap returning addresses in the same broad range.
    pub const MMAP_CURSOR_BASE: u64 = 0x0000_4080_0000_0000;

    /// Ceiling of the no-hint mmap window. The user stack lives at the
    /// TOP of the user half (`DEFAULT_USER_STACK_BASE` = 0x7FFF_FFFC_0000)
    /// and grows down, so the mmap arena must stop well below it: this
    /// leaves ~1 TiB of stack-growth headroom above the window while
    /// still giving mmap a ~63 TiB arena. `bump_mmap_cursor_past`
    /// ignores regions at/above this ceiling (the stack + its guard), so
    /// registering the high-addressed stack region can't drag the cursor
    /// up into the stack. Without that, the cursor climbed to the stack
    /// top and subsequent no-hint mmaps (notably 2nd+ thread stacks)
    /// were handed VAs that overlapped the stack and then straddled the
    /// 0x0000_8000_0000_0000 canonical boundary — a non-canonical store
    /// there #GP-kills the faulting thread, silently wedging every
    /// multithreaded process that spawned a second thread.
    pub const MMAP_WINDOW_TOP: u64 = 0x0000_7F00_0000_0000;

    /// End of the mappable user half: 1 << 47 is the first
    /// non-canonical low address on x86_64, and NARF's user layout
    /// (binary / interp / mmap arena / stack) tops out below it on
    /// both arches. `map_region` / `grow_region` reject anything
    /// crossing this so a user-controlled base (MAP_FIXED hint,
    /// shmat addr, mremap grow) can never register a region the
    /// paging layer can't legally install — x86_64 `map_4kb` returns
    /// `NonCanonical` for such a VA, which `materialize` treats as a
    /// can't-happen invariant violation and panics on.
    pub const USER_HALF_END: u64 = 0x0000_8000_0000_0000;

    /// Floor of the window where a *user-directed* fixed mapping may
    /// land. Everything below 512 GiB decodes to PML4[0], which every
    /// x86_64 user PML4 shares with the kernel (the low-identity
    /// window bulk-copied by `new_user_pml4`): a user mapping there
    /// would either hit a kernel huge page (`EncounteredHugePage`) or
    /// plant user PTEs inside KERNEL-SHARED page tables, leaking the
    /// mapping into every address space. NARF's own user layout
    /// starts at PML4[1] (binary base 0x0000_0080_0000_1000), so no
    /// legitimate fixed mapping lives below this. Policy is enforced
    /// at the syscall boundary (`sys_mmap` MAP_FIXED), not in
    /// `map_region` — kernel-internal callers and unit tests still
    /// place structural regions at low VAs.
    pub const USER_FIXED_FLOOR: u64 = 0x0000_0080_0000_0000;

    /// Fresh address space with no regions. Stage-4 arch backend
    /// must assign `root` to a freshly-allocated page-table frame.
    pub const fn empty() -> Self {
        Self {
            root: PhysAddr::new(0),
            #[cfg(target_arch = "aarch64")]
            asid: crate::asid_alloc::DomainTag::RESERVED,
            regions: IrqSafeSpinLock::new(RegionTable::new()),
            huge_regions: IrqSafeSpinLock::new(Vec::new()),
            mmap_cursor: core::sync::atomic::AtomicU64::new(Self::MMAP_CURSOR_BASE),
            vm_shared: core::sync::atomic::AtomicBool::new(false),
            numa_hints: IrqSafeSpinLock::new(NumaHints::new()),
        }
    }

    /// Temporarily remove one private resident 4 KiB leaf so its next access
    /// reports the accessing CPU's NUMA locality through a hint fault.
    ///
    /// Returns `Ok(false)` when the address is not an eligible resident base
    /// page (hole, lazy page, shared/locked mapping, or already sampled).
    ///
    /// # Safety
    /// `self.root` must be a live user page-table root and address-space
    /// teardown must not race this operation.
    pub unsafe fn protect_numa_hint_page(
        &self,
        vaddr: VirtAddr,
    ) -> Result<bool, AddressSpaceError> {
        let page = VirtAddr::new(vaddr.as_u64() & !0xFFF);
        let regions = self.regions.lock();
        let Some(region) = regions.containing(page.as_u64()) else {
            return Ok(false);
        };
        if region.perms.contains(RegionPerms::SHARED) || region.perms.contains(RegionPerms::LOCKED)
        {
            return Ok(false);
        }
        let index = ((page.as_u64() - region.base.as_u64()) >> 12) as usize;
        if region.phys.get(index).is_none_or(|phys| phys.raw() == 0) {
            return Ok(false);
        }
        let mut hints = self.numa_hints.lock();
        if hints.pages[..hints.len].contains(&page.as_u64()) || hints.len == MAX_NUMA_HINTS {
            return Ok(false);
        }
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: page belongs to the live private region resolved above.
            let removed = unsafe { crate::x86_64::paging::unmap_4kb_local(self.root, page) };
            if removed.is_err() {
                return Ok(false);
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: page belongs to the live private region resolved above.
            let removed = unsafe { crate::aarch64::paging::unmap_4kb(self.root, page) };
            if removed.is_err() {
                return Ok(false);
            }
        }
        let index = hints.len;
        hints.pages[index] = page.as_u64();
        hints.len += 1;
        drop(hints);
        drop(regions);
        self.flush_region_broadcast(page, 1);
        Ok(true)
    }

    /// Consume a recorded NUMA hint for `vaddr`.
    ///
    /// A true result gives the fault handler exclusive responsibility for
    /// restoring or migrating the still-owned backing page.
    pub fn take_numa_hint(&self, vaddr: VirtAddr) -> bool {
        let page = VirtAddr::new(vaddr.as_u64() & !0xFFF);
        let mut hints = self.numa_hints.lock();
        let Some(index) = hints.pages[..hints.len]
            .iter()
            .position(|candidate| *candidate == page.as_u64())
        else {
            return false;
        };
        hints.len -= 1;
        let last = hints.len;
        hints.pages[index] = hints.pages[last];
        hints.pages[last] = 0;
        true
    }

    /// Find the first eligible resident base page at or after `start`.
    /// This is allocation-free so a timer-return sampling hook can use it.
    pub fn next_numa_hint_candidate(&self, start: VirtAddr) -> Option<VirtAddr> {
        let start = start.as_u64() & !0xFFF;
        let regions = self.regions.lock();
        regions.next_numa_hint_candidate(start)
    }

    /// Mark this AS as shared by a `CLONE_VM` clone (thread creation).
    /// One-way: once multi-resident, PTE mutations broadcast cross-CPU
    /// shootdowns forever (threads may exit, but a racing stale-TLB
    /// window on the CPU a thread JUST ran on isn't worth tracking).
    pub fn mark_vm_shared(&self) {
        self.vm_shared
            .store(true, core::sync::atomic::Ordering::Release);
    }

    /// Whether PTE mutations on this AS must broadcast cross-CPU TLB
    /// shootdowns (see `vm_shared` field docs).
    #[inline]
    pub fn is_vm_shared(&self) -> bool {
        self.vm_shared.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Atomically reserve `bytes` of contiguous virtual address
    /// from the per-AS mmap cursor and return the base. Bytes are
    /// page-rounded by the caller; this routine just bumps.
    #[inline]
    pub fn reserve_mmap_va(&self, bytes: u64) -> u64 {
        use core::sync::atomic::Ordering;
        // O(1): the cursor is kept past every region ever mapped into the
        // mmap range (see `bump_mmap_cursor_past`, called from
        // `map_region`), so a plain bump never collides with an existing
        // mapping — including regions placed out-of-band (bootstrap
        // channel buffers, MAP_FIXED overlays) that didn't go through here.
        //
        // The cursor is monotonic (munmap does not reclaim VA), so it can
        // only climb. CAS the bump against `MMAP_WINDOW_TOP` so it FAILS
        // CLOSED at the ceiling: returning 0 (an invalid base the caller
        // maps to -ENOMEM) instead of marching into the stack reserve and
        // then across the non-canonical boundary — which would silently
        // re-create the #GP-kill the window was introduced to prevent.
        let bytes = bytes.max(0x1000);
        let mut cur = self.mmap_cursor.load(Ordering::Relaxed);
        loop {
            let end = cur.saturating_add(bytes);
            if end > Self::MMAP_WINDOW_TOP {
                return 0; // arena exhausted → caller returns -ENOMEM
            }
            match self.mmap_cursor.compare_exchange_weak(
                cur,
                end,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return cur,
                Err(observed) => cur = observed,
            }
        }
    }

    /// Reserve an mmap window with an aligned base. Any alignment padding is
    /// consumed from the monotonic arena, preventing a later mapping from
    /// colliding with the gap.
    pub fn reserve_mmap_va_aligned(&self, bytes: u64, align: u64) -> u64 {
        use core::sync::atomic::Ordering;
        if align < 4096 || !align.is_power_of_two() {
            return 0;
        }
        let mut cur = self.mmap_cursor.load(Ordering::Relaxed);
        loop {
            let Some(aligned) = cur.checked_add(align - 1).map(|v| v & !(align - 1)) else {
                return 0;
            };
            let Some(next) = aligned.checked_add(bytes.max(4096)) else {
                return 0;
            };
            if next > Self::MMAP_WINDOW_TOP {
                return 0;
            }
            match self
                .mmap_cursor
                .compare_exchange(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return aligned,
                Err(observed) => cur = observed,
            }
        }
    }

    /// Keep the mmap-allocation cursor past `region_end` when a region is
    /// mapped into the mmap window, so the next `reserve_mmap_va` can't
    /// hand back a colliding VA. No-op for regions that live outside the
    /// window: below it (program image / interp / brk) OR at/above it
    /// (the user stack + its guard, which sit at the very top of the
    /// user half). The latter exclusion is load-bearing — without it,
    /// registering the high-addressed stack region dragged the cursor up
    /// to the stack top, so subsequent (e.g. thread-stack) mmaps climbed
    /// into the stack and across the canonical boundary.
    fn bump_mmap_cursor_past(&self, region_base: u64, region_len: u64) {
        use core::sync::atomic::Ordering;
        if !(Self::MMAP_CURSOR_BASE..Self::MMAP_WINDOW_TOP).contains(&region_base) {
            return;
        }
        let region_end = region_base.saturating_add(region_len);
        let mut cur = self.mmap_cursor.load(Ordering::Relaxed);
        while region_end > cur {
            match self.mmap_cursor.compare_exchange(
                cur,
                region_end,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => cur = observed,
            }
        }
    }

    /// Allocate a fresh user-mode PML4 (x86_64) or TTBR0 page-table
    /// root (aarch64) inheriting every kernel-half entry from the
    /// currently-active root. The returned `AddressSpace` can be
    /// populated with user regions via `map_region` and activated
    /// via `activate()` (real `MOV CR3` on x86_64; real
    /// `MSR TTBR0_EL1` on aarch64).
    ///
    /// # Safety
    /// Caller must run with paging enabled. Post-construction the
    /// AS is safe to build up and activate per the normal flow.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn new_for_user() -> Result<Self, AddressSpaceError> {
        // SAFETY: contract documented on the function.
        let phys = unsafe { crate::x86_64::paging::new_user_pml4() }
            .map_err(|_| AddressSpaceError::OutOfRange)?;
        Ok(Self {
            root: phys,
            regions: IrqSafeSpinLock::new(RegionTable::new()),
            huge_regions: IrqSafeSpinLock::new(Vec::new()),
            mmap_cursor: core::sync::atomic::AtomicU64::new(Self::MMAP_CURSOR_BASE),
            vm_shared: core::sync::atomic::AtomicBool::new(false),
            numa_hints: IrqSafeSpinLock::new(NumaHints::new()),
        })
    }

    /// # Safety
    /// Caller must run with the MMU enabled. The fresh `TTBR0_EL1` root
    /// starts empty (the kernel half lives behind `TTBR1_EL1` and is
    /// unaffected); post-construction the AS is safe to build up via
    /// `map_region` and install via `activate()`.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn new_for_user() -> Result<Self, AddressSpaceError> {
        // SAFETY: contract documented on the function. aarch64's
        // split translation means the user root starts empty —
        // the kernel sits behind TTBR1 and is unaffected.
        // SAFETY: Valid memory or trusted environment
        let phys = unsafe { crate::aarch64::paging::new_user_ttbr0() }
            .map_err(|_| AddressSpaceError::OutOfRange)?;
        Ok(Self {
            root: phys,
            asid: crate::asid_alloc::allocate_process_asid(),
            regions: IrqSafeSpinLock::new(RegionTable::new()),
            huge_regions: IrqSafeSpinLock::new(Vec::new()),
            mmap_cursor: core::sync::atomic::AtomicU64::new(Self::MMAP_CURSOR_BASE),
            vm_shared: core::sync::atomic::AtomicBool::new(false),
            numa_hints: IrqSafeSpinLock::new(NumaHints::new()),
        })
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub unsafe fn new_for_user() -> Result<Self, AddressSpaceError> {
        Err(AddressSpaceError::NotImplemented)
    }

    /// Attach a region description to the address-space table. Does
    /// NOT program the page table — that lives in `arch/`. Checks
    /// for overlap with existing regions and 4 KiB alignment.
    pub fn map_region(&self, region: Region) -> Result<(), AddressSpaceError> {
        let _shared_guard = region
            .perms
            .contains(RegionPerms::SHARED)
            .then(|| SHARED_MAPPING_TRANSACTION.lock());
        self.map_region_inner(region)
    }

    fn map_region_inner(&self, region: Region) -> Result<(), AddressSpaceError> {
        if region.base.as_u64() & 0xFFF != 0 || region.len & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        // Per-page scatter list must cover every page in the region —
        // anything else means the caller computed `len` and `phys`
        // out of sync, which would silently leave pages unbacked or
        // leak frames during materialize.
        if region.phys.len() as u64 != region.len >> 12 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        let end = region
            .base
            .as_u64()
            .checked_add(region.len)
            .ok_or(AddressSpaceError::OutOfRange)?;
        // Reject regions crossing out of the user half. A base at or
        // past 1 << 47 is non-canonical (or kernel-half) — `map_4kb`
        // can never install its PTEs, and on x86_64 `materialize`
        // panics on the resulting `NonCanonical` error. stress-ng
        // --mmapfixed feeds exactly such bases as MAP_FIXED hints
        // (walking down from 1 << 63); fail typed instead.
        if end > Self::USER_HALF_END {
            return Err(AddressSpaceError::OutOfRange);
        }
        for r in self.huge_regions.lock().iter() {
            let r_end = r.base.as_u64() + r.len;
            if region.base.as_u64() < r_end && r.base.as_u64() < end {
                return Err(AddressSpaceError::Overlap);
            }
        }
        let mut regions = self.regions.lock();
        // Base-page VMAs are keyed by base. A new interval can overlap only
        // its immediate predecessor or successor, so both admission and
        // insertion remain O(log VMA) under random MAP_FIXED churn.
        if let Some(predecessor) = regions.predecessor(region.base.as_u64()) {
            if predecessor.base.as_u64().saturating_add(predecessor.len) > region.base.as_u64() {
                return Err(AddressSpaceError::Overlap);
            }
        }
        if regions
            .successor(region.base.as_u64())
            .is_some_and(|successor| successor.base.as_u64() < end)
        {
            return Err(AddressSpaceError::Overlap);
        }
        #[cfg(debug_assertions)]
        for r in regions.iter() {
            // Diagnostic double-free guard (debug builds only): a non-SHARED
            // region must not point at a phys frame already mapped by another
            // region in this AS, or `AddressSpace::drop` would unmap it twice
            // and double-free the phys. This is O(pages^2) per region pair —
            // catastrophic on an mmap-heavy workload where one AS faults in
            // hundreds of DSOs (a Plasma/Wayland session), which dominated the
            // CPU and stalled `narf-plasma` startup. The double-free it hunted
            // is fixed (frame-zero-on-free repro), so it is now debug-only; the
            // overlap check above stays in every build. SHARED regions borrow
            // registry-owned frames (aliasing is expected + safe), so skip them.
            if !region.perms.contains(RegionPerms::SHARED) {
                for new_p in &region.phys {
                    if new_p.raw() == 0 {
                        continue;
                    }
                    for existing_p in &r.phys {
                        if existing_p.raw() == new_p.raw() {
                            panic!(
                                "map_region: duplicate phys {:#x} new-base={:#x} existing-base={:#x}",
                                new_p.raw(),
                                region.base.as_u64(),
                                r.base.as_u64(),
                            );
                        }
                    }
                }
            }
        }
        let (rb, rl) = (region.base.as_u64(), region.len);
        if region.perms.contains(RegionPerms::SHARED) {
            retain_shared_frames(&region);
        }
        assert!(regions.insert(region).is_none());
        drop(regions);
        // Keep the mmap-allocation cursor past anything mapped into the
        // mmap range so a later `reserve_mmap_va` can't collide with it.
        self.bump_mmap_cursor_past(rb, rl);
        Ok(())
    }

    /// Register a SHARED region while the caller already holds
    /// [`with_shared_mapping_transaction`].
    ///
    /// # Safety
    /// The caller must hold that transaction across acquisition of the
    /// external owner's frame snapshot and this call.
    pub unsafe fn map_shared_region_locked(&self, region: Region) -> Result<(), AddressSpaceError> {
        if !region.perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        self.map_region_inner(region)
    }

    /// Replace every base-page alias of one externally-owned shared frame in
    /// this address space without freeing either frame.
    ///
    /// Callers must hold [`with_shared_mapping_transaction`] across the
    /// complete cross-address-space update and backing-owner commit.
    ///
    /// Returns the number of aliases replaced.
    ///
    /// # Safety
    /// `old_phys` and `new_phys` must be live page-aligned frames, and the
    /// caller must roll all previously updated address spaces back if this
    /// operation fails.
    pub unsafe fn replace_shared_frame(
        &self,
        old_phys: PhysAddr,
        new_phys: PhysAddr,
    ) -> Result<usize, AddressSpaceError> {
        let mut regions = self.regions.lock();
        let aliases: Vec<(u64, usize, VirtAddr, RegionPerms)> = regions
            .iter()
            .flat_map(|region| {
                let region_base = region.base.as_u64();
                region
                    .phys
                    .iter()
                    .enumerate()
                    .filter(move |(_, phys)| {
                        region.perms.contains(RegionPerms::SHARED) && **phys == old_phys
                    })
                    .map(move |(page_idx, _)| {
                        (
                            region_base,
                            page_idx,
                            VirtAddr::new(region.base.as_u64() + page_idx as u64 * 4096),
                            region.perms,
                        )
                    })
            })
            .collect();

        let mut replaced = 0usize;
        for &(region_base, page_idx, page_va, perms) in &aliases {
            // SAFETY: the caller guarantees a live root and both physical
            // frames; each alias was revalidated under the region lock.
            let result = unsafe {
                #[cfg(target_arch = "x86_64")]
                {
                    use crate::x86_64::paging::{map_4kb, unmap_4kb_local, PtFlags};
                    let mut flags = PtFlags::USER;
                    if perms.contains(RegionPerms::WRITE) {
                        flags |= PtFlags::WRITABLE;
                    }
                    if !perms.contains(RegionPerms::EXEC) {
                        flags |= PtFlags::NO_EXEC;
                    }
                    let _ = unmap_4kb_local(self.root, page_va);
                    map_4kb(self.root, page_va, new_phys, flags)
                }
                #[cfg(target_arch = "aarch64")]
                {
                    use crate::aarch64::paging::{map_4kb, unmap_4kb, PtFlags};
                    let mut flags = if perms.contains(RegionPerms::WRITE) {
                        PtFlags::AP_RW_EL0
                    } else {
                        PtFlags::AP_RO_EL0
                    };
                    if !perms.contains(RegionPerms::EXEC) {
                        flags = flags | PtFlags::UXN | PtFlags::PXN;
                    }
                    let _ = unmap_4kb(self.root, page_va);
                    map_4kb(self.root, page_va, new_phys, flags)
                }
            };
            if result.is_err() {
                for &(rollback_base, rollback_page, rollback_va, rollback_perms) in
                    aliases[..replaced].iter().rev()
                {
                    #[cfg(target_arch = "x86_64")]
                    {
                        use crate::x86_64::paging::{map_4kb, unmap_4kb_local, PtFlags};
                        let mut flags = PtFlags::USER;
                        if rollback_perms.contains(RegionPerms::WRITE) {
                            flags |= PtFlags::WRITABLE;
                        }
                        if !rollback_perms.contains(RegionPerms::EXEC) {
                            flags |= PtFlags::NO_EXEC;
                        }
                        // SAFETY: exact inverse replacement under the same
                        // root/frame lifetime contract.
                        unsafe {
                            let _ = unmap_4kb_local(self.root, rollback_va);
                            let _ = map_4kb(self.root, rollback_va, old_phys, flags);
                        }
                    }
                    #[cfg(target_arch = "aarch64")]
                    {
                        use crate::aarch64::paging::{map_4kb, unmap_4kb, PtFlags};
                        let mut flags = if rollback_perms.contains(RegionPerms::WRITE) {
                            PtFlags::AP_RW_EL0
                        } else {
                            PtFlags::AP_RO_EL0
                        };
                        if !rollback_perms.contains(RegionPerms::EXEC) {
                            flags = flags | PtFlags::UXN | PtFlags::PXN;
                        }
                        // SAFETY: rollback owns both the address-space root and
                        // old frame; this removes only the failed replacement leaf.
                        let _ = unsafe { unmap_4kb(self.root, rollback_va) };
                        // SAFETY: restores the original owned frame and permissions
                        // at the same leaf before the old translation is flushed.
                        let _ = unsafe { map_4kb(self.root, rollback_va, old_phys, flags) };
                    }
                    regions
                        .get_mut(rollback_base)
                        .expect("shared alias region disappeared under lock")
                        .phys[rollback_page] = old_phys;
                    self.flush_region_broadcast(rollback_va, 1);
                }
                return Err(AddressSpaceError::NotImplemented);
            }
            regions
                .get_mut(region_base)
                .expect("shared alias region disappeared under lock")
                .phys[page_idx] = new_phys;
            self.flush_region_broadcast(page_va, 1);
            replaced += 1;
        }
        Ok(replaced)
    }

    /// Install an owned hardware huge-page region and transfer ownership of
    /// every backing frame to this address space.
    ///
    /// This programs L2/PD 2 MiB leaves or L1/PDPT 1 GiB leaves directly.
    /// On failure, all leaves installed by this call are rolled back and all
    /// backing is returned to the hugepage pool.
    ///
    /// # Safety
    /// `self.root` must be a live, identity-reachable user page-table root
    /// owned by this address space and not concurrently destroyed.
    pub unsafe fn map_huge_region(&self, region: HugeRegion) -> Result<(), AddressSpaceError> {
        if self.root.as_u64() == 0 {
            return release_failed_huge_region(region, AddressSpaceError::OutOfRange);
        }
        let page_size = match region.size {
            crate::hugepage::HugeSize::M2 => crate::hugepage::HUGEPAGE_2M_BYTES,
            crate::hugepage::HugeSize::G1 => crate::hugepage::HUGEPAGE_1G_BYTES,
        };
        if region.base.as_u64() & (page_size - 1) != 0
            || region.len == 0
            || region.len & (page_size - 1) != 0
            || region.frames.len() as u64 != region.len / page_size
        {
            return release_failed_huge_region(region, AddressSpaceError::AlignmentMismatch);
        }
        let end = region
            .base
            .as_u64()
            .checked_add(region.len)
            .ok_or(AddressSpaceError::OutOfRange);
        let end = match end {
            Ok(end) => end,
            Err(error) => return release_failed_huge_region(region, error),
        };
        if end > Self::USER_HALF_END {
            return release_failed_huge_region(region, AddressSpaceError::OutOfRange);
        }
        let mut huge = self.huge_regions.lock();
        if huge.iter().any(|r| {
            let r_end = r.base.as_u64() + r.len;
            region.base.as_u64() < r_end && r.base.as_u64() < end
        }) {
            drop(huge);
            return release_failed_huge_region(region, AddressSpaceError::Overlap);
        }
        {
            // Keep the global address-space lock order huge -> regular,
            // matching map_region and range-mutating operations.
            let regular = self.regions.lock();
            if regular.iter().any(|r| {
                let r_end = r.base.as_u64() + r.len;
                region.base.as_u64() < r_end && r.base.as_u64() < end
            }) {
                drop(regular);
                drop(huge);
                return release_failed_huge_region(region, AddressSpaceError::Overlap);
            }
        }

        if let Err((installed, error)) = self.map_new_huge_leaves(&region, page_size) {
            // The x86 batch helper has released the page-table lock before
            // rollback, so these ordinary unmap helpers cannot self-deadlock.
            for j in 0..installed {
                let rollback_va = VirtAddr::new(region.base.as_u64() + j as u64 * page_size);
                let _ = self.unmap_huge_leaf(rollback_va, region.size);
            }
            for frame in region.frames {
                crate::hugepage::free_hugepage(frame);
            }
            return Err(error);
        }
        let (base, len) = (region.base.as_u64(), region.len);
        huge.push(region);
        drop(huge);
        self.bump_mmap_cursor_past(base, len);
        Ok(())
    }

    /// Install every fresh huge leaf in a region, reporting how many leaves
    /// need rollback if an installation fails.
    #[cfg(target_arch = "x86_64")]
    fn map_new_huge_leaves(
        &self,
        region: &HugeRegion,
        page_size: u64,
    ) -> Result<(), (usize, AddressSpaceError)> {
        // One per-root page-table lock covers the complete region rather than
        // disabling IRQs and reacquiring the same shard once per huge leaf.
        let _pt_guard = crate::x86_64::paging::pt_lock_for(self.root).lock();
        for (i, frame) in region.frames.iter().enumerate() {
            let va = VirtAddr::new(region.base.as_u64() + i as u64 * page_size);
            if let Err(error) =
                self.map_huge_leaf_locked(va, frame.phys(), region.size, region.perms)
            {
                return Err((i, error));
            }
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn map_new_huge_leaves(
        &self,
        region: &HugeRegion,
        page_size: u64,
    ) -> Result<(), (usize, AddressSpaceError)> {
        let _pt_guard = crate::aarch64::paging::pt_lock_for(self.root).lock();
        for (i, frame) in region.frames.iter().enumerate() {
            let va = VirtAddr::new(region.base.as_u64() + i as u64 * page_size);
            if let Err(error) =
                self.map_huge_leaf_locked(va, frame.phys(), region.size, region.perms)
            {
                return Err((i, error));
            }
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn map_huge_leaf_locked(
        &self,
        va: VirtAddr,
        phys: u64,
        size: crate::hugepage::HugeSize,
        perms: RegionPerms,
    ) -> Result<(), AddressSpaceError> {
        use crate::x86_64::paging::{map_1gb_locked, map_2mb_locked, PtFlags};
        let mut flags = PtFlags::USER;
        if perms.contains(RegionPerms::WRITE) {
            flags |= PtFlags::WRITABLE;
        }
        if !perms.contains(RegionPerms::EXEC) {
            flags |= PtFlags::NO_EXEC;
        }
        // SAFETY: map_new_huge_leaves holds this root's page-table mutation
        // lock; map_huge_region validated the live-root and alignment contract.
        let result = unsafe {
            match size {
                crate::hugepage::HugeSize::M2 => {
                    map_2mb_locked(self.root, va, PhysAddr::new(phys), flags)
                }
                crate::hugepage::HugeSize::G1 => {
                    map_1gb_locked(self.root, va, PhysAddr::new(phys), flags)
                }
            }
        };
        result.map_err(|_| AddressSpaceError::Overlap)
    }

    #[cfg(target_arch = "x86_64")]
    fn map_huge_leaf(
        &self,
        va: VirtAddr,
        phys: u64,
        size: crate::hugepage::HugeSize,
        perms: RegionPerms,
    ) -> Result<(), AddressSpaceError> {
        use crate::x86_64::paging::{map_1gb, map_2mb, PtFlags};
        let mut flags = PtFlags::USER;
        if perms.contains(RegionPerms::WRITE) {
            flags |= PtFlags::WRITABLE;
        }
        if !perms.contains(RegionPerms::EXEC) {
            flags |= PtFlags::NO_EXEC;
        }
        // SAFETY: map_huge_region validated both alignments and its caller
        // guarantees a live root owned by this address space.
        let result = unsafe {
            match size {
                crate::hugepage::HugeSize::M2 => map_2mb(self.root, va, PhysAddr::new(phys), flags),
                crate::hugepage::HugeSize::G1 => map_1gb(self.root, va, PhysAddr::new(phys), flags),
            }
        };
        result.map_err(|_| AddressSpaceError::Overlap)
    }

    #[cfg(target_arch = "aarch64")]
    fn map_huge_leaf_locked(
        &self,
        va: VirtAddr,
        phys: u64,
        size: crate::hugepage::HugeSize,
        perms: RegionPerms,
    ) -> Result<(), AddressSpaceError> {
        use crate::aarch64::paging::{map_1gb_locked, map_2mb_locked, PtFlags};
        let mut flags = if perms.contains(RegionPerms::WRITE) {
            PtFlags::AP_RW_EL0
        } else {
            PtFlags::AP_RO_EL0
        };
        if !perms.contains(RegionPerms::EXEC) {
            flags = flags | PtFlags::UXN | PtFlags::PXN;
        }
        // SAFETY: map_new_huge_leaves holds the root mutation lock.
        let result = unsafe {
            match size {
                crate::hugepage::HugeSize::M2 => {
                    map_2mb_locked(self.root, va, PhysAddr::new(phys), flags)
                }
                crate::hugepage::HugeSize::G1 => {
                    map_1gb_locked(self.root, va, PhysAddr::new(phys), flags)
                }
            }
        };
        result.map_err(|_| AddressSpaceError::Overlap)
    }

    #[cfg(target_arch = "aarch64")]
    fn map_huge_leaf(
        &self,
        va: VirtAddr,
        phys: u64,
        size: crate::hugepage::HugeSize,
        perms: RegionPerms,
    ) -> Result<(), AddressSpaceError> {
        use crate::aarch64::paging::{map_1gb, map_2mb, PtFlags};
        let mut flags = if perms.contains(RegionPerms::WRITE) {
            PtFlags::AP_RW_EL0
        } else {
            PtFlags::AP_RO_EL0
        };
        if !perms.contains(RegionPerms::EXEC) {
            flags = flags | PtFlags::UXN | PtFlags::PXN;
        }
        // SAFETY: map_huge_region validated both alignments and its caller
        // guarantees a live root owned by this address space.
        let result = unsafe {
            match size {
                crate::hugepage::HugeSize::M2 => map_2mb(self.root, va, PhysAddr::new(phys), flags),
                crate::hugepage::HugeSize::G1 => map_1gb(self.root, va, PhysAddr::new(phys), flags),
            }
        };
        result.map_err(|_| AddressSpaceError::Overlap)
    }

    #[cfg(target_arch = "x86_64")]
    fn unmap_huge_leaf(
        &self,
        va: VirtAddr,
        size: crate::hugepage::HugeSize,
    ) -> Result<PhysAddr, AddressSpaceError> {
        // SAFETY: callers only remove leaves recorded in this address
        // space's owned huge-region table while its root remains live.
        let result = unsafe {
            match size {
                crate::hugepage::HugeSize::M2 => crate::x86_64::paging::unmap_2mb(self.root, va),
                crate::hugepage::HugeSize::G1 => crate::x86_64::paging::unmap_1gb(self.root, va),
            }
        };
        result.map_err(|_| AddressSpaceError::Unmapped)
    }

    #[cfg(target_arch = "aarch64")]
    fn unmap_huge_leaf(
        &self,
        va: VirtAddr,
        size: crate::hugepage::HugeSize,
    ) -> Result<PhysAddr, AddressSpaceError> {
        // SAFETY: callers only remove leaves recorded in this address
        // space's owned huge-region table while its root remains live.
        let result = unsafe {
            match size {
                crate::hugepage::HugeSize::M2 => crate::aarch64::paging::unmap_2mb(self.root, va),
                crate::hugepage::HugeSize::G1 => crate::aarch64::paging::unmap_1gb(self.root, va),
            }
        };
        result.map_err(|_| AddressSpaceError::Unmapped)
    }

    /// Remove a huge region at exactly `base`, returning all backing to the
    /// boot-reserved hugepage pool.
    pub fn unmap_huge_region(&self, base: VirtAddr) -> Result<(), AddressSpaceError> {
        let region = {
            let mut huge = self.huge_regions.lock();
            let idx = huge
                .iter()
                .position(|r| r.base == base)
                .ok_or(AddressSpaceError::Unmapped)?;
            huge.swap_remove(idx)
        };
        let page_size = match region.size {
            crate::hugepage::HugeSize::M2 => crate::hugepage::HUGEPAGE_2M_BYTES,
            crate::hugepage::HugeSize::G1 => crate::hugepage::HUGEPAGE_1G_BYTES,
        };
        for i in 0..region.frames.len() {
            let va = VirtAddr::new(region.base.as_u64() + i as u64 * page_size);
            let _ = self.unmap_huge_leaf(va, region.size);
        }
        for frame in region.frames {
            crate::hugepage::free_hugepage(frame);
        }
        Ok(())
    }

    /// Grow an existing region in place to `new_len` (the `mremap(2)`
    /// no-move path). Extends the region's per-page scatter list with
    /// lazy (zero) pages and bumps `len`; the appended pages
    /// demand-page on first access exactly like a fresh anonymous
    /// `mmap`, so no copy and no extra `materialize` is needed — the
    /// original pages keep their frames at the same virtual address.
    ///
    /// Fails with `Overlap` if the grown tail would collide with
    /// another region, `Unmapped` if no region starts at `base`, or
    /// `AlignmentMismatch` if `new_len` isn't page-aligned. Shrinking
    /// is a no-op here (returns `Ok` leaving the region unchanged).
    pub fn grow_region(&self, base: VirtAddr, new_len: u64) -> Result<(), AddressSpaceError> {
        if new_len & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        let mut regions = self.regions.lock();
        let old_len = regions
            .get(base.as_u64())
            .ok_or(AddressSpaceError::Unmapped)?
            .len;
        if new_len <= old_len {
            return Ok(());
        }
        let new_end = base
            .as_u64()
            .checked_add(new_len)
            .ok_or(AddressSpaceError::OutOfRange)?;
        // Same user-half ceiling as `map_region`: a grow must not
        // push the region into non-canonical / kernel-half space.
        if new_end > Self::USER_HALF_END {
            return Err(AddressSpaceError::OutOfRange);
        }
        // Since the tree is non-overlapping and keyed by base, only the
        // immediate successor can collide with the grown tail.
        if regions
            .successor(base.as_u64().saturating_add(1))
            .is_some_and(|successor| successor.base.as_u64() < new_end)
        {
            return Err(AddressSpaceError::Overlap);
        }
        let add_pages = ((new_len - old_len) >> 12) as usize;
        let region = regions
            .get_mut(base.as_u64())
            .ok_or(AddressSpaceError::Unmapped)?;
        for _ in 0..add_pages {
            region.phys.push(PhysAddr::new(0));
        }
        region.len = new_len;
        let (rb, rl) = (base.as_u64(), new_len);
        drop(regions);
        // Keep the mmap-allocation cursor past the grown region, exactly as
        // `map_region` does for a fresh mapping. Without this, an in-place
        // `mremap` grow extends the region past the monotonic bump cursor;
        // a later `reserve_mmap_va` then hands back a VA *inside* the grown
        // tail, and `map_region` rejects it as Overlap — surfacing as a
        // spurious `mmap`/`malloc` failure (musl's mallocng grows arenas
        // this way, so a heavy client like weston's desktop-shell hits it).
        self.bump_mmap_cursor_past(rb, rl);
        Ok(())
    }

    /// Move one complete private base-page region to a disjoint virtual range,
    /// optionally resizing it at the same time (`mremap(MREMAP_MAYMOVE)`).
    ///
    /// Resident frames are re-addressed, not copied. A grown tail remains
    /// lazily unbacked; a truncated tail is released only after the old leaf
    /// translations have been removed and cross-CPU invalidation has
    /// completed. The target must already be free (the `MREMAP_FIXED` syscall
    /// path punches its replacement window first).
    ///
    /// This deliberately accepts only an exact, complete region. Linux can
    /// move a subrange spanning VMA fragments, but silently approximating that
    /// operation would lose per-fragment permissions and backing metadata.
    ///
    /// # Safety
    /// If `self.root` is non-zero it must remain a live user page-table root;
    /// the normal direct-map prerequisites for materialization and teardown
    /// apply.
    pub unsafe fn relocate_region(
        &self,
        old_base: VirtAddr,
        old_len: u64,
        new_base: VirtAddr,
        new_len: u64,
    ) -> Result<(), AddressSpaceError> {
        let old_lo = old_base.as_u64();
        let new_lo = new_base.as_u64();
        if old_lo & 0xFFF != 0
            || new_lo & 0xFFF != 0
            || old_len == 0
            || new_len == 0
            || old_len & 0xFFF != 0
            || new_len & 0xFFF != 0
        {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        let old_hi = old_lo
            .checked_add(old_len)
            .filter(|end| *end <= Self::USER_HALF_END)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let new_hi = new_lo
            .checked_add(new_len)
            .filter(|end| *end <= Self::USER_HALF_END)
            .ok_or(AddressSpaceError::OutOfRange)?;
        if old_lo < new_hi && new_lo < old_hi {
            return Err(AddressSpaceError::Overlap);
        }

        // Preserve the established huge -> regular lock ordering. Keeping
        // both tables locked through leaf installation makes the region table
        // the authority for the entire move: no sibling can map or tear down
        // either range between validation and publication.
        let huge = self.huge_regions.lock();
        if huge.iter().any(|region| {
            let rb = region.base.as_u64();
            let re = rb.saturating_add(region.len);
            rb < new_hi && new_lo < re
        }) {
            return Err(AddressSpaceError::Overlap);
        }
        let mut regions = self.regions.lock();
        if regions.swap_pages.range(old_lo..old_hi).next().is_some() {
            return Err(AddressSpaceError::NotImplemented);
        }
        let source = regions
            .get(old_lo)
            .filter(|region| region.len == old_len)
            .ok_or(AddressSpaceError::Unmapped)?
            .clone();
        if source.perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        if regions.has_overlap(new_lo, new_hi) {
            return Err(AddressSpaceError::Overlap);
        }

        let kept_pages = core::cmp::min(old_len, new_len) as usize >> 12;
        let mut moved = source.clone();
        moved.base = new_base;
        moved.len = new_len;
        moved.phys.truncate(kept_pages);
        moved
            .phys
            .resize((new_len >> 12) as usize, PhysAddr::new(0));

        if self.root.as_u64() != 0 {
            // Preinstall the complete destination while the source remains
            // valid. Region removal and MAP_FIXED punching retire their leaves
            // before deleting metadata, so the validated-free destination is
            // also PTE-free; an unexpected stale leaf makes installation fail
            // loudly instead of paying an absent-range page-table walk on
            // every move. If page-table allocation fails, removing the partial
            // destination is a lossless rollback because source bookkeeping
            // and leaves have not changed yet.
            // SAFETY: `moved` is the validated, disjoint destination region
            // and the address space owns the live page-table root.
            if unsafe { self.install_region_leaves_local(&moved) }.is_err() {
                // SAFETY: only leaves belonging to the validated destination
                // region can have been installed by the failed operation.
                unsafe { self.unmap_region_leaves_local(&moved) };
                return Err(AddressSpaceError::OutOfRange);
            }
            // Destination is complete; retire the source leaves before
            // publishing the new region coordinates.
            // SAFETY: `source` remains owned by this address space under the
            // region locks, and its validated user range is still mapped.
            unsafe { self.unmap_region_leaves_local(&source) };
        }
        let removed = regions
            .remove(old_lo)
            .expect("relocation source disappeared under region lock");
        debug_assert_eq!(removed, source);
        assert!(regions.insert(moved).is_none());
        drop(regions);
        drop(huge);

        // Invalidate both sides after publishing. The source flush is
        // load-bearing before truncated backing is returned to the allocator;
        // the destination flush discards any stale logically-unmapped entry a
        // CLONE_VM peer might have cached before this move.
        self.flush_region_broadcast(old_base, old_len >> 12);
        self.flush_region_broadcast(new_base, new_len >> 12);
        if self.root.as_u64() != 0 {
            for phys in source.phys.into_iter().skip(kept_pages) {
                if phys.raw() != 0 {
                    crate::frame::free_frame(crate::frame::PhysFrame::new(phys));
                }
            }
        }
        self.bump_mmap_cursor_past(new_lo, new_len);
        Ok(())
    }

    /// Remove a region whose base address matches `base` AND release
    /// every page it owned: walk the per-page PTEs via the per-arch
    /// `unmap_4kb`, and return each underlying physical frame to the
    /// allocator via `frame::free_frame` (which dec_refs on the COW
    /// path so shared frames survive until the last owner drops).
    ///
    /// Pre-fix this only popped the bookkeeping entry — the PTEs and
    /// the frames stayed live, leaking until the AS itself was
    /// dropped (which itself didn't free anything either). This
    /// closes both leaks for the `munmap` / `brk`-shrink paths;
    /// process-exit teardown rides on the new `Drop for AddressSpace`
    /// (below) which calls into the same primitive for every
    /// surviving region plus the page-table pages themselves.
    pub fn unmap_region(&self, base: VirtAddr) -> Result<Region, AddressSpaceError> {
        // Private regions have no externally-owned aliases, so unrelated
        // address spaces may tear them down concurrently. Keep the region
        // lock from classification through removal: dropping it between the
        // SHARED check and swap_remove would let a racing MAP_FIXED replace a
        // private mapping with a shared one and bypass the transaction.
        //
        // Shared regions retain the original global transaction ordering:
        // drop the region lock, acquire transaction -> region lock, re-find
        // the mapping, and hold the transaction through TLB invalidation and
        // the owner's release hook below.
        let mut regions = self.regions.lock();
        let shared = regions
            .get(base.as_u64())
            .ok_or(AddressSpaceError::Unmapped)?
            .perms
            .contains(RegionPerms::SHARED);
        let _shared_transaction = if shared {
            drop(regions);
            let transaction = SHARED_MAPPING_TRANSACTION.lock();
            regions = self.regions.lock();
            Some(transaction)
        } else {
            None
        };
        record_unmap_path(shared);
        #[cfg(target_arch = "x86_64")]
        let swapped_entries = {
            let region = regions
                .get(base.as_u64())
                .ok_or(AddressSpaceError::Unmapped)?;
            let lo = region.base.as_u64();
            let hi = lo.saturating_add(region.len);
            if regions.swap_pages.range(lo..hi).any(|(_, state)| {
                matches!(state, SwapPageState::Evicting(_) | SwapPageState::Loading)
            }) {
                return Err(AddressSpaceError::NotImplemented);
            }
            let pages: Vec<VirtAddr> = regions
                .swap_pages
                .range(lo..hi)
                .filter_map(|(&va, state)| {
                    matches!(state, SwapPageState::Swapped).then_some(VirtAddr::new(va))
                })
                .collect();
            // SAFETY: these VAs are stable Swapped records under the region
            // lock and name this live address-space root.
            let entries = unsafe { crate::swap::take_swap_entries(self.root, &pages) }
                .map_err(|_| AddressSpaceError::NotImplemented)?;
            for va in pages {
                regions.swap_pages.remove(&va.as_u64());
            }
            entries
        };
        let region = {
            let region = regions
                .remove(base.as_u64())
                .ok_or(AddressSpaceError::Unmapped)?;
            // Tear down the leaf PTEs BEFORE dropping the lock (local
            // invalidation only; the batched cross-CPU flush + the frame
            // frees run below, outside the lock). Deferring the whole walk
            // past the lock drop — the previous shape — left a window where
            // the table said "unmapped" while live PTEs lingered: a racing
            // MAP_FIXED mmap re-registered the range, its materialize() saw
            // the stale PTE (AlreadyMapped) and skipped installing its own,
            // and the deferred teardown then stripped the page out from
            // under the new region — leaving "backed" bookkeeping over an
            // absent PTE (stress-ng --vma's concurrent mmap/munmap churn).
            // The walk is allocation-free and bounded, so holding the
            // IrqSafeSpinLock across it is safe; frame frees (buddy locks)
            // stay outside.
            if self.root.as_u64() != 0 {
                // SAFETY: same identity-mapping precondition as
                // `materialize`; the pages lie inside `region`, which this
                // AS owned until the `remove` above.
                unsafe { self.unmap_region_leaves_local(&region) };
            }
            region
        };
        drop(regions);
        // ONE cross-CPU invalidation BEFORE any frame is freed for reuse
        // (no-op unless the AS is CLONE_VM-shared — see vm_shared docs).
        self.flush_region_broadcast(region.base, (region.len + 0xFFF) >> 12);
        #[cfg(target_arch = "x86_64")]
        crate::swap::swap_discard_batch(&swapped_entries);
        if self.root.as_u64() != 0 {
            self.free_region_frames(&region);
        }
        Ok(region)
    }

    /// MAP_FIXED "punch": drop the `[base, base+len)` sub-range from any
    /// overlapping region — unmapping + freeing ONLY those pages — while
    /// preserving the rest of each region (prefix `[rb, base)` and suffix
    /// `[base+len, re)`) with their existing frames and PTEs intact.
    ///
    /// After this the window is unmapped and free, so the caller can
    /// `map_region` a fresh mapping over it. The dynamic linker relies on
    /// exactly this: it maps a whole DSO file, then `MAP_FIXED`-overlays
    /// individual segments — the non-overlaid pages (e.g. the ELF header)
    /// must survive.
    pub fn punch_fixed(&self, base: VirtAddr, len: u64) -> Result<(), AddressSpaceError> {
        if base.as_u64() & 0xFFF != 0 || len & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        let lo = base.as_u64();
        let hi = lo.checked_add(len).ok_or(AddressSpaceError::OutOfRange)?;

        // Keep huge -> regular as the address-space lock order. Holding both
        // locks from classification through table mutation prevents a racing
        // shared MAP_FIXED from entering the range after we decide it is
        // private. If a shared alias is present, reacquire in transaction ->
        // huge -> regular order and keep the transaction through PTE
        // invalidation and the external owner's release hook.
        let mut huge = self.huge_regions.lock();
        let mut regions = self.regions.lock();
        let shared =
            regions.overlapping_any(lo, hi, |region| region.perms.contains(RegionPerms::SHARED));
        let _shared_transaction = if shared {
            drop(regions);
            drop(huge);
            let transaction = SHARED_MAPPING_TRANSACTION.lock();
            huge = self.huge_regions.lock();
            regions = self.regions.lock();
            Some(transaction)
        } else {
            None
        };
        record_unmap_path(shared);

        if regions.swap_pages.range(lo..hi).next().is_some() {
            // Partial MAP_FIXED teardown of swap backing needs slot-aware
            // splitting. Refuse until that transaction lands rather than
            // leaking a slot or converting preserved data to demand-zero.
            return Err(AddressSpaceError::NotImplemented);
        }

        // A hardware huge leaf cannot be split into a differently-sized
        // mapping without first manufacturing replacement backing. Permit
        // MAP_FIXED to remove whole huge regions, but reject a partial cut.
        let removed_huge = {
            if huge.iter().any(|region| {
                let rb = region.base.as_u64();
                let re = rb + region.len;
                let overlaps = re > lo && rb < hi;
                overlaps && !(lo <= rb && hi >= re)
            }) {
                return Err(AddressSpaceError::AlignmentMismatch);
            }
            let mut removed = Vec::new();
            let mut kept = Vec::with_capacity(huge.len());
            for region in core::mem::take(&mut *huge) {
                let rb = region.base.as_u64();
                let re = rb + region.len;
                if re <= lo || rb >= hi {
                    kept.push(region);
                } else {
                    removed.push(region);
                }
            }
            *huge = kept;
            removed
        };
        drop(huge);
        for region in removed_huge {
            let page_size = match region.size {
                crate::hugepage::HugeSize::M2 => crate::hugepage::HUGEPAGE_2M_BYTES,
                crate::hugepage::HugeSize::G1 => crate::hugepage::HUGEPAGE_1G_BYTES,
            };
            for i in 0..region.frames.len() {
                let va = VirtAddr::new(region.base.as_u64() + i as u64 * page_size);
                let _ = self.unmap_huge_leaf(va, region.size);
            }
            for frame in region.frames {
                crate::hugepage::free_hugepage(frame);
            }
        }

        // The ordered VMA index makes a hole query logarithmic. This is
        // the dominant MAP_FIXED stress pattern: after a large unmap,
        // stress-ng recreates its pages in random order. Rebuilding every
        // existing VMA for each still-empty page made that phase quadratic.
        if !regions.has_overlap(lo, hi) {
            drop(regions);
            return Ok(());
        }

        // Frames to free once the punched window's PTEs are gone from every
        // CPU. Snapshotted from each region's AUTHORITATIVE backing list
        // (`old.phys[pg]`) under the lock — NEVER read back from the PTE
        // walk. The previous shape deferred the PTE walk until AFTER the
        // lock was dropped and freed whatever frame the leaf pointed at BY
        // THEN: a sibling thread's racing MAP_FIXED mmap (punch → map_region
        // → materialize/demand-fault) could repopulate the window inside
        // that gap, and the deferred walk then tore down the NEW mapping's
        // PTE and freed ITS frame while the new region still owned it —
        // a double-free / use-after-free of a live frame, plus a region
        // whose bookkeeping says "backed" over a genuinely absent PTE
        // (an infinite-#PF trap for the old spurious-fault heuristic).
        // stress-ng --vma's concurrent mmap/munmap threads (CLONE_VM AS on
        // SMP) hit this window continuously.
        let mut to_free: Vec<crate::frame::PhysFrame> = Vec::new();
        let mut punched_pages: u64 = 0;
        {
            let old_regions = regions.drain_overlapping(lo, hi);
            let mut kept: Vec<Region> = Vec::with_capacity(old_regions.len() + 1);
            for old in old_regions {
                let rb = old.base.as_u64();
                let re = rb + old.len;
                let shared = old.perms.contains(RegionPerms::SHARED);
                let total = (old.len >> 12) as usize;
                let first = ((lo.max(rb) - rb) >> 12) as usize;
                let last = (((hi.min(re) - rb) >> 12) as usize).min(total);
                #[cfg(target_arch = "x86_64")]
                if self.root.as_u64() != 0 && first < last {
                    let start = VirtAddr::new(rb + first as u64 * 4096);
                    // SAFETY: the range is the page-aligned intersection of
                    // the live region and the punch window. The address-space
                    // region lock prevents a concurrent replacement while the
                    // range helper holds the root's PTE mutation lock once.
                    let _ = unsafe {
                        crate::x86_64::paging::unmap_4kb_local_range(
                            self.root,
                            start,
                            (last - first) as u64,
                        )
                    };
                }
                #[cfg(target_arch = "aarch64")]
                if self.root.as_u64() != 0 && first < last {
                    let start = VirtAddr::new(rb + first as u64 * 4096);
                    // SAFETY: same transaction and range proof as the x86_64
                    // arm; aarch64 performs the shareable TLBI in hardware.
                    let _ = unsafe {
                        crate::aarch64::paging::unmap_4kb_range(
                            self.root,
                            start,
                            (last - first) as u64,
                        )
                    };
                }
                for pg in first..last {
                    punched_pages += 1;
                    // The architecture range helper tore the leaf down NOW,
                    // under both the region transaction and root lock. Doing
                    // it atomically with the table update means no window
                    // exists where metadata says "free" while a stale leaf
                    // remains for racing materialize to swallow.
                    // Borrowed (SHARED) frames belong to an external
                    // registry — unmap the PTE but never free the phys.
                    if !shared {
                        if let Some(p) = old.phys.get(pg) {
                            if p.raw() != 0 {
                                to_free.push(crate::frame::PhysFrame::new(*p));
                            }
                        }
                    } else if let Some(p) = old.phys.get(pg) {
                        release_shared_phys(*p);
                    }
                }
                // Prefix [rb, lo) keeps its frames + already-installed PTEs.
                if rb < lo {
                    let n = ((lo - rb) >> 12) as usize;
                    kept.push(Region {
                        base: VirtAddr::new(rb),
                        len: (n as u64) * 4096,
                        perms: old.perms,
                        phys: old.phys[..n].to_vec(),
                    });
                }
                // Suffix [hi, re) likewise.
                if re > hi {
                    let start = ((hi - rb) >> 12) as usize;
                    kept.push(Region {
                        base: VirtAddr::new(hi),
                        len: old.len - (start as u64) * 4096,
                        perms: old.perms,
                        phys: old.phys[start..].to_vec(),
                    });
                }
            }
            for region in kept {
                assert!(regions.insert(region).is_none());
            }
        }
        drop(regions);
        // ONE cross-CPU invalidation covering the punched window, BEFORE any
        // frame is freed for reuse (same mmu_gather shape + vm_shared gating
        // as `unmap_region_pages`). This also replaces the previous PER-PAGE
        // broadcast+ack-wait (`unmap_4kb`) a CLONE_VM AS paid here — an IPI
        // round-trip per punched page under MAP_FIXED churn.
        if punched_pages > 0 {
            self.flush_region_broadcast(base, (hi - lo) >> 12);
        }
        if self.root.as_u64() != 0 {
            // `to_free` comes exclusively from `Region.phys`, whose backing
            // lists contain data frames only. The range flush above completed
            // before this batched owner drop.
            crate::frame::free_frame_batch(&to_free);
        }
        Ok(())
    }

    /// One batched cross-CPU TLB invalidation for `pages` pages starting at
    /// `base`, issued only when this AS can be TLB-resident on another CPU
    /// (CLONE_VM-shared — see the `vm_shared` field docs). Ranged broadcast
    /// for small spans; one full non-global flush past the ceiling (mirrors
    /// Linux's tlb_single_page_flush_ceiling). Callers MUST have already
    /// torn down / rewritten the covered leaf PTEs, and must call this
    /// BEFORE freeing any of the covered frames for reuse.
    fn flush_region_broadcast(&self, base: VirtAddr, pages: u64) {
        #[cfg(target_arch = "x86_64")]
        {
            const FULL_FLUSH_PAGE_CEILING: u64 = 512;
            if pages == 0 || !self.is_vm_shared() {
                return;
            }
            if pages > FULL_FLUSH_PAGE_CEILING {
                // SAFETY: CPL=0; the page-table helper already completed the
                // current CPU's local invalidation phase.
                unsafe { crate::x86_64::paging::flush_user_tlb_local() };
                crate::tlb_shootdown::shootdown_remote_full_for_tag(0);
            } else {
                crate::tlb_shootdown::shootdown_remote(
                    crate::tlb_shootdown::ShootdownRequest::for_range(0, base.as_u64(), pages),
                );
            }
        }
        // aarch64: `unmap_4kb`'s TLBI already covers the shareability
        // domain in hardware — no software broadcast needed.
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (base, pages);
        }
    }

    /// Walk a region's per-page PTEs, unmap each, and return its
    /// frame to the allocator. Used by `unmap_region` and by
    /// `Drop for AddressSpace`.
    ///
    /// # Safety
    /// `self.root` must be a valid identity-reachable PML4 / L0 root.
    /// Pages covered by `region` were previously installed via
    /// `materialize`. Concurrent access to the same region from
    /// another thread is the caller's problem (`unmap_region` holds
    /// no lock during this walk on purpose — see its comment).
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    unsafe fn unmap_region_pages(&self, region: &Region) {
        if self.root.as_u64() == 0 {
            return;
        }
        // Pass 1: tear down every leaf PTE with LOCAL invalidation only.
        // SAFETY: caller's contract (see the doc comment above).
        unsafe { self.unmap_region_leaves_local(region) };
        // Pass 2: ONE cross-CPU invalidation covering the whole region.
        // MUST land BEFORE any frame is freed for reuse — a peer CPU may
        // hold a stale TLB entry until this completes (`unmap_4kb_local`'s
        // contract). No-op unless the AS is CLONE_VM-shared: a single-
        // threaded process's stale entries can only live HERE, and the
        // per-page local INVLPGs above already dropped them.
        self.flush_region_broadcast(region.base, (region.len + 0xFFF) >> 12);
        // Pass 3: free the frames this region owns (and drop their rmap entries;
        // see free_region_frames).
        self.free_region_frames(region);
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    unsafe fn unmap_region_pages(&self, _region: &Region) {}

    /// Reclaim the resident private, unlocked, anonymous frames of this address
    /// space out from under a victim the OOM killer has already SIGKILLed,
    /// without waiting for it to schedule and run its own exit teardown.
    /// Returns the number of base pages freed. Equivalent to
    /// [`reap_anonymous_owned`](Self::reap_anonymous_owned) with
    /// `sole_owner = false` (so a still-`vm_shared` AS is left alone), reporting
    /// only the freed-page count. Prefer the `_owned` form from the reaper,
    /// which can also reap a `vm_shared` AS once it is confirmed single-owner
    /// and distinguishes "blocked, retry" from "nothing to do".
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn reap_anonymous(&self) -> usize {
        match self.reap_anonymous_owned(false) {
            crate::oom::ReapOutcome::Reaped(n) => n,
            crate::oom::ReapOutcome::Nothing | crate::oom::ReapOutcome::Blocked => 0,
        }
    }

    /// Reclaim the resident private, unlocked, anonymous frames of a SIGKILLed
    /// victim, reporting whether the pass made progress, found nothing, or was
    /// temporarily blocked and should be retried. See `crate::oom` for the whole
    /// soundness argument; in brief:
    ///
    ///   * The reaper holds an `Arc` to this AS, so the last-`Arc` `Drop`
    ///     teardown (which frees the same frames) cannot run concurrently —
    ///     no double free.
    ///   * No sibling thread may be mid-fault on this table. For a
    ///     single-threaded (`!vm_shared`) victim that holds by construction. For
    ///     a formerly-multithreaded (`vm_shared`) victim, `sole_owner` — passed
    ///     by the reaper as `Arc::strong_count(as) == 1` — proves every sibling
    ///     thread has exited and dropped its scheduler-slot `Arc`, so none is
    ///     live; a `vm_shared` victim that is not yet `sole_owner` returns
    ///     [`ReapOutcome::Blocked`] to be retried later. The region table is
    ///     taken with `try_lock` (a failure also returns `Blocked`), so no CPU
    ///     is spinning on it while the forced shootdown below waits for acks —
    ///     that would deadlock.
    ///   * A forced full user-TLB shootdown lands before any frame is freed, so
    ///     a CPU still momentarily running the doomed task cannot alias a reused
    ///     frame through a stale entry; its next access re-faults, and the
    ///     zeroed backing turns that into a fresh demand fault.
    ///
    /// SHARED (borrowed) and LOCKED regions, huge regions, and swap slots are
    /// left for the victim's own exit, matching every other teardown path.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn reap_anonymous_owned(&self, sole_owner: bool) -> crate::oom::ReapOutcome {
        use crate::oom::ReapOutcome;
        if self.root.as_u64() == 0 {
            return ReapOutcome::Nothing;
        }
        // A `vm_shared` AS may be resident on a live sibling until the LAST
        // thread exits; reap it only once the reaper is the sole `Arc` holder
        // (no scheduler slot references it => no live thread). Otherwise defer.
        if self.is_vm_shared() && !sole_owner {
            return ReapOutcome::Blocked;
        }
        let Some(mut regions) = self.regions.try_lock() else {
            // Lock transiently held; a later pass retries.
            return ReapOutcome::Blocked;
        };

        // Pass 1: tear down every reapable leaf PTE with local invalidation.
        let mut reaped_any = false;
        for r in regions.iter() {
            if r.perms.contains(RegionPerms::SHARED) || r.perms.contains(RegionPerms::LOCKED) {
                continue;
            }
            // SAFETY: identity-mapped root; the region was materialized through
            // it and the table lock pins its backing during the walk.
            unsafe { self.unmap_region_leaves_local(r) };
            reaped_any = true;
        }
        if !reaped_any {
            return ReapOutcome::Nothing;
        }

        // ONE forced full user-TLB shootdown across ALL CPUs. Unlike the
        // vm_shared-gated `flush_region_broadcast`, the reaper runs cross-task
        // and cannot assume the doomed AS is resident only on the local CPU;
        // for a formerly-`vm_shared` victim this flushes any stale entry left on
        // a CPU a now-dead thread last ran on. No CPU can be spinning on this
        // region lock (we hold it via try_lock; no live thread can contend it —
        // `!vm_shared`, or `sole_owner` proves all siblings exited), so the
        // ack-wait cannot deadlock.
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: CPL=0; the local invalidation phase completed above.
            unsafe { crate::x86_64::paging::flush_user_tlb_local() };
            crate::tlb_shootdown::shootdown_remote_full_for_tag(0);
        }

        // Pass 2: free the backing frames (allocation-free) and zero the
        // entries so the victim's own `Drop` teardown skips them — idempotent.
        let mut freed = 0usize;
        for r in regions.iter_mut() {
            if r.perms.contains(RegionPerms::SHARED) || r.perms.contains(RegionPerms::LOCKED) {
                continue;
            }
            let pages = ((r.len + 0xFFF) >> 12) as usize;
            let n = pages.min(r.phys.len());
            crate::frame::free_phys_batch(&r.phys[..n]);
            for p in r.phys[..n].iter_mut() {
                if p.raw() != 0 {
                    freed += 1;
                    *p = PhysAddr::new(0);
                }
            }
        }
        ReapOutcome::Reaped(freed)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn reap_anonymous(&self) -> usize {
        0
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn reap_anonymous_owned(&self, _sole_owner: bool) -> crate::oom::ReapOutcome {
        crate::oom::ReapOutcome::Nothing
    }

    /// Run `body` while holding this AS's region-table lock, so the crate's own
    /// tests can exercise the reaper's `try_lock`-failure (requeue) path — while
    /// the lock is held, [`reap_anonymous_owned`](Self::reap_anonymous_owned)
    /// returns [`ReapOutcome::Blocked`](crate::oom::ReapOutcome::Blocked).
    /// Test-support only; consumed by x86_64-only reaper smokes.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn with_regions_locked<R>(&self, body: impl FnOnce() -> R) -> R {
        let _guard = self.regions.lock();
        body()
    }

    /// Tear down every leaf PTE of `region` with LOCAL invalidation only
    /// (x86_64; aarch64's TLBI broadcasts in hardware). The cross-CPU
    /// shootdown is batched into ONE broadcast by the caller
    /// (`flush_region_broadcast`) — the historical per-page `unmap_4kb`
    /// broadcast + ack-wait cost thousands of IPI round-trips for a large
    /// region's teardown, seconds per exiting process.
    ///
    /// Allocation-free and bounded, so callers may hold the regions
    /// IrqSafeSpinLock across this walk (unmap_region does, to close the
    /// stale-PTE-after-table-update race).
    ///
    /// # Safety
    /// Same identity-mapping precondition as `materialize`; `self.root`
    /// must be a valid root and `region`'s pages were installed via it.
    #[cfg(target_arch = "x86_64")]
    unsafe fn unmap_region_leaves_local(&self, region: &Region) {
        let pages = (region.len + 0xFFF) >> 12;
        // SAFETY: contract documented on the function. The range helper keeps
        // the existing per-leaf walk + INVLPG semantics but acquires the
        // per-root page-table mutation lock once for the complete region.
        let _ =
            unsafe { crate::x86_64::paging::unmap_4kb_local_range(self.root, region.base, pages) };
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn unmap_region_leaves_local(&self, region: &Region) {
        let pages = (region.len + 0xFFF) >> 12;
        // SAFETY: see the x86_64 variant. aarch64's helper broadcasts the
        // complete range in hardware with one barrier pair.
        let _ = unsafe { crate::aarch64::paging::unmap_4kb_range(self.root, region.base, pages) };
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    unsafe fn unmap_region_leaves_local(&self, _region: &Region) {}

    /// Install every resident leaf of one already-validated region without
    /// consulting or locking the region table. Callers hold the table lock so
    /// backing, permissions, and ownership cannot change during the walk.
    #[cfg(target_arch = "x86_64")]
    unsafe fn install_region_leaves_local(&self, region: &Region) -> Result<(), AddressSpaceError> {
        use crate::x86_64::paging::{map_4kb_scatter_range, PtFlags};
        if region.perms.prot_only().0 == 0 {
            return Ok(());
        }
        let cow_counts = region
            .perms
            .contains(RegionPerms::COW)
            .then(|| crate::frame::cow::count_batch(&region.phys));
        // SAFETY: caller guarantees a live root and validated disjoint region;
        // the scatter list is authoritative backing and the paging helper
        // serialises the complete run with one per-root lock acquisition.
        unsafe {
            map_4kb_scatter_range(self.root, region.base, &region.phys, |index, phys| {
                let mut flags = PtFlags::USER;
                let cow_count = cow_counts.as_ref().map_or(0, |counts| counts[index]);
                if user_page_writable_at_count(region.perms, phys, cow_count) {
                    flags |= PtFlags::WRITABLE;
                }
                if !region.perms.contains(RegionPerms::EXEC) {
                    flags |= PtFlags::NO_EXEC;
                }
                flags
            })
        }
        .map_err(|_| AddressSpaceError::OutOfRange)
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn install_region_leaves_local(&self, region: &Region) -> Result<(), AddressSpaceError> {
        use crate::aarch64::paging::{map_4kb_scatter_range, PtFlags};
        if region.perms.prot_only().0 == 0 {
            return Ok(());
        }
        let cow_counts = region
            .perms
            .contains(RegionPerms::COW)
            .then(|| crate::frame::cow::count_batch(&region.phys));
        // SAFETY: same contract as the x86_64 implementation; the helper
        // holds the root lock and publishes the complete scatter run once.
        unsafe {
            map_4kb_scatter_range(self.root, region.base, &region.phys, |index, phys| {
                let cow_count = cow_counts.as_ref().map_or(0, |counts| counts[index]);
                let mut flags = if user_page_writable_at_count(region.perms, phys, cow_count) {
                    PtFlags::AP_RW_EL0
                } else {
                    PtFlags::AP_RO_EL0
                };
                if !region.perms.contains(RegionPerms::EXEC) {
                    flags = flags | PtFlags::UXN | PtFlags::PXN;
                }
                flags
            })
        }
        .map_err(|_| AddressSpaceError::OutOfRange)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    unsafe fn install_region_leaves_local(
        &self,
        _region: &Region,
    ) -> Result<(), AddressSpaceError> {
        Err(AddressSpaceError::NotImplemented)
    }

    /// Free the frames `region` owns, consulting the region's OWN backing
    /// list. We deliberately IGNORE what the PTE walk returned and free
    /// `region.phys[i]` instead — the region's backing list is
    /// authoritative, the PTE can lag it. `cow_split_on_write` repoints
    /// `region.phys[i]` to the fresh private frame, but the PTE is only
    /// rewritten by the SEPARATE `remap_page` (the #PF handler calls both;
    /// any caller that splits without remapping leaves the PTE pointing at
    /// the OLD, already-freed frame). Freeing the PTE target there would
    /// double-free the old frame — the root of the "marginal-buddy"
    /// corruption. Freeing `region.phys[i]` frees exactly the frame this
    /// region owns, regardless of PTE drift.
    ///
    /// Borrowed (SHARED) frames belong to an external registry — never
    /// freed here. Callers must have completed the cross-CPU flush first.
    fn free_region_frames(&self, region: &Region) {
        // Drop this region's reverse-map entries (frame → (this AS, va)) before
        // the frames are freed/released. This is the single teardown choke point
        // that BOTH `unmap_region` and `unmap_region_pages` route through.
        for (i, p) in region.phys.iter().enumerate() {
            if p.raw() != 0 {
                let va = VirtAddr::new(region.base.as_u64() + (i as u64) * 4096);
                crate::rmap::remove(*p, self.root, va);
            }
        }
        if region.perms.contains(RegionPerms::SHARED) {
            for phys in &region.phys {
                release_shared_phys(*phys);
            }
            return;
        }
        let pages = ((region.len + 0xFFF) >> 12) as usize;
        // Hand the backing list straight to the allocation-free batched free.
        // Collecting a region-sized `Vec<PhysFrame>` here allocated memory
        // proportional to the region in order to *free* memory, and panicked
        // the kernel when a large teardown ran with the frame pool already
        // exhausted. `free_phys_batch` windows the list with bounded stack
        // storage and skips zero/low-reserved entries internally.
        //
        // No `__pagetable_is_registered` guard here: a region's backing list
        // only ever holds DATA frames. Leaf retirement and the cross-CPU TLB
        // flush completed before this call, so the allocator may now drop all
        // owners while locking each touched COW shard once per window.
        let phys = &region.phys[..pages.min(region.phys.len())];
        crate::frame::free_phys_batch(phys);
    }

    /// Number of mapped regions.
    #[inline]
    pub fn region_count(&self) -> usize {
        self.regions.lock().len() + self.huge_regions.lock().len()
    }

    /// Return whether `vaddr` belongs to a registered base-page or hardware
    /// huge-page region.
    pub fn contains_address(&self, vaddr: VirtAddr) -> bool {
        let v = vaddr.as_u64();
        if self.huge_regions.lock().iter().any(|region| {
            let base = region.base.as_u64();
            v >= base && v < base.saturating_add(region.len)
        }) {
            return true;
        }
        self.regions.lock().containing(v).is_some()
    }

    /// Return the hardware leaf size covering `vaddr`.
    ///
    /// This reports registered mapping metadata without exposing physical
    /// backing or transferring frame ownership.
    pub fn mapped_page_size(&self, vaddr: VirtAddr) -> Option<u64> {
        let v = vaddr.as_u64();
        if let Some(region) = self.huge_regions.lock().iter().find(|region| {
            let base = region.base.as_u64();
            v >= base && v < base.saturating_add(region.len)
        }) {
            return Some(match region.size {
                crate::hugepage::HugeSize::M2 => crate::hugepage::HUGEPAGE_2M_BYTES,
                crate::hugepage::HugeSize::G1 => crate::hugepage::HUGEPAGE_1G_BYTES,
            });
        }
        self.regions.lock().containing(v).map(|_| 4096)
    }

    /// Return one Linux-mincore-shaped residency byte per base page.
    ///
    /// The complete rounded range is sampled under the huge -> regular region
    /// locks, so a racing VMA operation cannot mix metadata generations.
    /// Hardware huge leaves are resident for every base-page equivalent;
    /// lazy base-page slots report zero. Any unmapped page rejects the whole
    /// request without exposing a partial vector.
    pub fn residency_range(&self, base: VirtAddr, len: u64) -> Result<Vec<u8>, AddressSpaceError> {
        let lo = base.as_u64();
        if lo & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        let rounded_len = len
            .checked_add(0xFFF)
            .map(|value| value & !0xFFF)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let hi = lo
            .checked_add(rounded_len)
            .filter(|end| *end <= Self::USER_HALF_END)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let pages: usize = (rounded_len >> 12)
            .try_into()
            .map_err(|_| AddressSpaceError::OutOfRange)?;
        // Bit 7 is an internal "mapped" marker; bit 0 is the Linux residency
        // result. Keeping both in one vector avoids a second pages-sized
        // allocation on this observability path.
        let mut state = alloc::vec![0u8; pages];
        let huge = self.huge_regions.lock();
        let regular = self.regions.lock();
        regular.for_each_overlapping(lo, hi, |region| {
            let rb = region.base.as_u64();
            let re = rb.saturating_add(region.len);
            let begin = lo.max(rb);
            let end = hi.min(re);
            if begin >= end {
                return;
            }
            let first = ((begin - rb) >> 12) as usize;
            let last = ((end - rb) >> 12) as usize;
            for index in first..last {
                let out = ((rb + index as u64 * 4096 - lo) >> 12) as usize;
                state[out] = 0x80 | u8::from(region.phys[index].raw() != 0);
            }
        });
        for region in huge.iter() {
            let rb = region.base.as_u64();
            let re = rb.saturating_add(region.len);
            let begin = lo.max(rb);
            let end = hi.min(re);
            if begin >= end {
                continue;
            }
            let first = ((begin - lo) >> 12) as usize;
            let last = ((end - lo) >> 12) as usize;
            state[first..last].fill(0x81);
        }
        drop(regular);
        drop(huge);
        if state.iter().any(|value| value & 0x80 == 0) {
            return Err(AddressSpaceError::Unmapped);
        }
        for value in &mut state {
            *value &= 1;
        }
        Ok(state)
    }

    /// Copy resident user bytes through the kernel direct map without taking a
    /// page fault. Stops at the first unmapped or lazily unbacked byte.
    ///
    /// This is suitable for hard-IRQ sampling: it consults authoritative
    /// region ownership under the address-space locks and never dereferences
    /// the userspace virtual address directly.
    pub fn copy_user_bytes_nofault(&self, vaddr: VirtAddr, dst: &mut [u8]) -> usize {
        let mut copied = 0usize;
        while copied < dst.len() {
            let address = vaddr.as_u64().saturating_add(copied as u64);
            let base_regions = self.regions.lock();
            if let Some(region) = base_regions.containing(address) {
                let offset = address - region.base.as_u64();
                let page = (offset / 4096) as usize;
                let in_page = (offset % 4096) as usize;
                let Some(phys) = region
                    .phys
                    .get(page)
                    .copied()
                    .filter(|phys| phys.as_u64() != 0)
                else {
                    break;
                };
                let amount = (4096 - in_page).min(dst.len() - copied);
                // SAFETY: the region lock retains ownership of this resident
                // frame; PhysAddr::kernel_ptr addresses its direct mapping.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        PhysAddr::new(phys.as_u64().saturating_add(in_page as u64))
                            .kernel_ptr::<u8>(),
                        dst[copied..].as_mut_ptr(),
                        amount,
                    );
                }
                copied += amount;
                continue;
            }
            drop(base_regions);

            let huge_regions = self.huge_regions.lock();
            let Some(region) = huge_regions.iter().find(|region| {
                address >= region.base.as_u64()
                    && address < region.base.as_u64().saturating_add(region.len)
            }) else {
                break;
            };
            let offset = address - region.base.as_u64();
            let frame_size = region.frames.first().map_or(0, |frame| frame.size_bytes());
            if frame_size == 0 {
                break;
            }
            let frame = (offset / frame_size) as usize;
            let in_frame = offset % frame_size;
            let Some(backing) = region.frames.get(frame) else {
                break;
            };
            let amount = ((frame_size - in_frame) as usize).min(dst.len() - copied);
            // SAFETY: the huge-region lock retains this owned backing frame.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    PhysAddr::new(backing.phys().saturating_add(in_frame)).kernel_ptr::<u8>(),
                    dst[copied..].as_mut_ptr(),
                    amount,
                );
            }
            copied += amount;
        }
        copied
    }

    /// Snapshot region-level NUMA residency without cloning or transferring
    /// ownership of any physical backing.
    pub fn numa_regions_snapshot(&self) -> Vec<NumaRegionSnapshot> {
        let mut out = Vec::new();
        {
            let huge = self.huge_regions.lock();
            out.reserve(huge.len());
            for region in huge.iter() {
                let page_bytes = match region.size {
                    crate::hugepage::HugeSize::M2 => crate::hugepage::HUGEPAGE_2M_BYTES,
                    crate::hugepage::HugeSize::G1 => crate::hugepage::HUGEPAGE_1G_BYTES,
                };
                let pages_per_leaf = page_bytes >> 12;
                let mut node_pages = [0u64; crate::frame::MAX_NUMA_NODES];
                for frame in &region.frames {
                    let node = frame.node();
                    node_pages[node] = node_pages[node].saturating_add(pages_per_leaf);
                }
                out.push(NumaRegionSnapshot {
                    base: region.base,
                    len: region.len,
                    perms: region.perms,
                    kernel_page_kb: page_bytes >> 10,
                    resident_pages: region.frames.len() as u64 * pages_per_leaf,
                    node_pages,
                });
            }
        }
        {
            let regions = self.regions.lock();
            out.reserve(regions.len());
            for region in regions.iter() {
                let mut node_pages = [0u64; crate::frame::MAX_NUMA_NODES];
                let mut resident_pages = 0u64;
                for phys in &region.phys {
                    if phys.raw() == 0 {
                        continue;
                    }
                    // SAFETY: a non-zero Region backing slot denotes a live
                    // physical frame owned or borrowed by this address space.
                    let node = unsafe { crate::frame::narf_phys_node(phys.raw()) };
                    node_pages[node] = node_pages[node].saturating_add(1);
                    resident_pages += 1;
                }
                out.push(NumaRegionSnapshot {
                    base: region.base,
                    len: region.len,
                    perms: region.perms,
                    kernel_page_kb: 4,
                    resident_pages,
                    node_pages,
                });
            }
        }
        out.sort_by_key(|region| region.base.as_u64());
        out
    }

    /// Claim the slow portion of one anonymous/file demand fault.
    ///
    /// `repair_backed` runs under the region lock when metadata already owns a
    /// frame but the leaf is absent or stale.  An unbacked page receives a
    /// unique ticket; allocation, zeroing, and filesystem callbacks then run
    /// without this address space's IRQ-disabling lock.  A peer faulting the
    /// same page observes `InProgress`, while a different page gets its own
    /// ticket and can progress concurrently.
    fn claim_demand_page(
        &self,
        v: u64,
        repair_backed: impl FnOnce(PhysAddr, RegionPerms) -> Result<(), AddressSpaceError>,
    ) -> Result<DemandPageClaim, AddressSpaceError> {
        use core::sync::atomic::Ordering;

        let mut regions = self.regions.lock();
        let region = regions.containing(v).ok_or(AddressSpaceError::Unmapped)?;
        let rb = region.base.as_u64();
        if region.perms.prot_only().0 == 0 {
            return Err(AddressSpaceError::Unmapped);
        }
        let index = ((v - rb) >> 12) as usize;
        let phys = *region
            .phys
            .get(index)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let perms = region.perms;
        if phys.raw() != 0 {
            repair_backed(phys, perms)?;
            return Ok(DemandPageClaim::Resolved);
        }
        if regions.demand_pages.contains_key(&v) {
            return Ok(DemandPageClaim::InProgress);
        }
        let ticket = NEXT_DEMAND_TICKET.fetch_add(1, Ordering::Relaxed);
        regions.demand_pages.insert(v, ticket);
        Ok(DemandPageClaim::Owner {
            ticket,
            file_backed: perms.contains(RegionPerms::FILE_DEMAND),
        })
    }

    /// Publish a claimed frame and install its leaf as one region-lock
    /// transaction.  `false` means a concurrent VMA removal cancelled the
    /// ticket; the caller still owns anonymous backing and must free it.
    fn finish_demand_page(
        &self,
        v: u64,
        ticket: u64,
        phys: PhysAddr,
        install: impl FnOnce(PhysAddr, RegionPerms) -> Result<(), AddressSpaceError>,
    ) -> Result<bool, AddressSpaceError> {
        let mut regions = self.regions.lock();
        if regions.demand_pages.get(&v).copied() != Some(ticket) {
            return Ok(false);
        }
        let Some(region) = regions.containing_mut(v) else {
            regions.demand_pages.remove(&v);
            return Ok(false);
        };
        let rb = region.base.as_u64();
        let index = ((v - rb) >> 12) as usize;
        let Some(slot) = region.phys.get_mut(index) else {
            regions.demand_pages.remove(&v);
            return Ok(false);
        };
        if slot.raw() != 0 {
            regions.demand_pages.remove(&v);
            return Ok(false);
        }
        *slot = phys;
        let perms = region.perms;
        let result = install(phys, perms);
        regions.demand_pages.remove(&v);
        result.map(|()| true)
    }

    fn cancel_demand_page(&self, v: u64, ticket: u64) {
        let mut regions = self.regions.lock();
        if regions.demand_pages.get(&v).copied() == Some(ticket) {
            regions.demand_pages.remove(&v);
        }
    }

    /// Append cold private-anonymous reclaim candidates from this address
    /// space to `out`, stopping once the emitted runs cover at least
    /// `max_pages` resident pages (or a fixed per-call run cap is hit).
    ///
    /// Emits page-aligned contiguous runs of resident (`phys != 0`),
    /// non-transitioning pages drawn only from regions the swap executor
    /// accepts — private anonymous mappings (not `SHARED` / `FILE_DEMAND` /
    /// `COW` / `LOCKED`) with non-zero prot — so the runs feed
    /// [`crate::reclaim::plan_reclaim_ranges`] and then
    /// [`Self::swap_out_reclaim_plan`] without the executor rejecting them.
    /// `mapcount` is 1 and `expected_free_pages` equals the run length because
    /// a private anonymous page has a single mapping, so evicting it frees its
    /// frame.
    ///
    /// Aging is a CLOCK / second-chance pass over the leaf accessed (A) bits
    /// (see [`crate::x86_64::paging::test_and_clear_accessed`]): a page whose A
    /// bit is set was touched since the previous scan, so it is spared and its
    /// bit cleared; only a page still cold (A clear) since the last pass becomes
    /// a candidate. Every emitted candidate is therefore in the coldest tier, so
    /// `age` is 0 and the planner orders by yield then address. Because the scan
    /// clears A bits it is NOT read-only — it mutates leaf PTEs (an approximate
    /// hint, no TLB shootdown; see the helper) — but it only reads the region
    /// table and fills a fixed stack buffer under the region lock, copying into
    /// `out` after releasing it, so it never allocates while holding that lock.
    #[cfg(target_arch = "x86_64")]
    pub fn collect_anon_reclaim_candidates(
        &self,
        out: &mut Vec<crate::reclaim::ReclaimRangeCandidate>,
        max_pages: usize,
    ) {
        use crate::reclaim::ReclaimRangeCandidate;
        if max_pages == 0 {
            return;
        }
        // Per-call cap on distinct runs. Anonymous regions are usually
        // contiguous so a handful of runs cover them; a heavily fragmented
        // space is bounded here and revisited on kswapd's next pass. A fixed
        // buffer keeps the scan allocation-free under the region lock.
        const MAX_RUNS: usize = 64;
        let mut scratch: [Option<ReclaimRangeCandidate>; MAX_RUNS] = [None; MAX_RUNS];
        let mut n = 0usize;
        let mut collected = 0usize;
        {
            let table = self.regions.lock();
            'regions: for region in table.iter() {
                // Match swap_out_private_batch's eligibility exactly.
                if region.perms.contains(RegionPerms::LOCKED)
                    || region.perms.contains(RegionPerms::SHARED)
                    || region.perms.contains(RegionPerms::FILE_DEMAND)
                    || region.perms.contains(RegionPerms::COW)
                    || region.perms.prot_only().0 == 0
                {
                    continue;
                }
                let npages = region.phys.len();
                let root = self.root;
                let mut i = 0usize;
                while i < npages {
                    let va = region.base.as_u64() + (i as u64) * 4096;
                    // Skip holes (unbacked) and pages mid-swap-transition — no
                    // agable PTE there.
                    if region.phys[i].raw() == 0 || table.swap_pages.contains_key(&va) {
                        i += 1;
                        continue;
                    }
                    // CLOCK reference step: clear+read the leaf accessed bit. A
                    // warm page (A was set) is given a second chance — its bit is
                    // cleared and it is skipped this pass; only a cold page
                    // (untouched since the previous pass) starts a reclaim run.
                    // SAFETY: `root` is this space's live identity-reachable root.
                    let cold = unsafe {
                        crate::x86_64::paging::test_and_clear_accessed(root, VirtAddr::new(va))
                    } == Some(false);
                    if !cold {
                        i += 1;
                        continue;
                    }
                    // Extend a maximal cold run, ageing each page as we go.
                    let run_base = va;
                    let mut run_len = 1usize;
                    i += 1;
                    while i < npages && collected + run_len < max_pages {
                        let cva = region.base.as_u64() + (i as u64) * 4096;
                        if region.phys[i].raw() == 0 || table.swap_pages.contains_key(&cva) {
                            break;
                        }
                        // SAFETY: `root` is this space's live identity-reachable root.
                        let cold = unsafe {
                            crate::x86_64::paging::test_and_clear_accessed(root, VirtAddr::new(cva))
                        } == Some(false);
                        if !cold {
                            // Warm page: its A-bit was just cleared (second
                            // chance). Consume it so the outer loop doesn't
                            // re-examine the now-cold bit and wrongly include it.
                            i += 1;
                            break;
                        }
                        run_len += 1;
                        i += 1;
                    }
                    scratch[n] = Some(ReclaimRangeCandidate {
                        address_space_root: self.root,
                        base: VirtAddr::new(run_base),
                        pages: run_len,
                        mapcount: 1,
                        expected_free_pages: run_len,
                        age: 0,
                        locked: false,
                    });
                    n += 1;
                    collected += run_len;
                    if n == MAX_RUNS || collected >= max_pages {
                        break 'regions;
                    }
                }
            }
        }
        out.extend(scratch.iter().take(n).filter_map(|c| *c));
    }

    /// Swap one bounded run of private resident pages with a single backend
    /// vector operation and one TLB retirement.
    ///
    /// The region table records `Evicting` before backend I/O begins. On PTE
    /// commit the swap layer calls back before invalidation/free, allowing this
    /// method to clear authoritative `Region::phys` ownership and publish
    /// `Swapped` atomically under the region lock. Shared, COW, file-backed,
    /// locked, lazy, and already-transitioning pages are rejected.
    ///
    /// # Safety
    ///
    /// `self.root` must be a live identity-reachable root and every selected
    /// page must remain owned by this address space for the transaction. The
    /// internal transition records enforce the latter against VMA operations.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn swap_out_private_batch(
        &self,
        base: VirtAddr,
        pages: usize,
    ) -> Result<usize, crate::swap::SwapError> {
        use crate::swap::{SwapError, SwapVictim};

        if pages == 0 || pages > crate::swap::swap_batch_pages() || base.as_u64() & 0xfff != 0 {
            return Err(SwapError::InvalidBatch);
        }
        let mut victims = Vec::with_capacity(pages);
        {
            let mut table = self.regions.lock();
            for page in 0..pages {
                let offset = (page as u64)
                    .checked_mul(4096)
                    .ok_or(SwapError::InvalidBatch)?;
                let va = base
                    .as_u64()
                    .checked_add(offset)
                    .ok_or(SwapError::InvalidBatch)?;
                if table.swap_pages.contains_key(&va) {
                    return Err(SwapError::InvalidBatch);
                }
                let region = table.containing(va).ok_or(SwapError::MapFailed)?;
                if region.perms.contains(RegionPerms::LOCKED)
                    || region.perms.contains(RegionPerms::SHARED)
                    || region.perms.contains(RegionPerms::FILE_DEMAND)
                    || region.perms.contains(RegionPerms::COW)
                    || region.perms.prot_only().0 == 0
                {
                    return Err(SwapError::InvalidBatch);
                }
                let index = ((va - region.base.as_u64()) >> 12) as usize;
                let phys = *region.phys.get(index).ok_or(SwapError::MapFailed)?;
                if phys.raw() == 0 {
                    return Err(SwapError::InvalidBatch);
                }
                victims.push((
                    SwapVictim {
                        pml4_phys: self.root,
                        virt: VirtAddr::new(va),
                    },
                    phys,
                ));
            }
            for (victim, phys) in &victims {
                table
                    .swap_pages
                    .insert(victim.virt.as_u64(), SwapPageState::Evicting(*phys));
            }
        }

        let bare_victims: Vec<SwapVictim> = victims.iter().map(|(victim, _)| *victim).collect();
        // SAFETY: the transition table above pins metadata ownership. The
        // callback clears it before the swap primitive invalidates/frees.
        let result = unsafe {
            crate::swap::swap_out_batch_owned(&bare_victims, |resolved| {
                let mut table = self.regions.lock();
                for (victim, phys) in resolved {
                    let va = victim.virt.as_u64();
                    assert_eq!(
                        table.swap_pages.get(&va),
                        Some(&SwapPageState::Evicting(*phys)),
                        "swap ownership transition changed before PTE commit"
                    );
                    {
                        let region = table
                            .containing_mut(va)
                            .expect("swap victim region disappeared during transaction");
                        let index = ((va - region.base.as_u64()) >> 12) as usize;
                        assert_eq!(region.phys[index], *phys);
                        region.phys[index] = PhysAddr::new(0);
                    }
                    // Evicted to swap → no longer resident here; drop its rmap.
                    crate::rmap::remove(*phys, self.root, VirtAddr::new(va));
                    table.swap_pages.insert(va, SwapPageState::Swapped);
                }
            })
        };

        // Remove reservations for an aborted transaction or for a backed page
        // whose leaf was already absent and therefore was skipped.
        let mut table = self.regions.lock();
        for (victim, phys) in victims {
            if table.swap_pages.get(&victim.virt.as_u64()) == Some(&SwapPageState::Evicting(phys)) {
                table.swap_pages.remove(&victim.virt.as_u64());
            }
        }
        result
    }

    /// Execute this address space's selected PSS reclaim ranges with live VMA
    /// ownership integration and explicit partial progress.
    ///
    /// Large ranges are split at the runtime swap batch ceiling. A plan that
    /// names another root, shared/COW/locked backing, or malformed metadata
    /// stops at the first such submission and reports the pages already
    /// completed; earlier batches remain valid swap entries.
    ///
    /// # Safety
    ///
    /// `self.root` must remain a live identity-reachable root for the pass.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn swap_out_reclaim_plan(
        &self,
        plan: &crate::reclaim::ReclaimBatchPlan,
    ) -> crate::swap::SwapBatchReport {
        let mut report = crate::swap::SwapBatchReport {
            planned_pages: plan
                .ranges
                .iter()
                .fold(0usize, |sum, range| sum.saturating_add(range.pages)),
            ..crate::swap::SwapBatchReport::default()
        };
        let batch_pages = crate::swap::swap_batch_pages();
        for range in &plan.ranges {
            if range.address_space_root != self.root {
                report.error = Some(crate::swap::SwapError::InvalidBatch);
                return report;
            }
            let mut offset = 0usize;
            while offset < range.pages {
                let pages = (range.pages - offset).min(batch_pages);
                let byte_offset = match (offset as u64).checked_mul(4096) {
                    Some(offset) => offset,
                    None => {
                        report.error = Some(crate::swap::SwapError::InvalidBatch);
                        return report;
                    }
                };
                let base = match range.base.as_u64().checked_add(byte_offset) {
                    Some(base) => VirtAddr::new(base),
                    None => {
                        report.error = Some(crate::swap::SwapError::InvalidBatch);
                        return report;
                    }
                };
                report.attempted_pages = report.attempted_pages.saturating_add(pages);
                report.submissions = report.submissions.saturating_add(1);
                // SAFETY: forwarded live-root contract; the callee validates
                // and transactionally pins every Region backing slot.
                match unsafe { self.swap_out_private_batch(base, pages) } {
                    Ok(done) => report.swapped_pages = report.swapped_pages.saturating_add(done),
                    Err(error) => {
                        report.error = Some(error);
                        return report;
                    }
                }
                offset += pages;
            }
        }
        report
    }

    /// Demand-paging entry point — called from the user-mode #PF
    /// handler when CR2 (x86_64) / FAR_EL1 (aarch64) lands inside
    /// a known region whose `phys[i]` is the zero sentinel
    /// (lazy-allocated). Allocates a fresh zeroed frame, records
    /// it in the region's `phys` slot, and installs the leaf PTE
    /// with the region's perms.
    ///
    /// In a [`RegionPerms::FILE_DEMAND`] region the frame comes from the
    /// backing file instead — see [`install_file_fault_hook`] — and the
    /// region does not own it.
    ///
    /// Returns `Ok(())` on a successful page-in (caller resumes
    /// the faulting instruction). Returns `Unmapped` if no
    /// region contains `vaddr` (genuine SEGV — caller falls
    /// through to its panic / signal path), which is also how a
    /// file that refuses the fault surfaces. Returns
    /// `AlignmentMismatch` if the slot was already backed
    /// (spurious fault — usually a TLB shootdown race; safe to
    /// retry from the trap).
    ///
    /// # Safety
    /// - Identity-map of low 4 GiB must be live (used to zero
    ///   the fresh frame and walk the page tables).
    /// - `self.root` must be a valid page-table root for the AS
    ///   currently active on this CPU (caller's CR3 / TTBR0).
    /// - Frame allocator must be initialised.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn demand_alloc_page(&self, vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
        use crate::x86_64::paging::{map_4kb, MapError, PtFlags};
        let v = vaddr.as_u64() & !0xFFFu64;
        // Swap faults are resolved before anonymous/file demand allocation.
        // Evicting/Loading means another CPU owns the transition; returning Ok
        // retries the instruction until that bounded batch publishes a leaf.
        let swap_requests = {
            let mut table = self.regions.lock();
            match table.swap_pages.get(&v).copied() {
                Some(SwapPageState::Evicting(_)) | Some(SwapPageState::Loading) => return Ok(()),
                Some(SwapPageState::Swapped) => {
                    let region = table.containing(v).ok_or(AddressSpaceError::Unmapped)?;
                    let index = ((v - region.base.as_u64()) >> 12) as usize;
                    if region.phys.get(index).is_none_or(|phys| phys.raw() != 0) {
                        return Err(AddressSpaceError::NotImplemented);
                    }
                    let mut flags = PtFlags::USER;
                    if region.perms.contains(RegionPerms::WRITE) {
                        flags |= PtFlags::WRITABLE;
                    }
                    if !region.perms.contains(RegionPerms::EXEC) {
                        flags |= PtFlags::NO_EXEC;
                    }
                    // Read-ahead consecutive swapped leaves in this VMA. The
                    // faulting page is first, followed by increasing VAs, so
                    // a sequential workload consumes the complete contiguous
                    // slot run with one backend/PTE transaction.
                    let region_end = region.base.as_u64().saturating_add(region.len);
                    let mut requests = Vec::with_capacity(crate::swap::swap_batch_pages());
                    let mut cursor = v;
                    while cursor < region_end && requests.len() < crate::swap::swap_batch_pages() {
                        if table.swap_pages.get(&cursor) != Some(&SwapPageState::Swapped) {
                            break;
                        }
                        requests.push(crate::swap::SwapInRequest {
                            pml4_phys: self.root,
                            virt: VirtAddr::new(cursor),
                            flags,
                        });
                        cursor = cursor.saturating_add(4096);
                    }
                    for request in &requests {
                        table
                            .swap_pages
                            .insert(request.virt.as_u64(), SwapPageState::Loading);
                    }
                    Some(requests)
                }
                None => None,
            }
        };
        if let Some(requests) = swap_requests {
            let loaded = crate::swap::swap_in_batch_owned(&requests, |frames| {
                let mut table = self.regions.lock();
                for (request, phys) in requests.iter().zip(frames) {
                    let va = request.virt.as_u64();
                    assert_eq!(
                        table.swap_pages.get(&va),
                        Some(&SwapPageState::Loading),
                        "swap-in ownership transition changed before publish"
                    );
                    {
                        let region = table
                            .containing_mut(va)
                            .expect("swap-in region disappeared during transaction");
                        let index = ((va - region.base.as_u64()) >> 12) as usize;
                        assert_eq!(region.phys[index], PhysAddr::new(0));
                        region.phys[index] = *phys;
                    }
                    // Faulted back in and resident again → re-record its rmap.
                    crate::rmap::add(*phys, self.root, VirtAddr::new(va));
                    table.swap_pages.remove(&va);
                }
            });
            if loaded.is_ok() {
                return Ok(());
            }
            let mut table = self.regions.lock();
            for request in requests {
                let va = request.virt.as_u64();
                if table.swap_pages.get(&va) == Some(&SwapPageState::Loading) {
                    table.swap_pages.insert(va, SwapPageState::Swapped);
                }
            }
            return Err(AddressSpaceError::OutOfRange);
        }
        let claim = self.claim_demand_page(v, |phys, perms| {
            // Already backed, yet this CPU took a not-present #PF for it.
            // Two distinct causes, distinguished by whether the leaf PTE
            // in memory is actually present:
            //
            // (a) Leaf PRESENT — a peer CPU demand-faulted this page
            //     and, installing its leaf, allocated a fresh
            //     intermediate page-table page; THIS CPU's paging-
            //     structure cache still holds the pre-fault "not
            //     present" intermediate entry (x86 issues no shootdown
            //     for a not-present→present transition). INVLPG flushes
            //     this CPU's TLB + walk caches; the retry re-walks and
            //     observes the present PTE. (Before this branch existed
            //     the spurious fault fell through to try_grow_stack →
            //     fatal — the SMP-only mallocng heap crash.)
            //
            // (b) Leaf ABSENT — the bookkeeping says "backed" but the
            //     page table genuinely has no entry. Reachable when a
            //     racing VMA op strips the leaf after this region (or a
            //     replacement mapping) was registered — e.g. the
            //     map_region→materialize gap in sys_mmap, or a sibling
            //     thread's munmap/MAP_FIXED overlapping teardown.
            //     Blindly returning Ok here (the old shape) made the
            //     faulting instruction retry against a still-absent PTE
            //     forever: an unkillable, silent infinite-#PF loop —
            //     the stress-ng --vma SMP wedge. Self-heal instead:
            //     install the leaf for the frame the region owns.
            let va = VirtAddr::new(v);
            // SAFETY: `self.root` is this AS's valid live root; translate
            // only reads the tables through the identity map.
            if unsafe { crate::x86_64::paging::translate(self.root, va) }.is_some() {
                // SAFETY: INVLPG is always safe; `v` is the page-aligned
                // faulting VA whose leaf PTE this AS owns.
                unsafe {
                    crate::x86_64::paging::invlpg(va);
                }
                return Ok(());
            }
            let mut flags = PtFlags::USER;
            if user_page_writable(perms, phys) {
                flags |= PtFlags::WRITABLE;
            }
            if !perms.contains(RegionPerms::EXEC) {
                flags |= PtFlags::NO_EXEC;
            }
            // SAFETY: identity map + AS live (active CR3's #PF handler);
            // `phys` is the frame this region owns for the page.
            match unsafe { map_4kb(self.root, va, phys, flags) } {
                Ok(()) | Err(MapError::AlreadyMapped) => Ok(()),
                Err(_) => Err(AddressSpaceError::NotImplemented),
            }
        })?;
        let DemandPageClaim::Owner {
            ticket,
            file_backed,
        } = claim
        else {
            return Ok(());
        };

        // The ticket, not the region lock, excludes a duplicate slow path for
        // this page.  Other pages in the same CLONE_VM address space can now
        // allocate/zero or enter their backing file in parallel.
        let phys = if file_backed {
            match file_fault_frame(v) {
                Some(phys) => PhysAddr::new(phys),
                None => {
                    self.cancel_demand_page(v, ticket);
                    return Err(AddressSpaceError::Unmapped);
                }
            }
        } else {
            let frame = match crate::mempolicy::alloc_frame_policied(crate::frame::local_node()) {
                Ok(frame) => frame,
                Err(_) => {
                    self.cancel_demand_page(v, ticket);
                    return Err(AddressSpaceError::OutOfRange);
                }
            };
            let phys = frame.start_address();
            // SAFETY: identity-mapped DMA-equivalent; the frame is exclusively
            // owned by this ticket until finish_demand_page publishes it.
            unsafe {
                core::ptr::write_bytes(phys.raw() as *mut u8, 0, 4096);
            }
            phys
        };

        let published = self.finish_demand_page(v, ticket, phys, |phys, perms| {
            let mut flags = PtFlags::USER;
            if user_page_writable(perms, phys) {
                flags |= PtFlags::WRITABLE;
            }
            if !perms.contains(RegionPerms::EXEC) {
                flags |= PtFlags::NO_EXEC;
            }
            // SAFETY: finish_demand_page holds the authoritative region lock;
            // `phys` has just become this page's backing and the root is live.
            match unsafe { map_4kb(self.root, VirtAddr::new(v), phys, flags) } {
                Ok(()) | Err(MapError::AlreadyMapped) => Ok(()),
                Err(_) => Err(AddressSpaceError::NotImplemented),
            }
        })?;
        if published {
            // The fresh frame is now mapped + owned at `v`; record its rmap.
            crate::rmap::add(phys, self.root, VirtAddr::new(v));
        } else {
            // The ticket was cancelled before publication, so ownership never
            // left this fault path. A file hook supplies one external alias
            // reference, balanced through the normal shared release hook.
            if file_backed {
                release_shared_phys(phys);
            } else {
                crate::frame::free_frame(crate::frame::PhysFrame::new(phys));
            }
        }
        Ok(())
    }

    /// # Safety
    /// - The low-memory identity map must be live (used to zero the fresh
    ///   frame and walk the translation tables).
    /// - `self.root` must be a valid `TTBR0_EL1` root for the AS currently
    ///   active on this CPU.
    /// - The frame allocator must be initialised.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn demand_alloc_page(&self, vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
        use crate::aarch64::paging::{map_4kb, MapError, PtFlags};
        let v = vaddr.as_u64() & !0xFFFu64;
        let claim = self.claim_demand_page(v, |phys, perms| {
            // Already backed, yet this CPU faulted. Present leaf → a
            // peer installed it while this CPU's TLB / walk caches still
            // held the pre-fault miss: invalidate locally and retry.
            // ABSENT leaf → a racing VMA op stripped it after the
            // backing was registered; re-install the region's own frame
            // instead of retrying forever. See the x86_64 twin for the
            // full spurious-vs-raced rationale.
            let va = VirtAddr::new(v);
            // SAFETY: `self.root` is this AS's valid TTBR0 root;
            // translate only reads the tables.
            if unsafe { crate::aarch64::paging::translate(self.root, va) }.is_some() {
                // SAFETY: TLBI VAAE1IS at EL1 is always legal; `v` is the
                // page-aligned faulting VA owned by this AS.
                unsafe {
                    crate::aarch64::paging::tlb_invalidate_va_all_asids_inner_shareable(va);
                }
                return Ok(());
            }
            let mut flags = if user_page_writable(perms, phys) {
                PtFlags::AP_RW_EL0
            } else {
                PtFlags::AP_RO_EL0
            };
            if !perms.contains(RegionPerms::EXEC) {
                flags = flags | PtFlags::UXN | PtFlags::PXN;
            }
            // SAFETY: root valid + frame owned by this region (same
            // contract as the fresh-allocation path below).
            match unsafe { map_4kb(self.root, va, phys, flags) } {
                Ok(()) | Err(MapError::AlreadyMapped) => Ok(()),
                Err(_) => Err(AddressSpaceError::NotImplemented),
            }
        })?;
        let DemandPageClaim::Owner {
            ticket,
            file_backed,
        } = claim
        else {
            return Ok(());
        };

        let phys = if file_backed {
            match file_fault_frame(v) {
                Some(phys) => PhysAddr::new(phys),
                None => {
                    self.cancel_demand_page(v, ticket);
                    return Err(AddressSpaceError::Unmapped);
                }
            }
        } else {
            let frame = match crate::mempolicy::alloc_frame_policied(crate::frame::local_node()) {
                Ok(frame) => frame,
                Err(_) => {
                    self.cancel_demand_page(v, ticket);
                    return Err(AddressSpaceError::OutOfRange);
                }
            };
            let phys = frame.start_address();
            // SAFETY: the frame is exclusively owned and reachable through
            // the kernel TTBR1 RAM window while the ticket is outstanding.
            unsafe {
                core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096);
            }
            phys
        };

        let published = self.finish_demand_page(v, ticket, phys, |phys, perms| {
            let mut flags = if user_page_writable(perms, phys) {
                PtFlags::AP_RW_EL0
            } else {
                PtFlags::AP_RO_EL0
            };
            if !perms.contains(RegionPerms::EXEC) {
                flags = flags | PtFlags::UXN | PtFlags::PXN;
            }
            // SAFETY: as on x86_64, publication and leaf installation are one
            // region-lock transaction against this live TTBR0 root.
            match unsafe { map_4kb(self.root, VirtAddr::new(v), phys, flags) } {
                Ok(()) | Err(MapError::AlreadyMapped) => Ok(()),
                Err(_) => Err(AddressSpaceError::NotImplemented),
            }
        })?;
        if !published {
            if file_backed {
                release_shared_phys(phys);
            } else {
                crate::frame::free_frame(crate::frame::PhysFrame::new(phys));
            }
        }
        Ok(())
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub unsafe fn demand_alloc_page(&self, _vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
        Err(AddressSpaceError::NotImplemented)
    }

    /// Stack auto-extension. Called from the user-mode #PF / data-
    /// abort handler when the fault address lies in a region
    /// flagged `STACK_GUARD`. Allocates a fresh zeroed frame,
    /// promotes the guard region to R+W (installing the leaf PTE
    /// with the region's perms), and installs a fresh one-page
    /// guard region directly below — modelled on the implicit
    /// stack-grow behaviour POSIX.1-2017 §2.2.2 leaves
    /// implementation-defined.
    ///
    /// Rejects (`Overlap`) if a new guard one page below the
    /// current guard would collide with an existing region — the
    /// caller surfaces this as a real SEGV.
    ///
    /// Returns `Unmapped` if `vaddr` is outside every region or
    /// the containing region is not flagged `STACK_GUARD` (real
    /// access violation — the caller takes the SEGV path).
    ///
    /// # Safety
    /// - The low-4-GiB identity map must be live (used to zero
    ///   the fresh frame).
    /// - `self.root` must be a valid page-table root for the AS
    ///   currently active on this CPU.
    /// - Frame allocator must be initialised.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn try_grow_stack(&self, vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
        use crate::x86_64::paging::{map_4kb, MapError, PtFlags};
        let v_page = vaddr.as_u64() & !0xFFFu64;
        let mut regions = self.regions.lock();
        // Find the stack guard at or above the faulting page and within a
        // bounded gap. A single large frame allocation (`sub rsp, N` followed
        // by a write near the new top) touches a page SEVERAL pages below the
        // current stack bottom in one step — it lands BELOW the one-page guard
        // (so the old "fault must hit the guard region" test failed it as an
        // ordinary SEGV). We instead grow the stack down to cover the faulting
        // page in one shot. The bound keeps a wild pointer far below the stack
        // a real SEGV rather than silently mapping a huge gap.
        const MAX_GROW: u64 = 256 * 1024; // 64 pages
        let guard_base = regions
            .iter()
            .find(|r| {
                r.perms.contains(RegionPerms::STACK_GUARD) && {
                    let gb = r.base.as_u64();
                    gb >= v_page && gb - v_page <= MAX_GROW
                }
            })
            .map(|region| region.base.as_u64())
            .ok_or(AddressSpaceError::Unmapped)?;
        // New guard sits one page below the lowest page we are about to map.
        let new_guard_base = match v_page.checked_sub(0x1000) {
            Some(b) => b,
            None => return Err(AddressSpaceError::OutOfRange),
        };
        // Stack floor: the real user stack lives ABOVE the mmap window and
        // its growth reserve ends at MMAP_WINDOW_TOP. Refuse to let such a
        // stack grow past the floor (→ SIGSEGV) so it can never enter the
        // mmap window, where a later reserve_mmap_va — which deliberately
        // ignores the stack — could otherwise place an allocation under it.
        // Only fires on the crossing page, and only for a stack currently
        // above the window: low-address stacks (test arenas, alternate
        // layouts) sit entirely below the window and are unaffected.
        if guard_base >= Self::MMAP_WINDOW_TOP && new_guard_base < Self::MMAP_WINDOW_TOP {
            return Err(AddressSpaceError::OutOfRange);
        }
        // The new footprint we are claiming is [new_guard_base, guard_base):
        // the fresh guard page plus every page from `v_page` up to (but not
        // including) the old guard page — which stays region `idx`. Reject if
        // any OTHER region intersects it: the stack arena has run into the
        // heap / mmap window and the user gets a real SEGV.
        if regions.has_overlap(new_guard_base, guard_base) {
            return Err(AddressSpaceError::Overlap);
        }

        // Promote: map every page from `v_page` up to and including the old
        // guard page (`guard_base`) as R+W stack, collecting their frames.
        let flags = PtFlags::USER | PtFlags::WRITABLE | PtFlags::NO_EXEC;
        let npages = ((guard_base - v_page) / 0x1000) + 1;
        let mut new_phys: alloc::vec::Vec<crate::PhysAddr> =
            alloc::vec::Vec::with_capacity(npages as usize);
        let mut p = v_page;
        while p <= guard_base {
            let phys = crate::frame::alloc_user_frame()
                .map_err(|_| AddressSpaceError::OutOfRange)?
                .start_address();
            // SAFETY: identity-mapped; freshly-allocated frame is ours.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                core::ptr::write_bytes(phys.raw() as *mut u8, 0, 4096);
            }
            // SAFETY: root is valid (AS active); phys just allocated.
            // SAFETY: Valid memory or trusted environment
            match unsafe { map_4kb(self.root, VirtAddr::new(p), phys, flags) } {
                Ok(()) | Err(MapError::AlreadyMapped) => {}
                Err(_) => return Err(AddressSpaceError::NotImplemented),
            }
            new_phys.push(phys);
            p += 0x1000;
        }
        // Replace the one-page guard region with the expanded mapped stack
        // span [v_page, guard_base + 0x1000).
        let mut promoted = regions
            .remove(guard_base)
            .expect("stack guard disappeared under region lock");
        promoted.base = VirtAddr::new(v_page);
        promoted.len = npages * 0x1000;
        promoted.perms = RegionPerms::READ | RegionPerms::WRITE;
        promoted.phys = new_phys;
        assert!(regions.insert(promoted).is_none());

        // Install a fresh one-page guard region below. Lazy phys
        // (the slot stays unbacked — guard pages never need a
        // backing frame until they themselves get promoted).
        assert!(regions
            .insert(Region {
                base: VirtAddr::new(new_guard_base),
                len: 0x1000,
                perms: RegionPerms::STACK_GUARD,
                phys: alloc::vec![crate::PhysAddr::new(0)],
            })
            .is_none());
        Ok(())
    }

    /// # Safety
    /// - The low-memory identity map must be live (used to zero the fresh
    ///   frame).
    /// - `self.root` must be a valid `TTBR0_EL1` root for the AS currently
    ///   active on this CPU.
    /// - The frame allocator must be initialised.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn try_grow_stack(&self, vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
        use crate::aarch64::paging::{map_4kb, MapError, PtFlags};
        let v_page = vaddr.as_u64() & !0xFFFu64;
        let mut regions = self.regions.lock();
        // See the x86_64 sibling for the multi-page-grow rationale: a large
        // frame allocation touches a page several pages below the stack bottom
        // in one step, landing below the one-page guard. Grow down to cover it.
        const MAX_GROW: u64 = 256 * 1024; // 64 pages
        let guard_base = regions
            .iter()
            .find(|r| {
                r.perms.contains(RegionPerms::STACK_GUARD) && {
                    let gb = r.base.as_u64();
                    gb >= v_page && gb - v_page <= MAX_GROW
                }
            })
            .map(|region| region.base.as_u64())
            .ok_or(AddressSpaceError::Unmapped)?;
        let new_guard_base = match v_page.checked_sub(0x1000) {
            Some(b) => b,
            None => return Err(AddressSpaceError::OutOfRange),
        };
        // Stack floor: the real user stack lives ABOVE the mmap window and
        // its growth reserve ends at MMAP_WINDOW_TOP. Refuse to let such a
        // stack grow past the floor (→ SIGSEGV) so it can never enter the
        // mmap window, where a later reserve_mmap_va — which deliberately
        // ignores the stack — could otherwise place an allocation under it.
        // Only fires on the crossing page, and only for a stack currently
        // above the window: low-address stacks (test arenas, alternate
        // layouts) sit entirely below the window and are unaffected.
        if guard_base >= Self::MMAP_WINDOW_TOP && new_guard_base < Self::MMAP_WINDOW_TOP {
            return Err(AddressSpaceError::OutOfRange);
        }
        if regions.has_overlap(new_guard_base, guard_base) {
            return Err(AddressSpaceError::Overlap);
        }

        let flags = PtFlags::AP_RW_EL0 | PtFlags::UXN | PtFlags::PXN;
        let npages = ((guard_base - v_page) / 0x1000) + 1;
        let mut new_phys: alloc::vec::Vec<crate::PhysAddr> =
            alloc::vec::Vec::with_capacity(npages as usize);
        let mut p = v_page;
        while p <= guard_base {
            let phys = crate::frame::alloc_user_frame()
                .map_err(|_| AddressSpaceError::OutOfRange)?
                .start_address();
            // SAFETY: phys-as-virt via kernel_mut_ptr stays valid even
            // under user TTBR0.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096);
            }
            // SAFETY: see x86_64 sibling.
            match unsafe { map_4kb(self.root, VirtAddr::new(p), phys, flags) } {
                Ok(()) | Err(MapError::AlreadyMapped) => {}
                Err(_) => return Err(AddressSpaceError::NotImplemented),
            }
            new_phys.push(phys);
            p += 0x1000;
        }
        let mut promoted = regions
            .remove(guard_base)
            .expect("stack guard disappeared under region lock");
        promoted.base = VirtAddr::new(v_page);
        promoted.len = npages * 0x1000;
        promoted.perms = RegionPerms::READ | RegionPerms::WRITE;
        promoted.phys = new_phys;
        assert!(regions.insert(promoted).is_none());

        assert!(regions
            .insert(Region {
                base: VirtAddr::new(new_guard_base),
                len: 0x1000,
                perms: RegionPerms::STACK_GUARD,
                phys: alloc::vec![crate::PhysAddr::new(0)],
            })
            .is_none());
        Ok(())
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub unsafe fn try_grow_stack(&self, _vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
        Err(AddressSpaceError::NotImplemented)
    }

    /// Return whether base-page regions cover every byte in `[lo, hi)`.
    ///
    /// The region table is ordered by base, so coverage starts at the one
    /// predecessor that can contain `lo` and walks only the requested span.
    /// This helper is used before changing residency state: Linux returns
    /// `ENOMEM` when an `mlock`/`munlock` range contains a hole rather than
    /// partially changing the mapped fragments on either side.
    fn regions_cover_range(regions: &RegionTable, lo: u64, hi: u64) -> bool {
        regions.covers_range(lo, hi)
    }

    /// Coverage check across both base-page VMAs and hardware huge mappings.
    /// Lock order is huge -> regular, matching every mutating path.
    fn mappings_cover_range(&self, lo: u64, hi: u64) -> bool {
        let huge = self.huge_regions.lock();
        let regular = self.regions.lock();
        let mut coverage = Vec::new();
        regular.for_each_overlapping(lo, hi, |region| {
            let begin = lo.max(region.base.as_u64());
            let end = hi.min(region.base.as_u64().saturating_add(region.len));
            if begin < end {
                coverage.push((begin, end));
            }
        });
        coverage.extend(huge.iter().filter_map(|region| {
            let begin = lo.max(region.base.as_u64());
            let end = hi.min(region.base.as_u64().saturating_add(region.len));
            (begin < end).then_some((begin, end))
        }));
        coverage.sort_unstable_by_key(|&(begin, _)| begin);
        let mut cursor = lo;
        for (begin, end) in coverage {
            if begin > cursor {
                return false;
            }
            cursor = cursor.max(end);
            if cursor >= hi {
                return true;
            }
        }
        false
    }

    /// Split every base-page region intersecting `[lo, hi)` and set or clear
    /// `flag` on only the middle fragments.  Physical backing is moved into
    /// the new vectors rather than cloned, so ownership/refcounts are
    /// unchanged even for SHARED and COW mappings.
    fn set_region_flag_range(
        regions: &mut RegionTable,
        lo: u64,
        hi: u64,
        flag: RegionPerms,
        set: bool,
    ) {
        // Drain only the tree entries that intersect the request. Tiny
        // mlock/munlock calls therefore touch O(log VMA + intersections)
        // metadata rather than rebuilding a process-wide list.
        let originals = regions.drain_overlapping(lo, hi);
        if originals.is_empty() {
            return;
        }
        let mut rebuilt = Vec::with_capacity(originals.len() + 2);
        for region in originals {
            let rb = region.base.as_u64();
            let re = rb.saturating_add(region.len);
            if rb >= hi || re <= lo {
                rebuilt.push(region);
                continue;
            }

            let split_lo = lo.max(rb);
            let split_hi = hi.min(re);
            // LOCKED has no hardware-PTE representation. If this VMA already
            // has the requested state, a subrange operation is a metadata
            // no-op and must not fragment/reallocate it. This matters for
            // repeated mlockall(MCL_CURRENT), which otherwise rebuilds every
            // already-locked VMA on every call.
            if region.perms.contains(flag) == set {
                rebuilt.push(region);
                continue;
            }
            let head_pages = ((split_lo - rb) >> 12) as usize;
            let middle_pages = ((split_hi - split_lo) >> 12) as usize;
            let mut phys = region.phys.into_iter();
            let head_phys: Vec<_> = (&mut phys).take(head_pages).collect();
            let middle_phys: Vec<_> = (&mut phys).take(middle_pages).collect();
            let tail_phys: Vec<_> = phys.collect();

            if !head_phys.is_empty() {
                rebuilt.push(Region {
                    base: region.base,
                    len: head_phys.len() as u64 * 4096,
                    perms: region.perms,
                    phys: head_phys,
                });
            }
            let middle_perms = if set {
                RegionPerms(region.perms.0 | flag.0)
            } else {
                RegionPerms(region.perms.0 & !flag.0)
            };
            let middle = Region {
                base: VirtAddr::new(split_lo),
                len: middle_phys.len() as u64 * 4096,
                perms: middle_perms,
                phys: middle_phys,
            };
            rebuilt.push(middle);
            if !tail_phys.is_empty() {
                rebuilt.push(Region {
                    base: VirtAddr::new(split_hi),
                    len: tail_phys.len() as u64 * 4096,
                    perms: region.perms,
                    phys: tail_phys,
                });
            }
        }
        for region in rebuilt {
            assert!(regions.insert(region).is_none());
        }
    }

    /// Linux accepts an unaligned mlock address and rounds the complete byte
    /// interval out to pages.  Keep that validation identical for mlock,
    /// mlock2(MLOCK_ONFAULT), and munlock.
    fn rounded_lock_range(base: VirtAddr, len: u64) -> Result<(u64, u64), AddressSpaceError> {
        let requested_hi = base
            .as_u64()
            .checked_add(len)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let lo = base.as_u64() & !0xFFF;
        let hi = requested_hi
            .checked_add(0xFFF)
            .map(|end| end & !0xFFF)
            .filter(|end| *end <= Self::USER_HALF_END)
            .ok_or(AddressSpaceError::OutOfRange)?;
        Ok((lo, hi))
    }

    /// `mlock(base, len)` — force-back every lazy page in the rounded
    /// `[base, base + len)` range and set LOCKED on exactly that range.
    /// Returns Unmapped if any page in the request is unmapped.
    pub fn mlock_range(&self, base: VirtAddr, len: u64) -> Result<(), AddressSpaceError> {
        let (lo, hi) = Self::rounded_lock_range(base, len)?;
        // For a page-aligned address Linux treats zero bytes as a no-op. An
        // unaligned zero-byte request rounds over its containing page and is
        // validated normally.
        if lo == hi {
            return Ok(());
        }
        // Force-back any zero phys entries first; do this with
        // the lock dropped so frame allocation doesn't recurse
        // on an IRQ-safe lock. Snapshot the pages that need backing BY
        // VIRTUAL ADDRESS, not by (region index, slot index): a sibling
        // thread's mmap/munmap/mprotect between the two lock holds
        // reshuffles/splits the region list, so a saved index can point at
        // a DIFFERENT (possibly shorter) region on re-acquire — the old
        // index-keyed restamp then indexed `phys` out of bounds (kernel
        // panic with the regions lock held → every sibling VMA op spins
        // IRQs-off forever, wedging the whole machine under stress-ng
        // --vma's mlock-vs-mprotect churn) or stamped a frame into the
        // wrong region. VAs stay meaningful across any reshuffle.
        let mut anonymous_vas: Vec<u64> = Vec::new();
        let mut file_vas: Vec<u64> = Vec::new();
        let mut swap_vas: Vec<u64> = Vec::new();
        {
            let g = self.regions.lock();
            if !Self::regions_cover_range(&g, lo, hi) {
                return Err(AddressSpaceError::Unmapped);
            }
            if g.swap_pages.range(lo..hi).any(|(_, state)| {
                matches!(state, SwapPageState::Evicting(_) | SwapPageState::Loading)
            }) {
                return Err(AddressSpaceError::NotImplemented);
            }
            g.for_each_overlapping(lo, hi, |r| {
                let rb = r.base.as_u64();
                let re = rb.saturating_add(r.len);
                if rb >= hi || re <= lo {
                    return;
                }
                let first = ((lo.max(rb) - rb) >> 12) as usize;
                let last = ((hi.min(re) - rb) >> 12) as usize;
                for i in first..last {
                    if r.phys[i].raw() == 0 {
                        let va = rb + ((i as u64) << 12);
                        if g.swap_pages.get(&va) == Some(&SwapPageState::Swapped) {
                            swap_vas.push(va);
                        } else if r.perms.contains(RegionPerms::FILE_DEMAND) {
                            file_vas.push(va);
                        } else {
                            anonymous_vas.push(va);
                        }
                    }
                }
            });
        }

        // Preserved swap contents take precedence over anonymous zero-fill.
        // The first fault may batch-read consecutive entries; later VAs then
        // take the already-resident recovery path without changing contents.
        for va in swap_vas {
            // SAFETY: mlock operates on this live address-space root.
            unsafe { self.demand_alloc_page(VirtAddr::new(va))? };
        }

        // FILE_DEMAND pages are borrowed from their backing file.  Routing
        // them through the normal fault path is essential: allocating an
        // anonymous zero page here would both hide file contents and leak it
        // because SHARED teardown correctly never frees borrowed frames.
        for va in file_vas {
            // SAFETY: mlock is invoked for the current live address space;
            // demand_alloc_page has the same MMU/frame-allocator contract.
            unsafe { self.demand_alloc_page(VirtAddr::new(va))? };
        }

        // Allocate frames outside the lock.
        let mut allocations: alloc::vec::Vec<(u64, PhysAddr)> =
            alloc::vec::Vec::with_capacity(anonymous_vas.len());
        for va in anonymous_vas {
            let phys = match crate::mempolicy::alloc_frame_policied(crate::frame::local_node()) {
                Ok(frame) => frame.start_address(),
                Err(_) => {
                    for (_, allocated) in allocations {
                        crate::frame::free_frame(crate::frame::PhysFrame::new(allocated));
                    }
                    return Err(AddressSpaceError::OutOfRange);
                }
            };
            // SAFETY: identity-mapped on x86_64; aarch64
            // uses kernel_mut_ptr for the same purpose.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                #[cfg(target_arch = "x86_64")]
                core::ptr::write_bytes(phys.raw() as *mut u8, 0, 4096);
                #[cfg(target_arch = "aarch64")]
                core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096);
            }
            allocations.push((va, phys));
        }
        allocations.sort_unstable_by_key(|&(va, _)| va);

        // Re-acquire the lock, stamp the new frames by VA + set the
        // LOCKED flag, then re-materialise (still under the lock — see
        // `change_perms_range` for why the rewrite must not run after the
        // lock drop) so PTEs land for the freshly-backed pages.
        let mut g = self.regions.lock();
        if !Self::regions_cover_range(&g, lo, hi) {
            drop(g);
            for (_, phys) in allocations {
                crate::frame::free_frame(crate::frame::PhysFrame::new(phys));
            }
            return Err(AddressSpaceError::Unmapped);
        }

        // Ensure every still-lazy slot can be satisfied by the anonymous
        // allocation snapshot before publishing any of those frames.  If a
        // concurrent VMA replacement changed the range while the lock was
        // dropped, fail without partially setting LOCKED or placing an
        // anonymous frame in a newly-created FILE_DEMAND mapping.
        let mut restamp_valid = true;
        g.for_each_overlapping(lo, hi, |r| {
            let rb = r.base.as_u64();
            let re = rb.saturating_add(r.len);
            if rb >= hi || re <= lo {
                return;
            }
            let first = ((lo.max(rb) - rb) >> 12) as usize;
            let last = ((hi.min(re) - rb) >> 12) as usize;
            for i in first..last {
                if r.phys[i].raw() != 0 {
                    continue;
                }
                let va = rb + ((i as u64) << 12);
                if r.perms.contains(RegionPerms::FILE_DEMAND)
                    || allocations.binary_search_by_key(&va, |&(v, _)| v).is_err()
                {
                    restamp_valid = false;
                    return;
                }
            }
        });
        if !restamp_valid {
            drop(g);
            for (_, phys) in allocations {
                crate::frame::free_frame(crate::frame::PhysFrame::new(phys));
            }
            return Err(AddressSpaceError::Unmapped);
        }

        let mut stamped_vas = Vec::new();
        for (va, phys) in allocations {
            let mut consumed = false;
            if let Some(r) = g.containing_mut(va) {
                let rb = r.base.as_u64();
                let i = ((va - rb) >> 12) as usize;
                if i < r.phys.len()
                    && r.phys[i].raw() == 0
                    && !r.perms.contains(RegionPerms::FILE_DEMAND)
                {
                    r.phys[i] = phys;
                    consumed = true;
                    stamped_vas.push(va);
                }
            }
            if !consumed {
                // Raced with a demand fault (or an unmap) that beat us to
                // this page — give the frame back.
                crate::frame::free_frame(crate::frame::PhysFrame::new(phys));
            }
        }
        Self::set_region_flag_range(&mut g, lo, hi, RegionPerms::LOCKED, true);
        // LOCKED itself does not change page permissions, so only anonymous
        // pages newly backed above need PTE installation. Rewriting every
        // resident page made repeated mlock/mlockall proportional to the
        // entire locked working set even when no residency changed.
        let mut to_materialise = Vec::with_capacity(stamped_vas.len());
        for va in stamped_vas {
            if let Some(region) = g.containing(va) {
                let index = ((va - region.base.as_u64()) >> 12) as usize;
                to_materialise.push(Region {
                    base: VirtAddr::new(va),
                    len: 4096,
                    perms: region.perms,
                    phys: alloc::vec![region.phys[index]],
                });
            }
        }
        // SAFETY: same identity-map invariant; touched regions
        // are valid bookkeeping entries.
        // SAFETY: Valid memory or trusted environment
        unsafe { self.rewrite_perms_pages(&to_materialise) };
        drop(g);
        Ok(())
    }

    /// `mlock2(base, len, MLOCK_ONFAULT)` — mark exactly the rounded range
    /// LOCKED without populating lazy pages.  A later demand fault supplies
    /// the backing normally, while reclaim observes LOCKED and leaves it
    /// resident.  This differs intentionally from [`Self::mlock_range`],
    /// whose eager population is the defining `mlock(2)` behaviour.
    pub fn mlock_range_onfault(&self, base: VirtAddr, len: u64) -> Result<(), AddressSpaceError> {
        let (lo, hi) = Self::rounded_lock_range(base, len)?;
        if lo == hi {
            return Ok(());
        }
        let mut regions = self.regions.lock();
        if !Self::regions_cover_range(&regions, lo, hi) {
            return Err(AddressSpaceError::Unmapped);
        }
        Self::set_region_flag_range(&mut regions, lo, hi, RegionPerms::LOCKED, true);
        Ok(())
    }

    /// `munlock(base, len)` — clear LOCKED on exactly the rounded range.
    /// Frames stay backed (no swap exists yet to reclaim them). Returns
    /// Unmapped if any page in the request is unmapped.
    pub fn munlock_range(&self, base: VirtAddr, len: u64) -> Result<(), AddressSpaceError> {
        let (lo, hi) = Self::rounded_lock_range(base, len)?;
        if lo == hi {
            return Ok(());
        }
        let mut g = self.regions.lock();
        if !Self::regions_cover_range(&g, lo, hi) {
            return Err(AddressSpaceError::Unmapped);
        }
        Self::set_region_flag_range(&mut g, lo, hi, RegionPerms::LOCKED, false);
        Ok(())
    }

    /// Change permissions on every region whose base lies in
    /// `[base, base + len)`. The active PTEs are rewritten in
    /// place via the same primitives `materialize` uses, so the
    /// next user-mode access to the affected pages observes the
    /// new flags. Does NOT split a region — the caller must align
    /// `base` to a region's existing base and `len` to that
    /// region's `len` if they want surgical control. For the
    /// per-page regions installed by `sys_brk`-grow / `sys_mmap`'s
    /// per-page form, that means callers can change perms at any
    /// page granularity.
    ///
    /// Returns `Unmapped` if no regions intersect the requested
    /// range. Otherwise returns `Ok(())` after applying perms to
    /// every matching region.
    pub fn change_perms_range(
        &self,
        base: VirtAddr,
        len: u64,
        new_perms: RegionPerms,
    ) -> Result<(), AddressSpaceError> {
        let lo = base.as_u64();
        let hi = lo.saturating_add(len);
        // Mutate the bookkeeping AND rewrite the PTEs under one hold of
        // the regions lock. Rewriting after dropping the lock (the
        // previous shape) let a racing munmap/MAP_FIXED overlap complete
        // in the gap and FREE the snapshot's frames — the deferred
        // rewrite then re-installed PTEs over frames the buddy had
        // already re-handed out (use-after-free / cross-AS aliasing;
        // stress-ng --vma's concurrent mprotect+munmap threads).
        // The rewrite is allocation-light (map_4kb may allocate an
        // intermediate table page — regions→buddy lock order, same as
        // demand_alloc_page) and its batched cross-CPU flush is
        // deadlock-safe under an IrqSafeSpinLock: peers spinning on this
        // lock drain pending shootdowns via the spin hook, and the
        // ack-wait itself services peer shootdowns (see `remap_page`,
        // which has always broadcast under this lock).
        let mut g = self.regions.lock();
        if g.swap_pages
            .range(lo..hi)
            .any(|(_, state)| matches!(state, SwapPageState::Loading))
        {
            // A page-in commit has already captured the old PTE flags. Let
            // that bounded transaction finish rather than publish those old
            // flags after this permission change.
            return Err(AddressSpaceError::NotImplemented);
        }
        let mut hits = Vec::new();
        g.for_each_overlapping_mut(lo, hi, |r| {
            let rb = r.base.as_u64();
            let re = rb.saturating_add(r.len);
            if rb >= hi || re <= lo {
                return;
            }
            r.perms = new_perms;
            hits.push(r.clone());
        });
        if hits.is_empty() {
            return Err(AddressSpaceError::Unmapped);
        }
        // SAFETY: same identity-mapping precondition as
        // `materialize`. Each touched region's pages were
        // previously installed with map_4kb; we re-install with
        // the new flag set, which on x86_64's map_4kb takes the
        // AlreadyMapped path on the second pass. We reach the
        // PTE-level update by tearing down + re-installing each
        // page (cheaper than adding a per-arch in-place mutate
        // helper, since map_4kb already handles the leaf rewrite).
        // SAFETY: Valid memory or trusted environment
        unsafe { self.rewrite_perms_pages(&hits) };
        drop(g);
        Ok(())
    }

    /// Linux-compat `mprotect(base, len, new_perms)` — change
    /// permissions on `[base, base + len)` with region split where
    /// the range partially overlaps an existing region.
    ///
    /// Unlike [`change_perms_range`] (which is whole-region only),
    /// this surface implements POSIX `mprotect(2)` semantics:
    ///
    /// 1. Walk the AS's region list and pick every region that
    ///    intersects `[lo, hi)`.
    /// 2. For each hit region `[rb, re)`, split it at the request
    ///    boundaries:
    ///    - `[rb, lo)` keeps the old perms (head fragment).
    ///    - `[max(rb, lo), min(re, hi))` gets the new perms (middle).
    ///    - `[hi, re)` keeps the old perms (tail fragment).
    ///
    ///    Each fragment carries its own slice of the original
    ///    region's `phys` Vec, so `Drop for AddressSpace` doesn't
    ///    double-free.
    /// 3. W^X check: reject if `new_perms` carries BOTH WRITE and
    ///    EXEC. Same policy as [`wx::check_mmap_perms`] — JIT code
    ///    must take RW → RX via the cap path, never directly.
    /// 4. Re-materialise the affected (post-split) region's PTEs.
    ///
    /// `new_perms` is interpreted as a POSIX-prot mask only — any
    /// internal flags (LOCKED, STACK_GUARD) in `new_perms.0` are
    /// stripped before the assignment, so a stack-guard region
    /// stays a stack guard even if user code mprotects across it.
    /// The head and tail fragments preserve the original region's
    /// full perms field including those flags.
    ///
    /// Returns:
    /// - `Ok(())` on a successful change or zero-length no-op.
    /// - `Err(Unmapped)` if any page in a non-empty request is unmapped.
    /// - `Err(AlignmentMismatch)` if `base` is not page-aligned, or if
    ///   `new_perms` carries `WRITE | EXEC` (W^X). Length rounds upward.
    #[cfg(feature = "linux-compat")]
    pub fn mprotect_range(
        &self,
        base: VirtAddr,
        len: u64,
        new_perms: RegionPerms,
    ) -> Result<(), AddressSpaceError> {
        if base.as_u64() & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        if len == 0 {
            return Ok(());
        }
        // W^X: reject WRITE | EXEC outright. This is sys_mprotect's cap-free
        // fast path; the `Cap<Jit, Grant>`-gated transitions go through
        // `wx::jit_mprotect`, which classifies the change and then calls
        // `mprotect_range_wx_checked` below.
        let prot = new_perms.prot_only();
        if prot.contains(RegionPerms::WRITE | RegionPerms::EXEC) {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        self.mprotect_range_wx_checked(base, len, new_perms)
    }

    /// Permissions of the region covering `[base, base + len)`, or `None` if
    /// no single region covers the whole request.
    ///
    /// `wx::jit_mprotect` needs the *old* permission set to classify the
    /// transition, and "one region or nothing" is the right shape for that:
    /// a request straddling two regions with different permissions has no
    /// single `old` to classify, and silently classifying against the first
    /// one would let a JIT grant cover a region it was never meant to.
    ///
    /// **Not** a precondition for `mprotect(2)` in general — see
    /// [`Self::perms_intersecting`]. Making it one narrowed the syscall to
    /// single-region ranges and broke every multi-region `mprotect` that used
    /// to work.
    pub fn perms_covering(&self, base: VirtAddr, len: u64) -> Option<RegionPerms> {
        let lo = base.as_u64();
        let hi = lo.checked_add(len)?;
        self.regions
            .lock()
            .iter()
            .find(|r| {
                let rb = r.base.as_u64();
                rb <= lo && hi <= rb + r.len
            })
            .map(|r| r.perms)
    }

    /// Permissions of **every** region intersecting `[base, base + len)`.
    ///
    /// `mprotect_range` splits across every intersecting region, so the W^X
    /// classification has to see every one of them too. Using
    /// [`Self::perms_covering`] for that instead was a real regression: it
    /// returns `None` unless a *single* region spans the whole request, so a
    /// range crossing two adjacent mappings — or one an earlier `mprotect`
    /// had already split — was refused outright rather than classified.
    ///
    /// Returns them in region order. An empty result means nothing is mapped
    /// there, which is `mprotect_range`'s error to report, not this one's.
    pub fn perms_intersecting(&self, base: VirtAddr, len: u64) -> alloc::vec::Vec<RegionPerms> {
        let lo = base.as_u64();
        let Some(hi) = lo.checked_add(len) else {
            return alloc::vec::Vec::new();
        };
        self.regions
            .lock()
            .iter()
            .filter(|r| {
                let rb = r.base.as_u64();
                let re = rb + r.len;
                rb < hi && lo < re
            })
            .map(|r| r.perms)
            .collect()
    }

    /// `mprotect_range` **without** the W^X end-state rejection.
    ///
    /// Not public: the only caller is `wx::jit_mprotect`, which has already
    /// classified the `old → new` transition through
    /// [`wx::classify_mprotect`](crate::wx::classify_mprotect) and verified a
    /// live `Cap<Jit, Grant>`. Splitting it out this way keeps exactly one
    /// place where a W|X mapping can come into existence, and that place is
    /// capability-gated.
    #[cfg(feature = "linux-compat")]
    pub(crate) fn mprotect_range_wx_checked(
        &self,
        base: VirtAddr,
        len: u64,
        new_perms: RegionPerms,
    ) -> Result<(), AddressSpaceError> {
        let prot = new_perms.prot_only();
        // Linux requires `addr` to be page-aligned and rounds length upward.
        if base.as_u64() & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        if len == 0 {
            return Ok(());
        }
        let lo = base.as_u64();
        let rounded_len = len
            .checked_add(0xFFF)
            .map(|value| value & !0xFFF)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let hi = lo
            .checked_add(rounded_len)
            .filter(|end| *end <= Self::USER_HALF_END)
            .ok_or(AddressSpaceError::OutOfRange)?;
        if !self.mappings_cover_range(lo, hi) {
            return Err(AddressSpaceError::Unmapped);
        }

        // Avoid changing huge mappings and only then discovering that a
        // base-page swap-in covering the same request already captured stale
        // permissions. This is repeated under the region lock below to close
        // the race with a page-in that starts while huge leaves are updated.
        if self
            .regions
            .lock()
            .swap_pages
            .range(lo..hi)
            .any(|(_, state)| matches!(state, SwapPageState::Loading))
        {
            return Err(AddressSpaceError::NotImplemented);
        }

        let huge_touched = {
            let mut huge = self.huge_regions.lock();
            if huge.iter().any(|region| {
                let rb = region.base.as_u64();
                let re = rb + region.len;
                if rb >= hi || re <= lo {
                    return false;
                }
                let page_size = match region.size {
                    crate::hugepage::HugeSize::M2 => crate::hugepage::HUGEPAGE_2M_BYTES,
                    crate::hugepage::HugeSize::G1 => crate::hugepage::HUGEPAGE_1G_BYTES,
                };
                let split_lo = lo.max(rb);
                let split_hi = hi.min(re);
                (split_lo - rb) & (page_size - 1) != 0 || (split_hi - rb) & (page_size - 1) != 0
            }) {
                return Err(AddressSpaceError::AlignmentMismatch);
            }
            let mut touched = false;
            let mut rebuilt = Vec::with_capacity(huge.len() + 2);
            for region in core::mem::take(&mut *huge) {
                let rb = region.base.as_u64();
                let re = rb + region.len;
                if rb >= hi || re <= lo {
                    rebuilt.push(region);
                    continue;
                }
                let page_size = match region.size {
                    crate::hugepage::HugeSize::M2 => crate::hugepage::HUGEPAGE_2M_BYTES,
                    crate::hugepage::HugeSize::G1 => crate::hugepage::HUGEPAGE_1G_BYTES,
                };
                let split_lo = lo.max(rb);
                let split_hi = hi.min(re);
                let head = ((split_lo - rb) / page_size) as usize;
                let middle = ((split_hi - split_lo) / page_size) as usize;
                let mut iter = region.frames.into_iter();
                let head_frames: Vec<_> = (&mut iter).take(head).collect();
                let middle_frames: Vec<_> = (&mut iter).take(middle).collect();
                let tail_frames: Vec<_> = iter.collect();
                if !head_frames.is_empty() {
                    rebuilt.push(HugeRegion {
                        base: region.base,
                        len: head_frames.len() as u64 * page_size,
                        perms: region.perms,
                        size: region.size,
                        frames: head_frames,
                    });
                }
                for (i, frame) in middle_frames.iter().enumerate() {
                    let va = VirtAddr::new(split_lo + i as u64 * page_size);
                    let _ = self.unmap_huge_leaf(va, region.size);
                    self.map_huge_leaf(va, frame.phys(), region.size, prot)?;
                }
                // LINUX-GAP: bare `prot` here drops the internal flags —
                // LOCKED above all — where the 4 KiB path below preserves them
                // (`prot | preserved_flags`). Linux keeps `VM_LOCKED` across an
                // `mprotect`, so an `mlock`ed hugetlb mapping is silently
                // unlocked by a later `mprotect` of part of it.
                //
                // Consequences are contained today only because nothing reads a
                // *huge* region's LOCKED: the COW and fork paths consult
                // `self.regions` alone, and `Drop` frees huge frames
                // unconditionally (huge mappings never honour SHARED either).
                // The moment a reclaim tier consults huge LOCKED this becomes a
                // real unlock. Pinned for the 4 KiB path by
                // `smoke_memory_mlock_survives_mprotect`; deliberately not
                // "fixed" here because the flag has no consumer to be correct
                // for yet, and a fix with no test would just be a claim.
                rebuilt.push(HugeRegion {
                    base: VirtAddr::new(split_lo),
                    len: middle_frames.len() as u64 * page_size,
                    perms: prot,
                    size: region.size,
                    frames: middle_frames,
                });
                if !tail_frames.is_empty() {
                    rebuilt.push(HugeRegion {
                        base: VirtAddr::new(split_hi),
                        len: tail_frames.len() as u64 * page_size,
                        perms: region.perms,
                        size: region.size,
                        frames: tail_frames,
                    });
                }
                touched = true;
            }
            *huge = rebuilt;
            touched
        };

        // Compute + swap in the new (split) layout AND rewrite the
        // affected PTEs under one hold of the regions lock. The rewrite
        // used to run after the lock drop; a racing munmap of the same
        // range could then free the middle fragments' frames before the
        // deferred rewrite re-installed PTEs over them (use-after-free —
        // see `change_perms_range` for the full rationale + why the
        // under-lock broadcast is deadlock-safe).
        let mut g = self.regions.lock();
        if g.swap_pages
            .range(lo..hi)
            .any(|(_, state)| matches!(state, SwapPageState::Loading))
        {
            return Err(AddressSpaceError::NotImplemented);
        }
        let touched: Vec<Region> = {
            // Drain only the entries intersecting [lo, hi), split them, and
            // reinsert their disjoint fragments under the same lock.
            let originals = g.drain_overlapping(lo, hi);
            let mut new_list: Vec<Region> = Vec::with_capacity(originals.len() + 2);
            let mut hits: Vec<Region> = Vec::new();
            for r in originals.into_iter() {
                let rb = r.base.as_u64();
                let re = rb.saturating_add(r.len);
                // Intersection. Split into up to three pieces.
                // The old region owns r.phys; we slice it
                // disjointly into the new fragments so the Drop
                // path's per-frame free doesn't double-fire.
                let split_lo = lo.max(rb);
                let split_hi = hi.min(re);
                // Page indices in the original region's phys list.
                let head_pages = ((split_lo - rb) >> 12) as usize;
                let mid_pages = ((split_hi - split_lo) >> 12) as usize;

                // Carry over the phys slices. We move out of r.phys
                // by index into three owned Vecs so the original is
                // dropped empty.
                let mut phys_iter = r.phys.into_iter();
                let head_phys: Vec<PhysAddr> = (&mut phys_iter).take(head_pages).collect();
                let mid_phys: Vec<PhysAddr> = (&mut phys_iter).take(mid_pages).collect();
                let tail_phys: Vec<PhysAddr> = phys_iter.collect();

                // Head fragment (preserves old perms & internal
                // flags). May be empty when the request starts at
                // or before the region's base.
                if head_pages > 0 {
                    new_list.push(Region {
                        base: VirtAddr::new(rb),
                        len: (head_pages as u64) << 12,
                        perms: r.perms,
                        phys: head_phys,
                    });
                }

                // Middle fragment — the protected slice. The new
                // perms replace the POSIX-prot bits; internal flags
                // (LOCKED, STACK_GUARD) are preserved from the
                // original region.
                let preserved_flags = RegionPerms(r.perms.0 & !RegionPerms::PROT_MASK.0);
                let mid_region = Region {
                    base: VirtAddr::new(split_lo),
                    len: (mid_pages as u64) << 12,
                    perms: RegionPerms(prot.0 | preserved_flags.0),
                    phys: mid_phys,
                };
                hits.push(mid_region.clone());
                new_list.push(mid_region);

                // Tail fragment (preserves old perms).
                if !tail_phys.is_empty() {
                    new_list.push(Region {
                        base: VirtAddr::new(split_hi),
                        len: (tail_phys.len() as u64) << 12,
                        perms: r.perms,
                        phys: tail_phys,
                    });
                }
            }
            for region in new_list {
                assert!(g.insert(region).is_none());
            }
            hits
        };

        if touched.is_empty() && !huge_touched {
            return Err(AddressSpaceError::Unmapped);
        }
        if !touched.is_empty() {
            // SAFETY: same identity-mapping precondition as
            // `change_perms_range`. The middle fragments share their
            // phys frames with the pre-split region; rewriting the PTE
            // flags is safe because we hold the only reference to each
            // post-split phys slot (the Drop path consults the new
            // region table, not the old one) — and the regions lock is
            // still held, so no racing unmap can free them mid-rewrite.
            unsafe { self.rewrite_perms_pages(&touched) };
        }
        drop(g);
        Ok(())
    }

    /// Linux-compat `madvise(base, len, advice)` for MADV_DONTNEED
    /// (4) and MADV_FREE (8). For every page in `[base, base + len)`
    /// whose backing frame is non-zero, this routine:
    ///
    /// 1. Tears down the leaf PTE for that page (invlpg fires).
    /// 2. Frees the underlying frame via `free_frame`, which honours
    ///    the COW refcount table — a frame still shared with another
    ///    address space stays live; only sole-owner frames return to
    ///    the buddy allocator.
    /// 3. Sets the per-page `phys[i]` slot back to the zero sentinel,
    ///    so the next user-mode access takes the demand-paging path
    ///    in `demand_alloc_page` and gets a freshly-zeroed frame.
    ///
    /// Behavioural difference from Linux:
    /// - MADV_DONTNEED and MADV_FREE collapse to the same shape
    ///   here (eager release + lazy zero-on-fault). The lazy-reclaim
    ///   distinction Linux makes between the two requires a swap /
    ///   page-aging path NARF doesn't have yet; both end up with
    ///   "next access reads zero," which is what callers need.
    /// - LOCKED regions silently keep their pages backed (madvise
    ///   is a hint; an mlock'd page must stay resident). The region
    ///   is treated as "touched" for the return value but no frames
    ///   are released.
    /// - STACK_GUARD pages stay guard pages — they were never
    ///   backed, so there is nothing to release; the routine is a
    ///   no-op for those.
    ///
    /// Returns:
    /// - `Ok(())` on a successful pass or zero-length no-op.
    /// - `Err(Unmapped)` if any page in a non-empty request is unmapped.
    /// - `Err(AlignmentMismatch)` for misaligned `base`; length rounds up.
    #[cfg(feature = "linux-compat")]
    pub fn madvise_dontneed(&self, base: VirtAddr, len: u64) -> Result<(), AddressSpaceError> {
        if base.as_u64() & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        if len == 0 {
            return Ok(());
        }
        let lo = base.as_u64();
        let rounded_len = len
            .checked_add(0xFFF)
            .map(|value| value & !0xFFF)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let hi = lo
            .checked_add(rounded_len)
            .filter(|end| *end <= Self::USER_HALF_END)
            .ok_or(AddressSpaceError::OutOfRange)?;

        // Reject holes before clearing any backing. madvise is a hint, but
        // Linux still reports ENOMEM when part of the requested range is not
        // mapped; partial release before that error would be observable.
        {
            let regions = self.regions.lock();
            if !Self::regions_cover_range(&regions, lo, hi) {
                return Err(AddressSpaceError::Unmapped);
            }
        }

        // Collect the frames to free outside the lock. We stamp
        // `phys[i] = 0` AND tear down the leaf PTE while we hold the
        // lock, so a concurrent demand-fault observes a consistent
        // (unbacked, unmapped) page. The previous shape deferred the
        // PTE teardown past the lock drop, where the deferred walk
        // could strip a leaf a racing thread had just re-installed —
        // the same stale-walk family as the old `punch_fixed`, with
        // the same "backed bookkeeping over an absent PTE" terminal
        // state (an infinite-#PF loop before `demand_alloc_page`
        // learned to self-heal it).
        let mut to_release: Vec<crate::frame::PhysFrame> = Vec::new();
        let mut touched = false;
        #[cfg(target_arch = "x86_64")]
        let discarded_swap;
        {
            let mut g = self.regions.lock();
            #[cfg(target_arch = "x86_64")]
            {
                if g.swap_pages.range(lo..hi).any(|(_, state)| {
                    matches!(state, SwapPageState::Evicting(_) | SwapPageState::Loading)
                }) {
                    return Err(AddressSpaceError::NotImplemented);
                }
                let swapped_pages: Vec<VirtAddr> = g
                    .swap_pages
                    .range(lo..hi)
                    .filter_map(|(&va, state)| {
                        matches!(state, SwapPageState::Swapped).then_some(VirtAddr::new(va))
                    })
                    .collect();
                // SAFETY: stable same-root swap records are pinned by the
                // region lock; MADV_DONTNEED intentionally discards contents.
                discarded_swap =
                    unsafe { crate::swap::take_swap_entries(self.root, &swapped_pages) }
                        .map_err(|_| AddressSpaceError::NotImplemented)?;
                for va in swapped_pages {
                    g.swap_pages.remove(&va.as_u64());
                }
            }
            g.for_each_overlapping_mut(lo, hi, |r| {
                let rb = r.base.as_u64();
                let re = rb.saturating_add(r.len);
                if rb >= hi || re <= lo {
                    return;
                }
                touched = true;
                // LOCKED region — hint is honoured as a no-op so
                // mlock'd pages stay resident.
                if r.perms.contains(RegionPerms::LOCKED) {
                    return;
                }
                // SHARED region (vDSO / vvar / SysV shmem) — its frames
                // are BORROWED from a global singleton / external
                // registry, not allocated by this AS. Freeing them here
                // returns a live, externally-owned frame to the buddy,
                // which re-hands it out as another task's page table →
                // the cross-AS double-free behind the "marginal-buddy"
                // corruption. Every sibling teardown path
                // (`unmap_region_pages`, `punch_fixed`) skips SHARED for
                // exactly this reason; MADV_DONTNEED must too — treat it
                // as a no-op over a borrowed mapping.
                if r.perms.contains(RegionPerms::SHARED) {
                    return;
                }
                let start_v = lo.max(rb);
                let end_v = hi.min(re);
                let start_i = ((start_v - rb) >> 12) as usize;
                let end_i = ((end_v - rb) >> 12) as usize;
                #[cfg(target_arch = "aarch64")]
                if self.root.as_u64() != 0 && start_i < end_i {
                    // SAFETY: this is the page-aligned intersection with one
                    // live private, unlocked VMA. The region lock keeps its
                    // ownership stable while the helper clears and
                    // broadcasts the complete run under one root lock.
                    let _ = unsafe {
                        crate::aarch64::paging::unmap_4kb_range(
                            self.root,
                            VirtAddr::new(start_v),
                            (end_i - start_i) as u64,
                        )
                    };
                }
                for i in start_i..end_i {
                    let p = r.phys[i];
                    if p.raw() == 0 {
                        continue;
                    }
                    #[cfg(target_arch = "x86_64")]
                    let v = rb + ((i as u64) << 12);
                    if self.root.as_u64() != 0 {
                        #[cfg(target_arch = "x86_64")]
                        // SAFETY: identity-mapped; `v` lies in a bookkept
                        // region of this AS. LOCAL invalidation only —
                        // one batched cross-CPU flush below.
                        let _ = unsafe {
                            crate::x86_64::paging::unmap_4kb_local(self.root, VirtAddr::new(v))
                        };
                    }
                    to_release.push(crate::frame::PhysFrame::new(p));
                    r.phys[i] = PhysAddr::new(0);
                }
            });
        }
        if !touched {
            return Err(AddressSpaceError::Unmapped);
        }
        #[cfg(target_arch = "x86_64")]
        crate::swap::swap_discard_batch(&discarded_swap);
        // ONE cross-CPU invalidation over the advised span BEFORE any
        // frame is freed for reuse (no-op unless CLONE_VM-shared).
        if !to_release.is_empty() {
            self.flush_region_broadcast(base, (hi - lo) >> 12);
        }
        if self.root.as_u64() != 0 {
            // `to_release` is authoritative data backing only. The batched
            // allocator path consults COW ownership once per touched shard;
            // frames shared with another AS remain live.
            crate::frame::free_frame_batch(&to_release);
        }
        Ok(())
    }

    /// PTE-walk helper for `change_perms_range`. For each page in
    /// each region: unmap_4kb to recover the phys + clear the
    /// leaf PTE, then map_4kb with the new perms to reinstall.
    /// invlpg is issued by both calls, so the CPU's TLB observes
    /// the new flags on the next access.
    ///
    /// # Safety
    /// Identity-map contract identical to `unmap_region_pages`.
    /// Region.phys must remain valid for the duration of the
    /// call; we only re-target the same phys.
    #[cfg(target_arch = "x86_64")]
    unsafe fn rewrite_perms_pages(&self, regions: &[Region]) {
        use crate::x86_64::paging::{
            flush_user_tlb_local, rewrite_4kb_scatter_range, unmap_4kb_local_range, PtFlags,
        };
        if self.root.as_u64() == 0 {
            return;
        }
        // Batched-shootdown shape (Linux `flush_tlb_mm_range`): every
        // leaf-PTE rewrite below invalidates LOCALLY only; the cross-CPU
        // invalidation is either ONE ranged broadcast per region (small
        // batches — mprotect) or ONE full non-global flush for the whole
        // call (large batches — fork's whole-AS COW WRITE-strip via
        // `rematerialize`). The previous per-page `unmap_4kb` broadcast +
        // ack-wait cost thousands of IPI round-trips per fork of a large
        // process (~0.5 s each, unbounded when an AP acked slowly) — the
        // stress-ng --sigrt fork-phase crawl.
        // Only a CLONE_VM-shared AS can be resident on another CPU (see
        // the `vm_shared` field docs); for a single-threaded process the
        // per-page LOCAL invalidations below already cover the only CPU
        // that can hold its entries — skip the cross-CPU broadcast.
        const FULL_FLUSH_PAGE_CEILING: u64 = 512;
        let broadcast = self.is_vm_shared();
        let total_pages: u64 = regions.iter().map(|r| (r.len + 0xFFF) >> 12).sum();
        let use_full_flush = broadcast && total_pages > FULL_FLUSH_PAGE_CEILING;
        for r in regions {
            // PROT_NONE: tear down the leaf PTEs without freeing
            // the underlying frames (region.phys still owns them).
            // The next mprotect-back-to-RW just re-installs.
            if r.perms.prot_only().0 == 0 {
                // SAFETY: same identity-map invariant. The range helper holds
                // the root lock once and completes local invalidation.
                let _ = unsafe { unmap_4kb_local_range(self.root, r.base, r.phys.len() as u64) };
            } else {
                let cow_counts = r
                    .perms
                    .contains(RegionPerms::COW)
                    .then(|| crate::frame::cow::count_batch(&r.phys));
                // SAFETY: region ownership remains stable under the caller's
                // region lock. The helper skips zero lazy sentinels, holds the
                // page-table root lock once, and completes local invalidation.
                let _ = unsafe {
                    rewrite_4kb_scatter_range(self.root, r.base, &r.phys, |i, p| {
                        let mut flags = PtFlags::USER;
                        let cow_count = cow_counts.as_ref().map_or(0, |counts| counts[i]);
                        if user_page_writable_at_count(r.perms, p, cow_count) {
                            flags |= PtFlags::WRITABLE;
                        }
                        if !r.perms.contains(RegionPerms::EXEC) {
                            flags |= PtFlags::NO_EXEC;
                        }
                        flags
                    })
                };
            }
            let region_pages = (r.len + 0xFFF) >> 12;
            if broadcast && !use_full_flush && region_pages > 0 {
                crate::tlb_shootdown::shootdown_remote(
                    crate::tlb_shootdown::ShootdownRequest::for_range(
                        0,
                        r.base.as_u64(),
                        region_pages,
                    ),
                );
            }
        }
        if use_full_flush {
            // SAFETY: CPL=0; user PTEs are never GLOBAL, so a local
            // non-global flush covers the current CPU before remote dispatch.
            unsafe { flush_user_tlb_local() };
            crate::tlb_shootdown::shootdown_remote_full_for_tag(0);
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn rewrite_perms_pages(&self, regions: &[Region]) {
        use crate::aarch64::paging::{rewrite_4kb_scatter_range, unmap_4kb_range, PtFlags};
        if self.root.as_u64() == 0 {
            return;
        }
        for r in regions {
            if r.perms.prot_only().0 == 0 {
                // SAFETY: see x86_64 variant. The helper clears every leaf
                // under one root lock and one inner-shareable TLBI sequence.
                let _ = unsafe { unmap_4kb_range(self.root, r.base, r.phys.len() as u64) };
                continue;
            }
            let cow_counts = r
                .perms
                .contains(RegionPerms::COW)
                .then(|| crate::frame::cow::count_batch(&r.phys));
            // SAFETY: region ownership stays stable under the caller's region
            // lock. The helper performs one complete break-before-make
            // transaction and leaves zero backing sentinels unmapped.
            let _ = unsafe {
                rewrite_4kb_scatter_range(self.root, r.base, &r.phys, |i, p| {
                    let cow_count = cow_counts.as_ref().map_or(0, |counts| counts[i]);
                    let mut flags = if user_page_writable_at_count(r.perms, p, cow_count) {
                        PtFlags::AP_RW_EL0
                    } else {
                        PtFlags::AP_RO_EL0
                    };
                    if !r.perms.contains(RegionPerms::EXEC) {
                        flags = flags | PtFlags::UXN | PtFlags::PXN;
                    }
                    flags
                })
            };
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    unsafe fn rewrite_perms_pages(&self, _regions: &[Region]) {}

    /// Snapshot of the region list — returns an owned `Vec<Region>`
    /// so callers can iterate without holding the lock.
    pub fn regions_snapshot(&self) -> Vec<Region> {
        self.regions.lock().snapshot()
    }

    /// Total virtual bytes covered by base-page and hardware-huge regions.
    ///
    /// Unlike [`Self::regions_snapshot`], this does not clone each region's
    /// per-page backing vector. It is safe to use from exit/OOM accounting,
    /// where allocating metadata proportional to a dying task's address space
    /// can otherwise turn memory pressure into a kernel allocator panic.
    pub fn mapped_bytes(&self) -> u64 {
        self.memory_stats().mapped_bytes
    }

    /// Allocation-free aggregate virtual/resident memory accounting.
    ///
    /// The result includes base-page and hardware-huge regions. Lazy base-page
    /// slots whose physical entry is zero contribute virtual bytes but not
    /// resident pages.
    pub fn memory_stats(&self) -> AddressSpaceMemoryStats {
        let mut stats = AddressSpaceMemoryStats::default();
        {
            let huge = self.huge_regions.lock();
            for region in huge.iter() {
                stats.mapped_bytes = stats.mapped_bytes.saturating_add(region.len);
                let page_bytes = region.frames.first().map_or(0, |frame| frame.size_bytes());
                stats.resident_pages = stats
                    .resident_pages
                    .saturating_add((region.frames.len() as u64).saturating_mul(page_bytes >> 12));
                if region.perms.contains(RegionPerms::WRITE)
                    && !region.perms.contains(RegionPerms::EXEC)
                {
                    stats.writable_nonexec_bytes =
                        stats.writable_nonexec_bytes.saturating_add(region.len);
                }
            }
        }
        {
            let regions = self.regions.lock();
            for region in regions.iter() {
                stats.mapped_bytes = stats.mapped_bytes.saturating_add(region.len);
                stats.resident_pages = stats.resident_pages.saturating_add(
                    region.phys.iter().filter(|phys| phys.as_u64() != 0).count() as u64,
                );
                if region.perms.contains(RegionPerms::WRITE)
                    && !region.perms.contains(RegionPerms::EXEC)
                {
                    stats.writable_nonexec_bytes =
                        stats.writable_nonexec_bytes.saturating_add(region.len);
                }
            }
        }
        stats
    }

    /// Length of the region whose start address is exactly `base`.
    pub fn region_len_at_base(&self, base: VirtAddr) -> Option<u64> {
        let base = base.as_u64();
        if let Some(len) = self
            .huge_regions
            .lock()
            .iter()
            .find(|region| region.base.as_u64() == base)
            .map(|region| region.len)
        {
            return Some(len);
        }
        self.regions
            .lock()
            .iter()
            .find(|region| region.base.as_u64() == base)
            .map(|region| region.len)
    }

    /// Materialise all pending regions into actual page-table entries.
    ///
    /// This full walk is intended for address-space construction (exec/fork).
    /// Incremental mapping paths should use [`Self::materialize_range`] so one
    /// mmap does not revisit every page installed by every earlier mmap.
    ///
    /// # Safety
    /// The AS must have been constructed via `new_for_user`; its architecture
    /// page-table root must remain live for the duration of the call.
    pub unsafe fn materialize(&self) -> Result<(), AddressSpaceError> {
        // SAFETY: forwarded from this method's contract.
        unsafe { self.materialize_window(None) }
    }

    /// Materialise only recorded base-page mappings intersecting
    /// `[base, base + len)`.
    ///
    /// The region lock stays held while current backing metadata is translated
    /// into PTEs. This is load-bearing under `CLONE_VM`: taking a cloned Region
    /// snapshot and installing it after dropping the lock would let a racing
    /// munmap free its frames before this walk used them.
    ///
    /// # Safety
    /// Same live-root requirement as [`Self::materialize`]. `base` and `len`
    /// must describe a non-empty, page-aligned range in the user half.
    pub unsafe fn materialize_range(
        &self,
        base: VirtAddr,
        len: u64,
    ) -> Result<(), AddressSpaceError> {
        let lo = base.as_u64();
        if lo & 0xFFF != 0 || len == 0 || len & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        let hi = lo
            .checked_add(len)
            .filter(|end| *end <= Self::USER_HALF_END)
            .ok_or(AddressSpaceError::OutOfRange)?;
        // SAFETY: range validation above plus the caller's live-root contract.
        unsafe { self.materialize_window(Some((lo, hi))) }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn materialize_window(
        &self,
        window: Option<(u64, u64)>,
    ) -> Result<(), AddressSpaceError> {
        use crate::x86_64::paging::{map_4kb, MapError, PtFlags};
        if self.root.as_u64() == 0 {
            return Err(AddressSpaceError::OutOfRange);
        }
        let regions = self.regions.lock();
        for r in regions.iter() {
            // PROT_NONE region: bookkeeping is recorded but no PTE
            // installed. User-mode access faults with P=0 (page
            // not present), which `frame::x86_64::trap` reports
            // as a clean SEGV-equivalent. Used for stack guard
            // pages + post-mprotect(PROT_NONE) regions.
            if r.perms.prot_only().0 == 0 {
                continue;
            }
            let rb = r.base.as_u64();
            let re = rb + r.len;
            let (first, last) = match window {
                Some((lo, hi)) => {
                    let first = core::cmp::max(rb, lo);
                    let last = core::cmp::min(re, hi);
                    if first >= last {
                        continue;
                    }
                    (((first - rb) >> 12) as usize, ((last - rb) >> 12) as usize)
                }
                None => (0, r.phys.len()),
            };

            let cow_counts = r
                .perms
                .contains(RegionPerms::COW)
                .then(|| crate::frame::cow::count_batch(&r.phys[first..last]));

            for i in first..last {
                let p = r.phys[i];
                // Lazy / unbacked: phys[i] == 0 means the
                // demand-paging path will allocate + install on
                // first user-mode access. Skip here so the PTE
                // stays absent and the access faults with P=0.
                if p.raw() == 0 {
                    continue;
                }
                let mut flags = PtFlags::USER;
                let cow_count = cow_counts.as_ref().map_or(0, |counts| counts[i - first]);
                if user_page_writable_at_count(r.perms, p, cow_count) {
                    flags |= PtFlags::WRITABLE;
                }
                if !r.perms.contains(RegionPerms::EXEC) {
                    flags |= PtFlags::NO_EXEC;
                }
                let v = crate::VirtAddr::new(r.base.as_u64() + ((i as u64) << 12));
                // SAFETY: `self.root` is a valid PML4 per the
                // `new_for_user` contract; pages walked are within
                // the region we're materialising. `phys[i]` was
                // length-checked against `len/4096` at map_region.
                // SAFETY: Valid memory or trusted environment
                match unsafe { map_4kb(self.root, v, p, flags) } {
                    Ok(()) => {}
                    Err(MapError::AlreadyMapped) => {} // idempotent
                    // A user region VA that lands in the low-4 GiB window hits
                    // a 2 MiB / 1 GiB huge page in the kernel identity map that
                    // every user PML4 shares via PML4[0]. We can't split it —
                    // the table is shared with the kernel, and overriding an
                    // identity-mapped low frame would steal a page the kernel
                    // may need. This fires for a non-PIE ELF image loaded at
                    // the classic 0x400000. FAIL THE LOAD gracefully — a user
                    // binary must never panic the kernel — so the caller's
                    // materialize() error path tears the AS down and the exec
                    // returns an error instead of taking the whole system out.
                    Err(MapError::EncounteredHugePage) => {
                        return Err(AddressSpaceError::Overlap);
                    }
                    // A non-canonical VA can only come from a region whose
                    // base the caller failed to validate (map_region now
                    // rejects those, but stay graceful for any path that
                    // predates the check — a user-supplied MAP_FIXED hint
                    // must never panic the kernel).
                    Err(MapError::NonCanonical) => {
                        return Err(AddressSpaceError::OutOfRange);
                    }
                    // Any other map_4kb failure (frame exhaustion `NoFrame`, an
                    // unexpected `AlreadyMapped`, a misaligned VA) is caused by a
                    // user-triggered fork/exec/mmap under resource pressure — it
                    // must fail the AS build so the caller tears the AS down and
                    // returns an error, NEVER panic the whole kernel (systemd
                    // spawns dozens of services concurrently under SMP, so this
                    // path is hit under heavy allocation load).
                    Err(_) => {
                        return Err(AddressSpaceError::Overlap);
                    }
                }
                // The page is now mapped at `v` (Ok or idempotent AlreadyMapped;
                // every error arm returned above). Record the reverse mapping.
                crate::rmap::add(p, self.root, v);
            }
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn materialize_window(
        &self,
        window: Option<(u64, u64)>,
    ) -> Result<(), AddressSpaceError> {
        use crate::aarch64::paging::{map_4kb, MapError, PtFlags};
        if self.root.as_u64() == 0 {
            return Err(AddressSpaceError::OutOfRange);
        }
        let regions = self.regions.lock();
        for r in regions.iter() {
            // PROT_NONE region: no PTE installed. See x86_64
            // counterpart for rationale.
            if r.perms.prot_only().0 == 0 {
                continue;
            }
            let rb = r.base.as_u64();
            let re = rb + r.len;
            let (first, last) = match window {
                Some((lo, hi)) => {
                    let first = core::cmp::max(rb, lo);
                    let last = core::cmp::min(re, hi);
                    if first >= last {
                        continue;
                    }
                    (((first - rb) >> 12) as usize, ((last - rb) >> 12) as usize)
                }
                None => (0, r.phys.len()),
            };
            let cow_counts = r
                .perms
                .contains(RegionPerms::COW)
                .then(|| crate::frame::cow::count_batch(&r.phys[first..last]));
            for i in first..last {
                let p = r.phys[i];
                if p.raw() == 0 {
                    continue;
                }
                let cow_count = cow_counts.as_ref().map_or(0, |counts| counts[i - first]);
                let mut flags = if user_page_writable_at_count(r.perms, p, cow_count) {
                    PtFlags::AP_RW_EL0
                } else {
                    PtFlags::AP_RO_EL0
                };
                if !r.perms.contains(RegionPerms::EXEC) {
                    flags = flags | PtFlags::UXN | PtFlags::PXN;
                }
                let v = crate::VirtAddr::new(r.base.as_u64() + ((i as u64) << 12));
                // SAFETY: root is valid per `new_for_user`; pages
                // covered are within the just-allocated region.
                // `phys[i]` length was checked at map_region.
                // SAFETY: Valid memory or trusted environment
                match unsafe { map_4kb(self.root, v, p, flags) } {
                    Ok(()) => {}
                    Err(MapError::AlreadyMapped) => {}
                    // Any other map_4kb failure (frame exhaustion `NoFrame`, an
                    // unexpected `AlreadyMapped`, a misaligned VA) is caused by a
                    // user-triggered fork/exec/mmap under resource pressure — it
                    // must fail the AS build so the caller tears the AS down and
                    // returns an error, NEVER panic the whole kernel (systemd
                    // spawns dozens of services concurrently under SMP, so this
                    // path is hit under heavy allocation load).
                    Err(_) => {
                        return Err(AddressSpaceError::Overlap);
                    }
                }
                // The page is now mapped at `v`; record the reverse mapping.
                crate::rmap::add(p, self.root, v);
            }
        }
        Ok(())
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    unsafe fn materialize_window(
        &self,
        _window: Option<(u64, u64)>,
    ) -> Result<(), AddressSpaceError> {
        Err(AddressSpaceError::NotImplemented)
    }

    /// Force-rewrite every existing PTE to match the current region
    /// permission and per-page COW metadata. Unlike [`materialize`] (which
    /// skips already-mapped pages), this tears down and reinstalls every leaf
    /// PTE so writable leaves shared by a new fork child become read-only.
    ///
    /// Called on the **parent** address space after [`clone_for_fork`]
    /// to install READ-ONLY PTEs on regions that previously had WRITE.
    /// Without this the parent would continue writing to physical frames
    /// shared with the child (COW bypass), corrupting the child's view.
    ///
    /// # Safety
    /// - Identity map of the low 4 GiB must be live.
    /// - `self.root` must be a valid page-table root allocated by
    ///   `new_for_user`.
    /// - May be called while `self` is the active translation root — the
    ///   architecture permission-rewrite helper invalidates every changed
    ///   leaf before installing its replacement.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn rematerialize(&self) -> Result<(), AddressSpaceError> {
        // Hold the regions lock across the rewrite: cloning a snapshot and
        // rewriting after the drop (the previous shape) let a racing
        // munmap/MAP_FIXED overlap from a sibling thread free a frame and
        // then have the deferred rewrite re-install a PTE over it. See
        // `change_perms_range` for why the under-lock batched flush is
        // deadlock-safe.
        let g = self.regions.lock();
        let snapshot = g.snapshot();
        // SAFETY: identity-map live; `root` valid from `new_for_user`.
        unsafe { self.rewrite_perms_pages(&snapshot) };
        drop(g);
        Ok(())
    }

    /// # Safety
    /// Unsupported-architecture stub: a no-op that never touches page tables,
    /// so it has no preconditions. Present only to keep the API uniform.
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub unsafe fn rematerialize(&self) -> Result<(), AddressSpaceError> {
        Ok(())
    }

    /// Duplicate this address space for a `fork(2)`-style child.
    ///
    /// **Copy-on-write.** Per region, the child shares the
    /// parent's physical frames — `frame::cow::inc_ref(phys)` is called on
    /// every resident page so the frame allocator knows two owners (or more,
    /// for nested forks) share the page. The returned `AddressSpace` carries
    /// the same `Region.phys` Vec and both regions retain their authoritative
    /// POSIX WRITE permission while gaining the internal COW marker. Page-table
    /// materialization combines that marker with the per-frame refcount and
    /// installs read-only leaves until each page has a sole owner.
    ///
    /// On the first user-mode write to a shared page, the page-
    /// fault handler calls [`Self::cow_split_on_write`] which
    /// allocates a fresh frame, memcpys the contents, repoints
    /// the faulting AS's PTE at the new frame, and `dec_ref`s the
    /// old shared frame.
    ///
    /// # Safety
    /// - Paging is live (same Stage-4 contract `materialize`
    ///   rides on).
    /// - The frame allocator + the COW refcount table are
    ///   initialised.
    /// - Caller must `materialize()` the returned AS *and*
    ///   re-materialise the parent (since its pages just lost
    ///   WRITE) before either is re-activated.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn clone_for_fork(&self) -> Result<Self, AddressSpaceError> {
        // Exclude shared-page migration until the child has a complete alias
        // table. The child is not scheduler-visible during construction.
        let _shared_guard = SHARED_MAPPING_TRANSACTION.lock();
        // SAFETY: caller's contract — paging is live.
        let child = unsafe { Self::new_for_user() }?;

        // Mark every private region as potentially COW-shared. Keep its POSIX
        // WRITE permission authoritative; the PTE derivation consults this
        // marker plus each frame's refcount to force only shared pages RO.
        // Snapshot the resulting region list to clone into the child.
        let parent_regions: Vec<Region> = {
            let mut g = self.regions.lock();
            if !g.swap_pages.is_empty() {
                // Swap slots are single-owner today. Cloning phys=0 would
                // silently replace preserved contents with demand-zero.
                return Err(AddressSpaceError::NotImplemented);
            }
            for r in g.iter_mut() {
                // MAP_SHARED regions (POSIX shm AND borrowed device
                // frames — framebuffers, DRM dumb buffers) are genuinely
                // shared across fork: parent and child map the SAME
                // physical frames, both writable, each seeing the other's
                // writes (Linux MAP_SHARED). They must NOT be COW'd —
                // the frames are registry-owned / borrowed, not
                // COW-refcounted (the drop path likewise skips SHARED),
                // and stripping WRITE would silently fault the writer
                // into a private copy that never reaches the device.
                if r.perms.contains(RegionPerms::SHARED) {
                    continue;
                }
                // Private region: bump the COW refcount on every backing
                // frame, then mark the region so both ASes start shared pages
                // read-only and split on first authorized write.
                //
                // Skip unbacked (phys == 0) demand-paged slots: there is no
                // frame to share yet, so COW doesn't apply. `materialize`
                // already skips phys == 0, and each AS independently demand-
                // faults its own zeroed frame on first access (equivalent for
                // anonymous zero-fill pages until written). Calling inc_ref(0)
                // registered a bogus "frame 0" refcount entry that climbed into
                // the thousands across a large demand-paged region's fork, and
                // the matching dec_ref(0) on teardown risked free_frame(0) /
                // frame-0 reuse — corruption surfacing far away.
                r.perms = r.perms | RegionPerms::COW;
            }
            // Group all resident private backing by refcount shard and take
            // each touched lock once. Keep this inside the region transaction:
            // moving it below the lock would let munmap free a source before
            // its child's ownership was retained.
            let cow_frames: Vec<PhysAddr> = g
                .iter()
                .filter(|region| !region.perms.contains(RegionPerms::SHARED))
                .flat_map(|region| region.phys.iter().copied())
                .filter(|phys| phys.raw() != 0)
                .collect();
            crate::frame::cow::inc_ref_batch(&cow_frames);
            g.snapshot()
        };

        // The child's regions are a deep clone of the parent's
        // (post-mark) — same vaddr base, phys list, and logical permissions.
        for r in parent_regions.into_iter() {
            child.map_region_inner(r)?;
        }

        // Private hugetlb mappings are copied eagerly. The hugepage pool has
        // no sub-page COW metadata, so sharing a writable hardware block leaf
        // would violate fork isolation. Preserve each frame's NUMA placement.
        for region in self.huge_regions.lock().iter() {
            let mut frames = Vec::with_capacity(region.frames.len());
            for source in &region.frames {
                let replacement_result = match source.size() {
                    crate::hugepage::HugeSize::M2 => {
                        crate::hugepage::alloc_hugepage_2m_on(source.node())
                    }
                    crate::hugepage::HugeSize::G1 => {
                        crate::hugepage::alloc_hugepage_1g_on(source.node())
                    }
                };
                let replacement = match replacement_result {
                    Ok(frame) => frame,
                    Err(_) => {
                        for frame in frames {
                            crate::hugepage::free_hugepage(frame);
                        }
                        return Err(AddressSpaceError::OutOfRange);
                    }
                };
                // SAFETY: both huge frames are exclusively owned and
                // identity-reachable; their equal size bounds the copy.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        source.phys() as *const u8,
                        replacement.phys() as *mut u8,
                        source.size_bytes() as usize,
                    );
                }
                frames.push(replacement);
            }
            // SAFETY: the child root is fresh and the cloned region is
            // aligned and non-overlapping by construction.
            unsafe {
                child.map_huge_region(HugeRegion {
                    base: region.base,
                    len: region.len,
                    perms: region.perms,
                    size: region.size,
                    frames,
                })?;
            }
        }

        // Wave-49fu: inherit the parent's mmap_cursor. Without this
        // the child's first malloc-driven mmap (heap grow_heap) picks
        // MMAP_CURSOR_BASE — which already overlaps a parent-mmap'd
        // region the child just cloned — and map_region fails with
        // Overlap, breaking libc's malloc in the post-fork child.
        let parent_cursor = self.mmap_cursor.load(core::sync::atomic::Ordering::Relaxed);
        child
            .mmap_cursor
            .store(parent_cursor, core::sync::atomic::Ordering::Relaxed);

        Ok(child)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub unsafe fn clone_for_fork(&self) -> Result<Self, AddressSpaceError> {
        Err(AddressSpaceError::NotImplemented)
    }

    /// Split a COW-shared page on first write.
    ///
    /// Find the region containing `vaddr`, allocate a fresh frame,
    /// memcpy the old shared frame's contents into it, replace the
    /// region's per-page phys entry with the new frame,
    /// `dec_ref` the old frame. The caller is responsible for re-materialising
    /// the affected page in the live page-table tree (a real
    /// page-fault handler would do that on the way back out of
    /// the trap).
    ///
    /// Returns `Unmapped` if no region contains `vaddr`, if WRITE is not an
    /// authoritative permission, or if the region was not fork-COW marked.
    /// Returns `Ok(())` if the split succeeded OR if the frame
    /// already had refcount 1 (sole owner — no split needed,
    /// just regain WRITE).
    ///
    /// The x86_64 #PF handler in `frame/src/x86_64/trap.rs` calls
    /// this routine on user-mode write-to-RO faults (P+W+U bits
    /// set in the error code), then calls [`Self::remap_page`] to
    /// install the new PTE; production fork() callers therefore
    /// observe true split-on-write semantics. Aarch64 page-fault
    /// integration lands alongside the EL0 ↔ EL1 trap pipeline.
    ///
    /// # Safety
    /// - The low-4-GiB identity map must be live (used to memcpy
    ///   the old frame's bytes into the new one).
    /// - The frame allocator + COW refcount table are
    ///   initialised.
    pub unsafe fn cow_split_on_write(&self, vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
        // Tickets are page-scoped: faults at different byte offsets in one
        // page must serialize behind the same copy operation.
        let v = vaddr.as_u64() & !0xFFFu64;
        let (ticket, old_phys) = {
            use core::sync::atomic::Ordering;

            let mut regions = self.regions.lock();
            let region = regions.containing(v).ok_or(AddressSpaceError::Unmapped)?;
            // A present write fault is recoverable only when fork explicitly
            // made this logically-writable private mapping COW. In particular,
            // mprotect(PROT_READ) must fall through to SIGSEGV.
            if !region.perms.contains(RegionPerms::WRITE)
                || !region.perms.contains(RegionPerms::COW)
            {
                return Err(AddressSpaceError::Unmapped);
            }
            let page_idx = ((v - region.base.as_u64()) >> 12) as usize;
            let old_phys = *region
                .phys
                .get(page_idx)
                .ok_or(AddressSpaceError::OutOfRange)?;
            if crate::frame::cow::count(old_phys) <= 1 {
                return Ok(());
            }
            if regions.cow_pages.contains_key(&v) {
                // A peer owns this exact copy. The trap path retries the
                // still-read-only leaf while unrelated pages keep progressing.
                return Ok(());
            }
            let ticket = NEXT_COW_TICKET.fetch_add(1, Ordering::Relaxed);
            regions.cow_pages.insert(v, ticket);
            // VMA teardown may now remove its owner, but this temporary
            // reference keeps the source alive until the copy completes.
            crate::frame::cow::inc_ref(old_phys);
            (ticket, old_phys)
        };

        let new_frame = match crate::frame::alloc_user_frame() {
            Ok(frame) => frame,
            Err(_) => {
                let mut regions = self.regions.lock();
                if regions.cow_pages.get(&v).copied() == Some(ticket) {
                    regions.cow_pages.remove(&v);
                }
                drop(regions);
                crate::frame::free_frame(crate::frame::PhysFrame::new(old_phys));
                return Err(AddressSpaceError::OutOfRange);
            }
        };
        let new_phys = new_frame.start_address();
        // SAFETY: kernel_ptr / kernel_mut_ptr resolve through the
        // kernel's identity map (x86_64) or TTBR1 high-half RAM
        // window (aarch64), so the access stays valid even when
        // the calling thread has swapped TTBR0/CR3 to a user
        // root. Source/dest ranges are non-overlapping (distinct
        // freshly-allocated frames).
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::ptr::copy_nonoverlapping(
                old_phys.kernel_ptr::<u8>(),
                new_phys.kernel_mut_ptr::<u8>(),
                crate::frame::PAGE_SIZE as usize,
            );
        }

        let published = {
            let mut regions = self.regions.lock();
            let owns_ticket = regions.cow_pages.get(&v).copied() == Some(ticket);
            let current_matches = regions.containing(v).is_some_and(|region| {
                let page_idx = ((v - region.base.as_u64()) >> 12) as usize;
                region.perms.contains(RegionPerms::WRITE)
                    && region.perms.contains(RegionPerms::COW)
                    && region.phys.get(page_idx).copied() == Some(old_phys)
            });
            if owns_ticket && current_matches {
                let region = regions
                    .containing_mut(v)
                    .expect("COW region disappeared under its lock");
                let page_idx = ((v - region.base.as_u64()) >> 12) as usize;
                region.phys[page_idx] = new_phys;
                // This owner's page now maps its private copy: move its rmap
                // entry (other COW sharers of `old_phys` keep theirs).
                crate::rmap::remove(old_phys, self.root, VirtAddr::new(v));
                crate::rmap::add(new_phys, self.root, VirtAddr::new(v));
                regions.cow_pages.remove(&v);
                true
            } else {
                if owns_ticket {
                    regions.cow_pages.remove(&v);
                }
                false
            }
        };

        if published {
            // Release both the region's old ownership and the temporary pin.
            // Only the final decrement can actually return the source frame.
            crate::frame::free_frame(crate::frame::PhysFrame::new(old_phys));
            crate::frame::free_frame(crate::frame::PhysFrame::new(old_phys));
        } else {
            crate::frame::free_frame(new_frame);
            crate::frame::free_frame(crate::frame::PhysFrame::new(old_phys));
        }
        Ok(())
    }

    /// Move one resident, privately-owned 4 KiB page to `target_node`.
    ///
    /// The backing-list update and leaf-PTE replacement are serialized by
    /// the region lock. The old frame is not released until the replacement
    /// PTE is installed and any required cross-CPU TLB invalidation has
    /// completed, so no CPU can retain access to a frame returned to the
    /// buddy allocator.
    ///
    /// Returns the page's previous NUMA node. An already-local page succeeds
    /// without copying. Lazy/unmapped pages return [`AddressSpaceError::Unmapped`];
    /// externally-owned shared mappings return
    /// [`AddressSpaceError::SharedMapping`].
    ///
    /// # Safety
    /// The address-space root and direct-map/identity-map prerequisites are
    /// the same as [`Self::remap_page`].
    pub unsafe fn migrate_page_to_node(
        &self,
        vaddr: VirtAddr,
        target_node: usize,
    ) -> Result<usize, AddressSpaceError> {
        if target_node >= crate::frame::MAX_NUMA_NODES || self.root.as_u64() == 0 {
            return Err(AddressSpaceError::InvalidNode);
        }
        if let Some(result) = self.migrate_huge_page_to_node(vaddr, target_node) {
            return result;
        }
        let page_va = VirtAddr::new(vaddr.as_u64() & !0xFFF);
        let mut regions = self.regions.lock();
        let v = page_va.as_u64();
        let region = regions
            .iter_mut()
            .find(|r| {
                let base = r.base.as_u64();
                v >= base && v < base + r.len
            })
            .ok_or(AddressSpaceError::Unmapped)?;
        if region.perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        let page_idx = ((v - region.base.as_u64()) >> 12) as usize;
        let old_phys = region.phys[page_idx];
        if old_phys.raw() == 0 {
            return Err(AddressSpaceError::Unmapped);
        }
        // SAFETY: narf-frame supplies the topology hook in kernel binaries.
        let old_node = unsafe { crate::frame::narf_phys_node(old_phys.raw()) };
        if old_node == target_node {
            return Ok(old_node);
        }

        let new_frame = crate::frame::alloc_user_frame_on_strict(target_node)
            .map_err(|_| AddressSpaceError::OutOfRange)?;
        let new_phys = new_frame.start_address();
        // SAFETY: both frames are live, distinct 4 KiB direct-map ranges.
        unsafe {
            core::ptr::copy_nonoverlapping(
                old_phys.kernel_ptr::<u8>(),
                new_phys.kernel_mut_ptr::<u8>(),
                crate::frame::PAGE_SIZE as usize,
            );
        }

        // SAFETY: the live AS owns the page-table root; page_va and both
        // physical frames were validated from its private region.
        let map_result = unsafe {
            #[cfg(target_arch = "x86_64")]
            {
                use crate::x86_64::paging::{map_4kb, unmap_4kb_local, PtFlags};
                let mut flags = PtFlags::USER;
                if user_page_writable(region.perms, new_phys) {
                    flags |= PtFlags::WRITABLE;
                }
                if !region.perms.contains(RegionPerms::EXEC) {
                    flags |= PtFlags::NO_EXEC;
                }
                let _ = unmap_4kb_local(self.root, page_va);
                map_4kb(self.root, page_va, new_phys, flags)
            }
            #[cfg(target_arch = "aarch64")]
            {
                use crate::aarch64::paging::{map_4kb, unmap_4kb, PtFlags};
                let mut flags = if user_page_writable(region.perms, new_phys) {
                    PtFlags::AP_RW_EL0
                } else {
                    PtFlags::AP_RO_EL0
                };
                if !region.perms.contains(RegionPerms::EXEC) {
                    flags = flags | PtFlags::UXN | PtFlags::PXN;
                }
                let _ = unmap_4kb(self.root, page_va);
                map_4kb(self.root, page_va, new_phys, flags)
            }
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            {
                Err(crate::x86_64::paging::MapError::InvalidAddress)
            }
        };
        if map_result.is_err() {
            // Best-effort rollback: preserve the original mapping if the
            // replacement leaf could not be installed.
            #[cfg(target_arch = "x86_64")]
            {
                use crate::x86_64::paging::{map_4kb, PtFlags};
                let mut flags = PtFlags::USER;
                if user_page_writable(region.perms, old_phys) {
                    flags |= PtFlags::WRITABLE;
                }
                if !region.perms.contains(RegionPerms::EXEC) {
                    flags |= PtFlags::NO_EXEC;
                }
                // SAFETY: same root/page/backing invariants as above.
                let _ = unsafe { map_4kb(self.root, page_va, old_phys, flags) };
            }
            #[cfg(target_arch = "aarch64")]
            {
                use crate::aarch64::paging::{map_4kb, PtFlags};
                let mut flags = if user_page_writable(region.perms, old_phys) {
                    PtFlags::AP_RW_EL0
                } else {
                    PtFlags::AP_RO_EL0
                };
                if !region.perms.contains(RegionPerms::EXEC) {
                    flags = flags | PtFlags::UXN | PtFlags::PXN;
                }
                // SAFETY: same root/page/backing invariants as above.
                let _ = unsafe { map_4kb(self.root, page_va, old_phys, flags) };
            }
            crate::frame::free_frame(new_frame);
            return Err(AddressSpaceError::NotImplemented);
        }
        region.phys[page_idx] = new_phys;
        drop(regions);

        // The page now maps a fresh frame on the target node: move its rmap
        // entry so a later reverse-map walk finds the live frame.
        crate::rmap::remove(old_phys, self.root, page_va);
        crate::rmap::add(new_phys, self.root, page_va);

        self.flush_region_broadcast(page_va, 1);
        crate::frame::free_frame(crate::frame::PhysFrame::new(old_phys));
        Ok(old_node)
    }

    /// Copy `old_phys` → `new_phys` and atomically repoint the leaf at
    /// `page_va` from old to new, rolling the leaf back to `old_phys` if the
    /// replacement cannot be installed. Returns `Ok` when `new_phys` is mapped,
    /// `Err(())` (mapping restored to `old_phys`) otherwise.
    ///
    /// The relocation core of [`Self::relocate_page`]. It does NOT touch
    /// `Region.phys`, the reverse map, the cross-CPU TLB broadcast, or free
    /// either frame — the caller owns that bookkeeping under the region lock.
    /// `perms` is copied out of the region so no borrow is held across the call.
    /// (`migrate_page_to_node` predates this and still inlines the equivalent
    /// mechanics; folding it onto this helper is a follow-up.)
    ///
    /// # Safety
    /// `self.root` must be a live root; `page_va` must currently map `old_phys`
    /// in a private region, and `new_phys` must be a fresh, exclusively-owned
    /// frame; the direct map must be live.
    #[cfg(target_arch = "x86_64")]
    unsafe fn relocate_leaf(
        &self,
        page_va: VirtAddr,
        perms: RegionPerms,
        old_phys: PhysAddr,
        new_phys: PhysAddr,
    ) -> Result<(), ()> {
        // SAFETY: both frames are live, distinct 4 KiB direct-map ranges.
        unsafe {
            core::ptr::copy_nonoverlapping(
                old_phys.kernel_ptr::<u8>(),
                new_phys.kernel_mut_ptr::<u8>(),
                crate::frame::PAGE_SIZE as usize,
            );
        }
        // SAFETY: the live AS owns the root; `page_va` + both frames validated
        // by the caller from the private region.
        let map_result = unsafe {
            #[cfg(target_arch = "x86_64")]
            {
                use crate::x86_64::paging::{map_4kb, unmap_4kb_local, PtFlags};
                let mut flags = PtFlags::USER;
                if user_page_writable(perms, new_phys) {
                    flags |= PtFlags::WRITABLE;
                }
                if !perms.contains(RegionPerms::EXEC) {
                    flags |= PtFlags::NO_EXEC;
                }
                let _ = unmap_4kb_local(self.root, page_va);
                map_4kb(self.root, page_va, new_phys, flags).map_err(|_| ())
            }
            #[cfg(target_arch = "aarch64")]
            {
                use crate::aarch64::paging::{map_4kb, unmap_4kb, PtFlags};
                let mut flags = if user_page_writable(perms, new_phys) {
                    PtFlags::AP_RW_EL0
                } else {
                    PtFlags::AP_RO_EL0
                };
                if !perms.contains(RegionPerms::EXEC) {
                    flags = flags | PtFlags::UXN | PtFlags::PXN;
                }
                let _ = unmap_4kb(self.root, page_va);
                map_4kb(self.root, page_va, new_phys, flags).map_err(|_| ())
            }
        };
        if map_result.is_err() {
            // Best-effort rollback: restore the original mapping so the page
            // stays valid at `old_phys` (which the caller then keeps + frees the
            // unused `new_phys`).
            // SAFETY: same root/page/backing invariants as above.
            unsafe {
                #[cfg(target_arch = "x86_64")]
                {
                    use crate::x86_64::paging::{map_4kb, PtFlags};
                    let mut flags = PtFlags::USER;
                    if user_page_writable(perms, old_phys) {
                        flags |= PtFlags::WRITABLE;
                    }
                    if !perms.contains(RegionPerms::EXEC) {
                        flags |= PtFlags::NO_EXEC;
                    }
                    let _ = map_4kb(self.root, page_va, old_phys, flags);
                }
                #[cfg(target_arch = "aarch64")]
                {
                    use crate::aarch64::paging::{map_4kb, PtFlags};
                    let mut flags = if user_page_writable(perms, old_phys) {
                        PtFlags::AP_RW_EL0
                    } else {
                        PtFlags::AP_RO_EL0
                    };
                    if !perms.contains(RegionPerms::EXEC) {
                        flags = flags | PtFlags::UXN | PtFlags::PXN;
                    }
                    let _ = map_4kb(self.root, page_va, old_phys, flags);
                }
            }
            return Err(());
        }
        Ok(())
    }

    /// Relocate one resident private page at `vaddr` to a FRESH frame on its own
    /// NUMA node — the compaction primitive. Unlike [`Self::migrate_page_to_node`]
    /// it always moves the page to a new physical frame (there is no "already on
    /// the target node" short-circuit), so a caller defragmenting physical
    /// memory can evacuate a specific frame. Returns the new backing frame.
    ///
    /// Rejects SHARED, huge, lazy/unmapped, and COW-shared pages (a COW-shared
    /// frame has other owners whose PTEs this single-AS call cannot rewrite —
    /// that is the multi-owner migration follow-up). Serialized by the region
    /// lock against concurrent faults/unmaps in this address space.
    ///
    /// # Safety
    /// Same address-space-root / direct-map prerequisites as
    /// [`Self::migrate_page_to_node`].
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn relocate_page(&self, vaddr: VirtAddr) -> Result<PhysAddr, AddressSpaceError> {
        // SAFETY: forwarded to the caller's live-root / direct-map contract.
        unsafe { self.relocate_page_inner(vaddr, None) }
    }

    /// Like [`Self::relocate_page`] but relocates ONLY if the page still maps
    /// `expected_src`; returns [`AddressSpaceError::Unmapped`] if it moved out
    /// from under the caller (a concurrent fault/unmap). Used by
    /// [`crate::migrate::migrate_frame`] to evacuate one specific physical frame
    /// race-safely.
    ///
    /// # Safety
    /// Same prerequisites as [`Self::relocate_page`].
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn relocate_frame_at(
        &self,
        vaddr: VirtAddr,
        expected_src: PhysAddr,
    ) -> Result<PhysAddr, AddressSpaceError> {
        // SAFETY: forwarded to the caller's live-root / direct-map contract.
        unsafe { self.relocate_page_inner(vaddr, Some(expected_src)) }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn relocate_page_inner(
        &self,
        vaddr: VirtAddr,
        expected: Option<PhysAddr>,
    ) -> Result<PhysAddr, AddressSpaceError> {
        if self.root.as_u64() == 0 {
            return Err(AddressSpaceError::OutOfRange);
        }
        let page_va = VirtAddr::new(vaddr.as_u64() & !0xFFF);
        let v = page_va.as_u64();
        let mut regions = self.regions.lock();
        let region = regions
            .containing_mut(v)
            .ok_or(AddressSpaceError::Unmapped)?;
        if region.perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        let page_idx = ((v - region.base.as_u64()) >> 12) as usize;
        let old_phys = *region
            .phys
            .get(page_idx)
            .ok_or(AddressSpaceError::Unmapped)?;
        if old_phys.raw() == 0 {
            return Err(AddressSpaceError::Unmapped);
        }
        // Migration of a SPECIFIC frame (compaction) bails if the page moved out
        // from under us since rmap named it (a concurrent fault/unmap/COW), so it
        // never relocates the wrong page.
        if let Some(exp) = expected {
            if old_phys != exp {
                return Err(AddressSpaceError::Unmapped);
            }
        }
        // A COW-shared frame has other owners; relocating it here would leave
        // their PTEs pointing at the freed source. Refuse — multi-owner
        // migration (rmap-walk every owner) is a follow-up.
        if crate::frame::cow::count(old_phys) > 1 {
            return Err(AddressSpaceError::NotImplemented);
        }
        // Also refuse a page mid-swap-transition.
        if regions.swap_pages.contains_key(&v) {
            return Err(AddressSpaceError::NotImplemented);
        }
        let region = regions
            .containing_mut(v)
            .ok_or(AddressSpaceError::Unmapped)?;
        let perms = region.perms;
        // SAFETY: page_va maps old_phys on old_phys's own node keeps the copy
        // local; alloc on that node.
        let node = unsafe { crate::frame::narf_phys_node(old_phys.raw()) };
        let new_frame = crate::frame::alloc_user_frame_on_strict(node)
            .map_err(|_| AddressSpaceError::OutOfRange)?;
        let new_phys = new_frame.start_address();
        // SAFETY: live root; page_va maps old_phys; new_phys is a fresh frame.
        if unsafe { self.relocate_leaf(page_va, perms, old_phys, new_phys) }.is_err() {
            crate::frame::free_frame(new_frame);
            return Err(AddressSpaceError::NotImplemented);
        }
        region.phys[page_idx] = new_phys;
        drop(regions);

        // Move the reverse mapping to the live frame, flush peers before the
        // source is freed, then release it.
        crate::rmap::remove(old_phys, self.root, page_va);
        crate::rmap::add(new_phys, self.root, page_va);
        self.flush_region_broadcast(page_va, 1);
        crate::frame::free_frame(crate::frame::PhysFrame::new(old_phys));
        Ok(new_phys)
    }

    /// Repoint one owner's shared COW page at `vaddr` from `expected_src` to the
    /// pre-copied, shared `dst` frame — one step of multi-owner
    /// [`crate::migrate::migrate_frame`]. Under the region lock: verifies the
    /// page still maps `expected_src` (else the owner raced — COW-split or
    /// unmapped — and `Err(())` is returned so the caller drops this owner),
    /// installs a READ-ONLY leaf for `dst` (so a later write still faults into a
    /// proper COW split against `dst`'s shared refcount), repoints `Region.phys`
    /// and the reverse map, and flushes. Does NOT copy, allocate, free, or touch
    /// the COW refcount — the caller owns `dst`'s content and the src→dst
    /// refcount move.
    ///
    /// # Safety
    /// `self.root` must be a live root; `dst` must be a live frame holding a copy
    /// of `expected_src`'s contents; the direct map must be live.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn repoint_shared_page(
        &self,
        vaddr: VirtAddr,
        expected_src: PhysAddr,
        dst: PhysAddr,
    ) -> Result<(), ()> {
        if self.root.as_u64() == 0 {
            return Err(());
        }
        let page_va = VirtAddr::new(vaddr.as_u64() & !0xFFF);
        let v = page_va.as_u64();
        let mut regions = self.regions.lock();
        let (page_idx, perms) = {
            let region = regions.containing(v).ok_or(())?;
            let page_idx = ((v - region.base.as_u64()) >> 12) as usize;
            if region.phys.get(page_idx).copied() != Some(expected_src) {
                return Err(()); // raced: no longer maps the source
            }
            (page_idx, region.perms)
        };
        // Install a READ-ONLY leaf for `dst`: the page stays COW-shared, so a
        // write must fault into cow_split against dst's refcount.
        // SAFETY: live root; page_va currently maps expected_src.
        let installed = unsafe {
            use crate::x86_64::paging::{map_4kb, unmap_4kb_local, PtFlags};
            let mut flags = PtFlags::USER;
            if !perms.contains(RegionPerms::EXEC) {
                flags |= PtFlags::NO_EXEC;
            }
            let _ = unmap_4kb_local(self.root, page_va);
            map_4kb(self.root, page_va, dst, flags).is_ok()
        };
        if !installed {
            // Best-effort restore of the original mapping so the page stays valid.
            // SAFETY: same live-root / backing contract.
            unsafe {
                use crate::x86_64::paging::{map_4kb, PtFlags};
                let mut flags = PtFlags::USER;
                if user_page_writable(perms, expected_src) {
                    flags |= PtFlags::WRITABLE;
                }
                if !perms.contains(RegionPerms::EXEC) {
                    flags |= PtFlags::NO_EXEC;
                }
                let _ = map_4kb(self.root, page_va, expected_src, flags);
            }
            return Err(());
        }
        regions
            .containing_mut(v)
            .expect("region vanished under its own lock")
            .phys[page_idx] = dst;
        drop(regions);
        crate::rmap::remove(expected_src, self.root, page_va);
        crate::rmap::add(dst, self.root, page_va);
        self.flush_region_broadcast(page_va, 1);
        Ok(())
    }

    /// Move one resident private page to the closest node in the next slower
    /// memory tier.
    ///
    /// `allowed_nodes` is the caller's cpuset/mempolicy boundary. The source
    /// node is resolved from the authoritative backing list, then
    /// [`crate::numa_tier::demotion_target`] selects only a strictly lower
    /// tier. The actual ownership transfer, copy, PTE replacement, rollback,
    /// and TLB invalidation are delegated to [`Self::migrate_page_to_node`].
    ///
    /// # Safety
    /// Same address-space root and mapping-lifetime requirements as
    /// [`Self::migrate_page_to_node`].
    pub unsafe fn demote_page(
        &self,
        vaddr: VirtAddr,
        allowed_nodes: u64,
    ) -> Result<usize, AddressSpaceError> {
        let v = vaddr.as_u64();
        let source = {
            let huge = self.huge_regions.lock();
            huge.iter().find_map(|region| {
                let base = region.base.as_u64();
                if v < base || v >= base.saturating_add(region.len) {
                    return None;
                }
                let leaf_bytes = match region.size {
                    crate::hugepage::HugeSize::M2 => crate::hugepage::HUGEPAGE_2M_BYTES,
                    crate::hugepage::HugeSize::G1 => crate::hugepage::HUGEPAGE_1G_BYTES,
                };
                region
                    .frames
                    .get(((v - base) / leaf_bytes) as usize)
                    .map(|frame| frame.node())
            })
        }
        .or_else(|| {
            let regions = self.regions.lock();
            regions.iter().find_map(|region| {
                let base = region.base.as_u64();
                if v < base || v >= base.saturating_add(region.len) {
                    return None;
                }
                let phys = *region.phys.get(((v - base) >> 12) as usize)?;
                if phys.raw() == 0 {
                    None
                } else {
                    // SAFETY: non-zero backing entries name live frames.
                    Some(unsafe { crate::frame::narf_phys_node(phys.raw()) })
                }
            })
        })
        .ok_or(AddressSpaceError::Unmapped)?;

        let target = crate::numa_tier::demotion_target(source, allowed_nodes)
            .ok_or(AddressSpaceError::NoDemotionTarget)?;
        // SAFETY: inherited from this method's contract.
        unsafe { self.migrate_page_to_node(vaddr, target) }
    }

    /// Migrate the hardware huge leaf containing `vaddr`, if any.
    ///
    /// Huge mappings cannot be split into 4 KiB PTEs without changing their
    /// ABI and TLB behavior, so Linux-compatible migration of any constituent
    /// address moves the complete 2 MiB or 1 GiB leaf.
    fn migrate_huge_page_to_node(
        &self,
        vaddr: VirtAddr,
        target_node: usize,
    ) -> Option<Result<usize, AddressSpaceError>> {
        let mut huge = self.huge_regions.lock();
        let v = vaddr.as_u64();
        let (region_idx, frame_idx, leaf_va, size, perms) =
            huge.iter().enumerate().find_map(|(region_idx, region)| {
                let base = region.base.as_u64();
                if v < base || v >= base.saturating_add(region.len) {
                    return None;
                }
                let page_size = match region.size {
                    crate::hugepage::HugeSize::M2 => crate::hugepage::HUGEPAGE_2M_BYTES,
                    crate::hugepage::HugeSize::G1 => crate::hugepage::HUGEPAGE_1G_BYTES,
                };
                let frame_idx = ((v - base) / page_size) as usize;
                Some((
                    region_idx,
                    frame_idx,
                    VirtAddr::new(base + frame_idx as u64 * page_size),
                    region.size,
                    region.perms,
                ))
            })?;
        if perms.contains(RegionPerms::SHARED) {
            return Some(Err(AddressSpaceError::SharedMapping));
        }
        let old = huge[region_idx].frames[frame_idx];
        let old_node = old.node();
        if old_node == target_node {
            return Some(Ok(old_node));
        }
        let new = match crate::hugepage::alloc_hugepage_on(size, target_node) {
            Ok(frame) => frame,
            Err(_) => return Some(Err(AddressSpaceError::OutOfRange)),
        };
        let bytes = new.size_bytes();
        // SAFETY: both huge frames are live, distinct, naturally aligned
        // direct-map ranges of the same size, and the region lock prevents a
        // concurrent unmap from returning the source frame to the pool.
        unsafe {
            core::ptr::copy_nonoverlapping(
                PhysAddr::new(old.phys()).kernel_ptr::<u8>(),
                PhysAddr::new(new.phys()).kernel_mut_ptr::<u8>(),
                bytes as usize,
            );
        }

        if self.unmap_huge_leaf(leaf_va, size).is_err() {
            crate::hugepage::free_hugepage(new);
            return Some(Err(AddressSpaceError::Unmapped));
        }
        if let Err(error) = self.map_huge_leaf(leaf_va, new.phys(), size, perms) {
            // The old leaf's page-table ancestors remain allocated, so
            // restoring the same-size leaf cannot require new memory.
            let rollback = self.map_huge_leaf(leaf_va, old.phys(), size, perms);
            crate::hugepage::free_hugepage(new);
            return Some(match rollback {
                Ok(()) => Err(error),
                Err(_) => Err(AddressSpaceError::NotImplemented),
            });
        }
        huge[region_idx].frames[frame_idx] = new;
        drop(huge);

        self.flush_region_broadcast(leaf_va, bytes >> 12);
        crate::hugepage::free_hugepage(old);
        crate::frame::account_numa_allocation(target_node, target_node, bytes >> 12);
        Some(Ok(old_node))
    }

    /// Migrate all resident private pages whose current node is in
    /// `old_nodes` onto `new_nodes`, distributing pages round-robin across
    /// the destination mask. Returns the number of pages that could not be
    /// moved, matching `migrate_pages(2)`'s success return convention.
    ///
    /// # Safety
    /// Same address-space and direct-map prerequisites as
    /// [`Self::migrate_page_to_node`].
    pub unsafe fn migrate_pages_between(
        &self,
        old_nodes: u64,
        new_nodes: u64,
    ) -> Result<usize, AddressSpaceError> {
        if old_nodes == 0 || new_nodes == 0 {
            return Err(AddressSpaceError::InvalidNode);
        }
        let destinations: Vec<usize> = (0..crate::frame::MAX_NUMA_NODES)
            .filter(|node| (new_nodes >> node) & 1 != 0)
            .collect();
        if destinations.is_empty() {
            return Err(AddressSpaceError::InvalidNode);
        }
        let mut candidates: Vec<(VirtAddr, usize)> = {
            let regions = self.regions.lock();
            let mut out = Vec::new();
            for region in regions.iter() {
                if region.perms.contains(RegionPerms::SHARED) {
                    continue;
                }
                for (idx, phys) in region.phys.iter().enumerate() {
                    if phys.raw() == 0 {
                        continue;
                    }
                    // SAFETY: narf-frame supplies the topology hook.
                    let node = unsafe { crate::frame::narf_phys_node(phys.raw()) };
                    if (old_nodes >> node) & 1 != 0 {
                        out.push((VirtAddr::new(region.base.as_u64() + (idx as u64) * 4096), 1));
                    }
                }
            }
            out
        };
        {
            let huge = self.huge_regions.lock();
            for region in huge.iter() {
                if region.perms.contains(RegionPerms::SHARED) {
                    continue;
                }
                let page_size = match region.size {
                    crate::hugepage::HugeSize::M2 => crate::hugepage::HUGEPAGE_2M_BYTES,
                    crate::hugepage::HugeSize::G1 => crate::hugepage::HUGEPAGE_1G_BYTES,
                };
                for (idx, frame) in region.frames.iter().enumerate() {
                    if (old_nodes >> frame.node()) & 1 != 0 {
                        candidates.push((
                            VirtAddr::new(region.base.as_u64() + idx as u64 * page_size),
                            (page_size >> 12) as usize,
                        ));
                    }
                }
            }
        }
        let mut failed = 0usize;
        for (idx, (va, pages)) in candidates.into_iter().enumerate() {
            // SAFETY: forwarded contract; each VA came from this AS's live
            // backing list and migrate_page_to_node revalidates it under lock.
            if unsafe { self.migrate_page_to_node(va, destinations[idx % destinations.len()]) }
                .is_err()
            {
                failed += pages;
            }
        }
        Ok(failed)
    }

    /// Check or migrate resident pages in `[start, start + len)` so their
    /// backing lies in `target_nodes`.
    ///
    /// When `do_move` is false this is a placement audit and the return value
    /// is the number of resident pages outside the mask. When true, private
    /// pages are migrated round-robin across the target nodes and the return
    /// value is the number that remain misplaced. A hole in the requested
    /// virtual range returns [`AddressSpaceError::Unmapped`].
    ///
    /// # Safety
    /// Same address-space and direct-map prerequisites as
    /// [`Self::migrate_page_to_node`].
    pub unsafe fn conform_range_to_nodes(
        &self,
        start: VirtAddr,
        len: u64,
        target_nodes: u64,
        do_move: bool,
    ) -> Result<usize, AddressSpaceError> {
        if len == 0 || target_nodes == 0 {
            return Err(AddressSpaceError::InvalidNode);
        }
        let begin = start.as_u64();
        let end = begin
            .checked_add(len)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let destinations: Vec<usize> = (0..crate::frame::MAX_NUMA_NODES)
            .filter(|node| (target_nodes >> node) & 1 != 0)
            .collect();
        if destinations.is_empty() {
            return Err(AddressSpaceError::InvalidNode);
        }

        let (mut candidates, mut shared_misplaced, mut coverage) = {
            let regions = self.regions.lock();
            let coverage: Vec<(u64, u64)> = regions
                .iter()
                .filter_map(|region| {
                    let lo = region.base.as_u64().max(begin);
                    let hi = region.base.as_u64().saturating_add(region.len).min(end);
                    (lo < hi).then_some((lo, hi))
                })
                .collect();
            let mut pages = Vec::new();
            let mut shared = 0usize;
            for region in regions.iter() {
                let rbase = region.base.as_u64();
                let rlimit = rbase.saturating_add(region.len);
                let lo = begin.max(rbase);
                let hi = end.min(rlimit);
                if lo >= hi {
                    continue;
                }
                let first = ((lo - rbase) >> 12) as usize;
                let last = ((hi - rbase + 4095) >> 12) as usize;
                for idx in first..last.min(region.phys.len()) {
                    let phys = region.phys[idx];
                    if phys.raw() == 0 {
                        continue;
                    }
                    // SAFETY: narf-frame supplies the topology hook.
                    let node = unsafe { crate::frame::narf_phys_node(phys.raw()) };
                    if (target_nodes >> node) & 1 != 0 {
                        continue;
                    }
                    if region.perms.contains(RegionPerms::SHARED) {
                        shared += 1;
                    } else {
                        pages.push((VirtAddr::new(rbase + (idx as u64) * 4096), 1));
                    }
                }
            }
            (pages, shared, coverage)
        };
        let huge_coverage = {
            let huge = self.huge_regions.lock();
            let mut coverage = Vec::new();
            for region in huge.iter() {
                let rbase = region.base.as_u64();
                let rlimit = rbase.saturating_add(region.len);
                let lo = begin.max(rbase);
                let hi = end.min(rlimit);
                if lo >= hi {
                    continue;
                }
                coverage.push((lo, hi));
                let page_size = match region.size {
                    crate::hugepage::HugeSize::M2 => crate::hugepage::HUGEPAGE_2M_BYTES,
                    crate::hugepage::HugeSize::G1 => crate::hugepage::HUGEPAGE_1G_BYTES,
                };
                let first = ((lo - rbase) / page_size) as usize;
                let last = (hi - rbase).div_ceil(page_size) as usize;
                for idx in first..last.min(region.frames.len()) {
                    let frame = region.frames[idx];
                    if (target_nodes >> frame.node()) & 1 != 0 {
                        continue;
                    }
                    let covered_lo = lo.max(rbase + idx as u64 * page_size);
                    let covered_hi = hi.min(rbase + (idx as u64 + 1) * page_size);
                    let pages = ((covered_hi - covered_lo + 4095) >> 12) as usize;
                    if region.perms.contains(RegionPerms::SHARED) {
                        shared_misplaced += pages;
                    } else {
                        candidates.push((VirtAddr::new(rbase + idx as u64 * page_size), pages));
                    }
                }
            }
            coverage
        };

        coverage.extend(huge_coverage);
        coverage.sort_by_key(|&(lo, _)| lo);
        let mut cursor = begin;
        for &(lo, hi) in &coverage {
            if lo > cursor {
                return Err(AddressSpaceError::Unmapped);
            }
            cursor = cursor.max(hi);
        }
        if cursor < end {
            return Err(AddressSpaceError::Unmapped);
        }

        if !do_move {
            return Ok(candidates.iter().map(|(_, pages)| *pages).sum::<usize>() + shared_misplaced);
        }
        let mut failed = shared_misplaced;
        for (idx, (va, pages)) in candidates.into_iter().enumerate() {
            // SAFETY: each VA came from this AS's locked backing snapshot and
            // migrate_page_to_node revalidates it under the same region lock.
            if unsafe { self.migrate_page_to_node(va, destinations[idx % destinations.len()]) }
                .is_err()
            {
                failed += pages;
            }
        }
        Ok(failed)
    }

    /// Re-install the PTE for the page containing `vaddr` to
    /// reflect the region's current `phys[i]` + `perms`. Used by
    /// the page-fault handler after `cow_split_on_write` has
    /// repointed the per-page phys entry and restored WRITE — the
    /// PTE in the live page table still says RO until we walk it.
    ///
    /// Implementation: unmap the page (so map_4kb's "AlreadyMapped"
    /// guard doesn't reject), then map it again with the
    /// post-split phys + flags.
    ///
    /// # Safety
    /// - `self.root` must be a valid PML4 (per `new_for_user`).
    /// - The caller must serialise this against any concurrent
    ///   mutation of the same region.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn remap_page(&self, vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
        use crate::x86_64::paging::{map_4kb, unmap_4kb, MapError, PtFlags};
        if self.root.as_u64() == 0 {
            return Err(AddressSpaceError::OutOfRange);
        }
        let page_va = VirtAddr::new(vaddr.as_u64() & !0xFFF);
        let g = self.regions.lock();
        let v = page_va.as_u64();
        let region = g
            .iter()
            .find(|r| {
                let base = r.base.as_u64();
                v >= base && v < base + r.len
            })
            .ok_or(AddressSpaceError::Unmapped)?;
        let page_idx = ((v - region.base.as_u64()) >> 12) as usize;
        let phys = region.phys[page_idx];

        let mut flags = PtFlags::USER;
        if user_page_writable(region.perms, phys) {
            flags |= PtFlags::WRITABLE;
        }
        if !region.perms.contains(RegionPerms::EXEC) {
            flags |= PtFlags::NO_EXEC;
        }

        // COW-break hot path (one call per first-write #PF): only a
        // CLONE_VM-shared AS can hold this page's stale entry on another
        // CPU (see `vm_shared` docs) — a single-threaded process needs
        // the LOCAL invalidation only. The per-page broadcast + ack-wait
        // here was a storm-scale serializer under fork-heavy load.
        // SAFETY: root is a valid PML4; the page we're touching
        // sits inside `region` per the lookup above.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe {
            if self.is_vm_shared() {
                unmap_4kb(self.root, page_va)
            } else {
                crate::x86_64::paging::unmap_4kb_local(self.root, page_va)
            }
        };
        // SAFETY: `self.root` is this AS's live PML4 (same root just
        // passed to `unmap_4kb`); `page_va` is the page-aligned VA of a
        // page that belongs to `region` (the lookup above resolved it),
        // and `phys` is `region.phys[page_idx]`, the frame this AS owns
        // for that page. `flags` mirror the region's perms, so the new
        // PTE re-installs exactly the mapping we just tore down.
        // SAFETY: Valid memory or trusted environment
        match unsafe { map_4kb(self.root, page_va, phys, flags) } {
            Ok(()) => Ok(()),
            Err(MapError::AlreadyMapped) => Ok(()),
            Err(_) => Err(AddressSpaceError::NotImplemented),
        }
    }

    /// aarch64 sibling of the x86_64 `remap_page`. Same contract:
    /// look up the region containing `vaddr`, install a fresh PTE
    /// for that 4 KiB page reflecting the region's current
    /// `phys[i]` + `perms`. Used by the data-abort handler after
    /// `cow_split_on_write` repointed the per-page phys entry.
    ///
    /// # Safety
    /// - `self.root` must be a valid `TTBR0_EL1` L0 table (per `new_for_user`).
    /// - The caller must serialise this against any concurrent mutation of
    ///   the same region.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn remap_page(&self, vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
        use crate::aarch64::paging::{map_4kb, unmap_4kb, MapError, PtFlags};
        if self.root.as_u64() == 0 {
            return Err(AddressSpaceError::OutOfRange);
        }
        let page_va = VirtAddr::new(vaddr.as_u64() & !0xFFF);
        let g = self.regions.lock();
        let v = page_va.as_u64();
        let region = g
            .iter()
            .find(|r| {
                let base = r.base.as_u64();
                v >= base && v < base + r.len
            })
            .ok_or(AddressSpaceError::Unmapped)?;
        let page_idx = ((v - region.base.as_u64()) >> 12) as usize;
        let phys = region.phys[page_idx];

        // Mirror the materialize() flag derivation for aarch64.
        let mut flags = if user_page_writable(region.perms, phys) {
            PtFlags::AP_RW_EL0
        } else {
            PtFlags::AP_RO_EL0
        };
        if !region.perms.contains(RegionPerms::EXEC) {
            flags = flags | PtFlags::UXN | PtFlags::PXN;
        }

        // SAFETY: `self.root` is a valid `TTBR0_EL1` table (checked non-zero
        // above); `page_va` was just located inside `region`. unmap_4kb
        // invalidates the stale local TLB entry for that page.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { unmap_4kb(self.root, page_va) };
        // SAFETY: same `self.root`/`page_va` validity as above; `phys` is
        // `region.phys[page_idx]` for this page and `flags` derive from the
        // region's perms. map_4kb installs the fresh leaf PTE.
        // SAFETY: Valid memory or trusted environment
        match unsafe { map_4kb(self.root, page_va, phys, flags) } {
            Ok(()) => Ok(()),
            Err(MapError::AlreadyMapped) => Ok(()),
            Err(_) => Err(AddressSpaceError::NotImplemented),
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub unsafe fn remap_page(&self, _vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
        Err(AddressSpaceError::NotImplemented)
    }

    /// Find the region covering `vaddr`, if any. Returns a copy
    /// since the region table lives behind an interior lock.
    pub fn lookup(&self, vaddr: VirtAddr) -> Option<Region> {
        let a = vaddr.as_u64();
        self.regions
            .lock()
            .iter()
            .find(|r| a >= r.base.as_u64() && a < r.base.as_u64() + r.len)
            .cloned()
    }

    /// Make this address-space the active one. On x86_64 issues a
    /// `MOV CR3` with the right `compiler_fence` discipline; on
    /// aarch64 installs the `(root, ASID)` TTBR0 context with the architected
    /// DSB + MSR + ISB sequence. Nonzero lifetime-scoped ASIDs retain cached
    /// translations; the ASID-0 exhaustion fallback flushes on root changes.
    ///
    /// # Safety invariants (x86_64)
    /// - `self.root` must have been constructed via `new_for_user`,
    ///   which copies the currently-active kernel-half entries.
    ///   Activating a PML4 without kernel mappings triple-faults
    ///   on the next instruction fetch.
    ///
    /// # Safety invariants (aarch64)
    /// - `self.root` must point at a valid L0 table (the only
    ///   safe path is `new_for_user` → `new_user_ttbr0`).
    /// - The kernel must run on a TTBR1-resolved stack and
    ///   reach all phys-as-virt sites through `kernel_ptr` /
    ///   `kernel_mut_ptr`. Both invariants land at boot — the
    ///   `_start_rust_entry` switch to `stack_top_virt` and the
    ///   tree-wide migration of phys-as-virt accessors —
    ///   so callers in the Stage-4 scheduler / fork path don't
    ///   need to re-establish them.
    pub fn activate(&self) -> Result<(), AddressSpaceError> {
        if self.root.as_u64() == 0 {
            return Err(AddressSpaceError::OutOfRange);
        }
        #[cfg(target_arch = "x86_64")]
        {
            // Publish PCID-0 residency before loading the root. A concurrent
            // shared-AS invalidation therefore either targets this CPU or
            // completes before MOV CR3 observes the edited page tables.
            crate::tlb_shootdown::set_active_as(narf_lib::percpu::current_cpu() as u32, 0);
            // SAFETY: `new_for_user` (the only safe path to a
            // non-zero `root`) populated the kernel-half entries
            // from the current PML4, so the next instruction fetch
            // after the CR3 swap still resolves against a valid
            // kernel mapping. Interrupt state is the caller's
            // contract — the executor disables IRQs through the
            // existing `IrqSafeSpinLock` on the ready queue.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                crate::x86_64::paging::write_cr3(self.root);
            }
            Ok(())
        }
        #[cfg(target_arch = "aarch64")]
        {
            // aarch64 split translation: TTBR1 (high-half) carries
            // the kernel; TTBR0 (low-half) is per-AS. Every
            // kernel-side phys-as-virt access in the tree now
            // goes through `PhysAddr::kernel_ptr` /
            // `kernel_mut_ptr`, which OR-in `KERNEL_PHYS_OFFSET`
            // so reads land in TTBR1's high-half RAM window. The
            // boot stack is also aliased into TTBR1 via the
            // `stack_top_virt` symbol installed in
            // `build/linker/aarch64.ld`; `_start_rust_entry`
            // installs that high-VA stack pointer immediately
            // after the MMU is enabled. Swapping TTBR0 to
            // `self.root` therefore leaves all kernel reads/writes
            // valid; user code's low-half mappings come from the
            // regions we materialise into `self.root`.
            //
            // Install this address space's low-half root. The scheduler saves
            // the incoming TTBR0 around every user-task poll and restores it
            // before polling another task; the kernel itself executes and
            // accesses physical memory through the shared TTBR1 high half.
            // A lifetime-scoped nonzero ASID keeps this address space's cached
            // translations across switches. Pool exhaustion falls back to
            // ASID 0 and the local full-invalidation path.
            // SAFETY: `new_for_user` created `self.root` as a live L0 table;
            // TTBR1 carries the executing kernel across this low-half switch.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                crate::aarch64::paging::write_ttbr0_el1_asid(self.root, self.asid.tag);
            }
            Ok(())
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Err(AddressSpaceError::NotImplemented)
        }
    }
}

impl Default for AddressSpace {
    fn default() -> Self {
        Self::empty()
    }
}

impl Drop for AddressSpace {
    /// Process-exit teardown: log + (eventually) release every
    /// still-mapped region's data frames, free the per-AS page-
    /// table pages, and return the root PML4 (x86_64) / L0
    /// (aarch64) frame to the allocator. Called automatically when
    /// the last `Arc<AddressSpace>` for a retiring user task drops.
    ///
    /// Pre-fix the AS struct dropping was a silent leak — `root`
    /// is a `PhysAddr` (no destructor), so the user-private page
    /// tables + every data frame the task had mapped stayed live
    /// until reboot. Fixed by walking the per-arch tear-down
    /// helpers in the right order:
    ///   1. `unmap_region_pages` for each region → frees data
    ///      frames + zeros leaf PTEs.
    ///   2. `free_user_pml4_tree` (x86_64) / `free_user_ttbr0_tree`
    ///      (aarch64) → walks the user-half subtree, frees
    ///      intermediate page-table pages, frees the root.
    ///
    /// Safety: a Drop runs after the last `Arc` reference is
    /// released, so no CPU can be holding `self.root` as its
    /// active CR3 / TTBR0 (the scheduler MOV-CR3s on every poll;
    /// a retired task is off the ready queue). Kernel-half PML4
    /// entries on x86_64 are not freed — only the user half
    /// (entries 0..=255) and the PML4 frame itself.
    fn drop(&mut self) {
        {
            // Serialize externally owned aliases only through authoritative
            // leaf retirement and backing release. After both region tables
            // have been drained, last-Arc ownership prevents any new alias
            // from appearing and intermediate page-table reclaim needs no
            // shared-mapping exclusion.
            let _shared_transaction = SHARED_MAPPING_TRANSACTION.lock();
            let huge_regions = core::mem::take(&mut *self.huge_regions.lock());
            for region in huge_regions {
                let page_size = match region.size {
                    crate::hugepage::HugeSize::M2 => crate::hugepage::HUGEPAGE_2M_BYTES,
                    crate::hugepage::HugeSize::G1 => crate::hugepage::HUGEPAGE_1G_BYTES,
                };
                for i in 0..region.frames.len() {
                    let va = VirtAddr::new(region.base.as_u64() + i as u64 * page_size);
                    let _ = self.unmap_huge_leaf(va, region.size);
                }
                for frame in region.frames {
                    crate::hugepage::free_hugepage(frame);
                }
            }
            // Take ownership of the region list to avoid borrowing
            // through &mut self below; the list is about to be
            // dropped anyway.
            let regions = core::mem::take(&mut *self.regions.lock());
            #[cfg(target_arch = "x86_64")]
            let swapped_pages: Vec<VirtAddr> = regions
                .swap_pages
                .iter()
                .map(|(&va, state)| {
                    assert_eq!(
                        *state,
                        SwapPageState::Swapped,
                        "address space dropped during a swap ownership transition"
                    );
                    VirtAddr::new(va)
                })
                .collect();
            #[cfg(target_arch = "x86_64")]
            let swapped_entries = {
                // SAFETY: Drop has exclusive ownership of this live root and
                // all records above are stable Swapped entries.
                unsafe { crate::swap::take_swap_entries(self.root, &swapped_pages) }
                    .expect("stable swapped page lost its swap PTE before drop")
            };
            for r in regions.iter() {
                // SAFETY: see unmap_region_pages — same identity-map
                // contract; no CPU is using self.root at this point
                // since we're past the last Arc reference.
                // SAFETY: Valid memory or trusted environment
                unsafe { self.unmap_region_pages(r) };
            }
            #[cfg(target_arch = "x86_64")]
            crate::swap::swap_discard_batch(&swapped_entries);
        }
        // Now reclaim the page-table pages themselves. The
        // sentinel root == 0 means an `empty()` AS that never
        // got a real page-table allocation; nothing to free.
        if self.root.as_u64() != 0 {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: same — last reference gone, no active CR3.
            unsafe {
                crate::x86_64::paging::free_user_pml4_tree(self.root);
            }
            #[cfg(target_arch = "aarch64")]
            // SAFETY: same — last reference gone, no active TTBR0.
            unsafe {
                crate::aarch64::paging::free_user_ttbr0_tree(self.root);
            }
        }
        #[cfg(target_arch = "aarch64")]
        crate::asid_alloc::release_process_asid(self.asid);
    }
}

// ── In-kernel smokes: FILE_DEMAND routing ──────────────────────────────
//
// The arena's end-to-end tests live where the file is (`bpf/src/arena.rs`,
// `userspace/src/handlers/sys_mmap.rs`). These pin the *routing* — the part
// that lives here and is identical for any demand-pageable file — and they are
// arch-generic on purpose: the leaf install and its invalidation differ per
// architecture, and the syscall-layer tests that would exercise them are
// x86_64-only, so without these the aarch64 arm would ship unrun.

use narf_kernel_test::{kernel_test_in, TestResult};

/// Chained behind the test hook so a real demand mapping faulting while a test
/// holds the slot is still served.
///
/// **Never the test hook itself.** It was, briefly: the first test's restore
/// was `if let Some(prev)`, which does nothing when nothing had been installed
/// yet, so the test hook stayed in the slot and the second test's install
/// chained it to itself — an unconditional infinite recursion the moment it
/// was asked about an address it did not own. It hung the aarch64 memory run
/// (`qemu-system-aarch64 timed out after 600s`) and would have hung any
/// arch. [`arm_test_file_fault_hook`] is now the only way to set this.
static FILE_FAULT_HOOK_UNDER_TEST: IrqSafeSpinLock<Option<FileFaultHook>> =
    IrqSafeSpinLock::new(None);
/// Page the test hook answers for, and the frame it answers with.
static TEST_FAULT_PAGE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static TEST_FAULT_FRAME: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static TEST_FAULT_CALLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn test_file_fault_hook(vaddr: u64) -> Option<u64> {
    use core::sync::atomic::Ordering;
    let page = TEST_FAULT_PAGE.load(Ordering::Relaxed);
    if page != 0 && vaddr == page {
        TEST_FAULT_CALLS.fetch_add(1, Ordering::Relaxed);
        return Some(TEST_FAULT_FRAME.load(Ordering::Relaxed));
    }
    let chained = *FILE_FAULT_HOOK_UNDER_TEST.lock();
    chained.and_then(|h| h(vaddr))
}

/// Put the test hook in front of whatever is installed, chaining to it.
///
/// The chain is only updated when the displaced hook is *not* the test hook,
/// which is what keeps the recursion above impossible however many times this
/// is called and whatever the syscall layer installed in between. Nothing
/// restores the previous hook: with `TEST_FAULT_PAGE` back at zero the test
/// hook is a pure delegate, and `sys_mmap` reinstalls the real hook on every
/// path that can create a region needing it — so leaving it in front is inert,
/// while a restore has to get an `Option` right in a teardown that also runs on
/// the failure paths.
fn arm_test_file_fault_hook() {
    if let Some(displaced) = install_file_fault_hook(test_file_fault_hook) {
        if !core::ptr::fn_addr_eq(displaced, test_file_fault_hook as FileFaultHook) {
            *FILE_FAULT_HOOK_UNDER_TEST.lock() = Some(displaced);
        }
    }
}

/// Does `v` have a leaf translation in `a`? Per-arch because the walkers are.
fn translate_is_mapped(a: &AddressSpace, v: VirtAddr) -> bool {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `a.root` is a valid user root; `translate` only reads the tables
    // through the identity map.
    unsafe {
        crate::x86_64::paging::translate(a.root, v).is_some()
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: same.
    unsafe {
        crate::aarch64::paging::translate(a.root, v).is_some()
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (a, v);
        true
    }
}

fn smoke_memory_numa_candidate_seeks_from_cursor() -> TestResult {
    let mut table = RegionTable::new();
    let mut add = |base: u64, perms: RegionPerms, phys: Vec<PhysAddr>| {
        table.insert(Region {
            base: VirtAddr::new(base),
            len: phys.len() as u64 * 4096,
            perms,
            phys,
        });
    };
    add(
        0x1000,
        RegionPerms::READ | RegionPerms::WRITE,
        alloc::vec![
            PhysAddr::new(0),
            PhysAddr::new(0x20_000),
            PhysAddr::new(0x21_000)
        ],
    );
    add(0x5000, RegionPerms(0), alloc::vec![PhysAddr::new(0x22_000)]);
    add(
        0x7000,
        RegionPerms::READ | RegionPerms::LOCKED,
        alloc::vec![PhysAddr::new(0x23_000)],
    );
    add(0x8000, RegionPerms::READ, alloc::vec![PhysAddr::new(0)]);
    add(
        0xA000,
        RegionPerms::READ,
        alloc::vec![PhysAddr::new(0), PhysAddr::new(0x24_000)],
    );

    if table.next_numa_hint_candidate(0) != Some(VirtAddr::new(0x2000)) {
        return TestResult::Fail("NUMA cursor did not seek to first resident page");
    }
    if table.next_numa_hint_candidate(0x3000) != Some(VirtAddr::new(0x3000)) {
        return TestResult::Fail("NUMA cursor skipped resident page at cursor");
    }
    if table.next_numa_hint_candidate(0x4000) != Some(VirtAddr::new(0xB000)) {
        return TestResult::Fail("NUMA cursor did not skip holes and ineligible VMAs");
    }
    if table.next_numa_hint_candidate(0xC000).is_some() {
        return TestResult::Fail("NUMA cursor wrapped instead of reporting end of tree");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_numa_candidate_seeks_from_cursor);

/// Demand ownership is page-scoped, and removing/replacing a VMA cancels an
/// outstanding ticket before its slow path can publish into the new mapping.
fn smoke_memory_demand_tickets_are_page_scoped() -> TestResult {
    let a = AddressSpace::empty();
    let base = 0x0000_0080_0000_0000u64;
    let lazy_region = || Region {
        base: VirtAddr::new(base),
        len: 0x2000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0); 2],
    };
    if a.map_region(lazy_region()).is_err() {
        return TestResult::Fail("failed to install lazy ticket-test region");
    }

    let first = match a.claim_demand_page(base, |_, _| Err(AddressSpaceError::NotImplemented)) {
        Ok(DemandPageClaim::Owner { ticket, .. }) => ticket,
        _ => return TestResult::Fail("first page did not grant a demand ticket"),
    };
    if a.claim_demand_page(base, |_, _| Ok(())) != Ok(DemandPageClaim::InProgress) {
        return TestResult::Fail("same page admitted two demand owners");
    }
    let second = match a.claim_demand_page(base + 0x1000, |_, _| Ok(())) {
        Ok(DemandPageClaim::Owner { ticket, .. }) => ticket,
        _ => return TestResult::Fail("unrelated page was serialized behind first page"),
    };
    if first == second {
        return TestResult::Fail("different pages received the same live demand ticket");
    }

    if a.unmap_region(VirtAddr::new(base)).is_err() || a.map_region(lazy_region()).is_err() {
        return TestResult::Fail("failed to replace ticket-test region");
    }
    let published = a.finish_demand_page(base, first, PhysAddr::new(0x1000), |_, _| Ok(()));
    let replacement_stayed_lazy = a
        .lookup(VirtAddr::new(base))
        .is_some_and(|region| region.phys[0].raw() == 0);
    a.cancel_demand_page(base + 0x1000, second);

    if published != Ok(false) {
        TestResult::Fail("cancelled ticket published into a replacement VMA")
    } else if !replacement_stayed_lazy {
        TestResult::Fail("cancelled ticket changed replacement backing")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("memory", smoke_memory_demand_tickets_are_page_scoped);

/// A `FILE_DEMAND` region's unbacked page is filled by the installed hook, not
/// by the frame allocator, and the frame it names is the one that lands in the
/// region and in the page tables.
///
/// The distinction is the whole point: an ordinary lazy region gets a *fresh
/// zeroed* frame here, which for a file-backed mapping would mean userspace
/// looking at a blank page instead of the file's data. The test therefore
/// primes the hook's frame with a marker and reads it back through the
/// mapping — an implementation that fell through to `alloc_frame_policied`
/// passes every structural check and fails on the marker.
fn smoke_memory_file_demand_page_comes_from_the_hook() -> TestResult {
    use core::sync::atomic::Ordering;
    const MARKER: u64 = 0x0FD0_0FD0_1234_5678;

    // SAFETY: the syscall/trap path runs with paging active; this allocates an
    // independent user address space without switching the active one.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let frame = match crate::frame::alloc_frame() {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    let phys = frame.start_address();
    // SAFETY: a freshly-allocated frame is exclusively ours and reachable
    // through the kernel RAM accessor.
    unsafe {
        phys.kernel_mut_ptr::<u64>().write_volatile(MARKER);
    }

    let vbase = 0x0000_0080_0000_0000u64;
    if a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x2000,
        perms: RegionPerms::READ
            | RegionPerms::WRITE
            | RegionPerms::SHARED
            | RegionPerms::FILE_DEMAND,
        phys: alloc::vec![PhysAddr::new(0); 2],
    })
    .is_err()
    {
        crate::frame::free_frame(frame);
        return TestResult::Fail("map_region rejected a FILE_DEMAND region");
    }

    TEST_FAULT_PAGE.store(vbase, Ordering::Relaxed);
    TEST_FAULT_FRAME.store(phys.raw(), Ordering::Relaxed);
    TEST_FAULT_CALLS.store(0, Ordering::Relaxed);
    arm_test_file_fault_hook();

    // SAFETY: `a` is a live user root from `new_for_user`; the identity map is
    // up and the frame allocator is initialised.
    let served = unsafe { a.demand_alloc_page(VirtAddr::new(vbase + 0x40)) };
    let slot = a
        .lookup(VirtAddr::new(vbase))
        .and_then(|r| r.phys.first().copied());
    let mapped = translate_is_mapped(&a, VirtAddr::new(vbase));
    let untouched = a
        .lookup(VirtAddr::new(vbase))
        .and_then(|r| r.phys.get(1).copied());

    let mut verdict = if served.is_err() {
        TestResult::Fail("a FILE_DEMAND fault was not served by the hook")
    } else if TEST_FAULT_CALLS.load(Ordering::Relaxed) != 1 {
        TestResult::Fail("the fault did not reach the file-fault hook exactly once")
    } else if slot != Some(phys) {
        TestResult::Fail("the region does not hold the frame the hook named")
    } else if !mapped {
        TestResult::Fail("the fault installed no leaf PTE")
    } else if untouched != Some(PhysAddr::new(0)) {
        // A routing that populated the whole region would defeat demand paging.
        TestResult::Fail("an untouched page of the region was backed anyway")
    } else {
        TestResult::Pass
    };
    // Reading the marker is what separates "the hook was consulted" from "a
    // fresh zeroed frame was installed anyway".
    if matches!(verdict, TestResult::Pass) {
        // SAFETY: `phys` is the frame this test allocated and still owns.
        let seen = unsafe { phys.kernel_ptr::<u64>().read_volatile() };
        if seen != MARKER {
            verdict = TestResult::Fail("the mapped page is not the hook's frame contents");
        }
    }

    // Disarm by address, not by uninstalling: the hook stays in front as a
    // pure delegate. See `arm_test_file_fault_hook`.
    TEST_FAULT_PAGE.store(0, Ordering::Relaxed);
    // The region is SHARED, so teardown clears PTEs and frees nothing: this
    // frame is ours to return, exactly as a file's would be its own.
    drop(a);
    crate::frame::free_frame(frame);
    verdict
}
kernel_test_in!("memory", smoke_memory_file_demand_page_comes_from_the_hook);

/// A `FILE_DEMAND` fault the file refuses is a clean `Unmapped` — the caller's
/// SEGV path — and must not fall back to allocating an anonymous page.
///
/// A fallback would be the fail-open shape: userspace would get a blank
/// writable page where it asked for file data, and never learn the file said
/// no.
fn smoke_memory_file_demand_refusal_is_a_segv() -> TestResult {
    use core::sync::atomic::Ordering;

    // SAFETY: as the test above.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let vbase = 0x0000_0080_0000_0000u64;
    if a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x1000,
        perms: RegionPerms::READ
            | RegionPerms::WRITE
            | RegionPerms::SHARED
            | RegionPerms::FILE_DEMAND,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .is_err()
    {
        return TestResult::Fail("map_region rejected a FILE_DEMAND region");
    }

    // The hook answers for nothing, so this page is a refusal.
    TEST_FAULT_PAGE.store(0, Ordering::Relaxed);
    arm_test_file_fault_hook();

    // SAFETY: as the test above.
    let r = unsafe { a.demand_alloc_page(VirtAddr::new(vbase)) };
    let slot = a
        .lookup(VirtAddr::new(vbase))
        .and_then(|r| r.phys.first().copied());
    match r {
        Err(AddressSpaceError::Unmapped) if slot == Some(PhysAddr::new(0)) => TestResult::Pass,
        Err(AddressSpaceError::Unmapped) => {
            TestResult::Fail("a refused file fault backed the page anyway")
        }
        Ok(()) => TestResult::Fail("a refused file fault was served anyway"),
        Err(_) => TestResult::Fail("a refused file fault failed for the wrong reason"),
    }
}
kernel_test_in!("memory", smoke_memory_file_demand_refusal_is_a_segv);
