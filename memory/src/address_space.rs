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

#[path = "region_index.rs"]
mod region_index;
use region_index::RegionIndex;

/// Serializes creation and replacement of externally-owned shared aliases.
/// The closure must not await or enter code that can recursively map SHARED
/// memory.
static SHARED_MAPPING_TRANSACTION: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());
type SharedFrameHooks = (fn(u64), fn(u64));
static SHARED_FRAME_HOOKS: IrqSafeSpinLock<Option<SharedFrameHooks>> = IrqSafeSpinLock::new(None);
type AddressSpaceDropHook = fn(u64);
static ADDRESS_SPACE_DROP_HOOK: IrqSafeSpinLock<Option<AddressSpaceDropHook>> =
    IrqSafeSpinLock::new(None);
/// Monotonic address-space incarnation allocator. Zero remains the lazy,
/// unassigned sentinel used by `AddressSpace::empty()`'s const constructor.
static NEXT_ADDRESS_SPACE_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn allocate_address_space_id() -> u64 {
    NEXT_ADDRESS_SPACE_ID
        .fetch_update(
            core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed,
            |current| current.checked_add(1),
        )
        .expect("address-space incarnation exhausted")
}

#[cfg(feature = "kernel-test")]
static PRIVATE_UNMAP_FAST_PATHS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "kernel-test")]
static SHARED_UNMAP_TRANSACTIONS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "kernel-test")]
static FAIL_SHARED_ALIAS_AFTER_INSTALL: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "kernel-test")]
static FAIL_SHARED_RELOCATION_AFTER_INSTALL: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "kernel-test")]
static FAIL_FIXED_RELOCATION_AFTER_SHRINK: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "kernel-test")]
static FAIL_FORK_CHILD_REGION_RESERVE_AFTER: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "kernel-test")]
pub(crate) fn __test_fail_next_shared_alias_after_install() {
    FAIL_SHARED_ALIAS_AFTER_INSTALL.store(true, core::sync::atomic::Ordering::Release);
}
#[cfg(feature = "kernel-test")]
pub(crate) fn __test_fail_next_shared_relocation_after_install() {
    FAIL_SHARED_RELOCATION_AFTER_INSTALL.store(true, core::sync::atomic::Ordering::Release);
}
#[cfg(feature = "kernel-test")]
pub(crate) fn __test_fail_next_fixed_relocation_after_shrink() {
    FAIL_FIXED_RELOCATION_AFTER_SHRINK.store(true, core::sync::atomic::Ordering::Release);
}
#[cfg(feature = "kernel-test")]
pub(crate) fn __test_fail_fork_child_region_reserve_after(calls: usize) {
    assert!(calls != 0);
    FAIL_FORK_CHILD_REGION_RESERVE_AFTER.store(calls, core::sync::atomic::Ordering::Release);
}
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

/// Install the callback which retires ownership metadata kept above the
/// memory crate when an address space reaches its last reference.
pub fn install_address_space_drop_hook(hook: AddressSpaceDropHook) {
    *ADDRESS_SPACE_DROP_HOOK.lock() = Some(hook);
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

fn release_rmap_alias_reservations(sorted_phys: &[PhysAddr]) {
    let mut first = 0;
    while first < sorted_phys.len() {
        let phys = sorted_phys[first];
        let mut end = first + 1;
        while end < sorted_phys.len() && sorted_phys[end] == phys {
            end += 1;
        }
        crate::rmap::release_reserved_owner_slots(phys, end - first);
        first = end;
    }
}

fn reserve_rmap_alias_slots(sorted_phys: &mut [PhysAddr]) -> Result<(), ()> {
    sorted_phys.sort_unstable_by_key(|phys| phys.raw());
    let mut first = 0;
    while first < sorted_phys.len() {
        let phys = sorted_phys[first];
        let mut end = first + 1;
        while end < sorted_phys.len() && sorted_phys[end] == phys {
            end += 1;
        }
        if crate::rmap::try_reserve_owner_slots(phys, end - first).is_err() {
            release_rmap_alias_reservations(&sorted_phys[..first]);
            return Err(());
        }
        first = end;
    }
    Ok(())
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

    /// Internal flag: pages in this locked region become resident only when
    /// faulted.  Linux represents this as `VM_LOCKONFAULT` in addition to
    /// `VM_LOCKED`; keeping a distinct bit lets a future-lock policy survive
    /// VMA splits and growth without accidentally turning lazy locking into
    /// eager population.  The invariant is `LOCK_ONFAULT => LOCKED`.
    pub const LOCK_ONFAULT: RegionPerms = RegionPerms(1 << 13);

    /// Internal ownership marker for `brk(2)` heap fragments. Future-lock
    /// policy changes may split the heap into adjacent VMAs; this prevents a
    /// later grow from annexing an unrelated MAP_FIXED replacement that merely
    /// happens to end at the current break.
    pub const BRK_HEAP: RegionPerms = RegionPerms(1 << 14);

    /// Internal Linux `VM_SPECIAL` analogue. Device/PFN mappings, vDSO/vvar,
    /// guards, and kernel-created control rings are not eligible for mlock;
    /// they already have bespoke lifetime/backing rules that eager population
    /// must not enter.
    pub const LOCK_EXEMPT: RegionPerms = RegionPerms(1 << 15);

    /// Internal provenance marker for growable user-stack fragments. A guard
    /// may survive replacement of the VMA above it, so lock-mode inheritance
    /// is allowed only from a fragment carrying this marker.
    pub const STACK_SEGMENT: RegionPerms = RegionPerms(1 << 16);

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

/// Lock mode inherited by mappings created after `mlockall(MCL_FUTURE)`.
///
/// This belongs to the address space (Linux's `mm_struct`), so CLONE_VM
/// threads share it while a fork child starts with [`Self::None`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum FutureLockPolicy {
    #[default]
    None,
    Eager,
    OnFault,
}

/// Faulting task's Linux resource limits used by automatic stack expansion.
/// Kept as an explicit call argument because CLONE_VM does not necessarily
/// imply a shared thread group or shared rlimit table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StackGrowthLimits {
    pub memlock_bytes: u64,
    pub stack_bytes: u64,
    pub address_space_bytes: u64,
    pub bypass_memlock: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct StackGrowthPlan {
    v_page: u64,
    guard_base: u64,
    new_guard_base: u64,
    npages: u64,
    grown_perms: RegionPerms,
}

impl StackGrowthLimits {
    pub const UNLIMITED: Self = Self {
        memlock_bytes: u64::MAX,
        stack_bytes: u64::MAX,
        address_space_bytes: u64::MAX,
        bypass_memlock: true,
    };
}

impl FutureLockPolicy {
    #[inline]
    const fn region_bits(self) -> RegionPerms {
        match self {
            Self::None => RegionPerms(0),
            Self::Eager => RegionPerms::LOCKED,
            Self::OnFault => RegionPerms(RegionPerms::LOCKED.0 | RegionPerms::LOCK_ONFAULT.0),
        }
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

/// Proof that a particular VMA publication is still current.
///
/// The generation is intentionally opaque. Any structural replacement,
/// split, merge, or relocation invalidates old receipts, even when a peer
/// publishes an identical-looking range at the same address.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MappingReceipt {
    address_space_id: u64,
    base: VirtAddr,
    len: u64,
    mapping_id: u64,
    shared: bool,
}

impl MappingReceipt {
    #[inline]
    pub const fn base(self) -> VirtAddr {
        self.base
    }

    #[inline]
    pub const fn len(self) -> u64 {
        self.len
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

const INLINE_DEMAND_CLAIMS: usize = narf_lib::percpu::MAX_CPUS;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct DemandClaimEntry {
    vaddr: u64,
    ticket: u64,
}

/// Allocation-free common-case ownership for concurrent demand faults in one
/// address space. Claims are not CPU-owned: a fault may migrate in future, and
/// nested fault contexts must not alias a per-CPU slot. The overflow map keeps
/// capacity exhaustion correct instead of turning it into an ownerless retry.
#[derive(Clone, Debug)]
struct DemandClaims {
    inline: [DemandClaimEntry; INLINE_DEMAND_CLAIMS],
    len: usize,
    overflow: BTreeMap<u64, u64>,
    next_ticket: u64,
}

impl DemandClaims {
    const fn new() -> Self {
        Self {
            inline: [DemandClaimEntry {
                vaddr: 0,
                ticket: 0,
            }; INLINE_DEMAND_CLAIMS],
            len: 0,
            overflow: BTreeMap::new(),
            next_ticket: 1,
        }
    }

    fn get(&self, vaddr: u64) -> Option<u64> {
        self.inline[..self.len]
            .iter()
            .find_map(|entry| (entry.vaddr == vaddr).then_some(entry.ticket))
            .or_else(|| self.overflow.get(&vaddr).copied())
    }

    fn insert_new(&mut self, vaddr: u64) -> Result<u64, AddressSpaceError> {
        debug_assert!(self.get(vaddr).is_none());
        let ticket = self.next_ticket;
        self.next_ticket = self
            .next_ticket
            .checked_add(1)
            .ok_or(AddressSpaceError::OutOfRange)?;
        if self.len < INLINE_DEMAND_CLAIMS {
            self.inline[self.len] = DemandClaimEntry { vaddr, ticket };
            self.len += 1;
        } else {
            self.overflow.insert(vaddr, ticket);
        }
        Ok(ticket)
    }

    fn remove(&mut self, vaddr: u64) -> Option<u64> {
        if let Some(index) = self.inline[..self.len]
            .iter()
            .position(|entry| entry.vaddr == vaddr)
        {
            let ticket = self.inline[index].ticket;
            self.len -= 1;
            self.inline[index] = self.inline[self.len];
            self.inline[self.len] = DemandClaimEntry::default();
            Some(ticket)
        } else {
            self.overflow.remove(&vaddr)
        }
    }

    fn retain_outside(&mut self, lo: u64, hi: u64) {
        let mut index = 0;
        while index < self.len {
            let vaddr = self.inline[index].vaddr;
            if vaddr >= lo && vaddr < hi {
                self.len -= 1;
                self.inline[index] = self.inline[self.len];
                self.inline[self.len] = DemandClaimEntry::default();
            } else {
                index += 1;
            }
        }
        self.overflow.retain(|&vaddr, _| vaddr < lo || vaddr >= hi);
    }
}

impl Default for DemandClaims {
    fn default() -> Self {
        Self::new()
    }
}

/// Ordered base-page VMA index.
///
/// The virtual base is stored both as the tree key and in [`Region`] because
/// `Region` is part of the public snapshot/interface shape. All structural
/// mutation goes through this wrapper so those values cannot diverge. The
/// tree replaces the previous sorted `Vec`: lookup and random `MAP_FIXED`
/// insertion are O(log VMA), while ordered iteration remains linear.
#[derive(Clone, Debug)]
struct RegionTable {
    by_base: RegionIndex<RegionEntry>,
    /// Opaque publication generation for the VMA currently rooted at each
    /// base. A syscall may leave the VMA transaction only by carrying the
    /// matching receipt; replacement/splitting assigns a fresh generation so
    /// stale materialize or rollback work cannot act on a peer's mapping.
    next_mapping_id: u64,
    /// Default locking mode for subsequently-created ordinary VMAs.
    future_lock: FutureLockPolicy,
    /// Page-scoped demand-fault ownership.  The thread holding a ticket may
    /// drop the region lock while it allocates/zeros anonymous backing or
    /// calls into a demand-pageable file.  Structural VMA removal cancels
    /// every ticket in the removed region before a replacement can appear.
    demand_pages: DemandClaims,
    /// Page-scoped COW-copy ownership. The owner pins the source frame before
    /// dropping the region lock, so unrelated write faults can copy in
    /// parallel without letting VMA teardown recycle either source.
    cow_pages: BTreeMap<u64, u64>,
    /// Per-page swap ownership transitions, keyed by page-aligned user VA.
    /// Kept under the same lock as `Region::phys` so the two authorities can
    /// never disagree at a visible transaction boundary.
    swap_pages: BTreeMap<u64, SwapPageState>,
}

#[derive(Clone, Debug)]
struct RegionEntry {
    region: Region,
    mapping_id: u64,
}

impl Default for RegionTable {
    fn default() -> Self {
        Self::new()
    }
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
            by_base: RegionIndex::new(),
            next_mapping_id: 1,
            future_lock: FutureLockPolicy::None,
            demand_pages: DemandClaims::new(),
            cow_pages: BTreeMap::new(),
            swap_pages: BTreeMap::new(),
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.by_base.len()
    }

    #[inline]
    fn iter(&self) -> impl Iterator<Item = &Region> + '_ {
        self.by_base.iter().map(|(_, entry)| &entry.region)
    }

    fn for_each_mut(&mut self, mut visit: impl FnMut(&mut Region)) {
        self.by_base.for_each_mut(|entry| visit(&mut entry.region));
    }

    #[inline]
    fn get(&self, base: u64) -> Option<&Region> {
        self.by_base.get(base).map(|entry| &entry.region)
    }

    #[inline]
    fn get_mut(&mut self, base: u64) -> Option<&mut Region> {
        self.by_base.get_mut(base).map(|entry| &mut entry.region)
    }

    #[inline]
    fn predecessor(&self, base: u64) -> Option<&Region> {
        self.by_base
            .predecessor(base)
            .map(|(_, entry)| &entry.region)
    }

    #[inline]
    fn successor(&self, base: u64) -> Option<&Region> {
        self.by_base
            .successor_or_equal(base)
            .map(|(_, entry)| &entry.region)
    }

    fn containing(&self, address: u64) -> Option<&Region> {
        self.by_base
            .predecessor_or_equal(address)
            .map(|(_, entry)| &entry.region)
            .filter(|region| address < region.base.as_u64().saturating_add(region.len))
    }

    fn containing_mut(&mut self, address: u64) -> Option<&mut Region> {
        let base = self.by_base.predecessor_or_equal(address)?.0;
        let region = &mut self.by_base.get_mut(base)?.region;
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
            .predecessor_or_equal(start)
            .filter(|(_, entry)| {
                start < entry.region.base.as_u64().saturating_add(entry.region.len)
            })
            .map_or(start, |(base, _)| base);

        for (_, entry) in self.by_base.range(first_base, u64::MAX) {
            let region = &entry.region;
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

    /// Find the first lazy page in an eagerly locked ordinary VMA at or after
    /// `start`. Seek directly into the ordered VMA index so a population pass
    /// is O(log VMAs + visited pages), not a restart from the first VMA for
    /// every page it backs.
    fn next_eager_unbacked(&self, start: u64, hi: u64) -> Option<u64> {
        let first_base = self
            .by_base
            .predecessor_or_equal(start)
            .filter(|(_, entry)| {
                start < entry.region.base.as_u64().saturating_add(entry.region.len)
            })
            .map_or(start, |(base, _)| base);

        for (_, entry) in self.by_base.range(first_base, hi) {
            let region = &entry.region;
            if !region.perms.contains(RegionPerms::LOCKED)
                || region.perms.contains(RegionPerms::LOCK_ONFAULT)
                || region.perms.contains(RegionPerms::STACK_GUARD)
                || region.perms.contains(RegionPerms::LOCK_EXEMPT)
                || region.perms.prot_only().0 == 0
            {
                continue;
            }
            let rb = region.base.as_u64();
            let re = rb.saturating_add(region.len).min(hi);
            let page = start.max(rb);
            if page >= re {
                continue;
            }
            let first = ((page - rb) >> 12) as usize;
            let count = ((re - page) >> 12) as usize;
            // A demand-paged region's phys list may be SHORTER than its page
            // count; a page past the materialized prefix is unbacked (demand-zero)
            // exactly like an in-range `phys[i] == 0`. `phys.get(i)` treats both
            // uniformly (and can't panic on `first > phys.len()`).
            if let Some(i) =
                (first..first + count).find(|&i| region.phys.get(i).is_none_or(|p| p.raw() == 0))
            {
                return Some(page + ((i - first) as u64) * 4096);
            }
        }
        None
    }

    fn try_reserve_nodes(&mut self, additional: usize) -> Result<(), AddressSpaceError> {
        self.by_base
            .try_reserve_nodes(additional)
            .map_err(|_| AddressSpaceError::AllocationFailed)
    }

    fn insert(&mut self, region: Region) -> Result<Option<Region>, AddressSpaceError> {
        let base = region.base.as_u64();
        if self.by_base.get(base).is_none() {
            self.try_reserve_nodes(1)?;
        }
        Ok(self.insert_reserved(region))
    }

    fn insert_reserved(&mut self, region: Region) -> Option<Region> {
        let base = region.base.as_u64();
        let id = self.next_mapping_id;
        self.next_mapping_id = self
            .next_mapping_id
            .checked_add(1)
            .expect("VMA publication generation exhausted");
        self.by_base
            .insert_reserved(
                base,
                RegionEntry {
                    region,
                    mapping_id: id,
                },
            )
            .map(|entry| entry.region)
    }

    #[inline]
    fn remove(&mut self, base: u64) -> Option<Region> {
        let region = self.by_base.remove(base)?.region;
        let end = region.base.as_u64().saturating_add(region.len);
        self.demand_pages.retain_outside(region.base.as_u64(), end);
        self.cow_pages
            .retain(|&vaddr, _| vaddr < region.base.as_u64() || vaddr >= end);
        Some(region)
    }

    #[inline]
    fn mapping_id(&self, base: u64) -> Option<u64> {
        self.by_base.get(base).map(|entry| entry.mapping_id)
    }

    /// Assign a fresh publication generation and cancel every deferred page
    /// claim for an existing VMA whose backing identity changed in place.
    fn invalidate_mapping(&mut self, base: u64) {
        let end = base.saturating_add(
            self.by_base
                .get(base)
                .expect("cannot invalidate a missing VMA")
                .region
                .len,
        );
        let id = self.next_mapping_id;
        self.next_mapping_id = self
            .next_mapping_id
            .checked_add(1)
            .expect("VMA publication generation exhausted");
        self.by_base
            .get_mut(base)
            .expect("cannot invalidate a missing VMA")
            .mapping_id = id;
        self.demand_pages.retain_outside(base, end);
        self.cow_pages
            .retain(|&vaddr, _| vaddr < base || vaddr >= end);
    }

    fn has_overlap(&self, lo: u64, hi: u64) -> bool {
        self.predecessor(lo)
            .is_some_and(|region| region.base.as_u64().saturating_add(region.len) > lo)
            || self.by_base.range(lo, hi).next().is_some()
    }

    fn overlapping_any(&self, lo: u64, hi: u64, predicate: impl Fn(&Region) -> bool) -> bool {
        if self.predecessor(lo).is_some_and(|region| {
            region.base.as_u64().saturating_add(region.len) > lo && predicate(region)
        }) {
            return true;
        }
        self.by_base
            .range(lo, hi)
            .any(|(_, entry)| predicate(&entry.region))
    }

    /// Visit only VMAs intersecting `[lo, hi)`, in virtual order.
    fn for_each_overlapping(&self, lo: u64, hi: u64, mut visit: impl FnMut(&Region)) {
        if let Some(region) = self.predecessor(lo) {
            if region.base.as_u64().saturating_add(region.len) > lo {
                visit(region);
            }
        }
        for (_, entry) in self.by_base.range(lo, hi) {
            visit(&entry.region);
        }
    }

    /// Mutable counterpart of [`Self::for_each_overlapping`].
    fn for_each_overlapping_mut(&mut self, lo: u64, hi: u64, mut visit: impl FnMut(&mut Region)) {
        let start = self
            .by_base
            .predecessor(lo)
            .filter(|(_, entry)| entry.region.base.as_u64().saturating_add(entry.region.len) > lo)
            .map_or(lo, |(base, _)| base);
        self.by_base
            .for_each_range_mut(start, hi, |entry| visit(&mut entry.region));
    }

    /// Remove and return every VMA intersecting `[lo, hi)`, in virtual order.
    fn drain_overlapping(&mut self, lo: u64, hi: u64) -> Vec<Region> {
        let mut keys = Vec::new();
        if let Some((base, entry)) = self.by_base.predecessor(lo) {
            if entry.region.base.as_u64().saturating_add(entry.region.len) > lo {
                keys.push(base);
            }
        }
        keys.extend(self.by_base.range(lo, hi).map(|(base, _)| base));
        keys.into_iter()
            .filter_map(|base| self.remove(base))
            .collect()
    }

    fn covers_range(&self, lo: u64, hi: u64) -> bool {
        self.covered_prefix_end(lo, hi) >= hi
    }

    /// End of the contiguous mapped prefix beginning exactly at `lo`.
    /// Linux mlock-family operations modify earlier VMAs before reporting a
    /// later hole, so callers need the prefix boundary rather than only a
    /// whole-range boolean.
    fn covered_prefix_end(&self, lo: u64, hi: u64) -> u64 {
        let mut cursor = lo;
        if let Some(region) = self
            .by_base
            .predecessor_or_equal(lo)
            .map(|(_, entry)| &entry.region)
        {
            let begin = region.base.as_u64();
            let end = begin.saturating_add(region.len);
            if begin <= cursor && end > cursor {
                cursor = end;
                if cursor >= hi {
                    return hi;
                }
            }
        }
        for (_, entry) in self.by_base.range(cursor, hi) {
            let region = &entry.region;
            let begin = region.base.as_u64();
            if begin > cursor {
                return cursor;
            }
            cursor = cursor.max(begin.saturating_add(region.len));
            if cursor >= hi {
                return hi;
            }
        }
        cursor
    }

    fn snapshot(&self) -> Vec<Region> {
        self.iter().cloned().collect()
    }

    fn locked_bytes(&self) -> u64 {
        self.iter()
            .filter(|region| {
                region.perms.contains(RegionPerms::LOCKED)
                    && !region.perms.contains(RegionPerms::LOCK_EXEMPT)
                    && !region.perms.contains(RegionPerms::STACK_GUARD)
            })
            .fold(0, |total, region| total.saturating_add(region.len))
    }

    fn locked_overlap_bytes(&self, lo: u64, hi: u64) -> u64 {
        let mut total = 0u64;
        self.for_each_overlapping(lo, hi, |region| {
            if region.perms.contains(RegionPerms::LOCKED)
                && !region.perms.contains(RegionPerms::LOCK_EXEMPT)
                && !region.perms.contains(RegionPerms::STACK_GUARD)
            {
                let begin = lo.max(region.base.as_u64());
                let end = hi.min(region.base.as_u64().saturating_add(region.len));
                total = total.saturating_add(end.saturating_sub(begin));
            }
        });
        total
    }

    fn mapped_bytes(&self) -> u64 {
        self.iter()
            .fold(0, |total, region| total.saturating_add(region.len))
    }

    /// Bytes represented by Linux-style VMAs for resource-limit accounting.
    ///
    /// NARF keeps a synthetic inaccessible stack-guard entry in the region
    /// table. Linux's stack guard gap is not a VMA and therefore contributes
    /// neither to `mm->total_vm` (`RLIMIT_AS`) nor to the bytes charged by
    /// `mlockall(MCL_CURRENT)`. Keep the raw `mapped_bytes` statistic intact,
    /// but exclude that internal sentinel at admission boundaries.
    fn accounted_mapped_bytes(&self) -> u64 {
        self.iter()
            .filter(|region| !region.perms.contains(RegionPerms::STACK_GUARD))
            .fold(0, |total, region| total.saturating_add(region.len))
    }

    /// Linux `data_vm`: private writable mappings which are not stacks.
    fn data_mapped_bytes(&self) -> u64 {
        self.iter()
            .filter(|region| {
                region.perms.contains(RegionPerms::WRITE)
                    && !region.perms.contains(RegionPerms::SHARED)
                    && !region.perms.contains(RegionPerms::STACK_SEGMENT)
                    && !region.perms.contains(RegionPerms::STACK_GUARD)
            })
            .fold(0, |total, region| total.saturating_add(region.len))
    }

    /// Bytes in the exact-adjacent stack chain beginning at `base`.
    fn contiguous_stack_bytes_from(&self, base: u64) -> u64 {
        let mut cursor = base;
        let mut total = 0u64;
        while let Some(region) = self.get(cursor) {
            if !region.perms.contains(RegionPerms::STACK_SEGMENT) {
                break;
            }
            total = total.saturating_add(region.len);
            cursor = cursor.saturating_add(region.len);
        }
        total
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
    /// A mapping receipt was invalidated by a structural VMA mutation.
    StaleMapping,
    /// Kernel metadata for the requested VMA shape could not be allocated.
    /// Syscall boundaries normally expose this as `ENOMEM`.
    AllocationFailed,
    /// An eager `mlock` population pass could not obtain or install backing.
    /// Linux exposes this separately from an unmapped range: population-time
    /// failure is `EAGAIN`, a coverage hole is `ENOMEM`, and malformed range
    /// arithmetic is `EINVAL`.
    LockFailed,
    /// Virtual locked-byte accounting would exceed RLIMIT_MEMLOCK.
    LockLimit,
    /// Linux virtual-address or data-mapping accounting would exceed the
    /// caller's RLIMIT_AS or applicable RLIMIT_DATA.
    MappingLimit,
    /// Automatic stack growth would exceed RLIMIT_STACK or RLIMIT_AS.
    StackLimit,
    /// Anonymous demand backing hit the protected userspace-allocation
    /// reserve. The fault path may wake reclaim, park outside every
    /// address-space/allocator lock, and retry once; this is distinct from a
    /// missing VMA (`Unmapped`) or invalid placement (`OutOfRange`).
    ReclaimPressure,
    /// The requested NUMA node is outside the allocator's node table.
    InvalidNode,
    /// The mapping borrows externally-owned backing and cannot be migrated.
    SharedMapping,
    /// No online, allowed node exists in a strictly slower memory tier.
    NoDemotionTarget,
}

/// Failure from a fixed-target relocation after Linux-style destructive
/// replacement may have occurred.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FixedRelocationError {
    pub error: AddressSpaceError,
    pub target_punched: bool,
    /// Linux fixed shrinking retires the target, truncates the source tail,
    /// then attempts the move. Upper file/SysV owners must mirror this second
    /// independently committed topology transition before unlocking.
    pub source_shrunk: bool,
}

/// Linux resource limits applied atomically to one `mremap` growth.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MremapLimits {
    pub memlock_bytes: u64,
    pub address_space_bytes: u64,
    pub data_bytes: u64,
    pub data_max_bytes: u64,
    pub bypass_memlock: bool,
}

/// Linux operation which creates a second VMA over shared base-page backing.
///
/// Both modes preserve the source backing. `Duplicate` clones resident
/// translations; `DontUnmap` moves them to the destination so the retained
/// source VMA faults its shared backing back in. The other distinction is
/// resource accounting and the source VMA's lock state:
/// `Duplicate` is the historical `old_len == 0` shared-map duplication and
/// therefore admits locked growth before a fixed target is retired;
/// `DontUnmap` skips MEMLOCK admission, performs full-length AS/DATA admission
/// after a fixed punch, and clears `LOCKED|LOCK_ONFAULT` on the source VMA.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SharedMremapMode {
    Duplicate,
    DontUnmap,
}

impl MremapLimits {
    pub const UNLIMITED: Self = Self {
        memlock_bytes: u64::MAX,
        address_space_bytes: u64::MAX,
        data_bytes: u64::MAX,
        data_max_bytes: u64::MAX,
        bypass_memlock: true,
    };
}

/// Outcome of one serialized `brk(2)` address-space transaction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BrkUpdateResult {
    /// The request either succeeded or was rejected with Linux's `brk`
    /// convention; the contained value is the break to return to userspace.
    Complete(u64),
    /// The caller must prepare this many lazy page descriptors outside the
    /// IRQ-safe VMA lock and retry. No address-space state was changed.
    NeedPages(usize),
}

#[inline]
fn anonymous_demand_alloc_error(reserve_pressure: bool) -> AddressSpaceError {
    if reserve_pressure {
        AddressSpaceError::ReclaimPressure
    } else {
        AddressSpaceError::OutOfRange
    }
}

/// `demand_alloc_page` serves both page faults and eager `mlock`. Once mlock
/// has validated complete VMA coverage, its allocation-flavoured errors no
/// longer describe malformed virtual-address input; Linux reports them as a
/// population failure (`EAGAIN`).
#[inline]
fn mlock_population_error(error: AddressSpaceError) -> AddressSpaceError {
    match error {
        AddressSpaceError::OutOfRange | AddressSpaceError::ReclaimPressure => {
            AddressSpaceError::LockFailed
        }
        error => error,
    }
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
    /// Stable, never-reused identity for metadata owned outside `memory` and
    /// for binding opaque mapping receipts to this exact address space.
    /// Const-created empty spaces allocate it lazily on first observation.
    address_space_id: core::sync::atomic::AtomicU64,
    /// Lifetime-scoped aarch64 process ASID. Tag 0 is the safe fallback and
    /// selects the flushing TTBR0 switch path.
    #[cfg(target_arch = "aarch64")]
    asid: crate::asid_alloc::DomainTag,
    regions: IrqSafeSpinLock<RegionTable>,
    huge_regions: IrqSafeSpinLock<Vec<HugeRegion>>,
    /// Per-address-space VMA write transaction. Linux serializes mmap, mlock,
    /// stack growth, and mremap through the mm's mmap write lock. Keeping the
    /// equivalent lock per AS (rather than global) lets unrelated processes
    /// mutate their VMAs concurrently while making limit admission +
    /// MAP_FIXED replacement + publication indivisible to CLONE_VM peers.
    vma_transaction: IrqSafeSpinLock<()>,
    /// Per-AS mmap cursor: next free virt for a no-hint mmap.
    /// Lives here (not on a single global) so each process gets its
    /// own monotonically-increasing arena instead of a shared race.
    /// Initial value 0x4080_0000_0000 matches the prior global —
    /// well above the ELF + brk regions and below the user stack.
    mmap_cursor: core::sync::atomic::AtomicU64,
    /// Program break (top of the `brk(2)` heap), owned by the ADDRESS SPACE —
    /// not per-task. The heap is AS state: every `CLONE_VM` thread shares it and
    /// a real fork inherits it (see `clone_for_fork`). Keying it per-task let a
    /// worker thread with no entry answer `brk(0)` with the arena base, which
    /// glibc latched into its process-global `__curbrk`; the main thread's next
    /// `sbrk` then computed a mid-heap break and `sys_brk` unmapped live heap
    /// (kwin's deterministic heap-UAF SIGSEGV). `0` = unset; first use seeds it
    /// to the brk arena base.
    brk_top: core::sync::atomic::AtomicU64,
    /// Linux `RLIMIT_DATA` charges the file-backed program data span in
    /// addition to growth above `start_brk`. The ELF loader publishes that
    /// immutable span before the new task becomes runnable; fork inherits it.
    program_data_bytes: core::sync::atomic::AtomicU64,
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
            address_space_id: core::sync::atomic::AtomicU64::new(0),
            #[cfg(target_arch = "aarch64")]
            asid: crate::asid_alloc::DomainTag::RESERVED,
            regions: IrqSafeSpinLock::new(RegionTable::new()),
            huge_regions: IrqSafeSpinLock::new(Vec::new()),
            vma_transaction: IrqSafeSpinLock::new(()),
            mmap_cursor: core::sync::atomic::AtomicU64::new(Self::MMAP_CURSOR_BASE),
            brk_top: core::sync::atomic::AtomicU64::new(0),
            program_data_bytes: core::sync::atomic::AtomicU64::new(0),
            vm_shared: core::sync::atomic::AtomicBool::new(false),
            numa_hints: IrqSafeSpinLock::new(NumaHints::new()),
        }
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn __test_fail_next_region_index_reserve(&self) {
        self.regions.lock().by_base.fail_next_reserve_for_test();
    }

    /// Does `[base, base+len)` overlap any HUGE mapping?
    ///
    /// Huge mappings live in their own `huge_regions` vector, not in
    /// `regions`, so [`Self::perms_intersecting`] cannot see them. A caller
    /// that asks "is anything already here?" and consults only the base-page
    /// VMAs gets the wrong answer over a hugetlb mapping — which is exactly
    /// what made `MAP_FIXED_NOREPLACE` replace one instead of reporting
    /// -EEXIST. The admission path already scans this vector for overlap
    /// (see `map_huge_region_locked`); this exposes the same predicate to
    /// the syscall layer instead of leaving it to re-derive it.
    pub fn huge_intersects(&self, base: VirtAddr, len: u64) -> bool {
        let lo = base.as_u64();
        let Some(hi) = lo.checked_add(len) else {
            return false;
        };
        self.huge_regions.lock().iter().any(|r| {
            let rb = r.base.as_u64();
            rb < hi && lo < rb + r.len
        })
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn __test_huge_region_perms(&self, base: VirtAddr) -> Option<RegionPerms> {
        self.huge_regions
            .lock()
            .iter()
            .find(|region| region.base == base)
            .map(|region| region.perms)
    }

    /// Stable identity of this address-space incarnation.
    ///
    /// The value is unique for the kernel lifetime and is allocated once per
    /// address space, never once per mapping operation.
    pub fn identity(&self) -> u64 {
        use core::sync::atomic::Ordering;

        let current = self.address_space_id.load(Ordering::Acquire);
        if current != 0 {
            return current;
        }
        let candidate = allocate_address_space_id();
        match self.address_space_id.compare_exchange(
            0,
            candidate,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => candidate,
            Err(installed) => installed,
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

    /// Run one compound VMA mutation while excluding CLONE_VM peers.
    ///
    /// Callers that must snapshot externally-owned shared backing use this as
    /// the outer transaction, then take [`with_shared_mapping_transaction`]
    /// before calling a `*_shared_region_locked` method. The lock order is
    /// therefore always AS VMA -> shared-owner -> huge table -> regular table.
    pub fn with_vma_transaction<R>(&self, body: impl FnOnce() -> R) -> R {
        let _guard = self.vma_transaction.lock();
        body()
    }

    /// Return permissions for an exact base-page VMA without cloning its
    /// proportional backing metadata.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] while using the
    /// result to authorize a subsequent structural operation.
    pub unsafe fn exact_region_perms_locked(
        &self,
        base: VirtAddr,
        len: u64,
    ) -> Option<RegionPerms> {
        self.regions
            .lock()
            .get(base.as_u64())
            .filter(|region| region.len == len)
            .map(|region| region.perms)
    }

    /// Return permissions for the one base-page VMA covering `[base, base +
    /// len)` without cloning proportional backing metadata. A zero-length
    /// query identifies the VMA containing `base`, as required by Linux's
    /// `old_len == 0` shared-mremap duplication path.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] while using the
    /// result to authorize a subsequent structural operation.
    pub unsafe fn region_perms_covering_locked(
        &self,
        base: VirtAddr,
        len: u64,
    ) -> Option<RegionPerms> {
        let lo = base.as_u64();
        let hi = lo.checked_add(len)?;
        self.regions
            .lock()
            .containing(lo)
            .filter(|region| hi <= region.base.as_u64().saturating_add(region.len))
            .map(|region| region.perms)
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

    /// Read the current default mmap candidate without consuming it.
    /// Publication paths which must prepare file/SysV ownership for the exact
    /// destination use this under the VMA transaction, then rely on the
    /// successful map/alias operation to advance the cursor.
    ///
    /// # Safety
    /// The caller must hold this address space's VMA transaction continuously
    /// from this read through either publication or abandonment of the plan.
    pub unsafe fn mmap_cursor_candidate_locked(
        &self,
        len: u64,
    ) -> Result<VirtAddr, AddressSpaceError> {
        if len == 0 || len & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        let candidate = self.mmap_cursor.load(core::sync::atomic::Ordering::Relaxed);
        candidate
            .checked_add(len)
            .filter(|end| *end <= Self::MMAP_WINDOW_TOP)
            .ok_or(AddressSpaceError::MappingLimit)?;
        Ok(VirtAddr::new(candidate))
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

    /// Current program break (top of the `brk(2)` heap) for this address space,
    /// or `0` if `brk` has not been called yet (caller seeds the arena base).
    /// AS-scoped so `CLONE_VM` threads share it; see the `brk_top` field.
    pub fn brk_top(&self) -> u64 {
        self.brk_top.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Publish the main executable's Linux `end_data - start_data` charge.
    /// The ELF loader calls this before making the task runnable.
    pub fn set_program_data_bytes(&self, bytes: u64) {
        self.program_data_bytes
            .store(bytes, core::sync::atomic::Ordering::Release);
    }

    /// Main executable bytes charged by Linux `RLIMIT_DATA`.
    pub fn program_data_bytes(&self) -> u64 {
        self.program_data_bytes
            .load(core::sync::atomic::Ordering::Acquire)
    }

    /// Apply a Linux `brk(2)` request under one address-space VMA transaction.
    ///
    /// Policy rejection and mutation failure both return the unchanged break,
    /// as the raw Linux syscall does. Lazy page descriptors must be allocated
    /// by the caller outside this IRQ-safe transaction; if a CLONE_VM peer
    /// changed the break after that preparation, `NeedPages` requests an exact
    /// retry without publishing partial state.
    #[allow(clippy::too_many_arguments)]
    pub fn update_brk_limited(
        &self,
        heap_base: VirtAddr,
        arena_top: u64,
        requested: u64,
        lazy_pages: Vec<PhysAddr>,
        data_limit_bytes: u64,
        address_space_limit_bytes: u64,
        memlock_limit_bytes: u64,
        bypass_memlock_limit: bool,
    ) -> BrkUpdateResult {
        let vma_guard = self.vma_transaction.lock();
        let mut current = self.brk_top.load(core::sync::atomic::Ordering::Acquire);
        if current == 0 {
            current = heap_base.as_u64();
            self.brk_top
                .store(current, core::sync::atomic::Ordering::Release);
        }

        if requested == 0 {
            return BrkUpdateResult::Complete(current);
        }
        if requested < heap_base.as_u64() || requested > arena_top {
            return BrkUpdateResult::Complete(current);
        }

        // Linux performs RLIMIT_DATA admission before comparing page-aligned
        // breaks, so a same-page request cannot escape a non-page-aligned
        // limit. `requested >= heap_base` was established above.
        if data_limit_bytes != u64::MAX
            && requested
                .saturating_sub(heap_base.as_u64())
                .saturating_add(self.program_data_bytes())
                > data_limit_bytes
        {
            return BrkUpdateResult::Complete(current);
        }

        let current_aligned = current.saturating_add(0xFFF) & !0xFFF;
        let requested_aligned = requested.saturating_add(0xFFF) & !0xFFF;

        if requested <= current {
            if requested_aligned < current_aligned {
                // Linux rejects a shrink when no VMA intersects the old heap
                // tail. Generic MAP_FIXED punching treats an empty interval as
                // success, so retain this syscall-specific check here.
                let regions = self.regions.lock();
                let has_tail = regions.has_overlap(requested_aligned, current_aligned);
                drop(regions);
                if !has_tail
                    || self
                        .punch_fixed_locked(
                            VirtAddr::new(requested_aligned),
                            current_aligned - requested_aligned,
                        )
                        .is_err()
                {
                    return BrkUpdateResult::Complete(current);
                }
            }
            self.brk_top
                .store(requested, core::sync::atomic::Ordering::Release);
            return BrkUpdateResult::Complete(requested);
        }

        let pages = (requested_aligned - current_aligned) >> 12;
        if pages == 0 {
            self.brk_top
                .store(requested, core::sync::atomic::Ordering::Release);
            return BrkUpdateResult::Complete(requested);
        }
        let Ok(page_count) = usize::try_from(pages) else {
            return BrkUpdateResult::Complete(current);
        };
        // Demand-paged grow: the region's length is extended without materializing
        // any per-page phys slot, so the caller's `lazy_pages` pre-allocation is
        // no longer needed (pages fault in individually). Kept in the signature
        // for ABI stability with the fork/exec brk-inheritance paths.
        let _ = lazy_pages;

        // Linux compares total_vm + requested pages against RLIMIT_AS in
        // pages, effectively rounding a non-page-aligned byte limit down.
        if address_space_limit_bytes != u64::MAX {
            let huge = self.huge_regions.lock();
            let regions = self.regions.lock();
            let huge_bytes = huge
                .iter()
                .fold(0u64, |total, region| total.saturating_add(region.len));
            let accounted_pages = regions.accounted_mapped_bytes().saturating_add(huge_bytes) >> 12;
            drop(regions);
            drop(huge);
            if accounted_pages.saturating_add(pages) > (address_space_limit_bytes >> 12) {
                return BrkUpdateResult::Complete(current);
            }
        }

        let Ok((grow_hi, tail_perms)) = self.brk_extend_region_limited_locked(
            heap_base,
            current_aligned,
            page_count,
            memlock_limit_bytes,
            bypass_memlock_limit,
        ) else {
            return BrkUpdateResult::Complete(current);
        };
        self.brk_top
            .store(requested, core::sync::atomic::Ordering::Release);
        self.bump_mmap_cursor_past(current_aligned, grow_hi - current_aligned);
        drop(vma_guard);
        if tail_perms.contains(RegionPerms::LOCKED)
            && !tail_perms.contains(RegionPerms::LOCK_ONFAULT)
        {
            self.populate_locked_range_best_effort(current_aligned, grow_hi);
        }
        BrkUpdateResult::Complete(requested)
    }

    /// Extend the growable `brk(2)` heap at `heap_base` by `add_pages` pages at
    /// `[grow_lo, grow_lo + add_pages * 4096)`.
    ///
    /// Demand-paged: only the region's LENGTH is extended (O(1)); the backing
    /// `phys` list stays at its faulted prefix and each page materializes its
    /// slot on first fault. Nothing is pre-allocated, so an unused grown range
    /// costs nothing.
    ///
    /// Adjacent growth with identical permissions extends the last heap VMA in
    /// place. If `mlockall(MCL_FUTURE)` changed the inherited lock mode (or a
    /// fork left the old tail COW), a distinct tail VMA is required: extending
    /// the old one would retroactively change the status of earlier heap pages.
    ///
    /// `grow_lo` must be page-aligned and equal to the current end of the heap
    /// VMA (`heap_base + len`) when a heap VMA exists, or `heap_base` for the
    /// first grow. The appended tail must not overlap the successor VMA.
    pub fn brk_extend_region(
        &self,
        heap_base: VirtAddr,
        grow_lo: u64,
        add_pages: usize,
    ) -> Result<(), AddressSpaceError> {
        self.brk_extend_region_limited(heap_base, grow_lo, add_pages, u64::MAX, true)
    }

    /// Limit-enforcing `brk` growth transaction used by the Linux syscall.
    /// Demand-paged: extends the heap by `add_pages` pages of length; the pages
    /// materialize their backing individually on first fault.
    pub fn brk_extend_region_limited(
        &self,
        heap_base: VirtAddr,
        grow_lo: u64,
        add_pages: usize,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<(), AddressSpaceError> {
        let vma_guard = self.vma_transaction.lock();
        let (grow_hi, tail_perms) = self.brk_extend_region_limited_locked(
            heap_base,
            grow_lo,
            add_pages,
            limit_bytes,
            bypass_limit,
        )?;
        self.bump_mmap_cursor_past(grow_lo, grow_hi - grow_lo);
        drop(vma_guard);
        if tail_perms.contains(RegionPerms::LOCKED)
            && !tail_perms.contains(RegionPerms::LOCK_ONFAULT)
        {
            self.populate_locked_range_best_effort(grow_lo, grow_hi);
        }
        Ok(())
    }

    /// `brk_extend_region_limited` with the VMA transaction already held.
    fn brk_extend_region_limited_locked(
        &self,
        heap_base: VirtAddr,
        grow_lo: u64,
        add_pages: usize,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<(u64, RegionPerms), AddressSpaceError> {
        if grow_lo & 0xFFF != 0 || add_pages == 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        let add_len = (add_pages as u64) * 0x1000;
        let grow_hi = grow_lo
            .checked_add(add_len)
            .filter(|end| *end <= Self::USER_HALF_END)
            .ok_or(AddressSpaceError::OutOfRange)?;

        let mut regions = self.regions.lock();
        let mut tail_perms = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::BRK_HEAP;
        tail_perms.0 |= regions.future_lock.region_bits().0;
        if regions.future_lock != FutureLockPolicy::None
            && !bypass_limit
            && regions.locked_bytes().saturating_add(add_len) > limit_bytes
        {
            return Err(AddressSpaceError::LockLimit);
        }
        // The successor VMA (first base strictly above the growing region) must
        // start at or after the new tail end, or the heap would overlap it.
        if regions
            .successor(grow_lo)
            .is_some_and(|successor| successor.base.as_u64() < grow_hi)
        {
            return Err(AddressSpaceError::Overlap);
        }

        if grow_lo == heap_base.as_u64() {
            // First grow. A mapping already rooted at the conventional brk
            // base is not implicitly the heap: it may be a user MAP_FIXED
            // mapping. The old per-grow `map_region` path rejected that
            // collision; extending the foreign VMA would silently annex it
            // into brk ownership and later brk-shrink could free its pages.
            if regions.get(heap_base.as_u64()).is_some() {
                return Err(AddressSpaceError::Overlap);
            }
            if regions
                .predecessor(grow_lo)
                .is_some_and(|p| p.base.as_u64().saturating_add(p.len) > grow_lo)
            {
                return Err(AddressSpaceError::Overlap);
            }
            // Demand-paged: grow the length only, with an EMPTY phys list. Each
            // page materializes its slot on first fault (finish_demand_page), so
            // the grow is O(1) instead of O(pages) (no per-page zero-fill up
            // front), and pages the program never touches cost nothing.
            assert!(regions
                .insert(Region {
                    base: heap_base,
                    len: add_len,
                    perms: tail_perms,
                    phys: Vec::new(),
                })?
                .is_none());
        } else {
            // A later append is valid only when the heap still starts at its
            // owned base and its last fragment ends exactly at the append
            // site. This rejects a detached hole or foreign MAP_FIXED VMA.
            if !regions
                .get(heap_base.as_u64())
                .is_some_and(|root| root.perms.contains(RegionPerms::BRK_HEAP))
            {
                return Err(AddressSpaceError::Overlap);
            }
            let predecessor_base = regions
                .by_base
                .predecessor(grow_lo)
                .map(|(base, _)| base)
                .ok_or(AddressSpaceError::Overlap)?;
            let predecessor = regions
                .get(predecessor_base)
                .ok_or(AddressSpaceError::Overlap)?;
            if predecessor.base.as_u64().saturating_add(predecessor.len) != grow_lo
                || !predecessor.perms.contains(RegionPerms::BRK_HEAP)
            {
                return Err(AddressSpaceError::Overlap);
            }
            if predecessor.perms == tail_perms {
                let heap_tail = regions
                    .get_mut(predecessor_base)
                    .ok_or(AddressSpaceError::Overlap)?;
                // O(1) grow: extend the length only; phys stays at its faulted
                // prefix and grows lazily on fault (see the first-grow comment).
                heap_tail.len += add_len;
            } else {
                assert!(regions
                    .insert(Region {
                        base: VirtAddr::new(grow_lo),
                        len: add_len,
                        perms: tail_perms,
                        phys: Vec::new(),
                    })?
                    .is_none());
            }
        }
        drop(regions);
        Ok((grow_hi, tail_perms))
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
            address_space_id: core::sync::atomic::AtomicU64::new(0),
            regions: IrqSafeSpinLock::new(RegionTable::new()),
            huge_regions: IrqSafeSpinLock::new(Vec::new()),
            vma_transaction: IrqSafeSpinLock::new(()),
            mmap_cursor: core::sync::atomic::AtomicU64::new(Self::MMAP_CURSOR_BASE),
            brk_top: core::sync::atomic::AtomicU64::new(0),
            program_data_bytes: core::sync::atomic::AtomicU64::new(0),
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
            address_space_id: core::sync::atomic::AtomicU64::new(0),
            asid: crate::asid_alloc::allocate_process_asid(),
            regions: IrqSafeSpinLock::new(RegionTable::new()),
            huge_regions: IrqSafeSpinLock::new(Vec::new()),
            vma_transaction: IrqSafeSpinLock::new(()),
            mmap_cursor: core::sync::atomic::AtomicU64::new(Self::MMAP_CURSOR_BASE),
            brk_top: core::sync::atomic::AtomicU64::new(0),
            program_data_bytes: core::sync::atomic::AtomicU64::new(0),
            vm_shared: core::sync::atomic::AtomicBool::new(false),
            numa_hints: IrqSafeSpinLock::new(NumaHints::new()),
        })
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub unsafe fn new_for_user() -> Result<Self, AddressSpaceError> {
        Err(AddressSpaceError::NotImplemented)
    }

    /// Attach a region description to the address-space table. Checks for
    /// overlap and 4 KiB alignment. Ordinarily leaf installation remains an
    /// explicit materialize/fault operation; an eager MCL_FUTURE policy (or an
    /// incoming eager LOCKED region) best-effort populates lazy accessible
    /// pages after publication.
    pub fn map_region(&self, region: Region) -> Result<(), AddressSpaceError> {
        let vma_guard = self.vma_transaction.lock();
        let shared_guard = region
            .perms
            .contains(RegionPerms::SHARED)
            .then(|| SHARED_MAPPING_TRANSACTION.lock());
        let (receipt, eager) = self.map_region_inner(region, None, None)?;
        drop(shared_guard);
        drop(vma_guard);
        if eager {
            // Linux treats population triggered by an inherited future-lock
            // policy as best effort after publishing the mapping.  In
            // particular, allocation failure must not leave a half-created
            // VMA or resurrect locking after a concurrent munlockall.
            self.populate_locked_range_best_effort(
                receipt.base.as_u64(),
                receipt.base.as_u64().saturating_add(receipt.len),
            );
        }
        Ok(())
    }

    /// Preflight Linux locked-mapping admission before a destructive
    /// MAP_FIXED replacement. The final insertion repeats this check under
    /// the same region transaction that publishes the VMA.
    pub fn check_locked_mapping_limit(
        &self,
        len: u64,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<(), AddressSpaceError> {
        let regions = self.regions.lock();
        let mode = match (explicit_lock, regions.future_lock) {
            // Linux ORs MAP_LOCKED into mm->def_flags. An inherited
            // VM_LOCKONFAULT therefore remains on-fault rather than being
            // converted into eager locking by explicit MAP_LOCKED.
            (true, FutureLockPolicy::OnFault) => FutureLockPolicy::OnFault,
            (true, _) => FutureLockPolicy::Eager,
            (false, future) => future,
        };
        if mode != FutureLockPolicy::None
            && !bypass_limit
            && regions.locked_bytes().saturating_add(len) > limit_bytes
        {
            return Err(AddressSpaceError::LockLimit);
        }
        Ok(())
    }

    /// Register a user-created VMA with an atomic final RLIMIT_MEMLOCK check.
    pub fn map_region_limited(
        &self,
        region: Region,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<(), AddressSpaceError> {
        self.map_region_limited_receipt(region, explicit_lock, limit_bytes, bypass_limit)
            .map(|_| ())
    }

    /// [`Self::map_region_limited`] with an opaque receipt that scopes later
    /// materialization or rollback to this exact publication.
    pub fn map_region_limited_receipt(
        &self,
        region: Region,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<MappingReceipt, AddressSpaceError> {
        let vma_guard = self.vma_transaction.lock();
        let shared_guard = region
            .perms
            .contains(RegionPerms::SHARED)
            .then(|| SHARED_MAPPING_TRANSACTION.lock());
        let requested = explicit_lock.then_some(FutureLockPolicy::Eager);
        let (receipt, eager) =
            self.map_region_inner(region, requested, Some((limit_bytes, bypass_limit)))?;
        drop(shared_guard);
        drop(vma_guard);
        if eager {
            self.populate_locked_range_best_effort(
                receipt.base.as_u64(),
                receipt.base.as_u64().saturating_add(receipt.len),
            );
        }
        Ok(receipt)
    }

    /// Transaction-held counterpart of [`Self::map_region_limited_receipt`].
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`]. If `region` is
    /// shared it must then hold [`with_shared_mapping_transaction`].
    pub unsafe fn map_region_locked_limited_receipt(
        &self,
        region: Region,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<MappingReceipt, AddressSpaceError> {
        let requested = explicit_lock.then_some(FutureLockPolicy::Eager);
        self.map_region_inner(region, requested, Some((limit_bytes, bypass_limit)))
            .map(|(receipt, _)| receipt)
    }

    /// Replace a MAP_FIXED base-page window after performing Linux's full-new-
    /// length memlock admission against the pre-replacement address space.
    /// Admission, target retirement, and new VMA publication share the per-AS
    /// VMA transaction, so a CLONE_VM peer cannot consume the allowance or
    /// insert into the hole between those phases.
    pub fn replace_region_limited(
        &self,
        region: Region,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<(), AddressSpaceError> {
        self.replace_region_limited_receipt(region, explicit_lock, limit_bytes, bypass_limit)
            .map(|_| ())
    }

    /// [`Self::replace_region_limited`] with an opaque receipt for the newly
    /// published mapping.
    pub fn replace_region_limited_receipt(
        &self,
        region: Region,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<MappingReceipt, AddressSpaceError> {
        if region.perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        let vma_guard = self.vma_transaction.lock();
        self.check_locked_mapping_limit(region.len, explicit_lock, limit_bytes, bypass_limit)?;
        self.punch_fixed_locked_with_shared_reserving(region.base, region.len, false, 1)?;
        let requested = explicit_lock.then_some(FutureLockPolicy::Eager);
        // The authoritative pre-replacement check above remains valid while
        // `vma_guard` is held. Rechecking after the punch would use the wrong
        // (smaller) locked total and would not add safety.
        let (receipt, eager) = self.map_region_inner(region, requested, None)?;
        drop(vma_guard);
        if eager {
            self.populate_locked_range_best_effort(
                receipt.base.as_u64(),
                receipt.base.as_u64().saturating_add(receipt.len),
            );
        }
        Ok(receipt)
    }

    /// Transaction-held counterpart of
    /// [`Self::replace_region_limited_receipt`].
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`]. Shared regions
    /// additionally require [`with_shared_mapping_transaction`].
    pub unsafe fn replace_region_locked_limited_receipt(
        &self,
        region: Region,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<MappingReceipt, AddressSpaceError> {
        let shared = region.perms.contains(RegionPerms::SHARED);
        self.check_locked_mapping_limit(region.len, explicit_lock, limit_bytes, bypass_limit)?;
        self.punch_fixed_locked_with_shared_reserving(region.base, region.len, shared, 1)?;
        let requested = explicit_lock.then_some(FutureLockPolicy::Eager);
        self.map_region_inner(region, requested, None)
            .map(|(receipt, _)| receipt)
    }

    fn map_region_inner(
        &self,
        mut region: Region,
        requested_lock: Option<FutureLockPolicy>,
        lock_admission: Option<(u64, bool)>,
    ) -> Result<(MappingReceipt, bool), AddressSpaceError> {
        if region.perms.contains(RegionPerms::LOCK_ONFAULT) {
            region.perms.0 |= RegionPerms::LOCKED.0;
        }
        if region.base.as_u64() & 0xFFF != 0 || region.len & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        // Per-page scatter list must cover every page in the region —
        // anything else means the caller computed `len` and `phys` out of sync,
        // which would silently leave pages unbacked or leak frames during
        // materialize.
        //
        // EXCEPTION: a demand-paged BRK_HEAP region may carry a SHORTER phys list
        // than its page count. brk grow extends only the region's length (O(1));
        // each page materializes its phys slot on first fault (finish_demand_page
        // resizes the prefix). The pages past the prefix are demand-zero, so no
        // frame can leak (teardown iterates the materialized prefix) and none is
        // under-mapped (the fault path installs them lazily).
        let region_pages = region.len >> 12;
        let phys_covers = if region.perms.contains(RegionPerms::BRK_HEAP) {
            region.phys.len() as u64 <= region_pages
        } else {
            region.phys.len() as u64 == region_pages
        };
        if !phys_covers {
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
        let mode = match (requested_lock, regions.future_lock) {
            (Some(FutureLockPolicy::Eager), FutureLockPolicy::OnFault) => FutureLockPolicy::OnFault,
            (Some(mode), _) => mode,
            (None, future) => future,
        };
        // Linux performs admission before mmap_region identifies hugetlb,
        // DAX, PFNMAP, and other VM_SPECIAL mappings and clears their lock
        // bits. An ultimately-exempt mapping can therefore still fail with a
        // memlock-limit error before it replaces a MAP_FIXED target.
        if let Some((limit_bytes, bypass_limit)) = lock_admission {
            if mode != FutureLockPolicy::None
                && !bypass_limit
                && regions.locked_bytes().saturating_add(region.len) > limit_bytes
            {
                return Err(AddressSpaceError::LockLimit);
            }
        }
        if !region.perms.contains(RegionPerms::STACK_GUARD)
            && !region.perms.contains(RegionPerms::LOCK_EXEMPT)
        {
            match mode {
                FutureLockPolicy::None => {}
                FutureLockPolicy::Eager => {
                    region.perms.0 |= RegionPerms::LOCKED.0;
                    region.perms.0 &= !RegionPerms::LOCK_ONFAULT.0;
                }
                FutureLockPolicy::OnFault => {
                    region.perms.0 |= RegionPerms::LOCKED.0 | RegionPerms::LOCK_ONFAULT.0;
                }
            }
        }
        let eager = region.perms.contains(RegionPerms::LOCKED)
            && !region.perms.contains(RegionPerms::LOCK_ONFAULT)
            && !region.perms.contains(RegionPerms::STACK_GUARD)
            && !region.perms.contains(RegionPerms::LOCK_EXEMPT)
            && region.perms.prot_only().0 != 0;
        let (base, rb, rl) = (region.base, region.base.as_u64(), region.len);
        let shared = region.perms.contains(RegionPerms::SHARED);
        // A shared mapping acquires external frame ownership below. Prepare
        // its index slot first so an ENOMEM result cannot leak those retains.
        // MAP_FIXED callers preserve this slot across the target punch.
        regions.try_reserve_nodes(1)?;
        if region.perms.contains(RegionPerms::SHARED) {
            retain_shared_frames(&region);
        }
        assert!(regions.insert_reserved(region).is_none());
        let mapping_id = regions
            .mapping_id(rb)
            .expect("newly inserted VMA must have a publication generation");
        drop(regions);
        // Keep the mmap-allocation cursor past anything mapped into the
        // mmap range so a later `reserve_mmap_va` can't collide with it.
        self.bump_mmap_cursor_past(rb, rl);
        Ok((
            MappingReceipt {
                address_space_id: self.identity(),
                base,
                len: rl,
                mapping_id,
                shared,
            },
            eager,
        ))
    }

    /// Register a SHARED region while the caller already holds this address
    /// space's [`Self::with_vma_transaction`] and then
    /// [`with_shared_mapping_transaction`].
    ///
    /// # Safety
    /// The caller must hold both transactions, in that order, across
    /// acquisition of the external owner's frame snapshot and this call.
    pub unsafe fn map_shared_region_locked(&self, region: Region) -> Result<(), AddressSpaceError> {
        // SAFETY: forwarded from this method's transaction contract.
        unsafe { self.map_shared_region_locked_receipt(region) }.map(|_| ())
    }

    /// Receipt-returning counterpart of [`Self::map_shared_region_locked`].
    ///
    /// # Safety
    /// The caller must hold the per-AS VMA transaction followed by the shared
    /// mapping transaction.
    pub unsafe fn map_shared_region_locked_receipt(
        &self,
        region: Region,
    ) -> Result<MappingReceipt, AddressSpaceError> {
        if !region.perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        self.map_region_inner(region, None, None)
            .map(|(receipt, _)| receipt)
    }

    /// Limit-enforcing shared mapping insertion with both the per-AS VMA and
    /// shared-owner transactions already held by the caller.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] and then
    /// [`with_shared_mapping_transaction`] across the backing snapshot and
    /// this call.
    pub unsafe fn map_shared_region_locked_limited(
        &self,
        region: Region,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<(), AddressSpaceError> {
        // SAFETY: forwarded from this method's transaction contract.
        unsafe {
            self.map_shared_region_locked_limited_receipt(
                region,
                explicit_lock,
                limit_bytes,
                bypass_limit,
            )
        }
        .map(|_| ())
    }

    /// Receipt-returning counterpart of
    /// [`Self::map_shared_region_locked_limited`].
    ///
    /// # Safety
    /// The caller must hold the per-AS VMA transaction followed by the shared
    /// mapping transaction.
    pub unsafe fn map_shared_region_locked_limited_receipt(
        &self,
        region: Region,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<MappingReceipt, AddressSpaceError> {
        if !region.perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        let requested = explicit_lock.then_some(FutureLockPolicy::Eager);
        self.map_region_inner(region, requested, Some((limit_bytes, bypass_limit)))
            .map(|(receipt, _)| receipt)
    }

    /// Replace a shared MAP_FIXED window when the caller already owns a stable
    /// backing snapshot (for example a file/device `Arc`). This acquires the
    /// per-AS VMA transaction before the shared-frame transaction.
    ///
    /// # Safety
    /// Every nonzero frame in `region` must remain owned by the external
    /// backing object through this call and subsequent mapping lifetime.
    pub unsafe fn replace_shared_region_limited(
        &self,
        region: Region,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<(), AddressSpaceError> {
        // SAFETY: forwarded from this method's external-backing contract.
        unsafe {
            self.replace_shared_region_limited_receipt(
                region,
                explicit_lock,
                limit_bytes,
                bypass_limit,
            )
        }
        .map(|_| ())
    }

    /// Receipt-returning counterpart of
    /// [`Self::replace_shared_region_limited`].
    ///
    /// # Safety
    /// Every nonzero frame in `region` must remain externally owned for the
    /// complete mapping lifetime.
    pub unsafe fn replace_shared_region_limited_receipt(
        &self,
        region: Region,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<MappingReceipt, AddressSpaceError> {
        let _vma_guard = self.vma_transaction.lock();
        let _shared_guard = SHARED_MAPPING_TRANSACTION.lock();
        // SAFETY: both required transactions are held in documented order and
        // the caller supplies the external-backing lifetime contract.
        unsafe {
            self.replace_shared_region_locked_limited_receipt(
                region,
                explicit_lock,
                limit_bytes,
                bypass_limit,
            )
        }
    }

    /// Shared counterpart of [`Self::replace_region_limited`].
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] and then
    /// [`with_shared_mapping_transaction`] across the backing snapshot and
    /// this call.
    pub unsafe fn replace_shared_region_locked_limited(
        &self,
        region: Region,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<(), AddressSpaceError> {
        // SAFETY: forwarded from this method's transaction contract.
        unsafe {
            self.replace_shared_region_locked_limited_receipt(
                region,
                explicit_lock,
                limit_bytes,
                bypass_limit,
            )
        }
        .map(|_| ())
    }

    /// Receipt-returning counterpart of
    /// [`Self::replace_shared_region_locked_limited`].
    ///
    /// # Safety
    /// The caller must hold the per-AS VMA transaction followed by the shared
    /// mapping transaction.
    pub unsafe fn replace_shared_region_locked_limited_receipt(
        &self,
        region: Region,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<MappingReceipt, AddressSpaceError> {
        if !region.perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        self.check_locked_mapping_limit(region.len, explicit_lock, limit_bytes, bypass_limit)?;
        self.punch_fixed_locked_with_shared_reserving(region.base, region.len, true, 1)?;
        let requested = explicit_lock.then_some(FutureLockPolicy::Eager);
        self.map_region_inner(region, requested, None)
            .map(|(receipt, _)| receipt)
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
                    // Undo the rmap owner move this alias's successful
                    // replacement performed (new → back to old), mirroring the
                    // PTE/`phys` rollback above.
                    crate::rmap::remove(new_phys, self.root, rollback_va);
                    crate::rmap::add(old_phys, self.root, rollback_va);
                    self.flush_region_broadcast(rollback_va, 1);
                }
                return Err(AddressSpaceError::NotImplemented);
            }
            regions
                .get_mut(region_base)
                .expect("shared alias region disappeared under lock")
                .phys[page_idx] = new_phys;
            // Transfer the reverse-map owner from the old frame to the new one,
            // exactly as Linux page migration moves a folio's mapping
            // (mm/migrate.c `folio_migrate_mapping` / `remove_migration_ptes`)
            // so the OLD page's mapcount reaches 0 before it can be freed.
            // Without this, `old_phys` keeps a stale (root, va) owner pointing at
            // a frame whose leaf now maps `new_phys`, and freeing `old_phys`
            // later trips the nonzero-mapcount invariant.
            crate::rmap::remove(old_phys, self.root, page_va);
            crate::rmap::add(new_phys, self.root, page_va);
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
        let _vma_guard = self.vma_transaction.lock();
        // SAFETY: caller's contract is forwarded while the VMA transaction
        // excludes concurrent topology changes.
        unsafe { self.map_huge_region_locked(region) }
    }

    /// Linux syscall commit for an explicit hugetlb mapping. Memlock
    /// admission uses the full requested length before hugetlb exemption
    /// clears the lock bits; MAP_FIXED replacement and publication remain in
    /// the same per-AS VMA transaction.
    ///
    /// # Safety
    /// Same live-root and backing-ownership contract as
    /// [`Self::map_huge_region`].
    pub unsafe fn map_huge_region_limited(
        &self,
        region: HugeRegion,
        fixed: bool,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<(), AddressSpaceError> {
        let _vma_guard = self.vma_transaction.lock();
        // SAFETY: caller's contract is forwarded while the VMA transaction
        // excludes concurrent topology changes.
        unsafe {
            self.map_huge_region_locked_limited(
                region,
                fixed,
                explicit_lock,
                limit_bytes,
                bypass_limit,
            )
        }
    }

    /// Transaction-held counterpart of [`Self::map_huge_region_limited`].
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] and uphold the live
    /// root/backing ownership contract of [`Self::map_huge_region`].
    pub unsafe fn map_huge_region_locked_limited(
        &self,
        mut region: HugeRegion,
        fixed: bool,
        explicit_lock: bool,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<(), AddressSpaceError> {
        if let Err(error) =
            self.check_locked_mapping_limit(region.len, explicit_lock, limit_bytes, bypass_limit)
        {
            return release_failed_huge_region(region, error);
        }
        if fixed {
            if let Err(error) = self.punch_fixed_locked(region.base, region.len) {
                return release_failed_huge_region(region, error);
            }
        }
        // Explicit hugetlb VMAs are mlock-fixup exempt on Linux. Admission
        // above still happens, but successful VMAs carry neither lock bit.
        region.perms.0 &= !(RegionPerms::LOCKED.0 | RegionPerms::LOCK_ONFAULT.0);
        // SAFETY: caller's contract is forwarded; the VMA transaction is held.
        unsafe { self.map_huge_region_locked(region) }
    }

    /// [`Self::map_huge_region`] with the per-AS VMA transaction held.
    unsafe fn map_huge_region_locked(&self, region: HugeRegion) -> Result<(), AddressSpaceError> {
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
        let _vma_guard = self.vma_transaction.lock();
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
        self.grow_region_limited(base, new_len, MremapLimits::UNLIMITED)
    }

    /// Linux-limit-enforcing locked-VMA growth used by `mremap`.
    pub fn grow_region_limited(
        &self,
        base: VirtAddr,
        new_len: u64,
        limits: MremapLimits,
    ) -> Result<(), AddressSpaceError> {
        let eager_range = {
            let _vma_guard = self.vma_transaction.lock();
            self.grow_region_locked(base, None, new_len, limits)?
        };
        if let Some((lo, hi)) = eager_range {
            self.populate_locked_range_best_effort(lo, hi);
        }
        Ok(())
    }

    /// [`Self::grow_region_limited`] with the VMA transaction held.
    fn grow_region_locked(
        &self,
        base: VirtAddr,
        expected_old_len: Option<u64>,
        new_len: u64,
        limits: MremapLimits,
    ) -> Result<Option<(u64, u64)>, AddressSpaceError> {
        if new_len & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        let huge = self.huge_regions.lock();
        let mut regions = self.regions.lock();
        let old_len = regions
            .get(base.as_u64())
            .ok_or(AddressSpaceError::Unmapped)?
            .len;
        if expected_old_len.is_some_and(|expected| expected != old_len) {
            return Err(AddressSpaceError::Unmapped);
        }
        if new_len <= old_len {
            return Ok(None);
        }
        let source_perms = regions
            .get(base.as_u64())
            .ok_or(AddressSpaceError::Unmapped)?
            .perms;
        Self::check_mremap_growth_limits_locked(
            &regions,
            &huge,
            source_perms,
            new_len - old_len,
            limits,
        )?;
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
        let eager_locked = region.perms.contains(RegionPerms::LOCKED)
            && !region.perms.contains(RegionPerms::LOCK_ONFAULT)
            && !region.perms.contains(RegionPerms::LOCK_EXEMPT)
            && region.perms.prot_only().0 != 0;
        // VMA metadata allocation is fallible at the syscall boundary. An
        // unchecked Vec::push loop here lets an unprivileged gigantic
        // mremap reach the kernel allocator's abort path while IRQs and the
        // address-space transaction are held. Reserve before publishing any
        // length/backing change so ENOMEM leaves the source untouched.
        region
            .phys
            .try_reserve_exact(add_pages)
            .map_err(|_| AddressSpaceError::AllocationFailed)?;
        for _ in 0..add_pages {
            region.phys.push(PhysAddr::new(0));
        }
        region.len = new_len;
        let (rb, rl) = (base.as_u64(), new_len);
        drop(regions);
        drop(huge);
        // Keep the mmap-allocation cursor past the grown region, exactly as
        // `map_region` does for a fresh mapping. Without this, an in-place
        // `mremap` grow extends the region past the monotonic bump cursor;
        // a later `reserve_mmap_va` then hands back a VA *inside* the grown
        // tail, and `map_region` rejects it as Overlap — surfacing as a
        // spurious `mmap`/`malloc` failure (musl's mallocng grows arenas
        // this way, so a heavy client like weston's desktop-shell hits it).
        self.bump_mmap_cursor_past(rb, rl);
        Ok(eager_locked.then_some((rb.saturating_add(old_len), rb + new_len)))
    }

    /// Transaction-held exact-VMA growth used by the Linux `mremap` syscall.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`].
    pub unsafe fn grow_region_locked_limited(
        &self,
        base: VirtAddr,
        old_len: u64,
        new_len: u64,
        limits: MremapLimits,
    ) -> Result<Option<(u64, u64)>, AddressSpaceError> {
        self.grow_region_locked(base, Some(old_len), new_len, limits)
    }

    fn check_mremap_growth_limits_locked(
        regions: &RegionTable,
        huge: &[HugeRegion],
        source_perms: RegionPerms,
        charge_bytes: u64,
        limits: MremapLimits,
    ) -> Result<(), AddressSpaceError> {
        if charge_bytes == 0 || limits == MremapLimits::UNLIMITED {
            return Ok(());
        }
        if source_perms.contains(RegionPerms::LOCKED)
            && !limits.bypass_memlock
            && regions.locked_bytes().saturating_add(charge_bytes) > limits.memlock_bytes
        {
            return Err(AddressSpaceError::LockLimit);
        }
        let huge_mapped = huge
            .iter()
            .fold(0u64, |total, region| total.saturating_add(region.len));
        let mapped_pages = regions.accounted_mapped_bytes().saturating_add(huge_mapped) >> 12;
        if mapped_pages.saturating_add(charge_bytes >> 12) > (limits.address_space_bytes >> 12) {
            return Err(AddressSpaceError::MappingLimit);
        }
        let data_mapping = source_perms.contains(RegionPerms::WRITE)
            && !source_perms.contains(RegionPerms::SHARED)
            && !source_perms.contains(RegionPerms::STACK_SEGMENT)
            && !source_perms.contains(RegionPerms::STACK_GUARD);
        if data_mapping {
            let huge_data = huge
                .iter()
                .filter(|region| {
                    region.perms.contains(RegionPerms::WRITE)
                        && !region.perms.contains(RegionPerms::SHARED)
                        && !region.perms.contains(RegionPerms::STACK_SEGMENT)
                })
                .fold(0u64, |total, region| total.saturating_add(region.len));
            let data_pages = regions.data_mapped_bytes().saturating_add(huge_data) >> 12;
            let grown_data_pages = data_pages.saturating_add(charge_bytes >> 12);
            let exceeds_soft = grown_data_pages > (limits.data_bytes >> 12);
            let zero_soft_compat =
                limits.data_bytes == 0 && grown_data_pages <= (limits.data_max_bytes >> 12);
            if exceeds_soft && !zero_soft_compat {
                return Err(AddressSpaceError::MappingLimit);
            }
        }
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
        // SAFETY: caller's contract is forwarded to the limit-enforcing form.
        unsafe {
            self.relocate_region_limited(
                old_base,
                old_len,
                new_base,
                new_len,
                MremapLimits::UNLIMITED,
            )
        }
    }

    /// Limit-enforcing relocation/resize used by Linux `mremap`.
    ///
    /// # Safety
    /// Same live-root contract as [`Self::relocate_region`].
    pub unsafe fn relocate_region_limited(
        &self,
        old_base: VirtAddr,
        old_len: u64,
        new_base: VirtAddr,
        new_len: u64,
        limits: MremapLimits,
    ) -> Result<(), AddressSpaceError> {
        let eager_range = {
            let _vma_guard = self.vma_transaction.lock();
            // SAFETY: caller's contract is forwarded while topology is excluded.
            unsafe { self.relocate_region_locked(old_base, old_len, new_base, new_len, limits) }?
        };
        if let Some((lo, hi)) = eager_range {
            self.populate_locked_range_best_effort(lo, hi);
        }
        Ok(())
    }

    /// Transaction-held relocation used by the Linux `mremap` syscall.
    /// Eager locked-tail population must be completed after releasing the VMA
    /// transaction through [`Self::finish_relocation_population`].
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] and uphold the
    /// live-root contract from [`Self::relocate_region`].
    pub unsafe fn relocate_region_locked_limited(
        &self,
        old_base: VirtAddr,
        old_len: u64,
        new_base: VirtAddr,
        new_len: u64,
        limits: MremapLimits,
    ) -> Result<Option<(u64, u64)>, AddressSpaceError> {
        // SAFETY: the caller provides the transaction and live-root contract.
        unsafe { self.relocate_region_locked(old_base, old_len, new_base, new_len, limits) }
    }

    /// Fixed-target relocation with source-growth admission checked before
    /// target replacement under one VMA transaction.
    ///
    /// # Safety
    /// Same live-root contract as [`Self::relocate_region`].
    pub unsafe fn relocate_region_fixed_limited(
        &self,
        old_base: VirtAddr,
        old_len: u64,
        new_base: VirtAddr,
        new_len: u64,
        limits: MremapLimits,
    ) -> Result<(), FixedRelocationError> {
        let eager_range = {
            let _vma_guard = self.vma_transaction.lock();
            // SAFETY: the VMA transaction is held while target classification
            // remains stable.
            let shared =
                unsafe { self.fixed_relocation_needs_shared_transaction_locked(new_base, new_len) }
                    .map_err(|error| FixedRelocationError {
                        error,
                        target_punched: false,
                        source_shrunk: false,
                    })?;
            let relocate = || {
                // SAFETY: this wrapper holds the VMA transaction, conditionally
                // holds the shared transaction, and forwards its live root.
                unsafe {
                    self.relocate_region_fixed_locked_limited(
                        old_base, old_len, new_base, new_len, limits, shared,
                    )
                }
            };
            if shared {
                let _shared_guard = SHARED_MAPPING_TRANSACTION.lock();
                relocate()
            } else {
                relocate()
            }?
        };
        self.finish_relocation_population(eager_range);
        Ok(())
    }

    /// Transaction-held fixed relocation which independently reports whether
    /// its target was retired and whether a shrinking source was truncated
    /// before a later failure. Upper layers mirror both Linux-visible topology
    /// transitions in file/SysV owner metadata before releasing the locks. The
    /// supported private source is one exact Region; Linux cross-VMA move-only
    /// relocation remains an explicit unsupported shape.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`]. If
    /// `shared_transaction_held` is true it must additionally hold
    /// [`with_shared_mapping_transaction`]; if false, target classification
    /// under the VMA transaction must have proven no shared overlap. The
    /// live-root contract from [`Self::relocate_region`] continues to apply.
    pub unsafe fn relocate_region_fixed_locked_limited(
        &self,
        old_base: VirtAddr,
        old_len: u64,
        new_base: VirtAddr,
        new_len: u64,
        limits: MremapLimits,
        shared_transaction_held: bool,
    ) -> Result<Option<(u64, u64)>, FixedRelocationError> {
        let early = |error| FixedRelocationError {
            error,
            target_punched: false,
            source_shrunk: false,
        };
        // Validate every request property that is independent of target
        // contents before MAP_FIXED irreversibly retires that target.
        Self::relocation_bounds(old_base, old_len, new_base, new_len).map_err(early)?;
        self.check_relocation_limits(old_base, old_len, new_len, limits)
            .map_err(early)?;
        self.punch_fixed_locked_with_shared_reserving(
            new_base,
            new_len,
            shared_transaction_held,
            1,
        )
        .map_err(early)?;
        let mut source_shrunk = false;
        let move_old_len = if old_len > new_len {
            let tail_base = VirtAddr::new(old_base.as_u64() + new_len);
            self.punch_fixed_locked_with_shared_reserving(
                tail_base,
                old_len - new_len,
                shared_transaction_held,
                1,
            )
            .map_err(|error| FixedRelocationError {
                error,
                target_punched: true,
                source_shrunk: false,
            })?;
            source_shrunk = true;

            #[cfg(feature = "kernel-test")]
            if FAIL_FIXED_RELOCATION_AFTER_SHRINK.swap(false, core::sync::atomic::Ordering::AcqRel)
            {
                return Err(FixedRelocationError {
                    error: AddressSpaceError::AllocationFailed,
                    target_punched: true,
                    source_shrunk: true,
                });
            }
            new_len
        } else {
            old_len
        };
        // The authoritative pre-punch admission remains valid while the VMA
        // transaction is held. Do not recompute against the smaller
        // post-replacement total.
        // SAFETY: caller's contract is forwarded and both ranges are excluded
        // from concurrent topology mutation.
        unsafe {
            self.relocate_region_locked(
                old_base,
                move_old_len,
                new_base,
                new_len,
                MremapLimits::UNLIMITED,
            )
        }
        .map_err(|error| FixedRelocationError {
            error,
            target_punched: true,
            source_shrunk,
        })
    }

    /// Whether a fixed target overlaps borrowed/shared base-page backing.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] through the
    /// subsequent fixed relocation so the classification cannot go stale.
    pub unsafe fn fixed_relocation_needs_shared_transaction_locked(
        &self,
        base: VirtAddr,
        len: u64,
    ) -> Result<bool, AddressSpaceError> {
        if base.as_u64() & 0xFFF != 0 || len == 0 || len & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        let lo = base.as_u64();
        let hi = lo.checked_add(len).ok_or(AddressSpaceError::OutOfRange)?;
        let regions = self.regions.lock();
        Ok(regions.overlapping_any(lo, hi, |region| region.perms.contains(RegionPerms::SHARED)))
    }

    /// Complete eager locked-tail population after the caller releases every
    /// IRQ-safe VMA/external-owner transaction.
    pub fn finish_relocation_population(&self, eager_range: Option<(u64, u64)>) {
        if let Some((lo, hi)) = eager_range {
            self.populate_locked_range_best_effort(lo, hi);
        }
    }

    fn relocation_bounds(
        old_base: VirtAddr,
        old_len: u64,
        new_base: VirtAddr,
        new_len: u64,
    ) -> Result<(u64, u64, u64, u64), AddressSpaceError> {
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
        Ok((old_lo, old_hi, new_lo, new_hi))
    }

    fn check_relocation_limits(
        &self,
        old_base: VirtAddr,
        old_len: u64,
        new_len: u64,
        limits: MremapLimits,
    ) -> Result<(), AddressSpaceError> {
        let huge = self.huge_regions.lock();
        let regions = self.regions.lock();
        let old_lo = old_base.as_u64();
        let old_hi = old_lo
            .checked_add(old_len)
            .ok_or(AddressSpaceError::OutOfRange)?;
        if regions.swap_pages.range(old_lo..old_hi).next().is_some() {
            return Err(AddressSpaceError::NotImplemented);
        }
        let source = regions
            .get(old_lo)
            .filter(|region| region.len == old_len)
            .ok_or(AddressSpaceError::Unmapped)?;
        if source.perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        if new_len > old_len {
            Self::check_mremap_growth_limits_locked(
                &regions,
                &huge,
                source.perms,
                new_len - old_len,
                limits,
            )?;
        }
        Ok(())
    }

    /// [`Self::relocate_region_limited`] with the VMA transaction held.
    unsafe fn relocate_region_locked(
        &self,
        old_base: VirtAddr,
        old_len: u64,
        new_base: VirtAddr,
        new_len: u64,
        limits: MremapLimits,
    ) -> Result<Option<(u64, u64)>, AddressSpaceError> {
        let (old_lo, old_hi, new_lo, new_hi) =
            Self::relocation_bounds(old_base, old_len, new_base, new_len)?;

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
            .ok_or(AddressSpaceError::Unmapped)?;
        if new_len > old_len {
            Self::check_mremap_growth_limits_locked(
                &regions,
                &huge,
                source.perms,
                new_len - old_len,
                limits,
            )?;
        }
        if source.perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        if regions.has_overlap(new_lo, new_hi) {
            return Err(AddressSpaceError::Overlap);
        }

        let kept_pages = core::cmp::min(old_len, new_len) as usize >> 12;
        let new_pages =
            usize::try_from(new_len >> 12).map_err(|_| AddressSpaceError::AllocationFailed)?;
        // Build every proportional metadata allocation before changing the
        // source coordinates. extend/resize are infallible after an exact
        // successful reservation, so the source commit below cannot invoke
        // the allocator's abort path. A FIXED wrapper may already have retired
        // its target; that post-punch outcome is surfaced separately by the
        // syscall transaction rather than hidden as source mutation.
        let mut moved_phys = Vec::new();
        moved_phys
            .try_reserve_exact(new_pages)
            .map_err(|_| AddressSpaceError::AllocationFailed)?;
        moved_phys.extend(source.phys.iter().take(kept_pages).copied());
        moved_phys.resize(new_pages, PhysAddr::new(0));
        let moved = Region {
            base: new_base,
            len: new_len,
            perms: source.perms,
            phys: moved_phys,
        };
        // Prepare the destination index node before any leaf or source
        // mutation. `insert_reserved` below is therefore allocation-free.
        regions.try_reserve_nodes(1)?;
        let source = regions
            .get(old_lo)
            .filter(|region| region.len == old_len)
            .expect("validated relocation source disappeared under region lock");

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
            if let Err(error) = unsafe { self.install_region_leaves_local(&moved) } {
                // SAFETY: only leaves belonging to the validated destination
                // region can have been installed by the failed operation.
                unsafe { self.unmap_region_leaves_local(&moved) };
                return Err(error);
            }
            // A present source leaf must already have reverse-map authority.
            // Metadata-only internal construction may legitimately record a
            // resident frame without materializing its source leaf; that case
            // gains its first rmap entry at the installed destination below.
            for (index, &phys) in source.phys.iter().enumerate() {
                if phys.raw() == 0 {
                    continue;
                }
                let old_va = VirtAddr::new(old_lo + (index as u64) * 4096);
                #[cfg(target_arch = "x86_64")]
                // SAFETY: this address space owns the live root and `old_va`
                // lies in the validated source VMA held by the region lock.
                let present = unsafe { crate::x86_64::paging::translate(self.root, old_va) };
                #[cfg(target_arch = "aarch64")]
                // SAFETY: same live-root and source-VMA contract as x86_64.
                let present = unsafe { crate::aarch64::paging::translate(self.root, old_va) };
                if let Some(mapped) = present {
                    assert_eq!(mapped, phys, "relocation source leaf/backing mismatch");
                    assert!(
                        crate::rmap::contains_owner(phys, self.root, old_va),
                        "mapped relocation source missing from reverse map"
                    );
                }
            }
            // Destination is complete; retire the source leaves before
            // publishing the new region coordinates.
            // SAFETY: `source` remains owned by this address space under the
            // region locks, and its validated user range is still mapped.
            unsafe { self.unmap_region_leaves_local(source) };

            // Move the reverse-map authority in the same region transaction.
            // Reclaim and migration resolve a resident frame through rmap;
            // leaving the old VA recorded after moving the PTE makes them
            // operate on an absent source leaf and miss the live destination.
            // The region lock also excludes COW/swap mutations while each
            // retained frame changes coordinates. Truncated frames lose their
            // old owner here before the post-flush free below.
            for (index, &phys) in source.phys.iter().enumerate() {
                if phys.raw() == 0 {
                    continue;
                }
                let old_va = VirtAddr::new(old_lo + (index as u64) * 4096);
                if index < kept_pages {
                    let new_va = VirtAddr::new(new_lo + (index as u64) * 4096);
                    if !crate::rmap::move_owner(phys, self.root, old_va, new_va) {
                        crate::rmap::add(phys, self.root, new_va);
                    }
                } else {
                    crate::rmap::remove(phys, self.root, old_va);
                }
            }
        }
        let source = regions
            .remove(old_lo)
            .expect("relocation source disappeared under region lock");
        assert!(regions.insert_reserved(moved).is_none());
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
        let eager_range = (new_len > old_len
            && source.perms.contains(RegionPerms::LOCKED)
            && !source.perms.contains(RegionPerms::LOCK_ONFAULT)
            && !source.perms.contains(RegionPerms::LOCK_EXEMPT)
            && source.perms.prot_only().0 != 0)
            .then_some((new_lo + old_len, new_hi));
        Ok(eager_range)
    }

    /// Move one interval of an ordinary SHARED base-page VMA to a disjoint
    /// destination, optionally resizing it at the same time. Unlike
    /// [`Self::alias_shared_region_locked_limited`], this operation transfers
    /// the source VMA's backing ownership: kept resident PTE/rmap owners move
    /// to the destination, a grown tail remains lazy, and truncated shared
    /// backing is released only after the source TLB invalidation completes.
    ///
    /// The source interval must be contained by one Region. A prefix and/or
    /// suffix outside that interval is preserved as a separate Region with its
    /// original backing. Swap, huge-page, and cross-Region moves return
    /// [`AddressSpaceError::NotImplemented`] rather than approximating Linux
    /// with lost backing or permissions.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] followed by
    /// [`with_shared_mapping_transaction`], and `self.root` must satisfy the
    /// live-root contract from [`Self::relocate_region`]. External file/SysV
    /// ownership must be moved in the same outer transaction before faults can
    /// observe a lazy `FILE_DEMAND` destination.
    pub unsafe fn relocate_shared_region_locked_limited(
        &self,
        old_base: VirtAddr,
        old_len: u64,
        new_base: VirtAddr,
        new_len: u64,
        limits: MremapLimits,
    ) -> Result<Option<(u64, u64)>, AddressSpaceError> {
        let (old_lo, old_hi, new_lo, new_hi) =
            Self::relocation_bounds(old_base, old_len, new_base, new_len)?;

        let huge = self.huge_regions.lock();
        if huge.iter().any(|region| {
            let rb = region.base.as_u64();
            let re = rb.saturating_add(region.len);
            rb < old_hi && old_lo < re
        }) {
            return Err(AddressSpaceError::NotImplemented);
        }
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
        let source_region = regions
            .containing(old_lo)
            .ok_or(AddressSpaceError::Unmapped)?;
        let source_region_base = source_region.base.as_u64();
        let source_region_end = source_region_base
            .checked_add(source_region.len)
            .ok_or(AddressSpaceError::OutOfRange)?;
        if old_hi > source_region_end {
            return Err(AddressSpaceError::NotImplemented);
        }
        let source_perms = source_region.perms;
        if !source_perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        if source_perms.contains(RegionPerms::STACK_SEGMENT)
            || source_perms.contains(RegionPerms::STACK_GUARD)
        {
            return Err(AddressSpaceError::NotImplemented);
        }
        if new_len > old_len {
            // Normal FILE_DEMAND VMAs are LOCK_EXEMPT because their backing is
            // externally owned, but remain expandable. The non-file form is
            // the closest Region analogue of VM_DONTEXPAND/VM_PFNMAP, for
            // which Linux reports EFAULT on growth.
            if source_perms.contains(RegionPerms::LOCK_EXEMPT)
                && !source_perms.contains(RegionPerms::FILE_DEMAND)
            {
                return Err(AddressSpaceError::Unmapped);
            }
            Self::check_mremap_growth_limits_locked(
                &regions,
                &huge,
                source_perms,
                new_len - old_len,
                limits,
            )?;
        }
        if regions.has_overlap(new_lo, new_hi) {
            return Err(AddressSpaceError::Overlap);
        }

        let first = usize::try_from((old_lo - source_region_base) >> 12)
            .map_err(|_| AddressSpaceError::AllocationFailed)?;
        let old_pages =
            usize::try_from(old_len >> 12).map_err(|_| AddressSpaceError::AllocationFailed)?;
        let new_pages =
            usize::try_from(new_len >> 12).map_err(|_| AddressSpaceError::AllocationFailed)?;
        let kept_pages = core::cmp::min(old_pages, new_pages);
        let source_pages = source_region
            .phys
            .get(first..first.saturating_add(old_pages))
            .ok_or(AddressSpaceError::Unmapped)?;
        let mut source_phys = Vec::new();
        source_phys
            .try_reserve_exact(old_pages)
            .map_err(|_| AddressSpaceError::AllocationFailed)?;
        source_phys.extend_from_slice(source_pages);

        // Prepare every proportional backing vector before touching either
        // PTE tree. Region nodes are then provisionally inserted while the
        // table lock still hides them; any page-table allocation failure can
        // remove those nodes and leave the original source fully authoritative.
        let mut destination_phys = Vec::new();
        destination_phys
            .try_reserve_exact(new_pages)
            .map_err(|_| AddressSpaceError::AllocationFailed)?;
        destination_phys.extend(source_phys.iter().take(kept_pages).copied());
        destination_phys.resize(new_pages, PhysAddr::new(0));

        let head_pages = first;
        let tail_first = first
            .checked_add(old_pages)
            .ok_or(AddressSpaceError::AllocationFailed)?;
        let tail_pages = source_region.phys.len().saturating_sub(tail_first);
        let mut head_phys = Vec::new();
        if head_pages != 0 {
            // Clamp to the materialized prefix — a demand-paged region's phys list
            // may be shorter than its page count; the kept head keeps its faulted
            // prefix and stays demand-paged (the tail below already derives its
            // page count from `phys.len()`).
            let head_mat = head_pages.min(source_region.phys.len());
            head_phys
                .try_reserve_exact(head_mat)
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            head_phys.extend_from_slice(&source_region.phys[..head_mat]);
        }
        let mut tail_phys = Vec::new();
        if tail_pages != 0 {
            tail_phys
                .try_reserve_exact(tail_pages)
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            tail_phys.extend_from_slice(&source_region.phys[tail_first..]);
        }
        let mut truncated_phys = Vec::new();
        if old_pages > kept_pages {
            truncated_phys
                .try_reserve_exact(old_pages - kept_pages)
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            truncated_phys.extend_from_slice(&source_phys[kept_pages..]);
        }

        let destination_region = Region {
            base: new_base,
            len: new_len,
            perms: source_perms,
            phys: destination_phys,
        };
        let tail_region = (tail_pages != 0).then(|| Region {
            base: VirtAddr::new(old_hi),
            len: source_region_end - old_hi,
            perms: source_perms,
            phys: tail_phys,
        });

        // Only resident source leaves move. A nonresident shared page retains
        // its backing metadata and faults at the destination instead of being
        // accidentally made resident by the metadata transfer.
        let tracks_resident_leaves = self.root.as_u64() != 0 && source_perms.prot_only().0 != 0;
        let mut leaf_phys = Vec::new();
        if tracks_resident_leaves {
            leaf_phys
                .try_reserve_exact(new_pages)
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            for (index, &phys) in source_phys.iter().take(kept_pages).enumerate() {
                if phys.raw() == 0 {
                    leaf_phys.push(PhysAddr::new(0));
                    continue;
                }
                let source_va = VirtAddr::new(old_lo + index as u64 * 4096);
                #[cfg(target_arch = "x86_64")]
                // SAFETY: both structural transactions and the regions lock
                // keep the source PTE/backing pair stable through commit.
                let mapped = unsafe { crate::x86_64::paging::translate(self.root, source_va) };
                #[cfg(target_arch = "aarch64")]
                // SAFETY: same live-root/source-transaction proof as x86_64.
                let mapped = unsafe { crate::aarch64::paging::translate(self.root, source_va) };
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                let mapped = Some(phys);
                match mapped {
                    Some(mapped)
                        if mapped == phys
                            && crate::rmap::contains_owner(phys, self.root, source_va) =>
                    {
                        leaf_phys.push(phys);
                    }
                    Some(_) => return Err(AddressSpaceError::NotImplemented),
                    None => leaf_phys.push(PhysAddr::new(0)),
                }
            }
            leaf_phys.resize(new_pages, PhysAddr::new(0));
        }
        let destination_leaf_view = Region {
            base: new_base,
            len: new_len,
            perms: source_perms,
            phys: leaf_phys,
        };

        // A contained sub-VMA move publishes the destination and, when the
        // selected interval has a suffix, one preserved tail. Reserve both
        // arena slots before installing any destination leaf.
        regions.try_reserve_nodes(1 + usize::from(tail_pages != 0))?;

        // Publish the provisional tree nodes before the first PTE mutation.
        // They temporarily overlap the old source only inside this locked
        // table and are removed on every recoverable exit below. Their arena
        // capacity was fallibly prepared above, so publication cannot enter
        // the allocator's abort path.
        if let Some(tail) = tail_region {
            assert!(regions.insert_reserved(tail).is_none());
        }
        assert!(regions.insert_reserved(destination_region).is_none());

        if self.root.as_u64() != 0 {
            // SAFETY: destination is validated, disjoint, and free; caller
            // supplies the live-root contract.
            if let Err(error) = unsafe { self.install_region_leaves_local(&destination_leaf_view) }
            {
                let _destination = regions
                    .remove(new_lo)
                    .expect("failed shared relocation lost provisional destination");
                if tail_pages != 0 {
                    let _tail = regions
                        .remove(old_hi)
                        .expect("failed shared relocation lost provisional suffix");
                }
                // SAFETY: removes only the partial destination leaves installed
                // by the failed operation above.
                unsafe { self.unmap_region_leaves_local(&destination_leaf_view) };
                drop(regions);
                drop(huge);
                self.flush_region_broadcast(new_base, new_len >> 12);
                return Err(error);
            }

            #[cfg(feature = "kernel-test")]
            if FAIL_SHARED_RELOCATION_AFTER_INSTALL
                .swap(false, core::sync::atomic::Ordering::AcqRel)
            {
                let _destination = regions
                    .remove(new_lo)
                    .expect("injected shared relocation lost provisional destination");
                if tail_pages != 0 {
                    let _tail = regions
                        .remove(old_hi)
                        .expect("injected shared relocation lost provisional suffix");
                }
                // SAFETY: injection occurs before source/rmap/ownership commit.
                unsafe { self.unmap_region_leaves_local(&destination_leaf_view) };
                drop(regions);
                drop(huge);
                self.flush_region_broadcast(new_base, new_len >> 12);
                return Err(AddressSpaceError::AllocationFailed);
            }

            let source_view = Region {
                base: old_base,
                len: old_len,
                perms: source_perms,
                phys: Vec::new(),
            };
            // SAFETY: names exactly the validated source interval; kept
            // translations are already installed at their new coordinates.
            unsafe { self.unmap_region_leaves_local(&source_view) };
            if tracks_resident_leaves {
                for (index, &phys) in source_phys.iter().enumerate() {
                    if phys.raw() == 0 {
                        continue;
                    }
                    let old_va = VirtAddr::new(old_lo + index as u64 * 4096);
                    if index < kept_pages && destination_leaf_view.phys[index].raw() != 0 {
                        let new_va = VirtAddr::new(new_lo + index as u64 * 4096);
                        assert!(
                            crate::rmap::move_owner(phys, self.root, old_va, new_va),
                            "resident shared relocation source missing rmap owner"
                        );
                    } else {
                        crate::rmap::remove(phys, self.root, old_va);
                    }
                }
            }
        }

        // Retire the old VMA generation and publish its optional prefix. The
        // suffix and destination nodes were already published before the PTE
        // commit, so no operation returning a recoverable error follows.
        if head_pages == 0 {
            let _source = regions
                .remove(source_region_base)
                .expect("shared relocation source disappeared under region lock");
        } else {
            regions
                .demand_pages
                .retain_outside(source_region_base, source_region_end);
            regions
                .cow_pages
                .retain(|&vaddr, _| vaddr < source_region_base || vaddr >= source_region_end);
            let source = regions
                .get_mut(source_region_base)
                .expect("shared relocation source disappeared under region lock");
            source.len = old_lo - source_region_base;
            source.phys = head_phys;
            regions.invalidate_mapping(source_region_base);
        }
        drop(regions);
        drop(huge);

        self.flush_region_broadcast(old_base, old_len >> 12);
        self.flush_region_broadcast(new_base, new_len >> 12);
        for phys in truncated_phys {
            release_shared_phys(phys);
        }
        self.bump_mmap_cursor_past(new_lo, new_len);
        let eager_range = (new_len > old_len
            && source_perms.contains(RegionPerms::LOCKED)
            && !source_perms.contains(RegionPerms::LOCK_ONFAULT)
            && !source_perms.contains(RegionPerms::LOCK_EXEMPT)
            && source_perms.prot_only().0 != 0)
            .then_some((new_lo + old_len, new_hi));
        Ok(eager_range)
    }

    /// Acquire the VMA/shared transactions around an ordinary shared move and
    /// finish eager locked-tail population after releasing both IRQ-safe locks.
    ///
    /// # Safety
    /// Same live-root contract as [`Self::relocate_region`].
    pub unsafe fn relocate_shared_region_limited(
        &self,
        old_base: VirtAddr,
        old_len: u64,
        new_base: VirtAddr,
        new_len: u64,
        limits: MremapLimits,
    ) -> Result<(), AddressSpaceError> {
        let eager_range = {
            let _vma_guard = self.vma_transaction.lock();
            let _shared_guard = SHARED_MAPPING_TRANSACTION.lock();
            // SAFETY: wrapper supplies both required transactions and forwards
            // the caller's live-root contract.
            unsafe {
                self.relocate_shared_region_locked_limited(
                    old_base, old_len, new_base, new_len, limits,
                )
            }?
        };
        self.finish_relocation_population(eager_range);
        Ok(())
    }

    fn check_shared_relocation_source_and_limits_locked(
        &self,
        old_base: VirtAddr,
        old_len: u64,
        new_len: u64,
        limits: MremapLimits,
    ) -> Result<(), AddressSpaceError> {
        let old_lo = old_base.as_u64();
        let old_hi = old_lo
            .checked_add(old_len)
            .filter(|end| *end <= Self::USER_HALF_END)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let huge = self.huge_regions.lock();
        if huge.iter().any(|region| {
            let rb = region.base.as_u64();
            let re = rb.saturating_add(region.len);
            rb < old_hi && old_lo < re
        }) {
            return Err(AddressSpaceError::NotImplemented);
        }
        let regions = self.regions.lock();
        if regions.swap_pages.range(old_lo..old_hi).next().is_some() {
            return Err(AddressSpaceError::NotImplemented);
        }
        let source = regions
            .containing(old_lo)
            .ok_or(AddressSpaceError::Unmapped)?;
        if old_hi > source.base.as_u64().saturating_add(source.len) {
            return Err(AddressSpaceError::NotImplemented);
        }
        if !source.perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        if source.perms.contains(RegionPerms::STACK_SEGMENT)
            || source.perms.contains(RegionPerms::STACK_GUARD)
        {
            return Err(AddressSpaceError::NotImplemented);
        }
        if new_len > old_len {
            if source.perms.contains(RegionPerms::LOCK_EXEMPT)
                && !source.perms.contains(RegionPerms::FILE_DEMAND)
            {
                return Err(AddressSpaceError::Unmapped);
            }
            Self::check_mremap_growth_limits_locked(
                &regions,
                &huge,
                source.perms,
                new_len - old_len,
                limits,
            )?;
        }
        Ok(())
    }

    /// Fixed-target shared relocation. Source eligibility and growth limits
    /// are admitted before the destructive target punch. A shrinking move then
    /// truncates the source before attempting the move, matching Linux's
    /// `mremap_to()` ordering. Later failures report both committed topology
    /// changes so upper file/SysV ownership can match memory exactly.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] followed by
    /// [`with_shared_mapping_transaction`] and uphold the live-root contract.
    pub unsafe fn relocate_shared_region_fixed_locked_limited(
        &self,
        old_base: VirtAddr,
        old_len: u64,
        new_base: VirtAddr,
        new_len: u64,
        limits: MremapLimits,
        shared_transaction_held: bool,
    ) -> Result<Option<(u64, u64)>, FixedRelocationError> {
        let early = |error| FixedRelocationError {
            error,
            target_punched: false,
            source_shrunk: false,
        };
        Self::relocation_bounds(old_base, old_len, new_base, new_len).map_err(early)?;
        if !shared_transaction_held {
            return Err(early(AddressSpaceError::SharedMapping));
        }
        self.check_shared_relocation_source_and_limits_locked(old_base, old_len, new_len, limits)
            .map_err(early)?;
        self.punch_fixed_locked_with_shared_reserving(new_base, new_len, true, 2)
            .map_err(early)?;
        let mut source_shrunk = false;
        let move_old_len = if old_len > new_len {
            let tail_base = VirtAddr::new(old_base.as_u64() + new_len);
            self.punch_fixed_locked_with_shared_reserving(tail_base, old_len - new_len, true, 1)
                .map_err(|error| FixedRelocationError {
                    error,
                    target_punched: true,
                    source_shrunk: false,
                })?;
            source_shrunk = true;

            #[cfg(feature = "kernel-test")]
            if FAIL_FIXED_RELOCATION_AFTER_SHRINK.swap(false, core::sync::atomic::Ordering::AcqRel)
            {
                return Err(FixedRelocationError {
                    error: AddressSpaceError::AllocationFailed,
                    target_punched: true,
                    source_shrunk: true,
                });
            }
            new_len
        } else {
            old_len
        };
        // SAFETY: caller's VMA/shared/root contracts are forwarded. The
        // pre-punch admission remains authoritative while the VMA transaction
        // is held, so it must not be recomputed against the smaller mapping.
        unsafe {
            self.relocate_shared_region_locked_limited(
                old_base,
                move_old_len,
                new_base,
                new_len,
                MremapLimits::UNLIMITED,
            )
        }
        .map_err(|error| FixedRelocationError {
            error,
            target_punched: true,
            source_shrunk,
        })
    }

    /// Transaction-acquiring counterpart of
    /// [`Self::relocate_shared_region_fixed_locked_limited`].
    ///
    /// # Safety
    /// Same live-root contract as [`Self::relocate_region`].
    pub unsafe fn relocate_shared_region_fixed_limited(
        &self,
        old_base: VirtAddr,
        old_len: u64,
        new_base: VirtAddr,
        new_len: u64,
        limits: MremapLimits,
    ) -> Result<(), FixedRelocationError> {
        let eager_range = {
            let _vma_guard = self.vma_transaction.lock();
            let _shared_guard = SHARED_MAPPING_TRANSACTION.lock();
            // SAFETY: wrapper supplies both structural transactions and
            // forwards the caller's live-root contract.
            unsafe {
                self.relocate_shared_region_fixed_locked_limited(
                    old_base, old_len, new_base, new_len, limits, true,
                )
            }?
        };
        self.finish_relocation_population(eager_range);
        Ok(())
    }

    /// Move an exact private anonymous VMA's resident backing to a second VMA
    /// while leaving the source range mapped as lazy anonymous memory. This is
    /// Linux `MREMAP_DONTUNMAP`: the old range faults fresh backing (or can be
    /// intercepted by userfaultfd once that facility exists), never aliases
    /// the moved private frames.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] and uphold the live
    /// root contract from [`Self::relocate_region`].
    pub unsafe fn dontunmap_region_locked_limited(
        &self,
        old_base: VirtAddr,
        len: u64,
        new_base: VirtAddr,
        limits: MremapLimits,
    ) -> Result<(), AddressSpaceError> {
        let (old_lo, old_hi, new_lo, new_hi) =
            Self::relocation_bounds(old_base, len, new_base, len)?;
        self.check_dontunmap_source_locked(old_base, len)?;
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
        let source_perms = regions
            .get(old_lo)
            .filter(|region| region.len == len)
            .map(|region| region.perms)
            .ok_or(AddressSpaceError::Unmapped)?;
        if source_perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        if source_perms.contains(RegionPerms::LOCK_EXEMPT)
            || source_perms.contains(RegionPerms::STACK_SEGMENT)
        {
            return Err(AddressSpaceError::NotImplemented);
        }
        // DONTUNMAP retains the old VMA, so AS/DATA charge the complete new
        // mapping. Locked pages move rather than duplicate: the destination
        // retains LOCKED and the source loses it, keeping locked_vm constant.
        Self::check_mremap_growth_limits_locked(
            &regions,
            &huge,
            source_perms,
            len,
            MremapLimits {
                bypass_memlock: true,
                ..limits
            },
        )?;
        if regions.has_overlap(new_lo, new_hi) {
            return Err(AddressSpaceError::Overlap);
        }
        let pages = usize::try_from(len >> 12).map_err(|_| AddressSpaceError::AllocationFailed)?;
        let mut lazy_source = Vec::new();
        lazy_source
            .try_reserve_exact(pages)
            .map_err(|_| AddressSpaceError::AllocationFailed)?;
        lazy_source.resize(pages, PhysAddr::new(0));

        // DONTUNMAP changes the source backing in place below. Prepare the
        // destination node first so index ENOMEM leaves both VMAs untouched.
        // A fixed wrapper preserves this slot across target retirement.
        regions.try_reserve_nodes(1)?;

        let source = regions
            .get_mut(old_lo)
            .expect("DONTUNMAP source disappeared under region lock");
        let moved_phys = core::mem::replace(&mut source.phys, lazy_source);
        let mut moved = Region {
            base: new_base,
            len,
            perms: source_perms,
            phys: moved_phys,
        };
        if self.root.as_u64() != 0 {
            // SAFETY: the destination is validated free and the address space
            // owns the live root. Restore source metadata on the only fallible
            // page-table step.
            if let Err(error) = unsafe { self.install_region_leaves_local(&moved) } {
                // SAFETY: remove only a partial destination installed above.
                unsafe { self.unmap_region_leaves_local(&moved) };
                regions
                    .get_mut(old_lo)
                    .expect("DONTUNMAP rollback source disappeared")
                    .phys = core::mem::take(&mut moved.phys);
                drop(regions);
                drop(huge);
                // x86 leaf removal above is deliberately local so normal
                // teardown can batch shootdowns. Rollback is returning now,
                // so invalidate every temporary destination translation
                // before a CLONE_VM peer can retain a stale alias.
                self.flush_region_broadcast(new_base, len >> 12);
                return Err(error);
            }
            let old_view = Region {
                base: old_base,
                len,
                perms: source_perms,
                phys: Vec::new(),
            };
            // SAFETY: old_view names exactly the source leaves; backing stays
            // owned by `moved` throughout the transition.
            unsafe { self.unmap_region_leaves_local(&old_view) };
            for (index, &phys) in moved.phys.iter().enumerate() {
                if phys.raw() == 0 {
                    continue;
                }
                let old_va = VirtAddr::new(old_lo + index as u64 * 4096);
                let new_va = VirtAddr::new(new_lo + index as u64 * 4096);
                let moved_owner = crate::rmap::move_owner(phys, self.root, old_va, new_va);
                assert!(
                    moved_owner || source_perms.prot_only().0 == 0,
                    "mapped DONTUNMAP source missing from reverse map"
                );
            }
        }
        let source = regions
            .get_mut(old_lo)
            .expect("DONTUNMAP source disappeared before publication");
        source.perms = RegionPerms(
            source.perms.0
                & !(RegionPerms::LOCKED.0 | RegionPerms::LOCK_ONFAULT.0 | RegionPerms::COW.0),
        );
        regions.invalidate_mapping(old_lo);
        assert!(regions.insert_reserved(moved).is_none());
        drop(regions);
        drop(huge);
        self.flush_region_broadcast(old_base, len >> 12);
        self.flush_region_broadcast(new_base, len >> 12);
        self.bump_mmap_cursor_past(new_lo, len);
        Ok(())
    }

    /// Apply non-fixed DONTUNMAP using Linux's fifth argument as a preferred
    /// address. An occupied hint falls back to the monotonic mmap arena. The
    /// arena cursor advances only when publication succeeds, so allocation or
    /// resource-limit failures cannot consume virtual address space.
    ///
    /// # Safety
    /// Same VMA-transaction/live-root contract as
    /// [`Self::dontunmap_region_locked_limited`].
    pub unsafe fn dontunmap_region_hint_locked_limited(
        &self,
        old_base: VirtAddr,
        len: u64,
        hint: Option<VirtAddr>,
        limits: MremapLimits,
    ) -> Result<VirtAddr, AddressSpaceError> {
        if let Some(preferred) = hint {
            // SAFETY: the caller provides the transaction/root contract.
            match unsafe { self.dontunmap_region_locked_limited(old_base, len, preferred, limits) }
            {
                Ok(()) => return Ok(preferred),
                Err(AddressSpaceError::Overlap) => {}
                Err(error) => return Err(error),
            }
        }
        // SAFETY: this API requires the same caller-held VMA transaction as
        // the cursor candidate helper.
        let destination = unsafe { self.mmap_cursor_candidate_locked(len) }?;
        // SAFETY: the monotonic cursor is kept past every VMA in its arena;
        // the caller's VMA transaction prevents a concurrent publication in
        // this address space before the operation bumps the cursor on success.
        unsafe { self.dontunmap_region_locked_limited(old_base, len, destination, limits) }?;
        Ok(destination)
    }

    /// Validate DONTUNMAP source properties that Linux checks before a fixed
    /// target is retired. Resource-limit admission is deliberately excluded:
    /// Linux performs that after the fixed punch and can therefore return
    /// ENOMEM with the target already gone.
    fn check_dontunmap_source_locked(
        &self,
        old_base: VirtAddr,
        len: u64,
    ) -> Result<(), AddressSpaceError> {
        let old_lo = old_base.as_u64();
        let old_hi = old_lo
            .checked_add(len)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let regions = self.regions.lock();
        if regions.swap_pages.range(old_lo..old_hi).next().is_some() {
            return Err(AddressSpaceError::NotImplemented);
        }
        let source_perms = regions
            .get(old_lo)
            .filter(|region| region.len == len)
            .map(|region| region.perms)
            .ok_or(AddressSpaceError::Unmapped)?;
        if source_perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        if source_perms.contains(RegionPerms::LOCK_EXEMPT)
            || source_perms.contains(RegionPerms::STACK_SEGMENT)
        {
            return Err(AddressSpaceError::NotImplemented);
        }
        if self.root.as_u64() != 0 && source_perms.prot_only().0 != 0 {
            let source = regions
                .get(old_lo)
                .expect("validated DONTUNMAP source disappeared under region lock");
            for (index, &phys) in source.phys.iter().enumerate() {
                if phys.raw() == 0 {
                    continue;
                }
                let va = VirtAddr::new(old_lo + index as u64 * 4096);
                #[cfg(target_arch = "x86_64")]
                // SAFETY: the caller's live-root contract and VMA transaction
                // keep this source leaf stable for the eligibility check.
                let mapped = unsafe { crate::x86_64::paging::translate(self.root, va) };
                #[cfg(target_arch = "aarch64")]
                // SAFETY: same live-root/source-transaction proof as x86_64.
                let mapped = unsafe { crate::aarch64::paging::translate(self.root, va) };
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                let mapped = Some(phys);
                if mapped != Some(phys) || !crate::rmap::contains_owner(phys, self.root, va) {
                    return Err(AddressSpaceError::NotImplemented);
                }
            }
        }
        Ok(())
    }

    /// Fixed-target wrapper for [`Self::dontunmap_region_locked_limited`].
    /// Linux retires the fixed target before DONTUNMAP's full-length AS/DATA
    /// admission, so every later failure reports the destructive state.
    ///
    /// # Safety
    /// Same transaction/shared-target/live-root contract as
    /// [`Self::relocate_region_fixed_locked_limited`].
    pub unsafe fn dontunmap_region_fixed_locked_limited(
        &self,
        old_base: VirtAddr,
        len: u64,
        new_base: VirtAddr,
        limits: MremapLimits,
        shared_transaction_held: bool,
    ) -> Result<(), FixedRelocationError> {
        let early = |error| FixedRelocationError {
            error,
            target_punched: false,
            source_shrunk: false,
        };
        Self::relocation_bounds(old_base, len, new_base, len).map_err(early)?;
        self.check_dontunmap_source_locked(old_base, len)
            .map_err(early)?;
        self.punch_fixed_locked_with_shared_reserving(new_base, len, shared_transaction_held, 1)
            .map_err(early)?;
        // SAFETY: caller's transaction/root contract is forwarded; limits
        // are intentionally admitted after the target punch.
        unsafe { self.dontunmap_region_locked_limited(old_base, len, new_base, limits) }.map_err(
            |error| FixedRelocationError {
                error,
                target_punched: true,
                source_shrunk: false,
            },
        )
    }

    /// Create a second base-page VMA over one interval of an existing SHARED
    /// region. Source backing remains installed and every non-zero backing slot
    /// receives exactly one additional external-owner retain for the new VMA.
    /// `Duplicate` clones each resident source leaf/rmap owner; `DontUnmap`
    /// moves each resident leaf/rmap owner to the destination and leaves the
    /// source translation absent until its normal shared-backing refault.
    ///
    /// The interval may begin inside a Region but must remain wholly within
    /// that one Region. File/SysV ownership above the memory crate must be
    /// cloned in the same outer transaction before faults may observe lazy
    /// `FILE_DEMAND` slots at the destination.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] followed by
    /// [`with_shared_mapping_transaction`], and `self.root` must satisfy the
    /// live-root contract from [`Self::relocate_region`].
    pub unsafe fn alias_shared_region_locked_limited(
        &self,
        source: VirtAddr,
        len: u64,
        destination: VirtAddr,
        mode: SharedMremapMode,
        limits: MremapLimits,
    ) -> Result<Option<(u64, u64)>, AddressSpaceError> {
        let (source_lo, source_hi, destination_lo, destination_hi) =
            Self::relocation_bounds(source, len, destination, len)?;

        // Keep the established huge -> regular order through validation,
        // destination leaf installation, lifetime retention, and publication.
        // The caller's VMA/shared transactions exclude topology and external
        // backing changes while these IRQ-safe table locks are held.
        let huge = self.huge_regions.lock();
        if huge.iter().any(|region| {
            let rb = region.base.as_u64();
            let re = rb.saturating_add(region.len);
            rb < destination_hi && destination_lo < re
        }) {
            return Err(AddressSpaceError::Overlap);
        }
        let mut regions = self.regions.lock();
        if regions
            .swap_pages
            .range(source_lo..source_hi)
            .next()
            .is_some()
        {
            return Err(AddressSpaceError::NotImplemented);
        }
        let source_region = regions
            .containing(source_lo)
            .filter(|region| source_hi <= region.base.as_u64().saturating_add(region.len))
            .ok_or(AddressSpaceError::Unmapped)?;
        let source_region_base = source_region.base.as_u64();
        let source_perms = source_region.perms;
        if !source_perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        if (mode == SharedMremapMode::DontUnmap
            && source_perms.contains(RegionPerms::LOCK_EXEMPT)
            && !source_perms.contains(RegionPerms::FILE_DEMAND))
            || source_perms.contains(RegionPerms::STACK_SEGMENT)
            || source_perms.contains(RegionPerms::STACK_GUARD)
        {
            return Err(AddressSpaceError::NotImplemented);
        }

        // old_len==0 duplication is ordinary locked growth: MEMLOCK precedes
        // AS/DATA. DONTUNMAP moves the lock contract to the destination, so it
        // deliberately bypasses MEMLOCK while charging the complete new VMA.
        let admitted_limits = match mode {
            SharedMremapMode::Duplicate => limits,
            SharedMremapMode::DontUnmap => MremapLimits {
                bypass_memlock: true,
                ..limits
            },
        };
        Self::check_mremap_growth_limits_locked(
            &regions,
            &huge,
            source_perms,
            len,
            admitted_limits,
        )?;
        if regions.has_overlap(destination_lo, destination_hi) {
            return Err(AddressSpaceError::Overlap);
        }

        let first = usize::try_from((source_lo - source_region_base) >> 12)
            .map_err(|_| AddressSpaceError::AllocationFailed)?;
        let pages = usize::try_from(len >> 12).map_err(|_| AddressSpaceError::AllocationFailed)?;
        let source_phys = source_region
            .phys
            .get(first..first.saturating_add(pages))
            .ok_or(AddressSpaceError::Unmapped)?;
        let mut alias_phys = Vec::new();
        alias_phys
            .try_reserve_exact(pages)
            .map_err(|_| AddressSpaceError::AllocationFailed)?;
        alias_phys.extend_from_slice(source_phys);
        let alias = Region {
            base: destination,
            len,
            perms: source_perms,
            phys: alias_phys,
        };

        let tracks_resident_leaves = self.root.as_u64() != 0 && source_perms.prot_only().0 != 0;
        let mut leaf_phys = Vec::new();
        let mut reserved_phys = Vec::new();
        if tracks_resident_leaves {
            leaf_phys
                .try_reserve_exact(pages)
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            if mode == SharedMremapMode::Duplicate {
                reserved_phys
                    .try_reserve_exact(pages)
                    .map_err(|_| AddressSpaceError::AllocationFailed)?;
            }
            for (index, &phys) in alias.phys.iter().enumerate() {
                if phys.raw() == 0 {
                    leaf_phys.push(PhysAddr::new(0));
                    continue;
                }
                let source_va = VirtAddr::new(source_lo + index as u64 * 4096);
                #[cfg(target_arch = "x86_64")]
                // SAFETY: caller's live-root contract and both structural
                // transactions keep this source leaf stable through commit.
                let mapped = unsafe { crate::x86_64::paging::translate(self.root, source_va) };
                #[cfg(target_arch = "aarch64")]
                // SAFETY: same live-root/source-transaction proof as x86_64.
                let mapped = unsafe { crate::aarch64::paging::translate(self.root, source_va) };
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                let mapped = Some(phys);
                match mapped {
                    Some(mapped) => {
                        if mapped != phys
                            || !crate::rmap::contains_owner(phys, self.root, source_va)
                        {
                            return Err(AddressSpaceError::NotImplemented);
                        }
                        leaf_phys.push(phys);
                        if mode == SharedMremapMode::Duplicate {
                            reserved_phys.push(phys);
                        }
                    }
                    None => leaf_phys.push(PhysAddr::new(0)),
                }
            }
            if mode == SharedMremapMode::Duplicate {
                reserve_rmap_alias_slots(&mut reserved_phys)
                    .map_err(|_| AddressSpaceError::AllocationFailed)?;
            }
        }

        let leaf_view = Region {
            base: destination,
            len,
            perms: source_perms,
            phys: leaf_phys,
        };

        regions.try_reserve_nodes(1)?;

        // Allocate and publish both VMA-tree nodes before changing a PTE. The
        // region lock keeps the provisional destination invisible; rollback
        // removes it without releasing backing because no retain exists yet.
        assert!(regions.insert_reserved(alias).is_none());

        if self.root.as_u64() != 0 {
            // The source remains authoritative and unchanged until this sole
            // fallible page-table step has completed. A partial install owns no
            // rmap or external retain yet, so clearing the destination and its
            // provisional VMA is a complete rollback.
            // SAFETY: destination is a validated free user range and the caller
            // provides the live-root contract.
            let install_result = unsafe { self.install_region_leaves_local(&leaf_view) };
            if let Err(error) = install_result {
                let _alias = regions
                    .remove(destination_lo)
                    .expect("failed shared alias lost its provisional VMA");
                // SAFETY: removes only leaves installed into the validated
                // destination by the failed operation above.
                unsafe { self.unmap_region_leaves_local(&leaf_view) };
                release_rmap_alias_reservations(&reserved_phys);
                drop(regions);
                drop(huge);
                self.flush_region_broadcast(destination, len >> 12);
                return Err(error);
            }

            #[cfg(feature = "kernel-test")]
            if FAIL_SHARED_ALIAS_AFTER_INSTALL.swap(false, core::sync::atomic::Ordering::AcqRel) {
                let _alias = regions
                    .remove(destination_lo)
                    .expect("injected shared alias failure lost its provisional VMA");
                // SAFETY: the injection runs immediately after successful
                // installation and before any rmap/retain/source mutation.
                unsafe { self.unmap_region_leaves_local(&leaf_view) };
                release_rmap_alias_reservations(&reserved_phys);
                drop(regions);
                drop(huge);
                self.flush_region_broadcast(destination, len >> 12);
                return Err(AddressSpaceError::AllocationFailed);
            }

            if tracks_resident_leaves {
                match mode {
                    SharedMremapMode::Duplicate => {
                        for (index, &phys) in leaf_view.phys.iter().enumerate() {
                            if phys.raw() != 0 {
                                crate::rmap::add_reserved(
                                    phys,
                                    self.root,
                                    VirtAddr::new(destination_lo + index as u64 * 4096),
                                );
                            }
                        }
                    }
                    SharedMremapMode::DontUnmap => {
                        let source_view = Region {
                            base: source,
                            len,
                            perms: source_perms,
                            phys: Vec::new(),
                        };
                        // SAFETY: source_view names exactly the validated
                        // source interval. Its backing remains owned by the
                        // source Region and the newly retained alias.
                        unsafe { self.unmap_region_leaves_local(&source_view) };
                        for (index, &phys) in leaf_view.phys.iter().enumerate() {
                            if phys.raw() == 0 {
                                continue;
                            }
                            let old_va = VirtAddr::new(source_lo + index as u64 * 4096);
                            let new_va = VirtAddr::new(destination_lo + index as u64 * 4096);
                            assert!(
                                crate::rmap::move_owner(phys, self.root, old_va, new_va),
                                "resident shared DONTUNMAP source missing rmap owner"
                            );
                        }
                    }
                }
            }
        }

        // No fallible work follows this retain. It is therefore impossible to
        // expose an extra external hold without the corresponding VMA, or a VMA
        // without its hold. Region teardown performs the exact inverse once.
        retain_shared_frames(
            regions
                .get(destination_lo)
                .expect("committed shared alias lost its VMA"),
        );
        if mode == SharedMremapMode::DontUnmap {
            let source_region = regions
                .get_mut(source_region_base)
                .expect("shared mremap source disappeared under region lock");
            source_region.perms.0 &= !(RegionPerms::LOCKED.0 | RegionPerms::LOCK_ONFAULT.0);
            regions.invalidate_mapping(source_region_base);
        }
        drop(regions);
        drop(huge);

        if mode == SharedMremapMode::DontUnmap {
            self.flush_region_broadcast(source, len >> 12);
        }
        self.flush_region_broadcast(destination, len >> 12);
        self.bump_mmap_cursor_past(destination_lo, len);
        let eager = source_perms.contains(RegionPerms::LOCKED)
            && !source_perms.contains(RegionPerms::LOCK_ONFAULT)
            && !source_perms.contains(RegionPerms::LOCK_EXEMPT)
            && source_perms.prot_only().0 != 0;
        Ok(eager.then_some((destination_lo, destination_hi)))
    }

    /// Create a non-fixed shared alias using `hint` as a preferred address and
    /// the current mmap cursor as the fallback/default. Neither path reserves
    /// virtual address space up front: the cursor advances only after the VMA,
    /// PTEs, rmap owners, and backing retains have committed successfully.
    ///
    /// Returns the selected destination and any eager locked-population range;
    /// the caller must finish that range after releasing both transactions.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] followed by
    /// [`with_shared_mapping_transaction`] and uphold the live-root contract.
    pub unsafe fn alias_shared_region_hint_locked_limited(
        &self,
        source: VirtAddr,
        len: u64,
        hint: Option<VirtAddr>,
        mode: SharedMremapMode,
        limits: MremapLimits,
    ) -> Result<(VirtAddr, Option<(u64, u64)>), AddressSpaceError> {
        if let Some(preferred) = hint {
            // SAFETY: caller supplies both structural transactions and the
            // live-root contract.
            match unsafe {
                self.alias_shared_region_locked_limited(source, len, preferred, mode, limits)
            } {
                Ok(eager) => return Ok((preferred, eager)),
                Err(AddressSpaceError::Overlap) => {}
                Err(error) => return Err(error),
            }
        }

        let candidate = self.mmap_cursor.load(core::sync::atomic::Ordering::Relaxed);
        let end = candidate
            .checked_add(len)
            .filter(|end| *end <= Self::MMAP_WINDOW_TOP)
            .ok_or(AddressSpaceError::MappingLimit)?;
        debug_assert!(end > candidate);
        let destination = VirtAddr::new(candidate);
        // SAFETY: the cursor remains beyond every VMA in its arena, and the
        // caller-held VMA transaction excludes publication before this call
        // either commits and bumps the cursor or returns without consuming it.
        let eager = unsafe {
            self.alias_shared_region_locked_limited(source, len, destination, mode, limits)
        }?;
        Ok((destination, eager))
    }

    /// Acquire the VMA/shared-owner transactions around
    /// [`Self::alias_shared_region_locked_limited`] and finish any eager locked
    /// population after releasing both IRQ-safe locks.
    ///
    /// # Safety
    /// Same live-root contract as [`Self::relocate_region`].
    pub unsafe fn alias_shared_region_limited(
        &self,
        source: VirtAddr,
        len: u64,
        destination: VirtAddr,
        mode: SharedMremapMode,
        limits: MremapLimits,
    ) -> Result<(), AddressSpaceError> {
        let eager_range = {
            let _vma_guard = self.vma_transaction.lock();
            let _shared_guard = SHARED_MAPPING_TRANSACTION.lock();
            // SAFETY: this wrapper supplies both required transactions and
            // forwards the caller's live-root contract.
            unsafe {
                self.alias_shared_region_locked_limited(source, len, destination, mode, limits)
            }?
        };
        self.finish_relocation_population(eager_range);
        Ok(())
    }

    /// Fixed-target shared alias transaction. Source eligibility always
    /// precedes target retirement. `Duplicate` also performs MEMLOCK/AS/DATA
    /// admission before the punch; `DontUnmap` performs full-length AS/DATA
    /// admission afterwards, matching Linux `mremap_to()`.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] followed by
    /// [`with_shared_mapping_transaction`] and uphold the live-root contract.
    pub unsafe fn alias_shared_region_fixed_locked_limited(
        &self,
        source: VirtAddr,
        len: u64,
        destination: VirtAddr,
        mode: SharedMremapMode,
        limits: MremapLimits,
        shared_transaction_held: bool,
    ) -> Result<Option<(u64, u64)>, FixedRelocationError> {
        let early = |error| FixedRelocationError {
            error,
            target_punched: false,
            source_shrunk: false,
        };
        Self::relocation_bounds(source, len, destination, len).map_err(early)?;
        if !shared_transaction_held {
            return Err(early(AddressSpaceError::SharedMapping));
        }
        self.check_shared_mremap_source_locked(source, len, mode)
            .map_err(early)?;
        if mode == SharedMremapMode::Duplicate {
            self.check_shared_mremap_limits_locked(source, len, mode, limits)
                .map_err(early)?;
        }
        self.punch_fixed_locked_with_shared_reserving(destination, len, true, 1)
            .map_err(early)?;
        let post_punch_limits = if mode == SharedMremapMode::Duplicate {
            MremapLimits::UNLIMITED
        } else {
            limits
        };
        // SAFETY: caller's VMA/shared/root contracts are forwarded. Every
        // failure from this point observes the already-retired target.
        unsafe {
            self.alias_shared_region_locked_limited(
                source,
                len,
                destination,
                mode,
                post_punch_limits,
            )
        }
        .map_err(|error| FixedRelocationError {
            error,
            target_punched: true,
            source_shrunk: false,
        })
    }

    /// Transaction-acquiring counterpart of
    /// [`Self::alias_shared_region_fixed_locked_limited`].
    ///
    /// # Safety
    /// Same live-root contract as [`Self::relocate_region`].
    pub unsafe fn alias_shared_region_fixed_limited(
        &self,
        source: VirtAddr,
        len: u64,
        destination: VirtAddr,
        mode: SharedMremapMode,
        limits: MremapLimits,
    ) -> Result<(), FixedRelocationError> {
        let eager_range = {
            let _vma_guard = self.vma_transaction.lock();
            let _shared_guard = SHARED_MAPPING_TRANSACTION.lock();
            // SAFETY: this wrapper supplies both required transactions and
            // forwards the caller's live-root contract.
            unsafe {
                self.alias_shared_region_fixed_locked_limited(
                    source,
                    len,
                    destination,
                    mode,
                    limits,
                    true,
                )
            }?
        };
        self.finish_relocation_population(eager_range);
        Ok(())
    }

    fn check_shared_mremap_source_locked(
        &self,
        source: VirtAddr,
        len: u64,
        mode: SharedMremapMode,
    ) -> Result<RegionPerms, AddressSpaceError> {
        let source_lo = source.as_u64();
        if source_lo & 0xFFF != 0 || len == 0 || len & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        let source_hi = source_lo
            .checked_add(len)
            .filter(|end| *end <= Self::USER_HALF_END)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let regions = self.regions.lock();
        if regions
            .swap_pages
            .range(source_lo..source_hi)
            .next()
            .is_some()
        {
            return Err(AddressSpaceError::NotImplemented);
        }
        let source = regions
            .containing(source_lo)
            .filter(|region| source_hi <= region.base.as_u64().saturating_add(region.len))
            .ok_or(AddressSpaceError::Unmapped)?;
        if !source.perms.contains(RegionPerms::SHARED) {
            return Err(AddressSpaceError::SharedMapping);
        }
        if (mode == SharedMremapMode::DontUnmap
            && source.perms.contains(RegionPerms::LOCK_EXEMPT)
            && !source.perms.contains(RegionPerms::FILE_DEMAND))
            || source.perms.contains(RegionPerms::STACK_SEGMENT)
            || source.perms.contains(RegionPerms::STACK_GUARD)
        {
            return Err(AddressSpaceError::NotImplemented);
        }
        Ok(source.perms)
    }

    fn check_shared_mremap_limits_locked(
        &self,
        source: VirtAddr,
        len: u64,
        mode: SharedMremapMode,
        limits: MremapLimits,
    ) -> Result<(), AddressSpaceError> {
        let source_perms = self.check_shared_mremap_source_locked(source, len, mode)?;
        let huge = self.huge_regions.lock();
        let regions = self.regions.lock();
        let admitted_limits = match mode {
            SharedMremapMode::Duplicate => limits,
            SharedMremapMode::DontUnmap => MremapLimits {
                bypass_memlock: true,
                ..limits
            },
        };
        Self::check_mremap_growth_limits_locked(&regions, &huge, source_perms, len, admitted_limits)
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
        let _vma_guard = self.vma_transaction.lock();
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
        let _vma_guard = self.vma_transaction.lock();
        self.punch_fixed_locked(base, len)
    }

    /// [`Self::punch_fixed`] with the per-AS VMA transaction already held.
    fn punch_fixed_locked(&self, base: VirtAddr, len: u64) -> Result<(), AddressSpaceError> {
        self.punch_fixed_locked_with_shared(base, len, false)
    }

    /// Transaction-held MAP_FIXED punch used by syscall operations which must
    /// update external ownership before releasing the VMA transaction.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`].
    pub unsafe fn punch_fixed_locked_for_syscall(
        &self,
        base: VirtAddr,
        len: u64,
    ) -> Result<(), AddressSpaceError> {
        self.punch_fixed_locked(base, len)
    }

    /// Shared-aware syscall punch with both the VMA and shared-owner
    /// transactions already held in that order.
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`] and, when
    /// `shared_transaction_held` is true, [`with_shared_mapping_transaction`].
    pub unsafe fn punch_fixed_locked_for_syscall_with_shared(
        &self,
        base: VirtAddr,
        len: u64,
        shared_transaction_held: bool,
    ) -> Result<(), AddressSpaceError> {
        self.punch_fixed_locked_with_shared(base, len, shared_transaction_held)
    }

    /// MAP_FIXED punch with the VMA transaction held and, when
    /// `shared_transaction_held` is true, the shared-owner transaction held
    /// after it. This form lets a shared replacement keep its backing
    /// snapshot, target retirement, and alias publication in one lock order.
    fn punch_fixed_locked_with_shared(
        &self,
        base: VirtAddr,
        len: u64,
        shared_transaction_held: bool,
    ) -> Result<(), AddressSpaceError> {
        self.punch_fixed_locked_with_shared_reserving(base, len, shared_transaction_held, 0)
    }

    /// Punch while preserving allocation-free capacity for a caller's later
    /// VMA publications in the same outer VMA transaction.
    fn punch_fixed_locked_with_shared_reserving(
        &self,
        base: VirtAddr,
        len: u64,
        shared_transaction_held: bool,
        preserve_nodes: usize,
    ) -> Result<(), AddressSpaceError> {
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
        let _shared_transaction = if shared && !shared_transaction_held {
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
        if huge.iter().any(|region| {
            let rb = region.base.as_u64();
            let re = rb + region.len;
            let overlaps = re > lo && rb < hi;
            overlaps && !(lo <= rb && hi >= re)
        }) {
            return Err(AddressSpaceError::AlignmentMismatch);
        }

        // Build the complete proportional scratch plan before retiring a huge
        // leaf, removing a VMA, or touching a PTE. GlobalAlloc cannot recover
        // synchronously and an infallible Vec growth while these IRQ-safe locks
        // are held would abort the kernel after a partially destructive punch.
        // Every push in the commit phase below is covered by one of these exact
        // reservations, while every retained prefix/suffix already owns its
        // fallibly-cloned backing.
        let removed_huge_count = huge
            .iter()
            .filter(|region| {
                let rb = region.base.as_u64();
                let re = rb + region.len;
                re > lo && rb < hi
            })
            .count();
        let mut overlap_count = 0usize;
        regions.for_each_overlapping(lo, hi, |_| overlap_count += 1);
        if removed_huge_count == 0 && overlap_count == 0 {
            drop(regions);
            drop(huge);
            return Ok(());
        }

        let mut removed_huge = Vec::new();
        removed_huge
            .try_reserve_exact(removed_huge_count)
            .map_err(|_| AddressSpaceError::AllocationFailed)?;
        let mut kept_huge = Vec::new();
        if removed_huge_count != 0 {
            kept_huge
                .try_reserve_exact(huge.len() - removed_huge_count)
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
        }

        let mut overlap_keys = Vec::new();
        overlap_keys
            .try_reserve_exact(overlap_count)
            .map_err(|_| AddressSpaceError::AllocationFailed)?;
        regions.for_each_overlapping(lo, hi, |region| {
            overlap_keys.push(region.base.as_u64());
        });

        let mut replacement_count = 0usize;
        let mut private_release_count = 0usize;
        let mut shared_release_count = 0usize;
        let mut punched_pages = 0u64;
        for &key in &overlap_keys {
            let old = regions
                .get(key)
                .expect("preflight overlap key disappeared under region lock");
            let rb = old.base.as_u64();
            let re = rb + old.len;
            replacement_count = replacement_count
                .checked_add(usize::from(rb < lo) + usize::from(re > hi))
                .ok_or(AddressSpaceError::AllocationFailed)?;
            let total = (old.len >> 12) as usize;
            let first = ((lo.max(rb) - rb) >> 12) as usize;
            let last = (((hi.min(re) - rb) >> 12) as usize).min(total);
            punched_pages = punched_pages
                .checked_add((last - first) as u64)
                .ok_or(AddressSpaceError::OutOfRange)?;
            // A demand-paged BRK_HEAP region carries a phys list SHORTER than its
            // page count; pages past the materialized prefix are demand-zero with
            // no frame. Clamp the range to the materialized prefix — the rest have
            // nothing to release.
            let p_last = last.min(old.phys.len());
            let p_first = first.min(p_last);
            let resident = old.phys[p_first..p_last]
                .iter()
                .filter(|phys| phys.raw() != 0)
                .count();
            if old.perms.contains(RegionPerms::SHARED) {
                shared_release_count = shared_release_count
                    .checked_add(resident)
                    .ok_or(AddressSpaceError::AllocationFailed)?;
            } else {
                private_release_count = private_release_count
                    .checked_add(resident)
                    .ok_or(AddressSpaceError::AllocationFailed)?;
            }
        }

        let mut kept_regions = Vec::new();
        kept_regions
            .try_reserve_exact(replacement_count)
            .map_err(|_| AddressSpaceError::AllocationFailed)?;
        let mut to_free: Vec<crate::frame::PhysFrame> = Vec::new();
        to_free
            .try_reserve_exact(private_release_count)
            .map_err(|_| AddressSpaceError::AllocationFailed)?;
        let mut shared_to_release: Vec<PhysAddr> = Vec::new();
        shared_to_release
            .try_reserve_exact(shared_release_count)
            .map_err(|_| AddressSpaceError::AllocationFailed)?;

        // Every preserved prefix/suffix is published only after the original
        // nodes and leaves have been retired. Prepare their arena capacity
        // while the old topology is still authoritative.
        regions.try_reserve_nodes(replacement_count.saturating_add(preserve_nodes))?;

        let copy_backing = |source: &[PhysAddr]| -> Result<Vec<PhysAddr>, AddressSpaceError> {
            let mut backing = Vec::new();
            backing
                .try_reserve_exact(source.len())
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            backing.extend_from_slice(source);
            Ok(backing)
        };
        for &key in &overlap_keys {
            let old = regions
                .get(key)
                .expect("preflight overlap key disappeared under region lock");
            let rb = old.base.as_u64();
            let re = rb + old.len;
            let total = (old.len >> 12) as usize;
            let first = ((lo.max(rb) - rb) >> 12) as usize;
            let last = (((hi.min(re) - rb) >> 12) as usize).min(total);
            // Clamp to the materialized phys prefix — a demand-paged BRK_HEAP
            // region's unmaterialized tail is demand-zero (no frame to release).
            let p_last = last.min(old.phys.len());
            let p_first = first.min(p_last);
            if old.perms.contains(RegionPerms::SHARED) {
                // Retire each punched page's rmap owner before releasing the
                // borrowed frame, exactly as `free_region_frames` does for
                // SHARED regions (rmap::remove runs there before
                // `release_shared_phys`). The frame itself belongs to an
                // external registry and is not returned to the buddy here, but
                // its per-AS (root, va) reverse-map entry must still be dropped —
                // otherwise a later registry free finds a stale owner.
                // Clamp to the materialized phys prefix (like the release
                // `extend`s below): a demand-paged BRK_HEAP region's unmaterialized
                // tail has no frame and no rmap owner to retire, and slicing past
                // its short phys list would panic.
                for (off, phys) in old.phys[p_first..p_last].iter().enumerate() {
                    if phys.raw() != 0 {
                        let va = VirtAddr::new(rb + ((p_first + off) as u64) * 4096);
                        crate::rmap::remove(*phys, self.root, va);
                    }
                }
                shared_to_release.extend(
                    old.phys[p_first..p_last]
                        .iter()
                        .copied()
                        .filter(|phys| phys.raw() != 0),
                );
            } else {
                // Drop each punched page's rmap entry before its frame returns
                // to the buddy, mirroring `free_region_frames`: a MAP_FIXED
                // punch / munmap that frees resident private backing must not
                // leave a stale (root, va) owner on the reclaimed frame (Linux
                // free_pages_prepare's "nonzero mapcount" invariant).
                // Clamp to the materialized phys prefix (like the release
                // `extend`s below): a demand-paged BRK_HEAP region's unmaterialized
                // tail has no frame and no rmap owner to retire, and slicing past
                // its short phys list would panic.
                for (off, phys) in old.phys[p_first..p_last].iter().enumerate() {
                    if phys.raw() != 0 {
                        let va = VirtAddr::new(rb + ((p_first + off) as u64) * 4096);
                        crate::rmap::remove(*phys, self.root, va);
                    }
                }
                to_free.extend(
                    old.phys[p_first..p_last]
                        .iter()
                        .copied()
                        .filter(|phys| phys.raw() != 0)
                        .map(crate::frame::PhysFrame::new),
                );
            }
            if rb < lo {
                let n = ((lo - rb) >> 12) as usize;
                // Kept head keeps its materialized prefix; the region stays
                // demand-paged (its perms — BRK_HEAP for a heap split — permit a
                // short phys list).
                kept_regions.push(Region {
                    base: VirtAddr::new(rb),
                    len: (n as u64) * 4096,
                    perms: old.perms,
                    phys: copy_backing(&old.phys[..n.min(old.phys.len())])?,
                });
            }
            if re > hi {
                let start = ((hi - rb) >> 12) as usize;
                kept_regions.push(Region {
                    base: VirtAddr::new(hi),
                    len: old.len - (start as u64) * 4096,
                    perms: old.perms,
                    phys: copy_backing(&old.phys[start.min(old.phys.len())..])?,
                });
            }
        }

        // Commit the huge-table partition using only the pre-reserved buffers.
        // A base-page-only punch leaves the huge Vec and its allocation alone.
        if removed_huge_count != 0 {
            for region in core::mem::take(&mut *huge) {
                let rb = region.base.as_u64();
                let re = rb + region.len;
                if re <= lo || rb >= hi {
                    kept_huge.push(region);
                } else {
                    removed_huge.push(region);
                }
            }
            *huge = kept_huge;
        }
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
        if overlap_count == 0 {
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
        {
            for key in overlap_keys {
                let old = regions
                    .remove(key)
                    .expect("preflight overlap VMA disappeared under region lock");
                let rb = old.base.as_u64();
                let re = rb + old.len;
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
            }
            for region in kept_regions {
                assert!(regions.insert_reserved(region).is_none());
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
        // Shared owners may return their last frame to an external cache, so
        // release them only after the same remote invalidation that protects
        // private backing reuse. The shared-owner transaction remains held.
        for phys in shared_to_release {
            release_shared_phys(phys);
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
        let root = self.root;
        regions.for_each_mut(|r| {
            if !r.perms.contains(RegionPerms::SHARED) && !r.perms.contains(RegionPerms::LOCKED) {
                let pages = ((r.len + 0xFFF) >> 12) as usize;
                let n = pages.min(r.phys.len());
                // Drop each page's reverse-map entry BEFORE its frame returns to
                // the buddy, exactly as `free_region_frames` does on the ordinary
                // teardown path. Zeroing `phys[i]` below makes the later `Drop`
                // skip these pages, so this is the reaper's only opportunity to
                // retire their rmap owners: omitting it leaked a stale (root, va)
                // onto every reaped frame, which its next allocation inherited —
                // the invariant Linux enforces in `free_pages_prepare` via the
                // "nonzero mapcount" `bad_page` check.
                for (i, p) in r.phys[..n].iter().enumerate() {
                    if p.raw() != 0 {
                        let va = VirtAddr::new(r.base.as_u64() + (i as u64) * 4096);
                        crate::rmap::remove(*p, root, va);
                    }
                }
                crate::frame::free_phys_batch(&r.phys[..n]);
                for p in r.phys[..n].iter_mut() {
                    if p.raw() != 0 {
                        freed += 1;
                        *p = PhysAddr::new(0);
                    }
                }
            }
        });
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
    pub(crate) fn paging_install_error(
        error: crate::x86_64::paging::MapError,
    ) -> AddressSpaceError {
        use crate::x86_64::paging::MapError;

        match error {
            MapError::FrameExhausted => AddressSpaceError::AllocationFailed,
            MapError::NonCanonical => AddressSpaceError::OutOfRange,
            MapError::UnalignedVirt | MapError::UnalignedPhys => {
                AddressSpaceError::AlignmentMismatch
            }
            MapError::AlreadyMapped | MapError::EncounteredHugePage => AddressSpaceError::Overlap,
            // Only `protect_4kb` raises this, and the install path never
            // calls it — a leaf it is about to create cannot already be
            // absent. Mapped for exhaustiveness.
            MapError::NotMapped => AddressSpaceError::Unmapped,
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn paging_install_error(
        error: crate::aarch64::paging::MapError,
    ) -> AddressSpaceError {
        use crate::aarch64::paging::MapError;

        match error {
            MapError::NoFrame => AddressSpaceError::AllocationFailed,
            MapError::NonCanonical => AddressSpaceError::OutOfRange,
            MapError::UnalignedVirt | MapError::UnalignedPhys => {
                AddressSpaceError::AlignmentMismatch
            }
            MapError::AlreadyMapped | MapError::EncounteredBlock => AddressSpaceError::Overlap,
            // See the x86_64 twin: unreachable from the install path.
            MapError::NotMapped => AddressSpaceError::Unmapped,
        }
    }

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
        .map_err(Self::paging_install_error)
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
        .map_err(Self::paging_install_error)
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
    /// Hardware huge leaves are resident for every base-page equivalent.
    /// Ordinary non-PROT_NONE VMAs consult the actual leaf as well as backing
    /// metadata so a retained MREMAP_DONTUNMAP source reports nonresident until
    /// its shared backing faults back in. Any unmapped page rejects the whole
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
                let phys = region.phys[index];
                let va = VirtAddr::new(rb + index as u64 * 4096);
                let resident = if phys.raw() == 0 {
                    false
                } else if self.root.as_u64() == 0 || region.perms.prot_only().0 == 0 {
                    // Metadata-only construction and NARF's PROT_NONE
                    // representation have no leaf to consult.
                    true
                } else {
                    #[cfg(target_arch = "x86_64")]
                    // SAFETY: `self` keeps the root live; the region lock keeps
                    // this VA/backing generation stable during the walk.
                    let mapped = unsafe { crate::x86_64::paging::translate(self.root, va) };
                    #[cfg(target_arch = "aarch64")]
                    // SAFETY: same live-root and stable-region proof as x86_64.
                    let mapped = unsafe { crate::aarch64::paging::translate(self.root, va) };
                    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                    let mapped = Some(phys);
                    mapped == Some(phys)
                };
                state[out] = 0x80 | u8::from(resident);
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
        let mut regions = self.regions.lock();
        let region = regions.containing(v).ok_or(AddressSpaceError::Unmapped)?;
        let rb = region.base.as_u64();
        if region.perms.prot_only().0 == 0 {
            return Err(AddressSpaceError::Unmapped);
        }
        let index = ((v - rb) >> 12) as usize;
        // `containing(v)` proved the page lies in this region, so `index` is a
        // valid page. A demand-paged BRK_HEAP region grows its length without
        // materializing per-page phys slots, so an index past the materialized
        // prefix is simply an unfaulted (demand-zero) page — identical to an
        // in-range `phys[i] == 0`.
        let phys = region.phys.get(index).copied().unwrap_or(PhysAddr::new(0));
        let perms = region.perms;
        if phys.raw() != 0 {
            repair_backed(phys, perms)?;
            return Ok(DemandPageClaim::Resolved);
        }
        if regions.demand_pages.get(v).is_some() {
            return Ok(DemandPageClaim::InProgress);
        }
        let ticket = regions.demand_pages.insert_new(v)?;
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
        if regions.demand_pages.get(v) != Some(ticket) {
            return Ok(false);
        }
        let Some(region) = regions.containing_mut(v) else {
            regions.demand_pages.remove(v);
            return Ok(false);
        };
        let rb = region.base.as_u64();
        let index = ((v - rb) >> 12) as usize;
        // Grow the materialized phys prefix to cover this page for a demand-paged
        // region whose phys list is shorter than its length (BRK_HEAP): a grow
        // only extended the region's length, so the first fault of each page
        // installs its slot here. Intermediate pages fill with demand-zero
        // sentinels, keeping every page independently faultable. Sequential brk
        // touch makes this amortized O(1) per fault.
        if index >= region.phys.len() {
            region.phys.resize(index + 1, PhysAddr::new(0));
        }
        let slot = &mut region.phys[index];
        if slot.raw() != 0 {
            regions.demand_pages.remove(v);
            return Ok(false);
        }
        let perms = region.perms;
        if let Err(error) = install(phys, perms) {
            // The frame is still owned by the fault path. Keep metadata lazy
            // so a later fault can retry, and let the caller release the
            // unpublished frame after this lock is dropped.
            regions.demand_pages.remove(v);
            return Err(error);
        }
        *slot = phys;
        // Publication, reverse-map ownership, and ticket retirement are one
        // region-lock transaction. An overlapping unmap cannot free `phys`
        // between the leaf install and rmap registration.
        crate::rmap::add(phys, self.root, VirtAddr::new(v));
        regions.demand_pages.remove(v);
        Ok(true)
    }

    fn cancel_demand_page(&self, v: u64, ticket: u64) {
        let mut regions = self.regions.lock();
        if regions.demand_pages.get(v) == Some(ticket) {
            regions.demand_pages.remove(v);
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
    /// retry from the trap). Anonymous allocation refused by the protected
    /// user reserve returns `ReclaimPressure` after its ticket is cancelled;
    /// the frame fault path may park and retry it once.
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
                Ok(()) | Err(MapError::AlreadyMapped) => {
                    crate::rmap::add(phys, self.root, va);
                    Ok(())
                }
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
            let reserve_pressure = crate::reclaim::user_alloc_would_breach_reserve();
            let frame = match crate::mempolicy::alloc_frame_policied(crate::frame::local_node()) {
                Ok(frame) => frame,
                Err(_) => {
                    self.cancel_demand_page(v, ticket);
                    return Err(anonymous_demand_alloc_error(
                        reserve_pressure || crate::reclaim::user_alloc_would_breach_reserve(),
                    ));
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

        let published = match self.finish_demand_page(v, ticket, phys, |phys, perms| {
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
                Ok(()) => Ok(()),
                Err(_) => Err(AddressSpaceError::NotImplemented),
            }
        }) {
            Ok(published) => published,
            Err(error) => {
                if file_backed {
                    release_shared_phys(phys);
                } else {
                    crate::frame::free_frame(crate::frame::PhysFrame::new(phys));
                }
                return Err(error);
            }
        };
        if published {
            // The fresh frame, leaf, and reverse map were published together
            // by finish_demand_page while the region lock was held.
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
                Ok(()) | Err(MapError::AlreadyMapped) => {
                    crate::rmap::add(phys, self.root, va);
                    Ok(())
                }
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
            let reserve_pressure = crate::reclaim::user_alloc_would_breach_reserve();
            let frame = match crate::mempolicy::alloc_frame_policied(crate::frame::local_node()) {
                Ok(frame) => frame,
                Err(_) => {
                    self.cancel_demand_page(v, ticket);
                    return Err(anonymous_demand_alloc_error(
                        reserve_pressure || crate::reclaim::user_alloc_would_breach_reserve(),
                    ));
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

        let published = match self.finish_demand_page(v, ticket, phys, |phys, perms| {
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
                Ok(()) => Ok(()),
                Err(_) => Err(AddressSpaceError::NotImplemented),
            }
        }) {
            Ok(published) => published,
            Err(error) => {
                if file_backed {
                    release_shared_phys(phys);
                } else {
                    crate::frame::free_frame(crate::frame::PhysFrame::new(phys));
                }
                return Err(error);
            }
        };
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
    fn stack_growth_plan(
        regions: &RegionTable,
        huge_mapped_bytes: u64,
        v_page: u64,
        limits: StackGrowthLimits,
    ) -> Result<StackGrowthPlan, AddressSpaceError> {
        const MAX_GROW: u64 = 256 * 1024;

        let guard_base = regions
            .containing(v_page)
            .or_else(|| regions.successor(v_page))
            .filter(|region| {
                region.perms.contains(RegionPerms::STACK_GUARD) && {
                    let base = region.base.as_u64();
                    base >= v_page && base - v_page <= MAX_GROW
                }
            })
            .map(|region| region.base.as_u64())
            .ok_or(AddressSpaceError::Unmapped)?;
        let new_guard_base = v_page
            .checked_sub(0x1000)
            .ok_or(AddressSpaceError::OutOfRange)?;

        if guard_base >= Self::MMAP_WINDOW_TOP && new_guard_base < Self::MMAP_WINDOW_TOP {
            return Err(AddressSpaceError::OutOfRange);
        }
        if regions.has_overlap(new_guard_base, guard_base) {
            return Err(AddressSpaceError::Overlap);
        }

        let above_base = guard_base
            .checked_add(0x1000)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let mut grown_perms = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::STACK_SEGMENT;
        if let Some(above) = regions
            .containing(above_base)
            .filter(|above| above.base.as_u64() == above_base)
        {
            grown_perms.0 |= above.perms.0 & RegionPerms::EXEC.0;
            if above.perms.contains(RegionPerms::STACK_SEGMENT) {
                grown_perms.0 |=
                    above.perms.0 & (RegionPerms::LOCKED.0 | RegionPerms::LOCK_ONFAULT.0);
            }
        }

        let npages = guard_base
            .checked_sub(v_page)
            .and_then(|bytes| bytes.checked_div(0x1000))
            .and_then(|pages| pages.checked_add(1))
            .ok_or(AddressSpaceError::OutOfRange)?;
        let growth_bytes = npages
            .checked_mul(0x1000)
            .ok_or(AddressSpaceError::OutOfRange)?;

        let existing_stack_bytes = regions.contiguous_stack_bytes_from(above_base);
        if existing_stack_bytes.saturating_add(growth_bytes) > limits.stack_bytes {
            return Err(AddressSpaceError::StackLimit);
        }
        if regions
            .mapped_bytes()
            .saturating_add(huge_mapped_bytes)
            .saturating_add(growth_bytes)
            > limits.address_space_bytes
        {
            return Err(AddressSpaceError::StackLimit);
        }
        if grown_perms.contains(RegionPerms::LOCKED)
            && !limits.bypass_memlock
            && regions.locked_bytes().saturating_add(growth_bytes) > limits.memlock_bytes
        {
            return Err(AddressSpaceError::LockLimit);
        }

        Ok(StackGrowthPlan {
            v_page,
            guard_base,
            new_guard_base,
            npages,
            grown_perms,
        })
    }

    fn free_stack_frames(frames: Vec<crate::PhysAddr>) {
        for phys in frames {
            crate::frame::free_frame(crate::frame::PhysFrame::new(phys));
        }
    }

    unsafe fn allocate_stack_frames(
        npages: u64,
    ) -> Result<Vec<crate::PhysAddr>, AddressSpaceError> {
        let mut frames = Vec::with_capacity(npages as usize);
        for _ in 0..npages {
            let phys = match crate::frame::alloc_user_frame() {
                Ok(frame) => frame.start_address(),
                Err(_) => {
                    Self::free_stack_frames(frames);
                    return Err(AddressSpaceError::OutOfRange);
                }
            };
            // SAFETY: the fresh user frame is exclusively owned here and the
            // architecture's kernel alias remains valid while a user AS is
            // active.
            unsafe { core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096) };
            frames.push(phys);
        }
        Ok(frames)
    }

    /// Grow a stack without Linux task-specific resource limits.
    ///
    /// # Safety
    /// The low-memory kernel alias and `self.root` must be live, and the frame
    /// allocator must be initialized.
    pub unsafe fn try_grow_stack(&self, vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
        // SAFETY: caller's contract is forwarded with no effective limit for
        // kernel-internal/tests that do not have Linux task credentials.
        unsafe { self.try_grow_stack_limited(vaddr, StackGrowthLimits::UNLIMITED) }
    }

    #[cfg(target_arch = "x86_64")]
    /// Grow a stack after admitting the expansion against Linux task limits.
    ///
    /// # Safety
    /// Same live-root, kernel-alias, and allocator requirements as
    /// [`Self::try_grow_stack`].
    pub unsafe fn try_grow_stack_limited(
        &self,
        vaddr: VirtAddr,
        limits: StackGrowthLimits,
    ) -> Result<(), AddressSpaceError> {
        use crate::x86_64::paging::{map_4kb, unmap_4kb, PtFlags};
        let v_page = vaddr.as_u64() & !0xFFFu64;
        // Preflight under the VMA transaction, then allocate outside every
        // address-space lock. Allocation may reclaim or otherwise take an
        // unbounded path and must not pin an IRQ-safe guard.
        let plan = {
            let _vma_guard = self.vma_transaction.lock();
            let huge = self.huge_regions.lock();
            let regions = self.regions.lock();
            let huge_bytes = huge
                .iter()
                .fold(0u64, |total, region| total.saturating_add(region.len));
            Self::stack_growth_plan(&regions, huge_bytes, v_page, limits)?
        };
        // SAFETY: forwarded frame-allocation and kernel-alias contract.
        let new_phys = unsafe { Self::allocate_stack_frames(plan.npages) }?;
        let mut guard_phys = Vec::new();
        if guard_phys.try_reserve_exact(1).is_err() {
            Self::free_stack_frames(new_phys);
            return Err(AddressSpaceError::AllocationFailed);
        }
        guard_phys.push(crate::PhysAddr::new(0));

        // A CLONE_VM peer may have changed the stack while allocation ran.
        // Revalidate the complete plan before touching a PTE; a mismatch owns
        // no published state and can release every speculative frame.
        let _vma_guard = self.vma_transaction.lock();
        let huge = self.huge_regions.lock();
        let mut regions = self.regions.lock();
        let huge_bytes = huge
            .iter()
            .fold(0u64, |total, region| total.saturating_add(region.len));
        let current = Self::stack_growth_plan(&regions, huge_bytes, v_page, limits);
        if current != Ok(plan) {
            let error = current.err().unwrap_or(AddressSpaceError::Unmapped);
            drop(regions);
            drop(huge);
            drop(_vma_guard);
            Self::free_stack_frames(new_phys);
            return Err(error);
        }

        // The grown stack and replacement guard are committed only after PTE
        // installation, so prepare both index nodes before that first leaf.
        if let Err(error) = regions.try_reserve_nodes(2) {
            drop(regions);
            drop(huge);
            drop(_vma_guard);
            Self::free_stack_frames(new_phys);
            return Err(error);
        }

        let mut flags = PtFlags::USER | PtFlags::WRITABLE;
        if !plan.grown_perms.contains(RegionPerms::EXEC) {
            flags |= PtFlags::NO_EXEC;
        }
        for (index, phys) in new_phys.iter().copied().enumerate() {
            let page = VirtAddr::new(plan.v_page + (index as u64) * 0x1000);
            // SAFETY: the final plan is stable under the VMA transaction and
            // each frame is fresh, aligned, and exclusively owned.
            if unsafe { map_4kb(self.root, page, phys, flags) }.is_err() {
                for rollback in 0..index as u64 {
                    // SAFETY: only leaves installed by this transaction are
                    // rolled back; pre-existing leaves are never accepted.
                    let _ = unsafe {
                        unmap_4kb(self.root, VirtAddr::new(plan.v_page + rollback * 0x1000))
                    };
                }
                drop(regions);
                drop(huge);
                drop(_vma_guard);
                Self::free_stack_frames(new_phys);
                return Err(AddressSpaceError::NotImplemented);
            }
        }

        regions
            .remove(plan.guard_base)
            .expect("stack guard disappeared under region lock");
        assert!(regions
            .insert_reserved(Region {
                base: VirtAddr::new(plan.v_page),
                len: plan.npages * 0x1000,
                perms: plan.grown_perms,
                phys: new_phys,
            })
            .is_none());
        assert!(regions
            .insert_reserved(Region {
                base: VirtAddr::new(plan.new_guard_base),
                len: 0x1000,
                perms: RegionPerms::STACK_GUARD | RegionPerms::LOCK_EXEMPT,
                phys: guard_phys,
            })
            .is_none());
        Ok(())
    }

    /// Grow a stack after admitting the expansion against Linux task limits.
    ///
    /// # Safety
    /// - The low-memory identity map must be live (used to zero the fresh
    ///   frame).
    /// - `self.root` must be a valid `TTBR0_EL1` root for the AS currently
    ///   active on this CPU.
    /// - The frame allocator must be initialised.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn try_grow_stack_limited(
        &self,
        vaddr: VirtAddr,
        limits: StackGrowthLimits,
    ) -> Result<(), AddressSpaceError> {
        use crate::aarch64::paging::{map_4kb, unmap_4kb, PtFlags};
        let v_page = vaddr.as_u64() & !0xFFFu64;
        let plan = {
            let _vma_guard = self.vma_transaction.lock();
            let huge = self.huge_regions.lock();
            let regions = self.regions.lock();
            let huge_bytes = huge
                .iter()
                .fold(0u64, |total, region| total.saturating_add(region.len));
            Self::stack_growth_plan(&regions, huge_bytes, v_page, limits)?
        };
        // SAFETY: forwarded frame-allocation and kernel-alias contract.
        let new_phys = unsafe { Self::allocate_stack_frames(plan.npages) }?;
        let mut guard_phys = Vec::new();
        if guard_phys.try_reserve_exact(1).is_err() {
            Self::free_stack_frames(new_phys);
            return Err(AddressSpaceError::AllocationFailed);
        }
        guard_phys.push(crate::PhysAddr::new(0));

        let _vma_guard = self.vma_transaction.lock();
        let huge = self.huge_regions.lock();
        let mut regions = self.regions.lock();
        let huge_bytes = huge
            .iter()
            .fold(0u64, |total, region| total.saturating_add(region.len));
        let current = Self::stack_growth_plan(&regions, huge_bytes, v_page, limits);
        if current != Ok(plan) {
            let error = current.err().unwrap_or(AddressSpaceError::Unmapped);
            drop(regions);
            drop(huge);
            drop(_vma_guard);
            Self::free_stack_frames(new_phys);
            return Err(error);
        }

        if let Err(error) = regions.try_reserve_nodes(2) {
            drop(regions);
            drop(huge);
            drop(_vma_guard);
            Self::free_stack_frames(new_phys);
            return Err(error);
        }

        let mut flags = PtFlags::AP_RW_EL0 | PtFlags::PXN;
        if !plan.grown_perms.contains(RegionPerms::EXEC) {
            flags = flags | PtFlags::UXN;
        }
        for (index, phys) in new_phys.iter().copied().enumerate() {
            let page = VirtAddr::new(plan.v_page + (index as u64) * 0x1000);
            // SAFETY: the final plan is stable and the frame is fresh.
            if unsafe { map_4kb(self.root, page, phys, flags) }.is_err() {
                for rollback in 0..index as u64 {
                    // SAFETY: roll back only leaves installed above.
                    let _ = unsafe {
                        unmap_4kb(self.root, VirtAddr::new(plan.v_page + rollback * 0x1000))
                    };
                }
                drop(regions);
                drop(huge);
                drop(_vma_guard);
                Self::free_stack_frames(new_phys);
                return Err(AddressSpaceError::NotImplemented);
            }
        }

        regions
            .remove(plan.guard_base)
            .expect("stack guard disappeared under region lock");
        assert!(regions
            .insert_reserved(Region {
                base: VirtAddr::new(plan.v_page),
                len: plan.npages * 0x1000,
                perms: plan.grown_perms,
                phys: new_phys,
            })
            .is_none());

        assert!(regions
            .insert_reserved(Region {
                base: VirtAddr::new(plan.new_guard_base),
                len: 0x1000,
                perms: RegionPerms::STACK_GUARD | RegionPerms::LOCK_EXEMPT,
                phys: guard_phys,
            })
            .is_none());
        Ok(())
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub unsafe fn try_grow_stack_limited(
        &self,
        _vaddr: VirtAddr,
        _limits: StackGrowthLimits,
    ) -> Result<(), AddressSpaceError> {
        Err(AddressSpaceError::NotImplemented)
    }

    /// Return whether base-page regions cover every byte in `[lo, hi)`.
    ///
    /// The region table is ordered by base, so coverage starts at the one
    /// predecessor that can contain `lo` and walks only the requested span.
    /// This helper is used by VM operations that require atomic full coverage.
    fn regions_cover_range(regions: &RegionTable, lo: u64, hi: u64) -> bool {
        regions.covers_range(lo, hi)
    }

    /// Is every byte of `[base, base + len)` backed by a mapping — ordinary
    /// or hugetlb?
    ///
    /// `mm/madvise.c::madvise_walk_vmas` reports a hole two ways, and both
    /// end in -ENOMEM:
    ///
    ///     if (!vma)
    ///             return -ENOMEM;
    ///     ...
    ///     if (range->start < vma->vm_start) {
    ///             /* This indicates a gap between VMAs ... */
    ///             unmapped_error = -ENOMEM;
    ///
    /// Hugetlb VMAs count as coverage, so a range that straddles an ordinary
    /// and a huge mapping is not a hole — checking only the base-page tree
    /// would report ENOMEM for a perfectly well-formed range.
    pub fn range_fully_mapped(&self, base: VirtAddr, len: u64) -> bool {
        let lo = base.as_u64();
        let Some(hi) = lo.checked_add(len) else {
            return false;
        };
        if lo == hi {
            return true;
        }
        // Huge before regular — the lock order every mixed walk here uses.
        let huge = self.huge_regions.lock();
        let regions = self.regions.lock();
        Self::mappings_covered_prefix_end(&huge, &regions, lo, hi) >= hi
    }

    /// End of the contiguous mapped prefix across ordinary and explicit
    /// hugetlb VMAs. Hugetlb is a successful no-op for mlock fixup, but still
    /// fills coverage so a mixed regular/huge range is not reported as a hole.
    /// Caller holds huge -> regular locks.
    fn mappings_covered_prefix_end(
        huge: &[HugeRegion],
        regular: &RegionTable,
        lo: u64,
        hi: u64,
    ) -> u64 {
        let mut cursor = lo;
        while cursor < hi {
            let regular_end = regular
                .containing(cursor)
                .map(|region| region.base.as_u64().saturating_add(region.len));
            let huge_end = huge
                .iter()
                .find(|region| {
                    region.base.as_u64() <= cursor
                        && cursor < region.base.as_u64().saturating_add(region.len)
                })
                .map(|region| region.base.as_u64().saturating_add(region.len));
            let Some(end) = regular_end.into_iter().chain(huge_end).max() else {
                break;
            };
            if end <= cursor {
                break;
            }
            cursor = end.min(hi);
        }
        cursor
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
    ) -> Result<(), AddressSpaceError> {
        let mut additional_nodes = 0usize;
        regions.for_each_overlapping(lo, hi, |region| {
            let rb = region.base.as_u64();
            let re = rb.saturating_add(region.len);
            let exempt = (region.perms.contains(RegionPerms::LOCK_EXEMPT)
                || region.perms.contains(RegionPerms::STACK_GUARD))
                && (flag == RegionPerms::LOCKED || flag == RegionPerms::LOCK_ONFAULT);
            if !exempt && region.perms.contains(flag) != set {
                additional_nodes =
                    additional_nodes.saturating_add(usize::from(rb < lo) + usize::from(re > hi));
            }
        });
        regions.try_reserve_nodes(additional_nodes)?;

        // Drain only the tree entries that intersect the request. Tiny
        // mlock/munlock calls therefore touch O(log VMA + intersections)
        // metadata rather than rebuilding a process-wide list.
        let originals = regions.drain_overlapping(lo, hi);
        if originals.is_empty() {
            return Ok(());
        }
        let mut rebuilt = Vec::with_capacity(originals.len() + 2);
        for region in originals {
            let rb = region.base.as_u64();
            let re = rb.saturating_add(region.len);
            if rb >= hi || re <= lo {
                rebuilt.push(region);
                continue;
            }
            if (region.perms.contains(RegionPerms::LOCK_EXEMPT)
                || region.perms.contains(RegionPerms::STACK_GUARD))
                && (flag == RegionPerms::LOCKED || flag == RegionPerms::LOCK_ONFAULT)
            {
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
            assert!(regions.insert_reserved(region).is_none());
        }
        Ok(())
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
            .ok_or(AddressSpaceError::OutOfRange)?;
        Ok((lo, hi))
    }

    /// Current default inherited by subsequently-created ordinary mappings.
    pub fn future_lock_policy(&self) -> FutureLockPolicy {
        self.regions.lock().future_lock
    }

    /// Apply one `mlockall(2)` state transition atomically with respect to
    /// mapping insertion by CLONE_VM peers.
    ///
    /// `current` is `None` when MCL_CURRENT was absent, or the requested mode
    /// for every existing ordinary VMA. `future` always replaces the previous
    /// MCL_FUTURE mode; this is why a CURRENT-only call disables an older
    /// future policy while leaving it possible for a FUTURE-only call to leave
    /// current VMA flags untouched.
    pub fn update_mlockall(
        &self,
        current: Option<FutureLockPolicy>,
        future: FutureLockPolicy,
    ) -> Result<(), AddressSpaceError> {
        self.update_mlockall_limited(current, future, u64::MAX, true)
    }

    /// Limit-enforcing counterpart used by the Linux syscall boundary. A
    /// failed CURRENT admission leaves both current flags and the prior future
    /// policy unchanged.
    pub fn update_mlockall_limited(
        &self,
        current: Option<FutureLockPolicy>,
        future: FutureLockPolicy,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<(), AddressSpaceError> {
        let vma_guard = self.vma_transaction.lock();
        {
            let huge = self.huge_regions.lock();
            let mut regions = self.regions.lock();
            if current.is_some() && !bypass_limit {
                let huge_bytes = huge
                    .iter()
                    .fold(0u64, |total, region| total.saturating_add(region.len));
                if regions.accounted_mapped_bytes().saturating_add(huge_bytes) > limit_bytes {
                    return Err(AddressSpaceError::LockLimit);
                }
            }
            regions.future_lock = future;
            if let Some(mode) = current {
                let bits = mode.region_bits().0;
                regions.for_each_mut(|region| {
                    if region.perms.contains(RegionPerms::STACK_GUARD)
                        || region.perms.contains(RegionPerms::LOCK_EXEMPT)
                    {
                        return;
                    }
                    region.perms.0 &= !(RegionPerms::LOCKED.0 | RegionPerms::LOCK_ONFAULT.0);
                    region.perms.0 |= bits;
                });
            }
            drop(regions);
            drop(huge);
        }
        drop(vma_guard);
        if current == Some(FutureLockPolicy::Eager) {
            self.populate_locked_range_best_effort(0, Self::USER_HALF_END);
        }
        Ok(())
    }

    /// Clear existing locks and the inherited future policy in one address-
    /// space transaction. Resident pages remain backed.
    pub fn munlock_all(&self) -> Result<(), AddressSpaceError> {
        let _vma_guard = self.vma_transaction.lock();
        let mut regions = self.regions.lock();
        regions.future_lock = FutureLockPolicy::None;
        regions.for_each_mut(|region| {
            region.perms.0 &= !(RegionPerms::LOCKED.0 | RegionPerms::LOCK_ONFAULT.0);
        });
        Ok(())
    }

    /// Best-effort eager population for flags already published by mlockall
    /// or an inherited MCL_FUTURE policy. This helper never changes lock bits,
    /// so a racing munlockall cannot be undone after the region lock is
    /// dropped for allocation or a file-demand callback.
    fn populate_locked_range_best_effort(&self, lo: u64, hi: u64) {
        // `AddressSpace::empty` is intentionally metadata-only and is heavily
        // used by unit tests. A real user address space always owns a root.
        if self.root.raw() == 0 {
            return;
        }
        let mut va = lo & !0xFFF;
        while va < hi {
            let candidate = {
                let regions = self.regions.lock();
                regions.next_eager_unbacked(va, hi)
            };
            let Some(page) = candidate else {
                break;
            };
            // SAFETY: this is the same live-root population operation as an
            // ordinary user page fault. Failure is deliberately ignored.
            let _ = unsafe { self.demand_alloc_page(VirtAddr::new(page)) };
            va = page.saturating_add(4096);
        }
    }

    /// `mlock(base, len)` — force-back every lazy page in the rounded
    /// `[base, base + len)` range and set LOCKED on exactly that range.
    /// Returns Unmapped if any page in the request is unmapped. As on Linux,
    /// LOCKED is published before eager population and is not rolled back if
    /// a later page cannot be populated.
    pub fn mlock_range(&self, base: VirtAddr, len: u64) -> Result<(), AddressSpaceError> {
        self.mlock_range_limited(base, len, u64::MAX, true)
    }

    /// Linux-limit-enforcing eager lock operation. Locked accounting counts
    /// virtual pages (including lazy pages), subtracting overlap that is
    /// already locked before checking RLIMIT_MEMLOCK.
    pub fn mlock_range_limited(
        &self,
        base: VirtAddr,
        len: u64,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<(), AddressSpaceError> {
        let (lo, hi) = Self::rounded_lock_range(base, len)?;
        // For a page-aligned address Linux treats zero bytes as a no-op. An
        // unaligned zero-byte request rounds over its containing page and is
        // validated normally.
        if lo == hi {
            return Ok(());
        }
        let transitioning = {
            let _vma_guard = self.vma_transaction.lock();
            let huge = self.huge_regions.lock();
            let mut g = self.regions.lock();
            if !bypass_limit {
                let requested = hi.saturating_sub(lo);
                let additional = requested.saturating_sub(g.locked_overlap_bytes(lo, hi));
                if g.locked_bytes().saturating_add(additional) > limit_bytes {
                    return Err(AddressSpaceError::LockLimit);
                }
            }
            let covered_hi = Self::mappings_covered_prefix_end(&huge, &g, lo, hi);
            let transitioning = g.swap_pages.range(lo..covered_hi).any(|(_, state)| {
                matches!(state, SwapPageState::Evicting(_) | SwapPageState::Loading)
            });
            // Linux's do_mlock applies VM_LOCKED before __mm_populate and does
            // not roll it back when population later fails. Publishing the
            // flag in this coverage-validation transaction also avoids a
            // reclaim window between validation and the first allocation.
            Self::set_region_flag_range(&mut g, lo, covered_hi, RegionPerms::LOCKED, true)?;
            Self::set_region_flag_range(&mut g, lo, covered_hi, RegionPerms::LOCK_ONFAULT, false)?;
            if covered_hi < hi {
                return Err(AddressSpaceError::Unmapped);
            }
            transitioning
        };
        if transitioning {
            return Err(AddressSpaceError::LockFailed);
        }

        // Populate page-by-page through the ordinary ticketed fault path. It
        // already distinguishes anonymous, file-demand, and swapped backing,
        // installs the leaf and reverse map transactionally, and releases an
        // unpublished frame on races. No proportional snapshot/allocation is
        // needed merely to enumerate the range under memory pressure.
        let mut cursor = lo;
        loop {
            let candidate = {
                let regions = self.regions.lock();
                regions.next_eager_unbacked(cursor, hi)
            };
            let Some(va) = candidate else {
                break;
            };
            // SAFETY: mlock operates on this live address-space root and the
            // same allocator/MMU prerequisites as a user page fault.
            unsafe { self.demand_alloc_page(VirtAddr::new(va)) }.map_err(mlock_population_error)?;
            // `demand_alloc_page` returns Ok when a peer owns this page's
            // ticket or a swap transition is in progress. mlock cannot claim
            // eager population completed until backing is visible.
            let backed = {
                let regions = self.regions.lock();
                let Some(region) = regions.containing(va) else {
                    return Err(AddressSpaceError::LockFailed);
                };
                let index = ((va - region.base.as_u64()) >> 12) as usize;
                region.phys.get(index).is_some_and(|phys| phys.raw() != 0)
            };
            if !backed {
                return Err(AddressSpaceError::LockFailed);
            }
            cursor = va.saturating_add(4096);
        }
        Ok(())
    }

    /// `mlock2(base, len, MLOCK_ONFAULT)` — mark exactly the rounded range
    /// LOCKED without populating lazy pages.  A later demand fault supplies
    /// the backing normally, while reclaim observes LOCKED and leaves it
    /// resident.  This differs intentionally from [`Self::mlock_range`],
    /// whose eager population is the defining `mlock(2)` behaviour.
    pub fn mlock_range_onfault(&self, base: VirtAddr, len: u64) -> Result<(), AddressSpaceError> {
        self.mlock_range_onfault_limited(base, len, u64::MAX, true)
    }

    /// Linux-limit-enforcing MLOCK_ONFAULT operation.
    pub fn mlock_range_onfault_limited(
        &self,
        base: VirtAddr,
        len: u64,
        limit_bytes: u64,
        bypass_limit: bool,
    ) -> Result<(), AddressSpaceError> {
        let (lo, hi) = Self::rounded_lock_range(base, len)?;
        if lo == hi {
            return Ok(());
        }
        let _vma_guard = self.vma_transaction.lock();
        let huge = self.huge_regions.lock();
        let mut regions = self.regions.lock();
        if !bypass_limit {
            let requested = hi.saturating_sub(lo);
            let additional = requested.saturating_sub(regions.locked_overlap_bytes(lo, hi));
            if regions.locked_bytes().saturating_add(additional) > limit_bytes {
                return Err(AddressSpaceError::LockLimit);
            }
        }
        let covered_hi = Self::mappings_covered_prefix_end(&huge, &regions, lo, hi);
        Self::set_region_flag_range(&mut regions, lo, covered_hi, RegionPerms::LOCKED, true)?;
        Self::set_region_flag_range(
            &mut regions,
            lo,
            covered_hi,
            RegionPerms::LOCK_ONFAULT,
            true,
        )?;
        if covered_hi < hi {
            return Err(AddressSpaceError::Unmapped);
        }
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
        let _vma_guard = self.vma_transaction.lock();
        let huge = self.huge_regions.lock();
        let mut g = self.regions.lock();
        let covered_hi = Self::mappings_covered_prefix_end(&huge, &g, lo, hi);
        Self::set_region_flag_range(&mut g, lo, covered_hi, RegionPerms::LOCK_ONFAULT, false)?;
        Self::set_region_flag_range(&mut g, lo, covered_hi, RegionPerms::LOCKED, false)?;
        if covered_hi < hi {
            return Err(AddressSpaceError::Unmapped);
        }
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
        let _vma_guard = self.vma_transaction.lock();
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
        unsafe { self.rewrite_perms_pages(&hits, false) };
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
    pub(crate) fn mprotect_range_wx_checked(
        &self,
        base: VirtAddr,
        len: u64,
        new_perms: RegionPerms,
    ) -> Result<(), AddressSpaceError> {
        let _vma_guard = self.vma_transaction.lock();
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
        // Keep both topology locks from preflight through publication.  The
        // older two-phase shape changed huge leaves first and only then tried
        // to reserve base-page VMA nodes (or noticed a newly-started swap-in),
        // so an allocation failure could return after half of a mixed
        // huge/base request had already changed permissions.  VMA operations
        // use huge -> regular order consistently, and `vma_transaction`
        // prevents another structural operation from consuming this reserved
        // capacity before the split is published.
        let mut huge = self.huge_regions.lock();
        let mut g = self.regions.lock();
        if Self::mappings_covered_prefix_end(&huge, &g, lo, hi) < hi {
            return Err(AddressSpaceError::Unmapped);
        }
        if g.swap_pages
            .range(lo..hi)
            .any(|(_, state)| matches!(state, SwapPageState::Loading))
        {
            return Err(AddressSpaceError::NotImplemented);
        }
        let mut additional_nodes = 0usize;
        g.for_each_overlapping(lo, hi, |region| {
            let rb = region.base.as_u64();
            let re = rb.saturating_add(region.len);
            additional_nodes =
                additional_nodes.saturating_add(usize::from(rb < lo) + usize::from(re > hi));
        });
        g.try_reserve_nodes(additional_nodes)?;

        let huge_touched = {
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
                let preserved_flags = RegionPerms(region.perms.0 & !RegionPerms::PROT_MASK.0);
                rebuilt.push(HugeRegion {
                    base: VirtAddr::new(split_lo),
                    len: middle_frames.len() as u64 * page_size,
                    perms: RegionPerms(prot.0 | preserved_flags.0),
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
                assert!(g.insert_reserved(region).is_none());
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
            unsafe { self.rewrite_perms_pages(&touched, false) };
        }
        drop(g);
        drop(huge);
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
                // Clear the whole page-aligned intersection under ONE root lock
                // and a single upper-level walk, rather than re-locking the root
                // and walking PML4→PT for every resident page. This is the
                // intersection with one live private, unlocked, non-shared VMA;
                // the region lock keeps its ownership stable while the helper
                // clears the run. Missing leaves (unfaulted holes) are benign.
                // LOCAL invalidation only — the single cross-CPU broadcast below
                // runs before any freed backing can be reused.
                if self.root.as_u64() != 0 && start_i < end_i {
                    #[cfg(target_arch = "x86_64")]
                    // SAFETY: identity-mapped; the run lies in a bookkept region
                    // of this AS.
                    let _ = unsafe {
                        crate::x86_64::paging::unmap_4kb_local_range(
                            self.root,
                            VirtAddr::new(start_v),
                            (end_i - start_i) as u64,
                        )
                    };
                    #[cfg(target_arch = "aarch64")]
                    // SAFETY: as above; the helper clears the complete run under
                    // one root lock.
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
                    // Retire the reverse-map entry before the frame returns to
                    // the buddy, exactly as `free_region_frames` does on the
                    // ordinary unmap path. Zeroing `phys[i]` makes the later
                    // teardown skip this page, so MADV_DONTNEED/FREE is the only
                    // place to drop its rmap owner; omitting it leaked a stale
                    // (root, va) onto every reclaimed frame (Linux
                    // free_pages_prepare's "nonzero mapcount" invariant).
                    let va = VirtAddr::new(rb + (i as u64) * 4096);
                    crate::rmap::remove(p, self.root, va);
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
    unsafe fn rewrite_perms_pages(&self, regions: &[Region], cow_readonly: bool) {
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
            // Fork rematerialize (`cow_readonly`) only re-marks the COW regions
            // clone_for_fork touched; every other region's perms are unchanged,
            // so its live PTEs are already correct — skip it entirely.
            if cow_readonly && !r.perms.contains(RegionPerms::COW) {
                continue;
            }
            // PROT_NONE: tear down the leaf PTEs without freeing
            // the underlying frames (region.phys still owns them).
            // The next mprotect-back-to-RW just re-installs.
            if r.perms.prot_only().0 == 0 {
                // SAFETY: same identity-map invariant. The range helper holds
                // the root lock once and completes local invalidation.
                let _ = unsafe { unmap_4kb_local_range(self.root, r.base, r.phys.len() as u64) };
            } else {
                // Fork rematerialize: clone_for_fork inc_ref'd every private
                // page, so ALL of them must become read-only — skip the O(pages)
                // per-page COW refcount lookup and force RO. mprotect and the
                // other callers keep the exact per-page writability decision.
                let cow_counts = if cow_readonly {
                    None
                } else {
                    r.perms
                        .contains(RegionPerms::COW)
                        .then(|| crate::frame::cow::count_batch(&r.phys))
                };
                // SAFETY: region ownership remains stable under the caller's
                // region lock. The helper skips zero lazy sentinels, holds the
                // page-table root lock once, and completes local invalidation.
                let _ = unsafe {
                    rewrite_4kb_scatter_range(self.root, r.base, &r.phys, |i, p| {
                        let mut flags = PtFlags::USER;
                        let writable = if cow_readonly {
                            false
                        } else {
                            let cow_count = cow_counts.as_ref().map_or(0, |counts| counts[i]);
                            user_page_writable_at_count(r.perms, p, cow_count)
                        };
                        if writable {
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
    unsafe fn rewrite_perms_pages(&self, regions: &[Region], cow_readonly: bool) {
        use crate::aarch64::paging::{rewrite_4kb_scatter_range, unmap_4kb_range, PtFlags};
        if self.root.as_u64() == 0 {
            return;
        }
        for r in regions {
            // Fork rematerialize (`cow_readonly`): only the COW regions
            // clone_for_fork touched need re-marking; skip the rest.
            if cow_readonly && !r.perms.contains(RegionPerms::COW) {
                continue;
            }
            if r.perms.prot_only().0 == 0 {
                // SAFETY: see x86_64 variant. The helper clears every leaf
                // under one root lock and one inner-shareable TLBI sequence.
                let _ = unsafe { unmap_4kb_range(self.root, r.base, r.phys.len() as u64) };
                continue;
            }
            // Fork rematerialize: every private page was inc_ref'd, so all become
            // read-only — skip the per-page COW refcount lookup and force RO.
            let cow_counts = if cow_readonly {
                None
            } else {
                r.perms
                    .contains(RegionPerms::COW)
                    .then(|| crate::frame::cow::count_batch(&r.phys))
            };
            // SAFETY: region ownership stays stable under the caller's region
            // lock. The helper performs one complete break-before-make
            // transaction and leaves zero backing sentinels unmapped.
            let _ = unsafe {
                rewrite_4kb_scatter_range(self.root, r.base, &r.phys, |i, p| {
                    let writable = if cow_readonly {
                        false
                    } else {
                        let cow_count = cow_counts.as_ref().map_or(0, |counts| counts[i]);
                        user_page_writable_at_count(r.perms, p, cow_count)
                    };
                    let mut flags = if writable {
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
    unsafe fn rewrite_perms_pages(&self, _regions: &[Region], _cow_readonly: bool) {}

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

    /// Materialize only the VMA named by `receipt` if that exact publication
    /// remains current. A racing replacement invalidates the receipt and is
    /// left completely untouched.
    ///
    /// # Safety
    /// The address-space root must remain live for the duration of the call.
    pub unsafe fn materialize_mapping(
        &self,
        receipt: MappingReceipt,
    ) -> Result<(), AddressSpaceError> {
        let _vma_guard = self.vma_transaction.lock();
        // SAFETY: the transaction is held and the live-root requirement is
        // forwarded from this method's contract.
        unsafe { self.materialize_mapping_locked(receipt) }
    }

    /// Transaction-held counterpart of [`Self::materialize_mapping`].
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`], and the
    /// address-space root must remain live.
    pub unsafe fn materialize_mapping_locked(
        &self,
        receipt: MappingReceipt,
    ) -> Result<(), AddressSpaceError> {
        if !self.mapping_receipt_current_locked(receipt) {
            return Err(AddressSpaceError::StaleMapping);
        }
        // SAFETY: the receipt supplies a validated aligned user range and the
        // caller supplies the live-root contract.
        unsafe { self.materialize_range(receipt.base, receipt.len) }
    }

    /// Remove only the VMA named by `receipt`. If a peer replaced, split, or
    /// moved it, return `StaleMapping` without touching the peer's mapping.
    pub fn rollback_mapping(&self, receipt: MappingReceipt) -> Result<(), AddressSpaceError> {
        let _vma_guard = self.vma_transaction.lock();
        let _shared_guard = receipt.shared.then(|| SHARED_MAPPING_TRANSACTION.lock());
        // SAFETY: both structural transactions required by the receipt's
        // sharedness are held in canonical VMA -> shared order.
        unsafe { self.rollback_mapping_locked(receipt) }
    }

    /// Transaction-held counterpart of [`Self::rollback_mapping`].
    ///
    /// # Safety
    /// The caller must hold [`Self::with_vma_transaction`]. If `receipt` names
    /// a shared VMA, it must then hold [`with_shared_mapping_transaction`].
    pub unsafe fn rollback_mapping_locked(
        &self,
        receipt: MappingReceipt,
    ) -> Result<(), AddressSpaceError> {
        if !self.mapping_receipt_current_locked(receipt) {
            return Err(AddressSpaceError::StaleMapping);
        }
        self.punch_fixed_locked_with_shared(receipt.base, receipt.len, receipt.shared)
    }

    /// The caller holds the VMA transaction, making this validation stable
    /// until that transaction is released.
    fn mapping_receipt_current_locked(&self, receipt: MappingReceipt) -> bool {
        if receipt.address_space_id != self.identity() {
            return false;
        }
        let regions = self.regions.lock();
        regions.mapping_id(receipt.base.as_u64()) == Some(receipt.mapping_id)
            && regions.get(receipt.base.as_u64()).is_some_and(|region| {
                region.len == receipt.len
                    && region.perms.contains(RegionPerms::SHARED) == receipt.shared
            })
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
        use crate::x86_64::paging::{map_4kb, map_4kb_scatter_range, MapError, PtFlags};
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
            // Clamp to the materialized phys prefix: a demand-paged region has no
            // phys slot (and no PTE to install) for pages past it — they fault in
            // individually. Keeps a windowed materialize from slicing a short list.
            let last = last.min(r.phys.len());
            let first = first.min(last);

            let cow_counts = r
                .perms
                .contains(RegionPerms::COW)
                .then(|| crate::frame::cow::count_batch(&r.phys[first..last]));

            let slice = &r.phys[first..last];
            let window_base = crate::VirtAddr::new(r.base.as_u64() + ((first as u64) << 12));
            // Batched PTE install: ONE root-lock acquisition + ONE 4-level walk
            // per 512-page group (the helper caches the PT across a group),
            // versus a per-page lock + full walk. This is the dominant cost of
            // constructing a forked child AS; the parent rematerialize path
            // already uses the same helper via `install_region_leaves_local`.
            // Lazy (phys == 0) slots are skipped by the helper so their PTE
            // stays absent and first access demand-faults with P=0.
            // SAFETY: `self.root` is a valid PML4 per the `new_for_user`
            // contract; every VA lies within this region whose backing was
            // length-checked at map_region.
            let install = unsafe {
                map_4kb_scatter_range(self.root, window_base, slice, |index, phys| {
                    let mut flags = PtFlags::USER;
                    let cow_count = cow_counts.as_ref().map_or(0, |counts| counts[index]);
                    if user_page_writable_at_count(r.perms, phys, cow_count) {
                        flags |= PtFlags::WRITABLE;
                    }
                    if !r.perms.contains(RegionPerms::EXEC) {
                        flags |= PtFlags::NO_EXEC;
                    }
                    flags
                })
            };
            if install.is_err() {
                // The batched helper deliberately has partial-progress
                // semantics: a later allocation/collision failure leaves the
                // successfully installed prefix present. Recover through the
                // old scalar path so every installed leaf gains its rmap entry
                // and `AlreadyMapped` remains idempotent. Fresh fork children
                // stay on the all-batched fast path; only error/re-materialize
                // cases pay the repeated walks.
                for (index, &p) in slice.iter().enumerate() {
                    if p.raw() == 0 {
                        continue;
                    }
                    let cow_count = cow_counts.as_ref().map_or(0, |counts| counts[index]);
                    let mut flags = PtFlags::USER;
                    if user_page_writable_at_count(r.perms, p, cow_count) {
                        flags |= PtFlags::WRITABLE;
                    }
                    if !r.perms.contains(RegionPerms::EXEC) {
                        flags |= PtFlags::NO_EXEC;
                    }
                    let v = crate::VirtAddr::new(window_base.as_u64() + ((index as u64) << 12));
                    // SAFETY: same validated root/range/backing contract as the
                    // batched attempt above.
                    match unsafe { map_4kb(self.root, v, p, flags) } {
                        Ok(()) | Err(MapError::AlreadyMapped) => crate::rmap::add(p, self.root, v),
                        Err(MapError::EncounteredHugePage) => {
                            return Err(AddressSpaceError::Overlap);
                        }
                        Err(MapError::NonCanonical) => {
                            return Err(AddressSpaceError::OutOfRange);
                        }
                        Err(_) => return Err(AddressSpaceError::Overlap),
                    }
                }
                continue;
            }
            // Record the reverse mapping for every installed leaf. rmap shards
            // by phys — a separate lock from the page tables — so the expensive
            // 4-level walk was already amortised above; this is an O(1) insert
            // per page. Lazy (phys == 0) slots are not installed, so skip them.
            for (k, &p) in slice.iter().enumerate() {
                if p.raw() == 0 {
                    continue;
                }
                let v = crate::VirtAddr::new(window_base.as_u64() + ((k as u64) << 12));
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
        use crate::aarch64::paging::{map_4kb, map_4kb_scatter_range, MapError, PtFlags};
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
            // Clamp to the materialized phys prefix: a demand-paged region has no
            // phys slot (and no PTE to install) for pages past it — they fault in
            // individually. Keeps a windowed materialize from slicing a short list.
            let last = last.min(r.phys.len());
            let first = first.min(last);
            let cow_counts = r
                .perms
                .contains(RegionPerms::COW)
                .then(|| crate::frame::cow::count_batch(&r.phys[first..last]));
            let slice = &r.phys[first..last];
            let window_base = crate::VirtAddr::new(r.base.as_u64() + ((first as u64) << 12));
            // Batched PTE install: ONE root-lock + ONE table walk per 512-page
            // group, versus per-page. Mirrors the x86_64 counterpart and the
            // parent `install_region_leaves_local`; the dominant cost of a
            // forked child AS. Lazy (phys == 0) slots are skipped by the helper.
            // SAFETY: root is valid per `new_for_user`; every VA lies within
            // this region whose backing was length-checked at map_region.
            let install = unsafe {
                map_4kb_scatter_range(self.root, window_base, slice, |index, phys| {
                    let cow_count = cow_counts.as_ref().map_or(0, |counts| counts[index]);
                    let mut flags = if user_page_writable_at_count(r.perms, phys, cow_count) {
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
            if install.is_err() {
                // Preserve the scalar materialize contract on the batched
                // helper's partial-progress/error path. This records rmaps for
                // an installed prefix and keeps repeat materialization
                // idempotent without penalising a fresh child address space.
                for (index, &p) in slice.iter().enumerate() {
                    if p.raw() == 0 {
                        continue;
                    }
                    let cow_count = cow_counts.as_ref().map_or(0, |counts| counts[index]);
                    let mut flags = if user_page_writable_at_count(r.perms, p, cow_count) {
                        PtFlags::AP_RW_EL0
                    } else {
                        PtFlags::AP_RO_EL0
                    };
                    if !r.perms.contains(RegionPerms::EXEC) {
                        flags = flags | PtFlags::UXN | PtFlags::PXN;
                    }
                    let v = crate::VirtAddr::new(window_base.as_u64() + ((index as u64) << 12));
                    // SAFETY: same validated root/range/backing contract as the
                    // batched attempt above.
                    match unsafe { map_4kb(self.root, v, p, flags) } {
                        Ok(()) | Err(MapError::AlreadyMapped) => crate::rmap::add(p, self.root, v),
                        Err(MapError::NonCanonical) => {
                            return Err(AddressSpaceError::OutOfRange);
                        }
                        Err(_) => return Err(AddressSpaceError::Overlap),
                    }
                }
                continue;
            }
            // Reverse-map every installed leaf (rmap shards by phys, a separate
            // lock from the page tables; the costly walk was amortised above).
            for (k, &p) in slice.iter().enumerate() {
                if p.raw() == 0 {
                    continue;
                }
                let v = crate::VirtAddr::new(window_base.as_u64() + ((k as u64) << 12));
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
        // `cow_readonly = true`: fork-COW WRITE-strip. Every private page was
        // inc_ref'd by clone_for_fork so all become read-only; skip the per-page
        // refcount lookup and leave non-COW (e.g. MAP_SHARED) regions untouched.
        unsafe { self.rewrite_perms_pages(&snapshot, true) };
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
        // SAFETY: caller's contract — paging is live.
        let child = unsafe { Self::new_for_user() }?;
        #[cfg(feature = "kernel-test")]
        {
            let fail_after =
                FAIL_FORK_CHILD_REGION_RESERVE_AFTER.swap(0, core::sync::atomic::Ordering::AcqRel);
            if fail_after != 0 {
                child
                    .regions
                    .lock()
                    .by_base
                    .fail_reserve_after_for_test(fail_after);
            }
        }
        // Linearize the parent topology snapshot before taking the shared-
        // owner transaction. The child is not scheduler-visible during
        // construction. Release the VMA transaction once both regular and
        // huge metadata are owned snapshots; backing allocation/copy below
        // must not run with this IRQ-safe lock held.
        let vma_guard = self.vma_transaction.lock();
        let _shared_guard = SHARED_MAPPING_TRANSACTION.lock();

        // Mark every private region as potentially COW-shared. Keep its POSIX
        // WRITE permission authoritative; the PTE derivation consults this
        // marker plus each frame's refcount to force only shared pages RO.
        // Complete the huge metadata snapshot before publishing any base-page
        // COW retain. Huge backing itself remains parent-owned and is copied
        // eagerly below.
        let parent_huge: Vec<HugeRegion> = self
            .huge_regions
            .lock()
            .iter()
            .map(|region| HugeRegion {
                base: region.base,
                len: region.len,
                perms: region.perms,
                size: region.size,
                frames: region.frames.clone(),
            })
            .collect();
        // Snapshot the resulting region list and retain exactly the private
        // resident backing that the child will own.
        let (parent_regions, cow_frames): (Vec<Region>, Vec<PhysAddr>) = {
            let mut g = self.regions.lock();
            if !g.swap_pages.is_empty() {
                // Swap slots are single-owner today. Cloning phys=0 would
                // silently replace preserved contents with demand-zero.
                return Err(AddressSpaceError::NotImplemented);
            }
            g.for_each_mut(|r| {
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
                    return;
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
            });
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
            let parent_regions = g.snapshot();
            crate::frame::cow::inc_ref_batch(&cow_frames);
            (parent_regions, cow_frames)
        };
        drop(vma_guard);

        // The child's regions are a deep clone of the parent's
        // (post-mark) — same vaddr base, phys list, and logical permissions.
        let mut published_cow_frames = 0usize;
        for mut r in parent_regions.into_iter() {
            let region_cow_frames = if r.perms.contains(RegionPerms::SHARED) {
                0
            } else {
                r.phys.iter().filter(|phys| phys.raw() != 0).count()
            };
            // Linux fork clears VM_LOCKED_MASK in the child. The parent keeps
            // both its current locks and its future default; a CLONE_VM thread
            // shares this same AddressSpace instead of taking this path.
            r.perms.0 &= !(RegionPerms::LOCKED.0 | RegionPerms::LOCK_ONFAULT.0);
            if let Err(error) = child.map_region_inner(r, None, None) {
                // Child Drop owns and balances the published prefix. Restore
                // only the suffix which never acquired a child VMA; rolling
                // back the prefix here would double-decrement live backing.
                crate::frame::cow::rollback_inc_ref_batch(&cow_frames[published_cow_frames..]);
                return Err(error);
            }
            published_cow_frames += region_cow_frames;
        }
        debug_assert_eq!(published_cow_frames, cow_frames.len());
        // All externally-owned regular aliases are now retained by the child.
        // Huge allocations and multi-megabyte copies below neither consult nor
        // publish shared-owner state and must not run with this global IRQ-safe
        // transaction held.
        drop(_shared_guard);

        // Private hugetlb mappings are copied eagerly. The hugepage pool has
        // no sub-page COW metadata, so sharing a writable hardware block leaf
        // would violate fork isolation. Preserve each frame's NUMA placement.
        //
        // SHARED ones are the opposite case and must NOT be copied: a
        // `MAP_SHARED | MAP_HUGETLB` region is one object mapped twice, and
        // copying it would silently give parent and child private snapshots
        // that diverge on the first write — the failure would surface as lost
        // updates in whatever data structure the region holds, arbitrarily far
        // from the fork. Alias the frames and take a reference to each, so the
        // first address space to exit releases rather than frees them.
        for region in &parent_huge {
            if region.perms.contains(RegionPerms::SHARED) {
                for frame in &region.frames {
                    crate::hugepage::retain_hugepage(*frame);
                }
                // SAFETY: the child root is fresh and the region is aligned
                // and non-overlapping by construction; the frames are now
                // owned by both address spaces and the refcount says so.
                unsafe {
                    let mut child_perms = region.perms;
                    child_perms.0 &= !(RegionPerms::LOCKED.0 | RegionPerms::LOCK_ONFAULT.0);
                    if let Err(error) = child.map_huge_region(HugeRegion {
                        base: region.base,
                        len: region.len,
                        perms: child_perms,
                        size: region.size,
                        frames: region.frames.clone(),
                    }) {
                        for frame in &region.frames {
                            crate::hugepage::free_hugepage(*frame);
                        }
                        return Err(error);
                    }
                }
                continue;
            }
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
                // SAFETY: both huge frames are exclusively owned and their
                // equal size bounds the copy. Addressed through
                // `kernel_ptr` / `kernel_mut_ptr`, NOT as raw physical
                // addresses: a bare `phys as *const u8` is only dereferenceable
                // where the identity map makes physical equal virtual, which is
                // x86_64 (and only below `LOW_IDENTITY_LIMIT`). On aarch64 a
                // physical address resolves through TTBR0 — user space — so
                // every private huge fork faulted. The 4 KiB COW path below
                // already resolves this correctly and says so; this one was
                // missed.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        crate::PhysAddr::new(source.phys()).kernel_ptr::<u8>(),
                        crate::PhysAddr::new(replacement.phys()).kernel_mut_ptr::<u8>(),
                        source.size_bytes() as usize,
                    );
                }
                frames.push(replacement);
            }
            // SAFETY: the child root is fresh and the cloned region is
            // aligned and non-overlapping by construction.
            unsafe {
                let mut child_perms = region.perms;
                child_perms.0 &= !(RegionPerms::LOCKED.0 | RegionPerms::LOCK_ONFAULT.0);
                child.map_huge_region(HugeRegion {
                    base: region.base,
                    len: region.len,
                    perms: child_perms,
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
        // A real fork inherits the parent's program break: the child clones the
        // heap regions, so its break must start where the parent's is (a fresh
        // `0` would let the first child brk mass-unmap the cloned heap on the
        // shrink path). `CLONE_VM` threads need no copy — they share this AS.
        child
            .brk_top
            .store(self.brk_top(), core::sync::atomic::Ordering::Release);
        child.program_data_bytes.store(
            self.program_data_bytes(),
            core::sync::atomic::Ordering::Release,
        );

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

        // A CoW break must not be refused at the `min` watermark: the faulting
        // task already owns this shared page and is doing a legitimate write, so
        // failing here would deliver a spurious SIGSEGV on writable memory.
        // `alloc_user_frame_urgent` stays `Movable` (frees in bulk on teardown)
        // but may consume the reserve, matching Linux's CoW-break policy.
        let new_frame = match crate::frame::alloc_user_frame_urgent() {
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
            .containing_mut(v)
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
        unsafe { self.relocate_page_inner(vaddr, None, None) }
    }

    /// Relocate the private page at `vaddr` to the caller-provided `dst` frame
    /// (instead of a freshly-allocated one), only if it still maps
    /// `expected_src`. The compaction dual-scanner uses this to move a movable
    /// source into a specific free frame its free-scanner reserved, so migrated
    /// pages always land at the high end of the zone. On any failure `dst` is
    /// left untouched (the caller owns its reservation and releases it); on
    /// success `dst` becomes the page's live backing and must NOT be freed by
    /// the caller.
    ///
    /// # Safety
    /// Same prerequisites as [`Self::relocate_page`]; additionally `dst` must be
    /// a live, caller-owned frame (e.g. reserved out of the buddy) distinct from
    /// `expected_src`.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn relocate_frame_to(
        &self,
        vaddr: VirtAddr,
        expected_src: PhysAddr,
        dst: PhysAddr,
    ) -> Result<(), AddressSpaceError> {
        // SAFETY: forwarded to the caller's live-root / direct-map contract.
        unsafe {
            self.relocate_page_inner(vaddr, Some(expected_src), Some(dst))
                .map(|_| ())
        }
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
        unsafe { self.relocate_page_inner(vaddr, Some(expected_src), None) }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn relocate_page_inner(
        &self,
        vaddr: VirtAddr,
        expected: Option<PhysAddr>,
        dst: Option<PhysAddr>,
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
        // Destination: the caller-provided frame (dual-scanner), else a fresh
        // frame allocated on `old_phys`'s own node to keep the copy local.
        let (new_frame, new_phys) = match dst {
            Some(d) => (None, d),
            None => {
                // SAFETY: page_va maps old_phys; sample its node for a local alloc.
                let node = unsafe { crate::frame::narf_phys_node(old_phys.raw()) };
                let frame = crate::frame::alloc_user_frame_on_strict(node)
                    .map_err(|_| AddressSpaceError::OutOfRange)?;
                let phys = frame.start_address();
                (Some(frame), phys)
            }
        };
        // SAFETY: live root; page_va maps old_phys; new_phys is a live frame.
        if unsafe { self.relocate_leaf(page_va, perms, old_phys, new_phys) }.is_err() {
            // Free only a frame WE allocated; a caller-provided `dst` is left for
            // the caller to release.
            if let Some(frame) = new_frame {
                crate::frame::free_frame(frame);
            }
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
            let source = regions.iter().find_map(|region| {
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
            });
            source
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

    /// Ensure a *present* user page at `vaddr` can accept a supervisor-mode
    /// write (signal-frame placement, `copy_to_user`), resolving a COW copy in
    /// place. Returns `false` for a genuinely read-only mapping — e.g. an
    /// `mprotect(PROT_READ)` region or a bad `sigaltstack` — so the caller can
    /// force the signal's default action instead of taking an unrecoverable
    /// CPL=0 write fault that panics the kernel. Presence is the caller's job
    /// (back demand / guard pages via `demand_alloc_page` / `try_grow_stack`
    /// first); this checks writability, which presence alone does not imply.
    ///
    /// # Safety
    /// Same identity-map / active-frame contract as [`Self::cow_split_on_write`]
    /// and [`Self::remap_page`]: the low-4-GiB identity map must be live and the
    /// frame allocator + COW refcount table initialised.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn user_page_writable_or_resolve(&self, vaddr: VirtAddr) -> bool {
        let Some(region) = self.lookup(vaddr) else {
            // Unmapped: nothing to write to.
            return false;
        };
        if !region.perms.contains(RegionPerms::WRITE) {
            // Genuinely read-only mapping — not writable, not recoverable.
            return false;
        }
        if region.perms.contains(RegionPerms::COW) {
            // Writable-but-COW: resolve the private copy and rewrite the leaf so
            // the upcoming supervisor write lands on a private, writable page.
            // SAFETY: forwarded to the callees' documented contract.
            if unsafe { self.cow_split_on_write(vaddr) }.is_err() {
                return false;
            }
            // SAFETY: cow_split_on_write just touched this region's page.
            if unsafe { self.remap_page(vaddr) }.is_err() {
                return false;
            }
        }
        true
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
        // External VMA owners must outlive leaf invalidation and backing
        // release above, but belong to the address space rather than to any
        // particular PID (CLONE_VM may give several processes the same mm).
        // Call with no VMA/shared-owner lock held so dropping a filesystem
        // object cannot invert either transaction order.
        let address_space_id = self
            .address_space_id
            .load(core::sync::atomic::Ordering::Acquire);
        if address_space_id != 0 {
            if let Some(hook) = *ADDRESS_SPACE_DROP_HOOK.lock() {
                hook(address_space_id);
            }
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
        assert!(table
            .insert(Region {
                base: VirtAddr::new(base),
                len: phys.len() as u64 * 4096,
                perms,
                phys,
            })
            .expect("test RegionIndex reservation")
            .is_none());
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

/// A leaf-install failure must not publish backing metadata or consume the
/// page's ability to be claimed again. The fault path still owns and releases
/// the rejected frame.
fn smoke_memory_demand_install_error_stays_lazy() -> TestResult {
    let a = AddressSpace::empty();
    let base = 0x0000_0080_0010_0000u64;
    if a.map_region(Region {
        base: VirtAddr::new(base),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .is_err()
    {
        return TestResult::Fail("failed to install demand-error test region");
    }
    let first = match a.claim_demand_page(base, |_, _| Ok(())) {
        Ok(DemandPageClaim::Owner { ticket, .. }) => ticket,
        _ => return TestResult::Fail("failed to claim demand-error page"),
    };
    if a.finish_demand_page(base, first, PhysAddr::new(0x31_000), |_, _| {
        Err(AddressSpaceError::NotImplemented)
    }) != Err(AddressSpaceError::NotImplemented)
    {
        return TestResult::Fail("leaf-install error was not preserved");
    }
    if a.lookup(VirtAddr::new(base))
        .is_none_or(|region| region.phys[0].raw() != 0)
    {
        return TestResult::Fail("failed leaf install published backing metadata");
    }
    let second = match a.claim_demand_page(base, |_, _| Ok(())) {
        Ok(DemandPageClaim::Owner { ticket, .. }) => ticket,
        _ => return TestResult::Fail("failed leaf install stranded the demand ticket"),
    };
    a.cancel_demand_page(base, second);
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_demand_install_error_stays_lazy);

/// Successful demand publication records reverse ownership before the region
/// lock is released, on the architecture-independent transaction path.
fn smoke_memory_demand_publish_registers_rmap() -> TestResult {
    let a = AddressSpace::empty();
    let base = 0x0000_0080_0020_0000u64;
    let phys = PhysAddr::new(0x32_000);
    if a.map_region(Region {
        base: VirtAddr::new(base),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .is_err()
    {
        return TestResult::Fail("failed to install demand-rmap test region");
    }
    let ticket = match a.claim_demand_page(base, |_, _| Ok(())) {
        Ok(DemandPageClaim::Owner { ticket, .. }) => ticket,
        _ => return TestResult::Fail("failed to claim demand-rmap page"),
    };
    if a.finish_demand_page(base, ticket, phys, |_, _| Ok(())) != Ok(true) {
        return TestResult::Fail("failed to publish demand-rmap page");
    }
    let recorded = crate::rmap::owner_count(phys) == 1;
    crate::rmap::remove(phys, a.root, VirtAddr::new(base));
    // `phys` is a synthetic test address, not allocator-owned backing.
    core::mem::forget(a);
    if recorded {
        TestResult::Pass
    } else {
        TestResult::Fail("demand publication returned before rmap registration")
    }
}
kernel_test_in!("memory", smoke_memory_demand_publish_registers_rmap);

/// The inline table is a performance fast path, not a correctness capacity.
/// One claim beyond it must enter overflow, dedupe normally, and be cancelled
/// with the rest when its VMA is removed.
fn smoke_memory_demand_claim_inline_overflow_is_lossless() -> TestResult {
    let a = AddressSpace::empty();
    let base = 0x0000_0080_0030_0000u64;
    let pages = INLINE_DEMAND_CLAIMS + 1;
    if a.map_region(Region {
        base: VirtAddr::new(base),
        len: pages as u64 * 4096,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0); pages],
    })
    .is_err()
    {
        return TestResult::Fail("failed to install demand-overflow test region");
    }
    for page in 0..pages {
        let vaddr = base + page as u64 * 4096;
        if !matches!(
            a.claim_demand_page(vaddr, |_, _| Ok(())),
            Ok(DemandPageClaim::Owner { .. })
        ) {
            return TestResult::Fail("demand claim capacity serialized a distinct page");
        }
    }
    {
        let regions = a.regions.lock();
        if regions.demand_pages.len != INLINE_DEMAND_CLAIMS
            || regions.demand_pages.overflow.len() != 1
        {
            return TestResult::Fail("demand claim did not use bounded inline overflow");
        }
    }
    let overflow_va = base + INLINE_DEMAND_CLAIMS as u64 * 4096;
    if a.claim_demand_page(overflow_va, |_, _| Ok(())) != Ok(DemandPageClaim::InProgress) {
        return TestResult::Fail("overflow claim did not dedupe the same page");
    }
    if a.unmap_region(VirtAddr::new(base)).is_err() {
        return TestResult::Fail("failed to remove demand-overflow VMA");
    }
    let regions = a.regions.lock();
    if regions.demand_pages.len == 0 && regions.demand_pages.overflow.is_empty() {
        TestResult::Pass
    } else {
        TestResult::Fail("VMA removal left inline or overflow demand claims")
    }
}
kernel_test_in!(
    "memory",
    smoke_memory_demand_claim_inline_overflow_is_lossless
);

/// Ticket wrap must fail closed instead of reusing an identifier that could
/// let an old owner publish into a replacement VMA.
fn smoke_memory_demand_ticket_exhaustion_fails_closed() -> TestResult {
    let a = AddressSpace::empty();
    let base = 0x0000_0080_0040_0000u64;
    if a.map_region(Region {
        base: VirtAddr::new(base),
        len: 4096,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .is_err()
    {
        return TestResult::Fail("failed to install ticket-exhaustion region");
    }
    a.regions.lock().demand_pages.next_ticket = u64::MAX;
    if a.claim_demand_page(base, |_, _| Ok(())) != Err(AddressSpaceError::OutOfRange) {
        return TestResult::Fail("demand ticket wrapped instead of failing closed");
    }
    if a.regions.lock().demand_pages.get(base).is_some() {
        TestResult::Fail("ticket exhaustion installed an ownerless claim")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("memory", smoke_memory_demand_ticket_exhaustion_fails_closed);

/// Reserve pressure is a retryable demand-fault condition, while an ordinary
/// placement/range exhaustion remains the existing non-retryable surface.
fn smoke_memory_demand_pressure_is_distinct_from_range_failure() -> TestResult {
    if anonymous_demand_alloc_error(true) != AddressSpaceError::ReclaimPressure {
        return TestResult::Fail("reserve pressure was not classified for reclaim wait");
    }
    if anonymous_demand_alloc_error(false) != AddressSpaceError::OutOfRange {
        return TestResult::Fail("ordinary allocation failure became reclaim pressure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory",
    smoke_memory_demand_pressure_is_distinct_from_range_failure
);

/// Eager mlock converts allocation-shaped demand errors into its distinct
/// population-failure surface after VMA coverage has already been validated.
fn smoke_memory_mlock_population_error_is_typed() -> TestResult {
    if mlock_population_error(AddressSpaceError::OutOfRange) != AddressSpaceError::LockFailed
        || mlock_population_error(AddressSpaceError::ReclaimPressure)
            != AddressSpaceError::LockFailed
    {
        return TestResult::Fail("mlock allocation failure retained range errno semantics");
    }
    if mlock_population_error(AddressSpaceError::Unmapped) != AddressSpaceError::Unmapped {
        return TestResult::Fail("mlock coverage failure lost ENOMEM semantics");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_mlock_population_error_is_typed);

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
