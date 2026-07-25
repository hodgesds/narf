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

use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

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

    /// Internal flag: this region is `mlock`'d. The kernel ensures
    /// every page is backed (no zero entries in `phys`) and a
    /// future swap / page-reclaim pass will leave it alone.
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
    regions: IrqSafeSpinLock<Vec<Region>>,
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
            regions: IrqSafeSpinLock::new(Vec::new()),
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
        let Some(region) = regions.iter().find(|region| {
            let base = region.base.as_u64();
            page.as_u64() >= base && page.as_u64() < base.saturating_add(region.len)
        }) else {
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
        regions
            .iter()
            .filter(|region| {
                !region.perms.contains(RegionPerms::SHARED)
                    && !region.perms.contains(RegionPerms::LOCKED)
                    && region.perms.prot_only().0 != 0
            })
            .flat_map(|region| {
                region
                    .phys
                    .iter()
                    .enumerate()
                    .filter(|(_, phys)| phys.raw() != 0)
                    .map(|(index, _)| VirtAddr::new(region.base.as_u64() + (index as u64) * 4096))
            })
            .filter(|page| page.as_u64() >= start)
            .min_by_key(|page| page.as_u64())
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
            regions: IrqSafeSpinLock::new(Vec::new()),
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
            regions: IrqSafeSpinLock::new(Vec::new()),
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
        for r in regions.iter() {
            let r_end = r.base.as_u64() + r.len;
            if region.base.as_u64() < r_end && r.base.as_u64() < end {
                return Err(AddressSpaceError::Overlap);
            }
            // Diagnostic: catch the source of the double-free we
            // see in `AddressSpace::drop` — two regions in the
            // same AS pointing at the same physical frame would
            // be unmapped twice, double-freeing the phys. SHARED
            // regions borrow their frames (the registry owns them and
            // never lets the AS free them), so aliasing is expected and
            // safe — skip the guard for them.
            if region.perms.contains(RegionPerms::SHARED) {
                continue;
            }
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
        let (rb, rl) = (region.base.as_u64(), region.len);
        regions.push(region);
        drop(regions);
        // Keep the mmap-allocation cursor past anything mapped into the
        // mmap range so a later `reserve_mmap_va` can't collide with it.
        self.bump_mmap_cursor_past(rb, rl);
        Ok(())
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

        for (i, frame) in region.frames.iter().enumerate() {
            let va = VirtAddr::new(region.base.as_u64() + i as u64 * page_size);
            let result = self.map_huge_leaf(va, frame.phys(), region.size, region.perms);
            if result.is_err() {
                for j in 0..i {
                    let rollback_va = VirtAddr::new(region.base.as_u64() + j as u64 * page_size);
                    let _ = self.unmap_huge_leaf(rollback_va, region.size);
                }
                for frame in region.frames {
                    crate::hugepage::free_hugepage(frame);
                }
                return result;
            }
        }
        let (base, len) = (region.base.as_u64(), region.len);
        huge.push(region);
        drop(huge);
        self.bump_mmap_cursor_past(base, len);
        Ok(())
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
        let idx = regions
            .iter()
            .position(|r| r.base == base)
            .ok_or(AddressSpaceError::Unmapped)?;
        let old_len = regions[idx].len;
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
        // The grown tail [base+old_len, base+new_len) must not collide
        // with any OTHER region.
        let grow_lo = base.as_u64() + old_len;
        for (i, r) in regions.iter().enumerate() {
            if i == idx {
                continue;
            }
            let rb = r.base.as_u64();
            let re = rb + r.len;
            if rb < new_end && grow_lo < re {
                return Err(AddressSpaceError::Overlap);
            }
        }
        let add_pages = ((new_len - old_len) >> 12) as usize;
        let region = &mut regions[idx];
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
        let region = {
            let mut regions = self.regions.lock();
            let idx = regions
                .iter()
                .position(|r| r.base == base)
                .ok_or(AddressSpaceError::Unmapped)?;
            let region = regions.swap_remove(idx);
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
                // AS owned until the `swap_remove` above.
                unsafe { self.unmap_region_leaves_local(&region) };
            }
            region
        };
        // ONE cross-CPU invalidation BEFORE any frame is freed for reuse
        // (no-op unless the AS is CLONE_VM-shared — see vm_shared docs).
        self.flush_region_broadcast(region.base, (region.len + 0xFFF) >> 12);
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

        // A hardware huge leaf cannot be split into a differently-sized
        // mapping without first manufacturing replacement backing. Permit
        // MAP_FIXED to remove whole huge regions, but reject a partial cut.
        let removed_huge = {
            let mut huge = self.huge_regions.lock();
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
        let mut to_free: Vec<PhysAddr> = Vec::new();
        let mut punched_pages: u64 = 0;
        {
            let mut regions = self.regions.lock();
            let old_regions = core::mem::take(&mut *regions);
            let mut kept: Vec<Region> = Vec::with_capacity(old_regions.len());
            for old in old_regions {
                let rb = old.base.as_u64();
                let re = rb + old.len;
                if re <= lo || rb >= hi {
                    kept.push(old); // no overlap
                    continue;
                }
                let shared = old.perms.contains(RegionPerms::SHARED);
                let total = (old.len >> 12) as usize;
                for pg in 0..total {
                    let pv = rb + (pg as u64) * 4096;
                    if pv < lo || pv >= hi {
                        continue;
                    }
                    punched_pages += 1;
                    // Tear the leaf PTE down NOW, under the lock, with
                    // LOCAL invalidation only (one batched cross-CPU flush
                    // below). Doing it here — atomically with the table
                    // update — means no window ever exists where the table
                    // says "free" while a stale PTE lingers for a racing
                    // map_region+materialize to swallow via AlreadyMapped.
                    if self.root.as_u64() != 0 {
                        #[cfg(target_arch = "x86_64")]
                        // SAFETY: same identity-mapping precondition as
                        // `materialize`; `pv` was covered by the region
                        // being punched. Err (already absent) is benign.
                        let _ = unsafe {
                            crate::x86_64::paging::unmap_4kb_local(self.root, VirtAddr::new(pv))
                        };
                        #[cfg(target_arch = "aarch64")]
                        // SAFETY: see the x86_64 arm.
                        let _ = unsafe {
                            crate::aarch64::paging::unmap_4kb(self.root, VirtAddr::new(pv))
                        };
                    }
                    // Borrowed (SHARED) frames belong to an external
                    // registry — unmap the PTE but never free the phys.
                    if !shared {
                        if let Some(p) = old.phys.get(pg) {
                            if p.raw() != 0 {
                                to_free.push(*p);
                            }
                        }
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
            *regions = kept;
        }
        // ONE cross-CPU invalidation covering the punched window, BEFORE any
        // frame is freed for reuse (same mmu_gather shape + vm_shared gating
        // as `unmap_region_pages`). This also replaces the previous PER-PAGE
        // broadcast+ack-wait (`unmap_4kb`) a CLONE_VM AS paid here — an IPI
        // round-trip per punched page under MAP_FIXED churn.
        if punched_pages > 0 {
            self.flush_region_broadcast(base, (hi - lo) >> 12);
        }
        if self.root.as_u64() != 0 {
            for p in to_free {
                // `to_free` comes exclusively from `Region.phys`, whose
                // backing lists contain data frames only (same invariant as
                // `free_region_frames` below). A page-table frame cannot
                // appear here, so consulting the 16K-slot PT registry for
                // every punched page is both redundant and pathologically
                // expensive under Plasma's MAP_FIXED churn.
                crate::frame::free_frame(crate::frame::PhysFrame::new(p));
            }
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
                // SAFETY: CPL=0; flushes non-global entries — user PTEs are
                // never GLOBAL so the span's stale entries are covered.
                unsafe { crate::x86_64::paging::flush_user_tlb_all_cpus() };
            } else {
                // SAFETY: every page in the range was already unmapped /
                // rewritten by the caller; invlpg is unconditionally safe.
                unsafe { crate::x86_64::paging::invlpg_global_range(base, pages) };
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
        // Pass 3: free the frames this region owns.
        self.free_region_frames(region);
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    unsafe fn unmap_region_pages(&self, _region: &Region) {}

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
        use crate::x86_64::paging::unmap_4kb_local;
        let pages = (region.len + 0xFFF) >> 12;
        for i in 0..pages {
            let v = VirtAddr::new(region.base.as_u64() + (i << 12));
            // SAFETY: contract documented on the function; an `Err`
            // (already unmapped) is benign — frames are freed from
            // region.phys, not the PTE walk.
            let _ = unsafe { unmap_4kb_local(self.root, v) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn unmap_region_leaves_local(&self, region: &Region) {
        use crate::aarch64::paging::unmap_4kb;
        let pages = (region.len + 0xFFF) >> 12;
        for i in 0..pages {
            let v = VirtAddr::new(region.base.as_u64() + (i << 12));
            // SAFETY: see the x86_64 variant.
            let _ = unsafe { unmap_4kb(self.root, v) };
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    unsafe fn unmap_region_leaves_local(&self, _region: &Region) {}

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
        use crate::frame::{free_frame, PhysFrame};
        if region.perms.contains(RegionPerms::SHARED) {
            return;
        }
        let pages = (region.len + 0xFFF) >> 12;
        for i in 0..pages {
            let phys = match region.phys.get(i as usize) {
                Some(p) if p.raw() != 0 => *p,
                // Demand-paged-but-untouched (phys 0) or a length
                // mismatch: nothing this region owns to free here.
                _ => continue,
            };
            // No `__pagetable_is_registered` guard here: a region's
            // backing list only ever holds DATA frames (the loader,
            // demand_alloc, and cow_split all populate it), never a
            // page-table page — so the check could never fire, and at
            // O(PT_REGISTRY_LEN) per page it was a real teardown cost.
            free_frame(PhysFrame::new(phys));
        }
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
        self.regions.lock().iter().any(|region| {
            let base = region.base.as_u64();
            v >= base && v < base.saturating_add(region.len)
        })
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

    /// Demand-paging entry point — called from the user-mode #PF
    /// handler when CR2 (x86_64) / FAR_EL1 (aarch64) lands inside
    /// a known region whose `phys[i]` is the zero sentinel
    /// (lazy-allocated). Allocates a fresh zeroed frame, records
    /// it in the region's `phys` slot, and installs the leaf PTE
    /// with the region's perms.
    ///
    /// Returns `Ok(())` on a successful page-in (caller resumes
    /// the faulting instruction). Returns `Unmapped` if no
    /// region contains `vaddr` (genuine SEGV — caller falls
    /// through to its panic / signal path). Returns
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
        let mut regions = self.regions.lock();
        for r in regions.iter_mut() {
            let rb = r.base.as_u64();
            let re = rb.saturating_add(r.len);
            if v < rb || v >= re {
                continue;
            }
            // PROT_NONE: the fault is a real access violation, not
            // a demand-paging miss. Surface as Unmapped so the
            // trap handler reports the SEGV cleanly.
            if r.perms.prot_only().0 == 0 {
                return Err(AddressSpaceError::Unmapped);
            }
            let i = ((v - rb) >> 12) as usize;
            if i >= r.phys.len() {
                return Err(AddressSpaceError::OutOfRange);
            }
            if r.phys[i].raw() != 0 {
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
                let phys = r.phys[i];
                let mut flags = PtFlags::USER;
                if r.perms.contains(RegionPerms::WRITE) {
                    flags |= PtFlags::WRITABLE;
                }
                if !r.perms.contains(RegionPerms::EXEC) {
                    flags |= PtFlags::NO_EXEC;
                }
                // SAFETY: identity map + AS live (active CR3's #PF handler);
                // `phys` is the frame this region owns for the page.
                match unsafe { map_4kb(self.root, va, phys, flags) } {
                    Ok(()) | Err(MapError::AlreadyMapped) => return Ok(()),
                    Err(_) => return Err(AddressSpaceError::NotImplemented),
                }
            }
            // Allocate + zero the fresh frame, honoring the faulting
            // task's NUMA mempolicy (set_mempolicy/mbind). DEFAULT
            // resolves to the local node — today's behavior.
            let phys = crate::mempolicy::alloc_frame_policied(crate::frame::local_node())
                .map_err(|_| AddressSpaceError::OutOfRange)?
                .start_address();
            // SAFETY: identity-mapped DMA-equivalent; frame just
            // returned by allocator is exclusively ours.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                core::ptr::write_bytes(phys.raw() as *mut u8, 0, 4096);
            }
            r.phys[i] = phys;

            // Build PTE flags from region perms.
            let mut flags = PtFlags::USER;
            if r.perms.contains(RegionPerms::WRITE) {
                flags |= PtFlags::WRITABLE;
            }
            if !r.perms.contains(RegionPerms::EXEC) {
                flags |= PtFlags::NO_EXEC;
            }
            // SAFETY: identity map + AS is live (we're being
            // called from the active CR3's #PF handler).
            // SAFETY: Valid memory or trusted environment
            match unsafe { map_4kb(self.root, VirtAddr::new(v), phys, flags) } {
                Ok(()) | Err(MapError::AlreadyMapped) => return Ok(()),
                Err(_) => return Err(AddressSpaceError::NotImplemented),
            }
        }
        Err(AddressSpaceError::Unmapped)
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
        let mut regions = self.regions.lock();
        for r in regions.iter_mut() {
            let rb = r.base.as_u64();
            let re = rb.saturating_add(r.len);
            if v < rb || v >= re {
                continue;
            }
            if r.perms.prot_only().0 == 0 {
                return Err(AddressSpaceError::Unmapped);
            }
            let i = ((v - rb) >> 12) as usize;
            if i >= r.phys.len() {
                return Err(AddressSpaceError::OutOfRange);
            }
            if r.phys[i].raw() != 0 {
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
                    // SAFETY: TLBI VAE1 at EL1 is always legal; `v` is the
                    // page-aligned faulting VA owned by this AS.
                    unsafe {
                        crate::aarch64::paging::tlb_invalidate_vae1(va);
                    }
                    return Ok(());
                }
                let phys = r.phys[i];
                let mut flags = PtFlags::AP_RW_EL1;
                if !r.perms.contains(RegionPerms::EXEC) {
                    flags = flags | PtFlags::UXN | PtFlags::PXN;
                }
                // SAFETY: root valid + frame owned by this region (same
                // contract as the fresh-allocation path below).
                match unsafe { map_4kb(self.root, va, phys, flags) } {
                    Ok(()) | Err(MapError::AlreadyMapped) => return Ok(()),
                    Err(_) => return Err(AddressSpaceError::NotImplemented),
                }
            }
            let phys = crate::mempolicy::alloc_frame_policied(crate::frame::local_node())
                .map_err(|_| AddressSpaceError::OutOfRange)?
                .start_address();
            // SAFETY: identity-mapped per allocator contract.
            unsafe {
                core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096);
            }
            r.phys[i] = phys;
            let mut flags = PtFlags::AP_RW_EL1;
            if !r.perms.contains(RegionPerms::EXEC) {
                flags = flags | PtFlags::UXN | PtFlags::PXN;
            }
            // SAFETY: same.
            match unsafe { map_4kb(self.root, VirtAddr::new(v), phys, flags) } {
                Ok(()) | Err(MapError::AlreadyMapped) => return Ok(()),
                Err(_) => return Err(AddressSpaceError::NotImplemented),
            }
        }
        Err(AddressSpaceError::Unmapped)
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
        let idx = regions
            .iter()
            .position(|r| {
                r.perms.contains(RegionPerms::STACK_GUARD) && {
                    let gb = r.base.as_u64();
                    gb >= v_page && gb - v_page <= MAX_GROW
                }
            })
            .ok_or(AddressSpaceError::Unmapped)?;
        let guard_base = regions[idx].base.as_u64();
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
        for (i, r) in regions.iter().enumerate() {
            if i == idx {
                continue;
            }
            let rb = r.base.as_u64();
            let re = rb.saturating_add(r.len);
            if rb < guard_base && re > new_guard_base {
                return Err(AddressSpaceError::Overlap);
            }
        }

        // Promote: map every page from `v_page` up to and including the old
        // guard page (`guard_base`) as R+W stack, collecting their frames.
        let flags = PtFlags::USER | PtFlags::WRITABLE | PtFlags::NO_EXEC;
        let npages = ((guard_base - v_page) / 0x1000) + 1;
        let mut new_phys: alloc::vec::Vec<crate::PhysAddr> =
            alloc::vec::Vec::with_capacity(npages as usize);
        let mut p = v_page;
        while p <= guard_base {
            let phys = crate::frame::alloc_frame()
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
        regions[idx].base = VirtAddr::new(v_page);
        regions[idx].len = npages * 0x1000;
        regions[idx].perms = RegionPerms::READ | RegionPerms::WRITE;
        regions[idx].phys = new_phys;

        // Install a fresh one-page guard region below. Lazy phys
        // (the slot stays unbacked — guard pages never need a
        // backing frame until they themselves get promoted).
        regions.push(Region {
            base: VirtAddr::new(new_guard_base),
            len: 0x1000,
            perms: RegionPerms::STACK_GUARD,
            phys: alloc::vec![crate::PhysAddr::new(0)],
        });
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
        let idx = regions
            .iter()
            .position(|r| {
                r.perms.contains(RegionPerms::STACK_GUARD) && {
                    let gb = r.base.as_u64();
                    gb >= v_page && gb - v_page <= MAX_GROW
                }
            })
            .ok_or(AddressSpaceError::Unmapped)?;
        let guard_base = regions[idx].base.as_u64();
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
        for (i, r) in regions.iter().enumerate() {
            if i == idx {
                continue;
            }
            let rb = r.base.as_u64();
            let re = rb.saturating_add(r.len);
            if rb < guard_base && re > new_guard_base {
                return Err(AddressSpaceError::Overlap);
            }
        }

        let flags = PtFlags::AP_RW_EL1 | PtFlags::UXN | PtFlags::PXN;
        let npages = ((guard_base - v_page) / 0x1000) + 1;
        let mut new_phys: alloc::vec::Vec<crate::PhysAddr> =
            alloc::vec::Vec::with_capacity(npages as usize);
        let mut p = v_page;
        while p <= guard_base {
            let phys = crate::frame::alloc_frame()
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
        regions[idx].base = VirtAddr::new(v_page);
        regions[idx].len = npages * 0x1000;
        regions[idx].perms = RegionPerms::READ | RegionPerms::WRITE;
        regions[idx].phys = new_phys;

        regions.push(Region {
            base: VirtAddr::new(new_guard_base),
            len: 0x1000,
            perms: RegionPerms::STACK_GUARD,
            phys: alloc::vec![crate::PhysAddr::new(0)],
        });
        Ok(())
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub unsafe fn try_grow_stack(&self, _vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
        Err(AddressSpaceError::NotImplemented)
    }

    /// `mlock(base, len)` — force-back every lazy page in regions
    /// intersecting `[base, base + len)` and set the LOCKED flag.
    /// Returns Unmapped if no region intersects.
    pub fn mlock_range(&self, base: VirtAddr, len: u64) -> Result<(), AddressSpaceError> {
        let lo = base.as_u64();
        let hi = lo.saturating_add(len);
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
        let mut touched_any = false;
        let mut needed_vas: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
        {
            let g = self.regions.lock();
            for r in g.iter() {
                let rb = r.base.as_u64();
                let re = rb.saturating_add(r.len);
                if rb >= hi || re <= lo {
                    continue;
                }
                touched_any = true;
                for (i, p) in r.phys.iter().enumerate() {
                    if p.raw() == 0 {
                        needed_vas.push(rb + ((i as u64) << 12));
                    }
                }
            }
        }
        if !touched_any {
            return Err(AddressSpaceError::Unmapped);
        }
        // Allocate frames outside the lock.
        let mut allocations: alloc::vec::Vec<(u64, PhysAddr)> =
            alloc::vec::Vec::with_capacity(needed_vas.len());
        for va in needed_vas {
            let phys = crate::frame::alloc_frame()
                .map_err(|_| AddressSpaceError::OutOfRange)?
                .start_address();
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
        // Re-acquire the lock, stamp the new frames by VA + set the
        // LOCKED flag, then re-materialise (still under the lock — see
        // `change_perms_range` for why the rewrite must not run after the
        // lock drop) so PTEs land for the freshly-backed pages.
        let mut g = self.regions.lock();
        let mut stamped_bases: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
        for (va, phys) in allocations {
            let mut consumed = false;
            for r in g.iter_mut() {
                let rb = r.base.as_u64();
                let re = rb.saturating_add(r.len);
                if va < rb || va >= re {
                    continue;
                }
                let i = ((va - rb) >> 12) as usize;
                if i < r.phys.len() && r.phys[i].raw() == 0 {
                    r.phys[i] = phys;
                    consumed = true;
                    if !stamped_bases.contains(&rb) {
                        stamped_bases.push(rb);
                    }
                }
                break;
            }
            if !consumed {
                // Raced with a demand fault (or an unmap) that beat us to
                // this page — give the frame back.
                crate::frame::free_frame(crate::frame::PhysFrame::new(phys));
            }
        }
        // Flag every intersecting region LOCKED; collect the ones that
        // received fresh backing for the PTE rewrite.
        let mut to_materialise = alloc::vec::Vec::new();
        for r in g.iter_mut() {
            let rb = r.base.as_u64();
            let re = rb.saturating_add(r.len);
            if rb >= hi || re <= lo {
                continue;
            }
            r.perms = RegionPerms(r.perms.0 | RegionPerms::LOCKED.0);
            if stamped_bases.contains(&rb) {
                to_materialise.push(r.clone());
            }
        }
        // SAFETY: same identity-map invariant; touched regions
        // are valid bookkeeping entries.
        // SAFETY: Valid memory or trusted environment
        unsafe { self.rewrite_perms_pages(&to_materialise) };
        drop(g);
        Ok(())
    }

    /// `munlock(base, len)` — clear the LOCKED flag on every
    /// region intersecting `[base, base + len)`. Frames stay
    /// backed (no swap exists yet to reclaim them). Returns
    /// Unmapped if no region intersects.
    pub fn munlock_range(&self, base: VirtAddr, len: u64) -> Result<(), AddressSpaceError> {
        let lo = base.as_u64();
        let hi = lo.saturating_add(len);
        let mut g = self.regions.lock();
        let mut touched = false;
        for r in g.iter_mut() {
            let rb = r.base.as_u64();
            let re = rb.saturating_add(r.len);
            if rb >= hi || re <= lo {
                continue;
            }
            touched = true;
            r.perms = RegionPerms(r.perms.0 & !RegionPerms::LOCKED.0);
        }
        if !touched {
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
        let mut hits = Vec::new();
        for r in g.iter_mut() {
            let rb = r.base.as_u64();
            let re = rb.saturating_add(r.len);
            if rb >= hi || re <= lo {
                continue;
            }
            r.perms = new_perms;
            hits.push(r.clone());
        }
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
    /// - `Ok(())` on a successful change covering ≥ 1 page.
    /// - `Err(Unmapped)` if no region intersects the request.
    /// - `Err(AlignmentMismatch)` if `base` or `len` is not page-
    ///   aligned, or if `new_perms` carries `WRITE | EXEC` (W^X).
    #[cfg(feature = "linux-compat")]
    pub fn mprotect_range(
        &self,
        base: VirtAddr,
        len: u64,
        new_perms: RegionPerms,
    ) -> Result<(), AddressSpaceError> {
        // W^X: reject WRITE | EXEC outright. Used by sys_mprotect's
        // cap-free fast path; CAP_JIT-gated RW→RX transitions go
        // through a separate cap-checked entry.
        let prot = new_perms.prot_only();
        if prot.contains(RegionPerms::WRITE | RegionPerms::EXEC) {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        // Page-align the request. Linux mprotect(2) requires
        // `addr` to be page-aligned; `len` is rounded up by the
        // libc caller but we reject silently-misaligned lengths
        // so callers learn early.
        if base.as_u64() & 0xFFF != 0 || len & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        if len == 0 {
            return Err(AddressSpaceError::Unmapped);
        }
        let lo = base.as_u64();
        let hi = lo.saturating_add(len);

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
        let touched: Vec<Region> = {
            // Collect indices that intersect [lo, hi). Walk forward
            // and split in place — we drain the original Vec into
            // `new_list` so the bookkeeping stays consistent even
            // if a region's head fragment is empty (drop entirely).
            let originals: Vec<Region> = core::mem::take(&mut *g);
            let mut new_list: Vec<Region> = Vec::with_capacity(originals.len() + 2);
            let mut hits: Vec<Region> = Vec::new();
            for r in originals.into_iter() {
                let rb = r.base.as_u64();
                let re = rb.saturating_add(r.len);
                if rb >= hi || re <= lo {
                    // No intersection — keep verbatim.
                    new_list.push(r);
                    continue;
                }

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
            *g = new_list;
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
    /// - `Ok(())` on a successful pass over ≥ 1 region.
    /// - `Err(Unmapped)` if no region intersects the request.
    /// - `Err(AlignmentMismatch)` for misaligned `base` / `len`.
    #[cfg(feature = "linux-compat")]
    pub fn madvise_dontneed(&self, base: VirtAddr, len: u64) -> Result<(), AddressSpaceError> {
        if base.as_u64() & 0xFFF != 0 || len & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        if len == 0 {
            return Err(AddressSpaceError::Unmapped);
        }
        let lo = base.as_u64();
        let hi = lo.saturating_add(len);

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
        let mut to_release: Vec<PhysAddr> = Vec::new();
        let mut touched = false;
        {
            let mut g = self.regions.lock();
            for r in g.iter_mut() {
                let rb = r.base.as_u64();
                let re = rb.saturating_add(r.len);
                if rb >= hi || re <= lo {
                    continue;
                }
                touched = true;
                // LOCKED region — hint is honoured as a no-op so
                // mlock'd pages stay resident.
                if r.perms.contains(RegionPerms::LOCKED) {
                    continue;
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
                    continue;
                }
                let start_v = lo.max(rb);
                let end_v = hi.min(re);
                let start_i = ((start_v - rb) >> 12) as usize;
                let end_i = ((end_v - rb) >> 12) as usize;
                for i in start_i..end_i {
                    let p = r.phys[i];
                    if p.raw() == 0 {
                        continue;
                    }
                    let v = rb + ((i as u64) << 12);
                    if self.root.as_u64() != 0 {
                        #[cfg(target_arch = "x86_64")]
                        // SAFETY: identity-mapped; `v` lies in a bookkept
                        // region of this AS. LOCAL invalidation only —
                        // one batched cross-CPU flush below.
                        let _ = unsafe {
                            crate::x86_64::paging::unmap_4kb_local(self.root, VirtAddr::new(v))
                        };
                        #[cfg(target_arch = "aarch64")]
                        // SAFETY: see the x86_64 arm.
                        let _ = unsafe {
                            crate::aarch64::paging::unmap_4kb(self.root, VirtAddr::new(v))
                        };
                    }
                    to_release.push(p);
                    r.phys[i] = PhysAddr::new(0);
                }
            }
        }
        if !touched {
            return Err(AddressSpaceError::Unmapped);
        }
        // ONE cross-CPU invalidation over the advised span BEFORE any
        // frame is freed for reuse (no-op unless CLONE_VM-shared).
        if !to_release.is_empty() {
            self.flush_region_broadcast(base, (hi - lo) >> 12);
        }
        if self.root.as_u64() != 0 {
            for p in to_release {
                // `to_release` is sourced only from `Region.phys`; page-table
                // frames are never stored there. Keep madvise(DONTNEED)
                // proportional to the advised pages instead of scanning the
                // global 16K-entry PT registry once per page.
                // `free_frame` consults the COW refcount table, so a frame
                // still shared with another AS stays live until its last
                // owner releases it.
                crate::frame::free_frame(crate::frame::PhysFrame::new(p));
            }
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
            flush_user_tlb_all_cpus, invlpg_global_range, map_4kb, unmap_4kb_local, PtFlags,
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
                for i in 0..r.phys.len() {
                    let v = VirtAddr::new(r.base.as_u64() + ((i as u64) << 12));
                    // SAFETY: same identity-map invariant.
                    let _ = unsafe { unmap_4kb_local(self.root, v) };
                }
            } else {
                let mut flags = PtFlags::USER;
                if r.perms.contains(RegionPerms::WRITE) {
                    flags |= PtFlags::WRITABLE;
                }
                if !r.perms.contains(RegionPerms::EXEC) {
                    flags |= PtFlags::NO_EXEC;
                }
                for (i, p) in r.phys.iter().enumerate() {
                    // Skip demand-paged pages (phys == 0). They are
                    // NOT currently mapped (materialize skips them),
                    // so unmap_4kb would be a no-op and map_4kb would
                    // incorrectly install a PTE pointing at physical
                    // address 0 (BIOS/firmware area), corrupting the
                    // address space. Demand-paged pages get their
                    // real PTEs installed by `demand_alloc_page` on
                    // first user-mode access — no action needed here.
                    if p.raw() == 0 {
                        continue;
                    }
                    let v = VirtAddr::new(r.base.as_u64() + ((i as u64) << 12));
                    // SAFETY: identity-mapped; v lies inside r which
                    // was bookkept by a prior map_region.
                    // SAFETY: Valid memory or trusted environment
                    let _ = unsafe { unmap_4kb_local(self.root, v) };
                    // SAFETY: same.
                    let _ = unsafe { map_4kb(self.root, v, *p, flags) };
                }
            }
            let region_pages = (r.len + 0xFFF) >> 12;
            if broadcast && !use_full_flush && region_pages > 0 {
                // SAFETY: the pages in the range were rewritten above;
                // invlpg is unconditionally safe.
                unsafe { invlpg_global_range(r.base, region_pages) };
            }
        }
        if use_full_flush {
            // SAFETY: CPL=0; user PTEs are never GLOBAL, so a non-global
            // flush covers every stale entry this walk left on any CPU.
            unsafe { flush_user_tlb_all_cpus() };
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn rewrite_perms_pages(&self, regions: &[Region]) {
        use crate::aarch64::paging::{map_4kb, unmap_4kb, PtFlags};
        if self.root.as_u64() == 0 {
            return;
        }
        for r in regions {
            if r.perms.prot_only().0 == 0 {
                for i in 0..r.phys.len() {
                    let v = VirtAddr::new(r.base.as_u64() + ((i as u64) << 12));
                    // SAFETY: see x86_64 variant.
                    let _ = unsafe { unmap_4kb(self.root, v) };
                }
                continue;
            }
            let mut flags = PtFlags::AP_RW_EL1;
            if !r.perms.contains(RegionPerms::EXEC) {
                flags = flags | PtFlags::UXN | PtFlags::PXN;
            }
            for (i, p) in r.phys.iter().enumerate() {
                let v = VirtAddr::new(r.base.as_u64() + ((i as u64) << 12));
                // SAFETY: see x86_64 variant.
                let _ = unsafe { unmap_4kb(self.root, v) };
                // SAFETY: same.
                let _ = unsafe { map_4kb(self.root, v, *p, flags) };
            }
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    unsafe fn rewrite_perms_pages(&self, _regions: &[Region]) {}

    /// Snapshot of the region list — returns an owned `Vec<Region>`
    /// so callers can iterate without holding the lock.
    pub fn regions_snapshot(&self) -> Vec<Region> {
        self.regions.lock().clone()
    }

    /// Materialise all pending regions into actual page-table entries.
    /// Walks each region's pages and calls `map_4kb` on the AS's
    /// root translation table — PML4 on x86_64, L0 on aarch64.
    ///
    /// # Safety
    /// The AS must have been constructed via `new_for_user` (so
    /// `root` points at a valid full-copy PML4). Repeated calls are
    /// idempotent — `map_4kb` returns `AlreadyMapped` on the second
    /// pass and this surface treats it as success.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn materialize(&self) -> Result<(), AddressSpaceError> {
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
            let mut flags = PtFlags::USER;
            if r.perms.contains(RegionPerms::WRITE) {
                flags |= PtFlags::WRITABLE;
            }
            if !r.perms.contains(RegionPerms::EXEC) {
                flags |= PtFlags::NO_EXEC;
            }

            for (i, p) in r.phys.iter().enumerate() {
                // Lazy / unbacked: phys[i] == 0 means the
                // demand-paging path will allocate + install on
                // first user-mode access. Skip here so the PTE
                // stays absent and the access faults with P=0.
                if p.raw() == 0 {
                    continue;
                }
                let v = crate::VirtAddr::new(r.base.as_u64() + ((i as u64) << 12));
                // SAFETY: `self.root` is a valid PML4 per the
                // `new_for_user` contract; pages walked are within
                // the region we're materialising. `phys[i]` was
                // length-checked against `len/4096` at map_region.
                // SAFETY: Valid memory or trusted environment
                match unsafe { map_4kb(self.root, v, *p, flags) } {
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
            }
        }
        Ok(())
    }

    /// # Safety
    /// The AS must have been constructed via `new_for_user` (so `root`
    /// points at a valid `TTBR0_EL1` L0 table). Repeated calls are
    /// idempotent — `map_4kb` returns `AlreadyMapped` on the second pass
    /// and this surface treats it as success.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn materialize(&self) -> Result<(), AddressSpaceError> {
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
            // aarch64 perm translation:
            // - AP_RW_EL1 = kernel-writable; for user the AP field
            //   changes to RW-EL1/EL0 (0b01<<6). For now Stage-4
            //   structural keeps the kernel-mode bit; true EL0
            //   access lands with full user-mode enablement.
            // - UXN+PXN disable exec at the respective ELs; we set
            //   UXN unless `perms.contains(EXEC)`.
            let mut flags = PtFlags::AP_RW_EL1;
            if !r.perms.contains(RegionPerms::EXEC) {
                flags = flags | PtFlags::UXN | PtFlags::PXN;
            }
            for (i, p) in r.phys.iter().enumerate() {
                if p.raw() == 0 {
                    continue;
                }
                let v = crate::VirtAddr::new(r.base.as_u64() + ((i as u64) << 12));
                // SAFETY: root is valid per `new_for_user`; pages
                // covered are within the just-allocated region.
                // `phys[i]` length was checked at map_region.
                // SAFETY: Valid memory or trusted environment
                match unsafe { map_4kb(self.root, v, *p, flags) } {
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
            }
        }
        Ok(())
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub unsafe fn materialize(&self) -> Result<(), AddressSpaceError> {
        Err(AddressSpaceError::NotImplemented)
    }

    /// Force-rewrite every existing PTE to match the current region
    /// permission metadata. Unlike [`materialize`] (which skips
    /// already-mapped pages), this tears down and reinstalls every
    /// leaf PTE so stale permission bits (e.g. WRITE still set in
    /// old PTEs after `clone_for_fork` stripped WRITE from regions)
    /// are corrected.
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
    /// - May be called while `self` is the active CR3 — the `invlpg`
    ///   issued by `unmap_4kb` / `map_4kb` flushes each TLB entry.
    ///   Single-CPU Stage-4 BSP-only.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn rematerialize(&self) -> Result<(), AddressSpaceError> {
        // Hold the regions lock across the rewrite: cloning a snapshot and
        // rewriting after the drop (the previous shape) let a racing
        // munmap/MAP_FIXED overlap from a sibling thread free a frame and
        // then have the deferred rewrite re-install a PTE over it. See
        // `change_perms_range` for why the under-lock batched flush is
        // deadlock-safe.
        let g = self.regions.lock();
        // SAFETY: identity-map live; `root` valid from `new_for_user`.
        unsafe { self.rewrite_perms_pages(g.as_slice()) };
        drop(g);
        Ok(())
    }

    /// # Safety
    /// Non-x86_64 stub: a no-op that never touches page tables, so it has
    /// no preconditions. Present only to keep the per-arch API uniform.
    #[cfg(not(target_arch = "x86_64"))]
    pub unsafe fn rematerialize(&self) -> Result<(), AddressSpaceError> {
        Ok(())
    }

    /// Duplicate this address space for a `fork(2)`-style child.
    ///
    /// **Copy-on-write.** Per region, the child shares the
    /// parent's physical frames — `frame::cow::inc_ref(phys)` is
    /// called on every page so the frame allocator knows two
    /// owners (or more, for nested forks) share the page. The
    /// returned `AddressSpace` carries the same `Region.phys` Vec
    /// (cloned) as the parent and an extra cleared-WRITE flag in
    /// `Region.perms`. The parent's regions are mutated in place
    /// to also drop WRITE; both sides re-materialise lazily (the
    /// caller's `materialize()` runs the page-table walk that
    /// installs the read-only PTEs).
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

        // Mutate the parent's region table in place: drop WRITE
        // on every region so the next `materialize()` installs RO
        // PTEs and the first write traps. Snapshot the resulting
        // region list to clone into the child.
        let parent_regions: Vec<Region> = {
            let mut g = self.regions.lock();
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
                // frame, then strip WRITE so both ASes start the post-fork
                // window read-only and split on first write.
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
                for &p in r.phys.iter() {
                    if p.raw() == 0 {
                        continue;
                    }
                    let _ = crate::frame::cow::inc_ref(p);
                }
                r.perms = RegionPerms(r.perms.0 & !RegionPerms::WRITE.0);
            }
            g.clone()
        };

        // The child's regions are a deep clone of the parent's
        // (post-strip) — same vaddr base, same phys list, same
        // (now WRITE-stripped) perms.
        for r in parent_regions.into_iter() {
            child.map_region(r)?;
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
    /// `dec_ref` the old frame, and re-mark the region's perms
    /// with WRITE. The caller is responsible for re-materialising
    /// the affected page in the live page-table tree (a real
    /// page-fault handler would do that on the way back out of
    /// the trap).
    ///
    /// Returns `Unmapped` if no region contains `vaddr`.
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
        let mut g = self.regions.lock();
        let v = vaddr.as_u64();
        let region_idx = g
            .iter()
            .position(|r| {
                let base = r.base.as_u64();
                v >= base && v < base + r.len
            })
            .ok_or(AddressSpaceError::Unmapped)?;
        let page_idx = ((v - g[region_idx].base.as_u64()) >> 12) as usize;
        let old_phys = g[region_idx].phys[page_idx];

        // If this frame's refcount is 1 (we're sole owner), just
        // regain WRITE on the region. The dec_ref returns 0 in
        // that case (post-decrement); we re-bump because we still
        // own it.
        let count = crate::frame::cow::count(old_phys);
        if count <= 1 {
            // Sole owner — no copy needed.
            g[region_idx].perms = g[region_idx].perms | RegionPerms::WRITE;
            return Ok(());
        }

        // Multiple owners. Allocate a private frame, copy bytes,
        // dec_ref the shared one.
        let new_frame = crate::frame::alloc_frame().map_err(|_| AddressSpaceError::OutOfRange)?;
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
        let _new_count = crate::frame::cow::dec_ref(old_phys);
        g[region_idx].phys[page_idx] = new_phys;
        g[region_idx].perms = g[region_idx].perms | RegionPerms::WRITE;
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

        let new_frame = crate::frame::alloc_frame_on_strict(target_node)
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
                if region.perms.contains(RegionPerms::WRITE) {
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
                let mut flags = PtFlags::AP_RW_EL1;
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
                if region.perms.contains(RegionPerms::WRITE) {
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
                let mut flags = PtFlags::AP_RW_EL1;
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

        self.flush_region_broadcast(page_va, 1);
        crate::frame::free_frame(crate::frame::PhysFrame::new(old_phys));
        Ok(old_node)
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
        if region.perms.contains(RegionPerms::WRITE) {
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
        let mut flags = PtFlags::AP_RW_EL1;
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
    /// aarch64 issues `MSR TTBR0_EL1` with the architected
    /// MSR + DSB + TLBI + ISB sequence (see
    /// `aarch64::paging::write_ttbr0_el1`).
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
            // DIAGNOSTIC: write the CURRENT TTBR0 back to itself,
            // exercising the MSR + TLBI path without actually
            // changing the mapping. If this hangs, the issue is
            // the asm sequence or the TLBI itself — not the new
            // user-AS mapping.
            // SAFETY: ttbr0 read is unconditional.
            let cur = unsafe { crate::aarch64::paging::read_ttbr0_el1() };
            // SAFETY: writes the value just read from `TTBR0_EL1` straight
            // back, so the active low-half translation is unchanged; the
            // accompanying TLBI only flushes entries that are re-derived
            // identically. The kernel half lives in `TTBR1_EL1` and is
            // untouched, so kernel fetches/loads stay valid across the MSR.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                crate::aarch64::paging::write_ttbr0_el1(cur);
            }
            let _ = self.root;
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
        for r in regions.iter() {
            // SAFETY: see unmap_region_pages — same identity-map
            // contract; no CPU is using self.root at this point
            // since we're past the last Arc reference.
            // SAFETY: Valid memory or trusted environment
            unsafe { self.unmap_region_pages(r) };
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
    }
}
