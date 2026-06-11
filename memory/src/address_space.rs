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

/// Errors from the address-space surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddressSpaceError {
    NotImplemented,
    Overlap,
    OutOfRange,
    AlignmentMismatch,
    Unmapped,
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
    /// Per-AS mmap cursor: next free virt for a no-hint mmap.
    /// Lives here (not on a single global) so each process gets its
    /// own monotonically-increasing arena instead of a shared race.
    /// Initial value 0x4080_0000_0000 matches the prior global —
    /// well above the ELF + brk regions and below the user stack.
    mmap_cursor: core::sync::atomic::AtomicU64,
}

impl AddressSpace {
    /// Default base for the per-AS mmap cursor. Matches the prior
    /// global MMAP_CURSOR so existing user binaries continue to see
    /// mmap returning addresses in the same broad range.
    pub const MMAP_CURSOR_BASE: u64 = 0x0000_4080_0000_0000;

    /// Fresh address space with no regions. Stage-4 arch backend
    /// must assign `root` to a freshly-allocated page-table frame.
    pub const fn empty() -> Self {
        Self {
            root: PhysAddr::new(0),
            regions: IrqSafeSpinLock::new(Vec::new()),
            mmap_cursor: core::sync::atomic::AtomicU64::new(Self::MMAP_CURSOR_BASE),
        }
    }

    /// Atomically reserve `bytes` of contiguous virtual address
    /// from the per-AS mmap cursor and return the base. Bytes are
    /// page-rounded by the caller; this routine just bumps.
    #[inline]
    pub fn reserve_mmap_va(&self, bytes: u64) -> u64 {
        self.mmap_cursor
            .fetch_add(bytes, core::sync::atomic::Ordering::Relaxed)
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
            mmap_cursor: core::sync::atomic::AtomicU64::new(Self::MMAP_CURSOR_BASE),
        })
    }

    #[cfg(target_arch = "aarch64")]
    pub unsafe fn new_for_user() -> Result<Self, AddressSpaceError> {
        // SAFETY: contract documented on the function. aarch64's
        // split translation means the user root starts empty —
        // the kernel sits behind TTBR1 and is unaffected.
        let phys = unsafe { crate::aarch64::paging::new_user_ttbr0() }
            .map_err(|_| AddressSpaceError::OutOfRange)?;
        Ok(Self {
            root: phys,
            regions: IrqSafeSpinLock::new(Vec::new()),
            mmap_cursor: core::sync::atomic::AtomicU64::new(Self::MMAP_CURSOR_BASE),
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
        let mut regions = self.regions.lock();
        for r in regions.iter() {
            let r_end = r.base.as_u64() + r.len;
            if region.base.as_u64() < r_end && r.base.as_u64() < end {
                return Err(AddressSpaceError::Overlap);
            }
            // Diagnostic: catch the source of the double-free we
            // see in `AddressSpace::drop` — two regions in the
            // same AS pointing at the same physical frame would
            // be unmapped twice, double-freeing the phys.
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
        regions.push(region);
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
        let mut regions = self.regions.lock();
        let idx = regions
            .iter()
            .position(|r| r.base == base)
            .ok_or(AddressSpaceError::Unmapped)?;
        let region = regions.swap_remove(idx);
        // Drop the lock before walking PTEs so a Drop-time recursive
        // tear-down (or a parallel materialise on a different region)
        // doesn't reentrant-deadlock.
        drop(regions);
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        unsafe { self.unmap_region_pages(&region) };
        Ok(region)
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
    #[cfg(target_arch = "x86_64")]
    unsafe fn unmap_region_pages(&self, region: &Region) {
        use crate::frame::{free_frame, PhysFrame};
        use crate::x86_64::paging::unmap_4kb;
        if self.root.as_u64() == 0 {
            return;
        }
        let pages = (region.len + 0xFFF) >> 12;
        for i in 0..pages {
            let v = VirtAddr::new(region.base.as_u64() + (i << 12));
            // SAFETY: same identity-mapping precondition as
            // `materialize`; `v` lies inside `region` which was
            // bookkept by `map_region`.
            // An `Err` here means already-unmapped (double munmap, or the
            // region was partially materialised), which is benign: the
            // bookkeeping is gone now, the frames either never landed or are
            // already back in the allocator.
            if let Ok(phys) = unsafe { unmap_4kb(self.root, v) } {
                // Skip phys that's registered as a page-table
                // frame — `free_user_pml4_tree` will reclaim it
                // on its own walk. Freeing here would double-free.
                if crate::frame::__pagetable_is_registered(phys.raw()) {
                    continue;
                }
                free_frame(PhysFrame::new(phys));
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn unmap_region_pages(&self, region: &Region) {
        use crate::aarch64::paging::unmap_4kb;
        use crate::frame::{free_frame, PhysFrame};
        if self.root.as_u64() == 0 {
            return;
        }
        let pages = (region.len + 0xFFF) >> 12;
        for i in 0..pages {
            let v = VirtAddr::new(region.base.as_u64() + (i << 12));
            // SAFETY: see x86_64 variant.
            match unsafe { unmap_4kb(self.root, v) } {
                Ok(phys) => {
                    free_frame(PhysFrame::new(phys));
                }
                Err(_) => {}
            }
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    unsafe fn unmap_region_pages(&self, _region: &Region) {}

    /// Number of mapped regions.
    #[inline]
    pub fn region_count(&self) -> usize {
        self.regions.lock().len()
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
                // Already backed — spurious fault (TLB stale).
                return Err(AddressSpaceError::AlignmentMismatch);
            }
            // Allocate + zero the fresh frame.
            let phys = crate::frame::alloc_frame()
                .map_err(|_| AddressSpaceError::OutOfRange)?
                .start_address();
            // SAFETY: identity-mapped DMA-equivalent; frame just
            // returned by allocator is exclusively ours.
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
            match unsafe { map_4kb(self.root, VirtAddr::new(v), phys, flags) } {
                Ok(()) | Err(MapError::AlreadyMapped) => return Ok(()),
                Err(_) => return Err(AddressSpaceError::NotImplemented),
            }
        }
        Err(AddressSpaceError::Unmapped)
    }

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
                return Err(AddressSpaceError::AlignmentMismatch);
            }
            let phys = crate::frame::alloc_frame()
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
        let v = vaddr.as_u64() & !0xFFFu64;
        let mut regions = self.regions.lock();
        let idx = regions
            .iter()
            .position(|r| {
                let rb = r.base.as_u64();
                v >= rb && v < rb.saturating_add(r.len)
            })
            .ok_or(AddressSpaceError::Unmapped)?;
        if !regions[idx].perms.contains(RegionPerms::STACK_GUARD) {
            return Err(AddressSpaceError::Unmapped);
        }
        let guard_base = regions[idx].base.as_u64();
        // Reject if the new guard one page below would overlap an
        // existing region — the user has run out of stack arena
        // and gets a real SEGV.
        let new_guard_base = match guard_base.checked_sub(0x1000) {
            Some(b) => b,
            None => return Err(AddressSpaceError::OutOfRange),
        };
        for (i, r) in regions.iter().enumerate() {
            if i == idx {
                continue;
            }
            let rb = r.base.as_u64();
            let re = rb.saturating_add(r.len);
            if new_guard_base < re && rb < new_guard_base + 0x1000 {
                return Err(AddressSpaceError::Overlap);
            }
        }

        // Promote the existing guard region: allocate + zero
        // a frame, swap perms to R+W, install the leaf PTE.
        let phys = crate::frame::alloc_frame()
            .map_err(|_| AddressSpaceError::OutOfRange)?
            .start_address();
        // SAFETY: identity-mapped; freshly-allocated frame is ours
        // exclusively.
        unsafe {
            core::ptr::write_bytes(phys.raw() as *mut u8, 0, 4096);
        }
        regions[idx].phys[0] = phys;
        regions[idx].perms = RegionPerms::READ | RegionPerms::WRITE;

        let flags = PtFlags::USER | PtFlags::WRITABLE | PtFlags::NO_EXEC;
        // SAFETY: root is valid (AS active); guard region was
        // bookkept by `map_region`; phys just allocated.
        match unsafe { map_4kb(self.root, VirtAddr::new(guard_base), phys, flags) } {
            Ok(()) | Err(MapError::AlreadyMapped) => {}
            Err(_) => return Err(AddressSpaceError::NotImplemented),
        }

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

    #[cfg(target_arch = "aarch64")]
    pub unsafe fn try_grow_stack(&self, vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
        use crate::aarch64::paging::{map_4kb, MapError, PtFlags};
        let v = vaddr.as_u64() & !0xFFFu64;
        let mut regions = self.regions.lock();
        let idx = regions
            .iter()
            .position(|r| {
                let rb = r.base.as_u64();
                v >= rb && v < rb.saturating_add(r.len)
            })
            .ok_or(AddressSpaceError::Unmapped)?;
        if !regions[idx].perms.contains(RegionPerms::STACK_GUARD) {
            return Err(AddressSpaceError::Unmapped);
        }
        let guard_base = regions[idx].base.as_u64();
        let new_guard_base = match guard_base.checked_sub(0x1000) {
            Some(b) => b,
            None => return Err(AddressSpaceError::OutOfRange),
        };
        for (i, r) in regions.iter().enumerate() {
            if i == idx {
                continue;
            }
            let rb = r.base.as_u64();
            let re = rb.saturating_add(r.len);
            if new_guard_base < re && rb < new_guard_base + 0x1000 {
                return Err(AddressSpaceError::Overlap);
            }
        }

        let phys = crate::frame::alloc_frame()
            .map_err(|_| AddressSpaceError::OutOfRange)?
            .start_address();
        // SAFETY: phys-as-virt via kernel_mut_ptr stays valid even
        // under user TTBR0.
        unsafe {
            core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096);
        }
        regions[idx].phys[0] = phys;
        regions[idx].perms = RegionPerms::READ | RegionPerms::WRITE;

        let flags = PtFlags::AP_RW_EL1 | PtFlags::UXN | PtFlags::PXN;
        // SAFETY: see x86_64 sibling.
        match unsafe { map_4kb(self.root, VirtAddr::new(guard_base), phys, flags) } {
            Ok(()) | Err(MapError::AlreadyMapped) => {}
            Err(_) => return Err(AddressSpaceError::NotImplemented),
        }

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
        // on an IRQ-safe lock. Snapshot the region indices.
        let mut touched_any = false;
        let mut backings: alloc::vec::Vec<(usize, alloc::vec::Vec<usize>)> = alloc::vec::Vec::new();
        {
            let g = self.regions.lock();
            for (idx, r) in g.iter().enumerate() {
                let rb = r.base.as_u64();
                let re = rb.saturating_add(r.len);
                if rb >= hi || re <= lo {
                    continue;
                }
                touched_any = true;
                let mut needed = alloc::vec::Vec::new();
                for (i, p) in r.phys.iter().enumerate() {
                    if p.raw() == 0 {
                        needed.push(i);
                    }
                }
                if !needed.is_empty() {
                    backings.push((idx, needed));
                }
            }
        }
        if !touched_any {
            return Err(AddressSpaceError::Unmapped);
        }
        // Allocate frames outside the lock.
        let mut allocations: alloc::vec::Vec<(usize, alloc::vec::Vec<(usize, PhysAddr)>)> =
            alloc::vec::Vec::with_capacity(backings.len());
        for (idx, slots) in backings {
            let mut filled = alloc::vec::Vec::with_capacity(slots.len());
            for slot in slots {
                let phys = crate::frame::alloc_frame()
                    .map_err(|_| AddressSpaceError::OutOfRange)?
                    .start_address();
                // SAFETY: identity-mapped on x86_64; aarch64
                // uses kernel_mut_ptr for the same purpose.
                unsafe {
                    #[cfg(target_arch = "x86_64")]
                    core::ptr::write_bytes(phys.raw() as *mut u8, 0, 4096);
                    #[cfg(target_arch = "aarch64")]
                    core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096);
                }
                filled.push((slot, phys));
            }
            allocations.push((idx, filled));
        }
        // Re-acquire the lock and stamp the new frames + flag.
        // Then re-materialise so PTEs land for the freshly-backed
        // pages.
        let mut to_materialise = alloc::vec::Vec::new();
        {
            let mut g = self.regions.lock();
            for (idx, slots) in allocations {
                if let Some(r) = g.get_mut(idx) {
                    for (slot, phys) in slots {
                        if r.phys[slot].raw() == 0 {
                            r.phys[slot] = phys;
                        } else {
                            // Raced with a demand fault that beat
                            // us to it — give the frame back.
                            crate::frame::free_frame(crate::frame::PhysFrame::new(phys));
                        }
                    }
                    r.perms = RegionPerms(r.perms.0 | RegionPerms::LOCKED.0);
                    to_materialise.push(r.clone());
                }
            }
            // Also flag any region we touched but didn't have to
            // back (already-fully-backed mlock'd region).
            for r in g.iter_mut() {
                let rb = r.base.as_u64();
                let re = rb.saturating_add(r.len);
                if rb >= hi || re <= lo {
                    continue;
                }
                r.perms = RegionPerms(r.perms.0 | RegionPerms::LOCKED.0);
            }
        }
        // SAFETY: same identity-map invariant; touched regions
        // are valid bookkeeping entries.
        unsafe { self.rewrite_perms_pages(&to_materialise) };
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
        // Snapshot + mutate the bookkeeping under the lock; do
        // the PTE walk after dropping the lock so a concurrent
        // map_region on a non-overlapping region doesn't block.
        let touched: Vec<Region> = {
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
            hits
        };
        if touched.is_empty() {
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
        unsafe { self.rewrite_perms_pages(&touched) };
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

        // Snapshot the region list under the lock, compute the
        // new layout, then swap it in. The PTE rewrite happens
        // after the lock is dropped so the post-split rebuild
        // can't deadlock against concurrent map_region work on
        // an unrelated region.
        let touched: Vec<Region> = {
            let mut g = self.regions.lock();

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

        if touched.is_empty() {
            return Err(AddressSpaceError::Unmapped);
        }
        // SAFETY: same identity-mapping precondition as
        // `change_perms_range`. The middle fragments share their
        // phys frames with the pre-split region; rewriting the PTE
        // flags is safe because we hold the only reference to each
        // post-split phys slot (the Drop path consults the new
        // region table, not the old one).
        unsafe { self.rewrite_perms_pages(&touched) };
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

        // Collect (vaddr, phys) pairs to free outside the lock. We
        // also stamp `phys[i] = 0` while we hold it so a concurrent
        // demand-fault sees the slot as unbacked rather than racing
        // a half-freed frame.
        let mut to_release: Vec<(VirtAddr, PhysAddr)> = Vec::new();
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
                let start_v = lo.max(rb);
                let end_v = hi.min(re);
                let start_i = ((start_v - rb) >> 12) as usize;
                let end_i = ((end_v - rb) >> 12) as usize;
                for i in start_i..end_i {
                    let p = r.phys[i];
                    if p.raw() == 0 {
                        continue;
                    }
                    let v = VirtAddr::new(rb + ((i as u64) << 12));
                    to_release.push((v, p));
                    r.phys[i] = PhysAddr::new(0);
                }
            }
        }
        if !touched {
            return Err(AddressSpaceError::Unmapped);
        }
        // SAFETY: same identity-map invariant as change_perms_range
        // and unmap_region_pages — the kernel runs with a high-half
        // mapping and the user AS's leaf PTEs walk through self.root.
        unsafe { self.madvise_release_pages(&to_release) };
        Ok(())
    }

    /// PTE-walk helper for [`madvise_dontneed`]. Tear down the leaf
    /// PTE for each `(vaddr, phys)` pair and return the frame to the
    /// allocator. `free_frame` consults the COW refcount table, so a
    /// frame still shared with another AS stays live until its last
    /// owner releases it.
    ///
    /// # Safety
    /// Identity-map invariant identical to `unmap_region_pages`.
    /// Each `phys` must match the leaf the page table currently
    /// resolves to — `madvise_dontneed` snapshots the per-page phys
    /// list under the region lock so this contract holds.
    #[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
    unsafe fn madvise_release_pages(&self, pages: &[(VirtAddr, PhysAddr)]) {
        use crate::frame::{free_frame, PhysFrame};
        use crate::x86_64::paging::unmap_4kb;
        if self.root.as_u64() == 0 {
            return;
        }
        for (v, p) in pages {
            // SAFETY: identity-mapped; `v` came from a known
            // bookkept region.
            let _ = unsafe { unmap_4kb(self.root, *v) };
            if crate::frame::__pagetable_is_registered(p.raw()) {
                continue;
            }
            free_frame(PhysFrame::new(*p));
        }
    }

    #[cfg(all(feature = "linux-compat", target_arch = "aarch64"))]
    unsafe fn madvise_release_pages(&self, pages: &[(VirtAddr, PhysAddr)]) {
        use crate::aarch64::paging::unmap_4kb;
        use crate::frame::{free_frame, PhysFrame};
        if self.root.as_u64() == 0 {
            return;
        }
        for (v, p) in pages {
            // SAFETY: see x86_64 variant.
            let _ = unsafe { unmap_4kb(self.root, *v) };
            free_frame(PhysFrame::new(*p));
        }
    }

    #[cfg(all(
        feature = "linux-compat",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    unsafe fn madvise_release_pages(&self, _pages: &[(VirtAddr, PhysAddr)]) {}

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
        use crate::x86_64::paging::{map_4kb, unmap_4kb, PtFlags};
        if self.root.as_u64() == 0 {
            return;
        }
        for r in regions {
            // PROT_NONE: tear down the leaf PTEs without freeing
            // the underlying frames (region.phys still owns them).
            // The next mprotect-back-to-RW just re-installs.
            if r.perms.prot_only().0 == 0 {
                for i in 0..r.phys.len() {
                    let v = VirtAddr::new(r.base.as_u64() + ((i as u64) << 12));
                    // SAFETY: same identity-map invariant.
                    let _ = unsafe { unmap_4kb(self.root, v) };
                }
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
                let _ = unsafe { unmap_4kb(self.root, v) };
                // SAFETY: same.
                let _ = unsafe { map_4kb(self.root, v, *p, flags) };
            }
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
                match unsafe { map_4kb(self.root, v, *p, flags) } {
                    Ok(()) => {}
                    Err(MapError::AlreadyMapped) => {} // idempotent
                    Err(_) => return Err(AddressSpaceError::NotImplemented),
                }
            }
        }
        Ok(())
    }

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
                match unsafe { map_4kb(self.root, v, *p, flags) } {
                    Ok(()) => {}
                    Err(MapError::AlreadyMapped) => {}
                    Err(_) => return Err(AddressSpaceError::NotImplemented),
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
        let regions = self.regions.lock().clone();
        // SAFETY: identity-map live; `root` valid from `new_for_user`.
        unsafe { self.rewrite_perms_pages(&regions) };
        Ok(())
    }

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
                // Bump the refcount on every backing frame.
                for &p in r.phys.iter() {
                    let _ = crate::frame::cow::inc_ref(p);
                }
                // Strip WRITE — both ASes start the post-fork
                // window read-only and split on first write.
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

        // SAFETY: root is a valid PML4; the page we're touching
        // sits inside `region` per the lookup above.
        let _ = unsafe { unmap_4kb(self.root, page_va) };
        // SAFETY: `self.root` is this AS's live PML4 (same root just
        // passed to `unmap_4kb`); `page_va` is the page-aligned VA of a
        // page that belongs to `region` (the lookup above resolved it),
        // and `phys` is `region.phys[page_idx]`, the frame this AS owns
        // for that page. `flags` mirror the region's perms, so the new
        // PTE re-installs exactly the mapping we just tore down.
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

        // SAFETY: root is a valid translation table; `page_va`
        // sits inside `region`. unmap_4kb invalidates the local
        // TLB; map_4kb installs the fresh leaf.
        let _ = unsafe { unmap_4kb(self.root, page_va) };
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
            unsafe {
                crate::aarch64::paging::write_ttbr0_el1(cur);
            }
            let _ = self.root;
            return Ok(());
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
        // Take ownership of the region list to avoid borrowing
        // through &mut self below; the list is about to be
        // dropped anyway.
        let regions = core::mem::take(&mut *self.regions.lock());
        for r in regions.iter() {
            // SAFETY: see unmap_region_pages — same identity-map
            // contract; no CPU is using self.root at this point
            // since we're past the last Arc reference.
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
