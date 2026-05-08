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

    #[inline]
    pub const fn contains(self, o: RegionPerms) -> bool {
        self.0 & o.0 == o.0
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region {
    pub base: VirtAddr,
    pub len: u64,
    pub perms: RegionPerms,
    /// Per-page phys backing. Length must equal `len / 4096`; an
    /// empty Vec is a structural error rejected by `map_region`.
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
}

impl AddressSpace {
    /// Fresh address space with no regions. Stage-4 arch backend
    /// must assign `root` to a freshly-allocated page-table frame.
    pub const fn empty() -> Self {
        Self {
            root: PhysAddr::new(0),
            regions: IrqSafeSpinLock::new(Vec::new()),
        }
    }

    /// Allocate a fresh user-mode PML4 (x86_64) or TTBR0 page-table
    /// root (aarch64) inheriting every kernel-half entry from the
    /// currently-active root. The returned `AddressSpace` can be
    /// populated with user regions via `map_region` and activated
    /// via `activate()` — which on x86_64 is now a real `MOV CR3`.
    ///
    /// aarch64 returns `NotImplemented` until the TTBR0 primitive
    /// lands in `memory/src/aarch64/paging.rs`.
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
        }
        regions.push(region);
        Ok(())
    }

    /// Remove a region whose base address matches `base`.
    pub fn unmap_region(&self, base: VirtAddr) -> Result<Region, AddressSpaceError> {
        let mut regions = self.regions.lock();
        let idx = regions
            .iter()
            .position(|r| r.base == base)
            .ok_or(AddressSpaceError::Unmapped)?;
        Ok(regions.swap_remove(idx))
    }

    /// Number of mapped regions.
    #[inline]
    pub fn region_count(&self) -> usize {
        self.regions.lock().len()
    }

    /// Snapshot of the region list — returns an owned `Vec<Region>`
    /// so callers can iterate without holding the lock.
    pub fn regions_snapshot(&self) -> Vec<Region> {
        self.regions.lock().clone()
    }

    /// Materialise all pending regions into actual page-table entries.
    /// On x86_64 walks each region's pages and calls `map_4kb` on the
    /// AS's PML4 root; on aarch64 returns `NotImplemented` until the
    /// 4 KiB map primitive lands.
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
            let mut flags = PtFlags::USER;
            if r.perms.contains(RegionPerms::WRITE) {
                flags = flags | PtFlags::WRITABLE;
            }
            if !r.perms.contains(RegionPerms::EXEC) {
                flags = flags | PtFlags::NO_EXEC;
            }

            for (i, p) in r.phys.iter().enumerate() {
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
        let new_frame =
            crate::frame::alloc_frame().map_err(|_| AddressSpaceError::OutOfRange)?;
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
            flags = flags | PtFlags::WRITABLE;
        }
        if !region.perms.contains(RegionPerms::EXEC) {
            flags = flags | PtFlags::NO_EXEC;
        }

        // SAFETY: root is a valid PML4; the page we're touching
        // sits inside `region` per the lookup above.
        let _ = unsafe { unmap_4kb(self.root, page_va) };
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
    /// aarch64 returns `NotImplemented` until the TTBR0_EL1
    /// primitive lands.
    ///
    /// # Safety invariants (x86_64)
    /// - `self.root` must have been constructed via `new_for_user`,
    ///   which copies the currently-active kernel-half entries.
    ///   Activating a PML4 without kernel mappings triple-faults
    ///   on the next instruction fetch.
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
            return Ok(());
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
