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
    /// Allocates a fresh root page table (via `new_for_user`) and,
    /// for every region, allocates new physical frames and `memcpy`s
    /// the parent's bytes through the low-4-GiB identity map. The
    /// returned address space owns its own frames — mutations on
    /// either side do NOT propagate.
    ///
    /// FIXME(cow): non-COW first cut. A real copy-on-write fork
    /// would share frames via a per-frame refcount and split on the
    /// first user-mode write fault. The eventual hook lives in
    /// `narf_memory::region::cow_split_on_write` (not yet written);
    /// until then we eagerly memcpy. Acceptable on small Stage-4
    /// processes; expensive on large `brk` heaps.
    ///
    /// # Safety
    /// - The low-4-GiB identity map must be live (the same Stage-4
    ///   contract `materialize` rides on); the byte-copy walks each
    ///   region's parent + child frames through identity-mapped
    ///   raw pointers.
    /// - The frame allocator must be initialised.
    /// - Caller must `materialize()` the returned AS before
    ///   activating it; this routine does NOT walk page tables.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn clone_for_fork(&self) -> Result<Self, AddressSpaceError> {
        // SAFETY: caller's contract — paging is live.
        let child = unsafe { Self::new_for_user() }?;

        let parent_regions = self.regions.lock().clone();

        let mut child_regions: Vec<Region> = Vec::with_capacity(parent_regions.len());

        for r in parent_regions.iter() {
            let pages = r.phys.len();
            let mut child_phys: Vec<PhysAddr> = Vec::with_capacity(pages);
            for &parent_phys in r.phys.iter() {
                let f = crate::frame::alloc_frame().map_err(|_| AddressSpaceError::OutOfRange)?;
                let cphys = f.start_address();
                // SAFETY: low-4-GiB identity map covers both parent
                // and child phys frames; each is a 4 KiB page
                // contiguous in physical memory; the source/dest
                // ranges are non-overlapping (distinct frames the
                // allocator just handed us).
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        parent_phys.raw() as *const u8,
                        cphys.raw() as *mut u8,
                        crate::frame::PAGE_SIZE as usize,
                    );
                }
                child_phys.push(cphys);
            }
            child_regions.push(Region {
                base: r.base,
                len: r.len,
                perms: r.perms,
                phys: child_phys,
            });
        }

        // Push the regions into the child AS via map_region so the
        // overlap / alignment / phys-len invariants are re-checked
        // for free. The parent is well-formed by construction so
        // these never trip on a healthy parent.
        for r in child_regions.into_iter() {
            child.map_region(r)?;
        }

        Ok(child)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub unsafe fn clone_for_fork(&self) -> Result<Self, AddressSpaceError> {
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
            // aarch64 split translation would make TTBR0 swaps safe
            // in principle — the kernel lives behind TTBR1. In
            // practice the current boot's TTBR0 carries the kernel's
            // low-half identity map that the heap + free-list
            // access through raw phys-as-virt pointers, so swapping
            // it to a fresh empty table hangs. The full
            // `write_ttbr0_el1` primitive IS landed in
            // `aarch64::paging` and tested independently; wiring it
            // here waits on migrating the allocator off the identity
            // map (the same prerequisite x86_64 has for genuine
            // user-AS isolation).
            return Err(AddressSpaceError::NotImplemented);
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
