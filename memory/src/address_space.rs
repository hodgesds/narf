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

use crate::addr::{PhysAddr, VirtAddr};

/// Region permission flags. Mirrors ELF `PF_*` so the loader doesn't
/// need a translation step.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RegionPerms(pub u32);

impl RegionPerms {
    pub const EXEC:  RegionPerms = RegionPerms(1 << 0);
    pub const WRITE: RegionPerms = RegionPerms(1 << 1);
    pub const READ:  RegionPerms = RegionPerms(1 << 2);

    #[inline] pub const fn contains(self, o: RegionPerms) -> bool { self.0 & o.0 == o.0 }
}

impl core::ops::BitOr for RegionPerms {
    type Output = RegionPerms;
    fn bitor(self, rhs: RegionPerms) -> Self { RegionPerms(self.0 | rhs.0) }
}

/// A contiguous user-mode mapping.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Region {
    pub base:     VirtAddr,
    pub len:      u64,
    pub perms:    RegionPerms,
    /// Physical frame the first page of `base` maps to. Multi-frame
    /// mappings walk contiguous physical frames for Stage-4
    /// structural — the Stage-4+ refinement uses a scatter list.
    pub phys:     PhysAddr,
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
#[derive(Debug)]
pub struct AddressSpace {
    /// Root page-table physical frame. Filled in by the per-arch
    /// `new_table` primitive once it lands; `PhysAddr::new(0)`
    /// acts as "not-yet-initialised" sentinel.
    pub root: PhysAddr,
    regions:  Vec<Region>,
}

impl AddressSpace {
    /// Fresh address space with no regions. Stage-4 arch backend
    /// must assign `root` to a freshly-allocated page-table frame.
    pub const fn empty() -> Self {
        Self {
            root:    PhysAddr::new(0),
            regions: Vec::new(),
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
        Ok(Self { root: phys, regions: Vec::new() })
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub unsafe fn new_for_user() -> Result<Self, AddressSpaceError> {
        Err(AddressSpaceError::NotImplemented)
    }

    /// Attach a region description to the address-space table. Does
    /// NOT program the page table — that lives in `arch/`. Checks
    /// for overlap with existing regions and 4 KiB alignment.
    pub fn map_region(&mut self, region: Region) -> Result<(), AddressSpaceError> {
        if region.base.as_u64() & 0xFFF != 0 || region.len & 0xFFF != 0 {
            return Err(AddressSpaceError::AlignmentMismatch);
        }
        let end = region.base.as_u64().checked_add(region.len)
            .ok_or(AddressSpaceError::OutOfRange)?;
        for r in &self.regions {
            let r_end = r.base.as_u64() + r.len;
            if region.base.as_u64() < r_end && r.base.as_u64() < end {
                return Err(AddressSpaceError::Overlap);
            }
        }
        self.regions.push(region);
        Ok(())
    }

    /// Remove a region whose base address matches `base`.
    pub fn unmap_region(&mut self, base: VirtAddr) -> Result<Region, AddressSpaceError> {
        let idx = self.regions.iter().position(|r| r.base == base)
            .ok_or(AddressSpaceError::Unmapped)?;
        Ok(self.regions.swap_remove(idx))
    }

    /// Number of mapped regions.
    #[inline]
    pub fn region_count(&self) -> usize { self.regions.len() }

    /// Snapshot of the region list.
    pub fn regions(&self) -> &[Region] { &self.regions }

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
        if self.root.as_u64() == 0 { return Err(AddressSpaceError::OutOfRange); }
        for r in &self.regions {
            let mut flags = PtFlags::USER;
            if r.perms.contains(RegionPerms::WRITE) { flags = flags | PtFlags::WRITABLE; }
            if !r.perms.contains(RegionPerms::EXEC) { flags = flags | PtFlags::NO_EXEC; }

            let pages = r.len >> 12;
            for i in 0..pages {
                let v = crate::VirtAddr::new(r.base.as_u64() + (i << 12));
                let p = crate::PhysAddr::new(r.phys.as_u64() + (i << 12));
                // SAFETY: `self.root` is a valid PML4 per the
                // `new_for_user` contract; pages walked are within
                // the region we're materialising.
                match unsafe { map_4kb(self.root, v, p, flags) } {
                    Ok(()) => {}
                    Err(MapError::AlreadyMapped) => {}   // idempotent
                    Err(_)                        => return Err(AddressSpaceError::NotImplemented),
                }
            }
        }
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub unsafe fn materialize(&self) -> Result<(), AddressSpaceError> {
        Err(AddressSpaceError::NotImplemented)
    }

    /// Find the region covering `vaddr`, if any.
    pub fn lookup(&self, vaddr: VirtAddr) -> Option<&Region> {
        let a = vaddr.as_u64();
        self.regions.iter().find(|r| {
            a >= r.base.as_u64() && a < r.base.as_u64() + r.len
        })
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
            unsafe { crate::x86_64::paging::write_cr3(self.root); }
            return Ok(());
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(AddressSpaceError::NotImplemented)
        }
    }
}

impl Default for AddressSpace {
    fn default() -> Self { Self::empty() }
}
