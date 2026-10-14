//! Access to ANOTHER address space's memory: Linux `access_remote_vm`
//! (`mm/memory.c::__access_remote_vm`) and the page-pinning loop of
//! `process_vm_rw_single_vec` (`mm/process_vm_access.c`), over NARF's
//! authoritative region tables.
//!
//! The target's page tables are deliberately NOT walked. A leaf describes how
//! the *owner* may touch a page, not what a debugger may do with it: a
//! fork-shared page is mapped read-only although it is logically writable, a
//! `PROT_NONE` page has no leaf at all although its frame holds data, and a
//! lazy page has no leaf yet. Linux answers all three from the VMA and the
//! page it faults in (`get_user_pages_remote` → `handle_mm_fault`), and so do
//! these helpers: the region table names the frame, and a missing frame is
//! faulted in through the same demand path a hardware fault takes.
//!
//! Writes break COW in the TARGET only. A `FOLL_FORCE` write may land on a
//! read-only private mapping (a debugger's breakpoint in text) and gets its
//! own private copy there; it never writes through to a frame another address
//! space (a fork sibling, the vDSO master) still maps.

use super::{
    lock_address_space_shared_mapping_transaction, AddressSpace, RegionPerms, StackGrowthLimits,
};
use crate::{PhysAddr, VirtAddr};

/// How a remote access is admitted — the `gup_flags` that matter here.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RemoteAccess {
    /// `FOLL_WRITE`.
    pub write: bool,
    /// `FOLL_FORCE`: override the VMA's protection the way ptrace and
    /// `/proc/<pid>/mem` do (`check_vma_flags`).
    pub force: bool,
    /// `Some` makes an address below a growable stack expand it, as
    /// `__access_remote_vm`'s `expand_stack(mm, addr)` does, under the
    /// CALLER's limits (Linux's `acct_stack_growth` reads `current`'s
    /// rlimits). `None` is GUP proper (`process_vm_*`), which never expands.
    pub expand_stack: Option<StackGrowthLimits>,
}

/// Bound on the fault-in / COW-break retries for one page. Each retry is a
/// completed state transition (a frame published, a copy split) or a peer's
/// in-flight one; a page that never settles is reported as inaccessible.
const MAX_PAGE_ATTEMPTS: usize = 64;

/// What one region-table look at a page concluded.
enum PageStep {
    /// The access completed.
    Done,
    /// No frame backs the page yet: fault it in.
    FaultIn,
    /// A write needs a private copy first.
    BreakCow { prot_none: bool },
    /// No VMA covers the page (or it is a stack guard): try `expand_stack`.
    ExpandStack,
}

/// `mm/gup.c::check_vma_flags` for a NARF region.
///
/// - `VM_IO | VM_PFNMAP` → `-EFAULT`. NARF's device/PFN mappings (and the
///   vvar page) are the `SHARED | LOCK_EXEMPT` regions whose frames are not
///   allocator RAM.
/// - A write to a `!VM_WRITE` VMA needs `FOLL_FORCE` and `is_cow_mapping`,
///   i.e. a private mapping. NARF folds `VM_MAYWRITE` into "not `SHARED`":
///   every private mapping may be written by COW, and a shared mapping that
///   is not `VM_WRITE` is either `VM_SHARED` or a read-only file's shared
///   mapping with `VM_MAYWRITE` cleared — not a COW mapping either way.
/// - A read of a `!VM_READ` VMA needs `FOLL_FORCE` (every VMA has
///   `VM_MAYREAD`).
fn vma_admits(perms: RegionPerms, access: RemoteAccess) -> bool {
    if perms.contains(RegionPerms::SHARED)
        && perms.contains(RegionPerms::LOCK_EXEMPT)
        && !perms.contains(RegionPerms::PINNABLE_RAM)
    {
        return false;
    }
    if access.write {
        if !perms.contains(RegionPerms::WRITE)
            && (!access.force || perms.contains(RegionPerms::SHARED))
        {
            return false;
        }
    } else if !perms.contains(RegionPerms::READ) && !access.force {
        return false;
    }
    true
}

/// Whether a write to the resident `phys` of a region with `perms` must
/// first give the target a private copy — exactly when the owner's own write
/// would take the COW fault. A `VM_WRITE` private page is split only while
/// fork still shares it (`COW` and a refcount above one, the
/// `user_page_writable` rule the hardware leaf follows). A forced write to a
/// read-only private page (text, a `PROT_NONE` page) splits whenever any
/// other reference exists, since that page carries no COW marker at all.
/// `SHARED` frames are the mapped object itself and are written in place.
fn write_needs_private_copy(perms: RegionPerms, phys: PhysAddr) -> bool {
    if perms.contains(RegionPerms::SHARED) {
        return false;
    }
    if perms.contains(RegionPerms::WRITE) && !perms.contains(RegionPerms::COW) {
        return false;
    }
    crate::frame::cow::count(phys) > 1
}

/// Instruction-cache maintenance after a write into a page that may hold
/// code. Linux arm64 `copy_to_user_page` → `flush_ptrace_access` cleans the
/// kernel alias it wrote through for a `VM_EXEC` VMA; x86 keeps I/D coherent.
#[inline]
fn sync_icache_after_write(_perms: RegionPerms, _ptr: *mut u8, _len: usize) {
    #[cfg(target_arch = "aarch64")]
    if _perms.contains(RegionPerms::EXEC) && _len != 0 {
        // SAFETY: `ptr..ptr+len` lies in the kernel direct map of a frame the
        // caller still holds under the region lock.
        unsafe { narf_arch::aarch64::asm::flush_icache_range(_ptr as u64, _len as u64) };
    }
}

impl AddressSpace {
    /// Linux `access_remote_vm(mm, addr, buf, len, gup_flags)`: copy between
    /// `buf` and this address space starting at `addr`. Returns the number
    /// of bytes transferred, which stops short at the first page that cannot
    /// be accessed (Linux "ignore errors, just check how much was
    /// successfully transferred"). A read fills `buf`; a write consumes it.
    ///
    /// # Safety
    /// - `self` must be a live user address space whose root is valid (it may
    ///   be inactive on this CPU — that is the point). Lazy pages are faulted
    ///   in and COW is broken through the ordinary demand/COW paths, which
    ///   are safe against the owner running concurrently on another CPU.
    /// - The frame allocator and the kernel direct map must be live.
    pub unsafe fn access_remote(
        &self,
        addr: u64,
        buf: RemoteBuf<'_>,
        access: RemoteAccess,
    ) -> usize {
        let total = buf.len();
        let mut done = 0usize;
        let mut buf = buf;
        while done < total {
            let Some(at) = addr.checked_add(done as u64) else {
                break;
            };
            let in_page = (at & 0xFFF) as usize;
            let chunk = (4096 - in_page).min(total - done);
            let copy = |perms: RegionPerms, ptr: *mut u8| match &mut buf {
                RemoteBuf::Read(dst) => {
                    // SAFETY: `ptr` addresses `chunk` bytes of a frame
                    // retained by the region lock held around this call.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            ptr as *const u8,
                            dst[done..done + chunk].as_mut_ptr(),
                            chunk,
                        )
                    };
                }
                RemoteBuf::Write(src) => {
                    // SAFETY: as above; the admission check proved this
                    // frame is the target's own (shared-writable, or a
                    // private page no other mapping references).
                    unsafe {
                        core::ptr::copy_nonoverlapping(src[done..done + chunk].as_ptr(), ptr, chunk)
                    };
                    sync_icache_after_write(perms, ptr, chunk);
                }
            };
            // SAFETY: forwarded caller contract.
            let ok = unsafe { self.remote_page(at, access, copy) };
            if !ok {
                break;
            }
            done += chunk;
        }
        done
    }

    /// Resolve the page holding `addr` for `access` and run `op` on a
    /// direct-map pointer to that byte while the region lock retains the
    /// frame. `op` may touch bytes up to the end of the page. Returns `false`
    /// when the page is not accessible (GUP's `-EFAULT`).
    ///
    /// # Safety
    /// As [`Self::access_remote`].
    unsafe fn remote_page(
        &self,
        addr: u64,
        access: RemoteAccess,
        mut op: impl FnMut(RegionPerms, *mut u8),
    ) -> bool {
        let page = addr & !0xFFF;
        let in_page = addr & 0xFFF;
        for _ in 0..MAX_PAGE_ATTEMPTS {
            let step = {
                // Same exclusion `pin_user_page` takes: a cross-address-space
                // shared-page migration must not swap the frame under us.
                let _shared = lock_address_space_shared_mapping_transaction(self.identity());
                let regions = self.regions.lock();
                if let Some(region) = regions.containing(page) {
                    let perms = region.perms;
                    if perms.contains(RegionPerms::STACK_GUARD) {
                        // Linux has no VMA here: the gap below a stack.
                        PageStep::ExpandStack
                    } else {
                        if !vma_admits(perms, access) {
                            return false;
                        }
                        // MADV_GUARD_INSTALL marker: handle_pte_marker →
                        // VM_FAULT_SIGSEGV, so GUP fails.
                        if regions.guard_pages.contains(&page) {
                            return false;
                        }
                        let index = ((page - region.base.as_u64()) >> 12) as usize;
                        let phys = region.backing_at(index);
                        if phys.raw() == 0 {
                            PageStep::FaultIn
                        } else if access.write && write_needs_private_copy(perms, phys) {
                            PageStep::BreakCow {
                                prot_none: perms.prot_only().0 == 0,
                            }
                        } else {
                            op(
                                perms,
                                PhysAddr::new(phys.raw() + in_page).kernel_mut_ptr::<u8>(),
                            );
                            PageStep::Done
                        }
                    }
                } else {
                    drop(regions);
                    let huge = self.huge_regions.lock();
                    match huge.iter().find(|region| {
                        addr >= region.base.as_u64() && addr - region.base.as_u64() < region.len
                    }) {
                        Some(region) => {
                            if !vma_admits(region.perms, access) {
                                return false;
                            }
                            // Private hugetlb frames are copied eagerly at
                            // fork (`clone_for_fork`), so they are never
                            // shared with another address space; a shared
                            // one is written only when VM_WRITE (above).
                            let offset = addr - region.base.as_u64();
                            let Some(size) = region.frames.first().map(|f| f.size_bytes()) else {
                                return false;
                            };
                            let Some(frame) = region.frames.get((offset / size) as usize) else {
                                return false;
                            };
                            op(
                                region.perms,
                                PhysAddr::new(frame.phys() + offset % size).kernel_mut_ptr::<u8>(),
                            );
                            PageStep::Done
                        }
                        None => PageStep::ExpandStack,
                    }
                }
            };
            match step {
                PageStep::Done => return true,
                PageStep::FaultIn => {
                    // SAFETY: forwarded caller contract; the demand path is
                    // the one a hardware fault on this page would take.
                    match unsafe { self.demand_page_in(VirtAddr::new(page), access.force) } {
                        Ok(()) => {}
                        Err(_) => return false,
                    }
                }
                PageStep::BreakCow { prot_none } => {
                    // SAFETY: forwarded caller contract.
                    if unsafe { self.cow_split_mode(VirtAddr::new(page), access.force) }.is_err() {
                        return false;
                    }
                    // Point the owner's leaf at its new private copy (and
                    // retire every CPU's cached translation of the old one).
                    // A PROT_NONE page has no leaf to repoint.
                    // SAFETY: forwarded caller contract.
                    if !prot_none && unsafe { self.remap_page(VirtAddr::new(page)) }.is_err() {
                        return false;
                    }
                }
                PageStep::ExpandStack => {
                    let Some(limits) = access.expand_stack else {
                        return false;
                    };
                    // SAFETY: forwarded caller contract.
                    if unsafe { self.try_grow_stack_limited(VirtAddr::new(page), limits) }.is_err()
                    {
                        return false;
                    }
                }
            }
            core::hint::spin_loop();
        }
        false
    }
}

/// The local side of [`AddressSpace::access_remote`].
#[derive(Debug)]
pub enum RemoteBuf<'a> {
    /// Fill this buffer from the remote address space.
    Read(&'a mut [u8]),
    /// Write this buffer into the remote address space.
    Write(&'a [u8]),
}

impl RemoteBuf<'_> {
    fn len(&self) -> usize {
        match self {
            RemoteBuf::Read(b) => b.len(),
            RemoteBuf::Write(b) => b.len(),
        }
    }
}
