//! `MADV_GUARD_INSTALL` / `MADV_GUARD_REMOVE` smokes for `narf-memory`.
//!
//! Linux keeps a guard as a PTE marker (`mm/madvise.c`), so every path that
//! copies, moves, or drops page tables carries it: fork copies markers,
//! mremap moves them, munmap drops them, and MADV_DONTNEED / mprotect keep
//! them. One test per path, plus the fault, populate, and kernel-access
//! refusals.

use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};
use narf_kernel_test::{kernel_test_in, TestResult};

const PAGE: u64 = 0x1000;

fn anon(base: u64, pages: u64) -> Region {
    Region {
        base: VirtAddr::new(base),
        len: pages * PAGE,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        // Every page lazy: the first touch demand-faults.
        phys: alloc::vec![PhysAddr::new(0); pages as usize].into(),
    }
}

fn va(base: u64, page: u64) -> VirtAddr {
    VirtAddr::new(base + page * PAGE)
}

fn backing(a: &AddressSpace, v: VirtAddr) -> PhysAddr {
    a.page_backing(v).map_or(PhysAddr::new(0), |(_, phys)| phys)
}

#[cfg(target_arch = "x86_64")]
fn leaf(a: &AddressSpace, v: VirtAddr) -> Option<PhysAddr> {
    // SAFETY: `a.root` is the live root of a `new_for_user` address space.
    unsafe { crate::x86_64::paging::translate(a.root, v) }
}

#[cfg(target_arch = "aarch64")]
fn leaf(a: &AddressSpace, v: VirtAddr) -> Option<PhysAddr> {
    // SAFETY: `a.root` is the live root of a `new_for_user` address space.
    unsafe { crate::aarch64::paging::translate(a.root, v) }
}

/// A user address space with `pages` demand-paged anonymous pages at `base`,
/// every page faulted in.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn faulted_space(base: u64, pages: u64) -> Result<AddressSpace, TestResult> {
    // SAFETY: a fresh user address space; its root is live until dropped.
    let a = unsafe { AddressSpace::new_for_user() }
        .map_err(|_| TestResult::Skip("new_for_user failed"))?;
    if a.map_region(anon(base, pages)).is_err() {
        core::mem::forget(a);
        return Err(TestResult::Fail("map anonymous region"));
    }
    for page in 0..pages {
        // SAFETY: the page lies in the region just mapped into a live root.
        if unsafe { a.demand_alloc_page(va(base, page)) }.is_err() {
            core::mem::forget(a);
            return Err(TestResult::Skip("demand fault failed (memory pressure)"));
        }
    }
    Ok(a)
}

/// Install releases the private pages and makes them fault with `GuardPage`;
/// neighbours stay intact; remove lets the page fault back in, zero-filled.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_guard_install_faults_and_remove_restores() -> TestResult {
    const BASE: u64 = 0x0000_0080_0010_0000;
    let a = match faulted_space(BASE, 4) {
        Ok(a) => a,
        Err(result) => return result,
    };
    let stamped = backing(&a, va(BASE, 1));
    // SAFETY: the frame backs page 1 of `a` and is identity-mapped.
    unsafe { core::ptr::write_bytes(stamped.kernel_mut_ptr::<u8>(), 0xAB, 4096) };

    let result = (|| {
        if a.madvise_guard_install(va(BASE, 1), 2 * PAGE).is_err() {
            return Err("install over two faulted pages failed");
        }
        if !a.is_guard_page(va(BASE, 1)) || !a.is_guard_page(VirtAddr::new(BASE + 2 * PAGE + 7)) {
            return Err("installed pages carry no marker");
        }
        if a.is_guard_page(va(BASE, 0)) || a.is_guard_page(va(BASE, 3)) {
            return Err("install marked a neighbouring page");
        }
        if backing(&a, va(BASE, 1)).raw() != 0 || leaf(&a, va(BASE, 1)).is_some() {
            return Err("install kept the private page's frame or leaf");
        }
        if backing(&a, va(BASE, 0)).raw() == 0 || leaf(&a, va(BASE, 3)).is_none() {
            return Err("install released a neighbouring page");
        }
        // SAFETY: page 1 lies in a live region of `a`.
        if unsafe { a.demand_alloc_page(va(BASE, 1)) } != Err(AddressSpaceError::GuardPage) {
            return Err("a fault on a guard page was not GuardPage");
        }
        let mut byte = [0u8; 1];
        if a.copy_user_bytes_nofault(va(BASE, 2), &mut byte) != 0 {
            return Err("a nofault kernel read crossed a guard page");
        }
        if a.pin_user_page(va(BASE, 1)).is_some() {
            return Err("pin_user_page pinned a guard page");
        }
        // Idempotent: installing over an installed guard is a success.
        if a.madvise_guard_install(va(BASE, 1), PAGE).is_err() {
            return Err("re-install over a guard failed");
        }
        if a.madvise_guard_remove(va(BASE, 1), 2 * PAGE).is_err() {
            return Err("remove failed");
        }
        if a.is_guard_page(va(BASE, 1)) || a.is_guard_page(va(BASE, 2)) {
            return Err("remove left a marker");
        }
        // SAFETY: page 1 lies in a live region of `a`.
        if unsafe { a.demand_alloc_page(va(BASE, 1)) }.is_err() {
            return Err("the page did not fault in after remove");
        }
        let fresh = backing(&a, va(BASE, 1));
        // SAFETY: the frame now backs page 1 of `a`.
        let first = unsafe { *fresh.kernel_ptr::<u8>() };
        if fresh.raw() == 0 || first != 0 {
            return Err("the refaulted page was not zero-filled");
        }
        Ok(())
    })();
    core::mem::forget(a);
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_guard_install_faults_and_remove_restores
);

/// `madvise_walk_vmas`: an invalid VMA (VM_SPECIAL) stops the walk with
/// EINVAL after the VMAs before it were processed; a hole is ENOMEM but the
/// mapped parts are still processed.
fn smoke_memory_guard_walk_errors_match_linux() -> TestResult {
    const BASE: u64 = 0x0000_0080_0020_0000;
    let a = AddressSpace::empty();
    let special = Region {
        perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::LOCK_EXEMPT,
        ..anon(BASE + 2 * PAGE, 1)
    };
    // [0,2) plain | [2,3) special | [3,4) hole | [4,5) plain
    if a.map_region(anon(BASE, 2)).is_err()
        || a.map_region(special).is_err()
        || a.map_region(anon(BASE + 4 * PAGE, 1)).is_err()
    {
        return TestResult::Fail("map the walk layout");
    }
    if a.madvise_guard_install(va(BASE, 0), 5 * PAGE) != Err(AddressSpaceError::OutOfRange) {
        return TestResult::Fail("a VM_SPECIAL VMA in range was not EINVAL");
    }
    if !a.is_guard_page(va(BASE, 0)) || !a.is_guard_page(va(BASE, 1)) {
        return TestResult::Fail("the VMA before the invalid one was not processed");
    }
    if a.is_guard_page(va(BASE, 2)) || a.is_guard_page(va(BASE, 4)) {
        return TestResult::Fail("the walk went past the invalid VMA");
    }
    if a.madvise_guard_install(va(BASE, 3), 2 * PAGE) != Err(AddressSpaceError::Unmapped) {
        return TestResult::Fail("a range starting in a hole was not ENOMEM");
    }
    if !a.is_guard_page(va(BASE, 4)) {
        return TestResult::Fail("the mapped part after a hole was not processed");
    }
    if a.madvise_guard_remove(va(BASE, 0), 2 * PAGE).is_err() || a.is_guard_page(va(BASE, 0)) {
        return TestResult::Fail("remove over a plain VMA failed");
    }
    if a.madvise_guard_remove(va(BASE, 2), PAGE) != Err(AddressSpaceError::OutOfRange) {
        return TestResult::Fail("remove over a VM_SPECIAL VMA was not EINVAL");
    }
    if a.madvise_guard_install(va(BASE, 8), PAGE) != Err(AddressSpaceError::Unmapped) {
        return TestResult::Fail("install over nothing was not ENOMEM");
    }
    if a.madvise_guard_install(VirtAddr::new(BASE + 1), PAGE)
        != Err(AddressSpaceError::AlignmentMismatch)
    {
        return TestResult::Fail("a misaligned start was not EINVAL");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_guard_walk_errors_match_linux);

/// `is_valid_guard_vma(vma, allow_locked)`: install refuses an mlocked VMA,
/// remove accepts it. A populate (mlock after install) skips the guard.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_guard_locked_vma_and_populate_skip() -> TestResult {
    const BASE: u64 = 0x0000_0080_0030_0000;
    // SAFETY: a fresh user address space; its root is live until forgotten.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let result = (|| {
        a.map_region(anon(BASE, 3)).map_err(|_| "map")?;
        a.madvise_guard_install(va(BASE, 1), PAGE)
            .map_err(|_| "install over an unlocked VMA failed")?;
        // mlock populates everything but the guard and still succeeds.
        a.mlock_range(va(BASE, 0), 3 * PAGE)
            .map_err(|_| "mlock over a guarded range failed")?;
        if backing(&a, va(BASE, 0)).raw() == 0 || backing(&a, va(BASE, 2)).raw() == 0 {
            return Err("mlock did not populate the unguarded pages");
        }
        if backing(&a, va(BASE, 1)).raw() != 0 || !a.is_guard_page(va(BASE, 1)) {
            return Err("mlock populated the guard page");
        }
        if a.madvise_guard_install(va(BASE, 0), PAGE) != Err(AddressSpaceError::OutOfRange) {
            return Err("install over a locked VMA was not EINVAL");
        }
        if a.is_guard_page(va(BASE, 0)) {
            return Err("a refused install left a marker");
        }
        a.madvise_guard_remove(va(BASE, 0), 3 * PAGE)
            .map_err(|_| "remove over a locked VMA failed")?;
        if a.is_guard_page(va(BASE, 1)) {
            return Err("remove over a locked VMA kept the marker");
        }
        Ok(())
    })();
    core::mem::forget(a);
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_guard_locked_vma_and_populate_skip);

/// munmap — a partial punch, MAP_FIXED replacement, or a whole-VMA unmap —
/// drops the markers in the range; a new mapping there is not guarded.
fn smoke_memory_guard_munmap_drops_markers() -> TestResult {
    const BASE: u64 = 0x0000_0080_0040_0000;
    let a = AddressSpace::empty();
    if a.map_region(anon(BASE, 4)).is_err()
        || a.madvise_guard_install(va(BASE, 0), 4 * PAGE).is_err()
    {
        return TestResult::Fail("setup");
    }
    if a.punch_fixed(va(BASE, 1), PAGE).is_err() {
        return TestResult::Fail("punch");
    }
    if a.is_guard_page(va(BASE, 1)) {
        return TestResult::Fail("munmap kept the marker of the unmapped page");
    }
    if !a.is_guard_page(va(BASE, 0)) || !a.is_guard_page(va(BASE, 2)) {
        return TestResult::Fail("munmap dropped markers outside the range");
    }
    if a.map_region(anon(BASE + PAGE, 1)).is_err() || a.is_guard_page(va(BASE, 1)) {
        return TestResult::Fail("a new mapping inherited a stale marker");
    }
    // A whole-VMA unmap: the head fragment [0,1).
    if a.unmap_region(va(BASE, 0)).is_err() || a.is_guard_page(va(BASE, 0)) {
        return TestResult::Fail("unmap_region kept the VMA's marker");
    }
    if !a.is_guard_page(va(BASE, 3)) {
        return TestResult::Fail("unmap_region dropped another VMA's marker");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_guard_munmap_drops_markers);

/// MADV_DONTNEED and mprotect keep markers (Linux's zap skips markers and
/// change_protection leaves them).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_guard_survives_dontneed_and_mprotect() -> TestResult {
    const BASE: u64 = 0x0000_0080_0050_0000;
    let a = match faulted_space(BASE, 3) {
        Ok(a) => a,
        Err(result) => return result,
    };
    let result = (|| {
        a.madvise_guard_install(va(BASE, 1), PAGE)
            .map_err(|_| "install")?;
        a.madvise_dontneed(va(BASE, 0), 3 * PAGE)
            .map_err(|_| "dontneed")?;
        if !a.is_guard_page(va(BASE, 1)) {
            return Err("MADV_DONTNEED dropped the marker");
        }
        a.mprotect_range(va(BASE, 0), 3 * PAGE, RegionPerms::READ)
            .map_err(|_| "mprotect")?;
        a.mprotect_range(
            va(BASE, 0),
            3 * PAGE,
            RegionPerms::READ | RegionPerms::WRITE,
        )
        .map_err(|_| "mprotect back")?;
        if !a.is_guard_page(va(BASE, 1)) {
            return Err("mprotect dropped the marker");
        }
        // SAFETY: page 1 lies in a live region of `a`.
        if unsafe { a.demand_alloc_page(va(BASE, 1)) } != Err(AddressSpaceError::GuardPage) {
            return Err("the guard stopped faulting after dontneed/mprotect");
        }
        Ok(())
    })();
    core::mem::forget(a);
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_guard_survives_dontneed_and_mprotect);

/// fork copies the markers (`copy_page_range`); the copies are independent.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_guard_fork_copies_markers() -> TestResult {
    const BASE: u64 = 0x0000_0080_0060_0000;
    let parent = match faulted_space(BASE, 3) {
        Ok(a) => a,
        Err(result) => return result,
    };
    if parent.madvise_guard_install(va(BASE, 1), PAGE).is_err() {
        core::mem::forget(parent);
        return TestResult::Fail("install");
    }
    // SAFETY: the parent root is live; the child is a fresh address space.
    let child = match unsafe { parent.clone_for_fork() } {
        Ok(child) => child,
        Err(_) => {
            core::mem::forget(parent);
            return TestResult::Skip("clone_for_fork failed");
        }
    };
    let result = (|| {
        if !child.is_guard_page(va(BASE, 1)) {
            return Err("fork did not copy the marker");
        }
        if child.is_guard_page(va(BASE, 0)) || child.is_guard_page(va(BASE, 2)) {
            return Err("fork invented a marker");
        }
        // SAFETY: page 1 lies in a live region of the child.
        if unsafe { child.demand_alloc_page(va(BASE, 1)) } != Err(AddressSpaceError::GuardPage) {
            return Err("the child's copy does not fault");
        }
        parent
            .madvise_guard_remove(va(BASE, 1), PAGE)
            .map_err(|_| "parent remove")?;
        if !child.is_guard_page(va(BASE, 1)) {
            return Err("removing the parent's marker removed the child's");
        }
        child
            .madvise_guard_remove(va(BASE, 1), PAGE)
            .map_err(|_| "child remove")?;
        // SAFETY: page 1 lies in a live region of the child.
        if unsafe { child.demand_alloc_page(va(BASE, 1)) }.is_err() {
            return Err("the child's page did not fault in after remove");
        }
        Ok(())
    })();
    core::mem::forget(child);
    core::mem::forget(parent);
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_guard_fork_copies_markers);

/// mremap moves the markers with the pages (`move_ptes`); a shrink drops the
/// truncated tail's markers, and nothing is left at the old address.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_guard_mremap_moves_markers() -> TestResult {
    const OLD: u64 = 0x0000_0080_0070_0000;
    const NEW: u64 = 0x0000_0080_0080_0000;
    let a = match faulted_space(OLD, 4) {
        Ok(a) => a,
        Err(result) => return result,
    };
    let result = (|| {
        a.madvise_guard_install(va(OLD, 1), PAGE)
            .map_err(|_| "install 1")?;
        a.madvise_guard_install(va(OLD, 3), PAGE)
            .map_err(|_| "install 3")?;
        // SAFETY: `a` has a live root; the destination is unmapped.
        unsafe { a.relocate_region(va(OLD, 0), 4 * PAGE, va(NEW, 0), 2 * PAGE) }
            .map_err(|_| "mremap")?;
        if !a.is_guard_page(va(NEW, 1)) {
            return Err("mremap did not move the kept marker");
        }
        if a.is_guard_page(va(NEW, 0)) {
            return Err("mremap guarded an unguarded page");
        }
        if (0..4).any(|page| a.is_guard_page(va(OLD, page))) {
            return Err("mremap left a marker at the old address");
        }
        // The truncated page 3 is gone; remapping its old slot is unguarded.
        a.map_region(anon(OLD, 4)).map_err(|_| "remap old")?;
        if a.is_guard_page(va(OLD, 3)) {
            return Err("a truncated tail's marker survived");
        }
        // SAFETY: NEW+1 lies in a live region of `a`.
        if unsafe { a.demand_alloc_page(va(NEW, 1)) } != Err(AddressSpaceError::GuardPage) {
            return Err("the moved guard does not fault");
        }
        Ok(())
    })();
    core::mem::forget(a);
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_guard_mremap_moves_markers);

/// A guarded SHARED page keeps its borrowed frame (the data belongs to the
/// shared object) but loses its leaf, and nothing maps it again — not
/// `materialize`, not mprotect — until remove, after which it faults back to
/// the same frame.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_guard_shared_page_keeps_frame_without_leaf() -> TestResult {
    const BASE: u64 = 0x0000_0080_0090_0000;
    // SAFETY: a fresh user address space; its root is live until forgotten.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let frame = match crate::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => {
            core::mem::forget(a);
            return TestResult::Skip("frame drained");
        }
    };
    let result = (|| {
        a.map_region(Region {
            base: va(BASE, 0),
            len: PAGE,
            perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED,
            phys: alloc::vec![frame].into(),
        })
        .map_err(|_| "map shared")?;
        // SAFETY: `a` has a live root.
        unsafe { a.materialize() }.map_err(|error| match error {
            AddressSpaceError::Overlap => "materialize: Overlap",
            AddressSpaceError::OutOfRange => "materialize: OutOfRange",
            AddressSpaceError::NotImplemented => "materialize: NotImplemented",
            _ => "materialize: other",
        })?;
        if leaf(&a, va(BASE, 0)) != Some(frame) {
            return Err("setup: shared page not mapped");
        }
        a.madvise_guard_install(va(BASE, 0), PAGE)
            .map_err(|_| "install")?;
        if leaf(&a, va(BASE, 0)).is_some() {
            return Err("install left the shared page mapped");
        }
        if backing(&a, va(BASE, 0)) != frame {
            return Err("install dropped the shared object's frame");
        }
        // SAFETY: `a` has a live root.
        unsafe { a.materialize() }.map_err(|_| "rematerialize")?;
        a.mprotect_range(va(BASE, 0), PAGE, RegionPerms::READ)
            .map_err(|_| "mprotect")?;
        if leaf(&a, va(BASE, 0)).is_some() {
            return Err("materialize/mprotect remapped a guarded shared page");
        }
        let mut byte = [0u8; 1];
        if a.copy_user_bytes_nofault(va(BASE, 0), &mut byte) != 0 {
            return Err("a nofault kernel read went through a shared guard");
        }
        if a.pin_user_page(va(BASE, 0)).is_some() {
            return Err("pin_user_page pinned a shared guard page");
        }
        // SAFETY: BASE lies in a live region of `a`.
        if unsafe { a.demand_alloc_page(va(BASE, 0)) } != Err(AddressSpaceError::GuardPage) {
            return Err("a fault on a shared guard was not GuardPage");
        }
        a.madvise_guard_remove(va(BASE, 0), PAGE)
            .map_err(|_| "remove")?;
        // SAFETY: BASE lies in a live region of `a`.
        unsafe { a.demand_alloc_page(va(BASE, 0)) }.map_err(|_| "refault after remove")?;
        if leaf(&a, va(BASE, 0)) != Some(frame) {
            return Err("the shared page did not come back to its frame");
        }
        Ok(())
    })();
    core::mem::forget(a);
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_guard_shared_page_keeps_frame_without_leaf
);
