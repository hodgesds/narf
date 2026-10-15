//! Kernel tests for [`AddressSpace::access_remote`] — Linux
//! `access_remote_vm` / `get_user_pages_remote` semantics over NARF's region
//! tables. Every fixture is an inactive address space, exactly the situation
//! of a tracer reading its tracee.

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::address_space::{AddressSpace, Region, RegionPerms, RemoteAccess, RemoteBuf};
use crate::frame::cow;
use crate::{PhysAddr, VirtAddr};

const READ: RemoteAccess = RemoteAccess {
    write: false,
    force: false,
    expand_stack: None,
};
const FORCE_READ: RemoteAccess = RemoteAccess {
    write: false,
    force: true,
    expand_stack: None,
};
const WRITE: RemoteAccess = RemoteAccess {
    write: true,
    force: false,
    expand_stack: None,
};
const FORCE_WRITE: RemoteAccess = RemoteAccess {
    write: true,
    force: true,
    expand_stack: None,
};

fn pattern(i: usize) -> u8 {
    (i as u8).wrapping_mul(7).wrapping_add(1)
}

/// A zeroed-then-patterned allocator frame (`pattern(page * 4096 + i)`).
fn patterned_frame(page: usize) -> Option<PhysAddr> {
    let phys = crate::alloc_frame().ok()?.start_address();
    for i in 0..4096 {
        // SAFETY: the fresh frame is exclusively owned and direct-mapped.
        unsafe {
            phys.kernel_mut_ptr::<u8>()
                .add(i)
                .write(pattern(page * 4096 + i))
        };
    }
    Some(phys)
}

fn read_frame(phys: PhysAddr, offset: usize, out: &mut [u8]) {
    // SAFETY: test-owned live frame, bounded by the caller.
    unsafe {
        core::ptr::copy_nonoverlapping(
            phys.kernel_ptr::<u8>().add(offset),
            out.as_mut_ptr(),
            out.len(),
        )
    };
}

fn backing(a: &AddressSpace, va: u64) -> PhysAddr {
    a.page_backing(VirtAddr::new(va))
        .map_or(PhysAddr::new(0), |(_, phys)| phys)
}

#[cfg(target_arch = "x86_64")]
fn leaf(a: &AddressSpace, va: u64) -> Option<PhysAddr> {
    // SAFETY: test-owned live root; read-only walk.
    unsafe { crate::x86_64::paging::translate(a.root, VirtAddr::new(va)) }
}
#[cfg(target_arch = "aarch64")]
fn leaf(a: &AddressSpace, va: u64) -> Option<PhysAddr> {
    // SAFETY: test-owned live root; read-only walk.
    unsafe { crate::aarch64::paging::translate(a.root, VirtAddr::new(va)) }
}

/// Map `pages` patterned frames at `base` with `perms` and materialize.
fn fixture(base: u64, pages: usize, perms: RegionPerms) -> Result<AddressSpace, TestResult> {
    // SAFETY: paging is live in kernel tests.
    let a = unsafe { AddressSpace::new_for_user() }
        .map_err(|_| TestResult::Skip("AddressSpace::new_for_user not available"))?;
    let mut frames = alloc::vec::Vec::new();
    for page in 0..pages {
        frames.push(patterned_frame(page).ok_or(TestResult::Skip("frame allocator drained"))?);
    }
    a.map_region(Region {
        base: VirtAddr::new(base),
        len: pages as u64 * 4096,
        perms,
        phys: frames.into(),
    })
    .map_err(|_| TestResult::Fail("fixture map_region"))?;
    // SAFETY: the test owns the root and every backing frame.
    unsafe { a.materialize() }.map_err(|_| TestResult::Fail("fixture materialize"))?;
    Ok(a)
}

macro_rules! fixture_or_return {
    ($e:expr) => {
        match $e {
            Ok(a) => a,
            Err(r) => return r,
        }
    };
}

/// The PEEKDATA regression: a 4 KiB leaf names its frame's base, so a
/// leaf-walking reader returned the page's first byte for every byte of the
/// word. `access_remote` must return the bytes AT the address, across a page
/// boundary, and stop exactly where the mapping does.
fn smoke_memory_access_remote_reads_exact_bytes() -> TestResult {
    const BASE: u64 = 0x0000_0071_2000_0000;
    let a = fixture_or_return!(fixture(BASE, 2, RegionPerms::READ | RegionPerms::WRITE));
    let mut buf = [0u8; 16];
    // SAFETY: test-owned address space.
    if unsafe { a.access_remote(BASE + 0x123, RemoteBuf::Read(&mut buf), READ) } != 16 {
        return TestResult::Fail("in-page remote read was short");
    }
    if (0..16).any(|i| buf[i] != pattern(0x123 + i)) {
        return TestResult::Fail("remote read did not return the bytes at the in-page offset");
    }
    let mut word = [0u8; 8];
    // SAFETY: as above.
    if unsafe { a.access_remote(BASE + 0xffc, RemoteBuf::Read(&mut word), READ) } != 8 {
        return TestResult::Fail("page-straddling remote read was short");
    }
    if (0..8).any(|i| word[i] != pattern(0xffc + i)) {
        return TestResult::Fail("page-straddling remote read returned the wrong bytes");
    }
    // Stops exactly at the end of the mapping, and an unmapped start is 0.
    let mut tail = [0u8; 16];
    // SAFETY: as above.
    if unsafe { a.access_remote(BASE + 0x1ff8, RemoteBuf::Read(&mut tail), READ) } != 8 {
        return TestResult::Fail("remote read did not stop at the end of the mapping");
    }
    // SAFETY: as above.
    if unsafe { a.access_remote(BASE + 0x2000, RemoteBuf::Read(&mut tail), FORCE_READ) } != 0 {
        return TestResult::Fail("remote read of an unmapped address transferred bytes");
    }
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_access_remote_reads_exact_bytes);

/// A write into a fork-shared page breaks COW in the TARGET only: the
/// sibling's frame keeps its bytes, the target's leaf points at its copy.
/// A read-only private page (text) is written only with FOLL_FORCE, and is
/// split too.
fn smoke_memory_access_remote_write_breaks_cow_in_target_only() -> TestResult {
    const BASE: u64 = 0x0000_0071_2100_0000;
    cow::__test_clear();
    for (perms, what) in [
        (RegionPerms::READ | RegionPerms::WRITE, "writable"),
        (RegionPerms::READ | RegionPerms::EXEC, "read-only text"),
    ] {
        let parent = fixture_or_return!(fixture(BASE, 1, perms));
        let shared = backing(&parent, BASE);
        // SAFETY: test-owned parent.
        let child = match unsafe { parent.clone_for_fork() } {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("clone_for_fork"),
        };
        // SAFETY: test-owned child.
        if unsafe { child.materialize() }.is_err() {
            return TestResult::Fail("child materialize");
        }
        if cow::count(shared) < 2 {
            return TestResult::Fail("fork did not share the frame");
        }
        let stamp = [0xA5u8; 8];
        let read_only = !perms.contains(RegionPerms::WRITE);
        // SAFETY: test-owned child.
        let plain = unsafe { child.access_remote(BASE + 8, RemoteBuf::Write(&stamp), WRITE) };
        if read_only && plain != 0 {
            let _ = what;
            return TestResult::Fail("a non-forced write landed in read-only text");
        }
        if !read_only && plain != 8 {
            return TestResult::Fail("a write to a writable COW page failed");
        }
        if read_only {
            // SAFETY: as above.
            if unsafe { child.access_remote(BASE + 8, RemoteBuf::Write(&stamp), FORCE_WRITE) } != 8
            {
                return TestResult::Fail("FOLL_FORCE write to read-only text failed");
            }
        }
        let mine = backing(&child, BASE);
        if mine == shared || mine.raw() == 0 {
            return TestResult::Fail("remote write did not give the target a private copy");
        }
        let mut seen = [0u8; 8];
        read_frame(shared, 8, &mut seen);
        if (0..8).any(|i| seen[i] != pattern(8 + i)) {
            return TestResult::Fail("remote write leaked into the fork sibling's frame");
        }
        read_frame(mine, 8, &mut seen);
        if seen != stamp {
            return TestResult::Fail("target's private copy lacks the written bytes");
        }
        // The copy carries the rest of the page.
        read_frame(mine, 0, &mut seen);
        if (0..8).any(|i| seen[i] != pattern(i)) {
            return TestResult::Fail("COW copy lost the untouched bytes");
        }
        // The owner's live leaf must now name its copy.
        if leaf(&child, BASE) != Some(mine) {
            return TestResult::Fail("target leaf still names the shared frame");
        }
        if leaf(&parent, BASE) != Some(shared) {
            return TestResult::Fail("sibling leaf moved off its frame");
        }
        drop(child);
        drop(parent);
    }
    cow::__test_clear();
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_access_remote_write_breaks_cow_in_target_only
);

/// PROT_NONE: GUP refuses it without FOLL_FORCE and admits it with
/// (VM_MAYREAD / is_cow_mapping). A forced access backs a lazy page but must
/// never install an accessible leaf for the owner.
fn smoke_memory_access_remote_prot_none_needs_force_and_stays_unmapped() -> TestResult {
    const BASE: u64 = 0x0000_0071_2200_0000;
    // SAFETY: paging is live in kernel tests.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("AddressSpace::new_for_user not available"),
    };
    let Some(frame) = patterned_frame(0) else {
        return TestResult::Skip("frame allocator drained");
    };
    // Page 0 resident, page 1 lazy.
    if a.map_region(Region {
        base: VirtAddr::new(BASE),
        len: 0x2000,
        perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::ANON_MERGEABLE,
        phys: alloc::vec![frame, PhysAddr::new(0)].into(),
    })
    .is_err()
    {
        return TestResult::Fail("map_region");
    }
    // SAFETY: test-owned root and frame.
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize");
    }
    if a.mprotect_range(VirtAddr::new(BASE), 0x2000, RegionPerms(0))
        .is_err()
    {
        return TestResult::Fail("mprotect(PROT_NONE)");
    }
    let mut word = [0u8; 8];
    // SAFETY: test-owned address space.
    if unsafe { a.access_remote(BASE + 16, RemoteBuf::Read(&mut word), READ) } != 0 {
        return TestResult::Fail("non-forced read reached a PROT_NONE page");
    }
    // SAFETY: as above.
    if unsafe { a.access_remote(BASE + 16, RemoteBuf::Read(&mut word), FORCE_READ) } != 8
        || (0..8).any(|i| word[i] != pattern(16 + i))
    {
        return TestResult::Fail("forced read of a PROT_NONE page");
    }
    let stamp = [0x3Cu8; 8];
    // SAFETY: as above.
    if unsafe { a.access_remote(BASE + 16, RemoteBuf::Write(&stamp), FORCE_WRITE) } != 8 {
        return TestResult::Fail("forced write of a PROT_NONE page");
    }
    read_frame(backing(&a, BASE), 16, &mut word);
    if word != stamp {
        return TestResult::Fail("forced PROT_NONE write did not land in the frame");
    }
    // Lazy PROT_NONE page: zeros, backed, and still no leaf.
    word = [0xFF; 8];
    // SAFETY: as above.
    if unsafe { a.access_remote(BASE + 0x1000, RemoteBuf::Read(&mut word), FORCE_READ) } != 8
        || word != [0u8; 8]
    {
        return TestResult::Fail("forced read of a lazy PROT_NONE page");
    }
    if backing(&a, BASE + 0x1000).raw() == 0 {
        return TestResult::Fail("forced read did not back the lazy PROT_NONE page");
    }
    if leaf(&a, BASE).is_some() || leaf(&a, BASE + 0x1000).is_some() {
        return TestResult::Fail("forced access installed a leaf in a PROT_NONE VMA");
    }
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_access_remote_prot_none_needs_force_and_stays_unmapped
);

/// Shared mappings: VM_IO/VM_PFNMAP (a SHARED, LOCK_EXEMPT region whose
/// frames are not allocator RAM) is never accessible; a shared mapping is
/// written in place when VM_WRITE and never written otherwise, even forced
/// (not a COW mapping).
fn smoke_memory_access_remote_shared_and_pfn_rules() -> TestResult {
    const BASE: u64 = 0x0000_0071_2300_0000;
    let Some(frame) = patterned_frame(0) else {
        return TestResult::Skip("frame allocator drained");
    };
    let mut verdict = TestResult::Pass;
    for (perms, read_ok, write_ok, what) in [
        (
            RegionPerms::READ | RegionPerms::SHARED | RegionPerms::LOCK_EXEMPT,
            false,
            false,
            "PFN mapping",
        ),
        (
            RegionPerms::READ
                | RegionPerms::SHARED
                | RegionPerms::LOCK_EXEMPT
                | RegionPerms::PINNABLE_RAM,
            true,
            false,
            "read-only shared RAM",
        ),
        (
            RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED,
            true,
            true,
            "writable shared",
        ),
    ] {
        let _ = what;
        // SAFETY: paging is live in kernel tests.
        let Ok(a) = (unsafe { AddressSpace::new_for_user() }) else {
            verdict = TestResult::Skip("AddressSpace::new_for_user not available");
            break;
        };
        if a.map_region(Region {
            base: VirtAddr::new(BASE),
            len: 4096,
            perms,
            phys: alloc::vec![frame].into(),
        })
        .is_err()
        {
            verdict = TestResult::Fail("shared map_region");
            break;
        }
        let mut word = [0u8; 8];
        // SAFETY: test-owned address space; SHARED frames stay test-owned.
        let r = unsafe { a.access_remote(BASE, RemoteBuf::Read(&mut word), FORCE_READ) };
        if (r == 8) != read_ok {
            verdict = TestResult::Fail("shared/PFN read admission is wrong");
            break;
        }
        let stamp = [0x5Au8; 8];
        // SAFETY: as above.
        let w = unsafe { a.access_remote(BASE + 64, RemoteBuf::Write(&stamp), FORCE_WRITE) };
        if (w == 8) != write_ok {
            verdict = TestResult::Fail("shared/PFN write admission is wrong");
            break;
        }
        if write_ok {
            read_frame(frame, 64, &mut word);
            if word != stamp || backing(&a, BASE) != frame {
                verdict = TestResult::Fail("shared write did not land in the mapped object");
                break;
            }
        }
        drop(a);
    }
    // SHARED regions borrow their frames; the test owns this one.
    crate::free_frame(crate::PhysFrame::new(frame));
    verdict
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_access_remote_shared_and_pfn_rules);
