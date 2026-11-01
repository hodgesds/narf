//! Kernel page-attribute smokes (`crate::pageattr`).
//!
//! * a [`WcPages`] allocation is zero, recorded write-combining, and every
//!   kernel alias of every page is a 4 KiB write-combining leaf; dropping it
//!   restores write-back and forgets the record;
//! * splitting a huge direct-map leaf keeps every neighbouring translation;
//! * bytes written through the write-back alias before a retype are the
//!   bytes read through the write-combining alias after it, and back;
//! * refusals (not RAM, already typed, repeated, never typed) change nothing;
//! * a user leaf of a retyped page takes the recorded type whatever its
//!   region asked, through the real `map_region` + `materialize` path;
//! * aarch64 refuses every retype.

#![cfg(all(
    feature = "kernel-test",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use crate::pageattr::{ram_memory_type, set_pages_wb, set_pages_wc, PageAttrError, WcPages};
use narf_kernel_test::{kernel_test_in, TestResult};

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::*;
    use crate::address_space::__user_leaf_flags_for_test;
    use crate::frame::PhysFrame;
    use crate::memtype::MemoryType;
    use crate::memtype::{effective_memory_type, ram_alias_refusals};
    use crate::pageattr::{leaked_pages, retyped_pages, supported};
    use crate::x86_64::paging::{leaf_flags_at, translate, PtFlags};
    use crate::PhysAddr;
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    const PAGE: u64 = 4096;

    fn root() -> PhysAddr {
        crate::bpf_text::kernel_root_for_mapping().expect("kernel root recorded")
    }

    fn alias(phys: PhysAddr) -> VirtAddr {
        VirtAddr::new(phys.raw() | crate::addr::direct_map_base())
    }

    /// The direct-map leaf of `phys`: its memory-type selector and size.
    fn kernel_leaf(phys: PhysAddr) -> Option<(u64, u64)> {
        // SAFETY: read-only walk of the live kernel root.
        let (flags, size) = unsafe { leaf_flags_at(root(), alias(phys)) }?;
        let mask = if size == PAGE {
            PtFlags::CACHE_MASK_4K
        } else {
            PtFlags::CACHE_MASK_LARGE
        };
        Some((flags.bits() & mask.bits(), size))
    }

    fn wc_bits() -> u64 {
        crate::memtype::x86_leaf_bits_4k(MemoryType::WriteCombining).bits()
    }

    fn device_perms(base: RegionPerms) -> RegionPerms {
        base | RegionPerms::SHARED | RegionPerms::LOCK_EXEMPT
    }

    fn read_u64s(phys: PhysAddr) -> impl Iterator<Item = u64> {
        let base = phys.kernel_ptr::<u64>();
        // SAFETY: an owned, mapped page; volatile so WC reads are real reads.
        (0..512).map(move |i| unsafe { core::ptr::read_volatile(base.add(i)) })
    }

    fn fill(phys: PhysAddr, value: u64) {
        let base = phys.kernel_mut_ptr::<u64>();
        for i in 0..512 {
            // SAFETY: an owned, mapped page.
            unsafe { core::ptr::write_volatile(base.add(i), value ^ i as u64) };
        }
        // SAFETY: SFENCE has no preconditions; drains WC buffers.
        unsafe { core::arch::asm!("sfence", options(nostack, preserves_flags)) };
    }

    fn holds(phys: PhysAddr, value: u64) -> bool {
        read_u64s(phys)
            .enumerate()
            .all(|(i, word)| word == value ^ i as u64)
    }

    fn smoke_pageattr_wc_pages_retype_every_alias_and_restore() -> TestResult {
        if !supported() {
            return TestResult::Fail("pageattr unsupported after boot on x86_64");
        }
        let (retyped, leaked) = (retyped_pages(), leaked_pages());
        let pages = match WcPages::allocate(5) {
            Ok(pages) => pages,
            Err(PageAttrError::NoFrame) => return TestResult::Skip("frame allocator drained"),
            Err(_) => return TestResult::Fail("WcPages::allocate refused"),
        };
        let phys: alloc::vec::Vec<PhysAddr> =
            pages.frames().iter().map(|f| f.start_address()).collect();
        if retyped_pages() != retyped + 5 {
            return TestResult::Fail("retyped page count did not grow by the allocation");
        }
        for &p in &phys {
            if ram_memory_type(p) != Some(MemoryType::WriteCombining) {
                return TestResult::Fail("allocated page is not recorded write-combining");
            }
            if kernel_leaf(p) != Some((wc_bits(), PAGE)) {
                return TestResult::Fail("direct-map alias is not a 4 KiB WC leaf");
            }
            if read_u64s(p).any(|word| word != 0) {
                return TestResult::Fail("WcPages allocation is not zeroed");
            }
            if let Some(va) = crate::x86_64::mmu::kernel_window_va(p.raw()) {
                // SAFETY: read-only walk.
                let leaf = unsafe { leaf_flags_at(root(), VirtAddr::new(va)) };
                if leaf.map(|(f, s)| (f.bits() & PtFlags::CACHE_MASK_4K.bits(), s))
                    != Some((wc_bits(), PAGE))
                {
                    return TestResult::Fail("kernel-window alias was not retyped");
                }
            }
            fill(p, 0x5a5a_0000_0000_0000);
            if !holds(p, 0x5a5a_0000_0000_0000) {
                return TestResult::Fail("WC alias did not read back its writes");
            }
        }
        drop(pages);
        for &p in &phys {
            if ram_memory_type(p).is_some() {
                return TestResult::Fail("restored page is still recorded");
            }
            match kernel_leaf(p) {
                Some((0, PAGE)) => {}
                _ => return TestResult::Fail("restored alias is not a write-back 4 KiB leaf"),
            }
        }
        if retyped_pages() != retyped || leaked_pages() != leaked {
            return TestResult::Fail("restore leaked a record or a page");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/pageattr",
        smoke_pageattr_wc_pages_retype_every_alias_and_restore
    );

    /// A retype splits the alias's huge leaf into identical translations, and
    /// moves dirty write-back lines to memory before the first uncached read:
    /// bytes written through the write-back alias are what the WC alias reads,
    /// and WC writes are what the restored write-back alias reads.
    fn smoke_pageattr_split_keeps_translations_and_flushes_lines() -> TestResult {
        let Ok(frame) = crate::alloc_frame() else {
            return TestResult::Skip("frame allocator drained");
        };
        let p = frame.start_address();
        let result = (|| {
            let (_, before) = kernel_leaf(p).ok_or("frame has no direct-map alias")?;
            // Neighbours inside the leaf being split, where they exist.
            let base = p.raw() & !(before - 1);
            let neighbours: alloc::vec::Vec<u64> = [base, p.raw() ^ PAGE, base + before - PAGE]
                .into_iter()
                .filter(|&n| n != p.raw() && crate::frame::is_system_ram(PhysAddr::new(n)))
                .collect();
            fill(p, 0x1234_5678_0000_0000);
            // SAFETY: an owned frame, restored before it is freed below.
            unsafe { set_pages_wc(core::slice::from_ref(&frame)) }
                .map_err(|_| "set_pages_wc refused an owned RAM frame")?;
            let after = kernel_leaf(p);
            let mut outcome = Ok(());
            if after != Some((wc_bits(), PAGE)) {
                outcome = Err("retyped alias is not a 4 KiB WC leaf");
            }
            for &n in &neighbours {
                let n = PhysAddr::new(n);
                // SAFETY: read-only walk.
                if unsafe { translate(root(), alias(n)) } != Some(n) {
                    outcome = Err("split changed a neighbouring translation");
                }
                if kernel_leaf(n).is_none_or(|(bits, _)| bits != 0) {
                    outcome = Err("split changed a neighbour's memory type");
                }
            }
            if outcome.is_ok() && !holds(p, 0x1234_5678_0000_0000) {
                outcome = Err("WC alias read memory under a dirty write-back line");
            }
            fill(p, 0x0fed_cba9_0000_0000);
            // SAFETY: as above. A failed restore leaks the frame below.
            unsafe { set_pages_wb(core::slice::from_ref(&frame)) }
                .map_err(|_| "set_pages_wb refused a retyped frame")?;
            if outcome.is_ok() && !holds(p, 0x0fed_cba9_0000_0000) {
                outcome = Err("write-back alias lost bytes written write-combining");
            }
            outcome
        })();
        // Never free a page whose kernel aliases are still write-combining.
        if ram_memory_type(p).is_none() {
            crate::free_frame(frame);
        }
        match result {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!(
        "memory/pageattr",
        smoke_pageattr_split_keeps_translations_and_flushes_lines
    );

    /// A physical frame that is certainly not System RAM, as `memtype_tests`
    /// picks one. Never dereferenced: the refusal precedes every walk.
    fn device_frame() -> Option<PhysFrame> {
        const GIB: u64 = 1 << 30;
        let end = crate::frame::managed_phys_end().max(4 * GIB);
        let phys = PhysAddr::new(end.div_ceil(GIB) * GIB + GIB);
        (!crate::frame::is_system_ram(phys)).then(|| PhysFrame::new(phys))
    }

    fn smoke_pageattr_refusals_change_nothing() -> TestResult {
        let (Ok(a), Ok(b)) = (crate::alloc_frame(), crate::alloc_frame()) else {
            return TestResult::Skip("frame allocator drained");
        };
        let Some(device) = device_frame() else {
            crate::free_frame(a);
            crate::free_frame(b);
            return TestResult::Skip("no non-RAM physical address to test with");
        };
        let untouched = |f: &PhysFrame| {
            ram_memory_type(f.start_address()).is_none()
                && kernel_leaf(f.start_address()).is_some_and(|(bits, _)| bits == 0)
        };
        let retyped = retyped_pages();
        let result = (|| {
            // SAFETY: every RAM frame is owned by this test and restored
            // before it is freed; the device frame is refused before any walk.
            unsafe {
                if set_pages_wc(&[b, device]) != Err(PageAttrError::NotRam) || !untouched(&b) {
                    return Err("a non-RAM page did not refuse the whole request");
                }
                if set_pages_wb(&[b]) != Err(PageAttrError::Busy) {
                    return Err("restoring a never-retyped page was accepted");
                }
                if set_pages_wc(&[b, b]) != Err(PageAttrError::Busy) || !untouched(&b) {
                    return Err("a repeated page was accepted");
                }
                set_pages_wc(&[a]).map_err(|_| "set_pages_wc refused an owned frame")?;
                let refused = [
                    set_pages_wc(&[b, a]) == Err(PageAttrError::Busy),
                    untouched(&b),
                    set_pages_wb(&[a, a]) == Err(PageAttrError::Busy),
                    set_pages_wb(&[a, b]) == Err(PageAttrError::Busy),
                    ram_memory_type(a.start_address()) == Some(MemoryType::WriteCombining),
                    retyped_pages() == retyped + 1,
                ];
                set_pages_wb(&[a]).map_err(|_| "set_pages_wb refused a retyped frame")?;
                if refused.contains(&false) {
                    return Err("a busy request changed a page or its record");
                }
            }
            if retyped_pages() != retyped || !untouched(&a) {
                return Err("restore left a record or a typed alias");
            }
            Ok(())
        })();
        for frame in [a, b] {
            if ram_memory_type(frame.start_address()).is_none() {
                crate::free_frame(frame);
            }
        }
        match result {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!("memory/pageattr", smoke_pageattr_refusals_change_nothing);

    /// `lookup_memtype` for RAM: a retyped page's user leaf is write-combining
    /// whatever a special region asked, and is never typed in an ordinary
    /// region; once restored, a WC request is refused again.
    fn smoke_pageattr_user_leaf_takes_recorded_type() -> TestResult {
        let pages = match WcPages::allocate(1) {
            Ok(pages) => pages,
            Err(PageAttrError::NoFrame) => return TestResult::Skip("frame allocator drained"),
            Err(_) => return TestResult::Fail("WcPages::allocate refused"),
        };
        let p = pages.frames()[0].start_address();
        let rw = RegionPerms::READ | RegionPerms::WRITE;
        let refusals = ram_alias_refusals();
        for mt in MemoryType::ALL {
            let perms = device_perms(rw).with_memory_type(mt);
            if effective_memory_type(perms, p) != MemoryType::WriteCombining {
                return TestResult::Fail("a special region did not take the recorded type");
            }
            if __user_leaf_flags_for_test(perms, true, p).bits() & PtFlags::CACHE_MASK_4K.bits()
                != wc_bits()
            {
                return TestResult::Fail("leaf encoder ignored the recorded type");
            }
        }
        if effective_memory_type(rw.with_memory_type(MemoryType::WriteCombining), p)
            != MemoryType::WriteBack
        {
            return TestResult::Fail("an ordinary region carried a memory type");
        }
        if ram_alias_refusals() != refusals {
            return TestResult::Fail("a retyped page counted as a refused alias");
        }
        // SAFETY: paging and the frame allocator are live in the kernel suite.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(a) => a,
            Err(_) => return TestResult::Skip("new_for_user failed"),
        };
        let base = VirtAddr::new(0x0000_0000_4000_0000);
        let result = (|| {
            aspace
                .map_region(Region {
                    base,
                    len: PAGE,
                    // The region asks write-back: the recorded type still wins.
                    perms: device_perms(rw),
                    phys: alloc::vec![p].into(),
                })
                .map_err(|_| "map_region failed")?;
            // SAFETY: aspace owns a live root and the validated region.
            unsafe { aspace.materialize() }.map_err(|_| "materialize failed")?;
            // SAFETY: aspace's root is live.
            let leaf = unsafe { leaf_flags_at(aspace.root, base) }.ok_or("page not mapped")?;
            if leaf.1 != PAGE || leaf.0.bits() & PtFlags::CACHE_MASK_4K.bits() != wc_bits() {
                return Err("user leaf of a retyped page is not write-combining");
            }
            Ok(())
        })();
        let _ = aspace.unmap_region(base);
        drop(aspace);
        drop(pages);
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
        let perms = device_perms(rw).with_memory_type(MemoryType::WriteCombining);
        if effective_memory_type(perms, p) != MemoryType::WriteBack
            || ram_alias_refusals() <= refusals
        {
            return TestResult::Fail("a restored page kept its recorded type");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/pageattr",
        smoke_pageattr_user_leaf_takes_recorded_type
    );
}

#[cfg(target_arch = "aarch64")]
fn smoke_pageattr_aarch64_refuses_retype() -> TestResult {
    if crate::pageattr::supported() {
        return TestResult::Fail("aarch64 claims kernel page retyping");
    }
    if WcPages::allocate(1).err() != Some(PageAttrError::Unsupported) {
        return TestResult::Fail("WcPages::allocate did not refuse on aarch64");
    }
    let Ok(frame) = crate::alloc_frame() else {
        return TestResult::Skip("frame allocator drained");
    };
    // SAFETY: refused before any page-table access.
    let refused = unsafe { set_pages_wc(&[frame]) } == Err(PageAttrError::Unsupported)
        && unsafe { set_pages_wb(&[frame]) } == Err(PageAttrError::Unsupported)
        && ram_memory_type(frame.start_address()).is_none();
    crate::free_frame(frame);
    if !refused {
        return TestResult::Fail("a retype was not refused on aarch64");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("memory/pageattr", smoke_pageattr_aarch64_refuses_retype);
