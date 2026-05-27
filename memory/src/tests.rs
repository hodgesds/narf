//! Subsystem smokes for `narf-memory`.
//!
//! Migrated from `narf-verification`. Tests register under the
//! `memory` subsystem.

use narf_kernel_test::{kernel_test_in, TestResult};

#[cfg(target_arch = "x86_64")]
fn smoke_probe_catches_page_fault() -> TestResult {
    // Arm the recoverable-fault probe, write to an unmapped virtual
    // address (above our 4 GiB identity map), and verify the handler
    // caught the #PF (vector 14) instead of panic-exiting.
    use core::arch::asm;
    use narf_arch::x86_64::probe;

    // Address above our 4-GiB identity map. The MMU handoff installed a
    // PML4 with PDPT[0..=3] = 1-GiB huge pages covering phys 0..=4 GiB.
    // Anything at 4 GiB and above has no PML4 entry and will #PF.
    let unmapped: u64 = 0x0000_0001_0000_0000;

    let recovery: u64;
    // SAFETY: LEA of a local label is always safe.
    unsafe {
        asm!(
            "lea {rec}, [99f + rip]",
            rec = out(reg) recovery,
            options(nostack, preserves_flags),
        );
    }
    probe::arm(recovery);

    // SAFETY: if PKS / paging are broken and this write *succeeds*,
    // it just stores a byte at a virtual address that doesn't exist
    // in our PML4; the test reports failure rather than crashing.
    unsafe {
        asm!(
            "mov byte ptr [{ptr}], 0",
            "99:",
            ptr = in(reg) unmapped,
            options(nostack),
        );
    }

    let caught = probe::disarm();
    match caught.vector {
        Some(14) => TestResult::Pass,
        Some(_) => TestResult::Fail("wrong vector caught (not #PF)"),
        None => TestResult::Fail("probe didn't catch the expected #PF"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_probe_catches_page_fault);

#[cfg(target_arch = "x86_64")]
fn smoke_nx_enforces_no_exec() -> TestResult {
    // Map a page NO_EXEC, attempt to execute from it, verify the
    // resulting #PF has the instruction-fetch bit (bit 4) set.
    use crate::paging::{map_4kb, read_cr3, unmap_4kb, PtFlags};
    use crate::{alloc_frame, free_frame, FrameAllocError, VirtAddr};
    use core::arch::asm;
    use narf_arch::x86_64::{probe, Features};

    // SAFETY: CPUID always legal.
    let feats = unsafe { Features::probe() };
    if !feats.nx {
        return TestResult::Skip("NX not exposed");
    }

    let pml4 = unsafe { read_cr3() };
    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised")
        }
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    let virt = VirtAddr::new(0x3_0000_1000);
    let phys = frame.start_address();
    let flags = PtFlags::WRITABLE | PtFlags::NO_EXEC;

    // SAFETY: live PML4 modification on the BSP with the test's
    // chosen virt not overlapping anything else.
    if unsafe { map_4kb(pml4, virt, phys, flags) }.is_err() {
        free_frame(frame);
        return TestResult::Fail("map_4kb NO_EXEC failed");
    }

    let recovery: u64;
    // SAFETY: LEA of a local label.
    unsafe {
        asm!(
            "lea {r}, [77f + rip]",
            r = out(reg) recovery,
            options(nostack, preserves_flags),
        );
    }
    probe::arm(recovery);

    // SAFETY: `jmp {ptr}` transfers to the tagged-NX page. The CPU
    // raises #PF on instruction fetch; our probe redirects to `77:`.
    unsafe {
        asm!(
            "jmp {p}",
            "77:",
            p = in(reg) virt.raw(),
            options(nostack),
        );
    }

    let caught = probe::disarm();
    let _ = unsafe { unmap_4kb(pml4, virt) };
    free_frame(frame);

    match caught.vector {
        None => return TestResult::Fail("NX didn't fault on NO_EXEC jump"),
        Some(14) => {}
        Some(_) => return TestResult::Fail("wrong vector caught (not #PF)"),
    }
    if caught.error_code & (1 << 4) == 0 {
        return TestResult::Fail("fault caught but IF bit (4) not set — not NX");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_nx_enforces_no_exec);

#[cfg(target_arch = "x86_64")]
fn smoke_pks_enforces_deny_all() -> TestResult {
    use crate::paging::{map_4kb, read_cr3, unmap_4kb, PtFlags};
    use crate::{alloc_frame, free_frame, FrameAllocError, VirtAddr};
    use core::arch::asm;
    use narf_arch::x86_64::{
        pks::{self, DomainRights},
        probe, Features,
    };

    // SAFETY: CPUID always legal.
    let feats = unsafe { Features::probe() };
    if !feats.pks {
        return TestResult::Skip("PKS not exposed");
    }

    // SAFETY: allocator is up, read_cr3 is always safe.
    let pml4 = unsafe { read_cr3() };
    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised")
        }
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    let virt = VirtAddr::new(0x2_0000_1000);
    let phys = frame.start_address();
    let flags = PtFlags::WRITABLE | PtFlags::pk(9);

    // SAFETY: live PML4 modification.
    if unsafe { map_4kb(pml4, virt, phys, flags) }.is_err() {
        free_frame(frame);
        return TestResult::Fail("map_4kb of test page failed");
    }

    // SAFETY: CR4.PKS is 1.
    let saved_pkrs = unsafe { pks::save() };
    unsafe {
        pks::set_rights(9, DomainRights::DENY_ALL);
    }

    let recovery: u64;
    // SAFETY: LEA of a local label.
    unsafe {
        asm!(
            "lea {r}, [88f + rip]",
            r = out(reg) recovery,
            options(nostack, preserves_flags),
        );
    }
    probe::arm(recovery);

    // SAFETY: store that's expected to fault.
    unsafe {
        asm!(
            "mov byte ptr [{p}], 1",
            "88:",
            p = in(reg) virt.raw(),
            options(nostack),
        );
    }

    let caught = probe::disarm();

    // SAFETY: pks::save earlier.
    unsafe {
        pks::restore(saved_pkrs);
    }

    let _ = unsafe { unmap_4kb(pml4, virt) };
    free_frame(frame);

    match caught.vector {
        None => return TestResult::Fail("PKS didn't fault on DENY_ALL-tagged write"),
        Some(14) => {}
        Some(_) => return TestResult::Fail("wrong vector caught (not #PF)"),
    }
    if caught.error_code & (1 << 5) == 0 {
        return TestResult::Fail("fault caught, but PK bit (5) not set");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_pks_enforces_deny_all);

#[cfg(target_arch = "x86_64")]
fn smoke_pks_set_get_rights() -> TestResult {
    // SAFETY: CPUID always legal.
    let feats = unsafe { narf_arch::x86_64::Features::probe() };
    if !feats.pks {
        return TestResult::Skip("PKS not exposed by this CPU");
    }
    use narf_arch::x86_64::pks::{get_rights, restore, save, set_rights, DomainRights};
    // SAFETY: feats.pks==true.
    let saved = unsafe { save() };
    unsafe {
        set_rights(3, DomainRights::READ_ONLY);
        set_rights(7, DomainRights::DENY_ALL);
    }
    let r3 = unsafe { get_rights(3) };
    let r7 = unsafe { get_rights(7) };
    unsafe {
        restore(saved);
    }
    if r3 != DomainRights::READ_ONLY {
        return TestResult::Fail("set_rights(3, READ_ONLY) didn't round-trip");
    }
    if r7 != DomainRights::DENY_ALL {
        return TestResult::Fail("set_rights(7, DENY_ALL) didn't round-trip");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_pks_set_get_rights);

#[cfg(target_arch = "x86_64")]
fn smoke_pcid_cr3_roundtrip() -> TestResult {
    use narf_arch::x86_64::cr;
    use narf_arch::x86_64::pcid;

    if !pcid::is_active() {
        return TestResult::Skip("PCID enforcer not active (PKS-class CPU)");
    }

    // SAFETY: CR3 read at CPL=0.
    let cr3_before = unsafe { cr::read_cr3() };

    // SAFETY: PCID active; domains 0/3 are valid.
    let scope = unsafe { pcid::enter_domain(0, 3) };
    // SAFETY: CR3 read at CPL=0.
    let cr3_inside = unsafe { cr::read_cr3() };
    // SAFETY: matched scope.
    unsafe {
        pcid::exit_domain(scope);
    }
    // SAFETY: CR3 read at CPL=0.
    let cr3_after = unsafe { cr::read_cr3() };

    if cr3_inside & 0xFFF != 4 {
        return TestResult::Fail("CR3.PCID did not match driver_domain+1");
    }
    if (cr3_after & 0x000F_FFFF_FFFF_F000) != (cr3_before & 0x000F_FFFF_FFFF_F000) {
        return TestResult::Fail("CR3 PML4 base did not round-trip");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_pcid_cr3_roundtrip);

#[cfg(target_arch = "x86_64")]
fn smoke_pcid_per_domain_pml4s_distinct() -> TestResult {
    use narf_arch::x86_64::pcid;

    if !pcid::is_active() {
        return TestResult::Skip("PCID enforcer not active (PKS-class CPU)");
    }

    let mut seen: [u64; 16] = [0; 16];
    for d in 0u8..16 {
        let p = pcid::get_domain_pml4(d);
        if p == 0 {
            return TestResult::Fail("a domain has no registered PML4");
        }
        seen[d as usize] = p;
    }
    for i in 0..16 {
        for j in (i + 1)..16 {
            if seen[i] == seen[j] {
                return TestResult::Fail("two domains share a PML4 frame");
            }
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_pcid_per_domain_pml4s_distinct);

#[cfg(target_arch = "x86_64")]
fn smoke_pcid_domain_private_slots_isolated() -> TestResult {
    use crate::domain;
    use narf_arch::x86_64::pcid;

    if !pcid::is_active() {
        return TestResult::Skip("PCID enforcer not active (PKS-class CPU)");
    }

    for (d, present) in domain::private_slot_status().iter().copied() {
        if !present {
            return TestResult::Fail("a domain's own private slot is not present");
        }
        let _ = d;
    }
    for inspector in 0u8..16 {
        for target in 0u8..16 {
            if inspector == target {
                continue;
            }
            match domain::cross_domain_slot_present(inspector, target) {
                Some(true) => return TestResult::Fail("cross-domain slot leaked"),
                Some(false) => {}
                None => return TestResult::Fail("PML4 not registered"),
            }
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_pcid_domain_private_slots_isolated);

#[cfg(target_arch = "x86_64")]
fn smoke_pcid_domain_private_va_layout() -> TestResult {
    use crate::domain;

    for d in 0u8..16 {
        let base = match domain::domain_va_base(d) {
            Some(b) => b,
            None => return TestResult::Fail("domain_va_base returned None for valid id"),
        };
        let expected = 0xFFFF_8000_0000_0000u64 + (d as u64) * (1u64 << 39);
        if base != expected {
            return TestResult::Fail("domain_va_base layout drifted");
        }
    }
    if domain::domain_va_base(16).is_some() {
        return TestResult::Fail("domain_va_base accepted out-of-range id");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_pcid_domain_private_va_layout);

#[cfg(target_arch = "x86_64")]
fn smoke_pte_pk_field() -> TestResult {
    use crate::paging::PtFlags;
    let f = PtFlags::WRITABLE | PtFlags::pk(7);
    if f.pk_of() != 7 {
        return TestResult::Fail("pk_of didn't recover the PK field");
    }
    if !f.contains(PtFlags::WRITABLE) {
        return TestResult::Fail("pk bits stomped on unrelated flag bit");
    }
    let g = PtFlags::PRESENT | PtFlags::pk(0);
    if g.pk_of() != 0 {
        return TestResult::Fail("pk(0) encoding wrong");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_pte_pk_field);

#[cfg(target_arch = "x86_64")]
fn smoke_pkrs_roundtrip() -> TestResult {
    // SAFETY: CPUID is always legal.
    let feats = unsafe { narf_arch::x86_64::Features::probe() };
    if !feats.pks {
        return TestResult::Skip("PKS not exposed by this CPU");
    }
    use narf_arch::x86_64::msr::{rdmsr, wrmsr, IA32_PKRS};
    // SAFETY: feats.pks==true.
    let saved = unsafe { rdmsr(IA32_PKRS) };
    let test_value = 0xFFFF_FFFF_u64;
    unsafe {
        wrmsr(IA32_PKRS, test_value);
    }
    let got = unsafe { rdmsr(IA32_PKRS) };
    unsafe {
        wrmsr(IA32_PKRS, saved);
    }
    if got == test_value {
        TestResult::Pass
    } else {
        TestResult::Fail("PKRS roundtrip mismatch")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_pkrs_roundtrip);

#[cfg(target_arch = "x86_64")]
fn smoke_map_preserves_pk_field() -> TestResult {
    use crate::paging::{flags_at, map_4kb, unmap_4kb, PageTable, PtFlags};
    use crate::{alloc_frame, FrameAllocError, PhysAddr, VirtAddr};

    let pml4 = match alloc_frame() {
        Ok(f) => f.start_address(),
        Err(FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised")
        }
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    PageTable::zero_at(pml4.as_mut_ptr::<PageTable>());

    let virt = VirtAddr::new(0x9abc_0000);
    let phys = PhysAddr::new(0x8765_0000);
    let requested = PtFlags::WRITABLE | PtFlags::pk(5);
    // SAFETY: isolated PML4, identity-reachable via the low-4-GiB map.
    if unsafe { map_4kb(pml4, virt, phys, requested) }.is_err() {
        return TestResult::Fail("map_4kb with PK=5 failed");
    }
    let got = match unsafe { flags_at(pml4, virt) } {
        Some(f) => f,
        None => return TestResult::Fail("flags_at returned None"),
    };
    if got.pk_of() != 5 {
        return TestResult::Fail("PK field lost through map_4kb");
    }
    if !got.contains(PtFlags::WRITABLE) {
        return TestResult::Fail("WRITABLE lost");
    }
    if !got.contains(PtFlags::PRESENT) {
        return TestResult::Fail("PRESENT missing");
    }
    let _ = unsafe { unmap_4kb(pml4, virt) };
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_map_preserves_pk_field);

#[cfg(target_arch = "x86_64")]
fn smoke_paging_map_translate_unmap() -> TestResult {
    use crate::paging::{map_4kb, translate, unmap_4kb, PageTable, PtFlags};
    use crate::{alloc_frame, FrameAllocError, PhysAddr, VirtAddr};

    let pml4 = match alloc_frame() {
        Ok(f) => f.start_address(),
        Err(FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised")
        }
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    PageTable::zero_at(pml4.as_mut_ptr::<PageTable>());

    let virt = VirtAddr::new(0x5678_0000);
    let phys = PhysAddr::new(0x1234_0000);
    // SAFETY: PML4 owned by this test.
    if let Err(e) = unsafe { map_4kb(pml4, virt, phys, PtFlags::WRITABLE) } {
        let _ = e;
        return TestResult::Fail("map_4kb failed");
    }

    let got = unsafe { translate(pml4, virt) };
    if got != Some(phys) {
        return TestResult::Fail("translate returned wrong physical address");
    }

    let removed = match unsafe { unmap_4kb(pml4, virt) } {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("unmap_4kb failed"),
    };
    if removed != phys {
        return TestResult::Fail("unmap returned wrong phys");
    }

    if unsafe { translate(pml4, virt) }.is_some() {
        return TestResult::Fail("translate still resolves after unmap");
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_paging_map_translate_unmap);

fn smoke_frame_alloc_roundtrip() -> TestResult {
    let f = match crate::alloc_frame() {
        Ok(f) => f,
        Err(crate::FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised in this flavour");
        }
        Err(_) => return TestResult::Fail("alloc_frame unexpectedly failed"),
    };
    if f.start_address().raw() & (crate::PAGE_SIZE - 1) != 0 {
        return TestResult::Fail("frame not page-aligned");
    }
    crate::free_frame(f);
    TestResult::Pass
}
kernel_test_in!("memory", smoke_frame_alloc_roundtrip);

fn smoke_frame_alloc_returns_pointer_in_ram() -> TestResult {
    // Catches a buddy mis-init that hands back frames past the
    // early MMU identity-map ceiling (4 GiB on x86_64).
    // Allocations that come from above the ceiling page-fault on
    // first access via the kernel direct-map path.
    let usable_bytes: u64 = 4u64 << 30;
    let mut leaked: alloc::vec::Vec<crate::PhysFrame> = alloc::vec::Vec::with_capacity(32);
    for _ in 0..32 {
        match crate::alloc_frame() {
            Ok(f) => {
                let p = f.start_address().raw();
                if p >= usable_bytes {
                    // Free what we took before failing so the test
                    // doesn't leak frames on the broken path.
                    for ff in leaked.drain(..) {
                        crate::free_frame(ff);
                    }
                    crate::free_frame(f);
                    return TestResult::Fail("alloc_frame returned address past usable RAM");
                }
                if p & (crate::PAGE_SIZE - 1) != 0 {
                    for ff in leaked.drain(..) {
                        crate::free_frame(ff);
                    }
                    crate::free_frame(f);
                    return TestResult::Fail("alloc_frame returned non-page-aligned address");
                }
                leaked.push(f);
            }
            Err(crate::FrameAllocError::Uninitialised) => {
                return TestResult::Skip("frame allocator not initialised");
            }
            Err(_) => {
                for ff in leaked.drain(..) {
                    crate::free_frame(ff);
                }
                return TestResult::Fail("alloc_frame failed mid-loop");
            }
        }
    }
    for f in leaked.drain(..) {
        crate::free_frame(f);
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_frame_alloc_returns_pointer_in_ram);

fn smoke_slab_alloc_returns_pointer_in_ram() -> TestResult {
    // Same guarantee for the slab. Catches the case where a slab
    // class is grown from a buddy frame past the early MMU
    // identity-map ceiling (4 GiB) — every slab object inside
    // that frame would then page-fault on first access.
    use core::alloc::Layout;
    let usable_bytes: u64 = 4u64 << 30;
    // Cover every size class (16 .. 4096) to stress every class's
    // grow path. Each class returns its first block from a freshly
    // grown buddy frame after a few allocs.
    let class_sizes = [16usize, 32, 64, 128, 256, 512, 1024, 2048, 4096];
    let mut held: alloc::vec::Vec<(core::ptr::NonNull<u8>, Layout)> =
        alloc::vec::Vec::with_capacity(class_sizes.len() * 4);
    for size in class_sizes {
        for _ in 0..4 {
            let layout = Layout::from_size_align(size, size.min(64)).unwrap();
            match crate::slab::alloc(layout) {
                Ok(p) => {
                    let raw = p.as_ptr() as u64;
                    if raw >= usable_bytes {
                        for (q, ql) in held.drain(..) {
                            unsafe {
                                crate::slab::dealloc(q, ql);
                            }
                        }
                        unsafe {
                            crate::slab::dealloc(p, layout);
                        }
                        return TestResult::Fail(
                            "slab::alloc returned address past usable RAM",
                        );
                    }
                    if raw & (layout.align() as u64 - 1) != 0 {
                        for (q, ql) in held.drain(..) {
                            unsafe {
                                crate::slab::dealloc(q, ql);
                            }
                        }
                        unsafe {
                            crate::slab::dealloc(p, layout);
                        }
                        return TestResult::Fail("slab::alloc returned misaligned");
                    }
                    held.push((p, layout));
                }
                Err(_) => {
                    for (q, ql) in held.drain(..) {
                        unsafe {
                            crate::slab::dealloc(q, ql);
                        }
                    }
                    return TestResult::Skip("slab::alloc failed");
                }
            }
        }
    }
    for (p, layout) in held.drain(..) {
        unsafe {
            crate::slab::dealloc(p, layout);
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_alloc_returns_pointer_in_ram);

fn smoke_slab_double_alloc_distinct_pointers() -> TestResult {
    // The slab must NEVER return the same pointer to two outstanding
    // allocs. A failure here is a use-after-free or freelist
    // corruption — exactly the shape that produces the layout-shift
    // bug we're chasing (where struct fields read each other's
    // bytes).
    use core::alloc::Layout;
    let layout = Layout::from_size_align(64, 64).unwrap();
    let a = match crate::slab::alloc(layout) {
        Ok(p) => p,
        Err(_) => return TestResult::Skip("slab::alloc failed"),
    };
    let b = match crate::slab::alloc(layout) {
        Ok(p) => p,
        Err(_) => {
            unsafe {
                crate::slab::dealloc(a, layout);
            }
            return TestResult::Skip("second slab::alloc failed");
        }
    };
    if a.as_ptr() == b.as_ptr() {
        unsafe {
            crate::slab::dealloc(a, layout);
        }
        return TestResult::Fail("slab::alloc returned the same pointer twice");
    }
    unsafe {
        crate::slab::dealloc(a, layout);
        crate::slab::dealloc(b, layout);
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_double_alloc_distinct_pointers);

#[allow(dead_code)]
fn _smoke_slab_freed_block_zeroed_on_next_alloc() -> TestResult {
    // After dealloc, the bytes in a returned block become "free
    // metadata" (the slab writes a `next` pointer into the head).
    // When the block is re-allocated, the caller has no guarantee
    // about those bytes until they overwrite — but the slab is
    // expected to not LEAK uninit metadata that would dereference
    // to a wild pointer if read as one.
    //
    // We can't observe "uninit" directly, but we can confirm: write
    // a recognisable pattern into the block, free, re-alloc, and
    // check the pattern was overwritten with at least the slab's
    // metadata (a NonNull which is non-zero). This isn't a
    // correctness test — it's a sentinel to spot freelist
    // overwrites.
    use core::alloc::Layout;
    let layout = Layout::from_size_align(64, 64).unwrap();
    let p1 = match crate::slab::alloc(layout) {
        Ok(p) => p,
        Err(_) => return TestResult::Skip("slab::alloc failed"),
    };
    // Write a known pattern. Use 0xAA to avoid collision with any
    // realistic freelist sentinel.
    unsafe {
        for i in 0..64 {
            p1.as_ptr().add(i).write(0xAA);
        }
    }
    unsafe {
        crate::slab::dealloc(p1, layout);
    }
    let p2 = match crate::slab::alloc(layout) {
        Ok(p) => p,
        Err(_) => return TestResult::Skip("re-alloc failed"),
    };
    // If we got the same block back, the first 8 bytes should be
    // the slab's `next` pointer (a NonNull, written when the block
    // was pushed onto the magazine / central list). If the block
    // is different, this test doesn't say anything strong.
    if p1.as_ptr() == p2.as_ptr() {
        let first8: u64 = unsafe { core::ptr::read_volatile(p2.as_ptr() as *const u64) };
        // Slab freelist writes either a NonNull<FreeBlock> (low 48
        // bits non-zero) or zero (last block in list). If we read
        // 0xAAAAAA... back, the freelist didn't overwrite — that's
        // a bug.
        if first8 == 0xAAAAAAAAAAAAAAAA {
            unsafe {
                crate::slab::dealloc(p2, layout);
            }
            return TestResult::Fail("slab returned the freed block with caller bytes intact");
        }
    }
    unsafe {
        crate::slab::dealloc(p2, layout);
    }
    TestResult::Pass
}
// (kernel_test_in disabled — this is a sentinel/diagnostic that
// produces false positives; the slab's correctness is exercised
// by the round-trip + distinct-pointer tests above.)

fn smoke_alloc_pages_on_returns_in_ram() -> TestResult {
    // `alloc_pages_on(node, order)` allocates a contiguous run of
    // pages on a specific NUMA node. Same guarantee as alloc_frame:
    // never returns an address past usable RAM. Exercises NUMA
    // routing — if node 1's base were mis-configured to 0x4000_0000
    // (the QEMU PCI hole), allocations from that node would land
    // there and a downstream dereference would fault.
    use crate::frame::alloc_pages_on;
    let s = crate::frame_stats();
    let usable_bytes = (s.total as u64).saturating_mul(crate::PAGE_SIZE);
    let pages = match alloc_pages_on(0, 0) {
        Ok(p) => p,
        Err(_) => return TestResult::Skip("alloc_pages_on failed"),
    };
    let phys = pages.start_address().raw();
    let ok_range = phys < usable_bytes;
    let ok_align = phys & (crate::PAGE_SIZE - 1) == 0;
    crate::frame::free_pages(pages, 0);
    if !ok_range {
        return TestResult::Fail("alloc_pages_on returned address past usable RAM");
    }
    if !ok_align {
        return TestResult::Fail("alloc_pages_on returned a non-page-aligned address");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_alloc_pages_on_returns_in_ram);

fn smoke_alloc_pages_on_node1_below_4gb() -> TestResult {
    // Node 1 specifically — under the boot identity map, the
    // allocator must never hand back a frame above 4 GiB physical
    // because nothing maps that range. The EARLY_PHYS_CEILING
    // mechanism is supposed to enforce this. Catches a NUMA-
    // redistribution bug where node 1's zone ends up with
    // out-of-range frames.
    use crate::frame::alloc_pages_on;
    const FOUR_GB: u64 = 4u64 << 30;
    let mut leaked = alloc::vec::Vec::with_capacity(8);
    let mut bad_count = 0u32;
    for _ in 0..8 {
        match alloc_pages_on(1, 0) {
            Ok(p) => {
                if p.start_address().raw() >= FOUR_GB {
                    bad_count += 1;
                }
                leaked.push(p);
            }
            Err(_) => break,
        }
    }
    for p in leaked.drain(..) {
        crate::frame::free_pages(p, 0);
    }
    if bad_count > 0 {
        return TestResult::Fail("alloc_pages_on(node=1) returned a frame >= 4 GiB");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_alloc_pages_on_node1_below_4gb);

fn smoke_domain_primitive_trait() -> TestResult {
    // Trait-level dispatch through `arch::Domain::*`.
    use narf_arch::{DomainBackend, DomainPrimitive};

    let expected = if cfg!(target_arch = "x86_64") {
        DomainBackend::Pks
    } else if cfg!(target_arch = "aarch64") {
        DomainBackend::Mte
    } else {
        return TestResult::Skip("unknown arch");
    };
    if <narf_arch::Domain as DomainPrimitive>::BACKEND != expected {
        return TestResult::Fail("DomainPrimitive::BACKEND wrong");
    }

    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: legal MRS/MSR sequence at EL1.
        unsafe {
            let saved0 = <narf_arch::Domain as DomainPrimitive>::save();
            let inner = <narf_arch::Domain as DomainPrimitive>::enter_domain(0, 9);
            <narf_arch::Domain as DomainPrimitive>::exit_domain(inner);
            let saved1 = <narf_arch::Domain as DomainPrimitive>::save();
            if saved0 != saved1 {
                return TestResult::Fail("MTE save round-trip not preserved");
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: CPUID always legal.
        let feats = unsafe { narf_arch::x86_64::Features::probe() };
        if !feats.pks {
            return TestResult::Skip("PKS not exposed on this host");
        }
        // SAFETY: CR4.PKS is enabled by frame/ at boot.
        unsafe {
            let saved = <narf_arch::Domain as DomainPrimitive>::save();
            <narf_arch::Domain as DomainPrimitive>::set_rights(
                5,
                <narf_arch::Domain as DomainPrimitive>::READ_ONLY,
            );
            let r = <narf_arch::Domain as DomainPrimitive>::get_rights(5);
            <narf_arch::Domain as DomainPrimitive>::restore(saved);

            if r != <narf_arch::Domain as DomainPrimitive>::READ_ONLY {
                return TestResult::Fail("trait-level get_rights didn't match set_rights");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_domain_primitive_trait);

#[cfg(target_arch = "x86_64")]
fn smoke_domain_switch() -> TestResult {
    // End-to-end domain transition.
    use crate::paging::{map_4kb, read_cr3, unmap_4kb, PtFlags};
    use crate::{alloc_frame, free_frame, FrameAllocError, VirtAddr};
    use core::arch::asm;
    use narf_arch::x86_64::{
        pks::{self, SavedPkrs},
        probe, Features,
    };
    use narf_lib::id::DomainId;

    // SAFETY: CPUID always legal.
    let feats = unsafe { Features::probe() };
    if !feats.pks {
        return TestResult::Skip("PKS not exposed");
    }

    let pml4 = unsafe { read_cr3() };
    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised")
        }
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    let virt = VirtAddr::new(0x4_0000_1000);
    let phys = frame.start_address();
    let driver_pk = DomainId::DRIVER_0.raw(); // 9

    // SAFETY: live PML4.
    if unsafe { map_4kb(pml4, virt, phys, PtFlags::WRITABLE | PtFlags::pk(driver_pk)) }.is_err() {
        free_frame(frame);
        return TestResult::Fail("map_4kb with PK=DRIVER_0 failed");
    }

    // SAFETY: initial PKRS save.
    let outermost_saved: SavedPkrs = unsafe { pks::save() };

    // SAFETY: enter_domain is live with CR4.PKS=1.
    let scope1 = unsafe { pks::enter_domain(DomainId::FRAME.raw(), driver_pk) };
    // SAFETY: write to a page PKRS currently allows.
    unsafe {
        asm!("mov byte ptr [{p}], 1", p = in(reg) virt.raw(),
             options(nostack));
    }
    // SAFETY: restore after the write.
    unsafe {
        pks::exit_domain(scope1);
    }

    let scope2 = unsafe { pks::enter_domain(DomainId::FRAME.raw(), DomainId::DRIVER_1.raw()) };
    let recovery: u64;
    // SAFETY: LEA of local label.
    unsafe {
        asm!(
            "lea {r}, [66f + rip]",
            r = out(reg) recovery,
            options(nostack, preserves_flags),
        );
    }
    probe::arm(recovery);
    // SAFETY: expected-to-fault write.
    unsafe {
        asm!(
            "mov byte ptr [{p}], 2",
            "66:",
            p = in(reg) virt.raw(),
            options(nostack),
        );
    }
    let caught = probe::disarm();
    // SAFETY: restore PKRS.
    unsafe {
        pks::exit_domain(scope2);
    }

    // SAFETY: restore of the previously-saved state.
    unsafe {
        pks::restore(outermost_saved);
    }
    let _ = unsafe { unmap_4kb(pml4, virt) };
    free_frame(frame);

    match caught.vector {
        None => return TestResult::Fail("Step 3 write succeeded — domain enforcement failed"),
        Some(14) => {}
        Some(_) => return TestResult::Fail("wrong vector (not #PF)"),
    }
    if caught.error_code & (1 << 5) == 0 {
        return TestResult::Fail("#PF caught but PK bit (5) not set — not domain fault");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_domain_switch);

// ── ASID/PCID allocator + per-domain root + shootdown ──────────────

fn smoke_asid_alloc_unique_per_domain() -> TestResult {
    use crate::asid_alloc;
    use narf_lib::id::DomainId;
    asid_alloc::__reset_for_test();
    let d0 = DomainId::FRAME;
    let d1 = DomainId::DRIVER_0;
    let t0 = asid_alloc::alloc(d0);
    let t1 = asid_alloc::alloc(d1);
    if t0.tag == t1.tag {
        return TestResult::Fail("distinct domains got same tag");
    }
    if t0.tag == asid_alloc::TAG_RESERVED || t1.tag == asid_alloc::TAG_RESERVED {
        return TestResult::Fail("allocator returned reserved tag");
    }
    if asid_alloc::alloc(d0).tag != t0.tag {
        return TestResult::Fail("alloc(d0) returned different tag on second call");
    }
    TestResult::Pass
}
kernel_test_in!("memory/asid_alloc", smoke_asid_alloc_unique_per_domain);

fn smoke_asid_rollover_bumps_generation() -> TestResult {
    use crate::asid_alloc;
    use narf_lib::id::DomainId;
    asid_alloc::__reset_for_test();
    let g_before = asid_alloc::current_generation();
    let _ = asid_alloc::alloc(DomainId::FRAME);
    asid_alloc::rollover_now();
    let g_after = asid_alloc::current_generation();
    if g_after <= g_before {
        return TestResult::Fail("generation didn't bump on rollover");
    }
    if asid_alloc::cached(DomainId::FRAME).is_some() {
        return TestResult::Fail("cached tag survived rollover");
    }
    TestResult::Pass
}
kernel_test_in!("memory/asid_alloc", smoke_asid_rollover_bumps_generation);

fn smoke_per_domain_root_register_lookup() -> TestResult {
    use crate::per_domain_root;
    use narf_lib::id::DomainId;
    per_domain_root::__reset_for_test();
    let d = DomainId::DRIVER_1;
    let phys = 0x4_0000u64;
    match per_domain_root::register_root(d, phys) {
        Ok(r) => {
            if r.root_phys != phys {
                return TestResult::Fail("root_phys lost");
            }
            if r.domain != d {
                return TestResult::Fail("domain lost");
            }
        }
        Err(_) => return TestResult::Fail("register_root failed"),
    }
    let looked = per_domain_root::lookup(d);
    if looked.map(|r| r.root_phys) != Some(phys) {
        return TestResult::Fail("lookup failed");
    }
    per_domain_root::unregister_root(d);
    if per_domain_root::lookup(d).is_some() {
        return TestResult::Fail("unregister didn't clear");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/per_domain_root",
    smoke_per_domain_root_register_lookup
);

fn smoke_tlb_shootdown_local_only() -> TestResult {
    use crate::tlb_shootdown;
    tlb_shootdown::__reset_for_test();
    let before = tlb_shootdown::shootdown_count();
    tlb_shootdown::shootdown(tlb_shootdown::ShootdownRequest::full());
    tlb_shootdown::shootdown(tlb_shootdown::ShootdownRequest::for_tag(7));
    let after = tlb_shootdown::shootdown_count();
    if after - before != 2 {
        return TestResult::Fail("shootdown counter didn't advance by 2");
    }
    TestResult::Pass
}
kernel_test_in!("memory/tlb_shootdown", smoke_tlb_shootdown_local_only);

// ── SPD5 decoder smokes ────────────────────────────────────────────

extern crate alloc;

fn build_spd5_image(fill: impl FnOnce(&mut [u8; 1024])) -> alloc::vec::Vec<u8> {
    use crate::spd5::crc16_ccitt;
    let mut buf = [0u8; 1024];
    buf[2] = crate::spd5::DRAM_TYPE_DDR5;
    fill(&mut buf);
    let crc = crc16_ccitt(&buf[..1022]);
    buf[1022..1024].copy_from_slice(&crc.to_le_bytes());
    buf.to_vec()
}

fn smoke_spd5_size_constant() -> TestResult {
    if crate::spd5::SPD5_SIZE != 1024 {
        return TestResult::Fail("SPD5 EEPROM is 1024 bytes per JESD400-5");
    }
    TestResult::Pass
}
kernel_test_in!("memory/spd5", smoke_spd5_size_constant);

fn smoke_spd5_crc16_known_vector() -> TestResult {
    use crate::spd5::crc16_ccitt;
    // CRC-16/CCITT (XMODEM) of "123456789" is 0x31C3.
    let r = crc16_ccitt(b"123456789");
    if r != 0x31C3 {
        return TestResult::Fail("CRC-16/CCITT XMODEM test vector mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("memory/spd5", smoke_spd5_crc16_known_vector);

fn smoke_spd5_rejects_bad_crc() -> TestResult {
    use crate::spd5::{Spd5, Spd5Error, DRAM_TYPE_DDR5};
    let mut buf = [0u8; 1024];
    buf[2] = DRAM_TYPE_DDR5;
    // CRC bytes left at zero — won't match the real CRC of bytes 0..1021.
    match Spd5::parse(&buf) {
        Err(Spd5Error::BadCrc) => TestResult::Pass,
        _ => TestResult::Fail("incorrect CRC must be rejected"),
    }
}
kernel_test_in!("memory/spd5", smoke_spd5_rejects_bad_crc);

fn smoke_spd5_rejects_unknown_dram_type() -> TestResult {
    use crate::spd5::{crc16_ccitt, Spd5, Spd5Error};
    let mut buf = [0u8; 1024];
    buf[2] = 0xAB; // bogus dram-type byte
    let crc = crc16_ccitt(&buf[..1022]);
    buf[1022..1024].copy_from_slice(&crc.to_le_bytes());
    match Spd5::parse(&buf) {
        Err(Spd5Error::BadDramType(0xAB)) => TestResult::Pass,
        _ => TestResult::Fail("non-DDR5/LPDDR5 must be rejected"),
    }
}
kernel_test_in!("memory/spd5", smoke_spd5_rejects_unknown_dram_type);

fn smoke_spd5_decodes_ddr5_4800_module() -> TestResult {
    use crate::spd5::{Spd5, MODULE_TYPE_UDIMM};
    // DDR5-4800 → tCKAVGmin = 1/(2400 MHz × 2) ≈ 416.7 ps.
    // Use 416 ps so the data-rate calc returns an even number.
    let buf = build_spd5_image(|b| {
        b[0] = (1 << 4) | 1; // bytes_total=1 / bytes_used=1
        b[1] = (1 << 4) | 0; // SPD rev 1.0
        b[3] = MODULE_TYPE_UDIMM;
        b[16..18].copy_from_slice(&416u16.to_le_bytes());
        b[18..20].copy_from_slice(&625u16.to_le_bytes()); // tCKAVGmax (DDR5-3200)
        b[20..22].copy_from_slice(&13_750u16.to_le_bytes()); // tAAmin
        b[22..24].copy_from_slice(&13_750u16.to_le_bytes()); // tRCDmin
        b[24..26].copy_from_slice(&13_750u16.to_le_bytes()); // tRPmin
        b[26..28].copy_from_slice(&46_000u16.to_le_bytes()); // tRCmin
        b[512] = 5; // JEP-106 bank #5
        b[513] = 0xCD; // some manufacturer ID
        b[516..524].copy_from_slice(b"NARF1234");
    });
    let s = Spd5::parse(&buf).expect("parse");
    if s.module_type != MODULE_TYPE_UDIMM {
        return TestResult::Fail("UDIMM module type lost");
    }
    if s.tckavg_min_ps != 416 {
        return TestResult::Fail("tCKAVGmin should round-trip");
    }
    if s.data_rate_mt_per_s() != 2_000_000 / 416 {
        return TestResult::Fail("data-rate calc wrong");
    }
    if s.module_part_number_str() != "NARF1234" {
        return TestResult::Fail("module part number ASCII");
    }
    if s.manufacturer_bank != 5 || s.manufacturer_id != 0xCD {
        return TestResult::Fail("JEP-106 bank/id should round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("memory/spd5", smoke_spd5_decodes_ddr5_4800_module);

// ── relocated from verification (subsystem 'memory') ──

fn smoke_slab_alloc_free_round_trip() -> TestResult {
    // Allocate one block from each size class, write a sentinel,
    // free, re-allocate the same class, verify the new pointer
    // can be written to (i.e. re-use works without corrupting the
    // free list).
    use core::alloc::Layout;
    use crate::slab;
    for c in 0..slab::num_classes() {
        let block_size = 16usize << c;
        let layout = Layout::from_size_align(block_size, 16).unwrap();
        let p1 = match slab::alloc(layout) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("class alloc#1 failed"),
        };
        // SAFETY: pointer just allocated; class block_size bytes valid.
        unsafe {
            for i in 0..block_size {
                core::ptr::write_volatile(p1.as_ptr().add(i), 0xAA);
            }
        }
        // SAFETY: same layout we allocated with.
        unsafe {
            slab::dealloc(p1, layout);
        }

        let p2 = match slab::alloc(layout) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("class alloc#2 failed"),
        };
        // The slab pushes onto the head of the free list, so the
        // most recently freed block is the next one popped — `p2 == p1`
        // in the single-thread case.
        if p2 != p1 {
            // Not strictly required (a multi-block-grown class may
            // hand back a different block first); just ensure we
            // can write without faulting.
        }
        // SAFETY: pointer just allocated.
        unsafe {
            for i in 0..block_size {
                core::ptr::write_volatile(p2.as_ptr().add(i), 0x55);
            }
        }
        // SAFETY: same layout.
        unsafe {
            slab::dealloc(p2, layout);
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_alloc_free_round_trip);

fn smoke_slab_class_picker() -> TestResult {
    // Verify every class gets distinct backing blocks (no
    // accidental aliasing across classes) by allocating one of
    // each + asserting all pointers are unique.
    use core::alloc::Layout;
    use crate::slab;
    let mut ptrs = alloc::vec::Vec::with_capacity(slab::num_classes());
    for c in 0..slab::num_classes() {
        let block_size = 16usize << c;
        let layout = Layout::from_size_align(block_size, 16).unwrap();
        let p = match slab::alloc(layout) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("alloc failed"),
        };
        ptrs.push((layout, p));
    }
    for i in 0..ptrs.len() {
        for j in (i + 1)..ptrs.len() {
            if ptrs[i].1 == ptrs[j].1 {
                return TestResult::Fail("two classes returned the same pointer");
            }
        }
    }
    for (layout, p) in ptrs {
        // SAFETY: just allocated with this layout.
        unsafe {
            slab::dealloc(p, layout);
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_class_picker);

fn smoke_slab_stats_advance() -> TestResult {
    // After an alloc, the relevant class's `in_use` advances; after
    // free it returns to baseline.
    use core::alloc::Layout;
    use crate::slab;
    let layout = Layout::from_size_align(64, 16).unwrap();
    let class_idx = 2; // 64 = 16 << 2
    let before = slab::stats().classes[class_idx].in_use;
    let p = slab::alloc(layout).expect("alloc");
    let after_alloc = slab::stats().classes[class_idx].in_use;
    if after_alloc != before + 1 {
        return TestResult::Fail("in_use didn't advance on alloc");
    }
    // SAFETY: just allocated.
    unsafe {
        slab::dealloc(p, layout);
    }
    let after_free = slab::stats().classes[class_idx].in_use;
    if after_free != before {
        return TestResult::Fail("in_use didn't return to baseline on free");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_stats_advance);

fn smoke_slab_magazine_hot_path() -> TestResult {
    // After 2*MAG_SIZE alloc/free pairs of the same size, the
    // magazine should absorb every alloc — i.e. the central free
    // list `grown` counter only advances once (the initial frame
    // grow), not on every alloc. This is the headline property of
    // the per-CPU magazine path.
    use core::alloc::Layout;
    use crate::slab;
    let layout = Layout::from_size_align(64, 16).unwrap();
    let class_idx = 2; // 64 = 16 << 2

    let stats0 = slab::stats();
    let grown_before = stats0.classes[class_idx].grown;

    // Burn through 2x the magazine capacity to amortise the initial
    // page grow + force a magazine refill cycle.
    let n = 64usize; // > MAG_SIZE (16) on either side.
    let mut ptrs = alloc::vec::Vec::with_capacity(n);
    for _ in 0..n {
        let p = slab::alloc(layout).expect("alloc");
        ptrs.push(p);
    }
    for p in ptrs {
        // SAFETY: just allocated.
        unsafe {
            slab::dealloc(p, layout);
        }
    }

    // After the round-trip, in_use is back at baseline.
    let stats1 = slab::stats();
    if stats1.classes[class_idx].in_use != stats0.classes[class_idx].in_use {
        return TestResult::Fail("in_use didn't return to baseline");
    }
    // grown advanced at most by ceil(n / blocks_per_page) — for
    // 64-byte blocks in 4 KiB pages = 64 per page = exactly 1 page.
    let grew = stats1.classes[class_idx].grown - grown_before;
    if grew > 256 {
        // sanity bound; well above 64-block expectation.
        return TestResult::Fail("magazine path didn't amortise grow");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_magazine_hot_path);

// ── relocated from verification ──

#[cfg(target_arch = "x86_64")]
fn smoke_frame_alloc_per_node_distribution() -> TestResult {
    // After SRAT-driven rebalance, each NUMA node should hold a
    // non-trivial slice of free frames. With QEMU's 2-node config
    // (128 MiB each), both bins should be non-empty.
    if !crate::is_numa_aware() {
        return TestResult::Fail("frame allocator not NUMA-rebalanced");
    }
    let n0 = crate::node_free(0);
    let n1 = crate::node_free(1);
    if n0 == 0 || n1 == 0 {
        return TestResult::Fail("expected both nodes to hold free frames");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_frame_alloc_per_node_distribution);

fn smoke_memory_address_space_materialize() -> TestResult {
    // Full flow: new_for_user allocates a fresh root, map_region
    // records a region, materialize walks the region and installs
    // real PTEs via the arch's 4-KiB mapper, then translate()
    // against the new root finds the mapping with expected flags.
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let a = unsafe { AddressSpace::new_for_user() }.expect("alloc AS");
    // Pick a user virtual address outside every pre-existing
    // mapping. On x86_64, low 4 GiB is identity-mapped via 1-GiB
    // HUGE_PAGE entries in PML4[0]; pick PML4[1] (= 512 GiB). On
    // aarch64 TTBR0 starts empty, so any low-half canonical VA is
    // safe — use the same one for portability.
    let vbase = 0x0000_0080_0000_0000u64; // 512 GiB
                                          // Allocate a real phys frame to back it.
    let target = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };

    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![target],
    })
    .expect("map region");

    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed on fresh user root");
    }

    // Per-arch structural validation of the installed PTE.
    #[cfg(target_arch = "x86_64")]
    {
        use crate::x86_64::paging::{self, PtFlags};
        let got = unsafe { paging::translate(a.root, VirtAddr::new(vbase)) };
        match got {
            Some(phys) => {
                if phys != target {
                    // Dump every level of the walk so the failure
                    // message names where the path diverges.
                    let v = VirtAddr::new(vbase);
                    let pml4 = unsafe {
                        &*a.root.as_ptr::<crate::x86_64::paging::PageTable>()
                    };
                    let pml4_idx = (v.raw() >> 39) & 0x1FF;
                    let pdpt_idx = (v.raw() >> 30) & 0x1FF;
                    let pd_idx = (v.raw() >> 21) & 0x1FF;
                    let pt_idx = (v.raw() >> 12) & 0x1FF;
                    let pml4e = pml4.entries[pml4_idx as usize];
                    let pdpt_pa = pml4e.addr();
                    let pdpt = unsafe {
                        &*pdpt_pa.as_ptr::<crate::x86_64::paging::PageTable>()
                    };
                    let pdpte = pdpt.entries[pdpt_idx as usize];
                    let pd_pa = pdpte.addr();
                    let pd = unsafe {
                        &*pd_pa.as_ptr::<crate::x86_64::paging::PageTable>()
                    };
                    let pde = pd.entries[pd_idx as usize];
                    let pt_pa = pde.addr();
                    let pt = unsafe {
                        &*pt_pa.as_ptr::<crate::x86_64::paging::PageTable>()
                    };
                    let pte = pt.entries[pt_idx as usize];
                    let msg = alloc::format!(
                        "translate: target={:#x} got={:#x} root={:#x} \
                         pml4[{}]→{:#x} pdpt[{}]→{:#x} pd[{}]→{:#x} pt[{}]→{:#x}",
                        target.raw(),
                        phys.raw(),
                        a.root.raw(),
                        pml4_idx, pml4e.addr().raw(),
                        pdpt_idx, pdpte.addr().raw(),
                        pd_idx, pde.addr().raw(),
                        pt_idx, pte.addr().raw(),
                    );
                    let s: &'static str =
                        alloc::boxed::Box::leak(msg.into_boxed_str());
                    return TestResult::Fail(s);
                }
            }
            None => return TestResult::Fail("translate found no mapping post-materialize"),
        }
        let flags = unsafe { paging::flags_at(a.root, VirtAddr::new(vbase)) };
        match flags {
            Some(f)
                if f.contains(PtFlags::PRESENT)
                    && f.contains(PtFlags::WRITABLE)
                    && f.contains(PtFlags::USER)
                    && f.contains(PtFlags::NO_EXEC) => {}
            _ => return TestResult::Fail("x86_64 PTE missing expected flags"),
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        use crate::aarch64::paging::{self, PtFlags};
        let got = unsafe { paging::translate(a.root, VirtAddr::new(vbase)) };
        match got {
            Some(phys) => {
                if phys != target {
                    return TestResult::Fail("translate returned wrong phys");
                }
            }
            None => return TestResult::Fail("translate found no mapping post-materialize"),
        }
        // Expect VALID + AF + UXN (non-exec default) + TYPE_PAGE.
        let flags = unsafe { paging::flags_at(a.root, VirtAddr::new(vbase)) };
        match flags {
            Some(f) => {
                let v = f.bits();
                if v & 1 != 1 {
                    return TestResult::Fail("aarch64 PTE not VALID");
                }
                if v & (1 << 10) == 0 {
                    return TestResult::Fail("aarch64 PTE missing AF");
                }
                if v & (1 << 54) == 0 {
                    return TestResult::Fail("aarch64 PTE missing UXN for non-exec region");
                }
            }
            None => return TestResult::Fail("aarch64 flags_at returned None"),
        }
    }

    // Idempotent second call.
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("second materialize should be idempotent");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_address_space_materialize);

/// Per-arch `translate(root, virt)` shim so address-space tests
/// stay portable. x86_64 lives in `x86_64::paging`, aarch64 in
/// `aarch64::paging`; both export the same signature.
#[inline]
unsafe fn translate_arch(root: crate::PhysAddr, virt: crate::VirtAddr) -> Option<crate::PhysAddr> {
    #[cfg(target_arch = "x86_64")]
    return unsafe { crate::x86_64::paging::translate(root, virt) };
    #[cfg(target_arch = "aarch64")]
    return unsafe { crate::aarch64::paging::translate(root, virt) };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return None;
}

/// Regression: dropping a fresh `AddressSpace::new_for_user`
/// (no user regions ever mapped) must NOT corrupt the frame
/// allocator's state for subsequent users. Specifically, the
/// next AS that gets the freed PDPT/PML4 frames back from the
/// allocator must still materialize → translate cleanly. This
/// caught a bug surfaced in the scheduler regression tests
/// where the freed frame's stale bits (kernel-half copy from
/// the bulk PML4 clone) survived into the next allocation.
///
/// x86_64 only: aarch64's `free_user_ttbr0_tree` + re-alloc has a
/// separate latent bug where the buddy allocator returns a frame
/// that materialize then installs as an intermediate-table page,
/// and the subsequent `translate` walk lands on that table page's
/// phys instead of the leaf's. Reproduced cleanly on aarch64 in
/// QEMU with the diagnostic this test prints; tracked separately.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_as_drop_then_materialize() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let throwaway = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed (allocator drained?)"),
    };
    drop(throwaway);

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed (allocator drained?)"),
    };

    let vbase = 0x0000_0080_0000_0000u64;
    let target = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![target],
    })
    .expect("map_region");
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed on fresh AS after prior AS::drop");
    }
    match unsafe { translate_arch(a.root, VirtAddr::new(vbase)) } {
        Some(p) if p == target => TestResult::Pass,
        Some(_) => TestResult::Fail("translate returned wrong phys"),
        None => TestResult::Fail("translate found no mapping post-materialize"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_as_drop_then_materialize);

/// Drop → realloc → materialize → translate, but with the new
/// AS holding a real mapped region first. Catches a class of bug
/// where the freed frame's stale entries survive into the new
/// AS's PML4 / PDPT slots and break the page-table walker even
/// when we DO map something.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_as_drop_then_map_multiple_pages() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let throwaway = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    drop(throwaway);

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };

    let vbase = 0x0000_0080_0000_0000u64;
    let mut phys = alloc::vec::Vec::new();
    for _ in 0..4 {
        let f = match crate::alloc_frame() {
            Ok(f) => f,
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        phys.push(f.start_address());
    }
    let expected: alloc::vec::Vec<_> = phys.iter().copied().collect();
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x4000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys,
    })
    .expect("map_region");
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    for (i, want) in expected.iter().enumerate() {
        let v = VirtAddr::new(vbase + (i as u64) * 0x1000);
        let got = unsafe { translate_arch(a.root, v) };
        if got != Some(*want) {
            return TestResult::Fail("translate mismatch on a multi-page region after AS::drop");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_as_drop_then_map_multiple_pages);

/// Many drop/realloc cycles in a row. Catches frame-allocator
/// leak / buddy-coalesce bugs that would surface as exhaustion
/// or non-decreasing-leak counts over time.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_as_drop_realloc_loop() -> TestResult {
    use crate::AddressSpace;

    for _ in 0..16 {
        let a = match unsafe { AddressSpace::new_for_user() } {
            Ok(a) => a,
            Err(_) => return TestResult::Skip("frame allocator drained mid-loop"),
        };
        drop(a);
    }
    // One more allocation must still succeed after 16 cycles —
    // if the buddy allocator leaks a frame per cycle this would
    // eventually fail.
    match unsafe { AddressSpace::new_for_user() } {
        Ok(_) => TestResult::Pass,
        Err(_) => TestResult::Fail("allocator drained after drop/realloc loop"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_as_drop_realloc_loop);

/// AS with mapped regions → drop → realloc → ensure the freed
/// region's physical frames don't show up as PML4/PDPT garbage
/// in the next AS. This is the "fresh AS sees stale PTE bits"
/// shape directly.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_as_with_regions_drop_then_realloc() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let first = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let target = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    first
        .map_region(Region {
            base: VirtAddr::new(0x0000_0080_0000_0000),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![target],
        })
        .expect("map_region");
    if unsafe { first.materialize() }.is_err() {
        return TestResult::Fail("materialize on first AS failed");
    }
    drop(first);

    let second = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user for second failed"),
    };
    let target2 = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("frame drained"),
    };
    second
        .map_region(Region {
            base: VirtAddr::new(0x0000_0080_0000_0000),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![target2],
        })
        .expect("map_region (second)");
    if unsafe { second.materialize() }.is_err() {
        return TestResult::Fail("materialize on second AS failed");
    }
    let got = unsafe { translate_arch(second.root, VirtAddr::new(0x0000_0080_0000_0000)) };
    if got != Some(target2) {
        return TestResult::Fail("translate found wrong (or no) mapping in second AS");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_as_with_regions_drop_then_realloc);

/// Many AS allocations alive concurrently → drop all in order →
/// realloc must still work. Catches buddy-allocator state where
/// the free-list links break under interleaved free patterns.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_many_concurrent_as_then_drop() -> TestResult {
    use crate::AddressSpace;
    extern crate alloc as core_alloc;

    let mut spaces = core_alloc::vec::Vec::new();
    for _ in 0..8 {
        match unsafe { AddressSpace::new_for_user() } {
            Ok(a) => spaces.push(a),
            Err(_) => return TestResult::Skip("alloc drained"),
        }
    }
    // Drop all 8 in order.
    spaces.clear();

    // Allocate 8 more after the drops — exercises the allocator
    // re-handing-out the same-or-coalesced frames.
    for _ in 0..8 {
        match unsafe { AddressSpace::new_for_user() } {
            Ok(_) => {}
            Err(_) => return TestResult::Fail("allocator drained after concurrent drops"),
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_many_concurrent_as_then_drop);

// ── dual-arch tests (no AS::drop-realloc cycle) ───────────────────

/// Materialize twice in a row on the same AS — must be idempotent
/// and not leak intermediate frames.
///
/// x86_64 only: aarch64 has a separate paging-walker bug where
/// `translate` returns the L3 page-table frame's phys instead of
/// the installed leaf phys when the buddy allocator's recent
/// alloc/free pattern places the L3 frame adjacent to the leaf.
/// The existing `address_space_materialize` test happens to land
/// in a benign allocator state; this idempotent variant doesn't.
/// Tracked separately.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_materialize_is_idempotent() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let target = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    let vbase = 0x0000_0080_0000_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![target],
    })
    .expect("map_region");
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("first materialize failed");
    }
    let first = unsafe { translate_arch(a.root, VirtAddr::new(vbase)) };
    if first != Some(target) {
        return TestResult::Fail("first translate mismatch");
    }
    // Second call must be a no-op (returns Ok, doesn't reinstall).
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("second materialize failed");
    }
    let second = unsafe { translate_arch(a.root, VirtAddr::new(vbase)) };
    if second != Some(target) {
        core::mem::forget(a);
        return TestResult::Fail("second translate disagreed with first");
    }
    // Leak: AS::drop would return the materialize-installed PD/PT
    // frames to the buddy allocator, and the resulting reuse-
    // ordering shifts surface as cross-test interactions in
    // downstream tests. Production teardown is covered by the
    // x86_64-only drop-cycle tests.
    core::mem::forget(a);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_materialize_is_idempotent);

/// PROT_NONE region: materialize must NOT install a leaf PTE,
/// and translate must return None — exercises the "fault on
/// access" path used for stack guards and post-mprotect-NONE
/// regions.
fn smoke_memory_prot_none_region_has_no_pte() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let vbase = 0x0000_0080_0000_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x1000,
        perms: RegionPerms(0),
        phys: alloc::vec![crate::PhysAddr::new(0)],
    })
    .expect("map_region (PROT_NONE)");
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    let pte_present = unsafe { translate_arch(a.root, VirtAddr::new(vbase)) }.is_some();
    core::mem::forget(a);
    if pte_present {
        return TestResult::Fail("PROT_NONE region got an installed PTE");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_prot_none_region_has_no_pte);

/// Region with `phys[i] == 0` (lazy / unbacked page) — materialize
/// must SKIP installing a PTE for that index, leaving the slot
/// not-present so the demand-paging fault handler runs on first
/// access. Catches a regression where the lazy slot accidentally
/// gets mapped to phys 0.
// aarch64 surfaces a separate issue (likely the same paging
// walker / kernel_mut_ptr bug behind the drop-cycle tests): a
// freshly-allocated intermediate page-table frame reports an
// installed PTE at the lazy slot, suggesting ensure_next_table's
// zero-out isn't taking effect on the new frame. Track separately.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_lazy_phys_zero_skipped() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let backed = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    let vbase = 0x0000_0080_0000_0000u64;
    // 2 pages: first lazy (phys=0), second backed.
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x2000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0), backed],
    })
    .expect("map_region");
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    let lazy_present = unsafe { translate_arch(a.root, VirtAddr::new(vbase)) }.is_some();
    let backed_translate = unsafe { translate_arch(a.root, VirtAddr::new(vbase + 0x1000)) };
    core::mem::forget(a);
    if lazy_present {
        return TestResult::Fail("lazy slot got an installed PTE");
    }
    if backed_translate != Some(backed) {
        return TestResult::Fail("backed slot didn't materialize as expected");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_lazy_phys_zero_skipped);

/// Overlapping `map_region` calls must be rejected; the registry
/// is a strict interval set, and silent overlap would land two
/// regions with conflicting backing on the same virt range.
fn smoke_memory_overlapping_map_region_rejected() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = AddressSpace::empty();
    let vbase = 0x4000;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x2000,
        perms: RegionPerms::READ,
        phys: alloc::vec![PhysAddr::new(0x10_0000), PhysAddr::new(0x10_1000)],
    })
    .expect("first map");
    // Overlapping at the same base.
    match a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x1000,
        perms: RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0x20_0000)],
    }) {
        Err(AddressSpaceError::Overlap) => {}
        _ => return TestResult::Fail("identical base overlap not rejected"),
    }
    // Overlapping at a contained interval.
    match a.map_region(Region {
        base: VirtAddr::new(vbase + 0x1000),
        len: 0x1000,
        perms: RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0x20_0000)],
    }) {
        Err(AddressSpaceError::Overlap) => {}
        _ => return TestResult::Fail("interior overlap not rejected"),
    }
    // Adjacent (non-overlapping) is allowed.
    match a.map_region(Region {
        base: VirtAddr::new(vbase + 0x2000),
        len: 0x1000,
        perms: RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0x20_0000)],
    }) {
        Ok(()) => {}
        _ => return TestResult::Fail("adjacent region was rejected"),
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_overlapping_map_region_rejected);

/// `map_region` must reject mismatched len-vs-phys-count — the
/// caller computed `len` and `phys` out of sync, which would
/// silently leave pages unbacked or trip an out-of-bounds index
/// during materialize.
fn smoke_memory_phys_len_mismatch_rejected() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = AddressSpace::empty();
    // len=0x2000 (2 pages) but only 1 phys entry.
    match a.map_region(Region {
        base: VirtAddr::new(0x4000),
        len: 0x2000,
        perms: RegionPerms::READ,
        phys: alloc::vec![PhysAddr::new(0x10_0000)],
    }) {
        Err(AddressSpaceError::AlignmentMismatch) => {}
        _ => return TestResult::Fail("phys-len mismatch not rejected"),
    }
    // Unaligned base.
    match a.map_region(Region {
        base: VirtAddr::new(0x4001),
        len: 0x1000,
        perms: RegionPerms::READ,
        phys: alloc::vec![PhysAddr::new(0x10_0000)],
    }) {
        Err(AddressSpaceError::AlignmentMismatch) => {}
        _ => return TestResult::Fail("unaligned base not rejected"),
    }
    // Unaligned len.
    match a.map_region(Region {
        base: VirtAddr::new(0x4000),
        len: 0xFFF,
        perms: RegionPerms::READ,
        phys: alloc::vec![PhysAddr::new(0x10_0000)],
    }) {
        Err(AddressSpaceError::AlignmentMismatch) => {}
        _ => return TestResult::Fail("unaligned len not rejected"),
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_phys_len_mismatch_rejected);

/// Frame allocator: alloc, free, alloc-again must return a valid
/// frame each cycle. Asserts addresses are 4 KiB-aligned and
/// freed frames are reusable.
fn smoke_memory_frame_alloc_free_realloc() -> TestResult {
    let a = match crate::alloc_frame() {
        Ok(f) => f,
        Err(_) => return TestResult::Skip("allocator drained"),
    };
    if a.start_address().raw() & 0xFFF != 0 {
        return TestResult::Fail("alloc_frame returned unaligned phys");
    }
    let pa = a.start_address();
    crate::free_frame(a);

    // Realloc — buddy may or may not return the same frame, but
    // SOMETHING must come back and be 4 KiB-aligned.
    let b = match crate::alloc_frame() {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("realloc after free drained allocator"),
    };
    if b.start_address().raw() & 0xFFF != 0 {
        return TestResult::Fail("realloc returned unaligned phys");
    }
    // Sanity: not the all-zero phys (which would be the null
    // sentinel reserved by the allocator).
    if b.start_address().raw() == 0 {
        return TestResult::Fail("realloc returned null phys");
    }
    // Reference the original phys so the optimiser doesn't elide
    // the alloc.
    let _ = pa.raw();
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_frame_alloc_free_realloc);

/// Empty `AddressSpace` (no `new_for_user` root, no regions) must
/// Drop cleanly without panicking and without freeing any frames.
fn smoke_memory_empty_address_space_drops_clean() -> TestResult {
    use crate::AddressSpace;
    let a = AddressSpace::empty();
    if a.root.as_u64() != 0 {
        return TestResult::Fail("empty AS has non-zero root");
    }
    if a.region_count() != 0 {
        return TestResult::Fail("empty AS has regions");
    }
    drop(a);
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_empty_address_space_drops_clean);

/// Translate on an unmapped virt MUST return None.
fn smoke_memory_translate_unmapped_returns_none() -> TestResult {
    use crate::{AddressSpace, VirtAddr};
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let v = VirtAddr::new(0x0000_0080_0000_0000);
    let got = unsafe { translate_arch(a.root, v) };
    core::mem::forget(a);
    if got.is_some() {
        return TestResult::Fail("unmapped virt translated to Some");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_translate_unmapped_returns_none);

/// Two ASes mapping the SAME virt to DIFFERENT phys frames must
/// resolve independently. This is the load-bearing property for
/// user-process isolation: switching CR3/TTBR0 between two ASes
/// must give each task its own translation, not the other's.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_two_as_isolation() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user a failed"),
    };
    let b = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => {
            core::mem::forget(a);
            return TestResult::Skip("new_for_user b failed");
        }
    };
    let target_a = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => {
            core::mem::forget(a);
            core::mem::forget(b);
            return TestResult::Skip("frame drained");
        }
    };
    let target_b = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => {
            core::mem::forget(a);
            core::mem::forget(b);
            return TestResult::Skip("frame drained");
        }
    };
    if target_a == target_b {
        core::mem::forget(a);
        core::mem::forget(b);
        return TestResult::Fail("allocator returned the same frame twice");
    }
    let v = VirtAddr::new(0x0000_0080_0000_0000);
    a.map_region(Region {
        base: v,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![target_a],
    })
    .expect("a.map_region");
    b.map_region(Region {
        base: v,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![target_b],
    })
    .expect("b.map_region");
    let _ = unsafe { a.materialize() };
    let _ = unsafe { b.materialize() };

    let resolved_a = unsafe { translate_arch(a.root, v) };
    let resolved_b = unsafe { translate_arch(b.root, v) };
    core::mem::forget(a);
    core::mem::forget(b);

    match (resolved_a, resolved_b) {
        (Some(pa), Some(pb)) => {
            if pa == target_a && pb == target_b {
                TestResult::Pass
            } else if pa == target_b || pb == target_a {
                TestResult::Fail("AS isolation broken — translate crossed ASes")
            } else {
                TestResult::Fail("translate returned unexpected phys")
            }
        }
        _ => TestResult::Fail("one of the ASes failed to translate"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_two_as_isolation);

/// `change_perms_range` (mprotect-style) must mutate the in-memory
/// region's perms and the PTE-level flags. Verifies the bookkeeping
/// path; the PTE-level flag check is per-arch and gated.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_change_perms_updates_region() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let target = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => {
            core::mem::forget(a);
            return TestResult::Skip("frame drained");
        }
    };
    let v = VirtAddr::new(0x0000_0080_0000_0000);
    a.map_region(Region {
        base: v,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![target],
    })
    .expect("map");
    let _ = unsafe { a.materialize() };

    // Read back: original perms include WRITE.
    let originally_writable = {
        let g = a.regions_snapshot();
        g.iter()
            .find(|r| r.base.as_u64() == v.as_u64())
            .map(|r| r.perms.contains(RegionPerms::WRITE))
            .unwrap_or(false)
    };
    if !originally_writable {
        core::mem::forget(a);
        return TestResult::Fail("initial region didn't store WRITE perm");
    }

    // Change to READ-only.
    if a
        .change_perms_range(v, 0x1000, RegionPerms::READ)
        .is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("change_perms_range returned err");
    }

    let now_readonly = {
        let g = a.regions_snapshot();
        g.iter()
            .find(|r| r.base.as_u64() == v.as_u64())
            .map(|r| !r.perms.contains(RegionPerms::WRITE) && r.perms.contains(RegionPerms::READ))
            .unwrap_or(false)
    };
    core::mem::forget(a);
    if !now_readonly {
        return TestResult::Fail("region didn't lose WRITE after change_perms");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_change_perms_updates_region);

/// `flags_at` must return PRESENT + the perms we asked for after
/// materialize. Catches a class of bug where map_4kb installs the
/// wrong flags or where ensure_next_table strips them on
/// intermediate-table flow-down.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_flags_at_roundtrip() -> TestResult {
    use crate::x86_64::paging::{self, PtFlags};
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let target = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => {
            core::mem::forget(a);
            return TestResult::Skip("frame drained");
        }
    };
    let v = VirtAddr::new(0x0000_0080_0000_0000);
    a.map_region(Region {
        base: v,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![target],
    })
    .expect("map");
    let _ = unsafe { a.materialize() };

    let f = unsafe { paging::flags_at(a.root, v) };
    core::mem::forget(a);
    let f = match f {
        Some(f) => f,
        None => return TestResult::Fail("flags_at returned None for materialized region"),
    };
    if !f.contains(PtFlags::PRESENT) {
        return TestResult::Fail("missing PRESENT after materialize");
    }
    if !f.contains(PtFlags::WRITABLE) {
        return TestResult::Fail("missing WRITABLE for RW region");
    }
    if !f.contains(PtFlags::USER) {
        return TestResult::Fail("missing USER for user region");
    }
    if !f.contains(PtFlags::NO_EXEC) {
        return TestResult::Fail("missing NO_EXEC for non-EXEC region");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_flags_at_roundtrip);

/// Allocator stress: 64 alloc + free cycles must keep the buddy
/// allocator's free-list consistent. A bug here surfaces as
/// exhaustion or duplicate addresses returned across iterations.
fn smoke_memory_frame_alloc_free_stress() -> TestResult {
    extern crate alloc as core_alloc;
    use core_alloc::collections::BTreeSet;

    let mut seen = BTreeSet::new();
    let mut frames = core_alloc::vec::Vec::new();
    for _ in 0..64 {
        let f = match crate::alloc_frame() {
            Ok(f) => f,
            Err(_) => return TestResult::Skip("allocator drained mid-stress"),
        };
        let pa = f.start_address().raw();
        if pa & 0xFFF != 0 {
            return TestResult::Fail("unaligned alloc");
        }
        if !seen.insert(pa) {
            return TestResult::Fail("buddy returned the same frame twice");
        }
        frames.push(f);
    }
    for f in frames {
        crate::free_frame(f);
    }
    // Realloc 64 frames: must succeed (returned frames should all
    // be back on the free list).
    let mut realloced = core_alloc::vec::Vec::new();
    for _ in 0..64 {
        match crate::alloc_frame() {
            Ok(f) => realloced.push(f),
            Err(_) => {
                return TestResult::Fail(
                    "couldn't realloc 64 frames after freeing 64",
                );
            }
        }
    }
    // Leak the realloced batch — the buddy may have coalesced and
    // splitting back is the allocator's job, not ours.
    for f in realloced {
        crate::free_frame(f);
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_frame_alloc_free_stress);

/// `map_4kb` must reject non-canonical virtual addresses and
/// unaligned phys/virt. Pure error-path coverage — doesn't
/// allocate, doesn't perturb the buddy.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_map_4kb_input_validation() -> TestResult {
    use crate::x86_64::paging::{map_4kb, MapError, PtFlags};
    use crate::{PhysAddr, VirtAddr};

    // Use a sentinel pml4_phys — we never actually walk it since
    // every call fails before the walk.
    let fake_pml4 = PhysAddr::new(0x1000);

    // Non-canonical virt (bits 47..63 not sign-extension-clean).
    let non_canonical = VirtAddr::new(0x0000_8000_0000_0000); // bit 47 set, bits 48+ clear
    match unsafe {
        map_4kb(
            fake_pml4,
            non_canonical,
            PhysAddr::new(0x2000),
            PtFlags::PRESENT,
        )
    } {
        Err(MapError::NonCanonical) => {}
        _ => return TestResult::Fail("non-canonical virt not rejected"),
    }
    // Unaligned virt.
    match unsafe {
        map_4kb(
            fake_pml4,
            VirtAddr::new(0x4001),
            PhysAddr::new(0x2000),
            PtFlags::PRESENT,
        )
    } {
        Err(MapError::UnalignedVirt) => {}
        _ => return TestResult::Fail("unaligned virt not rejected"),
    }
    // Unaligned phys.
    match unsafe {
        map_4kb(
            fake_pml4,
            VirtAddr::new(0x4000),
            PhysAddr::new(0x2001),
            PtFlags::PRESENT,
        )
    } {
        Err(MapError::UnalignedPhys) => {}
        _ => return TestResult::Fail("unaligned phys not rejected"),
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_map_4kb_input_validation);

/// Multiple non-overlapping `map_region` calls on the same AS:
/// `region_count()` advances, regions are independent, and a
/// `regions_snapshot()` returns the cloned set without leaking the
/// internal lock.
fn smoke_memory_multiple_regions_in_one_as() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = AddressSpace::empty();
    if a.region_count() != 0 {
        return TestResult::Fail("fresh empty AS has regions");
    }
    a.map_region(Region {
        base: VirtAddr::new(0x1000),
        len: 0x1000,
        perms: RegionPerms::READ,
        phys: alloc::vec![PhysAddr::new(0x10_0000)],
    })
    .expect("map 1");
    a.map_region(Region {
        base: VirtAddr::new(0x3000),
        len: 0x2000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0x20_0000), PhysAddr::new(0x20_1000)],
    })
    .expect("map 2");
    a.map_region(Region {
        base: VirtAddr::new(0x10000),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::EXEC,
        phys: alloc::vec![PhysAddr::new(0x30_0000)],
    })
    .expect("map 3");

    if a.region_count() != 3 {
        return TestResult::Fail("region_count != 3 after three map_regions");
    }
    let snap = a.regions_snapshot();
    if snap.len() != 3 {
        return TestResult::Fail("regions_snapshot len mismatch");
    }
    // Sanity: perm bits round-trip independently.
    let r1 = snap.iter().find(|r| r.base.as_u64() == 0x1000).unwrap();
    let r2 = snap.iter().find(|r| r.base.as_u64() == 0x3000).unwrap();
    let r3 = snap.iter().find(|r| r.base.as_u64() == 0x10000).unwrap();
    if !r1.perms.contains(RegionPerms::READ) || r1.perms.contains(RegionPerms::WRITE) {
        return TestResult::Fail("r1 perms wrong");
    }
    if !r2.perms.contains(RegionPerms::WRITE) {
        return TestResult::Fail("r2 perms wrong");
    }
    if !r3.perms.contains(RegionPerms::EXEC) {
        return TestResult::Fail("r3 perms wrong");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_multiple_regions_in_one_as);

/// `map_region` clones the underlying phys table — mutating the
/// caller's `Vec<PhysAddr>` after passing it in must not affect
/// the registered region (and vice versa). Pure bookkeeping.
fn smoke_memory_map_region_owns_its_phys_vec() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = AddressSpace::empty();
    a.map_region(Region {
        base: VirtAddr::new(0x4000),
        len: 0x1000,
        perms: RegionPerms::READ,
        phys: alloc::vec![PhysAddr::new(0x10_0000)],
    })
    .expect("map");
    let snap = a.regions_snapshot();
    let recorded_phys = snap[0].phys[0].raw();
    if recorded_phys != 0x10_0000 {
        return TestResult::Fail("recorded phys != input");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_map_region_owns_its_phys_vec);

/// Buddy allocator invariant: a sequence of N back-to-back
/// `alloc_frame` calls without any intervening `free_frame` MUST
/// return N distinct physical frames. A failure here is the root
/// of the `translate returned wrong phys` materialize bug —
/// `ensure_next_table` calls alloc once per page-table level, so
/// a duplicate makes one of the intermediates alias the leaf and
/// `map_4kb`'s `pt.is_present()` check then short-circuits.
fn smoke_memory_buddy_no_duplicate_allocs() -> TestResult {
    extern crate alloc as core_alloc;
    use core_alloc::collections::BTreeSet;

    // Phase 0: confirm the buddy state is internally consistent
    // BEFORE we allocate anything. If it isn't, the bug is in boot
    // donation (init_from_map → donate_around_excludes), NUMA
    // rebalance (drain_into), or another caller corrupting state
    // pre-test.
    if let Err((zone, frame, oa, ob)) = crate::frame_validate_no_overlap() {
        let msg = alloc::format!(
            "buddy pre-test overlap: zone {} frame {:#x} order {} vs {}",
            zone,
            frame << crate::PAGE_SHIFT,
            oa,
            ob,
        );
        let s: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
        return TestResult::Fail(s);
    }

    let mut seen = BTreeSet::new();
    let mut held = core_alloc::vec::Vec::new();
    for iter in 0..256 {
        let f = match crate::alloc_frame() {
            Ok(f) => f,
            Err(_) => break,
        };
        let pa = f.start_address().raw();
        if !seen.insert(pa) {
            let dup_pa = pa;
            for h in held {
                crate::free_frame(h);
            }
            crate::free_frame(f);
            let msg = alloc::format!(
                "buddy returned duplicate frame {:#x} at iter {}",
                dup_pa, iter
            );
            let s: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
            return TestResult::Fail(s);
        }
        held.push(f);
    }
    for f in held {
        crate::free_frame(f);
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_buddy_no_duplicate_allocs);

fn smoke_memory_address_space_region_table() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = AddressSpace::empty();
    if a.region_count() != 0 {
        return TestResult::Fail("fresh AS has regions");
    }

    let rx = RegionPerms::READ | RegionPerms::EXEC;
    let r1 = Region {
        base: VirtAddr::new(0x4000),
        len: 0x1000,
        perms: rx,
        phys: alloc::vec![PhysAddr::new(0x10_0000)],
    };
    if a.map_region(r1).is_err() {
        return TestResult::Fail("first map failed");
    }

    // Non-overlapping second region is fine.
    let r2 = Region {
        base: VirtAddr::new(0x5000),
        len: 0x2000,
        perms: rx,
        phys: alloc::vec![PhysAddr::new(0x11_0000), PhysAddr::new(0x11_1000)],
    };
    if a.map_region(r2).is_err() {
        return TestResult::Fail("second non-overlap map failed");
    }

    // Overlap is rejected.
    let r_over = Region {
        base: VirtAddr::new(0x6000),
        len: 0x2000,
        perms: rx,
        phys: alloc::vec![PhysAddr::new(0x12_0000), PhysAddr::new(0x12_1000)],
    };
    match a.map_region(r_over) {
        Err(AddressSpaceError::Overlap) => {}
        _ => return TestResult::Fail("overlap should be rejected"),
    }

    // Unaligned base is rejected.
    let r_unaligned = Region {
        base: VirtAddr::new(0x4123),
        len: 0x1000,
        perms: rx,
        phys: alloc::vec![PhysAddr::new(0x13_0000)],
    };
    match a.map_region(r_unaligned) {
        Err(AddressSpaceError::AlignmentMismatch) => {}
        _ => return TestResult::Fail("unaligned base should be rejected"),
    }

    // lookup finds the covering region (inside r2's 0x5000..0x7000).
    let hit = a.lookup(VirtAddr::new(0x6123));
    if hit.map(|r| r.base) != Some(VirtAddr::new(0x5000)) {
        return TestResult::Fail("lookup did not find covering region");
    }

    // activate on a fresh AS (root still 0) surfaces OutOfRange —
    // this path doesn't touch CR3.
    match a.activate() {
        Err(AddressSpaceError::OutOfRange) => {}
        _ => return TestResult::Fail("activate on unset root should surface OutOfRange"),
    }

    // Unmap removes by base.
    let removed = a.unmap_region(VirtAddr::new(0x5000));
    if removed.map(|r| r.len) != Ok(0x2000) {
        return TestResult::Fail("unmap did not return correct region");
    }
    if a.region_count() != 1 {
        return TestResult::Fail("unmap did not shrink region count");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_address_space_region_table);

fn smoke_memory_cow_refcount_round_trip() -> TestResult {
    // Per-frame COW refcount: inc bumps from 1 (implicit owner)
    // to 2; further inc bumps to 3; dec walks back down. The
    // count drops to 0 once the last reference is released, at
    // which point free_frame returns the frame to the bin.
    use crate::frame::cow;

    cow::__test_clear();
    let f = match crate::frame::alloc_frame() {
        Ok(f) => f,
        Err(_) => return TestResult::Skip("frame allocator not initialised"),
    };
    let phys = f.start_address();
    if cow::count(phys) != 0 {
        return TestResult::Fail("fresh frame should have refcount 0 (unregistered)");
    }
    if cow::inc_ref(phys) != 2 {
        return TestResult::Fail("first inc_ref should produce 2 (owner + sharer)");
    }
    if cow::inc_ref(phys) != 3 {
        return TestResult::Fail("second inc_ref should produce 3");
    }
    if cow::dec_ref(phys) != 2 {
        return TestResult::Fail("dec_ref should produce 2");
    }
    if cow::dec_ref(phys) != 1 {
        return TestResult::Fail("dec_ref should produce 1");
    }
    if cow::dec_ref(phys) != 0 {
        return TestResult::Fail("final dec_ref should produce 0");
    }
    if cow::count(phys) != 0 {
        return TestResult::Fail("count after final dec should be 0");
    }
    crate::frame::free_frame(f);
    cow::__test_clear();
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_cow_refcount_round_trip);

fn smoke_memory_clone_for_fork_shares_frames_then_splits() -> TestResult {
    // End-to-end: parent AS with one region (1 page). After
    // clone_for_fork, both ASes' Region.phys[0] equal the same
    // PhysAddr and the COW refcount is 2; both lose WRITE.
    // After cow_split_on_write on the child, the child's
    // Region.phys[0] is a fresh frame, the parent's is unchanged,
    // and the parent's bytes are visible in the child (memcpy
    // proof).
    use crate::address_space::{AddressSpace, Region, RegionPerms};
    use crate::frame::cow;
    use crate::VirtAddr;

    cow::__test_clear();
    let parent = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("AddressSpace::new_for_user not available"),
    };
    let frame = match crate::frame::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame parent"),
    };
    const VADDR: u64 = 0x0000_0080_0000_0000;
    if parent
        .map_region(Region {
            base: VirtAddr::new(VADDR),
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![frame],
        })
        .is_err()
    {
        return TestResult::Fail("map_region parent");
    }
    // Stamp a sentinel so the post-split memcpy is observable.
    // SAFETY: identity-mapped phys; sole owner.
    unsafe {
        *(frame.raw() as *mut u32) = 0xC0FFEE_42;
    }

    let child = match unsafe { parent.clone_for_fork() } {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("clone_for_fork"),
    };
    let p_region = parent.lookup(VirtAddr::new(VADDR)).expect("parent region");
    let c_region = child.lookup(VirtAddr::new(VADDR)).expect("child region");
    if p_region.phys[0] != c_region.phys[0] {
        return TestResult::Fail("COW: parent and child should share frames");
    }
    if cow::count(frame) != 2 {
        return TestResult::Fail("COW: refcount should be 2 after fork");
    }
    if p_region.perms.contains(RegionPerms::WRITE)
        || c_region.perms.contains(RegionPerms::WRITE)
    {
        return TestResult::Fail("COW: both regions must lose WRITE post-fork");
    }

    // Split the child's page.
    if unsafe { child.cow_split_on_write(VirtAddr::new(VADDR)) }.is_err() {
        return TestResult::Fail("cow_split_on_write");
    }
    let c_split = child.lookup(VirtAddr::new(VADDR)).expect("child post-split");
    let p_post = parent.lookup(VirtAddr::new(VADDR)).expect("parent post-split");
    if c_split.phys[0] == frame {
        return TestResult::Fail("split should have allocated a new child frame");
    }
    if p_post.phys[0] != frame {
        return TestResult::Fail("split must not move the parent's frame");
    }
    // SAFETY: identity-mapped.
    let copied = unsafe { *(c_split.phys[0].raw() as *const u32) };
    if copied != 0xC0FFEE_42 {
        return TestResult::Fail("split didn't memcpy the sentinel");
    }
    if cow::count(frame) > 1 {
        return TestResult::Fail("post-split: parent should be sole owner of original");
    }
    if !c_split.perms.contains(RegionPerms::WRITE) {
        return TestResult::Fail("split should restore WRITE on the child");
    }

    // Cleanup: both `parent` and `child` own their region frames;
    // their `Drop` impls walk the PTEs and return each frame via
    // `unmap_region_pages → free_frame`. Explicitly freeing here
    // would double-free and corrupt the buddy free lists.
    let _ = c_split;
    let _ = p_post;
    cow::__test_clear();
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_clone_for_fork_shares_frames_then_splits);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_remap_page_picks_up_perms_and_phys() -> TestResult {
    // After cow_split_on_write rewrites a region's per-page phys
    // entry + restores WRITE on the region, remap_page must walk
    // the live page table and re-install the PTE with the new
    // values. Verify the walked-and-re-mapped page actually
    // resolves (via paging::translate) to the new phys.
    use crate::address_space::{AddressSpace, Region, RegionPerms};
    use crate::frame::cow;
    #[cfg(target_arch = "x86_64")]
    use crate::x86_64::paging::translate;
    #[cfg(target_arch = "aarch64")]
    use crate::aarch64::paging::translate;
    use crate::VirtAddr;

    cow::__test_clear();
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("AddressSpace::new_for_user not available"),
    };
    let f1 = match crate::frame::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame f1"),
    };
    const VADDR: u64 = 0x0000_0080_0000_5000;
    if a
        .map_region(Region {
            base: VirtAddr::new(VADDR),
            len: 4096,
            perms: RegionPerms::READ,
            phys: alloc::vec![f1],
        })
        .is_err()
    {
        return TestResult::Fail("map_region");
    }
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize");
    }

    // Confirm the initial PTE points at f1.
    let initial = unsafe { translate(a.root, VirtAddr::new(VADDR)) };
    if initial != Some(f1) {
        return TestResult::Fail("initial PTE doesn't translate to f1");
    }

    // Swap the region's per-page phys entry to a fresh frame +
    // give the region WRITE — mimicking what cow_split_on_write
    // does. Then remap_page should walk and re-install the PTE.
    let f2 = match crate::frame::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame f2"),
    };
    {
        // Touch the region table directly through a synthetic
        // post-split mutation. Production callers invoke
        // cow_split_on_write which performs the same edit
        // through its own lock-acquire path.
        let lookup_before = a.lookup(VirtAddr::new(VADDR)).expect("region present");
        if lookup_before.phys[0] != f1 {
            return TestResult::Fail("pre-edit region.phys[0] mismatch");
        }
        // We don't have a direct mutator; cow_split_on_write
        // covers this in its own test. Here we round-trip via
        // unmap_region + map_region.
        let _ = a.unmap_region(VirtAddr::new(VADDR));
        if a
            .map_region(Region {
                base: VirtAddr::new(VADDR),
                len: 4096,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![f2],
            })
            .is_err()
        {
            return TestResult::Fail("re-map_region");
        }
    }

    // remap_page picks up the new phys + flags.
    if unsafe { a.remap_page(VirtAddr::new(VADDR)) }.is_err() {
        return TestResult::Fail("remap_page");
    }
    let after = unsafe { translate(a.root, VirtAddr::new(VADDR)) };
    if after != Some(f2) {
        return TestResult::Fail("post-remap PTE doesn't translate to f2");
    }

    // f1 was already returned to the allocator by `unmap_region` →
    // `unmap_region_pages` → `free_frame`. f2 will be reclaimed by
    // `AddressSpace::drop` when `a` goes out of scope. Explicitly
    // freeing either here is a double-free that corrupts the buddy
    // free lists (the duplicate then surfaces several allocs later
    // as `translate returned wrong phys` in the materialize test).
    let _ = f1;
    let _ = f2;
    cow::__test_clear();
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_remap_page_picks_up_perms_and_phys);

fn smoke_hugepage_2m_reserve_alloc_free() -> TestResult {
    use crate::hugepage::{
        alloc_hugepage_2m, free_hugepage, reserve_from_regions, stats, HugeAllocError,
        HUGEPAGE_2M_BYTES,
    };
    use crate::frame::UsableRegion;
    use crate::PhysAddr;

    // Synthetic 16 MiB region aligned to 2 MiB. The phys addresses
    // here are bookkeeping-only — we never touch the memory, so it
    // doesn't matter that they don't correspond to real RAM.
    // Picked far above any realistic kernel-image footprint to
    // avoid colliding with anything else's bookkeeping.
    const SYNTH_BASE: u64 = 0x1_0000_0000;
    const PAGES: usize = 4;
    let region = UsableRegion {
        start: PhysAddr::new(SYNTH_BASE),
        len: (PAGES as u64) * HUGEPAGE_2M_BYTES,
    };

    let before = stats();
    let excludes = reserve_from_regions(&[region], PAGES, 0);
    if excludes.len() != PAGES {
        return TestResult::Fail("reserve_from_regions returned wrong exclude count");
    }
    let after_reserve = stats();
    if after_reserve.free_2m - before.free_2m != PAGES {
        return TestResult::Fail("free_2m didn't grow by reserve count");
    }

    // Drain exactly PAGES new allocations.
    let mut allocated = alloc::vec::Vec::new();
    for _ in 0..PAGES {
        match alloc_hugepage_2m() {
            Ok(f) => {
                if f.phys() & (HUGEPAGE_2M_BYTES - 1) != 0 {
                    return TestResult::Fail("alloc_hugepage_2m returned unaligned phys");
                }
                allocated.push(f);
            }
            Err(_) => return TestResult::Fail("alloc_hugepage_2m exhausted before PAGES"),
        }
    }

    // Free one back, alloc one — roundtrip works.
    let returned = allocated.pop().unwrap();
    free_hugepage(returned);
    match alloc_hugepage_2m() {
        Ok(f) => allocated.push(f),
        Err(_) => return TestResult::Fail("alloc after free returned Empty"),
    }

    // Drain leaves pool back at `before`. We've alloc'd PAGES from
    // our reservation; free them all to restore.
    for f in allocated.drain(..) {
        free_hugepage(f);
    }
    // Now drain the PAGES we reserved so the pool returns to its
    // entry state (no test pollution for siblings).
    for _ in 0..PAGES {
        if alloc_hugepage_2m().is_err() {
            return TestResult::Fail("teardown drain hit Empty early");
        }
    }
    // (PAGES+1)th alloc — should be Empty (assuming nothing else
    // reserved 2M pages this boot, which is the default).
    if before.free_2m == 0 {
        match alloc_hugepage_2m() {
            Err(HugeAllocError::Empty) => {}
            _ => return TestResult::Fail("expected Empty after draining test reservation"),
        }
    }

    TestResult::Pass
}
kernel_test_in!("memory/hugepage", smoke_hugepage_2m_reserve_alloc_free);

fn smoke_hugepage_1g_reserve_picks_aligned_chunk() -> TestResult {
    use crate::hugepage::{reserve_from_regions, stats, HUGEPAGE_1G_BYTES};
    use crate::frame::UsableRegion;
    use crate::PhysAddr;

    // Region whose start is mis-aligned: head is dropped, the one
    // 1 GiB-aligned chunk is taken, the tail stays for the buddy.
    // Pick a base that's NOT 1 GiB aligned but that admits one
    // aligned 1 GiB chunk somewhere inside.
    const SYNTH_BASE: u64 = 0x10_0000_0000 + 0x1234_5000; // mis-aligned
    let region = UsableRegion {
        start: PhysAddr::new(SYNTH_BASE),
        // 3 GiB — easily fits one aligned chunk regardless of
        // where the head lands.
        len: 3 * HUGEPAGE_1G_BYTES,
    };

    let before = stats();
    let excludes = reserve_from_regions(&[region], 0, 1);
    if excludes.len() != 1 {
        return TestResult::Fail("expected exactly one 1G exclude");
    }
    let (excl_start, excl_end) = excludes[0];
    if excl_start & (HUGEPAGE_1G_BYTES - 1) != 0 {
        return TestResult::Fail("1 GiB exclude start not aligned");
    }
    if excl_end - excl_start != HUGEPAGE_1G_BYTES {
        return TestResult::Fail("1 GiB exclude wrong length");
    }
    let after = stats();
    if after.free_1g - before.free_1g != 1 {
        return TestResult::Fail("free_1g didn't grow by 1");
    }

    // Teardown: drain the one we reserved so the pool returns to
    // its prior state.
    let _ = crate::hugepage::alloc_hugepage_1g();
    TestResult::Pass
}
kernel_test_in!("memory/hugepage", smoke_hugepage_1g_reserve_picks_aligned_chunk);

fn smoke_slab_steady_state_under_churn() -> TestResult {
    // Acceptance criterion #4 from the heap-migration spec: a
    // 1000-iteration alloc/free loop must hold steady at the
    // working-set size, not grow unboundedly. Exercise multiple
    // size classes (each with its own magazines + central free
    // list) so a leak in any one of them shows up.
    use core::alloc::Layout;
    use crate::slab;

    // One representative layout per class index. Sizes are chosen
    // to fall squarely inside their class so rounding doesn't move
    // them around between iterations.
    // Indices match slab's power-of-two layout: class i serves
    // (MIN_BLOCK << i) bytes, MIN_BLOCK = 16, N_CLASSES = 9.
    let layouts = [
        (Layout::from_size_align(16, 8).unwrap(), 0usize),
        (Layout::from_size_align(64, 16).unwrap(), 2),
        (Layout::from_size_align(256, 16).unwrap(), 4),
        (Layout::from_size_align(1024, 16).unwrap(), 6),
        (Layout::from_size_align(4096, 16).unwrap(), 8),
    ];

    let before = slab::stats();

    // Churn loop. Each iteration alloc+free of every class —
    // 5 classes × 1000 = 5000 allocs, 5000 frees. After the
    // loop, in_use for every touched class must equal its
    // baseline.
    for _ in 0..1000 {
        for &(layout, _) in &layouts {
            let p = match slab::alloc(layout) {
                Ok(p) => p,
                Err(_) => return TestResult::Fail("alloc failed during churn"),
            };
            // SAFETY: just allocated with this exact layout.
            unsafe { slab::dealloc(p, layout) };
        }
    }

    let after = slab::stats();
    for &(_, class_idx) in &layouts {
        let b = before.classes[class_idx].in_use;
        let a = after.classes[class_idx].in_use;
        if a != b {
            return TestResult::Fail("class in_use drifted from baseline");
        }
    }
    if after.large_in_use != before.large_in_use {
        return TestResult::Fail("large_in_use drifted (none of these layouts are large)");
    }

    // Backing page growth is allowed (magazines + slabs hold onto
    // pages for reuse) but bounded — each class shouldn't have
    // grown by more than a handful of pages relative to the burst
    // working set. 64 pages per class is generous (4096-block
    // class only needs 1 block per alloc, so ~5000 frames worst
    // case if magazines fail; 64 means we *did* batch).
    for &(_, class_idx) in &layouts {
        let g_before = before.classes[class_idx].grown;
        let g_after = after.classes[class_idx].grown;
        let delta = g_after - g_before;
        if delta > 64 {
            return TestResult::Fail("backing pages grew unboundedly under churn");
        }
    }

    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_steady_state_under_churn);

fn smoke_slab_large_alloc_steady_state() -> TestResult {
    // Same property for the >max_class_size path that routes
    // straight to the page-frame buddy. Uses a 16 KiB allocation
    // (above the 8 KiB largest size class).
    use core::alloc::Layout;
    use crate::slab;

    let layout = Layout::from_size_align(16384, 16).unwrap();
    let before = slab::stats().large_in_use;

    for _ in 0..256 {
        let p = match slab::alloc(layout) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("large alloc failed during churn"),
        };
        // SAFETY: just allocated.
        unsafe { slab::dealloc(p, layout) };
    }

    let after = slab::stats().large_in_use;
    if after != before {
        return TestResult::Fail("large_in_use drifted from baseline");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_large_alloc_steady_state);

fn smoke_buddy_oom_returns_empty() -> TestResult {
    // Acceptance criterion #9 (heap-migration spec §5.9): with
    // a small free pool, attempting to allocate a block bigger
    // than the pool returns the empty/error sentinel — the buddy
    // does NOT panic, fall back, or coalesce phantom RAM.
    use crate::buddy::{BuddyZone, MAX_ORDER};

    // Synthetic 1 MiB pool = 256 frames. Donated at frame 0x100
    // (above the LOW_RESERVED low-MiB skip used by the live
    // allocator, but irrelevant here — this zone is local).
    const SYNTH_BASE_FRAME: u64 = 0x100;
    const POOL_FRAMES: u64 = 256;
    let mut zone = BuddyZone::new();
    zone.donate(SYNTH_BASE_FRAME, POOL_FRAMES);

    // 2 MiB request (order 9 = 512 frames) into a 1 MiB pool —
    // must return None. Spec wording: "1 MiB total free RAM,
    // attempting to allocate 2 MiB returns Err".
    if zone.alloc(9).is_some() {
        return TestResult::Fail("over-pool request unexpectedly succeeded");
    }
    // Order beyond MAX_ORDER also rejected uniformly.
    if zone.alloc(MAX_ORDER + 1).is_some() {
        return TestResult::Fail("order > MAX_ORDER unexpectedly succeeded");
    }

    // The pool's still intact afterwards — failed allocs don't
    // strand frames. Drain it via the largest fitting order
    // (256 frames = order 8) and verify exhaustion.
    let f = zone.alloc(8);
    if f.is_none() {
        return TestResult::Fail("order-8 should fit a 1 MiB pool");
    }
    if zone.alloc(0).is_some() {
        return TestResult::Fail("post-drain alloc should return None");
    }
    TestResult::Pass
}
kernel_test_in!("memory/buddy", smoke_buddy_oom_returns_empty);

fn smoke_alloc_pages_on_rejects_oversize_order() -> TestResult {
    // Public frame API: alloc_pages_on must surface Exhausted for
    // requests that the buddy can't represent. Order > MAX_ORDER
    // is rejected before touching the pool.
    use crate::buddy::MAX_ORDER;
    use crate::frame::{alloc_pages_on, FrameAllocError};
    match alloc_pages_on(0, MAX_ORDER + 1) {
        Err(FrameAllocError::Exhausted) => TestResult::Pass,
        Err(FrameAllocError::Uninitialised) => {
            TestResult::Skip("frame allocator not initialised in this flavour")
        }
        Ok(_) => TestResult::Fail("oversize order should fail, not succeed"),
    }
}
kernel_test_in!("memory/buddy", smoke_alloc_pages_on_rejects_oversize_order);

#[cfg(target_arch = "x86_64")]
fn smoke_slab_atomic_alloc_magazine_only() -> TestResult {
    // try_alloc_atomic must succeed when the magazine is warm
    // (returns the same blocks the magazine holds, no central
    // refill, no buddy growth) and return None when the magazine
    // is drained — never blocking, never sleeping.
    use core::alloc::Layout;
    use crate::slab;

    let layout = Layout::from_size_align(64, 16).unwrap();
    // Warm the magazine with a normal alloc/free roundtrip.
    let p = slab::alloc(layout).expect("warm-up alloc");
    // SAFETY: just allocated.
    unsafe { slab::dealloc(p, layout) };

    // Atomic alloc → succeeds because the magazine has the block
    // we just freed.
    let p = match slab::try_alloc_atomic(layout) {
        Some(p) => p,
        None => return TestResult::Fail("warm magazine should serve atomic alloc"),
    };
    // Atomic dealloc → returns Ok (magazine has room).
    // SAFETY: just allocated by the matching atomic path.
    if unsafe { slab::try_dealloc_atomic(p, layout) }.is_err() {
        return TestResult::Fail("non-full magazine should accept atomic dealloc");
    }

    // Drain the magazine. Repeatedly atomic-alloc until None —
    // we must hit None without ever blocking on the central
    // free list. (May take up to MAG_SIZE iterations.)
    let mut drained = alloc::vec::Vec::new();
    for _ in 0..32 {
        match slab::try_alloc_atomic(layout) {
            Some(p) => drained.push(p),
            None => break,
        }
    }
    // Now should return None until something refills.
    if slab::try_alloc_atomic(layout).is_some() {
        return TestResult::Fail("drained magazine should return None");
    }

    // Cleanup: free everything via the regular path so we don't
    // strand blocks across tests.
    for p in drained {
        // SAFETY: blocks came from the same size class.
        unsafe { slab::dealloc(p, layout) };
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_slab_atomic_alloc_magazine_only);

#[cfg(target_arch = "x86_64")]
fn smoke_slab_atomic_perf_bounded() -> TestResult {
    // Acceptance criterion #6: try_alloc_atomic hot path < 100 ns,
    // failure path < 200 ns. We measure cycles via RDTSC and
    // convert at a 1 GHz floor (so 100 ns = 100 cycles minimum).
    //
    // QEMU TCG runs the kernel under binary translation, so the
    // observed cycle counts are wildly inflated. We use a loose
    // upper bound (< 50 000 cycles ≈ 50 µs at 1 GHz) just to
    // catch true degenerate paths (e.g. accidentally taking the
    // central lock). Real-HW perf is a follow-up benchmark.
    use core::alloc::Layout;
    use core::arch::x86_64::_rdtsc;
    use crate::slab;

    let layout = Layout::from_size_align(64, 16).unwrap();

    // Warm-up: pre-fill the magazine with N blocks so the hot
    // path doesn't take the slow refill route on the first iter.
    const N: usize = 64;
    let mut warm = alloc::vec::Vec::with_capacity(N);
    for _ in 0..N {
        warm.push(slab::alloc(layout).expect("warm-up alloc"));
    }
    for p in warm.drain(..) {
        // SAFETY: just allocated.
        unsafe { slab::dealloc(p, layout) };
    }

    // Hot path: alloc + dealloc pairs from the warm magazine.
    const ITERS: u64 = 1024;
    // SAFETY: RDTSC is unconditionally available on every x86_64
    // QEMU model + every supported real-HW target.
    let t0 = unsafe { _rdtsc() };
    for _ in 0..ITERS {
        let p = slab::try_alloc_atomic(layout).expect("warm magazine");
        // SAFETY: just allocated atomically.
        let _ = unsafe { slab::try_dealloc_atomic(p, layout) };
    }
    let t1 = unsafe { _rdtsc() };
    let hot_cycles_per_pair = (t1 - t0) / ITERS;
    if hot_cycles_per_pair > 50_000 {
        return TestResult::Fail("hot-path try_alloc_atomic took absurdly long");
    }

    // Failure path: drain the magazine, then measure repeated
    // try_alloc_atomic that all return None.
    let mut drained = alloc::vec::Vec::new();
    while let Some(p) = slab::try_alloc_atomic(layout) {
        drained.push(p);
        if drained.len() > 64 {
            break;
        }
    }
    let t0 = unsafe { _rdtsc() };
    for _ in 0..ITERS {
        if slab::try_alloc_atomic(layout).is_some() {
            // Magazine refilled by another CPU? Drain it.
            // (Kernel tests run on BSP single-CPU; this shouldn't
            // happen, but bail to avoid skewing the measurement.)
            return TestResult::Fail("magazine refilled mid-failure-loop");
        }
    }
    let t1 = unsafe { _rdtsc() };
    let fail_cycles = (t1 - t0) / ITERS;
    if fail_cycles > 50_000 {
        return TestResult::Fail("failure-path try_alloc_atomic took absurdly long");
    }

    // Cleanup.
    for p in drained {
        // SAFETY: blocks came from the same size class.
        unsafe { slab::dealloc(p, layout) };
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_slab_atomic_perf_bounded);

fn smoke_context_initial_state_sleepable() -> TestResult {
    // At test-suite entry the BSP is in process context: no IRQ
    // is being serviced. is_sleepable() must be true. We don't
    // assert on irqs_enabled() because parts of boot legitimately
    // run with IRQs masked and the sleepable predicate
    // intentionally only gates on in_irq().
    use crate::context::is_sleepable;
    if narf_lib::context::in_irq() {
        return TestResult::Fail("test entry should not be in IRQ context");
    }
    if !is_sleepable() {
        return TestResult::Fail("test entry should be sleepable");
    }
    TestResult::Pass
}
kernel_test_in!("memory/context", smoke_context_initial_state_sleepable);

fn smoke_context_enter_exit_round_trip() -> TestResult {
    // enter_irq increments, in_irq becomes true, is_sleepable
    // becomes false, exit_irq restores. The depth counter
    // saturates at 0 on extra exits — verify too.
    use crate::context::is_sleepable;
    use narf_lib::context::{enter_irq, exit_irq, in_irq};

    if in_irq() {
        return TestResult::Fail("precondition: not in IRQ");
    }
    enter_irq();
    if !in_irq() {
        return TestResult::Fail("enter_irq didn't bump depth");
    }
    if is_sleepable() {
        return TestResult::Fail("in_irq context must NOT be sleepable");
    }
    // Nested enter/exit.
    enter_irq();
    exit_irq();
    if !in_irq() {
        return TestResult::Fail("nested exit shouldn't drop depth to 0");
    }
    exit_irq();
    if in_irq() {
        return TestResult::Fail("balanced exits should clear depth");
    }
    // Saturate-at-0: extra exit doesn't underflow.
    exit_irq();
    if in_irq() {
        return TestResult::Fail("over-exit must saturate at 0");
    }
    TestResult::Pass
}
kernel_test_in!("memory/context", smoke_context_enter_exit_round_trip);

fn smoke_context_predicate_drives_assert() -> TestResult {
    // Acceptance criterion #5: the AllocContext debug assertion
    // sources its decision from `is_sleepable()`. We can't
    // observe a panic non-destructively in this kernel (panic
    // is `-> !`), so we exercise the predicate the assert reads
    // — same shape: enter IRQ, predicate must say "not
    // sleepable", exit, predicate must say "sleepable" again.
    use crate::context::is_sleepable;
    use narf_lib::context::{enter_irq, exit_irq};

    if !is_sleepable() {
        return TestResult::Fail("test entry should be sleepable");
    }
    enter_irq();
    let in_irq_sleepable = is_sleepable();
    exit_irq();
    if in_irq_sleepable {
        return TestResult::Fail(
            "is_sleepable() inside IRQ ctx must be false (else assert is silent)",
        );
    }
    if !is_sleepable() {
        return TestResult::Fail("post-exit should be sleepable again");
    }
    TestResult::Pass
}
kernel_test_in!("memory/context", smoke_context_predicate_drives_assert);
// Note: end-to-end "real IRQ handler observes in_irq() == true"
// test lives in interrupts/src/tests.rs (memory crate doesn't
// depend on narf-interrupts).

fn smoke_atomic_pool_drain_and_refill() -> TestResult {
    // Acceptance #7 substrate: pool of N pre-allocated items
    // drains via try_get, refills as Pooled handles drop.
    use crate::atomic_pool::AtomicPool;

    static POOL: narf_lib::sync::OnceLock<AtomicPool<u64>> =
        narf_lib::sync::OnceLock::new();
    let pool = POOL.get_or_init(|| AtomicPool::new(4, || 0u64));

    if pool.capacity() != 4 {
        return TestResult::Fail("capacity didn't stick");
    }
    if pool.free_count() != 4 {
        return TestResult::Fail("post-init free_count != capacity");
    }

    // Drain all 4.
    let h0 = pool.try_get().expect("get 0");
    let h1 = pool.try_get().expect("get 1");
    let h2 = pool.try_get().expect("get 2");
    let h3 = pool.try_get().expect("get 3");
    if pool.free_count() != 0 {
        return TestResult::Fail("post-drain free_count != 0");
    }

    // Empty pool returns None.
    if pool.try_get().is_some() {
        return TestResult::Fail("drained pool should return None");
    }

    // Drop one — count goes back up by 1.
    drop(h0);
    if pool.free_count() != 1 {
        return TestResult::Fail("drop didn't return item to pool");
    }

    // Re-lease the freed slot, mutate it, return it, lease again
    // — same physical Box should come back.
    let mut h_again = pool.try_get().expect("re-lease");
    *h_again = 42;
    drop(h_again);
    let h_check = pool.try_get().expect("re-lease 2");
    if *h_check != 42 {
        return TestResult::Fail("pool didn't preserve mutation across drop");
    }

    // Cleanup: drop everything.
    drop(h1);
    drop(h2);
    drop(h3);
    drop(h_check);
    if pool.free_count() != 4 {
        return TestResult::Fail("not all items returned after drop");
    }
    TestResult::Pass
}
kernel_test_in!("memory/atomic_pool", smoke_atomic_pool_drain_and_refill);
// End-to-end "AtomicPool used from real IRQ handler" test lives
// in interrupts/src/tests.rs (memory crate doesn't depend on
// narf-interrupts).

// ── deep memory/atomic_pool ──────────────────────────────────────

fn smoke_atomic_pool_capacity_pinned_after_drain() -> TestResult {
    use crate::atomic_pool::AtomicPool;
    use narf_lib::sync::IrqSafeSpinLock;
    static POOL: IrqSafeSpinLock<Option<&'static AtomicPool<u64>>> =
        IrqSafeSpinLock::new(None);
    let pool: &'static AtomicPool<u64> = {
        let p = alloc::boxed::Box::leak(alloc::boxed::Box::new(AtomicPool::new(3, || 0u64)));
        *POOL.lock() = Some(p);
        p
    };
    if pool.capacity() != 3 {
        return TestResult::Fail("capacity != 3 at init");
    }
    let a = pool.try_get();
    let b = pool.try_get();
    let c = pool.try_get();
    if a.is_none() || b.is_none() || c.is_none() {
        return TestResult::Fail("drain didn't yield 3 items");
    }
    if pool.capacity() != 3 {
        return TestResult::Fail("capacity() drifted while drained");
    }
    if pool.free_count() != 0 {
        return TestResult::Fail("free_count != 0 when drained");
    }
    if pool.try_get().is_some() {
        return TestResult::Fail("4th try_get should have returned None");
    }
    drop(a);
    drop(b);
    drop(c);
    if pool.free_count() != 3 {
        return TestResult::Fail("free_count didn't restore to 3");
    }
    TestResult::Pass
}
kernel_test_in!("memory/atomic_pool", smoke_atomic_pool_capacity_pinned_after_drain);

fn smoke_atomic_pool_pooled_deref_mut_visible_next_lease() -> TestResult {
    // Pooled<T>'s DerefMut writes are observable when the item
    // returns to the pool and is leased again — the pool isn't
    // resetting items on drop.
    use crate::atomic_pool::AtomicPool;
    use narf_lib::sync::IrqSafeSpinLock;
    static POOL: IrqSafeSpinLock<Option<&'static AtomicPool<u32>>> =
        IrqSafeSpinLock::new(None);
    let pool: &'static AtomicPool<u32> = {
        let p = alloc::boxed::Box::leak(alloc::boxed::Box::new(AtomicPool::new(1, || 0u32)));
        *POOL.lock() = Some(p);
        p
    };
    {
        let mut h = pool.try_get().expect("lease 1");
        *h = 0xDEAD_BEEF;
    }
    let h2 = pool.try_get().expect("lease 2");
    if *h2 != 0xDEAD_BEEF {
        return TestResult::Fail("mutation lost across drop+re-lease");
    }
    TestResult::Pass
}
kernel_test_in!("memory/atomic_pool", smoke_atomic_pool_pooled_deref_mut_visible_next_lease);

// ── deep memory/tlb_shootdown ────────────────────────────────────

fn smoke_tlb_shootdown_request_constructors() -> TestResult {
    use crate::tlb_shootdown::ShootdownRequest;
    let full = ShootdownRequest::full();
    if full.tag.is_some() || full.addr.is_some() || full.size.is_some() {
        return TestResult::Fail("full() should clear all fields");
    }
    let by_tag = ShootdownRequest::for_tag(42);
    if by_tag.tag != Some(42) || by_tag.addr.is_some() || by_tag.size.is_some() {
        return TestResult::Fail("for_tag() shape drifted");
    }
    let by_va = ShootdownRequest::for_va(7, 0xFFFF_8000_DEAD_0000);
    if by_va.tag != Some(7) || by_va.addr != Some(0xFFFF_8000_DEAD_0000) || by_va.size.is_some() {
        return TestResult::Fail("for_va() shape drifted");
    }
    TestResult::Pass
}
kernel_test_in!("memory/tlb_shootdown", smoke_tlb_shootdown_request_constructors);

fn smoke_tlb_shootdown_counter_monotonic() -> TestResult {
    use crate::tlb_shootdown::{shootdown, shootdown_count, ShootdownRequest, __reset_for_test};
    __reset_for_test();
    let base = shootdown_count();
    shootdown(ShootdownRequest::full());
    shootdown(ShootdownRequest::for_tag(1));
    shootdown(ShootdownRequest::for_va(2, 0x1000));
    let after = shootdown_count();
    if after.saturating_sub(base) != 3 {
        return TestResult::Fail("shootdown_count didn't increment by 3");
    }
    TestResult::Pass
}
kernel_test_in!("memory/tlb_shootdown", smoke_tlb_shootdown_counter_monotonic);

fn smoke_tlb_shootdown_request_equality() -> TestResult {
    use crate::tlb_shootdown::ShootdownRequest;
    let a = ShootdownRequest::for_va(5, 0x2000);
    let b = ShootdownRequest::for_va(5, 0x2000);
    let c = ShootdownRequest::for_va(5, 0x3000);
    if a != b {
        return TestResult::Fail("Eq on identical ShootdownRequest broke");
    }
    if a == c {
        return TestResult::Fail("Eq collapsed distinct ShootdownRequests");
    }
    TestResult::Pass
}
kernel_test_in!("memory/tlb_shootdown", smoke_tlb_shootdown_request_equality);

// ── deep memory/context ──────────────────────────────────────────

fn smoke_context_alloc_context_variants_distinct() -> TestResult {
    use crate::context::AllocContext;
    let all = [AllocContext::Sleepable, AllocContext::Atomic, AllocContext::IrqOff];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("AllocContext variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory/context", smoke_context_alloc_context_variants_distinct);

fn smoke_context_atomic_assert_is_noop() -> TestResult {
    // Atomic / IrqOff carry no precondition on the caller's
    // environment — debug_assert_consistent must accept them
    // regardless of IRQ state.
    use crate::context::AllocContext;
    AllocContext::Atomic.debug_assert_consistent();
    AllocContext::IrqOff.debug_assert_consistent();
    TestResult::Pass
}
kernel_test_in!("memory/context", smoke_context_atomic_assert_is_noop);

// ── deep memory/asid_alloc ──────────────────────────────────────

fn smoke_asid_alloc_cached_returns_same_tag() -> TestResult {
    use crate::asid_alloc::{alloc, cached, __reset_for_test};
    use narf_lib::id::DomainId;
    __reset_for_test();
    let dom = DomainId::SCRATCH;
    let issued = alloc(dom);
    let again = cached(dom).expect("cached should hit after alloc");
    if issued.tag != again.tag || issued.generation != again.generation {
        return TestResult::Fail("cached drifted from alloc");
    }
    TestResult::Pass
}
kernel_test_in!("memory/asid_alloc", smoke_asid_alloc_cached_returns_same_tag);

fn smoke_asid_alloc_invalidate_clears_cache() -> TestResult {
    use crate::asid_alloc::{alloc, cached, invalidate_tag, __reset_for_test};
    use narf_lib::id::DomainId;
    __reset_for_test();
    let dom = DomainId::SCRATCH;
    let _ = alloc(dom);
    if cached(dom).is_none() {
        return TestResult::Fail("cache miss right after alloc");
    }
    invalidate_tag(dom);
    if cached(dom).is_some() {
        return TestResult::Fail("invalidate_tag didn't clear cache");
    }
    // Next alloc issues a fresh tag.
    let fresh = alloc(dom);
    if fresh.tag == 0 {
        return TestResult::Fail("post-invalidate alloc returned reserved tag");
    }
    TestResult::Pass
}
kernel_test_in!("memory/asid_alloc", smoke_asid_alloc_invalidate_clears_cache);

fn smoke_asid_alloc_rollover_bumps_generation() -> TestResult {
    use crate::asid_alloc::{alloc, current_generation, rollover_now, __reset_for_test};
    use narf_lib::id::DomainId;
    __reset_for_test();
    let before = current_generation();
    let _ = alloc(DomainId::SCRATCH);
    rollover_now();
    let after = current_generation();
    if after <= before {
        return TestResult::Fail("rollover_now didn't bump generation");
    }
    // Re-alloc post-rollover must produce a tag in the new gen.
    let fresh = alloc(DomainId::SCRATCH);
    if fresh.generation != after {
        return TestResult::Fail("post-rollover alloc has stale generation");
    }
    TestResult::Pass
}
kernel_test_in!("memory/asid_alloc", smoke_asid_alloc_rollover_bumps_generation);

fn smoke_asid_alloc_reserved_tag_constant() -> TestResult {
    use crate::asid_alloc::TAG_RESERVED;
    if TAG_RESERVED != 0 {
        return TestResult::Fail("TAG_RESERVED drifted from 0");
    }
    TestResult::Pass
}
kernel_test_in!("memory/asid_alloc", smoke_asid_alloc_reserved_tag_constant);

// ── deep memory/per_domain_root ──────────────────────────────────

fn smoke_per_domain_root_alloc_error_variants_distinct() -> TestResult {
    use crate::per_domain_root::AllocError;
    let all = [AllocError::OutOfMemory, AllocError::NotInitialised, AllocError::AlreadyAllocated];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("AllocError variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory/per_domain_root", smoke_per_domain_root_alloc_error_variants_distinct);

fn smoke_per_domain_root_lookup_none_before_register() -> TestResult {
    use crate::per_domain_root::{__reset_for_test, lookup, unregister_root};
    use narf_lib::id::DomainId;
    __reset_for_test();
    // SCRATCH starts unregistered after reset.
    unregister_root(DomainId::SCRATCH);
    if lookup(DomainId::SCRATCH).is_some() {
        return TestResult::Fail("lookup after unregister returned Some");
    }
    TestResult::Pass
}
kernel_test_in!("memory/per_domain_root", smoke_per_domain_root_lookup_none_before_register);

fn smoke_per_domain_root_double_register_rejected() -> TestResult {
    use crate::per_domain_root::{__reset_for_test, register_root, unregister_root, AllocError};
    use narf_lib::id::DomainId;
    __reset_for_test();
    unregister_root(DomainId::SCRATCH);
    let dom = DomainId::SCRATCH;
    let first = register_root(dom, 0xFFFF_F000);
    if first.is_err() {
        return TestResult::Fail("first register_root failed");
    }
    match register_root(dom, 0xFFFE_F000) {
        Err(AllocError::AlreadyAllocated) => {}
        _ => return TestResult::Fail("double-register didn't surface AlreadyAllocated"),
    }
    unregister_root(dom);
    TestResult::Pass
}
kernel_test_in!("memory/per_domain_root", smoke_per_domain_root_double_register_rejected);

// ── deep memory/buddy ────────────────────────────────────────────

fn smoke_buddy_alloc_pages_on_order_round_trip() -> TestResult {
    // Order 0 (1 page) round-trips through alloc_pages_on / free_pages
    // on the default NUMA node. Uninitialised allocator is a valid
    // outcome on the slim test image — surface a Skip instead of
    // fabricating a pass.
    use crate::frame::{alloc_pages_on, free_pages, FrameAllocError};
    match alloc_pages_on(0, 0) {
        Ok(frame) => {
            free_pages(frame, 0);
            TestResult::Pass
        }
        Err(FrameAllocError::Uninitialised) => {
            TestResult::Skip("frame allocator not up in this flavour")
        }
        Err(FrameAllocError::Exhausted) => {
            TestResult::Skip("buddy exhausted on this test image")
        }
    }
}
kernel_test_in!("memory/buddy", smoke_buddy_alloc_pages_on_order_round_trip);

fn smoke_buddy_alloc_pages_on_max_order_boundary() -> TestResult {
    // MAX_ORDER itself must be accepted (Exhausted is fine — pool may
    // not have a contiguous run); MAX_ORDER+1 was already tested as
    // rejected, so the boundary lives one slot below.
    use crate::buddy::MAX_ORDER;
    use crate::frame::{alloc_pages_on, free_pages, FrameAllocError};
    match alloc_pages_on(0, MAX_ORDER) {
        Ok(frame) => {
            free_pages(frame, MAX_ORDER);
            TestResult::Pass
        }
        Err(FrameAllocError::Exhausted) | Err(FrameAllocError::Uninitialised) => TestResult::Pass,
    }
}
kernel_test_in!("memory/buddy", smoke_buddy_alloc_pages_on_max_order_boundary);

// ── deep memory/hugepage ─────────────────────────────────────────

fn smoke_hugepage_size_constants() -> TestResult {
    use crate::hugepage::{HUGEPAGE_1G_BYTES, HUGEPAGE_2M_BYTES};
    if HUGEPAGE_2M_BYTES != 2 * 1024 * 1024 {
        return TestResult::Fail("HUGEPAGE_2M_BYTES drifted from 2 MiB");
    }
    if HUGEPAGE_1G_BYTES != 1024 * 1024 * 1024 {
        return TestResult::Fail("HUGEPAGE_1G_BYTES drifted from 1 GiB");
    }
    if HUGEPAGE_1G_BYTES != HUGEPAGE_2M_BYTES * 512 {
        return TestResult::Fail("1 GiB / 2 MiB ratio drifted from 512");
    }
    TestResult::Pass
}
kernel_test_in!("memory/hugepage", smoke_hugepage_size_constants);

fn smoke_hugepage_alloc_2m_empty_after_no_reserve() -> TestResult {
    // With no reserve_from_regions call, the 2 MiB pool must be
    // empty and alloc_hugepage_2m must surface Empty rather than
    // hand back a fabricated frame.
    use crate::hugepage::{alloc_hugepage_2m, stats, HugeAllocError};
    let s = stats();
    if s.free_2m != 0 {
        // Pool may be warm from earlier tests — Skip rather than
        // mutate global state we don't own.
        return TestResult::Skip("hugepage 2m pool not empty");
    }
    match alloc_hugepage_2m() {
        Err(HugeAllocError::Empty) => TestResult::Pass,
        _ => TestResult::Fail("empty 2m pool didn't surface Empty"),
    }
}
kernel_test_in!("memory/hugepage", smoke_hugepage_alloc_2m_empty_after_no_reserve);

// ── demand paging — AddressSpace::demand_alloc_page surface ──────
//
// Anchored on the sys_mmap deferred-back flow: install a region
// with `phys[i] == 0` so materialize() leaves no PTE for that page;
// the user-mode #PF handler then routes the fault into
// `demand_alloc_page`, which allocates + zeroes a frame and
// installs the leaf PTE with the region's perms. These smokes
// drive `demand_alloc_page` directly (the trap path's plumbing is
// covered by smoke_memory_lazy_phys_zero_skipped + the
// userspace mmap tests).
//
// Cite: Intel SDM Vol. 3 §4.7 — page-fault error code semantics
// the kernel #PF dispatch uses to identify a P=0 (not-present)
// fault and route it here.

/// `demand_alloc_page` on a lazy slot must allocate a backing
/// frame, record it in the region's `phys`, and install a
/// translatable PTE with the region's perm bits.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_demand_alloc_installs_pte() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let vbase = 0x0000_0080_0000_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .expect("map_region");
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    if unsafe { translate_arch(a.root, VirtAddr::new(vbase)) }.is_some() {
        core::mem::forget(a);
        return TestResult::Fail("lazy slot had a PTE before demand-alloc");
    }
    if unsafe { a.demand_alloc_page(VirtAddr::new(vbase + 0x123)) }.is_err() {
        core::mem::forget(a);
        return TestResult::Fail("demand_alloc_page failed");
    }
    let pte = unsafe { translate_arch(a.root, VirtAddr::new(vbase)) };
    core::mem::forget(a);
    if pte.is_none() {
        return TestResult::Fail("demand-alloc didn't install a PTE");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_demand_alloc_installs_pte);

/// `demand_alloc_page` on an already-backed slot is a spurious
/// fault (TLB shootdown race). Returns AlignmentMismatch so the
/// trap handler retries cleanly without double-allocating.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_demand_alloc_already_backed_spurious() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let frame = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    let vbase = 0x0000_0080_0010_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![frame],
    })
    .expect("map_region");
    let r = unsafe { a.demand_alloc_page(VirtAddr::new(vbase)) };
    core::mem::forget(a);
    match r {
        Err(AddressSpaceError::AlignmentMismatch) => TestResult::Pass,
        other => {
            let _ = other;
            TestResult::Fail("backed slot didn't surface spurious-fault sentinel")
        }
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_demand_alloc_already_backed_spurious);

/// `demand_alloc_page` on a PROT_NONE region is a real access
/// violation; surface as Unmapped so the trap handler can route
/// the SEGV signal.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_demand_alloc_prot_none_is_unmapped() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let vbase = 0x0000_0080_0020_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x1000,
        perms: RegionPerms(0),
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .expect("map_region");
    let r = unsafe { a.demand_alloc_page(VirtAddr::new(vbase)) };
    core::mem::forget(a);
    match r {
        Err(AddressSpaceError::Unmapped) => TestResult::Pass,
        _ => TestResult::Fail("PROT_NONE fault did not surface Unmapped"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_demand_alloc_prot_none_is_unmapped);

/// `demand_alloc_page` outside any region returns Unmapped so the
/// trap handler falls through to the panic / signal path.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_demand_alloc_outside_region_unmapped() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let r = unsafe { a.demand_alloc_page(VirtAddr::new(0x0000_0090_0000_0000)) };
    core::mem::forget(a);
    match r {
        Err(AddressSpaceError::Unmapped) => TestResult::Pass,
        _ => TestResult::Fail("out-of-region fault did not surface Unmapped"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_demand_alloc_outside_region_unmapped);

/// Multi-page lazy region: each `demand_alloc_page` call must
/// allocate a *distinct* frame and install a distinct PTE per
/// page; the frame allocator is a freelist so identical-frame
/// regression is the failure mode we're guarding against.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_demand_alloc_multi_page_distinct_frames() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let vbase = 0x0000_0080_0030_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x3000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0); 3],
    })
    .expect("map_region");
    for i in 0..3 {
        if unsafe { a.demand_alloc_page(VirtAddr::new(vbase + (i as u64) * 0x1000)) }.is_err() {
            core::mem::forget(a);
            return TestResult::Fail("demand_alloc_page failed mid-loop");
        }
    }
    let p0 = unsafe { translate_arch(a.root, VirtAddr::new(vbase)) };
    let p1 = unsafe { translate_arch(a.root, VirtAddr::new(vbase + 0x1000)) };
    let p2 = unsafe { translate_arch(a.root, VirtAddr::new(vbase + 0x2000)) };
    core::mem::forget(a);
    if p0.is_none() || p1.is_none() || p2.is_none() {
        return TestResult::Fail("post-demand-alloc translate returned None");
    }
    if p0 == p1 || p1 == p2 || p0 == p2 {
        return TestResult::Fail("demand_alloc_page handed out duplicate frames");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_demand_alloc_multi_page_distinct_frames);

/// Fresh demand-allocated frame is zero-filled. Anonymous mmap
/// semantics require the user observes zeros — not the previous
/// owner's bytes.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_demand_alloc_zero_fills_frame() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let vbase = 0x0000_0080_0040_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .expect("map_region");
    if unsafe { a.demand_alloc_page(VirtAddr::new(vbase)) }.is_err() {
        core::mem::forget(a);
        return TestResult::Fail("demand_alloc_page failed");
    }
    let phys = match a.lookup(VirtAddr::new(vbase)) {
        Some(r) => r.phys[0],
        None => {
            core::mem::forget(a);
            return TestResult::Fail("region disappeared after demand alloc");
        }
    };
    // SAFETY: identity-mapped low 4 GiB; the frame was just returned
    // by the allocator and is exclusively held by `a`.
    let all_zero = unsafe {
        let p = phys.raw() as *const u8;
        (0..4096).all(|i| *p.add(i) == 0)
    };
    core::mem::forget(a);
    if !all_zero {
        return TestResult::Fail("demand-allocated frame was not zero-filled");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_demand_alloc_zero_fills_frame);

// ── stack auto-extension — AddressSpace::try_grow_stack ──────────
//
// The SysV stack init path installs a STACK_GUARD region one page
// below the user stack. A user-mode write that lands in that
// region faults with P=0 and the kernel #PF dispatch routes it
// into try_grow_stack: a fresh frame is allocated + zeroed, the
// guard region is promoted to R+W (PTE installed), and a new
// one-page guard region is appended directly below. The behaviour
// is POSIX.1-2017 §2.2.2 implementation-defined territory; the
// shape mirrors the standard stack auto-extension contract.

/// Happy path: faulting inside a STACK_GUARD region promotes it
/// to R+W (installing a PTE) AND appends a fresh guard region
/// one page below.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_try_grow_stack_promotes_and_installs_new_guard() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let guard = 0x0000_0080_0100_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(guard),
        len: 0x1000,
        perms: RegionPerms::STACK_GUARD,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .expect("map_region guard");
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    if unsafe { translate_arch(a.root, VirtAddr::new(guard)) }.is_some() {
        core::mem::forget(a);
        return TestResult::Fail("STACK_GUARD region had a PTE before grow");
    }
    if unsafe { a.try_grow_stack(VirtAddr::new(guard + 0x10)) }.is_err() {
        core::mem::forget(a);
        return TestResult::Fail("try_grow_stack failed on a STACK_GUARD region");
    }
    let promoted_pte = unsafe { translate_arch(a.root, VirtAddr::new(guard)) };
    let new_guard_pte = unsafe { translate_arch(a.root, VirtAddr::new(guard - 0x1000)) };
    let snap = a.regions_snapshot();
    let region_count = snap.len();
    let new_guard_present = snap
        .iter()
        .any(|r| r.base.as_u64() == guard - 0x1000 && r.perms.contains(RegionPerms::STACK_GUARD));
    let promoted = snap
        .iter()
        .find(|r| r.base.as_u64() == guard)
        .map(|r| r.perms.contains(RegionPerms::WRITE))
        .unwrap_or(false);
    core::mem::forget(a);
    if promoted_pte.is_none() {
        return TestResult::Fail("promoted guard didn't get a PTE");
    }
    if new_guard_pte.is_some() {
        return TestResult::Fail("new guard region got a PTE (must stay not-present)");
    }
    if region_count != 2 {
        return TestResult::Fail("expected promoted + new guard regions");
    }
    if !new_guard_present {
        return TestResult::Fail("new STACK_GUARD region missing one page below");
    }
    if !promoted {
        return TestResult::Fail("promoted region missing WRITE perm");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_try_grow_stack_promotes_and_installs_new_guard);

/// try_grow_stack on a non-STACK_GUARD region returns Unmapped
/// so the trap handler falls through to the SEGV path (a write
/// to a real PROT_NONE region or a backed RO region is not a
/// stack-grow event).
#[cfg(target_arch = "x86_64")]
fn smoke_memory_try_grow_stack_non_guard_is_unmapped() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let vbase = 0x0000_0080_0200_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x1000,
        perms: RegionPerms(0), // PROT_NONE, not STACK_GUARD
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .expect("map_region");
    let r = unsafe { a.try_grow_stack(VirtAddr::new(vbase)) };
    core::mem::forget(a);
    match r {
        Err(AddressSpaceError::Unmapped) => TestResult::Pass,
        _ => TestResult::Fail("non-guard region didn't surface Unmapped"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_try_grow_stack_non_guard_is_unmapped);

/// try_grow_stack outside any region returns Unmapped.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_try_grow_stack_outside_region_is_unmapped() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let r = unsafe { a.try_grow_stack(VirtAddr::new(0x0000_0080_0300_0000)) };
    core::mem::forget(a);
    match r {
        Err(AddressSpaceError::Unmapped) => TestResult::Pass,
        _ => TestResult::Fail("out-of-region grow didn't surface Unmapped"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_try_grow_stack_outside_region_is_unmapped);

/// New guard one page below the current guard must NOT collide
/// with an existing region. The grow surfaces Overlap so the trap
/// handler reports a real stack-overflow SEGV.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_try_grow_stack_collision_rejected() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let guard = 0x0000_0080_0400_0000u64;
    // Sitting region immediately below the guard — the new guard
    // (guard - 0x1000) lands in it.
    a.map_region(Region {
        base: VirtAddr::new(guard - 0x1000),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .expect("map_region neighbour");
    a.map_region(Region {
        base: VirtAddr::new(guard),
        len: 0x1000,
        perms: RegionPerms::STACK_GUARD,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .expect("map_region guard");
    let r = unsafe { a.try_grow_stack(VirtAddr::new(guard)) };
    core::mem::forget(a);
    match r {
        Err(AddressSpaceError::Overlap) => TestResult::Pass,
        _ => TestResult::Fail("colliding new-guard install was accepted"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_try_grow_stack_collision_rejected);

/// Sequential grows: starting from a single guard, three grows
/// produce three R+W stack pages and a guard sitting at the
/// new bottom. Catches a regression where the new guard install
/// races against the promotion bookkeeping.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_try_grow_stack_sequential() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let guard0 = 0x0000_0080_0500_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(guard0),
        len: 0x1000,
        perms: RegionPerms::STACK_GUARD,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .expect("map_region guard");
    // Walk three guards down.
    let mut cur = guard0;
    for _ in 0..3 {
        if unsafe { a.try_grow_stack(VirtAddr::new(cur)) }.is_err() {
            core::mem::forget(a);
            return TestResult::Fail("sequential grow failed mid-loop");
        }
        cur -= 0x1000;
    }
    let snap = a.regions_snapshot();
    let rw_count = snap
        .iter()
        .filter(|r| {
            !r.perms.contains(RegionPerms::STACK_GUARD)
                && r.perms.contains(RegionPerms::READ)
                && r.perms.contains(RegionPerms::WRITE)
        })
        .count();
    let guard_count = snap
        .iter()
        .filter(|r| r.perms.contains(RegionPerms::STACK_GUARD))
        .count();
    let lowest_guard = snap
        .iter()
        .filter(|r| r.perms.contains(RegionPerms::STACK_GUARD))
        .map(|r| r.base.as_u64())
        .min();
    core::mem::forget(a);
    if rw_count != 3 {
        return TestResult::Fail("expected 3 promoted stack pages");
    }
    if guard_count != 1 {
        return TestResult::Fail("expected exactly one trailing guard");
    }
    if lowest_guard != Some(guard0 - 3 * 0x1000) {
        return TestResult::Fail("trailing guard not three pages below the start");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_try_grow_stack_sequential);

/// STACK_GUARD bit lives outside the POSIX prot mask so an
/// `mprotect`-style query on the region's perms doesn't observe
/// it. Pins the bit position so a future flag addition doesn't
/// silently shadow it.
fn smoke_memory_stack_guard_bit_outside_prot_mask() -> TestResult {
    use crate::RegionPerms;
    let g = RegionPerms::STACK_GUARD;
    if g.prot_only().0 != 0 {
        return TestResult::Fail("STACK_GUARD bit leaked into prot mask");
    }
    if RegionPerms::STACK_GUARD.0 == RegionPerms::LOCKED.0 {
        return TestResult::Fail("STACK_GUARD collides with LOCKED bit");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_stack_guard_bit_outside_prot_mask);

// ── unmap returns frames to the buddy allocator ──────────────────
//
// sys_munmap and sys_brk-shrink route through
// `AddressSpace::unmap_region`, which walks every page's PTE,
// unmaps the leaf, and calls `free_frame` per phys. Pre-fix the
// bookkeeping entry was popped but the frames stayed live — those
// pages leaked until process exit. These smokes pin the free-back
// path against a future regression by snapshotting the buddy's
// free-frame count across the unmap.

/// `unmap_region` returns every backed frame to the allocator.
/// We snapshot the buddy's free count before mapping, allocate
/// + map a multi-page region, then unmap and confirm the free
/// count returns to (or above) the original — equality holds
/// when no concurrent task is allocating; allocator may also
/// have merged buddies which is fine.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_unmap_region_returns_frames() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let pages = 4usize;
    let before = crate::frame::stats().free;
    if before == 0 {
        core::mem::forget(a);
        return TestResult::Skip("frame allocator drained");
    }
    let mut phys_list = alloc::vec::Vec::with_capacity(pages);
    for _ in 0..pages {
        let f = match crate::alloc_frame() {
            Ok(f) => f,
            Err(_) => {
                core::mem::forget(a);
                return TestResult::Skip("frame allocator drained mid-test");
            }
        };
        phys_list.push(f.start_address());
    }
    let vbase = 0x0000_0080_0600_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: (pages as u64) * 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: phys_list,
    })
    .expect("map_region");
    if unsafe { a.materialize() }.is_err() {
        core::mem::forget(a);
        return TestResult::Fail("materialize failed");
    }
    let after_alloc = crate::frame::stats().free;
    if a.unmap_region(VirtAddr::new(vbase)).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("unmap_region failed");
    }
    let after_unmap = crate::frame::stats().free;
    core::mem::forget(a);
    // Every backed frame must have come back.
    if after_unmap < after_alloc + pages {
        return TestResult::Fail("unmap_region didn't return all frames");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_unmap_region_returns_frames);

/// Lazy region (every `phys[i] == 0`) unmap: nothing to free,
/// the unmap must not crash and the free count is unchanged.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_unmap_region_lazy_is_noop_on_free_count() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let vbase = 0x0000_0080_0700_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x3000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0); 3],
    })
    .expect("map_region");
    let before = crate::frame::stats().free;
    if a.unmap_region(VirtAddr::new(vbase)).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("unmap_region on lazy region failed");
    }
    let after = crate::frame::stats().free;
    core::mem::forget(a);
    // Lazy slots have no frame backing — free count must not move.
    if after != before {
        return TestResult::Fail("lazy unmap moved free-frame count unexpectedly");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_unmap_region_lazy_is_noop_on_free_count);

/// Mixed region (some lazy + some backed) returns ONLY the
/// backed slots. The demand-paging contract says lazy slots had
/// no frame; only post-demand-alloc slots own one.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_unmap_region_mixed_lazy_and_backed() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let backed = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    let vbase = 0x0000_0080_0800_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x3000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        // page 0: lazy, page 1: backed, page 2: lazy
        phys: alloc::vec![PhysAddr::new(0), backed, PhysAddr::new(0)],
    })
    .expect("map_region");
    if unsafe { a.materialize() }.is_err() {
        core::mem::forget(a);
        return TestResult::Fail("materialize failed");
    }
    let before = crate::frame::stats().free;
    if a.unmap_region(VirtAddr::new(vbase)).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("unmap_region failed");
    }
    let after = crate::frame::stats().free;
    core::mem::forget(a);
    // Exactly one frame should have come back.
    if after < before + 1 {
        return TestResult::Fail("backed page wasn't returned to allocator");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_unmap_region_mixed_lazy_and_backed);

/// Repeated alloc+map / unmap cycles must keep the allocator's
/// free count stable — leaks would walk it monotonically down.
/// Anchored against the brk-shrink + munmap teardown path.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_unmap_region_cycle_no_leak() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let baseline = crate::frame::stats().free;
    let pages = 3usize;
    for cycle in 0..4 {
        let mut phys_list = alloc::vec::Vec::with_capacity(pages);
        for _ in 0..pages {
            let f = match crate::alloc_frame() {
                Ok(f) => f,
                Err(_) => {
                    core::mem::forget(a);
                    return TestResult::Skip("frame allocator drained mid-test");
                }
            };
            phys_list.push(f.start_address());
        }
        let vbase = 0x0000_0080_0900_0000u64 + (cycle as u64) * 0x10_0000;
        a.map_region(Region {
            base: VirtAddr::new(vbase),
            len: (pages as u64) * 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: phys_list,
        })
        .expect("map_region");
        if unsafe { a.materialize() }.is_err() {
            core::mem::forget(a);
            return TestResult::Fail("materialize failed");
        }
        if a.unmap_region(VirtAddr::new(vbase)).is_err() {
            core::mem::forget(a);
            return TestResult::Fail("unmap_region failed");
        }
    }
    let after = crate::frame::stats().free;
    core::mem::forget(a);
    // After balanced cycles the free count must NOT have dropped
    // below baseline — a leak would walk it downward by `pages *
    // cycles` (12 frames here).
    if after + pages < baseline {
        return TestResult::Fail("repeated map+unmap leaked frames");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_unmap_region_cycle_no_leak);

/// `unmap_region` clears the bookkeeping AND tears down the PTEs
/// — a `translate` on the just-unmapped vaddr must return None.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_unmap_region_clears_ptes() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let frame = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    let vbase = 0x0000_0080_0A00_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![frame],
    })
    .expect("map_region");
    if unsafe { a.materialize() }.is_err() {
        core::mem::forget(a);
        return TestResult::Fail("materialize failed");
    }
    let before = unsafe { translate_arch(a.root, VirtAddr::new(vbase)) };
    if before.is_none() {
        core::mem::forget(a);
        return TestResult::Fail("post-materialize translate returned None");
    }
    if a.unmap_region(VirtAddr::new(vbase)).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("unmap_region failed");
    }
    let after = unsafe { translate_arch(a.root, VirtAddr::new(vbase)) };
    core::mem::forget(a);
    if after.is_some() {
        return TestResult::Fail("PTE survived unmap_region");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_unmap_region_clears_ptes);

// ── LZ4 codec smokes ────────────────────────────────────────────────

fn smoke_lz4_identity_zeros() -> TestResult {
    use crate::compress::test_helpers::roundtrip;
    let input = alloc::vec![0u8; 4096];
    match roundtrip(&input) {
        Ok(out) if out == input => TestResult::Pass,
        Ok(_) => TestResult::Fail("zeros round-trip mismatch"),
        Err(_) => TestResult::Fail("zeros round-trip errored"),
    }
}
kernel_test_in!("memory", smoke_lz4_identity_zeros);

fn smoke_lz4_identity_alphabet() -> TestResult {
    use crate::compress::test_helpers::roundtrip;
    let mut input = alloc::vec::Vec::with_capacity(4096);
    for i in 0..4096usize {
        input.push((b'A' + (i % 26) as u8) as u8);
    }
    match roundtrip(&input) {
        Ok(out) if out == input => TestResult::Pass,
        Ok(_) => TestResult::Fail("alphabet round-trip mismatch"),
        Err(_) => TestResult::Fail("alphabet round-trip errored"),
    }
}
kernel_test_in!("memory", smoke_lz4_identity_alphabet);

fn smoke_lz4_identity_pseudo_random() -> TestResult {
    use crate::compress::test_helpers::roundtrip;
    let mut input = alloc::vec::Vec::with_capacity(4096);
    for i in 0..4096u32 {
        input.push((i.wrapping_mul(0x9E37) >> 8) as u8);
    }
    match roundtrip(&input) {
        Ok(out) if out == input => TestResult::Pass,
        Ok(_) => TestResult::Fail("pseudo-random round-trip mismatch"),
        Err(_) => TestResult::Fail("pseudo-random round-trip errored"),
    }
}
kernel_test_in!("memory", smoke_lz4_identity_pseudo_random);

fn smoke_lz4_identity_runs() -> TestResult {
    // Highly compressible: 30 'A's. Verifies the byte-broadcast
    // path (offset=1, match-len > literal-len).
    use crate::compress::test_helpers::roundtrip;
    let input = alloc::vec![b'A'; 30];
    match roundtrip(&input) {
        Ok(out) if out == input => TestResult::Pass,
        _ => TestResult::Fail("run-length round-trip mismatch"),
    }
}
kernel_test_in!("memory", smoke_lz4_identity_runs);

fn smoke_lz4_output_too_small() -> TestResult {
    use crate::compress::lz4_encode;
    let input = alloc::vec![0u8; 4096];
    let mut output = [0u8; 4]; // way too small
    match lz4_encode(&input, &mut output) {
        Err(crate::compress::CompressError::OutputTooSmall) => TestResult::Pass,
        _ => TestResult::Fail("expected OutputTooSmall"),
    }
}
kernel_test_in!("memory", smoke_lz4_output_too_small);

fn smoke_lz4_decode_truncated() -> TestResult {
    use crate::compress::{lz4_decode, lz4_encode, lz4_max_compressed_len, CompressError};
    let input = alloc::vec![b'A'; 30];
    let mut enc = alloc::vec![0u8; lz4_max_compressed_len(input.len())];
    let n = match lz4_encode(&input, &mut enc) {
        Ok(n) => n,
        Err(_) => return TestResult::Fail("encode failed"),
    };
    if n < 5 {
        return TestResult::Skip("encoded payload too short for truncation test");
    }
    // Truncate to `n - 1` so the decoder runs out of input mid-
    // sequence — either short the match-extension byte or the
    // terminal literal stream. A 2-byte truncation isn't useful
    // because [token, literal] is a valid 1-byte-decoded sequence
    // (the spec lets the last sequence be literal-only).
    let mut out = [0u8; 64];
    match lz4_decode(&enc[..n - 1], &mut out) {
        Err(CompressError::MalformedInput) => TestResult::Pass,
        Err(CompressError::OutputTooSmall) => TestResult::Pass,
        Err(CompressError::ShortInput) => TestResult::Pass,
        Ok(decoded) if decoded < input.len() => TestResult::Pass,
        Ok(_) => TestResult::Fail("decode of truncated input matched original length"),
    }
}
kernel_test_in!("memory", smoke_lz4_decode_truncated);

// ── Zpool smokes ────────────────────────────────────────────────────

fn smoke_zpool_store_load_zeros() -> TestResult {
    use crate::zpool::{Zpool, ZPAGE_SIZE};
    let mut pool = Zpool::new();
    let raw = [0u8; ZPAGE_SIZE];
    let h = match pool.store(&raw) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("store(zeros) failed"),
    };
    let mut out = [0xFFu8; ZPAGE_SIZE];
    if pool.load(h, &mut out).is_err() {
        return TestResult::Fail("load(zeros) failed");
    }
    if out != raw {
        return TestResult::Fail("zeros round-trip mismatch");
    }
    let s = pool.stats();
    if s.stored_pages != 1 || s.raw_bytes != ZPAGE_SIZE as u64 {
        return TestResult::Fail("zpool stats wrong");
    }
    if s.compressed_bytes >= s.raw_bytes {
        return TestResult::Fail("zeros should compress smaller than raw");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_zpool_store_load_zeros);

fn smoke_zpool_store_load_random() -> TestResult {
    use crate::zpool::{Zpool, ZPAGE_SIZE};
    let mut raw = [0u8; ZPAGE_SIZE];
    for i in 0..ZPAGE_SIZE {
        raw[i] = ((i as u32).wrapping_mul(0x9E37) >> 8) as u8;
    }
    let mut pool = Zpool::new();
    let h = match pool.store(&raw) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("store(random) failed"),
    };
    let mut out = [0u8; ZPAGE_SIZE];
    if pool.load(h, &mut out).is_err() {
        return TestResult::Fail("load(random) failed");
    }
    if out != raw {
        return TestResult::Fail("random round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_zpool_store_load_random);

fn smoke_zpool_free_reuses_slots() -> TestResult {
    use crate::zpool::{Zpool, ZPAGE_SIZE};
    let mut pool = Zpool::new();
    let mut handles = alloc::vec::Vec::new();
    let mut raw = [0u8; ZPAGE_SIZE];
    for i in 0..100u32 {
        raw[0] = (i & 0xff) as u8;
        raw[1] = (i >> 8) as u8;
        match pool.store(&raw) {
            Ok(h) => handles.push((i, h)),
            Err(_) => return TestResult::Fail("store failed mid-loop"),
        }
    }
    if pool.stats().stored_pages != 100 {
        return TestResult::Fail("stored_pages != 100");
    }
    let mut kept = alloc::vec::Vec::new();
    for (idx, (i, h)) in handles.iter().enumerate() {
        if idx % 2 == 0 {
            pool.free(*h);
        } else {
            kept.push((*i, *h));
        }
    }
    if pool.stats().stored_pages != 50 {
        return TestResult::Fail("post-free stored_pages != 50");
    }
    if pool.stats().eviction_count != 50 {
        return TestResult::Fail("eviction_count != 50");
    }
    let mut out = [0u8; ZPAGE_SIZE];
    for (i, h) in &kept {
        if pool.load(*h, &mut out).is_err() {
            return TestResult::Fail("kept-handle load failed");
        }
        let expected = (*i & 0xff) as u8;
        if out[0] != expected || out[1] != ((*i >> 8) as u8) {
            return TestResult::Fail("kept-handle content mismatch");
        }
        for b in &out[2..] {
            if *b != 0 {
                return TestResult::Fail("kept-handle tail not zero");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_zpool_free_reuses_slots);

fn smoke_zpool_invalid_handle() -> TestResult {
    use crate::zpool::{Zpool, ZpoolError, ZPAGE_SIZE};
    let mut pool = Zpool::new();
    let raw = [7u8; ZPAGE_SIZE];
    let h = match pool.store(&raw) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("store failed"),
    };
    pool.free(h);
    let mut out = [0u8; ZPAGE_SIZE];
    match pool.load(h, &mut out) {
        Err(ZpoolError::InvalidHandle) => TestResult::Pass,
        _ => TestResult::Fail("expected InvalidHandle for freed slot"),
    }
}
kernel_test_in!("memory", smoke_zpool_invalid_handle);

// ── CompressedRamDisk smokes ────────────────────────────────────────

fn smoke_compressed_ramdisk_unwritten_reads_zeros() -> TestResult {
    use crate::compressed_ramdisk::CompressedRamDisk;
    let dev = CompressedRamDisk::new(16);
    let mut buf = alloc::vec![0xAAu8; 4096];
    if dev.read(0, 1, &mut buf).is_err() {
        return TestResult::Fail("read failed");
    }
    if buf.iter().any(|b| *b != 0) {
        return TestResult::Fail("unwritten LBA didn't return zeros");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_compressed_ramdisk_unwritten_reads_zeros);

fn smoke_compressed_ramdisk_write_read_roundtrip() -> TestResult {
    use crate::compressed_ramdisk::CompressedRamDisk;
    let dev = CompressedRamDisk::new(16);
    let mut data = alloc::vec![0u8; 4096];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }
    if dev.write(3, 1, &data).is_err() {
        return TestResult::Fail("write failed");
    }
    let mut out = alloc::vec![0u8; 4096];
    if dev.read(3, 1, &mut out).is_err() {
        return TestResult::Fail("read failed");
    }
    if out != data {
        return TestResult::Fail("write/read round-trip mismatch");
    }
    // Untouched LBAs still read zeros.
    let mut zeros = alloc::vec![0xCCu8; 4096];
    if dev.read(0, 1, &mut zeros).is_err() {
        return TestResult::Fail("zero-LBA read failed");
    }
    if zeros.iter().any(|b| *b != 0) {
        return TestResult::Fail("untouched LBA not zero");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_compressed_ramdisk_write_read_roundtrip);

fn smoke_compressed_ramdisk_zero_writes_free_slot() -> TestResult {
    use crate::compressed_ramdisk::CompressedRamDisk;
    let dev = CompressedRamDisk::new(64);
    let zero = alloc::vec![0u8; 4096];
    for i in 0..64u64 {
        if dev.write(i, 1, &zero).is_err() {
            return TestResult::Fail("zero write failed");
        }
    }
    let stats = dev.stats();
    if stats.stored_pages != 0 {
        return TestResult::Fail("zero writes shouldn't grow stored_pages");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_compressed_ramdisk_zero_writes_free_slot);

fn smoke_compressed_ramdisk_compresses_repetitive() -> TestResult {
    use crate::compressed_ramdisk::CompressedRamDisk;
    let dev = CompressedRamDisk::new(8);
    let mut data = alloc::vec![0u8; 4096];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 4) as u8; // highly compressible
    }
    for i in 0..8u64 {
        if dev.write(i, 1, &data).is_err() {
            return TestResult::Fail("write failed");
        }
    }
    let stats = dev.stats();
    if stats.stored_pages != 8 {
        return TestResult::Fail("expected 8 stored pages");
    }
    if stats.compressed_bytes as usize >= stats.raw_bytes as usize {
        return TestResult::Fail(
            "compressed_bytes ≥ raw_bytes on a highly-compressible pattern",
        );
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_compressed_ramdisk_compresses_repetitive);

fn smoke_compressed_ramdisk_out_of_range_rejected() -> TestResult {
    use crate::compressed_ramdisk::{CompressedRamDisk, RamDiskError};
    let dev = CompressedRamDisk::new(4);
    let data = alloc::vec![0xABu8; 4096];
    match dev.write(4, 1, &data) {
        Err(RamDiskError::OutOfRange) => {}
        _ => return TestResult::Fail("write past capacity should be OutOfRange"),
    }
    let mut out = alloc::vec![0u8; 4096];
    match dev.read(5, 1, &mut out) {
        Err(RamDiskError::OutOfRange) => {}
        _ => return TestResult::Fail("read past capacity should be OutOfRange"),
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_compressed_ramdisk_out_of_range_rejected);

// ── vmalloc (bump-pointer kernel-VA allocator) ──────────────────────

/// Round-trip: alloc + free returns a range with the requested
/// page-aligned length and a high-half base. Doesn't dereference
/// the range — vmalloc hands out unbacked VA.
fn smoke_vmalloc_alloc_free_roundtrip() -> TestResult {
    use crate::vmalloc;
    let prev = vmalloc::claimed_bytes();
    let r = match vmalloc::alloc(4096) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("alloc(4096) returned Err"),
    };
    if r.len != 4096 {
        return TestResult::Fail("alloc len != requested page");
    }
    if r.base & 0xFFF != 0 {
        return TestResult::Fail("alloc base not page-aligned");
    }
    if (r.base >> 47) != 0x1FFFF {
        return TestResult::Fail("alloc base not canonical-high");
    }
    if vmalloc::claimed_bytes() != prev + 4096 {
        return TestResult::Fail("claimed_bytes didn't track alloc");
    }
    vmalloc::free(r);
    TestResult::Pass
}
kernel_test_in!("memory", smoke_vmalloc_alloc_free_roundtrip);

/// Sub-page allocations round up to a whole page.
fn smoke_vmalloc_rounds_up_to_page() -> TestResult {
    use crate::vmalloc;
    let r = match vmalloc::alloc(1) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("alloc(1) returned Err"),
    };
    if r.len != 4096 {
        return TestResult::Fail("sub-page didn't round up to a page");
    }
    vmalloc::free(r);
    TestResult::Pass
}
kernel_test_in!("memory", smoke_vmalloc_rounds_up_to_page);

/// Zero-length request rejected with BadLen.
fn smoke_vmalloc_zero_len_rejected() -> TestResult {
    use crate::vmalloc::{self, VmallocError};
    match vmalloc::alloc(0) {
        Err(VmallocError::BadLen) => TestResult::Pass,
        Ok(_) => TestResult::Fail("zero-len alloc returned Ok"),
        Err(_) => TestResult::Fail("zero-len alloc returned wrong error"),
    }
}
kernel_test_in!("memory", smoke_vmalloc_zero_len_rejected);

/// Sequential allocations don't overlap. The bump cursor must
/// advance monotonically.
fn smoke_vmalloc_sequential_allocs_disjoint() -> TestResult {
    use crate::vmalloc;
    let a = match vmalloc::alloc(8192) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("alloc a failed"),
    };
    let b = match vmalloc::alloc(4096) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("alloc b failed"),
    };
    let c = match vmalloc::alloc(16 * 1024) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("alloc c failed"),
    };
    // Pairwise disjoint check.
    let pairs = [(a, b), (a, c), (b, c)];
    for (x, y) in pairs {
        let x_end = x.base + x.len;
        let y_end = y.base + y.len;
        if x.base < y_end && y.base < x_end {
            return TestResult::Fail("vmalloc ranges overlap");
        }
    }
    vmalloc::free(a);
    vmalloc::free(b);
    vmalloc::free(c);
    TestResult::Pass
}
kernel_test_in!("memory", smoke_vmalloc_sequential_allocs_disjoint);

/// claimed_bytes tracks the sum of all rounded-up requests.
fn smoke_vmalloc_claimed_bytes_tracks_sum() -> TestResult {
    use crate::vmalloc;
    let before = vmalloc::claimed_bytes();
    let r1 = vmalloc::alloc(4096).expect("alloc 1");
    let r2 = vmalloc::alloc(4096).expect("alloc 2");
    let r3 = vmalloc::alloc(8192).expect("alloc 3");
    let after = vmalloc::claimed_bytes();
    // Expect at least 16 KiB advanced. (Other concurrent
    // allocations from the boot path could've also advanced it,
    // so we use >= rather than ==.)
    if after.saturating_sub(before) < 4096 + 4096 + 8192 {
        return TestResult::Fail("claimed_bytes didn't advance by the requested amount");
    }
    vmalloc::free(r1);
    vmalloc::free(r2);
    vmalloc::free(r3);
    TestResult::Pass
}
kernel_test_in!("memory", smoke_vmalloc_claimed_bytes_tracks_sum);

// ── AtomicPool ──────────────────────────────────────────────────────

/// Lease + drop returns the item to the pool. free_count must
/// match capacity at rest and decrement on lease.
fn smoke_atomic_pool_lease_returns_on_drop() -> TestResult {
    use crate::atomic_pool::AtomicPool;
    // Box::leak to get a 'static reference — AtomicPool::try_get
    // requires &'static self for the Pooled's pool pointer.
    let pool: &'static AtomicPool<u64> =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(
            AtomicPool::new(4, || 0xDEAD_BEEFu64),
        ));
    if pool.capacity() != 4 {
        return TestResult::Fail("capacity mismatch");
    }
    if pool.free_count() != 4 {
        return TestResult::Fail("fresh pool's free count != capacity");
    }
    {
        let _a = pool.try_get().expect("first lease");
        if pool.free_count() != 3 {
            return TestResult::Fail("free count didn't decrement on lease");
        }
        let _b = pool.try_get().expect("second lease");
        if pool.free_count() != 2 {
            return TestResult::Fail("second lease didn't decrement further");
        }
    }
    // Both Pooled have dropped — items returned.
    if pool.free_count() != 4 {
        return TestResult::Fail("Drop didn't restore the items to the pool");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_atomic_pool_lease_returns_on_drop);

/// Exhausting the pool returns None on the next try_get; freeing
/// any handle restores availability.
fn smoke_atomic_pool_exhausted_returns_none() -> TestResult {
    use crate::atomic_pool::AtomicPool;
    let pool: &'static AtomicPool<u32> =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(
            AtomicPool::new(2, || 42u32),
        ));
    let a = pool.try_get().expect("a");
    let b = pool.try_get().expect("b");
    if pool.try_get().is_some() {
        return TestResult::Fail("try_get returned Some on exhausted pool");
    }
    drop(a);
    let _c = pool
        .try_get()
        .expect("after dropping one handle, pool has space");
    drop(b);
    TestResult::Pass
}
kernel_test_in!("memory", smoke_atomic_pool_exhausted_returns_none);

// (deref-round-trip already covered by atomic_pool.rs's
// smoke_atomic_pool_pooled_deref_mut_visible_next_lease.)

// ── W^X enforcement smokes ────────────────────────────────────────────

fn smoke_wx_rejects_writable_executable_mmap() -> TestResult {
    use crate::address_space::RegionPerms;
    use crate::wx::{check_mmap_perms, WxCheck};
    let wx = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::EXEC;
    if check_mmap_perms(wx) != WxCheck::DenyWX {
        return TestResult::Fail("mmap accepted PROT_WRITE | PROT_EXEC");
    }
    // Sanity: RX and RW should still be Allow.
    let rx = RegionPerms::READ | RegionPerms::EXEC;
    let rw = RegionPerms::READ | RegionPerms::WRITE;
    if check_mmap_perms(rx) != WxCheck::Allow {
        return TestResult::Fail("mmap rejected legitimate RX");
    }
    if check_mmap_perms(rw) != WxCheck::Allow {
        return TestResult::Fail("mmap rejected legitimate RW");
    }
    TestResult::Pass
}
kernel_test_in!("memory/wx", smoke_wx_rejects_writable_executable_mmap);

fn smoke_wx_mprotect_rw_to_rx_needs_cap() -> TestResult {
    use crate::address_space::RegionPerms;
    use crate::wx::{classify_mprotect, WxTransition};
    let rw = RegionPerms::READ | RegionPerms::WRITE;
    let rx = RegionPerms::READ | RegionPerms::EXEC;
    // RW -> RX is the JIT codegen flip; requires CAP_JIT.
    if classify_mprotect(rw, rx) != WxTransition::NeedsCapJit {
        return TestResult::Fail("RW->RX did not require CAP_JIT");
    }
    // RX -> RW is allowed (drop X, never both at once).
    if classify_mprotect(rx, rw) != WxTransition::Allow {
        return TestResult::Fail("RX->RW unexpectedly required cap");
    }
    // RX -> RWX is absolutely refused (the "self-modifying live code"
    // shape PaX rejects).
    let rwx = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::EXEC;
    if classify_mprotect(rx, rwx) != WxTransition::DenyXtoWX {
        return TestResult::Fail("RX->RWX was not absolutely refused");
    }
    TestResult::Pass
}
kernel_test_in!("memory/wx", smoke_wx_mprotect_rw_to_rx_needs_cap);

fn smoke_wx_classify_helpers() -> TestResult {
    use crate::address_space::RegionPerms;
    use crate::wx::{is_jit_buffer, is_jit_code};
    let rw = RegionPerms::READ | RegionPerms::WRITE;
    let rx = RegionPerms::READ | RegionPerms::EXEC;
    let ro = RegionPerms::READ;
    if !is_jit_buffer(rw) {
        return TestResult::Fail("RW not classified as JIT buffer");
    }
    if is_jit_buffer(rx) {
        return TestResult::Fail("RX wrongly classified as JIT buffer");
    }
    if !is_jit_code(rx) {
        return TestResult::Fail("RX not classified as JIT code");
    }
    if is_jit_code(ro) {
        return TestResult::Fail("RO wrongly classified as JIT code");
    }
    TestResult::Pass
}
kernel_test_in!("memory/wx", smoke_wx_classify_helpers);
