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
        Some(_)  => TestResult::Fail("wrong vector caught (not #PF)"),
        None     => TestResult::Fail("probe didn't catch the expected #PF"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_probe_catches_page_fault);

#[cfg(target_arch = "x86_64")]
fn smoke_nx_enforces_no_exec() -> TestResult {
    // Map a page NO_EXEC, attempt to execute from it, verify the
    // resulting #PF has the instruction-fetch bit (bit 4) set.
    use core::arch::asm;
    use narf_arch::x86_64::{probe, Features};
    use crate::{alloc_frame, FrameAllocError, free_frame, VirtAddr};
    use crate::paging::{map_4kb, unmap_4kb, read_cr3, PtFlags};

    // SAFETY: CPUID always legal.
    let feats = unsafe { Features::probe() };
    if !feats.nx {
        return TestResult::Skip("NX not exposed");
    }

    let pml4 = unsafe { read_cr3() };
    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) =>
            return TestResult::Skip("frame allocator not initialised"),
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
        None     => return TestResult::Fail("NX didn't fault on NO_EXEC jump"),
        Some(14) => {}
        Some(_)  => return TestResult::Fail("wrong vector caught (not #PF)"),
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
    use core::arch::asm;
    use narf_arch::x86_64::{probe, pks::{self, DomainRights}, Features};
    use crate::{alloc_frame, FrameAllocError, free_frame, VirtAddr};
    use crate::paging::{map_4kb, unmap_4kb, read_cr3, PtFlags};

    // SAFETY: CPUID always legal.
    let feats = unsafe { Features::probe() };
    if !feats.pks {
        return TestResult::Skip("PKS not exposed");
    }

    // SAFETY: allocator is up, read_cr3 is always safe.
    let pml4 = unsafe { read_cr3() };
    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) =>
            return TestResult::Skip("frame allocator not initialised"),
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
    unsafe { pks::set_rights(9, DomainRights::DENY_ALL); }

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
    unsafe { pks::restore(saved_pkrs); }

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
    use narf_arch::x86_64::pks::{save, restore, get_rights, set_rights, DomainRights};
    // SAFETY: feats.pks==true.
    let saved = unsafe { save() };
    unsafe {
        set_rights(3, DomainRights::READ_ONLY);
        set_rights(7, DomainRights::DENY_ALL);
    }
    let r3 = unsafe { get_rights(3) };
    let r7 = unsafe { get_rights(7) };
    unsafe { restore(saved); }
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
    use narf_arch::x86_64::pcid;
    use narf_arch::x86_64::cr;

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
    unsafe { pcid::exit_domain(scope); }
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
    use narf_arch::x86_64::pcid;
    use crate::domain;

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
            if inspector == target { continue; }
            match domain::cross_domain_slot_present(inspector, target) {
                Some(true)  => return TestResult::Fail("cross-domain slot leaked"),
                Some(false) => {}
                None        => return TestResult::Fail("PML4 not registered"),
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
            None    => return TestResult::Fail("domain_va_base returned None for valid id"),
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
    unsafe { wrmsr(IA32_PKRS, test_value); }
    let got = unsafe { rdmsr(IA32_PKRS) };
    unsafe { wrmsr(IA32_PKRS, saved); }
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
        Err(FrameAllocError::Uninitialised) =>
            return TestResult::Skip("frame allocator not initialised"),
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
        None    => return TestResult::Fail("flags_at returned None"),
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
    use crate::paging::{map_4kb, unmap_4kb, translate, PageTable, PtFlags};
    use crate::{alloc_frame, FrameAllocError, PhysAddr, VirtAddr};

    let pml4 = match alloc_frame() {
        Ok(f) => f.start_address(),
        Err(FrameAllocError::Uninitialised) =>
            return TestResult::Skip("frame allocator not initialised"),
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

fn smoke_domain_primitive_trait() -> TestResult {
    // Trait-level dispatch through `arch::Domain::*`.
    use narf_arch::{DomainPrimitive, DomainBackend};

    let expected = if cfg!(target_arch = "x86_64") { DomainBackend::Pks }
                   else if cfg!(target_arch = "aarch64") { DomainBackend::Mte }
                   else { return TestResult::Skip("unknown arch") };
    if <narf_arch::Domain as DomainPrimitive>::BACKEND != expected {
        return TestResult::Fail("DomainPrimitive::BACKEND wrong");
    }

    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: legal MRS/MSR sequence at EL1.
        unsafe {
            let saved0 = <narf_arch::Domain as DomainPrimitive>::save();
            let inner  = <narf_arch::Domain as DomainPrimitive>::enter_domain(0, 9);
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
    use core::arch::asm;
    use narf_arch::x86_64::{probe, pks::{self, SavedPkrs}, Features};
    use narf_lib::id::DomainId;
    use crate::{alloc_frame, FrameAllocError, free_frame, VirtAddr};
    use crate::paging::{map_4kb, unmap_4kb, read_cr3, PtFlags};

    // SAFETY: CPUID always legal.
    let feats = unsafe { Features::probe() };
    if !feats.pks { return TestResult::Skip("PKS not exposed"); }

    let pml4 = unsafe { read_cr3() };
    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) =>
            return TestResult::Skip("frame allocator not initialised"),
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    let virt = VirtAddr::new(0x4_0000_1000);
    let phys = frame.start_address();
    let driver_pk = DomainId::DRIVER_0.raw(); // 9

    // SAFETY: live PML4.
    if unsafe {
        map_4kb(pml4, virt, phys,
                PtFlags::WRITABLE | PtFlags::pk(driver_pk))
    }.is_err() {
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
    unsafe { pks::exit_domain(scope1); }

    let scope2 = unsafe { pks::enter_domain(DomainId::FRAME.raw(),
                                             DomainId::DRIVER_1.raw()) };
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
    unsafe { pks::exit_domain(scope2); }

    // SAFETY: restore of the previously-saved state.
    unsafe { pks::restore(outermost_saved); }
    let _ = unsafe { unmap_4kb(pml4, virt) };
    free_frame(frame);

    match caught.vector {
        None => return TestResult::Fail("Step 3 write succeeded — domain enforcement failed"),
        Some(14) => {}
        Some(_)  => return TestResult::Fail("wrong vector (not #PF)"),
    }
    if caught.error_code & (1 << 5) == 0 {
        return TestResult::Fail("#PF caught but PK bit (5) not set — not domain fault");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_domain_switch);
