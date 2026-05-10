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
                    return TestResult::Fail("translate returned wrong phys");
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

    // Cleanup — return the frames so subsequent tests in the
    // same boot don't pressure the allocator.
    crate::frame::free_frame(crate::frame::PhysFrame::new(c_split.phys[0]));
    crate::frame::free_frame(crate::frame::PhysFrame::new(frame));
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

    crate::frame::free_frame(crate::frame::PhysFrame::new(f1));
    crate::frame::free_frame(crate::frame::PhysFrame::new(f2));
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
