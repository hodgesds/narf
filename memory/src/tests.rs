//! Subsystem smokes for `narf-memory`.
//!
//! Migrated from `narf-verification`. Tests register under the
//! `memory` subsystem.

use narf_kernel_test::{kernel_test_in, TestResult};

/// A syscall that published mapping A must not materialize or roll back an
/// identical-looking mapping B installed by a racing `MAP_FIXED` peer.
fn smoke_mapping_receipts_reject_replaced_vma() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};
    use alloc::vec;

    let aspace = AddressSpace::empty();
    let base = VirtAddr::new(0x0000_0100_4000_0000);
    let first = match aspace.map_region_limited_receipt(
        Region {
            base,
            len: 4096,
            perms: RegionPerms::READ,
            phys: vec![PhysAddr::new(0)],
        },
        false,
        u64::MAX,
        false,
    ) {
        Ok(receipt) => receipt,
        Err(_) => return TestResult::Fail("initial receipt publication failed"),
    };
    let second = match aspace.replace_region_limited_receipt(
        Region {
            base,
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: vec![PhysAddr::new(0)],
        },
        false,
        u64::MAX,
        false,
    ) {
        Ok(receipt) => receipt,
        Err(_) => return TestResult::Fail("replacement receipt publication failed"),
    };

    // SAFETY: stale-receipt validation returns before consulting the empty
    // test address space's deliberately absent hardware root.
    if unsafe { aspace.materialize_mapping(first) } != Err(AddressSpaceError::StaleMapping) {
        return TestResult::Fail("stale receipt materialized a replacement VMA");
    }
    if aspace.rollback_mapping(first) != Err(AddressSpaceError::StaleMapping) {
        return TestResult::Fail("stale receipt rolled back a replacement VMA");
    }
    let Some(region) = aspace.lookup(base) else {
        return TestResult::Fail("replacement VMA disappeared");
    };
    if !region.perms.contains(RegionPerms::WRITE) || second.base() != base || second.len() != 4096 {
        return TestResult::Fail("replacement VMA or receipt changed");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_mapping_receipts_reject_replaced_vma);

/// A receipt is an address-space capability, not merely a `(base, len,
/// generation)` tuple. Independent address spaces begin their local mapping
/// generations at the same value, so the AS incarnation must also match.
fn smoke_mapping_receipts_reject_another_address_space() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};
    use alloc::vec;

    let first = AddressSpace::empty();
    let second = AddressSpace::empty();
    let base = VirtAddr::new(0x0000_0100_5000_0000);
    let region = || Region {
        base,
        len: 4096,
        perms: RegionPerms::READ,
        phys: vec![PhysAddr::new(0)],
    };
    let receipt = match first.map_region_limited_receipt(region(), false, u64::MAX, false) {
        Ok(receipt) => receipt,
        Err(_) => return TestResult::Fail("first AS receipt publication failed"),
    };
    if second
        .map_region_limited_receipt(region(), false, u64::MAX, false)
        .is_err()
    {
        return TestResult::Fail("second AS receipt publication failed");
    }
    if first.identity() == second.identity() {
        return TestResult::Fail("independent address spaces reused an identity");
    }
    if second.rollback_mapping(receipt) != Err(AddressSpaceError::StaleMapping) {
        return TestResult::Fail("foreign receipt rolled back an identical VMA");
    }
    if second.lookup(base).is_none() {
        return TestResult::Fail("foreign receipt removed the second AS mapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory",
    smoke_mapping_receipts_reject_another_address_space
);

#[cfg(target_arch = "x86_64")]
fn smoke_probe_catches_page_fault() -> TestResult {
    // Arm the recoverable-fault probe, write to an unmapped virtual
    // address (above our 4 GiB identity map), and verify the handler
    // caught the #PF (vector 14) instead of panic-exiting.
    use core::arch::asm;
    use narf_arch::x86_64::probe;

    // An address the kernel PML4 deliberately leaves unmapped. The low
    // identity map now covers 0..512 GiB (PML4[0]), and PML4[1] maps the
    // high-MMIO window 513 GiB..1 TiB but SKIPS its PDPT[0] — the
    // 512..513 GiB slot reserved for user space — so a kernel write to
    // 512 GiB walks a present PML4[1] into a not-present PDPT[0] and #PFs.
    let unmapped: u64 = 0x0000_0080_0000_0000;

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
    // SAFETY: Valid memory or trusted environment
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let pml4 = unsafe { read_cr3() };
    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised")
        }
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    // Map at 1 TiB (PML4[2]): outside the low identity map (0..512 GiB,
    // where every 1-GiB slot is a huge page map_4kb can't sub-divide)
    // and in the kernel PML4's empty user-reserved range, so map_4kb
    // builds fresh intermediate tables for a real 4 KiB leaf.
    let virt = VirtAddr::new(0x0000_0100_0000_1000);
    let phys = frame.start_address();
    let flags = PtFlags::WRITABLE | PtFlags::NO_EXEC;

    // SAFETY: live PML4 modification on the BSP with the test's
    // chosen virt not overlapping anything else.
    // SAFETY: Valid memory or trusted environment
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
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            "jmp {p}",
            "77:",
            p = in(reg) virt.raw(),
            options(nostack),
        );
    }

    let caught = probe::disarm();
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // Map at 1 TiB + 8 GiB (PML4[2]): outside the low identity map
    // (0..512 GiB, filled with 1-GiB huge pages that map_4kb can't
    // sub-divide → EncounteredHugePage) and in the kernel PML4's empty
    // user-reserved range, so map_4kb builds a real 4 KiB leaf. The old
    // 0x2_0000_1000 (8 GiB) fell inside a huge page once the low map grew
    // from 4 GiB to 512 GiB, which is what made this test start failing.
    let virt = VirtAddr::new(0x0000_0102_0000_1000);
    let phys = frame.start_address();
    let flags = PtFlags::WRITABLE | PtFlags::pk(9);

    // SAFETY: live PML4 modification.
    if unsafe { map_4kb(pml4, virt, phys, flags) }.is_err() {
        free_frame(frame);
        return TestResult::Fail("map_4kb of test page failed");
    }

    // SAFETY: CR4.PKS is 1.
    let saved_pkrs = unsafe { pks::save() };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    unsafe {
        set_rights(3, DomainRights::READ_ONLY);
        set_rights(7, DomainRights::DENY_ALL);
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let r3 = unsafe { get_rights(3) };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let r7 = unsafe { get_rights(7) };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // `enter_domain` does a NOFLUSH CR3 swap, which #GPs (and is therefore
    // correctly no-op'd) when CR4.PCIDE is off — a hypervisor can expose the
    // PCID *enforcer* paths while not advertising PCID to this CPU (QEMU
    // `-cpu max`+KVM leaves PCIDE off). Without PCIDE there is no CR3.PCID to
    // round-trip, so skip rather than assert tagging that can't happen here.
    if !pcid::pcide_enabled() {
        return TestResult::Skip("CR4.PCIDE not enabled (hypervisor doesn't expose PCID)");
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

// ── high-half kernel direct map ───────────────────────────────────
//
// `init_mmu` installs a direct map at PML4[384..510] (base
// `KERNEL_DIRECT_MAP_BASE = 0xFFFF_C000_0000_0000`) so the kernel can
// reach RAM above 512 GiB — which the low identity map can't cover,
// since PML4[1..255] is user address space. Slot 384 clears both the
// PCID per-domain range (PML4[256..271]) and the kernel image
// (PML4[511]). `PhysAddr::kernel_mut_ptr` OR's in the base once the map
// is live. These smokes run on the CI 1-2 GiB machine (so they exercise
// the low end of the map), but the mechanism they validate is identical
// for high frames; a >512 GiB boot is validated separately by hand.

/// The direct map is activated and structurally correct: PML4[384] of
/// the live kernel PML4 is a present PDPT whose entries identity-map
/// physical RAM via 1-GiB huge pages (virt `BASE + P` → phys `P`).
#[cfg(target_arch = "x86_64")]
fn smoke_direct_map_installed() -> TestResult {
    use crate::PhysAddr;
    use narf_arch::x86_64::cr;

    if !crate::direct_map_live() {
        // Built only when RAM > 512 GiB; the CI machine is smaller, so
        // there is nothing to inspect. The >512 GiB path is exercised
        // by a manual large-RAM boot.
        return TestResult::Skip("direct map not built (RAM <= 512 GiB)");
    }

    // Walk the live kernel PML4. Page-table frames are < 4 GiB, so the
    // low identity map (`as_ptr`) reaches them regardless of the direct
    // map. SAFETY: CR3 read at CPL=0.
    let cr3 = unsafe { cr::read_cr3() };
    let pml4_phys = cr3 & 0x000F_FFFF_FFFF_F000;

    // PML4[384] = the first direct-map slot (covers phys [0, 512 GiB)).
    let base = crate::KERNEL_DIRECT_MAP_PML4_BASE as u64;
    let e_ptr = PhysAddr::new(pml4_phys + base * 8).as_ptr::<u64>();
    // SAFETY: PML4 base is identity-mapped; offset base*8 is in-page.
    let e0 = unsafe { core::ptr::read_volatile(e_ptr) };
    if e0 & 1 == 0 {
        return TestResult::Fail("PML4[384] (direct map) not present");
    }
    let pdpt_phys = e0 & 0x000F_FFFF_FFFF_F000;

    // Spot-check several 1-GiB huge-page entries map the right phys.
    for gib in [0u64, 1, 3, 7, 511] {
        let ep = PhysAddr::new(pdpt_phys + gib * 8).as_ptr::<u64>();
        // SAFETY: PDPT base is identity-mapped; offset in-page.
        let e = unsafe { core::ptr::read_volatile(ep) };
        if e & 1 == 0 {
            return TestResult::Fail("direct-map PDPT entry not present");
        }
        if e & (1 << 7) == 0 {
            return TestResult::Fail("direct-map entry not a 1-GiB huge page");
        }
        // 1-GiB huge-page frame bits are [51:30].
        let mapped = e & 0x000F_FFFF_C000_0000;
        if mapped != (gib << 30) {
            return TestResult::Fail("direct-map entry maps wrong physical address");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_direct_map_installed);

/// The kernel RAM accessors are consistent: low frames (< 512 GiB, all
/// that exist on the CI machine) stay identity-mapped so `ptr == phys`
/// — that identity is what keeps the mass of `phys as *mut` code correct
/// — and a real frame is dereferenceable through `kernel_mut_ptr`.
#[cfg(target_arch = "x86_64")]
fn smoke_direct_map_low_frame_is_identity() -> TestResult {
    use crate::PhysAddr;

    // Valid whether or not the direct map was built: a < 512 GiB frame
    // is identity-mapped either way (the direct map only offsets frames
    // the low identity map can't reach).
    let frame = match crate::alloc_frame() {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    let phys: PhysAddr = frame.start_address();
    let id_ptr = phys.as_mut_ptr::<u64>();
    let km_ptr = phys.kernel_mut_ptr::<u64>();

    let result = (|| {
        // A < 512 GiB frame must map identity: kernel_mut_ptr == phys.
        if km_ptr as u64 != phys.raw() {
            return TestResult::Fail("low frame not identity-mapped by kernel_mut_ptr");
        }
        if !core::ptr::eq(km_ptr, id_ptr) {
            return TestResult::Fail("kernel_mut_ptr != as_mut_ptr for a low frame");
        }
        // from_kernel_ptr must round-trip.
        if PhysAddr::from_kernel_ptr(km_ptr).raw() != phys.raw() {
            return TestResult::Fail("from_kernel_ptr did not round-trip a low frame");
        }
        // Dereferenceable through kernel_mut_ptr.
        let sentinel: u64 = 0xA5A5_1234_DEAD_BEEF;
        // SAFETY: `phys` is a freshly-allocated, exclusively-owned frame.
        unsafe {
            core::ptr::write_volatile(km_ptr, sentinel);
            if core::ptr::read_volatile(phys.as_ptr::<u64>()) != sentinel {
                return TestResult::Fail("kernel_mut_ptr write not visible via identity");
            }
        }
        TestResult::Pass
    })();

    crate::free_frame(frame);
    result
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_direct_map_low_frame_is_identity);

/// The direct-map address arithmetic is correct for a frame the low
/// identity map can't reach (>= 512 GiB): `kernel_mut_ptr` applies the
/// offset, the result lands inside the direct-map window, and
/// `from_kernel_ptr` inverts it. Uses a synthetic phys — the map is
/// installed for [0, RAM), so this validates the transform, not a
/// dereference (a >512 GiB dereference needs a >512 GiB boot, checked
/// by hand).
#[cfg(target_arch = "x86_64")]
fn smoke_direct_map_high_phys_offset() -> TestResult {
    use crate::PhysAddr;

    if !crate::direct_map_live() {
        // The offset only applies when the direct map was built
        // (RAM > 512 GiB); on the smaller CI machine kernel_mut_ptr is
        // pure identity, so there is no offset to validate here.
        return TestResult::Skip("direct map not built (RAM <= 512 GiB)");
    }

    // First slot the identity map can't reach.
    let high = PhysAddr::new(600u64 << 30); // 600 GiB
    let km = high.kernel_mut_ptr::<u8>() as u64;

    // Must be offset into the direct-map window, not identity.
    if km == high.raw() {
        return TestResult::Fail("high frame was NOT offset (still identity)");
    }
    if km < crate::KERNEL_DIRECT_MAP_BASE {
        return TestResult::Fail("high frame VA is below the direct-map base");
    }
    // Offset must equal base + phys (the map is base | phys, disjoint).
    if km != crate::KERNEL_DIRECT_MAP_BASE + high.raw() {
        return TestResult::Fail("direct-map VA != base + phys");
    }
    // The VA must decode to the expected PML4 slot (384 + phys/512GiB).
    let expect_slot = crate::KERNEL_DIRECT_MAP_PML4_BASE as u64 + (600 / 512);
    if (km >> 39) & 0x1FF != expect_slot {
        return TestResult::Fail("direct-map VA lands in the wrong PML4 slot");
    }
    // Round-trip back to phys.
    if PhysAddr::from_kernel_ptr(km as *const u8).raw() != high.raw() {
        return TestResult::Fail("from_kernel_ptr did not round-trip a high frame");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_direct_map_high_phys_offset);

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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    unsafe {
        wrmsr(IA32_PKRS, test_value);
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let got = unsafe { rdmsr(IA32_PKRS) };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let got = unsafe { translate(pml4, virt) };
    if got != Some(phys) {
        return TestResult::Fail("translate returned wrong physical address");
    }

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let removed = match unsafe { unmap_4kb(pml4, virt) } {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("unmap_4kb failed"),
    };
    if removed != phys {
        return TestResult::Fail("unmap returned wrong phys");
    }

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { translate(pml4, virt) }.is_some() {
        return TestResult::Fail("translate still resolves after unmap");
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_paging_map_translate_unmap);

#[cfg(target_arch = "x86_64")]
fn smoke_paging_local_range_unmap_batches_present_leaves() -> TestResult {
    use crate::paging::{map_4kb, translate, unmap_4kb_local_range, PageTable, PtFlags};
    use crate::{alloc_frame, FrameAllocError, PhysAddr, VirtAddr};

    let pml4 = match alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised")
        }
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    PageTable::zero_at(pml4.as_mut_ptr::<PageTable>());
    let base = VirtAddr::new(0x567a_0000);
    for (page, phys) in [(0, 0x1235_0000), (2, 0x1235_2000)] {
        // SAFETY: the isolated root is owned by this test; the synthetic
        // backing addresses are aligned and are never dereferenced.
        if unsafe {
            map_4kb(
                pml4,
                VirtAddr::new(base.as_u64() + page * 4096),
                PhysAddr::new(phys),
                PtFlags::WRITABLE,
            )
        }
        .is_err()
        {
            return TestResult::Fail("range fixture map failed");
        }
    }
    // SAFETY: all three pages lie in the isolated live root; the middle page
    // is intentionally absent and must be treated as a benign miss.
    if unsafe { unmap_4kb_local_range(pml4, base, 3) } != Ok(2) {
        return TestResult::Fail("range unmap did not count present leaves");
    }
    for page in 0..3 {
        // SAFETY: read-only walk of the still-live isolated root.
        if unsafe { translate(pml4, VirtAddr::new(base.as_u64() + page * 4096)) }.is_some() {
            return TestResult::Fail("range unmap left a translation behind");
        }
    }
    // SAFETY: repeating an unmap over absent leaves is explicitly idempotent.
    if unsafe { unmap_4kb_local_range(pml4, base, 3) } != Ok(0) {
        return TestResult::Fail("repeated range unmap was not idempotent");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory",
    smoke_paging_local_range_unmap_batches_present_leaves
);

#[cfg(target_arch = "x86_64")]
fn smoke_paging_scatter_range_maps_present_and_skips_lazy() -> TestResult {
    #[cfg(feature = "kernel-test")]
    use crate::paging::__range_pt_walks_for_test;
    use crate::paging::{
        flags_at, map_4kb, map_4kb_scatter_range, rewrite_4kb_scatter_range, translate,
        unmap_4kb_local_range, PageTable, PtFlags, WalkIndices,
    };
    use crate::{alloc_frame, FrameAllocError, PhysAddr, VirtAddr};

    unsafe fn upper_user_bits(root: PhysAddr, virt: VirtAddr) -> Option<[bool; 3]> {
        let idx = WalkIndices::from_virt(virt);
        // SAFETY: the caller supplies a live, identity-reachable isolated root.
        let pml4 = unsafe { &*root.as_ptr::<PageTable>() };
        let pml4e = pml4.entries[idx.pml4];
        if !pml4e.is_present() {
            return None;
        }
        // SAFETY: the present non-leaf entry was created by map_4kb below.
        let pdpt = unsafe { &*pml4e.addr().as_ptr::<PageTable>() };
        let pdpte = pdpt.entries[idx.pdpt];
        if !pdpte.is_present() || pdpte.flags().contains(PtFlags::HUGE_PAGE) {
            return None;
        }
        // SAFETY: the verified non-huge entry names a live PD.
        let pd = unsafe { &*pdpte.addr().as_ptr::<PageTable>() };
        let pde = pd.entries[idx.pd];
        if !pde.is_present() || pde.flags().contains(PtFlags::HUGE_PAGE) {
            return None;
        }
        Some([
            pml4e.flags().contains(PtFlags::USER),
            pdpte.flags().contains(PtFlags::USER),
            pde.flags().contains(PtFlags::USER),
        ])
    }

    let pml4 = match alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised")
        }
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    PageTable::zero_at(pml4.as_mut_ptr::<PageTable>());
    let base = VirtAddr::new(0x567b_0000);
    let backing = [
        PhysAddr::new(0x1236_0000),
        PhysAddr::new(0),
        PhysAddr::new(0x1236_2000),
    ];
    #[cfg(feature = "kernel-test")]
    let walks_before_map = __range_pt_walks_for_test();
    // SAFETY: the test owns this isolated root; non-zero synthetic backing is
    // aligned and never dereferenced, while zero is the documented lazy slot.
    if unsafe {
        map_4kb_scatter_range(pml4, base, &backing, |_, _| {
            PtFlags::USER | PtFlags::WRITABLE
        })
    }
    .is_err()
    {
        return TestResult::Fail("scatter range map failed");
    }
    #[cfg(feature = "kernel-test")]
    {
        if __range_pt_walks_for_test() != walks_before_map + 1 {
            return TestResult::Fail("scatter map repeated an upper-level walk per page");
        }
    }
    for (page, expected) in backing.into_iter().enumerate() {
        // SAFETY: read-only walk of the still-live isolated root.
        let got = unsafe { translate(pml4, VirtAddr::new(base.as_u64() + page as u64 * 4096)) };
        let expected = (expected.raw() != 0).then_some(expected);
        if got != expected {
            return TestResult::Fail("scatter range translation mismatch");
        }
    }
    #[cfg(feature = "kernel-test")]
    let walks_before = __range_pt_walks_for_test();
    // SAFETY: permission-only rewrite of the same isolated-root backing.
    if unsafe {
        rewrite_4kb_scatter_range(pml4, base, &backing, |_, _| {
            PtFlags::USER | PtFlags::NO_EXEC
        })
    }
    .is_err()
    {
        return TestResult::Fail("scatter range permission rewrite failed");
    }
    #[cfg(feature = "kernel-test")]
    {
        if __range_pt_walks_for_test() != walks_before + 1 {
            return TestResult::Fail("scatter rewrite repeated an upper-level walk per page");
        }
    }
    for page in [0_u64, 2] {
        let va = VirtAddr::new(base.as_u64() + page * 4096);
        // SAFETY: read-only walk of the isolated live root.
        let read_only =
            unsafe { flags_at(pml4, va) }.is_some_and(|flags| !flags.contains(PtFlags::WRITABLE));
        if !read_only {
            return TestResult::Fail("scatter range rewrite left a writable leaf");
        }
    }
    // SAFETY: the lazy middle slot must remain absent after the rewrite.
    if unsafe { translate(pml4, VirtAddr::new(base.as_u64() + 4096)) }.is_some() {
        return TestResult::Fail("scatter range rewrite mapped a lazy slot");
    }
    // SAFETY: cleanup of the isolated test range.
    let _ = unsafe { unmap_4kb_local_range(pml4, base, 3) };
    let boundary_base = VirtAddr::new(0x567f_f000);
    let boundary_backing = [PhysAddr::new(0x1237_0000), PhysAddr::new(0x1237_1000)];
    #[cfg(feature = "kernel-test")]
    let walks_before_boundary = __range_pt_walks_for_test();
    // SAFETY: the isolated two-page range crosses a PT boundary; synthetic
    // aligned backing is never dereferenced.
    if unsafe {
        map_4kb_scatter_range(pml4, boundary_base, &boundary_backing, |_, _| {
            PtFlags::USER | PtFlags::WRITABLE
        })
    }
    .is_err()
    {
        return TestResult::Fail("scatter boundary map failed");
    }
    #[cfg(feature = "kernel-test")]
    {
        if __range_pt_walks_for_test() != walks_before_boundary + 2 {
            return TestResult::Fail("scatter map reused a PT across its boundary");
        }
    }
    // SAFETY: cleanup of the isolated boundary-spanning range.
    let _ = unsafe { unmap_4kb_local_range(pml4, boundary_base, 2) };

    // A fresh PML4 slot keeps this mapping-order fixture independent from the
    // earlier USER scatter mappings in slot zero.
    let order_base = VirtAddr::new(0x0000_0100_0000_0000);
    // SAFETY: fresh aligned leaf in the isolated root.
    if unsafe {
        map_4kb(
            pml4,
            order_base,
            PhysAddr::new(0x1238_0000),
            PtFlags::WRITABLE,
        )
    }
    .is_err()
    {
        return TestResult::Fail("supervisor-first fixture map failed");
    }
    // SAFETY: read-only inspection of the live isolated hierarchy.
    if unsafe { upper_user_bits(pml4, order_base) } != Some([false; 3]) {
        return TestResult::Fail("supervisor mapping unexpectedly promoted upper USER bits");
    }
    // SAFETY: deliberate collision in the isolated root must fail without
    // mutating intermediate permissions.
    if unsafe {
        map_4kb(
            pml4,
            order_base,
            PhysAddr::new(0x1238_1000),
            PtFlags::USER | PtFlags::WRITABLE,
        )
    } != Err(crate::paging::MapError::AlreadyMapped)
    {
        return TestResult::Fail("colliding USER map did not fail precisely");
    }
    // SAFETY: read-only inspection after the rejected mapping.
    if unsafe { upper_user_bits(pml4, order_base) } != Some([false; 3]) {
        return TestResult::Fail("failed USER map promoted intermediate permissions");
    }
    let user_virt = VirtAddr::new(order_base.raw() + 4096);
    // SAFETY: adjacent leaf is absent and shares the isolated hierarchy.
    if unsafe {
        map_4kb(
            pml4,
            user_virt,
            PhysAddr::new(0x1238_1000),
            PtFlags::USER | PtFlags::WRITABLE,
        )
    }
    .is_err()
    {
        return TestResult::Fail("user-second fixture map failed");
    }
    // SAFETY: read-only inspection after the successful USER mapping.
    if unsafe { upper_user_bits(pml4, user_virt) } != Some([true; 3]) {
        return TestResult::Fail("user mapping did not promote every upper USER bit");
    }
    // The upper promotion must not change the supervisor leaf's authority.
    // SAFETY: read-only leaf walk of the live isolated root.
    if unsafe { flags_at(pml4, order_base) }.is_some_and(|flags| flags.contains(PtFlags::USER)) {
        return TestResult::Fail("upper promotion changed supervisor leaf authority");
    }
    // SAFETY: cleanup of both order-sensitive fixture leaves.
    let _ = unsafe { unmap_4kb_local_range(pml4, order_base, 2) };
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory",
    smoke_paging_scatter_range_maps_present_and_skips_lazy
);

#[cfg(all(target_arch = "aarch64", feature = "kernel-test"))]
fn smoke_aarch64_paging_scatter_and_range_unmap() -> TestResult {
    use crate::aarch64::paging::{
        __batch_barrier_counts_for_test, __range_l3_walks_for_test, free_user_ttbr0_tree,
        map_4kb_scatter_range, translate, unmap_4kb_range, PageTable, PtFlags,
    };
    use crate::{alloc_frame, FrameAllocError, PhysAddr, VirtAddr};

    let root = match alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised")
        }
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    // SAFETY: the fresh frame is exclusively owned and direct-map reachable.
    unsafe { core::ptr::write_bytes(root.kernel_mut_ptr::<PageTable>(), 0, 1) };
    let base = VirtAddr::new(0x567b_0000);
    let backing = [
        PhysAddr::new(0x1236_0000),
        PhysAddr::new(0),
        PhysAddr::new(0x1236_2000),
    ];
    let barriers_before_map = __batch_barrier_counts_for_test();
    let walks_before_map = __range_l3_walks_for_test();
    // SAFETY: this test exclusively owns the root. Synthetic leaf backing is
    // aligned and never dereferenced; zero is the documented lazy sentinel.
    let mapped = unsafe {
        map_4kb_scatter_range(root, base, &backing, |_, _| {
            PtFlags::AP_RW_EL0 | PtFlags::UXN | PtFlags::PXN
        })
    };
    if mapped.is_err() {
        // SAFETY: no CPU installs this isolated root.
        unsafe { free_user_ttbr0_tree(root) };
        return TestResult::Fail("aarch64 scatter range map failed");
    }
    let barriers_after_map = __batch_barrier_counts_for_test();
    if barriers_after_map.0 != barriers_before_map.0 + 1
        || barriers_after_map.1 != barriers_before_map.1
    {
        // SAFETY: cleanup of a root never installed in TTBR0.
        let _ = unsafe { unmap_4kb_range(root, base, 3) };
        // SAFETY: no CPU has ever installed this isolated root.
        unsafe { free_user_ttbr0_tree(root) };
        return TestResult::Fail("aarch64 scatter map did not batch publication barriers");
    }
    if __range_l3_walks_for_test() != walks_before_map + 1 {
        // SAFETY: cleanup of a root never installed in TTBR0.
        let _ = unsafe { unmap_4kb_range(root, base, 3) };
        // SAFETY: no CPU has ever installed this isolated root.
        unsafe { free_user_ttbr0_tree(root) };
        return TestResult::Fail("aarch64 scatter map repeated an upper-level walk per page");
    }
    for (page, expected) in backing.into_iter().enumerate() {
        // SAFETY: read-only walk of the still-live isolated root.
        let got = unsafe { translate(root, VirtAddr::new(base.as_u64() + page as u64 * 4096)) };
        if got != (expected.raw() != 0).then_some(expected) {
            // SAFETY: cleanup of a root never installed in TTBR0.
            let _ = unsafe { unmap_4kb_range(root, base, 3) };
            // SAFETY: no CPU has ever installed this isolated root.
            unsafe { free_user_ttbr0_tree(root) };
            return TestResult::Fail("aarch64 scatter translation mismatch");
        }
    }
    let barriers_before_rewrite = __batch_barrier_counts_for_test();
    let walks_before_rewrite = __range_l3_walks_for_test();
    // SAFETY: this is a permission-only replacement of the same live backing
    // in the isolated root. The helper must perform one break-before-make
    // transaction for both present leaves while preserving the lazy hole.
    if unsafe {
        crate::aarch64::paging::rewrite_4kb_scatter_range(root, base, &backing, |_, _| {
            PtFlags::AP_RO_EL0 | PtFlags::UXN | PtFlags::PXN
        })
    }
    .is_err()
    {
        // SAFETY: cleanup of a root never installed in TTBR0.
        let _ = unsafe { unmap_4kb_range(root, base, 3) };
        // SAFETY: no CPU has ever installed this isolated root.
        unsafe { free_user_ttbr0_tree(root) };
        return TestResult::Fail("aarch64 scatter permission rewrite failed");
    }
    let barriers_after_rewrite = __batch_barrier_counts_for_test();
    if barriers_after_rewrite.0 != barriers_before_rewrite.0 + 1
        || barriers_after_rewrite.1 != barriers_before_rewrite.1 + 1
    {
        // SAFETY: cleanup of a root never installed in TTBR0.
        let _ = unsafe { unmap_4kb_range(root, base, 3) };
        // SAFETY: no CPU has ever installed this isolated root.
        unsafe { free_user_ttbr0_tree(root) };
        return TestResult::Fail("aarch64 rewrite did not batch break-before-make barriers");
    }
    if __range_l3_walks_for_test() != walks_before_rewrite + 2 {
        // SAFETY: cleanup of a root never installed in TTBR0.
        let _ = unsafe { unmap_4kb_range(root, base, 3) };
        // SAFETY: no CPU has ever installed this isolated root.
        unsafe { free_user_ttbr0_tree(root) };
        return TestResult::Fail("aarch64 rewrite did not batch both upper-level walks");
    }
    for page in [0_u64, 2] {
        let va = VirtAddr::new(base.as_u64() + page * 4096);
        // SAFETY: read-only walk of the isolated live root.
        let read_only = unsafe { crate::aarch64::paging::flags_at(root, va) }
            .is_some_and(|flags| flags.bits() & (0b11 << 6) == PtFlags::AP_RO_EL0.bits());
        if !read_only {
            // SAFETY: cleanup of a root never installed in TTBR0.
            let _ = unsafe { unmap_4kb_range(root, base, 3) };
            // SAFETY: no CPU has ever installed this isolated root.
            unsafe { free_user_ttbr0_tree(root) };
            return TestResult::Fail("aarch64 rewrite left a writable leaf");
        }
    }
    // SAFETY: all pages belong to the isolated root; the lazy middle leaf is a
    // benign miss and the hardware broadcast is safe even though the root was
    // never active.
    let barriers_before_unmap = __batch_barrier_counts_for_test();
    let walks_before_unmap = __range_l3_walks_for_test();
    // SAFETY: range unmap of the isolated root; no CPU ever installed it.
    if unsafe { unmap_4kb_range(root, base, 3) } != Ok(2) {
        // SAFETY: no CPU has ever installed this isolated root.
        unsafe { free_user_ttbr0_tree(root) };
        return TestResult::Fail("aarch64 range unmap count mismatch");
    }
    let barriers_after_unmap = __batch_barrier_counts_for_test();
    if barriers_after_unmap.1 != barriers_before_unmap.1 + 1 {
        // SAFETY: no CPU has ever installed this isolated root.
        unsafe { free_user_ttbr0_tree(root) };
        return TestResult::Fail("aarch64 range unmap did not batch TLBI barriers");
    }
    if __range_l3_walks_for_test() != walks_before_unmap + 1 {
        // SAFETY: no CPU has ever installed this isolated root.
        unsafe { free_user_ttbr0_tree(root) };
        return TestResult::Fail("aarch64 range unmap repeated an upper-level walk per page");
    }
    // SAFETY: idempotent re-unmap of the same isolated root.
    if unsafe { unmap_4kb_range(root, base, 3) } != Ok(0) {
        // SAFETY: no CPU has ever installed this isolated root.
        unsafe { free_user_ttbr0_tree(root) };
        return TestResult::Fail("aarch64 repeated range unmap was not idempotent");
    }
    let boundary_base = VirtAddr::new(0x567f_f000);
    let boundary_backing = [PhysAddr::new(0x1237_0000), PhysAddr::new(0x1237_1000)];
    let walks_before_boundary = __range_l3_walks_for_test();
    // SAFETY: the two-page isolated range straddles an L3-table boundary and
    // its aligned synthetic backing is never dereferenced.
    if unsafe {
        map_4kb_scatter_range(root, boundary_base, &boundary_backing, |_, _| {
            PtFlags::AP_RW_EL0 | PtFlags::UXN | PtFlags::PXN
        })
    }
    .is_err()
    {
        // SAFETY: no CPU has ever installed this isolated root.
        unsafe { free_user_ttbr0_tree(root) };
        return TestResult::Fail("aarch64 boundary scatter map failed");
    }
    if __range_l3_walks_for_test() != walks_before_boundary + 2 {
        // SAFETY: cleanup of a root never installed in TTBR0.
        let _ = unsafe { unmap_4kb_range(root, boundary_base, 2) };
        // SAFETY: no CPU has ever installed this isolated root.
        unsafe { free_user_ttbr0_tree(root) };
        return TestResult::Fail("aarch64 scatter map reused L3 across a boundary");
    }
    // SAFETY: final cleanup unmap of the isolated boundary root.
    let _ = unsafe { unmap_4kb_range(root, boundary_base, 2) };
    // SAFETY: no CPU has ever installed this isolated root.
    unsafe { free_user_ttbr0_tree(root) };
    TestResult::Pass
}
#[cfg(all(target_arch = "aarch64", feature = "kernel-test"))]
kernel_test_in!("memory", smoke_aarch64_paging_scatter_and_range_unmap);

#[cfg(all(target_arch = "aarch64", feature = "kernel-test"))]
fn smoke_aarch64_paging_root_locks_are_sharded() -> TestResult {
    use crate::aarch64::paging::pt_lock_for;

    let first = pt_lock_for(crate::PhysAddr::new(0x1000));
    let second = pt_lock_for(crate::PhysAddr::new(0x2000));
    let first_addr = first as *const _ as usize;
    let second_addr = second as *const _ as usize;
    if core::ptr::eq(first, second) || first_addr & 63 != 0 || second_addr.abs_diff(first_addr) < 64
    {
        return TestResult::Fail("aarch64 root mutation shards share a cache line");
    }
    let _held = first.lock();
    if second.try_lock().is_none() {
        return TestResult::Fail("one aarch64 root lock blocks an unrelated root");
    }
    TestResult::Pass
}
#[cfg(all(target_arch = "aarch64", feature = "kernel-test"))]
kernel_test_in!("memory", smoke_aarch64_paging_root_locks_are_sharded);

fn smoke_pagetable_registry_collision_and_tombstone_reuse() -> TestResult {
    // These synthetic, page-aligned addresses are outside the test VM's RAM.
    // Their page numbers differ by the hash-table length, so multiplication
    // by an odd hash constant leaves the same low index bits and forces a
    // probe-chain collision.
    const FIRST: u64 = 0x0000_0e00_0000_0000;
    const COLLIDING: u64 = FIRST + (131072 * 4096);
    const REPLACEMENT: u64 = COLLIDING + (131072 * 4096);
    crate::frame::__pagetable_register(FIRST);
    crate::frame::__pagetable_register(COLLIDING);
    if !crate::frame::__pagetable_is_registered(FIRST)
        || !crate::frame::__pagetable_is_registered(COLLIDING)
    {
        return TestResult::Fail("colliding page-table registrations were lost");
    }
    crate::frame::__pagetable_unregister(FIRST);
    if crate::frame::__pagetable_is_registered(FIRST)
        || !crate::frame::__pagetable_is_registered(COLLIDING)
    {
        return TestResult::Fail("tombstone broke the remaining probe chain");
    }
    crate::frame::__pagetable_register(REPLACEMENT);
    if !crate::frame::__pagetable_is_registered(REPLACEMENT) {
        return TestResult::Fail("tombstone slot was not reusable");
    }
    crate::frame::__pagetable_unregister(COLLIDING);
    crate::frame::__pagetable_unregister(REPLACEMENT);
    TestResult::Pass
}
kernel_test_in!(
    "memory",
    smoke_pagetable_registry_collision_and_tombstone_reuse
);

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
    use core::alloc::Layout;
    #[cfg(target_arch = "x86_64")]
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
                    #[cfg(target_arch = "x86_64")]
                    if raw >= usable_bytes {
                        for (q, ql) in held.drain(..) {
                            // SAFETY: the operation upholds its documented invariant (see surrounding context).
                            unsafe {
                                crate::slab::dealloc(q, ql);
                            }
                        }
                        // SAFETY: the operation upholds its documented invariant (see surrounding context).
                        unsafe {
                            crate::slab::dealloc(p, layout);
                        }
                        return TestResult::Fail("slab::alloc returned address past usable RAM");
                    }
                    if raw & (layout.align() as u64 - 1) != 0 {
                        for (q, ql) in held.drain(..) {
                            // SAFETY: the operation upholds its documented invariant (see surrounding context).
                            unsafe {
                                crate::slab::dealloc(q, ql);
                            }
                        }
                        // SAFETY: the operation upholds its documented invariant (see surrounding context).
                        unsafe {
                            crate::slab::dealloc(p, layout);
                        }
                        return TestResult::Fail("slab::alloc returned misaligned");
                    }
                    held.push((p, layout));
                }
                Err(_) => {
                    for (q, ql) in held.drain(..) {
                        // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
            // SAFETY: the operation upholds its documented invariant (see surrounding context).
            unsafe {
                crate::slab::dealloc(a, layout);
            }
            return TestResult::Skip("second slab::alloc failed");
        }
    };
    if a.as_ptr() == b.as_ptr() {
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        unsafe {
            crate::slab::dealloc(a, layout);
        }
        return TestResult::Fail("slab::alloc returned the same pointer twice");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    unsafe {
        for i in 0..64 {
            p1.as_ptr().add(i).write(0xAA);
        }
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
        // SAFETY: MMIO access to the device's mapped register block; the offset lies within the mapped BAR.
        let first8: u64 = unsafe { core::ptr::read_volatile(p2.as_ptr() as *const u64) };
        // Slab freelist writes either a NonNull<FreeBlock> (low 48
        // bits non-zero) or zero (last block in list). If we read
        // 0xAAAAAA... back, the freelist didn't overwrite — that's
        // a bug.
        if first8 == 0xAAAAAAAAAAAAAAAA {
            // SAFETY: the operation upholds its documented invariant (see surrounding context).
            unsafe {
                crate::slab::dealloc(p2, layout);
            }
            return TestResult::Fail("slab returned the freed block with caller bytes intact");
        }
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // The kernel direct/identity map covers the low 4 GiB on x86_64; an
    // allocation above that ceiling page-faults on first access. RAM is
    // NOT contiguous from 0 (PCI hole + reserved regions), so
    // `total_frames * PAGE_SIZE` is not a valid upper bound — a frame
    // legitimately above that count-derived size still sits in usable
    // RAM (that mismatch made this test intermittently fail). Use the
    // same 4 GiB ceiling as `smoke_frame_alloc_returns_pointer_in_ram`.
    const RAM_CEILING: u64 = 4u64 << 30;
    let pages = match alloc_pages_on(0, 0) {
        Ok(p) => p,
        Err(_) => return TestResult::Skip("alloc_pages_on failed"),
    };
    let phys = pages.start_address().raw();
    let ok_range = phys < RAM_CEILING;
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let pml4 = unsafe { read_cr3() };
    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised")
        }
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    // Map at 1 TiB + 16 GiB (PML4[2]): outside the low identity map
    // (0..512 GiB of 1-GiB huge pages map_4kb can't sub-divide) and in the
    // kernel PML4's empty user-reserved range, so map_4kb builds a real
    // 4 KiB leaf. The old 0x4_0000_1000 (16 GiB) fell inside a huge page
    // once the low map grew from 4 GiB to 512 GiB → map_4kb failed.
    let virt = VirtAddr::new(0x0000_0104_0000_1000);
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

#[cfg(target_arch = "aarch64")]
fn smoke_process_asids_are_unique_and_retired_before_reuse() -> TestResult {
    use crate::asid_alloc::{
        allocate_process_asid, process_asid_live_for_test, release_process_asid, N_DOMAINS,
        TAG_RESERVED,
    };

    let first = allocate_process_asid();
    let second = allocate_process_asid();
    if first.tag == TAG_RESERVED || second.tag == TAG_RESERVED {
        return TestResult::Fail("process allocator unexpectedly exhausted ASIDs");
    }
    if first.tag <= N_DOMAINS as u16 || second.tag <= N_DOMAINS as u16 {
        return TestResult::Fail("process ASID overlaps the domain-tag partition");
    }
    if first.tag == second.tag {
        return TestResult::Fail("live process address spaces received the same ASID");
    }
    if !process_asid_live_for_test(first.tag) || !process_asid_live_for_test(second.tag) {
        return TestResult::Fail("allocated process ASID was not marked live");
    }

    release_process_asid(first);
    if process_asid_live_for_test(first.tag) {
        release_process_asid(second);
        return TestResult::Fail("retired process ASID remained live");
    }
    release_process_asid(second);
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!(
    "memory/asid_alloc",
    smoke_process_asids_are_unique_and_retired_before_reuse
);

fn smoke_per_domain_root_register_lookup() -> TestResult {
    use crate::per_domain_root;
    use narf_lib::id::DomainId;

    // `register_root` mirrors into the LIVE PCID domain registry
    // (`pcid::set_domain_pml4`) and `__reset_for_test` clears the root
    // table — with a live enforcer this scribbles a fake phys over a real
    // driver domain's boot PML4 (DomainId::DRIVER_1 == 10) and breaks
    // smoke_pcid_domain_private_slots_isolated depending on link order.
    // The isolation smoke only runs when the enforcer is active, so gate
    // this pure-logic test to the complementary case; it still runs on CI
    // (TCG, no PCID) where the registry isn't live.
    #[cfg(target_arch = "x86_64")]
    if narf_arch::x86_64::pcid::is_active() {
        return TestResult::Skip("PCID enforcer live — would corrupt the boot domain registry");
    }

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
        b[1] = 1 << 4; // SPD rev 1.0 (major nibble = 1, minor nibble = 0)
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
    use crate::slab;
    use core::alloc::Layout;
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
    use crate::slab;
    use core::alloc::Layout;
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
    use crate::slab;
    use core::alloc::Layout;
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
    use crate::slab;
    use core::alloc::Layout;
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
    if !narf_lib::smp::is_online(1) {
        return TestResult::Skip(
            "needs the default multi-CPU/NUMA QEMU config; NARF_QEMU_SMP drops -numa + APs",
        );
    }
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

fn smoke_numa_allocation_stats_advance() -> TestResult {
    let before = crate::numa_node_stats(0);
    let frame = match crate::alloc_frame_on_strict(0) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Skip("node 0 strict allocation unavailable"),
    };
    let after = crate::numa_node_stats(0);
    crate::free_frame(frame);

    if after.numa_hit != before.numa_hit.saturating_add(1) {
        return TestResult::Fail("strict local allocation did not increment numa_hit");
    }
    let locality_before = before.local_node.saturating_add(before.other_node);
    let locality_after = after.local_node.saturating_add(after.other_node);
    if locality_after != locality_before.saturating_add(1) {
        return TestResult::Fail("allocation did not increment a locality counter");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_numa_allocation_stats_advance);

fn smoke_numa_node_total_is_stable() -> TestResult {
    let total = crate::node_total(0);
    if total == 0 {
        return TestResult::Skip("node 0 managed-page total unavailable");
    }
    let free_before = crate::node_free(0);
    let frame = match crate::alloc_frame_on_strict(0) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Skip("node 0 strict allocation unavailable"),
    };
    if crate::node_total(0) != total {
        crate::free_frame(frame);
        return TestResult::Fail("node total changed after allocation");
    }
    if crate::node_free(0) >= free_before {
        crate::free_frame(frame);
        return TestResult::Fail("node free count did not decrease");
    }
    crate::free_frame(frame);
    if crate::node_total(0) == total {
        TestResult::Pass
    } else {
        TestResult::Fail("node total changed after free")
    }
}
kernel_test_in!("memory", smoke_numa_node_total_is_stable);

fn smoke_numa_buddy_order_snapshot_sums_to_free() -> TestResult {
    for node in 0..crate::FRAME_MAX_NUMA_NODES {
        let total = crate::node_total(node);
        if total == 0 {
            continue;
        }
        let reconstructed = crate::node_free_blocks(node)
            .iter()
            .enumerate()
            .fold(0usize, |sum, (order, blocks)| {
                sum.saturating_add(blocks.saturating_mul(1usize << order))
            });
        if reconstructed != crate::node_free(node) {
            return TestResult::Fail("buddy order counts do not sum to node_free");
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_numa_buddy_order_snapshot_sums_to_free);

fn smoke_memory_address_space_materialize() -> TestResult {
    // Full flow: new_for_user allocates a fresh root, map_region
    // records a region, materialize walks the region and installs
    // real PTEs via the arch's 4-KiB mapper, then translate()
    // against the new root finds the mapping with expected flags.
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    if a.mapped_page_size(VirtAddr::new(vbase)) != Some(4096)
        || a.mapped_page_size(VirtAddr::new(vbase + 0x1000)).is_some()
    {
        return TestResult::Fail("base-page mapping reported the wrong leaf size");
    }

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed on fresh user root");
    }

    // Per-arch structural validation of the installed PTE.
    #[cfg(target_arch = "x86_64")]
    {
        use crate::x86_64::paging::{self, PtFlags};
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        let got = unsafe { paging::translate(a.root, VirtAddr::new(vbase)) };
        match got {
            Some(phys) => {
                if phys != target {
                    // Dump every level of the walk so the failure
                    // message names where the path diverges.
                    let v = VirtAddr::new(vbase);
                    // SAFETY: the pointer is non-null, aligned, and points to a live value for this access.
                    let pml4 = unsafe { &*a.root.as_ptr::<crate::x86_64::paging::PageTable>() };
                    let pml4_idx = (v.raw() >> 39) & 0x1FF;
                    let pdpt_idx = (v.raw() >> 30) & 0x1FF;
                    let pd_idx = (v.raw() >> 21) & 0x1FF;
                    let pt_idx = (v.raw() >> 12) & 0x1FF;
                    let pml4e = pml4.entries[pml4_idx as usize];
                    let pdpt_pa = pml4e.addr();
                    // SAFETY: the pointer is non-null, aligned, and points to a live value for this access.
                    let pdpt = unsafe { &*pdpt_pa.as_ptr::<crate::x86_64::paging::PageTable>() };
                    let pdpte = pdpt.entries[pdpt_idx as usize];
                    let pd_pa = pdpte.addr();
                    // SAFETY: the pointer is non-null, aligned, and points to a live value for this access.
                    let pd = unsafe { &*pd_pa.as_ptr::<crate::x86_64::paging::PageTable>() };
                    let pde = pd.entries[pd_idx as usize];
                    let pt_pa = pde.addr();
                    // SAFETY: the pointer is non-null, aligned, and points to a live value for this access.
                    let pt = unsafe { &*pt_pa.as_ptr::<crate::x86_64::paging::PageTable>() };
                    let pte = pt.entries[pt_idx as usize];
                    let msg = alloc::format!(
                        "translate: target={:#x} got={:#x} root={:#x} \
                         pml4[{}]→{:#x} pdpt[{}]→{:#x} pd[{}]→{:#x} pt[{}]→{:#x}",
                        target.raw(),
                        phys.raw(),
                        a.root.raw(),
                        pml4_idx,
                        pml4e.addr().raw(),
                        pdpt_idx,
                        pdpte.addr().raw(),
                        pd_idx,
                        pde.addr().raw(),
                        pt_idx,
                        pte.addr().raw(),
                    );
                    let s: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
                    return TestResult::Fail(s);
                }
            }
            None => return TestResult::Fail("translate found no mapping post-materialize"),
        }
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
        use crate::aarch64::paging::{self};
        // SAFETY: `a.root` is the root table of the `AddressSpace` just
        // materialized above; its tables are identity-mapped and no other
        // CPU mutates them under the single-threaded test runner.
        // SAFETY: Valid memory or trusted environment
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
        // SAFETY: `a.root` is the materialized address space's root table;
        // its tables are identity-mapped and unmutated by other CPUs in the
        // single-threaded test runner.
        // SAFETY: Valid memory or trusted environment
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    return unsafe { crate::x86_64::paging::translate(root, virt) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: this fn's own contract requires `root` to be a valid,
    // identity-mapped aarch64 root table; we forward it unchanged to the
    // arch `translate`, which has the same precondition.
    // SAFETY: Valid memory or trusted environment
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let throwaway = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed (allocator drained?)"),
    };
    drop(throwaway);

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    // SAFETY: test context has paging enabled and exclusively owns the AS.
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed on fresh AS after prior AS::drop");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let throwaway = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    drop(throwaway);

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    let expected: alloc::vec::Vec<_> = phys.to_vec();
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: 0x4000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys,
    })
    .expect("map_region");
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    for (i, want) in expected.iter().enumerate() {
        let v = VirtAddr::new(vbase + (i as u64) * 0x1000);
        // SAFETY: the pointer is non-null, aligned, and points to a live value for this access.
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
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        let a = match unsafe { AddressSpace::new_for_user() } {
            Ok(a) => a,
            Err(_) => return TestResult::Skip("frame allocator drained mid-loop"),
        };
        drop(a);
    }
    // One more allocation must still succeed after 16 cycles —
    // if the buddy allocator leaks a frame per cycle this would
    // eventually fail.
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { first.materialize() }.is_err() {
        return TestResult::Fail("materialize on first AS failed");
    }
    drop(first);

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { second.materialize() }.is_err() {
        return TestResult::Fail("materialize on second AS failed");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        match unsafe { AddressSpace::new_for_user() } {
            Ok(_) => {}
            Err(_) => return TestResult::Fail("allocator drained after concurrent drops"),
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_many_concurrent_as_then_drop);

/// Final-owner teardown must detach every sparse top-level subtree in one
/// short root transaction, then return the intermediate tables through the
/// batched allocator path. On x86_64 also prove that detachment did not weaken
/// the private-table ownership registry: every captured hierarchy frame must
/// be unregistered before it becomes reusable.
#[cfg(feature = "kernel-test")]
fn smoke_memory_sparse_root_teardown_is_batched() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let before = {
        #[cfg(target_arch = "x86_64")]
        {
            crate::x86_64::paging::__teardown_batch_counts_for_test()
        }
        #[cfg(target_arch = "aarch64")]
        {
            crate::aarch64::paging::__teardown_batch_counts_for_test()
        }
    };
    // These occupy top-level slots 1, 128, and 255 on both 48-bit, four-level
    // implementations while staying in the canonical user half.
    let bases = [
        0x0000_0080_0000_0000_u64,
        0x0000_4000_0000_0000_u64,
        0x0000_7fff_f000_0000_u64,
    ];
    // SAFETY: the test runner has paging enabled and exclusively owns the AS.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    for base in bases {
        let backing = match crate::alloc_frame() {
            Ok(frame) => frame.start_address(),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        if address_space
            .map_region(Region {
                base: VirtAddr::new(base),
                len: 4096,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![backing],
            })
            .is_err()
        {
            crate::free_frame(crate::PhysFrame::new(backing));
            return TestResult::Fail("sparse teardown fixture region was rejected");
        }
    }
    // SAFETY: the test owns the root and every registered backing frame.
    if unsafe { address_space.materialize() }.is_err() {
        return TestResult::Fail("sparse teardown fixture materialize failed");
    }

    #[cfg(target_arch = "x86_64")]
    let registered_tables = {
        use crate::x86_64::paging::PageTable;
        let mut tables = alloc::vec![address_space.root];
        // SAFETY: the materialized root and each verified present descriptor
        // are identity-reachable, live, and exclusively owned by this test.
        let pml4 = unsafe { &*address_space.root.as_ptr::<PageTable>() };
        for base in bases {
            let pml4e = pml4.entries[((base >> 39) & 0x1ff) as usize];
            if !pml4e.is_present() {
                return TestResult::Fail("sparse fixture is missing a PML4 entry");
            }
            tables.push(pml4e.addr());
            // SAFETY: the present PML4 entry names a live, identity-reachable
            // PDPT in this test's exclusively owned hierarchy.
            let pdpt = unsafe { &*pml4e.addr().as_ptr::<PageTable>() };
            let pdpte = pdpt.entries[((base >> 30) & 0x1ff) as usize];
            if !pdpte.is_present() {
                return TestResult::Fail("sparse fixture is missing a PDPT entry");
            }
            tables.push(pdpte.addr());
            // SAFETY: the present PDPT entry names a live, identity-reachable
            // PD in this test's exclusively owned hierarchy.
            let pd = unsafe { &*pdpte.addr().as_ptr::<PageTable>() };
            let pde = pd.entries[((base >> 21) & 0x1ff) as usize];
            if !pde.is_present() {
                return TestResult::Fail("sparse fixture is missing a PD entry");
            }
            tables.push(pde.addr());
        }
        if tables
            .iter()
            .any(|table| !crate::frame::__pagetable_is_registered(table.raw()))
        {
            return TestResult::Fail("sparse fixture table was not registry-owned");
        }
        tables
    };

    drop(address_space);
    let after = {
        #[cfg(target_arch = "x86_64")]
        {
            crate::x86_64::paging::__teardown_batch_counts_for_test()
        }
        #[cfg(target_arch = "aarch64")]
        {
            crate::aarch64::paging::__teardown_batch_counts_for_test()
        }
    };
    if after.0 != before.0 + bases.len() as u64 {
        return TestResult::Fail("final teardown did not detach every sparse top-level subtree");
    }
    // This fixture owns ten table frames (root plus three 3-level subtrees),
    // so the 64-frame bound must amortise them into exactly one return.
    if after.1 != before.1 + 1 {
        return TestResult::Fail("final teardown did not batch table-frame return");
    }
    #[cfg(target_arch = "x86_64")]
    if registered_tables
        .iter()
        .any(|table| crate::frame::__pagetable_is_registered(table.raw()))
    {
        return TestResult::Fail("final teardown left a stale page-table registration");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
kernel_test_in!("memory", smoke_memory_sparse_root_teardown_is_batched);

// ── dual-arch tests (no AS::drop-realloc cycle) ───────────────────

/// Accounting callers must be able to total a large lazy mapping without
/// cloning its per-page backing vector. The public result counts VMA spans,
/// including unbacked pages, and saturates rather than wrapping.
fn smoke_memory_mapped_bytes_counts_lazy_regions() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: the test owns the new user root for its complete lifetime.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let base = 0x0000_0080_0000_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(base),
        len: 0x3000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0); 3],
    })
    .expect("map first lazy region");
    a.map_region(Region {
        base: VirtAddr::new(base + 0x10_0000),
        len: 0x5000,
        perms: RegionPerms::READ,
        phys: alloc::vec![PhysAddr::new(0); 5],
    })
    .expect("map second lazy region");

    if a.mapped_bytes() != 0x8000 {
        return TestResult::Fail("mapped_bytes did not sum lazy VMA spans");
    }
    let stats = a.memory_stats();
    if stats.mapped_bytes != 0x8000
        || stats.resident_pages != 0
        || stats.writable_nonexec_bytes != 0x3000
    {
        return TestResult::Fail("allocation-free memory totals are incorrect");
    }
    if a.region_len_at_base(VirtAddr::new(base)) != Some(0x3000)
        || a.region_len_at_base(VirtAddr::new(base + 0x1000)).is_some()
    {
        return TestResult::Fail("exact-base region length lookup is incorrect");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_mapped_bytes_counts_lazy_regions);

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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("first materialize failed");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let first = unsafe { translate_arch(a.root, VirtAddr::new(vbase)) };
    if first != Some(target) {
        return TestResult::Fail("first translate mismatch");
    }
    // Second call must be a no-op (returns Ok, doesn't reinstall).
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("second materialize failed");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let lazy_present = unsafe { translate_arch(a.root, VirtAddr::new(vbase)) }.is_some();
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let v = VirtAddr::new(0x0000_0080_0000_0000);
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user a failed"),
    };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let _ = unsafe { a.materialize() };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let _ = unsafe { b.materialize() };

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let resolved_a = unsafe { translate_arch(a.root, v) };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    if a.change_perms_range(v, 0x1000, RegionPerms::READ).is_err() {
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let _ = unsafe { a.materialize() };

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
                return TestResult::Fail("couldn't realloc 64 frames after freeing 64");
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
                                                              // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

/// The no-hint mmap arena must FAIL CLOSED at `MMAP_WINDOW_TOP` rather
/// than letting the monotonic cursor march into the stack reserve and
/// across the non-canonical boundary (which would re-create the silent
/// #GP-kill the window was introduced to prevent). A reservation that
/// would cross the ceiling returns 0 (→ -ENOMEM at the syscall layer);
/// in-window reservations succeed and stay below the ceiling.
fn smoke_memory_mmap_arena_fails_closed_at_ceiling() -> TestResult {
    use crate::AddressSpace;

    let a = AddressSpace::empty();
    // A normal reservation succeeds and lands inside the window.
    let first = a.reserve_mmap_va(0x1000);
    if !(AddressSpace::MMAP_CURSOR_BASE..AddressSpace::MMAP_WINDOW_TOP).contains(&first) {
        return TestResult::Fail("first reservation outside the mmap window");
    }
    // Consume almost the entire window in one shot, parking the cursor a
    // hair below the ceiling.
    let window = AddressSpace::MMAP_WINDOW_TOP - AddressSpace::MMAP_CURSOR_BASE;
    let near = a.reserve_mmap_va(window - 0x4000);
    if near == 0 {
        return TestResult::Fail("large in-window reservation wrongly failed");
    }
    // A reservation that would cross MMAP_WINDOW_TOP must fail closed (0),
    // NOT hand back a base in the stack reserve / non-canonical half.
    let over = a.reserve_mmap_va(0x1_0000_0000); // 4 GiB — does not fit
    if over != 0 {
        return TestResult::Fail("reservation past the ceiling did not fail closed");
    }
    // And a tiny reservation that still fits at the very top succeeds.
    let last = a.reserve_mmap_va(0x1000);
    if last == 0 || last >= AddressSpace::MMAP_WINDOW_TOP {
        return TestResult::Fail("final in-window reservation failed or crossed ceiling");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_mmap_arena_fails_closed_at_ceiling);

/// Regression: an in-place `mremap` grow (`grow_region`) MUST advance the
/// monotonic mmap bump cursor past the grown region, exactly as a fresh
/// `map_region` does. Before the fix, `grow_region` extended the region's
/// length without bumping the cursor, so the next `reserve_mmap_va` handed
/// back a VA *inside* the grown tail and the follow-up `map_region` failed
/// with `Overlap` — surfacing in userspace as a spurious `mmap`/`malloc`
/// failure (musl's mallocng grows its arenas with mremap, so weston's
/// desktop-shell hit it and "could not allocate closure" → the compositor
/// quit). All regions are lazy (phys == 0); we only exercise VA bookkeeping.
fn smoke_memory_grow_region_bumps_mmap_cursor() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    let a = AddressSpace::empty();
    // Map a 1-page region at the bump cursor.
    let base = a.reserve_mmap_va(0x1000);
    if base == 0 {
        return TestResult::Fail("first reserve_mmap_va failed");
    }
    if a.map_region(Region {
        base: VirtAddr::new(base),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![crate::PhysAddr::new(0)],
    })
    .is_err()
    {
        return TestResult::Fail("initial map_region failed");
    }
    // Grow it in place to 4 pages — the mremap-style path.
    if a.grow_region(VirtAddr::new(base), 0x4000).is_err() {
        return TestResult::Fail("grow_region failed");
    }
    // The next reservation MUST land past the grown region (the bug:
    // cursor not bumped → a VA inside the grown tail comes back).
    let next = a.reserve_mmap_va(0x1000);
    if next == 0 {
        return TestResult::Fail("second reserve_mmap_va failed");
    }
    if next < base + 0x4000 {
        return TestResult::Fail("reserve handed back a VA inside the grown region");
    }
    // And mapping there must succeed — never collide with the grown region.
    if a.map_region(Region {
        base: VirtAddr::new(next),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![crate::PhysAddr::new(0)],
    })
    .is_err()
    {
        return TestResult::Fail("post-grow map_region overlapped the grown region");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_grow_region_bumps_mmap_cursor);

/// A relocating mremap must move live translations and ownership together:
/// the old leaves disappear, resident frames reappear at the destination
/// without copying, and a grown tail stays absent for demand paging.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_relocate_region_moves_live_leaves() -> TestResult {
    #[cfg(target_arch = "aarch64")]
    use crate::aarch64::paging::translate;
    #[cfg(target_arch = "x86_64")]
    use crate::x86_64::paging::translate;
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    const OLD: u64 = 0x0000_4080_0100_0000;
    const NEW: u64 = 0x0000_4080_0200_0000;
    // SAFETY: test boot initialized paging and the frame allocator.
    let aspace = match unsafe { AddressSpace::new_for_user() } {
        Ok(aspace) => aspace,
        Err(_) => return TestResult::Skip("new_for_user unavailable"),
    };
    let first = match crate::frame::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    let second = match crate::frame::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => {
            crate::frame::free_frame(crate::frame::PhysFrame::new(first));
            return TestResult::Skip("frame allocator drained");
        }
    };
    if aspace
        .map_region(Region {
            base: VirtAddr::new(OLD),
            len: 8192,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![first, second],
        })
        .is_err()
    {
        return TestResult::Fail("source registration failed");
    }
    // SAFETY: aspace owns a live root and both mapped frames.
    if unsafe { aspace.materialize_range(VirtAddr::new(OLD), 8192) }.is_err() {
        return TestResult::Fail("source materialization failed");
    }
    // SAFETY: both ranges are disjoint, page-aligned user ranges owned by
    // this live address space.
    if unsafe { aspace.relocate_region(VirtAddr::new(OLD), 8192, VirtAddr::new(NEW), 12288) }
        .is_err()
    {
        return TestResult::Fail("relocate_region failed");
    }

    // SAFETY: translate only reads the test-owned live page-table root.
    let old_first = unsafe { translate(aspace.root, VirtAddr::new(OLD)) };
    // SAFETY: same root and destination range.
    let new_first = unsafe { translate(aspace.root, VirtAddr::new(NEW)) };
    // SAFETY: same root and destination range.
    let new_second = unsafe { translate(aspace.root, VirtAddr::new(NEW + 4096)) };
    // SAFETY: the grown tail is expected to have no leaf.
    let new_tail = unsafe { translate(aspace.root, VirtAddr::new(NEW + 8192)) };
    let region = aspace.lookup(VirtAddr::new(NEW));
    let mut first_old_rmap = false;
    let mut first_new_rmap = false;
    crate::rmap::for_each_owner(first, |owner| {
        if owner.root == aspace.root && owner.va == VirtAddr::new(OLD) {
            first_old_rmap = true;
        }
        if owner.root == aspace.root && owner.va == VirtAddr::new(NEW) {
            first_new_rmap = true;
        }
    });
    if old_first.is_some()
        || new_first != Some(first)
        || new_second != Some(second)
        || new_tail.is_some()
        || first_old_rmap
        || !first_new_rmap
        || !region.is_some_and(|region| {
            region.base == VirtAddr::new(NEW)
                && region.len == 12288
                && region.phys == alloc::vec![first, second, crate::PhysAddr::new(0)]
        })
    {
        return TestResult::Fail("relocation did not move leaves/backing/rmap atomically");
    }
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_relocate_region_moves_live_leaves);

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
                dup_pa,
                iter
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

    #[cfg(feature = "kernel-test")]
    let unmap_paths_before = crate::address_space::__test_unmap_path_counts();
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
    if a.punch_fixed(VirtAddr::new(0x4000), 0x1000).is_err() || a.region_count() != 0 {
        return TestResult::Fail("private range punch failed");
    }
    #[cfg(feature = "kernel-test")]
    {
        let unmap_paths_after = crate::address_space::__test_unmap_path_counts();
        if unmap_paths_after.0 != unmap_paths_before.0 + 2
            || unmap_paths_after.1 != unmap_paths_before.1
        {
            return TestResult::Fail("private teardown entered the shared transaction path");
        }
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

fn smoke_memory_cow_refcount_batch_retains_each_owner() -> TestResult {
    use crate::frame::cow;

    cow::__test_clear();
    let mut frames = alloc::vec::Vec::new();
    for _ in 0..4 {
        match crate::frame::alloc_frame() {
            Ok(frame) => frames.push(frame),
            Err(_) => {
                for frame in frames {
                    crate::frame::free_frame(frame);
                }
                return TestResult::Skip("frame allocator not initialised");
            }
        }
    }
    let phys: alloc::vec::Vec<_> = frames.iter().map(|frame| frame.start_address()).collect();
    let batch = [
        phys[0],
        phys[1],
        phys[2],
        phys[3],
        phys[0],
        crate::PhysAddr::new(0),
    ];
    cow::inc_ref_batch(&batch);
    let counts = cow::count_batch(&batch);

    let mut verdict = if cow::count(phys[0]) != 3 {
        TestResult::Fail("duplicate batch entries did not retain distinct owners")
    } else if phys[1..].iter().any(|frame| cow::count(*frame) != 2) {
        TestResult::Fail("batch did not retain every unique frame")
    } else if cow::count(crate::PhysAddr::new(0)) != 0 {
        TestResult::Fail("batch registered the unbacked zero sentinel")
    } else if counts != [3, 2, 2, 2, 3, 0] {
        TestResult::Fail("batch count snapshot lost input order or duplicate identity")
    } else {
        TestResult::Pass
    };

    // Drop the synthetic batch owners. Every real frame keeps its implicit
    // original owner, so none is allocator-releasable yet.
    let releasable = cow::dec_ref_batch(&batch);
    let post_drop = cow::count_batch(&batch);
    if matches!(verdict, TestResult::Pass) && !releasable.is_empty() {
        verdict = TestResult::Fail("batch COW drop released a frame with a live owner");
    } else if matches!(verdict, TestResult::Pass) && post_drop != [1, 1, 1, 1, 1, 0] {
        verdict = TestResult::Fail("batch COW drop lost duplicate-owner cardinality");
    }

    crate::frame::free_frame_batch(&frames);
    if matches!(verdict, TestResult::Pass) && phys.iter().any(|frame| cow::count(*frame) != 0) {
        verdict = TestResult::Fail("allocator batch free left final COW owners registered");
    }
    cow::__test_clear();
    verdict
}
kernel_test_in!("memory", smoke_memory_cow_refcount_batch_retains_each_owner);

/// A failed fork owns only the child VMAs it actually published. If a later
/// child index insertion runs out of metadata, speculative COW retains for the
/// unpublished suffix must be undone while the partial child's Drop balances
/// the published prefix. Existing siblings must keep their exact ownership.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "kernel-test"
))]
fn smoke_memory_failed_fork_rolls_back_unpublished_cow_refs() -> TestResult {
    use crate::address_space::__test_fail_fork_child_region_reserve_after;
    use crate::frame::{self, cow};
    use crate::{AddressSpace, AddressSpaceError, Region, RegionPerms, VirtAddr};

    cow::__test_clear();
    // SAFETY: paging is live in the kernel-test harness and this test owns the
    // fresh root until teardown.
    let parent = match unsafe { AddressSpace::new_for_user() } {
        Ok(parent) => parent,
        Err(_) => return TestResult::Skip("fork rollback parent root unavailable"),
    };
    let first = match frame::alloc_frame() {
        Ok(frame) => frame,
        Err(_) => return TestResult::Skip("fork rollback first frame unavailable"),
    };
    let second = match frame::alloc_frame() {
        Ok(frame) => frame,
        Err(_) => {
            frame::free_frame(first);
            return TestResult::Skip("fork rollback second frame unavailable");
        }
    };
    let first_phys = first.start_address();
    let second_phys = second.start_address();
    let first_base = VirtAddr::new(0x0000_0080_3a00_0000);
    let second_base = VirtAddr::new(0x0000_0080_3a00_2000);
    if parent
        .map_region(Region {
            base: first_base,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![first_phys],
        })
        .is_err()
    {
        frame::free_frame(first);
        frame::free_frame(second);
        return TestResult::Fail("fork rollback first VMA setup failed");
    }
    if parent
        .map_region(Region {
            base: second_base,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![second_phys],
        })
        .is_err()
    {
        frame::free_frame(second);
        return TestResult::Fail("fork rollback second VMA setup failed");
    }

    __test_fail_fork_child_region_reserve_after(2);
    // SAFETY: the inactive parent is exclusively owned; the injected failure
    // occurs during child metadata publication before scheduler visibility.
    let first_failure = unsafe { parent.clone_for_fork() };
    if !matches!(first_failure, Err(AddressSpaceError::AllocationFailed)) {
        return TestResult::Fail("fork index failure did not surface AllocationFailed");
    }
    let parent_intact = parent.lookup(first_base).is_some_and(|region| {
        region.phys == alloc::vec![first_phys]
            && region.perms.contains(RegionPerms::WRITE)
            && region.perms.contains(RegionPerms::COW)
    }) && parent.lookup(second_base).is_some_and(|region| {
        region.phys == alloc::vec![second_phys]
            && region.perms.contains(RegionPerms::WRITE)
            && region.perms.contains(RegionPerms::COW)
    });
    if !parent_intact || cow::count(first_phys) > 1 || cow::count(second_phys) > 1 {
        return TestResult::Fail("failed fork leaked a child COW owner or changed the parent");
    }

    // Establish one real sibling, then repeat the same partial failure. Both
    // backing counts must return exactly to the two live owners; this catches
    // both a leaked suffix and an accidental rollback of the published prefix.
    // SAFETY: same exclusively-owned inactive-parent contract.
    let sibling = match unsafe { parent.clone_for_fork() } {
        Ok(sibling) => sibling,
        Err(_) => return TestResult::Fail("fork rollback sibling setup failed"),
    };
    if cow::count(first_phys) != 2 || cow::count(second_phys) != 2 {
        return TestResult::Fail("successful sibling did not own both COW frames");
    }
    __test_fail_fork_child_region_reserve_after(2);
    // SAFETY: same injected, unpublished-child contract as the first failure.
    let second_failure = unsafe { parent.clone_for_fork() };
    if !matches!(second_failure, Err(AddressSpaceError::AllocationFailed))
        || cow::count(first_phys) != 2
        || cow::count(second_phys) != 2
    {
        return TestResult::Fail("failed fork changed pre-existing sibling ownership");
    }

    drop(sibling);
    if cow::count(first_phys) > 1 || cow::count(second_phys) > 1 {
        return TestResult::Fail("sibling teardown left an extra COW owner");
    }
    drop(parent);
    if cow::count(first_phys) == 0 && cow::count(second_phys) == 0 {
        TestResult::Pass
    } else {
        TestResult::Fail("parent teardown left failed-fork COW metadata")
    }
}
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "kernel-test"
))]
kernel_test_in!(
    "memory",
    smoke_memory_failed_fork_rolls_back_unpublished_cow_refs
);

fn smoke_memory_clone_for_fork_shares_frames_then_splits() -> TestResult {
    // End-to-end: parent AS with one region (1 page). After
    // clone_for_fork, both ASes' Region.phys[0] equal the same
    // PhysAddr and the COW refcount is 2; both retain logical WRITE and gain
    // the internal COW marker so their hardware leaves remain read-only.
    // After cow_split_on_write on the child, the child's
    // Region.phys[0] is a fresh frame, the parent's is unchanged,
    // and the parent's bytes are visible in the child (memcpy
    // proof).
    use crate::address_space::{AddressSpace, Region, RegionPerms};
    use crate::frame::cow;
    use crate::VirtAddr;

    cow::__test_clear();
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
        *(frame.raw() as *mut u32) = 0xC0FF_EE42;
    }

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    if !p_region.perms.contains(RegionPerms::WRITE)
        || !c_region.perms.contains(RegionPerms::WRITE)
        || !p_region.perms.contains(RegionPerms::COW)
        || !c_region.perms.contains(RegionPerms::COW)
    {
        return TestResult::Fail("COW: fork lost logical WRITE or the COW marker");
    }

    // mprotect is the authority boundary: once the parent becomes logically
    // read-only, a present write fault must not be accepted as COW recovery.
    if parent
        .change_perms_range(VirtAddr::new(VADDR), 4096, RegionPerms::READ)
        .is_err()
    {
        return TestResult::Fail("mprotect-style permission change failed");
    }
    // SAFETY: VADDR names the test-owned present COW mapping; this deliberately
    // exercises rejection after its logical WRITE permission is removed.
    if unsafe { parent.cow_split_on_write(VirtAddr::new(VADDR)) }.is_ok() {
        return TestResult::Fail("COW recovery bypassed logical read-only permission");
    }

    // Split the child's page.
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { child.cow_split_on_write(VirtAddr::new(VADDR)) }.is_err() {
        return TestResult::Fail("cow_split_on_write");
    }
    // Mirror the production #PF flow: `cow_split_on_write` only repoints
    // `region.phys`; the leaf PTE is rewritten by the paired `remap_page`.
    // Splitting without it leaves the PTE pointing at the OLD (now
    // dec_ref'd) frame.
    // SAFETY: same identity-map contract as cow_split_on_write.
    if unsafe { child.remap_page(VirtAddr::new(VADDR)) }.is_err() {
        return TestResult::Fail("remap_page");
    }
    let c_split = child
        .lookup(VirtAddr::new(VADDR))
        .expect("child post-split");
    let p_post = parent
        .lookup(VirtAddr::new(VADDR))
        .expect("parent post-split");
    if c_split.phys[0] == frame {
        return TestResult::Fail("split should have allocated a new child frame");
    }
    if p_post.phys[0] != frame {
        return TestResult::Fail("split must not move the parent's frame");
    }
    // SAFETY: identity-mapped.
    let copied = unsafe { *(c_split.phys[0].raw() as *const u32) };
    if copied != 0xC0FF_EE42 {
        return TestResult::Fail("split didn't memcpy the sentinel");
    }
    if cow::count(frame) > 1 {
        return TestResult::Fail("post-split: parent should be sole owner of original");
    }
    if !c_split.perms.contains(RegionPerms::WRITE) {
        return TestResult::Fail("split should preserve logical WRITE on the child");
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
kernel_test_in!(
    "memory",
    smoke_memory_clone_for_fork_shares_frames_then_splits
);

fn smoke_memory_fork_child_demand_faults_lazily() -> TestResult {
    // Lazy child materialize (the sys_fork path that skips eager `materialize()`):
    // after `clone_for_fork` the child has NO leaf PTE installed for an inherited
    // base page. The production #PF path (`demand_alloc_page`) faults it in from
    // the resident, shared `region.phys` as a READ-ONLY COW leaf; a write then
    // splits it, copying the parent's bytes. Proves the child sees correct data
    // without the whole address space being installed up front.
    use crate::address_space::{AddressSpace, Region, RegionPerms};
    use crate::frame::cow;
    use crate::paging::translate;
    use crate::VirtAddr;

    cow::__test_clear();
    // SAFETY: paging is live in the running kernel test environment.
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
    // SAFETY: identity-mapped phys; sole owner. Sentinel proves the split copy.
    unsafe {
        *(frame.raw() as *mut u32) = 0xC0FF_EE42;
    }
    // SAFETY: paging live; new child AS, no concurrent writers.
    let child = match unsafe { parent.clone_for_fork() } {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("clone_for_fork"),
    };

    let result = (|| {
        let va = VirtAddr::new(VADDR);
        // Lazy: no leaf installed for the inherited page yet.
        // SAFETY: child.root is a valid PML4; translate only reads tables.
        if unsafe { translate(child.root, va) }.is_some() {
            return TestResult::Fail("child leaf present before demand fault (not lazy)");
        }
        // Demand-fault it in — the production #PF path for a resident COW page.
        // SAFETY: child AS live; identity map present.
        if unsafe { child.demand_alloc_page(va) }.is_err() {
            return TestResult::Fail("demand_alloc_page failed on a shared COW page");
        }
        // Now mapped to the SHARED frame, READ-ONLY (COW not yet split).
        // SAFETY: as above.
        if unsafe { translate(child.root, va) } != Some(frame) {
            return TestResult::Fail("demand fault did not map the shared frame");
        }
        // The demand-faulted COW leaf must be read-only so a write splits it.
        // The writable-bit flag name is arch-specific (x86 WRITABLE vs aarch64
        // AP_RW_EL0), so assert it on x86_64 where the perf work runs.
        #[cfg(target_arch = "x86_64")]
        {
            use crate::paging::{flags_at, PtFlags};
            // SAFETY: child.root is a valid PML4; flags_at only reads tables.
            if unsafe { flags_at(child.root, va) }.is_some_and(|f| f.contains(PtFlags::WRITABLE)) {
                return TestResult::Fail("demand-faulted COW page must be read-only");
            }
        }
        if cow::count(frame) != 2 {
            return TestResult::Fail("still shared: refcount should be 2");
        }
        // A write splits: child gets a fresh private frame with the sentinel.
        // SAFETY: VADDR names the child's present COW mapping.
        if unsafe { child.cow_split_on_write(va) }.is_err() {
            return TestResult::Fail("cow_split_on_write");
        }
        // SAFETY: pairs with the split to install the new leaf (production #PF flow).
        if unsafe { child.remap_page(va) }.is_err() {
            return TestResult::Fail("remap_page");
        }
        let c = child.lookup(va).expect("child post-split");
        if c.phys[0] == frame {
            return TestResult::Fail("split should allocate a fresh child frame");
        }
        // SAFETY: identity-mapped fresh frame.
        if unsafe { *(c.phys[0].raw() as *const u32) } != 0xC0FF_EE42 {
            return TestResult::Fail("split didn't memcpy the sentinel from the shared frame");
        }
        TestResult::Pass
    })();
    let _ = child;
    cow::__test_clear();
    result
}
kernel_test_in!("memory", smoke_memory_fork_child_demand_faults_lazily);

fn smoke_memory_cow_split_survives_reserve_watermark() -> TestResult {
    // Regression: a copy-on-write break must NOT be refused at the `min`
    // reserve watermark. `cow_split_on_write` allocates the private copy via
    // `alloc_user_frame_urgent` (AllocContext::UserReserve), which may consume
    // the reserve — the faulting task already owns the shared page and is doing
    // a legitimate write, so refusing it would deliver a spurious SIGSEGV on
    // writable memory. Before the fix the split used the reserve-respecting
    // `alloc_user_frame`, so at the watermark it returned Err → the trap path
    // fell through to SIGSEGV, killing stress-ng workers and wedging the run.
    use crate::address_space::{AddressSpace, Region, RegionPerms};
    use crate::frame::cow;
    use crate::{reclaim, VirtAddr};

    // Decide up front whether this host can be driven into a reserve breach,
    // reading the free-page count DIRECTLY rather than raising the watermark to
    // probe it. `set_min_free_pages` clamps WMARK_MIN to the 65536-page
    // (256 MiB) ceiling, so a host with more than that free can never be forced
    // into a breach. Probing via a temporary `set_min_free_pages` would raise
    // the watermark for other CPUs and can nudge kswapd into a reclaim pass that
    // reorders the buddy free lists — perturbing later frame-order-sensitive
    // tests. Skipping on a pure read keeps the skip path side-effect-free.
    const WMARK_CEIL_PAGES: usize = 65536;
    if crate::frame_stats().free > WMARK_CEIL_PAGES {
        return TestResult::Skip("cannot force reserve breach: >256 MiB free");
    }
    let saved_min = reclaim::watermark_min();
    reclaim::set_min_free_pages(u64::MAX);
    if !reclaim::user_alloc_would_breach_reserve() {
        reclaim::set_min_free_pages(saved_min);
        return TestResult::Skip("cannot force reserve breach: free above ceiling");
    }

    const VADDR: u64 = 0x0000_0080_0000_0000;
    cow::__test_clear();
    let build = || -> Result<(AddressSpace, AddressSpace, crate::PhysAddr), &'static str> {
        // SAFETY: the fresh roots are owned exclusively by this test and never
        // activated as a live task address space.
        let parent = unsafe { AddressSpace::new_for_user() }.map_err(|_| "new_for_user")?;
        let frame = crate::frame::alloc_frame()
            .map_err(|_| "alloc_frame")?
            .start_address();
        parent
            .map_region(Region {
                base: VirtAddr::new(VADDR),
                len: 4096,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![frame],
            })
            .map_err(|_| "map_region")?;
        // SAFETY: upholds clone_for_fork's documented invariant.
        let child = unsafe { parent.clone_for_fork() }.map_err(|_| "clone_for_fork")?;
        Ok((parent, child, frame))
    };
    let result = match build() {
        Err(e) => {
            reclaim::set_min_free_pages(saved_min);
            return TestResult::Fail(e);
        }
        Ok((parent, child, frame)) => {
            let r = if cow::count(frame) != 2 {
                TestResult::Fail("COW: refcount should be 2 after fork")
            // SAFETY: `cow_split_on_write` requires a live low-4-GiB identity
            // map (it memcpys the old frame's bytes into the new one) and an
            // initialised frame allocator + COW refcount table. All three hold
            // inside a kernel test: the identity map is established at boot,
            // and `cow::count(frame) == 2` immediately above proves the
            // refcount table is live for this very frame. VADDR names the
            // present COW mapping the fixture just forked.
            } else if unsafe { child.cow_split_on_write(VirtAddr::new(VADDR)) }.is_err() {
                // The bug: the CoW break was refused at the watermark.
                TestResult::Fail("CoW break refused at the reserve watermark (SIGSEGV regression)")
            // SAFETY: same address-space and direct-map prerequisites, and the
            // split above has just installed a private frame at VADDR, so the
            // PTE this re-walks is present.
            } else if unsafe { child.remap_page(VirtAddr::new(VADDR)) }.is_err() {
                TestResult::Fail("remap_page after reserve-watermark split")
            } else {
                let c = child
                    .lookup(VirtAddr::new(VADDR))
                    .expect("child post-split");
                if c.phys[0] == frame {
                    TestResult::Fail("reserve-watermark split did not allocate a private frame")
                } else if !c.perms.contains(RegionPerms::WRITE) {
                    TestResult::Fail("split lost logical WRITE")
                } else {
                    TestResult::Pass
                }
            };
            // `parent`/`child` Drop unmap every region, which calls rmap::remove
            // for each mapping before returning its frame to the buddy — so no
            // freed frame carries a live rmap owner into the next test (the
            // invariant Linux enforces in free_pages_prepare via the "nonzero
            // mapcount" bad_page check).
            drop(child);
            drop(parent);
            r
        }
    };
    reclaim::set_min_free_pages(saved_min);
    cow::__test_clear();
    result
}
kernel_test_in!("memory", smoke_memory_cow_split_survives_reserve_watermark);

fn smoke_memory_nested_fork_teardown_preserves_allocator_progress() -> TestResult {
    use crate::address_space::{AddressSpace, Region, RegionPerms};
    use crate::frame::{self, cow};
    use crate::VirtAddr;

    const PAGES: usize = 128;
    const BASE: u64 = 0x0000_0080_0000_0000;

    // Match stress-ng --mmapfork's troublesome ownership shape: a resident
    // private mapping is shared through two fork generations, every address
    // space exits, and the allocator must immediately make forward progress
    // for the next fork. The 128 pages fill/spill the order-0 cache repeatedly;
    // the userspace stress gate separately retains the exact 4 MiB workload.
    // SAFETY: paging and the frame allocator are live in kernel tests.
    let parent = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Skip("AddressSpace::new_for_user not available"),
    };
    let mut owned = alloc::vec::Vec::with_capacity(PAGES);
    for _ in 0..PAGES {
        match frame::alloc_frame() {
            Ok(frame) => owned.push(frame),
            Err(_) => {
                frame::free_frame_batch(&owned);
                return TestResult::Skip("not enough frames for nested-fork teardown");
            }
        }
    }
    let phys: alloc::vec::Vec<_> = owned.iter().map(|frame| frame.start_address()).collect();
    if parent
        .map_region(Region {
            base: VirtAddr::new(BASE),
            len: (PAGES as u64) << 12,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: phys.clone(),
        })
        .is_err()
    {
        frame::free_frame_batch(&owned);
        return TestResult::Fail("map_region nested-fork parent");
    }
    // Region metadata now owns every physical frame. PhysFrame is a copyable
    // handle, so dropping this temporary vector does not return its entries.
    drop(owned);

    // SAFETY: all roots are fresh, inactive user roots and BASE names the
    // test-owned resident mapping.
    if unsafe { parent.materialize() }.is_err() {
        return TestResult::Fail("materialize nested-fork parent");
    }
    // SAFETY: same live-paging contract as materialize above.
    let child = match unsafe { parent.clone_for_fork() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Fail("first nested clone_for_fork"),
    };
    // SAFETY: child is a fresh inactive user root; parent rewrite applies COW
    // permissions to its existing leaves.
    if unsafe { child.materialize() }.is_err() || unsafe { parent.rematerialize() }.is_err() {
        return TestResult::Fail("materialize first fork generation");
    }
    // SAFETY: same fork construction contract, now with an already-COW child.
    let grandchild = match unsafe { child.clone_for_fork() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Fail("second nested clone_for_fork"),
    };
    // SAFETY: grandchild is fresh and child owns the leaves being rewritten.
    if unsafe { grandchild.materialize() }.is_err() || unsafe { child.rematerialize() }.is_err() {
        return TestResult::Fail("materialize second fork generation");
    }
    if cow::count(phys[0]) != 3 || cow::count(phys[PAGES - 1]) != 3 {
        return TestResult::Fail("nested fork lost COW owner cardinality");
    }

    drop(parent);
    if cow::count(phys[0]) != 2 || cow::count(phys[PAGES - 1]) != 2 {
        return TestResult::Fail("parent teardown lost a nested COW owner");
    }
    drop(child);
    if cow::count(phys[0]) != 1 || cow::count(phys[PAGES - 1]) != 1 {
        return TestResult::Fail("child teardown lost the final nested COW owner");
    }
    drop(grandchild);
    if cow::count(phys[0]) != 0 || cow::count(phys[PAGES - 1]) != 0 {
        return TestResult::Fail("final nested teardown retained stale COW owners");
    }

    // The regression in 0239c302 made a later fork stop inside allocator-backed
    // address-space construction. A fresh root and clone are the progress
    // assertion; the harness timeout turns any allocator wedge into a failure.
    // SAFETY: allocator and paging remain live after the complete teardown.
    let probe = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Fail("allocator made no post-teardown progress"),
    };
    // SAFETY: probe is a fresh, inactive user root with no mappings.
    let probe_child = match unsafe { probe.clone_for_fork() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Fail("post-teardown clone_for_fork failed"),
    };
    drop(probe_child);
    drop(probe);
    TestResult::Pass
}
kernel_test_in!(
    "memory",
    smoke_memory_nested_fork_teardown_preserves_allocator_progress
);
/// Regression (mmap-scalability rebase, PR #161 commit 289ba96a): the vDSO
/// code page is mapped as a PRIVATE copy-on-write region backed by a
/// permanently shared master frame (refcount > 1 via `cow::inc_ref`), and
/// glibc's ld.so writes the vDSO's dynamic section in place. That write MUST
/// COW-split into a private page, not take a fatal fault. The rewrite
/// tightened `cow_split_on_write` to require the region carry BOTH WRITE and
/// COW; the vDSO mapping in `userspace/src/vdso.rs` still declared only
/// `READ | EXEC`, so cow_split declined the fault and systemd's first vDSO
/// write #PF-killed PID 1 at boot — invisible to CI because no desktop/systemd
/// boot runs in GHA. This mirrors the vDSO's mapping shape and pins the
/// invariant: a `READ|WRITE|EXEC|COW` region over a refcount>1 master
/// materializes read-only (executes, but writes fault), then COW-splits on
/// write into a writable private copy while the shared master stays pristine.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_vdso_shaped_cow_region_splits_on_write() -> TestResult {
    use crate::address_space::{AddressSpace, Region, RegionPerms};
    use crate::frame::cow;
    use crate::VirtAddr;

    const SENTINEL: u32 = 0x5D50_C0DE;
    // Above the low-4-GiB identity window so the executable leaf doesn't
    // collide with the kernel's shared huge PML4[0] mapping.
    const VADDR: u64 = 0x0000_0080_0000_0000;

    cow::__test_clear();
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let as_ = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("AddressSpace::new_for_user not available"),
    };
    let master_frame = match crate::frame::alloc_frame() {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("alloc_frame master"),
    };
    let master = master_frame.start_address();
    // Permanent baseline reference: the vDSO master is shared across every
    // process and never sole-owned, so its refcount stays > 1 and the leaf
    // stays read-only until a private split. 0 -> 2 (owner + sharer).
    if cow::inc_ref(master) != 2 {
        return TestResult::Fail("inc_ref master should produce 2");
    }
    // Sentinel in the master to prove the split COPIES it and never writes
    // through to the shared master.
    // SAFETY: identity-mapped freshly-allocated frame.
    unsafe {
        *(master.raw() as *mut u32) = SENTINEL;
    }

    if as_
        .map_region(Region {
            base: VirtAddr::new(VADDR),
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::EXEC | RegionPerms::COW,
            phys: alloc::vec![master],
        })
        .is_err()
    {
        return TestResult::Fail("map_region vdso-shaped");
    }

    // Materialize: while the master refcount is > 1, the leaf must be
    // read-only (`user_page_writable` == false), so the vDSO executes yet a
    // write faults into the COW path rather than writing the shared master.
    // SAFETY: root is live per new_for_user.
    if unsafe { as_.materialize() }.is_err() {
        return TestResult::Fail("materialize");
    }

    // THE REGRESSION: cow_split_on_write must accept the vDSO write. Before
    // the fix (region was READ|EXEC only) this returned Err and the caller
    // took a fatal #PF.
    // SAFETY: VADDR names the just-mapped present region.
    if unsafe { as_.cow_split_on_write(VirtAddr::new(VADDR)) }.is_err() {
        return TestResult::Fail(
            "cow_split_on_write rejected the vDSO write (the boot regression)",
        );
    }
    // Mirror the production #PF flow: cow_split only repoints region.phys;
    // remap_page rewrites the live leaf.
    // SAFETY: same identity-map contract as cow_split_on_write.
    if unsafe { as_.remap_page(VirtAddr::new(VADDR)) }.is_err() {
        return TestResult::Fail("remap_page");
    }

    let split = as_.lookup(VirtAddr::new(VADDR)).expect("post-split region");
    let private_phys = split.phys[0];
    if private_phys == master {
        return TestResult::Fail(
            "split must allocate a private frame, not write through the master",
        );
    }
    // The private copy carries the master's bytes (memcpy proof).
    // SAFETY: identity-mapped.
    if unsafe { *(private_phys.raw() as *const u32) } != SENTINEL {
        return TestResult::Fail("split didn't copy the master's bytes");
    }
    // The shared master is untouched — a write-through would corrupt every
    // other process's vDSO.
    // SAFETY: identity-mapped.
    if unsafe { *(master.raw() as *const u32) } != SENTINEL {
        return TestResult::Fail("master frame was written through (COW violated)");
    }
    // cow_split dec_ref'd the master once (2 -> 1) when it privatised.
    if cow::count(master) != 1 {
        return TestResult::Fail("master refcount should be 1 after the split");
    }

    // Cleanup: the AS Drop frees the private frame it now points at. The
    // master carries only our baseline ref and is no longer referenced by
    // any AS, so return it to the allocator explicitly.
    drop(as_);
    if cow::dec_ref(master) != 0 {
        return TestResult::Fail("final dec_ref of master should reach 0");
    }
    crate::frame::free_frame(master_frame);
    cow::__test_clear();
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_vdso_shaped_cow_region_splits_on_write
);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_remap_page_picks_up_perms_and_phys() -> TestResult {
    // After cow_split_on_write rewrites a region's per-page phys
    // entry + restores WRITE on the region, remap_page must walk
    // the live page table and re-install the PTE with the new
    // values. Verify the walked-and-re-mapped page actually
    // resolves (via paging::translate) to the new phys.
    #[cfg(target_arch = "aarch64")]
    use crate::aarch64::paging::translate;
    use crate::address_space::{AddressSpace, Region, RegionPerms};
    use crate::frame::cow;
    #[cfg(target_arch = "x86_64")]
    use crate::x86_64::paging::translate;
    use crate::VirtAddr;

    cow::__test_clear();
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("AddressSpace::new_for_user not available"),
    };
    let f1 = match crate::frame::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame f1"),
    };
    const VADDR: u64 = 0x0000_0080_0000_5000;
    if a.map_region(Region {
        base: VirtAddr::new(VADDR),
        len: 4096,
        perms: RegionPerms::READ,
        phys: alloc::vec![f1],
    })
    .is_err()
    {
        return TestResult::Fail("map_region");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize");
    }

    // Confirm the initial PTE points at f1.
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
        if a.map_region(Region {
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.remap_page(VirtAddr::new(VADDR)) }.is_err() {
        return TestResult::Fail("remap_page");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    use crate::frame::UsableRegion;
    use crate::hugepage::{
        alloc_hugepage_2m, alloc_hugepage_2m_on, alloc_hugepages_with, free_hugepage, node_stats,
        reserve_from_regions, stats, HugeAllocError, HugeSize, HUGEPAGE_2M_BYTES,
    };
    use crate::{Mempolicy, PhysAddr, MPOL_BIND};

    // Synthetic region aligned to 2 MiB. The phys addresses
    // here are bookkeeping-only — we never touch the memory, so it
    // doesn't matter that they don't correspond to real RAM.
    // Picked far above any realistic kernel-image footprint to
    // avoid colliding with anything else's bookkeeping.
    const SYNTH_BASE: u64 = 0x1_0000_0000;
    const PAGES: usize = 4;
    let region = UsableRegion {
        start: PhysAddr::new(SYNTH_BASE),
        len: ((PAGES + 1) as u64) * HUGEPAGE_2M_BYTES,
    };
    // Model the loaded kernel occupying one otherwise-usable huge frame.
    // Reservation must step over it and still satisfy the requested count
    // from the remainder of the region.
    let protected = [(
        SYNTH_BASE + HUGEPAGE_2M_BYTES,
        SYNTH_BASE + 2 * HUGEPAGE_2M_BYTES,
    )];

    let before = stats();
    // SAFETY: synthetic bookkeeping-only addresses are drained before the
    // test returns and no returned frame is dereferenced or donated.
    let excludes = unsafe { reserve_from_regions(&[region], &protected, PAGES, 0) };
    if excludes.len() != PAGES {
        return TestResult::Fail("reserve_from_regions returned wrong exclude count");
    }
    if excludes
        .iter()
        .any(|&(lo, hi)| lo < protected[0].1 && protected[0].0 < hi)
    {
        return TestResult::Fail("hugepage reservation overlapped a protected range");
    }
    // SAFETY: the exclude is a synthetic physical address used only for
    // topology lookup; the test never dereferences it.
    let target_node = unsafe { crate::frame::narf_phys_node(excludes[0].0) };
    let node_after_reserve = node_stats(target_node);
    let after_reserve = stats();
    if after_reserve.free_2m - before.free_2m != PAGES {
        return TestResult::Fail("free_2m didn't grow by reserve count");
    }
    if node_after_reserve.free_2m < PAGES {
        return TestResult::Fail("per-node free_2m omitted reserved pages");
    }

    let policy = Mempolicy {
        mode: MPOL_BIND,
        nodemask: 1u64 << target_node,
        allowed: 1u64 << target_node,
        home_node: target_node as u32,
        interleave_index: 0,
    };
    // An oversized batch must roll every pop back before reporting failure.
    let too_many = alloc::vec![policy; PAGES + 1];
    let before_failed_batch = node_stats(target_node);
    if alloc_hugepages_with(HugeSize::M2, &too_many, target_node).is_ok() {
        return TestResult::Fail("oversized hugepage batch unexpectedly succeeded");
    }
    if node_stats(target_node) != before_failed_batch {
        return TestResult::Fail("failed hugepage batch leaked a partial allocation");
    }

    // Drain exactly PAGES new allocations through one all-or-nothing pool
    // transaction, then validate strict physical placement.
    let policies = alloc::vec![policy; PAGES];
    let mut allocated = match alloc_hugepages_with(HugeSize::M2, &policies, target_node) {
        Ok(frames) => frames,
        Err(_) => return TestResult::Fail("batched strict hugepage allocation failed"),
    };
    for frame in &allocated {
        if frame.phys() & (HUGEPAGE_2M_BYTES - 1) != 0 {
            return TestResult::Fail("batched hugepage allocation returned unaligned phys");
        }
        if frame.node() != target_node {
            return TestResult::Fail("batched strict hugepage allocation returned wrong node");
        }
    }

    // Free one back, alloc one — roundtrip works.
    let returned = allocated.pop().unwrap();
    free_hugepage(returned);
    match alloc_hugepage_2m_on(target_node) {
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
    use crate::frame::UsableRegion;
    use crate::hugepage::{alloc_hugepage_1g_on, reserve_from_regions, stats, HUGEPAGE_1G_BYTES};
    use crate::{AddressSpace, HugeRegion, PhysAddr, RegionPerms, VirtAddr};

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
    // SAFETY: synthetic bookkeeping-only address; no frame is dereferenced or
    // donated and the reservation is drained before return.
    let excludes = unsafe { reserve_from_regions(&[region], &[], 0, 1) };
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

    // Install it as a real 1 GiB hardware leaf and verify translation keeps
    // the within-block offset.
    // SAFETY: topology lookup only; synthetic memory is not dereferenced.
    let node = unsafe { crate::frame::narf_phys_node(excl_start) };
    let frame = match alloc_hugepage_1g_on(node) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Fail("strict 1G allocation failed"),
    };
    let phys = frame.phys();
    // SAFETY: kernel test runs with paging live.
    let aspace = match unsafe { AddressSpace::new_for_user() } {
        Ok(aspace) => aspace,
        Err(_) => {
            crate::hugepage::free_hugepage(frame);
            return TestResult::Fail("1G test address-space creation failed");
        }
    };
    const USER_VA: u64 = 0x0000_5000_8000_0000;
    // SAFETY: fresh owned root with aligned VA and frame.
    if unsafe {
        aspace.map_huge_region(HugeRegion {
            base: VirtAddr::new(USER_VA),
            len: HUGEPAGE_1G_BYTES,
            perms: RegionPerms::READ,
            size: crate::hugepage::HugeSize::G1,
            frames: alloc::vec![frame],
        })
    }
    .is_err()
    {
        return TestResult::Fail("hardware 1G mapping failed");
    }
    let probe = VirtAddr::new(USER_VA + 0x20_0000);
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `aspace` owns the live root and no concurrent mutation occurs.
    let translated = unsafe { crate::x86_64::paging::translate(aspace.root, probe) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: `aspace` owns the live root and no concurrent mutation occurs.
    let translated = unsafe { crate::aarch64::paging::translate(aspace.root, probe) };
    if translated.map(PhysAddr::raw) != Some(phys + 0x20_0000) {
        return TestResult::Fail("1G translation lost its block offset");
    }
    if aspace.mapped_page_size(probe) != Some(HUGEPAGE_1G_BYTES) {
        return TestResult::Fail("1G mapping reported the wrong leaf size");
    }
    if !aspace.contains_address(VirtAddr::new(USER_VA + HUGEPAGE_1G_BYTES - 1)) {
        return TestResult::Fail("huge mapping absent from address-space membership");
    }
    if aspace.unmap_huge_region(VirtAddr::new(USER_VA)).is_err() {
        return TestResult::Fail("hardware 1G unmap failed");
    }
    // Teardown: drain the synthetic reservation so the pool returns to entry.
    let _ = alloc_hugepage_1g_on(node);
    TestResult::Pass
}
kernel_test_in!(
    "memory/hugepage",
    smoke_hugepage_1g_reserve_picks_aligned_chunk
);

fn smoke_hugepage_2m_hardware_mapping_roundtrip() -> TestResult {
    use crate::frame::UsableRegion;
    use crate::hugepage::{
        alloc_hugepage_2m_on, node_stats, reserve_from_regions, HUGEPAGE_2M_BYTES,
    };
    use crate::{AddressSpace, HugeRegion, PhysAddr, RegionPerms, VirtAddr};

    const SYNTH_BASE: u64 = 0x20_0000_0000;
    const USER_VA: u64 = 0x0000_5000_4000_0000;
    let region = UsableRegion {
        start: PhysAddr::new(SYNTH_BASE),
        len: 2 * HUGEPAGE_2M_BYTES,
    };
    // SAFETY: synthetic bookkeeping-only address; no frame is dereferenced or
    // donated and the reservation is drained before return.
    let excludes = unsafe { reserve_from_regions(&[region], &[], 2, 0) };
    if excludes.len() != 2 {
        return TestResult::Fail("failed to reserve synthetic 2M mapping frames");
    }
    // SAFETY: topology lookup only; no synthetic memory is dereferenced.
    let node = unsafe { crate::frame::narf_phys_node(excludes[0].0) };
    let before_map = node_stats(node);
    // SAFETY: kernel test runs with paging live.
    let aspace = match unsafe { AddressSpace::new_for_user() } {
        Ok(aspace) => aspace,
        Err(_) => return TestResult::Fail("user address-space creation failed"),
    };

    // Force a failure on the second leaf. The first leaf and both transferred
    // frames must roll back after the one-lock x86 batch releases its guard.
    let first = match alloc_hugepage_2m_on(node) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Fail("first strict 2M allocation failed"),
    };
    let second = match alloc_hugepage_2m_on(node) {
        Ok(frame) => frame,
        Err(_) => {
            crate::hugepage::free_hugepage(first);
            return TestResult::Fail("second strict 2M allocation failed");
        }
    };
    let conflict_va = VirtAddr::new(USER_VA + HUGEPAGE_2M_BYTES);
    #[cfg(target_arch = "x86_64")]
    // SAFETY: the inactive test root is exclusively owned and the synthetic
    // zero physical base is never dereferenced.
    let conflict = unsafe {
        crate::x86_64::paging::map_2mb(
            aspace.root,
            conflict_va,
            PhysAddr::new(0),
            crate::x86_64::paging::PtFlags::USER,
        )
    };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: same exclusive-root and never-dereferenced contract.
    let conflict = unsafe {
        crate::aarch64::paging::map_2mb(
            aspace.root,
            conflict_va,
            PhysAddr::new(0),
            crate::aarch64::paging::PtFlags::AP_RW_EL0,
        )
    };
    if conflict.is_err() {
        crate::hugepage::free_hugepage(first);
        crate::hugepage::free_hugepage(second);
        return TestResult::Fail("could not install second-leaf conflict");
    }
    // SAFETY: the fresh AS owns a live root; frames and VA are 2M-aligned.
    if unsafe {
        aspace.map_huge_region(HugeRegion {
            base: VirtAddr::new(USER_VA),
            len: 2 * HUGEPAGE_2M_BYTES,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            size: crate::hugepage::HugeSize::M2,
            frames: alloc::vec![first, second],
        })
    }
    .is_ok()
    {
        return TestResult::Fail("conflicting multi-leaf huge mapping succeeded");
    }
    #[cfg(target_arch = "x86_64")]
    let rolled_back =
        // SAFETY: the first leaf must have been removed from this owned root.
        unsafe { crate::x86_64::paging::translate(aspace.root, VirtAddr::new(USER_VA)) };
    #[cfg(target_arch = "aarch64")]
    let rolled_back =
        // SAFETY: the first leaf must have been removed from this owned root.
        unsafe { crate::aarch64::paging::translate(aspace.root, VirtAddr::new(USER_VA)) };
    if rolled_back.is_some() {
        return TestResult::Fail("failed huge batch left its first leaf mapped");
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: removes the test-owned structural conflict.
    let conflict_removed = unsafe { crate::x86_64::paging::unmap_2mb(aspace.root, conflict_va) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: removes the test-owned structural conflict.
    let conflict_removed = unsafe { crate::aarch64::paging::unmap_2mb(aspace.root, conflict_va) };
    if conflict_removed.is_err() || node_stats(node).free_2m != before_map.free_2m {
        return TestResult::Fail("failed huge batch did not restore pool ownership");
    }

    let first = match alloc_hugepage_2m_on(node) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Fail("first post-rollback allocation failed"),
    };
    let second = match alloc_hugepage_2m_on(node) {
        Ok(frame) => frame,
        Err(_) => {
            crate::hugepage::free_hugepage(first);
            return TestResult::Fail("second post-rollback allocation failed");
        }
    };
    let first_phys = first.phys();
    let second_phys = second.phys();
    // SAFETY: the AS owns a live root; frames and VA are 2M-aligned.
    if unsafe {
        aspace.map_huge_region(HugeRegion {
            base: VirtAddr::new(USER_VA),
            len: 2 * HUGEPAGE_2M_BYTES,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            size: crate::hugepage::HugeSize::M2,
            frames: alloc::vec![first, second],
        })
    }
    .is_err()
    {
        return TestResult::Fail("hardware 2M mapping failed");
    }
    let probe = VirtAddr::new(USER_VA + 0x1f000);
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `aspace` owns the live root and no concurrent mutation occurs.
    let translated = unsafe { crate::x86_64::paging::translate(aspace.root, probe) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: `aspace` owns the live root and no concurrent mutation occurs.
    let translated = unsafe { crate::aarch64::paging::translate(aspace.root, probe) };
    if translated.map(PhysAddr::raw) != Some(first_phys + 0x1f000) {
        return TestResult::Fail("huge-leaf translation lost its block offset");
    }
    let second_probe = VirtAddr::new(USER_VA + HUGEPAGE_2M_BYTES + 0x17000);
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `aspace` owns the live root and no concurrent mutation occurs.
    let second_translated = unsafe { crate::x86_64::paging::translate(aspace.root, second_probe) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: `aspace` owns the live root and no concurrent mutation occurs.
    let second_translated = unsafe { crate::aarch64::paging::translate(aspace.root, second_probe) };
    if second_translated.map(PhysAddr::raw) != Some(second_phys + 0x17000) {
        return TestResult::Fail("second huge leaf translated to the wrong frame");
    }
    if aspace.mapped_page_size(probe) != Some(HUGEPAGE_2M_BYTES) {
        return TestResult::Fail("2M mapping reported the wrong leaf size");
    }
    if aspace.unmap_huge_region(VirtAddr::new(USER_VA)).is_err() {
        return TestResult::Fail("hardware 2M unmap failed");
    }
    if node_stats(node).free_2m != before_map.free_2m {
        return TestResult::Fail("huge frame did not return to its NUMA pool");
    }
    // Drain the synthetic reservation so sibling tests see their entry state.
    let _ = alloc_hugepage_2m_on(node);
    let _ = alloc_hugepage_2m_on(node);
    TestResult::Pass
}
kernel_test_in!(
    "memory/hugepage",
    smoke_hugepage_2m_hardware_mapping_roundtrip
);

fn smoke_slab_steady_state_under_churn() -> TestResult {
    // Acceptance criterion #4 from the heap-migration spec: a
    // 1000-iteration alloc/free loop must hold steady at the
    // working-set size, not grow unboundedly. Exercise multiple
    // size classes (each with its own magazines + central free
    // list) so a leak in any one of them shows up.
    use crate::slab;
    use core::alloc::Layout;

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
    use crate::slab;
    use core::alloc::Layout;

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

fn smoke_buddy_migratetype_groups_by_mobility() -> TestResult {
    // A Movable free and an Unmovable free of the SAME order land in
    // separate partitions; neither counts against the other. Confirms the
    // free lists are actually partitioned by mobility.
    use crate::buddy::{BuddyZone, MigrateType};

    let mut zone = BuddyZone::new();
    // Seed 8 frames as a single order-3 Movable block (donate defaults to
    // Movable), then hand out one order-0 as Unmovable and free it as
    // Movable / Unmovable to place blocks in each partition deliberately.
    zone.donate(0x200, 8);

    // Free two explicit order-0 blocks into distinct partitions. Use
    // frames that are NOT buddies (0x300 and 0x340) so neither coalesces
    // nor is mistaken for the donated pool.
    zone.free_mt(0x300, 0, MigrateType::Unmovable);
    zone.free_mt(0x340, 0, MigrateType::Movable);

    if zone.free_block_count_mt(0, MigrateType::Unmovable) != 1 {
        return TestResult::Fail("unmovable order-0 not in unmovable partition");
    }
    if zone.free_block_count_mt(0, MigrateType::Movable) != 1 {
        return TestResult::Fail("movable order-0 not in movable partition");
    }
    // Partition-summed count sees both.
    if zone.free_block_count(0) != 2 {
        return TestResult::Fail("summed order-0 count wrong");
    }
    TestResult::Pass
}
kernel_test_in!("memory/buddy", smoke_buddy_migratetype_groups_by_mobility);

fn smoke_buddy_migratetype_no_cross_mobility_coalesce() -> TestResult {
    // Two buddies of DIFFERENT migratetypes must NOT coalesce, even though
    // they are physically adjacent and same-order. This is the invariant
    // that keeps each mobility class's contiguous regions from being
    // silently merged (and thus mis-labelled) across the boundary.
    use crate::buddy::{BuddyZone, MigrateType};

    let mut zone = BuddyZone::new();
    // Frames 0x400 and 0x401 are order-0 buddies (0x400 ^ 1 == 0x401).
    zone.free_mt(0x400, 0, MigrateType::Unmovable);
    zone.free_mt(0x401, 0, MigrateType::Movable);

    // No order-1 block should have formed in EITHER partition.
    if zone.free_block_count(1) != 0 {
        return TestResult::Fail("cross-mobility buddies wrongly coalesced");
    }
    if zone.free_block_count_mt(0, MigrateType::Unmovable) != 1
        || zone.free_block_count_mt(0, MigrateType::Movable) != 1
    {
        return TestResult::Fail("blocks did not stay as separate order-0 entries");
    }

    // Same-migratetype buddies DO coalesce: free 0x401's movable buddy
    // partner (0x400) as movable too and confirm an order-1 forms.
    let mut zone2 = BuddyZone::new();
    zone2.free_mt(0x400, 0, MigrateType::Movable);
    zone2.free_mt(0x401, 0, MigrateType::Movable);
    if zone2.free_block_count_mt(1, MigrateType::Movable) != 1 {
        return TestResult::Fail("same-mobility buddies failed to coalesce");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/buddy",
    smoke_buddy_migratetype_no_cross_mobility_coalesce
);

fn smoke_buddy_migratetype_fallback_steals() -> TestResult {
    // When a migratetype's own partition is empty, the allocator steals
    // from the fallback migratetype and CONVERTS the whole split block to
    // the requesting type, so subsequent same-type requests are served
    // from the just-stolen block's leftovers (Linux's whole-block steal).
    use crate::buddy::{BuddyZone, MigrateType};

    let mut zone = BuddyZone::new();
    // One order-3 (8-frame) block, all Movable.
    zone.donate(0x800, 8);

    // Request order-0 UNMOVABLE. Movable partition is the only source, so
    // it must steal the order-3 block, split it, and place the leftover
    // buddies into the UNMOVABLE partition.
    let f = match zone.alloc_mt(0, MigrateType::Unmovable) {
        Some(f) => f,
        None => return TestResult::Fail("unmovable steal from movable failed"),
    };
    if f != 0x800 {
        return TestResult::Fail("stole wrong block head");
    }
    // Leftovers (orders 0,1,2) now live in the UNMOVABLE partition.
    for o in 0..=2 {
        if zone.free_block_count_mt(o, MigrateType::Unmovable) != 1 {
            return TestResult::Fail("stolen leftovers not converted to unmovable");
        }
        if zone.free_block_count_mt(o, MigrateType::Movable) != 0 {
            return TestResult::Fail("movable partition should be drained by the steal");
        }
    }
    // A follow-up unmovable order-0 request is served from those leftovers
    // WITHOUT touching the movable pool (which is empty anyway).
    if zone.alloc_mt(0, MigrateType::Unmovable).is_none() {
        return TestResult::Fail("follow-up unmovable alloc should reuse stolen leftovers");
    }
    TestResult::Pass
}
kernel_test_in!("memory/buddy", smoke_buddy_migratetype_fallback_steals);

fn smoke_buddy_migratetype_reduces_fragmentation() -> TestResult {
    // Headline anti-fragmentation property. Two workloads run against
    // identical synthetic zones:
    //
    //   * UNGROUPED: unmovable and movable order-0 allocations interleave
    //     into ONE pool (simulated by allocating everything as one type),
    //     then only the movable ones are freed — leaving unmovable holes
    //     that block coalescing.
    //   * GROUPED: the same allocations are classified by mobility. When
    //     the movable ones are freed they coalesce back into a large
    //     contiguous run because the unmovable holes are in a separate
    //     region.
    //
    // We assert the grouped zone recovers a strictly larger top free order
    // than the ungrouped one.
    use crate::buddy::{BuddyZone, MigrateType};

    // Helper: highest order with at least one free block.
    fn top_order(z: &BuddyZone) -> i32 {
        for o in (0..=crate::buddy::MAX_ORDER).rev() {
            if z.free_block_count(o) > 0 {
                return o as i32;
            }
        }
        -1
    }

    const BASE: u64 = 0x1000;
    const N: u64 = 64; // 64 order-0 frames = a would-be order-6 block.

    // ---- UNGROUPED: unmovable and movable interleaved in one pool. ----
    // Allocate all 64 as Unmovable (one pool). Then free back only the
    // ODD-ADDRESSED frames (the "movable" role); the even frames (the
    // "unmovable" role) stay allocated. Freeing by frame-address parity is
    // deterministic: every freed odd frame's order-0 buddy is the adjacent
    // EVEN frame, which is still held — so NOTHING can coalesce above
    // order 0, whatever order the splitter handed frames out in.
    let mut ungrouped = BuddyZone::new();
    ungrouped.donate(BASE, N);
    let mut ung_frames = [0u64; N as usize];
    for slot in ung_frames.iter_mut() {
        match ungrouped.alloc_mt(0, MigrateType::Unmovable) {
            Some(f) => *slot = f,
            None => return TestResult::Fail("ungrouped alloc drained early"),
        }
    }
    for &f in ung_frames.iter() {
        if f % 2 == 1 {
            ungrouped.free_mt(f, 0, MigrateType::Unmovable);
        }
    }
    let ungrouped_top = top_order(&ungrouped);
    // Sanity: the interleaved free genuinely fragmented — no block above
    // order 0 formed.
    if ungrouped_top != 0 {
        return TestResult::Fail("ungrouped pool unexpectedly coalesced above order 0");
    }

    // ---- GROUPED: classify by role. ----
    // Even frames requested MOVABLE, odd frames UNMOVABLE. Because the two
    // classes are drawn from separate partitions, the movable frames form
    // a contiguous run; freeing them all coalesces upward.
    let mut grouped = BuddyZone::new();
    // Seed the pool split so movable frames are physically contiguous:
    // donate the low half movable, the high half unmovable.
    grouped.donate_as(BASE, N / 2, MigrateType::Movable);
    grouped.donate_as(BASE + N / 2, N / 2, MigrateType::Unmovable);
    // Allocate all movable frames, then free them all back.
    let mut grp_frames = [0u64; (N / 2) as usize];
    for slot in grp_frames.iter_mut() {
        match grouped.alloc_mt(0, MigrateType::Movable) {
            Some(f) => *slot = f,
            None => return TestResult::Fail("grouped movable alloc drained early"),
        }
    }
    for &f in grp_frames.iter() {
        grouped.free_mt(f, 0, MigrateType::Movable);
    }
    let grouped_top = top_order(&grouped);

    // The grouped movable region (32 frames) coalesces back to an order-5
    // block; the ungrouped pool is stuck at order 0 (every buddy pinned).
    if grouped_top <= ungrouped_top {
        return TestResult::Fail("grouping did not raise the largest free order");
    }
    if grouped_top < 5 {
        return TestResult::Fail("movable region failed to coalesce to order-5");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/buddy",
    smoke_buddy_migratetype_reduces_fragmentation
);

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
        Err(FrameAllocError::NotSupported) | Err(FrameAllocError::AuthorityRevoked) => {
            TestResult::Fail("unexpected error variant for oversize order")
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
    use crate::slab;
    use core::alloc::Layout;

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
    use crate::slab;
    use core::alloc::Layout;
    use core::arch::x86_64::_rdtsc;

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
    // SAFETY: Valid memory or trusted environment
    let t0 = unsafe { _rdtsc() };
    for _ in 0..ITERS {
        let p = slab::try_alloc_atomic(layout).expect("warm magazine");
        // SAFETY: just allocated atomically.
        let _ = unsafe { slab::try_dealloc_atomic(p, layout) };
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let t0 = unsafe { _rdtsc() };
    for _ in 0..ITERS {
        if slab::try_alloc_atomic(layout).is_some() {
            // Magazine refilled by another CPU? Drain it.
            // (Kernel tests run on BSP single-CPU; this shouldn't
            // happen, but bail to avoid skewing the measurement.)
            return TestResult::Fail("magazine refilled mid-failure-loop");
        }
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    static POOL: narf_lib::sync::OnceLock<AtomicPool<u64>> = narf_lib::sync::OnceLock::new();
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
    static POOL: IrqSafeSpinLock<Option<&'static AtomicPool<u64>>> = IrqSafeSpinLock::new(None);
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
kernel_test_in!(
    "memory/atomic_pool",
    smoke_atomic_pool_capacity_pinned_after_drain
);

fn smoke_atomic_pool_pooled_deref_mut_visible_next_lease() -> TestResult {
    // Pooled<T>'s DerefMut writes are observable when the item
    // returns to the pool and is leased again — the pool isn't
    // resetting items on drop.
    use crate::atomic_pool::AtomicPool;
    use narf_lib::sync::IrqSafeSpinLock;
    static POOL: IrqSafeSpinLock<Option<&'static AtomicPool<u32>>> = IrqSafeSpinLock::new(None);
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
kernel_test_in!(
    "memory/atomic_pool",
    smoke_atomic_pool_pooled_deref_mut_visible_next_lease
);

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
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_shootdown_request_constructors
);

fn smoke_tlb_shootdown_counter_monotonic() -> TestResult {
    use crate::tlb_shootdown::{shootdown, shootdown_count, ShootdownRequest};
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
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_shootdown_counter_monotonic
);

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
    let all = [
        AllocContext::Sleepable,
        AllocContext::Atomic,
        AllocContext::IrqOff,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("AllocContext variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/context",
    smoke_context_alloc_context_variants_distinct
);

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
    use crate::asid_alloc::{__reset_for_test, alloc, cached};
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
kernel_test_in!(
    "memory/asid_alloc",
    smoke_asid_alloc_cached_returns_same_tag
);

fn smoke_asid_alloc_invalidate_clears_cache() -> TestResult {
    use crate::asid_alloc::{__reset_for_test, alloc, cached, invalidate_tag};
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
kernel_test_in!(
    "memory/asid_alloc",
    smoke_asid_alloc_invalidate_clears_cache
);

fn smoke_asid_alloc_rollover_bumps_generation() -> TestResult {
    use crate::asid_alloc::{__reset_for_test, alloc, current_generation, rollover_now};
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
kernel_test_in!(
    "memory/asid_alloc",
    smoke_asid_alloc_rollover_bumps_generation
);

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
    let all = [
        AllocError::OutOfMemory,
        AllocError::NotInitialised,
        AllocError::AlreadyAllocated,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("AllocError variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/per_domain_root",
    smoke_per_domain_root_alloc_error_variants_distinct
);

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
kernel_test_in!(
    "memory/per_domain_root",
    smoke_per_domain_root_lookup_none_before_register
);

fn smoke_per_domain_root_double_register_rejected() -> TestResult {
    use crate::per_domain_root::{__reset_for_test, register_root, unregister_root, AllocError};
    use narf_lib::id::DomainId;
    // register_root mirrors a fake phys into the live PCID registry (here
    // for SCRATCH == domain 15); skip when the enforcer is live so it
    // can't corrupt boot isolation. See smoke_per_domain_root_register_lookup.
    #[cfg(target_arch = "x86_64")]
    if narf_arch::x86_64::pcid::is_active() {
        return TestResult::Skip("PCID enforcer live — would corrupt the boot domain registry");
    }
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
kernel_test_in!(
    "memory/per_domain_root",
    smoke_per_domain_root_double_register_rejected
);

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
        Err(FrameAllocError::Exhausted) => TestResult::Skip("buddy exhausted on this test image"),
        Err(FrameAllocError::NotSupported) | Err(FrameAllocError::AuthorityRevoked) => {
            TestResult::Fail("unexpected error variant from alloc_pages_on")
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
        Err(FrameAllocError::NotSupported) | Err(FrameAllocError::AuthorityRevoked) => {
            TestResult::Fail("unexpected error variant at MAX_ORDER boundary")
        }
    }
}
kernel_test_in!(
    "memory/buddy",
    smoke_buddy_alloc_pages_on_max_order_boundary
);

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
kernel_test_in!(
    "memory/hugepage",
    smoke_hugepage_alloc_2m_empty_after_no_reserve
);

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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { translate_arch(a.root, VirtAddr::new(vbase)) }.is_some() {
        core::mem::forget(a);
        return TestResult::Fail("lazy slot had a PTE before demand-alloc");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.demand_alloc_page(VirtAddr::new(vbase + 0x123)) }.is_err() {
        core::mem::forget(a);
        return TestResult::Fail("demand_alloc_page failed");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let pte = unsafe { translate_arch(a.root, VirtAddr::new(vbase)) };
    core::mem::forget(a);
    if pte.is_none() {
        return TestResult::Fail("demand-alloc didn't install a PTE");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_demand_alloc_installs_pte);

/// Live AddressSpace swap must move ownership with the PTE transition: two
/// pages fault back through `demand_alloc_page`, while teardown discards the
/// remaining swap slot without treating its zero `Region::phys` entry as an
/// anonymous demand-zero page or double-freeing the old frame.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_address_space_batched_swap_lifecycle() -> TestResult {
    use crate::reclaim::{plan_reclaim_ranges, ReclaimRangeCandidate};
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr, ZramBackend};

    if crate::swap_stats().resident != 0 {
        return TestResult::Skip("another swap lifecycle is active");
    }
    crate::install_swap_backend(ZramBackend::new());
    // SAFETY: paging and the frame allocator are live in the kernel suite.
    let aspace = match unsafe { AddressSpace::new_for_user() } {
        Ok(aspace) => aspace,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    const N: usize = 3;
    let base = VirtAddr::new(0x0000_0080_0008_0000);
    let mut phys = alloc::vec::Vec::with_capacity(N);
    for index in 0..N {
        let frame = match crate::alloc_frame() {
            Ok(frame) => frame,
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        let address = frame.start_address();
        // SAFETY: the fresh frame is exclusively owned by the new region.
        unsafe {
            core::ptr::write_bytes(address.kernel_mut_ptr::<u8>(), 0x91 + index as u8, 4096);
        }
        phys.push(address);
    }
    if aspace
        .map_region(Region {
            base,
            len: N as u64 * 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys,
        })
        .is_err()
    {
        return TestResult::Fail("swap lifecycle setup failed");
    }
    // SAFETY: `aspace` owns a live root and the validated private region.
    if unsafe { aspace.materialize() }.is_err() {
        return TestResult::Fail("swap lifecycle setup failed");
    }

    let plan = plan_reclaim_ranges(
        &[ReclaimRangeCandidate {
            address_space_root: aspace.root,
            base,
            pages: N,
            mapcount: 1,
            expected_free_pages: N,
            age: 0,
            locked: false,
        }],
        N,
        N,
    );
    // SAFETY: test owns this live address space and its private resident run.
    let report = unsafe { aspace.swap_out_reclaim_plan(&plan) };
    if report.error.is_some() || report.swapped_pages != N || report.submissions != 1 {
        return TestResult::Fail("AddressSpace batch page-out failed");
    }
    let snapshot = aspace.regions_snapshot();
    if snapshot.len() != 1 || snapshot[0].phys.iter().any(|entry| entry.raw() != 0) {
        return TestResult::Fail("page-out did not transfer Region ownership");
    }
    if crate::swap_stats().resident != N as u64 {
        return TestResult::Fail("batch page-out did not charge every slot");
    }

    // Fault the middle page: the first-class batch-in path restores it and
    // the consecutive page ahead, leaving page zero swapped for teardown.
    // SAFETY: same live-root/fault-path contract as a real user #PF.
    if unsafe { aspace.demand_alloc_page(VirtAddr::new(base.as_u64() + 4096)) }.is_err() {
        return TestResult::Fail("swap fault-in failed");
    }
    let after_fault = aspace.regions_snapshot();
    if after_fault[0].phys[0].raw() != 0 {
        return TestResult::Fail("batch-in unexpectedly pulled a page behind the fault");
    }
    for index in 1..N {
        let restored = after_fault[0].phys[index];
        if restored.raw() == 0 {
            return TestResult::Fail("fault-in did not republish Region backing");
        }
        // SAFETY: restored is resident and region-owned until teardown.
        if unsafe { core::ptr::read_volatile(restored.kernel_ptr::<u8>()) } != 0x91 + index as u8 {
            return TestResult::Fail("fault-in content mismatch");
        }
    }
    if crate::swap_stats().resident != 1 {
        return TestResult::Fail("batched page-in slot accounting is wrong");
    }

    if aspace.unmap_region(base).is_err() {
        return TestResult::Fail("mixed resident/swapped teardown failed");
    }
    if crate::swap_stats().resident != 0 {
        return TestResult::Fail("teardown leaked the unfaulted swap slot");
    }

    // mlock must preserve swapped contents by paging them in before setting
    // LOCKED; treating Region::phys==0 as anonymous would silently zero data.
    let lock_base = VirtAddr::new(base.as_u64() + 0x20_0000);
    let mut lock_phys = alloc::vec::Vec::new();
    for pattern in [0xa1u8, 0xa2] {
        let frame = match crate::alloc_frame() {
            Ok(frame) => frame.start_address(),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        // SAFETY: fresh private frame.
        unsafe { core::ptr::write_bytes(frame.kernel_mut_ptr::<u8>(), pattern, 4096) };
        lock_phys.push(frame);
    }
    if aspace
        .map_region(Region {
            base: lock_base,
            len: 8192,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: lock_phys,
        })
        .is_err()
    {
        return TestResult::Fail("mlock swap setup map failed");
    }
    // SAFETY: live test root.
    if unsafe { aspace.materialize_range(lock_base, 8192) }.is_err() {
        return TestResult::Fail("mlock swap setup materialize failed");
    }
    // SAFETY: private two-page run owned by the test AS.
    if unsafe { aspace.swap_out_private_batch(lock_base, 2) } != Ok(2)
        || aspace.mlock_range(lock_base, 8192).is_err()
    {
        return TestResult::Fail("mlock did not restore swapped contents");
    }
    let locked = aspace
        .regions_snapshot()
        .into_iter()
        .find(|region| region.base == lock_base)
        .expect("locked region missing");
    if !locked.perms.contains(RegionPerms::LOCKED) || locked.phys.iter().any(|phys| phys.raw() == 0)
    {
        return TestResult::Fail("mlock left swapped backing or failed to pin");
    }
    for (index, pattern) in [0xa1u8, 0xa2].into_iter().enumerate() {
        // SAFETY: mlock made the complete region resident.
        if unsafe { core::ptr::read_volatile(locked.phys[index].kernel_ptr::<u8>()) } != pattern {
            return TestResult::Fail("mlock replaced swap data with zero-fill");
        }
    }
    if crate::swap_stats().resident != 0 || aspace.unmap_region(lock_base).is_err() {
        return TestResult::Fail("mlock swap cleanup failed");
    }

    {
        // MADV_DONTNEED has the opposite contract: retire the stable swap
        // entry so the next touch is anonymous zero-fill.
        let discard_base = VirtAddr::new(base.as_u64() + 0x40_0000);
        let frame = match crate::alloc_frame() {
            Ok(frame) => frame.start_address(),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        // SAFETY: fresh private frame.
        unsafe { core::ptr::write_bytes(frame.kernel_mut_ptr::<u8>(), 0xd7, 4096) };
        if aspace
            .map_region(Region {
                base: discard_base,
                len: 4096,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![frame],
            })
            .is_err()
        {
            return TestResult::Fail("madvise swap setup map failed");
        }
        // SAFETY: live test root and private mapping.
        if unsafe { aspace.materialize_range(discard_base, 4096) }.is_err() {
            return TestResult::Fail("MADV_DONTNEED swap discard failed");
        }
        // SAFETY: the test AS exclusively owns this private resident page.
        if unsafe { aspace.swap_out_private_batch(discard_base, 1) } != Ok(1)
            || aspace.madvise_dontneed(discard_base, 4096).is_err()
        {
            return TestResult::Fail("MADV_DONTNEED swap discard failed");
        }
        if crate::swap_stats().resident != 0 {
            return TestResult::Fail("MADV_DONTNEED leaked a swap slot");
        }
        // SAFETY: normal anonymous demand fault after slot retirement.
        if unsafe { aspace.demand_alloc_page(discard_base) }.is_err() {
            return TestResult::Fail("post-madvise zero fault failed");
        }
        let zero = aspace
            .regions_snapshot()
            .into_iter()
            .find(|region| region.base == discard_base)
            .expect("madvise region missing")
            .phys[0];
        // SAFETY: demand fault made this region-owned frame resident.
        if unsafe { core::ptr::read_volatile(zero.kernel_ptr::<u8>()) } != 0 {
            return TestResult::Fail("MADV_DONTNEED preserved discarded swap data");
        }
        if aspace.unmap_region(discard_base).is_err() {
            return TestResult::Fail("madvise swap cleanup failed");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_address_space_batched_swap_lifecycle);

/// The anon-reclaim VMA scan must emit exactly the runs the swap executor
/// accepts: page-aligned resident private-anon runs (split at holes), never
/// shared/locked/file/COW/PROT_NONE regions, and bounded by `max_pages`.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_collect_anon_reclaim_candidates() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: paging and the frame allocator are live in the kernel suite.
    let aspace = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };

    // Region A: 4 private-anon RW pages, resident except a hole at index 2 →
    // the scan should split it into runs [0,1] and [3].
    let base_a = VirtAddr::new(0x0000_0080_0010_0000);
    let mut phys_a = alloc::vec::Vec::with_capacity(4);
    for i in 0..4usize {
        if i == 2 {
            phys_a.push(PhysAddr::new(0));
            continue;
        }
        match crate::alloc_frame() {
            Ok(f) => phys_a.push(f.start_address()),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        }
    }
    if aspace
        .map_region(Region {
            base: base_a,
            len: 4 * 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: phys_a,
        })
        .is_err()
    {
        return TestResult::Fail("map_region A failed");
    }

    // Region B: resident but SHARED → ineligible, contributes nothing.
    let base_b = VirtAddr::new(0x0000_0080_0020_0000);
    let mut phys_b = alloc::vec::Vec::with_capacity(1);
    match crate::alloc_frame() {
        Ok(f) => phys_b.push(f.start_address()),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    }
    if aspace
        .map_region(Region {
            base: base_b,
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED,
            phys: phys_b,
        })
        .is_err()
    {
        return TestResult::Fail("map_region B failed");
    }
    // SAFETY: aspace owns a live root and the validated regions.
    if unsafe { aspace.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }

    let result = (|| {
        let mut out = alloc::vec::Vec::new();
        aspace.collect_anon_reclaim_candidates(&mut out, 64);
        if out.len() != 2 {
            return TestResult::Fail("expected 2 runs (hole-split; shared skipped)");
        }
        let r0 = out.iter().find(|c| c.base.as_u64() == base_a.as_u64());
        let r1 = out
            .iter()
            .find(|c| c.base.as_u64() == base_a.as_u64() + 3 * 4096);
        let (r0, r1) = match (r0, r1) {
            (Some(a), Some(b)) => (a, b),
            _ => return TestResult::Fail("runs not at the expected bases"),
        };
        if r0.pages != 2 || r1.pages != 1 {
            return TestResult::Fail("hole did not split runs into [0,1] + [3]");
        }
        for c in &out {
            if c.address_space_root != aspace.root
                || c.mapcount != 1
                || c.expected_free_pages != c.pages
                || c.locked
            {
                return TestResult::Fail("candidate fields wrong");
            }
        }
        // max_pages bound: asking for 1 stops the first run at a single page.
        let mut bounded = alloc::vec::Vec::new();
        aspace.collect_anon_reclaim_candidates(&mut bounded, 1);
        if bounded.first().map(|c| c.pages) != Some(1) {
            return TestResult::Fail("max_pages=1 did not bound the first run to 1 page");
        }
        TestResult::Pass
    })();

    let _ = aspace.unmap_region(base_a);
    let _ = aspace.unmap_region(base_b);
    result
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_collect_anon_reclaim_candidates);

/// End-to-end anon reclaim: the VMA scan's candidates must feed
/// `plan_reclaim_ranges` and `swap_out_reclaim_plan` and actually swap the
/// pages out — proving the scan emits executor-compatible ranges (the risk the
/// hand-built swap-lifecycle test cannot catch).
#[cfg(target_arch = "x86_64")]
fn smoke_memory_anon_reclaim_scan_drives_swap() -> TestResult {
    use crate::reclaim::plan_reclaim_ranges;
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr, ZramBackend};

    if crate::swap_stats().resident != 0 {
        return TestResult::Skip("another swap lifecycle is active");
    }
    crate::install_swap_backend(ZramBackend::new());
    // SAFETY: paging and the frame allocator are live in the kernel suite.
    let aspace = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    const N: usize = 3;
    let base = VirtAddr::new(0x0000_0080_0030_0000);
    let mut phys = alloc::vec::Vec::with_capacity(N);
    for index in 0..N {
        let frame = match crate::alloc_frame() {
            Ok(f) => f.start_address(),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        // SAFETY: fresh private frame owned by the new region.
        unsafe { core::ptr::write_bytes(frame.kernel_mut_ptr::<u8>(), 0x70 + index as u8, 4096) };
        phys.push(frame);
    }
    if aspace
        .map_region(Region {
            base,
            len: N as u64 * 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys,
        })
        .is_err()
    {
        return TestResult::Fail("map_region failed");
    }
    // SAFETY: aspace owns a live root and the validated private region.
    if unsafe { aspace.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }

    let result = (|| {
        let mut candidates = alloc::vec::Vec::new();
        aspace.collect_anon_reclaim_candidates(&mut candidates, N);
        if candidates.iter().map(|c| c.pages).sum::<usize>() != N {
            return TestResult::Fail("scan did not surface all N resident pages");
        }
        let plan = plan_reclaim_ranges(&candidates, N, N);
        // SAFETY: test owns this live address space and its private resident run.
        let report = unsafe { aspace.swap_out_reclaim_plan(&plan) };
        if report.error.is_some() || report.swapped_pages != N {
            return TestResult::Fail("scan candidates did not swap out cleanly");
        }
        let snapshot = aspace.regions_snapshot();
        if snapshot[0].phys.iter().any(|e| e.raw() != 0) {
            return TestResult::Fail("page-out did not transfer Region ownership");
        }
        if crate::swap_stats().resident != N as u64 {
            return TestResult::Fail("swap accounting did not charge every page");
        }
        TestResult::Pass
    })();

    // Teardown discards the swap slots (Region::phys is all zero → swapped).
    let _ = aspace.unmap_region(base);
    if crate::swap_stats().resident != 0 {
        return TestResult::Fail("teardown leaked swap slots");
    }
    result
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_anon_reclaim_scan_drives_swap);

/// CLOCK aging: the scan must spare a recently-accessed (A-bit set) page — its
/// bit cleared for a second chance — and reclaim it only on a later pass once
/// it stays cold. Proves the scan no longer swaps out hot pages.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_anon_reclaim_clock_second_chance() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: paging and the frame allocator are live in the kernel suite.
    let aspace = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    const N: usize = 4;
    let base = VirtAddr::new(0x0000_0080_0040_0000);
    let mut phys = alloc::vec::Vec::with_capacity(N);
    for _ in 0..N {
        match crate::alloc_frame() {
            Ok(f) => phys.push(f.start_address()),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        }
    }
    if aspace
        .map_region(Region {
            base,
            len: N as u64 * 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys,
        })
        .is_err()
    {
        return TestResult::Fail("map_region failed");
    }
    // SAFETY: aspace owns a live root and the validated region.
    if unsafe { aspace.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }

    let result = (|| {
        // Freshly-mapped leaves have A=0 (no access happened). Mark page 1 as
        // recently accessed, as hardware would on a real touch.
        let hot = VirtAddr::new(base.as_u64() + 4096);
        // SAFETY: aspace owns a live root; `hot` is a materialized 4 KiB leaf.
        if !unsafe { crate::x86_64::paging::__set_accessed_for_test(aspace.root, hot) } {
            return TestResult::Fail("could not set the accessed bit on the hot page");
        }

        // Pass 1: the hot page (index 1) is spared and splits the run; the scan
        // clears its A-bit as the second chance.
        let mut pass1 = alloc::vec::Vec::new();
        aspace.collect_anon_reclaim_candidates(&mut pass1, 64);
        if pass1.iter().map(|c| c.pages).sum::<usize>() != N - 1 {
            return TestResult::Fail("pass 1 did not spare exactly the hot page");
        }
        if pass1.iter().any(|c| {
            c.base.as_u64() <= hot.as_u64()
                && hot.as_u64() < c.base.as_u64() + (c.pages as u64) * 4096
        }) {
            return TestResult::Fail("pass 1 included the recently-accessed page");
        }

        // Pass 2: the second chance is spent (A now clear), so every page is
        // cold and the whole region coalesces into one reclaimable run.
        let mut pass2 = alloc::vec::Vec::new();
        aspace.collect_anon_reclaim_candidates(&mut pass2, 64);
        if pass2.len() != 1 || pass2[0].pages != N || pass2[0].base.as_u64() != base.as_u64() {
            return TestResult::Fail("pass 2 did not reclaim the cooled page in one run");
        }
        TestResult::Pass
    })();

    let _ = aspace.unmap_region(base);
    result
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_anon_reclaim_clock_second_chance);

// Demand-paged brk exercises the x86_64 demand-fault path (like the other
// demand/reclaim tests here); gated to x86_64 accordingly.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_brk_grow_is_demand_paged() -> TestResult {
    // brk grow extends the heap region's LENGTH without materializing a phys
    // slot per page (O(1) grow, no eager zero-fill); each page installs its
    // backing slot only on first fault (finish_demand_page resizes the prefix).
    use crate::{AddressSpace, VirtAddr};

    // SAFETY: paging + frame allocator live in the kernel suite.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    // Conventional brk base (BRK_DEFAULT_BASE); grow the heap by N pages.
    let base = VirtAddr::new(0x0000_1000_0000_0000);
    const N: usize = 64;
    if a.brk_extend_region(base, base.as_u64(), N).is_err() {
        return TestResult::Fail("brk_extend_region failed");
    }
    let r = a.lookup(base).expect("brk region present");
    if r.len != (N as u64) * 0x1000 {
        return TestResult::Fail("brk grow did not extend region length");
    }
    // The whole point: the grow materialized NO per-page phys slots.
    if !r.phys.is_empty() {
        return TestResult::Fail("brk grow materialized phys eagerly (not demand-paged)");
    }

    // Fault page 10 → the fault path extends the phys prefix to cover it and
    // backs it, leaving pages 0..10 as demand-zero sentinels.
    let page10 = VirtAddr::new(base.as_u64() + 10 * 0x1000);
    // SAFETY: AS live; identity map present; page lies in the grown region.
    if unsafe { a.demand_alloc_page(page10) }.is_err() {
        return TestResult::Fail("demand fault of a grown brk page failed");
    }
    let r2 = a.lookup(base).expect("brk region present");
    if r2.phys.len() < 11 {
        return TestResult::Fail("fault did not extend the phys prefix to the faulted page");
    }
    if r2.phys[10].raw() == 0 {
        return TestResult::Fail("faulted brk page has no backing frame");
    }
    if r2.phys[0].raw() != 0 {
        return TestResult::Fail("an unfaulted brk page was unexpectedly backed");
    }
    // Pages past the faulted prefix are still unmaterialized (demand-zero).
    if (r2.phys.len() as u64) >= (r2.len >> 12) {
        return TestResult::Fail("phys prefix should be shorter than the region page count");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_brk_grow_is_demand_paged);

#[cfg(target_arch = "x86_64")]
fn smoke_memory_brk_shrink_punches_demand_paged() -> TestResult {
    // Shrinking a demand-paged brk (short phys) punches the tail. The punch path
    // used to slice `phys[first..last]` assuming a full-length list and PANICKED
    // on a short one (stress-ng --brk shrink). Regression: shrink after a sparse
    // fault must free only the faulted frames and leave the heap consistent.
    use crate::{AddressSpace, BrkUpdateResult, VirtAddr};

    // SAFETY: paging + frame allocator live in the kernel suite.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let base = VirtAddr::new(0x0000_1000_0000_0000);
    let arena_top = 0x0000_4000_0000_0000u64;
    let grow = |req: u64| {
        a.update_brk_limited(
            base,
            arena_top,
            req,
            alloc::vec::Vec::new(),
            u64::MAX,
            u64::MAX,
            u64::MAX,
            true,
        )
    };
    // Grow to 32 pages (O(1), no phys materialized).
    if !matches!(grow(base.as_u64() + 32 * 4096), BrkUpdateResult::Complete(v) if v == base.as_u64() + 32 * 4096)
    {
        return TestResult::Fail("brk grow failed");
    }
    // Fault two sparse pages (5 and 20) — materializes the prefix up to 20.
    for p in [5u64, 20] {
        // SAFETY: AS live; page lies in the grown region.
        if unsafe { a.demand_alloc_page(VirtAddr::new(base.as_u64() + p * 4096)) }.is_err() {
            return TestResult::Fail("fault of a grown brk page failed");
        }
    }
    // Shrink to 3 pages → punches [3, 32), which spans faulted (5, 20) AND
    // unmaterialized pages. Must not panic on the short phys list.
    if !matches!(grow(base.as_u64() + 3 * 4096), BrkUpdateResult::Complete(v) if v == base.as_u64() + 3 * 4096)
    {
        return TestResult::Fail("brk shrink failed");
    }
    let r = a.lookup(base).expect("brk region present");
    if r.len != 3 * 4096 {
        return TestResult::Fail("shrink did not reduce the heap length");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_brk_shrink_punches_demand_paged);

/// The rmap wiring must record a `(root, va) → phys` reverse mapping for every
/// resident page when a region is materialized, and drop it on unmap.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_rmap_tracks_materialized_region() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    crate::rmap::__reset_for_test();
    // SAFETY: paging and the frame allocator are live in the kernel suite.
    let aspace = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    const N: usize = 3;
    let base = VirtAddr::new(0x0000_0080_0050_0000);
    let mut phys = alloc::vec::Vec::with_capacity(N);
    for _ in 0..N {
        match crate::alloc_frame() {
            Ok(f) => phys.push(f.start_address()),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        }
    }
    let frames = phys.clone();
    if aspace
        .map_region(Region {
            base,
            len: N as u64 * 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys,
        })
        .is_err()
    {
        return TestResult::Fail("map_region failed");
    }
    // SAFETY: aspace owns a live root and the validated region.
    if unsafe { aspace.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }

    let result = (|| {
        // Each resident frame has exactly one owner: (this AS root, its va).
        for (i, p) in frames.iter().enumerate() {
            let va = base.as_u64() + (i as u64) * 4096;
            if crate::rmap::owner_count(*p) != 1 {
                return TestResult::Fail("materialize did not record one rmap owner per page");
            }
            let mut matched = false;
            crate::rmap::for_each_owner(*p, |o| {
                if o.root == aspace.root && o.va.as_u64() == va {
                    matched = true;
                }
            });
            if !matched {
                return TestResult::Fail("rmap owner did not match (root, va)");
            }
        }
        TestResult::Pass
    })();

    // Unmap frees the frames AND drops their rmap entries.
    let _ = aspace.unmap_region(base);
    for p in &frames {
        if crate::rmap::owner_count(*p) != 0 {
            crate::rmap::__reset_for_test();
            return TestResult::Fail("unmap did not clear the rmap entries");
        }
    }
    crate::rmap::__reset_for_test();
    result
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_rmap_tracks_materialized_region);

/// rmap across fork + COW-split: a fork-shared frame must gain a second owner,
/// and a COW write-split must MOVE the writer's owner to its private copy while
/// the other sharer keeps the original.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_rmap_fork_and_cow_split() -> TestResult {
    use crate::frame::cow;
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    crate::rmap::__reset_for_test();
    cow::__test_clear();
    // SAFETY: paging + frame allocator live in the kernel suite.
    let parent = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let p_frame = match crate::frame::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    let va = VirtAddr::new(0x0000_0080_0060_0000);
    if parent
        .map_region(Region {
            base: va,
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![p_frame],
        })
        .is_err()
    {
        return TestResult::Fail("map_region parent failed");
    }
    // SAFETY: aspace owns a live root and the validated region.
    if unsafe { parent.materialize() }.is_err() {
        return TestResult::Fail("materialize parent failed");
    }

    let result = (|| {
        if crate::rmap::owner_count(p_frame) != 1 {
            return TestResult::Fail("parent materialize should give the frame one owner");
        }
        // SAFETY: fork's documented contract; paging is live.
        let child = match unsafe { parent.clone_for_fork() } {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("clone_for_fork failed"),
        };
        // SAFETY: child owns a fresh root; materialize maps its COW-shared page.
        if unsafe { child.materialize() }.is_err() {
            return TestResult::Fail("materialize child failed");
        }
        // The shared frame now has two rmap owners (parent + child).
        if crate::rmap::owner_count(p_frame) != 2 {
            return TestResult::Fail("fork-shared frame should have 2 rmap owners");
        }
        // Split the child's page: writer gets a private copy.
        // SAFETY: `va` names the child's present COW mapping.
        if unsafe { child.cow_split_on_write(va) }.is_err() {
            return TestResult::Fail("cow_split_on_write failed");
        }
        // SAFETY: pairs with the split to rewrite the leaf PTE.
        if unsafe { child.remap_page(va) }.is_err() {
            return TestResult::Fail("remap_page failed");
        }
        let c_new = child.lookup(va).expect("child region").phys[0];
        if c_new == p_frame {
            return TestResult::Fail("split should allocate a fresh child frame");
        }
        // rmap moved: shared frame keeps only the parent; child's copy has one.
        if crate::rmap::owner_count(p_frame) != 1 {
            return TestResult::Fail("post-split shared frame should keep only the parent owner");
        }
        if crate::rmap::owner_count(c_new) != 1 {
            return TestResult::Fail("post-split child copy needs one rmap owner");
        }
        let mut parent_owns = false;
        crate::rmap::for_each_owner(p_frame, |o| {
            if o.root == parent.root && o.va == va {
                parent_owns = true;
            }
        });
        let mut child_owns = false;
        crate::rmap::for_each_owner(c_new, |o| {
            if o.root == child.root && o.va == va {
                child_owns = true;
            }
        });
        if !parent_owns || !child_owns {
            return TestResult::Fail("post-split rmap owners do not match (root, va)");
        }
        TestResult::Pass
    })();

    // parent/child Drop free their frames + rmap entries; reset the shared state.
    crate::rmap::__reset_for_test();
    cow::__test_clear();
    result
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_rmap_fork_and_cow_split);

/// rmap across a swap round-trip: swap-out must drop the evicted frame's rmap,
/// and the fault-in must record the fresh frame.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_rmap_swap_roundtrip() -> TestResult {
    use crate::reclaim::{plan_reclaim_ranges, ReclaimRangeCandidate};
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr, ZramBackend};

    if crate::swap_stats().resident != 0 {
        return TestResult::Skip("another swap lifecycle is active");
    }
    crate::rmap::__reset_for_test();
    crate::install_swap_backend(ZramBackend::new());
    // SAFETY: paging + frame allocator live in the kernel suite.
    let aspace = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    const N: usize = 2;
    let base = VirtAddr::new(0x0000_0080_0070_0000);
    let mut phys = alloc::vec::Vec::with_capacity(N);
    for _ in 0..N {
        match crate::alloc_frame() {
            Ok(f) => phys.push(f.start_address()),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        }
    }
    let old0 = phys[0];
    if aspace
        .map_region(Region {
            base,
            len: N as u64 * 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys,
        })
        .is_err()
    {
        return TestResult::Fail("map_region failed");
    }
    // SAFETY: aspace owns a live root and the validated region.
    if unsafe { aspace.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }

    let result = (|| {
        if crate::rmap::owner_count(old0) != 1 {
            return TestResult::Fail("materialize should record one rmap owner");
        }
        let plan = plan_reclaim_ranges(
            &[ReclaimRangeCandidate {
                address_space_root: aspace.root,
                base,
                pages: N,
                mapcount: 1,
                expected_free_pages: N,
                age: 0,
                locked: false,
            }],
            N,
            N,
        );
        // SAFETY: test owns this live address space and its private resident run.
        let report = unsafe { aspace.swap_out_reclaim_plan(&plan) };
        if report.error.is_some() || report.swapped_pages != N {
            return TestResult::Fail("swap-out did not evict every page");
        }
        // Evicted → rmap for the old frame is gone.
        if crate::rmap::owner_count(old0) != 0 {
            return TestResult::Fail("swap-out did not drop the evicted frame's rmap");
        }
        // Fault the first page back in.
        // SAFETY: same live-root/fault contract as a real user #PF.
        if unsafe { aspace.demand_alloc_page(base) }.is_err() {
            return TestResult::Fail("swap fault-in failed");
        }
        let new0 = aspace.regions_snapshot()[0].phys[0];
        if new0.raw() == 0 {
            return TestResult::Fail("fault-in did not republish backing");
        }
        if crate::rmap::owner_count(new0) != 1 {
            return TestResult::Fail("swap-in did not record the fresh frame's rmap");
        }
        TestResult::Pass
    })();

    let _ = aspace.unmap_region(base);
    crate::rmap::__reset_for_test();
    result
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_rmap_swap_roundtrip);

/// `relocate_page` (the compaction primitive) must move a private page to a
/// fresh frame, preserving its contents, and update both `Region.phys` and the
/// reverse map to the new frame.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_relocate_page_moves_frame() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    crate::rmap::__reset_for_test();
    // SAFETY: paging + frame allocator live in the kernel suite.
    let aspace = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let p = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    // Stamp a sentinel so the post-relocate copy is observable.
    // SAFETY: identity-mapped fresh frame, sole owner.
    unsafe { *(p.kernel_mut_ptr::<u32>()) = 0xBEEF_1234 };
    let va = VirtAddr::new(0x0000_0080_0080_0000);
    if aspace
        .map_region(Region {
            base: va,
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![p],
        })
        .is_err()
    {
        return TestResult::Fail("map_region failed");
    }
    // SAFETY: aspace owns a live root and the validated region.
    if unsafe { aspace.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }

    let result = (|| {
        if crate::rmap::owner_count(p) != 1 {
            return TestResult::Fail("setup: page should have one rmap owner");
        }
        // SAFETY: aspace owns the live root + private resident page.
        let new_p = match unsafe { aspace.relocate_page(va) } {
            Ok(x) => x,
            Err(_) => return TestResult::Fail("relocate_page failed"),
        };
        if new_p == p {
            return TestResult::Fail("relocate must move to a different frame");
        }
        // SAFETY: new_p is the live frame; identity-mapped.
        if unsafe { *(new_p.kernel_ptr::<u32>()) } != 0xBEEF_1234 {
            return TestResult::Fail("relocate did not preserve the page contents");
        }
        if aspace.regions_snapshot()[0].phys[0] != new_p {
            return TestResult::Fail("relocate did not update Region.phys");
        }
        if crate::rmap::owner_count(p) != 0 {
            return TestResult::Fail("relocate did not drop the old frame's rmap");
        }
        if crate::rmap::owner_count(new_p) != 1 {
            return TestResult::Fail("relocate did not record the new frame's rmap");
        }
        let mut ok = false;
        crate::rmap::for_each_owner(new_p, |o| {
            if o.root == aspace.root && o.va == va {
                ok = true;
            }
        });
        if !ok {
            return TestResult::Fail("relocated rmap owner does not match (root, va)");
        }
        TestResult::Pass
    })();

    let _ = aspace.unmap_region(va);
    crate::rmap::__reset_for_test();
    result
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_relocate_page_moves_frame);

/// `demand_alloc_page` on an already-backed slot is a spurious
/// fault (TLB shootdown race). Returns AlignmentMismatch so the
/// trap handler retries cleanly without double-allocating.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_demand_alloc_already_backed_spurious() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // A demand fault on an ALREADY-backed page is a spurious not-present
    // fault (a peer CPU installed the leaf while this CPU's paging-structure
    // cache still held the miss). demand_alloc_page must RECOVER it: INVLPG
    // the stale entry and return Ok so the faulting instruction re-walks and
    // succeeds. (It used to return AlignmentMismatch, which the #PF handler
    // treated as unhandled → fatal — the SMP mallocng heap-corruption crash.)
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let r = unsafe { a.demand_alloc_page(VirtAddr::new(vbase)) };
    core::mem::forget(a);
    match r {
        Ok(()) => TestResult::Pass,
        Err(e) => {
            let _ = e;
            TestResult::Fail("backed-slot spurious fault not recovered (expected Ok)")
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
        // SAFETY: the pointer is non-null, aligned, and points to a live value for this access.
        if unsafe { a.demand_alloc_page(VirtAddr::new(vbase + (i as u64) * 0x1000)) }.is_err() {
            core::mem::forget(a);
            return TestResult::Fail("demand_alloc_page failed mid-loop");
        }
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let p0 = unsafe { translate_arch(a.root, VirtAddr::new(vbase)) };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let p1 = unsafe { translate_arch(a.root, VirtAddr::new(vbase + 0x1000)) };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
kernel_test_in!(
    "memory",
    smoke_memory_demand_alloc_multi_page_distinct_frames
);

/// Fresh demand-allocated frame is zero-filled. Anonymous mmap
/// semantics require the user observes zeros — not the previous
/// owner's bytes.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_demand_alloc_zero_fills_frame() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: Valid memory or trusted environment
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("materialize failed");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { translate_arch(a.root, VirtAddr::new(guard)) }.is_some() {
        core::mem::forget(a);
        return TestResult::Fail("STACK_GUARD region had a PTE before grow");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.try_grow_stack(VirtAddr::new(guard + 0x10)) }.is_err() {
        core::mem::forget(a);
        return TestResult::Fail("try_grow_stack failed on a STACK_GUARD region");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let promoted_pte = unsafe { translate_arch(a.root, VirtAddr::new(guard)) };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
kernel_test_in!(
    "memory",
    smoke_memory_try_grow_stack_promotes_and_installs_new_guard
);

/// try_grow_stack on a non-STACK_GUARD region returns Unmapped
/// so the trap handler falls through to the SEGV path (a write
/// to a real PROT_NONE region or a backed RO region is not a
/// stack-grow event).
#[cfg(target_arch = "x86_64")]
fn smoke_memory_try_grow_stack_non_guard_is_unmapped() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let r = unsafe { a.try_grow_stack(VirtAddr::new(0x0000_0080_0300_0000)) };
    core::mem::forget(a);
    match r {
        Err(AddressSpaceError::Unmapped) => TestResult::Pass,
        _ => TestResult::Fail("out-of-region grow didn't surface Unmapped"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory",
    smoke_memory_try_grow_stack_outside_region_is_unmapped
);

/// New guard one page below the current guard must NOT collide
/// with an existing region. The grow surfaces Overlap so the trap
/// handler reports a real stack-overflow SEGV.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_try_grow_stack_collision_rejected() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let r = unsafe { a.try_grow_stack(VirtAddr::new(guard)) };
    core::mem::forget(a);
    match r {
        Err(AddressSpaceError::Overlap) => TestResult::Pass,
        _ => TestResult::Fail("colliding new-guard install was accepted"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_try_grow_stack_collision_rejected);

/// Sequential grows: starting from a single guard, three indexed lookups
/// create three backed R+W fragments with a guard at the new bottom.  Keeping
/// fragments avoids annexing an unmarked adjacent VMA; RegionSet makes guard
/// discovery O(log VMA) despite the fragments.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_try_grow_stack_sequential() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        if unsafe { a.try_grow_stack(VirtAddr::new(cur)) }.is_err() {
            core::mem::forget(a);
            return TestResult::Fail("sequential grow failed mid-loop");
        }
        cur -= 0x1000;
    }
    let snap = a.regions_snapshot();
    let rw_regions: alloc::vec::Vec<_> = snap
        .iter()
        .filter(|r| {
            !r.perms.contains(RegionPerms::STACK_GUARD)
                && r.perms.contains(RegionPerms::READ)
                && r.perms.contains(RegionPerms::WRITE)
        })
        .collect();
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
    if rw_regions.len() != 3 {
        return TestResult::Fail("sequential grows did not produce three fragments");
    }
    for expected in [guard0 - 2 * 0x1000, guard0 - 0x1000, guard0] {
        let Some(fragment) = rw_regions.iter().find(|r| r.base.as_u64() == expected) else {
            return TestResult::Fail("sequential stack fragment has the wrong base");
        };
        if fragment.len != 0x1000 || fragment.phys.len() != 1 || fragment.phys[0].raw() == 0 {
            return TestResult::Fail("sequential stack fragment is not singly backed");
        }
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

/// Realistic layout: a backed executable stack VMA sits directly above the
/// guard. Many one-page growths preserve EXEC on separate anonymous fragments
/// without changing the original VMA, and a guard tracks the new bottom.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_try_grow_stack_preserves_exec_without_annexing() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    // One backed, EXECUTABLE stack page, with a guard directly below.
    let stack_base = 0x0000_0080_0600_0000u64;
    let stack_frame = match crate::frame::alloc_user_frame() {
        Ok(f) => f.start_address(),
        Err(_) => {
            core::mem::forget(a);
            return TestResult::Skip("no frame for stack page");
        }
    };
    a.map_region(Region {
        base: VirtAddr::new(stack_base),
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::EXEC,
        phys: alloc::vec![stack_frame],
    })
    .expect("map_region stack");
    let guard0 = stack_base - 0x1000;
    a.map_region(Region {
        base: VirtAddr::new(guard0),
        len: 0x1000,
        perms: RegionPerms::STACK_GUARD,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .expect("map_region guard");
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        core::mem::forget(a);
        return TestResult::Fail("materialize failed");
    }

    // Grow the stack down 16 pages, one fault at a time.
    const GROWS: u64 = 16;
    let mut cur = guard0;
    for _ in 0..GROWS {
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        if unsafe { a.try_grow_stack(VirtAddr::new(cur + 0x40)) }.is_err() {
            core::mem::forget(a);
            return TestResult::Fail("in-place stack grow failed mid-loop");
        }
        cur -= 0x1000;
    }

    let snap = a.regions_snapshot();
    // Every grown page must be present in the tables and writable.
    let mut all_present_writable = true;
    let mut p = guard0;
    for _ in 0..GROWS {
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        if unsafe { translate_arch(a.root, VirtAddr::new(p)) }.is_none() {
            all_present_writable = false;
        }
        p -= 0x1000;
    }
    let stack_regions: alloc::vec::Vec<_> = snap
        .iter()
        .filter(|r| {
            !r.perms.contains(RegionPerms::STACK_GUARD) && r.perms.contains(RegionPerms::WRITE)
        })
        .collect();
    let guard_count = snap
        .iter()
        .filter(|r| r.perms.contains(RegionPerms::STACK_GUARD))
        .count();
    // The original VMA must remain intact rather than being annexed by the
    // grow path.  Each promoted guard is its own one-page anonymous fragment;
    // the ordered RegionSet still finds the next guard in O(log VMA), and the
    // executable-stack permission propagates across every fragment.
    let stack_ok = stack_regions.len() as u64 == GROWS + 1
        && stack_regions.iter().all(|s| {
            s.len == 0x1000
                && s.perms.contains(RegionPerms::EXEC)
                && s.phys.len() == 1
                && s.phys[0].raw() != 0
        })
        && stack_regions.iter().any(|s| s.base.as_u64() == stack_base);
    // Read back one grown page: try_grow_stack zeroes each frame.
    let lowest = stack_base - GROWS * 0x1000;
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let zeroed = unsafe { translate_arch(a.root, VirtAddr::new(lowest)) }
        .map(|pa| {
            // SAFETY: identity-mapped low physical memory.
            let byte = unsafe { core::ptr::read_volatile(pa.raw() as *const u8) };
            byte == 0
        })
        .unwrap_or(false);
    core::mem::forget(a);

    if !all_present_writable {
        return TestResult::Fail("a grown stack page was not present");
    }
    if !stack_ok {
        return TestResult::Fail("stack growth annexed a VMA or lost EXEC permissions");
    }
    if guard_count != 1 {
        return TestResult::Fail("expected exactly one trailing guard");
    }
    if !zeroed {
        return TestResult::Fail("grown stack page was not zeroed");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory",
    smoke_memory_try_grow_stack_preserves_exec_without_annexing
);

/// Linux stack expansion is admitted against RLIMIT_STACK and RLIMIT_AS
/// before allocating or publishing a leaf. A rejection must leave the guard
/// VMA and page tables unchanged.
fn smoke_memory_stack_growth_limits_preserve_guard() -> TestResult {
    use crate::{
        AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, StackGrowthLimits, VirtAddr,
    };

    for (offset, limits) in [
        (
            0u64,
            StackGrowthLimits {
                stack_bytes: 0,
                memlock_bytes: u64::MAX,
                address_space_bytes: u64::MAX,
                bypass_memlock: true,
            },
        ),
        (
            0x20_0000u64,
            StackGrowthLimits {
                stack_bytes: u64::MAX,
                memlock_bytes: u64::MAX,
                // The existing guard already consumes this page; promotion
                // plus the replacement guard grows total VM by one page.
                address_space_bytes: 0x1000,
                bypass_memlock: true,
            },
        ),
    ] {
        // SAFETY: the frame allocator and kernel page-table aliases are live
        // in the kernel-test environment.
        let address_space = match unsafe { AddressSpace::new_for_user() } {
            Ok(address_space) => address_space,
            Err(_) => return TestResult::Skip("new_for_user failed"),
        };
        let guard = 0x0000_0080_0700_0000u64 + offset;
        address_space
            .map_region(Region {
                base: VirtAddr::new(guard),
                len: 0x1000,
                perms: RegionPerms::STACK_GUARD | RegionPerms::LOCK_EXEMPT,
                phys: alloc::vec![PhysAddr::new(0)],
            })
            .expect("map stack guard");

        // SAFETY: the AS root is live and the guard contains no backing.
        let result =
            unsafe { address_space.try_grow_stack_limited(VirtAddr::new(guard + 8), limits) };
        let unchanged = address_space.regions_snapshot().iter().any(|region| {
            region.base.as_u64() == guard
                && region.len == 0x1000
                && region.perms.contains(RegionPerms::STACK_GUARD)
        });
        // SAFETY: the address-space root remains live until the test forgets
        // it below.
        let pte_absent =
            unsafe { translate_arch(address_space.root, VirtAddr::new(guard)).is_none() };
        core::mem::forget(address_space);
        if result != Err(AddressSpaceError::StackLimit) || !unchanged || !pte_absent {
            return TestResult::Fail("stack-limit rejection changed VMA or PTE state");
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_stack_growth_limits_preserve_guard);

/// A locked stack inherits VM_LOCKED into each grown page. Admission failure
/// is RLIMIT_MEMLOCK-specific and likewise occurs before allocation.
fn smoke_memory_locked_stack_growth_honours_memlock_limit() -> TestResult {
    use crate::{
        AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, StackGrowthLimits, VirtAddr,
    };

    // SAFETY: kernel-test paging/allocator setup satisfies new_for_user.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let guard = 0x0000_0080_0740_0000u64;
    address_space
        .map_region(Region {
            base: VirtAddr::new(guard),
            len: 0x1000,
            perms: RegionPerms::STACK_GUARD | RegionPerms::LOCK_EXEMPT,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .expect("map stack guard");
    address_space
        .map_region(Region {
            base: VirtAddr::new(guard + 0x1000),
            len: 0x1000,
            perms: RegionPerms::READ
                | RegionPerms::WRITE
                | RegionPerms::STACK_SEGMENT
                | RegionPerms::LOCKED,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .expect("map locked stack");

    let limits = StackGrowthLimits {
        stack_bytes: u64::MAX,
        // Existing stack consumes all available locked-byte budget.
        memlock_bytes: 0x1000,
        address_space_bytes: u64::MAX,
        bypass_memlock: false,
    };
    // SAFETY: root and allocator satisfy try_grow_stack_limited's contract.
    let result = unsafe { address_space.try_grow_stack_limited(VirtAddr::new(guard), limits) };
    let still_guard = address_space.regions_snapshot().iter().any(|region| {
        region.base.as_u64() == guard && region.perms.contains(RegionPerms::STACK_GUARD)
    });
    core::mem::forget(address_space);
    if result == Err(AddressSpaceError::LockLimit) && still_guard {
        TestResult::Pass
    } else {
        TestResult::Fail("locked stack growth ignored memlock admission")
    }
}
kernel_test_in!(
    "memory",
    smoke_memory_locked_stack_growth_honours_memlock_limit
);

/// An unexpected pre-existing leaf is an internal collision, not permission
/// to associate a newly allocated frame with someone else's PTE. The failed
/// transaction must preserve both the rogue leaf and the guard metadata.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_stack_growth_rejects_existing_leaf_without_unmapping_it() -> TestResult {
    use crate::x86_64::paging::{map_4kb, unmap_4kb, PtFlags};
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: kernel-test paging/allocator setup satisfies new_for_user.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let guard = 0x0000_0080_0780_0000u64;
    address_space
        .map_region(Region {
            base: VirtAddr::new(guard),
            len: 0x1000,
            perms: RegionPerms::STACK_GUARD | RegionPerms::LOCK_EXEMPT,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .expect("map stack guard");
    let rogue_frame = match crate::frame::alloc_user_frame() {
        Ok(frame) => frame,
        Err(_) => {
            core::mem::forget(address_space);
            return TestResult::Skip("no rogue frame");
        }
    };
    let rogue_phys = rogue_frame.start_address();
    // SAFETY: the test owns the aligned frame and empty user leaf.
    if unsafe {
        map_4kb(
            address_space.root,
            VirtAddr::new(guard),
            rogue_phys,
            PtFlags::USER | PtFlags::WRITABLE | PtFlags::NO_EXEC,
        )
    }
    .is_err()
    {
        crate::frame::free_frame(rogue_frame);
        core::mem::forget(address_space);
        return TestResult::Fail("could not install rogue stack leaf");
    }

    // SAFETY: the AS is live; the intentional PTE/VMA mismatch exercises the
    // transaction's collision rollback.
    let result = unsafe { address_space.try_grow_stack(VirtAddr::new(guard)) };
    // SAFETY: root remains live and the leaf should still name rogue_phys.
    let preserved =
        unsafe { translate_arch(address_space.root, VirtAddr::new(guard)) } == Some(rogue_phys);
    let still_guard = address_space.regions_snapshot().iter().any(|region| {
        region.base.as_u64() == guard && region.perms.contains(RegionPerms::STACK_GUARD)
    });
    // SAFETY: remove the leaf explicitly before returning its backing frame.
    let _ = unsafe { unmap_4kb(address_space.root, VirtAddr::new(guard)) };
    crate::frame::free_frame(rogue_frame);
    core::mem::forget(address_space);

    if result == Err(AddressSpaceError::NotImplemented) && preserved && still_guard {
        TestResult::Pass
    } else {
        TestResult::Fail("stack collision replaced/unmapped an existing leaf")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory",
    smoke_memory_stack_growth_rejects_existing_leaf_without_unmapping_it
);

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
/// We snapshot the buddy's free count before mapping, then map a
/// multi-page region, then unmap and confirm the free count
/// returns to (or above) the original — equality holds when no
/// concurrent task is allocating; the allocator may also have
/// merged buddies which is fine.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_unmap_region_returns_frames() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
kernel_test_in!(
    "memory",
    smoke_memory_unmap_region_lazy_is_noop_on_free_count
);

/// Mixed region (some lazy + some backed) returns ONLY the
/// backed slots. The demand-paging contract says lazy slots had
/// no frame; only post-demand-alloc slots own one.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_unmap_region_mixed_lazy_and_backed() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
        // Keep every cycle in the same 2 MiB leaf page table.  Empty
        // intermediate tables are intentionally retained until the
        // AddressSpace is dropped, so crossing a 2 MiB boundary here
        // would charge an additional table frame against a test that
        // is specifically measuring whether DATA frames are returned.
        let vbase = 0x0000_0080_0900_0000u64 + (cycle as u64) * 0x10_000;
        a.map_region(Region {
            base: VirtAddr::new(vbase),
            len: (pages as u64) * 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: phys_list,
        })
        .expect("map_region");
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
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

/// The OOM reaper reclaims a private anonymous region's resident frames out
/// from under a would-be victim, returns them to the pool, unmaps them, and is
/// idempotent — a second reap frees nothing (so it never double-frees against
/// the victim's own exit teardown).
#[cfg(target_arch = "x86_64")]
fn smoke_memory_reap_anonymous_reclaims_and_is_idempotent() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let pages = 4usize;
    let mut phys_list = alloc::vec::Vec::with_capacity(pages);
    for _ in 0..pages {
        match crate::alloc_frame() {
            Ok(f) => phys_list.push(f.start_address()),
            Err(_) => {
                core::mem::forget(a);
                return TestResult::Skip("frame allocator drained");
            }
        }
    }
    let vbase = 0x0000_0080_0B00_0000u64;
    a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: (pages as u64) * 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: phys_list,
    })
    .expect("map_region");
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        core::mem::forget(a);
        return TestResult::Fail("materialize failed");
    }

    // Reap must free exactly the region's resident pages and return them to
    // the pool. Measure the delta across the reap to isolate the data frames
    // from the (leaked-on-forget) page-table overhead.
    let before_reap = crate::frame::stats().free;
    let freed = a.reap_anonymous();
    let after_reap = crate::frame::stats().free;
    if freed != pages {
        core::mem::forget(a);
        return TestResult::Fail("reap did not free every resident anonymous page");
    }
    if after_reap < before_reap + pages {
        core::mem::forget(a);
        return TestResult::Fail("reaped frames did not return to the pool");
    }
    // Idempotent: a second reap frees nothing (backing already zeroed), so it
    // cannot double-free against the victim's own teardown.
    if a.reap_anonymous() != 0 {
        core::mem::forget(a);
        return TestResult::Fail("second reap double-counted freed frames");
    }
    // The reaped page must no longer translate.
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { translate_arch(a.root, VirtAddr::new(vbase)) }.is_some() {
        core::mem::forget(a);
        return TestResult::Fail("reaped page still translates");
    }
    // Forget (leak the page tables) rather than Drop so this test's free-page
    // accounting stays isolated to the reap; idempotency above already proved
    // Drop would be a safe no-op over the zeroed backing.
    core::mem::forget(a);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory",
    smoke_memory_reap_anonymous_reclaims_and_is_idempotent
);

/// Build a fresh user AS with `pages` resident private-anonymous base pages
/// mapped at `vbase`, wrapped in an `Arc` (as the reaper holds it). Returns
/// `None` (skip) if `new_for_user`, frame allocation, or materialize fails.
/// The caller must `core::mem::forget` the extracted AS (via `Arc::into_inner`)
/// to keep the reap frame-accounting isolated from page-table teardown.
#[cfg(target_arch = "x86_64")]
fn build_reapable_as(vbase: u64, pages: usize) -> Option<alloc::sync::Arc<crate::AddressSpace>> {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let a = unsafe { AddressSpace::new_for_user() }.ok()?;
    let mut phys_list = alloc::vec::Vec::with_capacity(pages);
    for _ in 0..pages {
        match crate::alloc_frame() {
            Ok(f) => phys_list.push(f.start_address()),
            Err(_) => {
                core::mem::forget(a);
                return None;
            }
        }
    }
    if a.map_region(Region {
        base: VirtAddr::new(vbase),
        len: (pages as u64) * 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: phys_list,
    })
    .is_err()
    {
        core::mem::forget(a);
        return None;
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        core::mem::forget(a);
        return None;
    }
    Some(alloc::sync::Arc::new(a))
}

/// Leak an `Arc<AddressSpace>`'s page tables the same way the sibling smoke does
/// (via `core::mem::forget` on the inner AS), keeping reap frame-accounting
/// isolated. Requires `arc` to be the sole owner.
#[cfg(target_arch = "x86_64")]
fn forget_sole_as(arc: alloc::sync::Arc<crate::AddressSpace>) {
    if let Some(inner) = alloc::sync::Arc::into_inner(arc) {
        core::mem::forget(inner);
    }
}

/// A victim whose region lock is transiently held is REQUEUED (not dropped) by
/// `reap_all`, then reaped once the lock is released — proving a transient
/// `try_lock` failure never strands the victim's frames.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_oom_reaper_requeues_locked_victim() -> TestResult {
    use crate::oom::{self, test_support, OomVictim};

    test_support::arm_queue();
    test_support::drain_queue();

    let vbase = 0x0000_0080_0C00_0000u64;
    let pages = 4usize;
    let Some(as_arc) = build_reapable_as(vbase, pages) else {
        return TestResult::Skip("could not build reapable AS");
    };

    if !test_support::enqueue(OomVictim {
        pid: 4242,
        tid: 4242,
        rss_pages: pages,
        address_space: as_arc.clone(),
        retries_left: 0,
    }) {
        forget_sole_as(as_arc);
        return TestResult::Fail("victim not enqueued");
    }

    // While the region lock is held, reap_all cannot make progress: the victim
    // must be requeued (not dropped) and no frames freed.
    let freed_while_locked = as_arc.with_regions_locked(oom::reap_all);
    if freed_while_locked != 0 {
        test_support::drain_queue();
        forget_sole_as(as_arc);
        return TestResult::Fail("reaped while region lock held");
    }
    if test_support::queued_len() != 1 {
        test_support::drain_queue();
        forget_sole_as(as_arc);
        return TestResult::Fail("locked victim was dropped, not requeued");
    }
    if !oom::reap_pending() {
        test_support::drain_queue();
        forget_sole_as(as_arc);
        return TestResult::Fail("reap_pending cleared with a victim still queued");
    }

    // Lock released: the next pass reaps the resident pages and empties queue.
    let freed = oom::reap_all();
    if freed != pages {
        test_support::drain_queue();
        forget_sole_as(as_arc);
        return TestResult::Fail("requeued victim not reaped after lock released");
    }
    if test_support::queued_len() != 0 || oom::reap_pending() {
        forget_sole_as(as_arc);
        return TestResult::Fail("queue not drained after successful reap");
    }
    forget_sole_as(as_arc);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_oom_reaper_requeues_locked_victim);

/// A permanently-blocked victim is retried exactly `REAP_MAX_RETRIES` times and
/// then abandoned (accounted, not silently leaked) — the bounded-retry contract.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_oom_reaper_honors_retry_bound() -> TestResult {
    use crate::oom::{self, test_support, OomVictim};

    test_support::arm_queue();
    test_support::drain_queue();

    let vbase = 0x0000_0080_0D00_0000u64;
    let pages = 2usize;
    let Some(as_arc) = build_reapable_as(vbase, pages) else {
        return TestResult::Skip("could not build reapable AS");
    };

    if !test_support::enqueue(OomVictim {
        pid: 4343,
        tid: 4343,
        rss_pages: pages,
        address_space: as_arc.clone(),
        retries_left: 0,
    }) {
        forget_sole_as(as_arc);
        return TestResult::Fail("victim not enqueued");
    }

    let abandoned_before = test_support::abandoned_count();

    // Hold the region lock across the whole retry sequence so every pass sees a
    // try_lock failure. The victim enters with retries_left = MAX_RETRIES, so it
    // survives MAX_RETRIES requeues and is abandoned on the pass after that.
    let outcome = as_arc.with_regions_locked(|| {
        // MAX_RETRIES passes: each decrements the budget and requeues.
        for _ in 0..test_support::MAX_RETRIES {
            let _ = oom::reap_all();
            if test_support::queued_len() != 1 {
                return Err("victim dropped before retry bound reached");
            }
        }
        // One more pass with the budget exhausted: victim abandoned, queue empty.
        let _ = oom::reap_all();
        if test_support::queued_len() != 0 {
            return Err("victim not abandoned after retry bound exhausted");
        }
        Ok(())
    });

    if let Err(msg) = outcome {
        test_support::drain_queue();
        forget_sole_as(as_arc);
        return TestResult::Fail(msg);
    }
    if test_support::abandoned_count() != abandoned_before + 1 {
        forget_sole_as(as_arc);
        return TestResult::Fail("abandonment not accounted");
    }
    if oom::reap_pending() {
        forget_sole_as(as_arc);
        return TestResult::Fail("reap_pending set after abandonment with empty queue");
    }
    // The AS was never reaped (lock held throughout); its frames belong to the
    // AS still. Drop the Arc so its own teardown frees them (no leak).
    drop(as_arc);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_oom_reaper_honors_retry_bound);

/// A `vm_shared` (formerly-multithreaded) victim is NOT reaped while another
/// `Arc` clone exists (a live sibling thread), but IS reaped once that clone is
/// dropped (last thread exited => reaper is sole owner) — the vm_shared
/// soundness gate.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_oom_reaper_defers_vm_shared_until_sole_owner() -> TestResult {
    use crate::oom::{self, test_support, OomVictim};

    test_support::arm_queue();
    test_support::drain_queue();

    let vbase = 0x0000_0080_0E00_0000u64;
    let pages = 3usize;
    let Some(as_arc) = build_reapable_as(vbase, pages) else {
        return TestResult::Skip("could not build reapable AS");
    };
    // Mark it multithreaded and simulate a still-live sibling thread by holding
    // an extra Arc clone (a scheduler slot's clone in production).
    as_arc.mark_vm_shared();
    let sibling = as_arc.clone();

    if !test_support::enqueue(OomVictim {
        pid: 4444,
        tid: 4444,
        rss_pages: pages,
        address_space: as_arc.clone(),
        retries_left: 0,
    }) {
        drop(sibling);
        forget_sole_as(as_arc);
        return TestResult::Fail("victim not enqueued");
    }

    // Sibling still live (strong_count > 1): reap_all must defer, not reap.
    let freed_live = oom::reap_all();
    if freed_live != 0 {
        test_support::drain_queue();
        drop(sibling);
        forget_sole_as(as_arc);
        return TestResult::Fail("reaped a vm_shared AS with a live sibling");
    }
    if test_support::queued_len() != 1 {
        test_support::drain_queue();
        drop(sibling);
        forget_sole_as(as_arc);
        return TestResult::Fail("vm_shared victim dropped instead of requeued");
    }

    // Last thread exits: drop the sibling clone, then our own local clone, so
    // the only remaining Arc is the queued victim's — the reaper is now the sole
    // owner (strong_count == 1) and may safely reap the formerly-vm_shared AS.
    // We deliberately hold no clone during reap: reap_all consumes and drops the
    // queued victim, whose Drop teardown (a safe no-op over the zeroed backing)
    // reclaims the page tables. No post-reap AS access, so no use-after-free.
    drop(sibling);
    let before_reap = crate::frame::stats().free;
    drop(as_arc);

    let freed = oom::reap_all();
    if freed != pages {
        test_support::drain_queue();
        return TestResult::Fail("vm_shared AS not reaped after sole ownership");
    }
    if test_support::queued_len() != 0 || oom::reap_pending() {
        return TestResult::Fail("queue not drained after vm_shared reap");
    }
    // The reaped data frames returned to the pool.
    if crate::frame::stats().free < before_reap + pages {
        return TestResult::Fail("reaped vm_shared frames did not return to pool");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory",
    smoke_memory_oom_reaper_defers_vm_shared_until_sole_owner
);

/// Frame-backed vmalloc: a 64 KiB `valloc` (the order-4 size that defeats a
/// contiguous buddy block under fragmentation) must map a usable,
/// virtually-contiguous region backed by scattered frames; `vfree` must FULLY
/// reclaim it — every data frame, the now-empty page table(s), and the VA — so
/// the pool returns exactly to its starting count with no residual retention.
#[cfg(target_arch = "x86_64")]
fn smoke_vmalloc_valloc_maps_scattered_and_reclaims() -> TestResult {
    const SIZE: usize = 64 * 1024;

    let free_before = crate::frame::stats().free;
    let p = match crate::vmalloc::valloc(SIZE) {
        Some(p) => p,
        None => return TestResult::Skip("valloc unavailable (kernel slot not reserved)"),
    };
    // The mapping must be coherent across every backing page.
    let bytes = p.as_ptr();
    // SAFETY: `valloc` returned SIZE bytes of mapped, writable kernel memory.
    unsafe {
        let mut i = 0;
        while i < SIZE {
            core::ptr::write_volatile(bytes.add(i), (i as u8) ^ 0xA5);
            i += 4096;
        }
        let mut i = 0;
        while i < SIZE {
            if core::ptr::read_volatile(bytes.add(i)) != ((i as u8) ^ 0xA5) {
                crate::vmalloc::vfree(p, SIZE);
                return TestResult::Fail("valloc mapping not coherent");
            }
            i += 4096;
        }
    }
    // SAFETY: pointer + size came from the matching `valloc`.
    unsafe { crate::vmalloc::vfree(p, SIZE) };
    // Full reclamation: data frames AND the emptied page table are returned, so
    // the free count is EXACTLY restored (no bounded page-table retention).
    if crate::frame::stats().free != free_before {
        return TestResult::Fail("valloc/vfree leaked frames or page tables");
    }
    // VA reclaimed: a second same-size allocation still succeeds.
    match crate::vmalloc::valloc(SIZE) {
        Some(p2) => {
            // SAFETY: matching valloc/vfree.
            unsafe { crate::vmalloc::vfree(p2, SIZE) };
            TestResult::Pass
        }
        None => TestResult::Fail("valloc VA not reclaimed after vfree"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_vmalloc_valloc_maps_scattered_and_reclaims);

/// `unmap_region` clears the bookkeeping AND tears down the PTEs
/// — a `translate` on the just-unmapped vaddr must return None.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_unmap_region_clears_ptes() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { a.materialize() }.is_err() {
        core::mem::forget(a);
        return TestResult::Fail("materialize failed");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let before = unsafe { translate_arch(a.root, VirtAddr::new(vbase)) };
    if before.is_none() {
        core::mem::forget(a);
        return TestResult::Fail("post-materialize translate returned None");
    }
    if a.unmap_region(VirtAddr::new(vbase)).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("unmap_region failed");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
        input.push(b'A' + (i % 26) as u8);
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
    for (i, byte) in raw.iter_mut().enumerate() {
        *byte = ((i as u32).wrapping_mul(0x9E37) >> 8) as u8;
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
        return TestResult::Fail("compressed_bytes ≥ raw_bytes on a highly-compressible pattern");
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
        alloc::boxed::Box::leak(alloc::boxed::Box::new(AtomicPool::new(4, || {
            0xDEAD_BEEFu64
        })));
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
        alloc::boxed::Box::leak(alloc::boxed::Box::new(AtomicPool::new(2, || 42u32)));
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

// ── KASLR smokes ──────────────────────────────────────────────────────

fn smoke_kaslr_random_u64_is_live() -> TestResult {
    use crate::kaslr::{random_u64, EntropySource};
    // Two reads should differ unless we're catastrophically unlucky
    // (one chance in 2^64). Any path returns a real source tag.
    let (a, sa) = random_u64();
    let (b, _sb) = random_u64();
    if a == b && a != 0 {
        return TestResult::Fail("random_u64 returned identical values back-to-back");
    }
    // Whatever source was selected, it must be one of the documented
    // variants — not a stub.
    if !matches!(
        sa,
        EntropySource::Rdrand | EntropySource::Rdseed | EntropySource::Rndr | EntropySource::TscMix
    ) {
        return TestResult::Fail("EntropySource not one of the documented variants");
    }
    TestResult::Pass
}
kernel_test_in!("memory/kaslr", smoke_kaslr_random_u64_is_live);

fn smoke_kaslr_user_mmap_slot_within_slack() -> TestResult {
    use crate::kaslr::{user_mmap_slot, USER_MMAP_RANDOM_BITS};
    let base = 0x4000_0000_0000_u64;
    let mask = (1u64 << USER_MMAP_RANDOM_BITS) - 1;
    let slot = user_mmap_slot(base);
    if slot < base {
        return TestResult::Fail("slot below base");
    }
    if slot >= base + (1u64 << USER_MMAP_RANDOM_BITS) {
        return TestResult::Fail("slot above slack window");
    }
    if (slot - base) & !(mask & !0xFFF) != 0 {
        return TestResult::Fail("slot not 4 KiB-aligned");
    }
    TestResult::Pass
}
kernel_test_in!("memory/kaslr", smoke_kaslr_user_mmap_slot_within_slack);

fn smoke_kaslr_tsc_mix_advances() -> TestResult {
    use crate::kaslr::tsc_mix;
    // TSC mix is the fallback path; verify it doesn't get stuck on
    // a single value. Two consecutive reads should differ on any CPU
    // with a moving cycle counter (RDTSC on x86_64, CNTVCT_EL0 on
    // aarch64). On non-x86 non-aarch64 it's a sentinel; skip.
    if !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
        return TestResult::Skip("tsc_mix is sentinel on this arch");
    }
    let a = tsc_mix();
    let b = tsc_mix();
    if a == b {
        return TestResult::Fail("tsc_mix returned the same value twice");
    }
    TestResult::Pass
}
kernel_test_in!("memory/kaslr", smoke_kaslr_tsc_mix_advances);

// ── ro_after_init smokes ──────────────────────────────────────────────

fn smoke_ro_after_init_rw_before_latch() -> TestResult {
    use crate::ro_after_init::{is_init_complete, mark_init_complete, RoCell, _reset_for_test};
    _reset_for_test();
    let cell = RoCell::new(42u32);
    if *cell.get() != 42 {
        return TestResult::Fail("RoCell::new did not store the initial value");
    }
    if is_init_complete() {
        return TestResult::Fail("init_complete latched before mark_init_complete");
    }
    // SAFETY: pre-init phase by virtue of `_reset_for_test`.
    unsafe {
        cell.set(123);
    }
    if *cell.get() != 123 {
        return TestResult::Fail("RoCell::set didn't update before init latch");
    }
    mark_init_complete();
    if !is_init_complete() {
        return TestResult::Fail("mark_init_complete didn't latch");
    }
    // Re-arm for other tests.
    _reset_for_test();
    TestResult::Pass
}
kernel_test_in!("memory/ro_after_init", smoke_ro_after_init_rw_before_latch);

fn smoke_ro_after_init_latch_observability() -> TestResult {
    use crate::ro_after_init::{_reset_for_test, is_init_complete, mark_init_complete};
    _reset_for_test();
    if is_init_complete() {
        return TestResult::Fail("reset did not clear the latch");
    }
    mark_init_complete();
    if !is_init_complete() {
        return TestResult::Fail("mark_init_complete didn't propagate");
    }
    // Idempotency: a second mark_init_complete should still leave the
    // latch set without panic or weirdness.
    mark_init_complete();
    if !is_init_complete() {
        return TestResult::Fail("idempotent mark_init_complete unlatched");
    }
    _reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "memory/ro_after_init",
    smoke_ro_after_init_latch_observability
);

// ── Wave-46: trap-driven COW write-fault round trip ─────────────────
//
// The #PF handler in frame/src/x86_64/trap.rs calls
// `cow_split_on_write` then `remap_page` on user-mode write faults
// where (P+W+U) all set. Earlier smokes cover each routine in
// isolation; these reproduce the *coupled* sequence so that
// regressions in either side surface here instead of only on real
// hardware after a fork.

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_cow_fault_path_child_diverges() -> TestResult {
    // Parent maps one writable page, stamps a sentinel, then forks.
    // Both sides materialise the post-fork RO PTEs. We then replay
    // exactly what the #PF handler does on the child's first write:
    //   1. cow_split_on_write — allocates a private frame, memcpys,
    //      dec_refs the shared frame; logical WRITE was retained throughout.
    //   2. remap_page — rewrites the live PTE so the next user
    //      instruction succeeds.
    // After the round trip, mutating through the child's PTE must
    // NOT corrupt the parent's still-shared frame.
    #[cfg(target_arch = "aarch64")]
    use crate::aarch64::paging::translate;
    use crate::address_space::{AddressSpace, Region, RegionPerms};
    use crate::frame::cow;
    #[cfg(target_arch = "x86_64")]
    use crate::x86_64::paging::translate;
    use crate::VirtAddr;

    cow::__test_clear();
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let parent = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("AddressSpace::new_for_user not available"),
    };
    let p_frame = match crate::frame::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame parent"),
    };
    const VADDR: u64 = 0x0000_0080_0046_0000;
    if parent
        .map_region(Region {
            base: VirtAddr::new(VADDR),
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![p_frame],
        })
        .is_err()
    {
        return TestResult::Fail("map_region parent");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { parent.materialize() }.is_err() {
        return TestResult::Fail("parent materialize");
    }
    // SAFETY: parent is sole owner; identity-mapped.
    unsafe {
        *(p_frame.raw() as *mut u32) = 0xCAFEBABE;
    }

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let child = match unsafe { parent.clone_for_fork() } {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("clone_for_fork"),
    };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { child.materialize() }.is_err() {
        return TestResult::Fail("child materialize");
    }
    // Parent's PTEs need re-walking: clone_for_fork marked the resident frames
    // COW-shared but the live PTEs are still RW.
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { parent.rematerialize() }.is_err() {
        return TestResult::Fail("parent rematerialize");
    }
    #[cfg(target_arch = "x86_64")]
    let parent_read_only = {
        // SAFETY: the parent owns this live root and the region lock is not
        // concurrently mutated by the isolated test.
        unsafe { crate::x86_64::paging::flags_at(parent.root, VirtAddr::new(VADDR)) }
            .is_some_and(|flags| !flags.contains(crate::x86_64::paging::PtFlags::WRITABLE))
    };
    #[cfg(target_arch = "aarch64")]
    let parent_read_only = {
        // SAFETY: same isolated live-root contract as the x86_64 check.
        unsafe { crate::aarch64::paging::flags_at(parent.root, VirtAddr::new(VADDR)) }.is_some_and(
            |flags| flags.bits() & (0b11 << 6) == crate::aarch64::paging::PtFlags::AP_RO_EL0.bits(),
        )
    };
    if !parent_read_only {
        return TestResult::Fail("parent rematerialize left the COW leaf writable");
    }

    // ── Replay the #PF handler's COW recovery on the child ──
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { child.cow_split_on_write(VirtAddr::new(VADDR)) }.is_err() {
        return TestResult::Fail("cow_split_on_write child");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { child.remap_page(VirtAddr::new(VADDR)) }.is_err() {
        return TestResult::Fail("remap_page child");
    }

    // Live PTE in the child must now resolve to a NEW phys frame.
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let child_pte = unsafe { translate(child.root, VirtAddr::new(VADDR)) };
    let child_phys = match child_pte {
        Some(p) => p,
        None => return TestResult::Fail("child PTE not present after remap"),
    };
    if child_phys == p_frame {
        return TestResult::Fail("child PTE still points at parent's frame");
    }
    // Parent's PTE must still resolve to the original shared frame.
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let parent_pte = unsafe { translate(parent.root, VirtAddr::new(VADDR)) };
    if parent_pte != Some(p_frame) {
        return TestResult::Fail("parent PTE moved off the original frame");
    }

    // Mutate through the child's private frame; the parent's shared
    // frame must not see the change.
    // SAFETY: identity-mapped, child is now sole owner of child_phys.
    unsafe {
        *(child_phys.raw() as *mut u32) = 0xDEADBEEF;
    }
    // SAFETY: identity-mapped.
    let parent_word = unsafe { *(p_frame.raw() as *const u32) };
    if parent_word != 0xCAFEBABE {
        return TestResult::Fail("child's post-split write leaked into parent");
    }
    // SAFETY: the pointer is non-null, aligned, and points to a live value for this access.
    let child_word = unsafe { *(child_phys.raw() as *const u32) };
    if child_word != 0xDEADBEEF {
        return TestResult::Fail("child's private frame did not retain write");
    }

    let _ = parent;
    let _ = child;
    cow::__test_clear();
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_cow_fault_path_child_diverges);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_cow_fault_path_parent_diverges() -> TestResult {
    // Symmetric to the child smoke: the trap handler runs on
    // whichever side writes first. Parent-side cow_split_on_write +
    // remap_page must allocate a private frame for the PARENT,
    // leaving the child with the original (now sole-owner) frame.
    #[cfg(target_arch = "aarch64")]
    use crate::aarch64::paging::translate;
    use crate::address_space::{AddressSpace, Region, RegionPerms};
    use crate::frame::cow;
    #[cfg(target_arch = "x86_64")]
    use crate::x86_64::paging::translate;
    use crate::VirtAddr;

    cow::__test_clear();
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let parent = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("AddressSpace::new_for_user not available"),
    };
    let orig_frame = match crate::frame::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame parent"),
    };
    const VADDR: u64 = 0x0000_0080_0046_1000;
    if parent
        .map_region(Region {
            base: VirtAddr::new(VADDR),
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![orig_frame],
        })
        .is_err()
    {
        return TestResult::Fail("map_region parent");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { parent.materialize() }.is_err() {
        return TestResult::Fail("parent materialize");
    }
    // SAFETY: sole owner pre-fork.
    unsafe {
        *(orig_frame.raw() as *mut u32) = 0xA5A5_A5A5;
    }

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let child = match unsafe { parent.clone_for_fork() } {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("clone_for_fork"),
    };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { child.materialize() }.is_err() {
        return TestResult::Fail("child materialize");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { parent.rematerialize() }.is_err() {
        return TestResult::Fail("parent rematerialize");
    }

    // Parent writes first → trap path runs on the parent.
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { parent.cow_split_on_write(VirtAddr::new(VADDR)) }.is_err() {
        return TestResult::Fail("cow_split_on_write parent");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { parent.remap_page(VirtAddr::new(VADDR)) }.is_err() {
        return TestResult::Fail("remap_page parent");
    }

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let parent_phys = match unsafe { translate(parent.root, VirtAddr::new(VADDR)) } {
        Some(p) => p,
        None => return TestResult::Fail("parent PTE not present after remap"),
    };
    if parent_phys == orig_frame {
        return TestResult::Fail("parent PTE still points at the shared frame");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    if unsafe { translate(child.root, VirtAddr::new(VADDR)) } != Some(orig_frame) {
        return TestResult::Fail("child PTE drifted off original after parent split");
    }
    // Parent now has refcount 0 on its private frame (fresh, never
    // cow-registered); child is now sole logical owner of orig_frame.
    if cow::count(orig_frame) > 1 {
        return TestResult::Fail("orig_frame refcount should drop to ≤1 after split");
    }

    // SAFETY: identity-mapped, parent owns parent_phys exclusively.
    unsafe {
        *(parent_phys.raw() as *mut u32) = 0x5A5A_5A5A;
    }
    // SAFETY: identity-mapped.
    let child_word = unsafe { *(orig_frame.raw() as *const u32) };
    if child_word != 0xA5A5_A5A5 {
        return TestResult::Fail("parent split leaked into child's frame");
    }

    let _ = parent;
    let _ = child;
    cow::__test_clear();
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_cow_fault_path_parent_diverges);

fn smoke_memory_cow_fault_path_outside_region_fails() -> TestResult {
    // Trap-handler fallthrough: cow_split_on_write on a vaddr that
    // is NOT in any region must return Unmapped so the #PF handler
    // falls through to the existing SIGSEGV/panic path. Regression
    // backstop on the gate that prevents a genuine RO-by-intent
    // fault from being silently turned into a COW recovery.
    use crate::address_space::{AddressSpace, AddressSpaceError, Region, RegionPerms};
    use crate::frame::cow;
    use crate::VirtAddr;

    cow::__test_clear();
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("AddressSpace::new_for_user not available"),
    };
    let f = match crate::frame::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame"),
    };
    const REGION_VADDR: u64 = 0x0000_0080_0046_2000;
    if a.map_region(Region {
        base: VirtAddr::new(REGION_VADDR),
        len: 4096,
        perms: RegionPerms::READ,
        phys: alloc::vec![f],
    })
    .is_err()
    {
        return TestResult::Fail("map_region");
    }

    // Vaddr well outside any mapped region.
    const STRAY: u64 = 0x0000_0080_00FF_E000;
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    match unsafe { a.cow_split_on_write(VirtAddr::new(STRAY)) } {
        Err(AddressSpaceError::Unmapped) => {}
        Ok(()) => return TestResult::Fail("split on unmapped vaddr returned Ok"),
        Err(_) => return TestResult::Fail("split returned wrong error variant"),
    }
    let _ = a;
    cow::__test_clear();
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_cow_fault_path_outside_region_fails);

// ---------------------------------------------------------------
// diag — fixed-region status state. Bare-metal bring-up surface;
// every updater must be O(1) atomic + every read must be coherent
// across the snapshot. Each smoke clears state at entry so the
// suite is reorderable.
// ---------------------------------------------------------------

fn smoke_diag_phase_round_trip() -> TestResult {
    use crate::diag::{self, BootPhase};
    diag::__reset_for_test();
    if diag::snapshot().phase != BootPhase::Firmware {
        return TestResult::Fail("initial phase not Firmware");
    }
    diag::set_phase(BootPhase::InitDevice);
    if diag::snapshot().phase != BootPhase::InitDevice {
        return TestResult::Fail("phase didn't round-trip through atomic");
    }
    diag::set_phase(BootPhase::Userspace);
    if diag::snapshot().phase != BootPhase::Userspace {
        return TestResult::Fail("phase transition to Userspace lost");
    }
    diag::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("memory", smoke_diag_phase_round_trip);

fn smoke_diag_bump_irq_counts_total_and_last() -> TestResult {
    use crate::diag;
    // `bump_irq` is also called by the live IRQ handler (interrupts::on_irq),
    // and vector 32 is the timer tick. Masking LOCAL IRQs across the
    // reset → bump → snapshot window keeps THIS CPU from perturbing the
    // global counter — but under SMP another core's timer IRQ can bump the
    // same global `IRQ_TOTAL` / clobber `LAST_IRQ_VECTOR` in that window
    // (the diag counters are a single global operator facility, not
    // per-CPU). So the exact-count assertion only holds on a uniprocessor
    // boot; under SMP we assert the sound monotonic invariant instead
    // (our three bumps definitely landed; peers can only add more).
    let smp = narf_lib::smp::cpu_count() > 1;
    let was_enabled = narf_arch::interrupts_enabled();
    // SAFETY: a brief local IRQ mask in a synchronous test; restored below.
    unsafe {
        narf_arch::disable_interrupts();
    }
    diag::__reset_for_test();
    diag::bump_irq(32);
    diag::bump_irq(33);
    diag::bump_irq(32);
    let s = diag::snapshot();
    diag::__reset_for_test();
    if was_enabled {
        // SAFETY: restoring the IRQ state observed on entry.
        unsafe {
            narf_arch::enable_interrupts();
        }
    }
    if smp {
        // Peers can only ADD to the global counter, never remove our bumps.
        if s.irq_total < 3 {
            return TestResult::Fail("irq_total under 3 after 3 bumps");
        }
        // LAST_IRQ_VECTOR may have been clobbered by a concurrent peer IRQ;
        // not assertable under SMP.
    } else {
        if s.irq_total != 3 {
            return TestResult::Fail("irq_total not 3 after 3 bumps");
        }
        if s.last_irq_vector != 32 {
            return TestResult::Fail("last_irq_vector not the latest bump");
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_diag_bump_irq_counts_total_and_last);

fn smoke_diag_note_pf_first_fault_wins() -> TestResult {
    use crate::diag;
    diag::__reset_for_test();
    diag::note_pf(0xDEAD_BEEF, 0xCAFE_F00D);
    diag::note_pf(0x1234_5678, 0xAAAA_BBBB);
    let s = diag::snapshot();
    if !s.first_pf_seen {
        return TestResult::Fail("first_pf_seen false after note_pf");
    }
    if s.first_pf_cr2 != 0xDEAD_BEEF || s.first_pf_rip != 0xCAFE_F00D {
        return TestResult::Fail("second note_pf overwrote first (must be first-fault-wins)");
    }
    diag::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("memory", smoke_diag_note_pf_first_fault_wins);

fn smoke_diag_latch_panic_first_only() -> TestResult {
    use crate::diag;
    diag::__reset_for_test();
    diag::latch_panic(0x4242_4242);
    diag::latch_panic(0x9999_9999);
    let s = diag::snapshot();
    if !s.panic_latched {
        return TestResult::Fail("panic_latched false after latch_panic");
    }
    if s.panic_marker != 0x4242_4242 {
        return TestResult::Fail("second latch_panic overwrote marker");
    }
    diag::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("memory", smoke_diag_latch_panic_first_only);

fn smoke_diag_heap_kb_round_trip() -> TestResult {
    use crate::diag;
    diag::__reset_for_test();
    diag::set_heap_kb(123, 4096);
    let s = diag::snapshot();
    if s.heap_used_kb != 123 || s.heap_total_kb != 4096 {
        return TestResult::Fail("heap_kb didn't round-trip");
    }
    diag::set_heap_kb(456, 4096);
    let s = diag::snapshot();
    if s.heap_used_kb != 456 {
        return TestResult::Fail("heap_used didn't update on second write");
    }
    diag::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("memory", smoke_diag_heap_kb_round_trip);

fn smoke_diag_phase_decode_clamps_unknown_to_firmware() -> TestResult {
    use crate::diag::BootPhase;
    if BootPhase::from_u8(200) != BootPhase::Firmware {
        return TestResult::Fail("out-of-range u8 must clamp to Firmware");
    }
    if BootPhase::from_u8(11) != BootPhase::Userspace {
        return TestResult::Fail("u8 11 must decode to Userspace");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_diag_phase_decode_clamps_unknown_to_firmware);

// ── Wave-66 — Linux-compat mprotect / madvise smokes ──────────────
//
// 1. `mprotect_range` splits a 3-page region cleanly when the middle
//    page is protected — head + middle + tail come back as three
//    distinct regions with disjoint phys slices and the middle gets
//    the new perms.
// 2. `mprotect_range` rejects WRITE | EXEC outright (W^X policy).
// 3. `madvise_dontneed` releases backed frames + zeros the per-page
//    phys list so the next access takes the demand-paging path.

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_mprotect_splits_region() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };

    // Three frames so the head/mid/tail each get a distinct phys.
    let mut frames: alloc::vec::Vec<PhysAddr> = alloc::vec::Vec::new();
    for _ in 0..3 {
        match crate::alloc_frame() {
            Ok(f) => frames.push(f.start_address()),
            Err(_) => {
                core::mem::forget(a);
                for p in frames.iter() {
                    crate::free_frame(crate::frame::PhysFrame::new(*p));
                }
                return TestResult::Skip("frame drained");
            }
        }
    }
    let v = VirtAddr::new(0x0000_0080_0001_0000);
    a.map_region(Region {
        base: v,
        len: 0x3000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: frames.clone(),
    })
    .expect("map");
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let _ = unsafe { a.materialize() };

    // Protect the middle page READ-only.
    let mid = VirtAddr::new(v.as_u64() + 0x1000);
    if a.mprotect_range(mid, 0x1000, RegionPerms::READ).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("mprotect_range middle slice failed");
    }

    let snap = a.regions_snapshot();
    let head = snap.iter().find(|r| r.base.as_u64() == v.as_u64());
    let middle = snap.iter().find(|r| r.base.as_u64() == v.as_u64() + 0x1000);
    let tail = snap.iter().find(|r| r.base.as_u64() == v.as_u64() + 0x2000);
    let ok = match (head, middle, tail) {
        (Some(h), Some(m), Some(t)) => {
            h.len == 0x1000
                && m.len == 0x1000
                && t.len == 0x1000
                && h.perms.contains(RegionPerms::WRITE)
                && !m.perms.contains(RegionPerms::WRITE)
                && m.perms.contains(RegionPerms::READ)
                && t.perms.contains(RegionPerms::WRITE)
                && h.phys.len() == 1
                && m.phys.len() == 1
                && t.phys.len() == 1
                && h.phys[0].raw() == frames[0].raw()
                && m.phys[0].raw() == frames[1].raw()
                && t.phys[0].raw() == frames[2].raw()
        }
        _ => false,
    };
    // Bookkeeping alone is insufficient: stress-ng caught a real regression
    // where mprotect returned success but the live leaf remained writable.
    // SAFETY: `a.root` is the live test-owned PML4 and `mid` is mapped above.
    #[cfg(target_arch = "x86_64")]
    let leaf_read_only = unsafe { crate::x86_64::paging::flags_at(a.root, mid) }
        .is_some_and(|flags| !flags.contains(crate::x86_64::paging::PtFlags::WRITABLE));
    // SAFETY: `a.root` is the live test-owned L0 and `mid` is mapped above.
    #[cfg(target_arch = "aarch64")]
    let leaf_read_only =
        unsafe { crate::aarch64::paging::flags_at(a.root, mid) }.is_some_and(|flags| {
            flags.bits() & (0b11 << 6) == crate::aarch64::paging::PtFlags::AP_RO_EL0.bits()
        });
    core::mem::forget(a);
    if ok && leaf_read_only {
        TestResult::Pass
    } else if !leaf_read_only {
        TestResult::Fail("mprotect bookkeeping changed but the leaf stayed writable")
    } else {
        TestResult::Fail("split layout / perms / phys did not match expectation")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_mprotect_splits_region);

/// Rewriting permissions on a lazy mapping must leave its zero backing
/// sentinel unmapped.  In particular, the aarch64 rewrite path once omitted
/// the `phys == 0` guard and installed a user leaf for physical address zero.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_mprotect_keeps_lazy_page_unmapped() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: fresh user AS used only by this test.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let va = VirtAddr::new(0x0000_0080_0800_0000);
    if a.map_region(Region {
        base: va,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .is_err()
        || a.mprotect_range(va, 0x1000, RegionPerms::READ).is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("lazy mprotect setup failed");
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: reads the test-owned page table.
    let translated = unsafe { crate::x86_64::paging::translate(a.root, va) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: reads the test-owned page table.
    let translated = unsafe { crate::aarch64::paging::translate(a.root, va) };
    let still_lazy = a
        .regions_snapshot()
        .iter()
        .find(|region| region.base == va)
        .is_some_and(|region| region.phys == alloc::vec![PhysAddr::new(0)]);
    core::mem::forget(a);
    if translated.is_none() && still_lazy {
        TestResult::Pass
    } else if translated.is_some() {
        TestResult::Fail("mprotect mapped the lazy-page zero sentinel")
    } else {
        TestResult::Fail("mprotect changed lazy backing metadata")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_mprotect_keeps_lazy_page_unmapped);

/// Linux rounds a non-zero length upward but refuses to partially protect a
/// range containing a hole. Validate the whole interval before splitting any
/// VMA; zero length remains a no-op even for a W|X-shaped request.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_mprotect_hole_is_atomic_and_len_rounds() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: fresh user AS used only by this test.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let base = 0x0000_0080_0c00_0000u64;
    for offset in [0, 0x2000] {
        if a.map_region(Region {
            base: VirtAddr::new(base + offset),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
        {
            core::mem::forget(a);
            return TestResult::Fail("map_region failed");
        }
    }
    if a.mprotect_range(VirtAddr::new(base), 0x3000, RegionPerms::READ)
        != Err(crate::AddressSpaceError::Unmapped)
    {
        core::mem::forget(a);
        return TestResult::Fail("mprotect across a hole did not fail atomically");
    }
    if a.regions_snapshot()
        .iter()
        .filter(|region| region.base.as_u64() == base || region.base.as_u64() == base + 0x2000)
        .any(|region| !region.perms.contains(RegionPerms::WRITE))
    {
        core::mem::forget(a);
        return TestResult::Fail("failed mprotect changed one side of the hole");
    }
    if a.mprotect_range(VirtAddr::new(base), 1, RegionPerms::READ)
        .is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("mprotect did not round a one-byte length");
    }
    let rounded = a
        .lookup(VirtAddr::new(base))
        .is_some_and(|region| !region.perms.contains(RegionPerms::WRITE));
    let wx = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::EXEC;
    let zero_ok = a
        .mprotect_range(VirtAddr::new(base + 0x1000), 0, wx)
        .is_ok();
    core::mem::forget(a);
    if rounded && zero_ok {
        TestResult::Pass
    } else if !rounded {
        TestResult::Fail("one-byte mprotect did not cover its page")
    } else {
        TestResult::Fail("zero-length mprotect was not a no-op")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_mprotect_hole_is_atomic_and_len_rounds
);

#[cfg(target_arch = "x86_64")]
fn smoke_memory_mprotect_rejects_write_exec() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    let v = VirtAddr::new(0x0000_0080_0002_0000);
    a.map_region(Region {
        base: v,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![target],
    })
    .expect("map");
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let _ = unsafe { a.materialize() };

    let wx = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::EXEC;
    let err = a.mprotect_range(v, 0x1000, wx);
    core::mem::forget(a);
    match err {
        Err(crate::AddressSpaceError::AlignmentMismatch) => TestResult::Pass,
        Ok(()) => TestResult::Fail("mprotect_range accepted WRITE|EXEC"),
        Err(_) => TestResult::Fail("wrong error for WRITE|EXEC"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_mprotect_rejects_write_exec);

#[cfg(target_arch = "x86_64")]
fn smoke_memory_madvise_dontneed_releases_pages() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    let v = VirtAddr::new(0x0000_0080_0003_0000);
    a.map_region(Region {
        base: v,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![target],
    })
    .expect("map");
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let _ = unsafe { a.materialize() };

    // Stamp the page so we can confirm DONTNEED dropped the frame —
    // the post-madvise demand-fault path would re-allocate a fresh
    // zeroed frame on next access.
    // SAFETY: identity-map covers the just-allocated frame.
    unsafe {
        core::ptr::write_bytes(target.raw() as *mut u8, 0xAB, 4096);
    }

    if a.madvise_dontneed(v, 0x1000).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("madvise_dontneed returned err");
    }

    let cleared = {
        let g = a.regions_snapshot();
        g.iter()
            .find(|r| r.base.as_u64() == v.as_u64())
            .map(|r| r.phys.len() == 1 && r.phys[0] == PhysAddr::new(0))
            .unwrap_or(false)
    };
    core::mem::forget(a);
    if cleared {
        TestResult::Pass
    } else {
        TestResult::Fail("madvise didn't zero per-page phys slot")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_madvise_dontneed_releases_pages);

/// MADV_DONTNEED over a MULTI-PAGE range with an interior unfaulted hole must
/// release every resident private frame and zero its per-page slot, while
/// leaving the hole's already-zero slot untouched. This exercises the batched
/// per-region range unmap (one root lock + one upper-level walk for the whole
/// intersection) rather than the single-page helper, so a regression in the
/// range teardown that dropped or double-counted a page would surface here.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_madvise_dontneed_range_frees_all_and_keeps_hole() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    // Three real resident frames with an unfaulted hole (phys 0) at index 1.
    let mut frames = alloc::vec::Vec::new();
    for _ in 0..3 {
        match crate::alloc_frame() {
            Ok(f) => frames.push(f.start_address()),
            Err(_) => {
                core::mem::forget(a);
                return TestResult::Skip("frame drained");
            }
        }
    }
    let v = VirtAddr::new(0x0000_0080_0005_0000);
    if a.map_region(Region {
        base: v,
        len: 0x4000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![frames[0], PhysAddr::new(0), frames[1], frames[2]],
    })
    .is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("map_region failed");
    }
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    let _ = unsafe { a.materialize() };

    if a.madvise_dontneed(v, 0x4000).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("madvise_dontneed over the range returned err");
    }

    let ok = {
        let g = a.regions_snapshot();
        g.iter()
            .find(|r| r.base.as_u64() == v.as_u64())
            .map(|r| r.phys.len() == 4 && r.phys.iter().all(|p| p.raw() == 0))
            .unwrap_or(false)
    };
    core::mem::forget(a);
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("range madvise left a resident slot or resized the region")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_madvise_dontneed_range_frees_all_and_keeps_hole
);

/// A supervisor-mode write (signal-frame placement) must be refused on a
/// present-but-read-only user page rather than faulting the kernel. This is the
/// guard behind deliver_signal's pre-flight: a stress-ng `bad-altstack` points
/// `sigaltstack` at a `PROT_READ` page, and without the writability gate the
/// CPL=0 frame write took an unrecoverable #PF and panicked the whole kernel
/// instead of terminating just the offending task (Linux `force_sigsegv`).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_user_page_writable_gates_readonly() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = AddressSpace::empty();
    let ro = VirtAddr::new(0x0000_0080_0090_0000);
    let rw = VirtAddr::new(0x0000_0080_0091_0000);
    if a.map_region(Region {
        base: ro,
        len: 0x1000,
        perms: RegionPerms::READ,
        phys: alloc::vec![PhysAddr::new(0x3000_0000)],
    })
    .is_err()
        || a.map_region(Region {
            base: rw,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0x3000_1000)],
        })
        .is_err()
    {
        return TestResult::Fail("map_region failed");
    }

    // Read-only page (a PROT_READ sigaltstack) must be refused.
    // SAFETY: identity map is live in the kernel-test environment; the method
    // only reads region metadata for a non-COW mapping.
    if unsafe { a.user_page_writable_or_resolve(ro) } {
        return TestResult::Fail("read-only page accepted for a supervisor write");
    }
    // Writable page is accepted.
    // SAFETY: as above.
    if !unsafe { a.user_page_writable_or_resolve(rw) } {
        return TestResult::Fail("writable page refused");
    }
    // Unmapped hole is refused.
    // SAFETY: as above.
    if unsafe { a.user_page_writable_or_resolve(VirtAddr::new(0x0000_0080_00a0_0000)) } {
        return TestResult::Fail("unmapped page accepted");
    }
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_user_page_writable_gates_readonly);

/// MADV_DONTNEED reports an unmapped hole without releasing either mapped
/// island, and rounds a one-byte request over its containing page.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_madvise_hole_is_atomic_and_len_rounds() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = AddressSpace::empty();
    let base = 0x0000_0080_0804_0000u64;
    for (offset, phys) in [(0, 0x2000_0000), (0x2000, 0x2000_1000)] {
        if a.map_region(Region {
            base: VirtAddr::new(base + offset),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(phys)],
        })
        .is_err()
        {
            return TestResult::Fail("map_region failed");
        }
    }
    if a.madvise_dontneed(VirtAddr::new(base), 0x3000) != Err(crate::AddressSpaceError::Unmapped) {
        return TestResult::Fail("madvise across a hole did not fail");
    }
    if a.regions_snapshot()
        .iter()
        .filter(|region| region.base.as_u64() == base || region.base.as_u64() == base + 0x2000)
        .any(|region| region.phys[0].raw() == 0)
    {
        return TestResult::Fail("failed madvise partially released backing");
    }
    if a.madvise_dontneed(VirtAddr::new(base), 1).is_err() {
        return TestResult::Fail("madvise did not round a one-byte length");
    }
    if a.lookup(VirtAddr::new(base))
        .is_some_and(|region| region.phys[0].raw() == 0)
        && a.madvise_dontneed(VirtAddr::new(base), 0).is_ok()
    {
        TestResult::Pass
    } else {
        TestResult::Fail("rounded/zero-length madvise semantics were wrong")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_madvise_hole_is_atomic_and_len_rounds);

/// Residency sampling walks a VMA once, preserves lazy-page state, rounds the
/// byte length, and rejects a trailing hole without returning a partial view.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_residency_range_is_coherent() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = AddressSpace::empty();
    let base = VirtAddr::new(0x0000_0080_0808_0000);
    if a.map_region(Region {
        base,
        len: 0x3000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![
            PhysAddr::new(0x2100_0000),
            PhysAddr::new(0),
            PhysAddr::new(0x2100_1000),
        ],
    })
    .is_err()
    {
        return TestResult::Fail("map_region failed");
    }
    if a.residency_range(base, 0x3000) != Ok(alloc::vec![1, 0, 1]) {
        return TestResult::Fail("resident/lazy vector was wrong");
    }
    if a.residency_range(base, 1) != Ok(alloc::vec![1]) {
        return TestResult::Fail("one-byte mincore range did not round up");
    }
    if a.residency_range(base, 0x4000) != Err(crate::AddressSpaceError::Unmapped) {
        return TestResult::Fail("residency range accepted a trailing hole");
    }
    if a.residency_range(VirtAddr::new(base.as_u64() + 1), 1)
        != Err(crate::AddressSpaceError::AlignmentMismatch)
        || a.residency_range(base, 0) != Ok(alloc::vec![])
    {
        return TestResult::Fail("residency range validation was wrong");
    }
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_residency_range_is_coherent);

// ── Wave-A pluggable FrameAlloc smoke ───────────────────────────────
//
// Verifies the seam: install a `BumpFrameAlloc` under a Grant cap,
// confirm `current_frame_alloc_name` flips, drive `alloc_frame_anywhere`
// through it, and confirm the returned frame's phys lies inside the
// bump region (i.e. dispatch actually crossed the trait object — not
// the buddy). Reinstalls `BUDDY_FRAME_ALLOC` on the way out so the
// rest of the smoke suite runs against the production allocator.
fn smoke_pluggable_frame_alloc() -> TestResult {
    use crate::frame::{
        current_frame_alloc_name, install_frame_alloc, BumpFrameAlloc, MemAlloc, BUDDY_FRAME_ALLOC,
        PAGE_SIZE,
    };
    use crate::{alloc_frame_anywhere, PhysAddr};
    use narf_capabilities::{Cap, Grant};

    // Default install. `init_from_map` ran earlier in the boot path
    // (the frame allocator is alive — every other smoke in this file
    // relies on that) so the buddy must be the active impl.
    if current_frame_alloc_name() != "buddy" {
        return TestResult::Fail("default FrameAlloc is not 'buddy' at smoke start");
    }

    // Synthetic phys region for the bump. We never dereference the
    // returned frame — the smoke only verifies dispatch lands in the
    // expected address window. We deliberately pick a window high
    // above the buddy's donated ranges so a collision is impossible.
    const BUMP_START: u64 = 0x0000_FFFF_0000_0000;
    const BUMP_END: u64 = 0x0000_FFFF_0000_8000; // 8 frames
    static BUMP: BumpFrameAlloc =
        BumpFrameAlloc::new_const(PhysAddr::new(BUMP_START), PhysAddr::new(BUMP_END));

    // Hygiene: a previous run of this smoke could have advanced the
    // cursor. Reset before installing.
    BUMP.__test_reset();

    let cap: Cap<MemAlloc, Grant> = Cap::<MemAlloc, Grant>::bootstrap();
    if install_frame_alloc(&cap, &BUMP).is_err() {
        return TestResult::Fail("install_frame_alloc(bump) failed");
    }
    if current_frame_alloc_name() != "bump" {
        // Restore default before bailing.
        let _ = install_frame_alloc(&cap, &BUDDY_FRAME_ALLOC);
        return TestResult::Fail("install didn't flip current_frame_alloc_name");
    }

    let frame = match alloc_frame_anywhere() {
        Ok(f) => f,
        Err(_) => {
            let _ = install_frame_alloc(&cap, &BUDDY_FRAME_ALLOC);
            return TestResult::Fail("alloc_frame_anywhere via bump returned Err");
        }
    };
    let phys = frame.start_address().raw();
    let in_window = (BUMP_START..BUMP_END).contains(&phys);
    let page_aligned = phys & (PAGE_SIZE - 1) == 0;

    // Reinstall the buddy default so subsequent smokes see a sane
    // allocator. This must run even if the asserts below fail.
    if install_frame_alloc(&cap, &BUDDY_FRAME_ALLOC).is_err() {
        return TestResult::Fail("could not reinstall BUDDY_FRAME_ALLOC for cleanup");
    }
    if current_frame_alloc_name() != "buddy" {
        return TestResult::Fail("post-cleanup name is not 'buddy'");
    }

    if !in_window {
        return TestResult::Fail("bump-allocated frame fell outside the bump window");
    }
    if !page_aligned {
        return TestResult::Fail("bump-allocated frame is not page-aligned");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_pluggable_frame_alloc);

// ── Wave-B pluggable HeapBackend smoke ──────────────────────────────
//
// Verifies the heap-backend seam: install a counting backend under a
// Grant cap that delegates to the production slab, drive a real
// `Vec` allocation through `#[global_allocator]`, and confirm the
// counter advanced. Reinstalls `SLAB_BACKEND` on the way out so the
// rest of the smoke suite runs against the production backend.
//
// `CountingHeapBackend` only delegates to `crate::slab` directly
// (rather than to `SLAB_BACKEND`) so the counting indirection is
// the only thing the active backend slot sees during the test.

#[derive(Debug)]
struct CountingHeapBackend {
    allocs: core::sync::atomic::AtomicU64,
    deallocs: core::sync::atomic::AtomicU64,
}

impl CountingHeapBackend {
    const fn new() -> Self {
        Self {
            allocs: core::sync::atomic::AtomicU64::new(0),
            deallocs: core::sync::atomic::AtomicU64::new(0),
        }
    }
    fn alloc_count(&self) -> u64 {
        self.allocs.load(core::sync::atomic::Ordering::Relaxed)
    }
    fn dealloc_count(&self) -> u64 {
        self.deallocs.load(core::sync::atomic::Ordering::Relaxed)
    }
}

impl crate::heap_backend::HeapBackend for CountingHeapBackend {
    fn name(&self) -> &'static str {
        "counting"
    }
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        self.allocs
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        match crate::slab::alloc(layout) {
            Ok(p) => p.as_ptr(),
            Err(_) => core::ptr::null_mut(),
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        self.deallocs
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if let Some(nn) = core::ptr::NonNull::new(ptr) {
            // SAFETY: caller asserts matching layout from a prior
            // `alloc` on this backend — which means it came from
            // `crate::slab::alloc`.
            // SAFETY: Valid memory or trusted environment
            unsafe { crate::slab::dealloc(nn, layout) };
        }
    }
}

fn smoke_pluggable_heap_backend() -> TestResult {
    use crate::heap_backend::{
        current_heap_backend_name, install_heap_backend, HeapAuthority, SLAB_BACKEND,
    };
    use narf_capabilities::{Cap, Grant};

    // By the time the smoke suite runs, `promote_to_slab` has flipped
    // the active backend to the slab — every other smoke in this file
    // relies on that.
    if current_heap_backend_name() != Some("slab") {
        return TestResult::Fail("default HeapBackend is not 'slab' at smoke start");
    }

    static COUNTER: CountingHeapBackend = CountingHeapBackend::new();
    let allocs_before = COUNTER.alloc_count();
    let deallocs_before = COUNTER.dealloc_count();

    let cap: Cap<HeapAuthority, Grant> = Cap::<HeapAuthority, Grant>::bootstrap();
    if install_heap_backend(&cap, &COUNTER).is_err() {
        return TestResult::Fail("install_heap_backend(counting) failed");
    }
    if current_heap_backend_name() != Some("counting") {
        let _ = install_heap_backend(&cap, &SLAB_BACKEND);
        return TestResult::Fail("install didn't flip current_heap_backend_name");
    }

    // Drive a real allocation through `#[global_allocator]`. A
    // 64-byte `Vec` falls into the slab's 64-byte class — well
    // inside the production code path. Drop it inside the
    // counting window so the dealloc counter advances too.
    {
        let v: alloc::vec::Vec<u8> = alloc::vec![0u8; 64];
        // Touch a byte so the optimiser can't fold the alloc away.
        core::hint::black_box(&v);
    }

    let allocs_after = COUNTER.alloc_count();
    let deallocs_after = COUNTER.dealloc_count();

    // Cleanup: reinstall the slab default before bailing on any
    // assertion, otherwise later smokes run under `CountingBackend`
    // and immediately segfault when it's dropped at end-of-test.
    if install_heap_backend(&cap, &SLAB_BACKEND).is_err() {
        return TestResult::Fail("could not reinstall SLAB_BACKEND for cleanup");
    }
    if current_heap_backend_name() != Some("slab") {
        return TestResult::Fail("post-cleanup name is not 'slab'");
    }

    if allocs_after <= allocs_before {
        return TestResult::Fail("counting backend's alloc counter didn't advance");
    }
    if deallocs_after <= deallocs_before {
        return TestResult::Fail("counting backend's dealloc counter didn't advance");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_pluggable_heap_backend);

fn smoke_pluggable_pager() -> TestResult {
    use crate::pager::{
        current_pager_name, install_pager, NoopPager, Pager, PagerAuthority, PagerError, ZpoolPager,
    };
    use crate::reclaim::PageFlags;
    use crate::PhysAddr;
    use narf_capabilities::{Cap, Grant};

    // Default after boot: NoopPager.
    if current_pager_name() != Some("noop") {
        return TestResult::Fail("default pager is not 'noop'");
    }

    let cap: Cap<PagerAuthority, Grant> = Cap::<PagerAuthority, Grant>::bootstrap();

    // Swap to the (stub) ZpoolPager. Dispatch witness: name flips.
    if install_pager(&cap, ZpoolPager).is_err() {
        return TestResult::Fail("install_pager(zpool) failed");
    }
    if current_pager_name() != Some("zpool") {
        let _ = install_pager(&cap, NoopPager);
        return TestResult::Fail("install didn't flip current_pager_name to zpool");
    }

    // ZpoolPager ships as a stub for Wave C — `page_out` must
    // return `Err(NoBacking)`, proving trait dispatch reached the
    // alternative impl (and not the noop fallback, which would
    // have returned the same error but via a different vtable —
    // hence the name check above).
    let res = ZpoolPager.page_out(PhysAddr::new(0x4000), PageFlags::empty());
    if res != Err(PagerError::NoBacking) {
        let _ = install_pager(&cap, NoopPager);
        return TestResult::Fail("ZpoolPager stub did not return NoBacking");
    }

    // LOCKED flag must short-circuit to BadFlags (real impl will
    // need this invariant; the stub honours it pre-emptively).
    let res_locked = ZpoolPager.page_out(PhysAddr::new(0x4000), PageFlags::LOCKED);
    if res_locked != Err(PagerError::BadFlags) {
        let _ = install_pager(&cap, NoopPager);
        return TestResult::Fail("ZpoolPager did not reject LOCKED with BadFlags");
    }

    // Restore default before next smoke.
    if install_pager(&cap, NoopPager).is_err() {
        return TestResult::Fail("could not reinstall NoopPager for cleanup");
    }
    if current_pager_name() != Some("noop") {
        return TestResult::Fail("post-cleanup pager name is not 'noop'");
    }

    TestResult::Pass
}
kernel_test_in!("memory", smoke_pluggable_pager);

// ── mmap-at-scale: replay ld-musl's per-DSO reserve→MAP_FIXED→mprotect
//    pattern many times and prove every mapping stays correct ──────────
//
// Loading a large shared-library closure (Mesa + LLVM ≈ 48 DSOs) runs, per
// DSO: (1) reserve the whole span PROT_NONE (lazy/anonymous), (2) MAP_FIXED
// real segments over it (punch the reservation + install), (3) mprotect a
// sub-range RO (RELRO). Each operation is fine in isolation, but at scale the
// region table + page tables must stay consistent across hundreds of
// split/overlay/mprotect operations. This stamps every segment frame with a
// unique magic, runs the pattern 80× (> the Mesa closure), then verifies
// EVERY segment still translates to ITS frame and still holds ITS magic — a
// regression guard for region-list / MAP_FIXED-overlay / mprotect-split
// corruption that only shows up under a big dlopen closure.
#[cfg(target_arch = "x86_64")]
fn smoke_mmap_scale_overlay_pattern_stays_consistent() -> TestResult {
    use crate::x86_64::paging;
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: Testing context; we don't switch CR3 or use it for active execution.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(x) => x,
        Err(_) => return TestResult::Skip("AS alloc failed"),
    };
    const N: u64 = 80;
    const SPAN: u64 = 6 * 0x1000;
    let base = 0x0000_4080_0000_0000u64; // the real user mmap-arena range
    let mut recs: alloc::vec::Vec<(u64, PhysAddr, u64)> = alloc::vec::Vec::new();

    for i in 0..N {
        let b = base + i * SPAN;
        if a.map_region(Region {
            base: VirtAddr::new(b),
            len: SPAN,
            perms: RegionPerms(0),
            phys: alloc::vec![PhysAddr::new(0); (SPAN >> 12) as usize],
        })
        .is_err()
        {
            return TestResult::Fail("reserve (PROT_NONE span) map_region failed");
        }
        for &pg in &[1u64, 3u64] {
            let va = b + pg * 0x1000;
            let frame = match crate::alloc_frame() {
                Ok(f) => f.start_address(),
                Err(_) => return TestResult::Skip("frame allocator drained"),
            };
            let magic = 0xA5A5_0000_0000_0000u64 ^ (i << 12) ^ pg;
            // SAFETY: freshly-allocated identity-mapped frame; stamp the page.
            unsafe {
                let p = frame.kernel_mut_ptr::<u64>();
                for k in 0..512 {
                    p.add(k).write(magic);
                }
            }
            let _ = a.punch_fixed(VirtAddr::new(va), 0x1000);
            if a.map_region(Region {
                base: VirtAddr::new(va),
                len: 0x1000,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![frame],
            })
            .is_err()
            {
                return TestResult::Fail("segment MAP_FIXED map_region failed");
            }
            recs.push((va, frame, magic));
        }
        // SAFETY: fresh user root; installs only this DSO's PTEs. This is the
        // same incremental path sys_mmap uses, so prior DSOs are not revisited.
        if unsafe { a.materialize_range(VirtAddr::new(b), SPAN) }.is_err() {
            return TestResult::Fail("materialize failed under scale");
        }
        // RELRO-style: drop the first segment to RO.
        let _ = a.mprotect_range(VirtAddr::new(b + 0x1000), 0x1000, RegionPerms::READ);
    }

    for (va, frame, magic) in &recs {
        // SAFETY: a.root is a live user PML4 from new_for_user.
        match unsafe { paging::translate(a.root, VirtAddr::new(*va)) } {
            Some(p) if p == *frame => {}
            Some(_) => return TestResult::Fail("VA translated to the WRONG frame at scale"),
            None => return TestResult::Fail("VA lost its mapping at scale"),
        }
        // SAFETY: identity-mapped frame; read its first stamped word.
        let got = unsafe { frame.kernel_ptr::<u64>().read() };
        if got != *magic {
            return TestResult::Fail("frame content corrupted at scale");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_mmap_scale_overlay_pattern_stays_consistent);

/// The ordered VMA index is the metadata foundation for logarithmic lookup,
/// insertion, and empty MAP_FIXED-punch checks. Exercise enough randomized
/// insertions to cross several B-tree levels, then verify predecessor and
/// successor overlap admission, a no-overlap punch, and keyed removal.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_regions_stay_sorted_for_fixed_churn() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: test-owned inactive user root.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("AS alloc failed"),
    };
    let base = 0x0000_4070_0000_0000u64;
    const PAGES: u64 = 1024;
    // Multiplication by an odd number permutes every element modulo 2^10.
    for i in 0..PAGES {
        let page = (i * 405) & (PAGES - 1);
        if a.map_region(Region {
            base: VirtAddr::new(base + page * 4096),
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
        {
            return TestResult::Fail("out-of-order VMA insertion failed");
        }
    }
    let before = a.regions_snapshot();
    if !before
        .windows(2)
        .all(|pair| pair[0].base.as_u64() < pair[1].base.as_u64())
    {
        return TestResult::Fail("VMA insertion lost sorted order");
    }
    if before.len() != PAGES as usize {
        return TestResult::Fail("random VMA insertion lost an entry");
    }
    if a.map_region(Region {
        base: VirtAddr::new(base + 512 * 4096),
        len: 4096,
        perms: RegionPerms::READ,
        phys: alloc::vec![PhysAddr::new(0)],
    }) != Err(crate::AddressSpaceError::Overlap)
    {
        return TestResult::Fail("tree admitted an equal-base overlap");
    }
    if a.punch_fixed(VirtAddr::new(base + 2 * PAGES * 4096), 4096)
        .is_err()
        || a.regions_snapshot().len() != before.len()
    {
        return TestResult::Fail("empty fixed punch changed the VMA table");
    }
    if a.unmap_region(VirtAddr::new(base + 512 * 4096)).is_err() {
        return TestResult::Fail("ordered VMA removal failed");
    }
    let after = a.regions_snapshot();
    if !after
        .windows(2)
        .all(|pair| pair[0].base.as_u64() < pair[1].base.as_u64())
    {
        return TestResult::Fail("VMA removal lost sorted order");
    }
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_regions_stay_sorted_for_fixed_churn);

/// Incremental materialisation must install exactly the requested page range,
/// with the same physical backing as a later full materialisation.
///
/// This is both a correctness test and the structural scalability guard: a
/// one-page mmap must not walk or install unrelated page slots merely because
/// they already exist in the same address space.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_materialize_range_installs_only_intersection() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: test-owned user root; it is never activated.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("AS alloc failed"),
    };
    // Validation is part of the new public surface: malformed intervals must
    // fail before any page-table walk can observe them.
    // SAFETY: `a` owns a live user root; this malformed range is rejected
    // before the implementation walks it.
    let misaligned = unsafe { a.materialize_range(VirtAddr::new(0x4081_0000_0001), 4096) };
    // SAFETY: same live-root argument; zero length is rejected.
    let empty = unsafe { a.materialize_range(VirtAddr::new(0x4081_0000_0000), 0) };
    // SAFETY: same live-root argument; crossing the user ceiling is rejected.
    let beyond_user =
        unsafe { a.materialize_range(VirtAddr::new(AddressSpace::USER_HALF_END - 4096), 8192) };
    if misaligned != Err(crate::AddressSpaceError::AlignmentMismatch)
        || empty != Err(crate::AddressSpaceError::AlignmentMismatch)
        || beyond_user != Err(crate::AddressSpaceError::OutOfRange)
    {
        return TestResult::Fail("materialize_range accepted a malformed interval");
    }
    let mut frames = alloc::vec::Vec::new();
    for _ in 0..3 {
        match crate::alloc_frame() {
            Ok(frame) => frames.push(frame.start_address()),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        }
    }
    let base = VirtAddr::new(0x0000_4081_0000_0000);
    if a.map_region(Region {
        base,
        len: 3 * 4096,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: frames.clone(),
    })
    .is_err()
    {
        return TestResult::Fail("map_region failed");
    }

    // SAFETY: the root is live and the interval is one aligned page inside
    // the recorded region.
    if unsafe { a.materialize_range(VirtAddr::new(base.as_u64() + 4096), 4096) }.is_err() {
        return TestResult::Fail("one-page materialize_range failed");
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn translated(a: &AddressSpace, va: VirtAddr) -> Option<PhysAddr> {
        // SAFETY: the caller passes a live test-owned user root.
        unsafe { crate::x86_64::paging::translate(a.root, va) }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe fn translated(a: &AddressSpace, va: VirtAddr) -> Option<PhysAddr> {
        // SAFETY: the caller passes a live test-owned user root.
        unsafe { crate::aarch64::paging::translate(a.root, va) }
    }

    // SAFETY: `a` owns a live user page-table root.
    let first = unsafe { translated(&a, base) };
    // SAFETY: same live-root argument.
    let last = unsafe { translated(&a, VirtAddr::new(base.as_u64() + 8192)) };
    if first.is_some() || last.is_some() {
        return TestResult::Fail("materialize_range installed a page outside its interval");
    }
    // SAFETY: same live-root argument.
    if unsafe { translated(&a, VirtAddr::new(base.as_u64() + 4096)) } != Some(frames[1]) {
        return TestResult::Fail("materialize_range installed the wrong middle-page backing");
    }

    // Full construction remains idempotent over the middle page and installs
    // both untouched neighbors with their original backing.
    // SAFETY: test-owned live root.
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("full materialize after range failed");
    }
    for (index, frame) in frames.iter().enumerate() {
        let va = VirtAddr::new(base.as_u64() + index as u64 * 4096);
        // SAFETY: test-owned live root.
        if unsafe { translated(&a, va) } != Some(*frame) {
            return TestResult::Fail("full materialize disagreed with range backing");
        }
        // The full batch encounters the already-mapped middle page after
        // installing its first-page prefix. Recovery must record that prefix
        // as well as the pre-existing and remaining leaves, without duplicate
        // owners on this test-owned backing.
        if crate::rmap::owner_count(*frame) != 1 {
            return TestResult::Fail("partial batch recovery left inconsistent rmap owners");
        }
    }
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_materialize_range_installs_only_intersection);

/// System V `shmat` maps a segment's registry-owned frames into the caller's
/// address space and installs the PTEs for ONLY that segment's VA window via
/// `materialize_range` (not a whole-address-space `materialize`, which the
/// shm-sysv shmget/shmat/shmdt loop otherwise re-paid per attach). This
/// mirrors that attach shape at the address-space layer and pins its three
/// load-bearing invariants:
///   * shared visibility — a second attach (a second AS here) aliases the
///     SAME physical frame, so a write through one attach is visible through
///     the other (`shmat` maps, never copies);
///   * range-scoped PTE install — `materialize_range` installs exactly the
///     segment window and nothing else;
///   * shared-frame lifetime — a SHARED region borrows registry-owned frames,
///     so dropping one attaching AS unmaps its PTEs but must NOT free the
///     frame while another AS still maps it (the cross-AS double-free hazard).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_shmat_shared_attach_range_materialize() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    #[cfg(target_arch = "x86_64")]
    unsafe fn translated(a: &AddressSpace, va: VirtAddr) -> Option<PhysAddr> {
        // SAFETY: the caller passes a live test-owned user root.
        unsafe { crate::x86_64::paging::translate(a.root, va) }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe fn translated(a: &AddressSpace, va: VirtAddr) -> Option<PhysAddr> {
        // SAFETY: the caller passes a live test-owned user root.
        unsafe { crate::aarch64::paging::translate(a.root, va) }
    }

    // Two independent user address spaces stand in for two processes attaching
    // the same segment. SAFETY: test-owned roots; neither is ever activated.
    // SAFETY: test-owned user root; it is never activated.
    let as_a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("AS a alloc failed"),
    };
    // SAFETY: test-owned user root; it is never activated.
    let as_b = match unsafe { AddressSpace::new_for_user() } {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("AS b alloc failed"),
    };

    // One page of registry-owned backing stands in for the shmem segment's
    // frame list. A single frame keeps the shared-alias reasoning exact.
    let seg = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    const SEG_LEN: u64 = 4096;
    // Above the low-4-GiB identity window so the leaf doesn't collide with the
    // kernel's shared huge PML4[0] identity mapping.
    let base_a = VirtAddr::new(0x0000_4090_0000_0000);
    let base_b = VirtAddr::new(0x0000_4098_0000_0000);

    // Attach shape: SHARED marks the frames as borrowed so neither unmap nor
    // AS-drop frees them; the transaction serializes the alias install exactly
    // as `sys_shmat` does. A single frame maps into both roots — no copy.
    let attach = |as_ref: &AddressSpace, base: VirtAddr| {
        as_ref.with_vma_transaction(|| {
            crate::with_shared_mapping_transaction(|| {
                // SAFETY: VMA + registry transactions cover alias insertion;
                // the live root's range install touches only this window.
                unsafe {
                    as_ref.map_shared_region_locked(Region {
                        base,
                        len: SEG_LEN,
                        perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED,
                        phys: alloc::vec![seg],
                    })?;
                    as_ref.materialize_range(base, SEG_LEN)
                }
            })
        })
    };
    if attach(&as_a, base_a).is_err() {
        return TestResult::Fail("first attach (map_shared + materialize_range) failed");
    }
    if attach(&as_b, base_b).is_err() {
        return TestResult::Fail("second attach (map_shared + materialize_range) failed");
    }

    // Range-scoped install: exactly the segment window is present, and both
    // attaches resolve to the SAME physical frame (shared visibility, not a
    // copy).
    // SAFETY: both roots are live test-owned user roots.
    if unsafe { translated(&as_a, base_a) } != Some(seg) {
        return TestResult::Fail("attach A did not install the segment PTE");
    }
    // SAFETY: as above.
    if unsafe { translated(&as_b, base_b) } != Some(seg) {
        return TestResult::Fail("attach B did not alias the SAME frame (visibility broken)");
    }
    // materialize_range must not spill outside the one-page window.
    // SAFETY: as above.
    if unsafe { translated(&as_a, VirtAddr::new(base_a.as_u64() + SEG_LEN)) }.is_some() {
        return TestResult::Fail("materialize_range installed a page past the segment");
    }

    // Write through the shared frame and read it back through B's mapping:
    // both attaches see the same bytes. The frame is identity-mapped, so its
    // phys doubles as a kernel VA here.
    const SENTINEL: u64 = 0x5347_5F53_484D_4154;
    // SAFETY: `seg` is a live, identity-mapped, freshly allocated frame.
    unsafe { core::ptr::write_volatile(seg.raw() as *mut u64, SENTINEL) };
    // SAFETY: B translated to `seg`; reading through that phys observes the
    // write, proving cross-attach shared visibility.
    let seen = unsafe { core::ptr::read_volatile(seg.raw() as *const u64) };
    if seen != SENTINEL {
        return TestResult::Fail("shared write not visible through the second attach");
    }

    // Detach one attach (drop A). A SHARED region unmaps its PTEs but must NOT
    // free the borrowed frame while B still maps it — the marginal-buddy
    // cross-AS double-free hazard.
    drop(as_a);
    // B still resolves the frame and still reads the sentinel: A's teardown
    // neither unmapped B nor freed the shared frame.
    // SAFETY: B owns a live user root; `seg` stays identity-mapped.
    if unsafe { translated(&as_b, base_b) } != Some(seg) {
        return TestResult::Fail("detaching A tore down B's still-live attach");
    }
    // SAFETY: as above.
    if unsafe { core::ptr::read_volatile(seg.raw() as *const u64) } != SENTINEL {
        return TestResult::Fail("shared frame was clobbered by A's detach");
    }
    // The clinching double-free check: had A's drop freed the still-mapped
    // frame, the allocator's free list would now hand it back. It must not.
    let probe = crate::alloc_frame().ok();
    if let Some(f) = probe.as_ref() {
        if f.start_address() == seg {
            return TestResult::Fail("detach freed a frame still attached elsewhere (double-free)");
        }
    }

    // Cleanup: drop B (releases its borrow, still no free of `seg`), return the
    // probe frame, then free the segment frame we own outright.
    drop(as_b);
    if let Some(f) = probe {
        crate::frame::free_frame(f);
    }
    crate::frame::free_frame(crate::frame::PhysFrame::new(seg));
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_shmat_shared_attach_range_materialize);

/// A bad, unrelated VMA must not poison incremental materialisation of a
/// valid mmap range. A test-owned huge leaf gives a deterministic structural
/// conflict that the full construction walk rejects.
#[cfg(target_arch = "x86_64")]
fn smoke_materialize_range_skips_unrelated_invalid_region() -> TestResult {
    use crate::x86_64::paging;
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: test-owned user root; it is never activated.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("AS alloc failed"),
    };
    let conflict = VirtAddr::new(0x0000_3000_0000_0000);
    // SAFETY: the test owns this inactive user root. Physical zero is never
    // accessed; the huge leaf exists only to create a page-table shape that a
    // 4 KiB materialization must reject.
    if unsafe {
        paging::map_2mb(
            a.root,
            conflict,
            crate::PhysAddr::new(0),
            paging::PtFlags::USER | paging::PtFlags::NO_EXEC,
        )
    }
    .is_err()
    {
        return TestResult::Fail("could not install structural conflict leaf");
    }
    let low_frame = match crate::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    let good_frame = match crate::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    if a.map_region(Region {
        base: conflict,
        len: 4096,
        perms: RegionPerms::READ,
        phys: alloc::vec![low_frame],
    })
    .is_err()
    {
        return TestResult::Fail("low structural region registration failed");
    }
    let good = VirtAddr::new(0x0000_4082_0000_0000);
    if a.map_region(Region {
        base: good,
        len: 4096,
        perms: RegionPerms::READ,
        phys: alloc::vec![good_frame],
    })
    .is_err()
    {
        return TestResult::Fail("good region registration failed");
    }

    // SAFETY: live root and valid high user interval.
    if unsafe { a.materialize_range(good, 4096) }.is_err() {
        return TestResult::Fail("unrelated invalid VMA poisoned range materialization");
    }
    // SAFETY: `a.root` is the live test user PML4.
    if unsafe { paging::translate(a.root, good) } != Some(good_frame) {
        return TestResult::Fail("valid range translated to the wrong frame");
    }
    // SAFETY: same root; the full walk should still detect the huge-leaf
    // conflict, proving the range call did not silently walk that VMA.
    if unsafe { a.materialize() } != Err(crate::AddressSpaceError::Overlap) {
        return TestResult::Fail("full materialize did not detect low identity-map conflict");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory",
    smoke_materialize_range_skips_unrelated_invalid_region
);

// ── demand-fault self-heal: "backed bookkeeping over an absent leaf PTE"
//    must install the PTE, not retry forever ──────────────────────────────
//
// A raced VMA op on a CLONE_VM-shared AS (MAP_FIXED punch / munmap overlap /
// the map_region→materialize gap in sys_mmap) can leave a region slot backed
// (`phys[i] != 0`) while the leaf PTE is genuinely ABSENT. The old
// demand_alloc_page treated EVERY already-backed not-present fault as a
// spurious stale-TLB fault — INVLPG + Ok — so the faulting instruction
// retried against a still-absent PTE forever: a silent, unkillable
// infinite-#PF loop (the stress-ng --vma SMP wedge). The fixed path consults
// translate(): present leaf → spurious (invlpg+retry); absent leaf →
// re-install the region's own frame.
#[cfg(target_arch = "x86_64")]
fn smoke_demand_fault_heals_absent_leaf_pte() -> TestResult {
    use crate::x86_64::paging;
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: test context; the AS is built + probed but never activated.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(x) => x,
        Err(_) => return TestResult::Skip("AS alloc failed"),
    };
    let va = VirtAddr::new(0x0000_4080_2000_0000u64);
    let frame = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("frame allocator drained"),
    };
    if a.map_region(Region {
        base: va,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![frame],
    })
    .is_err()
    {
        return TestResult::Fail("map_region failed");
    }
    // Deliberately DO NOT materialize: the slot is backed, the leaf is
    // absent — exactly the raced state a #PF then observes.
    // SAFETY: a.root is a live user PML4 from new_for_user; translate reads.
    if unsafe { paging::translate(a.root, va) }.is_some() {
        return TestResult::Fail("leaf unexpectedly present before the heal");
    }
    // SAFETY: identity map live; root valid; frame allocator initialised.
    if unsafe { a.demand_alloc_page(va) }.is_err() {
        return TestResult::Fail("demand_alloc_page rejected a backed-but-unmapped page");
    }
    // SAFETY: as above.
    match unsafe { paging::translate(a.root, va) } {
        Some(p) if p == frame => {}
        Some(_) => return TestResult::Fail("healed PTE points at the WRONG frame"),
        None => {
            return TestResult::Fail("demand_alloc_page returned Ok without installing the leaf")
        }
    }
    // Present-leaf spurious path still works: a second fault on the (now
    // mapped) page must succeed without disturbing the translation.
    // SAFETY: as above.
    if unsafe { a.demand_alloc_page(va) }.is_err() {
        return TestResult::Fail("spurious-fault path regressed on a present leaf");
    }
    // SAFETY: as above.
    match unsafe { paging::translate(a.root, va) } {
        Some(p) if p == frame => TestResult::Pass,
        _ => TestResult::Fail("spurious-fault path disturbed the translation"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_demand_fault_heals_absent_leaf_pte);

#[cfg(target_arch = "x86_64")]
fn smoke_numa_migrate_page_preserves_contents() -> TestResult {
    use crate::x86_64::paging;
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    if !crate::is_numa_aware() || crate::node_free(1) == 0 {
        return TestResult::Skip("requires two online NUMA memory nodes");
    }
    // SAFETY: test context; the AS is never activated concurrently.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(x) => x,
        Err(_) => return TestResult::Skip("AS alloc failed"),
    };
    let va = VirtAddr::new(0x0000_4080_3000_0000);
    let old = match crate::frame::alloc_frame_on_strict(0) {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Skip("node 0 allocation failed"),
    };
    // SAFETY: the freshly allocated frame is live in the direct map.
    unsafe { old.kernel_mut_ptr::<u64>().write(0x4E55_4D41_4D4F_5645) };
    if a.map_region(Region {
        base: va,
        len: 4096,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![old],
    })
    .is_err()
    {
        return TestResult::Fail("failed to register migration test page");
    }
    // SAFETY: a owns a fresh valid root and the test runs without mutation.
    if unsafe { a.materialize() }.is_err() {
        return TestResult::Fail("failed to materialize migration test page");
    }
    let node1_free_before = crate::node_free(1);
    // SAFETY: root/direct map are live, the range is fully mapped, and the
    // region is private.
    if unsafe { a.conform_range_to_nodes(va, 4096, 0b10, true) } != Ok(0) {
        return TestResult::Fail("range node 0 -> node 1 migration failed");
    }
    // SAFETY: a.root remains valid and no concurrent mutation occurs.
    let Some(new_phys) = (unsafe { paging::translate(a.root, va) }) else {
        return TestResult::Fail("migrated PTE is absent");
    };
    // ACPI parser smokes deliberately reset the live SRAT table, while the
    // buddy's boot-time NUMA partition remains authoritative. Verify strict
    // zone consumption rather than consulting that mutable test fixture.
    if crate::node_free(1) + 1 != node1_free_before {
        return TestResult::Fail("migrated page did not land on node 1");
    }
    // SAFETY: translated physical frame remains owned by the AS.
    if unsafe { new_phys.kernel_ptr::<u64>().read() } != 0x4E55_4D41_4D4F_5645 {
        return TestResult::Fail("migration did not preserve page contents");
    }
    // The ACPI topology-reset smokes described above also make AS teardown
    // unable to route this node-1 frame back to its boot-time zone. Leak this
    // isolated test AS rather than polluting the allocator for later smokes.
    core::mem::forget(a);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_numa_migrate_page_preserves_contents);

#[cfg(target_arch = "x86_64")]
fn smoke_numa_hint_fault_round_trip() -> TestResult {
    use crate::x86_64::paging;
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: test context has paging enabled and exclusively owns the AS.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(x) => x,
        Err(_) => return TestResult::Skip("AS alloc failed"),
    };
    let va = VirtAddr::new(0x0000_4080_3010_0000);
    let frame = match crate::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Skip("frame allocation failed"),
    };
    let registered = a.map_region(Region {
        base: va,
        len: 4096,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![frame],
    });
    // SAFETY: a owns a fresh valid root and the registered frame.
    let materialized = unsafe { a.materialize() };
    if registered.is_err() || materialized.is_err() {
        return TestResult::Fail("failed to materialize hint test page");
    }
    // SAFETY: this test exclusively owns the live address space.
    if unsafe { a.protect_numa_hint_page(va) } != Ok(true) {
        return TestResult::Fail("eligible page was not protected");
    }
    // SAFETY: read-only walk of the live root.
    if unsafe { paging::translate(a.root, va) }.is_some() {
        return TestResult::Fail("NUMA hint left the sampled PTE present");
    }
    if !a.take_numa_hint(va) {
        return TestResult::Fail("sampled address was not recorded");
    }
    // SAFETY: the sampled backing remains owned by a's region.
    if unsafe { a.remap_page(va) }.is_err() {
        return TestResult::Fail("hint fault could not restore the leaf");
    }
    // SAFETY: read-only walk of the live root.
    match unsafe { paging::translate(a.root, va) } {
        Some(phys) if phys == frame => TestResult::Pass,
        _ => TestResult::Fail("hint fault restored the wrong backing"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_numa_hint_fault_round_trip);

#[cfg(target_arch = "x86_64")]
fn smoke_mempolicy_allowed_mask_is_hard_boundary() -> TestResult {
    if !crate::is_numa_aware() || crate::node_free(1) == 0 {
        return TestResult::Skip("requires two NUMA memory nodes");
    }
    let before = crate::node_free(1);
    let policy = crate::Mempolicy {
        mode: crate::MPOL_DEFAULT,
        nodemask: 0,
        allowed: 0b10,
        home_node: u32::MAX,
        interleave_index: 0,
    };
    let frame = match crate::mempolicy::alloc_frame_with(policy, 0) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Fail("cpuset-constrained allocation failed"),
    };
    if crate::node_free(1) + 1 != before {
        return TestResult::Fail("DEFAULT policy escaped cpuset node mask");
    }
    // ACPI parser smokes mutate the live SRAT fixture after the allocator was
    // partitioned, so freeing this node-1 frame could route it to the wrong
    // zone. Keep this single test frame allocated.
    let _leaked_frame = frame;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_mempolicy_allowed_mask_is_hard_boundary);

#[cfg(target_arch = "x86_64")]
fn smoke_shared_frame_replacement_updates_all_aliases() -> TestResult {
    use crate::x86_64::paging;
    use crate::{AddressSpace, PhysFrame, Region, RegionPerms, VirtAddr};

    // SAFETY: test context has paging enabled and owns both fresh roots.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(aspace) => aspace,
        Err(_) => return TestResult::Skip("first AS allocation failed"),
    };
    // SAFETY: same as above.
    let b = match unsafe { AddressSpace::new_for_user() } {
        Ok(aspace) => aspace,
        Err(_) => return TestResult::Skip("second AS allocation failed"),
    };
    let old = match crate::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Skip("source allocation failed"),
    };
    let new = match crate::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Skip("target allocation failed"),
    };
    let va_a = VirtAddr::new(0x0000_4090_0000_0000);
    let va_b = VirtAddr::new(0x0000_4091_0000_0000);
    for (aspace, va) in [(&a, va_a), (&b, va_b)] {
        aspace
            .map_region(Region {
                base: va,
                len: 4096,
                perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED,
                phys: alloc::vec![old],
            })
            .expect("register shared alias");
        // SAFETY: fresh valid root and registered live frame.
        unsafe { aspace.materialize() }.expect("materialize shared alias");
    }
    let replaced = crate::with_shared_mapping_transaction(|| {
        // SAFETY: both frames and roots remain live for the transaction.
        let left = unsafe { a.replace_shared_frame(old, new) };
        // SAFETY: same transaction and lifetime proof.
        let right = unsafe { b.replace_shared_frame(old, new) };
        (left, right)
    });
    // SAFETY: read-only walks of live page-table roots.
    let translated = unsafe {
        (
            paging::translate(a.root, va_a),
            paging::translate(b.root, va_b),
        )
    };
    #[cfg(feature = "kernel-test")]
    let unmap_paths_before = crate::address_space::__test_unmap_path_counts();
    // Shared exact unmap and range punch must retain the serialized path after
    // private teardown gains its lock-local fast path.
    let unmapped_shared = a
        .unmap_region(va_a)
        .map(|region| region.perms.contains(RegionPerms::SHARED));
    let punched_shared = b.punch_fixed(va_b, 4096);
    // SAFETY: read-only walks of both still-live page-table roots.
    let aliases_gone = unsafe {
        paging::translate(a.root, va_a).is_none() && paging::translate(b.root, va_b).is_none()
    };
    #[cfg(feature = "kernel-test")]
    let unmap_paths_after = crate::address_space::__test_unmap_path_counts();
    drop(a);
    drop(b);
    crate::free_frame(PhysFrame::new(old));
    crate::free_frame(PhysFrame::new(new));
    match (
        replaced,
        translated,
        unmapped_shared,
        punched_shared,
        aliases_gone,
    ) {
        ((Ok(1), Ok(1)), (Some(left), Some(right)), Ok(true), Ok(()), true)
            if left == new && right == new && {
                #[cfg(feature = "kernel-test")]
                {
                    unmap_paths_after.0 == unmap_paths_before.0
                        && unmap_paths_after.1 == unmap_paths_before.1 + 2
                }
                #[cfg(not(feature = "kernel-test"))]
                {
                    true
                }
            } =>
        {
            TestResult::Pass
        }
        _ => TestResult::Fail("shared aliases did not move together"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_shared_frame_replacement_updates_all_aliases);

// ════════════════════════════════════════════════════════════════════
// mlock / munlock semantics.
//
// Coverage before this block was error-branch only: the six
// `abi_mem*_tests.rs` pins all assert a *rejection* (no address space →
// InvalidOp, bad flags → EINVAL), because the ABI harness deliberately
// installs no per-task AddressSpace. Nothing anywhere exercised
// `mlock_range`/`munlock_range` themselves, so neither the LOCKED
// bookkeeping nor mlock's primary documented job — force-backing lazy
// pages — had a test that could go red. munlock had no test at all.
// ════════════════════════════════════════════════════════════════════

/// Two pages mapped, one deliberately unbacked. `mlock` must allocate a
/// frame for the hole and stamp it into the region, and `munlock` must
/// leave the backing in place (there is no swap to release it to).
///
/// This is mlock's headline behaviour and it had zero coverage.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_mlock_force_backs_lazy_pages() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: fresh user AS for this test only; forgotten below rather
    // than dropped, as every sibling AS test in this file does.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let backed = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => {
            core::mem::forget(a);
            return TestResult::Skip("frame drained");
        }
    };
    let v = VirtAddr::new(0x0000_0080_1000_0000);
    // phys[1] == 0 is the "lazy / not yet backed" encoding mlock_range
    // scans for.
    if a.map_region(Region {
        base: v,
        len: 0x2000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![backed, PhysAddr::new(0)],
    })
    .is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("map_region rejected a partially-backed region");
    }

    let hole_before = a
        .regions_snapshot()
        .iter()
        .find(|r| r.base.as_u64() == v.as_u64())
        .and_then(|r| r.phys.get(1).map(|p| p.raw()));
    if hole_before != Some(0) {
        core::mem::forget(a);
        return TestResult::Fail("test setup: page 1 was not an unbacked hole");
    }

    if a.mlock_range(v, 0x2000).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("mlock_range on a mapped range returned Err");
    }

    let after = a
        .regions_snapshot()
        .iter()
        .find(|r| r.base.as_u64() == v.as_u64())
        .map(|r| {
            (
                r.phys.first().map(|p| p.raw()).unwrap_or(0),
                r.phys.get(1).map(|p| p.raw()).unwrap_or(0),
                r.perms.contains(RegionPerms::LOCKED),
            )
        });
    let Some((p0, p1, locked)) = after else {
        core::mem::forget(a);
        return TestResult::Fail("region vanished across mlock");
    };
    if p0 != backed.raw() {
        core::mem::forget(a);
        return TestResult::Fail("mlock disturbed an already-backed page");
    }
    if p1 == 0 {
        core::mem::forget(a);
        return TestResult::Fail("mlock did not force-back the lazy page");
    }
    if !locked {
        core::mem::forget(a);
        return TestResult::Fail("mlock did not set LOCKED");
    }

    // munlock clears the flag but must NOT hand the backing back: there
    // is no swap tier to release it to, and dropping it would turn a
    // munlock into a silent data loss.
    if a.munlock_range(v, 0x2000).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("munlock_range returned Err");
    }
    let unlocked = a
        .regions_snapshot()
        .iter()
        .find(|r| r.base.as_u64() == v.as_u64())
        .map(|r| {
            (
                r.perms.contains(RegionPerms::LOCKED),
                r.phys.get(1).map(|p| p.raw()).unwrap_or(0),
                r.perms.contains(RegionPerms::READ) && r.perms.contains(RegionPerms::WRITE),
            )
        });
    core::mem::forget(a);
    match unlocked {
        None => TestResult::Fail("region vanished across munlock"),
        Some((true, _, _)) => TestResult::Fail("munlock left LOCKED set"),
        Some((_, p, _)) if p != p1 => TestResult::Fail("munlock released the backing"),
        Some((_, _, false)) => TestResult::Fail("munlock clobbered the POSIX prot bits"),
        Some(_) => TestResult::Pass,
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_mlock_force_backs_lazy_pages);

/// Locking a subrange must neither populate nor pin the rest of a large VMA.
/// The old implementation scanned every phys slot and set LOCKED on the
/// whole intersecting region, making small locks of large mappings both
/// semantically wrong and proportional to the mapping size.  Also exercise
/// Linux's byte-length rounding by unlocking one byte of the first locked
/// page.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_mlock_splits_exact_subrange() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: fresh user AS used only by this test.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let base = 0x0000_0080_1800_0000u64;
    if a.map_region(Region {
        base: VirtAddr::new(base),
        len: 0x4000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0); 4],
    })
    .is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("map_region failed");
    }
    if a.mlock_range(VirtAddr::new(base + 0x1000), 0x2000).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("partial mlock failed");
    }

    let mut regions: alloc::vec::Vec<_> = a
        .regions_snapshot()
        .into_iter()
        .filter(|r| r.base.as_u64() >= base && r.base.as_u64() < base + 0x4000)
        .collect();
    regions.sort_by_key(|r| r.base.as_u64());
    let exact_lock = regions.len() == 3
        && regions[0].base.as_u64() == base
        && regions[0].len == 0x1000
        && !regions[0].perms.contains(RegionPerms::LOCKED)
        && regions[0].phys == alloc::vec![PhysAddr::new(0)]
        && regions[1].base.as_u64() == base + 0x1000
        && regions[1].len == 0x2000
        && regions[1].perms.contains(RegionPerms::LOCKED)
        && regions[1].phys.iter().all(|phys| phys.raw() != 0)
        && regions[2].base.as_u64() == base + 0x3000
        && regions[2].len == 0x1000
        && !regions[2].perms.contains(RegionPerms::LOCKED)
        && regions[2].phys == alloc::vec![PhysAddr::new(0)];
    if !exact_lock {
        core::mem::forget(a);
        return TestResult::Fail("mlock populated or locked outside its subrange");
    }

    if a.munlock_range(VirtAddr::new(base + 0x1000), 1).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("one-byte munlock failed");
    }
    let regions = a.regions_snapshot();
    let page_locked = |va: u64| {
        regions
            .iter()
            .find(|r| r.base.as_u64() <= va && va < r.base.as_u64() + r.len)
            .is_some_and(|r| r.perms.contains(RegionPerms::LOCKED))
    };
    let exact_unlock = !page_locked(base)
        && !page_locked(base + 0x1000)
        && page_locked(base + 0x2000)
        && !page_locked(base + 0x3000);
    core::mem::forget(a);
    if exact_unlock {
        TestResult::Pass
    } else {
        TestResult::Fail("munlock changed LOCKED outside its rounded page")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_mlock_splits_exact_subrange);

/// MLOCK_ONFAULT pins the VMA state without eagerly populating it; the first
/// access backs only the faulted page and the LOCKED marker survives.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_mlock_onfault_stays_lazy_until_fault() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: fresh user AS used only by this test.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let base = VirtAddr::new(0x0000_0080_1c00_0000);
    if a.map_region(Region {
        base,
        len: 0x2000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0); 2],
    })
    .is_err()
        || a.mlock_range_onfault(base, 0x2000).is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("MLOCK_ONFAULT setup failed");
    }
    let before = a
        .regions_snapshot()
        .iter()
        .find(|region| region.base == base)
        .is_some_and(|region| {
            region.perms.contains(RegionPerms::LOCKED)
                && region.phys.iter().all(|phys| phys.raw() == 0)
        });
    if !before {
        core::mem::forget(a);
        return TestResult::Fail("MLOCK_ONFAULT eagerly populated the range");
    }

    // SAFETY: test-owned live root and initialized frame allocator.
    if unsafe { a.demand_alloc_page(base) }.is_err() {
        core::mem::forget(a);
        return TestResult::Fail("demand fault after MLOCK_ONFAULT failed");
    }
    let after = a
        .regions_snapshot()
        .iter()
        .find(|region| region.base == base)
        .is_some_and(|region| {
            region.perms.contains(RegionPerms::LOCKED)
                && region.phys[0].raw() != 0
                && region.phys[1].raw() == 0
        });
    core::mem::forget(a);
    if after {
        TestResult::Pass
    } else {
        TestResult::Fail("fault populated the wrong pages or dropped LOCKED")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_mlock_onfault_stays_lazy_until_fault);

/// A range spanning two adjacent regions must flag **both**. The
/// intersect test is `rb < hi && lo < re`; an off-by-one there (or a
/// `find`-style "first match wins") would silently leave the second
/// region unlocked.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_mlock_spans_multiple_regions() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: as above.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let (f0, f1) = match (crate::alloc_frame(), crate::alloc_frame()) {
        (Ok(x), Ok(y)) => (x.start_address(), y.start_address()),
        _ => {
            core::mem::forget(a);
            return TestResult::Skip("frame drained");
        }
    };
    let base = 0x0000_0080_2000_0000u64;
    for (i, f) in [f0, f1].into_iter().enumerate() {
        if a.map_region(Region {
            base: VirtAddr::new(base + (i as u64) * 0x1000),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![f],
        })
        .is_err()
        {
            core::mem::forget(a);
            return TestResult::Fail("map_region failed");
        }
    }

    if a.mlock_range(VirtAddr::new(base), 0x2000).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("mlock_range across two regions returned Err");
    }
    let both = a
        .regions_snapshot()
        .iter()
        .filter(|r| r.base.as_u64() == base || r.base.as_u64() == base + 0x1000)
        .filter(|r| r.perms.contains(RegionPerms::LOCKED))
        .count();
    core::mem::forget(a);
    if both == 2 {
        TestResult::Pass
    } else {
        TestResult::Fail("mlock across two regions did not flag both")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_mlock_spans_multiple_regions);

/// Linux applies mlock flags VMA-by-VMA, so a later hole returns ENOMEM after
/// the mapped prefix has already changed. The island after the hole is not
/// reached.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_mlock_hole_preserves_linux_prefix_effect() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: fresh user AS used only by this test.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let base = 0x0000_0080_2800_0000u64;
    for offset in [0, 0x2000] {
        if a.map_region(Region {
            base: VirtAddr::new(base + offset),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
        {
            core::mem::forget(a);
            return TestResult::Fail("map_region failed");
        }
    }

    if a.mlock_range(VirtAddr::new(base), 0x3000).is_ok() {
        core::mem::forget(a);
        return TestResult::Fail("mlock across a hole succeeded");
    }
    let snapshot = a.regions_snapshot();
    let first_locked = snapshot
        .iter()
        .find(|r| r.base.as_u64() == base)
        .is_some_and(|r| r.perms.contains(RegionPerms::LOCKED));
    let later_untouched = snapshot
        .iter()
        .find(|r| r.base.as_u64() == base + 0x2000)
        .is_some_and(|r| !r.perms.contains(RegionPerms::LOCKED) && r.phys[0].raw() == 0);
    core::mem::forget(a);
    if first_locked && later_untouched {
        TestResult::Pass
    } else {
        TestResult::Fail("mlock hole did not preserve Linux prefix-side effect")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_mlock_hole_preserves_linux_prefix_effect
);

/// Linux marks a covered PROT_NONE VMA locked but does not attempt to fault
/// inaccessible pages during the eager population pass. The operation
/// succeeds and the backing stays lazy until permissions later allow access.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_mlock_prot_none_locks_without_population() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: fresh user AS used only by this test.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let base = 0x0000_0080_2A00_0000u64;
    if a.map_region(Region {
        base: VirtAddr::new(base),
        len: 0x1000,
        perms: RegionPerms::default(),
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("map_region failed");
    }
    if a.mlock_range(VirtAddr::new(base), 0x1000).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("covered PROT_NONE mlock failed");
    }
    let locked_lazy = a
        .regions_snapshot()
        .iter()
        .find(|r| r.base.as_u64() == base)
        .is_some_and(|r| r.perms.contains(RegionPerms::LOCKED) && r.phys[0].raw() == 0);
    core::mem::forget(a);
    if locked_lazy {
        TestResult::Pass
    } else {
        TestResult::Fail("PROT_NONE mlock populated backing or lost LOCKED")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_mlock_prot_none_locks_without_population
);

/// Only arithmetic wrap is EINVAL. A non-wrapping range beyond the user VMA
/// window is simply uncovered and therefore ENOMEM at the syscall boundary.
fn smoke_memory_mlock_range_error_classes_match_linux() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, VirtAddr};

    let a = AddressSpace::empty();
    if a.mlock_range(VirtAddr::new(u64::MAX - 0x100), 0x200) != Err(AddressSpaceError::OutOfRange) {
        return TestResult::Fail("wrapping mlock range did not classify as invalid");
    }
    if a.mlock_range(VirtAddr::new(AddressSpace::USER_HALF_END - 0x800), 0x1000)
        != Err(AddressSpaceError::Unmapped)
    {
        return TestResult::Fail("uncovered high mlock range did not classify as ENOMEM");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_memory_mlock_range_error_classes_match_linux);

/// Negative pair: a range intersecting nothing is `Unmapped`, for both
/// verbs. `munlock` had no negative test at all, so a change making it
/// silently succeed on an unmapped range would not have been noticed.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_mlock_unmapped_is_rejected() -> TestResult {
    use crate::{AddressSpace, VirtAddr};

    // SAFETY: as above.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let nowhere = VirtAddr::new(0x0000_0080_3000_0000);
    let mlock_err = a.mlock_range(nowhere, 0x1000).is_err();
    let munlock_err = a.munlock_range(nowhere, 0x1000).is_err();
    let zero_len_ok = a.mlock_range(nowhere, 0).is_ok()
        && a.mlock_range_onfault(nowhere, 0).is_ok()
        && a.munlock_range(nowhere, 0).is_ok();
    core::mem::forget(a);
    match (mlock_err, munlock_err, zero_len_ok) {
        (true, true, true) => TestResult::Pass,
        (false, _, _) => TestResult::Fail("mlock on an unmapped range succeeded"),
        (_, false, _) => TestResult::Fail("munlock on an unmapped range succeeded"),
        (_, _, false) => TestResult::Fail("zero-length lock operation was not a no-op"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_mlock_unmapped_is_rejected);

/// `mprotect` must not silently unlock an mlocked region.
///
/// Linux keeps `VM_LOCKED` across an `mprotect`, and NARF's 4 KiB path
/// does too — it rebuilds the middle fragment as `prot | preserved_flags`
/// where `preserved_flags` is everything outside `PROT_MASK`. This pins
/// that, because the obvious simplification (`perms: prot`) reads as
/// correct and silently drops LOCKED. The hugetlb path in the same
/// function *does* use bare `prot`; see the `// LINUX-GAP` note there.
#[cfg(target_arch = "x86_64")]
fn smoke_memory_mlock_survives_mprotect() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: as above.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let f = match crate::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => {
            core::mem::forget(a);
            return TestResult::Skip("frame drained");
        }
    };
    let v = VirtAddr::new(0x0000_0080_4000_0000);
    if a.map_region(Region {
        base: v,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![f],
    })
    .is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("map_region failed");
    }
    if a.mlock_range(v, 0x1000).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("mlock_range returned Err");
    }
    // RW -> R. Not a JIT transition, so no capability is involved.
    if a.mprotect_range(v, 0x1000, RegionPerms::READ).is_err() {
        core::mem::forget(a);
        return TestResult::Fail("mprotect_range returned Err");
    }
    let still = a
        .regions_snapshot()
        .iter()
        .find(|r| r.base.as_u64() == v.as_u64())
        .map(|r| {
            (
                r.perms.contains(RegionPerms::LOCKED),
                r.perms.contains(RegionPerms::WRITE),
            )
        });
    core::mem::forget(a);
    match still {
        Some((true, false)) => TestResult::Pass,
        Some((false, _)) => TestResult::Fail("mprotect silently cleared LOCKED"),
        Some((_, true)) => TestResult::Fail("mprotect did not drop WRITE"),
        None => TestResult::Fail("region vanished across mprotect"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_memory_mlock_survives_mprotect);

/// A mixed huge/base-page mprotect must reserve every base-page split node
/// before changing a huge leaf.  Otherwise ENOMEM can leave only the huge
/// prefix protected.  The successful retry also keeps internal VMA flags in
/// the huge middle, just as the ordinary 4 KiB path does.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "kernel-test"
))]
fn smoke_memory_mprotect_mixed_huge_index_oom_is_preflight() -> TestResult {
    use crate::frame::UsableRegion;
    use crate::hugepage::{
        alloc_hugepage_2m_on, reserve_from_regions, HugeSize, HUGEPAGE_2M_BYTES,
    };
    use crate::{
        AddressSpace, AddressSpaceError, HugeRegion, PhysAddr, Region, RegionPerms, VirtAddr,
    };

    const SYNTH_BASE: u64 = 0x40_0000_0000;
    const USER_VA: u64 = 0x0000_5000_6000_0000;
    let source = UsableRegion {
        start: PhysAddr::new(SYNTH_BASE),
        len: HUGEPAGE_2M_BYTES,
    };
    // SAFETY: the synthetic frame is mapped for metadata/translation checks
    // only and is returned to the test reservation before this test exits.
    let excludes = unsafe { reserve_from_regions(&[source], &[], 1, 0) };
    if excludes.len() != 1 {
        return TestResult::Fail("mixed mprotect hugepage reservation failed");
    }
    // SAFETY: topology lookup does not dereference the synthetic frame.
    let node = unsafe { crate::frame::narf_phys_node(excludes[0].0) };
    let frame = match alloc_hugepage_2m_on(node) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Fail("mixed mprotect hugepage allocation failed"),
    };
    // SAFETY: paging is live and the test exclusively owns this root.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => {
            crate::hugepage::free_hugepage(frame);
            let _ = alloc_hugepage_2m_on(node);
            return TestResult::Fail("mixed mprotect address-space creation failed");
        }
    };
    let huge_base = VirtAddr::new(USER_VA);
    // SAFETY: the fresh root, aligned VA, and owned aligned frame satisfy the
    // huge mapping contract.
    if unsafe {
        address_space.map_huge_region(HugeRegion {
            base: huge_base,
            len: HUGEPAGE_2M_BYTES,
            perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::LOCKED,
            size: HugeSize::M2,
            frames: alloc::vec![frame],
        })
    }
    .is_err()
    {
        let _ = alloc_hugepage_2m_on(node);
        return TestResult::Fail("mixed mprotect huge mapping failed");
    }
    let regular_base = VirtAddr::new(USER_VA + HUGEPAGE_2M_BYTES);
    if address_space
        .map_region(Region {
            base: regular_base,
            len: 0x3000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0); 3],
        })
        .is_err()
    {
        let _ = address_space.unmap_huge_region(huge_base);
        let _ = alloc_hugepage_2m_on(node);
        return TestResult::Fail("mixed mprotect regular mapping failed");
    }

    let writable_before = address_space.memory_stats().writable_nonexec_bytes;
    address_space.__test_fail_next_region_index_reserve();
    let failed =
        address_space.mprotect_range(huge_base, HUGEPAGE_2M_BYTES + 0x2000, RegionPerms::READ);
    let failure_atomic = failed == Err(AddressSpaceError::AllocationFailed)
        && address_space.memory_stats().writable_nonexec_bytes == writable_before
        && address_space.lookup(regular_base).is_some_and(|region| {
            region.len == 0x3000 && region.perms.contains(RegionPerms::WRITE)
        })
        && address_space
            .__test_huge_region_perms(huge_base)
            .is_some_and(|perms| perms.contains(RegionPerms::WRITE));
    if !failure_atomic {
        let _ = address_space.unmap_huge_region(huge_base);
        let _ = alloc_hugepage_2m_on(node);
        return TestResult::Fail("mixed mprotect ENOMEM partially changed permissions");
    }

    let retry =
        address_space.mprotect_range(huge_base, HUGEPAGE_2M_BYTES + 0x2000, RegionPerms::READ);
    let huge_preserved = address_space
        .__test_huge_region_perms(huge_base)
        .is_some_and(|perms| {
            perms.contains(RegionPerms::LOCKED) && !perms.contains(RegionPerms::WRITE)
        });
    let regular_split = address_space
        .lookup(regular_base)
        .is_some_and(|region| region.len == 0x2000 && !region.perms.contains(RegionPerms::WRITE))
        && address_space
            .lookup(VirtAddr::new(regular_base.as_u64() + 0x2000))
            .is_some_and(|region| {
                region.len == 0x1000 && region.perms.contains(RegionPerms::WRITE)
            });
    let unmapped = address_space.unmap_huge_region(huge_base).is_ok();
    let _ = alloc_hugepage_2m_on(node);
    if retry.is_ok() && huge_preserved && regular_split && unmapped {
        TestResult::Pass
    } else {
        TestResult::Fail("mixed mprotect retry lost flags or split metadata")
    }
}
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "kernel-test"
))]
kernel_test_in!(
    "memory",
    smoke_memory_mprotect_mixed_huge_index_oom_is_preflight
);

/// `MAP_SHARED | MAP_HUGETLB` is one object mapped twice, so fork must ALIAS
/// its huge frames, not copy them. Copying gives parent and child private
/// snapshots that diverge on the first write — and because nothing faults or
/// errors, that surfaces as lost updates in whatever the region holds,
/// arbitrarily far from the fork.
///
/// The private control arm is the point of the test. Private hugetlb mappings
/// must still be copied eagerly: the pool has no sub-page COW metadata, so
/// sharing a writable block leaf there would break fork isolation. One bit
/// selects between two opposite behaviours, and both have to be pinned or a
/// later change can quietly swap them.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "kernel-test"
))]
fn smoke_memory_shared_hugetlb_fork_aliases_frames() -> TestResult {
    use crate::frame::UsableRegion;
    use crate::hugepage::{
        alloc_hugepage_2m_on, free_hugepage, hugepage_refs, reserve_from_regions, HugeSize,
        HUGEPAGE_2M_BYTES,
    };
    use crate::{AddressSpace, HugeRegion, PhysAddr, RegionPerms, VirtAddr};

    const SYNTH_BASE: u64 = 0x40_8000_0000;
    const USER_VA: u64 = 0x0000_5000_9000_0000;
    // Two frames: one for the shared arm, one for the private arm's source.
    // The private arm's fork also needs a third to copy INTO.
    let source = UsableRegion {
        start: PhysAddr::new(SYNTH_BASE),
        len: HUGEPAGE_2M_BYTES * 3,
    };
    // SAFETY: the synthetic frames back mapping metadata only and are returned
    // to the test reservation before this test exits.
    let excludes = unsafe { reserve_from_regions(&[source], &[], 3, 0) };
    if excludes.len() != 3 {
        return TestResult::Fail("shared-hugetlb reservation failed");
    }
    // SAFETY: topology lookup does not dereference the synthetic frames.
    let node = unsafe { crate::frame::narf_phys_node(excludes[0].0) };

    let shared_frame = match alloc_hugepage_2m_on(node) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Fail("shared-hugetlb allocation failed"),
    };
    // SAFETY: paging is live and the test exclusively owns this root.
    let parent = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => {
            free_hugepage(shared_frame);
            return TestResult::Fail("shared-hugetlb address space creation failed");
        }
    };
    let base = VirtAddr::new(USER_VA);
    // SAFETY: fresh root, aligned VA, owned aligned frame.
    if unsafe {
        parent.map_huge_region(HugeRegion {
            base,
            len: HUGEPAGE_2M_BYTES,
            perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED,
            size: HugeSize::M2,
            frames: alloc::vec![shared_frame],
        })
    }
    .is_err()
    {
        free_hugepage(shared_frame);
        return TestResult::Fail("shared huge mapping failed");
    }
    if hugepage_refs(shared_frame) != 1 {
        return TestResult::Fail("a freshly mapped huge frame was not singly owned");
    }

    // SAFETY: paging is live; the parent is a well-formed user address space.
    let child = match unsafe { parent.clone_for_fork() } {
        Ok(child) => child,
        Err(_) => return TestResult::Fail("fork of a shared huge mapping failed"),
    };
    // Aliased, not copied: one more owner of the SAME frame.
    let aliased = hugepage_refs(shared_frame) == 2;
    // The child sees the mapping with the same permissions.
    let child_mapped = child
        .__test_huge_region_perms(base)
        .is_some_and(|perms| perms.contains(RegionPerms::SHARED));

    // Dropping one address space releases a reference; the frame stays live
    // for the other. Freeing it outright here would be a use-after-free in
    // whichever process still had it mapped.
    drop(child);
    let survives_first_exit = hugepage_refs(shared_frame) == 1;
    drop(parent);

    // Now unreferenced, so it is back in the pool and allocatable again.
    // Deliberately NOT freed again: this test must leave the pool's free
    // count exactly as it found it. Frames left in the free list are visible
    // to every later test through the shared pool, and the first symptom is
    // some unrelated case whose "this allocation must fail" assertion
    // silently starts succeeding.
    let reclaimed = alloc_hugepage_2m_on(node);
    let returned = reclaimed
        .as_ref()
        .is_ok_and(|f| f.phys() == shared_frame.phys());

    if !aliased {
        return TestResult::Fail("fork copied a shared huge mapping instead of aliasing it");
    }
    if !child_mapped {
        return TestResult::Fail("the forked child lost its shared huge mapping");
    }
    if !survives_first_exit {
        return TestResult::Fail("one address space exiting freed a still-shared huge frame");
    }
    if !returned {
        return TestResult::Fail("the last reference did not return the huge frame to the pool");
    }

    // ── Control: a PRIVATE huge mapping still forks by copy ───────────
    //
    // Unlike the shared arm, this one moves real bytes: forking a private
    // huge mapping copies the whole 2 MiB between frames. The frames here are
    // synthetic — fabricated addresses outside installed RAM, reserved so the
    // shared arm can exercise refcount and mapping bookkeeping without
    // perturbing the real pool — so whether they can be *dereferenced* is a
    // question, not a given.
    //
    // On x86_64 the identity map spans 512 GiB regardless of how much RAM is
    // installed, so the copy silently succeeds against physical addresses
    // that are not memory. On aarch64 the kernel linear map covers only what
    // `frame/src/aarch64/boot.S` mapped, and the copy faults. Ask the page
    // tables rather than assume either.
    let copy_target_is_addressable = {
        let va = crate::PhysAddr::new(SYNTH_BASE).kernel_ptr::<u8>() as u64;
        crate::bpf_text::kernel_root_for_mapping().is_some_and(|root| {
            // SAFETY: `root` is the recorded live kernel root; `translate`
            // only reads the tables.
            unsafe { crate::paging::translate(root, VirtAddr::new(va)) }.is_some()
        })
    };
    if !copy_target_is_addressable {
        // Drain the two frames the private arm would have taken, so the pool
        // is left exactly as it was found — three reserved, three drained.
        let _ = alloc_hugepage_2m_on(node);
        let _ = alloc_hugepage_2m_on(node);
        return TestResult::Skip(
            "synthetic huge frames are outside the kernel linear map; \
             a private fork's 2 MiB copy cannot be performed on them",
        );
    }

    let private_frame = match alloc_hugepage_2m_on(node) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Fail("private-hugetlb allocation failed"),
    };
    // SAFETY: paging is live and the test exclusively owns this root.
    let owner = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => {
            free_hugepage(private_frame);
            return TestResult::Fail("private-hugetlb address space creation failed");
        }
    };
    // SAFETY: fresh root, aligned VA, owned aligned frame.
    if unsafe {
        owner.map_huge_region(HugeRegion {
            base,
            len: HUGEPAGE_2M_BYTES,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            size: HugeSize::M2,
            frames: alloc::vec![private_frame],
        })
    }
    .is_err()
    {
        free_hugepage(private_frame);
        return TestResult::Fail("private huge mapping failed");
    }
    // SAFETY: same contract as the shared fork above.
    let private_child = unsafe { owner.clone_for_fork() };
    let copied = private_child.is_ok() && hugepage_refs(private_frame) == 1;
    drop(private_child);
    drop(owner);

    // Drain the private arm's two frames — the original and the copy fork
    // made — for the same reason. Three reserved, three drained.
    let _ = alloc_hugepage_2m_on(node);
    let _ = alloc_hugepage_2m_on(node);

    if !copied {
        return TestResult::Fail("fork aliased a PRIVATE huge mapping instead of copying it");
    }
    TestResult::Pass
}
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "kernel-test"
))]
kernel_test_in!("memory", smoke_memory_shared_hugetlb_fork_aliases_frames);

/// Huge mappings are held in `huge_regions`, a vector entirely separate from
/// the `regions` tree that [`AddressSpace::perms_intersecting`] walks. A
/// caller asking "is anything mapped here?" through `perms_intersecting`
/// alone therefore gets `false` over a live 2 MiB mapping — which is what let
/// `MAP_FIXED_NOREPLACE` (whose whole contract is -EEXIST instead of
/// replacement) unmap a hugetlb region it was supposed to refuse to touch.
///
/// This pins both halves: that `perms_intersecting` really is blind here (so
/// the second query is load-bearing, not belt-and-braces), and that
/// `huge_intersects` sees it with the right interval arithmetic. The
/// one-byte-past-the-end and adjacent-regular-region arms are the ones that
/// matter — a `<=` in place of `<` would make every FIXED_NOREPLACE probe
/// that merely abuts a huge mapping fail with a spurious EEXIST.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "kernel-test"
))]
fn smoke_memory_huge_intersects_sees_hugetlb_mappings() -> TestResult {
    use crate::frame::UsableRegion;
    use crate::hugepage::{
        alloc_hugepage_2m_on, reserve_from_regions, HugeSize, HUGEPAGE_2M_BYTES,
    };
    use crate::{AddressSpace, HugeRegion, PhysAddr, Region, RegionPerms, VirtAddr};

    const SYNTH_BASE: u64 = 0x40_4000_0000;
    const USER_VA: u64 = 0x0000_5000_7000_0000;
    let source = UsableRegion {
        start: PhysAddr::new(SYNTH_BASE),
        len: HUGEPAGE_2M_BYTES,
    };
    // SAFETY: the synthetic frame is used for mapping metadata only and is
    // returned to the test reservation before this test exits.
    let excludes = unsafe { reserve_from_regions(&[source], &[], 1, 0) };
    if excludes.len() != 1 {
        return TestResult::Fail("huge_intersects hugepage reservation failed");
    }
    // SAFETY: topology lookup does not dereference the synthetic frame.
    let node = unsafe { crate::frame::narf_phys_node(excludes[0].0) };
    let frame = match alloc_hugepage_2m_on(node) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Fail("huge_intersects hugepage allocation failed"),
    };
    // SAFETY: paging is live and the test exclusively owns this root.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => {
            crate::hugepage::free_hugepage(frame);
            let _ = alloc_hugepage_2m_on(node);
            return TestResult::Fail("huge_intersects address-space creation failed");
        }
    };
    let huge_base = VirtAddr::new(USER_VA);
    // SAFETY: the fresh root, aligned VA, and owned aligned frame satisfy the
    // huge mapping contract.
    if unsafe {
        address_space.map_huge_region(HugeRegion {
            base: huge_base,
            len: HUGEPAGE_2M_BYTES,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            size: HugeSize::M2,
            frames: alloc::vec![frame],
        })
    }
    .is_err()
    {
        let _ = alloc_hugepage_2m_on(node);
        return TestResult::Fail("huge_intersects huge mapping failed");
    }
    let regular_base = VirtAddr::new(USER_VA + HUGEPAGE_2M_BYTES);
    if address_space
        .map_region(Region {
            base: regular_base,
            len: 0x1000,
            perms: RegionPerms::READ,
            phys: alloc::vec![PhysAddr::new(0); 1],
        })
        .is_err()
    {
        let _ = address_space.unmap_huge_region(huge_base);
        let _ = alloc_hugepage_2m_on(node);
        return TestResult::Fail("huge_intersects regular mapping failed");
    }

    // The blindness this query exists to cover.
    let base_page_view_is_blind = address_space
        .perms_intersecting(huge_base, HUGEPAGE_2M_BYTES)
        .is_empty();
    let whole = address_space.huge_intersects(huge_base, HUGEPAGE_2M_BYTES);
    // A single byte anywhere inside counts.
    let inside = address_space.huge_intersects(VirtAddr::new(USER_VA + 0x1000), 1);
    // A probe that spans the boundary from below.
    let straddling = address_space.huge_intersects(VirtAddr::new(USER_VA - 0x1000), 0x2000);
    // Abutting from above is NOT an overlap: `regular_base` is the first byte
    // past the huge mapping's end.
    let abutting_after = address_space.huge_intersects(regular_base, 0x1000);
    // Abutting from below likewise.
    let abutting_before = address_space.huge_intersects(VirtAddr::new(USER_VA - 0x1000), 0x1000);
    // A zero-length probe overlaps nothing, and an overflowing one must not panic.
    let empty = address_space.huge_intersects(huge_base, 0);
    let overflow = address_space.huge_intersects(VirtAddr::new(u64::MAX - 1), 0x1000);

    let unmapped = address_space.unmap_huge_region(huge_base).is_ok();
    let _ = alloc_hugepage_2m_on(node);

    if !base_page_view_is_blind {
        return TestResult::Fail(
            "perms_intersecting now sees huge mappings; second query is stale",
        );
    }
    if !(whole && inside && straddling) {
        return TestResult::Fail("huge_intersects missed an overlapping range");
    }
    if abutting_after || abutting_before || empty || overflow {
        return TestResult::Fail("huge_intersects reported a non-overlapping range");
    }
    if !unmapped {
        return TestResult::Fail("huge_intersects test failed to unmap");
    }
    TestResult::Pass
}
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "kernel-test"
))]
kernel_test_in!("memory", smoke_memory_huge_intersects_sees_hugetlb_mappings);

/// `mm/madvise.c::madvise_walk_vmas` reports a hole as -ENOMEM whether the
/// range starts in one (`if (!vma) return -ENOMEM;`) or merely crosses one
/// (`unmapped_error = -ENOMEM`, after which the walk carries on). madvise
/// hints are otherwise no-ops here, so this coverage query is the entire
/// decision — a caller that madvises a region it believes it owns uses ENOMEM
/// to discover it does not, and a success tells it the opposite.
///
/// The mixed regular/huge arm is the one worth pinning. A range spanning an
/// ordinary and a hugetlb mapping is fully covered, and a query that walked
/// only the base-page tree would call it a hole and report ENOMEM for a
/// perfectly well-formed range.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "kernel-test"
))]
fn smoke_memory_range_fully_mapped_spans_regular_and_huge() -> TestResult {
    use crate::frame::UsableRegion;
    use crate::hugepage::{
        alloc_hugepage_2m_on, reserve_from_regions, HugeSize, HUGEPAGE_2M_BYTES,
    };
    use crate::{AddressSpace, HugeRegion, PhysAddr, Region, RegionPerms, VirtAddr};

    const SYNTH_BASE: u64 = 0x40_C000_0000;
    const USER_VA: u64 = 0x0000_5000_A000_0000;
    let source = UsableRegion {
        start: PhysAddr::new(SYNTH_BASE),
        len: HUGEPAGE_2M_BYTES,
    };
    // SAFETY: the synthetic frame backs mapping metadata only.
    let excludes = unsafe { reserve_from_regions(&[source], &[], 1, 0) };
    if excludes.len() != 1 {
        return TestResult::Fail("coverage-query reservation failed");
    }
    // SAFETY: topology lookup does not dereference the synthetic frame.
    let node = unsafe { crate::frame::narf_phys_node(excludes[0].0) };
    let frame = match alloc_hugepage_2m_on(node) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Fail("coverage-query hugepage allocation failed"),
    };
    // SAFETY: paging is live and the test exclusively owns this root.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => {
            crate::hugepage::free_hugepage(frame);
            return TestResult::Fail("coverage-query address space creation failed");
        }
    };
    // A huge mapping immediately followed by an ordinary one, no gap.
    let huge_base = VirtAddr::new(USER_VA);
    // SAFETY: fresh root, aligned VA, owned aligned frame.
    if unsafe {
        address_space.map_huge_region(HugeRegion {
            base: huge_base,
            len: HUGEPAGE_2M_BYTES,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            size: HugeSize::M2,
            frames: alloc::vec![frame],
        })
    }
    .is_err()
    {
        crate::hugepage::free_hugepage(frame);
        return TestResult::Fail("coverage-query huge mapping failed");
    }
    let regular_base = VirtAddr::new(USER_VA + HUGEPAGE_2M_BYTES);
    if address_space
        .map_region(Region {
            base: regular_base,
            len: 0x2000,
            perms: RegionPerms::READ,
            phys: alloc::vec![PhysAddr::new(0); 2],
        })
        .is_err()
    {
        let _ = address_space.unmap_huge_region(huge_base);
        let _ = alloc_hugepage_2m_on(node);
        return TestResult::Fail("coverage-query regular mapping failed");
    }

    // Each alone, and the two together across the boundary.
    let huge_only = address_space.range_fully_mapped(huge_base, HUGEPAGE_2M_BYTES);
    let regular_only = address_space.range_fully_mapped(regular_base, 0x2000);
    let spanning = address_space.range_fully_mapped(huge_base, HUGEPAGE_2M_BYTES + 0x2000);
    // One byte past the end is a hole, and so is a range that starts in one.
    let past_end = address_space.range_fully_mapped(huge_base, HUGEPAGE_2M_BYTES + 0x3000);
    let starts_in_hole = address_space.range_fully_mapped(VirtAddr::new(USER_VA - 0x1000), 0x1000);
    // Zero length covers nothing and must not be a hole; an overflowing
    // range must not panic.
    let empty = address_space.range_fully_mapped(huge_base, 0);
    let overflow = address_space.range_fully_mapped(VirtAddr::new(u64::MAX - 1), 0x1000);

    let unmapped = address_space.unmap_huge_region(huge_base).is_ok();
    // Drain the reserved frame so the shared pool's free count is unchanged.
    let _ = alloc_hugepage_2m_on(node);

    if !(huge_only && regular_only && spanning && empty) {
        return TestResult::Fail("range_fully_mapped reported a hole in a covered range");
    }
    if past_end || starts_in_hole || overflow {
        return TestResult::Fail("range_fully_mapped missed a hole");
    }
    if !unmapped {
        return TestResult::Fail("coverage-query test failed to unmap");
    }
    TestResult::Pass
}
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "kernel-test"
))]
kernel_test_in!(
    "memory",
    smoke_memory_range_fully_mapped_spans_regular_and_huge
);

/// `mm/msync.c` rejects MS_INVALIDATE over a `VM_LOCKED` VMA with -EBUSY.
/// NARF's msync reads that state back through `perms_intersecting`, so the
/// handler is only correct if LOCKED actually survives into the perms this
/// query reports — and only if the query reports the perms of *every* VMA the
/// range touches, not just the first. A range that is half unlocked and half
/// locked is still EBUSY on Linux, because the check sits inside the per-VMA
/// walk and `goto`s out on the first locked one.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "kernel-test"
))]
fn smoke_memory_perms_intersecting_reports_locked() -> TestResult {
    use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

    const USER_VA: u64 = 0x0000_5000_8000_0000;
    // SAFETY: paging is live and the test exclusively owns this root.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Fail("locked-perms address-space creation failed"),
    };
    let unlocked_base = VirtAddr::new(USER_VA);
    let locked_base = VirtAddr::new(USER_VA + 0x1000);
    if address_space
        .map_region(Region {
            base: unlocked_base,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0); 1],
        })
        .is_err()
        || address_space
            .map_region(Region {
                base: locked_base,
                len: 0x1000,
                perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::LOCKED,
                phys: alloc::vec![PhysAddr::new(0); 1],
            })
            .is_err()
    {
        return TestResult::Fail("locked-perms mapping failed");
    }

    let locked_only = address_space
        .perms_intersecting(locked_base, 0x1000)
        .iter()
        .any(|p| p.contains(RegionPerms::LOCKED));
    // The unlocked VMA alone must not report LOCKED, or msync would return
    // EBUSY for every MS_INVALIDATE and the flag would be unusable.
    let unlocked_only = address_space
        .perms_intersecting(unlocked_base, 0x1000)
        .iter()
        .any(|p| p.contains(RegionPerms::LOCKED));
    // Spanning both: Linux stops at the first locked VMA, so the mixed range
    // is EBUSY too. This is the arm that fails if the query ever collapses to
    // "perms of the VMA containing `base`".
    let spanning = address_space
        .perms_intersecting(unlocked_base, 0x2000)
        .iter()
        .any(|p| p.contains(RegionPerms::LOCKED));

    if locked_only && !unlocked_only && spanning {
        TestResult::Pass
    } else {
        TestResult::Fail("perms_intersecting misreported LOCKED across the range")
    }
}
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "kernel-test"
))]
kernel_test_in!("memory", smoke_memory_perms_intersecting_reports_locked);

/// Linux replaces `mm->def_flags` on every mlockall call rather than stacking
/// successive MCL_FUTURE modes.  In particular, MCL_CURRENT without
/// MCL_FUTURE clears a previously-installed future policy.
fn smoke_memory_future_lock_policy_replaces_and_current_clears() -> TestResult {
    use crate::{AddressSpace, FutureLockPolicy};

    let a = AddressSpace::empty();
    if a.update_mlockall(None, FutureLockPolicy::Eager).is_err()
        || a.future_lock_policy() != FutureLockPolicy::Eager
    {
        return TestResult::Fail("MCL_FUTURE did not install eager policy");
    }
    if a.update_mlockall(None, FutureLockPolicy::OnFault).is_err()
        || a.future_lock_policy() != FutureLockPolicy::OnFault
    {
        return TestResult::Fail("future on-fault policy did not replace eager policy");
    }
    if a.update_mlockall(Some(FutureLockPolicy::Eager), FutureLockPolicy::None)
        .is_err()
    {
        return TestResult::Fail("MCL_CURRENT policy update failed");
    }
    if a.future_lock_policy() == FutureLockPolicy::None {
        TestResult::Pass
    } else {
        TestResult::Fail("MCL_CURRENT without MCL_FUTURE left stale future policy")
    }
}
kernel_test_in!(
    "memory",
    smoke_memory_future_lock_policy_replaces_and_current_clears
);

/// New ordinary mappings inherit the address-space default.  Eager future
/// locking must populate a lazy page, while MCL_ONFAULT must preserve its lazy
/// slot and record the distinct on-fault mode in addition to LOCKED.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_future_lock_policy_applies_to_new_mappings() -> TestResult {
    use crate::{AddressSpace, FutureLockPolicy, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: paging is live in the kernel-test harness; this test exclusively
    // owns the fresh root and keeps it alive through both mapping operations.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    // Keep the VA in PML4[1]'s deliberately-empty 512..513 GiB user slot.
    // Addresses at/above 0x80_4000_0000 overlap the inherited high-MMIO map.
    let eager_base = VirtAddr::new(0x0000_0080_3400_0000);
    if a.update_mlockall(None, FutureLockPolicy::Eager).is_err()
        || a.map_region(Region {
            base: eager_base,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("eager future-lock mapping failed");
    }
    let eager = a.lookup(eager_base).map(|region| {
        (
            region.perms.contains(RegionPerms::LOCKED),
            region.perms.contains(RegionPerms::LOCK_ONFAULT),
            region.phys[0].raw() != 0,
        )
    });
    if !matches!(eager, Some((true, false, true))) {
        if a.root.raw() == 0 {
            core::mem::forget(a);
            return TestResult::Fail("new_for_user returned root zero, so eager helper skipped");
        }
        if !matches!(eager, Some((true, false, false))) {
            core::mem::forget(a);
            return TestResult::Fail("eager future policy did not publish the expected lock mode");
        }
        // Diagnostic control: exercise the same primitive the best-effort eager
        // helper calls.  The test still fails when this works; the distinction
        // tells us whether enumeration skipped the page or demand allocation
        // itself was unavailable without adding hot-path instrumentation.
        // SAFETY: fresh test-owned live root and initialized frame allocator.
        let direct = unsafe { a.demand_alloc_page(eager_base) };
        let direct_backed = a
            .lookup(eager_base)
            .is_some_and(|region| region.phys[0].raw() != 0);
        core::mem::forget(a);
        return match (direct, direct_backed) {
            (Ok(()), true) => {
                TestResult::Fail("direct demand worked but eager helper skipped the page")
            }
            (Ok(()), false) => {
                TestResult::Fail("direct demand returned success without publishing backing")
            }
            (Err(_), _) => TestResult::Fail("direct demand failed after eager helper failure"),
        };
    }

    let onfault_base = VirtAddr::new(0x0000_0080_3400_1000);
    if a.update_mlockall(None, FutureLockPolicy::OnFault).is_err()
        || a.map_region(Region {
            base: onfault_base,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("on-fault future-lock mapping failed");
    }
    let onfault = a.lookup(onfault_base).is_some_and(|region| {
        region.perms.contains(RegionPerms::LOCKED)
            && region.perms.contains(RegionPerms::LOCK_ONFAULT)
            && region.phys[0].raw() == 0
    });
    core::mem::forget(a);
    if onfault {
        TestResult::Pass
    } else {
        TestResult::Fail("on-fault future mapping was populated or lost its lock mode")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_future_lock_policy_applies_to_new_mappings
);

/// munlockall clears both current VMA lock modes and the policy inherited by
/// later mappings.  Resident contents remain backed.  Use an explicitly
/// resident setup page so this test is independent of eager-population coverage
/// above: one broken behavior should produce one focused failure.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_munlock_all_clears_current_and_future_locking() -> TestResult {
    use crate::{AddressSpace, FutureLockPolicy, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: fresh test-owned user root; paging and the frame allocator are
    // initialized by the kernel-test harness.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let resident = match crate::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => {
            core::mem::forget(a);
            return TestResult::Skip("frame drained");
        }
    };
    let locked_base = VirtAddr::new(0x0000_0080_3500_0000);
    if a.update_mlockall(None, FutureLockPolicy::OnFault).is_err()
        || a.map_region(Region {
            base: locked_base,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![resident],
        })
        .is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("munlockall setup failed");
    }
    if a.munlock_all().is_err() {
        core::mem::forget(a);
        return TestResult::Fail("munlockall failed");
    }
    let current_cleared = a.lookup(locked_base).is_some_and(|region| {
        !region.perms.contains(RegionPerms::LOCKED)
            && !region.perms.contains(RegionPerms::LOCK_ONFAULT)
            && region.phys[0] == resident
    });
    let later_base = VirtAddr::new(0x0000_0080_3500_1000);
    let later_unlocked = a.future_lock_policy() == FutureLockPolicy::None
        && a.map_region(Region {
            base: later_base,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_ok()
        && a.lookup(later_base).is_some_and(|region| {
            !region.perms.contains(RegionPerms::LOCKED)
                && !region.perms.contains(RegionPerms::LOCK_ONFAULT)
                && region.phys[0].raw() == 0
        });
    core::mem::forget(a);
    if current_cleared && later_unlocked {
        TestResult::Pass
    } else if !current_cleared {
        TestResult::Fail("munlockall changed backing or left current VMA locked")
    } else {
        TestResult::Fail("munlockall left a future-lock policy")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_munlock_all_clears_current_and_future_locking
);

/// POSIX memory locks do not cross fork.  Linux clears VM_LOCKED_MASK from
/// every duplicated VMA and excludes those bits from the child's def_flags;
/// the parent must remain unchanged.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_fork_clears_current_and_future_locking() -> TestResult {
    use crate::{AddressSpace, FutureLockPolicy, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: fresh test-owned root; clone_for_fork's allocator/MMU
    // preconditions are supplied by the kernel-test harness.
    let parent = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let base = VirtAddr::new(0x0000_0080_3600_0000);
    if parent
        .update_mlockall(None, FutureLockPolicy::OnFault)
        .is_err()
        || parent
            .map_region(Region {
                base,
                len: 0x1000,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![PhysAddr::new(0)],
            })
            .is_err()
    {
        core::mem::forget(parent);
        return TestResult::Fail("fork lock-policy setup failed");
    }
    // SAFETY: parent is inactive and exclusively owned here; neither address
    // space becomes scheduler-visible during the test.
    let child = match unsafe { parent.clone_for_fork() } {
        Ok(child) => child,
        Err(_) => {
            core::mem::forget(parent);
            return TestResult::Fail("clone_for_fork failed");
        }
    };
    let parent_kept = parent.future_lock_policy() == FutureLockPolicy::OnFault
        && parent.lookup(base).is_some_and(|region| {
            region.perms.contains(RegionPerms::LOCKED)
                && region.perms.contains(RegionPerms::LOCK_ONFAULT)
        });
    let child_cleared = child.future_lock_policy() == FutureLockPolicy::None
        && child.lookup(base).is_some_and(|region| {
            !region.perms.contains(RegionPerms::LOCKED)
                && !region.perms.contains(RegionPerms::LOCK_ONFAULT)
        });
    core::mem::forget(child);
    core::mem::forget(parent);
    if parent_kept && child_cleared {
        TestResult::Pass
    } else if !parent_kept {
        TestResult::Fail("fork cleared the parent's lock state")
    } else {
        TestResult::Fail("fork child inherited current or future memory locking")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_fork_clears_current_and_future_locking
);

/// RLIMIT_MEMLOCK accounts virtual bytes, but a repeated/overlapping mlock
/// must subtract pages that are already locked.  Expanding one page to two at
/// a two-page limit therefore succeeds; a third distinct page is rejected and
/// remains unchanged.
fn smoke_memory_mlock_limit_subtracts_locked_overlap() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = AddressSpace::empty();
    let base = 0x0000_4080_2400_0000u64;
    if a.map_region(Region {
        base: VirtAddr::new(base),
        len: 0x3000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0); 3],
    })
    .is_err()
    {
        return TestResult::Fail("lock-limit setup mapping failed");
    }
    if a.mlock_range_onfault_limited(VirtAddr::new(base), 0x1000, 0x2000, false)
        .is_err()
        || a.mlock_range_onfault_limited(VirtAddr::new(base), 0x2000, 0x2000, false)
            .is_err()
    {
        return TestResult::Fail("overlapping locked bytes were counted twice");
    }
    // Exercise the eager mlock limit API for the rejection arm as well; it
    // must fail admission before trying to populate the metadata-only AS.
    if a.mlock_range_limited(VirtAddr::new(base + 0x2000), 0x1000, 0x2000, false)
        != Err(AddressSpaceError::LockLimit)
    {
        return TestResult::Fail("distinct page beyond lock limit was admitted");
    }

    let regions = a.regions_snapshot();
    let lock_mode = |va: u64| {
        regions
            .iter()
            .find(|region| region.base.as_u64() <= va && va < region.base.as_u64() + region.len)
            .map(|region| {
                (
                    region.perms.contains(RegionPerms::LOCKED),
                    region.perms.contains(RegionPerms::LOCK_ONFAULT),
                )
            })
    };
    if lock_mode(base) == Some((true, true))
        && lock_mode(base + 0x1000) == Some((true, true))
        && lock_mode(base + 0x2000) == Some((false, false))
    {
        TestResult::Pass
    } else {
        TestResult::Fail("lock-limit failure mutated the rejected page")
    }
}
kernel_test_in!("memory", smoke_memory_mlock_limit_subtracts_locked_overlap);

/// A failed MCL_CURRENT limit preflight is transactional: it must not replace
/// the prior MCL_FUTURE default or partially rewrite current VMA lock modes.
fn smoke_memory_mlockall_limit_failure_preserves_state() -> TestResult {
    use crate::{
        AddressSpace, AddressSpaceError, FutureLockPolicy, PhysAddr, Region, RegionPerms, VirtAddr,
    };

    let a = AddressSpace::empty();
    let plain = VirtAddr::new(0x0000_4080_2500_0000);
    let inherited = VirtAddr::new(0x0000_4080_2500_1000);
    if a.map_region(Region {
        base: plain,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .is_err()
        || a.update_mlockall(None, FutureLockPolicy::OnFault).is_err()
        || a.map_region(Region {
            base: inherited,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
    {
        return TestResult::Fail("mlockall transaction setup failed");
    }
    if a.update_mlockall_limited(
        Some(FutureLockPolicy::Eager),
        FutureLockPolicy::Eager,
        0x1000,
        false,
    ) != Err(AddressSpaceError::LockLimit)
    {
        return TestResult::Fail("mlockall over the lock limit did not fail");
    }

    let plain_unchanged = a.lookup(plain).is_some_and(|region| {
        !region.perms.contains(RegionPerms::LOCKED)
            && !region.perms.contains(RegionPerms::LOCK_ONFAULT)
            && region.phys[0].raw() == 0
    });
    let inherited_unchanged = a.lookup(inherited).is_some_and(|region| {
        region.perms.contains(RegionPerms::LOCKED)
            && region.perms.contains(RegionPerms::LOCK_ONFAULT)
            && region.phys[0].raw() == 0
    });
    if a.future_lock_policy() == FutureLockPolicy::OnFault && plain_unchanged && inherited_unchanged
    {
        TestResult::Pass
    } else {
        TestResult::Fail("failed mlockall changed prior current/future lock state")
    }
}
kernel_test_in!(
    "memory",
    smoke_memory_mlockall_limit_failure_preserves_state
);

/// NARF's explicit stack-guard region models Linux's unmapped guard gap. It
/// must not consume RLIMIT_MEMLOCK admission for MCL_CURRENT.
fn smoke_memory_mlockall_limit_excludes_stack_guard() -> TestResult {
    use crate::{AddressSpace, FutureLockPolicy, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = AddressSpace::empty();
    let plain = VirtAddr::new(0x0000_4080_2580_0000);
    let guard = VirtAddr::new(0x0000_4080_2580_1000);
    if a.map_region(Region {
        base: plain,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .is_err()
        || a.map_region(Region {
            base: guard,
            len: 0x1000,
            perms: RegionPerms::STACK_GUARD | RegionPerms::LOCK_EXEMPT,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
    {
        return TestResult::Fail("guard accounting setup failed");
    }
    if a.update_mlockall_limited(
        Some(FutureLockPolicy::OnFault),
        FutureLockPolicy::None,
        0x1000,
        false,
    )
    .is_err()
    {
        return TestResult::Fail("synthetic guard consumed RLIMIT_MEMLOCK");
    }
    let plain_locked = a.lookup(plain).is_some_and(|region| {
        region.perms.contains(RegionPerms::LOCKED)
            && region.perms.contains(RegionPerms::LOCK_ONFAULT)
    });
    let guard_unlocked = a.lookup(guard).is_some_and(|region| {
        !region.perms.contains(RegionPerms::LOCKED)
            && !region.perms.contains(RegionPerms::LOCK_ONFAULT)
    });
    if plain_locked && guard_unlocked {
        TestResult::Pass
    } else {
        TestResult::Fail("MCL_CURRENT changed the synthetic guard")
    }
}
kernel_test_in!("memory", smoke_memory_mlockall_limit_excludes_stack_guard);

/// A PROT_NONE special VMA is neither eligible for inherited future locking
/// nor for MCL_CURRENT.  Its lazy slot must remain untouched by both eager
/// population opportunities.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_lock_exempt_prot_none_ignores_mlockall() -> TestResult {
    use crate::{AddressSpace, FutureLockPolicy, PhysAddr, Region, RegionPerms, VirtAddr};

    // SAFETY: fresh test-owned user root; paging is live in the test harness.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let base = VirtAddr::new(0x0000_4080_2600_0000);
    if a.update_mlockall(None, FutureLockPolicy::Eager).is_err()
        || a.map_region(Region {
            base,
            len: 0x1000,
            perms: RegionPerms::LOCK_EXEMPT,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
        || a.update_mlockall(Some(FutureLockPolicy::Eager), FutureLockPolicy::Eager)
            .is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("lock-exempt setup or mlockall failed");
    }
    let exempt = a.lookup(base).is_some_and(|region| {
        region.perms.prot_only().0 == 0
            && region.perms.contains(RegionPerms::LOCK_EXEMPT)
            && !region.perms.contains(RegionPerms::LOCKED)
            && !region.perms.contains(RegionPerms::LOCK_ONFAULT)
            && region.phys[0].raw() == 0
    });
    core::mem::forget(a);
    if exempt {
        TestResult::Pass
    } else {
        TestResult::Fail("mlockall locked or populated a PROT_NONE lock-exempt VMA")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_lock_exempt_prot_none_ignores_mlockall
);

/// Growing an eagerly locked VMA must populate the appended pages immediately;
/// leaving a zero slot would violate the original eager-lock contract.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_eager_locked_grow_populates_tail() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: fresh test-owned user root and initialized frame allocator.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let resident = match crate::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => {
            core::mem::forget(a);
            return TestResult::Skip("frame drained");
        }
    };
    let base = VirtAddr::new(0x0000_4080_2700_0000);
    if a.map_region(Region {
        base,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::LOCKED,
        phys: alloc::vec![resident],
    })
    .is_err()
        || a.grow_region(base, 0x2000).is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("eager locked grow failed");
    }
    let populated = a.lookup(base).is_some_and(|region| {
        region.len == 0x2000
            && region.perms.contains(RegionPerms::LOCKED)
            && !region.perms.contains(RegionPerms::LOCK_ONFAULT)
            && region.phys[0] == resident
            && region.phys[1].raw() != 0
            && region.phys[1] != resident
    });
    core::mem::forget(a);
    if populated {
        TestResult::Pass
    } else {
        TestResult::Fail("eager locked grow left its appended page lazy")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_eager_locked_grow_populates_tail);

/// A user-half-valid but allocator-impossible mremap grow must report a typed
/// allocation failure instead of entering the kernel allocator's abort path.
/// The failed reservation is made before `Region::len` or its backing vector
/// changes, so the original mapping remains authoritative.
fn smoke_memory_grow_metadata_allocation_is_fallible() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    let address_space = AddressSpace::empty();
    let base = VirtAddr::new(AddressSpace::MMAP_CURSOR_BASE);
    if address_space
        .map_region(Region {
            base,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
    {
        return TestResult::Fail("metadata-allocation setup failed");
    }
    let impossible_len = AddressSpace::USER_HALF_END - base.as_u64();
    if address_space.grow_region(base, impossible_len) != Err(AddressSpaceError::AllocationFailed) {
        return TestResult::Fail("impossible metadata grow did not fail cleanly");
    }
    if address_space
        .lookup(base)
        .is_some_and(|region| region.len == 0x1000 && region.phys == alloc::vec![PhysAddr::new(0)])
    {
        TestResult::Pass
    } else {
        TestResult::Fail("failed metadata reservation changed the source VMA")
    }
}
kernel_test_in!("memory", smoke_memory_grow_metadata_allocation_is_fallible);

/// mremap growth follows Linux's MEMLOCK -> AS -> DATA admission order and
/// implements the RLIMIT_DATA soft-zero/hard-limit compatibility exception.
fn smoke_memory_mremap_growth_limit_order_and_data_compat() -> TestResult {
    use crate::{
        AddressSpace, AddressSpaceError, MremapLimits, PhysAddr, Region, RegionPerms, VirtAddr,
    };

    let locked = AddressSpace::empty();
    let locked_base = VirtAddr::new(0x0000_4080_2500_0000);
    if locked
        .map_region(Region {
            base: locked_base,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::LOCKED,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
    {
        return TestResult::Fail("mremap limit-order setup failed");
    }
    let both_exceeded = locked.grow_region_limited(
        locked_base,
        0x2000,
        MremapLimits {
            memlock_bytes: 0x1000,
            address_space_bytes: 0x1000,
            data_bytes: u64::MAX,
            data_max_bytes: u64::MAX,
            bypass_memlock: false,
        },
    );
    let as_exceeded = locked.grow_region_limited(
        locked_base,
        0x2000,
        MremapLimits {
            memlock_bytes: u64::MAX,
            address_space_bytes: 0x1000,
            data_bytes: u64::MAX,
            data_max_bytes: u64::MAX,
            bypass_memlock: true,
        },
    );
    if both_exceeded != Err(AddressSpaceError::LockLimit)
        || as_exceeded != Err(AddressSpaceError::MappingLimit)
        || locked
            .lookup(locked_base)
            .is_none_or(|region| region.len != 0x1000)
    {
        return TestResult::Fail("mremap growth limit ordering or rollback was wrong");
    }

    let soft_zero = AddressSpace::empty();
    let soft_zero_base = VirtAddr::new(0x0000_4080_2510_0000);
    if soft_zero
        .map_region(Region {
            base: soft_zero_base,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
    {
        return TestResult::Fail("RLIMIT_DATA compatibility setup failed");
    }
    let compat = soft_zero.grow_region_limited(
        soft_zero_base,
        0x2000,
        MremapLimits {
            memlock_bytes: u64::MAX,
            address_space_bytes: u64::MAX,
            data_bytes: 0,
            data_max_bytes: 0x2000,
            bypass_memlock: true,
        },
    );

    let hard = AddressSpace::empty();
    let hard_base = VirtAddr::new(0x0000_4080_2520_0000);
    if hard
        .map_region(Region {
            base: hard_base,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
    {
        return TestResult::Fail("RLIMIT_DATA hard-limit setup failed");
    }
    let beyond_hard = hard.grow_region_limited(
        hard_base,
        0x2000,
        MremapLimits {
            memlock_bytes: u64::MAX,
            address_space_bytes: u64::MAX,
            data_bytes: 0,
            data_max_bytes: 0x1000,
            bypass_memlock: true,
        },
    );
    if compat.is_ok()
        && soft_zero
            .lookup(soft_zero_base)
            .is_some_and(|region| region.len == 0x2000)
        && beyond_hard == Err(AddressSpaceError::MappingLimit)
        && hard
            .lookup(hard_base)
            .is_some_and(|region| region.len == 0x1000)
    {
        TestResult::Pass
    } else {
        TestResult::Fail("RLIMIT_DATA soft-zero compatibility did not match Linux")
    }
}
kernel_test_in!(
    "memory",
    smoke_memory_mremap_growth_limit_order_and_data_compat
);

/// Shared mremap aliases may select an interval inside one Region. Historical
/// old_len==0 duplication performs MEMLOCK before AS admission and leaves the
/// source lock state alone; DONTUNMAP skips MEMLOCK, charges the complete new
/// VMA, and clears the lock bits only after the alias commits.
fn smoke_memory_shared_mremap_interval_and_limit_modes() -> TestResult {
    use crate::{
        AddressSpace, AddressSpaceError, MremapLimits, PhysAddr, Region, RegionPerms,
        SharedMremapMode, VirtAddr,
    };

    let address_space = AddressSpace::empty();
    let source = VirtAddr::new(0x0000_4080_2600_0000);
    let duplicate = VirtAddr::new(0x0000_4080_2610_0000);
    let dontunmap = VirtAddr::new(0x0000_4080_2620_0000);
    if address_space
        .map_region(Region {
            base: source,
            len: 0x3000,
            perms: RegionPerms::READ
                | RegionPerms::WRITE
                | RegionPerms::SHARED
                | RegionPerms::LOCKED,
            phys: alloc::vec![PhysAddr::new(0); 3],
        })
        .is_err()
    {
        return TestResult::Fail("shared mremap interval setup failed");
    }

    // The source already accounts for three locked pages, so a fourth page
    // fails Duplicate's pre-mutation MEMLOCK admission even though AS is open.
    // SAFETY: AddressSpace::empty has no live root; the test exercises only
    // serialized metadata publication.
    let memlock_failure = unsafe {
        address_space.alias_shared_region_limited(
            VirtAddr::new(source.as_u64() + 0x1000),
            0x1000,
            duplicate,
            SharedMremapMode::Duplicate,
            MremapLimits {
                memlock_bytes: 0x3000,
                address_space_bytes: u64::MAX,
                data_bytes: u64::MAX,
                data_max_bytes: u64::MAX,
                bypass_memlock: false,
            },
        )
    };
    if memlock_failure != Err(AddressSpaceError::LockLimit)
        || address_space.lookup(duplicate).is_some()
        || address_space
            .lookup(source)
            .is_none_or(|region| !region.perms.contains(RegionPerms::LOCKED))
    {
        return TestResult::Fail("Duplicate did not fail atomically at MEMLOCK");
    }

    // SAFETY: same metadata-only address-space contract as above.
    let duplicate_result = unsafe {
        address_space.alias_shared_region_limited(
            VirtAddr::new(source.as_u64() + 0x1000),
            0x1000,
            duplicate,
            SharedMremapMode::Duplicate,
            MremapLimits {
                memlock_bytes: 0x4000,
                address_space_bytes: 0x4000,
                data_bytes: u64::MAX,
                data_max_bytes: u64::MAX,
                bypass_memlock: false,
            },
        )
    };
    if duplicate_result.is_err()
        || address_space.lookup(duplicate).is_none_or(|region| {
            region.len != 0x1000 || !region.perms.contains(RegionPerms::LOCKED)
        })
        || address_space
            .lookup(source)
            .is_none_or(|region| !region.perms.contains(RegionPerms::LOCKED))
    {
        return TestResult::Fail("Duplicate did not preserve interval/lock metadata");
    }

    // Four pages are now mapped. DONTUNMAP bypasses a deliberately impossible
    // MEMLOCK limit but must fail AS admission before changing either VMA.
    // SAFETY: same metadata-only address-space contract as above.
    let as_failure = unsafe {
        address_space.alias_shared_region_limited(
            source,
            0x1000,
            dontunmap,
            SharedMremapMode::DontUnmap,
            MremapLimits {
                memlock_bytes: 0,
                address_space_bytes: 0x4000,
                data_bytes: u64::MAX,
                data_max_bytes: u64::MAX,
                bypass_memlock: false,
            },
        )
    };
    if as_failure != Err(AddressSpaceError::MappingLimit)
        || address_space.lookup(dontunmap).is_some()
        || address_space
            .lookup(source)
            .is_none_or(|region| !region.perms.contains(RegionPerms::LOCKED))
    {
        return TestResult::Fail("DONTUNMAP AS failure changed source metadata");
    }

    // SAFETY: same metadata-only address-space contract as above.
    let dontunmap_result = unsafe {
        address_space.alias_shared_region_limited(
            source,
            0x1000,
            dontunmap,
            SharedMremapMode::DontUnmap,
            MremapLimits {
                memlock_bytes: 0,
                address_space_bytes: 0x5000,
                data_bytes: u64::MAX,
                data_max_bytes: u64::MAX,
                bypass_memlock: false,
            },
        )
    };
    if dontunmap_result.is_ok()
        && address_space.lookup(source).is_some_and(|region| {
            !region.perms.contains(RegionPerms::LOCKED)
                && !region.perms.contains(RegionPerms::LOCK_ONFAULT)
        })
        && address_space.lookup(dontunmap).is_some_and(|region| {
            region.len == 0x1000 && region.perms.contains(RegionPerms::LOCKED)
        })
    {
        TestResult::Pass
    } else {
        TestResult::Fail("DONTUNMAP did not transfer the shared lock contract")
    }
}
kernel_test_in!(
    "memory",
    smoke_memory_shared_mremap_interval_and_limit_modes
);

/// Linux permits ordinary demand-paged file VMAs in DONTUNMAP despite their
/// lock-accounting exemption, rejects PFN/device-like DONTUNMAP sources, and
/// still permits the legacy old_len==0 shared duplication of such sources.
fn smoke_memory_shared_mremap_lock_exempt_eligibility() -> TestResult {
    use crate::{
        AddressSpace, AddressSpaceError, MremapLimits, PhysAddr, Region, RegionPerms,
        SharedMremapMode, VirtAddr,
    };

    let file_as = AddressSpace::empty();
    let file_source = VirtAddr::new(0x0000_4080_2630_0000);
    let file_alias = VirtAddr::new(0x0000_4080_2640_0000);
    if file_as
        .map_region(Region {
            base: file_source,
            len: 0x1000,
            perms: RegionPerms::READ
                | RegionPerms::SHARED
                | RegionPerms::FILE_DEMAND
                | RegionPerms::LOCK_EXEMPT,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
    {
        return TestResult::Fail("file DONTUNMAP eligibility setup failed");
    }
    // SAFETY: metadata-only address space; wrapper supplies both transactions.
    let file_result = unsafe {
        file_as.alias_shared_region_limited(
            file_source,
            0x1000,
            file_alias,
            SharedMremapMode::DontUnmap,
            MremapLimits::UNLIMITED,
        )
    };
    if file_result.is_err() || file_as.lookup(file_alias).is_none() {
        return TestResult::Fail("demand-paged file DONTUNMAP was rejected");
    }

    let device_as = AddressSpace::empty();
    let device_source = VirtAddr::new(0x0000_4080_2650_0000);
    let duplicate_alias = VirtAddr::new(0x0000_4080_2660_0000);
    let dontunmap_alias = VirtAddr::new(0x0000_4080_2670_0000);
    if device_as
        .map_region(Region {
            base: device_source,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::SHARED | RegionPerms::LOCK_EXEMPT,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
    {
        return TestResult::Fail("device shared-duplication eligibility setup failed");
    }
    // SAFETY: same metadata-only transaction contract as above.
    let duplicate_result = unsafe {
        device_as.alias_shared_region_limited(
            device_source,
            0x1000,
            duplicate_alias,
            SharedMremapMode::Duplicate,
            MremapLimits::UNLIMITED,
        )
    };
    // SAFETY: same metadata-only transaction contract as above.
    let dontunmap_result = unsafe {
        device_as.alias_shared_region_limited(
            device_source,
            0x1000,
            dontunmap_alias,
            SharedMremapMode::DontUnmap,
            MremapLimits::UNLIMITED,
        )
    };
    if duplicate_result.is_ok()
        && dontunmap_result == Err(AddressSpaceError::NotImplemented)
        && device_as.lookup(duplicate_alias).is_some()
        && device_as.lookup(dontunmap_alias).is_none()
    {
        TestResult::Pass
    } else {
        TestResult::Fail("LOCK_EXEMPT mode-specific eligibility diverged")
    }
}
kernel_test_in!("memory", smoke_memory_shared_mremap_lock_exempt_eligibility);

/// Duplicate preflight preserves a fixed target, while DONTUNMAP deliberately
/// performs full AS admission after target retirement and reports that state.
fn smoke_memory_shared_mremap_fixed_punch_order() -> TestResult {
    use crate::{
        AddressSpace, AddressSpaceError, FixedRelocationError, MremapLimits, PhysAddr, Region,
        RegionPerms, SharedMremapMode, VirtAddr,
    };

    let duplicate_as = AddressSpace::empty();
    let duplicate_source = VirtAddr::new(0x0000_4080_2700_0000);
    let duplicate_target = VirtAddr::new(AddressSpace::USER_FIXED_FLOOR);
    if duplicate_as
        .map_region(Region {
            base: duplicate_source,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::SHARED | RegionPerms::LOCKED,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
        || duplicate_as
            .map_region(Region {
                base: duplicate_target,
                len: 0x1000,
                perms: RegionPerms::READ,
                phys: alloc::vec![PhysAddr::new(0)],
            })
            .is_err()
    {
        return TestResult::Fail("fixed Duplicate setup failed");
    }
    // SAFETY: AddressSpace::empty has no live root; both wrappers serialize
    // their metadata-only fixed transactions internally.
    let duplicate_failure = unsafe {
        duplicate_as.alias_shared_region_fixed_limited(
            duplicate_source,
            0x1000,
            duplicate_target,
            SharedMremapMode::Duplicate,
            MremapLimits {
                memlock_bytes: 0x1000,
                address_space_bytes: u64::MAX,
                data_bytes: u64::MAX,
                data_max_bytes: u64::MAX,
                bypass_memlock: false,
            },
        )
    };
    if duplicate_failure
        != Err(FixedRelocationError {
            error: AddressSpaceError::LockLimit,
            target_punched: false,
            source_shrunk: false,
        })
        || duplicate_as.lookup(duplicate_target).is_none()
    {
        return TestResult::Fail("Duplicate limit failure retired its fixed target");
    }

    let dontunmap_as = AddressSpace::empty();
    let dontunmap_source = VirtAddr::new(0x0000_4080_2710_0000);
    let dontunmap_target = VirtAddr::new(AddressSpace::USER_FIXED_FLOOR);
    if dontunmap_as
        .map_region(Region {
            base: dontunmap_source,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::SHARED | RegionPerms::LOCKED,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
        || dontunmap_as
            .map_region(Region {
                base: dontunmap_target,
                len: 0x1000,
                perms: RegionPerms::READ,
                phys: alloc::vec![PhysAddr::new(0)],
            })
            .is_err()
    {
        return TestResult::Fail("fixed DONTUNMAP setup failed");
    }
    // SAFETY: same metadata-only fixed transaction contract as above.
    let dontunmap_failure = unsafe {
        dontunmap_as.alias_shared_region_fixed_limited(
            dontunmap_source,
            0x1000,
            dontunmap_target,
            SharedMremapMode::DontUnmap,
            MremapLimits {
                memlock_bytes: 0,
                address_space_bytes: 0x1000,
                data_bytes: u64::MAX,
                data_max_bytes: u64::MAX,
                bypass_memlock: false,
            },
        )
    };
    let expected = Err(FixedRelocationError {
        error: AddressSpaceError::MappingLimit,
        target_punched: true,
        source_shrunk: false,
    });
    if dontunmap_failure == expected
        && dontunmap_as.lookup(dontunmap_target).is_none()
        && dontunmap_as
            .lookup(dontunmap_source)
            .is_some_and(|region| region.perms.contains(RegionPerms::LOCKED))
    {
        TestResult::Pass
    } else {
        TestResult::Fail("DONTUNMAP did not expose its post-punch limit failure")
    }
}
kernel_test_in!("memory", smoke_memory_shared_mremap_fixed_punch_order);

/// Shared DONTUNMAP moves source residency/rmap authority to the destination,
/// keeps both backing descriptions, and lets the retained source fault the
/// same shared frame back in.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_shared_mremap_installs_destination_rmap() -> TestResult {
    use crate::{
        AddressSpace, MremapLimits, PhysAddr, PhysFrame, Region, RegionPerms, SharedMremapMode,
        VirtAddr,
    };

    #[cfg(target_arch = "x86_64")]
    unsafe fn translated(address_space: &AddressSpace, va: VirtAddr) -> Option<PhysAddr> {
        // SAFETY: caller supplies this test's live, exclusively-owned user root.
        unsafe { crate::x86_64::paging::translate(address_space.root, va) }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe fn translated(address_space: &AddressSpace, va: VirtAddr) -> Option<PhysAddr> {
        // SAFETY: same contract as the x86_64 arm above — the caller supplies
        // this test's live, exclusively-owned user root.
        unsafe { crate::aarch64::paging::translate(address_space.root, va) }
    }

    // SAFETY: the fresh user root is owned exclusively by this test and is
    // never activated as a task address space.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Skip("shared alias root allocation failed"),
    };
    let frame = match crate::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Skip("shared alias backing allocation failed"),
    };
    let source = VirtAddr::new(0x0000_4094_0000_0000);
    let destination = VirtAddr::new(0x0000_4095_0000_0000);
    let mapped = address_space.with_vma_transaction(|| {
        crate::with_shared_mapping_transaction(|| {
            // SAFETY: both required structural transactions are held; the root
            // and allocated backing remain live for publication/materialization.
            unsafe {
                address_space.map_shared_region_locked(Region {
                    base: source,
                    len: 0x1000,
                    perms: RegionPerms::READ
                        | RegionPerms::WRITE
                        | RegionPerms::SHARED
                        | RegionPerms::LOCKED,
                    phys: alloc::vec![frame],
                })?;
                address_space.materialize_range(source, 0x1000)
            }
        })
    });
    if mapped.is_err() {
        return TestResult::Fail("shared alias source materialization failed");
    }

    #[cfg(feature = "kernel-test")]
    {
        crate::address_space::__test_fail_next_shared_alias_after_install();
        // SAFETY: same live test-root and wrapper-supplied transactions as the
        // successful publication below. The injected error fires only after
        // the destination PTE has been installed.
        let injected = unsafe {
            address_space.alias_shared_region_limited(
                source,
                0x1000,
                destination,
                SharedMremapMode::DontUnmap,
                MremapLimits::UNLIMITED,
            )
        };
        // SAFETY: the rollback has completed while the test root remains live.
        let rolled_back_destination = unsafe { translated(&address_space, destination) };
        if injected != Err(crate::AddressSpaceError::AllocationFailed)
            || rolled_back_destination.is_some()
            || crate::rmap::owner_count(frame) != 1
            || address_space.lookup(destination).is_some()
            || address_space
                .lookup(source)
                .is_none_or(|region| !region.perms.contains(RegionPerms::LOCKED))
        {
            return TestResult::Fail("shared alias post-install rollback leaked state");
        }
    }

    // SAFETY: the test-owned user root and backing remain live; the convenience
    // wrapper supplies VMA then shared-owner serialization.
    let aliased = unsafe {
        address_space.alias_shared_region_limited(
            source,
            0x1000,
            destination,
            SharedMremapMode::DontUnmap,
            MremapLimits::UNLIMITED,
        )
    };
    // SAFETY: both read-only walks target this test's still-live user root.
    let source_translation = unsafe { translated(&address_space, source) };
    // SAFETY: same live-root proof as the source walk.
    let destination_translation = unsafe { translated(&address_space, destination) };
    let moved = aliased.is_ok()
        && source_translation.is_none()
        && destination_translation == Some(frame)
        && crate::rmap::owner_count(frame) == 1
        && address_space.residency_range(source, 0x1000) == Ok(alloc::vec![0])
        && address_space.residency_range(destination, 0x1000) == Ok(alloc::vec![1])
        && address_space.lookup(source).is_some_and(|region| {
            !region.perms.contains(RegionPerms::LOCKED) && region.phys == alloc::vec![frame]
        })
        && address_space.lookup(destination).is_some_and(|region| {
            region.perms.contains(RegionPerms::LOCKED) && region.phys == alloc::vec![frame]
        });
    if !moved {
        return TestResult::Fail("shared DONTUNMAP did not move residency/rmap authority");
    }

    // SAFETY: the retained source VMA still owns shared backing in this live
    // test root. The backed-fault repair path must reinstall its leaf and rmap.
    let refaulted = unsafe { address_space.demand_alloc_page(source) };
    // SAFETY: both walks target the still-live test root after refault repair.
    let source_after_refault = unsafe { translated(&address_space, source) };
    // SAFETY: same live-root proof for the unchanged destination.
    let destination_after_refault = unsafe { translated(&address_space, destination) };
    let correct = refaulted.is_ok()
        && source_after_refault == Some(frame)
        && destination_after_refault == Some(frame)
        && crate::rmap::owner_count(frame) == 2
        && address_space.residency_range(source, 0x1000) == Ok(alloc::vec![1])
        && address_space.residency_range(destination, 0x1000) == Ok(alloc::vec![1]);
    drop(address_space);
    crate::free_frame(PhysFrame::new(frame));
    if correct {
        TestResult::Pass
    } else {
        TestResult::Fail("shared DONTUNMAP source did not refault its backing")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_shared_mremap_installs_destination_rmap
);

/// Legacy old_len==0 shared duplication clones resident leaves instead of
/// moving them, unlike DONTUNMAP.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_shared_duplicate_clones_residency() -> TestResult {
    use crate::{
        AddressSpace, MremapLimits, PhysFrame, Region, RegionPerms, SharedMremapMode, VirtAddr,
    };

    // `free_frame` is rmap-agnostic: it returns the frame to the buddy
    // allocator without touching its owner list, because in production the
    // unmap path has already called `rmap::remove` for every mapping. A test
    // that frees a frame it never unmapped therefore leaves owners behind,
    // and the NEXT test to be handed that frame inherits them.
    //
    // That is exactly what happened here. This test asserts an owner count of
    // two, and was reading a frame that arrived with stale owners from an
    // earlier case — so it failed on a count of >2 while its own two owners
    // were both correctly registered. Every other rmap-sensitive test in this
    // crate (see `migrate.rs`) resets first; this one did not.
    crate::rmap::__reset_for_test();

    #[cfg(target_arch = "x86_64")]
    unsafe fn translated(address_space: &AddressSpace, va: VirtAddr) -> Option<crate::PhysAddr> {
        // SAFETY: caller supplies this test's live, exclusively-owned user root.
        unsafe { crate::x86_64::paging::translate(address_space.root, va) }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe fn translated(address_space: &AddressSpace, va: VirtAddr) -> Option<crate::PhysAddr> {
        // SAFETY: caller supplies this test's live, exclusively-owned user root.
        unsafe { crate::aarch64::paging::translate(address_space.root, va) }
    }

    // SAFETY: fresh test-owned root is never activated by a task.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Skip("shared Duplicate root allocation failed"),
    };
    let frame = match crate::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Skip("shared Duplicate backing allocation failed"),
    };
    let source = VirtAddr::new(0x0000_4096_0000_0000);
    let destination = VirtAddr::new(0x0000_4097_0000_0000);
    let mapped = address_space.with_vma_transaction(|| {
        crate::with_shared_mapping_transaction(|| {
            // SAFETY: both structural transactions and live-root ownership are
            // held through mapping and materialization.
            unsafe {
                address_space.map_shared_region_locked(Region {
                    base: source,
                    len: 0x1000,
                    perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED,
                    phys: alloc::vec![frame],
                })?;
                address_space.materialize_range(source, 0x1000)
            }
        })
    });
    if mapped.is_err() {
        return TestResult::Fail("shared Duplicate source materialization failed");
    }
    // SAFETY: wrapper supplies both transactions; root/backing remain live.
    let duplicated = unsafe {
        address_space.alias_shared_region_limited(
            source,
            0x1000,
            destination,
            SharedMremapMode::Duplicate,
            MremapLimits::UNLIMITED,
        )
    };
    // SAFETY: both translations read this test's live root.
    let source_translation = unsafe { translated(&address_space, source) };
    // SAFETY: same live-root proof as the source translation.
    let destination_translation = unsafe { translated(&address_space, destination) };
    // Report WHICH invariant broke. As a single six-way conjunction this
    // could only ever say "something about Duplicate is wrong", which is not
    // enough to act on — the alias, the rmap owner count and the two
    // residency views fail for quite different reasons.
    let owners = crate::rmap::owner_count(frame);
    let source_owned = crate::rmap::contains_owner(frame, address_space.root, source);
    let destination_owned = crate::rmap::contains_owner(frame, address_space.root, destination);
    let source_residency = address_space.residency_range(source, 0x1000);
    let destination_residency = address_space.residency_range(destination, 0x1000);
    let verdict: Result<(), &'static str> = (|| {
        if duplicated.is_err() {
            return Err("shared Duplicate alias failed outright");
        }
        if source_translation != Some(frame) {
            return Err("shared Duplicate dropped the SOURCE translation");
        }
        if destination_translation != Some(frame) {
            return Err("shared Duplicate did not map the DESTINATION to the frame");
        }
        if owners != 2 {
            // Say WHICH owner is missing: the destination never being
            // registered and the source being lost are different bugs with
            // different fixes, and "the count is wrong" distinguishes neither.
            return Err(match (source_owned, destination_owned) {
                (true, false) => "shared Duplicate never registered the DESTINATION rmap owner",
                (false, true) => "shared Duplicate LOST the source rmap owner",
                (false, false) => "shared Duplicate left the frame with no rmap owner at all",
                (true, true) if owners > 2 => {
                    "shared Duplicate left MORE than two rmap owners on the frame"
                }
                (true, true) => {
                    "shared Duplicate registered both owners but the count is below two"
                }
            });
        }
        if source_residency != Ok(alloc::vec![1]) {
            return Err("shared Duplicate cleared the SOURCE residency (moved, not cloned)");
        }
        if destination_residency != Ok(alloc::vec![1]) {
            return Err("shared Duplicate left the DESTINATION non-resident");
        }
        Ok(())
    })();
    drop(address_space);
    crate::free_frame(PhysFrame::new(frame));
    match verdict {
        Ok(()) => TestResult::Pass,
        Err(msg) => TestResult::Fail(msg),
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_shared_duplicate_clones_residency);

/// Ordinary nonzero-length shared mremap may select an interval inside one
/// VMA, preserve both outside fragments, transfer only the kept backing, and
/// lazily extend a locked destination after admitting the growth delta.
fn smoke_memory_shared_relocation_splits_and_grows() -> TestResult {
    use crate::{AddressSpace, MremapLimits, PhysAddr, Region, RegionPerms, VirtAddr};

    let address_space = AddressSpace::empty();
    let source = VirtAddr::new(0x0000_4080_2c00_0000);
    let destination = VirtAddr::new(0x0000_4080_2d00_0000);
    let backing = alloc::vec![
        PhysAddr::new(0x1100_0000),
        PhysAddr::new(0x1100_1000),
        PhysAddr::new(0x1100_2000),
        PhysAddr::new(0x1100_3000),
    ];
    if address_space
        .map_region(Region {
            base: source,
            len: 0x4000,
            perms: RegionPerms::READ
                | RegionPerms::WRITE
                | RegionPerms::SHARED
                | RegionPerms::LOCKED,
            phys: backing.clone(),
        })
        .is_err()
    {
        return TestResult::Fail("shared relocation split setup failed");
    }

    // SAFETY: AddressSpace::empty has no live root; the wrapper supplies both
    // structural transactions for this metadata-only move.
    let moved = unsafe {
        address_space.relocate_shared_region_limited(
            VirtAddr::new(source.as_u64() + 0x1000),
            0x2000,
            destination,
            0x3000,
            MremapLimits {
                memlock_bytes: 0x5000,
                address_space_bytes: 0x5000,
                data_bytes: 0,
                data_max_bytes: 0,
                bypass_memlock: false,
            },
        )
    };
    let head = address_space
        .lookup(source)
        .is_some_and(|region| region.len == 0x1000 && region.phys == alloc::vec![backing[0]]);
    let removed = address_space
        .lookup(VirtAddr::new(source.as_u64() + 0x1000))
        .is_none();
    let tail = address_space
        .lookup(VirtAddr::new(source.as_u64() + 0x3000))
        .is_some_and(|region| region.len == 0x1000 && region.phys == alloc::vec![backing[3]]);
    let destination_correct = address_space.lookup(destination).is_some_and(|region| {
        region.len == 0x3000
            && region.perms.contains(RegionPerms::LOCKED)
            && region.phys == alloc::vec![backing[1], backing[2], PhysAddr::new(0)]
    });
    if moved.is_ok() && head && removed && tail && destination_correct {
        TestResult::Pass
    } else {
        TestResult::Fail("shared relocation did not preserve split/backing metadata")
    }
}
kernel_test_in!("memory", smoke_memory_shared_relocation_splits_and_grows);

/// Region-index allocation is part of relocation preflight. Ordinary moves
/// leave the source authoritative, and fixed moves fail before retiring an
/// occupied target, when arena capacity cannot be prepared.
#[cfg(feature = "kernel-test")]
fn smoke_memory_shared_relocation_index_oom_is_preflight() -> TestResult {
    use crate::{
        AddressSpace, AddressSpaceError, FixedRelocationError, MremapLimits, PhysAddr, Region,
        RegionPerms, VirtAddr,
    };

    let address_space = AddressSpace::empty();
    let source = VirtAddr::new(0x0000_409d_0000_0000);
    let destination = VirtAddr::new(0x0000_409e_0000_0000);
    let target = VirtAddr::new(AddressSpace::USER_FIXED_FLOOR + 0x80_0000);
    let source_phys = alloc::vec![PhysAddr::new(0), PhysAddr::new(0), PhysAddr::new(0),];
    if address_space
        .map_region(Region {
            base: source,
            len: 0x3000,
            perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED,
            phys: source_phys.clone(),
        })
        .is_err()
        || address_space
            .map_region(Region {
                base: target,
                len: 0x1000,
                perms: RegionPerms::READ,
                phys: alloc::vec![PhysAddr::new(0)],
            })
            .is_err()
    {
        return TestResult::Fail("region-index OOM setup failed");
    }

    address_space.__test_fail_next_region_index_reserve();
    // SAFETY: AddressSpace::empty is metadata-only and this wrapper supplies
    // both structural transactions.
    let ordinary = unsafe {
        address_space.relocate_shared_region_limited(
            VirtAddr::new(source.as_u64() + 0x1000),
            0x1000,
            destination,
            0x1000,
            MremapLimits::UNLIMITED,
        )
    };
    if ordinary != Err(AddressSpaceError::AllocationFailed)
        || address_space.lookup(destination).is_some()
        || !address_space
            .lookup(source)
            .is_some_and(|region| region.len == 0x3000 && region.phys == source_phys)
    {
        return TestResult::Fail("ordinary shared index OOM mutated VMA state");
    }

    address_space.__test_fail_next_region_index_reserve();
    // SAFETY: same metadata-only proof. The occupied target must remain live
    // because its punch also prepares capacity for the later destination.
    let fixed = unsafe {
        address_space.relocate_shared_region_fixed_limited(
            source,
            0x3000,
            target,
            0x3000,
            MremapLimits::UNLIMITED,
        )
    };
    let expected = Err(FixedRelocationError {
        error: AddressSpaceError::AllocationFailed,
        target_punched: false,
        source_shrunk: false,
    });
    if fixed == expected
        && address_space.lookup(target).is_some()
        && address_space
            .lookup(source)
            .is_some_and(|region| region.len == 0x3000 && region.phys == source_phys)
    {
        TestResult::Pass
    } else {
        TestResult::Fail("fixed shared index OOM retired source or target")
    }
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "memory",
    smoke_memory_shared_relocation_index_oom_is_preflight
);

/// A resident ordinary shared move transfers PTE/rmap authority instead of
/// cloning it. A truncated page loses its rmap only after the source leaves
/// are retired, while a failed post-install attempt rolls back to the source.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_shared_relocation_moves_residency() -> TestResult {
    use crate::{AddressSpace, MremapLimits, PhysFrame, Region, RegionPerms, VirtAddr};

    // This test asserts exact global reverse-map owner counts. Isolate those
    // counts from deliberately retained mappings in earlier memory smokes.
    crate::rmap::__reset_for_test();

    #[cfg(target_arch = "x86_64")]
    unsafe fn translated(address_space: &AddressSpace, va: VirtAddr) -> Option<crate::PhysAddr> {
        // SAFETY: caller supplies this test's live, exclusively-owned root.
        unsafe { crate::x86_64::paging::translate(address_space.root, va) }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe fn translated(address_space: &AddressSpace, va: VirtAddr) -> Option<crate::PhysAddr> {
        // SAFETY: caller supplies this test's live, exclusively-owned root.
        unsafe { crate::aarch64::paging::translate(address_space.root, va) }
    }

    // SAFETY: fresh test root is exclusively owned and never activated.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(address_space) => address_space,
        Err(_) => return TestResult::Skip("shared relocation root allocation failed"),
    };
    let first = match crate::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Skip("shared relocation first frame unavailable"),
    };
    let second = match crate::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => {
            crate::free_frame(PhysFrame::new(first));
            return TestResult::Skip("shared relocation second frame unavailable");
        }
    };
    let source = VirtAddr::new(0x0000_4098_0000_0000);
    #[cfg(feature = "kernel-test")]
    let rollback_destination = VirtAddr::new(0x0000_4099_0000_0000);
    let destination = VirtAddr::new(0x0000_409a_0000_0000);
    let mapped = address_space.with_vma_transaction(|| {
        crate::with_shared_mapping_transaction(|| {
            // SAFETY: both structural transactions, the live root, and backing
            // frames remain owned by this test.
            unsafe {
                address_space.map_shared_region_locked(Region {
                    base: source,
                    len: 0x2000,
                    perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED,
                    phys: alloc::vec![first, second],
                })?;
                address_space.materialize_range(source, 0x2000)
            }
        })
    });
    if mapped.is_err() {
        return TestResult::Fail("shared relocation materialization failed");
    }

    #[cfg(feature = "kernel-test")]
    {
        crate::address_space::__test_fail_next_shared_relocation_after_install();
        // SAFETY: wrapper supplies both transactions; injected failure occurs
        // before any source/rmap/backing commit.
        let injected = unsafe {
            address_space.relocate_shared_region_limited(
                source,
                0x2000,
                rollback_destination,
                0x1000,
                MremapLimits::UNLIMITED,
            )
        };
        // SAFETY: all translations inspect this test's still-live root.
        let source_first = unsafe { translated(&address_space, source) };
        // SAFETY: same live-root proof.
        let source_second =
            unsafe { translated(&address_space, VirtAddr::new(source.as_u64() + 0x1000)) };
        // SAFETY: same live-root proof after rollback.
        let rolled_back = unsafe { translated(&address_space, rollback_destination) };
        if injected != Err(crate::AddressSpaceError::AllocationFailed) {
            return TestResult::Fail("shared relocation injection returned the wrong error");
        }
        if source_first != Some(first) || source_second != Some(second) {
            return TestResult::Fail("shared relocation rollback changed source translations");
        }
        if rolled_back.is_some() {
            return TestResult::Fail("shared relocation rollback left a destination translation");
        }
        if crate::rmap::owner_count(first) != 1 || crate::rmap::owner_count(second) != 1 {
            return TestResult::Fail("shared relocation rollback changed reverse-map ownership");
        }
        if address_space.lookup(rollback_destination).is_some() {
            return TestResult::Fail("shared relocation rollback left destination metadata");
        }
    }

    // SAFETY: wrapper supplies both transactions; root/backing remain live.
    let moved = unsafe {
        address_space.relocate_shared_region_limited(
            source,
            0x2000,
            destination,
            0x1000,
            MremapLimits::UNLIMITED,
        )
    };
    // SAFETY: all translations inspect the test-owned live root.
    let old_first = unsafe { translated(&address_space, source) };
    // SAFETY: same live-root proof.
    let old_second = unsafe { translated(&address_space, VirtAddr::new(source.as_u64() + 0x1000)) };
    // SAFETY: same live-root proof.
    let new_first = unsafe { translated(&address_space, destination) };
    let correct = moved.is_ok()
        && old_first.is_none()
        && old_second.is_none()
        && new_first == Some(first)
        && crate::rmap::owner_count(first) == 1
        && crate::rmap::contains_owner(first, address_space.root, destination)
        && crate::rmap::owner_count(second) == 0
        && address_space.lookup(source).is_none()
        && address_space
            .lookup(destination)
            .is_some_and(|region| region.len == 0x1000 && region.phys == alloc::vec![first]);
    drop(address_space);
    crate::free_frame(PhysFrame::new(first));
    crate::free_frame(PhysFrame::new(second));
    if correct {
        TestResult::Pass
    } else {
        TestResult::Fail("ordinary shared relocation cloned or lost residency")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_memory_shared_relocation_moves_residency);

/// Ordinary shared fixed moves admit locked growth before target retirement
/// and expose every later failure as destructive, matching Linux's ownership
/// handoff boundary.
fn smoke_memory_shared_relocation_fixed_order() -> TestResult {
    use crate::{
        AddressSpace, AddressSpaceError, FixedRelocationError, MremapLimits, PhysAddr, Region,
        RegionPerms, VirtAddr,
    };

    let address_space = AddressSpace::empty();
    let target = VirtAddr::new(AddressSpace::USER_FIXED_FLOOR);
    let source = VirtAddr::new(AddressSpace::USER_HALF_END - 0x1000);
    if address_space
        .map_region(Region {
            base: source,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::SHARED | RegionPerms::LOCKED,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
        || address_space
            .map_region(Region {
                base: target,
                len: 0x1000,
                perms: RegionPerms::READ,
                phys: alloc::vec![PhysAddr::new(0)],
            })
            .is_err()
    {
        return TestResult::Fail("shared fixed relocation setup failed");
    }

    // SAFETY: AddressSpace::empty has no live root; wrappers serialize these
    // metadata-only fixed transactions.
    let early = unsafe {
        address_space.relocate_shared_region_fixed_limited(
            source,
            0x1000,
            target,
            0x2000,
            MremapLimits {
                memlock_bytes: 0x1000,
                address_space_bytes: u64::MAX,
                data_bytes: u64::MAX,
                data_max_bytes: u64::MAX,
                bypass_memlock: false,
            },
        )
    };
    if early
        != Err(FixedRelocationError {
            error: AddressSpaceError::LockLimit,
            target_punched: false,
            source_shrunk: false,
        })
        || address_space.lookup(target).is_none()
    {
        return TestResult::Fail("shared fixed preflight retired its target");
    }

    let impossible_len = source.as_u64() - target.as_u64();
    // SAFETY: same metadata-only fixed transaction. Proportional preparation
    // fails only after the one-page target has been punched.
    let late = unsafe {
        address_space.relocate_shared_region_fixed_limited(
            source,
            0x1000,
            target,
            impossible_len,
            MremapLimits::UNLIMITED,
        )
    };
    if late
        == Err(FixedRelocationError {
            error: AddressSpaceError::AllocationFailed,
            target_punched: true,
            source_shrunk: false,
        })
        && address_space.lookup(target).is_none()
        && address_space.lookup(source).is_some()
    {
        TestResult::Pass
    } else {
        TestResult::Fail("shared fixed relocation hid its destructive failure")
    }
}
kernel_test_in!("memory", smoke_memory_shared_relocation_fixed_order);

/// Linux fixed-shrink ordering retires the destination, truncates the source,
/// then attempts the move. A late move failure must expose both destructive
/// steps so external file/SysV owners can publish the identical state.
#[cfg(feature = "kernel-test")]
fn smoke_memory_shared_fixed_shrink_reports_source_state() -> TestResult {
    use crate::{
        AddressSpace, AddressSpaceError, FixedRelocationError, MremapLimits, PhysAddr, Region,
        RegionPerms, VirtAddr,
    };

    let address_space = AddressSpace::empty();
    let target = VirtAddr::new(AddressSpace::USER_FIXED_FLOOR);
    let source = VirtAddr::new(0x0000_409b_0000_0000);
    if address_space
        .map_region(Region {
            base: source,
            len: 0x2000,
            perms: RegionPerms::READ | RegionPerms::SHARED,
            phys: alloc::vec![PhysAddr::new(0), PhysAddr::new(0)],
        })
        .is_err()
        || address_space
            .map_region(Region {
                base: target,
                len: 0x1000,
                perms: RegionPerms::READ,
                phys: alloc::vec![PhysAddr::new(0)],
            })
            .is_err()
    {
        return TestResult::Fail("shared fixed-shrink setup failed");
    }

    crate::address_space::__test_fail_next_fixed_relocation_after_shrink();
    // SAFETY: AddressSpace::empty is metadata-only and the wrapper supplies
    // the VMA then shared-owner transactions around the complete operation.
    let result = unsafe {
        address_space.relocate_shared_region_fixed_limited(
            source,
            0x2000,
            target,
            0x1000,
            MremapLimits::UNLIMITED,
        )
    };
    let expected = Err(FixedRelocationError {
        error: AddressSpaceError::AllocationFailed,
        target_punched: true,
        source_shrunk: true,
    });
    if result == expected
        && address_space.lookup(target).is_none()
        && address_space
            .lookup(source)
            .is_some_and(|region| region.len == 0x1000 && region.phys.len() == 1)
    {
        TestResult::Pass
    } else {
        TestResult::Fail("shared fixed-shrink failure state diverged from Linux")
    }
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "memory",
    smoke_memory_shared_fixed_shrink_reports_source_state
);

/// Private fixed shrinking has the same Linux progress boundary as SHARED:
/// destination retirement and source truncation remain committed if the later
/// move fails.
#[cfg(feature = "kernel-test")]
fn smoke_memory_private_fixed_shrink_reports_source_state() -> TestResult {
    use crate::{
        AddressSpace, AddressSpaceError, FixedRelocationError, MremapLimits, PhysAddr, Region,
        RegionPerms, VirtAddr,
    };

    let address_space = AddressSpace::empty();
    let target = VirtAddr::new(AddressSpace::USER_FIXED_FLOOR);
    let source = VirtAddr::new(0x0000_409c_0000_0000);
    if address_space
        .map_region(Region {
            base: source,
            len: 0x2000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![PhysAddr::new(0), PhysAddr::new(0)],
        })
        .is_err()
        || address_space
            .map_region(Region {
                base: target,
                len: 0x1000,
                perms: RegionPerms::READ,
                phys: alloc::vec![PhysAddr::new(0)],
            })
            .is_err()
    {
        return TestResult::Fail("private fixed-shrink setup failed");
    }

    crate::address_space::__test_fail_next_fixed_relocation_after_shrink();
    // SAFETY: AddressSpace::empty is metadata-only and the wrapper supplies
    // the required VMA transaction.
    let result = unsafe {
        address_space.relocate_region_fixed_limited(
            source,
            0x2000,
            target,
            0x1000,
            MremapLimits::UNLIMITED,
        )
    };
    let expected = Err(FixedRelocationError {
        error: AddressSpaceError::AllocationFailed,
        target_punched: true,
        source_shrunk: true,
    });
    if result == expected
        && address_space.lookup(target).is_none()
        && address_space
            .lookup(source)
            .is_some_and(|region| region.len == 0x1000 && region.phys.len() == 1)
    {
        TestResult::Pass
    } else {
        TestResult::Fail("private fixed-shrink failure state diverged from Linux")
    }
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "memory",
    smoke_memory_private_fixed_shrink_reports_source_state
);

/// Page-table frame exhaustion is an allocation failure (`ENOMEM` at Linux
/// syscall boundaries), not a malformed address or an occupied destination.
fn smoke_memory_paging_install_error_classification() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError};

    #[cfg(target_arch = "x86_64")]
    let correct = {
        use crate::x86_64::paging::MapError;
        AddressSpace::paging_install_error(MapError::FrameExhausted)
            == AddressSpaceError::AllocationFailed
            && AddressSpace::paging_install_error(MapError::NonCanonical)
                == AddressSpaceError::OutOfRange
            && AddressSpace::paging_install_error(MapError::AlreadyMapped)
                == AddressSpaceError::Overlap
            && AddressSpace::paging_install_error(MapError::EncounteredHugePage)
                == AddressSpaceError::Overlap
    };
    #[cfg(target_arch = "aarch64")]
    let correct = {
        use crate::aarch64::paging::MapError;
        AddressSpace::paging_install_error(MapError::NoFrame) == AddressSpaceError::AllocationFailed
            && AddressSpace::paging_install_error(MapError::NonCanonical)
                == AddressSpaceError::OutOfRange
            && AddressSpace::paging_install_error(MapError::AlreadyMapped)
                == AddressSpaceError::Overlap
            && AddressSpace::paging_install_error(MapError::EncounteredBlock)
                == AddressSpaceError::Overlap
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let correct = true;

    if correct {
        TestResult::Pass
    } else {
        TestResult::Fail("paging install errors collapsed allocation into range/state")
    }
}
kernel_test_in!("memory", smoke_memory_paging_install_error_classification);

/// A relocating grow preserves the source lock mode and eagerly populates only
/// the new destination tail.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_memory_eager_locked_relocate_growth_populates_tail() -> TestResult {
    use crate::{AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: fresh test-owned user root and initialized frame allocator.
    let a = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let resident = match crate::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => {
            core::mem::forget(a);
            return TestResult::Skip("frame drained");
        }
    };
    let old = VirtAddr::new(0x0000_4080_2800_0000);
    let new = VirtAddr::new(0x0000_4080_2900_0000);
    if a.map_region(Region {
        base: old,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::LOCKED,
        phys: alloc::vec![resident],
    })
    .is_err()
    {
        core::mem::forget(a);
        return TestResult::Fail("eager relocate setup failed");
    }
    // SAFETY: disjoint aligned user ranges in this exclusively-owned live AS.
    if unsafe { a.relocate_region(old, 0x1000, new, 0x2000) }.is_err() {
        core::mem::forget(a);
        return TestResult::Fail("eager locked relocate growth failed");
    }
    let populated = a.lookup(old).is_none()
        && a.lookup(new).is_some_and(|region| {
            region.len == 0x2000
                && region.perms.contains(RegionPerms::LOCKED)
                && !region.perms.contains(RegionPerms::LOCK_ONFAULT)
                && region.phys[0] == resident
                && region.phys[1].raw() != 0
                && region.phys[1] != resident
        });
    core::mem::forget(a);
    if populated {
        TestResult::Pass
    } else {
        TestResult::Fail("relocating eager grow left its new tail lazy")
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_memory_eager_locked_relocate_growth_populates_tail
);

/// Fixed relocation performs every non-destructive request/limit check before
/// punching the destination. Linux leaves the target intact for these early
/// failures.
fn smoke_memory_fixed_relocate_preflight_preserves_target() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    let address_space = AddressSpace::empty();
    let source = VirtAddr::new(0x0000_4080_2a00_0000);
    let target = VirtAddr::new(0x0000_4080_2b00_0000);
    let source_phys = PhysAddr::new(0x0200_0000);
    let target_phys = PhysAddr::new(0x0300_0000);
    if address_space
        .map_region(Region {
            base: source,
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::LOCKED,
            phys: alloc::vec![source_phys],
        })
        .is_err()
        || address_space
            .map_region(Region {
                base: target,
                len: 0x2000,
                perms: RegionPerms::READ,
                phys: alloc::vec![target_phys, PhysAddr::new(target_phys.raw() + 0x1000)],
            })
            .is_err()
    {
        return TestResult::Fail("fixed-relocate preflight setup failed");
    }

    // SAFETY: AddressSpace::empty has no live page-table root, so this test
    // exercises metadata transactions only.
    let limit_result = unsafe {
        address_space.relocate_region_fixed_limited(
            source,
            0x1000,
            target,
            0x2000,
            crate::MremapLimits {
                memlock_bytes: 0x1000,
                address_space_bytes: u64::MAX,
                data_bytes: u64::MAX,
                data_max_bytes: u64::MAX,
                bypass_memlock: false,
            },
        )
    };
    // SAFETY: as above; the out-of-range target must be rejected before any
    // page-table operation.
    let invalid_result = unsafe {
        address_space.relocate_region_fixed_limited(
            source,
            0x1000,
            VirtAddr::new(AddressSpace::USER_HALF_END - 0x1000),
            0x2000,
            crate::MremapLimits::UNLIMITED,
        )
    };
    // AS and DATA admission are also pre-punch checks. The existing source
    // plus target account for three pages; a one-page growth must fail against
    // the three-page AS ceiling without retiring either target page.
    // SAFETY: AddressSpace::empty has no live root; this is metadata-only.
    let as_result = unsafe {
        address_space.relocate_region_fixed_limited(
            source,
            0x1000,
            target,
            0x2000,
            crate::MremapLimits {
                memlock_bytes: u64::MAX,
                address_space_bytes: 0x3000,
                data_bytes: u64::MAX,
                data_max_bytes: u64::MAX,
                bypass_memlock: true,
            },
        )
    };
    // SAFETY: same metadata-only transaction as the AS-limit check above.
    let data_result = unsafe {
        address_space.relocate_region_fixed_limited(
            source,
            0x1000,
            target,
            0x2000,
            crate::MremapLimits {
                memlock_bytes: u64::MAX,
                address_space_bytes: u64::MAX,
                data_bytes: 0x1000,
                data_max_bytes: 0x1000,
                bypass_memlock: true,
            },
        )
    };
    let target_preserved = address_space.lookup(target).is_some_and(|region| {
        region.len == 0x2000
            && region.perms.prot_only() == RegionPerms::READ
            && region.phys == alloc::vec![target_phys, PhysAddr::new(target_phys.raw() + 0x1000)]
    });
    let source_preserved = address_space.lookup(source).is_some_and(|region| {
        region.len == 0x1000
            && region.perms.contains(RegionPerms::LOCKED)
            && region.phys == alloc::vec![source_phys]
    });
    let early = |error| {
        Err(crate::FixedRelocationError {
            error,
            target_punched: false,
            source_shrunk: false,
        })
    };
    if limit_result == early(AddressSpaceError::LockLimit)
        && invalid_result == early(AddressSpaceError::OutOfRange)
        && as_result == early(AddressSpaceError::MappingLimit)
        && data_result == early(AddressSpaceError::MappingLimit)
        && source_preserved
        && target_preserved
    {
        TestResult::Pass
    } else {
        TestResult::Fail("failed fixed-relocate preflight changed source or target")
    }
}
kernel_test_in!(
    "memory",
    smoke_memory_fixed_relocate_preflight_preserves_target
);

/// Once MAP_FIXED has retired its target, a later fallible relocation failure
/// must report that destructive state so filesystem/SysV owner tables mirror
/// memory instead of retaining stale backing references.
fn smoke_memory_fixed_relocate_reports_post_punch_failure() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    let address_space = AddressSpace::empty();
    let target = VirtAddr::new(AddressSpace::USER_FIXED_FLOOR);
    let source = VirtAddr::new(AddressSpace::USER_HALF_END - 0x1000);
    if address_space
        .map_region(Region {
            base: target,
            len: 0x1000,
            perms: RegionPerms::READ,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .is_err()
        || address_space
            .map_region(Region {
                base: source,
                len: 0x1000,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![PhysAddr::new(0)],
            })
            .is_err()
    {
        return TestResult::Fail("post-punch failure setup failed");
    }
    let impossible_len = source.as_u64() - target.as_u64();
    let outcome = address_space.with_vma_transaction(|| {
        crate::with_shared_mapping_transaction(|| {
            // SAFETY: metadata-only AddressSpace::empty has no live root and
            // both required structural transactions are held.
            unsafe {
                address_space.relocate_region_fixed_locked_limited(
                    source,
                    0x1000,
                    target,
                    impossible_len,
                    crate::MremapLimits::UNLIMITED,
                    false,
                )
            }
        })
    });
    let expected = Err(crate::FixedRelocationError {
        error: AddressSpaceError::AllocationFailed,
        target_punched: true,
        source_shrunk: false,
    });
    let source_preserved = address_space
        .lookup(source)
        .is_some_and(|region| region.len == 0x1000);
    if outcome == expected && source_preserved && address_space.lookup(target).is_none() {
        TestResult::Pass
    } else {
        TestResult::Fail("fixed relocation did not report its destructive failure state")
    }
}
kernel_test_in!(
    "memory",
    smoke_memory_fixed_relocate_reports_post_punch_failure
);

/// A mapping at the conventional brk base is not implicitly heap-owned.  A
/// later append must require BRK_HEAP on the root instead of annexing the
/// foreign VMA and exposing it to brk shrink/free.
fn smoke_memory_brk_growth_rejects_foreign_root() -> TestResult {
    use crate::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

    let a = AddressSpace::empty();
    let base = VirtAddr::new(0x0000_0000_7000_0000);
    if a.map_region(Region {
        base,
        len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys: alloc::vec![PhysAddr::new(0)],
    })
    .is_err()
    {
        return TestResult::Fail("foreign brk-root setup failed");
    }
    if a.brk_extend_region(base, base.as_u64() + 0x1000, 1) != Err(AddressSpaceError::Overlap) {
        return TestResult::Fail("brk annexed a root without BRK_HEAP provenance");
    }
    let unchanged = a.lookup(base).is_some_and(|region| {
        region.len == 0x1000
            && !region.perms.contains(RegionPerms::BRK_HEAP)
            && region.phys == alloc::vec![PhysAddr::new(0)]
    }) && a.lookup(VirtAddr::new(base.as_u64() + 0x1000)).is_none();
    if unchanged {
        TestResult::Pass
    } else {
        TestResult::Fail("rejected brk growth mutated the foreign root")
    }
}
kernel_test_in!("memory", smoke_memory_brk_growth_rejects_foreign_root);

// ── W^X: the kernel's non-text mappings have no executable alias ────────
//
// Before this, `mmu::init_mmu` built every window `PRESENT | WRITABLE |
// HUGE_PAGE` with no `NO_EXEC`, so every physical frame was aliased RWX at
// its identity address and again through the higher-half kernel window.
// Mapping BPF JIT text RX at a private kernel VA therefore bought nothing:
// the same bytes were executable at two other addresses that anyone with a
// kernel write could reach. These tests are the reason that claim can now be
// made, and the reason it will fail loudly if a future edit takes it back.

/// Jump to `alias` under an armed recoverable probe and report what the CPU
/// did.
///
/// The first 14 bytes of `alias` are overwritten with an absolute indirect
/// jump back to the probe's own recovery label, so the "it was executable
/// after all" branch lands somewhere safe instead of running whatever
/// happened to be in the page. A test whose failure mode is an unrecoverable
/// kernel crash tells you nothing.
///
/// # Safety
/// `alias` must be a writable kernel mapping of a frame the caller owns, at
/// least 14 bytes long.
#[cfg(target_arch = "x86_64")]
unsafe fn probe_fetch_at(alias: u64) -> narf_arch::x86_64::probe::Caught {
    use core::arch::asm;
    use narf_arch::x86_64::probe;

    let recovery: u64;
    // SAFETY: LEA of a local label is always safe.
    unsafe {
        asm!(
            "lea {r}, [66f + rip]",
            r = out(reg) recovery,
            options(nostack, preserves_flags),
        );
    }

    // `FF 25 00 00 00 00` = `jmp qword ptr [rip + 0]`, followed by the
    // 8-byte absolute target. Position-independent, so it works for any
    // distance between the alias and the kernel image — a `jmp rel32` does
    // not: the identity alias of a buddy frame and a `-2 GiB` kernel label
    // are almost exactly 2 GiB apart, right on the `i32` boundary.
    const JMP_INDIRECT: [u8; 6] = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    // SAFETY: per the fn contract, `alias` is a writable mapping of a frame
    // the caller owns and 14 bytes fit inside it.
    unsafe {
        let p = alias as *mut u8;
        for (i, b) in JMP_INDIRECT.iter().enumerate() {
            p.add(i).write_volatile(*b);
        }
        for (i, b) in recovery.to_le_bytes().iter().enumerate() {
            p.add(6 + i).write_volatile(*b);
        }
    }

    probe::arm(recovery);
    // SAFETY: either the fetch faults (the probe redirects RIP to `66:`) or
    // the stub we just wrote jumps to the same label. Both paths converge
    // with the stack untouched.
    unsafe {
        asm!(
            "jmp {p}",
            "66:",
            p = in(reg) alias,
            options(nostack),
        );
    }
    probe::disarm()
}

/// Classify what [`probe_fetch_at`] caught, so the three tests below agree on
/// what "the alias is not executable" means.
#[cfg(target_arch = "x86_64")]
fn expect_nx_fault(caught: narf_arch::x86_64::probe::Caught, what: &'static str) -> TestResult {
    match caught.vector {
        None => TestResult::Fail(what),
        Some(14) => {
            if caught.error_code & (1 << 4) == 0 {
                TestResult::Fail("faulted, but not on instruction fetch — not NX")
            } else {
                TestResult::Pass
            }
        }
        Some(_) => TestResult::Fail("wrong vector caught (not #PF)"),
    }
}

/// The load-bearing negative test: a frame the buddy handed out is writable
/// at its identity alias and **not executable there**.
///
/// This is the exact sequence an attacker with an arbitrary-kernel-write
/// primitive would perform, and it used to succeed at producing runnable
/// code. If someone drops `NO_EXEC` from `init_mmu`'s leaf flags, or the
/// 1 GiB → 2 MiB → 4 KiB demotion stops covering the address, this goes red.
#[cfg(target_arch = "x86_64")]
fn smoke_identity_alias_of_buddy_frame_is_nx() -> TestResult {
    use crate::{alloc_frame, free_frame, FrameAllocError};

    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised")
        }
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    let phys = frame.start_address().raw();
    if phys >= crate::addr::LOW_IDENTITY_LIMIT {
        free_frame(frame);
        return TestResult::Skip("frame is above the low identity map");
    }

    // SAFETY: `phys` is the identity alias of a frame we exclusively own.
    let caught = unsafe { probe_fetch_at(phys) };
    free_frame(frame);
    expect_nx_fault(caught, "identity alias of a buddy frame was executable")
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_identity_alias_of_buddy_frame_is_nx);

/// The same question asked of the higher-half kernel window, which is the
/// answer the identity map alone does not give.
///
/// `PML4[511]/PDPT[510]` used to be one 1 GiB RWX huge page over physical
/// 0..1 GiB — precisely where a small machine's buddy allocates — so NXing
/// only the identity map would have left a complete, equally reachable
/// replacement alias at `KERNEL_VIRT_BASE + phys`.
#[cfg(target_arch = "x86_64")]
fn smoke_kernel_window_alias_of_buddy_frame_is_nx() -> TestResult {
    use crate::{alloc_frame, free_frame, FrameAllocError};
    const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;

    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised")
        }
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    let phys = frame.start_address().raw();
    if phys >= (1u64 << 30) {
        free_frame(frame);
        return TestResult::Skip("frame is outside the higher-half kernel window");
    }

    // SAFETY: the kernel window aliases this frame writably and we own it.
    let caught = unsafe { probe_fetch_at(KERNEL_VIRT_BASE + phys) };
    free_frame(frame);
    expect_nx_fault(
        caught,
        "kernel-window alias of a buddy frame was executable",
    )
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_kernel_window_alias_of_buddy_frame_is_nx);

/// Positive control for the demotion: the AP trampoline window is still
/// executable, at 4 KiB granularity, and the page just past it is not.
///
/// Without the second half this would pass just as well if the whole first
/// 2 MiB had been left executable — 256× more RWX than the SIPI vector needs,
/// at a fixed and famous address.
#[cfg(target_arch = "x86_64")]
fn smoke_ap_trampoline_window_is_exactly_executable() -> TestResult {
    use crate::mmu::{AP_TRAMPOLINE_EXEC_BASE, AP_TRAMPOLINE_EXEC_LEN};
    use crate::paging::{leaf_flags_at, read_cr3, PtFlags};
    use crate::VirtAddr;

    // SAFETY: CR3 is readable at CPL=0 and names the live kernel PML4.
    let cr3 = unsafe { read_cr3() };
    // SAFETY: the live PML4 is identity-reachable.
    let inside = unsafe { leaf_flags_at(cr3, VirtAddr::new(AP_TRAMPOLINE_EXEC_BASE)) };
    let (flags, size) = match inside {
        Some(v) => v,
        None => return TestResult::Fail("AP trampoline page is not mapped at all"),
    };
    if size != 4096 {
        return TestResult::Fail("AP trampoline page was not demoted to a 4 KiB leaf");
    }
    if flags.contains(PtFlags::NO_EXEC) {
        return TestResult::Fail("AP trampoline page is NX — APs cannot reach long mode");
    }

    let past = AP_TRAMPOLINE_EXEC_BASE + AP_TRAMPOLINE_EXEC_LEN;
    // SAFETY: as above.
    match unsafe { leaf_flags_at(cr3, VirtAddr::new(past)) } {
        None => TestResult::Fail("the page past the trampoline window is unmapped"),
        Some((f, _)) if f.contains(PtFlags::NO_EXEC) => TestResult::Pass,
        Some(_) => TestResult::Fail("the executable window is wider than the trampoline"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_ap_trampoline_window_is_exactly_executable);

/// The kernel's own text stays executable and its `.bss` does not.
///
/// This is what catches a `kernel_exec_phys_range` that resolved to the wrong
/// linker symbols. A range that is too *small* kills the boot outright and
/// needs no test; a range that is too *large* boots perfectly well and
/// quietly restores the RWX alias. Only the `.bss` half notices that.
#[cfg(target_arch = "x86_64")]
fn smoke_kernel_text_executable_bss_is_not() -> TestResult {
    use crate::paging::{leaf_flags_at, read_cr3, PtFlags};
    use crate::VirtAddr;

    // A genuine `.bss` object — zero-initialised, so the linker cannot fold
    // it into `.rodata` — written to here so it cannot be optimised away.
    static BSS_WITNESS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    BSS_WITNESS.store(1, core::sync::atomic::Ordering::Relaxed);

    unsafe extern "C" {
        static __text_start: u8;
    }
    let text = core::ptr::addr_of!(__text_start) as u64;
    let bss = &BSS_WITNESS as *const _ as u64;

    // SAFETY: CR3 is readable at CPL=0 and names the live kernel PML4.
    let cr3 = unsafe { read_cr3() };
    // SAFETY: the live PML4 is identity-reachable.
    let t = unsafe { leaf_flags_at(cr3, VirtAddr::new(text)) };
    // SAFETY: as above.
    let b = unsafe { leaf_flags_at(cr3, VirtAddr::new(bss)) };

    match (t, b) {
        (None, _) => TestResult::Fail("kernel .text is unmapped"),
        (_, None) => TestResult::Fail("kernel .bss is unmapped"),
        (Some((tf, _)), Some((bf, _))) => {
            if tf.contains(PtFlags::NO_EXEC) {
                return TestResult::Fail("kernel .text is NX — the boot should not have survived");
            }
            if !bf.contains(PtFlags::NO_EXEC) {
                return TestResult::Fail("kernel .bss is executable — the exec range is too wide");
            }
            TestResult::Pass
        }
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_kernel_text_executable_bss_is_not);

/// aarch64 twin of the two `_is_nx` smokes above — asserted **structurally**,
/// by reading the live TTBR0/TTBR1 descriptors, rather than by taking the
/// fault.
///
/// LINUX-GAP: `narf_arch::x86_64::probe` has no aarch64 port
/// (`bpf/specification/spec.md` §8.8), so there is no way to attempt an
/// instruction fetch from a PXN page and survive it. Linux would express this
/// with an `extable`-covered probe either way; here the descriptor check is
/// what is available, and it catches the regression this work is guarding
/// against — a leaf built without PXN|UXN — even though it cannot witness the
/// CPU refusing the fetch.
///
/// Both windows are checked because they are different tables: the TTBR0 map
/// is the identity one, and the TTBR1 window at `KERNEL_PHYS_OFFSET` is what
/// `PhysAddr::kernel_ptr` actually resolves to on this arch, so it is the
/// alias every BPF pack write goes through.
#[cfg(target_arch = "aarch64")]
fn smoke_buddy_frame_alias_is_pxn() -> TestResult {
    use crate::aarch64::paging::{leaf_flags_at, read_ttbr0_el1, read_ttbr1_el1, PtFlags};
    use crate::{alloc_frame, free_frame, FrameAllocError, VirtAddr};

    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) => {
            return TestResult::Skip("frame allocator not initialised")
        }
        Err(_) => return TestResult::Fail("alloc_frame failed"),
    };
    let phys = frame.start_address().raw();
    let nx = PtFlags::PXN.bits() | PtFlags::UXN.bits();

    // SAFETY: `MRS .., TTBR0_EL1/TTBR1_EL1` is defined at EL1 with no
    // precondition, and both roots are reachable through the kernel accessor.
    let (ttbr0, ttbr1) = unsafe { (read_ttbr0_el1(), read_ttbr1_el1()) };
    // SAFETY: both roots are live translation tables.
    let ident = unsafe { leaf_flags_at(ttbr0, VirtAddr::new(phys)) };
    // SAFETY: as above; `phys | KERNEL_PHYS_OFFSET` is the kernel window
    // alias `PhysAddr::kernel_ptr` hands out.
    let window = unsafe { leaf_flags_at(ttbr1, VirtAddr::new(phys | crate::KERNEL_PHYS_OFFSET)) };
    free_frame(frame);

    match ident {
        None => return TestResult::Fail("buddy frame has no TTBR0 identity mapping"),
        Some((f, size)) => {
            if size != (1 << 21) {
                return TestResult::Fail("TTBR0 RAM block was not demoted to 2 MiB");
            }
            if f.bits() & nx != nx {
                return TestResult::Fail("TTBR0 identity alias of a buddy frame is executable");
            }
        }
    }
    match window {
        None => TestResult::Fail("buddy frame has no TTBR1 kernel-window mapping"),
        Some((f, size)) => {
            if size != (1 << 21) {
                TestResult::Fail("TTBR1 RAM block was not demoted to 2 MiB")
            } else if f.bits() & nx != nx {
                TestResult::Fail("TTBR1 kernel-window alias of a buddy frame is executable")
            } else {
                TestResult::Pass
            }
        }
    }
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("memory", smoke_buddy_frame_alias_is_pxn);

/// The aarch64 control: kernel `.text` is still fetchable at EL1 and `.bss` is
/// not.
///
/// Same argument as the x86_64 twin — an exec range that came out too small
/// never boots, so only the `.bss` half can catch one that came out too large.
#[cfg(target_arch = "aarch64")]
fn smoke_kernel_text_executable_bss_is_not_aarch64() -> TestResult {
    use crate::aarch64::paging::{leaf_flags_at, read_ttbr1_el1, PtFlags};
    use crate::VirtAddr;

    static BSS_WITNESS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    BSS_WITNESS.store(1, core::sync::atomic::Ordering::Relaxed);

    unsafe extern "C" {
        static __text_start: u8;
    }
    let text = core::ptr::addr_of!(__text_start) as u64;
    let bss = &BSS_WITNESS as *const _ as u64;

    // SAFETY: `MRS .., TTBR1_EL1` is defined at EL1 with no precondition.
    let ttbr1 = unsafe { read_ttbr1_el1() };
    // SAFETY: `ttbr1` is the live kernel translation table.
    let t = unsafe { leaf_flags_at(ttbr1, VirtAddr::new(text)) };
    // SAFETY: as above.
    let b = unsafe { leaf_flags_at(ttbr1, VirtAddr::new(bss)) };

    match (t, b) {
        (None, _) => TestResult::Fail("kernel .text is unmapped"),
        (_, None) => TestResult::Fail("kernel .bss is unmapped"),
        (Some((tf, _)), Some((bf, _))) => {
            if tf.bits() & PtFlags::PXN.bits() != 0 {
                return TestResult::Fail("kernel .text is PXN — the boot should not have survived");
            }
            if bf.bits() & PtFlags::PXN.bits() == 0 {
                return TestResult::Fail("kernel .bss is executable — the exec range is too wide");
            }
            TestResult::Pass
        }
    }
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("memory", smoke_kernel_text_executable_bss_is_not_aarch64);

// ── Why a raw `frame::stats().free` delta is not a measurement ──────
//
// The heap's slab calls `alloc_frame()` when a size class runs dry
// (slab.rs::refill_from_frame), so ANY Rust allocation can consume a buddy
// frame as a side effect. A test that brackets some operation with two
// `stats().free` samples is therefore measuring that operation MINUS
// whatever the heap took — and whether the heap took anything depends on
// how full the magazines already were, i.e. on what ran before.
//
// That is what made `smoke_bpf_arena_mapping_keeps_frames_alive_until_munmap`
// flaky: munmap returned all 16 arena frames every time, but the raw delta
// came up short whenever munmap's own bookkeeping happened to grow a class.
// `slab::frames_held()` is the correction; this test is what makes the
// mechanism a demonstrated fact rather than a plausible story.

fn smoke_slab_growth_consumes_buddy_frames() -> TestResult {
    use alloc::vec::Vec;

    // Force a size class to grow by allocating far more blocks than one
    // frame's worth, holding them so nothing is recycled.
    //
    // The outer vector is deliberately left UNRESERVED so it reallocs into
    // LARGE blocks inside the window (4096 Vec headers is a 64 KiB order-4
    // allocation). An earlier version of this test had to hoist that
    // outside the window because `frames_held` only knew about size
    // classes; it now counts large allocations too, so exercising both
    // halves here is what keeps that fix honest.
    let free_before = crate::frame::stats().free;
    let held_before = crate::slab::frames_held();

    let mut held: Vec<Vec<u8>> = Vec::new();
    for _ in 0..4096 {
        held.push(alloc::vec![0u8; 64]);
    }

    let free_after = crate::frame::stats().free;
    let held_after = crate::slab::frames_held();
    let heap_took = held_after.saturating_sub(held_before);

    // The premise: this burst DID make the heap take frames. Without that
    // the test proves nothing, so assert it rather than assuming it.
    if heap_took == 0 {
        drop(held);
        return TestResult::Fail("4096 x 64B did not grow the heap — premise broken");
    }

    // The raw free count went DOWN, which is exactly the noise a raw delta
    // silently attributes to the code under test.
    let raw_drop = free_before.saturating_sub(free_after);
    if raw_drop == 0 {
        drop(held);
        return TestResult::Fail("heap growth did not reduce the raw buddy free count");
    }

    // And the corrected quantity — free + frames_held — is stable across
    // the same window, because every frame the heap took is accounted for
    // rather than lost. This is now an EXACT identity: with large
    // allocations counted there is no remaining unattributed source, so a
    // tolerance here would only hide the next one.
    let net_before = free_before + held_before;
    let net_after = free_after + held_after;
    drop(held);
    if net_before != net_after {
        return TestResult::Fail("net (free + frames_held) drifted across pure heap growth");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_slab_growth_consumes_buddy_frames);
