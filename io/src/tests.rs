//! Per-crate smoke tests for `narf-io`.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_io_dma_alloc_free() -> TestResult {
    // alloc_coherent returns a page-aligned nonzero phys address with
    // the requested (rounded) length; drop returns the storage.
    use crate::{alloc_coherent, free_coherent};
    use narf_lib::id::DomainId;
    use narf_memory::PAGE_SIZE;

    let buf = match alloc_coherent(256, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable in this flavour"),
    };
    if buf.phys_addr().raw() == 0 {
        return TestResult::Fail("DMA buffer phys addr is zero");
    }
    if buf.phys_addr().raw() & (PAGE_SIZE - 1) != 0 {
        return TestResult::Fail("DMA buffer phys addr not page-aligned");
    }
    if buf.len() != PAGE_SIZE as usize {
        return TestResult::Fail("DMA buffer length not rounded to a page");
    }
    if buf.domain() != DomainId::DRIVER_0 {
        return TestResult::Fail("DMA buffer domain mismatch");
    }
    free_coherent(buf);
    TestResult::Pass
}
kernel_test_in!("io", smoke_io_dma_alloc_free);

fn smoke_io_dma_cap_bootstrap() -> TestResult {
    // Exercises Wave-2 cap table + Wave-3a DmaBuffer: bootstrap a
    // Cap<DmaBuffer, Write>, confirm it's live, revoke, confirm dead.
    use crate::DmaBuffer;
    use narf_capabilities::{Cap, CapError, CapType, Write};

    if DmaBuffer::KIND as u32 != narf_capabilities::CapKind::DmaBuffer as u32 {
        return TestResult::Fail("DmaBuffer::KIND not DmaBuffer");
    }

    let cap: Cap<DmaBuffer, Write> = Cap::<DmaBuffer, Write>::bootstrap();
    if !cap.is_live() {
        return TestResult::Fail("fresh DmaBuffer cap not live");
    }
    if cap.check_live().is_err() {
        return TestResult::Fail("check_live on fresh DmaBuffer cap failed");
    }
    let clone = cap;
    cap.revoke();
    match clone.check_live() {
        Err(CapError::Revoked) => {}
        Ok(_) => return TestResult::Fail("DmaBuffer cap still live after revoke"),
        Err(_) => return TestResult::Fail("DmaBuffer cap reported wrong error"),
    }
    TestResult::Pass
}
kernel_test_in!("io", smoke_io_dma_cap_bootstrap);

fn smoke_io_iommu_stub_map_unmap() -> TestResult {
    // Wave-3a IOMMU stub: construct a context, map a DmaBuffer, unmap.
    use crate::{alloc_coherent, IoError, IommuContext};
    use narf_lib::id::DomainId;

    let dom = DomainId::DRIVER_1;
    let buf = match alloc_coherent(4096, dom) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable in this flavour"),
    };

    let ctx = IommuContext::new(dom);
    if ctx.domain() != dom {
        return TestResult::Fail("IommuContext domain mismatch");
    }
    if ctx.mapping_count() != 0 {
        return TestResult::Fail("fresh context not empty");
    }

    if ctx.map(&buf, 0x1000_0000).is_err() {
        return TestResult::Fail("stub map returned error");
    }
    if ctx.mapping_count() != 1 {
        return TestResult::Fail("mapping count not bumped");
    }

    let other = match alloc_coherent(4096, DomainId::DRIVER_2) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator exhausted mid-test"),
    };
    match ctx.map(&other, 0x2000_0000) {
        Err(IoError::DomainMismatch) => {}
        _ => return TestResult::Fail("cross-domain map should have rejected"),
    }

    if ctx.unmap(0x1000_0000, 4096).is_err() {
        return TestResult::Fail("stub unmap returned error");
    }
    if ctx.mapping_count() != 0 {
        return TestResult::Fail("mapping count not decremented");
    }

    match ctx.unmap(0x1000_0000, 4096) {
        Err(IoError::NotMapped) => {}
        _ => return TestResult::Fail("unmap of empty context should fail"),
    }

    TestResult::Pass
}
kernel_test_in!("io", smoke_io_iommu_stub_map_unmap);

// ── IOMMU detection + identity-map ───────────────────────────────

fn smoke_iommu_initial_state_is_disabled_or_identity() -> TestResult {
    // Either the test boot ran narf_io::iommu::init (Identity) or
    // it didn't get that far (Disabled). Anything else means
    // someone snuck in PerDomain mode without test coverage.
    use crate::iommu;
    match iommu::mode() {
        iommu::IommuMode::Disabled | iommu::IommuMode::Identity => TestResult::Pass,
        iommu::IommuMode::PerDomain => TestResult::Fail("PerDomain mode active without backend"),
    }
}
kernel_test_in!("io/iommu", smoke_iommu_initial_state_is_disabled_or_identity);

fn smoke_iommu_force_identity_makes_map_passthrough() -> TestResult {
    // Force identity mode in the test fixture (so this passes
    // even on a boot path that didn't bring up real IVRS/DMAR
    // tables) and verify map_phys is a pure pass-through.
    use crate::iommu;

    let prev_mode = iommu::mode();
    iommu::__force_identity_for_test();
    let pass_through = iommu::map_phys(0xCAFE_F000).map(|x| x == 0xCAFE_F000).unwrap_or(false);
    let unmap_through = iommu::unmap_iova(0xCAFE_F000).map(|x| x == 0xCAFE_F000).unwrap_or(false);
    if !pass_through {
        iommu::__reset_for_test();
        return TestResult::Fail("identity map_phys must be a pass-through");
    }
    if !unmap_through {
        iommu::__reset_for_test();
        return TestResult::Fail("identity unmap_iova must be a pass-through");
    }
    iommu::__reset_for_test();
    // Restore prior mode hint by re-running a no-op. (We can't
    // perfectly restore without re-running init, but follow-on
    // tests reset themselves explicitly.)
    let _ = prev_mode;
    TestResult::Pass
}
kernel_test_in!("io/iommu", smoke_iommu_force_identity_makes_map_passthrough);

fn smoke_iommu_double_init_rejected() -> TestResult {
    // The second call to init must report AlreadyInitialised
    // without flipping mode back through Disabled.
    use crate::iommu;
    iommu::__reset_for_test();
    iommu::__force_identity_for_test();
    match iommu::init() {
        Err(iommu::IommuInitError::AlreadyInitialised) => {
            iommu::__reset_for_test();
            TestResult::Pass
        }
        _ => {
            iommu::__reset_for_test();
            TestResult::Fail("double init must return AlreadyInitialised")
        }
    }
}
kernel_test_in!("io/iommu", smoke_iommu_double_init_rejected);

fn smoke_iommu_context_map_returns_identity_iova() -> TestResult {
    // Allocate a coherent buffer, force-identity the IOMMU, map
    // it through an IommuContext — the returned IOVA must equal
    // the buffer's host-physical address (identity mode).
    use crate::iommu;
    use crate::{alloc_coherent, free_coherent, IommuContext};
    use narf_lib::id::DomainId;

    let dom = DomainId::DRIVER_0;
    let buf = match alloc_coherent(256, dom) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable"),
    };
    let phys = buf.phys_addr().raw();

    iommu::__force_identity_for_test();
    let ctx = IommuContext::new(dom);
    let iova = match ctx.map(&buf, 0) {
        Ok(v) => v,
        Err(_) => {
            iommu::__reset_for_test();
            free_coherent(buf);
            return TestResult::Fail("map under identity mode returned Err");
        }
    };
    if iova != phys {
        iommu::__reset_for_test();
        free_coherent(buf);
        return TestResult::Fail("identity-mode IOVA must equal the buffer phys");
    }
    if ctx.unmap(iova, buf.len()).is_err() {
        iommu::__reset_for_test();
        free_coherent(buf);
        return TestResult::Fail("identity-mode unmap returned Err");
    }
    if ctx.mapping_count() != 0 {
        iommu::__reset_for_test();
        free_coherent(buf);
        return TestResult::Fail("mapping count not reset after unmap");
    }

    iommu::__reset_for_test();
    free_coherent(buf);
    TestResult::Pass
}
kernel_test_in!("io/iommu", smoke_iommu_context_map_returns_identity_iova);

fn smoke_iommu_init_no_tables_returns_no_tables_parsed() -> TestResult {
    // With both IVRS and DMAR un-parsed, init must report
    // NoTablesParsed (so callers know to parse first).
    // We can only verify this when the real boot path didn't
    // already populate the parser caches; otherwise the
    // condition is unreachable in tests.
    use crate::iommu;
    iommu::__reset_for_test();
    if narf_acpi::is_ivrs_known() || narf_acpi::is_dmar_known() {
        return TestResult::Skip("ACPI tables already parsed in this boot");
    }
    match iommu::init() {
        Err(iommu::IommuInitError::NoTablesParsed) => TestResult::Pass,
        other => {
            iommu::__reset_for_test();
            let _ = other;
            TestResult::Fail("init without parsed tables should be NoTablesParsed")
        }
    }
}
kernel_test_in!("io/iommu", smoke_iommu_init_no_tables_returns_no_tables_parsed);

fn smoke_ioremap_direct_round_trip() -> TestResult {
    // Allocate a frame, scribble a sentinel through the identity
    // map, ioremap it as WriteBack-cached memory, read the
    // sentinel back through the new VA.
    //
    // Note: this exercises `narf_memory::ioremap`, not anything inside
    // `narf-io`. It lives here because the verification harness groups
    // it with the rest of the IO smokes; the underlying surface belongs
    // to memory/. If memory grows its own per-crate tests this should
    // migrate again.
    use core::sync::atomic::{compiler_fence, Ordering};
    use narf_memory::frame::alloc_frame;
    use narf_memory::ioremap::{self, MmioAttrs};

    let frame = match alloc_frame() {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("alloc_frame"),
    };
    let phys = frame.start_address().raw();
    const SENTINEL: u64 = 0xCAFE_BABE_DEAD_BEEF;
    // SAFETY: identity-mapped low-RAM frame; we own it.
    unsafe {
        core::ptr::write_volatile(phys as *mut u64, SENTINEL);
    }
    compiler_fence(Ordering::SeqCst);

    // SAFETY: phys is a frame we just got from alloc_frame.
    let m = match unsafe { ioremap::ioremap(phys, 4096, MmioAttrs::WriteBack) } {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("ioremap returned err"),
    };
    if m.virt == 0 {
        // SAFETY: m came from ioremap, but virt is invalid.
        unsafe {
            ioremap::iounmap(m);
        }
        return TestResult::Fail("ioremap returned virt=0");
    }
    // SAFETY: ioremap's contract guarantees the VA is now mapped.
    let v = unsafe { core::ptr::read_volatile(m.virt as *const u64) };
    let ok = v == SENTINEL;
    // SAFETY: paired with ioremap.
    unsafe {
        ioremap::iounmap(m);
    }
    if !ok {
        return TestResult::Fail("ioremap'd VA didn't read back the sentinel");
    }
    TestResult::Pass
}
kernel_test_in!("io", smoke_ioremap_direct_round_trip);

fn smoke_io_register_with_cap_resolves() -> TestResult {
    // Round-trip: alloc a buffer, register it with the cap-table,
    // confirm the returned cap resolves back to the same physical
    // address, then unregister and confirm the cap is dead.
    use crate::{alloc_coherent, register_with_cap, resolve_cap, unregister};
    use narf_capabilities::CapError;
    use narf_lib::id::DomainId;

    let buf = match alloc_coherent(256, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Skip("frame allocator unavailable"),
    };
    let phys = buf.phys_addr().raw();
    let cap = register_with_cap(buf);

    if !cap.is_live() {
        return TestResult::Fail("cap not live after register_with_cap");
    }

    let resolved = match resolve_cap(&cap) {
        Some(b) => b,
        None => return TestResult::Fail("resolve_cap returned None"),
    };
    if resolved.phys_addr().raw() != phys {
        return TestResult::Fail("resolve_cap returned wrong buffer");
    }
    if resolved.slot_index() != Some(cap.slot().index) {
        return TestResult::Fail("buffer slot_index doesn't match cap slot");
    }

    // Drop the resolved Arc so unregister can free the buffer.
    drop(resolved);
    let cap_copy = cap;
    unregister(cap);
    match cap_copy.check_live() {
        Err(CapError::Revoked) => {}
        Ok(_) => return TestResult::Fail("cap still live after unregister"),
        Err(_) => return TestResult::Fail("cap reported wrong error"),
    }
    TestResult::Pass
}
kernel_test_in!("io", smoke_io_register_with_cap_resolves);

// ── deep io coverage ──────────────────────────────────────────────

fn smoke_io_error_variants_distinct() -> TestResult {
    use crate::IoError;
    let all = [
        IoError::NoMemory,
        IoError::DomainMismatch,
        IoError::OutOfIova,
        IoError::NotMapped,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("IoError variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("io", smoke_io_error_variants_distinct);

fn smoke_io_coherency_variants_distinct() -> TestResult {
    use crate::Coherency;
    if Coherency::Coherent == Coherency::Streaming {
        return TestResult::Fail("Coherency variants collapsed");
    }
    TestResult::Pass
}
kernel_test_in!("io", smoke_io_coherency_variants_distinct);

fn smoke_io_dma_buffer_accessors() -> TestResult {
    // alloc_coherent caps requests at one page; pick 3000 bytes
    // (rounds up to 4096 internally).
    use crate::{alloc_coherent, Coherency, IoError};
    use narf_lib::id::DomainId;
    let buf = match alloc_coherent(3000, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_coherent failed"),
    };
    // alloc_with rounds len up to PAGE_SIZE.
    if buf.len() != 4096 {
        return TestResult::Fail("len wasn't page-rounded");
    }
    // Confirm > page rejects with NoMemory.
    match alloc_coherent(5000, DomainId::DRIVER_0) {
        Err(IoError::NoMemory) => {}
        _ => return TestResult::Fail("oversized alloc didn't reject"),
    }
    match alloc_coherent(0, DomainId::DRIVER_0) {
        Err(IoError::NoMemory) => {}
        _ => return TestResult::Fail("zero-len alloc didn't reject"),
    }
    if buf.is_empty() {
        return TestResult::Fail("is_empty true for sized buffer");
    }
    if buf.coherency() != Coherency::Coherent {
        return TestResult::Fail("coherency() didn't reflect construction");
    }
    if buf.domain() != DomainId::DRIVER_0 {
        return TestResult::Fail("domain() didn't reflect construction");
    }
    if buf.phys_addr().raw() == 0 {
        return TestResult::Fail("phys_addr is zero — frame allocator misfire?");
    }
    if buf.slot_index().is_some() {
        return TestResult::Fail("slot_index Some before register");
    }
    let _ = buf.as_ptr();
    let _ = buf.as_mut_ptr();
    TestResult::Pass
}
kernel_test_in!("io", smoke_io_dma_buffer_accessors);

fn smoke_io_dma_buffer_as_slice_round_trip() -> TestResult {
    use crate::alloc_coherent;
    use narf_lib::id::DomainId;
    let mut buf = match alloc_coherent(128, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc"),
    };
    {
        let s = buf.as_mut_slice();
        for (i, b) in s.iter_mut().enumerate().take(128) {
            *b = (i & 0xFF) as u8;
        }
    }
    {
        let s = buf.as_slice();
        for (i, b) in s.iter().enumerate().take(128) {
            if *b != (i & 0xFF) as u8 {
                return TestResult::Fail("as_slice readback mismatched write");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("io", smoke_io_dma_buffer_as_slice_round_trip);

fn smoke_io_unknown_resolve_returns_none() -> TestResult {
    use crate::resolve;
    if resolve(u32::MAX).is_some() {
        return TestResult::Fail("resolve(MAX) returned Some");
    }
    TestResult::Pass
}
kernel_test_in!("io", smoke_io_unknown_resolve_returns_none);

// ── deep io/iommu coverage ─────────────────────────────────────────

fn smoke_iommu_vendor_repr_pins_discriminants() -> TestResult {
    use crate::iommu::IommuVendor;
    if IommuVendor::None as u8 != 0 {
        return TestResult::Fail("None discriminant drifted from 0");
    }
    if IommuVendor::AmdVi as u8 != 1 {
        return TestResult::Fail("AmdVi drifted from 1");
    }
    if IommuVendor::IntelVtd as u8 != 2 {
        return TestResult::Fail("IntelVtd drifted from 2");
    }
    let all = [IommuVendor::None, IommuVendor::AmdVi, IommuVendor::IntelVtd];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("IommuVendor collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu", smoke_iommu_vendor_repr_pins_discriminants);

fn smoke_iommu_mode_variants_distinct() -> TestResult {
    use crate::iommu::IommuMode;
    let all = [IommuMode::Disabled, IommuMode::Identity, IommuMode::PerDomain];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("IommuMode variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu", smoke_iommu_mode_variants_distinct);

fn smoke_iommu_init_error_variants_distinct() -> TestResult {
    use crate::iommu::IommuInitError;
    let all = [
        IommuInitError::AlreadyInitialised,
        IommuInitError::NoTablesParsed,
        IommuInitError::NoIommusFound,
        IommuInitError::DeadMmio,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("IommuInitError variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu", smoke_iommu_init_error_variants_distinct);

fn smoke_iommu_accessors_match_state_after_reset() -> TestResult {
    use crate::iommu::{__reset_for_test, is_active, mode, vendor, IommuMode, IommuVendor};
    __reset_for_test();
    // After a reset the IOMMU is reported as Disabled / None / not active.
    if mode() != IommuMode::Disabled {
        return TestResult::Fail("mode != Disabled after reset");
    }
    if vendor() != IommuVendor::None {
        return TestResult::Fail("vendor != None after reset");
    }
    if is_active() {
        return TestResult::Fail("is_active() should be false after reset");
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu", smoke_iommu_accessors_match_state_after_reset);

fn smoke_iommu_unit_count_zero_after_reset() -> TestResult {
    use crate::iommu::{__reset_for_test, unit_count};
    __reset_for_test();
    if unit_count() != 0 {
        return TestResult::Fail("unit_count != 0 after reset");
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu", smoke_iommu_unit_count_zero_after_reset);

fn smoke_iommu_force_identity_sets_active_and_identity_mode() -> TestResult {
    use crate::iommu::{__force_identity_for_test, __reset_for_test, is_active, mode, IommuMode};
    __reset_for_test();
    __force_identity_for_test();
    if mode() != IommuMode::Identity {
        return TestResult::Fail("force_identity didn't set mode = Identity");
    }
    if !is_active() {
        return TestResult::Fail("is_active() should be true after force_identity");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("io/iommu", smoke_iommu_force_identity_sets_active_and_identity_mode);

fn smoke_iommu_caps_default_zero_after_reset() -> TestResult {
    use crate::iommu::{__reset_for_test, caps};
    __reset_for_test();
    let c = caps();
    if c.vendor != 0 || c.raw_caps_lo != 0 || c.raw_caps_hi != 0 {
        return TestResult::Fail("caps() didn't zero after reset");
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu", smoke_iommu_caps_default_zero_after_reset);
