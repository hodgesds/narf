//! Per-domain IOMMU translation smokes (`io/iommu/perdomain`).
//!
//! Driven through [`crate::iommu_model::ModelIommu`], a software backend
//! that walks NARF's real page tables but has no silicon behind it. These
//! prove the IOVA allocator, PTE encodings and the strict
//! unmap → invalidate → wait → free ordering; they do not prove any
//! AMD-Vi / VT-d / SMMU hardware behaviour.

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;

use crate::iommu::{self, Bdf, IommuDomain, IommuPerms, PageTableFormat};
use crate::iommu_model::{ModelEvent, ModelIommu};
use crate::iova::IovaAllocator;
use crate::{alloc_coherent_for, DmaDevice, IoError};

static MODEL: ModelIommu = ModelIommu::new(PageTableFormat::AmdV1);
static MODEL_VTD: ModelIommu = ModelIommu::new(PageTableFormat::VtdSecondStage);

/// Run `f` in PerDomain mode with `model`, always restoring Disabled mode.
fn with_model(
    model: &'static ModelIommu,
    f: impl FnOnce() -> Result<(), &'static str>,
) -> TestResult {
    if model.install().is_err() {
        iommu::__reset_for_test();
        return TestResult::Fail("enable_per_domain refused");
    }
    let r = f();
    iommu::__reset_for_test();
    model.clear();
    match r {
        Ok(()) => TestResult::Pass,
        Err("frame allocator unavailable") => TestResult::Skip("frame allocator unavailable"),
        Err(e) => TestResult::Fail(e),
    }
}

fn iova_alloc_size_aligned_top_down() -> TestResult {
    let mut a = IovaAllocator::new(0, 1 << 20);
    let Some(first) = a.alloc(3, u64::MAX, true) else {
        return TestResult::Fail("alloc failed");
    };
    // 3 pages round to a 4-page alignment, placed at the top.
    if first % 4 != 0 || first + 3 > (1 << 20) - 1 || first + 4 != 1 << 20 {
        return TestResult::Fail("3-page alloc not 4-aligned at the top");
    }
    let Some(second) = a.alloc(16, 0xFFFF, true) else {
        return TestResult::Fail("limited alloc failed");
    };
    if second % 16 != 0 || second + 15 > 0xFFFF {
        return TestResult::Fail("limited alloc misaligned or above limit");
    }
    if a.alloc(1, 0, false).is_some() {
        return TestResult::Fail("pfn 0 handed out");
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu/perdomain", iova_alloc_size_aligned_top_down);

fn iova_alloc_exhaustion_and_reserve() -> TestResult {
    // pfns 1..=8 allocatable.
    let mut a = IovaAllocator::new(1, 9);
    if a.alloc(4, u64::MAX, true) != Some(4) {
        return TestResult::Fail("first aligned 4-page block not at pfn 4");
    }
    if a.alloc(4, u64::MAX, true).is_some() {
        return TestResult::Fail("aligned block below start_pfn handed out");
    }
    if a.alloc(2, u64::MAX, true) != Some(2) {
        return TestResult::Fail("2-page block not at pfn 2");
    }
    a.reserve(8, 8);
    if a.alloc(1, u64::MAX, false) != Some(1) {
        return TestResult::Fail("last free pfn not handed out");
    }
    if a.alloc(1, u64::MAX, false).is_some() {
        return TestResult::Fail("exhausted allocator handed out a pfn");
    }
    if a.free(4) != Some(4) || a.alloc(4, u64::MAX, true) != Some(4) {
        return TestResult::Fail("freed block not reusable");
    }
    if a.alloc_fixed(3, 1) {
        return TestResult::Fail("fixed alloc over a live range");
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu/perdomain", iova_alloc_exhaustion_and_reserve);

fn pte_encodings_match_linux_generic_pt() -> TestResult {
    let amd = PageTableFormat::AmdV1;
    let vtd = PageTableFormat::VtdSecondStage;
    // amdv1pt_install_table: PR | NextLevel(level-1) | OA | IR | IW.
    if amd.table_entry(4, 0x1234_5000) != (1 | (3 << 9) | 0x1234_5000 | (1 << 61) | (1 << 62)) {
        return TestResult::Fail("AMD v1 table entry");
    }
    // amdv1pt_install_leaf_entry: PR | NL=0 | OA | FC | IR (read-only).
    if amd.leaf_entry(0xABC_D000, IommuPerms::READ) != (1 | 0xABC_D000 | (1 << 60) | (1 << 61)) {
        return TestResult::Fail("AMD v1 leaf entry");
    }
    if vtd.table_entry(2, 0x5000) != (0b11 | 0x5000)
        || vtd.leaf_entry(0x6000, IommuPerms::WRITE) != (0b10 | 0x6000)
    {
        return TestResult::Fail("VT-d second-stage entries");
    }
    if amd.present(0) || vtd.present(0x6000) || !vtd.present(0x6001) {
        return TestResult::Fail("present bit decode");
    }
    TestResult::Pass
}
kernel_test_in!("io/iommu/perdomain", pte_encodings_match_linux_generic_pt);

fn perdomain_map_translates_and_unmap_orders_invalidation() -> TestResult {
    for model in [&MODEL, &MODEL_VTD] {
        let r = with_model(model, || {
            let frame =
                narf_memory::alloc_pages_on(0, 1).map_err(|_| "frame allocator unavailable")?;
            let phys = frame.start_address().raw();
            let domain =
                iommu::default_domain(Bdf::new(0x7e, 0, 0)).map_err(|_| "default domain")?;
            let iova = domain
                .map(0, phys + 0x10, 8192, IommuPerms::READ_WRITE)
                .map_err(|_| "map")?;
            if iova & 0xFFF != 0x10 || iova == phys + 0x10 {
                return Err("IOVA lost the page offset or equals phys");
            }
            if domain.translate(iova) != Some((phys + 0x10, IommuPerms::READ_WRITE)) {
                return Err("first page does not translate to phys");
            }
            // 8 KiB at offset 0x10 spans three pages.
            if domain.translate((iova & !0xFFF) + 0x2000)
                != Some((phys + 0x2000, IommuPerms::READ_WRITE))
            {
                return Err("last page does not translate");
            }
            domain.unmap(iova, 8192).map_err(|_| "unmap")?;
            let flush = model.events().into_iter().rev().find_map(|e| match e {
                ModelEvent::Flush {
                    iova,
                    len,
                    cleared,
                    ok,
                    ..
                } => Some((iova, len, cleared, ok)),
                _ => None,
            });
            if flush != Some((iova & !0xFFF, 3 * 4096, Some(true), true)) {
                return Err("invalidation missing, wrong range or issued before PTE clear");
            }
            if domain.translate(iova).is_some() || domain.mapping_count() != 0 {
                return Err("mapping survived unmap");
            }
            iommu::release_default_domain(Bdf::new(0x7e, 0, 0)).map_err(|_| "release")?;
            narf_memory::free_pages(frame, 1);
            Ok(())
        });
        if !matches!(r, TestResult::Pass) {
            return r;
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "io/iommu/perdomain",
    perdomain_map_translates_and_unmap_orders_invalidation
);

fn perdomain_no_iova_reuse_before_invalidation_completes() -> TestResult {
    with_model(&MODEL, || {
        let domain = IommuDomain::new(0x7001);
        domain.attach(Bdf::new(0x7d, 0, 0)).map_err(|_| "attach")?;
        let phys = 0x4000_0000;
        let iova = domain
            .map(0, phys, 4096, IommuPerms::READ)
            .map_err(|_| "map")?;
        MODEL.set_fail_flush(true);
        if domain.unmap(iova, 4096) != Err(IoError::NotMapped) {
            return Err("unmap succeeded although invalidation failed");
        }
        MODEL.set_fail_flush(false);
        if domain.quarantined_pages() != 1 {
            return Err("failed-flush IOVA not quarantined");
        }
        if domain.translate(iova).is_some() {
            return Err("PTE not cleared before the failed invalidation");
        }
        if domain.map(iova, phys, 4096, IommuPerms::READ) != Err(IoError::OutOfIova) {
            return Err("quarantined IOVA handed out again");
        }
        // A completed invalidation does release the IOVA: top-down
        // allocation hands the same slot back.
        let a = domain
            .map(0, phys, 4096, IommuPerms::READ)
            .map_err(|_| "map 2")?;
        domain.unmap(a, 4096).map_err(|_| "unmap 2")?;
        let b = domain
            .map(0, phys, 4096, IommuPerms::READ)
            .map_err(|_| "map 3")?;
        if a != b {
            return Err("IOVA not reusable after a completed invalidation");
        }
        domain.unmap(b, 4096).map_err(|_| "unmap 3")?;
        domain.detach(Bdf::new(0x7d, 0, 0)).map_err(|_| "detach")?;
        Ok(())
    })
}
kernel_test_in!(
    "io/iommu/perdomain",
    perdomain_no_iova_reuse_before_invalidation_completes
);

fn perdomain_attach_is_exclusive_and_detach_flushes() -> TestResult {
    with_model(&MODEL, || {
        let a = IommuDomain::new(0x7002);
        let b = IommuDomain::new(0x7003);
        let bdf = Bdf::new(0x7c, 1, 2);
        a.attach(bdf).map_err(|_| "attach")?;
        let root = a.page_table_root().ok_or("no page table after attach")?.1;
        if !MODEL.events().contains(&ModelEvent::Attach {
            bdf,
            domain_id: 0x7002,
            root,
        }) {
            return Err("backend not pointed at the domain root");
        }
        if b.attach(bdf) != Err(IoError::DomainMismatch) {
            return Err("device attached to two domains");
        }
        a.detach(bdf).map_err(|_| "detach")?;
        if a.device_count() != 0 || a.detach(bdf).is_ok() {
            return Err("detach bookkeeping");
        }
        b.attach(bdf).map_err(|_| "re-attach after detach")?;
        b.detach(bdf).map_err(|_| "detach b")?;
        if IommuDomain::new(0).attach(bdf) != Err(IoError::DomainMismatch) {
            return Err("reserved domain ID 0 accepted");
        }
        Ok(())
    })
}
kernel_test_in!(
    "io/iommu/perdomain",
    perdomain_attach_is_exclusive_and_detach_flushes
);

fn perdomain_dma_buffer_carries_iova_not_phys() -> TestResult {
    with_model(&MODEL, || {
        let bdf = Bdf::new(0x7b, 0, 0);
        let domain = iommu::default_domain(bdf).map_err(|_| "default domain")?;
        let dev = DmaDevice::coherent().with_iommu_domain(domain.clone());
        let buf = match alloc_coherent_for(&dev, 8192, DomainId::DRIVER_0, u64::from(u32::MAX)) {
            Ok(b) => b,
            Err(IoError::NoMemory) => return Err("frame allocator unavailable"),
            Err(_) => return Err("alloc_coherent_for under PerDomain"),
        };
        let iova = buf.dma_addr().raw();
        let phys = buf.phys_addr().raw();
        if iova == phys || buf.iommu_domain_id() != Some(domain.domain_id()) {
            return Err("dma_addr is the physical address");
        }
        if iova + buf.len() as u64 - 1 > u64::from(u32::MAX) {
            return Err("IOVA above the coherent DMA mask");
        }
        if domain.translate(iova).map(|(p, _)| p) != Some(phys)
            || domain
                .translate(buf.dma_addr_at(4096).raw())
                .map(|(p, _)| p)
                != Some(phys + 4096)
        {
            return Err("IOVA does not translate to the buffer frames");
        }
        drop(buf);
        if domain.translate(iova).is_some() || domain.mapping_count() != 0 {
            return Err("buffer drop left the IOVA mapped");
        }
        // A device without a domain must not get physical addresses.
        if alloc_coherent_for(&DmaDevice::coherent(), 4096, DomainId::DRIVER_0, u64::MAX).err()
            != Some(IoError::NotMapped)
        {
            return Err("domain-less device got a buffer under PerDomain");
        }
        Ok(())
    })
}
kernel_test_in!(
    "io/iommu/perdomain",
    perdomain_dma_buffer_carries_iova_not_phys
);

fn perdomain_block_device_dma_blocks_then_restores() -> TestResult {
    with_model(&MODEL, || {
        let bdf = Bdf::new(0x7a, 0, 0);
        if iommu::block_device_dma(bdf) != Err(IoError::NotMapped) {
            return Err("a device without a default domain reported blocked");
        }
        let domain = iommu::default_domain(bdf).map_err(|_| "default domain")?;
        let dev = DmaDevice::coherent().with_iommu_domain(domain.clone());
        let buf = match alloc_coherent_for(&dev, 4096, DomainId::DRIVER_0, u64::from(u32::MAX)) {
            Ok(b) => b,
            Err(IoError::NoMemory) => return Err("frame allocator unavailable"),
            Err(_) => return Err("alloc_coherent_for under PerDomain"),
        };
        let iova = buf.dma_addr().raw();
        // A detach that does not complete leaves the device attached.
        MODEL.set_fail_detach(true);
        if iommu::block_device_dma(bdf) != Err(IoError::Timeout) || iommu::device_dma_blocked(bdf) {
            return Err("failed detach reported the device blocked");
        }
        MODEL.set_fail_detach(false);
        MODEL.clear_events();
        if iommu::block_device_dma(bdf) != Ok(iommu::DmaBlock::Blocked)
            || !iommu::device_dma_blocked(bdf)
            || iommu::block_device_dma(bdf) != Ok(iommu::DmaBlock::Blocked)
        {
            return Err("block not reported / not idempotent");
        }
        // Blocked first, then the buffer's own unmap + invalidation.
        drop(buf);
        let events = MODEL.events();
        let detach = events
            .iter()
            .position(|e| matches!(e, ModelEvent::Detach { bdf: b, .. } if *b == bdf));
        let flush = events.iter().position(|e| {
            matches!(e, ModelEvent::Flush { iova: i, cleared: Some(true), ok: true, .. } if *i == iova)
        });
        match (detach, flush) {
            (Some(d), Some(f)) if d < f => {}
            _ => return Err("buffer freed before the device was blocked"),
        }
        if domain.translate(iova).is_some() || domain.mapping_count() != 0 {
            return Err("blocked device's buffer stayed mapped");
        }
        iommu::restore_device_dma(bdf).map_err(|_| "restore")?;
        if iommu::device_dma_blocked(bdf) || domain.device_count() != 1 {
            return Err("restore did not re-attach the default domain");
        }
        iommu::restore_device_dma(bdf).map_err(|_| "restore is not idempotent")?;
        Ok(())
    })
}
kernel_test_in!(
    "io/iommu/perdomain",
    perdomain_block_device_dma_blocks_then_restores
);

fn identity_block_device_dma_is_untranslated() -> TestResult {
    iommu::__reset_for_test();
    let bdf = Bdf::new(0x79, 0, 0);
    let ok = iommu::block_device_dma(bdf) == Ok(iommu::DmaBlock::Untranslated)
        && iommu::restore_device_dma(bdf).is_ok()
        && !iommu::device_dma_blocked(bdf);
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("identity/disabled mode claimed an IOMMU block")
    }
}
kernel_test_in!(
    "io/iommu/perdomain",
    identity_block_device_dma_is_untranslated
);
