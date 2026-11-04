//! Production ring allocation behind a per-domain IOMMU.
//!
//! Linux mt76 has no IOMMU code: `dma_alloc_coherent` returns an iommu-dma
//! IOVA and the driver programs it. Here the function's default domain is
//! driven by `narf_io::iommu_model::ModelIommu`, a software backend over
//! NARF's real page tables (no silicon): this proves every programmed
//! descriptor/buffer address is an IOVA of the function's domain that
//! translates to the ring's frames, fits the 32-bit descriptor-base
//! registers, and is invalidated before release on teardown.
use super::super::*;
use narf_io::iommu::{self, Bdf, DmaBlock, PageTableFormat};
use narf_io::iommu_model::{ModelEvent, ModelIommu};
use narf_io::DmaDevice;
use narf_kernel_test::{kernel_test_in, TestResult};

static MODEL: ModelIommu = ModelIommu::new(PageTableFormat::AmdV1);

fn mapped(domain: &iommu::IommuDomain, buffer: &narf_io::DmaBuffer) -> bool {
    let iova = buffer.dma_addr().raw();
    iova != buffer.phys_addr().raw()
        && (0..buffer.len() as u64 / 4096).all(|page| {
            domain.translate(iova + page * 4096).map(|(p, _)| p)
                == Some(buffer.phys_addr().raw() + page * 4096)
        })
}

fn mt7921_rings_program_perdomain_iovas() -> TestResult {
    if MODEL.install().is_err() {
        iommu::__reset_for_test();
        return TestResult::Fail("enable_per_domain refused");
    }
    let bdf = Bdf::new(0x7a, 0, 0);
    let result = (|| {
        let domain = iommu::default_domain(bdf).map_err(|_| "default domain")?;
        let dev = DmaDevice::coherent().with_iommu_domain(domain.clone());
        let mut rings = Vec::new();
        let mut buffers = 0usize;
        for (base, rx) in [
            (TX_WM, false),
            (TX_FWDL, false),
            (TX_DATA, false),
            (RX_PRE, true),
            (RX_POST, true),
            (RX_DATA, true),
        ] {
            let ring = Ring::allocate_for(&dev, base, rx).map_err(|_| "ring allocation")?;
            if !mapped(&domain, &ring.descriptors)
                || !ring.buffers.iter().all(|b| mapped(&domain, b))
            {
                return Err("ring address is not a domain IOVA of its frames");
            }
            if ring.descriptors.dma_addr().raw() + (DEPTH * 16) as u64 > 1 << 32 {
                return Err("descriptor IOVA above the 32-bit ring base");
            }
            // mt7921_pci_probe: dma_set_mask(DMA_BIT_MASK(32)) for every mapping.
            if ring
                .buffers
                .iter()
                .any(|b| b.dma_addr().raw() + MAX_FRAME as u64 > 1 << 32)
            {
                return Err("frame buffer IOVA above the 32-bit DMA mask");
            }
            if rx
                && (0..DEPTH)
                    .any(|slot| ring.word(slot, 0) != ring.buffers[slot].dma_addr().raw() as u32)
            {
                return Err("RX descriptor not armed with the buffer IOVA");
            }
            buffers += 1 + ring.buffers.len();
            rings.push(ring);
        }
        if domain.mapping_count() != buffers {
            return Err("mapping count does not match ring buffers");
        }
        MODEL.clear_events();
        drop(rings);
        let flushes = MODEL
            .events()
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    ModelEvent::Flush {
                        cleared: Some(true),
                        ok: true,
                        ..
                    }
                )
            })
            .count();
        if flushes != buffers || domain.mapping_count() != 0 {
            return Err("teardown did not invalidate every cleared mapping");
        }
        Ok(())
    })();
    iommu::__reset_for_test();
    MODEL.clear();
    match result {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/mt7921/iommu",
    mt7921_rings_program_perdomain_iovas
);

/// Run `f` with `MODEL` installed (`PerDomain`) or in identity mode, always
/// restoring the disabled state.
fn with_iommu(per_domain: bool, f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    if per_domain {
        if MODEL.install().is_err() {
            iommu::__reset_for_test();
            return TestResult::Fail("enable_per_domain refused");
        }
    } else {
        iommu::__reset_for_test();
        MODEL.clear();
        iommu::__force_identity_for_test();
    }
    let result = f();
    MODEL.set_fail_detach(false);
    iommu::__reset_for_test();
    MODEL.clear();
    match result {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

/// The production backend over owned MMIO words, with the function at
/// `bdf` and every ring allocated through `dev`.
fn domain_rig(
    bdf: (u8, u8, u8),
    dev: &DmaDevice,
) -> Result<(Vec<u32>, Hardware, usize), &'static str> {
    let addr = narf_bus::PcieAddr::new(0, bdf.0, bdf.1, bdf.2);
    let (words, hw) = super::rig_with(dev, addr).map_err(|_| "rig allocation")?;
    Ok((words, hw, 6 * (1 + DEPTH)))
}

/// Every recorded invalidation follows the function's blocking detach, and
/// every one completed with its range already cleared.
fn blocked_before_every_flush(bdf: Bdf) -> bool {
    let events = MODEL.events();
    let Some(detach) = events
        .iter()
        .position(|e| matches!(e, ModelEvent::Detach { bdf: b, .. } if *b == bdf))
    else {
        return false;
    };
    let flushes = events
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e, ModelEvent::Flush { .. }))
        .collect::<Vec<_>>();
    !flushes.is_empty() && flushes.iter().all(|(at, e)| {
        *at > detach
            && matches!(e, ModelEvent::Flush { ok: true, cleared, .. } if *cleared != Some(false))
    })
}

/// Proven stop under `PerDomain`: after the device-side proof `release`
/// unpublishes through the IOMMU block; nothing is freed by the block, and
/// the later free of every ring unmaps strictly behind it.
fn mt7921_iommu_stop_blocks_then_frees() -> TestResult {
    with_iommu(true, || {
        let bdf = Bdf::new(0x7b, 0, 0);
        let domain = iommu::default_domain(bdf).map_err(|_| "default domain")?;
        let dev = DmaDevice::coherent().with_iommu_domain(domain.clone());
        let (words, mut hw, buffers) = domain_rig((0x7b, 0, 0), &dev)?;
        hw.owner.published = true;
        MODEL.clear_events();
        hw.unpublish().map_err(|_| "unpublish refused")?;
        if hw.owner.published
            || !iommu::device_dma_blocked(bdf)
            || domain.mapping_count() != buffers
        {
            return Err("stop did not block before reclaim, or freed early");
        }
        // Idempotent: recovery parks (blocks) before release blocks again.
        if hw.block_dma() != Ok(DmaBlock::Blocked) {
            return Err("second block of a blocked function was not Blocked");
        }
        drop(hw);
        drop(words);
        if domain.mapping_count() != 0 || !blocked_before_every_flush(bdf) {
            return Err("ring IOVA invalidation preceded the block or did not complete");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/mt7921/iommu",
    mt7921_iommu_stop_blocks_then_frees
);

/// Dead firmware / failed recovery: the owner is dropped with its rings
/// still published. Behind the IOMMU the drop blocks the function and only
/// then frees; a failed block keeps the rings retained (never freed).
fn mt7921_iommu_dead_owner_blocks_before_reclaim() -> TestResult {
    with_iommu(true, || {
        let bdf = Bdf::new(0x7c, 0, 0);
        let domain = iommu::default_domain(bdf).map_err(|_| "default domain")?;
        let dev = DmaDevice::coherent().with_iommu_domain(domain.clone());
        // Block failure: the device may still translate, so nothing is freed.
        let (words, mut hw, buffers) = domain_rig((0x7c, 0, 0), &dev)?;
        hw.owner.published = true;
        MODEL.set_fail_detach(true);
        if hw.block_for_reclaim() || !hw.owner.published || domain.mapping_count() != buffers {
            return Err("failed IOMMU block released published rings");
        }
        MODEL.set_fail_detach(false);
        MODEL.clear_events();
        drop(hw);
        drop(words);
        if !iommu::device_dma_blocked(bdf)
            || domain.mapping_count() != 0
            || !blocked_before_every_flush(bdf)
        {
            return Err("dead owner freed without a completed block first");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/mt7921/iommu",
    mt7921_iommu_dead_owner_blocks_before_reclaim
);

/// Recovery and re-attach: the function stays blocked across reset; the
/// retained rings are re-opened (`initialize` → `restore_dma`) and a new
/// generation (`Transport::new` → `restore_function_dma`) is re-attached
/// before its first mapping, whose IOVAs then translate for the device.
fn mt7921_iommu_recovery_restores_before_reallocation() -> TestResult {
    with_iommu(true, || {
        let bdf = Bdf::new(0x7d, 0, 0);
        let domain = iommu::default_domain(bdf).map_err(|_| "default domain")?;
        let dev = DmaDevice::coherent().with_iommu_domain(domain.clone());
        let (words, mut hw, buffers) = domain_rig((0x7d, 0, 0), &dev)?;
        hw.owner.published = true;
        hw.unpublish().map_err(|_| "unpublish refused")?;
        MODEL.clear_events();
        // Recovery reuses the same rings: restore keeps every mapping.
        hw.restore_dma().map_err(|_| "restore refused")?;
        if iommu::device_dma_blocked(bdf)
            || domain.mapping_count() != buffers
            || !matches!(MODEL.events().first(), Some(ModelEvent::Attach { bdf: b, .. }) if *b == bdf)
        {
            return Err("recovery did not re-attach the retained domain");
        }
        let fwdl = &hw.owner.storage.as_ref().ok_or("storage")?.fwdl;
        if !mapped(&domain, &fwdl.descriptors) || !fwdl.buffers.iter().all(|b| mapped(&domain, b)) {
            return Err("retained ring lost its IOVA translation");
        }
        // Stop again, free, then a fresh generation on the same function.
        hw.unpublish().map_err(|_| "second unpublish refused")?;
        drop(hw);
        drop(words);
        if !iommu::device_dma_blocked(bdf) || domain.mapping_count() != 0 {
            return Err("stopped generation not blocked and reclaimed");
        }
        MODEL.clear_events();
        let addr = narf_bus::PcieAddr::new(0, 0x7d, 0, 0);
        let device = BusDevice {
            addr: narf_bus::BusAddr::Pcie(addr),
            id: narf_bus::DeviceId {
                vendor: 0x14c3,
                device: 0x0616,
                class: 0x028000,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: narf_bus::BusKind::Pcie {
                addr,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        };
        restore_function_dma(&device).map_err(|_| "new generation restore refused")?;
        if iommu::device_dma_blocked(bdf)
            || !matches!(MODEL.events().first(), Some(ModelEvent::Attach { bdf: b, .. }) if *b == bdf)
        {
            return Err("new generation not re-attached before allocation");
        }
        let ring = Ring::allocate_for(&dev, TX_FWDL, false).map_err(|_| "reallocation")?;
        if !mapped(&domain, &ring.descriptors) || !ring.buffers.iter().all(|b| mapped(&domain, b)) {
            return Err("re-allocated ring is not a domain IOVA of its frames");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/mt7921/iommu",
    mt7921_iommu_recovery_restores_before_reallocation
);

/// Identity mode keeps today's behaviour: blocking is `Untranslated` and
/// touches no IOMMU, a still-published owner stays retained on drop, and
/// rings carry physical bus addresses.
fn mt7921_identity_iommu_keeps_retained_owner() -> TestResult {
    with_iommu(false, || {
        let (words, mut hw) = super::rig().map_err(|_| "rig allocation")?;
        hw.owner.published = true;
        if hw.block_dma() != Ok(DmaBlock::Untranslated)
            || hw.block_for_reclaim()
            || !hw.owner.published
            || restore_function_dma(&hw.device).is_err()
            || hw.restore_dma().is_err()
            || !MODEL.events().is_empty()
        {
            return Err("identity mode changed the retained-owner order");
        }
        let wm = &hw.owner.storage.as_ref().ok_or("storage")?.wm;
        if wm.descriptors.dma_addr().raw() != wm.descriptors.phys_addr().raw() {
            return Err("identity ring address is not physical");
        }
        hw.unpublish().map_err(|_| "unpublish refused")?;
        if hw.owner.published || !MODEL.events().is_empty() {
            return Err("identity unpublish touched the IOMMU");
        }
        drop(hw);
        drop(words);
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/mt7921/iommu",
    mt7921_identity_iommu_keeps_retained_owner
);
