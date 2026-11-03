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
use narf_io::iommu::{self, Bdf, PageTableFormat};
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
