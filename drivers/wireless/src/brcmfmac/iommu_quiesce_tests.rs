//! IOMMU-backed DMA quiescence smokes (`brcmfmac.md` "IOMMU-backed
//! quiescence"). The msgbuf model drives the actual `Runtime` stop proofs;
//! DMA blocking goes through the real `narf_io::iommu` block/restore API
//! with `narf_io::iommu_model::ModelIommu` as the `PerDomain` backend, and
//! every model mapping is backed by a real IOVA-mapped `DmaBuffer`. The
//! model proves ordering against NARF's page tables and recorded backend
//! calls only, not AMD-Vi silicon behaviour.
use super::*;
use narf_io::iommu::{self, Bdf, DmaBlock, PageTableFormat};
use narf_io::iommu_model::{ModelEvent, ModelIommu};

static IOMMU: ModelIommu = ModelIommu::new(PageTableFormat::AmdV1);

/// Run `f` with `IOMMU` installed (`PerDomain`) or in identity mode,
/// always restoring the disabled state.
fn with_iommu(per_domain: bool, f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    if per_domain {
        if IOMMU.install().is_err() {
            iommu::__reset_for_test();
            return TestResult::Fail("enable_per_domain refused");
        }
    } else {
        iommu::__reset_for_test();
        IOMMU.clear();
        iommu::__force_identity_for_test();
    }
    let result = f();
    IOMMU.set_fail_detach(false);
    iommu::__reset_for_test();
    IOMMU.clear();
    match result {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}

fn iommu_model(bdf: Bdf) -> (Model, Rc<IrqSafeSpinLock<State>>) {
    let (bus, s) = model();
    {
        let mut st = s.lock();
        st.msi = true;
        st.iommu = Some(bdf);
    }
    (bus, s)
}

/// Every recorded IOTLB invalidation of a freed mapping follows the
/// device's blocking detach, and every one completed.
fn blocked_before_every_flush(bdf: Bdf) -> bool {
    let events = IOMMU.events();
    let Some(detach) = events
        .iter()
        .position(|e| matches!(e, ModelEvent::Detach { bdf: b, .. } if *b == bdf))
    else {
        return false;
    };
    events.iter().enumerate().all(|(at, e)| match e {
        ModelEvent::Flush { ok, cleared, .. } => at > detach && *ok && *cleared != Some(false),
        _ => true,
    })
}

/// Confirmed stop under `PerDomain`: D3 ack, drain, IRQ release, BME clear
/// and flush reads, then the IOMMU block, and only then any free. Every
/// published IOVA is unmapped and invalidated after the block.
fn smoke_brcmf_iommu_stop_blocks_then_frees() -> TestResult {
    with_iommu(true, || {
        let bdf = Bdf::new(0x6b, 0, 0);
        let (bus, s) = iommu_model(bdf);
        s.lock().d3_ack = true;
        let mut owner = runtime::Runtime::attach(booted(bus)).map_err(|_| "attach failed")?;
        owner.enable_data().map_err(|_| "RX posting failed")?;
        let domain = iommu::default_domain(bdf).map_err(|_| "no default domain")?;
        {
            let st = s.lock();
            if st.restores != 1
                || iommu::device_dma_blocked(bdf)
                || domain.mapping_count() != st.allocated
            {
                return Err("generation not attached with every mapping in its domain");
            }
        }
        IOMMU.clear_events();
        if ready(owner.quiesce()).is_none_or(|r| r.is_err()) {
            return Err("acknowledged D3 stop did not complete");
        }
        {
            let st = s.lock();
            if !owner.is_reclaimable()
                || !owner.is_iommu_blocked()
                || st.blocks != [Ok(DmaBlock::Blocked)]
                || !iommu::device_dma_blocked(bdf)
                || st.dma_enable
                || st.dropped != 0
            {
                return Err("stop proof did not block the function before reclaim");
            }
        }
        drop(owner);
        let st = s.lock();
        if st.dropped != st.allocated || st.freed_while_attached != 0 || st.unsafe_free != 0 {
            return Err("mappings freed before the IOMMU block or not at all");
        }
        if domain.mapping_count() != 0 || !blocked_before_every_flush(bdf) {
            return Err("IOVA invalidation preceded the block or did not complete");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_iommu_stop_blocks_then_frees
);

/// FWHALT under `PerDomain`: the dead stop blocks the function after the
/// flush reads and before the watchdog reset; reclaim follows, and the
/// rebooted generation is re-attached (restore) before its first mapping.
fn smoke_brcmf_iommu_dead_firmware_blocks_before_reclaim() -> TestResult {
    with_iommu(true, || {
        let bdf = Bdf::new(0x6c, 0, 0);
        let (bus, s) = iommu_model(bdf);
        s.lock().lsc = 0x0011_0043;
        let mut owner = runtime::Runtime::attach(booted(bus)).map_err(|_| "attach failed")?;
        raise_mailbox(&mut s.lock(), D2H_DEV_FWHALT);
        if owner.poll().is_ok() || !owner.is_failed() {
            return Err("FWHALT did not fail the generation");
        }
        IOMMU.clear_events();
        narf_scheduler::block_on(owner.stop_dead()).map_err(|_| "dead-firmware stop failed")?;
        {
            let st = s.lock();
            if st.watchdogs_at_block != Some(0)
                || st.watchdogs != 1
                || !owner.is_reclaimable()
                || !owner.is_iommu_blocked()
                || st.dropped != 0
            {
                return Err("dead stop did not block before the reset / reclaim");
            }
        }
        let bus = owner
            .into_bus()
            .map_err(|_| "proven dead stop refused release")?;
        {
            let st = s.lock();
            if st.dropped != st.allocated || st.freed_while_attached != 0 {
                return Err("dead stop freed a mapping the device could still reach");
            }
        }
        if !blocked_before_every_flush(bdf) {
            return Err("IOVA invalidation preceded the block");
        }
        let booted = station_model::boot_fixture(bus).map_err(|_| "reboot download refused")?;
        let fresh = runtime::Runtime::attach(booted).map_err(|_| "rebooted attach failed")?;
        let domain = iommu::default_domain(bdf).map_err(|_| "no default domain")?;
        {
            let st = s.lock();
            if st.restores != 2
                || iommu::device_dma_blocked(bdf)
                || domain.device_count() != 1
                || domain.mapping_count() != st.allocated - st.dropped
            {
                return Err("fresh generation mapped before the device was restored");
            }
        }
        drop(fresh);
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_iommu_dead_firmware_blocks_before_reclaim
);

/// Without a device-side proof (late DMA after BME clear, or a vanished
/// function) a completed IOMMU block still makes the memory reclaimable
/// (Linux model), but the owner never claims a proven stop. A block whose
/// invalidation does not complete keeps everything pinned.
fn smoke_brcmf_iommu_unproven_stop_reclaims_only_behind_block() -> TestResult {
    with_iommu(true, || {
        let bdf = Bdf::new(0x6d, 0, 0);
        let (bus, s) = iommu_model(bdf);
        {
            let mut st = s.lock();
            st.d3_ack = true;
            st.late_dma = true;
        }
        let mut owner = runtime::Runtime::attach(booted(bus)).map_err(|_| "attach failed")?;
        if ready(owner.quiesce()) != Some(Err(runtime::Error::Protocol))
            || owner.is_reclaimable()
            || owner.is_iommu_blocked()
        {
            return Err("post-BME DMA activity was accepted as quiescence");
        }
        if !owner.release_dma() || !owner.is_iommu_blocked() || owner.is_reclaimable() {
            return Err("IOMMU block did not release the unproven generation");
        }
        drop(owner);
        {
            let st = s.lock();
            if st.dropped != st.allocated || st.freed_while_attached != 0 {
                return Err("unproven generation freed without a block");
            }
        }
        // Vanished function: the dead stop fails, the block still holds.
        let bdf = Bdf::new(0x6e, 0, 0);
        let (bus, s) = iommu_model(bdf);
        let mut owner = runtime::Runtime::attach(booted(bus)).map_err(|_| "attach failed")?;
        owner.fail();
        s.lock().gone = true;
        if narf_scheduler::block_on(owner.stop_dead()) != Err(runtime::Error::Access)
            || owner.is_reclaimable()
            || s.lock().watchdogs != 0
        {
            return Err("vanished function passed the dead stop");
        }
        drop(owner);
        {
            let st = s.lock();
            if st.dropped != st.allocated || st.freed_while_attached != 0 {
                return Err("vanished function's memory not reclaimed behind the block");
            }
        }
        // The blocking invalidation times out: the device may still DMA.
        let bdf = Bdf::new(0x6f, 0, 0);
        let (bus, s) = iommu_model(bdf);
        s.lock().d3_ack = true;
        let mut owner = runtime::Runtime::attach(booted(bus)).map_err(|_| "attach failed")?;
        IOMMU.set_fail_detach(true);
        if ready(owner.quiesce()) != Some(Err(runtime::Error::Access))
            || owner.is_reclaimable()
            || owner.is_iommu_blocked()
            || iommu::device_dma_blocked(bdf)
        {
            return Err("failed IOMMU block was accepted as quiescence");
        }
        drop(owner);
        if s.lock().dropped != 0 {
            return Err("memory released although the IOMMU block failed");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_iommu_unproven_stop_reclaims_only_behind_block
);

/// Identity mode: the IOMMU reports `Untranslated`, nothing is detached,
/// the device-side proof alone still gates reclaim, and an unproven stop
/// stays pinned exactly as before.
fn smoke_brcmf_identity_iommu_keeps_device_proof_order() -> TestResult {
    with_iommu(false, || {
        let bdf = Bdf::new(0x6a, 0, 0);
        let (bus, s) = iommu_model(bdf);
        s.lock().d3_ack = true;
        let mut owner = runtime::Runtime::attach(booted(bus)).map_err(|_| "attach failed")?;
        if ready(owner.quiesce()).is_none_or(|r| r.is_err()) {
            return Err("acknowledged D3 stop did not complete");
        }
        if !owner.is_reclaimable()
            || owner.is_iommu_blocked()
            || s.lock().blocks != [Ok(DmaBlock::Untranslated)]
            || iommu::device_dma_blocked(bdf)
        {
            return Err("identity mode claimed an IOMMU block");
        }
        drop(owner);
        {
            let st = s.lock();
            if st.dropped != st.allocated {
                return Err("device proof alone no longer reclaims in identity mode");
            }
        }
        let (bus, s) = iommu_model(bdf);
        {
            let mut st = s.lock();
            st.d3_ack = true;
            st.late_dma = true;
        }
        let mut owner = runtime::Runtime::attach(booted(bus)).map_err(|_| "attach failed")?;
        if ready(owner.quiesce()) != Some(Err(runtime::Error::Protocol)) || owner.release_dma() {
            return Err("identity mode released an unproven generation");
        }
        drop(owner);
        if s.lock().dropped != 0 || !IOMMU.events().is_empty() {
            return Err("identity mode freed DMA or touched the IOMMU backend");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_identity_iommu_keeps_device_proof_order
);
