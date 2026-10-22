//! Coordinated recovery while the retained platform owner excludes clients.
use super::*;
use crate::amdgpu_navi48_interrupts as irq;

impl Submitter {
    pub(super) async fn recover_faults(&self) {
        use core::fmt::Write as _;
        let mut owner = OWNER.lock().await;
        if *READ_GENERATION.lock() != self.generation {
            return;
        }
        let gang_busy = self.gangs.lock().busy();
        if gang_busy {
            self.abort_gangs("GC12 gang fault; independent replay forbidden");
            return;
        }
        // Freeze every ledger before the first await/reset. Synchronous
        // readers also freeze on BLOCKED; reset-test fences retire nothing.
        {
            let _generation = READ_GENERATION.lock();
            for watch in self.watch.lock().iter_mut() {
                watch.freeze();
            }
        }
        // Cancellation before media's later retirement must not leave old
        // proof metadata visible while the coordinated recovery is frozen.
        crate::amdgpu_info::publish_navi48_media(0, None);
        let result = async {
            let boot = owner
                .as_mut()
                .ok_or(RingError::Interrupts(crate::amdgpu_ih7::Error::Busy))?;
            let media = boot.client_media_owner();
            // JPEG0 lives only under VCN0's shared range; order follows rings.
            let owners: alloc::vec::Vec<_> = media
                .into_iter()
                .chain(media.and(boot.client_jpeg_owner()))
                .collect();
            // SAFETY: OWNER excludes every queue/clear/reset/PM user; all
            // ledgers are frozen and remain so on error or cancellation.
            let mut receipt =
                unsafe { irq::begin_recovery(&owners).await }.map_err(RingError::Interrupts)?;
            for (ring, pipe) in PIPES.into_iter().enumerate() {
                let vmid = self.watch.lock()[ring].reset_vmid();
                // SAFETY: all pending allocations/VMIDs stay pinned by the
                // frozen ledgers; these GC12 queues are exclusively owned.
                unsafe { boot.recover_client_ring(pipe, vmid).await }.map_err(RingError::Queue)?;
                // SAFETY: the ring's reset and fresh fence test just completed.
                unsafe {
                    receipt.retired(ring);
                }
            }
            // SAFETY: same exclusion; skipped kernel clears are requeued
            // before the SDMA test fence can be trusted by their waiters.
            unsafe { boot.recover_client_sdma(requeue_clears).await }.map_err(RingError::Sdma)?;
            // SAFETY: SDMA's reset and new fence test completed.
            unsafe {
                receipt.retired(SDMA_RING as usize);
            }
            if media.is_some() {
                // Restart clears codec context. Cancel every old media
                // context before awaiting; no media IB may be replayed.
                self.watch.lock()[MEDIA_RING as usize].stop();
                // SAFETY: all ledgers frozen, retained resources and OWNER
                // cover media drain, VCPU/LMI retirement and fresh transport.
                // A live JPEG ring is retired first, keeping its staged jobs.
                unsafe { boot.retire_client_media().await }.map_err(RingError::Media)?;
                // SAFETY: old media work retired and new transport drained.
                unsafe { receipt.retired(MEDIA_RING as usize) };
                if owners.len() > 1 {
                    // SAFETY: retire_client_media proved JPEG's JMI reset,
                    // clean DMA and power-down before VCN's own stop.
                    unsafe { receipt.retired(JPEG_RING as usize) };
                }
            }
            // SAFETY: all owned retirements proved; OWNER still excludes all
            // submissions and every ledger remains frozen until replay ends.
            let (scope, renewed_media) =
                unsafe { irq::finish_recovery(receipt).await }.map_err(RingError::Interrupts)?;
            if let Some(&handle) = renewed_media.get(1) {
                // SAFETY: the receipt renewed this exact retired JPEG owner.
                unsafe { boot.jpeg_rearmed(handle) };
            }
            if let Some(&handle) = renewed_media.first() {
                // SAFETY: the receipt renewed this exact retired media owner.
                unsafe { boot.media_rearmed(handle) };
                // SAFETY: all rings remain frozen; re-arm restored reporting
                // and OWNER retains the restarted VCN and renewed handle.
                unsafe { boot.reprove_client_media().await }.map_err(RingError::Media)?;
            }
            {
                let mut watches = self.watch.lock();
                for (ring, watch) in watches.iter_mut().enumerate() {
                    let hub = if matches!(ring as u32, MEDIA_RING | JPEG_RING) {
                        crate::amdgpu_navi48_faults::Hub::Mm
                    } else {
                        crate::amdgpu_navi48_faults::Hub::Gfx
                    };
                    watch.faulted(scope, ring, hub);
                }
            }
            // Mark all contexts first: a guilty context may have queued work
            // on several rings. Only healthy jobs receive replay fences.
            for ring in 0..RINGS {
                let jobs = self.watch.lock()[ring].replay();
                for (ticket, job) in jobs {
                    // SAFETY: OWNER and the frozen ledger retain all
                    // mappings, BOs and the correct hub's VMID. Restarted
                    // media contexts were cancelled and have no replay jobs;
                    // JPEG jobs replay from their retained kernel IB copies.
                    let seq = unsafe { media_clients::publish_client(boot, ring as u32, job) }
                        .map_err(RingError::Client)?;
                    self.watch.lock()[ring].replayed(ticket, seq);
                }
            }
            if irq::blocked() {
                return Err(RingError::Interrupts(crate::amdgpu_ih7::Error::Protocol));
            }
            // Commit all ledgers together; an earlier successful replay must
            // not retire memory when a later ring's replay fails.
            {
                let _generation = READ_GENERATION.lock();
                let mut watches = self.watch.lock();
                for watch in watches.iter_mut() {
                    watch.recovered(narf_time::monotonic_ns());
                }
            }
            *self.contexts.lock() = [(0, 0); RINGS];
            // All media proofs and every healthy replay committed under OWNER.
            media_clients::activate_media(boot);
            Ok(scope)
        }
        .await;
        match result {
            Ok(scope) => {
                let _ = self.progress();
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi48 fault recovery succeeded {scope:?}"
                );
            }
            Err(error) => {
                // Failure never reopens clients, even if source arming itself
                // succeeded before a replay submission failed.
                irq::quarantine().await;
                for watch in self.watch.lock().iter_mut() {
                    watch.stop();
                }
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi48 fault recovery refused {error:?}; device recovery required"
                );
            }
        }
    }
}
