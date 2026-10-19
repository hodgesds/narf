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
        // Freeze every ledger before the first await/reset. Synchronous
        // readers also freeze on BLOCKED; reset-test fences retire nothing.
        for watch in self.watch.lock().iter_mut() {
            watch.freeze();
        }
        let result = async {
            let boot = owner
                .as_mut()
                .ok_or(RingError::Interrupts(crate::amdgpu_ih7::Error::Busy))?;
            // SAFETY: OWNER excludes every queue/clear/reset/PM user; all
            // ledgers are frozen and remain so on error or cancellation.
            let mut receipt =
                unsafe { irq::begin_recovery().await }.map_err(RingError::Interrupts)?;
            for (ring, pipe) in PIPES.into_iter().enumerate() {
                let vmid = self.watch.lock()[ring].reset_vmid();
                // SAFETY: all pending allocations/VMIDs stay pinned by the
                // frozen ledgers; only these three kernel queues exist.
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
            // SAFETY: all three retirements proved; OWNER still excludes all
            // submissions and every ledger remains frozen until replay ends.
            let scope =
                unsafe { irq::finish_recovery(receipt).await }.map_err(RingError::Interrupts)?;
            {
                let mut watches = self.watch.lock();
                for (ring, watch) in watches.iter_mut().enumerate() {
                    watch.faulted(scope, ring, crate::amdgpu_navi48_faults::Hub::Gfx);
                }
            }
            // Mark all contexts first: a guilty context may have queued work
            // on several rings. Only healthy jobs receive replay fences.
            for ring in 0..RINGS {
                let jobs = self.watch.lock()[ring].replay();
                for (ticket, job) in jobs {
                    let seq = match PIPES.get(ring) {
                        // SAFETY: frozen ledger retains the complete job and
                        // its VMID, and OWNER excludes competing publication.
                        Some(&pipe) => unsafe { boot.submit_client_job(pipe, job) }
                            .map_err(RingError::Queue)?,
                        // SAFETY: same retained memory and exclusive SDMA owner.
                        None => {
                            // SAFETY: same retained memory and exclusive SDMA owner.
                            unsafe { boot.submit_client_sdma_job(job) }.map_err(RingError::Sdma)?
                        }
                    };
                    self.watch.lock()[ring].replayed(ticket, seq);
                }
            }
            if irq::blocked() {
                return Err(RingError::Interrupts(crate::amdgpu_ih7::Error::Protocol));
            }
            // Commit all ledgers together; an earlier successful replay must
            // not retire memory when a later ring's replay fails.
            {
                let mut watches = self.watch.lock();
                for watch in watches.iter_mut() {
                    watch.recovered(narf_time::monotonic_ns());
                }
            }
            *self.contexts.lock() = [(0, 0); RINGS];
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
