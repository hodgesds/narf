//! GC12 graphics+compute gangs. Linux amdgpu_cs_job_idx groups by entity,
//! the last IB chooses the leader, and amdgpu_job_run never replays a gang.
use super::*;
use crate::amdgpu_cs::{Ib, Submission, Submitter as Engine};
use crate::{amdgpu_ctx::Health, amdgpu_gfx12_queue as queues, amdgpu_vmid};
use narf_filesystem::FsError;

pub(super) struct Pair {
    pub ibs: [Vec<Ib>; 2],
    pub leader: usize,
}
/// Classify without hardware writes, including before dependency waits and
/// BO promotion. A same-ring request retains its existing submit path.
pub(super) fn plan(engine: &dyn Engine, submission: &Submission) -> Result<Option<Pair>, FsError> {
    let first = submission.ibs.first().ok_or(FsError::InvalidData)?;
    let first_ring = engine
        .ring_for(first.ip_type, first.ip_instance, first.ring)
        .ok_or(FsError::Unsupported)?;
    let mut rings = Vec::new();
    rings
        .try_reserve(submission.ibs.len())
        .map_err(|_| FsError::OutOfMemory)?;
    for ib in &submission.ibs {
        let ring = engine
            .ring_for(ib.ip_type, ib.ip_instance, ib.ring)
            .ok_or(FsError::Unsupported)?;
        if matches!(ring, MEDIA_RING | JPEG_RING) && submission.user_fence.is_some() {
            return Err(FsError::InvalidData);
        }
        rings.push(ring);
    }
    if rings.iter().all(|&ring| ring == first_ring) {
        if submission.ibs.len() > queues::MAX_JOB_IBS {
            return Err(FsError::Unsupported);
        }
        return Ok(None);
    }
    if rings.iter().any(|&ring| ring > 1) {
        return Err(FsError::Unsupported);
    }
    let mut ibs = [Vec::new(), Vec::new()];
    for (ib, ring) in submission.ibs.iter().zip(&rings) {
        let bucket = &mut ibs[*ring as usize];
        if bucket.len() == queues::MAX_JOB_IBS {
            return Err(FsError::Unsupported);
        }
        bucket.try_reserve(1).map_err(|_| FsError::OutOfMemory)?;
        bucket.push(*ib);
    }
    Ok(Some(Pair {
        ibs,
        leader: *rings.last().ok_or(FsError::InvalidData)? as usize,
    }))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Gang {
    tickets: [u64; 2],
    leader: u64,
}
#[derive(Default)]
pub(super) struct Ledger(Vec<Gang>);
impl Ledger {
    pub(super) fn new() -> Self {
        Self(Vec::new())
    }
    pub(super) fn busy(&self) -> bool {
        !self.0.is_empty()
    }
    fn reserve(&mut self) -> Result<(), FsError> {
        self.0.try_reserve(1).map_err(|_| FsError::OutOfMemory)
    }
    fn push(&mut self, tickets: [u64; 2], leader: usize) {
        self.0.push(Gang {
            tickets,
            leader: tickets[leader],
        });
    }
    /// A later fence of the same public leader context must not subsume an
    /// unfinished follower: syncobj/dma_resv may elide earlier context fences.
    fn predecessors(&self, ticket: u64) -> impl Iterator<Item = &Gang> {
        self.0.iter().filter(move |gang| {
            gang.leader >> 32 == ticket >> 32
                && (ticket as u32).wrapping_sub(gang.leader as u32) as i32 >= 0
        })
    }
    pub(super) fn done(&self, completed: [u32; RINGS], ticket: u64) -> bool {
        job_done(completed, ticket)
            && self
                .predecessors(ticket)
                .all(|gang| gang.tickets.iter().all(|&t| job_done(completed, t)))
    }
    pub(super) fn error(
        &self,
        ticket: u64,
        error: impl Fn(u64) -> Option<FsError>,
    ) -> Option<FsError> {
        self.predecessors(ticket)
            .flat_map(|gang| gang.tickets)
            .find_map(error)
    }
    pub(super) fn preserve_errors(
        &self,
        watches: &mut [crate::amdgpu_ring_watch::RingWatch; RINGS],
    ) {
        for gang in &self.0 {
            let error = gang
                .tickets
                .iter()
                .find_map(|&t| watches[(t >> 32) as usize].error(t as u32));
            if let Some(error) = error {
                watches[(gang.leader >> 32) as usize].fail_ticket(gang.leader as u32, error);
            }
        }
    }
    fn stop(&self, watches: &mut [crate::amdgpu_ring_watch::RingWatch; RINGS]) {
        self.preserve_errors(watches);
        for watch in watches.iter_mut() {
            watch.stop();
        }
        for gang in &self.0 {
            watches[(gang.leader >> 32) as usize]
                .fail_ticket(gang.leader as u32, FsError::Canceled);
        }
    }
    pub(super) fn retire(&mut self, completed: [u32; RINGS]) {
        self.0
            .retain(|gang| !gang.tickets.iter().all(|&t| job_done(completed, t)));
    }
}
impl Submitter {
    pub(super) fn complete(&self, completed: [u32; RINGS], ticket: u64) -> bool {
        self.gangs.lock().done(completed, ticket)
    }
    /// Stop every ledger and persist errors for already-finished leaders.
    /// A failed constituent is never replayed independently of its peer.
    pub(super) fn stop_all(&self) {
        {
            let gangs = self.gangs.lock();
            let mut watches = self.watch.lock();
            gangs.stop(&mut watches);
        }
    }
    pub(super) fn abort_gangs(&self, reason: &'static str) {
        self.stop_all();
        self.request_device_recovery(reason);
    }
    pub(super) async fn submit_gang(
        &self,
        vm: &crate::amdgpu_vm::VmState,
        submission: &Submission,
        health: &Arc<Health>,
        pair: Pair,
    ) -> Result<u64, FsError> {
        if vm.geometry() != crate::amdgpu_vm::Geometry::GMC12 {
            return Err(FsError::InvalidData);
        }
        let pd_addr = vm.root_pde().ok_or(FsError::InvalidData)?;
        let pasid = vm.pasid().ok_or(FsError::NoSpace)?;
        let entity = (vm.owner(), submission.ctx_id);
        let requests = core::array::from_fn::<_, 2, _>(|ring| amdgpu_vmid::GrabRequest {
            owner: vm.owner(),
            pd_addr,
            tlb_seq: vm.tlb_seq(),
            pasid,
            ring: ring as u32,
        });
        if pair.leader > 1 {
            return Err(FsError::InvalidData);
        }
        let make_job = |ring: usize| {
            let ibs = &pair.ibs[ring];
            if ibs.is_empty() || ibs.len() > queues::MAX_JOB_IBS {
                return Err(FsError::InvalidData);
            }
            let mut addresses = [(0, 0); queues::MAX_JOB_IBS];
            for (slot, ib) in addresses.iter_mut().zip(ibs) {
                *slot = (ib.va_start, ib.length_dw);
            }
            queues::Job::new(0, pasid, pd_addr, &addresses[..ibs.len()]).ok_or(FsError::InvalidData)
        };
        let mut jobs = [make_job(0)?, make_job(1)?];
        let order = if pair.leader == 0 { [1, 0] } else { [0, 1] };
        let deadline =
            narf_time::monotonic_ns().saturating_add(crate::amdgpu_ring_watch::JOB_TIMEOUT_NS);
        loop {
            let mut owner = OWNER.lock().await;
            let boot = owner.as_mut().ok_or(FsError::NoDevice)?;
            if *READ_GENERATION.lock() != self.generation
                || crate::amdgpu_navi48_interrupts::blocked()
            {
                return Err(FsError::NoDevice);
            }
            if health.reset_epoch() != crate::amdgpu_ctx::recoveries() {
                health.mark_canceled();
                return Err(FsError::Canceled);
            }
            if let Some(error) = health.error() {
                return Err(error);
            }
            {
                let watches = self.watch.lock();
                for watch in &watches[..2] {
                    if let Some(error) = watch.refusing() {
                        return Err(error);
                    }
                }
            }
            let completed = self.progress().ok_or(FsError::NoDevice)?;
            let done = |t| self.complete(completed, t);
            let error_slots = self.gangs.lock().0.len() + 1;
            let tickets = {
                let mut watches = self.watch.lock();
                // A partial publication must be able to stop every ledger
                // and persist completed leaders without allocating afterward.
                for watch in watches.iter_mut() {
                    watch.reserve_errors(error_slots)?;
                }
                [
                    u64::from(watches[0].reserve_submission()?),
                    (1 << 32) | u64::from(watches[1].reserve_submission()?),
                ]
            };
            // Private tentative VMID state; a refusal never changes live
            // grants or LUT/flush ordering. Concurrent GC12 flushes of the
            // same root/PASID follow normal VmidManager rules on each ring.
            let mut vmids = self.vmids.lock().clone();
            let mut admitted = true;
            for ring in order {
                let Some(grant) = vmids.grab(requests[ring], &done) else {
                    admitted = false;
                    break;
                };
                jobs[ring].vmid = grant.vmid;
                jobs[ring].flush = grant.needs_flush;
                jobs[ring].map_pasid = grant.map_pasid;
                jobs[ring].ctx_switch = self.contexts.lock()[ring] != entity;
                jobs[ring].mem_sync =
                    pair.ibs[ring][0].flags & crate::amdgpu_uapi::AMDGPU_IB_FLAG_EMIT_MEM_SYNC != 0;
                vmids.commit(requests[ring], grant, tickets[ring]);
            }
            let prepared = if admitted {
                // SAFETY: OWNER excludes every queue publisher/reset; both
                // jobs use this retained client's root and PASID grants.
                unsafe { boot.prepare_client_gang(jobs) }
            } else {
                Err(queues::Error::Busy)
            };
            let prepared = match prepared {
                Ok(prepared) => prepared,
                Err(queues::Error::Busy) => {
                    drop(owner);
                    if narf_time::monotonic_ns() >= deadline {
                        return Err(FsError::Busy);
                    }
                    narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant())
                        .await;
                    continue;
                }
                Err(queues::Error::Invalid) => return Err(FsError::InvalidData),
                Err(_) => return Err(FsError::NoDevice),
            };
            self.gangs.lock().reserve()?;
            let physical = prepared.sequences();
            // Register every receipt and the aggregate before the FIRST
            // possible WPTR write. No await separates receipts from publication.
            {
                let mut watches = self.watch.lock();
                for ring in order {
                    let seq = watches[ring].submitted(
                        physical[ring],
                        jobs[ring],
                        health.clone(),
                        narf_time::monotonic_ns(),
                    );
                    debug_assert_eq!(u64::from(ring as u32) << 32 | u64::from(seq), tickets[ring]);
                }
            }
            self.gangs.lock().push(tickets, pair.leader);
            for ticket in tickets {
                vm.note_job(ticket);
            }
            *self.vmids.lock() = vmids;
            for context in self.contexts.lock()[..2].iter_mut() {
                *context = entity;
            }
            // SAFETY: both consumers were admitted, all bytes/metadata are
            // prepared, and every constituent owns durable lifetime receipts.
            if unsafe { boot.publish_client_gang(prepared, PIPES[pair.leader]) }.is_err() {
                self.abort_gangs("uncertain GC12 gang publication");
                // Asynchronous device error, with the accepted aggregate
                // receipt. Generic CS must still attach BO/syncobj fences.
            }
            return Ok(tickets[pair.leader]);
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_gang_tests.rs"]
mod tests;
