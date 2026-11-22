//! API completion and physical retirement are separate on the native RDNA2
//! queues. Only observed writebacks can retire memory; reset/loss errors
//! wake clients while every unconfirmed resource remains quarantined.
use super::{ring_index, RING_IDS};
use crate::amdgpu_ctx::Health;
use alloc::{sync::Arc, vec::Vec};
use narf_filesystem::FsError;

#[derive(Debug)]
pub(super) struct Jobs {
    epoch: u64,
    completed: [u32; RING_IDS],
    pub terminal: Option<FsError>,
    /// (ticket, context health, VMID the job ran in; 0 when not recorded).
    pending: Vec<(u64, Arc<Health>, u8)>,
    /// Jobs a recovery failed while the submitter carried on, with their
    /// error, kept after they retire. Bounded: the oldest entries go first.
    failed: Vec<(u64, FsError)>,
    /// Sequences a VCN engine reset force-completed, per ring id: after
    /// the first, up to the second (`cancel`). They end with `-ECANCELED`.
    cancelled: Vec<(usize, u32, u32)>,
    /// Jobs whose timeout was suspended (`time_out`): `-ETIME` once done.
    timed_out: Vec<u64>,
}
/// How many recovered jobs keep their error after they retire.
const FAILED_KEPT: usize = 64; // linux: n/a (NARF bound)

/// The ticket's ring id (the low four bits of its ring index).
fn ring_id(ticket: u64) -> usize {
    ((ticket >> 32) as u32 & 15) as usize
}
/// Whether `ticket` of `epoch` is one of the sequences an engine reset
/// force-completed on a ring: (ring id, after, up to).
fn forced(epoch: u64, (ring, after, upto): (usize, u32, u32), ticket: u64) -> bool {
    use crate::amdgpu_fence_navi22::signaled;
    let seq = ticket as u32;
    (ticket >> 32) as u32 & !15 == ring_index(epoch, 0)
        && ring_id(ticket) == ring
        && signaled(upto, seq)
        && !signaled(after, seq)
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn ticket(epoch: u64, ring: usize, seq: u32) -> u64 {
        u64::from(ring_index(epoch, ring)) << 32 | u64::from(seq)
    }
    fn rdna2_failed_jobs_signal_without_retiring_memory() -> TestResult {
        let mut jobs = Jobs::new(13);
        let done = ticket(13, 0, 5);
        let pending = ticket(13, 1, 9);
        jobs.emitted(done, &Arc::new(Health::default()));
        let health = Arc::new(Health::default());
        jobs.emitted(pending, &health);
        let mut completed = [0; RING_IDS];
        completed[0] = 5;
        jobs.observe(completed);
        jobs.finish(FsError::Canceled);
        assert!(jobs.retired(done));
        assert_eq!(jobs.error(done), None);
        assert!(!jobs.retired(pending));
        assert_eq!(jobs.error(pending), Some(FsError::Canceled));
        assert_eq!(health.error(), Some(FsError::Canceled));
        completed[1] = 9;
        jobs.observe(completed);
        assert!(!jobs.retired(pending));
        jobs.finish(FsError::NoDevice);
        assert_eq!(jobs.error(pending), Some(FsError::NoDevice));
        assert_eq!(jobs.error(done), None);
        assert!(!jobs.retired(ticket(12, 0, 5)));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/fence-errors",
        rdna2_failed_jobs_signal_without_retiring_memory
    );
    fn rdna2_hang_preserves_guilt_and_late_publication_errors() -> TestResult {
        let mut jobs = Jobs::new(3);
        for (ring, seq) in [(1, 3), (1, 4), (0, 8)] {
            jobs.emitted(ticket(3, ring, seq), &Arc::new(Health::default()));
        }
        jobs.hang(1);
        assert_eq!(jobs.error(ticket(3, 1, 3)), Some(FsError::TimedOut));
        assert_eq!(jobs.error(ticket(3, 1, 4)), Some(FsError::Canceled));
        assert_eq!(jobs.error(ticket(3, 0, 8)), Some(FsError::Canceled));
        jobs.finish(FsError::Canceled);
        assert_eq!(jobs.error(ticket(3, 1, 3)), Some(FsError::TimedOut));
        let late = Arc::new(Health::default());
        jobs.emitted(ticket(3, 0, 9), &late);
        assert_eq!(late.error(), Some(FsError::Canceled));
        assert!(!jobs.retired(ticket(3, 0, 9)));
        let mut wrap = Jobs::new(3);
        let mut completed = [0; RING_IDS];
        completed[0] = u32::MAX - 1;
        wrap.observe(completed);
        wrap.emitted(ticket(3, 0, u32::MAX), &Arc::new(Health::default()));
        wrap.emitted(ticket(3, 0, 0), &Arc::new(Health::default()));
        completed[0] = 0;
        wrap.observe(completed);
        wrap.finish(FsError::Canceled);
        assert!(wrap.retired(ticket(3, 0, u32::MAX)) && wrap.retired(ticket(3, 0, 0)));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/fence-errors",
        rdna2_hang_preserves_guilt_and_late_publication_errors
    );
    /// A recovered hang (soft recovery, queue reset) fails the timed-out job
    /// alone, whose error outlives its retirement; the ledger stays open.
    fn rdna2_recovered_hang_fails_only_the_timed_out_job() -> TestResult {
        let mut jobs = Jobs::new(5);
        let (guilty, behind, other) = (
            Arc::new(Health::default()),
            Arc::new(Health::default()),
            Arc::new(Health::default()),
        );
        jobs.emitted_on(ticket(5, 0, 7), &guilty, 3);
        jobs.emitted_on(ticket(5, 0, 8), &behind, 4);
        jobs.emitted_on(ticket(5, 1, 2), &other, 5);
        if jobs.oldest(0) != Some((ticket(5, 0, 7), 3)) || jobs.oldest(2).is_some() {
            return TestResult::Fail("oldest job on a ring");
        }
        jobs.recovered(ticket(5, 0, 7));
        let mut completed = [0; RING_IDS];
        (completed[0], completed[1]) = (8, 2);
        jobs.observe(completed);
        if jobs.terminal.is_some()
            || jobs.error(ticket(5, 0, 7)) != Some(FsError::TimedOut)
            || guilty.error() != Some(FsError::TimedOut)
            || !jobs.retired(ticket(5, 0, 7))
            || jobs.error(ticket(5, 0, 8)).is_some()
            || behind.error().is_some()
            || jobs.error(ticket(5, 1, 2)).is_some()
            || other.error().is_some()
        {
            return TestResult::Fail("recovery failed more than the timed-out job");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/fence-errors",
        rdna2_recovered_hang_fails_only_the_timed_out_job
    );
    /// A queue reset fails the timed-out job (`TimedOut`, context guilty) and
    /// cancels the jobs behind it on that ring without poisoning their
    /// contexts; other rings and the ledger carry on.
    fn rdna2_queue_reset_cancels_the_ring_behind_the_guilty_job() -> TestResult {
        let mut jobs = Jobs::new(6);
        let (guilty, behind, other) = (
            Arc::new(Health::default()),
            Arc::new(Health::default()),
            Arc::new(Health::default()),
        );
        jobs.emitted_on(ticket(6, 1, 4), &guilty, 2);
        jobs.emitted_on(ticket(6, 1, 5), &behind, 3);
        jobs.emitted_on(ticket(6, 0, 9), &other, 4);
        jobs.reset(1, ticket(6, 1, 4));
        let mut completed = [0; RING_IDS];
        (completed[0], completed[1]) = (9, 5);
        jobs.observe(completed);
        if jobs.terminal.is_some()
            || jobs.error(ticket(6, 1, 4)) != Some(FsError::TimedOut)
            || guilty.error() != Some(FsError::TimedOut)
            || jobs.error(ticket(6, 1, 5)) != Some(FsError::Canceled)
            || behind.error().is_some()
            || jobs.error(ticket(6, 0, 9)).is_some()
            || other.error().is_some()
            || !jobs.retired(ticket(6, 1, 5))
        {
            return TestResult::Fail("queue reset failed the wrong jobs");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/fence-errors",
        rdna2_queue_reset_cancels_the_ring_behind_the_guilty_job
    );
    /// `amdgpu_vcn_reset_engine` force-completes every unsignalled fence of
    /// the reset instance's rings with `-ECANCELED`
    /// (`amdgpu_fence_driver_force_completion`), the timed-out job's
    /// included; nothing is re-emitted and no context is made guilty. The
    /// error stays with each cancelled job after its fence was forced (the
    /// memory retires), other rings are untouched, and the ring serves new
    /// jobs.
    fn rdna2_vcn_engine_reset_cancels_its_outstanding_jobs() -> TestResult {
        let mut jobs = Jobs::new(6);
        let tickets = [
            ticket(6, 0, 7), // GFX
            ticket(6, 4, 3), // VCN decode, the timed-out job
            ticket(6, 4, 4), // VCN decode, queued behind it
            ticket(6, 5, 9), // VCN encode 0
            ticket(6, 7, 2), // JPEG
        ];
        let health: Vec<Arc<Health>> = tickets.iter().map(|_| Arc::default()).collect();
        for (t, h) in tickets.iter().zip(&health) {
            jobs.emitted(*t, h);
        }
        jobs.cancel(4, 2, 4);
        jobs.cancel(5, 8, 9);
        let canceled = Some(FsError::Canceled);
        let errors: Vec<_> = tickets.iter().map(|t| jobs.error(*t)).collect();
        if errors != [None, canceled, canceled, canceled, None]
            || health[1..4].iter().any(|h| h.error() != canceled)
            || health[0].error().is_some()
            || health[4].error().is_some()
            || jobs.terminal.is_some()
        {
            return TestResult::Fail("an engine reset did not cancel exactly its outstanding jobs");
        }
        // The forced fences land: the memory retires, the errors remain.
        let mut completed = [0; RING_IDS];
        completed[4] = 4;
        completed[5] = 9;
        jobs.observe(completed);
        if !jobs.retired(tickets[1]) || jobs.error(tickets[1]) != canceled {
            return TestResult::Fail("a force-completed job lost its error");
        }
        // The reset ring takes and completes new work.
        jobs.emitted(ticket(6, 4, 5), &Arc::default());
        completed[4] = 5;
        jobs.observe(completed);
        if jobs.error(ticket(6, 4, 5)).is_some() || !jobs.retired(ticket(6, 4, 5)) {
            return TestResult::Fail("the reset ring does not serve new jobs");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi22-tdr/media",
        rdna2_vcn_engine_reset_cancels_its_outstanding_jobs
    );
    /// With no reset to follow, `amdgpu_job_timedout` sets `-ETIME` on the
    /// job's fence and suspends the timeout: the job stays outstanding
    /// (its waiter keeps waiting) and reports `-ETIME` only if its fence
    /// ever lands; its context's next submission fails
    /// (`drm_sched_entity_error`). Nothing else changes.
    fn rdna2_suspended_media_timeout_keeps_the_job_waiting() -> TestResult {
        let mut jobs = Jobs::new(6);
        let (late, other) = (ticket(6, 4, 3), ticket(6, 4, 4));
        let health = Arc::new(Health::default());
        jobs.emitted(late, &health);
        jobs.emitted(other, &Arc::default());
        jobs.time_out(4);
        if jobs.error(late).is_some()
            || jobs.error(other).is_some()
            || jobs.terminal.is_some()
            || health.error() != Some(FsError::TimedOut)
        {
            return TestResult::Fail("a suspended timeout ended or failed outstanding work");
        }
        let mut completed = [0; RING_IDS];
        completed[4] = 4;
        jobs.observe(completed);
        if jobs.error(late) != Some(FsError::TimedOut) || jobs.error(other).is_some() {
            return TestResult::Fail("a late fence did not report -ETIME on the timed-out job");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi22-tdr/media",
        rdna2_suspended_media_timeout_keeps_the_job_waiting
    );
    /// `amdgpu_fence_process` signals a job's fence when the engine's fence
    /// processing first sees its sequence written, and
    /// `dma_fence_signal_timestamp` records that instant: the job's
    /// `dma_fence.timestamp`, the same however late a client asks for it.
    /// A pending job has none; a ticket of another recovery epoch has none.
    fn rdna2_jobs_record_their_signal_time() -> TestResult {
        let mut jobs = Jobs::new(21);
        let (first, media) = (ticket(21, 0, 5), ticket(21, 4, 2));
        jobs.emitted(first, &Arc::default());
        jobs.emitted(media, &Arc::default());
        if jobs.signal_time(first).is_some() || jobs.signal_time(media).is_some() {
            return TestResult::Fail("a pending job has a signal time");
        }
        let mut completed = [0; RING_IDS];
        completed[0] = 5;
        let before = narf_time::wall::monotonic_ns();
        jobs.observe(completed);
        let after = narf_time::wall::monotonic_ns();
        let Some(at) = jobs.signal_time(first) else {
            return TestResult::Fail("a completed job has no signal time");
        };
        if at < before || at > after || jobs.signal_time(media).is_some() {
            return TestResult::Fail("the signal time is not the observation that completed it");
        }
        // Later samples neither move it nor stamp what they did not complete.
        jobs.observe(completed);
        completed[4] = 2;
        jobs.observe(completed);
        if jobs.signal_time(first) != Some(at)
            || jobs.signal_time(media).is_none_or(|media| media < at)
            || jobs.signal_time(ticket(20, 0, 5)).is_some()
        {
            return TestResult::Fail("signal times moved or crossed epochs");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/fence-time",
        rdna2_jobs_record_their_signal_time
    );
}
impl Jobs {
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            completed: [0; RING_IDS],
            terminal: None,
            pending: Vec::new(),
            failed: Vec::new(),
            cancelled: Vec::new(),
            timed_out: Vec::new(),
        }
    }
    pub fn retired(&self, ticket: u64) -> bool {
        let ring = (ticket >> 32) as u32;
        ring & !15 == ring_index(self.epoch, 0)
            && self
                .completed
                .get((ring & 15) as usize)
                .is_some_and(|&done| crate::amdgpu_fence_navi22::signaled(done, ticket as u32))
    }
    pub fn observe(&mut self, completed: [u32; RING_IDS]) {
        if self.terminal.is_some() {
            return;
        }
        self.completed = completed;
        let epoch = self.epoch;
        self.pending
            .retain(|(ticket, _, _)| !super::job_done(epoch, completed, *ticket));
    }
    pub fn emitted(&mut self, ticket: u64, health: &Arc<Health>) {
        self.emitted_on(ticket, health, 0);
    }
    /// [`Self::emitted`] for a job granted VMID `vmid`, which a soft recovery
    /// needs to name the waves it kills.
    pub fn emitted_on(&mut self, ticket: u64, health: &Arc<Health>, vmid: u8) {
        if self.terminal.is_some() {
            health.mark_canceled();
        }
        self.pending.push((ticket, health.clone(), vmid));
    }
    /// The oldest unfinished job on `ring` (the one a timeout blames) and
    /// its VMID.
    pub fn oldest(&self, ring: usize) -> Option<(u64, u8)> {
        self.pending
            .iter()
            .find(|(ticket, _, _)| ring_id(*ticket) == ring)
            .map(|(ticket, _, vmid)| (*ticket, *vmid))
    }
    /// A recovery freed the ring that `ticket`'s job stalled: that job fails
    /// with its context guilty (`TimedOut`), and nothing else does. The ring
    /// and every other job carry on.
    pub fn recovered(&mut self, ticket: u64) {
        if let Some((_, health, _)) = self.pending.iter().find(|(t, _, _)| *t == ticket) {
            health.mark_guilty();
        }
        self.fail(ticket, FsError::TimedOut);
    }
    /// A queue reset dropped every job on `ring`: `ticket`'s (the timed-out
    /// one) is [`Self::recovered`]'s, and the others fail `Canceled` with
    /// their contexts left usable. Linux re-emits those other contexts' work
    /// (`amdgpu_ring_reset_helper_end`); this does not. Record it before the
    /// ring's fences are forced, so no sample retires them as done.
    pub fn reset(&mut self, ring: usize, ticket: u64) {
        self.recovered(ticket);
        let behind: Vec<u64> = self
            .pending
            .iter()
            .map(|(t, _, _)| *t)
            .filter(|t| *t != ticket && ring_id(*t) == ring)
            .collect();
        for t in behind {
            self.fail(t, FsError::Canceled);
        }
    }
    fn fail(&mut self, ticket: u64, error: FsError) {
        if self.failed.len() == FAILED_KEPT {
            self.failed.remove(0);
        }
        self.failed.push((ticket, error));
    }
    pub fn finish(&mut self, error: FsError) {
        if self.terminal.is_none() || error == FsError::NoDevice {
            self.terminal = Some(error);
        }
        for (_, health, _) in &self.pending {
            health.mark_canceled();
        }
    }
    pub fn hang(&mut self, ring: usize) {
        if self.terminal.is_none() {
            self.mark_guilty(ring);
            self.finish(FsError::Canceled);
        }
    }
    /// The oldest pending job of ring `ring` timed out (`-ETIME`).
    fn mark_guilty(&mut self, ring: usize) {
        if let Some((_, health, _)) = self.pending.iter().find(|(t, _, _)| ring_id(*t) == ring) {
            health.mark_guilty();
        }
    }
    /// A VCN engine reset force-completed ring `ring`'s sequences after
    /// `after` up to `upto` (`amdgpu_fence_driver_force_completion`): those
    /// jobs end with `-ECANCELED`, the timed-out one included, and keep that
    /// error once their forced fences retire them. Their contexts' next
    /// submissions fail (`drm_sched_entity_error`); no context is guilty.
    pub fn cancel(&mut self, ring: usize, after: u32, upto: u32) {
        let epoch = self.epoch;
        for (ticket, health, _) in &self.pending {
            if forced(epoch, (ring, after, upto), *ticket) {
                health.mark_canceled();
            }
        }
        self.cancelled.push((ring, after, upto));
    }
    /// Ring `ring`'s oldest job timed out and nothing resets the ring
    /// (`amdgpu_job_timedout` without recovery: `-ETIME` on the job's fence,
    /// `drm_sched_suspend_timeout`). The job stays outstanding and reports
    /// `-ETIME` once its fence lands; its context's next submission fails.
    pub fn time_out(&mut self, ring: usize) {
        if let Some((ticket, health, _)) = self.pending.iter().find(|(t, _, _)| ring_id(*t) == ring)
        {
            health.mark_guilty();
            self.timed_out.push(*ticket);
        }
    }
    /// When job `ticket` was seen complete (`Submitter::signal_time`).
    pub fn signal_time(&self, ticket: u64) -> Option<u64> {
        let _ = ticket;
        None
    }
    pub fn error(&self, ticket: u64) -> Option<FsError> {
        if let Some(&(_, error)) = self.failed.iter().find(|(t, _)| *t == ticket) {
            return Some(error);
        }
        let epoch = self.epoch;
        if self.cancelled.iter().any(|&r| forced(epoch, r, ticket)) {
            return Some(FsError::Canceled);
        }
        if self.retired(ticket) {
            return self
                .timed_out
                .contains(&ticket)
                .then_some(FsError::TimedOut);
        }
        self.terminal.map(|error| {
            if error == FsError::Canceled {
                self.pending
                    .iter()
                    .find(|(t, _, _)| *t == ticket)
                    .and_then(|(_, h, _)| h.error())
                    .unwrap_or(error)
            } else {
                error
            }
        })
    }
}
