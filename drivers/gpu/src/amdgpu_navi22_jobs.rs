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
    pending: Vec<(u64, Arc<Health>)>,
    /// Ticket ring ids (bits) of a media engine that timed out
    /// (`fail_rings`): their unretired jobs fail, the other rings run on.
    failed: u16,
}

/// The ticket's ring id (the low four bits of its ring index).
fn ring_id(ticket: u64) -> usize {
    ((ticket >> 32) as u32 & 15) as usize
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
    /// `amdgpu_job_timedout` on a video ring: the timed-out job ends with
    /// ETIME (its context guilty) and the other jobs of that engine's rings
    /// with ECANCELED, while every other ring keeps running and retiring.
    /// Linux resets the VCN instance alone (`amdgpu_vcn_reset_engine`); a
    /// media timeout never fails graphics work.
    fn rdna2_media_timeout_fails_only_its_engines_rings() -> TestResult {
        let mut jobs = Jobs::new(4);
        let tickets = [
            ticket(4, 0, 7), // GFX
            ticket(4, 4, 3), // VCN decode, the timed-out job
            ticket(4, 4, 4), // VCN decode, queued behind it
            ticket(4, 5, 9), // VCN encode 0, same VCPU
            ticket(4, 7, 2), // JPEG
        ];
        let health: Vec<Arc<Health>> = tickets.iter().map(|_| Arc::default()).collect();
        for (t, h) in tickets.iter().zip(&health) {
            jobs.emitted(*t, h);
        }
        jobs.fail_rings(4, 0b111 << 4);
        let errors: Vec<_> = tickets.iter().map(|t| jobs.error(*t)).collect();
        if errors
            != [
                None,
                Some(FsError::TimedOut),
                Some(FsError::Canceled),
                Some(FsError::Canceled),
                None,
            ]
            || health[0].error().is_some()
            || health[4].error().is_some()
            || jobs.terminal.is_some()
        {
            return TestResult::Fail("a media timeout errors other than its engine's jobs");
        }
        let late = Arc::new(Health::default());
        jobs.emitted(ticket(4, 6, 1), &late);
        if late.error() != Some(FsError::Canceled) || jobs.error(ticket(4, 6, 1)).is_none() {
            return TestResult::Fail("a job published on a timed-out media ring runs");
        }
        let mut completed = [0; RING_IDS];
        completed[0] = 7;
        completed[7] = 2;
        jobs.observe(completed);
        if !jobs.retired(tickets[0]) || !jobs.retired(tickets[4]) || jobs.retired(tickets[1]) {
            return TestResult::Fail("other rings stop retiring after a media timeout");
        }
        jobs.finish(FsError::Canceled);
        if jobs.error(tickets[1]) != Some(FsError::TimedOut) {
            return TestResult::Fail("the timed-out media job lost its guilt");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi22-tdr/media",
        rdna2_media_timeout_fails_only_its_engines_rings
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
}
impl Jobs {
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            completed: [0; RING_IDS],
            terminal: None,
            pending: Vec::new(),
            failed: 0,
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
            .retain(|(ticket, _)| !super::job_done(epoch, completed, *ticket));
    }
    pub fn emitted(&mut self, ticket: u64, health: &Arc<Health>) {
        if self.terminal.is_some() || self.failed & 1 << ring_id(ticket) != 0 {
            health.mark_canceled();
        }
        self.pending.push((ticket, health.clone()));
    }
    pub fn finish(&mut self, error: FsError) {
        if self.terminal.is_none() || error == FsError::NoDevice {
            self.terminal = Some(error);
        }
        for (_, health) in &self.pending {
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
        if let Some((_, health)) = self.pending.iter().find(|(t, _)| ring_id(*t) == ring) {
            health.mark_guilty();
        }
    }
    /// A media engine's job on ring `hung` timed out (`amdgpu_job_timedout`
    /// on a video ring); `rings` (ticket ring-id bits) are every ring of that
    /// engine. The timed-out job ends with `-ETIME`, the other unretired
    /// jobs of those rings and any published there later with `-ECANCELED`,
    /// as Linux's VCN engine reset force-completes them. Other rings keep
    /// running; unconfirmed media memory stays quarantined until its own
    /// writeback retires it.
    pub fn fail_rings(&mut self, hung: usize, rings: u16) {
        if self.terminal.is_some() {
            return;
        }
        self.mark_guilty(hung);
        for (ticket, health) in &self.pending {
            if rings & 1 << ring_id(*ticket) != 0 {
                health.mark_canceled();
            }
        }
        self.failed |= rings;
    }
    /// A VCN engine reset force-completed ring `ring`'s sequences after
    /// `after` up to `upto` (`amdgpu_fence_driver_force_completion`).
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub fn cancel(&mut self, _ring: usize, _after: u32, _upto: u32) {}
    /// Ring `ring`'s oldest job timed out with no reset to follow
    /// (`drm_sched_suspend_timeout`).
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub fn time_out(&mut self, _ring: usize) {}
    pub fn error(&self, ticket: u64) -> Option<FsError> {
        if self.retired(ticket) {
            return None;
        }
        let failed = (self.failed & 1 << ring_id(ticket) != 0).then_some(FsError::Canceled);
        self.terminal.or(failed).map(|error| {
            if error == FsError::Canceled {
                self.pending
                    .iter()
                    .find(|(t, _)| *t == ticket)
                    .and_then(|(_, h)| h.error())
                    .unwrap_or(error)
            } else {
                error
            }
        })
    }
}
