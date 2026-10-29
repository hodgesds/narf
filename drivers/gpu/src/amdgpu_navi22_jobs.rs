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
}
impl Jobs {
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            completed: [0; RING_IDS],
            terminal: None,
            pending: Vec::new(),
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
        if self.terminal.is_some() {
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
            if let Some((_, health)) = self
                .pending
                .iter()
                .find(|(ticket, _)| (*ticket >> 32) as u32 & 15 == ring as u32)
            {
                health.mark_guilty();
            }
            self.finish(FsError::Canceled);
        }
    }
    pub fn error(&self, ticket: u64) -> Option<FsError> {
        if self.retired(ticket) {
            return None;
        }
        self.terminal.map(|error| {
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
