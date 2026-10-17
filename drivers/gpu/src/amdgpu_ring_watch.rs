//! Job timeouts on an in-order ring — drm_sched's timeout handler and
//! `amdgpu_job_timedout`.
//!
//! A [`RingWatch`] follows one ring's submitted jobs. The job at the front
//! has its timeout counted from the moment it got there (drm_sched re-arms
//! its timer whenever the oldest job completes), and once it has been there
//! longer than [`JOB_TIMEOUT_NS`] the ring is hung: that job ends with
//! `TimedOut` (`-ETIME`) and its context becomes guilty; every job queued
//! behind it ends with `Canceled` (`-ECANCELED`) and its context records
//! that. A hung ring takes no new jobs until it is recovered.
//!
//! An error ends a job for its waiters only. What the job may still touch
//! — its buffers, page tables and VMID — is released by the hardware fence
//! alone, so memory never returns while a hung engine could reach it.
//!
//! LINUX-GAP: Linux resets the ring (through MES on GFX12) and re-runs the
//! innocent jobs; until that exists here a hung ring stays hung.

use alloc::collections::VecDeque;
use alloc::sync::Arc;

use narf_filesystem::FsError;

use crate::amdgpu_ctx::Health;

/// amdgpu's default lockup timeout (`amdgpu_lockup_timeout`), the same for
/// graphics, compute and SDMA rings.
pub const JOB_TIMEOUT_NS: u64 = 2_000_000_000;

/// Whether sequence `seq` is at or before `completed` (32-bit sequences
/// wrap).
fn reached(completed: u32, seq: u32) -> bool {
    completed.wrapping_sub(seq) as i32 >= 0
}

/// One ring's jobs in flight and whether it hung.
#[derive(Debug, Default)]
pub struct RingWatch {
    /// Submitted, not yet seen complete, oldest first.
    pending: VecDeque<(u32, Arc<Health>)>,
    /// When the front job became the front, in monotonic ns.
    front_since: u64,
    /// The job that hung the ring, once it has.
    hung: Option<u32>,
}

impl RingWatch {
    pub const fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            front_since: 0,
            hung: None,
        }
    }

    /// Whether new jobs must be refused (`Canceled`), as the ring hung.
    pub fn refusing(&self) -> Option<FsError> {
        self.hung.map(|_| FsError::Canceled)
    }

    /// Job `seq` of a context with `health` went onto the ring at `now`.
    pub fn submitted(&mut self, seq: u32, health: Arc<Health>, now: u64) {
        if self.pending.is_empty() {
            self.front_since = now;
        }
        self.pending.push_back((seq, health));
    }

    /// Whether any job is still in flight.
    pub fn busy(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Forget the jobs up to `completed`; if the front job has now been
    /// there past the timeout, hang the ring and return that job.
    pub fn check(&mut self, completed: u32, now: u64) -> Option<u32> {
        let front = self.pending.front().map(|(seq, _)| *seq);
        while self
            .pending
            .front()
            .is_some_and(|(seq, _)| reached(completed, *seq))
        {
            self.pending.pop_front();
        }
        let (seq, health) = self.pending.front()?;
        if front != Some(*seq) {
            self.front_since = now;
            return None;
        }
        if self.hung.is_some() || now.saturating_sub(self.front_since) <= JOB_TIMEOUT_NS {
            return None;
        }
        health.mark_guilty();
        for (_, behind) in self.pending.iter().skip(1) {
            behind.mark_canceled();
        }
        self.hung = Some(*seq);
        self.hung
    }

    /// How job `seq` ended, if it did not complete normally: the job that
    /// hung the ring timed out, and each later one that has not completed
    /// was canceled.
    pub fn error(&self, seq: u32, completed: u32) -> Option<FsError> {
        let hung = self.hung?;
        if seq == hung {
            Some(FsError::TimedOut)
        } else if seq.wrapping_sub(hung) as i32 > 0 && !reached(completed, seq) {
            Some(FsError::Canceled)
        } else {
            None
        }
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const S: u64 = 1_000_000_000;

    /// The front job times out counted from when it reached the front; it
    /// is guilty, the jobs behind it canceled, and the ring refuses more.
    fn ring_watch_times_out_the_front_job() -> TestResult {
        let (a, b, c) = (
            Arc::new(Health::default()),
            Arc::new(Health::default()),
            Arc::new(Health::default()),
        );
        let mut w = RingWatch::new();
        if w.check(0, 0).is_some() || w.busy() {
            return TestResult::Fail("idle ring hung");
        }
        // Sequences straddle the 32-bit wrap.
        w.submitted(u32::MAX, a.clone(), 0);
        w.submitted(0, b.clone(), S);
        w.submitted(1, c.clone(), S);
        if w.check(u32::MAX - 1, JOB_TIMEOUT_NS).is_some() {
            return TestResult::Fail("hung at exactly the timeout");
        }
        // The first job completes late; the second's clock starts now.
        if w.check(u32::MAX, 3 * S).is_some()
            || w.check(u32::MAX, 3 * S + JOB_TIMEOUT_NS).is_some()
            || w.error(0, u32::MAX).is_some()
        {
            return TestResult::Fail("timeout not counted from reaching the front");
        }
        if w.check(u32::MAX, 3 * S + JOB_TIMEOUT_NS + 1) != Some(0) {
            return TestResult::Fail("front job past its timeout did not hang");
        }
        if a.error().is_some()
            || b.error() != Some(FsError::TimedOut)
            || c.error() != Some(FsError::Canceled)
        {
            return TestResult::Fail("context health after a hang");
        }
        if w.error(u32::MAX, u32::MAX).is_some()
            || w.error(0, u32::MAX) != Some(FsError::TimedOut)
            || w.error(1, u32::MAX) != Some(FsError::Canceled)
            || w.refusing() != Some(FsError::Canceled)
        {
            return TestResult::Fail("job errors after a hang");
        }
        // A hang is reported once, and the guilty job keeps its error even
        // if it finally completes; a canceled job that completes does not.
        if w.check(1, 10 * S).is_some()
            || w.error(0, 1) != Some(FsError::TimedOut)
            || w.error(1, 1).is_some()
            || w.busy()
        {
            return TestResult::Fail("errors after the hung jobs completed");
        }
        // Guilt is not downgraded by a later cancellation.
        b.mark_canceled();
        if b.error() != Some(FsError::TimedOut) {
            return TestResult::Fail("guilt downgraded");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu_cs", ring_watch_times_out_the_front_job);
}
