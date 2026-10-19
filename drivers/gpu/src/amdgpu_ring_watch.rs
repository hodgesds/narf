//! In-order client tickets, hardware fence translation and timeout recovery.
//!
//! Tickets survive ring resets. A reset test fence must never complete an
//! innocent job: retirement freezes before reset, then each retained job is
//! assigned its replay's hardware sequence. Buffers and VMIDs remain pinned
//! until the translated fence passes. The guilty context is never replayed.

use crate::{amdgpu_ctx::Health, amdgpu_gfx12_queue::Job};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use narf_filesystem::FsError;

pub const JOB_TIMEOUT_NS: u64 = 2_000_000_000;
fn reached(completed: u32, seq: u32) -> bool {
    completed.wrapping_sub(seq) as i32 >= 0
}

#[derive(Debug)]
struct Pending {
    ticket: u32,
    physical: Option<u32>,
    skipped: bool,
    job: Job,
    health: Arc<Health>,
}

/// Serialized with queue submission by the platform owner. Synchronous fence
/// readers may call `progress`; a hung ring stays frozen through reset/replay.
#[derive(Debug, Default)]
pub struct RingWatch {
    pending: VecDeque<Pending>,
    issued: u32,
    completed: u32,
    front_since: u64,
    hung: bool,
    /// Errors must survive subsequent recoveries and old dma-fence readers.
    failed: Vec<(u32, FsError)>,
}
impl RingWatch {
    pub const fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            issued: 0,
            completed: 0,
            front_since: 0,
            hung: false,
            failed: Vec::new(),
        }
    }
    pub fn refusing(&self) -> Option<FsError> {
        self.hung.then_some(FsError::Canceled)
    }
    /// Publish a submitted descriptor and return its stable client ticket.
    pub fn submitted(&mut self, physical: u32, job: Job, health: Arc<Health>, now: u64) -> u32 {
        if self.pending.is_empty() {
            self.front_since = now;
        }
        self.issued = self.issued.wrapping_add(1);
        // A ticket's prior incarnation has aged out after a full 32-bit wrap.
        self.failed.retain(|(t, _)| *t != self.issued);
        self.pending.push_back(Pending {
            ticket: self.issued,
            physical: Some(physical),
            skipped: false,
            job,
            health,
        });
        self.issued
    }
    pub fn busy(&self) -> bool {
        !self.pending.is_empty()
    }
    /// Translate only proven hardware completions, never a reset test fence.
    pub fn progress(&mut self, physical: u32, now: u64) -> u32 {
        if !self.hung {
            let mut advanced = false;
            while self
                .pending
                .front()
                .is_some_and(|p| p.skipped || p.physical.is_some_and(|s| reached(physical, s)))
            {
                self.completed = self.pending.pop_front().unwrap().ticket;
                advanced = true;
            }
            if advanced {
                self.front_since = now;
            }
        }
        self.completed
    }
    /// The caller already translated physical progress. Freeze retirement
    /// before the first reset write and identify the front job's VMID.
    pub fn check(&mut self, now: u64) -> Option<(u32, u8)> {
        let p = self.pending.front()?;
        if self.hung || now.saturating_sub(self.front_since) <= JOB_TIMEOUT_NS {
            return None;
        }
        p.health.mark_guilty();
        self.failed.push((p.ticket, FsError::TimedOut));
        self.hung = true;
        Some((p.ticket, p.job.vmid))
    }
    /// A successful reset test proved old slots no longer execute. Keep
    /// retirement frozen while replay descriptors are published. Other jobs
    /// in any guilty/canceled context are abandoned; healthy jobs keep tickets.
    pub fn replay(&mut self) -> Vec<(u32, Job)> {
        assert!(self.hung);
        let mut replay = Vec::new();
        for p in &mut self.pending {
            p.physical = None;
            p.skipped = p.health.error().is_some();
            if p.skipped {
                if !self.failed.iter().any(|(t, _)| *t == p.ticket) {
                    self.failed.push((p.ticket, FsError::Canceled));
                }
            } else {
                let mut job = p.job;
                job.flush = true;
                job.map_pasid = true;
                job.ctx_switch = true;
                replay.push((p.ticket, job));
            }
        }
        replay
    }
    pub fn replayed(&mut self, ticket: u32, physical: u32) {
        assert!(self.hung);
        let p = self
            .pending
            .iter_mut()
            .find(|p| p.ticket == ticket)
            .unwrap();
        assert!(!p.skipped && p.physical.is_none());
        p.physical = Some(physical);
    }
    /// Every innocent job has its new fence. Cancellation/failure before
    /// this point leaves all memory retained and new submissions refused.
    pub fn recovered(&mut self, now: u64) {
        assert!(self
            .pending
            .iter()
            .all(|p| p.skipped || p.physical.is_some()));
        self.front_since = now;
        self.hung = false;
    }
    /// Terminal to old waiters, without granting permission to retire memory.
    pub(crate) fn stop(&mut self) {
        self.hung = true;
        for p in &self.pending {
            p.health.mark_canceled();
            if !self.failed.iter().any(|(t, _)| *t == p.ticket) {
                self.failed.push((p.ticket, FsError::Canceled));
            }
        }
    }
    /// Only after full reset proved old jobs cannot execute. Preserve ticket
    /// numbering and errors across the new hardware's fence sequence zero.
    pub(crate) fn successor(&self) -> Self {
        Self {
            issued: self.issued,
            completed: self.issued,
            failed: self.failed.clone(),
            ..Self::new()
        }
    }
    pub fn error(&self, ticket: u32) -> Option<FsError> {
        self.failed
            .iter()
            .find(|(t, _)| *t == ticket)
            .map(|(_, e)| *e)
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn job(vmid: u8) -> Job {
        Job::new(vmid, 1, 0x1000, &[(0x2000, 4)]).unwrap()
    }
    fn ring_watch_replay_preserves_tickets_and_memory() -> TestResult {
        let a = Arc::new(Health::default());
        let b = Arc::new(Health::default());
        let mut w = RingWatch::new();
        w.issued = u32::MAX - 1;
        w.completed = u32::MAX - 1;
        let guilty = w.submitted(u32::MAX, job(1), a.clone(), 0);
        let innocent = w.submitted(0, job(2), b.clone(), 0);
        let same_context = w.submitted(1, job(1), a.clone(), 0);
        if w.progress(u32::MAX - 1, 0) != u32::MAX - 1
            || w.check(JOB_TIMEOUT_NS).is_some()
            || w.check(JOB_TIMEOUT_NS + 1) != Some((guilty, 1))
            || w.error(guilty) != Some(FsError::TimedOut)
            || b.error().is_some()
        {
            return TestResult::Fail("timeout blamed an innocent context");
        }
        // Reset test fence 2 passed every old slot. It must release nothing.
        if w.progress(2, JOB_TIMEOUT_NS + 2) != u32::MAX - 1 {
            return TestResult::Fail("test fence retired replay memory");
        }
        let replay = w.replay();
        if replay.len() != 1
            || replay[0].0 != innocent
            || !replay[0].1.flush
            || !replay[0].1.map_pasid
            || !replay[0].1.ctx_switch
            || w.error(same_context) != Some(FsError::Canceled)
        {
            return TestResult::Fail("replay did not exclude guilty context or restore VM state");
        }
        w.replayed(innocent, 3);
        if w.progress(3, JOB_TIMEOUT_NS + 3) != u32::MAX - 1 || w.refusing().is_none() {
            return TestResult::Fail("incomplete recovery released jobs");
        }
        w.recovered(JOB_TIMEOUT_NS + 4);
        if w.progress(2, JOB_TIMEOUT_NS + 5) != guilty
            || w.error(innocent).is_some()
            || w.progress(3, JOB_TIMEOUT_NS + 6) != same_context
            || w.busy()
        {
            return TestResult::Fail("logical completion did not follow replay fence");
        }
        let c = Arc::new(Health::default());
        let next = w.submitted(4, job(3), c, 10 * JOB_TIMEOUT_NS);
        if w.check(11 * JOB_TIMEOUT_NS + 1) != Some((next, 3))
            || w.error(guilty) != Some(FsError::TimedOut)
            || b.error().is_some()
        {
            return TestResult::Fail("second hang lost old errors or blamed innocent context");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu_cs",
        ring_watch_replay_preserves_tickets_and_memory
    );
    fn ring_watch_full_reset_preserves_ticket_namespace() -> TestResult {
        let health = Arc::new(Health::default());
        let mut old = RingWatch::new();
        let ticket = old.submitted(97, job(1), health.clone(), 0);
        old.stop();
        if old.progress(100, 1) != 0
            || old.error(ticket) != Some(FsError::Canceled)
            || health.error() != Some(FsError::Canceled)
        {
            return TestResult::Fail("reset cancellation retired memory or lost errors");
        }
        let mut new = old.successor();
        let next = new.submitted(1, job(2), Arc::new(Health::default()), 0);
        if next != ticket + 1
            || new.progress(0, 1) != ticket
            || new.error(ticket) != Some(FsError::Canceled)
            || new.progress(1, 2) != next
        {
            return TestResult::Fail("new hardware fences collided with old tickets");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu_cs",
        ring_watch_full_reset_preserves_ticket_namespace
    );
    fn ring_watch_front_timeout_rearms_on_completion() -> TestResult {
        let mut w = RingWatch::new();
        w.submitted(10, job(1), Arc::new(Health::default()), 0);
        let second = w.submitted(11, job(2), Arc::new(Health::default()), 1);
        if w.progress(10, JOB_TIMEOUT_NS + 1) != 1
            || w.check(2 * JOB_TIMEOUT_NS).is_some()
            || w.check(2 * JOB_TIMEOUT_NS + 2) != Some((second, 2))
        {
            return TestResult::Fail("front job did not receive its own timeout");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu_cs",
        ring_watch_front_timeout_rearms_on_completion
    );
}
