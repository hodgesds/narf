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
        // The CS ABI reserves handle zero for no job, including GFX ring 0.
        self.issued = self.issued.wrapping_add(1).max(1);
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
    /// Freeze even an idle ring before a coordinated reset. A dropped
    /// recovery keeps every ring closed and every pending allocation pinned.
    pub(crate) fn freeze(&mut self) {
        self.hung = true;
    }
    pub(crate) fn reset_vmid(&self) -> u8 {
        self.pending.front().map_or(0, |p| p.job.vmid)
    }
    /// Late vectors/latches can identify more contexts while reset is in
    /// progress. Apply the complete scope before choosing any replay jobs.
    pub(crate) fn faulted(
        &mut self,
        scope: crate::amdgpu_navi48_faults::RecoveryScope,
        ring: usize,
        hub: crate::amdgpu_navi48_faults::Hub,
    ) {
        assert!(self.hung);
        for p in &self.pending {
            if scope.guilty(p.job.pasid) {
                p.health.mark_guilty();
            } else if scope.queues & (1 << ring) != 0 || scope.unattributed(hub, p.job.vmid) {
                // A queue fault without a trustworthy client VMID cannot
                // prove which pending context was guilty.
                p.health.mark_canceled();
            }
        }
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
        Job::new(vmid, u16::from(vmid), 0x1000, &[(0x2000, 4)]).unwrap()
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
    fn ring_watch_ticket_wrap_skips_zero_without_completing_early() -> TestResult {
        let mut w = RingWatch::new();
        w.issued = u32::MAX - 1;
        w.completed = u32::MAX - 1;
        let last = w.submitted(u32::MAX, job(1), Arc::new(Health::default()), 0);
        let next = w.submitted(0, job(2), Arc::new(Health::default()), 0);
        assert_eq!(last, u32::MAX);
        assert_eq!(next, 1);
        assert_eq!(w.progress(u32::MAX - 1, 1), u32::MAX - 1);
        assert_eq!(w.progress(u32::MAX, 2), last);
        assert!(w.busy());
        assert_eq!(w.progress(0, 3), next);
        assert!(!w.busy());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu_cs",
        ring_watch_ticket_wrap_skips_zero_without_completing_early
    );
    fn ring_watch_late_pasid_fault_does_not_blame_reused_or_other_hub_vmid() -> TestResult {
        use crate::amdgpu_navi48_faults::{Hub, RecoveryScope};
        for case in 0..4 {
            let a = Arc::new(Health::default());
            let b = Arc::new(Health::default());
            let c = Arc::new(Health::default());
            let mut rings = [const { RingWatch::new() }; 4];
            for (ring, (vmid, pasid, health)) in [
                (5, 11, a.clone()),
                (5, 22, b.clone()), // reused GFX VMID, new address space
                (2, 11, a.clone()), // same PASID on a different VMID
                (5, 33, c.clone()), // independent MMHUB VMID 5
            ]
            .into_iter()
            .enumerate()
            {
                let job = Job::new(vmid, pasid, 0x1000, &[(0x2000, 4)]).unwrap();
                rings[ring].submitted(10, job, health, 0);
                rings[ring].freeze();
            }
            let mut scope = RecoveryScope {
                vmids: 1 << 5,
                ..Default::default()
            };
            scope.pasids[0] = 11;
            match case {
                1 => scope.unattributed_vmids[0] = 1 << 5,
                2 => scope.unattributed_vmids[1] = 1 << 5,
                3 => scope.queues = 1 << 1,
                _ => {}
            }
            for (ring, w) in rings.iter_mut().enumerate() {
                w.faulted(scope, ring, if ring == 3 { Hub::Mm } else { Hub::Gfx });
            }
            assert_eq!(a.error(), Some(FsError::TimedOut));
            assert_eq!(
                b.error(),
                matches!(case, 1 | 3).then_some(FsError::Canceled)
            );
            assert_eq!(c.error(), (case == 2).then_some(FsError::Canceled));
            assert!(rings[0].replay().is_empty());
            assert!(rings[2].replay().is_empty());
            assert_eq!(rings[1].replay().len(), usize::from(!matches!(case, 1 | 3)));
            assert_eq!(rings[3].replay().len(), usize::from(case != 2));
            for w in &mut rings {
                assert_eq!(w.progress(100, 1), 0); // no premature retirement
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu_cs",
        ring_watch_late_pasid_fault_does_not_blame_reused_or_other_hub_vmid
    );
    fn ring_watch_coordinated_fault_recovery_pins_every_ring_until_replay() -> TestResult {
        let guilty = Arc::new(Health::default());
        let healthy = Arc::new(Health::default());
        let mut rings = [const { RingWatch::new() }; 3];
        for w in &mut rings {
            w.submitted(10, job(1), guilty.clone(), 0);
            w.submitted(11, job(2), healthy.clone(), 0);
            w.freeze();
        }
        let refs = Arc::strong_count(&healthy);
        for w in &mut rings {
            assert_eq!(w.progress(99, 1), 0); // reset fence passed all old work
            assert!(w.refusing().is_some());
        }
        let scope = crate::amdgpu_navi48_faults::RecoveryScope {
            vmids: 1 << 1,
            pasids: core::array::from_fn(|i| if i == 0 { 1 } else { 0 }),
            ..Default::default()
        };
        for (ring, w) in rings.iter_mut().enumerate() {
            w.faulted(scope, ring, crate::amdgpu_navi48_faults::Hub::Gfx);
        }
        assert_eq!(guilty.error(), Some(FsError::TimedOut));
        assert_eq!(healthy.error(), None);
        for (ring, w) in rings.iter_mut().enumerate() {
            let jobs = w.replay();
            assert_eq!(jobs.len(), 1);
            let (ticket, job) = jobs[0];
            assert_eq!(ticket, 2);
            assert!(job.flush && job.map_pasid && job.ctx_switch);
            w.replayed(ticket, 100 + ring as u32);
        }
        // Cancellation or a later ring's error before the collective commit
        // must retain every allocation, including already-replayed jobs.
        for w in &mut rings {
            assert_eq!(w.progress(200, 2), 0);
        }
        assert_eq!(Arc::strong_count(&healthy), refs);
        for w in &mut rings {
            w.recovered(3);
        }
        for (ring, w) in rings.iter_mut().enumerate() {
            assert_eq!(w.progress(99, 4), 1);
            assert_eq!(w.error(1), Some(FsError::Canceled));
            assert_eq!(w.progress(100 + ring as u32, 5), 2);
            assert!(w.error(2).is_none());
        }
        assert_eq!(Arc::strong_count(&healthy), 1);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu_cs",
        ring_watch_coordinated_fault_recovery_pins_every_ring_until_replay
    );
}
