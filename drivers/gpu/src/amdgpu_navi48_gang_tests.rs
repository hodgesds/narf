use super::*;
use alloc::{boxed::Box, vec};
use core::{future::Future, pin::Pin};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Routes;
impl Engine for Routes {
    fn ring_for(&self, ip: u32, instance: u32, ring: u32) -> Option<u32> {
        if instance != 0 || ring != 0 {
            return None;
        }
        match ip {
            0 => Some(0),
            1 => Some(1),
            2 => Some(2),
            7 => Some(MEDIA_RING),
            8 => Some(JPEG_RING),
            _ => None,
        }
    }
    fn submit<'a>(
        &'a self,
        _: &'a crate::amdgpu_vm::VmState,
        _: &'a Submission,
        _: &'a Arc<Health>,
    ) -> Pin<Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn signalled(&self, _: u64) -> bool {
        false
    }
    fn wait(
        &self,
        _: u64,
        _: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>> {
        Box::pin(async { Ok(false) })
    }
}
fn submission(ips: &[u32]) -> Submission {
    Submission {
        ctx_id: 1,
        ibs: ips
            .iter()
            .enumerate()
            .map(|(i, &ip_type)| Ib {
                va_start: 0x10000 + i as u64 * 0x1000,
                length_dw: 8,
                ip_type,
                ip_instance: 0,
                ring: 0,
                flags: 0,
            })
            .collect(),
        in_syncobjs: Vec::new(),
        out_syncobjs: Vec::new(),
        bo_handles: None,
        dependencies: Vec::new(),
        user_fence: None,
    }
}
fn navi4_gang_groups_by_entity_and_last_ib_selects_leader() -> TestResult {
    for (ips, leader) in [(vec![1, 0, 1, 0], 0), (vec![0, 1, 0, 1], 1)] {
        let request = submission(&ips);
        let pair = plan(&Routes, &request).unwrap().unwrap();
        assert_eq!(pair.leader, leader);
        for ring in 0..2 {
            assert_eq!(
                pair.ibs[ring],
                request
                    .ibs
                    .iter()
                    .filter(|ib| ib.ip_type == ring as u32)
                    .copied()
                    .collect::<Vec<_>>()
            );
        }
    }
    assert!(plan(&Routes, &submission(&[0, 0])).unwrap().is_none());
    assert!(plan(&Routes, &submission(&[1, 1])).unwrap().is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi4_gang_groups_by_entity_and_last_ib_selects_leader
);
fn navi4_gang_limits_are_per_entity_and_other_engines_stay_refused() -> TestResult {
    let mut ips = vec![0; 8];
    ips.extend(vec![1; 8]);
    assert!(plan(&Routes, &submission(&ips)).unwrap().is_some());
    ips.push(1);
    assert_eq!(
        plan(&Routes, &submission(&ips)).err(),
        Some(FsError::Unsupported)
    );
    for ips in [&[0, 2][..], &[1, 7][..], &[0, 1, 2][..], &[99, 0][..]] {
        assert_eq!(
            plan(&Routes, &submission(ips)).err(),
            Some(FsError::Unsupported)
        );
    }
    let mut bad = submission(&[0, 1]);
    bad.ibs[1].ip_instance = 1;
    assert_eq!(plan(&Routes, &bad).err(), Some(FsError::Unsupported));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi4_gang_limits_are_per_entity_and_other_engines_stay_refused
);
fn navi4_gang_leader_fence_waits_for_all_members_and_preserves_context_order() -> TestResult {
    let mut ledger = Ledger::new();
    ledger.reserve().unwrap();
    ledger.push([7, (1 << 32) | 3], 0);
    let mut completed = [0; RINGS];
    completed[0] = 8;
    completed[1] = 2;
    assert!(!ledger.done(completed, 7));
    assert!(
        !ledger.done(completed, 8),
        "later leader context cannot hide outstanding READ follower"
    );
    assert!(ledger.done(completed, 6));
    ledger.retire(completed);
    assert!(ledger.busy());
    assert_eq!(
        ledger.error(7, |t| (t == ((1 << 32) | 3)).then_some(FsError::Canceled)),
        Some(FsError::Canceled)
    );
    completed[1] = 3;
    assert!(ledger.done(completed, 7));
    assert!(ledger.done(completed, 8));
    ledger.retire(completed);
    assert!(!ledger.busy());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi4_gang_leader_fence_waits_for_all_members_and_preserves_context_order
);
fn navi4_gang_wrap_and_reverse_leader_keep_follower_lifetimes() -> TestResult {
    let mut ledger = Ledger::new();
    ledger.reserve().unwrap();
    ledger.push([0xffff_fffe, (1 << 32) | 9], 0);
    let mut completed = [0; RINGS];
    completed[0] = 1;
    completed[1] = 8;
    assert!(!ledger.done(completed, 1));
    completed[1] = 9;
    assert!(ledger.done(completed, 1));
    ledger.retire(completed);
    ledger.reserve().unwrap();
    ledger.push([4, (1 << 32) | 11], 1);
    completed[0] = 3;
    completed[1] = 12;
    assert!(!ledger.done(completed, (1 << 32) | 11));
    assert!(!ledger.done(completed, (1 << 32) | 12));
    completed[0] = 4;
    assert!(ledger.done(completed, (1 << 32) | 12));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi4_gang_wrap_and_reverse_leader_keep_follower_lifetimes
);

fn navi4_gang_shared_resources_retire_only_after_both_physical_fences() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};
    struct Held(Arc<AtomicU32>);
    impl Drop for Held {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    const CARD: u32 = 0xfeed_0710;
    let count = Arc::new(AtomicU32::new(0));
    let mut ledger = Ledger::new();
    ledger.reserve().unwrap();
    ledger.push([7, (1 << 32) | 3], 0);
    crate::amdgpu_cs::defer_until(CARD, vec![7], Box::new(Held(count.clone())));
    let mut completed = [0; RINGS];
    completed[0] = 7;
    completed[1] = 2;
    crate::amdgpu_cs::retire(CARD, &|t| ledger.done(completed, t));
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "leader alone cannot release BO/PTE leases"
    );
    completed[1] = 3;
    crate::amdgpu_cs::retire(CARD, &|t| ledger.done(completed, t));
    assert_eq!(count.load(Ordering::SeqCst), 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi4_gang_shared_resources_retire_only_after_both_physical_fences
);
fn navi4_gang_reset_remembers_completed_leader_errors_and_never_replays_peer() -> TestResult {
    let mut watches = [const { crate::amdgpu_ring_watch::RingWatch::new() }; RINGS];
    let health = Arc::new(Health::default());
    let job = queues::Job::new(1, 0x44, 0x1234_0007, &[(0x10000, 8)]).unwrap();
    let mut tickets = [0; 2];
    for i in 0..2 {
        watches[i].reserve_errors(2).unwrap();
        watches[i].reserve_submission().unwrap();
        tickets[i] = (i as u64) << 32 | u64::from(watches[i].submitted(1, job, health.clone(), 0));
    }
    let mut ledger = Ledger::new();
    ledger.reserve().unwrap();
    ledger.push(tickets, 0);
    assert_eq!(watches[0].progress(1, 1), 1); // leader already left pending
    ledger.stop(&mut watches);
    assert_eq!(watches[0].error(tickets[0] as u32), Some(FsError::Canceled));
    assert_eq!(watches[1].error(tickets[1] as u32), Some(FsError::Canceled));
    assert!(watches[0].replay().is_empty());
    assert!(watches[1].replay().is_empty());
    let successors = core::array::from_fn::<_, RINGS, _>(|i| watches[i].successor());
    assert_eq!(
        successors[0].error(tickets[0] as u32),
        Some(FsError::Canceled)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi4_gang_reset_remembers_completed_leader_errors_and_never_replays_peer
);

fn navi4_gang_follower_error_survives_aggregate_metadata_retirement() -> TestResult {
    let mut watches = [const { crate::amdgpu_ring_watch::RingWatch::new() }; RINGS];
    let health = Arc::new(Health::default());
    let job = queues::Job::new(1, 0x45, 0x1234_0007, &[(0x10000, 8)]).unwrap();
    for watch in &mut watches[..2] {
        watch.reserve_errors(2).unwrap();
        watch.reserve_submission().unwrap();
        watch.submitted(1, job, health.clone(), 0);
        watch.progress(1, 1);
    }
    let mut ledger = Ledger::new();
    ledger.reserve().unwrap();
    ledger.push([1, (1 << 32) | 1], 0);
    watches[1].fail_ticket(1, FsError::TimedOut);
    ledger.preserve_errors(&mut watches);
    let mut completed = [0; RINGS];
    completed[0] = 1;
    completed[1] = 1;
    ledger.retire(completed);
    assert!(!ledger.busy());
    assert_eq!(watches[0].error(1), Some(FsError::TimedOut));
    assert_eq!(watches[0].successor().error(1), Some(FsError::TimedOut));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi4_gang_follower_error_survives_aggregate_metadata_retirement
);

fn navi4_gang_unrelated_relocation_does_not_retire_error_signals() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};
    struct Aborted;
    impl Engine for Aborted {
        fn ring_for(&self, ip: u32, instance: u32, ring: u32) -> Option<u32> {
            Routes.ring_for(ip, instance, ring)
        }
        fn submit<'a>(
            &'a self,
            _: &'a crate::amdgpu_vm::VmState,
            _: &'a Submission,
            _: &'a Arc<Health>,
        ) -> Pin<Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>> {
            Box::pin(async { Err(FsError::Unsupported) })
        }
        fn signalled(&self, _: u64) -> bool {
            true
        }
        fn error(&self, _: u64) -> Option<FsError> {
            Some(FsError::Canceled)
        }
        fn wait(
            &self,
            _: u64,
            _: u64,
        ) -> Pin<Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>> {
            Box::pin(async { Ok(true) })
        }
    }
    struct Held(Arc<AtomicU32>);
    impl Drop for Held {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    const CARD: u32 = 0xfeed_0711;
    let count = Arc::new(AtomicU32::new(0));
    let engine: Arc<dyn Engine> = Arc::new(Aborted);
    assert!(engine.signalled(7));
    assert!(!engine.retired(7));
    crate::amdgpu_cs::register_submitter(CARD, engine);
    crate::amdgpu_cs::defer_until(CARD, vec![7], Box::new(Held(count.clone())));
    let gate = narf_scheduler::block_on_spin(crate::amdgpu_gem::lock_placement_live(CARD)).unwrap();
    let gem = crate::amdgpu_gem::GemState::for_card(CARD);
    let (_, object) = gem.create_kernel_system(4096, &gate).unwrap();
    // This GTT-only target has no jobs. Relocation reaches the card-wide
    // deferred reap before refusing its disallowed VRAM placement.
    assert_eq!(
        narf_scheduler::block_on_spin(crate::amdgpu_vm::relocate(&gate, &object, true)),
        Err(FsError::Busy)
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "unrelated BO promotion freed uncertain GPU references"
    );
    // Explicit stopped-model receipt, standing in for proved whole reset.
    crate::amdgpu_cs::retire(CARD, &|_| true);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    crate::amdgpu_cs::unregister_submitter(CARD);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi4_gang_unrelated_relocation_does_not_retire_error_signals
);
