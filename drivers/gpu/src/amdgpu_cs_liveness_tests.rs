use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
struct Faults {
    ring: u32,
    ready: AtomicBool,
    error: AtomicU8,
}
impl Submitter for Faults {
    fn submit<'a>(
        &'a self,
        _: &'a VmState,
        _: &'a Submission,
        _: &'a Arc<crate::amdgpu_ctx::Health>,
    ) -> Pin<Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn signalled(&self, _: u64) -> bool {
        self.ready.load(Ordering::Acquire)
    }
    fn retired(&self, _: u64) -> bool {
        false
    }
    fn error(&self, _: u64) -> Option<FsError> {
        match self.error.load(Ordering::Acquire) {
            1 => Some(FsError::Canceled),
            2 => Some(FsError::TimedOut),
            3 => Some(FsError::NoDevice),
            _ => None,
        }
    }
    fn ring_for(&self, ip: u32, instance: u32, ring: u32) -> Option<u32> {
        (ip == uapi::AMDGPU_HW_IP_GFX && instance == 0 && ring == 0).then_some(self.ring)
    }
    fn wait(
        &self,
        ticket: u64,
        _: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>> {
        Box::pin(async move { Ok(self.signalled(ticket)) })
    }
}
fn cs_wait_errors_survive_engine_replacement_and_unregistration() -> TestResult {
    const CARD: u32 = 0xfeed_0406;
    let vm = VmState::new();
    let gem = crate::amdgpu_gem::GemState::new();
    let ctx = crate::amdgpu_ctx::CtxState::new();
    let id = ctx.alloc(0).unwrap();
    let syncobjs = IrqSafeSpinLock::new(crate::drm::syncobj::SyncObjTable::new());
    let lists = crate::amdgpu_bo_list::BoListTable::new();
    let open = CsOpen {
        vm: &vm,
        gem: &gem,
        ctx: &ctx,
        syncobjs: &syncobjs,
        bo_lists: &lists,
        files: None,
    };
    let old = Arc::new(Faults {
        ring: 0x10,
        ready: AtomicBool::new(true),
        error: AtomicU8::new(0),
    });
    let engine = old.clone() as Arc<dyn Submitter>;
    let ticket = 0x10u64 << 32 | 7;
    ctx.jobs.record(
        id,
        (uapi::AMDGPU_HW_IP_GFX, 0, 0),
        JobFence::new(&engine, CARD, ticket, vm.owner()),
    );
    let replacement: Arc<dyn Submitter> = Arc::new(Faults {
        ring: 0x20,
        ready: AtomicBool::new(true),
        error: AtomicU8::new(0),
    });
    let run = |f| narf_scheduler::block_on_spin(f);
    for current in [Some(&replacement), None] {
        for (code, expected) in [
            (1, FsError::Canceled),
            (2, FsError::TimedOut),
            (3, FsError::NoDevice),
        ] {
            old.error.store(code, Ordering::Release);
            for handle in [ticket, u64::MAX] {
                let mut req = [0u8; 32];
                req[..8].copy_from_slice(&handle.to_le_bytes());
                req[16..20].copy_from_slice(&uapi::AMDGPU_HW_IP_GFX.to_le_bytes());
                req[28..32].copy_from_slice(&id.to_le_bytes());
                assert_eq!(
                    run(wait_cs(CARD, current, req.as_mut_ptr() as usize, &open)),
                    Err(expected)
                );
            }
            let mut fence = [0u8; 24];
            fence[..4].copy_from_slice(&id.to_le_bytes());
            fence[4..8].copy_from_slice(&uapi::AMDGPU_HW_IP_GFX.to_le_bytes());
            fence[16..24].copy_from_slice(&ticket.to_le_bytes());
            for all in [0u32, 1] {
                let mut req = [0u8; 24];
                req[..8].copy_from_slice(&(fence.as_ptr() as u64).to_le_bytes());
                req[8..12].copy_from_slice(&1u32.to_le_bytes());
                req[12..16].copy_from_slice(&all.to_le_bytes());
                assert_eq!(
                    narf_scheduler::block_on_spin(wait_fences(
                        CARD,
                        current,
                        req.as_mut_ptr() as usize,
                        &open
                    )),
                    Err(expected)
                );
            }
        }
    }
    assert!(!engine.retired(ticket));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/fence-errors",
    cs_wait_errors_survive_engine_replacement_and_unregistration
);

fn cs_fence_history_keeps_pending_and_scopes_last_fence_to_context() -> TestResult {
    let history = History::new();
    let raw = Arc::new(Faults {
        ring: 1,
        ready: AtomicBool::new(false),
        error: AtomicU8::new(0),
    });
    let engine = raw.clone() as Arc<dyn Submitter>;
    let ip = (uapi::AMDGPU_HW_IP_GFX, 0, 0);
    let t = |s: u32| 1u64 << 32 | u64::from(s);
    for seq in 1..=100 {
        history.record(1, ip, JobFence::new(&engine, 1, t(seq), 1));
    }
    let get = |context, ticket| {
        history
            .resolve(1, context, ip, ticket)
            .map(|r| r.map(|j| j.map(|j| j.seq)))
    };
    assert_eq!(get(1, t(1)), Some(Ok(Some(t(1)))));
    assert_eq!(get(1, t(101)), Some(Err(FsError::InvalidData)));
    assert_eq!(get(2, t(1)), None);
    raw.ready.store(true, Ordering::Release);
    for seq in 101..=200 {
        history.record(1, ip, JobFence::new(&engine, 1, t(seq), 1));
    }
    assert_eq!(get(1, t(1)), Some(Ok(None)));
    history.record(2, ip, JobFence::new(&engine, 1, t(201), 2));
    assert_eq!(get(1, u64::MAX), Some(Ok(Some(t(200)))));
    assert_eq!(get(2, u64::MAX), Some(Ok(Some(t(201)))));
    history.forget(1);
    assert_eq!(get(1, t(200)), None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/fence-errors",
    cs_fence_history_keeps_pending_and_scopes_last_fence_to_context
);

fn cs_kernel_dependency_wait_refuses_terminal_card() -> TestResult {
    struct Never;
    impl narf_filesystem::DrmFence for Never {
        fn is_signalled(&self) -> bool {
            false
        }
        fn wait(&self, _: u64) -> bool {
            false
        }
        fn driver_name(&self) -> &str {
            "test"
        }
    }
    const CARD: u32 = 0xfeed_0405;
    let guard = narf_scheduler::block_on_spin(crate::amdgpu_gem::lock_placement(CARD));
    crate::amdgpu_gem::mark_placement_lost(CARD);
    // Device loss refuses an unsignalled foreign dependency immediately;
    // it need not wait for a timeout or the quarantined admission mutex.
    let result = narf_scheduler::block_on_spin(wait_kernel(
        CARD,
        alloc::vec![Arc::new(Never) as Arc<dyn narf_filesystem::DrmFence>],
        narf_time::monotonic_ns(),
    ));
    assert_eq!(result, Err(FsError::NoDevice));
    drop(guard);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-transfer",
    cs_kernel_dependency_wait_refuses_terminal_card
);
