// Native submit dependencies use the actual GuC CT state machine and fences.
use super::*;
use crate::intel_gpu_exec_sync::SyncRequest;

fn submitted(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    fence: &CompletionFence,
    registered: &mut BTreeMap<u32, u32>,
    start: u64,
) {
    assert!(!fence.is_submit_ready());
    for now in start..start + 20 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        assert!(!fence.is_submit_ready());
        if service_contexts(w, registered, false).contains(&0x1001) {
            // Firmware has queued the enable ACK, but the owner has not seen
            // it. Registration, policy, and CT enqueue alone are insufficient.
            assert!(!fence.is_submit_ready());
            assert_eq!(gt.poll(now + 1), Poll::Ready(Ok(GtState::SchedulingReady)));
            assert!(fence.is_submit_ready());
            assert!(!fence.is_signalled());
            for base in registered.values() {
                assert_eq!(w.0.borrow().memory[base].borrow()[0x800 / 4], 0);
            }
            return;
        }
    }
    panic!("GuC never acknowledged scheduling enable");
}

fn ready<F: Future + ?Sized>(mut call: core::pin::Pin<&mut F>) -> F::Output {
    let deadline = narf_time::monotonic_ns() + 10_000_000;
    loop {
        if let Poll::Ready(result) = call.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            return result;
        }
        assert!(
            narf_time::monotonic_ns() < deadline,
            "submit dependency stuck"
        );
        narf_scheduler::sleep_pumps::run();
    }
}

fn smoke_submit_fence_ioctl_admits_before_gpu_completion() -> TestResult {
    for flag in [abi::EXEC_FENCE_SUBMIT, abi::EXEC_FENCE_IN] {
        let platform = GtPlatform::Battlemage;
        let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
        prime(&mut gt, &w, 0xdfc);
        let (backend, info) = setup(platform, &gt);
        let file = RenderFile::new();
        let user = Fds::new();
        let handles = buffers(&file, &info, &user.user);
        let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
        let objects = result.weak_objects();
        let producer_context = UserContext::new();
        let (_, producer) = gt
            .submit_user_batch_with_output(
                100,
                producer_context.clone(),
                UserBatch(batch),
                &UserOutput {
                    user: &user,
                    address: 120,
                    input: 0,
                },
            )
            .unwrap();
        let exported = user.sync_file_fences(17).unwrap().pop().unwrap();
        assert!(!exported.is_submit_ready());
        let mut param = [0; 16];
        put32(&mut param, 0, 53); // I915_PARAM_HAS_EXEC_SUBMIT_FENCE
        put64(&mut param, 8, 2048);
        user.user.store(64, &param);
        assert_eq!(file.dispatch(&info, abi::GETPARAM, 64, &user), Some(Ok(0)));
        assert_eq!(u32_at(&user.user.load(2048, 4), 0), 1);
        exec(&user.user, handles, 0);
        let mut wire = user.user.load(64, 64);
        let flags = u64_at(&wire, 40);
        put64(&mut wire, 40, flags | flag);
        put64(&mut wire, 56, 17);
        user.user.store(64, &wire);
        let mut call =
            core::pin::pin!(file.dispatch_user(&info, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(backend.pending.lock().is_empty());
        // The copied descriptor payload survives close/reuse and wire edits.
        user.files.lock().clear();
        user.user.store(64, &[0; 64]);
        let mut registered = BTreeMap::new();
        submitted(&mut gt, &w, &producer, &mut registered, 101);
        assert!(exported.is_submit_ready());
        assert!(!exported.is_signalled());
        assert!(producer_context.busy());
        assert!(objects.iter().all(|o| o.upgrade().unwrap().busy() != 0));
        let mut consumer = None;
        if flag == abi::EXEC_FENCE_SUBMIT {
            reach_backend(call.as_mut(), &backend);
            let (_, fence) = backend.accept(&mut gt, 200);
            assert_eq!(ready(call.as_mut()), Some(Ok(0)));
            assert!(!producer.is_signalled());
            submitted(&mut gt, &w, &fence, &mut registered, 201);
            consumer = Some(fence);
        } else {
            let deadline = narf_time::monotonic_ns() + 300_000;
            while narf_time::monotonic_ns() < deadline {
                assert!(call
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
                narf_scheduler::sleep_pumps::run();
            }
            assert!(
                backend.pending.lock().is_empty(),
                "FENCE_IN used submit readiness"
            );
        }
        hardware_stop(&mut gt, &w, 0xdfc);
        assert_eq!(producer.result(), Some(Err(JobError::Reset)));
        assert!(exported.is_signalled());
        if let Some(fence) = consumer {
            assert_eq!(fence.result(), Some(Err(JobError::Reset)));
        }
        *backend.status.lock() = None;
        user.user.store(64, &param);
        assert_eq!(file.dispatch(&info, abi::GETPARAM, 64, &user), Some(Ok(0)));
        assert_eq!(u32_at(&user.user.load(2048, 4), 0), 0);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_submit_fence_ioctl_admits_before_gpu_completion
);

struct Foreign(AtomicBool);
impl DrmFence for Foreign {
    fn is_signalled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    fn wait(&self, _timeout_ms: u64) -> bool {
        self.is_signalled()
    }
    // Names must never be used to identify native submit semantics.
    fn driver_name(&self) -> &str {
        "intel-gpu"
    }
}

fn smoke_submit_fence_composites_keep_foreign_and_syncobj_completion() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let file = RenderFile::new();
    let user = Fds::new();
    let (batch, _) = PpgttProbeResult::prepare(platform).unwrap();
    let (_, producer) = gt
        .submit_user_batch(100, UserContext::new(), UserBatch(batch))
        .unwrap();
    let foreign = Arc::new(Foreign(AtomicBool::new(false)));
    let core = so::SyncObjCore::new(None);
    core.add_point(so::from_drm_leaves(alloc::vec![producer.clone()]), 7);
    core.add_point(so::from_drm_leaves(alloc::vec![foreign.clone()]), 11);
    let leaves = so::to_drm_leaves(&core.fence().unwrap());
    let exact: Arc<dyn DrmFence> = producer.clone();
    assert!(leaves.iter().any(|f| Arc::ptr_eq(f, &exact)));
    assert_eq!(leaves.len(), 2);
    user.files.lock().insert(9, leaves);
    let mut wire = [0; 64];
    put64(&mut wire, 40, abi::EXEC_FENCE_SUBMIT);
    put64(&mut wire, 56, 9);
    let submit = SyncRequest::read(&user, &wire)
        .unwrap()
        .resolve(&file.syncobjs)
        .unwrap();
    let mut submit_wait = core::pin::pin!(submit.wait());
    assert!(submit_wait
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    let mut registered = BTreeMap::new();
    submitted(&mut gt, &w, &producer, &mut registered, 101);
    assert!(submit_wait
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    foreign.0.store(true, Ordering::Release);
    ready(submit_wait.as_mut());
    assert!(!producer.is_signalled());
    // Ordinary IN, binary WAIT and timeline WAIT remain completion gates,
    // even when combined with SUBMIT on that same native input fence.
    put64(&mut wire, 40, abi::EXEC_FENCE_IN);
    let normal = SyncRequest::read(&user, &wire)
        .unwrap()
        .resolve(&file.syncobjs)
        .unwrap();
    let mut waits = alloc::vec![normal];
    for timeline in [false, true] {
        let handle = file.syncobjs.lock().create(0).unwrap();
        let core = file.syncobjs.lock().get(handle).unwrap().core().clone();
        let payload = so::from_drm_leaves(alloc::vec![producer.clone()]);
        if timeline {
            core.add_point(payload, 7);
        } else {
            core.replace_fence(Some(payload));
        }
        let mut entry = [0; 8];
        put32(&mut entry, 0, handle);
        put32(&mut entry, 4, 1);
        user.user.store(1024, &entry);
        wire = [0; 64];
        put64(&mut wire, 56, 9);
        if timeline {
            let mut extension = [0; 56];
            put64(&mut extension, 32, 1);
            put64(&mut extension, 40, 1024);
            put64(&mut extension, 48, 2048);
            user.user.store(1536, &extension);
            user.user.store(2048, &7u64.to_le_bytes());
            put64(
                &mut wire,
                40,
                abi::EXEC_FENCE_SUBMIT | abi::EXEC_USE_EXTENSIONS,
            );
            put64(&mut wire, 32, 1536);
        } else {
            put64(
                &mut wire,
                40,
                abi::EXEC_FENCE_SUBMIT | abi::EXEC_FENCE_ARRAY,
            );
            put32(&mut wire, 28, 1);
            put64(&mut wire, 32, 1024);
        }
        waits.push(
            SyncRequest::read(&user, &wire)
                .unwrap()
                .resolve(&file.syncobjs)
                .unwrap(),
        );
        file.syncobjs.lock().destroy(handle).unwrap();
    }
    let mut waits: Vec<_> = waits.iter().map(|s| Box::pin(s.wait())).collect();
    for wait in &mut waits {
        assert!(wait
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    hardware_stop(&mut gt, &w, 0xdfc);
    for wait in &mut waits {
        ready(wait.as_mut());
    }
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_submit_fence_composites_keep_foreign_and_syncobj_completion
);

fn smoke_submit_fence_loss_before_ack_waits_for_proven_reset() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let user = Fds::new();
    let file = RenderFile::new();
    let context = UserContext::new();
    let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
    let objects = result.weak_objects();
    let (_, producer) = gt
        .submit_user_batch(100, context.clone(), UserBatch(batch))
        .unwrap();
    user.files.lock().insert(9, alloc::vec![producer.clone()]);
    let mut wire = [0; 64];
    put64(&mut wire, 40, abi::EXEC_FENCE_SUBMIT);
    put64(&mut wire, 56, 9);
    let resolved = SyncRequest::read(&user, &wire)
        .unwrap()
        .resolve(&file.syncobjs)
        .unwrap();
    let mut wait = core::pin::pin!(resolved.wait());
    assert!(wait
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    let live = arena.live_allocations();
    event(&ct_memory(&w), 0x7001, &[0x123456]); // No matching request stamp.
    assert!(matches!(gt.poll(101), Poll::Ready(Err(_))));
    assert_eq!(gt.state(), GtState::Lost);
    assert!(!producer.is_submit_ready());
    assert!(!producer.is_signalled());
    assert!(context.busy());
    assert_eq!(arena.live_allocations(), live);
    assert!(objects.iter().all(|o| o.upgrade().unwrap().busy() != 0));
    assert!(wait
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    hardware_stop(&mut gt, &w, 0xdfc);
    assert_eq!(producer.result(), Some(Err(JobError::Reset)));
    assert!(producer.is_submit_ready());
    ready(wait.as_mut());
    assert!(!context.busy());
    assert!(objects.iter().all(|o| o.upgrade().unwrap().busy() == 0));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_submit_fence_loss_before_ack_waits_for_proven_reset
);

fn smoke_submit_fence_rejects_conflicting_inputs_and_bad_descriptors() -> TestResult {
    let user = Fds::new();
    let file = RenderFile::new();
    let mut wire = [0; 64];
    for output in [0, abi::EXEC_FENCE_OUT] {
        put64(
            &mut wire,
            40,
            abi::EXEC_FENCE_IN | abi::EXEC_FENCE_SUBMIT | output,
        );
        put64(&mut wire, 56, 9);
        user.files.lock().insert(9, Vec::new());
        assert!(matches!(
            SyncRequest::read(&user, &wire),
            Err(FsError::InvalidData)
        ));
        put64(&mut wire, 40, abi::EXEC_FENCE_SUBMIT | output);
        user.files.lock().clear();
        assert!(matches!(
            SyncRequest::read(&user, &wire),
            Err(FsError::InvalidData)
        ));
        // Signalled stub sync_files still satisfy SUBMIT immediately.
        user.files.lock().insert(9, Vec::new());
        let resolved = SyncRequest::read(&user, &wire)
            .unwrap()
            .resolve(&file.syncobjs)
            .unwrap();
        let mut wait = core::pin::pin!(resolved.wait());
        assert!(wait
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready());
    }
    assert!(user.sync_file_fences(17).is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_submit_fence_rejects_conflicting_inputs_and_bad_descriptors
);
