//! These fixtures drive Queue::run, the production worker loop, on both
//! architectures. Only its hardware session is substituted with Device.
use super::*;
use narf_filesystem::DrmFence;

struct Worker {
    device: Device,
    epoch: u64,
    lost: bool,
}
impl Worker {
    fn new() -> Self {
        Self {
            device: Device::new(),
            epoch: 1,
            lost: false,
        }
    }
}
impl queue::Worker for Worker {
    fn lost(&self) -> bool {
        self.lost
    }
    fn epoch(&self) -> u64 {
        self.epoch
    }
    fn process<'a>(
        &'a mut self,
        mode: &'a ModeState,
        open: u64,
        epoch: u64,
        plan: &'a Plan,
        reservation: Option<FlipEventReservation>,
    ) -> FsFuture<'a, FlipStamp> {
        assert_eq!(epoch, self.epoch);
        alloc::boxed::Box::pin(execute_plan(
            &mut self.device,
            mode,
            open,
            plan,
            reservation,
        ))
    }
}
fn submit(
    queue: &queue::Queue,
    request: Request,
    cpu: &Cpu,
    events: &Events,
) -> (Arc<queue::Completion>, bool, bool) {
    let geometry = Geometry {
        width: 64,
        height: 32,
        pitch: 256,
    };
    let mut admission = core::pin::pin!(queue.submit(7, request, geometry, 1, cpu, Some(events)));
    match admission
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(Some(submitted))) => submitted,
        _ => panic!("owned admission must finish before hardware worker/latch"),
    }
}
fn poll_worker<F: Future>(future: core::pin::Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn intel_kms_nonblock_returns_before_latch_with_owned_native_fence() -> TestResult {
    let mode = mode();
    let fb = framebuffer(&mode, 7, false).expect("WB source on both architectures");
    let queue = queue::Queue::new(mode.clone());
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let cpu = Cpu::new();
    let (completion, start, nonblock) =
        submit(&queue, atomic_frame(fb, EVENT | NONBLOCK), &cpu, &events);
    assert!(start && nonblock);
    assert_eq!(&cpu.bytes.lock()[128..132], &41i32.to_le_bytes());
    let exported = cpu.exported.lock()[0].clone();
    assert_eq!(exported.status(), 0);
    assert!(!exported.wait(0));
    assert!(completion.result().is_none());
    assert_eq!(mode.lock().crtcs[0].primary_fb, None);
    // Neither context nor OUT_FENCE_PTR is retained by the queued job.
    drop(cpu);
    let mut worker = Worker::new();
    let ready = worker.device.ready.clone();
    let copies = worker.device.copies.clone();
    let mut running = alloc::boxed::Box::pin(queue.run(&mut worker));
    assert!(poll_worker(running.as_mut()).is_pending());
    assert_eq!(copies.load(Ordering::Acquire), 1);
    assert_eq!(exported.status(), 0);
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    ready.store(true, Ordering::Release);
    assert!(poll_worker(running.as_mut()).is_ready());
    assert_eq!(
        completion.result(),
        Some(Ok(FlipStamp {
            ns: 1234567000,
            sequence: 77
        }))
    );
    assert_eq!(exported.status(), 1);
    assert_eq!(exported.timestamp_ns(), Some(1234567000));
    assert!(exported.wait(0));
    assert_eq!(mode.lock().crtcs[0].primary_fb, Some(fb));
    let mut event = [0; 32];
    assert_eq!(
        events.lock().read_deliverable_event(u64::MAX, &mut event),
        Some(32)
    );
    assert_eq!(
        u64::from_le_bytes(event[8..16].try_into().unwrap()),
        0x11223344
    );
    assert_eq!(u32::from_le_bytes(event[24..28].try_into().unwrap()), 77);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_nonblock_returns_before_latch_with_owned_native_fence
);

fn intel_kms_fifo_projects_state_and_serializes_legacy_behind_nonblock() -> TestResult {
    let mode = mode();
    let first = framebuffer(&mode, 7, false).unwrap();
    let second = framebuffer(&mode, 7, false).unwrap();
    let third = framebuffer(&mode, 7, false).unwrap();
    let queue = queue::Queue::new(mode.clone());
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let cpu = Cpu::new();
    let (a, start, _) = submit(&queue, atomic_frame(first, EVENT | NONBLOCK), &cpu, &events);
    assert!(start);
    let (b, start, _) = submit(
        &queue,
        atomic_frame(second, EVENT | NONBLOCK),
        &cpu,
        &events,
    );
    assert!(!start);
    // Actual Card is still the initial console. PAGE_FLIP must validate the
    // last accepted state's format/enable, then run after both atomic jobs.
    let (c, start, nonblock) = submit(
        &queue,
        Request::PageFlip(DrmModePageFlipUapi {
            crtc_id: 1,
            fb_id: third,
            flags: EVENT,
            reserved: 0,
            user_data: 0xaabbccdd,
        }),
        &cpu,
        &events,
    );
    assert!(!start && !nonblock);
    let mut worker = Worker::new();
    let ready = worker.device.ready.clone();
    let copies = worker.device.copies.clone();
    let mut running = alloc::boxed::Box::pin(queue.run(&mut worker));
    assert!(poll_worker(running.as_mut()).is_pending());
    assert_eq!(copies.load(Ordering::Acquire), 1);
    assert!(a.result().is_none() && b.result().is_none() && c.result().is_none());
    ready.store(true, Ordering::Release);
    assert!(poll_worker(running.as_mut()).is_ready());
    assert_eq!(copies.load(Ordering::Acquire), 3);
    assert_eq!(mode.lock().crtcs[0].primary_fb, Some(third));
    for expected in [0x11223344, 0x11223344, 0xaabbccdd] {
        let mut event = [0; 32];
        assert_eq!(
            events.lock().read_deliverable_event(u64::MAX, &mut event),
            Some(32)
        );
        assert_eq!(
            u64::from_le_bytes(event[8..16].try_into().unwrap()),
            expected
        );
    }
    assert_eq!(a.status(), 1);
    assert_eq!(b.status(), 1);
    assert_eq!(c.status(), 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_fifo_projects_state_and_serializes_legacy_behind_nonblock
);

fn intel_kms_queued_failure_cancels_dependents_without_success_events() -> TestResult {
    let mode = mode();
    let first = framebuffer(&mode, 7, false).unwrap();
    let second = framebuffer(&mode, 7, false).unwrap();
    let queue = queue::Queue::new(mode.clone());
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let cpu = Cpu::new();
    let (a, _, _) = submit(&queue, atomic_frame(first, EVENT | NONBLOCK), &cpu, &events);
    let (b, _, _) = submit(
        &queue,
        atomic_frame(second, EVENT | NONBLOCK),
        &cpu,
        &events,
    );
    let mut worker = Worker::new();
    worker.device.fail.store(true, Ordering::Release);
    let calls = worker.device.calls.clone();
    let mut running = alloc::boxed::Box::pin(queue.run(&mut worker));
    assert!(poll_worker(running.as_mut()).is_ready());
    assert_eq!(a.result(), Some(Err(FsError::TimedOut)));
    assert_eq!(a.status(), -110);
    assert!(a.wait(0));
    assert_eq!(b.result(), Some(Err(FsError::Busy)));
    assert!(b.status() < 0);
    assert_eq!(calls.load(Ordering::Acquire), 2); // no backend work for dependent job
    assert_eq!(mode.lock().crtcs[0].primary_fb, None);
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    assert!(events.lock().ensure_flip_event_space(128).is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_queued_failure_cancels_dependents_without_success_events
);

fn intel_kms_queued_close_and_worker_cancel_release_owned_lifetimes() -> TestResult {
    for armed in [false, true] {
        let mode = mode();
        let fb = framebuffer(&mode, 7, false).unwrap();
        let weak = Arc::downgrade(
            &mode
                .lock()
                .framebuffer(fb)
                .unwrap()
                .intel
                .as_ref()
                .unwrap()
                .object,
        );
        let queue = queue::Queue::new(mode.clone());
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let cpu = Cpu::new();
        let (completion, _, _) = submit(&queue, atomic_frame(fb, EVENT | NONBLOCK), &cpu, &events);
        let mut worker = Worker::new();
        let calls = worker.device.calls.clone();
        let mut running = alloc::boxed::Box::pin(queue.run(&mut worker));
        if armed {
            assert!(poll_worker(running.as_mut()).is_pending());
            assert!(mode.lock().intel_transaction_busy());
        }
        events.lock().close();
        {
            let mut card = mode.lock();
            card.release_file_framebuffers(7);
            card.master_release(7);
        }
        assert!(weak.upgrade().is_some()); // queued Plan pins independently of fd
        if armed {
            // Cancellation of the worker future fails the outstanding native
            // fence and drains/refunds queued jobs. Real hardware pages remain
            // additionally pinned by the display owner until safe restoration.
            drop(running);
        } else {
            assert!(poll_worker(running.as_mut()).is_ready());
            assert_eq!(calls.load(Ordering::Acquire), 0);
        }
        assert!(completion.status() < 0);
        assert!(weak.upgrade().is_none());
        assert!(!mode.lock().intel_transaction_busy());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        assert!(events.lock().ensure_flip_event_space(128).is_ok());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_queued_close_and_worker_cancel_release_owned_lifetimes
);

fn intel_kms_native_fence_export_faults_and_test_only_never_publish_jobs() -> TestResult {
    for cause in 0..3 {
        let mode = mode();
        let queue = queue::Queue::new(mode);
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let cpu = Cpu::new();
        let no_descriptor = cause == 1;
        cpu.no_descriptor.store(no_descriptor, Ordering::Release);
        cpu.bad_write.store(cause == 0, Ordering::Release);
        if cause == 2 {
            cpu.fail_after.store(1, Ordering::Release);
        }
        let geometry = Geometry {
            width: 64,
            height: 32,
            pitch: 256,
        };
        let mut admission = core::pin::pin!(queue.submit(
            7,
            disable(EVENT | NONBLOCK | ALLOW_MODESET),
            geometry,
            1,
            &cpu,
            Some(&events)
        ));
        match poll_worker(admission.as_mut()) {
            Poll::Ready(Err(queue::SubmitError::NoDescriptor)) if no_descriptor => {}
            Poll::Ready(Err(queue::SubmitError::Io(FsError::BadAddress))) if !no_descriptor => {}
            _ => panic!("export failure must abort before queue publication"),
        }
        assert!(cpu.exported.lock().is_empty());
        assert!(events.lock().ensure_flip_event_space(128).is_ok());
        let mut worker = Worker::new();
        let calls = worker.device.calls.clone();
        let mut running = core::pin::pin!(queue.run(&mut worker));
        assert!(poll_worker(running.as_mut()).is_ready());
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }
    let mode = mode();
    let queue = queue::Queue::new(mode);
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let cpu = Cpu::new();
    let geometry = Geometry {
        width: 64,
        height: 32,
        pitch: 256,
    };
    let mut admission = core::pin::pin!(queue.submit(
        7,
        disable(TEST_ONLY | ALLOW_MODESET | NONBLOCK),
        geometry,
        1,
        &cpu,
        Some(&events)
    ));
    assert!(matches!(
        poll_worker(admission.as_mut()),
        Poll::Ready(Ok(None))
    ));
    assert!(cpu.exported.lock().is_empty());
    assert_eq!(&cpu.bytes.lock()[128..132], &[0; 4]);
    assert!(events.lock().ensure_flip_event_space(128).is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_native_fence_export_faults_and_test_only_never_publish_jobs
);

fn intel_kms_old_epoch_jobs_fail_before_backend_or_success() -> TestResult {
    for lost in [false, true] {
        let mode = mode();
        let queue = queue::Queue::new(mode.clone());
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let cpu = Cpu::new();
        let (completion, _, _) = submit(
            &queue,
            disable(EVENT | NONBLOCK | ALLOW_MODESET),
            &cpu,
            &events,
        );
        let mut worker = Worker::new();
        worker.lost = lost;
        worker.epoch = if lost { 1 } else { 2 };
        let calls = worker.device.calls.clone();
        let mut running = core::pin::pin!(queue.run(&mut worker));
        assert!(poll_worker(running.as_mut()).is_ready());
        assert_eq!(completion.result(), Some(Err(FsError::NoDevice)));
        assert_eq!(completion.status(), -19);
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert!(mode.lock().crtcs[0].enabled);
        assert!(events.lock().ensure_flip_event_space(128).is_ok());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_old_epoch_jobs_fail_before_backend_or_success
);

fn intel_kms_queued_dumb_source_survives_handle_and_framebuffer_removal() -> TestResult {
    let mode = mode();
    let page = narf_memory::frame::alloc_pages_on(0, 1).expect("dumb source allocation");
    let (handle, fb) = {
        let mut card = mode.lock();
        let handle = card
            .register_dumb_backing(page.start_address().as_u64(), 8192, 1)
            .unwrap();
        let fb = card
            .addfb2(64, 32, DRM_FORMAT_XRGB8888, 256, handle)
            .unwrap();
        (handle, fb)
    };
    let queue = queue::Queue::new(mode.clone());
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let cpu = Cpu::new();
    let (completion, _, _) = submit(&queue, atomic_frame(fb, EVENT | NONBLOCK), &cpu, &events);
    {
        let mut card = mode.lock();
        assert_eq!(card.dumb_backing(handle).unwrap().refcount, 3);
        assert!(card.remove_dumb_backing(handle).is_none());
        assert!(card.rmfb(fb).unwrap().is_none());
        assert_eq!(card.dumb_backing(handle).unwrap().refcount, 1);
    }
    let mut worker = Worker::new();
    let calls = worker.device.calls.clone();
    let mut running = core::pin::pin!(queue.run(&mut worker));
    assert!(poll_worker(running.as_mut()).is_ready());
    assert!(completion.status() < 0);
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert!(mode.lock().dumb_backing(handle).is_none());
    assert!(events.lock().ensure_flip_event_space(128).is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_queued_dumb_source_survives_handle_and_framebuffer_removal
);

fn intel_kms_loss_after_latch_wait_cannot_publish_success() -> TestResult {
    let mode = mode();
    let queue = queue::Queue::new(mode.clone());
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let cpu = Cpu::new();
    let (completion, _, _) = submit(
        &queue,
        disable(EVENT | NONBLOCK | ALLOW_MODESET),
        &cpu,
        &events,
    );
    let mut worker = Worker::new();
    let ready = worker.device.ready.clone();
    let invalid = worker.device.invalid.clone();
    let mut running = core::pin::pin!(queue.run(&mut worker));
    assert!(poll_worker(running.as_mut()).is_pending());
    invalid.store(true, Ordering::Release);
    ready.store(true, Ordering::Release);
    assert!(poll_worker(running.as_mut()).is_ready());
    assert_eq!(completion.result(), Some(Err(FsError::NoDevice)));
    assert!(mode.lock().crtcs[0].enabled);
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    assert!(events.lock().ensure_flip_event_space(128).is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_loss_after_latch_wait_cannot_publish_success
);

struct InputFence;
impl DrmFence for InputFence {
    fn is_signalled(&self) -> bool {
        false
    }
    fn wait(&self, _: u64) -> bool {
        false
    }
}
fn intel_kms_input_fences_are_owned_and_wait_without_display_transaction() -> TestResult {
    let mode = mode();
    let queue = queue::Queue::new(mode.clone());
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let cpu = Cpu::new();
    let dependency: Arc<dyn DrmFence> = Arc::new(InputFence);
    let weak = Arc::downgrade(&dependency);
    cpu.inputs.lock().push(dependency);
    let request = Request::Atomic(OwnedAtomic {
        flags: NONBLOCK | EVENT,
        cookie: 123,
        objects: vec![PLANE_ID_BASE, 1],
        counts: vec![1, 1],
        props: vec![PLANE_IN_FENCE_FD_PROP_ID, CRTC_OUT_FENCE_PTR_PROP_ID],
        values: vec![9, 128],
    });
    let (completion, _, nonblock) = submit(&queue, request, &cpu, &events);
    assert!(nonblock);
    drop(cpu); // closing IN_FENCE_FD/user context cannot drop the dependency
    assert!(weak.upgrade().is_some());
    let mut worker = Worker::new();
    let calls = worker.device.calls.clone();
    let mut running = alloc::boxed::Box::pin(queue.run(&mut worker));
    assert!(poll_worker(running.as_mut()).is_pending());
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert!(!mode.lock().intel_transaction_busy());
    assert_eq!(completion.status(), 0);
    drop(running);
    assert!(completion.status() < 0);
    assert!(weak.upgrade().is_none());
    assert!(events.lock().ensure_flip_event_space(128).is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    intel_kms_input_fences_are_owned_and_wait_without_display_transaction
);
