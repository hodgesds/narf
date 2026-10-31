use super::*;

fn execute_one(w: &Window, registered: &BTreeMap<u32, u32>, id: u32) {
    let base = registered[&id];
    let d = w.0.borrow();
    let image = d.memory[&base].clone();
    let tail = image.borrow()[1024 + 7];
    let ring_base = image.borrow()[1024 + 9];
    let ring = d.memory[&ring_base].borrow();
    let stamp = ring[..tail as usize / 4]
        .windows(6)
        .find(|w| w[..4] == [0x7a000004, 0x01104080, base + 0x800, 0])
        .unwrap()[4];
    execute_ppgtt_probe(&d.regs, &image.borrow(), &ring, stamp, base);
    let mut image = image.borrow_mut();
    image[0x800 / 4] = stamp;
    image[1024 + 5] = tail;
}

fn smoke_xe_explicit_queues_overlap_and_cpu_reservations_wait_for_both() -> TestResult {
    use narf_filesystem::dma_buf::DmaResvUsage;
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let q1 = create_queue(&file, &info, &user, vm, 0);
    let q2 = create_queue(&file, &info, &user, vm, 0);
    let handles = buffers(&file, &info, &user, vm);
    let data = file.gem.object(handles[1]).unwrap();
    let submit = |queue, gt: &mut GuCGt<Window, Arena>| {
        exec_wire(&user, queue, true, &[]);
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (_, fence) = mailbox.accept(gt, 100);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        fence
    };
    let f1 = submit(q1, &mut gt);
    let f2 = submit(q2, &mut gt);
    assert_eq!(data.dma_buf.resv.fences(DmaResvUsage::Write).len(), 2);
    assert_eq!(data.read(128, &mut [0; 4]), Err(FsError::WouldBlock));
    let mut registered = BTreeMap::new();
    for now in 101..125 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
        if narf_filesystem::DrmFence::is_submit_ready(&*f1)
            && narf_filesystem::DrmFence::is_submit_ready(&*f2)
        {
            break;
        }
    }
    assert_eq!(registered.keys().copied().collect::<Vec<_>>(), [3, 4]);
    execute_one(&w, &registered, 3);
    finish(&mut gt, &w, &f1, &mut registered, 130);
    assert_eq!(f2.result(), None);
    assert_eq!(registered.len(), 1);
    assert_eq!(data.dma_buf.resv.fences(DmaResvUsage::Write).len(), 1);
    assert_eq!(data.read(128, &mut [0; 4]), Err(FsError::WouldBlock));
    execute_one(&w, &registered, 4);
    finish(&mut gt, &w, &f2, &mut registered, 200);
    let mut value = [0; 4];
    data.read(128, &mut value).unwrap();
    assert_eq!(u32_at(&value, 0), 0x4e415246);
    assert!(registered.is_empty());
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_explicit_queues_overlap_and_cpu_reservations_wait_for_both
);

fn smoke_xe_cancelled_bind_preserves_mapping_and_defers_signals() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let queue = create_queue(&file, &info, &user, vm, 0);
    let _ = buffers(&file, &info, &user, vm);
    exec_wire(&user, queue, true, &[]);
    let f1 = {
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (_, fence) = mailbox.accept(&mut gt, 100);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        fence
    };
    let output = file.syncobjs.lock().create(0).unwrap();
    let core = file.syncobjs.lock().get(output).unwrap().core().clone();
    let mut unmap = mapping(0, 0x1234_0000_0000, 0, 4096, 0, 0);
    put32(&mut unmap, 40, 1);
    put32(&mut unmap, 44, 8); // Mesa retains DUMPABLE on unbind.
    bind_wire(
        &user,
        vm,
        &[unmap],
        &[
            sync(0, u64::from(output), 0, true),
            sync(2, 0x6000, 21, true),
        ],
    );
    {
        let mut cancelled = core::pin::pin!(file.dispatch_user(&info, xe::VM_BIND, 64, &user));
        assert!(cancelled
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert!(core.fence().is_none());
    assert_eq!(user.read_u64_acquire(0x6000), Ok(0));
    let mut registered = BTreeMap::new();
    finish(&mut gt, &w, &f1, &mut registered, 101);
    exec_wire(&user, queue, true, &[]);
    let f2 = {
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (_, fence) = mailbox.accept(&mut gt, 200);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        fence
    };
    finish(&mut gt, &w, &f2, &mut registered, 201);
    bind_wire(
        &user,
        vm,
        &[unmap],
        &[
            sync(0, u64::from(output), 0, true),
            sync(2, 0x6000, 21, true),
        ],
    );
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    assert!(core.is_signalled());
    assert_eq!(user.read_u64_acquire(0x6000), Ok(21));
    exec_wire(&user, queue, true, &[]);
    assert_eq!(
        narf_scheduler::block_on_spin(file.dispatch_user(&info, xe::EXEC, 64, &user)),
        Some(Err(FsError::InvalidData))
    );
    assert!(mailbox.pending.lock().is_empty());
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_cancelled_bind_preserves_mapping_and_defers_signals
);

fn smoke_xe_sync_snapshots_barrier_firmware_and_closed_queue() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let q1 = create_queue(&file, &info, &user, vm, 0);
    let q2 = create_queue(&file, &info, &user, vm, 0);
    let _ = buffers(&file, &info, &user, vm);
    let input = file.syncobjs.lock().create(0).unwrap();
    let output = file.syncobjs.lock().create(0).unwrap();
    let out_core = file.syncobjs.lock().get(output).unwrap().core().clone();
    exec_wire(&user, q1, true, &[sync(0, u64::from(input), 0, true)]);
    let producer = {
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (_, fence) = mailbox.accept(&mut gt, 100);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        fence
    };
    exec_wire(
        &user,
        q2,
        true,
        &[
            sync(0, u64::from(input), 0, false),
            sync(1, u64::from(output), 7, true),
        ],
    );
    {
        let mut cancelled = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(cancelled
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert!(mailbox.pending.lock().is_empty());
    assert!(out_core.fence().is_none());
    let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    file.syncobjs.lock().destroy(input).unwrap();
    file.syncobjs.lock().destroy(output).unwrap();
    user.wire.store(64, &[0; 56]);
    let mut registered = BTreeMap::new();
    finish(&mut gt, &w, &producer, &mut registered, 101);
    for _ in 0..1_000_000 {
        if !mailbox.pending.lock().is_empty() {
            break;
        }
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        narf_scheduler::sleep_pumps::run();
    }
    assert!(!mailbox.pending.lock().is_empty(), "consumer never queued");
    let (_, consumer) = mailbox.accept(&mut gt, 200);
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );
    let payload = out_core.find_fence(7).unwrap();
    assert!(!payload.is_signalled());
    finish(&mut gt, &w, &consumer, &mut registered, 201);
    assert!(payload.is_signalled());
    let barrier = file.syncobjs.lock().create(0).unwrap();
    let barrier_core = file.syncobjs.lock().get(barrier).unwrap().core().clone();
    bind_wire(&user, vm, &[], &[sync(0, u64::from(barrier), 0, true)]);
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    assert!(barrier_core.is_signalled());
    // Mesa's GuC semaphore check queries the CSS compatibility interface,
    // not the firmware release version70.x. Unknown/HuC requests stay absent.
    let mut query = [0; 40];
    put32(&mut query, 8, 7);
    put64(&mut query, 16, u64::MAX);
    user.wire.store(64, &query);
    assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
    assert_eq!(u32_at(&user.wire.load(64, 40), 12), 32);
    put32(&mut query, 12, 32);
    put64(&mut query, 16, 1024);
    user.wire.store(64, &query);
    user.wire.store(1024, &[0; 32]);
    assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
    let version = user.wire.load(1024, 32);
    let expected = gt.submission_version();
    assert_eq!(
        (
            u32_at(&version, 8),
            u32_at(&version, 12),
            u32_at(&version, 16)
        ),
        (
            u32::from(expected.0),
            u32::from(expected.1),
            u32::from(expected.2)
        )
    );
    for (kind, error) in [(1u16, FsError::NoDevice), (2u16, FsError::InvalidData)] {
        let mut version = [0; 32];
        version[..2].copy_from_slice(&kind.to_le_bytes());
        user.wire.store(1024, &version);
        assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Err(error));
    }
    let mut wait = [0; 72];
    put64(&mut wait, 8, 0x6000);
    put64(&mut wait, 24, 99);
    put64(&mut wait, 32, u64::MAX);
    put64(&mut wait, 40, u64::MAX);
    put32(&mut wait, 48, q2);
    user.wire.store(64, &wait);
    let mut wait = core::pin::pin!(file.dispatch_user(&info, xe::WAIT_USER_FENCE, 64, &user));
    assert!(wait
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(
        close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, q2),
        Ok(0)
    );
    assert_eq!(
        ready(wait.as_mut()),
        Some(Err(crate::intel_gpu_user::io_error()))
    );
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_sync_snapshots_barrier_firmware_and_closed_queue
);
