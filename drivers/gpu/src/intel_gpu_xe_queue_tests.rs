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
    execute_ppgtt_probe(&d.regs, &image.borrow(), &ring, stamp, base, false);
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
    let submit = |queue, now, gt: &mut GuCGt<Window, Arena>| {
        exec_wire(&user, queue, true, &[]);
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(
            call.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let (_, fence) = mailbox.accept(gt, now);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        fence
    };
    let f1 = submit(q1, 100, &mut gt);
    let mut registered = BTreeMap::new();
    for now in 101..125 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
        if narf_filesystem::DrmFence::is_submit_ready(&*f1) {
            break;
        }
    }
    assert!(narf_filesystem::DrmFence::is_submit_ready(&*f1));
    assert_eq!(registered.len(), 1);
    let first_id = *registered.keys().next().unwrap();
    let f2 = submit(q2, 130, &mut gt);
    assert_eq!(data.dma_buf.resv.fences(DmaResvUsage::Write).len(), 2);
    assert_eq!(data.read(128, &mut [0; 4]), Err(FsError::WouldBlock));
    for now in 131..155 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
        if narf_filesystem::DrmFence::is_submit_ready(&*f1)
            && narf_filesystem::DrmFence::is_submit_ready(&*f2)
        {
            break;
        }
    }
    assert!(narf_filesystem::DrmFence::is_submit_ready(&*f2));
    assert_eq!(registered.len(), 2);
    assert!(registered.contains_key(&first_id));
    let second_id = *registered.keys().find(|id| **id != first_id).unwrap();
    assert_ne!(first_id, second_id);
    assert!(f1.result().is_none() && f2.result().is_none());
    execute_one(&w, &registered, first_id);
    finish(&mut gt, &w, &f1, &mut registered, 160);
    assert_eq!(f2.result(), None);
    assert_eq!(registered.len(), 1);
    assert_eq!(data.dma_buf.resv.fences(DmaResvUsage::Write).len(), 1);
    assert_eq!(data.read(128, &mut [0; 4]), Err(FsError::WouldBlock));
    assert!(registered.contains_key(&second_id));
    execute_one(&w, &registered, second_id);
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
        assert!(
            call.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
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
        assert!(
            cancelled
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    assert!(core.fence().is_none());
    assert_eq!(user.read_u64_acquire(0x6000), Ok(0));
    let mut registered = BTreeMap::new();
    finish(&mut gt, &w, &f1, &mut registered, 101);
    exec_wire(&user, queue, true, &[]);
    let f2 = {
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(
            call.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
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
        assert!(
            call.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
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
        assert!(
            cancelled
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    assert!(mailbox.pending.lock().is_empty());
    assert!(out_core.fence().is_none());
    let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
    assert!(
        call.as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    file.syncobjs.lock().destroy(input).unwrap();
    file.syncobjs.lock().destroy(output).unwrap();
    user.wire.store(64, &[0; 56]);
    let mut registered = BTreeMap::new();
    finish(&mut gt, &w, &producer, &mut registered, 101);
    for _ in 0..1_000_000 {
        if !mailbox.pending.lock().is_empty() {
            break;
        }
        assert!(
            call.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
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
    assert!(
        wait.as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
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

fn smoke_xe_parallel_queue_creation_validation_and_media_classes() -> TestResult {
    use crate::intel_gpu_engine::{Engine, EngineSet};
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let media_status = crate::intel_gpu_user::MediaGtStatus {
        epoch: 1,
        engines: EngineSet::of(&[Engine::Vcs0, Engine::Vcs1, Engine::Vecs0, Engine::Vecs1]),
        gmd: 0x1300,
        reference_clock: 19_200_000,
        topology: crate::intel_gpu_gt::media::MediaTopology::default(),
    };
    let (_mailbox, info) = setup_media(&mut gt, &w, platform, Some(media_status));

    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);

    let queue_wire_raw = |width: u16, count: u16, entries: &[[u16; 4]]| {
        let bytes: Vec<u8> = entries
            .iter()
            .flat_map(|e| e.iter().flat_map(|w| w.to_le_bytes()))
            .collect();
        user.wire.store(512, &bytes);
        let mut wire = [0u8; 48];
        wire[8..10].copy_from_slice(&width.to_le_bytes());
        wire[10..12].copy_from_slice(&count.to_le_bytes());
        put32(&mut wire, 12, vm);
        put64(&mut wire, 24, 512);
        user.wire.store(64, &wire);
    };

    // 1. Parallel queue with width 2 for Compute (class 4) on GT0 is
    // refused: MeteorLake publishes a single CCS (Ccs0) — `compute_instances`
    // returns 1 for Integrated platforms and the default CCS mode is 1 — so
    // the second lane has no published instance. Per spec.md §3,
    // "COMPUTE/VIDEO on a GT without published instances, return EINVAL".
    queue_wire_raw(2, 1, &[[4, 0, 0, 0], [4, 1, 0, 0]]);
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::InvalidData)
    );

    // 2. Parallel queue with width 2 for Video Decode (class 2, VCS) on GT1:
    queue_wire_raw(2, 1, &[[2, 0, 1, 0], [2, 1, 1, 0]]);
    assert_eq!(invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE), Ok(0));
    let q_vcs = u32_at(&user.wire.load(64, 48), 20);
    assert_ne!(q_vcs, 0);

    // 3. Parallel queue with width 2 for Video Enhance (class 3, VECS) on GT1:
    queue_wire_raw(2, 1, &[[3, 0, 1, 0], [3, 1, 1, 0]]);
    assert_eq!(invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE), Ok(0));
    let q_vecs = u32_at(&user.wire.load(64, 48), 20);
    assert_ne!(q_vecs, 0);

    // 4. Validation: Non-contiguous row [class, 0] and [class, 2] rejected:
    queue_wire_raw(2, 1, &[[4, 0, 0, 0], [4, 2, 0, 0]]);
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::InvalidData)
    );

    // 5. Validation: Class mismatch in row rejected:
    queue_wire_raw(2, 1, &[[4, 0, 0, 0], [1, 1, 0, 0]]);
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::InvalidData)
    );

    // 6. Validation: GT mismatch in row rejected:
    queue_wire_raw(2, 1, &[[4, 0, 0, 0], [4, 1, 1, 0]]);
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::InvalidData)
    );

    // 7. Validation: Duplicate placement rows rejected:
    queue_wire_raw(
        2,
        2,
        &[[4, 0, 0, 0], [4, 1, 0, 0], [4, 0, 0, 0], [4, 1, 0, 0]],
    );
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::InvalidData)
    );

    // 8. Validation: Class 0 (Render) with width > 1 rejected:
    queue_wire_raw(2, 1, &[[0, 0, 0, 0], [0, 1, 0, 0]]);
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::InvalidData)
    );

    // 9. Validation: Class 5 (Bind) with width > 1 rejected:
    queue_wire_raw(2, 1, &[[5, 0, 0, 0], [5, 1, 0, 0]]);
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::InvalidData)
    );

    // 10. Validation: Invalid width (width > 4 or width < 1):
    queue_wire_raw(
        5,
        1,
        &[
            [4, 0, 0, 0],
            [4, 1, 0, 0],
            [4, 2, 0, 0],
            [4, 3, 0, 0],
            [4, 4, 0, 0],
        ],
    );
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::InvalidData)
    );

    queue_wire_raw(0, 1, &[]);
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::InvalidData)
    );

    // 11. Multi-batch exec validation:
    // Submitting parallel exec with count != width (e.g. count=1 when width=2):
    let mut exec_wire = [0u8; 56];
    put32(&mut exec_wire, 8, q_vcs); // queue (width-2 VCS parallel queue; no Compute one exists on this GT0)
    put32(&mut exec_wire, 12, 0); // num_syncs
    put64(&mut exec_wire, 16, 0); // syncs
    put64(&mut exec_wire, 24, 0x1000); // batch address array
    exec_wire[32..34].copy_from_slice(&1u16.to_le_bytes()); // num_batches = 1 (mismatches width=2)
    user.wire.store(64, &exec_wire);
    assert_eq!(
        ready(core::pin::pin!(file.dispatch_user(
            &info,
            xe::EXEC,
            64,
            &user
        ))),
        Some(Err(FsError::InvalidData))
    );

    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_parallel_queue_creation_validation_and_media_classes
);
