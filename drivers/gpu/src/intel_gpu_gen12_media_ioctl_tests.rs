// Real Xe ioctl -> private VM/reservation -> main GuC media engine lifecycles.
use super::*;
use crate::intel_gpu_engine::Engine;
use crate::intel_gpu_gt::Gen12Platform;
fn media_gt(family: Gen12Platform) -> (Window, Arena, GuCGt<Window, Arena>) {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Gen12(family), 0x130044);
    w.0.borrow_mut()
        .regs
        .insert(0x9140, 0x000f00ff & !0x00040042);
    hardware_discovery(&mut gt, &w, 0x130044);
    hardware_scheduling(&mut gt, &w);
    let fence = gt.begin_context_defaults(10_000_000).unwrap();
    let mut registered = BTreeMap::new();
    for now in 10_000_001..10_001_025 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, true);
        if fence.result().is_some() {
            break;
        }
    }
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(registered.is_empty());
    (w, arena, gt)
}
fn submit(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &Cpu,
    mailbox: &Mailbox,
    gt: &mut GuCGt<Window, Arena>,
    (queue, now): (u32, u64),
) -> (Arc<UserContext>, Arc<CompletionFence>) {
    exec_wire(user, queue, true, &[sync(2, 0x2345_0000_0090, now, true)]);
    let mut call = core::pin::pin!(file.dispatch_user(info, xe::EXEC, 64, user));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    let result = mailbox.accept(gt, now);
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );
    result
}
fn smoke_xe_gen12_media_query_dense_queues_private_vm_and_user_fence() -> TestResult {
    for family in [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeS,
        Gen12Platform::AlderLakeN,
    ] {
        let (w, arena, mut gt) = media_gt(family);
        let platform = GtPlatform::Gen12(family);
        let (mailbox, info) = setup(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let mut query = [0; 40];
        user.wire.store(64, &query);
        assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
        assert_eq!(u32_at(&user.wire.load(64, 40), 12), 168);
        put32(&mut query, 12, 168);
        put64(&mut query, 16, 1024);
        user.wire.store(64, &query);
        assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
        let reply = user.wire.load(1024, 168);
        assert_eq!(u32_at(&reply, 0), 5);
        for (entry, (class, logical)) in
            reply[8..]
                .chunks_exact(32)
                .zip([(0u16, 0u16), (1, 0), (2, 0), (2, 1), (3, 0)])
        {
            assert_eq!(&entry[..2], &class.to_le_bytes());
            assert_eq!(&entry[2..4], &logical.to_le_bytes());
            assert!(entry[4..].iter().all(|v| *v == 0));
        }
        let vm = create_vm(&file, &info, &user);
        let handles = buffers(&file, &info, &user, vm);
        let data = file.gem.object(handles[1]).unwrap();
        for (class, logical) in [(2u8, 2u8), (2, 6), (3, 1), (3, 2), (4, 0)] {
            user.wire.store(512, &[class, 0, logical, 0, 0, 0, 0, 0]);
            let mut wire = [0; 48];
            put32(&mut wire, 8, 0x00010001);
            put32(&mut wire, 12, vm);
            put64(&mut wire, 24, 512);
            user.wire.store(64, &wire);
            assert_eq!(
                invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
                Err(FsError::InvalidData)
            );
        }
        for (index, (class, logical, engine, base)) in [
            (2, 0, Engine::Vcs1, 0x1c4244),
            (2, 1, Engine::Vcs6, 0x1f0244),
            (3, 0, Engine::Vecs2, 0x1e8244),
        ]
        .into_iter()
        .enumerate()
        {
            let queue = create_queue_instance(&file, &info, &user, vm, class, logical);
            let now = 20_000_000 + index as u64 * 100;
            let (context, fence) = submit(&file, &info, &user, &mailbox, &mut gt, (queue, now));
            assert_eq!(context.engine(), engine);
            assert_eq!(data.read(128, &mut [0; 4]), Err(FsError::WouldBlock));
            let mut registered = BTreeMap::new();
            for tick in now + 1..now + 30 {
                assert_eq!(gt.poll(tick), Poll::Ready(Ok(GtState::SchedulingReady)));
                service_contexts(&w, &mut registered, true);
                if user.read_u64_acquire(0x4090) == Ok(now) {
                    break;
                }
            }
            assert_eq!(user.read_u64_acquire(0x4090), Ok(now));
            assert_eq!(user.read_u64_acquire(0x4080), Ok(0x4e415246));
            assert!(fence.result().is_none());
            assert!(registered
                .values()
                .all(|address| w.0.borrow().memory[address].borrow()[1026] == base));
            finish(&mut gt, &w, &fence, &mut registered, now + 30);
            assert!(registered.is_empty());
            assert!(!context.busy());
            assert_eq!(
                close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
                Ok(0)
            );
        }
        assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
        hardware_stop(&mut gt, &w, 0x130044);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen12",
    smoke_xe_gen12_media_query_dense_queues_private_vm_and_user_fence
);

fn smoke_xe_gen12_media_cancelled_queue_error_capture_and_reset_ownership() -> TestResult {
    use crate::intel_gpu_error::{Reason, Snapshot};
    for (class, engine) in [(2, Engine::Vcs6), (3, Engine::Vecs2)] {
        let (w, arena, mut gt) = media_gt(Gen12Platform::AlderLakeP);
        let platform = GtPlatform::Gen12(Gen12Platform::AlderLakeP);
        let (mailbox, info) = setup(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let queue = create_queue_instance(
            &file,
            &info,
            &user,
            vm,
            class,
            if class == 2 { 1 } else { 0 },
        );
        let handles = buffers(&file, &info, &user, vm);
        let weak = handles.map(|handle| Arc::downgrade(&file.gem.object(handle).unwrap()));
        let (context, fence) = submit(&file, &info, &user, &mailbox, &mut gt, (queue, 30_000_000));
        assert_eq!(context.engine(), engine);
        let mut registered = BTreeMap::new();
        for now in 30_000_001..30_000_025 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, false);
        }
        assert_eq!(registered.len(), 1);
        let report = gt.error_report(
            Reason::Protocol,
            gt.user_epoch().unwrap(),
            30_000_026,
            || true,
            |offset| Some(w.read32(offset)),
        );
        let report = Snapshot {
            report,
            suppressed: 0,
        }
        .text();
        assert!(report.contains("register_access=Complete\n"));
        assert!(report.contains(if class == 2 {
            "placements=0x2000 " // Stable VCS6 slot13.
        } else {
            "placements=0x20000 " // Stable VECS2 slot17.
        }));
        assert_eq!(
            close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
            Ok(0)
        );
        assert!(context.banned());
        for handle in handles {
            assert_eq!(close(&file, &info, &user, abi::GEM_CLOSE, handle), Ok(0));
        }
        assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
        user.mapping.lock().take();
        let live = arena.live_allocations();
        assert!(weak.iter().all(|o| o.upgrade().is_some()));
        assert!(fence.result().is_none());
        // Loss prevents a terminal disable/deregister/TLB receipt. Reset is
        // required before any old page, reservation or user fence is released.
        assert!(gt.poll_with_access(30_000_030, || false).is_ready());
        assert_eq!(gt.state(), GtState::Lost);
        assert!(fence.result().is_none());
        assert_eq!(arena.live_allocations(), live);
        hardware_stop(&mut gt, &w, 0x130044);
        assert_eq!(fence.result(), Some(Err(JobError::Reset)));
        assert!(!context.busy());
        assert!(weak.iter().all(|o| o.upgrade().is_none()));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen12",
    smoke_xe_gen12_media_cancelled_queue_error_capture_and_reset_ownership
);
