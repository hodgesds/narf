// Real Xe HIGH admission/policy. Linux b90c984d xe_exec_queue.c556–574,
// xe_query.c312–350 and xe_guc_submit.c498–523 supply the literal ABI.
use super::*;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static NICE: AtomicBool = AtomicBool::new(false);
static CHECKS: AtomicUsize = AtomicUsize::new(0);
fn capable(cap: u32) -> bool {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    cap == 23 && NICE.load(Ordering::Acquire)
}
struct Caller(Option<fn(u32) -> bool>);
impl Caller {
    fn new(nice: bool) -> Self {
        NICE.store(nice, Ordering::Release);
        CHECKS.store(0, Ordering::Relaxed);
        Self(narf_filesystem::__test_swap_caller_capable_hook(Some(
            capable,
        )))
    }
}
impl Drop for Caller {
    fn drop(&mut self) {
        narf_filesystem::__test_swap_caller_capable_hook(self.0);
    }
}
fn property(user: &Cpu, value: u64) {
    let mut ext = [0; 48];
    put64(&mut ext, 24, value); // extension0/property0
    user.wire.store(8192, &ext);
    user.wire.store(64, &8192u64.to_le_bytes());
}
fn create_priority(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &Cpu,
    vm: u32,
    rows: &[[u16; 4]],
    width: u16,
    value: u64,
) -> u32 {
    queue_wire(user, vm, width, rows.len() as u16 / width, rows);
    property(user, value);
    assert_eq!(invoke(file, info, user, xe::EXEC_QUEUE_CREATE), Ok(0));
    u32_at(&user.wire.load(64, 48), 20)
}
fn config(user: &Cpu, size: u32, pointer: u64) {
    let mut wire = [0; 40];
    put32(&mut wire, 8, 2);
    put32(&mut wire, 12, size);
    put64(&mut wire, 16, pointer);
    user.wire.store(64, &wire);
}
fn registered_info(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    platform: GtPlatform,
) -> (Arc<Mailbox>, DeviceInfo, u32) {
    let (mailbox, info) = setup(gt, w, platform);
    let card = Arc::new(crate::drm_devfs_bridge::IntelGpuCard::new(
        alloc::string::String::new(),
        0x8086,
        info.device_id,
        0,
        0,
    ));
    card.install_user_backend(info.backend.unwrap()).unwrap();
    card.publish_gt_topology(gt).unwrap();
    let index = crate::drm_registry::register_drm_card(card);
    let info = DeviceInfo::for_card(index).unwrap();
    assert!(info.native_xe() && info.submission_ready());
    (mailbox, info, index)
}
// Independently decode pending CT bytes, before the firmware consumes them.
fn policy(w: &Window, priority: u32) -> bool {
    let memory = ct_memory(w);
    let words = memory.borrow();
    let mut head = words[0];
    let tail = words[1];
    let mut found = false;
    while head != tail {
        let length = words[1024 + head as usize] & 255;
        if words[1024 + ((head + 1) & 1023) as usize] as u16 == 0x100b {
            let got: Vec<_> = (3..=8)
                .map(|n| words[1024 + ((head + n) & 1023) as usize])
                .collect();
            assert_eq!(
                got,
                [0x20030001, priority, 0x20010001, 1000, 0x20020001, 500000]
            );
            found = true;
        }
        head = (head + length + 1) & 1023;
    }
    found
}
fn run_policy(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    fence: &CompletionFence,
    registered: &mut BTreeMap<u32, u32>,
    start: u64,
    priority: u32,
) {
    let mut observed = false;
    for now in start..start + 100 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        observed |= policy(w, priority);
        service_contexts(w, registered, true);
        if fence.result().is_some() {
            break;
        }
    }
    assert!(observed, "no priority policy reached GuC");
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(registered.is_empty());
}

fn smoke_xe_priority_current_authority_config_size_and_refusals() -> TestResult {
    let _caller = Caller::new(false);
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (_, info, card) = registered_info(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    for nice in [false, true, false] {
        NICE.store(nice, Ordering::Release);
        CHECKS.store(0, Ordering::Relaxed);
        user.wire.store(1024, &[0xa5; 48]);
        config(&user, 0, u64::MAX);
        assert_eq!(
            file.dispatch_card(card, xe::DEVICE_QUERY, 64, &user),
            Some(Ok(0))
        );
        assert_eq!(u32_at(&user.wire.load(64, 40), 12), 48);
        assert_eq!(user.wire.load(1024, 48), [0xa5; 48]);
        assert_eq!(
            CHECKS.load(Ordering::Relaxed),
            0,
            "size-only queried privilege"
        );
        config(&user, 47, u64::MAX);
        assert_eq!(
            invoke(&file, &info, &user, xe::DEVICE_QUERY),
            Err(FsError::InvalidData)
        );
        assert_eq!(CHECKS.load(Ordering::Relaxed), 0);
        config(&user, 48, 1024);
        assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
        assert_eq!(
            u64_at(&user.wire.load(1024, 48), 40),
            if nice { 2 } else { 1 }
        );
    }
    let retained = arena.live_allocations();
    let writes = w.0.borrow().writes.len();
    for (value, expected) in [
        (2, FsError::OperationNotPermitted),
        (3, FsError::InvalidData),
        (u64::MAX, FsError::InvalidData),
    ] {
        queue_wire(&user, vm, 1, 1, &[[0, 0, 0, 0]]);
        property(&user, value);
        assert_eq!(
            invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
            Err(expected)
        );
        assert_eq!(u32_at(&user.wire.load(64, 48), 20), 0);
    }
    narf_filesystem::__test_swap_caller_capable_hook(None);
    queue_wire(&user, vm, 1, 1, &[[0, 0, 0, 0]]);
    property(&user, 2);
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::OperationNotPermitted)
    );
    narf_filesystem::__test_swap_caller_capable_hook(Some(capable));
    // Pinned platform descriptors do not enable CGP on any qualified card.
    let mut ext = [0; 48];
    put32(&mut ext, 16, 4);
    put64(&mut ext, 24, 1 << 63);
    user.wire.store(8192, &ext);
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::NotImplemented)
    );
    assert_eq!(
        UserContext::new().configure_schedule(0, 1000),
        Err(FsError::InvalidData)
    );
    assert_eq!(arena.live_allocations(), retained);
    assert_eq!(w.0.borrow().writes.len(), writes);
    assert_eq!(
        create_priority(&file, &info, &user, vm, &[[0, 0, 0, 0]], 1, 1),
        1
    );
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_priority_current_authority_config_size_and_refusals
);

fn smoke_xe_priority_publication_rechecks_and_failed_copyout_consume_no_queue() -> TestResult {
    struct Revoke<'a>(&'a Cpu);
    impl IoctlContext for Revoke<'_> {
        fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), FsError> {
            self.0.read(address, bytes)?;
            if address == 8240 {
                NICE.store(false, Ordering::Release);
            }
            Ok(())
        }
        fn write(&self, address: u64, bytes: &[u8]) -> Result<(), FsError> {
            self.0.write(address, bytes)
        }
        fn nonblocking(&self) -> bool {
            false
        }
    }
    let _caller = Caller::new(true);
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (_, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let retained = arena.live_allocations();
    let writes = w.0.borrow().writes.len();
    queue_wire(&user, vm, 1, 1, &[[1, 0, 0, 0]]);
    property(&user, 2);
    user.wire.store(8192, &8240u64.to_le_bytes());
    let mut next = [0; 48];
    put32(&mut next, 16, 1);
    put64(&mut next, 24, 1000);
    user.wire.store(8240, &next);
    assert_eq!(
        file.dispatch(&info, xe::EXEC_QUEUE_CREATE, 64, &Revoke(&user)),
        Some(Err(FsError::OperationNotPermitted))
    );
    assert_eq!(CHECKS.load(Ordering::Relaxed), 2);
    assert_eq!(u32_at(&user.wire.load(64, 48), 20), 0);
    assert_eq!(arena.live_allocations(), retained);
    assert_eq!(w.0.borrow().writes.len(), writes);
    NICE.store(true, Ordering::Release);
    user.fail_report.store(true, Ordering::Release);
    queue_wire(&user, vm, 1, 1, &[[0, 0, 0, 0]]);
    property(&user, 2);
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::BadAddress)
    );
    user.fail_report.store(false, Ordering::Release);
    assert_eq!(
        create_priority(&file, &info, &user, vm, &[[0, 0, 0, 0]], 1, 2),
        1
    );
    NICE.store(false, Ordering::Release);
    assert_eq!(
        create_priority(&file, &info, &user, vm, &[[1, 0, 0, 0]], 1, 0),
        2
    );
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_priority_publication_rechecks_and_failed_copyout_consume_no_queue
);

fn smoke_xe_priority_real_rcs_copy_policy_and_retained_creator_grant() -> TestResult {
    let _caller = Caller::new(false);
    for platform in [
        GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
        GtPlatform::Alchemist,
        GtPlatform::Battlemage,
    ] {
        let ack = if platform == GtPlatform::Alchemist {
            0x130044
        } else {
            0xdfc
        };
        let (w, arena, mut gt) = hardware_model(platform, ack);
        prime(&mut gt, &w, ack);
        let (mailbox, info, card) = registered_info(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let handles = buffers(&file, &info, &user, vm);
        let mut now = 500;
        for class in [0, 1] {
            for (requested, firmware) in [(0, 3), (1, 2), (2, 1)] {
                NICE.store(true, Ordering::Release);
                queue_wire(&user, vm, 1, 1, &[[class, 0, 0, 0]]);
                property(&user, requested);
                assert_eq!(
                    file.dispatch_card(card, xe::EXEC_QUEUE_CREATE, 64, &user),
                    Some(Ok(0))
                );
                let queue = u32_at(&user.wire.load(64, 48), 20);
                NICE.store(false, Ordering::Release);
                // Source-shaped object grant: later loss changes new queue
                // admission/query, never this immutable configured policy.
                let checks = CHECKS.load(Ordering::Relaxed);
                for _ in 0..2 {
                    file.gem
                        .object(handles[1])
                        .unwrap()
                        .write(0x80, &[0; 8])
                        .unwrap();
                    exec_wire(&user, queue, true, &[]);
                    let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, now);
                    let mut registered = BTreeMap::new();
                    run_policy(&mut gt, &w, &fence, &mut registered, now + 1, firmware);
                    assert_eq!(user.read_u64_acquire(0x4080), Ok(0x4e415246));
                    assert!(!context.busy() && !context.banned());
                    now += 200;
                }
                assert_eq!(
                    CHECKS.load(Ordering::Relaxed),
                    checks,
                    "EXEC reauthorized a retained queue grant"
                );
                assert_eq!(
                    close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
                    Ok(0)
                );
            }
        }
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_priority_real_rcs_copy_policy_and_retained_creator_grant
);

fn smoke_xe_priority_virtual_and_parallel_migration_preserve_policy_and_gpu_join() -> TestResult {
    let _caller = Caller::new(true);
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt, ack) = discover(platform, 15);
    prime_mode(&mut gt, &w, 4);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let handles = buffers(&file, &info, &user, vm);
    for width in [1, 2] {
        NICE.store(true, Ordering::Release);
        let rows = if width == 1 {
            alloc::vec![[4, 0, 0, 0], [4, 1, 0, 0]]
        } else {
            alloc::vec![[4, 0, 0, 0], [4, 1, 0, 0], [4, 1, 0, 0], [4, 2, 0, 0]]
        };
        let queue = create_priority(&file, &info, &user, vm, &rows, width, 2);
        NICE.store(false, Ordering::Release);
        property(&user, 0); // userspace cannot change the copied policy
        let checks = CHECKS.load(Ordering::Relaxed);
        for chosen in [0, 1] {
            w.0.borrow_mut().virtual_pick = Some(chosen);
            file.gem
                .object(handles[1])
                .unwrap()
                .write(0x80, &[0; 32])
                .unwrap();
            let now = 500 + u64::from(width) * 1000 + u64::from(chosen) * 200;
            if width == 1 {
                exec_wire(&user, queue, true, &[]);
            } else {
                exec_parallel(
                    &user,
                    queue,
                    [0x1234_0000_0000; 2],
                    &[sync(
                        2,
                        0x2345_0000_0090,
                        0xfeed0000 + u64::from(chosen),
                        true,
                    )],
                );
            }
            let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, now);
            let mut registered = BTreeMap::new();
            run_policy(&mut gt, &w, &fence, &mut registered, now + 1, 1);
            assert_eq!(user.read_u64_acquire(0x4080), Ok(0x4e415246));
            if width == 2 {
                assert_eq!(
                    user.read_u64_acquire(0x4090),
                    Ok(0xfeed0000 + u64::from(chosen))
                );
            }
            assert!(!context.busy() && !context.banned());
            assert!(w.0.borrow().virtual_contexts.is_empty());
        }
        assert_eq!(CHECKS.load(Ordering::Relaxed), checks);
        assert_eq!(
            close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
            Ok(0)
        );
    }
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_priority_virtual_and_parallel_migration_preserve_policy_and_gpu_join
);

fn smoke_xe_priority_canceled_parallel_ioctl_close_retains_until_full_reset() -> TestResult {
    let _caller = Caller::new(true);
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt, ack) = discover(platform, 15);
    prime_mode(&mut gt, &w, 4);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let queue = create_priority(&file, &info, &user, vm, &[[4, 0, 0, 0], [4, 1, 0, 0]], 2, 2);
    let handles = buffers(&file, &info, &user, vm);
    let weak = handles.map(|handle| Arc::downgrade(&file.gem.object(handle).unwrap()));
    NICE.store(false, Ordering::Release);
    exec_parallel(&user, queue, [0x1234_0000_0000; 2], &[]);
    let (context, fence) = {
        let mut call = Box::pin(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let accepted = mailbox.accept(&mut gt, 500);
        drop(call); // caller cancellation never proves device stop
        accepted
    };
    let mut registered = BTreeMap::new();
    let mut observed = false;
    for now in 501..540 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        observed |= policy(&w, 1);
        service_contexts(&w, &mut registered, false);
    }
    assert!(observed && context.busy() && fence.result().is_none());
    let retained = arena.live_allocations();
    assert_eq!(
        close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
        Ok(0)
    );
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
    for handle in handles {
        assert_eq!(close(&file, &info, &user, abi::GEM_CLOSE, handle), Ok(0));
    }
    user.mapping.lock().take();
    drop(file);
    assert!(context.banned() && context.busy() && fence.result().is_none());
    assert_eq!(context.reset_stats(), (0, 0));
    assert_eq!(arena.live_allocations(), retained);
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    hardware_stop(&mut gt, &w, ack);
    assert_eq!(fence.result(), Some(Err(JobError::Reset)));
    assert_eq!(context.reset_stats(), (0, 1));
    assert!(!context.busy());
    assert!(weak.iter().all(|object| object.upgrade().is_none()));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_priority_canceled_parallel_ioctl_close_retains_until_full_reset
);
