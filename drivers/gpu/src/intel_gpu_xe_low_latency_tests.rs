// Raw Xe queue flags -> retained policy -> actual GuC CT, not a codec fixture.
// MIT Linux b90c984d: xe_exec_queue.c1105–1122, xe_guc_submit.c505–526,
// guc_klvs_abi.h133 and guc_actions_slpc_abi.h177 give independent literals.
use super::*;

fn create_hint(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &Cpu,
    vm: u32,
    width: u16,
    rows: &[[u16; 4]],
    flags: u32,
) -> Result<u32, FsError> {
    queue_wire(user, vm, width, rows.len() as u16 / width, rows);
    user.wire.store(80, &flags.to_le_bytes());
    invoke(file, info, user, xe::EXEC_QUEUE_CREATE)?;
    Ok(u32_at(&user.wire.load(64, 48), 20))
}
fn pending(w: &Window) -> Vec<Vec<u32>> {
    let memory = ct_memory(w);
    let words = memory.borrow();
    let (mut head, tail) = (words[0], words[1]);
    let mut requests = Vec::new();
    while head != tail {
        let count = words[1024 + head as usize] & 255;
        requests.push(
            (1..=count)
                .map(|n| words[1024 + ((head + n) & 1023) as usize])
                .collect(),
        );
        head = (head + count + 1) & 1023;
    }
    requests
}
fn hint_policy(w: &Window, hint: bool) -> bool {
    let mut seen = false;
    for request in pending(w) {
        if request[0] as u16 != 0x100b {
            continue;
        }
        assert_eq!(request.len(), 10);
        assert_eq!(
            &request[2..],
            &[
                0x20030001,
                2,
                0x20010001,
                1000,
                0x20020001,
                500000,
                0x20050001,
                if hint { 0x10000000 } else { 0 }
            ]
        );
        seen = true;
    }
    seen
}
fn run_hint(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    fence: &CompletionFence,
    registered: &mut BTreeMap<u32, u32>,
    start: u64,
    hint: bool,
) {
    let mut seen = false;
    let mut enabled = false;
    for now in start..start + 100 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if hint_policy(w, hint) {
            assert!(!enabled, "policy published after scheduling enable");
            assert!(!narf_filesystem::DrmFence::is_submit_ready(fence));
            seen = true;
        }
        let enable = pending(w)
            .iter()
            .any(|r| r[0] as u16 == 0x1001 && r[2] == 1);
        if enable {
            assert!(seen, "enable overtook retained context policy");
            assert!(!narf_filesystem::DrmFence::is_submit_ready(fence));
            enabled = true;
        }
        service_contexts(w, registered, true);
        if enable {
            assert!(
                !narf_filesystem::DrmFence::is_submit_ready(fence),
                "firmware enqueue alone acknowledged scheduling"
            );
        }
        if fence.result().is_some() {
            break;
        }
    }
    assert!(seen && enabled);
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(registered.is_empty());
}
fn config_flags(file: &RenderFile, info: &DeviceInfo, user: &Cpu) -> u64 {
    let mut wire = [0; 40];
    put32(&mut wire, 8, 2);
    put32(&mut wire, 12, 48);
    put64(&mut wire, 16, 1024);
    user.wire.store(64, &wire);
    assert_eq!(invoke(file, info, user, xe::DEVICE_QUERY), Ok(0));
    u64_at(&user.wire.load(1024, 48), 16)
}

fn smoke_xe_low_latency_raw_config_flags_refusals_and_copyout_rollback() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    assert_eq!(config_flags(&file, &info, &user), 10);
    let before = arena.live_allocations();
    let writes = w.0.borrow().writes.len();
    for (rows, flags, error) in [
        ([[0, 0, 0, 0]], 2, FsError::InvalidData),
        ([[0, 0, 0, 0]], u32::MAX, FsError::InvalidData),
        ([[5, 0, 0, 0]], 1, FsError::Unsupported),
        ([[4, 9, 0, 0]], 1, FsError::InvalidData),
    ] {
        assert_eq!(
            create_hint(&file, &info, &user, vm, 1, &rows, flags),
            Err(error)
        );
    }
    // There is no create property or dynamic low-latency mutation in Xe.
    // Unknown properties and the unsupported runtime setter stay refused.
    for property in [2, 3, 6] {
        queue_wire(&user, vm, 1, 1, &[[0, 0, 0, 0]]);
        let mut ext = [0; 48];
        put32(&mut ext, 16, property);
        user.wire.store(8192, &ext);
        user.wire.store(64, &8192u64.to_le_bytes());
        assert_eq!(
            invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
            Err(FsError::NotImplemented)
        );
    }
    assert_eq!(
        invoke(&file, &info, &user, 0x4028644e),
        Err(FsError::InvalidData)
    );
    let good = mailbox.status().unwrap();
    assert_eq!(good.submission_version, (1, 0, 0)); // submission ABI, not CSS 70.x
                                                    // ABI1 minor revisions retain the source policy key; major0/2 and an
                                                    // unpublished engine set must not acquire the public capability.
    *mailbox.status.lock() = Some(UserStatus {
        submission_version: (1, 7, 3),
        ..good
    });
    assert_eq!(config_flags(&file, &info, &user) & 2, 2);
    for bad in [
        None,
        Some(UserStatus { epoch: 0, ..good }),
        Some(UserStatus {
            submission_version: (0, 255, 255),
            ..good
        }),
        Some(UserStatus {
            submission_version: (2, 0, 0),
            ..good
        }),
        Some(UserStatus {
            engines: crate::intel_gpu_engine::EngineSet::default(),
            ..good
        }),
        Some(UserStatus {
            platform: GtPlatform::Alchemist,
            ..good
        }),
    ] {
        *mailbox.status.lock() = bad;
        assert_eq!(config_flags(&file, &info, &user) & 2, 0);
        assert_eq!(
            create_hint(&file, &info, &user, vm, 1, &[[0, 0, 0, 0]], 1),
            Err(if info.submission_ready() {
                FsError::Unsupported
            } else {
                FsError::NoDevice
            })
        );
    }
    *mailbox.status.lock() = Some(good);
    user.fail_report
        .store(true, core::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        create_hint(&file, &info, &user, vm, 1, &[[0, 0, 0, 0]], 1),
        Err(FsError::BadAddress)
    );
    user.fail_report
        .store(false, core::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        create_hint(&file, &info, &user, vm, 1, &[[0, 0, 0, 0]], 1),
        Ok(1)
    );
    assert_eq!(arena.live_allocations(), before);
    assert_eq!(
        w.0.borrow().writes.len(),
        writes,
        "refusal/create changed GPU state"
    );
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_low_latency_raw_config_flags_refusals_and_copyout_rollback
);

fn smoke_xe_low_latency_all_qualified_profiles_submission_abi_and_retained_context() -> TestResult {
    use crate::intel_gpu::Generation;
    use crate::intel_gpu_gt::Gen12Platform;
    for (platform, ack) in [
        (GtPlatform::Gen12(Gen12Platform::TigerLake), 0x130044),
        (GtPlatform::Gen12(Gen12Platform::AlderLakeS), 0x130044),
        (GtPlatform::Gen12(Gen12Platform::AlderLakeP), 0x130044),
        (GtPlatform::Gen12(Gen12Platform::AlderLakeN), 0x130044),
        (GtPlatform::Alchemist, 0x130044),
        (GtPlatform::Integrated(Generation::MeteorLake), 0xdfc),
        (GtPlatform::Integrated(Generation::LunarLake), 0xdfc),
        (GtPlatform::Integrated(Generation::PantherLake), 0xdfc),
        (GtPlatform::Battlemage, 0xdfc),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        prime(&mut gt, &w, ack);
        let (mailbox, info) = setup(&mut gt, &w, platform);
        assert_eq!(mailbox.status().unwrap().submission_version, (1, 0, 0));
        assert!(crate::intel_gpu_xe::low_latency_supported(&info));
        let file = RenderFile::new();
        let user = Cpu::new();
        assert_eq!(config_flags(&file, &info, &user) & 2, 2);
        let vm = create_vm(&file, &info, &user);
        let handles = buffers(&file, &info, &user, vm);
        let mut registered = BTreeMap::new();
        for (iteration, hint) in [false, true].into_iter().enumerate() {
            let queue =
                create_hint(&file, &info, &user, vm, 1, &[[0, 0, 0, 0]], u32::from(hint)).unwrap();
            let mut previous: Option<Arc<UserContext>> = None;
            for pass in 0..2 {
                // Rewriting the original user flag cannot change the queue.
                user.wire.store(80, &u32::from(!hint).to_le_bytes());
                file.gem
                    .object(handles[1])
                    .unwrap()
                    .write(0x80, &[0; 8])
                    .unwrap();
                exec_wire(&user, queue, true, &[]);
                let now = 500 + iteration as u64 * 400 + pass * 100;
                let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, now);
                if let Some(old) = &previous {
                    assert!(Arc::ptr_eq(old, &context));
                }
                assert_eq!(context.configure_low_latency(), Err(FsError::Busy));
                run_hint(&mut gt, &w, &fence, &mut registered, now + 1, hint);
                assert_eq!(user.read_u64_acquire(0x4080), Ok(0x4e415246));
                assert!(!context.busy() && !context.banned());
                previous = Some(context);
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
    smoke_xe_low_latency_all_qualified_profiles_submission_abi_and_retained_context
);

fn smoke_xe_low_latency_virtual_parallel_migration_preserves_policy_and_join() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt, ack) = discover(platform, 15);
    prime_mode(&mut gt, &w, 4);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let handles = buffers(&file, &info, &user, vm);
    for width in [1, 2] {
        let rows = if width == 1 {
            alloc::vec![[4, 0, 0, 0], [4, 1, 0, 0]]
        } else {
            alloc::vec![[4, 0, 0, 0], [4, 1, 0, 0], [4, 1, 0, 0], [4, 2, 0, 0]]
        };
        let queue = create_hint(&file, &info, &user, vm, width, &rows, 1).unwrap();
        let mut old: Option<Arc<UserContext>> = None;
        for chosen in [0, 1] {
            w.0.borrow_mut().virtual_pick = Some(chosen);
            file.gem
                .object(handles[1])
                .unwrap()
                .write(0x80, &[0; 32])
                .unwrap();
            if width == 1 {
                exec_wire(&user, queue, true, &[]);
            } else {
                exec_parallel(
                    &user,
                    queue,
                    [0x1234_0000_0000; 2],
                    &[sync(2, 0x2345_0000_0090, 0xfeed + u64::from(chosen), true)],
                );
            }
            let now = 500 + u64::from(width) * 1000 + u64::from(chosen) * 200;
            let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, now);
            if let Some(previous) = &old {
                assert!(Arc::ptr_eq(previous, &context));
            }
            run_hint(&mut gt, &w, &fence, &mut BTreeMap::new(), now + 1, true);
            assert_eq!(user.read_u64_acquire(0x4080), Ok(0x4e415246));
            if width == 2 {
                assert_eq!(
                    user.read_u64_acquire(0x4090),
                    Ok(0xfeed + u64::from(chosen))
                );
            }
            assert!(!context.busy() && !context.banned());
            old = Some(context);
        }
    }
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_low_latency_virtual_parallel_migration_preserves_policy_and_join
);

fn smoke_xe_low_latency_cancel_close_and_missing_enable_ack_retain_every_lane_until_reset(
) -> TestResult {
    for lose_ack in [false, true] {
        let platform = GtPlatform::Battlemage;
        let (w, arena, mut gt, ack) = discover(platform, 15);
        prime_mode(&mut gt, &w, 4);
        let (mailbox, info) = setup(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let queue =
            create_hint(&file, &info, &user, vm, 2, &[[4, 0, 0, 0], [4, 1, 0, 0]], 1).unwrap();
        let handles = buffers(&file, &info, &user, vm);
        let weak = handles.map(|handle| Arc::downgrade(&file.gem.object(handle).unwrap()));
        exec_parallel(&user, queue, [0x1234_0000_0000; 2], &[]);
        let (context, fence) = {
            let mut call = Box::pin(file.dispatch_user(&info, xe::EXEC, 64, &user));
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            let result = mailbox.accept(&mut gt, 500);
            drop(call);
            result
        };
        let mut registered = BTreeMap::new();
        let mut policy = false;
        let mut enabled = false;
        for now in 501..540 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            policy |= hint_policy(&w, true);
            if service_contexts(&w, &mut registered, false).contains(&0x1001) {
                assert!(policy);
                assert!(!narf_filesystem::DrmFence::is_submit_ready(&*fence));
                if lose_ack {
                    drop_reply(&w);
                }
                enabled = true;
                break;
            }
        }
        assert!(policy && enabled);
        if lose_ack {
            assert_eq!(
                gt.poll(5_000_001_000),
                Poll::Ready(Err(GtError::Scheduling(
                    crate::intel_gpu_guc_sched::SchedulingError::Timeout
                )))
            );
            assert!(!narf_filesystem::DrmFence::is_submit_ready(&*fence));
        } else {
            for now in 541..550 {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                service_contexts(&w, &mut registered, false);
            }
            assert!(narf_filesystem::DrmFence::is_submit_ready(&*fence));
        }
        let retained = arena.live_allocations();
        let group =
            w.0.borrow()
                .parallel_contexts
                .values()
                .next()
                .unwrap()
                .clone();
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
        assert!(context.busy() && context.banned() && fence.result().is_none());
        assert_eq!(context.reset_stats(), (0, 0));
        assert_eq!(arena.live_allocations(), retained);
        assert!(weak.iter().all(|object| object.upgrade().is_some()));
        assert!(group
            .images
            .iter()
            .all(|base| w.0.borrow().memory.contains_key(base)));
        assert!(w.0.borrow().memory.contains_key(&group.scratch));
        hardware_stop(&mut gt, &w, ack);
        assert_eq!(fence.result(), Some(Err(JobError::Reset)));
        assert_eq!(context.reset_stats(), (0, 1));
        assert!(!context.busy());
        assert!(weak.iter().all(|object| object.upgrade().is_none()));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_low_latency_cancel_close_and_missing_enable_ack_retain_every_lane_until_reset
);

fn smoke_xe_low_latency_obeys_acknowledged_global_frequency_and_power_policy() -> TestResult {
    use crate::intel_gpu_slpc::{FrequencyRange, PowerProfile, SlpcState};
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    SLPC_FIXTURE_MODE.store(0, core::sync::atomic::Ordering::Relaxed);
    let mut registered = BTreeMap::new();
    let drive = |gt: &mut GuCGt<Window, Arena>, registered: &mut BTreeMap<u32, u32>, start| {
        for now in start..start + 40 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, registered, true);
        }
    };
    gt.begin_slpc(500).unwrap();
    drive(&mut gt, &mut registered, 501);
    assert_eq!(gt.slpc(), SlpcState::Running);
    gt.begin_slpc_frequency_range(
        FrequencyRange {
            min_mhz: 1250,
            max_mhz: 2000,
        },
        550,
    )
    .unwrap();
    drive(&mut gt, &mut registered, 551);
    gt.begin_slpc_power_profile(PowerProfile::PowerSaving, 600)
        .unwrap();
    drive(&mut gt, &mut registered, 601);
    let status = gt.slpc_status().unwrap();
    assert_eq!(
        status.range,
        FrequencyRange {
            min_mhz: 1250,
            max_mhz: 2000
        }
    );
    assert_eq!(status.profile, PowerProfile::PowerSaving);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let queue = create_hint(&file, &info, &user, vm, 1, &[[0, 0, 0, 0]], 1).unwrap();
    let _ = buffers(&file, &info, &user, vm);
    exec_wire(&user, queue, true, &[]);
    let (_, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 700);
    let mut seen = false;
    for now in 701..800 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        seen |= hint_policy(&w, true);
        assert!(
            pending(&w).iter().all(|r| r[0] as u16 != 0x3003),
            "queue bypassed the global SLPC owner"
        );
        service_contexts(&w, &mut registered, true);
        assert_eq!(gt.slpc_status(), Some(status));
        if fence.result().is_some() {
            break;
        }
    }
    assert!(seen);
    assert_eq!(fence.result(), Some(Ok(())));
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_low_latency_obeys_acknowledged_global_frequency_and_power_policy
);

fn smoke_xe_low_latency_reset_epoch_refuses_old_context_and_fresh_queue_rewrites_policy(
) -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let queue = create_hint(&file, &info, &user, vm, 1, &[[0, 0, 0, 0]], 1).unwrap();
    let _ = buffers(&file, &info, &user, vm);
    exec_wire(&user, queue, true, &[]);
    let (old, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 500);
    run_hint(&mut gt, &w, &fence, &mut BTreeMap::new(), 501, true);
    let epoch = gt.user_epoch().unwrap();
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    assert_ne!(gt.user_epoch(), Some(epoch));
    let baseline = arena.live_allocations();
    let (batch, _) = PpgttProbeResult::prepare(platform).unwrap();
    assert!(gt
        .submit_user_batch(500, old.clone(), UserBatch(batch))
        .is_err());
    assert_eq!(arena.live_allocations(), baseline);
    assert!(old.banned());
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let queue = create_hint(&file, &info, &user, vm, 1, &[[0, 0, 0, 0]], 1).unwrap();
    let _ = buffers(&file, &info, &user, vm);
    exec_wire(&user, queue, true, &[]);
    let (new, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 500);
    assert!(!Arc::ptr_eq(&old, &new));
    run_hint(&mut gt, &w, &fence, &mut BTreeMap::new(), 501, true);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_low_latency_reset_epoch_refuses_old_context_and_fresh_queue_rewrites_policy
);
