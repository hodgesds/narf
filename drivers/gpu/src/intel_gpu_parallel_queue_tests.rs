// Actual Xe ioctl -> multi-LRC GuC registration/WQ -> two private rings ->
// all-lane retirement. MIT Linux b90c984d xe_exec{,_queue}.c,
// xe_guc_submit.c and xe_guc_submit_types.h supply the literal wire vectors.
use super::*;

fn queue_wire(user: &Cpu, vm: u32, width: u16, placements: u16, lanes: &[[u16; 4]]) {
    let bytes: Vec<_> = lanes
        .iter()
        .flatten()
        .flat_map(|n| n.to_le_bytes())
        .collect();
    user.wire.store(512, &bytes);
    let mut wire = [0; 48];
    put32(&mut wire, 8, u32::from(width) | u32::from(placements) << 16);
    put32(&mut wire, 12, vm);
    put64(&mut wire, 24, 512);
    user.wire.store(64, &wire);
}
fn create_parallel(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &Cpu,
    vm: u32,
    class: u16,
    first: u16,
) -> u32 {
    queue_wire(
        user,
        vm,
        2,
        1,
        &[[class, first, 0, 0], [class, first + 1, 0, 0]],
    );
    assert_eq!(invoke(file, info, user, xe::EXEC_QUEUE_CREATE), Ok(0));
    u32_at(&user.wire.load(64, 48), 20)
}
fn exec_parallel(user: &Cpu, queue: u32, addresses: [u64; 2], syncs: &[[u8; 48]]) {
    let mut wire = [0; 56];
    put32(&mut wire, 8, queue);
    put32(&mut wire, 12, syncs.len() as u32);
    put64(&mut wire, 16, 2048);
    put64(&mut wire, 24, 768);
    wire[32] = 2;
    user.wire.store(
        768,
        &addresses
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    user.wire.store(2048, &syncs.concat());
    user.wire.store(64, &wire);
}
fn accept(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &Cpu,
    mailbox: &Mailbox,
    gt: &mut GuCGt<Window, Arena>,
    now: u64,
) -> (Arc<UserContext>, Arc<CompletionFence>) {
    let mut call = core::pin::pin!(file.dispatch_user(info, xe::EXEC, 64, user));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    // Neither the placement row nor the batch-address vector remains a user
    // reference across the backend wait.
    let width = usize::from(u16::from_le_bytes(
        user.wire.load(64 + 32, 2).try_into().unwrap(),
    ))
    .max(2);
    user.wire.store(512, &alloc::vec![0xff; width * 8]);
    user.wire.store(768, &alloc::vec![0xff; width * 8]);
    let accepted = mailbox.accept(gt, now);
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );
    accepted
}
fn dispatch(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    registered: &mut BTreeMap<u32, u32>,
    start: u64,
    execute: bool,
) -> (u32, ParallelContext) {
    let mut actions = Vec::new();
    for now in start..start + 40 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        let current = service_contexts(w, registered, execute);
        let submitted = current.contains(&0x1000);
        actions.extend(current);
        if submitted {
            break;
        }
    }
    let actions: Vec<_> = actions
        .into_iter()
        .filter(|a| matches!(a, 0x7000 | 0x4601 | 0x100b | 0x1001 | 0x1000))
        .collect();
    assert_eq!(actions, [0x7000, 0x4601, 0x100b, 0x1001, 0x1000]);
    let d = w.0.borrow();
    assert_eq!(d.parallel_contexts.len(), 1);
    let (&id, group) = d.parallel_contexts.iter().next().unwrap();
    let group = group.clone();
    assert_eq!(registered.len(), group.images.len());
    for (index, base) in group.images.iter().enumerate() {
        assert_eq!(registered[&(id + index as u32)], *base);
    }
    assert_ne!(group.images[0], group.images[1]);
    (id, group)
}
fn exec_refusal(file: &RenderFile, info: &DeviceInfo, user: &Cpu) -> Result<u64, FsError> {
    match core::pin::pin!(file.dispatch_user(info, xe::EXEC, 64, user))
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Some(result)) => result,
        _ => panic!("parallel EXEC refusal parked"),
    }
}
fn smoke_parallel_queue_matrix_copy_fault_and_join_store_refusal() -> TestResult {
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 15);
    prime_mode(&mut gt, &w, 4);
    let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let baseline = arena.live_allocations();
    for (width, count, lanes) in [
        (0, 1, alloc::vec![[4, 0, 0, 0]]),
        (5, 1, alloc::vec![[4, 0, 0, 0]; 5]),
        (2, 2, alloc::vec![[4, 0, 0, 0]; 4]),
        (2, 1, alloc::vec![[0, 0, 0, 0]; 2]),
        (2, 1, alloc::vec![[5, 0, 0, 0]; 2]),
        (2, 1, alloc::vec![[4, 0, 0, 0], [1, 1, 0, 0]]),
        (2, 1, alloc::vec![[4, 0, 0, 0], [4, 0, 0, 0]]),
        (2, 1, alloc::vec![[4, 1, 0, 0], [4, 0, 0, 0]]),
        (2, 1, alloc::vec![[4, 0, 0, 0], [4, 2, 0, 0]]),
        (2, 1, alloc::vec![[1, 0, 0, 0], [1, 8, 0, 0]]),
        (2, 1, alloc::vec![[4, 0, 0, 0], [4, 1, 1, 0]]),
        (2, 1, alloc::vec![[4, 0, 0, 0], [4, 1, 0, 1]]),
    ] {
        queue_wire(&user, vm, width, count, &lanes);
        assert_eq!(
            invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
            Err(FsError::InvalidData)
        );
    }
    queue_wire(&user, vm, 2, 1, &[[4, 0, 0, 0], [4, 1, 0, 0]]);
    user.fail_report
        .store(true, core::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::BadAddress)
    );
    user.fail_report
        .store(false, core::sync::atomic::Ordering::Relaxed);
    let queue = create_parallel(&file, &info, &user, vm, 4, 0);
    assert_eq!(queue, 1, "failed create did not publish a queue name");
    let _handles = buffers(&file, &info, &user, vm);
    for count in [1, 3] {
        exec_parallel(&user, queue, [0x1234_0000_0000; 2], &[]);
        let mut wire = user.wire.load(64, 56);
        wire[32] = count;
        user.wire.store(64, &wire);
        assert_eq!(exec_refusal(&file, &info, &user), Err(FsError::InvalidData));
    }
    exec_parallel(
        &user,
        queue,
        [0x1234_0000_0000; 2],
        &[sync(2, 0x2345_0000_0090, 7, true)],
    );
    assert_eq!(
        exec_refusal(&file, &info, &user),
        Err(FsError::NotImplemented)
    );
    assert_eq!(user.read_u64_acquire(0x4090), Ok(0));
    exec_parallel(&user, queue, [0x1234_0000_0000; 2], &[]);
    let mut fault = user.wire.load(64, 56);
    put64(&mut fault, 24, 32760); // second qword crosses the process extent
    user.wire.store(64, &fault);
    assert_eq!(exec_refusal(&file, &info, &user), Err(FsError::BadAddress));
    // Both addresses must be mapped, qword aligned and copied before waiting.
    for child in [0, 0x1234_0000_0001, 0x1234_0000_1000] {
        exec_parallel(&user, queue, [0x1234_0000_0000, child], &[]);
        assert_eq!(exec_refusal(&file, &info, &user), Err(FsError::InvalidData));
    }
    assert!(mailbox.pending.lock().is_empty());
    assert_eq!(arena.live_allocations(), baseline);
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_queue_matrix_copy_fault_and_join_store_refusal
);

fn smoke_parallel_queue_real_copy_compute_wq_and_per_lane_saved_state() -> TestResult {
    for (platform, mask, mode, class, first) in [
        (GtPlatform::Alchemist, 10, 2, 4, 0),
        (GtPlatform::Battlemage, 15, 4, 4, 1),
        (GtPlatform::Battlemage, 10, 2, 1, 0),
    ] {
        let (w, arena, mut gt, ack) = discover(platform, mask);
        prime_mode(&mut gt, &w, mode);
        let (mailbox, info) = setup(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let queue = create_parallel(&file, &info, &user, vm, class, first);
        let handles = buffers(&file, &info, &user, vm);
        let addresses = if class == 1 {
            let words = [0x10000002u32, 0x88, 0x2345, 0x11223344, 0x05000000, 0];
            let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
            file.gem
                .object(handles[0])
                .unwrap()
                .write(4096 + 32, &bytes)
                .unwrap();
            [0x1234_0000_0000, 0x1234_0000_0020]
        } else {
            [0x1234_0000_0000; 2]
        };
        w.0.borrow_mut().parallel_reply_child = class == 1;
        let baseline = arena.live_allocations();
        let mut identity: Option<Arc<UserContext>> = None;
        for iteration in 0..3 {
            exec_parallel(&user, queue, addresses, &[]);
            if iteration == 2 {
                file.gem
                    .object(handles[1])
                    .unwrap()
                    .write(0x80, &[0; 16])
                    .unwrap();
                let mut wire = user.wire.load(64, 56);
                wire[32] = 0; // Linux also permits a width-two zero-batch barrier.
                put64(&mut wire, 24, 0); // ignored: no array is read for count0.
                user.wire.store(64, &wire);
            }
            let (context, fence) = accept(
                &file,
                &info,
                &user,
                &mailbox,
                &mut gt,
                500 + iteration * 100,
            );
            if let Some(previous) = &identity {
                assert!(Arc::ptr_eq(previous, &context));
            }
            identity = Some(context.clone());
            let mut registered = BTreeMap::new();
            let (id, group) = dispatch(&mut gt, &w, &mut registered, 501 + iteration * 100, false);
            let lanes = context.parallel().unwrap();
            let present = gt.engines().unwrap();
            assert_eq!(present.logical_instance(lanes[0]), Some(first));
            assert_eq!(present.logical_instance(lanes[1]), Some(first + 1));
            let d = w.0.borrow();
            let roots: Vec<_> = group
                .images
                .iter()
                .copied()
                .map(|base| {
                    let image = d.memory[&base].borrow();
                    assert_eq!(
                        image[1026],
                        lanes[usize::from(base == group.images[1])].base() + 0x244
                    );
                    if iteration != 0 {
                        assert_eq!(
                            image[0x1800 / 4],
                            if base == group.images[0] {
                                0xaabbccdd
                            } else {
                                0x55667788
                            }
                        );
                    }
                    u64::from(image[1024 + 0x31]) << 32 | u64::from(image[1024 + 0x33])
                })
                .collect();
            assert_eq!(roots[0], roots[1]);
            assert_ne!(roots[0], 0);
            assert!(group
                .images
                .iter()
                .all(|base| d.memory[base].borrow()[0x800 / 4] == 0));
            drop(d);
            assert!(
                narf_filesystem::DrmFence::is_submit_ready(fence.as_ref())
                    && fence.result().is_none()
            );
            for (lane, base) in group.images.iter().copied().enumerate() {
                execute_parallel_lane(&w, id, base);
                w.0.borrow().memory[&base].borrow_mut()[0x1800 / 4] =
                    [0xaabbccdd, 0x55667788][lane];
            }
            assert_eq!(
                user.read_u64_acquire(0x4080),
                Ok(if iteration == 2 { 0 } else { 0x4e415246 })
            );
            if class == 1 {
                assert_eq!(
                    user.read_u64_acquire(0x4088),
                    Ok(if iteration == 2 { 0 } else { 0x11223344 })
                );
            }
            assert_eq!(
                w.0.borrow().parallel_starts.len(),
                2 * (iteration as usize + 1)
            );
            finish(&mut gt, &w, &fence, &mut registered, 540 + iteration * 100);
            assert!(!context.busy() && !context.banned());
            assert!(registered.is_empty() && w.0.borrow().parallel_contexts.is_empty());
            assert_eq!(arena.live_allocations(), baseline);
        }
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_queue_real_copy_compute_wq_and_per_lane_saved_state
);

fn smoke_parallel_queue_partial_completion_close_and_final_tlb_own_every_lane() -> TestResult {
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let queue = create_parallel(&file, &info, &user, vm, 1, 0);
    let handles = buffers(&file, &info, &user, vm);
    let weak = handles.map(|h| Arc::downgrade(&file.gem.object(h).unwrap()));
    let output = file.syncobjs.lock().create(0).unwrap();
    let core = file.syncobjs.lock().get(output).unwrap().core().clone();
    exec_parallel(
        &user,
        queue,
        [0x1234_0000_0000; 2],
        &[sync(1, u64::from(output), 9, true)],
    );
    let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 500);
    let payload = core.find_fence(9).unwrap();
    w.0.borrow_mut().parallel_lanes = Some(1);
    let mut registered = BTreeMap::new();
    let (id, group) = dispatch(&mut gt, &w, &mut registered, 501, true);
    let retained = arena.live_allocations();
    w.0.borrow().memory[&group.scratch].borrow_mut()[3] = 2; // named SUSPENDED
    for now in 540..550 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        assert!(service_contexts(&w, &mut registered, true).is_empty());
    }
    assert_eq!(
        registered.len(),
        2,
        "parent completion must not deregister its child"
    );
    assert!(context.busy() && fence.result().is_none() && !payload.is_signalled());
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
    assert_eq!(arena.live_allocations(), retained);
    assert!(weak.iter().all(|o| o.upgrade().is_some()));
    execute_parallel_lane(&w, id, group.images[1]);
    // Firmware WQ-head publication need not be ordered before both lane
    // breadcrumbs. A well-formed old head waits boundedly rather than losing
    // the GT or allowing premature cleanup.
    w.0.borrow().memory[&group.scratch].borrow_mut()[0] = 0;
    assert_eq!(gt.poll(550), Poll::Ready(Ok(GtState::SchedulingReady)));
    assert!(service_contexts(&w, &mut registered, true).contains(&0x1001));
    assert_eq!(registered.len(), 2);
    let mut retired_stamp = None;
    for now in 551..580 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        let memory = ct_memory(&w);
        let mut words = memory.borrow_mut();
        let head = words[0];
        if registered.is_empty() && head != words[1] {
            assert_eq!(words[1024 + ((head + 1) & 1023) as usize] as u16, 0x7000);
            retired_stamp = Some(words[1024 + ((head + 2) & 1023) as usize]);
            words[0] = words[1]; // firmware deliberately withholds final TLB ACK
            break;
        }
        drop(words);
        service_contexts(&w, &mut registered, true);
    }
    let stamp = retired_stamp.expect("deregistered group waits for one final TLB ACK");
    assert_ne!(stamp & 0x80000000, 0);
    assert!(fence.result().is_none() && !payload.is_signalled() && context.busy());
    assert_eq!(arena.live_allocations(), retained);
    assert!(weak.iter().all(|o| o.upgrade().is_some()));
    event(&ct_memory(&w), 0x7001, &[stamp]);
    assert_eq!(gt.poll(581), Poll::Ready(Ok(GtState::SchedulingReady)));
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(payload.is_signalled() && !context.busy());
    assert!(weak.iter().all(|o| o.upgrade().is_none()));
    assert!(group
        .images
        .iter()
        .all(|base| !w.0.borrow().memory.contains_key(base)));
    assert!(!w.0.borrow().memory.contains_key(&group.scratch));
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_queue_partial_completion_close_and_final_tlb_own_every_lane
);

fn start_lane(w: &Window, base: u32, engine: Engine, ticks: u32) {
    let mut d = w.0.borrow_mut();
    let image = d.memory[&base].clone();
    let mut image = image.borrow_mut();
    let ring = d.memory[&image[1024 + 9]].borrow();
    assert_eq!(&ring[..4], &[0x12480002, 0x3a8, base + 0x810, 0]);
    let stamp = if engine.is_copy() { ring[9] } else { ring[7] };
    assert_ne!(stamp, 0);
    drop(ring);
    image[0x808 / 4] = stamp;
    image[0x810 / 4] = 0;
    image[0x108c / 4] = 1;
    d.regs.insert(u64::from(engine.base()) + 0x240, base);
    d.regs.insert(u64::from(engine.base()) + 0x3a8, ticks);
}
fn smoke_parallel_queue_every_lane_watchdog_and_child_reset_retire_together() -> TestResult {
    for (class, first, bad_lane, reset) in [
        (1, 0, 0, false),
        (1, 0, 1, false),
        (1, 0, 2, false), // both physical lanes exceed their own budgets
        (4, 0, 0, false),
        (4, 0, 1, false),
        (4, 0, 2, false),
        (4, 1, 1, false),
        (4, 2, 1, false),
        (4, 0, 1, true),
    ] {
        let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 15);
        prime_mode(&mut gt, &w, 4);
        let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
        w.0.borrow_mut().regs.insert(0xd00, 0); // known3MHz
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let queue = create_parallel(&file, &info, &user, vm, class, first);
        let _handles = buffers(&file, &info, &user, vm);
        exec_parallel(&user, queue, [0x1234_0000_0000; 2], &[]);
        let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 500);
        let mut registered = BTreeMap::new();
        let (id, group) = dispatch(&mut gt, &w, &mut registered, 501, false);
        let lanes = context.parallel().unwrap();
        let guilty = bad_lane % 2;
        let retained = arena.live_allocations();
        if reset {
            event(&ct_memory(&w), 0x1008, &[id + bad_lane as u32]);
            assert_eq!(gt.poll(540), Poll::Ready(Ok(GtState::SchedulingReady)));
        } else {
            // The other lane really finished. It must neither mask this
            // physical lane's timeout nor be charged for waiting at the join.
            if bad_lane == 2 {
                for (lane, engine) in lanes.iter().copied().enumerate() {
                    start_lane(&w, group.images[lane], engine, 15_000_000);
                }
            } else {
                execute_parallel_lane(&w, id, group.images[1 - guilty]);
                start_lane(&w, group.images[guilty], lanes[guilty], 15_000_000);
            }
            assert_eq!(
                gt.poll(5_000_001_000),
                Poll::Ready(Ok(GtState::SchedulingReady))
            );
        }
        let report = gt.take_error_report().expect("lane-specific first error");
        let text = crate::intel_gpu_error::Snapshot {
            report,
            suppressed: 0,
        }
        .text();
        let name = match lanes[guilty] {
            Engine::Bcs0 => "bcs0",
            Engine::Bcs8 => "bcs8",
            Engine::Ccs0 => "ccs0",
            Engine::Ccs1 => "ccs1",
            Engine::Ccs2 => "ccs2",
            Engine::Ccs3 => "ccs3",
            _ => unreachable!(),
        };
        let prefix = alloc::format!(
            "context {} placements=0x{:02x}",
            name,
            crate::intel_gpu_engine::EngineSet::of(&[lanes[guilty]]).bits()
        );
        let lane = text
            .lines()
            .find(|line| line.starts_with(prefix.as_str()))
            .unwrap_or_else(|| panic!("missing physical lane {prefix}: {text}"));
        let expected = if reset {
            "timed_out=0 reset=1 runtime_ticks=unavailable"
        } else {
            "timed_out=1 reset=0 runtime_ticks=15000000"
        };
        assert!(
            lane.contains(expected),
            "class={class} first={first} bad_lane={bad_lane} reset={reset}: {text}"
        );
        if !reset {
            let timed_out = text.matches(expected).count();
            assert_eq!(
                timed_out,
                if bad_lane == 2 { 2 } else { 1 },
                "class={class} first={first} bad_lane={bad_lane}: {text}"
            );
        } else {
            assert_eq!(
                text.matches(" reset=1 runtime_ticks=").count(),
                1,
                "only the notified child records an engine reset: {text}"
            );
        }
        assert!(context.busy() && !context.banned() && fence.result().is_none());
        assert_eq!(arena.live_allocations(), retained);
        assert!(group
            .images
            .iter()
            .all(|base| w.0.borrow().memory.contains_key(base)));
        assert!(w.0.borrow().memory.contains_key(&group.scratch));
        let now = if reset { 541 } else { 5_000_001_001 };
        for now in now..now + 50 {
            service_contexts(&w, &mut registered, false);
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            if fence.result().is_some() {
                break;
            }
        }
        assert_eq!(fence.result(), Some(Err(JobError::Hang)));
        assert!(context.banned() && !context.busy());
        assert_eq!(context.reset_stats(), (1, 0));
        assert!(registered.is_empty());
        assert!(group
            .images
            .iter()
            .all(|base| !w.0.borrow().memory.contains_key(base)));
        assert!(!w.0.borrow().memory.contains_key(&group.scratch));
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_queue_every_lane_watchdog_and_child_reset_retire_together
);

fn drop_reply(w: &Window) {
    let memory = ct_memory(w);
    let mut words = memory.borrow_mut();
    let head = words[512];
    assert_eq!(
        words[513].wrapping_sub(head) & 4095,
        4,
        "one unobserved mode reply"
    );
    // Firmware omitted this reply. Revert only its producer TAIL before any
    // host poll; mutating host-owned HEAD would instead inject CT Cursor loss.
    words[513] = head;
}
fn smoke_parallel_queue_malformed_lost_ack_and_cache_failure_keep_all_dma_until_reset() -> TestResult
{
    // Separate firmware incarnations: none of these uncertain transactions
    // may be reused, deregistered by guess, or implicitly released on Drop.
    for failure in 0..10 {
        let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
        prime_mode(&mut gt, &w, 2);
        let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let queue = create_parallel(&file, &info, &user, vm, 4, 0);
        let handles = buffers(&file, &info, &user, vm);
        let weak = handles.map(|h| Arc::downgrade(&file.gem.object(h).unwrap()));
        exec_parallel(&user, queue, [0x1234_0000_0000; 2], &[]);
        let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 500);
        let mut registered = BTreeMap::new();
        let (id, group) = if failure == 3 {
            // Enable accepted, its mode ACK lost. No SCHED success is invented.
            let mut enabled = false;
            for now in 501..530 {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                if service_contexts(&w, &mut registered, false).contains(&0x1001) {
                    drop_reply(&w);
                    enabled = true;
                    break;
                }
            }
            assert!(enabled);
            let d = w.0.borrow();
            let (&id, group) = d.parallel_contexts.iter().next().unwrap();
            let group = group.clone();
            (id, group)
        } else {
            dispatch(
                &mut gt,
                &w,
                &mut registered,
                501,
                matches!(failure, 1 | 4 | 8),
            )
        };
        let retained = arena.live_allocations();
        match failure {
            0 => w.0.borrow().memory[&group.scratch].borrow_mut()[0] = 4,
            1 => {
                w.0.borrow().memory[&group.images[1]].borrow_mut()[1024 + 5] = 0;
            }
            2 => event(&ct_memory(&w), 0x1002, &[id + 2, 1]),
            3 => {}
            4 => {
                assert_eq!(gt.poll(540), Poll::Ready(Ok(GtState::SchedulingReady)));
                assert!(service_contexts(&w, &mut registered, false).contains(&0x1001));
                drop_reply(&w);
            }
            5 => w.0.borrow_mut().fail_cpu_sync = true,
            6 => w.0.borrow().memory[&group.scratch].borrow_mut()[3] = 3,
            7 => w.0.borrow().memory[&group.scratch].borrow_mut()[2] = 4,
            8 => w.0.borrow().memory[&group.images[1]].borrow_mut()[1025] = 0,
            _ => {
                for now in [5_000_001_000, 10_000_001_000] {
                    assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                }
            }
        }
        let mut lost = false;
        for now in 541..580 {
            let now = if failure == 9 {
                now + 15_000_001_000
            } else if failure == 3 || failure == 4 {
                now + 5_000_001_000
            } else {
                now
            };
            match gt.poll(now) {
                Poll::Ready(Err(GtError::Scheduling(error))) => {
                    let expected = match failure {
                        3 | 4 | 9 => crate::intel_gpu_guc_sched::SchedulingError::Timeout,
                        5 => crate::intel_gpu_guc_sched::SchedulingError::Cache,
                        8 => crate::intel_gpu_guc_sched::SchedulingError::Residency(
                            crate::intel_gpu_user::io_error(),
                        ),
                        _ => crate::intel_gpu_guc_sched::SchedulingError::Protocol,
                    };
                    assert_eq!(error, expected, "parallel failure case {failure}");
                    lost = true;
                    break;
                }
                Poll::Ready(Ok(GtState::SchedulingReady)) => {
                    service_contexts(&w, &mut registered, false);
                }
                other => panic!("unexpected parallel failure case {failure}: {other:?}"),
            }
        }
        assert!(lost, "failure {failure} was silently accepted");
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
        assert!(context.busy() && fence.result().is_none());
        assert_eq!(context.reset_stats(), (0, 0));
        assert_eq!(arena.live_allocations(), retained);
        assert!(weak.iter().all(|o| o.upgrade().is_some()));
        assert!(group
            .images
            .iter()
            .all(|base| w.0.borrow().memory.contains_key(base)));
        assert!(w.0.borrow().memory.contains_key(&group.scratch));
        w.0.borrow_mut().fail_cpu_sync = false;
        hardware_stop(&mut gt, &w, ack);
        assert_eq!(fence.result(), Some(Err(JobError::Reset)));
        assert_eq!(context.reset_stats(), (0, 1));
        assert!(weak.iter().all(|o| o.upgrade().is_none()));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_queue_malformed_lost_ack_and_cache_failure_keep_all_dma_until_reset
);

fn smoke_parallel_queue_prepare_failure_rolls_back_both_lanes_and_identity() -> TestResult {
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let queue = create_parallel(&file, &info, &user, vm, 4, 0);
    let _handles = buffers(&file, &info, &user, vm);
    let baseline = arena.live_allocations();
    for fail in 1..=5 {
        exec_parallel(&user, queue, [0x1234_0000_0000; 2], &[]);
        let context = {
            let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            let pending = mailbox.pending.lock().pop().unwrap();
            let context = pending.context.clone();
            let next = w.0.borrow().allocations + fail;
            w.0.borrow_mut().fail_at = Some(next);
            assert!(gt
                .submit_user_batch(500, context.clone(), pending.batch)
                .is_err());
            w.0.borrow_mut().fail_at = None;
            // Leaving this scope drops the actual pending submit future,
            // rather than merely dropping a Pin reference to that future.
            context
        };
        assert!(!context.busy() && !context.banned());
        assert_eq!(arena.live_allocations(), baseline);
    }
    for iteration in 0..2 {
        exec_parallel(&user, queue, [0x1234_0000_0000; 2], &[]);
        let (_, fence) = accept(
            &file,
            &info,
            &user,
            &mailbox,
            &mut gt,
            600 + iteration * 100,
        );
        let mut registered = BTreeMap::new();
        let (id, _) = dispatch(&mut gt, &w, &mut registered, 601 + iteration * 100, true);
        assert!(id > 0 && id < 64);
        finish(&mut gt, &w, &fence, &mut registered, 640 + iteration * 100);
        assert_eq!(arena.live_allocations(), baseline);
    }
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_queue_prepare_failure_rolls_back_both_lanes_and_identity
);

fn smoke_parallel_queue_queued_gang_progress_and_finished_lane_exclusion() -> TestResult {
    for parent_finished in [false, true] {
        let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
        prime_mode(&mut gt, &w, 2);
        let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let queue = create_parallel(&file, &info, &user, vm, 4, 0);
        let _handles = buffers(&file, &info, &user, vm);
        exec_parallel(&user, queue, [0x1234_0000_0000; 2], &[]);
        let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 500);
        let mut registered = BTreeMap::new();
        let (id, group) = dispatch(&mut gt, &w, &mut registered, 501, false);
        let retained = arena.live_allocations();
        let lanes = context.parallel().unwrap();
        assert_eq!(lanes, &[Engine::Ccs1, Engine::Ccs3]);
        if parent_finished {
            execute_parallel_lane(&w, id, group.images[0]);
        }
        // A pending gang can wait for another queue on an unfinished engine.
        // Conversely, other work on an already finished lane must not conceal
        // the outstanding child's complete lack of scheduling progress.
        let busy = UserContext::for_engine(lanes[usize::from(!parent_finished)]);
        busy.configure_schedule(2, 1000).unwrap();
        let starts: &[u64] = if parent_finished {
            &[4_000_000_000, 8_000_000_000, 12_000_000_000]
        } else {
            &[4_000_000_000, 8_000_000_000, 12_000_000_000, 16_000_000_000]
        };
        for &start in starts {
            let (batch, result) = PpgttProbeResult::prepare(GtPlatform::Battlemage).unwrap();
            let (_, done) = gt
                .submit_user_batch(start, busy.clone(), UserBatch(batch))
                .unwrap();
            finish(&mut gt, &w, &done, &mut registered, start + 1);
            assert_eq!(result.verify(), Ok(()));
            assert!(!busy.busy() && !busy.banned());
            assert!(context.busy() && !context.banned() && fence.result().is_none());
            assert_eq!(registered.len(), 2);
            assert_eq!(arena.live_allocations(), retained);
            assert_eq!(w.0.borrow().memory[&group.images[1]].borrow()[0x808 / 4], 0);
        }
        if !parent_finished {
            assert!(
                w.0.borrow().parallel_starts.is_empty(),
                "gang never started"
            );
            assert_eq!(w.0.borrow().memory[&group.images[0]].borrow()[0x808 / 4], 0);
            // Now every unfinished engine is quiet. Queued does not mean
            // unbounded ownership: the last real completion starts this bound.
            for now in [21_000_001_000, 26_000_001_000] {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            }
        }
        let lost_at = if parent_finished {
            16_000_001_000
        } else {
            31_000_001_000
        };
        assert_eq!(
            gt.poll(lost_at),
            Poll::Ready(Err(GtError::Scheduling(
                crate::intel_gpu_guc_sched::SchedulingError::Timeout
            )))
        );
        assert!(context.busy() && !context.banned() && fence.result().is_none());
        assert_eq!(
            context.reset_stats(),
            (0, 0),
            "no guilt from queued gang liveness"
        );
        assert_eq!(arena.live_allocations(), retained);
        assert!(group
            .images
            .iter()
            .all(|base| w.0.borrow().memory.contains_key(base)));
        assert!(w.0.borrow().memory.contains_key(&group.scratch));
        hardware_stop(&mut gt, &w, ack);
        assert_eq!(fence.result(), Some(Err(JobError::Reset)));
        assert_eq!(context.reset_stats(), (0, 1));
        assert!(!busy.banned() && !busy.busy());
        assert!(group
            .images
            .iter()
            .all(|base| !w.0.borrow().memory.contains_key(base)));
        assert!(!w.0.borrow().memory.contains_key(&group.scratch));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_queue_queued_gang_progress_and_finished_lane_exclusion
);

mod wider {
    include!("intel_gpu_parallel_wide_tests.rs");
}
