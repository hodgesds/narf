// Width3/4 production Xe -> GuC multi-LRC -> per-lane private PPGTT fixtures.
// Literal ABI vectors: Linux b90c984d xe_guc_submit.c, xe_exec{,_queue}.c.
use super::*;

fn create_width(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &Cpu,
    vm: u32,
    first: u16,
    width: u16,
) -> u32 {
    let lanes: Vec<_> = (first..first + width)
        .map(|logical| [4, logical, 0, 0])
        .collect();
    queue_wire(user, vm, width, 1, &lanes);
    assert_eq!(invoke(file, info, user, xe::EXEC_QUEUE_CREATE), Ok(0));
    u32_at(&user.wire.load(64, 48), 20)
}
fn exec_width(user: &Cpu, queue: u32, addresses: &[u64], syncs: &[[u8; 48]], barrier: bool) {
    let mut wire = [0; 56];
    put32(&mut wire, 8, queue);
    put32(&mut wire, 12, syncs.len() as u32);
    put64(&mut wire, 16, 2048);
    put64(&mut wire, 24, if barrier { 0 } else { 768 });
    wire[32..34].copy_from_slice(&(if barrier { 0 } else { addresses.len() as u16 }).to_le_bytes());
    let bytes: Vec<_> = addresses.iter().flat_map(|n| n.to_le_bytes()).collect();
    user.wire.store(768, &bytes);
    user.wire.store(2048, &syncs.concat());
    user.wire.store(64, &wire);
}
fn lane_batches(file: &RenderFile, code: u32, width: usize) -> Vec<u64> {
    (0..width)
        .map(|lane| {
            let destination = 0x2345_0000_0080u64 + lane as u64 * 8;
            let words = [
                0x10000002u32,
                destination as u32,
                (destination >> 32) as u32,
                0xabc00000 + lane as u32,
                0x05000000,
                0,
            ];
            let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
            file.gem
                .object(code)
                .unwrap()
                .write(4096 + lane as u64 * 32, &bytes)
                .unwrap();
            0x1234_0000_0000 + lane as u64 * 32
        })
        .collect()
}
fn owned_allocations(w: &Window, group: &ParallelContext) -> Vec<u32> {
    let d = w.0.borrow();
    group
        .images
        .iter()
        .flat_map(|base| [*base, d.memory[base].borrow()[1024 + 9]])
        .chain(core::iter::once(group.scratch))
        .collect()
}
fn smoke_parallel_wide_matrix_vector_ownership_and_join_refusal() -> TestResult {
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 15);
    prime_mode(&mut gt, &w, 4);
    let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    for (width, count, row) in [
        (5, 1, alloc::vec![[4, 0, 0, 0]; 5]),
        (3, 2, alloc::vec![[4, 0, 0, 0]; 6]),
        (4, 2, alloc::vec![[4, 0, 0, 0]; 8]),
        (3, 1, alloc::vec![[1, 0, 0, 0], [1, 1, 0, 0], [1, 2, 0, 0]]),
        (3, 1, alloc::vec![[5, 0, 0, 0]; 3]),
        (3, 1, alloc::vec![[0, 0, 0, 0]; 3]),
        (3, 1, alloc::vec![[4, 0, 0, 0], [4, 2, 0, 0], [4, 3, 0, 0]]),
        (3, 1, alloc::vec![[4, 2, 0, 0], [4, 3, 0, 0], [4, 4, 0, 0]]),
        (
            4,
            1,
            alloc::vec![[4, 0, 0, 0], [4, 1, 0, 0], [4, 2, 0, 0], [4, 2, 0, 0]],
        ),
        (
            4,
            1,
            alloc::vec![[4, 0, 0, 0], [4, 1, 0, 0], [4, 2, 0, 0], [1, 1, 0, 0]],
        ),
        (
            4,
            1,
            alloc::vec![[4, 0, 0, 0], [4, 1, 0, 0], [4, 2, 0, 0], [4, 3, 1, 0]],
        ),
        (
            4,
            1,
            alloc::vec![[4, 0, 0, 0], [4, 1, 0, 0], [4, 2, 0, 0], [4, 3, 0, 1]],
        ),
    ] {
        queue_wire(&user, vm, width, count, &row);
        assert_eq!(
            invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
            Err(FsError::InvalidData)
        );
    }
    queue_wire(
        &user,
        vm,
        4,
        1,
        &[[4, 0, 0, 0], [4, 1, 0, 0], [4, 2, 0, 0], [4, 3, 0, 0]],
    );
    user.fail_report
        .store(true, core::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::BadAddress)
    );
    user.fail_report
        .store(false, core::sync::atomic::Ordering::Relaxed);
    let handles = buffers(&file, &info, &user, vm);
    let all_addresses = lane_batches(&file, handles[0], 4);
    for width in [3, 4] {
        let queue = create_width(&file, &info, &user, vm, 0, width);
        let addresses = all_addresses[..usize::from(width)].to_vec();
        for count in [1, 2, 5] {
            exec_width(&user, queue, &addresses, &[], false);
            let mut wire = user.wire.load(64, 56);
            wire[32..34].copy_from_slice(&(count as u16).to_le_bytes());
            user.wire.store(64, &wire);
            assert_eq!(exec_refusal(&file, &info, &user), Err(FsError::InvalidData));
        }
        for lane in 1..usize::from(width) {
            for bad in [0, 0x1234_0000_0001, 0x1234_0000_1000] {
                let mut invalid = addresses.clone();
                invalid[lane] = bad;
                exec_width(&user, queue, &invalid, &[], false);
                assert_eq!(exec_refusal(&file, &info, &user), Err(FsError::InvalidData));
            }
        }
        exec_width(&user, queue, &addresses, &[], false);
        let mut wire = user.wire.load(64, 56);
        put64(&mut wire, 24, 32768 - u64::from(width) * 8 + 8);
        user.wire.store(64, &wire);
        assert_eq!(exec_refusal(&file, &info, &user), Err(FsError::BadAddress));
        exec_width(
            &user,
            queue,
            &addresses,
            &[sync(2, 0x2345_0000_0090, 5, true)],
            false,
        );
        assert_eq!(
            exec_refusal(&file, &info, &user),
            Err(FsError::NotImplemented)
        );
        assert_eq!(user.read_u64_acquire(0x4090), Ok(0));
        assert!(mailbox.pending.lock().is_empty());
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
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_wide_matrix_vector_ownership_and_join_refusal
);

fn smoke_parallel_wide_sparse_dense_execution_all_lane_state_and_zero_barrier() -> TestResult {
    for platform in [GtPlatform::Alchemist, GtPlatform::Battlemage] {
        for (mask, mode, first, width) in [(13, 3, 0, 3), (15, 4, 1, 3), (15, 4, 0, 4)] {
            let (w, arena, mut gt, ack) = discover(platform, mask);
            prime_mode(&mut gt, &w, mode);
            let (mailbox, info) = setup(&mut gt, &w, platform);
            let file = RenderFile::new();
            let user = Cpu::new();
            let vm = create_vm(&file, &info, &user);
            let queue = create_width(&file, &info, &user, vm, first, width);
            let handles = buffers(&file, &info, &user, vm);
            let addresses = lane_batches(&file, handles[0], usize::from(width));
            let output = file.syncobjs.lock().create(0).unwrap();
            let timeline = file.syncobjs.lock().get(output).unwrap().core().clone();
            w.0.borrow_mut().parallel_reply_lane = Some(u32::from(width - 1));
            let baseline = arena.live_allocations();
            let mut identity: Option<Arc<UserContext>> = None;
            for iteration in 0..3 {
                file.gem
                    .object(handles[1])
                    .unwrap()
                    .write(0x80, &[0; 32])
                    .unwrap();
                exec_width(
                    &user,
                    queue,
                    &addresses,
                    &[sync(1, u64::from(output), iteration + 1, true)],
                    iteration == 2,
                );
                let start = 500 + iteration * 100;
                let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, start);
                if let Some(old) = &identity {
                    assert!(Arc::ptr_eq(old, &context));
                }
                identity = Some(context.clone());
                let payload = timeline.find_fence(iteration + 1).unwrap();
                let mut registered = BTreeMap::new();
                let (id, group) = dispatch(&mut gt, &w, &mut registered, start + 1, false);
                let lanes = context.parallel().unwrap();
                assert_eq!(lanes.len(), usize::from(width));
                let owned = owned_allocations(&w, &group);
                assert_eq!(owned.len(), usize::from(width) * 2 + 1);
                let roots: Vec<_> = group
                    .images
                    .iter()
                    .enumerate()
                    .map(|(index, base)| {
                        let d = w.0.borrow();
                        let image = d.memory[base].borrow();
                        assert_eq!(image[1026], lanes[index].base() + 0x244);
                        assert_eq!(
                            gt.engines().unwrap().logical_instance(lanes[index]),
                            Some(first + index as u16)
                        );
                        if iteration != 0 {
                            assert_eq!(image[0x1800 / 4], 0xd00d0000 + index as u32);
                        }
                        let ring = d.memory[&image[1024 + 9]].borrow();
                        if iteration != 2 {
                            let batch = ring
                                .windows(4)
                                .find(|w| w[..2] == [0x02800100, 0x18800101])
                                .unwrap();
                            assert_eq!(
                                u64::from(batch[2]) | u64::from(batch[3]) << 32,
                                addresses[index]
                            );
                        }
                        u64::from(image[1024 + 0x31]) << 32 | u64::from(image[1024 + 0x33])
                    })
                    .collect();
                assert!(roots.iter().all(|root| *root == roots[0] && *root != 0));
                {
                    let d = w.0.borrow();
                    let scratch = d.memory[&group.scratch].borrow();
                    assert_eq!(
                        [scratch[1], scratch[256]],
                        if width == 3 {
                            [24, 0x00050005]
                        } else {
                            [28, 0x00060005]
                        }
                    );
                }
                for (index, base) in group
                    .images
                    .iter()
                    .copied()
                    .enumerate()
                    .take(usize::from(width - 1))
                {
                    execute_parallel_lane(&w, id, base);
                    w.0.borrow().memory[&base].borrow_mut()[0x1800 / 4] = 0xd00d0000 + index as u32;
                }
                assert_eq!(
                    gt.poll(start + 40),
                    Poll::Ready(Ok(GtState::SchedulingReady))
                );
                assert!(service_contexts(&w, &mut registered, true).is_empty());
                assert_eq!(registered.len(), usize::from(width));
                assert!(context.busy() && fence.result().is_none() && !payload.is_signalled());
                let last = usize::from(width - 1);
                let base = group.images[last];
                execute_parallel_lane(&w, id, base);
                w.0.borrow().memory[&base].borrow_mut()[0x1800 / 4] = 0xd00d0000 + last as u32;
                for index in 0..usize::from(width) {
                    assert_eq!(
                        user.read_u64_acquire(0x4080 + index as u64 * 8),
                        Ok(if iteration == 2 {
                            0
                        } else {
                            0xabc00000 + index as u64
                        })
                    );
                }
                finish(&mut gt, &w, &fence, &mut registered, start + 60);
                assert!(!context.busy() && !context.banned() && payload.is_signalled());
                assert!(registered.is_empty() && w.0.borrow().parallel_contexts.is_empty());
                assert!(owned
                    .iter()
                    .all(|base| !w.0.borrow().memory.contains_key(base)));
                assert_eq!(arena.live_allocations(), baseline);
            }
            hardware_stop(&mut gt, &w, ack);
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_wide_sparse_dense_execution_all_lane_state_and_zero_barrier
);

fn smoke_parallel_wide_every_lane_runtime_and_high_child_reset_retire_as_group() -> TestResult {
    for width in [3u16, 4] {
        for bad in 0..=width + 1 {
            let (mask, mode) = if width == 3 { (13, 3) } else { (15, 4) };
            let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, mask);
            prime_mode(&mut gt, &w, mode);
            let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
            w.0.borrow_mut().regs.insert(0xd00, 0); // independently known3MHz
            let file = RenderFile::new();
            let user = Cpu::new();
            let vm = create_vm(&file, &info, &user);
            let queue = create_width(&file, &info, &user, vm, 0, width);
            let _handles = buffers(&file, &info, &user, vm);
            let addresses = alloc::vec![0x1234_0000_0000; usize::from(width)];
            exec_width(&user, queue, &addresses, &[], false);
            let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 500);
            let mut registered = BTreeMap::new();
            let (id, group) = dispatch(&mut gt, &w, &mut registered, 501, false);
            let owned = owned_allocations(&w, &group);
            let retained = arena.live_allocations();
            let lanes = context.parallel().unwrap();
            let reset = bad == width + 1;
            let all = bad == width;
            let guilty = if reset || all {
                usize::from(width - 1)
            } else {
                usize::from(bad)
            };
            if reset {
                event(&ct_memory(&w), 0x1008, &[id + u32::from(width - 1)]);
                assert_eq!(gt.poll(540), Poll::Ready(Ok(GtState::SchedulingReady)));
            } else {
                for (index, engine) in lanes.iter().copied().enumerate() {
                    if all || index == guilty {
                        start_lane(&w, group.images[index], engine, 15_000_000);
                    } else {
                        execute_parallel_lane(&w, id, group.images[index]);
                    }
                }
                assert_eq!(
                    gt.poll(5_000_001_000),
                    Poll::Ready(Ok(GtState::SchedulingReady))
                );
            }
            let report = gt.take_error_report().unwrap();
            let text = crate::intel_gpu_error::Snapshot {
                report,
                suppressed: 0,
            }
            .text();
            for (index, engine) in lanes.iter().enumerate() {
                let prefix = alloc::format!(
                    "context ccs{} placements=0x{:02x} id={}",
                    engine.physical_instance(),
                    crate::intel_gpu_engine::EngineSet::of(&[*engine]).bits(),
                    id + index as u32
                );
                let line = text
                    .lines()
                    .find(|line| line.starts_with(prefix.as_str()))
                    .unwrap_or_else(|| panic!("width{width} missing {prefix}: {text}"));
                let timeout = !reset && (all || index == guilty);
                let reset_lane = reset && index == guilty;
                assert!(
                    line.contains(&alloc::format!(
                        "timed_out={} reset={}",
                        u8::from(timeout),
                        u8::from(reset_lane)
                    )),
                    "width{width} bad{bad}: {text}"
                );
                if timeout {
                    assert!(
                        line.ends_with("runtime_ticks=15000000"),
                        "width{width} bad{bad}: {text}"
                    );
                }
            }
            assert!(context.busy() && !context.banned() && fence.result().is_none());
            assert_eq!(arena.live_allocations(), retained);
            assert!(owned
                .iter()
                .all(|base| w.0.borrow().memory.contains_key(base)));
            let start = if reset { 541 } else { 5_000_001_001 };
            for now in start..start + 50 {
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
            assert!(owned
                .iter()
                .all(|base| !w.0.borrow().memory.contains_key(base)));
            hardware_stop(&mut gt, &w, ack);
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_wide_every_lane_runtime_and_high_child_reset_retire_as_group
);

fn smoke_parallel_wide_last_lane_faults_and_cancel_retain_all_dma_until_reset() -> TestResult {
    for width in [3u16, 4] {
        for failure in 0..5 {
            let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 15);
            prime_mode(&mut gt, &w, 4);
            let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
            let file = RenderFile::new();
            let user = Cpu::new();
            let vm = create_vm(&file, &info, &user);
            let queue = create_width(&file, &info, &user, vm, 0, width);
            let handles = buffers(&file, &info, &user, vm);
            let weak = handles.map(|h| Arc::downgrade(&file.gem.object(h).unwrap()));
            let addresses = alloc::vec![0x1234_0000_0000; usize::from(width)];
            exec_width(&user, queue, &addresses, &[], false);
            let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 500);
            let mut registered = BTreeMap::new();
            let (id, group) = dispatch(&mut gt, &w, &mut registered, 501, failure < 2);
            let owned = owned_allocations(&w, &group);
            let retained = arena.live_allocations();
            let last = group.images[usize::from(width - 1)];
            match failure {
                0 => w.0.borrow().memory[&last].borrow_mut()[1024 + 5] = 0,
                1 => w.0.borrow().memory[&last].borrow_mut()[1025] = 0,
                2 => w.0.borrow().memory[&group.scratch].borrow_mut()[1] = 20, // stale width2 WQ extent
                3 => event(&ct_memory(&w), 0x1002, &[id + u32::from(width), 1]),
                _ => {
                    for base in group.images.iter().copied().take(usize::from(width - 1)) {
                        execute_parallel_lane(&w, id, base);
                    }
                }
            }
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
            if failure == 4 {
                for now in [5_000_001_000, 10_000_001_000] {
                    assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                }
            }
            let mut lost = false;
            for now in 540..580 {
                let now = if failure == 4 {
                    now + 15_000_001_000
                } else {
                    now
                };
                match gt.poll(now) {
                    Poll::Ready(Err(GtError::Scheduling(error))) => {
                        let expected = match failure {
                            1 => crate::intel_gpu_guc_sched::SchedulingError::Residency(
                                crate::intel_gpu_user::io_error(),
                            ),
                            4 => crate::intel_gpu_guc_sched::SchedulingError::Timeout,
                            _ => crate::intel_gpu_guc_sched::SchedulingError::Protocol,
                        };
                        assert_eq!(error, expected, "width{width} failure{failure}");
                        lost = true;
                        break;
                    }
                    Poll::Ready(Ok(GtState::SchedulingReady)) => {
                        service_contexts(&w, &mut registered, false);
                    }
                    other => panic!("width{width} failure{failure}: {other:?}"),
                }
            }
            assert!(lost, "width{width} failure{failure} silently accepted");
            assert!(context.busy() && context.banned() && fence.result().is_none());
            assert_eq!(context.reset_stats(), (0, 0));
            assert_eq!(arena.live_allocations(), retained);
            assert!(owned
                .iter()
                .all(|base| w.0.borrow().memory.contains_key(base)));
            assert!(weak.iter().all(|object| object.upgrade().is_some()));
            hardware_stop(&mut gt, &w, ack);
            assert_eq!(fence.result(), Some(Err(JobError::Reset)));
            assert_eq!(context.reset_stats(), (0, 1));
            assert!(owned
                .iter()
                .all(|base| !w.0.borrow().memory.contains_key(base)));
            assert!(weak.iter().all(|object| object.upgrade().is_none()));
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_wide_last_lane_faults_and_cancel_retain_all_dma_until_reset
);

fn smoke_parallel_wide_partial_allocation_rollback_preserves_queue_and_slots() -> TestResult {
    for width in [3u16, 4] {
        let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 15);
        prime_mode(&mut gt, &w, 4);
        let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let queue = create_width(&file, &info, &user, vm, 0, width);
        let _handles = buffers(&file, &info, &user, vm);
        let addresses = alloc::vec![0x1234_0000_0000; usize::from(width)];
        let baseline = arena.live_allocations();
        for fail in 1..=usize::from(width) * 2 + 1 {
            exec_width(&user, queue, &addresses, &[], false);
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
                context
            };
            assert!(!context.busy() && !context.banned());
            assert_eq!(
                arena.live_allocations(),
                baseline,
                "width{width} allocation{fail}"
            );
            assert!(w.0.borrow().parallel_contexts.is_empty());
        }
        exec_width(&user, queue, &addresses, &[], false);
        let (_, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 600);
        let mut registered = BTreeMap::new();
        dispatch(&mut gt, &w, &mut registered, 601, true);
        finish(&mut gt, &w, &fence, &mut registered, 640);
        assert_eq!(arena.live_allocations(), baseline);
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_wide_partial_allocation_rollback_preserves_queue_and_slots
);
