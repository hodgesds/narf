// Real Xe matrix -> GuC multi-LRC mask -> per-restore physical receipts ->
// private PPGTT execution/joins. MIT Linux b90c984d calc_validate_logical_mask,
// __register_mlrc_exec_queue and xe_lrc setup_utilization_wa supply the ABI.
use super::*;

fn matrix_wire(user: &Cpu, vm: u32, width: u16, starts: &[u16]) {
    let rows: Vec<_> = starts
        .iter()
        .flat_map(|start| (*start..*start + width).map(|logical| [4, logical, 0, 0]))
        .collect();
    queue_wire(user, vm, width, starts.len() as u16, &rows);
}
fn create_matrix(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &Cpu,
    vm: u32,
    width: u16,
    starts: &[u16],
) -> u32 {
    matrix_wire(user, vm, width, starts);
    assert_eq!(invoke(file, info, user, xe::EXEC_QUEUE_CREATE), Ok(0));
    u32_at(&user.wire.load(64, 48), 20)
}
fn mask(starts: &[u16], lane: usize) -> u32 {
    starts
        .iter()
        .fold(0, |mask, first| mask | 1 << (usize::from(*first) + lane))
}
fn receipt(engine: Engine) -> u32 {
    engine.physical_instance() << 4 | 5
}
fn retire_hung(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    fence: &CompletionFence,
    registered: &mut BTreeMap<u32, u32>,
    start: u64,
) {
    for now in start..start + 60 {
        service_contexts(w, registered, false);
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if fence.result().is_some() {
            break;
        }
    }
    assert_eq!(fence.result(), Some(Err(JobError::Hang)));
}

fn smoke_parallel_matrix_bounds_copied_placements_and_allocation_rollback() -> TestResult {
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 15);
    prime_mode(&mut gt, &w, 4);
    let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    for (width, count, rows) in [
        (
            2,
            2,
            alloc::vec![[4, 0, 0, 0], [4, 1, 0, 0], [4, 0, 0, 0], [4, 1, 0, 0]],
        ), // duplicate placement
        (
            2,
            2,
            alloc::vec![[4, 0, 0, 0], [4, 2, 0, 0], [4, 1, 0, 0], [4, 3, 0, 0]],
        ), // nonadjacent row
        (
            2,
            2,
            alloc::vec![[4, 0, 0, 0], [4, 1, 0, 0], [1, 1, 0, 0], [1, 2, 0, 0]],
        ),
        (
            2,
            2,
            alloc::vec![[4, 0, 0, 0], [4, 1, 0, 0], [4, 1, 1, 0], [4, 2, 0, 0]],
        ),
        (
            2,
            2,
            alloc::vec![[4, 0, 0, 0], [4, 1, 0, 0], [4, 1, 0, 1], [4, 2, 0, 0]],
        ),
        (
            2,
            2,
            alloc::vec![[1, 0, 0, 0], [1, 1, 0, 0], [1, 0, 0, 0], [1, 1, 0, 0]],
        ),
        (4, 3, alloc::vec![[4,0,0,0];12]),
    ] {
        queue_wire(&user, vm, width, count, &rows);
        assert_eq!(
            invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
            Err(FsError::InvalidData)
        );
    }
    matrix_wire(&user, vm, 3, &[0, 1]);
    user.fail_report
        .store(true, core::sync::atomic::Ordering::Release);
    assert_eq!(
        invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
        Err(FsError::BadAddress)
    );
    user.fail_report
        .store(false, core::sync::atomic::Ordering::Release);
    let queue = create_matrix(&file, &info, &user, vm, 3, &[1, 0]);
    assert_eq!(queue, 1, "failed proto-context did not publish a name");
    let _handles = buffers(&file, &info, &user, vm);
    let addresses = alloc::vec![0x1234_0000_0000;3];
    let baseline = arena.live_allocations();
    for failed in 1..=7 {
        exec_width(&user, queue, &addresses, &[], false);
        let context = {
            let mut future = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
            assert!(future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            let pending = mailbox.pending.lock().pop().unwrap();
            let context = pending.context.clone();
            let next = w.0.borrow().allocations + failed;
            w.0.borrow_mut().fail_at = Some(next);
            assert!(gt
                .submit_user_batch(500, context.clone(), pending.batch)
                .is_err());
            w.0.borrow_mut().fail_at = None;
            assert_eq!(
                context
                    .parallel_placements()
                    .unwrap()
                    .iter()
                    .map(|set| gt.engines().unwrap().logical_mask(*set).unwrap())
                    .collect::<Vec<_>>(),
                [3, 6, 12]
            );
            context
        };
        assert!(!context.busy() && !context.banned());
        assert_eq!(arena.live_allocations(), baseline);
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
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_matrix_bounds_copied_placements_and_allocation_rollback
);

fn smoke_parallel_matrix_gu_c_choices_private_execution_saved_state_and_gpu_join() -> TestResult {
    for platform in [GtPlatform::Alchemist, GtPlatform::Battlemage] {
        for (fuses, mode, width, starts) in [
            (13, 3, 2, alloc::vec![0, 1]),
            (15, 4, 2, alloc::vec![0, 1, 2]),
            (15, 4, 2, alloc::vec![2, 0]),
            (15, 4, 3, alloc::vec![1, 0]),
        ] {
            let (w, arena, mut gt, ack) = discover(platform, fuses);
            prime_mode(&mut gt, &w, mode);
            let (mailbox, info) = setup(&mut gt, &w, platform);
            let file = RenderFile::new();
            let user = Cpu::new();
            let vm = create_vm(&file, &info, &user);
            let queue = create_matrix(&file, &info, &user, vm, width, &starts);
            let handles = buffers(&file, &info, &user, vm);
            let addresses = lane_batches(&file, handles[0], usize::from(width));
            let baseline = arena.live_allocations();
            for job in 0..3u32 {
                let chosen = if job == 1 {
                    *starts.iter().min().unwrap()
                } else {
                    *starts.iter().max().unwrap()
                };
                w.0.borrow_mut().virtual_pick = Some(u32::from(chosen));
                let now = 500 + u64::from(job) * 100;
                let value = 0xfeed_0000_0000_0010 | u64::from(job);
                file.gem
                    .object(handles[1])
                    .unwrap()
                    .write(0x80, &[0; 136])
                    .unwrap();
                exec_width(
                    &user,
                    queue,
                    &addresses,
                    &[sync(2, 0x2345_0000_0100, value, true)],
                    job == 2,
                );
                let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, now);
                let sets = context.parallel_placements().unwrap();
                let mut registered = BTreeMap::new();
                let (id, group) = dispatch(&mut gt, &w, &mut registered, now + 1, false);
                let owned = owned_allocations(&w, &group);
                for (index, base) in group.images.iter().copied().enumerate() {
                    let d = w.0.borrow();
                    assert_eq!(d.virtual_contexts[&base], (4, mask(&starts, index)));
                    assert_eq!(
                        gt.engines().unwrap().logical_mask(sets[index]),
                        Some(mask(&starts, index))
                    );
                    let mut image = d.memory[&base].borrow_mut();
                    assert_eq!(
                        image[0x1800 / 4],
                        if job == 0 {
                            0
                        } else {
                            0xaa000000 + (job - 1) * 16 + index as u32
                        }
                    );
                    image[0x1800 / 4] = 0xaa000000 + job * 16 + index as u32;
                }
                for (index, base) in group.images.iter().copied().enumerate() {
                    execute_parallel_lane(&w, id, base);
                    let actual = gt
                        .engines()
                        .unwrap()
                        .from_class_instance(4, chosen + index as u16)
                        .unwrap();
                    assert_eq!(
                        w.0.borrow().memory[&base].borrow()[0x818 / 4],
                        receipt(actual)
                    );
                    if index + 1 < usize::from(width) {
                        assert_eq!(user.read_u64_acquire(0x4100), Ok(0));
                    }
                }
                assert_eq!(user.read_u64_acquire(0x4100), Ok(value));
                assert_eq!(w.0.borrow().parallel_join_stores.len(), job as usize + 1);
                assert!(context.busy() && fence.result().is_none());
                for index in 0..usize::from(width) {
                    assert_eq!(
                        user.read_u64_acquire(0x4080 + index as u64 * 8),
                        Ok(if job == 2 {
                            0
                        } else {
                            0xabc00000 + index as u64
                        })
                    );
                }
                finish(&mut gt, &w, &fence, &mut registered, now + 50);
                assert!(!context.busy() && !context.banned());
                assert_eq!(arena.live_allocations(), baseline);
                assert!(owned
                    .iter()
                    .all(|base| !w.0.borrow().memory.contains_key(base)));
                assert!(w.0.borrow().virtual_contexts.is_empty());
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
    smoke_parallel_matrix_gu_c_choices_private_execution_saved_state_and_gpu_join
);

fn smoke_parallel_matrix_every_lane_migration_watchdog_and_physical_timeout() -> TestResult {
    for width in [2u16, 3] {
        for guilty in 0..usize::from(width) {
            let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 15);
            prime_mode(&mut gt, &w, 4);
            let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
            w.0.borrow_mut().regs.insert(0xd00, 0);
            let file = RenderFile::new();
            let user = Cpu::new();
            let vm = create_vm(&file, &info, &user);
            let queue = create_matrix(&file, &info, &user, vm, width, &[0, 1]);
            let _handles = buffers(&file, &info, &user, vm);
            let addresses = alloc::vec![0x1234_0000_0000;usize::from(width)];
            exec_width(
                &user,
                queue,
                &addresses,
                &[sync(2, 0x2345_0000_0100, 21, true)],
                false,
            );
            let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 500);
            let mut registered = BTreeMap::new();
            let (id, group) = dispatch(&mut gt, &w, &mut registered, 501, false);
            let owned = owned_allocations(&w, &group);
            for row in 0..2u32 {
                w.0.borrow_mut().virtual_pick = Some(row);
                for (lane, base) in group.images.iter().copied().enumerate() {
                    execute_parallel_restore(&w, id, base, row == 0);
                    let engine = gt
                        .engines()
                        .unwrap()
                        .from_class_instance(4, row as u16 + lane as u16)
                        .unwrap();
                    start_lane(&w, base, engine, 3_000_000);
                }
                assert_eq!(
                    gt.poll(u64::from(row + 1) * 5_000_000_000 + 1000),
                    Poll::Ready(Ok(GtState::SchedulingReady))
                );
                assert!(
                    gt.take_error_report().is_none(),
                    "migration at equal counter is not a stuck lane"
                );
                assert!(service_contexts(&w, &mut registered, false).is_empty());
            }
            for (lane, base) in group.images.iter().copied().enumerate() {
                let physical = gt
                    .engines()
                    .unwrap()
                    .from_class_instance(4, lane as u16 + 1)
                    .unwrap();
                if lane == guilty {
                    start_lane(&w, base, physical, 15_000_000);
                } else {
                    execute_parallel_lane(&w, id, base);
                }
            }
            assert_eq!(
                gt.poll(15_000_001_000),
                Poll::Ready(Ok(GtState::SchedulingReady))
            );
            let report = gt.take_error_report().unwrap();
            let text = crate::intel_gpu_error::Snapshot {
                report,
                suppressed: 0,
            }
            .text();
            let physical = gt
                .engines()
                .unwrap()
                .from_class_instance(4, guilty as u16 + 1)
                .unwrap();
            let prefix = alloc::format!(
                "context ccs{} placements=0x{:02x} id={}",
                physical.physical_instance(),
                context.parallel_placements().unwrap()[guilty].bits(),
                id + guilty as u32
            );
            let line = text
                .lines()
                .find(|line| line.starts_with(&prefix))
                .unwrap_or_else(|| panic!("missing guilty migrated lane: {text}"));
            assert!(
                line.contains("timed_out=1 reset=0 runtime_ticks=15000000"),
                "{text}"
            );
            assert_eq!(user.read_u64_acquire(0x4100), Ok(0));
            assert!(context.busy() && fence.result().is_none());
            assert!(owned
                .iter()
                .all(|base| w.0.borrow().memory.contains_key(base)));
            retire_hung(&mut gt, &w, &fence, &mut registered, 15_000_001_001);
            assert_eq!(context.reset_stats(), (1, 0));
            assert!(context.banned() && !context.busy());
            hardware_stop(&mut gt, &w, ack);
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_matrix_every_lane_migration_watchdog_and_physical_timeout
);

fn smoke_parallel_matrix_untrusted_receipts_final_proof_and_close_require_reset() -> TestResult {
    for failure in 0..6 {
        let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 15);
        prime_mode(&mut gt, &w, 4);
        let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let queue = create_matrix(&file, &info, &user, vm, 2, &[0, 1]);
        let handles = buffers(&file, &info, &user, vm);
        let weak = handles.map(|handle| Arc::downgrade(&file.gem.object(handle).unwrap()));
        exec_width(&user, queue, &[0x1234_0000_0000; 2], &[], false);
        let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 500);
        let mut registered = BTreeMap::new();
        let (id, group) = dispatch(&mut gt, &w, &mut registered, 501, failure == 4);
        let owned = owned_allocations(&w, &group);
        let retained = arena.live_allocations();
        if failure == 4 {
            // Finish disable/deregister and stop just before final TLB ACK;
            // the final receipt check must cover the child too.
            let mut final_ack = false;
            for now in 540..560 {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                let actions = service_contexts(&w, &mut registered, false);
                if actions.contains(&0x7000) {
                    final_ack = true;
                    break;
                }
            }
            assert!(final_ack);
        } else {
            for base in group.images.iter().copied() {
                execute_parallel_restore(&w, id, base, true);
            }
        }
        match failure {
            0 => w.0.borrow().memory[&group.images[0]].borrow_mut()[0x818 / 4] = 3, //wrong class
            1 => w.0.borrow().memory[&group.images[1]].borrow_mut()[0x818 / 4] = 5, //CCS0 not in child mask
            2 => w.0.borrow().memory[&group.images[0]].borrow_mut()[0x818 / 4] = 0x35, //CCS3 not in parent mask
            3 => w.0.borrow_mut().fail_cpu_sync = true,
            4 => w.0.borrow().memory[&group.images[1]].borrow_mut()[0x818 / 4] = u32::MAX,
            _ => event(&ct_memory(&w), 0x1008, &[id + 1]),
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
        if failure == 5 {
            retire_hung(&mut gt, &w, &fence, &mut registered, 5_000_001_000);
            assert_eq!(context.reset_stats(), (1, 0));
        } else {
            let expected = if failure == 3 {
                crate::intel_gpu_guc_sched::SchedulingError::Cache
            } else {
                crate::intel_gpu_guc_sched::SchedulingError::Protocol
            };
            assert_eq!(
                gt.poll(5_000_001_000),
                Poll::Ready(Err(GtError::Scheduling(expected)))
            );
            assert!(context.busy() && fence.result().is_none());
            assert_eq!(context.reset_stats(), (0, 0));
            assert_eq!(arena.live_allocations(), retained);
            assert!(weak.iter().all(|object| object.upgrade().is_some()));
            assert!(owned
                .iter()
                .all(|base| w.0.borrow().memory.contains_key(base)));
            if failure == 0 {
                use crate::intel_gpu_error::{coredump, Reason};
                // Distinct device-saved words make every retained lane and
                // its ring independently identifiable in the passive copy.
                for (lane, base) in group.images.iter().enumerate() {
                    let d = w.0.borrow();
                    let ring = d.memory[base].borrow()[1033];
                    d.memory[base].borrow_mut()[0x1800 / 4] = 0xaabb0000 + lane as u32;
                    d.memory[&ring].borrow_mut()[0x1ffc / 4] = 0xccdd0000 + lane as u32;
                }
                w.0.borrow().memory[&group.scratch].borrow_mut()[0x300 / 4] = 0xfacefeed;
                let armed = coredump::Armed::reserve_for_test(59).unwrap();
                let report = gt.error_report(
                    Reason::Protocol,
                    0,
                    5_000_001_001,
                    || true,
                    |offset| Some(w.read32(offset)),
                );
                let (allocations, writes) = {
                    let d = w.0.borrow();
                    (d.allocations, d.writes.len())
                };
                gt.capture_coredump(armed, report, 5_000_001_002, [0xa5; 32], || true);
                assert_eq!(w.0.borrow().allocations, allocations);
                assert_eq!(
                    w.0.borrow().writes.len(),
                    writes,
                    "passive matrix capture wrote hardware"
                );
                assert_eq!(arena.live_allocations(), retained);
                assert!(context.busy() && fence.result().is_none());
                let captured = coredump::snapshot_bytes_for_test(59).unwrap();
                let word = |bytes: &[u8], at: usize| {
                    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
                };
                let exec = &captured[word(&captured, 144) as usize..];
                assert_eq!(&exec[..8], b"NARFEXEC");
                assert_eq!(
                    (
                        word(exec, 24),
                        word(exec, 28),
                        word(exec, 32),
                        word(exec, 36)
                    ),
                    (2, 2, 2, 0)
                );
                let stride = word(exec, 16) as usize;
                assert_eq!(stride, 128 + 16 * 4096 + 2 * 4096 + 4096);
                for (lane, placements) in context.parallel_placements().unwrap().iter().enumerate()
                {
                    let entry = &exec[64 + lane * stride..];
                    assert_eq!(
                        (word(entry, 0), word(entry, 4), word(entry, 8)),
                        (id + lane as u32, id, lane as u32)
                    );
                    assert_eq!(word(entry, 24), placements.bits());
                    assert_eq!(word(entry, 40), if lane == 0 { 7 } else { 3 });
                    assert_eq!((word(entry, 48), word(entry, 56)), (3 * 4096, 2 * 4096));
                    assert_eq!(
                        word(&captured, word(entry, 44) as usize + 0x1800),
                        0xaabb0000 + lane as u32
                    );
                    assert_eq!(
                        word(&captured, word(entry, 52) as usize + 0x1ffc),
                        0xccdd0000 + lane as u32
                    );
                    if lane == 0 {
                        assert_eq!(word(entry, 64), 4096);
                        assert_eq!(
                            word(&captured, word(entry, 60) as usize + 0x300),
                            0xfacefeed
                        );
                    } else {
                        assert_eq!(
                            (word(entry, 60), word(entry, 64)),
                            (0, 0),
                            "scratch belongs only to parent entry"
                        );
                    }
                }
                assert!(coredump::clear_for_test(59));
            }
        }
        w.0.borrow_mut().fail_cpu_sync = false;
        hardware_stop(&mut gt, &w, ack);
        assert!(weak.iter().all(|object| object.upgrade().is_none()));
        assert_eq!(
            fence.result(),
            Some(Err(if failure == 5 {
                JobError::Hang
            } else {
                JobError::Reset
            }))
        );
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_matrix_untrusted_receipts_final_proof_and_close_require_reset
);

fn smoke_parallel_matrix_queued_placement_progress_and_finished_lane_exclusion() -> TestResult {
    for parent_finished in [false, true] {
        let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 15);
        prime_mode(&mut gt, &w, 4);
        let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        let queue = create_matrix(&file, &info, &user, vm, 2, &[0, 1]);
        let _handles = buffers(&file, &info, &user, vm);
        exec_width(&user, queue, &[0x1234_0000_0000; 2], &[], false);
        let (context, fence) = accept(&file, &info, &user, &mailbox, &mut gt, 500);
        let mut registered = BTreeMap::new();
        let (id, group) = dispatch(&mut gt, &w, &mut registered, 501, false);
        if parent_finished {
            // Select CCS0, which belongs only to the parent placement set;
            // progress there cannot conceal the unfinished child's stall.
            w.0.borrow_mut().virtual_pick = Some(0);
            execute_parallel_lane(&w, id, group.images[0]);
        }
        let busy = UserContext::for_engine(if parent_finished {
            Engine::Ccs0
        } else {
            Engine::Ccs2
        });
        busy.configure_schedule(2, 1000).unwrap();
        for start in [4_000_000_000, 8_000_000_000, 12_000_000_000] {
            let (batch, result) = PpgttProbeResult::prepare(GtPlatform::Battlemage).unwrap();
            let (_, done) = gt
                .submit_user_batch(start, busy.clone(), UserBatch(batch))
                .unwrap();
            finish(&mut gt, &w, &done, &mut registered, start + 1);
            assert_eq!(result.verify(), Ok(()));
            assert!(context.busy() && fence.result().is_none());
        }
        if !parent_finished {
            assert_eq!(
                gt.poll(16_000_001_000),
                Poll::Ready(Ok(GtState::SchedulingReady))
            );
            assert!(context.busy() && !context.banned());
        }
        let now = if parent_finished {
            16_000_001_000
        } else {
            27_000_001_000
        };
        assert_eq!(
            gt.poll(now),
            Poll::Ready(Err(GtError::Scheduling(
                crate::intel_gpu_guc_sched::SchedulingError::Timeout
            )))
        );
        assert_eq!(context.reset_stats(), (0, 0));
        assert!(context.busy() && fence.result().is_none());
        hardware_stop(&mut gt, &w, ack);
        assert_eq!(fence.result(), Some(Err(JobError::Reset)));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_parallel",
    smoke_parallel_matrix_queued_placement_progress_and_finished_lane_exclusion
);
