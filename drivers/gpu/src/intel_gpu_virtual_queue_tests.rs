// Xe placement matrix -> GuC virtual registration -> hardware-owned engine
// receipt -> private PPGTT execution and terminal context retirement.
// Linux b90c984d xe_exec_queue.c::calc_validate_logical_mask,
// xe_guc_submit.c::__register_exec_queue and xe_lrc.c::setup_utilization_wa.
use super::*;
use crate::intel_gpu_engine::EngineSet;

fn queue_wire(user: &Cpu, vm: u32, width: u16, entries: &[[u16; 4]]) {
    let instances: Vec<_> = entries
        .iter()
        .flatten()
        .flat_map(|n| n.to_le_bytes())
        .collect();
    user.wire.store(512, &instances);
    let mut wire = [0; 48];
    put32(
        &mut wire,
        8,
        u32::from(width) | (entries.len() as u32) << 16,
    );
    put32(&mut wire, 12, vm);
    put64(&mut wire, 24, 512);
    user.wire.store(64, &wire);
}

fn smoke_virtual_queue_matrix_validation_and_dense_physical_masks() -> TestResult {
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    let (_, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    for (width, entries) in [
        (0, alloc::vec![[4, 0, 0, 0]]),
        (2, alloc::vec![[4, 0, 0, 0], [4, 1, 0, 0]]),
        (1, alloc::vec![]),
        (1, alloc::vec![[4, 0, 0, 0]; 10]),
        (1, alloc::vec![[4, 0, 0, 0], [1, 1, 0, 0]]),
        (1, alloc::vec![[4, 0, 0, 0], [4, 1, 1, 0]]),
        (1, alloc::vec![[4, 0, 0, 0], [4, 1, 0, 1]]),
        (1, alloc::vec![[4, 0, 0, 0], [4, 2, 0, 0]]),
        (1, alloc::vec![[1, 0, 0, 0], [1, 8, 0, 0]]),
        (1, alloc::vec![[5, 0, 0, 0], [5, 0, 0, 0]]),
    ] {
        queue_wire(&user, vm, width, &entries);
        assert_eq!(
            invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE),
            Err(FsError::InvalidData)
        );
    }
    // Linux collapses duplicate placements rather than interpreting them as
    // weights or parallel width. Nine entries remains the ABI matrix bound.
    queue_wire(&user, vm, 1, &[[4, 1, 0, 0]; 9]);
    assert_eq!(invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE), Ok(0));
    let queue = u32_at(&user.wire.load(64, 48), 20);
    assert_eq!(
        close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
        Ok(0)
    );
    let present = gt.engines().unwrap();
    let sparse = EngineSet::of(&[Engine::Ccs1, Engine::Ccs3]);
    assert_eq!(present.logical_mask(sparse), Some(3));
    assert_eq!(
        present.logical_mask(EngineSet::of(&[Engine::Ccs3])),
        Some(2)
    );
    assert_eq!(present.logical_mask(EngineSet::of(&[Engine::Ccs0])), None);
    assert_eq!(
        present.logical_mask(EngineSet::of(&[Engine::Ccs1, Engine::Bcs0])),
        None
    );
    assert_eq!(present.logical_mask(EngineSet::default()), None);
    assert_eq!(sparse.decode_hardware_id(0x15), Some(Engine::Ccs1));
    assert_eq!(sparse.decode_hardware_id(0x35), Some(Engine::Ccs3));
    assert_eq!(
        sparse.decode_hardware_id(0x14),
        None,
        "GuC compute class is not hardware class"
    );
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_virtual_queues",
    smoke_virtual_queue_matrix_validation_and_dense_physical_masks
);

fn smoke_virtual_queue_guc_selection_migration_and_saved_context() -> TestResult {
    for (platform, class) in [
        (GtPlatform::Alchemist, 4u16),
        (GtPlatform::Battlemage, 4),
        (GtPlatform::Battlemage, 1),
    ] {
        let (w, arena, mut gt, ack) = discover(platform, 10);
        prime_mode(&mut gt, &w, 2);
        let (mailbox, info) = setup(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        queue_wire(
            &user,
            vm,
            1,
            &[[class, 1, 0, 0], [class, 0, 0, 0], [class, 1, 0, 0]],
        );
        assert_eq!(invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE), Ok(0));
        let queue = u32_at(&user.wire.load(64, 48), 20);
        let handles = buffers(&file, &info, &user, vm);
        let placements = if class == 4 {
            EngineSet::of(&[Engine::Ccs1, Engine::Ccs3])
        } else {
            EngineSet::of(&[Engine::Bcs0, Engine::Bcs8])
        };
        let baseline = arena.live_allocations();
        let mut identity = None;
        for (iteration, logical, hardware) in [
            (0, 1, if class == 4 { 0x35 } else { 0x83 }),
            (1, 0, if class == 4 { 0x15 } else { 3 }),
        ] {
            w.0.borrow_mut().virtual_pick = Some(logical);
            file.gem
                .object(handles[1])
                .unwrap()
                .write(0x80, &[0; 4])
                .unwrap();
            exec_wire(&user, queue, true, &[]);
            let (context, fence) = {
                let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
                assert!(call
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
                let accepted = mailbox.accept(&mut gt, 500 + iteration * 100);
                assert_eq!(
                    call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Some(Ok(0)))
                );
                accepted
            };
            assert_eq!(context.placements(), placements);
            if let Some(previous) = &identity {
                assert!(
                    Arc::ptr_eq(previous, &context),
                    "one persistent virtual LRC"
                );
            }
            identity = Some(context.clone());
            let mut registered = BTreeMap::new();
            let mut saw = false;
            for now in 501 + iteration * 100..580 + iteration * 100 {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                service_contexts(&w, &mut registered, true);
                if !saw {
                    if let Some(base) = registered.values().next() {
                        let d = w.0.borrow();
                        assert_eq!(
                            d.virtual_contexts[base],
                            (if class == 4 { 4 } else { 3 }, 3)
                        );
                        let mut image = d.memory[base].borrow_mut();
                        assert_eq!(
                            image[0x1800 / 4],
                            if iteration == 0 { 0 } else { 0xa11c0001 }
                        );
                        image[0x1800 / 4] = 0xa11c0001 + iteration as u32;
                        saw = true;
                    }
                }
                if fence.result().is_some() {
                    break;
                }
            }
            assert!(saw && registered.is_empty());
            assert_eq!(fence.result(), Some(Ok(())));
            assert_eq!(w.0.borrow().virtual_restores.last().unwrap().1, hardware);
            assert_eq!(user.read_u64_acquire(0x4080), Ok(0x4e415246));
            assert_eq!(arena.live_allocations(), baseline);
            assert!(!context.busy() && !context.banned());
        }
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_virtual_queues",
    smoke_virtual_queue_guc_selection_migration_and_saved_context
);

fn smoke_virtual_queue_preemption_migrates_one_live_context_without_false_hang() -> TestResult {
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    w.0.borrow_mut().regs.insert(0xd00, 0);
    let context =
        UserContext::for_placements(EngineSet::of(&[Engine::Ccs1, Engine::Ccs3])).unwrap();
    let (batch, result) = PpgttProbeResult::prepare(GtPlatform::Battlemage).unwrap();
    let (id, fence) = gt
        .submit_user_batch(500, context.clone(), UserBatch(batch))
        .unwrap();
    let mut registered = BTreeMap::new();
    for now in 501..530 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
    }
    let base = registered[&u32::from(id)];
    w.0.borrow_mut().virtual_pick = Some(0);
    execute_virtual_restore(&w, base, true);
    w.0.borrow_mut().regs.insert(0x1c3a8, 3_000_000);
    assert_eq!(
        gt.poll(5_000_001_000),
        Poll::Ready(Ok(GtState::SchedulingReady))
    );
    // Hardware saves the accumulated counter, then GuC restores the same
    // image on physical CCS3. An equal counter on a new engine is no hang.
    w.0.borrow().memory[&base].borrow_mut()[0x108c / 4] = 3_000_000;
    w.0.borrow_mut().virtual_pick = Some(1);
    execute_virtual_restore(&w, base, false);
    w.0.borrow_mut().regs.insert(0x263a8, 3_000_000);
    assert_eq!(
        gt.poll(10_000_001_000),
        Poll::Ready(Ok(GtState::SchedulingReady))
    );
    w.0.borrow_mut().regs.insert(0x263a8, 6_000_000);
    assert_eq!(
        gt.poll(15_000_001_000),
        Poll::Ready(Ok(GtState::SchedulingReady))
    );
    // Another context preempts it. Wall time must not inflate the two
    // seconds accumulated across both physical placements.
    w.0.borrow().memory[&base].borrow_mut()[0x108c / 4] = 6_000_000;
    w.0.borrow_mut().regs.insert(0x26240, 0);
    assert_eq!(
        gt.poll(20_000_001_000),
        Poll::Ready(Ok(GtState::SchedulingReady))
    );
    assert!(fence.result().is_none() && !context.banned());
    execute_compute(&w, base);
    finish_policy(&mut gt, &w, &fence, &mut registered, 20_000_001_001, 3);
    assert_eq!(result.verify(), Ok(()));
    assert_eq!(w.0.borrow().virtual_restores, [(base, 0x15), (base, 0x35)]);
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_virtual_queues",
    smoke_virtual_queue_preemption_migrates_one_live_context_without_false_hang
);

fn smoke_virtual_queue_queued_context_accepts_other_placement_progress() -> TestResult {
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 2);
    let context =
        UserContext::for_placements(EngineSet::of(&[Engine::Ccs1, Engine::Ccs3])).unwrap();
    let innocent = UserContext::for_engine(Engine::Ccs3);
    let (batch, result) = PpgttProbeResult::prepare(GtPlatform::Battlemage).unwrap();
    let (_, pending) = gt
        .submit_user_batch(500, context.clone(), UserBatch(batch))
        .unwrap();
    let mut registered = BTreeMap::new();
    for now in 501..530 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
    }
    for start in [4_000_000_000, 8_000_000_000, 12_000_000_000, 16_000_000_000] {
        let (batch, good) = PpgttProbeResult::prepare(GtPlatform::Battlemage).unwrap();
        let (_, done) = gt
            .submit_user_batch(start, innocent.clone(), UserBatch(batch))
            .unwrap();
        finish_policy(&mut gt, &w, &done, &mut registered, start + 1, 3);
        assert_eq!(good.verify(), Ok(()));
        assert!(pending.result().is_none() && !context.banned());
    }
    assert!(
        w.0.borrow().virtual_restores.is_empty(),
        "queued virtual context never started"
    );
    hardware_stop(&mut gt, &w, ack);
    assert_eq!(pending.result(), Some(Err(JobError::Reset)));
    assert!(!innocent.banned());
    drop((gt, result));
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_virtual_queues",
    smoke_virtual_queue_queued_context_accepts_other_placement_progress
);

fn smoke_virtual_queue_watchdog_uses_every_physical_engine_and_terminal_retirement() -> TestResult {
    for engine in [
        Engine::Bcs0,
        Engine::Bcs8,
        Engine::Ccs0,
        Engine::Ccs1,
        Engine::Ccs2,
        Engine::Ccs3,
    ] {
        let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 15);
        prime_mode(&mut gt, &w, 4);
        // RPM_CONFIG0=0 gives an independently known 3MHz clock.
        w.0.borrow_mut().regs.insert(0xd00, 0);
        let epoch = gt.user_epoch();
        let placements = if engine.is_copy() {
            EngineSet::of(&[Engine::Bcs0, Engine::Bcs8])
        } else {
            EngineSet::of(&[Engine::Ccs0, Engine::Ccs1, Engine::Ccs2, Engine::Ccs3])
        };
        let guilty = UserContext::for_placements(placements).unwrap();
        let (batch, result) = PpgttProbeResult::prepare(GtPlatform::Battlemage).unwrap();
        let weak = result.weak_objects();
        drop(result);
        let (id, fence) = gt
            .submit_user_batch(500, guilty.clone(), UserBatch(batch))
            .unwrap();
        let mut registered = BTreeMap::new();
        for now in 501..530 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, false);
        }
        let base = registered[&u32::from(id)];
        let logical = gt.engines().unwrap().logical_instance(engine).unwrap();
        w.0.borrow_mut().virtual_pick = Some(u32::from(logical));
        execute_virtual_restore(&w, base, true);
        w.0.borrow_mut()
            .regs
            .insert(u64::from(engine.base()) + 0x3a8, 15_000_000);
        let retained = arena.live_allocations();
        assert_eq!(
            gt.poll(5_000_001_000),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        let report = gt
            .take_error_report()
            .expect("actual physical runtime exceeded five seconds");
        let text = crate::intel_gpu_error::Snapshot {
            report,
            suppressed: 0,
        }
        .text();
        let name = match engine {
            Engine::Bcs0 => "bcs0",
            Engine::Bcs8 => "bcs8",
            Engine::Ccs0 => "ccs0",
            Engine::Ccs1 => "ccs1",
            Engine::Ccs2 => "ccs2",
            Engine::Ccs3 => "ccs3",
            Engine::Rcs0 => unreachable!(),
        };
        assert!(text.contains(&alloc::format!(
            "context {} placements=0x{:02x}",
            name,
            placements.bits()
        )));
        assert!(text.contains("runtime_ticks=15000000"));
        assert!(fence.result().is_none() && weak.iter().all(|o| o.upgrade().is_some()));
        assert_eq!(arena.live_allocations(), retained);
        for now in 5_000_001_001..5_000_001_080 {
            service_contexts(&w, &mut registered, false);
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            if fence.result().is_some() {
                break;
            }
        }
        assert_eq!(fence.result(), Some(Err(JobError::Hang)));
        assert!(guilty.banned() && !guilty.busy());
        assert_eq!(guilty.reset_stats(), (1, 0));
        assert_eq!(gt.user_epoch(), epoch);
        assert!(weak.iter().all(|o| o.upgrade().is_none()));
        assert!(registered.is_empty());
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_virtual_queues",
    smoke_virtual_queue_watchdog_uses_every_physical_engine_and_terminal_retirement
);

fn smoke_virtual_queue_close_and_untrusted_receipt_require_reset_before_reclaim() -> TestResult {
    for bad_receipt in [false, true] {
        let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
        prime_mode(&mut gt, &w, 2);
        let (mailbox, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = create_vm(&file, &info, &user);
        queue_wire(&user, vm, 1, &[[4, 0, 0, 0], [4, 1, 0, 0]]);
        assert_eq!(invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE), Ok(0));
        let queue = u32_at(&user.wire.load(64, 48), 20);
        let handles = buffers(&file, &info, &user, vm);
        let weak = handles.map(|handle| Arc::downgrade(&file.gem.object(handle).unwrap()));
        exec_wire(&user, queue, true, &[]);
        let (context, fence) = {
            let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            let accepted = mailbox.accept(&mut gt, 500);
            assert_eq!(
                call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Some(Ok(0)))
            );
            accepted
        };
        let mut registered = BTreeMap::new();
        for now in 501..530 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, false);
        }
        assert!(context.busy() && !context.banned());
        assert_eq!(context.reset_stats(), (0, 0));
        assert_eq!(
            close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
            Ok(0)
        );
        // Destroy immediately closes admission through request_ban, without
        // deciding guilt or establishing any terminal device completion.
        assert!(context.banned());
        assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
        for handle in handles {
            assert_eq!(close(&file, &info, &user, abi::GEM_CLOSE, handle), Ok(0));
        }
        user.mapping.lock().take();
        let retained = arena.live_allocations();
        if bad_receipt {
            let base = *registered.values().next().unwrap();
            execute_virtual_restore(&w, base, true);
            // Physical CCS0 is outside this sparse queue's placement set.
            w.0.borrow().memory[&base].borrow_mut()[0x818 / 4] = 5;
            assert_eq!(
                gt.poll(5_000_001_000),
                Poll::Ready(Err(GtError::Scheduling(
                    crate::intel_gpu_guc_sched::SchedulingError::Protocol
                )))
            );
        } else {
            // Never-started is innocent; bounded group liveness eventually
            // resets the GT rather than blaming an arbitrary placement.
            for now in [5_000_001_000, 10_000_001_000] {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            }
            assert_eq!(
                gt.poll(15_000_001_000),
                Poll::Ready(Err(GtError::Scheduling(
                    crate::intel_gpu_guc_sched::SchedulingError::Timeout
                )))
            );
        }
        assert_eq!(
            fence.result(),
            None,
            "terminal fence before reset, bad_receipt={bad_receipt}"
        );
        assert!(
            context.busy(),
            "GPU ownership ended before reset, bad_receipt={bad_receipt}"
        );
        assert!(context.banned(), "destroyed queue reopened admission");
        assert_eq!(
            context.reset_stats(),
            (0, 0),
            "close or uncertain execution guessed guilt"
        );
        assert_eq!(arena.live_allocations(), retained);
        assert!(weak.iter().all(|o| o.upgrade().is_some()));
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
    "drivers/gpu/intel_gpu_virtual_queues",
    smoke_virtual_queue_close_and_untrusted_receipt_require_reset_before_reclaim
);
