// Production multi-CCS conversations. Independent literal vectors from MIT
// Linux b90c984d xe_gt_ccs_mode.c, xe_hw_engine.c, xe_lrc.c and GuC ADS ABI.
use super::*;
use crate::intel_gpu_engine::{ccs_mode, compute_selection, Engine};

fn discover(platform: GtPlatform, mask: u8) -> (Window, Arena, GuCGt<Window, Arena>, u64) {
    let ack = if platform == GtPlatform::Alchemist {
        0x130044
    } else {
        0xdfc
    };
    let (w, arena, mut gt) = hardware_model(platform, ack);
    {
        let mut d = w.0.borrow_mut();
        if platform == GtPlatform::Battlemage {
            d.regs
                .insert(0x9114, 0x10 | (u32::from(mask) << 16) | (1 << 20));
        } else {
            let dss = (0..4)
                .filter(|n| mask & (1 << n) != 0)
                .fold(0, |dss, n| dss | 1 << (n * 8));
            d.regs.insert(0x913c, dss);
            d.regs.insert(0x9144, 0);
        }
    }
    hardware_discovery(&mut gt, &w, ack);
    (w, arena, gt, ack)
}

fn prime_mode(gt: &mut GuCGt<Window, Arena>, w: &Window, mode: u8) {
    hardware_scheduling_reload_mode(gt, w, mode);
    gt.begin_ct(18).unwrap();
    for now in 19..25 {
        w.0.borrow_mut().regs.insert(0x190240, 0xf0000001);
        assert!(gt.poll(now).is_pending());
    }
    w.0.borrow_mut().regs.insert(0x190240, 0xf0000000);
    assert_eq!(gt.poll(25), Poll::Ready(Ok(GtState::SchedulingReady)));
    let completion = gt.begin_context_defaults(26).unwrap();
    let mut registered = BTreeMap::new();
    for now in 27..400 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(w, &mut registered, true);
        if completion.result().is_some() {
            break;
        }
    }
    assert_eq!(completion.result(), Some(Ok(())));
    assert!(registered.is_empty());
}

fn smoke_multi_ccs_partition_validation_sparse_mapping_and_literals() -> TestResult {
    for mask in 0u8..16 {
        for requested in 0u8..6 {
            let slices = mask.count_ones();
            let valid = (requested == 1 && slices == 0)
                || (requested != 0
                    && u32::from(requested) <= slices
                    && slices % u32::from(requested) == 0);
            assert_eq!(compute_selection(mask, requested).is_some(), valid);
            if let Some(set) = compute_selection(mask, requested) {
                assert_eq!(
                    set.compute().count(),
                    usize::from(requested).min(slices as usize)
                );
                for (logical, engine) in set.compute().enumerate() {
                    assert!(mask & (1 << engine.physical_instance()) != 0);
                    assert_eq!(set.logical_instance(engine), Some(logical as u16));
                    assert_eq!(set.from_class_instance(4, logical as u16), Some(engine));
                }
                assert_eq!(
                    set.from_class_instance(4, set.compute().count() as u16),
                    None
                );
            }
        }
    }
    for (mask, count, expected) in [
        (15, 1, 0x0fff0000),
        (15, 2, 0x0fff0208),
        (15, 4, 0x0fff0688),
        (10, 1, 0x0fff03cf),
        (10, 2, 0x0fff07cf),
        (7, 3, 0x0fff0e88),
    ] {
        assert_eq!(ccs_mode(mask, count), Some(expected));
    }
    assert_eq!(compute_selection(0x80, 1), None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_multi_ccs",
    smoke_multi_ccs_partition_validation_sparse_mapping_and_literals
);

fn smoke_multi_ccs_ads_defaults_per_instance_private_execution_and_retirement() -> TestResult {
    for platform in [GtPlatform::Alchemist, GtPlatform::Battlemage] {
        for (mask, mode, selected, partition) in [
            (15, 2, 3, 0x208),
            (15, 4, 15, 0x688),
            (7, 3, 7, 0xe88),
            (10, 1, 2, 0x3cf),
            (10, 2, 10, 0x7cf),
            (8, 1, 8, 0),
        ] {
            let (w, arena, mut gt, ack) = discover(platform, mask);
            prime_mode(&mut gt, &w, mode);
            let engines = gt.engines().unwrap();
            let actual = engines
                .compute()
                .fold(0u8, |bits, e| bits | 1 << e.physical_instance());
            assert_eq!(actual, selected);
            {
                let d = w.0.borrow();
                if mask.count_ones() > 1 {
                    assert_eq!(d.regs[&0x14804] & 0xfff, partition);
                }
                let ads = d.memory[&0x20001000].borrow();
                assert_eq!(ads[(0x123c + 528) / 4], u32::from(selected));
                let mut logical = 0;
                for (physical, base) in [0x1a000u32, 0x1c000, 0x1e000, 0x26000]
                    .into_iter()
                    .enumerate()
                {
                    let header = (0x400 + physical * 8) / 4;
                    if selected & (1 << physical) == 0 {
                        assert_eq!((ads[header], ads[header + 1]), (0, 0));
                        continue;
                    }
                    let map = (ads[(0x123c + 128) / 4] >> (logical * 8)) & 255;
                    assert_eq!(map, physical as u32);
                    logical += 1;
                    assert_eq!(ads[header + 1], 3);
                    let saves = (ads[header] - 0x20001000) as usize / 4;
                    assert_eq!(
                        [ads[saves], ads[saves + 4], ads[saves + 8]],
                        [base + 0x29c, base + 0x80, base + 0xa8]
                    );
                    assert_eq!(d.regs[&u64::from(base + 0x4d0)], 0x1000dafc);
                    for n in 3..12 {
                        assert_eq!(d.regs[&u64::from(base + 0x4d0 + n * 4)], base + 0x94);
                    }
                }
                // The per-class golden comes from the first published CCS,
                // including sparse fuses where physical CCS0 is absent.
                let golden = d.memory[&ads[0x1024 / 4]].borrow();
                assert_eq!(
                    golden[1026],
                    [0x1a244, 0x1c244, 0x1e244, 0x26244][selected.trailing_zeros() as usize]
                );
            }
            let baseline = arena.live_allocations();
            for engine in engines.compute() {
                let probe = gt.submit_ppgtt_probe_on(500, engine).unwrap();
                let weak = probe.result.weak_objects();
                let mut registered = BTreeMap::new();
                finish_policy(&mut gt, &w, &probe.completion, &mut registered, 501, 3);
                assert_eq!(probe.result.verify(), Ok(()));
                drop(probe);
                assert!(weak.iter().all(|o| o.upgrade().is_none()));
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
    "drivers/gpu/intel_gpu_multi_ccs",
    smoke_multi_ccs_ads_defaults_per_instance_private_execution_and_retirement
);

fn smoke_multi_ccs_sparse_xe_query_queue_submission_and_timestamp() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt, ack) = discover(platform, 10);
    prime_mode(&mut gt, &w, 2);
    let (mailbox, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let reply = xe_query(&file, &info, &user, 0);
    assert_eq!(reply.len(), 8 + 5 * 32);
    assert_eq!(u32_at(&reply, 0), 5);
    for (entry, pair) in reply[8..].chunks_exact(32).zip([
        [0, 0, 0, 0],
        [1, 0, 0, 0],
        [1, 0, 1, 0],
        [4, 0, 0, 0],
        [4, 0, 1, 0],
    ]) {
        assert_eq!(&entry[..4], &pair);
        assert!(entry[4..].iter().all(|byte| *byte == 0));
    }
    let vm = create_vm(&file, &info, &user);
    let handles = buffers(&file, &info, &user, vm);
    for (logical, physical) in [(0, Engine::Ccs1), (1, Engine::Ccs3)] {
        file.gem
            .object(handles[1])
            .unwrap()
            .write(128, &[0; 4])
            .unwrap();
        let queue = create_queue_instance(&file, &info, &user, vm, 4, logical);
        exec_wire(&user, queue, true, &[]);
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (context, fence) = mailbox.accept(&mut gt, 700);
        assert_eq!(context.engine(), physical);
        assert_eq!(ready(call.as_mut()), Some(Ok(0)));
        let mut registered = BTreeMap::new();
        finish(&mut gt, &w, &fence, &mut registered, 701);
        let mut output = [0; 4];
        file.gem
            .object(handles[1])
            .unwrap()
            .read(128, &mut output)
            .unwrap();
        assert_eq!(u32::from_le_bytes(output), 0x4e415246);
    }
    w.0.borrow_mut().regs.insert(0x26358, 0x12345678);
    w.0.borrow_mut().regs.insert(0x2635c, 0xabcdef);
    assert_eq!(
        gt.engine_cycles(Engine::Ccs3, 1).unwrap().engine_cycles,
        0xabcdef12345678
    );
    assert_eq!(gt.engine_cycles(Engine::Ccs0, 1), Err(GtError::State));
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_multi_ccs",
    smoke_multi_ccs_sparse_xe_query_queue_submission_and_timestamp
);

fn smoke_multi_ccs_refused_modes_and_lost_policy_retain_until_reset() -> TestResult {
    for platform in [GtPlatform::Alchemist, GtPlatform::Battlemage] {
        for mode in [0, 2, 4, 5] {
            let (w, arena, mut gt, ack) = discover(platform, 7);
            let count = arena.live_allocations();
            let writes = w.0.borrow().writes.len();
            assert!(matches!(
                gt.begin_scheduling_with_ccs_mode(12, mode),
                Err(GtError::Registers(
                    crate::intel_gpu_gt_registers::RegisterError::ComputeMode
                ))
            ));
            assert_eq!(gt.state(), GtState::Ready);
            assert_eq!(arena.live_allocations(), count);
            assert_eq!(w.0.borrow().writes.len(), writes);
            hardware_stop(&mut gt, &w, ack);
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
        for lost_register in [0x264d0, 0x14800, 0x14804] {
            let (w, arena, mut gt, ack) = discover(platform, 10);
            prime_mode(&mut gt, &w, 2);
            let epoch = gt.user_epoch();
            let probe = gt.submit_ppgtt_probe_on(500, Engine::Ccs3).unwrap();
            let weak = probe.result.weak_objects();
            drop(probe.result);
            let mut registered = BTreeMap::new();
            for now in 501..520 {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                service_contexts(&w, &mut registered, false);
            }
            let retained = arena.live_allocations();
            w.0.borrow_mut().regs.insert(
                lost_register,
                if lost_register == 0x264d0 { 0xdafc } else { 0 },
            );
            let writes = w.0.borrow().writes.len();
            // Policy is revalidated at admission, before allocating or
            // registering another job, without repairing a live engine.
            assert_eq!(
                gt.submit_ppgtt_probe_on(521, Engine::Ccs3).map(|_| ()),
                Err(GtError::Registers(
                    crate::intel_gpu_gt_registers::RegisterError::Verify(lost_register)
                ))
            );
            assert_eq!(gt.state(), GtState::Lost);
            assert_eq!(w.0.borrow().writes.len(), writes);
            assert_eq!(
                w.0.borrow().regs[&lost_register],
                if lost_register == 0x264d0 { 0xdafc } else { 0 }
            );
            assert!(gt.user_epoch().is_none() && epoch.is_some());
            assert_eq!(arena.live_allocations(), retained);
            assert!(probe.completion.result().is_none());
            assert!(weak.iter().all(|o| o.upgrade().is_some()));
            hardware_stop(&mut gt, &w, ack);
            assert_eq!(
                probe.completion.result(),
                Some(Err(crate::intel_gpu_fence::JobError::Reset))
            );
            assert!(weak.iter().all(|o| o.upgrade().is_none()));
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_multi_ccs",
    smoke_multi_ccs_refused_modes_and_lost_policy_retain_until_reset
);

fn smoke_multi_ccs_timeout_bans_only_physical_ccs3_after_terminal_retirement() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt, ack) = discover(platform, 10);
    prime_mode(&mut gt, &w, 2);
    let epoch = gt.user_epoch();
    let guilty = UserContext::for_engine(Engine::Ccs3);
    let innocent = UserContext::for_engine(Engine::Ccs1);
    let (batch, bad_result) = PpgttProbeResult::prepare(platform).unwrap();
    let (bad_id, bad) = gt
        .submit_user_batch(500, guilty.clone(), UserBatch(batch))
        .unwrap();
    let weak = bad_result.weak_objects();
    drop(bad_result);
    let (batch, good_result) = PpgttProbeResult::prepare(platform).unwrap();
    let (good_id, good) = gt
        .submit_user_batch(500, innocent.clone(), UserBatch(batch))
        .unwrap();
    assert_ne!(bad_id, good_id);
    let mut registered = BTreeMap::new();
    for now in 501..530 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
    }
    execute_compute(&w, registered[&u32::from(good_id)]);
    finish_policy(&mut gt, &w, &good, &mut registered, 531, 3);
    assert_eq!(good_result.verify(), Ok(()));
    let base = registered[&u32::from(bad_id)];
    model_runtime(&w, base, 0, 15_000_000, true);
    assert_eq!(
        gt.poll(5_000_001_000),
        Poll::Ready(Ok(GtState::SchedulingReady))
    );
    assert!(bad.result().is_none());
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    for now in 5_000_001_001..5_000_001_060 {
        service_contexts(&w, &mut registered, false);
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if bad.result().is_some() {
            break;
        }
    }
    assert_eq!(
        bad.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Hang))
    );
    assert!(guilty.banned() && !innocent.banned());
    assert!(weak.iter().all(|object| object.upgrade().is_none()));
    assert_eq!(gt.user_epoch(), epoch);
    assert!(registered.is_empty());
    hardware_stop(&mut gt, &w, ack);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_multi_ccs",
    smoke_multi_ccs_timeout_bans_only_physical_ccs3_after_terminal_retirement
);
