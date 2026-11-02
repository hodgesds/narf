// Native production Control -> GuCGt full-stop -> rebuilt owner conversations.
use super::*;
use crate::intel_gpu_ccs_control::Control;
use core::sync::atomic::{AtomicU64, Ordering};

fn finish_stop(gt: &mut GuCGt<Window, Arena>, w: &Window, arena: &Arena, ack: u64, now: u64) {
    assert_eq!(gt.state(), GtState::Stopping);
    let retained = arena.live_allocations();
    assert!(gt.poll(now + 1).is_pending());
    reset_done(w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(now + 2).is_pending());
    assert_eq!(gt.state(), GtState::ResettingEngines);
    assert_eq!(
        arena.live_allocations(),
        retained,
        "GuC reset was treated as engine stop"
    );
    assert!(gt.poll(now + 3).is_pending());
    assert_eq!(arena.live_allocations(), retained);
    reset_done(w);
    assert!(gt.poll(now + 4).is_pending());
    assert_eq!(gt.state(), GtState::ReleasingRender);
    assert!(arena.live_allocations() < retained);
    assert!(gt.poll(now + 5).is_pending());
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(now + 6).is_pending());
    w.0.borrow_mut().regs.insert(ack, 0);
    assert_eq!(gt.poll(now + 7), Poll::Ready(Ok(GtState::Stopped)));
}

fn rebuild(
    w: &Window,
    arena: &Arena,
    platform: GtPlatform,
    ack: u64,
    mode: u8,
) -> GuCGt<Window, Arena> {
    assert_eq!(arena.live_allocations(), 0);
    // The new production GGTT owner starts its free arena at the same base
    // only after the old owner was proven stopped and destroyed.
    w.0.borrow_mut().next = 0x20000000;
    let mut boot = stage(w.clone(), arena.clone(), platform);
    if platform == GtPlatform::Battlemage {
        boot.config.uncached_mocs = Some(3);
    }
    let mut gt = GuCGt::from_staged_hardware(boot).unwrap();
    hardware_discovery(&mut gt, w, ack);
    prime_mode(&mut gt, w, mode);
    gt
}

fn all_private_probes(gt: &mut GuCGt<Window, Arena>, w: &Window, control: &Control) {
    for engine in gt.engines().unwrap().iter() {
        let probe = gt.submit_ppgtt_probe_on(500, engine).unwrap();
        assert!(
            control.fixture_client().is_err(),
            "gate reopened before startup probes"
        );
        let mut registered = BTreeMap::new();
        finish_policy(gt, w, &probe.completion, &mut registered, 501, 3);
        assert_eq!(probe.result.verify(), Ok(()));
    }
}

fn smoke_dynamic_ccs_full_reset_rebuilds_every_engine_before_new_epoch() -> TestResult {
    for platform in [GtPlatform::Alchemist, GtPlatform::Battlemage] {
        let (w, arena, mut gt, ack) = discover(platform, 15);
        prime_mode(&mut gt, &w, 1);
        let control = Control::fixture();
        let epoch = AtomicU64::new(gt.user_epoch().unwrap());
        control
            .publish(epoch.load(Ordering::Acquire), (15, 1))
            .unwrap();
        for mode in [2, 4, 1] {
            let old_epoch = epoch.load(Ordering::Acquire);
            let client = control.fixture_client().unwrap();
            let writes = w.0.borrow().writes.len();
            assert_eq!(control.fixture_request(mode), Err(FsError::Busy));
            assert_eq!(w.0.borrow().writes.len(), writes);
            drop(client);
            assert_eq!(control.fixture_request(mode), Ok(()));
            assert!(control.fixture_client().is_err());
            assert_eq!(
                control.begin(&mut gt, old_epoch, 1000, |_| {
                    assert_eq!(w.0.borrow().writes.len(), writes);
                    epoch.store(0, Ordering::Release);
                }),
                Ok(Some(mode))
            );
            assert_eq!(epoch.load(Ordering::Acquire), 0);
            finish_stop(&mut gt, &w, &arena, ack, 1000);
            assert!(control.fixture_client().is_err());
            drop(gt);
            assert_eq!(arena.live_allocations(), 0);
            gt = rebuild(&w, &arena, platform, ack, mode);
            assert_ne!(gt.user_epoch(), Some(old_epoch));
            all_private_probes(&mut gt, &w, &control);
            let current = gt.user_epoch().unwrap();
            assert_eq!(
                control.publish_with(current, (15, mode), || {
                    assert!(control.fixture_client().is_err());
                    epoch.store(current, Ordering::Release);
                }),
                Ok(())
            );
            assert_eq!(epoch.load(Ordering::Acquire), current);
            drop(control.fixture_client().unwrap());
            assert!(gt.idle());
        }
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ccs_control",
    smoke_dynamic_ccs_full_reset_rebuilds_every_engine_before_new_epoch
);

fn smoke_dynamic_ccs_busy_lastclose_job_refuses_reset_without_reclaim() -> TestResult {
    let (w, arena, mut gt, ack) = discover(GtPlatform::Battlemage, 10);
    prime_mode(&mut gt, &w, 1);
    let epoch = gt.user_epoch().unwrap();
    let control = Control::fixture();
    control.publish(epoch, (10, 1)).unwrap();
    let probe = gt.submit_ppgtt_probe_on(500, Engine::Ccs1).unwrap();
    let weak = probe.result.weak_objects();
    drop(probe.result);
    let retained = arena.live_allocations();
    let writes = w.0.borrow().writes.len();
    control.fixture_request(2).unwrap();
    assert_eq!(
        control.begin(&mut gt, epoch, 501, |_| panic!("busy job admitted reset")),
        Ok(None)
    );
    assert_eq!(gt.state(), GtState::SchedulingReady);
    assert_eq!(gt.user_epoch(), Some(epoch));
    assert_eq!(arena.live_allocations(), retained);
    assert_eq!(w.0.borrow().writes.len(), writes);
    assert!(probe.completion.result().is_none());
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    drop(control.fixture_client().unwrap());
    let mut registered = BTreeMap::new();
    finish_policy(&mut gt, &w, &probe.completion, &mut registered, 502, 3);
    assert!(weak.iter().all(|object| object.upgrade().is_none()));
    control.fixture_request(2).unwrap();
    assert_eq!(control.begin(&mut gt, epoch, 600, |_| {}), Ok(Some(2)));
    finish_stop(&mut gt, &w, &arena, ack, 600);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    control.close();
    assert!(
        control.fixture_client().is_err(),
        "cancel/drop reopened a reset transaction"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ccs_control",
    smoke_dynamic_ccs_busy_lastclose_job_refuses_reset_without_reclaim
);

fn smoke_dynamic_ccs_stop_loss_and_failed_new_probe_keep_gate_closed() -> TestResult {
    for fail_stop in [true, false] {
        let platform = GtPlatform::Battlemage;
        let (w, arena, mut gt, ack) = discover(platform, 10);
        prime_mode(&mut gt, &w, 1);
        let epoch = gt.user_epoch().unwrap();
        let control = Control::fixture();
        control.publish(epoch, (10, 1)).unwrap();
        control.fixture_request(2).unwrap();
        assert_eq!(control.begin(&mut gt, epoch, 1000, |_| {}), Ok(Some(2)));
        if fail_stop {
            let retained = arena.live_allocations();
            assert!(matches!(gt.poll(10_000_000), Poll::Ready(Err(_))));
            assert_eq!(arena.live_allocations(), retained);
            control.close();
            assert!(control.fixture_client().is_err());
            assert_eq!(control.publish(epoch, (10, 1)), Err(FsError::NoDevice));
            assert!(control.fixture_client().is_err());
            // Timeout is no reset-completion evidence: the first owned
            // GuC reset remains asserted, so another reset must refuse.
            assert_eq!(
                gt.begin_stop(10_000_001),
                Err(GtError::Boot(crate::intel_gpu_guc_boot::BootError::Busy))
            );
            assert_eq!(arena.live_allocations(), retained);
            assert!(control.fixture_client().is_err());
            reset_done(&w); // the original request finally self-clears
            assert_eq!(arena.live_allocations(), retained);
            gt.begin_stop(10_000_002).unwrap();
            // A newly completed GuC reset still cannot release engine DMA:
            // finish_stop requires the separate full-engine reset proof.
            finish_stop(&mut gt, &w, &arena, ack, 10_000_002);
        } else {
            finish_stop(&mut gt, &w, &arena, ack, 1000);
        }
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
        gt = rebuild(&w, &arena, platform, ack, 2);
        let probe = gt.submit_ppgtt_probe_on(500, Engine::Ccs3).unwrap();
        let weak = probe.result.weak_objects();
        drop(probe.result);
        let mut registered = BTreeMap::new();
        for now in 501..530 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, false);
        }
        let image = w.0.borrow().memory[&registered[&u32::from(probe.context_id)]].clone();
        image.borrow_mut()[0x800 / 4] = u32::MAX;
        assert!(matches!(gt.poll(531), Poll::Ready(Err(_))));
        control.close();
        assert!(control.fixture_client().is_err());
        assert!(probe.completion.result().is_none());
        assert!(weak.iter().all(|object| object.upgrade().is_some()));
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
        assert!(weak.iter().all(|object| object.upgrade().is_none()));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ccs_control",
    smoke_dynamic_ccs_stop_loss_and_failed_new_probe_keep_gate_closed
);
