// Actual Gen12 fuse -> retained wake/reset -> GuC/ADS/LRC/private-VM owners.
// Literal wire/register oracles: Linux b90c984d xe_hw_engine.c, xe_force_wake.c,
// xe_lrc.c, xe_ring_ops.c, xe_wa.c. Opaque capture slots belong only to the model.
use super::*;

const SPARSE: u32 = 0x000f00ff & !0x00040042; // VCS1/6, VECS2
fn model_media(family: Gen12Platform, fuse: u32) -> (Window, Arena, GuCGt<Window, Arena>) {
    let (w, arena, gt) = hardware_model(GtPlatform::Gen12(family), 0x130044);
    w.0.borrow_mut().regs.insert(0x9140, fuse);
    (w, arena, gt)
}
fn prime_media(gt: &mut GuCGt<Window, Arena>, w: &Window) {
    hardware_discovery(gt, w, 0x130044);
    hardware_scheduling(gt, w);
    let fence = gt.begin_context_defaults(10_000_000).unwrap();
    let mut registered = BTreeMap::new();
    for now in 10_000_001..10_001_025 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(w, &mut registered, true);
        if fence.result().is_some() {
            break;
        }
    }
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(registered.is_empty());
    assert!(gt.user_epoch().is_some());
}
fn held(w: &Window) {
    let d = w.0.borrow();
    for (request, ack) in [(0xa544, 0xd54), (0xa558, 0xd68), (0xa568, 0xd78)] {
        assert_eq!(d.regs[&request] & 1, 1);
        assert_eq!(d.regs[&ack] & 1, 1);
    }
}
fn smoke_gen12_media_fused_inventory_ads_default_capture_and_wake_lifetime() -> TestResult {
    for family in [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeS,
        Gen12Platform::AlderLakeN,
    ] {
        let (w, arena, mut gt) = model_media(family, SPARSE);
        prime_media(&mut gt, &w);
        held(&w);
        let engines = gt.engines().unwrap();
        assert_eq!(
            engines.iter().collect::<Vec<_>>(),
            [
                Engine::Rcs0,
                Engine::Bcs0,
                Engine::Vcs1,
                Engine::Vcs6,
                Engine::Vecs2
            ]
        );
        let d = w.0.borrow();
        let ads = d.memory[&0x20001000].borrow();
        assert_eq!((ads[0x11a4 / 4], ads[0x11a8 / 4]), (0x20006000, 0)); // KLV page +0x5000 only for media policy
        for (engine, class, physical) in [
            (Engine::Vcs1, 1, 1),
            (Engine::Vcs6, 1, 6),
            (Engine::Vecs2, 2, 2),
        ] {
            let header = (class * 256 + physical * 8) as usize / 4;
            assert_eq!(ads[header + 1], 16);
            assert!(ads[header] >= 0x20003000 && ads[header] + 16 * 16 <= 0x20006000);
            let saves = ads_registers(&w, engine);
            assert_eq!(saves[&(engine.base() + 0xc4)].1, 1);
            assert!(
                !saves.contains_key(&(engine.base() + 0x3f10)),
                "GT WA must not enter an engine-save list"
            );
            assert_eq!(
                d.regs[&(u64::from(engine.base()) + 0x4d0)],
                0x10000000 | (engine.base() + 0x3a8)
            );
            assert_eq!(d.regs[&(u64::from(engine.base()) + 0xc4)], 0x306);
            let golden = d.memory[&ads[(0x1014 + class * 4) as usize / 4]].borrow();
            assert_eq!(golden.len(), 2048);
            assert_eq!(golden[1025], 0x11081019);
            assert_eq!(&golden[0x1800 / 4..0x1810 / 4], &[2, 0x2000, 0x40, 0x200]);
        }
        assert!(d.writes.contains(&(0x1f3f10, 0x400000)));
        assert!(!d.writes.iter().any(|(reg, _)| *reg == 0x1c7f10)); // odd VCS1
        for request in [0xa544, 0xa558, 0xa568] {
            assert!(!d.writes.contains(&(request, 0x00010000)));
        }
        assert_eq!(d.gmd_reads, 0);
        drop(ads);
        drop(d);
        hardware_stop(&mut gt, &w, 0x130044);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
        for request in [0xa544, 0xa558, 0xa568] {
            assert_eq!(w.0.borrow().regs[&request] & 1, 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen12",
    smoke_gen12_media_fused_inventory_ads_default_capture_and_wake_lifetime
);

fn smoke_gen12_media_maximum_ads_saves_keep_klv_and_private_ranges_disjoint() -> TestResult {
    let (w, arena, mut gt) = model_media(Gen12Platform::TigerLake, 0);
    prime_media(&mut gt, &w);
    assert_eq!(gt.engines().unwrap().iter().count(), 14);
    let d = w.0.borrow();
    let ads = d.memory[&0x20001000].borrow();
    let mut end = 0x20003000;
    for engine in gt.engines().unwrap().iter() {
        let at = (engine.guc_class() * 256 + engine.physical_instance() * 8) as usize / 4;
        assert_eq!(ads[at], end);
        end += ads[at + 1] * 16;
    }
    assert!(end > 0x20004000, "exercise the former one-page save limit");
    assert!(end <= 0x20006000);
    assert_eq!(ads[0x11a4 / 4], 0x20006000);
    assert!(ads.len() * 4 >= 0x6000);
    assert!(ads[0x4000 / 4..0x5000 / 4].iter().all(|v| *v == 0));
    // Maximum physical masks; logical mapping is independently dense.
    assert_eq!(ads[(0x123c + 512 + 4) / 4], 255);
    assert_eq!(ads[(0x123c + 512 + 8) / 4], 15);
    assert_eq!(ads[(0x123c + 32) / 4], 0x03020100);
    assert_eq!(ads[(0x123c + 36) / 4], 0x07060504);
    drop(ads);
    drop(d);
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen12",
    smoke_gen12_media_maximum_ads_saves_keep_klv_and_private_ranges_disjoint
);

fn smoke_gen12_nonrender_golden_restore_and_media_virtual_engine_receipt() -> TestResult {
    let (w, arena, mut gt) = model_media(Gen12Platform::AlderLakeP, SPARSE);
    prime_media(&mut gt, &w);
    for placements in [
        EngineSet::of(&[Engine::Bcs0]),
        EngineSet::of(&[Engine::Vcs1, Engine::Vcs6]),
        EngineSet::of(&[Engine::Vecs2]),
    ] {
        let context = UserContext::for_placements(placements).unwrap();
        let mut prior = 0;
        for pass in 0..2 {
            let now = 20_000_000 + placements.bits() as u64 * 1000 + pass * 100;
            let (batch, result) =
                PpgttProbeResult::prepare(GtPlatform::Gen12(Gen12Platform::AlderLakeP)).unwrap();
            let (_, fence) = gt
                .submit_user_batch(now, context.clone(), UserBatch(batch))
                .unwrap();
            let (base, mut registered) = running(&mut gt, &w, now + 1);
            let image = w.0.borrow().memory[&base].clone();
            let ring = image.borrow()[1024 + 9];
            assert_ne!(ring, prior);
            assert_eq!(
                &image.borrow()[0x1800 / 4..0x1810 / 4],
                if pass == 0 {
                    &[2, 0x2000, 0x40, 0x200]
                } else {
                    &[0x7a12cafe, 0x2000, 0x40, 0x200]
                }
            );
            image.borrow_mut()[0x1800 / 4] = 0x7a12cafe;
            execute_user(&w, base);
            if placements.iter().count() > 1 {
                assert_eq!(image.borrow()[0x818 / 4], 0x61);
                assert_eq!(w.0.borrow().virtual_restores.last(), Some(&(base, 0x61)));
            }
            assert!(fence.result().is_none());
            finish_registered(&mut gt, &w, &fence, now + 30, &mut registered);
            assert_eq!(result.verify(), Ok(()));
            held(&w);
            prior = ring;
        }
    }
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen12",
    smoke_gen12_nonrender_golden_restore_and_media_virtual_engine_receipt
);

fn smoke_gen12_media_cancel_cache_loss_reset_and_delayed_wake_ack_retain_pages() -> TestResult {
    use core::{
        future::Future,
        task::{Context, Waker},
    };
    for engine in [Engine::Vcs6, Engine::Vecs2] {
        let (w, arena, mut gt) = model_media(Gen12Platform::AlderLakeP, SPARSE);
        prime_media(&mut gt, &w);
        let platform = GtPlatform::Gen12(Gen12Platform::AlderLakeP);
        let context = UserContext::for_engine(engine);
        let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
        let before = arena.live_allocations();
        w.0.borrow_mut().fail_sync = true;
        assert!(gt
            .submit_user_batch(30_000_000, context.clone(), UserBatch(batch))
            .is_err());
        assert_eq!(arena.live_allocations(), before);
        assert!(!context.busy());
        drop(result);
        w.0.borrow_mut().fail_sync = false;
        let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
        let weak = result.weak_objects();
        let (_, fence) = gt
            .submit_user_batch(31_000_000, context.clone(), UserBatch(batch))
            .unwrap();
        let (base, _) = running(&mut gt, &w, 31_000_001);
        {
            let mut wait = core::pin::pin!(fence.wait());
            assert!(wait
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        context.request_ban();
        drop(result);
        let live = arena.live_allocations();
        assert!(weak.iter().all(|o| o.upgrade().is_some()));
        assert!(gt.poll_with_access(31_000_030, || false).is_ready());
        assert_eq!(gt.state(), GtState::Lost);
        assert!(fence.result().is_none());
        gt.begin_stop(10_000_000_000).unwrap();
        let now = gen12_until(&mut gt, &w, 10_000_010_000, GtState::ResettingEngines);
        assert_eq!(arena.live_allocations(), live);
        assert!(w.0.borrow().memory.contains_key(&base));
        assert!(fence.result().is_none());
        gen12_progress(&w);
        assert!(gt.poll(now + 10_000).is_pending());
        assert_eq!(gt.state(), GtState::ReleasingGen12Media);
        // Request clear is not an ACK receipt. No modeled ACK is advanced here.
        assert!(gt.poll(now + 20_000).is_pending());
        assert!(fence.result().is_none());
        assert_eq!(arena.live_allocations(), live);
        assert!(weak.iter().all(|o| o.upgrade().is_some()));
        gen12_until(&mut gt, &w, now + 30_000, GtState::Stopped);
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
    smoke_gen12_media_cancel_cache_loss_reset_and_delayed_wake_ack_retain_pages
);

fn smoke_gen12_media_wake_loss_refuses_new_work_before_allocation() -> TestResult {
    let (w, arena, mut gt) = model_media(Gen12Platform::TigerLake, SPARSE);
    prime_media(&mut gt, &w);
    w.0.borrow_mut().regs.insert(0xd78, 0);
    let live = arena.live_allocations();
    assert!(gt.submit_ppgtt_probe_on(20_000_000, Engine::Vecs2).is_err());
    assert_eq!(gt.state(), GtState::Lost);
    assert_eq!(arena.live_allocations(), live);
    assert_eq!(w.0.borrow().regs[&0xa568] & 1, 1); // uncertain ownership retained
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen12",
    smoke_gen12_media_wake_loss_refuses_new_work_before_allocation
);
