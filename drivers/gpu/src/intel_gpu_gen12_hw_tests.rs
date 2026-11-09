// Gen12 platform selection reaches the actual GuC/ADS/LRC/PPGTT owners.
// Independent literals: Linux b90c984d xe_lrc.c gen12_{rcs,xcs}_offsets,
// xe_ring_ops.c, xe_guc_ads.c Wa1607983814 and xe_wa_oob.rules.
use super::*;
use crate::intel_gpu_engine::{Engine, EngineSet};
use crate::intel_gpu_exec::PpgttProbeResult;
use crate::intel_gpu_fence::{CompletionFence, JobError};
use crate::intel_gpu_gt::Gen12Platform;
use crate::intel_gpu_user::{UserBatch, UserContext};

fn finish(gt: &mut GuCGt<Window, Arena>, w: &Window, fence: &CompletionFence, now: u64) {
    let mut registered = BTreeMap::new();
    finish_registered(gt, w, fence, now, &mut registered);
}
fn finish_registered(
    gt: &mut GuCGt<Window, Arena>,
    w: &Window,
    fence: &CompletionFence,
    now: u64,
    registered: &mut BTreeMap<u32, u32>,
) {
    for tick in now..now + 200 {
        assert_eq!(gt.poll(tick), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(w, registered, true);
        if fence.result().is_some() {
            break;
        }
    }
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(registered.is_empty());
}
fn prime(gt: &mut GuCGt<Window, Arena>, w: &Window) {
    hardware_discovery(gt, w, 0x130044);
    hardware_scheduling(gt, w);
    let fence = gt.begin_context_defaults(10_000_000).unwrap();
    finish(gt, w, &fence, 10_000_001);
}

fn smoke_gen12_guc_lrc_ads_restore_and_private_execution() -> TestResult {
    for family in [
        Gen12Platform::AlderLakeP,
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeS,
        Gen12Platform::AlderLakeN,
    ] {
        let platform = GtPlatform::Gen12(family);
        let (w, arena, mut gt) = hardware_model(platform, 0x130044);
        w.0.borrow_mut().regs.insert(0x913c, 4); // sparse DSS2, source steering0/2
        prime(&mut gt, &w);
        assert_eq!(gt.hwconfig().is_some(), family == Gen12Platform::AlderLakeP);
        assert_eq!(
            gt.engines(),
            Some(EngineSet::of(&[Engine::Rcs0, Engine::Bcs0]))
        );
        assert_eq!(
            w.0.borrow().gmd_reads,
            0,
            "pre-GMD platform accessed GMD_ID"
        );
        {
            let d = w.0.borrow();
            let ads = d.memory[&0x20001000].borrow();
            let rcsc = if matches!(family, Gen12Platform::TigerLake | Gen12Platform::AlderLakeP) {
                57
            } else {
                56
            };
            assert_eq!((ads[0], ads[1]), (0x20003000, rcsc));
            assert_eq!(ads[0x300 / 4 + 1], 16);
            let mut sr = alloc::vec![
                (0x2080, 0),
                (0x20a8, 0),
                (0x20c4, 1),
                (0x229c, 0),
                (0x14800, 1),
                (0xb004, 0),
                (0x20a0, 0),
                (0xe4f4, 0x00200003),
                (0xe48c, 0x00200003),
                (0x20ec, 1),
                (0xe18c, 0x00200003),
                (0x20e0, 1),
            ];
            if rcsc == 57 {
                sr.push((0x2050, 1));
            }
            for index in 0..32 {
                sr.push((0xb020 + index as u32 * 4, 0));
            }
            for register in (0x24d0..=0x24fc).step_by(4) {
                sr.push((register, 0));
            }
            sr.sort_unstable_by_key(|entry| entry.0);
            let saves = ads_registers(&w, Engine::Rcs0);
            assert_eq!(saves.len(), sr.len());
            for (reg, flags) in sr {
                assert_eq!(saves[&reg].1, flags);
                assert_eq!(
                    saves[&reg].0,
                    if reg == 0x2080 { d.regs[&0x2080] } else { 0 }
                );
            }
            for engine in [Engine::Rcs0, Engine::Bcs0] {
                let class = engine.guc_class() as usize;
                let golden = d.memory[&ads[(0x1014 + class * 4) / 4]].borrow();
                // Rcs0's first group carries OACTXCONTROL (issue #1821):
                // 14 registers on Gen12.
                assert_eq!(
                    golden[1025],
                    if engine == Engine::Rcs0 {
                        0x1108101b
                    } else {
                        0x11081019
                    }
                );
                assert_eq!(golden[1024 + 0x21], 0x11081011);
                assert_eq!(golden[1024 + 0x61], 0x01000000);
                assert_eq!((golden[1024 + 0x13], golden[1024 + 0x15]), (0, 0));
                if engine == Engine::Rcs0 {
                    assert_eq!(
                        &golden[1024 + 0x34..1024 + 0x3b],
                        &[0x11081005, 0x21b0, 0, 0x25a8, 0, 0x25ac, 0]
                    );
                    assert_eq!(golden[1024 + 0x51], 0x11081065);
                    assert_eq!(golden[1024 + 0xb9], 0x05000001);
                }
            }
        }
        for (index, engine) in [Engine::Rcs0, Engine::Bcs0].into_iter().enumerate() {
            let context = UserContext::for_engine(engine);
            let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
            let weak = result.weak_objects();
            let (_, fence) = gt
                .submit_user_batch(
                    20_000_000 + index as u64 * 250_000,
                    context.clone(),
                    UserBatch(batch),
                )
                .unwrap();
            assert!(result.verify().is_err());
            finish(&mut gt, &w, &fence, 20_000_001 + index as u64 * 250_000);
            assert_eq!(result.verify(), Ok(()));
            assert!(!context.busy());
            drop(result);
            assert!(weak.iter().all(|object| object.upgrade().is_none()));
        }
        assert_eq!(w.0.borrow().gmd_reads, 0);
        assert!(w.0.borrow().gen12_restores.len() >= 6);
        hardware_stop(&mut gt, &w, 0x130044);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen12",
    smoke_gen12_guc_lrc_ads_restore_and_private_execution
);

fn running(gt: &mut GuCGt<Window, Arena>, w: &Window, start: u64) -> (u32, BTreeMap<u32, u32>) {
    let mut registered = BTreeMap::new();
    for now in start..start + 24 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(w, &mut registered, false);
    }
    assert_eq!(registered.len(), 1);
    (*registered.values().next().unwrap(), registered)
}
fn execute_user(w: &Window, base: u32) {
    execute_gen12_restore(w, base, true);
    if w.0.borrow().memory[&base].borrow()[1026] != 0x2244 {
        execute_copy(w, base);
        return;
    }
    let d = w.0.borrow();
    let image = d.memory[&base].clone();
    let ring_base = image.borrow()[1024 + 9];
    let ring = d.memory[&ring_base].borrow().clone();
    let stamp = ring[7];
    execute_ppgtt_probe(&d.regs, &image.borrow(), &ring, stamp, base, false);
    let tail = image.borrow()[1024 + 7];
    image.borrow_mut()[0x800 / 4] = stamp;
    image.borrow_mut()[1024 + 5] = tail;
}

fn smoke_gen12_persistent_state_repatches_owned_restore_ring_on_every_submit() -> TestResult {
    let platform = GtPlatform::Gen12(Gen12Platform::AlderLakeP);
    let (w, arena, mut gt) = hardware_model(platform, 0x130044);
    prime(&mut gt, &w);
    for engine in [Engine::Rcs0, Engine::Bcs0] {
        let context = UserContext::for_engine(engine);
        let mut prior_ring = 0;
        for pass in 0..2 {
            let start = 20_000_000 + engine.index() as u64 * 1_000_000 + pass * 250_000;
            let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
            let (_, fence) = gt
                .submit_user_batch(start, context.clone(), UserBatch(batch))
                .unwrap();
            let (base, mut registered) = running(&mut gt, &w, start + 1);
            let image = w.0.borrow().memory[&base].clone();
            let ring = image.borrow()[1024 + 9];
            assert_ne!(ring, prior_ring);
            assert_eq!(image.borrow()[1024 + 0x13], (ring + 4096) | 1);
            if engine == Engine::Rcs0 {
                assert_eq!(image.borrow()[1024 + 0x15], (ring + 4224) | 1);
            }
            if pass != 0 {
                assert_eq!(
                    image.borrow()[0x1800 / 4],
                    0x7a12cafe,
                    "opaque state was not restored"
                );
            }
            image.borrow_mut()[0x1800 / 4] = 0x7a12cafe;
            execute_user(&w, base);
            // The GPU store alone is not terminal ownership. Saved head,
            // disable/deregister and final TLB ACK remain necessary.
            assert!(fence.result().is_none());
            finish_registered(&mut gt, &w, &fence, start + 30, &mut registered);
            assert_eq!(result.verify(), Ok(()));
            prior_ring = ring;
        }
    }
    assert_eq!(w.0.borrow().gmd_reads, 0);
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen12",
    smoke_gen12_persistent_state_repatches_owned_restore_ring_on_every_submit
);

fn smoke_gen12_cache_refusal_and_cancel_reset_retain_every_dma_page() -> TestResult {
    use core::{
        future::Future,
        task::{Context, Waker},
    };
    let platform = GtPlatform::Gen12(Gen12Platform::AlderLakeP);
    for engine in [Engine::Rcs0, Engine::Bcs0] {
        let (w, arena, mut gt) = hardware_model(platform, 0x130044);
        prime(&mut gt, &w);
        let context = UserContext::for_engine(engine);
        let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
        let count = arena.live_allocations();
        w.0.borrow_mut().fail_sync = true;
        assert!(matches!(
            gt.submit_user_batch(25_000_000, context.clone(), UserBatch(batch)),
            Err(GtError::Scheduling(
                crate::intel_gpu_guc_sched::SchedulingError::Cache
            ))
        ));
        assert_eq!(arena.live_allocations(), count);
        assert!(!context.busy());
        assert!(result.verify().is_err());
        drop(result);
        w.0.borrow_mut().fail_sync = false;
        let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
        let weak = result.weak_objects();
        let (_, fence) = gt
            .submit_user_batch(30_000_000, context.clone(), UserBatch(batch))
            .unwrap();
        let (base, _) = running(&mut gt, &w, 30_000_001);
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
        assert!(weak.iter().all(|object| object.upgrade().is_some()));
        assert!(gt.poll_with_access(30_000_030, || false).is_ready());
        assert_eq!(gt.state(), GtState::Lost);
        assert!(fence.result().is_none());
        assert_eq!(arena.live_allocations(), live);
        assert!(w.0.borrow().memory.contains_key(&base));
        gt.begin_stop(10_000_000_000).unwrap();
        let now = gen12_until(&mut gt, &w, 10_000_010_000, GtState::ResettingEngines);
        assert!(fence.result().is_none());
        assert_eq!(arena.live_allocations(), live);
        gen12_progress(&w);
        assert!(gt.poll(now + 10_000).is_pending());
        assert_eq!(gt.state(), GtState::ReleasingGen12Media);
        assert!(fence.result().is_none());
        gen12_until(&mut gt, &w, now + 20_000, GtState::Stopped);
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
    "drivers/gpu/intel_gpu_gen12",
    smoke_gen12_cache_refusal_and_cancel_reset_retain_every_dma_page
);

mod media {
    include!("intel_gpu_gen12_media_hw_tests.rs");
}
