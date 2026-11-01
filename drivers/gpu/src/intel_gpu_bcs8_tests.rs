// BMG COPY1 conversations through production GuC/ADS/LRC/PPGTT ownership.
// Literal identities follow MIT Linux b90c984d xe_hw_engine/xe_guc_ads,
// xe_lrc xe2_bcs_offsets, xe_ring_ops and xe_irq_regs.
use super::*;
use crate::intel_gpu_engine::Engine;
use crate::intel_gpu_exec::PpgttProbeResult;
use crate::intel_gpu_user::{UserBatch, UserContext};

fn prime_copy8(gt: &mut GuCGt<Window, Arena>, w: &Window) {
    hardware_discovery(gt, w, 0xdfc);
    hardware_scheduling(gt, w);
    let completion = gt.begin_context_defaults(26).unwrap();
    let mut registered = BTreeMap::new();
    for now in 27..180 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(w, &mut registered, true);
        if completion.result().is_some() {
            break;
        }
    }
    assert_eq!(completion.result(), Some(Ok(())));
    assert!(registered.is_empty());
}

fn smoke_bcs8_discovery_ads_private_probe_and_retirement() -> TestResult {
    for release in [1, 2] {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        w.0.borrow_mut()
            .regs
            .insert(0xd8c, 20 << 22 | release << 14);
        prime_copy8(&mut gt, &w);
        assert!(gt.engines().unwrap().contains(Engine::Bcs8));
        {
            let d = w.0.borrow();
            let ads = d.memory[&0x20001000].borrow();
            // Logical [0,1] -> hardware [0,8]; other mappings remain invalid.
            assert_eq!(ads[(0x123c + 96) / 4], 0x20200800);
            assert_eq!(ads[(0x123c + 524) / 4], 0x101);
            assert_eq!(ads[0x340 / 4 + 1], 3);
            assert_ne!(ads[0x300 / 4], ads[0x340 / 4]);
            let saves = (ads[0x340 / 4] - 0x20001000) as usize / 4;
            assert_eq!(
                [ads[saves], ads[saves + 4], ads[saves + 8]],
                [0x3ee29c, 0x3ee080, 0x3ee0a8]
            );
            assert_eq!(ads[saves + 2], 1);
            assert_eq!(ads[saves + 5], d.regs[&0x3ee080]);
            assert_eq!(d.regs[&0x3ee0c4], 0x3f7e0306);
            assert_eq!(d.regs[&0x3ee0d4] & 0xc080, 0xc080);
            assert_eq!(d.regs[&0x3ee050] & 0x1000, 0x1000);
            for slot in 0..12 {
                assert_eq!(d.regs[&(0x3ee4d0 + slot * 4)], 0x3ee094);
            }
        }
        let baseline = arena.live_allocations();
        let probe = gt.submit_ppgtt_probe_on(200, Engine::Bcs8).unwrap();
        let weak = probe.result.weak_objects();
        assert!(probe.result.verify().is_err());
        let mut registered = BTreeMap::new();
        let mut saw_copy8 = false;
        for now in 201..260 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, true);
            for image in registered.values() {
                let d = w.0.borrow();
                let image = d.memory[image].borrow();
                assert_eq!(image[1026], 0x3ee244);
                assert_eq!(
                    &image[1024 + 0x41..1024 + 0x46],
                    &[
                        0x11081003,
                        0x3ee200,
                        0,
                        0x3ee204,
                        0xffff8787 | 3 << 9 | 3 << 1
                    ]
                );
                saw_copy8 = true;
            }
            if probe.completion.result().is_some() {
                break;
            }
        }
        assert!(saw_copy8);
        assert_eq!(probe.completion.result(), Some(Ok(())));
        assert_eq!(probe.result.verify(), Ok(()));
        assert_eq!(arena.live_allocations(), baseline);
        drop(probe);
        assert!(weak.iter().all(|object| object.upgrade().is_none()));
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_bcs8",
    smoke_bcs8_discovery_ads_private_probe_and_retirement
);

fn smoke_bcs8_timeout_isolates_copy1_from_copy0() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    prime_copy8(&mut gt, &w);
    let baseline = arena.live_allocations();
    let guilty = UserContext::for_engine(Engine::Bcs8);
    let innocent = UserContext::for_engine(Engine::Bcs0);
    let (batch, result) = PpgttProbeResult::prepare(GtPlatform::Battlemage).unwrap();
    let (_, bad) = gt
        .submit_user_batch(200, guilty.clone(), UserBatch(batch))
        .unwrap();
    let (batch, good_result) = PpgttProbeResult::prepare(GtPlatform::Battlemage).unwrap();
    let (_, good) = gt
        .submit_user_batch(200, innocent.clone(), UserBatch(batch))
        .unwrap();
    let mut registered = BTreeMap::new();
    for now in 201..230 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
    }
    let mut copy0 = None;
    let mut copy8 = None;
    for &base in registered.values() {
        match w.0.borrow().memory[&base].borrow()[1026] {
            0x22244 => copy0 = Some(base),
            0x3ee244 => copy8 = Some(base),
            _ => panic!("unexpected execution engine"),
        }
    }
    let base = copy8.unwrap();
    {
        let mut d = w.0.borrow_mut();
        let image = d.memory[&base].clone();
        let ring = d.memory[&image.borrow()[1033]].clone();
        assert_eq!(&ring.borrow()[..4], &[0x12480002, 0x3a8, base + 0x810, 0]);
        let stamp = ring.borrow()[9]; // copy MI_FLUSH_DW start, after timestamp prefix
        image.borrow_mut()[0x808 / 4] = stamp;
        image.borrow_mut()[0x810 / 4] = 0;
        image.borrow_mut()[1024 + 0x23] = 1;
        d.regs.insert(0x3ee240, base);
        d.regs.insert(0x3ee3a8, 30_000_000); // 10 GPU seconds at RPM_CONFIG0=0
    }
    execute_copy(&w, copy0.unwrap());
    let count = arena.live_allocations();
    assert_eq!(
        gt.poll(5_000_000_300),
        Poll::Ready(Ok(GtState::SchedulingReady))
    );
    assert!(bad.result().is_none());
    assert!(arena.live_allocations() >= count);
    for now in 5_000_000_301..5_000_000_380 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
        if bad.result().is_some() && good.result().is_some() {
            break;
        }
    }
    assert_eq!(
        bad.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Hang))
    );
    assert_eq!(good.result(), Some(Ok(())));
    assert!(guilty.banned());
    assert!(!innocent.banned());
    assert_eq!(good_result.verify(), Ok(()));
    assert!(gt.user_epoch().is_some());
    drop((result, good_result));
    assert_eq!(arena.live_allocations(), baseline);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_bcs8",
    smoke_bcs8_timeout_isolates_copy1_from_copy0
);

fn smoke_bcs8_lost_policy_keeps_cancelled_probe_until_full_reset() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    prime_copy8(&mut gt, &w);
    let probe = gt.submit_ppgtt_probe_on(200, Engine::Bcs8).unwrap();
    let weak = probe.result.weak_objects();
    let fence = probe.completion.clone();
    drop(probe);
    let mut registered = BTreeMap::new();
    for now in 201..225 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
    }
    w.0.borrow_mut().regs.insert(0x3ee4fc, 0x3ee030);
    assert!(gt.submit_kernel_probe(226).is_err());
    assert_eq!(gt.state(), GtState::Lost);
    let count = arena.live_allocations();
    assert!(fence.result().is_none());
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    assert_eq!(arena.live_allocations(), count);
    hardware_stop(&mut gt, &w, 0xdfc);
    assert_eq!(
        fence.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    assert!(weak.iter().all(|object| object.upgrade().is_none()));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_bcs8",
    smoke_bcs8_lost_policy_keeps_cancelled_probe_until_full_reset
);

fn smoke_guc_log_live_owner_snapshot_and_reload_incarnation() -> TestResult {
    use crate::intel_gpu_guc_log::{CaptureBuffer, HEADER_BYTES, LOG_BYTES};
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    prime_copy8(&mut gt, &w);
    let epoch = gt.user_epoch().unwrap();
    let logs = {
        let d = w.0.borrow();
        d.memory[&(d.regs[&0xc184] & !0xfff)].clone()
    };
    // Firmware DMA publishes opaque words. Copying must preserve the exact
    // bounded allocation even when the optional state headers are malformed.
    for (index, word) in logs.borrow_mut().iter_mut().enumerate() {
        *word = 0x5a000000 ^ index as u32;
    }
    let snapshot = gt
        .snapshot_guc_log(
            CaptureBuffer::reserve_for_test(54).unwrap(),
            epoch,
            123456,
            [0xa5; 32],
            || true,
        )
        .unwrap();
    let mut header = [0; HEADER_BYTES];
    assert_eq!(snapshot.read_for_test(0, &mut header), HEADER_BYTES);
    assert_eq!(
        u64::from_le_bytes(header[32..40].try_into().unwrap()),
        epoch
    );
    let incarnation = u64::from_le_bytes(header[40..48].try_into().unwrap());
    assert_ne!(incarnation, 0);
    assert_eq!(&header[56..68], &[70, 0, 0, 0, 54, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&header[80..112], &[0xa5; 32]);
    let mut payload = alloc::vec![0; LOG_BYTES];
    assert_eq!(
        snapshot.read_for_test(HEADER_BYTES as u64, &mut payload),
        LOG_BYTES
    );
    for (index, bytes) in payload.chunks_exact(4).enumerate() {
        assert_eq!(
            u32::from_le_bytes(bytes.try_into().unwrap()),
            0x5a000000 ^ index as u32
        );
    }
    let refused = CaptureBuffer::reserve_for_test(54).unwrap();
    {
        // A wake/MMIO read would reborrow this register bank and panic.
        let _exclusive = w.0.borrow_mut();
        assert!(gt
            .snapshot_guc_log(refused, epoch, 0, [0; 32], || false)
            .is_err());
        assert!(gt
            .snapshot_guc_log(
                CaptureBuffer::reserve_for_test(54).unwrap(),
                epoch + 1,
                0,
                [0; 32],
                || true
            )
            .is_err());
    }
    drop(snapshot);
    hardware_stop(&mut gt, &w, 0xdfc);
    assert!(gt
        .snapshot_guc_log(
            CaptureBuffer::reserve_for_test(54).unwrap(),
            epoch,
            0,
            [0; 32],
            || true
        )
        .is_err());
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    // A fresh firmware upload must not relabel previous-incarnation bytes.
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    prime_copy8(&mut gt, &w);
    let snapshot = gt
        .snapshot_guc_log(
            CaptureBuffer::reserve_for_test(54).unwrap(),
            gt.user_epoch().unwrap(),
            0,
            [0xa5; 32],
            || true,
        )
        .unwrap();
    assert_eq!(snapshot.read_for_test(0, &mut header), HEADER_BYTES);
    assert_ne!(
        u64::from_le_bytes(header[40..48].try_into().unwrap()),
        incarnation
    );
    assert_eq!(
        snapshot.read_for_test(HEADER_BYTES as u64, &mut payload),
        LOG_BYTES
    );
    assert!(payload.iter().all(|byte| *byte == 0));
    drop(snapshot);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_log_live_owner_snapshot_and_reload_incarnation
);
