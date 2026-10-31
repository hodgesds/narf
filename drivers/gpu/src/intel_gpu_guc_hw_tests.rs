// Native Rust hardware conversations over the real GuCGt/CT/scheduler owners.
// Reference vectors: MIT Linux xe_guc_submit.c, xe_lrc.c, xe_guc_ads.c,
// xe_mocs.c at b90c984d615e8ce2af96f5b1411a962d83fed2ad.

mod userspace {
    include!("intel_gpu_user_tests.rs");
}

fn smoke_hardware_irq_notification_requires_actual_retirement() -> TestResult {
    for (platform, ack) in [
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
        ),
        (GtPlatform::Alchemist, 0x130044),
        (GtPlatform::Battlemage, 0xdfc),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        hardware_discovery(&mut gt, &w, ack);
        hardware_scheduling(&mut gt, &w);
        let irq = crate::intel_gpu_gt_irq::Controller::new(w.clone()).unwrap();
        irq.activate().unwrap();
        assert_eq!(irq.service(0), Ok(false));
        let baseline = arena.live_allocations();
        let (_, fence) = gt.submit_kernel_probe(100).unwrap();
        // A valid GuC notification without a CT reply/breadcrumb must not
        // complete this real scheduler fence or reclaim its DMA backing.
        let live = arena.live_allocations();
        let notify = |now| {
            {
                let mut d = w.0.borrow_mut();
                d.regs.insert(0x190008, 0x80000001);
                d.regs.insert(0x190010, 0x80000001);
                d.regs.insert(0x190018, 0x02000001);
            }
            assert_eq!(
                irq.hard_irq(),
                narf_interrupts::dispatch::IrqStatus::Handled
            );
            assert_eq!(irq.service(now), Ok(true));
            assert_eq!(irq.service(now + 1), Ok(true));
            assert_eq!(irq.service(now + 2), Ok(false));
        };
        notify(101);
        assert!(fence.result().is_none());
        assert_eq!(arena.live_allocations(), live);
        let mut registered = BTreeMap::new();
        for now in 110..160 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, true);
            notify(now * 10);
            if fence.result().is_some() {
                break;
            }
        }
        assert_eq!(fence.result(), Some(Ok(())));
        assert_eq!(arena.live_allocations(), baseline);
        assert!(irq.quiesce());
        assert_eq!(w.read32(0x190008) & 0x80000000, 0);
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_irq",
    smoke_hardware_irq_notification_requires_actual_retirement
);

fn smoke_hardware_id_recycling_beyond_16bit_request_limit() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    hardware_discovery(&mut gt, &w, 0xdfc);
    hardware_scheduling(&mut gt, &w);
    let baseline = arena.live_allocations();
    let mut registered = BTreeMap::new();
    for request in 0..65540u64 {
        let start = 100 + request * 50;
        let (id, fence) = gt.submit_kernel_probe(start).unwrap();
        assert_eq!(u64::from(id), request % 64 + 1);
        for now in start + 1..start + 40 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, true);
            if fence.result().is_some() {
                break;
            }
        }
        assert_eq!(fence.result(), Some(Ok(())));
        assert!(registered.is_empty());
        assert_eq!(arena.live_allocations(), baseline);
    }
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_id_recycling_beyond_16bit_request_limit
);

fn smoke_hardware_recycled_id_rejects_stale_cookie_and_breadcrumb() -> TestResult {
    for stale_cookie in [true, false] {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        hardware_discovery(&mut gt, &w, 0xdfc);
        hardware_scheduling(&mut gt, &w);
        let mut registered = BTreeMap::new();
        for request in 0..64u64 {
            let start = 100 + request * 50;
            let (_, fence) = gt.submit_kernel_probe(start).unwrap();
            for now in start + 1..start + 40 {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                service_contexts(&w, &mut registered, true);
                if fence.result().is_some() {
                    break;
                }
            }
            assert_eq!(fence.result(), Some(Ok(())));
        }
        let (id, fence) = gt.submit_kernel_probe(4000).unwrap();
        assert_eq!(id, 1);
        if stale_cookie {
            assert_eq!(gt.poll(4001), Poll::Ready(Ok(GtState::SchedulingReady)));
            event(&ct_memory(&w), 0x7001, &[1]);
        } else {
            for now in 4001..4010 {
                assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
                service_contexts(&w, &mut registered, false);
                if let Some(base) = registered.get(&1) {
                    w.0.borrow().memory[base].borrow_mut()[0x800 / 4] = 1;
                    break;
                }
            }
        }
        let baseline = arena.live_allocations();
        let mut lost = false;
        for now in 4010..4020 {
            if matches!(gt.poll(now), Poll::Ready(Err(_))) {
                lost = true;
                break;
            }
            service_contexts(&w, &mut registered, false);
        }
        assert!(lost);
        assert!(fence.result().is_none());
        assert_eq!(arena.live_allocations(), baseline);
        hardware_stop(&mut gt, &w, 0xdfc);
        assert_eq!(
            fence.result(),
            Some(Err(crate::intel_gpu_fence::JobError::Reset))
        );
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_recycled_id_rejects_stale_cookie_and_breadcrumb
);

fn hardware_model(platform: GtPlatform, ack: u64) -> (Window, Arena, GuCGt<Window, Arena>) {
    hardware_model_with_interface(platform, ack, 1)
}
fn hardware_model_with_interface(
    platform: GtPlatform,
    ack: u64,
    version: u8,
) -> (Window, Arena, GuCGt<Window, Arena>) {
    let (window, arena) = model();
    {
        let mut d = window.0.borrow_mut();
        d.regs.insert(ack, 0);
        d.regs.insert(0xa188, 2);
        d.regs.insert(0xa278, 2);
        d.regs.insert(0xd84, 0);
        d.regs.insert(0xfd0, 1);
        d.regs.insert(0x913c, 5);
        d.regs.insert(0x9144, 6);
        d.regs.insert(0x9134, 5);
        d.regs.insert(0x9114, 0x10);
        d.regs.insert(0x9118, 1);
        d.regs.insert(
            0xd8c,
            if platform == GtPlatform::Battlemage {
                (20 << 22) | (1 << 14)
            } else {
                (12 << 22) | (70 << 14)
            },
        );
    }
    let mut boot = stage(window.clone(), arena.clone(), platform);
    boot.submission_version = (version, 0, 0);
    if platform == GtPlatform::Battlemage {
        boot.config.uncached_mocs = Some(3);
    }
    let gt = GuCGt::from_staged_hardware(boot).unwrap();
    (window, arena, gt)
}

fn hardware_discovery(gt: &mut GuCGt<Window, Arena>, w: &Window, ack: u64) {
    gt.begin(0).unwrap();
    assert!(gt.poll(1).is_pending());
    w.0.borrow_mut().regs.insert(ack, 1);
    assert!(gt.poll(2).is_pending());
    assert_eq!(gt.state(), GtState::PreparingHardware);
    assert_eq!(w.0.borrow().regs.get(&0xa278), Some(&3));
    w.0.borrow_mut().regs.insert(0xd84, 1);
    assert!(gt.poll(3).is_pending());
    reset_done(w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(4).is_pending());
    assert_eq!(w.0.borrow().regs.get(&0x941c), Some(&1));
    reset_done(w);
    assert!(gt.poll(5).is_pending());
    reset_done(w);
    assert!(gt.poll(6).is_pending());
    w.0.borrow_mut().regs.insert(0xc314, 0x10);
    assert!(gt.poll(7).is_pending());
    w.0.borrow_mut().regs.insert(0xc000, 0x8000f000);
    assert_eq!(gt.poll(8), Poll::Ready(Ok(GtState::Ready)));
    gt.begin_hwconfig(9).unwrap();
    w.0.borrow_mut().regs.insert(0x190240, 0xf000000c);
    assert!(gt.poll(10).is_pending());
    hwconfig_device_write(w, &[7, 1, 8]);
    w.0.borrow_mut().regs.insert(0x190240, 0xf0000000);
    assert_eq!(gt.poll(11), Poll::Ready(Ok(GtState::Ready)));
}

fn smoke_hardware_topology_publication_and_card_queries() -> TestResult {
    use crate::drm_devfs_bridge::IntelGpuCard;
    use crate::intel_gpu_render::{tests::check_card_topology, DeviceInfo};
    for (platform, device, ack) in [
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0x7d55,
            0xdfc,
        ),
        (GtPlatform::Alchemist, 0x56a0, 0x130044),
        (GtPlatform::Battlemage, 0xe20b, 0xdfc),
    ] {
        let card = Arc::new(IntelGpuCard::new(
            alloc::string::String::new(),
            0x8086,
            device,
            0,
            0,
        ));
        let other = Arc::new(IntelGpuCard::new(
            alloc::string::String::new(),
            0x8086,
            device,
            0,
            0,
        ));
        let index = crate::drm_registry::register_drm_card(card.clone());
        let other_index = crate::drm_registry::register_drm_card(other.clone());
        let before = DeviceInfo::for_card(index).unwrap();
        check_card_topology(index, None, None).unwrap();
        let (w, arena, mut gt) = hardware_model(platform, ack);
        assert!(card.publish_gt_topology(&mut gt).is_err());
        hardware_discovery(&mut gt, &w, ack);
        card.publish_gt_topology(&mut gt).unwrap();
        card.publish_gt_topology(&mut gt).unwrap(); // identical resume observation
        assert!(before.topology.is_none());
        assert!(DeviceInfo::for_card(other_index)
            .unwrap()
            .topology
            .is_none());
        let snapshot = DeviceInfo::for_card(index).unwrap().topology.unwrap();
        assert_eq!((snapshot.geometry_dss(), snapshot.compute_dss()), (5, 6));

        let (w2, arena2, mut gt2) = hardware_model(platform, ack);
        w2.0.borrow_mut()
            .regs
            .extend([(0x913c, 2), (0x9144, 0), (0x9134, 3)]);
        hardware_discovery(&mut gt2, &w2, ack);
        assert_eq!(
            card.publish_gt_topology(&mut gt2),
            Err(GtError::Topology(
                crate::intel_gpu_topology::TopologyError::Unstable
            ))
        );
        other.publish_gt_topology(&mut gt2).unwrap();
        let wrong = IntelGpuCard::new(alloc::string::String::new(), 0x8086, 0xffff, 0, 0);
        assert!(wrong.publish_gt_topology(&mut gt).is_err());
        hardware_stop(&mut gt, &w, ack);
        hardware_stop(&mut gt2, &w2, ack);
        drop(gt);
        drop(gt2);
        assert_eq!(
            (arena.live_allocations(), arena2.live_allocations()),
            (0, 0)
        );
        assert_eq!((snapshot.geometry_dss(), snapshot.compute_dss()), (5, 6));

        let mut expected = if platform == GtPlatform::Battlemage {
            let mut bytes = alloc::vec![0;53];
            bytes[..16].copy_from_slice(&[0, 0, 1, 0, 32, 0, 8, 0, 1, 0, 4, 0, 5, 0, 1, 0]);
            bytes[16..24].copy_from_slice(&[1, 7, 0, 0, 0, 5, 5, 5]);
            bytes
        } else {
            let mut bytes = alloc::vec![0;85];
            bytes[..16].copy_from_slice(&[0, 0, 1, 0, 32, 0, 16, 0, 1, 0, 4, 0, 5, 0, 2, 0]);
            bytes[16..27].copy_from_slice(&[1, 7, 0, 0, 0, 0x33, 0, 0x33, 0, 0x33, 0]);
            bytes
        };
        let mut geometry = expected.clone();
        geometry[17] = 5;
        if platform == GtPlatform::Battlemage {
            geometry[22] = 0;
        } else {
            geometry[23..25].fill(0);
        }
        check_card_topology(index, Some(&expected), Some(&geometry)).unwrap();
        expected[17] = 2;
        expected[21..].fill(0);
        if platform == GtPlatform::Battlemage {
            expected[22] = 3;
        } else {
            expected[23] = 0xf;
        }
        check_card_topology(other_index, Some(&expected), Some(&expected)).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_topology_publication_and_card_queries
);

fn smoke_hardware_fuse_admission_before_dma_and_scheduling() -> TestResult {
    use crate::intel_gpu_topology::TopologyError;
    for fuses in [[0, 0, 1], [1, 0, 0], [1, 1, u32::MAX]] {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
        w.0.borrow_mut()
            .regs
            .extend([(0x913c, fuses[0]), (0x9144, fuses[1]), (0x9134, fuses[2])]);
        gt.begin(0).unwrap();
        w.0.borrow_mut().regs.insert(0x130044, 1);
        assert!(gt.poll(1).is_pending());
        w.0.borrow_mut().regs.insert(0xd84, 1);
        assert!(gt.poll(2).is_pending());
        reset_done(&w);
        assert!(gt.poll(3).is_pending());
        reset_done(&w);
        assert!(matches!(gt.poll(4), Poll::Ready(Err(GtError::Topology(_)))));
        assert_eq!(gt.state(), GtState::Lost);
        assert!(gt.topology().is_none());
        assert!(!w
            .0
            .borrow()
            .writes
            .iter()
            .any(|&(r, v)| (r == 0xc314 && v == 0x00110011) || r == 0x2080));
        hardware_stop(&mut gt, &w, 0x130044);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
    w.0.borrow_mut().regs.insert(0x913c, 0); // valid compute-only GT
    hardware_discovery(&mut gt, &w, 0x130044);
    assert!(!gt.topology().unwrap().has_render());
    let count = arena.live_allocations();
    assert_eq!(
        gt.begin_scheduling(12),
        Err(GtError::Topology(TopologyError::NoRender))
    );
    assert_eq!(arena.live_allocations(), count);
    assert!(!w.0.borrow().writes.iter().any(|(r, _)| *r == 0x2080));
    let card = crate::drm_devfs_bridge::IntelGpuCard::new(
        alloc::string::String::new(),
        0x8086,
        0x56a0,
        0,
        0,
    );
    w.0.borrow_mut().regs.insert(0x130044, 0);
    assert_eq!(card.publish_gt_topology(&mut gt), Err(GtError::WakeLost));
    assert_eq!(gt.state(), GtState::Lost);
    gt.begin_stop(20).unwrap();
    w.0.borrow_mut().regs.insert(0x130044, 1);
    assert!(gt.poll(21).is_pending());
    reset_done(&w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(22).is_pending());
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(23).is_pending());
    w.0.borrow_mut().regs.insert(0x130044, 0);
    assert_eq!(gt.poll(24), Poll::Ready(Ok(GtState::Stopped)));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_fuse_admission_before_dma_and_scheduling
);

fn hardware_scheduling_reload(gt: &mut GuCGt<Window, Arena>, w: &Window) {
    let before = {
        let d = w.0.borrow();
        let ads = d.memory[&0x20001000].borrow();
        (
            d.regs[&0xc188],
            ads[0x11a4 / 4..0x11b0 / 4].to_vec(),
            ads[0x3000 / 4..0x4000 / 4].to_vec(),
        )
    };
    gt.begin_scheduling(12).unwrap();
    assert_eq!(gt.state(), GtState::PreparingScheduling);
    assert!(gt.poll(12).is_pending());
    assert_eq!(gt.state(), GtState::StartingScheduling);
    assert!(gt.poll(13).is_pending());
    reset_done(w);
    assert!(gt.poll(14).is_pending()); // stop, ADS rewrite, reset for reload
    reset_done(w);
    assert!(gt.poll(15).is_pending());
    w.0.borrow_mut().regs.insert(0xc314, 0x10);
    assert!(gt.poll(16).is_pending());
    w.0.borrow_mut().regs.insert(0xc000, 0x8000f000);
    assert_eq!(gt.poll(17), Poll::Ready(Ok(GtState::Ready)));
    {
        let d = w.0.borrow();
        let ads = d.memory[&0x20001000].borrow();
        assert_eq!(d.regs[&0xc188], before.0);
        assert_eq!(&ads[0x11a4 / 4..0x11b0 / 4], before.1.as_slice());
        assert_eq!(&ads[0x3000 / 4..0x4000 / 4], before.2.as_slice());
        assert_eq!(ads[0x2000 / 4], 0x229c); // KLVs did not overlap register saves
    }
}

fn hardware_scheduling(gt: &mut GuCGt<Window, Arena>, w: &Window) {
    hardware_scheduling_reload(gt, w);
    gt.begin_ct(18).unwrap();
    for now in 19..25 {
        w.0.borrow_mut().regs.insert(0x190240, 0xf0000001);
        assert!(gt.poll(now).is_pending());
    }
    w.0.borrow_mut().regs.insert(0x190240, 0xf0000000);
    assert_eq!(gt.poll(25), Poll::Ready(Ok(GtState::SchedulingReady)));
}

fn smoke_hardware_nonpriv_profiles_before_ring_and_reload() -> TestResult {
    let mtl = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    for (platform, ack, main, release) in [
        (GtPlatform::Alchemist, 0x130044, 12, 55),
        (mtl, 0xdfc, 12, 70),
        (mtl, 0xdfc, 12, 71),
        (mtl, 0xdfc, 12, 74),
        (GtPlatform::Battlemage, 0xdfc, 20, 1),
        (GtPlatform::Battlemage, 0xdfc, 20, 2),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        w.0.borrow_mut()
            .regs
            .insert(0xd8c, (main << 22) | (release << 14) | 4);
        hardware_discovery(&mut gt, &w, ack);
        {
            let mut device = w.0.borrow_mut();
            for slot in 0..12 {
                device.regs.insert(0x24d0 + slot * 4, 0x2030);
            }
            device.writes.clear();
        }
        hardware_scheduling(&mut gt, &w);
        {
            let d = w.0.borrow();
            let policy: Vec<_> = d
                .writes
                .iter()
                .copied()
                .filter(|(reg, _)| (0x24d0..=0x24fc).contains(reg))
                .collect();
            assert_eq!(policy.len(), 15);
            for (slot, entry) in policy[..12].iter().enumerate() {
                assert_eq!(*entry, (0x24d0 + slot as u64 * 4, 0x2094));
            }
            assert_eq!(
                &policy[12..],
                &[(0x24d0, 0x1000dafc), (0x24d4, 0x1000db01), (0x24d8, 0xdb1c)]
            );
            let last = d.writes.iter().rposition(|p| p.0 == 0x24d8).unwrap();
            let enable = d.writes.iter().position(|p| p.0 == 0x2080).unwrap();
            assert!(last < enable, "RCS published before access policy");
            for (slot, expected) in [
                0x1000dafc, 0x1000db01, 0xdb1c, 0x2094, 0x2094, 0x2094, 0x2094, 0x2094, 0x2094,
                0x2094, 0x2094, 0x2094,
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(d.regs[&(0x24d0 + slot as u64 * 4)], expected);
            }
        }
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_nonpriv_profiles_before_ring_and_reload
);

fn smoke_hardware_nonpriv_failure_blocks_reload_and_ct() -> TestResult {
    use crate::intel_gpu_gt_registers::RegisterError;
    for failure in 0..3 {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        hardware_discovery(&mut gt, &w, 0xdfc);
        if failure <= 1 {
            gt.begin_scheduling(12).unwrap();
            if failure == 0 {
                w.0.borrow_mut().regs.insert(0x24fc, u32::MAX);
                assert_eq!(
                    gt.poll(12),
                    Poll::Ready(Err(GtError::Registers(RegisterError::Unavailable)))
                );
                assert!(!w.0.borrow().writes.iter().any(|p| p.0 == 0x2080));
            } else {
                assert!(gt.poll(12).is_pending());
                w.0.borrow_mut().regs.insert(0x24fc, 0x2030);
                assert!(gt.poll(13).is_pending());
                reset_done(&w);
                assert!(gt.poll(14).is_pending());
                reset_done(&w);
                assert!(gt.poll(15).is_pending());
                w.0.borrow_mut().regs.insert(0xc314, 0x10);
                assert!(gt.poll(16).is_pending());
                w.0.borrow_mut().regs.insert(0xc000, 0x8000f000);
                assert_eq!(
                    gt.poll(17),
                    Poll::Ready(Err(GtError::Registers(RegisterError::Verify(0x24fc))))
                );
                assert_eq!(gt.begin_ct(18), Err(GtError::State));
            }
        } else {
            hardware_scheduling_reload(&mut gt, &w);
            gt.begin_ct(18).unwrap();
            for now in 19..25 {
                w.0.borrow_mut().regs.insert(0x190240, 0xf0000001);
                assert!(gt.poll(now).is_pending());
            }
            w.0.borrow_mut().regs.insert(0x24d0, 0xdafc); // RO became RW
            w.0.borrow_mut().regs.insert(0x190240, 0xf0000000);
            assert_eq!(
                gt.poll(25),
                Poll::Ready(Err(GtError::Registers(RegisterError::Verify(0x24d0))))
            );
        }
        assert_eq!(gt.state(), GtState::Lost);
        assert!(arena.live_allocations() > 0);
        let count = arena.live_allocations();
        assert!(gt.submit_kernel_probe(30).is_err());
        assert_eq!(arena.live_allocations(), count);
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_nonpriv_failure_blocks_reload_and_ct
);

fn smoke_hardware_nonpriv_drift_retains_jobs_until_full_reset() -> TestResult {
    use crate::intel_gpu_gt_registers::RegisterError;
    for api in 0..3 {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        hardware_discovery(&mut gt, &w, 0xdfc);
        hardware_scheduling(&mut gt, &w);
        let probe = gt.submit_ppgtt_probe(26).unwrap();
        let weak = probe.result.weak_objects();
        let completion = probe.completion.clone();
        drop(probe);
        let mut registered = BTreeMap::new();
        for now in 27..33 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, false);
        }
        w.0.borrow_mut().regs.insert(0x24fc, 0x20002030);
        let count = arena.live_allocations();
        let result = match api {
            0 => gt.submit_kernel_probe(33).map(|_| ()),
            1 => gt.begin_context_defaults(33).map(|_| ()),
            _ => gt.submit_ppgtt_probe(33).map(|_| ()),
        };
        assert_eq!(
            result,
            Err(GtError::Registers(RegisterError::Verify(0x24fc)))
        );
        assert_eq!(gt.state(), GtState::Lost);
        assert_eq!(arena.live_allocations(), count);
        assert_eq!(completion.result(), None);
        assert_eq!(weak[1].upgrade().unwrap().busy(), 0x10001);
        assert_eq!(
            w.0.borrow().regs[&0x24fc],
            0x20002030,
            "live policy was silently repaired"
        );
        gt.begin_stop(10_000_000_000).unwrap();
        reset_done(&w);
        w.0.borrow_mut().regs.insert(0xc314, 0);
        assert!(gt.poll(10_000_000_001).is_pending());
        assert_eq!(gt.state(), GtState::ResettingEngines);
        assert_eq!(completion.result(), None);
        assert_eq!(weak[1].upgrade().unwrap().busy(), 0x10001);
        assert!(gt.poll(10_000_000_002).is_pending());
        reset_done(&w);
        assert!(gt.poll(10_000_000_003).is_pending());
        assert_eq!(
            completion.result(),
            Some(Err(crate::intel_gpu_fence::JobError::Reset))
        );
        assert!(weak.iter().all(|object| object.upgrade().is_none()));
        w.0.borrow_mut().regs.insert(0xd84, 0);
        assert!(gt.poll(10_000_000_004).is_pending());
        w.0.borrow_mut().regs.insert(0xdfc, 0);
        assert_eq!(gt.poll(10_000_000_005), Poll::Ready(Ok(GtState::Stopped)));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_nonpriv_drift_retains_jobs_until_full_reset
);

fn smoke_hardware_register_initialization_gates_scheduling() -> TestResult {
    use crate::intel_gpu_gt_registers::RegisterError;
    for failure in 0..4 {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        hardware_discovery(&mut gt, &w, 0xdfc);
        let before = arena.live_allocations();
        if failure == 0 {
            w.0.borrow_mut().regs.insert(0xd8c, (20 << 22) | (4 << 14));
            assert!(matches!(
                gt.begin_scheduling(12),
                Err(GtError::Registers(_))
            ));
            assert_eq!(gt.state(), GtState::Ready);
            assert_eq!(arena.live_allocations(), before);
        } else {
            gt.begin_scheduling(12).unwrap();
            let count = arena.live_allocations();
            assert_eq!(count, before + 4); // HWSP + golden per RCS0/BCS0
            if failure == 1 {
                w.0.borrow_mut().regs.insert(0xe7cc, u32::MAX);
                assert_eq!(
                    gt.poll(13),
                    Poll::Ready(Err(GtError::Registers(RegisterError::Unavailable)))
                );
                assert_eq!(gt.state(), GtState::Lost);
                assert_eq!(w.0.borrow().regs[&0xfd0], 1);
                assert!(!w.0.borrow().writes.iter().any(|p| p.0 == 0xb0c8));
            } else {
                w.0.borrow_mut().regs.insert(0xfd0, 0);
                for now in 13..17 {
                    assert!(gt.poll(now).is_pending());
                }
                assert_eq!(gt.state(), GtState::PreparingScheduling);
                if failure == 2 {
                    assert_eq!(
                        gt.poll(50_000_012),
                        Poll::Ready(Err(GtError::Registers(RegisterError::Timeout)))
                    );
                    assert_eq!(gt.state(), GtState::Lost);
                }
            }
            assert_eq!(arena.live_allocations(), count);
        }
        assert!(!w.0.borrow().writes.iter().any(|p| p.0 == 0x2080));
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_register_initialization_gates_scheduling
);

fn smoke_hardware_workaround_ip_change_blocks_reload() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    hardware_discovery(&mut gt, &w, 0xdfc);
    w.0.borrow_mut().regs.insert(0xd8c, (20 << 22) | (2 << 14));
    gt.begin_scheduling(12).unwrap();
    assert!(gt.poll(12).is_pending());
    assert!(gt.poll(13).is_pending());
    reset_done(&w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    let count = arena.live_allocations();
    assert_eq!(
        gt.poll(14),
        Poll::Ready(Err(GtError::Boot(BootError::Device)))
    );
    assert_eq!(gt.state(), GtState::Lost);
    assert_eq!(arena.live_allocations(), count);
    assert_eq!(
        w.0.borrow()
            .writes
            .iter()
            .filter(|p| **p == (0xc314, 0x00110011))
            .count(),
        1
    );
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_workaround_ip_change_blocks_reload
);

fn hardware_stop(gt: &mut GuCGt<Window, Arena>, w: &Window, ack: u64) {
    gt.begin_stop(10_000_000_000).unwrap();
    assert!(gt.poll(10_000_000_001).is_pending());
    reset_done(w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(10_000_000_002).is_pending());
    if gt.state() == GtState::ResettingEngines {
        assert_eq!(w.0.borrow().regs.get(&0x941c), Some(&1));
        assert!(gt.poll(10_000_000_003).is_pending());
        reset_done(w);
        assert!(gt.poll(10_000_000_004).is_pending());
    }
    assert_eq!(gt.state(), GtState::ReleasingRender);
    assert_eq!(w.0.borrow().regs.get(&0xa278), Some(&2));
    assert!(gt.poll(10_000_000_005).is_pending());
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(10_000_000_006).is_pending());
    w.0.borrow_mut().regs.insert(ack, 0);
    assert_eq!(gt.poll(10_000_000_007), Poll::Ready(Ok(GtState::Stopped)));
}

fn ct_memory(w: &Window) -> Words {
    w.0.borrow()
        .memory
        .values()
        .find(|b| b.borrow().len() == 6144)
        .expect("CT")
        .clone()
}
fn event(memory: &Words, action: u32, payload: &[u32]) {
    let mut words = memory.borrow_mut();
    let tail = words[513];
    words[2048 + (tail & 4095) as usize] = 1 + payload.len() as u32;
    words[2048 + ((tail + 1) & 4095) as usize] = 0x90000000 | action;
    for (i, word) in payload.iter().enumerate() {
        words[2048 + ((tail + 2 + i as u32) & 4095) as usize] = *word;
    }
    words[513] = (tail + 2 + payload.len() as u32) & 4095;
}
fn service_contexts(w: &Window, registered: &mut BTreeMap<u32, u32>, execute: bool) -> Vec<u16> {
    let memory = ct_memory(w);
    let mut requests = Vec::new();
    {
        let mut words = memory.borrow_mut();
        let mut head = words[0];
        let tail = words[1];
        while head != tail {
            let count = words[1024 + head as usize] & 0xff;
            let mut request = Vec::new();
            for i in 1..=count {
                request.push(words[1024 + ((head + i) & 1023) as usize]);
            }
            assert_eq!(request[0] >> 28, 2, "fast request");
            requests.push(request);
            head = (head + count + 1) & 1023;
        }
        words[0] = head;
    }
    let mut actions = Vec::new();
    for request in requests {
        let action = request[0] as u16;
        actions.push(action);
        match action {
            0x7000 => {
                assert_eq!(request.len(), 3);
                assert_eq!(request[2], 0x80000003);
                event(&memory, 0x7001, &[request[1]]);
            }
            0x4502 => {
                // GUC_RENDER_CLASS for RCS0, GUC_BLITTER_CLASS for BCS0.
                assert!(matches!(request[3], 0 | 3));
                assert_eq!(&request[1..10], &[1, request[2], request[3], 1, 0, 0, 0, 0, 0]);
                assert_eq!(request.len(), 12);
                assert!(matches!(request[10] & 0xfff, 0x19 | 0x119));
                let image = w.0.borrow().memory[&(request[10] & !0xfff)].clone();
                assert_eq!(image.borrow()[1024 + 0x33] != 0, request[10] & 0x100 != 0);
                let base = if request[3] == 3 { 0x22244 } else { 0x2244 };
                assert_eq!(image.borrow()[1024 + 2], base);
                assert_eq!(request[11], 0);
                assert!(registered
                    .insert(request[2], request[10] & !0xfff)
                    .is_none());
            }
            0x100b => {
                assert!(matches!(request[3], 2 | 3));
                assert!((1..=100_000).contains(&request[5]));
                assert_eq!(
                    [request[2], request[4], request[6], request[7]],
                    [0x20030001, 0x20010001, 0x20020001, 500000]
                );
            }
            0x1001 => {
                let id = request[1];
                let base = registered[&id];
                let copy = w.0.borrow().memory[&base].borrow()[1024 + 2] == 0x22244;
                if request[2] == 1 && execute && copy {
                    execute_copy(w, base);
                } else if request[2] == 1 && execute {
                    let mut d = w.0.borrow_mut();
                    assert!(d.synced.contains(&base));
                    let image = d.memory[&base].clone();
                    let ring_base = image.borrow()[1024 + 9];
                    {
                        let data = image.borrow();
                        assert_eq!(
                            &data[1024..1031],
                            &[0, 0x1108101d, 0x2244, data[1027], 0x2034, 0, 0x2030]
                        );
                        assert!(matches!(data[1027], 0x00090009 | 0x00090008));
                        assert_eq!(data[1032], 0x2038);
                        assert_eq!(data[1024 + 33], 0x11081011);
                        assert_eq!(data[1024 + 65], 0x11080001);
                        assert_eq!(data[1024 + 68], 0x05000001);
                        // xe_lrc.c::reset_stop_ring, graphics IP >= 12.50.
                        assert_eq!(data[1024 + 0x71], 0x01000000);
                        assert_eq!(data[1024 + 0x72], 0);
                    }
                    assert!(d.synced.contains(&ring_base));
                    let ring_backing = d.memory[&ring_base].clone();
                    let ring = ring_backing.borrow();
                    let tail = image.borrow()[1024 + 7];
                    let stamp = if tail == 32 {
                        ring[5]
                    } else {
                        ring[..tail as usize / 4]
                            .windows(6)
                            .find(|v| v[..4] == [0x7a000004, 0x01104080, base + 0x800, 0])
                            .expect("GGTT post-sync immediate")[4]
                    };
                    assert_ne!(stamp, 0);
                    if image.borrow()[1024 + 0x33] != 0 {
                        execute_ppgtt_probe(&d.regs, &image.borrow(), &ring, stamp, base);
                    } else if tail != 32 {
                        let (svg, used) =
                            crate::intel_gpu_context::tests::execute(&ring[1..], &mut d.regs);
                        assert_eq!(svg.len(), 50);
                        assert_eq!(
                            svg[49],
                            if d.regs[&0xd8c] >> 22 == 20 {
                                0x78000002
                            } else {
                                0x79000002
                            }
                        );
                        assert_eq!(ring[0], 0x04000001);
                        assert_eq!(ring[used + 1] & 0xfffffdff, 0x7a000004);
                        // Opaque device-saved state, outside the hand-written
                        // register restore groups. The driver must copy it.
                        image.borrow_mut()[0x2000 / 4] = 0xc01dcafe;
                        image.borrow_mut()[0x2004 / 4] = d.regs[&0x7044];
                        // Fixture-only opaque save area, not a claimed hardware
                        // SVG layout. Capture proves every header reaches clones.
                        image.borrow_mut()[0x2100 / 4..0x2100 / 4 + 50].copy_from_slice(&svg);
                    } else {
                        assert_eq!(
                            &ring[..8],
                            &[
                                0x04000001,
                                0,
                                0x10400002,
                                base + 0x800,
                                0,
                                stamp,
                                0x01000000,
                                0
                            ]
                        );
                        assert_eq!(tail, 32);
                    }
                    image.borrow_mut()[0x800 / 4] = stamp;
                    image.borrow_mut()[1024 + 5] = tail;
                }
                event(&memory, 0x1002, &[id, request[2]]);
            }
            0x4503 => {
                assert!(registered.remove(&request[1]).is_some());
                event(&memory, 0x4600, &[request[1]]);
            }
            _ => panic!("unexpected action {action:x}"),
        }
    }
    actions
}

// Independent BCS0 model from Linux xe_lrc.c {gen12_xcs,xe2_bcs}_offsets,
// xe_ring_ops.c::__emit_job_gen12_simple and xe_gt.c::emit_wa_job literals.
fn execute_copy(w: &Window, base: u32) {
    let mut d = w.0.borrow_mut();
    assert!(d.synced.contains(&base));
    let xe2 = d.regs[&0xd8c] >> 22 == 20;
    let image = d.memory[&base].clone();
    let (tail, ring_base) = {
        let data = image.borrow();
        assert_eq!(data.len(), 2048);
        assert_eq!(
            &data[1024..1031],
            &[
                0,
                if xe2 { 0x1108101d } else { 0x11081019 },
                0x22244,
                data[1027],
                0x22034,
                0,
                0x22030
            ]
        );
        assert!(matches!(data[1027], 0x00090009 | 0x00090008));
        assert_eq!((data[1032], data[1024 + 0x21]), (0x22038, 0x11081011));
        assert_eq!(data[1024 + 0x71], 0x01000000);
        (data[1024 + 7], data[1024 + 9])
    };
    assert!(d.synced.contains(&ring_base));
    let ring = d.memory[&ring_base].borrow().clone();
    let words = &ring[..tail as usize / 4];
    assert_eq!(words.len() % 2, 0);
    let stamp = if tail == 32 {
        assert_eq!(&words[..3], &[0x04000001, 0, 0x10400002]);
        assert_eq!(words[3], base + 0x800);
        words[5]
    } else {
        // MI_FLUSH_DW | OP_STOREDW | IMM_DW to the GGTT breadcrumb, then
        // MI_USER_INTERRUPT, ARB_ON, ARB_CHECK.
        let at = words
            .windows(7)
            .rposition(|v| {
                v[..3] == [0x13004002, (base + 0x800) | 4, 0]
                    && v[4..] == [0x01000000, 0x04000001, 0x02800000]
            })
            .expect("copy breadcrumb");
        words[at + 3]
    };
    assert_ne!(stamp, 0);
    let root = (u64::from(image.borrow()[1024 + 0x31]) << 32) | u64::from(image.borrow()[1024 + 0x33]);
    if root != 0 {
        // A PPGTT copy job begins with a TLB-invalidating start stamp.
        assert_eq!(
            &words[..7],
            &[0x04000001, 0x02800101, 0x13044002, (base + 0x808) | 4, 0, stamp, 0x02800100]
        );
        execute_copy_ppgtt(root, &words[7..]);
    } else if tail != 32 {
        // emit_wa_job's non-MCR RMW of BLIT_CCTL to the uncached MOCS.
        // RING_CMD_CCTL is pinned per platform by the RCS tests; BCS0's ring
        // and BLIT_CCTL must use the same uncached MOCS index.
        let cctl = d.regs[&0x20c4];
        assert_eq!(d.regs[&0x220c4], cctl);
        let uc = (cctl >> 1) & 0x3f;
        assert_eq!(cctl, 0x3f7e0000 | uc << 8 | uc << 1);
        assert_eq!(
            &words[1..28],
            &[
                0x15080001, 0x22204, 0x600, 0x11080003, 0x608, 0x7e7e, 0x610,
                uc << 9 | uc << 1, 0x0d000007, 0x08008000, 0x48008401, 0x10200000,
                0x18000031, 0x08008000, 0x08008402, 0x10300000, 0x18000031, 0x15040001,
                0x600, 0x22204, 0x11080005, 0x600, 0, 0x608, 0, 0x610, 0,
            ]
        );
        let old = d.regs.get(&0x22204).copied().unwrap_or(0xffff_ffff);
        let value = (old & !0x7e7e) | uc << 9 | uc << 1;
        d.regs.insert(0x22204, value);
        if xe2 {
            // xe2_bcs_offsets saves BLIT_CCTL in the context image.
            image.borrow_mut()[1024 + 0x45] = value;
        }
    }
    image.borrow_mut()[0x800 / 4] = stamp;
    image.borrow_mut()[1024 + 5] = tail;
}

// Walk the production page tables for a copy job: an optional PPGTT batch
// whose literal MI_STORE_DATA_IMM is executed, then an optional user fence.
fn execute_copy_ppgtt(root: u64, words: &[u32]) {
    let walk = |va: u64| -> u64 {
        let mut page = root & 0x0000_3fff_ffff_f000;
        for shift in [39, 30, 21, 12] {
            let address = narf_memory::PhysAddr::new(page).kernel_ptr::<u64>();
            // SAFETY: the fixture's production tables stay resident until
            // terminal completion; this walk never dereferences user memory.
            let entry =
                unsafe { core::ptr::read_volatile(address.add(((va >> shift) & 511) as usize)) };
            assert_eq!(entry & 1, 1);
            page = entry & 0x0000_3fff_ffff_f000;
        }
        page | (va & 4095)
    };
    let mut i = 0;
    if words[0] == 0x18800101 {
        let batch = u64::from(words[1]) | u64::from(words[2]) << 32;
        let code = narf_memory::PhysAddr::new(walk(batch)).kernel_ptr::<u32>();
        // SAFETY: translated page is an owned resident batch BO.
        let cmd = unsafe { core::slice::from_raw_parts(code, 6) };
        assert_eq!((cmd[0], cmd[4], cmd[5]), (0x10000002, 0x05000000, 0));
        let dst = u64::from(cmd[1]) | u64::from(cmd[2]) << 32;
        let target = narf_memory::PhysAddr::new(walk(dst)).kernel_mut_ptr::<u32>();
        // SAFETY: the walk resolved one owned writable result dword.
        unsafe { core::ptr::write_volatile(target, cmd[3]) };
        i = 3;
    }
    assert_eq!(words[i], 0x04000000);
    i += 1;
    if words[i] == 0x13000002 {
        assert_eq!(&words[i + 1..i + 5], &[0, 0, 0, 0x10200003]);
        let address = u64::from(words[i + 5]) | u64::from(words[i + 6]) << 32;
        let value = u64::from(words[i + 7]) | u64::from(words[i + 8]) << 32;
        let target = narf_memory::PhysAddr::new(walk(address)).kernel_mut_ptr::<u64>();
        // SAFETY: an owned, aligned, writable user-fence qword.
        unsafe { core::ptr::write_volatile(target, value) };
        i += 9;
    }
    assert_eq!(words[i], 0x13004002);
}

// Independent fixed-command device model. It follows the actual production
// table pages, verifies their PAT/permissions, fetches the private batch via
// four hardware-style reads and writes the translated destination page.
fn execute_ppgtt_probe(regs: &BTreeMap<u64, u32>, image: &[u32], ring: &[u32], id: u32, base: u32) {
    let pat = if regs.get(&0x480c) == Some(&2) {
        3
    } else if regs.get(&0x4808) == Some(&0xf) {
        2
    } else {
        0
    };
    let table_pat = if pat == 3 {
        assert_eq!(regs.get(&0x4808), Some(&0xc));
        2
    } else {
        pat
    };
    let root = (u64::from(image[1024 + 0x31]) << 32) | u64::from(image[1024 + 0x33]);
    assert_eq!(root & 0xfff, 3 | table_pat << 3);
    let walk = |va: u64, writable: bool| -> u64 {
        let mut page = root & 0x0000_3fff_ffff_f000;
        for shift in [39, 30, 21, 12] {
            let address = narf_memory::PhysAddr::new(page).kernel_ptr::<u64>();
            // SAFETY: this fixture built and retains all four physical tables;
            // the independent walk never uses an external/raw user pointer.
            let entry =
                unsafe { core::ptr::read_volatile(address.add(((va >> shift) & 511) as usize)) };
            assert_eq!(entry & 1, 1);
            assert_eq!(
                entry & 0x18,
                (if shift == 12 { pat } else { table_pat }) << 3
            );
            assert_eq!(entry & 2 != 0, shift != 12 || writable);
            page = entry & 0x0000_3fff_ffff_f000;
        }
        page | (va & 4095)
    };
    let mut expected = alloc::vec![0x04000001, 0x02800101, 0x7a000404, 0x20344c1c, 0xd0, 0, 0, 0,];
    if pat == 3 {
        expected.extend_from_slice(&[0x11020001, 0x4208, 1, 0]);
    }
    let has_batch = ring.windows(2).any(|w| w == [0x02800100, 0x18800101]);
    if has_batch {
        expected.extend_from_slice(&[0x02800100, 0x18800101, 0, 0x1234, 0x04000000]);
    }
    if pat == 0 || pat == 3 {
        expected.extend_from_slice(&[0x7a000004, 1, 0xd0, 0, 0, 0]);
    }
    expected.extend_from_slice(&[0x7a000204, 0x101010a1, 0, 0, 0, 0]);
    let user_store = ring.windows(6).find(|w| w[0] == 0x10200003);
    if let Some(store) = user_store {
        assert_eq!(store[5], 0); // qword alignment NOP
        expected.extend_from_slice(store);
    }
    expected.extend_from_slice(&[
        0x7a000004,
        0x01104080,
        base + 0x800,
        0,
        id,
        0,
        0x01000000,
        0x04000001,
        0x02800000,
    ]);
    if expected.len() % 2 != 0 {
        expected.push(0);
    }
    assert_eq!(image[1031] as usize, expected.len() * 4);
    assert_eq!(&ring[..expected.len()], expected.as_slice());
    // Literal batch from xe_mi_commands.h, independent of the producer's codec.
    if has_batch {
        let code = narf_memory::PhysAddr::new(walk(0x1234_0000_0000, false)).kernel_ptr::<u32>();
        for (i, word) in [0x10000002, 0x80, 0x2345, 0x4e415246, 0x05000000, 0]
            .into_iter()
            .enumerate()
        {
            // SAFETY: translated page is owned by the resident fixture.
            assert_eq!(unsafe { core::ptr::read_volatile(code.add(i)) }, word);
        }
        let target =
            narf_memory::PhysAddr::new(walk(0x2345_0000_0080, true)).kernel_mut_ptr::<u32>();
        // SAFETY: the validated writable leaf is an owned private result page.
        unsafe { core::ptr::write_volatile(target, 0x4e415246) };
    }
    if let Some(store) = user_store {
        let address = u64::from(store[1]) | u64::from(store[2]) << 32;
        let value = u64::from(store[3]) | u64::from(store[4]) << 32;
        assert_eq!(address & 7, 0);
        let target = narf_memory::PhysAddr::new(walk(address, true)).kernel_mut_ptr::<u64>();
        // SAFETY: the independent hardware walk resolved one owned aligned
        // writable qword. This models the actual ring's PPGTT store.
        unsafe { core::ptr::write_volatile(target, value) };
    }
}

fn golden_memory(w: &Window) -> Words {
    golden_for_class(w, 0)
}

fn golden_for_class(w: &Window, class: usize) -> Words {
    let d = w.0.borrow();
    let base = d.memory[&0x20001000].borrow()[0x1014 / 4 + class];
    d.memory[&base].clone()
}

fn smoke_hardware_default_context_capture_and_clone() -> TestResult {
    for (platform, ack, gmd) in [
        (GtPlatform::Alchemist, 0x130044, 0),
        (GtPlatform::Battlemage, 0xdfc, (20 << 22) | (1 << 14)),
        (GtPlatform::Battlemage, 0xdfc, (20 << 22) | (2 << 14)),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
            (12 << 22) | (70 << 14),
        ),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
            (12 << 22) | (71 << 14),
        ),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
            (12 << 22) | (74 << 14),
        ),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        if gmd != 0 {
            w.0.borrow_mut().regs.insert(0xd8c, gmd);
        }
        hardware_discovery(&mut gt, &w, ack);
        hardware_scheduling(&mut gt, &w);
        let count = arena.live_allocations();
        let golden = golden_memory(&w);
        let copy_golden = golden_for_class(&w, 3);
        assert!(golden.borrow().iter().all(|word| *word == 0));
        assert!(copy_golden.borrow().iter().all(|word| *word == 0));
        let completion = gt.begin_context_defaults(26).unwrap();
        assert!(!gt.context_defaults_ready());
        assert!(matches!(gt.begin_context_defaults(26), Err(GtError::Busy)));
        assert!(matches!(
            gt.submit_kernel_probe(26),
            Err(GtError::Scheduling(
                crate::intel_gpu_guc_sched::SchedulingError::Busy
            ))
        ));
        {
            use core::{
                future::Future,
                task::{Context, Waker},
            };
            let mut wait = core::pin::pin!(completion.wait());
            assert!(wait
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        let mut registered = BTreeMap::new();
        let mut registrations = 0;
        let mut rcs_first = false;
        for now in 27..150 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            if completion.result().is_some() {
                break;
            }
            assert!(!gt.context_defaults_ready());
            // RCS publishes before BCS's seed; BCS publishes only at the end.
            assert!(copy_golden.borrow().iter().all(|word| *word == 0));
            if !rcs_first && golden.borrow().iter().any(|word| *word != 0) {
                rcs_first = true;
                assert_eq!(registrations, 2);
            }
            registrations += service_contexts(&w, &mut registered, true)
                .iter()
                .filter(|a| **a == 0x4502)
                .count();
        }
        assert!(rcs_first);
        assert_eq!(registrations, 4);
        assert_eq!(completion.result(), Some(Ok(())));
        assert!(gt.context_defaults_ready());
        assert_eq!(arena.live_allocations(), count);
        {
            let data = golden.borrow();
            assert!(data[..1024].iter().all(|word| *word == 0));
            assert_eq!(data[1027], 0x00090008);
            assert_eq!((data[1029], data[1031], data[1033]), (0, 0, 0));
            assert_eq!(data[0x2000 / 4], 0xc01dcafe);
            assert_ne!(data[0x2004 / 4] & 0x20, 0);
            assert_eq!(data[0x2100 / 4], 0x78150009);
            assert_eq!(data[0x2100 / 4 + 45], 0x78770001); // MESH_CONTROL
            assert_eq!(
                data[0x2100 / 4 + 49],
                if platform == GtPlatform::Battlemage {
                    0x78000002
                } else {
                    0x79000002
                }
            );
        }
        {
            // BCS0's retired seed image: restore enabled, ring slots cleared,
            // hardware-saved BLIT_CCTL (xe2_bcs_offsets) carried to clones.
            let data = copy_golden.borrow();
            assert_eq!(data.len(), 2048);
            assert!(data[..1024].iter().all(|word| *word == 0));
            let xe2 = platform == GtPlatform::Battlemage;
            assert_eq!(data[1025], if xe2 { 0x1108101d } else { 0x11081019 });
            assert_eq!((data[1026], data[1027]), (0x22244, 0x00090008));
            assert_eq!((data[1029], data[1031], data[1033]), (0, 0, 0));
            if xe2 {
                // RMW of the all-ones fixture reset value keeps reserved bits.
                assert_eq!(data[1024 + 0x45], (u32::MAX & !0x7e7e) | 3 << 9 | 3 << 1);
            }
            let ads = w.0.borrow().memory[&0x20001000].clone();
            let ads = ads.borrow();
            // Mapping, enable mask, state size and BCS0 register saves.
            assert_eq!((ads[(0x123c + 96) / 4], ads[(0x123c + 524) / 4]), (0x20202000, 1));
            assert_eq!(ads[0x1060 / 4], 8192 - 4096 - 384);
            assert_eq!(ads[0x300 / 4 + 1], 3);
            let saves = (ads[0x300 / 4] - 0x20001000) as usize / 4;
            assert_eq!(
                [ads[saves], ads[saves + 2], ads[saves + 4], ads[saves + 8], ads[saves + 12]],
                [0x2229c, 1, 0x22080, 0x220a8, 0]
            );
            assert_eq!(ads[saves + 5], w.0.borrow().regs[&0x22080]);
        }
        // A fresh PPGTT context must inherit the device's saved opaque state,
        // restore it rather than inhibit, and receive its own ring and root.
        let probe = gt.submit_ppgtt_probe(100).unwrap();
        for now in 101..125 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, true);
            for base in registered.values() {
                let image = w.0.borrow().memory[base].clone();
                assert_eq!(image.borrow()[1027], 0x00090008);
                assert_eq!(image.borrow()[0x2000 / 4], 0xc01dcafe);
                assert_eq!(
                    &image.borrow()[0x2100 / 4..0x2100 / 4 + 50],
                    &golden.borrow()[0x2100 / 4..0x2100 / 4 + 50]
                );
                assert_ne!(image.borrow()[1033], 0);
            }
            if probe.completion.result().is_some() {
                break;
            }
        }
        assert_eq!(probe.completion.result(), Some(Ok(())));
        assert_eq!(probe.result.verify(), Ok(()));
        hardware_stop(&mut gt, &w, ack);
        assert!(!gt.context_defaults_ready());
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_default_context_capture_and_clone
);

fn smoke_hardware_defaults_failures_wait_for_full_reset() -> TestResult {
    for cpu_sync in [false, true] {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
        hardware_discovery(&mut gt, &w, 0x130044);
        hardware_scheduling(&mut gt, &w);
        let count = arena.live_allocations();
        let completion = gt.begin_context_defaults(26).unwrap();
        let mut registered = BTreeMap::new();
        let mut corrupted = false;
        let mut lost = false;
        for now in 27..90 {
            if let Poll::Ready(Err(GtError::Scheduling(_))) = gt.poll(now) {
                lost = true;
                break;
            }
            service_contexts(&w, &mut registered, true);
            if !corrupted {
                for base in registered.values() {
                    let image = w.0.borrow().memory[base].clone();
                    if image.borrow()[0x2000 / 4] == 0xc01dcafe {
                        if cpu_sync {
                            w.0.borrow_mut().fail_cpu_sync = true;
                        } else {
                            image.borrow_mut()[1025] = u32::MAX;
                        }
                        corrupted = true;
                        break;
                    }
                }
            }
        }
        assert!(corrupted && lost);
        assert_eq!(gt.state(), GtState::Lost);
        assert!(completion.result().is_none());
        assert!(!gt.context_defaults_ready());
        assert!(arena.live_allocations() > count);
        hardware_stop(&mut gt, &w, 0x130044);
        assert_eq!(
            completion.result(),
            Some(Err(crate::intel_gpu_fence::JobError::Reset))
        );
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_defaults_failures_wait_for_full_reset
);

fn smoke_hardware_default_switch_cancel_requires_full_reset() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
    hardware_discovery(&mut gt, &w, 0x130044);
    hardware_scheduling(&mut gt, &w);
    let baseline = arena.live_allocations();
    let completion = gt.begin_context_defaults(26).unwrap();
    let mut registered = BTreeMap::new();
    for now in 27..60 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if arena.live_allocations() == baseline + 3 {
            break;
        }
        service_contexts(&w, &mut registered, true);
    }
    // The seed is fully retired but deliberately retained; the second
    // context has been allocated. A GuC-only reset cannot free either one.
    assert_eq!(arena.live_allocations(), baseline + 3);
    assert!(completion.result().is_none());
    gt.begin_stop(10_000_000_000).unwrap();
    reset_done(&w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(10_000_000_001).is_pending());
    assert_eq!(gt.state(), GtState::ResettingEngines);
    assert!(completion.result().is_none());
    assert!(arena.live_allocations() >= baseline + 2);
    assert!(gt.poll(10_000_000_002).is_pending());
    reset_done(&w);
    assert!(gt.poll(10_000_000_003).is_pending());
    assert_eq!(
        completion.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(10_000_000_004).is_pending());
    w.0.borrow_mut().regs.insert(0x130044, 0);
    assert_eq!(gt.poll(10_000_000_005), Poll::Ready(Ok(GtState::Stopped)));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_default_switch_cancel_requires_full_reset
);

fn smoke_hardware_ppgtt_store_and_retirement() -> TestResult {
    for (platform, ack) in [
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
        ),
        (GtPlatform::Alchemist, 0x130044),
        (GtPlatform::Battlemage, 0xdfc),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        hardware_discovery(&mut gt, &w, ack);
        hardware_scheduling(&mut gt, &w);
        let count = arena.live_allocations();
        let probe = gt.submit_ppgtt_probe(26).unwrap();
        assert!(probe.result.verify().is_err());
        let weak = probe.result.weak_objects();
        assert!(weak.iter().all(|o| o.strong_count() == 2));
        assert_eq!(weak[0].upgrade().unwrap().busy(), 0x10000);
        assert_eq!(weak[1].upgrade().unwrap().busy(), 0x10001);
        {
            use crate::intel_gpu_exec::{ExecObject, ExecRequest};
            let count = arena.live_allocations();
            let batch = ExecRequest {
                context_id: 0,
                batch_va: 0x1234_0000_0000,
                batch_len: 24,
                objects: alloc::vec![
                    ExecObject {
                        object: weak[0].upgrade().unwrap(),
                        va: 0x1234_0000_0000,
                        writable: false
                    },
                    ExecObject {
                        object: weak[1].upgrade().unwrap(),
                        va: 0x2345_0000_0000,
                        writable: true
                    },
                ],
            }
            .prepare_for_gt(platform)
            .unwrap();
            // SAFETY: the fixed private probe is unchanged; its conflicting
            // writer must be rejected before any context reaches firmware.
            let rejected = unsafe { gt.submit_kernel_batch(26, batch) };
            assert!(matches!(
                rejected,
                Err(GtError::Scheduling(
                    crate::intel_gpu_guc_sched::SchedulingError::Residency(
                        narf_filesystem::FsError::WouldBlock
                    )
                ))
            ));
            assert_eq!(arena.live_allocations(), count);
        }
        let mut registered = BTreeMap::new();
        for now in 27..48 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, true);
            if probe.completion.result().is_some() {
                break;
            }
        }
        assert_eq!(probe.completion.result(), Some(Ok(())));
        assert!(weak.iter().all(|o| o.upgrade().unwrap().busy() == 0));
        assert_eq!(probe.result.verify(), Ok(()));
        assert_eq!(arena.live_allocations(), count);
        // Priming after a resident job could capture that job's graphics
        // state, even after complete retirement. It requires a fresh GT.
        assert!(matches!(gt.begin_context_defaults(100), Err(GtError::Busy)));
        assert!(weak.iter().all(|o| o.strong_count() == 1));
        drop(probe);
        assert!(weak.iter().all(|o| o.upgrade().is_none()));
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_ppgtt_store_and_retirement
);

fn smoke_hardware_reservation_cache_failure_releases_before_retry() -> TestResult {
    use crate::intel_gpu_exec::{ExecObject, ExecRequest, PpgttProbeResult};
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    hardware_discovery(&mut gt, &w, 0xdfc);
    hardware_scheduling(&mut gt, &w);
    let baseline = arena.live_allocations();
    let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
    let weak = result.weak_objects();
    w.0.borrow_mut().fail_sync = true;
    // SAFETY: the fixed private probe is trusted and has no mapped aliases.
    let failed = unsafe { gt.submit_kernel_batch(26, batch) };
    assert!(matches!(
        failed,
        Err(GtError::Scheduling(
            crate::intel_gpu_guc_sched::SchedulingError::Cache
        ))
    ));
    assert_eq!(arena.live_allocations(), baseline);
    assert!(weak
        .iter()
        .all(|object| object.strong_count() == 1 && object.upgrade().unwrap().busy() == 0));
    w.0.borrow_mut().fail_sync = false;
    let batch = ExecRequest {
        context_id: 0,
        batch_va: 0x1234_0000_0000,
        batch_len: 24,
        objects: alloc::vec![
            ExecObject {
                object: weak[0].upgrade().unwrap(),
                va: 0x1234_0000_0000,
                writable: false
            },
            ExecObject {
                object: weak[1].upgrade().unwrap(),
                va: 0x2345_0000_0000,
                writable: true
            },
        ],
    }
    .prepare_for_gt(platform)
    .unwrap();
    // SAFETY: unchanged private probe, with failed submission fully released.
    let (id, completion) = unsafe { gt.submit_kernel_batch(26, batch) }.unwrap();
    assert_eq!(
        id, 1,
        "failed pre-publication submission consumed an identity"
    );
    assert_eq!(weak[1].upgrade().unwrap().busy(), 0x10001);
    hardware_stop(&mut gt, &w, 0xdfc);
    assert_eq!(
        completion.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    assert!(weak
        .iter()
        .all(|object| object.upgrade().unwrap().busy() == 0));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_reservation_cache_failure_releases_before_retry
);

fn smoke_hardware_ppgtt_cancel_and_reset() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    hardware_discovery(&mut gt, &w, 0xdfc);
    hardware_scheduling(&mut gt, &w);
    let probe = gt.submit_ppgtt_probe(26).unwrap();
    let weak = probe.result.weak_objects();
    let completion = probe.completion.clone();
    // Dropping the result and cancelling a waiter never abandons DMA owners.
    {
        use core::{
            future::Future,
            task::{Context, Waker},
        };
        let mut wait = core::pin::pin!(completion.wait());
        assert!(wait
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    drop(probe);
    let mut registered = BTreeMap::new();
    for now in 27..32 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
    }
    let count = arena.live_allocations();
    assert!(weak.iter().all(|o| o.strong_count() == 1));
    assert!(matches!(
        gt.poll(5_000_000_026),
        Poll::Ready(Err(GtError::Scheduling(_)))
    ));
    assert!(completion.result().is_none());
    assert_eq!(weak[1].upgrade().unwrap().busy(), 0x10001);
    gt.begin_stop(10_000_000_000).unwrap();
    reset_done(&w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(10_000_000_001).is_pending());
    assert_eq!(gt.state(), GtState::ResettingEngines);
    assert_eq!(arena.live_allocations(), count);
    assert!(weak.iter().all(|o| o.strong_count() == 1));
    assert!(gt.poll(10_000_000_002).is_pending());
    reset_done(&w);
    assert!(gt.poll(10_000_000_003).is_pending());
    assert_eq!(
        completion.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    assert!(weak.iter().all(|o| o.upgrade().is_none()));
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(10_000_000_004).is_pending());
    w.0.borrow_mut().regs.insert(0xdfc, 0);
    assert_eq!(gt.poll(10_000_000_005), Poll::Ready(Ok(GtState::Stopped)));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_ppgtt_cancel_and_reset
);

fn smoke_hardware_ppgtt_admission_and_lost_proof() -> TestResult {
    use crate::{intel_gpu_exec::PpgttProbeResult, intel_gpu_guc_sched::SchedulingError};
    let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
    hardware_discovery(&mut gt, &w, 0x130044);
    hardware_scheduling(&mut gt, &w);
    let count = arena.live_allocations();
    let (batch, result) = PpgttProbeResult::prepare(GtPlatform::Battlemage).unwrap();
    let foreign = result.weak_objects();
    // SAFETY: this is the fixed, private kernel probe; the mismatch must fail
    // before publication and release its private page-table residency.
    let admission = unsafe { gt.submit_kernel_batch(26, batch) };
    assert!(matches!(
        admission,
        Err(GtError::Scheduling(SchedulingError::Address))
    ));
    assert_eq!(arena.live_allocations(), count);
    assert!(foreign.iter().all(|o| o.strong_count() == 1));
    drop(result);
    assert!(foreign.iter().all(|o| o.upgrade().is_none()));
    let probe = gt.submit_ppgtt_probe(26).unwrap();
    let weak = probe.result.weak_objects();
    let completion = probe.completion.clone();
    drop(probe);
    let mut registered = BTreeMap::new();
    // Reach disable acknowledgment, before consuming deregistration.
    for now in 27..34 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, true);
        if let Some(base) = registered.values().next() {
            let image = w.0.borrow().memory[base].clone();
            if image.borrow()[0x800 / 4] != 0 {
                // Corrupt only the saved head after device completion. The
                // breadcrumb and GuC ACK still cannot authorize retirement.
                image.borrow_mut()[1024 + 5] = 0;
                break;
            }
        }
    }
    let mut lost = false;
    for now in 34..45 {
        match gt.poll(now) {
            Poll::Ready(Err(GtError::Scheduling(SchedulingError::Protocol))) => {
                lost = true;
                break;
            }
            Poll::Ready(Ok(GtState::SchedulingReady)) => {
                service_contexts(&w, &mut registered, false);
            }
            other => panic!("unexpected retirement state {other:?}"),
        }
    }
    assert!(lost);
    assert!(completion.result().is_none());
    assert!(weak.iter().all(|o| o.strong_count() == 1));
    hardware_stop(&mut gt, &w, 0x130044);
    assert_eq!(
        completion.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    assert!(weak.iter().all(|o| o.upgrade().is_none()));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_ppgtt_admission_and_lost_proof
);

fn smoke_hardware_gt_reload_and_context_execution() -> TestResult {
    for (platform, ack) in [
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
        ),
        (GtPlatform::Alchemist, 0x130044),
        (GtPlatform::Battlemage, 0xdfc),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        hardware_discovery(&mut gt, &w, ack);
        {
            let d = w.0.borrow();
            let expected = match platform {
                GtPlatform::Alchemist => (0xb020, 0x00d00090),
                GtPlatform::Battlemage => (0x400c, 0x13c),
                _ => (0xb030, 0x00500050),
            };
            assert!(d.writes.contains(&expected));
            assert!(
                d.writes.iter().position(|(r, _)| *r == expected.0).unwrap()
                    < d.writes
                        .iter()
                        .position(|p| *p == (0xc314, 0x00110011))
                        .unwrap()
            );
        }
        hardware_scheduling(&mut gt, &w);
        assert_eq!(w.0.borrow().regs.get(&0xc18c), Some(&16));
        assert_eq!(
            w.0.borrow().memory[&0x20001000].borrow()[0x1054 / 4],
            if platform == GtPlatform::Battlemage {
                0x2e80
            } else {
                0xce80
            }
        );
        let count = arena.live_allocations();
        let (id, completion) = gt.submit_kernel_probe(26).unwrap();
        let (_, other) = gt.submit_kernel_probe(26).unwrap();
        assert_eq!(id, 1);
        assert_eq!(arena.live_allocations(), count + 4);
        {
            use core::{
                future::Future,
                task::{Context, Waker},
            };
            let mut wait = core::pin::pin!(completion.wait());
            assert!(wait
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert!(completion.result().is_none());
        let mut registered = BTreeMap::new();
        let mut actions = Vec::new();
        for now in 27..44 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            actions.extend(service_contexts(&w, &mut registered, true));
            if completion.result().is_some() && other.result().is_some() {
                break;
            }
        }
        assert_eq!(completion.result(), Some(Ok(())));
        assert_eq!(other.result(), Some(Ok(())));
        assert_eq!(arena.live_allocations(), count);
        assert_eq!(
            &actions[..8],
            &[0x7000, 0x7000, 0x4502, 0x4502, 0x100b, 0x100b, 0x1001, 0x1001]
        );
        assert!(registered.is_empty());
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_gt_reload_and_context_execution
);

fn smoke_hardware_context_faults_require_full_reset() -> TestResult {
    for malformed in [false, true] {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        hardware_discovery(&mut gt, &w, 0xdfc);
        hardware_scheduling(&mut gt, &w);
        let (_, completion) = gt.submit_kernel_probe(26).unwrap();
        let mut registered = BTreeMap::new();
        for now in 27..32 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, false);
        }
        let count = arena.live_allocations();
        if malformed {
            event(&ct_memory(&w), 0x1002, &[0xffff, 1]);
        }
        let now = if malformed { 32 } else { 5_000_000_026 };
        assert!(matches!(
            gt.poll(now),
            Poll::Ready(Err(GtError::Scheduling(_)))
        ));
        assert_eq!(gt.state(), GtState::Lost);
        assert!(completion.result().is_none());
        assert_eq!(arena.live_allocations(), count);
        gt.begin_stop(10_000_000_000).unwrap();
        reset_done(&w);
        w.0.borrow_mut().regs.insert(0xc314, 0);
        assert!(gt.poll(10_000_000_001).is_pending());
        assert_eq!(gt.state(), GtState::ResettingEngines);
        assert_eq!(arena.live_allocations(), count);
        assert!(completion.result().is_none());
        assert!(gt.poll(10_000_000_002).is_pending());
        reset_done(&w);
        assert!(gt.poll(10_000_000_003).is_pending());
        assert_eq!(
            completion.result(),
            Some(Err(crate::intel_gpu_fence::JobError::Reset))
        );
        assert_eq!(arena.live_allocations(), 4);
        w.0.borrow_mut().regs.insert(0xd84, 0);
        assert!(gt.poll(10_000_000_004).is_pending());
        w.0.borrow_mut().regs.insert(0xdfc, 0);
        assert_eq!(gt.poll(10_000_000_005), Poll::Ready(Ok(GtState::Stopped)));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_context_faults_require_full_reset
);

fn smoke_hardware_boot_failure_and_cancelled_reload() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
    hardware_discovery(&mut gt, &w, 0x130044);
    gt.begin_scheduling(12).unwrap();
    gt.begin_stop(13).unwrap();
    reset_done(&w);
    w.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(gt.poll(14).is_pending());
    assert_eq!(gt.state(), GtState::ResettingEngines);
    assert_eq!(
        w.0.borrow()
            .writes
            .iter()
            .filter(|p| **p == (0xc314, 0x00110011))
            .count(),
        1
    );
    reset_done(&w);
    assert!(gt.poll(15).is_pending());
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(16).is_pending());
    w.0.borrow_mut().regs.insert(0x130044, 0);
    assert_eq!(gt.poll(17), Poll::Ready(Ok(GtState::Stopped)));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);

    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    hardware_discovery(&mut gt, &w, 0xdfc);
    hardware_scheduling(&mut gt, &w);
    let (_, completion) = gt.submit_kernel_probe(26).unwrap();
    assert_eq!(gt.poll(27), Poll::Ready(Ok(GtState::SchedulingReady)));
    let weak = Rc::downgrade(&w.0);
    let count = arena.live_allocations();
    drop(w);
    drop(arena);
    drop(gt);
    assert_eq!(weak.upgrade().unwrap().borrow().memory.len(), count);
    assert!(completion.result().is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_boot_failure_and_cancelled_reload
);

fn smoke_hardware_context_pressure_and_identity() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
    hardware_discovery(&mut gt, &w, 0x130044);
    hardware_scheduling(&mut gt, &w);
    let baseline = arena.live_allocations();
    let mut fences = Vec::new();
    for expected in 1..=64 {
        let (id, fence) = gt.submit_kernel_probe(26).unwrap();
        assert_eq!(id, expected);
        fences.push(fence);
    }
    assert!(gt.submit_kernel_probe(26).is_err());
    let mut registered = BTreeMap::new();
    assert_eq!(gt.poll(27), Poll::Ready(Ok(GtState::SchedulingReady)));
    service_contexts(&w, &mut registered, true);
    for now in 28..31 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
    }
    // Registrations and policies occupy the real H2G ring. Full leaves
    // unsent phases intact and does not poison a healthy GT.
    assert!(fences.iter().all(|f| f.result().is_none()));
    for now in 31..60 {
        service_contexts(&w, &mut registered, true);
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if fences.iter().all(|f| f.result().is_some()) {
            break;
        }
    }
    assert!(fences.iter().all(|f| f.result() == Some(Ok(()))));
    assert_eq!(arena.live_allocations(), baseline);
    let (id, _) = gt.submit_kernel_probe(61).unwrap();
    assert_eq!(id, 1, "fully retired identities are recyclable");
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_context_pressure_and_identity
);

fn smoke_hardware_cache_policy_and_current_authority() -> TestResult {
    use crate::intel_gpu_gt_hw::{AuthorizedWindow, HardwareInit};
    use crate::intel_gpu_rcs::{GgttArena, SharedArena};
    use narf_capabilities::Cap;
    let mut memory = alloc::vec![0u32; 4*1024*1024];
    let bar = narf_bus::bar::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xdead0000),
        virt: memory.as_mut_ptr() as u64,
        len: 16 * 1024 * 1024,
        kind: narf_bus::bar::BarKind::Mmio64 {
            prefetchable: false,
        },
    };
    let cap: Cap<narf_bus::BusDeviceCap, narf_capabilities::Write> = Cap::bootstrap();
    let window = AuthorizedWindow::new(bar, cap);
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let mut arena = SharedArena::new(GgttArena::for_gt(bar, cap, platform));
    let mut backing = arena.alloc(1).unwrap();
    let pte = (0x800000 + u64::from(backing.ggtt_offset() / 4096) * 8) as usize / 4;
    assert_eq!(memory[pte], 0, "staging wrote live GGTT before reset");
    let mut hardware = HardwareInit::new(platform).unwrap();
    hardware.begin(&window, 0).unwrap();
    memory[0xd84 / 4] = 1;
    assert!(hardware.poll(&window, 1).is_pending());
    memory[0x941c / 4] = 0;
    memory[0xc000 / 4] = 1;
    assert!(hardware.poll(&window, 2).is_pending());
    memory[0x941c / 4] = 0;
    memory[0xfd0 / 4] = 1;
    let Poll::Ready(Ok(policy)) = hardware.poll(&window, 3) else {
        panic!("cache initialization")
    };
    assert_eq!(memory[pte], 0);
    arena.configure_cache(&mut backing, policy).unwrap();
    let entry = u64::from(memory[pte]) | u64::from(memory[pte + 1]) << 32;
    assert_eq!(entry & 0xfff0000000000fff, 0x0030000000000001);
    assert_eq!(backing.coherent_for_device(), cfg!(target_arch = "x86_64"));
    arena.free(backing);
    assert_eq!(memory[pte], 0);
    let old = memory[0x4000 / 4];
    cap.revoke();
    assert_eq!(window.read32(0x4000), u32::MAX);
    window.write32(0x4000, 0xaabbccdd);
    assert_eq!(memory[0x4000 / 4], old, "revoked authority wrote MMIO");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_cache_policy_and_current_authority
);

fn smoke_hardware_admission_and_boot_failure() -> TestResult {
    for compatibility in [true, false] {
        let (w, arena, mut gt) = hardware_model_with_interface(
            GtPlatform::Battlemage,
            0xdfc,
            if compatibility { 0 } else { 1 },
        );
        hardware_discovery(&mut gt, &w, 0xdfc);
        let count = arena.live_allocations();
        if !compatibility {
            w.0.borrow_mut().coherent = false;
        }
        assert!(gt.begin_scheduling(12).is_err());
        assert_eq!(gt.state(), GtState::Ready);
        assert_eq!(arena.live_allocations(), count);
        assert!(!w.0.borrow().writes.iter().any(|(reg, _)| *reg == 0x2080));
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    let (w, arena, mut gt) = hardware_model(GtPlatform::Alchemist, 0x130044);
    gt.begin(0).unwrap();
    w.0.borrow_mut().regs.insert(0x130044, 1);
    assert!(gt.poll(1).is_pending());
    w.0.borrow_mut().regs.insert(0xd84, 1);
    assert!(gt.poll(2).is_pending());
    assert!(matches!(
        gt.poll(5_000_002),
        Poll::Ready(Err(GtError::Hardware(_)))
    ));
    assert_eq!(gt.state(), GtState::Lost);
    assert!(!w
        .0
        .borrow()
        .writes
        .iter()
        .any(|(reg, _)| *reg == 0xc314 || *reg == 0xb020));
    gt.begin_stop(5_000_003).unwrap();
    w.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(5_000_004).is_pending());
    w.0.borrow_mut().regs.insert(0x130044, 0);
    assert_eq!(gt.poll(5_000_005), Poll::Ready(Ok(GtState::Stopped)));
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_hardware_admission_and_boot_failure
);
