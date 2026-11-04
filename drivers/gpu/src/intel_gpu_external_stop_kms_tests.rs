use super::*;

fn smoke_gen12_external_drain_gate_raw_fifo_refuses_new_arm_without_dma_or_success() -> TestResult {
    let mode = mode();
    let Some(fb) = frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let q = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let p = MockPlatform::new();
    let mut worker = Worker {
        device: Arc::new(p.gen12(Gen12Platform::AlderLakeP)),
    };
    request(&cpu, fb, NONBLOCK | TEST_ONLY);
    assert!(
        admission(&q, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
            .unwrap()
            .is_none()
    );
    assert!(cpu.exported.lock().is_empty() && p.primary_mappings().is_empty());
    request(&cpu, fb, NONBLOCK | EVENT);
    let done = submit(&q, &cpu, &events);
    let fence = cpu.exported.lock()[0].clone();
    let guard = worker.device.legacy_drain().unwrap();
    assert_eq!(p.read32(LIVE), CONSOLE);
    drop(guard); // dropping a stop waiter must not reopen internal admission
    run(q.run(&mut worker));
    assert!(done.status() < 0 && fence.status() < 0);
    assert!(p.primary_mappings().is_empty() && p.dsb_mappings().is_empty());
    assert_eq!(p.read32(SURF), CONSOLE);
    assert_eq!(mode.lock().crtcs[0].primary_fb, None);
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    assert!(run(worker.device.session()).is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_external_drain_gate_raw_fifo_refuses_new_arm_without_dma_or_success
);

fn smoke_gen12_external_drain_cancel_and_master_close_keep_existing_primary_dma() -> TestResult {
    let mode = mode();
    let Some(a) = frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let retained_object = weak(&mode, a);
    let b = frame(&mode, 7).unwrap();
    let q = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let p = MockPlatform::new();
    let mut worker = Worker {
        device: Arc::new(p.gen12(Gen12Platform::TigerLake)),
    };
    request(&cpu, a, NONBLOCK);
    let abandoned = submit(&q, &cpu, &events);
    p.allow_flips(false);
    let mut work = Box::pin(q.run(&mut worker));
    for _ in 0..8 {
        pending(work.as_mut());
        if p.read32(SURF) != CONSOLE {
            break;
        }
    }
    assert_ne!(p.read32(SURF), CONSOLE);
    assert_eq!(p.read32(LIVE), CONSOLE);
    drop(work);
    assert!(abandoned.status() < 0);
    let retained = p.primary_mappings();
    assert_eq!(mapped_pages(&retained), 2);
    for &(r, _) in &retained {
        if r % 8 == 0 {
            assert_eq!(p.read32(r + 4) & !0x7f, 0);
        }
    }
    drop(worker.device.legacy_drain().unwrap());
    request(&cpu, b, NONBLOCK | EVENT);
    let refused = submit(&q, &cpu, &events);
    run(q.run(&mut worker));
    assert!(refused.status() < 0);
    mode.lock().release_file_framebuffers(7);
    mode.lock().master_release(7);
    assert!(retained_object.upgrade().is_some());
    assert_eq!(p.primary_mappings(), retained);
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    p.poison();
    // A missing console PTE is not a reset/idle witness and cannot release BOs.
    p.set(CONSOLE_PTE, 0);
    assert!(run(worker.device.recover()).is_err());
    assert_eq!(p.primary_mappings(), retained);
    assert!(retained_object.upgrade().is_some());
    p.set(CONSOLE_PTE, 0x100001);
    p.allow_flips(true);
    run(worker.device.recover()).unwrap();
    assert_eq!(p.read32(LIVE), CONSOLE);
    assert!(p.primary_mappings().is_empty());
    assert!(retained_object.upgrade().is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_external_drain_cancel_and_master_close_keep_existing_primary_dma
);

fn smoke_gen12_primary_family_inventory_raw_fifo_ignores_absent_planes_but_refuses_live_supported(
) -> TestResult {
    for (family, last) in [
        (Gen12Platform::TigerLake, 7u64),
        (Gen12Platform::AlderLakeS, 5),
        (Gen12Platform::AlderLakeP, 5),
        (Gen12Platform::AlderLakeN, 5),
    ] {
        // Both normal direct takeover and fresh recovery use this source
        // inventory; the platform model returns MAX for absent ADL planes6/7.
        let active_mode = mode();
        let Some(fb) = frame(&active_mode, 7) else {
            return TestResult::Pass;
        };
        let q = queue::Queue::new(active_mode);
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let p = MockPlatform::new();
        let mut worker = Worker {
            device: Arc::new(p.gen12(family)),
        };
        request(&cpu, fb, NONBLOCK);
        let done = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(done.status(), 1);
        p.poison();
        run(worker.device.recover()).unwrap();
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert!(p.primary_mappings().is_empty());
        assert_eq!(p.forbidden_display_reads(), 0);
        for plane in 2..=last {
            let mode = mode();
            let fb = frame(&mode, 7).unwrap();
            let q = queue::Queue::new(mode);
            let cpu = Cpu::new();
            let events = Events::new(IrqSafeSpinLock::new(Default::default()));
            let p = MockPlatform::new();
            let mut worker = Worker {
                device: Arc::new(p.gen12(family)),
            };
            p.set(0x70080 + plane * 0x100, 0x80000000);
            request(&cpu, fb, NONBLOCK | EVENT);
            let done = submit(&q, &cpu, &events);
            run(q.run(&mut worker));
            assert!(done.status() < 0);
            assert!(p.primary_mappings().is_empty());
            assert_eq!(p.forbidden_display_reads(), 0);
            assert!(!events.lock().has_deliverable_event(u64::MAX));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_primary_family_inventory_raw_fifo_ignores_absent_planes_but_refuses_live_supported
);
