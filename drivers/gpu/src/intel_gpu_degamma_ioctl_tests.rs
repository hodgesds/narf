// Actual atomic UAPI -> retained FIFO -> pre-CSC RAM/DSB, Linux b90c984d.
use super::*;
fn dg_bytes(curve: bool) -> Vec<u8> {
    (0..129u32)
        .flat_map(|i| {
            let v = (if curve {
                i * i * 65535 / (128 * 128)
            } else {
                i * 65535 / 128
            }) as u16;
            [
                v.to_le_bytes(),
                v.to_le_bytes(),
                v.to_le_bytes(),
                [0xff, 0xff],
            ]
            .concat()
        })
        .collect()
}
fn dg_blob(mode: &ModeState, curve: bool) -> u32 {
    mode.lock().create_property_blob(dg_bytes(curve)).unwrap()
}
fn dg_request(cpu: &Cpu, id: u32, flags: u32) {
    let mut header = [0u8; 56];
    header[..4].copy_from_slice(&flags.to_le_bytes());
    header[4..8].copy_from_slice(&1u32.to_le_bytes());
    for (at, pointer) in [(8, 128u64), (16, 144), (24, 160), (32, 192)] {
        header[at..at + 8].copy_from_slice(&pointer.to_le_bytes());
    }
    header[48..56].copy_from_slice(&0xdededeu64.to_le_bytes());
    cpu.write(64, &header).unwrap();
    cpu.write(128, &1u32.to_le_bytes()).unwrap();
    cpu.write(144, &2u32.to_le_bytes()).unwrap();
    cpu.write(160, &CRTC_DEGAMMA_LUT_PROP_ID.to_le_bytes())
        .unwrap();
    cpu.write(164, &CRTC_OUT_FENCE_PTR_PROP_ID.to_le_bytes())
        .unwrap();
    cpu.write(192, &u64::from(id).to_le_bytes()).unwrap();
    cpu.write(200, &512u64.to_le_bytes()).unwrap();
}
fn fixture() -> (MockPlatform, ModeState, queue::Queue, Worker, Cpu, Events) {
    let p = MockPlatform::new();
    p.dsb_timing();
    let mode = color_mode();
    let queue = queue::Queue::new(mode.clone());
    let worker = Worker {
        device: Arc::new(p.meteor()),
    };
    (
        p,
        mode,
        queue,
        worker,
        Cpu::new(),
        Events::new(IrqSafeSpinLock::new(Default::default())),
    )
}
fn admit_as(queue: &queue::Queue, cpu: &Cpu, events: &Events, open: u64) -> Arc<queue::Completion> {
    run(admit(
        queue,
        open,
        drm_uapi::DRM_IOCTL_MODE_ATOMIC,
        64,
        cpu,
        Some(events),
        Geometry {
            width: 64,
            height: 32,
            pitch: 256,
        },
        1,
    ))
    .unwrap()
    .unwrap()
    .0
}
fn smoke_intel_degamma_real_property_cpu_preload_latch_and_original_restore() -> TestResult {
    let (p, mode, queue, mut worker, cpu, events) = fixture();
    let original = p.pre_palette();
    let id = dg_blob(&mode, false);
    assert_eq!(
        crtc_color_properties(&mode.lock(), 1).1,
        vec![0, 0, 1024, 0, 129]
    );
    dg_request(&cpu, id, NONBLOCK | EVENT);
    let done = submit(&queue, &cpu, &events);
    assert_eq!(done.status(), 0);
    assert_eq!(p.pre_writes(), 0);
    mode.lock().destroy_property_blob(id);
    cpu.write(192, &0u64.to_le_bytes()).unwrap();
    let mut work = Box::pin(queue.run(&mut worker));
    assert!(work
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(p.pre_writes(), 131);
    assert_eq!(p.read32(0x4a480), 1 << 31);
    assert_eq!(done.status(), 0);
    assert_eq!(mode.lock().crtc_color(1).unwrap().degamma_lut, 0);
    run(work);
    assert_eq!(done.status(), 1);
    assert_eq!(mode.lock().crtc_color(1).unwrap().degamma_lut, id);
    let values = p.pre_palette();
    assert_eq!(values[0], 0);
    assert_eq!(values[128], 0xffffff);
    assert_eq!(&values[129..], &[1 << 24; 2]);
    assert_eq!(p.read32(0x4a484), 0);
    assert_eq!(p.palette_writes(), 0);
    // Keep the color owner alive across degamma disable, then change CTM
    // again. A saved original palette must not cause repeated RAM writes.
    let ctm = blob(&mode);
    request(&cpu, ctm, NONBLOCK);
    let matrix = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(matrix.status(), 1);
    assert_eq!(p.pre_writes(), 131);
    dg_request(&cpu, 0, NONBLOCK);
    let clear = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(clear.status(), 1);
    assert_eq!(p.read32(0x4a480), 0);
    assert_eq!(p.pre_palette(), original);
    assert_eq!(p.pre_writes(), 262);
    request(&cpu, 0, NONBLOCK);
    let bypass = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(bypass.status(), 1);
    assert_eq!(p.pre_writes(), 262);
    assert_eq!(p.pre_palette(), original);
    assert!(mode.lock().property_blob(id).is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_degamma_real_property_cpu_preload_latch_and_original_restore
);
fn smoke_intel_degamma_fifo_replacement_preserves_ctm_primary_and_blob_identity() -> TestResult {
    let (p, mode, queue, mut worker, cpu, events) = fixture();
    let first = dg_blob(&mode, false);
    let second = dg_blob(&mode, true);
    dg_request(&cpu, first, NONBLOCK);
    let a = submit(&queue, &cpu, &events);
    dg_request(&cpu, second, NONBLOCK | EVENT);
    let b = submit(&queue, &cpu, &events);
    mode.lock().destroy_property_blob(first);
    mode.lock().destroy_property_blob(second);
    run(queue.run(&mut worker));
    assert_eq!(a.status(), 1);
    #[cfg(target_arch = "aarch64")]
    {
        assert!(b.status() < 0);
        assert_eq!(mode.lock().crtc_color(1).unwrap().degamma_lut, first);
    }
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(b.status(), 1);
        assert_eq!(mode.lock().crtc_color(1).unwrap().degamma_lut, second);
        assert_eq!(p.pre_writes(), 262);
        let curve = p.pre_palette();
        let ctm = blob(&mode);
        request(&cpu, ctm, NONBLOCK);
        let changed = submit(&queue, &cpu, &events);
        run(queue.run(&mut worker));
        assert_eq!(changed.status(), 1);
        assert_eq!(p.pre_writes(), 262);
        assert_eq!(p.pre_palette(), curve);
        assert_ne!(p.read32(0x49028), 0);
        let fb = framebuffer(&mode, 7, true).unwrap();
        let flip = run(queue.submit(
            7,
            atomic_frame(fb, NONBLOCK),
            Geometry {
                width: 64,
                height: 32,
                pitch: 256,
            },
            1,
            &cpu,
            None,
        ))
        .unwrap()
        .unwrap()
        .0;
        run(queue.run(&mut worker));
        assert_eq!(flip.status(), 1);
        assert_eq!(p.pre_palette(), curve);
        assert_eq!(mode.lock().crtc_color(1).unwrap().degamma_lut, second);
        // Real legacy SET resets DEGAMMA and CTM using one common DSB arm.
        let mut header = [0; 32];
        header[..4].copy_from_slice(&1u32.to_le_bytes());
        header[4..8].copy_from_slice(&256u32.to_le_bytes());
        for (at, ptr) in [(8, 512u64), (16, 1024), (24, 1536)] {
            header[at..at + 8].copy_from_slice(&ptr.to_le_bytes());
            cpu.write(ptr, &vec![0xff; 512]).unwrap();
        }
        cpu.write(64, &header).unwrap();
        let legacy = run(admit(
            &queue,
            7,
            drm_uapi::iowr(b'd' as u32, 0xa5, 32),
            64,
            &cpu,
            None,
            Geometry {
                width: 64,
                height: 32,
                pitch: 256,
            },
            1,
        ))
        .unwrap()
        .unwrap()
        .0;
        run(queue.run(&mut worker));
        assert_eq!(legacy.status(), 1);
        assert_eq!(p.read32(0x4a480), 1 << 30);
        assert_eq!(p.read32(0x49028), 0);
        assert_eq!(mode.lock().crtc_color(1).unwrap().degamma_lut, 0);
        // Legacy SET bypasses PRE while keeping POST active. Cleanup must
        // remain pending; rewriting shared color RAM here is unsafe.
        assert_eq!(p.pre_palette(), curve);
        assert_eq!(p.pre_writes(), 262);
    }
    let before_restore = p.pre_writes();
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    assert_eq!(p.pre_palette(), core::array::from_fn(|i| i as u32 + 17));
    assert_eq!(p.pre_writes(), before_restore + 131);
    run(session.restore_console()).unwrap();
    assert_eq!(p.pre_writes(), before_restore + 131);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_degamma_fifo_replacement_preserves_ctm_primary_and_blob_identity
);
fn smoke_intel_degamma_invalid_test_only_and_inherited_state_never_write() -> TestResult {
    let (p, mode, queue, mut worker, cpu, events) = fixture();
    for kind in 0..4 {
        let mut bytes = dg_bytes(false);
        match kind {
            0 => {
                bytes.pop();
            }
            1 => {
                bytes[2] = 1;
            }
            2 => {
                bytes[64 * 8..65 * 8].fill(0);
            }
            _ => {
                bytes.resize(130 * 8, 0);
            }
        };
        let id = mode.lock().create_property_blob(bytes).unwrap();
        dg_request(&cpu, id, TEST_ONLY);
        assert!(matches!(
            run(admit(
                &queue,
                7,
                drm_uapi::DRM_IOCTL_MODE_ATOMIC,
                64,
                &cpu,
                Some(&events),
                Geometry {
                    width: 64,
                    height: 32,
                    pitch: 256
                },
                1
            )),
            Err(queue::SubmitError::Io(FsError::InvalidData))
        ));
        mode.lock().destroy_property_blob(id);
    }
    let id = dg_blob(&mode, false);
    dg_request(&cpu, id, TEST_ONLY);
    assert!(run(admit(
        &queue,
        7,
        drm_uapi::DRM_IOCTL_MODE_ATOMIC,
        64,
        &cpu,
        Some(&events),
        Geometry {
            width: 64,
            height: 32,
            pitch: 256
        },
        1
    ))
    .unwrap()
    .is_none());
    assert_eq!(p.pre_writes(), 0);
    assert!(p.dsb_mappings().is_empty());
    assert!(cpu.exported.lock().is_empty());
    p.set(0x4a480, 1 << 31);
    dg_request(&cpu, id, NONBLOCK);
    let done = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert!(done.status() < 0);
    assert_eq!(p.pre_writes(), 0);
    mode.lock().intel_ctm = false;
    assert_eq!(crtc_color_properties(&mode.lock(), 1).1, vec![0, 0, 4096]);
    assert_eq!(
        crtc_color_property(
            &mode.lock(),
            1,
            CRTC_DEGAMMA_LUT_PROP_ID,
            u64::from(id),
            &mut CrtcColorChange::default()
        ),
        Err(FsError::InvalidData)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_degamma_invalid_test_only_and_inherited_state_never_write
);
fn smoke_intel_degamma_cancel_reset_master_restore_and_write_fault_retain_owner() -> TestResult {
    let (p, mode, queue, mut worker, cpu, events) = fixture();
    let original = p.pre_palette();
    let first = dg_blob(&mode, false);
    let second = dg_blob(&mode, true);
    dg_request(&cpu, first, NONBLOCK);
    let a = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(a.status(), 1);
    dg_request(&cpu, second, NONBLOCK | EVENT);
    let b = submit(&queue, &cpu, &events);
    #[cfg(target_arch = "x86_64")]
    {
        p.stall_dsb(0, true);
        let mut work = Box::pin(queue.run(&mut worker));
        assert!(work
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        drop(work);
        assert!(b.status() < 0);
        let mappings = p.dsb_mappings();
        assert!(!mappings.is_empty());
        p.poison();
        p.stall_dsb(0, false);
        run(worker.device.recover()).unwrap();
        assert_eq!(p.pre_palette(), original);
        assert_eq!(p.dsb_mappings(), mappings);
    }
    #[cfg(target_arch = "aarch64")]
    {
        run(queue.run(&mut worker));
        assert!(b.status() < 0);
    }
    mode.lock().master_release(7);
    mode.lock().master_open(8);
    dg_request(&cpu, second, NONBLOCK);
    let c = admit_as(&queue, &cpu, &events, 8);
    run(queue.run(&mut worker));
    assert_eq!(c.status(), 1);
    let confirmed = p.pre_palette();
    let mut session = run(worker.device.session()).unwrap();
    run(restore_released_master(&mut session, &mode)).unwrap();
    assert_eq!(p.pre_palette(), confirmed);
    drop(session);
    dg_request(&cpu, 0, NONBLOCK);
    let clear = admit_as(&queue, &cpu, &events, 8);
    run(queue.run(&mut worker));
    assert_eq!(clear.status(), 1);
    assert_eq!(p.pre_palette(), original);
    p.refuse_palette(true);
    dg_request(&cpu, first, NONBLOCK);
    let fault = admit_as(&queue, &cpu, &events, 8);
    run(queue.run(&mut worker));
    assert!(fault.status() < 0);
    assert_eq!(mode.lock().crtc_color(1).unwrap().degamma_lut, 0);
    assert!(run(worker.device.session()).is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_degamma_cancel_reset_master_restore_and_write_fault_retain_owner
);
