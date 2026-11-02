// Raw DRM admission -> actual FIFO -> Gen12 route/resource/PTE owner and
// PollIo primary latch. No backend present override or MTL display gate.
use super::*;
use crate::intel_gpu_gt::Gen12Platform;
const CONSOLE: u32 = 0x1000000;
const SURF: u64 = 0x7019c;
const LIVE: u64 = 0x701ac;
const CONSOLE_PTE: u64 = crate::intel_gpu_gtt::GGTT_ARRAY_BASE + 0x1000000 / 4096 * 8;
fn geometry() -> Geometry {
    Geometry {
        width: 64,
        height: 32,
        pitch: 256,
    }
}
fn mode() -> ModeState {
    let state = super::super::mode();
    state.lock().intel_display = true;
    state
}
fn frame(mode: &ModeState, owner: u64) -> Option<u32> {
    use crate::intel_gpu_gem::{GemState, Placement};
    let gem = GemState::new();
    let h = match gem.create_placed(8192, None, Placement::SystemWc, |_, _| Ok(())) {
        Ok(h) => h,
        Err(FsError::NotImplemented) => {
            assert!(cfg!(target_arch = "aarch64"));
            return None;
        }
        Err(error) => panic!("Gen12 WC framebuffer: {error:?}"),
    };
    Some(
        mode.lock()
            .addfb2_intel(
                &crate::drm::fb_cmd::FbCmd {
                    width: 64,
                    height: 32,
                    pixel_format: DRM_FORMAT_XRGB8888,
                    handles: [h, 0, 0, 0],
                    pitches: [256, 0, 0, 0],
                    ..Default::default()
                },
                gem.object(h).unwrap(),
                owner,
                true,
            )
            .unwrap(),
    )
}
fn weak(mode: &ModeState, fb: u32) -> alloc::sync::Weak<crate::intel_gpu_gem::GemObject> {
    Arc::downgrade(
        &mode
            .lock()
            .framebuffer(fb)
            .unwrap()
            .intel
            .as_ref()
            .unwrap()
            .object,
    )
}
fn request(cpu: &Cpu, fb: u32, flags: u32) {
    let mut bytes = [0; 56];
    bytes[..4].copy_from_slice(&flags.to_le_bytes());
    bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
    for (at, ptr) in [
        (8, 128u64),
        (16, 144),
        (24, 160),
        (32, 256),
        (48, 0x12345678),
    ] {
        bytes[at..at + 8].copy_from_slice(&ptr.to_le_bytes());
    }
    cpu.write(64, &bytes).unwrap();
    for (at, v) in [
        (128, PLANE_ID_BASE),
        (132, 1),
        (144, 2),
        (148, 1),
        (160, PLANE_FB_ID_PROP_ID),
        (164, PLANE_CRTC_ID_PROP_ID),
        (168, CRTC_OUT_FENCE_PTR_PROP_ID),
    ] {
        cpu.write(at, &v.to_le_bytes()).unwrap();
    }
    for (at, v) in [(256, u64::from(fb)), (264, 1), (272, 512)] {
        cpu.write(at, &v.to_le_bytes()).unwrap();
    }
}
fn admission(
    q: &queue::Queue,
    cpu: &Cpu,
    events: &Events,
    open: u64,
    cmd: u32,
) -> Result<queue::Submitted, queue::SubmitError> {
    run(admit(q, open, cmd, 64, cpu, Some(events), geometry(), 1))
}
fn submit(q: &queue::Queue, cpu: &Cpu, events: &Events) -> Arc<queue::Completion> {
    let mut future = Box::pin(admit(
        q,
        7,
        drm_uapi::DRM_IOCTL_MODE_ATOMIC,
        64,
        cpu,
        Some(events),
        geometry(),
        1,
    ));
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(Some((done, _, true)))) => done,
        Poll::Ready(Err(error)) => panic!("Gen12 raw admission: {error:?}"),
        _ => panic!("Gen12 NONBLOCK foreground waited for hardware"),
    }
}
fn pending<F: Future>(future: core::pin::Pin<&mut F>) {
    assert!(future
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
}
fn mapped_pages(words: &[(u64, u32)]) -> usize {
    // The model omits zero dwords. PAT-free Gen12 PTEs below4GiB have
    // no stored high half, so count present low halves instead of words.
    words
        .iter()
        .filter(|(register, value)| register % 8 == 0 && value & 1 != 0)
        .count()
}
fn families() -> [Gen12Platform; 4] {
    [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeS,
        Gen12Platform::AlderLakeN,
    ]
}

fn smoke_intel_gen12_fixed_primary_raw_fifo_native_latch_and_cache_format() -> TestResult {
    for family in families() {
        let mode = mode();
        {
            let card = mode.lock();
            assert!(!card.intel_ctm && !card.intel_x_tiled && !card.intel_tile4);
        }
        let Some(fb) = frame(&mode, 7) else {
            return TestResult::Pass;
        };
        let q = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let p = MockPlatform::new();
        let mut worker = Worker {
            device: Arc::new(p.gen12(family)),
        };
        // Gen12 system GGTT does not consume MTL's PAT register/index bits.
        p.set(0x4804, u32::MAX);
        request(&cpu, fb, NONBLOCK | TEST_ONLY);
        assert!(
            admission(&q, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
                .unwrap()
                .is_none()
        );
        assert!(p.primary_mappings().is_empty() && cpu.exported.lock().is_empty());
        request(&cpu, fb, NONBLOCK | EVENT);
        let done = submit(&q, &cpu, &events);
        let fence = cpu.exported.lock()[0].clone();
        p.allow_flips(false);
        let mut work = Box::pin(q.run(&mut worker));
        pending(work.as_mut());
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert_eq!((done.status(), fence.status()), (0, 0));
        assert_eq!(mode.lock().crtcs[0].primary_fb, None);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        let mappings = p.primary_mappings();
        assert_eq!(mapped_pages(&mappings), 2);
        for &(register, pte) in &mappings {
            if register % 8 == 0 {
                assert_eq!(pte & 0xfff, 1);
                // Read even an omitted zero high half. Gen12 has a39-bit
                // address and no display PAT fields in bits52/53.
                assert_eq!(p.read32(register + 4) & !0x7f, 0);
            }
        }
        assert!(p.dsb_mappings().is_empty());
        p.allow_flips(true);
        run(work);
        assert_eq!((done.status(), fence.status()), (1, 1));
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(fb));
        let mut session = run(worker.device.session()).unwrap();
        run(session.restore_console()).unwrap();
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert!(p.primary_mappings().is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gen12_fixed_primary_raw_fifo_native_latch_and_cache_format
);

fn smoke_intel_gen12_fixed_primary_refuses_foreign_route_resources_and_console_pte() -> TestResult {
    for (r, value) in [
        (0x60400, 0x92000006),
        (0x60400, 0x88000006),
        (0xc7200, 0),
        (0x45008, 0),
        (0x70240, u32::MAX),
        (0x7027c, 2048 << 16),
        (0x71008, 0xc0000000),
        (0x68180, 1 << 31),
        (0x4438c, 1 << 31),
        (CONSOLE_PTE, 0x100003),
        (0x70180, 0x84000001),
        (0x70180, 0x84008000),
        (0x70180, 0x84800000),
        (0x701c8, 1 << 31),
    ] {
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
        p.set(r, value);
        request(&cpu, fb, NONBLOCK | EVENT);
        let rejected = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert!(
            rejected.status() < 0,
            "foreign register {r:#x} was accepted"
        );
        assert!(p.primary_mappings().is_empty());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        assert_eq!(p.read32(LIVE), CONSOLE);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gen12_fixed_primary_refuses_foreign_route_resources_and_console_pte
);

fn smoke_intel_gen12_primary_cancel_master_close_and_projected_pageflip_keep_pages() -> TestResult {
    let mode = mode();
    let Some(a) = frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let old = weak(&mode, a);
    let q = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let p = MockPlatform::new();
    let mut worker = Worker {
        device: Arc::new(p.gen12(Gen12Platform::TigerLake)),
    };
    request(&cpu, a, NONBLOCK | EVENT);
    let abandoned = submit(&q, &cpu, &events);
    p.allow_flips(false);
    let mut work = Box::pin(q.run(&mut worker));
    pending(work.as_mut());
    drop(work);
    assert!(abandoned.status() < 0);
    let retained = p.primary_mappings();
    mode.lock().release_file_framebuffers(7);
    mode.lock().master_release(7);
    mode.lock().master_open(8);
    assert!(old.upgrade().is_some());
    let b = frame(&mode, 8).unwrap();
    let c = frame(&mode, 8).unwrap();
    request(&cpu, b, NONBLOCK);
    let replacement = admission(&q, &cpu, &events, 8, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
        .unwrap()
        .unwrap()
        .0;
    let mut bytes = [0; 24];
    for (at, v) in [(0, 1u32), (4, c), (8, EVENT)] {
        bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    cpu.write(64, &bytes).unwrap();
    let last = admission(&q, &cpu, &events, 8, drm_uapi::DRM_IOCTL_MODE_PAGE_FLIP)
        .unwrap()
        .unwrap()
        .0;
    let mut work = Box::pin(q.run(&mut worker));
    for _ in 0..3 {
        pending(work.as_mut());
    }
    assert_eq!(replacement.status(), 0);
    assert_eq!(p.primary_mappings(), retained);
    p.allow_flips(true);
    run(work);
    assert_eq!((replacement.status(), last.status()), (1, 1));
    assert!(old.upgrade().is_none());
    assert_eq!(mode.lock().crtcs[0].primary_fb, Some(c));
    let live = p.read32(LIVE);
    let mut session = run(worker.device.session()).unwrap();
    run(restore_released_master(&mut session, &mode)).unwrap();
    assert_eq!(
        p.read32(LIVE),
        live,
        "stale close must preserve the new master"
    );
    run(session.restore_console()).unwrap();
    assert_eq!(p.read32(LIVE), CONSOLE);
    assert!(p.primary_mappings().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gen12_primary_cancel_master_close_and_projected_pageflip_keep_pages
);

fn smoke_intel_gen12_primary_resource_loss_and_reset_retain_until_original_console_proof(
) -> TestResult {
    let mode = mode();
    let Some(a) = frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let b = frame(&mode, 7).unwrap();
    let old = weak(&mode, a);
    let new = weak(&mode, b);
    let q = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let p = MockPlatform::new();
    let mut worker = Worker {
        device: Arc::new(p.gen12(Gen12Platform::AlderLakeP)),
    };
    request(&cpu, a, NONBLOCK);
    let first = submit(&q, &cpu, &events);
    run(q.run(&mut worker));
    assert_eq!(first.status(), 1);
    let old_surface = p.read32(LIVE);
    assert_eq!(p.read32(SURF), old_surface);
    assert_ne!(old_surface, CONSOLE);
    request(&cpu, b, NONBLOCK | EVENT);
    let failed = submit(&q, &cpu, &events);
    p.allow_flips(false);
    let mut work = Box::pin(q.run(&mut worker));
    // Advance through any prior-frame/status wait to the actual second arm.
    // A single Pending does not prove that its new mappings were published.
    for _ in 0..8 {
        pending(work.as_mut());
        if p.read32(SURF) != p.read32(LIVE) {
            break;
        }
    }
    assert_ne!(p.read32(SURF), p.read32(LIVE));
    assert_ne!(p.read32(SURF), CONSOLE);
    assert_eq!(p.read32(LIVE), old_surface);
    assert_eq!(failed.status(), 0);
    let retained = p.primary_mappings();
    assert_eq!(mapped_pages(&retained), 4);
    let watermark = p.read32(0x70240);
    p.set(0x70240, watermark ^ 1);
    p.allow_flips(true);
    run(work);
    assert!(failed.status() < 0);
    assert_eq!(p.primary_mappings(), retained);
    mode.lock().release_file_framebuffers(7);
    assert!(old.upgrade().is_some() && new.upgrade().is_some());
    p.poison();
    assert!(run(worker.device.recover()).is_err());
    assert_eq!(p.primary_mappings(), retained);
    p.set(0x70240, watermark);
    // Even a corrected route/WM image is not proof of original console RAM.
    p.set(CONSOLE_PTE + 8, 0x101003);
    assert!(run(worker.device.recover()).is_err());
    assert_eq!(p.primary_mappings(), retained);
    p.set(CONSOLE_PTE + 8, 0x101001);
    run(worker.device.recover()).unwrap();
    assert_eq!(p.read32(LIVE), CONSOLE);
    assert!(p.primary_mappings().is_empty());
    assert!(old.upgrade().is_none() && new.upgrade().is_none());
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    assert!(worker.device.legacy().is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gen12_primary_resource_loss_and_reset_retain_until_original_console_proof
);
