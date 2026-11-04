// Real ADDFB2/atomic/FIFO/DSB/PollIo conversations. Pinned Linux b90c984d:
// intel_fb tile geometry, intel_dpt_common no-DPT, skl_plane_update_* and WMs.
use super::*;
use crate::intel_gpu_scanout::{Layout, View, X_TILED_MODIFIER};

const CTL: u64 = 0x70180;
const STRIDE: u64 = 0x70188;
const SURF: u64 = 0x7019c;
const LIVE: u64 = 0x701ac;
fn geometry() -> Geometry {
    Geometry {
        width: 64,
        height: 32,
        pitch: 512,
    }
}
fn tiled_mode() -> ModeState {
    let mode = color_mode();
    mode.lock().intel_x_tiled = true;
    mode
}
fn frame(mode: &ModeState, owner: u64, tiled: bool, wc: bool) -> Result<u32, FsError> {
    let gem = crate::intel_gpu_gem::GemState::new();
    let handle = gem.create_placed(
        16384,
        None,
        if wc {
            crate::intel_gpu_gem::Placement::SystemWc
        } else {
            crate::intel_gpu_gem::Placement::System
        },
        |_, _| Ok(()),
    )?;
    mode.lock()
        .addfb2_intel(
            &crate::drm::fb_cmd::FbCmd {
                width: 128,
                height: 32,
                pixel_format: DRM_FORMAT_XRGB8888,
                handles: [handle, 0, 0, 0],
                pitches: [512, 0, 0, 0],
                flags: 2,
                modifier: [if tiled { X_TILED_MODIFIER } else { 0 }, 0, 0, 0],
                ..Default::default()
            },
            gem.object(handle)?,
            owner,
            true,
        )
        .map_err(|_| FsError::InvalidData)
}
fn wc_frame(mode: &ModeState, owner: u64, tiled: bool) -> Option<u32> {
    match frame(mode, owner, tiled, true) {
        Ok(id) => Some(id),
        Err(FsError::NotImplemented) => {
            assert!(cfg!(target_arch = "aarch64"));
            None
        }
        Err(error) => panic!("tiled framebuffer allocation: {error:?}"),
    }
}
fn worker(p: &MockPlatform) -> Worker {
    p.cursor_resources(); // actual off-pipe resource/no-DPT initialization
    Worker {
        device: Arc::new(p.meteor_pitch(512)),
    }
}
fn request(cpu: &Cpu, fb: u32, flags: u32, color: Option<(u32, u32)>) {
    let mut header = [0; 56];
    header[..4].copy_from_slice(&flags.to_le_bytes());
    header[4..8].copy_from_slice(&2u32.to_le_bytes());
    for (at, value) in [(8, 128u64), (16, 144), (24, 160), (32, 256)] {
        header[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    header[48..56].copy_from_slice(&0x5854494cu64.to_le_bytes());
    cpu.write(64, &header).unwrap();
    cpu.write(128, &PLANE_ID_BASE.to_le_bytes()).unwrap();
    cpu.write(132, &1u32.to_le_bytes()).unwrap();
    cpu.write(144, &2u32.to_le_bytes()).unwrap();
    cpu.write(148, &(if color.is_some() { 3u32 } else { 1 }).to_le_bytes())
        .unwrap();
    let mut props = vec![
        PLANE_FB_ID_PROP_ID,
        PLANE_CRTC_ID_PROP_ID,
        CRTC_OUT_FENCE_PTR_PROP_ID,
    ];
    let mut values = vec![u64::from(fb), 1, 512];
    if let Some((ctm, gamma)) = color {
        props.extend([CRTC_CTM_PROP_ID, CRTC_GAMMA_LUT_PROP_ID]);
        values.extend([u64::from(ctm), u64::from(gamma)]);
    }
    for (i, p) in props.into_iter().enumerate() {
        cpu.write(160 + i as u64 * 4, &p.to_le_bytes()).unwrap();
    }
    for (i, v) in values.into_iter().enumerate() {
        cpu.write(256 + i as u64 * 8, &v.to_le_bytes()).unwrap();
    }
}
fn admission(
    queue: &queue::Queue,
    cpu: &Cpu,
    events: &Events,
    open: u64,
    cmd: u32,
) -> Result<queue::Submitted, queue::SubmitError> {
    run(admit(
        queue,
        open,
        cmd,
        64,
        cpu,
        Some(events),
        geometry(),
        1,
    ))
}
fn submit(queue: &queue::Queue, cpu: &Cpu, events: &Events) -> Arc<queue::Completion> {
    let mut future = Box::pin(admit(
        queue,
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
        Poll::Ready(Ok(Some((completion, _, true)))) => completion,
        Poll::Ready(Err(error)) => panic!("X foreground refusal: {error:?}"),
        _ => panic!("X NONBLOCK admission did not return immediately"),
    }
}
fn pending<F: Future>(future: core::pin::Pin<&mut F>) {
    assert!(future
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
}

fn smoke_intel_x_tiled_uapi_common_arm_and_both_hardware_witnesses() -> TestResult {
    let mode = tiled_mode();
    let Some(fb) = wc_frame(&mode, 7, true) else {
        return TestResult::Pass;
    };
    let ctm = blob(&mode);
    let gamma = gamma_blob(&mode, false);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    request(&cpu, fb, NONBLOCK | EVENT, Some((ctm, gamma)));
    let complete = submit(&queue, &cpu, &events);
    let fence = cpu.exported.lock()[0].clone();
    let p = MockPlatform::new();
    let mut worker = worker(&p);
    assert_eq!(p.read32(0x7026c) & (1 << 19), 1 << 19);
    p.allow_flips(false);
    let mut work = Box::pin(queue.run(&mut worker));
    pending(work.as_mut());
    assert_eq!(p.read32(CTL), 0x84000000);
    #[cfg(target_arch = "x86_64")]
    {
        let words = p.dsb_commands();
        let pos = |reg: u32| {
            words
                .iter()
                .position(|&(_, h)| h >> 24 == 1 && h & 0xfffff == reg)
                .unwrap()
        };
        let evade = words.iter().position(|&(_, h)| h >> 24 == 6).unwrap();
        assert!(pos(0x70188) < evade);
        assert!(evade < pos(0x701a4) && pos(0x701a4) < pos(0x70180) && pos(0x70180) < pos(0x7019c));
        assert_eq!(words[pos(0x70188)].0, 1);
        assert_eq!(words[pos(0x70180)].0, 0x84000400);
    }
    for _ in 0..8 {
        pending(work.as_mut());
    }
    assert_eq!(p.read32(CTL), 0x84000400);
    assert_eq!(p.read32(STRIDE), 1);
    assert_eq!(p.read32(LIVE), 0x1000000);
    assert_eq!((complete.status(), fence.status()), (0, 0));
    assert!(mode.lock().crtcs[0].primary_fb.is_none());
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    p.allow_flips(true);
    run(work);
    assert_eq!((complete.status(), fence.status()), (1, 1));
    assert_eq!(mode.lock().crtcs[0].primary_fb, Some(fb));
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, gamma);
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    assert_eq!(
        (p.read32(CTL), p.read32(STRIDE), p.read32(LIVE)),
        (0x84000000, 8, 0x1000000)
    );
    assert!(p.primary_mappings().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_x_tiled_uapi_common_arm_and_both_hardware_witnesses
);

fn smoke_intel_x_tiled_fifo_pageflip_returns_linear_and_retires_old_window() -> TestResult {
    let mode = tiled_mode();
    let Some(a) = wc_frame(&mode, 7, true) else {
        return TestResult::Pass;
    };
    let b = wc_frame(&mode, 7, false).unwrap();
    let old = Arc::downgrade(
        &mode
            .lock()
            .framebuffer(a)
            .unwrap()
            .intel
            .as_ref()
            .unwrap()
            .object,
    );
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    request(&cpu, a, NONBLOCK, None);
    let first = submit(&queue, &cpu, &events);
    let mut bytes = [0; 24];
    for (at, v) in [(0, 1u32), (4, b), (8, EVENT)] {
        bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    cpu.write(64, &bytes).unwrap();
    let (second, _, nonblock) =
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_PAGE_FLIP)
            .unwrap()
            .unwrap();
    assert!(!nonblock);
    let p = MockPlatform::new();
    let mut worker = worker(&p);
    let mut work = Box::pin(queue.run(&mut worker));
    for _ in 0..16 {
        pending(work.as_mut());
        if first.status() == 1 {
            break;
        }
    }
    assert_eq!(first.status(), 1);
    assert_eq!(second.status(), 0);
    let both = p.primary_mappings();
    assert_eq!(both.len(), 16);
    p.allow_flips(false);
    for _ in 0..6 {
        pending(work.as_mut());
    }
    assert_eq!(p.primary_mappings(), both);
    assert_eq!(second.status(), 0);
    p.allow_flips(true);
    run(work);
    assert_eq!(second.status(), 1);
    assert_eq!((p.read32(CTL), p.read32(STRIDE)), (0x84000000, 8));
    assert_eq!(p.primary_mappings().len(), 8);
    mode.lock().rmfb(a).unwrap();
    assert!(old.upgrade().is_none());
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_x_tiled_fifo_pageflip_returns_linear_and_retires_old_window
);

fn smoke_intel_x_tiled_layout_extent_metadata_test_only_and_arch_refusal() -> TestResult {
    let mode = tiled_mode();
    let capability = Cpu::new();
    capability.write(64, &0x10u64.to_le_bytes()).unwrap();
    capability.write(72, &u64::MAX.to_le_bytes()).unwrap();
    assert_eq!(
        intel_modifiers_cap(&mode, drm_uapi::DRM_IOCTL_GET_CAP, 64, &capability),
        Some(Ok(0))
    );
    assert_eq!(&capability.bytes.lock()[72..80], &1u64.to_le_bytes());
    assert_eq!(
        intel_modifiers_cap(&mode, drm_uapi::DRM_IOCTL_GET_CAP, u64::MAX, &capability),
        Some(Err(FsError::BadAddress))
    );
    capability.bad_write.store(true, Ordering::Release);
    assert_eq!(
        intel_modifiers_cap(&mode, drm_uapi::DRM_IOCTL_GET_CAP, 64, &capability),
        Some(Err(FsError::BadAddress))
    );
    capability.bad_write.store(false, Ordering::Release);
    capability.write(64, &0x13u64.to_le_bytes()).unwrap();
    assert_eq!(
        intel_modifiers_cap(&mode, drm_uapi::DRM_IOCTL_GET_CAP, 64, &capability),
        None
    );
    let info = intel_primary_formats_blob(&mode.lock(), INTEL_PRIMARY_FORMATS_BLOB).unwrap();
    assert_eq!(info.len(), 80);
    assert_eq!(&info[24..28], &DRM_FORMAT_XRGB8888.to_le_bytes());
    assert_eq!(&info[72..80], &0x0100000000000001u64.to_le_bytes());
    mode.lock().intel_x_tiled = false;
    assert_eq!(
        intel_modifiers_cap(&mode, drm_uapi::DRM_IOCTL_GET_CAP, u64::MAX, &capability),
        None
    );
    assert_eq!(crate::drm::ioctl::cap_value(0x10), Some(0));
    assert!(intel_primary_formats_blob(&mode.lock(), INTEL_PRIMARY_FORMATS_BLOB).is_none());
    assert!(frame(&mode, 7, true, false).is_err());
    mode.lock().intel_x_tiled = true;
    let view = View {
        layout: Layout::X,
        origin: Default::default(),
        input: Default::default(),
    };
    assert_eq!(
        view.footprint(Geometry {
            height: 33,
            ..geometry()
        })
        .unwrap(),
        (0, 0, 20480)
    );
    for bad in [
        Geometry {
            pitch: 576,
            ..geometry()
        },
        Geometry {
            width: 5121,
            pitch: 20992,
            ..geometry()
        },
        Geometry {
            height: 4321,
            ..geometry()
        },
    ] {
        assert!(view.footprint(bad).is_err());
    }
    assert_eq!(
        View {
            origin: crate::intel_gpu_scanout::Viewport { x: 1, y: 0 },
            ..view
        }
        .footprint(geometry())
        .unwrap(),
        (0, 1, 16384)
    );
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let wb = frame(&mode, 7, true, false).unwrap();
    request(&cpu, wb, NONBLOCK | TEST_ONLY, None);
    let object = mode
        .lock()
        .framebuffer(wb)
        .unwrap()
        .intel
        .as_ref()
        .unwrap()
        .object
        .clone();
    let mut cmd = crate::drm::fb_cmd::FbCmd {
        width: 128,
        height: 33,
        pixel_format: DRM_FORMAT_XRGB8888,
        handles: [1, 0, 0, 0],
        pitches: [512, 0, 0, 0],
        flags: 2,
        modifier: [X_TILED_MODIFIER, 0, 0, 0],
        ..Default::default()
    };
    assert_eq!(
        mode.lock().addfb2_intel(&cmd, object.clone(), 7, true),
        Err(crate::drm::card::CardError::InvalidDimensions)
    );
    cmd.height = 32;
    cmd.offsets[0] = 4;
    assert!(mode
        .lock()
        .addfb2_intel(&cmd, object.clone(), 7, true)
        .is_err());
    cmd.offsets[0] = 0;
    cmd.modifier[0] = 0x0100000000000002;
    assert!(mode.lock().addfb2_intel(&cmd, object, 7, true).is_err());
    assert!(matches!(
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
        Err(queue::SubmitError::Io(FsError::Unsupported))
    ));
    let Some(fb) = wc_frame(&mode, 7, true) else {
        return TestResult::Pass;
    };
    request(&cpu, fb, NONBLOCK | TEST_ONLY, None);
    assert!(
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
            .unwrap()
            .is_none()
    );
    assert!(cpu.exported.lock().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_x_tiled_layout_extent_metadata_test_only_and_arch_refusal
);

fn smoke_intel_x_tiled_live_nodpt_resource_loss_refuses_before_dma() -> TestResult {
    for loss in [0, u32::MAX] {
        let mode = tiled_mode();
        let Some(fb) = wc_frame(&mode, 7, true) else {
            return TestResult::Pass;
        };
        let queue = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        request(&cpu, fb, NONBLOCK | EVENT, None);
        let done = submit(&queue, &cpu, &events);
        let p = MockPlatform::new();
        let mut worker = worker(&p);
        p.set(0x7026c, loss);
        run(queue.run(&mut worker));
        assert!(done.status() < 0);
        assert!(p.primary_mappings().is_empty());
        assert!(p.dsb_mappings().is_empty());
        assert_eq!(p.read32(SURF), 0x1000000);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_x_tiled_live_nodpt_resource_loss_refuses_before_dma
);

fn smoke_intel_x_tiled_cancel_partial_arm_reset_and_master_handoff_retain_owners() -> TestResult {
    for dropped in [u64::MAX, CTL, STRIDE] {
        let mode = tiled_mode();
        let Some(fb) = wc_frame(&mode, 7, true) else {
            return TestResult::Pass;
        };
        let queue = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        request(&cpu, fb, NONBLOCK | EVENT, None);
        let done = submit(&queue, &cpu, &events);
        let p = MockPlatform::new();
        let mut worker = worker(&p);
        p.allow_flips(false);
        p.refuse_layout(dropped);
        let mut work = Box::pin(queue.run(&mut worker));
        pending(work.as_mut());
        pending(work.as_mut());
        assert!(!p.primary_mappings().is_empty());
        drop(work);
        assert!(done.status() < 0);
        let retained = p.primary_mappings();
        let dsb = p.dsb_mappings();
        assert!(worker.device.legacy().is_err());
        assert_eq!(p.primary_mappings(), retained);
        p.refuse_layout(u64::MAX);
        p.allow_flips(true);
        p.poison();
        run(worker.device.recover()).unwrap();
        assert_eq!(
            (p.read32(CTL), p.read32(STRIDE), p.read32(LIVE)),
            (0x84000000, 8, 0x1000000)
        );
        assert!(p.primary_mappings().is_empty());
        assert_eq!(p.dsb_mappings(), dsb);
        request(&cpu, fb, NONBLOCK, None);
        let next = submit(&queue, &cpu, &events);
        run(queue.run(&mut worker));
        assert_eq!(next.status(), 1);
        mode.lock().master_release(7);
        mode.lock().master_open(8);
        let b = wc_frame(&mode, 8, true).unwrap();
        request(&cpu, b, NONBLOCK, None);
        let replaced = admission(&queue, &cpu, &events, 8, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
            .unwrap()
            .unwrap()
            .0;
        run(queue.run(&mut worker));
        assert_eq!(replaced.status(), 1);
        assert_eq!(p.read32(CTL), 0x84000400);
        let live = p.read32(LIVE);
        let mut session = run(worker.device.session()).unwrap();
        run(restore_released_master(&mut session, &mode)).unwrap();
        assert_eq!(p.read32(LIVE), live);
        assert_eq!(p.read32(CTL), 0x84000400);
        run(session.restore_console()).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_x_tiled_cancel_partial_arm_reset_and_master_handoff_retain_owners
);

mod panning {
    include!("intel_gpu_x_tiled_viewport_tests.rs");
}
mod tile4 {
    include!("intel_gpu_tile4_ioctl_tests.rs");
}
