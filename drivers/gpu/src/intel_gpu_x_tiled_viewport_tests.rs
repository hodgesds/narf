// Pinned Linux b90c984d intel_compute_aligned_offset: X tiles are 512 bytes
// by eight rows. A two-column pitch distinguishes this from linear panning.
// These conversations retain the actual framebuffer/FIFO/GGTT/DSB owners.
use super::*;
use crate::intel_gpu_scanout::Viewport;

const OFFSET: u64 = 0x701a4;
const CONSOLE: u32 = 0x1000000;

pub(super) fn geometry() -> Geometry {
    Geometry {
        pitch: 1024,
        ..super::geometry()
    }
}
fn frame(mode: &ModeState, owner: u64, wc: bool) -> Result<u32, FsError> {
    use crate::intel_gpu_gem::{GemState, Placement};
    let gem = GemState::new();
    let handle = gem.create_placed(
        98304,
        None,
        if wc {
            Placement::SystemWc
        } else {
            Placement::System
        },
        |_, _| Ok(()),
    )?;
    mode.lock()
        .addfb2_intel(
            &crate::drm::fb_cmd::FbCmd {
                width: 256,
                height: 96,
                pixel_format: DRM_FORMAT_XRGB8888,
                handles: [handle, 0, 0, 0],
                pitches: [1024, 0, 0, 0],
                flags: 2,
                modifier: [X_TILED_MODIFIER, 0, 0, 0],
                ..Default::default()
            },
            gem.object(handle)?,
            owner,
            true,
        )
        .map_err(|_| FsError::InvalidData)
}
fn wc_frame(mode: &ModeState, owner: u64) -> Option<u32> {
    match frame(mode, owner, true) {
        Ok(id) => Some(id),
        Err(FsError::NotImplemented) => {
            assert!(cfg!(target_arch = "aarch64"));
            None
        }
        Err(error) => panic!("X viewport allocation: {error:?}"),
    }
}
pub(super) fn weak(
    mode: &ModeState,
    fb: u32,
) -> alloc::sync::Weak<crate::intel_gpu_gem::GemObject> {
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
pub(super) fn worker(p: &MockPlatform) -> Worker {
    p.cursor_resources();
    Worker {
        device: Arc::new(p.meteor_pitch(1024)),
    }
}
pub(super) fn request(cpu: &Cpu, fb: u32, x: u32, y: u32, flags: u32, color: Option<(u32, u32)>) {
    let mut header = [0; 56];
    header[..4].copy_from_slice(&flags.to_le_bytes());
    header[4..8].copy_from_slice(&2u32.to_le_bytes());
    for (at, address) in [
        (8, 128u64),
        (16, 144),
        (24, 160),
        (32, 256),
        (48, 0x5850414e),
    ] {
        header[at..at + 8].copy_from_slice(&address.to_le_bytes());
    }
    cpu.write(64, &header).unwrap();
    for (at, value) in [
        (128, PLANE_ID_BASE),
        (132, 1),
        (144, 4),
        (148, if color.is_some() { 3 } else { 1 }),
    ] {
        cpu.write(at, &value.to_le_bytes()).unwrap();
    }
    let mut props = vec![
        PLANE_FB_ID_PROP_ID,
        PLANE_CRTC_ID_PROP_ID,
        PLANE_SRC_X_PROP_ID,
        PLANE_SRC_Y_PROP_ID,
        CRTC_OUT_FENCE_PTR_PROP_ID,
    ];
    let mut values = vec![
        u64::from(fb),
        1,
        u64::from(x) << 16,
        u64::from(y) << 16,
        512,
    ];
    if let Some((ctm, gamma)) = color {
        props.extend([CRTC_CTM_PROP_ID, CRTC_GAMMA_LUT_PROP_ID]);
        values.extend([u64::from(ctm), u64::from(gamma)]);
    }
    for (i, value) in props.iter().enumerate() {
        cpu.write(160 + i as u64 * 4, &value.to_le_bytes()).unwrap();
    }
    for (i, value) in values.iter().enumerate() {
        cpu.write(256 + i as u64 * 8, &value.to_le_bytes()).unwrap();
    }
}
pub(super) fn admission(
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
pub(super) fn submit(queue: &queue::Queue, cpu: &Cpu, events: &Events) -> Arc<queue::Completion> {
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
        Poll::Ready(Err(error)) => panic!("X viewport admission: {error:?}"),
        _ => panic!("X viewport NONBLOCK admission waited for hardware"),
    }
}
pub(super) fn origin(mode: &ModeState) -> (u32, u32) {
    let card = mode.lock();
    (card.crtcs[0].x, card.crtcs[0].y)
}
fn set_crtc(cpu: &Cpu, mode: &ModeState, fb: u32, x: u32, y: u32) {
    let wire = {
        let card = mode.lock();
        card.mode_wire(&card.crtcs[0].mode.unwrap())
    };
    let mut bytes = [0; 104];
    for (at, value) in [
        (12, 1u32),
        (16, fb),
        (20, x),
        (24, y),
        (32, 1),
        (36, wire.clock),
        (60, wire.vrefresh),
        (64, wire.flags),
        (68, wire.r#type),
    ] {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (i, value) in [
        wire.hdisplay,
        wire.hsync_start,
        wire.hsync_end,
        wire.htotal,
        wire.hskew,
        wire.vdisplay,
        wire.vsync_start,
        wire.vsync_end,
        wire.vtotal,
        wire.vscan,
    ]
    .into_iter()
    .enumerate()
    {
        bytes[40 + i * 2..42 + i * 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[72..104].copy_from_slice(&wire.name);
    cpu.write(64, &bytes).unwrap();
}

fn smoke_intel_x_viewport_literal_bounds_and_foreground_test_only() -> TestResult {
    let x = |x, y| View {
        layout: Layout::X,
        origin: Viewport { x, y },
        input: Default::default(),
    };
    // Literal tile-column/row, residual-coordinate and selected-prefix vectors.
    for (view, expected) in [
        (x(129, 17), (0x5000, 0x10001, 0xe000)),
        (x(128, 8), (0x3000, 0, 0xa000)),
        (x(127, 7), (0, 0x7007f, 0xa000)),
        (x(3, 2), (0, 0x20003, 0xa000)),
    ] {
        assert_eq!(view.footprint(geometry()).unwrap(), expected);
    }
    assert_eq!(
        Viewport { x: 129, y: 17 }.layout(geometry()).unwrap(),
        (0x4000, 0x10081, 0xc400)
    );
    for view in [x(193, 0), x(u32::MAX, 0), x(0, 65536)] {
        assert!(view.footprint(geometry()).is_err());
    }
    assert!(x(0, 8192)
        .footprint(Geometry {
            pitch: 131072,
            ..geometry()
        })
        .is_err());
    let mode = tiled_mode();
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let wb = frame(&mode, 7, false).unwrap();
    request(&cpu, wb, 129, 17, NONBLOCK | TEST_ONLY, None);
    assert!(matches!(
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
        Err(queue::SubmitError::Io(FsError::Unsupported))
    ));
    let Some(fb) = wc_frame(&mode, 7) else {
        return TestResult::Pass;
    };
    for (x, y) in [(193, 0), (0, 65), (65535, 65535)] {
        request(&cpu, fb, x, y, NONBLOCK | TEST_ONLY, None);
        assert!(admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC).is_err());
    }
    request(&cpu, fb, 129, 17, NONBLOCK | TEST_ONLY, None);
    cpu.write(272, &((129u64 << 16) | 1).to_le_bytes()).unwrap();
    assert!(matches!(
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
        Err(queue::SubmitError::Io(FsError::InvalidData))
    ));
    let p = MockPlatform::new();
    let mut worker = worker(&p);
    request(&cpu, fb, 129, 17, NONBLOCK | TEST_ONLY, None);
    assert!(
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
            .unwrap()
            .is_none()
    );
    assert!(p.primary_mappings().is_empty() && p.primary_updates().is_empty());
    assert!(cpu.exported.lock().is_empty());
    // Strict pre-trigger refusal rolls back a staged panned mapping without
    // losing the console or leaving the otherwise usable owner quarantined.
    p.set(0x60420, 1 << 31);
    request(&cpu, fb, 129, 17, NONBLOCK | EVENT, None);
    let failed = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert!(failed.status() < 0);
    assert!(p.primary_mappings().is_empty() && p.primary_updates().is_empty());
    assert!(worker.device.legacy().is_ok());
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_x_viewport_literal_bounds_and_foreground_test_only
);

fn smoke_intel_x_viewport_joint_uapi_requires_both_native_witnesses() -> TestResult {
    let mode = tiled_mode();
    let Some(fb) = wc_frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let ctm = blob(&mode);
    let gamma = gamma_blob(&mode, false);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    request(&cpu, fb, 129, 17, NONBLOCK | EVENT, Some((ctm, gamma)));
    let done = submit(&queue, &cpu, &events);
    let fence = cpu.exported.lock()[0].clone();
    drop(cpu); // queued work has no user pointers/context
    let p = MockPlatform::new();
    let mut worker = worker(&p);
    let resources =
        [0x45230, 0x45234, 0x45008, 0x45030, 0x70240, 0x70250].map(|r| (r, p.read32(r)));
    p.allow_flips(false);
    let mut work = Box::pin(queue.run(&mut worker));
    pending(work.as_mut());
    assert_eq!(p.read32(OFFSET), 0);
    #[cfg(target_arch = "x86_64")]
    {
        let words = p.dsb_commands();
        let pos = |reg| {
            words
                .iter()
                .position(|&(_, high)| high >> 24 == 1 && high & 0xfffff == reg)
                .unwrap()
        };
        let evade = words.iter().position(|&(_, high)| high >> 24 == 6).unwrap();
        assert!(pos(STRIDE as u32) < evade && evade < pos(OFFSET as u32));
        assert!(pos(OFFSET as u32) < pos(CTL as u32) && pos(CTL as u32) < pos(SURF as u32));
        assert_eq!(words[pos(OFFSET as u32)].0, 0x10001);
        assert_eq!(words[pos(SURF as u32)].0, 0x0a005000);
        assert_eq!(words[pos(STRIDE as u32)].0, 2);
    }
    for _ in 0..10 {
        pending(work.as_mut());
    }
    assert_eq!(
        (
            p.read32(OFFSET),
            p.read32(SURF),
            p.read32(CTL),
            p.read32(STRIDE)
        ),
        (0x10001, 0x0a005000, 0x84000400, 2)
    );
    assert_eq!(p.primary_mappings().len(), 28); // fourteen padded pages
    assert_eq!(p.read32(LIVE), CONSOLE);
    assert_eq!((done.status(), fence.status()), (0, 0));
    assert_eq!(origin(&mode), (0, 0));
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    assert_eq!(resources.map(|(r, _)| (r, p.read32(r))), resources);
    p.allow_flips(true);
    run(work);
    assert_eq!((done.status(), fence.status()), (1, 1));
    assert_eq!(origin(&mode), (129, 17));
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, gamma);
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    assert_eq!(
        (
            p.read32(OFFSET),
            p.read32(CTL),
            p.read32(STRIDE),
            p.read32(LIVE)
        ),
        (0, 0x84000000, 16, CONSOLE)
    );
    assert!(p.primary_mappings().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_x_viewport_joint_uapi_requires_both_native_witnesses
);

fn smoke_intel_x_viewport_fifo_pageflip_and_same_bo_view_identity() -> TestResult {
    let mode = tiled_mode();
    let Some(a) = wc_frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let b = wc_frame(&mode, 7).unwrap();
    let old = weak(&mode, a);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    request(&cpu, a, 129, 17, NONBLOCK, None);
    let first = submit(&queue, &cpu, &events);
    let mut bytes = [0; 24];
    for (at, value) in [(0, 1u32), (4, b), (8, EVENT)] {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
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
    p.allow_flips(false);
    for _ in 0..6 {
        pending(work.as_mut());
    }
    assert_eq!(p.primary_mappings().len(), 56);
    assert_eq!(origin(&mode), (129, 17));
    assert_eq!(p.read32(OFFSET), 0x10001);
    assert_eq!(second.status(), 0);
    p.allow_flips(true);
    run(work);
    assert_eq!(second.status(), 1);
    assert_eq!(p.primary_mappings().len(), 28);
    mode.lock().rmfb(a).unwrap();
    assert!(old.upgrade().is_none());
    let live = p.read32(LIVE);
    request(&cpu, b, 127, 7, NONBLOCK, None);
    let changed = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(changed.status(), 1);
    assert_ne!(
        p.read32(LIVE),
        live,
        "same BO with different tile origin owns a different window"
    );
    assert_eq!(p.read32(OFFSET), 0x7007f);
    assert_eq!(p.primary_mappings().len(), 20);
    assert_eq!(origin(&mode), (127, 7));
    set_crtc(&cpu, &mode, b, 128, 8);
    let (legacy, _, nonblock) =
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_SETCRTC)
            .unwrap()
            .unwrap();
    assert!(!nonblock);
    run(queue.run(&mut worker));
    assert_eq!(legacy.status(), 1);
    assert_eq!(origin(&mode), (128, 8));
    assert_eq!(p.read32(OFFSET), 0);
    let first_pte = p.primary_mappings()[0].0;
    let mapping_base = (first_pte - crate::intel_gpu_gtt::GGTT_ARRAY_BASE) / 8 * 4096;
    assert_eq!(u64::from(p.read32(LIVE)), mapping_base + 0x3000);
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_x_viewport_fifo_pageflip_and_same_bo_view_identity
);

fn smoke_intel_x_viewport_cancel_reset_and_replacement_master_keep_dma_owned() -> TestResult {
    let mode = tiled_mode();
    let Some(a) = wc_frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let old = weak(&mode, a);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let p = MockPlatform::new();
    let mut worker = worker(&p);
    request(&cpu, a, 129, 17, NONBLOCK | EVENT, None);
    let failed = submit(&queue, &cpu, &events);
    p.allow_flips(false);
    let mut work = Box::pin(queue.run(&mut worker));
    pending(work.as_mut());
    pending(work.as_mut());
    assert_eq!(p.read32(OFFSET), 0x10001);
    drop(work);
    assert!(failed.status() < 0);
    mode.lock().release_file_framebuffers(7);
    assert!(old.upgrade().is_some());
    let mappings = p.primary_mappings();
    let commands = p.dsb_mappings();
    let writes = p.primary_updates();
    assert!(!mappings.is_empty());
    let other = wc_frame(&mode, 7).unwrap();
    request(&cpu, other, 3, 2, NONBLOCK, None);
    let refused = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert!(
        refused.status() < 0,
        "unpublished panned state stays quarantined"
    );
    assert_eq!(p.primary_mappings(), mappings);
    assert_eq!(p.primary_updates(), writes);
    p.stall_dsb(0, true);
    p.poison();
    let mut recovery = Box::pin(worker.device.recover());
    for _ in 0..3 {
        pending(recovery.as_mut());
    }
    assert_eq!(p.primary_mappings(), mappings);
    assert_eq!(p.primary_updates(), writes);
    drop(recovery);
    p.stall_dsb(0, false);
    p.allow_flips(true);
    run(worker.device.recover()).unwrap();
    assert_eq!(
        (
            p.read32(OFFSET),
            p.read32(CTL),
            p.read32(STRIDE),
            p.read32(LIVE)
        ),
        (0, 0x84000000, 16, CONSOLE)
    );
    assert!(p.primary_mappings().is_empty() && old.upgrade().is_none());
    assert_eq!(p.dsb_mappings(), commands);
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    let a = wc_frame(&mode, 7).unwrap();
    request(&cpu, a, 129, 17, NONBLOCK, None);
    let restored = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(restored.status(), 1);
    mode.lock().master_release(7);
    mode.lock().master_open(8);
    let b = wc_frame(&mode, 8).unwrap();
    request(&cpu, b, 3, 2, NONBLOCK, None);
    let replaced = admission(&queue, &cpu, &events, 8, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
        .unwrap()
        .unwrap()
        .0;
    run(queue.run(&mut worker));
    assert_eq!(replaced.status(), 1);
    assert_eq!((origin(&mode), p.read32(OFFSET)), ((3, 2), 0x20003));
    let live = p.read32(LIVE);
    let mut session = run(worker.device.session()).unwrap();
    run(restore_released_master(&mut session, &mode)).unwrap();
    assert_eq!((p.read32(LIVE), p.read32(OFFSET)), (live, 0x20003));
    run(session.restore_console()).unwrap();
    assert_eq!(p.read32(OFFSET), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_x_viewport_cancel_reset_and_replacement_master_keep_dma_owned
);
