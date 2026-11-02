//! Real atomic/legacy entry decoding, FIFO projection, GGTT and DSB execution.
//! The native PCI model executes retained command pages; it does not supply
//! fabricated primary completion or bypass production WC admission.
use super::*;
use crate::intel_gpu_color::{GAMMA, MODE};
use core::pin::Pin;

const OFFSET: u64 = 0x701a4;
const SURF: u64 = 0x7019c;
const LIVE: u64 = 0x701ac;
const CONSOLE: u32 = 0x1000000;

fn geometry() -> Geometry {
    Geometry {
        width: 64,
        height: 32,
        pitch: 512,
    }
}
fn origin(mode: &ModeState) -> (u32, u32) {
    let card = mode.lock();
    (card.crtcs[0].x, card.crtcs[0].y)
}
fn frame(mode: &ModeState, owner: u64, wc: bool) -> Result<u32, FsError> {
    use crate::intel_gpu_gem::{GemState, Placement};
    let gem = GemState::new();
    let handle = gem.create_placed(
        512 * 96,
        None,
        if wc {
            Placement::SystemWc
        } else {
            Placement::System
        },
        |_, _| Ok(()),
    )?;
    let object = gem.object(handle)?;
    let command = crate::drm::fb_cmd::FbCmd {
        width: 128,
        height: 96,
        pixel_format: DRM_FORMAT_XRGB8888,
        handles: [handle, 0, 0, 0],
        pitches: [512, 0, 0, 0],
        ..Default::default()
    };
    mode.lock()
        .addfb2_intel(&command, object, owner, true)
        .map_err(|_| FsError::InvalidData)
}
fn wc_frame(mode: &ModeState, owner: u64) -> Option<u32> {
    match frame(mode, owner, true) {
        Ok(id) => Some(id),
        Err(FsError::NotImplemented) => {
            assert!(cfg!(target_arch = "aarch64"));
            None
        }
        Err(error) => panic!("viewport WC framebuffer failed: {error:?}"),
    }
}
fn weak(mode: &ModeState, id: u32) -> alloc::sync::Weak<crate::intel_gpu_gem::GemObject> {
    Arc::downgrade(
        &mode
            .lock()
            .framebuffer(id)
            .unwrap()
            .intel
            .as_ref()
            .unwrap()
            .object,
    )
}
fn source_request(cpu: &Cpu, fb: u32, x: u32, y: u32, flags: u32, color: Option<(u32, u32)>) {
    let mut header = [0; 56];
    header[..4].copy_from_slice(&flags.to_le_bytes());
    header[4..8].copy_from_slice(&2u32.to_le_bytes());
    for (at, address) in [
        (8, 128u64),
        (16, 144),
        (24, 160),
        (32, 256),
        (48, 0xabcddcba),
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
        _ => panic!("viewport NONBLOCK admission waited for hardware"),
    }
}
fn pending<F: Future>(future: Pin<&mut F>) {
    assert!(future
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
}
fn worker(platform: &MockPlatform) -> Worker {
    platform.dsb_timing();
    Worker {
        device: Arc::new(platform.meteor_pitch(512)),
    }
}
fn page_flip(cpu: &Cpu, id: u32) {
    let mut bytes = [0; 24];
    for (at, value) in [(0, 1u32), (4, id), (8, EVENT)] {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[16..24].copy_from_slice(&0x1234u64.to_le_bytes());
    cpu.write(64, &bytes).unwrap();
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

fn smoke_intel_viewport_uapi_joint_arm_requires_real_primary_and_dsb_completion() -> TestResult {
    let mode = color_mode();
    let Some(fb) = wc_frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let ctm = blob(&mode);
    let gamma = gamma_blob(&mode, true);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    source_request(&cpu, fb, 3, 17, NONBLOCK | EVENT, Some((ctm, gamma)));
    let completed = submit(&queue, &cpu, &events);
    let fence = cpu.exported.lock()[0].clone();
    drop(cpu);
    let platform = MockPlatform::new();
    let mut worker = worker(&platform);
    platform.allow_flips(false);
    let mut work = Box::pin(queue.run(&mut worker));
    pending(work.as_mut());
    assert!(
        platform.primary_updates().is_empty(),
        "CPU stage must not expose OFFSET"
    );
    assert_eq!(platform.read32(OFFSET), 0);
    pending(work.as_mut());
    assert_eq!(
        platform.primary_updates(),
        [(OFFSET, 0x10003), (SURF, 0xa002000)]
    );
    assert_eq!(platform.arm_order(), [GAMMA, MODE, SURF]);
    assert_eq!(
        platform.primary_mappings().len(),
        14,
        "map all seven source-prefix pages"
    );
    for _ in 0..3 {
        pending(work.as_mut());
    }
    assert_eq!(platform.read32(0x70c08), 0, "DSB is independently retired");
    assert_eq!(platform.read32(LIVE), CONSOLE);
    assert_eq!((completed.status(), fence.status()), (0, 0));
    assert_eq!(origin(&mode), (0, 0));
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    platform.allow_flips(true);
    run(work);
    assert_eq!((completed.status(), fence.status()), (1, 1));
    {
        let card = mode.lock();
        assert_eq!(
            (card.crtcs[0].primary_fb, card.crtcs[0].x, card.crtcs[0].y),
            (Some(fb), 3, 17)
        );
        assert_eq!(
            (
                card.crtc_color(1).unwrap().ctm,
                card.crtc_color(1).unwrap().gamma_lut
            ),
            (ctm, gamma)
        );
    }
    assert!(events.lock().has_deliverable_event(u64::MAX));
    let commands = platform.dsb_mappings();
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    assert_eq!(platform.read32(OFFSET), 0);
    assert_eq!(platform.read32(LIVE), CONSOLE);
    assert_eq!(platform.read32(GAMMA), 0);
    assert!(platform.primary_mappings().is_empty());
    assert_eq!(platform.dsb_mappings(), commands);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_viewport_uapi_joint_arm_requires_real_primary_and_dsb_completion
);

fn smoke_intel_viewport_fifo_pageflip_inherits_origin_and_replaces_same_bo_view() -> TestResult {
    let mode = color_mode();
    let Some(a) = wc_frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let b = wc_frame(&mode, 7).unwrap();
    let old = weak(&mode, a);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    source_request(&cpu, a, 3, 17, NONBLOCK, None);
    let first = submit(&queue, &cpu, &events);
    page_flip(&cpu, b);
    let (second, _, nonblock) =
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_PAGE_FLIP)
            .unwrap()
            .unwrap();
    assert!(!nonblock, "legacy caller waits the same owned FIFO");
    let platform = MockPlatform::new();
    let mut worker = worker(&platform);
    let mut work = Box::pin(queue.run(&mut worker));
    for _ in 0..3 {
        pending(work.as_mut());
    }
    // The no-LUT source still owes its post-vblank +1us wait and PROG.
    // A latched primary alone must not publish this joint transaction.
    assert_eq!(platform.read32(LIVE), 0xa002000);
    assert_ne!(platform.read32(0x44408) & 8, 0);
    assert_ne!(platform.read32(0x70b08) & 1, 0);
    assert_eq!(platform.read32(0x70b28) & 1, 0);
    assert_eq!(first.status(), 0);
    pending(work.as_mut());
    assert_eq!(first.status(), 1);
    assert_eq!(second.status(), 0);
    let both = platform.primary_mappings();
    assert_eq!(both.len(), 28);
    assert_eq!(origin(&mode), (3, 17));
    platform.allow_flips(false);
    for _ in 0..3 {
        pending(work.as_mut());
    }
    assert_eq!(platform.primary_mappings(), both);
    assert_eq!(second.status(), 0);
    platform.allow_flips(true);
    run(work);
    assert_eq!(second.status(), 1);
    assert_eq!(platform.primary_mappings().len(), 14);
    {
        let card = mode.lock();
        assert_eq!((card.crtcs[0].primary_fb, card.crtcs[0].y), (Some(b), 17));
    }
    mode.lock().rmfb(a).unwrap();
    assert!(old.upgrade().is_none());
    let previous = platform.read32(LIVE);
    set_crtc(&cpu, &mode, b, 7, 2);
    let (changed, _, nonblock) =
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_SETCRTC)
            .unwrap()
            .unwrap();
    assert!(!nonblock);
    run(queue.run(&mut worker));
    assert_eq!(changed.status(), 1);
    assert_ne!(
        platform.read32(LIVE),
        previous,
        "same BO with different viewport needs its own mapping identity"
    );
    assert_eq!(platform.read32(OFFSET), 0x20007);
    source_request(&cpu, b, 0, 0, NONBLOCK, None);
    let zero = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(zero.status(), 1);
    assert_eq!(platform.read32(OFFSET), 0);
    assert_eq!(origin(&mode), (0, 0));
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_viewport_fifo_pageflip_inherits_origin_and_replaces_same_bo_view
);

fn smoke_intel_viewport_foreground_bounds_test_only_and_prearm_rollback() -> TestResult {
    let mode = color_mode();
    let wb = frame(&mode, 7, false).unwrap();
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    source_request(&cpu, wb, 3, 17, NONBLOCK | TEST_ONLY, None);
    assert!(matches!(
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
        Err(queue::SubmitError::Io(FsError::Unsupported))
    ));
    let Some(fb) = wc_frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let platform = MockPlatform::new();
    let mut worker = worker(&platform);
    for (x, y) in [(65, 0), (0, 65), (65535, 65535)] {
        source_request(&cpu, fb, x, y, NONBLOCK | TEST_ONLY, None);
        assert!(admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC).is_err());
    }
    source_request(&cpu, fb, 3, 17, NONBLOCK | TEST_ONLY, None);
    cpu.write(272, &((3u64 << 16) | 1).to_le_bytes()).unwrap();
    assert!(matches!(
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
        Err(queue::SubmitError::Io(FsError::InvalidData))
    ));
    for (prop, value) in [
        (PLANE_SRC_W_PROP_ID, 63u64 << 16),
        (PLANE_CRTC_X_PROP_ID, 1),
    ] {
        source_request(&cpu, fb, 3, 17, NONBLOCK | TEST_ONLY, None);
        cpu.write(168, &prop.to_le_bytes()).unwrap();
        cpu.write(272, &value.to_le_bytes()).unwrap();
        assert!(matches!(
            admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
            Err(queue::SubmitError::Io(FsError::Unsupported))
        ));
    }
    mode.lock().intel_ctm = false;
    source_request(&cpu, fb, 3, 17, NONBLOCK | TEST_ONLY, None);
    assert!(matches!(
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
        Err(queue::SubmitError::Io(FsError::Unsupported))
    ));
    mode.lock().intel_ctm = true;
    source_request(&cpu, fb, 3, 17, NONBLOCK | TEST_ONLY, None);
    assert!(matches!(
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
        Ok(None)
    ));
    assert!(platform.primary_mappings().is_empty());
    assert!(platform.primary_updates().is_empty());
    assert!(cpu.exported.lock().is_empty());
    // Unsupported timing is a strict pre-trigger refusal, even after the
    // new viewport mapping was staged. No OFFSET reaches hardware.
    platform.set(0x60420, 1 << 31);
    source_request(&cpu, fb, 3, 17, NONBLOCK | EVENT, None);
    let rejected = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert!(rejected.status() < 0);
    assert!(platform.primary_updates().is_empty());
    assert!(platform.primary_mappings().is_empty());
    assert_eq!(platform.read32(OFFSET), 0);
    assert!(worker.device.legacy().is_ok());
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    platform.set(0x60420, 0);
    source_request(&cpu, fb, 3, 17, NONBLOCK, None);
    let first = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(first.status(), 1);
    let front = platform.primary_mappings();
    let updates = platform.primary_updates();
    platform.set(0x60420, 1 << 31);
    source_request(&cpu, fb, 4, 18, NONBLOCK | EVENT, None);
    let refused = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert!(refused.status() < 0);
    assert_eq!(platform.primary_mappings(), front);
    assert_eq!(platform.primary_updates(), updates);
    assert_eq!(origin(&mode), (3, 17));
    platform.set(0x60420, 0);
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_viewport_foreground_bounds_test_only_and_prearm_rollback
);

fn smoke_intel_viewport_cancel_master_handoff_restores_offset_before_replacement() -> TestResult {
    let mode = color_mode();
    let Some(fb) = wc_frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let retained = weak(&mode, fb);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let platform = MockPlatform::new();
    let mut worker = worker(&platform);
    source_request(&cpu, fb, 3, 17, NONBLOCK | EVENT, None);
    let abandoned = submit(&queue, &cpu, &events);
    let mut work = Box::pin(queue.run(&mut worker));
    pending(work.as_mut());
    pending(work.as_mut());
    assert_eq!(platform.read32(OFFSET), 0x10003);
    drop(work);
    assert!(abandoned.status() < 0);
    let mappings = platform.primary_mappings();
    mode.lock().release_file_framebuffers(7);
    mode.lock().master_release(7);
    mode.lock().master_open(8);
    let b = wc_frame(&mode, 8).unwrap();
    platform.stall_dsb(0, true);
    source_request(&cpu, b, 5, 3, NONBLOCK, None);
    let (replacement, _, _) = admission(&queue, &cpu, &events, 8, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
        .unwrap()
        .unwrap();
    let mut work = Box::pin(queue.run(&mut worker));
    for _ in 0..3 {
        pending(work.as_mut());
    }
    assert_eq!(replacement.status(), 0);
    assert_eq!(platform.primary_mappings(), mappings);
    assert_eq!(platform.read32(OFFSET), 0x10003);
    assert!(retained.upgrade().is_some());
    platform.stall_dsb(0, false);
    run(work);
    assert_eq!(replacement.status(), 1);
    assert!(retained.upgrade().is_none());
    let writes = platform.primary_updates();
    assert_eq!(&writes[2..4], &[(OFFSET, 0), (SURF, CONSOLE)]);
    assert_eq!(platform.read32(OFFSET), 0x30005);
    assert_eq!(origin(&mode), (5, 3));
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    let surface = platform.read32(LIVE);
    let mut session = run(worker.device.session()).unwrap();
    run(restore_released_master(&mut session, &mode)).unwrap();
    assert_eq!(
        platform.read32(LIVE),
        surface,
        "stale close cannot undo replacement master"
    );
    assert_eq!(platform.read32(OFFSET), 0x30005);
    run(session.restore_console()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_viewport_cancel_master_handoff_restores_offset_before_replacement
);

fn smoke_intel_viewport_reset_retires_commands_before_zeroing_offset_or_unmapping() -> TestResult {
    for corrupt_offset in [false, true] {
        let mode = color_mode();
        let Some(a) = wc_frame(&mode, 7) else {
            return TestResult::Pass;
        };
        let b = wc_frame(&mode, 7).unwrap();
        let old = weak(&mode, a);
        let new = weak(&mode, b);
        let queue = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let platform = MockPlatform::new();
        let mut worker = worker(&platform);
        source_request(&cpu, a, 3, 17, NONBLOCK, None);
        let first = submit(&queue, &cpu, &events);
        run(queue.run(&mut worker));
        assert_eq!(first.status(), 1);
        source_request(&cpu, b, 5, 18, NONBLOCK | EVENT, None);
        let failed = submit(&queue, &cpu, &events);
        let mut work = Box::pin(queue.run(&mut worker));
        pending(work.as_mut());
        pending(work.as_mut());
        assert_eq!(platform.read32(OFFSET), 0x20005);
        let writes = platform.primary_updates();
        let mappings = platform.primary_mappings();
        let commands = platform.dsb_mappings();
        if corrupt_offset {
            platform.set(OFFSET, 0xffff);
            run(work);
            platform.poison();
        } else {
            platform.stall_dsb(0, true);
            platform.poison();
            run(work);
        }
        assert!(failed.status() < 0);
        mode.lock().release_file_framebuffers(7);
        assert_eq!(platform.primary_mappings(), mappings);
        assert!(old.upgrade().is_some() && new.upgrade().is_some());
        if !corrupt_offset {
            let mut recovery = Box::pin(worker.device.recover());
            for _ in 0..3 {
                pending(recovery.as_mut());
            }
            assert_eq!(platform.primary_updates(), writes);
            assert_eq!(platform.primary_mappings(), mappings);
            drop(recovery);
            platform.stall_dsb(0, false);
        }
        run(worker.device.recover()).unwrap();
        assert_eq!(platform.read32(OFFSET), 0);
        assert_eq!(platform.read32(LIVE), CONSOLE);
        assert!(old.upgrade().is_none() && new.upgrade().is_none());
        assert!(platform.primary_mappings().is_empty());
        assert_eq!(platform.dsb_mappings(), commands);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        assert!(worker.device.legacy().is_ok());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_viewport_reset_retires_commands_before_zeroing_offset_or_unmapping
);
