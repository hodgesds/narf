//! Decoded mixed UAPI -> retained FIFO -> Presenter + real GGTT DSB transport.
//! The native device executes actual command pages; time/register IO are modeled.
use super::*;
use crate::intel_gpu_color::{GAMMA, MODE};
use alloc::sync::Weak;
use core::pin::Pin;

const SURF: u64 = 0x7019c;
const LIVE: u64 = 0x701ac;
const CONSOLE: u32 = 0x1000000;
fn mixed_request(cpu: &Cpu, fb: u32, ctm: u32, gamma: u32, flags: u32) {
    combined_color_request(cpu, ctm, gamma, flags);
    cpu.write(68, &2u32.to_le_bytes()).unwrap();
    cpu.write(132, &PLANE_ID_BASE.to_le_bytes()).unwrap();
    cpu.write(148, &2u32.to_le_bytes()).unwrap();
    cpu.write(172, &PLANE_FB_ID_PROP_ID.to_le_bytes()).unwrap();
    cpu.write(176, &PLANE_CRTC_ID_PROP_ID.to_le_bytes())
        .unwrap();
    cpu.write(216, &u64::from(fb).to_le_bytes()).unwrap();
    cpu.write(224, &1u64.to_le_bytes()).unwrap();
}
fn weak(mode: &ModeState, fb: u32) -> Weak<crate::intel_gpu_gem::GemObject> {
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
fn wc_frame(mode: &ModeState, owner: u64) -> Option<u32> {
    match framebuffer(mode, owner, true) {
        Ok(id) => Some(id),
        Err(FsError::NotImplemented) => {
            assert!(cfg!(target_arch = "aarch64"));
            None
        }
        Err(error) => panic!("mixed WC framebuffer failed: {error:?}"),
    }
}
fn pending<F: Future>(future: Pin<&mut F>) {
    assert!(future
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
}
fn geometry() -> Geometry {
    Geometry {
        width: 64,
        height: 32,
        pitch: 256,
    }
}

fn smoke_intel_mixed_nonblock_common_arm_and_both_hardware_witnesses() -> TestResult {
    let mode = color_mode();
    let Some(fb) = wc_frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let ctm = blob(&mode);
    let gamma = gamma_blob(&mode, true);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let platform = MockPlatform::new();
    platform.dsb_timing();
    platform.allow_flips(false);
    let mut worker = Worker {
        device: Arc::new(platform.meteor()),
    };
    mixed_request(&cpu, fb, ctm, gamma, NONBLOCK | EVENT);
    let completion = submit(&queue, &cpu, &events);
    let fence = cpu.exported.lock()[0].clone();
    assert_eq!(completion.status(), 0);
    assert!(platform.arm_order().is_empty());
    assert!(mode.lock().destroy_property_blob(ctm));
    assert!(mode.lock().destroy_property_blob(gamma));
    drop(cpu);
    let mut work = Box::pin(queue.run(&mut worker));
    pending(work.as_mut());
    assert_eq!(
        platform.read32(SURF),
        CONSOLE,
        "CPU stage must not arm the primary early"
    );
    assert_eq!(platform.read32(MODE), 0);
    assert_eq!(platform.palette_writes(), 0);
    pending(work.as_mut());
    assert_ne!(platform.read32(SURF), CONSOLE);
    assert_eq!(platform.arm_order(), [GAMMA, MODE, SURF]);
    for _ in 0..3 {
        pending(work.as_mut());
    }
    assert_eq!(
        platform.read32(0x70c08),
        0,
        "DSB leaf has retired independently"
    );
    assert_eq!(
        platform.read32(LIVE),
        CONSOLE,
        "primary witness deliberately absent"
    );
    assert_eq!(completion.status(), 0);
    assert_eq!(fence.status(), 0);
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    assert_eq!(mode.lock().crtcs[0].primary_fb, None);
    assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, 0);
    platform.allow_flips(true);
    run(work);
    assert_eq!(completion.status(), 1);
    assert_eq!(fence.status(), 1);
    assert_eq!(mode.lock().crtcs[0].primary_fb, Some(fb));
    let color = {
        let card = mode.lock();
        let color = card.crtc_color(1).unwrap();
        (color.ctm, color.gamma_lut)
    };
    assert_eq!(color, (ctm, gamma));
    let mut event = [0; 32];
    assert_eq!(
        events.lock().read_deliverable_event(u64::MAX, &mut event),
        Some(32)
    );
    assert_eq!(
        u32::from_le_bytes(event[24..28].try_into().unwrap()),
        platform.read32(0x70040)
    );
    let dsb = platform.dsb_mappings();
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    assert_eq!(platform.read32(LIVE), CONSOLE);
    assert_eq!(platform.read32(MODE), 0);
    assert_eq!(platform.read32(GAMMA), 0);
    assert!(platform.primary_mappings().is_empty());
    assert_eq!(platform.dsb_mappings(), dsb);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_mixed_nonblock_common_arm_and_both_hardware_witnesses
);

fn smoke_intel_mixed_fifo_projects_frame_and_color_and_retires_old_window_last() -> TestResult {
    let mode = color_mode();
    let Some(a) = wc_frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let b = wc_frame(&mode, 7).unwrap();
    let old = weak(&mode, a);
    let ca = blob(&mode);
    let cb = blob(&mode);
    let ga = gamma_blob(&mode, false);
    let gb = gamma_blob(&mode, true);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    mixed_request(&cpu, a, ca, ga, NONBLOCK | EVENT);
    let first = submit(&queue, &cpu, &events);
    mixed_request(&cpu, b, cb, gb, NONBLOCK | EVENT);
    let second = submit(&queue, &cpu, &events);
    for id in [ca, cb, ga, gb] {
        assert!(mode.lock().destroy_property_blob(id));
        assert!(mode.lock().property_blob(id).is_some());
    }
    let platform = MockPlatform::new();
    platform.dsb_timing();
    let mut worker = Worker {
        device: Arc::new(platform.meteor()),
    };
    let mut work = Box::pin(queue.run(&mut worker));
    for _ in 0..3 {
        pending(work.as_mut());
        assert_eq!((first.status(), second.status()), (0, 0));
    }
    pending(work.as_mut());
    assert_eq!((first.status(), second.status()), (1, 0));
    assert_eq!(mode.lock().crtcs[0].primary_fb, Some(a));
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, ga);
    let both = platform.primary_mappings();
    assert_eq!(both.len(), 8, "front and pending windows both retained");
    pending(work.as_mut());
    pending(work.as_mut());
    assert_eq!(platform.primary_mappings(), both);
    assert_eq!(second.status(), 0);
    assert!(old.upgrade().is_some());
    run(work);
    assert_eq!(second.status(), 1);
    assert_eq!(mode.lock().crtcs[0].primary_fb, Some(b));
    assert_eq!(platform.primary_mappings().len(), 4);
    assert!(mode.lock().property_blob(ca).is_none());
    assert!(mode.lock().property_blob(ga).is_none());
    mode.lock().rmfb(a).unwrap();
    assert!(old.upgrade().is_none());
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_mixed_fifo_projects_frame_and_color_and_retires_old_window_last
);

fn smoke_intel_mixed_test_only_eligibility_and_prearm_rollback_preserve_confirmed_front(
) -> TestResult {
    let mode = color_mode();
    let wb = framebuffer(&mode, 7, false).unwrap();
    let ctm = blob(&mode);
    let gamma = gamma_blob(&mode, false);
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let queue = queue::Queue::new(mode.clone());
    mixed_request(&cpu, wb, ctm, gamma, NONBLOCK | TEST_ONLY);
    assert!(matches!(
        run(admit(
            &queue,
            7,
            drm_uapi::DRM_IOCTL_MODE_ATOMIC,
            64,
            &cpu,
            Some(&events),
            geometry(),
            1
        )),
        Err(queue::SubmitError::Io(FsError::Unsupported))
    ));
    assert!(cpu.exported.lock().is_empty());
    let Some(a) = wc_frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let b = wc_frame(&mode, 7).unwrap();
    let platform = MockPlatform::new();
    platform.dsb_timing();
    let mut worker = Worker {
        device: Arc::new(platform.meteor()),
    };
    mixed_request(&cpu, a, ctm, gamma, NONBLOCK | TEST_ONLY);
    assert!(matches!(
        run(admit(
            &queue,
            7,
            drm_uapi::DRM_IOCTL_MODE_ATOMIC,
            64,
            &cpu,
            Some(&events),
            geometry(),
            1
        )),
        Ok(None)
    ));
    assert!(cpu.exported.lock().is_empty());
    assert!(platform.primary_mappings().is_empty());
    assert!(platform.arm_order().is_empty());
    // Refuse after preparing the target but strictly before DSB exposure;
    // rollback the new window/metadata and resume an untouched console.
    platform.set(0x60420, 1 << 31);
    mixed_request(&cpu, a, ctm, gamma, NONBLOCK | EVENT);
    let refused = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert!(refused.status() < 0);
    assert!(platform.primary_mappings().is_empty());
    assert_eq!(platform.read32(SURF), CONSOLE);
    assert!(worker.device.legacy().is_ok());
    assert_eq!(platform.console_resumes(), 1);
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    platform.set(0x60420, 0);
    mixed_request(&cpu, a, ctm, gamma, NONBLOCK);
    let first = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(first.status(), 1);
    let front = platform.primary_mappings();
    let surface = platform.read32(LIVE);
    let resumes = platform.console_resumes();
    let new_gamma = gamma_blob(&mode, true);
    platform.set(0x60420, 1 << 28);
    mixed_request(&cpu, b, ctm, new_gamma, NONBLOCK | EVENT);
    let refused = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert!(refused.status() < 0);
    assert_eq!(platform.primary_mappings(), front);
    assert_eq!(platform.read32(LIVE), surface);
    assert_eq!(platform.read32(SURF), surface);
    assert_eq!(platform.console_resumes(), resumes);
    assert_eq!(mode.lock().crtcs[0].primary_fb, Some(a));
    assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, gamma);
    assert!(run(worker.device.session()).is_ok());
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    platform.set(0x60420, 0);
    mixed_request(&cpu, b, ctm, new_gamma, NONBLOCK);
    let second = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(second.status(), 1);
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_mixed_test_only_eligibility_and_prearm_rollback_preserve_confirmed_front
);

fn smoke_intel_mixed_cancel_close_handoff_keeps_both_dma_owners_until_restore() -> TestResult {
    let mode = color_mode();
    let Some(fb) = wc_frame(&mode, 7) else {
        return TestResult::Pass;
    };
    let frame = weak(&mode, fb);
    let ctm = blob(&mode);
    let gamma = gamma_blob(&mode, true);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let platform = MockPlatform::new();
    platform.dsb_timing();
    let mut worker = Worker {
        device: Arc::new(platform.meteor()),
    };
    mixed_request(&cpu, fb, ctm, gamma, NONBLOCK | EVENT);
    let cancelled = submit(&queue, &cpu, &events);
    let mut work = Box::pin(queue.run(&mut worker));
    pending(work.as_mut());
    pending(work.as_mut());
    drop(work);
    assert!(cancelled.status() < 0);
    // A color-only clear must not publish Card's old framebuffer while
    // abandoned mixed hardware is free to latch a new one. Nor can an
    // observation/surface-only path silently turn it into a successful clear.
    gamma_request(&cpu, 0, NONBLOCK | EVENT);
    let clear = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert!(clear.status() < 0);
    let (observed, _, _) = run(queue.submit(7, observe(), geometry(), 1, &cpu, Some(&events)))
        .unwrap()
        .unwrap();
    run(queue.run(&mut worker));
    assert!(observed.status() < 0);
    assert_eq!(mode.lock().crtcs[0].primary_fb, None);
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    let mappings = platform.primary_mappings();
    let commands = platform.dsb_mappings();
    assert_eq!(mappings.len(), 4);
    assert_eq!(commands.len(), 8);
    events.lock().close();
    mode.lock().release_file_framebuffers(7);
    mode.lock().master_release(7);
    mode.lock().master_open(8);
    assert!(frame.upgrade().is_some());
    platform.stall_dsb(1, true);
    let replacement = Events::new(IrqSafeSpinLock::new(Default::default()));
    let (completed, _, _) =
        run(queue.submit(8, observe(), geometry(), 1, &cpu, Some(&replacement)))
            .unwrap()
            .unwrap();
    let mut work = Box::pin(queue.run(&mut worker));
    for _ in 0..3 {
        pending(work.as_mut());
    }
    assert_eq!(completed.status(), 0);
    assert_eq!(platform.primary_mappings(), mappings);
    assert_eq!(platform.dsb_mappings(), commands);
    assert!(frame.upgrade().is_some());
    platform.stall_dsb(1, false);
    // Cancel full restoration after color bypass is confirmed but before
    // the independently armed original console surface has latched.
    for _ in 0..3 {
        pending(work.as_mut());
    }
    assert_eq!(completed.status(), 0);
    assert_eq!(platform.read32(GAMMA), 0);
    assert_eq!(platform.read32(SURF), CONSOLE);
    assert_ne!(platform.read32(LIVE), CONSOLE);
    drop(work);
    assert!(completed.status() < 0);
    assert!(mode.lock().intel_master_restore_pending());
    assert!(frame.upgrade().is_some());
    assert_eq!(platform.primary_mappings(), mappings);
    let (retry, _, _) = run(queue.submit(8, observe(), geometry(), 1, &cpu, Some(&replacement)))
        .unwrap()
        .unwrap();
    run(queue.run(&mut worker));
    assert_eq!(retry.status(), 1);
    assert_eq!(platform.read32(LIVE), CONSOLE);
    assert_eq!(platform.read32(MODE), 0);
    assert_eq!(platform.read32(GAMMA), 0);
    assert!(frame.upgrade().is_none());
    assert!(platform.primary_mappings().is_empty());
    assert_eq!(platform.dsb_mappings(), commands);
    assert!(!mode.lock().intel_master_restore_pending());
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    let b = wc_frame(&mode, 8).unwrap();
    let (shown, _, _) = run(queue.submit(
        8,
        atomic_frame(b, NONBLOCK),
        geometry(),
        1,
        &cpu,
        Some(&replacement),
    ))
    .unwrap()
    .unwrap();
    run(queue.run(&mut worker));
    assert_eq!(shown.status(), 1);
    let surface = platform.read32(LIVE);
    let mut session = run(worker.device.session()).unwrap();
    run(restore_released_master(&mut session, &mode)).unwrap();
    assert_eq!(platform.read32(LIVE), surface);
    run(session.restore_console()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_mixed_cancel_close_handoff_keeps_both_dma_owners_until_restore
);

fn smoke_intel_mixed_reset_and_color_fault_retain_old_pending_surfaces_through_fresh_retirement(
) -> TestResult {
    for fault in [false, true] {
        let mode = color_mode();
        let Some(a) = wc_frame(&mode, 7) else {
            return TestResult::Pass;
        };
        let b = wc_frame(&mode, 7).unwrap();
        let old = weak(&mode, a);
        let next = weak(&mode, b);
        let ca = blob(&mode);
        let cb = blob(&mode);
        let ga = gamma_blob(&mode, false);
        let gb = gamma_blob(&mode, true);
        let queue = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let platform = MockPlatform::new();
        platform.dsb_timing();
        let mut worker = Worker {
            device: Arc::new(platform.meteor()),
        };
        mixed_request(&cpu, a, ca, ga, NONBLOCK);
        let first = submit(&queue, &cpu, &events);
        run(queue.run(&mut worker));
        assert_eq!(first.status(), 1);
        mixed_request(&cpu, b, cb, gb, NONBLOCK | EVENT);
        let second = submit(&queue, &cpu, &events);
        let mut work = Box::pin(queue.run(&mut worker));
        pending(work.as_mut());
        pending(work.as_mut());
        let mappings = platform.primary_mappings();
        let commands = platform.dsb_mappings();
        assert_eq!(mappings.len(), 8);
        if fault {
            platform.refuse_palette(true);
            run(work);
            assert!(second.status() < 0);
            platform.refuse_palette(false);
            platform.poison();
        } else {
            platform.stall_dsb(1, true);
            platform.poison();
            run(work);
            assert!(second.status() < 0);
        }
        mode.lock().release_file_framebuffers(7);
        assert!(old.upgrade().is_some());
        assert!(next.upgrade().is_some());
        assert_eq!(platform.primary_mappings(), mappings);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        if !fault {
            let arms = platform.primary_arms();
            let mut recover = Box::pin(worker.device.recover());
            for _ in 0..3 {
                pending(recover.as_mut());
            }
            assert_eq!(platform.primary_arms(), arms);
            assert_eq!(platform.primary_mappings(), mappings);
            assert_eq!(platform.dsb_mappings(), commands);
            drop(recover);
            platform.stall_dsb(1, false);
        }
        run(worker.device.recover()).unwrap();
        assert!(old.upgrade().is_none());
        assert!(next.upgrade().is_none());
        assert!(platform.primary_mappings().is_empty());
        assert_eq!(platform.dsb_mappings(), commands);
        assert_eq!(platform.read32(LIVE), CONSOLE);
        assert_eq!(platform.read32(MODE), 0);
        assert_eq!(platform.read32(GAMMA), 0);
        assert!(run(worker.device.session()).is_ok());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_mixed_reset_and_color_fault_retain_old_pending_surfaces_through_fresh_retirement
);
