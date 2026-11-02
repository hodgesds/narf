// Native UAPI/FIFO/WM/GGTT/DSB conversations. Hardware executes the actual WC
// command pages; independent literals come from Linux b90c984d intel_fb.c,
// skl_compute_wm_params/plane_wm/transition_wm and icl_plane_update_noarm.
use super::panning::{admission, geometry, origin, request, submit, weak, worker};
use super::*;
use crate::intel_gpu_scanout::{Viewport, TILE4_MODIFIER};

const OFFSET: u64 = 0x701a4;
const CONSOLE: u32 = 0x1000000;
const WM: [u64; 9] = [
    0x70240, 0x70244, 0x70248, 0x7024c, 0x70250, 0x70254, 0x70258, 0x7025c, 0x70268,
];
fn mode() -> ModeState {
    let mode = tiled_mode();
    mode.lock().intel_tile4 = true;
    mode
}
fn frame(mode: &ModeState, owner: u64, modifier: u64, wc: bool) -> Result<u32, FsError> {
    use crate::intel_gpu_gem::{GemState, Placement};
    let gem = GemState::new();
    let h = gem.create_placed(
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
                handles: [h, 0, 0, 0],
                pitches: [1024, 0, 0, 0],
                flags: 2,
                modifier: [modifier, 0, 0, 0],
                ..Default::default()
            },
            gem.object(h)?,
            owner,
            true,
        )
        .map_err(|_| FsError::InvalidData)
}
fn wc_frame(mode: &ModeState, owner: u64, modifier: u64) -> Option<u32> {
    match frame(mode, owner, modifier, true) {
        Ok(id) => Some(id),
        Err(FsError::NotImplemented) => {
            assert!(cfg!(target_arch = "aarch64"));
            None
        }
        Err(error) => panic!("Tile4 framebuffer: {error:?}"),
    }
}
fn wms(p: &MockPlatform) -> [u32; 9] {
    WM.map(|r| p.read32(r))
}
fn cursor(
    queue: &queue::Queue,
    cpu: &Cpu,
    gem: &crate::intel_gpu_gem::GemState,
    handle: u32,
) -> Arc<queue::Completion> {
    let bytes: Vec<u8> = [3u32, 1, 5, 2, 64, 64, handle, 0, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    cpu.write(64, &bytes).unwrap();
    run(admit_with_gem(
        queue,
        7,
        drm_uapi::iowr(b'd' as u32, 0xbb, 36),
        64,
        cpu,
        None,
        geometry(),
        1,
        Some(gem),
    ))
    .unwrap()
    .unwrap()
    .0
}

fn smoke_intel_tile4_source_literals_metadata_bounds_and_test_only() -> TestResult {
    use crate::intel_gpu_wm::{compute_tile4_watermarks, WmParams};
    let latencies = [6, 8, 10, 12, 14, 16];
    for (params, expected) in [
        (
            WmParams {
                pixel_rate_khz: 1034,
                htotal: 224,
                width_px: 64,
                cpp: 4,
            },
            (4, 7, 21),
        ),
        (
            WmParams {
                pixel_rate_khz: 65000,
                htotal: 1344,
                width_px: 1024,
                cpp: 4,
            },
            (34, 67, 81),
        ),
    ] {
        let wm = compute_tile4_watermarks(&params, &latencies);
        for level in wm.levels {
            assert!(level.enable);
            assert_eq!(
                (level.blocks, level.lines, level.min_ddb_alloc),
                (expected.0, 4, expected.1)
            );
        }
        assert_eq!((wm.trans.blocks, wm.trans.lines), (expected.2, 0));
        assert!(!wm.sagv.enable && !wm.sagv_trans.enable);
    }
    assert!(
        !compute_tile4_watermarks(
            &WmParams {
                pixel_rate_khz: u32::MAX,
                htotal: u32::MAX,
                width_px: u32::MAX,
                cpp: u32::MAX,
            },
            &latencies
        )
        .levels[0]
            .enable
    );
    let view = View {
        layout: Layout::Tile4,
        origin: Viewport { x: 33, y: 33 },
    };
    assert_eq!(
        view.footprint(geometry()).unwrap(),
        (0x9000, 0x10001, 98304)
    );
    assert!(view
        .footprint(Geometry {
            pitch: 1088,
            ..geometry()
        })
        .is_err());
    let mode = mode();
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let formats = intel_primary_formats_blob(&mode.lock(), INTEL_PRIMARY_FORMATS_BLOB).unwrap();
    assert_eq!(formats.len(), 104);
    assert_eq!(&formats[16..20], &3u32.to_le_bytes());
    assert_eq!(&formats[96..104], &0x0100000000000009u64.to_le_bytes());
    mode.lock().intel_tile4 = false;
    assert!(frame(&mode, 7, TILE4_MODIFIER, false).is_err());
    mode.lock().intel_tile4 = true;
    let wb = frame(&mode, 7, TILE4_MODIFIER, false).unwrap();
    request(&cpu, wb, 33, 33, NONBLOCK | TEST_ONLY, None);
    assert!(matches!(
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
        Err(queue::SubmitError::Io(FsError::Unsupported))
    ));
    let Some(fb) = wc_frame(&mode, 7, TILE4_MODIFIER) else {
        return TestResult::Pass;
    };
    let p = MockPlatform::new();
    let _worker = worker(&p);
    let timing = p.dsb_timing();
    crate::intel_gpu_kms::tile4_profile(&p, geometry(), timing).unwrap();
    for (x, y) in [(193, 0), (0, 65)] {
        request(&cpu, fb, x, y, NONBLOCK | TEST_ONLY, None);
        assert!(admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC).is_err());
    }
    let saved = wms(&p);
    request(&cpu, fb, 33, 33, NONBLOCK | TEST_ONLY, None);
    assert!(
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
            .unwrap()
            .is_none()
    );
    assert_eq!(wms(&p), saved);
    assert!(p.primary_mappings().is_empty() && p.dsb_mappings().is_empty());
    assert!(cpu.exported.lock().is_empty());
    // Hardware layout alone cannot become a fresh inherited resource owner.
    p.set(CTL, 0x84001400);
    assert!(crate::intel_gpu_kms::tile4_profile(&p, geometry(), timing).is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_tile4_source_literals_metadata_bounds_and_test_only
);

fn smoke_intel_tile4_joint_wm_primary_color_and_cursor_use_actual_fifo() -> TestResult {
    let mode = mode();
    let Some(fb) = wc_frame(&mode, 7, TILE4_MODIFIER) else {
        return TestResult::Pass;
    };
    let ctm = blob(&mode);
    let gamma = gamma_blob(&mode, false);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    request(&cpu, fb, 33, 33, NONBLOCK | EVENT, Some((ctm, gamma)));
    let complete = submit(&queue, &cpu, &events);
    let fence = cpu.exported.lock()[0].clone();
    let p = MockPlatform::new();
    let mut worker = worker(&p);
    let original = wms(&p);
    let global = [0x45230, 0x45234, 0x4438c, 0x7003c, 0x7027c, 0x7017c].map(|r| (r, p.read32(r)));
    p.allow_flips(false);
    let mut work = Box::pin(queue.run(&mut worker));
    pending(work.as_mut());
    assert_eq!(
        wms(&p),
        original,
        "foreground/staging cannot expose shadow WMs"
    );
    #[cfg(target_arch = "x86_64")]
    {
        let words = p.dsb_commands();
        let pos = |r| {
            words
                .iter()
                .position(|&(_, h)| h >> 24 == 1 && h & 0xfffff == r)
                .unwrap()
        };
        let evade = words.iter().position(|&(_, h)| h >> 24 == 6).unwrap();
        for r in WM {
            assert!(pos(r as u32) < evade);
        }
        assert!(
            evade < pos(OFFSET as u32)
                && pos(OFFSET as u32) < pos(CTL as u32)
                && pos(CTL as u32) < pos(SURF as u32)
        );
        assert_eq!(words[pos(0x70240)].0, 0x80010004);
        assert_eq!(words[pos(0x70268)].0, 0x80000015);
        assert_eq!(words[pos(STRIDE as u32)].0, 8);
        assert_eq!(words[pos(SURF as u32)].0, 0x0a009000);
    }
    for _ in 0..10 {
        pending(work.as_mut());
    }
    assert_eq!(
        wms(&p),
        [
            0x80010004, 0x80010004, 0x80010004, 0x80010004, 0x80010004, 0x80010004, 0, 0,
            0x80000015
        ]
    );
    assert_eq!(
        (
            p.read32(CTL),
            p.read32(STRIDE),
            p.read32(OFFSET),
            p.read32(LIVE)
        ),
        (0x84001400, 8, 0x10001, CONSOLE)
    );
    assert_eq!(p.primary_mappings().len(), 48);
    assert_eq!((complete.status(), fence.status()), (0, 0));
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    assert_eq!(global.map(|(r, _)| (r, p.read32(r))), global);
    p.allow_flips(true);
    run(work);
    assert_eq!((complete.status(), fence.status()), (1, 1));
    assert_eq!(origin(&mode), (33, 33));
    let gem = crate::intel_gpu_gem::GemState::new();
    let handle = gem.create(16384, |_, _| Ok(())).unwrap();
    gem.object(handle)
        .unwrap()
        .write(0, &vec![0x7a; 16384])
        .unwrap();
    let moved = cursor(&queue, &cpu, &gem, handle);
    run(queue.run(&mut worker));
    assert_eq!(moved.status(), 1);
    assert_eq!(p.read32(0x70080), 0x27);
    assert_eq!(p.read32(0x700ac), p.read32(0x70084));
    let b = wc_frame(&mode, 7, TILE4_MODIFIER).unwrap();
    request(&cpu, b, 35, 34, NONBLOCK, None);
    let flip = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(flip.status(), 1);
    let color = mode.lock().crtc_color(1).unwrap().clone();
    assert_eq!((color.ctm, color.gamma_lut), (ctm, gamma));
    assert_eq!(p.read32(0x70080), 0x27);
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    assert_eq!(wms(&p), original);
    assert_eq!(
        (
            p.read32(CTL),
            p.read32(STRIDE),
            p.read32(OFFSET),
            p.read32(LIVE)
        ),
        (0x84000000, 16, 0, CONSOLE)
    );
    assert_eq!(p.read32(0x70080), 0);
    assert!(p.primary_mappings().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_tile4_joint_wm_primary_color_and_cursor_use_actual_fifo
);

fn smoke_intel_tile4_projected_pageflip_x_and_linear_preserve_old_images() -> TestResult {
    let mode = mode();
    let Some(a) = wc_frame(&mode, 7, TILE4_MODIFIER) else {
        return TestResult::Pass;
    };
    let b = wc_frame(&mode, 7, X_TILED_MODIFIER).unwrap();
    let c = wc_frame(&mode, 7, 0).unwrap();
    let old = weak(&mode, a);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    request(&cpu, a, 33, 33, NONBLOCK, None);
    let first = submit(&queue, &cpu, &events);
    let mut flip = [0; 24];
    for (at, value) in [(0, 1u32), (4, b), (8, EVENT)] {
        flip[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    cpu.write(64, &flip).unwrap();
    let second = admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_PAGE_FLIP)
        .unwrap()
        .unwrap()
        .0;
    flip[4..8].copy_from_slice(&c.to_le_bytes());
    cpu.write(64, &flip).unwrap();
    let third = admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_PAGE_FLIP)
        .unwrap()
        .unwrap()
        .0;
    let p = MockPlatform::new();
    let mut worker = worker(&p);
    let original = wms(&p);
    let mut work = Box::pin(queue.run(&mut worker));
    for _ in 0..16 {
        pending(work.as_mut());
        if first.status() == 1 {
            break;
        }
    }
    assert_eq!(first.status(), 1);
    p.allow_flips(false);
    for _ in 0..6 {
        pending(work.as_mut());
    }
    assert_eq!((second.status(), third.status()), (0, 0));
    assert_eq!(p.primary_mappings().len(), 84); // Tile4 24 + X18 pages
    assert!(old.upgrade().is_some());
    assert_eq!(origin(&mode), (33, 33));
    p.allow_flips(true);
    run(work);
    assert_eq!((second.status(), third.status()), (1, 1));
    assert_eq!(wms(&p), original);
    assert_eq!((p.read32(CTL), p.read32(STRIDE)), (0x84000000, 16));
    assert_eq!(p.primary_mappings().len(), 34);
    mode.lock().rmfb(a).unwrap();
    assert!(old.upgrade().is_none());
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    assert_eq!(wms(&p), original);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_tile4_projected_pageflip_x_and_linear_preserve_old_images
);

fn smoke_intel_tile4_prearm_and_partial_watermark_faults_retain_restore_owner() -> TestResult {
    for fault in [0x60420, 0x70240] {
        let mode = mode();
        let Some(fb) = wc_frame(&mode, 7, TILE4_MODIFIER) else {
            return TestResult::Pass;
        };
        let queue = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let p = MockPlatform::new();
        let mut worker = worker(&p);
        let original = wms(&p);
        request(&cpu, fb, 33, 33, NONBLOCK | EVENT, None);
        let failed = submit(&queue, &cpu, &events);
        if fault == 0x60420 {
            p.set(fault, 1 << 31);
        } else {
            p.refuse_layout(fault);
        }
        run(queue.run(&mut worker));
        assert!(failed.status() < 0);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        if fault == 0x60420 {
            assert_eq!(wms(&p), original);
            assert!(p.primary_mappings().is_empty() && p.primary_updates().is_empty());
            assert!(worker.device.legacy().is_ok());
        } else {
            assert!(!p.primary_mappings().is_empty());
            assert!(worker.device.legacy().is_err());
            let retained = p.primary_mappings();
            // WM0 stayed original, but the next shadow WM was exposed.
            // Lose that restore write after WM0 succeeds: ownership must
            // survive a partially rewritten original image as well.
            p.refuse_layout(0x70244);
            p.poison();
            assert!(run(worker.device.recover()).is_err());
            assert_eq!(p.primary_mappings(), retained);
            p.refuse_layout(u64::MAX);
            run(worker.device.recover()).unwrap();
            assert_eq!(wms(&p), original);
            assert!(p.primary_mappings().is_empty());
            assert_eq!(p.read32(LIVE), CONSOLE);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_tile4_prearm_and_partial_watermark_faults_retain_restore_owner
);

fn smoke_intel_tile4_cancel_master_handoff_and_repeated_reset_retire_dma_first() -> TestResult {
    let mode = mode();
    let Some(a) = wc_frame(&mode, 7, TILE4_MODIFIER) else {
        return TestResult::Pass;
    };
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let p = MockPlatform::new();
    let mut worker = worker(&p);
    let original = wms(&p);
    request(
        &cpu,
        a,
        33,
        33,
        NONBLOCK,
        Some((blob(&mode), gamma_blob(&mode, false))),
    );
    let first = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(first.status(), 1);
    mode.lock().master_release(7);
    mode.lock().master_open(8);
    let b = wc_frame(&mode, 8, TILE4_MODIFIER).unwrap();
    request(&cpu, b, 35, 34, NONBLOCK, None);
    let replacement = admission(&queue, &cpu, &events, 8, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
        .unwrap()
        .unwrap()
        .0;
    run(queue.run(&mut worker));
    assert_eq!(replacement.status(), 1);
    let live = p.read32(LIVE);
    {
        let mut session = run(worker.device.session()).unwrap();
        run(restore_released_master(&mut session, &mode)).unwrap();
        assert_eq!(p.read32(LIVE), live);
    }
    for _ in 0..2 {
        request(&cpu, b, 37, 35, NONBLOCK | EVENT, None);
        let abandoned = admission(&queue, &cpu, &events, 8, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
            .unwrap()
            .unwrap()
            .0;
        p.allow_flips(false);
        let mut work = Box::pin(queue.run(&mut worker));
        pending(work.as_mut());
        pending(work.as_mut());
        drop(work);
        assert!(abandoned.status() < 0);
        let mappings = p.primary_mappings();
        let image = wms(&p);
        let commands = p.dsb_mappings();
        p.stall_dsb(0, true);
        p.poison();
        let fresh = crate::intel_gpu_kms::Platform::recovery_platform(&p, true, false).unwrap();
        let mut recovery = Box::pin(worker.device.recover());
        for _ in 0..3 {
            pending(recovery.as_mut());
        }
        assert_eq!(wms(&p), [u32::MAX; 9]);
        assert_eq!(wms(&fresh), image);
        assert_eq!(p.primary_mappings(), mappings);
        drop(recovery);
        p.stall_dsb(0, false);
        p.allow_flips(true);
        run(worker.device.recover()).unwrap();
        assert_eq!(wms(&p), original);
        assert_eq!(
            (
                p.read32(CTL),
                p.read32(STRIDE),
                p.read32(OFFSET),
                p.read32(LIVE)
            ),
            (0x84000000, 16, 0, CONSOLE)
        );
        assert!(p.primary_mappings().is_empty());
        assert_eq!(p.dsb_mappings(), commands);
        // Card still describes the last published client rectangle. The new
        // transaction rechecks actual restored authority, recreating its own
        // resource journal rather than reusing a recovery-only IO view.
        request(&cpu, b, 35, 34, NONBLOCK, None);
        let next = admission(&queue, &cpu, &events, 8, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
            .unwrap()
            .unwrap()
            .0;
        run(queue.run(&mut worker));
        assert_eq!(next.status(), 1);
    }
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
    assert_eq!(wms(&p), original);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_intel_tile4_cancel_master_handoff_and_repeated_reset_retire_dma_first
);
