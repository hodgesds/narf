// Actual raw ATOMIC/PAGE_FLIP/CURSOR2 -> Card/FIFO -> Gen12 source owners.
// Pinned Linux b90c984d: intel_dpt_common, intel_fb aligned offsets,
// skl_universal_plane min_alignment/stride/arm, non-Y skl_watermark formula.
use super::*;
use crate::intel_gpu_color::{Profile, GAMMA, MODE};
use crate::intel_gpu_gt::Gen12Platform;
use crate::intel_gpu_scanout::X_TILED_MODIFIER;
use core::pin::Pin;
const SURF: u64 = 0x7019c;
const LIVE: u64 = 0x701ac;
const CONSOLE: u32 = 0x1000000;
fn geometry(pitch: u32) -> Geometry {
    Geometry {
        width: 64,
        height: 32,
        pitch,
    }
}
// Independent Wa_22012358565 literals, not the production control helper.
fn control(family: Gen12Platform) -> u32 {
    match family {
        Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN => 0x94000000,
        Gen12Platform::TigerLake | Gen12Platform::AlderLakeS => 0x84000000,
    }
}
fn families() -> [Gen12Platform; 4] {
    [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeS,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeN,
    ]
}
fn fixture(
    family: Gen12Platform,
    pitch: u32,
) -> (MockPlatform, ModeState, queue::Queue, Worker, Cpu, Events) {
    let p = MockPlatform::new();
    p.gen12_cursor_resources(family);
    let mode = mode();
    {
        let mut c = mode.lock();
        c.intel_display = true;
        c.intel_ctm_only = true;
        c.intel_gen12_lut = Some(Profile::gen12(family));
        c.intel_gen12_joint = true;
        c.intel_gen12_views = Some(family);
        c.intel_x_tiled = true;
        c.crtc_color.push(crate::drm::card::CrtcColor::new(1));
    }
    let q = queue::Queue::new(mode.clone());
    let worker = Worker {
        device: Arc::new(p.gen12_pitch(family, pitch)),
    };
    assert_eq!(p.read32(0x70180), control(family));
    (
        p,
        mode,
        q,
        worker,
        Cpu::new(),
        Events::new(IrqSafeSpinLock::new(Default::default())),
    )
}
fn frame(mode: &ModeState, open: u64, tiled: bool) -> Option<u32> {
    let gem = crate::intel_gpu_gem::GemState::new();
    let h = match gem.create_placed(
        512 * 96,
        None,
        crate::intel_gpu_gem::Placement::SystemWc,
        |_, _| Ok(()),
    ) {
        Ok(h) => h,
        Err(FsError::NotImplemented) => {
            assert!(cfg!(target_arch = "aarch64"));
            return None;
        }
        Err(e) => panic!("view frame: {e:?}"),
    };
    Some(
        mode.lock()
            .addfb2_intel(
                &crate::drm::fb_cmd::FbCmd {
                    width: 128,
                    height: 96,
                    pixel_format: DRM_FORMAT_XRGB8888,
                    handles: [h, 0, 0, 0],
                    pitches: [512, 0, 0, 0],
                    flags: 2,
                    modifier: [if tiled { X_TILED_MODIFIER } else { 0 }, 0, 0, 0],
                    ..Default::default()
                },
                gem.object(h).unwrap(),
                open,
                true,
            )
            .unwrap(),
    )
}
fn raw(cpu: &Cpu, flags: u32, objects: &[(u32, &[(u32, u64)])]) {
    let mut h = [0; 56];
    h[..4].copy_from_slice(&flags.to_le_bytes());
    h[4..8].copy_from_slice(&(objects.len() as u32).to_le_bytes());
    for (at, ptr) in [(8, 128u64), (16, 160), (24, 192), (32, 512)] {
        h[at..at + 8].copy_from_slice(&ptr.to_le_bytes());
    }
    h[48..56].copy_from_slice(&0x1213u64.to_le_bytes());
    cpu.write(64, &h).unwrap();
    let mut at = 0;
    for (i, (id, props)) in objects.iter().enumerate() {
        cpu.write(128 + i as u64 * 4, &id.to_le_bytes()).unwrap();
        cpu.write(160 + i as u64 * 4, &(props.len() as u32).to_le_bytes())
            .unwrap();
        for (prop, value) in *props {
            cpu.write(192 + at * 4, &prop.to_le_bytes()).unwrap();
            cpu.write(512 + at * 8, &value.to_le_bytes()).unwrap();
            at += 1;
        }
    }
}
fn request(cpu: &Cpu, fb: u32, x: u32, y: u32, flags: u32, color: Option<(u32, u32)>) {
    let mut c = vec![(CRTC_OUT_FENCE_PTR_PROP_ID, 1024)];
    if let Some((ctm, gamma)) = color {
        c.extend([
            (CRTC_CTM_PROP_ID, ctm.into()),
            (CRTC_GAMMA_LUT_PROP_ID, gamma.into()),
        ]);
    }
    raw(
        cpu,
        flags,
        &[
            (1, &c),
            (
                PLANE_ID_BASE,
                &[
                    (PLANE_FB_ID_PROP_ID, fb.into()),
                    (PLANE_CRTC_ID_PROP_ID, 1),
                    (PLANE_SRC_X_PROP_ID, u64::from(x) << 16),
                    (PLANE_SRC_Y_PROP_ID, u64::from(y) << 16),
                ],
            ),
        ],
    );
}
fn admission(
    q: &queue::Queue,
    cpu: &Cpu,
    events: &Events,
    pitch: u32,
    open: u64,
    cmd: u32,
) -> Result<queue::Submitted, queue::SubmitError> {
    run(admit(
        q,
        open,
        cmd,
        64,
        cpu,
        Some(events),
        geometry(pitch),
        1,
    ))
}
fn submit(q: &queue::Queue, cpu: &Cpu, events: &Events, pitch: u32) -> Arc<queue::Completion> {
    admission(q, cpu, events, pitch, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
        .unwrap()
        .unwrap()
        .0
}
fn pending<F: Future>(f: Pin<&mut F>) {
    assert!(f.poll(&mut Context::from_waker(Waker::noop())).is_pending());
}
fn until<F: Future>(mut f: Pin<&mut F>, check: impl Fn() -> bool) {
    for _ in 0..256 {
        pending(f.as_mut());
        if check() {
            return;
        }
    }
    panic!("actual Gen12 arm witness absent");
}
fn armed(p: &MockPlatform) -> bool {
    p.read32(0x70b08) & (1 << 31) != 0 && !p.dsb_mappings().is_empty()
}
fn pages(p: &MockPlatform, m: &[(u64, u32)]) -> usize {
    for &(r, v) in m {
        if r % 8 == 0 {
            assert_eq!(v & 4095, 1);
            assert!(p.read32(r + 4) < 128);
        } else {
            assert!(v < 128);
        }
    }
    m.iter().filter(|(r, _)| r % 8 == 0).count()
}
fn resources(p: &MockPlatform) -> Vec<u32> {
    [
        0x70240, 0x70244, 0x70248, 0x7024c, 0x70250, 0x70254, 0x70258, 0x7025c, 0x70268, 0x7027c,
        0x7017c, 0x46000, 0x45008, 0x44fe8,
    ]
    .into_iter()
    .map(|r| p.read32(r))
    .collect()
}
fn restore(worker: &mut Worker) {
    let mut s = run(worker.device.session()).unwrap();
    run(s.restore_console()).unwrap();
}
fn gamma(mode: &ModeState, profile: Profile, half: bool) -> u32 {
    let size = profile.sizes().0;
    mode.lock()
        .create_property_blob(
            (0..size)
                .flat_map(|i| {
                    let v = (i as u64 * 65535 / (size - 1) as u64) as u16;
                    let v = if half { v / 2 } else { v };
                    [v, v, v, 0].into_iter().flat_map(u16::to_le_bytes)
                })
                .collect(),
        )
        .unwrap()
}

fn smoke_gen12_small_linear_direct_joint_and_fragmented_reuse_keep_family_surf_alignment(
) -> TestResult {
    for family in families() {
        let (p, mode, q, mut worker, cpu, events) = fixture(family, 256);
        let a = match framebuffer(&mode, 7, true) {
            Ok(a) => a,
            Err(FsError::NotImplemented) => continue,
            Err(e) => panic!("{e:?}"),
        };
        let b = framebuffer(&mode, 7, true).unwrap();
        let c = framebuffer(&mode, 7, true).unwrap();
        let d = framebuffer(&mode, 7, true).unwrap();
        let ctm = blob(&mode);
        request(&cpu, a, 0, 0, NONBLOCK, None);
        let first = submit(&q, &cpu, &events, 256);
        run(q.run(&mut worker));
        assert_eq!(first.status(), 1);
        let base = p.read32(LIVE);
        assert_eq!(
            base % 16384,
            0,
            "first arena base is independently16KiB aligned"
        );
        p.allow_flips(false);
        request(&cpu, b, 0, 0, NONBLOCK | EVENT, Some((ctm, 0)));
        let second = submit(&q, &cpu, &events, 256);
        let mut task = Box::pin(q.run(&mut worker));
        until(task.as_mut(), || p.read32(SURF) != base);
        let next = p.read32(SURF);
        let alignment = if matches!(
            family,
            Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN
        ) {
            16384
        } else {
            4096
        };
        assert_eq!(next % alignment, 0);
        assert_eq!(
            next - base,
            if alignment == 16384 { 16384 } else { 8192 },
            "two-page BO must not lower ADLP/N minimum alignment"
        );
        assert_eq!(pages(&p, &p.primary_mappings()), 4);
        assert_eq!(second.status(), 0);
        assert_eq!(p.read32(LIVE), base);
        p.allow_flips(true);
        run(task);
        assert_eq!(second.status(), 1);
        assert_eq!(pages(&p, &p.primary_mappings()), 2);
        request(&cpu, c, 0, 0, NONBLOCK, None);
        let third = submit(&q, &cpu, &events, 256);
        run(q.run(&mut worker));
        assert_eq!(third.status(), 1);
        assert_eq!(
            p.read32(LIVE),
            base,
            "retired prefix and alignment gap merge for safe fragmented reuse"
        );
        request(&cpu, d, 0, 0, NONBLOCK, Some((ctm, 0)));
        let fourth = submit(&q, &cpu, &events, 256);
        run(q.run(&mut worker));
        assert_eq!(fourth.status(), 1);
        assert_eq!(p.read32(LIVE), next);
        restore(&mut worker);
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert!(p.primary_mappings().is_empty());
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_small_linear_direct_joint_and_fragmented_reuse_keep_family_surf_alignment
);

fn smoke_gen12_x_tiled_raw_common_arm_literal_offsets_unchanged_wm_and_dual_witnesses() -> TestResult
{
    for family in families() {
        let (p, mode, q, mut worker, cpu, events) = fixture(family, 512);
        let Some(fb) = frame(&mode, 7, true) else {
            continue;
        };
        let original = resources(&p);
        if matches!(
            family,
            Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN
        ) {
            assert_eq!(p.read32(0x42084) & (1 << 30), 1 << 30);
        }
        p.stall_dsb(0, true);
        p.allow_flips(false);
        request(&cpu, fb, 7, 17, NONBLOCK | EVENT, None);
        let done = submit(&q, &cpu, &events, 512);
        let fence = cpu.exported.lock()[0].clone();
        let mut task = Box::pin(q.run(&mut worker));
        until(task.as_mut(), || {
            armed(&p) && !p.primary_mappings().is_empty()
        });
        #[cfg(target_arch = "x86_64")]
        {
            let cmds = p.dsb_commands();
            let pos = |reg| {
                cmds.iter()
                    .position(|&(_, h)| h >> 24 == 1 && h & 0xfffff == reg)
                    .unwrap()
            };
            let ev = cmds
                .iter()
                .position(|&(l, h)| h >> 24 == 6 && l != 0)
                .unwrap();
            assert!(
                pos(0x70188) < ev
                    && ev < pos(0x701a4)
                    && pos(0x701a4) < pos(0x70180)
                    && pos(0x70180) < pos(0x7019c)
            );
            assert_eq!(cmds[pos(0x70188)].0, 1);
            assert_eq!(cmds[pos(0x70180)].0, (control(family) | 0x400));
        }
        assert_eq!(p.read32(SURF), CONSOLE);
        assert_eq!(p.read32(0x70180), control(family));
        p.stall_dsb(0, false);
        until(task.as_mut(), || {
            p.read32(SURF) != CONSOLE && p.read32(0x70b08) == 0
        });
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert_eq!((done.status(), fence.status()), (0, 0));
        assert_eq!(mode.lock().crtcs[0].primary_fb, None);
        assert_eq!(p.read32(0x70180), (control(family) | 0x400));
        assert_eq!(p.read32(0x70188), 1);
        let mobile = matches!(
            family,
            Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN
        );
        assert_eq!(
            p.read32(SURF),
            160 * 1024 * 1024 + if mobile { 0 } else { 8192 }
        );
        assert_eq!(
            p.read32(0x701a4),
            if mobile { 17 << 16 | 7 } else { 1 << 16 | 7 }
        );
        assert_eq!(resources(&p), original);
        assert_eq!(pages(&p, &p.primary_mappings()), 7);
        p.allow_flips(true);
        run(task);
        assert_eq!((done.status(), fence.status()), (1, 1));
        assert_eq!(
            {
                let c = mode.lock();
                (c.crtcs[0].x, c.crtcs[0].y)
            },
            (7, 17)
        );
        let dsb = p.dsb_mappings();
        restore(&mut worker);
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert_eq!(p.read32(0x70180), control(family));
        assert_eq!(p.read32(0x70188), 8);
        assert_eq!(p.read32(0x701a4), 0);
        assert!(p.primary_mappings().is_empty());
        assert_eq!(p.dsb_mappings(), dsb);
        assert_eq!(resources(&p), original);
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_x_tiled_raw_common_arm_literal_offsets_unchanged_wm_and_dual_witnesses
);

fn smoke_gen12_linear_pan_raw_fifo_pageflip_inherits_origin_and_returns_to_direct() -> TestResult {
    for family in families() {
        let (p, mode, q, mut worker, cpu, events) = fixture(family, 512);
        let Some(a) = frame(&mode, 7, false) else {
            continue;
        };
        let b = frame(&mode, 7, false).unwrap();
        let original = resources(&p);
        request(&cpu, a, 7, 17, NONBLOCK, None);
        let first = submit(&q, &cpu, &events, 512);
        let mut w = [0; 24];
        w[..4].copy_from_slice(&1u32.to_le_bytes());
        w[4..8].copy_from_slice(&b.to_le_bytes());
        cpu.write(64, &w).unwrap();
        let second = admission(
            &q,
            &cpu,
            &events,
            512,
            7,
            drm_uapi::DRM_IOCTL_MODE_PAGE_FLIP,
        )
        .unwrap()
        .unwrap()
        .0;
        run(q.run(&mut worker));
        assert_eq!((first.status(), second.status()), (1, 1));
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(b));
        assert_eq!(
            {
                let c = mode.lock();
                (c.crtcs[0].x, c.crtcs[0].y)
            },
            (7, 17)
        );
        assert_eq!(p.read32(0x70180), control(family));
        assert_eq!(p.read32(0x70188), 8);
        let mobile = matches!(
            family,
            Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN
        );
        assert_eq!(
            p.read32(0x701a4),
            if mobile { 17 << 16 | 7 } else { 1 << 16 | 7 }
        );
        request(&cpu, a, 0, 0, NONBLOCK, None);
        let origin = submit(&q, &cpu, &events, 512);
        run(q.run(&mut worker));
        assert_eq!(origin.status(), 1);
        assert_eq!(p.read32(0x701a4), 0);
        let dsb = p.dsb_writes().len();
        request(&cpu, b, 0, 0, NONBLOCK, None);
        let direct = submit(&q, &cpu, &events, 512);
        run(q.run(&mut worker));
        assert_eq!(direct.status(), 1);
        assert_eq!(p.dsb_writes().len(), dsb);
        assert_eq!(resources(&p), original);
        restore(&mut worker);
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_linear_pan_raw_fifo_pageflip_inherits_origin_and_returns_to_direct
);

fn smoke_gen12_x_native_lut_preload_and_live_cursor_keep_independent_owners_on_clear() -> TestResult
{
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        let profile = Profile::gen12(family);
        let (p, mode, q, mut worker, cpu, events) = fixture(family, 512);
        let Some(fb) = frame(&mode, 7, true) else {
            continue;
        };
        mode.lock().intel_hw_cursor = true;
        let gem = crate::intel_gpu_gem::GemState::new();
        let h = gem.create(16384, |_, _| Ok(())).unwrap();
        gem.object(h).unwrap().write(0, &vec![0x7a; 16384]).unwrap();
        let w: Vec<u8> = [3u32, 1, 2, 3, 64, 64, h, 0, 0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        cpu.write(64, &w).unwrap();
        let image = run(admit_with_gem(
            &q,
            7,
            drm_uapi::iowr(b'd' as u32, 0xbb, 36),
            64,
            &cpu,
            Some(&events),
            geometry(512),
            1,
            Some(&gem),
        ))
        .unwrap()
        .unwrap()
        .0;
        run(q.run(&mut worker));
        assert_eq!(image.status(), 1);
        let cursor = p.cursor_mappings();
        assert_eq!(
            pages(&p, &cursor),
            8,
            "both16KiB private cursor slots remain mapped"
        );
        let base = p.read32(0x700ac);
        let ctm = blob(&mode);
        let lut = gamma(&mode, profile, false);
        let original = resources(&p);
        p.stall_dsb(0, true);
        request(&cpu, fb, 7, 17, NONBLOCK | EVENT, Some((ctm, lut)));
        let done = submit(&q, &cpu, &events, 512);
        assert!(mode.lock().destroy_property_blob(lut));
        let mut task = Box::pin(q.run(&mut worker));
        until(task.as_mut(), || armed(&p));
        if profile == Profile::Display12 {
            assert!(p.primary_mappings().is_empty());
            assert_eq!(p.read32(GAMMA), 0);
            #[cfg(target_arch = "x86_64")]
            assert!(p
                .dsb_commands()
                .iter()
                .all(|&(_, h)| h >> 24 != 1 || h & 0xfffff != SURF as u32));
        }
        p.stall_dsb(0, false);
        run(task);
        assert_eq!(done.status(), 1);
        assert_eq!(p.read32(0x700ac), base);
        assert_eq!(p.cursor_mappings(), cursor);
        assert_eq!(resources(&p), original);
        let loaded = p.precision();
        request(&cpu, fb, 7, 17, NONBLOCK, Some((0, 0)));
        let clear = submit(&q, &cpu, &events, 512);
        run(q.run(&mut worker));
        assert_eq!(clear.status(), 1);
        assert_eq!(p.read32(GAMMA), 0);
        assert_eq!(p.read32(MODE), 0);
        assert_eq!(p.read32(0x700ac), base);
        assert_eq!(p.cursor_mappings(), cursor);
        if profile == Profile::Display12 {
            assert_eq!(p.precision(), loaded);
        }
        restore(&mut worker);
        assert_eq!(p.read32(0x700ac), 0);
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert!(p.primary_mappings().is_empty());
        assert_eq!(p.unreadable_prec_reads(), 0);
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_x_native_lut_preload_and_live_cursor_keep_independent_owners_on_clear
);

fn smoke_gen12_views_raw_test_only_bounds_capabilities_and_missing_dpt_refuse_before_dma(
) -> TestResult {
    for family in families() {
        let (p, mode, q, mut worker, cpu, events) = fixture(family, 512);
        let Some(fb) = frame(&mode, 7, true) else {
            continue;
        };
        let source = mode.lock().framebuffer(fb).unwrap().clone();
        assert_eq!(
            run(copy_frame_to_query(
                &source,
                &mode,
                narf_graphics_driver::generic::GenericFb::new(0x12345000, 64, 32, 512, 32),
                || panic!("tiled row-copy must refuse before console query"),
                || panic!("tiled row-copy must never claim a console")
            )),
            Err(FsError::Unsupported)
        );
        request(&cpu, fb, 7, 17, NONBLOCK | TEST_ONLY, None);
        assert!(
            admission(&q, &cpu, &events, 512, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
                .unwrap()
                .is_none()
        );
        assert!(cpu.exported.lock().is_empty());
        assert!(p.primary_mappings().is_empty() && p.dsb_mappings().is_empty());
        mode.lock().intel_gen12_views = None;
        assert!(matches!(
            admission(&q, &cpu, &events, 512, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
            Err(queue::SubmitError::Io(FsError::Unsupported))
        ));
        mode.lock().intel_gen12_views = Some(family);
        for (x, y) in [(65, 17), (7, 65)] {
            request(&cpu, fb, x, y, NONBLOCK | TEST_ONLY, None);
            assert!(admission(&q, &cpu, &events, 512, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC).is_err());
        }
        request(&cpu, fb, 7, 17, NONBLOCK | TEST_ONLY, None);
        cpu.write(512 + 3 * 8, &((7u64 << 16) | 1).to_le_bytes())
            .unwrap();
        assert!(admission(&q, &cpu, &events, 512, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC).is_err());
        if matches!(
            family,
            Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN
        ) {
            p.set(0x42084, 0);
            request(&cpu, fb, 7, 17, NONBLOCK, None);
            let failed = submit(&q, &cpu, &events, 512);
            run(q.run(&mut worker));
            assert!(failed.status() < 0);
            assert!(p.primary_mappings().is_empty() && p.dsb_mappings().is_empty());
            assert_eq!(p.read32(LIVE), CONSOLE);
        }
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_views_raw_test_only_bounds_capabilities_and_missing_dpt_refuse_before_dma
);

fn smoke_gen12_x_pan_prearm_rollback_and_partial_layout_fault_retain_plane_journal() -> TestResult {
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        let (p, mode, q, mut worker, cpu, events) = fixture(family, 512);
        let Some(a) = frame(&mode, 7, false) else {
            continue;
        };
        let b = frame(&mode, 7, true).unwrap();
        request(&cpu, a, 3, 9, NONBLOCK, None);
        let first = submit(&q, &cpu, &events, 512);
        run(q.run(&mut worker));
        assert_eq!(first.status(), 1);
        let old = p.primary_mappings();
        let live = p.read32(LIVE);
        let offset = p.read32(0x701a4);
        let original = resources(&p);
        p.set(0x60420, 1 << 31);
        request(&cpu, b, 7, 17, NONBLOCK | EVENT, None);
        let refused = submit(&q, &cpu, &events, 512);
        run(q.run(&mut worker));
        assert!(refused.status() < 0);
        assert_eq!(p.primary_mappings(), old);
        assert_eq!(p.read32(LIVE), live);
        assert_eq!(p.read32(0x701a4), offset);
        assert_eq!(p.read32(0x70188), 8);
        assert!(run(worker.device.session()).is_ok());
        p.set(0x60420, 0);
        p.refuse_layout(0x70180);
        p.stall_dsb(0, true);
        request(&cpu, b, 7, 17, NONBLOCK | EVENT, None);
        let failed = submit(&q, &cpu, &events, 512);
        let mut task = Box::pin(q.run(&mut worker));
        until(task.as_mut(), || armed(&p) && p.primary_mappings() != old);
        let both = p.primary_mappings();
        let dsb = p.dsb_mappings();
        p.stall_dsb(0, false);
        run(task);
        assert!(failed.status() < 0);
        assert_eq!(p.primary_mappings(), both);
        assert_eq!(p.dsb_mappings(), dsb);
        assert_eq!(p.read32(0x70180), control(family));
        assert_eq!(
            p.read32(0x70188),
            1,
            "partial new stride is retained, never adopted"
        );
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(a));
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        assert!(run(worker.device.session()).is_err());
        p.refuse_layout(u64::MAX);
        p.poison();
        run(worker.device.recover()).unwrap();
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert_eq!(p.read32(0x70188), 8);
        assert_eq!(p.read32(0x701a4), 0);
        assert!(p.primary_mappings().is_empty());
        assert_eq!(resources(&p), original);
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_x_pan_prearm_rollback_and_partial_layout_fault_retain_plane_journal
);

fn smoke_gen12_x_pan_cancel_master_and_reset_source_leaf_stalls_restore_linear_console(
) -> TestResult {
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        for stalled in [0, 1] {
            let profile = Profile::gen12(family);
            let (p, mode, q, mut worker, cpu, events) = fixture(family, 512);
            let Some(a) = frame(&mode, 7, true) else {
                continue;
            };
            let b = frame(&mode, 7, false).unwrap();
            let ga = gamma(&mode, profile, false);
            let gb = gamma(&mode, profile, true);
            request(&cpu, a, 7, 17, NONBLOCK, Some((0, ga)));
            let first = submit(&q, &cpu, &events, 512);
            run(q.run(&mut worker));
            assert_eq!(first.status(), 1);
            let original = resources(&p);
            let old_pages = pages(&p, &p.primary_mappings());
            let old_arms = p.primary_arms();
            p.stall_dsb(stalled, true);
            request(&cpu, b, 3, 9, NONBLOCK | EVENT, Some((0, gb)));
            let cancelled = submit(&q, &cpu, &events, 512);
            let mut task = Box::pin(q.run(&mut worker));
            until(task.as_mut(), || {
                armed(&p)
                    && pages(&p, &p.primary_mappings()) > old_pages
                    // With only the leaf stalled, the live source may still
                    // issue its pending surface arm. Observe that before
                    // cancellation; recovery must not issue a console arm
                    // until the independently stalled engine retires.
                    && (stalled == 0 || p.primary_arms() > old_arms)
            });
            let both = p.primary_mappings();
            let dsb = p.dsb_mappings();
            drop(task);
            assert!(cancelled.status() < 0);
            p.poison();
            let arms = p.primary_arms();
            let mut recovery = Box::pin(worker.device.recover());
            for _ in 0..3 {
                pending(recovery.as_mut());
            }
            assert_eq!(p.primary_arms(), arms);
            assert_eq!(p.primary_mappings(), both);
            assert_eq!(p.dsb_mappings(), dsb);
            p.stall_dsb(stalled, false);
            run(recovery).unwrap();
            assert_eq!(p.read32(LIVE), CONSOLE);
            assert_eq!(p.read32(0x70180), control(family));
            assert_eq!(p.read32(0x70188), 8);
            assert_eq!(p.read32(0x701a4), 0);
            assert!(p.primary_mappings().is_empty());
            assert_eq!(p.dsb_mappings(), dsb);
            assert_eq!(resources(&p), original);
            assert_eq!(p.read32(GAMMA), 0);
            assert!(!events.lock().has_deliverable_event(u64::MAX));
            mode.lock().master_release(7);
            mode.lock().master_open(8);
            let mut session = run(worker.device.session()).unwrap();
            run(restore_released_master(&mut session, &mode)).unwrap();
            drop(session);
            assert!(!mode.lock().intel_master_restore_pending());
            assert_eq!(p.unreadable_prec_reads(), 0);
            assert_eq!(p.forbidden_display_reads(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_x_pan_cancel_master_and_reset_source_leaf_stalls_restore_linear_console
);

fn smoke_gen12_x_cancel_master_handoff_retains_pending_view_until_linear_console_latch(
) -> TestResult {
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        let (p, mode, q, mut worker, cpu, events) = fixture(family, 512);
        let Some(fb) = frame(&mode, 7, true) else {
            continue;
        };
        let held = Arc::downgrade(
            &mode
                .lock()
                .framebuffer(fb)
                .unwrap()
                .intel
                .as_ref()
                .unwrap()
                .object,
        );
        let ctm = blob(&mode);
        let original = resources(&p);
        p.stall_dsb(0, true);
        request(&cpu, fb, 7, 17, NONBLOCK | EVENT, Some((ctm, 0)));
        let cancelled = submit(&q, &cpu, &events, 512);
        let mut task = Box::pin(q.run(&mut worker));
        until(task.as_mut(), || {
            armed(&p) && !p.primary_mappings().is_empty()
        });
        let primary = p.primary_mappings();
        let dsb = p.dsb_mappings();
        drop(task);
        assert!(cancelled.status() < 0);
        events.lock().close();
        mode.lock().release_file_framebuffers(7);
        mode.lock().master_release(7);
        mode.lock().master_open(8);
        assert!(held.upgrade().is_some());
        let replacement = Events::new(IrqSafeSpinLock::new(Default::default()));
        let (done, _, _) = run(q.submit(8, observe(), geometry(512), 1, &cpu, Some(&replacement)))
            .unwrap()
            .unwrap();
        let mut task = Box::pin(q.run(&mut worker));
        for _ in 0..3 {
            pending(task.as_mut());
        }
        assert_eq!(done.status(), 0);
        assert_eq!(p.primary_mappings(), primary);
        assert_eq!(p.dsb_mappings(), dsb);
        assert!(held.upgrade().is_some());
        p.stall_dsb(0, false);
        run(task);
        assert_eq!(done.status(), 1);
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert_eq!(p.read32(0x70180), control(family));
        assert_eq!(p.read32(0x70188), 8);
        assert_eq!(p.read32(0x701a4), 0);
        assert!(p.primary_mappings().is_empty());
        assert_eq!(p.dsb_mappings(), dsb);
        assert!(held.upgrade().is_none());
        assert_eq!(resources(&p), original);
        assert!(!mode.lock().intel_master_restore_pending());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_x_cancel_master_handoff_retains_pending_view_until_linear_console_latch
);

fn smoke_gen12_views_raw_missing_or_foreign_arb_slots_refuse_before_dma() -> TestResult {
    for family in families() {
        for wrong in [
            control(family) ^ 0x10000000,
            control(family) | 0x20000000,
            control(family) | 0x40000000,
        ] {
            let (p, mode, q, mut worker, cpu, events) = fixture(family, 512);
            let Some(fb) = frame(&mode, 7, true) else {
                continue;
            };
            // Published capabilities remain metadata; actual admission must
            // revalidate the immutable source family before any PTE or DSB.
            p.set(0x70180, wrong);
            request(&cpu, fb, 7, 17, NONBLOCK | TEST_ONLY, None);
            assert!(
                admission(&q, &cpu, &events, 512, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
                    .unwrap()
                    .is_none()
            );
            assert!(p.primary_mappings().is_empty() && p.dsb_mappings().is_empty());
            request(&cpu, fb, 7, 17, NONBLOCK | EVENT, None);
            let failed = submit(&q, &cpu, &events, 512);
            let fence = cpu.exported.lock()[0].clone();
            run(q.run(&mut worker));
            assert!(failed.status() < 0 && fence.status() < 0);
            assert!(p.primary_mappings().is_empty() && p.dsb_mappings().is_empty());
            assert!(p.arm_order().is_empty());
            assert_eq!(p.palette_writes() + p.pre_writes(), 0);
            assert_eq!(p.read32(LIVE), CONSOLE);
            assert!(!events.lock().has_deliverable_event(u64::MAX));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_views_raw_missing_or_foreign_arb_slots_refuse_before_dma
);
