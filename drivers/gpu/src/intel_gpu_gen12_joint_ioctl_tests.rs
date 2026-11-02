// Raw atomic ABI -> actual retained FIFO -> Gen12 primary + color + DSB.
// Source: MIT Linux b90c984d intel_display.c:7263-7406, intel_dsb.c:755-827,
// skl_universal_plane.c:1648-1694; no new timing, layout or output profile.
use super::*;
use crate::intel_gpu_color::{Profile, GAMMA, MODE};
use crate::intel_gpu_gt::Gen12Platform;
use alloc::sync::Weak;
use core::pin::Pin;

const SURF: u64 = 0x7019c;
const LIVE: u64 = 0x701ac;
const CONSOLE: u32 = 0x1000000;
fn families() -> [Gen12Platform; 4] {
    [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeS,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeN,
    ]
}
fn geometry() -> Geometry {
    Geometry {
        width: 64,
        height: 32,
        pitch: 256,
    }
}
fn fixture(family: Gen12Platform) -> (MockPlatform, ModeState, queue::Queue, Worker, Cpu, Events) {
    let p = MockPlatform::new();
    p.gen12_cursor_resources(family);
    let mode = mode();
    {
        let mut card = mode.lock();
        card.intel_display = true;
        card.intel_ctm_only = true;
        card.intel_gen12_lut = Some(Profile::gen12(family));
        card.intel_gen12_joint = true;
        card.crtc_color.push(crate::drm::card::CrtcColor::new(1));
        // Lastclose removes the old framebuffer and clears its CRTC mode.
        // The real fixed panel still advertises its timing, which the next
        // master's admission needs before its worker restores the console.
        let fixed = card.crtcs[0].mode.unwrap();
        card.encoders.push(crate::drm::card::Encoder {
            id: 2,
            encoder_type: crate::drm::card::EncoderType::Tmds,
            possible_crtcs: 1,
            possible_clones: 0,
            crtc_id: Some(1),
        });
        card.connectors.push(crate::drm::card::Connector {
            id: 3,
            connector_type: crate::drm::card::ConnectorType::Edp,
            connector_type_id: 1,
            status: crate::drm::card::ConnectorStatus::Connected,
            encoder_id: Some(2),
            modes: vec![fixed],
        });
    }
    let q = queue::Queue::new(mode.clone());
    let worker = Worker {
        device: Arc::new(p.gen12(family)),
    };
    assert_eq!(
        p.read32(0x70180),
        match family {
            Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN => 0x94000000,
            _ => 0x84000000,
        }
    );
    (
        p,
        mode,
        q,
        worker,
        Cpu::new(),
        Events::new(IrqSafeSpinLock::new(Default::default())),
    )
}
fn frame(mode: &ModeState, open: u64) -> Option<u32> {
    match framebuffer(mode, open, true) {
        Ok(id) => Some(id),
        Err(FsError::NotImplemented) => {
            assert!(cfg!(target_arch = "aarch64"));
            None
        }
        Err(e) => panic!("Gen12 joint WC frame: {e:?}"),
    }
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
fn post(mode: &ModeState, profile: Profile, legacy: bool, variant: bool) -> u32 {
    let size = if legacy { 256 } else { profile.sizes().0 };
    let bytes = (0..size)
        .flat_map(|i| {
            let v = (i as u64 * 65535 / (size - 1) as u64) as u16;
            let v = if variant { v / 2 } else { v };
            [v, v, v, 0].into_iter().flat_map(u16::to_le_bytes)
        })
        .collect();
    mode.lock().create_property_blob(bytes).unwrap()
}
fn pre(mode: &ModeState, profile: Profile) -> u32 {
    let size = profile.sizes().1;
    mode.lock()
        .create_property_blob(
            (0..size)
                .flat_map(|i| {
                    let v = (i * 65535 / (size - 1)) as u16;
                    [v, v, v, 0].into_iter().flat_map(u16::to_le_bytes)
                })
                .collect(),
        )
        .unwrap()
}
fn raw(cpu: &Cpu, flags: u32, objects: &[(u32, &[(u32, u64)])]) {
    let mut h = [0; 56];
    h[..4].copy_from_slice(&flags.to_le_bytes());
    h[4..8].copy_from_slice(&(objects.len() as u32).to_le_bytes());
    for (at, ptr) in [(8, 128u64), (16, 160), (24, 192), (32, 512)] {
        h[at..at + 8].copy_from_slice(&ptr.to_le_bytes());
    }
    h[48..56].copy_from_slice(&0x1288u64.to_le_bytes());
    cpu.write(64, &h).unwrap();
    let mut at = 0;
    for (i, (object, props)) in objects.iter().enumerate() {
        cpu.write(128 + i as u64 * 4, &object.to_le_bytes())
            .unwrap();
        cpu.write(160 + i as u64 * 4, &(props.len() as u32).to_le_bytes())
            .unwrap();
        for (prop, value) in *props {
            cpu.write(192 + at * 4, &prop.to_le_bytes()).unwrap();
            cpu.write(512 + at * 8, &value.to_le_bytes()).unwrap();
            at += 1;
        }
    }
}
fn joint(cpu: &Cpu, fb: u32, ctm: u32, post: u32, pre: u32, flags: u32) {
    raw(
        cpu,
        flags,
        &[
            (
                1,
                &[
                    (CRTC_CTM_PROP_ID, ctm.into()),
                    (CRTC_GAMMA_LUT_PROP_ID, post.into()),
                    (CRTC_DEGAMMA_LUT_PROP_ID, pre.into()),
                    (CRTC_OUT_FENCE_PTR_PROP_ID, 1024),
                ],
            ),
            (
                PLANE_ID_BASE,
                &[(PLANE_FB_ID_PROP_ID, fb.into()), (PLANE_CRTC_ID_PROP_ID, 1)],
            ),
        ],
    );
}
fn ctm_joint(cpu: &Cpu, fb: u32, ctm: u32, flags: u32) {
    raw(
        cpu,
        flags,
        &[
            (
                1,
                &[
                    (CRTC_CTM_PROP_ID, ctm.into()),
                    (CRTC_OUT_FENCE_PTR_PROP_ID, 1024),
                ],
            ),
            (
                PLANE_ID_BASE,
                &[(PLANE_FB_ID_PROP_ID, fb.into()), (PLANE_CRTC_ID_PROP_ID, 1)],
            ),
        ],
    );
}
fn admission(
    q: &queue::Queue,
    cpu: &Cpu,
    events: &Events,
    open: u64,
) -> Result<queue::Submitted, queue::SubmitError> {
    run(admit(
        q,
        open,
        drm_uapi::DRM_IOCTL_MODE_ATOMIC,
        64,
        cpu,
        Some(events),
        geometry(),
        1,
    ))
}
fn pending<F: Future>(f: Pin<&mut F>) {
    assert!(f.poll(&mut Context::from_waker(Waker::noop())).is_pending());
}
fn until<F: Future>(mut f: Pin<&mut F>, check: impl Fn() -> bool) {
    for _ in 0..24 {
        pending(f.as_mut());
        if check() {
            return;
        }
    }
    panic!("Gen12 joint fixture did not reach native hardware boundary");
}
fn sparse(p: &MockPlatform, mappings: &[(u64, u32)], pages: usize) {
    assert_eq!(mappings.iter().filter(|(r, _)| r % 8 == 0).count(), pages);
    for &(r, v) in mappings {
        if r % 8 == 0 {
            assert_eq!(v & 4095, 1);
            assert!(p.read32(r + 4) < 128);
        } else {
            assert!(v < 128);
        }
    }
}
fn restore(worker: &mut Worker) {
    let mut session = run(worker.device.session()).unwrap();
    run(session.restore_console()).unwrap();
}

fn smoke_gen12_joint_raw_test_only_independent_capability_and_fixed_linear_refusal() -> TestResult {
    for family in families() {
        let (p, mode, q, mut worker, cpu, events) = fixture(family);
        let Some(fb) = frame(&mode, 7) else {
            continue;
        };
        let ctm = blob(&mode);
        mode.lock().intel_gen12_lut = None; // CTM-only joint grants neither LUT nor cursor.
        assert!(!mode.lock().intel_color(1));
        assert!(!mode.lock().intel_cursor_supported(1));
        ctm_joint(&cpu, fb, ctm, NONBLOCK | TEST_ONLY);
        assert!(admission(&q, &cpu, &events, 7).unwrap().is_none());
        assert!(cpu.exported.lock().is_empty());
        assert_eq!(p.primary_arms(), 0);
        assert!(p.primary_mappings().is_empty() && p.dsb_mappings().is_empty());
        mode.lock().intel_gen12_joint = false;
        assert!(matches!(
            admission(&q, &cpu, &events, 7),
            Err(queue::SubmitError::Io(FsError::Unsupported))
        ));
        mode.lock().intel_gen12_joint = true;
        let wb = framebuffer(&mode, 7, false).unwrap();
        ctm_joint(&cpu, wb, ctm, NONBLOCK | TEST_ONLY);
        assert!(matches!(
            admission(&q, &cpu, &events, 7),
            Err(queue::SubmitError::Io(FsError::Unsupported))
        ));
        raw(
            &cpu,
            NONBLOCK | TEST_ONLY,
            &[
                (1, &[(CRTC_CTM_PROP_ID, ctm.into())]),
                (
                    PLANE_ID_BASE,
                    &[
                        (PLANE_FB_ID_PROP_ID, fb.into()),
                        (PLANE_CRTC_ID_PROP_ID, 1),
                        (PLANE_SRC_X_PROP_ID, 1 << 16),
                    ],
                ),
            ],
        );
        assert!(matches!(
            admission(&q, &cpu, &events, 7),
            Err(queue::SubmitError::Io(FsError::Unsupported))
        ));
        ctm_joint(&cpu, fb, ctm, NONBLOCK | EVENT);
        let done = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(done.status(), 1);
        assert_eq!(p.arm_order(), [GAMMA, MODE, SURF]);
        assert_eq!(p.palette_writes(), 0);
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(fb));
        assert!(!mode.lock().intel_cursor_supported(1));
        restore(&mut worker);
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_joint_raw_test_only_independent_capability_and_fixed_linear_refusal
);

fn smoke_gen12_joint_raw_native_full_stream_preload_and_both_retirement_witnesses() -> TestResult {
    for family in families() {
        let profile = Profile::gen12(family);
        let (p, mode, q, mut worker, cpu, events) = fixture(family);
        let Some(fb) = frame(&mode, 7) else {
            continue;
        };
        let ctm = blob(&mode);
        let gamma = post(&mode, profile, false, false);
        let pre = pre(&mode, profile);
        let original_pre = p.pre_palette();
        let original_post = p.precision();
        p.allow_flips(false);
        joint(&cpu, fb, ctm, gamma, pre, NONBLOCK | EVENT);
        let done = submit(&q, &cpu, &events);
        let fence = cpu.exported.lock()[0].clone();
        for id in [ctm, gamma, pre] {
            assert!(mode.lock().destroy_property_blob(id));
        }
        let mut task = Box::pin(q.run(&mut worker));
        pending(task.as_mut());
        if profile == Profile::Display12 {
            assert_eq!(p.read32(SURF), CONSOLE);
            assert!(
                p.primary_mappings().is_empty(),
                "inactive preload precedes primary stage"
            );
            #[cfg(target_arch = "x86_64")]
            assert!(p
                .dsb_commands()
                .iter()
                .all(|&(_, h)| h >> 24 != 1 || h & 0xfffff != SURF as u32));
        }
        until(task.as_mut(), || {
            p.read32(SURF) != CONSOLE && p.read32(0x70b08) == 0 && p.read32(0x70c08) == 0
        });
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert_eq!((done.status(), fence.status()), (0, 0));
        assert_eq!(mode.lock().crtcs[0].primary_fb, None);
        assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, 0);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        let order = p.arm_order();
        assert_eq!(&order[order.len() - 3..], [GAMMA, MODE, SURF]);
        sparse(&p, &p.primary_mappings(), 2);
        sparse(&p, &p.dsb_mappings(), 4);
        assert_eq!(p.pre_palette()[profile.sizes().1], 65536);
        if profile == Profile::Display12 {
            assert_eq!(p.superfine_writes(), 18);
            assert_eq!(p.palette_writes(), 1024);
        }
        p.allow_flips(true);
        run(task);
        assert_eq!((done.status(), fence.status()), (1, 1));
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(fb));
        assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, gamma);
        let mut event = [0; 32];
        assert_eq!(
            events.lock().read_deliverable_event(u64::MAX, &mut event),
            Some(32)
        );
        assert_eq!(
            u32::from_le_bytes(event[24..28].try_into().unwrap()),
            p.read32(0x70040)
        );
        let loaded = p.precision();
        let dsb = p.dsb_mappings();
        restore(&mut worker);
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert_eq!(p.read32(GAMMA), 0);
        assert_eq!(p.read32(MODE), 0);
        assert_eq!(p.pre_palette(), original_pre);
        assert_eq!(
            p.precision(),
            if profile == Profile::Display12 {
                loaded
            } else {
                original_post
            }
        );
        assert!(p.primary_mappings().is_empty());
        assert_eq!(p.dsb_mappings(), dsb);
        assert_eq!(p.unreadable_prec_reads(), 0);
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_joint_raw_native_full_stream_preload_and_both_retirement_witnesses
);

fn smoke_gen12_joint_raw_fifo_native_legacy_replacement_and_direct_primary_preserve_color(
) -> TestResult {
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        let profile = Profile::gen12(family);
        let (p, mode, q, mut worker, cpu, events) = fixture(family);
        let Some(a) = frame(&mode, 7) else {
            continue;
        };
        let b = frame(&mode, 7).unwrap();
        let c = frame(&mode, 7).unwrap();
        let old = weak(&mode, a);
        let ctm = blob(&mode);
        let native = post(&mode, profile, false, false);
        let legacy = post(&mode, profile, true, true);
        joint(&cpu, a, ctm, native, 0, NONBLOCK);
        let first = submit(&q, &cpu, &events);
        joint(&cpu, b, ctm, legacy, 0, NONBLOCK | EVENT);
        let second = submit(&q, &cpu, &events);
        for id in [native, legacy, ctm] {
            assert!(mode.lock().destroy_property_blob(id));
        }
        let mut task = Box::pin(q.run(&mut worker));
        until(task.as_mut(), || first.status() == 1);
        assert_eq!(second.status(), 0);
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(a));
        p.stall_dsb(1, true);
        until(task.as_mut(), || {
            p.primary_mappings()
                .iter()
                .filter(|(r, _)| r % 8 == 0)
                .count()
                == 4
        });
        let both = p.primary_mappings();
        sparse(&p, &both, 4);
        let dsb = p.dsb_mappings();
        for _ in 0..3 {
            pending(task.as_mut());
        }
        assert_eq!(p.primary_mappings(), both);
        assert!(old.upgrade().is_some());
        assert_eq!(second.status(), 0);
        p.stall_dsb(1, false);
        run(task);
        assert_eq!(second.status(), 1);
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(b));
        assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, legacy);
        assert_eq!(p.read32(GAMMA), 1 << 30);
        sparse(&p, &p.primary_mappings(), 2);
        mode.lock().rmfb(a).unwrap();
        assert!(old.upgrade().is_none());
        let arms = p.arm_order();
        let palette = p.palette_writes();
        let (done, _, _) = run(q.submit(
            7,
            atomic_frame(c, NONBLOCK),
            geometry(),
            1,
            &cpu,
            Some(&events),
        ))
        .unwrap()
        .unwrap();
        run(q.run(&mut worker));
        assert_eq!(done.status(), 1);
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(c));
        assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, legacy);
        assert_eq!(p.palette_writes(), palette);
        assert_eq!(p.dsb_mappings(), dsb);
        assert_eq!(p.arm_order().len(), arms.len() + 1);
        restore(&mut worker);
        assert_eq!(p.unreadable_prec_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_joint_raw_fifo_native_legacy_replacement_and_direct_primary_preserve_color
);

fn smoke_gen12_joint_raw_native_frame_and_shared_observation_required_before_publication(
) -> TestResult {
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        let (p, mode, q, mut worker, cpu, events) = fixture(family);
        let Some(fb) = frame(&mode, 7) else {
            continue;
        };
        let ctm = blob(&mode);
        p.allow_frames(false);
        ctm_joint(&cpu, fb, ctm, NONBLOCK | EVENT);
        let done = submit(&q, &cpu, &events);
        let mut task = Box::pin(q.run(&mut worker));
        for _ in 0..4 {
            pending(task.as_mut());
        }
        assert_ne!(p.read32(LIVE), CONSOLE);
        assert_eq!(done.status(), 0);
        p.tear_visible_frame(true);
        p.allow_frames(true);
        until(task.as_mut(), || {
            p.read32(0x70b08) == 0 && p.read32(SURF) != CONSOLE
        });
        for _ in 0..3 {
            pending(task.as_mut());
        }
        assert_eq!(done.status(), 0);
        assert_eq!(mode.lock().crtcs[0].primary_fb, None);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        let primary = p.primary_mappings();
        let dsb = p.dsb_mappings();
        p.tear_visible_frame(false);
        run(task);
        assert_eq!(done.status(), 1);
        assert_eq!(p.primary_mappings(), primary);
        assert_eq!(p.dsb_mappings(), dsb);
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(fb));
        restore(&mut worker);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_joint_raw_native_frame_and_shared_observation_required_before_publication
);

fn smoke_gen12_joint_raw_cancel_master_handoff_retains_both_owners_until_fresh_console(
) -> TestResult {
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        let profile = Profile::gen12(family);
        let (p, mode, q, mut worker, cpu, events) = fixture(family);
        let Some(a) = frame(&mode, 7) else {
            continue;
        };
        let b = frame(&mode, 7).unwrap();
        let old = weak(&mode, b);
        let ctm = blob(&mode);
        let ga = post(&mode, profile, false, false);
        let gb = post(&mode, profile, false, true);
        joint(&cpu, a, ctm, ga, 0, NONBLOCK);
        let first = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(first.status(), 1);
        p.stall_dsb(1, true);
        joint(&cpu, b, ctm, gb, 0, NONBLOCK | EVENT);
        let cancelled = submit(&q, &cpu, &events);
        let mut task = Box::pin(q.run(&mut worker));
        until(task.as_mut(), || p.read32(SURF) != p.read32(LIVE));
        drop(task);
        assert!(cancelled.status() < 0);
        let primary = p.primary_mappings();
        let dsb = p.dsb_mappings();
        events.lock().close();
        mode.lock().release_file_framebuffers(7);
        mode.lock().master_release(7);
        mode.lock().master_open(8);
        assert!(old.upgrade().is_some());
        let replacement = Events::new(IrqSafeSpinLock::new(Default::default()));
        let (done, _, _) = run(q.submit(8, observe(), geometry(), 1, &cpu, Some(&replacement)))
            .unwrap()
            .unwrap();
        let mut task = Box::pin(q.run(&mut worker));
        for _ in 0..3 {
            pending(task.as_mut());
        }
        assert_eq!(done.status(), 0);
        assert_eq!(p.primary_mappings(), primary);
        assert_eq!(p.dsb_mappings(), dsb);
        assert!(old.upgrade().is_some());
        p.stall_dsb(1, false);
        run(task);
        assert_eq!(done.status(), 1);
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert_eq!(p.read32(GAMMA), 0);
        assert_eq!(p.read32(MODE), 0);
        assert!(p.primary_mappings().is_empty());
        assert_eq!(p.dsb_mappings(), dsb);
        assert!(old.upgrade().is_none());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        assert!(!mode.lock().intel_master_restore_pending());
        assert!(!mode.lock().crtcs[0].enabled);
        assert!(mode.lock().crtcs[0].mode.is_none());
        let c = frame(&mode, 8).unwrap();
        // RMFB disabled the old software CRTC. Re-enable the advertised fixed
        // timing through the real raw ABI before a later joint color commit.
        // A color commit cannot substitute for this non-color activation.
        let fixed_blob = {
            let mut card = mode.lock();
            let fixed = card
                .connectors
                .iter()
                .find(|connector| connector.id == 3)
                .unwrap()
                .modes[0];
            let wire = card.mode_wire(&fixed);
            // drm_mode_modeinfo is exactly 68 bytes; CTM's 72-byte encoding
            // is unrelated. Match DrmModeModeInfo::from_bytes independently.
            let mut bytes = vec![0; 68];
            bytes[..4].copy_from_slice(&wire.clock.to_ne_bytes());
            for (index, value) in [
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
                bytes[4 + index * 2..6 + index * 2].copy_from_slice(&value.to_ne_bytes());
            }
            bytes[24..28].copy_from_slice(&wire.vrefresh.to_ne_bytes());
            bytes[28..32].copy_from_slice(&wire.flags.to_ne_bytes());
            bytes[32..36].copy_from_slice(&wire.r#type.to_ne_bytes());
            bytes[36..68].copy_from_slice(&wire.name);
            card.create_property_blob(bytes).unwrap()
        };
        let bypass_writes = p.palette_writes();
        raw(
            &cpu,
            ALLOW_MODESET | NONBLOCK,
            &[
                (
                    1,
                    &[
                        (CRTC_MODE_ID_PROP_ID, fixed_blob.into()),
                        (CRTC_ACTIVE_PROP_ID, 1),
                        (CRTC_OUT_FENCE_PTR_PROP_ID, 1024),
                    ],
                ),
                (
                    PLANE_ID_BASE,
                    &[(PLANE_FB_ID_PROP_ID, c.into()), (PLANE_CRTC_ID_PROP_ID, 1)],
                ),
            ],
        );
        let (activated, _, _) = admission(&q, &cpu, &replacement, 8).unwrap().unwrap();
        run(q.run(&mut worker));
        assert_eq!(activated.status(), 1);
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(c));
        assert!(mode.lock().crtcs[0].enabled);
        assert_eq!(
            mode.lock().crtcs[0]
                .mode
                .map(|fixed| (fixed.width, fixed.height)),
            Some((64, 32))
        );
        assert_ne!(p.read32(LIVE), CONSOLE);
        assert_eq!(p.read32(GAMMA), 0);
        assert_eq!(p.read32(MODE), 0);
        assert_eq!(p.palette_writes(), bypass_writes);
        let writes = p.palette_writes();
        joint(&cpu, c, 0, gb, 0, NONBLOCK);
        let (fresh, _, _) = admission(&q, &cpu, &replacement, 8).unwrap().unwrap();
        run(q.run(&mut worker));
        assert_eq!(fresh.status(), 1);
        assert_eq!(
            p.palette_writes() - writes,
            1024,
            "dirty inactive RAM must receive a complete new native stream"
        );
        restore(&mut worker);
        assert_eq!(p.unreadable_prec_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_joint_raw_cancel_master_handoff_retains_both_owners_until_fresh_console
);

fn smoke_gen12_joint_raw_reset_retires_source_then_leaf_before_console_and_mapping_release(
) -> TestResult {
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        for stalled in [0, 1] {
            let profile = Profile::gen12(family);
            let (p, mode, q, mut worker, cpu, events) = fixture(family);
            let Some(a) = frame(&mode, 7) else {
                continue;
            };
            let b = frame(&mode, 7).unwrap();
            let ctm = blob(&mode);
            let ga = post(&mode, profile, false, false);
            let gb = post(&mode, profile, false, true);
            joint(&cpu, a, ctm, ga, 0, NONBLOCK);
            let first = submit(&q, &cpu, &events);
            run(q.run(&mut worker));
            assert_eq!(first.status(), 1);
            p.stall_dsb(stalled, true);
            joint(&cpu, b, ctm, gb, 0, NONBLOCK | EVENT);
            let failed = submit(&q, &cpu, &events);
            let mut task = Box::pin(q.run(&mut worker));
            pending(task.as_mut());
            pending(task.as_mut());
            let primary = p.primary_mappings();
            let dsb = p.dsb_mappings();
            let arms = p.primary_arms();
            p.poison();
            run(task);
            assert!(failed.status() < 0);
            let mut recovery = Box::pin(worker.device.recover());
            for _ in 0..3 {
                pending(recovery.as_mut());
            }
            assert_eq!(p.primary_mappings(), primary);
            assert_eq!(p.dsb_mappings(), dsb);
            assert_eq!(p.primary_arms(), arms);
            assert_eq!(mode.lock().crtcs[0].primary_fb, Some(a));
            assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, ga);
            drop(recovery);
            assert!(run(worker.device.session()).is_err());
            p.stall_dsb(stalled, false);
            run(worker.device.recover()).unwrap();
            assert!(p.primary_mappings().is_empty());
            assert_eq!(p.dsb_mappings(), dsb);
            assert_eq!(p.read32(LIVE), CONSOLE);
            assert_eq!(p.read32(GAMMA), 0);
            assert_eq!(p.read32(MODE), 0);
            assert!(!events.lock().has_deliverable_event(u64::MAX));
            assert_eq!(p.unreadable_prec_reads(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_joint_raw_reset_retires_source_then_leaf_before_console_and_mapping_release
);

fn smoke_gen12_joint_raw_partial_fault_or_failed_surface_arm_quarantines_both_dma_owners(
) -> TestResult {
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        for fault in [0, 1, 2, 3] {
            let profile = Profile::gen12(family);
            let (p, mode, q, mut worker, cpu, events) = fixture(family);
            let Some(a) = frame(&mode, 7) else {
                continue;
            };
            let b = frame(&mode, 7).unwrap();
            let ctm = blob(&mode);
            let ga = post(&mode, profile, false, false);
            let gb = post(&mode, profile, false, true);
            joint(&cpu, a, ctm, ga, 0, NONBLOCK);
            let first = submit(&q, &cpu, &events);
            run(q.run(&mut worker));
            assert_eq!(first.status(), 1);
            if fault == 0 {
                if profile == Profile::Display12 {
                    // Fine/coarse are unreadable: fail the reliable endpoint,
                    // rather than pretend discarded fine writes are observable.
                    p.refuse_layout(0x4a410);
                } else {
                    p.refuse_palette(true);
                }
            }
            if fault == 3 {
                p.refuse_layout(SURF);
            }
            joint(&cpu, b, ctm, gb, 0, NONBLOCK | EVENT);
            let failed = submit(&q, &cpu, &events);
            let mut task = Box::pin(q.run(&mut worker));
            pending(task.as_mut());
            let primary = p.primary_mappings();
            let dsb = p.dsb_mappings();
            if fault == 1 {
                p.set(0x44408, 1 << 7);
            }
            if fault == 2 {
                p.set(0x70b28, 2);
            }
            if fault == 3 {
                until(task.as_mut(), || {
                    p.read32(0x70b08) == 0 && p.read32(0x70c08) == 0
                });
                p.advance_time(1_000_000_000);
            }
            run(task);
            assert!(failed.status() < 0);
            assert_eq!(mode.lock().crtcs[0].primary_fb, Some(a));
            assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, ga);
            assert_eq!(p.primary_mappings(), primary);
            assert_eq!(p.dsb_mappings(), dsb);
            assert!(!events.lock().has_deliverable_event(u64::MAX));
            assert!(run(worker.device.session()).is_err());
            p.refuse_palette(false);
            p.refuse_layout(u64::MAX);
            p.set(0x44408, 0);
            if fault == 2 {
                p.set(0x70b28, 0);
            }
            p.poison();
            run(worker.device.recover()).unwrap();
            assert_eq!(p.read32(LIVE), CONSOLE);
            assert!(p.primary_mappings().is_empty());
            assert_eq!(p.dsb_mappings(), dsb);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_joint_raw_partial_fault_or_failed_surface_arm_quarantines_both_dma_owners
);

fn smoke_gen12_joint_raw_prearm_refusal_or_resource_loss_never_releases_a_live_target() -> TestResult
{
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        let (p, mode, q, mut worker, cpu, events) = fixture(family);
        let Some(a) = frame(&mode, 7) else {
            continue;
        };
        let b = frame(&mode, 7).unwrap();
        let ctm = blob(&mode);
        ctm_joint(&cpu, a, ctm, NONBLOCK);
        let first = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(first.status(), 1);
        let front = p.primary_mappings();
        let dsb = p.dsb_mappings();
        let live = p.read32(LIVE);
        p.set(0x60420, 1 << 31);
        ctm_joint(&cpu, b, ctm, NONBLOCK | EVENT);
        let refused = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert!(refused.status() < 0);
        assert_eq!(p.primary_mappings(), front);
        assert_eq!(p.dsb_mappings(), dsb);
        assert_eq!(p.read32(LIVE), live);
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(a));
        assert!(run(worker.device.session()).is_ok());
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        p.set(0x60420, 0);
        ctm_joint(&cpu, b, ctm, NONBLOCK | EVENT);
        let failed = submit(&q, &cpu, &events);
        p.allow_flips(false);
        let mut task = Box::pin(q.run(&mut worker));
        pending(task.as_mut());
        pending(task.as_mut());
        let both = p.primary_mappings();
        let ddb = p.read32(0x7027c);
        p.set(0x7027c, ddb ^ 1);
        p.allow_flips(true);
        run(task);
        assert!(failed.status() < 0);
        assert_eq!(p.primary_mappings(), both);
        assert_eq!(p.dsb_mappings(), dsb);
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(a));
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        p.set(0x7027c, ddb);
        p.poison();
        run(worker.device.recover()).unwrap();
        assert!(p.primary_mappings().is_empty());
        assert_eq!(p.read32(LIVE), CONSOLE);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_joint_raw_prearm_refusal_or_resource_loss_never_releases_a_live_target
);

fn smoke_gen12_joint_raw_independent_live_cursor_survives_same_frame_native_and_clear() -> TestResult
{
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        let profile = Profile::gen12(family);
        let (p, mode, q, mut worker, cpu, events) = fixture(family);
        let Some(fb) = frame(&mode, 7) else {
            continue;
        };
        mode.lock().intel_hw_cursor = true;
        let gem = crate::intel_gpu_gem::GemState::new();
        let handle = gem.create(16384, |_, _| Ok(())).unwrap();
        gem.object(handle)
            .unwrap()
            .write(0, &vec![0x7a; 16384])
            .unwrap();
        let wire: Vec<u8> = [3u32, 1, 2, 3, 64, 64, handle, 0, 0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        cpu.write(64, &wire).unwrap();
        let cursor = run(admit_with_gem(
            &q,
            7,
            drm_uapi::iowr(b'd' as u32, 0xbb, 36),
            64,
            &cpu,
            Some(&events),
            geometry(),
            1,
            Some(&gem),
        ))
        .unwrap()
        .unwrap()
        .0;
        run(q.run(&mut worker));
        assert_eq!(cursor.status(), 1);
        let base = p.read32(0x700ac);
        let cursor_maps = p.cursor_mappings();
        assert_ne!(base, 0);
        sparse(&p, &cursor_maps, 8);
        let ctm = blob(&mode);
        let gamma = post(&mode, profile, false, false);
        joint(&cpu, fb, ctm, gamma, 0, NONBLOCK | EVENT);
        let shown = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(shown.status(), 1);
        assert_eq!(p.read32(0x700ac), base);
        assert_eq!(p.cursor_mappings(), cursor_maps);
        let writes = p.palette_writes();
        joint(&cpu, fb, 0, 0, 0, NONBLOCK);
        let clear = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(clear.status(), 1);
        assert_eq!(p.read32(GAMMA), 0);
        assert_eq!(p.read32(MODE), 0);
        assert_eq!(p.read32(0x700ac), base);
        assert_eq!(p.cursor_mappings(), cursor_maps);
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(fb));
        assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, 0);
        if profile == Profile::Display12 {
            assert_eq!(p.palette_writes(), writes);
        }
        restore(&mut worker);
        assert_eq!(p.read32(0x700ac), 0);
        assert_eq!(p.read32(LIVE), CONSOLE);
        assert!(p.primary_mappings().is_empty());
        assert_eq!(p.cursor_mappings(), cursor_maps);
        assert_eq!(p.unreadable_prec_reads(), 0);
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_joint_raw_independent_live_cursor_survives_same_frame_native_and_clear
);

fn smoke_gen12_joint_raw_stale_advertisement_without_route_console_or_pcode_proof_refuses_dma(
) -> TestResult {
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        for missing in 0..4 {
            let (p, mode, q, mut worker, cpu, events) = fixture(family);
            let Some(fb) = frame(&mode, 7) else {
                continue;
            };
            let ctm = blob(&mode);
            ctm_joint(&cpu, fb, ctm, NONBLOCK | TEST_ONLY);
            assert!(admission(&q, &cpu, &events, 7).unwrap().is_none());
            match missing {
                0 => p.set(0x60400, 0x8a000007),
                1 => p.set(0x7027c, p.read32(0x7027c) ^ 1),
                2 => p.set(
                    crate::intel_gpu_gtt::GGTT_ARRAY_BASE + 0x1000000 / 4096 * 8 + 8,
                    0,
                ),
                _ => p.pcode_values([0; 8], 10, 0),
            }
            ctm_joint(&cpu, fb, ctm, NONBLOCK | EVENT);
            let failed = submit(&q, &cpu, &events);
            run(q.run(&mut worker));
            assert!(failed.status() < 0);
            assert_eq!(mode.lock().crtcs[0].primary_fb, None);
            assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, 0);
            assert!(p.primary_mappings().is_empty() && p.dsb_mappings().is_empty());
            assert_eq!(p.primary_arms(), 0);
            assert_eq!(p.read32(LIVE), CONSOLE);
            assert!(!events.lock().has_deliverable_event(u64::MAX));
            assert_eq!(p.forbidden_display_reads(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_joint_raw_stale_advertisement_without_route_console_or_pcode_proof_refuses_dma
);
