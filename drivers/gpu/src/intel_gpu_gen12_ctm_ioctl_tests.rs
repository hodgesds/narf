// Raw atomic -> actual Card projection/FIFO -> retained Gen12 route/PTE/CSC.
// MIT Linux b90c984d intel_color.c: tgl_color_funcs and icl_color_commit_*.
// Gen12 exposes CTM alone; no MTL PAT/DSB, native LUT or cursor claim.
use super::*;
use crate::intel_gpu_gt::Gen12Platform;

const CSC: u64 = crate::intel_gpu_color::MODE;
const COEFFICIENT: u64 = 0x49010;
const ORIGINAL: u32 = 0x12345678;
const CONSOLE_PTE: u64 = crate::intel_gpu_gtt::GGTT_ARRAY_BASE + 0x1000000 / 4096 * 8;

fn families() -> [Gen12Platform; 4] {
    [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeS,
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
fn ctm_mode() -> ModeState {
    let mode = super::super::mode();
    {
        let mut card = mode.lock();
        card.intel_display = true;
        card.intel_ctm_only = true;
        card.crtc_color.push(crate::drm::card::CrtcColor::new(1));
    }
    mode
}
fn pending<F: Future>(future: core::pin::Pin<&mut F>) {
    assert!(future
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
}
fn admission(
    queue: &queue::Queue,
    cpu: &Cpu,
    events: &Events,
    open: u64,
    command: u32,
) -> Result<queue::Submitted, queue::SubmitError> {
    run(admit(
        queue,
        open,
        command,
        64,
        cpu,
        Some(events),
        geometry(),
        1,
    ))
}
fn atomic(cpu: &Cpu, flags: u32, objects: &[(u32, &[(u32, u64)])]) {
    let mut bytes = [0; 56];
    bytes[..4].copy_from_slice(&flags.to_le_bytes());
    bytes[4..8].copy_from_slice(&(objects.len() as u32).to_le_bytes());
    for (at, pointer) in [(8, 128u64), (16, 160), (24, 192), (32, 512)] {
        bytes[at..at + 8].copy_from_slice(&pointer.to_le_bytes());
    }
    cpu.write(64, &bytes).unwrap();
    let mut at = 0;
    for (i, (object, properties)) in objects.iter().enumerate() {
        cpu.write(128 + i as u64 * 4, &object.to_le_bytes())
            .unwrap();
        cpu.write(160 + i as u64 * 4, &(properties.len() as u32).to_le_bytes())
            .unwrap();
        for (property, value) in *properties {
            cpu.write(192 + at * 4, &property.to_le_bytes()).unwrap();
            cpu.write(512 + at * 8, &value.to_le_bytes()).unwrap();
            at += 1;
        }
    }
}

fn smoke_intel_gen12_ctm_only_raw_properties_test_only_and_lut_cursor_refusal() -> TestResult {
    let mode = ctm_mode();
    let id = blob(&mode);
    {
        let card = mode.lock();
        assert!(card.intel_ctm_supported(1));
        assert!(!card.intel_color(1) && !card.legacy_gamma_supported(1));
        assert!(!card.intel_ctm && !card.intel_x_tiled && !card.intel_tile4);
        assert_eq!(
            crtc_color_properties(&card, 1),
            (vec![CRTC_CTM_PROP_ID], vec![0])
        );
        for property in [CRTC_GAMMA_LUT_PROP_ID, CRTC_DEGAMMA_LUT_PROP_ID] {
            assert_eq!(
                crtc_color_property(&card, 1, property, 0, &mut CrtcColorChange::default()),
                Err(FsError::InvalidData)
            );
        }
    }
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    request(&cpu, id, NONBLOCK | TEST_ONLY);
    assert!(
        admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
            .unwrap()
            .is_none()
    );
    assert!(cpu.exported.lock().is_empty());
    for property in [CRTC_GAMMA_LUT_PROP_ID, CRTC_DEGAMMA_LUT_PROP_ID] {
        atomic(&cpu, NONBLOCK | TEST_ONLY, &[(1, &[(property, 0)])]);
        assert!(matches!(
            admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
            Err(queue::SubmitError::Io(FsError::Unsupported))
        ));
    }
    // Changed primary/route requests cannot enter the unqualified joint DSB.
    for (object, property, value) in [
        (1, CRTC_ACTIVE_PROP_ID, 0),
        (PLANE_ID_BASE, PLANE_FB_ID_PROP_ID, 0),
        (PLANE_ID_BASE, PLANE_CRTC_ID_PROP_ID, 0),
        (PLANE_ID_BASE, PLANE_SRC_X_PROP_ID, 1 << 16),
    ] {
        atomic(
            &cpu,
            NONBLOCK | TEST_ONLY | ALLOW_MODESET,
            &[
                (1, &[(CRTC_CTM_PROP_ID, u64::from(id))]),
                (object, &[(property, value)]),
            ],
        );
        assert!(matches!(
            admission(&queue, &cpu, &events, 7, drm_uapi::DRM_IOCTL_MODE_ATOMIC),
            Err(queue::SubmitError::Io(FsError::Unsupported))
        ));
    }
    // A bogus nested pointer is never copied for unadvertised legacy gamma.
    let mut bytes = [0xff; 32];
    bytes[..4].copy_from_slice(&1u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&256u32.to_le_bytes());
    cpu.write(64, &bytes).unwrap();
    assert!(matches!(
        admission(
            &queue,
            &cpu,
            &events,
            7,
            drm_uapi::iowr(b'd' as u32, 0xa5, 32)
        ),
        Err(queue::SubmitError::Io(FsError::NotImplemented))
    ));
    let mut cursor = [0u8; 36];
    cursor[..4].copy_from_slice(&1u32.to_le_bytes());
    cursor[4..8].copy_from_slice(&1u32.to_le_bytes());
    cpu.write(64, &cursor).unwrap();
    let gem = crate::intel_gpu_gem::GemState::new();
    assert!(matches!(
        run(admit_with_gem(
            &queue,
            7,
            drm_uapi::iowr(b'd' as u32, 0xbb, 36),
            64,
            &cpu,
            Some(&events),
            geometry(),
            1,
            Some(&gem)
        )),
        Err(queue::SubmitError::Io(FsError::Unsupported))
    ));
    assert!(mode.lock().destroy_property_blob(id));
    assert!(mode.lock().property_blob(id).is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gen12_ctm_only_raw_properties_test_only_and_lut_cursor_refusal
);

fn smoke_intel_gen12_ctm_raw_fifo_blob_pin_real_latch_and_original_clear() -> TestResult {
    for family in families() {
        let mode = ctm_mode();
        let id = blob(&mode);
        let queue = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let platform = MockPlatform::new();
        platform.set(COEFFICIENT, ORIGINAL);
        platform.set(0x4804, u32::MAX); // Gen12 never borrows MTL PAT authority.
        let device = Arc::new(platform.gen12(family));
        let mut worker = Worker {
            device: device.clone(),
        };
        request(&cpu, id, NONBLOCK | EVENT);
        let done = submit(&queue, &cpu, &events);
        let fence = cpu.exported.lock()[0].clone();
        drop(cpu);
        assert!(mode.lock().destroy_property_blob(id));
        assert!(mode.lock().property_blob(id).is_some());
        let mut work = Box::pin(queue.run(&mut worker));
        pending(work.as_mut());
        assert_eq!(platform.read32(CSC), 1 << 31);
        assert_eq!(platform.read32(COEFFICIENT), 0x78003000);
        assert_eq!((done.status(), fence.status()), (0, 0));
        assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, 0);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        assert!(platform.primary_mappings().is_empty() && platform.dsb_mappings().is_empty());
        assert_eq!(platform.palette_writes() + platform.pre_writes(), 0);
        assert_eq!(platform.primary_arms(), 0);
        run(work);
        assert_eq!((done.status(), fence.status()), (1, 1));
        assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, id);
        assert_eq!(
            crtc_color_properties(&mode.lock(), 1).1,
            vec![u64::from(id)]
        );
        let mut event = [0; 32];
        assert_eq!(
            events.lock().read_deliverable_event(u64::MAX, &mut event),
            Some(32)
        );
        assert_eq!(u32::from_le_bytes(event[24..28].try_into().unwrap()), 41);
        let cpu = Cpu::new();
        request(&cpu, 0, NONBLOCK);
        let cleared = submit(&queue, &cpu, &events);
        run(queue.run(&mut worker));
        assert_eq!(cleared.status(), 1);
        assert_eq!(
            (platform.read32(CSC), platform.read32(COEFFICIENT)),
            (0, ORIGINAL)
        );
        assert!(mode.lock().property_blob(id).is_none());
        assert!(device.legacy().is_ok());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gen12_ctm_raw_fifo_blob_pin_real_latch_and_original_clear
);

fn smoke_intel_gen12_ctm_raw_foreign_route_resources_and_color_refuse_before_arm() -> TestResult {
    for (register, value) in [
        (0x60400, 0x92000006),
        (0x60400, 0x88000006),
        (0xc7200, 0),
        (0x45008, 0),
        (0x70240, 0),
        (0x71008, 0xc0000000),
        (0x68180, 1 << 31),
        (0x4438c, 1 << 31),
        (CONSOLE_PTE, 0x100003),
        (0x70180, 0x84008000),
        (0x701cc, 0),
        (0x701c8, 1 << 31),
        (CSC, 1 << 30),
        (crate::intel_gpu_color::GAMMA, 1 << 31),
    ] {
        let mode = ctm_mode();
        let id = blob(&mode);
        let queue = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let platform = MockPlatform::new();
        platform.set(register, value);
        let mut worker = Worker {
            device: Arc::new(platform.gen12(Gen12Platform::AlderLakeP)),
        };
        request(&cpu, id, NONBLOCK | EVENT);
        let rejected = submit(&queue, &cpu, &events);
        let fence = cpu.exported.lock()[0].clone();
        run(queue.run(&mut worker));
        assert!(
            rejected.status() < 0 && fence.status() < 0,
            "foreign {register:#x} accepted"
        );
        assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, 0);
        assert!(platform.arm_order().is_empty());
        assert!(platform.primary_mappings().is_empty() && platform.dsb_mappings().is_empty());
        assert_eq!(platform.palette_writes() + platform.pre_writes(), 0);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gen12_ctm_raw_foreign_route_resources_and_color_refuse_before_arm
);

fn smoke_intel_gen12_ctm_cancel_and_master_close_restore_without_publication() -> TestResult {
    for close in [false, true] {
        let mode = ctm_mode();
        let id = blob(&mode);
        let queue = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let platform = MockPlatform::new();
        platform.set(COEFFICIENT, ORIGINAL);
        let device = Arc::new(platform.gen12(Gen12Platform::TigerLake));
        let mut worker = Worker {
            device: device.clone(),
        };
        request(&cpu, id, NONBLOCK | EVENT);
        let done = submit(&queue, &cpu, &events);
        let fence = cpu.exported.lock()[0].clone();
        mode.lock().destroy_property_blob(id);
        let mut work = Box::pin(queue.run(&mut worker));
        pending(work.as_mut());
        if close {
            mode.lock().master_release(7);
            run(work);
        } else {
            drop(work);
            assert_eq!(platform.read32(CSC), 1 << 31);
            assert!(device.legacy().is_err());
            let mut session = run(device.session()).unwrap();
            run(session.restore_console()).unwrap();
        }
        assert!(done.status() < 0 && fence.status() < 0);
        assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, 0);
        assert_eq!(
            (platform.read32(CSC), platform.read32(COEFFICIENT)),
            (0, ORIGINAL)
        );
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        assert!(mode.lock().property_blob(id).is_none());
        assert!(device.legacy().is_ok());
        assert!(platform.primary_mappings().is_empty() && platform.dsb_mappings().is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gen12_ctm_cancel_and_master_close_restore_without_publication
);

fn smoke_intel_gen12_ctm_reset_requires_original_resource_and_complete_console_proof() -> TestResult
{
    for family in families() {
        let mode = ctm_mode();
        let id = blob(&mode);
        let queue = queue::Queue::new(mode.clone());
        let cpu = Cpu::new();
        let events = Events::new(IrqSafeSpinLock::new(Default::default()));
        let platform = MockPlatform::new();
        platform.set(COEFFICIENT, ORIGINAL);
        let device = Arc::new(platform.gen12(family));
        let mut worker = Worker {
            device: device.clone(),
        };
        request(&cpu, id, NONBLOCK | EVENT);
        let done = submit(&queue, &cpu, &events);
        let fence = cpu.exported.lock()[0].clone();
        let mut work = Box::pin(queue.run(&mut worker));
        pending(work.as_mut());
        let watermark = platform.read32(0x70240);
        platform.poison();
        run(work);
        assert!(done.status() < 0 && fence.status() < 0);
        assert!(run(device.session()).is_err() && device.legacy().is_err());
        platform.set(0x70240, watermark ^ 1);
        assert!(run(device.recover()).is_err());
        platform.set(0x70240, watermark);
        platform.set(CONSOLE_PTE + 8, 0x101003);
        assert!(run(device.recover()).is_err());
        assert!(device.legacy().is_err());
        platform.set(CONSOLE_PTE + 8, 0x101001);
        run(device.recover()).unwrap();
        assert_eq!(
            (platform.read32(CSC), platform.read32(COEFFICIENT)),
            (0, ORIGINAL)
        );
        assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, 0);
        assert!(platform.primary_mappings().is_empty() && platform.dsb_mappings().is_empty());
        assert_eq!(platform.palette_writes() + platform.pre_writes(), 0);
        assert!(!events.lock().has_deliverable_event(u64::MAX));
        assert!(device.legacy().is_ok());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gen12_ctm_reset_requires_original_resource_and_complete_console_proof
);

fn smoke_intel_gen12_ctm_partial_arm_quarantines_until_fresh_original_replay() -> TestResult {
    let mode = ctm_mode();
    let id = blob(&mode);
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let platform = MockPlatform::new();
    platform.set(COEFFICIENT, ORIGINAL);
    platform.refuse_layout(CSC);
    let device = Arc::new(platform.gen12(Gen12Platform::AlderLakeS));
    let mut worker = Worker {
        device: device.clone(),
    };
    request(&cpu, id, NONBLOCK | EVENT);
    let done = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert!(done.status() < 0);
    assert_eq!(platform.read32(COEFFICIENT), 0x78003000);
    assert_eq!(platform.read32(CSC), 0);
    assert!(run(device.session()).is_err() && device.legacy().is_err());
    assert!(!events.lock().has_deliverable_event(u64::MAX));
    platform.poison();
    platform.refuse_layout(u64::MAX);
    run(device.recover()).unwrap();
    assert_eq!(
        (platform.read32(CSC), platform.read32(COEFFICIENT)),
        (0, ORIGINAL)
    );
    assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, 0);
    assert!(device.legacy().is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gen12_ctm_partial_arm_quarantines_until_fresh_original_replay
);

fn smoke_intel_gen12_ctm_replacement_master_projects_and_stale_close_preserves_new_matrix(
) -> TestResult {
    let mode = ctm_mode();
    let a = blob(&mode);
    let b = blob(&mode);
    let c = mode
        .lock()
        .create_property_blob(
            [2u64 << 32, 0, 0, 0, 1 << 32, 0, 0, 0, 1 << 32]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect(),
        )
        .unwrap();
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let platform = MockPlatform::new();
    let device = Arc::new(platform.gen12(Gen12Platform::AlderLakeN));
    let mut worker = Worker {
        device: device.clone(),
    };
    request(&cpu, a, NONBLOCK | EVENT);
    let abandoned = submit(&queue, &cpu, &events);
    let mut work = Box::pin(queue.run(&mut worker));
    pending(work.as_mut());
    drop(work);
    mode.lock().master_release(7);
    mode.lock().master_open(8);
    request(&cpu, b, NONBLOCK);
    let first = admission(&queue, &cpu, &events, 8, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
        .unwrap()
        .unwrap()
        .0;
    request(&cpu, c, NONBLOCK);
    let second = admission(&queue, &cpu, &events, 8, drm_uapi::DRM_IOCTL_MODE_ATOMIC)
        .unwrap()
        .unwrap()
        .0;
    for id in [a, b, c] {
        mode.lock().destroy_property_blob(id);
    }
    run(queue.run(&mut worker));
    assert!(abandoned.status() < 0);
    assert_eq!((first.status(), second.status()), (1, 1));
    assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, c);
    assert!(mode.lock().property_blob(a).is_none() && mode.lock().property_blob(b).is_none());
    assert!(mode.lock().property_blob(c).is_some());
    assert_eq!(
        (platform.read32(CSC), platform.read32(COEFFICIENT)),
        (1 << 31, 0x68003000)
    );
    let mut session = run(device.session()).unwrap();
    run(restore_released_master(&mut session, &mode)).unwrap();
    assert_eq!(platform.read32(CSC), 1 << 31);
    assert_eq!(platform.read32(COEFFICIENT), 0x68003000);
    run(session.restore_console()).unwrap();
    assert_eq!(platform.read32(CSC), 0);
    assert!(platform.primary_mappings().is_empty() && platform.dsb_mappings().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gen12_ctm_replacement_master_projects_and_stale_close_preserves_new_matrix
);

fn smoke_intel_gen12_ctm_coexists_with_owned_direct_primary_and_restores_both() -> TestResult {
    let mode = ctm_mode();
    let fb = match super::super::framebuffer(&mode, 7, true) {
        Ok(fb) => fb,
        Err(FsError::NotImplemented) => {
            assert!(cfg!(target_arch = "aarch64"));
            return TestResult::Pass;
        }
        Err(error) => panic!("Gen12 primary storage: {error:?}"),
    };
    let queue = queue::Queue::new(mode.clone());
    let cpu = Cpu::new();
    let events = Events::new(IrqSafeSpinLock::new(Default::default()));
    let platform = MockPlatform::new();
    platform.set(COEFFICIENT, ORIGINAL);
    let device = Arc::new(platform.gen12(Gen12Platform::TigerLake));
    let mut worker = Worker {
        device: device.clone(),
    };
    atomic(
        &cpu,
        NONBLOCK,
        &[(
            PLANE_ID_BASE,
            &[
                (PLANE_FB_ID_PROP_ID, u64::from(fb)),
                (PLANE_CRTC_ID_PROP_ID, 1),
            ],
        )],
    );
    let primary = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(primary.status(), 1);
    let live = platform.read32(0x701ac);
    let mappings = platform.primary_mappings();
    assert_eq!(mappings.iter().filter(|&&(r, _)| r % 8 == 0).count(), 2);
    for &(r, v) in &mappings {
        if r % 8 == 0 {
            assert_eq!(v & 4095, 1);
            assert!(platform.read32(r + 4) < 128);
        }
    }
    let id = blob(&mode);
    request(&cpu, id, NONBLOCK);
    let color = submit(&queue, &cpu, &events);
    run(queue.run(&mut worker));
    assert_eq!(color.status(), 1);
    assert_eq!(platform.read32(0x701ac), live);
    assert_eq!(platform.primary_mappings(), mappings);
    assert_eq!(mode.lock().crtcs[0].primary_fb, Some(fb));
    assert_eq!(mode.lock().crtc_color(1).unwrap().ctm, id);
    assert!(platform.dsb_mappings().is_empty());
    let mut session = run(device.session()).unwrap();
    run(session.restore_console()).unwrap();
    assert_eq!(platform.read32(0x701ac), 0x1000000);
    assert_eq!(
        (platform.read32(CSC), platform.read32(COEFFICIENT)),
        (0, ORIGINAL)
    );
    assert!(platform.primary_mappings().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_intel_gen12_ctm_coexists_with_owned_direct_primary_and_restores_both
);
