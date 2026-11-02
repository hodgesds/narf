// Raw atomic/legacy UAPI -> actual FIFO -> Gen12 native color owners.
// Display12's fine/coarse readout is deliberately unusable in the model.
use super::*;
use crate::intel_gpu_color::{Profile, MAX_COLOR_BLOB, MAX_COLOR_BLOB_TOTAL};
use crate::intel_gpu_gt::Gen12Platform;
fn families() -> [Gen12Platform; 4] {
    [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeS,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeN,
    ]
}
fn fixture(family: Gen12Platform) -> (MockPlatform, ModeState, queue::Queue, Worker, Cpu, Events) {
    let p = MockPlatform::new();
    p.gen12_cursor_resources(family);
    let mode = mode();
    {
        let mut c = mode.lock();
        c.intel_display = true;
        c.intel_ctm_only = true;
        c.intel_gen12_lut = Some(Profile::gen12(family));
        c.crtc_color.push(crate::drm::card::CrtcColor::new(1));
    }
    let q = queue::Queue::new(mode.clone());
    let worker = Worker {
        device: Arc::new(p.gen12(family)),
    };
    (
        p,
        mode,
        q,
        worker,
        Cpu::new(),
        Events::new(IrqSafeSpinLock::new(Default::default())),
    )
}
fn gamma(profile: Profile, variant: bool) -> Vec<u8> {
    let size = profile.sizes().0;
    let mut bytes = Vec::with_capacity(size * 8);
    for i in 0..size {
        let channels: [u16; 3] = if profile == Profile::Display12 {
            [
                (i / 4).min(65535) as u16,
                (i / 8).min(65535) as u16,
                (i / 16).min(65535) as u16,
            ]
        } else {
            [((size - i) * 63) as u16, (i * 31) as u16, (i * 15) as u16]
        };
        for v in channels {
            bytes.extend((if variant { v / 2 } else { v }).to_le_bytes());
        }
        bytes.extend([0, 0]);
    }
    bytes
}
fn pre(profile: Profile) -> Vec<u8> {
    (0..profile.sizes().1)
        .flat_map(|i| {
            let v = (i * 65535 / (profile.sizes().1 - 1)) as u16;
            [v, v, v, 0].into_iter().flat_map(u16::to_le_bytes)
        })
        .collect()
}
fn atomic(cpu: &Cpu, gamma: u32, pre: u32) {
    let mut header = [0; 56];
    header[..4].copy_from_slice(&NONBLOCK.to_le_bytes());
    header[4..8].copy_from_slice(&1u32.to_le_bytes());
    for (offset, ptr) in [(8, 128u64), (16, 144), (24, 160), (32, 192)] {
        header[offset..offset + 8].copy_from_slice(&ptr.to_le_bytes());
    }
    cpu.write(64, &header).unwrap();
    cpu.write(128, &1u32.to_le_bytes()).unwrap();
    cpu.write(144, &3u32.to_le_bytes()).unwrap();
    for (i, (prop, value)) in [
        (CRTC_GAMMA_LUT_PROP_ID, u64::from(gamma)),
        (CRTC_DEGAMMA_LUT_PROP_ID, u64::from(pre)),
        (CRTC_OUT_FENCE_PTR_PROP_ID, 512),
    ]
    .into_iter()
    .enumerate()
    {
        cpu.write(160 + i as u64 * 4, &prop.to_le_bytes()).unwrap();
        cpu.write(192 + i as u64 * 8, &value.to_le_bytes()).unwrap();
    }
}
fn smoke_gen12_lut_raw_native_sizes_q16_and_full_stream_or_exact_restore() -> TestResult {
    for family in families() {
        let profile = Profile::gen12(family);
        let (p, mode, q, mut worker, cpu, events) = fixture(family);
        {
            let c = mode.lock();
            assert!(c.intel_color(1) && c.legacy_gamma_supported(1));
            assert!(!c.intel_cursor_supported(1));
            assert!(!c.intel_ctm);
            let (_, values) = crtc_color_properties(&c, 1);
            assert_eq!(values[2], profile.sizes().0 as u64);
            assert_eq!(values[4], profile.sizes().1 as u64);
        }
        #[cfg(target_arch = "x86_64")]
        let original = p.precision();
        #[cfg(target_arch = "x86_64")]
        let original_pre = p.pre_palette();
        let post = mode
            .lock()
            .create_property_blob(gamma(profile, false))
            .unwrap();
        let pre = mode.lock().create_property_blob(pre(profile)).unwrap();
        atomic(&cpu, post, pre);
        let done = submit(&q, &cpu, &events);
        #[cfg(target_arch = "x86_64")]
        let fence = cpu.exported.lock()[0].clone();
        assert!(mode.lock().destroy_property_blob(post));
        assert!(mode.lock().destroy_property_blob(pre));
        let mut task = Box::pin(q.run(&mut worker));
        let first = task.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        #[cfg(target_arch = "x86_64")]
        {
            assert!(first.is_pending());
            assert_eq!(done.status(), 0);
            assert_eq!(fence.status(), 0);
            assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, 0);
            if profile == Profile::Display12 {
                assert_eq!(p.read32(crate::intel_gpu_color::GAMMA), 0);
                assert!(
                    p.dsb_commands().iter().all(|&(_, h)| h >> 24 != 1
                        || h & 0xfffff != crate::intel_gpu_color::GAMMA as u32),
                    "inactive preload must contain no LUT enable arm"
                );
            }
        }
        if first.is_pending() {
            run(task);
        } else {
            drop(task);
        }
        #[cfg(target_arch = "aarch64")]
        {
            assert!(done.status() < 0);
            assert!(p.dsb_mappings().is_empty());
            continue;
        }
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(done.status(), 1);
            assert_eq!(fence.status(), 1);
            assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, post);
            assert_eq!(
                p.read32(crate::intel_gpu_color::GAMMA),
                0xc0000000 | if profile == Profile::Display12 { 3 } else { 1 }
            );
            let loaded_pre = p.pre_palette();
            let size = profile.sizes().1;
            assert_eq!(loaded_pre[size - 1], 65535);
            assert_eq!(loaded_pre[size], 65536);
            assert_eq!(loaded_pre[size + 1], 65536);
            if profile == Profile::Display12 {
                assert_eq!(p.superfine_writes(), 18);
                assert_eq!(p.palette_writes(), 1024);
                assert_eq!(p.superfine()[16], 0x02004000);
                assert_eq!(p.precision()[0], 0x02004000);
                assert_eq!(p.precision()[515], 0x00400801);
                assert_eq!(
                    [p.read32(0x4a410), p.read32(0x4a414), p.read32(0x4a418)],
                    [65535, 32768, 16384]
                );
                assert_eq!(
                    p.unreadable_prec_reads(),
                    0,
                    "source does not offer fine/coarse readback"
                );
            }
            let mappings = p.dsb_mappings();
            let visible = p.precision();
            atomic(&cpu, 0, 0);
            let clear = submit(&q, &cpu, &events);
            run(q.run(&mut worker));
            assert_eq!(clear.status(), 1);
            assert_eq!(p.read32(crate::intel_gpu_color::GAMMA), 0);
            assert_eq!(p.read32(crate::intel_gpu_color::MODE), 0);
            assert_eq!(p.pre_palette(), original_pre);
            if profile == Profile::Display12 {
                assert_eq!(
                    p.precision(),
                    visible,
                    "bypass restoration leaves inactive canonical RAM exclusively owned"
                );
                assert_ne!(visible, original);
                assert_eq!(p.unreadable_prec_reads(), 0);
            } else {
                assert_eq!(
                    p.precision(),
                    original,
                    "display13 retains exact RAM restoration"
                );
            }
            assert!(mode.lock().property_blob(post).is_none());
            assert!(mode.lock().property_blob(pre).is_none());
            assert_eq!(p.dsb_mappings(), mappings);
            assert_eq!(p.forbidden_display_reads(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_lut_raw_native_sizes_q16_and_full_stream_or_exact_restore
);
fn smoke_gen12_lut_raw_replace_cancel_and_reset_stop_source_leaf_before_bypass() -> TestResult {
    #[cfg(target_arch = "x86_64")]
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        let profile = Profile::gen12(family);
        let (p, mode, q, mut worker, cpu, events) = fixture(family);
        let a = mode
            .lock()
            .create_property_blob(gamma(profile, false))
            .unwrap();
        let b = mode
            .lock()
            .create_property_blob(gamma(profile, true))
            .unwrap();
        atomic(&cpu, a, 0);
        let first = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(first.status(), 1);
        atomic(&cpu, b, 0);
        let changed = submit(&q, &cpu, &events);
        p.stall_dsb(1, true);
        let mut task = Box::pin(q.run(&mut worker));
        assert!(task
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        drop(task);
        assert!(changed.status() < 0);
        let mappings = p.dsb_mappings();
        let arms = p.primary_arms();
        let native_writes = p.writes().len();
        p.poison();
        let mut recovery = Box::pin(worker.device.recover());
        for _ in 0..3 {
            assert!(recovery
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(
            p.primary_arms(),
            arms,
            "fresh primary cannot outrun retained leaf DMA"
        );
        assert!(
            p.writes()[native_writes..]
                .iter()
                .all(|&(r, v)| r != crate::intel_gpu_color::GAMMA || v != 0),
            "fresh bypass cannot outrun retained leaf DMA"
        );
        assert_eq!(p.dsb_mappings(), mappings);
        p.stall_dsb(1, false);
        run(recovery).unwrap();
        assert_eq!(p.read32(crate::intel_gpu_color::GAMMA), 0);
        assert_eq!(p.read32(crate::intel_gpu_color::MODE), 0);
        assert_eq!(p.dsb_mappings(), mappings);
        assert_eq!(p.unreadable_prec_reads(), 0);
        assert_eq!(p.forbidden_display_reads(), 0);
        // Clear software publication after fresh recovery, then force a full
        // new table rewrite. Dirty inactive RAM is never adopted as a target.
        mode.lock().master_release(7);
        mode.lock().master_open(8);
        let mut session = run(worker.device.session()).unwrap();
        run(restore_released_master(&mut session, &mode)).unwrap();
        drop(session);
        let writes = p.palette_writes();
        atomic(&cpu, b, 0);
        let fresh = run(admit(
            &q,
            8,
            drm_uapi::DRM_IOCTL_MODE_ATOMIC,
            64,
            &cpu,
            Some(&events),
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
        run(q.run(&mut worker));
        assert_eq!(fresh.status(), 1);
        assert_eq!(p.palette_writes() - writes, 1024);
        if profile == Profile::Display12 {
            assert_eq!(p.read32(0x4a410), 32767);
        }
        let base = p.read32(crate::intel_gpu_color::GAMMA);
        let mut session = run(worker.device.session()).unwrap();
        run(restore_released_master(&mut session, &mode)).unwrap();
        drop(session);
        assert_eq!(
            p.read32(crate::intel_gpu_color::GAMMA),
            base,
            "stale A cleanup cannot restore over B's native LUT"
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_lut_raw_replace_cancel_and_reset_stop_source_leaf_before_bypass
);
fn smoke_gen12_lut_raw_bad_sizes_unsampled_monotonic_and_equal_rgb_refuse_before_dma() -> TestResult
{
    for family in families() {
        let profile = Profile::gen12(family);
        let (p, mode, q, _, cpu, events) = fixture(family);
        let mut bytes = gamma(profile, false);
        if profile == Profile::Display12 {
            bytes[17 * 8..17 * 8 + 2].copy_from_slice(&0u16.to_le_bytes());
        } else {
            bytes.truncate(1023 * 8);
        }
        let bad = mode.lock().create_property_blob(bytes).unwrap();
        atomic(&cpu, bad, 0);
        let result = run(admit(
            &q,
            7,
            drm_uapi::DRM_IOCTL_MODE_ATOMIC,
            64,
            &cpu,
            Some(&events),
            Geometry {
                width: 64,
                height: 32,
                pitch: 256,
            },
            1,
        ));
        assert!(result.is_err());
        let mut bytes = pre(profile);
        bytes[8..10].copy_from_slice(&99u16.to_le_bytes());
        let bad = mode.lock().create_property_blob(bytes).unwrap();
        atomic(&cpu, 0, bad);
        assert!(run(admit(
            &q,
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
        .is_err());
        assert!(p.dsb_mappings().is_empty());
        assert_eq!(p.palette_writes(), 0);
        assert_eq!(p.superfine_writes(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_lut_raw_bad_sizes_unsampled_monotonic_and_equal_rgb_refuse_before_dma
);
fn smoke_gen12_lut_raw_readable_loss_or_dsb_fault_never_publishes_and_retains_dma() -> TestResult {
    #[cfg(target_arch = "x86_64")]
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        for fault in [false, true] {
            let profile = Profile::gen12(family);
            let (p, mode, q, mut worker, cpu, events) = fixture(family);
            let id = mode
                .lock()
                .create_property_blob(gamma(profile, false))
                .unwrap();
            atomic(&cpu, id, 0);
            let done = submit(&q, &cpu, &events);
            let fence = cpu.exported.lock()[0].clone();
            if !fault {
                p.refuse_palette(true);
            }
            let mut task = Box::pin(q.run(&mut worker));
            assert!(task
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            if fault {
                p.set(0x70b28, 8);
            }
            run(task);
            assert!(done.status() < 0 && fence.status() < 0);
            assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, 0);
            assert!(!p.dsb_mappings().is_empty());
            assert!(run(worker.device.session()).is_err());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_lut_raw_readable_loss_or_dsb_fault_never_publishes_and_retains_dma
);

fn smoke_gen12_lut_raw_create_blob_exact_abi_and_total_storage_bound() -> TestResult {
    let (_, mode, _, _, _, _) = fixture(Gen12Platform::TigerLake);
    assert_eq!(MAX_COLOR_BLOB, 2097160);
    assert_eq!(property_blob_limit(&mode.lock()), 2097160);
    let mut wire = [0; 16];
    wire[..8].copy_from_slice(&4096u64.to_le_bytes());
    wire[8..12].copy_from_slice(&(MAX_COLOR_BLOB as u32).to_le_bytes());
    create_property_blob_owned(&mode, &mut wire, |ptr, len| {
        assert_eq!(ptr, 4096);
        assert_eq!(len, 2097160);
        Ok(gamma(Profile::Display12, false))
    })
    .unwrap();
    let id = u32::from_le_bytes(wire[12..16].try_into().unwrap());
    assert_eq!(mode.lock().property_blob(id).unwrap().len(), 2097160);
    wire[8..12].copy_from_slice(&((MAX_COLOR_BLOB + 1) as u32).to_le_bytes());
    assert_eq!(
        create_property_blob_owned(&mode, &mut wire, |_, _| panic!("oversized blob copied")),
        Err(FsError::InvalidData)
    );
    // Includes retained, user-destroyed blobs: storage accounting follows the
    // actual Card allocation, rather than only live userspace handles.
    let mut ids = vec![id];
    for _ in 1..MAX_COLOR_BLOB_TOTAL / MAX_COLOR_BLOB {
        ids.push(
            mode.lock()
                .create_property_blob(vec![0; MAX_COLOR_BLOB])
                .unwrap(),
        );
    }
    assert!(mode
        .lock()
        .create_property_blob(vec![0; MAX_COLOR_BLOB])
        .is_err());
    assert!(mode.lock().intel_retain_blob(ids[0]));
    mode.lock().destroy_property_blob(ids[0]);
    assert!(
        mode.lock()
            .create_property_blob(vec![0; MAX_COLOR_BLOB])
            .is_err(),
        "destroyed pinned blob still consumes the Card budget"
    );
    mode.lock().intel_release_blob(ids[0]);
    assert!(mode
        .lock()
        .create_property_blob(vec![0; MAX_COLOR_BLOB])
        .is_ok());
    let (_, other, _, _, _, _) = fixture(Gen12Platform::AlderLakeP);
    assert_eq!(property_blob_limit(&other.lock()), 1024 * 1024);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_lut_raw_create_blob_exact_abi_and_total_storage_bound
);

fn smoke_gen12_lut_raw_legacy256_set_get_and_dirty_bypass_reentry_full_rewrite() -> TestResult {
    #[cfg(target_arch = "x86_64")]
    for family in families() {
        let (p, mode, q, mut worker, cpu, events) = fixture(family);
        let profile = Profile::gen12(family);
        let id = mode
            .lock()
            .create_property_blob(gamma(profile, false))
            .unwrap();
        atomic(&cpu, id, 0);
        let native = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(native.status(), 1);
        let mut wire = [0; 32];
        wire[..4].copy_from_slice(&1u32.to_le_bytes());
        wire[4..8].copy_from_slice(&256u32.to_le_bytes());
        for (at, ptr) in [(8, 768u64), (16, 1280), (24, 1792)] {
            wire[at..at + 8].copy_from_slice(&ptr.to_le_bytes());
        }
        for i in 0..256 {
            for (ptr, v) in [
                (768u64, (i * 257) as u16),
                (1280, (65535 - i * 257) as u16),
                (1792, 55555u16),
            ] {
                cpu.write(ptr + i as u64 * 2, &v.to_le_bytes()).unwrap();
            }
        }
        cpu.write(64, &wire).unwrap();
        let done = run(admit(
            &q,
            7,
            drm_uapi::iowr(b'd' as u32, 0xa5, 32),
            64,
            &cpu,
            Some(&events),
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
        run(q.run(&mut worker));
        assert_eq!(done.status(), 1);
        assert_eq!(p.read32(crate::intel_gpu_color::GAMMA), 1 << 30);
        assert_eq!(get_legacy_gamma(&mode, 64, &cpu), Ok(0));
        assert_eq!(
            u16::from_le_bytes(cpu.bytes.lock()[1792..1794].try_into().unwrap()),
            55555
        );
        atomic(&cpu, 0, 0);
        let clear = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(clear.status(), 1);
        assert!(
            worker.device.legacy().is_ok(),
            "only confirmed visible bypass may enter the legacy guard"
        );
        if profile == Profile::Display12 {
            p.set(crate::intel_gpu_color::GAMMA, 1 << 30);
            assert!(
                worker.device.legacy().is_err(),
                "dirty RAM cannot be adopted as active gamma through legacy reentry"
            );
            p.set(crate::intel_gpu_color::GAMMA, 0);
        }
        let before = p.palette_writes();
        atomic(&cpu, id, 0);
        let again = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(again.status(), 1);
        assert_eq!(
            p.palette_writes() - before,
            1024,
            "activation always rewrites the entire native table"
        );
        assert_eq!(p.unreadable_prec_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_lut_raw_legacy256_set_get_and_dirty_bypass_reentry_full_rewrite
);

fn smoke_gen12_lut_raw_test_only_accepts_native_but_refuses_unqualified_joint() -> TestResult {
    for family in families() {
        let profile = Profile::gen12(family);
        let (p, mode, q, _, cpu, events) = fixture(family);
        let id = mode
            .lock()
            .create_property_blob(gamma(profile, false))
            .unwrap();
        atomic(&cpu, id, 0);
        cpu.write(64, &(NONBLOCK | TEST_ONLY).to_le_bytes())
            .unwrap();
        assert!(run(admit(
            &q,
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
        assert!(cpu.exported.lock().is_empty());
        let target = framebuffer(&mode, 7, true);
        #[cfg(target_arch = "aarch64")]
        if matches!(target, Err(FsError::NotImplemented)) {
            continue;
        }
        let target = target.unwrap();
        cpu.write(68, &2u32.to_le_bytes()).unwrap();
        cpu.write(132, &PLANE_ID_BASE.to_le_bytes()).unwrap();
        cpu.write(144, &1u32.to_le_bytes()).unwrap();
        cpu.write(148, &1u32.to_le_bytes()).unwrap();
        cpu.write(160, &CRTC_GAMMA_LUT_PROP_ID.to_le_bytes())
            .unwrap();
        cpu.write(164, &PLANE_FB_ID_PROP_ID.to_le_bytes()).unwrap();
        cpu.write(192, &u64::from(id).to_le_bytes()).unwrap();
        cpu.write(200, &u64::from(target).to_le_bytes()).unwrap();
        assert!(matches!(
            run(admit(
                &q,
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
            Err(queue::SubmitError::Io(FsError::Unsupported))
        ));
        assert!(p.dsb_mappings().is_empty());
        assert_eq!(p.palette_writes(), 0);
        assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_lut_raw_test_only_accepts_native_but_refuses_unqualified_joint
);

fn smoke_gen12_lut_concurrent_copy_budget_reserves_before_copy_and_releases_on_error() -> TestResult
{
    let (_, mode, _, _, _, _) = fixture(Gen12Platform::TigerLake);
    let budget = reserve_property_blob_copy(&mode, MAX_COLOR_BLOB_TOTAL).unwrap();
    let mut wire = [0; 16];
    wire[8..12].copy_from_slice(&(MAX_COLOR_BLOB as u32).to_le_bytes());
    assert_eq!(
        create_property_blob_owned(&mode, &mut wire, |_, _| panic!(
            "unreserved large user copy"
        )),
        Err(FsError::OutOfMemory)
    );
    drop(budget);
    assert_eq!(
        create_property_blob_owned(&mode, &mut wire, |_, _| Err(FsError::BadAddress)),
        Err(FsError::BadAddress)
    );
    assert!(
        reserve_property_blob_copy(&mode, MAX_COLOR_BLOB_TOTAL).is_ok(),
        "failed copy must return its full staging budget"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_lut_concurrent_copy_budget_reserves_before_copy_and_releases_on_error
);

fn smoke_gen12_lut_raw_missing_pipeline_or_resource_proof_refuses_before_dma() -> TestResult {
    for family in families() {
        for (r, v) in [
            (0x60400, 0x8a000007),
            (0x7027c, 2047 << 16),
            (crate::intel_gpu_pcode::PCODE_MAILBOX, 1 << 31),
            (crate::intel_gpu_color::GAMMA, 1 << 30),
            (0x701cc, 1 << 14),
        ] {
            let profile = Profile::gen12(family);
            let (p, mode, q, mut worker, cpu, events) = fixture(family);
            let id = mode
                .lock()
                .create_property_blob(gamma(profile, false))
                .unwrap();
            p.set(r, v);
            atomic(&cpu, id, 0);
            let done = submit(&q, &cpu, &events);
            run(q.run(&mut worker));
            assert!(done.status() < 0);
            assert!(p.dsb_mappings().is_empty());
            assert_eq!(p.palette_writes(), 0);
            assert_eq!(p.superfine_writes(), 0);
            assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_lut_raw_missing_pipeline_or_resource_proof_refuses_before_dma
);

fn smoke_gen12_lut_raw_cursor_capability_and_live_cursor_survive_native_clear() -> TestResult {
    #[cfg(target_arch = "x86_64")]
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        let profile = Profile::gen12(family);
        let (p, mode, q, mut worker, cpu, events) = fixture(family);
        assert!(!mode.lock().intel_cursor_supported(1));
        mode.lock().intel_hw_cursor = true;
        let gem = crate::intel_gpu_gem::GemState::new();
        let handle = gem.create(16384, |_, _| Ok(())).unwrap();
        gem.object(handle)
            .unwrap()
            .write(0, &vec![0x7a; 16384])
            .unwrap();
        let cursor = drm_uapi::iowr(b'd' as u32, 0xbb, 36);
        let wire: Vec<u8> = [3u32, 1, 2, 3, 64, 64, handle, 0, 0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        cpu.write(64, &wire).unwrap();
        let image = run(admit_with_gem(
            &q,
            7,
            cursor,
            64,
            &cpu,
            Some(&events),
            Geometry {
                width: 64,
                height: 32,
                pitch: 256,
            },
            1,
            Some(&gem),
        ))
        .unwrap()
        .unwrap()
        .0;
        run(q.run(&mut worker));
        assert_eq!(image.status(), 1);
        let base = p.read32(0x700ac);
        let mappings = p.cursor_mappings();
        assert_ne!(base, 0);
        let id = mode
            .lock()
            .create_property_blob(gamma(profile, false))
            .unwrap();
        atomic(&cpu, id, 0);
        let color = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(color.status(), 1);
        assert_eq!(p.read32(0x700ac), base);
        atomic(&cpu, 0, 0);
        let clear = submit(&q, &cpu, &events);
        run(q.run(&mut worker));
        assert_eq!(clear.status(), 1);
        assert_eq!(p.read32(0x700ac), base);
        assert_eq!(p.cursor_mappings(), mappings);
        p.set(0x60400, 0x8a000007);
        let wire: Vec<u8> = [2u32, 1, 4, 5, 64, 64, 0, 0, 0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        cpu.write(64, &wire).unwrap();
        let moved = run(admit_with_gem(
            &q,
            7,
            cursor,
            64,
            &cpu,
            Some(&events),
            Geometry {
                width: 64,
                height: 32,
                pitch: 256,
            },
            1,
            Some(&gem),
        ))
        .unwrap()
        .unwrap()
        .0;
        run(q.run(&mut worker));
        assert!(moved.status() < 0);
        assert_eq!(p.read32(0x700ac), base);
        assert_eq!(p.cursor_mappings(), mappings);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_lut_raw_cursor_capability_and_live_cursor_survive_native_clear
);

fn smoke_gen12_lut_raw_preload_cancel_retains_original_pre_and_never_enables() -> TestResult {
    #[cfg(target_arch = "x86_64")]
    {
        let (p, mode, q, mut worker, cpu, events) = fixture(Gen12Platform::TigerLake);
        let original_pre = p.pre_palette();
        let post = mode
            .lock()
            .create_property_blob(gamma(Profile::Display12, false))
            .unwrap();
        let pre = mode
            .lock()
            .create_property_blob(pre(Profile::Display12))
            .unwrap();
        atomic(&cpu, post, pre);
        let done = submit(&q, &cpu, &events);
        p.stall_dsb(1, true);
        let mut work = Box::pin(q.run(&mut worker));
        assert!(work
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert_eq!(p.read32(crate::intel_gpu_color::GAMMA), 0);
        let mappings = p.dsb_mappings();
        drop(work);
        assert!(done.status() < 0);
        mode.lock().destroy_property_blob(post);
        mode.lock().destroy_property_blob(pre);
        let mut guard = run(worker.device.session()).unwrap();
        let mut restore = Box::pin(guard.restore_console());
        for _ in 0..3 {
            assert!(restore
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            assert_eq!(p.read32(crate::intel_gpu_color::GAMMA), 0);
        }
        p.stall_dsb(1, false);
        run(restore).unwrap();
        drop(guard);
        assert_eq!(p.read32(crate::intel_gpu_color::GAMMA), 0);
        assert_eq!(p.read32(crate::intel_gpu_color::MODE), 0);
        assert_eq!(p.pre_palette(), original_pre);
        assert_eq!(p.dsb_mappings(), mappings);
        assert_eq!(p.unreadable_prec_reads(), 0);
        assert_eq!(mode.lock().crtc_color(1).unwrap().gamma_lut, 0);
        assert!(mode.lock().property_blob(post).is_none());
        assert!(mode.lock().property_blob(pre).is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_gen12_lut_raw_preload_cancel_retains_original_pre_and_never_enables
);
