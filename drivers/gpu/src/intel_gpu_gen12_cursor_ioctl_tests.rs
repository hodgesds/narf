// Raw CURSOR2 -> Card projection/FIFO -> real Gen12 WC/GGTT/DSB/latch.
// LUT and joint primary/color capability remains deliberately absent.
use super::*;
use crate::intel_gpu_gt::Gen12Platform;
fn families() -> [Gen12Platform; 4] {
    [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeS,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeN,
    ]
}
fn fixture(family: Gen12Platform) -> (MockPlatform, ModeState, queue::Queue, Worker, Cpu) {
    let p = MockPlatform::new();
    p.gen12_cursor_resources(family);
    let mode = mode();
    {
        let mut card = mode.lock();
        card.intel_display = true;
        card.intel_ctm_only = true;
        card.intel_hw_cursor = true;
        card.crtc_color.push(crate::drm::card::CrtcColor::new(1));
    }
    let queue = queue::Queue::new(mode.clone());
    let worker = Worker {
        device: Arc::new(p.gen12(family)),
    };
    (p, mode, queue, worker, Cpu::new())
}
fn smoke_gen12_cursor_raw_fifo_family_ctl_pat_free_mapping_and_fixed_partition() -> TestResult {
    for family in families() {
        let (p, mode, q, mut worker, cpu) = fixture(family);
        {
            let card = mode.lock();
            assert!(card.intel_cursor_supported(1));
            assert!(card.intel_ctm_supported(1));
            assert!(!card.intel_ctm && !card.intel_color(1) && !card.legacy_gamma_supported(1));
        }
        let (gem, handle) = make_gem();
        #[cfg(target_arch = "x86_64")]
        let partition = (p.read32(0x7027c), p.read32(0x7017c));
        p.set(0x44408, (1 << 18) | (1 << 24)); // Gen12 owns no ATS status.
        p.stall_dsb(0, true);
        request(&cpu, 3, handle, -2, 3);
        let done = submit(&q, &cpu, &gem);
        let mut task = Box::pin(q.run(&mut worker));
        let first = task.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        #[cfg(target_arch = "x86_64")]
        {
            assert!(first.is_pending());
            poll_cursor_armed(&p, task.as_mut());
            assert_eq!(done.status(), 0);
            let commands = p.dsb_commands();
            let write = |register| {
                commands
                    .iter()
                    .position(|&(_, h)| h >> 24 == 1 && h & 0xfffff == register)
                    .unwrap()
            };
            let evasion = commands
                .iter()
                .position(|&(l, h)| h >> 24 == 6 && l != 0)
                .unwrap();
            assert!(evasion < write(0x70140) && write(0x7017c) < write(0x700a0));
            assert!(
                write(0x700a0) < write(0x70080)
                    && write(0x70080) < write(0x70088)
                    && write(0x70088) < write(0x70084)
            );
        }
        p.stall_dsb(0, false);
        if first.is_pending() {
            run(task);
        } else {
            drop(task);
        }
        #[cfg(target_arch = "aarch64")]
        {
            assert!(done.status() < 0);
            continue;
        }
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(done.status(), 1);
            assert_eq!(
                p.read32(0x44408) & ((1 << 18) | (1 << 24)),
                (1 << 18) | (1 << 24)
            );
            let ctl = if matches!(
                family,
                Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN
            ) {
                0x10000027
            } else {
                0x27
            };
            assert_eq!(p.read32(0x70080), ctl);
            assert_eq!(p.read32(0x700a0), 0);
            let base = p.read32(0x700ac);
            assert_ne!(base, 0);
            assert_eq!(base, p.read32(0x70084));
            let dsb = p.dsb_mappings();
            let cursor = p.cursor_mappings();
            assert!(!dsb.is_empty() && !cursor.is_empty());
            for &(r, v) in dsb.iter().chain(&cursor) {
                if r % 8 == 0 {
                    assert_eq!(v & 4095, 1, "Gen12 GGTT has no PAT index");
                    assert!(p.read32(r + 4) < 128);
                } else {
                    assert!(v < 128, "all DMA lies below the 39-bit mask");
                }
            }
            assert!(p
                .dsb_writes()
                .iter()
                .filter(|&&(r, _)| r == 0x70b28 || r == 0x70c28)
                .all(|&(_, v)| v & ((1 << 4) | (1 << 20)) == 0));
            gem.object(handle)
                .unwrap()
                .write(0, &vec![0x3b; 16384])
                .unwrap();
            request(&cpu, 1, handle, 0, 0);
            let replaced = submit(&q, &cpu, &gem);
            run(q.run(&mut worker));
            assert_eq!(replaced.status(), 1);
            assert_ne!(p.read32(0x700ac), base);
            request(&cpu, 2, 0, 400, 0);
            let offscreen = submit(&q, &cpu, &gem);
            run(q.run(&mut worker));
            assert_eq!(offscreen.status(), 1);
            assert_eq!(p.read32(0x700ac), 0);
            assert_eq!(
                p.read32(0x70140),
                0,
                "offscreen fetch WMs are disabled; DDB stays reserved"
            );
            request(&cpu, 2, 0, 5, -4);
            let visible = submit(&q, &cpu, &gem);
            run(q.run(&mut worker));
            assert_eq!(visible.status(), 1);
            assert_eq!(p.read32(0x70080), ctl);
            request(&cpu, 1, 0, 0, 0);
            let hide = submit(&q, &cpu, &gem);
            run(q.run(&mut worker));
            assert_eq!(hide.status(), 1);
            assert_eq!(p.read32(0x700ac), 0);
            assert_eq!(p.read32(0x70140), 0);
            assert_eq!((p.read32(0x7027c), p.read32(0x7017c)), partition);
            assert_eq!(p.dsb_mappings(), dsb);
            assert_eq!(p.cursor_mappings(), cursor);
            run(worker.device.quiesce()).unwrap();
            assert_eq!(p.forbidden_display_reads(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_gen12_cursor_raw_fifo_family_ctl_pat_free_mapping_and_fixed_partition
);

fn smoke_gen12_cursor_raw_writer_handle_close_and_queued_move() -> TestResult {
    let (p, _, q, mut worker, cpu) = fixture(Gen12Platform::AlderLakeP);
    let (gem, handle) = make_gem();
    let object = gem.object(handle).unwrap();
    let weak = Arc::downgrade(&object);
    let gate = Arc::new(Gate(AtomicBool::new(false)));
    object.import_fences(vec![gate.clone()], true);
    drop(object);
    request(&cpu, 3, handle, 1, 2);
    let image = submit(&q, &cpu, &gem);
    gem.close(handle).unwrap();
    request(&cpu, 2, 0, 7, 8);
    let moved = submit(&q, &cpu, &gem);
    let mut task = Box::pin(q.run(&mut worker));
    assert!(task
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert!(weak.upgrade().is_some());
    assert_eq!(image.status(), 0);
    assert_eq!(moved.status(), 0);
    assert!(p.dsb_mappings().is_empty() && p.cursor_mappings().is_empty());
    gate.0.store(true, Ordering::Release);
    run(task);
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(image.status(), 1);
        assert_eq!(moved.status(), 1);
        assert_eq!(p.read32(0x70088), 8 << 16 | 7);
        run(worker.device.quiesce()).unwrap();
    }
    #[cfg(target_arch = "aarch64")]
    assert!(image.status() < 0);
    assert!(weak.upgrade().is_none());
    assert_eq!(p.forbidden_display_reads(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_gen12_cursor_raw_writer_handle_close_and_queued_move
);

fn smoke_gen12_cursor_raw_cancel_reset_all_console_ptes_and_source_stop_before_fresh_off(
) -> TestResult {
    #[cfg(target_arch = "x86_64")]
    {
        let (p, _, q, mut worker, cpu) = fixture(Gen12Platform::TigerLake);
        let (gem, handle) = make_gem();
        request(&cpu, 3, handle, 1, 2);
        let done = submit(&q, &cpu, &gem);
        p.stall_dsb(0, true);
        let mut task = Box::pin(q.run(&mut worker));
        poll_cursor_armed(&p, task.as_mut());
        drop(task);
        assert!(done.status() < 0);
        gem.close(handle).unwrap();
        let dsb = p.dsb_mappings();
        let cursor = p.cursor_mappings();
        assert!(!dsb.is_empty() && !cursor.is_empty());
        p.poison();
        assert!(run(worker.device.session()).is_err());
        let pte = crate::intel_gpu_gtt::GGTT_ARRAY_BASE + 0x1000000 / 4096 * 8 + 8;
        let old = p.read32(pte);
        // Poisoned IO returns all ones; the fixture still owns the exact known
        // original second console mapping, independently of its first page.
        assert_eq!(old, u32::MAX);
        p.set(pte, 0);
        assert_eq!(run(worker.device.recover()), Err(FsError::NoDevice));
        assert_eq!(p.dsb_mappings(), dsb);
        assert_eq!(p.cursor_mappings(), cursor);
        p.set(pte, 0x101001);
        let writes = p.dsb_writes().len();
        let mut recovery = Box::pin(worker.device.recover());
        assert!(recovery
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(
            p.dsb_writes()[writes..].is_empty(),
            "stalled source cannot be declared stopped"
        );
        p.stall_dsb(0, false);
        run(recovery).unwrap();
        assert!(!worker.device.reset_lost());
        assert_eq!(p.read32(0x70080), 0);
        assert_eq!(p.read32(0x700ac), 0);
        let recovery_writes = p.dsb_writes();
        let recovery_writes = &recovery_writes[writes..];
        let source_off = recovery_writes
            .iter()
            .position(|&(r, v)| r == 0x70b08 && v == 0)
            .unwrap();
        let leaf_off = recovery_writes
            .iter()
            .position(|&(r, v)| r == 0x70c08 && v == 0)
            .unwrap();
        let fresh_on = recovery_writes
            .iter()
            .position(|&(r, v)| r == 0x70b08 && v == 1 << 31)
            .unwrap();
        assert!(source_off < leaf_off && leaf_off < fresh_on);
        assert_eq!(p.dsb_mappings(), dsb);
        assert_eq!(p.cursor_mappings(), cursor);
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_gen12_cursor_raw_cancel_reset_all_console_ptes_and_source_stop_before_fresh_off
);

fn smoke_gen12_cursor_raw_master_replacement_preserves_new_cursor_and_ctm_clear_proof() -> TestResult
{
    #[cfg(target_arch = "x86_64")]
    {
        let (p, mode, q, mut worker, cpu) = fixture(Gen12Platform::AlderLakeN);
        let (gem, handle) = make_gem();
        request(&cpu, 3, handle, 1, 2);
        let done = submit(&q, &cpu, &gem);
        run(q.run(&mut worker));
        assert_eq!(done.status(), 1);
        let dsb = p.dsb_mappings();
        let cursor = p.cursor_mappings();
        mode.lock().master_release(7);
        mode.lock().master_open(8);
        request(&cpu, 3, handle, 3, 4);
        let b = run(admit_with_gem(
            &q,
            8,
            CURSOR2,
            64,
            &cpu,
            None,
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
        assert_eq!(b.status(), 1);
        let base = p.read32(0x700ac);
        let mut session = run(worker.device.session()).unwrap();
        run(restore_released_master(&mut session, &mode)).unwrap();
        assert_eq!(p.read32(0x700ac), base);
        // CTM-only clear must retain the Gen12 primary/resource witness while
        // the independently owned cursor is visible and no Presenter exists.
        let matrix = [1 << 32, 0, 0, 0, 1 << 32, 0, 0, 0, 1 << 32];
        run(session.set_ctm(Some(matrix))).unwrap();
        run(session.set_ctm(None)).unwrap();
        drop(session);
        p.set(0x60400, 0x8a000007);
        request(&cpu, 2, 0, 5, 6);
        let c = run(admit_with_gem(
            &q,
            8,
            CURSOR2,
            64,
            &cpu,
            None,
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
        assert!(c.status() < 0);
        assert_eq!(p.read32(0x700ac), base);
        assert_eq!(p.dsb_mappings(), dsb);
        assert_eq!(p.cursor_mappings(), cursor);
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_gen12_cursor_raw_master_replacement_preserves_new_cursor_and_ctm_clear_proof
);

fn smoke_gen12_cursor_raw_foreign_resources_bad_wire_and_missing_live_refuse_publication(
) -> TestResult {
    for (r, v) in [
        (0x60400, 0x8a000007),
        (0x7027c, 2047 << 16),
        (0x7017c, 0),
        (0x71080, 0x27),
        (0x70b08, 1 << 31),
        (0x700a0, 1),
        (0x70140, 0x80004003),
        (crate::intel_gpu_pcode::PCODE_MAILBOX, 1 << 31),
    ] {
        let (p, _, q, mut worker, cpu) = fixture(Gen12Platform::AlderLakeS);
        let (gem, handle) = make_gem();
        p.set(r, v);
        request(&cpu, 3, handle, 0, 0);
        let done = submit(&q, &cpu, &gem);
        run(q.run(&mut worker));
        assert!(done.status() < 0);
        assert!(p.dsb_mappings().is_empty() && p.cursor_mappings().is_empty());
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    let (p, _, q, _, cpu) = fixture(Gen12Platform::TigerLake);
    let (gem, handle) = make_gem();
    for (offset, value) in [(0u64, 4u32), (16, 65), (20, 63), (8, 32768)] {
        request(&cpu, 3, handle, 0, 0);
        cpu.write(64 + offset, &value.to_le_bytes()).unwrap();
        assert!(run(admit_with_gem(
            &q,
            7,
            CURSOR2,
            64,
            &cpu,
            None,
            Geometry {
                width: 64,
                height: 32,
                pitch: 256
            },
            1,
            Some(&gem)
        ))
        .is_err());
    }
    assert!(p.dsb_mappings().is_empty() && p.cursor_mappings().is_empty());
    #[cfg(target_arch = "x86_64")]
    {
        for fault in [0u32, 8, 1 << 11] {
            let (p, _, q, mut worker, cpu) = fixture(Gen12Platform::AlderLakeP);
            let (gem, handle) = make_gem();
            request(&cpu, 3, handle, 0, 0);
            let done = submit(&q, &cpu, &gem);
            p.stall_dsb(0, true);
            let mut task = Box::pin(q.run(&mut worker));
            if fault == 0 {
                p.allow_flips(false);
            }
            poll_cursor_armed(&p, task.as_mut());
            if fault == 8 {
                p.set(0x70b28, fault);
            } else if fault != 0 {
                p.set(0x44408, fault);
            }
            p.stall_dsb(0, false);
            run(task);
            assert!(done.status() < 0);
            assert!(!p.dsb_mappings().is_empty() && !p.cursor_mappings().is_empty());
            if fault != 1 << 11 {
                assert_eq!(p.read32(0x700ac), 0);
            }
            assert!(run(worker.device.session()).is_err());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_gen12_cursor_raw_foreign_resources_bad_wire_and_missing_live_refuse_publication
);

fn smoke_gen12_cursor_raw_primary_fifo_and_surface_restore_keep_independent_cursor() -> TestResult {
    #[cfg(target_arch = "x86_64")]
    for family in [Gen12Platform::TigerLake, Gen12Platform::AlderLakeP] {
        let (p, mode, q, mut worker, cpu) = fixture(family);
        let (gem, handle) = make_gem();
        request(&cpu, 3, handle, 1, 2);
        let image = submit(&q, &cpu, &gem);
        run(q.run(&mut worker));
        assert_eq!(image.status(), 1);
        let cursor = p.cursor_mappings();
        let dsb = p.dsb_mappings();
        let base = p.read32(0x700ac);
        // PAGE_FLIP replaces an established userspace primary. The initial
        // console has no GEM framebuffer in Card, so establish one through
        // the actual raw ATOMIC decoder and queue before requesting a flip.
        let initial = framebuffer(&mode, 7, true).unwrap();
        atomic_wire(&cpu, 0, 1, 2);
        cpu.write(164, &PLANE_CRTC_ID_PROP_ID.to_le_bytes())
            .unwrap();
        cpu.write(192, &u64::from(initial).to_le_bytes()).unwrap();
        cpu.write(200, &1u64.to_le_bytes()).unwrap();
        let established = run(admit_with_gem(
            &q,
            7,
            drm_uapi::DRM_IOCTL_MODE_ATOMIC,
            64,
            &cpu,
            None,
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
        assert_eq!(established.status(), 1);
        assert_eq!(mode.lock().crtcs[0].primary_fb, Some(initial));
        assert_eq!(p.read32(0x700ac), base);
        let target = framebuffer(&mode, 7, true).unwrap();
        let mut wire = [0; 24];
        wire[..4].copy_from_slice(&1u32.to_le_bytes());
        wire[4..8].copy_from_slice(&target.to_le_bytes());
        cpu.write(64, &wire).unwrap();
        let flip = run(admit_with_gem(
            &q,
            7,
            drm_uapi::DRM_IOCTL_MODE_PAGE_FLIP,
            64,
            &cpu,
            None,
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
        assert_eq!(flip.status(), 1);
        assert_ne!(p.read32(0x701ac), 0x1000000);
        assert_eq!(p.read32(0x700ac), base);
        let mut guard = run(worker.device.session()).unwrap();
        run(guard.restore_surface()).unwrap();
        drop(guard);
        assert_eq!(p.read32(0x701ac), 0x1000000);
        assert_eq!(p.read32(0x700ac), base);
        request(&cpu, 2, 0, 3, 4);
        let moved = submit(&q, &cpu, &gem);
        run(q.run(&mut worker));
        assert_eq!(moved.status(), 1);
        assert_eq!(p.cursor_mappings(), cursor);
        assert_eq!(p.dsb_mappings(), dsb);
        run(worker.device.quiesce()).unwrap();
        assert_eq!(p.forbidden_display_reads(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_gen12_cursor_raw_primary_fifo_and_surface_restore_keep_independent_cursor
);
