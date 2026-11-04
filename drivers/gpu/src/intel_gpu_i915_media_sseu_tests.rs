// Raw registered-card SSEU queries over actually published main-GuC engines.
// Linux b90c984d i915_gem_context.c::lookup_user_engine/get_sseu,
// intel_engine_cs.c:1279-1280 and intel_context.c:401 whole-device defaults.
use super::*;

fn image(class: u16, instance: u16, flags: u32) -> [u8; 40] {
    let mut wire = [0xa5; 40];
    wire[..2].copy_from_slice(&class.to_le_bytes());
    wire[2..4].copy_from_slice(&instance.to_le_bytes());
    put32(&mut wire, 4, flags);
    put32(&mut wire, 28, 0);
    wire
}
fn query(
    file: &RenderFile,
    card: u32,
    user: &Cpu,
    id: u32,
    size: u32,
    set: bool,
) -> Result<u64, FsError> {
    let mut wire = [0; 24];
    put32(&mut wire, 0, id);
    put32(&mut wire, 4, size);
    put64(&mut wire, 8, 7); // I915_CONTEXT_PARAM_SSEU, independent UAPI literal.
    put64(&mut wire, 16, 2048);
    user.wire.store(64, &wire);
    file.dispatch_card(
        card,
        if set {
            abi::GEM_CONTEXT_SETPARAM
        } else {
            abi::GEM_CONTEXT_GETPARAM
        },
        64,
        user,
    )
    .expect("registered i915 query dispatch")
}
fn expected(mut wire: [u8; 40], dss: u64, eus: u16) -> [u8; 40] {
    put64(&mut wire, 8, 1);
    put64(&mut wire, 16, dss);
    wire[24..26].copy_from_slice(&eus.to_le_bytes());
    wire[26..28].copy_from_slice(&eus.to_le_bytes());
    wire
}
fn traffic(w: &Window, arena: &Arena, mailbox: &Mailbox) -> (usize, usize, usize, u32, usize) {
    let d = w.0.borrow();
    (
        d.mmio_reads.get(),
        d.writes.len(),
        arena.live_allocations(),
        arena.live_pages(),
        mailbox.pending.lock().len(),
    )
}
fn map(file: &RenderFile, card: u32, user: &Cpu, id: u32, entries: &[(u16, u16)]) {
    let param = engines_param(&user.wire, id, entries, 8192);
    user.wire.store(64, &param);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, user),
        Some(Ok(0))
    );
}

fn smoke_i915_media_sseu_sparse_dense_defaults_on_each_gen12_family() -> TestResult {
    for family in [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeS,
        Gen12Platform::AlderLakeN,
    ] {
        let (w, arena, mut gt) = media(family, SPARSE);
        let engines = gt.engines().unwrap();
        assert_eq!(engines.from_class_instance(2, 0), Some(Engine::Vcs1));
        assert_eq!(engines.from_class_instance(2, 1), Some(Engine::Vcs6));
        assert_eq!(engines.from_class_instance(3, 0), Some(Engine::Vecs2));
        let (mailbox, info, card) = registered(&mut gt, &w, GtPlatform::Gen12(family));
        assert_eq!(info.topology.as_ref().unwrap().geometry_dss(), 5);
        let file = RenderFile::new();
        let user = Cpu::new();
        let id = prototype(&file, card, &user);
        let before = traffic(&w, &arena, &mailbox);
        for (class, instance) in [(0, 0), (1, 0), (2, 0), (2, 1), (3, 0)] {
            let wire = image(class, instance, 0);
            user.wire.store(2048, &wire);
            assert_eq!(query(&file, card, &user, id, 40, false), Ok(0));
            // Full-device architectural defaults, not invented media/codec EUs.
            assert_eq!(user.wire.load(2048, 40), expected(wire, 5, 16));
            assert_eq!(u32_at(&user.wire.load(64, 24), 4), 32);
        }
        for (class, instance) in [(2, 2), (2, 6), (3, 1), (3, 2)] {
            let wire = image(class, instance, 0);
            user.wire.store(2048, &wire);
            assert_eq!(
                query(&file, card, &user, id, 40, false),
                Err(FsError::InvalidData)
            );
            assert_eq!(user.wire.load(2048, 40), wire);
            assert_eq!(u32_at(&user.wire.load(64, 24), 4), 40);
        }
        assert_eq!(traffic(&w, &arena, &mailbox), before);
        hardware_stop(&mut gt, &w, 0x130044);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_media_sseu",
    smoke_i915_media_sseu_sparse_dense_defaults_on_each_gen12_family
);

fn smoke_i915_media_sseu_wire_faults_and_size_only_finalize_without_dma() -> TestResult {
    let family = Gen12Platform::TigerLake;
    let (w, arena, mut gt) = media(family, SPARSE);
    let (mailbox, _, card) = registered(&mut gt, &w, GtPlatform::Gen12(family));
    let file = RenderFile::new();
    let user = Cpu::new();
    let id = prototype(&file, card, &user);
    let before = traffic(&w, &arena, &mailbox);
    user.wire.fault_read_at(Some(2048));
    assert_eq!(query(&file, card, &user, id, 0, false), Ok(0));
    assert_eq!(u32_at(&user.wire.load(64, 24), 4), 32);
    user.wire.fault_read_at(None);
    let param = engines_param(&user.wire, id, &[(2, 0)], 8192);
    user.wire.store(64, &param);
    assert_eq!(
        file.dispatch_card(card, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Err(FsError::InvalidData)),
        "size-only lookup must finalize the original proto-context"
    );
    assert_eq!(
        query(&file, card, &user, id + 100, 0, false),
        Err(FsError::NotFound)
    );
    for size in [1, 31] {
        assert_eq!(
            query(&file, card, &user, id, size, false),
            Err(FsError::InvalidData)
        );
    }
    assert_eq!(
        query(&file, card, &user, id, 31, true),
        Err(FsError::InvalidData)
    );
    assert_eq!(
        query(&file, card, &user, id, 32, true),
        Err(FsError::NoDevice)
    );
    for (class, instance, flags, reserved) in [
        (2, 0, 2, 0),
        (2, 0, 1, 0), // indexed mode requires an explicit engine map
        (2, 0, 0, 1),
        (4, 0, 0, 0),
        (0xffff, 0, 0, 0),
        (0, 1, 0, 0),
        (1, 1, 0, 0),
    ] {
        let mut wire = image(class, instance, flags);
        put32(&mut wire, 28, reserved);
        user.wire.store(2048, &wire);
        assert_eq!(
            query(&file, card, &user, id, 40, false),
            Err(FsError::InvalidData)
        );
        assert_eq!(user.wire.load(2048, 40), wire);
        assert_eq!(u32_at(&user.wire.load(64, 24), 4), 40);
    }
    let wire = image(2, 1, 0);
    user.wire.store(2048, &wire);
    user.wire.fault_read_at(Some(2048));
    assert_eq!(
        query(&file, card, &user, id, 40, false),
        Err(FsError::BadAddress)
    );
    user.wire.fault_read_at(None);
    user.wire.fault_write_at(Some(2048));
    assert_eq!(
        query(&file, card, &user, id, 40, false),
        Err(FsError::BadAddress)
    );
    user.wire.fault_write_at(None);
    assert_eq!(user.wire.load(2048, 40), wire);
    assert_eq!(u32_at(&user.wire.load(64, 24), 4), 40);
    user.fail_report
        .store(true, core::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        query(&file, card, &user, id, 40, false),
        Err(FsError::BadAddress)
    );
    user.fail_report
        .store(false, core::sync::atomic::Ordering::Relaxed);
    assert_eq!(u32_at(&user.wire.load(64, 24), 4), 40);
    assert_eq!(user.wire.load(2048, 40), expected(wire, 5, 16));
    assert_eq!(traffic(&w, &arena, &mailbox), before);
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_media_sseu",
    smoke_i915_media_sseu_wire_faults_and_size_only_finalize_without_dma
);

fn smoke_i915_media_sseu_retained_snapshot_survives_stop_but_cannot_submit() -> TestResult {
    let family = Gen12Platform::AlderLakeP;
    let (w, arena, mut gt) = media(family, SPARSE);
    let (mailbox, _, card) = registered(&mut gt, &w, GtPlatform::Gen12(family));
    let file = RenderFile::new();
    let user = Cpu::new();
    let retained = prototype(&file, card, &user);
    let executed = prototype(&file, card, &user);
    let never_observed = prototype(&file, card, &user);
    let handles = handles(&file, card, &user);
    // Even size-only observation captures actual published identities; no
    // UserContext, page tables, ring or BO is created for this host-only query.
    assert_eq!(query(&file, card, &user, retained, 0, false), Ok(0));
    // A real retained legacy media selection also records the actual map.
    // Query only after stop, so the SSEU path cannot seed this one itself.
    legacy_exec(&user.wire, handles, executed);
    set_ring(&user.wire, 2 | 2 << 13);
    let (context, fence) = submit(&file, card, &user, &mailbox, &mut gt, 30_000_000);
    assert_eq!(context.engine(), Engine::Vcs6);
    let mut active = BTreeMap::new();
    finish_policy(&mut gt, &w, &fence, &mut active, 30_000_001, 2);
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(active.is_empty());
    let mut value = [0; 4];
    file.gem
        .object(handles[1])
        .unwrap()
        .read(128, &mut value)
        .unwrap();
    assert_eq!(u32::from_le_bytes(value), 0x4e415246);
    *mailbox.status.lock() = None;
    hardware_stop(&mut gt, &w, 0x130044);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    let before = traffic(&w, &arena, &mailbox);
    for (class, instance) in [(0, 0), (1, 0), (2, 0), (2, 1), (3, 0)] {
        let wire = image(class, instance, 0);
        user.wire.store(2048, &wire);
        assert_eq!(query(&file, card, &user, retained, 40, false), Ok(0));
        assert_eq!(user.wire.load(2048, 40), expected(wire, 5, 16));
    }
    user.wire.store(2048, &image(2, 1, 0));
    assert_eq!(query(&file, card, &user, executed, 32, false), Ok(0));
    let wire = image(2, 0, 0);
    user.wire.store(2048, &wire);
    assert_eq!(
        query(&file, card, &user, never_observed, 40, false),
        Err(FsError::NoDevice)
    );
    assert_eq!(user.wire.load(2048, 40), wire);
    // Existing RENDER0/COPY0 immutable stopped queries do not need this snapshot.
    for class in [0, 1] {
        user.wire.store(2048, &image(class, 0, 0));
        assert_eq!(query(&file, card, &user, never_observed, 32, false), Ok(0));
    }
    legacy_exec(&user.wire, handles, retained);
    set_ring(&user.wire, 2);
    poll_refusal(&file, card, &user, FsError::NoDevice);
    assert_eq!(traffic(&w, &arena, &mailbox), before);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_media_sseu",
    smoke_i915_media_sseu_retained_snapshot_survives_stop_but_cannot_submit
);

fn smoke_i915_media_sseu_indexed_sparse_slots_holes_and_ignored_class_after_stop() -> TestResult {
    let family = Gen12Platform::AlderLakeS;
    let (w, arena, mut gt) = media(family, SPARSE);
    let (mailbox, _, card) = registered(&mut gt, &w, GtPlatform::Gen12(family));
    let file = RenderFile::new();
    let user = Cpu::new();
    let id = prototype(&file, card, &user);
    map(&file, card, &user, id, &[(2, 1), (3, 0), (0xffff, 0xffff)]);
    for stopped in [false, true] {
        if stopped {
            *mailbox.status.lock() = None;
            hardware_stop(&mut gt, &w, 0x130044);
        }
        let before = traffic(&w, &arena, &mailbox);
        for index in [0, 1] {
            let wire = image(0xfffe, index, 1);
            user.wire.store(2048, &wire);
            assert_eq!(query(&file, card, &user, id, 40, false), Ok(0));
            assert_eq!(user.wire.load(2048, 40), expected(wire, 5, 16));
        }
        for (class, instance, flags) in [(2, 0, 0), (3, 0, 0), (0, 2, 1), (0, 3, 1)] {
            let wire = image(class, instance, flags);
            user.wire.store(2048, &wire);
            assert_eq!(
                query(&file, card, &user, id, 40, false),
                Err(FsError::InvalidData)
            );
            assert_eq!(user.wire.load(2048, 40), wire);
        }
        assert_eq!(traffic(&w, &arena, &mailbox), before);
    }
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_media_sseu",
    smoke_i915_media_sseu_indexed_sparse_slots_holes_and_ignored_class_after_stop
);

fn smoke_i915_media_sseu_unpublished_fused_and_foreign_status_never_seed_snapshot() -> TestResult {
    let family = Gen12Platform::AlderLakeN;
    for fuse in [0x000f00ff, 0x000f00ff & !0x40] {
        let (w, arena, mut gt) = media(family, fuse);
        let (mailbox, _, card) = registered(&mut gt, &w, GtPlatform::Gen12(family));
        let file = RenderFile::new();
        let user = Cpu::new();
        let saved = (*mailbox.status.lock()).unwrap();
        let before = traffic(&w, &arena, &mailbox);
        for mode in 0..4 {
            let mut status = saved;
            match mode {
                0 => *mailbox.status.lock() = None,
                1 => {
                    status.epoch = 0;
                    *mailbox.status.lock() = Some(status);
                }
                2 => {
                    status.platform = GtPlatform::Battlemage;
                    *mailbox.status.lock() = Some(status);
                }
                _ => {
                    status.engines = EngineSet::default();
                    *mailbox.status.lock() = Some(status);
                }
            }
            let cold = prototype(&file, card, &user);
            user.wire.store(2048, &image(2, 0, 0));
            assert_eq!(
                query(&file, card, &user, cold, 32, false),
                Err(FsError::NoDevice)
            );
            *mailbox.status.lock() = Some(saved);
            // A failed cold lookup can later observe a genuinely live set;
            // empty or mismatched state was not permanently invented as one.
            user.wire.store(2048, &image(2, 0, 0));
            assert_eq!(
                query(&file, card, &user, cold, 32, false),
                if fuse == 0x000f00ff {
                    Err(FsError::InvalidData)
                } else {
                    Ok(0)
                }
            );
            user.wire.store(2048, &image(2, 1, 0));
            assert_eq!(
                query(&file, card, &user, cold, 32, false),
                Err(FsError::InvalidData)
            );
            user.wire.store(2048, &image(3, 0, 0));
            assert_eq!(
                query(&file, card, &user, cold, 32, false),
                Err(FsError::InvalidData)
            );
        }
        assert_eq!(traffic(&w, &arena, &mailbox), before);
        hardware_stop(&mut gt, &w, 0x130044);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_media_sseu",
    smoke_i915_media_sseu_unpublished_fused_and_foreign_status_never_seed_snapshot
);

fn smoke_i915_media_sseu_other_profiles_refuse_and_legacy_view_stays_eight_bits() -> TestResult {
    for platform in [
        GtPlatform::Alchemist,
        GtPlatform::Integrated(crate::intel_gpu::Generation::PantherLake),
    ] {
        let (w, arena, mut gt, ack) = discover(platform, 3);
        prime_mode(&mut gt, &w, 1);
        let (mailbox, info, card) = registered(&mut gt, &w, platform);
        let file = RenderFile::new();
        let user = Cpu::new();
        let id = prototype(&file, card, &user);
        let before = traffic(&w, &arena, &mailbox);
        for class in [2, 3] {
            user.wire.store(2048, &image(class, 0, 0));
            assert_eq!(
                query(&file, card, &user, id, 32, false),
                Err(FsError::InvalidData)
            );
        }
        let wire = image(0, 0, 0);
        user.wire.store(2048, &wire);
        assert_eq!(query(&file, card, &user, id, 0, false), Ok(0));
        if platform.is_ptl() {
            assert_eq!(
                query(&file, card, &user, id, 40, false),
                Err(FsError::NoDevice)
            );
            assert_eq!(user.wire.load(2048, 40), wire);
        } else {
            // Sparse physical DSS0/8 remains visible in the full query but
            // deliberately truncates to the old eight-bit context ABI here.
            assert_eq!(info.topology.as_ref().unwrap().geometry_dss(), 0x101);
            assert_eq!(query(&file, card, &user, id, 40, false), Ok(0));
            assert_eq!(user.wire.load(2048, 40), expected(wire, 1, 16));
        }
        assert_eq!(traffic(&w, &arena, &mailbox), before);
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_i915_media_sseu",
    smoke_i915_media_sseu_other_profiles_refuse_and_legacy_view_stays_eight_bits
);
