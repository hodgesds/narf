// A real BMG GuCGt owner: OA reservation before scheduling, published facts,
// a privileged LRI configuration job retired through the GuC scheduler,
// stream programming, the 200 Hz tail service, a read, and full-reset
// retirement of the exposed buffer. Linux b90c984d xe_oa.c vectors.
use super::*;
use crate::{intel_gpu_oa as oa, intel_gpu_uapi::u32_at};
use narf_filesystem::FsError;

fn smoke_oa_hardware_bmg_reservation_ring_job_read_and_reset_retirement() -> TestResult {
    let (io, arena) = model();
    io.0.borrow_mut().regs.extend([
        (0xdfc, 0),
        (0xa188, 2),
        (0xa278, 2),
        (0xd84, 0),
        (0xfd0, 1),
        (0x913c, 5),
        (0x9144, 6),
        (0x9134, 5),
        (0x9114, 0x10),
        (0x9118, 1),
        (0x138000, (18 << 16) | 180),
        (0x13800c, 90),
        (0x145998, (6 << 16) | 60),
        (0x145ef0, 30 << 8),
        (0xd8c, (20 << 22) | (1 << 14)),
    ]);
    let boot = GuCBoot::stage_image(
        io.clone(),
        arena.clone(),
        GtPlatform::Battlemage,
        CssImage::parse(&image(), 70).unwrap(),
        BootConfig {
            device_id: 0xe20b,
            revision: 3,
            huc_upload_bytes: 0,
            uncached_mocs: Some(3),
        },
    )
    .unwrap();
    let mut gt = GuCGt::from_staged_hardware(boot).unwrap();
    let initial = arena.live_allocations();
    assert_eq!(gt.prepare_oa(), Err(FsError::Unsupported));
    assert_eq!(arena.live_allocations(), initial);
    hardware_discovery(&mut gt, &io, 0xdfc);
    let before: BTreeSet<_> = io.0.borrow().memory.keys().copied().collect();
    io.0.borrow_mut().writes.clear();
    gt.prepare_oa().unwrap();
    assert_eq!(gt.prepare_oa(), Err(FsError::Unsupported));
    let base = *io
        .0
        .borrow()
        .memory
        .keys()
        .find(|base| !before.contains(*base))
        .unwrap();
    assert_eq!(io.0.borrow().memory[&base].borrow().len() * 4, 16 << 20);
    // __xe_oa_init_oa_units: counters off, MMIO trigger disabled.
    assert!(io
        .0
        .borrow()
        .writes
        .ends_with(&[(0xdaf4, 0), (0xdaf8, 0x4000_4000)]));
    hardware_scheduling(&mut gt, &io);
    let completion = gt.begin_context_defaults(26).unwrap();
    let mut registered = BTreeMap::new();
    for now in 27..300 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if completion.result().is_some() {
            break;
        }
        service_contexts(&io, &mut registered, true);
    }
    assert_eq!(completion.result(), Some(Ok(())));
    assert!(gt.user_epoch().is_some() && gt.idle());
    let facts = gt.device_facts().unwrap();
    let device = gt.oa_device(48, &facts).unwrap();
    assert_eq!(
        (device.graphics, device.reserve, device.timestamp),
        (2001, 16 << 20, facts.reference_clock)
    );
    assert_eq!(u32_at(&oa::query(Some(device)), 8), 1);

    // PEC64u32 (320 bytes): Xe2 overrun mode makes a report-multiple ring.
    let session = oa::test_session(device, 12, 128 << 10, Some(5), &[(0x13000, 7), (0xe458, 9)]);
    let request = oa::Request::Open { enable: true };
    let jobs = gt.oa_begin(&session, &request, 700, || true).unwrap();
    assert_eq!(jobs.len(), 1);
    assert!(!gt.idle(), "an open stream holds the GT awake");
    assert_eq!(io.0.borrow().regs[&0x2b28], 0x17);
    assert_eq!(io.0.borrow().regs[&0x8718] & 0x6000_0000, 0x6000_0000);
    let fence = gt.submit_oa_job(701, &session, &jobs[0]).unwrap();
    for now in 702..900 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if fence.result().is_some() {
            break;
        }
        service_contexts(&io, &mut registered, true);
    }
    assert_eq!(fence.result(), Some(Ok(())));
    // The kernel ring's MI_LOAD_REGISTER_IMM reached the configuration.
    assert_eq!(
        (io.0.borrow().regs[&0x13000], io.0.borrow().regs[&0xe458]),
        (7, 9)
    );
    gt.oa_finish(&session, &request, 900, || true).unwrap();
    {
        let d = io.0.borrow();
        assert_eq!(d.regs[&0xdb08], base | 1);
        assert_eq!((d.regs[&0xdb00], d.regs[&0xdb04]), (base, base));
        assert_eq!(d.regs[&0xdaf4], (0x3f << 22) | (1 << 2) | 1);
    }
    // One landed report: the following report's header has also landed.
    {
        let d = io.0.borrow();
        let mut words = d.memory[&base].borrow_mut();
        for (i, word) in words[..80].iter_mut().enumerate() {
            *word = 0x4f41_0000 | i as u32;
        }
        words[80] = 0x4f41_ffff;
    }
    io.0.borrow_mut().regs.insert(0xdb04, base + 640);
    gt.poll_oa(900 + oa::POLL_NS, || true);
    let mut out = [0u8; 1024];
    assert_eq!(gt.oa_read(&session, &mut out, false, || true), Ok(320));
    assert_eq!(u32_at(&out, 4 * 79), 0x4f41_004f);
    assert_eq!(io.0.borrow().regs[&0xdb00], base + 320);
    assert_eq!(
        gt.oa_read(&session, &mut out, false, || true),
        Err(FsError::WouldBlock)
    );

    // Stop/reset: the stream is terminal, counters halt, the metric set is
    // undone, and the exposed buffer outlives GuC stop until GRDOM_FULL.
    let retained = arena.live_allocations();
    gt.begin_stop(1000).unwrap();
    assert_eq!(
        gt.oa_read(&session, &mut out, false, || true),
        Err(FsError::NoDevice)
    );
    assert!(gt.poll(1001).is_pending());
    {
        let d = io.0.borrow();
        assert_eq!(d.regs[&0xdaf4], 0);
        assert_eq!(d.regs[&0xdaf8], 0x4000_4000);
        assert_eq!(d.regs[&0x8718] & 0x6000_0000, 0);
        assert!(d.memory.contains_key(&base));
    }
    assert_eq!(arena.live_allocations(), retained);
    reset_done(&io);
    assert!(gt.poll(1002).is_pending());
    assert_eq!(gt.state(), GtState::ResettingEngines);
    assert!(io.0.borrow().memory.contains_key(&base));
    assert!(gt.poll(1003).is_pending());
    assert!(io.0.borrow().memory.contains_key(&base));
    reset_done(&io);
    assert!(gt.poll(1004).is_pending());
    assert!(!io.0.borrow().memory.contains_key(&base));
    io.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(gt.poll(1005).is_pending());
    io.0.borrow_mut().regs.insert(0xdfc, 0);
    assert_eq!(gt.poll(1006), Poll::Ready(Ok(GtState::Stopped)));
    drop(gt);
    drop(session);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_hardware_bmg_reservation_ring_job_read_and_reset_retirement
);

fn smoke_oa_per_context_job_executes_on_bound_queue_and_saves_state() -> TestResult {
    let (io, arena) = model();
    io.0.borrow_mut().regs.extend([
        (0xdfc, 0),
        (0xa188, 2),
        (0xa278, 2),
        (0xd84, 0),
        (0xfd0, 1),
        (0x913c, 5),
        (0x9144, 6),
        (0x9134, 5),
        (0x9114, 0x10),
        (0x9118, 1),
        (0x138000, (18 << 16) | 180),
        (0x13800c, 90),
        (0x145998, (6 << 16) | 60),
        (0x145ef0, 30 << 8),
        (0xd8c, (20 << 22) | (1 << 14)),
    ]);
    let boot = GuCBoot::stage_image(
        io.clone(),
        arena.clone(),
        GtPlatform::Battlemage,
        CssImage::parse(&image(), 70).unwrap(),
        BootConfig {
            device_id: 0xe20b,
            revision: 3,
            huc_upload_bytes: 0,
            uncached_mocs: Some(3),
        },
    )
    .unwrap();
    let mut gt = GuCGt::from_staged_hardware(boot).unwrap();
    hardware_discovery(&mut gt, &io, 0xdfc);
    // Reserve the OA unit before scheduling: `oa_device` returns None
    // without it (see `GuCGt::oa_device`, `parts.oa`), which panicked at
    // `:220` on the first runs that reached this test.
    gt.prepare_oa().unwrap();
    hardware_scheduling(&mut gt, &io);
    let completion = gt.begin_context_defaults(26).unwrap();
    let mut registered = BTreeMap::new();
    for now in 27..300 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if completion.result().is_some() {
            break;
        }
        service_contexts(&io, &mut registered, true);
    }
    assert_eq!(completion.result(), Some(Ok(())));
    assert!(gt.user_epoch().is_some() && gt.idle());
    let facts = gt.device_facts().unwrap();
    let device = gt.oa_device(48, &facts).unwrap();

    // A bound Rcs0 queue 10 whose liveness the test controls, so the stale
    // path below can kill it between `begin` and the submit.
    let alive_flag = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(true));
    let alive: alloc::sync::Arc<dyn Fn() -> bool + Send + Sync> = {
        let flag = alive_flag.clone();
        alloc::sync::Arc::new(move || flag.load(core::sync::atomic::Ordering::Relaxed))
    };
    // PEC64u32 (320 bytes) with an empty configuration: `begin` returns only
    // the per-context job, tagged for the bound queue.
    let session = oa::test_session_exec(
        device,
        12,
        128 << 10,
        crate::intel_gpu_engine::Engine::Rcs0,
        10,
        alive,
    );
    let request = oa::Request::Open { enable: true };
    let jobs = gt.oa_begin(&session, &request, 700, || true).unwrap();
    assert_eq!(jobs.len(), 1);
    assert!(jobs[0].per_context());
    let oacontrol = jobs[0].words()[4];
    let fence = gt.submit_oa_job(701, &session, &jobs[0]).unwrap();
    for now in 702..900 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if fence.result().is_some() {
            break;
        }
        service_contexts(&io, &mut registered, true);
    }
    assert_eq!(fence.result(), Some(Ok(())));
    // The LRI landed live on the bound queue's context...
    assert_eq!(
        (
            io.0.borrow().regs[&0x2360],
            io.0.borrow().regs[&0x2960],
            io.0.borrow().regs[&0x2244],
        ),
        (1, oacontrol, 0x0100_0100)
    );
    // ...and, unlike the kernel-ring path, reached the bound queue's saved
    // state: RING_CONTEXT_CONTROL is the image's first group value slot
    // (saved word 3). The fence only signals after capture, so this also
    // proves the job retired on the bound context, not a fresh kernel one.
    assert_eq!(
        session.queue_binding().unwrap().context.saved_word(3),
        Some(0x0100_0100)
    );

    // A queue that dies between `begin` and the submit fails clean at the
    // submit (ENOENT), never falling back to the kernel ring.
    let jobs = gt
        .oa_begin(&session, &oa::Request::Enable, 910, || true)
        .unwrap();
    assert_eq!(jobs.len(), 1);
    assert!(jobs[0].per_context());
    alive_flag.store(false, core::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        gt.submit_oa_job(911, &session, &jobs[0]),
        Err(FsError::NotFound)
    ));
    alive_flag.store(true, core::sync::atomic::Ordering::Relaxed);

    // Disable retires on the bound queue too, clearing the saved bit.
    let jobs = gt
        .oa_begin(&session, &oa::Request::Disable, 920, || true)
        .unwrap();
    assert_eq!(jobs.len(), 1);
    assert!(jobs[0].per_context());
    let fence = gt.submit_oa_job(921, &session, &jobs[0]).unwrap();
    for now in 922..1000 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if fence.result().is_some() {
            break;
        }
        service_contexts(&io, &mut registered, true);
    }
    assert_eq!(fence.result(), Some(Ok(())));
    assert_eq!(io.0.borrow().regs[&0x2244], 0x0100_0000);
    assert_eq!(
        session.queue_binding().unwrap().context.saved_word(3),
        Some(0x0100_0000)
    );
    gt.oa_finish(&session, &oa::Request::Disable, 1000, || true)
        .unwrap();
    drop(gt);
    drop(session);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_oa",
    smoke_oa_per_context_job_executes_on_bound_queue_and_saves_state
);
