//! Legacy UAPI -> real FIFO -> retained WC/PTE/DSB cursor production path.
//! The existing native PCI model executes actual command pages and latches
//! cursor SURFLIVE on a later frame, independently of primary completion.
use super::*;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_kms::{tests::MockPlatform, Device};
use narf_filesystem::DrmFence;
// Linux drm.h: DRM_IOWR(0xbb, struct drm_mode_cursor2), nine u32 fields.
const CURSOR2: u32 = drm_uapi::iowr(b'd' as u32, 0xbb, 36);
struct Worker {
    device: Arc<Device<MockPlatform>>,
}
impl queue::Worker for Worker {
    fn lost(&self) -> bool {
        self.device.reset_lost()
    }
    fn epoch(&self) -> u64 {
        1
    }
    fn process<'a>(
        &'a mut self,
        mode: &'a ModeState,
        open: u64,
        _epoch: u64,
        plan: &'a Plan,
        reservation: Option<FlipEventReservation>,
    ) -> FsFuture<'a, FlipStamp> {
        Box::pin(async move {
            let mut guard = self.device.session().await?;
            execute_plan(&mut guard, mode, open, plan, reservation).await
        })
    }
}
fn run<F: Future>(future: F) -> F::Output {
    let mut f = Box::pin(future);
    for _ in 0..256 {
        if let Poll::Ready(r) = f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            return r;
        }
    }
    panic!("cursor worker did not finish")
}
fn request(cpu: &Cpu, flags: u32, handle: u32, x: i32, y: i32) {
    let values = [flags, 1, x as u32, y as u32, 64, 64, handle, 7, 9];
    let bytes: Vec<u8> = values.into_iter().flat_map(u32::to_le_bytes).collect();
    cpu.write(64, &bytes).unwrap();
}
fn submit(
    q: &queue::Queue,
    cpu: &Cpu,
    gem: &crate::intel_gpu_gem::GemState,
) -> Arc<queue::Completion> {
    run(admit_with_gem(
        q,
        7,
        CURSOR2,
        64,
        cpu,
        None,
        Geometry {
            width: 64,
            height: 32,
            pitch: 256,
        },
        1,
        Some(gem),
    ))
    .unwrap()
    .unwrap()
    .0
}
fn make_gem() -> (crate::intel_gpu_gem::GemState, u32) {
    let gem = crate::intel_gpu_gem::GemState::new();
    let handle = gem.create(16384, |_, _| Ok(())).unwrap();
    gem.object(handle)
        .unwrap()
        .write(0, &vec![0x7a; 16384])
        .unwrap();
    (gem, handle)
}
fn fixture() -> (MockPlatform, ModeState, queue::Queue, Worker, Cpu) {
    let p = MockPlatform::new();
    p.cursor_resources();
    let mode = mode();
    {
        let mut c = mode.lock();
        c.intel_display = true;
        c.intel_ctm = true;
        c.crtc_color.push(crate::drm::card::CrtcColor::new(1));
    }
    let queue = queue::Queue::new(mode.clone());
    let worker = Worker {
        device: Arc::new(p.meteor()),
    };
    (p, mode, queue, worker, Cpu::new())
}
#[cfg(target_arch = "x86_64")]
fn assert_cursor_arm_order(platform: &MockPlatform) {
    // Read the actual retained WC command pages through their installed
    // PTEs, independently of the production command-builder classification.
    let commands = platform.dsb_commands();
    let evasion = commands
        .iter()
        .position(|&(low, high)| high >> 24 == 6 && low != 0)
        .unwrap();
    let write = |register| {
        commands
            .iter()
            .position(|&(_, high)| high >> 24 == 1 && high & 0xfffff == register)
            .unwrap()
    };
    let ctl = write(0x70080);
    for register in [
        0x70140, 0x70144, 0x70148, 0x7014c, 0x70150, 0x70154, 0x70158, 0x7015c, 0x70168, 0x7017c,
    ] {
        let wm = write(register);
        assert!(evasion < wm && wm < ctl);
    }
    assert!(ctl < write(0x70088) && write(0x70088) < write(0x70084));
}
fn smoke_intel_cursor_native_uapi_fifo_latch_replacement_move_and_hide() -> TestResult {
    let (p, mode, q, mut worker, cpu) = fixture();
    let (gem, handle) = make_gem();
    request(&cpu, 3, handle, -2, 3);
    let done = submit(&q, &cpu, &gem);
    assert_eq!(done.status(), 0);
    assert!(mode
        .lock()
        .native_planes
        .iter()
        .all(|plane| !plane.is_cursor()));
    let mut work = Box::pin(q.run(&mut worker));
    let first = work.as_mut().poll(&mut Context::from_waker(Waker::noop()));
    #[cfg(target_arch = "x86_64")]
    {
        assert!(first.is_pending());
        assert_cursor_arm_order(&p);
    }
    #[cfg(target_arch = "aarch64")]
    {
        if first.is_pending() {
            run(work);
        }
        assert!(done.status() < 0);
        assert_eq!(p.read32(0x70080), 0);
    }
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(done.status(), 0);
        run(work);
        assert_eq!(done.status(), 1);
        assert_eq!(p.read32(0x70b08) & ((1 << 31) | 1), 0);
        assert_eq!(p.read32(0x70c08) & ((1 << 31) | 1), 0);
        let base = p.read32(0x700ac);
        assert_ne!(base, 0);
        assert_eq!(p.read32(0x70088), 0x00038002);
        assert_eq!(p.read32(0x70080), 0x27);
        assert!(
            mode.lock().native_planes.iter().all(|p| !p.is_cursor()),
            "no speculative universal cursor advertisement"
        );
        let pte = crate::intel_gpu_gtt::GGTT_ARRAY_BASE + u64::from(base) / 4096 * 8;
        let phys =
            (u64::from(p.read32(pte)) | (u64::from(p.read32(pte + 4)) << 32)) & 0x00003ffffffff000;
        assert_eq!(
            // SAFETY: the retained cursor owner/PTE owns this private WC page.
            unsafe {
                core::ptr::read_volatile(narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>())
            },
            0x7a
        );
        let mappings = p.dsb_mappings();
        let mut session = run(worker.device.session()).unwrap();
        let mut changed_timing = p.dsb_timing();
        changed_timing.flags ^= 1;
        let arms = p.arm_order();
        assert!(matches!(
            run(session.cursor(None, false, Some((1, 2)), changed_timing)),
            Err(FsError::Unsupported)
        ));
        assert_eq!(p.arm_order(), arms);
        assert_eq!(p.dsb_mappings(), mappings);
        drop(session);
        gem.object(handle)
            .unwrap()
            .write(0, &vec![0x3b; 16384])
            .unwrap();
        request(&cpu, 1, handle, 0, 0);
        let replaced = submit(&q, &cpu, &gem);
        run(q.run(&mut worker));
        assert_eq!(replaced.status(), 1);
        assert_ne!(p.read32(0x700ac), base);
        assert_eq!(p.read32(0x70088), 0x00038002);
        request(&cpu, 2, 0, 10, -4);
        let moved = submit(&q, &cpu, &gem);
        run(q.run(&mut worker));
        assert_eq!(moved.status(), 1);
        assert_eq!(p.read32(0x70088), 0x8004000a);
        assert_eq!(
            p.dsb_mappings(),
            mappings,
            "same private BO/VA mappings across replacement/move"
        );
        // A normal queued primary flip keeps the independent cursor front.
        let target = framebuffer(&mode, 7, true).unwrap();
        let cursor_base = p.read32(0x700ac);
        for request in [
            atomic_frame(target, 0),
            Request::PageFlip(DrmModePageFlipUapi {
                crtc_id: 1,
                fb_id: target,
                flags: 0,
                reserved: 0,
                user_data: 0,
            }),
        ] {
            let flip = run(q.submit(
                7,
                request,
                Geometry {
                    width: 64,
                    height: 32,
                    pitch: 256,
                },
                1,
                &cpu,
                None,
            ))
            .unwrap()
            .unwrap()
            .0;
            run(q.run(&mut worker));
            assert_eq!(flip.status(), 1);
            assert_eq!(p.read32(0x700ac), cursor_base);
        }
        let resumes = p.console_resumes();
        let mut session = run(worker.device.session()).unwrap();
        run(session.restore_surface()).unwrap();
        assert_eq!(p.console_resumes(), resumes);
        assert_eq!(p.read32(0x700ac), cursor_base);
        drop(session);
        // The real color entrypoint also preserves the separately-owned
        // cursor when the primary has already returned to the console.
        let coefficients: [u64; 9] = [1 << 32, 0, 0, 0, 1 << 32, 0, 0, 0, 1 << 32];
        let color = mode
            .lock()
            .create_property_blob(
                coefficients
                    .into_iter()
                    .flat_map(u64::to_le_bytes)
                    .collect(),
            )
            .unwrap();
        for value in [u64::from(color), 0] {
            let changed = run(q.submit(
                7,
                Request::Atomic(OwnedAtomic {
                    flags: 0,
                    cookie: 0,
                    objects: vec![1],
                    counts: vec![1],
                    props: vec![CRTC_CTM_PROP_ID],
                    values: vec![value],
                }),
                Geometry {
                    width: 64,
                    height: 32,
                    pitch: 256,
                },
                1,
                &cpu,
                None,
            ))
            .unwrap()
            .unwrap()
            .0;
            run(q.run(&mut worker));
            assert_eq!(changed.status(), 1);
            assert_eq!(p.read32(0x700ac), cursor_base);
            assert_eq!(p.console_resumes(), resumes);
        }
        request(&cpu, 1, 0, 0, 0);
        let hidden = submit(&q, &cpu, &gem);
        run(q.run(&mut worker));
        assert_eq!(hidden.status(), 1);
        assert_cursor_arm_order(&p);
        assert_eq!(p.read32(0x700ac), 0);
        assert_eq!(p.read32(0x70080), 0);
        assert_eq!(p.dsb_mappings(), mappings);
        run(worker.device.quiesce()).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_intel_cursor_native_uapi_fifo_latch_replacement_move_and_hide
);
fn smoke_intel_cursor_cancelled_dma_close_and_reset_require_cursor_retirement() -> TestResult {
    #[cfg(target_arch = "x86_64")]
    {
        let (p, mode, q, mut worker, cpu) = fixture();
        let (gem, handle) = make_gem();
        request(&cpu, 3, handle, 1, 2);
        let done = submit(&q, &cpu, &gem);
        p.stall_dsb(0, true);
        let mut task = Box::pin(q.run(&mut worker));
        assert!(task
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        drop(task);
        assert!(done.status() < 0);
        gem.close(handle).unwrap();
        let retained = p.dsb_mappings();
        assert!(!retained.is_empty());
        p.stall_dsb(0, false);
        let mut guard = run(worker.device.session()).unwrap();
        run(guard.restore_console()).unwrap();
        assert_eq!(p.read32(0x700ac), 0);
        assert_eq!(p.read32(0x70080), 0);
        assert_eq!(p.dsb_mappings(), retained);
        drop(guard);
        let (gem, handle) = make_gem();
        request(&cpu, 3, handle, 3, 4);
        let done = submit(&q, &cpu, &gem);
        run(q.run(&mut worker));
        assert_eq!(done.status(), 1);
        mode.lock().master_release(7);
        mode.lock().master_open(8);
        request(&cpu, 3, handle, 5, 6);
        let replacement = run(admit_with_gem(
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
        assert_eq!(replacement.status(), 1);
        let replacement_base = p.read32(0x700ac);
        let mut session = run(worker.device.session()).unwrap();
        run(restore_released_master(&mut session, &mode)).unwrap();
        assert_eq!(
            p.read32(0x700ac),
            replacement_base,
            "stale A close cannot hide B's committed cursor"
        );
        drop(session);
        p.poison();
        assert!(run(worker.device.session()).is_err());
        run(worker.device.recover()).unwrap();
        assert_eq!(p.read32(0x70080), 0);
        assert_eq!(p.read32(0x700ac), 0);
        assert_eq!(p.dsb_mappings(), retained);
        assert_eq!(p.read32(0x70b08) & ((1 << 31) | 1), 0);
        assert_eq!(p.read32(0x70c08) & ((1 << 31) | 1), 0);
        // Successful recovery must replace the temporary fresh IO view:
        // a second reset refuses ordinary access until independently retired.
        let mut session = run(worker.device.session()).unwrap();
        let timing = p.dsb_timing();
        run(session.cursor(
            Some(gem.object(handle).unwrap()),
            true,
            Some((7, 8)),
            timing,
        ))
        .unwrap();
        drop(session);
        p.stall_dsb(0, true);
        let mut session = run(worker.device.session()).unwrap();
        let mut pending = Box::pin(session.cursor(None, false, Some((9, 10)), timing));
        assert!(pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        p.poison();
        drop(pending);
        assert_eq!(session.ownership_valid(), Err(FsError::NoDevice));
        drop(session);
        let mut recovery = Box::pin(worker.device.recover());
        assert!(recovery
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(worker.device.reset_lost());
        assert_eq!(p.dsb_mappings(), retained);
        p.stall_dsb(0, false);
        run(recovery).unwrap();
        assert_eq!(p.read32(0x70080), 0);
        assert_eq!(p.read32(0x700ac), 0);
        assert_eq!(p.dsb_mappings(), retained);
        mode.lock().master_release(8);
        mode.lock().master_open(9);
        let mut session = run(worker.device.session()).unwrap();
        run(restore_released_master(&mut session, &mode)).unwrap();
        assert_eq!(p.read32(0x70080), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_intel_cursor_cancelled_dma_close_and_reset_require_cursor_retirement
);
fn smoke_intel_cursor_unowned_resources_and_missing_live_latch_never_publish_success() -> TestResult
{
    let p = MockPlatform::new();
    p.dsb_timing();
    let mode = mode();
    let q = queue::Queue::new(mode);
    let mut worker = Worker {
        device: Arc::new(p.meteor()),
    };
    let cpu = Cpu::new();
    let (gem, handle) = make_gem();
    request(&cpu, 3, handle, 0, 0);
    let done = submit(&q, &cpu, &gem);
    run(q.run(&mut worker));
    assert!(done.status() < 0);
    assert_eq!(p.read32(0x70080), 0);
    assert!(p.dsb_mappings().is_empty());
    #[cfg(target_arch = "x86_64")]
    {
        // Reserving DSB refuses stale enabled firmware state before either
        // command/PTE exposure. That strict refusal releases only untouched
        // cursor metadata and resumes the otherwise-unowned console.
        let (p, _, q, mut worker, cpu) = fixture();
        let (gem, handle) = make_gem();
        p.set(0x70b08, 1 << 31);
        let resumes = p.console_resumes();
        request(&cpu, 3, handle, 0, 0);
        let refused = submit(&q, &cpu, &gem);
        run(q.run(&mut worker));
        assert!(refused.status() < 0);
        assert_eq!(p.read32(0x70080), 0);
        assert!(p.dsb_mappings().is_empty());
        assert_eq!(p.console_resumes(), resumes + 1);
        assert!(run(worker.device.session()).is_ok());
        let (p, _, q, mut worker, cpu) = fixture();
        let (gem, handle) = make_gem();
        request(&cpu, 3, handle, 0, 0);
        let done = submit(&q, &cpu, &gem);
        p.allow_flips(false);
        run(q.run(&mut worker));
        assert!(done.status() < 0);
        assert_eq!(p.read32(0x700ac), 0);
        assert!(!p.dsb_mappings().is_empty());
        assert!(run(worker.device.session()).is_err());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_intel_cursor_unowned_resources_and_missing_live_latch_never_publish_success
);

struct Gate(AtomicBool);
impl DrmFence for Gate {
    fn is_signalled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    fn wait(&self, _timeout: u64) -> bool {
        self.is_signalled()
    }
}
fn smoke_intel_cursor_writer_dependency_and_handle_close_keep_only_owned_resources() -> TestResult {
    let (p, _, q, mut worker, cpu) = fixture();
    let (gem, handle) = make_gem();
    let object = gem.object(handle).unwrap();
    let weak = Arc::downgrade(&object);
    let fence = Arc::new(Gate(AtomicBool::new(false)));
    object.import_fences(vec![fence.clone()], true);
    drop(object);
    request(&cpu, 3, handle, 2, 3);
    let done = submit(&q, &cpu, &gem);
    gem.close(handle).unwrap();
    assert!(weak.upgrade().is_some());
    let mut task = Box::pin(q.run(&mut worker));
    assert!(task
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(done.status(), 0);
    assert!(p.dsb_mappings().is_empty());
    fence.0.store(true, Ordering::Release);
    run(task);
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(done.status(), 1);
        assert_ne!(p.read32(0x700ac), 0);
        let mut session = run(worker.device.session()).unwrap();
        run(session.restore_console()).unwrap();
    }
    #[cfg(target_arch = "aarch64")]
    assert!(done.status() < 0);
    assert!(
        weak.upgrade().is_none(),
        "hardware fetch owns private copied WC pages, not a closed caller handle"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_intel_cursor_writer_dependency_and_handle_close_keep_only_owned_resources
);
