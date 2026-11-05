// Literal BCS commands execute through the real GuC/CT/LRC/PPGTT owners.
use super::*;
use crate::intel_gpu_exec::copy::CopyRequest;
use crate::intel_gpu_fence::{CompletionFence, JobError};
use crate::intel_gpu_gem::{GemObject, GemState};
use crate::intel_gpu_guc_sched::SchedulingError;
use crate::intel_gpu_vram::Vram;
use narf_filesystem::FsError;

fn prime_copy(gt: &mut GuCGt<Window, Arena>, w: &Window, ack: u64) {
    hardware_discovery(gt, w, ack);
    hardware_scheduling(gt, w);
    let fence = gt.begin_context_defaults(26).unwrap();
    finish_copy(gt, w, &fence, 27);
}
fn finish_copy(gt: &mut GuCGt<Window, Arena>, w: &Window, fence: &CompletionFence, start: u64) {
    let mut registered = BTreeMap::new();
    for now in start..start + 200 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(w, &mut registered, true);
        if fence.result().is_some() {
            break;
        }
    }
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(registered.is_empty());
}
fn object(gem: &GemState, size: u64) -> Arc<GemObject> {
    gem.object(gem.create(size, |_, _| Ok(())).unwrap())
        .unwrap()
}
fn request(source: &Arc<GemObject>, destination: &Arc<GemObject>, len: u64) -> CopyRequest {
    CopyRequest::new(source.clone(), 0, destination.clone(), 0, len).unwrap()
}

fn smoke_copy_jobs_real_system_ranges_chunking_and_reservations() -> TestResult {
    for (platform, ack) in [
        (GtPlatform::Alchemist, 0x130044),
        (GtPlatform::Battlemage, 0xdfc),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        prime_copy(&mut gt, &w, ack);
        let gem = GemState::new();
        let bytes = 8 * 1024 * 1024 + 4096;
        let source = object(&gem, bytes + 3 * 4096);
        let destination = object(&gem, bytes + 3 * 4096);
        let pattern: Vec<_> = (0..bytes)
            .map(|i| ((i * 13 + (i >> 12)) & 255) as u8)
            .collect();
        source.write(4096, &pattern).unwrap();
        destination
            .write(0, &alloc::vec![0xa5; destination.size() as usize])
            .unwrap();
        let count = arena.live_allocations();
        let epoch = gt.user_epoch().unwrap();
        let fence = gt
            .copy_objects(
                250,
                CopyRequest::new(source.clone(), 4096, destination.clone(), 8192, bytes).unwrap(),
                epoch,
                None,
            )
            .unwrap();
        assert_eq!((source.busy(), destination.busy()), (0x10000, 0x10001));
        assert_eq!(source.write(0, &[1]), Err(FsError::WouldBlock));
        assert_eq!(destination.read(0, &mut [0]), Err(FsError::WouldBlock));
        let before = arena.live_allocations();
        assert!(matches!(
            gt.copy_objects(251, request(&source, &destination, 4096), epoch, None),
            Err(GtError::Scheduling(SchedulingError::Residency(
                FsError::WouldBlock
            )))
        ));
        assert_eq!(
            arena.live_allocations(),
            before,
            "conflict allocated a persistent job"
        );
        finish_copy(&mut gt, &w, &fence, 252);
        assert_eq!(arena.live_allocations(), count);
        assert_eq!((source.busy(), destination.busy()), (0, 0));
        let mut actual = alloc::vec![0; bytes as usize];
        destination.read(8192, &mut actual).unwrap();
        assert_eq!(actual, pattern);
        destination.read(0, &mut actual[..8192]).unwrap();
        assert!(actual[..8192].iter().all(|b| *b == 0xa5));
        let mut tail = [0; 4096];
        destination.read(8192 + bytes, &mut tail).unwrap();
        assert_eq!(tail, [0xa5; 4096]);
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_copy",
    smoke_copy_jobs_real_system_ranges_chunking_and_reservations
);

fn smoke_copy_jobs_range_alias_cache_and_epoch_refusals() -> TestResult {
    let gem = GemState::new();
    let source = object(&gem, 16384);
    let destination = object(&gem, 16384);
    for (s, d, len) in [
        (0, 0, 0),
        (1, 0, 4096),
        (0, 1, 4096),
        (0, 0, 4097),
        (0, 0, 20480),
        (u64::MAX - 4095, 0, 4096),
        (0, 0, 132 * 1024 * 1024),
    ] {
        assert_eq!(
            CopyRequest::new(source.clone(), s, destination.clone(), d, len).err(),
            Some(FsError::InvalidData)
        );
    }
    assert_eq!(
        CopyRequest::new(source.clone(), 0, source.clone(), 4096, 8192).err(),
        Some(FsError::InvalidData)
    );
    assert!(CopyRequest::new(source.clone(), 0, source.clone(), 8192, 4096).is_ok());
    let wc = match gem.create_placed(
        4096,
        None,
        crate::intel_gpu_gem::Placement::SystemWc,
        |_, _| Ok(()),
    ) {
        Ok(handle) => Some(gem.object(handle).unwrap()),
        Err(FsError::NotImplemented) if cfg!(target_arch = "aarch64") => None,
        Err(e) => panic!("create_placed SystemWc: {e:?}"),
    };
    if let Some(wc) = wc {
        assert_eq!(
            CopyRequest::new(wc, 0, destination.clone(), 0, 4096).err(),
            Some(FsError::Unsupported)
        );
    }
    // SAFETY: `source` retains this owned allocator frame throughout pinning
    // and the temporary USERPTR object's lifetime.
    let pin = unsafe {
        narf_memory::address_space::UserPagePin::retain_ram(narf_memory::PhysAddr::new(
            source.pages().next().unwrap(),
        ))
    };
    let userptr = GemObject::from_user_pins(alloc::vec![pin], 1).unwrap();
    assert_eq!(
        CopyRequest::new(userptr, 0, destination.clone(), 0, 4096).err(),
        Some(FsError::Unsupported)
    );
    for (platform, ack) in [
        (GtPlatform::Alchemist, 0x130044),
        (GtPlatform::Battlemage, 0xdfc),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        prime_copy(&mut gt, &w, ack);
        let before = arena.live_allocations();
        let writes = w.0.borrow().writes.len();
        let epoch = gt.user_epoch().unwrap();
        for wrong in [0, epoch + 1] {
            assert_eq!(
                gt.copy_objects(250, request(&source, &destination, 4096), wrong, None)
                    .err(),
                Some(GtError::State)
            );
        }
        assert_eq!(w.0.borrow().writes.len(), writes);
        assert_eq!(arena.live_allocations(), before);
        assert_eq!((source.busy(), destination.busy()), (0, 0));
        hardware_stop(&mut gt, &w, ack);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_copy",
    smoke_copy_jobs_range_alias_cache_and_epoch_refusals
);

struct Local {
    pool: Arc<Vram>,
    frame: narf_memory::frame::PhysFrame,
}
impl Local {
    fn new(platform: GtPlatform, gt: &mut GuCGt<Window, Arena>, w: &Window, ack: u64) -> Self {
        let bytes = 4 * 65536;
        w.0.borrow_mut().regs.extend([
            (0x1083a0, 1 << 8),
            (0x108104, 0),
            (
                0x108100,
                if platform == GtPlatform::Alchemist {
                    bytes + 4 * 1024 * 1024
                } else {
                    bytes
                },
            ),
            (0x4910, 4 << 8),
            (0x8800, 0),
        ]);
        prime_copy(gt, w, ack);
        let frame = narf_memory::frame::alloc_pages_on(0, 6).unwrap();
        let bar = narf_bus::MmioRegion {
            phys: frame.start_address(),
            virt: frame.start_address().kernel_ptr::<u8>() as u64,
            len: u64::from(bytes),
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: these exclusively owned contiguous frames simulate LMEM.
        unsafe { core::ptr::write_bytes(bar.virt as *mut u8, 0xa5, bar.len as usize) };
        let layout = gt.vram_layout().expect("production-qualified layout");
        assert_eq!(layout.usable, bar.len);
        // SAFETY: the same GT-qualified, exclusive fixture BAR remains live
        // until all jobs/BOs have retired and finish() is called.
        let pool = unsafe {
            if platform == GtPlatform::Alchemist {
                Vram::new_dg2(bar, layout)
            } else {
                Vram::new(bar, layout)
            }
        }
        .unwrap();
        crate::intel_gpu_exec::vram_clear::fixture_seed(0, bar.len, bar.virt);
        FIXTURE_VRAM.store(bar.phys.raw(), core::sync::atomic::Ordering::Relaxed);
        Self { pool, frame }
    }
    fn object(
        &self,
        gem: &GemState,
        gt: &mut GuCGt<Window, Arena>,
        w: &Window,
        now: u64,
    ) -> Arc<GemObject> {
        let pending = gem.prepare_vram(65536, None, &self.pool).unwrap();
        let clear = if gt.vram_needs_ccs_clear() {
            let fence = gt
                .clear_vram(now, pending.object(), gt.user_epoch().unwrap())
                .unwrap();
            finish_copy(gt, w, &fence, now + 1);
            fence
        } else {
            // SAFETY: the fake aperture and GT are exclusively owned here;
            // no real power/capability transition can overlap this chunk.
            unsafe {
                pending
                    .object()
                    .begin_cpu_vram_clear()
                    .unwrap()
                    .clear_next()
            }
            .unwrap()
        };
        let handle = gem.publish_vram(pending, &clear, |_, _| Ok(())).unwrap();
        gem.object(handle).unwrap()
    }
    fn finish(self) {
        assert_eq!(self.pool.used(), 0);
        drop(self.pool);
        crate::intel_gpu_exec::vram_clear::fixture_finish();
        FIXTURE_VRAM.store(0, core::sync::atomic::Ordering::Relaxed);
        narf_memory::frame::free_pages(self.frame, 6);
    }
}

fn smoke_copy_jobs_local_upload_copy_readback_and_ccs() -> TestResult {
    for (platform, ack) in [
        (GtPlatform::Alchemist, 0x130044),
        (GtPlatform::Battlemage, 0xdfc),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        let local = Local::new(platform, &mut gt, &w, ack);
        let gem = GemState::new();
        let first = local.object(&gem, &mut gt, &w, 250);
        let second = local.object(&gem, &mut gt, &w, 500);
        let source = object(&gem, 65536);
        let output = object(&gem, 65536);
        let pattern: Vec<_> = (0..65536)
            .map(|i| ((i * 37 + (i >> 8)) & 255) as u8)
            .collect();
        source.write(0, &pattern).unwrap();
        let epoch = gt.user_epoch().unwrap();
        let fence = gt
            .copy_objects(
                750,
                request(&source, &first, 65536),
                epoch,
                Some(&local.pool),
            )
            .unwrap();
        finish_copy(&mut gt, &w, &fence, 751);
        let auxiliary: Vec<_> = (0..256).map(|i| (i * 29) as u8).collect();
        if platform == GtPlatform::Alchemist {
            // A previous GPU workload may populate auxiliary state. Local
            // copy must preserve it, rather than clear the destination CCS.
            crate::intel_gpu_exec::vram_clear::fixture_metadata(
                first.pages().next().unwrap(),
                &auxiliary,
            );
        }
        let fence = gt
            .copy_objects(
                1000,
                request(&first, &second, 65536),
                epoch,
                Some(&local.pool),
            )
            .unwrap();
        finish_copy(&mut gt, &w, &fence, 1001);
        let mut actual = alloc::vec![0; 65536];
        second.read(0, &mut actual).unwrap();
        assert_eq!(actual, pattern);
        if platform == GtPlatform::Alchemist {
            let before = arena.live_allocations();
            assert!(matches!(
                gt.copy_objects(
                    1250,
                    request(&second, &output, 65536),
                    epoch,
                    Some(&local.pool)
                ),
                Err(GtError::Scheduling(SchedulingError::Residency(
                    FsError::Unsupported
                )))
            ));
            assert_eq!(arena.live_allocations(), before);
            let metadata = crate::intel_gpu_exec::vram_clear::fixture_state().0;
            assert_eq!(&metadata[..256], &auxiliary);
            assert_eq!(&metadata[256..512], &auxiliary);
            assert!(metadata[512..].iter().all(|b| *b == 0xa5));
            assert_eq!(
                CopyRequest::new(source.clone(), 0, first.clone(), 4096, 4096).err(),
                Some(FsError::InvalidData)
            );
        } else {
            let fence = gt
                .copy_objects(
                    1250,
                    request(&second, &output, 65536),
                    epoch,
                    Some(&local.pool),
                )
                .unwrap();
            finish_copy(&mut gt, &w, &fence, 1251);
            output.read(0, &mut actual).unwrap();
            assert_eq!(actual, pattern);
        }
        assert!(matches!(
            gt.copy_objects(1500, request(&first, &second, 65536), epoch, None),
            Err(GtError::Scheduling(SchedulingError::Residency(
                FsError::InvalidData
            )))
        ));
        let frame = narf_memory::frame::alloc_pages_on(0, 4).unwrap();
        let bar = narf_bus::MmioRegion {
            phys: frame.start_address(),
            virt: frame.start_address().kernel_ptr::<u8>() as u64,
            len: 65536,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: independent exclusive storage models a foreign card pool;
        // no BO uses it and it is dropped before the frames are released.
        let foreign = unsafe {
            if platform == GtPlatform::Alchemist {
                Vram::new_dg2(bar, local.pool.layout)
            } else {
                Vram::new(bar, local.pool.layout)
            }
        }
        .unwrap();
        let writes = w.0.borrow().writes.len();
        assert!(matches!(
            gt.copy_objects(1501, request(&first, &second, 65536), epoch, Some(&foreign)),
            Err(GtError::Scheduling(SchedulingError::Residency(
                FsError::InvalidData
            )))
        ));
        assert_eq!(w.0.borrow().writes.len(), writes);
        drop(foreign);
        narf_memory::frame::free_pages(frame, 4);
        drop((first, second, source, output, gem));
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
        local.finish();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_copy",
    smoke_copy_jobs_local_upload_copy_readback_and_ccs
);

fn smoke_copy_jobs_canceled_waiter_and_lost_gt_retain_until_full_reset() -> TestResult {
    use core::{
        future::Future,
        task::{Context, Waker},
    };
    for loss in [false, true] {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        prime_copy(&mut gt, &w, 0xdfc);
        let gem = GemState::new();
        let source = object(&gem, 4096);
        let destination = object(&gem, 4096);
        let weak = [Arc::downgrade(&source), Arc::downgrade(&destination)];
        let fence = gt
            .copy_objects(
                250,
                request(&source, &destination, 4096),
                gt.user_epoch().unwrap(),
                None,
            )
            .unwrap();
        {
            let mut wait = core::pin::pin!(fence.wait());
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
        drop((source, destination, gem));
        let mut registered = BTreeMap::new();
        for now in 251..275 {
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, false);
        }
        let count = arena.live_allocations();
        assert!(weak.iter().all(|object| object.upgrade().is_some()));
        let result = if loss {
            gt.poll_with_access(276, || false)
        } else {
            gt.poll(5_000_000_276)
        };
        assert!(
            matches!(result, Poll::Ready(Err(_))),
            "loss={loss} result={result:?}"
        );
        assert_eq!(gt.state(), GtState::Lost);
        assert!(fence.result().is_none());
        assert_eq!(weak[1].upgrade().unwrap().busy(), 0x10001);
        gt.begin_stop(10_000_000_000).unwrap();
        reset_done(&w);
        w.0.borrow_mut().regs.insert(0xc314, 0);
        assert!(gt.poll(10_000_000_001).is_pending());
        assert_eq!(gt.state(), GtState::ResettingEngines);
        assert_eq!(arena.live_allocations(), count);
        assert!(fence.result().is_none());
        assert!(weak.iter().all(|object| object.upgrade().is_some()));
        assert!(gt.poll(10_000_000_002).is_pending());
        reset_done(&w);
        assert!(gt.poll(10_000_000_003).is_pending());
        assert_eq!(fence.result(), Some(Err(JobError::Reset)));
        assert!(weak.iter().all(|object| object.upgrade().is_none()));
        w.0.borrow_mut().regs.insert(0xd84, 0);
        assert!(gt.poll(10_000_000_004).is_pending());
        w.0.borrow_mut().regs.insert(0xdfc, 0);
        assert_eq!(gt.poll(10_000_000_005), Poll::Ready(Ok(GtState::Stopped)));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_copy",
    smoke_copy_jobs_canceled_waiter_and_lost_gt_retain_until_full_reset
);

fn smoke_copy_jobs_cache_failure_before_publication_releases_reservations() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    prime_copy(&mut gt, &w, 0xdfc);
    let gem = GemState::new();
    let source = object(&gem, 4096);
    let destination = object(&gem, 4096);
    source.write(0, &[0x6d; 4096]).unwrap();
    let count = arena.live_allocations();
    let epoch = gt.user_epoch().unwrap();
    w.0.borrow_mut().fail_sync = true;
    assert_eq!(
        gt.copy_objects(250, request(&source, &destination, 4096), epoch, None)
            .err(),
        Some(GtError::Scheduling(SchedulingError::Cache))
    );
    assert_eq!(arena.live_allocations(), count);
    assert_eq!((source.busy(), destination.busy()), (0, 0));
    let mut actual = [1; 4096];
    destination.read(0, &mut actual).unwrap();
    assert_eq!(actual, [0; 4096]);
    w.0.borrow_mut().fail_sync = false;
    let fence = gt
        .copy_objects(251, request(&source, &destination, 4096), epoch, None)
        .unwrap();
    finish_copy(&mut gt, &w, &fence, 252);
    destination.read(0, &mut actual).unwrap();
    assert_eq!(actual, [0x6d; 4096]);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_copy",
    smoke_copy_jobs_cache_failure_before_publication_releases_reservations
);

fn smoke_copy_jobs_disjoint_alias_and_lost_wake_before_publication() -> TestResult {
    for fail in [false, true] {
        let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
        prime_copy(&mut gt, &w, 0xdfc);
        let gem = GemState::new();
        let data = object(&gem, 4 * 4096);
        data.write(0, &[0x5c; 4096]).unwrap();
        let count = arena.live_allocations();
        let epoch = gt.user_epoch().unwrap();
        let old_request = w.0.borrow().regs[&0xa188];
        let writes = w.0.borrow().writes.len();
        if fail {
            w.0.borrow_mut().regs.insert(0xa188, u32::MAX);
        }
        let copy = CopyRequest::new(data.clone(), 0, data.clone(), 8192, 4096).unwrap();
        let result = gt.copy_objects(250, copy, epoch, None);
        if fail {
            assert_eq!(result.err(), Some(GtError::Unavailable));
            assert_eq!(gt.state(), GtState::Lost);
            assert_eq!(arena.live_allocations(), count);
            assert_eq!(data.busy(), 0);
            assert_eq!(w.0.borrow().writes.len(), writes);
            w.0.borrow_mut().regs.insert(0xa188, old_request);
        } else {
            let fence = result.unwrap();
            assert_eq!(
                data.busy(),
                0x10001,
                "RO/RW aliases need one writer reservation"
            );
            finish_copy(&mut gt, &w, &fence, 251);
        }
        let mut actual = [0; 4096];
        data.read(8192, &mut actual).unwrap();
        assert_eq!(actual, [if fail { 0 } else { 0x5c }; 4096]);
        data.read(4096, &mut actual).unwrap();
        assert_eq!(actual, [0; 4096]);
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_copy",
    smoke_copy_jobs_disjoint_alias_and_lost_wake_before_publication
);
