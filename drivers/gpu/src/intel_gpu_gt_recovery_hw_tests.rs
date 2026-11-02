// Real GuCGt/CT/scheduler + common physical recovery coordinator. The mailbox
// transports actual native submissions; no fixture signals a fence or creates
// Ready. This is not physical PCI/Owner/firmware-file/S3 execution coverage.
use super::*;
use crate::intel_gpu_engine::{Engine, EngineSet};
use crate::intel_gpu_gt_runtime::recovery::{Coordinator, Publication, Worker};
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
struct RecoveryBackend {
    mailbox: Arc<Mailbox>,
    publication: Arc<Publication>,
    epoch: Arc<AtomicU64>,
    platform: GtPlatform,
}
impl UserBackend for RecoveryBackend {
    fn status(&self) -> Option<UserStatus> {
        let status = self.mailbox.status()?;
        (status.epoch != 0 && self.epoch.load(Ordering::Acquire) == status.epoch).then_some(status)
    }
    fn reset_availability_epoch(&self) -> Option<u64> {
        self.publication
            .epoch(self.platform, self.epoch.load(Ordering::Acquire))
    }
    fn native_xe(&self) -> bool {
        true
    }
    fn submit<'a>(
        &'a self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>> {
        self.mailbox.submit(context, batch)
    }
}

struct Fixture {
    io: Window,
    arena: Arena,
    gt: GuCGt<Window, Arena>,
    publication: Arc<Publication>,
    epoch: Arc<AtomicU64>,
    worker: Option<Worker>,
    coordinator: Coordinator,
    clock: u64,
}
impl Fixture {
    fn new(platform: GtPlatform, media: bool) -> Self {
        Self::with_topology(platform, media, |_| {})
    }

    fn with_topology(platform: GtPlatform, media: bool, topology: impl FnOnce(&Window)) -> Self {
        let ack = platform.guc_forcewake_ack().unwrap();
        let (io, arena, mut gt) = hardware_model(platform, ack);
        if media {
            assert!(platform.is_gen12());
            io.0.borrow_mut()
                .regs
                .insert(0x9140, 0x000f00ff & !0x00040042);
        }
        topology(&io); // physical fuse input precedes every discovery read
        let publication = Arc::new(Publication::new(platform));
        let epoch = Arc::new(AtomicU64::new(0));
        let worker = publication.worker(epoch.clone()).unwrap();
        hardware_discovery(&mut gt, &io, ack);
        hardware_scheduling(&mut gt, &io);
        let mut clock = 20_000_000;
        let completion = gt.begin_context_defaults(clock).unwrap();
        let mut registered = BTreeMap::new();
        for _ in 0..1024 {
            clock += 1;
            assert_eq!(gt.poll(clock), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&io, &mut registered, true);
            if completion.result().is_some() {
                break;
            }
        }
        assert_eq!(completion.result(), Some(Ok(())));
        assert!(registered.is_empty() && gt.context_defaults_ready());
        assert!(gt.recovery_identity().is_some());
        let coordinator = Coordinator::new(publication.clone());
        Self {
            io,
            arena,
            gt,
            publication,
            epoch,
            worker: Some(worker),
            coordinator,
            clock,
        }
    }

    fn qualify(&mut self) -> Vec<Engine> {
        let baseline = self.arena.live_allocations();
        self.coordinator
            .begin_qualification(&mut self.gt, self.clock)
            .unwrap();
        assert!(self.coordinator.ready(&self.gt).is_err());
        let engines = self.gt.engines().unwrap();
        let mut observed = Vec::new();
        let mut registered = BTreeMap::new();
        let mut complete = false;
        for _ in 0..1024 {
            self.clock += 1;
            assert_eq!(
                self.coordinator.poll(&mut self.gt, self.clock, || true),
                Poll::Ready(Ok(GtState::SchedulingReady))
            );
            let (engine, owned) = self.coordinator.pending_probe().unwrap();
            if observed.last() != Some(&engine) {
                assert!(owned.completion.result().is_none());
                assert!(owned.result.verify().is_err());
                observed.push(engine);
            }
            service_contexts(&self.io, &mut registered, true);
            assert!(self
                .publication
                .epoch(
                    self.gt.recovery_identity().unwrap().0,
                    self.gt.user_epoch().unwrap()
                )
                .is_none());
            if self
                .coordinator
                .advance_qualification(&mut self.gt, self.clock)
                .unwrap()
            {
                complete = true;
                break;
            }
        }
        assert!(complete && registered.is_empty());
        assert_eq!(observed, engines.iter().collect::<Vec<_>>());
        assert_eq!(self.arena.live_allocations(), baseline);
        observed
    }

    fn publish(&mut self) -> u64 {
        let epoch = self.gt.user_epoch().unwrap();
        self.coordinator.ready(&self.gt).unwrap().publish().unwrap();
        self.epoch.store(epoch, Ordering::Release);
        epoch
    }

    fn backend(&self) -> (Arc<RecoveryBackend>, DeviceInfo) {
        let (backend, info, _) = self.registered_backend();
        (backend, info)
    }

    fn registered_backend(&self) -> (Arc<RecoveryBackend>, DeviceInfo, u32) {
        let (platform, engines, _) = self.gt.recovery_identity().unwrap();
        let mailbox = Arc::new(Mailbox {
            status: IrqSafeSpinLock::new(Some(UserStatus {
                epoch: self.gt.user_epoch().unwrap(),
                platform,
                submission_version: self.gt.submission_version(),
                engines,
            })),
            pending: IrqSafeSpinLock::new(Vec::new()),
        });
        let backend = Arc::new(RecoveryBackend {
            mailbox,
            publication: self.publication.clone(),
            epoch: self.epoch.clone(),
            platform,
        });
        let device = match platform {
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake) => 0x9a49,
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeP) => 0x46a6,
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeS) => 0x4680,
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeN) => 0x46d1,
            GtPlatform::Alchemist => 0x56a0,
            GtPlatform::Battlemage => 0xe20b,
            _ if platform.is_lnl() => 0x6420,
            _ if platform.is_ptl() => 0xb080,
            _ => 0x7d55,
        };
        let card = Arc::new(crate::drm_devfs_bridge::IntelGpuCard::new(
            alloc::string::String::new(),
            0x8086,
            device,
            0,
            0,
        ));
        card.install_user_backend(backend.clone()).unwrap();
        let index = crate::drm_registry::register_drm_card(card);
        let info = DeviceInfo::for_card(index).unwrap();
        assert_eq!(info.platform, platform);
        (backend, info, index)
    }

    fn stop(mut self) {
        self.coordinator.fault();
        self.epoch.store(0, Ordering::Release);
        let platform = self.io.0.borrow().profile.unwrap();
        hardware_stop(
            &mut self.gt,
            &self.io,
            platform.guc_forcewake_ack().unwrap(),
        );
        drop(self.gt);
        assert_eq!(self.arena.live_allocations(), 0);
    }
}

fn raw_reset(file: &RenderFile, info: &DeviceInfo, user: &User) -> i32 {
    let mut wire = [0; 16];
    put32(&mut wire, 0, 35);
    put64(&mut wire, 8, 512);
    user.store(64, &wire);
    user.store(508, &[0xa5; 12]);
    assert_eq!(file.dispatch(info, abi::GETPARAM, 64, user), Some(Ok(0)));
    assert_eq!(user.load(508, 4), [0xa5; 4]);
    assert_eq!(user.load(516, 4), [0xa5; 4]);
    let value = u32_at(&user.load(512, 4), 0) as i32;
    assert!(matches!(value, 0 | 1));
    value
}

fn smoke_i915_reset_every_engine_qualification_and_cached_raw_level() -> TestResult {
    use crate::{intel_gpu::Generation, intel_gpu_gt::Gen12Platform};
    for platform in [
        GtPlatform::Gen12(Gen12Platform::TigerLake),
        GtPlatform::Gen12(Gen12Platform::AlderLakeP),
        GtPlatform::Gen12(Gen12Platform::AlderLakeS),
        GtPlatform::Gen12(Gen12Platform::AlderLakeN),
        GtPlatform::Alchemist,
        GtPlatform::Battlemage,
        GtPlatform::Integrated(Generation::MeteorLake),
        GtPlatform::Integrated(Generation::LunarLake),
        GtPlatform::Integrated(Generation::PantherLake),
    ] {
        let mut fixture = Fixture::new(platform, platform.is_gen12());
        let (backend, info) = fixture.backend();
        let file = RenderFile::new();
        let user = User::new();
        assert_eq!(raw_reset(&file, &info, &user), 0);
        let engines = fixture.qualify();
        if platform.is_gen12() {
            assert_eq!(
                engines,
                [
                    Engine::Rcs0,
                    Engine::Bcs0,
                    Engine::Vcs1,
                    Engine::Vcs6,
                    Engine::Vecs2
                ]
            );
        }
        let epoch = fixture.publish();
        assert_eq!(backend.reset_availability_epoch(), Some(epoch));
        let before = {
            let d = fixture.io.0.borrow();
            (
                d.writes.len(),
                d.mmio_reads.get(),
                d.gmd_reads,
                d.regs.clone(),
                fixture.arena.live_allocations(),
            )
        };
        for _ in 0..4 {
            assert_eq!(raw_reset(&file, &info, &user), 1);
        }
        let d = fixture.io.0.borrow();
        assert_eq!(
            (
                d.writes.len(),
                d.mmio_reads.get(),
                d.gmd_reads,
                d.regs.clone(),
                fixture.arena.live_allocations()
            ),
            before
        );
        drop(d);
        // Same real status transported by a backend without a recovery owner.
        let mut unsupported = info.clone();
        unsupported.backend = Some(backend.mailbox.clone());
        assert_eq!(raw_reset(&file, &unsupported, &user), 0);
        let mut foreign = info.clone();
        foreign.platform = if platform == GtPlatform::Battlemage {
            GtPlatform::Alchemist
        } else {
            GtPlatform::Battlemage
        };
        assert_eq!(raw_reset(&file, &foreign, &user), 0);
        let original = *backend.mailbox.status.lock();
        for change in 0..3 {
            let mut status = original.unwrap();
            match change {
                0 => status.epoch += 1,
                1 => status.engines = EngineSet::default(),
                _ => status.submission_version = (2, 0, 0),
            }
            *backend.mailbox.status.lock() = Some(status);
            assert_eq!(raw_reset(&file, &info, &user), 0);
        }
        *backend.mailbox.status.lock() = original;
        raw_reset(&file, &info, &user);
        user.fault_write_at(Some(512));
        assert_eq!(
            file.dispatch(&info, abi::GETPARAM, 64, &user),
            Some(Err(FsError::BadAddress))
        );
        user.fault_write_at(None);
        assert_eq!(raw_reset(&file, &info, &user), 1);
        fixture.stop();
        assert_eq!(raw_reset(&file, &info, &user), 0);
    }
    two_card_recovery_isolation();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_recovery",
    smoke_i915_reset_every_engine_qualification_and_cached_raw_level
);

/// Continue a cleanup already accepted by the common coordinator. No helper
/// calls begin_stop again, and missing independent full-reset proof is tested
/// before the model supplies it. These are BMG's established stop literals.
fn retire_bmg(fixture: &mut Fixture, start: u64, completion: &CompletionFence) {
    assert!(fixture
        .coordinator
        .poll(&mut fixture.gt, start + 1, || true)
        .is_pending());
    reset_done(&fixture.io);
    fixture.io.0.borrow_mut().regs.insert(0xc314, 0);
    assert!(fixture
        .coordinator
        .poll(&mut fixture.gt, start + 2, || true)
        .is_pending());
    assert_eq!(fixture.gt.state(), GtState::ResettingEngines);
    assert_eq!(fixture.io.0.borrow().regs.get(&0x941c), Some(&1));
    let retained = fixture.arena.live_allocations();
    assert!(fixture
        .coordinator
        .poll(&mut fixture.gt, start + 3, || true)
        .is_pending());
    assert_eq!(fixture.arena.live_allocations(), retained);
    assert!(completion.result().is_none());
    // This fresh self-clear/status/DMA observation is the independent proof.
    reset_done(&fixture.io);
    assert!(fixture
        .coordinator
        .poll(&mut fixture.gt, start + 4, || true)
        .is_pending());
    assert_eq!(
        completion.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    assert!(fixture
        .coordinator
        .poll(&mut fixture.gt, start + 5, || true)
        .is_pending());
    fixture.io.0.borrow_mut().regs.insert(0xd84, 0);
    assert!(fixture
        .coordinator
        .poll(&mut fixture.gt, start + 6, || true)
        .is_pending());
    fixture.io.0.borrow_mut().regs.insert(0xdfc, 0);
    assert_eq!(
        fixture
            .coordinator
            .poll(&mut fixture.gt, start + 7, || true),
        Poll::Ready(Ok(GtState::Stopped))
    );
}

fn replace_stopped(fixture: &mut Fixture) {
    replace_stopped_with_topology(fixture, |_| {});
}

fn replace_stopped_with_topology(fixture: &mut Fixture, topology: impl FnOnce(&Window)) {
    assert_eq!(fixture.gt.state(), GtState::Stopped);
    let old_arena = fixture.arena.clone();
    let (io, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    topology(&io); // clean resume observes the same actual physical fuse input
    hardware_discovery(&mut gt, &io, 0xdfc);
    hardware_scheduling(&mut gt, &io);
    let mut clock = 20_000_000;
    let completion = gt.begin_context_defaults(clock).unwrap();
    let mut registered = BTreeMap::new();
    for _ in 0..200 {
        clock += 1;
        assert_eq!(gt.poll(clock), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&io, &mut registered, true);
        if completion.result().is_some() {
            break;
        }
    }
    assert_eq!(completion.result(), Some(Ok(())));
    assert!(registered.is_empty());
    fixture.gt = gt; // the old, proven Stopped graph alone is reclaimed
    assert_eq!(old_arena.live_allocations(), 0);
    fixture.io = io;
    fixture.arena = arena;
    fixture.clock = clock;
}

fn refresh_status(backend: &RecoveryBackend, gt: &GuCGt<Window, Arena>) {
    *backend.mailbox.status.lock() = Some(UserStatus {
        epoch: gt.user_epoch().unwrap(),
        platform: gt.recovery_identity().unwrap().0,
        submission_version: gt.submission_version(),
        engines: gt.engines().unwrap(),
    });
}

fn recovery_census(fixture: &Fixture) -> (usize, usize, u32, BTreeMap<u64, u32>, usize) {
    let device = fixture.io.0.borrow();
    (
        device.writes.len(),
        device.mmio_reads.get(),
        device.gmd_reads,
        device.regs.clone(),
        fixture.arena.live_allocations(),
    )
}

fn two_card_recovery_isolation() {
    let mut first = Fixture::new(GtPlatform::Battlemage, false);
    let mut second = Fixture::new(GtPlatform::Alchemist, false);
    first.qualify();
    second.qualify();
    let first_epoch = first.publish();
    let second_epoch = second.publish();
    assert_ne!(first_epoch, second_epoch);
    assert!(!Arc::ptr_eq(&first.publication, &second.publication));
    let (first_backend, first_info, first_index) = first.registered_backend();
    let (second_backend, second_info, second_index) = second.registered_backend();
    assert_ne!(first_index, second_index);
    assert_ne!(first_info.device_id, second_info.device_id);
    assert_eq!(
        crate::drm_registry::pci_id(first_index),
        Some((0x8086, 0xe20b))
    );
    assert_eq!(
        crate::drm_registry::pci_id(second_index),
        Some((0x8086, 0x56a0))
    );
    assert!(!Arc::ptr_eq(&first_backend, &second_backend));
    let first_file = RenderFile::new();
    let second_file = RenderFile::new();
    let first_user = User::new();
    let second_user = User::new();
    assert_eq!(raw_reset(&first_file, &first_info, &first_user), 1);
    assert_eq!(raw_reset(&second_file, &second_info, &second_user), 1);

    // The unaffected registered card owns an actual raw i915 private store.
    // Execute its ENABLE once, then leave its terminal retirement pending
    // throughout the other card's fault, full reset and requalification.
    let second_baseline = second.arena.live_allocations();
    let handles = buffers(&second_file, &second_info, &second_user);
    let code = Arc::downgrade(&second_file.gem.object(handles[0]).unwrap());
    let data = second_file.gem.object(handles[1]).unwrap();
    let mut value = [0; 4];
    data.read(0x80, &mut value).unwrap();
    assert_eq!(value, [0; 4]);
    exec(&second_user, handles, 0);
    let (context, completion) = {
        let mut call = core::pin::pin!(second_file.dispatch_user(
            &second_info,
            abi::GEM_EXECBUFFER2,
            64,
            &second_user,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(call.as_mut().poll(&mut cx).is_pending());
        let accepted = second_backend.mailbox.accept(&mut second.gt, second.clock);
        assert_eq!(call.as_mut().poll(&mut cx), Poll::Ready(Some(Ok(0))));
        accepted
    };
    let weak_context = Arc::downgrade(&context);
    drop(context);
    let mut second_registered = BTreeMap::new();
    let mut enabled = false;
    for _ in 0..100 {
        second.clock += 1;
        assert_eq!(
            second
                .coordinator
                .poll(&mut second.gt, second.clock, || true),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        if service_contexts(&second.io, &mut second_registered, true).contains(&0x1001) {
            enabled = true;
            break;
        }
    }
    assert!(enabled && !second_registered.is_empty());
    assert!(completion.result().is_none());
    assert_eq!(data.read(0x80, &mut value), Err(FsError::WouldBlock));
    drop(second_file);
    assert!(code.upgrade().is_some());
    assert!(weak_context.upgrade().unwrap().busy());
    let second_file = RenderFile::new();
    let second_identity = second.gt.recovery_identity().unwrap();
    let second_pending = recovery_census(&second);

    let stalled = first.gt.submit_ppgtt_probe(first.clock).unwrap();
    let first_completion = stalled.completion.clone();
    let first_objects = stalled.result.weak_objects();
    drop(stalled);
    let mut first_registered = BTreeMap::new();
    for _ in 0..20 {
        first.clock += 1;
        assert_eq!(
            first.coordinator.poll(&mut first.gt, first.clock, || true),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        service_contexts(&first.io, &mut first_registered, false);
    }
    assert!(!first_registered.is_empty() && first_completion.result().is_none());
    assert_eq!(
        first
            .coordinator
            .poll(&mut first.gt, first.clock + 1, || false),
        Poll::Ready(Err(GtError::Unavailable))
    );
    assert_eq!(raw_reset(&first_file, &first_info, &first_user), 0);
    assert_eq!(raw_reset(&second_file, &second_info, &second_user), 1);
    assert_eq!(recovery_census(&second), second_pending);
    first.epoch.store(0, Ordering::Release);
    assert_eq!(
        first
            .coordinator
            .begin_cleanup(&mut first.gt, 10_000_000_000),
        Ok(true)
    );
    retire_bmg(&mut first, 10_000_000_000, &first_completion);
    assert!(first_objects
        .iter()
        .all(|object| object.upgrade().is_none()));
    assert_eq!(first.coordinator.after_stop(&first.gt), Ok(true));
    assert_eq!(raw_reset(&first_file, &first_info, &first_user), 0);
    assert_eq!(raw_reset(&second_file, &second_info, &second_user), 1);
    assert_eq!(recovery_census(&second), second_pending);
    assert!(completion.result().is_none() && code.upgrade().is_some());
    assert!(weak_context.upgrade().unwrap().busy());

    first.coordinator.cold();
    replace_stopped(&mut first);
    first.qualify();
    refresh_status(&first_backend, &first.gt);
    let recovered_epoch = first.publish();
    assert_ne!(recovered_epoch, first_epoch);
    assert_eq!(second.epoch.load(Ordering::Acquire), second_epoch);
    assert_eq!(second.gt.recovery_identity(), Some(second_identity));
    assert_eq!(raw_reset(&first_file, &first_info, &first_user), 1);
    assert_eq!(raw_reset(&second_file, &second_info, &second_user), 1);
    assert_eq!(recovery_census(&second), second_pending);

    // Only the unaffected card's own actual CT/retirement conversation may
    // complete its fence and release the closed file's context/code graph.
    for _ in 0..100 {
        second.clock += 1;
        assert_eq!(
            second
                .coordinator
                .poll(&mut second.gt, second.clock, || true),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        service_contexts(&second.io, &mut second_registered, true);
        if completion.result().is_some() {
            break;
        }
    }
    assert_eq!(completion.result(), Some(Ok(())));
    assert!(second_registered.is_empty());
    assert!(weak_context.upgrade().is_none() && code.upgrade().is_none());
    data.read(0x80, &mut value).unwrap();
    assert_eq!(u32::from_le_bytes(value), 0x4e415246);
    assert_eq!(second.arena.live_allocations(), second_baseline);
    assert_eq!(second.gt.recovery_identity(), Some(second_identity));
    assert_eq!(raw_reset(&second_file, &second_info, &second_user), 1);
    drop(data);
    let second_idle = recovery_census(&second);
    first.stop();
    assert_eq!(first_backend.reset_availability_epoch(), None);
    assert_eq!(
        second_backend.reset_availability_epoch(),
        Some(second_epoch)
    );
    assert_eq!(raw_reset(&first_file, &first_info, &first_user), 0);
    assert_eq!(raw_reset(&second_file, &second_info, &second_user), 1);
    assert_eq!(recovery_census(&second), second_idle);
    drop((first_file, second_file));
    second.stop();
    assert_eq!(first_backend.reset_availability_epoch(), None);
    assert_eq!(second_backend.reset_availability_epoch(), None);
}

fn smoke_i915_reset_watchdog_retained_cleanup_cold_and_requalification() -> TestResult {
    let mut fixture = Fixture::new(GtPlatform::Battlemage, false);
    fixture.qualify();
    let old = fixture.publish();
    let (backend, info) = fixture.backend();
    let file = RenderFile::new();
    let user = User::new();
    assert_eq!(raw_reset(&file, &info, &user), 1);
    // Accept an actual raw i915 job, then close its file/caller references.
    let handles = buffers(&file, &info, &user);
    exec(&user, handles, 0);
    let (context, user_fence) = {
        let mut call = core::pin::pin!(file.dispatch_user(&info, abi::GEM_EXECBUFFER2, 64, &user));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(call.as_mut().poll(&mut cx).is_pending());
        let accepted = backend.mailbox.accept(&mut fixture.gt, fixture.clock);
        assert_eq!(call.as_mut().poll(&mut cx), Poll::Ready(Some(Ok(0))));
        accepted
    };
    let weak_context = Arc::downgrade(&context);
    drop(context);
    drop(file);
    let file = RenderFile::new();
    {
        let mut wait = core::pin::pin!(user_fence.wait());
        assert!(wait
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    // A trusted job supplies the existing mandatory global fallback timeout;
    // user cancellation/preemption alone is not a full-reset receipt.
    let probe = fixture.gt.submit_ppgtt_probe(fixture.clock).unwrap();
    let weak = probe.result.weak_objects();
    let completion = probe.completion.clone();
    drop(probe);
    let mut registered = BTreeMap::new();
    for _ in 0..20 {
        fixture.clock += 1;
        assert_eq!(
            fixture
                .coordinator
                .poll(&mut fixture.gt, fixture.clock, || true),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        service_contexts(&fixture.io, &mut registered, false);
    }
    assert!(!registered.is_empty() && completion.result().is_none());
    assert!(weak_context.upgrade().unwrap().busy());
    let before = fixture
        .io
        .0
        .borrow()
        .writes
        .iter()
        .filter(|(reg, _)| matches!(*reg, 0x941c | 0xc000))
        .count();
    assert_eq!(
        fixture
            .coordinator
            .poll(&mut fixture.gt, fixture.clock + 5_000_000_000, || true),
        Poll::Ready(Err(GtError::Scheduling(
            crate::intel_gpu_guc_sched::SchedulingError::Timeout
        )))
    );
    assert_eq!(fixture.gt.state(), GtState::Lost);
    assert_eq!(raw_reset(&file, &info, &user), 0);
    assert_eq!(
        fixture
            .io
            .0
            .borrow()
            .writes
            .iter()
            .filter(|(reg, _)| matches!(*reg, 0x941c | 0xc000))
            .count(),
        before,
        "fault observation must not overtake owner diagnostics/IRQ closure"
    );
    assert!(completion.result().is_none() && user_fence.result().is_none());
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    // Physical Owner additionally closes IRQs, snapshots diagnostics and
    // quarantines display before entering this common cleanup entry point.
    fixture.epoch.store(0, Ordering::Release);
    assert_eq!(
        fixture
            .coordinator
            .begin_cleanup(&mut fixture.gt, 10_000_000_000),
        Ok(true)
    );
    retire_bmg(&mut fixture, 10_000_000_000, &completion);
    assert_eq!(
        user_fence.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    assert!(weak.iter().all(|object| object.upgrade().is_none()));
    assert!(weak_context.upgrade().is_none());
    assert_eq!(fixture.coordinator.after_stop(&fixture.gt), Ok(true));
    fixture.coordinator.cold();
    assert_eq!(raw_reset(&file, &info, &user), 0);
    replace_stopped(&mut fixture);
    assert_ne!(fixture.gt.user_epoch(), Some(old));
    assert!(fixture.coordinator.ready(&fixture.gt).is_err());
    fixture.qualify();
    refresh_status(&backend, &fixture.gt);
    let current = fixture.publish();
    assert_ne!(current, old);
    assert_eq!(raw_reset(&file, &info, &user), 1);
    fixture.stop();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_recovery",
    smoke_i915_reset_watchdog_retained_cleanup_cold_and_requalification
);

fn two_ccs_bmg_topology(io: &Window) {
    // Linux xe_gt_regs.h: XEHP_FUSE4 CCS_EN[19:16], CFEG_WMTP_DISABLE bit20,
    // GT_L3_EXC[6:4]. Same physical sparse CCS1/3 input as discover(BMG,10).
    // Mode1 initially selects one engine; the two physical slices permit mode2.
    io.0.borrow_mut()
        .regs
        .insert(0x9114, 0x10 | (0b1010 << 16) | (1 << 20));
}

fn smoke_i915_reset_park_refusal_same_epoch_and_ccs_refusal_keep_ready() -> TestResult {
    let mut fixture = Fixture::with_topology(GtPlatform::Battlemage, false, two_ccs_bmg_topology);
    assert_eq!(fixture.gt.compute_configuration(), Some((0b1010, 1)));
    fixture.qualify();
    let epoch = fixture.publish();
    let (backend, info) = fixture.backend();
    let file = RenderFile::new();
    let user = User::new();
    let probe = fixture.gt.submit_ppgtt_probe(fixture.clock).unwrap();
    let compute = fixture.gt.compute_configuration().unwrap();
    // Production cached park admission sees actual unfinished GPU ownership.
    assert_eq!(
        fixture.coordinator.accept_park(&fixture.gt, epoch),
        Err(GtError::Busy)
    );
    assert_eq!(raw_reset(&file, &info, &user), 1);
    let control = crate::intel_gpu_ccs_control::Control::fixture();
    control.publish_with(epoch, compute, || {}).unwrap();
    control.fixture_request(2).unwrap();
    assert_eq!(
        control.begin(&mut fixture.gt, epoch, fixture.clock, |_| panic!(
            "busy CCS callback"
        )),
        Ok(None)
    );
    assert_eq!(raw_reset(&file, &info, &user), 1);
    let mut registered = BTreeMap::new();
    for _ in 0..100 {
        fixture.clock += 1;
        assert_eq!(
            fixture
                .coordinator
                .poll(&mut fixture.gt, fixture.clock, || true),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        service_contexts(&fixture.io, &mut registered, true);
        if probe.completion.result().is_some() {
            break;
        }
    }
    assert_eq!(probe.completion.result(), Some(Ok(())));
    assert_eq!(probe.result.verify(), Ok(()));
    assert!(registered.is_empty());
    drop(probe);
    assert_eq!(
        fixture.coordinator.accept_park(&fixture.gt, epoch),
        Ok((epoch, fixture.gt.engines().unwrap(), compute))
    );
    // A clean park deliberately keeps the user epoch while availability is0.
    assert_eq!(fixture.epoch.load(Ordering::Acquire), epoch);
    assert_eq!(raw_reset(&file, &info, &user), 0);
    hardware_stop(&mut fixture.gt, &fixture.io, 0xdfc);
    fixture.coordinator.cold();
    replace_stopped_with_topology(&mut fixture, two_ccs_bmg_topology);
    assert_eq!(raw_reset(&file, &info, &user), 0);
    fixture.qualify();
    assert_eq!(fixture.gt.compute_configuration(), Some(compute));
    fixture.gt.adopt_user_epoch(epoch).unwrap();
    refresh_status(&backend, &fixture.gt);
    assert_eq!(raw_reset(&file, &info, &user), 0);
    assert_eq!(fixture.publish(), epoch);
    assert_eq!(raw_reset(&file, &info, &user), 1);
    fixture.stop();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_recovery",
    smoke_i915_reset_park_refusal_same_epoch_and_ccs_refusal_keep_ready
);

fn smoke_i915_reset_worker_cancellation_stale_ready_and_retained_dma() -> TestResult {
    let mut fixture = Fixture::new(GtPlatform::Battlemage, false);
    fixture.qualify();
    let stale = fixture.coordinator.ready(&fixture.gt).unwrap();
    fixture.publication.withdraw();
    assert_eq!(stale.publish(), Err(GtError::State));
    fixture.qualify();
    let stale = fixture.coordinator.ready(&fixture.gt).unwrap();
    drop(fixture.worker.take());
    assert_eq!(stale.publish(), Err(GtError::State));
    fixture.worker = Some(fixture.publication.worker(fixture.epoch.clone()).unwrap());
    fixture.qualify();
    let epoch = fixture.publish();
    let (backend, info) = fixture.backend();
    let file = RenderFile::new();
    let user = User::new();
    assert_eq!(raw_reset(&file, &info, &user), 1);
    assert!(fixture.publication.worker(fixture.epoch.clone()).is_err());
    assert_eq!(backend.reset_availability_epoch(), Some(epoch));
    let probe = fixture.gt.submit_ppgtt_probe(fixture.clock).unwrap();
    let completion = probe.completion.clone();
    let weak = probe.result.weak_objects();
    drop(probe);
    let live = fixture.arena.live_allocations();
    let before = {
        let d = fixture.io.0.borrow();
        (d.writes.len(), d.mmio_reads.get())
    };
    drop(fixture.worker.take());
    assert_eq!(fixture.epoch.load(Ordering::Acquire), 0);
    assert_eq!(backend.reset_availability_epoch(), None);
    assert_eq!(raw_reset(&file, &info, &user), 0);
    assert_eq!(fixture.arena.live_allocations(), live);
    let d = fixture.io.0.borrow();
    assert_eq!((d.writes.len(), d.mmio_reads.get()), before);
    drop(d);
    assert!(completion.result().is_none());
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    fixture.stop();
    assert_eq!(
        completion.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    assert!(weak.iter().all(|object| object.upgrade().is_none()));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_recovery",
    smoke_i915_reset_worker_cancellation_stale_ready_and_retained_dma
);

fn smoke_i915_reset_initial_fault_and_failed_cleanup_cannot_restart() -> TestResult {
    // A not-yet-published graph may be cleaned but cannot get automatic Cold.
    let mut initial = Fixture::new(GtPlatform::Battlemage, false);
    initial
        .coordinator
        .begin_qualification(&mut initial.gt, initial.clock)
        .unwrap();
    let completion = initial
        .coordinator
        .pending_probe()
        .unwrap()
        .1
        .completion
        .clone();
    let weak = initial
        .coordinator
        .pending_probe()
        .unwrap()
        .1
        .result
        .weak_objects();
    assert_eq!(
        initial
            .coordinator
            .poll(&mut initial.gt, initial.clock + 1, || false),
        Poll::Ready(Err(GtError::Unavailable))
    );
    assert!(initial.coordinator.ready(&initial.gt).is_err());
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    assert_eq!(
        initial
            .coordinator
            .begin_cleanup(&mut initial.gt, 10_000_000_000),
        Ok(true)
    );
    retire_bmg(&mut initial, 10_000_000_000, &completion);
    assert_eq!(initial.coordinator.after_stop(&initial.gt), Ok(false));
    assert!(weak.iter().all(|object| object.upgrade().is_none()));
    drop(initial.gt);
    assert_eq!(initial.arena.live_allocations(), 0);

    let mut fixture = Fixture::new(GtPlatform::Battlemage, false);
    fixture.qualify();
    fixture.publish();
    let (backend, info) = fixture.backend();
    let file = RenderFile::new();
    let user = User::new();
    let probe = fixture.gt.submit_ppgtt_probe(fixture.clock).unwrap();
    let completion = probe.completion.clone();
    let weak = probe.result.weak_objects();
    drop(probe);
    assert_eq!(
        fixture
            .coordinator
            .poll(&mut fixture.gt, fixture.clock + 1, || false),
        Poll::Ready(Err(GtError::Unavailable))
    );
    fixture.epoch.store(0, Ordering::Release);
    assert_eq!(raw_reset(&file, &info, &user), 0);
    assert_eq!(
        fixture
            .coordinator
            .begin_cleanup(&mut fixture.gt, 10_000_000_000),
        Ok(true)
    );
    assert!(fixture
        .coordinator
        .poll(&mut fixture.gt, 10_000_000_001, || true)
        .is_pending());
    reset_done(&fixture.io);
    // GuC reset alone with firmware DMA still active is not retirement.
    fixture.io.0.borrow_mut().regs.insert(0xc314, 1);
    assert!(fixture
        .coordinator
        .poll(&mut fixture.gt, 10_000_000_002, || true)
        .is_pending());
    let retained = fixture.arena.live_allocations();
    assert!(matches!(
        fixture
            .coordinator
            .poll(&mut fixture.gt, 12_000_000_000, || true),
        Poll::Ready(Err(_))
    ));
    assert_eq!(fixture.arena.live_allocations(), retained);
    assert!(completion.result().is_none());
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    assert_eq!(
        fixture
            .coordinator
            .begin_cleanup(&mut fixture.gt, 12_000_000_001),
        Ok(false)
    );
    assert!(fixture.coordinator.ready(&fixture.gt).is_err());
    assert_eq!(backend.reset_availability_epoch(), None);
    // An independent recovery can still retire retained owners. Its later
    // success cannot revive the failed coordinator's automatic-restart claim.
    fixture.io.0.borrow_mut().regs.insert(0xc314, 0);
    fixture.gt.begin_stop(20_000_000_000).unwrap();
    retire_bmg(&mut fixture, 20_000_000_000, &completion);
    assert_eq!(fixture.coordinator.after_stop(&fixture.gt), Ok(false));
    drop(fixture.gt);
    assert_eq!(fixture.arena.live_allocations(), 0);
    assert!(weak.iter().all(|object| object.upgrade().is_none()));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_recovery",
    smoke_i915_reset_initial_fault_and_failed_cleanup_cannot_restart
);

fn smoke_i915_reset_qualification_cache_failure_never_publishes() -> TestResult {
    let mut fixture = Fixture::new(GtPlatform::Battlemage, false);
    fixture.io.0.borrow_mut().fail_sync = true;
    assert!(fixture
        .coordinator
        .begin_qualification(&mut fixture.gt, fixture.clock)
        .is_err());
    assert!(fixture.coordinator.ready(&fixture.gt).is_err());
    assert_eq!(
        fixture
            .publication
            .epoch(GtPlatform::Battlemage, fixture.gt.user_epoch().unwrap_or(0)),
        None
    );
    fixture.io.0.borrow_mut().fail_sync = false;
    fixture.stop();

    let mut fixture = Fixture::new(GtPlatform::Battlemage, false);
    fixture
        .coordinator
        .begin_qualification(&mut fixture.gt, fixture.clock)
        .unwrap();
    let completion = fixture
        .coordinator
        .pending_probe()
        .unwrap()
        .1
        .completion
        .clone();
    let weak = fixture
        .coordinator
        .pending_probe()
        .unwrap()
        .1
        .result
        .weak_objects();
    let mut registered = BTreeMap::new();
    fixture.io.0.borrow_mut().fail_cpu_sync = true;
    let mut lost = false;
    for _ in 0..100 {
        fixture.clock += 1;
        if let Poll::Ready(Err(_)) =
            fixture
                .coordinator
                .poll(&mut fixture.gt, fixture.clock, || true)
        {
            lost = true;
            break;
        }
        service_contexts(&fixture.io, &mut registered, true);
    }
    assert!(lost && fixture.gt.state() == GtState::Lost);
    assert!(fixture.coordinator.ready(&fixture.gt).is_err());
    assert!(completion.result().is_none());
    assert!(weak.iter().all(|object| object.upgrade().is_some()));
    fixture.io.0.borrow_mut().fail_cpu_sync = false;
    fixture.stop();
    assert_eq!(
        completion.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    assert!(weak.iter().all(|object| object.upgrade().is_none()));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_recovery",
    smoke_i915_reset_qualification_cache_failure_never_publishes
);
