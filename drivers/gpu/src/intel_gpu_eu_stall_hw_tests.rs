// Exact LNL source vectors through actual GuCGt owners and raw Xe ioctls.
// A mailbox transports Send futures to the !Send deterministic GT model;
// it never fabricates a sampler control result or a DMA retirement proof.
use super::*;
use crate::{
    intel_gpu_eu_stall::{Config, Info, Operation, Session},
    intel_gpu_render::{DeviceInfo, RenderFile, tests::User},
    intel_gpu_user::{UserBackend, UserBatch, UserContext, UserStatus},
    intel_gpu_xe_uapi as xe,
};
use alloc::boxed::Box;
use core::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Waker},
};
use narf_filesystem::{FileOps, FsError, FsFuture, IoctlContext, ReadOptions};
use narf_lib::sync::IrqSafeSpinLock;

fn lnl_gt(did: u16) -> (EuStallWindow, Arena, GuCGt<EuStallWindow, Arena>, u32) {
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake);
    let (inner, arena) = model();
    {
        let mut d = inner.0.borrow_mut();
        d.profile = Some(platform);
        d.regs.extend([
            (0xdfc, 0),
            (0xa188, 2),
            (0xa278, 2),
            (0xd84, 0),
            (0xfd0, 1),
            (0x913c, 5),
            (0x9144, 6),
            (0x9134, 0x81),
            (0x9114, 0xf0010),
            (0x9118, 1),
            (0xd8c, (20 << 22) | (4 << 14)),
            (0x38a188, 0),
            (0x380dfc, 0),
            (0x380d8c, 20 << 22),
            (0x38941c, 0),
            (0x38c000, 1),
            (0x38c314, 0),
            (0x138000, (18 << 16) | 180),
            (0x13800c, 90),
            (0x145998, (6 << 16) | 60),
            (0x145ef0, 30 << 8),
        ]);
    }
    let io = EuStallWindow {
        inner,
        samplers: Rc::new(RefCell::new(EuStallRegisters::default())),
    };
    let boot = GuCBoot::stage_image(
        io.clone(),
        arena.clone(),
        platform,
        CssImage::parse(&image(), 70).unwrap(),
        BootConfig {
            device_id: did,
            revision: 3,
            huc_upload_bytes: 0,
            uncached_mocs: Some(3),
        },
    )
    .unwrap();
    let mut gt = GuCGt::from_staged_hardware(boot).unwrap();
    assert_eq!(gt.prepare_eu_stall(62), Err(FsError::Unsupported));
    hardware_discovery(&mut gt, &io.inner, 0xdfc);
    let old: BTreeSet<_> = io.inner.0.borrow().memory.keys().copied().collect();
    gt.prepare_eu_stall(62).unwrap();
    let base = *io
        .inner
        .0
        .borrow()
        .memory
        .keys()
        .find(|base| !old.contains(*base))
        .unwrap();
    let info = gt.eu_stall_info().unwrap();
    assert_eq!((info.platform, info.dss, info.per_group), (platform, 7, 4));
    assert_eq!(
        io.inner.0.borrow().memory[&base].borrow().len() * 4,
        3 * 524288
    );
    assert!(gt.user_epoch().is_none());
    hardware_scheduling(&mut gt, &io.inner);
    let fence = gt.begin_context_defaults(26).unwrap();
    let mut contexts = BTreeMap::new();
    let mut heavy = 0;
    for now in 27..300 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        if fence.result().is_some() {
            break;
        }
        heavy += service_contexts(&io.inner, &mut contexts, true)
            .iter()
            .filter(|a| **a == 0x7000)
            .count();
    }
    assert_eq!(fence.result(), Some(Ok(())));
    assert!(gt.user_epoch().is_some() && heavy >= 2 && contexts.is_empty());
    assert!(!io.inner.0.borrow().writes.iter().any(|(r, _)| *r == 0xe520));
    (io, arena, gt, base)
}
fn stop(gt: &mut GuCGt<EuStallWindow, Arena>, io: &EuStallWindow, base: u32) {
    gt.begin_stop(100_000_000).unwrap();
    assert!(gt.user_epoch().is_none());
    assert!(gt.poll(100_000_001).is_pending());
    assert!(io.inner.0.borrow().memory.contains_key(&base));
    reset_done(&io.inner);
    assert!(gt.poll(100_000_002).is_pending());
    assert_eq!(gt.state(), GtState::ResettingEngines);
    assert_eq!(io.inner.0.borrow().regs[&0x941c], 1);
    assert!(io.inner.0.borrow().memory.contains_key(&base));
    assert!(gt.poll(100_000_003).is_pending());
    reset_done(&io.inner); // independent full graphics-GT reset completion
    assert!(gt.poll(100_000_004).is_pending());
    assert!(!io.inner.0.borrow().memory.contains_key(&base));
    assert!(gt.eu_stall_info().is_none());
    for now in 100_000_005..100_000_100 {
        lnl_progress(&io.inner);
        let result = gt.poll(now);
        assert!(!matches!(result, Poll::Ready(Err(_))), "{result:?}");
        if gt.state() == GtState::Stopped {
            return;
        }
    }
    panic!("LNL retained media wake did not retire")
}

#[derive(Debug)]
struct Reply {
    result: IrqSafeSpinLock<Option<Result<(), FsError>>>,
}
#[derive(Debug)]
struct Request {
    session: Arc<Session>,
    operation: Operation,
    reply: Arc<Reply>,
}
#[derive(Debug)]
struct Mailbox {
    status: IrqSafeSpinLock<Option<UserStatus>>,
    info: Info,
    pending: IrqSafeSpinLock<Option<Request>>,
}
impl Mailbox {
    fn accept(&self, gt: &mut GuCGt<EuStallWindow, Arena>) {
        let request = self.pending.lock().take().expect("raw observation request");
        let result = gt.control_eu_stall(request.session, request.operation, || true);
        *request.reply.result.lock() = Some(result);
    }
}
impl UserBackend for Mailbox {
    fn status(&self) -> Option<UserStatus> {
        *self.status.lock()
    }
    fn native_xe(&self) -> bool {
        true
    }
    fn eu_stall_info(&self) -> Option<Info> {
        self.status().map(|_| self.info)
    }
    fn eu_stall_control(&self, session: Arc<Session>, operation: Operation) -> FsFuture<'_, ()> {
        Box::pin(async move {
            let reply = Arc::new(Reply {
                result: IrqSafeSpinLock::new(None),
            });
            let request = Request {
                session,
                operation,
                reply: reply.clone(),
            };
            assert!(self.pending.lock().replace(request).is_none());
            core::future::poll_fn(|_| match reply.result.lock().take() {
                Some(result) => Poll::Ready(result),
                None => Poll::Pending,
            })
            .await
        })
    }
    fn submit<'a>(
        &'a self,
        _: Arc<UserContext>,
        _: UserBatch,
    ) -> FsFuture<'a, Arc<crate::intel_gpu_fence::CompletionFence>> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
}
struct Cpu {
    wire: User,
    file: IrqSafeSpinLock<Option<Arc<dyn FileOps>>>,
    install: AtomicBool,
}
impl Cpu {
    fn new() -> Self {
        Self {
            wire: User::new(),
            file: IrqSafeSpinLock::new(None),
            install: AtomicBool::new(true),
        }
    }
    fn opening(&self) {
        let mut wire = [0u8; 32];
        wire[8..16].copy_from_slice(&1u64.to_le_bytes());
        wire[24..32].copy_from_slice(&128u64.to_le_bytes());
        self.wire.store(32, &wire);
        let mut property = [0u8; 32];
        property[16..20].copy_from_slice(&1u32.to_le_bytes());
        self.wire.store(128, &property); // source GT_ID = 0
    }
}
impl IoctlContext for Cpu {
    fn nonblocking(&self) -> bool {
        self.wire.nonblocking()
    }
    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), FsError> {
        self.wire.read(address, bytes)
    }
    fn write(&self, address: u64, bytes: &[u8]) -> Result<(), FsError> {
        self.wire.write(address, bytes)
    }
    fn install_file(&self, file: Arc<dyn FileOps>, cloexec: bool) -> Result<i32, FsError> {
        assert!(!cloexec);
        if !self.install.load(Ordering::Acquire) {
            return Err(FsError::OutOfMemory);
        }
        assert!(self.file.lock().replace(file).is_none());
        Ok(37)
    }
}
static ALLOWED: AtomicBool = AtomicBool::new(true);
fn capable(cap: u32) -> bool {
    cap == 38 && ALLOWED.load(Ordering::Acquire)
}
struct CapabilityHook(Option<fn(u32) -> bool>);
impl CapabilityHook {
    fn new() -> Self {
        Self(narf_filesystem::__test_swap_caller_capable_hook(Some(
            capable,
        )))
    }
}
impl Drop for CapabilityHook {
    fn drop(&mut self) {
        narf_filesystem::__test_swap_caller_capable_hook(self.0);
    }
}
fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = Box::pin(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("unexpected observation wait"),
    }
}
fn smoke_lnl_eu_stall_raw_query_open_cancel_reopen_and_full_reset_owner() -> TestResult {
    let _hook = CapabilityHook::new();
    ALLOWED.store(true, Ordering::Release);
    for did in [0x6420, 0x64a0, 0x64b0] {
        let (io, arena, mut gt, base) = lnl_gt(did);
        let backend = Arc::new(Mailbox {
            status: IrqSafeSpinLock::new(Some(UserStatus {
                epoch: gt.user_epoch().unwrap(),
                platform: GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake),
                submission_version: gt.submission_version(),
                engines: gt.engines().unwrap(),
            })),
            info: gt.eu_stall_info().unwrap(),
            pending: IrqSafeSpinLock::new(None),
        });
        let card = Arc::new(crate::drm_devfs_bridge::IntelGpuCard::new(
            alloc::string::String::new(),
            0x8086,
            did,
            0,
            0,
        ));
        card.install_user_backend(backend.clone()).unwrap();
        let index = crate::drm_registry::register_drm_card(card);
        let info = DeviceInfo::for_card(index).unwrap();
        let file = RenderFile::new();
        let cpu = Cpu::new();
        let mut query = [0u8; 40];
        query[8..12].copy_from_slice(&10u32.to_le_bytes());
        cpu.wire.store(64, &query);
        let reads = io.inner.0.borrow().mmio_reads.get();
        assert_eq!(
            ready(file.dispatch_user(&info, xe::DEVICE_QUERY, 64, &cpu)),
            Some(Ok(0))
        );
        let reply = cpu.wire.load(64, 40);
        assert_eq!(&reply[12..16], &136u32.to_le_bytes());
        query[12..16].copy_from_slice(&136u32.to_le_bytes());
        query[16..24].copy_from_slice(&512u64.to_le_bytes());
        cpu.wire.store(64, &query);
        assert_eq!(
            ready(file.dispatch_user(&info, xe::DEVICE_QUERY, 64, &cpu)),
            Some(Ok(0))
        );
        let bytes = cpu.wire.load(512, 136);
        assert_eq!(
            &bytes[8..32],
            &[1u64, 64, 524288]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            io.inner.0.borrow().mmio_reads.get(),
            reads,
            "query must not touch hardware"
        );
        cpu.opening();
        ALLOWED.store(false, Ordering::Release);
        assert_eq!(
            ready(file.dispatch_user(&info, xe::OBSERVATION, 32, &cpu)),
            Some(Err(FsError::PermissionDenied))
        );
        assert!(backend.pending.lock().is_none());
        ALLOWED.store(true, Ordering::Release);
        // Revoke current privilege across the real Attach await boundary.
        let mut denied = Box::pin(file.dispatch_user(&info, xe::OBSERVATION, 32, &cpu));
        assert!(
            denied
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        backend.accept(&mut gt);
        ALLOWED.store(false, Ordering::Release);
        assert_eq!(
            denied
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(FsError::PermissionDenied)))
        );
        drop(denied);
        gt.poll_eu_stall(399, || true);
        ALLOWED.store(true, Ordering::Release);
        assert!(cpu.file.lock().is_none());
        // Drop a raw open after the real GT accepts Attach but before fd install.
        let mut open = Box::pin(file.dispatch_user(&info, xe::OBSERVATION, 32, &cpu));
        assert!(
            open.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        backend.accept(&mut gt);
        drop(open);
        gt.poll_eu_stall(400, || true);
        assert!(cpu.file.lock().is_none());
        let retained = arena.live_allocations();
        // A fresh open attaches the same preallocated GGTT mapping.
        let mut open = Box::pin(file.dispatch_user(&info, xe::OBSERVATION, 32, &cpu));
        assert!(
            open.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        backend.accept(&mut gt);
        assert_eq!(
            open.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(37)))
        );
        drop(open);
        let descriptor = cpu.file.lock().take().unwrap();
        let mut enable = Box::pin(descriptor.ioctl_user(0x6900, 0, &cpu));
        assert!(
            enable
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        backend.accept(&mut gt);
        assert_eq!(
            enable
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(0))
        );
        drop(enable);
        assert!(!gt.idle());
        assert_eq!(arena.live_allocations(), retained);
        for dss in 0..3 {
            assert_eq!(io.samplers.borrow().values[&(dss, 0xe53c)], 0x34);
            assert_eq!(io.samplers.borrow().values[&(dss, 0xe520)], base | 0x12);
        }
        let record: [u32; 16] = core::array::from_fn(|n| 0x70605040 + n as u32);
        io.inner.0.borrow().memory[&base].borrow_mut()[..16].copy_from_slice(&record);
        io.samplers.borrow_mut().values.insert((0, 0xe528), 4);
        gt.poll_eu_stall(500, || true);
        let mut bytes = [0u8; 64];
        assert_eq!(
            ready(descriptor.read_with_options(0, &mut bytes, ReadOptions { nonblocking: true })),
            Ok(64)
        );
        assert_eq!(
            &bytes[..],
            record
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>()
                .as_slice()
        );
        io.samplers.borrow_mut().values.insert((0, 0xe528), 6); // observed drop
        gt.poll_eu_stall(5_000_500, || true);
        assert_eq!(
            ready(descriptor.read(0, &mut bytes)),
            Err(crate::intel_gpu_user::io_error())
        );
        ALLOWED.store(false, Ordering::Release);
        assert_eq!(
            ready(descriptor.read(0, &mut bytes)),
            Err(FsError::OperationNotPermitted)
        );
        ALLOWED.store(true, Ordering::Release);
        // Last close stops the real sampler, then another disabled open
        // reuses the identical BO without a new PTE or allocation.
        drop(descriptor);
        gt.poll_eu_stall(5_000_501, || true);
        assert!(gt.idle());
        assert_eq!(arena.live_allocations(), retained);
        for dss in 0..3 {
            assert_eq!(io.samplers.borrow().values[&(dss, 0xe520)], 0);
        }
        let mut open = Box::pin(file.dispatch_user(&info, xe::OBSERVATION, 32, &cpu));
        assert!(
            open.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        backend.accept(&mut gt);
        assert_eq!(
            open.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(37)))
        );
        drop(open);
        let descriptor = cpu.file.lock().take().unwrap();
        let mut enable = Box::pin(descriptor.ioctl_user(0x6900, 0, &cpu));
        assert!(
            enable
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        backend.accept(&mut gt);
        assert_eq!(
            enable
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(0))
        );
        drop(enable);
        assert_eq!(arena.live_allocations(), retained);
        stop(&mut gt, &io, base);
        *backend.status.lock() = None;
        assert_eq!(
            ready(descriptor.read(0, &mut bytes)),
            Err(FsError::NoDevice)
        );
        assert_eq!(
            ready(file.dispatch_user(&info, xe::DEVICE_QUERY, 64, &cpu)),
            Some(Err(FsError::NoDevice))
        );
        drop(descriptor);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_lnl_eu_stall_raw_query_open_cancel_reopen_and_full_reset_owner
);

fn smoke_lnl_eu_stall_live_media_cache_and_partial_authority_loss_retain_dma() -> TestResult {
    for failure in 0..6 {
        let (io, arena, mut gt, base) = lnl_gt(0x6420);
        let session =
            Session::new(gt.eu_stall_info().unwrap(), Config { rate: 4, wait: 1 }).unwrap();
        gt.control_eu_stall(session.clone(), Operation::Attach, || true)
            .unwrap();
        if failure == 0 {
            io.inner.0.borrow_mut().regs.insert(0x380dfc, 0);
        }
        if failure == 1 {
            io.inner.0.borrow_mut().regs.insert(0x400c, 0x130);
        }
        if failure == 2 {
            io.inner.0.borrow_mut().regs.insert(0x4808, 0xe);
        }
        if failure == 3 {
            io.samplers.borrow_mut().lose_media_on_read = Some(0xe520);
        }
        if failure == 4 {
            io.samplers.borrow_mut().lost = true;
        }
        let reads = io.inner.0.borrow().mmio_reads.get();
        assert!(
            gt.control_eu_stall(session.clone(), Operation::Enable, || failure != 5)
                .is_err()
        );
        if failure == 5 {
            assert_eq!(io.inner.0.borrow().mmio_reads.get(), reads);
        }
        assert!(
            !io.samplers
                .borrow()
                .values
                .iter()
                .any(|((_, r), v)| *r == 0xe520 && v & 2 != 0)
        );
        assert!(io.inner.0.borrow().memory.contains_key(&base));
        let retained = arena.live_allocations();
        // Restore model reachability for independent full reset; this is not
        // a sampler retry or a new admission proof. Old session remains lost.
        io.inner.0.borrow_mut().regs.extend([
            (0x380dfc, 1),
            (0x400c, 0x13c),
            (0x4808, 0xf),
            (0xfd0, 1),
        ]);
        io.samplers.borrow_mut().lose_media_on_read = None;
        io.samplers.borrow_mut().lost = false;
        stop(&mut gt, &io, base);
        assert!(arena.live_allocations() < retained);
        assert_eq!(session.read_for_test(&mut [0; 64]), Err(FsError::NoDevice));
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_lnl_eu_stall_live_media_cache_and_partial_authority_loss_retain_dma
);

fn smoke_lnl_eu_stall_wrong_ip_and_ptl_refuse_before_sampler_allocation() -> TestResult {
    for ptl in [false, true] {
        let platform = GtPlatform::Integrated(if ptl {
            crate::intel_gpu::Generation::PantherLake
        } else {
            crate::intel_gpu::Generation::LunarLake
        });
        let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
        hardware_discovery(&mut gt, &w, 0xdfc);
        let retained = arena.live_allocations();
        if !ptl {
            w.0.borrow_mut().regs.insert(0xd8c, (20 << 22) | (1 << 14));
        }
        assert_eq!(
            gt.prepare_eu_stall(62),
            Err(if ptl {
                FsError::Unsupported
            } else {
                FsError::NoDevice
            })
        );
        assert!(gt.eu_stall_info().is_none());
        assert_eq!(arena.live_allocations(), retained);
        assert!(!w.0.borrow().writes.iter().any(|(r, _)| *r == 0xe520));
        if !ptl {
            w.0.borrow_mut().regs.insert(0xd8c, (20 << 22) | (4 << 14));
        }
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_gt",
    smoke_lnl_eu_stall_wrong_ip_and_ptl_refuse_before_sampler_allocation
);
