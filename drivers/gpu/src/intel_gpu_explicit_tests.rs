use super::*;
use crate::drm::syncobj as so;
use crate::intel_gpu_user::UserOutput;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_filesystem::{DrmFence, InstallFdError, IoctlContext};

struct Fds {
    user: User,
    files: IrqSafeSpinLock<BTreeMap<i32, Vec<Arc<dyn DrmFence>>>>,
    fail_report: AtomicBool,
    full: AtomicBool,
}
impl Fds {
    fn new() -> Self {
        Self {
            user: User::new(),
            files: IrqSafeSpinLock::new(BTreeMap::new()),
            fail_report: AtomicBool::new(false),
            full: AtomicBool::new(false),
        }
    }
}
impl IoctlContext for Fds {
    fn read(&self, address: u64, data: &mut [u8]) -> Result<(), FsError> {
        self.user.read(address, data)
    }
    fn write(&self, address: u64, data: &[u8]) -> Result<(), FsError> {
        if self.fail_report.load(Ordering::Relaxed) && address == 120 {
            return Err(FsError::BadAddress);
        }
        self.user.write(address, data)
    }
    fn nonblocking(&self) -> bool {
        false
    }
    fn sync_file_fences(&self, fd: i32) -> Option<Vec<Arc<dyn DrmFence>>> {
        self.files.lock().get(&fd).cloned()
    }
    fn install_sync_file(
        &self,
        fences: Vec<Arc<dyn DrmFence>>,
        report: &mut dyn FnMut(i32) -> Result<(), FsError>,
    ) -> Result<i32, InstallFdError> {
        if self.full.load(Ordering::Relaxed) {
            return Err(InstallFdError::NoDescriptor);
        }
        report(17).map_err(InstallFdError::Report)?;
        self.files.lock().insert(17, fences);
        Ok(17)
    }
}

fn smoke_explicit_output_transaction_and_real_terminal_fence() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let baseline = arena.live_allocations();
    let context = UserContext::new();
    let user = Fds::new();
    user.user.store(120, &0x76543210u64.to_le_bytes());
    let output = UserOutput {
        user: &user,
        address: 120,
        input: 0x76543210,
    };
    for full in [true, false] {
        user.full.store(full, Ordering::Relaxed);
        user.fail_report.store(!full, Ordering::Relaxed);
        let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
        let weak = result.weak_objects();
        let error =
            gt.submit_user_batch_with_output(100, context.clone(), UserBatch(batch), &output);
        assert!(
            matches!(error,Err(GtError::Scheduling(crate::intel_gpu_guc_sched::SchedulingError::Output(e)))
            if e == if full {InstallFdError::NoDescriptor}else{InstallFdError::Report(FsError::BadAddress)})
        );
        assert!(!context.busy());
        assert!(context.last().is_none());
        assert!(user.files.lock().is_empty());
        assert_eq!(arena.live_allocations(), baseline);
        assert!(weak.iter().all(|o| o.upgrade().unwrap().busy() == 0));
    }
    user.fail_report.store(false, Ordering::Relaxed);
    let (batch, result) = PpgttProbeResult::prepare(platform).unwrap();
    let (id, fence) = gt
        .submit_user_batch_with_output(100, context.clone(), UserBatch(batch), &output)
        .unwrap();
    assert_eq!(id, 3, "failed output transactions consumed an identity");
    assert_eq!(
        u64_at(&user.user.load(120, 8), 0),
        (17u64 << 32) | 0x76543210
    );
    let exported = user.sync_file_fences(17).unwrap().pop().unwrap();
    let exact: Arc<dyn DrmFence> = fence.clone();
    assert!(Arc::ptr_eq(&exported, &exact));
    assert!(!exported.is_signalled());
    user.files.lock().clear();
    complete(&mut gt, &w, &fence, 101, 0xc01dcafe, 0x12345678);
    assert!(exported.is_signalled());
    assert_eq!(result.verify(), Ok(()));
    let (batch, _) = PpgttProbeResult::prepare(platform).unwrap();
    let (_, fence) = gt
        .submit_user_batch_with_output(200, context, UserBatch(batch), &output)
        .unwrap();
    let exported = user.sync_file_fences(17).unwrap().pop().unwrap();
    hardware_stop(&mut gt, &w, 0xdfc);
    assert_eq!(fence.result(), Some(Err(JobError::Reset)));
    assert!(exported.is_signalled());
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_explicit_output_transaction_and_real_terminal_fence
);

fn setup(platform: GtPlatform, gt: &GuCGt<Window, Arena>) -> (Arc<Mailbox>, DeviceInfo) {
    let backend = Arc::new(Mailbox {
        status: IrqSafeSpinLock::new(Some(UserStatus {
            epoch: gt.user_epoch().unwrap(),
            platform,
            submission_version: gt.submission_version(),
        })),
        pending: IrqSafeSpinLock::new(Vec::new()),
    });
    let info = DeviceInfo {
        device_id: 0xe20b,
        platform,
        memory_bytes: 0x80000000,
        hwconfig: None,
        topology: None,
        backend: Some(backend.clone()),
    };
    (backend, info)
}
fn reach_backend<F: Future>(mut call: core::pin::Pin<&mut F>, backend: &Mailbox) {
    let deadline = narf_time::monotonic_ns() + 10_000_000;
    while backend.pending.lock().is_empty() {
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(
            narf_time::monotonic_ns() < deadline,
            "ready dependency never resumed submission"
        );
        narf_scheduler::sleep_pumps::run();
    }
}

fn smoke_explicit_input_snapshot_cancel_and_gpu_ordering() -> TestResult {
    let platform = GtPlatform::Battlemage;
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (backend, info) = setup(platform, &gt);
    let file = RenderFile::new();
    let user = Fds::new();
    let handles = buffers(&file, &info, &user.user);
    let (batch, _) = PpgttProbeResult::prepare(platform).unwrap();
    let (_, dependency) = gt
        .submit_user_batch(100, UserContext::new(), UserBatch(batch))
        .unwrap();
    user.files.lock().insert(9, alloc::vec![dependency.clone()]);
    exec(&user.user, handles, 0);
    let mut wire = user.user.load(64, 64);
    let flags = u64_at(&wire, 40);
    put64(&mut wire, 40, flags | abi::EXEC_FENCE_IN);
    put64(&mut wire, 56, 9);
    user.user.store(64, &wire);
    {
        let mut cancelled =
            core::pin::pin!(file.dispatch_user(&info, abi::GEM_EXECBUFFER2, 64, &user));
        assert!(cancelled
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert!(backend.pending.lock().is_empty());
    let mut call = core::pin::pin!(file.dispatch_user(&info, abi::GEM_EXECBUFFER2, 64, &user));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    // Closing/reusing the input descriptor and rewriting flags cannot retarget
    // a copied request or release its original GPU dependency.
    user.files.lock().clear();
    user.user.store(64, &[0; 64]);
    complete(&mut gt, &w, &dependency, 101, 0xc01dcafe, 0x11111111);
    reach_backend(call.as_mut(), &backend);
    let (_, fence) = backend.accept(&mut gt, 200);
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );
    complete(&mut gt, &w, &fence, 201, 0xc01dcafe, 0x22222222);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_explicit_input_snapshot_cancel_and_gpu_ordering
);

fn smoke_explicit_syncobj_binary_timeline_and_handle_lifetime() -> TestResult {
    for timeline in [false, true] {
        let platform = GtPlatform::Battlemage;
        let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
        prime(&mut gt, &w, 0xdfc);
        let (backend, info) = setup(platform, &gt);
        let file = RenderFile::new();
        let user = User::new();
        let handles = buffers(&file, &info, &user);
        let create = || {
            let mut request = [0u8; 8];
            let address = request.as_mut_ptr() as u64;
            assert_eq!(
                narf_scheduler::block_on_spin(file.dispatch_user(
                    &info,
                    crate::drm_uapi::DRM_IOCTL_SYNCOBJ_CREATE,
                    address,
                    &user
                )),
                Some(Ok(0))
            );
            u32_at(&request, 0)
        };
        let input = create();
        let output = create();
        let in_core = file.syncobjs.lock().get(input).unwrap().core().clone();
        let out_core = file.syncobjs.lock().get(output).unwrap().core().clone();
        let (batch, _) = PpgttProbeResult::prepare(platform).unwrap();
        let (_, dependency) = gt
            .submit_user_batch(100, UserContext::new(), UserBatch(batch))
            .unwrap();
        let payload = so::from_drm_leaves(alloc::vec![dependency.clone()]);
        if timeline {
            in_core.add_point(payload, 7);
        } else {
            in_core.replace_fence(Some(payload));
        }
        exec(&user, handles, 0);
        let mut wire = user.load(64, 64);
        let flags = u64_at(&wire, 40);
        let mut entries = [0; 16];
        put32(&mut entries, 0, input);
        put32(&mut entries, 4, 1);
        put32(&mut entries, 8, output);
        put32(&mut entries, 12, 2);
        user.store(1024, &entries);
        if timeline {
            let mut ext = [0; 56];
            put64(&mut ext, 32, 2);
            put64(&mut ext, 40, 1024);
            put64(&mut ext, 48, 2048);
            user.store(1536, &ext);
            let mut points = [0; 16];
            put64(&mut points, 0, 7);
            put64(&mut points, 8, 11);
            user.store(2048, &points);
            put64(&mut wire, 40, flags | abi::EXEC_USE_EXTENSIONS);
            put64(&mut wire, 32, 1536);
        } else {
            put64(&mut wire, 40, flags | abi::EXEC_FENCE_ARRAY);
            put32(&mut wire, 28, 2);
            put64(&mut wire, 32, 1024);
        }
        user.store(64, &wire);
        let mut call =
            core::pin::pin!(file.dispatch_user(&info, abi::GEM_EXECBUFFER2_WR, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        file.syncobjs.lock().destroy(input).unwrap();
        file.syncobjs.lock().destroy(output).unwrap();
        assert!(out_core.fence().is_none());
        assert!(backend.pending.lock().is_empty());
        complete(&mut gt, &w, &dependency, 101, 0xc01dcafe, 0x11112222);
        reach_backend(call.as_mut(), &backend);
        let (_, fence) = backend.accept(&mut gt, 200);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        let signalled = out_core.find_fence(if timeline { 11 } else { 0 }).unwrap();
        assert!(!signalled.is_signalled());
        complete(&mut gt, &w, &fence, 201, 0xc01dcafe, 0x33334444);
        assert!(signalled.is_signalled());
        hardware_stop(&mut gt, &w, 0xdfc);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_explicit_syncobj_binary_timeline_and_handle_lifetime
);

fn smoke_explicit_wire_failures_leave_syncobjs_untouched() -> TestResult {
    use crate::intel_gpu_exec_sync::SyncRequest;
    let file = RenderFile::new();
    let user = Fds::new();
    let handle = file.syncobjs.lock().create(0).unwrap();
    let core = file.syncobjs.lock().get(handle).unwrap().core().clone();
    let mut wire = [0; 64];
    put64(&mut wire, 40, abi::EXEC_FENCE_IN);
    put64(&mut wire, 56, 99);
    assert!(matches!(
        SyncRequest::read(&user, &wire),
        Err(FsError::InvalidData)
    ));
    // A sync_file containing the signalled stub has zero leaf dependencies.
    user.files.lock().insert(99, Vec::new());
    let resolved = SyncRequest::read(&user, &wire)
        .unwrap()
        .resolve(&file.syncobjs)
        .unwrap();
    narf_scheduler::block_on_spin(resolved.wait());
    wire = [0; 64];
    put64(&mut wire, 40, abi::EXEC_FENCE_ARRAY);
    put32(&mut wire, 28, 1);
    put64(&mut wire, 32, 1024);
    for (object, flags, error) in [
        (handle, 4, FsError::InvalidData),
        (handle + 100, 1, FsError::NotFound),
        (handle, 1, FsError::InvalidData),
    ] {
        let mut entry = [0; 8];
        put32(&mut entry, 0, object);
        put32(&mut entry, 4, flags);
        user.user.store(1024, &entry);
        let result = SyncRequest::read(&user, &wire).and_then(|s| s.resolve(&file.syncobjs));
        assert!(matches!(result,Err(e) if e==error));
        assert!(core.fence().is_none());
    }
    put64(
        &mut wire,
        40,
        abi::EXEC_FENCE_ARRAY | abi::EXEC_USE_EXTENSIONS,
    );
    assert!(matches!(
        SyncRequest::read(&user, &wire),
        Err(FsError::InvalidData)
    ));
    put32(&mut wire, 28, 0);
    put64(&mut wire, 40, abi::EXEC_USE_EXTENSIONS);
    put64(&mut wire, 32, 1536);
    let mut extension = [0; 56];
    put64(&mut extension, 0, 1536);
    user.user.store(1536, &extension);
    assert!(matches!(
        SyncRequest::read(&user, &wire),
        Err(FsError::InvalidData)
    ));
    put64(&mut extension, 0, 0);
    put64(&mut extension, 32, 1);
    put64(&mut extension, 40, 1024);
    put64(&mut extension, 48, 2048);
    user.user.store(1536, &extension);
    let mut entry = [0; 8];
    put32(&mut entry, 0, handle);
    put32(&mut entry, 4, 3);
    user.user.store(1024, &entry);
    user.user.store(2048, &7u64.to_le_bytes());
    assert!(
        matches!(SyncRequest::read(&user, &wire), Err(FsError::InvalidData)),
        "waiting and signalling the same timeline point creates a cycle"
    );
    put32(&mut entry, 4, 2);
    user.user.store(1024, &entry);
    put64(&mut extension, 32, 4097);
    user.user.store(1536, &extension);
    assert!(matches!(
        SyncRequest::read(&user, &wire),
        Err(FsError::InvalidData)
    ));
    assert!(core.fence().is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_explicit_wire_failures_leave_syncobjs_untouched
);

mod submit {
    include!("intel_gpu_submit_tests.rs");
}
