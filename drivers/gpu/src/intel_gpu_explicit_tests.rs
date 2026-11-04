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
    // Each published engine retires a seed and a switch context. Preserve
    // the no-consumption assertion without assuming a fixed engine count.
    let first_user_id = (2 * gt.engines().unwrap().iter().count() + 1) as u16;
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
    assert_eq!(
        id, first_user_id,
        "failed output transactions consumed an identity"
    );
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
            engines: gt.engines().unwrap(),
        })),
        pending: IrqSafeSpinLock::new(Vec::new()),
    });
    let info = DeviceInfo {
        device_id: 0xe20b,
        platform,
        memory_bytes: 0x80000000,
        hwconfig: None,
        topology: None,
        vram: None,
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
        SyncRequest::read(&user, &wire, &file.syncobjs),
        Err(FsError::InvalidData)
    ));
    // A sync_file containing the signalled stub has zero leaf dependencies.
    user.files.lock().insert(99, Vec::new());
    let resolved = SyncRequest::read(&user, &wire, &file.syncobjs)
        .unwrap()
        .resolve();
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
        let result = SyncRequest::read(&user, &wire, &file.syncobjs).map(SyncRequest::resolve);
        assert!(matches!(result,Err(e) if e==error));
        assert!(core.fence().is_none());
    }
    put64(
        &mut wire,
        40,
        abi::EXEC_FENCE_ARRAY | abi::EXEC_USE_EXTENSIONS,
    );
    assert!(matches!(
        SyncRequest::read(&user, &wire, &file.syncobjs),
        Err(FsError::InvalidData)
    ));
    put32(&mut wire, 28, 0);
    put64(&mut wire, 40, abi::EXEC_USE_EXTENSIONS);
    put64(&mut wire, 32, 1536);
    // parse_execbuf2_extensions walks i915_user_extensions, which keeps no
    // visited set: a self-referencing empty TIMELINE_FENCES is parsed 512
    // times and the 513th link is -E2BIG (this pinned -EINVAL).
    let mut extension = [0; 56];
    put64(&mut extension, 0, 1536);
    user.user.store(1536, &extension);
    assert!(matches!(
        SyncRequest::read(&user, &wire, &file.syncobjs),
        Err(FsError::ArgumentListTooLong)
    ));
    // Only DRM_I915_GEM_EXECBUFFER_EXT_TIMELINE_FENCES (0) is in the table.
    put64(&mut extension, 0, 0);
    put32(&mut extension, 8, 1);
    user.user.store(1536, &extension);
    assert!(matches!(
        SyncRequest::read(&user, &wire, &file.syncobjs),
        Err(FsError::InvalidData)
    ));
    put32(&mut extension, 8, 0);
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
        matches!(SyncRequest::read(&user, &wire, &file.syncobjs), Err(FsError::InvalidData)),
        "waiting and signalling the same timeline point creates a cycle"
    );
    assert!(core.fence().is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_explicit_wire_failures_leave_syncobjs_untouched
);

/// MIT Linux b90c984d i915_gem_execbuffer.c::add_timeline_fence_array:2786
/// and add_fence_array:2919: overflow bound (EINVAL), access_ok of each
/// array (EFAULT) and the eb->fences krealloc (ENOMEM above KMALLOC_MAX_SIZE)
/// precede the entries; then each entry is copied, flag-checked, its point
/// read, its syncobj found (ENOENT) and its fence resolved before the next
/// entry is copied. i915_gem_do_execbuffer parses the IN/SUBMIT sync_file
/// only after both arrays. There is no other fence-count bound.
fn smoke_explicit_fence_arrays_resolve_entry_by_entry() -> TestResult {
    use crate::intel_gpu_exec_sync::SyncRequest;
    const END: u64 = 32768; // first unreadable fixture byte
    // access_ok's bound, spelled out: x86_64 USER_PTR_MAX = TASK_SIZE_MAX =
    // (1 << 47) - PAGE_SIZE; arm64 TASK_SIZE_MAX = 1 << 48.
    const USER_LIMIT: u64 = if cfg!(target_arch = "aarch64") {
        1 << 48
    } else {
        (1 << 47) - 4096
    };
    let file = RenderFile::new();
    let user = Fds::new();
    let handle = file.syncobjs.lock().create(0).unwrap();
    let core = file.syncobjs.lock().get(handle).unwrap().core().clone();
    let bad = handle + 100;
    let entry = |at: u64, handle: u32, flags: u32| {
        let mut bytes = [0; 8];
        put32(&mut bytes, 0, handle);
        put32(&mut bytes, 4, flags);
        user.user.store(at, &bytes);
    };
    // A TIMELINE_FENCES link at `at`.
    let link = |at: u64, next: u64, count: u64, handles: u64, values: u64| {
        let mut extension = [0; 56];
        put64(&mut extension, 0, next);
        put64(&mut extension, 32, count);
        put64(&mut extension, 40, handles);
        put64(&mut extension, 48, values);
        user.user.store(at, &extension);
    };
    let timeline = |chain: u64| {
        let mut wire = [0; 64];
        put64(&mut wire, 40, abi::EXEC_USE_EXTENSIONS);
        put64(&mut wire, 32, chain);
        SyncRequest::read(&user, &wire, &file.syncobjs).map(|_| ())
    };
    let binary = |flags: u64, count: u32, array: u64, fd: u64| {
        let mut wire = [0; 64];
        put64(&mut wire, 40, abi::EXEC_FENCE_ARRAY | flags);
        put32(&mut wire, 28, count);
        put64(&mut wire, 32, array);
        put64(&mut wire, 56, fd);
        SyncRequest::read(&user, &wire, &file.syncobjs).map(|_| ())
    };
    user.user.store(2048, &[0; 16]); // two readable zero points
    let cases: [(u32, u32, u64, FsError, &str); 4] = [
        (bad, 0, 2048, FsError::NotFound, "drm_syncobj_find before entry 1"),
        (handle, 4, END, FsError::InvalidData, "flags before the point"),
        (bad, 0, END, FsError::BadAddress, "the point before the find"),
        (handle, 1, 2048, FsError::InvalidData, "WAIT with no fence"),
    ];
    for (object, flags, values, expected, why) in cases {
        // Entry 1 of the handles array is past the readable fixture.
        entry(END - 8, object, flags);
        link(1536, 0, 2, END - 8, values);
        assert_eq!(timeline(1536), Err(expected), "{why}");
    }
    // The same-point WAIT|SIGNAL refusal follows drm_syncobj_find.
    entry(1024, bad, 3);
    user.user.store(2048, &7u64.to_le_bytes());
    link(1536, 0, 1, 1024, 2048);
    assert_eq!(timeline(1536), Err(FsError::NotFound));
    entry(1024, handle, 3);
    assert_eq!(timeline(1536), Err(FsError::InvalidData));
    user.user.store(2048, &[0; 8]);

    // Preamble: access_ok of values precedes entry 0's ENOENT; the
    // overflow bound is EINVAL; past it access_ok fails; the krealloc of
    // (num_fences + nfences) * 32 bytes fails above 4 MiB.
    entry(1024, bad, 0);
    for (count, values, expected) in [
        (2, USER_LIMIT - 8, FsError::BadAddress),
        (1 << 59, 2048, FsError::InvalidData),
        ((1 << 59) - 1, 2048, FsError::BadAddress),
        (131_073, 2048, FsError::OutOfMemory),
        (131_072, 2048, FsError::NotFound),
    ] {
        link(1536, 0, count, 1024, values);
        assert_eq!(timeline(1536), Err(expected), "preamble {count}");
    }
    // access_ok admits an array ending exactly at the bound (the krealloc
    // then fails) and refuses one byte more, for either array. On x86_64
    // the last page below 1 << 47 is past USER_PTR_MAX.
    const BIG: u64 = 131_073;
    let at_limit = USER_LIMIT - BIG * 8;
    let page_below_half = if cfg!(target_arch = "aarch64") {
        FsError::OutOfMemory
    } else {
        FsError::BadAddress
    };
    for (handles, values, expected) in [
        (1024, at_limit, FsError::OutOfMemory),
        (at_limit, 2048, FsError::OutOfMemory),
        (1024, at_limit + 1, FsError::BadAddress),
        (at_limit + 1, 2048, FsError::BadAddress),
        (1024, (1 << 47) - BIG * 8, page_below_half),
    ] {
        link(1536, 0, BIG, handles, values);
        assert_eq!(timeline(1536), Err(expected), "access_ok {values:#x}");
    }
    // eb->num_fences spans the chain's extensions; a skipped (fence-less,
    // flag-less) entry is not added, an added SIGNAL entry is.
    for (flags, expected) in [(0, FsError::NotFound), (2, FsError::OutOfMemory)] {
        entry(4096, handle, flags);
        link(1536, 1600, 1, 4096, 2048);
        link(1600, 0, 131_072, 1024, 2048);
        assert_eq!(timeline(1536), Err(expected), "accumulated {flags}");
    }

    // add_timeline_fence_array's `err` survives a tolerated SIGNAL
    // find_seqno failure into a later fence-less entry of the same
    // extension, but not into the next extension.
    let binary_payload = file.syncobjs.lock().create(0).unwrap();
    file.syncobjs
        .lock()
        .get(binary_payload)
        .unwrap()
        .core()
        .replace_fence(Some(so::stub()));
    entry(4096, binary_payload, 2);
    entry(4104, handle, 0);
    user.user.store(8192, &5u64.to_le_bytes());
    user.user.store(8200, &[0; 8]);
    link(1536, 0, 2, 4096, 8192);
    assert_eq!(timeline(1536), Err(FsError::InvalidData));
    link(1536, 1600, 1, 4096, 8192);
    link(1600, 0, 1, 4104, 8200);
    assert_eq!(timeline(1536), Ok(()));

    // No 4096-entry cap: five links of 1000 SIGNAL entries, 5000 fences.
    for n in 0..1000 {
        entry(4096 + n * 8, handle, 2);
    }
    user.user.store(12288, &[0; 8000]);
    for n in 0..5 {
        let next = if n == 4 { 0 } else { 1600 + n * 64 };
        link(1536 + n * 64, next, 1000, 4096, 12288);
    }
    assert_eq!(timeline(1536), Ok(()));

    // FENCE_ARRAY: the same per-entry order and krealloc bound.
    entry(END - 8, bad, 0);
    assert_eq!(binary(0, 2, END - 8, 0), Err(FsError::NotFound));
    entry(END - 8, handle, 1);
    assert_eq!(binary(0, 2, END - 8, 0), Err(FsError::InvalidData));
    entry(1024, bad, 0);
    assert_eq!(binary(0, 131_073, 1024, 0), Err(FsError::OutOfMemory));
    assert_eq!(binary(0, 131_072, 1024, 0), Err(FsError::NotFound));
    assert_eq!(binary(0, 2, USER_LIMIT - 8, 0), Err(FsError::BadAddress));
    assert_eq!(
        binary(0, BIG as u32, at_limit, 0),
        Err(FsError::OutOfMemory)
    );
    assert_eq!(
        binary(0, BIG as u32, at_limit + 1, 0),
        Err(FsError::BadAddress)
    );
    assert_eq!(binary(0, 1000, 4096, 0), Ok(()));
    // The array is parsed before the IN/SUBMIT sync_file and its checks.
    for inputs in [
        abi::EXEC_FENCE_IN,
        abi::EXEC_FENCE_IN | abi::EXEC_FENCE_SUBMIT,
    ] {
        assert_eq!(binary(inputs, 1, 1024, 99), Err(FsError::NotFound));
        assert_eq!(binary(inputs, 1, 4096, 99), Err(FsError::InvalidData));
    }
    assert!(core.fence().is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_explicit_fence_arrays_resolve_entry_by_entry
);

/// MIT Linux b90c984d i915_gem_execbuffer.c::i915_gem_execbuffer2_ioctl:3555
/// runs check_buffer_count:3541 and i915_gem_check_execbuffer:2180, copies
/// the exec-object array (-EFAULT), and only then calls
/// i915_gem_do_execbuffer:3339, which refuses I915_EXEC_SECURE (-ENODEV)
/// before parse_execbuf2_extensions, add_fence_array and the IN/SUBMIT
/// sync_file; eb_lookup_vmas resolves the objects after all of them.
fn smoke_explicit_execbuffer_checks_and_copies_before_fences() -> TestResult {
    use crate::intel_gpu_exec::ExecRequest;
    const UNREADABLE: u64 = 0x7fff_0000;
    let file = RenderFile::new();
    let user = Fds::new();
    let object = file.gem.create(4096, |_, _| Ok(())).unwrap();
    // One pinned 48-bit object at 2 MiB, and a FENCE_ARRAY entry waiting on
    // a syncobj that does not exist (-ENOENT once parsed).
    let mut entry = [0; 56];
    put32(&mut entry, 0, object);
    put64(&mut entry, 24, 0x20_0000);
    put64(&mut entry, 32, 0x18);
    user.user.store(256, &entry);
    let mut fence = [0; 8];
    put32(&mut fence, 0, 99);
    put32(&mut fence, 4, 1);
    user.user.store(1024, &fence);
    let fenced = abi::EXEC_NO_RELOC | abi::EXEC_FENCE_ARRAY;
    let submit = |edit: &dyn Fn(&mut [u8; 64])| {
        let mut request = [0; 64];
        put64(&mut request, 0, 256);
        put32(&mut request, 8, 1);
        put32(&mut request, 16, 8);
        put32(&mut request, 28, 1);
        put64(&mut request, 32, 1024);
        put64(&mut request, 40, fenced);
        edit(&mut request);
        user.user.store(64, &request);
        ExecRequest::read_submission(&user, 64, &file.gem, &file.syncobjs).map(|(exec, _)| exec)
    };
    let errno = |edit: &dyn Fn(&mut [u8; 64])| submit(edit).map(|_| ());
    let plain = |request: &mut [u8; 64]| {
        put32(request, 28, 0);
        put64(request, 32, 0);
        put64(request, 40, abi::EXEC_NO_RELOC);
    };
    assert_eq!(errno(&|_| {}), Err(FsError::NotFound), "the fence array");
    // check_buffer_count and i915_gem_check_execbuffer, before the fences.
    let header: [(&dyn Fn(&mut [u8; 64]), &str); 8] = [
        (&|r: &mut [u8; 64]| put32(r, 8, 0), "no buffers"),
        (&|r: &mut [u8; 64]| put32(r, 12, 4), "batch_start_offset & 7"),
        (&|r: &mut [u8; 64]| put32(r, 16, 12), "batch_len & 7"),
        (&|r: &mut [u8; 64]| put32(r, 20, 1), "DR1"),
        (&|r: &mut [u8; 64]| put32(r, 24, 1), "DR4"),
        (&|r: &mut [u8; 64]| put64(r, 40, fenced | 1 << 6), "CONSTANTS_MASK"),
        (&|r: &mut [u8; 64]| put64(r, 40, fenced | 1 << 15), "RESOURCE_STREAMER"),
        (&|r: &mut [u8; 64]| put64(r, 40, fenced | 1 << 22), "unknown flag"),
    ];
    for (edit, why) in header {
        assert_eq!(errno(edit), Err(FsError::InvalidData), "{why}");
    }
    // DRI1 cliprects without FENCE_ARRAY or USE_EXTENSIONS: before the copy.
    assert_eq!(
        errno(&|r| {
            put64(r, 40, abi::EXEC_NO_RELOC);
            put64(r, 0, UNREADABLE);
        }),
        Err(FsError::InvalidData)
    );
    // The exec-object copy precedes the fences.
    assert_eq!(
        errno(&|r| put64(r, 0, UNREADABLE)),
        Err(FsError::BadAddress)
    );
    // SECURE: after the copy, before the fences.
    let secure = fenced | abi::EXEC_SECURE;
    assert_eq!(errno(&|r| put64(r, 40, secure)), Err(FsError::NoDevice));
    assert_eq!(
        errno(&|r| {
            put64(r, 40, secure);
            put64(r, 0, UNREADABLE);
        }),
        Err(FsError::BadAddress)
    );
    // The objects follow the fences: an unknown object flag loses to the
    // fence, and is -EINVAL without one.
    let mut bad = entry;
    put64(&mut bad, 32, 0x18 | 1 << 9);
    user.user.store(256, &bad);
    assert_eq!(errno(&|_| {}), Err(FsError::NotFound));
    assert_eq!(errno(&plain), Err(FsError::InvalidData));
    user.user.store(256, &entry);
    // UXA's DR4 0xffffffff is fixed up to 0; IS_PINNED only steers gen2;
    // rsvd1's upper half never reaches i915_gem_context_lookup(u32).
    let exec = submit(&|r| {
        plain(r);
        put32(r, 24, u32::MAX);
        put64(r, 40, abi::EXEC_NO_RELOC | abi::EXEC_IS_PINNED);
        put64(r, 48, 1 << 32 | 5);
    })
    .expect("accepted execbuffer");
    assert_eq!(exec.context_id, 5);
    // The synchronous kernel path keeps the same order.
    let mut request = [0; 64];
    put64(&mut request, 0, UNREADABLE);
    put32(&mut request, 8, 1);
    put32(&mut request, 16, 8);
    put64(&mut request, 40, abi::EXEC_NO_RELOC | abi::EXEC_SECURE);
    user.user.store(64, &request);
    assert_eq!(
        ExecRequest::read(&user, 64, &file.gem).map(|_| ()),
        Err(FsError::BadAddress)
    );
    put64(&mut request, 0, 256);
    user.user.store(64, &request);
    assert_eq!(
        ExecRequest::read(&user, 64, &file.gem).map(|_| ()),
        Err(FsError::NoDevice)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_explicit_execbuffer_checks_and_copies_before_fences
);

/// MIT Linux b90c984d i915_gem_execbuffer.c::i915_gem_do_execbuffer:3339
/// reads rsvd2 only for I915_EXEC_FENCE_IN/SUBMIT (lower_32_bits, the
/// sync_file) and FENCE_OUT (the reported fd); with none of them any
/// value is ignored, and i915_gem_check_execbuffer never looks at it.
fn smoke_explicit_execbuffer_ignores_rsvd2_without_fence_flags() -> TestResult {
    use crate::intel_gpu_exec::ExecRequest;
    let file = RenderFile::new();
    let user = Fds::new();
    let object = file.gem.create(4096, |_, _| Ok(())).unwrap();
    let mut entry = [0; 56];
    put32(&mut entry, 0, object);
    put64(&mut entry, 24, 0x20_0000);
    put64(&mut entry, 32, 0x18);
    user.user.store(256, &entry);
    let store = |flags: u64| {
        let mut request = [0; 64];
        put64(&mut request, 0, 256);
        put32(&mut request, 8, 1);
        put32(&mut request, 16, 8);
        put64(&mut request, 40, abi::EXEC_NO_RELOC | flags);
        put64(&mut request, 56, 0xdead_beef_0000_0063);
        user.user.store(64, &request);
    };
    store(0);
    let (_, sync) = ExecRequest::read_submission(&user, 64, &file.gem, &file.syncobjs)
        .expect("rsvd2 without fence flags");
    assert!(!sync.output);
    assert!(ExecRequest::read(&user, 64, &file.gem).is_ok(), "synchronous path");
    // FENCE_OUT keeps the low half for its report.
    store(abi::EXEC_FENCE_OUT);
    let (_, sync) = ExecRequest::read_submission(&user, 64, &file.gem, &file.syncobjs)
        .expect("FENCE_OUT");
    assert!(sync.output);
    assert_eq!(sync.input_word, 0x63);
    // FENCE_IN does read it: fd 0x63 is no sync_file.
    store(abi::EXEC_FENCE_IN);
    assert_eq!(
        ExecRequest::read_submission(&user, 64, &file.gem, &file.syncobjs).map(|_| ()),
        Err(FsError::InvalidData)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_explicit_execbuffer_ignores_rsvd2_without_fence_flags
);

mod submit {
    include!("intel_gpu_submit_tests.rs");
}
