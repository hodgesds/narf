// Included in intel_gpu_render::tests: native wire and shared PRIME coverage.
use crate::intel_gpu_fence::{CompletionFence, JobError};
use crate::intel_gpu_gem::reserve_gpu;
use core::{
    future::Future,
    pin::Pin,
    task::{Context as TaskContext, Poll, Waker},
};

fn poll_sync<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut TaskContext::from_waker(Waker::noop()))
}

fn smoke_intel_busy_wait_deadline_cancel_and_cpu_copy() -> TestResult {
    let file = RenderFile::new();
    let user = User::new();
    let info = info(Generation::MeteorLake);
    let handle = file.gem.create(4096, |_, _| Ok(())).unwrap();
    let object = file.gem.object(handle).unwrap();
    let completion = Arc::new(CompletionFence::new());
    reserve_gpu(&[(object.clone(), true)], &completion).unwrap();
    let mut request = [0; 16];
    put32(&mut request, 0, handle);
    user.store(64, &request);
    assert_eq!(invoke(&file, &user, abi::GEM_BUSY), Ok(0));
    assert_eq!(u32_at(&user.load(64, 8), 4), 0x10001);
    user.store(64, &request);
    let wait = file.dispatch_user(&info, abi::GEM_WAIT, 64, &user);
    assert_eq!(
        narf_scheduler::block_on_spin(wait),
        Some(Err(FsError::TimedOut))
    );
    assert_eq!(u64_at(&user.load(64, 16), 8), 0);
    put64(&mut request, 8, 1_000_000);
    user.store(64, &request);
    {
        let mut wait = core::pin::pin!(file.dispatch_user(&info, abi::GEM_WAIT, 64, &user));
        assert!(poll_sync(wait.as_mut()).is_pending());
        // A parked future owns its copied relative deadline. Rewriting the
        // wire cannot extend it or cause periodic restart with a fresh budget.
        put64(&mut request, 8, i64::MAX as u64);
        user.store(64, &request);
        assert_eq!(
            narf_scheduler::block_on_spin(wait),
            Some(Err(FsError::TimedOut))
        );
    }
    assert_eq!(u64_at(&user.load(64, 16), 8), 0);
    put64(&mut request, 8, u64::MAX);
    user.store(64, &request);
    {
        let mut wait = core::pin::pin!(file.dispatch_user(&info, abi::GEM_WAIT, 64, &user));
        assert!(poll_sync(wait.as_mut()).is_pending());
    }
    assert_eq!(object.busy(), 0x10001, "cancelled wait released a live job");
    assert!(completion.result().is_none());
    completion.signal(Err(JobError::Reset));
    assert_eq!(
        narf_scheduler::block_on_spin(file.dispatch_user(&info, abi::GEM_WAIT, 64, &user)),
        Some(Ok(0))
    );
    assert_eq!(u64_at(&user.load(64, 16), 8), u64::MAX);
    put32(&mut request, 4, 1);
    user.store(64, &request);
    assert_eq!(
        narf_scheduler::block_on_spin(file.dispatch_user(&info, abi::GEM_WAIT, 64, &user)),
        Some(Err(FsError::InvalidData))
    );
    put32(&mut request, 4, 0);
    put64(&mut request, 8, 0);
    user.store(64, &request);
    *user.fail_write.lock() = Some(72);
    assert_eq!(
        narf_scheduler::block_on_spin(file.dispatch_user(&info, abi::GEM_WAIT, 64, &user)),
        Some(Err(FsError::BadAddress))
    );
    *user.fail_write.lock() = None;

    let reader = Arc::new(CompletionFence::new());
    reserve_gpu(&[(object.clone(), false)], &reader).unwrap();
    let mut copy = [0; 32];
    put32(&mut copy, 0, handle);
    put64(&mut copy, 16, 1);
    put64(&mut copy, 24, 256);
    user.store(64, &copy);
    user.store(256, &[0x5a]);
    let mut write = core::pin::pin!(file.dispatch_user(&info, abi::GEM_PWRITE, 64, &user));
    assert!(poll_sync(write.as_mut()).is_pending());
    // Input for this chunk was already copied before sleeping.
    user.store(256, &[0xff]);
    reader.signal(Ok(()));
    assert_eq!(narf_scheduler::block_on_spin(write), Some(Ok(0)));
    let mut byte = [0];
    object.read(0, &mut byte).unwrap();
    assert_eq!(byte, [0x5a]);
    let domain_reader = Arc::new(CompletionFence::new());
    reserve_gpu(&[(object.clone(), false)], &domain_reader).unwrap();
    let mut domain = [0; 12];
    put32(&mut domain, 0, handle);
    put32(&mut domain, 4, 1);
    put32(&mut domain, 8, 1);
    user.store(64, &domain);
    let mut wait = core::pin::pin!(file.dispatch_user(&info, abi::GEM_SET_DOMAIN, 64, &user));
    assert!(poll_sync(wait.as_mut()).is_pending());
    file.gem.close(handle).unwrap();
    user.store(64, &[0; 12]);
    domain_reader.signal(Ok(()));
    assert_eq!(
        narf_scheduler::block_on_spin(wait),
        Some(Ok(0)),
        "parked domain wait lost its copied request/object"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_render",
    smoke_intel_busy_wait_deadline_cancel_and_cpu_copy
);

struct SyncExportUser {
    user: User,
    installed: IrqSafeSpinLock<Vec<Arc<dyn narf_filesystem::DrmFence>>>,
}
impl IoctlContext for SyncExportUser {
    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), FsError> {
        self.user.read(address, bytes)
    }
    fn write(&self, address: u64, bytes: &[u8]) -> Result<(), FsError> {
        self.user.write(address, bytes)
    }
    fn nonblocking(&self) -> bool {
        false
    }
    fn install_sync_file(
        &self,
        fences: Vec<Arc<dyn narf_filesystem::DrmFence>>,
        report: &mut dyn FnMut(i32) -> Result<(), FsError>,
    ) -> Result<i32, narf_filesystem::InstallFdError> {
        report(17).map_err(narf_filesystem::InstallFdError::Report)?;
        *self.installed.lock() = fences;
        Ok(17)
    }
}

fn smoke_intel_prime_reservations_sync_file_and_copy_fault() -> TestResult {
    use narf_filesystem::dma_buf::*;
    let gem = GemState::new();
    let handle = gem.create(4096, |_, _| Ok(())).unwrap();
    let object = gem.object(handle).unwrap();
    let prime = crate::drm_devfs_bridge::intel_dma_buf_file(2, object.clone());
    let alias = crate::drm_devfs_bridge::intel_dma_buf_file(2, object.clone());
    let ctx = SyncExportUser {
        user: User::new(),
        installed: IrqSafeSpinLock::new(Vec::new()),
    };
    let a = Arc::new(CompletionFence::new());
    let b = Arc::new(CompletionFence::new());
    reserve_gpu(&[(object.clone(), false)], &a).unwrap();
    reserve_gpu(&[(object.clone(), false)], &b).unwrap();
    ctx.user.store(64, &DMA_BUF_SYNC_READ.to_le_bytes());
    assert_eq!(
        narf_scheduler::block_on_spin(prime.ioctl_user(DMA_BUF_IOCTL_SYNC, 64, &ctx)),
        Ok(0)
    );
    ctx.user.store(64, &DMA_BUF_SYNC_WRITE.to_le_bytes());
    {
        let mut wait = alias.ioctl_user(DMA_BUF_IOCTL_SYNC, 64, &ctx);
        assert!(poll_sync(wait.as_mut()).is_pending());
    }
    assert_eq!(object.busy(), 0x10000);
    ctx.user
        .store(64, &(DMA_BUF_SYNC_WRITE | DMA_BUF_SYNC_END).to_le_bytes());
    assert_eq!(
        narf_scheduler::block_on_spin(prime.ioctl_user(DMA_BUF_IOCTL_SYNC, 64, &ctx)),
        Ok(0)
    );
    ctx.user.store(64, &DMA_BUF_SYNC_WRITE.to_le_bytes());
    assert_eq!(
        narf_scheduler::block_on_spin(alias.ioctl_user(DMA_BUF_IOCTL_EXPORT_SYNC_FILE, 64, &ctx)),
        Ok(0)
    );
    assert_eq!(
        ctx.installed.lock().len(),
        2,
        "independent LRC fences collapsed"
    );
    assert_eq!(u32_at(&ctx.user.load(64, 8), 4), 17);
    a.signal(Ok(()));
    assert!(ctx.installed.lock().iter().any(|f| !f.is_signalled()));
    b.signal(Err(JobError::Reset));
    assert!(ctx.installed.lock().iter().all(|f| f.is_signalled()));
    ctx.installed.lock().clear();
    let writer = Arc::new(CompletionFence::new());
    reserve_gpu(&[(object.clone(), true)], &writer).unwrap();
    ctx.user.store(64, &DMA_BUF_SYNC_READ.to_le_bytes());
    *ctx.user.fail_write.lock() = Some(64);
    assert_eq!(
        narf_scheduler::block_on_spin(prime.ioctl_user(DMA_BUF_IOCTL_EXPORT_SYNC_FILE, 64, &ctx)),
        Err(FsError::BadAddress)
    );
    assert!(ctx.installed.lock().is_empty());
    *ctx.user.fail_write.lock() = None;
    assert_eq!(
        narf_scheduler::block_on_spin(prime.ioctl_user(DMA_BUF_IOCTL_EXPORT_SYNC_FILE, 64, &ctx)),
        Ok(0)
    );
    assert_eq!(ctx.installed.lock().len(), 1);
    ctx.user.store(128, b"intel-shared\0");
    assert_eq!(
        narf_scheduler::block_on_spin(alias.ioctl_user(DMA_BUF_SET_NAME_B, 128, &ctx)),
        Ok(0)
    );
    assert_eq!(
        object.dma_buf.name().as_deref(),
        Some(b"intel-shared".as_slice())
    );
    // This export-only context does not resolve sync_file descriptors. A
    // previously unsupported import now validates that fd and returns EINVAL
    // without altering the shared reservation or its existing native writer.
    let before = object.dma_buf.resv.generation();
    assert_eq!(
        narf_scheduler::block_on_spin(prime.ioctl_user(DMA_BUF_IOCTL_IMPORT_SYNC_FILE, 64, &ctx)),
        Err(FsError::InvalidData)
    );
    assert_eq!(object.dma_buf.resv.generation(), before);
    assert_eq!(object.busy(), 0x10001);
    gem.close(handle).unwrap();
    drop(prime);
    drop(alias);
    assert!(!ctx.installed.lock()[0].is_signalled());
    writer.signal(Ok(()));
    assert!(ctx.installed.lock()[0].is_signalled());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_render",
    smoke_intel_prime_reservations_sync_file_and_copy_fault
);
