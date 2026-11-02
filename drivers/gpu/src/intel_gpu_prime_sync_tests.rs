//! Native PRIME fd -> shared reservation -> CPU/GPU admission conversations.
use super::*;
use crate::{drm_devfs_bridge::intel_dma_buf_file, intel_gpu_fence::CompletionFence};
use alloc::vec;
use core::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicI32, AtomicUsize},
    task::{Context, Poll, Waker},
};
use narf_filesystem::{dma_buf::*, DrmFence, InstallFdError, IoctlContext};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Cpu {
    bytes: IrqSafeSpinLock<[u8; 32]>,
    input: IrqSafeSpinLock<Option<Vec<Arc<dyn DrmFence>>>>,
    exported: IrqSafeSpinLock<Vec<Arc<dyn DrmFence>>>,
    lookups: AtomicUsize,
    parks: AtomicUsize,
    fault: AtomicBool,
}
impl Cpu {
    fn new() -> Self {
        Self {
            bytes: IrqSafeSpinLock::new([0; 32]),
            input: IrqSafeSpinLock::new(None),
            exported: IrqSafeSpinLock::new(Vec::new()),
            lookups: AtomicUsize::new(0),
            parks: AtomicUsize::new(0),
            fault: AtomicBool::new(false),
        }
    }
    fn request(&self, flags: u32, fd: i32) {
        let mut bytes = self.bytes.lock();
        bytes[..4].copy_from_slice(&flags.to_le_bytes());
        bytes[4..8].copy_from_slice(&fd.to_le_bytes());
    }
}
impl IoctlContext for Cpu {
    fn read(&self, at: u64, out: &mut [u8]) -> Result<(), FsError> {
        assert!(
            RESERVATIONS.try_lock().is_some(),
            "user callback under admission lock"
        );
        if self.fault.load(Ordering::Acquire) {
            return Err(FsError::BadAddress);
        }
        out.copy_from_slice(
            self.bytes
                .lock()
                .get(at as usize..at as usize + out.len())
                .ok_or(FsError::BadAddress)?,
        );
        Ok(())
    }
    fn write(&self, at: u64, input: &[u8]) -> Result<(), FsError> {
        assert!(RESERVATIONS.try_lock().is_some());
        self.bytes
            .lock()
            .get_mut(at as usize..at as usize + input.len())
            .ok_or(FsError::BadAddress)?
            .copy_from_slice(input);
        Ok(())
    }
    fn nonblocking(&self) -> bool {
        false
    }
    fn sync_file_fences(&self, fd: i32) -> Option<Vec<Arc<dyn DrmFence>>> {
        assert!(RESERVATIONS.try_lock().is_some());
        self.lookups.fetch_add(1, Ordering::Relaxed);
        if fd == 7 {
            self.input.lock().clone()
        } else {
            None
        }
    }
    fn install_sync_file(
        &self,
        fences: Vec<Arc<dyn DrmFence>>,
        report: &mut dyn FnMut(i32) -> Result<(), FsError>,
    ) -> Result<i32, InstallFdError> {
        report(9).map_err(InstallFdError::Report)?;
        *self.exported.lock() = fences;
        Ok(9)
    }
    fn restart_after(&self, _: u64) -> bool {
        assert!(RESERVATIONS.try_lock().is_some());
        self.parks.fetch_add(1, Ordering::Relaxed);
        true
    }
}
fn run<F: Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("unexpected parked native PRIME ioctl"),
    }
}
fn object() -> Arc<GemObject> {
    let gem = GemState::new();
    gem.object(gem.create(PAGE, |_, _| Ok(())).unwrap())
        .unwrap()
}
struct Foreign {
    done: AtomicI32,
    context: u64,
    seqno: u64,
    dropped: Arc<AtomicBool>,
    owner: alloc::sync::Weak<GemObject>,
}
impl Foreign {
    fn new(owner: &Arc<GemObject>, context: u64, seqno: u64) -> Arc<Self> {
        Arc::new(Self {
            done: AtomicI32::new(0),
            context,
            seqno,
            dropped: Arc::new(AtomicBool::new(false)),
            owner: Arc::downgrade(owner),
        })
    }
    fn unlocked(&self) {
        assert!(
            RESERVATIONS.try_lock().is_some(),
            "foreign callback/drop under admission lock"
        );
        if let Some(owner) = self.owner.upgrade() {
            let _ = owner.dma_buf.resv.generation();
        }
    }
}
impl DrmFence for Foreign {
    fn is_signalled(&self) -> bool {
        self.unlocked();
        self.done.load(Ordering::Acquire) != 0
    }
    fn wait(&self, _: u64) -> bool {
        self.is_signalled()
    }
    fn context(&self) -> Option<u64> {
        self.unlocked();
        Some(self.context)
    }
    fn seqno(&self) -> u64 {
        self.unlocked();
        self.seqno
    }
    fn status(&self) -> i32 {
        self.unlocked();
        self.done.load(Ordering::Acquire)
    }
}
impl Drop for Foreign {
    fn drop(&mut self) {
        self.unlocked();
        self.dropped.store(true, Ordering::Release);
    }
}

fn smoke_intel_prime_import_errno_order_empty_and_fault_publish_nothing() -> TestResult {
    let object = object();
    let file = intel_dma_buf_file(777, object.clone());
    let cpu = Cpu::new();
    for flags in [0, 4, 5, u32::MAX] {
        cpu.request(flags, 7);
        assert_eq!(
            run(file.ioctl_user(DMA_BUF_IOCTL_IMPORT_SYNC_FILE, 0, &cpu)),
            Err(FsError::InvalidData)
        );
    }
    assert_eq!(cpu.lookups.load(Ordering::Acquire), 0);
    cpu.request(2, -1);
    assert_eq!(
        run(file.ioctl_user(DMA_BUF_IOCTL_IMPORT_SYNC_FILE, 0, &cpu)),
        Err(FsError::InvalidData)
    );
    cpu.request(2, 7);
    cpu.fault.store(true, Ordering::Release);
    assert_eq!(
        run(file.ioctl_user(DMA_BUF_IOCTL_IMPORT_SYNC_FILE, 0, &cpu)),
        Err(FsError::BadAddress)
    );
    cpu.fault.store(false, Ordering::Release);
    assert_eq!(object.dma_buf.resv.generation(), 0);
    *cpu.input.lock() = Some(Vec::new());
    assert_eq!(
        run(file.ioctl_user(DMA_BUF_IOCTL_IMPORT_SYNC_FILE, 0, &cpu)),
        Ok(0)
    );
    assert_eq!(object.dma_buf.resv.generation(), 0);
    assert_eq!(object.busy(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_intel_prime_import_errno_order_empty_and_fault_publish_nothing
);

fn smoke_intel_prime_import_shared_aliases_cpu_direction_and_sync_file_export() -> TestResult {
    let object = object();
    let file = intel_dma_buf_file(777, object.clone());
    let alias = intel_dma_buf_file(777, object.clone());
    let cpu = Cpu::new();
    let reader = Foreign::new(&object, 91, 1);
    *cpu.input.lock() = Some(vec![reader.clone()]);
    cpu.request(1, 7);
    assert_eq!(
        run(file.ioctl_user(DMA_BUF_IOCTL_IMPORT_SYNC_FILE, 0, &cpu)),
        Ok(0)
    );
    assert_eq!(object.busy(), 0x10000);
    assert_eq!(object.read(0, &mut [0]), Ok(()));
    assert_eq!(object.write(0, &[1]), Err(FsError::WouldBlock));
    cpu.request(1, 0);
    assert_eq!(
        run(alias.ioctl_user(DMA_BUF_IOCTL_EXPORT_SYNC_FILE, 0, &cpu)),
        Ok(0)
    );
    assert!(
        cpu.exported.lock().is_empty(),
        "CPU reader waits only for writers"
    );
    cpu.request(2, 0);
    assert_eq!(
        run(alias.ioctl_user(DMA_BUF_IOCTL_EXPORT_SYNC_FILE, 0, &cpu)),
        Ok(0)
    );
    let exact: Arc<dyn DrmFence> = reader.clone();
    assert!(Arc::ptr_eq(&cpu.exported.lock()[0], &exact));
    let writer = Foreign::new(&object, 92, 1);
    *cpu.input.lock() = Some(vec![writer.clone()]);
    cpu.request(3, 7);
    assert_eq!(
        run(alias.ioctl_user(DMA_BUF_IOCTL_IMPORT_SYNC_FILE, 0, &cpu)),
        Ok(0)
    );
    assert_eq!(object.read(0, &mut [0]), Err(FsError::WouldBlock));
    cpu.request(1, 0);
    assert_eq!(
        run(file.ioctl_user(DMA_BUF_IOCTL_SYNC, 0, &cpu)),
        Err(FsError::WouldBlock)
    );
    assert_eq!(cpu.parks.load(Ordering::Acquire), 1);
    writer.done.store(-5, Ordering::Release);
    assert_eq!(object.read(0, &mut [0]), Ok(()));
    assert_eq!(object.write(0, &[2]), Err(FsError::WouldBlock));
    reader.done.store(1, Ordering::Release);
    assert_eq!(object.write(0, &[2]), Ok(()));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_intel_prime_import_shared_aliases_cpu_direction_and_sync_file_export
);

fn smoke_intel_prime_import_implicit_rollback_and_explicit_xe_cpu_exclusion() -> TestResult {
    let a = object();
    let b = object();
    let foreign = Foreign::new(&a, 93, 1);
    a.import_fences(vec![foreign.clone()], true);
    let completion = Arc::new(CompletionFence::new());
    let before = b.dma_buf.resv.generation();
    assert_eq!(
        reserve_gpu(&[(b.clone(), true), (a.clone(), false)], &completion),
        Err(FsError::WouldBlock)
    );
    assert_eq!(b.dma_buf.resv.generation(), before);
    // Xe's explicit-sync contract admits GPU work without implicit waiting.
    reserve_gpu_explicit(&[(a.clone(), true)], &completion);
    assert_eq!(a.read(0, &mut [0]), Err(FsError::WouldBlock));
    foreign.done.store(1, Ordering::Release);
    assert_eq!(a.read(0, &mut [0]), Err(FsError::WouldBlock));
    completion.signal(Err(crate::intel_gpu_fence::JobError::Reset));
    assert_eq!(a.write(0, &[9]), Ok(()));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_intel_prime_import_implicit_rollback_and_explicit_xe_cpu_exclusion
);

fn smoke_intel_prime_foreign_identity_status_and_final_drop_never_hold_admission() -> TestResult {
    let object = object();
    let old = Foreign::new(&object, 94, 1);
    let dropped = old.dropped.clone();
    object.import_fences(vec![old.clone()], true);
    let reader2 = Foreign::new(&object, 94, 2);
    let dropped2 = reader2.dropped.clone();
    let reader3 = Foreign::new(&object, 94, 3);
    let dropped3 = reader3.dropped.clone();
    // One multi-leaf READ batch collapses its earlier reader but cannot
    // downgrade the preexisting WRITE usage on the ordered timeline.
    object.import_fences(vec![reader2, reader3.clone()], false);
    assert!(dropped2.load(Ordering::Acquire));
    assert_eq!(object.busy(), 0x10001);
    old.done.store(1, Ordering::Release);
    drop(old);
    assert_eq!(object.busy(), 0x10000);
    let new = Foreign::new(&object, 94, 4);
    object.import_fences(vec![new.clone()], true);
    drop(reader3);
    assert!(dropped.load(Ordering::Acquire));
    assert!(dropped3.load(Ordering::Acquire));
    assert_eq!(object.busy(), 0x10001);
    let completion = Arc::new(CompletionFence::new());
    reserve_gpu_explicit(&[(object.clone(), false)], &completion);
    new.done.store(1, Ordering::Release);
    assert_eq!(object.busy(), 0x10000);
    assert_eq!(object.read(0, &mut [0]), Ok(()));
    completion.signal(Ok(()));
    assert_eq!(object.write(0, &[3]), Ok(()));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_intel_prime_foreign_identity_status_and_final_drop_never_hold_admission
);

struct Race {
    object: alloc::sync::Weak<GemObject>,
    armed: AtomicBool,
    inserted: Arc<CompletionFence>,
}
impl DrmFence for Race {
    fn is_signalled(&self) -> bool {
        assert!(RESERVATIONS.try_lock().is_some());
        if self.armed.swap(false, Ordering::AcqRel) {
            self.object
                .upgrade()
                .unwrap()
                .import_fences(vec![self.inserted.clone()], true);
        }
        false
    }
    fn wait(&self, _: u64) -> bool {
        false
    }
}
fn smoke_intel_prime_racing_import_invalidates_cpu_and_all_object_gpu_admission() -> TestResult {
    let b = object();
    let object = object();
    let race = Arc::new(Race {
        object: Arc::downgrade(&object),
        armed: AtomicBool::new(false),
        inserted: Arc::new(CompletionFence::new()),
    });
    object.import_fences(vec![race.clone()], false);
    race.armed.store(true, Ordering::Release);
    let mut byte = [77];
    assert_eq!(object.read(0, &mut byte), Err(FsError::WouldBlock));
    assert_eq!(byte, [77]);
    race.inserted.signal(Ok(()));
    race.armed.store(true, Ordering::Release);
    let candidate = Arc::new(CompletionFence::new());
    let before = b.dma_buf.resv.generation();
    assert_eq!(
        reserve_gpu(&[(b.clone(), true), (object.clone(), false)], &candidate),
        Err(FsError::WouldBlock)
    );
    assert_eq!(b.dma_buf.resv.generation(), before);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_intel_prime_racing_import_invalidates_cpu_and_all_object_gpu_admission
);

fn smoke_intel_prime_mapping_and_shared_fences_outlive_handles_and_descriptors() -> TestResult {
    let gem = GemState::new();
    let handle = gem.create(PAGE, |_, _| Ok(())).unwrap();
    let object = gem.object(handle).unwrap();
    let file = intel_dma_buf_file(777, object.clone());
    let importer = GemState::new();
    let imported = importer.import(&object).unwrap();
    let mapping = file.mmap_backing(0, PAGE as usize).unwrap();
    let weak = Arc::downgrade(&object);
    let foreign = Foreign::new(&object, 95, 1);
    let raw: Arc<dyn DrmFence> = foreign.clone();
    let cpu = Cpu::new();
    *cpu.input.lock() = Some(vec![raw]);
    cpu.request(2, 7);
    assert_eq!(
        run(file.ioctl_user(DMA_BUF_IOCTL_IMPORT_SYNC_FILE, 0, &cpu)),
        Ok(0)
    );
    gem.close(handle).unwrap();
    drop(file);
    *cpu.input.lock() = None;
    assert_eq!(importer.object(imported).unwrap().busy(), 0x10001);
    importer.close(imported).unwrap();
    drop(object);
    assert!(weak.upgrade().is_some());
    foreign.done.store(-5, Ordering::Release);
    assert_eq!(weak.upgrade().unwrap().busy(), 0);
    drop(mapping);
    assert!(weak.upgrade().is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_prime",
    smoke_intel_prime_mapping_and_shared_fences_outlive_handles_and_descriptors
);
