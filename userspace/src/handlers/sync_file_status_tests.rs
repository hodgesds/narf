//! Source vectors: Linux sync_file.c::sync_file_ioctl_fence_info and
//! dma-fence.h::dma_fence_get_status_locked (b90c984d615e).
use super::*;
use core::sync::atomic::{AtomicI32, Ordering};
use narf_filesystem::{DrmFence, FsError, IoctlContext};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

struct Fence(AtomicI32);
impl DrmFence for Fence {
    fn is_signalled(&self) -> bool {
        self.status() != 0
    }
    fn status(&self) -> i32 {
        self.0.load(Ordering::Acquire)
    }
    fn wait(&self, _: u64) -> bool {
        self.is_signalled()
    }
    fn timestamp_ns(&self) -> Option<u64> {
        self.is_signalled().then_some(987654321)
    }
}
struct Memory(IrqSafeSpinLock<[u8; 512]>);
impl Memory {
    fn new() -> Self {
        Self(IrqSafeSpinLock::new([0; 512]))
    }
    fn query(&self, file: &DrmSyncFile, detailed: bool, count: u32) -> (i32, Vec<i32>) {
        let mut request = [0; SYNC_FILE_INFO_SIZE];
        if detailed {
            request[40..44].copy_from_slice(&count.to_ne_bytes());
            request[48..56].copy_from_slice(&128u64.to_ne_bytes());
        }
        self.write(16, &request).unwrap();
        assert_eq!(file.ioctl_fence_info(16, self), Ok(0));
        self.read(16, &mut request).unwrap();
        assert_eq!(
            u32::from_ne_bytes(request[40..44].try_into().unwrap()),
            count
        );
        let status = i32::from_ne_bytes(request[32..36].try_into().unwrap());
        let leaves = if detailed {
            self.0.lock()[128..128 + count as usize * SYNC_FENCE_INFO_SIZE]
                .chunks_exact(SYNC_FENCE_INFO_SIZE)
                .map(|entry| i32::from_ne_bytes(entry[64..68].try_into().unwrap()))
                .collect()
        } else {
            Vec::new()
        };
        (status, leaves)
    }
}
impl IoctlContext for Memory {
    fn read(&self, address: u64, dst: &mut [u8]) -> Result<(), FsError> {
        let start = address as usize;
        let end = start
            .checked_add(dst.len())
            .filter(|end| *end <= 512)
            .ok_or(FsError::BadAddress)?;
        dst.copy_from_slice(&self.0.lock()[start..end]);
        Ok(())
    }
    fn write(&self, address: u64, src: &[u8]) -> Result<(), FsError> {
        let start = address as usize;
        let end = start
            .checked_add(src.len())
            .filter(|end| *end <= 512)
            .ok_or(FsError::BadAddress)?;
        self.0.lock()[start..end].copy_from_slice(src);
        Ok(())
    }
    fn nonblocking(&self) -> bool {
        false
    }
}

fn smoke_sync_file_native_terminal_failure_is_readable_and_keeps_errno() -> TestResult {
    let fence = Arc::new(Fence(AtomicI32::new(0)));
    let file = DrmSyncFile::device(fence.clone());
    let memory = Memory::new();
    assert_eq!(narf_filesystem::FileOps::poll_readiness(&file), 0);
    assert_eq!(memory.query(&file, false, 1).0, 0);
    assert_eq!(memory.query(&file, true, 1), (0, alloc::vec![0]));
    fence.0.store(-110, Ordering::Release);
    assert!(fence.wait(0));
    assert_eq!(
        narf_filesystem::FileOps::poll_readiness(&file),
        narf_filesystem::POLL_IN
    );
    assert_eq!(memory.query(&file, false, 1).0, -110);
    assert_eq!(memory.query(&file, true, 1), (-110, alloc::vec![-110]));
    let mut timestamp = [0; 8];
    memory.read(128 + 72, &mut timestamp).unwrap();
    assert_eq!(u64::from_ne_bytes(timestamp), 987654321);
    TestResult::Pass
}
kernel_test_in!(
    "syscall_abi",
    smoke_sync_file_native_terminal_failure_is_readable_and_keeps_errno
);

fn smoke_sync_file_error_pending_leaf_order_matches_linux_info_queries() -> TestResult {
    for error_first in [false, true] {
        let pending = Arc::new(Fence(AtomicI32::new(0)));
        let failed = Arc::new(Fence(AtomicI32::new(-5)));
        let leaves: Vec<Arc<dyn DrmFence>> = if error_first {
            alloc::vec![failed.clone(), pending.clone()]
        } else {
            alloc::vec![pending.clone(), failed.clone()]
        };
        let file = DrmSyncFile::from_singleton(leaves);
        let memory = Memory::new();
        assert_eq!(narf_filesystem::FileOps::poll_readiness(&file), 0);
        // Count-only uses the container, which still has a pending leaf.
        assert_eq!(memory.query(&file, false, 2).0, 0);
        let (status, leaves) = memory.query(&file, true, 2);
        assert_eq!(status, if error_first { -5 } else { 0 });
        assert_eq!(
            leaves,
            if error_first {
                alloc::vec![-5, 0]
            } else {
                alloc::vec![0, -5]
            }
        );
        pending.0.store(1, Ordering::Release);
        assert_eq!(
            narf_filesystem::FileOps::poll_readiness(&file),
            narf_filesystem::POLL_IN
        );
        assert_eq!(memory.query(&file, false, 2).0, -5);
        assert_eq!(memory.query(&file, true, 2).0, -5);
    }
    TestResult::Pass
}
kernel_test_in!(
    "syscall_abi",
    smoke_sync_file_error_pending_leaf_order_matches_linux_info_queries
);

/// A fence whose driver records its signal time, as `dma_fence_signal`
/// stamps `fence->timestamp`: pending until `signal(status, at)`.
struct Timed {
    status: AtomicI32,
    at: core::sync::atomic::AtomicU64,
    context: u64,
}
impl Timed {
    fn new(context: u64) -> Arc<Self> {
        Arc::new(Self {
            status: AtomicI32::new(0),
            at: core::sync::atomic::AtomicU64::new(0),
            context,
        })
    }
    fn signal(&self, status: i32, at: u64) {
        self.at.store(at, Ordering::Release);
        self.status.store(status, Ordering::Release);
    }
}
impl DrmFence for Timed {
    fn is_signalled(&self) -> bool {
        self.status() != 0
    }
    fn status(&self) -> i32 {
        self.status.load(Ordering::Acquire)
    }
    fn wait(&self, _: u64) -> bool {
        self.is_signalled()
    }
    fn context(&self) -> Option<u64> {
        Some(self.context)
    }
    fn seqno(&self) -> u64 {
        1
    }
    fn timestamp_ns(&self) -> Option<u64> {
        self.is_signalled().then(|| self.at.load(Ordering::Acquire))
    }
}
/// A fence that completes while FILE_INFO looks at it: pending at its first
/// observation, signalled (status 1, no driver timestamp) from then on.
struct Completing(core::sync::atomic::AtomicU32);
impl DrmFence for Completing {
    fn is_signalled(&self) -> bool {
        self.0.fetch_add(1, Ordering::AcqRel) > 0
    }
    fn wait(&self, _: u64) -> bool {
        self.is_signalled()
    }
}
/// Entry `i`'s `(status, timestamp_ns)` after `Memory::query(.., true, ..)`.
fn entry(memory: &Memory, i: u64) -> (i32, u64) {
    let mut bytes = [0u8; SYNC_FENCE_INFO_SIZE];
    memory
        .read(128 + i * SYNC_FENCE_INFO_SIZE as u64, &mut bytes)
        .unwrap();
    (
        i32::from_ne_bytes(bytes[64..68].try_into().unwrap()),
        u64::from_ne_bytes(bytes[72..80].try_into().unwrap()),
    )
}

/// Chromium's `GpuFence::GetStatusChangeTime` reads FILE_INFO twice (count,
/// then the array) and logs "No timestamp provided from
/// sync_(pt|fence)_info" when the file's status is 1 but every
/// `sync_fence_info.timestamp_ns` is 0. Linux's `sync_fill_fence_info` takes
/// `dma_fence_get_status(fence)` first and only then the timestamp of a
/// fence `dma_fence_is_signaled` reports signalled, the time
/// `dma_fence_signal_timestamp` recorded: a status of 1 or an error always
/// comes with that time. A pending fence reports 0; a fence the driver
/// stamped reports its stamp, not the query's time; a merged file reports
/// each leaf's; an errored fence its error and signal time.
fn smoke_sync_file_info_reports_signal_times_like_sync_fill_fence_info() -> TestResult {
    let memory = Memory::new();
    // Pending, then signalled at a recorded time, queried much later.
    let fence = Timed::new(0x51);
    let file = DrmSyncFile::device(fence.clone());
    if memory.query(&file, true, 1) != (0, alloc::vec![0]) || entry(&memory, 0).1 != 0 {
        return TestResult::Fail("a pending fence reported a status or a timestamp");
    }
    fence.signal(1, 4_000_000);
    if memory.query(&file, false, 1).0 != 1
        || memory.query(&file, true, 1) != (1, alloc::vec![1])
        || entry(&memory, 0).1 != 4_000_000
    {
        return TestResult::Fail("a signalled fence did not report its signal time");
    }
    // A fence completing between the two samples FILE_INFO takes of it.
    let file = DrmSyncFile::device(Arc::new(Completing(core::sync::atomic::AtomicU32::new(0))));
    let (status, _) = memory.query(&file, true, 1);
    let (leaf, timestamp) = entry(&memory, 0);
    if (status != 0 || leaf != 0) && timestamp == 0 {
        return TestResult::Fail("a signalled status came without a timestamp");
    }
    let (status, _) = memory.query(&file, true, 1);
    let (_, again) = entry(&memory, 0);
    if status != 1 || again == 0 || (timestamp != 0 && again != timestamp) {
        return TestResult::Fail("a signalled fence's timestamp is missing or moved");
    }
    // A merge of two pending fences: each leaf keeps its own signal time.
    let (a, b) = (Timed::new(0x60), Timed::new(0x70));
    let merged = DrmSyncFile::merge(
        &DrmSyncFile::device(a.clone()),
        &DrmSyncFile::device(b.clone()),
        &[0; 32],
    );
    a.signal(1, 5_000_000);
    if memory.query(&merged, true, 2) != (0, alloc::vec![1, 0])
        || entry(&memory, 0).1 != 5_000_000
        || entry(&memory, 1).1 != 0
    {
        return TestResult::Fail("a half-signalled merge");
    }
    b.signal(1, 6_000_000);
    if memory.query(&merged, true, 2) != (1, alloc::vec![1, 1])
        || entry(&memory, 0).1 != 5_000_000
        || entry(&memory, 1).1 != 6_000_000
    {
        return TestResult::Fail("a signalled merge lost a leaf's signal time");
    }
    // An errored fence: its error, and the time it signalled.
    let failed = Timed::new(0x80);
    let file = DrmSyncFile::device(failed.clone());
    failed.signal(-5, 7_000_000);
    if memory.query(&file, false, 1).0 != -5
        || memory.query(&file, true, 1) != (-5, alloc::vec![-5])
        || entry(&memory, 0).1 != 7_000_000
    {
        return TestResult::Fail("an errored fence's status or signal time");
    }
    TestResult::Pass
}
kernel_test_in!(
    "syscall_abi/sync-file-info",
    smoke_sync_file_info_reports_signal_times_like_sync_fill_fence_info
);
