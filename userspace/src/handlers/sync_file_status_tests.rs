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
