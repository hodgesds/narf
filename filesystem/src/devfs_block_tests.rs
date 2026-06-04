//! Smoke tests for `BlockFile` and the `/dev/` block-device surfaces.
//!
//! Each test registers (and cleans up) a `FakeBlockDevice` so tests
//! are isolated from one another and from production block devices.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use narf_block::registry::{BlockDeviceSync, BlockIoError};

// ── FakeBlockDevice ───────────────────────────────────────────────────

/// In-memory block device backed by a `Vec<u8>`.
///
/// - `lba_size`: configurable (default 512).
/// - capacity: `data.len() / lba_size` LBAs.
struct FakeBlockDevice {
    data: narf_lib::sync::IrqSafeSpinLock<Vec<u8>>,
    lba_size: u32,
}

impl core::fmt::Debug for FakeBlockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FakeBlockDevice")
            .field("lba_size", &self.lba_size)
            .finish_non_exhaustive()
    }
}

impl FakeBlockDevice {
    /// Create a `n_blocks`-block device with `lba_size`-byte sectors.
    fn new(n_blocks: usize, lba_size: u32) -> Arc<Self> {
        Arc::new(FakeBlockDevice {
            data: narf_lib::sync::IrqSafeSpinLock::new(vec![0u8; n_blocks * lba_size as usize]),
            lba_size,
        })
    }

    /// Pre-fill with `fill_byte`.
    fn filled(n_blocks: usize, lba_size: u32, fill_byte: u8) -> Arc<Self> {
        Arc::new(FakeBlockDevice {
            data: narf_lib::sync::IrqSafeSpinLock::new(vec![
                fill_byte;
                n_blocks * lba_size as usize
            ]),
            lba_size,
        })
    }
}

impl BlockDeviceSync for FakeBlockDevice {
    fn lba_size(&self) -> u32 {
        self.lba_size
    }

    fn capacity(&self) -> u64 {
        let g = self.data.lock();
        (g.len() / self.lba_size as usize) as u64
    }

    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        let g = self.data.lock();
        let bs = self.lba_size as usize;
        let start = lba as usize * bs;
        let end = start + n_blocks as usize * bs;
        if end > g.len() {
            return Err(BlockIoError::OutOfRange);
        }
        if out.len() < end - start {
            return Err(BlockIoError::BufferTooSmall);
        }
        out[..end - start].copy_from_slice(&g[start..end]);
        Ok(())
    }

    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError> {
        let mut g = self.data.lock();
        let bs = self.lba_size as usize;
        let start = lba as usize * bs;
        let end = start + n_blocks as usize * bs;
        if end > g.len() {
            return Err(BlockIoError::OutOfRange);
        }
        if data.len() < end - start {
            return Err(BlockIoError::BufferTooSmall);
        }
        g[start..end].copy_from_slice(&data[..end - start]);
        Ok(())
    }
}

// ── poll_once helper ──────────────────────────────────────────────────

fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw_waker() -> RawWaker {
        unsafe fn no_clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        unsafe fn no_op(_: *const ()) {}
        const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

// ── Test 1: BlockFile::read — aligned, 1 block ────────────────────────

fn smoke_devfs_block_read_aligned_one_block() -> TestResult {
    use crate::devfs_block::BlockFile;
    use crate::FileOps;

    // 4-block device, 512-byte sectors, pre-filled with 0xAB.
    let dev = FakeBlockDevice::filled(4, 512, 0xAB);
    let bf = BlockFile::from_dev(dev);

    let mut buf = [0u8; 512];
    let r = poll_once(bf.read(0, &mut buf));
    match r {
        Some(Ok(n)) if n == 512 => {}
        _ => return TestResult::Fail("aligned read should return 512"),
    }
    if buf.iter().any(|&b| b != 0xAB) {
        return TestResult::Fail("aligned read returned wrong bytes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/devfs_block",
    smoke_devfs_block_read_aligned_one_block
);

// ── Test 2: BlockFile::read — unaligned start ─────────────────────────

fn smoke_devfs_block_read_unaligned_start() -> TestResult {
    use crate::devfs_block::BlockFile;
    use crate::FileOps;

    // 4-block / 512-byte device.  Byte 0..511 = 0x11, 512..1023 = 0x22.
    let dev = FakeBlockDevice::new(4, 512);
    {
        let mut g = dev.data.lock();
        for b in g[0..512].iter_mut() {
            *b = 0x11;
        }
        for b in g[512..1024].iter_mut() {
            *b = 0x22;
        }
    }
    let bf = BlockFile::from_dev(dev);

    // Read 100 bytes starting at offset 500 (spans LBA 0 into LBA 1).
    let mut buf = [0u8; 100];
    let r = poll_once(bf.read(500, &mut buf));
    match r {
        Some(Ok(n)) if n == 100 => {}
        _ => return TestResult::Fail("unaligned-start read should return 100"),
    }
    // Bytes 0..11 come from LBA 0 (0x11), bytes 12..99 from LBA 1 (0x22).
    if buf[..12].iter().any(|&b| b != 0x11) {
        return TestResult::Fail("unaligned start: LBA-0 bytes wrong");
    }
    if buf[12..].iter().any(|&b| b != 0x22) {
        return TestResult::Fail("unaligned start: LBA-1 bytes wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/devfs_block",
    smoke_devfs_block_read_unaligned_start
);

// ── Test 3: BlockFile::read — spans 3 blocks ──────────────────────────

fn smoke_devfs_block_read_spans_three_blocks() -> TestResult {
    use crate::devfs_block::BlockFile;
    use crate::FileOps;

    // 4-block / 512-byte device.  Fill each block with a different byte.
    let dev = FakeBlockDevice::new(4, 512);
    {
        let mut g = dev.data.lock();
        for b in g[0..512].iter_mut() {
            *b = 0xAA;
        }
        for b in g[512..1024].iter_mut() {
            *b = 0xBB;
        }
        for b in g[1024..1536].iter_mut() {
            *b = 0xCC;
        }
    }
    let bf = BlockFile::from_dev(dev);

    // Read 1500 bytes from offset 0 (covers first 3 blocks fully).
    let mut buf = [0u8; 1500];
    let r = poll_once(bf.read(0, &mut buf));
    match r {
        Some(Ok(n)) if n == 1500 => {}
        _ => return TestResult::Fail("3-block read should return 1500"),
    }
    if buf[..512].iter().any(|&b| b != 0xAA) {
        return TestResult::Fail("block 0 bytes wrong");
    }
    if buf[512..1024].iter().any(|&b| b != 0xBB) {
        return TestResult::Fail("block 1 bytes wrong");
    }
    if buf[1024..1500].iter().any(|&b| b != 0xCC) {
        return TestResult::Fail("block 2 partial bytes wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/devfs_block",
    smoke_devfs_block_read_spans_three_blocks
);

// ── Test 4: BlockFile::write — aligned, 1 block ──────────────────────

fn smoke_devfs_block_write_aligned() -> TestResult {
    use crate::devfs_block::BlockFile;
    use crate::FileOps;

    let dev = FakeBlockDevice::filled(4, 512, 0x00);
    let bf = BlockFile::from_dev(dev);

    let payload = [0xDE_u8; 512];
    let w = poll_once(bf.write(0, &payload));
    match w {
        Some(Ok(n)) if n == 512 => {}
        _ => return TestResult::Fail("aligned write should return 512"),
    }

    // Read it back.
    let mut readback = [0u8; 512];
    let r = poll_once(bf.read(0, &mut readback));
    if !matches!(r, Some(Ok(512))) {
        return TestResult::Fail("readback after aligned write failed");
    }
    if readback.iter().any(|&b| b != 0xDE) {
        return TestResult::Fail("readback bytes wrong after aligned write");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/devfs_block", smoke_devfs_block_write_aligned);

// ── Test 5: BlockFile::write — unaligned RMW ──────────────────────────

fn smoke_devfs_block_write_unaligned_rmw() -> TestResult {
    use crate::devfs_block::BlockFile;
    use crate::FileOps;

    // Device pre-filled with 0xFF.  We write 200 bytes at offset 100
    // and verify the bytes at [0..100] and [300..512] are still 0xFF.
    let dev = FakeBlockDevice::filled(4, 512, 0xFF);
    let bf = BlockFile::from_dev(dev);

    let payload = [0x00_u8; 200];
    let w = poll_once(bf.write(100, &payload));
    match w {
        Some(Ok(n)) if n == 200 => {}
        _ => return TestResult::Fail("unaligned write should return 200"),
    }

    // Read the entire first block back.
    let mut block0 = [0u8; 512];
    let r = poll_once(bf.read(0, &mut block0));
    if !matches!(r, Some(Ok(512))) {
        return TestResult::Fail("readback of block 0 failed");
    }
    // Bytes [0..100] and [300..512] must still be 0xFF (RMW preserved them).
    if block0[..100].iter().any(|&b| b != 0xFF) {
        return TestResult::Fail("RMW: bytes before write range corrupted");
    }
    if block0[100..300].iter().any(|&b| b != 0x00) {
        return TestResult::Fail("RMW: written bytes are wrong");
    }
    if block0[300..].iter().any(|&b| b != 0xFF) {
        return TestResult::Fail("RMW: bytes after write range corrupted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/devfs_block",
    smoke_devfs_block_write_unaligned_rmw
);

// ── Test 6: BlockFile::stat — correct size ────────────────────────────

fn smoke_devfs_block_stat_size() -> TestResult {
    use crate::devfs_block::BlockFile;
    use crate::{FileOps, FileType};

    let dev = FakeBlockDevice::new(8, 512);
    let bf = BlockFile::from_dev(dev);

    let stat = bf.stat();
    if stat.size != 8 * 512 {
        return TestResult::Fail("stat.size != 8 * 512");
    }
    if stat.blocks != 8 {
        return TestResult::Fail("stat.blocks != 8");
    }
    if stat.mode.file_type != FileType::Special {
        return TestResult::Fail("stat.mode.file_type != Special");
    }
    if stat.mode.perms != 0o660 {
        return TestResult::Fail("stat.mode.perms != 0o660");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/devfs_block", smoke_devfs_block_stat_size);

// ── Test 7: DevDir lookup finds a registered block device ─────────────

fn smoke_devfs_block_devdir_lookup_nvme0() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, DevFs, FileType};

    // Save the registry state so we can restore it.
    let snap = narf_block::registry::__snapshot_for_test();

    // Register a fake "nvme0-test" device.
    let dev = FakeBlockDevice::filled(16, 512, 0xCC);
    narf_block::registry::register_block_device("nvme0-test", dev);

    // Mount a fresh DevFs.
    let auth = bootstrap_mount_authority();
    let mnt = registry().mount(&auth, "/dev-blk-test", DevFs::new());
    let _mnt = match mnt {
        Ok(h) => h,
        Err(_) => {
            narf_block::registry::__restore_for_test(snap);
            return TestResult::Fail("DevFs mount failed");
        }
    };

    let ops = registry()
        .resolve_absolute("/dev-blk-test/nvme0-test", |fs, rel| {
            crate::resolve(fs.root(), rel).ok()
        })
        .flatten();

    narf_block::registry::__restore_for_test(snap);

    match ops {
        Some(f) => {
            let stat = f.stat();
            if stat.mode.file_type != FileType::Special {
                return TestResult::Fail("nvme0-test node is not Special");
            }
            TestResult::Pass
        }
        None => TestResult::Fail("DevDir lookup of nvme0-test returned None"),
    }
}
kernel_test_in!(
    "filesystem/devfs_block",
    smoke_devfs_block_devdir_lookup_nvme0
);

// ── Test 8: /dev/disk/by-label lookup ────────────────────────────────

fn smoke_devfs_block_disk_by_label_lookup() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, DevFs, FileType};
    use narf_block::registry::{
        PartitionMetadata, __restore_for_test, __snapshot_for_test, register_block_device_with_meta,
    };

    let snap = __snapshot_for_test();

    // Register a partition with a label.
    let dev = FakeBlockDevice::filled(4, 512, 0x55);
    let meta = PartitionMetadata {
        partlabel: alloc::string::String::from("NARF_ROOT_TEST"),
        partuuid: alloc::string::String::from("aaaaaaaa-0000-0000-0000-bbbbbbbbbbbb"),
    };
    register_block_device_with_meta("nvme0p1-lbltest", dev, Some(meta));

    let auth = bootstrap_mount_authority();
    let mnt = registry().mount(&auth, "/dev-disk-lbl-test", DevFs::new());
    let _mnt = match mnt {
        Ok(h) => h,
        Err(_) => {
            __restore_for_test(snap);
            return TestResult::Fail("DevFs mount for by-label test failed");
        }
    };

    // Walk manually: DevDir → "disk" → "by-label" → "NARF_ROOT_TEST".
    use crate::FsInstance;
    let root: Arc<dyn crate::DirOps> = crate::DevFs::new().root();

    let disk_dir = root.lookup_dir("disk");
    __restore_for_test(snap);

    let disk_dir = match disk_dir {
        Some(d) => d,
        None => return TestResult::Fail("DevDir has no 'disk' subdir"),
    };
    let by_label_dir = disk_dir.lookup_dir("by-label");
    let by_label_dir = match by_label_dir {
        Some(d) => d,
        None => return TestResult::Fail("disk/ has no 'by-label' subdir"),
    };
    // The restore happened already; by-label lookup will miss.
    // Instead, re-register to finish the lookup test cleanly.
    let snap2 = __snapshot_for_test();
    let dev2 = FakeBlockDevice::filled(4, 512, 0x55);
    let meta2 = PartitionMetadata {
        partlabel: alloc::string::String::from("NARF_ROOT_TEST"),
        partuuid: alloc::string::String::new(),
    };
    register_block_device_with_meta("nvme0p1-lbltest2", dev2, Some(meta2));

    let result = by_label_dir.lookup("NARF_ROOT_TEST");
    __restore_for_test(snap2);

    match result {
        Some(f) => {
            if f.stat().mode.file_type != FileType::Special {
                return TestResult::Fail("by-label node not Special");
            }
            TestResult::Pass
        }
        None => TestResult::Fail("by-label lookup of NARF_ROOT_TEST returned None"),
    }
}
kernel_test_in!(
    "filesystem/devfs_block",
    smoke_devfs_block_disk_by_label_lookup
);

// ── Test 9: BlockFile::read returns 0 at EOF ─────────────────────────

fn smoke_devfs_block_read_eof() -> TestResult {
    use crate::devfs_block::BlockFile;
    use crate::FileOps;

    let dev = FakeBlockDevice::new(2, 512);
    let bf = BlockFile::from_dev(dev);

    let mut buf = [0u8; 64];
    // Offset == capacity → EOF
    let r = poll_once(bf.read(1024, &mut buf));
    match r {
        Some(Ok(0)) => TestResult::Pass,
        _ => TestResult::Fail("read at EOF should return Ok(0)"),
    }
}
kernel_test_in!("filesystem/devfs_block", smoke_devfs_block_read_eof);

// ── Test 10: BlockFile::poll_readiness ───────────────────────────────

fn smoke_devfs_block_poll_readiness() -> TestResult {
    use crate::devfs_block::BlockFile;
    use crate::{FileOps, POLL_IN, POLL_OUT};

    let dev = FakeBlockDevice::new(1, 512);
    let bf = BlockFile::from_dev(dev);
    let ready = bf.poll_readiness();
    if ready & POLL_IN == 0 || ready & POLL_OUT == 0 {
        return TestResult::Fail("block device should always be POLL_IN|POLL_OUT ready");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/devfs_block", smoke_devfs_block_poll_readiness);
