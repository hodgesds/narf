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
    // SAFETY: raw_waker() returns a vtable whose functions are all no-ops;
    // the waker never dereferences its data pointer.
    // SAFETY: Valid memory or trusted environment
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: fut is a local owned future that is not moved after this point.
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
        Some(Ok(512)) => {}
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
        Some(Ok(100)) => {}
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
        Some(Ok(1500)) => {}
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
        Some(Ok(512)) => {}
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
        Some(Ok(200)) => {}
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
    if stat.mode.file_type != FileType::Block {
        return TestResult::Fail("stat.mode.file_type != Block");
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
            if stat.mode.file_type != FileType::Block {
                return TestResult::Fail("nvme0-test node is not Block");
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
        __restore_for_test, __snapshot_for_test, register_block_device_with_meta, PartitionMetadata,
    };

    let snap = __snapshot_for_test();

    // Register a partition with a label.
    let dev = FakeBlockDevice::filled(4, 512, 0x55);
    let meta = PartitionMetadata {
        gpt_type_guid: alloc::string::String::new(),
        partlabel: alloc::string::String::from("NARF_ROOT_TEST"),
        partuuid: alloc::string::String::from("aaaaaaaa-0000-0000-0000-bbbbbbbbbbbb"),
        fs_uuid: alloc::string::String::new(),
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
        gpt_type_guid: alloc::string::String::new(),
        partlabel: alloc::string::String::from("NARF_ROOT_TEST"),
        partuuid: alloc::string::String::new(),
        fs_uuid: alloc::string::String::new(),
    };
    register_block_device_with_meta("nvme0p1-lbltest2", dev2, Some(meta2));

    let result = by_label_dir.lookup("NARF_ROOT_TEST");
    __restore_for_test(snap2);

    match result {
        Some(f) => {
            if f.stat().mode.file_type != FileType::Symlink {
                return TestResult::Fail("by-label node is not a symlink");
            }
            let mut target = [0u8; 64];
            match poll_once(f.read(0, &mut target)) {
                Some(Ok(n)) if &target[..n] == b"../../nvme0p1-lbltest2" => TestResult::Pass,
                _ => TestResult::Fail("by-label symlink has the wrong target"),
            }
        }
        None => TestResult::Fail("by-label lookup of NARF_ROOT_TEST returned None"),
    }
}
kernel_test_in!(
    "filesystem/devfs_block",
    smoke_devfs_block_disk_by_label_lookup
);

// systemd turns fstab's `UUID=7FC5-5A22` into a .device job for this path.
// The EFI partition therefore must be discoverable through DevFs, not merely
// recorded in the block registry.
fn smoke_devfs_block_disk_by_uuid_lookup() -> TestResult {
    use crate::{DevFs, FileType, FsInstance};
    use narf_block::registry::{
        __reset_for_test, __restore_for_test, __snapshot_for_test, register_block_device_with_meta,
        PartitionMetadata,
    };

    let snap = __snapshot_for_test();
    __reset_for_test();
    let meta = PartitionMetadata {
        gpt_type_guid: alloc::string::String::new(),
        partlabel: alloc::string::String::new(),
        partuuid: alloc::string::String::new(),
        fs_uuid: alloc::string::String::from("7FC5-5A22"),
    };
    register_block_device_with_meta(
        "vblk0p1-uuidtest",
        FakeBlockDevice::filled(4, 512, 0x55),
        Some(meta),
    );

    let root = DevFs::new().root();
    let result = root
        .lookup_dir("disk")
        .and_then(|disk| disk.lookup_dir("by-uuid"))
        .and_then(|by_uuid| by_uuid.lookup("7fc5-5a22"));
    __restore_for_test(snap);

    match result {
        Some(file) if file.stat().mode.file_type == FileType::Symlink => {
            let mut target = [0u8; 64];
            match poll_once(file.read(0, &mut target)) {
                Some(Ok(n)) if &target[..n] == b"../../vblk0p1-uuidtest" => TestResult::Pass,
                _ => TestResult::Fail("by-uuid symlink has the wrong target"),
            }
        }
        _ => TestResult::Fail("by-uuid did not resolve the FAT volume UUID"),
    }
}
kernel_test_in!(
    "filesystem/devfs_block",
    smoke_devfs_block_disk_by_uuid_lookup
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

// ── Test 11: chown/chmod on a block node PERSISTS across re-lookup ─────
//
// Regression for the CachyOS boot: udev's coldplug does
//   `chown(/dev/sata0, 0, 993); chmod(/dev/sata0, 0o660)`
// and the node kept returning EOPNOTSUPP because `BlockFile` — synthesised
// fresh on every `/dev/<name>` lookup — implemented neither `set_owners` nor
// `set_perms`, and had nowhere to store them. A persistent name-keyed overlay
// now backs both, so the new owner/mode survive the next lookup's brand-new
// `BlockFile`.

fn smoke_devfs_block_chown_chmod_persists() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, DevFs};

    crate::devfs_block::__reset_block_attrs_for_test();
    let snap = narf_block::registry::__snapshot_for_test();

    let dev = FakeBlockDevice::filled(8, 512, 0x00);
    narf_block::registry::register_block_device("nvme0-attr", dev);

    let auth = bootstrap_mount_authority();
    let mnt = registry().mount(&auth, "/dev-attr-test", DevFs::new());
    let _mnt = match mnt {
        Ok(h) => h,
        Err(_) => {
            narf_block::registry::__restore_for_test(snap);
            crate::devfs_block::__reset_block_attrs_for_test();
            return TestResult::Fail("DevFs mount for chown/chmod test failed");
        }
    };

    let resolve = || {
        registry()
            .resolve_absolute("/dev-attr-test/nvme0-attr", |fs, rel| {
                crate::resolve(fs.root(), rel).ok()
            })
            .flatten()
    };

    // Baseline: default root:disk 0o660.
    let node = match resolve() {
        Some(f) => f,
        None => {
            narf_block::registry::__restore_for_test(snap);
            crate::devfs_block::__reset_block_attrs_for_test();
            return TestResult::Fail("initial block-node lookup returned None");
        }
    };
    if node.owners() != (0, 6) || node.stat().mode.perms != 0o660 {
        narf_block::registry::__restore_for_test(snap);
        crate::devfs_block::__reset_block_attrs_for_test();
        return TestResult::Fail("unexpected default block-node owner/mode");
    }

    // udev-style chown to root:993 and chmod to 0o640.
    let set_ok = matches!(poll_once(node.set_owners(0, 993)), Some(Ok(())))
        && matches!(poll_once(node.set_perms(0o640)), Some(Ok(())));
    drop(node);
    if !set_ok {
        narf_block::registry::__restore_for_test(snap);
        crate::devfs_block::__reset_block_attrs_for_test();
        return TestResult::Fail("set_owners/set_perms returned an error (EOPNOTSUPP regression)");
    }

    // Re-resolve builds a BRAND-NEW BlockFile; the change must survive.
    let reop = resolve();
    narf_block::registry::__restore_for_test(snap);

    let verdict = match reop {
        Some(f) => {
            if f.owners() == (0, 993) && f.stat().mode.perms == 0o640 {
                TestResult::Pass
            } else {
                TestResult::Fail("chown/chmod did not persist across block-node re-lookup")
            }
        }
        None => TestResult::Fail("re-lookup of block node returned None"),
    };
    crate::devfs_block::__reset_block_attrs_for_test();
    verdict
}
kernel_test_in!(
    "filesystem/devfs_block",
    smoke_devfs_block_chown_chmod_persists
);

// ── Test 12: symlinkat under /dev/disk/by-uuid ────────────────────────
//
// Regression for the CachyOS boot: udev computes each filesystem's UUID and
// creates `/dev/disk/by-uuid/<uuid> -> ../../<dev>`, but `DevDiskByUuid` had
// no `symlink` op so the `symlinkat` failed and `udevadm settle` never
// completed. The directory now carries a writable overlay: the alias is
// created, resolves on lookup, `readlink`s to its target, appears in readdir,
// and can be unlinked.

fn smoke_devfs_disk_by_uuid_symlink_roundtrip() -> TestResult {
    use crate::devfs_block::DevDiskByUuid;
    use crate::{DirOps, FileType, FsError};

    crate::devfs_block::__reset_disk_links_for_test();
    let dir = DevDiskByUuid;

    let uuid = "066fb7bb-1111-2222-3333-444455556666";
    let target = "../../vblk0p2";

    let finish = |verdict: TestResult| {
        crate::devfs_block::__reset_disk_links_for_test();
        verdict
    };

    // Create the alias.
    if !matches!(poll_once(dir.symlink(uuid, target)), Some(Ok(_))) {
        return finish(TestResult::Fail(
            "by-uuid symlink create failed (EINVAL regression)",
        ));
    }
    // A duplicate create is EEXIST (Busy), matching Linux symlink(2).
    if !matches!(
        poll_once(dir.symlink(uuid, target)),
        Some(Err(FsError::Busy))
    ) {
        return finish(TestResult::Fail(
            "duplicate by-uuid symlink did not report Busy",
        ));
    }
    // It resolves on lookup and stats as a symlink.
    let node = match dir.lookup(uuid) {
        Some(f) => f,
        None => {
            return finish(TestResult::Fail(
                "created by-uuid symlink not found on lookup",
            ))
        }
    };
    if node.stat().mode.file_type != FileType::Symlink {
        return finish(TestResult::Fail("looked-up by-uuid node is not a symlink"));
    }
    // readlink returns the verbatim target.
    let mut buf = [0u8; 64];
    match poll_once(node.read(0, &mut buf)) {
        Some(Ok(n)) if &buf[..n] == target.as_bytes() => {}
        _ => {
            return finish(TestResult::Fail(
                "by-uuid readlink returned the wrong target",
            ))
        }
    }
    // readdir lists it.
    let listed = dir.enumerate(0, 64);
    if !listed
        .iter()
        .any(|(nm, ft)| nm == uuid && *ft == FileType::Symlink)
    {
        return finish(TestResult::Fail("by-uuid symlink absent from enumerate"));
    }
    // Unlink removes it.
    if !matches!(poll_once(dir.unlink(uuid)), Some(Ok(()))) {
        return finish(TestResult::Fail("by-uuid symlink unlink failed"));
    }
    if dir.lookup(uuid).is_some() {
        return finish(TestResult::Fail(
            "by-uuid symlink still present after unlink",
        ));
    }
    finish(TestResult::Pass)
}
kernel_test_in!(
    "filesystem/devfs_block",
    smoke_devfs_disk_by_uuid_symlink_roundtrip
);

// ── mount(2) block sources: registry names behind /dev/ paths ─────────

fn smoke_block_source_name_resolves_dev_paths() -> TestResult {
    use crate::fs_registry::block_source_name;
    let snap = narf_block::registry::__snapshot_for_test();
    narf_block::registry::register_block_device("narfsrcp9", FakeBlockDevice::new(8, 512));
    // The bare name, its /dev/ path, and the chrooted /mnt/dev/ path that
    // mount(8) passes from systemd's root all name the device; a deeper
    // path does not.
    let ok = ["narfsrcp9", "/dev/narfsrcp9", "/mnt/dev/narfsrcp9"]
        .iter()
        .all(|source| block_source_name(source) == Some("narfsrcp9"));
    let nested = block_source_name("/dev/disk/narfsrcp9").is_none();
    narf_block::registry::__restore_for_test(snap);
    if !ok {
        return TestResult::Fail("registered block source not resolved from its path");
    }
    if !nested {
        return TestResult::Fail("only a direct child of a dev/ directory names a device");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/devfs_block",
    smoke_block_source_name_resolves_dev_paths
);

// ── >65535-LBA requests are split, never truncated to u16 ─────────────

/// Wraps a [`FakeBlockDevice`] and records every call's block count, so a
/// test can see how a large request was split.
struct CountingDev {
    inner: Arc<FakeBlockDevice>,
    calls: narf_lib::sync::IrqSafeSpinLock<Vec<u16>>,
}

impl core::fmt::Debug for CountingDev {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CountingDev").finish_non_exhaustive()
    }
}

impl BlockDeviceSync for CountingDev {
    fn lba_size(&self) -> u32 {
        self.inner.lba_size()
    }
    fn capacity(&self) -> u64 {
        self.inner.capacity()
    }
    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        self.calls.lock().push(n_blocks);
        self.inner.read(lba, n_blocks, out)
    }
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError> {
        self.calls.lock().push(n_blocks);
        self.inner.write(lba, n_blocks, data)
    }
}

/// A 70 000-LBA write and read (8-byte sectors keep the device at 560 KiB)
/// move every byte: each device call carries at most 65 535 blocks, so the
/// count never wraps through `u16` (which moved `70 000 mod 65 536 = 4 464`
/// blocks and still reported success). An unaligned start exercises the RMW
/// of the first and last block across the chunk boundary.
fn smoke_devfs_block_large_request_is_chunked() -> TestResult {
    use crate::devfs_block::BlockFile;
    use crate::FileOps;

    const LBAS: usize = 70_000;
    const BS: u32 = 8;
    let fake = FakeBlockDevice::filled(LBAS + 2, BS, 0x5A);
    let dev = Arc::new(CountingDev {
        inner: fake.clone(),
        calls: narf_lib::sync::IrqSafeSpinLock::new(Vec::new()),
    });
    let bf = BlockFile::from_dev(dev.clone());
    if BlockFile::max_chunk_lbas(BS) != u64::from(u16::MAX)
        || BlockFile::max_chunk_lbas(4096) != 256
    {
        return TestResult::Fail("chunk size must respect u16 and the 1 MiB stage");
    }

    // Aligned 70 000-LBA write.
    let len = LBAS * BS as usize;
    let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    match poll_once(bf.write(0, &payload)) {
        Some(Ok(n)) if n == len => {}
        _ => return TestResult::Fail("large aligned write did not report the full length"),
    }
    if *dev.calls.lock() != [u16::MAX, (LBAS - u16::MAX as usize) as u16] {
        return TestResult::Fail("70 000 LBAs must be written as 65 535 + 4 465");
    }
    {
        let g = fake.data.lock();
        if g[..len] != payload[..] || g[len..].iter().any(|&b| b != 0x5A) {
            return TestResult::Fail("large write did not land every block exactly");
        }
    }

    // Aligned 70 000-LBA read back.
    dev.calls.lock().clear();
    let mut back = vec![0u8; len];
    match poll_once(bf.read(0, &mut back)) {
        Some(Ok(n)) if n == len => {}
        _ => return TestResult::Fail("large aligned read did not report the full length"),
    }
    if back != payload {
        return TestResult::Fail("large read returned wrong bytes");
    }
    if *dev.calls.lock() != [u16::MAX, (LBAS - u16::MAX as usize) as u16] {
        return TestResult::Fail("70 000 LBAs must be read as 65 535 + 4 465");
    }

    // Unaligned: start 3 bytes into LBA 1, span past the chunk boundary.
    dev.calls.lock().clear();
    let off = BS as u64 + 3;
    let ulen = len - 16;
    let upayload: Vec<u8> = (0..ulen).map(|i| (i % 13) as u8 ^ 0xC3).collect();
    match poll_once(bf.write(off, &upayload)) {
        Some(Ok(n)) if n == ulen => {}
        _ => return TestResult::Fail("large unaligned write did not report the full length"),
    }
    {
        let g = fake.data.lock();
        let o = off as usize;
        if g[o..o + ulen] != upayload[..]
            || g[..o] != payload[..o]
            || g[o + ulen..len] != payload[o + ulen..]
        {
            return TestResult::Fail("large unaligned write clobbered or missed bytes");
        }
    }
    let mut uback = vec![0u8; ulen];
    match poll_once(bf.read(off, &mut uback)) {
        Some(Ok(n)) if n == ulen && uback == upayload => {}
        _ => return TestResult::Fail("large unaligned read-back mismatch"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/devfs_block",
    smoke_devfs_block_large_request_is_chunked
);

/// A device error after the first chunk is a short count, not a success
/// claiming every byte (and not an error that hides the bytes moved).
fn smoke_devfs_block_large_request_short_count() -> TestResult {
    use crate::devfs_block::BlockFile;
    use crate::FileOps;

    // 70 000 blocks exposed, but the backing store ends after 66 000: the
    // second chunk is out of range on the device.
    const BS: u32 = 8;
    let fake = FakeBlockDevice::filled(66_000, BS, 0x11);
    let mut bf = BlockFile::from_dev(fake);
    bf.lba_count = 70_000;
    let mut buf = vec![0u8; 70_000 * BS as usize];
    match poll_once(bf.read(0, &mut buf)) {
        Some(Ok(n)) if n == u16::MAX as usize * BS as usize => {}
        _ => return TestResult::Fail("read past a failing chunk must return the short count"),
    }
    let data = vec![0x22u8; 70_000 * BS as usize];
    match poll_once(bf.write(0, &data)) {
        Some(Ok(n)) if n == u16::MAX as usize * BS as usize => {}
        _ => return TestResult::Fail("write past a failing chunk must return the short count"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/devfs_block",
    smoke_devfs_block_large_request_short_count
);

// ── /dev/btrfs-control: BTRFS_IOC_DEVICES_READY ─────────────────────────

/// A fake disk whose primary btrfs superblock (64 KiB) carries `fsid` and
/// `num_devices`.
fn fake_btrfs_member(fsid: [u8; 16], num_devices: u64) -> Arc<FakeBlockDevice> {
    let dev = FakeBlockDevice::new(256, 512); // 128 KiB
    let mut sb = vec![0u8; 4096];
    sb[0x20..0x30].copy_from_slice(&fsid);
    sb[0x40..0x48].copy_from_slice(b"_BHRfS_M");
    sb[0x88..0x90].copy_from_slice(&num_devices.to_le_bytes());
    let _ = dev.write(65536 / 512, 8, &sb);
    dev
}

fn smoke_btrfs_control_devices_ready() -> TestResult {
    use crate::devfs_misc::btrfs_devices_ready;
    let snap = narf_block::registry::__snapshot_for_test();
    let single = [0x11u8; 16];
    let multi = [0x22u8; 16];
    narf_block::registry::register_block_device("narfbtrfs1p2", fake_btrfs_member(single, 1));
    narf_block::registry::register_block_device("narfbtrfs2a", fake_btrfs_member(multi, 2));
    let single_ready = btrfs_devices_ready("/dev/narfbtrfs1p2");
    let half = btrfs_devices_ready("/dev/narfbtrfs2a");
    narf_block::registry::register_block_device("narfbtrfs2b", fake_btrfs_member(multi, 2));
    let whole = btrfs_devices_ready("/mnt/dev/narfbtrfs2a");
    let not_btrfs = btrfs_devices_ready("/dev/narf-no-such");
    narf_block::registry::__restore_for_test(snap);
    if single_ready != Ok(0) {
        return TestResult::Fail("a single-device btrfs must always be ready");
    }
    if half != Ok(1) {
        return TestResult::Fail("one of two members present must be not-ready");
    }
    if whole != Ok(0) {
        return TestResult::Fail("both members present must be ready");
    }
    if not_btrfs.is_ok() {
        return TestResult::Fail("an unknown device must be an error, not an answer");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/devfs_block", smoke_btrfs_control_devices_ready);
