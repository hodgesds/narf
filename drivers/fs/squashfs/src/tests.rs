//! SquashFS conformance and corruption regression tests.

use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

const FIXTURE: &[u8] = include_bytes!("../testdata/linux-gzip.sqfs");

fn poll_once<F: core::future::Future>(mut future: F) -> Option<F::Output> {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn raw_waker() -> RawWaker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        unsafe fn no_op(_: *const ()) {}
        const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTABLE)
    }

    // SAFETY: the no-op vtable never dereferences the null data pointer.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut context = Context::from_waker(&waker);
    // SAFETY: `future` remains at this stack location until it is dropped.
    let pinned = unsafe { Pin::new_unchecked(&mut future) };
    match pinned.poll(&mut context) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

fn mount_image(
    image: Vec<u8>,
) -> Result<
    alloc::sync::Arc<crate::volume::SquashfsVolume<narf_block::ram::RamBlockDevice>>,
    narf_filesystem::FsError,
> {
    use narf_block::ram::RamBlockDevice;
    use narf_lib::id::DomainId;

    let device = RamBlockDevice::from_image(512, image);
    poll_once(crate::volume::SquashfsVolume::mount(
        device,
        DomainId::DRIVER_0,
    ))
    .ok_or(narf_filesystem::FsError::InvalidData)?
}

fn smoke_squashfs_linux_fixture_mount_read() -> TestResult {
    use narf_filesystem::{FileType, FsInstance};

    let volume = match mount_image(FIXTURE.to_vec()) {
        Ok(volume) => volume,
        Err(_) => return TestResult::Fail("Linux mksquashfs fixture did not mount"),
    };
    if volume.name() != "squashfs" {
        return TestResult::Fail("filesystem name mismatch");
    }
    let root = volume.root();
    if root.ino() == 0 || root.dir_mode() != 0o755 || root.dir_owners() != (0, 0) {
        return TestResult::Fail("root metadata mismatch");
    }
    let entries = match poll_once(root.enumerate_async(0, 32)) {
        Some(Ok(entries)) => entries,
        _ => return TestResult::Fail("root enumeration failed"),
    };
    for expected in [
        ("data-link", FileType::Symlink),
        ("hello.txt", FileType::File),
        ("nested", FileType::Dir),
        ("pipe", FileType::Fifo),
        ("sparse.bin", FileType::File),
    ] {
        if !entries
            .iter()
            .any(|(name, file_type)| name == expected.0 && *file_type == expected.1)
        {
            return TestResult::Fail("expected root entry missing");
        }
    }

    let hello = match poll_once(root.lookup_async("hello.txt")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("hello lookup failed"),
    };
    if hello.ino() == 0 || hello.owners() != (0, 0) || hello.stat().mode.perms != 0o644 {
        return TestResult::Fail("hello metadata mismatch");
    }
    let mut bytes = [0u8; 32];
    let n = match poll_once(hello.read(0, &mut bytes)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("fragment-backed hello read failed"),
    };
    if &bytes[..n] != b"narf-squashfs\n" {
        return TestResult::Fail("hello contents mismatch");
    }
    let statx = match poll_once(hello.statx_async(0, u32::MAX)) {
        Some(Ok(statx)) => statx,
        _ => return TestResult::Fail("native statx failed"),
    };
    if statx.ino != hello.ino() || statx.mtime.seconds != 1_700_000_000 {
        return TestResult::Fail("statx inode/timestamp mismatch");
    }

    let nested = match poll_once(root.lookup_dir_async("nested")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("nested directory lookup failed"),
    };
    let data = match poll_once(nested.lookup_async("data.txt")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("nested data lookup failed"),
    };
    let n = match poll_once(data.read(0, &mut bytes)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("nested data read failed"),
    };
    if &bytes[..n] != b"nested-payload\n" {
        return TestResult::Fail("nested data mismatch");
    }

    let link = match poll_once(root.lookup_async("data-link")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("symlink lookup failed"),
    };
    let n = match poll_once(link.read(0, &mut bytes)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("symlink read failed"),
    };
    if &bytes[..n] != b"nested/data.txt" {
        return TestResult::Fail("symlink target mismatch");
    }

    let statfs = match poll_once(volume.statfs()) {
        Some(Ok(statfs)) => statfs,
        _ => return TestResult::Fail("statfs failed"),
    };
    if statfs.block_size != 4096
        || statfs.blocks != 1
        || statfs.blocks_free != 0
        || statfs.files != 7
        || statfs.name_len != 256
    {
        return TestResult::Fail("Linux statfs fields mismatch");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/squashfs",
    smoke_squashfs_linux_fixture_mount_read
);

fn smoke_squashfs_sparse_and_read_only() -> TestResult {
    use narf_filesystem::{FsError, FsInstance};

    let volume = match mount_image(FIXTURE.to_vec()) {
        Ok(volume) => volume,
        Err(_) => return TestResult::Fail("fixture mount failed"),
    };
    let root = volume.root();
    let sparse = match poll_once(root.lookup_async("sparse.bin")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("sparse lookup failed"),
    };
    let mut bytes = [0xa5u8; 16384];
    let n = match poll_once(sparse.read(0, &mut bytes)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("sparse read failed"),
    };
    if n != bytes.len() {
        return TestResult::Fail("sparse short read");
    }
    if bytes[..12000].iter().any(|byte| *byte != 0)
        || &bytes[12000..12009] != b"tail-data"
        || bytes[12009..].iter().any(|byte| *byte != 0)
    {
        return TestResult::Fail("sparse hole/data reconstruction mismatch");
    }

    match poll_once(sparse.write(0, b"x")) {
        Some(Err(FsError::ReadOnly)) => {}
        _ => return TestResult::Fail("write did not return ReadOnly"),
    }
    match poll_once(sparse.truncate(0)) {
        Some(Err(FsError::ReadOnly)) => {}
        _ => return TestResult::Fail("truncate did not return ReadOnly"),
    }
    match poll_once(root.create("new")) {
        Some(Err(FsError::ReadOnly)) => {}
        _ => return TestResult::Fail("create did not return ReadOnly"),
    }
    match poll_once(root.unlink("hello.txt")) {
        Some(Err(FsError::ReadOnly)) => {}
        _ => return TestResult::Fail("unlink did not return ReadOnly"),
    }
    match poll_once(root.rename("hello.txt", "renamed")) {
        Some(Err(FsError::ReadOnly)) => {}
        _ => return TestResult::Fail("rename did not return ReadOnly"),
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/squashfs", smoke_squashfs_sparse_and_read_only);

fn smoke_squashfs_rejects_corrupt_superblocks() -> TestResult {
    use narf_filesystem::FsError;

    let cases: &[(usize, &[u8])] = &[
        (0, &0u32.to_le_bytes()),
        (22, &21u16.to_le_bytes()),
        (40, &8192u64.to_le_bytes()),
        (32, &8192u64.to_le_bytes()),
    ];
    for &(offset, replacement) in cases {
        let mut image = FIXTURE.to_vec();
        image[offset..offset + replacement.len()].copy_from_slice(replacement);
        if mount_image(image).is_ok() {
            return TestResult::Fail("corrupt superblock mounted");
        }
    }

    let mut unsupported = FIXTURE.to_vec();
    unsupported[20..22].copy_from_slice(&6u16.to_le_bytes());
    if !matches!(mount_image(unsupported), Err(FsError::Unsupported)) {
        return TestResult::Fail("unsupported compressor was not rejected honestly");
    }

    // Corrupt the first inode metadata header to encode a zero-byte block.
    let inode_table = u64::from_le_bytes(FIXTURE[64..72].try_into().unwrap()) as usize;
    let mut metadata = FIXTURE.to_vec();
    metadata[inode_table..inode_table + 2].fill(0);
    if mount_image(metadata).is_ok() {
        return TestResult::Fail("zero-length inode metadata block mounted");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/squashfs",
    smoke_squashfs_rejects_corrupt_superblocks
);

/// `linux-gzip.sqfs` with distinct per-inode mtimes (`testdata/patch_times.py`):
/// `/` 1600000000, `nested/` 1650000123, `hello.txt` 1700000123,
/// `nested/data.txt` 0xF000_0000.
const TIMES_FIXTURE: &[u8] = include_bytes!("../testdata/linux-times.sqfs");

/// A file reports its on-disk `squashfs_base_inode.mtime` exactly, through
/// `InodeAttrs` (which the stat path prefers over the lossy
/// `Stat::mtime_cycles`) and `statx`. SquashFS has no other time, and Linux's
/// `squashfs_new_inode` reports the mtime as atime and ctime too.
fn smoke_squashfs_file_exact_mtime() -> TestResult {
    use narf_filesystem::FsInstance;

    let volume = match mount_image(TIMES_FIXTURE.to_vec()) {
        Ok(volume) => volume,
        Err(_) => return TestResult::Fail("times fixture did not mount"),
    };
    let hello = match poll_once(volume.root().lookup_async("hello.txt")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("hello lookup failed"),
    };
    let want = 1_700_000_123u64 * 1_000_000_000;
    let attrs = hello.inode_attrs();
    if attrs.mtime_ns != want {
        return TestResult::Fail("file mtime_ns is not the on-disk mtime");
    }
    if attrs.atime_ns != want || attrs.ctime_ns != want {
        return TestResult::Fail("file atime/ctime are not the mtime, as Linux reports");
    }
    if hello.stat().mtime_cycles != narf_time::ns_to_cycles(want) {
        return TestResult::Fail("Stat::mtime_cycles does not derive from the exact mtime");
    }
    match poll_once(hello.statx_async(0, u32::MAX)) {
        Some(Ok(sx)) if (sx.mtime.seconds, sx.mtime.nanoseconds) == (1_700_000_123, 0) => {}
        _ => return TestResult::Fail("statx mtime is not the on-disk mtime"),
    }
    // The fixture's other inodes carry other times: a driver reporting the
    // superblock's mkfs_time (1700000000) or a shared value fails here.
    if attrs.mtime_ns == u64::from(volume.superblock.mkfs_time) * 1_000_000_000 {
        return TestResult::Fail("file reported the superblock mkfs_time");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/squashfs", smoke_squashfs_file_exact_mtime);

/// A directory's mtime reaches the stat path via `DirOps::dir_mtime_ns` and
/// `inode_attrs().mtime_ns`, exactly; the epoch (what every SquashFS
/// directory used to report) made every fontconfig cache look stale.
fn smoke_squashfs_dir_exact_mtime() -> TestResult {
    use narf_filesystem::FsInstance;

    let volume = match mount_image(TIMES_FIXTURE.to_vec()) {
        Ok(volume) => volume,
        Err(_) => return TestResult::Fail("times fixture did not mount"),
    };
    let root = volume.root();
    let root_want = 1_600_000_000u64 * 1_000_000_000;
    if root.dir_mtime_ns() != root_want || root.inode_attrs().mtime_ns != root_want {
        return TestResult::Fail("root dir mtime is not the on-disk mtime");
    }
    let nested = match poll_once(root.lookup_dir_async("nested")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("nested lookup failed"),
    };
    let want = 1_650_000_123u64 * 1_000_000_000;
    if nested.dir_mtime_ns() != want {
        return TestResult::Fail("nested/ dir_mtime_ns is not the on-disk mtime");
    }
    let attrs = nested.inode_attrs();
    if attrs.mtime_ns != want || attrs.atime_ns != want || attrs.ctime_ns != want {
        return TestResult::Fail("nested/ inode_attrs times are not the on-disk mtime");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/squashfs", smoke_squashfs_dir_exact_mtime);

/// Edges of the 32-bit seconds-only field: Linux decodes it unsigned
/// (`le32_to_cpu` into a `time64_t`), so 0xF000_0000 is 4026531840 s (2097),
/// not a pre-1970 negative time, and there is never a sub-second part.
fn smoke_squashfs_mtime_unsigned_whole_seconds() -> TestResult {
    use narf_filesystem::FsInstance;

    let volume = match mount_image(TIMES_FIXTURE.to_vec()) {
        Ok(volume) => volume,
        Err(_) => return TestResult::Fail("times fixture did not mount"),
    };
    let nested = match poll_once(volume.root().lookup_dir_async("nested")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("nested lookup failed"),
    };
    let data = match poll_once(nested.lookup_async("data.txt")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("nested data lookup failed"),
    };
    let want = 0xF000_0000u64 * 1_000_000_000;
    if data.inode_attrs().mtime_ns != want {
        return TestResult::Fail("a 32-bit mtime >= 2^31 was not decoded unsigned");
    }
    match poll_once(data.statx_async(0, u32::MAX)) {
        Some(Ok(sx)) if (sx.mtime.seconds, sx.mtime.nanoseconds) == (0xF000_0000, 0) => {}
        _ => return TestResult::Fail("statx mtime >= 2^31 was not decoded unsigned"),
    }
    for ns in [data.inode_attrs().mtime_ns, nested.dir_mtime_ns()] {
        if ns % 1_000_000_000 != 0 {
            return TestResult::Fail("SquashFS reported a sub-second part it cannot store");
        }
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/squashfs",
    smoke_squashfs_mtime_unsigned_whole_seconds
);

/// SquashFS is read-only: Linux forces `SB_RDONLY` in `squashfs_fill_super`,
/// so `link(2)` fails with EROFS from `mnt_want_write` (after the old name's
/// lookup and the new name's EEXIST check, which the VFS does before the
/// filesystem is asked). The driver answers `ReadOnly` (EROFS) for both link
/// forms and creates no name.
fn smoke_squashfs_link_is_erofs() -> TestResult {
    use narf_filesystem::{FsError, FsInstance};

    let volume = match mount_image(TIMES_FIXTURE.to_vec()) {
        Ok(volume) => volume,
        Err(_) => return TestResult::Fail("times fixture did not mount"),
    };
    let root = volume.root();
    if !matches!(
        poll_once(root.link("hello.txt", "alias")),
        Some(Err(FsError::ReadOnly))
    ) {
        return TestResult::Fail("link on SquashFS did not return ReadOnly (EROFS)");
    }
    let nested = match poll_once(root.lookup_dir_async("nested")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("nested lookup failed"),
    };
    if !matches!(
        poll_once(root.link_to("hello.txt", &*nested, "alias")),
        Some(Err(FsError::ReadOnly))
    ) {
        return TestResult::Fail("cross-directory link did not return ReadOnly (EROFS)");
    }
    if !matches!(
        poll_once(root.lookup_async("alias")),
        Some(Err(FsError::NotFound))
    ) || !matches!(
        poll_once(nested.lookup_async("alias")),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("a refused link created a name");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/squashfs", smoke_squashfs_link_is_erofs);
