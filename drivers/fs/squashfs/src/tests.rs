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
