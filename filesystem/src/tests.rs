//! Subsystem smokes for `narf-filesystem`.
//!
//! Migrated from `narf-verification`. Tests register under the
//! `filesystem` subsystem.

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

// Tiny CPIO newc archive with a single file "hello" containing "world".
// Hand-built so the test has zero dependency on a host cpio tool;
// see filesystem/src/lib.rs for the on-the-wire format.
static SMOKE_INITRAMFS: &[u8] = b"\
070701\
00000001\
000081A4\
00000000\
00000000\
00000001\
00000064\
00000005\
00000000\
00000000\
00000000\
00000000\
00000006\
00000000\
hello\0\
world\0\0\0\
070701\
00000000\
00000000\
00000000\
00000000\
00000001\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
0000000B\
00000000\
TRAILER!!!\0\0\0\0";

fn smoke_fs_initramfs_mount_and_stat() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, resolve, FileType, Initramfs};

    let fs = match Initramfs::from_cpio("smoke-fs-stat", SMOKE_INITRAMFS) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("CPIO parse failed at fixture build"),
    };

    let authority = bootstrap_mount_authority();
    let _handle = match registry().mount(&authority, "/smoke-stat", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount() refused a live authority"),
    };

    let stat_opt = registry()
        .with_mount("/smoke-stat", |fs| {
            let root = fs.root();
            let file = resolve(root, "hello").ok()?;
            Some(file.stat())
        })
        .flatten();

    let stat = match stat_opt {
        Some(s) => s,
        None => return TestResult::Fail("resolve(hello) failed inside mounted FS"),
    };
    if stat.size != 5 {
        return TestResult::Fail("stat.size != 5");
    }
    if stat.mode.file_type != FileType::File {
        return TestResult::Fail("stat reported non-File type");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_initramfs_mount_and_stat);

fn smoke_fs_initramfs_read() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, resolve, Initramfs};
    use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);
    static GOT_LEN: AtomicUsize = AtomicUsize::new(0);
    OUTCOME.store(0, Ordering::Relaxed);
    GOT_LEN.store(0, Ordering::Relaxed);

    let fs = match Initramfs::from_cpio("smoke-fs-read", SMOKE_INITRAMFS) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("CPIO parse failed at fixture build"),
    };
    let authority = bootstrap_mount_authority();
    let _handle = match registry().mount(&authority, "/smoke-read", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount() refused a live authority"),
    };

    let file = match registry()
        .with_mount("/smoke-read", |fs| resolve(fs.root(), "hello").ok())
        .flatten()
    {
        Some(f) => f,
        None => return TestResult::Fail("resolve(hello) returned None"),
    };

    narf_scheduler::init();
    narf_scheduler::spawn(async move {
        let mut buf = [0u8; 16];
        let n = match file.read(0, &mut buf).await {
            Ok(n) => n,
            Err(_) => {
                OUTCOME.store(3, Ordering::Relaxed);
                return;
            }
        };
        GOT_LEN.store(n, Ordering::Relaxed);
        if n != 5 {
            OUTCOME.store(3, Ordering::Relaxed);
            return;
        }
        if &buf[..5] == b"world" {
            OUTCOME.store(1, Ordering::Relaxed);
        } else {
            OUTCOME.store(2, Ordering::Relaxed);
        }
    });
    narf_scheduler::run_until_empty();

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("read returned wrong bytes"),
        3 => TestResult::Fail("read short or errored"),
        _ => TestResult::Fail("read task never ran"),
    }
}
kernel_test_in!("filesystem", smoke_fs_initramfs_read);

fn smoke_fs_lookup_missing() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, resolve, FsError, Initramfs};

    let fs = match Initramfs::from_cpio("smoke-fs-miss", SMOKE_INITRAMFS) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("CPIO parse failed at fixture build"),
    };
    let authority = bootstrap_mount_authority();
    let _handle = match registry().mount(&authority, "/smoke-miss", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount() refused a live authority"),
    };

    let res = registry().with_mount("/smoke-miss", |fs| resolve(fs.root(), "does-not-exist"));
    match res {
        Some(Err(FsError::NotFound)) => TestResult::Pass,
        Some(Err(_)) => TestResult::Fail("wrong error for missing file"),
        Some(Ok(_)) => TestResult::Fail("missing file resolved to a node"),
        None => TestResult::Fail("with_mount couldn't find the mount we just made"),
    }
}
kernel_test_in!("filesystem", smoke_fs_lookup_missing);

fn smoke_fs_mount_revoked_authority() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, FsError, Initramfs};

    let fs = match Initramfs::from_cpio("smoke-fs-rev", SMOKE_INITRAMFS) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("CPIO parse failed at fixture build"),
    };
    let authority = bootstrap_mount_authority();
    authority.revoke();
    match registry().mount(&authority, "/smoke-rev", fs) {
        Err(FsError::PermissionDenied) => TestResult::Pass,
        Err(_) => TestResult::Fail("revoked authority returned wrong FsError"),
        Ok(_) => TestResult::Fail("mount() accepted a revoked authority"),
    }
}
kernel_test_in!("filesystem", smoke_fs_mount_revoked_authority);

fn smoke_fs_fuse_opcode_constants() -> TestResult {
    use crate::{FuseOpcode, FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION};
    if FuseOpcode::Lookup as u32 != 1 {
        return TestResult::Fail("FuseOpcode::Lookup drifted from UAPI");
    }
    if FuseOpcode::Init as u32 != 26 {
        return TestResult::Fail("FuseOpcode::Init drifted from UAPI");
    }
    if FuseOpcode::ReadDir as u32 != 28 {
        return TestResult::Fail("FuseOpcode::ReadDir drifted from UAPI");
    }
    if FUSE_KERNEL_VERSION != 7 || FUSE_KERNEL_MINOR_VERSION != 36 {
        return TestResult::Fail("FUSE protocol version mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_fuse_opcode_constants);

fn smoke_fs_page_cache_dirty_drain() -> TestResult {
    use crate::{Page, PageCache, PageKey};

    let pc = PageCache::new();
    let k = PageKey {
        fs_id: 1,
        inode: 2,
        page_off: 0,
    };

    if pc.lookup(k).is_some() {
        return TestResult::Fail("empty cache should lookup None");
    }
    let p = Page::zeroed();
    pc.insert(k, p);
    if pc.len() != 1 {
        return TestResult::Fail("insert did not grow cache");
    }

    if !pc.mark_dirty(k) {
        return TestResult::Fail("mark_dirty missed a live key");
    }
    let drained = pc.drain_dirty();
    if drained.len() != 1 || drained[0].0 != k {
        return TestResult::Fail("drain_dirty did not return the marked page");
    }
    let again = pc.drain_dirty();
    if !again.is_empty() {
        return TestResult::Fail("second drain without new mark should be empty");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_page_cache_dirty_drain);
