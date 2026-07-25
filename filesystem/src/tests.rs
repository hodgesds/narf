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

    narf_scheduler::__reset_queues_for_test();
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

// ── Mount/path resolution + memfs/devfs handler tests (relocated from verification) ──

fn smoke_filesystem_resolve_absolute_picks_longest_prefix() -> TestResult {
    // Mount two FSes — one at `/test_pa` and one nested under
    // `/test_pa/sub`. `resolve_absolute("/test_pa/sub/x")` must
    // match the nested mount and hand the FS a relative path of
    // `x`, NOT `sub/x` against the outer FS.
    use crate::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use narf_capabilities::{Cap, Grant};

    struct OuterFs;
    struct InnerFs;
    struct DummyDir;
    struct DummyFile;
    impl FileOps for DummyFile {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, _b: &'a [u8]) -> FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async { Ok(0) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: crate::Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
    }
    impl DirOps for DummyDir {
        fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
            Some(Arc::new(DummyFile))
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    impl FsInstance for OuterFs {
        fn root(&self) -> Arc<dyn DirOps> {
            Arc::new(DummyDir)
        }
        fn name(&self) -> &str {
            "outer"
        }
    }
    impl FsInstance for InnerFs {
        fn root(&self) -> Arc<dyn DirOps> {
            Arc::new(DummyDir)
        }
        fn name(&self) -> &str {
            "inner"
        }
    }

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    if registry().mount(&auth, "/test_pa", OuterFs).is_err() {
        return TestResult::Fail("outer mount failed");
    }
    if registry().mount(&auth, "/test_pa/sub", InnerFs).is_err() {
        return TestResult::Fail("inner mount failed");
    }

    // Path under outer mount.
    let outer = registry().resolve_absolute("/test_pa/x", |fs, rel| {
        (fs.name() == "outer", alloc::string::String::from(rel))
    });
    match outer {
        Some((true, ref s)) if s == "x" => {}
        _ => return TestResult::Fail("outer mount + relative path mismatch"),
    }

    // Path under inner mount — longest-prefix wins over outer.
    let inner = registry().resolve_absolute("/test_pa/sub/y", |fs, rel| {
        (fs.name() == "inner", alloc::string::String::from(rel))
    });
    match inner {
        Some((true, ref s)) if s == "y" => {}
        _ => return TestResult::Fail("inner mount didn't win on longer prefix"),
    }

    // Unmounted prefix behavior depends on whether a root mount
    // ("/") exists in the registry. `resolve_absolute` intentionally
    // special-cases the root mount as a fallback that matches every
    // absolute path (the doc-comment on resolve_absolute spells
    // this out: "Special-case "/" so the root mount always matches
    // as the fallback option"). So `/elsewhere/z` resolves to root
    // when root is mounted, returns None otherwise. Either is
    // correct; the test pinned only the no-root case and was flaky
    // depending on whether the initramfs-mount-at-boot initcall
    // had run before this test. Assert against the actual
    // invariant: when root is mounted, every path resolves; when
    // it isn't, paths not covered by another mount don't.
    let root_present = registry().list().iter().any(|p| p == "/");
    let elsewhere_resolved =
        registry().resolve_absolute("/elsewhere/z", |_, rel| alloc::string::String::from(rel));
    match (root_present, &elsewhere_resolved) {
        (true, Some(rel)) if rel == "elsewhere/z" => {}
        (true, _) => {
            return TestResult::Fail(
                "root mount present but /elsewhere/z didn't resolve to it with rel='elsewhere/z'",
            );
        }
        (false, None) => {}
        (false, Some(_)) => {
            return TestResult::Fail(
                "no root mount yet /elsewhere/z resolved — which mount caught it?",
            );
        }
    }

    // Empty path → None regardless of root.
    if registry().resolve_absolute("", |_, _| ()).is_some() {
        return TestResult::Fail("empty path should not resolve");
    }

    TestResult::Pass
}
kernel_test_in!(
    "filesystem",
    smoke_filesystem_resolve_absolute_picks_longest_prefix
);

fn smoke_filesystem_memfs_unlink_round_trip() -> TestResult {
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
        // SAFETY: raw_waker() returns a vtable whose no-op/no-clone fns are sound for a
        // single-threaded test poll; the RawWaker is not used after this scope.
        // SAFETY: Valid memory or trusted environment
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` is a local mut binding that outlives this block; we do not move it.
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        match pinned.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    // Mount a MemFs at /test_unlink seeded with one file. The first
    // resolve_parent_absolute → unlink should succeed; the second
    // should hit NotFound (file already gone).
    use crate::{bootstrap_mount_authority, registry, FsError, MemFs, MountPoint};
    use narf_capabilities::{Cap, Grant};

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let fs = MemFs::with_seeds("test-unlink", &[("doomed", b"x")]);
    let mount_handle = match registry().mount(&auth, "/test_unlink", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("memfs mount failed"),
    };

    // Pre-condition: lookup confirms the file exists via the open
    // path (FileOps reachable through resolve_absolute).
    let pre = registry().resolve_absolute("/test_unlink/doomed", |fs, rel| {
        crate::resolve(fs.root(), rel).is_ok()
    });
    if pre != Some(true) {
        return TestResult::Fail("seeded file not findable pre-unlink");
    }

    // First unlink: success.
    let r1 = registry().resolve_parent_absolute("/test_unlink/doomed", |_fs, parent, leaf| {
        poll_once(parent.unlink(leaf))
    });
    if !matches!(r1, Some(Some(Ok(())))) {
        return TestResult::Fail("first unlink should succeed");
    }

    // Post-condition: lookup now misses.
    let post = registry().resolve_absolute("/test_unlink/doomed", |fs, rel| {
        crate::resolve(fs.root(), rel).is_ok()
    });
    if post != Some(false) {
        return TestResult::Fail("file still findable after unlink");
    }

    // Second unlink: NotFound.
    let r2 = registry().resolve_parent_absolute("/test_unlink/doomed", |_fs, parent, leaf| {
        poll_once(parent.unlink(leaf))
    });
    if !matches!(r2, Some(Some(Err(FsError::NotFound)))) {
        return TestResult::Fail("second unlink should report NotFound");
    }

    // Free the mount + FS so a long test sequence doesn't accumulate
    // FS state (the global registry has no GC and the kernel heap is
    // bounded).
    let _ = registry().unmount(&mount_handle, "/test_unlink");
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_filesystem_memfs_unlink_round_trip);

/// A pathname AF_UNIX `bind()` materialises an S_IFSOCK inode in Linux;
/// NARF does the same via `DirOps::create_socket`. This exercises the
/// memfs (tmpfs) implementation directly: create a socket node, confirm it
/// `stat`s as `FileType::Socket` (so `[ -S ]`/`ls -l` see a socket, not a
/// regular file), and that it can be unlinked. Without the socket type,
/// wayland/dbus/shell probes of the bound socket path misread it.
fn smoke_filesystem_memfs_socket_node() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, MemFs, MountPoint};
    use narf_capabilities::{Cap, Grant};

    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VT)
        }
        static VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        // SAFETY: the vtable's clone/wake/drop are all no-ops over a null
        // data pointer, so the RawWaker upholds the Waker contract trivially.
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VT)) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` is a local mut binding that outlives this block and is
        // never moved after being pinned here.
        let fut = unsafe { core::pin::Pin::new_unchecked(&mut fut) };
        match fut.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let fs = MemFs::with_seeds("test-socknode", &[]);
    let mount_handle = match registry().mount(&auth, "/test_socknode", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("memfs mount failed"),
    };

    // bind() side: create the socket inode.
    let created = registry().resolve_parent_absolute("/test_socknode/sock", |_fs, parent, leaf| {
        poll_once(parent.create_socket(leaf, 0o755))
    });
    if !matches!(created, Some(Some(Ok(_)))) {
        let _ = registry().unmount(&mount_handle, "/test_socknode");
        return TestResult::Fail("create_socket failed on memfs");
    }

    // stat() must report S_IFSOCK, not S_IFREG.
    let is_sock = registry().resolve_absolute("/test_socknode/sock", |fs, rel| {
        crate::resolve(fs.root(), rel)
            .map(|f| f.stat().mode.file_type == crate::FileType::Socket)
            .unwrap_or(false)
    });
    if is_sock != Some(true) {
        let _ = registry().unmount(&mount_handle, "/test_socknode");
        return TestResult::Fail("bound socket path did not stat as S_IFSOCK");
    }

    // unlink() removes the node (dbus/wayland unlink a stale socket path).
    let unl = registry().resolve_parent_absolute("/test_socknode/sock", |_fs, parent, leaf| {
        poll_once(parent.unlink(leaf))
    });
    if !matches!(unl, Some(Some(Ok(())))) {
        let _ = registry().unmount(&mount_handle, "/test_socknode");
        return TestResult::Fail("unlink of socket node failed");
    }

    let _ = registry().unmount(&mount_handle, "/test_socknode");
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_filesystem_memfs_socket_node);

/// Shared no-op-waker poll driver for the FIFO smokes below — the FIFO
/// `read`/`write`/`mknod` futures resolve synchronously (VecDeque + atomics),
/// so a single poll to completion is enough.
fn fifo_poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn noop(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VT)
    }
    static VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: no-op vtable over a null data pointer — trivially valid.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VT)) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` outlives this block and is never moved after pinning.
    let fut = unsafe { core::pin::Pin::new_unchecked(&mut fut) };
    match fut.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// `mkfifo`/`mknod(S_IFIFO)` on tmpfs must create a real FIFO inode that
/// `stat`s as `FileType::Fifo` (S_IFIFO), NOT a regular file. A fresh mknod on
/// a not-yet-existing path must SUCCEED — this is the systemd
/// `systemd-initctl.socket` "Failed to open FIFO '/run/initctl': File exists"
/// regression (the FIFO was previously created as a plain file, so the later
/// open-as-FIFO mismatched).
fn smoke_filesystem_fifo_mknod_stat() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, FileType, MemFs, MountPoint};
    use narf_capabilities::{Cap, Grant};

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let fs = MemFs::with_seeds("test-fifo-mknod", &[]);
    let mount_handle = match registry().mount(&auth, "/test_fifo_mknod", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("memfs mount failed"),
    };

    // Fresh mknod(S_IFIFO) on a non-existent path SUCCEEDS.
    let created = registry().resolve_parent_absolute("/test_fifo_mknod/f", |_fs, parent, leaf| {
        fifo_poll_once(parent.mknod(leaf, FileType::Fifo, 0))
    });
    if !matches!(created, Some(Some(Ok(_)))) {
        let _ = registry().unmount(&mount_handle, "/test_fifo_mknod");
        return TestResult::Fail("fresh mknod(S_IFIFO) did not succeed");
    }

    // stat() reports S_IFIFO, not S_IFREG.
    let is_fifo = registry().resolve_absolute("/test_fifo_mknod/f", |fs, rel| {
        crate::resolve(fs.root(), rel)
            .map(|f| f.stat().mode.file_type == FileType::Fifo)
            .unwrap_or(false)
    });

    let _ = registry().unmount(&mount_handle, "/test_fifo_mknod");
    if is_fifo != Some(true) {
        return TestResult::Fail("FIFO path did not stat as S_IFIFO");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_filesystem_fifo_mknod_stat);

/// systemd `systemd-initctl.socket` full "File exists" regression. systemd's
/// `fifo_address_create()` `mkfifo`s `/run/initctl`, tolerates EEXIST if the
/// node is already there, then `open()`s + `fstat()`s it and REQUIRES
/// `S_ISFIFO(st_mode)`. So a re-`mknod(S_IFIFO)` on an existing FIFO must
/// report the "already exists" error (the syscall layer's -EEXIST) WITHOUT
/// clobbering the node, and the path must still `stat` as a FIFO — else
/// systemd surfaces the tolerated EEXIST as a fatal "Failed to listen".
fn smoke_filesystem_fifo_mknod_eexist_keeps_fifo() -> TestResult {
    use crate::{
        bootstrap_mount_authority, registry, FileOps, FileType, FsError, MemFs, MountPoint,
    };
    use narf_capabilities::{Cap, Grant};

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let fs = MemFs::with_seeds("test-fifo-eexist", &[]);
    let mount_handle = match registry().mount(&auth, "/test_fifo_eexist", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("memfs mount failed"),
    };

    let finish = |r: TestResult| {
        let _ = registry().unmount(&mount_handle, "/test_fifo_eexist");
        r
    };

    // First mknod(S_IFIFO) creates the node.
    let created = registry()
        .resolve_parent_absolute("/test_fifo_eexist/initctl", |_fs, parent, leaf| {
            fifo_poll_once(parent.mknod(leaf, FileType::Fifo, 0))
        });
    if !matches!(created, Some(Some(Ok(_)))) {
        return finish(TestResult::Fail("fresh mknod(S_IFIFO) did not succeed"));
    }

    // A SECOND mknod on the same path must fail "already exists" — memfs
    // reports `Busy`, which the syscall layer maps to -EEXIST — and must NOT
    // replace the FIFO with a fresh node.
    let again = registry()
        .resolve_parent_absolute("/test_fifo_eexist/initctl", |_fs, parent, leaf| {
            fifo_poll_once(parent.mknod(leaf, FileType::Fifo, 0))
        });
    if !matches!(again, Some(Some(Err(FsError::Busy)))) {
        return finish(TestResult::Fail(
            "re-mknod of existing FIFO did not report EEXIST",
        ));
    }

    // After the tolerated EEXIST the path must still stat as a FIFO so
    // systemd's `S_ISFIFO(st_mode)` check passes and it opens the fd.
    let is_fifo = registry().resolve_absolute("/test_fifo_eexist/initctl", |fs, rel| {
        crate::resolve(fs.root(), rel)
            .map(|f| f.stat().mode.file_type == FileType::Fifo)
            .unwrap_or(false)
    });
    if is_fifo != Some(true) {
        return finish(TestResult::Fail(
            "FIFO path did not stat as S_IFIFO after EEXIST",
        ));
    }

    // The open systemd does is O_RDWR|O_NONBLOCK: a read+write handle pair on
    // the shared buffer must be usable without blocking (both directions
    // rendezvous on one node).
    let shared = registry().resolve_absolute("/test_fifo_eexist/initctl", |fs, rel| {
        crate::resolve(fs.root(), rel)
            .ok()
            .and_then(|f| f.fifo_shared())
    });
    let shared = match shared {
        Some(Some(s)) => s,
        _ => return finish(TestResult::Fail("FIFO node did not expose a shared buffer")),
    };
    let rdwr =
        crate::fifo::FifoHandle::open(shared, 0, 0o600, 0, 0, /*r*/ true, /*w*/ true);
    let msg = b"initctl";
    if !matches!(fifo_poll_once(rdwr.write(0, msg)), Some(Ok(n)) if n == msg.len()) {
        return finish(TestResult::Fail("O_RDWR FIFO write did not complete"));
    }
    let mut buf = [0u8; 8];
    match fifo_poll_once(rdwr.read(0, &mut buf)) {
        Some(Ok(r)) if &buf[..r] == msg => finish(TestResult::Pass),
        _ => finish(TestResult::Fail("O_RDWR FIFO read-back mismatch")),
    }
}
kernel_test_in!("filesystem", smoke_filesystem_fifo_mknod_eexist_keeps_fifo);

/// O_RDWR-style round-trip: a read/write handle pair on one shared FIFO node
/// carries bytes through the shared buffer and reads them back in order.
fn smoke_filesystem_fifo_rdwr_round_trip() -> TestResult {
    use crate::fifo::{FifoNode, FifoShared};
    use crate::FileOps;
    use alloc::sync::Arc;

    let node = FifoNode::new(0x1234, 0o666);
    let shared: Arc<FifoShared> = node.fifo_shared().expect("node exposes shared");
    // One read-capable and one write-capable handle (as O_RDWR would give,
    // modelled here as a reader handle + a writer handle over one buffer).
    let writer = crate::fifo::FifoHandle::open(
        shared.clone(),
        0x1234,
        0o666,
        0,
        0,
        /*r*/ false,
        /*w*/ true,
    );
    let reader = crate::fifo::FifoHandle::open(
        shared.clone(),
        0x1234,
        0o666,
        0,
        0,
        /*r*/ true,
        /*w*/ false,
    );

    let msg = b"fifo-hello";
    let n = match fifo_poll_once(writer.write(0, msg)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("FIFO write did not complete"),
    };
    if n != msg.len() {
        return TestResult::Fail("FIFO short write");
    }

    let mut buf = [0u8; 16];
    let r = match fifo_poll_once(reader.read(0, &mut buf)) {
        Some(Ok(r)) => r,
        _ => return TestResult::Fail("FIFO read did not complete"),
    };
    if r != msg.len() || &buf[..r] != msg {
        return TestResult::Fail("FIFO read-back mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_filesystem_fifo_rdwr_round_trip);

/// EOF: once the last writer handle is dropped, a reader at an empty buffer
/// reads 0 (end-of-file), and `read_should_block` reports false (don't park).
fn smoke_filesystem_fifo_eof_on_writer_close() -> TestResult {
    use crate::fifo::FifoNode;
    use crate::FileOps;
    use alloc::sync::Arc;

    let node = FifoNode::new(0x2000, 0o666);
    let shared = node.fifo_shared().expect("shared");
    let reader = crate::fifo::FifoHandle::open(shared.clone(), 0x2000, 0o666, 0, 0, true, false);
    let writer = Arc::new(crate::fifo::FifoHandle::open(
        shared.clone(),
        0x2000,
        0o666,
        0,
        0,
        false,
        true,
    ));

    // Writer open + empty buffer ⇒ the read must PARK (block), not EOF.
    if !reader.read_should_block() {
        return TestResult::Fail("empty FIFO with open writer should block");
    }

    // Drop the last writer: now an empty read is genuine EOF.
    drop(writer);
    if reader.read_should_block() {
        return TestResult::Fail("empty FIFO with no writer must not block (EOF)");
    }
    let mut buf = [0u8; 8];
    match fifo_poll_once(reader.read(0, &mut buf)) {
        Some(Ok(0)) => TestResult::Pass,
        _ => TestResult::Fail("closed-writer FIFO read did not report EOF (0)"),
    }
}
kernel_test_in!("filesystem", smoke_filesystem_fifo_eof_on_writer_close);

/// A write with NO readers left is a broken pipe (`FsError::BrokenPipe`), which
/// the syscall layer turns into SIGPIPE + -EPIPE.
fn smoke_filesystem_fifo_broken_pipe_no_readers() -> TestResult {
    use crate::fifo::FifoNode;
    use crate::{FileOps, FsError};

    let node = FifoNode::new(0x3000, 0o666);
    let shared = node.fifo_shared().expect("shared");
    // A writer with zero readers (never opened a read end).
    let writer = crate::fifo::FifoHandle::open(shared.clone(), 0x3000, 0o666, 0, 0, false, true);
    match fifo_poll_once(writer.write(0, b"x")) {
        Some(Err(FsError::BrokenPipe)) => TestResult::Pass,
        _ => TestResult::Fail("write to reader-less FIFO did not report BrokenPipe"),
    }
}
kernel_test_in!("filesystem", smoke_filesystem_fifo_broken_pipe_no_readers);

/// Peer open-count bookkeeping — the signal the syscall layer's fifo(7)
/// rendezvous reads: O_WRONLY|O_NONBLOCK with `reader_count() == 0` is
/// -ENXIO; once a reader opens (count > 0), the writer's open would proceed.
/// Handle Drop must decrement, so a closed peer stops being observable.
fn smoke_filesystem_fifo_peer_counts() -> TestResult {
    use crate::fifo::FifoNode;
    use crate::FileOps;

    let node = FifoNode::new(0x4000, 0o666);
    let shared = node.fifo_shared().expect("shared");

    // No openers yet: an O_WRONLY|O_NONBLOCK open would see no reader → ENXIO.
    if shared.reader_count() != 0 || shared.writer_count() != 0 {
        return TestResult::Fail("fresh FIFO reported nonzero open counts");
    }

    // A reader opens: now a writer's peer (reader) is present.
    let reader = crate::fifo::FifoHandle::open(shared.clone(), 0x4000, 0o666, 0, 0, true, false);
    if shared.reader_count() != 1 {
        return TestResult::Fail("reader open did not bump reader_count");
    }

    // A writer opens: the reader's peer (writer) is now present too.
    let writer = crate::fifo::FifoHandle::open(shared.clone(), 0x4000, 0o666, 0, 0, false, true);
    if shared.writer_count() != 1 {
        return TestResult::Fail("writer open did not bump writer_count");
    }

    // Dropping the writer clears the writer count (reader would then EOF).
    drop(writer);
    if shared.writer_count() != 0 {
        return TestResult::Fail("writer close did not decrement writer_count");
    }
    // Dropping the reader clears the reader count (writer would then EPIPE).
    drop(reader);
    if shared.reader_count() != 0 {
        return TestResult::Fail("reader close did not decrement reader_count");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_filesystem_fifo_peer_counts);

/// Every in-memory directory must carry a unique, stable, nonzero inode so
/// it is distinguishable from its parent. systemd's `rm_rf` refuses to
/// descend when a directory and its parent share `(st_dev, st_ino)` (its
/// "you've hit a filesystem root" guard) — and NARF reports `st_dev = 0`
/// everywhere, so a colliding `st_ino` made every `mkdir`-created temp
/// subdir look like `/` ("Attempted to remove entire root file system").
/// Regression: mkdir a nested chain and assert all inodes differ.
fn smoke_filesystem_memfs_dir_inodes_distinct() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, DirOps, MemFs, MountPoint};
    use alloc::sync::Arc;
    use narf_capabilities::{Cap, Grant};

    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VT)
        }
        static VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        // SAFETY: no-op vtable over a null data pointer — trivially valid.
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VT)) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` outlives this block and is never moved after pinning.
        let fut = unsafe { core::pin::Pin::new_unchecked(&mut fut) };
        match fut.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let fs = MemFs::with_seeds("test-dirino", &[]);
    let mount_handle = match registry().mount(&auth, "/test_dirino", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("memfs mount failed"),
    };

    // Grab the mount root, then mkdir a nested chain /a -> /a/b.
    let root: Option<Arc<dyn DirOps>> = registry()
        .resolve_absolute("/test_dirino", |fs, _rel| Some(fs.root()))
        .flatten();
    let result = (|| {
        let root = root?;
        let a = poll_once(root.mkdir("a"))?.ok()?;
        let b = poll_once(a.mkdir("b"))?.ok()?;
        Some((root.ino(), a.ino(), b.ino()))
    })();

    let _ = registry().unmount(&mount_handle, "/test_dirino");

    let (root_ino, ia, ib) = match result {
        Some(t) => t,
        None => return TestResult::Fail("mkdir chain on memfs failed"),
    };
    if root_ino == 0 || ia == 0 || ib == 0 {
        return TestResult::Fail("a MemFs directory reported inode 0");
    }
    if root_ino == ia || root_ino == ib || ia == ib {
        return TestResult::Fail("MemFs directory inodes collided (parent==child)");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_filesystem_memfs_dir_inodes_distinct);

fn smoke_filesystem_devfs_null_zero() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, DevFs};
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
        fn raw_waker() -> RawWaker {
            unsafe fn no_clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            unsafe fn no_op(_: *const ()) {}
            const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
            RawWaker::new(core::ptr::null(), &VTAB)
        }
        // SAFETY: raw_waker() returns a vtable whose no-op/no-clone fns are sound for a
        // single-threaded test poll; the RawWaker is not used after this scope.
        // SAFETY: Valid memory or trusted environment
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` is a local mut binding that outlives this block; we do not move it.
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        match pinned.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    let auth = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/dev", DevFs::new());

    // /dev/null: read returns 0; write returns the requested length.
    let null_ops = registry()
        .resolve_absolute("/dev/null", |fs, rel| crate::resolve(fs.root(), rel).ok())
        .flatten();
    let null_ops = match null_ops {
        Some(o) => o,
        None => return TestResult::Fail("resolve /dev/null failed"),
    };
    let mut buf = [0xAAu8; 8];
    let r = poll_once(null_ops.read(0, &mut buf));
    if !matches!(r, Some(Ok(0))) {
        return TestResult::Fail("/dev/null read != 0");
    }
    // Write succeeds and returns the byte count.
    let w = poll_once(null_ops.write(0, b"discarded payload"));
    if !matches!(w, Some(Ok(n)) if n == 17) {
        return TestResult::Fail("/dev/null write did not consume all bytes");
    }

    // /dev/zero: read fills with zeros + returns the requested length.
    let zero_ops = registry()
        .resolve_absolute("/dev/zero", |fs, rel| crate::resolve(fs.root(), rel).ok())
        .flatten();
    let zero_ops = match zero_ops {
        Some(o) => o,
        None => return TestResult::Fail("resolve /dev/zero failed"),
    };
    let mut zbuf = [0xFFu8; 16];
    let r = poll_once(zero_ops.read(0, &mut zbuf));
    if !matches!(r, Some(Ok(n)) if n == 16) {
        return TestResult::Fail("/dev/zero read != 16");
    }
    if zbuf.iter().any(|&b| b != 0) {
        return TestResult::Fail("/dev/zero did not zero-fill");
    }

    // stat reports Special.
    use crate::FileType;
    if null_ops.stat().mode.file_type != FileType::Special {
        return TestResult::Fail("/dev/null stat is not Special");
    }
    if zero_ops.stat().mode.file_type != FileType::Special {
        return TestResult::Fail("/dev/zero stat is not Special");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_filesystem_devfs_null_zero);

fn smoke_filesystem_devfs_random_urandom() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, DevFs};
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
        fn raw_waker() -> RawWaker {
            unsafe fn no_clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            unsafe fn no_op(_: *const ()) {}
            const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
            RawWaker::new(core::ptr::null(), &VTAB)
        }
        // SAFETY: raw_waker() returns a vtable whose no-op/no-clone fns are sound for a
        // single-threaded test poll; the RawWaker is not used after this scope.
        // SAFETY: Valid memory or trusted environment
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` is a local mut binding that outlives this block; we do not move it.
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        match pinned.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    let auth = bootstrap_mount_authority();
    crate::csprng::init_csprng();
    let _ = registry().mount(&auth, "/dev", DevFs::new());

    // Each of /dev/random and /dev/urandom must (a) succeed reading
    // 16 bytes and (b) produce a not-all-zero buffer.
    for path in ["/dev/random", "/dev/urandom"] {
        let ops = registry()
            .resolve_absolute(path, |fs, rel| crate::resolve(fs.root(), rel).ok())
            .flatten();
        let ops = match ops {
            Some(o) => o,
            None => return TestResult::Fail("resolve dev rng failed"),
        };
        let mut buf = [0u8; 16];
        let r = poll_once(ops.read(0, &mut buf));
        if !matches!(r, Some(Ok(n)) if n == 16) {
            return TestResult::Fail("rng read != 16");
        }
        if buf.iter().all(|&b| b == 0) {
            return TestResult::Fail("rng buffer is all zeros");
        }
    }

    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_filesystem_devfs_random_urandom);

fn smoke_filesystem_devfs_console_keystrokes() -> TestResult {
    // Push a sequence of `KeyEvent`s onto `narf_input`'s global ring,
    // then read `/dev/console` and verify each press surfaces as the
    // expected ASCII byte. Exercises the full keyboard-→-VFS path
    // without depending on a live xHCI controller.
    use crate::{bootstrap_mount_authority, registry, DevFs};
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use narf_input::{init_global_ring, push_global, InputEvent, KeyCode, KeyEvent, Modifiers};

    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
        fn raw_waker() -> RawWaker {
            unsafe fn no_clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            unsafe fn no_op(_: *const ()) {}
            const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
            RawWaker::new(core::ptr::null(), &VTAB)
        }
        // SAFETY: raw_waker() returns a vtable whose no-op/no-clone fns are sound for a
        // single-threaded test poll; the RawWaker is not used after this scope.
        // SAFETY: Valid memory or trusted environment
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` is a local mut binding that outlives this block; we do not move it.
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        match pinned.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    // Make sure the ring exists. Idempotent — production code lights
    // it up at boot via `narf_input::register_initcalls`.
    init_global_ring(64);

    // Drain anything previously queued (other smokes / boot-time
    // events) so the assert below sees only what we push here.
    while narf_input::pop_global().is_some() {}

    // The console line discipline is process-global; reset it to a clean
    // cooked state so a prior test's leftover partial line / raw-mode
    // termios can't perturb this canonical-mode assertion.
    crate::console_tty::__test_reset_cooked();

    let auth = bootstrap_mount_authority();
    // /dev may already be mounted by an earlier smoke; mount_default
    // returns Busy in that case and we ignore — the existing mount
    // is what we want.
    let _ = registry().mount(&auth, "/dev/console-test-mount", DevFs::new());
    let console = registry()
        .resolve_absolute("/dev/console-test-mount/console", |fs, rel| {
            crate::resolve(fs.root(), rel).ok()
        })
        .flatten();
    let console = match console {
        Some(c) => c,
        None => return TestResult::Fail("resolve /dev/console failed"),
    };

    // Push: 'h', 'I' (shift held), '1', '\n', release of 'h'.
    let mods_none = Modifiers::EMPTY;
    let mods_shift = Modifiers::SHIFT;
    push_global(InputEvent::Key(KeyEvent {
        code: KeyCode::H,
        pressed: true,
        modifiers: mods_none,
    }));
    push_global(InputEvent::Key(KeyEvent {
        code: KeyCode::I,
        pressed: true,
        modifiers: mods_shift,
    }));
    push_global(InputEvent::Key(KeyEvent {
        code: KeyCode::Key1,
        pressed: true,
        modifiers: mods_none,
    }));
    push_global(InputEvent::Key(KeyEvent {
        code: KeyCode::Enter,
        pressed: true,
        modifiers: mods_none,
    }));
    push_global(InputEvent::Key(KeyEvent {
        code: KeyCode::H,
        pressed: false,
        modifiers: mods_none,
    }));

    let mut buf = [0u8; 16];
    let n = match poll_once(console.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("/dev/console read returned Pending or Err"),
    };
    if n != 4 {
        return TestResult::Fail("expected 4 translated bytes (h, I, 1, \\n)");
    }
    if &buf[..n] != b"hI1\n" {
        return TestResult::Fail("translation produced unexpected bytes");
    }

    // Second read with empty ring returns 0 (non-blocking).
    let mut buf = [0u8; 4];
    let n = match poll_once(console.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("second /dev/console read returned Pending or Err"),
    };
    if n != 0 {
        return TestResult::Fail("empty ring should return 0 bytes");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_filesystem_devfs_console_keystrokes);

fn smoke_filesystem_devfs_mount_default_idempotent() -> TestResult {
    use crate::{mount_devfs_default, registry};

    // Mount via the boot helper. Twice — second call should be a
    // benign no-op (Busy-error swallowed internally).
    mount_devfs_default();
    mount_devfs_default();

    // /dev is reachable: resolve_absolute against /dev/null finds
    // a DirOps lookup hit.
    let ops = registry()
        .resolve_absolute("/dev/null", |fs, rel| crate::resolve(fs.root(), rel).ok())
        .flatten();
    if ops.is_none() {
        return TestResult::Fail("mount_default did not mount /dev");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem",
    smoke_filesystem_devfs_mount_default_idempotent
);

// ── extended filesystem coverage ───────────────────────────────────
//
// Existing surface hits the initramfs + memfs + devfs happy paths
// and one mount-prefix scenario. New smokes close invariants on:
//   - `posix_access_ok` permission algebra
//   - sync `resolve` path-shape validation
//   - PageCache edges (missing key, idempotent drain, generation bump)
//   - VfsRegistry mount/unmount round-trip
//   - Mode constants
//   - error-discriminant distinctness

fn smoke_fs_posix_access_root_bypass() -> TestResult {
    use crate::{AccessRequest, Accessor, FileOwner};
    let check = |fu, fg, fp, au, ag, r, w, x| {
        crate::posix_access_ok(
            FileOwner {
                uid: fu,
                gid: fg,
                perms: fp,
            },
            Accessor { uid: au, gid: ag },
            AccessRequest {
                read: r,
                write: w,
                exec: x,
            },
        )
    };
    // Root reads + writes anything regardless of perms (POSIX privileged-process rule).
    if !check(1000, 1000, 0o000, 0, 0, true, true, false) {
        return TestResult::Fail("root denied read on perms=000");
    }
    if !check(1000, 1000, 0o000, 0, 0, false, true, false) {
        return TestResult::Fail("root denied write on perms=000");
    }
    // Root exec requires at least one exec bit somewhere.
    if check(1000, 1000, 0o644, 0, 0, false, false, true) {
        return TestResult::Fail("root got exec on perms=644 (no x bit anywhere)");
    }
    if !check(1000, 1000, 0o755, 0, 0, false, false, true) {
        return TestResult::Fail("root denied exec on perms=755");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_posix_access_root_bypass);

fn smoke_fs_posix_access_owner_group_other() -> TestResult {
    use crate::{AccessRequest, Accessor, FileOwner};
    let check = |fu, fg, fp, au, ag, r, w, x| {
        crate::posix_access_ok(
            FileOwner {
                uid: fu,
                gid: fg,
                perms: fp,
            },
            Accessor { uid: au, gid: ag },
            AccessRequest {
                read: r,
                write: w,
                exec: x,
            },
        )
    };
    // File owned by 1000:2000 with perms=0o640 (owner rw-, group r--, other ---).
    // Owner (uid=1000): can read + write, can't exec.
    if !check(1000, 2000, 0o640, 1000, 0, true, true, false) {
        return TestResult::Fail("owner denied legitimate rw");
    }
    if check(1000, 2000, 0o640, 1000, 0, false, false, true) {
        return TestResult::Fail("owner got exec when perms had no x");
    }
    // Group member (gid=2000 but uid != owner): can read, can't write.
    if !check(1000, 2000, 0o640, 1001, 2000, true, false, false) {
        return TestResult::Fail("group member denied read");
    }
    if check(1000, 2000, 0o640, 1001, 2000, false, true, false) {
        return TestResult::Fail("group member got write when group bits forbade it");
    }
    // Other (different uid + gid): no access at all.
    if check(1000, 2000, 0o640, 1001, 2001, true, false, false) {
        return TestResult::Fail("other got read on perms=640 (other=---)");
    }
    // Other with perms=0o644 → other can read but not write.
    if !check(1000, 2000, 0o644, 1001, 2001, true, false, false) {
        return TestResult::Fail("other denied read on perms=644");
    }
    if check(1000, 2000, 0o644, 1001, 2001, false, true, false) {
        return TestResult::Fail("other got write on perms=644");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_posix_access_owner_group_other);

fn smoke_fs_resolve_rejects_empty_path() -> TestResult {
    // resolve() rejects empty paths with InvalidPath.
    use crate::{resolve, DirEntry, DirOps, FileOps, FsError};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    struct EmptyDir;
    impl DirOps for EmptyDir {
        fn lookup(&self, _: &str) -> Option<Arc<dyn FileOps>> {
            None
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    match resolve(Arc::new(EmptyDir), "") {
        Err(FsError::InvalidPath) => TestResult::Pass,
        _ => TestResult::Fail("empty path didn't surface InvalidPath"),
    }
}
kernel_test_in!("filesystem", smoke_fs_resolve_rejects_empty_path);

fn smoke_fs_resolve_rejects_absolute_path() -> TestResult {
    // resolve() is for RELATIVE paths — leading `/` must be rejected.
    use crate::{resolve, DirEntry, DirOps, FileOps, FsError};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    struct EmptyDir;
    impl DirOps for EmptyDir {
        fn lookup(&self, _: &str) -> Option<Arc<dyn FileOps>> {
            None
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    match resolve(Arc::new(EmptyDir), "/foo") {
        Err(FsError::InvalidPath) => TestResult::Pass,
        _ => TestResult::Fail("absolute path didn't surface InvalidPath"),
    }
}
kernel_test_in!("filesystem", smoke_fs_resolve_rejects_absolute_path);

fn smoke_fs_resolve_rejects_dot_dot() -> TestResult {
    // sync resolve() doesn't support `..` — must surface InvalidPath
    // rather than walking off the mount.
    use crate::{resolve, DirEntry, DirOps, FileOps, FsError};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    struct EmptyDir;
    impl DirOps for EmptyDir {
        fn lookup(&self, _: &str) -> Option<Arc<dyn FileOps>> {
            None
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    match resolve(Arc::new(EmptyDir), "foo/../bar") {
        Err(FsError::InvalidPath) => TestResult::Pass,
        _ => TestResult::Fail(".. didn't surface InvalidPath"),
    }
}
kernel_test_in!("filesystem", smoke_fs_resolve_rejects_dot_dot);

fn smoke_fs_resolve_tolerates_redundant_separators_and_dot() -> TestResult {
    // `//` and `.` segments are tolerated and skipped. Confirm that
    // `foo` and `.//foo` resolve to the same node by stub instrumentation.
    use crate::{resolve, DirEntry, DirOps, FileOps, FsFuture, Mode, Stat};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};

    static LOOKUPS: AtomicU32 = AtomicU32::new(0);
    LOOKUPS.store(0, Ordering::Relaxed);

    struct StubFile;
    impl FileOps for StubFile {
        fn read<'a>(&'a self, _: u64, _: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async { Ok(0) })
        }
        fn write<'a>(&'a self, _: u64, _: &'a [u8]) -> FsFuture<'a, usize> {
            Box::pin(async { Ok(0) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
    }
    struct StubDir;
    impl DirOps for StubDir {
        fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
            if name == "foo" {
                LOOKUPS.fetch_add(1, Ordering::Relaxed);
                Some(Arc::new(StubFile))
            } else {
                None
            }
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    if resolve(Arc::new(StubDir), "foo").is_err() {
        return TestResult::Fail("plain foo didn't resolve");
    }
    if resolve(Arc::new(StubDir), "./foo").is_err() {
        return TestResult::Fail("./foo didn't resolve");
    }
    if resolve(Arc::new(StubDir), ".//foo").is_err() {
        return TestResult::Fail(".//foo didn't resolve");
    }
    if LOOKUPS.load(Ordering::Relaxed) != 3 {
        return TestResult::Fail("expected exactly 3 lookups across the three resolutions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem",
    smoke_fs_resolve_tolerates_redundant_separators_and_dot
);

fn smoke_fs_page_cache_lookup_missing_is_none() -> TestResult {
    use crate::{PageCache, PageKey};
    let pc = PageCache::new();
    let k = PageKey {
        fs_id: 99,
        inode: 99,
        page_off: 99,
    };
    if pc.lookup(k).is_some() {
        return TestResult::Fail("lookup on absent key returned Some");
    }
    if !pc.is_empty() {
        return TestResult::Fail("fresh cache reported non-empty");
    }
    if pc.mark_dirty(k) {
        return TestResult::Fail("mark_dirty on absent key returned true");
    }
    if !pc.drain_dirty().is_empty() {
        return TestResult::Fail("drain_dirty on empty cache returned entries");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_page_cache_lookup_missing_is_none);

fn smoke_fs_page_cache_generation_bumps_on_dirty() -> TestResult {
    // mark_dirty bumps the generation counter — readers use this
    // to detect they raced against a writer.
    use crate::{Page, PageCache, PageKey};
    let pc = PageCache::new();
    let k = PageKey {
        fs_id: 1,
        inode: 1,
        page_off: 0,
    };
    pc.insert(k, Page::zeroed());
    let g0 = pc.lookup(k).unwrap().gen;
    pc.mark_dirty(k);
    let g1 = pc.lookup(k).unwrap().gen;
    if g1 != g0 + 1 {
        return TestResult::Fail("generation didn't bump by 1 on first dirty");
    }
    // drain_dirty clears `dirty` but does NOT reset the generation.
    let drained = pc.drain_dirty();
    if drained.len() != 1 || !drained[0].1.dirty {
        return TestResult::Fail("drained page shape wrong");
    }
    let g2 = pc.lookup(k).unwrap().gen;
    if g2 != g1 {
        return TestResult::Fail("drain_dirty altered generation");
    }
    // Re-mark dirty → bumps again.
    pc.mark_dirty(k);
    let g3 = pc.lookup(k).unwrap().gen;
    if g3 != g1 + 1 {
        return TestResult::Fail("second mark_dirty didn't bump generation");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_page_cache_generation_bumps_on_dirty);

fn smoke_fs_page_cache_insert_overwrites() -> TestResult {
    // Insert replaces in place — second insert with same key wins.
    use crate::{Page, PageCache, PageKey};
    let pc = PageCache::new();
    let k = PageKey {
        fs_id: 1,
        inode: 1,
        page_off: 0,
    };
    pc.insert(k, Page::zeroed());
    if pc.len() != 1 {
        return TestResult::Fail("first insert didn't grow to 1");
    }
    let mut p2 = Page::zeroed();
    p2.gen = 42;
    pc.insert(k, p2);
    if pc.len() != 1 {
        return TestResult::Fail("second insert grew length (should overwrite in place)");
    }
    let got = pc.lookup(k).unwrap();
    if got.gen != 42 {
        return TestResult::Fail("second insert didn't replace value");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_page_cache_insert_overwrites);

fn smoke_fs_mode_constants_match_perms() -> TestResult {
    use crate::{FileType, Mode};
    if Mode::FILE_RO.file_type != FileType::File || Mode::FILE_RO.perms != 0o444 {
        return TestResult::Fail("FILE_RO drifted");
    }
    if Mode::FILE_RW.file_type != FileType::File || Mode::FILE_RW.perms != 0o666 {
        return TestResult::Fail("FILE_RW drifted");
    }
    if Mode::DIR_RO.file_type != FileType::Dir || Mode::DIR_RO.perms != 0o555 {
        return TestResult::Fail("DIR_RO drifted");
    }
    if Mode::DIR_RW.file_type != FileType::Dir || Mode::DIR_RW.perms != 0o777 {
        return TestResult::Fail("DIR_RW drifted");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_mode_constants_match_perms);

fn smoke_fs_registry_mount_unmount_round_trip() -> TestResult {
    // Mount a MemFs, observe it in list(), unmount via the handle,
    // confirm it's gone.
    use crate::{bootstrap_mount_authority, registry, MemFs};
    let auth = bootstrap_mount_authority();
    let fs = MemFs::with_seeds("rt-mu", &[("greeting", b"hi")]);
    let path = "/smoke-mu";
    let handle = match registry().mount(&auth, path, fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount failed"),
    };
    let listed = registry().list();
    if !listed.iter().any(|p| p == path) {
        return TestResult::Fail("mount didn't show up in registry.list()");
    }
    if registry().unmount(&handle, path).is_err() {
        return TestResult::Fail("unmount failed with a live handle");
    }
    let listed_after = registry().list();
    if listed_after.iter().any(|p| p == path) {
        return TestResult::Fail("mount still in registry after unmount");
    }
    // Second unmount on same path → NotFound.
    match registry().unmount(&handle, path) {
        Err(crate::FsError::NotFound) => TestResult::Pass,
        _ => TestResult::Fail("double unmount didn't surface NotFound"),
    }
}
kernel_test_in!("filesystem", smoke_fs_registry_mount_unmount_round_trip);

fn smoke_fs_registry_unmount_revoked_handle_rejected() -> TestResult {
    // A revoked handle must not be able to unmount, regardless of
    // path validity.
    use crate::{bootstrap_mount_authority, registry, FsError, MemFs};
    let auth = bootstrap_mount_authority();
    let fs = MemFs::with_seeds("rt-rev", &[("x", b"y")]);
    let path = "/smoke-rev-mu";
    let handle = match registry().mount(&auth, path, fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount failed"),
    };
    handle.revoke();
    match registry().unmount(&handle, path) {
        Err(FsError::PermissionDenied) => {
            // Restore so subsequent tests aren't sitting on a corpse:
            // mount a fresh handle to clean up.
            let auth2 = bootstrap_mount_authority();
            let h2 = registry()
                .mount(&auth2, "/smoke-rev-cleanup", MemFs::with_seeds("c", &[]))
                .ok();
            // Remove the original entry now that we have a fresh handle —
            // but we can't unmount the revoked one. Leave it; tests are
            // additive and the suite tolerates registry residue.
            let _ = h2;
            TestResult::Pass
        }
        _ => TestResult::Fail("revoked handle accepted unmount"),
    }
}
kernel_test_in!(
    "filesystem",
    smoke_fs_registry_unmount_revoked_handle_rejected
);

fn smoke_fs_error_variants_distinct() -> TestResult {
    use crate::FsError;
    let all = [
        FsError::NotFound,
        FsError::PermissionDenied,
        FsError::InvalidPath,
        FsError::Busy,
        FsError::ReadOnly,
        FsError::NoSpace,
        FsError::Unsupported,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("two FsError variants compared equal");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_error_variants_distinct);

fn smoke_fs_filetype_variants_distinct() -> TestResult {
    use crate::FileType;
    let all = [
        FileType::File,
        FileType::Dir,
        FileType::Symlink,
        FileType::Special,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("two FileType variants compared equal");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_filetype_variants_distinct);

// ── filesystem/root_mount ──────────────────────────────────────────

fn smoke_fs_root_mount_factory_register_lookup() -> TestResult {
    use crate::root_mount::{__reset_for_test, factory_count, lookup_factory, register_fs_factory};
    use narf_block::fs_detect::FsType;
    __reset_for_test();
    if factory_count() != 0 {
        return TestResult::Fail("fresh registry must be empty");
    }
    fn dummy_ext_factory(
        _dev: alloc::sync::Arc<dyn narf_block::BlockDeviceSync>,
    ) -> Result<alloc::sync::Arc<dyn crate::FsInstance>, crate::FsError> {
        Err(crate::FsError::PermissionDenied)
    }
    register_fs_factory(FsType::Ext, dummy_ext_factory);
    if factory_count() != 1 {
        return TestResult::Fail("post-register count must be 1");
    }
    if lookup_factory(FsType::Ext).is_none() {
        return TestResult::Fail("ext factory not found");
    }
    if lookup_factory(FsType::Fat).is_some() {
        return TestResult::Fail("fat factory must not be present");
    }
    // Re-register replaces in place.
    register_fs_factory(FsType::Ext, dummy_ext_factory);
    if factory_count() != 1 {
        return TestResult::Fail("re-register must not duplicate");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/root_mount",
    smoke_fs_root_mount_factory_register_lookup
);

fn smoke_fs_root_mount_walker_yields_no_mountable_on_empty_registry() -> TestResult {
    use crate::root_mount::{try_mount_root, RootMountError, __reset_for_test};
    use crate::MountPoint;
    use narf_capabilities::{Cap, Grant};
    __reset_for_test();
    // No FS factories registered → walker can't find a mount even
    // if block devices have known FS magic.
    let auth: Cap<MountPoint, Grant> = Cap::bootstrap();
    match try_mount_root(&auth) {
        Err(RootMountError::NoFactory(_)) | Err(RootMountError::NoMountable) => TestResult::Pass,
        Ok(_) => TestResult::Fail("no factories must NOT yield a mount"),
        Err(other) => {
            let _ = other;
            TestResult::Fail("wrong error variant")
        }
    }
}
kernel_test_in!(
    "filesystem/root_mount",
    smoke_fs_root_mount_walker_yields_no_mountable_on_empty_registry
);

// ── filesystem/root_selector ───────────────────────────────────────

fn smoke_root_selector_parses_dev_path() -> TestResult {
    use crate::root_selector::RootSelector;
    match RootSelector::from_cmdline("quiet root=/dev/nvme0p1 init=/sbin/init") {
        Some(RootSelector::ByName(name)) if name == "nvme0p1" => TestResult::Pass,
        _ => TestResult::Fail("root=/dev/nvme0p1 must yield ByName(\"nvme0p1\")"),
    }
}
kernel_test_in!(
    "filesystem/root_selector",
    smoke_root_selector_parses_dev_path
);

fn smoke_root_selector_parses_bare_name() -> TestResult {
    use crate::root_selector::RootSelector;
    // Without /dev/ prefix — should also work.
    match RootSelector::from_cmdline("root=usb-msc0p1") {
        Some(RootSelector::ByName(name)) if name == "usb-msc0p1" => TestResult::Pass,
        _ => TestResult::Fail("bare name root= must yield ByName"),
    }
}
kernel_test_in!(
    "filesystem/root_selector",
    smoke_root_selector_parses_bare_name
);

fn smoke_root_selector_parses_partlabel() -> TestResult {
    use crate::root_selector::RootSelector;
    match RootSelector::from_cmdline("root=PARTLABEL=NARF_ROOT") {
        Some(RootSelector::ByPartLabel(label)) if label == "NARF_ROOT" => TestResult::Pass,
        _ => TestResult::Fail("PARTLABEL not parsed"),
    }
}
kernel_test_in!(
    "filesystem/root_selector",
    smoke_root_selector_parses_partlabel
);

fn smoke_root_selector_parses_uuid_variants() -> TestResult {
    use crate::root_selector::RootSelector;
    let uuid = "12345678-1234-1234-1234-123456789ABC";
    let p = alloc::format!("root=PARTUUID={}", uuid);
    match RootSelector::from_cmdline(&p) {
        Some(RootSelector::ByPartUuid(u)) if u == uuid => {}
        _ => return TestResult::Fail("PARTUUID not parsed"),
    }
    let f = alloc::format!("root=UUID={}", uuid);
    match RootSelector::from_cmdline(&f) {
        Some(RootSelector::ByFsUuid(u)) if u == uuid => TestResult::Pass,
        _ => TestResult::Fail("UUID not parsed"),
    }
}
kernel_test_in!(
    "filesystem/root_selector",
    smoke_root_selector_parses_uuid_variants
);

fn smoke_root_selector_returns_none_when_absent() -> TestResult {
    use crate::root_selector::RootSelector;
    match RootSelector::from_cmdline("quiet noapic init=/init") {
        None => TestResult::Pass,
        _ => TestResult::Fail("absent root= must yield None"),
    }
}
kernel_test_in!(
    "filesystem/root_selector",
    smoke_root_selector_returns_none_when_absent
);

fn smoke_root_selector_first_root_wins() -> TestResult {
    use crate::root_selector::RootSelector;
    // Multiple root=: parser takes the first.
    match RootSelector::from_cmdline("root=/dev/a root=/dev/b") {
        Some(RootSelector::ByName(name)) if name == "a" => TestResult::Pass,
        _ => TestResult::Fail("first root= must win"),
    }
}
kernel_test_in!(
    "filesystem/root_selector",
    smoke_root_selector_first_root_wins
);

fn smoke_root_mount_selector_no_match_refuses() -> TestResult {
    use crate::root_mount::{try_mount_root_with, RootMountError, __reset_for_test};
    use crate::root_selector::RootSelector;
    use crate::MountPoint;
    use narf_capabilities::{Cap, Grant};
    __reset_for_test();
    let auth: Cap<MountPoint, Grant> = Cap::bootstrap();
    // No registered block device named "doesnt-exist" — walker
    // must refuse rather than fall through to a different device.
    let sel = RootSelector::ByName(alloc::string::String::from("doesnt-exist-p1"));
    match try_mount_root_with(&auth, Some(&sel)) {
        Err(RootMountError::SelectorNoMatch) | Err(RootMountError::NoMountable) => TestResult::Pass,
        _ => TestResult::Fail("name-only selector miss must refuse"),
    }
}
kernel_test_in!(
    "filesystem/root_selector",
    smoke_root_mount_selector_no_match_refuses
);

// ── /dev/input smoke tests ─────────────────────────────────────────────────────
//
// All smokes prefix their ROUTER-registered devices with a comment so
// readers know which global state they touch.  Each test unregisters its
// device before returning.

/// Helper: poll a future exactly once, returning `None` on Pending.
fn poll_once_devfs_input<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
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
    // SAFETY: raw_waker() returns a vtable whose no-op/no-clone fns are sound for a
    // single-threaded test poll; the RawWaker is not used after this scope.
    // SAFETY: Valid memory or trusted environment
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is a local mut binding that outlives this block; we do not move it.
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// 1. DevInputDir enumerate finds event0 after a device registers.
fn smoke_dev_input_dir_enumerate_finds_event0() -> TestResult {
    use crate::devfs_input::DevInputDir;
    use crate::DirOps;
    use narf_input::evdev::{DeviceCaps, ROUTER};

    let (id, _node) = ROUTER.register_device(DeviceCaps::new());

    let dir = DevInputDir;
    let entries = dir.enumerate(0, 32);
    let found = entries.iter().any(|(name, _)| name.starts_with("event"));
    ROUTER.unregister_device(id);

    if !found {
        return TestResult::Fail("enumerate did not find any event* entry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/devfs_input",
    smoke_dev_input_dir_enumerate_finds_event0
);

/// 2. InputEventFile read with empty ring + zero-size buf → 0 bytes (non-blocking).
fn smoke_dev_input_read_zero_buf_non_blocking() -> TestResult {
    use crate::devfs_input::{DeviceKind, InputEventFile};
    use crate::FileOps;
    use narf_input::evdev::{DeviceCaps, ROUTER};

    let (id, _node) = ROUTER.register_device(DeviceCaps::new());
    let file = match InputEventFile::open(id, DeviceKind::Hardware) {
        Some(f) => f,
        None => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("open returned None for live device");
        }
    };

    let mut buf = [];
    let result = poll_once_devfs_input(file.read(0, &mut buf));
    ROUTER.unregister_device(id);

    match result {
        Some(Ok(0)) => TestResult::Pass,
        Some(Ok(n)) => {
            let _ = n;
            TestResult::Fail("empty buf read returned non-zero byte count")
        }
        Some(Err(_)) => TestResult::Fail("empty buf read returned error"),
        None => TestResult::Fail("empty buf read returned Pending"),
    }
}
kernel_test_in!(
    "filesystem/devfs_input",
    smoke_dev_input_read_zero_buf_non_blocking
);

/// 3. InputEventFile read with 1 event available → exactly one 24-byte
///    Linux `input_event`, with tv_sec/tv_usec present and type/code/value
///    unpacking to the event that was dispatched.
fn smoke_dev_input_read_one_event_correct_layout() -> TestResult {
    use crate::devfs_input::{DeviceKind, InputEventFile, LINUX_INPUT_EVENT_SIZE};
    use crate::FileOps;
    use narf_input::evdev::key::KEY_A;
    use narf_input::evdev::{DeviceCaps, EvdevEvent, EventType, ROUTER};

    let mut caps = DeviceCaps::new();
    caps.add_key(KEY_A);
    let (id, node) = ROUTER.register_device(caps);

    // `time` is monotonic nanoseconds; the split is sec = ns / 1e9,
    // usec = (ns % 1e9) / 1000. Pick a value giving tv_sec=2, tv_usec=500.
    let now = 2_000_500_000u64;
    let sent = EvdevEvent {
        time: now,
        type_: EventType::Key,
        code: KEY_A,
        value: 1,
    };
    node.dispatch(sent);

    let file = match InputEventFile::open(id, DeviceKind::Hardware) {
        Some(f) => f,
        None => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("open returned None");
        }
    };

    let mut buf = [0u8; LINUX_INPUT_EVENT_SIZE];
    let result = poll_once_devfs_input(file.read(0, &mut buf));
    ROUTER.unregister_device(id);

    match result {
        Some(Ok(n)) if n == LINUX_INPUT_EVENT_SIZE => {}
        Some(Ok(_)) => {
            return TestResult::Fail("read did not return exactly one 24-byte record");
        }
        _ => return TestResult::Fail("read failed or returned Pending"),
    }

    // Decode the 24-byte Linux input_event: tv_sec(8) tv_usec(8) type(2)
    // code(2) value(4), all little-endian.
    let tv_sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let tv_usec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    let raw_type = u16::from_le_bytes(buf[16..18].try_into().unwrap());
    let code = u16::from_le_bytes(buf[18..20].try_into().unwrap());
    let value = i32::from_le_bytes(buf[20..24].try_into().unwrap());

    if tv_sec != 2 || tv_usec != 500 {
        return TestResult::Fail("tv_sec/tv_usec did not split the timestamp correctly");
    }
    if raw_type != EventType::Key as u16 {
        return TestResult::Fail("event type mismatch in serialised bytes");
    }
    if code != KEY_A {
        return TestResult::Fail("event code mismatch");
    }
    if value != 1 {
        return TestResult::Fail("event value mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/devfs_input",
    smoke_dev_input_read_one_event_correct_layout
);

/// 4. InputEventFile read with 5 events available and a 10-event buffer →
///    exactly 5 events returned in one call.
fn smoke_dev_input_read_five_events_in_one_call() -> TestResult {
    use crate::devfs_input::{DeviceKind, InputEventFile, LINUX_INPUT_EVENT_SIZE};
    use crate::FileOps;
    use narf_input::evdev::key::KEY_A;
    use narf_input::evdev::{DeviceCaps, EvdevEvent, EventType, ROUTER};

    let mut caps = DeviceCaps::new();
    caps.add_key(KEY_A);
    let (id, node) = ROUTER.register_device(caps);

    let now = narf_time::now_cycles();
    for v in 0i32..5 {
        node.dispatch(EvdevEvent {
            time: now,
            type_: EventType::Key,
            code: KEY_A,
            value: v,
        });
    }

    let file = match InputEventFile::open(id, DeviceKind::Hardware) {
        Some(f) => f,
        None => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("open returned None");
        }
    };

    let mut buf = [0u8; LINUX_INPUT_EVENT_SIZE * 10];
    let result = poll_once_devfs_input(file.read(0, &mut buf));
    ROUTER.unregister_device(id);

    match result {
        Some(Ok(n)) if n == LINUX_INPUT_EVENT_SIZE * 5 => TestResult::Pass,
        Some(Ok(_)) => TestResult::Fail("read returned wrong byte count for 5 events"),
        _ => TestResult::Fail("read failed or returned Pending"),
    }
}
kernel_test_in!(
    "filesystem/devfs_input",
    smoke_dev_input_read_five_events_in_one_call
);

/// 5. Write to hardware device → PermissionDenied.
fn smoke_dev_input_write_hardware_denied() -> TestResult {
    use crate::devfs_input::{DeviceKind, InputEventFile};
    use crate::{FileOps, FsError};
    use narf_input::evdev::{DeviceCaps, ROUTER};

    let (id, _node) = ROUTER.register_device(DeviceCaps::new());
    let file = match InputEventFile::open(id, DeviceKind::Hardware) {
        Some(f) => f,
        None => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("open returned None");
        }
    };

    // Attempt to write one 24-byte Linux input_event of zeros.
    let payload = [0u8; crate::devfs_input::LINUX_INPUT_EVENT_SIZE];
    let result = poll_once_devfs_input(file.write(0, &payload));
    ROUTER.unregister_device(id);

    match result {
        Some(Err(FsError::PermissionDenied)) => TestResult::Pass,
        Some(Err(_)) => TestResult::Fail("wrong error variant for hardware write"),
        Some(Ok(_)) => TestResult::Fail("hardware write unexpectedly succeeded"),
        None => TestResult::Fail("hardware write returned Pending"),
    }
}
kernel_test_in!(
    "filesystem/devfs_input",
    smoke_dev_input_write_hardware_denied
);

/// 6. Write to UserDevice → event injected; reader sees it round-trip.
fn smoke_dev_input_write_uinput_injects_event() -> TestResult {
    use crate::devfs_input::{DeviceKind, InputEventFile, LINUX_INPUT_EVENT_SIZE};
    use crate::FileOps;
    use narf_input::evdev::key::KEY_A;
    use narf_input::evdev::{DeviceCaps, EventType, ROUTER};

    let mut caps = DeviceCaps::new();
    caps.add_key(KEY_A);
    let (id, _node) = ROUTER.register_device(caps);

    let file = match InputEventFile::open(id, DeviceKind::UserDevice) {
        Some(f) => f,
        None => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("open returned None");
        }
    };

    // Build a 24-byte Linux input_event (tv_sec/tv_usec zero, EV_KEY KEY_A press).
    let mut payload = [0u8; LINUX_INPUT_EVENT_SIZE];
    payload[16..18].copy_from_slice(&(EventType::Key as u16).to_le_bytes());
    payload[18..20].copy_from_slice(&KEY_A.to_le_bytes());
    payload[20..24].copy_from_slice(&1i32.to_le_bytes());

    // Write the event via the uinput path.
    let write_result = poll_once_devfs_input(file.write(0, &payload));
    match write_result {
        Some(Ok(n)) if n == LINUX_INPUT_EVENT_SIZE => {}
        _ => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("uinput write failed or returned wrong count");
        }
    }

    // Open a reader and check the event arrived.
    let reader = match ROUTER.open_reader(id) {
        Some(r) => r,
        None => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("open_reader returned None after inject");
        }
    };
    let ev_got = reader.poll_event();
    ROUTER.unregister_device(id);

    match ev_got {
        Some(e) if e.type_ == EventType::Key && e.code == KEY_A && e.value == 1 => TestResult::Pass,
        Some(_) => TestResult::Fail("injected event had wrong fields"),
        None => TestResult::Fail("reader saw no event after uinput write"),
    }
}
kernel_test_in!(
    "filesystem/devfs_input",
    smoke_dev_input_write_uinput_injects_event
);

/// 7. `/dev/input/event0` open by path resolves through DevDir → InputEventFile.
fn smoke_dev_input_open_by_path() -> TestResult {
    use crate::{bootstrap_mount_authority, registry, DevFs, FileType};
    use narf_input::evdev::{DeviceCaps, ROUTER};

    let (id, _node) = ROUTER.register_device(DeviceCaps::new());
    let event_num = id.0 - 1;

    let auth = bootstrap_mount_authority();
    // Mount at a test-local path to avoid colliding with earlier smokes.
    let _ = registry().mount(&auth, "/dev", DevFs::new());

    // Build the path "/dev/input/eventN" for the device we just registered.
    let abs_path = alloc::format!("/dev/input/event{}", event_num);
    let result =
        registry().resolve_absolute(&abs_path, |fs, rel| crate::resolve(fs.root(), rel).ok());

    ROUTER.unregister_device(id);

    match result {
        Some(Some(file_ops)) => {
            // Confirm stat returns FileType::Special.
            if file_ops.stat().mode.file_type != FileType::Special {
                return TestResult::Fail("event file stat is not Special");
            }
            TestResult::Pass
        }
        Some(None) => TestResult::Fail("resolve returned None for event file"),
        None => TestResult::Fail("resolve_absolute did not find /dev mount"),
    }
}
kernel_test_in!("filesystem/devfs_input", smoke_dev_input_open_by_path);

/// 8. EVIOCGVERSION / EVIOCGBIT(EV_KEY) / EVIOCGNAME — the capability
///    ioctls evdev readers issue at startup.
///
/// The handlers copy into `arg` via `copy_to_user_bytes`, whose only
/// effect in kernel-test context is the SMAP STAC/CLAC bracket; a kernel
/// stack buffer address is a valid destination inside that window.
fn smoke_dev_input_eviocg_ioctls() -> TestResult {
    use crate::devfs_input::{DeviceKind, InputEventFile};
    use crate::FileOps;
    use narf_input::evdev::key::KEY_A;
    use narf_input::evdev::{DeviceCaps, EventType, ROUTER};

    // _IOC(dir, type, nr, size) helper mirroring the kernel macro.
    fn ioc(dir: u32, nr: u32, size: u32) -> u32 {
        (dir << 30) | (size << 16) | ((b'E' as u32) << 8) | nr
    }
    const READ: u32 = 2;

    let mut caps = DeviceCaps::new();
    caps.add_key(KEY_A);
    let (id, _node) = ROUTER.register_device(caps);

    let file = match InputEventFile::open(id, DeviceKind::Hardware) {
        Some(f) => f,
        None => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("open returned None");
        }
    };

    // EVIOCGVERSION → i32 0x010001.
    let mut ver = 0i32;
    let cmd = ioc(READ, 0x01, 4);
    match file.ioctl(cmd, &mut ver as *mut i32 as usize) {
        Ok(4) => {}
        _ => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("EVIOCGVERSION returned wrong count");
        }
    }
    if ver != 0x01_0001 {
        ROUTER.unregister_device(id);
        return TestResult::Fail("EVIOCGVERSION value mismatch");
    }

    // EVIOCGBIT(EV_KEY, 96) → keybit; bit KEY_A must be set.
    let mut keybit = [0u8; 96];
    let cmd = ioc(READ, 0x20 + EventType::Key as u32, keybit.len() as u32);
    match file.ioctl(cmd, keybit.as_mut_ptr() as usize) {
        Ok(n) if n as usize == keybit.len() => {}
        _ => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("EVIOCGBIT(EV_KEY) returned wrong count");
        }
    }
    let byte = (KEY_A / 8) as usize;
    let bit = KEY_A % 8;
    if keybit[byte] & (1u8 << bit) == 0 {
        ROUTER.unregister_device(id);
        return TestResult::Fail("EVIOCGBIT(EV_KEY) did not reflect KEY_A");
    }

    // EVIOCGNAME(32) → non-empty NUL-terminated string.
    let mut name = [0u8; 32];
    let cmd = ioc(READ, 0x06, name.len() as u32);
    let nlen = match file.ioctl(cmd, name.as_mut_ptr() as usize) {
        Ok(n) => n as usize,
        _ => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("EVIOCGNAME failed");
        }
    };
    ROUTER.unregister_device(id);

    if nlen < 2 || name[0] == 0 || name[nlen - 1] != 0 {
        return TestResult::Fail("EVIOCGNAME did not return a NUL-terminated name");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/devfs_input", smoke_dev_input_eviocg_ioctls);

/// 9. `/dev/uinput` end-to-end loopback: declare caps + create a virtual
///    device via the control ioctls, inject an EV_KEY/KEY_A press through
///    the control file's `write`, read it back from the new `eventN`
///    reader, then destroy the device and confirm it disappears.
///
/// This is the userspace input-injection path (ydotool/wtype) exercised
/// entirely in-kernel, with no musl and no hardware key events.
fn smoke_uinput_loopback() -> TestResult {
    use crate::devfs_input::{UinputControlFile, LINUX_INPUT_EVENT_SIZE};
    use crate::FileOps;
    use narf_input::evdev::key::KEY_A;
    use narf_input::evdev::{EventType, ROUTER};

    // _IOC(dir, 'U', nr, size) — uinput type byte is 'U' = 0x55.
    fn ioc(dir: u32, nr: u32, size: u32) -> u32 {
        (dir << 30) | (size << 16) | ((b'U' as u32) << 8) | nr
    }
    const NONE: u32 = 0;
    const WRITE: u32 = 1;
    const EV_KEY: u32 = 1;

    // uinput ioctl nr values (linux/uinput.h).
    const UI_DEV_CREATE: u32 = 1;
    const UI_DEV_DESTROY: u32 = 2;
    const UI_DEV_SETUP: u32 = 3;
    const UI_SET_EVBIT: u32 = 100;
    const UI_SET_KEYBIT: u32 = 101;

    let before: alloc::vec::Vec<_> = ROUTER.device_ids();

    let ctrl = UinputControlFile::new();

    // Declare capabilities: EV_KEY support + KEY_A. For SET_*BIT the arg is
    // the code VALUE itself, not a user pointer.
    if ctrl
        .ioctl(ioc(WRITE, UI_SET_EVBIT, 4), EV_KEY as usize)
        .is_err()
    {
        return TestResult::Fail("UI_SET_EVBIT failed");
    }
    if ctrl
        .ioctl(ioc(WRITE, UI_SET_KEYBIT, 4), KEY_A as usize)
        .is_err()
    {
        return TestResult::Fail("UI_SET_KEYBIT failed");
    }
    // UI_DEV_SETUP: accepted no-op (we pass a null arg; handler must not deref).
    if ctrl.ioctl(ioc(WRITE, UI_DEV_SETUP, 92), 0).is_err() {
        return TestResult::Fail("UI_DEV_SETUP failed");
    }
    // Create the virtual device.
    if ctrl.ioctl(ioc(NONE, UI_DEV_CREATE, 0), 0).is_err() {
        return TestResult::Fail("UI_DEV_CREATE failed");
    }

    // A new device id must have appeared in the router.
    let after: alloc::vec::Vec<_> = ROUTER.device_ids();
    let new_id = match after.iter().find(|id| !before.contains(id)) {
        Some(id) => *id,
        None => return TestResult::Fail("UI_DEV_CREATE did not register a new device"),
    };

    // Open a reader on the freshly-created device (the eventN node).
    let reader = match ROUTER.open_reader(new_id) {
        Some(r) => r,
        None => {
            ctrl.ioctl(ioc(NONE, UI_DEV_DESTROY, 0), 0).ok();
            return TestResult::Fail("open_reader returned None for created device");
        }
    };

    // Build EV_KEY/KEY_A press + EV_SYN report, two 24-byte records.
    let mut payload = [0u8; LINUX_INPUT_EVENT_SIZE * 2];
    // Record 0: EV_KEY, KEY_A, value=1 (press).
    payload[16..18].copy_from_slice(&(EventType::Key as u16).to_le_bytes());
    payload[18..20].copy_from_slice(&KEY_A.to_le_bytes());
    payload[20..24].copy_from_slice(&1i32.to_le_bytes());
    // Record 1: EV_SYN, SYN_REPORT(0), value=0 — type/code/value all zero,
    // which decodes to EventType::Syn so it is left as-is.

    let write_result = poll_once_devfs_input(ctrl.write(0, &payload));
    match write_result {
        Some(Ok(n)) if n == LINUX_INPUT_EVENT_SIZE * 2 => {}
        _ => {
            ctrl.ioctl(ioc(NONE, UI_DEV_DESTROY, 0), 0).ok();
            return TestResult::Fail("uinput write failed or wrong count");
        }
    }

    // Read back the injected press from the reader.
    let press = reader.poll_event();
    let got_press = matches!(
        press,
        Some(e) if e.type_ == EventType::Key && e.code == KEY_A && e.value == 1
    );
    if !got_press {
        ctrl.ioctl(ioc(NONE, UI_DEV_DESTROY, 0), 0).ok();
        return TestResult::Fail("reader did not see injected EV_KEY/KEY_A press");
    }

    // Destroy the device; it must vanish from the router.
    if ctrl.ioctl(ioc(NONE, UI_DEV_DESTROY, 0), 0).is_err() {
        return TestResult::Fail("UI_DEV_DESTROY failed");
    }
    if ROUTER.device_ids().contains(&new_id) {
        return TestResult::Fail("device still present after UI_DEV_DESTROY");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/devfs_input", smoke_uinput_loopback);

/// MemFs hard links: `DirOps::link` must alias the SAME backing node
/// (a write through one name is visible through the other — the
/// Arc-clone-as-inode-refcount model), refuse to replace an existing
/// destination (EEXIST shape, unlike rename's atomic replace), refuse
/// a directory source, and report NotFound for a missing source.
fn smoke_filesystem_memfs_link_aliases_node() -> TestResult {
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
        // SAFETY: raw_waker() returns a vtable whose no-op/no-clone fns are sound for a
        // single-threaded test poll; the RawWaker is not used after this scope.
        // SAFETY: Valid memory or trusted environment
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` is a local mut binding that outlives this block; we do not move it.
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        match pinned.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    use crate::{bootstrap_mount_authority, registry, FsError, MemFs, MountPoint};
    use narf_capabilities::{Cap, Grant};

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let fs = MemFs::with_seeds("test-link", &[("orig", b"aa"), ("taken", b"x")]);
    let mount_handle = match registry().mount(&auth, "/test_link", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("memfs mount failed"),
    };

    // link orig → alias: success.
    let r = registry().resolve_parent_absolute("/test_link/orig", |_fs, parent, leaf| {
        poll_once(parent.link(leaf, "alias"))
    });
    if !matches!(r, Some(Some(Ok(())))) {
        let _ = registry().unmount(&mount_handle, "/test_link");
        return TestResult::Fail("link(orig, alias) should succeed");
    }

    // Write through `orig`, read through `alias` — one backing node.
    let wrote = registry().resolve_absolute("/test_link/orig", |fs, rel| {
        crate::resolve(fs.root(), rel)
            .ok()
            .and_then(|ops| poll_once(ops.write(0, b"zz")))
            .is_some_and(|r| r.is_ok())
    });
    if wrote != Some(true) {
        let _ = registry().unmount(&mount_handle, "/test_link");
        return TestResult::Fail("write through orig failed");
    }
    let read_back = registry().resolve_absolute("/test_link/alias", |fs, rel| {
        let mut buf = [0u8; 2];
        crate::resolve(fs.root(), rel)
            .ok()
            .and_then(|ops| poll_once(ops.read(0, &mut buf)))
            .is_some_and(|r| r.is_ok())
            .then_some(buf)
    });
    if read_back != Some(Some(*b"zz")) {
        let _ = registry().unmount(&mount_handle, "/test_link");
        return TestResult::Fail("write via orig not visible via alias (not one node)");
    }

    // Existing destination → Busy (EEXIST shape).
    let r = registry().resolve_parent_absolute("/test_link/orig", |_fs, parent, leaf| {
        poll_once(parent.link(leaf, "taken"))
    });
    if !matches!(r, Some(Some(Err(FsError::Busy)))) {
        let _ = registry().unmount(&mount_handle, "/test_link");
        return TestResult::Fail("link onto an existing name must be Busy");
    }

    // Missing source → NotFound.
    let r = registry().resolve_parent_absolute("/test_link/ghost", |_fs, parent, leaf| {
        poll_once(parent.link(leaf, "whatever"))
    });
    if !matches!(r, Some(Some(Err(FsError::NotFound)))) {
        let _ = registry().unmount(&mount_handle, "/test_link");
        return TestResult::Fail("link from a missing source must be NotFound");
    }

    let _ = registry().unmount(&mount_handle, "/test_link");
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_filesystem_memfs_link_aliases_node);

/// O_TMPFILE end-to-end at the VFS layer: mint an anonymous (nameless)
/// inode with `new_anon_memfile`, write bytes, read them back, stat the
/// size — the fd-facing operations the open handler installs — then
/// materialise it via `DirOps::link_node` (the `linkat(AT_EMPTY_PATH)`
/// step) and confirm the named path now resolves to the SAME inode with
/// the written contents. Also checks `supports_tmpfile()` is true for
/// memfs and false (with `link_node` → Unsupported) for a directory whose
/// filesystem can't hold an externally-minted node, which is the
/// EOPNOTSUPP fall-back the open handler reports.
fn smoke_filesystem_o_tmpfile_link_node() -> TestResult {
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
        // SAFETY: the no-op/no-clone waker vtable is sound for a single
        // synchronous poll; the RawWaker does not escape this scope.
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` is a local mut binding that outlives this block and
        // is never moved after being pinned.
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        match pinned.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    use crate::{
        bootstrap_mount_authority, new_anon_memfile, registry, DirEntry, DirOps, FileOps, FsError,
        FsInstance, MemFs, MountPoint,
    };
    use alloc::sync::Arc;
    use narf_capabilities::{Cap, Grant};

    // The anonymous inode the open handler mints for O_TMPFILE.
    let node = new_anon_memfile();

    // Directory backing memfs must advertise tmpfile support.
    let dir_fs = MemFs::new("tmpfile-support-probe");
    if !dir_fs.root().supports_tmpfile() {
        return TestResult::Fail("memfs directory must support O_TMPFILE");
    }

    // Write + read-back + stat through the nameless inode (the fd path).
    if !matches!(poll_once(node.write(0, b"tmpfile-bytes")), Some(Ok(13))) {
        return TestResult::Fail("write to anon O_TMPFILE inode failed");
    }
    let mut rb = [0u8; 13];
    if !matches!(poll_once(node.read(0, &mut rb)), Some(Ok(13))) || &rb != b"tmpfile-bytes" {
        return TestResult::Fail("read-back from anon O_TMPFILE inode wrong");
    }
    if node.stat().size != 13 {
        return TestResult::Fail("stat size on anon O_TMPFILE inode wrong");
    }
    // ftruncate then re-stat (fstat/ftruncate ride the same FileOps).
    if poll_once(node.truncate(5)).is_none() || node.stat().size != 5 {
        return TestResult::Fail("ftruncate on anon O_TMPFILE inode wrong");
    }

    // Materialise: linkat(AT_EMPTY_PATH) → link_node into a mounted dir.
    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let fs = MemFs::new("tmpfile-mat");
    let mount_handle = match registry().mount(&auth, "/tmpfile_mat", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("memfs mount failed"),
    };
    let r = registry().resolve_absolute("/tmpfile_mat", |fs, _rel| {
        poll_once(fs.root().link_node("published", Arc::clone(&node)))
    });
    if !matches!(r, Some(Some(Ok(())))) {
        let _ = registry().unmount(&mount_handle, "/tmpfile_mat");
        return TestResult::Fail("link_node materialisation should succeed");
    }

    // The named path now resolves to the SAME inode: it reads the exact
    // (truncated) bytes and any subsequent write through the fd is visible.
    let read_named = registry().resolve_absolute("/tmpfile_mat/published", |fs, rel| {
        let mut buf = [0u8; 5];
        crate::resolve(fs.root(), rel)
            .ok()
            .and_then(|ops| poll_once(ops.read(0, &mut buf)))
            .is_some_and(|r| r.is_ok())
            .then_some(buf)
    });
    if read_named != Some(Some(*b"tmpfi")) {
        let _ = registry().unmount(&mount_handle, "/tmpfile_mat");
        return TestResult::Fail("materialised name doesn't read the inode's bytes");
    }
    // Aliasing: write through the original fd handle, see it under the name.
    if !matches!(poll_once(node.write(0, b"ALIAS")), Some(Ok(5))) {
        let _ = registry().unmount(&mount_handle, "/tmpfile_mat");
        return TestResult::Fail("write via fd after link failed");
    }
    let alias_seen = registry().resolve_absolute("/tmpfile_mat/published", |fs, rel| {
        let mut buf = [0u8; 5];
        crate::resolve(fs.root(), rel)
            .ok()
            .and_then(|ops| poll_once(ops.read(0, &mut buf)))
            .is_some_and(|r| r.is_ok())
            .then_some(buf)
    });
    if alias_seen != Some(Some(*b"ALIAS")) {
        let _ = registry().unmount(&mount_handle, "/tmpfile_mat");
        return TestResult::Fail("fd write not visible via materialised name (not one inode)");
    }

    // link_node onto an existing name → Busy (linkat never replaces).
    let again = registry().resolve_absolute("/tmpfile_mat", |fs, _rel| {
        poll_once(fs.root().link_node("published", new_anon_memfile()))
    });
    if !matches!(again, Some(Some(Err(FsError::Busy)))) {
        let _ = registry().unmount(&mount_handle, "/tmpfile_mat");
        return TestResult::Fail("link_node onto an existing name must be Busy");
    }
    let _ = registry().unmount(&mount_handle, "/tmpfile_mat");

    // EOPNOTSUPP fall-back: a directory whose FS can't hold an
    // externally-minted node reports it unsupported and rejects link_node.
    struct RoDir;
    impl DirOps for RoDir {
        fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
            None
        }
        fn iter<'a>(&'a self) -> alloc::boxed::Box<dyn Iterator<Item = DirEntry> + 'a> {
            alloc::boxed::Box::new(core::iter::empty())
        }
    }
    let ro = RoDir;
    if ro.supports_tmpfile() {
        return TestResult::Fail("a non-tmpfs directory must report no O_TMPFILE support");
    }
    if !matches!(
        poll_once(ro.link_node("x", new_anon_memfile())),
        Some(Err(FsError::Unsupported))
    ) {
        return TestResult::Fail("link_node on a non-supporting dir must be Unsupported");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_filesystem_o_tmpfile_link_node);

// ── resolve_async NoFollow (readlink / lstat) semantics ────────────
//
// These exercise the `follow_final` param threaded through the VFS
// walker: readlink / lstat / *_NOFOLLOW must operate on a final
// symlink itself, while intermediate symlinks are always followed and
// the FOLLOW path keeps resolving the target.

fn poll_once_resolve<F: core::future::Future>(fut: F) -> Option<F::Output> {
    use core::pin::pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    unsafe fn no_clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    unsafe fn no_op(_: *const ()) {}
    const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
    // SAFETY: `VTAB`'s callbacks are all no-ops over a null data pointer,
    // satisfying the Waker::from_raw contract.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTAB)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

// Build a MemFs shaped like:
//   /link    -> "target"   (final symlink under test)
//   /target  = regular file "hello"
//   /dir     = directory containing /dir/leaf = "inside"
//   /dsym    -> "dir"       (symlink-to-directory, an intermediate hop)
fn build_symlink_fs() -> alloc::sync::Arc<crate::MemFs> {
    use crate::FsInstance;
    let fs = alloc::sync::Arc::new(crate::MemFs::new("symlink-resolve-test"));
    let root = fs.root();
    poll_once_resolve(root.symlink("link", "target"))
        .and_then(|r| r.ok())
        .expect("mint /link");
    let target = poll_once_resolve(root.create("target"))
        .and_then(|r| r.ok())
        .expect("mint /target");
    poll_once_resolve(target.write(0, b"hello"))
        .and_then(|r| r.ok())
        .expect("write /target");
    let dir = poll_once_resolve(root.mkdir("dir"))
        .and_then(|r| r.ok())
        .expect("mkdir /dir");
    let leaf = poll_once_resolve(dir.create("leaf"))
        .and_then(|r| r.ok())
        .expect("mint /dir/leaf");
    poll_once_resolve(leaf.write(0, b"inside"))
        .and_then(|r| r.ok())
        .expect("write /dir/leaf");
    poll_once_resolve(root.symlink("dsym", "dir"))
        .and_then(|r| r.ok())
        .expect("mint /dsym");
    fs
}

fn ftype_of(f: &alloc::sync::Arc<dyn crate::FileOps>) -> crate::FileType {
    poll_once_resolve(f.stat_async())
        .and_then(|r| r.ok())
        .map(|s| s.mode.file_type)
        .unwrap_or(crate::FileType::File)
}

// (1) NoFollow of a final symlink returns the Symlink node itself; its
//     read yields the target string ("target") — this is what readlink
//     copies to the user buffer.
fn smoke_fs_resolve_nofollow_returns_symlink() -> TestResult {
    let fs = build_symlink_fs();
    let node = match poll_once_resolve(crate::resolve_async_nofollow(
        crate::FsInstance::root(&*fs),
        "link",
    )) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("resolve_async_nofollow(link) failed"),
    };
    if ftype_of(&node) != crate::FileType::Symlink {
        return TestResult::Fail("NoFollow final symlink did not return a Symlink node");
    }
    let mut buf = [0u8; 32];
    match poll_once_resolve(node.read(0, &mut buf)) {
        Some(Ok(n)) if &buf[..n] == b"target" => TestResult::Pass,
        _ => TestResult::Fail("symlink node did not read back its target bytes"),
    }
}
kernel_test_in!("filesystem", smoke_fs_resolve_nofollow_returns_symlink);

// (2) Follow of the same final symlink resolves to the TARGET's node
//     (a regular file whose contents are "hello").
fn smoke_fs_resolve_follow_reaches_target() -> TestResult {
    let fs = build_symlink_fs();
    let node = match poll_once_resolve(crate::resolve_async(crate::FsInstance::root(&*fs), "link"))
    {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("resolve_async(link) failed"),
    };
    if ftype_of(&node) != crate::FileType::File {
        return TestResult::Fail("Follow of final symlink did not reach the target file");
    }
    let mut buf = [0u8; 32];
    match poll_once_resolve(node.read(0, &mut buf)) {
        Some(Ok(n)) if &buf[..n] == b"hello" => TestResult::Pass,
        _ => TestResult::Fail("followed target did not read back its file contents"),
    }
}
kernel_test_in!("filesystem", smoke_fs_resolve_follow_reaches_target);

// (3) Under NoFollow, an INTERMEDIATE symlink-to-directory is still
//     followed: /dsym/leaf (dsym -> dir) resolves to /dir/leaf.
fn smoke_fs_resolve_nofollow_follows_intermediate_symlink() -> TestResult {
    let fs = build_symlink_fs();
    let node = match poll_once_resolve(crate::resolve_async_nofollow(
        crate::FsInstance::root(&*fs),
        "dsym/leaf",
    )) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("resolve_async_nofollow(dsym/leaf) failed"),
    };
    if ftype_of(&node) != crate::FileType::File {
        return TestResult::Fail("intermediate symlink-to-dir was not followed under NoFollow");
    }
    let mut buf = [0u8; 32];
    match poll_once_resolve(node.read(0, &mut buf)) {
        Some(Ok(n)) if &buf[..n] == b"inside" => TestResult::Pass,
        _ => TestResult::Fail("dsym/leaf did not read back /dir/leaf contents"),
    }
}
kernel_test_in!(
    "filesystem",
    smoke_fs_resolve_nofollow_follows_intermediate_symlink
);
// ── fstype registry (fs_registry) ──────────────────────────────────
//
// A third-party crate can register a mountable fstype via
// `register_fstype`, after which `sys_mount` builds it through
// `lookup_fstype`. We can't drive the full `sys_mount` syscall from a
// kernel test, so exercise the registry API directly: register a
// trivial custom fstype (returns a seeded `MemFs`), look it up, build,
// `mount_arc` it, and resolve the seeded file through the mount.
fn smoke_fs_registry_custom_fstype_mounts() -> TestResult {
    use crate::{
        bootstrap_mount_authority, lookup_fstype, register_fstype, registry, resolve, FsError,
        FsInstance, MemFs,
    };
    use alloc::sync::Arc;

    // A builder for a custom "smokefs" type. Seeds one file so a
    // resolve() through the mount can confirm a working FsInstance.
    fn build_smokefs(_source: &str, _data: &str) -> Result<Arc<dyn FsInstance>, FsError> {
        let fs = MemFs::with_seeds("smokefs", &[("greeting", b"hi")]);
        Ok(Arc::new(fs) as Arc<dyn FsInstance>)
    }

    register_fstype("smokefs", build_smokefs);

    // An unregistered type must not resolve.
    if lookup_fstype("definitely-not-registered").is_some() {
        return TestResult::Fail("lookup_fstype returned Some for an unregistered type");
    }

    let builder = match lookup_fstype("smokefs") {
        Some(b) => b,
        None => return TestResult::Fail("lookup_fstype(smokefs) returned None after register"),
    };

    let fs = match builder("some-source", "some-data") {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("smokefs builder returned Err"),
    };

    let authority = bootstrap_mount_authority();
    let _handle = match registry().mount_arc(&authority, "/smoke-registry", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount_arc refused a live authority"),
    };

    let stat_opt = registry()
        .with_mount("/smoke-registry", |fs| {
            let file = resolve(fs.root(), "greeting").ok()?;
            Some(file.stat())
        })
        .flatten();

    match stat_opt {
        Some(s) if s.size == 2 => TestResult::Pass,
        Some(_) => TestResult::Fail("seeded file resolved with wrong size"),
        None => TestResult::Fail("resolve(greeting) failed through the registered mount"),
    }
}
kernel_test_in!("filesystem", smoke_fs_registry_custom_fstype_mounts);
// ── FUSE subsystem smokes ──────────────────────────────────────────
//
// These exercise the full FUSE client path — connection transport,
// `/dev/fuse` device, `FuseFs` VFS bridge — against a tiny in-kernel
// emulated daemon (no real userspace program). The daemon and the VFS
// client run as two cooperative tasks on the test scheduler; the client's
// reply-futures self-wake so `run_until_empty` interleaves both until the
// exchange completes.

/// Assert the wire-struct sizes match Linux `include/uapi/linux/fuse.h`
/// so ABI drift against a real virtiofsd/libfuse daemon is caught.
fn smoke_fs_fuse_struct_sizes() -> TestResult {
    use crate::fuse::*;
    use core::mem::size_of;
    if size_of::<FuseInHeader>() != 40 {
        return TestResult::Fail("fuse_in_header != 40");
    }
    if size_of::<FuseOutHeader>() != 16 {
        return TestResult::Fail("fuse_out_header != 16");
    }
    if size_of::<FuseInitIn>() != 64 {
        return TestResult::Fail("fuse_init_in != 64");
    }
    if size_of::<FuseInitOut>() != 64 {
        return TestResult::Fail("fuse_init_out != 64");
    }
    if size_of::<FuseAttr>() != 88 {
        return TestResult::Fail("fuse_attr != 88");
    }
    if size_of::<FuseEntryOut>() != 128 {
        return TestResult::Fail("fuse_entry_out != 128");
    }
    if size_of::<FuseAttrOut>() != 104 {
        return TestResult::Fail("fuse_attr_out != 104");
    }
    if size_of::<FuseGetattrIn>() != 16 {
        return TestResult::Fail("fuse_getattr_in != 16");
    }
    if size_of::<FuseOpenIn>() != 8 {
        return TestResult::Fail("fuse_open_in != 8");
    }
    if size_of::<FuseOpenOut>() != 16 {
        return TestResult::Fail("fuse_open_out != 16");
    }
    if size_of::<FuseReadIn>() != 40 {
        return TestResult::Fail("fuse_read_in != 40");
    }
    if size_of::<FuseWriteIn>() != 40 {
        return TestResult::Fail("fuse_write_in != 40");
    }
    if size_of::<FuseWriteOut>() != 8 {
        return TestResult::Fail("fuse_write_out != 8");
    }
    if size_of::<FuseMknodIn>() != 16 {
        return TestResult::Fail("fuse_mknod_in != 16");
    }
    if size_of::<FuseMkdirIn>() != 8 {
        return TestResult::Fail("fuse_mkdir_in != 8");
    }
    if size_of::<FuseRenameIn>() != 8 {
        return TestResult::Fail("fuse_rename_in != 8");
    }
    if size_of::<FuseLinkIn>() != 8 {
        return TestResult::Fail("fuse_link_in != 8");
    }
    if size_of::<FuseCreateIn>() != 16 {
        return TestResult::Fail("fuse_create_in != 16");
    }
    if size_of::<FuseSetattrIn>() != 88 {
        return TestResult::Fail("fuse_setattr_in != 88");
    }
    if size_of::<FuseReleaseIn>() != 24 {
        return TestResult::Fail("fuse_release_in != 24");
    }
    if size_of::<FuseForgetIn>() != 8 {
        return TestResult::Fail("fuse_forget_in != 8");
    }
    if size_of::<FuseDirent>() != 24 {
        return TestResult::Fail("fuse_dirent header != 24");
    }
    if size_of::<FuseDirentPlus>() != 152 {
        return TestResult::Fail("fuse_direntplus header != 152");
    }
    if size_of::<FuseForgetOne>() != 16 || size_of::<FuseBatchForgetIn>() != 8 {
        return TestResult::Fail("fuse batch-forget layouts drifted");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_fuse_struct_sizes);

fn smoke_fs_fuse_request_context() -> TestResult {
    use crate::fuse::{pod_from_bytes, FuseInHeader, FuseOpcode};
    use crate::fuse_conn::{
        install_request_context_provider, FuseConnection, FuseRequestContext,
        __test_reset_request_context_provider,
    };

    fn context() -> FuseRequestContext {
        FuseRequestContext {
            uid: 1001,
            gid: 1002,
            pid: 1003,
        }
    }

    install_request_context_provider(context);
    let conn = FuseConnection::new();
    conn.submit_noreply(FuseOpcode::Destroy, 0, &[]);
    let request = conn.dequeue_request();
    __test_reset_request_context_provider();

    let Some(header) = request.as_deref().and_then(pod_from_bytes::<FuseInHeader>) else {
        return TestResult::Fail("FUSE request header missing");
    };
    if (header.uid, header.gid, header.pid) == (1001, 1002, 1003) {
        TestResult::Pass
    } else {
        TestResult::Fail("FUSE request context not propagated")
    }
}
kernel_test_in!("filesystem", smoke_fs_fuse_request_context);

fn smoke_fs_fuse_cache_notifications() -> TestResult {
    use crate::fuse::*;
    use crate::fuse_conn::FuseConnection;

    let conn = FuseConnection::new();
    let inode = fuse_reply(
        0,
        FUSE_NOTIFY_INVAL_INODE,
        &pod_as_bytes(&FuseNotifyInvalInodeOut {
            ino: 2,
            offset: 0,
            len: -1,
        }),
    );
    let mut entry_body = pod_as_bytes(&FuseNotifyInvalEntryOut {
        parent: FUSE_ROOT_ID,
        namelen: 5,
        flags: 0,
    });
    entry_body.extend_from_slice(b"hello");
    let entry = fuse_reply(0, FUSE_NOTIFY_INVAL_ENTRY, &entry_body);
    let mut delete_body = pod_as_bytes(&FuseNotifyDeleteOut {
        parent: FUSE_ROOT_ID,
        child: 2,
        namelen: 5,
        padding: 0,
    });
    delete_body.extend_from_slice(b"hello");
    let delete = fuse_reply(0, FUSE_NOTIFY_DELETE, &delete_body);

    if conn.complete_reply(&inode) != Some(inode.len())
        || conn.complete_reply(&entry) != Some(entry.len())
        || conn.complete_reply(&delete) != Some(delete.len())
    {
        return TestResult::Fail("valid FUSE cache notification rejected");
    }
    entry_body.pop();
    let malformed = fuse_reply(0, FUSE_NOTIFY_INVAL_ENTRY, &entry_body);
    if conn.complete_reply(&malformed).is_some() {
        TestResult::Fail("short FUSE cache notification accepted")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("filesystem", smoke_fs_fuse_cache_notifications);

fn smoke_fs_fuse_batches_forgets() -> TestResult {
    use crate::fuse::*;
    use crate::fuse_conn::FuseConnection;

    let conn = FuseConnection::new();
    conn.submit_noreply(
        FuseOpcode::Forget,
        11,
        &pod_as_bytes(&FuseForgetIn { nlookup: 2 }),
    );
    conn.submit_noreply(
        FuseOpcode::Forget,
        12,
        &pod_as_bytes(&FuseForgetIn { nlookup: 3 }),
    );
    let Some(request) = conn.dequeue_request() else {
        return TestResult::Fail("batched forget missing");
    };
    let Some(header) = pod_from_bytes::<FuseInHeader>(&request) else {
        return TestResult::Fail("batched forget header malformed");
    };
    let offset = core::mem::size_of::<FuseInHeader>();
    let Some(batch) = pod_from_bytes::<FuseBatchForgetIn>(&request[offset..]) else {
        return TestResult::Fail("batched forget body malformed");
    };
    let entries = offset + core::mem::size_of::<FuseBatchForgetIn>();
    let first = pod_from_bytes::<FuseForgetOne>(&request[entries..]);
    let second = pod_from_bytes::<FuseForgetOne>(
        &request[entries + core::mem::size_of::<FuseForgetOne>()..],
    );
    if header.opcode == FuseOpcode::BatchForget as u32
        && batch.count == 2
        && first.map(|entry| (entry.nodeid, entry.nlookup)) == Some((11, 2))
        && second.map(|entry| (entry.nodeid, entry.nlookup)) == Some((12, 3))
        && conn.dequeue_request().is_none()
    {
        TestResult::Pass
    } else {
        TestResult::Fail("forget requests not coalesced")
    }
}
kernel_test_in!("filesystem", smoke_fs_fuse_batches_forgets);

/// Encode a `fuse_out_header` + `body` reply for `unique`.
fn fuse_reply(unique: u64, error: i32, body: &[u8]) -> alloc::vec::Vec<u8> {
    use crate::fuse::*;
    let total = core::mem::size_of::<FuseOutHeader>() + body.len();
    let hdr = FuseOutHeader {
        len: total as u32,
        error,
        unique,
    };
    let mut msg = pod_as_bytes(&hdr);
    msg.extend_from_slice(body);
    msg
}

/// Service a single FUSE request the emulated daemon dequeued. Models a
/// filesystem with one regular file "hello" (nodeid 2, contents "world")
/// directly under the root (nodeid 1). Returns the encoded reply, or
/// `None` for an opcode it doesn't model (which fails the request).
fn fuse_daemon_answer(req: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    use crate::fuse::*;
    let hdr: FuseInHeader = pod_from_bytes(req)?;
    let unique = hdr.unique;
    let body = &req[core::mem::size_of::<FuseInHeader>()..hdr.len as usize];
    let opcode = hdr.opcode;

    // Attributes for the file "hello": regular, 0644, 5 bytes.
    let file_attr = FuseAttr {
        ino: 2,
        size: 5,
        blocks: 1,
        mode: S_IFREG | 0o644,
        nlink: 1,
        blksize: 512,
        ..Default::default()
    };
    // Attributes for the root dir.
    let dir_attr = FuseAttr {
        ino: FUSE_ROOT_ID,
        size: 0,
        blocks: 0,
        mode: S_IFDIR | 0o755,
        nlink: 2,
        blksize: 512,
        ..Default::default()
    };

    match opcode {
        // FUSE_INIT (26): echo version + a plausible negotiated reply.
        26 => {
            let init: FuseInitIn = pod_from_bytes(body)?;
            let out = FuseInitOut {
                major: FUSE_KERNEL_VERSION,
                minor: FUSE_KERNEL_MINOR_VERSION,
                max_readahead: 0,
                flags: init.flags,
                max_background: 0,
                congestion_threshold: 0,
                max_write: 128 * 1024,
                time_gran: 1,
                max_pages: 32,
                map_alignment: 0,
                flags2: init.flags2,
                max_stack_depth: 0,
                request_timeout: 0,
                unused: [0; 11],
            };
            Some(fuse_reply(unique, 0, &pod_as_bytes(&out)))
        }
        // FUSE_LOOKUP (1): resolve a name under `hdr.nodeid`.
        1 => {
            let name_len = body.iter().position(|&b| b == 0).unwrap_or(body.len());
            let name = core::str::from_utf8(&body[..name_len]).unwrap_or("");
            if hdr.nodeid == FUSE_ROOT_ID && (name == "hello" || name == "sym") {
                let mut attr = file_attr;
                if name == "sym" {
                    attr.mode = S_IFLNK | 0o777;
                    attr.size = 5;
                }
                let out = FuseEntryOut {
                    nodeid: if name == "sym" { 5 } else { 2 },
                    generation: 1,
                    attr,
                    ..Default::default()
                };
                Some(fuse_reply(unique, 0, &pod_as_bytes(&out)))
            } else {
                // -ENOENT
                Some(fuse_reply(unique, -2, &[]))
            }
        }
        // FUSE_GETATTR (3).
        3 => {
            let attr = if hdr.nodeid == 2 { file_attr } else { dir_attr };
            let out = FuseAttrOut {
                attr_valid: 0,
                attr_valid_nsec: 0,
                dummy: 0,
                attr,
            };
            Some(fuse_reply(unique, 0, &pod_as_bytes(&out)))
        }
        // FUSE_OPEN (14) / FUSE_OPENDIR (27): hand back a fixed handle.
        14 | 27 => {
            let out = FuseOpenOut {
                fh: 0x42,
                open_flags: 0,
                padding: 0,
            };
            Some(fuse_reply(unique, 0, &pod_as_bytes(&out)))
        }
        // FUSE_READ (15): return the file bytes at the requested range.
        15 => {
            let rin: FuseReadIn = pod_from_bytes(body)?;
            let contents = b"world";
            let off = rin.offset as usize;
            let end = core::cmp::min(contents.len(), off + rin.size as usize);
            let slice = if off < contents.len() {
                &contents[off..end]
            } else {
                &[][..]
            };
            Some(fuse_reply(unique, 0, slice))
        }
        // FUSE_READLINK (5): target bytes, with no trailing NUL.
        5 => Some(fuse_reply(unique, 0, b"hello")),
        // FUSE_STATFS (17): filesystem-wide capacity.
        17 => {
            let out = FuseStatfsOut {
                st: FuseKstatfs {
                    blocks: 1024,
                    bfree: 512,
                    bavail: 500,
                    files: 100,
                    ffree: 75,
                    bsize: 4096,
                    namelen: 255,
                    frsize: 4096,
                    ..Default::default()
                },
            };
            Some(fuse_reply(unique, 0, &pod_as_bytes(&out)))
        }
        // FUSE_SETXATTR / REMOVEXATTR.
        21 | 24 => Some(fuse_reply(unique, 0, &[])),
        // FUSE_GETXATTR: size probe then value.
        22 => {
            let input: FuseGetxattrIn = pod_from_bytes(body)?;
            if input.size == 0 {
                Some(fuse_reply(
                    unique,
                    0,
                    &pod_as_bytes(&FuseGetxattrOut {
                        size: 3,
                        padding: 0,
                    }),
                ))
            } else {
                Some(fuse_reply(unique, 0, b"bar"))
            }
        }
        // FUSE_LISTXATTR: size probe then NUL-separated names.
        23 => {
            let input: FuseGetxattrIn = pod_from_bytes(body)?;
            if input.size == 0 {
                Some(fuse_reply(
                    unique,
                    0,
                    &pod_as_bytes(&FuseGetxattrOut {
                        size: 9,
                        padding: 0,
                    }),
                ))
            } else {
                Some(fuse_reply(unique, 0, b"user.foo\0"))
            }
        }
        // FUSE_ACCESS.
        34 => Some(fuse_reply(unique, 0, &[])),
        // FUSE_GETLK reports unlocked; SETLK/SETLKW acknowledge.
        31 => Some(fuse_reply(
            unique,
            0,
            &pod_as_bytes(&FuseLkOut {
                lk: FuseFileLock {
                    type_: 2, // F_UNLCK
                    ..Default::default()
                },
            }),
        )),
        32 | 33 => Some(fuse_reply(unique, 0, &[])),
        43 => Some(fuse_reply(unique, 0, &[])),
        46 => {
            let input: FuseLseekIn = pod_from_bytes(body)?;
            Some(fuse_reply(
                unique,
                0,
                &pod_as_bytes(&FuseLseekOut {
                    offset: input.offset + 4,
                }),
            ))
        }
        47 => {
            let input: FuseCopyFileRangeIn = pod_from_bytes(body)?;
            Some(fuse_reply(
                unique,
                0,
                &pod_as_bytes(&FuseWriteOut {
                    size: input.len as u32,
                    padding: 0,
                }),
            ))
        }
        40 => Some(fuse_reply(
            unique,
            0,
            &pod_as_bytes(&FusePollOut {
                revents: crate::POLL_IN,
                padding: 0,
            }),
        )),
        // FUSE_WRITE (16): report the requested payload size.
        16 => {
            let win: FuseWriteIn = pod_from_bytes(body)?;
            if win.size > 128 * 1024 {
                return Some(fuse_reply(unique, -22, &[]));
            }
            let out = FuseWriteOut {
                size: win.size,
                padding: 0,
            };
            Some(fuse_reply(unique, 0, &pod_as_bytes(&out)))
        }
        // FUSE_READDIR / FUSE_READDIRPLUS: one entry, "hello".
        28 | 44 => {
            let mut out = alloc::vec::Vec::new();
            let de = FuseDirent {
                ino: 2,
                off: 1,
                namelen: 5,
                type_: 8, // DT_REG
            };
            if opcode == 44 {
                out.extend_from_slice(&pod_as_bytes(&FuseDirentPlus {
                    entry_out: FuseEntryOut {
                        nodeid: 2,
                        generation: 1,
                        attr: file_attr,
                        ..Default::default()
                    },
                    dirent: de,
                }));
            } else {
                out.extend_from_slice(&pod_as_bytes(&de));
            }
            out.extend_from_slice(b"hello");
            while out.len() % FUSE_DIRENT_ALIGN != 0 {
                out.push(0);
            }
            Some(fuse_reply(unique, 0, &out))
        }
        // FUSE_SETATTR (4): return refreshed attributes.
        4 => {
            let input: FuseSetattrIn = pod_from_bytes(body)?;
            let mut attr = file_attr;
            if input.valid & FATTR_SIZE != 0 {
                attr.size = input.size;
            }
            if input.valid & FATTR_MODE != 0 {
                attr.mode = input.mode;
            }
            let out = FuseAttrOut {
                attr,
                ..Default::default()
            };
            Some(fuse_reply(unique, 0, &pod_as_bytes(&out)))
        }
        // FUSE_CREATE (35): entry followed by open result.
        35 => {
            let entry = FuseEntryOut {
                nodeid: 4,
                generation: 1,
                attr: file_attr,
                ..Default::default()
            };
            let open = FuseOpenOut {
                fh: 0x44,
                ..Default::default()
            };
            let mut out = pod_as_bytes(&entry);
            out.extend_from_slice(&pod_as_bytes(&open));
            Some(fuse_reply(unique, 0, &out))
        }
        // FUSE_MKNOD / MKDIR / SYMLINK / LINK return an entry.
        6 | 8 | 9 | 13 => {
            let is_dir = opcode == 9;
            let entry = FuseEntryOut {
                nodeid: if is_dir { 3 } else { 4 },
                generation: 1,
                attr: if is_dir { dir_attr } else { file_attr },
                ..Default::default()
            };
            Some(fuse_reply(unique, 0, &pod_as_bytes(&entry)))
        }
        // Namespace mutations, durability, and handle releases acknowledge empty.
        10 | 11 | 12 | 18 | 20 | 25 | 29 | 30 | 45 => Some(fuse_reply(unique, 0, &[])),
        // FUSE_FORGET (2): has no reply; drop it.
        2 => None,
        // Anything else → -ENOSYS.
        _ => Some(fuse_reply(unique, -38, &[])),
    }
}

/// Spawn the emulated FUSE daemon: drain + answer requests until the
/// client sets `done != 0` or a generous iteration cap is hit (bounding
/// `run_until_empty`).
fn spawn_fuse_daemon(
    conn: alloc::sync::Arc<crate::fuse_conn::FuseConnection>,
    done: &'static core::sync::atomic::AtomicU8,
) {
    use core::sync::atomic::Ordering;
    narf_scheduler::spawn(async move {
        for _ in 0..100_000usize {
            if let Some(req) = conn.dequeue_request() {
                if let Some(reply) = fuse_daemon_answer(&req) {
                    let _ = conn.complete_reply(&reply);
                }
                continue;
            }
            if done.load(Ordering::Relaxed) != 0 {
                break;
            }
            narf_scheduler::yield_now().await;
        }
    });
}

/// End-to-end: mount a `FuseFs` over an emulated daemon, resolve
/// "hello" through the mount registry, and read it back.
fn smoke_fs_fuse_end_to_end() -> TestResult {
    use crate::fuse_conn::{FuseConnection, FuseFs};
    use crate::{bootstrap_mount_authority, registry, FsInstance};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);
    static GOT: AtomicUsize = AtomicUsize::new(0);
    OUTCOME.store(0, Ordering::Relaxed);
    GOT.store(0, Ordering::Relaxed);

    let conn = Arc::new(FuseConnection::new());
    let fs = Arc::new(FuseFs::new("fuse-test", Arc::clone(&conn)));

    // Mount the FuseFs so resolution goes through the real registry path.
    let auth = bootstrap_mount_authority();
    let fs_dyn: Arc<dyn FsInstance> = Arc::clone(&fs) as Arc<dyn FsInstance>;
    let _handle = match registry().mount_arc(&auth, "/fuse_e2e", fs_dyn) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("FuseFs mount failed"),
    };

    narf_scheduler::__reset_queues_for_test();
    spawn_fuse_daemon(Arc::clone(&conn), &OUTCOME);

    // Client task: INIT handshake, then resolve+read "hello".
    let cfs = Arc::clone(&fs);
    narf_scheduler::spawn(async move {
        if cfs.init().await.is_err() {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }
        let root = cfs.root();
        let file = match root.lookup_async("hello").await {
            Ok(f) => f,
            Err(_) => {
                OUTCOME.store(3, Ordering::Relaxed);
                return;
            }
        };
        let mut buf = [0u8; 16];
        let n = match file.read(0, &mut buf).await {
            Ok(n) => n,
            Err(_) => {
                OUTCOME.store(4, Ordering::Relaxed);
                return;
            }
        };
        GOT.store(n, Ordering::Relaxed);
        if n == 5 && &buf[..5] == b"world" {
            OUTCOME.store(1, Ordering::Relaxed);
        } else {
            OUTCOME.store(5, Ordering::Relaxed);
        }
    });

    narf_scheduler::run_until_empty();

    let _ = unmount_for_test_fuse("/fuse_e2e");

    match OUTCOME.load(Ordering::Relaxed) {
        1 if conn.negotiated_minor() == crate::fuse::FUSE_KERNEL_MINOR_VERSION
            && conn.max_write() == 128 * 1024
            && conn.negotiated_flags() & crate::fuse::FuseInitFlag::PosixLocks as u64 != 0 =>
        {
            TestResult::Pass
        }
        1 => TestResult::Fail("FUSE_INIT limits or flags not negotiated"),
        2 => TestResult::Fail("FUSE_INIT handshake failed"),
        3 => TestResult::Fail("FUSE_LOOKUP hello failed"),
        4 => TestResult::Fail("FUSE_READ hello failed"),
        5 => TestResult::Fail("read returned wrong bytes"),
        _ => TestResult::Fail("client task never completed"),
    }
}
kernel_test_in!("filesystem", smoke_fs_fuse_end_to_end);

/// Readdir + getattr through the FUSE bridge.
fn smoke_fs_fuse_readdir_getattr() -> TestResult {
    use crate::fuse_conn::{FuseConnection, FuseFs};
    use crate::{FileType, FsInstance};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);
    OUTCOME.store(0, Ordering::Relaxed);

    let conn = Arc::new(FuseConnection::new());
    let fs = Arc::new(FuseFs::new("fuse-rd", Arc::clone(&conn)));

    narf_scheduler::__reset_queues_for_test();
    spawn_fuse_daemon(Arc::clone(&conn), &OUTCOME);

    let cfs = Arc::clone(&fs);
    narf_scheduler::spawn(async move {
        if cfs.init().await.is_err() {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }
        let root = cfs.root();
        // readdir should list exactly ["hello" (File)].
        let entries = match root.enumerate_async(0, 32).await {
            Ok(e) => e,
            Err(_) => {
                OUTCOME.store(3, Ordering::Relaxed);
                return;
            }
        };
        if entries.len() != 1 || entries[0].0 != "hello" || entries[0].1 != FileType::File {
            OUTCOME.store(4, Ordering::Relaxed);
            return;
        }
        // getattr on the file via stat_async → size 5.
        let file = match root.lookup_async("hello").await {
            Ok(f) => f,
            Err(_) => {
                OUTCOME.store(5, Ordering::Relaxed);
                return;
            }
        };
        let st = match file.stat_async().await {
            Ok(s) => s,
            Err(_) => {
                OUTCOME.store(6, Ordering::Relaxed);
                return;
            }
        };
        if st.size == 5 && st.mode.file_type == FileType::File {
            OUTCOME.store(1, Ordering::Relaxed);
        } else {
            OUTCOME.store(7, Ordering::Relaxed);
        }
    });

    narf_scheduler::run_until_empty();

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("FUSE_INIT failed"),
        3 => TestResult::Fail("readdir failed"),
        4 => TestResult::Fail("readdir wrong entries"),
        5 => TestResult::Fail("lookup failed"),
        6 => TestResult::Fail("getattr failed"),
        7 => TestResult::Fail("getattr wrong attrs"),
        _ => TestResult::Fail("client never completed"),
    }
}
kernel_test_in!("filesystem", smoke_fs_fuse_readdir_getattr);

/// READLINK and STATFS use their dedicated Linux FUSE operations.
fn smoke_fs_fuse_metadata_queries() -> TestResult {
    use crate::fuse_conn::{FuseConnection, FuseFs};
    use crate::FsInstance;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);
    OUTCOME.store(0, Ordering::Relaxed);

    let conn = Arc::new(FuseConnection::new());
    let fs = Arc::new(FuseFs::new("fuse-meta", Arc::clone(&conn)));
    narf_scheduler::__reset_queues_for_test();
    spawn_fuse_daemon(Arc::clone(&conn), &OUTCOME);

    narf_scheduler::spawn(async move {
        if fs.init().await.is_err() {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }
        let link = match fs.root().lookup_async("sym").await {
            Ok(link) => link,
            Err(_) => {
                OUTCOME.store(3, Ordering::Relaxed);
                return;
            }
        };
        let mut target = [0u8; 16];
        if link.read(0, &mut target).await != Ok(5) || &target[..5] != b"hello" {
            OUTCOME.store(4, Ordering::Relaxed);
            return;
        }
        let stat = match fs.statfs().await {
            Ok(stat) => stat,
            Err(_) => {
                OUTCOME.store(5, Ordering::Relaxed);
                return;
            }
        };
        if stat.blocks == 1024
            && stat.blocks_free == 512
            && stat.blocks_available == 500
            && stat.files == 100
            && stat.files_free == 75
            && stat.block_size == 4096
            && stat.name_len == 255
        {
            OUTCOME.store(1, Ordering::Relaxed);
        } else {
            OUTCOME.store(6, Ordering::Relaxed);
        }
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("FUSE_INIT failed"),
        3 => TestResult::Fail("FUSE symlink lookup failed"),
        4 => TestResult::Fail("FUSE_READLINK returned wrong target"),
        5 => TestResult::Fail("FUSE_STATFS failed"),
        6 => TestResult::Fail("FUSE_STATFS returned wrong capacity"),
        _ => TestResult::Fail("FUSE metadata client never completed"),
    }
}
kernel_test_in!("filesystem", smoke_fs_fuse_metadata_queries);

/// Linux mutation operations traverse the real VFS trait surface and
/// produce replies with the expected entry/open shapes.
fn smoke_fs_fuse_mutations() -> TestResult {
    use crate::fuse_conn::{FuseConnection, FuseFs};
    use crate::{FileType, FsInstance};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);
    OUTCOME.store(0, Ordering::Relaxed);

    let conn = Arc::new(FuseConnection::new());
    let fs = Arc::new(FuseFs::new("fuse-rw", Arc::clone(&conn)));
    narf_scheduler::__reset_queues_for_test();
    spawn_fuse_daemon(Arc::clone(&conn), &OUTCOME);

    narf_scheduler::spawn(async move {
        if fs.init().await.is_err() {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }
        let root = fs.root();
        let file = match root.create("new").await {
            Ok(file) => file,
            Err(_) => {
                OUTCOME.store(3, Ordering::Relaxed);
                return;
            }
        };
        let large_write = alloc::vec![0x5a; 128 * 1024 + 17];
        if file.write(0, b"payload").await != Ok(7)
            || file.write(7, &large_write).await != Ok(large_write.len())
            || file.truncate(3).await.is_err()
            || file.set_perms(0o600).await.is_err()
            || file.set_owners(1000, 1000).await.is_err()
            || file.flush().await.is_err()
            || file.fsync(false).await.is_err()
            || file.fsync(true).await.is_err()
            || file.set_xattr("user.foo", b"bar", 0).await.is_err()
            || file.get_xattr("user.foo").await != Ok(b"bar".to_vec())
            || file.list_xattr().await != Ok(b"user.foo\0".to_vec())
            || file.remove_xattr("user.foo").await.is_err()
            || file.access(6).await.is_err()
            || file
                .set_lock(
                    7,
                    crate::FileLock {
                        start: 0,
                        end: 99,
                        type_: 1,
                        pid: 7,
                    },
                    false,
                )
                .await
                .is_err()
            || file
                .set_lock(
                    7,
                    crate::FileLock {
                        start: 0,
                        end: 99,
                        type_: 1,
                        pid: 7,
                    },
                    true,
                )
                .await
                .is_err()
            || file
                .get_lock(
                    7,
                    crate::FileLock {
                        start: 0,
                        end: 99,
                        type_: 1,
                        pid: 7,
                    },
                )
                .await
                .map(|lock| lock.type_)
                != Ok(2)
            || file.fallocate(0, 0, 4096).await.is_err()
            || file.seek(4, 3).await != Ok(8)
            || file.copy_file_range_to(0, &*file, 8, 16, 0).await != Ok(16)
        {
            OUTCOME.store(4, Ordering::Relaxed);
            return;
        }
        let _ = file.poll_readiness();
        narf_scheduler::yield_now().await;
        if file.poll_readiness() != crate::POLL_IN {
            OUTCOME.store(4, Ordering::Relaxed);
            return;
        }
        let dir = match root.mkdir("dir").await {
            Ok(dir) => dir,
            Err(_) => {
                OUTCOME.store(5, Ordering::Relaxed);
                return;
            }
        };
        if root.mknod("fifo", FileType::Fifo, 0).await.is_err()
            || root.symlink("sym", "new").await.is_err()
            || root.link("hello", "hard").await.is_err()
            || root.link_to("hello", &*dir, "cross-hard").await.is_err()
            || root
                .rename_to("new", &*dir, "cross-renamed", 1)
                .await
                .is_err()
            || root.rename("new", "renamed").await.is_err()
            || root.unlink("renamed").await.is_err()
            || root.rmdir("dir").await.is_err()
        {
            OUTCOME.store(5, Ordering::Relaxed);
            return;
        }
        OUTCOME.store(1, Ordering::Relaxed);
    });

    narf_scheduler::run_until_empty();
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("FUSE_INIT failed"),
        3 => TestResult::Fail("FUSE_CREATE failed"),
        4 => TestResult::Fail("FUSE file mutation failed"),
        5 => TestResult::Fail("FUSE namespace mutation failed"),
        _ => TestResult::Fail("FUSE mutation client never completed"),
    }
}
kernel_test_in!("filesystem", smoke_fs_fuse_mutations);

/// A too-small `/dev/fuse` daemon buffer returns EINVAL-shaped
/// `InvalidData` without consuming or truncating the queued request.
fn smoke_fs_fuse_short_read_preserves_request() -> TestResult {
    use crate::fuse_conn::{DevFuse, FuseFs};
    use crate::{FileOps, FsError};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};

    static OUTCOME: AtomicU8 = AtomicU8::new(0);
    OUTCOME.store(0, Ordering::Relaxed);

    let dev: Arc<dyn FileOps> = DevFuse::open_new();
    let conn = DevFuse::connection_of(&dev).unwrap();
    let fs = Arc::new(FuseFs::new("fuse-short", Arc::clone(&conn)));
    narf_scheduler::__reset_queues_for_test();

    let daemon_dev = Arc::clone(&dev);
    let daemon_conn = Arc::clone(&conn);
    narf_scheduler::spawn(async move {
        while !daemon_conn.has_request() {
            narf_scheduler::yield_now().await;
        }
        let mut short = [0u8; 1];
        if daemon_dev.read(0, &mut short).await != Err(FsError::InvalidData)
            || !daemon_conn.has_request()
        {
            OUTCOME.store(2, Ordering::Relaxed);
            return;
        }
        let mut full = [0u8; 512];
        let n = match daemon_dev.read(0, &mut full).await {
            Ok(n) => n,
            Err(_) => {
                OUTCOME.store(3, Ordering::Relaxed);
                return;
            }
        };
        let Some(reply) = fuse_daemon_answer(&full[..n]) else {
            OUTCOME.store(4, Ordering::Relaxed);
            return;
        };
        let _ = daemon_conn.complete_reply(&reply);
    });

    narf_scheduler::spawn(async move {
        if fs.init().await.is_ok() {
            OUTCOME.store(1, Ordering::Relaxed);
        } else {
            OUTCOME.store(5, Ordering::Relaxed);
        }
    });
    narf_scheduler::run_until_empty();

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("short read consumed or accepted request"),
        3 => TestResult::Fail("full retry failed"),
        4 => TestResult::Fail("preserved request was malformed"),
        5 => TestResult::Fail("FUSE_INIT retry failed"),
        _ => TestResult::Fail("short-read tasks never completed"),
    }
}
kernel_test_in!("filesystem", smoke_fs_fuse_short_read_preserves_request);

/// Cancelling an operation already read by the daemon emits FUSE_INTERRUPT
/// naming the original request unique ID.
fn smoke_fs_fuse_delivered_cancel_interrupts() -> TestResult {
    use crate::fuse::{pod_from_bytes, FuseInHeader, FuseInterruptIn, FuseOpcode};
    use crate::fuse_conn::{FuseConnection, FuseFs};
    use alloc::sync::Arc;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VT)
    }
    fn noop(_: *const ()) {}
    static VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);

    let conn = Arc::new(FuseConnection::new());
    let fs = FuseFs::new("fuse-cancel", Arc::clone(&conn));
    let mut future = alloc::boxed::Box::pin(fs.init());
    // SAFETY: the static vtable never dereferences its null data pointer.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VT)) };
    let mut cx = Context::from_waker(&waker);
    if !matches!(Pin::new(&mut future).poll(&mut cx), Poll::Pending) {
        return TestResult::Fail("FUSE_INIT unexpectedly completed without daemon");
    }
    let original = match conn.dequeue_request() {
        Some(request) => request,
        None => return TestResult::Fail("FUSE_INIT was not queued"),
    };
    let original_header: FuseInHeader = match pod_from_bytes(&original) {
        Some(header) => header,
        None => return TestResult::Fail("FUSE_INIT header malformed"),
    };
    drop(future);
    let interrupt = match conn.dequeue_request() {
        Some(request) => request,
        None => return TestResult::Fail("delivered cancellation did not queue interrupt"),
    };
    let header: FuseInHeader = match pod_from_bytes(&interrupt) {
        Some(header) => header,
        None => return TestResult::Fail("FUSE_INTERRUPT header malformed"),
    };
    let body = &interrupt[core::mem::size_of::<FuseInHeader>()..];
    let input: FuseInterruptIn = match pod_from_bytes(body) {
        Some(input) => input,
        None => return TestResult::Fail("FUSE_INTERRUPT body malformed"),
    };
    if header.opcode == FuseOpcode::Interrupt as u32 && input.unique == original_header.unique {
        TestResult::Pass
    } else {
        TestResult::Fail("FUSE_INTERRUPT named wrong request")
    }
}
kernel_test_in!("filesystem", smoke_fs_fuse_delivered_cancel_interrupts);

/// `/dev/fuse` device wiring: opening the node yields a DevFuse whose
/// connection is recoverable (the mount path's `fd=N` → connection step).
fn smoke_fs_fuse_dev_node() -> TestResult {
    use crate::fuse_conn::DevFuse;
    use crate::{FileOps, FsInstance};
    use alloc::sync::Arc;

    // The devfs root must expose "fuse".
    let devfs = crate::devfs::DevFs::new();
    let root = devfs.root();
    let node: Arc<dyn FileOps> = match root.lookup("fuse") {
        Some(n) => n,
        None => return TestResult::Fail("/dev/fuse not found in devfs"),
    };
    // The node must be recoverable as a DevFuse connection.
    let conn = match DevFuse::connection_of(&node) {
        Some(c) => c,
        None => return TestResult::Fail("/dev/fuse node is not a DevFuse"),
    };
    if !conn.is_connected() {
        return TestResult::Fail("fresh connection reports disconnected");
    }
    // Each open() mints a *distinct* connection (Linux clones per-open).
    let node2 = root.lookup("fuse").unwrap();
    let conn2 = DevFuse::connection_of(&node2).unwrap();
    if Arc::ptr_eq(&conn, &conn2) {
        return TestResult::Fail("two opens shared one connection");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_fuse_dev_node);

/// Test-only unmount helper for the FUSE e2e mounts.
fn unmount_for_test_fuse(path: &str) -> Result<(), crate::FsError> {
    use narf_capabilities::Cap;
    let handle: Cap<crate::MountPoint, narf_capabilities::Write> =
        Cap::<crate::MountPoint, narf_capabilities::Write>::bootstrap();
    crate::registry().unmount(&handle, path)
}

// ── overlayfs (union filesystem) smokes ─────────────────────────────

/// Synchronously drive a single-poll future to completion for the
/// overlay tests. Every overlay op resolves in one poll (all the
/// backing MemFs ops are ready immediately), so a no-op waker suffices.
/// Duplicated per convention with the other tests in this module.
fn poll_once_overlay<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
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
    // SAFETY: the no-op vtable is sound for a single-threaded test poll;
    // the RawWaker is not used after this scope.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is a local mut binding that outlives this block and
    // is never moved out.
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// Build a two-layer overlay (lower: `a`,`shared`; upper: `b`,`shared`)
/// and assert union + shadowing semantics on lookup and enumerate.
fn smoke_overlay_union_shadow() -> TestResult {
    use crate::{DirOps, FsInstance, MemFs, OverlayFs};
    use alloc::sync::Arc;
    use alloc::vec;

    let lower = Arc::new(MemFs::with_seeds(
        "ov-lower",
        &[("a", b"lower-a"), ("shared", b"LOWER-shared")],
    ));
    let upper = Arc::new(MemFs::with_seeds(
        "ov-upper",
        &[("b", b"upper-b"), ("shared", b"UPPER-shared")],
    ));

    let ov = OverlayFs::new("ov", upper.root(), vec![lower.root() as Arc<dyn DirOps>]);
    let root = ov.root();

    // lookup `a` → present only in lower.
    let fa = match root.lookup("a") {
        Some(f) => f,
        None => return TestResult::Fail("overlay lookup(a) missed the lower-only file"),
    };
    let mut buf = [0u8; 32];
    let n = match poll_once_overlay(fa.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read(a) did not complete"),
    };
    if &buf[..n] != b"lower-a" {
        return TestResult::Fail("lookup(a) returned wrong (non-lower) content");
    }

    // lookup `b` → present only in upper.
    let fb = match root.lookup("b") {
        Some(f) => f,
        None => return TestResult::Fail("overlay lookup(b) missed the upper-only file"),
    };
    let n = match poll_once_overlay(fb.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read(b) did not complete"),
    };
    if &buf[..n] != b"upper-b" {
        return TestResult::Fail("lookup(b) returned wrong (non-upper) content");
    }

    // lookup `shared` → upper shadows lower.
    let fs = match root.lookup("shared") {
        Some(f) => f,
        None => return TestResult::Fail("overlay lookup(shared) missed"),
    };
    let n = match poll_once_overlay(fs.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read(shared) did not complete"),
    };
    if &buf[..n] != b"UPPER-shared" {
        return TestResult::Fail("lookup(shared) did not shadow lower with upper");
    }

    // enumerate → deduped union {a, b, shared}.
    let names = root.enumerate(0, 64);
    let has = |n: &str| names.iter().any(|(name, _)| name == n);
    if names.len() != 3 || !has("a") || !has("b") || !has("shared") {
        return TestResult::Fail("enumerate did not produce the deduped union {a,b,shared}");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_overlay_union_shadow);

/// A file created through the overlay lands in the upper layer and is
/// invisible in the lower layer.
fn smoke_overlay_create_lands_in_upper() -> TestResult {
    use crate::{DirOps, FsInstance, MemFs, OverlayFs};
    use alloc::sync::Arc;
    use alloc::vec;

    let lower = Arc::new(MemFs::with_seeds("ov2-lower", &[("base", b"x")]));
    let upper = Arc::new(MemFs::new("ov2-upper"));
    let lower_root = lower.root();
    let upper_root = upper.root();

    let ov = OverlayFs::new("ov2", upper.root(), vec![lower.root() as Arc<dyn DirOps>]);
    let root = ov.root();

    // Create `fresh` via the overlay.
    let created = poll_once_overlay(root.create("fresh"));
    if !matches!(created, Some(Ok(_))) {
        return TestResult::Fail("overlay create(fresh) failed");
    }
    // Write into it and read back through the union.
    if let Some(Ok(f)) = created {
        let w = poll_once_overlay(f.write(0, b"hello"));
        if !matches!(w, Some(Ok(5))) {
            return TestResult::Fail("write to created file failed");
        }
    }

    // Visible in the union.
    if root.lookup("fresh").is_none() {
        return TestResult::Fail("created file not visible in the union");
    }
    // Present in the raw upper layer.
    if upper_root.lookup("fresh").is_none() {
        return TestResult::Fail("created file did not land in upper layer");
    }
    // Absent from the raw lower layer.
    if lower_root.lookup("fresh").is_some() {
        return TestResult::Fail("created file leaked into the read-only lower layer");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_overlay_create_lands_in_upper);

/// Unlinking a lower-only file records a whiteout in upper: the file
/// vanishes from the union while the lower layer itself is untouched.
fn smoke_overlay_whiteout_unlink() -> TestResult {
    use crate::{DirOps, FsInstance, MemFs, OverlayFs, WHITEOUT_PREFIX};
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec;

    let lower = Arc::new(MemFs::with_seeds(
        "ov3-lower",
        &[("keep", b"k"), ("gone", b"g")],
    ));
    let upper = Arc::new(MemFs::new("ov3-upper"));
    let lower_root = lower.root();
    let upper_root = upper.root();

    let ov = OverlayFs::new("ov3", upper.root(), vec![lower.root() as Arc<dyn DirOps>]);
    let root = ov.root();

    // Precondition: both visible in the union.
    if root.lookup("gone").is_none() || root.lookup("keep").is_none() {
        return TestResult::Fail("lower files not visible in the union pre-unlink");
    }

    // Unlink the lower-only file `gone`.
    let r = poll_once_overlay(root.unlink("gone"));
    if !matches!(r, Some(Ok(()))) {
        return TestResult::Fail("overlay unlink(gone) failed");
    }

    // `gone` now invisible in the union; `keep` still visible.
    if root.lookup("gone").is_some() {
        return TestResult::Fail("whited-out file still visible in the union");
    }
    if root.lookup("keep").is_none() {
        return TestResult::Fail("unrelated lower file vanished from the union");
    }

    // The whiteout marker exists in upper; it is itself never enumerated.
    let wh = {
        let mut s = String::from(WHITEOUT_PREFIX);
        s.push_str("gone");
        s
    };
    if upper_root.lookup(&wh).is_none() {
        return TestResult::Fail("no whiteout marker recorded in upper");
    }
    let names = root.enumerate(0, 64);
    if names
        .iter()
        .any(|(n, _)| n == "gone" || n.starts_with(WHITEOUT_PREFIX))
    {
        return TestResult::Fail("enumerate surfaced a whited-out entry or the marker itself");
    }

    // The lower layer itself is untouched — `gone` still there raw.
    if lower_root.lookup("gone").is_none() {
        return TestResult::Fail("read-only lower layer was mutated by the whiteout");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_overlay_whiteout_unlink);

/// Copy-up on write: writing to a lower-only file copies it into upper
/// and directs the write there; the lower stays unmodified.
fn smoke_overlay_copy_up_on_write() -> TestResult {
    use crate::{DirOps, FsInstance, MemFs, OverlayFs};
    use alloc::sync::Arc;
    use alloc::vec;

    let lower = Arc::new(MemFs::with_seeds("ov4-lower", &[("doc", b"original")]));
    let upper = Arc::new(MemFs::new("ov4-upper"));
    let lower_root = lower.root();
    let upper_root = upper.root();

    let ov = OverlayFs::new("ov4", upper.root(), vec![lower.root() as Arc<dyn DirOps>]);
    let root = ov.root();

    // Open the lower-only file through the overlay and overwrite byte 0.
    let f = match root.lookup("doc") {
        Some(f) => f,
        None => return TestResult::Fail("lookup(doc) missed the lower file"),
    };
    let w = poll_once_overlay(f.write(0, b"X"));
    if !matches!(w, Some(Ok(1))) {
        return TestResult::Fail("write to lower-only file did not complete");
    }

    // The union now sees the modified content ("Xriginal").
    let mut buf = [0u8; 16];
    let n = match poll_once_overlay(f.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read-back after copy-up did not complete"),
    };
    if &buf[..n] != b"Xriginal" {
        return TestResult::Fail("copy-up write not reflected on read-back");
    }

    // The copy landed in upper.
    let uf = match upper_root.lookup("doc") {
        Some(f) => f,
        None => return TestResult::Fail("copy-up did not create the upper copy"),
    };
    let n = match poll_once_overlay(uf.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read of upper copy did not complete"),
    };
    if &buf[..n] != b"Xriginal" {
        return TestResult::Fail("upper copy has wrong content after copy-up");
    }

    // The lower layer is untouched — still "original".
    let lf = match lower_root.lookup("doc") {
        Some(f) => f,
        None => return TestResult::Fail("lower file vanished"),
    };
    let n = match poll_once_overlay(lf.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read of lower did not complete"),
    };
    if &buf[..n] != b"original" {
        return TestResult::Fail("copy-up mutated the read-only lower file");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_overlay_copy_up_on_write);

// ── /dev/console + /dev/tty1 terminal ioctls (getty/agetty path) ────────
//
// A distro getty/agetty on the console opens `/dev/tty1` (or /dev/console),
// probes it with a battery of tty/VT/keyboard ioctls, then sets the fg
// pgrp. These smokes pin the DevConsole ioctl surface those probes hit:
// the winsize + fg-pgrp round-trips, and — crucially — that the VT/KD
// probes return a *sane* result (0 or ENOTTY) rather than a bare failure
// that would abort getty. All args are stack pointers accessed through the
// same `write_user_*` helpers the syscall path uses (kernel stack pages are
// supervisor memory, so the SMAP bracket permits access here).

/// Resolve a fresh `/dev/tty1` FileOps (a `DevConsole`) for ioctl tests.
#[cfg(feature = "linux-compat")]
fn open_dev_tty1_for_test() -> Option<alloc::sync::Arc<dyn crate::FileOps>> {
    use crate::{bootstrap_mount_authority, registry, DevFs};
    let auth = bootstrap_mount_authority();
    // Idempotent: a prior smoke may already own this mountpoint.
    let _ = registry().mount(&auth, "/dev/tty-ioctl-test-mount", DevFs::new());
    registry()
        .resolve_absolute("/dev/tty-ioctl-test-mount/tty1", |fs, rel| {
            crate::resolve(fs.root(), rel).ok()
        })
        .flatten()
}

// /dev/tty1 exists and is the singleton console tty (same tty id as
// /dev/console) — getty@tty1 opens it. Also exercises TIOCGWINSZ + the
// TIOCSWINSZ→TIOCGWINSZ round-trip glibc's `TIOCGWINSZ`/`resize` use.
#[cfg(feature = "linux-compat")]
fn smoke_devfs_tty1_is_console_and_winsize_roundtrip() -> TestResult {
    use crate::devfs_pty::{TIOCGWINSZ, TIOCSWINSZ};
    crate::console_tty::__test_reset_cooked();
    let tty1 = match open_dev_tty1_for_test() {
        Some(t) => t,
        None => return TestResult::Fail("resolve /dev/tty1 failed"),
    };
    if tty1.tty_id() != Some(crate::TTY_ID_CONSOLE) {
        return TestResult::Fail("/dev/tty1 is not the console tty");
    }
    // Default TIOCGWINSZ is plausible (non-zero rows/cols).
    let mut ws: [u16; 4] = [0; 4];
    if tty1.ioctl(TIOCGWINSZ, ws.as_mut_ptr() as usize) != Ok(0) {
        return TestResult::Fail("TIOCGWINSZ failed");
    }
    if ws[0] == 0 || ws[1] == 0 {
        return TestResult::Fail("TIOCGWINSZ returned an implausible 0x0 winsize");
    }
    // Set → get round-trip.
    let mut set_ws: [u16; 4] = [40, 100, 0, 0];
    if tty1.ioctl(TIOCSWINSZ, set_ws.as_mut_ptr() as usize) != Ok(0) {
        return TestResult::Fail("TIOCSWINSZ failed");
    }
    let mut got: [u16; 4] = [0; 4];
    if tty1.ioctl(TIOCGWINSZ, got.as_mut_ptr() as usize) != Ok(0) {
        return TestResult::Fail("TIOCGWINSZ (post-set) failed");
    }
    if got[0] != 40 || got[1] != 100 {
        return TestResult::Fail("winsize did not round-trip on /dev/tty1");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "filesystem",
    smoke_devfs_tty1_is_console_and_winsize_roundtrip
);

// TIOCSPGRP → TIOCGPGRP round-trip on /dev/console: getty sets the
// foreground pgrp for the login session; login reads it back.
#[cfg(feature = "linux-compat")]
fn smoke_devfs_console_fg_pgrp_roundtrip() -> TestResult {
    use crate::devfs_pty::{TIOCGPGRP, TIOCSPGRP};
    crate::console_tty::__test_reset_cooked();
    let tty1 = match open_dev_tty1_for_test() {
        Some(t) => t,
        None => return TestResult::Fail("resolve /dev/tty1 failed"),
    };
    let mut set_pgrp: i32 = 4242;
    if tty1.ioctl(TIOCSPGRP, &mut set_pgrp as *mut i32 as usize) != Ok(0) {
        return TestResult::Fail("TIOCSPGRP failed");
    }
    let mut got: i32 = 0;
    if tty1.ioctl(TIOCGPGRP, &mut got as *mut i32 as usize) != Ok(0) {
        return TestResult::Fail("TIOCGPGRP failed");
    }
    if got != 4242 {
        return TestResult::Fail("fg pgrp did not round-trip on /dev/console");
    }
    // A negative pgrp is rejected with EINVAL, not stored.
    let mut bad: i32 = -1;
    if tty1.ioctl(TIOCSPGRP, &mut bad as *mut i32 as usize).is_ok() {
        return TestResult::Fail("TIOCSPGRP accepted a negative pgrp");
    }
    crate::console_tty::__test_reset_cooked();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_devfs_console_fg_pgrp_roundtrip);

// The VT / keyboard probes agetty fires must degrade gracefully: KDGKBMODE
// and KDGETMODE succeed reporting the default text mode (0); the VT_*
// switching ioctls return ENOTTY (Unsupported) so a VT-aware agetty falls
// back to serial mode instead of aborting on a bare failure; TCFLSH/TCSBRK
// succeed as no-ops. None of these may be a bare error the caller can't
// interpret.
#[cfg(feature = "linux-compat")]
fn smoke_devfs_console_vt_kd_probes_degrade() -> TestResult {
    use crate::devfs_pty::{
        KDGETMODE, KDGKBMODE, TCFLSH, TCSBRK, VT_ACTIVATE, VT_GETMODE, VT_GETSTATE, VT_OPENQRY,
        VT_WAITACTIVE,
    };
    crate::console_tty::__test_reset_cooked();
    let tty1 = match open_dev_tty1_for_test() {
        Some(t) => t,
        None => return TestResult::Fail("resolve /dev/tty1 failed"),
    };
    // KDGKBMODE / KDGETMODE succeed and report the default (0).
    for &(cmd, name) in &[(KDGKBMODE, "KDGKBMODE"), (KDGETMODE, "KDGETMODE")] {
        let mut mode: i32 = -7;
        if tty1.ioctl(cmd, &mut mode as *mut i32 as usize) != Ok(0) {
            return TestResult::Fail(name);
        }
        if mode != 0 {
            return TestResult::Fail("KD probe did not report default mode 0");
        }
    }
    // VT switching ioctls are ENOTTY (Unsupported), not a bare -1.
    let mut scratch: i32 = 0;
    let sp = &mut scratch as *mut i32 as usize;
    for &(cmd, name) in &[
        (VT_OPENQRY, "VT_OPENQRY"),
        (VT_GETMODE, "VT_GETMODE"),
        (VT_GETSTATE, "VT_GETSTATE"),
        (VT_ACTIVATE, "VT_ACTIVATE"),
        (VT_WAITACTIVE, "VT_WAITACTIVE"),
    ] {
        match tty1.ioctl(cmd, sp) {
            Err(crate::FsError::Unsupported) => {}
            _ => return TestResult::Fail(name),
        }
    }
    // TCFLSH / TCSBRK succeed as no-ops.
    if tty1.ioctl(TCFLSH, 0) != Ok(0) || tty1.ioctl(TCSBRK, 0) != Ok(0) {
        return TestResult::Fail("TCFLSH/TCSBRK did not succeed as no-ops");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_devfs_console_vt_kd_probes_degrade);
