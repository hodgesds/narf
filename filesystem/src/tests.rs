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

    // Pick a time that yields non-zero tv_sec AND tv_usec when split as
    // microseconds (sec = time / 1e6, usec = time % 1e6).
    let now = 2_000_500u64;
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
