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
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use narf_capabilities::{Cap, Grant};
    use crate::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };

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

    // Unmounted prefix → None.
    if registry()
        .resolve_absolute("/elsewhere/z", |_, _| ())
        .is_some()
    {
        return TestResult::Fail("non-existent prefix should not resolve");
    }
    // Empty path → None.
    if registry().resolve_absolute("", |_, _| ()).is_some() {
        return TestResult::Fail("empty path should not resolve");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_filesystem_resolve_absolute_picks_longest_prefix);

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
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        match pinned.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    // Mount a MemFs at /test_unlink seeded with one file. The first
    // resolve_parent_absolute → unlink should succeed; the second
    // should hit NotFound (file already gone).
    use narf_capabilities::{Cap, Grant};
    use crate::{bootstrap_mount_authority, registry, FsError, MemFs, MountPoint};

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
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use crate::{bootstrap_mount_authority, registry, DevFs};

    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
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

    let auth = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/dev", DevFs::new());

    // /dev/null: read returns 0; write returns the requested length.
    let null_ops = registry()
        .resolve_absolute("/dev/null", |fs, rel| {
            crate::resolve(fs.root(), rel).ok()
        })
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
        .resolve_absolute("/dev/zero", |fs, rel| {
            crate::resolve(fs.root(), rel).ok()
        })
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
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use crate::{bootstrap_mount_authority, registry, DevFs};

    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
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

    let auth = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/dev", DevFs::new());

    // Each of /dev/random and /dev/urandom must (a) succeed reading
    // 16 bytes and (b) produce a not-all-zero buffer.
    for path in ["/dev/random", "/dev/urandom"] {
        let ops = registry()
            .resolve_absolute(path, |fs, rel| {
                crate::resolve(fs.root(), rel).ok()
            })
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
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use crate::{bootstrap_mount_authority, registry, DevFs};
    use narf_input::{init_global_ring, push_global, InputEvent, KeyCode, KeyEvent, Modifiers};

    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
        fn raw_waker() -> RawWaker {
            unsafe fn no_clone(_: *const ()) -> RawWaker { raw_waker() }
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

    // Make sure the ring exists. Idempotent — production code lights
    // it up at boot via `narf_input::register_initcalls`.
    init_global_ring(64);

    // Drain anything previously queued (other smokes / boot-time
    // events) so the assert below sees only what we push here.
    while narf_input::pop_global().is_some() {}

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
    push_global(InputEvent::Key(KeyEvent { code: KeyCode::H, pressed: true, modifiers: mods_none }));
    push_global(InputEvent::Key(KeyEvent { code: KeyCode::I, pressed: true, modifiers: mods_shift }));
    push_global(InputEvent::Key(KeyEvent { code: KeyCode::Key1, pressed: true, modifiers: mods_none }));
    push_global(InputEvent::Key(KeyEvent { code: KeyCode::Enter, pressed: true, modifiers: mods_none }));
    push_global(InputEvent::Key(KeyEvent { code: KeyCode::H, pressed: false, modifiers: mods_none }));

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
        .resolve_absolute("/dev/null", |fs, rel| {
            crate::resolve(fs.root(), rel).ok()
        })
        .flatten();
    if ops.is_none() {
        return TestResult::Fail("mount_default did not mount /dev");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_filesystem_devfs_mount_default_idempotent);

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
    use crate::posix_access_ok;
    // Root reads + writes anything regardless of perms (POSIX privileged-process rule).
    if !posix_access_ok(1000, 1000, 0o000, 0, 0, true, true, false) {
        return TestResult::Fail("root denied read on perms=000");
    }
    if !posix_access_ok(1000, 1000, 0o000, 0, 0, false, true, false) {
        return TestResult::Fail("root denied write on perms=000");
    }
    // Root exec requires at least one exec bit somewhere.
    if posix_access_ok(1000, 1000, 0o644, 0, 0, false, false, true) {
        return TestResult::Fail("root got exec on perms=644 (no x bit anywhere)");
    }
    if !posix_access_ok(1000, 1000, 0o755, 0, 0, false, false, true) {
        return TestResult::Fail("root denied exec on perms=755");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_posix_access_root_bypass);

fn smoke_fs_posix_access_owner_group_other() -> TestResult {
    use crate::posix_access_ok;
    // File owned by 1000:2000 with perms=0o640 (owner rw-, group r--, other ---).
    // Owner (uid=1000): can read + write, can't exec.
    if !posix_access_ok(1000, 2000, 0o640, 1000, 0, true, true, false) {
        return TestResult::Fail("owner denied legitimate rw");
    }
    if posix_access_ok(1000, 2000, 0o640, 1000, 0, false, false, true) {
        return TestResult::Fail("owner got exec when perms had no x");
    }
    // Group member (gid=2000 but uid != owner): can read, can't write.
    if !posix_access_ok(1000, 2000, 0o640, 1001, 2000, true, false, false) {
        return TestResult::Fail("group member denied read");
    }
    if posix_access_ok(1000, 2000, 0o640, 1001, 2000, false, true, false) {
        return TestResult::Fail("group member got write when group bits forbade it");
    }
    // Other (different uid + gid): no access at all.
    if posix_access_ok(1000, 2000, 0o640, 1001, 2001, true, false, false) {
        return TestResult::Fail("other got read on perms=640 (other=---)");
    }
    // Other with perms=0o644 → other can read but not write.
    if !posix_access_ok(1000, 2000, 0o644, 1001, 2001, true, false, false) {
        return TestResult::Fail("other denied read on perms=644");
    }
    if posix_access_ok(1000, 2000, 0o644, 1001, 2001, false, true, false) {
        return TestResult::Fail("other got write on perms=644");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_fs_posix_access_owner_group_other);

fn smoke_fs_resolve_rejects_empty_path() -> TestResult {
    // resolve() rejects empty paths with InvalidPath.
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use crate::{resolve, DirEntry, DirOps, FileOps, FsError};
    struct EmptyDir;
    impl DirOps for EmptyDir {
        fn lookup(&self, _: &str) -> Option<Arc<dyn FileOps>> { None }
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
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use crate::{resolve, DirEntry, DirOps, FileOps, FsError};
    struct EmptyDir;
    impl DirOps for EmptyDir {
        fn lookup(&self, _: &str) -> Option<Arc<dyn FileOps>> { None }
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
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use crate::{resolve, DirEntry, DirOps, FileOps, FsError};
    struct EmptyDir;
    impl DirOps for EmptyDir {
        fn lookup(&self, _: &str) -> Option<Arc<dyn FileOps>> { None }
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
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    use crate::{resolve, DirEntry, DirOps, FileOps, FsFuture, Mode, Stat};

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
            Stat { size: 0, blocks: 0, mode: Mode::FILE_RO, mtime_cycles: 0 }
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
kernel_test_in!("filesystem", smoke_fs_resolve_tolerates_redundant_separators_and_dot);

fn smoke_fs_page_cache_lookup_missing_is_none() -> TestResult {
    use crate::{PageCache, PageKey};
    let pc = PageCache::new();
    let k = PageKey { fs_id: 99, inode: 99, page_off: 99 };
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
    let k = PageKey { fs_id: 1, inode: 1, page_off: 0 };
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
    let k = PageKey { fs_id: 1, inode: 1, page_off: 0 };
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
kernel_test_in!("filesystem", smoke_fs_registry_unmount_revoked_handle_rejected);

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
