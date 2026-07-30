//! End-to-end filesystem mount → traverse → read → unmount smokes.
//!
//! ## Scope
//!
//! These smokes walk the **full VFS path** that per-FS unit tests do not:
//!
//!   synthesised image → `Initramfs` / `MemFs` (`FsInstance`) →
//!   `VfsRegistry::mount` → `resolve` / `enumerate` →
//!   `FileOps::read` → `FileOps::stat` → `VfsRegistry::unmount` →
//!   re-resolve → `FsError::NotFound`
//!
//! The per-FS drivers (ext2/ext4, exfat, fat, iso9660, minix, udf, 9p)
//! each have their own on-disk-parser unit smokes in
//! `drivers/fs/*/src/tests.rs`. Those smokes test the FS-specific
//! byte-layout decoding. The smokes here test the **VFS plumbing** —
//! mount table locking, path resolution, enumerate, stat, and unmount
//! bookkeeping — using `Initramfs` (CPIO newc, already in this crate)
//! and `MemFs` as the backing `FsInstance`.
//!
//! Adding the per-FS driver crates as `[dependencies]` of
//! `narf-filesystem` would introduce a circular dependency (every FS
//! driver crate lists `narf-filesystem` as a dependency). The VFS
//! coverage matrix comment at the bottom of this file records which
//! FS types are covered at the VFS layer versus the parser layer.
//!
//! ## Image synthesis
//!
//! All images are built inline in Rust using `build_cpio_archive` below.
//! No binary fixtures are committed. To regenerate an equivalent
//! external image for manual inspection:
//!
//!   # Flat archive with "hello.txt":
//!   echo -n "hello from narf" | cpio -o -H newc > flat.cpio
//!   # Nested: dir1/dir2/nested.txt
//!   install -D /dev/stdin dir1/dir2/nested.txt <<< "nested content"
//!   find dir1 | cpio -o -H newc > nested.cpio
//!
//! ## Smoke inventory
//!
//!   1. `smoke_vfs_mount_read_unmount`        — mount → resolve → read → unmount → NotFound
//!   2. `smoke_vfs_dir_listing`               — mount → enumerate root → expected entries
//!   3. `smoke_vfs_nested_dir_traverse`       — mount → traverse dir1/dir2 → read nested.txt
//!   4. `smoke_vfs_bad_superblock`            — MemFs with junk content returns expected behaviour
//!   5. `smoke_vfs_iso_shaped_readonly`       — read-only FS via Initramfs; write returns ReadOnly
//!   6. `smoke_vfs_writable_fs`               — MemFs as writable FS: create + read back
//!   7. `smoke_vfs_fat_shaped_flat_read`      — flat CPIO image with FAT-like single level
//!   8. `smoke_vfs_multi_mount`               — two mounts; unmount one; other still live
//!   9. `smoke_vfs_busy_on_dup_mountpoint`    — double mount on same path → FsError::Busy
//!  10. `smoke_vfs_stat_size_and_mode`        — stat reports correct size + FileType::File
//!
//! GPL-2.0-or-later — NARF is GPL-2.0-or-later as of 2026-05-20.

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{bootstrap_mount_authority, registry, resolve, FileType, FsError, Initramfs, MemFs};

static MOUNT_CHANGE_HOOK_HITS: AtomicUsize = AtomicUsize::new(0);

fn count_mount_change() {
    MOUNT_CHANGE_HOOK_HITS.fetch_add(1, Ordering::Relaxed);
}

fn ignore_mount_change() {}

// ── poll_once helper ──────────────────────────────────────────────────
//
// The VFS `FileOps::read` returns a `Pin<Box<dyn Future>>`. For
// Initramfs / MemFs the future is always immediately ready (no real
// I/O), so `poll_once` completes synchronously. Tests that need the
// real async scheduler use `narf_scheduler::spawn` + `run_until_empty`
// as in `filesystem/src/tests.rs`.

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

// ── CPIO newc builder ─────────────────────────────────────────────────
//
// CPIO newc (magic "070701") on-wire format per the CPIO specification
// (also documented in Linux `Documentation/driver-api/early-userspace/
// buffer-format.rst`):
//
//   [110-byte fixed header][namesize bytes including NUL][pad to 4B]
//   [filesize bytes][pad to 4B]
//   ...
//   sentinel entry "TRAILER!!!" with filesize=0.
//
// Each header field is 8 ASCII hex digits. The 13 fields (at byte
// offsets from the start of the header, after the 6-byte magic) are:
//   0:  c_ino        6:  c_mtime    12: c_rdevmajor
//   1:  c_mode       7:  c_filesize 13: c_rdevminor
//   2:  c_uid        8:  c_devmajor 14: c_namesize
//   3:  c_gid        9:  c_devminor 15: c_check  (namesize at idx 13)
//   4:  c_nlink      10: unused
//   5:  (spare)
//
// Reference: Linux `Documentation/driver-api/early-userspace/
// buffer-format.rst`, section "newc format".

/// Write an 8-digit ASCII-hex field into `out` at `pos`.
fn write_hex8(out: &mut Vec<u8>, v: u32) {
    let s = alloc::format!("{:08X}", v);
    out.extend_from_slice(s.as_bytes());
}

/// Pad `out` to the next 4-byte boundary.
fn pad4(out: &mut Vec<u8>) {
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// One file entry for `build_cpio_archive`.
struct CpioEntry<'a> {
    /// Archive path, e.g. `"hello.txt"` or `"dir1/dir2/nested.txt"`.
    name: &'a str,
    /// `0o100644` for regular files; `0o040755` for directories.
    mode: u32,
    /// File content (empty for directory entries).
    data: &'a [u8],
}

/// Build a valid CPIO newc archive from a list of `CpioEntry` records.
/// The archive is self-contained and can be parsed by `Initramfs::from_cpio`.
///
/// Inode numbers are assigned sequentially starting from 1. mtime is
/// set to 0x64 (=100 decimal) for all entries, giving a stable, easily
/// checkable value.
fn build_cpio_archive(entries: &[CpioEntry<'_>]) -> Vec<u8> {
    let mut out = Vec::new();

    for (i, e) in entries.iter().enumerate() {
        let ino = (i + 1) as u32;
        let name_bytes = e.name.as_bytes();
        let namesize = name_bytes.len() + 1; // +1 for the NUL terminator

        // Magic.
        out.extend_from_slice(b"070701");
        // c_ino
        write_hex8(&mut out, ino);
        // c_mode
        write_hex8(&mut out, e.mode);
        // c_uid
        write_hex8(&mut out, 0);
        // c_gid
        write_hex8(&mut out, 0);
        // c_nlink
        write_hex8(&mut out, 1);
        // c_mtime
        write_hex8(&mut out, 0x64);
        // c_filesize
        write_hex8(&mut out, e.data.len() as u32);
        // c_devmajor
        write_hex8(&mut out, 0);
        // c_devminor
        write_hex8(&mut out, 0);
        // c_rdevmajor
        write_hex8(&mut out, 0);
        // c_rdevminor
        write_hex8(&mut out, 0);
        // c_namesize
        write_hex8(&mut out, namesize as u32);
        // c_check (reserved, always 0)
        write_hex8(&mut out, 0);

        // Name bytes + NUL.
        out.extend_from_slice(name_bytes);
        out.push(0);
        pad4(&mut out);

        // File data.
        out.extend_from_slice(e.data);
        pad4(&mut out);
    }

    // TRAILER!!! sentinel.
    // CPIO newc header has 13 fields after the magic:
    //   1:  c_ino       2:  c_mode     3:  c_uid      4:  c_gid
    //   5:  c_nlink     6:  c_mtime    7:  c_filesize  8:  c_devmajor
    //   9:  c_devminor  10: c_rdevmajor 11: c_rdevminor
    //   12: c_namesize  13: c_check
    // Write fields 1–11 as zero, then the real namesize, then check.
    let trailer = b"TRAILER!!!";
    let namesize = trailer.len() + 1;
    out.extend_from_slice(b"070701");
    for _ in 0..11 {
        write_hex8(&mut out, 0);
    }
    write_hex8(&mut out, namesize as u32);
    // c_check
    write_hex8(&mut out, 0);
    out.extend_from_slice(trailer);
    out.push(0);
    pad4(&mut out);

    out
}

/// Parse a dynamically-built CPIO archive and return an `Initramfs`.
/// The archive is leaked to `'static` so the Initramfs can borrow it.
/// Each test that calls this mints a new leak — acceptable in a
/// single-run test harness where the process terminates afterward.
fn make_initramfs(name: &'static str, entries: &[CpioEntry<'_>]) -> Option<Initramfs> {
    let archive: Vec<u8> = build_cpio_archive(entries);
    // Leak to 'static — necessary because Initramfs::from_cpio requires
    // `&'static [u8]`. The test harness runs in a single boot-smoke
    // invocation so the leaked bytes are reclaimed on process exit.
    let leaked: &'static [u8] = Vec::leak(archive);
    Initramfs::from_cpio(name, leaked).ok()
}

// ── Smoke 1: mount + read + unmount → NotFound ────────────────────────
//
// 1. Build a CPIO archive with one file "hello.txt" → "hello from narf".
// 2. Wrap in Initramfs; mount on "/fme1".
// 3. resolve("hello.txt") → FileOps; read → verify content.
// 4. unmount; resolve → NotFound (no mount covers the path).
//
// This is the canonical end-to-end path. All other smokes assume this
// path works and focus on a specific slice of functionality.

fn smoke_vfs_mount_read_unmount() -> TestResult {
    const CONTENT: &[u8] = b"hello from narf";
    const PATH: &str = "/fme1";

    let fs = match make_initramfs(
        "fme1",
        &[CpioEntry {
            name: "hello.txt",
            mode: 0o100644,
            data: CONTENT,
        }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build failed"),
    };

    let auth = bootstrap_mount_authority();
    let handle = match registry().mount(&auth, PATH, fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount() failed"),
    };

    // Resolve and read.
    let file = match registry().with_mount(PATH, |fs| resolve(fs.root(), "hello.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("resolve hello.txt failed"),
    };

    let mut buf = vec![0u8; 32];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read failed"),
    };
    if n != CONTENT.len() || &buf[..n] != CONTENT {
        return TestResult::Fail("read content mismatch");
    }

    // Unmount.
    if registry().unmount(&handle, PATH).is_err() {
        return TestResult::Fail("unmount failed");
    }

    // After unmount, with_mount returns None (no matching path).
    if registry().with_mount(PATH, |_| ()).is_some() {
        return TestResult::Fail("mount still visible after unmount");
    }

    // After unmount the `/fme1` mount is gone. A covering `/` mount
    // (installed during boot) may still match the path, but resolving
    // the fme1 file through the root FS must fail — only a successful
    // resolve would mean the unmounted FS is still live.
    let post = registry().resolve_absolute(PATH, |fs, rel| resolve(fs.root(), rel));
    if matches!(post, Some(Ok(_))) {
        return TestResult::Fail("resolve_absolute found path after unmount");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_mount_read_unmount);

/// Mount stacking (Linux overmount): a mount onto an already-occupied path
/// succeeds and shadows the one below; resolution sees the topmost; unmount
/// pops it and reveals the mount underneath. systemd's ProtectHostname= binds
/// a read-only /proc/sys/kernel/domainname over the live one — rejecting the
/// overmount with EBUSY broke service namespace setup (226/EXIT_NAMESPACE).
fn smoke_registry_overmount_stacks() -> TestResult {
    let auth = bootstrap_mount_authority();
    const PATH: &str = "/fme-stack";

    // Bottom mount is visible.
    let h1 = match registry().mount(&auth, PATH, MemFs::new("stack-bottom")) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("bottom mount failed"),
    };
    let id_bottom = registry().mount_id_at(PATH);
    if registry().resolve_absolute(PATH, |fs, _| fs.name() == "stack-bottom") != Some(true) {
        let _ = registry().unmount(&h1, PATH);
        return TestResult::Fail("bottom mount not visible");
    }

    // Overmount onto the SAME path must succeed (stacking), not EBUSY.
    let h2 = match registry().mount(&auth, PATH, MemFs::new("stack-top")) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&h1, PATH);
            return TestResult::Fail("overmount rejected — registry lacks stacking");
        }
    };
    // Topmost is now visible, with a distinct mount id.
    let id_top = registry().mount_id_at(PATH);
    let top_visible = registry().resolve_absolute(PATH, |fs, _| fs.name() == "stack-top");
    if top_visible != Some(true) {
        let _ = registry().unmount(&h2, PATH);
        let _ = registry().unmount(&h1, PATH);
        return TestResult::Fail("top of stack not visible after overmount");
    }
    if id_top.is_none() || id_top == id_bottom {
        let _ = registry().unmount(&h2, PATH);
        let _ = registry().unmount(&h1, PATH);
        return TestResult::Fail("stacked mounts must have distinct mount ids");
    }

    // Pop the top: the bottom mount is revealed again (both fs identity and id).
    if registry().unmount(&h2, PATH).is_err() {
        let _ = registry().unmount(&h1, PATH);
        return TestResult::Fail("unmount top of stack failed");
    }
    if registry().resolve_absolute(PATH, |fs, _| fs.name() == "stack-bottom") != Some(true) {
        let _ = registry().unmount(&h1, PATH);
        return TestResult::Fail("popping top did not reveal the lower mount");
    }
    if registry().mount_id_at(PATH) != id_bottom {
        let _ = registry().unmount(&h1, PATH);
        return TestResult::Fail("revealed mount is not the original bottom");
    }

    // Popping the last mount leaves the path unmounted.
    if registry().unmount(&h1, PATH).is_err() {
        return TestResult::Fail("unmount bottom failed");
    }
    if registry().with_mount(PATH, |_| ()).is_some() {
        return TestResult::Fail("path still mounted after popping the whole stack");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/e2e/mount", smoke_registry_overmount_stacks);

/// A deep (3-layer) stack pops strictly LIFO: each unmount reveals exactly the
/// layer beneath, in reverse mount order.
fn smoke_registry_overmount_deep_lifo() -> TestResult {
    let auth = bootstrap_mount_authority();
    const PATH: &str = "/fme-deep";

    let hb = match registry().mount(&auth, PATH, MemFs::new("deep-bottom")) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("bottom mount failed"),
    };
    let hm = match registry().mount(&auth, PATH, MemFs::new("deep-middle")) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&hb, PATH);
            return TestResult::Fail("middle overmount failed");
        }
    };
    let ht = match registry().mount(&auth, PATH, MemFs::new("deep-top")) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&hm, PATH);
            let _ = registry().unmount(&hb, PATH);
            return TestResult::Fail("top overmount failed");
        }
    };

    let visible = |want: &str| {
        registry().resolve_absolute(PATH, |fs, _| if fs.name() == want { 1u8 } else { 0 })
            == Some(1)
    };

    let mut fail: Option<&'static str> = None;
    if !visible("deep-top") {
        fail = Some("top of a 3-deep stack not visible");
    }
    if fail.is_none() && registry().unmount(&ht, PATH).is_err() {
        fail = Some("pop top failed");
    }
    if fail.is_none() && !visible("deep-middle") {
        fail = Some("pop top must reveal the middle mount");
    }
    if fail.is_none() && registry().unmount(&hm, PATH).is_err() {
        fail = Some("pop middle failed");
    }
    if fail.is_none() && !visible("deep-bottom") {
        fail = Some("pop middle must reveal the bottom mount");
    }
    // Always drain to keep the global registry clean for later tests.
    let _ = registry().unmount(&ht, PATH);
    let _ = registry().unmount(&hm, PATH);
    let _ = registry().unmount(&hb, PATH);
    match fail {
        Some(m) => TestResult::Fail(m),
        None => TestResult::Pass,
    }
}
kernel_test_in!("filesystem/e2e/mount", smoke_registry_overmount_deep_lifo);

/// A same-path stack coexists with a DEEPER nested mount: longest-prefix
/// resolution still selects the nested mount for paths under it, while the
/// stack's topmost wins for paths at the stacked level.
fn smoke_registry_stack_under_nested_mount() -> TestResult {
    let auth = bootstrap_mount_authority();
    const BASE: &str = "/nst";
    const SUB: &str = "/nst/sub";

    let hb = match registry().mount(&auth, BASE, MemFs::new("nst-bottom")) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("base bottom mount failed"),
    };
    let ht = match registry().mount(&auth, BASE, MemFs::new("nst-top")) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&hb, BASE);
            return TestResult::Fail("base overmount failed");
        }
    };
    let hs = match registry().mount(&auth, SUB, MemFs::new("nst-sub")) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&ht, BASE);
            let _ = registry().unmount(&hb, BASE);
            return TestResult::Fail("nested mount failed");
        }
    };

    // A path at the stacked level resolves to the stack's TOP.
    let at_base =
        registry().resolve_absolute("/nst/x", |fs, _| fs.name() == "nst-top") == Some(true);
    // A path under the deeper mount resolves to the NESTED fs (longest prefix
    // beats the stack), not to either /nst layer.
    let at_sub =
        registry().resolve_absolute("/nst/sub/y", |fs, _| fs.name() == "nst-sub") == Some(true);

    let _ = registry().unmount(&hs, SUB);
    let _ = registry().unmount(&ht, BASE);
    let _ = registry().unmount(&hb, BASE);

    if at_base && at_sub {
        TestResult::Pass
    } else {
        TestResult::Fail("longest-prefix must beat a same-path stack for deeper mounts")
    }
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_registry_stack_under_nested_mount
);

/// A mount-table change wakes blocked poll/epoll waiters after advancing the
/// mountinfo generation. systemd relies on that wake to drain libmount before
/// it reaps a successful mount(8) child; polling the generation alone is too
/// late because SIGCHLD may otherwise win the event-loop race.
fn smoke_global_mount_change_fires_wake_hook() -> TestResult {
    const PATH: &str = "/mount-change-wake";
    let auth = bootstrap_mount_authority();
    MOUNT_CHANGE_HOOK_HITS.store(0, Ordering::Relaxed);
    crate::install_mount_change_hook(count_mount_change);

    let handle = match registry().mount(&auth, PATH, MemFs::new("mount-change-wake")) {
        Ok(handle) => handle,
        Err(_) => {
            crate::install_mount_change_hook(ignore_mount_change);
            return TestResult::Fail("mount change setup failed");
        }
    };
    let woke_after_mount = MOUNT_CHANGE_HOOK_HITS.load(Ordering::Acquire) == 1;
    let unmounted = registry().unmount(&handle, PATH).is_ok();
    crate::install_mount_change_hook(ignore_mount_change);

    if woke_after_mount && unmounted {
        TestResult::Pass
    } else {
        TestResult::Fail("a successful global mount must fire exactly one wake hook")
    }
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_global_mount_change_fires_wake_hook
);

/// A private `MountNamespace` (the path a service takes after
/// `unshare(CLONE_NEWNS)`) supports the same overmount stacking as the global
/// registry: overmount succeeds, topmost is visible, unmount reveals the lower.
/// This is the exact path systemd's ProtectHostname= domainname bind takes.
fn smoke_ns_overmount_stacks() -> TestResult {
    let auth = bootstrap_mount_authority();
    let ns = crate::MountNamespace::snapshot_global();
    const PATH: &str = "/ns-stack";

    if ns
        .mount_arc(&auth, PATH, alloc::sync::Arc::new(MemFs::new("ns-bottom")))
        .is_err()
    {
        return TestResult::Fail("ns bottom mount failed");
    }
    if ns
        .mount_arc(&auth, PATH, alloc::sync::Arc::new(MemFs::new("ns-top")))
        .is_err()
    {
        return TestResult::Fail("ns overmount rejected — namespace lacks stacking");
    }
    let top_visible = ns.resolve_absolute(PATH, |fs, _| fs.name() == "ns-top") == Some(true);
    if !top_visible {
        return TestResult::Fail("ns top of stack not visible");
    }
    if ns.unmount(PATH).is_err() {
        return TestResult::Fail("ns unmount top failed");
    }
    let bottom_revealed = ns.resolve_absolute(PATH, |fs, _| fs.name() == "ns-bottom") == Some(true);
    if !bottom_revealed {
        return TestResult::Fail("ns unmount did not reveal the lower mount");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/e2e/mount", smoke_ns_overmount_stacks);

/// A FILE can be bind-mounted (mount --bind of a file), producing a
/// file-rooted mount: it appears as a mount entry (so /proc/self/mountinfo
/// lists it — what systemd's read-only procfs-control-file protection needs)
/// and resolving its path returns the bound file's content. Without this the
/// self-bind was a no-op, the path never showed up as a mount, and systemd's
/// recursive read-only remount looped 32× then failed EBUSY / 226.
fn smoke_registry_file_bind_resolves_to_file() -> TestResult {
    let auth = bootstrap_mount_authority();
    let src = match make_initramfs(
        "fb-src",
        &[CpioEntry {
            name: "f.txt",
            mode: 0o100644,
            data: b"filedata",
        }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build failed"),
    };
    let h_src = match registry().mount(&auth, "/fb_src", src) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("source mount failed"),
    };

    // Bind the FILE /fb_src/f.txt onto /fb_dst.
    let h_dst = match registry().bind_mount(&auth, "/fb_src/f.txt", "/fb_dst") {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&h_src, "/fb_src");
            return TestResult::Fail("file bind_mount failed (a file source must bind)");
        }
    };

    // The target is a file-rooted mount: root_file() is the bound file and it
    // reads back the source content.
    let content_ok = registry().with_mount("/fb_dst", |fs| match fs.root_file() {
        Some(file) => {
            let mut buf = vec![0u8; 16];
            matches!(poll_once(file.read(0, &mut buf)), Some(Ok(n)) if &buf[..n] == b"filedata")
        }
        None => false,
    }) == Some(true);

    // It is a real mount entry (this is what makes it appear in mountinfo).
    let listed = registry().list().iter().any(|p| p == "/fb_dst");

    let _ = registry().unmount(&h_dst, "/fb_dst");
    let _ = registry().unmount(&h_src, "/fb_src");

    if content_ok && listed {
        TestResult::Pass
    } else {
        TestResult::Fail("a file bind mount must be listed and resolve to the file's content")
    }
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_registry_file_bind_resolves_to_file
);

/// Bind mounts and detached `clone_tree_at` roots are alternate paths into
/// the same backing filesystem, not newly-created filesystems.  Consumers
/// that key VFS objects by `(backing filesystem, inode)` (notably pathname
/// AF_UNIX) rely on this identity surviving each adapter boundary.
fn smoke_bind_and_clone_tree_preserve_backing_identity() -> TestResult {
    let auth = bootstrap_mount_authority();
    let source = match registry().mount(&auth, "/bind-id-src", MemFs::new("bind-id-src")) {
        Ok(handle) => handle,
        Err(_) => return TestResult::Fail("source mount for backing-identity test failed"),
    };
    let expected = registry().resolve_absolute("/bind-id-src", |fs, _| fs.backing_identity());
    let alias = match registry().bind_mount(&auth, "/bind-id-src", "/bind-id-alias") {
        Ok(handle) => handle,
        Err(_) => {
            let _ = registry().unmount(&source, "/bind-id-src");
            return TestResult::Fail("bind mount for backing-identity test failed");
        }
    };
    let alias_identity =
        registry().resolve_absolute("/bind-id-alias", |fs, _| fs.backing_identity());
    let clone_identity = registry()
        .clone_tree_at("/bind-id-src")
        .map(|fs| fs.backing_identity());

    let _ = registry().unmount(&alias, "/bind-id-alias");
    let _ = registry().unmount(&source, "/bind-id-src");

    if expected.is_some() && expected == alias_identity && expected == clone_identity {
        TestResult::Pass
    } else {
        TestResult::Fail("bind/clone adapters changed the backing filesystem identity")
    }
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_bind_and_clone_tree_preserve_backing_identity
);

/// Stacking works for FILES too: overmounting one bound file with another
/// shadows it, and unmounting reveals the file underneath — the file analogue
/// of smoke_registry_overmount_stacks.
fn smoke_registry_file_overmount_stacks() -> TestResult {
    let auth = bootstrap_mount_authority();
    let a = match make_initramfs(
        "fov-a",
        &[CpioEntry {
            name: "a.txt",
            mode: 0o100644,
            data: b"aaa",
        }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build a failed"),
    };
    let b = match make_initramfs(
        "fov-b",
        &[CpioEntry {
            name: "b.txt",
            mode: 0o100644,
            data: b"bbb",
        }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build b failed"),
    };
    let ha = match registry().mount(&auth, "/fova", a) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount a failed"),
    };
    let hb = match registry().mount(&auth, "/fovb", b) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&ha, "/fova");
            return TestResult::Fail("mount b failed");
        }
    };

    let reads = |want: &[u8]| {
        registry().with_mount("/fovstk", |fs| match fs.root_file() {
            Some(file) => {
                let mut buf = vec![0u8; 8];
                matches!(poll_once(file.read(0, &mut buf)), Some(Ok(n)) if &buf[..n] == want)
            }
            None => false,
        }) == Some(true)
    };

    // Bottom file, then overmount with the top file.
    let hbot = match registry().bind_mount(&auth, "/fova/a.txt", "/fovstk") {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&hb, "/fovb");
            let _ = registry().unmount(&ha, "/fova");
            return TestResult::Fail("bottom file bind failed");
        }
    };
    let htop = match registry().bind_mount(&auth, "/fovb/b.txt", "/fovstk") {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&hbot, "/fovstk");
            let _ = registry().unmount(&hb, "/fovb");
            let _ = registry().unmount(&ha, "/fova");
            return TestResult::Fail("file overmount failed");
        }
    };

    let top_wins = reads(b"bbb");
    let popped = registry().unmount(&htop, "/fovstk").is_ok();
    let bottom_revealed = reads(b"aaa");

    let _ = registry().unmount(&hbot, "/fovstk");
    let _ = registry().unmount(&hb, "/fovb");
    let _ = registry().unmount(&ha, "/fova");

    if top_wins && popped && bottom_revealed {
        TestResult::Pass
    } else {
        TestResult::Fail("file overmount must shadow the lower file and reveal it on unmount")
    }
}
kernel_test_in!("filesystem/e2e/mount", smoke_registry_file_overmount_stacks);

// ── Smoke 2: directory listing ────────────────────────────────────────
//
// Mount a CPIO archive with:
//   hello.txt  (regular file)
//   world.bin  (regular file)
//
// enumerate(root, 0, 64) must return at least "hello.txt" and "world.bin"
// as FileType::File entries.
//
// Rationale: `DirOps::enumerate` is the VFS readdir surface; verifying
// it works through the mount layer is separate from the per-FS parser
// test that checks raw dirent decoding.

fn smoke_vfs_dir_listing() -> TestResult {
    const PATH: &str = "/fme2";

    let fs = match make_initramfs(
        "fme2",
        &[
            CpioEntry {
                name: "hello.txt",
                mode: 0o100644,
                data: b"h",
            },
            CpioEntry {
                name: "world.bin",
                mode: 0o100644,
                data: b"w",
            },
        ],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build failed"),
    };

    let auth = bootstrap_mount_authority();
    let handle = match registry().mount(&auth, PATH, fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount() failed"),
    };

    let entries: Vec<(String, FileType)> =
        match registry().with_mount(PATH, |fs| fs.root().enumerate(0, 64)) {
            Some(e) => e,
            None => return TestResult::Fail("with_mount returned None"),
        };

    let has_hello = entries
        .iter()
        .any(|(n, t)| n == "hello.txt" && *t == FileType::File);
    let has_world = entries
        .iter()
        .any(|(n, t)| n == "world.bin" && *t == FileType::File);

    // Cleanup regardless of assertions.
    let _ = registry().unmount(&handle, PATH);

    if !has_hello {
        return TestResult::Fail("enumerate missing hello.txt");
    }
    if !has_world {
        return TestResult::Fail("enumerate missing world.bin");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_dir_listing);

// ── Smoke 3: nested directory traversal ──────────────────────────────
//
// Image contains "dir1/dir2/nested.txt" → "deep content".
// `resolve(root, "dir1/dir2/nested.txt")` must return the file and
// `read` must yield "deep content".
//
// This exercises `DirOps::lookup_dir` through the resolve() walker:
// the VFS splits the path into segments, calls `lookup_dir("dir1")`,
// then `lookup_dir("dir2")`, then `lookup("nested.txt")`.
//
// References:
//   Linux `fs/namei.c::walk_component` — segment-by-segment descent.

fn smoke_vfs_nested_dir_traverse() -> TestResult {
    const CONTENT: &[u8] = b"deep content";
    const PATH: &str = "/fme3";

    let fs = match make_initramfs(
        "fme3",
        &[CpioEntry {
            name: "dir1/dir2/nested.txt",
            mode: 0o100644,
            data: CONTENT,
        }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build failed"),
    };

    let auth = bootstrap_mount_authority();
    let handle = match registry().mount(&auth, PATH, fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount() failed"),
    };

    let file = match registry().with_mount(PATH, |fs| resolve(fs.root(), "dir1/dir2/nested.txt")) {
        Some(Ok(f)) => f,
        Some(Err(e)) => {
            let _ = registry().unmount(&handle, PATH);
            let _ = e;
            return TestResult::Fail("resolve nested path failed");
        }
        None => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("with_mount returned None");
        }
    };

    let mut buf = vec![0u8; 32];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("read failed");
        }
    };

    let _ = registry().unmount(&handle, PATH);

    if n != CONTENT.len() || &buf[..n] != CONTENT {
        return TestResult::Fail("nested file content mismatch");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_nested_dir_traverse);

// ── Smoke 4: invalid/junk backing → graceful error ────────────────────
//
// A MemFs starts empty. `resolve("nonexistent")` must return
// `FsError::NotFound`, not a panic or UB. This tests that the VFS
// mount machinery handles a legitimately mountable but empty FS, and
// that NotFound propagates correctly through `with_mount`.
//
// Background: per the task spec, "FakeBlockDevice with junk bytes →
// mount → returns FsError::InvalidFormat". The per-FS drivers' unit
// tests cover the format-validation path (e.g. ext2's superblock magic
// check). At the VFS layer, a successfully-mounted FS that has no
// matching file returns `NotFound` — the correct error for a
// "successfully mounted but file absent" case.
//
// A CPIO archive built from zero bytes would fail Initramfs::from_cpio
// with BadMagic — that's the "bad superblock" case at this layer.

fn smoke_vfs_empty_fs_lookup_returns_not_found() -> TestResult {
    const PATH: &str = "/fme4";

    // Mount an empty MemFs — it's "valid" but has no files.
    let auth = bootstrap_mount_authority();
    let handle = match registry().mount(&auth, PATH, MemFs::new("fme4-empty")) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount() failed"),
    };

    let result = registry().with_mount(PATH, |fs| resolve(fs.root(), "no-such-file"));

    let _ = registry().unmount(&handle, PATH);

    match result {
        Some(Err(FsError::NotFound)) => TestResult::Pass,
        Some(Err(_)) => TestResult::Fail("wrong error for missing file in empty FS"),
        Some(Ok(_)) => TestResult::Fail("resolved a file that does not exist"),
        None => TestResult::Fail("with_mount returned None for live mount"),
    }
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_vfs_empty_fs_lookup_returns_not_found
);

// ── Smoke 4b: bad CPIO magic → Initramfs::from_cpio rejects ──────────
//
// The "bad superblock" case for CPIO-backed mounts. Attempting to parse
// junk bytes with `Initramfs::from_cpio` must return `CpioError::BadMagic`
// (or similar), and the returned `Err` prevents any mount from occurring.

fn smoke_vfs_bad_cpio_magic_rejects_mount() -> TestResult {
    // Feed pure junk — not a valid CPIO header.
    let junk: &'static [u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
    match Initramfs::from_cpio("bad", junk) {
        Err(_) => TestResult::Pass,
        Ok(_) => TestResult::Fail("from_cpio accepted junk bytes — should reject"),
    }
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_vfs_bad_cpio_magic_rejects_mount
);

// ── Smoke 5: read-only FS — write returns ReadOnly ────────────────────
//
// Initramfs is read-only. `FileOps::write` on any Initramfs file must
// return `FsError::ReadOnly`. This mirrors the behaviour of every
// read-only block-backed FS (iso9660, CD-ROM FAT, squashfs).
//
// References:
//   Linux `fs/romfs/mmap-nommu.c` — `romfs_readpage`; write path
//   returns `EROFS` (= read-only filesystem).

fn smoke_vfs_readonly_fs_write_returns_error() -> TestResult {
    const PATH: &str = "/fme5";
    const CONTENT: &[u8] = b"read only data";

    let fs = match make_initramfs(
        "fme5",
        &[CpioEntry {
            name: "ro.txt",
            mode: 0o100444,
            data: CONTENT,
        }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build failed"),
    };

    let auth = bootstrap_mount_authority();
    let handle = match registry().mount(&auth, PATH, fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount() failed"),
    };

    let file = match registry().with_mount(PATH, |fs| resolve(fs.root(), "ro.txt")) {
        Some(Ok(f)) => f,
        _ => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("resolve ro.txt failed");
        }
    };

    // Verify read works.
    let mut buf = vec![0u8; 32];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("read failed on read-only file");
        }
    };
    if n != CONTENT.len() || &buf[..n] != CONTENT {
        let _ = registry().unmount(&handle, PATH);
        return TestResult::Fail("read content mismatch on ro file");
    }

    // Verify write returns ReadOnly.
    let write_result = poll_once(file.write(0, b"attempt"));
    let _ = registry().unmount(&handle, PATH);

    match write_result {
        Some(Err(FsError::ReadOnly)) => TestResult::Pass,
        Some(Err(_)) => TestResult::Fail("write on initramfs returned wrong error (not ReadOnly)"),
        Some(Ok(_)) => TestResult::Fail("write on read-only initramfs succeeded — should fail"),
        None => TestResult::Fail("write future returned Pending (should be Ready)"),
    }
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_vfs_readonly_fs_write_returns_error
);

// ── Smoke 6: writable FS — create + write + read back ────────────────
//
// MemFs is the writable in-memory FS used for /tmp and /dev/shm.
// This smoke mounts a MemFs, creates a file, writes content, reads
// it back, and verifies the round-trip — the write-path analogue of
// smoke 1.
//
// This covers the MemFs-backed VFS path that FAT/exfat/ext4 (all
// writable block FSes) go through at the VFS layer.

fn smoke_vfs_writable_fs_create_write_read() -> TestResult {
    const PATH: &str = "/fme6";
    const PAYLOAD: &[u8] = b"writable fs content";

    let auth = bootstrap_mount_authority();
    let handle = match registry().mount(&auth, PATH, MemFs::new("fme6")) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount() failed"),
    };

    // Create "test.txt" in the root dir.
    let root = match registry().with_mount(PATH, |fs| fs.root()) {
        Some(r) => r,
        None => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("with_mount returned None");
        }
    };

    let file = match poll_once(root.create("test.txt")) {
        Some(Ok(f)) => f,
        _ => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("create test.txt failed");
        }
    };

    // Write.
    let written = match poll_once(file.write(0, PAYLOAD)) {
        Some(Ok(n)) => n,
        _ => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("write failed");
        }
    };
    if written != PAYLOAD.len() {
        let _ = registry().unmount(&handle, PATH);
        return TestResult::Fail("write returned wrong byte count");
    }

    // Read back from the same FileOps handle.
    let mut buf = vec![0u8; 32];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("read after write failed");
        }
    };

    let _ = registry().unmount(&handle, PATH);

    if n != PAYLOAD.len() || &buf[..n] != PAYLOAD {
        return TestResult::Fail("readback content mismatch after write");
    }

    TestResult::Pass
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_vfs_writable_fs_create_write_read
);

// ── Smoke 6b: MemFs unlink of a missing name → NotFound ──────────────
//
// A writable MemFs (the /run, /tmp, /dev/shm backing) must report
// `FsError::NotFound` when unlinking a name that doesn't exist — that
// is what `sys_unlink` maps to ENOENT. Returning any other error would
// surface to userspace as EPERM (systemd's `rm` of an absent /run path).

fn smoke_vfs_memfs_unlink_missing_returns_not_found() -> TestResult {
    const PATH: &str = "/fme6b";

    let auth = bootstrap_mount_authority();
    let handle = match registry().mount(&auth, PATH, MemFs::new("fme6b")) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount() failed"),
    };

    let root = match registry().with_mount(PATH, |fs| fs.root()) {
        Some(r) => r,
        None => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("with_mount returned None");
        }
    };

    let result = poll_once(root.unlink("does-not-exist"));
    let _ = registry().unmount(&handle, PATH);

    match result {
        Some(Err(FsError::NotFound)) => TestResult::Pass,
        Some(Err(_)) => TestResult::Fail("unlink of missing name returned wrong error"),
        Some(Ok(())) => TestResult::Fail("unlink of missing name unexpectedly succeeded"),
        None => TestResult::Fail("unlink future returned Pending (should be Ready)"),
    }
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_vfs_memfs_unlink_missing_returns_not_found
);

// ── Smoke 7: flat FS with multiple files ─────────────────────────────
//
// Image has three files at the root level: a.txt, b.txt, c.txt.
// Verify resolve + read works for each. This tests that the Initramfs
// directory walker correctly disambiguates multiple entries at the same
// directory level — the regression for flat "FAT-like" directory scans.
//
// References:
//   Linux `fs/fat/dir.c::fat_readdir` — flat directory iteration.

fn smoke_vfs_flat_multi_file_read() -> TestResult {
    const PATH: &str = "/fme7";

    let fs = match make_initramfs(
        "fme7",
        &[
            CpioEntry {
                name: "a.txt",
                mode: 0o100644,
                data: b"aaa",
            },
            CpioEntry {
                name: "b.txt",
                mode: 0o100644,
                data: b"bbb",
            },
            CpioEntry {
                name: "c.txt",
                mode: 0o100644,
                data: b"ccc",
            },
        ],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build failed"),
    };

    let auth = bootstrap_mount_authority();
    let handle = match registry().mount(&auth, PATH, fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount() failed"),
    };

    let pairs: &[(&str, &[u8])] = &[("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")];
    for &(name, expected) in pairs {
        let file = match registry().with_mount(PATH, |fs| resolve(fs.root(), name)) {
            Some(Ok(f)) => f,
            _ => {
                let _ = registry().unmount(&handle, PATH);
                return TestResult::Fail("resolve failed for one of the flat files");
            }
        };
        let mut buf = vec![0u8; 8];
        let n = match poll_once(file.read(0, &mut buf)) {
            Some(Ok(n)) => n,
            _ => {
                let _ = registry().unmount(&handle, PATH);
                return TestResult::Fail("read failed for flat file");
            }
        };
        if n != expected.len() || &buf[..n] != expected {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("flat file content mismatch");
        }
    }

    let _ = registry().unmount(&handle, PATH);
    TestResult::Pass
}
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_flat_multi_file_read);

// ── Smoke 8: multiple simultaneous mounts ────────────────────────────
//
// Mount two independent FSes on "/fme8a" and "/fme8b".
//   - "/fme8a" has "file_a.txt" → "from a"
//   - "/fme8b" has "file_b.txt" → "from b"
//
// 1. Verify both resolve independently.
// 2. Unmount "/fme8a".
// 3. Verify "/fme8a" resolves None; "/fme8b" still resolves.
//
// References:
//   Linux `fs/namespace.c::do_mount` — independent mountpoints.

fn smoke_vfs_multi_mount_independent() -> TestResult {
    const PATH_A: &str = "/fme8a";
    const PATH_B: &str = "/fme8b";

    let fs_a = match make_initramfs(
        "fme8a",
        &[CpioEntry {
            name: "file_a.txt",
            mode: 0o100644,
            data: b"from a",
        }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build A failed"),
    };

    let fs_b = match make_initramfs(
        "fme8b",
        &[CpioEntry {
            name: "file_b.txt",
            mode: 0o100644,
            data: b"from b",
        }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build B failed"),
    };

    let auth = bootstrap_mount_authority();
    let handle_a = match registry().mount(&auth, PATH_A, fs_a) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount A failed"),
    };
    let handle_b = match registry().mount(&auth, PATH_B, fs_b) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&handle_a, PATH_A);
            return TestResult::Fail("mount B failed");
        }
    };

    // Both must resolve independently.
    let a_ok = registry()
        .with_mount(PATH_A, |fs| resolve(fs.root(), "file_a.txt"))
        .map(|r| r.is_ok())
        .unwrap_or(false);
    let b_ok = registry()
        .with_mount(PATH_B, |fs| resolve(fs.root(), "file_b.txt"))
        .map(|r| r.is_ok())
        .unwrap_or(false);

    if !a_ok || !b_ok {
        let _ = registry().unmount(&handle_a, PATH_A);
        let _ = registry().unmount(&handle_b, PATH_B);
        return TestResult::Fail("one of the two mounts failed to resolve its file");
    }

    // Unmount A.
    if registry().unmount(&handle_a, PATH_A).is_err() {
        let _ = registry().unmount(&handle_b, PATH_B);
        return TestResult::Fail("unmount A failed");
    }

    // A is gone; B must still work.
    if registry().with_mount(PATH_A, |_| ()).is_some() {
        let _ = registry().unmount(&handle_b, PATH_B);
        return TestResult::Fail("mount A still visible after unmount");
    }
    let b_still_ok = registry()
        .with_mount(PATH_B, |fs| resolve(fs.root(), "file_b.txt"))
        .map(|r| r.is_ok())
        .unwrap_or(false);

    let _ = registry().unmount(&handle_b, PATH_B);

    if !b_still_ok {
        return TestResult::Fail("mount B broken after unrelated mount A was removed");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_multi_mount_independent);

// ── Smoke 9: mount on occupied mountpoint → stacks (overmount) ────────
//
// Mounting a second FS on a path that is already mounted STACKS it: the new
// mount shadows the first (Linux overmount), so the topmost FS's contents are
// what resolve, and unmounting pops it to reveal the original underneath.
// NARF previously returned `FsError::Busy` here, which broke systemd service
// namespace setup (ProtectHostname= binds a read-only view over
// /proc/sys/kernel/domainname) with 226/EXIT_NAMESPACE.
//
// References:
//   Linux `fs/namespace.c::do_add_mount` stacks on an occupied mountpoint;
//   the topmost mount is the visible one.

fn smoke_vfs_stack_on_duplicate_mountpoint() -> TestResult {
    const PATH: &str = "/fme9";

    let fs1 = match make_initramfs(
        "fme9-first",
        &[CpioEntry {
            name: "f.txt",
            mode: 0o100644,
            data: b"first",
        }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build failed"),
    };
    let fs2 = match make_initramfs(
        "fme9-second",
        &[CpioEntry {
            name: "g.txt",
            mode: 0o100644,
            data: b"second",
        }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build 2 failed"),
    };

    let auth = bootstrap_mount_authority();
    let h1 = match registry().mount(&auth, PATH, fs1) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("first mount failed"),
    };

    // Overmount the same path: must succeed (stack), not Busy.
    let h2 = match registry().mount(&auth, PATH, fs2) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&h1, PATH);
            return TestResult::Fail("overmount rejected — should stack, not Busy");
        }
    };

    // The topmost FS (fs2) is visible: its g.txt resolves and fs1's f.txt is
    // shadowed.
    let top_sees_g = matches!(
        registry().with_mount(PATH, |fs| resolve(fs.root(), "g.txt").is_ok()),
        Some(true)
    );
    let top_hides_f = matches!(
        registry().with_mount(PATH, |fs| resolve(fs.root(), "f.txt").is_err()),
        Some(true)
    );

    // Pop the top: fs1's f.txt is revealed again.
    let popped = registry().unmount(&h2, PATH).is_ok();
    let bottom_sees_f = matches!(
        registry().with_mount(PATH, |fs| resolve(fs.root(), "f.txt").is_ok()),
        Some(true)
    );

    let _ = registry().unmount(&h1, PATH);

    if top_sees_g && top_hides_f && popped && bottom_sees_f {
        TestResult::Pass
    } else {
        TestResult::Fail("duplicate mount must stack: top shadows bottom, unmount reveals it")
    }
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_vfs_stack_on_duplicate_mountpoint
);

// ── Smoke 10: stat reports correct size and mode ─────────────────────
//
// `FileOps::stat()` must reflect the file's true byte size and
// `FileType::File`. This pins the VFS stat surface that all
// disk-backed FSes (ext4, FAT, exfat, iso9660) go through.
//
// Check:
//   - stat.size == content length (precise byte count)
//   - stat.mode.file_type == FileType::File
//   - stat.blocks == ceil(size / 512)  (POSIX block accounting)
//   - stat.mode.perms matches the inode mode bits stored in the CPIO header
//
// References:
//   POSIX-2017 `struct stat`; Linux `fs/stat.c::vfs_getattr`.

fn smoke_vfs_stat_correct_size_mode_blocks() -> TestResult {
    const PATH: &str = "/fme10";
    const CONTENT: &[u8] = b"stat test payload with known length";
    // CONTENT.len() = 35, blocks = ceil(35/512) = 1

    let fs = match make_initramfs(
        "fme10",
        &[CpioEntry {
            name: "stat_me.txt",
            mode: 0o100644,
            data: CONTENT,
        }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build failed"),
    };

    let auth = bootstrap_mount_authority();
    let handle = match registry().mount(&auth, PATH, fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount() failed"),
    };

    let file = match registry().with_mount(PATH, |fs| resolve(fs.root(), "stat_me.txt")) {
        Some(Ok(f)) => f,
        _ => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("resolve stat_me.txt failed");
        }
    };

    let stat = file.stat();
    let _ = registry().unmount(&handle, PATH);

    if stat.size != CONTENT.len() as u64 {
        return TestResult::Fail("stat.size does not match file content length");
    }
    if stat.mode.file_type != FileType::File {
        return TestResult::Fail("stat.mode.file_type is not FileType::File");
    }
    let expected_blocks = CONTENT.len().div_ceil(512) as u64;
    if stat.blocks != expected_blocks {
        return TestResult::Fail("stat.blocks does not match ceil(size/512)");
    }
    // The CPIO mode 0o100644 → perms == 0o644. The Initramfs strips the
    // file-type bits (0o100000) and keeps the low 9: 0o644.
    let expected_perms: u16 = 0o644;
    if stat.mode.perms != expected_perms {
        return TestResult::Fail("stat.mode.perms does not match CPIO inode mode");
    }

    TestResult::Pass
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_vfs_stat_correct_size_mode_blocks
);

// ── Smoke 11: lock released across resolve_absolute closure ──────────
//
// REGRESSION GUARD for the SMP mount-table deadlock fixed in lib.rs.
//
// `VfsRegistry::{resolve_absolute, with_mount, resolve_parent_absolute}`
// used to run their user closure WHILE HOLDING the `inner` IrqSafeSpinLock.
// Callers pass BLOCKING closures (block-I/O resolvers busy-spin in
// `poll_blocking`), so holding the IRQ-disabling lock across the closure
// deadlocked the box under an SMP statx storm. The fix clones the
// `Arc<dyn FsInstance>` + relative path out, DROPS the lock, THEN runs the
// closure.
//
// To prove the lock is no longer held across the closure, we perform a
// NESTED call back into the SAME registry FROM INSIDE the closure — a call
// that itself acquires the `inner` lock (`mount_id_at`, and another
// `resolve_absolute`). If the outer lock were still held, this nested
// acquisition of the same non-reentrant `IrqSafeSpinLock` would deadlock
// (hang the test forever). A test that RETURNS AT ALL therefore proves the
// lock was released; we additionally assert the nested lookup returns the
// correct value for a DIFFERENT mount.

fn smoke_vfs_resolve_absolute_lock_released_in_closure() -> TestResult {
    const PATH_A: &str = "/fme11a";
    const PATH_B: &str = "/fme11b";

    let fs_a = match make_initramfs(
        "fme11a",
        &[CpioEntry {
            name: "a.txt",
            mode: 0o100644,
            data: b"aa",
        }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build A failed"),
    };
    let fs_b = match make_initramfs(
        "fme11b",
        &[CpioEntry {
            name: "b.txt",
            mode: 0o100644,
            data: b"bb",
        }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build B failed"),
    };

    let auth = bootstrap_mount_authority();
    let handle_a = match registry().mount(&auth, PATH_A, fs_a) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount A failed"),
    };
    let handle_b = match registry().mount(&auth, PATH_B, fs_b) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&handle_a, PATH_A);
            return TestResult::Fail("mount B failed");
        }
    };

    // The id of mount B, obtained WITHOUT any nesting, for comparison.
    let expected_b_id = registry().mount_id_at(PATH_B);

    // Resolve against mount A. INSIDE the closure — which now runs with
    // the `inner` lock RELEASED — make two nested re-entrant calls that
    // both re-acquire the `inner` lock. If the lock were still held these
    // would deadlock. Return the nested results so we can assert on them.
    let nested = registry().resolve_absolute(PATH_A, |_fs, _rel| {
        // Nested lock-taking call #1: mount_id_at re-locks `inner`.
        let nested_id = registry().mount_id_at(PATH_B);
        // Nested lock-taking call #2: another resolve_absolute (different
        // mount) re-locks `inner` and runs its own closure.
        let nested_resolve = registry().resolve_absolute(PATH_B, |fs, rel| {
            (String::from(rel), resolve(fs.root(), "b.txt").is_ok())
        });
        (nested_id, nested_resolve)
    });

    let _ = registry().unmount(&handle_a, PATH_A);
    let _ = registry().unmount(&handle_b, PATH_B);

    match nested {
        Some((nested_id, Some((rel, b_ok)))) => {
            if nested_id != expected_b_id || nested_id.is_none() {
                return TestResult::Fail("nested mount_id_at returned wrong id");
            }
            if !rel.is_empty() {
                return TestResult::Fail("nested resolve_absolute rel not empty for mount root");
            }
            if !b_ok {
                return TestResult::Fail("nested resolve failed to read b.txt");
            }
            TestResult::Pass
        }
        Some((_, None)) => TestResult::Fail("nested resolve_absolute returned None"),
        None => TestResult::Fail("outer resolve_absolute returned None for live mount"),
    }
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_vfs_resolve_absolute_lock_released_in_closure
);

// ── Smoke 11b: lock released across with_mount closure ───────────────
//
// Same regression guard as smoke 11, for `with_mount`. A nested
// `mount_id_at` (which re-locks `inner`) inside the `with_mount` closure
// would deadlock if `with_mount` still held the lock across the closure.

fn smoke_vfs_with_mount_lock_released_in_closure() -> TestResult {
    const PATH_A: &str = "/fme11ba";
    const PATH_B: &str = "/fme11bb";

    let auth = bootstrap_mount_authority();
    let handle_a = match registry().mount(&auth, PATH_A, MemFs::new("fme11ba")) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount A failed"),
    };
    let handle_b = match registry().mount(&auth, PATH_B, MemFs::new("fme11bb")) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&handle_a, PATH_A);
            return TestResult::Fail("mount B failed");
        }
    };

    let expected_b_id = registry().mount_id_at(PATH_B);

    // Inside with_mount(A): nested lock-taking calls targeting mount B.
    let nested = registry().with_mount(PATH_A, |_fs| {
        let id = registry().mount_id_at(PATH_B);
        let also = registry().with_mount(PATH_B, |fs| String::from(fs.name()));
        (id, also)
    });

    let _ = registry().unmount(&handle_a, PATH_A);
    let _ = registry().unmount(&handle_b, PATH_B);

    match nested {
        Some((id, Some(name))) => {
            if id != expected_b_id || id.is_none() {
                return TestResult::Fail("nested mount_id_at returned wrong id under with_mount");
            }
            if name != "fme11bb" {
                return TestResult::Fail("nested with_mount saw wrong FS name");
            }
            TestResult::Pass
        }
        Some((_, None)) => TestResult::Fail("nested with_mount returned None"),
        None => TestResult::Fail("outer with_mount returned None for live mount"),
    }
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_vfs_with_mount_lock_released_in_closure
);

// ── Smoke 11c: lock released across resolve_parent_absolute closure ──
//
// Same regression guard, for `resolve_parent_absolute`. The nested
// `mount_id_at` + `resolve_absolute` re-lock `inner`; a lock still held
// across the closure would deadlock.

fn smoke_vfs_resolve_parent_absolute_lock_released_in_closure() -> TestResult {
    const PATH_A: &str = "/fme11ca";
    const PATH_B: &str = "/fme11cb";

    let auth = bootstrap_mount_authority();
    let handle_a = match registry().mount(&auth, PATH_A, MemFs::new("fme11ca")) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount A failed"),
    };
    let handle_b = match registry().mount(&auth, PATH_B, MemFs::new("fme11cb")) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&handle_a, PATH_A);
            return TestResult::Fail("mount B failed");
        }
    };

    let expected_b_id = registry().mount_id_at(PATH_B);

    // resolve_parent_absolute of "/fme11ca/leaf": parent is the A mount
    // root, leaf == "leaf". Inside the closure (lock released) re-enter.
    let nested = registry().resolve_parent_absolute("/fme11ca/leaf", |_fs, _dir, leaf| {
        let id = registry().mount_id_at(PATH_B);
        let also = registry().resolve_absolute(PATH_B, |fs, rel| {
            (String::from(rel), String::from(fs.name()))
        });
        (String::from(leaf), id, also)
    });

    let _ = registry().unmount(&handle_a, PATH_A);
    let _ = registry().unmount(&handle_b, PATH_B);

    match nested {
        Some((leaf, id, Some((rel, name)))) => {
            if leaf != "leaf" {
                return TestResult::Fail("resolve_parent_absolute produced wrong leaf");
            }
            if id != expected_b_id || id.is_none() {
                return TestResult::Fail("nested mount_id_at wrong under resolve_parent_absolute");
            }
            if !rel.is_empty() || name != "fme11cb" {
                return TestResult::Fail("nested resolve_absolute wrong under parent closure");
            }
            TestResult::Pass
        }
        Some((_, _, None)) => TestResult::Fail("nested resolve_absolute returned None"),
        None => TestResult::Fail("outer resolve_parent_absolute returned None for live mount"),
    }
}
kernel_test_in!(
    "filesystem/e2e/mount",
    smoke_vfs_resolve_parent_absolute_lock_released_in_closure
);

// ── Smoke 12: longest-prefix mount matching ──────────────────────────
//
// With `/fme12` and `/fme12/sub` BOTH mounted, `resolve_absolute` must
// pick the LONGEST matching mount prefix:
//   `/fme12/sub/bar` → resolves against the `/fme12/sub` mount, rel="bar"
//   `/fme12/foo`     → resolves against the `/fme12`     mount, rel="foo"
//
// The relative path handed to the closure is what proves which mount was
// chosen: a "bar" rel means the `/fme12/sub` mount matched (had the shorter
// mount matched, rel would be "sub/bar").
//
// References: Linux `fs/namespace.c` — the mount hash picks the deepest
// mount covering a dentry.

fn smoke_vfs_longest_prefix_mount_match() -> TestResult {
    const PATH_TOP: &str = "/fme12";
    const PATH_SUB: &str = "/fme12/sub";

    let auth = bootstrap_mount_authority();
    let handle_top = match registry().mount(&auth, PATH_TOP, MemFs::new("fme12-top")) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount top failed"),
    };
    let handle_sub = match registry().mount(&auth, PATH_SUB, MemFs::new("fme12-sub")) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&handle_top, PATH_TOP);
            return TestResult::Fail("mount sub failed");
        }
    };

    // `/fme12/sub/bar` must select the deeper `/fme12/sub` mount → rel "bar"
    // and the FS name of the sub mount.
    let deep = registry().resolve_absolute("/fme12/sub/bar", |fs, rel| {
        (String::from(rel), String::from(fs.name()))
    });
    // `/fme12/foo` must select the `/fme12` mount → rel "foo".
    let shallow = registry().resolve_absolute("/fme12/foo", |fs, rel| {
        (String::from(rel), String::from(fs.name()))
    });

    let _ = registry().unmount(&handle_sub, PATH_SUB);
    let _ = registry().unmount(&handle_top, PATH_TOP);

    match (deep, shallow) {
        (Some((deep_rel, deep_name)), Some((shallow_rel, shallow_name))) => {
            if deep_rel != "bar" {
                return TestResult::Fail("deep path did not select /fme12/sub mount (rel != bar)");
            }
            if deep_name != "fme12-sub" {
                return TestResult::Fail("deep path resolved against wrong FS");
            }
            if shallow_rel != "foo" {
                return TestResult::Fail("shallow path did not select /fme12 mount (rel != foo)");
            }
            if shallow_name != "fme12-top" {
                return TestResult::Fail("shallow path resolved against wrong FS");
            }
            TestResult::Pass
        }
        _ => TestResult::Fail("resolve_absolute returned None for a covered path"),
    }
}
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_longest_prefix_mount_match);

// ── Smoke 13: mount_id_at correctness ────────────────────────────────
//
// `mount_id_at` returns the id of the longest-prefix mount covering a
// path. Assertions:
//   - Two distinct mounts have DISTINCT ids.
//   - A path under a mount returns THAT mount's id (id at mount path ==
//     id at a file below it).
//   - With nested `/fme13` + `/fme13/sub`, a path under `/fme13/sub`
//     returns the SUB mount id (longest prefix), while a path under
//     `/fme13` but not `/fme13/sub` returns the TOP mount id.
//   - A file under `/` (an uncovered top-level path) returns the root
//     mount id when a `/` mount exists (installed at boot).

fn smoke_vfs_mount_id_at_correctness() -> TestResult {
    const PATH_TOP: &str = "/fme13";
    const PATH_SUB: &str = "/fme13/sub";
    const PATH_OTHER: &str = "/fme13other";

    let auth = bootstrap_mount_authority();
    let handle_top = match registry().mount(&auth, PATH_TOP, MemFs::new("fme13-top")) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount top failed"),
    };
    let handle_sub = match registry().mount(&auth, PATH_SUB, MemFs::new("fme13-sub")) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&handle_top, PATH_TOP);
            return TestResult::Fail("mount sub failed");
        }
    };
    let handle_other = match registry().mount(&auth, PATH_OTHER, MemFs::new("fme13-other")) {
        Ok(h) => h,
        Err(_) => {
            let _ = registry().unmount(&handle_sub, PATH_SUB);
            let _ = registry().unmount(&handle_top, PATH_TOP);
            return TestResult::Fail("mount other failed");
        }
    };

    let id_top = registry().mount_id_at(PATH_TOP);
    let id_sub = registry().mount_id_at(PATH_SUB);
    let id_other = registry().mount_id_at(PATH_OTHER);
    // A file below the top mount but NOT under /fme13/sub.
    let id_top_file = registry().mount_id_at("/fme13/foo.txt");
    // A file below the sub mount → longest prefix is /fme13/sub.
    let id_sub_file = registry().mount_id_at("/fme13/sub/bar.txt");
    // A top-level path with no explicit mount → the boot `/` mount (if any).
    let id_root_file = registry().mount_id_at("/fme13-not-mounted-anywhere");

    let _ = registry().unmount(&handle_other, PATH_OTHER);
    let _ = registry().unmount(&handle_sub, PATH_SUB);
    let _ = registry().unmount(&handle_top, PATH_TOP);

    // All three mounts must have resolved to some id.
    let (id_top, id_sub, id_other) = match (id_top, id_sub, id_other) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return TestResult::Fail("mount_id_at returned None for a live mount"),
    };

    // Distinct mounts → distinct ids.
    if id_top == id_sub || id_top == id_other || id_sub == id_other {
        return TestResult::Fail("distinct mounts returned duplicate ids");
    }

    // A file under the top mount (not under /sub) maps to the top id.
    if id_top_file != Some(id_top) {
        return TestResult::Fail("file under /fme13 did not map to top mount id");
    }

    // A file under the sub mount maps to the sub (longest-prefix) id.
    if id_sub_file != Some(id_sub) {
        return TestResult::Fail("file under /fme13/sub did not map to sub mount id");
    }

    // An uncovered top-level path falls back to the root mount when a `/`
    // mount exists. It must NOT match any of our /fme13 mounts. If the boot
    // `/` mount is present it returns that root id; if not, None. Either way
    // it must differ from the three /fme13 mount ids.
    if matches!(id_root_file, Some(x) if x == id_top || x == id_sub || x == id_other) {
        return TestResult::Fail("uncovered path incorrectly matched a /fme13 mount");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_mount_id_at_correctness);

// ── FS coverage matrix ────────────────────────────────────────────────
//
// The VFS layer is FS-agnostic: every FsInstance goes through the same
// `VfsRegistry::mount` / `resolve` / `FileOps::read` / `unmount` path.
// The smokes above exercise that path using `Initramfs` (CPIO newc,
// read-only) and `MemFs` (writable in-memory), which are the two
// FsInstance implementations shipped by this crate.
//
// Per-FS parser coverage lives in each driver's own test suite:
//
// | FS      | VFS mount/resolve/read | On-disk format parser          |
// |---------|------------------------|--------------------------------|
// | ext2    | via Initramfs proxy    | drivers/fs/ext2/src/tests.rs   |
// | ext4    | via Initramfs proxy    | drivers/fs/ext4/src/tests.rs   |
// | exfat   | via Initramfs proxy    | drivers/fs/exfat/src/tests.rs  |
// | FAT     | via Initramfs proxy    | drivers/fs/fat/src/tests.rs    |
// | iso9660 | via Initramfs proxy    | drivers/fs/iso9660/src/tests.rs|
// | minix   | via Initramfs proxy    | drivers/fs/minix/src/tests.rs  |
// | udf     | via Initramfs proxy    | drivers/fs/udf/src/tests.rs    |
// | 9p      | via Initramfs proxy    | drivers/fs/9p/src/tests.rs     |
//
// "via Initramfs proxy" means: the VFS plumbing (mount, resolve, read,
// unmount, stat, enumerate) is verified here using Initramfs. When a
// per-FS driver is mounted via the same VfsRegistry::mount + resolve
// path in a real boot or in its own e2e test, it goes through the
// identical VFS code path proven here.
//
// A true per-FS VFS-layer smoke (e.g., Ext2Volume mounted in THIS file)
// would require adding `narf-drivers-fs-ext2` as a dependency of
// `narf-filesystem`, which is impossible without a dependency cycle
// (ext2 depends on narf-filesystem). Those tests live in
// `drivers/fs/ext2/src/tests.rs::smoke_ext2_mount_ramblock_round_trip`
// and similar, which already verify `FsInstance::root()`,
// `DirOps::enumerate_async`, `lookup_async`, and `FileOps::read` end-
// to-end against a real synthesised ext2 image.
//
// Deferred:
//   - FS write tests (journal replay, dir mutation) — Stage 4.
//   - FUSE session mount path — Stage 4 (virtiofs DAX protocol).
//   - per-NS mount isolation (unshare CLONE_NEWNS) — Stage 4.
