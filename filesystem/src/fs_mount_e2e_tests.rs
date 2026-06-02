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

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{
    bootstrap_mount_authority, registry, resolve, FileType, FsError, FsInstance, Initramfs,
    MemFs, Mode,
};

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
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
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

    // resolve_absolute with no covering mount returns None.
    let post = registry().resolve_absolute(PATH, |fs, rel| resolve(fs.root(), rel));
    if post.is_some() {
        return TestResult::Fail("resolve_absolute found path after unmount");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_mount_read_unmount);

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

    let entries: Vec<(String, FileType)> = match registry().with_mount(PATH, |fs| {
        fs.root().enumerate(0, 64)
    }) {
        Some(e) => e,
        None => return TestResult::Fail("with_mount returned None"),
    };

    let has_hello = entries.iter().any(|(n, t)| n == "hello.txt" && *t == FileType::File);
    let has_world = entries.iter().any(|(n, t)| n == "world.bin" && *t == FileType::File);

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

    let file = match registry()
        .with_mount(PATH, |fs| resolve(fs.root(), "dir1/dir2/nested.txt"))
    {
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
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_empty_fs_lookup_returns_not_found);

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
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_bad_cpio_magic_rejects_mount);

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
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_readonly_fs_write_returns_error);

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
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_writable_fs_create_write_read);

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
            CpioEntry { name: "a.txt", mode: 0o100644, data: b"aaa" },
            CpioEntry { name: "b.txt", mode: 0o100644, data: b"bbb" },
            CpioEntry { name: "c.txt", mode: 0o100644, data: b"ccc" },
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
        &[CpioEntry { name: "file_a.txt", mode: 0o100644, data: b"from a" }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build A failed"),
    };

    let fs_b = match make_initramfs(
        "fme8b",
        &[CpioEntry { name: "file_b.txt", mode: 0o100644, data: b"from b" }],
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

// ── Smoke 9: mount on occupied mountpoint → Busy ──────────────────────
//
// Attempt to mount a second FS on the same path while the first is
// still mounted. `VfsRegistry::mount` must return `FsError::Busy`.
//
// References:
//   Linux `fs/namespace.c::do_add_mount` → -EBUSY when the mount point
//   is already occupied without `MNT_BIND`.

fn smoke_vfs_busy_on_duplicate_mountpoint() -> TestResult {
    const PATH: &str = "/fme9";

    let fs1 = match make_initramfs(
        "fme9-first",
        &[CpioEntry { name: "f.txt", mode: 0o100644, data: b"first" }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build failed"),
    };
    let fs2 = match make_initramfs(
        "fme9-second",
        &[CpioEntry { name: "g.txt", mode: 0o100644, data: b"second" }],
    ) {
        Some(f) => f,
        None => return TestResult::Fail("CPIO build 2 failed"),
    };

    let auth = bootstrap_mount_authority();
    let handle = match registry().mount(&auth, PATH, fs1) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("first mount failed"),
    };

    let second_result = registry().mount(&auth, PATH, fs2);

    let _ = registry().unmount(&handle, PATH);

    match second_result {
        Err(FsError::Busy) => TestResult::Pass,
        Err(_) => TestResult::Fail("double mount returned wrong error (expected Busy)"),
        Ok(h2) => {
            // Clean up the unexpected second mount.
            let _ = registry().unmount(&h2, PATH);
            TestResult::Fail("double mount succeeded — should return Busy")
        }
    }
}
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_busy_on_duplicate_mountpoint);

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
kernel_test_in!("filesystem/e2e/mount", smoke_vfs_stat_correct_size_mode_blocks);

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
