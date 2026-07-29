//! Dedicated tmpfs / `MemFs` behaviour suite.
//!
//! ## Scope
//!
//! `MemFs` is NARF's in-memory read/write filesystem — the backing store
//! for `/tmp`, `/run`, and `/dev/shm` (i.e. Linux tmpfs). Its correctness
//! is load-bearing for systemd (`XDG_RUNTIME_DIR`, `rm_rf` root-guard),
//! shells (temp files), and the musl dynamic linker (per-inode DSO dedup).
//!
//! These smokes drive the `FsInstance` / `DirOps` / `FileOps` trait surface
//! DIRECTLY (per-node, no VFS), plus one via the `VfsRegistry` mount path.
//! They complement the VFS-plumbing smokes in `fs_mount_e2e_tests.rs`, which
//! exercise MemFs only incidentally.
//!
//! ## Smoke inventory
//!
//!   1. `smoke_memfs_write_read_roundtrip`   — write bytes, read back exact + at offset
//!   2. `smoke_memfs_stat_size_type_mode`    — stat size/type/perms; size grows on write
//!   3. `smoke_memfs_nested_dirs_lookup`     — mkdir a/b/c; lookup_dir traverses; miss → None
//!   4. `smoke_memfs_dir_listing_enumerate`  — enumerate returns created entries
//!   5. `smoke_memfs_unlink_rmdir_semantics` — unlink removes; rmdir empty ok; rmdir non-empty fails
//!   6. `smoke_memfs_rename_within_and_cross`— rename within-dir overwrites; cross-dir Unsupported
//!   7. `smoke_memfs_mode_perms_roundtrip`   — create mode, stat shows it; set_perms/chmod round-trip
//!   8. `smoke_memfs_truncate_grow_shrink`   — truncate grows (zero-fill) / shrinks; stat reflects
//!   9. `smoke_memfs_distinct_inodes`        — distinct files, and dir vs parent, have distinct ino()
//!  10. `smoke_memfs_registry_mount_roundtrip` — mount via registry, write through path, unmount → NotFound
//!
//! GPL-2.0-or-later — NARF is GPL-2.0-or-later as of 2026-05-20.

extern crate alloc;

use alloc::vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{bootstrap_mount_authority, registry, resolve, FileType, FsError, FsInstance, MemFs};

// ── poll_once helper ──────────────────────────────────────────────────
//
// The `DirOps`/`FileOps` async methods return `Pin<Box<dyn Future>>`. For
// MemFs the future is always immediately ready (no real I/O, just a
// spinlock over a `BTreeMap`/`Vec`), so `poll_once` completes synchronously.
// This mirrors the helper in `fs_mount_e2e_tests.rs`.

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
    // SAFETY: raw_waker() returns a vtable whose no-op/no-clone fns are sound
    // for a single-threaded test poll; the RawWaker is not used after this scope.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is a local mut binding that outlives this block; not moved.
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

// ── Smoke 1: write + read round-trip (exact content, length, offset) ──
//
// Create a file in the MemFs root, write a payload, read it back and
// verify exact bytes + length. Then read at a non-zero offset and verify
// the tail slice matches. This pins `FileOps::read`/`write` — the /tmp
// data path.

fn smoke_memfs_write_read_roundtrip() -> TestResult {
    const PAYLOAD: &[u8] = b"tmpfs round trip payload";

    let fs = MemFs::new("memfs-rw");
    let root = fs.root();

    let file = match poll_once(root.create("data.bin")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create data.bin failed"),
    };

    let written = match poll_once(file.write(0, PAYLOAD)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("write failed"),
    };
    if written != PAYLOAD.len() {
        return TestResult::Fail("write returned wrong byte count");
    }

    // Full read from offset 0.
    let mut buf = vec![0u8; 64];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read failed"),
    };
    if n != PAYLOAD.len() || &buf[..n] != PAYLOAD {
        return TestResult::Fail("full readback content/length mismatch");
    }

    // Read at an offset — the tail of the payload.
    const OFF: usize = 7; // "trip payload"
    let mut tail = vec![0u8; 64];
    let m = match poll_once(file.read(OFF as u64, &mut tail)) {
        Some(Ok(m)) => m,
        _ => return TestResult::Fail("offset read failed"),
    };
    if m != PAYLOAD.len() - OFF || tail[..m] != PAYLOAD[OFF..] {
        return TestResult::Fail("offset read content/length mismatch");
    }

    // Read fully past EOF → 0 bytes (MemFs short-reads / EOFs at len).
    let z = match poll_once(file.read(PAYLOAD.len() as u64, &mut buf)) {
        Some(Ok(z)) => z,
        _ => return TestResult::Fail("read at EOF failed"),
    };
    if z != 0 {
        return TestResult::Fail("read at EOF did not return 0");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/memfs", smoke_memfs_write_read_roundtrip);

// ── Smoke 2: stat reports size + FileType::File + perms; grows on write ─
//
// A freshly created MemFile stats as size 0, FileType::File, perms 0o666
// (MemFs DEFAULT_PERMS). After a write, stat.size grows to the byte count.

fn smoke_memfs_stat_size_type_mode() -> TestResult {
    const PAYLOAD: &[u8] = b"twelve bytes";

    let fs = MemFs::new("memfs-stat");
    let root = fs.root();

    let file = match poll_once(root.create("s.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create s.txt failed"),
    };

    // Fresh file: empty, regular, default perms.
    let s0 = file.stat();
    if s0.size != 0 {
        return TestResult::Fail("fresh file size is not 0");
    }
    if s0.mode.file_type != FileType::File {
        return TestResult::Fail("fresh file type is not FileType::File");
    }
    // MemFs mints files with DEFAULT_PERMS == 0o666.
    if s0.mode.perms != 0o666 {
        return TestResult::Fail("fresh file perms are not 0o666");
    }

    // After a write, size reflects the payload length.
    if poll_once(file.write(0, PAYLOAD)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("write failed");
    }
    let s1 = file.stat();
    if s1.size != PAYLOAD.len() as u64 {
        return TestResult::Fail("size did not grow to payload length after write");
    }
    if s1.mode.file_type != FileType::File {
        return TestResult::Fail("type changed after write");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/memfs", smoke_memfs_stat_size_type_mode);

// ── Smoke 3: nested directories + lookup_dir traversal + miss → None ──
//
// mkdir a nested chain a/b/c via DirOps::mkdir on each level, then
// traverse with lookup_dir. A missing component (a/b/nope) returns None.
// This is the systemd `mkdir -p` / `rm_rf` descent path.

fn smoke_memfs_nested_dirs_lookup() -> TestResult {
    let fs = MemFs::new("memfs-dirs");
    let root = fs.root();

    // mkdir a
    let a = match poll_once(root.mkdir("a")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir a failed"),
    };
    // mkdir a/b
    let b = match poll_once(a.mkdir("b")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir a/b failed"),
    };
    // mkdir a/b/c
    if poll_once(b.mkdir("c")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("mkdir a/b/c failed");
    }

    // lookup_dir traverses each level from the root.
    let a2 = match root.lookup_dir("a") {
        Some(d) => d,
        None => return TestResult::Fail("lookup_dir a returned None"),
    };
    let b2 = match a2.lookup_dir("b") {
        Some(d) => d,
        None => return TestResult::Fail("lookup_dir a/b returned None"),
    };
    if b2.lookup_dir("c").is_none() {
        return TestResult::Fail("lookup_dir a/b/c returned None");
    }

    // A missing component returns None (not a panic / wrong node).
    if b2.lookup_dir("nope").is_some() {
        return TestResult::Fail("lookup_dir of missing component returned Some");
    }
    // lookup_dir on a plain file name (none created here) is also None.
    if root.lookup_dir("does-not-exist").is_some() {
        return TestResult::Fail("lookup_dir of absent name returned Some");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/memfs", smoke_memfs_nested_dirs_lookup);

// ── Smoke 4: directory listing via DirOps::enumerate ──────────────────
//
// Create two files and one subdir at the root, then enumerate and verify
// each created entry appears with the right FileType. MemFs's `iter()` is
// empty by design (its keys are owned Strings, not &'static), so
// `enumerate` is the readdir surface.

fn smoke_memfs_dir_listing_enumerate() -> TestResult {
    let fs = MemFs::new("memfs-list");
    let root = fs.root();

    if poll_once(root.create("alpha")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("create alpha failed");
    }
    if poll_once(root.create("beta")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("create beta failed");
    }
    if poll_once(root.mkdir("subdir")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("mkdir subdir failed");
    }

    let entries = root.enumerate(0, 64);
    if entries.len() != 3 {
        return TestResult::Fail("enumerate did not return exactly 3 entries");
    }

    let has = |name: &str, ft: FileType| entries.iter().any(|(n, t)| n == name && *t == ft);
    if !has("alpha", FileType::File) {
        return TestResult::Fail("enumerate missing alpha as File");
    }
    if !has("beta", FileType::File) {
        return TestResult::Fail("enumerate missing beta as File");
    }
    if !has("subdir", FileType::Dir) {
        return TestResult::Fail("enumerate missing subdir as Dir");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/memfs", smoke_memfs_dir_listing_enumerate);

// ── Smoke 5: unlink / rmdir semantics ─────────────────────────────────
//
//  - unlink removes a file (subsequent lookup fails).
//  - rmdir removes an empty directory.
//  - rmdir on a NON-empty directory fails (MemFs maps POSIX ENOTEMPTY to
//    FsError::Busy).
//  - unlink of a missing name → NotFound; rmdir of a missing name → NotFound.

fn smoke_memfs_unlink_rmdir_semantics() -> TestResult {
    let fs = MemFs::new("memfs-rm");
    let root = fs.root();

    // Create a file, then unlink it.
    if poll_once(root.create("victim")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("create victim failed");
    }
    if root.lookup("victim").is_none() {
        return TestResult::Fail("victim not found before unlink");
    }
    if poll_once(root.unlink("victim")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("unlink victim failed");
    }
    if root.lookup("victim").is_some() {
        return TestResult::Fail("victim still resolvable after unlink");
    }

    // Empty dir → rmdir succeeds.
    if poll_once(root.mkdir("emptydir")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("mkdir emptydir failed");
    }
    if poll_once(root.rmdir("emptydir")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("rmdir of empty dir failed");
    }
    if root.lookup_dir("emptydir").is_some() {
        return TestResult::Fail("emptydir still resolvable after rmdir");
    }

    // Non-empty dir → rmdir fails (ENOTEMPTY-shaped == FsError::Busy).
    let full = match poll_once(root.mkdir("fulldir")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir fulldir failed"),
    };
    if poll_once(full.create("child")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("create fulldir/child failed");
    }
    match poll_once(root.rmdir("fulldir")) {
        Some(Err(FsError::Busy)) => {}
        Some(Err(_)) => return TestResult::Fail("rmdir non-empty returned wrong error"),
        Some(Ok(())) => return TestResult::Fail("rmdir of non-empty dir unexpectedly succeeded"),
        None => return TestResult::Fail("rmdir future returned Pending"),
    }

    // Missing name → NotFound for both unlink and rmdir.
    if !matches!(
        poll_once(root.unlink("ghost")),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("unlink of missing name did not return NotFound");
    }
    if !matches!(poll_once(root.rmdir("ghost")), Some(Err(FsError::NotFound))) {
        return TestResult::Fail("rmdir of missing name did not return NotFound");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/memfs", smoke_memfs_unlink_rmdir_semantics);

// ── Smoke 6: rename within a dir (overwrite) + cross-dir behaviour ────
//
// MemFs `DirOps::rename` renames within the SAME directory and ATOMICALLY
// REPLACES an existing destination (the write-temp-then-rename save idiom).
// Cross-directory rename goes through `rename_to`, which MemDir does not
// override → the trait default returns `Unsupported`. Both facts are pinned.

fn smoke_memfs_rename_within_and_cross() -> TestResult {
    const OLD: &[u8] = b"original contents";
    const NEW: &[u8] = b"replacement";

    let fs = MemFs::new("memfs-rename");
    let root = fs.root();

    // Create "src" with known bytes, rename src → dst (no existing dst).
    let src = match poll_once(root.create("src")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create src failed"),
    };
    if poll_once(src.write(0, OLD)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("write src failed");
    }
    if poll_once(root.rename("src", "dst")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("rename src -> dst failed");
    }
    if root.lookup("src").is_some() {
        return TestResult::Fail("old name src still present after rename");
    }
    // dst must resolve and carry the original bytes.
    let dst = match root.lookup("dst") {
        Some(f) => f,
        None => return TestResult::Fail("dst not present after rename"),
    };
    let mut buf = vec![0u8; 64];
    let n = match poll_once(dst.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read dst after rename failed"),
    };
    if &buf[..n] != OLD {
        return TestResult::Fail("dst content mismatch after rename");
    }

    // Overwrite semantics: create "other" with NEW, rename other → dst.
    // The existing dst must be atomically replaced by other's node.
    let other = match poll_once(root.create("other")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create other failed"),
    };
    if poll_once(other.write(0, NEW)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("write other failed");
    }
    if poll_once(root.rename("other", "dst")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("overwriting rename other -> dst failed");
    }
    let dst2 = match root.lookup("dst") {
        Some(f) => f,
        None => return TestResult::Fail("dst missing after overwriting rename"),
    };
    let mut buf2 = vec![0u8; 64];
    let m = match poll_once(dst2.read(0, &mut buf2)) {
        Some(Ok(m)) => m,
        _ => return TestResult::Fail("read dst after overwrite failed"),
    };
    if &buf2[..m] != NEW {
        return TestResult::Fail("dst was not replaced by overwriting rename");
    }

    // Cross-directory rename via rename_to is not implemented by MemDir →
    // the DirOps trait default returns Unsupported.
    let subdir = match poll_once(root.mkdir("dir2")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir dir2 failed"),
    };
    let cross = poll_once(root.rename_to("dst", subdir.as_ref(), "moved", 0));
    match cross {
        Some(Err(FsError::Unsupported)) => {}
        _ => return TestResult::Fail("cross-dir rename_to did not report Unsupported"),
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/memfs", smoke_memfs_rename_within_and_cross);

// ── Smoke 7: mode / permission round-trip ─────────────────────────────
//
// File perms: created at 0o666; `FileOps::set_perms` (the chmod backing)
// updates the low-9 bits and `stat` reflects it. Directory perms:
// `DirOps::set_dir_mode` (chmod on a dir) updates and `dir_mode` reflects —
// the `chmod 0700 XDG_RUNTIME_DIR` path systemd/dbus require.

fn smoke_memfs_mode_perms_roundtrip() -> TestResult {
    let fs = MemFs::new("memfs-mode");
    let root = fs.root();

    // File chmod round-trip.
    let file = match poll_once(root.create("perm.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create perm.txt failed"),
    };
    if file.stat().mode.perms != 0o666 {
        return TestResult::Fail("initial file perms not 0o666");
    }
    if poll_once(file.set_perms(0o600)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("set_perms failed");
    }
    if file.stat().mode.perms != 0o600 {
        return TestResult::Fail("stat did not reflect set_perms(0o600)");
    }

    // Directory chmod round-trip. Fresh MemDir default is 0o755.
    let dir = match poll_once(root.mkdir("securedir")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir securedir failed"),
    };
    if dir.dir_mode() & 0o777 != 0o755 {
        return TestResult::Fail("fresh dir mode not 0o755");
    }
    dir.set_dir_mode(0o700);
    if dir.dir_mode() & 0o777 != 0o700 {
        return TestResult::Fail("dir_mode did not reflect set_dir_mode(0o700)");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/memfs", smoke_memfs_mode_perms_roundtrip);

// ── Smoke 8: truncate grows / shrinks; stat reflects ──────────────────
//
// `FileOps::truncate` resizes exactly: growing zero-fills, shrinking drops
// the tail. stat.size must track. This is ftruncate(2) on tmpfs.

fn smoke_memfs_truncate_grow_shrink() -> TestResult {
    const PAYLOAD: &[u8] = b"abcdefghij"; // 10 bytes

    let fs = MemFs::new("memfs-trunc");
    let root = fs.root();

    let file = match poll_once(root.create("t.bin")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create t.bin failed"),
    };
    if poll_once(file.write(0, PAYLOAD)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("initial write failed");
    }
    if file.stat().size != 10 {
        return TestResult::Fail("size not 10 after write");
    }

    // Shrink to 4.
    if poll_once(file.truncate(4)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("shrink truncate failed");
    }
    if file.stat().size != 4 {
        return TestResult::Fail("stat.size not 4 after shrink");
    }
    let mut buf = vec![0xFFu8; 16];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read after shrink failed"),
    };
    if n != 4 || &buf[..4] != b"abcd" {
        return TestResult::Fail("content after shrink is not the first 4 bytes");
    }

    // Grow to 8 — the two new bytes must be zero-filled.
    if poll_once(file.truncate(8)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("grow truncate failed");
    }
    if file.stat().size != 8 {
        return TestResult::Fail("stat.size not 8 after grow");
    }
    let mut buf2 = vec![0xFFu8; 16];
    let m = match poll_once(file.read(0, &mut buf2)) {
        Some(Ok(m)) => m,
        _ => return TestResult::Fail("read after grow failed"),
    };
    if m != 8 || buf2[..4] != *b"abcd" || buf2[4..8] != [0u8; 4] {
        return TestResult::Fail("grow did not zero-fill the tail");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/memfs", smoke_memfs_truncate_grow_shrink);

// ── Smoke 9: distinct inodes (rm_rf / DSO-dedup hazard guard) ──────────
//
// MemFs assigns a unique, stable st_ino to every node from a high base.
// This guards two real regressions:
//   - musl dedups DSOs by (st_dev, st_ino); same-ino files collapse.
//   - systemd's rm_rf refuses to descend when a dir and its parent share
//     (st_dev, st_ino) — a constant ino 0 makes every subdir look like /.
// Assert: two distinct files, and a subdir vs its parent root, all have
// distinct, non-zero ino().

fn smoke_memfs_distinct_inodes() -> TestResult {
    let fs = MemFs::new("memfs-ino");
    let root = fs.root();

    let f1 = match poll_once(root.create("one")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create one failed"),
    };
    let f2 = match poll_once(root.create("two")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create two failed"),
    };
    let sub = match poll_once(root.mkdir("child")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir child failed"),
    };

    let ino1 = f1.ino();
    let ino2 = f2.ino();
    let root_ino = root.ino();
    let sub_ino = sub.ino();

    // MemFs mints real inodes — none should be the synthetic 0.
    if ino1 == 0 || ino2 == 0 || root_ino == 0 || sub_ino == 0 {
        return TestResult::Fail("MemFs node reported the synthetic ino 0");
    }
    // Two distinct files must not alias.
    if ino1 == ino2 {
        return TestResult::Fail("two distinct files share an inode");
    }
    // A subdir must be distinct from its parent (the rm_rf root-guard).
    if sub_ino == root_ino {
        return TestResult::Fail("subdir and parent root share an inode");
    }
    // And files must be distinct from directories.
    if ino1 == root_ino || ino1 == sub_ino || ino2 == root_ino || ino2 == sub_ino {
        return TestResult::Fail("a file inode collided with a directory inode");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/memfs", smoke_memfs_distinct_inodes);

// ── Smoke 10: mount via registry, write through path, unmount → NotFound ─
//
// The one VFS-path smoke: mount a MemFs, resolve + create a file through
// the mount, write + read it back, unmount, then re-resolve and confirm
// the path is gone. Cleanup unmounts on every exit path.

fn smoke_memfs_registry_mount_roundtrip() -> TestResult {
    const PATH: &str = "/memfs_reg";
    const PAYLOAD: &[u8] = b"through the vfs";

    let auth = bootstrap_mount_authority();
    let handle = match registry().mount(&auth, PATH, MemFs::new("memfs-reg")) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount() failed"),
    };

    // Create a file at the mount root, write, read back.
    let root = match registry().with_mount(PATH, |fs| fs.root()) {
        Some(r) => r,
        None => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("with_mount returned None");
        }
    };
    let file = match poll_once(root.create("f.txt")) {
        Some(Ok(f)) => f,
        _ => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("create through mount failed");
        }
    };
    if poll_once(file.write(0, PAYLOAD)).map(|r| r.is_ok()) != Some(true) {
        let _ = registry().unmount(&handle, PATH);
        return TestResult::Fail("write through mount failed");
    }

    // Re-resolve by path and read back.
    let resolved = registry().with_mount(PATH, |fs| resolve(fs.root(), "f.txt"));
    let rfile = match resolved {
        Some(Ok(f)) => f,
        _ => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("resolve f.txt through mount failed");
        }
    };
    let mut buf = vec![0u8; 32];
    let n = match poll_once(rfile.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => {
            let _ = registry().unmount(&handle, PATH);
            return TestResult::Fail("read through mount failed");
        }
    };
    if n != PAYLOAD.len() || &buf[..n] != PAYLOAD {
        let _ = registry().unmount(&handle, PATH);
        return TestResult::Fail("readback through mount mismatch");
    }

    // Unmount, then confirm the path is gone.
    if registry().unmount(&handle, PATH).is_err() {
        return TestResult::Fail("unmount failed");
    }
    if registry().with_mount(PATH, |_| ()).is_some() {
        return TestResult::Fail("mount still visible after unmount");
    }
    // A covering `/` boot mount may match the path prefix, but resolving
    // the memfs file through it must fail — success would mean the FS is
    // still live.
    let post = registry().resolve_absolute(PATH, |fs, rel| resolve(fs.root(), rel));
    if matches!(post, Some(Ok(_))) {
        return TestResult::Fail("resolve_absolute found path after unmount");
    }

    TestResult::Pass
}
kernel_test_in!("filesystem/memfs", smoke_memfs_registry_mount_roundtrip);
