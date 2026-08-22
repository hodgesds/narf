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
//!   6. `smoke_memfs_rename_within_and_cross`— rename within-dir overwrites; cross-dir moves
//!   7. `smoke_memfs_mode_perms_roundtrip`   — create mode, stat shows it; set_perms/chmod round-trip
//!   8. `smoke_memfs_truncate_grow_shrink`   — truncate grows (zero-fill) / shrinks; stat reflects
//!   9. `smoke_memfs_distinct_inodes`        — distinct files, and dir vs parent, have distinct ino()
//!  10. `smoke_memfs_registry_mount_roundtrip` — mount via registry, write through path, unmount → NotFound
//!  11. `smoke_memfs_large_dir_enumerate_walks_all` — N-entry readdir returns every name once, sorted; lookup/remove all
//!
//! GPL-2.0-or-later — NARF is GPL-2.0-or-later as of 2026-05-20.

extern crate alloc;

use alloc::vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{
    bootstrap_mount_authority, registry, resolve, FileType, FsDqBlk, FsError, FsInstance, MemFs,
    QuotaKind, RamFs, RamFsOptions, TmpFs, TmpFsOptions, QIF_BLIMITS,
};

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
// Cross-directory rename goes through `rename_to` and must move the same
// inode into the destination directory.

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

    // Cross-directory rename preserves the inode and contents.
    let subdir = match poll_once(root.mkdir("dir2")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir dir2 failed"),
    };
    let moved_ino = dst2.ino();
    if poll_once(root.rename_to("dst", subdir.as_ref(), "moved", 0)).map(|result| result.is_ok())
        != Some(true)
    {
        return TestResult::Fail("cross-dir rename_to failed");
    }
    if root.lookup("dst").is_some() {
        return TestResult::Fail("cross-dir rename left the old name behind");
    }
    let moved = match subdir.lookup("moved") {
        Some(file) => file,
        None => return TestResult::Fail("cross-dir rename did not create destination"),
    };
    if moved.ino() != moved_ino {
        return TestResult::Fail("cross-dir rename changed inode identity");
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

fn smoke_tmpfs_linux_mount_options() -> TestResult {
    let parsed = match TmpFsOptions::parse(
        "size=25%,nr_inodes=2K,mode=0710,uid=12,gid=34,noswap,inode32,huge=never",
        4096,
        1,
        2,
    ) {
        Ok(parsed) => parsed,
        Err(_) => return TestResult::Fail("valid Linux tmpfs options were rejected"),
    };
    if parsed.max_blocks != Some(1024)
        || parsed.max_inodes != Some(2048)
        || parsed.root_mode != 0o710
        || parsed.root_uid != 12
        || parsed.root_gid != 34
        || !parsed.noswap
        || parsed.inode64
    {
        return TestResult::Fail("tmpfs option values were parsed incorrectly");
    }
    if TmpFsOptions::parse("huge=always", 4096, 0, 0).is_ok()
        || TmpFsOptions::parse("size=101%", 4096, 0, 0).is_ok()
        || TmpFsOptions::parse("mode=888", 4096, 0, 0).is_ok()
    {
        return TestResult::Fail("unsupported or malformed tmpfs option was accepted");
    }
    let ramfs = match RamFsOptions::parse("size=1M,unknown=value,mode=0701", 9, 10) {
        Ok(parsed) => parsed,
        Err(_) => return TestResult::Fail("ramfs rejected historically ignored options"),
    };
    if ramfs.root_mode != 0o701 || ramfs.root_uid != 9 || ramfs.root_gid != 10 {
        return TestResult::Fail("ramfs mode/owner options were parsed incorrectly");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_linux_mount_options);

/// tmpfs `usrquota`: a per-user block hard limit is enforced (EDQUOT), other
/// users are unaffected, and chown transfers the charge to the new owner.
fn smoke_tmpfs_usrquota_blocks_and_transfer() -> TestResult {
    const U: u32 = 1000;
    // usrquota on; generous mount size so the per-user limit is what bites.
    let fs = match TmpFs::from_options_with_total("usrquota,size=1M", 4096, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("usrquota tmpfs construction failed"),
    };
    // Give uid 1000 a 2-block hard limit.
    let limit = FsDqBlk {
        blocks_hard: 2,
        valid: QIF_BLIMITS,
        ..Default::default()
    };
    if fs.quota_set(QuotaKind::User, U, &limit).is_err() {
        return TestResult::Fail("quota_set(user) failed");
    }
    let root = fs.root();
    let file = match poll_once(root.create("u1000")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    if poll_once(file.set_owners(U, 0)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("chown to uid 1000 failed");
    }
    // Two pages = exactly the limit → OK.
    if poll_once(file.write(0, &[b'x'; 8192])).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("write within quota failed");
    }
    // A third page must exceed the hard limit → EDQUOT (QuotaExceeded).
    if !matches!(
        poll_once(file.write(8192, b"y")),
        Some(Err(FsError::QuotaExceeded))
    ) {
        return TestResult::Fail("over-quota write did not return QuotaExceeded");
    }
    // The user's usage is exactly the limit.
    match fs.quota_get(QuotaKind::User, U) {
        Ok(dq) if dq.blocks_used == 2 && dq.blocks_hard == 2 => {}
        _ => return TestResult::Fail("quota_get did not report used==2"),
    }
    // A file owned by root (uid 0, no limit set) is unaffected.
    let rootfile = match poll_once(root.create("root")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create root file failed"),
    };
    if poll_once(rootfile.write(0, &[b'z'; 8192 * 4])).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("unlimited (root-owned) write hit a quota");
    }
    // chown the capped file back to root → uid 1000's usage drops to zero.
    if poll_once(file.set_owners(0, 0)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("chown back to root failed");
    }
    match fs.quota_get(QuotaKind::User, U) {
        Ok(dq) if dq.blocks_used == 0 => {}
        _ => return TestResult::Fail("chown did not transfer the charge off uid 1000"),
    }
    // And chowning a file ONTO an already-full user must fail with EDQUOT.
    if poll_once(file.set_owners(U, 0)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("re-chown onto uid 1000 (2 blocks == limit) should fit");
    }
    let file2 = match poll_once(root.create("u1000b")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create second file failed"),
    };
    if poll_once(file2.write(0, b"q")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("root-owned write failed");
    }
    if !matches!(
        poll_once(file2.set_owners(U, 0)),
        Some(Err(FsError::QuotaExceeded))
    ) {
        return TestResult::Fail("chown onto an over-limit user did not return EDQUOT");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_usrquota_blocks_and_transfer);

/// tmpfs quota soft vs hard limit: writes are allowed PAST the soft limit
/// (within the default grace period) but blocked at the hard limit — the
/// distinction that separates a soft warning from a hard cap. Deterministic
/// (the default 7-day grace never expires during the test, so no wall-clock
/// dependency).
fn smoke_tmpfs_usrquota_soft_vs_hard() -> TestResult {
    const U: u32 = 1001;
    let fs = match TmpFs::from_options_with_total("usrquota,size=1M", 4096, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("usrquota tmpfs construction failed"),
    };
    // Soft limit 1 block, hard limit 3 blocks.
    let limit = FsDqBlk {
        blocks_soft: 1,
        blocks_hard: 3,
        valid: QIF_BLIMITS,
        ..Default::default()
    };
    if fs.quota_set(QuotaKind::User, U, &limit).is_err() {
        return TestResult::Fail("quota_set(soft+hard) failed");
    }
    let root = fs.root();
    let file = match poll_once(root.create("soft")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    if poll_once(file.set_owners(U, 0)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("chown failed");
    }
    // Three pages: crosses the soft limit at page 2 but stays within grace and
    // under the hard limit, so all succeed.
    if poll_once(file.write(0, &[b'a'; 4096 * 3])).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("writes up to the hard limit (past soft) should succeed");
    }
    // A fourth page exceeds the hard limit → EDQUOT.
    if !matches!(
        poll_once(file.write(4096 * 3, b"d")),
        Some(Err(FsError::QuotaExceeded))
    ) {
        return TestResult::Fail("write past the hard limit did not return EDQUOT");
    }
    // The soft-limit grace deadline is armed (over soft) — verify it is recorded.
    // (`btime` is a wall-clock deadline; if the test clock is 0 it may read 0,
    // so only assert usage here, which is clock-independent.)
    match fs.quota_get(QuotaKind::User, U) {
        Ok(dq) if dq.blocks_used == 3 => {}
        _ => return TestResult::Fail("quota_get should report 3 blocks used"),
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_usrquota_soft_vs_hard);

fn smoke_tmpfs_sparse_block_and_inode_limits() -> TestResult {
    let fs = match TmpFs::from_options_with_total("size=8K,nr_inodes=3", 1024, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let root = fs.root();
    let initial = match poll_once(fs.statfs()) {
        Some(Ok(stat)) => stat,
        _ => return TestResult::Fail("initial tmpfs statfs failed"),
    };
    if initial.blocks != 2 || initial.blocks_free != 2 || initial.files_free != 2 {
        return TestResult::Fail("initial tmpfs statfs limits are wrong");
    }
    let file = match poll_once(root.create("sparse")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs file creation failed"),
    };
    if poll_once(file.truncate(1 << 30)).map(|result| result.is_ok()) != Some(true) {
        return TestResult::Fail("sparse truncate failed");
    }
    let after_hole = match poll_once(fs.statfs()) {
        Some(Ok(stat)) => stat,
        _ => return TestResult::Fail("tmpfs statfs after hole failed"),
    };
    if after_hole.blocks_free != 2 || file.stat().blocks != 0 {
        return TestResult::Fail("sparse truncate consumed tmpfs blocks");
    }
    if poll_once(file.write(0, b"a")).map(|result| result.is_ok()) != Some(true)
        || poll_once(file.write(8192, b"b")).map(|result| result.is_ok()) != Some(true)
    {
        return TestResult::Fail("writes within tmpfs block limit failed");
    }
    if !matches!(
        poll_once(file.write(16384, b"c")),
        Some(Err(FsError::NoSpace))
    ) {
        return TestResult::Fail("tmpfs block limit did not return NoSpace");
    }
    let full = match poll_once(fs.statfs()) {
        Some(Ok(stat)) => stat,
        _ => return TestResult::Fail("tmpfs full statfs failed"),
    };
    if full.blocks_free != 0 || file.stat().blocks != 16 {
        return TestResult::Fail("tmpfs allocated-page accounting is wrong");
    }
    if poll_once(file.truncate(4096)).map(|result| result.is_ok()) != Some(true) {
        return TestResult::Fail("tmpfs shrink failed");
    }
    let shrunk = match poll_once(fs.statfs()) {
        Some(Ok(stat)) => stat,
        _ => return TestResult::Fail("tmpfs shrunk statfs failed"),
    };
    if shrunk.blocks_free != 1 || file.stat().blocks != 8 {
        return TestResult::Fail("tmpfs shrink did not release blocks");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/tmpfs",
    smoke_tmpfs_sparse_block_and_inode_limits
);

fn smoke_tmpfs_unlinked_open_inode_lifetime() -> TestResult {
    let fs = match TmpFs::from_options_with_total("size=16K,nr_inodes=2", 1024, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let root = fs.root();
    let held = match poll_once(root.create("held")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("first inode reservation failed"),
    };
    if !matches!(poll_once(root.create("full")), Some(Err(FsError::NoSpace))) {
        return TestResult::Fail("tmpfs inode limit was not enforced");
    }
    if poll_once(root.unlink("held")).map(|result| result.is_ok()) != Some(true) {
        return TestResult::Fail("unlink of held tmpfs file failed");
    }
    if !matches!(
        poll_once(root.create("still-full")),
        Some(Err(FsError::NoSpace))
    ) {
        return TestResult::Fail("unlink released an inode still held open");
    }
    drop(held);
    if poll_once(root.create("reused")).map(|result| result.is_ok()) != Some(true) {
        return TestResult::Fail("last close did not release tmpfs inode");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_unlinked_open_inode_lifetime);

fn smoke_tmpfs_unlinked_open_fifo_inode_lifetime() -> TestResult {
    let fs = match TmpFs::from_options_with_total("size=16K,nr_inodes=2", 1024, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let root = fs.root();
    let node = match poll_once(root.mknod("fifo", FileType::Fifo, 0)) {
        Some(Ok(node)) => node,
        _ => return TestResult::Fail("tmpfs FIFO creation failed"),
    };
    let shared = match node.fifo_shared() {
        Some(shared) => shared,
        None => return TestResult::Fail("tmpfs FIFO has no shared state"),
    };
    let handle = crate::fifo::FifoHandle::open_owned(
        shared,
        node.clone(),
        node.ino(),
        node.stat().mode.perms,
        0,
        0,
        true,
        true,
    );
    drop(node);
    if poll_once(root.unlink("fifo")).map(|result| result.is_ok()) != Some(true) {
        return TestResult::Fail("tmpfs FIFO unlink failed");
    }
    if !matches!(
        poll_once(root.create("still-full")),
        Some(Err(FsError::NoSpace))
    ) {
        return TestResult::Fail("open FIFO did not retain its tmpfs inode charge");
    }
    drop(handle);
    if poll_once(root.create("reused")).map(|result| result.is_ok()) != Some(true) {
        return TestResult::Fail("closing unlinked FIFO did not release inode charge");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/tmpfs",
    smoke_tmpfs_unlinked_open_fifo_inode_lifetime
);

fn smoke_tmpfs_fallocate_seek_and_hole_punch() -> TestResult {
    const KEEP_SIZE: u32 = 0x01;
    const PUNCH_HOLE: u32 = 0x02;
    const SEEK_DATA: u32 = 3;
    const SEEK_HOLE: u32 = 4;
    let fs = match TmpFs::from_options_with_total("size=16K,nr_inodes=3", 1024, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let file = match poll_once(fs.root().create("allocated")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs file creation failed"),
    };
    if poll_once(file.truncate(16 * 1024)).map(|result| result.is_ok()) != Some(true)
        || poll_once(file.fallocate(KEEP_SIZE, 4096, 4096)).map(|result| result.is_ok())
            != Some(true)
        || poll_once(file.seek(0, SEEK_DATA)) != Some(Ok(4096))
        || poll_once(file.seek(4096, SEEK_HOLE)) != Some(Ok(8192))
    {
        return TestResult::Fail("tmpfs fallocate or sparse seek semantics are wrong");
    }
    if poll_once(file.fallocate(PUNCH_HOLE | KEEP_SIZE, 4096, 4096)).map(|result| result.is_ok())
        != Some(true)
        || poll_once(file.seek(0, SEEK_DATA)).is_none()
    {
        return TestResult::Fail("tmpfs hole punch failed");
    }
    if !matches!(
        poll_once(file.seek(0, SEEK_DATA)),
        Some(Err(FsError::NoSpace))
    ) || file.stat().size != 16 * 1024
        || file.stat().blocks != 0
    {
        return TestResult::Fail("tmpfs punched file did not become a sparse hole");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/tmpfs",
    smoke_tmpfs_fallocate_seek_and_hole_punch
);

fn smoke_tmpfs_cross_dir_link_and_special_node() -> TestResult {
    let fs = match TmpFs::from_options_with_total("size=16K,nr_inodes=8", 1024, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let root = fs.root();
    let dir = match poll_once(root.mkdir("dir")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("tmpfs mkdir failed"),
    };
    let file = match poll_once(root.create("source")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs create failed"),
    };
    if poll_once(root.link_to("source", dir.as_ref(), "linked")).map(|result| result.is_ok())
        != Some(true)
    {
        return TestResult::Fail("cross-directory tmpfs hard link failed");
    }
    if dir.lookup("linked").map(|linked| linked.ino()) != Some(file.ino()) {
        return TestResult::Fail("tmpfs hard link did not preserve inode");
    }
    let node = match poll_once(root.mknod("ttyX", FileType::Special, (4 << 8) | 1)) {
        Some(Ok(node)) => node,
        _ => return TestResult::Fail("tmpfs character-device mknod failed"),
    };
    if node.stat().mode.file_type != FileType::Special || node.rdev() != ((4 << 8) | 1) {
        return TestResult::Fail("tmpfs special node lost type or rdev");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/tmpfs",
    smoke_tmpfs_cross_dir_link_and_special_node
);

fn smoke_tmpfs_xattrs_and_reconfigure() -> TestResult {
    let fs = match TmpFs::from_options_with_total("size=16K,nr_inodes=8", 1024, 7, 8) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let root = fs.root();
    if root.dir_mode() != 0o1777 || root.dir_owners() != (7, 8) {
        return TestResult::Fail("tmpfs default root metadata is not Linux-shaped");
    }
    let file = match poll_once(root.create("xattr")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs create failed"),
    };
    if poll_once(file.set_xattr("user.test", b"value", 1)).map(|result| result.is_ok())
        != Some(true)
        || poll_once(file.get_xattr("user.test")) != Some(Ok(b"value".to_vec()))
        || poll_once(file.list_xattr()) != Some(Ok(b"user.test\0".to_vec()))
    {
        return TestResult::Fail("tmpfs xattr round-trip failed");
    }
    if fs.reconfigure("size=4K,nr_inodes=4").is_err() {
        return TestResult::Fail("valid tmpfs shrink remount failed");
    }
    let resized = match poll_once(fs.statfs()) {
        Some(Ok(stat)) => stat,
        _ => return TestResult::Fail("tmpfs statfs after reconfigure failed"),
    };
    if resized.blocks != 1 || resized.files != 4 {
        return TestResult::Fail("tmpfs reconfigure did not update statfs limits");
    }
    if fs.reconfigure("nr_inodes=1").is_ok() {
        return TestResult::Fail("tmpfs remount accepted an inode limit below usage");
    }

    let ramfs = match RamFs::from_options("size=1,mode=0700", 3, 4) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("ramfs construction failed"),
    };
    let ram_root = ramfs.root();
    let ram_stat = match poll_once(ramfs.statfs()) {
        Some(Ok(stat)) => stat,
        _ => return TestResult::Fail("ramfs statfs failed"),
    };
    if ramfs.name() != "ramfs"
        || ram_root.dir_mode() != 0o700
        || ram_root.dir_owners() != (3, 4)
        || ram_stat.blocks != 0
        || ram_stat.files != 0
        || ramfs.reconfigure("size=1M").is_ok()
    {
        return TestResult::Fail("ramfs identity/options/statfs semantics are wrong");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_xattrs_and_reconfigure);

// ── Smoke: large-directory readdir walks every entry exactly once ─────
//
// stress-ng's chdir/dirdeep classes create thousands of entries in one
// tmpfs directory, then read them all back and remove them. getdents64
// drives readdir by snapshotting the tail at each cursor via
// `enumerate_async(cursor, usize::MAX)` and serving entries positionally,
// so this test reproduces that walk directly: it fills a directory with N
// entries, then advances a cursor one entry at a time — requesting the
// remaining tail on each step — and asserts every created name is
// returned exactly once, in the BTreeMap's sorted order. It also confirms
// lookup and removal of all N entries succeed, guarding the tmpfs
// create/enumerate/remove path that mass mkdir/rmdir hammers.
fn smoke_memfs_large_dir_enumerate_walks_all() -> TestResult {
    const N: usize = 2048;
    let fs = MemFs::new("memfs-bigdir");
    let root = fs.root();

    // Create N entries with names whose lexicographic order differs from
    // creation order, so a correct sorted readdir can't accidentally pass
    // by echoing insertion order.
    for i in 0..N {
        let name = alloc::format!("entry-{:05}", (i * 7919) % N);
        if poll_once(root.create(&name)).map(|r| r.is_ok()) != Some(true) {
            return TestResult::Fail("create in large dir failed");
        }
    }

    // Positional walk mirroring the getdents64 handler: snapshot the tail
    // at `cursor`, consume its head, advance the cursor by one.
    let mut seen: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
    let mut cursor = 0usize;
    loop {
        let tail = match poll_once(root.enumerate_async(cursor, usize::MAX)) {
            Some(Ok(v)) => v,
            _ => return TestResult::Fail("enumerate_async tail snapshot failed"),
        };
        let head = match tail.into_iter().next() {
            Some(e) => e,
            None => break,
        };
        seen.push(head.0);
        cursor += 1;
    }

    if seen.len() != N {
        return TestResult::Fail("readdir did not return exactly N entries");
    }
    // BTreeMap iteration is sorted; the positional walk must be sorted too.
    if seen.windows(2).any(|w| w[0] >= w[1]) {
        return TestResult::Fail("readdir entries not strictly sorted / had a duplicate");
    }

    // Every created name is lookup-resolvable and removable.
    for i in 0..N {
        let name = alloc::format!("entry-{:05}", (i * 7919) % N);
        if root.lookup(&name).is_none() {
            return TestResult::Fail("large-dir entry not found by lookup");
        }
        if poll_once(root.unlink(&name)).map(|r| r.is_ok()) != Some(true) {
            return TestResult::Fail("unlink of large-dir entry failed");
        }
    }
    if !root.enumerate(0, 1).is_empty() {
        return TestResult::Fail("directory not empty after removing all entries");
    }

    TestResult::Pass
}
kernel_test_in!(
    "filesystem/memfs",
    smoke_memfs_large_dir_enumerate_walks_all
);
