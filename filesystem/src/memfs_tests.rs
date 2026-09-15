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

/// Successful subdirectory lookups enter the per-CPU read cache. Warm each
/// name before mutating it so this test proves rename/rmdir generations reject
/// stale cache entries rather than merely exercising the BTreeMap slow path.
fn smoke_memfs_dir_cache_invalidates_mutations() -> TestResult {
    let fs = MemFs::new("memfs-dir-cache");
    let root = fs.root();

    let original = match poll_once(root.mkdir("old")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("mkdir old failed"),
    };
    let original_ino = original.ino();
    if root.lookup_dir("old").is_none() || root.lookup_dir("old").is_none() {
        return TestResult::Fail("could not warm old directory lookup");
    }

    if poll_once(root.rename("old", "new")).map(|result| result.is_ok()) != Some(true) {
        return TestResult::Fail("directory rename failed");
    }
    if root.lookup_dir("old").is_some() {
        return TestResult::Fail("cached old name survived rename");
    }
    if root.lookup_dir("new").map(|dir| dir.ino()) != Some(original_ino) {
        return TestResult::Fail("renamed directory missing or changed identity");
    }

    if poll_once(root.rmdir("new")).map(|result| result.is_ok()) != Some(true) {
        return TestResult::Fail("rmdir new failed");
    }
    if root.lookup_dir("new").is_some() {
        return TestResult::Fail("cached directory survived rmdir");
    }

    let replacement = match poll_once(root.mkdir("new")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("replacement mkdir failed"),
    };
    if replacement.ino() == original_ino
        || root.lookup_dir("new").map(|dir| dir.ino()) != Some(replacement.ino())
    {
        return TestResult::Fail("recreated name resolved to stale cached directory");
    }

    TestResult::Pass
}
kernel_test_in!(
    "filesystem/memfs",
    smoke_memfs_dir_cache_invalidates_mutations
);

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

/// A `MAP_SHARED` mapping of a tmpfs file aliases the FILE'S OWN page.
///
/// On Linux a tmpfs page and its mapped page are one object: the folio
/// `shmem_get_folio` returns is the page `filemap_map_pages` installs, and
/// `read`/`write` reach it through the same `address_space`. So a store
/// through the mapping IS a store to the file and vice versa, with no
/// `msync` anywhere.
///
/// NARF used to route tmpfs onto the generic fallback in `mapped_file`,
/// which gives each `(file, offset)` a PRIVATE frame, copies the bytes in
/// at fault time and back out on `msync`/`fsync`. Neither direction
/// worked: a store through the mapping was invisible to `read(2)` until an
/// explicit flush, and a `write(2)` was invisible to an already-faulted
/// mapping forever. `memfd_create` + `mmap` — Wayland buffers, dbus,
/// PulseAudio — is exactly that shape.
///
/// This drives `FileOps::mmap_fault` and the frame it hands back directly,
/// which is the object `sys_mmap` installs into the PTE; a full user
/// mapping adds an address space but not a different page.
fn smoke_memfs_mmap_fault_aliases_the_file_page() -> TestResult {
    let fs = MemFs::new("memfs-mmap-shared");
    let file = match poll_once(fs.root().create("shared")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("create mapped file failed"),
    };
    // The generic copy path is opted into by `mmap_cache_generation`, and
    // `sys_mmap` picks between the two on exactly that. tmpfs must not
    // advertise it, or none of the below is reachable from a real mmap.
    if file.mmap_cache_generation().is_some() {
        return TestResult::Fail("tmpfs still opts into the private-copy mmap path");
    }
    if poll_once(file.write(0, b"from-write")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("seed write failed");
    }
    let phys = match file.mmap_fault(0) {
        Ok(phys) => phys,
        Err(_) => return TestResult::Fail("tmpfs does not support demand-paged mmap"),
    };
    if phys == 0 || phys % 4096 != 0 {
        return TestResult::Fail("mmap_fault returned an unusable frame address");
    }
    // SAFETY: `phys` is a live frame owned by the file, which this test
    // holds; `kernel_mut_ptr` is its direct-map address.
    let mapped = unsafe {
        core::slice::from_raw_parts_mut(
            narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>(),
            4096,
        )
    };
    // Direction 1: a write(2) is visible through the mapping.
    if &mapped[..10] != b"from-write" {
        return TestResult::Fail("a write(2) was not visible through the mapping");
    }
    // Direction 2: a store through the mapping is visible to read(2),
    // with no msync.
    mapped[..9].copy_from_slice(b"from-mmap");
    let mut back = [0u8; 9];
    if poll_once(file.read(0, &mut back)) != Some(Ok(9)) || &back != b"from-mmap" {
        return TestResult::Fail("a store through the mapping was not visible to read(2)");
    }
    // Idempotent per offset: the fault handler can run twice for one page
    // on two CPUs, and a second frame would simply be dropped.
    if file.mmap_fault(0) != Ok(phys) {
        return TestResult::Fail("mmap_fault is not idempotent for one offset");
    }
    // A fault past the end grows the file — the mapping TRACKS the file
    // rather than snapshotting it, which is the whole reason this is
    // `mmap_fault` and not `mmap_frames`.
    let grown = match file.mmap_fault(8192) {
        Ok(phys) => phys,
        Err(_) => return TestResult::Fail("mmap_fault of a hole failed"),
    };
    if grown == phys {
        return TestResult::Fail("two different offsets share one frame");
    }
    if file.stat().size < 8192 + 4096 {
        return TestResult::Fail("a fault past the end did not grow the file");
    }
    // The page is real file content: readable, and charged.
    if file.stat().blocks != 2 * (4096 / 512) {
        return TestResult::Fail("mmap_fault did not charge its pages as blocks");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/memfs",
    smoke_memfs_mmap_fault_aliases_the_file_page
);

/// A mapped page survives being truncated away, and keeps its charge.
///
/// Linux would `unmap_mapping_range` the inode and let further accesses
/// take SIGBUS. NARF has no reverse map from a file range to the mappings
/// of it and no cross-address-space PTE invalidation, so freeing the frame
/// would hand the buddy allocator a page userspace can still write —
/// the hazard `mapped_file`'s module header exists to describe.
///
/// So a page that has been handed to `mmap_fault` is RETIRED rather than
/// freed: dropped from the file's contents, kept as a frame until the
/// inode dies. It keeps its block charge, which is the part that matters
/// for more than safety — without it, `mmap` a page, punch it, repeat
/// would be an unbounded allocation the mount's own accounting reports as
/// empty. See `filesystem/specification/tmpfs-shared-mappings.md`.
fn smoke_memfs_mapped_page_is_retired_not_freed() -> TestResult {
    const PUNCH_HOLE: u32 = 0x02;
    const KEEP_SIZE: u32 = 0x01;
    let fs = match TmpFs::from_options_with_total("size=64K,nr_inodes=8", 4096, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let file = match poll_once(fs.root().create("mapped")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs create failed"),
    };
    if poll_once(file.write(0, &[0xA5u8; 8192])).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("seed write failed");
    }
    // Map the FIRST page only; the second stays unmapped so the two
    // removal paths can be told apart.
    if file.mmap_fault(0).is_err() {
        return TestResult::Fail("mmap_fault failed");
    }
    let used = |fs: &TmpFs| match poll_once(fs.statfs()) {
        Some(Ok(stat)) => stat.blocks - stat.blocks_free,
        _ => u64::MAX,
    };
    if used(&fs) != 2 {
        return TestResult::Fail("two written pages are not two charged blocks");
    }
    // Punch the UNMAPPED page: its frame is freed and its charge released.
    if poll_once(file.fallocate(PUNCH_HOLE | KEEP_SIZE, 4096, 4096)).map(|r| r.is_ok())
        != Some(true)
    {
        return TestResult::Fail("hole punch of the unmapped page failed");
    }
    if used(&fs) != 1 {
        return TestResult::Fail("punching an unmapped page did not release its block");
    }
    // Punch the MAPPED page: it leaves the file's contents — the read is a
    // hole now — but the frame and its charge stay.
    if poll_once(file.fallocate(PUNCH_HOLE | KEEP_SIZE, 0, 4096)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("hole punch of the mapped page failed");
    }
    let mut back = [0xFFu8; 8];
    if poll_once(file.read(0, &mut back)) != Some(Ok(8)) || back != [0u8; 8] {
        return TestResult::Fail("the punched page did not read back as a hole");
    }
    if used(&fs) != 1 {
        return TestResult::Fail("a retired page lost its charge — mmap-then-punch would be free");
    }
    // The mount still works afterwards: retention is bounded by what was
    // mapped, not a wedge.
    if poll_once(fs.root().create("after")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("the filesystem was unusable after a retirement");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/memfs",
    smoke_memfs_mapped_page_is_retired_not_freed
);
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
        // `mode=888` is not octal: `fsparam_u32oct` runs kstrtouint(.., 8).
        || TmpFsOptions::parse("mode=888", 4096, 0, 0).is_ok()
        || TmpFsOptions::parse("noswap=1", 4096, 0, 0).is_ok()
        || TmpFsOptions::parse("casefold", 4096, 0, 0).is_ok()
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

/// tmpfs sizing options parse exactly as Linux parses them.
///
/// `shmem_parse_one` runs every numeric option through `memparse`
/// (`lib/cmdline.c`) and then rejects the value if anything is left over —
/// `if (*rest) goto bad_value`. That pins four behaviours NARF used to get
/// wrong, each of which either failed a mount Linux accepts or accepted one
/// it rejects:
///
///  * suffixes are ONE letter from `K M G T P E`, either case. `1kB` leaves
///    a `B` in `rest` and is a bad value, even though it reads like a unit.
///  * the number is `simple_strtoull(.., 0)`, so `0x`-hex and leading-zero
///    octal are legal spellings of a size.
///  * `size=N%` has NO upper bound — an over-committed `size=200%` tmpfs is
///    a legal (if unwise) mount, not EINVAL.
///  * `mode=` is masked with 07777, not range-checked, so `mode=17777`
///    mounts as 07777.
fn smoke_tmpfs_memparse_matches_linux() -> TestResult {
    let blocks = |options: &str| TmpFsOptions::parse(options, 4096, 0, 0).map(|o| o.max_blocks);
    // 1 MiB = 256 pages, spelled four ways memparse accepts.
    if blocks("size=1M") != Ok(Some(256))
        || blocks("size=1m") != Ok(Some(256))
        || blocks("size=1024K") != Ok(Some(256))
        || blocks("size=0x100000") != Ok(Some(256))
        // Leading zero is octal: 04000000 == 1 MiB.
        || blocks("size=04000000") != Ok(Some(256))
        // A bare byte count rounds UP to whole pages (DIV_ROUND_UP).
        || blocks("size=4097") != Ok(Some(2))
    {
        return TestResult::Fail("tmpfs size= does not parse like Linux memparse");
    }
    // Trailing junk — including the plausible-looking `kB`/`MB` — is a bad
    // value, because memparse consumes at most one suffix letter.
    if blocks("size=1kB").is_ok()
        || blocks("size=1MB").is_ok()
        || blocks("size=1M2").is_ok()
        || blocks("size=").is_ok()
        || blocks("size=junk").is_ok()
        || blocks("size=50%%").is_ok()
    {
        return TestResult::Fail("tmpfs size= accepted a value Linux rejects");
    }
    // Percentages: no 100% ceiling, and the arithmetic is Linux's —
    // bytes = (N << PAGE_SHIFT) * totalram / 100, THEN rounded up to whole
    // pages. 1% of 4096 pages is 41 blocks, not the 40 that
    // `N * pages / 100` would give, and 1% of a ONE-page machine still
    // rounds up to 1 block instead of collapsing to 0.
    if blocks("size=200%") != Ok(Some(8192))
        || blocks("size=1%") != Ok(Some(41))
        || TmpFsOptions::parse("size=1%", 1, 0, 0).map(|o| o.max_blocks) != Ok(Some(1))
    {
        return TestResult::Fail("tmpfs size=N% is not Linux's percentage arithmetic");
    }
    // nr_blocks > LONG_MAX and nr_inodes > ULONG_MAX/BOGO_INODE_SIZE are the
    // two explicit range rejections in shmem_parse_one.
    if TmpFsOptions::parse("nr_blocks=0x7fffffffffffffff", 4096, 0, 0).is_err()
        || TmpFsOptions::parse("nr_blocks=0x8000000000000000", 4096, 0, 0).is_ok()
        // ULONG_MAX / BOGO_INODE_SIZE == 0x003f_ffff_ffff_ffff.
        || TmpFsOptions::parse("nr_inodes=0x003fffffffffffff", 4096, 0, 0).is_err()
        || TmpFsOptions::parse("nr_inodes=0x0040000000000000", 4096, 0, 0).is_ok()
    {
        return TestResult::Fail("tmpfs block/inode count range checks do not match Linux");
    }
    // `size=0` / `nr_inodes=0` are Linux's explicit "no limit".
    if blocks("size=0") != Ok(None)
        || TmpFsOptions::parse("nr_inodes=0", 4096, 0, 0).map(|o| o.max_inodes) != Ok(None)
    {
        return TestResult::Fail("tmpfs zero limits are not unlimited");
    }
    // `result.uint_32 & 07777` masks; it does not reject.
    if TmpFsOptions::parse("mode=17777", 4096, 0, 0).map(|o| o.root_mode) != Ok(0o7777) {
        return TestResult::Fail("tmpfs mode= is not masked with 07777");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_memparse_matches_linux);

/// The quota mount options Linux tmpfs accepts, and what they mean.
///
/// Two things this pins that NARF had wrong:
///
///  * bare `quota` is `QTYPE_MASK_USR | QTYPE_MASK_GRP` — BOTH kinds — not
///    an alias for `usrquota` (`shmem_parse_one`, `case Opt_quota`).
///  * `{usr,grp}quota_{block,inode}_hardlimit=` exist at all. They are the
///    limit every id starts with (`shmem_acquire_dquot` copies them into a
///    freshly acquired dquot), so enforcement must bite for a user that
///    `setquota` has never been run for.
///
/// The block limit is a BYTE count, which is why the 8 KiB limit below
/// stops the third page rather than the third block-of-something.
fn smoke_tmpfs_quota_mount_hardlimits() -> TestResult {
    const U: u32 = 4242;
    let both = match TmpFsOptions::parse("quota", 4096, 0, 0) {
        Ok(parsed) => parsed,
        Err(_) => return TestResult::Fail("bare `quota` was rejected"),
    };
    if !both.usrquota || !both.grpquota {
        return TestResult::Fail("bare `quota` did not enable both quota kinds");
    }
    // Hard limits must be nonzero and within SHMEM_QUOTA_MAX_*_LIMIT.
    if TmpFsOptions::parse("usrquota,usrquota_block_hardlimit=0", 4096, 0, 0).is_ok()
        || TmpFsOptions::parse(
            "usrquota,usrquota_block_hardlimit=0x8000000000000000",
            4096,
            0,
            0,
        )
        .is_ok()
        || TmpFsOptions::parse("usrquota,usrquota_inode_hardlimit=0", 4096, 0, 0).is_ok()
    {
        return TestResult::Fail("an out-of-range quota hard limit was accepted");
    }
    let fs = match TmpFs::from_options_with_total(
        "usrquota,size=1M,usrquota_block_hardlimit=8K,usrquota_inode_hardlimit=4",
        4096,
        0,
        0,
    ) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("quota hard-limit mount options were rejected"),
    };
    let root = fs.root();
    let file = match poll_once(root.create("charged")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs create failed"),
    };
    if poll_once(file.set_owners(U, U)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("chown to the limited uid failed");
    }
    // 8 KiB of block hard limit = exactly two pages for this owner.
    if poll_once(file.write(0, &[1u8; 4096])).map(|r| r.is_ok()) != Some(true)
        || poll_once(file.write(4096, &[2u8; 4096])).map(|r| r.is_ok()) != Some(true)
    {
        return TestResult::Fail("writes inside the default block hard limit failed");
    }
    if !matches!(
        poll_once(file.write(8192, &[3u8; 4096])),
        Some(Err(FsError::QuotaExceeded))
    ) {
        return TestResult::Fail("mount-default block hard limit was not enforced");
    }
    // The limit is the id's starting point, so a read-back reports it in
    // fs blocks (8 KiB / 4 KiB = 2) without any setquota having run.
    match fs.quota_get(QuotaKind::User, U) {
        Ok(blk) if blk.blocks_hard == 2 && blk.inodes_hard == 4 => {}
        _ => return TestResult::Fail("mount-default quota limits are not reported"),
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_quota_mount_hardlimits);

/// `mount -o remount` follows `shmem_reconfigure`.
///
/// Every failure there is `invalfc()` — **-EINVAL** — including the two
/// that read like capacity errors ("Too small a size for current use",
/// "Too few inodes for current use"). NARF reported ENOSPC for those, which
/// tells `mount` the filesystem is full rather than that the request was
/// refused.
fn smoke_tmpfs_remount_matches_shmem_reconfigure() -> TestResult {
    let fs = match TmpFs::from_options_with_total("size=1M,nr_inodes=16", 4096, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let file = match poll_once(fs.root().create("live")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs create failed"),
    };
    if poll_once(file.write(0, &[7u8; 8192])).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("tmpfs write failed");
    }
    // Two pages are in use, so a one-page limit strands them: EINVAL.
    if fs.reconfigure("size=4K") != Err(FsError::InvalidData) {
        return TestResult::Fail("too-small remount did not report EINVAL");
    }
    // Quota cannot be turned ON by a remount, and this mount has none.
    if fs.reconfigure("usrquota") != Err(FsError::InvalidData)
        || fs.reconfigure("quota") != Err(FsError::InvalidData)
    {
        return TestResult::Fail("remount enabled quota on a mount without it");
    }
    // size=0 lifts the limit even though data is live, then a limit cannot
    // be re-imposed on the now-unlimited mount ("Cannot retroactively
    // limit size").
    if fs.reconfigure("size=0").is_err() {
        return TestResult::Fail("remount to unlimited was rejected");
    }
    if fs.reconfigure("size=1M") != Err(FsError::InvalidData) {
        return TestResult::Fail("remount retroactively limited an unlimited mount");
    }

    let quota_fs = match TmpFs::from_options_with_total(
        "usrquota,size=1M,usrquota_block_hardlimit=8K",
        4096,
        0,
        0,
    ) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("quota tmpfs construction failed"),
    };
    // Quota already loaded: naming it again is accepted and does nothing.
    if quota_fs.reconfigure("usrquota").is_err() {
        return TestResult::Fail("remount rejected an already-loaded quota type");
    }
    // "Cannot change global quota limit on remount" — but repeating the
    // same value is fine.
    if quota_fs.reconfigure("usrquota_block_hardlimit=8K").is_err() {
        return TestResult::Fail("remount rejected an unchanged quota hard limit");
    }
    if quota_fs.reconfigure("usrquota_block_hardlimit=16K") != Err(FsError::InvalidData) {
        return TestResult::Fail("remount changed a global quota hard limit");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/tmpfs",
    smoke_tmpfs_remount_matches_shmem_reconfigure
);

/// `/proc/mounts` and mountinfo carry tmpfs's real options.
///
/// Linux `mm/shmem.c::shmem_show_options` prints a field only when it
/// differs from the default, which is why a plain `/run` reads as
/// `rw,inode64` and a sized one as `rw,size=…k,mode=755,inode64`. NARF used
/// to print a bare `rw` for every mount, so nothing downstream could see a
/// tmpfs's size, mode or quota state — `findmnt -o OPTIONS`, systemd's
/// mount-unit comparison, and any script grepping the size out of
/// /proc/mounts all read the same empty answer for every tmpfs.
///
/// The units are the fiddly part and are pinned here: `size=` is KiB
/// (`K(sbinfo->max_blocks)`), `mode=` is `%03ho` octal with no leading
/// zero, and the quota hard limits are the raw BYTE counts memparse
/// produced.
fn smoke_tmpfs_show_options_matches_shmem() -> TestResult {
    // A default mount prints nothing but the two always-on flags: its
    // limits ARE shmem_default_max_{blocks,inodes}() and its root is 01777.
    let plain = match TmpFs::from_options_with_total("", 4096, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("default tmpfs construction failed"),
    };
    if plain.show_options() != ",inode64,noswap" {
        return TestResult::Fail("default tmpfs printed non-default options");
    }
    let sized = match TmpFs::from_options_with_total(
        "size=1M,nr_inodes=16,mode=0755,uid=5,gid=6,inode32",
        4096,
        0,
        0,
    ) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("sized tmpfs construction failed"),
    };
    if sized.show_options() != ",size=1024k,nr_inodes=16,mode=755,uid=5,gid=6,inode32,noswap" {
        return TestResult::Fail("tmpfs show_options is not Linux-shaped");
    }
    // The size field tracks the LIVE limit, so a remount is visible.
    if sized.reconfigure("size=2M").is_err() {
        return TestResult::Fail("tmpfs remount failed");
    }
    if !sized.show_options().starts_with(",size=2048k,") {
        return TestResult::Fail("tmpfs show_options did not follow a remount");
    }
    let quota = match TmpFs::from_options_with_total(
        "usrquota,usrquota_block_hardlimit=8K,grpquota_inode_hardlimit=4",
        4096,
        0,
        0,
    ) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("quota tmpfs construction failed"),
    };
    if quota.show_options()
        != ",inode64,noswap,usrquota,usrquota_block_hardlimit=8192,grpquota_inode_hardlimit=4"
    {
        return TestResult::Fail("tmpfs quota options are not rendered like Linux");
    }
    // ramfs has no `show_options` at all in Linux — `ramfs_ops` leaves the
    // super_operations slot empty — so it must contribute nothing.
    let ramfs = match RamFs::from_options("mode=0700", 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("ramfs construction failed"),
    };
    if !FsInstance::show_options(&ramfs).is_empty() {
        return TestResult::Fail("ramfs invented mount options");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_show_options_matches_shmem);

/// Every tmpfs inode type holds extended attributes, with Linux's
/// `user.*` restriction.
///
/// `shmem_xattr_handlers` hangs off the SUPERBLOCK and
/// `shmem_{inode,dir,special,symlink}_inode_operations` all carry
/// `.listxattr`, so a directory, a symlink, a device node and a FIFO take
/// attributes just as a regular file does. NARF had them on regular files
/// only, so an SELinux label on a directory, or `setfattr` on `/tmp`
/// itself, had nowhere to go — the syscall layer silently diverted it into
/// a path-keyed side table that no `unlink` or `rename` ever cleaned up.
///
/// `fs/xattr.c::xattr_permission` is the other half: "In the `user.*`
/// namespace, only regular files and directories can have extended
/// attributes", and a write to one elsewhere is EPERM.
fn smoke_tmpfs_xattrs_on_every_inode_type() -> TestResult {
    let fs = match TmpFs::from_options_with_total("size=1M,nr_inodes=32", 4096, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let root = fs.root();

    // A directory takes `user.*`, and round-trips through DirOps.
    let dir = match poll_once(root.mkdir("labelled")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("tmpfs mkdir failed"),
    };
    if poll_once(dir.set_xattr("user.owner", b"narf", 0)).map(|r| r.is_ok()) != Some(true)
        || poll_once(dir.get_xattr("user.owner")) != Some(Ok(b"narf".to_vec()))
        || poll_once(dir.list_xattr()) != Some(Ok(b"user.owner\0".to_vec()))
    {
        return TestResult::Fail("tmpfs directory xattr round-trip failed");
    }
    if poll_once(dir.set_xattr("security.selinux", b"ctx", 0)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("tmpfs directory rejected a security.* xattr");
    }
    if poll_once(dir.remove_xattr("user.owner")).map(|r| r.is_ok()) != Some(true)
        || !matches!(
            poll_once(dir.remove_xattr("user.owner")),
            Some(Err(FsError::NotFound))
        )
    {
        return TestResult::Fail("tmpfs directory xattr removal is wrong");
    }

    // A symlink, a device node and a FIFO take the privileged namespaces
    // but refuse `user.*` with EPERM.
    let link = match poll_once(root.symlink("link", "/target")) {
        Some(Ok(link)) => link,
        _ => return TestResult::Fail("tmpfs symlink failed"),
    };
    let dev = match poll_once(root.mknod("dev", FileType::Special, 0x0103)) {
        Some(Ok(node)) => node,
        _ => return TestResult::Fail("tmpfs mknod failed"),
    };
    let fifo = match poll_once(root.mknod("pipe", FileType::Fifo, 0)) {
        Some(Ok(node)) => node,
        _ => return TestResult::Fail("tmpfs mkfifo failed"),
    };
    for node in [&link, &dev, &fifo] {
        if poll_once(node.set_xattr("security.selinux", b"ctx", 0)).map(|r| r.is_ok()) != Some(true)
            || poll_once(node.get_xattr("security.selinux")) != Some(Ok(b"ctx".to_vec()))
        {
            return TestResult::Fail("tmpfs non-regular inode lost a security.* xattr");
        }
        if !matches!(
            poll_once(node.set_xattr("user.nope", b"x", 0)),
            Some(Err(FsError::OperationNotPermitted))
        ) {
            return TestResult::Fail("user.* was accepted on a non-regular, non-directory inode");
        }
        // A remove carries MAY_WRITE too, so it is EPERM and not ENODATA.
        if !matches!(
            poll_once(node.remove_xattr("user.nope")),
            Some(Err(FsError::OperationNotPermitted))
        ) {
            return TestResult::Fail("removexattr of user.* did not report EPERM");
        }
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_xattrs_on_every_inode_type);

/// Extended attributes are charged against the `nr_inodes=` budget.
///
/// tmpfs does not count inodes: it budgets `free_ispace` BYTES, where an
/// inode costs `BOGO_INODE_SIZE` (1024) and an attribute costs
/// `simple_xattr_space(name, size)` = `40 + size + strlen(name)`
/// (`mm/shmem.c::shmem_xattr_handler_set`). So attributes make `statfs`
/// report fewer free inodes, a full mount refuses a new one with ENOSPC,
/// and evicting the inode returns `BOGO_INODE_SIZE + freed_ispace` in one
/// step (`shmem_free_inode`).
fn smoke_tmpfs_xattr_inode_space_budget() -> TestResult {
    // 8 inodes = 8192 bytes of inode space.
    let fs = match TmpFs::from_options_with_total("size=1M,nr_inodes=8", 4096, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let root = fs.root();
    let free = || match poll_once(fs.statfs()) {
        Some(Ok(stat)) => stat.files_free,
        _ => u64::MAX,
    };
    // Root inode only: 8192 - 1024 = 7168 bytes -> 7 free inodes.
    if free() != 7 {
        return TestResult::Fail("fresh tmpfs did not report free inodes as free_ispace/1024");
    }
    let file = match poll_once(root.create("charged")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs create failed"),
    };
    if free() != 6 {
        return TestResult::Fail("an inode did not cost BOGO_INODE_SIZE of inode space");
    }
    // simple_xattr_space("user.big", 2048) = 40 + 2048 + 8 = 2096 bytes.
    // Used inode space becomes 2048 + 2096 = 4144, so the free count is
    // (8192 - 4144) / 1024 = 3 — an xattr is not free, and it is not
    // rounded to a whole notional inode either.
    let big = alloc::vec![0xA5u8; 2048];
    if poll_once(file.set_xattr("user.big", &big, 0)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("tmpfs xattr set failed");
    }
    if free() != 3 {
        return TestResult::Fail("an xattr did not consume the inode-space budget");
    }
    // Replacing it with a small value gives the difference back:
    // 2048 + (40 + 4 + 8) = 2100 used, so (8192 - 2100) / 1024 = 5.
    if poll_once(file.set_xattr("user.big", b"tiny", 0)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("tmpfs xattr replace failed");
    }
    if free() != 5 {
        return TestResult::Fail("replacing an xattr did not release the old value's space");
    }
    // Fill the remaining space with attributes and confirm the mount then
    // refuses BOTH a new attribute and a new inode, with ENOSPC.
    let filler = alloc::vec![0u8; 1024];
    let mut set = 0;
    loop {
        let name = alloc::format!("user.f{}", set);
        match poll_once(file.set_xattr(&name, &filler, 0)) {
            Some(Ok(())) => set += 1,
            Some(Err(FsError::NoSpace)) => break,
            _ => return TestResult::Fail("unexpected error filling the inode-space budget"),
        }
        if set > 16 {
            return TestResult::Fail("xattrs never exhausted the inode-space budget");
        }
    }
    if !matches!(
        poll_once(root.create("denied")),
        Some(Err(FsError::NoSpace))
    ) {
        return TestResult::Fail("xattrs did not consume the budget a new inode needs");
    }
    // Evicting the inode returns its BOGO_INODE_SIZE *and* every byte its
    // attributes held, so the mount is usable again.
    if poll_once(root.unlink("charged")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("tmpfs unlink failed");
    }
    drop(file);
    // Only the root inode is left: (8192 - 1024) / 1024 = 7.
    if free() != 7 {
        return TestResult::Fail("evicting an inode did not return its xattr space");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_xattr_inode_space_budget);

/// `XATTR_CREATE` / `XATTR_REPLACE` follow `fs/xattr.c::simple_xattr_set`.
///
/// It tests the flag BITS, and tests CREATE first. Passing both is
/// therefore not EINVAL: it is EEXIST when the attribute is present and
/// ENODATA when it is not. Only a bit outside the pair is EINVAL, and that
/// check lives in `setxattr_copy` before the filesystem is reached.
fn smoke_tmpfs_xattr_flag_semantics() -> TestResult {
    const XATTR_CREATE: u32 = 1;
    const XATTR_REPLACE: u32 = 2;
    let fs = match TmpFs::from_options_with_total("size=1M,nr_inodes=8", 4096, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let file = match poll_once(fs.root().create("flags")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs create failed"),
    };
    // REPLACE before the attribute exists → ENODATA.
    if !matches!(
        poll_once(file.set_xattr("user.k", b"v", XATTR_REPLACE)),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("XATTR_REPLACE on a missing attribute is not ENODATA");
    }
    // Both flags, attribute missing → ENODATA (not EINVAL).
    if !matches!(
        poll_once(file.set_xattr("user.k", b"v", XATTR_CREATE | XATTR_REPLACE)),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("CREATE|REPLACE on a missing attribute is not ENODATA");
    }
    if poll_once(file.set_xattr("user.k", b"v", XATTR_CREATE)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("XATTR_CREATE of a new attribute failed");
    }
    // CREATE over an existing attribute → EEXIST, and so does both-flags.
    if !matches!(
        poll_once(file.set_xattr("user.k", b"v", XATTR_CREATE)),
        Some(Err(FsError::Busy))
    ) || !matches!(
        poll_once(file.set_xattr("user.k", b"v", XATTR_CREATE | XATTR_REPLACE)),
        Some(Err(FsError::Busy))
    ) {
        return TestResult::Fail("XATTR_CREATE over an existing attribute is not EEXIST");
    }
    // A bit outside the documented pair → EINVAL.
    if !matches!(
        poll_once(file.set_xattr("user.k", b"v", 4)),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("an unknown setxattr flag was accepted");
    }
    // A failed set must not leak the inode space it provisionally charged.
    let before = match poll_once(fs.statfs()) {
        Some(Ok(stat)) => stat.files_free,
        _ => return TestResult::Fail("tmpfs statfs failed"),
    };
    for _ in 0..8 {
        let _ = poll_once(file.set_xattr("user.k", b"vvvv", XATTR_CREATE));
    }
    let after = match poll_once(fs.statfs()) {
        Some(Ok(stat)) => stat.files_free,
        _ => return TestResult::Fail("tmpfs statfs failed"),
    };
    if before != after {
        return TestResult::Fail("a rejected setxattr leaked inode space");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_xattr_flag_semantics);

/// A write that fills the mount part-way returns a SHORT COUNT.
///
/// `shmem_file_write_iter` runs `mm/filemap.c::generic_perform_write`,
/// which breaks out of its per-folio loop when `write_begin` fails and
/// then does:
///
/// ```text
/// if (!written)
///         return status;
/// iocb->ki_pos += written;
/// return written;
/// ```
///
/// so ENOSPC surfaces only when NOTHING was written — the next write is
/// the one that reports it. NARF was all-or-nothing, which is visible from
/// userspace: `cp` onto a nearly-full `/tmp` left a zero-length file and
/// reported ENOSPC where Linux fills the filesystem and reports how much
/// it wrote.
///
/// The short write must also be a PREFIX. A page-at-a-time fallback that
/// charged pages out of order would leave a file with a hole in the middle
/// and a length that claims the whole range.
fn smoke_tmpfs_short_write_at_enospc() -> TestResult {
    // 4 blocks total; the root inode costs none of them.
    let fs = match TmpFs::from_options_with_total("size=16K,nr_inodes=8", 4096, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let root = fs.root();
    let file = match poll_once(root.create("filler")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs create failed"),
    };
    // Ask for 6 pages when only 4 exist: 4 land, and the call reports it.
    let payload = alloc::vec![0x5Au8; 6 * 4096];
    match poll_once(file.write(0, &payload)) {
        Some(Ok(n)) if n == 4 * 4096 => {}
        Some(Ok(n)) => {
            let _ = n;
            return TestResult::Fail("write past the mount limit reported the wrong count");
        }
        _ => return TestResult::Fail("write past the mount limit failed instead of short-writing"),
    }
    // What landed is the prefix, and the file's length matches it exactly.
    if file.stat().size != 4 * 4096 || file.stat().blocks != 4 * (4096 / 512) {
        return TestResult::Fail("short write left the wrong length or block count");
    }
    let mut back = alloc::vec![0u8; 4 * 4096];
    if poll_once(file.read(0, &mut back)) != Some(Ok(4 * 4096)) || back.iter().any(|&b| b != 0x5A) {
        return TestResult::Fail("short write did not land as a contiguous prefix");
    }
    // NOW the filesystem is full, so the next write is the one that errors.
    if !matches!(
        poll_once(file.write(4 * 4096, &payload)),
        Some(Err(FsError::NoSpace))
    ) {
        return TestResult::Fail("a write with no room at all did not report ENOSPC");
    }
    // Rewriting bytes that are already resident needs no new block and must
    // still complete in full.
    if poll_once(file.write(0, &[1u8; 4096])) != Some(Ok(4096)) {
        return TestResult::Fail("overwriting a resident page failed on a full mount");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_short_write_at_enospc);

/// The same short-write rule when a per-owner QUOTA is what runs out.
///
/// `shmem_inode_acct_blocks` returns -EDQUOT from `dquot_alloc_block_nodirty`
/// through the same `write_begin` failure path, so the loop breaks
/// identically and the partial count is returned. A quota that stopped a
/// write dead would make `cp` behave differently on a quota'd tmpfs than on
/// a full one, for no reason Linux has.
fn smoke_tmpfs_short_write_at_edquot() -> TestResult {
    const U: u32 = 7007;
    let fs = match TmpFs::from_options_with_total(
        "usrquota,size=1M,usrquota_block_hardlimit=8K",
        4096,
        0,
        0,
    ) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("quota tmpfs construction failed"),
    };
    let file = match poll_once(fs.root().create("quota'd")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs create failed"),
    };
    if poll_once(file.set_owners(U, U)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("chown to the limited uid failed");
    }
    // The owner may hold 8 KiB = two pages; ask for five.
    let payload = alloc::vec![0xC3u8; 5 * 4096];
    match poll_once(file.write(0, &payload)) {
        Some(Ok(n)) if n == 2 * 4096 => {}
        _ => return TestResult::Fail("hitting a block quota did not produce a short write"),
    }
    if !matches!(
        poll_once(file.write(2 * 4096, &payload)),
        Some(Err(FsError::QuotaExceeded))
    ) {
        return TestResult::Fail("a write with no quota left did not report EDQUOT");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_short_write_at_edquot);

/// `st_nlink` follows the namespace, for files AND directories.
///
/// Every tmpfs inode reported 1. Two things break on that. A hard link is
/// invisible: `ls -l` shows 1, `find -links +1` finds nothing, and a
/// backup tool that dedups by link count writes the data twice. And
/// `find`'s leaf optimisation — "a directory whose `st_nlink` is exactly 2
/// has no subdirectories, so its remaining children need not be stat'd" —
/// cannot run at all, because Linux's count for a directory is
/// `2 + subdirectories` (itself, its `.`, and one `..` per child) and a
/// flat 1 is below the floor.
///
/// An `O_TMPFILE` inode is the interesting case in the other direction:
/// `shmem_tmpfile` reaches `d_tmpfile`, which decrements the link count to
/// **0**, and `linkat(AT_EMPTY_PATH)` is what raises it. A caller uses that
/// zero to tell an unlinked temporary from a named file.
fn smoke_tmpfs_link_counts_follow_the_namespace() -> TestResult {
    let fs = match TmpFs::from_options_with_total("size=1M,nr_inodes=64", 4096, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let root = fs.root();
    // A fresh directory: itself + its own `.`.
    if root.inode_attrs().nlink != 2 {
        return TestResult::Fail("an empty tmpfs directory does not report 2 links");
    }
    let file = match poll_once(root.create("one")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs create failed"),
    };
    if file.inode_attrs().nlink != 1 {
        return TestResult::Fail("a newly created file does not report 1 link");
    }
    if poll_once(root.link("one", "two")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("tmpfs hard link failed");
    }
    if file.inode_attrs().nlink != 2 {
        return TestResult::Fail("a hard link did not raise the link count");
    }
    if poll_once(root.unlink("two")).map(|r| r.is_ok()) != Some(true)
        || file.inode_attrs().nlink != 1
    {
        return TestResult::Fail("unlinking a name did not lower the link count");
    }
    // Directories: each child directory's `..` is another link to its parent.
    let a = match poll_once(root.mkdir("a")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("tmpfs mkdir failed"),
    };
    let b = match poll_once(root.mkdir("b")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("tmpfs mkdir failed"),
    };
    if root.inode_attrs().nlink != 4 || a.inode_attrs().nlink != 2 {
        return TestResult::Fail("mkdir did not raise the parent's link count");
    }
    if poll_once(a.mkdir("x")).map(|r| r.is_ok()) != Some(true) || a.inode_attrs().nlink != 3 {
        return TestResult::Fail("a nested mkdir did not raise its parent's link count");
    }
    // Moving a directory carries its `..` link to the new parent.
    if poll_once(a.rename_to("x", &*b, "y", 0)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("cross-directory rename failed");
    }
    if a.inode_attrs().nlink != 2 || b.inode_attrs().nlink != 3 {
        return TestResult::Fail("renaming a directory did not move the parent link counts");
    }
    if poll_once(b.rmdir("y")).map(|r| r.is_ok()) != Some(true) || b.inode_attrs().nlink != 2 {
        return TestResult::Fail("rmdir did not lower the parent's link count");
    }
    // A rename that REPLACES a file takes the replaced inode's last name.
    let victim = match poll_once(root.create("victim")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs create failed"),
    };
    if poll_once(root.rename("one", "victim")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("replacing rename failed");
    }
    if victim.inode_attrs().nlink != 0 {
        return TestResult::Fail("a replaced inode kept its link count");
    }
    // O_TMPFILE: nameless until linkat gives it one.
    let tmp = match poll_once(root.tmpfile(0o600)) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs tmpfile failed"),
    };
    if tmp.inode_attrs().nlink != 0 || !tmp.inode_attrs().tracked {
        return TestResult::Fail("an O_TMPFILE inode does not report zero links");
    }
    if poll_once(root.link_node("named", tmp.clone())).map(|r| r.is_ok()) != Some(true)
        || tmp.inode_attrs().nlink != 1
    {
        return TestResult::Fail("linkat did not give the O_TMPFILE inode its first link");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/tmpfs",
    smoke_tmpfs_link_counts_follow_the_namespace
);

/// atime, mtime and ctime are three separate stamps, with relatime.
///
/// NARF reported mtime for all three, so `chmod` looked like a rewrite to
/// anything comparing ctime, and atime never moved at all. Linux moves
/// mtime+ctime together on a data change (`file_update_time`), ctime alone
/// on a metadata change (`setattr_copy`), and atime on read under the
/// `relatime` rule in `fs/inode.c::relatime_need_update`:
///
/// ```text
/// if (inode_get_atime <= inode_get_mtime) return 1;
/// if (inode_get_atime <= inode_get_ctime) return 1;
/// if ((long)(now.tv_sec - atime.tv_sec) >= 24*60*60) return 1;
/// return 0;
/// ```
fn smoke_tmpfs_timestamps_are_three_distinct_stamps() -> TestResult {
    const SECOND: u64 = 1_000_000_000;
    let fs = match TmpFs::from_options_with_total("size=1M,nr_inodes=16", 4096, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let file = match poll_once(fs.root().create("stamped")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs create failed"),
    };
    // ctime from creation, to compare the explicit set against.
    let created_ctime = file.inode_attrs().ctime_ns;
    // Plant known atime/mtime. `notify_change` stamps ctime as well — with
    // NOW, not with either planted value.
    if file.set_times(Some(SECOND), Some(2 * SECOND)).is_err() {
        return TestResult::Fail("set_times failed");
    }
    let attrs = file.inode_attrs();
    if attrs.atime_ns != SECOND || narf_time::cycles_to_ns(file.stat().mtime_cycles) != 2 * SECOND {
        return TestResult::Fail("set_times did not plant atime/mtime");
    }
    // Asserted RELATIVE to the inode's own creation stamp, never against an
    // absolute instant. `ctime_ns > 2 * SECOND` reads as "ctime is a real
    // wall-clock now", but it is only true once the wall clock has passed
    // two seconds — which on a machine with no RTC depends on how far into
    // the boot this case happens to run. It passed for several runs and
    // then failed, having moved earlier in the schedule.
    //
    // Strict `>`: an unstamped ctime keeps exactly the creation value, so
    // `>=` would hold whether or not `set_times` stamped anything. The
    // clock is TSC-derived with nanosecond resolution and the two reads are
    // separated by a lock, a store and several calls, so it always moves.
    if attrs.ctime_ns <= created_ctime {
        return TestResult::Fail("an explicit utimensat did not stamp ctime");
    }
    if attrs.ctime_ns == SECOND || attrs.ctime_ns == 2 * SECOND {
        return TestResult::Fail("an explicit utimensat stamped ctime with the PASSED time");
    }
    // chmod moves ctime and leaves mtime alone. Making a file executable
    // must not make `make` think it was rebuilt.
    if poll_once(file.set_perms(0o700)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("chmod failed");
    }
    if narf_time::cycles_to_ns(file.stat().mtime_cycles) != 2 * SECOND {
        return TestResult::Fail("chmod moved mtime");
    }
    if file.inode_attrs().ctime_ns < attrs.ctime_ns {
        return TestResult::Fail("chmod did not stamp ctime");
    }
    // relatime: atime is refreshed only when it is no newer than the last
    // change. atime(1s) <= mtime(2s), so this read must move it.
    let mut buf = [0u8; 1];
    if poll_once(file.read(0, &mut buf)).is_none() {
        return TestResult::Fail("read failed");
    }
    let after_read = file.inode_attrs().atime_ns;
    if after_read == SECOND {
        return TestResult::Fail("relatime did not refresh a stale atime");
    }
    // Now plant an atime far AHEAD of both other stamps: relatime must
    // leave it alone, which is the whole point of the policy — a read loop
    // over a warm file does not keep dirtying the inode.
    let far = after_read.saturating_add(3600 * SECOND);
    if file.set_times(Some(far), Some(2 * SECOND)).is_err() {
        return TestResult::Fail("set_times failed");
    }
    if poll_once(file.read(0, &mut buf)).is_none() {
        return TestResult::Fail("read failed");
    }
    if file.inode_attrs().atime_ns != far {
        return TestResult::Fail("relatime refreshed an atime that was already current");
    }
    // A write moves mtime AND ctime together.
    let before_write = file.inode_attrs().ctime_ns;
    if poll_once(file.write(0, b"x")).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("write failed");
    }
    if narf_time::cycles_to_ns(file.stat().mtime_cycles) == 2 * SECOND
        || file.inode_attrs().ctime_ns < before_write
    {
        return TestResult::Fail("a write did not move mtime and ctime together");
    }
    // A directory has real timestamps too, and a namespace change moves
    // them — `ls -l /tmp` showed the epoch for every directory before.
    let dir = fs.root();
    if dir.dir_mtime_ns() == 0 {
        return TestResult::Fail("a tmpfs directory has no mtime");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/tmpfs",
    smoke_tmpfs_timestamps_are_three_distinct_stamps
);

/// Each mount has its own `st_dev`, and every inode on it reports that one.
///
/// `st_dev` was 0 everywhere, so nothing could tell two filesystems apart:
/// `find -xdev` never pruned, `du -x` never stopped, and systemd's
/// mount-point probe — which compares a directory's `st_dev` to its
/// parent's — saw one flat filesystem. Linux gives every superblock without
/// a block device a distinct anonymous number (`fs/super.c::get_anon_bdev`).
fn smoke_tmpfs_distinct_device_numbers() -> TestResult {
    let first = match TmpFs::from_options_with_total("size=1M", 4096, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let second = match TmpFs::from_options_with_total("size=1M", 4096, 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("tmpfs construction failed"),
    };
    let first_dev = first.root().inode_attrs().dev;
    let second_dev = second.root().inode_attrs().dev;
    if first_dev == 0 || second_dev == 0 {
        return TestResult::Fail("a tmpfs mount has no device number");
    }
    if first_dev == second_dev {
        return TestResult::Fail("two tmpfs mounts share a device number");
    }
    // Every inode on a mount reports that mount's device — files,
    // directories, symlinks and special nodes alike.
    let root = first.root();
    let file = match poll_once(root.create("f")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("tmpfs create failed"),
    };
    let link = match poll_once(root.symlink("l", "/f")) {
        Some(Ok(link)) => link,
        _ => return TestResult::Fail("tmpfs symlink failed"),
    };
    let node = match poll_once(root.mknod("d", FileType::Special, 0x0103)) {
        Some(Ok(node)) => node,
        _ => return TestResult::Fail("tmpfs mknod failed"),
    };
    let sub = match poll_once(root.mkdir("s")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("tmpfs mkdir failed"),
    };
    if file.inode_attrs().dev != first_dev
        || link.inode_attrs().dev != first_dev
        || node.inode_attrs().dev != first_dev
        || sub.inode_attrs().dev != first_dev
    {
        return TestResult::Fail("an inode reported a device other than its mount's");
    }
    // ramfs is a separate filesystem and gets its own number.
    let ramfs = match RamFs::from_options("", 0, 0) {
        Ok(fs) => fs,
        Err(_) => return TestResult::Fail("ramfs construction failed"),
    };
    if ramfs.root().inode_attrs().dev == first_dev {
        return TestResult::Fail("a ramfs mount shares tmpfs's device number");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/tmpfs", smoke_tmpfs_distinct_device_numbers);

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
// `enumerate_async(cursor, bounded_batch)` and serving entries positionally,
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
