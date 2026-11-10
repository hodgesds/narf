//! Tree-log replay and the fsync log writer.

use super::*;
use alloc::string::String;
use narf_filesystem::{DirOps, FileType, FsInstance};

/// A filesystem a real Linux kernel fsynced into and was then killed on
/// (`narf-btrfs-host --emit-linux-log-fixture`, which documents the script):
/// one tree log holding new and partly rewritten extents with checksums, a
/// truncation, an inline file grown out of its item, new directories, a
/// directory fsync after unlink + rename + create, a hard link, an xattr
/// removal and a write into preallocated space.
const FIXTURE_LINUXLOG_SPARSE: &[u8] = include_bytes!("../../testdata/fixture-linuxlog.img.sparse");

/// What Linux's own replay of that log yields (the same tool prints it):
/// `(path, kind, perms, nlink, size, FNV-1a of the content)`.
const LINUX_REPLAYED: &[(&str, char, u16, u32, u64, u64)] = &[
    ("d", 'd', 0o755, 1, 0, 0xcbf29ce484222325),
    ("d/created", 'f', 0o644, 1, 0, 0xcbf29ce484222325),
    ("d/keep", 'f', 0o644, 1, 12000, 0x9b435cdf7253df4c),
    ("d/renamed-new", 'f', 0o644, 1, 5000, 0xbbbc82b238564a80),
    ("d/sub", 'd', 0o755, 1, 0, 0xcbf29ce484222325),
    ("linked", 'f', 0o644, 2, 2000, 0x8e512b65578fca8d),
    ("linked2", 'f', 0o644, 2, 2000, 0x8e512b65578fca8d),
    ("nd", 'd', 0o755, 1, 0, 0xcbf29ce484222325),
    ("nd/deeper", 'd', 0o755, 1, 0, 0xcbf29ce484222325),
    ("nd/deeper/f", 'f', 0o644, 1, 4000, 0x1a15e9fac14e3489),
    ("new", 'f', 0o644, 1, 20000, 0x0d84165ecebe16fd),
    ("over", 'f', 0o644, 1, 40000, 0xfde5a32cdfd04aea),
    ("pre", 'f', 0o644, 1, 262144, 0x5e017e6cc0bf00f6),
    ("small", 'f', 0o644, 1, 9100, 0x6ddbf4a24d626c4f),
    ("tiny", 'f', 0o644, 1, 300, 0xc75c259334b46750),
    ("trunc", 'f', 0o644, 1, 20001, 0x2776e03b986dde58),
    ("xa", 'f', 0o644, 1, 1500, 0x4bcdc77d990164c7),
];

const FNV_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

fn fnv(data: &[u8]) -> u64 {
    let mut h = FNV_BASIS;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

type Entry = (String, char, u16, u32, u64, u64);

/// Every entry under `root`, sorted by path, in [`LINUX_REPLAYED`]'s shape.
fn walk(root: Arc<dyn DirOps>) -> Result<Vec<Entry>, &'static str> {
    let mut out: Vec<Entry> = Vec::new();
    let mut stack: Vec<(String, Arc<dyn DirOps>)> = alloc::vec![(String::new(), root)];
    while let Some((path, dir)) = stack.pop() {
        let entries = match poll_once(dir.enumerate_async(0, usize::MAX)) {
            Some(Ok(entries)) => entries,
            _ => return Err("readdir failed"),
        };
        for (name, ft) in entries {
            let p = if path.is_empty() {
                name.clone()
            } else {
                alloc::format!("{path}/{name}")
            };
            if ft == FileType::Dir {
                let Some(Ok(d)) = poll_once(dir.lookup_dir_async(&name)) else {
                    return Err("directory lookup failed");
                };
                out.push((p.clone(), 'd', d.dir_mode() & 0o7777, 1, 0, FNV_BASIS));
                stack.push((p, d));
                continue;
            }
            let Some(Ok(f)) = poll_once(dir.lookup_async(&name)) else {
                return Err("file lookup failed");
            };
            let Some(Ok(sx)) = poll_once(f.statx_async(0, 0x7ff)) else {
                return Err("statx failed");
            };
            let Some(Ok(st)) = poll_once(f.stat_async()) else {
                return Err("stat failed");
            };
            let mut data = alloc::vec![0u8; st.size as usize];
            let mut done = 0usize;
            while done < data.len() {
                match poll_once(f.read(done as u64, &mut data[done..])) {
                    Some(Ok(0)) => break,
                    Some(Ok(n)) => done += n,
                    _ => return Err("read failed (checksum?)"),
                }
            }
            if done != data.len() {
                return Err("short read");
            }
            out.push((
                p,
                if ft == FileType::Symlink { 'l' } else { 'f' },
                st.mode.perms & 0o7777,
                sx.nlink,
                st.size,
                fnv(&data),
            ));
        }
    }
    out.sort();
    Ok(out)
}

/// Whether the tree under `root` is exactly what Linux's replay left.
fn is_as_linux_replayed(root: Arc<dyn DirOps>) -> Result<(), &'static str> {
    let got = walk(root)?;
    if got.len() != LINUX_REPLAYED.len() {
        return Err("entry count differs from Linux's replay");
    }
    for (have, want) in got.iter().zip(LINUX_REPLAYED) {
        if have.0 != want.0 {
            return Err("an entry's name differs from Linux's replay");
        }
        if (have.1, have.2, have.3) != (want.1, want.2, want.3) {
            return Err("an entry's type, mode or link count differs from Linux's replay");
        }
        if (have.4, have.5) != (want.4, want.5) {
            return Err("a file's size or content differs from Linux's replay");
        }
    }
    Ok(())
}

fn log_root_on(dev: &WritableSparseDevice) -> u64 {
    format::le64(
        &read_super_at(dev, format::SUPERBLOCK_OFFSET),
        format::OFF_LOG_ROOT,
    )
    .unwrap_or(u64::MAX)
}

/// Mounting a filesystem Linux fsynced into and crashed on replays Linux's
/// log into exactly the tree Linux's own replay produces — names, link
/// counts, sizes and every byte, read back through data checksums — clears
/// the log, and leaves a filesystem that takes writes and remounts the same.
fn smoke_btrfs_replays_a_linux_written_log() -> TestResult {
    let device = writable_sparse(FIXTURE_LINUXLOG_SPARSE);
    if log_root_on(&device) == 0 {
        return TestResult::Fail("fixture carries no log");
    }
    let vol = match mount_writable(device.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("mount (replay) failed"),
    };
    if log_root_on(&device) != 0 || vol.superblock().log_root != 0 {
        return TestResult::Fail("log_root not cleared after replay");
    }
    if let Err(why) = is_as_linux_replayed(vol.root()) {
        return TestResult::Fail(why);
    }
    // Xattr deletion is replayed: the fsync after `removexattr` dropped one
    // attribute and added another.
    let Some(Ok(xa)) = poll_once(vol.root().lookup_async("xa")) else {
        return TestResult::Fail("xa missing");
    };
    if !matches!(poll_once(xa.get_xattr("user.keep")), Some(Ok(v)) if v.len() == 20)
        || !matches!(poll_once(xa.get_xattr("user.new")), Some(Ok(v)) if v.len() == 10)
        || matches!(poll_once(xa.get_xattr("user.drop")), Some(Ok(_)))
    {
        return TestResult::Fail("xattrs not as the log left them");
    }
    // The replayed filesystem is an ordinary one.
    let Some(Ok(f)) = poll_once(vol.root().create("after-replay")) else {
        return TestResult::Fail("create after replay failed");
    };
    if !matches!(poll_once(f.write(0, &[0x5a; 9000])), Some(Ok(9000)))
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
        || !matches!(poll_once(vol.root().unlink("after-replay")), Some(Ok(())))
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return TestResult::Fail("write after replay failed");
    }
    drop(f);
    drop(xa);
    drop(vol);
    let again = match mount_writable(device) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("remount after replay failed"),
    };
    match is_as_linux_replayed(again.root()) {
        Ok(()) => TestResult::Pass,
        Err(_) => TestResult::Fail("replayed state did not persist"),
    }
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_replays_a_linux_written_log);

/// A device that fails every write after the first `left`: what the
/// filesystem below it holds is what a power cut at that write leaves.
#[derive(Debug)]
struct CutDevice {
    inner: Arc<WritableSparseDevice>,
    left: core::sync::atomic::AtomicI64,
    writes: core::sync::atomic::AtomicU64,
}

impl narf_block::BlockDeviceSync for CutDevice {
    fn lba_size(&self) -> u32 {
        self.inner.lba_size()
    }
    fn capacity(&self) -> u64 {
        self.inner.capacity()
    }
    fn read(&self, lba: u64, n: u16, out: &mut [u8]) -> Result<(), narf_block::BlockIoError> {
        self.inner.read(lba, n, out)
    }
    fn write(&self, lba: u64, n: u16, data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        use core::sync::atomic::Ordering::Relaxed;
        self.writes.fetch_add(1, Relaxed);
        if self.left.fetch_sub(1, Relaxed) <= 0 {
            return Err(narf_block::BlockIoError::DriverError);
        }
        self.inner.write(lba, n, data)
    }
}

/// Mount `inner` through a [`CutDevice`] allowing `left` writes; returns how
/// many writes the mount attempted.
fn mount_cut(inner: &Arc<WritableSparseDevice>, left: i64) -> u64 {
    let cut = Arc::new(CutDevice {
        inner: inner.clone(),
        left: core::sync::atomic::AtomicI64::new(left),
        writes: core::sync::atomic::AtomicU64::new(0),
    });
    let dev = narf_block::SyncBlock::new(cut.clone() as Arc<dyn narf_block::BlockDeviceSync>);
    // The mount may fail (it lost its device part-way) or succeed (the cut
    // came after the replay's superblock); either way its views are gone
    // before the device is looked at again.
    let mounted = poll_once(BtrfsVolume::mount(dev, DomainId::DRIVER_0));
    drop(mounted);
    cut.writes.load(core::sync::atomic::Ordering::Relaxed)
}

/// Replay is one transaction: a crash at any write of it leaves either the
/// log still in place (and the next mount replays it in full) or the
/// replayed tree, never something in between. Cuts the device at every
/// write of the replay (a spread of them when there are many) and requires
/// the mount after each to end at Linux's result.
fn smoke_btrfs_log_replay_survives_a_crash_at_any_write() -> TestResult {
    let total = mount_cut(&writable_sparse(FIXTURE_LINUXLOG_SPARSE), i64::MAX);
    if total < 8 {
        return TestResult::Fail("replay wrote implausibly little");
    }
    let step = (total / 40).max(1);
    let mut cut = 0u64;
    let mut log_kept = 0u32;
    while cut <= total {
        let device = writable_sparse(FIXTURE_LINUXLOG_SPARSE);
        mount_cut(&device, cut as i64);
        if log_root_on(&device) != 0 {
            log_kept += 1;
        }
        let vol = match mount_writable(device.clone()) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("mount after an interrupted replay failed"),
        };
        if log_root_on(&device) != 0 {
            return TestResult::Fail("log_root set after the second replay");
        }
        if is_as_linux_replayed(vol.root()).is_err() {
            return TestResult::Fail("an interrupted replay did not end at Linux's result");
        }
        cut += step;
    }
    if log_kept == 0 {
        return TestResult::Fail("no cut left the log in place: the sweep proved nothing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_log_replay_survives_a_crash_at_any_write
);

// ── The fsync log writer ───────────────────────────────────────────

type TestVol = Arc<BtrfsVolume<narf_block::SyncBlock>>;

/// The device as a power cut right now would leave it: a copy nothing the
/// mounted volume does afterwards (its unmount commit included) can reach.
fn crash_copy(dev: &Arc<WritableSparseDevice>) -> Arc<WritableSparseDevice> {
    Arc::new(WritableSparseDevice {
        runs: dev.runs.clone(),
        total: dev.total,
        lba_size: dev.lba_size,
        reads: core::sync::atomic::AtomicUsize::new(0),
        overlay: narf_lib::sync::IrqSafeSpinLock::new(dev.overlay.lock().clone()),
    })
}

/// `len` bytes that differ for every `seed` and position.
fn pattern(seed: u64, len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| {
            let x =
                (i ^ seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)).wrapping_mul(0xD6E8_FEB8_6659_FD93);
            (x >> 29) as u8
        })
        .collect()
}

/// The whole content of the file `name` in `dir`, or `None` if it is not
/// there or cannot be read back (a checksum mismatch is a read error).
fn content(dir: &Arc<dyn DirOps>, name: &str) -> Option<Vec<u8>> {
    let f = poll_once(dir.lookup_async(name))?.ok()?;
    let size = poll_once(f.stat_async())?.ok()?.size as usize;
    let mut data = alloc::vec![0u8; size];
    let mut done = 0usize;
    while done < size {
        match poll_once(f.read(done as u64, &mut data[done..]))? {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(_) => return None,
        }
    }
    (done == size).then_some(data)
}

fn put(dir: &Arc<dyn DirOps>, name: &str, offset: u64, data: &[u8]) -> bool {
    let f = match poll_once(dir.lookup_async(name)) {
        Some(Ok(f)) => f,
        _ => match poll_once(dir.create(name)) {
            Some(Ok(f)) => f,
            _ => return false,
        },
    };
    matches!(poll_once(f.write(offset, data)), Some(Ok(n)) if n == data.len())
}

fn fsync_file(dir: &Arc<dyn DirOps>, name: &str, data_only: bool) -> bool {
    match poll_once(dir.lookup_async(name)) {
        Some(Ok(f)) => matches!(poll_once(f.fsync(data_only)), Some(Ok(()))),
        _ => false,
    }
}

/// A fresh writable filesystem and its device.
fn log_fixture() -> Option<(Arc<WritableSparseDevice>, TestVol)> {
    let device = writable_sparse(FIXTURE_BGT_SPARSE);
    let vol = mount_writable(device.clone()).ok()?;
    Some((device, vol))
}

/// Mount what a crash at this instant leaves on `device` — replaying the
/// log if it carries one — and return the copy and the mount.
fn after_crash(device: &Arc<WritableSparseDevice>) -> Option<(Arc<WritableSparseDevice>, TestVol)> {
    let copy = crash_copy(device);
    let vol = mount_writable(copy.clone()).ok()?;
    (log_root_on(&copy) == 0 && vol.superblock().log_root == 0).then_some((copy, vol))
}

/// An fsync writes the inode to the tree log and one superblock; it does
/// not commit the transaction. After a crash, replay brings back exactly
/// what each fsync covered: a new file by name with its data, an
/// overwrite, an append, a truncation, a file in directories that did not
/// exist at the last commit — and nothing written after the fsync.
fn smoke_btrfs_fsync_goes_through_the_log() -> TestResult {
    let Some((device, vol)) = log_fixture() else {
        return TestResult::Fail("fixture failed to mount");
    };
    let root = vol.root();
    let base = pattern(1, 200_000);
    let long = pattern(2, 300_000);
    if !put(&root, "over", 0, &base)
        || !put(&root, "trunc", 0, &long)
        || !put(&root, "app", 0, &base[..5000])
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return TestResult::Fail("setup failed");
    }
    let before = vol.commit_stats().snapshot();
    let (logged_before, _, committed_before) = crate::stats::fsync_counts();

    // A new file.
    let fresh = pattern(3, 70_000);
    if !put(&root, "new", 0, &fresh) || !fsync_file(&root, "new", false) {
        return TestResult::Fail("fsync of a new file failed");
    }
    if log_root_on(&device) == 0 {
        return TestResult::Fail("fsync left no log on the device");
    }
    // An overwrite in the middle, an append, a truncation.
    let patch = pattern(4, 8192);
    let tail = pattern(5, 3000);
    let mut over = base.clone();
    over[4096..4096 + 8192].copy_from_slice(&patch);
    let mut app = base[..5000].to_vec();
    app.extend_from_slice(&tail);
    let Some(Ok(trunc)) = poll_once(root.lookup_async("trunc")) else {
        return TestResult::Fail("trunc missing");
    };
    if !put(&root, "over", 4096, &patch)
        || !fsync_file(&root, "over", false)
        || !put(&root, "app", 5000, &tail)
        || !fsync_file(&root, "app", true)
        || !matches!(poll_once(trunc.truncate(100_001)), Some(Ok(())))
        || !matches!(poll_once(trunc.fsync(false)), Some(Ok(())))
    {
        return TestResult::Fail("overwrite/append/truncate + fsync failed");
    }
    // A file under two directories created in this transaction.
    let deep = pattern(6, 9000);
    let made = poll_once(root.mkdir("d1"))
        .and_then(|d| d.ok())
        .and_then(|d1| {
            let d2 = poll_once(d1.mkdir("d2"))?.ok()?;
            (put(&d2, "deep", 0, &deep) && fsync_file(&d2, "deep", false)).then_some(())
        });
    if made.is_none() {
        return TestResult::Fail("fsync under new directories failed");
    }
    // Written after its fsync, and never synced: must not come back.
    if !put(&root, "new", 0, &pattern(7, 20_000)) || !put(&root, "unsynced", 0, &pattern(8, 5000)) {
        return TestResult::Fail("unsynced writes failed");
    }

    let cost = vol.commit_stats().snapshot().since(&before);
    let (logged, _, committed) = crate::stats::fsync_counts();
    if logged - logged_before != 5 || committed != committed_before {
        return TestResult::Fail("an fsync did not go through the log");
    }
    if cost.commits != 0 {
        return TestResult::Fail("an fsync committed the transaction");
    }
    if cost.super_writes != 5 {
        return TestResult::Fail("five fsyncs did not cost exactly five superblock writes");
    }

    let Some((_copy, crashed)) = after_crash(&device) else {
        return TestResult::Fail("mount after the crash failed or left the log");
    };
    let r = crashed.root();
    if content(&r, "new").as_deref() != Some(&fresh[..]) {
        return TestResult::Fail("fsynced new file not back as fsynced");
    }
    if content(&r, "over").as_deref() != Some(&over[..]) {
        return TestResult::Fail("fsynced overwrite not back");
    }
    if content(&r, "app").as_deref() != Some(&app[..]) {
        return TestResult::Fail("fdatasynced append not back");
    }
    if content(&r, "trunc").as_deref() != Some(&long[..100_001]) {
        return TestResult::Fail("fsynced truncation not back");
    }
    let found = poll_once(r.lookup_dir_async("d1"))
        .and_then(|d| d.ok())
        .and_then(|d1| poll_once(d1.lookup_dir_async("d2"))?.ok())
        .and_then(|d2| content(&d2, "deep"));
    if found.as_deref() != Some(&deep[..]) {
        return TestResult::Fail("file under new directories not back");
    }
    if poll_once(r.lookup_async("unsynced")).is_some_and(|f| f.is_ok()) {
        return TestResult::Fail("a file nobody fsynced came back");
    }
    // The replayed filesystem commits and remounts like any other.
    if !put(&r, "later", 0, &tail) || !matches!(poll_once(crashed.sync_to_disk()), Some(Ok(()))) {
        return TestResult::Fail("write after replay failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_fsync_goes_through_the_log);

/// The desktop pattern: write a temporary file, fsync it, rename it over the
/// real one — sixty times. It costs sixty log syncs (one superblock write
/// each) and no transaction commit, where it used to cost sixty commits; and
/// after a crash at the end every real file is whole, old or new.
fn smoke_btrfs_fsync_burst_does_not_commit_per_fsync() -> TestResult {
    let Some((device, vol)) = log_fixture() else {
        return TestResult::Fail("fixture failed to mount");
    };
    let root = vol.root();
    const FILES: usize = 60;
    for i in 0..FILES {
        if !put(
            &root,
            &alloc::format!("cfg{i}"),
            0,
            &pattern(i as u64, 2000 + i * 37),
        ) {
            return TestResult::Fail("setup write failed");
        }
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return TestResult::Fail("setup sync failed");
    }
    let before = vol.commit_stats().snapshot();
    let (logged_before, _, committed_before) = crate::stats::fsync_counts();
    for i in 0..FILES {
        let tmp = alloc::format!("cfg{i}.tmp");
        if !put(&root, &tmp, 0, &pattern(1000 + i as u64, 3000 + i * 53))
            || !fsync_file(&root, &tmp, false)
            || !matches!(
                poll_once(root.rename(&tmp, &alloc::format!("cfg{i}"))),
                Some(Ok(()))
            )
        {
            return TestResult::Fail("temp + fsync + rename failed");
        }
    }
    let cost = vol.commit_stats().snapshot().since(&before);
    let (logged, _, committed) = crate::stats::fsync_counts();
    let (logged, committed) = (logged - logged_before, committed - committed_before);
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "btrfs: burst of {FILES} temp+fsync+rename: {logged} fsyncs logged, {committed} committed; {} superblock writes, {} transaction commits (one commit and superblock per fsync before the tree log)",
            cost.super_writes, cost.commits
        );
    }
    if logged + committed != FILES as u64 {
        return TestResult::Fail("fsync count does not add up");
    }
    // Space pressure may make the odd fsync commit; the burst as a whole
    // must not.
    if committed > 3 || cost.commits > 3 {
        return TestResult::Fail("the burst committed the transaction per fsync");
    }
    if cost.super_writes > FILES as u64 + 3 {
        return TestResult::Fail("the burst wrote more superblocks than fsyncs");
    }

    let Some((_copy, crashed)) = after_crash(&device) else {
        return TestResult::Fail("mount after the crash failed or left the log");
    };
    let r = crashed.root();
    for i in 0..FILES {
        let old = pattern(i as u64, 2000 + i * 37);
        let new = pattern(1000 + i as u64, 3000 + i * 53);
        match content(&r, &alloc::format!("cfg{i}")) {
            Some(data) if data == old || data == new => {}
            _ => return TestResult::Fail("a replaced file is neither old nor new after the crash"),
        }
        // The fsynced temporary either made it to its final name or is
        // still there under its own, whole.
        let tmp = content(&r, &alloc::format!("cfg{i}.tmp"));
        let renamed = content(&r, &alloc::format!("cfg{i}"));
        if tmp.as_deref() != Some(&new[..]) && renamed.as_deref() != Some(&new[..]) {
            return TestResult::Fail("an fsynced temporary file was lost");
        }
    }
    // And without a crash, a commit makes the renames durable.
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) || log_root_on(&device) != 0 {
        return TestResult::Fail("the commit after the burst did not clear the log");
    }
    drop(root);
    drop(vol);
    let Ok(clean) = mount_writable(device) else {
        return TestResult::Fail("remount after the committed burst failed");
    };
    let r = clean.root();
    for i in 0..FILES {
        if content(&r, &alloc::format!("cfg{i}")).as_deref()
            != Some(&pattern(1000 + i as u64, 3000 + i * 53)[..])
        {
            return TestResult::Fail("committed rename lost");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_fsync_burst_does_not_commit_per_fsync
);

/// A commit ends the log it follows: the committed superblock names no log,
/// the log's blocks return to the allocator, and an fsync in the next
/// transaction starts a new log on top of the commit.
fn smoke_btrfs_fsync_log_across_a_commit() -> TestResult {
    let Some((device, vol)) = log_fixture() else {
        return TestResult::Fail("fixture failed to mount");
    };
    let root = vol.root();
    let one = pattern(11, 40_000);
    let two = pattern(12, 40_000);
    let three = pattern(13, 40_000);
    if !put(&root, "seed", 0, &one) || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return TestResult::Fail("setup failed");
    }
    if !put(&root, "c1", 0, &one) || !fsync_file(&root, "c1", false) || log_root_on(&device) == 0 {
        return TestResult::Fail("first fsync left no log");
    }
    // A full commit: the log is gone from the superblock on the device.
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) || log_root_on(&device) != 0 {
        return TestResult::Fail("commit did not clear log_root");
    }
    // The next transaction: change c1 without syncing it, fsync a new file.
    if !put(&root, "c1", 40_000, &two)
        || !put(&root, "c2", 0, &three)
        || !fsync_file(&root, "c2", false)
        || log_root_on(&device) == 0
    {
        return TestResult::Fail("fsync after the commit left no log");
    }
    let Some((_copy, crashed)) = after_crash(&device) else {
        return TestResult::Fail("mount after the crash failed or left the log");
    };
    let r = crashed.root();
    if content(&r, "c1").as_deref() != Some(&one[..]) {
        return TestResult::Fail("committed file not as committed after replay");
    }
    if content(&r, "c2").as_deref() != Some(&three[..]) {
        return TestResult::Fail("file fsynced after the commit not back");
    }
    // Many log generations in a row reuse the space commits release.
    for round in 0..12u64 {
        let data = pattern(100 + round, 30_000);
        if !put(&root, "churn", 0, &data)
            || !fsync_file(&root, "churn", false)
            || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
        {
            return TestResult::Fail("fsync + commit round failed");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_fsync_log_across_a_commit);

/// What the log cannot express exactly commits instead, and is just as
/// durable: an fsync of a directory, of a file renamed since the last
/// commit, and of a new file under a name another inode held at the last
/// commit.
fn smoke_btrfs_fsync_falls_back_to_a_commit() -> TestResult {
    let Some((device, vol)) = log_fixture() else {
        return TestResult::Fail("fixture failed to mount");
    };
    let root = vol.root();
    let a = pattern(21, 12_000);
    let b = pattern(22, 30_000);
    if !put(&root, "old-name", 0, &a)
        || !put(&root, "taken", 0, &a)
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return TestResult::Fail("setup failed");
    }
    let fallbacks = |reason: &str| {
        crate::stats::fsync_fallbacks()
            .into_iter()
            .find(|(r, _)| *r == reason)
            .map_or(0, |(_, n)| n)
    };
    use crate::write::tree_log::Fallback;

    // A directory after a create and a rename in it.
    let dirs = fallbacks(Fallback::NotRegularFile.name());
    let Some(Ok(dir)) = poll_once(root.mkdir("dir")) else {
        return TestResult::Fail("mkdir failed");
    };
    if !put(&dir, "x", 0, &b)
        || !matches!(poll_once(dir.rename("x", "y")), Some(Ok(())))
        || !matches!(poll_once(dir.fsync(false)), Some(Ok(())))
        || fallbacks(Fallback::NotRegularFile.name()) != dirs + 1
        || log_root_on(&device) != 0
    {
        return TestResult::Fail("directory fsync did not commit");
    }
    let Some((_c, crashed)) = after_crash(&device) else {
        return TestResult::Fail("mount after the directory fsync failed");
    };
    let entry = poll_once(crashed.root().lookup_dir_async("dir"))
        .and_then(|d| d.ok())
        .and_then(|d| content(&d, "y"));
    if entry.as_deref() != Some(&b[..]) {
        return TestResult::Fail("directory fsync lost the renamed entry");
    }
    drop(crashed);

    // A file renamed since the last commit.
    let renamed = fallbacks(Fallback::NamesChanged.name());
    if !matches!(poll_once(root.rename("old-name", "new-name")), Some(Ok(())))
        || !put(&root, "new-name", 0, &b)
        || !fsync_file(&root, "new-name", false)
        || fallbacks(Fallback::NamesChanged.name()) != renamed + 1
    {
        return TestResult::Fail("fsync of a renamed file did not commit");
    }
    // A new file under a name another inode held at the last commit.
    let collided = fallbacks(Fallback::NameCollision.name());
    if !matches!(poll_once(root.unlink("taken")), Some(Ok(())))
        || !put(&root, "taken", 0, &b)
        || !fsync_file(&root, "taken", false)
        || fallbacks(Fallback::NameCollision.name()) != collided + 1
    {
        return TestResult::Fail("fsync under a reused name did not commit");
    }
    let Some((_c, crashed)) = after_crash(&device) else {
        return TestResult::Fail("mount after the fallback fsyncs failed");
    };
    let r = crashed.root();
    if content(&r, "new-name").as_deref() != Some(&b[..])
        || content(&r, "taken").as_deref() != Some(&b[..])
        || poll_once(r.lookup_async("old-name")).is_some_and(|f| f.is_ok())
    {
        return TestResult::Fail("a committed fsync was not durable");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_fsync_falls_back_to_a_commit);

/// A log NARF wrote survives a crash in the middle of its own replay: cut
/// the device at every write of the replay (a spread when there are many)
/// and the next mount still ends at what the uninterrupted replay gives.
fn smoke_btrfs_own_log_replay_survives_a_crash_at_any_write() -> TestResult {
    let Some((device, vol)) = log_fixture() else {
        return TestResult::Fail("fixture failed to mount");
    };
    let root = vol.root();
    if !put(&root, "o", 0, &pattern(31, 150_000))
        || !put(&root, "t", 0, &pattern(32, 90_000))
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return TestResult::Fail("setup failed");
    }
    let Some(Ok(t)) = poll_once(root.lookup_async("t")) else {
        return TestResult::Fail("t missing");
    };
    let made = poll_once(root.mkdir("nd"))
        .and_then(|d| d.ok())
        .is_some_and(|nd| put(&nd, "f", 0, &pattern(33, 20_000)) && fsync_file(&nd, "f", false));
    if !made
        || !put(&root, "o", 8192, &pattern(34, 30_000))
        || !fsync_file(&root, "o", false)
        || !matches!(poll_once(t.truncate(10_001)), Some(Ok(())))
        || !matches!(poll_once(t.fsync(false)), Some(Ok(())))
        || !put(&root, "n", 0, &pattern(35, 300))
        || !fsync_file(&root, "n", false)
    {
        return TestResult::Fail("logging failed");
    }
    let image = crash_copy(&device);
    if log_root_on(&image) == 0 {
        return TestResult::Fail("no log to replay");
    }
    // The uninterrupted replay is the reference.
    let reference = {
        let copy = crash_copy(&image);
        let Ok(v) = mount_writable(copy) else {
            return TestResult::Fail("reference replay failed");
        };
        match walk(v.root()) {
            Ok(tree) => tree,
            Err(why) => return TestResult::Fail(why),
        }
    };
    let total = mount_cut(&crash_copy(&image), i64::MAX);
    let step = (total / 40).max(1);
    let mut cut = 0u64;
    let mut log_kept = 0u32;
    while cut <= total {
        let copy = crash_copy(&image);
        mount_cut(&copy, cut as i64);
        if log_root_on(&copy) != 0 {
            log_kept += 1;
        }
        let Ok(v) = mount_writable(copy.clone()) else {
            return TestResult::Fail("mount after an interrupted replay failed");
        };
        if log_root_on(&copy) != 0 {
            return TestResult::Fail("log_root set after the second replay");
        }
        match walk(v.root()) {
            Ok(tree) if tree == reference => {}
            _ => return TestResult::Fail("an interrupted replay ended somewhere else"),
        }
        cut += step;
    }
    if log_kept == 0 {
        return TestResult::Fail("no cut left the log in place: the sweep proved nothing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_own_log_replay_survives_a_crash_at_any_write
);
