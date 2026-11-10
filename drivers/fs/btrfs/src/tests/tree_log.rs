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
