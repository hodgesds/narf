//! Operations of different inodes side by side on several CPUs: each holds
//! its own inode's and directory's locks and joins the running transaction
//! beside the others, and a commit closes it (`crate::txn_gate`).

use super::*;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, Ordering};
use narf_filesystem::{DirOps, FileOps, FsInstance};

type Vol = Arc<BtrfsVolume<narf_block::SyncBlock>>;
type Job = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

/// Run each `(cpu, job)` on its CPU and wait for all of them.
fn run_parallel(jobs: Vec<(u32, Job)>) -> Result<(), &'static str> {
    use core::fmt::Write as _;
    let done = Arc::new(AtomicU32::new(0));
    let failed = Arc::new(AtomicU32::new(0));
    let count = jobs.len() as u32;
    for (cpu, job) in jobs {
        let (done, failed) = (done.clone(), failed.clone());
        narf_scheduler::spawn_stackful_pinned(
            async move {
                if let Err(error) = job.await {
                    let _ = writeln!(narf_console::Writer, "btrfs concurrent cpu {cpu}: {error}");
                    failed.fetch_add(1, Ordering::AcqRel);
                }
                done.fetch_add(1, Ordering::AcqRel);
            },
            cpu,
        );
    }
    let mut spins = 0u64;
    while done.load(Ordering::Acquire) < count && spins < 40_000_000_000 {
        core::hint::spin_loop();
        spins += 1;
    }
    if done.load(Ordering::Acquire) < count {
        return Err("the concurrent operations did not finish (deadlock?)");
    }
    if failed.load(Ordering::Acquire) != 0 {
        return Err("a concurrent operation failed");
    }
    Ok(())
}

fn fresh() -> Result<(Arc<WritableSparseDevice>, Vol), &'static str> {
    if narf_lib::smp::cpu_count() < 5 {
        return Err("skip");
    }
    let dev = writable_sparse(FIXTURE_BGT_SPARSE);
    let vol = mount_writable(dev.clone()).map_err(|_| "fixture did not mount")?;
    Ok((dev, vol))
}

fn body(tag: &str, i: u32) -> Vec<u8> {
    format!("{tag}:{i}:").into_bytes().repeat(37)
}

fn result(r: Result<(), &'static str>) -> TestResult {
    match r {
        Ok(()) => TestResult::Pass,
        Err("skip") => TestResult::Skip("needs five CPUs"),
        Err(e) => TestResult::Fail(e),
    }
}

fn err<E: core::fmt::Debug>(what: &'static str) -> impl Fn(E) -> String {
    move |e| format!("{what}: {e:?}")
}

/// The `(index, inode)` of every `DIR_INDEX` item of directory `dir`.
fn dir_indexes(vol: &Vol, dir: u64) -> Result<Vec<(u64, u64)>, &'static str> {
    let items = poll_once(btree::collect_for(
        &**vol,
        vol.fs_tree_root().0,
        dir,
        format::DIR_INDEX_KEY,
    ))
    .and_then(|r| r.ok())
    .ok_or("reading DIR_INDEX items failed")?;
    items
        .into_iter()
        .map(|(key, body)| {
            Ok((
                key.offset,
                format::le64(&body, 0).map_err(|_| "short DIR_INDEX")?,
            ))
        })
        .collect()
}

/// Creates in one shared directory and in a directory each, from four CPUs
/// at once, with writes and fsyncs between: every new inode gets its own
/// number and every name its own directory index, and the result survives
/// a remount.
fn concurrent_creates() -> Result<(), &'static str> {
    const PER: u32 = 40;
    let (dev, vol) = fresh()?;
    let root = vol.root();
    let shared = poll_once(root.mkdir("shared"))
        .and_then(|r| r.ok())
        .ok_or("mkdir failed")?;
    let mut own = Vec::new();
    for cpu in 1..=4u32 {
        own.push(
            poll_once(root.mkdir(&format!("own{cpu}")))
                .and_then(|r| r.ok())
                .ok_or("mkdir failed")?,
        );
    }
    let jobs = (1..=4u32)
        .zip(own.iter().cloned())
        .map(|(cpu, mine)| {
            let shared = shared.clone();
            let job: Job = Box::pin(async move {
                for i in 0..PER {
                    for (dir, name) in [(&shared, format!("c{cpu}-{i}")), (&mine, format!("f{i}"))]
                    {
                        let file = dir.create(&name).await.map_err(err("create"))?;
                        let data = body(&name, cpu);
                        file.write(0, &data).await.map_err(err("write"))?;
                        if i % 10 == 9 {
                            file.fsync(false).await.map_err(err("fsync"))?;
                        }
                    }
                }
                Ok(())
            });
            (cpu, job)
        })
        .collect();
    run_parallel(jobs)?;
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("sync failed");
    }
    let check = |vol: &Vol| -> Result<(), &'static str> {
        let root = vol.root();
        let mut inodes = alloc::collections::BTreeSet::new();
        let mut names = 0usize;
        let shared = poll_once(root.lookup_dir_async("shared"))
            .and_then(|r| r.ok())
            .ok_or("shared missing")?;
        let indexes = dir_indexes(vol, shared.ino())?;
        if indexes.len() != (4 * PER) as usize {
            return Err("the shared directory lost a name (two creates shared a directory index)");
        }
        for (_, ino) in &indexes {
            inodes.insert(*ino);
        }
        names += indexes.len();
        for cpu in 1..=4u32 {
            let dir = poll_once(root.lookup_dir_async(&format!("own{cpu}")))
                .and_then(|r| r.ok())
                .ok_or("own dir missing")?;
            let indexes = dir_indexes(vol, dir.ino())?;
            if indexes.len() != PER as usize {
                return Err("a directory lost a name");
            }
            for (_, ino) in &indexes {
                inodes.insert(*ino);
            }
            names += indexes.len();
            for i in 0..PER {
                let name = format!("f{i}");
                let file = poll_once(dir.lookup_async(&name))
                    .and_then(|r| r.ok())
                    .ok_or("a file is missing")?;
                if read_all(&file, 4096) != Some(body(&name, cpu)) {
                    return Err("a file's contents are wrong");
                }
            }
        }
        if inodes.len() != names {
            return Err("two concurrently created inodes got the same number");
        }
        Ok(())
    };
    check(&vol)?;
    check(&mount_writable(dev).map_err(|_| "remount failed")?)
}

fn smoke_btrfs_concurrent_creates_get_distinct_numbers() -> TestResult {
    result(concurrent_creates())
}

kernel_test_in!(
    "drivers/fs/btrfs/race",
    smoke_btrfs_concurrent_creates_get_distinct_numbers
);

/// Renames across two directories in opposite directions from two CPUs at
/// once, with a third writing to the files wherever they are: the ordered
/// directory locks (and the cross-directory rename lock, Linux
/// `lock_rename`) keep them from deadlocking, and every file ends up in
/// exactly one place with its data.
fn rename_across() -> Result<(), &'static str> {
    const FILES: u32 = 12;
    const ROUNDS: u32 = 8;
    let (dev, vol) = fresh()?;
    let root = vol.root();
    let a = poll_once(root.mkdir("a"))
        .and_then(|r| r.ok())
        .ok_or("mkdir failed")?;
    let b = poll_once(root.mkdir("b"))
        .and_then(|r| r.ok())
        .ok_or("mkdir failed")?;
    for i in 0..FILES {
        for (dir, tag) in [(&a, "x"), (&b, "y")] {
            let name = format!("{tag}{i}");
            let file = poll_once(dir.create(&name))
                .and_then(|r| r.ok())
                .ok_or("create failed")?;
            if !matches!(poll_once(file.write(0, &body(&name, 0))), Some(Ok(_))) {
                return Err("seed write failed");
            }
        }
    }
    let mover = |from: Arc<dyn DirOps>, to: Arc<dyn DirOps>, tag: &'static str| -> Job {
        Box::pin(async move {
            for _ in 0..ROUNDS {
                for i in 0..FILES {
                    let name = format!("{tag}{i}");
                    from.rename_to(&name, &*to, &name, 0)
                        .await
                        .map_err(err("rename"))?;
                }
                for i in 0..FILES {
                    let name = format!("{tag}{i}");
                    to.rename_to(&name, &*from, &name, 0)
                        .await
                        .map_err(err("rename back"))?;
                }
            }
            Ok(())
        })
    };
    let writer: Job = {
        let (a, b) = (a.clone(), b.clone());
        Box::pin(async move {
            for round in 0..ROUNDS * 4 {
                for i in 0..FILES {
                    for tag in ["x", "y"] {
                        let name = format!("{tag}{i}");
                        // Wherever it is just now; a rename may move it
                        // between the two lookups, and then it is skipped.
                        let file = match a.lookup_async(&name).await {
                            Ok(file) => file,
                            Err(FsError::NotFound) => match b.lookup_async(&name).await {
                                Ok(file) => file,
                                Err(FsError::NotFound) => continue,
                                Err(e) => return Err(format!("lookup: {e:?}")),
                            },
                            Err(e) => return Err(format!("lookup: {e:?}")),
                        };
                        let data = body(&name, 0);
                        file.write(0, &data).await.map_err(err("write"))?;
                        if round % 8 == 7 {
                            file.fsync(true).await.map_err(err("fdatasync"))?;
                        }
                    }
                }
            }
            Ok(())
        })
    };
    run_parallel(alloc::vec![
        (1, mover(a.clone(), b.clone(), "x")),
        (2, mover(b.clone(), a.clone(), "y")),
        (3, writer),
    ])?;
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("sync failed");
    }
    let check = |vol: &Vol| -> Result<(), &'static str> {
        let root = vol.root();
        for (dir, tag) in [("a", "x"), ("b", "y")] {
            let dir = poll_once(root.lookup_dir_async(dir))
                .and_then(|r| r.ok())
                .ok_or("dir missing")?;
            if dir_indexes(vol, dir.ino())?.len() != FILES as usize {
                return Err("a directory holds the wrong number of names");
            }
            for i in 0..FILES {
                let name = format!("{tag}{i}");
                let file = poll_once(dir.lookup_async(&name))
                    .and_then(|r| r.ok())
                    .ok_or("a renamed file is missing")?;
                if read_all(&file, 4096) != Some(body(&name, 0)) {
                    return Err("a renamed file's contents are wrong");
                }
            }
        }
        Ok(())
    };
    check(&vol)?;
    check(&mount_writable(dev).map_err(|_| "remount failed")?)
}

fn smoke_btrfs_cross_dir_renames_do_not_deadlock() -> TestResult {
    result(rename_across())
}

kernel_test_in!(
    "drivers/fs/btrfs/race",
    smoke_btrfs_cross_dir_renames_do_not_deadlock
);

/// Unlinks that leave orphans, lookups of the same names, and writes that
/// reap the orphans on their way in, from three CPUs at once: a lookup
/// either finds a name with its data or does not find it, an orphan is
/// evicted once, and none is left once the operations stop.
fn orphans_vs_lookups() -> Result<(), &'static str> {
    const FILES: u32 = 60;
    let (dev, vol) = fresh()?;
    let root = vol.root();
    let dir = poll_once(root.mkdir("o"))
        .and_then(|r| r.ok())
        .ok_or("mkdir failed")?;
    let other = poll_once(root.create("busy"))
        .and_then(|r| r.ok())
        .ok_or("create failed")?;
    let stop = Arc::new(AtomicU32::new(0));
    let unlinker: Job = {
        let (dir, stop) = (dir.clone(), stop.clone());
        Box::pin(async move {
            let mut held = Vec::new();
            for i in 0..FILES {
                let name = format!("o{i}");
                let file = dir.create(&name).await.map_err(err("create"))?;
                file.write(0, &body(&name, 0).repeat(64))
                    .await
                    .map_err(err("write"))?;
                dir.unlink(&name).await.map_err(err("unlink"))?;
                // Every third stays open past its unlink, as a process
                // reading a deleted file keeps it.
                if i % 3 == 0 {
                    held.push(file);
                }
                if held.len() > 4 {
                    held.remove(0);
                }
            }
            stop.store(1, Ordering::Release);
            Ok(())
        })
    };
    let looker: Job = {
        let (dir, stop) = (dir.clone(), stop.clone());
        Box::pin(async move {
            while stop.load(Ordering::Acquire) == 0 {
                for i in 0..FILES {
                    let name = format!("o{i}");
                    match dir.lookup_async(&name).await {
                        Ok(file) => {
                            let mut buf = alloc::vec![0u8; 64];
                            let n = file.read(0, &mut buf).await.map_err(err("read"))?;
                            let want = body(&name, 0);
                            if n != 0 && buf[..n.min(want.len())] != want[..n.min(want.len())] {
                                return Err(format!(
                                    "{name}: a looked-up file read the wrong bytes"
                                ));
                            }
                        }
                        Err(FsError::NotFound) => {}
                        Err(e) => return Err(format!("lookup {name}: {e:?}")),
                    }
                }
                narf_scheduler::yield_now().await;
            }
            Ok(())
        })
    };
    let reaper: Job = {
        let (other, stop) = (other.clone(), stop.clone());
        Box::pin(async move {
            let mut i = 0u64;
            while stop.load(Ordering::Acquire) == 0 {
                other
                    .write(i * 4096 % (1 << 20), &[0x5a; 4096])
                    .await
                    .map_err(err("write"))?;
                if i % 16 == 15 {
                    other.fsync(false).await.map_err(err("fsync"))?;
                }
                i += 1;
            }
            Ok(())
        })
    };
    run_parallel(alloc::vec![(1, unlinker), (2, looker), (3, reaper)])?;
    // Every handle is gone: one more operation reaps what is left.
    for _ in 0..4 {
        if !matches!(poll_once(other.write(0, b"last")), Some(Ok(4))) {
            return Err("final write failed");
        }
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("sync failed");
    }
    let orphans = poll_once(btree::collect_for(
        &*vol,
        vol.fs_tree_root().0,
        crate::orphans::ORPHAN_OBJECTID,
        crate::orphans::ORPHAN_ITEM_KEY,
    ))
    .and_then(|r| r.ok())
    .ok_or("reading orphan items failed")?;
    if !orphans.is_empty() {
        return Err("orphans were left behind");
    }
    if !dir_indexes(&vol, dir.ino())?.is_empty() {
        return Err("an unlinked name is still in the directory");
    }
    drop(dir);
    drop(other);
    drop(root);
    mount_writable(dev)
        .map(|_| ())
        .map_err(|_| "remount failed")
}

fn smoke_btrfs_orphan_eviction_beside_lookups() -> TestResult {
    result(orphans_vs_lookups())
}

kernel_test_in!(
    "drivers/fs/btrfs/race",
    smoke_btrfs_orphan_eviction_beside_lookups
);

/// The subvolume's referenced bytes (`QGROUP_INFO.rfer`).
fn qgroup_rfer(vol: &Vol, id: u64) -> Option<u64> {
    let root_tree = vol.root_tree_root().0;
    let quota_root = poll_once(crate::roots::find_root(
        &**vol,
        root_tree,
        format::QUOTA_TREE_OBJECTID,
    ))
    .and_then(Result::ok)?
    .0;
    let body = poll_once(btree::find_item(
        &**vol,
        quota_root,
        &BtrfsKey::new(0, format::QGROUP_INFO_KEY, id),
    ))
    .and_then(Result::ok)
    .flatten()?;
    format::le64(&body, 8).ok()
}

/// Two writers of two files under one qgroup limit, from two CPUs at once:
/// each write reserves before it stages, so the two cannot both be admitted
/// past the limit, and the committed usage stays within it.
fn quota_two_handles() -> Result<(), &'static str> {
    let (_dev, vol) = fresh()?;
    let root = vol.root();
    let mut ctl = [0u8; 16];
    ctl[0..8].copy_from_slice(&1u64.to_ne_bytes());
    if !matches!(
        poll_once(root.ioctl_async(crate::node::BTRFS_IOC_QUOTA_CTL, 0, &ctl, 16)),
        Some(Ok(_))
    ) {
        return Err("quota enable failed");
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("sync failed");
    }
    let id = vol.fs_tree_id();
    let used = qgroup_rfer(&vol, id).ok_or("no qgroup info")?;
    let limit = used + (768 << 10);
    let mut args = [0u8; 48];
    args[8..16].copy_from_slice(&1u64.to_ne_bytes());
    args[16..24].copy_from_slice(&limit.to_ne_bytes());
    if !matches!(
        poll_once(root.ioctl_async(crate::node::BTRFS_IOC_QGROUP_LIMIT, 0, &args, 48)),
        Some(Ok(_))
    ) {
        return Err("qgroup limit failed");
    }
    let files: Vec<Arc<dyn FileOps>> = ["q1", "q2"]
        .iter()
        .map(|n| {
            poll_once(root.create(n))
                .and_then(|r| r.ok())
                .ok_or("create failed")
        })
        .collect::<Result<_, _>>()?;
    let accepted = Arc::new(AtomicU32::new(0));
    let jobs = files
        .iter()
        .cloned()
        .enumerate()
        .map(|(n, file)| {
            let accepted = accepted.clone();
            let job: Job = Box::pin(async move {
                for i in 0..64u64 {
                    match file
                        .write(i * (32 << 10), &[0x40 + n as u8; 32 << 10])
                        .await
                    {
                        Ok(_) => {
                            accepted.fetch_add(32, Ordering::AcqRel);
                        }
                        Err(FsError::QuotaExceeded) => return Ok(()),
                        Err(e) => return Err(format!("write: {e:?}")),
                    }
                }
                Err("the limit never refused a write".into())
            });
            (n as u32 + 1, job)
        })
        .collect();
    run_parallel(jobs)?;
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("sync failed");
    }
    let after = qgroup_rfer(&vol, id).ok_or("no qgroup info")?;
    if after > limit {
        return Err("two concurrent writers were admitted past the qgroup limit");
    }
    if u64::from(accepted.load(Ordering::Acquire)) << 10 > limit - used {
        return Err("more data was accepted than the limit leaves room for");
    }
    Ok(())
}

fn smoke_btrfs_quota_two_concurrent_writers() -> TestResult {
    result(quota_two_handles())
}

kernel_test_in!(
    "drivers/fs/btrfs/race",
    smoke_btrfs_quota_two_concurrent_writers
);
