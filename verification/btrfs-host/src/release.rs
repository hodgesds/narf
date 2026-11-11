//! The `release` scenario: truncating and unlinking large files on a small
//! filesystem, and crashing in the middle of it.
//!
//! Freeing a file's data drops one reference per extent, and each dropped
//! reference is reserved for at its worst case: a path of the csum, extent
//! and free-space trees of its own. An operation that drops a whole file's
//! extents at once therefore asks for metadata space in proportion to the
//! file — gigabytes for a few hundred megabytes of data — which no
//! filesystem has free; the reservation is refused, and the chunk allocation
//! a refused reservation leads to turns unallocated device space into
//! METADATA chunks until the operation gives up with `ENOSPC`. Linux never
//! reserves for the whole file: `btrfs_truncate` and `btrfs_evict_inode`
//! restart their transaction every few items (`btrfs_truncate_inode_items`
//! returning `-EAGAIN`), a truncate writing the inode's size down to the
//! last item it removed each time.
//!
//! **Reservation.** Files of 1, 1,000 and 100,000 single-page extents, a
//! 256 MiB file and a 1 GiB file written in 1 MiB calls, on a 6 GiB
//! filesystem: one of each size is truncated to nothing, another unlinked.
//! Each must succeed without a METADATA chunk being allocated (free metadata
//! exceeds what the operation dirties many times over), and the most any
//! single staged operation reserves for its own extents must be small and
//! must not follow the file's size.
//!
//! **Crashes.** With every step committed on its own
//! (`write::set_dealloc_step_sync`), a file is truncated — to nothing, to an
//! extent boundary in its middle, to the middle of an extent — or unlinked,
//! and the recorded write stream is cut at every flush and at random points
//! in between ([`crate::crash`]). Each crashed image must pass `btrfs check`
//! and remount under NARF with the file at one of the sizes a step leaves:
//! never shorter than asked for, never with anything but its old contents up
//! to that size (or, for the unlink, the name either still there or gone,
//! and the filesystem checking clean once NARF has finished reclaiming the
//! orphan). A truncate that drops no more than a step's worth — every small
//! file's `O_TRUNC`, mid-extent or not — must commit exactly once: old state
//! or new, nothing in between.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use narf_drivers_fs_btrfs::stats;
use narf_filesystem::{DirOps, FileOps, FsError, FsInstance};

use crate::dev::RecDev;
use crate::host::block_on;
use crate::model::Flat;
use crate::workload::CommitRec;
use crate::{crash, dev, fixture, linux, narf, Args};

const PAGE: usize = 4096;
/// Extent items one step of a truncate or an eviction drops
/// (`write::DEALLOC_STEP_EXTENTS`).
const STEP: usize = 16;
/// The most tree blocks one staged operation may reserve for its own
/// extents: a step's worth of dropped references, with room to spare.
const STEP_RESERVATION_BLOCKS: u64 = 1024;

fn err<E: std::fmt::Debug>(what: &str) -> impl Fn(E) -> String + '_ {
    move |e| format!("{what}: {e:?}")
}

fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = (seed + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Write `body` at `at`, whole.
async fn write_all(file: &Arc<dyn FileOps>, at: u64, body: &[u8]) -> Result<(), String> {
    let mut done = 0;
    while done < body.len() {
        let n = file
            .write(at + done as u64, &body[done..])
            .await
            .map_err(err("write"))?;
        if n == 0 {
            return Err("write made no progress".into());
        }
        done += n;
    }
    Ok(())
}

/// Create `name` from `count` writes of `len` bytes each, one after the
/// other: page-sized writes make an extent each, larger ones an extent per
/// 128 KiB.
fn build(
    dir: &Arc<dyn DirOps>,
    name: &str,
    count: usize,
    len: usize,
) -> Result<Arc<dyn FileOps>, String> {
    block_on(async {
        let file = dir.create(name).await.map_err(err("create"))?;
        for i in 0..count {
            let body = noise((i as u64) << 20 ^ count as u64 ^ (len as u64) << 44, len);
            write_all(&file, (i * len) as u64, &body).await?;
        }
        file.fsync(false).await.map_err(err("fsync"))?;
        Ok(file)
    })
}

/// Features of the scenario's filesystems: `no-holes`, as `mkfs.btrfs`
/// makes them now, unless a case wants explicit hole items.
const FEATURES: &str = "block-group-tree,free-space-tree,no-holes";
const FEATURES_HOLE_ITEMS: &str = "block-group-tree,free-space-tree";

fn mkfs(dir: &Path, size: u64, tag: u64, features: &str) -> Result<PathBuf, String> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let rootdir = dir.join("rootdir");
    std::fs::create_dir_all(rootdir.join("@/etc")).unwrap();
    std::fs::create_dir_all(rootdir.join("@home")).unwrap();
    std::fs::write(rootdir.join("@/etc/hostname"), b"release\n").unwrap();
    let img = dir.join("release.img");
    fixture::mkfs(
        &img,
        &rootdir,
        &fixture::MkfsSpec {
            uuid: &format!("c4c405ee-0000-4a11-9e57-{:012x}", 0x4e1e_0000_0000u64 + tag),
            size,
            nodesize: 16384,
            csum: "crc32c",
            features,
        },
    )?;
    Ok(img)
}

/// One measured operation.
struct Row {
    what: String,
    result: Result<(), FsError>,
    /// METADATA chunks before and after.
    chunks: (usize, usize),
    /// The most tree blocks one staged operation reserved for its extents.
    reserved: u64,
    seconds: f64,
}

/// Run `op` (which ends by committing), recording what it did to the
/// filesystem's METADATA chunks and what its steps reserved.
fn measure(img: &Path, what: String, op: impl FnOnce() -> Result<(), FsError>) -> Row {
    let before = linux::chunk_counts(img).1;
    stats::reset_max_op_reservation();
    let started = Instant::now();
    let result = op();
    Row {
        what,
        result,
        chunks: (before, linux::chunk_counts(img).1),
        reserved: stats::max_op_reservation(),
        seconds: started.elapsed().as_secs_f64(),
    }
}

/// `ORPHAN_ITEM`s in subvolume tree `id`.
fn orphan_items(img: &Path, id: u64) -> Result<usize, String> {
    let out = linux::btrfs()
        .args(["inspect-internal", "dump-tree", "-t", &id.to_string()])
        .arg(img)
        .output()
        .map_err(|e| format!("dump-tree: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "dump-tree -t {id} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains("ORPHAN_ITEM"))
        .count())
}

/// The reservation half; returns its report lines.
fn reservation(args: &Args) -> Result<String, String> {
    let dir = args.workdir.join("release");
    let img = mkfs(&dir, 6 << 30, 1, FEATURES)?;
    let (fsid, nodesize, _) = dev::image_identity(&img);
    let mount = || -> Result<Arc<dyn FsInstance>, String> {
        let dev = Arc::new(RecDev::open(&img, 512, fsid, nodesize));
        narf::register_root(dev, &fsid)?;
        Ok(narf::mount_root_rw(&fsid, "@", &[])?.remove(0))
    };
    let scale = args.ops.clamp(300, 3000);
    // (label, writes, bytes per write, truncated?, unlinked?): the three
    // extent counts, each truncated and unlinked, then the two operations of
    // the soak that found the defect.
    let shapes = [
        ("1 extent".to_string(), 1usize, 128usize << 10, true, true),
        ("1000 extents".to_string(), 1000, PAGE, true, true),
        (
            format!("{} extents", 100_000 * scale / 3000),
            100_000 * scale / 3000,
            PAGE,
            true,
            true,
        ),
        (
            format!("{} MiB in 1 MiB writes", 256 * scale / 3000),
            256 * scale / 3000,
            1 << 20,
            true,
            false,
        ),
        (
            format!("{} MiB in 1 MiB writes", 1024 * scale / 3000),
            1024 * scale / 3000,
            1 << 20,
            false,
            true,
        ),
    ];

    let fs = mount()?;
    let top = block_on(fs.root().mkdir("release")).map_err(err("mkdir"))?;
    let mut rows = Vec::new();
    // A failure to build the next files (after an operation above went
    // wrong) ends the measurements but not the report.
    let mut build_error = None;
    for (index, (label, count, len, truncated, unlinked)) in shapes.iter().enumerate() {
        // Both files first, so each operation meets a filesystem that also
        // holds the other's data.
        let (cut_name, gone_name) = (format!("truncate-{index}"), format!("unlink-{index}"));
        let make = |wanted: &bool, name: &str| match wanted {
            true => build(&top, name, *count, *len).map(Some),
            false => Ok(None),
        };
        let built = make(truncated, &cut_name).and_then(|cut| {
            let gone = make(unlinked, &gone_name)?;
            block_on(top.fsync(false)).map_err(err("fsync"))?;
            Ok((cut, gone))
        });
        let (cut, gone) = match built {
            Ok(files) => files,
            Err(e) => {
                build_error = Some(format!("building the files of {label}: {e}"));
                break;
            }
        };
        if let Some(cut) = cut {
            rows.push(measure(&img, format!("truncate to 0, {label}"), || {
                block_on(async {
                    cut.truncate(0).await?;
                    cut.fsync(false).await
                })
            }));
        }
        // The last reference goes with the handle; the inode is reclaimed
        // by the next operation, and the fsync commits it.
        if gone.is_some() {
            drop(gone);
            let poke = format!("after-{index}");
            rows.push(measure(&img, format!("unlink, {label}"), || {
                block_on(async {
                    top.unlink(&gone_name).await?;
                    top.create(&poke).await?;
                    top.fsync(false).await
                })
            }));
        }
    }
    drop(top);
    drop(fs);
    narf::reset();

    let node_mib = f64::from(nodesize) / 1048576.0;
    let lines: Vec<String> = rows
        .iter()
        .map(|r| {
            format!(
                "    {}: {}; METADATA chunks {} -> {}; most one step reserved {} tree blocks ({:.1} MiB); {:.2} s",
                r.what,
                match &r.result {
                    Ok(()) => "ok".to_string(),
                    Err(e) => format!("FAILED ({e:?})"),
                },
                r.chunks.0,
                r.chunks.1,
                r.reserved,
                r.reserved as f64 * node_mib,
                r.seconds
            )
        })
        .collect();
    let report = lines.join("\n");
    if let Some(e) = build_error {
        return Err(format!("{report}\n{e}"));
    }
    for r in &rows {
        if r.result.is_err() {
            return Err(format!("{report}\n{} failed", r.what));
        }
        if r.chunks.1 != r.chunks.0 {
            return Err(format!(
                "{report}\n{} allocated {} METADATA chunk(s)",
                r.what,
                r.chunks.1 - r.chunks.0
            ));
        }
        if r.reserved > STEP_RESERVATION_BLOCKS {
            return Err(format!(
                "{report}\n{}: one step reserved {} tree blocks, more than {STEP_RESERVATION_BLOCKS}",
                r.what, r.reserved
            ));
        }
    }
    // Rows 2 and 3 are the 1,000-extent file, 4 and 5 the one a hundred
    // times that: what a step reserves does not follow the file (the trees
    // it is priced against may have gained a level in between, which is the
    // factor allowed).
    if rows[4].reserved > 2 * rows[2].reserved || rows[5].reserved > 2 * rows[3].reserved {
        return Err(format!(
            "{report}\nthe reservation of a step depends on the size of the file"
        ));
    }

    linux::check(&img, false)?;
    linux::check(&img, true)?;
    let subvols = linux::subvolumes(&img)?;
    let at = linux::subvol_id(&subvols, "@").ok_or("no @ subvolume")?;
    let orphans = orphan_items(&img, at)?;
    if orphans != 0 {
        return Err(format!("{report}\n{orphans} orphan item(s) left behind"));
    }
    let fs = mount()?;
    let top = block_on(fs.root().lookup_dir_async("release")).map_err(err("remount: lookup"))?;
    for (index, (_, _, _, truncated, _)) in shapes.iter().enumerate() {
        if *truncated {
            let cut = block_on(top.lookup_async(&format!("truncate-{index}")))
                .map_err(err("remount: lookup truncated file"))?;
            let size = block_on(cut.stat_async()).map_err(err("stat"))?.size;
            if size != 0 {
                return Err(format!("truncate-{index} is {size} bytes after remount"));
            }
        }
        if block_on(top.lookup_async(&format!("unlink-{index}"))).is_ok() {
            return Err(format!("unlink-{index} is back after remount"));
        }
    }
    drop(top);
    drop(fs);
    narf::reset();
    linux::check(&img, false).map_err(|e| format!("after NARF remount: {e}"))?;
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(report)
}

/// What a crash case does to its file.
#[derive(Clone, Copy)]
enum Cut {
    /// Truncate to this many bytes.
    Truncate(u64),
    Unlink,
}

/// One crash case: a file of `pages` single-page extents followed by `big`
/// 128 KiB extents, cut as `cut` says with every step committed, and the
/// write stream replayed with crashes. `single` says the operation must
/// commit exactly once.
fn crash_case(
    args: &Args,
    name: &str,
    (pages, big): (usize, usize),
    cut: Cut,
    single: bool,
    features: &str,
) -> Result<String, String> {
    let dir = args
        .workdir
        .join(format!("release-crash-{}", name.replace([' ', ','], "-")));
    let img = mkfs(
        &dir,
        512 << 20,
        0x100 + name.len() as u64 * 7 + pages as u64,
        features,
    )?;
    let (fsid, nodesize, _) = dev::image_identity(&img);
    let open = |recording: bool| -> Result<(Arc<RecDev>, Arc<dyn FsInstance>), String> {
        let dev = Arc::new(RecDev::open(&img, 512, fsid, nodesize));
        dev.set_recording(recording);
        narf::register_root(dev.clone(), &fsid)?;
        Ok((dev, narf::mount_root_rw(&fsid, "@", &[])?.remove(0)))
    };
    // The file, committed; then the image as the crash replay starts from.
    {
        let (_dev, fs) = open(false)?;
        let top = block_on(fs.root().mkdir("crash")).map_err(err("mkdir"))?;
        let file = build(&top, "victim", pages, PAGE)?;
        block_on(async {
            for i in 0..big {
                let body = noise(0xb16 + i as u64, 128 << 10);
                write_all(&file, (pages * PAGE + i * (128 << 10)) as u64, &body).await?;
            }
            file.fsync(false).await.map_err(err("fsync"))
        })?;
        drop(file);
        drop(top);
        drop(fs);
        narf::reset();
    }
    let base = dir.join("base.img");
    linux::clone_file(&img, &base);
    let base_gen = dev::image_identity(&base).2;

    let (dev, fs) = open(true)?;
    let root = fs.root();
    let before = narf::walk(&root)?.0;
    let top = block_on(root.lookup_dir_async("crash")).map_err(err("lookup"))?;
    narf_drivers_fs_btrfs::write::set_dealloc_step_sync(true);
    let done = block_on(async {
        match cut {
            Cut::Truncate(size) => {
                let file = top.lookup_async("victim").await?;
                file.truncate(size).await?;
                file.fsync(false).await
            }
            Cut::Unlink => {
                top.unlink("victim").await?;
                top.create("poke").await?;
                top.fsync(false).await
            }
        }
    });
    narf_drivers_fs_btrfs::write::set_dealloc_step_sync(false);
    done.map_err(err("the operation"))?;
    let after = narf::walk(&root)?.0;
    drop(top);
    drop(root);
    drop(fs);
    narf::reset();
    dev.set_recording(false);
    let log = dev.take_log();
    // Every generation whose superblock reached the device, once.
    let gens: std::collections::BTreeSet<u64> = dev
        .sb_gens()
        .into_iter()
        .filter(|&gen| gen > base_gen)
        .collect();
    drop(dev);
    if single && gens.len() != 1 {
        return Err(format!(
            "{name}: a truncate within one step committed {} times; it must be one transaction",
            gens.len()
        ));
    }
    if !single && gens.len() < 3 {
        return Err(format!(
            "{name}: only {} commits; the steps were not committed one by one",
            gens.len()
        ));
    }

    // Every state a crash may leave: the old one, the new one, and for a
    // truncate the file cut at each extent boundary a step can stop at.
    let mut states = vec![vec![before.clone()], vec![after]];
    match cut {
        Cut::Truncate(size) => {
            let Some(Flat::File { data, .. }) = before.get("crash/victim") else {
                return Err(format!("{name}: no victim in the model"));
            };
            let old = data.clone();
            // Item starts from the cut on: a page each, then 128 KiB each.
            let starts: Vec<usize> = (0..pages)
                .map(|i| i * PAGE)
                .chain((0..big).map(|i| pages * PAGE + i * (128 << 10)))
                .filter(|&start| start as u64 >= size.next_multiple_of(PAGE as u64))
                .collect();
            let mut left = starts.len();
            while left > STEP {
                left -= STEP;
                let mut state = before.clone();
                if let Some(Flat::File { data, .. }) = state.get_mut("crash/victim") {
                    *data = Arc::new(old[..starts[left]].to_vec());
                }
                states.push(vec![state]);
            }
        }
        Cut::Unlink => {
            // The name gone, the next file not yet there.
            let mut state = before.clone();
            state.remove("crash/victim");
            states.push(vec![state]);
        }
    }
    let commits: Vec<CommitRec> = gens
        .iter()
        .map(|&gen| CommitRec {
            gen,
            candidates: states.clone(),
            // Every state a step can leave is listed above, exactly.
            shrinking: None,
        })
        .collect();
    let rep = crash::run(
        &crash::Input {
            base: &base,
            log: &log,
            commits: &commits,
            base_gen,
            base_state: vec![before],
            lba: 512,
            fsid,
            nodesize,
            root_subvol: "@",
            others: &[],
        },
        &crash::Opts {
            cuts: 0,
            exhaustive: true,
            seed: args.seed,
            jobs: args.jobs,
            workdir: dir.join("cuts"),
        },
    );
    if !rep.failures.is_empty() {
        return Err(format!(
            "{name}: {} of {} crash cuts failed (images kept in {}):\n{}",
            rep.failures.len(),
            rep.cuts,
            dir.join("cuts").display(),
            rep.failures.join("\n")
        ));
    }
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(format!(
        "    crash, {name}: {} commits, {} cuts over {} flushes, {} states allowed; every image checks clean and remounts at one of them",
        gens.len(),
        rep.cuts,
        rep.flush_boundaries,
        states.len(),
    ))
}

/// A directory removed while still open, as Linux `btrfs_rmdir` leaves it
/// after a crash: the inode unlinked under an ORPHAN_ITEM
/// (`write::set_rmdir_leaves_orphan`). Linux must check the image clean with
/// the orphan in it; the next NARF mount must evict it, and Linux must then
/// check the image clean with no orphan item left.
fn dir_orphan(args: &Args) -> Result<String, String> {
    let dir = args.workdir.join("release-dir-orphan");
    let img = mkfs(&dir, 512 << 20, 0x0d1, FEATURES)?;
    let (fsid, nodesize, _) = dev::image_identity(&img);
    let mount = || -> Result<Arc<dyn FsInstance>, String> {
        let dev = Arc::new(RecDev::open(&img, 512, fsid, nodesize));
        narf::register_root(dev, &fsid)?;
        Ok(narf::mount_root_rw(&fsid, "@", &[])?.remove(0))
    };
    {
        let fs = mount()?;
        let root = fs.root();
        block_on(async {
            drop(root.mkdir("gone").await?);
            narf_drivers_fs_btrfs::write::set_rmdir_leaves_orphan(true);
            let removed = root.rmdir("gone").await;
            narf_drivers_fs_btrfs::write::set_rmdir_leaves_orphan(false);
            removed?;
            root.fsync(false).await
        })
        .map_err(err("rmdir"))?;
        drop(root);
        drop(fs);
        narf::reset();
    }
    linux::check(&img, false).map_err(|e| format!("directory orphan, before recovery: {e}"))?;
    let subvols = linux::subvolumes(&img)?;
    let at = linux::subvol_id(&subvols, "@").ok_or("no @ subvolume")?;
    if orphan_items(&img, at)? != 1 {
        return Err("directory orphan: rmdir did not leave one orphan item".into());
    }
    {
        let fs = mount()?;
        if block_on(fs.root().lookup_dir_async("gone")).is_ok() {
            return Err("directory orphan: the directory is back".into());
        }
        block_on(async {
            fs.root().create("after").await?;
            fs.root().fsync(false).await
        })
        .map_err(err("write after recovery"))?;
        drop(fs);
        narf::reset();
    }
    linux::check(&img, false).map_err(|e| format!("directory orphan, after recovery: {e}"))?;
    let left = orphan_items(&img, at)?;
    if left != 0 {
        return Err(format!("directory orphan: {left} orphan item(s) left"));
    }
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok("    directory orphan (Linux rmdir of an open directory): btrfs check clean before and after, evicted by the next mount".into())
}

pub fn run(args: &Args) -> Result<String, String> {
    let t0 = Instant::now();
    let mut lines = vec![reservation(args)?];
    let page = PAGE as u64;
    for (name, shape, cut, single) in [
        // Large: many steps, each its own commit.
        ("truncate to nothing", (120, 4), Cut::Truncate(0), false),
        (
            "truncate to an extent boundary",
            (120, 4),
            Cut::Truncate(40 * page),
            false,
        ),
        (
            "truncate into an extent",
            (120, 4),
            Cut::Truncate(40 * page + 1234),
            false,
        ),
        ("unlink", (120, 4), Cut::Unlink, false),
        // Without `no-holes`: an eviction from the end of the file leaves no
        // gap `btrfs check` would want a hole item for.
        ("unlink, explicit hole items", (120, 4), Cut::Unlink, false),
        // Within a step: one transaction, whatever the cut.
        ("small truncate to nothing", (12, 0), Cut::Truncate(0), true),
        (
            "small truncate into an extent",
            (12, 0),
            Cut::Truncate(5 * page + 700),
            true,
        ),
        (
            "shrinking the last extent",
            (0, 2),
            Cut::Truncate(200_000),
            true,
        ),
    ] {
        let features = if name.contains("explicit hole items") {
            FEATURES_HOLE_ITEMS
        } else {
            FEATURES
        };
        lines.push(crash_case(args, name, shape, cut, single, features)?);
    }
    lines.push(dir_orphan(args)?);
    Ok(format!(
        "release: OK\n{}\n    btrfs check clean (also --check-data-csum), no orphan item left, files empty or gone after a remount; {:.0?}",
        lines.join("\n"),
        t0.elapsed()
    ))
}
