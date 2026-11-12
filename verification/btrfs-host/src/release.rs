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
use narf_drivers_fs_btrfs::write::{
    FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE,
};
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
    /// Steps the operation takes (extent items over the step size).
    steps: u64,
    /// Device writes, tree nodes written and commits, the closing fsync's
    /// commit included.
    device_writes: u64,
    tree_written: u64,
    commits: u64,
}

/// Run `op` (which ends by committing), recording what it did to the
/// filesystem's METADATA chunks, what its steps reserved and what it wrote.
fn measure(
    img: &Path,
    dev: &RecDev,
    what: String,
    items: usize,
    op: impl FnOnce() -> Result<(), FsError>,
) -> Row {
    let before = linux::chunk_counts(img).1;
    stats::reset_max_op_reservation();
    let (totals, writes) = (stats::totals(), dev.writes());
    let started = Instant::now();
    let result = op();
    let seconds = started.elapsed().as_secs_f64();
    let cost = stats::totals().since(&totals);
    Row {
        what,
        result,
        chunks: (before, linux::chunk_counts(img).1),
        reserved: stats::max_op_reservation(),
        seconds,
        steps: items.div_ceil(STEP).max(1) as u64,
        device_writes: dev.writes() - writes,
        tree_written: cost.written.total(),
        commits: cost.commits,
    }
}

/// Create `name` from `count` page-sized writes a page apart: `count`
/// extents with a hole after each.
fn build_strided(
    dir: &Arc<dyn DirOps>,
    name: &str,
    count: usize,
) -> Result<Arc<dyn FileOps>, String> {
    block_on(async {
        let file = dir.create(name).await.map_err(err("create"))?;
        for i in 0..count {
            let body = noise(0x5eed ^ (i as u64) << 20 ^ count as u64, PAGE);
            write_all(&file, (2 * i * PAGE) as u64, &body).await?;
        }
        file.fsync(false).await.map_err(err("fsync"))?;
        Ok(file)
    })
}

/// Whether `[at, at + len)` of `file` reads as zeros, checked a page at a
/// time with a stride (the whole of a large file would take long).
fn reads_zero(file: &Arc<dyn FileOps>, at: u64, len: u64) -> Result<bool, String> {
    block_on(async {
        let mut page = vec![0u8; PAGE];
        let stride = (len / 2048).max(PAGE as u64) / PAGE as u64 * PAGE as u64;
        let mut off = at;
        while off < at + len {
            let n = file.read(off, &mut page).await.map_err(err("read"))?;
            if page[..n].iter().any(|&b| b != 0) {
                return Ok(false);
            }
            off += stride;
        }
        Ok(true)
    })
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

/// What a file must hold after an `fallocate` row: (row, file, offset and
/// length of a range that must read as zeros, the size it must have).
type RangeCheck = (usize, Arc<dyn FileOps>, u64, u64, u64);

/// The reservation half; returns its report lines.
fn reservation(args: &Args) -> Result<String, String> {
    let dir = args.workdir.join("release");
    let img = mkfs(&dir, 6 << 30, 1, FEATURES)?;
    let (fsid, nodesize, _) = dev::image_identity(&img);
    let mount = || -> Result<(Arc<RecDev>, Arc<dyn FsInstance>), String> {
        let dev = Arc::new(RecDev::open(&img, 512, fsid, nodesize));
        narf::register_root(dev.clone(), &fsid)?;
        Ok((dev, narf::mount_root_rw(&fsid, "@", &[])?.remove(0)))
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

    let (dev, fs) = mount()?;
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
        // Extent items the file holds.
        let items = count * len.div_ceil(128 << 10);
        if let Some(cut) = cut {
            rows.push(measure(
                &img,
                &dev,
                format!("truncate to 0, {label}"),
                items,
                || {
                    block_on(async {
                        cut.truncate(0).await?;
                        cut.fsync(false).await
                    })
                },
            ));
        }
        // The last reference goes with the handle; the inode is reclaimed
        // by the next operation, and the fsync commits it.
        if gone.is_some() {
            drop(gone);
            let poke = format!("after-{index}");
            rows.push(measure(
                &img,
                &dev,
                format!("unlink, {label}"),
                items,
                || {
                    block_on(async {
                        top.unlink(&gone_name).await?;
                        top.create(&poke).await?;
                        // Each operation (an fsync among them) takes on a
                        // bounded part of the eviction: 64 steps.
                        for _ in 0..items.div_ceil(STEP * 64) + 1 {
                            top.fsync(false).await?;
                        }
                        Ok(())
                    })
                },
            ));
        }
    }
    // fallocate: a punch over files of 1,000 and of 100,000 single-page
    // extents, a preallocation of as many holes, a zero-range over as many
    // extents (Linux `btrfs_punch_hole` / `btrfs_replace_file_extents`,
    // `btrfs_prealloc_file_range`, `btrfs_zero_range`).
    let falloc_first = rows.len();
    // (row, file, offset, length, size it must keep, what the range must read)
    let mut checks: Vec<RangeCheck> = Vec::new();
    for (index, count) in [1000usize, 100_000 * scale / 3000].into_iter().enumerate() {
        if build_error.is_some() {
            break;
        }
        let made = (|| -> Result<_, String> {
            let punched = build(&top, &format!("punch-{index}"), count, PAGE)?;
            let filled = build_strided(&top, &format!("prealloc-{index}"), count)?;
            let zeroed = build(&top, &format!("zero-{index}"), count, PAGE)?;
            block_on(top.fsync(false)).map_err(err("fsync"))?;
            Ok((punched, filled, zeroed))
        })();
        let (punched, filled, zeroed) = match made {
            Ok(files) => files,
            Err(e) => {
                build_error = Some(format!("building the fallocate files of {count}: {e}"));
                break;
            }
        };
        let size = (count * PAGE) as u64;
        let mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
        rows.push(measure(
            &img,
            &dev,
            format!("punch, {count} extents"),
            count,
            || {
                block_on(async {
                    punched.fallocate(mode, 0, size).await?;
                    punched.fsync(false).await
                })
            },
        ));
        checks.push((rows.len() - 1, punched, 0, size, size));
        // `count` holes between `count` extents, and one more page past EOF.
        let span = (2 * count * PAGE) as u64;
        rows.push(measure(
            &img,
            &dev,
            format!("preallocate, {count} holes"),
            count,
            || {
                block_on(async {
                    filled.fallocate(0, 0, span).await?;
                    filled.fsync(false).await
                })
            },
        ));
        checks.push((
            rows.len() - 1,
            filled,
            span - PAGE as u64,
            PAGE as u64,
            span,
        ));
        rows.push(measure(
            &img,
            &dev,
            format!("zero range, {count} extents"),
            count,
            || {
                block_on(async {
                    zeroed.fallocate(FALLOC_FL_ZERO_RANGE, 0, size).await?;
                    zeroed.fsync(false).await
                })
            },
        ));
        checks.push((rows.len() - 1, zeroed, 0, size, size));
    }
    // What each file must hold now.
    let mut content_error = None;
    for (row, file, at, len, size) in &checks {
        if rows[*row].result.is_err() {
            continue;
        }
        let stat = block_on(file.stat_async()).map_err(err("stat"))?;
        if stat.size != *size {
            content_error = Some(format!(
                "{}: the file is {} bytes, not {size}",
                rows[*row].what, stat.size
            ));
            break;
        }
        if !reads_zero(file, *at, *len)? {
            content_error = Some(format!(
                "{}: the range does not read as zeros",
                rows[*row].what
            ));
            break;
        }
    }
    drop(checks);
    drop(top);
    drop(fs);
    drop(dev);
    narf::reset();

    let node_mib = f64::from(nodesize) / 1048576.0;
    let lines: Vec<String> = rows
        .iter()
        .map(|r| {
            format!(
                "    {}: {}; METADATA chunks {} -> {}; most one step reserved {} tree blocks ({:.1} MiB); {:.2} s; {} steps, per step {:.1} device writes, {:.1} tree nodes written; {} commits",
                r.what,
                match &r.result {
                    Ok(()) => "ok".to_string(),
                    Err(e) => format!("FAILED ({e:?})"),
                },
                r.chunks.0,
                r.chunks.1,
                r.reserved,
                r.reserved as f64 * node_mib,
                r.seconds,
                r.steps,
                r.device_writes as f64 / r.steps as f64,
                r.tree_written as f64 / r.steps as f64,
                r.commits,
            )
        })
        .collect();
    let report = lines.join("\n");
    if let Some(e) = build_error.or(content_error) {
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
    // The same for each fallocate mode: 1,000 extents, then 100,000.
    for kind in 0..3 {
        let (small, large) = (&rows[falloc_first + kind], &rows[falloc_first + 3 + kind]);
        if large.reserved > 2 * small.reserved.max(1) {
            return Err(format!(
                "{report}\n{}: the reservation of a step depends on the size of the range",
                large.what
            ));
        }
    }

    linux::check(&img, false)?;
    linux::check(&img, true)?;
    let subvols = linux::subvolumes(&img)?;
    let at = linux::subvol_id(&subvols, "@").ok_or("no @ subvolume")?;
    let orphans = orphan_items(&img, at)?;
    if orphans != 0 {
        return Err(format!("{report}\n{orphans} orphan item(s) left behind"));
    }
    let (_dev, fs) = mount()?;
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
    /// `fallocate(mode, off, len)`.
    Falloc {
        mode: u32,
        off: u64,
        len: u64,
    },
}

/// The file a crash case starts from.
#[derive(Clone, Copy)]
struct Shape {
    /// Single-page extents, from offset 0 — a page apart when `strided`, a
    /// hole after each.
    pages: usize,
    /// 128 KiB extents after them.
    big: usize,
    strided: bool,
}

const fn shape(pages: usize, big: usize) -> Shape {
    Shape {
        pages,
        big,
        strided: false,
    }
}

/// One crash case.
struct Case {
    name: &'static str,
    shape: Shape,
    cut: Cut,
    /// The operation must commit exactly once.
    single: bool,
    /// For an `fallocate`: where each step but the last leaves off, worked
    /// out from the file's layout (punch and zero-range: the start of every
    /// 17th extent item from the range's first whole sector; preallocation:
    /// the end of every 16th extent laid down). The driver must report the
    /// same marks, and the states they make are the ones allowed.
    marks: Vec<u64>,
    /// Whether `marks` must match exactly. Where free space decides how
    /// many extents a step can lay down, the driver's marks are taken
    /// instead, as long as they rise through the range.
    exact_marks: bool,
    features: &'static str,
    image: u64,
}

/// One crash case: the file `shape` describes, cut as `cut` says with every
/// step committed, and the write stream replayed with crashes.
fn crash_case(args: &Args, case: &Case) -> Result<String, String> {
    let Case {
        name,
        shape,
        cut,
        single,
        ..
    } = *case;
    let (pages, big) = (shape.pages, shape.big);
    let dir = args
        .workdir
        .join(format!("release-crash-{}", name.replace([' ', ','], "-")));
    let img = mkfs(
        &dir,
        case.image,
        0x100 + name.len() as u64 * 7 + pages as u64,
        case.features,
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
        let file = if shape.strided {
            build_strided(&top, "victim", pages)?
        } else {
            build(&top, "victim", pages, PAGE)?
        };
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
            Cut::Falloc { mode, off, len } => {
                let file = top.lookup_async("victim").await?;
                let _ = stats::take_step_marks();
                file.fallocate(mode, off, len).await?;
                file.fsync(false).await
            }
        }
    });
    narf_drivers_fs_btrfs::write::set_dealloc_step_sync(false);
    done.map_err(err("the operation"))?;
    let mut marks = case.marks.clone();
    if let Cut::Falloc { off, len, .. } = cut {
        let reported = stats::take_step_marks();
        let rises = reported.windows(2).all(|w| w[0] < w[1])
            && reported.iter().all(|&m| m > off && m < off + len);
        if case.exact_marks && reported != case.marks {
            return Err(format!(
                "{name}: the steps left off at {reported:?}, not at {:?}",
                case.marks
            ));
        }
        if !case.exact_marks && (reported.is_empty() || !rises) {
            return Err(format!("{name}: the steps left off at {reported:?}"));
        }
        marks = reported;
    }
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
    if !single && gens.len() < 2 {
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
        Cut::Falloc { mode, off, len } => {
            let Some(Flat::File { data, .. }) = before.get("crash/victim") else {
                return Err(format!("{name}: no victim in the model"));
            };
            let old = data.clone();
            let end = off + len;
            for &mark in &marks {
                let mut bytes = (*old).clone();
                if mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE) != 0 {
                    // Zero up to the mark, and the partial sector at the end
                    // of the range, which the first step zeroes.
                    let n = bytes.len();
                    let clip = |x: u64| (x as usize).min(n);
                    let (a, b) = (clip(off), clip(mark.min(end)));
                    bytes[a..b.max(a)].fill(0);
                    let (c, d) = (clip((end - end % PAGE as u64).max(off)), clip(end));
                    bytes[c..d.max(c)].fill(0);
                } else if mode & FALLOC_FL_KEEP_SIZE == 0 {
                    let size = mark.min(end) as usize;
                    if size > bytes.len() {
                        bytes.resize(size, 0);
                    }
                }
                let mut state = before.clone();
                if let Some(Flat::File { data, .. }) = state.get_mut("crash/victim") {
                    *data = Arc::new(bytes);
                }
                states.push(vec![state]);
            }
        }
    }
    let commits: Vec<CommitRec> = gens
        .iter()
        .map(|&gen| CommitRec {
            gen,
            candidates: states.clone(),
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
            default_profile: false,
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
/// check the image clean with no orphan item and nothing of the directory.
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

/// A read-only snapshot NARF takes and never touches, judged by Linux.
///
/// Snapshot creation is refused under `narf.disks=root-rw`, so this runs on
/// a host image mounted under the default profile
/// ([`narf::mount_default`]). With every commit's writes recorded, the
/// stream is cut at every flush around the snapshot's transaction: each
/// image must pass `btrfs check` (which reads the snapshot's tree through
/// its ROOT_ITEM) and remount at the state before or after. Then the final
/// image: `btrfs check`, also `--check-data-csum`, and `btrfs restore` of
/// the snapshot alone, whose files must be the source's at the time of the
/// snapshot, byte for byte, though the source changed afterwards.
fn readonly_snapshot(args: &Args) -> Result<String, String> {
    let dir = args.workdir.join("release-snapshot");
    let img = mkfs(&dir, 512 << 20, 0x5a9, FEATURES)?;
    let (fsid, nodesize, _) = dev::image_identity(&img);
    // Files to snapshot, committed; the image the replay starts from.
    {
        let dev = Arc::new(RecDev::open(&img, 512, fsid, nodesize));
        let fs = narf::mount_default(dev, &fsid, "@")?;
        let top = block_on(fs.root().mkdir("data")).map_err(err("mkdir"))?;
        drop(build(&top, "pages", 60, PAGE)?);
        drop(build(&top, "big", 3, 128 << 10)?);
        block_on(fs.root().fsync(false)).map_err(err("fsync"))?;
        drop(top);
        drop(fs);
        narf::reset();
    }
    let base = dir.join("base.img");
    linux::clone_file(&img, &base);
    let base_gen = dev::image_identity(&base).2;

    let dev = Arc::new(RecDev::open(&img, 512, fsid, nodesize));
    dev.set_recording(true);
    let fs = narf::mount_default(dev.clone(), &fsid, "@")?;
    let root = fs.root();
    let before = narf::walk(&root)?.0;
    block_on(async {
        root.snapshot_async(root.clone(), "ro-snap", true).await?;
        root.fsync(false).await
    })
    .map_err(err("snapshot"))?;
    let after = narf::walk(&root)?.0;
    let snap_gens: Vec<u64> = dev
        .sb_gens()
        .into_iter()
        .filter(|&g| g > base_gen)
        .collect();
    dev.set_recording(false);
    let log = dev.take_log();
    // Change the source afterwards: the snapshot must not follow.
    let data = block_on(root.lookup_dir_async("data")).map_err(err("lookup"))?;
    let pages = block_on(data.lookup_async("pages")).map_err(err("lookup"))?;
    block_on(async {
        pages.write(0, &vec![0xeeu8; 3 * PAGE]).await?;
        pages.truncate((30 * PAGE) as u64).await?;
        data.unlink("big").await?;
        root.fsync(false).await
    })
    .map_err(err("changing the source"))?;
    drop(pages);
    drop(data);
    drop(root);
    drop(fs);
    narf::reset();

    let commits: Vec<CommitRec> = snap_gens
        .iter()
        .map(|&gen| CommitRec {
            gen,
            candidates: vec![vec![before.clone()], vec![after.clone()]],
        })
        .collect();
    let rep = crash::run(
        &crash::Input {
            base: &base,
            log: &log,
            commits: &commits,
            base_gen,
            base_state: vec![before.clone()],
            lba: 512,
            fsid,
            nodesize,
            root_subvol: "@",
            others: &[],
            default_profile: true,
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
            "read-only snapshot: {} of {} crash cuts failed:\n{}",
            rep.failures.len(),
            rep.cuts,
            rep.failures.join("\n")
        ));
    }
    linux::check(&img, false).map_err(|e| format!("read-only snapshot: {e}"))?;
    linux::check(&img, true).map_err(|e| format!("read-only snapshot: {e}"))?;
    // Linux reads the snapshot: restore it and compare with the source as
    // it was when the snapshot was taken.
    let subvols = linux::subvolumes(&img)?;
    let snap_id = subvols
        .iter()
        .find(|sub| sub.name == "ro-snap")
        .map(|sub| sub.id)
        .ok_or("read-only snapshot: no subvolume ro-snap")?;
    let restored = linux::restore(&img, snap_id, &dir.join("restored"))
        .map_err(|e| format!("read-only snapshot: btrfs restore of the snapshot: {e}"))?;
    let mut compared = 0usize;
    for (path, entry) in &before {
        let Flat::File { data, .. } = entry else {
            continue;
        };
        match restored.get(path) {
            Some(Flat::File { data: got, .. }) if got == data => compared += 1,
            _ => {
                return Err(format!(
                "read-only snapshot: {path} as restored differs from the source at snapshot time"
            ))
            }
        }
    }
    if compared < 3 {
        return Err(format!(
            "read-only snapshot: only {compared} files compared"
        ));
    }
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(format!(
        "    read-only snapshot (default profile): {} commits, {} cuts, every image checks clean and remounts before or after; btrfs check (also --check-data-csum) clean, btrfs restore of the snapshot matches the source at snapshot time ({compared} files) after the source changed",
        snap_gens.len(),
        rep.cuts
    ))
}

/// Every extent of `img` in a block group of its own type: tree blocks
/// (`METADATA_ITEM`, or an `EXTENT_ITEM` flagged `TREE_BLOCK`) in METADATA
/// or SYSTEM groups, data in DATA groups; a mixed group takes both. From
/// Linux's own dump of the extent tree. Returns how many were checked.
fn extents_in_their_groups(img: &Path) -> Result<usize, String> {
    let out = linux::btrfs()
        .args(["inspect-internal", "dump-tree", "-t", "extent"])
        .arg(img)
        .output()
        .map_err(|e| format!("dump-tree: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let lines: Vec<&str> = text.lines().collect();
    // (start, end, flags line), then (bytenr, is tree block).
    let mut groups: Vec<(u64, u64, String)> = Vec::new();
    let mut extents: Vec<(u64, bool)> = Vec::new();
    let num = |w: &str| {
        w.trim_matches(|c: char| !c.is_ascii_digit())
            .parse::<u64>()
            .ok()
    };
    for (i, line) in lines.iter().enumerate() {
        let Some(at) = line.find("key (") else {
            continue;
        };
        let words: Vec<&str> = line[at + 5..].split_whitespace().collect();
        if words.len() < 3 {
            continue;
        }
        let (Some(start), Some(third)) = (num(words[0]), num(words[2])) else {
            continue;
        };
        let next = lines.get(i + 1).copied().unwrap_or("");
        match words[1] {
            "BLOCK_GROUP_ITEM" => groups.push((start, start + third, next.to_string())),
            "METADATA_ITEM" => extents.push((start, true)),
            "EXTENT_ITEM" => extents.push((start, next.contains("TREE_BLOCK"))),
            _ => {}
        }
    }
    if groups.is_empty() || extents.is_empty() {
        return Err("no block groups or extents in the dump".into());
    }
    for &(bytenr, tree) in &extents {
        let Some((_, _, flags)) = groups.iter().find(|(s, e, _)| bytenr >= *s && bytenr < *e)
        else {
            return Err(format!("extent {bytenr} lies in no block group"));
        };
        let fits = if tree {
            flags.contains("METADATA") || flags.contains("SYSTEM")
        } else {
            flags.contains("DATA")
        };
        if !fits {
            return Err(format!(
                "{} at {bytenr} lies in a block group of the wrong type ({})",
                if tree {
                    "a tree block"
                } else {
                    "a data extent"
                },
                flags.trim()
            ));
        }
    }
    Ok(extents.len())
}

/// A filesystem without a free-space tree — mixed block groups, the only
/// shape of one the read-write gate lets NARF write — goes through the bump
/// allocator (the default profile; `root-rw` requires the tree). That
/// allocator answered "infinitely much free" to the batch's reservation
/// check, so a batch took operations until its commit found no room and
/// lost all of them. Here files are created, written and unlinked until the
/// filesystem says no: every operation must succeed or be refused with
/// ENOSPC, every commit must land, the filesystem stay writable,
/// `btrfs check` pass, and every extent lie in a block group of its type.
fn no_free_space_tree(args: &Args) -> Result<String, String> {
    let dir = args.workdir.join("release-no-fst");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let rootdir = dir.join("rootdir");
    std::fs::create_dir_all(rootdir.join("@")).unwrap();
    std::fs::create_dir_all(rootdir.join("@home")).unwrap();
    let img = dir.join("release.img");
    fixture::mkfs(
        &img,
        &rootdir,
        &fixture::MkfsSpec {
            uuid: "c4c405ee-0000-4a11-9e57-4e1e000000f5",
            size: 128 << 20,
            // Mixed block groups need nodesize = sectorsize.
            nodesize: 4096,
            csum: "crc32c",
            features: "mixed-bg,no-holes,^free-space-tree,^block-group-tree",
        },
    )?;
    let (fsid, nodesize, _) = dev::image_identity(&img);
    let dev = Arc::new(RecDev::open(&img, 512, fsid, nodesize));
    let fs = narf::mount_default(dev, &fsid, "@")?;
    let top = block_on(fs.root().mkdir("churn")).map_err(err("mkdir"))?;
    let mut done = 0usize;
    let mut refused = None;
    for i in 0..4000usize {
        let name = format!("f{i}");
        let r: Result<(), FsError> = block_on(async {
            let file = top.create(&name).await?;
            file.write(0, &noise(i as u64, 3000 + (i % 7) * 9000))
                .await?;
            drop(file);
            // Every third file stays: the filesystem fills.
            if i % 3 != 0 {
                top.unlink(&name).await?;
            }
            if i % 50 == 49 {
                top.fsync(false).await?;
            }
            Ok(())
        });
        match r {
            Ok(()) => done += 1,
            Err(error) => {
                refused = Some(error);
                break;
            }
        }
    }
    let synced = block_on(top.fsync(false));
    let writable = !fs.always_read_only();
    drop(top);
    drop(fs);
    narf::reset();
    if let Some(error) = &refused {
        if *error != FsError::NoSpace {
            return Err(format!(
                "no free-space tree: operation {done} failed with {error:?}, not ENOSPC"
            ));
        }
    }
    if synced.is_err() || !writable {
        return Err(format!(
            "no free-space tree: the last commit {synced:?}, writable {writable}: operations reported successful were lost"
        ));
    }
    linux::check(&img, false).map_err(|e| format!("no free-space tree: {e}"))?;
    let checked = extents_in_their_groups(&img).map_err(|e| format!("no free-space tree: {e}"))?;
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(format!(
        "    no free-space tree, mixed groups (bump allocator): {done} files before {}; every commit landed, btrfs check clean, {checked} extents each in a block group of its type",
        match refused {
            Some(_) => "ENOSPC",
            None => "the end of the run",
        }
    ))
}

/// Two handles of one file, overlapping writes through either, and a read
/// through either after every operation, against a byte model: unaligned
/// writes of 1 byte to 70 KiB, truncates up and down, fsyncs, and a handle
/// dropped and reopened now and then. The soak saw reads return a range's
/// previous bytes after a store; here every read must return the model's.
fn two_handles(args: &Args) -> Result<String, String> {
    let dir = args.workdir.join("release-two-handles");
    let img = mkfs(&dir, 512 << 20, 0x2b, FEATURES)?;
    let (fsid, nodesize, _) = dev::image_identity(&img);
    let dev = Arc::new(RecDev::open(&img, 512, fsid, nodesize));
    narf::register_root(dev, &fsid)?;
    let fs = narf::mount_root_rw(&fsid, "@", &[])?.remove(0);
    let root = fs.root();
    let open = || block_on(root.lookup_async("shared")).map_err(err("lookup"));
    drop(block_on(root.create("shared")).map_err(err("create"))?);
    let mut handles = [open()?, open()?];
    let mut model: Vec<u8> = Vec::new();
    let mut rng = args.seed ^ 0x2b2b_7777;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    const SPAN: u64 = 1 << 20;
    let ops = args.ops.max(300) * 4;
    let mut reads = 0usize;
    for op in 0..ops {
        let h = (next() % 2) as usize;
        let kind = next() % 20;
        let at = next() % SPAN;
        let len = 1 + next() % (70 << 10);
        let what: Result<(), String> = block_on(async {
            match kind {
                0..=11 => {
                    let body = noise(op as u64 ^ at, len as usize);
                    let mut done = 0usize;
                    while done < body.len() {
                        let n = handles[h]
                            .write(at + done as u64, &body[done..])
                            .await
                            .map_err(err("write"))?;
                        done += n;
                    }
                    let end = (at + len) as usize;
                    if model.len() < end {
                        model.resize(end, 0);
                    }
                    model[at as usize..end].copy_from_slice(&body);
                }
                12..=13 => {
                    let size = next() % SPAN;
                    handles[h].truncate(size).await.map_err(err("truncate"))?;
                    model.resize(size as usize, 0);
                }
                14 => handles[h].fsync(false).await.map_err(err("fsync"))?,
                15 => {
                    // Drop a handle and look the file up again.
                    handles[h] = root.lookup_async("shared").await.map_err(err("lookup"))?;
                }
                _ => {}
            }
            Ok(())
        });
        what.map_err(|e| format!("two handles: op {op}: {e}"))?;
        // A read through either handle of a range around the last write.
        for (reader, handle) in handles.iter().enumerate() {
            let from = at.saturating_sub(next() % 8192);
            let want_len = (len + 16384).min(SPAN) as usize;
            let mut got = vec![0u8; want_len];
            let n = block_on(handle.read(from, &mut got)).map_err(err("read"))?;
            let want: &[u8] = model.get(from as usize..).unwrap_or(&[]);
            let want = &want[..want.len().min(want_len)];
            if n != want.len() || got[..n] != *want {
                let first = got[..n]
                    .iter()
                    .zip(want)
                    .position(|(g, w)| g != w)
                    .map_or(n.min(want.len()), |i| i);
                return Err(format!(
                    "two handles: op {op} (kind {kind}, handle {h}, at {at}, len {len}): read through handle {reader} of {want_len} at {from} returned {n} bytes, {} expected; first difference at file offset {}",
                    want.len(),
                    from + first as u64
                ));
            }
            reads += 1;
        }
    }
    drop(handles);
    drop(root);
    drop(fs);
    narf::reset();
    linux::check(&img, false).map_err(|e| format!("two handles: {e}"))?;
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(format!(
        "    two handles of one file: {ops} writes/truncates/fsyncs/reopens, {reads} reads each equal to the model; btrfs check clean"
    ))
}

/// One of the operations [`poll_all`] runs side by side.
type Job<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + 'a>>;

/// Poll `futures` round-robin until every one is done, calling `done(i)` as
/// future `i` completes: on the host nothing parks, so a future that is
/// pending is waiting for a lock another of them holds, or yielded between
/// two steps of a long operation.
fn poll_all(
    mut futures: Vec<Job<'_>>,
    mut done: impl FnMut(usize) -> Result<(), String>,
) -> Result<(), String> {
    use std::task::{Context, Poll, Waker};
    let mut cx = Context::from_waker(Waker::noop());
    let mut finished = vec![false; futures.len()];
    for _ in 0..1u64 << 26 {
        let mut all = true;
        for (i, future) in futures.iter_mut().enumerate() {
            if finished[i] {
                continue;
            }
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(result) => {
                    result?;
                    finished[i] = true;
                    done(i)?;
                }
                Poll::Pending => all = false,
            }
        }
        if all {
            return Ok(());
        }
    }
    Err("futures still pending after 2^26 rounds".into())
}

/// Concurrent `fsync`s beside a long truncate: a stepwise truncate of a
/// file of 96 one-page extents, `fsync`s of two files written just before,
/// a write and `fsync` of a third, and an `fsync` of a fourth with nothing
/// new, all polled round-robin so their commits interleave with the
/// truncate's steps and share commits with each other.
///
/// Every crash cut of the recorded stream must check clean and remount at
/// a state some commit could hold, and each `fsync` must keep its promise:
/// the image as it stands when the call returns, read by `btrfs restore`,
/// holds the file's new contents.
fn group_commit(args: &Args) -> Result<String, String> {
    const FILES: usize = 4;
    const PAGES: usize = 96;
    const BODY: usize = 64 << 10;
    let dir = args.workdir.join("release-group-commit");
    let img = mkfs(&dir, 512 << 20, 0x6c, FEATURES)?;
    let (fsid, nodesize, _) = dev::image_identity(&img);
    let open = |recording: bool| -> Result<(Arc<RecDev>, Arc<dyn FsInstance>), String> {
        let dev = Arc::new(RecDev::open(&img, 512, fsid, nodesize));
        dev.set_recording(recording);
        narf::register_root(dev.clone(), &fsid)?;
        Ok((dev, narf::mount_root_rw(&fsid, "@", &[])?.remove(0)))
    };
    let name = |i: usize| format!("f{i}");
    {
        let (_dev, fs) = open(false)?;
        let top = block_on(fs.root().mkdir("g")).map_err(err("mkdir"))?;
        for i in 0..FILES {
            let file = block_on(top.create(&name(i))).map_err(err("create"))?;
            block_on(write_all(&file, 0, &noise(0x900 + i as u64, BODY)))?;
        }
        drop(build(&top, "victim", PAGES, PAGE)?);
        block_on(top.fsync(false)).map_err(err("fsync"))?;
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
    let top = block_on(root.lookup_dir_async("g")).map_err(err("lookup"))?;
    let files: Vec<Arc<dyn FileOps>> = (0..FILES)
        .map(|i| block_on(top.lookup_async(&name(i))).map_err(err("lookup")))
        .collect::<Result<_, _>>()?;
    let victim = block_on(top.lookup_async("victim")).map_err(err("lookup"))?;
    let new: Vec<Vec<u8>> = (0..FILES).map(|i| noise(0xa00 + i as u64, BODY)).collect();
    for (file, body) in files.iter().zip(&new).take(2) {
        block_on(write_all(file, 0, body))?;
    }
    // What each future, once done, promises is durable: (file, contents).
    let promises: Vec<Option<(usize, Vec<u8>)>> = vec![
        None,
        Some((0, new[0].clone())),
        Some((1, new[1].clone())),
        Some((2, new[2].clone())),
        Some((3, noise(0x903, BODY))),
    ];
    let futures: Vec<Job<'_>> = vec![
        Box::pin(async { victim.truncate(0).await.map_err(err("truncate")) }),
        Box::pin(async { files[0].fsync(false).await.map_err(err("fsync")) }),
        Box::pin(async { files[1].fsync(true).await.map_err(err("fdatasync")) }),
        Box::pin(async {
            write_all(&files[2], 0, &new[2]).await?;
            files[2].fsync(false).await.map_err(err("fsync"))
        }),
        Box::pin(async { files[3].fsync(false).await.map_err(err("fsync")) }),
    ];
    let mut snapshots: Vec<(PathBuf, usize, Vec<u8>)> = Vec::new();
    poll_all(futures, |i| {
        if let Some((file, data)) = &promises[i] {
            let snap = dir.join(format!("fsync{i}.img"));
            linux::clone_file(&img, &snap);
            snapshots.push((snap, *file, data.clone()));
        }
        Ok(())
    })?;
    let after = narf::walk(&root)?.0;
    drop(files);
    drop(victim);
    drop(top);
    drop(root);
    drop(fs);
    narf::reset();
    dev.set_recording(false);
    let log = dev.take_log();
    let gens: std::collections::BTreeSet<u64> = dev
        .sb_gens()
        .into_iter()
        .filter(|&gen| gen > base_gen)
        .collect();
    drop(dev);

    // Each fsync's promise, on the image as it stood when the call returned.
    for (snap, file, data) in &snapshots {
        let subs = linux::subvolumes(snap)?;
        let id = linux::subvol_id(&subs, "@").ok_or("group commit: no @ subvolume")?;
        let tree = linux::restore(snap, id, &snap.with_extension("restore"))?;
        match tree.get(&format!("g/{}", name(*file))) {
            Some(Flat::File { data: got, .. }) if **got == *data => {}
            _ => {
                return Err(format!(
                    "group commit: {} did not hold f{file}'s fsynced contents",
                    snap.display()
                ))
            }
        }
    }

    // Every state a crash may leave: f0 and f1 rewritten (no commit came
    // between their writes and the fsyncs), f2 old or new, and the victim
    // whole, cut at each step's extent boundary, or empty.
    let Some(Flat::File { data: old, .. }) = before.get("g/victim") else {
        return Err("group commit: no victim in the model".into());
    };
    let old = old.clone();
    let mut cuts: Vec<usize> = vec![old.len(), 0];
    let mut left = PAGES;
    while left > STEP {
        left -= STEP;
        cuts.push(left * PAGE);
    }
    let set = |state: &mut crate::model::FlatTree, path: &str, bytes: Vec<u8>| {
        if let Some(Flat::File { data, .. }) = state.get_mut(path) {
            *data = Arc::new(bytes);
        }
    };
    let mut states = vec![vec![before.clone()], vec![after]];
    for &cut in &cuts {
        for f2 in [false, true] {
            let mut state = before.clone();
            set(&mut state, "g/f0", new[0].clone());
            set(&mut state, "g/f1", new[1].clone());
            if f2 {
                set(&mut state, "g/f2", new[2].clone());
            }
            set(&mut state, "g/victim", old[..cut].to_vec());
            states.push(vec![state]);
        }
    }
    let commits: Vec<CommitRec> = gens
        .iter()
        .map(|&gen| CommitRec {
            gen,
            candidates: states.clone(),
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
            default_profile: false,
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
            "group commit: {} of {} crash cuts failed (images kept in {}):\n{}",
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
        "    group commit: {} fsyncs beside a stepwise truncate kept their promises in {} commits; {} cuts over {} flushes check clean and remount at one of {} states",
        snapshots.len(),
        gens.len(),
        rep.cuts,
        rep.flush_boundaries,
        states.len(),
    ))
}

pub fn run(args: &Args) -> Result<String, String> {
    let t0 = Instant::now();
    let mut lines = vec![reservation(args)?];
    let page = PAGE as u64;
    let step = STEP as u64;
    let case = |name, shape, cut, single| Case {
        name,
        shape,
        cut,
        single,
        marks: Vec::new(),
        exact_marks: true,
        features: FEATURES,
        image: 512 << 20,
    };
    let punch = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
    // A punch or zero-range of `[10 pages + 100, 100 pages)` over single-page
    // extents: whole sectors from page 11, a step every 16 extent items.
    let (cut_from, cut_len) = (10 * page + 100, 90 * page - 100);
    let cut_marks: Vec<u64> = (1..)
        .map(|k| 11 * page + k * step * page)
        .take_while(|&mark| mark < 100 * page)
        .collect();
    let cases = [
        // Large: many steps, each its own commit.
        case(
            "truncate to nothing",
            shape(120, 4),
            Cut::Truncate(0),
            false,
        ),
        case(
            "truncate to an extent boundary",
            shape(120, 4),
            Cut::Truncate(40 * page),
            false,
        ),
        case(
            "truncate into an extent",
            shape(120, 4),
            Cut::Truncate(40 * page + 1234),
            false,
        ),
        case("unlink", shape(120, 4), Cut::Unlink, false),
        Case {
            features: FEATURES_HOLE_ITEMS,
            ..case(
                "unlink, explicit hole items",
                shape(120, 4),
                Cut::Unlink,
                false,
            )
        },
        Case {
            marks: cut_marks.clone(),
            ..case(
                "punch",
                shape(120, 0),
                Cut::Falloc {
                    mode: punch,
                    off: cut_from,
                    len: cut_len,
                },
                false,
            )
        },
        Case {
            marks: cut_marks.clone(),
            features: FEATURES_HOLE_ITEMS,
            ..case(
                "punch, explicit hole items",
                shape(120, 0),
                Cut::Falloc {
                    mode: punch,
                    off: cut_from,
                    len: cut_len,
                },
                false,
            )
        },
        Case {
            marks: cut_marks,
            ..case(
                "zero range",
                shape(120, 0),
                Cut::Falloc {
                    mode: FALLOC_FL_ZERO_RANGE,
                    off: cut_from,
                    len: cut_len,
                },
                false,
            )
        },
        // 40 holes a page each, and one page past EOF: the 16th and 32nd
        // holes end where a step does.
        Case {
            marks: vec![32 * page, 64 * page],
            ..case(
                "preallocate holes",
                Shape {
                    pages: 40,
                    big: 0,
                    strided: true,
                },
                Cut::Falloc {
                    mode: 0,
                    off: 0,
                    len: 80 * page,
                },
                false,
            )
        },
        // 17 extents of 8 MiB past EOF (more where free space is in
        // pieces): the size moves with every step but the last.
        Case {
            marks: vec![8 * page + 128 * (1 << 20)],
            exact_marks: false,
            image: 2 << 30,
            ..case(
                "preallocate past EOF",
                shape(8, 0),
                Cut::Falloc {
                    mode: 0,
                    off: 8 * page,
                    len: 136 << 20,
                },
                false,
            )
        },
        // Within a step: one transaction, whatever the cut.
        case(
            "small truncate to nothing",
            shape(12, 0),
            Cut::Truncate(0),
            true,
        ),
        case(
            "small truncate into an extent",
            shape(12, 0),
            Cut::Truncate(5 * page + 700),
            true,
        ),
        case(
            "shrinking the last extent",
            shape(0, 2),
            Cut::Truncate(200_000),
            true,
        ),
        case(
            "small punch",
            shape(12, 0),
            Cut::Falloc {
                mode: punch,
                off: 2 * page + 5,
                len: 6 * page,
            },
            true,
        ),
        case(
            "small zero range",
            shape(12, 0),
            Cut::Falloc {
                mode: FALLOC_FL_ZERO_RANGE,
                off: 2 * page + 5,
                len: 6 * page,
            },
            true,
        ),
        case(
            "small preallocation",
            shape(4, 0),
            Cut::Falloc {
                mode: FALLOC_FL_KEEP_SIZE,
                off: 4 * page,
                len: 10 * page,
            },
            true,
        ),
    ];
    for case in &cases {
        lines.push(crash_case(args, case)?);
    }
    lines.push(dir_orphan(args)?);
    lines.push(readonly_snapshot(args)?);
    lines.push(no_free_space_tree(args)?);
    lines.push(two_handles(args)?);
    lines.push(group_commit(args)?);
    Ok(format!(
        "release: OK\n{}\n    btrfs check clean (also --check-data-csum), no orphan item left, files empty or gone after a remount; {:.0?}",
        lines.join("\n"),
        t0.elapsed()
    ))
}
