//! The `scale` scenario: what a commit costs on a filesystem shaped like an
//! installed root.
//!
//! The other scenarios run on images of a gigabyte or two with a handful of
//! block groups, where every tree is one or two levels and "the whole tree"
//! and "the part a commit touches" are nearly the same thing. An installed
//! root is hundreds of mostly-full 1 GiB DATA block groups with free space
//! in small pieces all over them, and three-level extent and free-space
//! trees. This scenario builds that shape on a sparse image without writing
//! the data:
//!
//!  * per DATA block group, pairs of files take turns preallocating 4 KiB
//!    extents (`fallocate`, nothing written), so their extents alternate on
//!    disk, and a ballast file preallocates the rest of the group. When the
//!    existing groups are full the next `fallocate` allocates a chunk at
//!    reservation time, as on a root that grows;
//!  * one file of every pair is then unlinked, leaving a single-sector
//!    `FREE_SPACE_EXTENT` between two used sectors for each of its extents:
//!    hundreds of thousands of them, spread over every group;
//!  * a share of the kept files are written instead of preallocated, so the
//!    checksum tree is more than a leaf.
//!
//! A desktop-like workload then runs in small transactions — a save-file
//! loop (create a temporary file, write, fsync, rename over the old name),
//! log appends with fsync, and bursts of creates and unlinks closed by one
//! directory fsync — and every commit is recorded: nodes visited and written
//! per tree, fixed-point rounds, blocks allocated beyond the batch's
//! reservation, and wall time. The counts are deterministic; the times are
//! indicative only. The workload runs once without the free-space view audit
//! (which re-reads the whole tree and would be counted) and once with it, so
//! every commit of the second pass is compared with the tree it wrote.
//!
//! `btrfs check`, with and without data checksums, judges the result, and a
//! NARF remount reads every workload file back.
//!
//! Not reproduced: the checksum tree of a root holding hundreds of gigabytes
//! of written data (that needs the data), snapshots, and compression of the
//! ballast.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use narf_drivers_fs_btrfs::stats::{self, Totals};
use narf_filesystem::{DirOps, FileOps, FsInstance};

use crate::dev::RecDev;
use crate::host::block_on;
use crate::{dev, fixture, linux, narf, Args};

/// The shape to build.
#[derive(Clone, Copy, Debug)]
struct Shape {
    /// DATA block groups to fill (1 GiB each).
    groups: usize,
    /// Single-sector holes to leave in each.
    holes_per_group: usize,
    /// Of the kept 4 KiB extents of each group, how many are written (and so
    /// checksummed) instead of preallocated.
    written_per_group: usize,
}

/// 4 KiB extents per fragment file: an operation on a file reads all of its
/// extent items, so the files stay small.
const EXTENTS_PER_FILE: usize = 64;
const SECTOR: u64 = 4096;
const GIB: u64 = 1 << 30;

fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = (seed + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn err<E: std::fmt::Debug>(what: &str) -> impl Fn(E) -> String + '_ {
    move |e| format!("{what}: {e:?}")
}

async fn write_all(file: &Arc<dyn FileOps>, mut off: u64, mut body: &[u8]) -> Result<(), String> {
    while !body.is_empty() {
        let n = file.write(off, body).await.map_err(err("write"))?;
        if n == 0 {
            return Err("write made no progress".into());
        }
        off += n as u64;
        body = &body[n..];
    }
    Ok(())
}

/// What `btrfs inspect-internal tree-stats` says of one tree.
#[derive(Clone, Copy, Debug, Default)]
struct TreeShape {
    levels: u64,
    blocks: u64,
}

fn tree_shape(img: &Path, tree: &str, nodesize: u64) -> Result<TreeShape, String> {
    let out = linux::btrfs()
        .args(["inspect-internal", "tree-stats", "-b", "-t", tree])
        .arg(img)
        .output()
        .map_err(|e| format!("tree-stats: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "tree-stats -t {tree} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |name: &str| -> Option<u64> {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(name))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|n| n.parse().ok())
    };
    let size = field("Total size:").ok_or_else(|| format!("tree-stats -t {tree}: {text}"))?;
    let levels = field("Levels:").ok_or_else(|| format!("tree-stats -t {tree}: {text}"))?;
    Ok(TreeShape {
        levels,
        blocks: size / nodesize,
    })
}

/// Free extents and block groups in the free-space tree, from its info items.
fn free_extents(img: &Path) -> Result<(usize, usize), String> {
    let out = linux::btrfs()
        .args(["inspect-internal", "dump-tree", "-t", "10"])
        .arg(img)
        .output()
        .map_err(|e| format!("dump-tree: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "dump-tree -t 10 failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let (mut extents, mut groups) = (0usize, 0usize);
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(rest) = line.trim().strip_prefix("free space info extent count ") {
            groups += 1;
            extents += rest
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(0);
        }
    }
    Ok((extents, groups))
}

/// One recorded commit.
#[derive(Clone, Copy, Debug)]
struct Commit {
    cost: Totals,
    wall: Duration,
}

impl Commit {
    /// Blocks the commit allocated beyond its batch's reservation.
    fn overrun(&self) -> u64 {
        self.cost
            .last_commit_blocks
            .saturating_sub(self.cost.last_commit_reserved)
    }
}

/// Run `op`, which must commit, and record what that cost — when it was one
/// commit. A step that had to reclaim space first (a commit, then a chunk
/// allocation, before the commit of its own) is counted in `irregular`
/// instead: its totals are not one commit's.
fn commit_with<T>(
    log: &mut Vec<Commit>,
    irregular: &mut usize,
    op: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let before = stats::totals();
    let started = Instant::now();
    let value = op()?;
    let wall = started.elapsed();
    let cost = stats::totals().since(&before);
    match cost.commits {
        0 => return Err("a measured step did not commit".into()),
        1 => log.push(Commit { cost, wall }),
        _ => *irregular += 1,
    }
    Ok(value)
}

/// `min / median / max` of one figure over `commits`.
fn spread(commits: &[Commit], figure: impl Fn(&Commit) -> u64) -> String {
    let mut values: Vec<u64> = commits.iter().map(figure).collect();
    values.sort_unstable();
    match values.as_slice() {
        [] => "-".into(),
        v => format!("{}/{}/{}", v[0], v[v.len() / 2], v[v.len() - 1]),
    }
}

fn report(kind: &str, commits: &[Commit]) -> String {
    format!(
        "      {kind}: {} commits; rounds {}; visited fst {} extent {} block-group {} csum {} root {} (from the device {}); wrote fst {} all trees {}; over reservation {}; {} ms",
        commits.len(),
        spread(commits, |c| c.cost.rounds),
        spread(commits, |c| c.cost.read.free_space),
        spread(commits, |c| c.cost.read.extent),
        spread(commits, |c| c.cost.read.block_group),
        spread(commits, |c| c.cost.read.csum),
        spread(commits, |c| c.cost.read.root),
        spread(commits, |c| c.cost.device_reads),
        spread(commits, |c| c.cost.written.free_space),
        spread(commits, |c| c.cost.written.total()),
        spread(commits, |c| c.overrun()),
        {
            let mut ms: Vec<f64> = commits
                .iter()
                .map(|c| c.wall.as_secs_f64() * 1000.0)
                .collect();
            ms.sort_by(f64::total_cmp);
            match ms.as_slice() {
                [] => "-".into(),
                v => format!("{:.1}/{:.1}/{:.1}", v[0], v[v.len() / 2], v[v.len() - 1]),
            }
        },
    )
}

/// The files the workload leaves behind, by path under its directory.
type Model = BTreeMap<String, Vec<u8>>;

/// What the workload recorded, per kind of transaction.
#[derive(Default)]
struct Recorded {
    save: Vec<Commit>,
    append: Vec<Commit>,
    create_burst: Vec<Commit>,
    unlink_burst: Vec<Commit>,
    /// Steps that committed more than once (space reclaim).
    irregular: usize,
}

/// The desktop-like workload, in `dir`. `tag` keeps the names of two passes
/// apart; `rounds` scales it.
fn desktop(
    dir: &Arc<dyn DirOps>,
    tag: &str,
    rounds: usize,
    model: &mut Model,
) -> Result<Recorded, String> {
    let mut rec = Recorded::default();
    // Start from a committed state, so the first measured commit holds only
    // its own operations.
    block_on(dir.fsync(false)).map_err(err("fsync"))?;
    // KDE's `QSaveFile`: a temporary file, written, fsynced, renamed over
    // one of a few names. The rename (which drops the file it replaces)
    // commits with the next save.
    let sizes = [1400usize, 6000, 20_000, 150_000, 700, 4096, 40_000, 9000];
    for i in 0..rounds * 8 {
        let body = noise(i as u64 ^ 0x5a5a, sizes[i % sizes.len()]);
        let tmp = format!("{tag}-save.{i:06x}.tmp");
        let name = format!("{tag}-save-{}.conf", i % 24);
        commit_with(&mut rec.save, &mut rec.irregular, || {
            block_on(async {
                let file = dir.create(&tmp).await.map_err(err("create"))?;
                write_all(&file, 0, &body).await?;
                file.fsync(false).await.map_err(err("fsync"))
            })
        })?;
        block_on(dir.rename(&tmp, &name)).map_err(err("rename"))?;
        model.insert(name, body);
    }
    // A log: append a line, fsync.
    let log_name = format!("{tag}-journal.log");
    let log = block_on(dir.create(&log_name)).map_err(err("create log"))?;
    let mut log_body = Vec::new();
    for i in 0..rounds * 4 {
        let line = noise(i as u64 ^ 0x1066, 300);
        commit_with(&mut rec.append, &mut rec.irregular, || {
            block_on(async {
                write_all(&log, log_body.len() as u64, &line).await?;
                log.fsync(false).await.map_err(err("fsync"))
            })
        })?;
        log_body.extend_from_slice(&line);
    }
    model.insert(log_name, log_body);
    // A package manager or a browser cache: many small files, then one
    // fsync of the directory; later all of them go again.
    for burst in 0..rounds {
        let names: Vec<String> = (0..48)
            .map(|i| format!("{tag}-cache-{burst}-{i}"))
            .collect();
        commit_with(&mut rec.create_burst, &mut rec.irregular, || {
            block_on(async {
                for (i, name) in names.iter().enumerate() {
                    let body = noise((burst * 64 + i) as u64, 500 + (i % 12) * 2600);
                    let file = dir.create(name).await.map_err(err("create"))?;
                    write_all(&file, 0, &body).await?;
                    model.insert(name.clone(), body);
                }
                dir.fsync(false).await.map_err(err("fsync"))
            })
        })?;
        // Keep the last burst so the final image holds some of them.
        if burst + 1 == rounds {
            break;
        }
        commit_with(&mut rec.unlink_burst, &mut rec.irregular, || {
            block_on(async {
                for name in &names {
                    dir.unlink(name).await.map_err(err("unlink"))?;
                    model.remove(name);
                }
                dir.fsync(false).await.map_err(err("fsync"))
            })
        })?;
    }
    Ok(rec)
}

/// Read every file of `model` back from `dir`.
fn verify(dir: &Arc<dyn DirOps>, model: &Model, what: &str) -> Result<(), String> {
    block_on(async {
        for (name, want) in model {
            let file = dir
                .lookup_async(name)
                .await
                .map_err(|e| format!("{what}: lookup {name}: {e:?}"))?;
            let got = narf::read_all(&file)
                .await
                .map_err(|e| format!("{what}: read {name}: {e:?}"))?;
            if got != *want {
                return Err(format!(
                    "{what}: {name} reads back {} bytes that differ from the {} written",
                    got.len(),
                    want.len()
                ));
            }
        }
        Ok(())
    })
}

/// Fill `shape.groups` DATA block groups under `top`, leaving the files to
/// unlink in `drop`. Returns the number of 4 KiB extents laid down.
fn build(top: &Arc<dyn DirOps>, shape: Shape) -> Result<(usize, Vec<String>), String> {
    let pairs = shape.holes_per_group.div_ceil(EXTENTS_PER_FILE);
    let written_pairs = shape.written_per_group.div_ceil(EXTENTS_PER_FILE);
    let burst_bytes = (pairs * EXTENTS_PER_FILE) as u64 * 2 * SECTOR;
    let mut drop = Vec::new();
    let mut extents = 0usize;
    block_on(async {
        for group in 0..shape.groups {
            for pair in 0..pairs {
                let keep_name = format!("k{group}-{pair}");
                let drop_name = format!("d{group}-{pair}");
                let keep = top.create(&keep_name).await.map_err(err("create"))?;
                let hole = top.create(&drop_name).await.map_err(err("create"))?;
                for i in 0..EXTENTS_PER_FILE as u64 {
                    // File offsets leave a gap between extents, so no two
                    // can ever be one item.
                    let off = i * 2 * SECTOR;
                    if pair < written_pairs {
                        let body = noise((group * pairs + pair) as u64 * 64 + i, SECTOR as usize);
                        write_all(&keep, off, &body).await?;
                    } else {
                        keep.fallocate(0, off, SECTOR)
                            .await
                            .map_err(err("fallocate"))?;
                    }
                    hole.fallocate(0, off, SECTOR)
                        .await
                        .map_err(err("fallocate"))?;
                    extents += 2;
                }
                drop.push(drop_name);
            }
            let ballast = top
                .create(&format!("ballast{group}"))
                .await
                .map_err(err("create"))?;
            ballast
                .fallocate(0, 0, GIB - burst_bytes)
                .await
                .map_err(|e| format!("ballast {group}: {e:?}"))?;
        }
        top.fsync(false).await.map_err(err("fsync"))
    })?;
    Ok((extents, drop))
}

fn run_shape(args: &Args, shape: Shape, rounds: usize, full: bool) -> Result<String, String> {
    let t0 = Instant::now();
    let dir = args.workdir.join("scale");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let rootdir = dir.join("rootdir");
    std::fs::create_dir_all(rootdir.join("@/etc")).unwrap();
    std::fs::create_dir_all(rootdir.join("@home")).unwrap();
    std::fs::write(rootdir.join("@/etc/hostname"), b"scale\n").unwrap();
    let img = dir.join("scale.img");
    // Room for the groups to fill, the metadata they need, and the workload.
    let size = (shape.groups as u64 + 24) * GIB;
    fixture::mkfs(
        &img,
        &rootdir,
        &fixture::MkfsSpec {
            uuid: "c4c405ee-0000-4a11-9e57-5ca1e0000001",
            size,
            nodesize: 16384,
            csum: "crc32c",
            features: "block-group-tree,free-space-tree,no-holes",
        },
    )?;
    let (fsid, nodesize, _) = dev::image_identity(&img);
    let mount = || -> Result<Arc<dyn FsInstance>, String> {
        let dev = Arc::new(RecDev::open(&img, 512, fsid, nodesize));
        narf::register_root(dev, &fsid)?;
        Ok(narf::mount_root_rw(&fsid, "@", &[])?.remove(0))
    };

    // Build the shape. The audit re-reads the whole free-space tree after
    // every commit; `btrfs check` judges this phase instead.
    narf_drivers_fs_btrfs::allocator::set_view_audit(false);
    let fs = mount()?;
    let top = block_on(fs.root().mkdir("ballast")).map_err(err("mkdir"))?;
    let (extents, drop_names) = build(&top, shape)?;
    block_on(async {
        for name in &drop_names {
            top.unlink(name).await.map_err(err("unlink"))?;
        }
        top.fsync(false).await.map_err(err("fsync"))
    })?;
    let built = t0.elapsed();

    // The measured pass, then the audited one.
    let desk = block_on(fs.root().mkdir("desk")).map_err(err("mkdir"))?;
    let mut model = Model::new();
    let measured = desktop(&desk, "m", rounds, &mut model)?;
    narf_drivers_fs_btrfs::allocator::set_view_audit(true);
    let audited = desktop(&desk, "a", rounds.div_ceil(4), &mut model)?;
    let audited_commits = audited.save.len()
        + audited.append.len()
        + audited.create_burst.len()
        + audited.unlink_burst.len()
        + audited.irregular;
    verify(&desk, &model, "in-session")?;
    drop(desk);
    drop(top);
    drop(fs);
    narf::reset();
    let worked = t0.elapsed();

    linux::check(&img, false)?;
    linux::check(&img, true)?;
    let node = u64::from(nodesize);
    let fst = tree_shape(&img, "10", node)?;
    let extent = tree_shape(&img, "2", node)?;
    let csum = tree_shape(&img, "7", node)?;
    let bgt = tree_shape(&img, "11", node)?;
    let (free, groups) = free_extents(&img)?;
    let (data_chunks, meta_chunks) = linux::chunk_counts(&img);
    if full && (fst.levels < 3 || extent.levels < 3) {
        return Err(format!(
            "the trees stayed shallow: free-space {fst:?}, extent {extent:?}"
        ));
    }
    if data_chunks < shape.groups {
        return Err(format!(
            "{data_chunks} DATA chunks, wanted at least {}",
            shape.groups
        ));
    }
    // A fresh mount reads the workload back and can still write.
    let fs = mount()?;
    if fs.always_read_only() {
        return Err("remounted read-only".into());
    }
    let desk = block_on(fs.root().lookup_dir_async("desk")).map_err(err("remount: lookup"))?;
    verify(&desk, &model, "after remount")?;
    let mut after = Model::new();
    desktop(&desk, "r", 1, &mut after)?;
    verify(&desk, &after, "after remount")?;
    drop(desk);
    drop(fs);
    narf::reset();
    linux::check(&img, false).map_err(|e| format!("after NARF remount: {e}"))?;
    linux::check(&img, true).map_err(|e| format!("after NARF remount: {e}"))?;
    let disk = std::os::unix::fs::MetadataExt::blocks(&std::fs::metadata(&img).unwrap()) * 512;
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(format!(
        "    {} GiB image ({} MiB on disk), 16384-byte nodes: {data_chunks} DATA + {meta_chunks} METADATA chunks, {groups} block groups, {extents} 4 KiB extents laid down, {free} free extents\n\
         \x20   trees (levels, blocks): free-space {}, {}; extent {}, {}; csum {}, {}; block-group {}, {}\n\
         \x20   per commit, min/median/max (node visits include cache hits; times are indicative; {} steps that reclaimed space first are left out):\n{}\n{}\n{}\n{}\n\
         \x20   {audited_commits} more commits with the free-space view audited against the tree; btrfs check clean (also --check-data-csum), before and after a remount\n\
         \x20   built in {:.0?}, workload {:.0?}, total {:.0?}",
        size / GIB,
        disk >> 20,
        fst.levels,
        fst.blocks,
        extent.levels,
        extent.blocks,
        csum.levels,
        csum.blocks,
        bgt.levels,
        bgt.blocks,
        measured.irregular,
        report("save file (create, write, fsync; rename over)", &measured.save),
        report("log append + fsync", &measured.append),
        report("48 creates + one fsync", &measured.create_burst),
        report("48 unlinks + one fsync", &measured.unlink_burst),
        built,
        worked - built,
        t0.elapsed(),
    ))
}

pub fn run(args: &Args) -> Result<String, String> {
    // 320 DATA block groups at the default `--ops`; fewer for a quick run,
    // which then does not reach three-level trees (and is not held to it).
    let full = args.ops >= 3000;
    let shape = Shape {
        groups: (320 * args.ops / 3000).clamp(4, 1024),
        holes_per_group: 1152,
        written_per_group: 128,
    };
    let line = run_shape(args, shape, 12, full);
    // The audit is a process-wide switch the scenario turns off for its
    // build and measured passes; leave it as the harness set it.
    narf_drivers_fs_btrfs::allocator::set_view_audit(true);
    Ok(format!("scale: OK\n{}", line?))
}
