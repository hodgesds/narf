//! The `overwrite` scenario: what one small write costs against the number
//! of extent items the file already has, and how fast plain sequential
//! writes go.
//!
//! A file whose pages were written one `write` at a time has one
//! `EXTENT_DATA` item per page: memory-mapped files flushed page by page
//! (journald's journal, shader-cache indexes), databases, anything appended
//! in small pieces. Overwriting one page of such a file must cost what
//! overwriting one page of any file costs — a descent to the extent items
//! the range overlaps (Linux `btrfs_drop_extents` from a
//! `btrfs_lookup_file_extent` at the range's start) — and not a walk over
//! every extent item the inode has, which makes N overwrites cost N² and,
//! while it runs, holds every other writer on the filesystem behind it.
//!
//! The scenario builds files of increasing extent counts, each one page per
//! `write` — in file order, and one with its pages written in a shuffled
//! order, as a sparse mapped file is first written back — and measures on
//! each:
//!
//!  * `random` — single-page overwrites at random offsets;
//!  * `rewrite` — the pages rewritten in file order, the pattern of a mapped
//!    file written back page by page.
//!
//! Per overwrite it records the fs-tree nodes visited (cache hits included),
//! the nodes read from the device, and wall time. The node counts are
//! deterministic and asserted: the largest file may not cost more per
//! overwrite than the smallest by more than its tree's extra level allows.
//! Wall time is held to a loose multiple, since the host is shared.
//!
//! It then writes one file sequentially in 128 KiB and in 4 KiB calls and
//! reports MiB/s with the node visits and device writes per MiB: harness
//! measurements, not benchmarks. Every file is read back against what was
//! written, in the session and after a remount, and `btrfs check` (with data
//! checksums) judges the image.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use narf_drivers_fs_btrfs::stats::{self, Totals};
use narf_filesystem::{DirOps, FileOps, FsInstance};

use crate::dev::RecDev;
use crate::host::block_on;
use crate::workload::Rng;
use crate::{dev, fixture, linux, narf, Args};

const PAGE: usize = 4096;

/// The page of `file` at `index` as its `version`-th write left it.
fn page(file: u64, index: u64, version: u64) -> [u8; PAGE] {
    let mut x = (file << 48 | index << 16 | version).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut out = [0u8; PAGE];
    for b in out.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    out
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

/// What a run of single-page writes cost, per write.
#[derive(Clone, Copy, Debug)]
struct PerWrite {
    writes: u64,
    /// Fs-tree node visits (the `other` class: subvolume trees).
    fs_visits: f64,
    /// Node visits of every tree.
    visits: f64,
    device_reads: f64,
    /// Tree nodes written, of every tree (commits included).
    written: f64,
    micros: f64,
}

fn per_write(cost: &Totals, writes: u64, elapsed: std::time::Duration) -> PerWrite {
    let n = writes as f64;
    PerWrite {
        writes,
        fs_visits: cost.read.other as f64 / n,
        visits: cost.read.total() as f64 / n,
        device_reads: cost.device_reads as f64 / n,
        written: cost.written.total() as f64 / n,
        micros: elapsed.as_secs_f64() * 1e6 / n,
    }
}

impl std::fmt::Display for PerWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} writes: fs-tree nodes visited {:.1}, all trees {:.1}, read from the device {:.2}, tree nodes written {:.1}, {:.0} us",
            self.writes, self.fs_visits, self.visits, self.device_reads, self.written, self.micros
        )
    }
}

/// One file of `pages` single-page extents and the version each page holds.
struct Fragmented {
    id: u64,
    name: String,
    file: Arc<dyn FileOps>,
    versions: Vec<u64>,
    build: PerWrite,
    random: PerWrite,
    rewrite: PerWrite,
}

/// Write page `index` of `f` once more.
async fn overwrite(f: &mut Fragmented, index: usize) -> Result<(), String> {
    f.versions[index] += 1;
    let body = page(f.id, index as u64, f.versions[index]);
    write_all(&f.file, (index * PAGE) as u64, &body).await
}

fn build(
    dir: &Arc<dyn DirOps>,
    id: u64,
    pages: usize,
    shuffled: bool,
    rng: &mut Rng,
) -> Result<Fragmented, String> {
    let name = format!("pages-{pages}{}", if shuffled { "-shuffled" } else { "" });
    let mut order: Vec<usize> = (0..pages).collect();
    if shuffled {
        for i in (1..pages).rev() {
            order.swap(i, rng.below(i as u64 + 1) as usize);
        }
    }
    let file = block_on(dir.create(&name)).map_err(err("create"))?;
    let mut f = Fragmented {
        id,
        name,
        file,
        versions: vec![0; pages],
        build: per_write(&Totals::default(), 1, Default::default()),
        random: per_write(&Totals::default(), 1, Default::default()),
        rewrite: per_write(&Totals::default(), 1, Default::default()),
    };
    // One `write` per page: one extent item each.
    let (before, started) = (stats::totals(), Instant::now());
    block_on(async {
        for &index in &order {
            overwrite(&mut f, index).await?;
        }
        f.file.fsync(false).await.map_err(err("fsync"))
    })?;
    f.build = per_write(
        &stats::totals().since(&before),
        pages as u64,
        started.elapsed(),
    );

    const RANDOM: u64 = 1000;
    let (before, started) = (stats::totals(), Instant::now());
    block_on(async {
        for _ in 0..RANDOM {
            let index = rng.below(pages as u64) as usize;
            overwrite(&mut f, index).await?;
        }
        f.file.fsync(false).await.map_err(err("fsync"))
    })?;
    f.random = per_write(&stats::totals().since(&before), RANDOM, started.elapsed());

    // Page by page from the start: a mapping written back.
    let span = pages.min(2000);
    let (before, started) = (stats::totals(), Instant::now());
    block_on(async {
        for index in 0..span {
            overwrite(&mut f, index).await?;
        }
        f.file.fsync(false).await.map_err(err("fsync"))
    })?;
    f.rewrite = per_write(
        &stats::totals().since(&before),
        span as u64,
        started.elapsed(),
    );
    Ok(f)
}

/// Read `name` back and compare it with `want(page index)`.
fn verify_pages(
    dir: &Arc<dyn DirOps>,
    name: &str,
    pages: usize,
    want: impl Fn(u64) -> [u8; PAGE],
    what: &str,
) -> Result<(), String> {
    block_on(async {
        let file = dir
            .lookup_async(name)
            .await
            .map_err(|e| format!("{what}: lookup {name}: {e:?}"))?;
        let got = narf::read_all(&file)
            .await
            .map_err(|e| format!("{what}: read {name}: {e:?}"))?;
        if got.len() != pages * PAGE {
            return Err(format!(
                "{what}: {name} is {} bytes, want {}",
                got.len(),
                pages * PAGE
            ));
        }
        for (index, chunk) in got.chunks(PAGE).enumerate() {
            if chunk != want(index as u64) {
                return Err(format!("{what}: {name} page {index} differs"));
            }
        }
        Ok(())
    })
}

/// A sequential write of `mib` MiB in `chunk`-byte calls.
struct Sequential {
    name: String,
    id: u64,
    pages: usize,
    line: String,
}

fn sequential(
    dir: &Arc<dyn DirOps>,
    dev: &RecDev,
    id: u64,
    mib: usize,
    chunk: usize,
) -> Result<Sequential, String> {
    let name = format!("stream-{}k", chunk / 1024);
    let pages = mib * (1 << 20) / PAGE;
    let file = block_on(dir.create(&name)).map_err(err("create"))?;
    let per_call = chunk / PAGE;
    let mut body = vec![0u8; chunk];
    let (before, writes_before, started) = (stats::totals(), dev.writes(), Instant::now());
    block_on(async {
        for call in 0..pages / per_call {
            for (i, slot) in body.chunks_mut(PAGE).enumerate() {
                slot.copy_from_slice(&page(id, (call * per_call + i) as u64, 1));
            }
            write_all(&file, (call * chunk) as u64, &body).await?;
        }
        file.fsync(false).await.map_err(err("fsync"))
    })?;
    let elapsed = started.elapsed();
    let cost = stats::totals().since(&before);
    let line = format!(
        "{mib} MiB in {} KiB writes: {:.1} MiB/s; per MiB: {:.0} tree nodes visited, {:.1} tree nodes written, {:.1} device writes, {:.2} commits",
        chunk / 1024,
        mib as f64 / elapsed.as_secs_f64(),
        cost.read.total() as f64 / mib as f64,
        cost.written.total() as f64 / mib as f64,
        (dev.writes() - writes_before) as f64 / mib as f64,
        cost.commits as f64 / mib as f64,
    );
    Ok(Sequential {
        name,
        id,
        pages,
        line,
    })
}

pub fn run(args: &Args) -> Result<String, String> {
    let t0 = Instant::now();
    let dir = args.workdir.join("overwrite");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let rootdir = dir.join("rootdir");
    std::fs::create_dir_all(rootdir.join("@/etc")).unwrap();
    std::fs::create_dir_all(rootdir.join("@home")).unwrap();
    std::fs::write(rootdir.join("@/etc/hostname"), b"overwrite\n").unwrap();
    let img = dir.join("overwrite.img");
    fixture::mkfs(
        &img,
        &rootdir,
        &fixture::MkfsSpec {
            uuid: "c4c405ee-0000-4a11-9e57-0e7217e00001",
            size: 8 << 30,
            nodesize: 16384,
            csum: "crc32c",
            features: "block-group-tree,free-space-tree,no-holes",
        },
    )?;
    let (fsid, nodesize, _) = dev::image_identity(&img);
    let open = |img: &Path| -> Result<(Arc<RecDev>, Arc<dyn FsInstance>), String> {
        let dev = Arc::new(RecDev::open(img, 512, fsid, nodesize));
        narf::register_root(dev.clone(), &fsid)?;
        Ok((dev.clone(), narf::mount_root_rw(&fsid, "@", &[])?.remove(0)))
    };
    // Fewer pages for a quick run; the default reaches a second tree level
    // of extent items (a 16 KiB leaf holds about 200 of them).
    let scale = args.ops.clamp(300, 3000);
    let sizes = [
        (1000usize, false),
        (4000 * scale / 3000, false),
        (16_000 * scale / 3000, false),
        (4000 * scale / 3000, true),
    ];
    let mut rng = Rng::new(args.seed ^ 0x0e72);

    let (dev, fs) = open(&img)?;
    let top = block_on(fs.root().mkdir("overwrite")).map_err(err("mkdir"))?;
    let mut files = Vec::new();
    for (id, &(pages, shuffled)) in sizes.iter().enumerate() {
        files.push(build(&top, id as u64 + 1, pages, shuffled, &mut rng)?);
    }
    let streams = [
        sequential(&top, &dev, 100, 192 * scale / 3000, 128 << 10)?,
        sequential(&top, &dev, 101, 48 * scale / 3000, PAGE)?,
    ];
    let check_all = |top: &Arc<dyn DirOps>, what: &str| -> Result<(), String> {
        for f in &files {
            let (id, versions) = (f.id, &f.versions);
            verify_pages(
                top,
                &f.name,
                versions.len(),
                |index| page(id, index, versions[index as usize]),
                what,
            )?;
        }
        for s in &streams {
            verify_pages(top, &s.name, s.pages, |index| page(s.id, index, 1), what)?;
        }
        Ok(())
    };
    check_all(&top, "in-session")?;
    drop(top);
    drop(fs);
    narf::reset();
    if !dev.violations().is_empty() {
        return Err(format!("request-shape violations: {:#?}", dev.violations()));
    }
    drop(dev);
    linux::check(&img, false)?;
    linux::check(&img, true)?;
    let (dev, fs) = open(&img)?;
    let top = block_on(fs.root().lookup_dir_async("overwrite")).map_err(err("remount: lookup"))?;
    check_all(&top, "after remount")?;
    drop(top);
    drop(fs);
    narf::reset();
    drop(dev);
    linux::check(&img, false).map_err(|e| format!("after NARF remount: {e}"))?;

    let mut lines = Vec::new();
    for f in &files {
        lines.push(format!(
            "    {} ({} single-page extents)\n      built, {}\n      random overwrites, {}\n      rewritten in order, {}",
            f.name,
            f.versions.len(),
            f.build,
            f.random,
            f.rewrite
        ));
    }
    for s in &streams {
        lines.push(format!("    sequential, {}", s.line));
    }
    let report = format!(
        "{}\n    btrfs check clean (also --check-data-csum); every page read back, before and after a remount; {:.0?}",
        lines.join("\n"),
        t0.elapsed()
    );
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    // An overwrite reaches the items of its own range: one descent each to
    // look them up, to read the old sector's neighbours and to COW the path,
    // however many extent items the file has. The largest file's tree may be
    // a level taller than the smallest's; nothing else may differ.
    let small = &files[0];
    for large in &files[1..] {
        for (what, a, b) in [
            ("random overwrite", &small.random, &large.random),
            ("in-order rewrite", &small.rewrite, &large.rewrite),
        ] {
            if b.fs_visits > a.fs_visits * 1.5 + 4.0 {
                return Err(format!(
                    "{report}\na {what} visits {:.1} fs-tree nodes in {} and {:.1} in {}: the cost follows the file's extent count",
                    a.fs_visits, small.name, b.fs_visits, large.name
                ));
            }
            if b.device_reads > a.device_reads + 1.0 {
                return Err(format!(
                    "{report}\na {what} reads {:.2} nodes from the device in {}, {:.2} in {}",
                    b.device_reads, large.name, a.device_reads, small.name
                ));
            }
            if b.micros > a.micros * 4.0 + 200.0 {
                return Err(format!(
                    "{report}\na {what} takes {:.0} us in {} and {:.0} us in {}",
                    a.micros, small.name, b.micros, large.name
                ));
            }
        }
    }
    Ok(format!("overwrite: OK\n{report}"))
}
