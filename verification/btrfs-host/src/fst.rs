//! The `fst` scenario: Linux's verdict on free-space trees NARF maintained
//! incrementally.
//!
//! Two shapes the random workloads do not reach:
//!
//!  * `large` — thousands of single-sector holes punched into the data block
//!    groups of a fresh image, so the free-space tree grows from one leaf to
//!    a multi-level tree while every commit path-COWs only the leaves it
//!    touches (splits, emptied leaves, a root that gains levels);
//!  * `bitmap` — the committed fixture whose block group Linux converted to
//!    `FREE_SPACE_BITMAP` items, written to without converting it back.
//!
//! Each ends with `btrfs check` (which compares the free-space tree with the
//! extent tree and fails on any difference) with and without data checksums,
//! `dump-tree` to confirm the shape was really reached, and a NARF remount.

use std::path::Path;
use std::sync::Arc;

use narf_filesystem::{DirOps, FsInstance};

use crate::dev::RecDev;
use crate::host::block_on;
use crate::{dev, fixture, linux, narf, Args};

/// What `dump-tree -t 10` shows of a free-space tree.
#[derive(Debug, Default, Clone, Copy)]
struct Shape {
    leaves: usize,
    nodes: usize,
    level: usize,
    extents: usize,
    bitmaps: usize,
    /// Sum of `extent_count` over the bitmap block groups.
    bitmap_runs: usize,
}

fn fst_shape(img: &Path) -> Result<Shape, String> {
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
    let mut shape = Shape::default();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // Each block prints two header lines; only the first has "items".
        if line.starts_with("leaf ") && line.contains(" items ") {
            shape.leaves += 1;
        } else if line.starts_with("node ") && line.contains(" items ") {
            shape.nodes += 1;
            if let Some(level) = line
                .split(" level ")
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|n| n.parse::<usize>().ok())
            {
                shape.level = shape.level.max(level);
            }
        } else if line.contains("FREE_SPACE_EXTENT") {
            shape.extents += 1;
        } else if line.contains("FREE_SPACE_BITMAP") {
            shape.bitmaps += 1;
        } else if let Some(rest) = line.trim().strip_prefix("free space info extent count ") {
            // "<count> flags <flags>"; flags 1 = USING_BITMAPS.
            let mut words = rest.split_whitespace();
            let count = words.next().and_then(|n| n.parse::<usize>().ok());
            if let (Some(count), Some("flags"), Some("1")) = (count, words.next(), words.next()) {
                shape.bitmap_runs += count;
            }
        }
    }
    Ok(shape)
}

fn sync(dir: &Arc<dyn DirOps>) -> Result<(), String> {
    block_on(dir.fsync(false)).map_err(|e| format!("sync: {e:?}"))
}

/// Create `count` files of one 4 KiB data extent each under `dir`.
fn fill(dir: &Arc<dyn DirOps>, prefix: &str, count: usize) -> Result<(), String> {
    block_on(async {
        for i in 0..count {
            let name = format!("{prefix}{i}");
            let file = dir
                .create(&name)
                .await
                .map_err(|e| format!("create {name}: {e:?}"))?;
            // Incompressible, so the extent stays a full sector.
            let mut body = [0u8; 4096];
            let mut x = (i as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            for b in body.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = x as u8;
            }
            file.write(0, &body)
                .await
                .map_err(|e| format!("write {name}: {e:?}"))?;
        }
        Ok(())
    })
}

/// Remove every `step`-th file `{prefix}{i}` below `count`, from `first`.
fn punch(
    dir: &Arc<dyn DirOps>,
    prefix: &str,
    count: usize,
    first: usize,
    step: usize,
) -> Result<(), String> {
    block_on(async {
        for i in (first..count).step_by(step) {
            let name = format!("{prefix}{i}");
            dir.unlink(&name)
                .await
                .map_err(|e| format!("unlink {name}: {e:?}"))?;
        }
        Ok(())
    })
}

fn entries(dir: &Arc<dyn DirOps>) -> Result<usize, String> {
    block_on(dir.enumerate_async(0, usize::MAX))
        .map(|e| e.len())
        .map_err(|e| format!("readdir: {e:?}"))
}

/// Check `img` with Linux, then make sure NARF mounts it again and still
/// finds `want` entries in `dir_name`.
fn judge(
    img: &Path,
    mount: &dyn Fn() -> Result<Arc<dyn FsInstance>, String>,
    dir_name: &str,
    want: usize,
) -> Result<(), String> {
    linux::check(img, false)?;
    linux::check(img, true)?;
    let fs = mount()?;
    let dir = block_on(fs.root().lookup_dir_async(dir_name))
        .map_err(|e| format!("remount: lookup {dir_name}: {e:?}"))?;
    let got = entries(&dir)?;
    drop(dir);
    drop(fs);
    narf::reset();
    if got != want {
        return Err(format!("remount: {got} entries in {dir_name}, want {want}"));
    }
    linux::check(img, false).map_err(|e| format!("after NARF remount: {e}"))
}

fn run_large(args: &Args, nodesize: u32, files: usize) -> Result<String, String> {
    let dir = args.workdir.join(format!("fst-large-{nodesize}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let rootdir = dir.join("rootdir");
    std::fs::create_dir_all(rootdir.join("@/etc")).unwrap();
    std::fs::create_dir_all(rootdir.join("@home")).unwrap();
    std::fs::write(rootdir.join("@/etc/hostname"), b"fst\n").unwrap();
    let img = dir.join("fst.img");
    fixture::mkfs(
        &img,
        &rootdir,
        &fixture::MkfsSpec {
            uuid: &format!(
                "c4c405ee-0000-4a11-9e57-{:012x}",
                0xf570_0000_0000u64 + u64::from(nodesize)
            ),
            size: 1 << 30,
            nodesize,
            csum: "crc32c",
            features: "block-group-tree,free-space-tree,no-holes",
        },
    )?;
    let before = fst_shape(&img)?;
    let (fsid, node, _) = dev::image_identity(&img);
    let mount = || -> Result<Arc<dyn FsInstance>, String> {
        let dev = Arc::new(RecDev::open(&img, 512, fsid, node));
        narf::register_root(dev, &fsid)?;
        Ok(narf::mount_root_rw(&fsid, "@", &[])?.remove(0))
    };
    let fs = mount()?;
    let top = block_on(fs.root().mkdir("holes")).map_err(|e| format!("mkdir: {e:?}"))?;
    // Fill, punch every other file, commit; then refill part of the holes
    // (exact fits and front carves) and punch a different stride, so free
    // extents are split, consumed and merged across many leaves.
    fill(&top, "a", files)?;
    sync(&top)?;
    punch(&top, "a", files, 0, 2)?;
    sync(&top)?;
    fill(&top, "b", files / 4)?;
    punch(&top, "a", files, 1, 6)?;
    sync(&top)?;
    punch(&top, "b", files / 4, 0, 3)?;
    sync(&top)?;
    let want = entries(&top)?;
    drop(top);
    drop(fs);
    narf::reset();
    let after = fst_shape(&img)?;
    if after.level == 0 || after.leaves < 4 {
        return Err(format!(
            "large ({nodesize}): the free-space tree stayed small: {after:?}"
        ));
    }
    judge(&img, &mount, "holes", want)?;
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(format!(
        "    large, {nodesize}-byte nodes: {files} files punched; free-space tree {} leaf/level {} -> {} leaves + {} nodes, level {}, {} free extents, {} bitmaps; btrfs check clean",
        before.leaves, before.level, after.leaves, after.nodes, after.level, after.extents, after.bitmaps
    ))
}

fn run_bitmap(args: &Args) -> Result<String, String> {
    let dir = args.workdir.join("fst-bitmap");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let img = dir.join("bitmap.img");
    fixture::unsparse(&fixture::testdata().join("fixture-bitmap.img.sparse"), &img);
    linux::check(&img, true).map_err(|e| format!("pristine bitmap fixture: {e}"))?;
    let before = fst_shape(&img)?;
    if before.bitmaps == 0 {
        return Err("bitmap fixture has no FREE_SPACE_BITMAP".into());
    }
    let (fsid, node, _) = dev::image_identity(&img);
    let mount = || -> Result<Arc<dyn FsInstance>, String> {
        let dev = Arc::new(RecDev::open(&img, 512, fsid, node));
        narf::register_root(dev, &fsid)?;
        // Not a production-root shape (mixed block groups): mounted under
        // the default policy, where the gate accepts what the writer can
        // keep consistent.
        narf_block::disk_policy::__set_policy_for_test(Some(
            narf_block::disk_policy::DiskPolicy::All,
        ));
        let fstype =
            narf_filesystem::lookup_fstype("btrfs").ok_or("btrfs fstype not registered")?;
        let source = format!("/dev/{}", narf::PART);
        fstype
            .init(&narf_filesystem::MountRequest {
                fs_type: "btrfs",
                source: &source,
                options: narf::FSTAB_OPTS,
                uid: 0,
                gid: 0,
                umask: 0o022,
                initial_namespace: true,
                read_only: false,
            })
            .map_err(|e| {
                format!(
                    "bitmap mount: {e:?}; refusal: {:?}",
                    narf_drivers_fs_btrfs::rw_gate::last_refusal()
                )
            })
    };
    let fs = mount()?;
    if fs.always_read_only() {
        return Err("bitmap fixture mounted read-only".into());
    }
    let top = block_on(fs.root().mkdir("bits")).map_err(|e| format!("mkdir: {e:?}"))?;
    const FILES: usize = 600;
    fill(&top, "a", FILES)?;
    sync(&top)?;
    punch(&top, "a", FILES, 0, 2)?;
    sync(&top)?;
    fill(&top, "b", FILES / 3)?;
    punch(&top, "a", FILES, 1, 4)?;
    sync(&top)?;
    let want = entries(&top)?;
    drop(top);
    drop(fs);
    narf::reset();
    let after = fst_shape(&img)?;
    if after.bitmaps == 0 {
        return Err("the bitmap block group lost its bitmaps".into());
    }
    if after.bitmap_runs == before.bitmap_runs {
        return Err("the workload did not reach the bitmap block group".into());
    }
    judge(&img, &mount, "bits", want)?;
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(format!(
        "    bitmap fixture: {} bitmap item(s), {} free runs -> {} bitmap item(s), {} free runs after {} creates and {} unlinks; btrfs check clean",
        before.bitmaps,
        before.bitmap_runs,
        after.bitmaps,
        after.bitmap_runs,
        FILES + FILES / 3,
        FILES / 2 + FILES / 4
    ))
}

pub fn run(args: &Args) -> Result<String, String> {
    let lines = [
        run_large(args, 4096, 12_000)?,
        run_large(args, 16_384, 24_000)?,
        run_bitmap(args)?,
    ];
    Ok(format!("fst: OK\n{}", lines.join("\n")))
}
